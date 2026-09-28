//! DNS service: `dns` section runtime — server transports, rule walk,
//! response cache, fakeip pools and hostname resolution for outbounds.
//!
//! Absent `dns` section = system mode (`resolve` falls back to the OS
//! resolver through [`connect_tcp`]).

mod cache;
pub mod codec;
mod rules;
pub mod transport;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hickory_proto::rr::RecordType;
use serde_json::Value;
use tokio::net::TcpStream;

pub use rules::{Action, QueryMeta, RejectMethod, Rule, WalkOptions};
pub use transport::{FakeIpStore, ServerConfig};

use cache::{Cache, CacheHit, CacheKey};
use codec::QueryInfo;

const DEFAULT_CACHE_CAPACITY: usize = 1024;
const DEFAULT_OPTIMISTIC_TIMEOUT: Duration = Duration::from_secs(3 * 24 * 3600);
/// Address resolution probes both families unless the strategy says otherwise.
const RESOLVE_TIMEOUT_GUARD: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    AsIs,
    PreferIPv4,
    PreferIPv6,
    IPv4Only,
    IPv6Only,
}

impl Strategy {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "" => Ok(Self::AsIs),
            "prefer_ipv4" => Ok(Self::PreferIPv4),
            "prefer_ipv6" => Ok(Self::PreferIPv6),
            "ipv4_only" => Ok(Self::IPv4Only),
            "ipv6_only" => Ok(Self::IPv6Only),
            other => anyhow::bail!("dns.strategy: unknown value {other:?}"),
        }
    }

    fn query_types(self) -> &'static [RecordType] {
        match self {
            Self::IPv4Only => &[RecordType::A],
            Self::IPv6Only => &[RecordType::AAAA],
            _ => &[RecordType::A, RecordType::AAAA],
        }
    }
}

pub struct DnsService {
    servers: HashMap<String, Arc<ServerConfig>>,
    rules: Vec<Rule>,
    final_tag: String,
    strategy: Strategy,
    disable_cache: bool,
    disable_expire: bool,
    optimistic_timeout: Option<Duration>,
    cache: RwLock<Cache>,
    inflight: std::sync::Mutex<HashMap<CacheKey, Arc<tokio::sync::Mutex<()>>>>,
    refreshing: std::sync::Mutex<HashSet<CacheKey>>,
    /// Installed after the router exists, so `detour` can dial through it.
    router: RwLock<Option<Arc<crate::route::Router>>>,
}

impl DnsService {
    /// The transport dialer, carrying the router once the instance is up.
    fn dialer(&self) -> transport::Dialer {
        transport::Dialer {
            router: self.router.read().ok().and_then(|router| router.clone()),
        }
    }

    /// `dns.server.detour` needs the outbounds; the instance wires them in.
    pub fn set_router(&self, router: Arc<crate::route::Router>) {
        if let Ok(mut current) = self.router.write() {
            *current = Some(router);
        }
    }

    /// Build from the root document; `Ok(None)` when there is no `dns` section.
    pub fn build(root: &Value) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(dns) = root.get("dns") else {
            return Ok(None);
        };
        let map = dns
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("dns: must be a JSON object"))?;

        let mut servers: HashMap<String, Arc<ServerConfig>> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        let empty = Vec::new();
        for (i, obj) in map
            .get("servers")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let cfg = ServerConfig::build(obj, &format!("dns.servers[{i}"))?;
            if cfg.tag.is_empty() {
                anyhow::bail!("dns.servers[{i}]: missing tag");
            }
            if servers.contains_key(&cfg.tag) {
                anyhow::bail!("dns.servers[{i}]: duplicate tag {:?}", cfg.tag);
            }
            order.push(cfg.tag.clone());
            servers.insert(cfg.tag.clone(), Arc::new(cfg));
        }

        let mut rules = Vec::new();
        // dns rules consult the same rule sets as the route rules
        let empty_route = serde_json::Map::new();
        let route = root
            .get("route")
            .and_then(Value::as_object)
            .unwrap_or(&empty_route);
        let rule_sets = crate::route::build_rule_sets(route)?;
        for (i, obj) in map
            .get("rules")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let at = format!("dns.rules[{i}]");
            if obj.get("type").and_then(Value::as_str) == Some("logical") {
                anyhow::bail!("{at}: logical dns rules are not implemented yet");
            }
            rules.push(Rule::build_with_rule_sets(obj, &at, &rule_sets)?);
        }

        let final_tag = match map.get("final").and_then(Value::as_str) {
            Some(tag) => {
                if !servers.contains_key(tag) {
                    anyhow::bail!("dns.final: unknown dns server {tag:?}");
                }
                tag.to_string()
            }
            None => order
                .first()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("dns: servers must not be empty"))?,
        };

        let strategy = Strategy::parse(
            map.get("strategy")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        let disable_cache = map
            .get("disable_cache")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let disable_expire = map
            .get("disable_expire")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if map.get("independent_cache").and_then(Value::as_bool) == Some(true) {
            crate::logging::warn(format_args!(
                "dns.independent_cache is deprecated (ignored)"
            ));
        }

        let optimistic_timeout = match map.get("optimistic") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => {
                if *b {
                    Some(DEFAULT_OPTIMISTIC_TIMEOUT)
                } else {
                    None
                }
            }
            Some(obj @ Value::Object(_)) => {
                let enabled = obj.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                if !enabled {
                    None
                } else {
                    let timeout = crate::outbound::urltest::parse_duration(
                        obj.get("timeout"),
                        DEFAULT_OPTIMISTIC_TIMEOUT,
                        "dns.optimistic.timeout",
                    )?;
                    Some(timeout)
                }
            }
            Some(_) => anyhow::bail!("dns.optimistic: must be a bool or object"),
        };
        if optimistic_timeout.is_some() && disable_cache {
            anyhow::bail!("`optimistic` is conflict with `disable_cache`");
        }
        if optimistic_timeout.is_some() && disable_expire {
            anyhow::bail!("`optimistic` is conflict with `disable_expire`");
        }

        let cache_capacity = map
            .get("cache_capacity")
            .and_then(Value::as_u64)
            .map(|c| c as usize)
            .unwrap_or(DEFAULT_CACHE_CAPACITY)
            .max(1024);

        if map.get("reverse_mapping").and_then(Value::as_bool) == Some(true) {
            crate::logging::warn(format_args!("dns.reverse_mapping is not implemented yet"));
        }
        if map.get("client_subnet").is_some_and(|v| !v.is_null()) {
            crate::logging::warn(format_args!("dns.client_subnet is not implemented yet"));
        }

        Ok(Some(Arc::new(Self {
            servers,
            rules,
            final_tag,
            strategy,
            disable_cache,
            disable_expire,
            optimistic_timeout,
            cache: RwLock::new(Cache::new(cache_capacity)),
            inflight: std::sync::Mutex::new(HashMap::new()),
            refreshing: std::sync::Mutex::new(HashSet::new()),
            router: RwLock::new(None),
        })))
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// All fakeip stores (for reverse lookups from routing/sniffing later).
    pub fn fakeip_stores(&self) -> Vec<Arc<FakeIpStore>> {
        self.servers
            .values()
            .filter_map(|s| s.store.clone())
            .collect()
    }

    /// Reverse fakeip lookup: fake address → original domain.
    pub fn fakeip_domain(&self, ip: IpAddr) -> Option<String> {
        self.servers
            .values()
            .find_map(|s| s.store.as_ref().and_then(|f| f.lookup_domain(ip)))
    }

    /// Run the rule walk and produce the raw response for `query`.
    ///
    /// `allow_fakeip` is false for address lookups (outbound server
    /// resolution) — fakeip routes are skipped, as in sing-box.
    pub async fn exchange(
        self: &Arc<Self>,
        meta: &QueryMeta,
        query: &[u8],
        allow_fakeip: bool,
    ) -> std::io::Result<Vec<u8>> {
        self.exchange_inner(meta, query, allow_fakeip, false).await
    }

    async fn exchange_inner(
        self: &Arc<Self>,
        meta: &QueryMeta,
        query: &[u8],
        allow_fakeip: bool,
        skip_cache_read: bool,
    ) -> std::io::Result<Vec<u8>> {
        let (query_msg, info) = codec::parse_query(query)?;
        let mut opts = WalkOptions::default();
        let mut target: Option<Arc<ServerConfig>> = None;
        for rule in &self.rules {
            if !rule.matches(meta, &info) {
                continue;
            }
            match &rule.action {
                Action::RouteOptions {
                    rewrite_ttl,
                    disable_cache,
                } => {
                    if let Some(ttl) = rewrite_ttl {
                        opts.rewrite_ttl = Some(*ttl);
                    }
                    if *disable_cache {
                        opts.disable_cache = true;
                    }
                }
                Action::Route {
                    server,
                    rewrite_ttl,
                    disable_cache,
                } => {
                    // an empty server is the reference default: dns.final
                    let tag = if server.is_empty() {
                        self.final_tag.as_str()
                    } else {
                        server.as_str()
                    };
                    let Some(cfg) = self.servers.get(tag) else {
                        crate::logging::warn(format_args!("dns: transport not found: {tag}"));
                        continue;
                    };
                    if cfg.is_fakeip() && !allow_fakeip {
                        continue;
                    }
                    if let Some(ttl) = rewrite_ttl {
                        opts.rewrite_ttl = Some(*ttl);
                    }
                    if *disable_cache || cfg.is_fakeip() {
                        opts.disable_cache = true;
                    }
                    target = Some(Arc::clone(cfg));
                    break;
                }
                Action::Reject => {
                    return match rule.reject_method {
                        RejectMethod::Refused => {
                            codec::refused_response(&query_msg).map_err(std::io::Error::other)
                        }
                        RejectMethod::Drop => Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "dns: query dropped by rule",
                        )),
                    };
                }
                Action::Predefined(predefined) => {
                    return codec::predefined_response(&query_msg, predefined)
                        .map_err(std::io::Error::other);
                }
                Action::Evaluate | Action::Respond => {
                    crate::logging::warn(format_args!(
                        "dns: evaluate/respond actions are a known gap; rule ignored"
                    ));
                }
            }
        }
        let target = match target {
            Some(cfg) => cfg,
            None => Arc::clone(
                self.servers
                    .get(&self.final_tag)
                    .ok_or_else(|| std::io::Error::other("dns: final server missing"))?,
            ),
        };

        if target.is_fakeip() {
            let store = target
                .store
                .clone()
                .ok_or_else(|| std::io::Error::other("dns: fakeip server without store"))?;
            return self.fakeip_answer(&query_msg, &info, &store, opts.rewrite_ttl);
        }

        let use_cache = !self.disable_cache && !opts.disable_cache;
        let key = CacheKey {
            tag: target.tag.clone(),
            name: info.name.clone(),
            qtype: u16::from(info.qtype),
        };
        let optimistic = if self.optimistic_timeout.is_some() && use_cache {
            self.optimistic_timeout
        } else {
            None
        };

        if use_cache && !skip_cache_read {
            let now = std::time::Instant::now();
            let hit = self.cache.read().expect("dns cache").get(&key, now);
            match hit {
                Some(CacheHit::Fresh(raw)) => return codec::set_id(&raw, info.id),
                Some(CacheHit::Stale(raw)) => {
                    self.spawn_refresh(meta.clone(), query.to_vec(), allow_fakeip, key.clone());
                    return codec::set_id(&raw, info.id);
                }
                None => {}
            }
        }

        let lock = {
            let mut inflight = self.inflight.lock().expect("dns inflight");
            Arc::clone(
                inflight
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _guard = lock.lock().await;
        if use_cache && !skip_cache_read {
            let now = std::time::Instant::now();
            if let Some(CacheHit::Fresh(raw)) = self.cache.read().expect("dns cache").get(&key, now)
            {
                return codec::set_id(&raw, info.id);
            }
        }

        let response = self.exchange_remote(&target, query).await?;
        let rewritten = match opts.rewrite_ttl {
            Some(ttl) => codec::rewrite_ttl(&response, ttl)?,
            None => response,
        };

        if use_cache && let Ok(meta_resp) = codec::response_meta(&rewritten) {
            let cacheable = matches!(
                meta_resp.rcode,
                hickory_proto::op::ResponseCode::NoError
                    | hickory_proto::op::ResponseCode::NXDomain
            );
            if cacheable {
                let mut cache = self.cache.write().expect("dns cache");
                // disable_expire pins entries (ttl checked against optimistic window only).
                let meta_for_insert = if self.disable_expire {
                    codec::ResponseMeta {
                        rcode: meta_resp.rcode,
                        min_answer_ttl: Some(u32::MAX),
                    }
                } else {
                    meta_resp
                };
                cache.insert(key.clone(), rewritten.clone(), &meta_for_insert, optimistic);
            }
        }
        codec::set_id(&rewritten, info.id)
    }

    fn spawn_refresh(
        self: &Arc<Self>,
        meta: QueryMeta,
        query: Vec<u8>,
        allow_fakeip: bool,
        key: CacheKey,
    ) {
        if !self
            .refreshing
            .lock()
            .expect("refresh set")
            .insert(key.clone())
        {
            return;
        }
        let service = Arc::clone(self);
        tokio::spawn(async move {
            let _ = service
                .exchange_inner(&meta, &query, allow_fakeip, true)
                .await;
            service.refreshing.lock().expect("refresh set").remove(&key);
        });
    }

    fn fakeip_answer(
        &self,
        query_msg: &hickory_proto::op::Message,
        info: &QueryInfo,
        store: &FakeIpStore,
        rewrite_ttl: Option<u32>,
    ) -> std::io::Result<Vec<u8>> {
        let v6 = match info.qtype {
            RecordType::A => false,
            RecordType::AAAA => true,
            _ => {
                return Err(std::io::Error::other(
                    "dns: fakeip only supports A/AAAA queries",
                ));
            }
        };
        if v6 && !store.has_v6() {
            return codec::empty_success(query_msg).map_err(std::io::Error::other);
        }
        if !v6 && !store.has_v4() {
            return codec::empty_success(query_msg).map_err(std::io::Error::other);
        }
        let addr = store.create(&info.name, v6)?;
        let ttl = rewrite_ttl.unwrap_or(codec::DEFAULT_TTL);
        codec::synth_address(query_msg, addr, ttl).map_err(std::io::Error::other)
    }

    async fn exchange_remote(
        self: &Arc<Self>,
        cfg: &ServerConfig,
        query: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let addr = self.resolve_server_addr(cfg, 0).await?;
        let raw = transport::exchange(cfg, addr, query, &self.dialer()).await?;
        Ok(raw)
    }

    /// Resolve the transport's own address (domain servers via
    /// `domain_resolver`, otherwise the system resolver with a warning).
    ///
    /// Boxed future: `resolve_server_addr` ↔ `lookup_via` recurse through
    /// each other (domain_resolver chains), which needs indirection.
    fn resolve_server_addr<'a>(
        self: &'a Arc<Self>,
        cfg: &'a ServerConfig,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<SocketAddr>> + Send + 'a>>
    {
        Box::pin(async move {
            if let Some(ip) = transport::is_ip_literal(&cfg.server) {
                return Ok(SocketAddr::new(ip, cfg.port));
            }
            if depth > 4 {
                return Err(std::io::Error::other(format!(
                    "dns: server address chain too deep for {:?}",
                    cfg.tag
                )));
            }
            if let Some(resolver_tag) = &cfg.domain_resolver {
                let resolver = self.servers.get(resolver_tag).ok_or_else(|| {
                    std::io::Error::other(format!(
                        "dns: domain_resolver {resolver_tag:?} not found (server {:?})",
                        cfg.tag
                    ))
                })?;
                if resolver.is_fakeip() {
                    return Err(std::io::Error::other(
                        "dns: domain_resolver must not be a fakeip server",
                    ));
                }
                let addrs = self.lookup_via(resolver, &cfg.server, depth + 1).await?;
                let ip = pick_address(addrs, self.strategy)
                    .ok_or_else(|| std::io::Error::other("dns: no addresses resolved"))?;
                return Ok(SocketAddr::new(ip, cfg.port));
            }
            crate::logging::warn(format_args!(
                "dns: server {:?} host {:?} resolved via system (no domain_resolver)",
                cfg.tag, cfg.server
            ));
            let mut addrs = tokio::net::lookup_host((cfg.server.as_str(), cfg.port)).await?;
            addrs
                .next()
                .ok_or_else(|| std::io::Error::other("dns: system resolution returned nothing"))
        })
    }

    /// Address lookup strictly through `resolver` (bootstrap), bypassing the
    /// rule walk so the chain cannot loop back onto itself.
    async fn lookup_via(
        self: &Arc<Self>,
        resolver: &Arc<ServerConfig>,
        host: &str,
        depth: u8,
    ) -> std::io::Result<Vec<IpAddr>> {
        let mut out = Vec::new();
        for qtype in self.strategy.query_types() {
            let query = codec::build_query(rand_id(), host, *qtype)?;
            let addr = self.resolve_server_addr(resolver, depth).await?;
            let raw = transport::exchange(resolver, addr, &query, &self.dialer()).await?;
            out.extend(codec::answer_ips(&raw)?);
        }
        Ok(out)
    }

    /// `resolve` rule action with an explicit server tag: lookup bypasses the
    /// dns rule walk and goes straight through that transport.
    pub async fn resolve_via(
        self: &Arc<Self>,
        server_tag: &str,
        host: &str,
    ) -> std::io::Result<Vec<IpAddr>> {
        if let Some(ip) = transport::is_ip_literal(host) {
            return Ok(vec![ip]);
        }
        let cfg = self
            .servers
            .get(server_tag)
            .ok_or_else(|| std::io::Error::other(format!("DNS server not found: {server_tag}")))?;
        if cfg.is_fakeip() {
            return Err(std::io::Error::other(format!(
                "DNS server not found: {server_tag}"
            )));
        }
        let addrs = self.lookup_via(cfg, host, 0).await?;
        Ok(order_addresses(addrs, self.strategy))
    }

    /// Resolve a hostname to addresses through the dns section
    /// (system-mode fallback lives in [`connect_tcp`]).
    pub async fn resolve(self: &Arc<Self>, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let fut = async {
            if let Some(ip) = transport::is_ip_literal(host) {
                return Ok(vec![ip]);
            }
            let qtypes = self.strategy.query_types();
            let mut handles = Vec::with_capacity(qtypes.len());
            for qtype in qtypes {
                let host = host.to_string();
                let service = Arc::clone(self);
                handles.push(tokio::spawn(async move {
                    let query = codec::build_query(rand_id(), &host, *qtype)?;
                    let meta = QueryMeta::default();
                    let raw = service
                        .exchange(&meta, &query, false)
                        .await
                        .map_err(std::io::Error::other)?;
                    codec::answer_ips(&raw)
                }));
            }
            let mut collected = Vec::new();
            for handle in handles {
                let ips = handle
                    .await
                    .map_err(|e| std::io::Error::other(format!("dns: resolve task: {e}")))?;
                collected.extend(ips?);
            }
            if collected.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("dns: no addresses for {host:?}"),
                ));
            }
            Ok(order_addresses(collected, self.strategy))
        };
        tokio::time::timeout(RESOLVE_TIMEOUT_GUARD, fut)
            .await
            .map_err(|_| std::io::Error::other(format!("dns: resolve timeout for {host:?}")))?
    }
}

fn order_addresses(mut addrs: Vec<IpAddr>, strategy: Strategy) -> Vec<IpAddr> {
    match strategy {
        Strategy::PreferIPv6 | Strategy::IPv6Only => {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        }
        Strategy::PreferIPv4 | Strategy::IPv4Only | Strategy::AsIs => {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }
    }
    addrs
}

fn pick_address(addrs: Vec<IpAddr>, strategy: Strategy) -> Option<IpAddr> {
    order_addresses(addrs, strategy).into_iter().next()
}

fn rand_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Process-wide service handle + outbound dialing helper
// ---------------------------------------------------------------------------

static SERVICE: RwLock<Option<Arc<DnsService>>> = RwLock::new(None);
static DEFAULT_DOMAIN_RESOLVER: RwLock<Option<String>> = RwLock::new(None);

/// Install (or clear) the process-wide dns service; called from `start()`.
pub fn set_service(service: Option<Arc<DnsService>>) {
    let mut slot = SERVICE.write().unwrap_or_else(|e| e.into_inner());
    *slot = service;
}

pub fn current() -> Option<Arc<DnsService>> {
    SERVICE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `route.default_domain_resolver` tag used when dialing outbound servers
/// (reference `networkManager.DefaultOptions().DomainResolver`).
pub fn set_default_domain_resolver(tag: Option<String>) {
    let mut slot = DEFAULT_DOMAIN_RESOLVER
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *slot = tag;
}

pub fn default_domain_resolver() -> Option<String> {
    DEFAULT_DOMAIN_RESOLVER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Connect to `host:port` through the dns service when configured, else via
/// the OS resolver. IP literals short-circuit.
pub async fn connect_tcp(host: &str, port: u16) -> std::io::Result<TcpStream> {
    if let Some(ip) = transport::is_ip_literal(host) {
        return TcpStream::connect(SocketAddr::new(ip, port)).await;
    }
    if let Some(service) = current() {
        let addrs = match default_domain_resolver() {
            Some(tag) => service.resolve_via(&tag, host).await?,
            None => service.resolve(host).await?,
        };
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect(SocketAddr::new(addr, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        return Err(last_err.unwrap_or_else(|| {
            std::io::Error::other(format!("dns: connect to {host}:{port} failed"))
        }));
    }
    TcpStream::connect((host, port)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_parse() {
        assert_eq!(
            Strategy::parse("prefer_ipv4").unwrap(),
            Strategy::PreferIPv4
        );
        assert_eq!(Strategy::parse("").unwrap(), Strategy::AsIs);
        assert!(Strategy::parse("bogus").is_err());
    }

    #[test]
    fn build_minimal() {
        let root = serde_json::json!({
            "dns": {
                "servers": [
                    {"type": "udp", "tag": "u", "server": "127.0.0.1"},
                    {"type": "fakeip", "tag": "f", "inet4_range": "198.18.0.0/15"}
                ],
                "rules": [
                    {"action": "route", "server": "f", "domain_suffix": ["x.test"]}
                ],
                "final": "u",
                "strategy": "prefer_ipv4"
            }
        });
        let svc = DnsService::build(&root).unwrap().expect("service");
        assert_eq!(svc.final_tag, "u");
        assert_eq!(svc.strategy, Strategy::PreferIPv4);
        assert_eq!(svc.rules.len(), 1);
        assert!(svc.fakeip_stores().len() == 1);
    }

    #[test]
    fn optimistic_conflicts() {
        let root = serde_json::json!({
            "dns": {
                "servers": [{"type": "udp", "tag": "u", "server": "127.0.0.1"}],
                "disable_cache": true,
                "optimistic": true
            }
        });
        let err = match DnsService::build(&root) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("optimistic must conflict with disable_cache"),
        };
        assert!(err.contains("optimistic"), "{err}");
    }
}
