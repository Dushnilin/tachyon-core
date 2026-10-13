//! DNS service: `dns` section runtime — server transports, rule walk,
//! response cache, fakeip pools and hostname resolution for outbounds.
//!
//! Absent `dns` section = system mode (`resolve` falls back to the OS
//! resolver through [`connect_tcp`]).

mod cache;
pub mod codec;
pub mod fastest_ip;
pub mod group;
pub mod mdns;
mod rules;
pub mod transport;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use hickory_proto::rr::{RData, RecordType};
use serde_json::Value;

pub use fastest_ip::{FastestIpCache, FastestIpConfig};
pub use rules::{Action, QueryMeta, RejectMethod, Rule, WalkOptions};
pub use transport::{FakeIpStore, Kind, ServerConfig};

use cache::{Cache, CacheHit, CacheKey};
use codec::QueryInfo;

const DEFAULT_CACHE_CAPACITY: usize = 1024;
const DEFAULT_OPTIMISTIC_TIMEOUT: Duration = Duration::from_secs(3 * 24 * 3600);
/// `dns.reverse_mapping` cache, same size as the reference's LRU.
const REVERSE_CAPACITY: usize = 1024;
/// Address resolution probes both families unless the strategy says otherwise.
const RESOLVE_TIMEOUT_GUARD: Duration = Duration::from_secs(10);
/// The reference's `mdnsTimeout`: an mDNS answer is either already on the LAN
/// or it is not coming.
const MDNS_TIMEOUT: Duration = Duration::from_secs(1);
/// How long a `domain_resolver` answer for a transport's own address is
/// reused. A failed refresh falls back to the expired entry (with a warning)
/// instead of taking the transport down — see `resolve_server_addr`.
const SERVER_ADDR_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    AsIs,
    PreferIPv4,
    PreferIPv6,
    IPv4Only,
    IPv6Only,
}

impl Strategy {
    pub(crate) fn parse(raw: &str) -> anyhow::Result<Self> {
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

    /// The record type a `prefer_*` strategy is satisfied with alone.
    fn preferred_family(self) -> Option<RecordType> {
        match self {
            Self::PreferIPv4 => Some(RecordType::A),
            Self::PreferIPv6 => Some(RecordType::AAAA),
            _ => None,
        }
    }
}

type ServerAddrLockMap = HashMap<(String, String), Weak<tokio::sync::Mutex<()>>>;

pub struct DnsService {
    servers: HashMap<String, Arc<ServerConfig>>,
    rules: Vec<Rule>,
    final_tag: String,
    strategy: Strategy,
    disable_cache: bool,
    disable_expire: bool,
    serve_stale: bool,
    serve_stale_duration: Duration,
    fastest_ip: FastestIpConfig,
    fastest_ip_cache: FastestIpCache,
    optimistic_timeout: Option<Duration>,
    cache: RwLock<Cache>,
    /// One lock per name that is being looked up right now; the value is a
    /// `Weak` so a finished query stops keeping anything alive — dead entries
    /// are purged on the next insert (the key itself owns an `Arc<str>`).
    inflight: std::sync::Mutex<HashMap<CacheKey, Weak<tokio::sync::Mutex<()>>>>,
    refreshing: std::sync::Mutex<HashSet<CacheKey>>,
    /// Resolved transport addresses (domain_resolver result) for a short while,
    /// and a lock so a burst of dials resolves a server once, not once each:
    /// dozens of identical bootstrap queries at the same instant get dropped
    /// upstream and every one of them sat out the full timeout.
    server_addrs: std::sync::Mutex<HashMap<(String, String), (SocketAddr, Instant)>>,
    server_addr_locks: std::sync::Mutex<ServerAddrLockMap>,
    /// Installed after the router exists, so `detour` can dial through it.
    router: RwLock<Option<Arc<crate::route::Router>>>,
    /// `dns.reverse_mapping`: ip → domain learned from A/AAAA answers, present
    /// only when the option is on (the reference leaves its LRU nil).
    reverse: Option<RwLock<HashMap<IpAddr, ReverseEntry>>>,
    /// `dns.client_subnet`: the EDNS0 client subnet every upstream query
    /// carries, already masked, with its prefix length.
    client_subnet: Option<(IpAddr, u8)>,
}

/// One learned `ip → domain` binding and when it stops being valid.
#[derive(Debug, Clone)]
struct ReverseEntry {
    domain: String,
    expires: Instant,
}

/// What an `evaluate` step resolved, kept for the rules that come after it.
struct Evaluated {
    raw: Vec<u8>,
    from_fakeip: bool,
    /// When the answer was produced, not when it was read out of the cache.
    received: Instant,
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
    ///
    /// Used where no router exists yet — tests and `check`-only paths. A
    /// running box goes through [`Self::build_with_registry`] so its rule
    /// sets are the ones the fetcher feeds.
    pub fn build(root: &Value) -> anyhow::Result<Option<Arc<Self>>> {
        let empty_route = serde_json::Map::new();
        let route = root
            .get("route")
            .and_then(Value::as_object)
            .unwrap_or(&empty_route);
        let owned = crate::route::build_rule_sets(
            route,
            &crate::http_client::Registry::from_config(root)?,
        )?;
        Self::build_with_registry(root, &owned)
    }

    /// Build against an existing `route.rule_set` registry.
    ///
    /// Rebuilding the registry here would give every remote set a second,
    /// permanently empty body: only the router's copy is ever handed to the
    /// downloader, so a DNS rule gated on a remote set could never match.
    pub fn build_with_registry(
        root: &Value,
        rule_sets: &crate::route::rule_set::RuleSetRegistry,
    ) -> anyhow::Result<Option<Arc<Self>>> {
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
        start_dns_groups(&servers, &order)?;

        let mut rules = Vec::new();
        for (i, obj) in map
            .get("rules")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let at = format!("dns.rules[{i}]");
            rules.push(Rule::build_with_rule_sets(obj, &at, rule_sets)?);
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

        let (serve_stale, serve_stale_duration) = match map.get("serve_stale") {
            None | Some(Value::Null) => (false, Duration::from_secs(7 * 24 * 3600)),
            Some(Value::Bool(b)) => (*b, Duration::from_secs(7 * 24 * 3600)),
            Some(obj @ Value::Object(_)) => {
                let enabled = obj.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                let duration = crate::outbound::urltest::parse_duration(
                    obj.get("timeout").or_else(|| obj.get("max_stale")),
                    Duration::from_secs(7 * 24 * 3600),
                    "dns.serve_stale.timeout",
                )?;
                (enabled, duration)
            }
            Some(_) => anyhow::bail!("dns.serve_stale: must be a bool or object"),
        };

        let fastest_ip = match map.get("fastest_ip") {
            None | Some(Value::Null) => FastestIpConfig::default(),
            Some(Value::Bool(b)) => FastestIpConfig {
                enabled: *b,
                ..Default::default()
            },
            Some(obj @ Value::Object(_)) => {
                let enabled = obj.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                let timeout = crate::outbound::urltest::parse_duration(
                    obj.get("timeout"),
                    Duration::from_millis(200),
                    "dns.fastest_ip.timeout",
                )?;
                let port = obj
                    .get("port")
                    .and_then(Value::as_u64)
                    .map(|p| p as u16)
                    .unwrap_or(443);
                FastestIpConfig {
                    enabled,
                    timeout,
                    port,
                }
            }
            Some(_) => anyhow::bail!("dns.fastest_ip: must be a bool or object"),
        };

        let cache_capacity = map
            .get("cache_capacity")
            .and_then(Value::as_u64)
            .map(|c| c as usize)
            .unwrap_or(DEFAULT_CACHE_CAPACITY)
            .max(1024);

        // reference `dns.reverse_mapping`: an off option keeps the LRU nil
        let reverse_mapping = map.get("reverse_mapping").and_then(Value::as_bool) == Some(true);
        let client_subnet = parse_client_subnet(map.get("client_subnet"))?;

        Ok(Some(Arc::new(Self {
            servers,
            rules,
            final_tag,
            strategy,
            disable_cache,
            disable_expire,
            serve_stale,
            serve_stale_duration,
            fastest_ip,
            fastest_ip_cache: FastestIpCache::new(cache_capacity, Duration::from_secs(300)),
            optimistic_timeout,
            cache: RwLock::new(Cache::new(cache_capacity)),
            inflight: std::sync::Mutex::new(HashMap::new()),
            refreshing: std::sync::Mutex::new(HashSet::new()),
            server_addrs: std::sync::Mutex::new(HashMap::new()),
            server_addr_locks: std::sync::Mutex::new(HashMap::new()),
            router: RwLock::new(None),
            reverse: reverse_mapping.then(|| RwLock::new(HashMap::new())),
            client_subnet,
        })))
    }

    /// Migrate active cache, server addresses, reverse mappings, and fakeip pools from an earlier DNS service.
    pub fn migrate_from(&self, old: &DnsService) {
        let now = Instant::now();
        if let (Ok(old_cache), Ok(mut new_cache)) = (old.cache.read(), self.cache.write()) {
            old_cache.copy_valid_into(&mut new_cache, now);
        }
        old.fastest_ip_cache.copy_into(&self.fastest_ip_cache);
        if let (Ok(old_addrs), Ok(mut new_addrs)) =
            (old.server_addrs.lock(), self.server_addrs.lock())
        {
            for (k, (addr, valid_until)) in old_addrs.iter() {
                if now < *valid_until {
                    new_addrs.insert(k.clone(), (*addr, *valid_until));
                }
            }
        }
        if let (Some(old_rev_lock), Some(new_rev_lock)) = (&old.reverse, &self.reverse)
            && let (Ok(old_rev), Ok(mut new_rev)) = (old_rev_lock.read(), new_rev_lock.write())
        {
            for (ip, entry) in old_rev.iter() {
                if entry.expires > now {
                    new_rev.insert(*ip, entry.clone());
                }
            }
        }
        for (tag, new_server) in &self.servers {
            if let Some(old_server) = old.servers.get(tag)
                && let (Some(new_store), Some(old_store)) = (&new_server.store, &old_server.store)
            {
                new_store.migrate_from(old_store);
            }
        }
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// One configured server by tag, with the runtime state it owns (a group's
    /// record tables, a fakeip pool).
    pub fn server(&self, tag: &str) -> Option<Arc<ServerConfig>> {
        self.servers.get(tag).cloned()
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

    pub fn is_fakeip(&self, ip: IpAddr) -> bool {
        self.servers
            .values()
            .any(|s| s.store.as_ref().is_some_and(|store| store.contains(ip)))
    }

    pub fn attach_cache(&self, cache: Option<crate::cache_file::SharedCacheFile>) {
        for store in self.fakeip_stores() {
            store.attach_cache(cache.clone());
        }
    }

    /// `dns.reverse_mapping` on: every A/AAAA answer becomes `ip → domain`
    /// for its TTL, so a connection that dials that IP can still match
    /// domain rules. FakeIP answers are skipped — they have their own map.
    fn record_reverse(&self, raw: &[u8], from_fakeip: bool) {
        self.record_reverse_at(raw, from_fakeip, Instant::now());
    }

    /// `received` is when the answer arrived — the TTL counts from there, so
    /// serving the same bytes out of the cache cannot extend the mapping.
    fn record_reverse_at(&self, raw: &[u8], from_fakeip: bool, received: Instant) {
        let Some(reverse) = &self.reverse else {
            return;
        };
        if from_fakeip {
            return;
        }
        let Ok(message) = codec::parse_message(raw) else {
            return;
        };
        if message.answers.is_empty() {
            return;
        }
        let now = Instant::now();
        let Ok(mut map) = reverse.write() else {
            return;
        };
        map.retain(|_, entry| entry.expires > now);
        if map.len() >= REVERSE_CAPACITY {
            // ponytail: the reference is an LRU of 1024; dropping the whole
            // map at the cap holds the same memory ceiling without the
            // recency bookkeeping. Replace with an LRU if it ever bites.
            map.clear();
        }
        for answer in &message.answers {
            let ip = match &answer.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
                _ => continue,
            };
            map.insert(
                ip,
                ReverseEntry {
                    domain: codec::normalize_name(&answer.name.to_string()),
                    expires: received + Duration::from_secs(answer.ttl as u64),
                },
            );
        }
    }

    /// Reference `LookupReverseMapping`: the domain an IP was last answered
    /// under, while that answer's TTL still holds.
    pub fn reverse_domain(&self, ip: IpAddr) -> Option<String> {
        let map = self.reverse.as_ref()?.read().ok()?;
        let entry = map.get(&ip)?;
        (entry.expires > Instant::now()).then(|| entry.domain.clone())
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
        crate::logging::debug(format_args!(
            "[DNS-TRACE] query: {} ({:?}) from {:?} allow_fakeip={}",
            info.name, info.qtype, meta.source, allow_fakeip
        ));
        let mut opts = WalkOptions::default();
        let mut target: Option<Arc<ServerConfig>> = None;
        // what the last `evaluate` resolved: the response rules after it test
        // this answer, and `respond` hands it back to the client
        let mut evaluated: Option<Evaluated> = None;
        let mut answer_ips: Vec<std::net::IpAddr> = Vec::new();
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            let ips = evaluated.as_ref().map(|_| answer_ips.as_slice());
            if !rule.matches_stage(meta, &info, ips) {
                continue;
            }
            crate::logging::debug(format_args!(
                "[DNS-TRACE] rule [{}] MATCHED for {} action={:?}",
                rule_idx, info.name, rule.action
            ));
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
                    let raw = codec::predefined_response(&query_msg, predefined)
                        .map_err(std::io::Error::other)?;
                    // a rule answer has no transport behind it, and the
                    // reference records those as well
                    self.record_reverse(&raw, false);
                    return Ok(raw);
                }
                Action::Evaluate {
                    server,
                    rewrite_ttl,
                    disable_cache,
                } => {
                    let tag = if server.is_empty() {
                        self.final_tag.as_str()
                    } else {
                        server.as_str()
                    };
                    let Some(cfg) = self.servers.get(tag) else {
                        crate::logging::warn(format_args!(
                            "dns: transport not found for evaluate: {tag}"
                        ));
                        continue;
                    };
                    if cfg.is_fakeip() && !allow_fakeip {
                        continue;
                    }
                    let mut eval_opts = opts.clone();
                    if let Some(ttl) = rewrite_ttl {
                        eval_opts.rewrite_ttl = Some(*ttl);
                    }
                    eval_opts.disable_cache |= *disable_cache;
                    match self
                        .exchange_target(
                            &query_msg,
                            &info,
                            meta,
                            query,
                            allow_fakeip,
                            skip_cache_read,
                            Arc::clone(cfg),
                            eval_opts,
                        )
                        .await
                    {
                        Ok((raw, from_fakeip, received)) => {
                            answer_ips = codec::answer_ips(&raw).unwrap_or_default();
                            evaluated = Some(Evaluated {
                                raw,
                                from_fakeip,
                                received,
                            });
                        }
                        // a transport that cannot stage the answer stages
                        // nothing: the walk goes on and a rule that needs
                        // the answer reports it itself
                        Err(e) => {
                            crate::logging::warn(format_args!(
                                "dns: evaluate transport {tag} failed: {e}"
                            ));
                            continue;
                        }
                    }
                }
                Action::Respond => {
                    let Some(answer) = evaluated.as_ref() else {
                        return Err(std::io::Error::other(
                            "dns: respond without an evaluated response",
                        ));
                    };
                    let raw = match opts.rewrite_ttl {
                        Some(ttl) => codec::rewrite_ttl(&answer.raw, ttl)?,
                        None => answer.raw.clone(),
                    };
                    self.record_reverse_at(&raw, answer.from_fakeip, answer.received);
                    return codec::set_id(&raw, info.id);
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
        let from_fakeip = target.is_fakeip();
        let (raw, _, received) = self
            .exchange_target(
                &query_msg,
                &info,
                meta,
                query,
                allow_fakeip,
                skip_cache_read,
                target,
                opts,
            )
            .await?;
        // only the answer handed to the client earns a reverse entry; an
        // evaluated one that no rule picked is discarded with the walk
        self.record_reverse_at(&raw, from_fakeip, received);
        Ok(raw)
    }

    /// Everything below the rule walk: transport selection, the wire cache,
    /// TTL rewriting and the id stamp, shared by `evaluate` and by the route
    /// the walk settles on so both see the same options.
    ///
    /// The tuple carries the answer, whether it came out of a fakeip store,
    /// and when that answer was produced — a cache hit reports the original
    /// insert, so repeated hits cannot push a reverse entry past its TTL.
    #[allow(clippy::too_many_arguments)]
    async fn exchange_target(
        self: &Arc<Self>,
        query_msg: &hickory_proto::op::Message,
        info: &QueryInfo,
        meta: &QueryMeta,
        query: &[u8],
        allow_fakeip: bool,
        skip_cache_read: bool,
        target: Arc<ServerConfig>,
        opts: WalkOptions,
    ) -> std::io::Result<(Vec<u8>, bool, Instant)> {
        let from_fakeip = target.is_fakeip();
        let (raw, received) = self
            .exchange_answer(
                query_msg,
                info,
                meta,
                query,
                allow_fakeip,
                skip_cache_read,
                target,
                &opts,
            )
            .await?;
        // rewrite_ttl covers the hosts, local and fakeip answers as well,
        // which never reach the wire; running it a second time over an answer
        // the wire path already rewrote leaves that one unchanged
        let raw = match opts.rewrite_ttl {
            Some(ttl) => codec::rewrite_ttl(&raw, ttl)?,
            None => raw,
        };
        Ok((raw, from_fakeip, received))
    }

    /// The transport half of an exchange, without the rule walk. Reverse
    /// mapping is the caller's business: it records what it returns.
    #[allow(clippy::too_many_arguments)]
    async fn exchange_answer(
        self: &Arc<Self>,
        query_msg: &hickory_proto::op::Message,
        info: &QueryInfo,
        meta: &QueryMeta,
        query: &[u8],
        allow_fakeip: bool,
        skip_cache_read: bool,
        target: Arc<ServerConfig>,
        opts: &WalkOptions,
    ) -> std::io::Result<(Vec<u8>, Instant)> {
        // the hosts and local transports answer without touching the wire
        match target.kind {
            Kind::Hosts => {
                let sources = target
                    .hosts
                    .as_ref()
                    .ok_or_else(|| std::io::Error::other("dns: hosts server without sources"))?;
                let addrs = sources.lookup(&info.name);
                if addrs.is_empty() {
                    return codec::name_error(query_msg)
                        .map(|raw| (raw, Instant::now()))
                        .map_err(std::io::Error::other);
                }
                let raw = codec::synth_addresses(query_msg, &addrs, codec::DEFAULT_TTL)
                    .map_err(std::io::Error::other)?;
                return codec::set_id(&raw, info.id).map(|raw| (raw, Instant::now()));
            }
            Kind::Local | Kind::Dhcp | Kind::Resolved => {
                if mdns::is_local_domain(&info.name)
                    && let Some(mdns_result) = self.local_zone_mdns(query).await
                {
                    let raw = mdns_result?;
                    return codec::set_id(&raw, info.id).map(|raw| (raw, Instant::now()));
                }
                let addrs = match self.neighbor_lookup(&target, &info.name) {
                    Some(addresses) => addresses,
                    None => system_lookup(&info.name).await,
                };
                if addrs.is_empty() {
                    return codec::name_error(query_msg)
                        .map(|raw| (raw, Instant::now()))
                        .map_err(std::io::Error::other);
                }
                let raw = codec::synth_addresses(query_msg, &addrs, codec::DEFAULT_TTL)
                    .map_err(std::io::Error::other)?;
                return codec::set_id(&raw, info.id).map(|raw| (raw, Instant::now()));
            }
            _ => {}
        }

        // the group sits under the cache: only the answer it returns is cached
        if let Some(group) = target.group.clone() {
            let service: Arc<DnsService> = Arc::clone(self);
            let members: Arc<dyn group::Members> = service;
            let raw = group.exchange(members, query).await?;
            return codec::set_id(&raw, info.id).map(|raw| (raw, Instant::now()));
        }

        if target.is_fakeip() {
            let store = target
                .store
                .clone()
                .ok_or_else(|| std::io::Error::other("dns: fakeip server without store"))?;
            let raw = self.fakeip_answer(query_msg, info, &store, opts.rewrite_ttl)?;
            return Ok((raw, Instant::now()));
        }

        let use_cache = !self.disable_cache && !opts.disable_cache;
        let key = CacheKey {
            tag: target.tag.clone().into(),
            name: info.name.clone().into(),
            qtype: u16::from(info.qtype),
        };
        let optimistic = if self.optimistic_timeout.is_some() && use_cache {
            self.optimistic_timeout
        } else {
            None
        };

        if use_cache && !skip_cache_read {
            let now = std::time::Instant::now();
            let hit = {
                let mut cache = self.cache.write().expect("dns cache");
                cache.get(&key, now)
            };
            match hit {
                Some((CacheHit::Fresh(raw), received)) => {
                    let raw = if self.fastest_ip.enabled {
                        self.apply_fastest_ip(&raw, &info.name, now).await
                    } else {
                        raw.to_vec()
                    };
                    return codec::set_id(&raw, info.id).map(|raw| (raw, received));
                }
                Some((CacheHit::Stale(raw), received)) => {
                    self.spawn_refresh(meta.clone(), query.to_vec(), allow_fakeip, key.clone());
                    let raw = if self.fastest_ip.enabled {
                        self.apply_fastest_ip(&raw, &info.name, now).await
                    } else {
                        raw.to_vec()
                    };
                    return codec::set_id(&raw, info.id).map(|raw| (raw, received));
                }
                None => {}
            }
        }

        let lock = {
            let mut inflight = self.inflight.lock().expect("dns inflight");
            inflight.retain(|_, weak| weak.strong_count() > 0);
            match inflight.get(&key).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    inflight.insert(key.clone(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        let _guard = lock.lock().await;
        if use_cache && !skip_cache_read {
            let now = std::time::Instant::now();
            let hit = {
                let mut cache = self.cache.write().expect("dns cache");
                cache.get(&key, now)
            };
            if let Some((CacheHit::Fresh(raw), received)) = hit {
                let raw = if self.fastest_ip.enabled {
                    self.apply_fastest_ip(&raw, &info.name, now).await
                } else {
                    raw.to_vec()
                };
                return codec::set_id(&raw, info.id).map(|raw| (raw, received));
            }
        }

        let response = match self.exchange_remote(&target, query).await {
            Ok(resp) => {
                if self.serve_stale
                    && use_cache
                    && let Ok(meta) = codec::response_meta(&resp)
                    && meta.rcode == hickory_proto::op::ResponseCode::ServFail
                {
                    let now = Instant::now();
                    let stale_hit = {
                        let mut cache = self.cache.write().expect("dns cache");
                        cache.get_stale_fallback(&key, now, self.serve_stale_duration)
                    };
                    if let Some((stale_raw, rec)) = stale_hit {
                        crate::logging::debug(format_args!(
                            "dns: upstream {} returned SERVFAIL, returning stale cached response",
                            target.tag
                        ));
                        let stale_raw = if self.fastest_ip.enabled {
                            self.apply_fastest_ip(&stale_raw, &info.name, now).await
                        } else {
                            stale_raw.to_vec()
                        };
                        return codec::set_id(&stale_raw, info.id).map(|raw| (raw, rec));
                    }
                }
                resp
            }
            Err(e) => {
                if self.serve_stale && use_cache {
                    let now = Instant::now();
                    let stale_hit = {
                        let mut cache = self.cache.write().expect("dns cache");
                        cache.get_stale_fallback(&key, now, self.serve_stale_duration)
                    };
                    if let Some((stale_raw, rec)) = stale_hit {
                        crate::logging::debug(format_args!(
                            "dns: upstream {} failed ({e}), returning stale cached response",
                            target.tag
                        ));
                        let stale_raw = if self.fastest_ip.enabled {
                            self.apply_fastest_ip(&stale_raw, &info.name, now).await
                        } else {
                            stale_raw.to_vec()
                        };
                        return codec::set_id(&stale_raw, info.id).map(|raw| (raw, rec));
                    }
                }
                return Err(e);
            }
        };

        let now = Instant::now();
        let response = if self.fastest_ip.enabled {
            self.apply_fastest_ip(&response, &info.name, now).await
        } else {
            response
        };

        let rewritten: Arc<[u8]> = match opts.rewrite_ttl {
            Some(ttl) => codec::rewrite_ttl(&response, ttl)?.into(),
            None => response.into(),
        };

        let mut received = Instant::now();
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
                received = cache.insert(
                    key.clone(),
                    Arc::clone(&rewritten),
                    &meta_for_insert,
                    optimistic,
                );
            }
        }
        codec::set_id(&rewritten, info.id).map(|raw| (raw, received))
    }

    async fn apply_fastest_ip(&self, raw: &[u8], name: &str, now: Instant) -> Vec<u8> {
        let Ok(ips) = codec::answer_ips(raw) else {
            return raw.to_vec();
        };
        if ips.len() <= 1 {
            return raw.to_vec();
        }
        let winner = match self.fastest_ip_cache.get(name, &ips, now) {
            Some(cached) => Some(cached),
            None => {
                if let Some(best) =
                    fastest_ip::find_fastest_ip(&ips, self.fastest_ip.port, self.fastest_ip.timeout)
                        .await
                {
                    self.fastest_ip_cache.put(name.to_string(), best, now);
                    Some(best)
                } else {
                    None
                }
            }
        };
        match winner {
            Some(w) => {
                codec::reorder_answers_by_fastest_ip(raw, w).unwrap_or_else(|_| raw.to_vec())
            }
            None => raw.to_vec(),
        }
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
            // the key is cleared from any exit: a panic inside exchange_inner
            // would otherwise leave this name stuck as "refreshing" forever
            struct ClearRefresh {
                service: Arc<DnsService>,
                key: CacheKey,
            }
            impl Drop for ClearRefresh {
                fn drop(&mut self) {
                    let mut refreshing = self
                        .service
                        .refreshing
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    refreshing.remove(&self.key);
                }
            }
            let _clear = ClearRefresh {
                service: Arc::clone(&service),
                key,
            };
            let _ = service
                .exchange_inner(&meta, &query, allow_fakeip, true)
                .await;
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
        if cfg.kind == Kind::Mdns {
            // no address to resolve: the query goes to the multicast group
            return self.mdns_exchange(cfg, query).await;
        }
        let addr = self.resolve_server_addr(cfg, 0).await?;
        // reference `prepareExchangeMessage`: `client_subnet` rides along on
        // every query we send upstream
        let query = match self.client_subnet {
            Some((subnet, bits)) => codec::set_client_subnet(query, subnet, bits),
            None => query.to_vec(),
        };
        let raw = transport::exchange(cfg, addr, &query, &self.dialer()).await?;
        Ok(raw)
    }

    /// The mDNS lookup behind a `mdns` server. The reference waits one second
    /// unless the caller gave it a longer deadline, so a plain `timeout` is the
    /// ceiling here too.
    async fn mdns_exchange(&self, cfg: &ServerConfig, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let ifaces = mdns::interfaces(&cfg.mdns_interfaces)?;
        mdns::exchange(query, &ifaces, cfg.timeout.min(MDNS_TIMEOUT)).await
    }

    /// The mDNS lookup behind a `local` server, which the reference gives to the
    /// LAN for every name in an mDNS zone (`local.ExchangeAsync`): the `mdns`
    /// transport when one is configured, the multicast group otherwise.
    async fn local_zone_mdns(&self, query: &[u8]) -> Option<std::io::Result<Vec<u8>>> {
        let cfg = self
            .servers
            .values()
            .find(|cfg| cfg.kind == Kind::Mdns)
            .cloned();
        let (interfaces, timeout) = match &cfg {
            Some(cfg) => (cfg.mdns_interfaces.clone(), cfg.timeout),
            None => (Vec::new(), transport::DEFAULT_DNS_TIMEOUT),
        };
        Some(
            async move {
                let ifaces = mdns::interfaces(&interfaces)?;
                mdns::exchange(query, &ifaces, timeout.min(MDNS_TIMEOUT)).await
            }
            .await,
        )
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
            if cfg.kind == Kind::Tailscale {
                // This transport addresses an endpoint, never a network host.
                return Ok(SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0));
            }
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
                let cache_key = (resolver_tag.clone(), cfg.server.clone());
                let stale = |this: &Self| {
                    this.server_addrs
                        .lock()
                        .ok()
                        .and_then(|map| map.get(&cache_key).copied())
                        .map(|(addr, _)| SocketAddr::new(addr.ip(), cfg.port))
                };
                let fresh = |this: &Self| {
                    this.server_addrs
                        .lock()
                        .ok()
                        .and_then(|map| map.get(&cache_key).copied())
                        .filter(|(_, at)| at.elapsed() < SERVER_ADDR_TTL)
                        .map(|(addr, _)| SocketAddr::new(addr.ip(), cfg.port))
                };
                if let Some(addr) = fresh(self) {
                    return Ok(addr);
                }
                // only the outermost lookup takes the lock: a chained resolver
                // resolving its own address would otherwise wait on itself
                let _once = match depth {
                    0 => {
                        let lock = {
                            let mut locks =
                                self.server_addr_locks.lock().expect("server addr locks");
                            locks.retain(|_, weak| weak.strong_count() > 0);
                            match locks.get(&cache_key).and_then(Weak::upgrade) {
                                Some(lock) => lock,
                                None => {
                                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                                    locks.insert(cache_key.clone(), Arc::downgrade(&lock));
                                    lock
                                }
                            }
                        };
                        Some(lock.lock_owned().await)
                    }
                    _ => None,
                };
                if let Some(addr) = fresh(self) {
                    return Ok(addr);
                }
                // A resolver that just timed out must not take the transport
                // down with it: the last known address keeps serving until a
                // refresh succeeds. One dropped UDP probe used to kill the
                // whole dns-server transport every TTL window.
                let stale_or_err = |e: std::io::Error| -> std::io::Result<SocketAddr> {
                    if let Some(addr) = stale(self) {
                        crate::logging::warn(format_args!(
                            "dns: domain_resolver {resolver_tag:?} failed for {:?} ({e}), reusing stale address {addr}",
                            cfg.server
                        ));
                        return Ok(addr);
                    }
                    Err(std::io::Error::other(format!(
                        "dns: domain_resolver {resolver_tag:?} failed for {:?}: {e}",
                        cfg.server
                    )))
                };
                match self.lookup_via(resolver, &cfg.server, depth + 1).await {
                    Ok(addrs) if !addrs.is_empty() => {
                        let ip = pick_address(addrs, self.strategy)
                            .ok_or_else(|| std::io::Error::other("dns: no addresses resolved"))?;
                        let addr = SocketAddr::new(ip, cfg.port);
                        if let Ok(mut map) = self.server_addrs.lock() {
                            map.insert(cache_key.clone(), (addr, Instant::now()));
                        }
                        return Ok(addr);
                    }
                    Ok(_) => {
                        return stale_or_err(std::io::Error::other(format!(
                            "dns: domain_resolver {:?} returned no address for {:?}",
                            resolver_tag, cfg.server
                        )));
                    }
                    Err(e) => return stale_or_err(e),
                }
            }
            crate::logging::warn(format_args!(
                "dns: server {:?} host {:?} resolved via system (no domain_resolver or fallback)",
                cfg.tag, cfg.server
            ));
            let mut addrs = tokio::net::lookup_host((cfg.server.as_str(), cfg.port)).await?;
            addrs
                .next()
                .ok_or_else(|| std::io::Error::other("dns: system resolution returned nothing"))
        })
    }

    /// The `local` transport's `neighbor_domain`: `<host><suffix>` answered from
    /// the neighbour tables, the way the reference's
    /// `PreferredDomainResolver` answers before it falls back to the system.
    fn neighbor_lookup(&self, cfg: &ServerConfig, name: &str) -> Option<Vec<IpAddr>> {
        if cfg.neighbor_domain.is_empty() {
            return None;
        }
        let resolver = crate::route::neighbor::current()?;
        let canonical = codec::normalize_name(name);
        for entry in &cfg.neighbor_domain {
            // the entries keep their leading dot (`check` insists on it), so
            // the suffix is matched as written
            let suffix = codec::normalize_name(entry);
            if !suffix.starts_with('.') {
                continue;
            }
            let Some(host) = canonical.strip_suffix(&suffix) else {
                continue;
            };
            let addresses = resolver.lookup_addresses(host);
            if !addresses.is_empty() {
                return Some(addresses);
            }
        }
        None
    }

    /// One member exchange for a group: straight to the transport, with no
    /// rule walk and no cache of its own — the group owns both, and a nested
    /// group runs its own selection.
    async fn exchange_member(
        self: &Arc<Self>,
        tag: &str,
        query: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let cfg = self
            .servers
            .get(tag)
            .ok_or_else(|| std::io::Error::other(format!("DNS server not found: {tag}")))?;
        if let Some(group) = cfg.group.clone() {
            let service: Arc<DnsService> = Arc::clone(self);
            let members: Arc<dyn group::Members> = service;
            return group.exchange(members, query).await;
        }
        if matches!(cfg.kind, Kind::Local | Kind::Dhcp | Kind::Resolved) {
            let (query_msg, info) = codec::parse_query(query)?;
            if mdns::is_local_domain(&info.name)
                && let Some(mdns_result) = self.local_zone_mdns(query).await
            {
                return mdns_result;
            }
            let addrs = match self.neighbor_lookup(cfg, &info.name) {
                Some(addresses) => addresses,
                None => system_lookup(&info.name).await,
            };
            if addrs.is_empty() {
                return codec::name_error(&query_msg).map_err(std::io::Error::other);
            }
            return codec::synth_addresses(&query_msg, &addrs, codec::DEFAULT_TTL)
                .map_err(std::io::Error::other);
        }
        self.exchange_remote(cfg, query).await
    }

    /// Address lookup strictly through `resolver` (bootstrap), bypassing the
    /// rule walk so the chain cannot loop back onto itself.
    async fn lookup_via(
        self: &Arc<Self>,
        resolver: &Arc<ServerConfig>,
        host: &str,
        depth: u8,
    ) -> std::io::Result<Vec<IpAddr>> {
        if resolver.kind == Kind::Hosts {
            if let Some(sources) = resolver.hosts.as_ref() {
                return Ok(sources.lookup(host));
            }
            return Ok(Vec::new());
        }
        if matches!(resolver.kind, Kind::Local | Kind::Dhcp | Kind::Resolved) {
            let addrs = match self.neighbor_lookup(resolver, host) {
                Some(addresses) => addresses,
                None => system_lookup(host).await,
            };
            return Ok(addrs);
        }
        // Both families in flight at once, the way resolve_with already
        // queries: a sequential A-then-AAAA walk let a v6 probe the uplink
        // silently drops hold the server_addr_lock for its whole retransmit
        // schedule, and the bootstrap lookup behind it died at the 5s mark.
        let qtypes = self.strategy.query_types();
        let mut handles = Vec::with_capacity(qtypes.len());
        for &qtype in qtypes {
            let this = Arc::clone(self);
            let resolver = Arc::clone(resolver);
            let host = host.to_string();
            handles.push(tokio::spawn(async move {
                let query = codec::build_query(rand_id(), &host, qtype)?;
                let addr = this.resolve_server_addr(&resolver, depth).await?;
                let raw = transport::exchange(&resolver, addr, &query, &this.dialer()).await?;
                codec::answer_ips(&raw)
            }));
        }
        let mut order: Vec<_> = qtypes.iter().copied().zip(handles).collect();
        if matches!(self.strategy, Strategy::PreferIPv6) {
            order.reverse();
        }
        let mut out = Vec::new();
        let mut last_err = None;
        for (_qtype, mut handle) in order {
            // If we already have addresses for one family, don't hang indefinitely
            // on a second family that the uplink or DNS server drops.
            if !out.is_empty() {
                if self.strategy.preferred_family().is_some() {
                    handle.abort();
                    break;
                }
                // For AsIs, give the other family a short grace period (50ms)
                // so concurrent replies are not lost, but abort if it's lagging or dropped.
                match tokio::time::timeout(Duration::from_millis(50), &mut handle).await {
                    Ok(Ok(Ok(ips))) => out.extend(ips),
                    Ok(Ok(Err(e))) => last_err = Some(e),
                    Ok(Err(e)) => {
                        last_err = Some(std::io::Error::other(format!("dns: resolve task: {e}")))
                    }
                    Err(_) => {
                        handle.abort();
                        break;
                    }
                }
            } else {
                match handle.await {
                    Ok(Ok(ips)) => out.extend(ips),
                    Ok(Err(e)) => last_err = Some(e),
                    Err(e) => {
                        last_err = Some(std::io::Error::other(format!("dns: resolve task: {e}")))
                    }
                }
            }
        }
        match (out.is_empty(), last_err) {
            (true, Some(e)) => Err(e),
            _ => Ok(out),
        }
    }

    /// `resolve` rule action with an explicit server tag: lookup bypasses the
    /// dns rule walk and goes straight through that transport.
    pub async fn resolve_via(
        self: &Arc<Self>,
        server_tag: &str,
        host: &str,
    ) -> std::io::Result<Vec<IpAddr>> {
        self.resolve_via_with(server_tag, host, None).await
    }

    /// The same through one server, with the strategy the caller wants instead of
    /// the service default (`domain_strategy` on a dialer).
    pub async fn resolve_via_with(
        self: &Arc<Self>,
        server_tag: &str,
        host: &str,
        strategy: Option<Strategy>,
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
        Ok(order_addresses(addrs, strategy.unwrap_or(self.strategy)))
    }

    /// Resolve a hostname to addresses through the dns section
    /// (system-mode fallback lives in [`connect_tcp`]).
    pub async fn resolve(self: &Arc<Self>, host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.resolve_with(host, None).await
    }

    /// The same with the strategy the caller wants, which is the service default
    /// when it has none: `domain_strategy` on a dialer asks for exactly this.
    pub async fn resolve_with(
        self: &Arc<Self>,
        host: &str,
        strategy: Option<Strategy>,
    ) -> std::io::Result<Vec<IpAddr>> {
        let strategy = strategy.unwrap_or(self.strategy);
        let fut = async {
            if let Some(ip) = transport::is_ip_literal(host) {
                return Ok(vec![ip]);
            }
            let qtypes = strategy.query_types();
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
            Ok(order_addresses(collected, strategy))
        };
        tokio::time::timeout(RESOLVE_TIMEOUT_GUARD, fut)
            .await
            .map_err(|_| std::io::Error::other(format!("dns: resolve timeout for {host:?}")))?
    }
}

/// Reference `TransportManager.Start`: every group member must exist, must be
/// a transport that can fail over (`fakeip` and `hosts` cannot), and the
/// dependencies must resolve — what is left over is a cycle, reported with the
/// same text the reference's start loop produces.
fn start_dns_groups(
    servers: &HashMap<String, Arc<ServerConfig>>,
    order: &[String],
) -> anyhow::Result<()> {
    for tag in order {
        let Some(cfg) = servers.get(tag) else {
            continue;
        };
        let Some(group) = cfg.group.as_ref() else {
            continue;
        };
        for member in &group.members {
            let Some(other) = servers.get(member) else {
                anyhow::bail!("group[{tag}]: DNS server not found: {member}");
            };
            let kind = match other.kind {
                Kind::Fakeip => "fakeip",
                Kind::Hosts => "hosts",
                _ => continue,
            };
            anyhow::bail!("group[{tag}]: server type {kind} is not allowed in a group: {member}");
        }
    }
    // white/grey/black walk over the group dependencies; grey is a cycle
    let mut done: HashSet<&str> = HashSet::new();
    for tag in order {
        let mut path: Vec<&str> = Vec::new();
        if let Some(cycle) = group_cycle(servers, tag, &mut path, &mut done) {
            anyhow::bail!("circular server dependency: {}", cycle.join(" -> "));
        }
    }
    Ok(())
}

fn group_cycle<'a>(
    servers: &'a HashMap<String, Arc<ServerConfig>>,
    tag: &'a str,
    path: &mut Vec<&'a str>,
    done: &mut HashSet<&'a str>,
) -> Option<Vec<String>> {
    if done.contains(tag) {
        return None;
    }
    if let Some(at) = path.iter().position(|seen| *seen == tag) {
        let mut cycle: Vec<String> = path[at..].iter().map(|tag| tag.to_string()).collect();
        cycle.push(tag.to_string());
        return Some(cycle);
    }
    path.push(tag);
    let members: Vec<String> = servers
        .get(tag)
        .and_then(|cfg| cfg.group.as_ref())
        .map(|group| group.members.clone())
        .unwrap_or_default();
    for member in members {
        let found = servers.get_key_value(&member).map(|(key, _)| key.as_str());
        let Some(key) = found else { continue };
        if let Some(cycle) = group_cycle(servers, key, path, done) {
            return Some(cycle);
        }
    }
    path.pop();
    done.insert(tag);
    None
}

impl group::Members for DnsService {
    fn exchange(
        self: Arc<Self>,
        tag: String,
        query: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<u8>>> + Send>> {
        Box::pin(async move { self.exchange_member(&tag, &query).await })
    }
}

/// `dns.client_subnet`: a CIDR, or a bare address which the reference turns
/// into a host prefix. Returns the masked address and its prefix length.
fn parse_client_subnet(value: Option<&Value>) -> anyhow::Result<Option<(IpAddr, u8)>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        anyhow::bail!("dns.client_subnet: must be a string");
    };
    let bad = || anyhow::anyhow!("dns.client_subnet: {raw:?} is not an IP prefix");
    let (addr, bits) = match raw.rsplit_once('/') {
        Some((addr, bits)) => (
            transport::is_ip_literal(addr).ok_or_else(bad)?,
            bits.parse().map_err(|_| bad())?,
        ),
        None => {
            let addr = transport::is_ip_literal(raw).ok_or_else(bad)?;
            (addr, if addr.is_ipv4() { 32 } else { 128 })
        }
    };
    if bits > if addr.is_ipv4() { 32 } else { 128 } {
        return Err(bad());
    }
    Ok(Some((mask_host_bits(addr, bits), bits)))
}

/// Zero the host bits, the way `netip.ParsePrefix` stores a prefix.
fn mask_host_bits(addr: IpAddr, bits: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let masked = match bits {
                0 => 0,
                bits => u32::from(v4) & (!0u32 << (32 - bits)),
            };
            IpAddr::V4(masked.into())
        }
        IpAddr::V6(v6) => {
            let masked = match bits {
                0 => 0,
                bits => u128::from(v6) & (!0u128 << (128 - bits)),
            };
            IpAddr::V6(masked.into())
        }
    }
}

pub(crate) fn order_addresses(mut addrs: Vec<IpAddr>, strategy: Strategy) -> Vec<IpAddr> {
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

/// The `local` transport hands the question to the system resolver.
pub(crate) async fn system_lookup(host: &str) -> Vec<std::net::IpAddr> {
    match tokio::net::lookup_host((host, 0)).await {
        Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
        Err(_) => Vec::new(),
    }
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

    #[tokio::test]
    async fn a_local_server_hands_mdns_zones_to_the_lan() {
        // the mdns server names an interface that does not exist, so the query
        // fails with the mDNS error instead of quietly falling through to the
        // system resolver -- which is how we know the hand-off happened
        let root = serde_json::json!({
            "dns": {
                "servers": [
                    {"type": "mdns", "tag": "m", "interface": "no-such-interface"},
                    {"type": "local", "tag": "l"}
                ],
                "final": "l",
                "disable_cache": true
            }
        });
        let svc = Arc::new(DnsService::build(&root).unwrap().expect("service"));
        let meta = QueryMeta {
            inbound: Some("dns-in".into()),
            source: None,
            network: Some("udp".into()),
        };
        let query = codec::build_query(1, "printer.local", RecordType::A).expect("query");
        let err = svc
            .exchange(&meta, &query, true)
            .await
            .expect_err("no interface, no mDNS answer");
        assert!(
            err.to_string().contains("missing usable mDNS interfaces"),
            "{err}"
        );
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

    #[test]
    fn smart_dns_config_parse() {
        let root = serde_json::json!({
            "dns": {
                "servers": [{"type": "udp", "tag": "u", "server": "127.0.0.1"}],
                "serve_stale": {
                    "enabled": true,
                    "timeout": "3d"
                },
                "fastest_ip": {
                    "enabled": true,
                    "timeout": "350ms",
                    "port": 8443
                }
            }
        });
        let svc = DnsService::build(&root).unwrap().expect("service");
        assert!(svc.serve_stale);
        assert_eq!(svc.serve_stale_duration, Duration::from_secs(3 * 24 * 3600));
        assert!(svc.fastest_ip.enabled);
        assert_eq!(svc.fastest_ip.timeout, Duration::from_millis(350));
        assert_eq!(svc.fastest_ip.port, 8443);

        let root_bool = serde_json::json!({
            "dns": {
                "servers": [{"type": "udp", "tag": "u", "server": "127.0.0.1"}],
                "serve_stale": true,
                "fastest_ip": true
            }
        });
        let svc_bool = DnsService::build(&root_bool).unwrap().expect("service");
        assert!(svc_bool.serve_stale);
        assert_eq!(
            svc_bool.serve_stale_duration,
            Duration::from_secs(7 * 24 * 3600)
        );
        assert!(svc_bool.fastest_ip.enabled);
        assert_eq!(svc_bool.fastest_ip.timeout, Duration::from_millis(200));
        assert_eq!(svc_bool.fastest_ip.port, 443);
    }

    #[tokio::test]
    async fn serve_stale_recovers_from_upstream_failure() {
        // Upstream points to a local address with no listener on UDP port 1
        let root = serde_json::json!({
            "dns": {
                "servers": [{"type": "udp", "tag": "dead", "server": "127.0.0.1", "server_port": 1}],
                "final": "dead",
                "serve_stale": true,
                "timeout": "50ms"
            }
        });
        let svc = Arc::new(DnsService::build(&root).unwrap().expect("service"));

        // Synthetic cached answer with 1s TTL
        let q_raw = codec::build_query(1, "stale.test", RecordType::A).unwrap();
        let (q_msg, _q_info) = codec::parse_query(&q_raw).unwrap();
        let test_ip: IpAddr = "1.2.3.4".parse().unwrap();
        let resp_raw = codec::synth_addresses(&q_msg, &[test_ip], 1).unwrap();

        let key = CacheKey {
            tag: "dead".into(),
            name: "stale.test".into(),
            qtype: 1,
        };
        let meta_resp = codec::response_meta(&resp_raw).unwrap();
        // Insert into cache
        svc.cache
            .write()
            .unwrap()
            .insert(key.clone(), resp_raw.clone(), &meta_resp, None);

        // Sleep to ensure normal TTL (1s) expires
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Verify normal cache hit is now expired (None)
        let now = Instant::now();
        assert!(svc.cache.write().unwrap().get(&key, now).is_none());
        assert!(
            svc.cache
                .write()
                .unwrap()
                .get_stale_fallback(&key, now, Duration::from_secs(60))
                .is_some()
        );

        // When exchange is performed, upstream fails because port 1 is dead or times out.
        // But with serve_stale enabled, it recovers and returns the stale cached response!
        let meta = QueryMeta::default();
        let out = svc
            .exchange(&meta, &q_raw, false)
            .await
            .expect("serve_stale fallback");
        let ips = codec::answer_ips(&out).expect("answer IPs");
        assert_eq!(ips, vec![test_ip]);
    }
}
