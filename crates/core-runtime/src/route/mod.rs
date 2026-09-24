//! Routing engine: rule walk with actions (route / route-options / reject /
//! hijack-dns / sniff / resolve), connection context, and outbound dispatch.

pub mod rule;
pub mod sniff;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use crate::inbound::Target;
pub use rule::{Action, RejectMethod, ResolveAction, RouteOptions, Rule, apply_route_options};

use crate::dns::{self, QueryMeta};
use crate::inbound::Conn;
use crate::logging;
use crate::outbound::block::Block;
use crate::outbound::direct::Direct;
use crate::outbound::proxy::{HttpOut, Selector, Socks};
use crate::outbound::secure::{Trojan, Vless};
use crate::outbound::shadowsocks::stream::Shadowsocks;
use crate::outbound::urltest::Urltest;
use crate::outbound::vmess::Vmess;

/// Result of a completed rule walk for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Outbound(usize),
    HijackDns,
}

/// Sniff outcome recorded on the context for duplicate-skip logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffError {
    NeedMore,
    Failed(String),
}

/// Per-connection metadata visible to rule matchers and actions.
#[derive(Debug, Clone)]
pub struct ConnContext {
    pub inbound: Option<String>,
    pub source: SocketAddr,
    pub destination: Target,
    pub origin_destination: Option<Target>,
    pub network: &'static str,
    pub protocol: Option<String>,
    pub domain: Option<String>,
    pub auth_user: Option<String>,
    pub client: Option<String>,
    pub destination_addresses: Vec<IpAddr>,
    pub fakeip: bool,
    pub sniff_prefix: Vec<u8>,
    pub sniff_error: Option<SniffError>,
    pub sniffer_names: Vec<String>,
    pub ip_version: Option<u8>,
    pub route_original_destination: Option<Target>,
}

use std::net::IpAddr;

impl ConnContext {
    pub fn new(
        inbound: &str,
        source: SocketAddr,
        destination: Target,
        network: &'static str,
    ) -> Self {
        Self {
            inbound: Some(inbound.to_string()),
            source,
            destination,
            origin_destination: None,
            network,
            protocol: None,
            domain: None,
            auth_user: None,
            client: None,
            destination_addresses: Vec::new(),
            fakeip: false,
            sniff_prefix: Vec::new(),
            sniff_error: None,
            sniffer_names: Vec::new(),
            ip_version: None,
            route_original_destination: None,
        }
    }
}

pub enum Outbound {
    Direct(Direct),
    Block(Block),
    Socks(Socks),
    Http(HttpOut),
    Shadowsocks(Shadowsocks),
    Vless(Vless),
    Trojan(Trojan),
    Vmess(Vmess),
    Urltest(Urltest),
    Selector(Selector),
}

impl Outbound {
    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        match self {
            Outbound::Direct(direct) => direct
                .connect(target)
                .await
                .map(|s| Conn::Plain(Box::new(s))),
            Outbound::Block(block) => block
                .connect(target)
                .await
                .map(|s| Conn::Plain(Box::new(s))),
            Outbound::Socks(socks) => socks
                .connect(target)
                .await
                .map(|s| Conn::Plain(Box::new(s))),
            Outbound::Http(http) => http.connect(target).await.map(|s| Conn::Plain(Box::new(s))),
            Outbound::Shadowsocks(ss) => ss
                .connect(target)
                .await
                .map(|(reader, writer)| Conn::Shadowsocks(Box::new(reader), writer)),
            Outbound::Vless(vless) => vless.connect(target).await.map(Conn::Plain),
            Outbound::Trojan(trojan) => trojan.connect(target).await.map(Conn::Plain),
            Outbound::Vmess(vmess) => vmess.connect(target).await.map(Conn::Plain),
            Outbound::Urltest(urltest) => urltest.connect(router, target).await,
            Outbound::Selector(selector) => selector.connect(router, target).await,
        }
    }

    fn build(obj: &Value, at: &str) -> anyhow::Result<Outbound> {
        let ty = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing type"))?;
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        match ty {
            "direct" => Ok(Outbound::Direct(Direct)),
            "block" => Ok(Outbound::Block(Block)),
            "socks" => Ok(Outbound::Socks(Socks::build(obj, at)?)),
            "http" => Ok(Outbound::Http(HttpOut::build(obj, at)?)),
            "shadowsocks" => Ok(Outbound::Shadowsocks(Shadowsocks::build(obj, at)?)),
            "vless" => Ok(Outbound::Vless(Vless::build(obj, at)?)),
            "trojan" => Ok(Outbound::Trojan(Trojan::build(obj, at)?)),
            "vmess" => Ok(Outbound::Vmess(Vmess::build(obj, at)?)),
            "urltest" => Ok(Outbound::Urltest(Urltest::build(obj, at)?)),
            "selector" => Ok(Outbound::Selector(Selector::build(obj, at)?)),
            other => Err(anyhow::anyhow!(
                "{at}: outbound type {other:?} not implemented yet"
            )),
        }
    }
}

/// `route` section fields accepted by check but not yet honored at runtime.
const ROUTE_UNIMPL_FIELDS: &[&str] = &[
    "geoip",
    "geosite",
    "rule_set",
    "find_process",
    "find_neighbor",
    "dhcp_lease_files",
    "auto_detect_interface",
    "override_android_vpn",
    "default_interface",
    "default_mark",
    "default_domain_resolver",
    "default_domain_strategy",
    "default_network_strategy",
    "default_network_type",
    "default_fallback_network_type",
    "default_fallback_delay",
    "default_http_client",
];

pub struct Router {
    outbounds: Vec<Outbound>,
    tags: HashMap<String, usize>,
    default: usize,
    rules: Vec<Rule>,
    probe_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Router {
    /// Abort the urltest probe loops (called on instance shutdown).
    pub fn take_probe_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut *self.probe_tasks.lock().expect("probe tasks"))
    }
}

impl Router {
    pub fn new(root: &Value) -> anyhow::Result<Arc<Router>> {
        let empty = Vec::new();
        let outbounds_list = root
            .get("outbounds")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let mut outbounds = Vec::with_capacity(outbounds_list.len());
        let mut tags = HashMap::new();
        for (i, obj) in outbounds_list.iter().enumerate() {
            let tag = obj
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !tag.is_empty() {
                if tags.contains_key(&tag) {
                    anyhow::bail!("duplicate outbound tag: {tag}");
                }
                tags.insert(tag, i);
            }
            outbounds.push(Outbound::build(obj, &format!("outbounds[{i}]"))?);
        }
        for outbound in &mut outbounds {
            match outbound {
                Outbound::Selector(selector) => selector.resolve(&tags)?,
                Outbound::Urltest(urltest) => urltest.resolve(&tags)?,
                _ => {}
            }
        }

        let mut rules = Vec::new();
        if let Some(route) = root.get("route")
            && let Some(map) = route.as_object()
        {
            for key in ROUTE_UNIMPL_FIELDS {
                if map.get(*key).is_some_and(|v| !v.is_null()) {
                    logging::warn(format_args!("route.{key} is not implemented yet (ignored)"));
                }
            }
            if let Some(list) = map.get("rules").and_then(Value::as_array) {
                for (i, obj) in list.iter().enumerate() {
                    rules.push(Rule::build(obj, &format!("route.rules[{i}]"), true)?);
                }
            }
        }

        let default = match root
            .get("route")
            .and_then(|r| r.get("final"))
            .and_then(Value::as_str)
        {
            Some(final_tag) => {
                let idx = *tags.get(final_tag).ok_or_else(|| {
                    anyhow::anyhow!("route.final: unknown outbound {final_tag:?}")
                })?;
                logging::info(format_args!("routing final: {final_tag}"));
                idx
            }
            None => 0,
        };
        let router = Arc::new(Router {
            outbounds,
            tags,
            default,
            rules,
            probe_tasks: std::sync::Mutex::new(Vec::new()),
        });
        for outbound in &router.outbounds {
            if let Outbound::Urltest(urltest) = outbound {
                let handle = urltest.spawn(Arc::clone(&router));
                router.probe_tasks.lock().expect("probe tasks").push(handle);
            }
        }
        Ok(router)
    }

    pub fn index_of(&self, tag: &str) -> Option<usize> {
        self.tags.get(tag).copied()
    }

    pub fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        self.connect_index(self.default, target)
    }

    /// dyn-erased so selector chains do not form an infinitely sized future.
    pub fn connect_index<'a>(
        &'a self,
        index: usize,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        Box::pin(async move {
            let Some(outbound) = self.outbounds.get(index) else {
                return Err(io::Error::other("outbound index out of range"));
            };
            outbound.connect(self, target).await
        })
    }

    /// Walk `route.rules` for one connection: prepare metadata, apply phase-A
    /// options, run phase-B sniff/resolve, stop on a terminal action.
    pub async fn route<S>(&self, client: &mut S, ctx: &mut ConnContext) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.route_walk(Some(client), ctx).await
    }

    /// Rule walk without a client stream (HTTP plain forward: the request
    /// head is already consumed and `protocol` is set, so sniff is skipped).
    pub async fn route_raw(&self, ctx: &mut ConnContext) -> io::Result<Decision> {
        self.route_walk::<tokio::net::TcpStream>(None, ctx).await
    }

    async fn route_walk<S>(
        &self,
        mut client: Option<&mut S>,
        ctx: &mut ConnContext,
    ) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        prepare(ctx);
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.matches(ctx) {
                continue;
            }
            let action = rule.action();
            logging::debug(format_args!(
                "route: match[{i}] {} => {}",
                ctx.destination,
                action.type_name()
            ));

            if let Some(opts) = action.route_options() {
                apply_route_options(ctx, opts);
            }

            match action {
                Action::Sniff { sniffer, timeout } => {
                    if let Some(c) = client.as_deref_mut() {
                        sniff::action_sniff(c, ctx, sniffer, *timeout).await;
                    }
                }
                Action::Resolve(res) => {
                    action_resolve(ctx, res).await?;
                }
                _ => {}
            }

            match action {
                Action::Route { outbound, .. } => {
                    return Ok(Decision::Outbound(self.outbound_index(outbound)?));
                }
                Action::Bypass { outbound, .. } if !outbound.is_empty() => {
                    return Ok(Decision::Outbound(self.outbound_index(outbound)?));
                }
                Action::Reject { method } => {
                    return Err(reject_error(*method));
                }
                Action::HijackDns => return Ok(Decision::HijackDns),
                _ => {}
            }
        }
        Ok(Decision::Outbound(self.default))
    }

    fn outbound_index(&self, tag: &str) -> io::Result<usize> {
        self.index_of(tag)
            .ok_or_else(|| io::Error::other(format!("outbound not found: {tag}")))
    }
}

/// FakeIP reverse mapping + ip_version before the rule walk.
fn prepare(ctx: &mut ConnContext) {
    if let Target::Ip(addr) = ctx.destination
        && let Some(dns) = dns::current()
        && let Some(domain) = dns.fakeip_domain(addr.ip())
    {
        ctx.origin_destination = Some(ctx.destination.clone());
        ctx.destination = Target::Domain(domain, addr.port());
        ctx.fakeip = true;
        logging::debug(format_args!(
            "route: found fakeip domain: {}",
            ctx.destination
        ));
    }
    ctx.ip_version = match ctx.destination {
        Target::Ip(a) => Some(if a.is_ipv6() { 6 } else { 4 }),
        Target::Domain(..) => None,
    };
}

fn reject_error(method: RejectMethod) -> io::Error {
    match method {
        RejectMethod::Default => {
            io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by rule")
        }
        RejectMethod::Drop => io::Error::new(io::ErrorKind::ConnectionReset, "dropped by rule"),
        RejectMethod::Reply => {
            io::Error::other("reject method `reply` is not supported for TCP connections")
        }
    }
}

async fn action_resolve(ctx: &mut ConnContext, action: &ResolveAction) -> io::Result<()> {
    let Target::Domain(host, _) = &ctx.destination else {
        return Ok(());
    };
    let host = host.clone();
    let Some(dns) = dns::current() else {
        return Err(io::Error::other("resolve action requires dns section"));
    };
    let addrs = match &action.server {
        Some(tag) => dns.resolve_via(tag, &host).await?,
        None => dns.resolve(&host).await?,
    };
    logging::debug(format_args!(
        "route: resolved [{}] for {host}",
        addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    ctx.destination_addresses = addrs;
    Ok(())
}

const DNS_HIJACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve length-prefixed TCP DNS queries through the dns service
/// (`action: hijack-dns`); `prefix` is sniffed bytes already read.
pub async fn hijack_dns<S>(client: &mut S, ctx: &ConnContext) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dns =
        dns::current().ok_or_else(|| io::Error::other("hijack-dns: dns service not configured"))?;
    let mut buf = ctx.sniff_prefix.clone();
    let mut chunk = vec![0u8; 4096];
    loop {
        while buf.len() < 2 {
            match tokio::time::timeout(DNS_HIJACK_TIMEOUT, client.read(&mut chunk)).await {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "hijack-dns: read timeout",
                    ));
                }
            }
        }
        let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        if len < 12 {
            return Err(io::Error::other("hijack-dns: bad query length"));
        }
        while buf.len() < 2 + len {
            match tokio::time::timeout(DNS_HIJACK_TIMEOUT, client.read(&mut chunk)).await {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "hijack-dns: truncated query",
                    ));
                }
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "hijack-dns: read timeout",
                    ));
                }
            }
        }
        let query = buf[2..2 + len].to_vec();
        buf.drain(..2 + len);

        let meta = QueryMeta {
            inbound: ctx.inbound.clone(),
            source: Some(ctx.source.ip()),
            network: Some("tcp".to_string()),
        };
        let resp = dns.exchange(&meta, &query, true).await?;
        let mut framed = Vec::with_capacity(2 + resp.len());
        framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        framed.extend_from_slice(&resp);
        client.write_all(&framed).await?;
    }
}
