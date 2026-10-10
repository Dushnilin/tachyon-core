//! Routing engine: rule walk with actions (route / route-options / reject /
//! hijack-dns / sniff / resolve), connection context, and outbound dispatch.

pub mod mmap_set;
pub mod neighbor;
pub mod process;
pub mod rule;
pub mod rule_set;
pub mod rule_set_index;
pub mod rule_set_remote;
pub mod sniff;

use std::borrow::Cow;
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
pub use rule::{
    Action, RejectFlood, RejectMethod, ResolveAction, RouteOptions, Rule, apply_route_options,
};

use crate::dns::{self, QueryMeta};
use crate::inbound::Conn;
use crate::logging;
use crate::outbound::anytls::AnyTls;
use crate::outbound::block::Block;
use crate::outbound::chain::Chain;
use crate::outbound::direct::Direct;
use crate::outbound::fptn::Fptn;
use crate::outbound::hysteria2::Hysteria2;
use crate::outbound::masque::Masque;
use crate::outbound::mieru::Mieru;
use crate::outbound::naive::Naive;
use crate::outbound::openvpn::OpenVpn;
use crate::outbound::proxy::{HttpOut, Selector, Socks};
use crate::outbound::secure::{Trojan, Vless};
use crate::outbound::shadowsocks::stream::Shadowsocks;
use crate::outbound::shadowtls::ShadowTls;
use crate::outbound::snell::Snell;
use crate::outbound::tailscale::Tailscale;
use crate::outbound::tuic::Tuic;
use crate::outbound::urltest::Urltest;
use crate::outbound::vmess::Vmess;
use crate::outbound::wireguard::WireGuard;

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
    /// Clash connection view: the rule that produced the decision.
    pub matched_rule: Option<(String, String)>,
    /// `route.find_neighbor`: the client's hardware address, when the
    /// neighbour tables know it.
    pub source_mac: Option<neighbor::MacAddr>,
    /// `route.find_neighbor`: the client's DHCP hostname.
    pub source_hostname: Option<String>,
    /// `route.find_process`: the process that opened the connection.
    pub process: Option<process::ProcessInfo>,
    pub udp_timeout: Option<Duration>,
    pub udp_disable_domain_unmapping: Option<bool>,
    pub tls_fragment: Option<bool>,
    pub tls_record_fragment: Option<bool>,
}

use std::net::IpAddr;

impl Default for ConnContext {
    fn default() -> Self {
        Self {
            inbound: None,
            source: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            destination: Target::Ip(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            )),
            origin_destination: None,
            network: "tcp",
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
            matched_rule: None,
            source_mac: None,
            source_hostname: None,
            process: None,
            udp_timeout: None,
            udp_disable_domain_unmapping: None,
            tls_fragment: None,
            tls_record_fragment: None,
        }
    }
}

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
            network,
            ..Default::default()
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
    Hysteria2(Hysteria2),
    Fptn(Fptn),
    Masque(Masque),
    Snell(Snell),
    Mieru(Mieru),
    Tuic(Tuic),
    WireGuard(WireGuard),
    OpenVpn(OpenVpn),
    Naive(Naive),
    AnyTls(AnyTls),
    Urltest(Urltest),
    Selector(Selector),
    Chain(Chain),
    ShadowTls(ShadowTls),
    Tailscale(Tailscale),
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
            Outbound::Socks(socks) => socks.connect(target).await.map(Conn::Plain),
            Outbound::Http(http) => http.connect(target).await.map(Conn::Plain),
            Outbound::Shadowsocks(ss) => ss
                .connect(target)
                .await
                .map(|(reader, writer)| Conn::Shadowsocks(Box::new(reader), writer)),
            Outbound::Vless(vless) => vless.connect(target).await.map(Conn::Plain),
            Outbound::Trojan(trojan) => trojan.connect(target).await.map(Conn::Plain),
            Outbound::Vmess(vmess) => vmess.connect(target).await.map(Conn::Plain),
            Outbound::Hysteria2(hy2) => hy2.connect(target).await.map(Conn::Plain),
            Outbound::Fptn(fptn) => fptn.connect(target).await.map(Conn::Plain),
            Outbound::Masque(masque) => masque.connect(target).await.map(Conn::Plain),
            Outbound::Snell(snell) => snell.connect(target).await.map(Conn::Plain),
            Outbound::Mieru(mieru) => mieru.connect(target).await.map(Conn::Plain),
            Outbound::Tuic(tuic) => tuic.connect(target).await.map(Conn::Plain),
            Outbound::WireGuard(wg) => wg.connect(target).await.map(Conn::Plain),
            Outbound::OpenVpn(ovpn) => ovpn.connect(target).await.map(Conn::Plain),
            Outbound::Naive(naive) => naive.connect(target).await.map(Conn::Plain),
            Outbound::AnyTls(anytls) => anytls.connect(target).await.map(Conn::Plain),
            Outbound::Urltest(urltest) => urltest.connect(router, target).await,
            Outbound::Selector(selector) => selector.connect(router, target).await,
            Outbound::Chain(chain) => chain.connect(router, target).await,
            Outbound::ShadowTls(stls) => stls.connect(target).await.map(Conn::Plain),
            Outbound::Tailscale(ts) => ts.connect(target).await.map(Conn::Plain),
        }
    }

    /// UDP dial; only outbounds that can carry datagrams implement it.
    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        match self {
            Outbound::Direct(direct) => direct.connect_udp(target).await,
            Outbound::Socks(socks) => socks.connect_udp(target).await,
            Outbound::Hysteria2(hy2) => hy2.connect_udp(target).await,
            Outbound::Fptn(fptn) => fptn.connect_udp(target).await,
            Outbound::Masque(masque) => masque.connect_udp(target).await,
            Outbound::Vless(vless) => vless.connect_udp(target).await,
            Outbound::Vmess(vmess) => vmess.connect_udp(target).await,
            Outbound::Trojan(trojan) => trojan.connect_udp(target).await,
            Outbound::Snell(snell) => snell.connect_udp(target).await,
            Outbound::Mieru(mieru) => mieru.connect_udp(target).await,
            Outbound::Tuic(tuic) => tuic.connect_udp(target).await,
            Outbound::WireGuard(wg) => wg.connect_udp(target).await,
            Outbound::OpenVpn(ovpn) => ovpn.connect_udp(target).await,
            Outbound::Naive(naive) => naive.connect_udp(target).await,
            Outbound::AnyTls(anytls) => anytls.connect_udp(target).await,
            Outbound::Block(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "blocked by outbound",
            )),
            Outbound::Selector(selector) => selector.connect_udp(router, target).await,
            Outbound::Urltest(urltest) => urltest.connect_udp(router, target).await,
            Outbound::Chain(chain) => chain.connect_udp(router, target).await,
            Outbound::ShadowTls(stls) => stls.connect_udp(target).await,
            Outbound::Tailscale(ts) => ts.connect_udp(target).await,
            _ => Err(io::Error::other("udp not supported by this outbound")),
        }
    }

    pub fn apply_dial_defaults(
        &mut self,
        default_mark: Option<u32>,
        default_interface: Option<&str>,
    ) {
        let apply = |dial: &mut crate::outbound::dial::DialOptions| {
            if dial.routing_mark.is_none() {
                dial.routing_mark = default_mark;
            }
            if dial.bind_interface.is_none() {
                dial.bind_interface = default_interface.map(str::to_string);
            }
        };

        match self {
            Outbound::Direct(d) => apply(&mut d.dial),
            Outbound::Vless(v) => apply(&mut v.dial),
            Outbound::Trojan(t) => apply(&mut t.dial),
            Outbound::Shadowsocks(s) => apply(&mut s.dial),
            Outbound::Vmess(m) => apply(&mut m.dial),
            Outbound::Socks(s) => apply(&mut s.dial),
            Outbound::Http(h) => apply(&mut h.dial),
            Outbound::ShadowTls(s) => apply(&mut s.dial),
            Outbound::Naive(n) => apply(&mut n.dial),
            Outbound::Snell(s) => apply(&mut s.dial),
            Outbound::Mieru(m) => apply(&mut m.dial),
            _ => {}
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
            "direct" => Ok(Outbound::Direct(Direct::build(obj, at)?)),
            "block" => Ok(Outbound::Block(Block)),
            "socks" => Ok(Outbound::Socks(Socks::build(obj, at)?)),
            "http" => Ok(Outbound::Http(HttpOut::build(obj, at)?)),
            "shadowsocks" => Ok(Outbound::Shadowsocks(Shadowsocks::build(obj, at)?)),
            "vless" => Ok(Outbound::Vless(Vless::build(obj, at)?)),
            "trojan" => Ok(Outbound::Trojan(Trojan::build(obj, at)?)),
            "vmess" => Ok(Outbound::Vmess(Vmess::build(obj, at)?)),
            "hysteria2" => Ok(Outbound::Hysteria2(Hysteria2::build(obj, at)?)),
            "fptn" => Ok(Outbound::Fptn(Fptn::build(obj, at)?)),
            "masque" => Ok(Outbound::Masque(Masque::build(obj, at)?)),
            "snell" => Ok(Outbound::Snell(Snell::build(obj, at)?)),
            "mieru" => Ok(Outbound::Mieru(Mieru::build(obj, at)?)),
            "tuic" => Ok(Outbound::Tuic(Tuic::build(obj, at)?)),
            "naive" => Ok(Outbound::Naive(Naive::build(obj, at)?)),
            "anytls" => Ok(Outbound::AnyTls(AnyTls::build(obj, at)?)),
            "urltest" => Ok(Outbound::Urltest(Urltest::build(obj, at)?)),
            "selector" => Ok(Outbound::Selector(Selector::build(obj, at)?)),
            "chain" => Ok(Outbound::Chain(Chain::build(obj, at)?)),
            "shadowtls" => Ok(Outbound::ShadowTls(ShadowTls::build(obj, at)?)),
            other => Err(anyhow::anyhow!(
                "{at}: outbound type {other:?} not implemented yet"
            )),
        }
    }
}

/// `route` section fields accepted by check but not yet honored at runtime.
/// `route.rule_set`: the inline, local and remote variants. Inline and local
/// sets load here; a remote set needs the downloader and is reported instead of
/// being silently ignored.
pub(crate) fn build_rule_sets(
    route: &serde_json::Map<String, Value>,
    clients: &crate::http_client::Registry,
) -> anyhow::Result<rule_set::RuleSetRegistry> {
    let mut registry = rule_set::RuleSetRegistry::new();
    let mut remotes = rule_set_remote::RemoteRegistry::new();
    let Some(list) = route.get("rule_set").filter(|value| !value.is_null()) else {
        return Ok(registry);
    };
    let entries = list
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("route.rule_set: must be an array"))?;
    for (i, entry) in entries.iter().enumerate() {
        let at = format!("route.rule_set[{i}]");
        let entry = entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let ty = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("inline");
        let tags = rule_set_tags(entry, &at)?;
        let use_mmap = entry.get("mmap").and_then(Value::as_bool).unwrap_or(false);
        let mode_str = entry.get("mode").and_then(Value::as_str).unwrap_or("auto");
        let mode = match mode_str {
            "memory" => mmap_set::MmapMode::Memory,
            "mmap" => mmap_set::MmapMode::Mmap,
            _ => mmap_set::MmapMode::Auto,
        };

        match ty {
            "inline" => {
                let rules = entry
                    .get("rules")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if use_mmap {
                    let mut compiler = mmap_set::RuleSetCompiler::new();
                    let tsrs_bytes = compiler.compile(&rules)?;
                    let cache_file = entry.get("cache_file").and_then(Value::as_str);
                    let target_path = if let Some(cf) = cache_file {
                        std::path::PathBuf::from(cf)
                    } else {
                        rule_set_remote::default_tsrs_cache_path(&tags[0])
                    };
                    if let Some(parent) = target_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    std::fs::write(&target_path, &tsrs_bytes)?;
                    let mmap_set = std::sync::Arc::new(mmap_set::MmapRuleSet::open_with_mode(
                        &target_path,
                        mode,
                    )?);
                    logging::info(format_args!(
                        "compiled and mmapped inline rule-set {}",
                        tags.join(",")
                    ));
                    registry.insert(std::sync::Arc::new(rule_set::RuleSet::new_with_mmap(
                        tags, mmap_set,
                    )));
                } else {
                    logging::info(format_args!("loaded rule-set {}", tags.join(",")));
                    registry.insert(std::sync::Arc::new(rule_set::RuleSet::new(tags, rules)));
                }
            }
            "local" => {
                let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
                let resolved_path = resolve_rule_set_path(path, &tags);
                let data = std::fs::read(&resolved_path)
                    .map_err(|err| anyhow::anyhow!("{at}: read {path}: {err}"))?;
                if data.starts_with(b"TSRS") {
                    let mmap_set = std::sync::Arc::new(mmap_set::MmapRuleSet::open_with_mode(
                        &resolved_path,
                        mode,
                    )?);
                    logging::info(format_args!(
                        "loaded rule-set {} via mmap from {}",
                        tags.join(","),
                        resolved_path
                    ));
                    registry.insert(std::sync::Arc::new(rule_set::RuleSet::new_with_mmap(
                        tags, mmap_set,
                    )));
                } else {
                    let rules = parse_rule_set_payload(&data, entry, &at)?;
                    if use_mmap {
                        let mut compiler = mmap_set::RuleSetCompiler::new();
                        let tsrs_bytes = compiler.compile(&rules)?;
                        let cache_file = entry.get("cache_file").and_then(Value::as_str);
                        let target_path = if let Some(cf) = cache_file {
                            std::path::PathBuf::from(cf)
                        } else {
                            rule_set_remote::default_tsrs_cache_path(&tags[0])
                        };
                        if let Some(parent) = target_path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        std::fs::write(&target_path, &tsrs_bytes)?;
                        let mmap_set = std::sync::Arc::new(mmap_set::MmapRuleSet::open_with_mode(
                            &target_path,
                            mode,
                        )?);
                        logging::info(format_args!(
                            "compiled and mmapped rule-set {} ({} rules)",
                            tags.join(","),
                            rules.len()
                        ));
                        registry.insert(std::sync::Arc::new(rule_set::RuleSet::new_with_mmap(
                            tags, mmap_set,
                        )));
                    } else {
                        logging::info(format_args!("loaded rule-set {}", tags.join(",")));
                        registry.insert(std::sync::Arc::new(rule_set::RuleSet::new(tags, rules)));
                    }
                }
            }
            "remote" => {
                let url = entry
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .replace("{tag}", &tags[0]);
                if url.is_empty() {
                    anyhow::bail!("{at}: missing url");
                }
                let client_spec = entry.get("http_client").filter(|v| !v.is_null());
                let detour = entry
                    .get("download_detour")
                    .and_then(Value::as_str)
                    .filter(|tag| !tag.is_empty());
                let client = if client_spec.is_some() {
                    if detour.is_some() {
                        anyhow::bail!(
                            "{at}: http_client is conflict with deprecated download_detour field"
                        );
                    }
                    let spec = clients.resolve(client_spec, &at)?;
                    crate::http_client::HttpClient::from_config(spec.as_ref(), &at)?
                } else if let Some(detour) = detour {
                    logging::warn(format_args!(
                        "{at}: download_detour is deprecated, use http_client"
                    ));
                    let mut wrapper = serde_json::Map::new();
                    wrapper.insert("detour".into(), Value::String(detour.into()));
                    crate::http_client::HttpClient::from_config(Some(&Value::Object(wrapper)), &at)?
                } else {
                    let spec = clients.default_client(route)?;
                    crate::http_client::HttpClient::from_config(spec.as_ref(), &at)?
                };
                let update_interval = crate::outbound::urltest::parse_duration(
                    entry.get("update_interval"),
                    std::time::Duration::ZERO,
                    &at,
                )?;
                let cache_interval = crate::outbound::urltest::parse_duration(
                    entry.get("cache_interval"),
                    std::time::Duration::ZERO,
                    &at,
                )?;
                let delta_update = entry
                    .get("delta_update")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let cache_file = entry
                    .get("cache_file")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let initial_path = entry
                    .get("initial_path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .and_then(|path| std::path::absolute(resolve_rule_set_path(path, &tags)).ok())
                    .map(|path| path.to_string_lossy().replace('\\', "/"));
                let set = std::sync::Arc::new(rule_set::RuleSet::new(tags.clone(), Vec::new()));
                remotes.push(rule_set_remote::RemoteRuleSet {
                    tags: tags.clone(),
                    spec: rule_set_remote::RemoteSpec {
                        url,
                        initial_path,
                        update_interval,
                        client,
                        format: entry
                            .get("format")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        mmap: use_mmap,
                        delta_update,
                        cache_interval,
                        cache_file,
                        mode,
                    },
                    set: set.clone(),
                    etag: None,
                    last_updated: None,
                });
                registry.insert(set);
            }
            other => anyhow::bail!("{at}: unknown rule-set type: {other}"),
        }
    }
    registry.attach_remotes(remotes);
    Ok(registry)
}

/// `option.RuleSet.tag`: a listable of non-empty strings.
fn rule_set_tags(entry: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Vec<String>> {
    let mut tags = Vec::new();
    match entry.get("tag") {
        Some(Value::String(text)) => tags.push(text.clone()),
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(text) = item.as_str() {
                    tags.push(text.to_string());
                }
            }
        }
        _ => {}
    }
    if tags.is_empty() || tags.iter().any(|tag| tag.is_empty()) {
        anyhow::bail!("{at}: missing tag");
    }
    Ok(tags)
}

/// A multi-tag set interpolates `{tag}` per tag; the first tag loads by default.
fn resolve_rule_set_path(path: &str, tags: &[String]) -> String {
    if !path.contains("{tag}") {
        return path.to_string();
    }
    path.replace("{tag}", &tags[0])
}

/// The payload of a local rule set: the binary container or the source JSON.
fn parse_rule_set_payload(
    data: &[u8],
    entry: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<Vec<Value>> {
    let format = entry.get("format").and_then(Value::as_str).unwrap_or("");
    if format == "tsrs" || data.starts_with(b"TSRS") {
        return Ok(Vec::new());
    }
    let binary = format == "binary"
        || (format.is_empty() && data.starts_with(b"SRS"))
        || (format.is_empty()
            && entry
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.ends_with(".srs")));
    if binary {
        return core_config::srs::read(data).map_err(|err| anyhow::anyhow!("{at}: {err}"));
    }
    let text = std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("{at}: not utf-8"))?;
    let value: Value =
        serde_json::from_str(text).map_err(|err| anyhow::anyhow!("{at}: parse source: {err}"))?;
    Ok(value
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

const ROUTE_UNIMPL_FIELDS: &[&str] = &[
    "geoip",
    "geosite",
    "override_android_vpn",
    "default_network_strategy",
    "default_network_type",
    "default_fallback_network_type",
    "default_fallback_delay",
];

/// Parsed `route` section dialing defaults (reference `NetworkOptions`).
#[derive(Debug, Clone, Default)]
pub struct RouteDefaults {
    pub auto_detect_interface: bool,
    pub default_interface: Option<String>,
    pub default_mark: Option<u32>,
    /// `route.default_domain_resolver` server tag (string form or `.server`).
    pub default_domain_resolver: Option<String>,
    /// `route.find_neighbor`: learn the client's MAC and DHCP hostname.
    pub find_neighbor: bool,
}

impl RouteDefaults {
    fn parse(route: Option<&Value>) -> anyhow::Result<Self> {
        let Some(map) = route.and_then(Value::as_object) else {
            return Ok(Self::default());
        };
        let mut out = Self {
            auto_detect_interface: map
                .get("auto_detect_interface")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            default_interface: map
                .get("default_interface")
                .and_then(Value::as_str)
                .map(str::to_string),
            default_mark: map
                .get("default_mark")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
            default_domain_resolver: None,
            find_neighbor: map
                .get("find_neighbor")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        match map.get("default_domain_resolver") {
            None | Some(Value::Null) => {}
            Some(Value::String(tag)) => out.default_domain_resolver = Some(tag.clone()),
            Some(obj @ Value::Object(_)) => {
                out.default_domain_resolver = obj
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            Some(_) => anyhow::bail!(
                "route.default_domain_resolver: json: cannot unmarshal into option._DomainResolveOptions"
            ),
        }
        Ok(out)
    }

    /// Interface to bind outbound dials to: explicit `default_interface`
    /// wins, otherwise the auto-detected default route NIC when
    /// `auto_detect_interface` is set (reference `DefaultDialer`).
    pub fn bind_interface(&self) -> Option<String> {
        if let Some(name) = &self.default_interface {
            return Some(name.clone());
        }
        if self.auto_detect_interface {
            return detect_default_interface();
        }
        None
    }
}

/// Detect the default-route NIC (Linux `/proc/net/route`); other platforms
/// have no portable equivalent and return `None`.
fn detect_default_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in table.lines().skip(1) {
            let mut cols = line.split_whitespace();
            let iface = cols.next()?;
            let dest = cols.next()?;
            // Destination 00000000 = default route.
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub struct RouterInner {
    pub(crate) outbounds: Vec<Outbound>,
    pub(crate) tags: HashMap<String, usize>,
    pub(crate) default: usize,
    pub(crate) rules: Vec<Rule>,
    pub(crate) defaults: RouteDefaults,
    pub(crate) rule_sets: Option<Arc<rule_set::RuleSetRegistry>>,
    /// `route.find_process`, or any rule that names a process: the `/proc`
    /// walk per connection is only worth it when something will read it.
    pub(crate) find_process: bool,
    pub(crate) probe_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Clash `DelayHistory` slots, one per outbound: reference keeps a
    /// single record per proxy, replaced by every successful probe.
    pub(crate) delay_history: Vec<std::sync::Mutex<Option<(String, u32)>>>,
}

pub struct Router {
    inner: std::sync::RwLock<Arc<RouterInner>>,
}

/// A `local` DNS server with `neighbor_domain` answers from the same tables.
fn neighbor_domain_configured(root: &Value) -> bool {
    root.get("dns")
        .and_then(|dns| dns.get("servers"))
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers.iter().any(|server| {
                server.get("type").and_then(Value::as_str) == Some("local")
                    && server
                        .get("neighbor_domain")
                        .is_some_and(|value| !value.is_null())
            })
        })
}

impl RouterInner {
    /// The registry both routers share, remote sets included.
    pub fn rule_sets(&self) -> &rule_set::RuleSetRegistry {
        self.rule_sets
            .as_ref()
            .expect("route registry built in Router::new")
    }

    /// Route dialing defaults (`route.auto_detect_interface`, …).
    pub fn defaults(&self) -> &RouteDefaults {
        &self.defaults
    }

    /// Abort the urltest probe loops (called on instance shutdown).
    pub fn take_probe_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut *self.probe_tasks.lock().expect("probe tasks"))
    }

    /// Clash `DelayHistory`: record a successful probe against `index`.
    pub fn record_delay(&self, index: usize, delay: u32) {
        let index = self.delay_provenance_index(index);
        let Some(slot) = self.delay_history.get(index) else {
            return;
        };
        #[cfg(feature = "clash-api")]
        let ts = crate::clash_api::history_timestamp();
        #[cfg(not(feature = "clash-api"))]
        let ts = String::new();
        *slot.lock().expect("delay history") = Some((ts, delay));
    }

    /// The stored record behind `index`, groups resolving to their member.
    pub fn delay_history(&self, index: usize) -> Option<(String, u32)> {
        self.delay_history
            .get(self.delay_provenance_index(index))?
            .lock()
            .expect("delay history")
            .clone()
    }

    /// Walk `now` down through selector/urltest chains to the member that
    /// holds the record.
    fn delay_provenance_index(&self, index: usize) -> usize {
        let mut index = index;
        for _ in 0..self.outbounds.len() {
            let now_tag = match self.outbounds.get(index) {
                Some(Outbound::Selector(selector)) => selector.now(),
                Some(Outbound::Urltest(urltest)) => urltest.now(),
                _ => break,
            };
            match self.tags.get(now_tag) {
                Some(&next) if next != index => index = next,
                _ => break,
            }
        }
        index
    }

    pub(crate) fn build(root: &Value) -> anyhow::Result<Self> {
        let expanded = core_config::fptn::expand(root).map_err(|e| anyhow::anyhow!("{e}"))?;
        let root: Cow<'_, Value> = match expanded {
            Some(value) => Cow::Owned(value),
            None => Cow::Borrowed(root),
        };
        let defaults = RouteDefaults::parse(root.get("route"))?;
        if let Some(tag) = &defaults.default_domain_resolver {
            crate::dns::set_default_domain_resolver(Some(tag.clone()));
        } else {
            crate::dns::set_default_domain_resolver(None);
        }
        let bind_iface = defaults.bind_interface();
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
            let mut outbound = Outbound::build(obj, &format!("outbounds[{i}]"))?;
            outbound.apply_dial_defaults(defaults.default_mark, bind_iface.as_deref());
            outbounds.push(outbound);
        }
        let endpoints_list = root
            .get("endpoints")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for (i, obj) in endpoints_list.iter().enumerate() {
            let at = format!("endpoints[{i}]");
            let ty = obj.get("type").and_then(Value::as_str).unwrap_or_default();
            let map = obj
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
            let outbound = match ty {
                "wireguard" => Outbound::WireGuard(WireGuard::build(map, &at)?),
                "openvpn-client" => Outbound::OpenVpn(OpenVpn::build(map, &at)?),
                "openconnect" => anyhow::bail!(
                    "{at}: openconnect client is not implemented yet (config check parity only)"
                ),
                "tailscale" => Outbound::Tailscale(Tailscale::build(map, &at)?),
                _ => anyhow::bail!("{at}: unknown endpoint type: {ty}"),
            };
            let tag = map
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !tag.is_empty() {
                if tags.contains_key(&tag) {
                    anyhow::bail!("duplicate outbound tag: {tag}");
                }
                tags.insert(tag, outbounds.len());
            }
            outbounds.push(outbound);
        }
        for outbound in &mut outbounds {
            match outbound {
                Outbound::Selector(selector) => selector.resolve(&tags)?,
                Outbound::Urltest(urltest) => urltest.resolve(&tags)?,
                Outbound::Chain(chain) => chain.resolve(&tags)?,
                _ => {}
            }
        }

        let mut rules = Vec::new();
        let mut registry = rule_set::RuleSetRegistry::new();
        if let Some(route) = root.get("route")
            && let Some(map) = route.as_object()
        {
            for key in ROUTE_UNIMPL_FIELDS {
                if map.get(*key).is_some_and(|v| !v.is_null()) {
                    logging::warn(format_args!("route.{key} is not implemented yet (ignored)"));
                }
            }
            registry = build_rule_sets(map, &crate::http_client::Registry::from_config(&root)?)?;
            if let Some(list) = map.get("rules").and_then(Value::as_array) {
                for (i, obj) in list.iter().enumerate() {
                    rules.push(Rule::build_with_rule_sets(
                        obj,
                        &format!("route.rules[{i}]"),
                        true,
                        &registry,
                    )?);
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

        let lease_files: Vec<String> = root
            .get("route")
            .and_then(|route| route.get("dhcp_lease_files"))
            .map(|value| match value {
                Value::String(path) => vec![path.clone()],
                Value::Array(list) => list
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        let find_process = root
            .get("route")
            .and_then(|route| route.get("find_process"))
            .and_then(Value::as_bool)
            == Some(true)
            || rules.iter().any(Rule::needs_process);
        if defaults.find_neighbor
            || rules.iter().any(Rule::needs_neighbor)
            || neighbor_domain_configured(&root)
        {
            let resolver = neighbor::NeighborResolver::new(&lease_files);
            resolver.start();
            neighbor::install(resolver);
        }
        let delay_history = (0..outbounds.len())
            .map(|_| std::sync::Mutex::new(None))
            .collect();
        Ok(RouterInner {
            outbounds,
            tags,
            default,
            rules,
            defaults,
            rule_sets: Some(Arc::new(registry)),
            find_process,
            probe_tasks: std::sync::Mutex::new(Vec::new()),
            delay_history,
        })
    }

    /// Start listening endpoints (e.g. WireGuard server listeners).
    pub async fn start_endpoints(&self) -> io::Result<()> {
        for outbound in &self.outbounds {
            if let Outbound::WireGuard(wg) = outbound {
                wg.start_listen().await?;
            }
        }
        Ok(())
    }

    /// Index of the outbound `route.final` points at (the direct default).
    pub fn default_index(&self) -> usize {
        self.default
    }

    pub fn index_of(&self, tag: &str) -> Option<usize> {
        self.tags.get(tag).copied()
    }

    /// (index, tag, outbound) for every built outbound — clash API views.
    pub fn outbound_table(&self) -> impl Iterator<Item = (usize, &str, &Outbound)> {
        self.outbounds.iter().enumerate().map(|(i, outbound)| {
            let tag = self
                .tags
                .iter()
                .find(|(_, idx)| **idx == i)
                .map(|(t, _)| t.as_str())
                .unwrap_or("");
            (i, tag, outbound)
        })
    }

    /// Clash view: per rule, the Clash condition items and the
    /// outbound they select.
    pub fn clash_rules(&self) -> Vec<(String, String, String)> {
        self.rules.iter().map(|rule| rule.clash_view()).collect()
    }

    pub fn default_tag(&self) -> &str {
        self.outbound_table()
            .find(|(i, ..)| *i == self.default)
            .map(|(_, tag, _)| tag)
            .unwrap_or("")
    }

    /// Switch a `selector` group to one of its members (clash `PUT /proxies`).
    pub fn select_member(&self, group_tag: &str, member: &str) -> Result<bool, SelectError> {
        let index = self.index_of(group_tag).ok_or(SelectError::NotFound)?;
        let Some(outbound) = self.outbounds.get(index) else {
            return Err(SelectError::NotFound);
        };
        match outbound {
            Outbound::Selector(selector) => {
                if selector.select(member) {
                    Ok(true)
                } else {
                    Err(SelectError::NotMember)
                }
            }
            _ => Err(SelectError::NotSelector),
        }
    }

    pub async fn route_walk<S>(
        &self,
        mut client: Option<&mut S>,
        ctx: &mut ConnContext,
    ) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        prepare(ctx, self.find_process);
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.matches(ctx) {
                continue;
            }
            let action = rule.action();
            ctx.matched_rule = Some(rule.clash_primary());
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
                Action::Reject {
                    method,
                    no_drop,
                    flood,
                } => {
                    return Err(reject_error(*method, *no_drop, flood));
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

impl Router {
    pub fn new(root: &Value) -> anyhow::Result<Arc<Router>> {
        let inner = RouterInner::build(root)?;
        let router = Arc::new(Router {
            inner: std::sync::RwLock::new(Arc::new(inner)),
        });
        let inner_ref = router.inner();
        for outbound in &inner_ref.outbounds {
            if let Outbound::Urltest(urltest) = outbound {
                let handle = urltest.spawn(Arc::clone(&router));
                inner_ref
                    .probe_tasks
                    .lock()
                    .expect("probe tasks")
                    .push(handle);
            }
        }
        Ok(router)
    }

    pub fn inner(&self) -> Arc<RouterInner> {
        self.inner.read().expect("router inner lock").clone()
    }

    pub fn rule_sets(&self) -> Arc<rule_set::RuleSetRegistry> {
        self.inner()
            .rule_sets
            .as_ref()
            .expect("route registry built in Router::new")
            .clone()
    }

    pub fn defaults(&self) -> RouteDefaults {
        self.inner().defaults.clone()
    }

    pub fn take_probe_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        self.inner().take_probe_tasks()
    }

    pub fn record_delay(&self, index: usize, delay: u32) {
        self.inner().record_delay(index, delay);
    }

    pub fn delay_history(&self, index: usize) -> Option<(String, u32)> {
        self.inner().delay_history(index)
    }

    pub fn default_index(&self) -> usize {
        self.inner().default_index()
    }

    pub fn index_of(&self, tag: &str) -> Option<usize> {
        self.inner().index_of(tag)
    }

    pub fn default_tag(&self) -> String {
        self.inner().default_tag().to_string()
    }

    pub fn clash_rules(&self) -> Vec<(String, String, String)> {
        self.inner().clash_rules()
    }

    pub fn select_member(&self, group_tag: &str, member: &str) -> Result<bool, SelectError> {
        self.inner().select_member(group_tag, member)
    }

    pub fn start_endpoints<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        let inner = self.inner();
        Box::pin(async move { inner.start_endpoints().await })
    }

    pub fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        self.connect_index(self.default_index(), target)
    }

    pub fn connect_index<'a>(
        &'a self,
        index: usize,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        let inner = self.inner();
        Box::pin(async move {
            let Some(outbound) = inner.outbounds.get(index) else {
                return Err(io::Error::other("outbound index out of range"));
            };
            outbound.connect(self, target).await
        })
    }

    pub fn connect_udp_index<'a>(
        &'a self,
        index: usize,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<tokio::net::UdpSocket>> + Send + 'a>> {
        let inner = self.inner();
        Box::pin(async move {
            let Some(outbound) = inner.outbounds.get(index) else {
                return Err(io::Error::other("outbound index out of range"));
            };
            outbound.connect_udp(self, target).await
        })
    }

    pub async fn route<S>(&self, client: &mut S, ctx: &mut ConnContext) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner().route_walk(Some(client), ctx).await
    }

    pub async fn route_raw(&self, ctx: &mut ConnContext) -> io::Result<Decision> {
        self.inner()
            .route_walk::<tokio::net::TcpStream>(None, ctx)
            .await
    }

    pub fn build_inner(root: &Value) -> anyhow::Result<RouterInner> {
        RouterInner::build(root)
    }

    pub async fn apply_inner(self: &Arc<Self>, new_inner: RouterInner) -> anyhow::Result<()> {
        let old_inner = self.inner();

        // 1. Preserve delay history by tag across reloads
        for (tag, &old_idx) in &old_inner.tags {
            if let Some(hist) = old_inner.delay_history(old_idx)
                && let Some(&new_idx) = new_inner.tags.get(tag)
                && let Some(slot) = new_inner.delay_history.get(new_idx)
            {
                *slot.lock().expect("delay history") = Some(hist);
            }
        }

        // 2. Preserve selector and urltest selections and latencies
        for (tag, &old_idx) in &old_inner.tags {
            if let Some(Outbound::Selector(old_sel)) = old_inner.outbounds.get(old_idx)
                && let Some(&new_idx) = new_inner.tags.get(tag)
                && let Some(Outbound::Selector(new_sel)) = new_inner.outbounds.get(new_idx)
            {
                let _ = new_sel.select(old_sel.now());
            } else if let Some(Outbound::Urltest(old_url)) = old_inner.outbounds.get(old_idx)
                && let Some(&new_idx) = new_inner.tags.get(tag)
                && let Some(Outbound::Urltest(new_url)) = new_inner.outbounds.get(new_idx)
            {
                let _ = new_url.select(old_url.now());
                new_url.copy_latencies_from(old_url);
            }
        }

        // 3. Stop old urltest probe tasks
        let old_tasks = old_inner.take_probe_tasks();
        for task in old_tasks {
            task.abort();
        }

        // 4. Atomically install new inner router
        let new_inner = Arc::new(new_inner);
        *self.inner.write().expect("router inner lock") = Arc::clone(&new_inner);

        // 5. Spawn new urltest probe tasks using self (Arc<Router>)
        for outbound in &new_inner.outbounds {
            if let Outbound::Urltest(urltest) = outbound {
                let handle = urltest.spawn(Arc::clone(self));
                new_inner
                    .probe_tasks
                    .lock()
                    .expect("probe tasks")
                    .push(handle);
            }
        }

        Ok(())
    }

    pub async fn reload(self: &Arc<Self>, root: &Value) -> anyhow::Result<()> {
        let new_inner = RouterInner::build(root)?;
        self.apply_inner(new_inner).await
    }
}

/// `PUT /proxies/{name}` failure classes (reference clash API messages).
#[derive(Debug, PartialEq, Eq)]
pub enum SelectError {
    NotFound,
    NotSelector,
    NotMember,
}

/// FakeIP reverse mapping + ip_version before the rule walk.
fn prepare(ctx: &mut ConnContext, want_process: bool) {
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
    } else if ctx.domain.is_none()
        && let Target::Ip(addr) = ctx.destination
        && let Some(dns) = dns::current()
        && let Some(domain) = dns.reverse_domain(addr.ip())
    {
        // `dns.reverse_mapping`: the dial target stays the IP, only the
        // domain rules get to see the name the answer came from
        ctx.domain = Some(domain.clone());
        logging::debug(format_args!("route: found reverse mapped domain: {domain}"));
    }
    // `route.find_neighbor`: the client's own identity, for the
    // `source_mac_address` / `source_hostname` rule items
    if let Some(resolver) = neighbor::current() {
        ctx.source_mac = resolver.lookup_mac(ctx.source.ip());
        ctx.source_hostname = resolver.lookup_hostname(ctx.source.ip());
    }
    // `route.find_process`: the process behind the socket, for the
    // `process_name` / `process_path` / `user` rule items
    let destination = match ctx.origin_destination.as_ref().unwrap_or(&ctx.destination) {
        Target::Ip(addr) => Some(*addr),
        Target::Domain(..) => None,
    };
    if want_process && let Some(info) = process::find_owner(ctx.network, ctx.source, destination) {
        // per-connection, so debug: at the default level this costs nothing —
        // and the user suffix is built inside the format, not before it
        match &info.user_name {
            Some(name) => logging::debug(format_args!(
                "found process path: {}, user: {}",
                info.path, name
            )),
            None => logging::debug(format_args!("found process path: {}", info.path)),
        }
        ctx.process = Some(info);
    }
    ctx.ip_version = match ctx.destination {
        Target::Ip(a) => Some(if a.is_ipv6() { 6 } else { 4 }),
        Target::Domain(..) => None,
    };
}

fn reject_error(method: RejectMethod, no_drop: bool, flood: &rule::RejectFlood) -> io::Error {
    match method {
        RejectMethod::Drop => io::Error::new(io::ErrorKind::ConnectionReset, "dropped by rule"),
        RejectMethod::Reply => {
            io::Error::other("reject method `reply` is not supported for TCP connections")
        }
        RejectMethod::Default => {
            if !no_drop && flood.trigger() {
                logging::debug(format_args!("dropped due to flooding"));
                return io::Error::new(io::ErrorKind::ConnectionReset, "dropped by rule");
            }
            io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by rule")
        }
    }
}

async fn action_resolve(ctx: &mut ConnContext, action: &ResolveAction) -> io::Result<()> {
    let host = match &ctx.destination {
        Target::Domain(host, _) => host.clone(),
        Target::Ip(_) => match &ctx.domain {
            Some(d) => d.clone(),
            None => return Ok(()),
        },
    };
    let Some(dns) = dns::current() else {
        return Err(io::Error::other("resolve action requires dns section"));
    };
    let resolve_fut = async {
        match &action.server {
            Some(tag) => dns.resolve_via_with(tag, &host, action.strategy).await,
            None => dns.resolve_with(&host, action.strategy).await,
        }
    };
    let addrs = if let Some(timeout) = action.timeout {
        tokio::time::timeout(timeout, resolve_fut)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("resolve timeout for {host}"),
                )
            })?
    } else {
        resolve_fut.await
    }?;
    logging::debug(format_args!(
        "route: resolved [{}] for {host}",
        addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    if ctx.ip_version.is_none() && !addrs.is_empty() {
        ctx.ip_version = Some(if addrs[0].is_ipv6() { 6 } else { 4 });
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn route_defaults_parse_string_and_object_resolver() {
        let d = RouteDefaults::parse(Some(&json!({
            "auto_detect_interface": true,
            "default_interface": "eth9",
            "default_mark": 42,
            "default_domain_resolver": "u"
        })))
        .unwrap();
        assert!(d.auto_detect_interface);
        assert_eq!(d.default_interface.as_deref(), Some("eth9"));
        assert_eq!(d.default_mark, Some(42));
        assert_eq!(d.default_domain_resolver.as_deref(), Some("u"));
        assert_eq!(d.bind_interface().as_deref(), Some("eth9"));

        let d = RouteDefaults::parse(Some(&json!({
            "default_domain_resolver": {"server": "u", "strategy": "prefer_ipv4"}
        })))
        .unwrap();
        assert_eq!(d.default_domain_resolver.as_deref(), Some("u"));
        assert_eq!(d.bind_interface(), None);

        let d = RouteDefaults::parse(Some(&json!({"default_domain_resolver": null}))).unwrap();
        assert_eq!(d.default_domain_resolver, None);

        RouteDefaults::parse(Some(&json!({"default_domain_resolver": ["x"]})))
            .expect_err("array form must fail");
        RouteDefaults::parse(Some(&json!({"auto_detect_interface": "yes"}))).ok();
    }

    /// The whole path, not just the lookup: a live socket, `prepare`, and a
    /// rule that names this very process. Linux-only because the searcher is.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_rule_can_route_by_the_process_that_opened_the_socket() {
        // the rule names whatever this test binary is called
        let own = std::fs::read_link("/proc/self/exe").expect("own exe");
        let name = own
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        let router = Router::new(&json!({
            "outbounds": [{"type": "direct", "tag": "d"}],
            "route": {
                "find_process": true,
                "rules": [{"process_name": name, "outbound": "d"}],
                "final": "d"
            }
        }))
        .expect("router");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        let mut ctx = ConnContext::new(
            "in",
            client.local_addr().expect("source"),
            Target::Ip(server.local_addr().expect("server")),
            "tcp",
        );
        prepare(&mut ctx, true);
        let owner = ctx.process.as_ref().expect("prepare found the owner");
        assert_eq!(owner.path, own.to_string_lossy(), "this very test binary");
        assert!(
            router.inner().rules[0].matches(&ctx),
            "and the rule matches it"
        );
        drop((client, server));
    }

    #[test]
    fn router_applies_route_defaults_to_direct() {
        let router = Router::new(&json!({
            "outbounds": [
                {"type": "direct", "tag": "marked"},
                {"type": "direct", "tag": "plain"}
            ],
            "route": {
                "final": "plain",
                "default_interface": "lo",
                "default_mark": 7,
                "default_domain_resolver": "u"
            }
        }))
        .unwrap();
        assert_eq!(router.defaults().default_mark, Some(7));
        assert_eq!(router.defaults().bind_interface().as_deref(), Some("lo"));
        assert_eq!(
            router.defaults().default_domain_resolver.as_deref(),
            Some("u"),
            "route defaults install the ddr tag"
        );

        // Explicit outbound fields win over route defaults. `routing_mark` is
        // Linux-only, and off Linux the reference refuses it, so the mark can
        // only be checked there; the interface option is portable.
        let router = Router::new(&json!({
            "outbounds": [{"type": "direct", "tag": "d", "bind_interface": "eth0"}],
            "route": {"final": "d", "default_interface": "lo", "default_mark": 7}
        }))
        .unwrap();
        match router.inner().outbounds.first() {
            Some(Outbound::Direct(d)) => {
                assert_eq!(d.dial.bind_interface.as_deref(), Some("eth0"));
            }
            _ => panic!("expected direct outbound"),
        }

        #[cfg(target_os = "linux")]
        {
            let router = Router::new(&json!({
                "outbounds": [{"type": "direct", "tag": "d", "routing_mark": 99}],
                "route": {"final": "d", "default_mark": 7}
            }))
            .unwrap();
            match router.inner().outbounds.first() {
                Some(Outbound::Direct(d)) => assert_eq!(d.dial.routing_mark, Some(99)),
                _ => panic!("expected direct outbound"),
            }
        }

        // No route section defaults to empty ddr tag.
        let router = Router::new(&json!({"outbounds": [{"type": "direct", "tag": "d"}]})).unwrap();
        assert_eq!(router.defaults().default_domain_resolver, None);
    }

    #[test]
    fn clash_delay_history_records_and_groups_derive() {
        let router = Router::new(&json!({
            "outbounds": [
                {"type": "direct", "tag": "d1"},
                {"type": "socks", "tag": "dead", "server": "127.0.0.1", "server_port": 1},
                {"type": "selector", "tag": "sel", "outbounds": ["d1", "dead"]}
            ],
            "route": {"final": "d1"}
        }))
        .unwrap();
        let d1 = router.inner().tags["d1"];
        let sel = router.inner().tags["sel"];

        assert!(router.delay_history(d1).is_none(), "no probe, no record");
        router.record_delay(d1, 654);
        let (time, delay) = router.delay_history(d1).expect("recorded");
        assert_eq!(delay, 654);
        assert!(time.contains('T') && time.ends_with('Z'), "RFC3339: {time}");
        let (group_time, group_delay) = router.delay_history(sel).expect("derived");
        assert_eq!(group_delay, 654, "selector follows its current member");
        assert_eq!(group_time, time, "same record, one timestamp");

        router
            .select_member("sel", "dead")
            .expect("selector switches");
        assert!(
            router.delay_history(sel).is_none(),
            "the new member has no record of its own"
        );

        router.record_delay(d1, 700);
        let (_, delay) = router.delay_history(d1).expect("recorded");
        assert_eq!(delay, 700, "one slot, replaced per probe");
    }

    #[tokio::test]
    async fn router_hot_reload_migrates_delay_and_selectors() {
        let root1 = json!({
            "outbounds": [
                {"type": "direct", "tag": "d1"},
                {"type": "direct", "tag": "d2"},
                {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2"]}
            ],
            "route": {"final": "d1"}
        });
        let router = Router::new(&root1).unwrap();
        let d2 = router.index_of("d2").unwrap();
        router.record_delay(d2, 123);
        router.select_member("sel", "d2").unwrap();

        // New config with reordered outbounds or added outbound:
        let root2 = json!({
            "outbounds": [
                {"type": "direct", "tag": "d3"},
                {"type": "direct", "tag": "d2"},
                {"type": "direct", "tag": "d1"},
                {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2", "d3"]}
            ],
            "route": {"final": "d2"}
        });
        router.reload(&root2).await.unwrap();

        // Verify delay history migrated for d2:
        let new_d2 = router.index_of("d2").unwrap();
        assert_eq!(router.delay_history(new_d2).unwrap().1, 123);

        // Verify selector choice preserved:
        let sel_idx = router.index_of("sel").unwrap();
        assert_eq!(router.delay_history(sel_idx).unwrap().1, 123);
    }

    #[test]
    fn reject_error_flood_and_no_drop() {
        let flood = rule::RejectFlood::default();
        for _ in 0..50 {
            let e = reject_error(RejectMethod::Default, false, &flood);
            assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "pre-flood");
        }
        let e = reject_error(RejectMethod::Default, false, &flood);
        assert_eq!(
            e.kind(),
            io::ErrorKind::ConnectionReset,
            "51st hit escalates to drop"
        );

        let flood = rule::RejectFlood::default();
        for _ in 0..60 {
            let e = reject_error(RejectMethod::Default, true, &flood);
            assert_eq!(
                e.kind(),
                io::ErrorKind::ConnectionRefused,
                "no_drop never floods"
            );
        }

        let flood = rule::RejectFlood::default();
        let e = reject_error(RejectMethod::Drop, false, &flood);
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
        assert!(!flood.trigger(), "drop method must not touch the counter");
    }
}
