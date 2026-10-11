//! Route rule build + match: default/logical rules, group semantics,
//! all matchers used by real configs, and rule actions.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;

use super::ConnContext;
use crate::dns::transport::IpPrefix;
use crate::outbound::urltest::parse_duration;

pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

/// reference `RuleActionReject` flood window: >50 default rejects in 30s
/// escalate to `drop`.
const REJECT_FLOOD_WINDOW: Duration = Duration::from_secs(30);
const REJECT_FLOOD_LIMIT: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectMethod {
    Default,
    Drop,
    Reply,
}

/// Shared per-rule reject trigger history (reference `dropCounter`).
#[derive(Debug, Default)]
pub struct RejectFlood {
    hits: Mutex<Vec<Instant>>,
}

impl RejectFlood {
    /// Record a trigger and report whether the flood limit is exceeded.
    pub fn trigger(&self) -> bool {
        let mut hits = self.hits.lock().expect("reject flood");
        let now = Instant::now();
        hits.retain(|t| now.duration_since(*t) <= REJECT_FLOOD_WINDOW);
        hits.push(now);
        hits.len() > REJECT_FLOOD_LIMIT
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouteOptions {
    pub override_address: Option<TargetOverride>,
    pub override_port: Option<u16>,
    pub udp_timeout: Option<Duration>,
    pub udp_disable_domain_unmapping: Option<bool>,
    pub tls_fragment: Option<bool>,
    pub tls_record_fragment: Option<bool>,
}

/// Host part of `override_address` (port embedded in the string is ignored).
#[derive(Debug, Clone)]
pub enum TargetOverride {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone)]
pub struct ResolveAction {
    pub server: Option<String>,
    pub strategy: Option<crate::dns::Strategy>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub enum Action {
    Route {
        outbound: String,
        opts: RouteOptions,
    },
    RouteOptions(RouteOptions),
    Direct,
    Bypass {
        outbound: String,
        opts: RouteOptions,
    },
    Reject {
        method: RejectMethod,
        no_drop: bool,
        flood: Arc<RejectFlood>,
    },
    HijackDns,
    Sniff {
        sniffer: Vec<String>,
        timeout: Duration,
    },
    Resolve(ResolveAction),
}

impl Action {
    /// Phase-A route options for this action (route / route-options /
    /// bypass-with-outbound); `None` means no options to apply.
    pub fn route_options(&self) -> Option<&RouteOptions> {
        match self {
            Action::Route { opts, .. } => Some(opts),
            Action::RouteOptions(opts) => Some(opts),
            Action::Bypass { outbound, opts } if !outbound.is_empty() => Some(opts),
            _ => None,
        }
    }

    /// Reference `RuleAction.String()` for `GET /rules` and the `rule` field
    /// of `/connections`.
    pub fn clash_view(&self) -> String {
        match self {
            Action::Route { outbound, opts } | Action::Bypass { outbound, opts }
                if !outbound.is_empty() =>
            {
                let mut parts = vec![outbound.clone()];
                parts.extend(opts.descriptions());
                format!("{}({})", self.type_name(), parts.join(","))
            }
            Action::Route { .. } => "route()".to_string(),
            Action::Bypass { .. } => "bypass()".to_string(),
            Action::RouteOptions(opts) => {
                format!("route-options({})", opts.descriptions().join(","))
            }
            Action::Direct => "direct".to_string(),
            Action::Reject { method, .. } => match method {
                RejectMethod::Default => "reject".to_string(),
                RejectMethod::Drop => "reject(drop)".to_string(),
                RejectMethod::Reply => "reject(reply)".to_string(),
            },
            Action::HijackDns => "hijack-dns".to_string(),
            Action::Sniff { sniffer, timeout } => {
                let mut parts = sniffer.clone();
                if !timeout.is_zero() {
                    parts.push(go_duration_string(*timeout));
                }
                if parts.is_empty() {
                    "sniff".to_string()
                } else {
                    format!("sniff({})", parts.join(","))
                }
            }
            Action::Resolve(action) => {
                let mut parts: Vec<String> = action.server.iter().cloned().collect();
                if let Some(name) = action.strategy.and_then(strategy_name) {
                    parts.push(name.to_string());
                }
                if parts.is_empty() {
                    "resolve".to_string()
                } else {
                    format!("resolve({})", parts.join(","))
                }
            }
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Action::Route { .. } => "route",
            Action::RouteOptions(_) => "route-options",
            Action::Direct => "direct",
            Action::Bypass { .. } => "bypass",
            Action::Reject { .. } => "reject",
            Action::HijackDns => "hijack-dns",
            Action::Sniff { .. } => "sniff",
            Action::Resolve(_) => "resolve",
        }
    }
}

impl RouteOptions {
    /// `RuleActionRouteOptions.Descriptions`, limited to the options this
    /// core carries. `udp-timeout` is a bare flag there too.
    fn descriptions(&self) -> Vec<String> {
        let mut out = Vec::new();
        match &self.override_address {
            Some(TargetOverride::Ip(ip)) => out.push(format!("override-address={ip}")),
            Some(TargetOverride::Domain(host)) => out.push(format!("override-address={host}")),
            None => {}
        }
        if let Some(port) = self.override_port.filter(|p| *p > 0) {
            out.push(format!("override-port={port}"));
        }
        if self.udp_disable_domain_unmapping == Some(true) {
            out.push("udp-disable-domain-unmapping".into());
        }
        if self.udp_timeout.is_some_and(|t| !t.is_zero()) {
            out.push("udp-timeout".into());
        }
        if self.tls_fragment == Some(true) {
            out.push("tls-fragment".into());
        }
        if self.tls_record_fragment == Some(true) {
            out.push("tls-record-fragment".into());
        }
        out
    }
}

/// `option.DomainStrategy` names; `as_is` prints nothing.
fn strategy_name(strategy: crate::dns::Strategy) -> Option<&'static str> {
    use crate::dns::Strategy;
    match strategy {
        Strategy::AsIs => None,
        Strategy::PreferIPv4 => Some("prefer_ipv4"),
        Strategy::PreferIPv6 => Some("prefer_ipv6"),
        Strategy::IPv4Only => Some("ipv4_only"),
        Strategy::IPv6Only => Some("ipv6_only"),
    }
}

/// Go `time.Duration.String()`: `0s`, `300ms`, `1.5µs`, `1m30s`, `1h0m0s`.
fn go_duration_string(d: Duration) -> String {
    fn fixed(value: u128, digits: u32) -> String {
        let scale = 10u128.pow(digits);
        let (int, rem) = (value / scale, value % scale);
        if rem == 0 {
            return int.to_string();
        }
        let frac = format!("{rem:0width$}", width = digits as usize);
        format!("{int}.{}", frac.trim_end_matches('0'))
    }
    let ns = d.as_nanos();
    match ns {
        0 => "0s".to_string(),
        1..1_000 => format!("{ns}ns"),
        1_000..1_000_000 => format!("{}\u{b5}s", fixed(ns, 3)),
        1_000_000..1_000_000_000 => format!("{}ms", fixed(ns, 6)),
        _ => {
            let seconds = format!("{}s", fixed(ns % 60_000_000_000, 9));
            let minutes = ns / 60_000_000_000;
            match (minutes / 60, minutes % 60) {
                (0, 0) => seconds,
                (0, m) => format!("{m}m{seconds}"),
                (h, m) => format!("{h}h{m}m{seconds}"),
            }
        }
    }
}

/// Match-state group flags (mirrors sing-box `ruleMatchState`).
const SOURCE_ADDRESS: u8 = 1;
const SOURCE_PORT: u8 = 2;
const DEST_ADDRESS: u8 = 4;
const DEST_PORT: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogicalMode {
    And,
    Or,
}

#[derive(Debug, Clone)]
pub enum Rule {
    Default(Box<DefaultRule>),
    Logical(Box<LogicalRule>),
}

#[derive(Debug, Clone)]
pub struct LogicalRule {
    mode: LogicalMode,
    rules: Vec<Rule>,
    invert: bool,
    action: Action,
}

#[derive(Debug, Clone)]
pub struct DefaultRule {
    /// Plain AND items (inbound, network, protocol, ip_version, auth_user, …).
    plain: Vec<PlainItem>,
    source_address: Vec<AddressItem>,
    source_port: Vec<PortItem>,
    dest_address: Vec<DomainItem>,
    dest_ip_cidr: Vec<IpCidrItem>,
    dest_port: Vec<PortItem>,
    has_items: bool,
    /// The rule sets this rule consults (empty when it has no `rule_set`).
    rule_sets: Vec<std::sync::Arc<super::rule_set::RuleSet>>,
    /// The `rule_set` tags as configured, for the description.
    rule_set_tags: Vec<String>,
    invert: bool,
    action: Action,
}

#[derive(Debug, Clone)]
enum PlainItem {
    Inbound(Vec<String>),
    IpVersion {
        is_v6: bool,
    },
    Network(Vec<String>),
    AuthUser(Vec<String>),
    Protocol(Vec<String>),
    Client(Vec<String>),
    /// The clash mode in force, as set through the controller.
    ClashMode(Vec<String>),
    /// The client's hardware address, from the neighbour tables.
    SourceMac(Vec<super::neighbor::MacAddr>),
    /// The client's DHCP hostname, from the neighbour tables.
    SourceHostname(Vec<String>),
    /// The basename of the owning process's path.
    ProcessName(Vec<String>),
    /// The owning process's path, whole.
    ProcessPath(Vec<String>),
    /// The owning process's path, by regexp.
    ProcessPathRegex(Vec<Regex>),
    /// The uid that owns the process. Kept signed because the reference
    /// reserves -1 for "unknown", so a config listing it must not match.
    UserId(Vec<i64>),
    /// The user name that owns the process.
    User(Vec<String>),
    /// Unsupported matcher (package_name*, …): always false.
    Unsupported,
}

#[derive(Debug, Clone)]
enum AddressItem {
    Cidr(Vec<IpPrefix>),
    IsPrivate,
}

#[derive(Debug, Clone)]
enum PortItem {
    Ports(Vec<u16>),
    /// The parsed ranges, and the strings they came from: the reference
    /// describes a range the way the config wrote it (`:3000`, `10:`).
    Ranges(Vec<(u16, u16)>, Vec<String>),
}

#[derive(Debug, Clone)]
enum DomainItem {
    Exact(Vec<String>),
    Suffix(Vec<String>),
    Keyword(Vec<String>),
    Regex(Vec<Regex>),
}

/// The items `route/process_cache.go` looks a process up for.
fn is_process_item(item: &PlainItem) -> bool {
    matches!(
        item,
        PlainItem::ProcessName(_)
            | PlainItem::ProcessPath(_)
            | PlainItem::ProcessPathRegex(_)
            | PlainItem::UserId(_)
            | PlainItem::User(_)
    )
}

#[derive(Debug, Clone)]
struct IpCidrItem {
    prefixes: Vec<IpPrefix>,
    is_private: bool,
}

/// Reference item descriptions: one value inline, up to three in brackets,
/// longer lists truncated with `...`.
fn field_list(name: &str, values: &[String]) -> String {
    match values.len() {
        0 => String::new(),
        1 => format!("{name}={}", values[0]),
        len if len <= 3 => format!("{name}=[{}]", values.join(" ")),
        _ => format!("{name}=[{}...]", values[..3].join(" ")),
    }
}

/// Merge per-value `name=value` pairs of one category back into the reference
/// bracket form (`domain=[a b]`, or `domain_suffix=[...]` when mixed).
fn collapse_fields(parts: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for part in parts {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        match &mut current {
            Some((active, values)) if active == name => values.push(value.to_string()),
            _ => {
                if let Some((name, values)) = current.take() {
                    out.push(field_list(&name, &values));
                }
                current = Some((name.to_string(), vec![value.to_string()]));
            }
        }
    }
    if let Some((name, values)) = current {
        out.push(field_list(&name, &values));
    }
    out.join(" ")
}

/// `port=` / `port_range=` (or the `source_` pair), as the reference items
/// describe themselves.
fn port_description(source: bool, item: &PortItem) -> String {
    let prefix = if source { "source_" } else { "" };
    match item {
        PortItem::Ports(ports) => {
            let values: Vec<String> = ports.iter().map(u16::to_string).collect();
            field_list(&format!("{prefix}port"), &values)
        }
        PortItem::Ranges(_, raw) => field_list(&format!("{prefix}port_range"), raw),
    }
}

fn wrap_invert(invert: bool, payload: &str) -> String {
    if invert {
        format!("!({payload})")
    } else {
        payload.to_string()
    }
}

/// A plain item's place in the reference order and its description. Ranks
/// under 10 go before the domain items, the rest after the ports.
fn plain_description(item: &PlainItem) -> Option<(u8, String)> {
    let described = match item {
        PlainItem::Inbound(list) => (0, field_list("inbound", list)),
        PlainItem::IpVersion { is_v6 } => (1, format!("ip_version={}", if *is_v6 { 6 } else { 4 })),
        PlainItem::Network(list) => (2, field_list("network", list)),
        PlainItem::AuthUser(list) => (3, field_list("auth_user", list)),
        PlainItem::Protocol(list) => (4, field_list("protocol", list)),
        PlainItem::Client(list) => (5, field_list("client", list)),
        PlainItem::ProcessName(list) => (10, field_list("process_name", list)),
        PlainItem::ProcessPath(list) => (11, field_list("process_path", list)),
        PlainItem::ProcessPathRegex(list) => {
            let values: Vec<String> = list.iter().map(|re| re.as_str().into()).collect();
            (12, field_list("process_path_regex", &values))
        }
        PlainItem::User(list) => (13, field_list("user", list)),
        PlainItem::UserId(list) => {
            let values: Vec<String> = list.iter().map(|n| n.to_string()).collect();
            (14, field_list("user_id", &values))
        }
        PlainItem::ClashMode(list) => (15, field_list("clash_mode", list)),
        PlainItem::SourceMac(list) => {
            let values: Vec<String> = list.iter().map(super::neighbor::mac_string).collect();
            (16, field_list("source_mac_address", &values))
        }
        PlainItem::SourceHostname(list) => (17, field_list("source_hostname", list)),
        // package_name* and friends never match and carry no description
        PlainItem::Unsupported => return None,
    };
    Some(described)
}

impl Rule {
    /// Top-level `route.rules[i]` entry (`check_outbound` matches reference
    /// `NewRule(..., true)`).
    pub fn build(obj: &Value, at: &str, check_outbound: bool) -> anyhow::Result<Self> {
        Self::build_with_rule_sets(
            obj,
            at,
            check_outbound,
            &super::rule_set::RuleSetRegistry::new(),
        )
    }

    pub fn build_with_rule_sets(
        obj: &Value,
        at: &str,
        check_outbound: bool,
        registry: &super::rule_set::RuleSetRegistry,
    ) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let ty = map.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "" | "default" => {
                if !rule_is_valid(map) {
                    anyhow::bail!("{at}: missing conditions");
                }
                let action = build_action(map, at)?;
                if matches!(action, Action::Route { ref outbound, .. } if outbound.is_empty())
                    && check_outbound
                {
                    anyhow::bail!("{at}: missing outbound field");
                }
                let rule = Self::build_default(map, at, action, registry)?;
                Ok(rule)
            }
            "logical" => {
                if !logical_is_valid(map) {
                    anyhow::bail!("{at}: missing conditions");
                }
                let action = build_action(map, at)?;
                if matches!(action, Action::Route { ref outbound, .. } if outbound.is_empty())
                    && check_outbound
                {
                    anyhow::bail!("{at}: missing outbound field");
                }
                Self::build_logical(map, at, action, registry)
            }
            other => anyhow::bail!("{at}: unknown rule type: {other}"),
        }
    }

    fn build_default(
        map: &serde_json::Map<String, Value>,
        at: &str,
        action: Action,
        registry: &super::rule_set::RuleSetRegistry,
    ) -> anyhow::Result<Self> {
        let mut plain = Vec::new();
        let mut source_address = Vec::new();
        let mut source_port = Vec::new();
        let mut dest_address = Vec::new();
        let mut dest_ip_cidr = Vec::new();
        let mut dest_port = Vec::new();
        let mut rule_set_tags: Vec<String> = Vec::new();

        if let Some(v) = string_list(map, "inbound", at)? {
            plain.push(PlainItem::Inbound(v));
        }
        if let Some(v) = map.get("ip_version").and_then(Value::as_i64) {
            match v {
                4 => plain.push(PlainItem::IpVersion { is_v6: false }),
                6 => plain.push(PlainItem::IpVersion { is_v6: true }),
                other => anyhow::bail!("{at}: invalid ip version: {other}"),
            }
        }
        if let Some(v) = string_list(map, "network", at)? {
            plain.push(PlainItem::Network(v));
        }
        if let Some(v) = string_list(map, "auth_user", at)? {
            plain.push(PlainItem::AuthUser(v));
        }
        if let Some(v) = string_list(map, "protocol", at)? {
            plain.push(PlainItem::Protocol(v));
        }
        if let Some(v) = string_list(map, "client", at)? {
            plain.push(PlainItem::Client(v));
        }

        let domains = string_list(map, "domain", at)?;
        let suffixes = string_list(map, "domain_suffix", at)?;
        if let Some(v) = domains {
            dest_address.push(DomainItem::Exact(lower_all(v)));
        }
        if let Some(v) = suffixes {
            dest_address.push(DomainItem::Suffix(lower_all(v)));
        }
        if let Some(v) = string_list(map, "domain_keyword", at)? {
            // Reference matches keywords as-is against a lowered host.
            dest_address.push(DomainItem::Keyword(v));
        }
        if let Some(exprs) = string_list(map, "domain_regex", at)? {
            let mut compiled = Vec::with_capacity(exprs.len());
            for (i, expr) in exprs.iter().enumerate() {
                let re = Regex::new(expr)
                    .map_err(|e| anyhow::anyhow!("{at}: parse expression {i}: {e}"))?;
                compiled.push(re);
            }
            dest_address.push(DomainItem::Regex(compiled));
        }

        if let Some(v) = map.get("geosite").filter(|v| !v.is_null()) {
            let _ = v;
            anyhow::bail!(
                "{at}: geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
            );
        }
        if let Some(v) = map.get("geoip").filter(|v| !v.is_null()) {
            let _ = v;
            anyhow::bail!(
                "{at}: geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
            );
        }
        if let Some(v) = map.get("source_geoip").filter(|v| !v.is_null()) {
            let _ = v;
            anyhow::bail!(
                "{at}: geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0"
            );
        }

        if let Some(v) = string_list(map, "source_ip_cidr", at)? {
            let prefixes = parse_prefixes(&v, at, "source_ip_cidr")?;
            source_address.push(AddressItem::Cidr(prefixes));
        }
        if map.get("source_ip_is_private").and_then(Value::as_bool) == Some(true) {
            source_address.push(AddressItem::IsPrivate);
        }
        if let Some(v) = string_list(map, "ip_cidr", at)? {
            let prefixes = parse_prefixes(&v, at, "ip_cidr")?;
            dest_ip_cidr.push(IpCidrItem {
                prefixes,
                is_private: false,
            });
        }
        if map.get("ip_is_private").and_then(Value::as_bool) == Some(true) {
            dest_ip_cidr.push(IpCidrItem {
                prefixes: Vec::new(),
                is_private: true,
            });
        }

        if let Some(v) = port_list(map, "source_port", at)? {
            source_port.push(PortItem::Ports(v));
        }
        if let Some(v) = string_list(map, "source_port_range", at)? {
            source_port.push(PortItem::Ranges(parse_ranges(&v, at)?, v));
        }
        if let Some(v) = port_list(map, "port", at)? {
            dest_port.push(PortItem::Ports(v));
        }
        if let Some(v) = string_list(map, "port_range", at)? {
            dest_port.push(PortItem::Ranges(parse_ranges(&v, at)?, v));
        }

        const UNSUPPORTED: &[&str] = &[
            "package_name",
            "package_name_regex",
            "network_type",
            "network_is_expensive",
            "network_is_constrained",
            "wifi_ssid",
            "wifi_bssid",
            "interface_address",
            "network_interface_address",
            "default_interface_address",
            "preferred_by",
        ];
        if let Some(v) = string_list(map, "clash_mode", at)? {
            plain.push(PlainItem::ClashMode(v));
        }
        // the neighbour tables answer these two, so they need `find_neighbor`
        // (or a `local` server with `neighbor_domain`) to be running
        if let Some(v) = string_list(map, "source_mac_address", at)? {
            plain.push(PlainItem::SourceMac(
                v.iter()
                    .map(|raw| super::neighbor::parse_mac(raw).unwrap_or([0; 6]))
                    .collect(),
            ));
        }
        if let Some(v) = string_list(map, "source_hostname", at)? {
            plain.push(PlainItem::SourceHostname(v));
        }
        // `route.find_process` answers these: the process behind the socket
        if let Some(v) = string_list(map, "process_name", at)? {
            plain.push(PlainItem::ProcessName(v));
        }
        if let Some(v) = string_list(map, "process_path", at)? {
            plain.push(PlainItem::ProcessPath(v));
        }
        if let Some(v) = string_list(map, "process_path_regex", at)? {
            plain.push(PlainItem::ProcessPathRegex(
                v.iter()
                    .map(|raw| {
                        Regex::new(raw).map_err(|e| anyhow::anyhow!("{at}.process_path_regex: {e}"))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
            ));
        }
        if let Some(v) = int_list(map, "user_id", at)? {
            // the reference compares against a uid, so a negative one never
            // matches anything and is kept as the "unknown" marker
            plain.push(PlainItem::UserId(v));
        }
        if let Some(v) = string_list(map, "user", at)? {
            plain.push(PlainItem::User(v));
        }

        for key in UNSUPPORTED {
            if map.get(*key).is_some_and(|v| !v.is_null()) {
                crate::logging::warn(format_args!(
                    "{at}: {key} matcher is not supported (rule inert for that item)"
                ));
                plain.push(PlainItem::Unsupported);
            }
        }

        if let Some(v) = string_list(map, "rule_set", at)? {
            rule_set_tags = v;
        }
        let rule_sets = registry.resolve(&rule_set_tags)?;

        let invert = map.get("invert").and_then(Value::as_bool).unwrap_or(false);
        let has_items = !plain.is_empty()
            || !source_address.is_empty()
            || !source_port.is_empty()
            || !dest_address.is_empty()
            || !dest_ip_cidr.is_empty()
            || !dest_port.is_empty()
            || !rule_set_tags.is_empty();

        Ok(Rule::Default(Box::new(DefaultRule {
            plain,
            source_address,
            source_port,
            dest_address,
            dest_ip_cidr,
            dest_port,
            has_items,
            rule_sets,
            rule_set_tags,
            invert,
            action,
        })))
    }

    fn build_logical(
        map: &serde_json::Map<String, Value>,
        at: &str,
        action: Action,
        registry: &super::rule_set::RuleSetRegistry,
    ) -> anyhow::Result<Self> {
        let mode = match map.get("mode").and_then(Value::as_str) {
            Some("and") => LogicalMode::And,
            Some("or") => LogicalMode::Or,
            Some(other) => anyhow::bail!("{at}: unknown logical mode: {other}"),
            None => anyhow::bail!("{at}: unknown logical mode: "),
        };
        let subs = map
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing rules"))?;
        let mut rules = Vec::with_capacity(subs.len());
        for (i, sub) in subs.iter().enumerate() {
            let sub_at = format!("{at}: sub rule[{i}]");
            reject_nested_action(sub, &sub_at)?;
            rules.push(Self::build_with_rule_sets(sub, &sub_at, false, registry)?);
        }
        let invert = map.get("invert").and_then(Value::as_bool).unwrap_or(false);
        Ok(Rule::Logical(Box::new(LogicalRule {
            mode,
            rules,
            invert,
            action,
        })))
    }

    pub fn action(&self) -> &Action {
        match self {
            Rule::Default(r) => &r.action,
            Rule::Logical(r) => &r.action,
        }
    }

    /// Reference `GET /rules` entry: `(type, payload, proxy)` where payload
    /// is the rule's `String()`.
    pub fn clash_view(&self) -> (String, String, String) {
        let kind = match self {
            Rule::Default(_) => "default",
            Rule::Logical(_) => "logical",
        };
        (
            kind.to_string(),
            self.description(),
            self.action().clash_view(),
        )
    }

    /// `rule.String()`: items for a default rule; for a logical one the
    /// subrules joined by ` && ` / ` || `, unparenthesised.
    fn description(&self) -> String {
        match self {
            Rule::Default(r) => r.item_description(),
            Rule::Logical(r) => {
                let op = match r.mode {
                    LogicalMode::And => " && ",
                    LogicalMode::Or => " || ",
                };
                let inner: Vec<String> = r.rules.iter().map(Rule::description).collect();
                wrap_invert(r.invert, &inner.join(op))
            }
        }
    }

    /// The `rule` field of a `/connections` entry: `<rule> => <action>`.
    pub fn clash_primary(&self) -> String {
        format!("{} => {}", self.description(), self.action().clash_view())
    }

    pub fn matches(&self, ctx: &ConnContext) -> bool {
        match self {
            Rule::Default(r) => r.matches(ctx),
            Rule::Logical(r) => r.matches(ctx),
        }
    }

    /// `isProcessRule`: this rule needs the process searcher, so the router
    /// has to arm it even without `route.find_process`.
    pub fn needs_process(&self) -> bool {
        match self {
            Rule::Default(r) => r.plain.iter().any(is_process_item),
            Rule::Logical(r) => r.rules.iter().any(Rule::needs_process),
        }
    }

    /// `isNeighborRule`: this rule needs the neighbour tables, so the router
    /// has to build them even without `route.find_neighbor`.
    pub fn needs_neighbor(&self) -> bool {
        match self {
            Rule::Default(r) => r
                .plain
                .iter()
                .any(|item| matches!(item, PlainItem::SourceMac(_) | PlainItem::SourceHostname(_))),
            Rule::Logical(r) => r.rules.iter().any(Rule::needs_neighbor),
        }
    }
}

impl DefaultRule {
    /// `abstractDefaultRule.String`: item descriptions joined by spaces,
    /// wrapped in `!(...)` for inverted rules.
    fn item_description(&self) -> String {
        // `NewDefaultRule` appends items in a fixed order: the connection
        // items first, then domains, addresses, ports, the process and
        // neighbour items, and the rule sets last
        let mut plain: Vec<(u8, String)> =
            self.plain.iter().filter_map(plain_description).collect();
        plain.sort_by_key(|(rank, _)| *rank);
        let (head, tail): (Vec<_>, Vec<_>) = plain.into_iter().partition(|(rank, _)| *rank < 10);

        let mut parts: Vec<String> = head.into_iter().map(|(_, text)| text).collect();
        let domains: Vec<String> = self
            .dest_address
            .iter()
            .filter_map(|item| match item {
                DomainItem::Exact(list) => Some(("domain", list.clone())),
                DomainItem::Suffix(list) => Some(("domain_suffix", list.clone())),
                DomainItem::Keyword(list) => Some(("domain_keyword", list.clone())),
                DomainItem::Regex(_) => None,
            })
            .flat_map(|(name, list)| {
                list.into_iter()
                    .map(|value| format!("{name}={value}"))
                    .collect::<Vec<_>>()
            })
            .collect();
        if !domains.is_empty() {
            parts.push(collapse_fields(&domains));
        }
        for item in &self.dest_address {
            if let DomainItem::Regex(list) = item {
                let values: Vec<String> = list.iter().map(|re| re.as_str().to_string()).collect();
                parts.push(field_list("domain_regex", &values));
            }
        }
        for item in &self.source_address {
            match item {
                AddressItem::Cidr(list) => {
                    let values: Vec<String> = list.iter().map(IpPrefix::to_cidr).collect();
                    parts.push(field_list("source_ip_cidr", &values));
                }
                AddressItem::IsPrivate => parts.push("source_ip_is_private=true".to_string()),
            }
        }
        for item in &self.dest_ip_cidr {
            let values: Vec<String> = item.prefixes.iter().map(IpPrefix::to_cidr).collect();
            if !values.is_empty() {
                parts.push(field_list("ip_cidr", &values));
            }
            if item.is_private {
                parts.push("ip_is_private=true".to_string());
            }
        }
        for item in &self.source_port {
            parts.push(port_description(true, item));
        }
        for item in &self.dest_port {
            parts.push(port_description(false, item));
        }
        parts.extend(tail.into_iter().map(|(_, text)| text));
        // `RuleSetItem.String` brackets every multi-tag list, never truncates
        match self.rule_set_tags.as_slice() {
            [] => {}
            [tag] => parts.push(format!("rule_set={tag}")),
            tags => parts.push(format!("rule_set=[{}]", tags.join(" "))),
        }
        wrap_invert(self.invert, &parts.join(" "))
    }

    fn matches(&self, ctx: &ConnContext) -> bool {
        if !self.has_items {
            // Empty allItems → true, invert ignored (reference Match).
            return true;
        }
        let matched = self.match_inner(ctx);
        matched != self.invert
    }

    fn match_inner(&self, ctx: &ConnContext) -> bool {
        let mut required = 0u8;
        let mut satisfied = 0u8;

        if !self.source_address.is_empty() {
            required |= SOURCE_ADDRESS;
            if self
                .source_address
                .iter()
                .any(|item| item.matches_source(ctx))
            {
                satisfied |= SOURCE_ADDRESS;
            }
        }
        if !self.source_port.is_empty() {
            required |= SOURCE_PORT;
            if self
                .source_port
                .iter()
                .any(|item| item.matches(ctx.source.port()))
            {
                satisfied |= SOURCE_PORT;
            }
        }
        if !self.dest_address.is_empty() {
            required |= DEST_ADDRESS;
            if self.dest_address.iter().any(|item| item.matches(ctx)) {
                satisfied |= DEST_ADDRESS;
            }
        }
        if !self.dest_ip_cidr.is_empty() {
            // ip_cidr / ip_is_private share the destination-address group flag.
            required |= DEST_ADDRESS;
            if satisfied & DEST_ADDRESS == 0
                && self.dest_ip_cidr.iter().any(|item| item.matches(ctx))
            {
                satisfied |= DEST_ADDRESS;
            }
        }
        if !self.dest_port.is_empty() {
            required |= DEST_PORT;
            if self
                .dest_port
                .iter()
                .any(|item| item.matches(ctx.destination.port()))
            {
                satisfied |= DEST_PORT;
            }
        }

        if !self.rule_sets.is_empty() {
            // `RuleSetItem`: any referenced set matching satisfies the item
            required |= DEST_ADDRESS;
            if satisfied & DEST_ADDRESS == 0 && self.rule_sets.iter().any(|set| set.matches(ctx)) {
                satisfied |= DEST_ADDRESS;
            }
        }

        for item in &self.plain {
            if !item.matches(ctx) {
                return false;
            }
        }
        required & !satisfied == 0
    }
}

impl LogicalRule {
    fn matches(&self, ctx: &ConnContext) -> bool {
        let matched = match self.mode {
            LogicalMode::And => self.rules.iter().all(|r| r.matches(ctx)),
            LogicalMode::Or => self.rules.iter().any(|r| r.matches(ctx)),
        };
        matched != self.invert
    }
}

impl PlainItem {
    fn matches(&self, ctx: &ConnContext) -> bool {
        match self {
            PlainItem::Inbound(list) => ctx
                .inbound
                .as_deref()
                .is_some_and(|v| list.iter().any(|i| i == v)),
            PlainItem::IpVersion { is_v6 } => {
                if let Some(v) = ctx.ip_version {
                    return (v == 6) == *is_v6;
                }
                if let super::Target::Ip(addr) = ctx.destination {
                    return addr.is_ipv6() == *is_v6;
                }
                false
            }
            PlainItem::Network(list) => list.iter().any(|n| n == ctx.network),
            PlainItem::AuthUser(list) => ctx
                .auth_user
                .as_deref()
                .is_some_and(|u| list.iter().any(|i| i == u)),
            PlainItem::Protocol(list) => ctx
                .protocol
                .as_deref()
                .is_some_and(|p| list.iter().any(|i| i == p)),
            PlainItem::Client(list) => ctx
                .client
                .as_deref()
                .is_some_and(|c| list.iter().any(|i| i == c)),
            PlainItem::ClashMode(list) => list.iter().any(|mode| mode == crate::clash_mode::get()),
            PlainItem::SourceMac(list) => ctx.source_mac.is_some_and(|mac| list.contains(&mac)),
            PlainItem::SourceHostname(list) => ctx
                .source_hostname
                .as_deref()
                .is_some_and(|name| list.iter().any(|item| item == name)),
            // the reference requires a non-empty path for all three path
            // matchers (`ProcessPath == ""` never matches)
            PlainItem::ProcessName(list) => ctx
                .process
                .as_ref()
                .is_some_and(|info| !info.path.is_empty() && list.iter().any(|n| n == info.name())),
            PlainItem::ProcessPath(list) => ctx
                .process
                .as_ref()
                .is_some_and(|info| !info.path.is_empty() && list.contains(&info.path)),
            PlainItem::ProcessPathRegex(list) => ctx.process.as_ref().is_some_and(|info| {
                !info.path.is_empty() && list.iter().any(|re| re.is_match(&info.path))
            }),
            // -1 is the reference's "unknown uid" and matches nothing
            PlainItem::UserId(list) => ctx
                .process
                .as_ref()
                .and_then(|info| info.user_id)
                .is_some_and(|uid| list.contains(&(uid as i64))),
            PlainItem::User(list) => ctx.process.as_ref().is_some_and(|info| {
                info.user_name
                    .as_deref()
                    .is_some_and(|name| list.iter().any(|item| item == name))
            }),
            PlainItem::Unsupported => false,
        }
    }
}

impl AddressItem {
    fn matches_source(&self, ctx: &ConnContext) -> bool {
        match self {
            AddressItem::Cidr(prefixes) => prefixes.iter().any(|p| p.contains(ctx.source.ip())),
            AddressItem::IsPrivate => !is_public_addr(ctx.source.ip()),
        }
    }
}

impl PortItem {
    fn matches(&self, port: u16) -> bool {
        match self {
            PortItem::Ports(list) => list.contains(&port),
            PortItem::Ranges(ranges, _) => ranges.iter().any(|(a, b)| port >= *a && port <= *b),
        }
    }
}

impl DomainItem {
    fn matches(&self, ctx: &ConnContext) -> bool {
        let host = match domain_host(ctx) {
            Some(h) => h,
            None => return false,
        };
        match self {
            DomainItem::Exact(list) => list.iter().any(|d| d.as_str() == host.as_ref()),
            DomainItem::Suffix(list) => list.iter().any(|s| domain_suffix_match(&host, s)),
            DomainItem::Keyword(list) => list.iter().any(|k| host.contains(k.as_str())),
            DomainItem::Regex(list) => list.iter().any(|re| re.is_match(&host)),
        }
    }
}

impl IpCidrItem {
    fn matches(&self, ctx: &ConnContext) -> bool {
        if self.is_private {
            return match ctx.destination {
                super::Target::Ip(addr) => !is_public_addr(addr.ip()),
                _ => ctx
                    .destination_addresses
                    .iter()
                    .any(|ip| !is_public_addr(*ip)),
            };
        }
        match ctx.destination {
            super::Target::Ip(addr) => self.prefixes.iter().any(|p| p.contains(addr.ip())),
            _ if !ctx.destination_addresses.is_empty() => ctx
                .destination_addresses
                .iter()
                .any(|ip| self.prefixes.iter().any(|p| p.contains(*ip))),
            _ => false,
        }
    }
}

/// The connection's host, lowercased. Borrowed when the case is already down,
/// which is the common case: the scan is free and the `String` is not.
pub(super) fn domain_host<'a>(ctx: &'a ConnContext) -> Option<Cow<'a, str>> {
    let raw = match &ctx.domain {
        Some(d) => d.as_str(),
        None => match &ctx.destination {
            super::Target::Domain(h, _) => h.as_str(),
            super::Target::Ip(_) => return None,
        },
    };
    Some(if raw.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(raw.to_ascii_lowercase())
    } else {
        Cow::Borrowed(raw)
    })
}

/// Label-boundary suffix match; a leading-dot suffix is a pure string suffix.
pub(super) fn domain_suffix_match(host: &str, suffix: &str) -> bool {
    if suffix.starts_with('.') {
        return host.ends_with(suffix);
    }
    let Some(rest) = host.len().checked_sub(suffix.len()) else {
        return false;
    };
    // equal length is the exact match; otherwise the byte in front of the
    // suffix has to be the label dot — no `format!` on the match path
    host.ends_with(suffix) && (rest == 0 || host.as_bytes()[rest - 1] == b'.')
}

/// sing `network.IsPublicAddr`: not private/loopback/multicast/link-local/
/// interface-local-multicast/unspecified.
pub fn is_public_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_private()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_link_local()
                || a.is_unspecified())
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            let ula = s[0] & 0xfe00 == 0xfc00;
            let link_local = s[0] & 0xffc0 == 0xfe80;
            let iface_mc = s[0] == 0xff01;
            !(ula
                || a.is_loopback()
                || a.is_multicast()
                || link_local
                || iface_mc
                || a.is_unspecified())
        }
    }
}

/// Reference `DefaultRule.IsValid`: any field besides `invert` set.
fn rule_is_valid(map: &serde_json::Map<String, Value>) -> bool {
    map.keys().any(|k| k != "invert" && k != "type")
}

fn logical_is_valid(map: &serde_json::Map<String, Value>) -> bool {
    let Some(rules) = map.get("rules").and_then(Value::as_array) else {
        return false;
    };
    if rules.is_empty() {
        return false;
    }
    rules.iter().all(|sub| {
        sub.as_object()
            .is_some_and(|m| rule_is_valid(m) || logical_is_valid(m))
    })
}

/// Nested rules reject configured route-rule actions (reference
/// `rejectNestedRouteRuleAction`).
const ROUTE_ACTION_KEYS: &[&str] = &[
    "action",
    "outbound",
    "override_address",
    "override_port",
    "method",
    "no_drop",
    "sniffer",
    "timeout",
    "server",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "network_strategy",
    "fallback_delay",
    "udp_timeout",
    "udp_connect",
    "udp_disable_domain_unmapping",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof",
    "tls_spoof_method",
];

fn reject_nested_action(obj: &Value, at: &str) -> anyhow::Result<()> {
    let map = match obj.as_object() {
        Some(m) => m,
        None => return Ok(()),
    };
    if ROUTE_ACTION_KEYS.iter().any(|k| map.contains_key(*k)) {
        anyhow::bail!("{at}: rule action is not supported in nested rules");
    }
    if map.get("type").and_then(Value::as_str) == Some("logical")
        && let Some(subs) = map.get("rules").and_then(Value::as_array)
    {
        for (i, sub) in subs.iter().enumerate() {
            reject_nested_action(sub, &format!("{at}: sub rule[{i}]"))?;
        }
    }
    Ok(())
}

fn build_action(map: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Action> {
    let raw = map.get("action").and_then(Value::as_str).unwrap_or("");
    match raw {
        "" | "route" => {
            let outbound = map
                .get("outbound")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(Action::Route {
                outbound,
                opts: build_route_options(map, at)?,
            })
        }
        "route-options" => {
            let opts = build_route_options(map, at)?;
            if opts.override_address.is_none()
                && opts.override_port.is_none()
                && opts.udp_timeout.is_none()
                && !has_any_route_option_field(map)
            {
                anyhow::bail!("{at}: empty route option action");
            }
            if map.get("tls_fragment").and_then(Value::as_bool) == Some(true)
                && map.get("tls_record_fragment").and_then(Value::as_bool) == Some(true)
            {
                anyhow::bail!(
                    "{at}: `tls_fragment` and `tls_record_fragment` are mutually exclusive"
                );
            }
            Ok(Action::RouteOptions(opts))
        }
        "direct" => Ok(Action::Direct),
        "bypass" => {
            let outbound = map
                .get("outbound")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(Action::Bypass {
                outbound,
                opts: build_route_options(map, at)?,
            })
        }
        "reject" => {
            let no_drop = map.get("no_drop").and_then(Value::as_bool) == Some(true);
            let method = match map.get("method").and_then(Value::as_str) {
                None | Some("") | Some("default") => RejectMethod::Default,
                Some("drop") => {
                    if no_drop {
                        anyhow::bail!("{at}: no_drop is not available in current context");
                    }
                    RejectMethod::Drop
                }
                Some("reply") => RejectMethod::Reply,
                Some(other) => anyhow::bail!("{at}: unknown reject method: {other}"),
            };
            Ok(Action::Reject {
                method,
                no_drop,
                flood: Arc::new(RejectFlood::default()),
            })
        }
        "hijack-dns" => Ok(Action::HijackDns),
        "sniff" => {
            let sniffer = string_list(map, "sniffer", at)?.unwrap_or_default();
            for name in &sniffer {
                if !is_known_sniffer(name) {
                    anyhow::bail!("{at}: unknown sniffer: {name}");
                }
            }
            // zero means unset: the sniffers fall back to the default, and
            // the description prints only what the config gave
            let timeout = parse_duration(
                map.get("timeout"),
                Duration::ZERO,
                &format!("{at}: timeout"),
            )?;
            Ok(Action::Sniff { sniffer, timeout })
        }
        "resolve" => {
            let server = map
                .get("server")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let strategy = match map.get("strategy").and_then(Value::as_str) {
                Some(s) if !s.is_empty() => Some(crate::dns::Strategy::parse(s)?),
                _ => None,
            };
            let timeout = if let Some(v) = map.get("timeout") {
                let d = parse_duration(Some(v), Duration::ZERO, &format!("{at}: timeout"))?;
                if d == Duration::ZERO { None } else { Some(d) }
            } else {
                None
            };
            for key in [
                "disable_cache",
                "disable_optimistic_cache",
                "rewrite_ttl",
                "client_subnet",
            ] {
                if map.get(key).is_some_and(|v| !v.is_null()) {
                    crate::logging::warn(format_args!(
                        "{at}: resolve.{key} is not implemented yet (ignored)"
                    ));
                }
            }
            Ok(Action::Resolve(ResolveAction {
                server,
                strategy,
                timeout,
            }))
        }
        other => anyhow::bail!("{at}: unknown rule action: {other}"),
    }
}

fn has_any_route_option_field(map: &serde_json::Map<String, Value>) -> bool {
    [
        "network_strategy",
        "fallback_delay",
        "udp_connect",
        "udp_disable_domain_unmapping",
        "tls_fragment",
        "tls_record_fragment",
        "tls_spoof",
        "tls_spoof_method",
    ]
    .iter()
    .any(|k| map.get(*k).is_some_and(|v| !v.is_null()))
}

fn build_route_options(
    map: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<RouteOptions> {
    let mut opts = RouteOptions::default();
    if let Some(raw) = map.get("override_address").and_then(Value::as_str) {
        opts.override_address = Some(parse_override_address(raw, at)?);
    }
    if let Some(port) = map.get("override_port").and_then(Value::as_u64) {
        opts.override_port =
            Some(u16::try_from(port).map_err(|_| anyhow::anyhow!("{at}: invalid override_port"))?);
    }
    if let Some(v) = map.get("udp_timeout") {
        opts.udp_timeout = Some(parse_duration(
            Some(v),
            Duration::ZERO,
            &format!("{at}: udp_timeout"),
        )?);
        if opts.udp_timeout == Some(Duration::ZERO) {
            opts.udp_timeout = None;
        }
    }
    if let Some(b) = map
        .get("udp_disable_domain_unmapping")
        .and_then(Value::as_bool)
    {
        opts.udp_disable_domain_unmapping = Some(b);
    }
    if let Some(b) = map.get("tls_fragment").and_then(Value::as_bool) {
        opts.tls_fragment = Some(b);
    }
    if let Some(b) = map.get("tls_record_fragment").and_then(Value::as_bool) {
        opts.tls_record_fragment = Some(b);
    }
    for key in [
        "network_strategy",
        "fallback_delay",
        "udp_connect",
        "tls_spoof",
        "tls_spoof_method",
    ] {
        if map.get(key).is_some_and(|v| !v.is_null()) {
            crate::logging::warn(format_args!(
                "{at}: route option {key} is not implemented yet (ignored)"
            ));
        }
    }
    Ok(opts)
}

/// Host part only — a port embedded in `override_address` is ignored
/// (reference `applyRouteOptionsOverride` keeps the current destination port).
fn parse_override_address(raw: &str, at: &str) -> anyhow::Result<TargetOverride> {
    let host = if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(TargetOverride::Ip(ip));
    } else if let Some(rest) = raw.strip_prefix('[') {
        // [v6]:port
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("{at}: invalid override_address {raw:?}"))?;
        &rest[..end]
    } else if let Some((h, p)) = raw.rsplit_once(':')
        && p.parse::<u16>().is_ok()
        && !h.contains(':')
    {
        h
    } else {
        raw
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(TargetOverride::Ip(ip))
    } else if host.is_empty() {
        anyhow::bail!("{at}: invalid override_address {raw:?}")
    } else {
        Ok(TargetOverride::Domain(host.to_string()))
    }
}

pub fn is_known_sniffer(name: &str) -> bool {
    matches!(
        name,
        "tls" | "http" | "quic" | "dns" | "stun" | "bittorrent" | "dtls" | "ssh" | "rdp" | "ntp"
    )
}

fn lower_all(v: Vec<String>) -> Vec<String> {
    v.into_iter().map(|s| s.to_ascii_lowercase()).collect()
}

fn string_list(
    map: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(vec![s.clone()])),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                let s = v
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{at}: {key} entries must be strings"))?;
                if s.is_empty() && (key == "domain" || key == "domain_suffix") {
                    anyhow::bail!("{at}: {key}: empty item is not allowed");
                }
                out.push(s.to_string());
            }
            Ok(Some(out))
        }
        Some(_) => Err(anyhow::anyhow!("{at}: {key} must be a string or array")),
    }
}

/// `badoption.Listable[int32]`: one number or an array of them, signed because
/// the reference's `user_id` reserves -1 for "unknown".
fn int_list(
    map: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<Option<Vec<i64>>> {
    let number = |v: &Value| {
        v.as_i64()
            .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
            .ok_or_else(|| anyhow::anyhow!("{at}: invalid {key}"))
    };
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v @ Value::Number(_)) => Ok(Some(vec![number(v)?])),
        Some(Value::Array(items)) => items
            .iter()
            .map(number)
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(anyhow::anyhow!("{at}: {key} must be a number or array")),
    }
}

fn port_list(
    map: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<Option<Vec<u16>>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let p = u16::try_from(n.as_u64().unwrap_or(u64::MAX))
                .map_err(|_| anyhow::anyhow!("{at}: invalid {key}"))?;
            Ok(Some(vec![p]))
        }
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                let p = v
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or_else(|| anyhow::anyhow!("{at}: invalid {key}"))?;
                out.push(p);
            }
            Ok(Some(out))
        }
        Some(_) => Err(anyhow::anyhow!("{at}: {key} must be a number or array")),
    }
}

fn parse_prefixes(raw: &[String], at: &str, key: &str) -> anyhow::Result<Vec<IpPrefix>> {
    raw.iter()
        .map(|s| {
            let with_bits = if s.contains('/') {
                s.clone()
            } else {
                let ip: IpAddr = s
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{at}: bad {key}: {s:?}: unable to parse IP"))?;
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                format!("{s}/{bits}")
            };
            IpPrefix::parse(&with_bits).map_err(|e| anyhow::anyhow!("{at}: bad {key}: {s:?}: {e}"))
        })
        .collect()
}

fn parse_ranges(raw: &[String], at: &str) -> anyhow::Result<Vec<(u16, u16)>> {
    raw.iter()
        .map(|s| {
            let Some((a, b)) = s.split_once(':') else {
                anyhow::bail!("{at}: bad port range: {s}");
            };
            let start = if a.is_empty() {
                0
            } else {
                a.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("{at}: bad port range: {s}"))?
            };
            let end = if b.is_empty() {
                u16::MAX
            } else {
                b.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("{at}: bad port range: {s}"))?
            };
            Ok((start, end))
        })
        .collect()
}

/// Apply phase-A route options to the connection context.
pub fn apply_route_options(ctx: &mut ConnContext, opts: &RouteOptions) {
    let overriding = opts.override_address.is_some() || opts.override_port.is_some();
    if overriding && ctx.route_original_destination.is_none() {
        ctx.route_original_destination = Some(ctx.destination.clone());
    }
    if opts.override_address.is_some() {
        ctx.destination_addresses.clear();
    }
    if let Some(addr) = &opts.override_address {
        let port = ctx.destination.port();
        ctx.destination = match addr {
            TargetOverride::Ip(ip) => super::Target::Ip(SocketAddr::new(*ip, port)),
            TargetOverride::Domain(h) => super::Target::Domain(h.clone(), port),
        };
    }
    if let Some(port) = opts.override_port {
        ctx.destination = match &ctx.destination {
            super::Target::Ip(a) => super::Target::Ip(SocketAddr::new(a.ip(), port)),
            super::Target::Domain(h, _) => super::Target::Domain(h.clone(), port),
        };
    }
    if let Some(d) = opts.udp_timeout {
        ctx.udp_timeout = Some(d);
    }
    if let Some(b) = opts.udp_disable_domain_unmapping {
        ctx.udp_disable_domain_unmapping = Some(b);
    }
    if let Some(b) = opts.tls_fragment {
        ctx.tls_fragment = Some(b);
    }
    if let Some(b) = opts.tls_record_fragment {
        ctx.tls_record_fragment = Some(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::Ipv4Addr;

    fn ctx_to(host: &str, port: u16) -> ConnContext {
        ConnContext {
            inbound: Some("in".into()),
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            destination: super::super::Target::Domain(host.to_string(), port),
            ..Default::default()
        }
    }

    #[test]
    fn clash_mode_follows_the_controller() {
        let rule = Rule::build(
            &json!({"action": "route", "outbound": "o", "clash_mode": ["global"]}),
            "r",
            true,
        )
        .unwrap();
        let ctx = ctx_to("example.com", 443);
        crate::clash_mode::set("rule");
        assert!(!rule.matches(&ctx), "the mode is not global yet");
        crate::clash_mode::set("global");
        assert!(rule.matches(&ctx));
        crate::clash_mode::set("direct");
        assert!(!rule.matches(&ctx), "and not after switching away");
        // the description follows the matcher
        assert_eq!(rule.clash_view().1, "clash_mode=global");
    }

    fn describe(rule: Value) -> (String, String) {
        let (_, payload, action) = Rule::build(&rule, "r", true).unwrap().clash_view();
        (payload, action)
    }

    #[test]
    fn descriptions_follow_the_reference_order() {
        // items print in `NewDefaultRule` order, whatever order the config used
        let (payload, action) = describe(json!({
            "port_range": ["10:20"], "source_port_range": ["30:"], "ip_is_private": true,
            "source_ip_is_private": true, "process_name": ["curl"], "domain_suffix": ["b.com"],
            "domain": ["a.com"], "network": ["tcp"], "inbound": ["in"],
            "action": "route", "outbound": "direct", "override_port": 53, "tls_fragment": true,
        }));
        assert_eq!(
            payload,
            "inbound=in network=tcp domain=a.com domain_suffix=b.com \
             source_ip_is_private=true ip_is_private=true source_port_range=30: \
             port_range=10:20 process_name=curl"
        );
        assert_eq!(action, "route(direct,override-port=53,tls-fragment)");

        let (payload, _) = describe(json!({
            "type": "logical", "mode": "or", "invert": true, "action": "reject",
            "rules": [{"port": 1}, {"type": "logical", "mode": "and",
                       "rules": [{"port": 2}, {"network": "udp"}]}],
        }));
        assert_eq!(payload, "!(port=1 || port=2 && network=udp)");
    }

    #[test]
    fn action_descriptions() {
        let action = |extra: Value| {
            let mut rule = json!({"port": 1});
            rule.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            describe(rule).1
        };
        assert_eq!(action(json!({"action": "sniff"})), "sniff");
        assert_eq!(
            action(json!({"action": "sniff", "timeout": "1.5s"})),
            "sniff(1.5s)"
        );
        assert_eq!(
            action(json!({"action": "sniff", "sniffer": ["dns"], "timeout": "90s"})),
            "sniff(dns,1m30s)"
        );
        assert_eq!(action(json!({"action": "resolve"})), "resolve");
        assert_eq!(
            action(json!({"action": "resolve", "server": "dns-u", "strategy": "ipv4_only"})),
            "resolve(dns-u,ipv4_only)"
        );
        assert_eq!(
            action(
                json!({"action": "route-options", "override_address": "1.2.3.4",
                          "udp_timeout": "5m"})
            ),
            "route-options(override-address=1.2.3.4,udp-timeout)"
        );
        assert_eq!(action(json!({"action": "bypass"})), "bypass()");
        assert_eq!(
            action(json!({"action": "reject", "method": "drop"})),
            "reject(drop)"
        );
    }

    #[test]
    fn go_duration_strings() {
        for (d, want) in [
            (Duration::ZERO, "0s"),
            (Duration::from_nanos(500), "500ns"),
            (Duration::from_nanos(1_500), "1.5\u{b5}s"),
            (Duration::from_millis(300), "300ms"),
            (Duration::from_millis(1_500), "1.5s"),
            (Duration::from_secs(90), "1m30s"),
            (Duration::from_secs(3_600), "1h0m0s"),
            (Duration::from_millis(120_500), "2m0.5s"),
        ] {
            assert_eq!(go_duration_string(d), want);
        }
    }

    #[test]
    fn domain_suffix_boundary() {
        let rule = Rule::build(
            &json!({"action": "route", "outbound": "o", "domain_suffix": ["example.com"]}),
            "r",
            true,
        )
        .unwrap();
        assert!(rule.matches(&ctx_to("example.com", 443)));
        assert!(rule.matches(&ctx_to("www.example.com", 443)));
        assert!(!rule.matches(&ctx_to("notexample.com", 443)));
        assert!(!rule.matches(&ctx_to("example.com.evil", 443)));
    }

    #[test]
    fn leading_dot_suffix_is_pure() {
        let rule = Rule::build(
            &json!({"action": "route", "outbound": "o", "domain_suffix": [".example.com"]}),
            "r",
            true,
        )
        .unwrap();
        assert!(rule.matches(&ctx_to("www.example.com", 443)));
        assert!(!rule.matches(&ctx_to("example.com", 443)));
    }

    #[test]
    fn port_group_and_invert() {
        let rule = Rule::build(
            &json!({"action": "route", "outbound": "o", "port": [80, 443], "invert": true}),
            "r",
            true,
        )
        .unwrap();
        assert!(!rule.matches(&ctx_to("x.test", 443)));
        assert!(rule.matches(&ctx_to("x.test", 8080)));
    }

    #[test]
    fn logical_and_or() {
        let and = Rule::build(
            &json!({
                "type": "logical", "mode": "and", "action": "route", "outbound": "o",
                "rules": [
                    {"domain": ["a.test"]},
                    {"port": [443]}
                ]
            }),
            "r",
            true,
        )
        .unwrap();
        assert!(and.matches(&ctx_to("a.test", 443)));
        assert!(!and.matches(&ctx_to("a.test", 80)));
        assert!(!and.matches(&ctx_to("b.test", 443)));

        let or = Rule::build(
            &json!({
                "type": "logical", "mode": "or", "action": "route", "outbound": "o",
                "rules": [
                    {"domain": ["a.test"]},
                    {"port": [443]}
                ]
            }),
            "r",
            true,
        )
        .unwrap();
        assert!(or.matches(&ctx_to("a.test", 80)));
        assert!(or.matches(&ctx_to("b.test", 443)));
        assert!(!or.matches(&ctx_to("b.test", 80)));
    }

    #[test]
    fn empty_rule_matches_everything() {
        let rule = Rule::build(&json!({"action": "hijack-dns"}), "r", true).unwrap();
        assert!(rule.matches(&ctx_to("anything", 1)));
    }

    #[test]
    fn missing_conditions_rejected() {
        let err = Rule::build(&json!({"invert": true}), "r", true).unwrap_err();
        assert!(err.to_string().contains("missing conditions"));
    }

    #[test]
    fn missing_outbound_rejected() {
        let err = Rule::build(&json!({"domain": ["a.test"]}), "r", true).unwrap_err();
        assert!(err.to_string().contains("missing outbound field"));
    }

    #[test]
    fn nested_action_rejected() {
        let err = Rule::build(
            &json!({
                "type": "logical", "mode": "and", "action": "route", "outbound": "o",
                "rules": [{"domain": ["a.test"], "action": "reject"}]
            }),
            "r",
            true,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("rule action is not supported in nested rules"),
            "{err}"
        );
    }

    #[test]
    fn ip_cidr_and_domain_share_group() {
        let rule = Rule::build(
            &json!({
                "action": "route", "outbound": "o",
                "domain_suffix": ["a.test"],
                "ip_cidr": ["10.0.0.0/8"]
            }),
            "r",
            true,
        )
        .unwrap();
        let mut c = ctx_to("b.test", 443);
        c.destination_addresses = vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))];
        assert!(rule.matches(&c));
        let c2 = ctx_to("www.a.test", 443);
        assert!(rule.matches(&c2));
        assert!(!rule.matches(&ctx_to("b.test", 443)));
    }

    #[test]
    fn is_public_addr_semantics() {
        assert!(is_public_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_public_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_public_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_addr(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        let ula: IpAddr = "fd00::1".parse().unwrap();
        assert!(!is_public_addr(ula));
        let ll: IpAddr = "fe80::1".parse().unwrap();
        assert!(!is_public_addr(ll));
        assert!(!is_public_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn override_address_strips_port() {
        let opts = parse_override_address("1.2.3.4:8443", "r").unwrap();
        match opts {
            TargetOverride::Ip(ip) => assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            _ => panic!("expected ip"),
        }
        let opts = parse_override_address("example.com", "r").unwrap();
        assert!(matches!(opts, TargetOverride::Domain(ref h) if h == "example.com"));
    }

    #[test]
    fn port_range_parse() {
        let r = parse_ranges(&["80:90".into(), ":100".into(), "200:".into()], "r").unwrap();
        assert_eq!(r, vec![(80, 90), (0, 100), (200, 65535)]);
        assert!(parse_ranges(&["80".into()], "r").is_err());
    }

    #[test]
    fn unknown_rule_type() {
        let err = Rule::build(&json!({"type": "bogus", "domain": ["a"]}), "r", true).unwrap_err();
        assert!(err.to_string().contains("unknown rule type"));
    }

    #[test]
    fn reject_flood_window_escalates_after_50() {
        let flood = RejectFlood::default();
        for _ in 0..50 {
            assert!(!flood.trigger(), "within window must not flood");
        }
        assert!(flood.trigger(), "51st hit inside 30s window floods");
    }

    #[test]
    fn reject_method_build_parity() {
        let r = Rule::build(
            &json!({"action": "reject", "method": "drop", "port": [1]}),
            "r",
            true,
        )
        .unwrap();
        match r.action() {
            Action::Reject {
                method,
                no_drop,
                flood,
            } => {
                assert_eq!(*method, RejectMethod::Drop);
                assert!(!*no_drop);
                assert!(!flood.trigger(), "drop never counts toward flood");
            }
            other => panic!("expected reject, got {:?}", other.type_name()),
        }

        let r = Rule::build(
            &json!({"action": "reject", "no_drop": true, "port": [1]}),
            "r",
            true,
        )
        .unwrap();
        match r.action() {
            Action::Reject {
                method,
                no_drop,
                flood,
            } => {
                assert_eq!(*method, RejectMethod::Default);
                assert!(*no_drop);
                // no_drop short-circuits before the counter in reject_error;
                // the shared flood handle itself is still fresh.
                assert!(!flood.trigger());
            }
            other => panic!("expected reject, got {:?}", other.type_name()),
        }

        let err = Rule::build(
            &json!({"action": "reject", "method": "drop", "no_drop": true, "port": [1]}),
            "r",
            true,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no_drop is not available"),
            "{err}"
        );
        let err = Rule::build(
            &json!({"action": "reject", "method": "bogus", "port": [1]}),
            "r",
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown reject method"), "{err}");
    }

    /// The process matchers read the owner `route.find_process` found, and
    /// every one of them needs a path — the reference treats an empty
    /// `ProcessPath` as "no owner", whatever else it knows. One rule per item:
    /// the items of a rule are ANDed, so mixing them would prove nothing.
    #[test]
    fn process_matchers_read_the_socket_owner() {
        let rule = |item: serde_json::Value| {
            let mut spec = item.as_object().unwrap().clone();
            spec.insert("port".into(), json!([443]));
            spec.insert("outbound".into(), json!("d"));
            Rule::build(&Value::Object(spec), "r", true).expect("rule")
        };
        let owner = |path: &str, uid: Option<u32>, user: Option<&str>| {
            let mut ctx = ctx_to("example.com", 443);
            ctx.process = Some(super::super::process::ProcessInfo {
                path: path.to_string(),
                user_id: uid,
                user_name: user.map(str::to_string),
            });
            ctx
        };
        let sing_box = owner("/usr/bin/sing-box", Some(0), Some("root"));

        for (item, matches, why) in [
            (
                json!({"process_name": ["curl"]}),
                false,
                "the basename differs",
            ),
            (
                json!({"process_name": "sing-box"}),
                true,
                "one string is one value",
            ),
            (
                json!({"process_path": ["/usr/bin/sing-box"]}),
                true,
                "the whole path",
            ),
            (
                json!({"process_path": ["/usr/bin/"]}),
                false,
                "not a prefix match",
            ),
            (
                json!({"process_path_regex": ["^/usr/.*box$"]}),
                true,
                "by regexp",
            ),
            (json!({"user": ["root"]}), true, "the name from /etc/passwd"),
            (json!({"user": ["nobody"]}), false, "another user"),
            (json!({"user_id": [0]}), true, "the uid itself"),
            (json!({"user_id": [1000]}), false, "another uid"),
        ] {
            let rule = rule(item.clone());
            assert!(rule.needs_process(), "{item} needs the searcher");
            assert_eq!(rule.matches(&sing_box), matches, "{item}: {why}");
        }

        assert!(
            !rule(json!({"process_name": ["sing-box"]})).matches(&owner("", Some(0), Some("root"))),
            "an empty path never matches, the reference guards on it"
        );
        assert!(
            !rule(json!({"user_id": [0]})).matches(&owner("/usr/bin/sing-box", None, None)),
            "a process with no readable uid matches no uid rule"
        );
        assert!(
            !rule(json!({"user": ["root"]})).matches(&ctx_to("example.com", 443)),
            "no searcher ran, so no owner"
        );
    }

    #[test]
    fn a_process_free_rule_never_asks_for_the_searcher() {
        let rule = Rule::build(
            &json!({"domain": ["example.com"], "outbound": "d"}),
            "r",
            true,
        )
        .expect("rule");
        assert!(!rule.needs_process());
    }

    #[test]
    fn resolve_action_options_parsed() {
        let rule = Rule::build(
            &json!({
                "domain": ["example.com"],
                "action": "resolve",
                "server": "local-dns",
                "strategy": "ipv4_only",
                "timeout": "5s"
            }),
            "r",
            true,
        )
        .expect("rule");

        match rule.action() {
            Action::Resolve(res) => {
                assert_eq!(res.server.as_deref(), Some("local-dns"));
                assert_eq!(res.strategy, Some(crate::dns::Strategy::IPv4Only));
                assert_eq!(res.timeout, Some(Duration::from_secs(5)));
            }
            other => panic!("expected Action::Resolve, got {:?}", other),
        }
    }

    #[test]
    fn route_options_parsed_and_applied() {
        let rule = Rule::build(
            &json!({
                "domain": ["example.com"],
                "action": "route-options",
                "override_address": "1.1.1.1",
                "override_port": 853,
                "udp_timeout": "30s",
                "udp_disable_domain_unmapping": true,
                "tls_fragment": true,
                "tls_record_fragment": false,
            }),
            "r",
            true,
        )
        .expect("rule");

        let opts = rule.action().route_options().expect("route options");
        assert_eq!(opts.override_port, Some(853));
        assert_eq!(opts.udp_timeout, Some(Duration::from_secs(30)));
        assert_eq!(opts.udp_disable_domain_unmapping, Some(true));
        assert_eq!(opts.tls_fragment, Some(true));
        assert_eq!(opts.tls_record_fragment, Some(false));

        let mut ctx = ctx_to("example.com", 443);
        apply_route_options(&mut ctx, opts);

        assert_eq!(ctx.destination.port(), 853);
        assert_eq!(ctx.udp_timeout, Some(Duration::from_secs(30)));
        assert_eq!(ctx.udp_disable_domain_unmapping, Some(true));
        assert_eq!(ctx.tls_fragment, Some(true));
        assert_eq!(ctx.tls_record_fragment, Some(false));
    }
}
