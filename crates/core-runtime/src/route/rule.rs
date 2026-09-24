//! Route rule build + match: default/logical rules, group semantics,
//! all matchers used by real configs, and rule actions.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use super::ConnContext;
use crate::dns::transport::IpPrefix;
use crate::outbound::urltest::parse_duration;

pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectMethod {
    Default,
    Drop,
    Reply,
}

#[derive(Debug, Clone, Default)]
pub struct RouteOptions {
    pub override_address: Option<TargetOverride>,
    pub override_port: Option<u16>,
    pub udp_timeout: Option<Duration>,
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
    /// `rule_set` present: whole rule never matches (before invert), F3 gap.
    rule_set_never_match: bool,
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
    /// Unsupported matcher (process_*, clash_mode, …): always false.
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
    Ranges(Vec<(u16, u16)>),
}

#[derive(Debug, Clone)]
enum DomainItem {
    Exact(Vec<String>),
    Suffix(Vec<String>),
    Keyword(Vec<String>),
    Regex(Vec<Regex>),
}

#[derive(Debug, Clone)]
struct IpCidrItem {
    prefixes: Vec<IpPrefix>,
    is_private: bool,
}

impl Rule {
    /// Top-level `route.rules[i]` entry (`check_outbound` matches reference
    /// `NewRule(..., true)`).
    pub fn build(obj: &Value, at: &str, check_outbound: bool) -> anyhow::Result<Self> {
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
                let rule = Self::build_default(map, at, action)?;
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
                Self::build_logical(map, at, action)
            }
            other => anyhow::bail!("{at}: unknown rule type: {other}"),
        }
    }

    fn build_default(
        map: &serde_json::Map<String, Value>,
        at: &str,
        action: Action,
    ) -> anyhow::Result<Self> {
        let mut plain = Vec::new();
        let mut source_address = Vec::new();
        let mut source_port = Vec::new();
        let mut dest_address = Vec::new();
        let mut dest_ip_cidr = Vec::new();
        let mut dest_port = Vec::new();
        let mut rule_set_never_match = false;

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
            source_port.push(PortItem::Ranges(parse_ranges(&v, at)?));
        }
        if let Some(v) = port_list(map, "port", at)? {
            dest_port.push(PortItem::Ports(v));
        }
        if let Some(v) = string_list(map, "port_range", at)? {
            dest_port.push(PortItem::Ranges(parse_ranges(&v, at)?));
        }

        const UNSUPPORTED: &[&str] = &[
            "process_name",
            "process_path",
            "process_path_regex",
            "package_name",
            "package_name_regex",
            "user",
            "user_id",
            "clash_mode",
            "network_type",
            "network_is_expensive",
            "network_is_constrained",
            "wifi_ssid",
            "wifi_bssid",
            "interface_address",
            "network_interface_address",
            "default_interface_address",
            "source_mac_address",
            "source_hostname",
            "preferred_by",
        ];
        for key in UNSUPPORTED {
            if map.get(*key).is_some_and(|v| !v.is_null()) {
                crate::logging::warn(format_args!(
                    "{at}: {key} matcher is not supported (rule inert for that item)"
                ));
                plain.push(PlainItem::Unsupported);
            }
        }

        if map.get("rule_set").is_some_and(|v| !v.is_null()) {
            crate::logging::warn(format_args!(
                "{at}: rule_set matchers land in F3 (rule never matches)"
            ));
            rule_set_never_match = true;
        }
        if map
            .get("rule_set_ipcidr_match_source")
            .and_then(Value::as_bool)
            == Some(true)
        {
            crate::logging::warn(format_args!(
                "{at}: rule_set_ip_cidr_match_source is ignored (rule_set unimplemented)"
            ));
        }

        let invert = map.get("invert").and_then(Value::as_bool).unwrap_or(false);
        let has_items = !plain.is_empty()
            || !source_address.is_empty()
            || !source_port.is_empty()
            || !dest_address.is_empty()
            || !dest_ip_cidr.is_empty()
            || !dest_port.is_empty()
            || rule_set_never_match;

        Ok(Rule::Default(Box::new(DefaultRule {
            plain,
            source_address,
            source_port,
            dest_address,
            dest_ip_cidr,
            dest_port,
            has_items,
            rule_set_never_match,
            invert,
            action,
        })))
    }

    fn build_logical(
        map: &serde_json::Map<String, Value>,
        at: &str,
        action: Action,
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
            rules.push(Self::build(sub, &sub_at, false)?);
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

    pub fn matches(&self, ctx: &ConnContext) -> bool {
        match self {
            Rule::Default(r) => r.matches(ctx),
            Rule::Logical(r) => r.matches(ctx),
        }
    }
}

impl DefaultRule {
    fn matches(&self, ctx: &ConnContext) -> bool {
        if self.rule_set_never_match {
            return false;
        }
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
            PortItem::Ranges(ranges) => ranges.iter().any(|(a, b)| port >= *a && port <= *b),
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
            DomainItem::Exact(list) => list.iter().any(|d| d == &host),
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

fn domain_host(ctx: &ConnContext) -> Option<String> {
    if let Some(d) = &ctx.domain {
        return Some(d.to_ascii_lowercase());
    }
    match &ctx.destination {
        super::Target::Domain(h, _) => Some(h.to_ascii_lowercase()),
        super::Target::Ip(_) => None,
    }
}

/// Label-boundary suffix match; a leading-dot suffix is a pure string suffix.
fn domain_suffix_match(host: &str, suffix: &str) -> bool {
    if suffix.starts_with('.') {
        host.ends_with(suffix)
    } else {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    }
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
            let method = match map.get("method").and_then(Value::as_str) {
                None | Some("") | Some("default") => RejectMethod::Default,
                Some("drop") => {
                    if map.get("no_drop").and_then(Value::as_bool) == Some(true) {
                        anyhow::bail!("{at}: no_drop is not available in current context");
                    }
                    RejectMethod::Drop
                }
                Some("reply") => RejectMethod::Reply,
                Some(other) => anyhow::bail!("{at}: unknown reject method: {other}"),
            };
            Ok(Action::Reject { method })
        }
        "hijack-dns" => Ok(Action::HijackDns),
        "sniff" => {
            let sniffer = string_list(map, "sniffer", at)?.unwrap_or_default();
            for name in &sniffer {
                if !is_known_sniffer(name) {
                    anyhow::bail!("{at}: unknown sniffer: {name}");
                }
            }
            let timeout = parse_duration(
                map.get("timeout"),
                DEFAULT_SNIFF_TIMEOUT,
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
            for key in [
                "strategy",
                "disable_cache",
                "disable_optimistic_cache",
                "rewrite_ttl",
                "client_subnet",
                "timeout",
            ] {
                if map.get(key).is_some_and(|v| !v.is_null()) {
                    crate::logging::warn(format_args!(
                        "{at}: resolve.{key} is not implemented yet (ignored)"
                    ));
                }
            }
            Ok(Action::Resolve(ResolveAction { server }))
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
    for key in [
        "network_strategy",
        "fallback_delay",
        "udp_connect",
        "udp_disable_domain_unmapping",
        "tls_fragment",
        "tls_record_fragment",
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
}
