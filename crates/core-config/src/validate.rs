//! Semantic validation mirroring reference `sing-box check` (F1).
//!
//! Rules were derived empirically against sing-box-lx v1.14.1-lx.8: the
//! differential harness compares exit codes only, so messages here are
//! best-effort echoes of the reference wording, not a contract.
//!
//! Known intentional gaps (documented in COMPAT.md):
//! - per-protocol outbound/inbound field allowlists (reference rejects
//!   unknown fields inside protocol objects; we only check fields we
//!   verified empirically);
//! - PEM/x509 content parsing of server certificates (presence only).

use serde_json::{Map, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

const KNOWN_TOP_LEVEL: &[&str] = &[
    "log",
    "dns",
    "ntp",
    "certificate",
    "endpoints",
    "inbounds",
    "outbounds",
    "route",
    "services",
    "experimental",
    "http_clients",
];

const KNOWN_LOG_FIELDS: &[&str] = &["disabled", "level", "timestamp", "output", "time"];
const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal"];

const KNOWN_EXPERIMENTAL_FIELDS: &[&str] = &["cache_file", "clash_api"];

const KNOWN_ROUTE_FIELDS: &[&str] = &[
    "rules",
    "final",
    "rule_set",
    "geoip",
    "geosite",
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

const RULE_ACTIONS: &[&str] = &[
    "route",
    "route-options",
    "bypass",
    "hijack-dns",
    "direct",
    "sniff",
    "reject",
    "resolve",
];

/// Route-rule action fields rejected inside nested (logical sub) rules.
const NESTED_ACTION_KEYS: &[&str] = &[
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

const DNS_LEGACY_ERROR: &str = "legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats";

const KNOWN_INBOUND_TYPES: &[&str] = &[
    "mixed",
    "direct",
    "redirect",
    "tproxy",
    "socks",
    "http",
    "tun",
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "anytls",
    "hysteria2",
    "tuic",
    "shadowtls",
    "naive",
    "hysteria",
];

const KNOWN_OUTBOUND_TYPES: &[&str] = &[
    "direct",
    "block",
    "selector",
    "urltest",
    "socks",
    "http",
    "shadowsocks",
    "shadowtls",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hysteria",
    "tuic",
    "anytls",
    "chain",
    "masque",
    "naive",
    "tor",
    "ssh",
    "snell",
    "wireguard",
    "dns",
];

const TRANSPORT_TYPES: &[&str] = &["ws", "quic", "grpc", "httpupgrade", "http", "xhttp"];

const DNS_SERVER_TYPES: &[&str] = &[
    "tcp", "udp", "tls", "https", "quic", "h3", "hosts", "fakeip", "dhcp",
];

const SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "none",
    "rc4-md5",
];

const UTLS_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "edge",
    "ios",
    "android",
    "randomized",
    "random",
];

const TLS_REQUIRED_OUTBOUNDS: &[&str] = &[
    "hysteria2",
    "tuic",
    "anytls",
    "hysteria",
    "naive",
    "shadowtls",
];

const TLS_REQUIRED_INBOUNDS: &[&str] = &["hysteria2", "tuic", "hysteria"];

const SERVER_TLS_INBOUNDS: &[&str] = &["mixed", "http", "trojan"];

const TUN_LEGACY_FIELDS: &[&str] = &[
    "inet4_address",
    "inet6_address",
    "inet4_route_address",
    "inet6_route_address",
    "inet4_route_exclude_address",
    "inet6_route_exclude_address",
];

/// Validate a parsed configuration document against reference `check` rules.
pub fn validate(root: &Value) -> Result<(), String> {
    let root = root
        .as_object()
        .ok_or_else(|| "config: must be a JSON object".to_string())?;

    for key in root.keys() {
        if !KNOWN_TOP_LEVEL.contains(&key.as_str()) {
            return Err(format!("{key}: json: unknown field \"{key}\""));
        }
    }

    if let Some(log) = root.get("log") {
        validate_log(log)?;
    }
    if let Some(experimental) = root.get("experimental") {
        validate_experimental(experimental)?;
    }
    if let Some(route) = root.get("route") {
        validate_route(route)?;
    }
    if let Some(dns) = root.get("dns") {
        validate_dns(dns)?;
    }

    let mut inbound_tags: HashSet<&str> = HashSet::new();
    let mut outbound_tags: HashSet<&str> = HashSet::new();

    if let Some(list) = root.get("inbounds") {
        let entries = list.as_array().ok_or("inbounds: must be an array")?;
        for (i, entry) in entries.iter().enumerate() {
            let obj = object_entry(entry, &format!("inbounds[{i}]"))?;
            let ty = type_field(obj, &format!("inbounds[{i}]"))?;
            if !KNOWN_INBOUND_TYPES.contains(&ty) {
                return Err(format!("inbounds[{i}]: unknown inbound type: {ty}"));
            }
            let tag = tag_field(obj, &format!("inbounds[{i}]"))?;
            if !tag.is_empty() && !inbound_tags.insert(tag) {
                return Err(format!("duplicate inbound tag: {tag}"));
            }
            if let Some(listen) = obj.get("listen") {
                let addr = listen
                    .as_str()
                    .ok_or_else(|| format!("inbounds[{i}].listen: must be a string"))?;
                if IpAddr::from_str(addr).is_err() {
                    return Err(format!(
                        "inbounds[{i}].listen: ParseAddr(\"{addr}\"): unable to parse IP"
                    ));
                }
            }
            if let Some(port) = obj.get("listen_port") {
                check_u16(port).map_err(|m| format!("inbounds[{i}].listen_port: {m}"))?;
            }
            validate_inbound(i, ty, tag, obj)?;
        }
    }

    if let Some(list) = root.get("outbounds") {
        let entries = list.as_array().ok_or("outbounds: must be an array")?;
        for (i, entry) in entries.iter().enumerate() {
            let obj = object_entry(entry, &format!("outbounds[{i}]"))?;
            let ty = type_field(obj, &format!("outbounds[{i}]"))?;
            if !KNOWN_OUTBOUND_TYPES.contains(&ty) {
                return Err(format!("outbounds[{i}]: unknown outbound type: {ty}"));
            }
            let tag = tag_field(obj, &format!("outbounds[{i}]"))?;
            if !tag.is_empty() && !outbound_tags.insert(tag) {
                return Err(format!("duplicate outbound/endpoint tag: {tag}"));
            }
            if let Some(port) = obj.get("server_port") {
                check_u16(port).map_err(|m| format!("outbounds[{i}].server_port: {m}"))?;
            }
            validate_outbound(i, ty, tag, obj)?;
        }
    }

    if let Some(list) = root.get("endpoints") {
        let entries = list.as_array().ok_or("endpoints: must be an array")?;
        for (i, entry) in entries.iter().enumerate() {
            let obj = object_entry(entry, &format!("endpoints[{i}]"))?;
            let ty = type_field(obj, &format!("endpoints[{i}]"))?;
            if ty != "wireguard" {
                return Err(format!("endpoints[{i}]: unknown endpoint type: {ty}"));
            }
            let tag = tag_field(obj, &format!("endpoints[{i}]"))?;
            if !tag.is_empty() && !outbound_tags.insert(tag) {
                return Err(format!("duplicate outbound/endpoint tag: {tag}"));
            }
            if !obj.contains_key("private_key") {
                return Err(format!(
                    "initialize endpoint[{i}] wireguard[{tag}]: missing private key"
                ));
            }
        }
    }

    Ok(())
}

fn validate_log(log: &Value) -> Result<(), String> {
    let obj = log
        .as_object()
        .ok_or_else(|| "log: must be a JSON object".to_string())?;
    for key in obj.keys() {
        if !KNOWN_LOG_FIELDS.contains(&key.as_str()) {
            return Err(format!("log: {key}: json: unknown field \"{key}\""));
        }
    }
    if let Some(level) = obj.get("level") {
        let level = level
            .as_str()
            .ok_or_else(|| "log: level: must be a string".to_string())?;
        if !LOG_LEVELS.contains(&level) {
            return Err(format!(
                "create log factory: parse log level: unknown log level: {level}"
            ));
        }
    }
    Ok(())
}

fn validate_experimental(experimental: &Value) -> Result<(), String> {
    let obj = experimental
        .as_object()
        .ok_or_else(|| "experimental: must be a JSON object".to_string())?;
    for key in obj.keys() {
        if !KNOWN_EXPERIMENTAL_FIELDS.contains(&key.as_str()) {
            return Err(format!(
                "experimental: {key}: json: unknown field \"{key}\""
            ));
        }
    }
    Ok(())
}

fn validate_route(route: &Value) -> Result<(), String> {
    let obj = route
        .as_object()
        .ok_or_else(|| "route: must be a JSON object".to_string())?;
    for key in obj.keys() {
        if !KNOWN_ROUTE_FIELDS.contains(&key.as_str()) {
            return Err(format!("route: {key}: json: unknown field \"{key}\""));
        }
    }
    if let Some(rules) = obj.get("rules") {
        let rules = rules
            .as_array()
            .ok_or_else(|| "route.rules: must be an array".to_string())?;
        for (i, rule) in rules.iter().enumerate() {
            validate_route_rule(rule, &format!("route.rules[{i}]"), false)?;
        }
    }
    Ok(())
}

/// Reference `NewRule(..., checkOutbound)` + `rejectNestedRouteRuleAction`.
fn validate_route_rule(rule: &Value, at: &str, nested: bool) -> Result<(), String> {
    let rule = rule
        .as_object()
        .ok_or_else(|| format!("{at}: must be an object"))?;

    if nested {
        for key in NESTED_ACTION_KEYS {
            if rule.contains_key(*key) {
                return Err(format!(
                    "{at}: rule action is not supported in nested rules"
                ));
            }
        }
    }

    let ty = rule.get("type").and_then(Value::as_str).unwrap_or("");
    match ty {
        "" | "default" => {
            if !rule.keys().any(|k| k != "invert" && k != "type") {
                return Err(format!("{at}: missing conditions"));
            }
            check_route_rule_action(rule, at, nested)?;
        }
        "logical" => {
            match rule.get("mode").and_then(Value::as_str) {
                Some("and") | Some("or") => {}
                Some(other) => return Err(format!("{at}: unknown logical mode: {other}")),
                None => return Err(format!("{at}: unknown logical mode: ")),
            }
            let subs = rule
                .get("rules")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{at}: missing rules"))?;
            if subs.is_empty()
                || !subs.iter().all(|sub| {
                    sub.as_object().is_some_and(|m| {
                        m.keys().any(|k| k != "invert" && k != "type")
                            || m.get("type").and_then(Value::as_str) == Some("logical")
                    })
                })
            {
                return Err(format!("{at}: missing conditions"));
            }
            check_route_rule_action(rule, at, nested)?;
            for (i, sub) in subs.iter().enumerate() {
                validate_route_rule(sub, &format!("{at}: sub rule[{i}]"), true)?;
            }
        }
        other => return Err(format!("{at}: unknown rule type: {other}")),
    }
    Ok(())
}

fn check_route_rule_action(
    rule: &Map<String, Value>,
    at: &str,
    nested: bool,
) -> Result<(), String> {
    let action = rule.get("action").and_then(Value::as_str).unwrap_or("");
    if !action.is_empty() && !RULE_ACTIONS.contains(&action) {
        return Err(format!("{at}: unknown rule action: {action}"));
    }
    if (action.is_empty() || action == "route") && !nested {
        let outbound = rule.get("outbound").and_then(Value::as_str).unwrap_or("");
        if outbound.is_empty() {
            return Err(format!("{at}: missing outbound field"));
        }
    }
    Ok(())
}

fn validate_dns(dns: &Value) -> Result<(), String> {
    let obj = dns
        .as_object()
        .ok_or_else(|| "dns: must be a JSON object".to_string())?;
    let Some(servers) = obj.get("servers") else {
        return Ok(());
    };
    let servers = servers
        .as_array()
        .ok_or_else(|| "dns.servers: must be an array".to_string())?;
    for (i, server) in servers.iter().enumerate() {
        let server = server.as_object().ok_or_else(|| {
            format!(
                "dns.servers[{i}]: json: cannot unmarshal value into Go struct field RawDNSOptions.servers of type option._DNSServerOptions"
            )
        })?;
        let Some(ty) = server.get("type") else {
            return Err(format!("dns.servers[{i}]: {DNS_LEGACY_ERROR}"));
        };
        let ty = ty
            .as_str()
            .ok_or_else(|| format!("dns.servers[{i}].type: must be a string"))?;
        if !DNS_SERVER_TYPES.contains(&ty) {
            return Err(format!("dns.servers[{i}]: unknown transport type: {ty}"));
        }
        if (ty == "fakeip" || ty == "dhcp") && server.contains_key("server") {
            return Err(format!(
                "dns.servers[{i}]: server: json: unknown field \"server\""
            ));
        }
        if ty == "fakeip" {
            let has_ranges =
                server.contains_key("inet4_range") || server.contains_key("inet6_range");
            if !has_ranges {
                let tag = server.get("tag").and_then(Value::as_str).unwrap_or("");
                return Err(format!(
                    "initialize DNS server[{i}] fakeip[{tag}]: at least one of inet4_range or inet6_range must be set"
                ));
            }
        }
    }
    Ok(())
}

fn validate_inbound(i: usize, ty: &str, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("initialize inbound[{i}] {ty}[{tag}]");

    if ty == "tun" && TUN_LEGACY_FIELDS.iter().any(|f| obj.contains_key(*f)) {
        return Err(format!(
            "{at}: legacy tun address fields are deprecated in sing-box 1.10.0 and removed in sing-box 1.12.0"
        ));
    }

    if ty == "shadowtls" {
        let handshake_ok = obj
            .get("handshake")
            .and_then(Value::as_object)
            .is_some_and(|hs| {
                hs.get("server")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                    && hs.get("server_port").is_some()
            });
        if !handshake_ok {
            return Err(format!("{at}: missing default handshake information"));
        }
    }

    if ty == "naive" && !tls_enabled(obj.get("tls")) {
        return Err(format!("{at}: TLS is required for QUIC server"));
    }

    if TLS_REQUIRED_INBOUNDS.contains(&ty) && !tls_enabled(obj.get("tls")) {
        return Err(format!("{at}: TLS required"));
    }

    if ty == "shadowsocks" {
        validate_ss_method(obj, &at, true)?;
        if !ss_inbound_has_password(obj) {
            return Err(format!("{at}: missing password"));
        }
    }

    if tls_enabled(obj.get("tls")) && SERVER_TLS_INBOUNDS.contains(&ty) {
        validate_server_tls(obj.get("tls").unwrap(), &at)?;
    }

    Ok(())
}

fn validate_outbound(
    i: usize,
    ty: &str,
    tag: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
    let at = format!("initialize outbound[{i}] {ty}[{tag}]");

    match ty {
        "dns" => {
            return Err(format!(
                "outbounds[{i}]: dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead"
            ));
        }
        "wireguard" => {
            return Err(format!(
                "{at}: WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead"
            ));
        }
        _ => {}
    }

    if let Some(transport) = obj.get("transport") {
        let transport = transport
            .as_object()
            .ok_or_else(|| format!("outbounds[{i}].transport: must be a JSON object"))?;
        let transport_ty = type_field(transport, &format!("outbounds[{i}].transport"))?;
        if !TRANSPORT_TYPES.contains(&transport_ty) {
            return Err(format!(
                "outbounds[{i}].transport: unknown transport type: {transport_ty}"
            ));
        }
        if transport_ty == "quic" && !tls_enabled(obj.get("tls")) {
            return Err(format!("{at}: create client transport: quic: TLS required"));
        }
    }

    if TLS_REQUIRED_OUTBOUNDS.contains(&ty) && !tls_enabled(obj.get("tls")) {
        return Err(format!("{at}: TLS required"));
    }

    match ty {
        "selector" | "urltest" => {
            let members = obj
                .get("outbounds")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{at}: missing tags"))?;
            if members.is_empty() {
                return Err(format!("{at}: missing tags"));
            }
            for (m, member) in members.iter().enumerate() {
                if !member.is_string() {
                    return Err(format!("{at}: outbounds[{m}]: must be a string"));
                }
            }
        }
        "chain" => {
            let count = obj
                .get("outbounds")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if count < 2 {
                return Err(format!("{at}: chain requires at least 2 outbounds"));
            }
        }
        "masque" => {
            let has_ip = ["ip", "ipv6"].iter().any(|k| {
                obj.get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            });
            if !has_ip {
                return Err(format!("{at}: masque: at least one of ip/ipv6 is required"));
            }
        }
        "shadowsocks" => {
            validate_ss_method(obj, &at, false)?;
            let password = obj.get("password").and_then(Value::as_str).unwrap_or("");
            if password.is_empty() {
                return Err(format!("{at}: missing password"));
            }
            if let Some(required_len) =
                ss_2022_key_len(obj.get("method").and_then(Value::as_str).unwrap_or(""))
            {
                let decoded = decode_base64_std(password)
                    .ok_or_else(|| format!("{at}: decode key: encoding/base64: invalid input"))?;
                if decoded.len() != required_len {
                    return Err(format!(
                        "{at}: bad key length, required {required_len}, got {}",
                        decoded.len()
                    ));
                }
            }
        }
        "snell" => match obj.get("version") {
            None => return Err(format!("outbounds[{i}]: snell: missing version")),
            Some(version) => {
                let version = version
                    .as_u64()
                    .ok_or_else(|| format!("outbounds[{i}]: snell: version must be a number"))?;
                if version != 4 {
                    return Err(format!(
                        "outbounds[{i}]: snell: unsupported version: {version}"
                    ));
                }
            }
        },
        "hysteria" => {
            let has_up = ["up", "up_mbps"].iter().any(|k| obj.contains_key(*k));
            if !has_up {
                return Err(format!("{at}: missing upload speed"));
            }
            let has_down = ["down", "down_mbps"].iter().any(|k| obj.contains_key(*k));
            if !has_down {
                return Err(format!("{at}: missing download speed"));
            }
        }
        "tuic" => {
            let uuid = obj.get("uuid").and_then(Value::as_str).unwrap_or("");
            if !valid_uuid(uuid) {
                return Err(format!("{at}: invalid uuid: uuid: incorrect UUID length"));
            }
        }
        _ => {}
    }

    if tls_enabled(obj.get("tls")) {
        let tls = obj.get("tls").unwrap();
        validate_utls_reality(tls, &at)?;
    }

    Ok(())
}

fn validate_utls_reality(tls: &Value, at: &str) -> Result<(), String> {
    let Some(tls) = tls.as_object() else {
        return Ok(());
    };

    let utls_enabled = tls
        .get("utls")
        .and_then(Value::as_object)
        .is_some_and(|u| u.get("enabled").and_then(Value::as_bool) == Some(true));
    if utls_enabled {
        let fingerprint = tls
            .get("utls")
            .and_then(Value::as_object)
            .and_then(|u| u.get("fingerprint"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !fingerprint.is_empty() && !UTLS_FINGERPRINTS.contains(&fingerprint) {
            return Err(format!("{at}: unknown uTLS fingerprint: {fingerprint}"));
        }
    }

    let reality_enabled = tls
        .get("reality")
        .and_then(Value::as_object)
        .is_some_and(|r| r.get("enabled").and_then(Value::as_bool) == Some(true));
    if reality_enabled {
        if !utls_enabled {
            return Err(format!("{at}: uTLS is required by reality client"));
        }
        let reality = tls.get("reality").unwrap();
        let public_key = reality
            .get("public_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        if decode_base64_url_raw(public_key).is_none_or(|k| k.len() != 32) {
            return Err(format!("{at}: invalid public_key"));
        }
        if let Some(short_id) = reality.get("short_id").and_then(Value::as_str)
            && !short_id.is_empty()
        {
            check_short_id(short_id).map_err(|m| format!("{at}: {m}"))?;
        }
    }

    Ok(())
}

fn validate_server_tls(tls: &Value, at: &str) -> Result<(), String> {
    let tls = tls
        .as_object()
        .ok_or_else(|| format!("{at}: tls: must be a JSON object"))?;
    if !tls.contains_key("certificate") && !tls.contains_key("certificate_path") {
        return Err(format!("{at}: missing certificate"));
    }
    if !tls.contains_key("key") && !tls.contains_key("key_path") {
        return Err(format!("{at}: missing key"));
    }
    Ok(())
}

fn validate_ss_method(obj: &Map<String, Value>, at: &str, inbound: bool) -> Result<(), String> {
    let method = obj.get("method").and_then(Value::as_str).unwrap_or("");
    if !SS_METHODS.contains(&method) {
        if inbound {
            return Err(format!("{at}: unsupported method: {method}"));
        }
        return Err(format!("{at}: unknown method: {method}"));
    }
    Ok(())
}

fn ss_inbound_has_password(obj: &Map<String, Value>) -> bool {
    if obj
        .get("password")
        .and_then(Value::as_str)
        .is_some_and(|p| !p.is_empty())
    {
        return true;
    }
    obj.get("users")
        .and_then(Value::as_array)
        .is_some_and(|users| !users.is_empty())
}

fn ss_2022_key_len(method: &str) -> Option<usize> {
    match method {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Some(32),
        _ => None,
    }
}

fn tls_enabled(tls: Option<&Value>) -> bool {
    tls.and_then(|t| t.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn object_entry<'a>(entry: &'a Value, at: &str) -> Result<&'a Map<String, Value>, String> {
    entry
        .as_object()
        .ok_or_else(|| format!("{at}: must be a JSON object"))
}

fn type_field<'a>(obj: &'a Map<String, Value>, at: &str) -> Result<&'a str, String> {
    match obj.get("type") {
        None => Ok(""),
        Some(Value::String(ty)) => Ok(ty.as_str()),
        Some(_) => Err(format!(
            "{at}.type: json: cannot unmarshal into Go field of type string"
        )),
    }
}

fn tag_field<'a>(obj: &'a Map<String, Value>, at: &str) -> Result<&'a str, String> {
    match obj.get("tag") {
        None => Ok(""),
        Some(Value::String(tag)) => Ok(tag.as_str()),
        Some(_) => Err(format!(
            "{at}.tag: json: cannot unmarshal into Go field of type string"
        )),
    }
}

fn check_u16(value: &Value) -> Result<(), String> {
    match value.as_u64() {
        Some(n) if n <= u64::from(u16::MAX) => Ok(()),
        Some(n) => Err(format!(
            "json: cannot unmarshal number {n} into Go field of type uint16"
        )),
        None => Err("json: cannot unmarshal value into Go field of type uint16".to_string()),
    }
}

fn check_short_id(short_id: &str) -> Result<(), String> {
    if !short_id.len().is_multiple_of(2) {
        return Err("decode short_id: encoding/hex: odd length hex string".to_string());
    }
    if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("decode short_id: encoding/hex: invalid byte".to_string());
    }
    if short_id.len() / 2 > 8 {
        return Err("invalid short_id".to_string());
    }
    Ok(())
}

fn valid_uuid(uuid: &str) -> bool {
    let core = uuid.strip_prefix("urn:uuid:").unwrap_or(uuid);
    let core = match core.strip_prefix('{') {
        Some(rest) => rest.strip_suffix('}').unwrap_or(rest),
        None => core,
    };
    if core.contains('-') {
        let parts: Vec<&str> = core.split('-').collect();
        let expected = [8, 4, 4, 4, 12];
        if parts.len() != expected.len() {
            return false;
        }
        if parts
            .iter()
            .zip(expected)
            .any(|(part, len)| part.len() != len)
        {
            return false;
        }
    }
    let hex: String = core.chars().filter(|c| *c != '-').collect();
    hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Standard base64 with padding (Go `base64.StdEncoding`).
fn decode_base64_std(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let mut unpadded = input.as_bytes();
    while unpadded.last() == Some(&b'=') {
        unpadded = &unpadded[..unpadded.len() - 1];
    }
    if input.len() - unpadded.len() > 2 {
        return None;
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(unpadded.len() * 3 / 4);
    for &byte in unpadded {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// Raw base64url without padding (Go `base64.RawURLEncoding`).
fn decode_base64_url_raw(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 == 1 || input.contains('=') {
        return None;
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for &byte in input.as_bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_empty_config() {
        assert!(validate(&json!({})).is_ok());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let err = validate(&json!({"clash_api": {}})).unwrap_err();
        assert!(err.contains("unknown field \"clash_api\""));
    }

    #[test]
    fn rejects_unknown_inbound_type() {
        let err = validate(&json!({"inbounds": [{"type": "wireguard"}]})).unwrap_err();
        assert!(err.contains("unknown inbound type: wireguard"));
    }

    #[test]
    fn accepts_valid_tachyon_shape() {
        let cfg = json!({
            "log": {"level": "warn", "timestamp": false},
            "dns": {"servers": [{"type": "udp", "tag": "d", "server": "1.1.1.1"}], "final": "d"},
            "inbounds": [{"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": 2080}],
            "outbounds": [
                {"type": "direct", "tag": "direct-out"},
                {"type": "shadowsocks", "tag": "n", "server": "e.com", "server_port": 443,
                 "method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MGFiY2RlZg=="}
            ],
            "route": {"rules": [{"action": "route", "outbound": "n"}], "final": "direct-out"}
        });
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn u16_bounds() {
        assert!(check_u16(&json!(0)).is_ok());
        assert!(check_u16(&json!(65535)).is_ok());
        assert!(check_u16(&json!(65536)).is_err());
        assert!(check_u16(&json!(-1)).is_err());
        assert!(check_u16(&json!("443")).is_err());
    }

    #[test]
    fn uuid_forms() {
        assert!(valid_uuid("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert!(valid_uuid("b831381d63244d53ad4f8cda48b30811"));
        assert!(valid_uuid("urn:uuid:b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert!(!valid_uuid("nope"));
        assert!(!valid_uuid(""));
    }

    #[test]
    fn base64_variants() {
        assert_eq!(decode_base64_std("AAAA").as_deref(), Some(&[0u8, 0, 0][..]));
        assert_eq!(
            decode_base64_std("MTIzNDU2Nzg5MGFiY2RlZg==").map(|v| v.len()),
            Some(16)
        );
        assert!(decode_base64_std("AAAAA").is_none());
        assert!(decode_base64_std("!!??").is_none());
        assert_eq!(
            decode_base64_url_raw("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").map(|v| v.len()),
            Some(32)
        );
        assert!(decode_base64_url_raw("AAAA").is_none_or(|v| v.len() != 32));
        assert!(decode_base64_url_raw("AAAA=").is_none());
    }

    #[test]
    fn short_id_rules() {
        assert!(check_short_id("0123456789abcdef").is_ok());
        assert!(check_short_id("").is_ok());
        assert!(check_short_id("0123456789abcdef01").is_err());
        assert!(check_short_id("abc").is_err());
        assert!(check_short_id("zz").is_err());
    }

    #[test]
    fn tls_defaults_disabled() {
        assert!(!tls_enabled(None));
        assert!(!tls_enabled(Some(&json!({}))));
        assert!(!tls_enabled(Some(&json!({"enabled": false}))));
        assert!(tls_enabled(Some(&json!({"enabled": true}))));
    }
}
