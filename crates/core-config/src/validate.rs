//! Semantic validation mirroring reference `sing-box check` (F1 + F2 hy2/tuic).
//!
//! Rules were derived empirically against sing-box-lx v1.14.1-lx.8: the
//! differential harness compares exit codes only, so messages here are
//! best-effort echoes of the reference wording, not a contract.
//!
//! Known intentional gaps (documented in COMPAT.md):
//! - field allowlists for protocols other than hysteria2/tuic;
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

/// reference `option.NTPOptions` = ServerOptions + DialerOptions + own fields.
const KNOWN_NTP_FIELDS: &[&str] = &[
    "enabled",
    "interval",
    "write_to_system",
    "server",
    "server_port",
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "protect_path",
    "routing_mark",
    "reuse_addr",
    "netns",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "udp_fragment",
    "domain_resolver",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
    "domain_strategy",
];

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
    "default_network_strategy",
    "default_network_type",
    "default_fallback_network_type",
    "default_fallback_delay",
    "default_http_client",
];

/// reference `option.DomainStrategy` values accepted on `domain_resolver.strategy`.
const DOMAIN_STRATEGIES: &[&str] = &[
    "",
    "as_is",
    "prefer_ipv4",
    "prefer_ipv6",
    "ipv4_only",
    "ipv6_only",
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

/// Legacy inbound fields: known keys; any non-zero value → legacy-field error.
const LEGACY_INBOUND_FIELDS: &[&str] = &[
    "sniff",
    "sniff_override_destination",
    "sniff_timeout",
    "domain_strategy",
    "udp_disable_domain_unmapping",
];

const LEGACY_INBOUND_ERROR: &str = "legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions";

/// reference `option.DialerOptions` (shared by hy2/tuic outbound).
const DIALER_OUT_FIELDS: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "protect_path",
    "routing_mark",
    "reuse_addr",
    "netns",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "udp_fragment",
    "domain_resolver",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
    "domain_strategy",
];

/// reference `option.ListenOptions` (shared by hy2/tuic inbound).
const LISTEN_IN_FIELDS: &[&str] = &[
    "listen",
    "listen_port",
    "bind_interface",
    "routing_mark",
    "reuse_addr",
    "netns",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "udp_timeout",
    "detour",
    "proxy_protocol",
    "proxy_protocol_accept_no_header",
];

/// reference `option.QUICOptions` flattened (idle_timeout, keep_alive_period,
/// HTTP2 window fields, initial_packet_size, disable_path_mtu_discovery).
const QUIC_OUT_FIELDS: &[&str] = &[
    "idle_timeout",
    "keep_alive_period",
    "stream_receive_window",
    "connection_receive_window",
    "max_concurrent_streams",
    "initial_packet_size",
    "disable_path_mtu_discovery",
];

/// reference `option.OutboundTLSOptions`.
const TLS_OUT_FIELDS: &[&str] = &[
    "enabled",
    "engine",
    "disable_sni",
    "server_name",
    "insecure",
    "alpn",
    "min_version",
    "max_version",
    "cipher_suites",
    "curve_preferences",
    "certificate",
    "certificate_path",
    "certificate_public_key_sha256",
    "client_certificate",
    "client_certificate_path",
    "client_key",
    "client_key_path",
    "fragment",
    "fragment_fallback_delay",
    "record_fragment",
    "spoof",
    "spoof_method",
    "kernel_tx",
    "kernel_rx",
    "handshake_timeout",
    "ech",
    "utls",
    "reality",
];

/// reference `option.InboundTLSOptions`.
const TLS_IN_FIELDS: &[&str] = &[
    "enabled",
    "server_name",
    "insecure",
    "alpn",
    "min_version",
    "max_version",
    "cipher_suites",
    "curve_preferences",
    "certificate",
    "certificate_path",
    "client_authentication",
    "client_certificate",
    "client_certificate_path",
    "client_certificate_public_key_sha256",
    "key",
    "key_path",
    "kernel_tx",
    "kernel_rx",
    "handshake_timeout",
    "certificate_provider",
    "acme",
    "ech",
    "reality",
];

/// Hy2 outbound allowlist (lx hysteria2.go), excluding TLS/QUIC containers.
const HY2_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "server",
    "server_port",
    "server_ports",
    "hop_interval",
    "hop_interval_max",
    "up_mbps",
    "down_mbps",
    "obfs",
    "password",
    "network",
    "bbr_profile",
    "brutal_debug",
    "disable_chrome_parrot",
    "realm",
    "tls",
];

/// Tuic outbound allowlist (lx tuic.go).
const TUIC_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "server",
    "server_port",
    "uuid",
    "password",
    "congestion_control",
    "udp_relay_mode",
    "udp_over_stream",
    "zero_rtt_handshake",
    "heartbeat",
    "network",
    "tls",
];

/// Hy2 inbound allowlist (lx hy2_inbound.go).
const HY2_IN_FIELDS: &[&str] = &[
    "type",
    "tag",
    "up_mbps",
    "down_mbps",
    "obfs",
    "users",
    "ignore_client_bandwidth",
    "masquerade",
    "bbr_profile",
    "brutal_debug",
    "realm",
    "tls",
];

/// Tuic inbound allowlist (lx tuic inbound options).
const TUIC_IN_FIELDS: &[&str] = &[
    "type",
    "tag",
    "users",
    "congestion_control",
    "auth_timeout",
    "zero_rtt_handshake",
    "heartbeat",
    "tls",
];

const BBR_PROFILES: &[&str] = &["standard", "conservative", "aggressive"];
const TUIC_CC_ALGS: &[&str] = &["cubic", "new_reno", "bbr"];
const TUIC_UDP_RELAY_MODES: &[&str] = &["native", "quic"];
const OBFS_TYPES: &[&str] = &["salamander", "gecko"];
const MASQ_URL_SCHEMES: &[&str] = &["file", "http", "https"];
const MASQ_OBJ_TYPES: &[&str] = &["file", "proxy", "string"];
const MASQ_FILE_FIELDS: &[&str] = &["type", "directory"];
const MASQ_PROXY_FIELDS: &[&str] = &["type", "url", "rewrite_host"];
const MASQ_STRING_FIELDS: &[&str] = &["type", "status_code", "headers", "content"];
const HTTP_CLIENT_BASE_FIELDS: &[&str] = &[
    "tag",
    "engine",
    "version",
    "disable_version_fallback",
    "headers",
    "tls",
];
const HTTP2_CLIENT_FIELDS: &[&str] = &[
    "idle_timeout",
    "keep_alive_period",
    "stream_receive_window",
    "connection_receive_window",
    "max_concurrent_streams",
];
const QUIC_CLIENT_EXTRA_FIELDS: &[&str] = &["initial_packet_size", "disable_path_mtu_discovery"];
const REALM_OUT_FIELDS: &[&str] = &[
    "server_url",
    "token",
    "realm_id",
    "stun_servers",
    "ip_version",
    "port_mapping",
    "http_client",
];
const REALM_IN_FIELDS: &[&str] = &[
    "server_url",
    "token",
    "realm_id",
    "stun_servers",
    "stun_domain_resolver",
    "ip_version",
    "port_mapping",
    "http_client",
];
const REALM_PM_FIELDS: &[&str] = &["enabled", "timeout", "lifetime"];

fn reject_unknown_fields(
    obj: &Map<String, Value>,
    allowed: &[&str],
    at: &str,
) -> Result<(), String> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{at}.{key}: json: unknown field \"{key}\""));
        }
    }
    Ok(())
}

/// Go `my_time.ParseDuration` subset (badoption.Duration string form).
/// Grammar: `[-+]?([0-9]*(\.[0-9]*)?[a-zµμ]+)+`
fn go_parse_duration(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err(format!("time: invalid duration \"{raw}\""));
    }
    let mut s = raw;
    if let Some(rest) = s.strip_prefix('-').or_else(|| s.strip_prefix('+')) {
        s = rest;
    }
    if s.is_empty() {
        return Err(format!("time: invalid duration \"{raw}\""));
    }
    const UNITS: &[&str] = &["ns", "us", "µs", "μs", "ms", "s", "m", "h", "d"];
    let mut consumed_any = false;
    while !s.is_empty() {
        // number part: digits and at most one '.'
        let mut num_len = 0usize;
        let mut dots = 0;
        for c in s.chars() {
            if c.is_ascii_digit() {
                num_len += 1;
            } else if c == '.' {
                dots += 1;
                if dots > 1 {
                    break;
                }
                num_len += 1;
            } else {
                break;
            }
        }
        // trailing '.' with no digits after is still consumed by loop only if digit before
        if num_len == 0 {
            return Err(if consumed_any {
                format!("time: missing unit in duration \"{raw}\"")
            } else {
                format!("time: invalid duration \"{raw}\"")
            });
        }
        // unit: leading alphabetic characters (including µ/μ)
        let rest = &s[num_len..];
        let unit_len = rest
            .chars()
            .take_while(|c| c.is_alphabetic())
            .map(char::len_utf8)
            .sum::<usize>();
        if unit_len == 0 {
            return Err(format!("time: missing unit in duration \"{raw}\""));
        }
        let unit = &rest[..unit_len];
        if !UNITS.contains(&unit) {
            return Err(format!(
                "time: unknown unit \"{unit}\" in duration \"{raw}\""
            ));
        }
        s = &rest[unit_len..];
        consumed_any = true;
    }
    if !consumed_any {
        return Err(format!("time: invalid duration \"{raw}\""));
    }
    Ok(())
}

/// Decode-time duration field: string → Go parse; null → invalid duration "";
/// number/bool → cannot unmarshal into Go struct field of type string.
fn check_duration_field(
    value: &Value,
    at: &str,
    go_struct: &str,
    go_field: &str,
) -> Result<(), String> {
    match value {
        Value::Null => Err(format!("{at}: time: invalid duration \"\"")),
        Value::String(s) => go_parse_duration(s).map_err(|m| format!("{at}: {m}")),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number into Go struct field {go_struct}.{go_field} of type string"
        )),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field {go_struct}.{go_field} of type string"
        )),
        Value::Array(_) => Err(format!(
            "{at}: json: cannot unmarshal array into Go struct field {go_struct}.{go_field} of type string"
        )),
        Value::Object(_) => Err(format!(
            "{at}: json: cannot unmarshal object into Go struct field {go_struct}.{go_field} of type string"
        )),
    }
}

/// MemoryBytes: number OK; null OK; string = leading digits + unit.
fn check_memory_bytes(
    value: &Value,
    at: &str,
    go_struct: &str,
    go_field: &str,
) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Number(_) => Ok(()),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field {go_struct}.{go_field} of type int"
        )),
        Value::String(s) => check_memory_bytes_str(s, at),
        Value::Array(_) | Value::Object(_) => Err(format!(
            "{at}: json: cannot unmarshal value into Go struct field {go_struct}.{go_field} of type string"
        )),
    }
}

fn check_memory_bytes_str(s: &str, at: &str) -> Result<(), String> {
    let digits = s.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 || s.starts_with(|c: char| c.is_whitespace() || c == '-' || c == '+') {
        return Err(format!("{at}: invalid format: {s}"));
    }
    let unit = &s[digits..];
    let unit_trim = unit.trim();
    if unit_trim.is_empty() {
        return Err(format!("{at}: invalid format: {s}"));
    }
    let matches = unit_trim.eq_ignore_ascii_case("b")
        || unit_trim.eq_ignore_ascii_case("kb")
        || unit_trim.eq_ignore_ascii_case("mb")
        || unit_trim.eq_ignore_ascii_case("gb")
        || unit_trim.eq_ignore_ascii_case("tb")
        || unit_trim.eq_ignore_ascii_case("k");
    if matches {
        Ok(())
    } else {
        Err(format!("{at}: unsupported unit: {unit}"))
    }
}

/// Listable network: string | string[]; case-sensitive tcp/udp.
fn check_network(value: &Value, at: &str, go_struct: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            if s == "tcp" || s == "udp" {
                Ok(())
            } else {
                Err(format!("{at}: unknown network: {s}"))
            }
        }
        Value::Array(items) => {
            for item in items {
                let s = item.as_str().ok_or_else(|| {
                    format!(
                        "{at}: json: cannot unmarshal array into Go struct field {go_struct}.network of type string"
                    )
                })?;
                if s != "tcp" && s != "udp" {
                    return Err(format!("{at}: unknown network: {s}"));
                }
            }
            Ok(())
        }
        Value::Number(_) | Value::Bool(_) | Value::Object(_) => Err(format!(
            "{at}: json: cannot unmarshal value into Go struct field {go_struct}.network of type string"
        )),
    }
}

/// Int field: number OK; null/[] no-op; bool/string → cannot unmarshal.
fn check_int_field(value: &Value, at: &str, go_struct: &str, go_field: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Array(_) => Ok(()),
        Value::Number(_) => Ok(()),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field {go_struct}.{go_field} of type int"
        )),
        Value::String(_) => Err(format!(
            "{at}: json: cannot unmarshal string into Go struct field {go_struct}.{go_field} of type int"
        )),
        Value::Object(_) => Err(format!(
            "{at}: json: cannot unmarshal object into Go struct field {go_struct}.{go_field} of type int"
        )),
    }
}

/// String enum field at decode: null/[] OK; bool → cannot unmarshal; string OK.
fn check_string_field(
    value: &Value,
    at: &str,
    go_struct: &str,
    go_field: &str,
) -> Result<(), String> {
    match value {
        Value::Null | Value::Array(_) | Value::String(_) => Ok(()),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field {go_struct}.{go_field} of type string"
        )),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number into Go struct field {go_struct}.{go_field} of type string"
        )),
        Value::Object(_) => Err(format!(
            "{at}: json: cannot unmarshal object into Go struct field {go_struct}.{go_field} of type string"
        )),
    }
}

/// server_ports Listable[string]: null/[] OK; string|number|array; range checked at init.
fn check_server_ports_listable(value: &Value, at: &str) -> Result<Vec<String>, String> {
    match value {
        Value::Null | Value::Array(_) => {
            let mut out = Vec::new();
            if let Value::Array(items) = value {
                for (idx, item) in items.iter().enumerate() {
                    match item {
                        Value::String(s) => out.push(s.clone()),
                        _ => {
                            return Err(format!(
                                "{at}: (json: cannot unmarshal array into Go value of type string | [{idx}]: json: cannot unmarshal value into Go value of type string)"
                            ));
                        }
                    }
                }
            }
            Ok(out)
        }
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Number(_) => Err(format!(
            "{at}: (json: cannot unmarshal number into Go value of type string | json: cannot unmarshal number into Go value of type []string)"
        )),
        Value::Bool(_) => Err(format!(
            "{at}: (json: cannot unmarshal bool into Go value of type string | json: cannot unmarshal bool into Go value of type []string)"
        )),
        Value::Object(_) => Err(format!(
            "{at}: (json: cannot unmarshal object into Go value of type string | json: cannot unmarshal object into Go value of type []string)"
        )),
    }
}

/// ParseUint base10 bitSize16; empty part → 0.
fn parse_port_part(s: &str) -> Result<u16, String> {
    if s.is_empty() {
        return Ok(0);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "strconv.ParseUint: parsing \"{s}\": invalid syntax"
        ));
    }
    match s.parse::<u64>() {
        Ok(n) if n <= u64::from(u16::MAX) => Ok(n as u16),
        Ok(_) => Err(format!(
            "strconv.ParseUint: parsing \"{s}\": value out of range"
        )),
        Err(_) => Err(format!(
            "strconv.ParseUint: parsing \"{s}\": invalid syntax"
        )),
    }
}

fn check_port_range(raw: &str) -> Result<(), String> {
    let Some((a, b)) = raw.split_once(':') else {
        return Err(format!("bad port range: {raw}"));
    };
    let start = parse_port_part(a).map_err(|e| format!("bad port range: {raw}: {e}"))?;
    let end = parse_port_part(b).map_err(|e| format!("bad port range: {raw}: {e}"))?;
    let _ = (start, end);
    Ok(())
}

/// reference: realm present ⇔ object with ≥1 key (empty object behaves as nil).
fn realm_present(value: Option<&Value>) -> bool {
    value.is_some_and(|v| v.as_object().is_some_and(|m| !m.is_empty()))
}

fn reject_unknown_fields_deep(value: &Value, path: &str, allowed: &[&str]) -> Result<(), String> {
    if let Some(obj) = value.as_object() {
        for key in obj.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(format!("{path}.{key}: json: unknown field \"{key}\""));
            }
        }
    }
    Ok(())
}

fn validate_obfs(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Array(_) => Ok(()),
        Value::String(_) => Err(format!(
            "{at}: json: cannot unmarshal string into Go struct field Hysteria2OutboundOptions.obfs of type option._Hysteria2Obfs"
        )),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number into Go struct field Hysteria2OutboundOptions.obfs of type option._Hysteria2Obfs"
        )),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field Hysteria2OutboundOptions.obfs of type option._Hysteria2Obfs"
        )),
        Value::Object(map) => {
            let ty = map.get("type").and_then(Value::as_str).unwrap_or("");
            if !OBFS_TYPES.contains(&ty) {
                return Err(format!("{at}: unknown obfs type: {ty}"));
            }
            if ty == "gecko" {
                for key in map.keys() {
                    if key != "type" {
                        return Err(format!("{at}.{key}: json: unknown field \"{key}\""));
                    }
                }
            }
            Ok(())
        }
    }
}

fn validate_masquerade(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            // reference url.Parse → scheme
            let scheme = match s.split_once("://") {
                Some((scheme, _)) => scheme.to_string(),
                None => {
                    // bare path → file? only if starts with / and no scheme-like prefix
                    let scheme_like = s
                        .split_once(':')
                        .filter(|(head, _)| {
                            !head.is_empty()
                                && head.starts_with(|c: char| c.is_ascii_alphabetic())
                                && head.chars().all(|c| {
                                    c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'
                                })
                        })
                        .map(|(head, _)| head.to_string());
                    scheme_like.unwrap_or_default()
                }
            };
            if scheme.is_empty() {
                // no scheme: accept absolute path as file, reject other forms?
                if s.starts_with('/') {
                    return Ok(());
                }
                return Err(format!("{at}: unknown masquerade URL scheme: {scheme}"));
            }
            if !MASQ_URL_SCHEMES.contains(&scheme.as_str()) {
                return Err(format!("{at}: unknown masquerade URL scheme: {scheme}"));
            }
            Ok(())
        }
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number into Go struct field Hysteria2InboundOptions.masquerade of type option._Hysteria2Masquerade"
        )),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field Hysteria2InboundOptions.masquerade of type option._Hysteria2Masquerade"
        )),
        Value::Array(_) => Err(format!(
            "{at}: json: cannot unmarshal array into Go struct field Hysteria2InboundOptions.masquerade of type option._Hysteria2Masquerade"
        )),
        Value::Object(map) => {
            let ty = map.get("type").and_then(Value::as_str).unwrap_or("");
            if !MASQ_OBJ_TYPES.contains(&ty) {
                return Err(format!("{at}: unknown masquerade type: {ty}"));
            }
            let allowed: &[&str] = match ty {
                "file" => MASQ_FILE_FIELDS,
                "proxy" => MASQ_PROXY_FIELDS,
                "string" => MASQ_STRING_FIELDS,
                _ => &[],
            };
            for key in map.keys() {
                if !allowed.contains(&key.as_str()) {
                    return Err(format!("{at}.{key}: json: unknown field \"{key}\""));
                }
            }
            Ok(())
        }
    }
}

fn validate_users_hy2(value: &Value, at: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let users = value
        .as_array()
        .ok_or_else(|| format!("{at}: json: cannot unmarshal value into Go struct field Hysteria2InboundOptions.users of type []option.Hysteria2User"))?;
    for (idx, user) in users.iter().enumerate() {
        let u = user.as_object().ok_or_else(|| {
            format!("{at}[{idx}]: json: cannot unmarshal value into Go value of type option.Hysteria2User")
        })?;
        reject_unknown_fields(u, &["name", "password"], &format!("{at}[{idx}"))?;
    }
    Ok(())
}

fn validate_users_tuic(value: &Value, at: &str, init_at: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let users = value
        .as_array()
        .ok_or_else(|| format!("{at}: json: cannot unmarshal value into Go struct field TUICInboundOptions.users of type []option.TUICUser"))?;
    for (idx, user) in users.iter().enumerate() {
        let u = user.as_object().ok_or_else(|| {
            format!(
                "{at}[{idx}]: json: cannot unmarshal value into Go value of type option.TUICUser"
            )
        })?;
        reject_unknown_fields(u, &["name", "uuid", "password"], &format!("{at}[{idx}"))?;
        if let Some(uuid) = u.get("uuid").and_then(Value::as_str)
            && !valid_uuid(uuid)
        {
            return Err(format!(
                "{init_at}: invalid uuid for user {idx}: uuid: incorrect UUID length"
            ));
        }
    }
    Ok(())
}

fn validate_realm(value: &Value, at: &str, inbound: bool) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let map = value.as_object().ok_or_else(|| {
        format!("{at}: json: cannot unmarshal value into Go field of type option.Hysteria2Realm")
    })?;
    if map.is_empty() {
        return Ok(());
    }
    let allowed = if inbound {
        REALM_IN_FIELDS
    } else {
        REALM_OUT_FIELDS
    };
    reject_unknown_fields(map, allowed, at)?;
    if let Some(pm) = map.get("port_mapping")
        && let Some(pm_obj) = pm.as_object()
    {
        reject_unknown_fields(pm_obj, REALM_PM_FIELDS, &format!("{at}.port_mapping"))?;
        if let Some(t) = pm_obj.get("timeout") {
            check_duration_field(
                t,
                &format!("{at}.port_mapping.timeout"),
                "Hysteria2RealmPortMapping",
                "timeout",
            )?;
        }
        if let Some(t) = pm_obj.get("lifetime") {
            check_duration_field(
                t,
                &format!("{at}.port_mapping.lifetime"),
                "Hysteria2RealmPortMapping",
                "lifetime",
            )?;
        }
    }
    if let Some(hc) = map.get("http_client")
        && hc.is_object()
    {
        validate_http_client(hc, &format!("{at}.http_client"))?;
    }
    Ok(())
}

fn validate_http_client(value: &Value, at: &str) -> Result<(), String> {
    if value.is_null() || value.is_string() {
        return Ok(());
    }
    let map = value
        .as_object()
        .ok_or_else(|| format!("{at}: json: cannot unmarshal value into Go struct field Hysteria2RealmOptions.http_client of type option._DomainResolveOptions"))?;
    let version = map
        .get("version")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))
        .unwrap_or(0);
    if map.contains_key("version") && map.get("version").and_then(Value::as_u64).is_none() {
        return Err(format!(
            "{at}.version: json: cannot unmarshal value into Go struct field of type int"
        ));
    }
    match version {
        0 | 2 => {
            let mut allowed: Vec<&str> = HTTP_CLIENT_BASE_FIELDS.to_vec();
            allowed.extend(HTTP2_CLIENT_FIELDS);
            allowed.extend(DIALER_OUT_FIELDS);
            reject_unknown_fields(map, &allowed, at)?;
            for f in HTTP2_CLIENT_FIELDS {
                if let Some(v) = map.get(*f) {
                    if *f == "stream_receive_window" || *f == "connection_receive_window" {
                        check_memory_bytes(v, &format!("{at}.{f}"), "HTTP2Options", f)?;
                    } else if *f == "idle_timeout" || *f == "keep_alive_period" {
                        check_duration_field(v, &format!("{at}.{f}"), "HTTP2Options", f)?;
                    } else {
                        check_int_field(v, &format!("{at}.{f}"), "HTTP2Options", f)?;
                    }
                }
            }
            Ok(())
        }
        1 => {
            let mut allowed: Vec<&str> = HTTP_CLIENT_BASE_FIELDS.to_vec();
            allowed.extend(DIALER_OUT_FIELDS);
            reject_unknown_fields(map, &allowed, at)?;
            Ok(())
        }
        3 => {
            let mut allowed: Vec<&str> = HTTP_CLIENT_BASE_FIELDS.to_vec();
            allowed.extend(HTTP2_CLIENT_FIELDS);
            allowed.extend(QUIC_CLIENT_EXTRA_FIELDS);
            allowed.extend(DIALER_OUT_FIELDS);
            reject_unknown_fields(map, &allowed, at)?;
            for f in HTTP2_CLIENT_FIELDS {
                if let Some(v) = map.get(*f) {
                    if *f == "stream_receive_window" || *f == "connection_receive_window" {
                        check_memory_bytes(v, &format!("{at}.{f}"), "HTTP2Options", f)?;
                    } else if *f == "idle_timeout" || *f == "keep_alive_period" {
                        check_duration_field(v, &format!("{at}.{f}"), "HTTP2Options", f)?;
                    } else {
                        check_int_field(v, &format!("{at}.{f}"), "HTTP2Options", f)?;
                    }
                }
            }
            Ok(())
        }
        other => Err(format!("{at}: unknown HTTP version: {other}")),
    }
}

fn validate_tls_container(value: &Value, at: &str, inbound: bool) -> Result<(), String> {
    if !value.is_object() {
        return Ok(());
    }
    let allowed = if inbound {
        TLS_IN_FIELDS
    } else {
        TLS_OUT_FIELDS
    };
    reject_unknown_fields_deep(value, at, allowed)?;
    let obj = value.as_object().unwrap();
    if let Some(f) = obj.get("fragment_fallback_delay") {
        check_duration_field(
            f,
            &format!("{at}.fragment_fallback_delay"),
            "OutboundTLSOptions",
            "fragment_fallback_delay",
        )?;
    }
    if let Some(f) = obj.get("handshake_timeout") {
        check_duration_field(
            f,
            &format!("{at}.handshake_timeout"),
            "TLSOptions",
            "handshake_timeout",
        )?;
    }
    Ok(())
}

/// Legacy inbound fields: known keys, non-zero → legacy error (decode-time).
fn check_legacy_inbound(obj: &Map<String, Value>) -> Result<(), String> {
    if obj.get("sniff").and_then(Value::as_bool) == Some(true) {
        return Err(LEGACY_INBOUND_ERROR.to_string());
    }
    if obj
        .get("sniff_override_destination")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(LEGACY_INBOUND_ERROR.to_string());
    }
    if obj
        .get("udp_disable_domain_unmapping")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(LEGACY_INBOUND_ERROR.to_string());
    }
    if let Some(ds) = obj.get("domain_strategy").and_then(Value::as_str)
        && !ds.is_empty()
    {
        return Err(LEGACY_INBOUND_ERROR.to_string());
    }
    if let Some(t) = obj.get("sniff_timeout") {
        if t.is_null() {
            return Err("time: invalid duration \"\"".to_string());
        }
        if let Some(s) = t.as_str() {
            if s.is_empty() {
                return Err("time: invalid duration \"\"".to_string());
            }
            go_parse_duration(s)?;
            if s != "0s" && s != "0" {
                return Err(LEGACY_INBOUND_ERROR.to_string());
            }
        } else if t.is_number() {
            // non-zero number duration would be non-zero → legacy; 0 OK
            if t.as_f64().is_some_and(|n| n != 0.0) {
                return Err(LEGACY_INBOUND_ERROR.to_string());
            }
        } else if t.as_bool() == Some(true) {
            return Err(LEGACY_INBOUND_ERROR.to_string());
        }
    }
    Ok(())
}

/// UDPTimeoutCompat: number (seconds) or duration string.
fn check_udp_timeout(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null => Err(format!("{at}: time: invalid duration \"\"")),
        Value::Number(_) => Ok(()),
        Value::String(s) => go_parse_duration(s).map_err(|m| format!("{at}: {m}")),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field ListenOptions.udp_timeout of type string"
        )),
        Value::Array(_) | Value::Object(_) => Err(format!(
            "{at}: json: cannot unmarshal value into Go struct field ListenOptions.udp_timeout of type string"
        )),
    }
}

fn validate_hy2_out_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let mut allowed: Vec<&str> = HY2_OUT_FIELDS.to_vec();
    allowed.extend(DIALER_OUT_FIELDS);
    allowed.extend(QUIC_OUT_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;

    if let Some(v) = obj.get("hop_interval") {
        check_duration_field(
            v,
            &format!("{at}.hop_interval"),
            "Hysteria2OutboundOptions",
            "hop_interval",
        )?;
    }
    if let Some(v) = obj.get("hop_interval_max") {
        check_duration_field(
            v,
            &format!("{at}.hop_interval_max"),
            "Hysteria2OutboundOptions",
            "hop_interval_max",
        )?;
    }
    if let Some(v) = obj.get("up_mbps") {
        check_int_field(
            v,
            &format!("{at}.up_mbps"),
            "Hysteria2OutboundOptions",
            "up_mbps",
        )?;
    }
    if let Some(v) = obj.get("down_mbps") {
        check_int_field(
            v,
            &format!("{at}.down_mbps"),
            "Hysteria2OutboundOptions",
            "down_mbps",
        )?;
    }
    if let Some(v) = obj.get("bbr_profile") {
        check_string_field(
            v,
            &format!("{at}.bbr_profile"),
            "Hysteria2OutboundOptions",
            "bbr_profile",
        )?;
    }
    if let Some(v) = obj.get("password") {
        check_string_field(
            v,
            &format!("{at}.password"),
            "Hysteria2OutboundOptions",
            "password",
        )?;
    }
    if let Some(v) = obj.get("network") {
        check_network(v, &format!("{at}.network"), "Hysteria2OutboundOptions")?;
    }
    for f in ["idle_timeout", "keep_alive_period"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(
                v,
                &format!("{at}.{f}"),
                "Hysteria2OutboundOptions.QUICOptions.HTTP2Options",
                f,
            )?;
        }
    }
    for f in ["stream_receive_window", "connection_receive_window"] {
        if let Some(v) = obj.get(f) {
            check_memory_bytes(
                v,
                &format!("{at}.{f}"),
                "Hysteria2OutboundOptions.QUICOptions.HTTP2Options",
                f,
            )?;
        }
    }
    for f in ["max_concurrent_streams", "initial_packet_size"] {
        if let Some(v) = obj.get(f) {
            check_int_field(
                v,
                &format!("{at}.{f}"),
                "Hysteria2OutboundOptions.QUICOptions",
                f,
            )?;
        }
    }
    if let Some(v) = obj.get("connect_timeout") {
        check_duration_field(
            v,
            &format!("{at}.connect_timeout"),
            "Hysteria2OutboundOptions.DialerOptions.AbstractDialerOptions",
            "connect_timeout",
        )?;
    }
    if let Some(v) = obj.get("fallback_delay") {
        check_duration_field(
            v,
            &format!("{at}.fallback_delay"),
            "Hysteria2OutboundOptions.DialerOptions.AbstractDialerOptions",
            "fallback_delay",
        )?;
    }
    if let Some(v) = obj.get("tcp_keep_alive") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive"),
            "Hysteria2OutboundOptions.DialerOptions.AbstractDialerOptions",
            "tcp_keep_alive",
        )?;
    }
    if let Some(v) = obj.get("tcp_keep_alive_interval") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive_interval"),
            "Hysteria2OutboundOptions.DialerOptions.AbstractDialerOptions",
            "tcp_keep_alive_interval",
        )?;
    }
    if let Some(v) = obj.get("domain_resolver") {
        domain_resolver_server(v, &format!("{at}.domain_resolver"))?;
    }
    if let Some(tls) = obj.get("tls") {
        validate_tls_container(tls, &format!("{at}.tls"), false)?;
        validate_utls_reality(tls, &format!("initialize outbound[{i}]"))?;
    }
    if let Some(obfs) = obj.get("obfs") {
        validate_obfs(obfs, &format!("{at}.obfs"))?;
    }
    if let Some(realm) = obj.get("realm") {
        validate_realm(realm, &format!("{at}.realm"), false)?;
    }
    if let Some(ports) = obj.get("server_ports") {
        check_server_ports_listable(ports, &format!("{at}.server_ports"))?;
    }
    Ok(())
}

fn validate_tuic_out_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let mut allowed: Vec<&str> = TUIC_OUT_FIELDS.to_vec();
    allowed.extend(DIALER_OUT_FIELDS);
    allowed.extend(QUIC_OUT_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;

    if let Some(v) = obj.get("heartbeat") {
        check_duration_field(
            v,
            &format!("{at}.heartbeat"),
            "TUICOutboundOptions",
            "heartbeat",
        )?;
    }
    if let Some(v) = obj.get("password") {
        check_string_field(
            v,
            &format!("{at}.password"),
            "TUICOutboundOptions",
            "password",
        )?;
    }
    if let Some(v) = obj.get("congestion_control") {
        check_string_field(
            v,
            &format!("{at}.congestion_control"),
            "TUICOutboundOptions",
            "congestion_control",
        )?;
    }
    if let Some(v) = obj.get("udp_relay_mode") {
        check_string_field(
            v,
            &format!("{at}.udp_relay_mode"),
            "TUICOutboundOptions",
            "udp_relay_mode",
        )?;
    }
    if let Some(v) = obj.get("network") {
        check_network(v, &format!("{at}.network"), "TUICOutboundOptions")?;
    }
    if let Some(v) = obj.get("connect_timeout") {
        check_duration_field(
            v,
            &format!("{at}.connect_timeout"),
            "TUICOutboundOptions.DialerOptions.AbstractDialerOptions",
            "connect_timeout",
        )?;
    }
    if let Some(v) = obj.get("fallback_delay") {
        check_duration_field(
            v,
            &format!("{at}.fallback_delay"),
            "TUICOutboundOptions.DialerOptions.AbstractDialerOptions",
            "fallback_delay",
        )?;
    }
    if let Some(v) = obj.get("tcp_keep_alive") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive"),
            "TUICOutboundOptions.DialerOptions.AbstractDialerOptions",
            "tcp_keep_alive",
        )?;
    }
    if let Some(v) = obj.get("tcp_keep_alive_interval") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive_interval"),
            "TUICOutboundOptions.DialerOptions.AbstractDialerOptions",
            "tcp_keep_alive_interval",
        )?;
    }
    if let Some(v) = obj.get("domain_resolver") {
        domain_resolver_server(v, &format!("{at}.domain_resolver"))?;
    }
    if let Some(tls) = obj.get("tls") {
        validate_tls_container(tls, &format!("{at}.tls"), false)?;
        validate_utls_reality(tls, &format!("initialize outbound[{i}]"))?;
    }
    Ok(())
}

fn validate_hy2_in_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("inbounds[{i}]");
    let mut allowed: Vec<&str> = HY2_IN_FIELDS.to_vec();
    allowed.extend(LISTEN_IN_FIELDS);
    allowed.extend(QUIC_OUT_FIELDS);
    allowed.extend(LEGACY_INBOUND_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;

    if let Some(v) = obj.get("up_mbps") {
        check_int_field(
            v,
            &format!("{at}.up_mbps"),
            "Hysteria2InboundOptions",
            "up_mbps",
        )?;
    }
    if let Some(v) = obj.get("down_mbps") {
        check_int_field(
            v,
            &format!("{at}.down_mbps"),
            "Hysteria2InboundOptions",
            "down_mbps",
        )?;
    }
    if let Some(v) = obj.get("bbr_profile") {
        check_string_field(
            v,
            &format!("{at}.bbr_profile"),
            "Hysteria2InboundOptions",
            "bbr_profile",
        )?;
    }
    if let Some(v) = obj.get("udp_timeout") {
        check_udp_timeout(v, &format!("{at}.udp_timeout"))?;
    }
    if let Some(v) = obj.get("tcp_keep_alive") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive"),
            "ListenOptions.AbstractListenOptions",
            "tcp_keep_alive",
        )?;
    }
    if let Some(v) = obj.get("tcp_keep_alive_interval") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive_interval"),
            "ListenOptions.AbstractListenOptions",
            "tcp_keep_alive_interval",
        )?;
    }
    if let Some(v) = obj.get("sniff_timeout") {
        check_duration_field(
            v,
            &format!("{at}.sniff_timeout"),
            "InboundOptions",
            "sniff_timeout",
        )?;
    }
    for f in ["idle_timeout", "keep_alive_period"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(
                v,
                &format!("{at}.{f}"),
                "Hysteria2InboundOptions.QUICOptions.HTTP2Options",
                f,
            )?;
        }
    }
    for f in ["stream_receive_window", "connection_receive_window"] {
        if let Some(v) = obj.get(f) {
            check_memory_bytes(
                v,
                &format!("{at}.{f}"),
                "Hysteria2InboundOptions.QUICOptions.HTTP2Options",
                f,
            )?;
        }
    }
    if let Some(obfs) = obj.get("obfs") {
        validate_obfs(obfs, &format!("{at}.obfs"))?;
    }
    if let Some(users) = obj.get("users") {
        validate_users_hy2(users, &format!("{at}.users"))?;
    }
    if let Some(mq) = obj.get("masquerade") {
        validate_masquerade(mq, &format!("{at}.masquerade"))?;
    }
    if let Some(realm) = obj.get("realm") {
        validate_realm(realm, &format!("{at}.realm"), true)?;
    }
    if let Some(tls) = obj.get("tls") {
        validate_tls_container(tls, &format!("{at}.tls"), true)?;
    }
    check_legacy_inbound(obj)?;
    Ok(())
}

fn validate_tuic_in_decode(
    i: usize,
    init_at: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
    let at = format!("inbounds[{i}]");
    let mut allowed: Vec<&str> = TUIC_IN_FIELDS.to_vec();
    allowed.extend(LISTEN_IN_FIELDS);
    allowed.extend(QUIC_OUT_FIELDS);
    allowed.extend(LEGACY_INBOUND_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;

    if let Some(v) = obj.get("heartbeat") {
        check_duration_field(
            v,
            &format!("{at}.heartbeat"),
            "TUICInboundOptions",
            "heartbeat",
        )?;
    }
    if let Some(v) = obj.get("auth_timeout") {
        check_duration_field(
            v,
            &format!("{at}.auth_timeout"),
            "TUICInboundOptions",
            "auth_timeout",
        )?;
    }
    if let Some(v) = obj.get("congestion_control") {
        check_string_field(
            v,
            &format!("{at}.congestion_control"),
            "TUICInboundOptions",
            "congestion_control",
        )?;
    }
    if let Some(v) = obj.get("udp_timeout") {
        check_udp_timeout(v, &format!("{at}.udp_timeout"))?;
    }
    if let Some(v) = obj.get("tcp_keep_alive") {
        check_duration_field(
            v,
            &format!("{at}.tcp_keep_alive"),
            "ListenOptions.AbstractListenOptions",
            "tcp_keep_alive",
        )?;
    }
    if let Some(users) = obj.get("users") {
        validate_users_tuic(users, &format!("{at}.users"), init_at)?;
    }
    if let Some(tls) = obj.get("tls") {
        validate_tls_container(tls, &format!("{at}.tls"), true)?;
    }
    check_legacy_inbound(obj)?;
    Ok(())
}

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
    if let Some(ntp) = root.get("ntp") {
        validate_ntp(ntp)?;
    }
    if let Some(experimental) = root.get("experimental") {
        validate_experimental(experimental)?;
    }
    let mut dns_tags: HashSet<String> = HashSet::new();
    let mut has_outbounds = false;
    if let Some(route) = root.get("route") {
        validate_route(route)?;
    }
    if let Some(dns) = root.get("dns") {
        validate_dns(dns, &mut dns_tags)?;
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
        has_outbounds = !entries.is_empty();
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

    // reference: decode-time shape of `route.default_domain_resolver`.
    let mut ddr_tag: Option<String> = None;
    if let Some(route) = root.get("route")
        && let Some(ddr) = route.get("default_domain_resolver")
        && !ddr.is_null()
    {
        ddr_tag = domain_resolver_server(ddr, "route.default_domain_resolver")?;
    }

    // reference: initialize outbound → `default domain resolver not found: X`
    // runs only when outbounds exist (empty/absent list skips dialer setup).
    if has_outbounds
        && let Some(tag) = ddr_tag
        && !tag.is_empty()
        && !dns_tags.contains(&tag)
    {
        return Err(format!(
            "initialize outbound[0] direct[direct]: default domain resolver not found: {tag}"
        ));
    }

    Ok(())
}

/// reference `option.DomainResolveOptions.UnmarshalJSON`: string tag or object
/// with required non-empty `server`; returns the server tag (`None` for null).
fn domain_resolver_server(value: &Value, at: &str) -> Result<Option<String>, String> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Object(map) => {
            let server = map
                .get("server")
                .ok_or_else(|| format!("{at}: empty domain_resolver.server"))?;
            let server = server.as_str().ok_or_else(|| {
                format!(
                    "{at}.server: json: cannot unmarshal number into Go struct field _DomainResolveOptions.server of type string"
                )
            })?;
            if server.is_empty() {
                return Err(format!("{at}: empty domain_resolver.server"));
            }
            if let Some(strategy) = map.get("strategy") {
                let strategy = strategy.as_str().ok_or_else(|| {
                    format!("{at}.strategy: json: cannot unmarshal into Go field of type string")
                })?;
                if !DOMAIN_STRATEGIES.contains(&strategy) {
                    return Err(format!(
                        "{at}.strategy: unknown domain strategy: {strategy}"
                    ));
                }
            }
            Ok(Some(server.to_string()))
        }
        Value::Array(_) => Err(format!(
            "{at}: json: cannot unmarshal array into Go struct field RouteOptions.route.default_domain_resolver of type option._DomainResolveOptions"
        )),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number into Go struct field RouteOptions.route.default_domain_resolver of type option._DomainResolveOptions"
        )),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field RouteOptions.route.default_domain_resolver of type option._DomainResolveOptions"
        )),
    }
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

fn validate_ntp(ntp: &Value) -> Result<(), String> {
    let obj = ntp
        .as_object()
        .ok_or_else(|| "ntp: must be a JSON object".to_string())?;
    for key in obj.keys() {
        if !KNOWN_NTP_FIELDS.contains(&key.as_str()) {
            return Err(format!("ntp: {key}: json: unknown field \"{key}\""));
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
    if action == "reject" {
        let method = rule.get("method").and_then(Value::as_str).unwrap_or("");
        match method {
            "" | "default" | "drop" | "reply" => {}
            other => return Err(format!("{at}: unknown reject method: {other}")),
        }
        if method == "drop" && rule.get("no_drop").and_then(Value::as_bool) == Some(true) {
            return Err(format!("{at}: no_drop is not available in current context"));
        }
    }
    Ok(())
}

fn validate_dns(dns: &Value, tags: &mut HashSet<String>) -> Result<(), String> {
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
        if let Some(tag) = server.get("tag").and_then(Value::as_str) {
            tags.insert(tag.to_string());
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

    match ty {
        "hysteria2" => validate_hy2_in_decode(i, obj)?,
        "tuic" => validate_tuic_in_decode(i, &at, obj)?,
        _ => {
            check_legacy_inbound(obj)?;
        }
    }

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

    if ty == "hysteria2" || ty == "tuic" {
        if tls_enabled(obj.get("tls")) {
            validate_server_tls(obj.get("tls").unwrap(), &at)?;
        }
        if ty == "hysteria2" {
            if let Some(obfs) = obj.get("obfs")
                && obfs.is_object()
                && obfs.as_object().is_some_and(|m| !m.is_empty())
            {
                let has_user_pw = obj
                    .get("users")
                    .and_then(Value::as_array)
                    .is_some_and(|users| {
                        users.iter().any(|u| {
                            u.get("password")
                                .and_then(Value::as_str)
                                .is_some_and(|p| !p.is_empty())
                        })
                    });
                if !has_user_pw {
                    return Err(format!("{at}: missing obfs password"));
                }
            }
            if let Some(bbr) = obj.get("bbr_profile").and_then(Value::as_str)
                && !bbr.is_empty()
                && !BBR_PROFILES.contains(&bbr)
            {
                return Err(format!("{at}: unsupported BBR profile: {bbr}"));
            }
            if let Some(mq) = obj.get("masquerade")
                && mq.is_string()
            {
                validate_masquerade(mq, "masquerade")?;
            }
            if let Some(realm) = obj.get("realm")
                && realm_present(Some(realm))
            {
                let realm_obj = realm.as_object().unwrap();
                let url = realm_obj
                    .get("server_url")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if url.is_empty() {
                    return Err(format!(
                        "{at}: create realm server: control server URL is required"
                    ));
                }
                let host = url_host(url);
                if host.is_empty() {
                    return Err(format!(
                        "{at}: create realm server: control server URL is required"
                    ));
                }
                if realm_obj
                    .get("realm_id")
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.is_empty())
                {
                    return Err(format!("{at}: create realm server: realm ID is required"));
                }
                if let Some(iv) = realm_obj.get("ip_version").and_then(Value::as_i64)
                    && iv != 0
                    && iv != 4
                    && iv != 6
                {
                    return Err(format!("{at}: invalid IP version: {iv}"));
                }
                if let Some(listen) = obj.get("listen").and_then(Value::as_str)
                    && let Ok(ip) = IpAddr::from_str(listen)
                    && realm_obj.get("ip_version").and_then(Value::as_i64) == Some(6)
                    && ip.is_ipv4()
                {
                    return Err(format!(
                        "{at}: realm.ip_version 6 conflicts with listen address {listen}"
                    ));
                }
            }
        }
        if ty == "tuic" {
            if let Some(cc) = obj.get("congestion_control").and_then(Value::as_str)
                && !cc.is_empty()
                && !TUIC_CC_ALGS.contains(&cc)
            {
                return Err(format!("{at}: unknown congestion control algorithm: {cc}"));
            }
            if let Some(users) = obj.get("users").and_then(Value::as_array) {
                for (idx, user) in users.iter().enumerate() {
                    let uuid = user.get("uuid").and_then(Value::as_str).unwrap_or("");
                    if !valid_uuid(uuid) {
                        return Err(format!(
                            "{at}: invalid uuid for user {idx}: uuid: incorrect UUID length"
                        ));
                    }
                }
            }
        }
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
        "hysteria2" => validate_hy2_out_decode(i, obj)?,
        "tuic" => validate_tuic_out_decode(i, obj)?,
        _ => {}
    }

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
        "hysteria2" => {
            let realm = obj.get("realm");
            let has_server = obj
                .get("server")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
                || obj.get("server_port").is_some()
                || obj
                    .get("server_ports")
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty());
            if realm_present(realm) && has_server {
                return Err(format!(
                    "{at}: realm conflicts with server, server_port, and server_ports"
                ));
            }
            if realm_present(realm) {
                let realm_obj = realm.unwrap().as_object().unwrap();
                let url = realm_obj
                    .get("server_url")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let host = url_host(url);
                if host.is_empty() {
                    return Err(format!("{at}: missing host in realm server_url"));
                }
                if let Some(iv) = realm_obj.get("ip_version").and_then(Value::as_i64)
                    && iv != 0
                    && iv != 4
                    && iv != 6
                {
                    return Err(format!("{at}: invalid IP version: {iv}"));
                }
            }
            if tls_enabled(obj.get("tls"))
                && !tls_insecure(obj.get("tls"))
                && server_address(obj).is_empty()
            {
                return Err(format!("{at}: missing server_name or insecure=true"));
            }
            if let Some(obfs) = obj.get("obfs")
                && obfs.is_object()
                && obfs.as_object().is_some_and(|m| !m.is_empty())
            {
                let password = obj.get("password").and_then(Value::as_str).unwrap_or("");
                if password.is_empty() {
                    return Err(format!("{at}: missing obfs password"));
                }
            }
            if let Some(ports) = obj.get("server_ports") {
                let ranges = check_server_ports_listable(ports, "server_ports")
                    .map_err(|m| format!("{at}: {m}"))?;
                for r in &ranges {
                    check_port_range(r).map_err(|m| format!("{at}: {m}"))?;
                }
            }
            if let Some(bbr) = obj.get("bbr_profile").and_then(Value::as_str)
                && !bbr.is_empty()
                && !BBR_PROFILES.contains(&bbr)
            {
                return Err(format!("{at}: unsupported BBR profile: {bbr}"));
            }
            if realm_present(realm) {
                let realm_obj = realm.unwrap().as_object().unwrap();
                if let Some(pm) = realm_obj.get("port_mapping").and_then(Value::as_object)
                    && pm.get("enabled").and_then(Value::as_bool) == Some(true)
                    && realm_obj.get("ip_version").and_then(Value::as_i64) == Some(6)
                {
                    return Err(format!("{at}: port mapping requires IPv4"));
                }
            }
            if let Some(hc) = obj
                .get("realm")
                .and_then(|r| r.as_object())
                .and_then(|m| m.get("http_client"))
                && let Some(tag) = hc.as_str()
                && !tag.is_empty()
            {
                // reference resolves at initialize: create realm http client: http_client not found
                let _ = tag;
            }
        }
        "tuic" => {
            if tls_enabled(obj.get("tls"))
                && !tls_insecure(obj.get("tls"))
                && server_address(obj).is_empty()
            {
                return Err(format!("{at}: missing server_name or insecure=true"));
            }
            let uuid = obj.get("uuid").and_then(Value::as_str).unwrap_or("");
            if !valid_uuid(uuid) {
                return Err(format!("{at}: invalid uuid: uuid: incorrect UUID length"));
            }
            if obj.get("udp_over_stream").and_then(Value::as_bool) == Some(true)
                && obj
                    .get("udp_relay_mode")
                    .and_then(Value::as_str)
                    .is_some_and(|m| !m.is_empty())
            {
                return Err(format!(
                    "{at}: udp_over_stream is conflict with udp_relay_mode"
                ));
            }
            if let Some(mode) = obj.get("udp_relay_mode").and_then(Value::as_str)
                && !mode.is_empty()
                && !TUIC_UDP_RELAY_MODES.contains(&mode)
            {
                return Err(format!(
                    "{at}: unknown udp_relay_mode: {mode} (expected native or quic)"
                ));
            }
            if let Some(cc) = obj.get("congestion_control").and_then(Value::as_str)
                && !cc.is_empty()
                && !TUIC_CC_ALGS.contains(&cc)
            {
                return Err(format!("{at}: unknown congestion control algorithm: {cc}"));
            }
        }
        _ => {}
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
        _ => {}
    }

    if tls_enabled(obj.get("tls")) {
        let tls = obj.get("tls").unwrap();
        validate_utls_reality(tls, &at)?;
    }

    Ok(())
}

fn server_address(obj: &Map<String, Value>) -> String {
    if realm_present(obj.get("realm")) {
        let url = obj
            .get("realm")
            .and_then(|r| r.as_object())
            .and_then(|m| m.get("server_url"))
            .and_then(Value::as_str)
            .unwrap_or("");
        return url_host(url);
    }
    obj.get("server")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn url_host(url: &str) -> String {
    // reference url.Parse → Hostname()
    let rest = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.rsplit_once('@') {
        Some((_, hostport)) => hostport,
        None => authority,
    };
    let host = match hostport_split(host) {
        Some(h) => h,
        None => host,
    };
    host.to_string()
}

fn hostport_split(s: &str) -> Option<&str> {
    if s.starts_with('[') {
        let end = s.find(']')?;
        Some(&s[1..end])
    } else if let Some((host, port)) = s.rsplit_once(':')
        && !host.contains(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        Some(host)
    } else {
        Some(s)
    }
}

fn tls_insecure(tls: Option<&Value>) -> bool {
    tls.and_then(|t| t.get("insecure"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
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

    #[test]
    fn rejects_default_domain_strategy() {
        let err =
            validate(&json!({"route": {"default_domain_strategy": "prefer_ipv4"}})).unwrap_err();
        assert!(err.contains("default_domain_strategy"), "{err}");
    }

    #[test]
    fn domain_resolver_shapes() {
        assert_eq!(
            domain_resolver_server(&json!("u"), "at").unwrap(),
            Some("u".into())
        );
        assert_eq!(
            domain_resolver_server(&json!(""), "at").unwrap(),
            Some("".into())
        );
        assert_eq!(domain_resolver_server(&json!(null), "at").unwrap(), None);
        assert_eq!(
            domain_resolver_server(&json!({"server": "u", "strategy": "prefer_ipv4"}), "at")
                .unwrap(),
            Some("u".into())
        );
        assert_eq!(
            domain_resolver_server(&json!({"server": "u", "strategy": ""}), "at").unwrap(),
            Some("u".into())
        );
        let err = domain_resolver_server(&json!({}), "at").unwrap_err();
        assert!(err.contains("empty domain_resolver.server"), "{err}");
        let err = domain_resolver_server(&json!({"server": ""}), "at").unwrap_err();
        assert!(err.contains("empty domain_resolver.server"), "{err}");
        let err = domain_resolver_server(&json!({"server": 42}), "at").unwrap_err();
        assert!(err.contains("cannot unmarshal number"), "{err}");
        let err = domain_resolver_server(&json!(["x"]), "at").unwrap_err();
        assert!(err.contains("cannot unmarshal array"), "{err}");
        let err = domain_resolver_server(&json!(42), "at").unwrap_err();
        assert!(err.contains("cannot unmarshal number"), "{err}");
        let err =
            domain_resolver_server(&json!({"server": "u", "strategy": "bogus"}), "at").unwrap_err();
        assert!(err.contains("unknown domain strategy: bogus"), "{err}");
    }

    #[test]
    fn default_domain_resolver_tag_missing() {
        let err = validate(&json!({
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct", "default_domain_resolver": "nope"}
        }))
        .unwrap_err();
        assert!(
            err.contains("default domain resolver not found: nope"),
            "{err}"
        );
    }

    #[test]
    fn default_domain_resolver_tag_ok() {
        let cfg = json!({
            "dns": {"servers": [{"type": "udp", "tag": "u", "server": "1.1.1.1"}], "final": "u"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct", "default_domain_resolver": "u"}
        });
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn default_domain_resolver_without_outbounds_ok() {
        let cfg = json!({"route": {"default_domain_resolver": "u"}});
        assert!(validate(&cfg).is_ok());
        let cfg = json!({"outbounds": [], "route": {"default_domain_resolver": "u"}});
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn reject_method_validation() {
        let err = validate(&json!({
            "outbounds": [{"type": "direct", "tag": "d"}],
            "route": {"final": "d", "rules": [{"action": "reject", "method": "bogus"}]}
        }))
        .unwrap_err();
        assert!(err.contains("unknown reject method: bogus"), "{err}");
        let err = validate(&json!({
            "outbounds": [{"type": "direct", "tag": "d"}],
            "route": {"final": "d", "rules": [{"action": "reject", "method": "drop", "no_drop": true}]}
        }))
        .unwrap_err();
        assert!(err.contains("no_drop is not available"), "{err}");
        assert!(
            validate(&json!({
                "outbounds": [{"type": "direct", "tag": "d"}],
                "route": {"final": "d", "rules": [{"action": "reject"}]}
            }))
            .is_ok()
        );
        assert!(
            validate(&json!({
                "outbounds": [{"type": "direct", "tag": "d"}],
                "route": {"final": "d", "rules": [{"action": "reject", "method": "drop"}]}
            }))
            .is_ok()
        );
        assert!(
            validate(&json!({
                "outbounds": [{"type": "direct", "tag": "d"}],
                "route": {"final": "d", "rules": [{"action": "reject", "method": "reply"}]}
            }))
            .is_ok()
        );
        assert!(
            validate(&json!({
                "outbounds": [{"type": "direct", "tag": "d"}],
                "route": {"final": "d", "rules": [{"action": "reject", "no_drop": true}]}
            }))
            .is_ok()
        );
    }

    #[test]
    fn go_duration_rules() {
        assert!(go_parse_duration("30s").is_ok());
        assert!(go_parse_duration("1h30m").is_ok());
        assert!(go_parse_duration("1.5s").is_ok());
        assert!(go_parse_duration("1d2h").is_ok());
        assert!(go_parse_duration("1us").is_ok());
        assert!(go_parse_duration("1µs").is_ok());
        assert!(go_parse_duration("-30s").is_ok());
        assert!(go_parse_duration("+5s").is_ok());
        assert!(go_parse_duration("0").is_err());
        assert!(go_parse_duration("").is_err());
        assert!(go_parse_duration("30").is_err());
        assert!(go_parse_duration("bogus").is_err());
        assert!(go_parse_duration("2w").is_err());
        assert!(go_parse_duration("1e3s").is_err());
        assert!(go_parse_duration("1.5.5s").is_err());
    }

    #[test]
    fn memory_bytes_rules() {
        assert!(check_memory_bytes_str("1KB", "at").is_ok());
        assert!(check_memory_bytes_str("1 MB", "at").is_ok());
        assert!(check_memory_bytes_str("1gb", "at").is_ok());
        assert!(check_memory_bytes_str("1k", "at").is_ok());
        assert!(check_memory_bytes_str("1TB", "at").is_ok());
        assert!(check_memory_bytes_str("1KB ", "at").is_ok());
        assert!(check_memory_bytes_str("1  KB", "at").is_ok());
        assert!(check_memory_bytes_str(" 1KB", "at").is_err());
        assert!(check_memory_bytes_str("12345678", "at").is_err());
        assert!(check_memory_bytes_str("MB", "at").is_err());
        assert!(check_memory_bytes_str("1KiB", "at").is_err());
        assert!(check_memory_bytes_str("1MiB", "at").is_err());
        assert!(check_memory_bytes_str("-1MB", "at").is_err());
        assert!(check_memory_bytes_str("32 MiB", "at").is_err());
        assert!(check_memory_bytes_str("1.5MB", "at").is_err());
    }

    #[test]
    fn port_range_rules() {
        assert!(check_port_range("443:500").is_ok());
        assert!(check_port_range("443:").is_ok());
        assert!(check_port_range(":443").is_ok());
        assert!(check_port_range(":").is_ok());
        assert!(check_port_range("500:443").is_ok());
        assert!(check_port_range("0:0").is_ok());
        assert!(check_port_range("1:65535").is_ok());
        assert!(check_port_range("443").is_err());
        assert!(check_port_range("bogus").is_err());
        assert!(check_port_range("::").is_err());
        assert!(check_port_range("1:2:3").is_err());
        assert!(check_port_range("443:500:").is_err());
        assert!(check_port_range(" 443:500").is_err());
        assert!(check_port_range("-1:2").is_err());
        assert!(check_port_range("65536:65537").is_err());
    }

    #[test]
    fn network_list_rules() {
        assert!(check_network(&json!("tcp"), "at", "S").is_ok());
        assert!(check_network(&json!("udp"), "at", "S").is_ok());
        assert!(check_network(&json!("TCP"), "at", "S").is_err());
        assert!(check_network(&json!(["tcp", "udp"]), "at", "S").is_ok());
        assert!(check_network(&json!([]), "at", "S").is_ok());
        assert!(check_network(&json!(null), "at", "S").is_ok());
        assert!(check_network(&json!(1), "at", "S").is_err());
        assert!(check_network(&json!(["tcp", "bogus"]), "at", "S").is_err());
        assert!(check_network(&json!(["tcp", 1]), "at", "S").is_err());
    }

    #[test]
    fn realm_empty_object_is_absent() {
        assert!(!realm_present(Some(&json!({}))));
        assert!(realm_present(Some(&json!({"server_url": ""}))));
        assert!(!realm_present(Some(&json!(null))));
        assert!(!realm_present(None));
    }

    #[test]
    fn hy2_out_unknown_field() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "xyz": 1
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("outbounds[0].xyz: json: unknown field \"xyz\""),
            "{err}"
        );
    }

    #[test]
    fn hy2_out_tls_unknown_field() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true, "xyz": 1}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("outbounds[0].tls.xyz"), "{err}");
    }

    #[test]
    fn hy2_out_rejects_congestion_control() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "congestion_control": "bbr"
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("unknown field \"congestion_control\""),
            "{err}"
        );
    }

    #[test]
    fn hy2_out_bad_duration() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "hop_interval": "bogus"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("time: invalid duration"), "{err}");
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "hop_interval": 30
            }]
        }))
        .unwrap_err();
        assert!(err.contains("cannot unmarshal number"), "{err}");
    }

    #[test]
    fn hy2_out_up_mbps_string() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "up_mbps": "10"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("up_mbps"), "{err}");
    }

    #[test]
    fn hy2_out_server_ports_rules() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "server_ports": 1
            }]
        }))
        .unwrap_err();
        assert!(err.contains("server_ports"), "{err}");
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "server_ports": ["443"]
            }]
        }))
        .unwrap_err();
        assert!(err.contains("bad port range"), "{err}");
        assert!(
            validate(&json!({
                "outbounds": [{
                    "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                    "tls": {"enabled": true, "insecure": true}, "server_ports": ["443:500"]
                }]
            }))
            .is_ok()
        );
    }

    #[test]
    fn hy2_out_bad_bbr_case() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "bbr_profile": "Standard"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("unsupported BBR profile: Standard"), "{err}");
        assert!(
            validate(&json!({
                "outbounds": [{
                    "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                    "tls": {"enabled": true, "insecure": true}, "bbr_profile": "standard"
                }]
            }))
            .is_ok()
        );
    }

    #[test]
    fn hy2_out_obfs_password_required() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true},
                "obfs": {"type": "salamander"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("missing obfs password"), "{err}");
        assert!(
            validate(&json!({
                "outbounds": [{
                    "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                    "tls": {"enabled": true, "insecure": true},
                    "obfs": {"type": "salamander"}, "password": "x"
                }]
            }))
            .is_ok()
        );
    }

    #[test]
    fn hy2_out_obfs_bad_type() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "obfs": {"type": "bad"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("unknown obfs type: bad"), "{err}");
    }

    #[test]
    fn hy2_out_realm_conflict() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true},
                "realm": {"server_url": ""}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("realm conflicts"), "{err}");
        assert!(
            validate(&json!({
                "outbounds": [{
                    "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                    "tls": {"enabled": true, "insecure": true}, "realm": {}
                }]
            }))
            .is_ok()
        );
    }

    #[test]
    fn hy2_out_realm_no_host() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t",
                "tls": {"enabled": true, "insecure": true},
                "realm": {"server_url": ""}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("missing host in realm server_url"), "{err}");
    }

    #[test]
    fn hy2_out_bad_network() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true}, "network": "TCP"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("unknown network: TCP"), "{err}");
    }

    #[test]
    fn hy2_out_realm_unknown_field() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "tls": {"enabled": true, "insecure": true},
                "realm": {"xyz": 1}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("realm.xyz"), "{err}");
    }

    #[test]
    fn tuic_out_unknown_field() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "tuic", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "x",
                "tls": {"enabled": true, "insecure": true}, "auth_timeout": "5s"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("auth_timeout"), "{err}");
    }

    #[test]
    fn tuic_out_bad_cc() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "tuic", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "x",
                "tls": {"enabled": true, "insecure": true}, "congestion_control": "weird"
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("unknown congestion control algorithm: weird"),
            "{err}"
        );
    }

    #[test]
    fn tuic_out_bad_relay() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "tuic", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "x",
                "tls": {"enabled": true, "insecure": true}, "udp_relay_mode": "weird"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("unknown udp_relay_mode"), "{err}");
    }

    #[test]
    fn tuic_out_ovs_conflict() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "tuic", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "x",
                "tls": {"enabled": true, "insecure": true},
                "udp_over_stream": true, "udp_relay_mode": "native"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("udp_over_stream is conflict"), "{err}");
    }

    #[test]
    fn tuic_out_bad_heartbeat() {
        let err = validate(&json!({
            "outbounds": [{
                "type": "tuic", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "x",
                "tls": {"enabled": true, "insecure": true}, "heartbeat": "bogus"
            }]
        }))
        .unwrap_err();
        assert!(err.contains("time: invalid duration"), "{err}");
    }

    #[test]
    fn hy2_in_unknown_field() {
        let err = validate(&json!({
            "inbounds": [{
                "type": "hysteria2", "tag": "t", "listen": "127.0.0.1", "listen_port": 8443,
                "tls": {"enabled": true, "certificate_path": "x", "key_path": "y"},
                "xyz": 1
            }]
        }))
        .unwrap_err();
        assert!(err.contains("inbounds[0].xyz"), "{err}");
    }

    #[test]
    fn hy2_in_no_cert() {
        let err = validate(&json!({
            "inbounds": [{
                "type": "hysteria2", "tag": "t", "listen": "127.0.0.1", "listen_port": 8443,
                "tls": {"enabled": true}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("missing certificate"), "{err}");
    }

    #[test]
    fn tuic_in_unknown_field() {
        let err = validate(&json!({
            "inbounds": [{
                "type": "tuic", "tag": "t", "listen": "127.0.0.1", "listen_port": 8443,
                "tls": {"enabled": true, "certificate_path": "x", "key_path": "y"},
                "up_mbps": 10
            }]
        }))
        .unwrap_err();
        assert!(err.contains("up_mbps"), "{err}");
    }

    #[test]
    fn legacy_inbound_sniff() {
        let err = validate(&json!({
            "inbounds": [{
                "type": "mixed", "tag": "t", "listen": "127.0.0.1", "listen_port": 2080,
                "sniff": true
            }]
        }))
        .unwrap_err();
        assert!(err.contains("legacy inbound fields"), "{err}");
        assert!(
            validate(&json!({
                "inbounds": [{
                    "type": "mixed", "tag": "t", "listen": "127.0.0.1", "listen_port": 2080,
                    "sniff": false, "domain_strategy": "", "sniff_timeout": "0s"
                }]
            }))
            .is_ok()
        );
    }

    #[test]
    fn masquerade_rules() {
        assert!(validate_masquerade(&json!("http://x/"), "at").is_ok());
        assert!(validate_masquerade(&json!("file:///x"), "at").is_ok());
        let err = validate_masquerade(&json!("ftp://x"), "at").unwrap_err();
        assert!(err.contains("unknown masquerade URL scheme: ftp"), "{err}");
        let err = validate_masquerade(&json!({"type": "bogus"}), "at").unwrap_err();
        assert!(err.contains("unknown masquerade type: bogus"), "{err}");
        let err =
            validate_masquerade(&json!({"type": "file", "xyz": 1}), "masquerade").unwrap_err();
        assert!(err.contains("masquerade.xyz"), "{err}");
        assert!(validate_masquerade(&json!({"type": "proxy", "url": "http://x/"}), "at").is_ok());
        assert!(validate_masquerade(&json!({"type": "string", "status_code": 302}), "at").is_ok());
    }

    #[test]
    fn valid_hy2_tuic_shapes() {
        let cfg = json!({
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": 2080}],
            "outbounds": [
                {"type": "hysteria2", "tag": "hy2", "server": "127.0.0.1", "server_port": 8443,
                 "up_mbps": 10, "down_mbps": 10, "password": "x",
                 "tls": {"enabled": true, "insecure": true}},
                {"type": "tuic", "tag": "tuic", "server": "127.0.0.1", "server_port": 443,
                 "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "s",
                 "tls": {"enabled": true, "insecure": true}},
                {"type": "direct", "tag": "direct"}
            ],
            "route": {"final": "direct"}
        });
        assert!(validate(&cfg).is_ok());
    }
}
