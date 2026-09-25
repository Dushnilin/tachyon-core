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

/// reference `option.WireGuardEndpointOptions`: wireguard.go root fields +
/// `option.AmneziaWGOptions` (wireguard_awg.go, embedded without a wrapper
/// key) + the `type`/`tag` wrapper fields. Shared dial fields live in
/// `DIALER_OUT_FIELDS` and are accepted alongside these.
const KNOWN_ENDPOINT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "system",
    "name",
    "mtu",
    "address",
    "private_key",
    "listen_port",
    "peers",
    "udp_timeout",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "workers",
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "id",
    "ip",
    "ib",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
];

/// reference `option.WireGuardPeer` (wireguard.go).
const KNOWN_ENDPOINT_PEER_FIELDS: &[&str] = &[
    "address",
    "port",
    "public_key",
    "pre_shared_key",
    "allowed_ips",
    "persistent_keepalive_interval",
    "reserved",
];

/// reference `option.UNNATBehavior` (udp-nat shared doc).
const UDP_NAT_BEHAVIORS: &[&str] = &[
    "endpoint_independent",
    "address_dependent",
    "address_and_port_dependent",
];

/// reference network strategy values (dial.md `network_strategy`).
const NETWORK_STRATEGIES: &[&str] = &["", "default", "hybrid", "fallback"];

/// reference InterfaceType values (dial.md `network_type`). `""` is not a
/// valid element: a toplevel `""` only passes through the base64 special case.
const INTERFACE_TYPES: &[&str] = &["wifi", "cellular", "ethernet", "other"];

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
    "chrome_psk",
    "chrome_psk_shuffle",
    "chrome_padding_psk_shuffle",
    "chrome_pq",
    "chrome_pq_psk",
    "firefox",
    "safari",
    "edge",
    "360",
    "qq",
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

/// anytls outbound allowlist (reference option.AnyTLSOutboundOptions),
/// excluding the dialer/TLS containers.
const ANYTLS_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "server",
    "server_port",
    "tls",
    "password",
    "idle_session_check_interval",
    "idle_session_timeout",
    "min_idle_session",
    "client_metadata",
];

/// Go `tls.CipherSuites()` names accepted by the reference TLS client init.
const TLS_CIPHER_SUITES: &[&str] = &[
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
];

/// reference `ParseTLSVersion` accepted values.
const TLS_VERSIONS: &[&str] = &["1.0", "1.1", "1.2", "1.3"];

/// reference `option.CurvePreference` names (compared case-insensitively).
const CURVE_PREFERENCES: &[&str] = &["p256", "p384", "p521", "x25519", "x25519mlkem768"];

/// reference `tlsspoof.ParseMethod` accepted values.
const SPOOF_METHODS: &[&str] = &[
    "",
    "wrong-sequence",
    "wrong-checksum",
    "wrong-ack",
    "wrong-md5",
    "wrong-timestamp",
];

/// Masque outbound allowlist (option.MASQUEOutboundOptions), excluding
/// dialer/TLS containers.
const MASQUE_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "server",
    "server_port",
    "profile",
    "vhttp",
    "network",
    "private_key",
    "public_key",
    "ip",
    "ipv6",
    "uri",
    "mtu",
    "sni",
    "skip_cert_verify",
    "fragment",
    "fragment_fallback_delay",
    "record_fragment",
    "idle_timeout",
    "keep_alive_period",
    "network_list",
    "tls",
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
    if raw == "0" || raw == "+0" || raw == "-0" {
        return Ok(());
    }
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

/// Parsed duration in nanoseconds for legacy-vs-tls conflict comparisons
/// (`badoption.Duration` equality). `None` when the text is not a valid
/// duration — callers treat that as zero, decode has already rejected it.
fn go_duration_ns(raw: &str) -> Option<i128> {
    let mut s = raw;
    let mut sign: i128 = 1;
    if let Some(rest) = s.strip_prefix('-') {
        sign = -1;
        s = rest;
    } else if let Some(rest) = s.strip_prefix('+') {
        s = rest;
    }
    if s.is_empty() {
        return None;
    }
    let mut total: i128 = 0;
    let mut consumed_any = false;
    while !s.is_empty() {
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
        if num_len == 0 {
            return None;
        }
        let value: f64 = s[..num_len].parse().ok()?;
        let rest = &s[num_len..];
        let unit_len = rest
            .chars()
            .take_while(|c| c.is_alphabetic())
            .map(char::len_utf8)
            .sum::<usize>();
        if unit_len == 0 {
            return None;
        }
        let mult: i128 = match &rest[..unit_len] {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            "d" => 86_400_000_000_000,
            _ => return None,
        };
        total += (value * mult as f64) as i128;
        s = &rest[unit_len..];
        consumed_any = true;
    }
    if !consumed_any {
        return None;
    }
    Some(sign * total)
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
    // reference stage-2 prune runs deep inside the container: `{}`/`[]`
    // (including nested empties) behave as absent fields.
    let Some(value) = deep_prune(value) else {
        return Ok(());
    };
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    let allowed = if inbound {
        TLS_IN_FIELDS
    } else {
        TLS_OUT_FIELDS
    };

    if !inbound {
        const GS: &str = "OutboundTLSOptions.OutboundTLSOptionsContainer";
        for f in [
            "enabled",
            "insecure",
            "disable_sni",
            "fragment",
            "record_fragment",
            "kernel_tx",
            "kernel_rx",
        ] {
            if let Some(v) = obj.get(f) {
                ep_bool(v, &format!("{at}.{f}"), GS, &format!("tls.{f}"))?;
            }
        }
        for f in [
            "server_name",
            "engine",
            "min_version",
            "max_version",
            "certificate_path",
            "client_certificate_path",
            "client_key_path",
            "spoof",
            "spoof_method",
        ] {
            if let Some(v) = obj.get(f) {
                ep_str(v, &format!("{at}.{f}"), GS, &format!("tls.{f}"))?;
            }
        }
        for f in [
            "alpn",
            "certificate",
            "client_certificate",
            "client_key",
            "cipher_suites",
        ] {
            if let Some(v) = obj.get(f) {
                check_listable_string(v, &format!("{at}.{f}"))?;
            }
        }
        if let Some(v) = obj.get("curve_preferences") {
            check_curve_preferences(v, &format!("{at}.curve_preferences"))?;
        }
        for f in [
            "certificate_public_key_sha256",
            "client_certificate_public_key_sha256",
        ] {
            if let Some(v) = obj.get(f) {
                check_listable_bytes(v, &format!("{at}.{f}"))?;
            }
        }
        if let Some(v) = obj.get("ech") {
            validate_tls_ech_container(v, &format!("{at}.ech"))?;
        }
        if let Some(v) = obj.get("utls") {
            validate_tls_utls_container(v, &format!("{at}.utls"))?;
        }
        if let Some(v) = obj.get("reality") {
            validate_tls_reality_container(v, &format!("{at}.reality"))?;
        }
    }

    for f in ["fragment_fallback_delay", "handshake_timeout"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(
                v,
                &format!("{at}.{f}"),
                "OutboundTLSOptions.OutboundTLSOptionsContainer",
                &format!("tls.{f}"),
            )?;
        }
    }
    reject_unknown_fields_deep(&value, at, allowed)?;
    Ok(())
}

/// Listable[string] decode: null/string ok; arrays validate element-wise
/// (a null element becomes `""`); other kinds report the listable union.
fn check_listable_string(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::String(_) => Ok(()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                match item {
                    Value::Null | Value::String(_) => {}
                    other => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: json: cannot unmarshal {} into Go value of type string)",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(())
        }
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type string | json: cannot unmarshal {kind} into Go value of type []string)"
            ))
        }
    }
}

/// Listable[CurvePreference]: strings validate case-insensitively against the
/// reference curve names; null ok; union errors mirror the reference decode.
fn check_curve_preferences(value: &Value, at: &str) -> Result<(), String> {
    fn known(s: &str) -> bool {
        CURVE_PREFERENCES.iter().any(|c| c.eq_ignore_ascii_case(s))
    }
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            if known(s) {
                Ok(())
            } else {
                Err(format!(
                    "{at}: (unknown curve name: {s} | json: cannot unmarshal string into Go value of type []option.CurvePreference)"
                ))
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) if known(s) => {}
                    Value::String(s) => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: unknown curve name: {s})"
                        ));
                    }
                    Value::Null => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: unknown curve name: )"
                        ));
                    }
                    other => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: json: cannot unmarshal {} into Go value of type string)",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(())
        }
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type string | json: cannot unmarshal {kind} into Go value of type []option.CurvePreference)"
            ))
        }
    }
}

/// Listable[[]byte] (`certificate_public_key_sha256`): the array decode tries
/// element-wise byte values first, then element-wise base64 strings; the union
/// reports both attempt failures.
fn check_listable_bytes(value: &Value, at: &str) -> Result<(), String> {
    fn attempt_bytes(items: &[Value]) -> Result<(), String> {
        for (i, item) in items.iter().enumerate() {
            match item {
                Value::Null => {}
                Value::Number(n)
                    if n.as_f64()
                        .is_some_and(|f| f.fract() == 0.0 && (0.0..=255.0).contains(&f)) => {}
                Value::Number(_) => {
                    return Err(format!(
                        "[{i}]: json: cannot unmarshal number {} into Go value of type uint8",
                        go_number_literal(item)
                    ));
                }
                other => {
                    return Err(format!(
                        "[{i}]: json: cannot unmarshal {} into Go value of type uint8",
                        json_kind(other)
                    ));
                }
            }
        }
        Ok(())
    }
    fn attempt_b64(items: &[Value]) -> Result<(), String> {
        for (i, item) in items.iter().enumerate() {
            match item {
                Value::Null => {}
                Value::String(s) => {
                    if let Some(idx) = go_b64_error_index(s) {
                        return Err(format!("[{i}]: illegal base64 data at input byte {idx}"));
                    }
                }
                other => {
                    return Err(format!(
                        "[{i}]: json: cannot unmarshal {} into Go value of type []uint8",
                        json_kind(other)
                    ));
                }
            }
        }
        Ok(())
    }
    match value {
        Value::Null => Ok(()),
        Value::String(s) => match go_b64_error_index(s) {
            None => Ok(()),
            Some(idx) => Err(format!(
                "{at}: (illegal base64 data at input byte {idx} | json: cannot unmarshal string into Go value of type [][]uint8)"
            )),
        },
        Value::Array(items) => {
            let first = attempt_bytes(items);
            if first.is_ok() {
                return Ok(());
            }
            let second = attempt_b64(items);
            if second.is_ok() {
                return Ok(());
            }
            Err(format!(
                "{at}: ({} | {})",
                first.unwrap_err(),
                second.unwrap_err()
            ))
        }
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type []uint8 | json: cannot unmarshal {kind} into Go value of type [][]uint8)"
            ))
        }
    }
}

fn validate_tls_ech_container(value: &Value, at: &str) -> Result<(), String> {
    const GS: &str = "OutboundECHOptions.OutboundTLSOptionsContainer";
    match value {
        Value::Null => Ok(()),
        Value::Object(m) => {
            for f in [
                "enabled",
                "query_server_name",
                "pq_signature_schemes_enabled",
                "dynamic_record_sizing_disabled",
            ] {
                if let Some(v) = m.get(f) {
                    ep_bool(v, &format!("{at}.{f}"), GS, &format!("tls.ech.{f}"))?;
                }
            }
            if let Some(v) = m.get("config_path") {
                ep_str(v, &format!("{at}.config_path"), GS, "tls.ech.config_path")?;
            }
            if let Some(v) = m.get("config") {
                check_listable_string(v, &format!("{at}.config"))?;
            }
            reject_unknown_fields_deep(
                value,
                at,
                &[
                    "enabled",
                    "config",
                    "config_path",
                    "query_server_name",
                    "pq_signature_schemes_enabled",
                    "dynamic_record_sizing_disabled",
                ],
            )?;
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            GS,
            "tls.ech",
            "option.OutboundECHOptions",
        )),
    }
}

fn validate_tls_utls_container(value: &Value, at: &str) -> Result<(), String> {
    const GS: &str = "OutboundUTLSOptions.OutboundTLSOptionsContainer";
    match value {
        Value::Null => Ok(()),
        Value::Object(m) => {
            if let Some(v) = m.get("enabled") {
                ep_bool(v, &format!("{at}.enabled"), GS, "tls.utls.enabled")?;
            }
            if let Some(v) = m.get("fingerprint") {
                ep_str(v, &format!("{at}.fingerprint"), GS, "tls.utls.fingerprint")?;
            }
            reject_unknown_fields_deep(value, at, &["enabled", "fingerprint"])?;
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            GS,
            "tls.utls",
            "option.OutboundUTLSOptions",
        )),
    }
}

fn validate_tls_reality_container(value: &Value, at: &str) -> Result<(), String> {
    const GS: &str = "OutboundRealityOptions.OutboundTLSOptionsContainer";
    match value {
        Value::Null => Ok(()),
        Value::Object(m) => {
            if let Some(v) = m.get("enabled") {
                ep_bool(v, &format!("{at}.enabled"), GS, "tls.reality.enabled")?;
            }
            for f in ["public_key", "short_id", "key_share"] {
                if let Some(v) = m.get(f) {
                    ep_str(v, &format!("{at}.{f}"), GS, &format!("tls.reality.{f}"))?;
                }
            }
            reject_unknown_fields_deep(
                value,
                at,
                &["enabled", "public_key", "short_id", "key_share"],
            )?;
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            GS,
            "tls.reality",
            "option.OutboundRealityOptions",
        )),
    }
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

fn validate_masque_out_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    // reference stage-2 prune: the whole outbound map drops prunable values
    // before the strict options decode, so `{}`/`[]` act as absent fields.
    let pruned: Map<String, Value> = obj
        .iter()
        .filter(|(_, v)| !prunes_value(v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let obj = &pruned;

    // Field checks run before the unknown-field pass: the reference reports
    // whichever error comes first in document order, and a fixed field order
    // matches more observed probes than the BTreeMap alphabetical key walk.
    for f in ["profile", "ip", "ipv6"] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), "MASQUEOutboundOptions", f)?;
        }
    }
    if let Some(v) = obj.get("network_list") {
        check_masque_network_list(v, &format!("{at}.network_list"))?;
    }
    for f in [
        "vhttp",
        "network",
        "sni",
        "uri",
        "private_key",
        "public_key",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), "MASQUEOutboundOptions", f)?;
        }
    }
    if let Some(v) = obj.get("server") {
        ep_str(
            v,
            &format!("{at}.server"),
            "MASQUEOutboundOptions.ServerOptions",
            "server",
        )?;
    }
    if let Some(v) = obj.get("detour") {
        ep_str(
            v,
            &format!("{at}.detour"),
            "MASQUEOutboundOptions.DialerOptions",
            "detour",
        )?;
    }
    if let Some(v) = obj.get("bind_interface") {
        ep_str(
            v,
            &format!("{at}.bind_interface"),
            "MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions",
            "bind_interface",
        )?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(
            v,
            &format!("{at}.mtu"),
            "MASQUEOutboundOptions",
            "mtu",
            u64::from(u32::MAX),
        )?;
    }
    for f in ["skip_cert_verify", "fragment", "record_fragment"] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), "MASQUEOutboundOptions", f)?;
        }
    }
    if let Some(v) = obj.get("udp_fragment") {
        ep_bool(
            v,
            &format!("{at}.udp_fragment"),
            "MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions",
            "udp_fragment",
        )?;
    }
    for f in ["fragment_fallback_delay", "keep_alive_period"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), "MASQUEOutboundOptions", f)?;
        }
    }
    // lx 1.14.2-lx.3: `idle_timeout` is a pointer — null means "absent".
    if let Some(v) = obj.get("idle_timeout").filter(|v| !v.is_null()) {
        check_duration_field(
            v,
            &format!("{at}.idle_timeout"),
            "MASQUEOutboundOptions",
            "idle_timeout",
        )?;
    }
    for f in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "fallback_delay",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(
                v,
                &format!("{at}.{f}"),
                "MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions",
                f,
            )?;
        }
    }
    if let Some(v) = obj.get("routing_mark") {
        check_routing_mark(v, &format!("{at}.routing_mark"))?;
    }
    if let Some(v) = obj.get("domain_resolver") {
        match v {
            Value::Array(_) | Value::Number(_) | Value::Bool(_) => {
                return Err(go_field_err(
                    &format!("{at}.domain_resolver"),
                    v,
                    "MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions",
                    "domain_resolver",
                    "option._DomainResolveOptions",
                ));
            }
            _ => {
                domain_resolver_server(v, &format!("{at}.domain_resolver"))?;
            }
        }
    }
    if let Some(tls) = obj.get("tls") {
        match tls {
            Value::Null => {}
            Value::Object(_) => validate_tls_container(tls, &format!("{at}.tls"), false)?,
            other => {
                return Err(go_field_err(
                    &format!("{at}.tls"),
                    other,
                    "MASQUEOutboundOptions.OutboundTLSOptionsContainer",
                    "tls",
                    "option.OutboundTLSOptions",
                ));
            }
        }
    }

    let mut allowed: Vec<&str> = MASQUE_OUT_FIELDS.to_vec();
    allowed.extend(DIALER_OUT_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;
    Ok(())
}

/// `network_list` (Listable[string] at decode): null OK; string validated
/// against tcp/udp; an array of strings/nulls validates element-wise (a null
/// element becomes `""`), any other array shape reports the array kind.
fn check_masque_network_list(value: &Value, at: &str) -> Result<(), String> {
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
            if !items.iter().all(|v| v.is_string() || v.is_null()) {
                return Err(go_field_err(
                    at,
                    value,
                    "MASQUEOutboundOptions",
                    "network_list",
                    "string",
                ));
            }
            for item in items {
                let s = item.as_str().unwrap_or("");
                if s != "tcp" && s != "udp" {
                    return Err(format!("{at}: unknown network: {s}"));
                }
            }
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            "MASQUEOutboundOptions",
            "network_list",
            "string",
        )),
    }
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
            if let Some(port) = obj
                .get("server_port")
                .filter(|p| !p.is_null() && !prunes_value(p))
            {
                check_u16(port).map_err(|m| format!("outbounds[{i}].server_port: {m}"))?;
            }
            validate_outbound(i, ty, tag, obj, &dns_tags)?;
        }
    }

    if let Some(list) = root.get("endpoints") {
        let entries = list.as_array().ok_or_else(|| {
            format!(
                "endpoints: json: cannot unmarshal {} into Go struct field _Options.endpoints of type []option.Endpoint",
                json_kind(list)
            )
        })?;
        // reference: whole config decodes before any endpoint initializes, so
        // decode checks for every endpoint run first, then the initialize pass.
        let mut initialized: Vec<(usize, String)> = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            let obj = entry.as_object().ok_or_else(|| {
                format!(
                    "endpoints[{i}]: json: cannot unmarshal {} into Go struct field _Options.endpoints of type option._Endpoint",
                    json_kind(entry)
                )
            })?;
            let ty = match obj.get("type") {
                None | Some(Value::Null) => "",
                Some(Value::String(s)) => s.as_str(),
                Some(v) => {
                    return Err(format!(
                        "endpoints[{i}].type: json: cannot unmarshal {} into Go struct field _Endpoint.type of type string",
                        json_kind(v)
                    ));
                }
            };
            if ty != "wireguard" {
                return Err(format!("endpoints[{i}]: unknown endpoint type: {ty}"));
            }
            let tag = match obj.get("tag") {
                None | Some(Value::Null) => "",
                Some(Value::String(s)) => s.as_str(),
                Some(v) => {
                    return Err(format!(
                        "endpoints[{i}].tag: json: cannot unmarshal {} into Go struct field _Endpoint.tag of type string",
                        json_kind(v)
                    ));
                }
            };
            if !tag.is_empty() && !outbound_tags.insert(tag) {
                return Err(format!("duplicate outbound/endpoint tag: {tag}"));
            }
            endpoint_decode(i, obj)?;
            initialized.push((i, tag.to_string()));
        }
        for (i, tag) in initialized {
            let obj = entries[i].as_object().expect("validated above");
            endpoint_initialize(i, &tag, obj)?;
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
                    "{at}.server: json: cannot unmarshal {} into Go struct field _DomainResolveOptions.server of type string",
                    json_kind(server)
                )
            })?;
            if server.is_empty() {
                return Err(format!("{at}: empty domain_resolver.server"));
            }
            if let Some(strategy) = map.get("strategy") {
                let strategy = strategy.as_str().ok_or_else(|| {
                    format!(
                        "{at}.strategy: json: cannot unmarshal {} into Go struct field _DomainResolveOptions.strategy of type string",
                        json_kind(strategy)
                    )
                })?;
                if !DOMAIN_STRATEGIES.contains(&strategy) {
                    return Err(format!(
                        "{at}.strategy: unknown domain strategy: {strategy}"
                    ));
                }
            }
            if let Some(timeout) = map.get("timeout") {
                check_duration_field(
                    timeout,
                    &format!("{at}.timeout"),
                    "_DomainResolveOptions",
                    "timeout",
                )?;
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

/// Reference `option.V2RayXHTTPOptions` decode + the sing-box-extended
/// option-layer normalization gates (SPEC 002 / PARAM_MAP): modes, placements,
/// range fields, xmux. Unknown fields reject like the strict JSON decoder;
/// `uplink_http_method: GET` outside packet-up is the lx soft fallback (WARN
/// at runtime, accepted at check).
fn validate_xhttp_transport(t: &Map<String, Value>, at: &str) -> Result<(), String> {
    const KNOWN: &[&str] = &[
        "type",
        "host",
        "path",
        "mode",
        "headers",
        "x_padding_bytes",
        "xmux",
        "no_grpc_header",
        "session_placement",
        "session_key",
        "seq_placement",
        "seq_key",
        "session_table",
        "session_length",
        "uplink_data_placement",
        "uplink_data_key",
        "uplink_chunk_size",
        "uplink_http_method",
        "x_padding_obfs_mode",
        "x_padding_key",
        "x_padding_header",
        "x_padding_placement",
        "x_padding_method",
        "sc_max_each_post_bytes",
        "sc_min_posts_interval_ms",
        "sc_max_concurrent_posts",
        "server_max_header_bytes",
        "no_sse_header",
        "sc_max_buffered_posts",
        "sc_stream_up_server_secs",
    ];
    for k in t.keys() {
        if !KNOWN.contains(&k.as_str()) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    let mode = t.get("mode").and_then(Value::as_str).unwrap_or("");
    match mode {
        "" | "auto" | "packet-up" | "stream-up" | "stream-one" => {}
        other => return Err(format!("v2ray-xhttp: unknown mode: {other}")),
    }
    for f in [
        "host",
        "path",
        "session_placement",
        "session_key",
        "seq_placement",
        "seq_key",
        "session_table",
        "session_length",
        "uplink_data_placement",
        "uplink_data_key",
        "uplink_chunk_size",
        "uplink_http_method",
        "x_padding_bytes",
        "x_padding_key",
        "x_padding_header",
        "x_padding_placement",
        "x_padding_method",
        "sc_max_each_post_bytes",
        "sc_min_posts_interval_ms",
        "sc_stream_up_server_secs",
    ] {
        if let Some(v) = t.get(f)
            && !v.is_string()
            && !v.is_null()
        {
            return Err(format!(
                "{at}.{f}: json: cannot unmarshal {} into string",
                json_kind(v)
            ));
        }
    }
    for f in ["no_grpc_header", "x_padding_obfs_mode", "no_sse_header"] {
        if let Some(v) = t.get(f)
            && !v.is_boolean()
            && !v.is_null()
        {
            return Err(format!(
                "{at}.{f}: json: cannot unmarshal {} into bool",
                json_kind(v)
            ));
        }
    }
    for f in [
        "sc_max_concurrent_posts",
        "server_max_header_bytes",
        "sc_max_buffered_posts",
    ] {
        if let Some(v) = t.get(f)
            && !v.is_number()
            && !v.is_null()
        {
            return Err(format!(
                "{at}.{f}: json: cannot unmarshal {} into int",
                json_kind(v)
            ));
        }
    }
    for (f, allowed, label) in [
        (
            "session_placement",
            &["path", "query", "header", "cookie"][..],
            "session placement",
        ),
        (
            "seq_placement",
            &["path", "query", "header", "cookie"][..],
            "seq placement",
        ),
        (
            "uplink_data_placement",
            &["body", "auto", "header", "cookie"][..],
            "uplink data placement",
        ),
        (
            "x_padding_placement",
            &["cookie", "header", "query", "queryInHeader"][..],
            "x padding placement",
        ),
        (
            "x_padding_method",
            &["repeat-x", "tokenish"][..],
            "x padding method",
        ),
    ] {
        if let Some(v) = t.get(f).and_then(Value::as_str)
            && !v.is_empty()
            && !allowed.contains(&v)
        {
            return Err(format!("v2ray-xhttp: unsupported {label}: {v}"));
        }
    }
    // header/cookie uplink payload is a packet-up-only shape (hard gate).
    let uplink = t
        .get("uplink_data_placement")
        .and_then(Value::as_str)
        .unwrap_or("");
    if matches!(uplink, "header" | "cookie") && mode != "packet-up" {
        return Err(format!(
            "v2ray-xhttp: uplink_data_placement can be {uplink} only in packet-up mode"
        ));
    }
    // Ranged string fields: "N" | "N-M", N <= M.
    for f in [
        "x_padding_bytes",
        "session_length",
        "uplink_chunk_size",
        "sc_max_each_post_bytes",
        "sc_min_posts_interval_ms",
        "sc_stream_up_server_secs",
    ] {
        if let Some(v) = t.get(f).and_then(Value::as_str)
            && !v.is_empty()
        {
            let parts: Vec<&str> = v.split('-').collect();
            if parts.len() > 2 {
                return Err(format!(
                    "{at}.{f}: invalid range \"{v}\": expected int or \"min-max\""
                ));
            }
            let parse = |s: &str| -> Result<i64, String> {
                s.trim().parse::<i64>().map_err(|_| {
                    format!("{at}.{f}: invalid range \"{v}\": parse \"{s}\": invalid syntax")
                })
            };
            let lo = parse(parts[0])?;
            let hi = if parts.len() == 2 {
                parse(parts[1])?
            } else {
                lo
            };
            if hi < lo {
                return Err(format!(
                    "{at}.{f}: invalid range \"{v}\": range start > end"
                ));
            }
        }
    }
    // session id space: table required with a nonzero length; space >= 2^31.
    let table = t
        .get("session_table")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let length = t
        .get("session_length")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !table.is_empty() || !length.is_empty() {
        if table.is_empty() {
            return Err(format!(
                "{at}.session_table: required when session_length is set"
            ));
        }
        let lo = length
            .split('-')
            .next()
            .unwrap_or("0")
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{at}.session_length: invalid range \"{length}\""))?;
        if lo == 0 {
            return Err(format!("{at}.session_length: must be above 0"));
        }
        // id space: len(table)^min >= 2^31
        let space = (table.chars().count() as u64).saturating_pow(lo.min(63) as u32);
        if space < (1u64 << 31) {
            return Err(format!(
                "{at}.session_length: session id space {space} is too small (want >= 2^31)"
            ));
        }
    }
    // xmux
    if let Some(xmux) = t.get("xmux") {
        let Some(xmux) = xmux.as_object() else {
            return Err(format!("{at}.xmux: must be a JSON object"));
        };
        for k in xmux.keys() {
            if ![
                "max_concurrency",
                "max_connections",
                "c_max_reuse_times",
                "h_max_request_times",
                "h_max_reusable_secs",
                "h_keep_alive_period",
            ]
            .contains(&k.as_str())
            {
                return Err(format!("{at}.xmux.{k}: json: unknown field \"{k}\""));
            }
        }
        let has = |f: &str| xmux.get(f).is_some_and(|v| !v.is_null());
        if has("max_concurrency") && has("max_connections") {
            return Err(format!(
                "{at}.xmux: max_concurrency and max_connections are mutually exclusive"
            ));
        }
        for f in [
            "max_concurrency",
            "max_connections",
            "c_max_reuse_times",
            "h_max_request_times",
            "h_max_reusable_secs",
        ] {
            match xmux.get(f) {
                None | Some(Value::Null) => {}
                Some(Value::Number(_)) => {}
                Some(Value::String(s)) => {
                    let parts: Vec<&str> = s.split('-').collect();
                    if parts.len() > 2 {
                        return Err(format!(
                            "{at}.xmux.{f}: invalid range \"{s}\": expected int or \"min-max\""
                        ));
                    }
                }
                Some(Value::Array(items)) => {
                    if items.len() != 2 || items.iter().any(|v| !v.is_number()) {
                        return Err(format!("{at}.xmux.{f}: range array must be [min, max]"));
                    }
                }
                Some(other) => {
                    return Err(format!(
                        "{at}.xmux.{f}: json: cannot unmarshal {} into range",
                        json_kind(other)
                    ));
                }
            }
        }
        if let Some(v) = xmux.get("h_keep_alive_period")
            && !v.is_number()
            && !v.is_null()
        {
            return Err(format!(
                "{at}.xmux.h_keep_alive_period: json: cannot unmarshal {} into int",
                json_kind(v)
            ));
        }
    }
    Ok(())
}

/// VLESS `encryption` spec (SPEC 032): parse + padding validation mirror the
/// reference client setup, so a malformed string fails at check time.
fn validate_vless_encryption(obj: &Map<String, Value>) -> Result<(), String> {
    let Some(enc) = obj.get("encryption").and_then(Value::as_str) else {
        return Ok(());
    };
    if enc.is_empty() || enc == "none" {
        return Ok(());
    }
    let spec = crate::vless_enc::parse_client_encryption(enc)
        .map_err(|e| format!("parse encryption: {e}"))?;
    crate::vless_enc::parse_padding(&spec.padding)
        .map_err(|e| format!("initialize encryption: {e}"))?;
    Ok(())
}

fn validate_anytls_out_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    // reference stage-2 prune runs deep: empty containers behave as absent.
    let pruned =
        deep_prune(&Value::Object(obj.clone())).unwrap_or_else(|| Value::Object(Map::new()));
    let Some(pruned) = pruned.as_object() else {
        return Ok(());
    };
    let obj = pruned;
    const ABS: &str = "AnyTLSOutboundOptions.DialerOptions.AbstractDialerOptions";

    // Field checks run before the unknown-field pass (fixed order matches the
    // observed reference probes better than the BTreeMap alphabetical walk).
    if let Some(v) = obj.get("detour") {
        ep_str(
            v,
            &format!("{at}.detour"),
            "AnyTLSOutboundOptions.DialerOptions",
            "detour",
        )?;
    }
    for f in [
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "protect_path",
        "netns",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), ABS, f)?;
        }
    }
    for f in [
        "bind_address_no_port",
        "tcp_fast_open",
        "tcp_multi_path",
        "disable_tcp_keep_alive",
        "udp_fragment",
        "reuse_addr",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), ABS, f)?;
        }
    }
    for f in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "fallback_delay",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), ABS, f)?;
        }
    }
    if let Some(v) = obj.get("routing_mark") {
        check_routing_mark(v, &format!("{at}.routing_mark"))?;
    }
    if let Some(v) = obj.get("domain_resolver") {
        match v {
            Value::Array(_) | Value::Number(_) | Value::Bool(_) => {
                return Err(go_field_err(
                    &format!("{at}.domain_resolver"),
                    v,
                    ABS,
                    "domain_resolver",
                    "option._DomainResolveOptions",
                ));
            }
            _ => {
                domain_resolver_server(v, &format!("{at}.domain_resolver"))?;
            }
        }
    }
    if let Some(v) = obj.get("network_strategy") {
        match v {
            Value::Null => {}
            Value::String(s) if matches!(s.as_str(), "default" | "fallback" | "hybrid") => {}
            Value::String(s) => {
                return Err(format!(
                    "{at}.network_strategy: unknown network strategy: {s}"
                ));
            }
            other => {
                return Err(go_field_err(
                    &format!("{at}.network_strategy"),
                    other,
                    ABS,
                    "network_strategy",
                    "string",
                ));
            }
        }
    }
    for f in ["network_type", "fallback_network_type"] {
        if let Some(v) = obj.get(f) {
            check_interface_types(v, &format!("{at}.{f}"))?;
        }
    }
    if let Some(v) = obj.get("domain_strategy") {
        match v {
            Value::Null => {}
            Value::String(s) if DOMAIN_STRATEGIES.contains(&s.as_str()) => {}
            Value::String(s) => {
                return Err(format!(
                    "{at}.domain_strategy: unknown domain strategy: {s}"
                ));
            }
            other => {
                return Err(go_field_err(
                    &format!("{at}.domain_strategy"),
                    other,
                    ABS,
                    "domain_strategy",
                    "string",
                ));
            }
        }
    }
    if let Some(v) = obj.get("server") {
        ep_str(
            v,
            &format!("{at}.server"),
            "AnyTLSOutboundOptions.ServerOptions",
            "server",
        )?;
    }
    if let Some(v) = obj.get("tls") {
        match v {
            Value::Null => {}
            Value::Object(_) => validate_tls_container(v, &format!("{at}.tls"), false)?,
            other => {
                return Err(go_field_err(
                    &format!("{at}.tls"),
                    other,
                    "AnyTLSOutboundOptions.OutboundTLSOptionsContainer",
                    "tls",
                    "option.OutboundTLSOptions",
                ));
            }
        }
    }
    if let Some(v) = obj.get("password") {
        ep_str(
            v,
            &format!("{at}.password"),
            "AnyTLSOutboundOptions",
            "password",
        )?;
    }
    for f in ["idle_session_check_interval", "idle_session_timeout"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), "AnyTLSOutboundOptions", f)?;
        }
    }
    if let Some(v) = obj.get("min_idle_session") {
        check_min_idle_session(v, &format!("{at}.min_idle_session"))?;
    }
    if let Some(v) = obj.get("client_metadata") {
        ep_str(
            v,
            &format!("{at}.client_metadata"),
            "AnyTLSOutboundOptions",
            "client_metadata",
        )?;
    }

    let mut allowed: Vec<&str> = ANYTLS_OUT_FIELDS.to_vec();
    allowed.extend(DIALER_OUT_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;
    Ok(())
}

/// `min_idle_session`: pointer-like int — null/empty containers ok; integral
/// numbers in Go `int` range ok; everything else reports the float64 rendering
/// of the literal (reference custom unmarshal decodes through float64).
fn check_min_idle_session(value: &Value, at: &str) -> Result<(), String> {
    const GS: &str = "AnyTLSOutboundOptions";
    match value {
        Value::Null => Ok(()),
        Value::Number(n) => {
            let ok = n.as_f64().is_some_and(|f| {
                f.fract() == 0.0 && (-9223372036854775808.0..9223372036854775808.0).contains(&f)
            });
            if ok {
                Ok(())
            } else {
                let literal = n
                    .as_f64()
                    .map_or_else(|| go_number_literal(value), |f| format!("{f}"));
                Err(format!(
                    "{at}: json: cannot unmarshal number {literal} into Go struct field {GS}.min_idle_session of type int"
                ))
            }
        }
        other => Err(go_field_err(at, other, GS, "min_idle_session", "int")),
    }
}

/// reference `common/tls.NewClientWithOptions` for the anytls outbound:
/// engine dispatch → reality/utls/std client construction checks.
fn validate_tls_client_init(obj: &Map<String, Value>, at: &str) -> Result<(), String> {
    let tls = obj.get("tls").and_then(Value::as_object);
    let get = |k: &str| tls.and_then(|m| m.get(k));

    let engine = get("engine").and_then(Value::as_str).unwrap_or("");
    match engine {
        "" | "go" => {}
        "apple" => {
            if !cfg!(target_os = "macos") {
                return Err(format!(
                    "{at}: Apple TLS engine is not available on non-Apple platforms"
                ));
            }
        }
        "windows" => {
            if !cfg!(windows) {
                return Err(format!(
                    "{at}: Windows TLS engine is not available on non-Windows platforms"
                ));
            }
        }
        other => return Err(format!("{at}: unknown tls engine: {other}")),
    }

    let server = obj.get("server").and_then(Value::as_str).unwrap_or("");
    let server_name = get("server_name").and_then(Value::as_str).unwrap_or("");
    let sni = if server_name.is_empty() {
        server
    } else {
        server_name
    };
    let insecure = get("insecure").and_then(Value::as_bool).unwrap_or(false);
    let disable_sni = get("disable_sni").and_then(Value::as_bool).unwrap_or(false);
    let spoof = get("spoof").and_then(Value::as_str).unwrap_or("");
    let method = get("spoof_method").and_then(Value::as_str).unwrap_or("");
    let reality_on = get("reality")
        .and_then(Value::as_object)
        .is_some_and(|m| m.get("enabled").and_then(Value::as_bool) == Some(true));
    let utls_on = get("utls")
        .and_then(Value::as_object)
        .is_some_and(|m| m.get("enabled").and_then(Value::as_bool) == Some(true));

    if reality_on {
        if !utls_on {
            return Err(format!("{at}: uTLS is required by reality client"));
        }
        if !spoof.is_empty() || !method.is_empty() {
            return Err(format!("{at}: spoof is unsupported in reality"));
        }
    }

    // shared checks (std/utls/reality clients share this order)
    if sni.is_empty() && !insecure {
        return Err(format!("{at}: missing server_name or insecure=true"));
    }
    if !insecure && disable_sni && reality_on {
        return Err(format!("{at}: disable_sni is unsupported in reality"));
    }

    let cert_inline = tls_listable_join(get("certificate"));
    let cert_path = get("certificate_path")
        .and_then(Value::as_str)
        .unwrap_or("");
    let sha_present = match get("certificate_public_key_sha256") {
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        _ => false,
    };
    if sha_present && (!cert_inline.is_empty() || !cert_path.is_empty()) {
        return Err(format!(
            "{at}: certificate_public_key_sha256 is conflict with certificate or certificate_path"
        ));
    }

    for field in ["min_version", "max_version"] {
        let v = get(field).and_then(Value::as_str).unwrap_or("");
        if !v.is_empty() && !TLS_VERSIONS.contains(&v) {
            return Err(format!("{at}: parse {field}: unknown tls version:{v}"));
        }
    }
    if let Some(ciphers) = get("cipher_suites").and_then(Value::as_array) {
        for c in ciphers {
            let name = c.as_str().unwrap_or("");
            if !TLS_CIPHER_SUITES.contains(&name) {
                return Err(format!("{at}: unknown cipher_suite: {name}"));
            }
        }
    }

    let mut cert_content = cert_inline;
    if cert_content.is_empty() && !cert_path.is_empty() {
        cert_content = go_read_file(cert_path)
            .map_err(|e| format!("{at}: read certificate: open {cert_path}: {e}"))?;
    }
    if !cert_content.is_empty() && !cert_content.contains("-----BEGIN CERTIFICATE-----") {
        return Err(format!(
            "{at}: failed to parse certificate:\n\n{cert_content}"
        ));
    }

    let client_cert = tls_listable_join(get("client_certificate"));
    let client_cert = if !client_cert.is_empty() {
        client_cert
    } else {
        let p = get("client_certificate_path")
            .and_then(Value::as_str)
            .unwrap_or("");
        if p.is_empty() {
            String::new()
        } else {
            go_read_file(p).map_err(|e| format!("{at}: read client certificate: open {p}: {e}"))?
        }
    };
    let client_key = tls_listable_join(get("client_key"));
    let client_key = if !client_key.is_empty() {
        client_key
    } else {
        let p = get("client_key_path").and_then(Value::as_str).unwrap_or("");
        if p.is_empty() {
            String::new()
        } else {
            go_read_file(p).map_err(|e| format!("{at}: read client key: open {p}: {e}"))?
        }
    };
    if !client_cert.is_empty() && !client_key.is_empty() {
        // reference parses the x509 key pair here; parse failures are
        // unprobed — accept and continue.
    } else if !client_cert.is_empty() || !client_key.is_empty() {
        return Err(format!(
            "{at}: client certificate and client key must be provided together"
        ));
    }

    // reference parseTLSSpoofOptions
    if spoof.is_empty() {
        if !method.is_empty() {
            return Err(format!("{at}: spoof_method requires spoof"));
        }
    } else {
        if !SPOOF_METHODS.contains(&method) {
            return Err(format!("{at}: tls_spoof: unknown method: {method}"));
        }
        if disable_sni || sni.is_empty() || crate::netip_parse::parse_addr(sni).is_ok() {
            return Err(format!("{at}: `spoof` requires TLS ClientHello with SNI"));
        }
        if spoof.eq_ignore_ascii_case(sni) {
            return Err(format!("{at}: `spoof` must differ from `server_name`"));
        }
    }

    if utls_on {
        let fingerprint = get("utls")
            .and_then(Value::as_object)
            .and_then(|m| m.get("fingerprint"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !fingerprint.is_empty() && !UTLS_FINGERPRINTS.contains(&fingerprint) {
            return Err(format!("{at}: unknown uTLS fingerprint: {fingerprint}"));
        }
        let ech_on = get("ech")
            .and_then(Value::as_object)
            .is_some_and(|m| m.get("enabled").and_then(Value::as_bool) == Some(true));
        if ech_on && reality_on {
            return Err(format!("{at}: Reality is conflict with ECH"));
        }
    }

    let kernel_tx = get("kernel_tx").and_then(Value::as_bool).unwrap_or(false);
    let kernel_rx = get("kernel_rx").and_then(Value::as_bool).unwrap_or(false);
    if (kernel_tx || kernel_rx) && !reality_on && !cfg!(target_os = "linux") {
        return Err(format!("{at}: kTLS is only supported on Linux"));
    }

    if reality_on {
        // reference newRealityClient: public_key → short_id → key_share → kTLS
        let reality = get("reality").and_then(Value::as_object).unwrap();
        let pk = reality
            .get("public_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(idx) = go_b64_rawurl_error_index(pk) {
            return Err(format!(
                "{at}: decode public_key: illegal base64 data at input byte {idx}"
            ));
        }
        if go_b64_rawurl_decoded_len(pk) != 32 {
            return Err(format!("{at}: invalid public_key"));
        }
        let short_id = reality
            .get("short_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        check_short_id(short_id).map_err(|m| format!("{at}: {m}"))?;
        let key_share = reality
            .get("key_share")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !matches!(key_share, "" | "hybrid" | "classical") {
            return Err(format!(
                "{at}: unknown reality key_share: {key_share} (expected \"hybrid\" or \"classical\")"
            ));
        }
        if (kernel_tx || kernel_rx) && !cfg!(target_os = "linux") {
            return Err(format!("{at}: kTLS is only supported on Linux"));
        }
    }

    Ok(())
}

/// Listable[string] → joined content (reference `strings.Join(list, "\n")`).
fn tls_listable_join(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// reference `filemanager.ReadFile` error suffix for missing paths.
fn go_read_file(path: &str) -> Result<String, String> {
    std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|_| {
            if cfg!(windows) {
                "The system cannot find the path specified.".to_string()
            } else {
                "no such file or directory".to_string()
            }
        })
}

fn validate_outbound(
    i: usize,
    ty: &str,
    tag: &str,
    obj: &Map<String, Value>,
    dns_tags: &HashSet<String>,
) -> Result<(), String> {
    let at = format!("initialize outbound[{i}] {ty}[{tag}]");

    match ty {
        "hysteria2" => validate_hy2_out_decode(i, obj)?,
        "tuic" => validate_tuic_out_decode(i, obj)?,
        "masque" => validate_masque_out_decode(i, obj)?,
        "anytls" => validate_anytls_out_decode(i, obj)?,
        "vless" => validate_vless_encryption(obj)?,
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
        if transport_ty == "xhttp" {
            validate_xhttp_transport(transport, &format!("outbounds[{i}].transport"))?;
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
        "anytls" => {
            // reference protocol/anytls NewOutbound: TLS required → tfo →
            // NewClientWithOptions (TLS client checks) → dialer setup.
            if obj.get("tcp_fast_open").and_then(Value::as_bool) == Some(true) {
                return Err(format!(
                    "{at}: tcp_fast_open is not supported with anytls outbound"
                ));
            }
            validate_tls_client_init(obj, &at)?;
            // reference dialer: a domain server resolves through the
            // configured domain_resolver tag at initialize.
            let server = obj.get("server").and_then(Value::as_str).unwrap_or("");
            if !server.is_empty()
                && crate::netip_parse::parse_addr(server).is_err()
                && let Some(dr) = obj.get("domain_resolver")
                && !prunes_value(dr)
            {
                let tag = domain_resolver_server(dr, &format!("outbounds[{i}].domain_resolver"))?;
                if let Some(tag) = tag
                    && !tag.is_empty()
                    && !dns_tags.contains(&tag)
                {
                    return Err(format!("{at}: domain resolver not found: {tag}"));
                }
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
            // reference NewOutbound: ParseProfile → resolveLegacyOptions →
            // uri → resolveVHTTP → parsePrefixes → keys → key parse → mtu.
            let profile_name = obj.get("profile").and_then(Value::as_str).unwrap_or("");
            let pin = matches!(profile_name, "" | "cloudflare");
            let default_uri = if pin {
                "https://cloudflareaccess.com"
            } else {
                ""
            };
            if !pin && profile_name != "standard" {
                return Err(format!("{at}: masque: unknown profile: {profile_name}"));
            }

            let legacy_network = obj.get("network").and_then(Value::as_str).unwrap_or("");
            let mut vhttp = obj.get("vhttp").and_then(Value::as_str).unwrap_or("");
            if !legacy_network.is_empty() {
                if !vhttp.is_empty() && vhttp != legacy_network {
                    return Err(format!(
                        "{at}: masque: `vhttp` is {vhttp} but deprecated `network` is {legacy_network} — remove `network`"
                    ));
                }
                if vhttp.is_empty() {
                    vhttp = legacy_network;
                }
            }

            let tls_obj = obj.get("tls").and_then(Value::as_object);
            let tls_server_name = tls_obj
                .and_then(|m| m.get("server_name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let legacy_sni = obj.get("sni").and_then(Value::as_str).unwrap_or("");
            if !legacy_sni.is_empty()
                && !tls_server_name.is_empty()
                && tls_server_name != legacy_sni
            {
                return Err(format!(
                    "{at}: masque: `tls.server_name` is {tls_server_name} but deprecated `sni` is {legacy_sni} — remove `sni`"
                ));
            }

            let legacy_ffd = obj
                .get("fragment_fallback_delay")
                .and_then(Value::as_str)
                .unwrap_or("");
            if go_duration_ns(legacy_ffd).unwrap_or(0) != 0 {
                let tls_ffd = tls_obj
                    .and_then(|m| m.get("fragment_fallback_delay"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if go_duration_ns(tls_ffd).unwrap_or(0) != 0
                    && go_duration_ns(tls_ffd) != go_duration_ns(legacy_ffd)
                {
                    return Err(format!(
                        "{at}: masque: `tls.fragment_fallback_delay` and deprecated `fragment_fallback_delay` disagree — remove the latter"
                    ));
                }
            }

            let mut uri = obj.get("uri").and_then(Value::as_str).unwrap_or("");
            if uri.is_empty() {
                uri = default_uri;
            }
            if uri.is_empty() {
                return Err(format!(
                    "{at}: masque: uri is required for the standard profile — set it to the server's CONNECT-IP request URI, e.g. https://<host>/.well-known/masque/ip/*/*/"
                ));
            }

            let mut network = vhttp;
            if network.is_empty() {
                network = "auto";
            }
            if network != "h3" && network != "h2" && network != "auto" {
                return Err(format!(
                    "{at}: masque: invalid vhttp: {network} (expected h3, h2 or auto)"
                ));
            }
            let mut auto_mode = network == "auto";
            if auto_mode && profile_name == "standard" {
                auto_mode = false;
                network = "h3";
            }
            if auto_mode {
                network = "h3";
            }
            if network == "h2" && profile_name == "standard" {
                return Err(format!(
                    "{at}: masque: vhttp h2 is not implemented for the standard profile"
                ));
            }

            let ip = obj.get("ip").and_then(Value::as_str).unwrap_or("");
            let ipv6 = obj.get("ipv6").and_then(Value::as_str).unwrap_or("");
            if !ip.is_empty()
                && let Err(e) = crate::netip_parse::check_masque_prefix(ip, false)
            {
                return Err(format!("{at}: parse ip: {e}"));
            }
            if !ipv6.is_empty()
                && let Err(e) = crate::netip_parse::check_masque_prefix(ipv6, true)
            {
                return Err(format!("{at}: parse ipv6: {e}"));
            }
            if ip.is_empty() && ipv6.is_empty() {
                return Err(format!("{at}: masque: at least one of ip/ipv6 is required"));
            }

            let priv_key = obj.get("private_key").and_then(Value::as_str).unwrap_or("");
            let pub_key = obj.get("public_key").and_then(Value::as_str).unwrap_or("");
            if pin && (priv_key.is_empty() || pub_key.is_empty()) {
                return Err(format!(
                    "{at}: masque: private_key and public_key are required for the cloudflare profile"
                ));
            }
            if !priv_key.is_empty() {
                if let Some(idx) = go_b64_check(priv_key) {
                    return Err(format!(
                        "{at}: parse private_key: illegal base64 data at input byte {idx}"
                    ));
                }
                let der = decode_base64_std(priv_key).unwrap_or_default();
                if let Err(e) = crate::asn1_x509::parse_ec_private(&der) {
                    return Err(format!("{at}: parse private_key: {e}"));
                }
            }
            if !pub_key.is_empty() {
                if let Some(idx) = go_b64_check(pub_key) {
                    return Err(format!(
                        "{at}: parse public_key: illegal base64 data at input byte {idx}"
                    ));
                }
                let der = decode_base64_std(pub_key).unwrap_or_default();
                match crate::asn1_x509::parse_pkix_public(&der) {
                    Ok(crate::asn1_x509::PubKey::Ecdsa) => {}
                    Ok(crate::asn1_x509::PubKey::NotEcdsa) => {
                        return Err(format!(
                            "{at}: parse public_key: public_key is not an ECDSA key"
                        ));
                    }
                    Err(e) => return Err(format!("{at}: parse public_key: {e}")),
                }
            }

            let mtu = obj
                .get("mtu")
                .and_then(Value::as_u64)
                .filter(|m| *m != 0)
                .unwrap_or(1280);
            if (network == "h2" || auto_mode) && mtu > 16000 {
                return Err(format!(
                    "{at}: masque: mtu {mtu} too large for h2 (max 16000)"
                ));
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

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "bool",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Null => "null",
    }
}

/// The reference decoder treats a bare `{}` as a zero value for any field
/// (observed for peers, address elements, detour) but rejects non-empty
/// objects against scalar/slice targets. `null` is a no-op everywhere.
fn is_zero_json(value: &Value) -> bool {
    value.is_null() || matches!(value, Value::Object(map) if map.is_empty())
}

/// reference stage-2 prune: a value decodes to nothing when it is an object
/// whose children all prune, or an array whose elements all prune (empty
/// containers included). Scalars and null survive.
fn prunes_value(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.values().all(prunes_value),
        Value::Array(items) => items.iter().all(prunes_value),
        _ => false,
    }
}

/// reference stage-2 prune, applied recursively: drop every prunable child,
/// then re-evaluate the parent (a container whose children all prune prunes
/// itself). `null` and scalars survive; returns `None` when the subtree prunes.
fn deep_prune(value: &Value) -> Option<Value> {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if let Some(v) = deep_prune(v) {
                    out.insert(k.clone(), v);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(Value::Object(out))
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                if let Some(v) = deep_prune(v) {
                    out.push(v);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(Value::Array(out))
            }
        }
        other => Some(other.clone()),
    }
}

/// Go `json: cannot unmarshal <kind> into Go struct field <gs>.<f> of type <ty>`.
fn go_field_err(at: &str, value: &Value, go_struct: &str, field: &str, ty: &str) -> String {
    format!(
        "{at}: json: cannot unmarshal {} into Go struct field {go_struct}.{field} of type {ty}",
        json_kind(value)
    )
}

/// string-typed struct field: null/empty-object OK.
fn ep_str(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        Value::String(_) => Ok(()),
        v if is_zero_json(v) => Ok(()),
        other => Err(go_field_err(at, other, go_struct, field, "string")),
    }
}

/// bool-typed struct field: null/empty-object OK.
fn ep_bool(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        Value::Bool(_) => Ok(()),
        v if is_zero_json(v) => Ok(()),
        other => Err(go_field_err(at, other, go_struct, field, "bool")),
    }
}

/// Go number literal rendering for error messages (`4.5`, `4294967296`).
fn go_number_literal(value: &Value) -> String {
    value.to_string()
}

/// unsigned integer struct field (uint16/uint32): in-range numbers OK,
/// out-of-range/fractional numbers carry the literal (`number 4.5`).
fn ep_unsigned(
    value: &Value,
    at: &str,
    go_struct: &str,
    field: &str,
    max: u64,
) -> Result<(), String> {
    let ty = if max == u64::from(u32::MAX) {
        "uint32"
    } else {
        "uint16"
    };
    match value {
        v if is_zero_json(v) => Ok(()),
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= max => Ok(()),
            _ => Err(format!(
                "{at}: json: cannot unmarshal number {} into Go struct field {go_struct}.{field} of type {ty}",
                go_number_literal(value)
            )),
        },
        other => Err(go_field_err(at, other, go_struct, field, ty)),
    }
}

/// int-typed struct field (Go int): any integer OK, floats carry the literal.
fn ep_int(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        v if is_zero_json(v) => Ok(()),
        Value::Number(n) => match n.as_i64() {
            Some(_) => Ok(()),
            None => Err(format!(
                "{at}: json: cannot unmarshal number {} into Go struct field {go_struct}.{field} of type int",
                go_number_literal(value)
            )),
        },
        other => Err(go_field_err(at, other, go_struct, field, "int")),
    }
}

/// Go `strconv.ParseUint` error text (`strconv.ParseUint: parsing "x": ...`).
fn go_parse_uint_err(s: &str, bit_size: u32) -> String {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return format!("strconv.ParseUint: parsing {s:?}: invalid syntax");
    }
    match s.parse::<u128>() {
        Ok(n) if n <= go_uint_max(bit_size) => String::new(),
        _ => format!("strconv.ParseUint: parsing {s:?}: value out of range"),
    }
}

fn go_uint_max(bit_size: u32) -> u128 {
    if bit_size >= 128 {
        u128::MAX
    } else {
        (1u128 << bit_size) - 1
    }
}

/// `routing_mark` custom unmarshaller: number or numeric string; everything
/// else reports the first (string) unmarshal error under the wrapper.
fn check_routing_mark(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null => Err(format!(
            "{at}: strconv.ParseUint: parsing \"\": invalid syntax"
        )),
        v if is_zero_json(v) => Ok(()),
        Value::String(s) => {
            let err = go_parse_uint_err(s, 32);
            if err.is_empty() {
                Ok(())
            } else {
                Err(format!("{at}: {err}"))
            }
        }
        Value::Number(n) => match n.as_u64() {
            Some(_) => Ok(()),
            None => Err(format!(
                "{at}: invalid number or string mark: json: cannot unmarshal number into Go value of type string"
            )),
        },
        other => Err(format!(
            "{at}: invalid number or string mark: json: cannot unmarshal {} into Go value of type string",
            json_kind(other)
        )),
    }
}

/// Go base64 StdEncoding first-error index (mirrors `illegal base64 data at
/// input byte N`): first non-alphabet byte, broken padding, or a lone
/// trailing char (`len % 4 == 1` reports `len - 1`).
fn go_b64_error_index(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let is_b64 = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    let mut i = 0;
    while i < b.len() && is_b64(b[i]) {
        i += 1;
    }
    if i < b.len() && b[i] != b'=' {
        return Some(i);
    }
    let pad_start = i;
    while i < b.len() && b[i] == b'=' {
        i += 1;
    }
    if i < b.len() {
        return Some(i);
    }
    let pad = b.len() - pad_start;
    if pad > 0 {
        if pad > 2 || !b.len().is_multiple_of(4) || pad_start % 4 != (4 - pad) % 4 {
            return Some(pad_start);
        }
        return None;
    }
    match b.len() % 4 {
        0 => None,
        1 => Some(b.len() - 1),
        2 => Some(b.len() - 2),
        _ => Some(b.len() - 3),
    }
}

/// base64 decode for endpoint keys: `None` = valid, `Some(idx)` = Go error index.
fn go_b64_check(s: &str) -> Option<usize> {
    go_b64_error_index(s)
}

/// Go `base64.RawURLEncoding` first-error index: URL alphabet without
/// padding; `len % 4 == 1` is rejected at the trailing byte.
fn go_b64_rawurl_error_index(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let is_rawurl = |c: u8| c.is_ascii_alphanumeric() || c == b'-' || c == b'_';
    if let Some(i) = b.iter().position(|c| !is_rawurl(*c)) {
        return Some(i);
    }
    if b.len() % 4 == 1 {
        return Some(b.len() - 1);
    }
    None
}

/// decoded length of a valid RawURL base64 string.
fn go_b64_rawurl_decoded_len(s: &str) -> usize {
    match s.len() % 4 {
        2 => s.len() / 4 * 3 + 1,
        3 => s.len() / 4 * 3 + 2,
        _ => s.len() / 4 * 3,
    }
}

/// reference `option.AWGRange` decode (`normalizeAWGRange`): canonical
/// `"N"` / `"N-M"` string, `""` when unset. Errors mirror
/// `AWGRange.UnmarshalJSON` / `normalizeAWGRange`.
fn awg_normalize_range(spec: &str) -> Result<String, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() > 2 {
        return Err(format!(
            "invalid range {:?}: expected uint32 or \"min-max\"",
            trimmed
        ));
    }
    let start_s = parts[0].trim();
    let start = match parse_go_u32(start_s) {
        Some(n) => n,
        None => return Err(awg_parse_err(trimmed, parts[0], start_s)),
    };
    let end = if parts.len() == 2 {
        let end_s = parts[1].trim();
        match parse_go_u32(end_s) {
            Some(n) => n,
            None => return Err(awg_parse_err(trimmed, parts[1], end_s)),
        }
    } else {
        start
    };
    if end < start {
        return Err(format!("invalid range {trimmed:?}: range start > end"));
    }
    if end == 0 {
        return Ok(String::new());
    }
    if start == end {
        return Ok(start.to_string());
    }
    Ok(format!("{start}-{end}"))
}

fn awg_parse_err(spec: &str, raw_part: &str, trimmed_part: &str) -> String {
    let reason = if trimmed_part.is_empty() || !trimmed_part.bytes().all(|b| b.is_ascii_digit()) {
        "invalid syntax"
    } else {
        "value out of range"
    };
    format!(
        "invalid range {:?}: parse {:?}: strconv.ParseUint: parsing {:?}: {reason}",
        spec, raw_part, trimmed_part
    )
}

fn parse_go_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// AWGRange-typed field decode: null/empty-object OK, string normalized,
/// in-range number OK; anything else is `invalid range <json>`.
fn check_awg_range(value: &Value, at: &str) -> Result<(), String> {
    match value {
        v if is_zero_json(v) => Ok(()),
        Value::Null => Ok(()),
        Value::String(s) => awg_normalize_range(s)
            .map(drop)
            .map_err(|m| format!("{at}: {m}")),
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= u32::MAX as u64 => Ok(()),
            _ => Err(format!(
                "{at}: invalid range {value}: expected uint32 or \"min-max\" string"
            )),
        },
        other => Err(format!(
            "{at}: invalid range {other}: expected uint32 or \"min-max\" string"
        )),
    }
}

/// canonical form of an AWGRange field (`None` = unset), used by the
/// initialize-time `IsSet` gate. Decode errors are unreachable here.
fn awg_range_canonical(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => awg_normalize_range(s).ok().filter(|c| !c.is_empty()),
        Value::Number(n) => n
            .as_u64()
            .filter(|x| *x != 0 && *x <= u32::MAX as u64)
            .map(|x| x.to_string()),
        v if is_zero_json(v) => None,
        _ => None,
    }
}

/// Go `netip.ParsePrefix` failure reason (without the wrapper).
fn prefix_parse_reason(s: &str) -> Result<(), String> {
    let Some(i) = s.rfind('/') else {
        return Err("no '/'".to_string());
    };
    let addr = &s[..i];
    let bits = &s[i + 1..];
    let is_v4 =
        parse_ip_addr(addr).ok_or_else(|| format!("ParseAddr({addr:?}): unable to parse IP"))?;
    let bit_len: i64 = if is_v4 { 32 } else { 128 };
    let f: i64 = bits
        .parse()
        .map_err(|_| format!("bad bits after slash: {bits:?}"))?;
    if f < 0 || f > bit_len {
        return Err("prefix length out of range".to_string());
    }
    Ok(())
}

/// IPv4/IPv6 literal parser (netip.ParseAddr subset): dotted quad without
/// leading zeros, or colon-hex with at most one `::` and an optional
/// trailing v4 / `%zone`.
fn parse_ip_addr(s: &str) -> Option<bool> {
    let s = s.split('%').next().unwrap_or("");
    if s.is_empty() {
        return None;
    }
    if !s.contains(':') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        for p in &parts {
            if p.is_empty()
                || p.len() > 3
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
                || p.parse::<u16>().ok()? > 255
            {
                return None;
            }
        }
        return Some(true);
    }
    // IPv6: split on "::" (at most once), groups of 1-4 hex digits, optional
    // trailing dotted quad.
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => {
            if t.contains("::") {
                return None;
            }
            (h, Some(t))
        }
        None => (s, None),
    };
    let mut count = split_ipv6_groups(head)?.len();
    if let Some(t) = tail {
        let groups = split_ipv6_groups(t)?;
        if let Some(last) = groups.last() {
            if last.contains('.') {
                // trailing v4 counts as two groups
                if !parse_ip_addr(last)? || groups.len() > 1 {
                    return None;
                }
                count += 2;
            } else {
                count += groups.len();
            }
        }
    }
    if tail.is_none() && count != 8 {
        return None;
    }
    if tail.is_some() && count > 7 {
        return None;
    }
    Some(false)
}

/// one IPv6 "run" (side of `::`): empty or ≥1 groups of 1-4 hex digits.
fn split_ipv6_groups(part: &str) -> Option<Vec<&str>> {
    if part.is_empty() {
        return Some(Vec::new());
    }
    let groups: Vec<&str> = part.split(':').collect();
    for g in &groups {
        if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
    }
    Some(groups)
}

/// `badoption.Listable[netip.Prefix]` decode: returns kept entries where
/// `Zero` marks a `null` element (fails `AddPrefix` at initialize) while a
/// bare `{}` element is dropped. Errors mirror the reference's combined
/// single/list attempt text: `<at>: (<err A> | <err B>)`.
fn check_prefix_list(value: &Value, at: &str) -> Result<Vec<bool>, String> {
    const SINGLE: &str = "json: cannot unmarshal array into Go value of type **netip.Prefix";
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(s) => match prefix_parse_reason(s) {
            Ok(()) => Ok(vec![true]),
            Err(reason) => Err(format!(
                "{at}: (netip.ParsePrefix({s:?}): {reason} | json: cannot unmarshal string into Go value of type []netip.Prefix)"
            )),
        },
        Value::Array(items) => {
            let mut out = Vec::new();
            for (idx, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) => match prefix_parse_reason(s) {
                        Ok(()) => out.push(true),
                        Err(reason) => {
                            return Err(format!(
                                "{at}: ({SINGLE} | netip.ParsePrefix({s:?}): {reason})"
                            ));
                        }
                    },
                    Value::Null => out.push(false),
                    Value::Object(map) if map.is_empty() => {}
                    other => {
                        return Err(format!(
                            "{at}: ({SINGLE} | [{idx}]: json: cannot unmarshal {} into Go value of type netip.Prefix)",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(out)
        }
        Value::Object(map) if map.is_empty() => Ok(Vec::new()),
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type **netip.Prefix | json: cannot unmarshal {kind} into Go value of type []netip.Prefix)"
            ))
        }
    }
}

/// `udp_mapping` / `udp_filtering`: string enum of NAT behaviors.
fn check_udp_nat(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        Value::String(s) if UDP_NAT_BEHAVIORS.contains(&s.as_str()) => Ok(()),
        Value::String(s) => Err(format!("{at}: unknown UDP NAT behavior: {s}")),
        v if is_zero_json(v) => Ok(()),
        other => Err(go_field_err(at, other, go_struct, field, "string")),
    }
}

/// `network_type` / `fallback_network_type`: listable InterfaceType. The
/// reference decodes the toplevel value as a single InterfaceType first, then
/// as a slice (where a plain string goes through the base64 special case for
/// byte-like slices) and reports the union of both failures.
fn check_interface_types(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::String(s) => {
            if INTERFACE_TYPES.contains(&s.as_str()) {
                Ok(())
            } else if go_b64_error_index(s).is_none() {
                // path2: string → []byte base64 special case succeeds
                Ok(())
            } else {
                Err(format!(
                    "{at}: (unknown interface type: {s} | illegal base64 data at input byte {})",
                    go_b64_error_index(s).unwrap_or(0)
                ))
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) if INTERFACE_TYPES.contains(&s.as_str()) => {}
                    Value::String(s) => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: unknown interface type: {s})"
                        ));
                    }
                    // null → UnmarshalJSON(null) → lookup of `""`
                    Value::Null => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: unknown interface type: )"
                        ));
                    }
                    other => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type string | [{i}]: json: cannot unmarshal {} into Go value of type string)",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(())
        }
        v if is_zero_json(v) => Ok(()),
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type string | json: cannot unmarshal {kind} into Go value of type []option.InterfaceType)"
            ))
        }
    }
}

/// reference `option.AmneziaWGOptions` + wireguard root decode checks.
fn endpoint_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_ENDPOINT_FIELDS.contains(&k) && !DIALER_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    const WG: &str = "WireGuardEndpointOptions";
    const AWG: &str = "WireGuardEndpointOptions.AmneziaWGOptions";
    const DIAL: &str = "WireGuardEndpointOptions.DialerOptions";
    const ABS: &str = "WireGuardEndpointOptions.DialerOptions.AbstractDialerOptions";

    if let Some(v) = obj.get("system") {
        ep_bool(v, &format!("{at}.system"), WG, "system")?;
    }
    if let Some(v) = obj.get("name") {
        ep_str(v, &format!("{at}.name"), WG, "name")?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(v, &format!("{at}.mtu"), WG, "mtu", u32::MAX as u64)?;
    }
    if let Some(v) = obj.get("private_key") {
        ep_str(v, &format!("{at}.private_key"), WG, "private_key")?;
    }
    if let Some(v) = obj.get("listen_port") {
        ep_unsigned(
            v,
            &format!("{at}.listen_port"),
            WG,
            "listen_port",
            u16::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("workers") {
        ep_int(v, &format!("{at}.workers"), WG, "workers")?;
    }
    if let Some(v) = obj.get("udp_timeout") {
        check_duration_field(v, &format!("{at}.udp_timeout"), WG, "udp_timeout")?;
    }
    if let Some(v) = obj.get("udp_mapping") {
        check_udp_nat(v, &format!("{at}.udp_mapping"), WG, "udp_mapping")?;
    }
    if let Some(v) = obj.get("udp_filtering") {
        check_udp_nat(v, &format!("{at}.udp_filtering"), WG, "udp_filtering")?;
    }
    if let Some(v) = obj.get("udp_nat_max") {
        ep_unsigned(
            v,
            &format!("{at}.udp_nat_max"),
            WG,
            "udp_nat_max",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("address") {
        check_prefix_list(v, &format!("{at}.address"))?;
    }
    for f in ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"] {
        if let Some(v) = obj.get(f) {
            ep_unsigned(v, &format!("{at}.{f}"), AWG, f, u32::MAX as u64)?;
        }
    }
    for f in [
        "h1",
        "h2",
        "h3",
        "h4",
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
    ] {
        if let Some(v) = obj.get(f) {
            check_awg_range(v, &format!("{at}.{f}"))?;
        }
    }
    for f in [
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
        "id",
        "ip",
        "ib",
        "header_protection_key",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), AWG, f)?;
        }
    }
    for f in ["random_trailers", "disable_cookies"] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), AWG, f)?;
        }
    }
    if let Some(v) = obj.get("peers") {
        endpoint_peers_decode(i, v)?;
    }

    // shared dial fields.
    for f in [
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "netns",
        "protect_path",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), ABS, f)?;
        }
    }
    for f in [
        "bind_address_no_port",
        "tcp_fast_open",
        "tcp_multi_path",
        "disable_tcp_keep_alive",
        "udp_fragment",
        "reuse_addr",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), ABS, f)?;
        }
    }
    for f in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "fallback_delay",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), ABS, f)?;
        }
    }
    if let Some(v) = obj.get("detour") {
        match v {
            Value::String(_) | Value::Null => {}
            Value::Object(map) if map.is_empty() => {}
            other => {
                return Err(go_field_err(
                    &format!("{at}.detour"),
                    other,
                    DIAL,
                    "detour",
                    "string",
                ));
            }
        }
    }
    if let Some(v) = obj.get("routing_mark") {
        check_routing_mark(v, &format!("{at}.routing_mark"))?;
    }
    if let Some(v) = obj.get("domain_resolver") {
        match v {
            Value::String(_) | Value::Null => {}
            Value::Object(map) if map.is_empty() => {}
            Value::Object(_) => {
                domain_resolver_server(v, &format!("{at}.domain_resolver"))?;
            }
            other => {
                return Err(go_field_err(
                    &format!("{at}.domain_resolver"),
                    other,
                    ABS,
                    "domain_resolver",
                    "option._DomainResolveOptions",
                ));
            }
        }
    }
    if let Some(v) = obj.get("network_strategy") {
        match v {
            Value::String(s) if NETWORK_STRATEGIES.contains(&s.as_str()) => {}
            Value::String(s) => {
                return Err(format!(
                    "{at}.network_strategy: unknown network strategy: {s}"
                ));
            }
            x if is_zero_json(x) => {}
            other => {
                return Err(go_field_err(
                    &format!("{at}.network_strategy"),
                    other,
                    ABS,
                    "network_strategy",
                    "string",
                ));
            }
        }
    }
    if let Some(v) = obj.get("domain_strategy") {
        match v {
            Value::String(s) if DOMAIN_STRATEGIES.contains(&s.as_str()) => {}
            Value::String(s) => {
                return Err(format!(
                    "{at}.domain_strategy: unknown domain strategy: {s}"
                ));
            }
            x if is_zero_json(x) => {}
            other => {
                return Err(go_field_err(
                    &format!("{at}.domain_strategy"),
                    other,
                    ABS,
                    "domain_strategy",
                    "string",
                ));
            }
        }
    }
    for f in ["network_type", "fallback_network_type"] {
        if let Some(v) = obj.get(f) {
            check_interface_types(v, &format!("{at}.{f}"))?;
        }
    }
    Ok(())
}

fn endpoint_peers_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].peers");
    const WGP: &str = "WireGuardPeer.peers";
    const GO_PEERS: &str = "WireGuardEndpointOptions.peers";
    match value {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Array(items) => {
            for (j, entry) in items.iter().enumerate() {
                let peer_at = format!("{at}[{j}]");
                let peer = match entry {
                    Value::Object(map) => map,
                    v if is_zero_json(v) => continue,
                    other => {
                        return Err(format!(
                            "{peer_at}: json: cannot unmarshal {} into Go struct field {GO_PEERS} of type option.WireGuardPeer",
                            json_kind(other)
                        ));
                    }
                };
                reject_unknown_fields(peer, KNOWN_ENDPOINT_PEER_FIELDS, &peer_at)?;
                if let Some(v) = peer.get("address") {
                    ep_str(v, &format!("{peer_at}.address"), WGP, "address")?;
                }
                if let Some(v) = peer.get("port") {
                    ep_unsigned(v, &format!("{peer_at}.port"), WGP, "port", u16::MAX as u64)?;
                }
                for f in ["public_key", "pre_shared_key"] {
                    if let Some(v) = peer.get(f) {
                        ep_str(v, &format!("{peer_at}.{f}"), WGP, f)?;
                    }
                }
                if let Some(v) = peer.get("allowed_ips") {
                    check_prefix_list(v, &format!("{peer_at}.allowed_ips"))?;
                }
                if let Some(v) = peer.get("persistent_keepalive_interval") {
                    check_awg_range(v, &format!("{peer_at}.persistent_keepalive_interval"))?;
                }
                if let Some(v) = peer.get("reserved") {
                    check_reserved(v, &format!("{peer_at}.reserved"))?;
                }
            }
            Ok(())
        }
        other => Err(format!(
            "{at}: json: cannot unmarshal {} into Go struct field {GO_PEERS} of type []option.WireGuardPeer",
            json_kind(other)
        )),
    }
}

fn check_reserved(value: &Value, at: &str) -> Result<(), String> {
    const WGP: &str = "WireGuardPeer.peers";
    match value {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                match item {
                    Value::Number(n) => match n.as_u64() {
                        Some(x) if x <= u8::MAX as u64 => {}
                        _ => {
                            return Err(format!(
                                "{at}[{idx}]: json: cannot unmarshal number {} into Go struct field {WGP}.reserved of type uint8",
                                go_number_literal(item)
                            ));
                        }
                    },
                    v if is_zero_json(v) => {}
                    other => {
                        return Err(format!(
                            "{at}[{idx}]: json: cannot unmarshal {} into Go struct field {WGP}.reserved of type uint8",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(())
        }
        other => Err(format!(
            "{at}: json: cannot unmarshal {} into Go struct field {WGP}.reserved of type []uint8",
            json_kind(other)
        )),
    }
}

/// strict LDH masquerade domain validator (mirror of `validateMasqueDomain`).
fn validate_masque_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("amneziawg: id (masquerade domain) is required when ip/ib is set".to_string());
    }
    let name = domain.strip_suffix('.').unwrap_or(domain);
    if name.is_empty() || name.len() > 253 {
        return Err(format!(
            "amneziawg: invalid masquerade domain {domain:?}: empty or longer than 253 bytes"
        ));
    }
    if name.starts_with('.') {
        return Err(format!(
            "amneziawg: invalid masquerade domain {domain:?}: leading dot"
        ));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: label longer than 63 bytes"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: label with leading/trailing hyphen"
            ));
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: illegal character (only a-z A-Z 0-9 - _ allowed)"
            ));
        }
    }
    Ok(())
}

fn endpoint_str<'a>(obj: &'a Map<String, Value>, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("")
}

/// reference initialize pass: private key → AWG (`awgIpcLines`) → addresses →
/// peers, mirroring `protocol/wireguard/endpoint.go` + `device_awg.go`.
fn endpoint_initialize(i: usize, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("initialize endpoint[{i}] wireguard[{tag}]");
    let private_key = endpoint_str(obj, "private_key");
    if private_key.is_empty() {
        return Err(format!("{at}: missing private key"));
    }
    if let Some(idx) = go_b64_check(private_key) {
        return Err(format!(
            "{at}: decode private key: illegal base64 data at input byte {idx}"
        ));
    }

    let u32_field = |key: &str| -> u64 { obj.get(key).and_then(Value::as_u64).unwrap_or(0) };
    let (jc, jmin, jmax) = (u32_field("jc"), u32_field("jmin"), u32_field("jmax"));
    let (s1, s2, s3, s4) = (
        u32_field("s1"),
        u32_field("s2"),
        u32_field("s3"),
        u32_field("s4"),
    );
    let hpk = endpoint_str(obj, "header_protection_key");
    let (id, ip, ib) = (
        endpoint_str(obj, "id"),
        endpoint_str(obj, "ip"),
        endpoint_str(obj, "ib"),
    );
    let (i1, i2) = (endpoint_str(obj, "i1"), endpoint_str(obj, "i2"));
    let ranges_set = [
        "h1",
        "h2",
        "h3",
        "h4",
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
    ]
    .iter()
    .any(|f| awg_range_canonical(obj.get(*f)).is_some());
    let awg_set = jc != 0
        || jmin != 0
        || jmax != 0
        || s1 != 0
        || s2 != 0
        || s3 != 0
        || s4 != 0
        || ranges_set
        || [
            i1,
            i2,
            endpoint_str(obj, "i3"),
            endpoint_str(obj, "i4"),
            endpoint_str(obj, "i5"),
        ]
        .iter()
        .any(|s| !s.is_empty())
        || !id.is_empty()
        || !ip.is_empty()
        || !ib.is_empty()
        || !hpk.is_empty()
        || obj.get("random_trailers").and_then(Value::as_bool) == Some(true)
        || obj.get("disable_cookies").and_then(Value::as_bool) == Some(true);

    if awg_set {
        if jmin > jmax {
            return Err(format!(
                "{at}: amneziawg: jmin ({jmin}) must be <= jmax ({jmax})"
            ));
        }
        if !hpk.is_empty() {
            match go_b64_check(hpk) {
                Some(idx) => {
                    return Err(format!(
                        "{at}: amneziawg: decode header_protection_key (expected base64, as printed by `awg genkey`): illegal base64 data at input byte {idx}"
                    ));
                }
                None => {
                    let len = go_b64_decoded_len(hpk);
                    if len != 32 {
                        return Err(format!(
                            "{at}: amneziawg: header_protection_key must decode to 32 bytes, got {len}"
                        ));
                    }
                    if go_b64_decoded_bytes(hpk).is_some_and(|b| b.iter().all(|x| *x == 0)) {
                        return Err(format!(
                            "{at}: amneziawg: header_protection_key is all zeros (the device treats that as \"off\"); omit the field instead"
                        ));
                    }
                    for (key, value) in [("s1", s1), ("s2", s2), ("s3", s3), ("s4", s4)] {
                        if value < 12 {
                            return Err(format!(
                                "{at}: amneziawg: {key}={value} is too short for header_protection_key: each of s1-s4 must be at least 12 bytes (the padding carries the header cipher nonce)"
                            ));
                        }
                    }
                }
            }
        }
        if !id.is_empty() || !ip.is_empty() || !ib.is_empty() {
            if !i1.is_empty() {
                return Err(format!(
                    "{at}: amneziawg: id/ip/ib masquerade conflicts with an explicit i1; use one or the other"
                ));
            }
            let proto = ip.trim().to_lowercase();
            if proto.is_empty() {
                return Err(format!(
                    "{at}: amneziawg: ip (masquerade protocol) is required when id/ib is set; one of quic|dns|stun|sip"
                ));
            }
            let domain = id.trim();
            if !domain.is_empty() {
                validate_masque_domain(domain).map_err(|m| format!("{at}: {m}"))?;
            }
            let browser = ib.trim().to_lowercase();
            if !browser.is_empty() {
                if !["chrome", "firefox", "curl"].contains(&browser.as_str()) {
                    return Err(format!(
                        "{at}: amneziawg: unknown masquerade browser {ib:?}; one of chrome|firefox|curl"
                    ));
                }
                if proto != "quic" {
                    return Err(format!(
                        "{at}: amneziawg: ib (browser) is only meaningful with ip=quic, got ip={proto:?}"
                    ));
                }
            }
            match proto.as_str() {
                "quic" => {
                    if domain.is_empty() {
                        return Err(format!(
                            "{at}: amneziawg: id (masquerade domain) is required for ip=quic (it becomes the ClientHello SNI)"
                        ));
                    }
                }
                "stun" | "dns" | "sip" => {}
                _ => {
                    return Err(format!(
                        "{at}: amneziawg: unknown masquerade protocol {proto:?}; one of quic|dns|stun|sip"
                    ));
                }
            }
            if proto == "sip" && !i2.is_empty() {
                return Err(format!(
                    "{at}: amneziawg: id/ip/ib masquerade (ip=sip) fills i2; an explicit i2 conflicts with it"
                ));
            }
        }
    }

    if let Some(address) = obj.get("address")
        && let Ok(list) = check_prefix_list(address, &format!("{at}.address"))
        && list.contains(&false)
    {
        return Err(format!("{at}: AddPrefix(invalid IP/-1)"));
    }
    if let Some(Value::Array(peers)) = obj.get("peers") {
        for (j, peer) in peers.iter().enumerate() {
            let allowed = peer
                .as_object()
                .and_then(|m| m.get("allowed_ips"))
                .map(|v| check_prefix_list(v, &format!("{at}.peers[{j}].allowed_ips")))
                .transpose()?
                .unwrap_or_default();
            if allowed.is_empty() {
                return Err(format!("{at}: missing allowed ips for peer {j}"));
            }
            if allowed.contains(&false) {
                return Err(format!("{at}: AddPrefix(invalid IP/-1)"));
            }
        }
    }
    Ok(())
}

/// decoded length of a valid base64 string (data bytes, ignoring padding).
fn go_b64_decoded_len(s: &str) -> usize {
    let data = s.bytes().take_while(|b| *b != b'=').count();
    let full = data / 4 * 3;
    match data % 4 {
        0 => full,
        2 => full + 1,
        3 => full + 2,
        _ => full,
    }
}

/// decoded bytes of a valid base64 string (`None` if invalid alphabet).
fn go_b64_decoded_bytes(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for b in s.bytes() {
        if b == b'=' {
            break;
        }
        let v = ALPHABET.iter().position(|&c| c == b)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn object_entry<'a>(entry: &'a Value, at: &str) -> Result<&'a Map<String, Value>, String> {
    entry
        .as_object()
        .ok_or_else(|| format!("{at}: must be a JSON object"))
}

fn type_field<'a>(obj: &'a Map<String, Value>, at: &str) -> Result<&'a str, String> {
    match obj.get("type") {
        // reference: json null leaves the Go string at "" and falls through
        // to the unknown-type check.
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(ty)) => Ok(ty.as_str()),
        Some(_) => Err(format!(
            "{at}.type: json: cannot unmarshal into Go field of type string"
        )),
    }
}

fn tag_field<'a>(obj: &'a Map<String, Value>, at: &str) -> Result<&'a str, String> {
    match obj.get("tag") {
        None | Some(Value::Null) => Ok(""),
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
    // reference checks the length cap before hex.Decode (SPEC 090).
    if short_id.len() > 16 {
        return Err("invalid short_id".to_string());
    }
    if !short_id.len().is_multiple_of(2) {
        return Err("decode short_id: encoding/hex: odd length hex string".to_string());
    }
    if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("decode short_id: encoding/hex: invalid byte".to_string());
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
        assert!(go_parse_duration("0").is_ok());
        assert!(go_parse_duration("+0").is_ok());
        assert!(go_parse_duration("-0").is_ok());
        assert!(go_parse_duration("").is_err());
        assert!(go_parse_duration("00").is_err());
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

    // ── WireGuard / AmneziaWG endpoint check-parity (messages verified
    //    against sing-box-lx v1.14.1-lx.8 and re-verified byte-identical on
    //    v1.14.2-lx.1) ──────────────────────────────────────────────────

    const WG_PRIV: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const WG_PEER_KEY: &str = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=";

    /// build a single wireguard endpoint config from an endpoint object
    fn wg_cfg(ep: Value) -> Value {
        json!({"endpoints": [ep]})
    }

    /// wireguard endpoint skeleton: key, address, one peer with allowed ips
    fn wg_ep(extra: Value) -> Value {
        let mut ep = json!({
            "type": "wireguard",
            "tag": "ep",
            "private_key": WG_PRIV,
            "address": ["10.0.0.2/32"],
            "peers": [{"public_key": WG_PEER_KEY, "allowed_ips": ["10.0.0.1/32"]}],
        });
        if let Value::Object(extra) = extra {
            ep.as_object_mut().unwrap().extend(extra);
        }
        ep
    }

    #[test]
    fn wg_decode_errors() {
        let err = validate(&wg_cfg(
            json!({"type": "wireguard", "tag": "ep", "bogus": 1}),
        ))
        .unwrap_err();
        assert!(
            err.contains("endpoints[0].bogus: json: unknown field \"bogus\""),
            "{err}"
        );

        let err = validate(&wg_cfg(json!({"type": "wireguard", "tag": 5}))).unwrap_err();
        assert!(
            err.contains(
                "endpoints[0].tag: json: cannot unmarshal number into Go struct field _Endpoint.tag of type string"
            ),
            "{err}"
        );

        let err = validate(&json!({"endpoints": [{"type": "gost", "tag": "e"}]})).unwrap_err();
        assert!(
            err.contains("endpoints[0]: unknown endpoint type: gost"),
            "{err}"
        );

        let err = validate(&wg_cfg(
            wg_ep(json!({"peers": [{"public_key": WG_PEER_KEY, "allowed_ips": ["10.0.0.1/32"], "xyz": 1}]})),
        ))
        .unwrap_err();
        assert!(
            err.contains("endpoints[0].peers[0].xyz: json: unknown field \"xyz\""),
            "{err}"
        );
    }

    #[test]
    fn wg_listable_prefix_errors() {
        let err = validate(&wg_cfg(wg_ep(json!({"address": ["1.2.3.4/33"]})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].address: (json: cannot unmarshal array into Go value of type **netip.Prefix | netip.ParsePrefix(\"1.2.3.4/33\"): prefix length out of range)"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"address": "bogus"})))).unwrap_err();
        assert!(
            err.contains("netip.ParsePrefix(\"bogus\"): no '/'"),
            "{err}"
        );
    }

    #[test]
    fn awg_range_errors() {
        let err = validate(&wg_cfg(wg_ep(json!({"h1": "xyz"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].h1: invalid range \"xyz\": parse \"xyz\": strconv.ParseUint: parsing \"xyz\": invalid syntax"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"h1": "10-5"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].h1: invalid range \"10-5\": range start > end"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"h4": 4.5})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].h4: invalid range 4.5: expected uint32 or \"min-max\""),
            "{err}"
        );
    }

    #[test]
    fn awg_type_errors() {
        let err = validate(&wg_cfg(wg_ep(json!({"jc": "100"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].jc: json: cannot unmarshal string into Go struct field WireGuardEndpointOptions.AmneziaWGOptions.jc of type uint32"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"private_key": 7})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].private_key: json: cannot unmarshal number into Go struct field WireGuardEndpointOptions.private_key of type string"),
            "{err}"
        );
    }

    #[test]
    fn awg_initialize_errors() {
        let err = validate(&wg_cfg(wg_ep(json!({"jmin": 100, "jmax": 50})))).unwrap_err();
        assert!(
            err.contains(
                "initialize endpoint[0] wireguard[ep]: amneziawg: jmin (100) must be <= jmax (50)"
            ),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"header_protection_key": "AAAA"})))).unwrap_err();
        assert!(
            err.contains("initialize endpoint[0] wireguard[ep]: amneziawg: header_protection_key must decode to 32 bytes, got 3"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"id": "example.com", "i1": "AAAA"})))).unwrap_err();
        assert!(
            err.contains("initialize endpoint[0] wireguard[ep]: amneziawg: id/ip/ib masquerade conflicts with an explicit i1; use one or the other"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"id": "..bad..", "ip": "quic"})))).unwrap_err();
        assert!(
            err.contains("initialize endpoint[0] wireguard[ep]: amneziawg: invalid masquerade domain \"..bad..\": leading dot"),
            "{err}"
        );

        let err = validate(&wg_cfg(json!({
            "type": "wireguard", "tag": "ep", "private_key": WG_PRIV,
            "address": ["10.0.0.2/32"],
            "peers": [{"public_key": WG_PEER_KEY}],
        })))
        .unwrap_err();
        assert!(
            err.contains("initialize endpoint[0] wireguard[ep]: missing allowed ips for peer 0"),
            "{err}"
        );

        let err = validate(&wg_cfg(json!({"type": "wireguard", "tag": "ep"}))).unwrap_err();
        assert!(
            err.contains("initialize endpoint[0] wireguard[ep]: missing private key"),
            "{err}"
        );
    }

    #[test]
    fn wg_dialer_value_errors() {
        let err = validate(&wg_cfg(wg_ep(json!({"udp_mapping": "bogus"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].udp_mapping: unknown UDP NAT behavior: bogus"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"udp_timeout": "abc"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].udp_timeout: time: invalid duration \"abc\""),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"network_strategy": "bogus"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].network_strategy: unknown network strategy: bogus"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"domain_strategy": "bogus"})))).unwrap_err();
        assert!(
            err.contains("endpoints[0].domain_strategy: unknown domain strategy: bogus"),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"routing_mark": "x"})))).unwrap_err();
        assert!(
            err.contains(
                "endpoints[0].routing_mark: strconv.ParseUint: parsing \"x\": invalid syntax"
            ),
            "{err}"
        );

        let err = validate(&wg_cfg(wg_ep(json!({"network_type": "bogus"})))).unwrap_err();
        assert!(err.contains("unknown interface type: bogus"), "{err}");
    }

    #[test]
    fn wg_reserved_element_error() {
        let err = validate(&wg_cfg(wg_ep(json!({
            "peers": [{"public_key": WG_PEER_KEY, "allowed_ips": ["10.0.0.1/32"], "reserved": [300]}],
        }))))
        .unwrap_err();
        assert!(
            err.contains("endpoints[0].peers[0].reserved[0]: json: cannot unmarshal number 300 into Go struct field WireGuardPeer.peers.reserved of type uint8"),
            "{err}"
        );
    }

    #[test]
    fn accepts_valid_wireguard_and_awg_endpoints() {
        let cfg = json!({
            "log": {"level": "error"},
            "endpoints": [
                {"type": "wireguard", "tag": "wg", "private_key": WG_PRIV,
                 "address": ["10.0.0.2/32"], "mtu": 1408,
                 "udp_timeout": "5m", "udp_mapping": "endpoint_independent",
                 "network_strategy": "default",
                 "peers": [{"address": "1.2.3.4", "port": 51820,
                            "public_key": WG_PEER_KEY,
                            "allowed_ips": ["10.0.0.1/32"],
                            "persistent_keepalive_interval": "25-35"}]},
                {"type": "wireguard", "tag": "awg", "private_key": WG_PRIV,
                 "address": ["10.0.0.3/32"],
                 "jc": 4, "jmin": 40, "jmax": 70,
                 "s1": 0, "s2": 0, "h1": 1, "h2": 2, "h3": 3, "h4": 4,
                 "peers": [{"public_key": WG_PEER_KEY, "allowed_ips": ["10.0.0.1/32"]}]},
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": [{"inbound": [], "outbound": "wg"}], "final": "direct"}
        });
        assert!(validate(&cfg).is_ok());
    }

    const MASQUE_PRIV: &str = "MHcCAQEEII0yRXpZqxtdgaDRKlsmWg1QDp+D5AWvSHg2WAaubf3woAoGCCqGSM49AwEHoUQDQgAE7IKkFW+4TVa3+LQyWrHAit6Q3J/FdgtrHn0+AioSqpCSojadOVInMjSDxN920+T1Rcplag2IRpgoCr7Fyp2tJA==";
    const MASQUE_PUB: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7IKkFW+4TVa3+LQyWrHAit6Q3J/FdgtrHn0+AioSqpCSojadOVInMjSDxN920+T1Rcplag2IRpgoCr7Fyp2tJA==";
    const MASQUE_RSA_PUB: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAya+MLkgQqDELBz+zMa/DG0JaDq5Q5LA4TX6WnTy+ISaP/xRa+55nwG58Jb3XTbIpErPX09NMol6LhX6fPVLRPLGb/ayr49WRbsUR9rzYNm1aB3QVZLJzTT2TuTAqCrQm2nix1QLIx/J632Dpharr1rkvWGcAC9PWd0t41FCa2oxElOM1SnMk+lmK7BC4AoXlR1DGSTXKY2UZZMw9ECoQqthWvA6t7s+q+rbzPW0NTllKMi8r0o+Cy5lfWFoHjVrbz8flItbR2MUUYV2p7Vn2gavpxsF9RIRkbHzJdVZYBUNAA+ZK/p4mVgRjuemy9AheSfcWhu6512dQadaP2zKLEQIDAQAB";

    /// cloudflare base outbound from the probe corpus; `extra` keys overlay it.
    fn masque(extra: Value) -> Value {
        let mut out = json!({
            "type": "masque", "tag": "warp",
            "server": "162.159.198.2", "server_port": 443,
            "profile": "cloudflare",
            "tls": {"server_name": "www.cloudflare.com"},
            "private_key": MASQUE_PRIV,
            "public_key": MASQUE_PUB,
            "ip": "172.16.0.2/32"
        });
        if let Value::Object(map) = &mut out
            && let Value::Object(extra) = extra
        {
            for (k, v) in extra {
                match (k.as_str(), v) {
                    ("tls", Value::Object(extra_tls)) => {
                        if let Some(Value::Object(base_tls)) = map.get_mut("tls") {
                            for (tk, tv) in extra_tls {
                                base_tls.insert(tk, tv);
                            }
                        } else {
                            map.insert("tls".to_string(), Value::Object(extra_tls));
                        }
                    }
                    (k, v) => {
                        map.insert(k.to_string(), v);
                    }
                }
            }
        }
        json!({"outbounds": [out]})
    }

    fn masque_err(extra: Value) -> String {
        validate(&masque(extra)).unwrap_err()
    }

    #[test]
    fn accepts_valid_masque() {
        assert!(validate(&masque(json!({}))).is_ok());
        // uri absent: the cloudflare profile supplies the default URI
        assert!(validate(&masque(json!({"uri": null}))).is_ok());
        // legacy network folds into vhttp without a conflict
        assert!(validate(&masque(json!({"network": "h3"}))).is_ok());
        // standard profile carries no keys
        let cfg =
            masque(json!({"profile": "standard", "uri": "https://x/.well-known/masque/ip/*/*/"}));
        let Value::Object(root) = cfg else { panic!() };
        let Value::Array(obs) = &root["outbounds"] else {
            panic!()
        };
        let Value::Object(ob) = &obs[0] else { panic!() };
        let mut ob = ob.clone();
        ob.remove("private_key");
        ob.remove("public_key");
        assert!(validate(&json!({"outbounds": [ob]})).is_ok());
    }

    #[test]
    fn masque_profile_and_vhttp_errors() {
        let err = masque_err(json!({"profile": "nope"}));
        assert!(err.contains("masque: unknown profile: nope"), "{err}");

        let err = masque_err(json!({"profile": "standard", "uri": null}));
        assert!(
            err.contains("masque: uri is required for the standard profile — set it to the server's CONNECT-IP request URI, e.g. https://<host>/.well-known/masque/ip/*/*/"),
            "{err}"
        );

        let err = masque_err(json!({"vhttp": "bogus"}));
        assert!(
            err.contains("masque: invalid vhttp: bogus (expected h3, h2 or auto)"),
            "{err}"
        );

        let err = masque_err(json!({"profile": "standard", "uri": "https://x/", "vhttp": "h2"}));
        assert!(
            err.contains("masque: vhttp h2 is not implemented for the standard profile"),
            "{err}"
        );

        let err = masque_err(json!({"profile": "standard", "uri": null, "vhttp": "bad"}));
        assert!(
            err.contains("uri is required for the standard profile"),
            "{err}"
        );

        let err = masque_err(json!({"ip": "bogus", "vhttp": "bad"}));
        assert!(err.contains("invalid vhttp: bad"), "{err}");
    }

    #[test]
    fn masque_legacy_conflicts() {
        let err = masque_err(json!({"network": "h3", "vhttp": "h2"}));
        assert!(
            err.contains("masque: `vhttp` is h2 but deprecated `network` is h3 — remove `network`"),
            "{err}"
        );

        let err = masque_err(json!({"sni": "x.example"}));
        assert!(
            err.contains("masque: `tls.server_name` is www.cloudflare.com but deprecated `sni` is x.example — remove `sni`"),
            "{err}"
        );

        let err = masque_err(json!({
            "tls": {"server_name": "www.cloudflare.com", "fragment_fallback_delay": "2s"},
            "fragment_fallback_delay": "1s"
        }));
        assert!(
            err.contains("masque: `tls.fragment_fallback_delay` and deprecated `fragment_fallback_delay` disagree — remove the latter"),
            "{err}"
        );

        // equal durations in different spellings are not a conflict
        assert!(
            validate(&masque(json!({
                "tls": {"server_name": "www.cloudflare.com", "fragment_fallback_delay": "1000ms"},
                "fragment_fallback_delay": "1s"
            })))
            .is_ok()
        );

        // legacy sni with no tls block folds silently
        assert!(validate(&masque(json!({"tls": null, "sni": "x.example"}))).is_ok());
    }

    #[test]
    fn masque_keys_and_parsing() {
        let err = masque_err(json!({"private_key": null, "public_key": null}));
        assert!(
            err.contains(
                "masque: private_key and public_key are required for the cloudflare profile"
            ),
            "{err}"
        );

        let err = masque_err(json!({"private_key": []}));
        assert!(
            err.contains("private_key and public_key are required"),
            "{err}"
        );

        let err = masque_err(json!({"private_key": "not/base64!!"}));
        assert!(
            err.contains("parse private_key: illegal base64 data at input byte 10"),
            "{err}"
        );

        let err = masque_err(json!({"private_key": "YQ"}));
        assert!(
            err.contains("parse private_key: illegal base64 data at input byte 0"),
            "{err}"
        );

        let err = masque_err(json!({"private_key": "YQ=="}));
        assert!(
            err.contains("parse private_key: x509: failed to parse EC private key"),
            "{err}"
        );

        let err = masque_err(json!({"public_key": MASQUE_RSA_PUB}));
        assert!(
            err.contains("parse public_key: public_key is not an ECDSA key"),
            "{err}"
        );

        let err = masque_err(json!({"public_key": "!!!"}));
        assert!(
            err.contains("parse public_key: illegal base64 data at input byte 0"),
            "{err}"
        );
    }

    #[test]
    fn masque_prefix_errors() {
        let err = masque_err(json!({"ip": "not-an-ip"}));
        assert!(
            err.contains("parse ip: netip.ParsePrefix(\"not-an-ip/32\"): ParseAddr(\"not-an-ip\"): unable to parse IP"),
            "{err}"
        );

        let err = masque_err(json!({"ip": "1.2.3.4/33"}));
        assert!(
            err.contains("parse ip: netip.ParsePrefix(\"1.2.3.4/33\"): prefix length out of range"),
            "{err}"
        );

        let err = masque_err(json!({"ip": "fe80::1%eth0/64"}));
        assert!(
            err.contains("parse ip: netip.ParsePrefix(\"fe80::1%eth0/64\"): IPv6 zones cannot be present in a prefix"),
            "{err}"
        );

        let err = masque_err(json!({"ip": null, "ipv6": null}));
        assert!(
            err.contains("masque: at least one of ip/ipv6 is required"),
            "{err}"
        );

        let err = masque_err(json!({"ipv6": "bogus"}));
        assert!(
            err.contains("parse ipv6: netip.ParsePrefix(\"bogus/128\"): ParseAddr(\"bogus\"): unable to parse IP"),
            "{err}"
        );
    }

    #[test]
    fn masque_mtu_h2_ceiling() {
        let err = masque_err(json!({"mtu": 16001}));
        assert!(
            err.contains("masque: mtu 16001 too large for h2 (max 16000)"),
            "{err}"
        );

        let err = masque_err(json!({"vhttp": "h2", "mtu": 65536}));
        assert!(
            err.contains("masque: mtu 65536 too large for h2 (max 16000)"),
            "{err}"
        );

        assert!(validate(&masque(json!({"mtu": 16000}))).is_ok());
        assert!(validate(&masque(json!({"mtu": 0}))).is_ok());
        assert!(validate(&masque(json!({"vhttp": "h3", "mtu": 65536}))).is_ok());
    }

    #[test]
    fn masque_decode_field_errors() {
        let err = masque_err(json!({"profile": 1}));
        assert!(
            err.contains("outbounds[0].profile: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.profile of type string"),
            "{err}"
        );

        let err = masque_err(json!({"ip": 3}));
        assert!(
            err.contains("outbounds[0].ip: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.ip of type string"),
            "{err}"
        );

        let err = masque_err(json!({"uri": 1}));
        assert!(
            err.contains("outbounds[0].uri: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.uri of type string"),
            "{err}"
        );

        let err = masque_err(json!({"uri": ["x"]}));
        assert!(
            err.contains("outbounds[0].uri: json: cannot unmarshal array into Go struct field MASQUEOutboundOptions.uri of type string"),
            "{err}"
        );

        let err = masque_err(json!({"mtu": -1}));
        assert!(
            err.contains("outbounds[0].mtu: json: cannot unmarshal number -1 into Go struct field MASQUEOutboundOptions.mtu of type uint32"),
            "{err}"
        );

        let err = masque_err(json!({"mtu": "x"}));
        assert!(
            err.contains("outbounds[0].mtu: json: cannot unmarshal string into Go struct field MASQUEOutboundOptions.mtu of type uint32"),
            "{err}"
        );

        let err = masque_err(json!({"server": 1}));
        assert!(
            err.contains("outbounds[0].server: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.ServerOptions.server of type string"),
            "{err}"
        );

        let err = masque_err(json!({"skip_cert_verify": 4}));
        assert!(
            err.contains("outbounds[0].skip_cert_verify: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.skip_cert_verify of type bool"),
            "{err}"
        );

        let err = masque_err(json!({"tls": "x"}));
        assert!(
            err.contains("outbounds[0].tls: json: cannot unmarshal string into Go struct field MASQUEOutboundOptions.OutboundTLSOptionsContainer.tls of type option.OutboundTLSOptions"),
            "{err}"
        );
    }

    #[test]
    fn masque_decode_dialer_errors() {
        let err = masque_err(json!({"detour": 1}));
        assert!(
            err.contains("outbounds[0].detour: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.DialerOptions.detour of type string"),
            "{err}"
        );

        let err = masque_err(json!({"bind_interface": 1}));
        assert!(
            err.contains("outbounds[0].bind_interface: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions.bind_interface of type string"),
            "{err}"
        );

        let err = masque_err(json!({"connect_timeout": null}));
        assert!(
            err.contains("outbounds[0].connect_timeout: time: invalid duration \"\""),
            "{err}"
        );

        let err = masque_err(json!({"connect_timeout": 1}));
        assert!(
            err.contains("outbounds[0].connect_timeout: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions.connect_timeout of type string"),
            "{err}"
        );

        let err = masque_err(json!({"keep_alive_period": "bogus"}));
        assert!(
            err.contains("outbounds[0].keep_alive_period: time: invalid duration \"bogus\""),
            "{err}"
        );

        // lx 1.14.2-lx.3: idle_timeout is a pointer — null means absent.
        assert!(validate(&masque(json!({"idle_timeout": null}))).is_ok());

        let err = masque_err(json!({"udp_fragment": 1}));
        assert!(
            err.contains("outbounds[0].udp_fragment: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions.udp_fragment of type bool"),
            "{err}"
        );

        let err = masque_err(json!({"domain_resolver": 1}));
        assert!(
            err.contains("outbounds[0].domain_resolver: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.DialerOptions.AbstractDialerOptions.domain_resolver of type option._DomainResolveOptions"),
            "{err}"
        );

        assert!(validate(&masque(json!({"domain_resolver": "u"}))).is_ok());
    }

    #[test]
    fn masque_routing_mark_rules() {
        let err = masque_err(json!({"routing_mark": null}));
        assert!(
            err.contains(
                "outbounds[0].routing_mark: strconv.ParseUint: parsing \"\": invalid syntax"
            ),
            "{err}"
        );

        let err = masque_err(json!({"routing_mark": 1.5}));
        assert!(
            err.contains("outbounds[0].routing_mark: invalid number or string mark: json: cannot unmarshal number into Go value of type string"),
            "{err}"
        );

        let err = masque_err(json!({"routing_mark": true}));
        assert!(
            err.contains("outbounds[0].routing_mark: invalid number or string mark: json: cannot unmarshal bool into Go value of type string"),
            "{err}"
        );

        assert!(validate(&masque(json!({"routing_mark": 255}))).is_ok());
        assert!(validate(&masque(json!({"routing_mark": "255"}))).is_ok());
    }

    #[test]
    fn masque_network_list_rules() {
        let err = masque_err(json!({"network_list": "icmp"}));
        assert!(
            err.contains("outbounds[0].network_list: unknown network: icmp"),
            "{err}"
        );

        let err = masque_err(json!({"network_list": "4"}));
        assert!(
            err.contains("outbounds[0].network_list: unknown network: 4"),
            "{err}"
        );

        let err = masque_err(json!({"network_list": [null]}));
        assert!(
            err.contains("outbounds[0].network_list: unknown network: "),
            "{err}"
        );

        let err = masque_err(json!({"network_list": ["icmp"]}));
        assert!(
            err.contains("outbounds[0].network_list: unknown network: icmp"),
            "{err}"
        );

        let err = masque_err(json!({"network_list": ["icmp", "zz"]}));
        assert!(
            err.contains("outbounds[0].network_list: unknown network: icmp"),
            "{err}"
        );

        let err = masque_err(json!({"network_list": ["tcp", 1]}));
        assert!(
            err.contains("outbounds[0].network_list: json: cannot unmarshal array into Go struct field MASQUEOutboundOptions.network_list of type string"),
            "{err}"
        );

        let err = masque_err(json!({"network_list": 123}));
        assert!(
            err.contains("outbounds[0].network_list: json: cannot unmarshal number into Go struct field MASQUEOutboundOptions.network_list of type string"),
            "{err}"
        );

        let err = masque_err(json!({"network_list": true}));
        assert!(
            err.contains("outbounds[0].network_list: json: cannot unmarshal bool into Go struct field MASQUEOutboundOptions.network_list of type string"),
            "{err}"
        );

        // prunable containers behave as absent fields
        assert!(validate(&masque(json!({"network_list": []}))).is_ok());
        assert!(validate(&masque(json!({"network_list": {}}))).is_ok());
        assert!(validate(&masque(json!({"network_list": null}))).is_ok());
        assert!(validate(&masque(json!({"network_list": ["tcp", "udp"]}))).is_ok());
    }

    #[test]
    fn masque_prune_and_unknown_fields() {
        // prunable unknown fields vanish before the strict decode
        assert!(validate(&masque(json!({"zzz": {}}))).is_ok());
        assert!(validate(&masque(json!({"zzz": []}))).is_ok());
        assert!(validate(&masque(json!({"zzz": [[]]}))).is_ok());
        assert!(validate(&masque(json!({"mtu": {}}))).is_ok());
        assert!(validate(&masque(json!({"uri": null}))).is_ok());

        // surviving unknown fields are rejected whatever their shape
        for extra in [
            json!({"zzz": 1}),
            json!({"zzz": null}),
            json!({"zzz": ["x"]}),
        ] {
            let err = masque_err(extra);
            assert!(
                err.contains("outbounds[0].zzz: json: unknown field \"zzz\""),
                "{err}"
            );
        }

        let err = masque_err(json!({"interface_name": "eth0"}));
        assert!(err.contains("unknown field \"interface_name\""), "{err}");

        // field errors are reported before unknown fields (probe p6_unknown_vs_str)
        let err = masque_err(json!({"profile": 1, "zzz": 2}));
        assert!(
            err.contains("MASQUEOutboundOptions.profile of type string"),
            "{err}"
        );
        let err = masque_err(json!({"profile": 1, "aaa": 2}));
        assert!(
            err.contains("MASQUEOutboundOptions.profile of type string"),
            "{err}"
        );

        // error ordering inside the field pass follows the probe matrix
        let err = masque_err(json!({"profile": 1, "mtu": -1}));
        assert!(
            err.contains("MASQUEOutboundOptions.profile of type string"),
            "{err}"
        );
        let err = masque_err(json!({"ip": 3, "vhttp": 2}));
        assert!(
            err.contains("MASQUEOutboundOptions.ip of type string"),
            "{err}"
        );
        let err = masque_err(json!({"network_list": "icmp", "vhttp": "bad"}));
        assert!(err.contains("unknown network: icmp"), "{err}");
        let err = masque_err(json!({"keep_alive_period": "bogus1", "idle_timeout": "bogus2"}));
        assert!(
            err.contains("keep_alive_period: time: invalid duration \"bogus1\""),
            "{err}"
        );
    }

    #[test]
    fn masque_type_and_tag_null() {
        // type: null falls through to the unknown-type check (pc_type_null)
        let err = validate(&json!({"outbounds": [{"type": null, "tag": "w"}]})).unwrap_err();
        assert!(
            err.contains("outbounds[0]: unknown outbound type: "),
            "{err}"
        );

        // tag: null behaves as an absent tag
        let err = validate(&json!({"outbounds": [{"type": "masque"}]})).unwrap_err();
        assert!(err.contains("at least one of ip/ipv6 is required"), "{err}");
    }

    #[test]
    fn masque_server_port_generic_check() {
        let err = masque_err(json!({"server_port": -1}));
        assert!(err.contains("outbounds[0].server_port:"), "{err}");
        let err = masque_err(json!({"server_port": 70000}));
        assert!(err.contains("outbounds[0].server_port:"), "{err}");
        // prunable/null ports skip the generic check
        assert!(validate(&masque(json!({"server_port": null}))).is_ok());
        assert!(validate(&masque(json!({"server_port": []}))).is_ok());
    }
}
