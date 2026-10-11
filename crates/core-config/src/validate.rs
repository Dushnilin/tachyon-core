//! Semantic validation mirroring reference `sing-box check` (F1 + F2 hy2/tuic).
//!
//! Rules were derived empirically against sing-box-lx v1.14.1-lx.8: the
//! differential harness compares exit codes only, so messages here are
//! best-effort echoes of the reference wording, not a contract.
//!
//! Known intentional gaps (documented in COMPAT.md):
//! - field allowlists for protocols other than hysteria2/tuic;
//! - PEM/x509 content parsing of server certificates (presence only).

use base64::Engine as _;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

const KNOWN_TOP_LEVEL: &[&str] = &[
    "lx",
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
    "network_namespaces",
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

/// `option.CacheFileOptions`: bbolt store behind `experimental.cache_file`.
const CACHE_FILE_FIELDS: &[&str] = &[
    "enabled",
    "path",
    "cache_id",
    "store_fakeip",
    "store_rdrc",
    "rdrc_timeout",
    "store_dns",
    "buffer_size",
    "flush_interval",
];
const CACHE_FILE_BOOL_FIELDS: &[&str] = &["enabled", "store_fakeip", "store_rdrc", "store_dns"];

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
    "lx_idle_suspend",
    "lx_idle_suspend_reachable",
    "lx_idle_teardown",
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
    "tls_fragment_fallback_delay",
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
    "snell",
    "cloudflared",
    "fptn",
    "mieru",
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
    "fptn",
    "mieru",
    "dns",
    "bridge",
];

/// `option.BridgeOutboundOptions` (protocol/bridge): no dialer/listen embedding,
/// four optional fields, no init validation.
const BRIDGE_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "interface",
    "bridge_name",
    "iproute2_table_index",
    "iproute2_rule_index",
];

/// `option.CloudflaredInboundOptions` (include/cloudflared): no listen options,
/// two embedded `DialerOptions`.
const CLOUDFLARED_IN_FIELDS: &[&str] = &[
    "type",
    "tag",
    "token",
    "ha_connections",
    "protocol",
    "post_quantum",
    "edge_ip_version",
    "datagram_version",
    "grace_period",
    "region",
    "control_dialer",
    "tunnel_dialer",
];

const TRANSPORT_TYPES: &[&str] = &["ws", "quic", "grpc", "httpupgrade", "http", "xhttp"];

const DNS_SERVER_TYPES: &[&str] = &[
    "tcp",
    "udp",
    "tls",
    "https",
    "quic",
    "h3",
    "hosts",
    "fakeip",
    "dhcp",
    // lx/upstream additions
    "local",
    "mdns",
    "resolved",
    "tailscale",
    "openvpn",
    "openconnect",
    "group",
];

/// `RawLocalDNSServerOptions` = DialerOptions; every DNS transport embeds it.
const DNS_DIALER_FIELDS: &[&str] = DIALER_OUT_FIELDS;

/// Per-type allowlists (option/dns.go + the endpoint option structs).
fn dns_server_fields(ty: &str) -> Vec<&'static str> {
    let dialer = DNS_DIALER_FIELDS;
    let mut fields: Vec<&'static str> = vec!["type", "tag"];
    fields.extend_from_slice(dialer);
    match ty {
        "udp" | "tcp" => fields.extend_from_slice(&["server", "server_port"]),
        "tls" | "quic" => {
            fields.extend_from_slice(&["server", "server_port", "tls"]);
        }
        "https" => {
            fields.extend_from_slice(&["server", "server_port", "tls", "path", "method", "headers"])
        }
        "h3" => {
            fields.extend_from_slice(&["server", "server_port", "tls", "path", "method", "headers"])
        }
        "hosts" => fields.extend_from_slice(&["path", "predefined"]),
        "fakeip" => fields.extend_from_slice(&["inet4_range", "inet6_range"]),
        "local" => fields.extend_from_slice(&["prefer_go", "neighbor_domain"]),
        "dhcp" => fields.extend_from_slice(&["prefer_go", "neighbor_domain", "interface"]),
        "mdns" => fields.extend_from_slice(&["prefer_go", "neighbor_domain", "interface"]),
        "resolved" => fields.extend_from_slice(&["service", "accept_default_resolvers"]),
        "tailscale" | "openvpn" | "openconnect" => {
            fields.extend_from_slice(&[
                "endpoint",
                "accept_default_resolvers",
                "accept_search_domain",
            ]);
        }
        "group" => fields.extend_from_slice(&["servers", "mode", "error_ttl", "win_ttl"]),
        _ => {}
    }
    fields
}

/// Types whose init requires an endpoint tag (protocol/{tailscale,openvpn,
/// openconnect}/dns_transport.go).
fn dns_endpoint_tag_error(ty: &str, i: usize, tag: &str) -> Option<String> {
    let message = match ty {
        "tailscale" => "missing tailscale endpoint tag",
        "openvpn" | "openconnect" => "missing endpoint tag",
        _ => return None,
    };
    Some(format!("initialize DNS server[{i}] {ty}[{tag}]: {message}"))
}

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

const SERVER_TLS_INBOUNDS: &[&str] = &["mixed", "http", "trojan", "vless", "vmess", "shadowsocks"];

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
/// reference `option.ServerOptions` embeddings: `{proto}OutboundOptions`
/// carrying a plain-string `server` (snell/anytls/masque validate their own).
const SERVER_OUT_BASES: &[(&str, &str)] = &[
    ("socks", "SOCKSOutboundOptions"),
    ("http", "HTTPOutboundOptions"),
    ("shadowsocks", "ShadowsocksOutboundOptions"),
    ("shadowtls", "ShadowTLSOutboundOptions"),
    ("vmess", "VMessOutboundOptions"),
    ("vless", "VLESSOutboundOptions"),
    ("trojan", "TrojanOutboundOptions"),
    ("hysteria", "HysteriaOutboundOptions"),
    ("hysteria2", "Hysteria2OutboundOptions"),
    ("tuic", "TUICOutboundOptions"),
    ("naive", "NaiveOutboundOptions"),
    ("ssh", "SSHOutboundOptions"),
];

pub(crate) const DIALER_OUT_FIELDS: &[&str] = &[
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

/// reference `route/rule/rule_dns.go`: a top-level DNS rule with the `route`
/// action (or none) must name a server, and its matchers decode like the
/// reference listables.
fn validate_dns_rules(rules: &Value) -> Result<(), String> {
    let rules = rules
        .as_array()
        .ok_or_else(|| "dns.rules: must be an array".to_string())?;
    for (i, rule) in rules.iter().enumerate() {
        let at = format!("initialize dns router: parse dns rule[{i}]");
        let rule = rule
            .as_object()
            .ok_or_else(|| format!("{at}: must be an object"))?;
        reject_unknown_fields(rule, DNS_RULE_FIELDS, &format!("dns.rules[{i}]"))?;
        if let Some(value) = rule.get("rule_set").filter(|value| !prunes_value(value)) {
            check_listable_string_field(value, &format!("dns.rules[{i}].rule_set"))?;
        }
        for field in ["domain_regex", "process_path_regex"] {
            if let Some(value) = rule.get(field).filter(|value| !prunes_value(value)) {
                check_listable_string_field(value, &format!("dns.rules[{i}].{field}"))?;
                check_regex_listable(value, &format!("dns.rules[{i}].{field}"))?;
            }
        }
        let action = rule.get("action").and_then(Value::as_str).unwrap_or("");
        let server = rule.get("server").and_then(Value::as_str).unwrap_or("");
        match action {
            "" | "route" | "evaluate" => {
                if server.is_empty() {
                    return Err(format!("{at}: missing server field"));
                }
            }
            "reject" if rule.get("method").and_then(Value::as_str) == Some("reply") => {
                return Err(format!(
                    "{at}: reject method `reply` is not supported for DNS rules"
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// `badoption.Listable[string]` field: the reference reports both shapes.
fn check_listable_string_field(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::String(_) => Ok(()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if !matches!(item, Value::String(_) | Value::Null) {
                    return Err(format!(
                        "{at}: (json: cannot unmarshal array into Go value of type string | [{index}]: json: cannot unmarshal {} into Go value of type string)",
                        json_kind(item)
                    ));
                }
            }
            Ok(())
        }
        other => Err(format!(
            "{at}: (json: cannot unmarshal {} into Go value of type string | json: cannot unmarshal {} into Go value of type []string)",
            json_kind(other),
            json_kind(other)
        )),
    }
}

/// A `*_regex` listable: the reference compiles every expression while it
/// parses the rule (`parse expression N: ...`), so a pattern it cannot read is
/// a config error, not a runtime surprise. Go's regexp and the `regex` crate
/// are both RE2, so a pattern one accepts the other does too.
fn check_regex_listable(value: &Value, at: &str) -> Result<(), String> {
    let list = match value {
        Value::Null => return Ok(()),
        Value::String(_) => vec![value],
        Value::Array(items) => items.iter().collect(),
        other => {
            return Err(format!(
                "{at}: (json: cannot unmarshal {} into Go value of type string | json: cannot unmarshal {} into Go value of type []string)",
                json_kind(other),
                json_kind(other)
            ));
        }
    };
    for (index, item) in list.iter().enumerate() {
        let Some(pattern) = item.as_str() else {
            return Err(format!(
                "{at}: (json: cannot unmarshal array into Go value of type string | [{index}]: json: cannot unmarshal {} into Go value of type string)",
                json_kind(item)
            ));
        };
        #[cfg(feature = "regex")]
        if let Err(err) = regex::Regex::new(pattern) {
            return Err(format!(
                "{at}: parse expression {index}: error parsing regexp: {err}"
            ));
        }
        #[cfg(not(feature = "regex"))]
        let _ = pattern;
    }
    Ok(())
}

/// `badoption.Listable[int32]` field: same two shapes, an int32 instead of a
/// string (`user_id`, whose -1 the reference reserves for "unknown").
fn check_listable_int_field(value: &Value, at: &str) -> Result<(), String> {
    let int32 = |v: &Value| v.as_i64().is_some_and(|n| i32::try_from(n).is_ok());
    match value {
        Value::Null => Ok(()),
        Value::Number(_) if int32(value) => Ok(()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if !int32(item) {
                    return Err(format!(
                        "{at}: (json: cannot unmarshal array into Go value of type int32 | [{index}]: json: cannot unmarshal {} into Go value of type int32)",
                        json_kind(item)
                    ));
                }
            }
            Ok(())
        }
        other => Err(format!(
            "{at}: (json: cannot unmarshal {} into Go value of type int32 | json: cannot unmarshal {} into Go value of type []int32)",
            json_kind(other),
            json_kind(other)
        )),
    }
}

/// reference `option.DefaultHeadlessRule` (a rule-set rule): the matchers a
/// headless rule may carry, plus the `type` switch.
const HEADLESS_RULE_FIELDS: &[&str] = &[
    "type",
    "query_type",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "ip_cidr",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "wifi_ssid",
    "wifi_bssid",
    "network_interface_address",
    "default_interface_address",
    "invert",
];

/// reference `option._RuleSet` + the inline/local/remote option structs.
const RULE_SET_INLINE_FIELDS: &[&str] = &["type", "tag", "format", "rules"];
const RULE_SET_LOCAL_FIELDS: &[&str] = &["type", "tag", "format", "path", "mmap", "mode"];
const RULE_SET_REMOTE_FIELDS: &[&str] = &[
    "type",
    "tag",
    "format",
    "url",
    "initial_path",
    "http_client",
    "update_interval",
    "download_detour",
    "mmap",
    "delta_update",
    "cache_interval",
    "cache_file",
    "mode",
];

/// reference `option.HTTPClientOptions` (shared by the remote rule sets and the
/// 1.15 `default_http_client` gate).
const HTTP_CLIENT_FIELDS: &[&str] = &[
    "url",
    "headers",
    "proxy",
    "dialer",
    "tls",
    "idle_timeout",
    "insecure",
    "address_resolver",
    "address_strategy",
    "network",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "udp_fragment",
    "tcp_fast_open",
    "tcp_multi_path",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
];

/// `C.RuleSetTagPlaceholder` — the `{tag}` a multi-tag local/remote rule set
/// must interpolate in its path or url.
const RULE_SET_TAG_PLACEHOLDER: &str = "{tag}";

/// Go struct that embeds `option.ListenOptions` for every inbound type, as the
/// strict decoder names it in `cannot unmarshal ... into Go struct field ...`.
const INBOUND_LISTEN_STRUCT: &[(&str, &str)] = &[
    ("mixed", "HTTPMixedInboundOptions"),
    ("http", "HTTPMixedInboundOptions"),
    ("socks", "SocksInboundOptions"),
    ("tproxy", "TProxyInboundOptions"),
    ("redirect", "RedirectInboundOptions"),
    ("direct", "DirectInboundOptions"),
    ("trojan", "TrojanInboundOptions"),
    ("shadowsocks", "ShadowsocksInboundOptions"),
    ("shadowtls", "ShadowTLSInboundOptions"),
    ("vmess", "VMessInboundOptions"),
    ("vless", "VLESSInboundOptions"),
    ("anytls", "AnyTLSInboundOptions"),
    ("naive", "NaiveInboundOptions"),
    ("hysteria", "HysteriaInboundOptions"),
    ("hysteria2", "Hysteria2InboundOptions"),
    ("tuic", "TUICInboundOptions"),
    ("snell", "SnellInboundOptions"),
    ("fptn", "FPTNInboundOptions"),
    ("mieru", "MieruInboundOptions"),
];

/// Fields each simple inbound type declares beyond `ListenOptions` and the
/// shared containers (users, tls, multiplex, transport, domain_resolver).
const INBOUND_OWN_FIELDS: &[(&str, &[&str])] = &[
    (
        "mixed",
        &["users", "domain_resolver", "set_system_proxy", "tls"],
    ),
    (
        "http",
        &["users", "domain_resolver", "set_system_proxy", "tls"],
    ),
    ("socks", &["users", "domain_resolver"]),
    (
        "tproxy",
        &["network", "udp_mapping", "udp_filtering", "udp_nat_max"],
    ),
    ("redirect", &[]),
    ("direct", &["network", "override_address", "override_port"]),
    (
        "trojan",
        &[
            "users",
            "fallback",
            "fallback_for_alpn",
            "multiplex",
            "transport",
            "tls",
        ],
    ),
    (
        "shadowsocks",
        &[
            "network",
            "method",
            "password",
            "users",
            "destinations",
            "multiplex",
            "managed",
            "tls",
        ],
    ),
    (
        "shadowtls",
        &[
            "version",
            "password",
            "users",
            "handshake",
            "handshake_for_server_name",
            "strict_mode",
            "wildcard_sni",
        ],
    ),
    ("vmess", &["users", "multiplex", "transport", "tls"]),
    ("vless", &["users", "multiplex", "transport", "tls"]),
    ("anytls", &["users", "padding_scheme", "tls"]),
    (
        "naive",
        &["users", "network", "quic_congestion_control", "tls"],
    ),
    (
        "hysteria",
        &[
            "up",
            "up_mbps",
            "down",
            "down_mbps",
            "obfs",
            "users",
            "recv_window_conn",
            "recv_window_client",
            "max_conn_client",
            "disable_mtu_discovery",
            "tls",
        ],
    ),
    (
        "tun",
        &[
            "interface_name",
            "netns",
            "mtu",
            "address",
            "dns_mode",
            "dns_address",
            "auto_route",
            "iproute2_table_index",
            "iproute2_rule_index",
            "auto_redirect",
            "auto_redirect_input_mark",
            "auto_redirect_output_mark",
            "auto_redirect_reset_mark",
            "auto_redirect_nfqueue",
            "auto_redirect_iproute2_fallback_rule_index",
            "exclude_mptcp",
            "loopback_address",
            "strict_route",
            "route_address",
            "route_address_set",
            "route_exclude_address",
            "route_exclude_address_set",
            "include_interface",
            "exclude_interface",
            "include_uid",
            "include_uid_range",
            "exclude_uid",
            "exclude_uid_range",
            "include_android_user",
            "include_package",
            "exclude_package",
            "include_mac_address",
            "exclude_mac_address",
            "udp_timeout",
            "udp_mapping",
            "udp_filtering",
            "udp_nat_max",
            "stack",
            "platform",
            "gso",
            "inet4_address",
            "inet6_address",
            "inet4_route_address",
            "inet6_route_address",
            "inet4_route_exclude_address",
            "inet6_route_exclude_address",
            "endpoint_independent_nat",
        ],
    ),
    ("mieru", &["users", "transport"]),
    (
        "fptn",
        &[
            "users",
            "tls",
            "dns",
            "dns_ipv6",
            "ipv4_pool",
            "ipv6_pool",
            "obfuscation",
        ],
    ),
];

/// Inbound container fields: the Go field path the decoder reports and the type
/// it fails with. `users` is a list, the rest are objects.
const INBOUND_CONTAINERS: &[(&str, &str, &str, &str, bool)] = &[
    // (inbound type, field, Go field path, Go type, wants an object)
    (
        "mixed",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "trojan",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "vmess",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "vless",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "shadowsocks",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "anytls",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "naive",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "http",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "tuic",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "hysteria",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "hysteria2",
        "tls",
        "InboundTLSOptionsContainer.tls",
        "option.InboundTLSOptions",
        true,
    ),
    (
        "shadowsocks",
        "multiplex",
        "multiplex",
        "option.InboundMultiplexOptions",
        true,
    ),
    (
        "vmess",
        "multiplex",
        "multiplex",
        "option.InboundMultiplexOptions",
        true,
    ),
    (
        "vless",
        "multiplex",
        "multiplex",
        "option.InboundMultiplexOptions",
        true,
    ),
    (
        "trojan",
        "multiplex",
        "multiplex",
        "option.InboundMultiplexOptions",
        true,
    ),
    (
        "vmess",
        "transport",
        "transport",
        "option._V2RayTransportOptions",
        true,
    ),
    (
        "vless",
        "transport",
        "transport",
        "option._V2RayTransportOptions",
        true,
    ),
    (
        "trojan",
        "transport",
        "transport",
        "option._V2RayTransportOptions",
        true,
    ),
    ("mixed", "users", "users", "[]auth.User", false),
    ("http", "users", "users", "[]auth.User", false),
    ("socks", "users", "users", "[]auth.User", false),
    ("naive", "users", "users", "[]auth.User", false),
    (
        "shadowsocks",
        "users",
        "users",
        "[]option.ShadowsocksUser",
        false,
    ),
    ("vmess", "users", "users", "[]option.VMessUser", false),
    ("vless", "users", "users", "[]option.VLESSUser", false),
    ("trojan", "users", "users", "[]option.TrojanUser", false),
    ("anytls", "users", "users", "[]option.AnyTLSUser", false),
    (
        "hysteria2",
        "users",
        "users",
        "[]option.Hysteria2User",
        false,
    ),
];

/// Go kinds of the simple inbound fields (`option` structs above). The check is
/// the strict decoder: wrong JSON kind -> `cannot unmarshal ... of type ...`.
const INBOUND_FIELD_KINDS: &[(&str, &str, &str)] = &[
    // (inbound type, field, Go kind)
    ("mixed", "set_system_proxy", "bool"),
    ("http", "set_system_proxy", "bool"),
    ("tproxy", "network", "network_list"),
    ("tproxy", "udp_mapping", "string"),
    ("tproxy", "udp_filtering", "string"),
    ("tproxy", "udp_nat_max", "uint32"),
    ("redirect", "network", "network_list"),
    ("direct", "network", "network_list"),
    ("direct", "override_address", "string"),
    ("direct", "override_port", "uint16"),
    ("trojan", "fallback", "server_options"),
    ("shadowsocks", "network", "network_list"),
    ("shadowsocks", "method", "string"),
    ("shadowsocks", "password", "string"),
    ("shadowsocks", "destinations", "destination_list"),
    ("shadowsocks", "managed", "bool"),
    ("shadowtls", "version", "int"),
    ("shadowtls", "password", "string"),
    ("shadowtls", "handshake", "object"),
    ("shadowtls", "handshake_for_server_name", "object"),
    ("shadowtls", "strict_mode", "bool"),
    ("shadowtls", "wildcard_sni", "int"),
    ("anytls", "padding_scheme", "listable_string"),
    ("trojan", "fallback_for_alpn", "fallback_map"),
    ("tuic", "zero_rtt_handshake", "bool"),
    ("tuic", "idle_timeout", "quic_duration"),
    ("tuic", "keep_alive_period", "quic_duration"),
    ("tuic", "disable_path_mtu_discovery", "quic_bool"),
    ("naive", "network", "network_list"),
    ("naive", "quic_congestion_control", "string"),
    ("hysteria", "up", "network_bytes"),
    ("hysteria", "down", "network_bytes"),
    ("hysteria", "up_mbps", "int"),
    ("hysteria", "down_mbps", "int"),
    ("hysteria", "obfs", "string"),
    ("hysteria", "recv_window_conn", "uint64"),
    ("hysteria", "recv_window_client", "uint64"),
    ("hysteria", "max_conn_client", "int"),
    ("hysteria", "disable_mtu_discovery", "bool"),
];

/// `byteformats.NetworkBytesCompat` (sing/common/byteformats): a byte count, or
/// a digit prefix plus one of the case-sensitive network units.
const NETWORK_UNITS: &[&str] = &[
    "Bps", "Kbps", "KBps", "Mbps", "MBps", "Gbps", "GBps", "Tbps", "TBps", "Pbps", "PBps", "Ebps",
    "EBps",
];

fn check_network_bytes(
    value: &Value,
    at: &str,
    go_struct: &str,
    field: &str,
) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        // any integer is a byte count, signed included
        Value::Number(_) => Ok(()),
        Value::String(text) => {
            let Some(unit_index) = text
                .char_indices()
                .find(|(_, c)| !c.is_ascii_digit())
                .map(|(index, _)| index)
            else {
                return Ok(());
            };
            if unit_index == 0 {
                return Err(format!("{at}: invalid format: {text}"));
            }
            let digits = &text[..unit_index];
            if digits.parse::<u64>().is_err() {
                return Err(format!(
                    "{at}: parse {digits}: strconv.ParseUint: parsing \"{digits}\": invalid syntax"
                ));
            }
            let raw_unit = &text[unit_index..];
            if !NETWORK_UNITS.contains(&raw_unit.trim()) {
                return Err(format!("{at}: unsupported unit: {raw_unit}"));
            }
            Ok(())
        }
        other => Err(go_type_error(other, at, go_struct, field, "string")),
    }
}

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
    "certificate_sha256",
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

/// Snell outbound base allowlist (`option.AbstractSnellOutboundOptions` +
/// `ServerOptions`; version-specific fields are added after the version switch).
const SNELL_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "version",
    "psk",
    "userkey",
    "reuse",
    "network",
    "server",
    "server_port",
];

/// Snell inbound base allowlist (`option.AbstractSnellInboundOptions`).
const SNELL_IN_FIELDS: &[&str] = &["type", "tag", "version", "psk", "users"];

// Plain outbound field sets (reference option/*.go: DialerOptions +
// ServerOptions + OutboundTLSOptionsContainer are appended at decode time).
const SOCKS_OUT_FIELDS: &[&str] = &["version", "username", "password", "network", "udp_over_tcp"];
const HTTP_OUT_FIELDS: &[&str] = &["username", "password", "path", "headers"];
const SS_OUT_FIELDS: &[&str] = &[
    "method",
    "password",
    "plugin",
    "plugin_opts",
    "network",
    "udp_over_tcp",
    "multiplex",
];
const SHADOWTLS_OUT_FIELDS: &[&str] = &["version", "password"];
const VMESS_OUT_FIELDS: &[&str] = &[
    "uuid",
    "security",
    "alter_id",
    "global_padding",
    "authenticated_length",
    "network",
    "packet_encoding",
    "multiplex",
    "transport",
];
const VLESS_OUT_FIELDS: &[&str] = &[
    "uuid",
    "flow",
    "encryption",
    "network",
    "packet_encoding",
    "multiplex",
    "transport",
];
const TROJAN_OUT_FIELDS: &[&str] = &["password", "network", "multiplex", "transport"];
const HYSTERIA_OUT_FIELDS: &[&str] = &[
    "server_ports",
    "hop_interval",
    "up",
    "up_mbps",
    "down",
    "down_mbps",
    "obfs",
    "auth",
    "auth_str",
    "recv_window_conn",
    "recv_window",
    "disable_mtu_discovery",
    "network",
];
const NAIVE_OUT_FIELDS: &[&str] = &[
    "username",
    "password",
    "insecure_concurrency",
    "extra_headers",
    "stream_receive_window",
    "udp_over_tcp",
    "quic",
    "quic_congestion_control",
    "quic_session_receive_window",
];
const SSH_OUT_FIELDS: &[&str] = &[
    "user",
    "password",
    "private_key",
    "private_key_path",
    "private_key_passphrase",
    "host_key",
    "host_key_algorithms",
    "client_version",
    "cipher",
    "mac",
    "kex_algorithm",
];
const DIRECT_OUT_FIELDS: &[&str] = &["override_address", "override_port", "proxy_protocol"];
const TOR_OUT_FIELDS: &[&str] = &["executable_path", "extra_args", "data_directory", "torrc"];
const SELECTOR_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "outbounds",
    "default",
    "interrupt_exist_connections",
];
const URLTEST_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "outbounds",
    "url",
    "interval",
    "tolerance",
    "idle_timeout",
    "interrupt_exist_connections",
    "mode",
    "balancer",
];
const CHAIN_OUT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "outbounds",
    "idle_timeout",
    "strip_evasion",
    "strip",
    "rewrite",
    "interrupt_exist_connections",
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

/// `json: cannot unmarshal {kind} into Go struct field {struct}.{field} of type {go}`
fn go_type_error(value: &Value, at: &str, go_struct: &str, field: &str, go: &str) -> String {
    format!(
        "{at}: json: cannot unmarshal {} into Go struct field {go_struct}.{field} of type {go}",
        json_kind(value)
    )
}

/// `badoption.Duration` in nanoseconds; a bare `0` (no unit) is 0, which
/// `go_duration_ns` reports as unparsed because it has no unit suffix.
fn go_duration_ns_or_zero(raw: &str) -> i64 {
    go_duration_ns(raw).unwrap_or(0) as i64
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
        Value::Null => Ok(()),
        Value::Array(_) => Err(format!(
            "{at}: json: cannot unmarshal array into Go struct field {go_struct}.{go_field} of type int"
        )),
        Value::Number(n) => {
            // reference decode parses numbers through float64: a fraction, a
            // magnitude beyond int64, or a non-integer literal is rejected.
            match n.as_f64() {
                Some(f)
                    if f.fract() == 0.0
                        && (-9223372036854775808.0f64..9223372036854775808.0f64).contains(&f) =>
                {
                    Ok(())
                }
                _ => Err(format!(
                    "{at}: json: cannot unmarshal number {n} into Go struct field {go_struct}.{go_field} of type int"
                )),
            }
        }
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

/// `[]netip.Prefix` / `[]netip.Addr` (tun address lists): the reference decoder
/// reports the pointer, the slice and the failing element in one message.
fn check_listable_netip(value: &Value, at: &str, element: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(_) => Ok(()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if !item.is_string() {
                    return Err(format!(
                        "{at}: (json: cannot unmarshal array into Go value of type **{element} | [{index}]: json: cannot unmarshal {} into Go value of type {element})",
                        json_kind(item)
                    ));
                }
            }
            Ok(())
        }
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type **{element} | json: cannot unmarshal {kind} into Go value of type []{element})"
            ))
        }
    }
}

/// `[]string` field: a bare string or an array of strings, with the reference
/// element paths.
fn check_string_list(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(_) => Ok(()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if !item.is_string() {
                    return Err(format!(
                        "{at}[{index}]: json: cannot unmarshal {} into Go struct field {go_struct}.{field} of type string",
                        json_kind(item)
                    ));
                }
            }
            Ok(())
        }
        other => Err(format!(
            "{at}: json: cannot unmarshal {} into Go struct field {go_struct}.{field} of type []string",
            json_kind(other)
        )),
    }
}

/// Unsigned integer field at decode: null OK; a number must be a
/// non-negative integer within the Go uint range for `bits`; other kinds and
/// out-of-range numbers report the reference Go unmarshal error including the
/// offending number.
fn check_uint_field(
    value: &Value,
    at: &str,
    go_struct: &str,
    go_field: &str,
    bits: u64,
) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Number(n) => {
            let max: u64 = if bits == 8 {
                u8::MAX as u64
            } else {
                u32::MAX as u64
            };
            match n.as_u64() {
                Some(v) if v <= max => Ok(()),
                _ => Err(format!(
                    "{at}: json: cannot unmarshal number {n} into Go struct field {go_struct}.{go_field} of type uint{bits}"
                )),
            }
        }
        other => Err(format!(
            "{at}: json: cannot unmarshal {} into Go struct field {go_struct}.{go_field} of type uint{bits}",
            json_kind(other)
        )),
    }
}

/// Bool field at decode: null OK; every other kind reports the Go message.
fn check_bool_field(
    value: &Value,
    at: &str,
    go_struct: &str,
    go_field: &str,
) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        other => Err(format!(
            "{at}: json: cannot unmarshal {} into Go struct field {go_struct}.{go_field} of type bool",
            json_kind(other)
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

fn validate_obfs(value: &Value, at: &str, go_struct: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Array(_) => Ok(()),
        Value::String(_) => Err(format!(
            "{at}: json: cannot unmarshal string into Go struct field {go_struct}.obfs of type option._Hysteria2Obfs"
        )),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number into Go struct field {go_struct}.obfs of type option._Hysteria2Obfs"
        )),
        Value::Bool(_) => Err(format!(
            "{at}: json: cannot unmarshal bool into Go struct field {go_struct}.obfs of type option._Hysteria2Obfs"
        )),
        Value::Object(map) => {
            // The reference decodes the shared fields first and only runs the
            // strict per-type pass for gecko, which is the one type with a
            // struct of its own; salamander keeps whatever it is given.
            let ty = map.get("type").and_then(Value::as_str);
            if let Some(ty) = ty
                && !OBFS_TYPES.contains(&ty)
            {
                return Err(format!("{at}: unknown obfs type: {ty}"));
            }
            let gecko = ty == Some("gecko");
            if gecko || ty.is_none() {
                for key in map.keys() {
                    let shared = matches!(key.as_str(), "type" | "password");
                    let sized =
                        gecko && matches!(key.as_str(), "min_packet_size" | "max_packet_size");
                    if !shared && !sized {
                        return Err(format!("{at}.{key}: json: unknown field \"{key}\""));
                    }
                }
            }
            let Some(_ty) = ty else {
                return Ok(());
            };
            if map
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                return Err(format!("{at}: missing obfs password"));
            }
            if gecko {
                // upstream defaults 0 to 512/1200 and rejects the rest
                let read = |name: &str| -> Result<i64, String> {
                    match map.get(name) {
                        None | Some(Value::Null) => Ok(0),
                        Some(Value::Number(n)) => Ok(n.as_i64().unwrap_or(-1)),
                        Some(_) => Err(format!("{at}.{name}: json: cannot unmarshal")),
                    }
                };
                let min = read("min_packet_size")?;
                let max = read("max_packet_size")?;
                // upstream replaces 0 with the defaults and rejects anything
                // that is not strictly positive afterwards
                let max = if max == 0 { 1200 } else { max };
                let min = if min == 0 { 512 } else { min };
                if min <= 0 || min > max || max > 2048 {
                    return Err(format!("{at}: gecko: invalid packet size range"));
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
    let users = value.as_array().ok_or_else(|| {
        format!(
            "{at}: json: cannot unmarshal {} into Go struct field Hysteria2InboundOptions.users of type []option.Hysteria2User",
            json_kind(value)
        )
    })?;
    for (idx, user) in users.iter().enumerate() {
        let u = user.as_object().ok_or_else(|| {
            format!("{at}[{idx}]: json: cannot unmarshal value into Go value of type option.Hysteria2User")
        })?;
        reject_unknown_fields(u, &["name", "password"], &format!("{at}[{idx}"))?;
    }
    Ok(())
}

fn validate_users_tuic(value: &Value, at: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let users = value.as_array().ok_or_else(|| {
        format!(
            "{at}: json: cannot unmarshal {} into Go struct field TUICInboundOptions.users of type []option.TUICUser",
            json_kind(value)
        )
    })?;
    for (idx, user) in users.iter().enumerate() {
        let u = user.as_object().ok_or_else(|| {
            format!(
                "{at}[{idx}]: json: cannot unmarshal value into Go value of type option.TUICUser"
            )
        })?;
        reject_unknown_fields(u, &["name", "uuid", "password"], &format!("{at}[{idx}]"))?;
    }
    Ok(())
}

/// reference `protocol/tuic.NewInbound`: the uuid list is walked after the
/// server TLS config is built, so this is an init-chain check.
fn check_users_tuic_uuid(value: &Value, init_at: &str) -> Result<(), String> {
    let Some(users) = value.as_array() else {
        return Ok(());
    };
    for (idx, user) in users.iter().enumerate() {
        let Some(uuid) = user
            .get("uuid")
            .and_then(Value::as_str)
            .filter(|uuid| !uuid.is_empty())
        else {
            return Err(format!("{init_at}: missing uuid for user {idx}"));
        };
        if !valid_uuid(uuid) {
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
        format!(
            "{at}: json: cannot unmarshal {} into Go struct field Hysteria2{}Options.realm of type option.Hysteria2{}Realm",
            json_kind(value),
            if inbound { "Inbound" } else { "Outbound" },
            if inbound { "Inbound" } else { "" }
        )
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

/// The top-level `http_clients` registry: `option._Options.HTTPClients`.
/// Each entry decodes like the inline `http_client` object, plus the tag the
/// registry is keyed by — the reference reports those two before it looks at
/// anything inside the entry.
fn validate_http_clients(clients: &Value) -> Result<(), String> {
    if clients.is_null() {
        return Ok(());
    }
    let list = clients.as_array().ok_or_else(|| {
        go_type_error(
            clients,
            "http_clients",
            "_Options",
            "http_clients",
            "[]option.HTTPClient",
        )
    })?;
    let mut tags: HashSet<String> = HashSet::new();
    for (i, entry) in list.iter().enumerate() {
        let at = format!("http_clients[{i}]");
        let object = entry.as_object().ok_or_else(|| {
            go_type_error(
                entry,
                &at,
                "_Options",
                "http_clients",
                "option._HTTPClientOptions",
            )
        })?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty());
        match tag {
            None => return Err("missing http client tag".to_string()),
            Some(tag) if !tags.insert(tag.to_string()) => {
                return Err(format!("duplicate http client tag: {tag}"));
            }
            Some(_) => {}
        }
        validate_http_client(entry, &at)?;
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

/// The reference prune drops every Go zero value, so an explicit `false`
/// never reaches the strict decoder and cannot fail a bool field.
fn is_pruned_bool(value: &Value) -> bool {
    is_zero_json(value) || matches!(value, Value::Bool(false))
}

/// reference `option.ListenOptions` (option/inbound.go) for one inbound type:
/// the field kinds, the listen address parse and the FwMark shape. The
/// messages name the struct that embeds `ListenOptions`, like the decoder.
fn validate_listen_options(i: usize, ty: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let Some((_, go_struct)) = INBOUND_LISTEN_STRUCT.iter().find(|(known, _)| *known == ty) else {
        return Ok(());
    };
    let at = format!("inbounds[{i}]");
    let field_at = |value: &Value, field: &str, go: &str| {
        format!(
            "{at}.{field}: json: cannot unmarshal {} into Go struct field {go_struct}.ListenOptions.{field} of type {go}",
            json_kind(value)
        )
    };
    if let Some(listen) = obj.get("listen").filter(|value| !prunes_value(value)) {
        let Some(addr) = listen.as_str() else {
            return Err(field_at(listen, "listen", "string"));
        };
        if IpAddr::from_str(addr).is_err() {
            return Err(format!(
                "{at}.listen: ParseAddr(\"{addr}\"): unable to parse IP"
            ));
        }
    }
    if let Some(port) = obj.get("listen_port").filter(|value| !prunes_value(value)) {
        match port.as_u64() {
            Some(number) if number <= u64::from(u16::MAX) => {}
            Some(number) => {
                return Err(format!(
                    "{at}.listen_port: json: cannot unmarshal number {number} into Go struct field {go_struct}.ListenOptions.listen_port of type uint16"
                ));
            }
            None => return Err(field_at(port, "listen_port", "uint16")),
        }
    }
    for field in ["bind_interface", "netns", "detour"] {
        if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
            && !value.is_string()
        {
            return Err(field_at(value, field, "string"));
        }
    }
    for field in [
        "reuse_addr",
        "disable_tcp_keep_alive",
        "tcp_fast_open",
        "tcp_multi_path",
        "proxy_protocol",
        "proxy_protocol_accept_no_header",
    ] {
        if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
            && !is_pruned_bool(value)
            && !matches!(value, Value::Bool(_))
        {
            return Err(field_at(value, field, "bool"));
        }
    }
    for field in ["tcp_keep_alive", "tcp_keep_alive_interval"] {
        if let Some(value) = obj.get(field).filter(|value| !prunes_value(value)) {
            check_duration_field(
                value,
                &format!("{at}.{field}"),
                &format!("{go_struct}.ListenOptions"),
                field,
            )?;
        }
    }
    if let Some(value) = obj.get("udp_fragment").filter(|value| !prunes_value(value))
        && !is_pruned_bool(value)
        && !matches!(value, Value::Bool(_))
    {
        return Err(field_at(value, "udp_fragment", "bool"));
    }
    if let Some(value) = obj.get("udp_timeout").filter(|value| !prunes_value(value)) {
        check_udp_timeout(value, &format!("{at}.udp_timeout"))?;
    }
    if (ty == "mixed" || ty == "http" || ty == "socks")
        && let Some(value) = obj
            .get("domain_resolver")
            .filter(|value| !prunes_value(value))
    {
        if !value.is_object() {
            return Err(format!(
                "{at}.domain_resolver: json: cannot unmarshal {} into Go struct field {go_struct}.domain_resolver of type option._DomainResolveOptions",
                json_kind(value)
            ));
        }
        domain_resolver_server(value, &format!("{at}.domain_resolver"))?;
    }
    // reference `option.FwMark`: a string mark, or a uint32 number
    if let Some(value) = obj.get("routing_mark").filter(|value| !prunes_value(value)) {
        match value {
            Value::String(text) => {
                if parse_go_uint(text.as_str(), 32).is_none() {
                    return Err(format!(
                        "{at}.routing_mark: strconv.ParseUint: parsing \"{text}\": invalid syntax"
                    ));
                }
            }
            Value::Number(number) => {
                if number
                    .as_u64()
                    .is_none_or(|mark| mark > u64::from(u32::MAX))
                {
                    return Err(format!(
                        "{at}.routing_mark: invalid number or string mark: json: cannot unmarshal number into Go value of type string"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "{at}.routing_mark: invalid number or string mark: json: cannot unmarshal {} into Go value of type string",
                    json_kind(other)
                ));
            }
        }
    }
    Ok(())
}

/// `strconv.ParseUint(text, 0, bits)`: base prefixes, no sign, no underscores.
fn parse_go_uint(text: &str, bits: u32) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let (digits, base) = match text.as_bytes()[0] {
        b'0' if text.len() > 1 => match text.as_bytes().get(1) {
            Some(b'x') | Some(b'X') => (&text[2..], 16),
            Some(b'o') | Some(b'O') => (&text[2..], 8),
            Some(b'b') | Some(b'B') => (&text[2..], 2),
            _ => (&text[1..], 8),
        },
        _ => (text, 10),
    };
    if digits.is_empty() {
        return None;
    }
    let value = u64::from_str_radix(digits, base).ok()?;
    (bits == 32 && value <= u64::from(u32::MAX)).then_some(value)
}

/// Unknown-field rejection for the inbound types without a dedicated decode
/// pass, using the field sets the reference option structs declare.
fn validate_inbound_fields(i: usize, ty: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("inbounds[{i}]");
    // the container fields
    let go_struct = INBOUND_LISTEN_STRUCT
        .iter()
        .find(|(known, _)| *known == ty)
        .map(|(_, name)| *name)
        .unwrap_or("");
    for (inbound, field, path, go, wants_object) in INBOUND_CONTAINERS {
        if *inbound != ty {
            continue;
        }
        let Some(value) = obj.get(*field).filter(|value| !prunes_value(value)) else {
            continue;
        };
        let shaped = if *wants_object {
            value.is_object()
        } else {
            value.is_array()
        };
        if !shaped {
            return Err(go_type_error(
                value,
                &format!("{at}.{field}"),
                go_struct,
                path,
                go,
            ));
        }
    }

    for (inbound, field, kind) in INBOUND_FIELD_KINDS {
        if *inbound != ty {
            continue;
        }
        let Some(value) = obj.get(*field).filter(|value| !prunes_value(value)) else {
            continue;
        };
        let field_at = format!("{at}.{field}");
        match *kind {
            "bool" => {
                if is_pruned_bool(value) || matches!(value, Value::Bool(_)) {
                    continue;
                }
                return Err(go_type_error(value, &field_at, go_struct, field, "bool"));
            }
            "string" => {
                if value.is_string() {
                    continue;
                }
                return Err(go_type_error(value, &field_at, go_struct, field, "string"));
            }
            "listable_string" => {
                // badoption.Listable[string] reports both shapes in one message
                check_listable_string(value, &field_at)?;
                continue;
            }
            "network_list" => {
                // option.NetworkList: a string or a list of them, and any other
                // shape fails as the element type
                let shaped = match value {
                    Value::String(_) => true,
                    Value::Array(items) => {
                        items.iter().all(|item| item.is_string() || item.is_null())
                    }
                    _ => false,
                };
                if !shaped {
                    return Err(go_type_error(value, &field_at, go_struct, field, "string"));
                }
                continue;
            }
            "server_options" => {
                if value.is_object() {
                    continue;
                }
                return Err(go_type_error(
                    value,
                    &field_at,
                    go_struct,
                    field,
                    "option.ServerOptions",
                ));
            }
            "fallback_map" => {
                if value.is_object() {
                    continue;
                }
                return Err(go_type_error(
                    value,
                    &field_at,
                    go_struct,
                    field,
                    "map[string]*option.ServerOptions",
                ));
            }
            "quic_duration" => {
                check_duration_field(
                    value,
                    &field_at,
                    &format!("{go_struct}.QUICOptions.HTTP2Options"),
                    field,
                )?;
                continue;
            }
            "quic_bool" => {
                if is_pruned_bool(value) || matches!(value, Value::Bool(_)) {
                    continue;
                }
                return Err(go_type_error(
                    value,
                    &field_at,
                    &format!("{go_struct}.QUICOptions"),
                    field,
                    "bool",
                ));
            }
            "object" => {
                if value.is_object() {
                    continue;
                }
                return Err(go_type_error(
                    value,
                    &field_at,
                    go_struct,
                    field,
                    "map[string]interface {}",
                ));
            }
            "destination_list" => match value {
                Value::Null => {}
                Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        if !item.is_object() {
                            return Err(go_type_error(
                                item,
                                &format!("{field_at}[{index}]"),
                                go_struct,
                                &format!("{field}[{index}]"),
                                "option.ShadowsocksDestination",
                            ));
                        }
                    }
                }
                other => {
                    return Err(go_type_error(
                        other,
                        &field_at,
                        go_struct,
                        field,
                        "[]option.ShadowsocksDestination",
                    ));
                }
            },
            "int" => check_int_field(value, &field_at, go_struct, field)?,
            "uint16" => check_uint_field(value, &field_at, go_struct, field, 16)?,
            "uint32" => check_uint_field(value, &field_at, go_struct, field, 32)?,
            "uint64" => check_uint_field(value, &field_at, go_struct, field, 64)?,
            "network_bytes" => check_network_bytes(value, &field_at, go_struct, field)?,
            _ => {}
        }
    }

    if ty == "tun" {
        let Some((_, own)) = INBOUND_OWN_FIELDS.iter().find(|(known, _)| *known == ty) else {
            return Ok(());
        };
        let mut allowed: Vec<&str> = vec!["type", "tag"];
        allowed.extend_from_slice(own);
        allowed.extend(LEGACY_INBOUND_FIELDS);
        reject_unknown_fields(obj, &allowed, &at)?;
        let go_struct = "TunInboundOptions";
        for field in [
            "mtu",
            "iproute2_table_index",
            "iproute2_rule_index",
            "auto_redirect_iproute2_fallback_rule_index",
        ] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value)) {
                check_uint_field(value, &format!("{at}.{field}"), go_struct, field, 32)?;
            }
        }
        for field in ["interface_name", "netns", "dns_mode", "stack"] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
                && !value.is_string()
            {
                return Err(go_type_error(
                    value,
                    &format!("{at}.{field}"),
                    go_struct,
                    field,
                    "string",
                ));
            }
        }
        if let Some(value) = obj.get("platform").filter(|value| !prunes_value(value))
            && !value.is_object()
        {
            return Err(go_type_error(
                value,
                &format!("{at}.platform"),
                go_struct,
                "platform",
                "option.TunPlatformOptions",
            ));
        }
        for field in [
            "address",
            "route_address",
            "route_exclude_address",
            "inet4_address",
            "inet6_address",
            "inet4_route_address",
            "inet6_route_address",
            "inet4_route_exclude_address",
            "inet6_route_exclude_address",
        ] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value)) {
                check_listable_netip(value, &format!("{at}.{field}"), "netip.Prefix")?;
            }
        }
        for field in ["dns_address", "loopback_address"] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value)) {
                check_listable_netip(value, &format!("{at}.{field}"), "netip.Addr")?;
            }
        }
        for field in [
            "route_address_set",
            "route_exclude_address_set",
            "include_interface",
            "exclude_interface",
            "include_uid_range",
            "exclude_uid_range",
            "include_package",
            "exclude_package",
            "include_mac_address",
            "exclude_mac_address",
        ] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value)) {
                check_listable_string(value, &format!("{at}.{field}"))?;
            }
        }
        for field in ["udp_mapping", "udp_filtering"] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
                && !value.is_string()
            {
                return Err(go_type_error(
                    value,
                    &format!("{at}.{field}"),
                    go_struct,
                    field,
                    "string",
                ));
            }
        }
        // the legacy `InboundOptions` embed is decoded before the legacy gate
        for field in [
            "sniff",
            "sniff_override_destination",
            "udp_disable_domain_unmapping",
        ] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
                && !is_pruned_bool(value)
                && !matches!(value, Value::Bool(_))
            {
                return Err(go_type_error(
                    value,
                    &format!("{at}.{field}"),
                    "TunInboundOptions.InboundOptions",
                    field,
                    "bool",
                ));
            }
        }
        for field in ["domain_strategy", "sniff_timeout"] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
                && !value.is_string()
            {
                return Err(go_type_error(
                    value,
                    &format!("{at}.{field}"),
                    "TunInboundOptions.InboundOptions",
                    field,
                    "string",
                ));
            }
        }
        for field in [
            "auto_route",
            "strict_route",
            "auto_redirect",
            "exclude_mptcp",
            "gso",
            "endpoint_independent_nat",
        ] {
            if let Some(value) = obj.get(field).filter(|value| !prunes_value(value))
                && !is_pruned_bool(value)
                && !matches!(value, Value::Bool(_))
            {
                return Err(go_type_error(
                    value,
                    &format!("{at}.{field}"),
                    go_struct,
                    field,
                    "bool",
                ));
            }
        }
        return Ok(());
    }
    let Some((_, own)) = INBOUND_OWN_FIELDS.iter().find(|(known, _)| *known == ty) else {
        return Ok(());
    };
    let mut allowed: Vec<&str> = vec!["type", "tag"];
    allowed.extend(LISTEN_IN_FIELDS);
    allowed.extend_from_slice(own);
    allowed.extend(LEGACY_INBOUND_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;
    // `transport` and `multiplex` are in the allowed lists because the reference
    // has them on a server inbound, and a migrated xray config is mostly those
    // two fields. `ws`, `httpupgrade`, `grpc` and `xhttp` are answered by
    // `core_runtime::inbound::transport`; the rest of the transport types and
    // every server-side mux are read by nothing on this side, so a listener
    // started with one binds the port, answers nothing, and the failure arrives
    // at the first connection instead of at startup. Refuse those instead, and
    // say where they do work.
    for (field, where_works) in [
        (
            "transport",
            "move it to the outbound (outbounds[].transport speaks ws, grpc, \
             xhttp and httpupgrade)",
        ),
        (
            "multiplex",
            "run the server side with the reference until this side catches up",
        ),
    ] {
        let Some(value) = obj.get(field).filter(|value| !prunes_value(value)) else {
            continue;
        };
        let kind = value
            .get("type")
            .or_else(|| value.get("protocol"))
            .and_then(Value::as_str)
            .unwrap_or("enabled");
        if field == "transport" && matches!(kind, "ws" | "httpupgrade" | "grpc" | "xhttp") {
            // these four are served, by `core_runtime::inbound::transport`: a
            // websocket handshake, an httpupgrade 101, one HTTP/2 POST stream,
            // or the XHTTP download/upload requests, then the protocol bytes
            continue;
        }
        if field == "transport"
            && value
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("tcp"))
        {
            // mieru's own `transport` is a plain "TCP" string, not a v2ray object
            continue;
        }
        return Err(format!(
            "{at}.{field}: server-side {field} is not implemented yet, so nothing \
             would read this field and the listener would serve nothing: \
             {where_works} (got {kind})"
        ));
    }
    Ok(())
}

/// reference `option.RuleSet.UnmarshalJSON` plus the router init that parses
/// the rule sets: tag, variant fields, format defaults, the `{tag}`
/// placeholder, and the empty-inline/local-file checks.
fn validate_rule_sets(route: &Map<String, Value>) -> Result<(), String> {
    let Some(list) = route.get("rule_set").filter(|value| !prunes_value(value)) else {
        return Ok(());
    };
    let entries = list
        .as_array()
        .ok_or_else(|| "route.rule_set: must be an array".to_string())?;
    for (i, entry) in entries.iter().enumerate() {
        let at = format!("route.rule_set[{i}]");
        let entry = entry
            .as_object()
            .ok_or_else(|| format!("{at}: must be an object"))?;
        let ty = match entry.get("type") {
            None | Some(Value::Null) => "inline",
            Some(Value::String(text)) => text.as_str(),
            Some(other) => {
                return Err(format!(
                    "{at}.type: json: cannot unmarshal {} into Go struct field _RuleSet.type of type string",
                    json_kind(other)
                ));
            }
        };
        let allowed: &[&str] = match ty {
            "inline" => RULE_SET_INLINE_FIELDS,
            "local" => RULE_SET_LOCAL_FIELDS,
            "remote" => RULE_SET_REMOTE_FIELDS,
            other => return Err(format!("{at}: unknown rule-set type: {other}")),
        };
        // the tag is read before the variant fields, like the reference
        let tags = rule_set_tags(entry, &at)?;
        reject_unknown_fields(entry, allowed, &at)?;

        let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
        let url = entry.get("url").and_then(Value::as_str).unwrap_or("");
        let initial_path = entry
            .get("initial_path")
            .and_then(Value::as_str)
            .unwrap_or("");
        // `format` defaults from the path/url extension outside inline
        let mut format = entry
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if ty != "inline" && format.is_empty() {
            format = rule_set_default_format(if ty == "local" { path } else { url });
            if format.is_empty() {
                return Err(format!("{at}: missing format"));
            }
        }
        if !format.is_empty() && !matches!(format.as_str(), "source" | "binary" | "tsrs") {
            return Err(format!("{at}: unknown rule-set format: {format}"));
        }
        if tags.len() > 1 {
            match ty {
                "inline" => {
                    return Err(format!(
                        "{at}: inline rule-set does not support multiple tags"
                    ));
                }
                "local" => {
                    if !path.contains(RULE_SET_TAG_PLACEHOLDER) {
                        return Err(format!(
                            "{at}: missing {RULE_SET_TAG_PLACEHOLDER} placeholder in path"
                        ));
                    }
                }
                _ => {
                    if !url.contains(RULE_SET_TAG_PLACEHOLDER) {
                        return Err(format!(
                            "{at}: missing {RULE_SET_TAG_PLACEHOLDER} placeholder in url"
                        ));
                    }
                    if !initial_path.is_empty() && !initial_path.contains(RULE_SET_TAG_PLACEHOLDER)
                    {
                        return Err(format!(
                            "{at}: missing {RULE_SET_TAG_PLACEHOLDER} placeholder in initial_path"
                        ));
                    }
                }
            }
        }
        if let Some(interval) = entry.get("update_interval").filter(|v| !prunes_value(v)) {
            check_duration_field(
                interval,
                &format!("{at}.update_interval"),
                "RemoteRuleSet",
                "update_interval",
            )?;
        }
        if let Some(client) = entry.get("http_client").filter(|v| !prunes_value(v)) {
            // a string is a `http_clients` tag, resolved when the set starts
            if let Some(client) = client.as_object() {
                reject_unknown_fields(client, HTTP_CLIENT_FIELDS, &format!("{at}.http_client"))?;
            } else if !client.is_string() {
                return Err(format!(
                    "{at}.http_client: json: cannot unmarshal {} into Go value of type option.HTTPClientOptions",
                    json_kind(client)
                ));
            }
        }
        if let Some(rules) = entry.get("rules").filter(|v| !prunes_value(v)) {
            let rules = rules.as_array().ok_or_else(|| {
                format!("{at}.rules: json: cannot unmarshal {} into Go value of type []option.HeadlessRule", json_kind(rules))
            })?;
            for (index, rule) in rules.iter().enumerate() {
                let rule_at = format!("{at}.rules[{index}]");
                let rule = rule.as_object().ok_or_else(|| {
                    format!("{rule_at}: json: cannot unmarshal {} into Go value of type option.HeadlessRule", json_kind(rule))
                })?;
                reject_unknown_fields(rule, HEADLESS_RULE_FIELDS, &rule_at)?;
            }
        }
    }
    // reference `initialize router`: the rule sets are parsed after the config
    // decodes, so the errors carry the router prefix.
    for (i, entry) in entries.iter().enumerate() {
        let entry = match entry.as_object() {
            Some(entry) => entry,
            None => continue,
        };
        let ty = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("inline");
        let at_init = format!("initialize router: parse rule-set[{i}]");
        match ty {
            "inline" => {
                let rules = entry
                    .get("rules")
                    .and_then(Value::as_array)
                    .map(|rules| rules.as_slice())
                    .unwrap_or(&[]);
                if rules.is_empty() || rules.iter().any(|rule| !headless_rule_is_valid(rule)) {
                    return Err(format!("{at_init}: empty inline rule-set"));
                }
            }
            "local" => {
                let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
                if path.is_empty() {
                    continue;
                }
                let absolute = std::path::absolute(path)
                    .map(|path| path.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path.to_string());
                let data = std::fs::read(path).map_err(|err| {
                    format!("{at_init}: {}", go_path_error("open", &absolute, &err))
                })?;
                check_rule_set_payload(&data, entry, &at_init)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// `option.RuleSet.tag`: a listable of non-empty strings.
fn rule_set_tags(entry: &Map<String, Value>, at: &str) -> Result<Vec<String>, String> {
    let raw = match entry.get("tag") {
        None | Some(Value::Null) => return Err(format!("{at}: missing tag")),
        Some(value) => value,
    };
    let mut tags = Vec::new();
    match raw {
        Value::String(text) => tags.push(text.clone()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                match item {
                    Value::String(text) => tags.push(text.clone()),
                    other => {
                        return Err(format!(
                            "{at}.tag[{index}]: json: cannot unmarshal {} into Go value of type string",
                            json_kind(other)
                        ));
                    }
                }
            }
        }
        other => {
            return Err(format!(
                "{at}.tag: json: cannot unmarshal {} into Go value of type string",
                json_kind(other)
            ));
        }
    }
    if tags.is_empty() || tags.iter().any(|tag| tag.is_empty()) {
        return Err(format!("{at}: missing tag"));
    }
    Ok(tags)
}

/// `ruleSetDefaultFormat`: the extension of the path or url, url query ignored.
fn rule_set_default_format(path: &str) -> String {
    let path = match path.split_once('?') {
        Some((head, _)) if path.starts_with("http") => head,
        _ => path,
    };
    if path.ends_with(".json") {
        return "source".to_string();
    }
    if path.ends_with(".srs") {
        return "binary".to_string();
    }
    if path.ends_with(".tsrs") {
        return "tsrs".to_string();
    }
    String::new()
}

/// `DefaultHeadlessRule.IsValid`: a rule that carries no matcher (beyond
/// `invert`) is not a rule.
fn headless_rule_is_valid(rule: &Value) -> bool {
    let Some(rule) = rule.as_object() else {
        return false;
    };
    rule.keys().any(|key| key != "invert" && key != "type")
}

/// The payload of a local rule set: source JSON or the binary SRS container.
fn check_rule_set_payload(data: &[u8], entry: &Map<String, Value>, at: &str) -> Result<(), String> {
    let format = rule_set_payload_format(entry);
    if format == "tsrs" || data.starts_with(b"TSRS") {
        return Ok(());
    }
    if format == "binary" {
        return match crate::srs::read(data) {
            Ok(_) => Ok(()),
            Err(message) => Err(format!("{at}: {message}")),
        };
    }
    let text = match std::str::from_utf8(data) {
        Ok(text) => text,
        Err(_) => return Err(format!("{at}: invalid sing-box rule-set file")),
    };
    let value: Value =
        serde_json::from_str(text).map_err(|err| format!("{at}: parse rule-set source: {err}"))?;
    let Some(object) = value.as_object() else {
        return Err(format!("{at}: parse rule-set source: must be an object"));
    };
    match object.get("version") {
        Some(Value::Number(number)) => {
            let version = number.as_u64().unwrap_or(0);
            if !(1..=5).contains(&version) {
                return Err(format!("{at}: unknown rule-set version: {version}"));
            }
        }
        Some(Value::Null) | None => {
            return Err(format!("{at}: missing rule-set version"));
        }
        Some(other) => {
            return Err(format!(
                "{at}.version: json: cannot unmarshal {} into Go struct field _PlainRuleSetCompat.version of type uint8",
                json_kind(other)
            ));
        }
    }
    if let Some(rules) = object.get("rules").filter(|value| !prunes_value(value)) {
        let rules = rules.as_array().ok_or_else(|| {
            format!(
                "{at}.rules: json: cannot unmarshal {} into Go value of type []option.HeadlessRule",
                json_kind(rules)
            )
        })?;
        if rules.is_empty() || rules.iter().any(|rule| !headless_rule_is_valid(rule)) {
            return Err(format!("{at}: empty rule-set"));
        }
    }
    reject_unknown_fields(object, &["version", "rules"], at)?;
    Ok(())
}

/// The effective format of a local rule set entry.
fn rule_set_payload_format(entry: &Map<String, Value>) -> String {
    let explicit = entry.get("format").and_then(Value::as_str).unwrap_or("");
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
    if path.ends_with(".srs") {
        "binary".to_string()
    } else if path.ends_with(".json") {
        "source".to_string()
    } else {
        "binary".to_string()
    }
}

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
        validate_obfs(obfs, &format!("{at}.obfs"), "Hysteria2OutboundOptions")?;
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
        check_network_list(v, &format!("{at}.network_list"), "MASQUEOutboundOptions")?;
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
/// `opts` is the Go struct name used in unmarshal-style error messages.
fn check_network_list(value: &Value, at: &str, opts: &str) -> Result<(), String> {
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
                return Err(go_field_err(at, value, opts, "network_list", "string"));
            }
            for item in items {
                let s = item.as_str().unwrap_or("");
                if s != "tcp" && s != "udp" {
                    return Err(format!("{at}: unknown network: {s}"));
                }
            }
            Ok(())
        }
        other => Err(go_field_err(at, other, opts, "network_list", "string")),
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
    for field in ["ignore_client_bandwidth", "brutal_debug"] {
        if let Some(v) = obj.get(field).filter(|v| !prunes_value(v))
            && !is_pruned_bool(v)
            && !matches!(v, Value::Bool(_))
        {
            return Err(go_type_error(
                v,
                &format!("{at}.{field}"),
                "Hysteria2InboundOptions",
                field,
                "bool",
            ));
        }
    }
    if let Some(v) = obj
        .get("disable_path_mtu_discovery")
        .filter(|v| !prunes_value(v))
        && !is_pruned_bool(v)
        && !matches!(v, Value::Bool(_))
    {
        return Err(go_type_error(
            v,
            &format!("{at}.disable_path_mtu_discovery"),
            "Hysteria2InboundOptions.QUICOptions",
            "disable_path_mtu_discovery",
            "bool",
        ));
    }
    if let Some(obfs) = obj.get("obfs") {
        validate_obfs(obfs, &format!("{at}.obfs"), "Hysteria2InboundOptions")?;
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
    let _ = init_at;
    if let Some(users) = obj.get("users") {
        validate_users_tuic(users, &format!("{at}.users"))?;
    }
    if let Some(tls) = obj.get("tls") {
        validate_tls_container(tls, &format!("{at}.tls"), true)?;
    }
    check_legacy_inbound(obj)?;
    Ok(())
}

/// Validate a parsed configuration document against reference `check` rules.
/// `network_namespaces`: a list of `{"type": "", "tag": "", "path": ""}` or
/// `{"type": "unshare", "tag": "", "pid_file": ""}`, the reference's
/// discriminated union on `type`.
fn validate_network_namespaces(value: &Value) -> Result<(), String> {
    let list = value
        .as_array()
        .ok_or_else(|| "network_namespaces: must be a list".to_string())?;
    for (index, entry) in list.iter().enumerate() {
        let at = format!("network_namespaces[{index}]");
        let obj = entry
            .as_object()
            .ok_or_else(|| format!("{at}: must be an object"))?;
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}: missing tag"))?;
        if tag.is_empty() {
            return Err(format!("{at}: missing tag"));
        }
        match obj.get("type").and_then(Value::as_str).unwrap_or("") {
            "" | "default" => {
                let path = obj
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{at}: missing path"))?;
                if path.is_empty() {
                    return Err(format!("{at}: missing path"));
                }
                // the reference decodes `default` with only its own fields, so a
                // foreign one is an unknown field rather than a semantic check
                if obj.contains_key("pid_file") {
                    return Err(format!("{at}.pid_file: json: unknown field \"pid_file\""));
                }
            }
            "unshare" => {
                if obj.contains_key("path") {
                    return Err(format!("{at}.path: json: unknown field \"path\""));
                }
                if let Some(pid_file) = obj.get("pid_file")
                    && !pid_file.is_null()
                    && pid_file.as_str().is_none_or(str::is_empty)
                {
                    return Err(format!("{at}.pid_file: must be a non-empty string"));
                }
            }
            other => {
                return Err(format!("{at}: unknown network namespace type: {other}"));
            }
        }
    }
    // after the decode, which is where Go puts it: `NewManager` refuses a
    // populated list off Linux (`common/netns/manager_stub.go`)
    if !list.is_empty() && !cfg!(target_os = "linux") {
        return Err("network namespaces are only supported on Linux".to_string());
    }
    Ok(())
}

pub fn validate(root: &Value) -> Result<(), String> {
    let root = root
        .as_object()
        .ok_or_else(|| "config: must be a JSON object".to_string())?;

    for key in root.keys() {
        if !KNOWN_TOP_LEVEL.contains(&key.as_str()) {
            return Err(format!("{key}: json: unknown field \"{key}\""));
        }
    }

    // ResolveLX: decode the block, fold the deprecated route.lx_idle_*
    // aliases into it, then validate the merged result once.
    let mut lx = validate_lx(root.get("lx"))?.unwrap_or_default();
    if let Some(route) = root.get("route") {
        let warnings = resolve_lx_aliases(&mut lx, route)?;
        record_warnings(warnings);
    }
    resolve_lx_values(&lx)?;

    if let Some(clients) = root.get("http_clients") {
        validate_http_clients(clients)?;
    }
    if let Some(namespaces) = root.get("network_namespaces") {
        validate_network_namespaces(namespaces)?;
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
    validate_domain_resolver_gate(&Value::Object(root.clone()))?;
    let mut dns_tags: HashSet<String> = HashSet::new();
    let mut has_outbounds = false;
    if let Some(route) = root.get("route") {
        validate_route(route)?;
    }
    if let Some(dns) = root.get("dns") {
        validate_dns(dns, &mut dns_tags)?;
    }

    let mut inbound_tags: HashSet<String> = HashSet::new();
    let mut outbound_tags: HashSet<String> = HashSet::new();

    if let Some(list) = root.get("inbounds") {
        let entries = list.as_array().ok_or("inbounds: must be an array")?;
        for (i, raw) in entries.iter().enumerate() {
            // reference stage-2 prune runs before every option decode: empty
            // containers behave as absent (whole entries keep their shape).
            let entry = if raw.is_object() {
                deep_prune(raw).unwrap_or_else(|| Value::Object(Map::new()))
            } else {
                raw.clone()
            };
            let entry = &entry;
            let obj = object_entry(entry, &format!("inbounds[{i}]"))?;
            let ty = type_field(obj, &format!("inbounds[{i}]"))?;
            if !KNOWN_INBOUND_TYPES.contains(&ty) {
                return Err(format!("inbounds[{i}]: unknown inbound type: {ty}"));
            }
            let tag = tag_field(obj, &format!("inbounds[{i}]"))?;
            if !tag.is_empty() && !inbound_tags.insert(tag.to_string()) {
                return Err(format!("duplicate inbound tag: {tag}"));
            }
            validate_inbound(i, ty, &index_tag(tag, i), obj)?;
        }
    }

    if let Some(list) = root.get("outbounds") {
        let entries = list.as_array().ok_or("outbounds: must be an array")?;
        has_outbounds = !entries.is_empty();
        for (i, raw) in entries.iter().enumerate() {
            // reference stage-2 prune runs before every option decode: empty
            // containers behave as absent (whole entries keep their shape).
            let entry = if raw.is_object() {
                deep_prune(raw).unwrap_or_else(|| Value::Object(Map::new()))
            } else {
                raw.clone()
            };
            let entry = &entry;
            let obj = object_entry(entry, &format!("outbounds[{i}]"))?;
            let ty = type_field(obj, &format!("outbounds[{i}]"))?;
            if !KNOWN_OUTBOUND_TYPES.contains(&ty) {
                return Err(format!("outbounds[{i}]: unknown outbound type: {ty}"));
            }
            let tag = tag_field(obj, &format!("outbounds[{i}]"))?;
            if !tag.is_empty() && !outbound_tags.insert(tag.to_string()) {
                return Err(format!("duplicate outbound/endpoint tag: {tag}"));
            }
            if let Some(port) = obj
                .get("server_port")
                .filter(|p| !p.is_null() && !prunes_value(p))
            {
                check_u16(port).map_err(|m| format!("outbounds[{i}].server_port: {m}"))?;
            }
            validate_outbound(i, ty, &index_tag(tag, i), obj, &dns_tags)?;
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
        let mut initialized: Vec<(usize, String, String)> = Vec::new();
        for (i, raw) in entries.iter().enumerate() {
            // reference stage-2 prune runs before every option decode: empty
            // containers behave as absent (whole entries keep their shape).
            let entry = if raw.is_object() {
                deep_prune(raw).unwrap_or_else(|| Value::Object(Map::new()))
            } else {
                raw.clone()
            };
            let entry = &entry;
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
            if !ENDPOINT_TYPES.contains(&ty) {
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
            if !tag.is_empty() && !outbound_tags.insert(tag.to_string()) {
                return Err(format!("duplicate outbound/endpoint tag: {tag}"));
            }
            endpoint_decode(i, obj, ty)?;
            initialized.push((i, index_tag(tag, i), ty.to_string()));
        }
        for (i, tag, ty) in initialized {
            let raw = &entries[i];
            let entry = if raw.is_object() {
                deep_prune(raw).unwrap_or_else(|| Value::Object(Map::new()))
            } else {
                raw.clone()
            };
            let obj = entry.as_object().expect("validated above");
            endpoint_initialize(i, &tag, obj, &ty)?;
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
    if experimental.is_null() {
        return Ok(());
    }
    let obj = experimental.as_object().ok_or_else(|| {
        format!(
            "experimental: json: cannot unmarshal {} into Go struct field \
             _Options.experimental of type option.ExperimentalOptions",
            json_kind(experimental)
        )
    })?;
    for key in obj.keys() {
        if !KNOWN_EXPERIMENTAL_FIELDS.contains(&key.as_str()) {
            return Err(format!("experimental.{key}: json: unknown field \"{key}\""));
        }
    }
    if let Some(cache) = obj.get("cache_file")
        && !cache.is_null()
    {
        validate_cache_file(cache)?;
    }
    if let Some(clash) = obj.get("clash_api")
        && !clash.is_null()
    {
        validate_clash_api(clash)?;
    }
    Ok(())
}

/// `option.CacheFileOptions` decode: field set, types and the duration gate.
fn validate_cache_file(cache: &Value) -> Result<(), String> {
    let obj = cache.as_object().ok_or_else(|| {
        format!(
            "experimental.cache_file: json: cannot unmarshal {} into Go struct field \
             option.CacheFileOptions",
            json_kind(cache)
        )
    })?;
    for (key, value) in obj {
        let at = format!("experimental.cache_file.{key}");
        if !CACHE_FILE_FIELDS.contains(&key.as_str()) {
            return Err(format!("{at}: json: unknown field \"{key}\""));
        }
        if CACHE_FILE_BOOL_FIELDS.contains(&key.as_str()) {
            if !matches!(value, Value::Bool(_)) {
                return Err(format!(
                    "{at}: json: cannot unmarshal {} into Go value of type bool",
                    json_kind(value)
                ));
            }
            continue;
        }
        match value {
            Value::String(_) | Value::Null => {}
            other => {
                return Err(format!(
                    "{at}: json: cannot unmarshal {} into Go value of type string",
                    json_kind(other)
                ));
            }
        }
        if key == "rdrc_timeout" {
            go_parse_duration(value.as_str().unwrap_or_default())?;
        }
    }
    Ok(())
}

/// `option.ClashAPIOptions` decode: field allowlist + type checks in input
/// order, then the reference's post-decode deprecation guard (raised by
/// `create clash-server` during `check` as well as `run`).
fn validate_clash_api(clash: &Value) -> Result<(), String> {
    const STRING_FIELDS: &[&str] = &[
        "external_controller",
        "external_ui",
        "external_ui_download_url",
        "external_ui_download_detour",
        "secret",
        "default_mode",
        "cache_file",
        "cache_id",
    ];
    const BOOL_FIELDS: &[&str] = &[
        "access_control_allow_private_network",
        "store_mode",
        "store_selected",
        "store_fakeip",
    ];
    const DEPRECATED_TRUTHY: &[&str] = &["store_mode", "store_selected", "store_fakeip"];
    const DEPRECATED_NONEMPTY: &[&str] = &["cache_file", "cache_id"];

    let obj = clash.as_object().ok_or_else(|| {
        format!(
            "experimental.clash_api: json: cannot unmarshal {} into Go struct field \
             ExperimentalOptions.experimental.clash_api of type option.ClashAPIOptions",
            json_kind(clash)
        )
    })?;
    for (key, value) in obj {
        let at = format!("experimental.clash_api.{key}");
        if STRING_FIELDS.contains(&key.as_str()) {
            if !matches!(value, Value::String(_) | Value::Null) {
                return Err(format!(
                    "{at}: json: cannot unmarshal {} into Go struct field \
                     ClashAPIOptions.experimental.clash_api.{key} of type string",
                    json_kind(value)
                ));
            }
        } else if BOOL_FIELDS.contains(&key.as_str()) {
            if !matches!(value, Value::Bool(_) | Value::Null) {
                return Err(format!(
                    "{at}: json: cannot unmarshal {} into Go struct field \
                     ClashAPIOptions.experimental.clash_api.{key} of type bool",
                    json_kind(value)
                ));
            }
        } else if key == "access_control_allow_origin" {
            check_listable_string(value, &at)?;
        } else {
            return Err(format!("{at}: json: unknown field \"{key}\""));
        }
    }
    let deprecated = DEPRECATED_TRUTHY
        .iter()
        .any(|k| obj.get(*k) == Some(&Value::Bool(true)))
        || DEPRECATED_NONEMPTY.iter().any(|k| {
            obj.get(*k)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        });
    if deprecated {
        return Err(
            "create clash-server: cache_file and related fields in Clash API is deprecated \
             in sing-box 1.8.0, use experimental.cache_file instead."
                .to_string(),
        );
    }
    Ok(())
}

/// Fields the reference accepts in `route.rules[]` / `dns.rules[]` / the `dns`
/// object. Derived by probing v1.14.2-lx.8 rather than by reading the Go
/// structs: the rule option types still embed dial and action option structs
/// that the decoder no longer unmarshals inside a rule, so a struct walk
/// over-approximates badly (43 phantom fields on a route rule).
///
/// `action`/`type`/`mode`/`rules` and the predefined-response keys cannot be
/// classified by a plain value sweep (they need meaningful values), so they are
/// listed here next to the probed names. The generic probe answers "is this key
/// known at all"; these are the ones whose value had to be a valid enum or a
/// nested object to get an answer.
const ROUTE_RULE_FIELDS: &[&str] = &[
    "action",
    "auth_user",
    "clash_mode",
    "client",
    "domain",
    "domain_keyword",
    "domain_regex",
    "domain_suffix",
    "fallback_delay",
    "inbound",
    "invert",
    "ip_cidr",
    "ip_is_private",
    "ip_version",
    "method",
    "mode",
    "network",
    "network_is_constrained",
    "network_is_expensive",
    "network_strategy",
    "network_type",
    "no_drop",
    "outbound",
    "override_address",
    "override_port",
    "package_name",
    "package_name_regex",
    "port",
    "port_range",
    "preferred_by",
    "process_name",
    "process_path",
    "process_path_regex",
    "protocol",
    "rewrite_ttl",
    "rule_set",
    "rule_set_ip_cidr_match_source",
    "rule_set_ipcidr_match_source",
    "rules",
    "server",
    "sniffer",
    "source_hostname",
    "source_ip_cidr",
    "source_ip_is_private",
    "source_mac_address",
    "source_port",
    "source_port_range",
    "strategy",
    "timeout",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof",
    "type",
    "udp_connect",
    "udp_disable_domain_unmapping",
    "udp_timeout",
    "user",
    "user_id",
    "wifi_bssid",
    "wifi_ssid",
];

const DNS_RULE_FIELDS: &[&str] = &[
    "action",
    "answer",
    "auth_user",
    "clash_mode",
    "client_subnet",
    "disable_cache",
    "disable_optimistic_cache",
    "domain",
    "domain_keyword",
    "domain_regex",
    "domain_suffix",
    "extra",
    "geoip",
    "geosite",
    "inbound",
    "interface_address",
    "invert",
    "ip_accept_any",
    "ip_cidr",
    "ip_is_private",
    "ip_version",
    "match_response",
    "method",
    "mode",
    "network",
    "network_is_constrained",
    "network_is_expensive",
    "network_type",
    "no_drop",
    "ns",
    "outbound",
    "package_name",
    "package_name_regex",
    "port",
    "port_range",
    "preferred_by",
    "process_name",
    "process_path",
    "process_path_regex",
    "protocol",
    "query_client_subnet",
    "query_dnssec",
    "query_type",
    "rcode",
    "remove_client_subnet",
    "response_answer",
    "response_extra",
    "response_ns",
    "response_rcode",
    "rewrite_ttl",
    "rule_set",
    "rule_set_ip_cidr_accept_empty",
    "rule_set_ip_cidr_match_source",
    "rule_set_ipcidr_match_source",
    "rules",
    "server",
    "source_geoip",
    "source_hostname",
    "source_ip_cidr",
    "source_ip_is_private",
    "source_mac_address",
    "source_port",
    "source_port_range",
    "speculative",
    "type",
    "user",
    "user_id",
    "wifi_bssid",
    "wifi_ssid",
];

const DNS_TOP_FIELDS: &[&str] = &[
    "cache_capacity",
    "client_subnet",
    "disable_cache",
    "disable_expire",
    "final",
    "independent_cache",
    "optimistic",
    "reverse_mapping",
    "rules",
    "servers",
    "strategy",
    "timeout",
];

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
    // `default_http_client` names one of the top-level `http_clients`, so it
    // decodes as a plain tag: an object here is what the reference refuses
    if let Some(value) = obj
        .get("default_http_client")
        .filter(|value| !value.is_null())
    {
        check_string_field(
            value,
            "route.default_http_client",
            "RouteOptions",
            "route.default_http_client",
        )?;
    }
    validate_rule_sets(obj)?;
    Ok(())
}

/// Reference `NewRule(..., checkOutbound)` + `rejectNestedRouteRuleAction`.
fn validate_route_rule(rule: &Value, at: &str, nested: bool) -> Result<(), String> {
    let rule = rule
        .as_object()
        .ok_or_else(|| format!("{at}: must be an object"))?;
    reject_unknown_fields(rule, ROUTE_RULE_FIELDS, at)?;

    if nested {
        for key in NESTED_ACTION_KEYS {
            if rule.contains_key(*key) {
                return Err(format!(
                    "{at}: rule action is not supported in nested rules"
                ));
            }
        }
    }

    if let Some(value) = rule.get("rule_set").filter(|value| !prunes_value(value)) {
        check_listable_string_field(value, &format!("{at}.rule_set"))?;
    }
    check_route_option_values(rule, at)?;
    if let Some(value) = rule.get("ip_version").filter(|value| !prunes_value(value)) {
        match value.as_i64() {
            Some(4 | 6) => {}
            Some(other) => return Err(format!("{at}: invalid ip version: {other}")),
            None => {
                return Err(go_type_error(
                    value,
                    &format!("{at}.ip_version"),
                    "RawDefaultRule",
                    "ip_version",
                    "int",
                ));
            }
        }
    }
    // the process matchers are listables too, and the reference decodes them
    // before it ever looks at a rule's contents
    for field in ["process_name", "process_path", "process_path_regex", "user"] {
        if let Some(value) = rule.get(field).filter(|value| !prunes_value(value)) {
            check_listable_string_field(value, &format!("{at}.{field}"))?;
        }
    }
    for field in ["domain_regex", "process_path_regex"] {
        if let Some(value) = rule.get(field).filter(|value| !prunes_value(value)) {
            check_regex_listable(value, &format!("{at}.{field}"))?;
        }
    }
    if let Some(value) = rule.get("user_id").filter(|value| !prunes_value(value)) {
        check_listable_int_field(value, &format!("{at}.user_id"))?;
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

/// reference `option.RawRouteOptionsActionOptions`: the route-options fields
/// a rule decodes on `route` and `route-options` alike (probed on
/// v1.14.2-lx.11; lx.8 had not shown them to the key sweep).
fn check_route_option_values(rule: &Map<String, Value>, at: &str) -> Result<(), String> {
    const GO: &str = "RouteActionOptions.RawRouteOptionsActionOptions";
    let not_string = |value: &Value, field: &str| {
        format!(
            "{at}.{field}: json: cannot unmarshal {} into Go struct field {GO}.{field} of type string",
            json_kind(value)
        )
    };
    for field in ["udp_timeout", "tls_fragment_fallback_delay"] {
        if let Some(value) = rule.get(field).filter(|value| !prunes_value(value)) {
            let Some(text) = value.as_str() else {
                return Err(not_string(value, field));
            };
            go_parse_duration(text).map_err(|m| format!("{at}.{field}: {m}"))?;
        }
    }
    if let Some(value) = rule
        .get("network_strategy")
        .filter(|value| !prunes_value(value))
    {
        let Some(text) = value.as_str() else {
            return Err(not_string(value, "network_strategy"));
        };
        if !NETWORK_STRATEGIES.contains(&text) {
            return Err(format!(
                "{at}.network_strategy: unknown network strategy: {text}"
            ));
        }
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

/// `common/dialer`: with two or more DNS transports a dialer needs an explicit
/// resolver — `domain_resolver` on the dial fields, or
/// `route.default_domain_resolver`. A single DNS transport is the default and
/// needs nothing. The reference reaches this while building each outbound's
/// dialer, so `block` (which has none) does not trigger it, and an unknown tag
/// fails with its own message.
fn validate_domain_resolver_gate(root: &Value) -> Result<(), String> {
    let Some(dns) = root.get("dns").and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(servers) = dns.get("servers").and_then(Value::as_array) else {
        return Ok(());
    };
    if servers.len() < 2 {
        return Ok(());
    }
    let default_resolver = root
        .get("route")
        .and_then(|route| route.get("default_domain_resolver"))
        .and_then(Value::as_str)
        .filter(|tag| !tag.is_empty());
    if let Some(tag) = default_resolver {
        if !servers.iter().any(|server| {
            server
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|known| known == tag)
        }) {
            return Err(format!(
                "initialize network manager: default domain resolver not found: {tag}"
            ));
        }
        return Ok(());
    }
    // an explicit tag must name a dns server; the reference builds endpoints
    // before outbounds, so an endpoint with a bad tag is reported first
    let empty = Vec::new();
    let known = |tag: &str| {
        servers.iter().any(|server| {
            server
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|known| known == tag)
        })
    };
    for (kind, list) in [
        ("endpoint", root.get("endpoints").and_then(Value::as_array)),
        ("outbound", root.get("outbounds").and_then(Value::as_array)),
    ] {
        for (i, entry) in list.unwrap_or(&empty).iter().enumerate() {
            let Some(tag) = entry
                .get("domain_resolver")
                .and_then(Value::as_str)
                .filter(|tag| !tag.is_empty())
            else {
                continue;
            };
            if !known(tag) {
                let ty = entry.get("type").and_then(Value::as_str).unwrap_or("");
                return Err(format!(
                    "initialize {kind}[{i}] {ty}: domain resolver not found: {tag}"
                ));
            }
        }
    }
    // every dialer-carrying outbound needs its own resolver otherwise
    for outbound in root
        .get("outbounds")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
    {
        let Some(obj) = outbound.as_object() else {
            continue;
        };
        if obj.get("type").and_then(Value::as_str) == Some("block") {
            continue;
        }
        if obj
            .get("domain_resolver")
            .and_then(Value::as_str)
            .is_some_and(|tag| !tag.is_empty())
        {
            continue;
        }
        return Err(
            "missing `route.default_domain_resolver` or `domain_resolver` in dial fields is \
             deprecated in sing-box 1.12.0 and will be removed in sing-box 1.14.0, checkout \
             documentation for migration: \
             https://sing-box.sagernet.org/migration/#migrate-outbound-dns-rule-items-to-domain-resolver"
                .to_string(),
        );
    }
    Ok(())
}

/// `option.OptimisticDNSOptions` unmarshals from a bare bool (the marshalled
/// form when no timeout is set) or from `{enabled, timeout}`.
fn validate_dns_optimistic(value: &Value) -> Result<(), String> {
    match value {
        Value::Bool(_) => Ok(()),
        Value::Object(obj) => {
            for (key, field) in obj {
                let at = format!("dns.optimistic.{key}");
                match key.as_str() {
                    "enabled" => {
                        if !matches!(field, Value::Bool(_)) {
                            return Err(format!(
                                "{at}: json: cannot unmarshal {} into Go struct field \
                                 _OptimisticDNSOptions.enabled of type bool",
                                json_kind(field)
                            ));
                        }
                    }
                    "timeout" => {
                        let text = field.as_str().ok_or_else(|| {
                            format!(
                                "{at}: json: cannot unmarshal {} into Go struct field \
                                 _OptimisticDNSOptions.timeout of type duration",
                                json_kind(field)
                            )
                        })?;
                        go_parse_duration(text)?;
                    }
                    other => {
                        return Err(format!("{at}: json: unknown field \"{other}\""));
                    }
                }
            }
            Ok(())
        }
        other => Err(format!(
            "dns.optimistic: json: cannot unmarshal {} into Go struct field \
             _DNSServerOptions.optimistic of type option.OptimisticDNSOptions",
            json_kind(other)
        )),
    }
}

fn validate_dns(dns: &Value, tags: &mut HashSet<String>) -> Result<(), String> {
    let obj = dns
        .as_object()
        .ok_or_else(|| "dns: must be a JSON object".to_string())?;
    reject_unknown_fields(obj, DNS_TOP_FIELDS, "dns")?;
    if let Some(value) = obj.get("client_subnet").filter(|value| !value.is_null()) {
        check_prefixable_field(
            value,
            "dns.client_subnet",
            "RawDNSOptions.DNSClientOptions",
            "client_subnet",
        )?;
    }
    if let Some(rules) = obj.get("rules").filter(|value| !prunes_value(value)) {
        validate_dns_rules(rules)?;
    }
    if let Some(optimistic) = obj.get("optimistic").filter(|value| !value.is_null()) {
        validate_dns_optimistic(optimistic)?;
    }
    let Some(servers) = obj.get("servers") else {
        return Ok(());
    };
    let servers = servers
        .as_array()
        .ok_or_else(|| "dns.servers: must be an array".to_string())?;
    let mut seen: Vec<(String, &'static str, usize)> = Vec::new();
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
        let server_tag = index_tag(server.get("tag").and_then(Value::as_str).unwrap_or(""), i);
        tags.insert(server_tag.clone());
        let static_ty = DNS_SERVER_TYPES
            .iter()
            .find(|known| **known == ty)
            .copied()
            .unwrap_or("");
        seen.push((server_tag.clone(), static_ty, i));
        // per-type field allowlist (reference decodes the concrete options
        // with DisallowUnknownFields)
        let allowed = dns_server_fields(ty);
        for key in server.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(format!(
                    "dns.servers[{i}].{key}: json: unknown field \"{key}\""
                ));
            }
        }
        validate_dns_server_fields(ty, server, i, &server_tag, &seen)?;
        if ty == "fakeip" {
            let has_ranges =
                server.contains_key("inet4_range") || server.contains_key("inet6_range");
            let tag = server.get("tag").and_then(Value::as_str).unwrap_or("");
            let tag = if tag.is_empty() {
                i.to_string()
            } else {
                tag.to_string()
            };
            if !has_ranges {
                return Err(format!(
                    "initialize DNS server[{i}] fakeip[{tag}]: at least one of inet4_range or inet6_range must be set"
                ));
            }
        }
    }
    // the default transport (`dns.final`, else the first server) cannot be fakeip
    let final_tag = obj.get("final").and_then(Value::as_str).unwrap_or("");
    let default = if final_tag.is_empty() {
        seen.first()
    } else {
        seen.iter().find(|(known, _, _)| known == final_tag)
    };
    if let Some((tag, ty, index)) = default
        && *ty == "fakeip"
    {
        return Err(format!(
            "initialize DNS server[{index}] fakeip[{tag}]: default server cannot be fakeip"
        ));
    }
    Ok(())
}

/// reference `option.SnellInboundOptions.UnmarshalJSON` (same three passes as
/// the outbound, version enum 5/6, users decoded without strict unknown).
fn validate_snell_in_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("inbounds[{i}]");
    const ABSI: &str = "_SnellInboundOptions.AbstractSnellInboundOptions";
    const LIS: &str = "_SnellInboundOptions.AbstractSnellInboundOptions.ListenOptions";

    // pass 1: base + listen field types.
    if let Some(v) = obj.get("version") {
        snell_version_check(v, &format!("{at}.version"), "_SnellInboundOptions")?;
    }
    if let Some(v) = obj.get("psk") {
        ep_str(v, &format!("{at}.psk"), ABSI, "psk")?;
    }
    if let Some(v) = obj.get("users") {
        snell_users_decode(v, &format!("{at}.users"))?;
    }
    for f in ["bind_interface", "netns", "detour"] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), LIS, f)?;
        }
    }
    for f in [
        "reuse_addr",
        "disable_tcp_keep_alive",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "proxy_protocol",
        "proxy_protocol_accept_no_header",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), LIS, f)?;
        }
    }
    for f in ["tcp_keep_alive", "tcp_keep_alive_interval"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), LIS, f)?;
        }
    }
    if let Some(v) = obj.get("udp_timeout") {
        check_udp_timeout(v, &format!("{at}.udp_timeout"))?;
    }
    if let Some(v) = obj.get("routing_mark") {
        check_routing_mark(v, &format!("{at}.routing_mark"))?;
    }

    // pass 2: version switch.
    let version = snell_version(obj);
    match version {
        0 => return Err(format!("{at}: snell: missing version")),
        5 | 6 => {}
        v => return Err(format!("{at}: snell: unsupported version: {v}")),
    }

    // pass 3: version-specific fields, then unknown fields + legacy check.
    let mut allowed: Vec<&str> = SNELL_IN_FIELDS.to_vec();
    allowed.extend(LISTEN_IN_FIELDS);
    allowed.extend(LEGACY_INBOUND_FIELDS);
    if version == 5 {
        if let Some(v) = obj.get("obfs_mode") {
            ep_str(
                v,
                &format!("{at}.obfs_mode"),
                "SnellObfsServerOptions",
                "obfs_mode",
            )?;
        }
        allowed.push("obfs_mode");
    } else {
        if let Some(v) = obj.get("mode") {
            ep_str(v, &format!("{at}.mode"), "SnellV6Options", "mode")?;
        }
        allowed.push("mode");
    }
    reject_unknown_fields(obj, &allowed, &at)?;
    check_legacy_inbound(obj)?;
    Ok(())
}

/// users: elements decode leniently (no unknown rejection); null elements and
/// prunable containers match the reference slice decode.
fn snell_users_decode(value: &Value, at: &str) -> Result<(), String> {
    const GO: &str = "_SnellInboundOptions.AbstractSnellInboundOptions";
    match value {
        Value::Null => Ok(()),
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                match item {
                    Value::Null => {}
                    Value::Object(user) => {
                        let uat = format!("{at}[{idx}]");
                        if let Some(v) = user.get("userkey") {
                            ep_str(
                                v,
                                &format!("{uat}.userkey"),
                                "SnellUser.AbstractSnellInboundOptions.users",
                                "userkey",
                            )?;
                        }
                        if let Some(v) = user.get("name") {
                            ep_str(
                                v,
                                &format!("{uat}.name"),
                                "SnellUser.AbstractSnellInboundOptions.users",
                                "name",
                            )?;
                        }
                    }
                    other => {
                        return Err(format!(
                            "{at}[{idx}]: json: cannot unmarshal {} into Go struct field {GO}.users of type option.SnellUser",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(())
        }
        other => Err(go_field_err(at, other, GO, "users", "[]option.SnellUser")),
    }
}

/// reference inbound init: mode/obfs parse, psk checks (v6 enforces the
/// 12..255-byte psk range), then per-user key rules.
fn validate_snell_in_init(at: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let psk = obj.get("psk").and_then(Value::as_str).unwrap_or("");
    if snell_version(obj) == 5 {
        let raw = obj.get("obfs_mode").and_then(Value::as_str).unwrap_or("");
        if !matches!(raw.to_lowercase().as_str(), "" | "none" | "http" | "tls") {
            return Err(format!("{at}: snell: unknown obfs mode: {raw}"));
        }
        if psk.is_empty() {
            return Err(format!("{at}: snell: missing pre-shared key"));
        }
    } else {
        let raw = obj.get("mode").and_then(Value::as_str).unwrap_or("");
        if !matches!(raw, "" | "default" | "unshaped" | "unsafe-raw") {
            return Err(format!("{at}: snell: unknown v6 mode: {raw}"));
        }
        if psk.is_empty() {
            return Err(format!("{at}: snell: missing pre-shared key"));
        }
        if !(12..=255).contains(&psk.len()) {
            return Err(format!(
                "{at}: snell: psk length must be between 12 and 255 bytes"
            ));
        }
    }
    if let Some(users) = obj.get("users").and_then(Value::as_array)
        && !users.is_empty()
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for user in users {
            let key = user.get("userkey").and_then(Value::as_str).unwrap_or("");
            if key.is_empty() {
                return Err(format!("{at}: snell: bad user key"));
            }
            if key.len() > 255 {
                return Err(format!("{at}: snell: user key too long"));
            }
            if !seen.insert(key) {
                return Err(format!("{at}: snell: duplicate user key"));
            }
        }
    }
    Ok(())
}

fn validate_inbound(i: usize, ty: &str, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("initialize inbound[{i}] {ty}[{tag}]");
    validate_listen_options(i, ty, obj)?;
    validate_inbound_fields(i, ty, obj)?;

    match ty {
        "cloudflared" => {
            reject_unknown_fields(obj, CLOUDFLARED_IN_FIELDS, &format!("inbounds[{i}]"))?;
            for field in ["ha_connections", "edge_ip_version"] {
                if let Some(value) = obj.get(field).filter(|v| !prunes_value(v)) {
                    check_int_field(
                        value,
                        &format!("inbounds[{i}].{field}"),
                        "CloudflaredInboundOptions",
                        field,
                    )?;
                }
            }
            for field in ["token", "protocol", "datagram_version", "region"] {
                if let Some(value) = obj.get(field).filter(|v| !prunes_value(v)) {
                    ep_str(
                        value,
                        &format!("inbounds[{i}].{field}"),
                        "CloudflaredInboundOptions",
                        field,
                    )?;
                }
            }
            if let Some(value) = obj.get("post_quantum").filter(|v| !prunes_value(v)) {
                check_bool_field(
                    value,
                    &format!("inbounds[{i}].post_quantum"),
                    "CloudflaredInboundOptions",
                    "post_quantum",
                )?;
            }
            if let Some(value) = obj.get("grace_period").filter(|v| !prunes_value(v)) {
                check_duration_field(
                    value,
                    &format!("inbounds[{i}].grace_period"),
                    "CloudflaredInboundOptions",
                    "grace_period",
                )?;
            }
            for field in ["control_dialer", "tunnel_dialer"] {
                if let Some(dialer) = obj.get(field).filter(|v| !prunes_value(v)) {
                    let dialer = dialer.as_object().ok_or_else(|| {
                        format!("inbounds[{i}].{field}: json: cannot unmarshal value into Go struct field CloudflaredInboundOptions.{field} of type option.DialerOptions")
                    })?;
                    reject_unknown_fields(
                        dialer,
                        DIALER_OUT_FIELDS,
                        &format!("inbounds[{i}].{field}"),
                    )?;
                }
            }
            // the reference build has no `with_cloudflared` tag
            return Err(format!(
                "{at}: Cloudflared is not included in this build, rebuild with -tags with_cloudflared"
            ));
        }
        "hysteria2" => validate_hy2_in_decode(i, obj)?,
        "tuic" => validate_tuic_in_decode(i, &at, obj)?,
        "snell" => {
            validate_snell_in_decode(i, obj)?;
            validate_snell_in_init(&at, obj)?;
        }
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
            validate_server_tls(obj.get("tls").unwrap(), &at, &format!("inbounds[{i}].tls"))?;
        }
        if ty == "tuic"
            && let Some(users) = obj.get("users")
        {
            check_users_tuic_uuid(users, &at)?;
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
        validate_server_tls(obj.get("tls").unwrap(), &at, &format!("inbounds[{i}].tls"))?;
    }

    Ok(())
}

/// Reference `option.V2RayXHTTPOptions` decode + the sing-box-extended
/// option-layer normalization gates (SPEC 002 / PARAM_MAP): modes, placements,
/// range fields, xmux. Unknown fields reject like the strict JSON decoder;
/// `uplink_http_method: GET` outside packet-up is the lx soft fallback (WARN
/// at runtime, accepted at check).
/// V2Ray transport container (http/ws/quic/grpc/httpupgrade): unknown-field
/// rejection against the per-type struct plus value-kind checks. `xhttp` has
/// its own validator.
fn validate_v2ray_transport(tty: &str, t: &Map<String, Value>, at: &str) -> Result<(), String> {
    const HTTP: &[&str] = &[
        "type",
        "host",
        "path",
        "method",
        "headers",
        "idle_timeout",
        "ping_timeout",
    ];
    const WS: &[&str] = &[
        "type",
        "path",
        "headers",
        "max_early_data",
        "early_data_header_name",
    ];
    const QUIC: &[&str] = &["type"];
    const GRPC: &[&str] = &[
        "type",
        "service_name",
        "idle_timeout",
        "ping_timeout",
        "permit_without_stream",
    ];
    const HTTPUP: &[&str] = &["type", "host", "path", "headers"];
    let allowed = match tty {
        "http" => HTTP,
        "ws" => WS,
        "quic" => QUIC,
        "grpc" => GRPC,
        _ => HTTPUP,
    };
    reject_unknown_fields(t, allowed, at)?;
    match tty {
        "http" => {
            if let Some(v) = t.get("host") {
                check_listable_string(v, &format!("{at}.host"))?;
            }
            for f in ["path", "method"] {
                if let Some(v) = t.get(f) {
                    check_string_field(v, &format!("{at}.{f}"), "V2RayHTTPOptions", f)?;
                }
            }
            if let Some(v) = t.get("headers") {
                check_http_header(v, &format!("{at}.headers"), "V2RayHTTPOptions", "headers")?;
            }
            for f in ["idle_timeout", "ping_timeout"] {
                if let Some(v) = t.get(f) {
                    check_duration_field(v, &format!("{at}.{f}"), "V2RayHTTPOptions", f)?;
                }
            }
        }
        "ws" => {
            for f in ["path", "early_data_header_name"] {
                if let Some(v) = t.get(f) {
                    check_string_field(v, &format!("{at}.{f}"), "V2RayWebsocketOptions", f)?;
                }
            }
            if let Some(v) = t.get("max_early_data") {
                check_uint_field(
                    v,
                    &format!("{at}.max_early_data"),
                    "V2RayWebsocketOptions",
                    "max_early_data",
                    32,
                )?;
            }
            if let Some(v) = t.get("headers") {
                check_http_header(
                    v,
                    &format!("{at}.headers"),
                    "V2RayWebsocketOptions",
                    "headers",
                )?;
            }
        }
        "grpc" => {
            if let Some(v) = t.get("service_name") {
                check_string_field(
                    v,
                    &format!("{at}.service_name"),
                    "V2RayGRPCOptions",
                    "service_name",
                )?;
            }
            for f in ["idle_timeout", "ping_timeout"] {
                if let Some(v) = t.get(f) {
                    check_duration_field(v, &format!("{at}.{f}"), "V2RayGRPCOptions", f)?;
                }
            }
            if let Some(v) = t.get("permit_without_stream") {
                ep_bool(
                    v,
                    &format!("{at}.permit_without_stream"),
                    "V2RayGRPCOptions",
                    "permit_without_stream",
                )?;
            }
        }
        "httpupgrade" => {
            for f in ["host", "path"] {
                if let Some(v) = t.get(f) {
                    check_string_field(v, &format!("{at}.{f}"), "V2RayHTTPUpgradeOptions", f)?;
                }
            }
            if let Some(v) = t.get("headers") {
                check_http_header(
                    v,
                    &format!("{at}.headers"),
                    "V2RayHTTPUpgradeOptions",
                    "headers",
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_xhttp_transport(t: &Map<String, Value>, at: &str) -> Result<(), String> {
    let uses_x_session_names = t.contains_key("session_id_length");
    // Forkop/sing-box X use session_id_*; upstream Tachyon uses session_*.
    // Validate both spellings with the same rules, without silently ignoring them.
    let mut normalized = t.clone();
    for (alias, canonical) in [
        ("session_id_table", "session_table"),
        ("session_id_length", "session_length"),
    ] {
        if let Some(value) = normalized.remove(alias) {
            if normalized
                .get(canonical)
                .is_some_and(|existing| existing != &value)
            {
                return Err(format!("{at}: conflicting {alias} and {canonical}"));
            }
            normalized.insert(canonical.to_owned(), value);
        }
    }
    for field in [
        "x_padding_bytes",
        "session_length",
        "uplink_chunk_size",
        "sc_max_each_post_bytes",
        "sc_min_posts_interval_ms",
        "sc_stream_up_server_secs",
    ] {
        if let Some(value) = normalized.get(field).and_then(Value::as_u64) {
            normalized.insert(field.to_owned(), Value::String(value.to_string()));
        }
    }
    let t = &normalized;
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
    if !table.is_empty() || (!length.is_empty() && !uses_x_session_names) {
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
        let space = (crate::xhttp_session_table(&table).chars().count() as u64)
            .saturating_pow(lo.min(63) as u32);
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
        let has = |f: &str| {
            xmux.get(f).is_some_and(|v| {
                !v.is_null()
                    && v.as_u64() != Some(0)
                    && v.as_str() != Some("0")
                    && v.as_str() != Some("0-0")
            })
        };
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

fn validate_anytls_out_decode(i: usize, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    // reference stage-2 prune runs deep: empty containers behave as absent.
    let pruned =
        deep_prune(&Value::Object(obj.clone())).unwrap_or_else(|| Value::Object(Map::new()));
    let Some(pruned) = pruned.as_object() else {
        return Ok(());
    };
    let obj = pruned;
    const ABS: &str = "AnyTLSOutboundOptions.DialerOptions.AbstractDialerOptions";
    check_dialer_platform_gates(obj, &format!("initialize outbound[{i}] anytls[{tag}]"))?;

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

/// reference `option.SnellOutboundOptions.UnmarshalJSON`: base pass (types),
/// version switch, then version-specific fields plus unknown fields via
/// `badjson.UnmarshallExcluded`. Input is already stage-2 pruned by `validate`.
fn validate_snell_out_decode(i: usize, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    const ABSO: &str = "_SnellOutboundOptions.AbstractSnellOutboundOptions";
    const SRV: &str = "_SnellOutboundOptions.AbstractSnellOutboundOptions.ServerOptions";

    // pass 1: base + dialer field types.
    if let Some(v) = obj.get("version") {
        snell_version_check(v, &format!("{at}.version"), "_SnellOutboundOptions")?;
    }
    for f in ["psk", "userkey"] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), ABSO, f)?;
        }
    }
    if let Some(v) = obj.get("reuse") {
        ep_bool(v, &format!("{at}.reuse"), ABSO, "reuse")?;
    }
    if let Some(v) = obj.get("network") {
        snell_network(v, &format!("{at}.network"), ABSO)?;
    }
    if let Some(v) = obj.get("server") {
        ep_str(v, &format!("{at}.server"), SRV, "server")?;
    }
    check_dialer_fields(
        &at,
        &format!("initialize outbound[{i}] snell[{tag}]"),
        obj,
        "_SnellOutboundOptions.AbstractSnellOutboundOptions",
    )?;

    // pass 2: version switch.
    let version = snell_version(obj);
    match version {
        0 => return Err(format!("{at}: snell: missing version")),
        4 | 6 => {}
        v => return Err(format!("{at}: snell: unsupported version: {v}")),
    }

    // pass 3: version-specific fields, then unknown fields.
    let mut allowed: Vec<&str> = SNELL_OUT_FIELDS.to_vec();
    allowed.extend(DIALER_OUT_FIELDS);
    if version == 4 {
        for f in ["obfs_mode", "obfs_host"] {
            if let Some(v) = obj.get(f) {
                ep_str(v, &format!("{at}.{f}"), "SnellObfsClientOptions", f)?;
            }
        }
        allowed.extend(["obfs_mode", "obfs_host"]);
    } else {
        if let Some(v) = obj.get("mode") {
            ep_str(v, &format!("{at}.mode"), "SnellV6Options", "mode")?;
        }
        allowed.push("mode");
    }
    reject_unknown_fields(obj, &allowed, &at)?;
    Ok(())
}

/// `version`: type errors report first (pass 1); the value itself is read back
/// for the version switch. Integral floats (`4.0`) decode like Go's int.
fn snell_version_check(value: &Value, at: &str, go_struct: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Number(n)
            if n.as_i64().is_some() || n.as_f64().is_some_and(|f| f.fract() == 0.0) =>
        {
            Ok(())
        }
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number {} into Go struct field {go_struct}.version of type int",
            go_number_literal(value)
        )),
        other => Err(go_field_err(at, other, go_struct, "version", "int")),
    }
}

fn snell_version(obj: &Map<String, Value>) -> i64 {
    match obj.get("version") {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
            .unwrap_or(0),
        _ => 0,
    }
}

/// NetworkList: listable network enum; scalars otherwise follow the string
/// field decode, arrays report the array-level type error.
fn snell_network(value: &Value, at: &str, go_struct: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) if s == "tcp" || s == "udp" => Ok(()),
        Value::String(s) => Err(format!("{at}: unknown network: {s}")),
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(s) if s == "tcp" || s == "udp" => {}
                    Value::String(s) => return Err(format!("{at}: unknown network: {s}")),
                    _ => {
                        return Err(format!(
                            "{at}: json: cannot unmarshal array into Go struct field {go_struct}.network of type string"
                        ));
                    }
                }
            }
            Ok(())
        }
        other => Err(go_field_err(at, other, go_struct, "network", "string")),
    }
}

/// `netip.ParseAddr`: strict IP literal, optional non-empty zone.
fn valid_netip_addr(s: &str) -> bool {
    let (addr, zone) = match s.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (s, None),
    };
    if zone.is_some_and(|z| z.is_empty()) {
        return false;
    }
    addr.parse::<IpAddr>().is_ok()
}

/// Dialer field value checks for the plain outbounds; `prefix` is the Go
/// struct that embeds `DialerOptions` (e.g. `SOCKSOutboundOptions`).
/// reference `common/dialer.New`: the platform gates and the option conflict
/// it reports while the dialer is built.
fn check_dialer_platform_gates(obj: &Map<String, Value>, init_at: &str) -> Result<(), String> {
    if let Some(mark) = obj.get("routing_mark").and_then(Value::as_u64)
        && mark > 0
        && !cfg!(target_os = "linux")
    {
        return Err(format!(
            "{init_at}: `routing_mark` is only supported on Linux"
        ));
    }
    if obj.get("bind_address_no_port").and_then(Value::as_bool) == Some(true)
        && !cfg!(target_os = "linux")
    {
        return Err(format!(
            "{init_at}: `bind_address_no_port` is only supported on Linux"
        ));
    }
    let network_strategy = obj
        .get("network_strategy")
        .is_some_and(|value| !prunes_value(value));
    let default_bind = ["bind_interface", "inet4_bind_address", "inet6_bind_address"]
        .iter()
        .any(|field| obj.get(*field).is_some_and(|value| !prunes_value(value)))
        || obj.get("tcp_fast_open").and_then(Value::as_bool) == Some(true);
    if network_strategy && default_bind {
        return Err(format!(
            "{init_at}: `network_strategy` is conflict with `bind_interface`, `inet4_bind_address`, `inet6_bind_address` and `tcp_fast_open`"
        ));
    }
    Ok(())
}

fn check_dialer_fields(
    at: &str,
    init_at: &str,
    obj: &Map<String, Value>,
    prefix: &str,
) -> Result<(), String> {
    check_dialer_platform_gates(obj, init_at)?;
    let dial = format!("{prefix}.DialerOptions");
    let abs = format!("{dial}.AbstractDialerOptions");
    if let Some(v) = obj.get("detour") {
        ep_str(v, &format!("{at}.detour"), &dial, "detour")?;
    }
    for f in [
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "protect_path",
        "netns",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), &abs, f)?;
        }
    }
    // reference parses inet4/inet6 bind addresses at decode (netip.Addr).
    for f in ["inet4_bind_address", "inet6_bind_address"] {
        if let Some(Value::String(s)) = obj.get(f)
            && !valid_netip_addr(s)
        {
            return Err(format!("{at}.{f}: ParseAddr({s:?}): unable to parse IP"));
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
            ep_bool(v, &format!("{at}.{f}"), &abs, f)?;
        }
    }
    for f in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "fallback_delay",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), &abs, f)?;
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
                    &abs,
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
            Value::String(s) if NETWORK_STRATEGIES.contains(&s.as_str()) => {}
            Value::String(s) => {
                return Err(format!(
                    "{at}.network_strategy: unknown network strategy: {s}"
                ));
            }
            other => {
                return Err(go_field_err(
                    &format!("{at}.network_strategy"),
                    other,
                    &abs,
                    "network_strategy",
                    "string",
                ));
            }
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
                    &abs,
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

/// `option.UDPOverTCPOptions`: bool or strict {enabled, version} object.
fn check_udp_over_tcp(value: &Value, at: &str, outer: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Object(map) => {
            reject_unknown_fields(map, &["enabled", "version"], at)?;
            if let Some(v) = map.get("enabled") {
                ep_bool(v, &format!("{at}.enabled"), "_UDPOverTCPOptions", "enabled")?;
            }
            if let Some(v) = map.get("version")
                && !matches!(v, Value::Number(_))
            {
                return Err(go_type_error(
                    v,
                    &format!("{at}.version"),
                    "_UDPOverTCPOptions",
                    "version",
                    "uint8",
                ));
            }
            if let Some(v) = map.get("version")
                && v.as_u64().is_none_or(|number| number > u64::from(u8::MAX))
            {
                return Err(go_type_error(
                    v,
                    &format!("{at}.version"),
                    "_UDPOverTCPOptions",
                    "version",
                    "uint8",
                ));
            }
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            outer,
            "udp_over_tcp",
            "option._UDPOverTCPOptions",
        )),
    }
}

/// `option.OutboundMultiplexOptions` (+ nested brutal).
fn check_out_multiplex(value: &Value, at: &str, outer: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Object(map) => {
            reject_unknown_fields(
                map,
                &[
                    "enabled",
                    "protocol",
                    "max_connections",
                    "min_streams",
                    "max_streams",
                    "padding",
                    "brutal",
                ],
                at,
            )?;
            // the decoder reports the json path inside the container
            for f in ["enabled", "padding"] {
                if let Some(v) = map.get(f) {
                    ep_bool(
                        v,
                        &format!("{at}.{f}"),
                        "OutboundMultiplexOptions",
                        &format!("multiplex.{f}"),
                    )?;
                }
            }
            if let Some(v) = map.get("protocol") {
                ep_str(
                    v,
                    &format!("{at}.protocol"),
                    "OutboundMultiplexOptions",
                    "multiplex.protocol",
                )?;
            }
            for f in ["max_connections", "min_streams", "max_streams"] {
                if let Some(v) = map.get(f) {
                    check_int_field(
                        v,
                        &format!("{at}.{f}"),
                        "OutboundMultiplexOptions",
                        &format!("multiplex.{f}"),
                    )?;
                }
            }
            if let Some(brutal) = map.get("brutal")
                && !brutal.is_null()
            {
                let bat = format!("{at}.brutal");
                match brutal {
                    Value::Object(bm) => {
                        reject_unknown_fields(bm, &["enabled", "up_mbps", "down_mbps"], &bat)?;
                        if let Some(v) = bm.get("enabled") {
                            ep_bool(v, &format!("{bat}.enabled"), "BrutalOptions", "enabled")?;
                        }
                        for f in ["up_mbps", "down_mbps"] {
                            if let Some(v) = bm.get(f) {
                                check_int_field(v, &format!("{bat}.{f}"), "BrutalOptions", f)?;
                            }
                        }
                    }
                    other => {
                        return Err(go_field_err(
                            &bat,
                            other,
                            "BrutalOptions",
                            "brutal",
                            "value",
                        ));
                    }
                }
            }
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            outer,
            "multiplex",
            "option.OutboundMultiplexOptions",
        )),
    }
}

fn check_http_header(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    // badoption.HTTPHeader
    match value {
        Value::Null => Ok(()),
        Value::Object(map) => {
            for (k, v) in map {
                check_listable_string(v, &format!("{at}.{k}"))?;
            }
            Ok(())
        }
        other => Err(go_field_err(
            at,
            other,
            go_struct,
            field,
            "badoption.HTTPHeader",
        )),
    }
}

/// Decode for the plain outbounds without a bespoke validator: allowed-field
/// rejection + per-type value checks + shared dialer/tls containers.
fn validate_plain_out_decode(
    i: usize,
    ty: &str,
    tag: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let (protocol, go_base, has_tls, has_quic): (&[&str], &str, bool, bool) = match ty {
        "socks" => (SOCKS_OUT_FIELDS, "SOCKSOutboundOptions", false, false),
        "http" => (HTTP_OUT_FIELDS, "HTTPOutboundOptions", true, false),
        // `ShadowsocksOutboundOptions` embeds `OutboundTLSOptionsContainer`, so a
        // shadowsocks server behind TLS is a shape the reference builds
        "shadowsocks" => (SS_OUT_FIELDS, "ShadowsocksOutboundOptions", true, false),
        "shadowtls" => (
            SHADOWTLS_OUT_FIELDS,
            "ShadowTLSOutboundOptions",
            true,
            false,
        ),
        "vmess" => (VMESS_OUT_FIELDS, "VMessOutboundOptions", true, false),
        "vless" => (VLESS_OUT_FIELDS, "VLESSOutboundOptions", true, false),
        "trojan" => (TROJAN_OUT_FIELDS, "TrojanOutboundOptions", true, false),
        "hysteria" => (HYSTERIA_OUT_FIELDS, "HysteriaOutboundOptions", true, true),
        "naive" => (NAIVE_OUT_FIELDS, "NaiveOutboundOptions", true, false),
        "ssh" => (SSH_OUT_FIELDS, "SSHOutboundOptions", false, false),
        other => return Err(format!("{at}: unsupported plain outbound type: {other}")),
    };
    let mut allowed: Vec<&str> = protocol.to_vec();
    allowed.extend(DIALER_OUT_FIELDS);
    allowed.extend(["type", "tag", "server", "server_port"]);
    if has_tls {
        allowed.push("tls");
    }
    if has_quic {
        allowed.extend(QUIC_OUT_FIELDS);
    }
    reject_unknown_fields(obj, &allowed, &at)?;

    let strings: &[&str] = match ty {
        "socks" => &["version", "username", "password"],
        "http" => &["username", "password", "path"],
        "shadowsocks" => &["method", "password", "plugin", "plugin_opts"],
        "shadowtls" => &["password"],
        "vmess" => &["uuid", "security", "packet_encoding"],
        "vless" => &["uuid", "flow", "encryption", "packet_encoding"],
        "trojan" => &["password"],
        "naive" => &["username", "password", "quic_congestion_control"],
        "ssh" => &[
            "user",
            "password",
            "private_key_path",
            "private_key_passphrase",
            "client_version",
        ],
        "hysteria" => &["obfs", "auth_str"],
        _ => &[],
    };
    for f in strings {
        if let Some(v) = obj.get(*f) {
            ep_str(v, &format!("{at}.{f}"), go_base, f)?;
        }
    }
    for f in match ty {
        "vmess" => &["alter_id"][..],
        "naive" => &["insecure_concurrency"][..],
        "hysteria" => &["up_mbps", "down_mbps", "recv_window_conn", "recv_window"][..],
        "shadowtls" => &["version"][..],
        _ => &[],
    } {
        if let Some(v) = obj.get(*f) {
            check_int_field(v, &format!("{at}.{f}"), go_base, f)?;
        }
    }
    for f in match ty {
        "vmess" => &["global_padding", "authenticated_length"][..],
        "naive" => &["quic"][..],
        _ => &[],
    } {
        if let Some(v) = obj.get(*f) {
            ep_bool(v, &format!("{at}.{f}"), go_base, f)?;
        }
    }
    if matches!(
        ty,
        "socks" | "shadowsocks" | "vmess" | "vless" | "trojan" | "hysteria"
    ) && let Some(v) = obj.get("network")
    {
        snell_network(v, &format!("{at}.network"), go_base)?;
    }
    if matches!(ty, "ssh") {
        for f in [
            "private_key",
            "host_key",
            "host_key_algorithms",
            "cipher",
            "mac",
            "kex_algorithm",
        ] {
            if let Some(v) = obj.get(f) {
                check_listable_string(v, &format!("{at}.{f}"))?;
            }
        }
    }
    if ty == "hysteria"
        && let Some(v) = obj.get("server_ports")
    {
        check_listable_string(v, &format!("{at}.server_ports"))?;
    }
    if ty == "hysteria"
        && let Some(v) = obj.get("hop_interval")
    {
        check_duration_field(v, &format!("{at}.hop_interval"), go_base, "hop_interval")?;
    }
    if ty == "naive" {
        for f in ["stream_receive_window", "quic_session_receive_window"] {
            if let Some(v) = obj.get(f) {
                check_memory_bytes(v, &format!("{at}.{f}"), go_base, f)?;
            }
        }
        if let Some(v) = obj.get("extra_headers") {
            check_http_header(v, &format!("{at}.extra_headers"), go_base, "extra_headers")?;
        }
        // the reference switches on the congestion control whether or not
        // `quic` is set, so an unknown name is a config error either way
        if let Some(Value::String(cc)) = obj.get("quic_congestion_control")
            && !matches!(cc.as_str(), "" | "bbr" | "bbr2" | "cubic" | "reno")
        {
            return Err(format!("{at}: unknown quic congestion control: {cc}"));
        }
        // a naive tunnel may not skip certificate checking
        for (field, message) in [
            ("insecure", "insecure is not supported on naive outbound"),
            (
                "disable_sni",
                "disable_sni is not supported on naive outbound",
            ),
        ] {
            if obj.get("tls").and_then(|tls| tls.get(field)) == Some(&Value::Bool(true)) {
                return Err(format!("{at}: {message}"));
            }
        }
    }
    if ty == "http"
        && let Some(v) = obj.get("headers")
    {
        check_http_header(v, &format!("{at}.headers"), go_base, "headers")?;
    }
    if matches!(ty, "socks" | "shadowsocks" | "naive")
        && let Some(v) = obj.get("udp_over_tcp")
    {
        check_udp_over_tcp(v, &format!("{at}.udp_over_tcp"), go_base)?;
    }
    if matches!(ty, "shadowsocks" | "vmess" | "vless" | "trojan")
        && let Some(v) = obj.get("multiplex")
    {
        // the reference switches on the protocol name whatever `enabled` says
        if let Some(Value::String(protocol)) = v.get("protocol")
            && !matches!(protocol.as_str(), "" | "h2mux" | "smux" | "yamux")
        {
            return Err(format!("{at}: unknown protocol: {protocol}"));
        }
        check_out_multiplex(v, &format!("{at}.multiplex"), go_base)?;
    }
    if has_tls
        && let Some(tls) = obj.get("tls")
        && !tls.is_null()
    {
        if !tls.is_object() {
            return Err(go_field_err(
                &format!("{at}.tls"),
                tls,
                &format!("{go_base}.OutboundTLSOptionsContainer"),
                "tls",
                "option.OutboundTLSOptions",
            ));
        }
        validate_tls_container(tls, &format!("{at}.tls"), false)?;
    }
    check_dialer_fields(
        &at,
        &format!("initialize outbound[{i}] {ty}[{tag}]"),
        obj,
        go_base,
    )?;
    Ok(())
}

fn validate_direct_out_decode(i: usize, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let mut allowed: Vec<&str> = DIALER_OUT_FIELDS.to_vec();
    allowed.extend(DIRECT_OUT_FIELDS);
    allowed.extend(["type", "tag"]);
    reject_unknown_fields(obj, &allowed, &at)?;
    if let Some(v) = obj.get("proxy_protocol") {
        check_uint_field(
            v,
            &format!("{at}.proxy_protocol"),
            "_DirectOutboundOptions",
            "proxy_protocol",
            8,
        )?;
    }
    if let Some(v) = obj.get("override_address") {
        ep_str(
            v,
            &format!("{at}.override_address"),
            "_DirectOutboundOptions",
            "override_address",
        )?;
    }
    if let Some(v) = obj.get("override_port") {
        check_u16(v).map_err(|m| format!("{at}.override_port: {m}"))?;
    }
    check_dialer_fields(
        &at,
        &format!("initialize outbound[{i}] direct[{tag}]"),
        obj,
        "_DirectOutboundOptions",
    )?;
    //nolint:staticcheck
    let override_address = obj
        .get("override_address")
        .and_then(Value::as_str)
        .unwrap_or("");
    let override_port = obj
        .get("override_port")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if !override_address.is_empty() || override_port != 0 {
        return Err(format!(
            "{at}: destination override fields in direct outbound are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use route options instead"
        ));
    }
    Ok(())
}

fn validate_tor_out_decode(i: usize, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let mut allowed: Vec<&str> = DIALER_OUT_FIELDS.to_vec();
    allowed.extend(TOR_OUT_FIELDS);
    allowed.extend(["type", "tag"]);
    reject_unknown_fields(obj, &allowed, &at)?;
    for f in ["executable_path", "data_directory"] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), "TorOutboundOptions", f)?;
        }
    }
    if let Some(v) = obj.get("extra_args") {
        check_string_list(
            v,
            &format!("{at}.extra_args"),
            "TorOutboundOptions",
            "extra_args",
        )?;
    }
    if let Some(v) = obj.get("torrc")
        && !v.is_null()
    {
        let Some(m) = v.as_object() else {
            return Err(go_field_err(
                &format!("{at}.torrc"),
                v,
                "TorOutboundOptions",
                "torrc",
                "map[string]string",
            ));
        };
        for (k, item) in m {
            if !item.is_string() && !item.is_null() {
                return Err(go_field_err(
                    &format!("{at}.torrc.{k}"),
                    item,
                    "TorOutboundOptions",
                    "torrc",
                    "string",
                ));
            }
        }
    }
    check_dialer_fields(
        &at,
        &format!("initialize outbound[{i}] tor[{tag}]"),
        obj,
        "TorOutboundOptions",
    )?;
    Ok(())
}

/// Official `CensorshipStrategy::kSniRealityMode*` reality profiles as
/// (`reality_<name>`, official enum name) pairs; the strategy numbers
/// (20..=24, 60..=62, 80..=83, 100, 101) are accepted numerically.
const FPTN_REALITY_PROFILES: &[(&str, &str)] = &[
    ("reality_chrome145", "kSniRealityModeChrome145"),
    ("reality_chrome146", "kSniRealityModeChrome146"),
    ("reality_chrome147", "kSniRealityModeChrome147"),
    ("reality_chrome148", "kSniRealityModeChrome148"),
    ("reality_chrome149", "kSniRealityModeChrome149"),
    ("reality_firefox149", "kSniRealityModeFirefox149"),
    ("reality_firefox150", "kSniRealityModeFirefox150"),
    ("reality_firefox151", "kSniRealityModeFirefox151"),
    ("reality_yandex24", "kSniRealityModeYandex24"),
    ("reality_yandex25", "kSniRealityModeYandex25"),
    ("reality_yandex26_3", "kSniRealityModeYandex26_3"),
    ("reality_yandex26_4", "kSniRealityModeYandex26_4"),
    ("reality_safari26_4", "kSniRealityModeSafari26_4"),
    ("reality_safari26_5", "kSniRealityModeSafari26_5"),
];

/// Censorship strategy knob shared by both fptn forms (token and server).
fn check_fptn_obfuscation(obj: &Map<String, Value>, at: &str) -> Result<(), String> {
    let Some(v) = obj.get("obfuscation").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let raw = match v.as_str() {
        Some(s) => s,
        None => return Err(format!("{at}.obfuscation: must be a string")),
    };
    let reality = match raw {
        "tls" | "tls_obfuscator" | "kTlsObfuscator" | "1" | "none" | "sni" | "kSni" | "0" => false,
        "reality" => true,
        "kSniRealityMode" | "2" => {
            return Err(format!(
                "{at}.obfuscation: reality mode 1 (kSniRealityMode) is deprecated in \
                 the reference client; use \"reality\" (mode 2)"
            ));
        }
        other => {
            if FPTN_REALITY_PROFILES
                .iter()
                .any(|(alias, official)| *alias == other || *official == other)
            {
                true
            } else if let Ok(n) = other.parse::<u16>() {
                matches!(n, 20..=24 | 60..=62 | 80..=83 | 100 | 101)
            } else {
                return Err(format!(
                    "{at}.obfuscation: invalid value (expected \"tls\", \"none\", \
                     \"reality\" or a reality profile such as \"reality_chrome149\")"
                ));
            }
        }
    };
    if reality && let Some(sv) = obj.get("sni").filter(|sv| !sv.is_null()) {
        // The decoy ClientHello needs a capture-length SNI (4..=64, the
        // template tables' entry range); an absent sni still resolves to a
        // hostname server name at runtime and is checked there.
        let sni = sv
            .as_str()
            .ok_or_else(|| format!("{at}.sni: must be a string"))?;
        if !(4..=64).contains(&sni.len()) {
            return Err(format!(
                "{at}: reality obfuscation needs sni of 4..=64 bytes, got {}",
                sni.len()
            ));
        }
    }
    Ok(())
}

fn validate_mieru_out(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let mut allowed: Vec<&str> = vec![
        "type",
        "tag",
        "server",
        "server_port",
        "server_ports",
        "transport",
        "username",
        "password",
        "multiplexing",
        "traffic_pattern",
    ];
    allowed.extend_from_slice(DIALER_OUT_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;
    match obj.get("server") {
        Some(Value::String(s)) if !s.is_empty() => {}
        Some(Value::String(_)) | None | Some(Value::Null) => {
            return Err(format!("{at}: missing server"));
        }
        Some(_) => return Err(format!("{at}.server: must be a string")),
    }
    if matches!(obj.get("server_port"), None | Some(Value::Null))
        && matches!(obj.get("server_ports"), None | Some(Value::Null))
    {
        return Err(format!("{at}: missing server_port"));
    }
    for field in ["username", "password"] {
        match obj.get(field) {
            Some(Value::String(s)) if !s.is_empty() => {}
            Some(Value::String(_)) | None | Some(Value::Null) => {
                return Err(format!("{at}: missing {field}"));
            }
            Some(_) => return Err(format!("{at}.{field}: must be a string")),
        }
    }
    match obj.get("transport") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s == "TCP" || s == "UDP" => {}
        Some(_) => return Err(format!("{at}.transport: must be TCP or UDP")),
    }
    Ok(())
}

fn validate_fptn_out_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    check_fptn_obfuscation(obj, &at)?;
    if let Some(v) = obj.get("sni").filter(|v| !v.is_null())
        && !v.is_string()
    {
        return Err(format!("{at}.sni: must be a string"));
    }
    if let Some(v) = obj.get("mtu").filter(|v| !v.is_null())
        && !v.is_u64()
    {
        return Err(format!("{at}.mtu: must be an integer"));
    }
    if let Some(v) = obj.get("network_list") {
        check_network_list(v, &format!("{at}.network_list"), "FPTNOutboundOptions")?;
    }
    if !obj.contains_key("server") {
        let mut allowed: Vec<&str> = vec!["type", "tag", "token"];
        allowed.extend_from_slice(DIALER_OUT_FIELDS);
        // Set-once knobs copied to every expanded member by `fptn::expand`.
        allowed.extend_from_slice(&["obfuscation", "sni", "mtu", "network_list"]);
        reject_unknown_fields(obj, &allowed, &at)?;
        match obj.get("token") {
            Some(Value::String(s)) if !s.is_empty() => {}
            Some(Value::String(_)) | None | Some(Value::Null) => {
                return Err(format!("{at}: missing token"));
            }
            Some(_) => return Err(format!("{at}.token: must be a string")),
        }
        return Ok(());
    }
    let mut allowed: Vec<&str> = vec![
        "type",
        "tag",
        "server",
        "server_port",
        "username",
        "password",
        "md5_fingerprint",
        "sni",
        "mtu",
        "network_list",
        "obfuscation",
    ];
    allowed.extend_from_slice(DIALER_OUT_FIELDS);
    reject_unknown_fields(obj, &allowed, &at)?;
    match obj.get("server") {
        Some(Value::String(s)) if !s.is_empty() => {}
        Some(Value::String(_)) | None | Some(Value::Null) => {
            return Err(format!("{at}: missing server"));
        }
        Some(_) => return Err(format!("{at}.server: must be a string")),
    }
    if matches!(obj.get("server_port"), None | Some(Value::Null)) {
        return Err(format!("{at}: missing server_port"));
    }
    for field in ["username", "password"] {
        match obj.get(field) {
            Some(Value::String(s)) if !s.is_empty() => {}
            Some(Value::String(_)) | None | Some(Value::Null) => {
                return Err(format!("{at}: missing {field}"));
            }
            Some(_) => return Err(format!("{at}.{field}: must be a string")),
        }
    }
    if let Some(v) = obj.get("md5_fingerprint").filter(|v| !v.is_null())
        && !v.is_string()
    {
        return Err(format!("{at}.md5_fingerprint: must be a string"));
    }
    Ok(())
}

fn validate_group_out_decode(i: usize, ty: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("outbounds[{i}]");
    let allowed: &[&str] = match ty {
        "selector" => SELECTOR_OUT_FIELDS,
        "urltest" => URLTEST_OUT_FIELDS,
        _ => CHAIN_OUT_FIELDS,
    };
    reject_unknown_fields(obj, allowed, &at)?;
    if let Some(v) = obj.get("outbounds") {
        let go_struct = match ty {
            "selector" => "SelectorOutboundOptions",
            "urltest" => "URLTestOutboundOptions",
            _ => "ChainOutboundOptions",
        };
        check_string_list(v, &format!("{at}.outbounds"), go_struct, "outbounds")?;
    }
    match ty {
        "selector" => {
            if let Some(v) = obj.get("default") {
                ep_str(
                    v,
                    &format!("{at}.default"),
                    "SelectorOutboundOptions",
                    "default",
                )?;
            }
            if let Some(v) = obj.get("interrupt_exist_connections") {
                ep_bool(
                    v,
                    &format!("{at}.interrupt_exist_connections"),
                    "SelectorOutboundOptions",
                    "interrupt_exist_connections",
                )?;
            }
        }
        "urltest" => {
            for f in ["url", "mode"] {
                if let Some(v) = obj.get(f) {
                    ep_str(v, &format!("{at}.{f}"), "URLTestOutboundOptions", f)?;
                }
            }
            for f in ["interval", "idle_timeout"] {
                if let Some(v) = obj.get(f) {
                    check_duration_field(v, &format!("{at}.{f}"), "URLTestOutboundOptions", f)?;
                }
            }
            if let Some(v) = obj.get("tolerance") {
                check_u16(v).map_err(|m| format!("{at}.tolerance: {m}"))?;
            }
            if let Some(v) = obj.get("interrupt_exist_connections") {
                ep_bool(
                    v,
                    &format!("{at}.interrupt_exist_connections"),
                    "URLTestOutboundOptions",
                    "interrupt_exist_connections",
                )?;
            }
            if let Some(bal) = obj.get("balancer")
                && !bal.is_null()
            {
                let bat = format!("{at}.balancer");
                if !bal.is_object() {
                    return Err(go_field_err(
                        &bat,
                        bal,
                        "URLTestOutboundOptions",
                        "balancer",
                        "option.URLTestBalancerOptions",
                    ));
                }
                let bm = bal.as_object().expect("checked above");
                reject_unknown_fields(bm, &["pool", "pool_tolerance", "sticky_hash"], &bat)?;
                if let Some(v) = bm.get("pool") {
                    check_int_field(v, &format!("{bat}.pool"), "URLTestBalancerOptions", "pool")?;
                }
                if let Some(v) = bm.get("pool_tolerance") {
                    check_u16(v).map_err(|m| format!("{bat}.pool_tolerance: {m}"))?;
                }
                if let Some(v) = bm.get("sticky_hash") {
                    let gs = "URLTestBalancerOptions.balancer.sticky_hash";
                    match v {
                        Value::Array(items) => {
                            for (idx, item) in items.iter().enumerate() {
                                if !item.is_string() && !item.is_null() {
                                    return Err(format!(
                                        "{bat}.sticky_hash[{idx}]: json: cannot unmarshal {} into Go struct field {gs} of type string",
                                        json_kind(item)
                                    ));
                                }
                            }
                        }
                        Value::Null => {}
                        other => {
                            return Err(format!(
                                "{bat}.sticky_hash: json: cannot unmarshal {} into Go struct field {gs} of type []string",
                                json_kind(other)
                            ));
                        }
                    }
                }
            }
        }
        _ => {
            if let Some(v) = obj.get("idle_timeout") {
                check_duration_field(
                    v,
                    &format!("{at}.idle_timeout"),
                    "ChainOutboundOptions",
                    "idle_timeout",
                )?;
            }
            if let Some(v) = obj.get("interrupt_exist_connections") {
                ep_bool(
                    v,
                    &format!("{at}.interrupt_exist_connections"),
                    "ChainOutboundOptions",
                    "interrupt_exist_connections",
                )?;
            }
            if let Some(v) = obj.get("strip_evasion") {
                ep_bool(
                    v,
                    &format!("{at}.strip_evasion"),
                    "ChainOutboundOptions",
                    "strip_evasion",
                )?;
            }
            for f in ["strip", "rewrite"] {
                if let Some(v) = obj.get(f)
                    && !v.is_null()
                {
                    let Some(m) = v.as_object() else {
                        return Err(go_field_err(
                            &format!("{at}.{f}"),
                            v,
                            "ChainOutboundOptions",
                            f,
                            "value",
                        ));
                    };
                    // strip values are map[string]bool; rewrite values are
                    // opaque to the reference decode (no kind check).
                    if f == "strip" {
                        for (k, item) in m {
                            if !item.is_boolean() && !item.is_null() {
                                return Err(go_field_err(
                                    &format!("{at}.strip[\"{k}\"]"),
                                    item,
                                    "ChainOutboundOptions",
                                    "strip",
                                    "bool",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
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
        "anytls" => validate_anytls_out_decode(i, tag, obj)?,
        "snell" => validate_snell_out_decode(i, tag, obj)?,
        "fptn" => validate_fptn_out_decode(i, obj)?,
        "mieru" => validate_mieru_out(i, obj)?,
        "socks" | "http" | "shadowsocks" | "shadowtls" | "vmess" | "vless" | "trojan"
        | "hysteria" | "naive" | "ssh" => {
            validate_plain_out_decode(i, ty, tag, obj)?;
            if ty == "vless" {
                validate_vless_encryption(obj)?;
            }
        }
        "direct" => validate_direct_out_decode(i, tag, obj)?,
        "bridge" => {
            reject_unknown_fields(obj, BRIDGE_OUT_FIELDS, &format!("outbounds[{i}]"))?;
            for field in ["iproute2_table_index", "iproute2_rule_index"] {
                if let Some(value) = obj.get(field).filter(|v| !prunes_value(v)) {
                    check_int_field(
                        value,
                        &format!("outbounds[{i}].{field}"),
                        "BridgeOutboundOptions",
                        field,
                    )?;
                }
            }
        }
        "block" => {
            reject_unknown_fields(obj, &["type", "tag"], &format!("outbounds[{i}]"))?;
        }
        "tor" => validate_tor_out_decode(i, tag, obj)?,
        "selector" | "urltest" | "chain" => validate_group_out_decode(i, ty, obj)?,
        _ => {}
    }
    if let Some(base) = SERVER_OUT_BASES
        .iter()
        .find(|(t, _)| *t == ty)
        .map(|(_, b)| *b)
        && let Some(v) = obj.get("server")
    {
        ep_str(
            v,
            &format!("outbounds[{i}].server"),
            &format!("{base}.ServerOptions"),
            "server",
        )?;
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

    if let Some(transport) = obj.get("transport").filter(|_| ty != "mieru") {
        let go_struct = SERVER_OUT_BASES
            .iter()
            .find(|(known, _)| *known == ty)
            .map(|(_, name)| *name)
            .unwrap_or("V2RayOutboundOptions");
        let transport = transport.as_object().ok_or_else(|| {
            go_type_error(
                transport,
                &format!("outbounds[{i}].transport"),
                go_struct,
                "transport",
                "option._V2RayTransportOptions",
            )
        })?;
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
        } else if matches!(
            transport_ty,
            "http" | "ws" | "quic" | "grpc" | "httpupgrade"
        ) {
            validate_v2ray_transport(
                transport_ty,
                transport,
                &format!("outbounds[{i}].transport"),
            )?;
        }
    }

    if TLS_REQUIRED_OUTBOUNDS.contains(&ty) && !tls_enabled(obj.get("tls")) {
        return Err(format!("{at}: TLS required"));
    }

    match ty {
        "socks" => {
            if let Some(Value::String(s)) = obj.get("version")
                && !matches!(s.as_str(), "" | "4" | "4a" | "5")
            {
                return Err(format!("{at}: unknown socks version: {s}"));
            }
        }
        "vmess" => {
            if let Some(Value::String(s)) = obj.get("security")
                && !matches!(
                    s.as_str(),
                    "" | "auto" | "zero" | "none" | "aes-128-gcm" | "chacha20-poly1305"
                )
            {
                return Err(format!("{at}: vmess: unsupported security type: {s}"));
            }
            if let Some(Value::String(s)) = obj.get("packet_encoding")
                && !matches!(s.as_str(), "" | "packetaddr" | "xudp")
            {
                return Err(format!("{at}: unknown packet encoding: {s}"));
            }
        }
        "vless" => {
            if let Some(Value::String(s)) = obj.get("packet_encoding")
                && !matches!(s.as_str(), "" | "packetaddr" | "xudp")
            {
                return Err(format!("{at}: unknown packet encoding: {s}"));
            }
        }
        "urltest" => {
            if let Some(Value::String(s)) = obj.get("mode")
                && !matches!(s.as_str(), "" | "least_test" | "round_robin")
            {
                return Err(format!("{at}: unknown urltest mode: {s}"));
            }
            let mode = obj.get("mode").and_then(Value::as_str).unwrap_or("");
            if let Some(bal) = obj.get("balancer")
                && !bal.is_null()
            {
                // reference badjson round-trip: `{}` and `{"sticky_hash": []}`
                // collapse to an absent balancer pointer; any other key means
                // the balancer is present.
                let bm = bal.as_object().expect("decode checked above");
                let present = !bm.is_empty()
                    && !(bm.len() == 1
                        && matches!(bm.get("sticky_hash"), Some(Value::Array(a)) if a.is_empty()));
                if mode != "round_robin" {
                    if present {
                        return Err(format!(
                            "{at}: urltest: balancer is only valid with mode: round_robin"
                        ));
                    }
                } else if present {
                    if let Some(n) = bm.get("pool").and_then(Value::as_i64)
                        && n < 0
                    {
                        return Err(format!("{at}: urltest balancer.pool must be >= 1"));
                    }
                    if let Some(Value::Array(items)) = bm.get("sticky_hash") {
                        let mut vals: Vec<&str> = Vec::new();
                        for item in items {
                            vals.push(match item {
                                Value::String(s) => s.as_str(),
                                _ => "",
                            });
                        }
                        let none_ok = vals.len() == 1 && vals[0] == "none";
                        if !vals.is_empty() && !none_ok {
                            for c in &vals {
                                if *c == "none" {
                                    return Err(format!(
                                        "{at}: urltest sticky_hash: \"none\" must be the only component (it disables stickiness)"
                                    ));
                                }
                                if !matches!(
                                    *c,
                                    "process" | "domain" | "source_ip" | "dest_ip" | "dest_port"
                                ) {
                                    return Err(format!(
                                        "{at}: unknown urltest sticky_hash component: {c}"
                                    ));
                                }
                            }
                        }
                    }
                    if let Some(n) = bm.get("pool_tolerance").and_then(Value::as_u64)
                        && n > 15000
                    {
                        return Err(format!(
                            "{at}: urltest balancer.pool_tolerance is in milliseconds and must be <= 15000 (alive delays cap at the 15s probe timeout); use 0 for first-live mode"
                        ));
                    }
                }
            }
        }
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
        "fptn" | "mieru" => {
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
        "direct" => {
            // reference NewOutbound: detour is rejected in direct context.
            if obj
                .get("detour")
                .and_then(Value::as_str)
                .is_some_and(|d| !d.is_empty())
            {
                return Err(format!("{at}: `detour` is not supported in direct context"));
            }
            if let Some(Value::Number(n)) = obj.get("proxy_protocol")
                && n.as_u64().is_some_and(|v| v != 0)
            {
                return Err(format!(
                    "{at}: Proxy Protocol is deprecated and removed in sing-box 1.6.0"
                ));
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
            if let Some(Value::Object(m)) = obj.get("strip") {
                const STRIP_KEYS: &[&str] = &[
                    "multiplex.padding",
                    "tls.fragment",
                    "tls.utls",
                    "xhttp.padding",
                ];
                for k in m.keys() {
                    if !STRIP_KEYS.contains(&k.as_str()) {
                        return Err(format!(
                            "{at}: strip: unknown key {k} (known: {})",
                            STRIP_KEYS.join(", ")
                        ));
                    }
                }
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
        "snell" => {
            // reference NewOutbound: obfs/mode parse, then psk, then userkey.
            if snell_version(obj) == 4 {
                let raw = obj.get("obfs_mode").and_then(Value::as_str).unwrap_or("");
                if !matches!(raw.to_lowercase().as_str(), "" | "none" | "http" | "tls") {
                    return Err(format!("{at}: snell: unknown obfs mode: {raw}"));
                }
            } else {
                let raw = obj.get("mode").and_then(Value::as_str).unwrap_or("");
                if !matches!(raw, "" | "default" | "unshaped" | "unsafe-raw") {
                    return Err(format!("{at}: snell: unknown v6 mode: {raw}"));
                }
            }
            let psk = obj.get("psk").and_then(Value::as_str).unwrap_or("");
            if psk.is_empty() {
                return Err(format!("{at}: snell: missing pre-shared key"));
            }
            if obj
                .get("userkey")
                .and_then(Value::as_str)
                .is_some_and(|k| k.len() > 255)
            {
                return Err(format!("{at}: snell: user key too long"));
            }
        }
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

/// Go `syscall.Errno.Error()` on Windows comes from a hardcoded English table,
/// not from the (localized) system message text Rust would print.
#[cfg(windows)]
fn go_os_error_text(code: i32) -> Option<&'static str> {
    Some(match code {
        1 => "Incorrect function.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        5 => "Access is denied.",
        21 => "The device is not ready.",
        32 => "The process cannot access the file because it is being used by another process.",
        53 => "The network path was not found.",
        67 => "The network name cannot be found.",
        80 => "Cannot create a file when that file already exists.",
        123 => "The filename, directory name, or volume label syntax is incorrect.",
        145 => "The directory is not empty.",
        206 => "The filename or extension is too long.",
        267 => "The directory name is invalid.",
        995 => {
            "The I/O operation was aborted because either the application has called the Abort function or the I/O operation has been canceled."
        }
        _ => return None,
    })
}

#[cfg(not(windows))]
fn go_os_error_text(_code: i32) -> Option<&'static str> {
    None
}

/// Go `*fs.PathError`: `<op> <path>: <error>`. Go reports the bare syscall
/// message, so the Rust " (os error N)" suffix goes away and the unix
/// `strerror` text (already lowercased by Go) is lowercased here as well.
fn go_path_error(op: &str, path: &str, err: &std::io::Error) -> String {
    let text = match err.raw_os_error().and_then(go_os_error_text) {
        Some(known) => known.to_string(),
        None => {
            let raw = err.to_string();
            let raw = match raw.rfind(" (os error ") {
                Some(index) => raw[..index].to_string(),
                None => raw,
            };
            if cfg!(windows) {
                raw
            } else {
                let mut chars = raw.chars();
                match chars.next() {
                    Some(first) => {
                        let lowered: String = first.to_lowercase().collect();
                        lowered + chars.as_str()
                    }
                    None => raw,
                }
            }
        }
    };
    format!("{op} {path}: {text}")
}

/// reference `filemanager.ReadFile` at check time: the server certificate and
/// key are read while the TLS server config is built, so a missing file fails
/// `check` exactly like the reference does. Go reports `open` for a failed
/// open and `read` for a failed read (a directory opens fine, reading does not).
fn read_tls_file(path: &str, at: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|err| {
        if std::fs::metadata(path).is_ok_and(|meta| meta.is_dir()) {
            // Go opens the directory and only fails while reading it
            let text = if cfg!(windows) {
                "Incorrect function."
            } else {
                "is a directory"
            };
            return format!("{at}: read certificate: read {path}: {text}");
        }
        format!(
            "{at}: read certificate: {}",
            go_path_error("open", path, &err)
        )
    })?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|err| {
        format!(
            "{at}: read certificate: {}",
            go_path_error("read", path, &err)
        )
    })?;
    Ok(data)
}

/// Go `pem.Decode` blocks that base64-decode; blocks with broken base64 are
/// skipped entirely, matching the decoder.
fn pem_blocks(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &str = "-----END ";
    let mut blocks = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = data[offset..]
        .windows(BEGIN.len())
        .position(|window| window == BEGIN)
    {
        let head = offset + found + BEGIN.len();
        let Some(label_end) = data[head..].windows(5).position(|w| w == b"-----") else {
            break;
        };
        let label = match std::str::from_utf8(&data[head..head + label_end]) {
            Ok(text) => text.to_string(),
            Err(_) => break,
        };
        let body = head + label_end + 5;
        let tail = format!("{END}{label}-----");
        let Some(found_end) = data[body..]
            .windows(tail.len())
            .position(|window| window == tail.as_bytes())
        else {
            break;
        };
        let encoded: String = data[body..body + found_end]
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| *byte as char)
            .collect();
        if let Some(der) = decode_base64_std(&encoded) {
            blocks.push((label, der));
        }
        offset = body + found_end + tail.len();
    }
    blocks
}

/// Minimal DER shape check: one SEQUENCE with at least one element.
fn der_is_sequence(der: &[u8]) -> bool {
    !der.is_empty() && der[0] == 0x30
}

/// Go `x509.ParseCertificate` on something that is not a certificate reports
/// "x509: malformed certificate"; the inner signature algorithm and signature
/// are checked here, which covers truncated and non-DER input.
fn der_is_certificate(der: &[u8]) -> bool {
    let Some(children) = der_children(der) else {
        return false;
    };
    children.len() == 3
        && children[0].0 == 0x30
        && children[1].0 == 0x30
        && children[2].0 == 0x03
        && der_children(children[0].2).is_some()
}

/// `SEQUENCE { INTEGER version, ... }` covers PKCS#1, PKCS#8 and SEC1 keys.
fn der_is_private_key(der: &[u8]) -> bool {
    let Some(children) = der_children(der) else {
        return false;
    };
    children.len() >= 2 && children[0].0 == 0x02
}

/// SEQUENCE children as `(tag, content, whole element)`.
type DerChildren<'a> = Vec<(u8, &'a [u8], &'a [u8])>;

fn der_children(der: &[u8]) -> Option<DerChildren<'_>> {
    if !der_is_sequence(der) {
        return None;
    }
    let mut cursor = 1usize;
    // length octets
    let first = *der.get(cursor)?;
    if first & 0x80 == 0 {
        cursor += 1;
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        cursor += 1 + count;
    }
    let mut children = Vec::new();
    while cursor < der.len() {
        let element_start = cursor;
        let tag = der[cursor];
        cursor += 1;
        let first = *der.get(cursor)?;
        let (length, header) = if first & 0x80 == 0 {
            (first as usize, 1usize)
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return None;
            }
            let mut value = 0usize;
            for byte in der.get(cursor + 1..cursor + 1 + count)? {
                value = (value << 8) | *byte as usize;
            }
            (value, 1 + count)
        };
        let start = cursor + header;
        let end = start.checked_add(length)?;
        let content = der.get(start..end)?;
        children.push((tag, content, &der[element_start..end]));
        cursor = end;
    }
    Some(children)
}

/// reference `crypto/tls.X509KeyPair`, restricted to the PEM shapes and the
/// shallow DER checks that cover truncated, swapped and garbage inputs. The
/// public/private key comparison is not part of `check` parity yet.
/// reference `option.CertificateProviderOptions` plus the inline providers
/// registered by this build (`acme`, `tailscale`).
fn validate_certificate_provider(value: &Value, at: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    // a bare string is a shared provider tag reference
    let Some(provider) = value.as_object() else {
        return match value.as_str() {
            Some(_) => Ok(()),
            None => Err(format!(
                "{at}: json: cannot unmarshal {} into Go value of type option.CertificateProviderOptions",
                json_kind(value)
            )),
        };
    };
    if provider.is_empty() {
        return Ok(());
    }
    let ty = match provider.get("type") {
        None | Some(Value::Null) => {
            return Err(format!("{at}: missing certificate provider type"));
        }
        Some(Value::String(text)) => text.as_str(),
        Some(other) => {
            return Err(format!(
                "{at}.type: json: cannot unmarshal {} into Go struct field _CertificateProviderInline.type of type string",
                json_kind(other)
            ));
        }
    };
    match ty {
        "acme" => {
            const ACME_FIELDS: &[&str] = &[
                "type",
                "domain",
                "data_directory",
                "default_server_name",
                "email",
                "provider",
                "account_key",
                "disable_http_challenge",
                "disable_tls_alpn_challenge",
                "alternative_http_port",
                "alternative_tls_port",
                "external_account",
                "dns01_challenge",
                "http_challenge",
                "challenges",
            ];
            reject_unknown_fields(provider, ACME_FIELDS, at)?;
            for field in ["domain", "default_server_name"] {
                if let Some(list) = provider.get(field).filter(|v| !prunes_value(v)) {
                    // badoption.Listable[string]
                    match list {
                        Value::String(_) => {}
                        Value::Array(items) => {
                            for (index, item) in items.iter().enumerate() {
                                if !item.is_string() {
                                    return Err(format!(
                                        "{at}.{field}[{index}]: json: cannot unmarshal {} into Go value of type string",
                                        json_kind(item)
                                    ));
                                }
                            }
                        }
                        other => {
                            return Err(format!(
                                "{at}.{field}: json: cannot unmarshal {} into Go value of type string",
                                json_kind(other)
                            ));
                        }
                    }
                }
            }
            for field in ["data_directory", "email", "provider", "account_key"] {
                if let Some(text) = provider.get(field).filter(|v| !prunes_value(v)) {
                    ep_str(
                        text,
                        &format!("{at}.{field}"),
                        "ACMECertificateProviderOptions",
                        field,
                    )?;
                }
            }
            for field in ["disable_http_challenge", "disable_tls_alpn_challenge"] {
                if let Some(flag) = provider.get(field).filter(|v| !prunes_value(v)) {
                    check_bool_field(
                        flag,
                        &format!("{at}.{field}"),
                        "ACMECertificateProviderOptions",
                        field,
                    )?;
                }
            }
            for field in ["alternative_http_port", "alternative_tls_port"] {
                if let Some(port) = provider.get(field).filter(|v| !prunes_value(v)) {
                    if let Some(number) = port.as_u64() {
                        if number > u64::from(u16::MAX) {
                            return Err(format!(
                                "{at}.{field}: json: cannot unmarshal number {number} into Go struct field ACMECertificateProviderOptions.{field} of type uint16"
                            ));
                        }
                    } else {
                        return Err(format!(
                            "{at}.{field}: json: cannot unmarshal {} into Go struct field ACMECertificateProviderOptions.{field} of type uint16",
                            json_kind(port)
                        ));
                    }
                }
            }
            if let Some(account) = provider
                .get("external_account")
                .filter(|v| !prunes_value(v))
            {
                let account = account.as_object().ok_or_else(|| {
                    format!("{at}.external_account: json: cannot unmarshal {} into Go value of type option.ACMEExternalAccountOptions", json_kind(account))
                })?;
                reject_unknown_fields(
                    account,
                    ACME_EXTERNAL_ACCOUNT_FIELDS,
                    &format!("{at}.external_account"),
                )?;
            }
            for field in ["dns01_challenge", "http_challenge"] {
                if let Some(challenge) = provider.get(field).filter(|v| !prunes_value(v)) {
                    let challenge = challenge.as_object().ok_or_else(|| {
                        format!("{at}.{field}: json: cannot unmarshal {} into Go value of type option.ACMEProviderOptions", json_kind(challenge))
                    })?;
                    reject_unknown_fields(
                        challenge,
                        ACME_PROVIDER_FIELDS,
                        &format!("{at}.{field}"),
                    )?;
                    validate_acme_dns01(challenge, &format!("{at}.{field}.dns01"))?;
                }
            }
            if let Some(challenges) = provider.get("challenges").filter(|v| !prunes_value(v)) {
                let entries = challenges.as_array().ok_or_else(|| {
                    format!("{at}.challenges: json: cannot unmarshal {} into Go value of type []option.ACMEChallengeOptions", json_kind(challenges))
                })?;
                for (index, entry) in entries.iter().enumerate() {
                    let entry = entry.as_object().ok_or_else(|| {
                        format!("{at}.challenges[{index}]: json: cannot unmarshal {} into Go value of type option.ACMEChallengeOptions", json_kind(entry))
                    })?;
                    reject_unknown_fields(
                        entry,
                        ACME_PROVIDER_FIELDS,
                        &format!("{at}.challenges[{index}]"),
                    )?;
                    validate_acme_dns01(entry, &format!("{at}.challenges[{index}].dns01"))?;
                }
            }
        }
        "tailscale" => {
            const TAILSCALE_FIELDS: &[&str] = &["type", "endpoint"];
            reject_unknown_fields(provider, TAILSCALE_FIELDS, at)?;
            if let Some(endpoint) = provider.get("endpoint").filter(|v| !prunes_value(v)) {
                ep_str(
                    endpoint,
                    &format!("{at}.endpoint"),
                    "TailscaleCertificateProviderOptions",
                    "endpoint",
                )?;
            }
        }
        other => {
            return Err(format!("{at}: unknown certificate provider type: {other}"));
        }
    }
    Ok(())
}

/// `option.ACMEProviderDNS01ChallengeOptions`: the shape is picked by the
/// `provider` name, so the fields are validated against that choice.
fn validate_acme_dns01(challenge: &Map<String, Value>, at: &str) -> Result<(), String> {
    let Some(entry) = challenge.get("dns01").filter(|v| !prunes_value(v)) else {
        return Ok(());
    };
    let entry = entry.as_object().ok_or_else(|| {
        format!(
            "{at}: json: cannot unmarshal {} into Go value of type string",
            json_kind(entry)
        )
    })?;
    let provider = entry
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let allowed = match ACME_DNS01_PROVIDERS
        .iter()
        .find(|(name, _)| *name == provider)
    {
        Some((_, fields)) => fields,
        None => return Ok(()),
    };
    let mut all: Vec<&str> = allowed.to_vec();
    all.extend(ACME_DNS01_FIELDS);
    reject_unknown_fields(entry, &all, at)?;
    Ok(())
}

/// reference `common/tls.newCertificateProvider`: the inline providers of this
/// build fail fast, and the tailscale one needs a live endpoint tag.
fn acme_provider_init_error(ty: &str, tls: &Map<String, Value>) -> Option<String> {
    let prefix = "create inline certificate provider";
    match ty {
        "acme" => Some(format!(
            "{prefix}: ACME is not included in this build, rebuild with -tags with_acme"
        )),
        "tailscale" => {
            let endpoint = tls
                .get("certificate_provider")
                .and_then(Value::as_object)
                .and_then(|provider| provider.get("endpoint"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if endpoint.is_empty() {
                return Some(format!("{prefix}: missing tailscale endpoint tag"));
            }
            Some(format!("{prefix}: endpoint not found: {endpoint}"))
        }
        _ => None,
    }
}

fn tls_key_pair_error(certificate: &[u8], key: &[u8]) -> Option<String> {
    let cert_blocks = pem_blocks(certificate);
    if cert_blocks.is_empty() {
        return Some("tls: failed to find any PEM data in certificate input".to_string());
    }
    let cert_block = cert_blocks.iter().find(|(label, _)| label == "CERTIFICATE");
    let Some((_, der)) = cert_block else {
        if cert_blocks
            .iter()
            .any(|(label, _)| label.ends_with("PRIVATE KEY"))
        {
            return Some("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched".to_string());
        }
        let skipped: Vec<&str> = cert_blocks
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        return Some(format!(
            "tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: [{}]",
            skipped.join(" ")
        ));
    };
    if !der_is_certificate(der) {
        return Some("x509: malformed certificate".to_string());
    }
    let key_blocks = pem_blocks(key);
    if key_blocks.is_empty() {
        return Some("tls: failed to find any PEM data in key input".to_string());
    }
    let key_block = key_blocks
        .iter()
        .find(|(label, _)| label.ends_with("PRIVATE KEY"));
    let Some((_, der)) = key_block else {
        // the hint only fires when the very first block is a certificate
        if key_blocks
            .first()
            .is_some_and(|(label, _)| label == "CERTIFICATE")
        {
            return Some(
                "tls: found a certificate rather than a key in the PEM for the private key"
                    .to_string(),
            );
        }
        let skipped: Vec<&str> = key_blocks.iter().map(|(label, _)| label.as_str()).collect();
        return Some(format!(
            "tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: [{}]",
            skipped.join(" ")
        ));
    };
    if !der_is_private_key(der) {
        return Some("tls: failed to parse private key".to_string());
    }
    None
}

/// reference `option.ACMEExternalAccountOptions`.
const ACME_EXTERNAL_ACCOUNT_FIELDS: &[&str] = &["key_id", "hmac"];

/// reference `option.ACMEProviderDNS01ChallengeOptions`: the provider name
/// selects one of the registered challenge options.
const ACME_DNS01_PROVIDERS: &[(&str, &[&str])] = &[
    (
        "cloudflare",
        &["token", "account_id", "zone_id", "service_token"],
    ),
    ("alidns", &["access_key_id", "access_key_secret"]),
    ("duckdns", &["token"]),
    ("google cloud dns", &["service_account_json", "project_id"]),
    (
        "azure",
        &[
            "environment",
            "client_id",
            "client_secret",
            "subscription_id",
            "resource_group",
            "user_agent",
        ],
    ),
    (
        "rfc2136",
        &[
            "address",
            "name",
            "key",
            "key_algorithm",
            "key_name",
            "key_secret",
        ],
    ),
    ("acme dns", &["name_server", "provider"]),
    ("http", &["endpoint", "ip_address"]),
    ("local", &["path"]),
];

/// reference `option.ACMEProviderOptions` (the inline ACME challenge set).
const ACME_PROVIDER_FIELDS: &[&str] = &["http", "dns01", "ip"];

/// reference `option.ACMEProviderDNS01ChallengeOptions` common fields.
const ACME_DNS01_FIELDS: &[&str] = &["provider", "disable_glob"];

/// reference `common/tls.NewSTDServer`: a `certificate_provider` or an inline
/// `acme` block with a domain supplies the certificate, and `insecure` generates
/// a throwaway key pair instead. Every other server needs a non-empty
/// certificate and key (the reference compares values, not key presence).
fn validate_server_tls(tls: &Value, at: &str, field_at: &str) -> Result<(), String> {
    let tls = tls
        .as_object()
        .ok_or_else(|| format!("{at}: tls: must be a JSON object"))?;
    if let Some(value) = tls.get("certificate_provider").filter(|v| !prunes_value(v)) {
        validate_certificate_provider(value, &format!("{field_at}.certificate_provider"))?;
    }
    let provider = tls
        .get("certificate_provider")
        .is_some_and(|value| !prunes_value(value));
    let acme = tls.get("acme").is_some_and(|value| !prunes_value(value));
    if provider && acme {
        return Err(format!(
            "{at}: certificate_provider and acme are mutually exclusive"
        ));
    }
    if provider {
        // the inline provider is built first, and only then does `insecure`
        // have nothing left to attach to
        if let Some(ty) = tls
            .get("certificate_provider")
            .and_then(Value::as_object)
            .and_then(|provider| provider.get("type"))
            .and_then(Value::as_str)
            && let Some(message) = acme_provider_init_error(ty, tls)
        {
            return Err(format!("{at}: {message}"));
        }
        if tls.get("insecure").and_then(Value::as_bool) == Some(true) {
            return Err(format!("{at}: tls: insecure unused"));
        }
        return Ok(());
    }
    let insecure = tls
        .get("insecure")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let acme_domain = tls
        .get("acme")
        .and_then(Value::as_object)
        .is_some_and(|acme| {
            acme.get("domain")
                .and_then(Value::as_str)
                .is_some_and(|domain| !domain.is_empty())
        });
    if insecure && (provider || acme_domain) {
        return Err(format!("{at}: tls: insecure unused"));
    }
    if provider || acme_domain {
        return Ok(());
    }
    let inline = |key: &str| -> Vec<u8> {
        tls.get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<&str>>()
                    .join("\n")
                    .into_bytes()
            })
            .unwrap_or_default()
    };
    let certificate_path = tls
        .get("certificate_path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let key_path = tls
        .get("key_path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // the reference reads both files before looking at what it got
    let certificate = if !certificate_path.is_empty() {
        Some(read_tls_file(&certificate_path, at)?)
    } else {
        let inline_data = inline("certificate");
        (!inline_data.is_empty()).then_some(inline_data)
    };
    let key = if !key_path.is_empty() {
        Some(read_tls_file(&key_path, at).map_err(|message| {
            // Go names the operation after the field it fills
            message.replacen("read certificate:", "read key:", 1)
        })?)
    } else {
        let inline_data = inline("key");
        (!inline_data.is_empty()).then_some(inline_data)
    };
    if let (Some(certificate), Some(key)) = (&certificate, &key)
        && let Some(message) = tls_key_pair_error(certificate, key)
    {
        return Err(format!("{at}: parse x509 key pair: {message}"));
    }
    let has_certificate = certificate.is_some();
    let has_key = key.is_some();
    if !has_certificate && !has_key && insecure {
        // the reference generates a throwaway key pair from the ClientHello
        return Ok(());
    }
    if !has_certificate {
        return Err(format!("{at}: missing certificate"));
    }
    if !has_key {
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
            Some(v) if v <= u32::MAX as u64 => Ok(()),
            _ => Err(format!(
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

/// `badoption.Prefixable` field: a CIDR string, or a bare address the
/// reference turns into a host prefix. The failure is the decode error Go
/// reports, and a string that is neither keeps the `netip.ParsePrefix` text
/// the reference falls back to.
fn check_prefixable_field(
    value: &Value,
    at: &str,
    go_struct: &str,
    go_field: &str,
) -> Result<(), String> {
    let wrong_type = |kind: &str| {
        format!(
            "{at}: json: cannot unmarshal {kind} into Go struct field {go_struct}.{go_field} of type string"
        )
    };
    match value {
        Value::String(s) => match prefix_parse_reason(s) {
            Ok(()) => Ok(()),
            // ParsePrefix fails first on a bare address, then the reference
            // retries it as one
            Err(_) if parse_ip_addr(s).is_some() => Ok(()),
            Err(reason) => Err(format!("{at}: netip.ParsePrefix({s:?}): {reason}")),
        },
        Value::Number(_) => Err(wrong_type("number")),
        Value::Bool(_) => Err(wrong_type("bool")),
        Value::Array(_) => Err(wrong_type("array")),
        Value::Object(_) => Err(wrong_type("object")),
        Value::Null => Ok(()),
    }
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
fn wireguard_endpoint_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_ENDPOINT_FIELDS.contains(&k) && !DIALER_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    const WG: &str = "WireGuardEndpointOptions";
    const AWG: &str = "WireGuardEndpointOptions.AmneziaWGOptions";

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

    endpoint_dial_decode(
        &at,
        obj,
        "WireGuardEndpointOptions.DialerOptions",
        "WireGuardEndpointOptions.DialerOptions.AbstractDialerOptions",
    )
}

/// shared dial fields: `DialerOptions` + `DialerOptions.AbstractDialerOptions`
/// of every endpoint entry (wireguard, openvpn, tailscale, openconnect).
fn endpoint_dial_decode(
    at: &str,
    obj: &Map<String, Value>,
    dial: &str,
    abs: &str,
) -> Result<(), String> {
    // shared dial fields.
    for f in [
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "netns",
        "protect_path",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), abs, f)?;
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
            ep_bool(v, &format!("{at}.{f}"), abs, f)?;
        }
    }
    for f in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "fallback_delay",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), abs, f)?;
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
                    dial,
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
                    abs,
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
                    abs,
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
                    abs,
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
fn wireguard_endpoint_initialize(
    i: usize,
    tag: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
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

/// reference `box.go`: an empty tag falls back to the entry index, so every
/// `initialize ...` message names the index instead of an empty bracket.
fn index_tag(tag: &str, i: usize) -> String {
    if tag.is_empty() {
        i.to_string()
    } else {
        tag.to_string()
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
/// Standard base64 with padding; anything the alphabet does not cover, or a
/// length that is not a multiple of four, is not a key.
fn decode_base64_std(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(input).ok()
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
    /// The `network_namespaces` section: a discriminated union on `type` with
    /// `tag` required, the path only for `default` and the pid file only for
    /// `unshare` -- reference `option.NetworkNamespace`.
    /// One entry of the section, as the JSON an operator would write.
    fn netns_err(entry: &str) -> String {
        let entry: Value = serde_json::from_str(entry).expect("test json");
        validate(&json!({
            "outbounds": [{"type": "direct", "tag": "d"}],
            "network_namespaces": [entry],
        }))
        .expect_err("should be rejected")
    }

    #[test]
    fn network_namespaces_is_refused_off_linux() {
        // common/netns/manager_stub.go: an empty list is fine everywhere, a
        // populated one is a Linux-only feature
        assert!(
            validate(&json!({
                "outbounds": [{"type": "direct", "tag": "d"}],
                "network_namespaces": [],
            }))
            .is_ok()
        );
        let result = validate(&json!({
            "outbounds": [{"type": "direct", "tag": "d"}],
            "network_namespaces": [{"tag": "v", "path": "/run/netns/a"}],
        }));
        if cfg!(target_os = "linux") {
            assert!(result.is_ok(), "{:?}", result.err());
        } else {
            assert_eq!(
                result.unwrap_err(),
                "network namespaces are only supported on Linux"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn network_namespaces_accepts_both_types() {
        for section in [
            json!({"type": "default", "tag": "vpn", "path": "/run/netns/sing"}),
            json!({"tag": "vpn", "path": "sing"}),
            json!({"type": "unshare", "tag": "fresh"}),
            json!({"type": "unshare", "tag": "fresh", "pid_file": "/tmp/pid"}),
        ] {
            let result = validate(&json!({
                "outbounds": [{"type": "direct", "tag": "d"}],
                "network_namespaces": [section.clone()],
            }));
            assert!(result.is_ok(), "{section} should pass: {:?}", result.err());
        }
    }

    #[test]
    fn a_server_inbound_with_a_transport_is_refused_not_ignored() {
        // measured on the router: a vless+ws inbound started, bound its port,
        // and then every client hung, because nothing on this side reads
        // `transport`. A migrated xray server config is mostly that field, so
        // it has to fail at startup instead.
        for ty in ["vless", "vmess", "trojan"] {
            let cfg = json!({
                "inbounds": [{
                    "type": ty,
                    "listen": "127.0.0.1",
                    "listen_port": 18443,
                    "users": [],
                    "transport": {"type": "quic", "path": "/bench"},
                }],
                "outbounds": [],
            });
            let err = validate(&cfg).expect_err("quic is not runnable on an inbound");
            assert!(
                err.contains("server-side transport is not implemented yet"),
                "{ty}: {err}"
            );
            assert!(err.contains("outbounds[].transport"), "{ty}: {err}");
            // ws, httpupgrade, grpc and xhttp are served now, on the inbound
            for ok_ty in ["ws", "httpupgrade", "grpc", "xhttp"] {
                let served = json!({
                    "inbounds": [{
                        "type": ty,
                        "listen": "127.0.0.1",
                        "listen_port": 18443,
                        "users": [],
                        "transport": {"type": ok_ty, "path": "/bench"},
                    }],
                    "outbounds": [],
                });
                assert!(
                    validate(&served).is_ok(),
                    "{ty}/{ok_ty}: {:?}",
                    validate(&served).err()
                );
            }
            // and the field is still legal where it is spoken
            let ok = json!({
                "outbounds": [{
                    "type": "vless",
                    "server": "127.0.0.1",
                    "server_port": 443,
                    "uuid": "b7f8c2d1-4a3e-4f5b-9c6d-8e1a2b3c4d5e",
                    "transport": {"type": "ws", "path": "/bench"},
                }],
            });
            assert!(
                validate(&ok).is_ok(),
                "{ty} outbound: {:?}",
                validate(&ok).err()
            );
            // same class, same reason: a server-side mux is accepted by the
            // reference and ignored here
            let mux = json!({
                "inbounds": [{
                    "type": "vless",
                    "listen": "127.0.0.1",
                    "listen_port": 18443,
                    "users": [],
                    "multiplex": {"enabled": true, "protocol": "h2mux"},
                }],
                "outbounds": [],
            });
            assert!(
                validate(&mux)
                    .expect_err("a mux server is not runnable either")
                    .contains("server-side multiplex is not implemented yet")
            );
        }
    }

    #[test]
    fn network_namespaces_wants_a_list_of_tagged_objects() {
        let err = validate(&json!({"outbounds": [], "network_namespaces": {}}))
            .expect_err("an object, not a list");
        assert!(err.contains("network_namespaces: must be a list"), "{err}");
        assert!(netns_err("null").contains("must be an object"));
        assert!(netns_err(r#"{"path": "/run/netns/a"}"#).contains("missing tag"));
        assert!(netns_err(r#"{"tag": ""}"#).contains("missing tag"));
        // the two types carry different fields, and the reference refuses the
        // one that does not belong
        assert!(netns_err(r#"{"tag": "v"}"#).contains("missing path"));
        assert!(
            netns_err(r#"{"tag": "v", "path": "/run/netns/a", "pid_file": "/tmp/p"}"#)
                .contains(r#"pid_file: json: unknown field "pid_file""#)
        );
        assert!(
            netns_err(r#"{"type": "unshare", "tag": "v", "path": "/run/netns/a"}"#)
                .contains(r#"path: json: unknown field "path""#)
        );
        assert!(
            netns_err(r#"{"type": "nope", "tag": "v"}"#)
                .contains("unknown network namespace type: nope")
        );
    }

    use super::*;
    use serde_json::json;
    use std::fs;

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
    fn clash_api_check_parity() {
        let run = |cfg: Value| validate(&cfg).unwrap_err();

        let err = run(json!({"experimental": {"clash_api": {"foo": 1}}}));
        assert_eq!(
            err,
            "experimental.clash_api.foo: json: unknown field \"foo\""
        );

        let err = run(json!({"experimental": {"clash_api": {"external_controller": 1}}}));
        assert_eq!(
            err,
            "experimental.clash_api.external_controller: json: cannot unmarshal number into \
             Go struct field ClashAPIOptions.experimental.clash_api.external_controller \
             of type string"
        );
        let err = run(json!({"experimental": {"clash_api": {"store_mode": 1}}}));
        assert!(
            err.contains(
                "Go struct field ClashAPIOptions.experimental.clash_api.store_mode of type bool"
            ),
            "{err}"
        );

        let err = run(json!({"experimental": {"clash_api": {"access_control_allow_origin": 1}}}));
        assert_eq!(
            err,
            "experimental.clash_api.access_control_allow_origin: (json: cannot unmarshal number \
             into Go value of type string | json: cannot unmarshal number into Go value of type []string)"
        );
        let err = run(json!({"experimental": {"clash_api": {"access_control_allow_origin": [1]}}}));
        assert!(
            err.contains("[0]: json: cannot unmarshal number into Go value of type string"),
            "{err}"
        );

        let err = run(json!({"experimental": {"clash_api": 1}}));
        assert_eq!(
            err,
            "experimental.clash_api: json: cannot unmarshal number into Go struct field \
             ExperimentalOptions.experimental.clash_api of type option.ClashAPIOptions"
        );
        let err = run(json!({"experimental": 1}));
        assert_eq!(
            err,
            "experimental: json: cannot unmarshal number into Go struct field \
             _Options.experimental of type option.ExperimentalOptions"
        );
        let err = run(json!({"experimental": {"zz": 1}}));
        assert_eq!(err, "experimental.zz: json: unknown field \"zz\"");

        assert!(validate(&json!({"experimental": null})).is_ok());
        assert!(validate(&json!({"experimental": {"clash_api": null}})).is_ok());
        let ok = json!({"experimental": {"clash_api": {
            "external_controller": "127.0.0.1:9090", "secret": "s",
            "access_control_allow_origin": ["*"],
            "store_mode": false, "cache_file": "", "cache_id": "",
            "default_mode": "rule", "external_ui": "/nonexistent"
        }}});
        assert!(validate(&ok).is_ok(), "{ok}");

        let deprecated = "create clash-server: cache_file and related fields in Clash API is \
                           deprecated in sing-box 1.8.0, use experimental.cache_file instead.";
        let err = run(json!({"experimental": {"clash_api": {"store_selected": true}}}));
        assert_eq!(err, deprecated);
        let err = run(json!({"experimental": {"clash_api": {"cache_file": "c.db"}}}));
        assert_eq!(err, deprecated);
        // decode errors precede the deprecation guard
        let err = run(json!({"experimental": {"clash_api": {"store_mode": 1}}}));
        assert!(!err.starts_with("create clash-server"), "{err}");
    }

    #[test]
    fn the_http_clients_registry_needs_unique_tags() {
        let base = serde_json::json!({"outbounds": [{"type": "direct", "tag": "d"}]});
        let with = |clients: serde_json::Value| {
            let mut root = base.clone();
            root["http_clients"] = clients;
            validate(&root)
        };
        assert!(
            with(serde_json::json!([{"tag": "a"}, {"tag": "a"}]))
                .unwrap_err()
                .contains("duplicate http client tag: a")
        );
        assert_eq!(
            with(serde_json::json!([{"detour": "d"}])).unwrap_err(),
            "missing http client tag"
        );
        assert_eq!(
            with(serde_json::json!(["a"])).unwrap_err(),
            "http_clients[0]: json: cannot unmarshal string into Go struct field \
             _Options.http_clients of type option._HTTPClientOptions"
        );
        assert!(
            with(serde_json::json!([{"tag": "a", "bogus": 1}]))
                .unwrap_err()
                .contains("http_clients[0].bogus: json: unknown field \"bogus\""),
            "an entry decodes like the inline object form"
        );
        assert!(
            with(serde_json::json!([{"tag": "a", "detour": "d"}])).is_ok(),
            "a tag is the only thing it adds"
        );
    }

    #[test]
    fn default_http_client_is_a_client_tag() {
        // the reference decodes it as a plain string naming a `http_clients`
        // entry, so an object is refused before anything else looks at it
        let err = validate(&json!({
            "route": {"default_http_client": {"detour": "d"}},
            "outbounds": [{"type": "direct", "tag": "d"}]
        }))
        .unwrap_err();
        assert_eq!(
            err,
            "route.default_http_client: json: cannot unmarshal object into Go struct field \
             RouteOptions.route.default_http_client of type string"
        );
        assert!(
            validate(&json!({
                "route": {"default_http_client": "clash"},
                "outbounds": [{"type": "direct", "tag": "d"}]
            }))
            .is_ok(),
            "a tag is accepted even though the registry is not built yet"
        );
    }

    #[test]
    fn client_subnet_check_parity() {
        let run = |raw: Value| {
            validate(&json!({
                "dns": {"servers": [{"type": "udp", "tag": "d", "server": "1.1.1.1"}], "final": "d",
                        "client_subnet": raw}
            }))
            .unwrap_err()
        };
        let ok = |raw: Value| {
            validate(&json!({
                "dns": {"servers": [{"type": "udp", "tag": "d", "server": "1.1.1.1"}], "final": "d",
                        "client_subnet": raw}
            }))
        };

        // a CIDR, and a bare address the reference makes a host prefix of
        assert!(ok(json!("1.2.3.0/24")).is_ok());
        assert!(ok(json!("1.2.3.4")).is_ok());
        assert!(ok(json!("2001:db8::/32")).is_ok());
        assert!(
            ok(json!("1.2.3.4/24")).is_ok(),
            "the prefix is masked, not refused"
        );

        // the reference decodes a single string, not a list
        let err = run(json!(["1.2.3.0/24"]));
        assert_eq!(
            err,
            "dns.client_subnet: json: cannot unmarshal array into Go struct field \
             RawDNSOptions.DNSClientOptions.client_subnet of type string"
        );
        let err = run(json!(5));
        assert_eq!(
            err,
            "dns.client_subnet: json: cannot unmarshal number into Go struct field \
             RawDNSOptions.DNSClientOptions.client_subnet of type string"
        );
        // a string that is neither a prefix nor an address keeps the
        // ParsePrefix failure the reference falls back to
        let err = run(json!("nonsense"));
        assert_eq!(
            err,
            "dns.client_subnet: netip.ParsePrefix(\"nonsense\"): no '/'"
        );
        let err = run(json!(""));
        assert_eq!(err, "dns.client_subnet: netip.ParsePrefix(\"\"): no '/'");
        let err = run(json!("1.2.3.0/33"));
        assert_eq!(
            err,
            "dns.client_subnet: netip.ParsePrefix(\"1.2.3.0/33\"): prefix length out of range"
        );
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
    fn hy2_gecko_obfs_fields_follow_the_reference() {
        let base = |obfs: serde_json::Value| {
            json!({
                "outbounds": [{
                    "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                    "password": "p", "tls": {"enabled": true, "insecure": true},
                    "obfs": obfs
                }]
            })
        };
        // gecko merges the shared fields with its own struct
        assert!(
            validate(&base(json!({"type": "gecko", "password": "x"}))).is_ok(),
            "gecko without explicit sizes is fine"
        );
        assert!(
            validate(&base(json!({
                "type": "gecko", "password": "x",
                "min_packet_size": 700, "max_packet_size": 1500
            })))
            .is_ok()
        );
        // only the gecko branch runs the strict per-type pass
        assert!(
            validate(&base(
                json!({"type": "gecko", "password": "x", "salt": "y"})
            ))
            .is_err(),
            "gecko rejects a field of its own struct"
        );
        assert!(
            validate(&base(
                json!({"type": "salamander", "password": "x", "salt": "y"})
            ))
            .is_ok(),
            "salamander keeps whatever it is given"
        );
        // an object without a type is checked against the shared fields alone
        assert!(validate(&base(json!({}))).is_ok());
        assert!(validate(&base(json!({"bogus": 1}))).is_err());
        assert!(validate(&base(json!({"type": ""}))).is_err());
        // the size range is validated up front, with 0 defaulting to 512/1200
        for sizes in [
            json!({"min_packet_size": 1500, "max_packet_size": 600}),
            json!({"max_packet_size": 3000}),
            json!({"min_packet_size": -1}),
        ] {
            let mut obfs = json!({"type": "gecko", "password": "x"});
            for (key, value) in sizes.as_object().expect("object") {
                obfs[key] = value.clone();
            }
            let err = validate(&base(obfs)).expect_err("invalid range");
            assert!(err.contains("invalid packet size range"), "{err}");
        }
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
                    "obfs": {"type": "salamander", "password": "x"}, "password": "p"
                }]
            }))
            .is_ok()
        );
        // the obfs password is the one that matters, not the tunnel password
        assert!(
            validate(&json!({
                "outbounds": [{
                    "type": "hysteria2", "tag": "t", "server": "1.2.3.4", "server_port": 443,
                    "tls": {"enabled": true, "insecure": true},
                    "obfs": {"type": "salamander"}, "password": "p"
                }]
            }))
            .is_err()
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
    fn fptn_extra_fields_and_obfuscation_rules() {
        let server_form = |extra: Value| {
            let mut ob = json!({
                "type": "fptn", "tag": "x", "server": "1.2.3.4", "server_port": 443,
                "username": "u", "password": "p"
            });
            if let (Some(dst), Some(src)) = (ob.as_object_mut(), extra.as_object()) {
                for (k, v) in src {
                    dst.insert(k.clone(), v.clone());
                }
            }
            validate(&json!({"outbounds": [ob]})).unwrap_err()
        };
        let token_form = |extra: Value| {
            let mut ob = json!({"type": "fptn", "tag": "x", "token": "fptn:zz"});
            if let (Some(dst), Some(src)) = (ob.as_object_mut(), extra.as_object()) {
                for (k, v) in src {
                    dst.insert(k.clone(), v.clone());
                }
            }
            validate(&json!({"outbounds": [ob]})).unwrap_err()
        };

        // Both forms accept the runtime knobs.
        assert!(
            validate(&json!({"outbounds": [{
                "type": "fptn", "tag": "x", "server": "1.2.3.4", "server_port": 443,
                "username": "u", "password": "p", "sni": "sni.example", "mtu": 1400,
                "network_list": ["tcp"], "obfuscation": "tls"
            }]}))
            .is_ok()
        );
        assert!(
            validate(&json!({"outbounds": [{
                "type": "fptn", "tag": "x", "token": "fptn:zz",
                "sni": "sni.example", "mtu": 1400, "network_list": "udp",
                "obfuscation": "none"
            }]}))
            .is_ok()
        );

        let err = server_form(json!({"obfuscation": "bogus"}));
        assert!(
            err.contains("outbounds[0].obfuscation: invalid value"),
            "{err}"
        );
        let err = token_form(json!({"obfuscation": 1}));
        assert!(
            err.contains("outbounds[0].obfuscation: must be a string"),
            "{err}"
        );
        // Reality profiles: alias, official enum name, strategy number.
        for obf in [
            "reality",
            "reality_chrome149",
            "kSniRealityModeFirefox151",
            "reality_safari26_5",
            "24",
            "101",
        ] {
            assert!(
                validate(&json!({"outbounds": [{
                    "type": "fptn", "tag": "x", "token": "fptn:zz",
                    "sni": "www.cloudflare.com", "obfuscation": obf
                }]}))
                .is_ok(),
                "{obf}"
            );
        }
        // Deprecated reality mode 1 is rejected with a pointer to mode 2.
        for obf in ["kSniRealityMode", "2"] {
            let err = token_form(json!({"obfuscation": obf}));
            assert!(err.contains("reality mode 1"), "{err}");
        }
        // Reality needs a capture-length SNI when one is set explicitly.
        let err = server_form(json!({"obfuscation": "reality", "sni": "ab"}));
        assert!(err.contains("4..=64"), "{err}");
        let err = token_form(json!({"obfuscation": "reality_chrome145", "sni": ""}));
        assert!(err.contains("4..=64"), "{err}");
        let err = server_form(json!({"sni": 5}));
        assert!(err.contains("outbounds[0].sni: must be a string"), "{err}");
        let err = server_form(json!({"mtu": "big"}));
        assert!(
            err.contains("outbounds[0].mtu: must be an integer"),
            "{err}"
        );
        let err = server_form(json!({"network_list": ["icmp"]}));
        assert!(
            err.contains("outbounds[0].network_list: unknown network: icmp"),
            "{err}"
        );
        let err = server_form(json!({"network_list": [1]}));
        assert!(
            err.contains("FPTNOutboundOptions.network_list"),
            "expected FPTN struct name in {err}"
        );
        let err = token_form(json!({"fptn_unknown": 1}));
        assert!(err.contains("unknown field"), "{err}");
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

    /// Parse a config literal for the lx parity tests.
    fn lx_json(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).expect("probe json")
    }

    #[test]
    fn lx_block_decode_and_resolution() {
        // empty / null blocks are accepted
        assert!(validate(&lx_json(r#"{"lx":{}}"#)).is_ok());
        assert!(validate(&lx_json(r#"{"lx":null}"#)).is_ok());
        assert!(validate(&lx_json(r#"{"lx":{"wg":null,"masque":null}}"#)).is_ok());
        // full block with every knob
        assert!(
            validate(&lx_json(
                r#"{"lx":{"wg":{"idle_suspend":"30s","idle_suspend_reachable":"5m",
                    "idle_teardown":"0","lazy_build":true,"build_max":4,
                    "build_overflow":"build"}}}"#
            ))
            .is_ok()
        );
        assert!(validate(&lx_json(r#"{"lx":{"masque":{"idle_timeout":"30s"}}}"#)).is_ok());
        assert!(validate(&lx_json(r#"{"lx":{"wg":{"build_overflow":"wait"}}}"#)).is_ok());
    }

    #[test]
    fn lx_decode_errors() {
        let cases = [
            (
                r#"{"lx":{"nope":{}}}"#,
                r#"lx.nope: json: unknown field "nope""#,
            ),
            (
                r#"{"lx":{"wg":{"nope":1}}}"#,
                r#"lx.wg.nope: json: unknown field "nope""#,
            ),
            (
                r#"{"lx":{"masque":{"nope":1}}}"#,
                r#"lx.masque.nope: json: unknown field "nope""#,
            ),
            (
                r#"{"lx":5}"#,
                "lx: json: cannot unmarshal number into Go struct field _Options.lx of type option.LXOptions",
            ),
            (
                r#"{"lx":{"wg":5}}"#,
                "lx.wg: json: cannot unmarshal number into Go struct field LXOptions.lx.wg of type option.LXWGOptions",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend":5}}}"#,
                "lx.wg.idle_suspend: json: cannot unmarshal number into Go struct field LXWGOptions.lx.wg.idle_suspend of type string",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend":"5x"}}}"#,
                r#"lx.wg.idle_suspend: time: unknown unit "x" in duration "5x""#,
            ),
            (
                r#"{"lx":{"wg":{"lazy_build":"yes"}}}"#,
                "lx.wg.lazy_build: json: cannot unmarshal string into Go struct field LXWGOptions.lx.wg.lazy_build of type bool",
            ),
            (
                r#"{"lx":{"wg":{"build_max":"4"}}}"#,
                "lx.wg.build_max: json: cannot unmarshal string into Go struct field LXWGOptions.lx.wg.build_max of type int",
            ),
            (
                r#"{"lx":{"wg":{"build_max":1.5}}}"#,
                "lx.wg.build_max: json: cannot unmarshal number 1.5 into Go struct field LXWGOptions.lx.wg.build_max of type int",
            ),
        ];
        for (config, message) in cases {
            assert_eq!(validate(&lx_json(config)).unwrap_err(), message, "{config}");
        }
    }

    #[test]
    fn lx_resolution_chain() {
        let cases = [
            (
                r#"{"lx":{"wg":{"idle_suspend":"-1s"}}}"#,
                "lx.wg.idle_suspend must be >= 0",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend":"1s","idle_suspend_reachable":"-1s"}}}"#,
                "lx.wg.idle_suspend_reachable must be >= 0",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend":"1s","idle_teardown":"-1s"}}}"#,
                "lx.wg.idle_teardown must be >= 0",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend_reachable":"5m"}}}"#,
                "lx.wg.idle_suspend_reachable requires lx.wg.idle_suspend",
            ),
            (
                r#"{"lx":{"wg":{"idle_teardown":"0"}}}"#,
                "lx.wg.idle_teardown requires lx.wg.idle_suspend",
            ),
            (
                r#"{"lx":{"wg":{"lazy_build":true}}}"#,
                "lx.wg.lazy_build requires lx.wg.idle_suspend",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend":"5m","idle_suspend_reachable":"1m"}}}"#,
                "lx.wg.idle_suspend_reachable must be >= lx.wg.idle_suspend",
            ),
            (
                r#"{"lx":{"wg":{"idle_suspend":"1s","build_max":-1}}}"#,
                "lx.wg.build_max must be >= 0",
            ),
            (
                r#"{"lx":{"wg":{"build_overflow":"nope"}}}"#,
                "lx.wg.build_overflow must be \"wait\" or \"build\"",
            ),
            (
                r#"{"lx":{"masque":{"idle_timeout":"-1s"}}}"#,
                "lx.masque.idle_timeout must be >= 0",
            ),
        ];
        for (config, message) in cases {
            assert_eq!(validate(&lx_json(config)).unwrap_err(), message, "{config}");
        }
    }

    #[test]
    fn lx_legacy_route_aliases() {
        // folds silently, exit 0
        assert!(validate(&lx_json(r#"{"route":{"lx_idle_suspend":"30s"}}"#)).is_ok());
        assert!(
            validate(&lx_json(
                r#"{"route":{"lx_idle_suspend":"30s","lx_idle_teardown":"1m"}}"#
            ))
            .is_ok()
        );
        assert!(
            validate(&lx_json(
                r#"{"lx":{"wg":{"idle_suspend":"30s"}},"route":{"lx_idle_suspend":"30s"}}"#
            ))
            .is_ok()
        );
        // the folded value feeds the same validation chain
        assert_eq!(
            validate(&lx_json(r#"{"route":{"lx_idle_suspend_reachable":"5m"}}"#)).unwrap_err(),
            "lx.wg.idle_suspend_reachable requires lx.wg.idle_suspend"
        );
        assert_eq!(
            validate(&lx_json(r#"{"route":{"lx_idle_teardown":"0"}}"#)).unwrap_err(),
            "lx.wg.idle_teardown requires lx.wg.idle_suspend"
        );
        // conflicting values are rejected before the chain runs
        assert_eq!(
            validate(&lx_json(
                r#"{"lx":{"wg":{"idle_suspend":"30s"}},"route":{"lx_idle_suspend":"1m"}}"#
            ))
            .unwrap_err(),
            "route.lx_idle_suspend conflicts with lx.wg.idle_suspend"
        );
        assert_eq!(
            validate(&lx_json(
                r#"{"lx":{"wg":{"idle_teardown":"0"}},"route":{"lx_idle_teardown":"1m"}}"#
            ))
            .unwrap_err(),
            "route.lx_idle_teardown conflicts with lx.wg.idle_teardown"
        );
        // decode errors keep the route prefix and the Go field path
        assert_eq!(
            validate(&lx_json(r#"{"route":{"lx_idle_suspend":"5x"}}"#)).unwrap_err(),
            r#"route.lx_idle_suspend: time: unknown unit "x" in duration "5x""#
        );
        assert_eq!(
            validate(&lx_json(r#"{"route":{"lx_idle_suspend":30}}"#)).unwrap_err(),
            "route.lx_idle_suspend: json: cannot unmarshal number into Go struct field RouteOptions.route.lx_idle_suspend of type string"
        );
    }

    #[test]
    fn dns_server_types_and_fields() {
        let json = |raw: &str| lx_json(raw);
        // new transports decode
        for config in [
            r#"{"dns":{"servers":[{"type":"local","tag":"l","prefer_go":true}]}}"#,
            r#"{"dns":{"servers":[{"type":"local","tag":"l","neighbor_domain":[".local"]}]}}"#,
            r#"{"dns":{"servers":[{"type":"mdns","tag":"m","interface":["eth0"]}]}}"#,
            r#"{"dns":{"servers":[{"type":"dhcp","tag":"d","interface":"eth0"}]}}"#,
            r#"{"dns":{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},
                {"type":"group","tag":"g","servers":["a"],"mode":"fastest"}]}}"#,
            r#"{"dns":{"servers":[{"type":"https","tag":"h","server":"1.1.1.1","path":"/dns-query"}]}}"#,
        ] {
            assert!(validate(&json(config)).is_ok(), "{config}");
        }
        // unknown fields are rejected with the reference's path
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","bogus":1}]}}"#
            ))
            .unwrap_err(),
            r#"dns.servers[0].bogus: json: unknown field "bogus""#
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"local","tag":"l","path":"/x"}]}}"#
            ))
            .unwrap_err(),
            r#"dns.servers[0].path: json: unknown field "path""#
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"local","tag":"l","prefer_go":"yes"}]}}"#
            ))
            .unwrap_err(),
            "dns.servers[0].prefer_go: json: cannot unmarshal string into Go struct field LocalDNSServerOptions.prefer_go of type bool"
        );
        // init-chain messages
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"local","tag":"l","neighbor_domain":["home.arpa"]}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[0] local[l]: neighbor_domain entry must start with '.': home.arpa"
        );
        assert_eq!(
            validate(&json(r#"{"dns":{"servers":[{"type":"h3","tag":"h"}]}}"#)).unwrap_err(),
            "initialize DNS server[0] h3[h]: missing server_name or insecure=true"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"tailscale","tag":"t"}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[0] tailscale[t]: missing tailscale endpoint tag"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"openvpn","tag":"o"}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[0] openvpn[o]: missing endpoint tag"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"openconnect","tag":"c"}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[0] openconnect[c]: missing endpoint tag"
        );
        // h3 accepts a bare server address as the effective name
        assert!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"h3","tag":"h","server":"1.1.1.1"}]}}"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn dns_group_and_default_rules() {
        let json = |raw: &str| lx_json(raw);
        // group messages carry the initialize prefix and the group[tag] body
        assert_eq!(
            validate(&json(r#"{"dns":{"servers":[{"type":"group","tag":"g"}]}}"#)).unwrap_err(),
            "initialize DNS server[0] group[g]: group[g]: servers is required and must not be empty"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},
                    {"type":"group","tag":"g","servers":["a","a"]}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[1] group[g]: group[g]: duplicate server: a"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},
                    {"type":"group","tag":"g","servers":["g"]}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[1] group[g]: group[g]: group cannot contain itself"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},
                    {"type":"group","tag":"g","servers":["a"],"mode":"nope"}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[1] group[g]: group[g]: unknown mode: nope (expected stable, fastest or parallel)"
        );
        // the default server may not be fakeip
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"fakeip","tag":"f","inet4_range":"198.18.0.0/15"}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[0] fakeip[f]: default server cannot be fakeip"
        );
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"fakeip","tag":"f","inet4_range":"198.18.0.0/15"},
                    {"type":"udp","tag":"a","server":"1.1.1.1"}],"final":"f"}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[0] fakeip[f]: default server cannot be fakeip"
        );
        // ...but fine as a non-default member
        assert!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},
                    {"type":"fakeip","tag":"f","inet4_range":"198.18.0.0/15"}]}}"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn empty_tag_falls_back_to_index() {
        let json = |raw: &str| lx_json(raw);
        // reference box.go: an untagged entry is named by its index
        assert_eq!(
            validate(&json(r#"{"inbounds":[{"type":"shadowtls"}]}"#)).unwrap_err(),
            "initialize inbound[0] shadowtls[0]: missing default handshake information"
        );
        assert_eq!(
            validate(&json(r#"{"outbounds":[{"type":"anytls"}]}"#)).unwrap_err(),
            "initialize outbound[0] anytls[0]: TLS required"
        );
        assert_eq!(
            validate(&json(r#"{"dns":{"servers":[{"type":"h3"}]}}"#)).unwrap_err(),
            "initialize DNS server[0] h3[0]: missing server_name or insecure=true"
        );
        assert_eq!(
            validate(&json(r#"{"dns":{"servers":[{"type":"tailscale"}]}}"#)).unwrap_err(),
            "initialize DNS server[0] tailscale[0]: missing tailscale endpoint tag"
        );
        // the message carries the real position, not a hardcoded 0
        assert_eq!(
            validate(&json(
                r#"{"dns":{"servers":[{"type":"udp","tag":"a","server":"1.1.1.1"},
                    {"type":"group","tag":"g","servers":[]}]}}"#
            ))
            .unwrap_err(),
            "initialize DNS server[1] group[g]: group[g]: servers is required and must not be empty"
        );
    }

    #[test]
    fn bridge_outbound_and_cloudflared_inbound() {
        let json = |raw: &str| lx_json(raw);
        // bridge has no dialer/listen options and no init validation
        for config in [
            r#"{"outbounds":[{"type":"bridge"}]}"#,
            r#"{"outbounds":[{"type":"bridge","tag":"b","bridge_name":"br0","interface":"eth0"}]}"#,
            r#"{"outbounds":[{"type":"bridge","iproute2_table_index":100,"iproute2_rule_index":200}]}"#,
        ] {
            assert!(validate(&json(config)).is_ok(), "{config}");
        }
        assert_eq!(
            validate(&json(
                r#"{"outbounds":[{"type":"bridge","server":"example.com"}]}"#
            ))
            .unwrap_err(),
            r#"outbounds[0].server: json: unknown field "server""#
        );
        assert_eq!(
            validate(&json(
                r#"{"outbounds":[{"type":"bridge","iproute2_table_index":"x"}]}"#
            ))
            .unwrap_err(),
            "outbounds[0].iproute2_table_index: json: cannot unmarshal string into Go struct field BridgeOutboundOptions.iproute2_table_index of type int"
        );
        // cloudflared decodes, then fails like a build without with_cloudflared
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"cloudflared","token":"t"}]}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] cloudflared[0]: Cloudflared is not included in this build, rebuild with -tags with_cloudflared"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"cloudflared","tunnel_dialer":{"nope":1}}]}"#
            ))
            .unwrap_err(),
            r#"inbounds[0].tunnel_dialer.nope: json: unknown field "nope""#
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"cloudflared","grace_period":30}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].grace_period: json: cannot unmarshal number into Go struct field CloudflaredInboundOptions.grace_period of type string"
        );
    }

    /// the corpus certificate, so the `check`-time file reads resolve
    fn cert_fixture(name: &str) -> String {
        format!(
            "{}/../../tests/golden/certs/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
        .replace('\\', "/")
    }

    #[test]
    fn server_tls_certificate_sources() {
        let json = |raw: &str| lx_json(raw);
        let inbound = |tls: &str| {
            json(&format!(
                r#"{{"inbounds":[{{"type":"hysteria2","tls":{tls}}}]}}"#
            ))
        };
        let certificate = cert_fixture("localhost.crt");
        let key = cert_fixture("localhost.key");
        // the reference compares values, so empty paths do not count
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_path":"","key_path":""}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: missing certificate"
        );
        assert_eq!(
            validate(&inbound(&format!(
                r#"{{"enabled":true,"certificate_path":"{certificate}"}}"#
            )))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: missing key"
        );
        assert!(
            validate(&inbound(&format!(
                r#"{{"enabled":true,"certificate_path":"{certificate}","key_path":"{key}"}}"#
            )))
            .is_ok()
        );
        // the files are read while the server config is built
        let absent = validate(&inbound(&format!(
            r#"{{"enabled":true,"certificate_path":"{}/absent.crt"}}"#,
            cert_fixture("")
        )))
        .unwrap_err();
        assert!(
            absent.starts_with("initialize inbound[0] hysteria2[0]: read certificate: open "),
            "{absent}"
        );
        // inline PEM still has to hold real blocks
        let certificate_pem = fs::read_to_string(cert_fixture("localhost.crt")).unwrap();
        let key_pem = fs::read_to_string(cert_fixture("localhost.key")).unwrap();
        let inline_pair = serde_json::json!({
            "enabled": true,
            "certificate": [certificate_pem],
            "key": [key_pem]
        })
        .to_string();
        assert!(validate(&inbound(&inline_pair)).is_ok());
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate":["hello"],"key":["hello"]}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: parse x509 key pair: tls: failed to find any PEM data in certificate input"
        );
        let swapped = serde_json::json!({
            "enabled": true,
            "certificate": [key_pem],
            "key": [certificate_pem]
        })
        .to_string();
        assert_eq!(
            validate(&inbound(&swapped)).unwrap_err(),
            "initialize inbound[0] hysteria2[0]: parse x509 key pair: tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"
        );
        // insecure generates a throwaway key pair
        assert!(validate(&inbound(r#"{"enabled":true,"insecure":true}"#)).is_ok());
        // a certificate provider supplies the certificate
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":{"type":"acme"}}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: create inline certificate provider: ACME is not included in this build, rebuild with -tags with_acme"
        );
        // an empty provider object is pruned away like any other empty value
        assert_eq!(
            validate(&inbound(r#"{"enabled":true,"certificate_provider":{}}"#)).unwrap_err(),
            "initialize inbound[0] hysteria2[0]: missing certificate"
        );
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":{"domain":"example.com"}}"#
            ))
            .unwrap_err(),
            "inbounds[0].tls.certificate_provider: missing certificate provider type"
        );
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":{"type":"cloudflare_origin_ca"}}"#
            ))
            .unwrap_err(),
            "inbounds[0].tls.certificate_provider: unknown certificate provider type: cloudflare_origin_ca"
        );
        // a shared provider reference is only resolved at start
        assert!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":"shared"}"#
            ))
            .is_ok()
        );
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":{"type":"acme"},"insecure":true}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: create inline certificate provider: ACME is not included in this build, rebuild with -tags with_acme"
        );
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":{"type":"acme"},"acme":{"domain":"example.com"}}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: certificate_provider and acme are mutually exclusive"
        );
        assert_eq!(
            validate(&inbound(
                r#"{"enabled":true,"certificate_provider":{"type":"tailscale","endpoint":"ts"}}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] hysteria2[0]: create inline certificate provider: endpoint not found: ts"
        );
    }

    /// The same validation the QUIC server inbounds get has to run for the proxy
    /// ones too: a `tls` block on a vless inbound that `check` does not look at
    /// is a block the runtime may refuse with words the reference never says.
    #[test]
    fn server_tls_is_validated_on_every_inbound_that_accepts_it() {
        let certificate = cert_fixture("localhost.crt");
        let key = cert_fixture("localhost.key");
        for ty in ["vless", "vmess", "trojan", "shadowsocks", "mixed"] {
            // shadowsocks reads its own fields before the tls block, so it
            // needs the two that make it a shadowsocks server at all
            let extra = if ty == "shadowsocks" {
                r#""method":"aes-128-gcm","password":"hunter2","#
            } else {
                ""
            };
            let inbound = |tls: &str| {
                lx_json(&format!(
                    r#"{{"inbounds":[{{"type":"{ty}",{extra}"tls":{tls}}}]}}"#
                ))
            };
            let missing = format!("initialize inbound[0] {ty}[0]: missing certificate");
            assert_eq!(
                validate(&inbound(r#"{"enabled":true}"#)).unwrap_err(),
                missing,
                "{ty}"
            );
            assert_eq!(
                validate(&inbound(&format!(
                    r#"{{"enabled":true,"certificate_path":"{certificate}"}}"#
                )))
                .unwrap_err(),
                format!("initialize inbound[0] {ty}[0]: missing key"),
                "{ty}"
            );
            assert!(
                validate(&inbound(&format!(
                    r#"{{"enabled":true,"certificate_path":"{certificate}","key_path":"{key}"}}"#
                )))
                .is_ok(),
                "{ty}"
            );
            // a tls block that is not an object is a decode error, not a block
            // that happens to be off
            assert!(
                validate(&inbound(r#""yes""#)).is_err(),
                "{ty} took a tls block that is not an object"
            );
        }
    }

    #[test]
    fn tuic_inbound_uuid_is_an_init_check() {
        let json = |raw: &str| lx_json(raw);
        // the server TLS config is built before the user list is walked
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"tuic","users":[{"uuid":"x"}],"tls":{"enabled":true}}]}"#
            ))
            .unwrap_err(),
            "initialize inbound[0] tuic[0]: missing certificate"
        );
        let tls = format!(
            r#""tls":{{"enabled":true,"certificate_path":"{}","key_path":"{}"}}"#,
            cert_fixture("localhost.crt"),
            cert_fixture("localhost.key")
        );
        assert!(
            validate(&json(&format!(
                r#"{{"inbounds":[{{"type":"tuic","users":[{{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}}],{tls}}}]}}"#
            )))
            .is_ok(),
            "a valid certificate pair and uuid must pass"
        );
        assert_eq!(
            validate(&json(&format!(
                r#"{{"inbounds":[{{"type":"tuic","users":[{{"uuid":"x"}}],{tls}}}]}}"#
            )))
            .unwrap_err(),
            "initialize inbound[0] tuic[0]: invalid uuid for user 0: uuid: incorrect UUID length"
        );
        assert_eq!(
            validate(&json(&format!(
                r#"{{"inbounds":[{{"type":"tuic","users":[{{"name":"n"}}],{tls}}}]}}"#
            )))
            .unwrap_err(),
            "initialize inbound[0] tuic[0]: missing uuid for user 0"
        );
        // the user list is still a decode-time shape check
        assert_eq!(
            validate(&json(r#"{"inbounds":[{"type":"tuic","users":5}]}"#)).unwrap_err(),
            "inbounds[0].users: json: cannot unmarshal number into Go struct field TUICInboundOptions.users of type []option.TUICUser"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"tuic","users":[{"uuid":"x","nope":1}]}]}"#
            ))
            .unwrap_err(),
            r#"inbounds[0].users[0].nope: json: unknown field "nope""#
        );
    }

    #[test]
    fn inbound_listen_options_and_fields() {
        let json = |raw: &str| lx_json(raw);
        // unknown fields on the inbounds that had no decode pass
        assert_eq!(
            validate(&json(r#"{"inbounds":[{"type":"mixed","bogus":1}]}"#)).unwrap_err(),
            r#"inbounds[0].bogus: json: unknown field "bogus""#
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"mixed","connect_timeout":"1s"}]}"#
            ))
            .unwrap_err(),
            r#"inbounds[0].connect_timeout: json: unknown field "connect_timeout""#
        );
        assert_eq!(
            validate(&json(r#"{"inbounds":[{"type":"tun","listen":"::"}]}"#)).unwrap_err(),
            r#"inbounds[0].listen: json: unknown field "listen""#
        );
        // ListenOptions field kinds name the struct that embeds it
        assert_eq!(
            validate(&json(r#"{"inbounds":[{"type":"socks","listen":1}]}"#)).unwrap_err(),
            "inbounds[0].listen: json: cannot unmarshal number into Go struct field SocksInboundOptions.ListenOptions.listen of type string"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"mixed","listen_port":70000}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].listen_port: json: cannot unmarshal number 70000 into Go struct field HTTPMixedInboundOptions.ListenOptions.listen_port of type uint16"
        );
        assert_eq!(
            validate(&json(r#"{"inbounds":[{"type":"mixed","reuse_addr":1}]}"#)).unwrap_err(),
            "inbounds[0].reuse_addr: json: cannot unmarshal number into Go struct field HTTPMixedInboundOptions.ListenOptions.reuse_addr of type bool"
        );
        // the reference prune drops Go zero values, so `false` is not an error
        assert!(
            validate(&json(
                r#"{"inbounds":[{"type":"tproxy","listen":"::","listen_port":1,"tcp_fast_open":false}]}"#
            ))
            .is_ok()
        );
        // FwMark: uint32 or a parseable string
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"mixed","routing_mark":-1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].routing_mark: invalid number or string mark: json: cannot unmarshal number into Go value of type string"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"mixed","routing_mark":"zz"}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].routing_mark: strconv.ParseUint: parsing \"zz\": invalid syntax"
        );
        for mark in ["0", "1", "0x10", "010"] {
            assert!(
                validate(&json(&format!(
                    r#"{{"inbounds":[{{"type":"mixed","routing_mark":"{mark}"}}]}}"#
                )))
                .is_ok(),
                "{mark}"
            );
        }
        // per-type scalar fields
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"direct","override_address":1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].override_address: json: cannot unmarshal number into Go struct field DirectInboundOptions.override_address of type string"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"tproxy","listen":"::","listen_port":1,"udp_nat_max":"x"}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].udp_nat_max: json: cannot unmarshal string into Go struct field TProxyInboundOptions.udp_nat_max of type uint32"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"tun","interface_name":"tun0","address":["172.19.0.1/30"],"mtu":"x"}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].mtu: json: cannot unmarshal string into Go struct field TunInboundOptions.mtu of type uint32"
        );
    }

    #[test]
    fn inbound_containers_and_field_kinds() {
        let json = |raw: &str| lx_json(raw);
        // container fields fail on their own kind, with the embedding container
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"tuic","users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"tls":1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].tls: json: cannot unmarshal number into Go struct field TUICInboundOptions.InboundTLSOptionsContainer.tls of type option.InboundTLSOptions"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":2080,"users":1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].users: json: cannot unmarshal number into Go struct field HTTPMixedInboundOptions.users of type []auth.User"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"vmess","users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"multiplex":1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].multiplex: json: cannot unmarshal number into Go struct field VMessInboundOptions.multiplex of type option.InboundMultiplexOptions"
        );
        // NetworkList and badoption.Listable[string] report differently
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"shadowsocks","method":"aes-128-gcm","password":"p","network":1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].network: json: cannot unmarshal number into Go struct field ShadowsocksInboundOptions.network of type string"
        );
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"anytls","users":[{"password":"p"}],"tls":{"enabled":true,"insecure":true},"padding_scheme":[1]}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].padding_scheme: (json: cannot unmarshal array into Go value of type string | [0]: json: cannot unmarshal number into Go value of type string)"
        );
        // the QUIC options live under their container path
        assert_eq!(
            validate(&json(
                r#"{"inbounds":[{"type":"tuic","users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"tls":{"enabled":true,"insecure":true},"idle_timeout":1}]}"#
            ))
            .unwrap_err(),
            "inbounds[0].idle_timeout: json: cannot unmarshal number into Go struct field TUICInboundOptions.QUICOptions.HTTP2Options.idle_timeout of type string"
        );
        // the dialer gates of common/dialer.New (the mark is Linux-only)
        let routing_mark =
            json(r#"{"outbounds":[{"type":"socks","server":"a.com","routing_mark":1}]}"#);
        if cfg!(target_os = "linux") {
            assert!(validate(&routing_mark).is_ok());
        } else {
            assert_eq!(
                validate(&routing_mark).unwrap_err(),
                "initialize outbound[0] socks[0]: `routing_mark` is only supported on Linux"
            );
        }
        assert_eq!(
            validate(&json(
                r#"{"outbounds":[{"type":"socks","server":"a.com","network_strategy":"default","tcp_fast_open":true}]}"#
            ))
            .unwrap_err(),
            "initialize outbound[0] socks[0]: `network_strategy` is conflict with `bind_interface`, `inet4_bind_address`, `inet6_bind_address` and `tcp_fast_open`"
        );
        // the group member lists decode before the init pass
        assert_eq!(
            validate(&json(
                r#"{"outbounds":[{"type":"selector","outbounds":1}]}"#
            ))
            .unwrap_err(),
            "outbounds[0].outbounds: json: cannot unmarshal number into Go struct field SelectorOutboundOptions.outbounds of type []string"
        );
    }
}

// ---------------------------------------------------------------------------
// Endpoint types beyond wireguard: openvpn-client / openvpn-server /
// tailscale / openconnect. Field sets and init chains mirror the reference
// (option/openvpn.go, option/tailscale.go, option/openconnect.go,
// protocol/openvpn/{client,server}.go, sing-openvpn options_validation.go).
// Probed message matrix lives in the tests at the bottom of this file.
// ---------------------------------------------------------------------------

const ENDPOINT_TYPES: &[&str] = &[
    "wireguard",
    "openvpn-client",
    "openvpn-server",
    "tailscale",
    "openconnect",
];

const OVPN_CLIENT: &str = "OpenVPNClientEndpointOptions";
const OVPN_SERVER: &str = "OpenVPNServerEndpointOptions";
const TS_EP: &str = "TailscaleEndpointOptions";
const OC_EP: &str = "OpenConnectEndpointOptions";

/// reference `option.OpenVPNClientEndpointOptions` + wrapper + embedded
/// `OpenVPNEndpointOptions`/`ServerOptions`/`OpenVPNEndpointOptions.dialer`
/// (dial fields come from `DIALER_OUT_FIELDS`).
const KNOWN_OVPN_CLIENT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "system",
    "name",
    "mtu",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "udp_timeout",
    "server",
    "server_port",
    "mode",
    "network",
    "servers",
    "remote_random",
    "address",
    "peer_address",
    "peer_address_ipv6",
    "topology",
    "username",
    "password",
    "auth_retry",
    "static_challenge",
    "static_challenge_echo",
    "static_key",
    "static_key_path",
    "key_direction",
    "tls",
    "cipher",
    "data_ciphers",
    "data_ciphers_fallback",
    "auth",
    "mss_fix",
    "mss_fix_disabled",
    "mss_fix_mode",
    "fragment",
    "replay_window",
    "replay_window_time",
    "compression",
    "compression_lzo",
    "allow_compression",
    "route_no_pull",
    "pull_filters",
    "routes",
    "route_gateway",
    "route_metric",
    "redirect_gateway",
    "redirect_gateway_flags",
    "redirect_private",
    "block_ipv6",
    "ping_interval",
    "ping_restart",
    "ping_restart_disabled",
    "renegotiate_interval",
    "renegotiate_disabled",
    "renegotiate_bytes",
    "renegotiate_packets",
    "tls_timeout",
    "handshake_window",
    "explicit_exit_notify",
];

/// reference `option.OpenVPNServerEndpointOptions`: ListenOptions (incl. the
/// embedded InboundOptions decode fields) + `OpenVPNEndpointOptions` +
/// server fields. No dialer fields on the server side.
const KNOWN_OVPN_SERVER_FIELDS: &[&str] = &[
    "type",
    "tag",
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
    "sniff",
    "sniff_override_destination",
    "sniff_timeout",
    "domain_strategy",
    "udp_disable_domain_unmapping",
    "system",
    "name",
    "mtu",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "mode",
    "network",
    "remote",
    "remote_port",
    "max_clients",
    "address",
    "peer_address",
    "peer_address_ipv6",
    "topology",
    "duplicate_cn",
    "users",
    "static_key",
    "static_key_path",
    "key_direction",
    "tls",
    "cipher",
    "data_ciphers",
    "data_ciphers_fallback",
    "auth",
    "mss_fix",
    "mss_fix_disabled",
    "mss_fix_mode",
    "replay_window",
    "replay_window_time",
    "push",
    "ping_interval",
    "ping_restart",
    "renegotiate_interval",
    "renegotiate_disabled",
    "renegotiate_bytes",
    "renegotiate_packets",
    "handshake_window",
];

/// reference `option.TailscaleEndpointOptions` + wrapper.
const KNOWN_TAILSCALE_FIELDS: &[&str] = &[
    "type",
    "tag",
    "state_directory",
    "auth_key",
    "control_url",
    "ephemeral",
    "hostname",
    "accept_routes",
    "exit_node",
    "exit_node_allow_lan_access",
    "advertise_routes",
    "advertise_exit_node",
    "advertise_tags",
    "listen_port",
    "relay_server_port",
    "relay_server_static_endpoints",
    "system_interface",
    "system_interface_name",
    "system_interface_mtu",
    "udp_timeout",
    "ssh_server",
    "taildrop_directory",
];

/// reference `option.OpenConnectEndpointOptions` + wrapper.
const KNOWN_OPENCONNECT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "system",
    "name",
    "udp_timeout",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "server",
    "flavor",
    "username",
    "password",
    "auth_group",
    "cookie",
    "token",
    "reported_os",
    "user_agent",
    "version",
    "local_hostname",
    "mobile",
    "csd",
    "hip",
    "tncc",
    "fortinet_host_check",
    "no_udp",
    "dtls_local_port",
    "compression_disabled",
    "compression_mode",
    "ipv6_disabled",
    "http_keepalive_disabled",
    "xml_post_disabled",
    "external_auth_disabled",
    "password_authentication_disabled",
    "tcp_keep_alive_enabled",
    "pfs",
    "mtu",
    "base_mtu",
    "dpd_interval",
    "reconnect_timeout",
    "trojan_interval",
    "queue_length",
    "allow_insecure_crypto",
    "tls",
    "form_entries",
];

const KNOWN_OVPN_TLS_OUT_FIELDS: &[&str] = &[
    "server_name",
    "server_name_type",
    "certificate",
    "certificate_path",
    "client_certificate",
    "client_certificate_path",
    "client_key",
    "client_key_path",
    "peer_fingerprint",
    "crl_path",
    "remote_certificate_ku",
    "remote_certificate_eku",
    "remote_certificate_tls",
    "certificate_profile",
    "ns_certificate_type",
    "version_min",
    "version_max",
    "cipher",
    "groups",
    "control_wrap",
];

const KNOWN_OVPN_TLS_IN_FIELDS: &[&str] = &[
    "certificate",
    "certificate_path",
    "key",
    "key_path",
    "client_certificate",
    "client_certificate_path",
    "verify_client_certificate",
    "client_name",
    "client_name_type",
    "peer_fingerprint",
    "crl_path",
    "remote_certificate_ku",
    "remote_certificate_eku",
    "remote_certificate_tls",
    "certificate_profile",
    "ns_certificate_type",
    "version_min",
    "version_max",
    "cipher",
    "groups",
    "control_wrap",
];

const KNOWN_OVPN_CWRAP_FIELDS: &[&str] = &["type", "key", "key_path", "direction"];
const KNOWN_OVPN_CWRAP_IN_FIELDS: &[&str] =
    &["type", "key", "key_path", "direction", "force_cookie"];
const KNOWN_OVPN_REMOTE_FIELDS: &[&str] = &["server", "server_port", "network"];
const KNOWN_OVPN_PULL_FILTER_FIELDS: &[&str] = &["action", "text"];
const KNOWN_OVPN_USER_FIELDS: &[&str] = &["username", "password"];
const KNOWN_OVPN_PUSH_FIELDS: &[&str] = &[
    "routes",
    "dns",
    "dns_servers",
    "search_domains",
    "dhcp_options",
    "redirect_gateway",
    "redirect_gateway_flags",
    "block_outside_dns",
    "ping_interval",
    "ping_restart",
];
const KNOWN_OVPN_PUSH_DNS_SERVER_FIELDS: &[&str] = &[
    "priority",
    "addresses",
    "resolve_domains",
    "dnssec",
    "transport",
    "sni",
];
const KNOWN_TS_SSH_FIELDS: &[&str] = &[
    "enabled",
    "disable_pty",
    "disable_sftp",
    "disable_forwarding",
];
const KNOWN_OC_TOKEN_FIELDS: &[&str] = &[
    "mode",
    "secret",
    "secret_path",
    "pin",
    "password",
    "device_id",
    "counter",
];
const KNOWN_OC_TLS_FIELDS: &[&str] = &[
    "insecure",
    "server_name",
    "peer_fingerprint",
    "system_trust_disabled",
    "certificate_authority",
    "certificate_authority_path",
    "client_certificate",
    "client_certificate_path",
    "client_key",
    "client_key_path",
    "client_key_password",
    "mca_certificate",
    "mca_certificate_path",
    "mca_key",
    "mca_key_path",
    "mca_key_password",
];
const KNOWN_OC_MOBILE_FIELDS: &[&str] = &["platform_version", "device_type", "device_unique_id"];
const KNOWN_OC_WRAPPER_FIELDS: &[&str] = &["wrapper_path"];
const KNOWN_OC_TNCC_FIELDS: &[&str] = &[
    "wrapper_path",
    "device_id",
    "user_agent",
    "machine_identification_enabled",
    "certificates",
];
const KNOWN_OC_TNCC_CERT_FIELDS: &[&str] = &["certificate", "certificate_path"];
const KNOWN_OC_FORTINET_FIELDS: &[&str] = &["hostcheck", "check_virtual_desktop"];
const KNOWN_OC_FORM_ENTRY_FIELDS: &[&str] =
    &["form_id", "submission_key", "name", "value", "promote"];

/// canonical data-cipher names accepted by the reference
/// (`sing-openvpn validateDataCipherName`).
const OVPN_CANONICAL_CIPHERS: &[&str] = &[
    "",
    "BF-CBC",
    "DES-CBC",
    "DES-EDE-CBC",
    "DES-EDE3-CBC",
    "CAST5-CBC",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "ARIA-128-CBC",
    "ARIA-192-CBC",
    "ARIA-256-CBC",
    "CAMELLIA-128-CBC",
    "CAMELLIA-192-CBC",
    "CAMELLIA-256-CBC",
    "SEED-CBC",
    "SM4-CBC",
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "NONE",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

/// ciphers usable in static_key mode (`staticCipherKeySize`).
const OVPN_STATIC_CIPHERS: &[&str] = &[
    "BF-CBC",
    "DES-CBC",
    "DES-EDE-CBC",
    "DES-EDE3-CBC",
    "CAST5-CBC",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "ARIA-128-CBC",
    "ARIA-192-CBC",
    "ARIA-256-CBC",
    "CAMELLIA-128-CBC",
    "CAMELLIA-192-CBC",
    "CAMELLIA-256-CBC",
    "SEED-CBC",
    "SM4-CBC",
    "NONE",
];

const OVPN_AUTH_DIGESTS: &[&str] = &[
    "",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "RIPEMD160",
    "MD5",
    "NONE",
];

const OVPN_CLIENT_PROTOCOLS: &[&str] = &["", "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"];
const OVPN_SERVER_PROTOCOLS: &[&str] = &["", "udp", "tcp"];
const OVPN_MODES: &[&str] = &["", "tls", "static_key"];
const OVPN_TOPOLOGIES: &[&str] = &["", "net30", "p2p", "subnet"];
const OVPN_KEY_DIRECTIONS: &[&str] = &["", "server", "client"];
const OVPN_AUTH_RETRIES: &[&str] = &["", "none", "nointeract", "interact"];
const OVPN_PULL_FILTER_ACTIONS: &[&str] = &["accept", "ignore", "reject"];
const OC_FLAVORS: &[&str] = &["", "anyconnect", "gp", "fortinet", "f5", "pulse", "nc"];
const OVPN_REMOTE_CERT_TLS: &[&str] = &["", "server", "client", "none"];
const OVPN_TLS_VERIFY_X509: &[&str] = &["", "subject", "name", "name-prefix"];
const OVPN_NS_CERT_TYPES: &[&str] = &["", "server", "client"];
const OVPN_MSS_FIX_MODES: &[&str] = &["", "mtu", "fixed"];

fn endpoint_decode(i: usize, obj: &Map<String, Value>, ty: &str) -> Result<(), String> {
    match ty {
        "wireguard" => wireguard_endpoint_decode(i, obj),
        "openvpn-client" => openvpn_client_decode(i, obj),
        "openvpn-server" => openvpn_server_decode(i, obj),
        "tailscale" => tailscale_decode(i, obj),
        "openconnect" => openconnect_decode(i, obj),
        _ => Err(format!("endpoints[{i}]: unknown endpoint type: {ty}")),
    }
}

fn openvpn_client_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_CLIENT_FIELDS.contains(&k) && !DIALER_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    let epc = format!("{OVPN_CLIENT}.OpenVPNEndpointOptions");
    if let Some(v) = obj.get("system") {
        ep_bool(v, &format!("{at}.system"), &epc, "system")?;
    }
    if let Some(v) = obj.get("name") {
        ep_str(v, &format!("{at}.name"), &epc, "name")?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(v, &format!("{at}.mtu"), &epc, "mtu", u32::MAX as u64)?;
    }
    if let Some(v) = obj.get("udp_mapping") {
        check_udp_nat(v, &format!("{at}.udp_mapping"), &epc, "udp_mapping")?;
    }
    if let Some(v) = obj.get("udp_filtering") {
        check_udp_nat(v, &format!("{at}.udp_filtering"), &epc, "udp_filtering")?;
    }
    if let Some(v) = obj.get("udp_nat_max") {
        ep_unsigned(
            v,
            &format!("{at}.udp_nat_max"),
            &epc,
            "udp_nat_max",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("udp_timeout") {
        check_duration_field(v, &format!("{at}.udp_timeout"), OVPN_CLIENT, "udp_timeout")?;
    }
    let srv = format!("{OVPN_CLIENT}.ServerOptions");
    if let Some(v) = obj.get("server") {
        ep_str(v, &format!("{at}.server"), &srv, "server")?;
    }
    if let Some(v) = obj.get("server_port") {
        ep_unsigned(
            v,
            &format!("{at}.server_port"),
            &srv,
            "server_port",
            u16::MAX as u64,
        )?;
    }
    for f in [
        "mode",
        "network",
        "topology",
        "username",
        "password",
        "auth_retry",
        "static_challenge",
        "key_direction",
        "cipher",
        "auth",
        "mss_fix_mode",
        "compression",
        "compression_lzo",
        "allow_compression",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), OVPN_CLIENT, f)?;
        }
    }
    for f in [
        "static_challenge_echo",
        "remote_random",
        "route_no_pull",
        "redirect_gateway",
        "redirect_private",
        "block_ipv6",
        "ping_restart_disabled",
        "renegotiate_disabled",
        "mss_fix_disabled",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), OVPN_CLIENT, f)?;
        }
    }
    for f in [
        "mss_fix",
        "fragment",
        "replay_window",
        "route_metric",
        "explicit_exit_notify",
    ] {
        if let Some(v) = obj.get(f) {
            ep_unsigned(v, &format!("{at}.{f}"), OVPN_CLIENT, f, u32::MAX as u64)?;
        }
    }
    for f in ["renegotiate_bytes", "renegotiate_packets"] {
        if let Some(v) = obj.get(f) {
            check_u64_field(v, &format!("{at}.{f}"), OVPN_CLIENT, f)?;
        }
    }
    for f in [
        "replay_window_time",
        "ping_interval",
        "ping_restart",
        "renegotiate_interval",
        "tls_timeout",
        "handshake_window",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), OVPN_CLIENT, f)?;
        }
    }
    if let Some(v) = obj.get("address") {
        check_prefix_list(v, &format!("{at}.address"))?;
    }
    if let Some(v) = obj.get("routes") {
        check_prefix_list(v, &format!("{at}.routes"))?;
    }
    for f in ["peer_address", "peer_address_ipv6", "route_gateway"] {
        if let Some(v) = obj.get(f) {
            check_addr_field(v, &format!("{at}.{f}"), OVPN_CLIENT, f)?;
        }
    }
    if let Some(v) = obj.get("data_ciphers") {
        check_listable_string(v, &format!("{at}.data_ciphers"))?;
    }
    if let Some(v) = obj.get("data_ciphers_fallback") {
        ep_str(
            v,
            &format!("{at}.data_ciphers_fallback"),
            OVPN_CLIENT,
            "data_ciphers_fallback",
        )?;
    }
    if let Some(v) = obj.get("static_key") {
        check_listable_string(v, &format!("{at}.static_key"))?;
    }
    if let Some(v) = obj.get("static_key_path") {
        ep_str(
            v,
            &format!("{at}.static_key_path"),
            OVPN_CLIENT,
            "static_key_path",
        )?;
    }
    if let Some(v) = obj.get("redirect_gateway_flags") {
        check_listable_string(v, &format!("{at}.redirect_gateway_flags"))?;
    }
    if let Some(v) = obj.get("servers") {
        openvpn_servers_decode(i, v)?;
    }
    if let Some(v) = obj.get("pull_filters") {
        openvpn_pull_filters_decode(i, v)?;
    }
    if let Some(v) = obj.get("tls") {
        openvpn_client_tls_decode(i, v)?;
    }
    endpoint_dial_decode(
        &at,
        obj,
        &format!("{OVPN_CLIENT}.DialerOptions"),
        &format!("{OVPN_CLIENT}.DialerOptions.AbstractDialerOptions"),
    )
}

fn openvpn_servers_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].servers");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_CLIENT,
                "servers",
                "[]option.OpenVPNRemoteOptions",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type option.OpenVPNRemoteOptions",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OVPN_REMOTE_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        let srv = "OpenVPNRemoteOptions.servers.ServerOptions";
        if let Some(v) = m.get("server") {
            ep_str(v, &format!("{path}.server"), srv, "server")?;
        }
        if let Some(v) = m.get("server_port") {
            ep_unsigned(
                v,
                &format!("{path}.server_port"),
                srv,
                "server_port",
                u16::MAX as u64,
            )?;
        }
        if let Some(v) = m.get("network") {
            ep_str(
                v,
                &format!("{path}.network"),
                "OpenVPNRemoteOptions",
                "servers.network",
            )?;
        }
    }
    Ok(())
}

fn openvpn_pull_filters_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].pull_filters");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_CLIENT,
                "pull_filters",
                "[]option.OpenVPNPullFilterOptions",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type option.OpenVPNPullFilterOptions",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OVPN_PULL_FILTER_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        for f in KNOWN_OVPN_PULL_FILTER_FIELDS {
            if let Some(v) = m.get(*f) {
                ep_str(v, &format!("{path}.{f}"), "OpenVPNPullFilterOptions", f)?;
            }
        }
    }
    Ok(())
}

fn openvpn_client_tls_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].tls");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_CLIENT,
                "tls",
                "option.OpenVPNOutboundTLSOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_TLS_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in [
        "server_name",
        "server_name_type",
        "certificate_path",
        "client_certificate_path",
        "client_key_path",
        "crl_path",
        "remote_certificate_eku",
        "remote_certificate_tls",
        "certificate_profile",
        "ns_certificate_type",
        "version_min",
        "version_max",
        "cipher",
        "groups",
    ] {
        if let Some(v) = m.get(f) {
            ep_str(v, &format!("{at}.{f}"), OVPN_CLIENT, &format!("tls.{f}"))?;
        }
    }
    for f in [
        "certificate",
        "client_certificate",
        "client_key",
        "peer_fingerprint",
        "remote_certificate_ku",
    ] {
        if let Some(v) = m.get(f) {
            check_listable_string(v, &format!("{at}.{f}"))?;
        }
    }
    if let Some(v) = m.get("control_wrap") {
        openvpn_control_wrap_decode(i, v, false)?;
    }
    Ok(())
}

fn openvpn_server_tls_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].tls");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_SERVER,
                "tls",
                "option.OpenVPNInboundTLSOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_TLS_IN_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in [
        "certificate_path",
        "key_path",
        "client_certificate_path",
        "verify_client_certificate",
        "client_name",
        "client_name_type",
        "crl_path",
        "remote_certificate_eku",
        "remote_certificate_tls",
        "certificate_profile",
        "ns_certificate_type",
        "version_min",
        "version_max",
        "cipher",
        "groups",
    ] {
        if let Some(v) = m.get(f) {
            ep_str(v, &format!("{at}.{f}"), OVPN_SERVER, &format!("tls.{f}"))?;
        }
    }
    for f in [
        "certificate",
        "key",
        "client_certificate",
        "peer_fingerprint",
        "remote_certificate_ku",
    ] {
        if let Some(v) = m.get(f) {
            check_listable_string(v, &format!("{at}.{f}"))?;
        }
    }
    if let Some(v) = m.get("control_wrap") {
        openvpn_control_wrap_decode(i, v, true)?;
    }
    Ok(())
}

fn openvpn_control_wrap_decode(i: usize, value: &Value, inbound: bool) -> Result<(), String> {
    let at = format!("endpoints[{i}].tls.control_wrap");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                if inbound { OVPN_SERVER } else { OVPN_CLIENT },
                "tls.control_wrap",
                if inbound {
                    "option.OpenVPNInboundControlWrapOptions"
                } else {
                    "option.OpenVPNControlWrapOptions"
                },
            ));
        }
    };
    let known: &[&str] = if inbound {
        KNOWN_OVPN_CWRAP_IN_FIELDS
    } else {
        KNOWN_OVPN_CWRAP_FIELDS
    };
    for key in m.keys() {
        let k = key.as_str();
        if !known.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in ["type", "direction"] {
        if let Some(v) = m.get(f) {
            ep_str(
                v,
                &format!("{at}.{f}"),
                if inbound { OVPN_SERVER } else { OVPN_CLIENT },
                &format!("tls.control_wrap.{f}"),
            )?;
        }
    }
    for f in ["key", "key_path"] {
        if let Some(v) = m.get(f) {
            check_listable_string(v, &format!("{at}.{f}"))?;
        }
    }
    if inbound && let Some(v) = m.get("force_cookie") {
        ep_bool(
            v,
            &format!("{at}.force_cookie"),
            OVPN_SERVER,
            "tls.control_wrap.force_cookie",
        )?;
    }
    Ok(())
}

fn openvpn_server_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_SERVER_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    let listen = format!("{OVPN_SERVER}.ListenOptions");
    if let Some(v) = obj.get("listen") {
        ep_str(v, &format!("{at}.listen"), &listen, "listen")?;
    }
    if let Some(v) = obj.get("listen_port") {
        ep_unsigned(
            v,
            &format!("{at}.listen_port"),
            &listen,
            "listen_port",
            u16::MAX as u64,
        )?;
    }
    for f in ["bind_interface", "netns"] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), &listen, f)?;
        }
    }
    if let Some(v) = obj.get("routing_mark") {
        check_routing_mark(v, &format!("{at}.routing_mark"))?;
    }
    for f in [
        "reuse_addr",
        "disable_tcp_keep_alive",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "proxy_protocol",
        "proxy_protocol_accept_no_header",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), &listen, f)?;
        }
    }
    for f in ["tcp_keep_alive", "tcp_keep_alive_interval", "udp_timeout"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), &listen, f)?;
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
                    &listen,
                    "detour",
                    "string",
                ));
            }
        }
    }
    let inb = format!("{OVPN_SERVER}.ListenOptions.InboundOptions");
    if let Some(v) = obj.get("sniff") {
        ep_bool(v, &format!("{at}.sniff"), &inb, "sniff")?;
    }
    if let Some(v) = obj.get("sniff_override_destination") {
        ep_bool(
            v,
            &format!("{at}.sniff_override_destination"),
            &inb,
            "sniff_override_destination",
        )?;
    }
    if let Some(v) = obj.get("sniff_timeout") {
        check_duration_field(v, &format!("{at}.sniff_timeout"), &inb, "sniff_timeout")?;
    }
    if let Some(v) = obj.get("udp_disable_domain_unmapping") {
        ep_bool(
            v,
            &format!("{at}.udp_disable_domain_unmapping"),
            &inb,
            "udp_disable_domain_unmapping",
        )?;
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
                    &inb,
                    "domain_strategy",
                    "string",
                ));
            }
        }
    }
    let epc = format!("{OVPN_SERVER}.OpenVPNEndpointOptions");
    if let Some(v) = obj.get("system") {
        ep_bool(v, &format!("{at}.system"), &epc, "system")?;
    }
    if let Some(v) = obj.get("name") {
        ep_str(v, &format!("{at}.name"), &epc, "name")?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(v, &format!("{at}.mtu"), &epc, "mtu", u32::MAX as u64)?;
    }
    if let Some(v) = obj.get("udp_mapping") {
        check_udp_nat(v, &format!("{at}.udp_mapping"), &epc, "udp_mapping")?;
    }
    if let Some(v) = obj.get("udp_filtering") {
        check_udp_nat(v, &format!("{at}.udp_filtering"), &epc, "udp_filtering")?;
    }
    if let Some(v) = obj.get("udp_nat_max") {
        ep_unsigned(
            v,
            &format!("{at}.udp_nat_max"),
            &epc,
            "udp_nat_max",
            u32::MAX as u64,
        )?;
    }
    for f in [
        "mode",
        "network",
        "remote",
        "topology",
        "key_direction",
        "cipher",
        "auth",
        "mss_fix_mode",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    for f in ["duplicate_cn", "mss_fix_disabled"] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    if let Some(v) = obj.get("remote_port") {
        ep_unsigned(
            v,
            &format!("{at}.remote_port"),
            OVPN_SERVER,
            "remote_port",
            u16::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("max_clients") {
        ep_int(v, &format!("{at}.max_clients"), OVPN_SERVER, "max_clients")?;
    }
    for f in ["mss_fix", "replay_window"] {
        if let Some(v) = obj.get(f) {
            ep_unsigned(v, &format!("{at}.{f}"), OVPN_SERVER, f, u32::MAX as u64)?;
        }
    }
    for f in ["renegotiate_bytes", "renegotiate_packets"] {
        if let Some(v) = obj.get(f) {
            check_u64_field(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    for f in [
        "replay_window_time",
        "ping_interval",
        "ping_restart",
        "renegotiate_interval",
        "handshake_window",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    if let Some(v) = obj.get("address") {
        check_prefix_list(v, &format!("{at}.address"))?;
    }
    for f in ["peer_address", "peer_address_ipv6"] {
        if let Some(v) = obj.get(f) {
            check_addr_field(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    if let Some(v) = obj.get("data_ciphers") {
        check_listable_string(v, &format!("{at}.data_ciphers"))?;
    }
    if let Some(v) = obj.get("data_ciphers_fallback") {
        ep_str(
            v,
            &format!("{at}.data_ciphers_fallback"),
            OVPN_SERVER,
            "data_ciphers_fallback",
        )?;
    }
    if let Some(v) = obj.get("static_key") {
        check_listable_string(v, &format!("{at}.static_key"))?;
    }
    if let Some(v) = obj.get("static_key_path") {
        ep_str(
            v,
            &format!("{at}.static_key_path"),
            OVPN_SERVER,
            "static_key_path",
        )?;
    }
    if let Some(v) = obj.get("users") {
        openvpn_users_decode(i, v)?;
    }
    if let Some(v) = obj.get("push") {
        openvpn_push_decode(i, v)?;
    }
    if let Some(v) = obj.get("tls") {
        openvpn_server_tls_decode(i, v)?;
    }
    Ok(())
}

fn openvpn_users_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].users");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_SERVER,
                "users",
                "[]auth.User",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type auth.User",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OVPN_USER_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        for f in KNOWN_OVPN_USER_FIELDS {
            if let Some(v) = m.get(*f) {
                ep_str(v, &format!("{path}.{f}"), "User", f)?;
            }
        }
    }
    Ok(())
}

fn openvpn_push_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].push");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_SERVER,
                "push",
                "option.OpenVPNPushOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_PUSH_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    if let Some(v) = m.get("routes") {
        check_prefix_list(v, &format!("{at}.routes"))?;
    }
    if let Some(v) = m.get("dns") {
        check_listable_addr(v, &format!("{at}.dns"))?;
    }
    if let Some(v) = m.get("search_domains") {
        check_listable_string(v, &format!("{at}.search_domains"))?;
    }
    if let Some(v) = m.get("dhcp_options") {
        check_listable_string(v, &format!("{at}.dhcp_options"))?;
    }
    if let Some(v) = m.get("redirect_gateway_flags") {
        check_listable_string(v, &format!("{at}.redirect_gateway_flags"))?;
    }
    for f in ["redirect_gateway", "block_outside_dns"] {
        if let Some(v) = m.get(f) {
            ep_bool(v, &format!("{at}.{f}"), "OpenVPNPushOptions", f)?;
        }
    }
    for f in ["ping_interval", "ping_restart"] {
        if let Some(v) = m.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), "OpenVPNPushOptions", f)?;
        }
    }
    if let Some(v) = m.get("dns_servers") {
        openvpn_push_dns_servers_decode(i, v)?;
    }
    Ok(())
}

fn openvpn_push_dns_servers_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].push.dns_servers");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                "OpenVPNPushOptions",
                "dns_servers",
                "[]option.OpenVPNPushDNSServerOptions",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type option.OpenVPNPushDNSServerOptions",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OVPN_PUSH_DNS_SERVER_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        if let Some(v) = m.get("priority") {
            ep_int(
                v,
                &format!("{path}.priority"),
                "OpenVPNPushDNSServerOptions",
                "priority",
            )?;
        }
        for f in ["addresses", "resolve_domains"] {
            if let Some(v) = m.get(f) {
                check_listable_string(v, &format!("{path}.{f}"))?;
            }
        }
        for f in ["dnssec", "transport", "sni"] {
            if let Some(v) = m.get(f) {
                ep_str(v, &format!("{path}.{f}"), "OpenVPNPushDNSServerOptions", f)?;
            }
        }
    }
    Ok(())
}

fn tailscale_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_TAILSCALE_FIELDS.contains(&k) && !DIALER_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in [
        "state_directory",
        "auth_key",
        "control_url",
        "hostname",
        "exit_node",
        "system_interface_name",
        "taildrop_directory",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), TS_EP, f)?;
        }
    }
    if let Some(v) = obj.get("exit_node_allow_lan_access") {
        ep_bool(
            v,
            &format!("{at}.exit_node_allow_lan_access"),
            TS_EP,
            "exit_node_allow_lan_access",
        )?;
    }
    for f in [
        "ephemeral",
        "accept_routes",
        "advertise_exit_node",
        "system_interface",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), TS_EP, f)?;
        }
    }
    if let Some(v) = obj.get("listen_port") {
        ep_unsigned(
            v,
            &format!("{at}.listen_port"),
            TS_EP,
            "listen_port",
            u16::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("relay_server_port") {
        match v {
            Value::Number(_) | Value::Null => {
                ep_unsigned(
                    v,
                    &format!("{at}.relay_server_port"),
                    TS_EP,
                    "relay_server_port",
                    u16::MAX as u64,
                )?;
            }
            other => {
                return Err(go_field_err(
                    &format!("{at}.relay_server_port"),
                    other,
                    TS_EP,
                    "relay_server_port",
                    "uint16",
                ));
            }
        }
    }
    if let Some(v) = obj.get("system_interface_mtu") {
        ep_unsigned(
            v,
            &format!("{at}.system_interface_mtu"),
            TS_EP,
            "system_interface_mtu",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("udp_timeout").filter(|v| !prunes_value(v)) {
        match v {
            Value::Number(_) => {}
            other => {
                return Err(go_type_error(
                    other,
                    &format!("{at}.udp_timeout"),
                    TS_EP,
                    "udp_timeout",
                    "string",
                ));
            }
        }
        if let Value::String(text) = v {
            go_parse_duration(text).map_err(|m| format!("{at}.udp_timeout: {m}"))?;
        }
    }
    if let Some(v) = obj.get("advertise_routes")
        && !v.is_null()
    {
        if v.is_array() {
            check_prefix_list(v, &format!("{at}.advertise_routes"))?;
        } else {
            return Err(format!(
                "{at}.advertise_routes: json: cannot unmarshal {} into Go struct field TailscaleEndpointOptions.advertise_routes of type []netip.Prefix",
                json_kind(v)
            ));
        }
    }
    if let Some(v) = obj.get("advertise_tags") {
        check_listable_string(v, &format!("{at}.advertise_tags"))?;
    }
    if let Some(v) = obj.get("relay_server_static_endpoints")
        && !v.is_null()
    {
        if v.is_array() {
            check_listable_addr_port(v, &format!("{at}.relay_server_static_endpoints"))?;
        } else {
            return Err(format!(
                "{at}.relay_server_static_endpoints: json: cannot unmarshal {} into Go struct field TailscaleEndpointOptions.relay_server_static_endpoints of type []netip.AddrPort",
                json_kind(v)
            ));
        }
    }
    if let Some(v) = obj.get("ssh_server") {
        tailscale_ssh_server_decode(i, v)?;
    }
    endpoint_dial_decode(
        &at,
        obj,
        &format!("{TS_EP}.DialerOptions"),
        &format!("{TS_EP}.DialerOptions.AbstractDialerOptions"),
    )
}

fn tailscale_ssh_server_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].ssh_server");
    match value {
        Value::Bool(_) | Value::Null => Ok(()),
        Value::Object(m) => {
            for key in m.keys() {
                let k = key.as_str();
                if !KNOWN_TS_SSH_FIELDS.contains(&k) {
                    return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
                }
            }
            for f in KNOWN_TS_SSH_FIELDS {
                if let Some(v) = m.get(*f) {
                    ep_bool(v, &format!("{at}.{f}"), "TailscaleSSHServerOptions", f)?;
                }
            }
            Ok(())
        }
        other => Err(go_field_err(
            &at,
            other,
            TS_EP,
            "ssh_server",
            "option._TailscaleSSHServerOptions",
        )),
    }
}

fn openconnect_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_OPENCONNECT_FIELDS.contains(&k) && !DIALER_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    if let Some(v) = obj.get("system") {
        ep_bool(v, &format!("{at}.system"), OC_EP, "system")?;
    }
    if let Some(v) = obj.get("name") {
        ep_str(v, &format!("{at}.name"), OC_EP, "name")?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(v, &format!("{at}.mtu"), OC_EP, "mtu", u32::MAX as u64)?;
    }
    if let Some(v) = obj.get("base_mtu") {
        ep_unsigned(
            v,
            &format!("{at}.base_mtu"),
            OC_EP,
            "base_mtu",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("dtls_local_port") {
        ep_unsigned(
            v,
            &format!("{at}.dtls_local_port"),
            OC_EP,
            "dtls_local_port",
            u16::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("queue_length") {
        ep_unsigned(
            v,
            &format!("{at}.queue_length"),
            OC_EP,
            "queue_length",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("udp_mapping") {
        check_udp_nat(v, &format!("{at}.udp_mapping"), OC_EP, "udp_mapping")?;
    }
    if let Some(v) = obj.get("udp_filtering") {
        check_udp_nat(v, &format!("{at}.udp_filtering"), OC_EP, "udp_filtering")?;
    }
    if let Some(v) = obj.get("udp_nat_max") {
        ep_unsigned(
            v,
            &format!("{at}.udp_nat_max"),
            OC_EP,
            "udp_nat_max",
            u32::MAX as u64,
        )?;
    }
    for f in [
        "server",
        "flavor",
        "username",
        "password",
        "auth_group",
        "cookie",
        "reported_os",
        "user_agent",
        "version",
        "local_hostname",
        "compression_mode",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), OC_EP, f)?;
        }
    }
    for f in [
        "no_udp",
        "compression_disabled",
        "ipv6_disabled",
        "http_keepalive_disabled",
        "xml_post_disabled",
        "external_auth_disabled",
        "password_authentication_disabled",
        "tcp_keep_alive_enabled",
        "pfs",
        "allow_insecure_crypto",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), OC_EP, f)?;
        }
    }
    for f in [
        "udp_timeout",
        "dpd_interval",
        "reconnect_timeout",
        "trojan_interval",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), OC_EP, f)?;
        }
    }
    if let Some(v) = obj.get("token") {
        openconnect_object_decode(
            i,
            v,
            "token",
            OC_EP,
            "option.OpenConnectTokenOptions",
            KNOWN_OC_TOKEN_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("mobile") {
        openconnect_object_decode(
            i,
            v,
            "mobile",
            OC_EP,
            "option.OpenConnectMobileOptions",
            KNOWN_OC_MOBILE_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("csd") {
        openconnect_object_decode(
            i,
            v,
            "csd",
            OC_EP,
            "option.OpenConnectCSDOptions",
            KNOWN_OC_WRAPPER_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("hip") {
        openconnect_object_decode(
            i,
            v,
            "hip",
            OC_EP,
            "option.OpenConnectHIPOptions",
            KNOWN_OC_WRAPPER_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("fortinet_host_check") {
        openconnect_object_decode(
            i,
            v,
            "fortinet_host_check",
            OC_EP,
            "option.OpenConnectFortinetHostCheckOptions",
            KNOWN_OC_FORTINET_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("tncc") {
        openconnect_tncc_decode(i, v)?;
    }
    if let Some(v) = obj.get("tls") {
        openconnect_object_decode(
            i,
            v,
            "tls",
            OC_EP,
            "option.OpenConnectTLSOptions",
            KNOWN_OC_TLS_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("form_entries") {
        openconnect_form_entries_decode(i, v)?;
    }
    endpoint_dial_decode(
        &at,
        obj,
        &format!("{OC_EP}.DialerOptions"),
        &format!("{OC_EP}.DialerOptions.AbstractDialerOptions"),
    )
}

fn openconnect_object_decode(
    i: usize,
    value: &Value,
    field: &str,
    outer: &str,
    go_ty: &str,
    known: &[&str],
) -> Result<(), String> {
    let at = format!("endpoints[{i}].{field}");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(&at, other, outer, field, go_ty));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !known.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for k in known {
        if let Some(v) = m.get(*k) {
            match v {
                Value::Bool(_) | Value::Null => {}
                Value::Number(_) if *k == "counter" => {}
                Value::String(_) => {}
                x if is_zero_json(x) => {}
                other => {
                    let ty = if *k == "counter" { "uint64" } else { "string" };
                    return Err(go_field_err(
                        &format!("{at}.{k}"),
                        other,
                        outer,
                        &format!("{field}.{k}"),
                        ty,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn openconnect_tncc_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].tncc");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OC_EP,
                "tncc",
                "option.OpenConnectTNCCOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OC_TNCC_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in ["wrapper_path", "device_id", "user_agent"] {
        if let Some(v) = m.get(f) {
            ep_str(v, &format!("{at}.{f}"), OC_EP, &format!("tncc.{f}"))?;
        }
    }
    if let Some(v) = m.get("machine_identification_enabled") {
        ep_bool(
            v,
            &format!("{at}.machine_identification_enabled"),
            OC_EP,
            "tncc.machine_identification_enabled",
        )?;
    }
    if let Some(v) = m.get("certificates") {
        let items = match v {
            Value::Array(items) => items,
            Value::Null => return Ok(()),
            other => {
                return Err(go_field_err(
                    &format!("{at}.certificates"),
                    other,
                    OC_EP,
                    "tncc.certificates",
                    "[]option.OpenConnectTNCCCertificateOptions",
                ));
            }
        };
        for (n, item) in items.iter().enumerate() {
            let path = format!("{at}.certificates[{n}]");
            let cm = match item {
                Value::Object(cm) => cm,
                other => {
                    return Err(format!(
                        "{path}: json: cannot unmarshal {} into Go value of type option.OpenConnectTNCCCertificateOptions",
                        json_kind(other)
                    ));
                }
            };
            for key in cm.keys() {
                let k = key.as_str();
                if !KNOWN_OC_TNCC_CERT_FIELDS.contains(&k) {
                    return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
                }
            }
            if let Some(cv) = cm.get("certificate") {
                check_listable_string(cv, &format!("{path}.certificate"))?;
            }
            if let Some(cv) = cm.get("certificate_path") {
                ep_str(
                    cv,
                    &format!("{path}.certificate_path"),
                    "OpenConnectTNCCCertificateOptions",
                    "certificate_path",
                )?;
            }
        }
    }
    Ok(())
}

fn openconnect_form_entries_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].form_entries");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OC_EP,
                "form_entries",
                "[]option.OpenConnectFormEntryOptions",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type option.OpenConnectFormEntryOptions",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OC_FORM_ENTRY_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        for &f in KNOWN_OC_FORM_ENTRY_FIELDS {
            if let Some(v) = m.get(f) {
                match f {
                    "promote" => {
                        ep_bool(v, &format!("{path}.{f}"), "OpenConnectFormEntryOptions", f)?
                    }
                    _ => ep_str(v, &format!("{path}.{f}"), "OpenConnectFormEntryOptions", f)?,
                }
            }
        }
    }
    Ok(())
}

/// `uint64` struct field: non-negative numbers OK.
fn check_u64_field(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        v if is_zero_json(v) => Ok(()),
        Value::Number(n) if n.as_u64().is_some() => Ok(()),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number {} into Go struct field {go_struct}.{field} of type uint64",
            go_number_literal(value)
        )),
        other => Err(go_field_err(at, other, go_struct, field, "uint64")),
    }
}

/// `*badoption.Addr` struct field: null / string / empty object OK.
fn check_addr_field(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            if s.parse::<std::net::IpAddr>().is_ok() {
                Ok(())
            } else {
                Err(format!("{at}: ParseAddr({s:?}): unable to parse IP"))
            }
        }
        Value::Object(m) if m.is_empty() => Ok(()),
        other => Err(go_field_err(at, other, go_struct, field, "netip.Addr")),
    }
}

/// `badoption.Listable[netip.Addr]` decode: single address or array; the
/// reference union error keeps both attempts (`... | ParseAddr(...): ...`).
fn check_listable_addr(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            if s.parse::<std::net::IpAddr>().is_ok() {
                Ok(())
            } else {
                Err(format!(
                    "{at}: (netip.ParseAddr({s:?}): unable to parse IP | json: cannot unmarshal string into Go value of type **netip.Addr)"
                ))
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Null => {}
                    Value::String(s) if s.parse::<std::net::IpAddr>().is_ok() => {}
                    Value::String(s) => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type **netip.Addr | ParseAddr({s:?}): unable to parse IP)"
                        ));
                    }
                    other => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type **netip.Addr | json: cannot unmarshal {} into Go value of type netip.Addr)",
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
                "{at}: (json: cannot unmarshal {kind} into Go value of type string | json: cannot unmarshal {kind} into Go value of type **netip.Addr)"
            ))
        }
    }
}

/// `badoption.Listable[netip.AddrPort]` decode.
fn check_listable_addr_port(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::String(_) => Ok(()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                match item {
                    Value::Null | Value::String(_) => {}
                    other => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type **netip.AddrPort | [{i}]: json: cannot unmarshal {} into Go value of type netip.AddrPort)",
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
                "{at}: (json: cannot unmarshal {kind} into Go value of type string | json: cannot unmarshal {kind} into Go value of type **netip.AddrPort)"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint initialize pass for openvpn-client / openvpn-server / tailscale /
// openconnect (wireguard keeps its own initializer). Orders and messages are
// byte-for-byte from sbx-src protocol/openvpn/{client,server}.go,
// protocol/openconnect/client.go, protocol/tailscale/endpoint.go and
// sing-openvpn options_validation.go / compression_options.go /
// allow_compression.go / client_supervisor.go / tls_config.go /
// peer_certificate_verifier.go, plus sing-openconnect client.go /
// tls_config.go / http_client.go / flavor.go. Probed matrix: probe_ep/*.
// ---------------------------------------------------------------------------

/// reference `validateDataCipherName` switch — exactly the first 22 entries
/// of the decode-time canonical list (TLS_* suite names are NOT data ciphers).
fn ovpn_is_data_cipher(name: &str) -> bool {
    OVPN_CANONICAL_CIPHERS[..22].contains(&name)
}

const OVPN_TLS_CERT_PROFILES: &[&str] = &["", "legacy", "preferred", "insecure", "suiteb"];
const OVPN_ALLOW_COMPRESSION: &[&str] = &["", "no", "asym", "yes"];
const OVPN_CLIENT_CERT_POLICY: &[&str] = &["", "require", "optional", "none"];
const OC_COMPRESSION_MODES: &[&str] = &["stateless", "all"];
const OC_TOKEN_MODES: &[&str] = &["totp", "hotp", "stoken", "oidc"];
const OC_PROTOCOL_BAD: &[char] = &['\x00', '\r', '\n'];

/// `openSSLKeyPurposeNames` (peer_certificate_verifier.go).
const OVPN_EKU_NAMES: &[&str] = &[
    "server",
    "client",
    "TLS Web Server Authentication",
    "TLS Web Client Authentication",
    "Code Signing",
    "E-mail Protection",
    "IPSec End System",
    "IPSec Tunnel",
    "IPSec User",
    "Time Stamping",
    "OCSP Signing",
    "Any Extended Key Usage",
    "Microsoft Server Gated Crypto",
    "Netscape Server Gated Crypto",
    "Microsoft Commercial Code Signing",
    "Microsoft Individual Code Signing",
];

/// `tlsCipherTranslationTable`: OpenSSL name + Go `tls.CipherSuiteName` name.
const OVPN_TLS_CIPHER_SUITE_NAMES: &[&str] = &[
    "RC4-SHA",
    "DES-CBC3-SHA",
    "AES128-SHA",
    "AES256-SHA",
    "AES128-SHA256",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-ECDSA-RC4-SHA",
    "ECDHE-RSA-RC4-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
];

/// `tlsGroupAliases` keys.
const OVPN_TLS_GROUP_ALIASES: &[&str] = &[
    "X25519",
    "CURVE25519",
    "SECP256R1",
    "PRIME256V1",
    "P-256",
    "NISTP256",
    "SECP384R1",
    "P-384",
    "NISTP384",
    "SECP521R1",
    "P-521",
    "NISTP521",
];

/// reference `box.go`: empty endpoint tag falls back to the entry index, and
/// every NewEndpoint error is wrapped `initialize endpoint[{i}]{type}[{tag}]`.
fn endpoint_initialize(
    i: usize,
    tag: &str,
    obj: &Map<String, Value>,
    ty: &str,
) -> Result<(), String> {
    let tag = if tag.is_empty() {
        i.to_string()
    } else {
        tag.to_string()
    };
    if ty == "wireguard" {
        // the wireguard initializer builds its own identical prefix.
        return wireguard_endpoint_initialize(i, &tag, obj);
    }
    // reference `common/dialer.New` builds the endpoint dialer during init
    if let Some(mark) = obj.get("routing_mark").and_then(Value::as_u64)
        && mark > 0
        && !cfg!(target_os = "linux")
    {
        return Err(format!(
            "initialize endpoint[{i}] {ty}[{tag}]: `routing_mark` is only supported on Linux"
        ));
    }
    let result = match ty {
        "openvpn-client" => openvpn_client_initialize(i, &tag, obj),
        "openvpn-server" => openvpn_server_initialize(i, &tag, obj),
        "tailscale" => tailscale_initialize(i, &tag, obj),
        "openconnect" => openconnect_initialize(i, &tag, obj),
        other => return Err(format!("endpoints[{i}]: unknown endpoint type: {other}")),
    };
    result.map_err(|e| format!("initialize endpoint[{i}] {ty}[{tag}]: {e}"))
}

fn ep_bool_val(obj: &Map<String, Value>, key: &str) -> bool {
    obj.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn ep_u64_val(obj: &Map<String, Value>, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// duration field → nanoseconds (decode already rejected bad text).
fn ep_ns(obj: &Map<String, Value>, key: &str) -> i128 {
    obj.get(key)
        .and_then(Value::as_str)
        .and_then(go_duration_ns)
        .unwrap_or(0)
}

/// nested object present (post-prune: non-null only; `tls: {}` prunes to nil).
fn ovpn_nested_present(obj: &Map<String, Value>, key: &str) -> bool {
    matches!(obj.get(key), Some(v) if !v.is_null() && !prunes_value(v))
}

/// `badoption.Listable` length: string (even `""`) → 1, array → len, else 0.
fn ovpn_listable_len(value: Option<&Value>) -> usize {
    match value {
        Some(Value::String(_)) => 1,
        Some(Value::Array(items)) => items.len(),
        _ => 0,
    }
}

fn ovpn_listable_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect(),
        _ => Vec::new(),
    }
}

/// reference `materialSource`: inline list joined with `\n`.
fn ovpn_material_content(value: Option<&Value>) -> String {
    tls_listable_join(value)
}

fn ovpn_material_is_set(content: &str, path: &str) -> bool {
    !content.is_empty() || !path.is_empty()
}

/// `material.Validate`: conflict only.
fn ovpn_material_source(name: &str, value: Option<&Value>, path: &str) -> Result<String, String> {
    let content = ovpn_material_content(value);
    if !path.is_empty() && !content.is_empty() {
        return Err(format!("material path and content are both set: {name}"));
    }
    Ok(content)
}

fn ovpn_required_material_source(
    name: &str,
    value: Option<&Value>,
    path: &str,
) -> Result<String, String> {
    let content = ovpn_material_source(name, value, path)?;
    if !ovpn_material_is_set(&content, path) {
        return Err(format!("missing `{name}` or `{name}_path`"));
    }
    Ok(content)
}

/// `keyDirectionValue` (protocol/openvpn/endpoint.go).
fn ovpn_key_direction_value(direction: &str) -> Result<i32, String> {
    if !OVPN_KEY_DIRECTIONS.contains(&direction) {
        return Err(format!(
            "unsupported key direction: {direction} (expected \"server\" or \"client\")"
        ));
    }
    Ok(match direction {
        "" => -1,
        "server" => 0,
        _ => 1,
    })
}

/// control-wrap activity: `Type/Key/KeyPath/Direction` (+ `ForceCookie` server-side).
fn ovpn_control_wrap_active(wrap: &Map<String, Value>, force_cookie_counts: bool) -> bool {
    let wrap_type = wrap.get("type").and_then(Value::as_str).unwrap_or("");
    let key_path = wrap.get("key_path").and_then(Value::as_str).unwrap_or("");
    let direction = wrap.get("direction").and_then(Value::as_str).unwrap_or("");
    !wrap_type.is_empty()
        || ovpn_listable_len(wrap.get("key")) > 0
        || !key_path.is_empty()
        || !direction.is_empty()
        || (force_cookie_counts && ep_bool_val(wrap, "force_cookie"))
}

/// reference `validateDataCipherName` + `tlsStreamCipherSpec` stream fallback.
fn ovpn_cipher_name_ok(cipher: &str) -> bool {
    if ovpn_is_data_cipher(cipher) {
        return true;
    }
    let base = cipher
        .strip_suffix("-CFB")
        .or_else(|| cipher.strip_suffix("-OFB"));
    match base {
        Some(base) => OVPN_STATIC_CIPHERS.contains(&format!("{base}-CBC").as_str()),
        None => false,
    }
}

/// reference `validateDataChannelNames`.
fn ovpn_validate_data_channel_names(
    options_name: &str,
    cipher: &str,
    ciphers: &[String],
    fallback: &str,
    auth: &str,
) -> Result<(), String> {
    if !ovpn_cipher_name_ok(cipher) {
        return Err(format!(
            "{options_name}.Cipher must use a canonical OpenVPN cipher name"
        ));
    }
    for (idx, data_cipher) in ciphers.iter().enumerate() {
        if data_cipher.is_empty() {
            return Err(format!("{options_name}.Ciphers[{idx}] must not be empty"));
        }
        if !ovpn_cipher_name_ok(data_cipher) {
            return Err(format!(
                "{options_name}.Ciphers[{idx}] must use a canonical OpenVPN cipher name"
            ));
        }
    }
    if !ovpn_cipher_name_ok(fallback) {
        return Err(format!(
            "{options_name}.FallbackCipher must use a canonical OpenVPN cipher name"
        ));
    }
    if !OVPN_AUTH_DIGESTS.contains(&auth) {
        return Err(format!(
            "{options_name}.Auth must use a canonical OpenVPN digest name"
        ));
    }
    Ok(())
}

/// reference `validateDataChannelPolicy`.
fn ovpn_validate_data_channel_policy(
    options_name: &str,
    mss_fix: u64,
    mss_fix_disabled: bool,
    mss_fix_mode: &str,
    replay_window: u64,
    replay_window_time_ns: i128,
) -> Result<(), String> {
    if mss_fix > 0 && mss_fix_disabled {
        return Err(format!(
            "{options_name}.MSSFix conflicts with MSSFixDisabled"
        ));
    }
    if mss_fix_disabled && !mss_fix_mode.is_empty() {
        return Err(format!(
            "{options_name}.MSSFixMode conflicts with MSSFixDisabled"
        ));
    }
    if mss_fix == 0 && !mss_fix_mode.is_empty() {
        return Err(format!("{options_name}.MSSFixMode requires MSSFix"));
    }
    if !OVPN_MSS_FIX_MODES.contains(&mss_fix_mode) {
        return Err(format!("{options_name}.MSSFixMode must be mtu or fixed"));
    }
    if replay_window > 65536 {
        return Err(format!("{options_name}.ReplayWindow must not exceed 65536"));
    }
    if !(0..=600_000_000_000).contains(&replay_window_time_ns) {
        return Err(format!(
            "{options_name}.ReplayWindowTime must be between 0s and 600s"
        ));
    }
    if replay_window_time_ns % 1_000_000_000 != 0 {
        return Err(format!(
            "{options_name}.ReplayWindowTime must use whole seconds"
        ));
    }
    Ok(())
}

/// `strconv.ParseUint(value, 16, 64)` error text (base-16, no sign/prefix).
fn ovpn_parse_hex_u64(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
        || value.starts_with('+')
        || value.starts_with('-')
    {
        return Err(format!(
            "strconv.ParseUint: parsing \"{value}\": invalid syntax"
        ));
    }
    let digits = value.trim_start_matches('0');
    if digits.len() > 16 {
        return Err(format!(
            "strconv.ParseUint: parsing \"{value}\": value out of range"
        ));
    }
    if digits.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("strconv.ParseUint: parsing \"{value}\": value out of range"))
}

/// `parseRemoteCertKeyUsages`.
fn ovpn_validate_ku_values(values: &[String]) -> Result<(), String> {
    for value in values {
        if value.is_empty() {
            return Err("empty key usage hex".to_string());
        }
        ovpn_parse_hex_u64(value)?;
    }
    Ok(())
}

/// `parseObjectIdentifier`: error text replaced by the caller.
fn ovpn_parse_object_identifier(value: &str) -> Result<(), ()> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 2 {
        return Err(());
    }
    let mut components = Vec::with_capacity(parts.len());
    for part in parts {
        if part.is_empty() {
            return Err(());
        }
        // Go strconv.Atoi: optional sign, base-10 digits.
        let (sign, digits) = match part.strip_prefix('-') {
            Some(rest) => (-1i64, rest),
            None => match part.strip_prefix('+') {
                Some(rest) => (1i64, rest),
                None => (1i64, part),
            },
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        let component: i64 = digits
            .parse::<i64>()
            .map_err(|_| ())?
            .checked_mul(sign)
            .ok_or(())?;
        if component < 0 {
            return Err(());
        }
        components.push(component as u64);
    }
    if components[0] > 2 || (components[0] < 2 && components[1] > 39) {
        return Err(());
    }
    Ok(())
}

/// `parseRemoteCertExtKeyUsage`.
fn ovpn_validate_eku_value(value: &str) -> Result<(), String> {
    if value.is_empty() || OVPN_EKU_NAMES.contains(&value) {
        return Ok(());
    }
    ovpn_parse_object_identifier(value)
        .map_err(|_| format!("unsupported remote-cert-eku value: {value}"))
}

/// `validateTLSOptionNames` (client library order, `ClientOptions.TLS` names).
/// `remote_certificate_tls` is an endpoint enum; after it passes, the library
/// `expandRemoteCertTLS` check never fails.
#[allow(clippy::too_many_arguments)]
fn ovpn_validate_tls_option_names(
    verify_x509_type: &str,
    peer_fingerprints: &[String],
    remote_cert_ku: &[String],
    remote_cert_eku: &str,
    ns_cert_type: &str,
    version_min: &str,
    version_max: &str,
    cert_profile: &str,
    tls_cipher: &str,
    tls_groups: &str,
) -> Result<(), String> {
    if !OVPN_TLS_VERIFY_X509.contains(&verify_x509_type) {
        return Err(
            "ClientOptions.TLS.VerifyX509Type must be subject, name, or name-prefix".to_string(),
        );
    }
    for (idx, fingerprint) in peer_fingerprints.iter().enumerate() {
        let ok = fingerprint.len() == 64
            && fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(format!(
                "ClientOptions.TLS.PeerFingerprint[{idx}] must be canonical lowercase hex"
            ));
        }
    }
    ovpn_validate_ku_values(remote_cert_ku)?;
    ovpn_validate_eku_value(remote_cert_eku)?;
    if !OVPN_NS_CERT_TYPES.contains(&ns_cert_type) {
        return Err("ClientOptions.TLS.NSCertificateType must be server or client".to_string());
    }
    // resolveTLSVersionBounds: min token, then max token.
    ovpn_parse_tls_version_token(version_min)?;
    ovpn_parse_tls_version_token(version_max)?;
    let parsed_min = match version_min {
        "" => 0x0303u16,
        "1.0" => 0x0301,
        "1.1" => 0x0302,
        "1.2" => 0x0303,
        _ => 0x0304,
    };
    let parsed_max = match version_max {
        "" => 0,
        "1.0" => 0x0301,
        "1.1" => 0x0302,
        "1.2" => 0x0303,
        _ => 0x0304,
    };
    if parsed_max != 0 && parsed_max < parsed_min {
        return Err("tls-version-min bigger than tls-version-max".to_string());
    }
    if !OVPN_TLS_CERT_PROFILES.contains(&cert_profile) {
        return Err(format!("unknown tls-cert-profile value: {cert_profile}"));
    }
    if !tls_cipher.is_empty() {
        for token in tls_cipher.split(':') {
            if token.is_empty() {
                return Err("tls-cipher contains an empty cipher suite".to_string());
            }
            if !OVPN_TLS_CIPHER_SUITE_NAMES.contains(&token) {
                return Err(format!("unsupported tls-cipher name: {token}"));
            }
        }
    }
    if !tls_groups.is_empty() {
        for token in tls_groups.split(':') {
            if token.is_empty() {
                return Err("tls-groups contains an empty group name".to_string());
            }
            if !OVPN_TLS_GROUP_ALIASES.contains(&token) {
                return Err(format!("unsupported tls-groups name: {token}"));
            }
        }
    }
    Ok(())
}

fn ovpn_parse_tls_version_token(token: &str) -> Result<(), String> {
    match token {
        "" | "1.0" | "1.1" | "1.2" | "1.3" => Ok(()),
        other => Err(format!("unknown tls-version parameter: {other}")),
    }
}

/// `validateTLSCredentialSet` with `requireCertAndKey = false` (client).
fn ovpn_validate_tls_credential_set(
    mode: &str,
    ca_set: bool,
    cert_set: bool,
    key_set: bool,
    fingerprint_set: bool,
) -> Result<(), String> {
    if !ca_set && !cert_set && !key_set && !fingerprint_set {
        if mode == "tls" {
            return Err(
                "tls mode: either certificate-authority or peer-fingerprint must be configured"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if mode != "tls" {
        return Err(
            "option is not supported yet: certificate material outside tls mode".to_string(),
        );
    }
    if cert_set != key_set {
        return Err("certificate and key must both be set or both omitted".to_string());
    }
    Ok(())
}

/// `validateClientPolicyOptions`.
fn ovpn_validate_client_policy_options(
    topology: &str,
    auth_retry: &str,
    pull_filters: &[Map<String, Value>],
    fragment: u64,
) -> Result<(), String> {
    if !OVPN_TOPOLOGIES.contains(&topology) {
        return Err("ClientOptions.Tunnel.Topology must be net30, p2p, or subnet".to_string());
    }
    if !OVPN_AUTH_RETRIES.contains(&auth_retry) {
        return Err(
            "ClientOptions.Authentication.AuthRetry must be none, nointeract, or interact"
                .to_string(),
        );
    }
    for (idx, filter) in pull_filters.iter().enumerate() {
        let action = filter.get("action").and_then(Value::as_str).unwrap_or("");
        if !OVPN_PULL_FILTER_ACTIONS.contains(&action) {
            return Err(format!(
                "ClientOptions.Pull.Filters[{idx}].Action must be accept, ignore, or reject"
            ));
        }
        let text = filter.get("text").and_then(Value::as_str).unwrap_or("");
        if text.is_empty() {
            return Err(format!(
                "ClientOptions.Pull.Filters[{idx}].Text must not be empty"
            ));
        }
    }
    if fragment > 0 && fragment < 68 {
        return Err("ClientOptions.DataChannel.Fragment must be zero or at least 68".to_string());
    }
    Ok(())
}

/// `validateDurationOption`.
fn ovpn_validate_duration_option(name: &str, value_ns: i128) -> Result<(), String> {
    if value_ns < 0 {
        return Err(format!("{name} must not be negative"));
    }
    if value_ns > 0 && value_ns < 1_000_000_000 {
        return Err(format!("{name} must be zero or at least 1s"));
    }
    Ok(())
}

/// `validatePingDurationOption`.
fn ovpn_validate_ping_duration_option(name: &str, value_ns: i128) -> Result<(), String> {
    ovpn_validate_duration_option(name, value_ns)?;
    if value_ns % 1_000_000_000 != 0 {
        return Err(format!("{name} must use whole seconds"));
    }
    Ok(())
}

/// `validateClientDurationOptions`.
fn ovpn_validate_client_duration_options(obj: &Map<String, Value>) -> Result<(), String> {
    let reneg = ep_ns(obj, "renegotiate_interval");
    let reneg_disabled = ep_bool_val(obj, "renegotiate_disabled");
    if reneg_disabled && reneg > 0 {
        return Err(
            "ClientOptions.Timing.RenegotiationInterval conflicts with RenegotiationDisabled"
                .to_string(),
        );
    }
    ovpn_validate_duration_option("ClientOptions.Timing.RenegotiationInterval", reneg)?;
    ovpn_validate_ping_duration_option(
        "ClientOptions.Timing.PingInterval",
        ep_ns(obj, "ping_interval"),
    )?;
    ovpn_validate_ping_duration_option(
        "ClientOptions.Timing.PingRestart",
        ep_ns(obj, "ping_restart"),
    )?;
    if ep_bool_val(obj, "ping_restart_disabled") && ep_ns(obj, "ping_restart") > 0 {
        return Err(
            "ClientOptions.Timing.PingRestart conflicts with PingRestartDisabled".to_string(),
        );
    }
    ovpn_validate_duration_option("ClientOptions.Timing.TLSTimeout", ep_ns(obj, "tls_timeout"))?;
    ovpn_validate_duration_option(
        "ClientOptions.Timing.HandWindow",
        ep_ns(obj, "handshake_window"),
    )
}

// ---------------------------------------------------------------------------
// openvpn client library phase helpers: compression, allow-compression,
// remotes (resolveClientRemotes) — sing-openvpn compression_options.go,
// allow_compression.go, client_supervisor.go.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct OvpnCompressionSettings {
    alg: u8, // 0 none, 1 stub, 2 lzo, 3 lz4, 4 stub-v2, 5 lz4-v2
    swap: bool,
    adaptive: bool,
    asymmetric: bool,
}

/// reference `compressionSettings.apply` for the `compress` directive.
fn ovpn_apply_compress(settings: &mut OvpnCompressionSettings, value: &str) -> Result<(), String> {
    match value {
        "" | "stub" => {
            settings.alg = 1;
            settings.swap = true;
        }
        "stub-v2" => settings.alg = 4,
        "lzo" => {
            settings.alg = 2;
            settings.adaptive = false;
            settings.swap = false;
        }
        "lz4" => {
            settings.alg = 3;
            settings.swap = true;
        }
        "lz4-v2" => settings.alg = 5,
        "migrate" | "none" | "no" | "disabled" | "off" => {
            *settings = OvpnCompressionSettings::default();
        }
        other => {
            return Err(format!("unsupported compression option: compress {other}"));
        }
    }
    Ok(())
}

/// reference `compressionSettings.apply` for the `comp-lzo` directive.
fn ovpn_apply_comp_lzo(settings: &mut OvpnCompressionSettings, value: &str) -> Result<(), String> {
    settings.swap = false;
    match value {
        "" | "adaptive" => {
            settings.alg = 2;
            settings.adaptive = true;
            settings.asymmetric = false;
        }
        "yes" => {
            settings.alg = 2;
            settings.adaptive = false;
            settings.asymmetric = false;
        }
        "asym" => {
            settings.alg = 2;
            settings.adaptive = false;
            settings.asymmetric = true;
        }
        "no" => {
            settings.alg = 1;
            settings.adaptive = false;
        }
        "none" | "disabled" | "off" => {
            *settings = OvpnCompressionSettings::default();
        }
        other => {
            return Err(format!("unsupported compression option: comp-lzo {other}"));
        }
    }
    Ok(())
}

fn ovpn_non_stub(settings: &OvpnCompressionSettings) -> bool {
    matches!(settings.alg, 2 | 3 | 5)
}

/// `resolveCompressionSettings` + `resolveEffectiveAllowCompressionPolicy`.
fn ovpn_resolve_compression(obj: &Map<String, Value>) -> Result<(), String> {
    let compression = obj
        .get("compression")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let compression_lzo = obj
        .get("compression_lzo")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut settings = OvpnCompressionSettings::default();
    if !compression.is_empty() {
        ovpn_apply_compress(&mut settings, &compression)?;
    }
    if !compression_lzo.is_empty() {
        ovpn_apply_comp_lzo(&mut settings, &compression_lzo)?;
    }
    let allow = obj
        .get("allow_compression")
        .and_then(Value::as_str)
        .unwrap_or("");
    if allow.is_empty() {
        return Ok(());
    }
    if !OVPN_ALLOW_COMPRESSION.contains(&allow) {
        return Err("invalid allow-compression value".to_string());
    }
    if allow == "no" && ovpn_non_stub(&settings) {
        return Err(
            "allow-compression no conflicts with statically enabled compression".to_string(),
        );
    }
    Ok(())
}

/// endpoint-side remote list: global protocol defaults to `udp`.
struct OvpnRemote {
    host: String,
    port: u64,
    protocol: String,
}

fn ovpn_build_remotes(obj: &Map<String, Value>) -> (String, Vec<OvpnRemote>) {
    let network = endpoint_str(obj, "network");
    let global = if network.is_empty() {
        "udp".to_string()
    } else {
        network.to_string()
    };
    if let Some(server) = obj.get("server").and_then(Value::as_str) {
        return (
            global,
            vec![OvpnRemote {
                host: server.to_string(),
                port: obj.get("server_port").and_then(Value::as_u64).unwrap_or(0),
                protocol: endpoint_str(obj, "network").to_string(),
            }],
        );
    }
    let mut remotes = Vec::new();
    if let Some(Value::Array(items)) = obj.get("servers") {
        for entry in items {
            let Value::Object(remote) = entry else {
                continue;
            };
            remotes.push(OvpnRemote {
                host: endpoint_str(remote, "server").to_string(),
                port: remote
                    .get("server_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                protocol: endpoint_str(remote, "network").to_string(),
            });
        }
    }
    (global, remotes)
}

/// `resolveTransportProtocol`: concrete endpoint values never use "".
fn ovpn_resolve_transport_protocol(protocol: &str) -> Result<(), String> {
    if !protocol.is_empty() && OVPN_CLIENT_PROTOCOLS.contains(&protocol) {
        Ok(())
    } else {
        Err("unsupported openvpn protocol".to_string())
    }
}

/// `resolveClientRemotes`: global enum → per-remote host → port → enum.
fn ovpn_resolve_client_remotes(global: &str, remotes: &[OvpnRemote]) -> Result<(), String> {
    ovpn_resolve_transport_protocol(global)?;
    for (idx, remote) in remotes.iter().enumerate() {
        let host = remote.host.as_str();
        if host.is_empty()
            || host.contains([' ', '\t', '\r', '\n'])
            || host.starts_with('[')
            || host.ends_with(']')
        {
            return Err(format!(
                "option is not supported yet: invalid remote host at index {idx}"
            ));
        }
        if remote.port == 0 {
            return Err(format!(
                "option is not supported yet: empty remote port at index {idx}"
            ));
        }
        let protocol = if remote.protocol.is_empty() {
            global
        } else {
            remote.protocol.as_str()
        };
        ovpn_resolve_transport_protocol(protocol)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// openvpn-client initialize — sbx-src protocol/openvpn/client.go
// buildClientOptions (157) → buildClientTunnelOptions (407) →
// buildStaticKeyClientOptions (316) / tls branch (181) → NewClient library
// phase (sing-openvpn client.go NewClient → validateImplementedClientOptions).
// ---------------------------------------------------------------------------

fn openvpn_client_initialize(i: usize, tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let _ = (i, tag);
    let mode = endpoint_str(obj, "mode");
    let mode = if mode.is_empty() { "tls" } else { mode };
    if !OVPN_MODES.contains(&mode) {
        return Err(format!(
            "unsupported mode: {mode} (expected \"tls\" or \"static_key\")"
        ));
    }
    let server = endpoint_str(obj, "server");
    let servers = match obj.get("servers") {
        Some(Value::Array(items)) => items.len(),
        _ => 0,
    };
    if !server.is_empty() && servers > 0 {
        return Err("`server` is conflict with `servers`".to_string());
    }
    if server.is_empty() && servers == 0 {
        return Err("missing `server` or `servers`".to_string());
    }
    let (global_protocol, remotes) = ovpn_build_remotes(obj);

    // buildClientTunnelOptions(options, mode == static_key)
    let peer4 = endpoint_str(obj, "peer_address");
    if !peer4.is_empty() && parse_ip_addr(peer4) != Some(true) {
        return Err("`peer_address` must be an IPv4 address".to_string());
    }
    let peer6 = endpoint_str(obj, "peer_address_ipv6");
    if !peer6.is_empty() && parse_ip_addr(peer6) != Some(false) {
        return Err("`peer_address_ipv6` must be an IPv6 address".to_string());
    }
    let mut addresses: Vec<String> = Vec::new();
    if let Some(Value::Array(items)) = obj.get("address") {
        for item in items {
            match item.as_str() {
                Some(s) => addresses.push(s.to_string()),
                None => return Err("`address[0]` is invalid".to_string()),
            }
        }
    }
    let mut has4 = false;
    let mut has6 = false;
    for (addr_index, address) in addresses.iter().enumerate() {
        let host = address.split('/').next().unwrap_or("");
        match parse_ip_addr(host) {
            Some(true) => has4 = true,
            Some(false) => has6 = true,
            None => return Err(format!("`address[{addr_index}]` is invalid")),
        }
    }
    if mode == "static_key" {
        if addresses.is_empty() {
            return Err("missing `address` in `static_key` mode".to_string());
        }
        if has4 && peer4.is_empty() {
            return Err(
                "missing `peer_address` for the IPv4 tunnel address in `static_key` mode"
                    .to_string(),
            );
        }
        if has6 && peer6.is_empty() {
            return Err(
                "missing `peer_address_ipv6` for the IPv6 tunnel address in `static_key` mode"
                    .to_string(),
            );
        }
        if !peer4.is_empty() && !has4 {
            return Err(
                "`peer_address` requires an IPv4 tunnel `address` in `static_key` mode".to_string(),
            );
        }
        if !peer6.is_empty() && !has6 {
            return Err(
                "`peer_address_ipv6` requires an IPv6 tunnel `address` in `static_key` mode"
                    .to_string(),
            );
        }
    }

    if mode == "static_key" {
        openvpn_client_static_options(obj)?;
    } else {
        openvpn_client_tls_options(obj)?;
    }

    // NewClient library phase (endpoint defaults guarantee non-empty values).
    ovpn_resolve_client_remotes(&global_protocol, &remotes)?;
    let fragment = ep_u64_val(obj, "fragment");
    if fragment > 0
        && remotes.iter().any(|remote| {
            let protocol = if remote.protocol.is_empty() {
                global_protocol.as_str()
            } else {
                remote.protocol.as_str()
            };
            protocol.starts_with("tcp")
        })
    {
        return Err("option is not supported yet: fragment with tcp remote".to_string());
    }
    ovpn_resolve_compression(obj)?;
    ovpn_validate_client_duration_options(obj)?;
    let cipher = endpoint_str(obj, "cipher");
    let data_ciphers = ovpn_listable_values(obj.get("data_ciphers"));
    let data_ciphers_fallback = endpoint_str(obj, "data_ciphers_fallback");
    let auth = endpoint_str(obj, "auth");
    ovpn_validate_data_channel_names(
        "ClientOptions.DataChannel",
        cipher,
        &data_ciphers,
        data_ciphers_fallback,
        auth,
    )?;
    ovpn_validate_data_channel_policy(
        "ClientOptions.DataChannel",
        ep_u64_val(obj, "mss_fix"),
        ep_bool_val(obj, "mss_fix_disabled"),
        endpoint_str(obj, "mss_fix_mode"),
        ep_u64_val(obj, "replay_window"),
        ep_ns(obj, "replay_window_time"),
    )?;
    if mode == "static_key" {
        if cipher.is_empty() {
            return Err(
                "ClientOptions.DataChannel.Cipher is required in static_key mode".to_string(),
            );
        }
        if !OVPN_STATIC_CIPHERS.contains(&cipher) {
            return Err(format!(
                "ClientOptions.DataChannel.Cipher is not supported in static_key mode: {cipher}"
            ));
        }
        if !data_ciphers.is_empty() || !data_ciphers_fallback.is_empty() {
            return Err(
                "option is not supported yet: data_ciphers in static_key mode; use Cipher"
                    .to_string(),
            );
        }
    }

    // ClientTLSOptions inputs (tls branch filled them; static mode keeps "").
    let tls = match obj.get("tls") {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    };
    let tls_get = |key: &str| -> String {
        tls.and_then(|m| m.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let mut verify_x509_type = tls_get("server_name_type");
    if verify_x509_type.is_empty() && !tls_get("server_name").is_empty() {
        verify_x509_type = "name".to_string();
    }
    let peer_fingerprints = ovpn_listable_values(tls.and_then(|m| m.get("peer_fingerprint")));
    let remote_cert_ku = ovpn_listable_values(tls.and_then(|m| m.get("remote_certificate_ku")));
    ovpn_validate_tls_option_names(
        &verify_x509_type,
        &peer_fingerprints,
        &remote_cert_ku,
        &tls_get("remote_certificate_eku"),
        &tls_get("ns_certificate_type"),
        &tls_get("version_min"),
        &tls_get("version_max"),
        &tls_get("certificate_profile"),
        &tls_get("cipher"),
        &tls_get("groups"),
    )?;

    // validateTLSCredentialSet(mode, ..., requireCertAndKey=false)
    let ca_content = tls_listable_join(tls.and_then(|m| m.get("certificate")));
    let ca_path = tls_get("certificate_path");
    let cert_content = tls_listable_join(tls.and_then(|m| m.get("client_certificate")));
    let cert_path = tls_get("client_certificate_path");
    let key_content = tls_listable_join(tls.and_then(|m| m.get("client_key")));
    let key_path = tls_get("client_key_path");
    ovpn_validate_tls_credential_set(
        mode,
        ovpn_material_is_set(&ca_content, &ca_path),
        ovpn_material_is_set(&cert_content, &cert_path),
        ovpn_material_is_set(&key_content, &key_path),
        !peer_fingerprints.is_empty(),
    )?;

    let topology = endpoint_str(obj, "topology");
    let auth_retry = endpoint_str(obj, "auth_retry");
    let mut pull_filters: Vec<Map<String, Value>> = Vec::new();
    if let Some(Value::Array(items)) = obj.get("pull_filters") {
        for item in items {
            if let Value::Object(m) = item {
                pull_filters.push(m.clone());
            }
        }
    }
    ovpn_validate_client_policy_options(topology, auth_retry, &pull_filters, fragment)
}

/// buildStaticKeyClientOptions (client.go:316).
fn openvpn_client_static_options(obj: &Map<String, Value>) -> Result<(), String> {
    if ovpn_nested_present(obj, "tls") {
        return Err("`tls` options are not supported in `static_key` mode".to_string());
    }
    let auth_retry = endpoint_str(obj, "auth_retry");
    if !endpoint_str(obj, "username").is_empty()
        || !endpoint_str(obj, "password").is_empty()
        || (!auth_retry.is_empty() && auth_retry != "none")
        || !endpoint_str(obj, "static_challenge").is_empty()
        || ep_bool_val(obj, "static_challenge_echo")
    {
        return Err(
            "username/password authentication is not supported in `static_key` mode".to_string(),
        );
    }
    if ep_bool_val(obj, "route_no_pull") || ovpn_listable_len(obj.get("pull_filters")) > 0 {
        return Err("pull options are not supported in `static_key` mode".to_string());
    }
    if ep_ns(obj, "renegotiate_interval") != 0
        || ep_bool_val(obj, "renegotiate_disabled")
        || ep_u64_val(obj, "renegotiate_bytes") != 0
        || ep_u64_val(obj, "renegotiate_packets") != 0
        || ep_ns(obj, "tls_timeout") != 0
        || ep_ns(obj, "handshake_window") != 0
    {
        return Err(
            "TLS timing and renegotiation options are not supported in `static_key` mode"
                .to_string(),
        );
    }
    if ovpn_listable_len(obj.get("data_ciphers")) > 0
        || !endpoint_str(obj, "data_ciphers_fallback").is_empty()
    {
        return Err(
            "`data_ciphers` and `data_ciphers_fallback` are not supported in `static_key` mode; use `cipher`"
                .to_string(),
        );
    }
    ovpn_required_material_source(
        "static_key",
        obj.get("static_key"),
        endpoint_str(obj, "static_key_path"),
    )?;
    ovpn_key_direction_value(endpoint_str(obj, "key_direction"))?;
    Ok(())
}

/// tls branch (client.go:181).
fn openvpn_client_tls_options(obj: &Map<String, Value>) -> Result<(), String> {
    if !ovpn_nested_present(obj, "tls") {
        return Err("missing `tls` options".to_string());
    }
    if ovpn_listable_len(obj.get("static_key")) > 0
        || !endpoint_str(obj, "static_key_path").is_empty()
    {
        return Err(
            "`static_key` and `static_key_path` are only supported in `static_key` mode"
                .to_string(),
        );
    }
    if !endpoint_str(obj, "key_direction").is_empty() {
        return Err(
            "`key_direction` is only supported in `static_key` mode; use `tls.control_wrap.direction` for `tls_auth`"
                .to_string(),
        );
    }
    if !endpoint_str(obj, "cipher").is_empty() {
        return Err(
            "`cipher` is only supported in `static_key` mode; use `data_ciphers` or `data_ciphers_fallback` in TLS mode"
                .to_string(),
        );
    }
    let tls = match obj.get("tls") {
        Some(Value::Object(m)) => m,
        _ => return Err("missing `tls` options".to_string()),
    };
    ovpn_material_source(
        "tls.certificate",
        tls.get("certificate"),
        &tls_str(tls, "certificate_path"),
    )?;
    ovpn_material_source(
        "tls.client_certificate",
        tls.get("client_certificate"),
        &tls_str(tls, "client_certificate_path"),
    )?;
    ovpn_material_source(
        "tls.client_key",
        tls.get("client_key"),
        &tls_str(tls, "client_key_path"),
    )?;
    // control wrap
    if let Some(Value::Object(wrap)) = tls.get("control_wrap")
        && ovpn_control_wrap_active(wrap, false)
    {
        let control_key = ovpn_required_material_source(
            "tls.control_wrap.key",
            wrap.get("key"),
            &tls_str(wrap, "key_path"),
        )?;
        let _ = control_key;
        let wrap_type = tls_str(wrap, "type");
        let direction = tls_str(wrap, "direction");
        match wrap_type.as_str() {
            "tls_auth" => {
                ovpn_key_direction_value(&direction)?;
            }
            "tls_crypt" | "tls_crypt_v2" => {
                if !direction.is_empty() {
                    return Err(
                        "`tls.control_wrap.direction` is only supported by `tls_auth`".to_string(),
                    );
                }
            }
            "" => return Err("missing control wrap type".to_string()),
            other => return Err(format!("unknown control wrap type: {other}")),
        }
    }
    let remote_certificate_tls = tls_str(tls, "remote_certificate_tls");
    if !OVPN_REMOTE_CERT_TLS.contains(&remote_certificate_tls.as_str()) {
        return Err(format!(
            "invalid `tls.remote_certificate_tls`: {remote_certificate_tls}"
        ));
    }
    let remote_certificate_eku = tls_str(tls, "remote_certificate_eku");
    if !remote_certificate_eku.is_empty() && !remote_certificate_tls.is_empty() {
        return Err(
            "`tls.remote_certificate_eku` is conflict with `tls.remote_certificate_tls`"
                .to_string(),
        );
    }
    Ok(())
}

fn tls_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

// ---------------------------------------------------------------------------
// openvpn-server initialize — sbx-src protocol/openvpn/server.go
// NewServerEndpoint → buildServerOptions (264) at check time; the ovpn.NewServer
// library (validateImplementedServerOptions / validateServerTunnelOptions /
// validateServerResourceOptions / applyServerPush DNSSEC etc.) runs at Start()
// and is unreachable during `check`.
// ---------------------------------------------------------------------------

fn openvpn_server_initialize(
    _i: usize,
    _tag: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
    let mode = endpoint_str(obj, "mode");
    let mode = if mode.is_empty() { "tls" } else { mode };
    if !OVPN_MODES.contains(&mode) {
        return Err(format!(
            "unsupported mode: {mode} (expected \"tls\" or \"static_key\")"
        ));
    }
    let mut addresses: Vec<String> = Vec::new();
    if let Some(Value::Array(items)) = obj.get("address") {
        for item in items {
            match item.as_str() {
                Some(s) => addresses.push(s.to_string()),
                None => return Err("server address[0] is invalid".to_string()),
            }
        }
    }
    if addresses.is_empty() {
        return Err("missing server address".to_string());
    }
    // validateServerAddresses: sequential duplicate/validity scan.
    let mut has4 = false;
    let mut has6 = false;
    for (addr_index, address) in addresses.iter().enumerate() {
        let host = address.split('/').next().unwrap_or("");
        match parse_ip_addr(host) {
            Some(true) => {
                if has4 {
                    return Err("multiple IPv4 server address pools are not supported".to_string());
                }
                has4 = true;
            }
            Some(false) => {
                if has6 {
                    return Err("multiple IPv6 server address pools are not supported".to_string());
                }
                has6 = true;
            }
            None => return Err(format!("server address[{addr_index}] is invalid")),
        }
    }
    let topology = endpoint_str(obj, "topology");
    if !OVPN_TOPOLOGIES.contains(&topology) {
        return Err(format!(
            "invalid topology {topology}, allowed values: subnet, p2p, net30"
        ));
    }
    let network = endpoint_str(obj, "network");
    if !OVPN_SERVER_PROTOCOLS.contains(&network) {
        return Err(format!("unsupported network: {network}"));
    }
    let protocol = if network.is_empty() { "udp" } else { network };

    if mode == "static_key" {
        return openvpn_server_static_options(obj, protocol, &addresses, has4, has6);
    }

    if !ovpn_nested_present(obj, "tls") {
        return Err("missing `tls` options".to_string());
    }
    if ovpn_listable_len(obj.get("static_key")) > 0
        || !endpoint_str(obj, "static_key_path").is_empty()
        || !endpoint_str(obj, "key_direction").is_empty()
        || !endpoint_str(obj, "cipher").is_empty()
        || !endpoint_str(obj, "remote").is_empty()
        || obj.get("remote_port").and_then(Value::as_u64).unwrap_or(0) != 0
        || obj
            .get("peer_address")
            .is_some_and(|v| !prunes_value(v) && !v.is_null())
        || obj
            .get("peer_address_ipv6")
            .is_some_and(|v| !prunes_value(v) && !v.is_null())
    {
        return Err("static-key server options require `mode: static_key`".to_string());
    }
    openvpn_server_tls_options(obj)?;
    openvpn_server_push_options(obj)
}

/// buildStaticKeyServerOptions (server.go:346).
fn openvpn_server_static_options(
    obj: &Map<String, Value>,
    protocol: &str,
    addresses: &[String],
    has4: bool,
    has6: bool,
) -> Result<(), String> {
    if ovpn_nested_present(obj, "tls") {
        return Err("`tls` options are not supported in `static_key` mode".to_string());
    }
    if ovpn_listable_len(obj.get("users")) > 0 || ep_bool_val(obj, "duplicate_cn") {
        return Err("user authentication is not supported in `static_key` mode".to_string());
    }
    if ovpn_nested_present(obj, "push") {
        return Err("push options are not supported in `static_key` mode".to_string());
    }
    if ep_ns(obj, "renegotiate_interval") != 0
        || ep_bool_val(obj, "renegotiate_disabled")
        || ep_u64_val(obj, "renegotiate_bytes") != 0
        || ep_u64_val(obj, "renegotiate_packets") != 0
        || ep_ns(obj, "handshake_window") != 0
    {
        return Err(
            "TLS timing and renegotiation options are not supported in `static_key` mode"
                .to_string(),
        );
    }
    if ovpn_listable_len(obj.get("data_ciphers")) > 0
        || !endpoint_str(obj, "data_ciphers_fallback").is_empty()
    {
        return Err(
            "`data_ciphers` and `data_ciphers_fallback` are not supported in `static_key` mode; use `cipher`"
                .to_string(),
        );
    }
    ovpn_required_material_source(
        "static_key",
        obj.get("static_key"),
        endpoint_str(obj, "static_key_path"),
    )?;
    ovpn_key_direction_value(endpoint_str(obj, "key_direction"))?;
    let peer4 = endpoint_str(obj, "peer_address");
    if !peer4.is_empty() && parse_ip_addr(peer4) != Some(true) {
        return Err("`peer_address` must be an IPv4 address".to_string());
    }
    let peer6 = endpoint_str(obj, "peer_address_ipv6");
    if !peer6.is_empty() && parse_ip_addr(peer6) != Some(false) {
        return Err("`peer_address_ipv6` must be an IPv6 address".to_string());
    }
    let _ = addresses;
    if has4 && peer4.is_empty() {
        return Err("missing `peer_address` for the IPv4 static-key tunnel".to_string());
    }
    if has6 && peer6.is_empty() {
        return Err("missing `peer_address_ipv6` for the IPv6 static-key tunnel".to_string());
    }
    if !peer4.is_empty() && !has4 {
        return Err(
            "`peer_address` requires an IPv4 tunnel `address` in `static_key` mode".to_string(),
        );
    }
    if !peer6.is_empty() && !has6 {
        return Err(
            "`peer_address_ipv6` requires an IPv6 tunnel `address` in `static_key` mode"
                .to_string(),
        );
    }
    let remote = endpoint_str(obj, "remote");
    let remote_port = obj.get("remote_port").and_then(Value::as_u64).unwrap_or(0);
    if protocol == "udp" {
        if remote.is_empty() || remote_port == 0 {
            return Err(
                "`remote` and `remote_port` are required for a UDP static-key server".to_string(),
            );
        }
    } else if !remote.is_empty() || remote_port != 0 {
        return Err(
            "`remote` and `remote_port` are only used by a UDP static-key server".to_string(),
        );
    }
    Ok(())
}

/// tls branch (server.go:297) — buildServerTLSOptions (442).
fn openvpn_server_tls_options(obj: &Map<String, Value>) -> Result<(), String> {
    let tls = match obj.get("tls") {
        Some(Value::Object(m)) => m,
        _ => return Err("missing `tls` options".to_string()),
    };
    let tls_str_of = |map: &Map<String, Value>, key: &str| -> String {
        map.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let vcc = tls_str_of(tls, "verify_client_certificate");
    if !OVPN_CLIENT_CERT_POLICY.contains(&vcc.as_str()) {
        return Err(format!(
            "invalid client certificate policy {vcc}, allowed values: require, optional, none"
        ));
    }
    ovpn_required_material_source(
        "tls.certificate",
        tls.get("certificate"),
        &tls_str_of(tls, "certificate_path"),
    )?;
    ovpn_required_material_source("tls.key", tls.get("key"), &tls_str_of(tls, "key_path"))?;
    ovpn_material_source(
        "tls.client_certificate",
        tls.get("client_certificate"),
        &tls_str_of(tls, "client_certificate_path"),
    )?;
    let remote_certificate_tls = tls_str_of(tls, "remote_certificate_tls");
    if !OVPN_REMOTE_CERT_TLS.contains(&remote_certificate_tls.as_str()) {
        return Err(format!(
            "invalid `tls.remote_certificate_tls`: {remote_certificate_tls}"
        ));
    }
    let remote_certificate_eku = tls_str_of(tls, "remote_certificate_eku");
    if !remote_certificate_eku.is_empty() && !remote_certificate_tls.is_empty() {
        return Err(
            "`tls.remote_certificate_eku` is conflict with `tls.remote_certificate_tls`"
                .to_string(),
        );
    }
    // control wrap: activity includes force_cookie on the server.
    if let Some(Value::Object(wrap)) = tls.get("control_wrap")
        && ovpn_control_wrap_active(wrap, true)
    {
        let wrap_key = ovpn_required_material_source(
            "tls.control_wrap.key",
            wrap.get("key"),
            &tls_str_of(wrap, "key_path"),
        )?;
        let _ = wrap_key;
        let wrap_type = tls_str_of(wrap, "type");
        let direction = tls_str_of(wrap, "direction");
        let force_cookie = ep_bool_val(wrap, "force_cookie");
        match wrap_type.as_str() {
            "tls_auth" => {
                if force_cookie {
                    return Err(
                        "`tls.control_wrap.force_cookie` is only supported by `tls_crypt_v2`"
                            .to_string(),
                    );
                }
                ovpn_key_direction_value(&direction)?;
            }
            "tls_crypt" => {
                if !direction.is_empty() {
                    return Err(
                        "`tls.control_wrap.direction` is only supported by `tls_auth`".to_string(),
                    );
                }
                if force_cookie {
                    return Err(
                        "`tls.control_wrap.force_cookie` is only supported by `tls_crypt_v2`"
                            .to_string(),
                    );
                }
            }
            "tls_crypt_v2" => {
                if !direction.is_empty() {
                    return Err(
                        "`tls.control_wrap.direction` is only supported by `tls_auth`".to_string(),
                    );
                }
            }
            "" => return Err("missing control wrap type".to_string()),
            other => return Err(format!("unknown control wrap type: {other}")),
        }
    }
    Ok(())
}

/// applyServerPushOptions (server.go:536) — endpoint-stage errors only.
fn openvpn_server_push_options(obj: &Map<String, Value>) -> Result<(), String> {
    let Some(Value::Object(push)) = obj.get("push") else {
        return Ok(());
    };
    if let Some(Value::Array(dns_servers)) = push.get("dns_servers") {
        for (server_index, server) in dns_servers.iter().enumerate() {
            let Value::Object(server) = server else {
                continue;
            };
            if let Some(Value::Array(items)) = server.get("addresses") {
                for (address_index, item) in items.iter().enumerate() {
                    let value = item.as_str().unwrap_or("");
                    if !ovpn_push_dns_addr_ok(value) {
                        return Err(format!(
                            "invalid push.dns_servers[{server_index}].addresses[{address_index}]: {value}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// netip.ParseAddr / ParseAddrPort with a non-zero port requirement.
fn ovpn_push_dns_addr_ok(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return matches!(port.parse::<u16>(), Ok(p) if p != 0);
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.contains(':') || host.parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }
    matches!(port.parse::<u16>(), Ok(p) if p != 0)
}

// ---------------------------------------------------------------------------
// tailscale initialize — sbx-src/protocol/tailscale/endpoint.go NewEndpoint.
// ---------------------------------------------------------------------------

fn tailscale_initialize(_i: usize, _tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    // ssh_server.enabled runs adapter.CheckSecurityFeature — a runtime
    // platform feature check that passes for the reference in check mode.
    if let Some(Value::Array(items)) = obj.get("advertise_routes") {
        for item in items {
            let Some(s) = item.as_str() else { continue };
            let Some((host, bits)) = s.split_once('/') else {
                continue;
            };
            let unspecified = if host.contains(':') {
                host.parse::<std::net::Ipv6Addr>()
                    .map(|a| a.is_unspecified())
                    .unwrap_or(false)
            } else {
                host.parse::<std::net::Ipv4Addr>()
                    .map(|a| a.is_unspecified())
                    .unwrap_or(false)
            };
            if unspecified && bits == "0" {
                return Err(
                    "`advertise_routes` cannot be default, use `advertise_exit_node` instead."
                        .to_string(),
                );
            }
        }
    } else if let Some(Value::String(s)) = obj.get("advertise_routes") {
        let Some((host, bits)) = s.split_once('/') else {
            return Ok(());
        };
        let unspecified = if host.contains(':') {
            host.parse::<std::net::Ipv6Addr>()
                .map(|a| a.is_unspecified())
                .unwrap_or(false)
        } else {
            host.parse::<std::net::Ipv4Addr>()
                .map(|a| a.is_unspecified())
                .unwrap_or(false)
        };
        if unspecified && bits == "0" {
            return Err(
                "`advertise_routes` cannot be default, use `advertise_exit_node` instead."
                    .to_string(),
            );
        }
    }
    if ep_bool_val(obj, "advertise_exit_node") && !endpoint_str(obj, "exit_node").is_empty() {
        return Err(
            "cannot advertise an exit node and use an exit node at the same time.".to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// openconnect initialize — sbx-src/protocol/openconnect/client.go NewEndpoint
// (keepalive → url.Parse → materials) + sing-openconnect NewClient
// (defaults → token → validateClientOptions → parseServerURL → buildClientTLS →
// flavor).
// ---------------------------------------------------------------------------

fn openconnect_initialize(_i: usize, _tag: &str, obj: &Map<String, Value>) -> Result<(), String> {
    let keep_alive_enabled = ep_bool_val(obj, "tcp_keep_alive_enabled")
        || ep_ns(obj, "tcp_keep_alive") != 0
        || ep_ns(obj, "tcp_keep_alive_interval") != 0;
    if keep_alive_enabled && ep_bool_val(obj, "disable_tcp_keep_alive") {
        return Err("tcp_keep_alive_enabled conflicts with disable_tcp_keep_alive".to_string());
    }
    // CheckSecurityFeature for csd/hip/tncc wrapper paths is a runtime check.
    let server = endpoint_str(obj, "server");
    oc_check_url_parse(server)?;
    // buildClientOptions material sources (validate-only).
    let tls = match obj.get("tls") {
        Some(Value::Object(m)) => m,
        _ => &Map::new(),
    };
    oc_material_source(
        "tls.certificate_authority",
        tls.get("certificate_authority"),
        &oc_str(tls, "certificate_authority_path"),
    )?;
    oc_material_source(
        "tls.client_certificate",
        tls.get("client_certificate"),
        &oc_str(tls, "client_certificate_path"),
    )?;
    oc_material_source(
        "tls.client_key",
        tls.get("client_key"),
        &oc_str(tls, "client_key_path"),
    )?;
    oc_material_source(
        "tls.mca_certificate",
        tls.get("mca_certificate"),
        &oc_str(tls, "mca_certificate_path"),
    )?;
    oc_material_source(
        "tls.mca_key",
        tls.get("mca_key"),
        &oc_str(tls, "mca_key_path"),
    )?;
    if let Some(Value::Object(tncc)) = obj.get("tncc")
        && let Some(Value::Array(certs)) = tncc.get("certificates")
    {
        for (cert_index, cert) in certs.iter().enumerate() {
            let Value::Object(cert) = cert else { continue };
            oc_material_source(
                &format!("tncc.certificates[{cert_index}].certificate"),
                cert.get("certificate"),
                &oc_str(cert, "certificate_path"),
            )?;
        }
    }

    // openconnect.NewClient
    if server.is_empty() {
        return Err("missing openconnect server".to_string());
    }
    let token = match obj.get("token") {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    };
    let token_secret = token.map(|m| oc_str(m, "secret")).unwrap_or_default();
    let token_secret_path = token.map(|m| oc_str(m, "secret_path")).unwrap_or_default();
    if !token_secret_path.is_empty() {
        if !token_secret.is_empty() {
            return Err("token secret and secret path cannot both be configured".to_string());
        }
        go_read_file(&token_secret_path).map_err(|e| {
            format!("load token secret: read openconnect material: open {token_secret_path}: {e}")
        })?;
    }
    oc_validate_client_options(obj)?;

    // parseServerURL(options.Server)
    oc_check_server_url(server)?;

    // buildClientTLS(options.TLSConfig)
    oc_build_client_tls(tls)?;

    // newFlavorFrontend(options.Flavor) — flavor defaults to "anyconnect".
    let flavor = endpoint_str(obj, "flavor");
    if !OC_FLAVORS.contains(&flavor) {
        return Err(format!("unsupported openconnect flavor: {flavor}"));
    }
    Ok(())
}

fn oc_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// reference `materialSource` (sing-openconnect material.go).
fn oc_material_source(name: &str, value: Option<&Value>, path: &str) -> Result<String, String> {
    let content = tls_listable_join(value);
    if !path.is_empty() && !content.is_empty() {
        return Err(format!("material path and content are both set: {name}"));
    }
    Ok(content)
}

/// reference `validateClientOptions` (sing-openconnect client.go:202).
fn oc_validate_client_options(obj: &Map<String, Value>) -> Result<(), String> {
    // char scan: fixed order (Go map iteration is randomized; DTLS cipher
    // fields do not exist in the endpoint options).
    for (name, key) in [
        ("local hostname", "local_hostname"),
        ("user agent", "user_agent"),
        ("version", "version"),
    ] {
        let value = oc_str(obj, key);
        if value.chars().any(|c| OC_PROTOCOL_BAD.contains(&c)) {
            return Err(format!("{name} contains an invalid protocol character"));
        }
    }
    if let Some(Value::Object(mobile)) = obj.get("mobile") {
        for (name, key) in [
            ("mobile platform version", "platform_version"),
            ("mobile device type", "device_type"),
            ("mobile device unique ID", "device_unique_id"),
        ] {
            let value = oc_str(mobile, key);
            if value.is_empty() {
                return Err(format!("{name} cannot be empty"));
            }
            if value.chars().any(|c| OC_PROTOCOL_BAD.contains(&c)) {
                return Err(format!("{name} contains an invalid protocol character"));
            }
        }
    }
    if ep_ns(obj, "reconnect_timeout") < 0 {
        return Err("reconnect timeout cannot be negative".to_string());
    }
    if ep_ns(obj, "trojan_interval") < 0 {
        return Err("trojan interval cannot be negative".to_string());
    }
    let dpd = ep_ns(obj, "dpd_interval");
    if !(0..=4_611_686_018_427_387_903).contains(&dpd) {
        return Err("DPD interval is outside the supported range".to_string());
    }
    let mtu = ep_u64_val(obj, "mtu");
    let base_mtu = ep_u64_val(obj, "base_mtu");
    if mtu > 65535 || base_mtu > 65535 {
        return Err("MTU exceeds wire limit".to_string());
    }
    // queue_length: u32 can never exceed usize::MAX/2 on supported targets.
    let raw_mode = oc_str(obj, "compression_mode");
    let mode = if raw_mode.is_empty() {
        "stateless"
    } else {
        raw_mode.as_str()
    };
    if !OC_COMPRESSION_MODES.contains(&mode) {
        return Err(format!("unsupported compression mode: {mode}"));
    }
    if ep_bool_val(obj, "compression_disabled") && mode != "stateless" {
        return Err(format!(
            "compression_disabled conflicts with compression mode {mode}"
        ));
    }
    if let Some(Value::Array(entries)) = obj.get("form_entries") {
        for entry in entries {
            let Value::Object(entry) = entry else {
                continue;
            };
            let submission_key = oc_str(entry, "submission_key");
            let form_id = oc_str(entry, "form_id");
            let name = oc_str(entry, "name");
            if submission_key.is_empty() && (form_id.is_empty() || name.is_empty()) {
                return Err(
                    "form entry requires a submission key or a form ID and field name".to_string(),
                );
            }
            if ep_bool_val(entry, "promote") && !oc_str(entry, "value").is_empty() {
                return Err("promoted form entry cannot also provide a value".to_string());
            }
        }
    }
    if let Some(Value::Object(token)) = obj.get("token") {
        let secret = oc_str(token, "secret");
        let secret_path = oc_str(token, "secret_path");
        if secret.is_empty() && secret_path.is_empty() {
            return Err("software token requires a secret".to_string());
        }
        let mode = oc_str(token, "mode");
        if !OC_TOKEN_MODES.contains(&mode.as_str()) {
            return Err(format!(
                "unsupported openconnect software token mode: {mode}"
            ));
        }
    }
    Ok(())
}

/// reference `parseServerURL` (sing-openconnect http_client.go:18).
fn oc_check_server_url(server: &str) -> Result<(), String> {
    let url = if server.contains("://") {
        server.to_string()
    } else {
        format!("https://{server}")
    };
    let rest = match url.find("://") {
        Some(idx) => &url[idx + 3..],
        None => url.as_str(),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(idx) => (Some(&authority[..idx]), &authority[idx + 1..]),
        None => (None, authority),
    };
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.split_once("]:") {
            Some((host, port)) => (host, Some(port)),
            None => (stripped, None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            _ => (hostport, None),
        }
    };
    let scheme = url.split("://").next().unwrap_or("").to_ascii_lowercase();
    if scheme != "https" || host.is_empty() {
        return Err("server must be an HTTPS host".to_string());
    }
    if userinfo.is_some() {
        return Err("server must not contain URL user information".to_string());
    }
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let after_authority = &url[scheme_end + authority.len()..];
    if after_authority.contains('?') || after_authority.contains('#') {
        return Err("server must not contain a query or fragment".to_string());
    }
    let _ = port;
    Ok(())
}

/// reference endpoint-side `url.Parse` (client.go:133) — best-effort: control
/// characters and a non-numeric port are the reachable failures.
fn oc_check_url_parse(server: &str) -> Result<(), String> {
    let url = if server.contains("://") {
        server.to_string()
    } else {
        format!("https://{server}")
    };
    if url.chars().any(|c| c < '\x20' || c == '\x7f') {
        return Err(format!(
            "parse server: parse {url:?}: net/url: invalid control character in URL"
        ));
    }
    let rest = match url.find("://") {
        Some(idx) => &url[idx + 3..],
        None => url.as_str(),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let hostport = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    if !hostport.starts_with('[') {
        if let Some((_, port)) = hostport.rsplit_once(':')
            && !port.is_empty()
            && !port.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "parse server: parse {url:?}: invalid port \":{port}\" after host"
            ));
        }
    } else if let Some(rest) = hostport.strip_prefix('[')
        && let Some((_, port)) = rest.split_once("]:")
        && !port.is_empty()
        && !port.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "parse server: parse {url:?}: invalid port \":{port}\" after host"
        ));
    }
    Ok(())
}

/// reference `buildClientTLS` (sing-openconnect tls_config.go:43).
fn oc_build_client_tls(tls: &Map<String, Value>) -> Result<(), String> {
    let ca = tls_listable_join(tls.get("certificate_authority"));
    let ca_path = oc_str(tls, "certificate_authority_path");
    if !ca.is_empty() || !ca_path.is_empty() {
        let content = if !ca_path.is_empty() {
            go_read_file(&ca_path).map_err(|e| {
                format!(
                    "load TLS certificate authority: read openconnect material: open {ca_path}: {e}"
                )
            })?
        } else {
            ca.clone()
        };
        if !oc_pem_has_certificate(&content) {
            return Err("invalid openconnect TLS material: certificate authority".to_string());
        }
    }
    oc_load_optional_certificate(
        tls,
        "client_certificate",
        "client_certificate_path",
        "client_key",
        "client_key_path",
        "client_key_password",
        "client",
    )?;
    oc_load_optional_certificate(
        tls,
        "mca_certificate",
        "mca_certificate_path",
        "mca_key",
        "mca_key_path",
        "mca_key_password",
        "MCA",
    )?;
    // certificate expiry warnings / MinVersion / cipher / PFS are driven by
    // fields the endpoint never sets (defaults cannot fail).
    let fingerprints = ovpn_listable_values(tls.get("peer_fingerprint"));
    for value in &fingerprints {
        oc_parse_peer_fingerprint(value)?;
    }
    Ok(())
}

/// reference `loadOptionalCertificate` (tls_config.go:669).
fn oc_load_optional_certificate(
    tls: &Map<String, Value>,
    cert_key: &str,
    cert_path_key: &str,
    key_key: &str,
    key_path_key: &str,
    password_key: &str,
    name: &str,
) -> Result<(), String> {
    let cert_content = tls_listable_join(tls.get(cert_key));
    let cert_path = oc_str(tls, cert_path_key);
    let key_content = tls_listable_join(tls.get(key_key));
    let key_path = oc_str(tls, key_path_key);
    let cert_set = !cert_content.is_empty() || !cert_path.is_empty();
    let key_set = !key_content.is_empty() || !key_path.is_empty();
    if cert_set != key_set {
        return Err(format!(
            "invalid openconnect TLS material: {name} certificate and key must both be set"
        ));
    }
    if !cert_set {
        return Ok(());
    }
    let cert_pem = if !cert_path.is_empty() {
        go_read_file(&cert_path).map_err(|e| {
            format!("load {name} certificate: read openconnect material: open {cert_path}: {e}")
        })?
    } else {
        cert_content
    };
    let key_pem = if !key_path.is_empty() {
        go_read_file(&key_path).map_err(|e| {
            format!("load {name} key: read openconnect material: open {key_path}: {e}")
        })?
    } else {
        key_content
    };
    let password = oc_str(tls, password_key);
    oc_decrypt_key_pem(&key_pem, &password).map_err(|e| format!("decrypt {name} key: {e}"))?;
    if !oc_pem_has_certificate(&cert_pem) {
        return Err(format!(
            "parse {name} certificate and key: x509: failed to find any PEM data in certificate input"
        ));
    }
    if !oc_pem_has_private_key(&key_pem) {
        return Err(format!(
            "parse {name} certificate and key: x509: failed to find any PEM data in key input"
        ));
    }
    // certificate/key DER match cannot be verified without crypto parsing —
    // documented GAP; probing uses non-PEM material that fails above.
    Ok(())
}

/// reference `decryptPrivateKeyPEM` (tls_config.go:695) — password checks only.
fn oc_decrypt_key_pem(content: &str, password: &str) -> Result<(), String> {
    for block in oc_pem_blocks(content) {
        if block.0 == "ENCRYPTED PRIVATE KEY" && password.is_empty() {
            return Err("encrypted PKCS#8 private key requires a password".to_string());
        }
        if block.2 && password.is_empty() {
            return Err("encrypted private key requires a password".to_string());
        }
    }
    Ok(())
}

/// minimal PEM scanner: (type, base64 body, legacy_encrypted_header).
fn oc_pem_blocks(content: &str) -> Vec<(String, String, bool)> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx].trim_end_matches('\r');
        if let Some(ty) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            if ty.is_empty() || ty.contains(' ') || ty.contains(':') {
                idx += 1;
                continue;
            }
            let mut body_lines: Vec<&str> = Vec::new();
            let mut legacy_encrypted = false;
            let mut in_headers = true;
            let mut j = idx + 1;
            let mut closed = false;
            while j < lines.len() {
                let cur = lines[j].trim_end_matches('\r');
                if cur.starts_with("-----END ") {
                    closed = true;
                    break;
                }
                if in_headers {
                    if cur.trim().is_empty() {
                        in_headers = false;
                    } else if cur.starts_with("Proc-Type:") && cur.contains("ENCRYPTED") {
                        legacy_encrypted = true;
                    } else if cur.contains(':') && !cur.starts_with("-----") {
                        // PEM header line.
                    } else {
                        in_headers = false;
                        body_lines.push(cur);
                    }
                } else {
                    body_lines.push(cur);
                }
                j += 1;
            }
            if closed {
                blocks.push((ty.to_string(), body_lines.concat(), legacy_encrypted));
                idx = j + 1;
                continue;
            }
        }
        idx += 1;
    }
    blocks
}

fn oc_pem_has_certificate(content: &str) -> bool {
    matches!(
        oc_pem_blocks(content).first(),
        Some((ty, body, _)) if ty == "CERTIFICATE" && oc_base64_ok(body)
    )
}

fn oc_pem_has_private_key(content: &str) -> bool {
    matches!(
        oc_pem_blocks(content).first(),
        Some((ty, body, _))
            if matches!(ty.as_str(), "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY")
                && oc_base64_ok(body)
    )
}

/// conservative base64 validity (std alphabet, padding only at the end).
fn oc_base64_ok(body: &str) -> bool {
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if body.is_empty() {
        return false;
    }
    let bytes = body.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    let mut padding = 0;
    for (idx, b) in bytes.iter().enumerate() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                if padding > 0 {
                    return false;
                }
            }
            b'=' => {
                padding += 1;
                if idx < bytes.len() - 2 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    padding <= 2
}

/// reference `parsePeerFingerprint` (tls_config.go:233).
fn oc_parse_peer_fingerprint(value: &str) -> Result<(), String> {
    let mut encoded: &str = value;
    let mut maximum_length = 40usize;
    let mut case_sensitive = false;
    if let Some(rest) = value.strip_prefix("sha1:") {
        encoded = rest;
    } else if let Some(rest) = value.strip_prefix("sha256:") {
        encoded = rest;
        maximum_length = 64;
    } else if let Some(rest) = value.strip_prefix("pin-sha256:") {
        encoded = rest;
        maximum_length = 44;
        case_sensitive = true;
    } else if value.contains(':') {
        return Err(format!(
            "unsupported server certificate fingerprint: {value}"
        ));
    }
    if encoded.len() < 4 || encoded.len() > maximum_length {
        return Err(format!("invalid server certificate fingerprint: {value}"));
    }
    if case_sensitive {
        for (idx, ch) in encoded.char_indices() {
            let ok = ch.is_ascii_alphanumeric() || ch == '+' || ch == '/';
            if !ok && (ch != '=' || idx < encoded.len().saturating_sub(2)) {
                return Err(format!("invalid server certificate fingerprint: {value}"));
            }
        }
        if encoded.len() == maximum_length {
            let decoded = oc_base64_strict_decode(encoded);
            if decoded.as_deref().map(|d| d.len()) != Some(32) {
                return Err(format!("invalid server certificate fingerprint: {value}"));
            }
        }
    } else {
        if !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("invalid server certificate fingerprint: {value}"));
        }
    }
    Ok(())
}

/// strict base64 std decode (non-zero trailing bits rejected), 32-byte check.
fn oc_base64_strict_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for (idx, b) in bytes.iter().enumerate() {
        if *b == b'=' {
            if idx < bytes.len() - 2 {
                return None;
            }
            if !bits.is_multiple_of(8) && (buf & ((1 << bits) - 1)) != 0 {
                return None;
            }
            continue;
        }
        let val = ALPHABET.iter().position(|a| a == b)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if out.len() != 32 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod endpoint_probe_parity_tests {
    use super::validate;
    use serde_json::Value;

    fn cfg(raw: &str) -> Value {
        serde_json::from_str(raw).expect("probe json")
    }

    #[test]
    fn parity_ep_type_missing() {
        let err = validate(&cfg(
            r#"{"log":{"level":"warn"},"endpoints":[{"tag":"x"}]}"#,
        ))
        .unwrap_err();
        assert_eq!(err, r#"endpoints[0]: unknown endpoint type: "#);
    }

    #[test]
    fn parity_ep_type_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"endpoints":[5]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0]: json: cannot unmarshal number into Go struct field _Options.endpoints of type option._Endpoint"#
        );
    }

    #[test]
    fn parity_ep_unknown() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"bogus","tag":"x"}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0]: unknown endpoint type: bogus"#);
    }

    #[test]
    fn parity_oc_badfield() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"x","nope":1}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].nope: json: unknown field "nope""#);
    }

    #[test]
    fn parity_oc_clientcert_only() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","tls":{"client_certificate":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: invalid openconnect TLS material: client certificate and key must both be set"#
        );
    }

    #[test]
    fn parity_oc_compmode_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","compression_mode":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: unsupported compression mode: bogus"#
        );
    }

    #[test]
    fn parity_oc_flavor_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"x","flavor":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: unsupported openconnect flavor: bogus"#
        );
    }

    #[test]
    fn parity_oc_flavor_garbca() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","flavor":"bogus","tls":{"certificate_authority":"garbage"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: invalid openconnect TLS material: certificate authority"#
        );
    }

    #[test]
    fn parity_oc_full() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"vpn.example.com","username":"u","password":"p"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_oc_garbca() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","tls":{"certificate_authority":"garbage"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: invalid openconnect TLS material: certificate authority"#
        );
    }

    #[test]
    fn parity_oc_http_scheme() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"http://example.com"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: server must be an HTTPS host"#
        );
    }

    #[test]
    fn parity_oc_keepalive_conflict() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","tcp_keep_alive_enabled":true,"disable_tcp_keep_alive":true}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: tcp_keep_alive_enabled conflicts with disable_tcp_keep_alive"#
        );
    }

    #[test]
    fn parity_oc_mtu_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"x","mtu":"abc"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].mtu: json: cannot unmarshal string into Go struct field OpenConnectEndpointOptions.mtu of type uint32"#
        );
    }

    #[test]
    fn parity_oc_noserver() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: missing openconnect server"#
        );
    }

    #[test]
    fn parity_oc_server_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].server: json: cannot unmarshal number into Go struct field OpenConnectEndpointOptions.server of type string"#
        );
    }

    #[test]
    fn parity_oc_tls_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"x","tls":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].tls: json: cannot unmarshal number into Go struct field OpenConnectEndpointOptions.tls of type option.OpenConnectTLSOptions"#
        );
    }

    #[test]
    fn parity_oc_tlsemt() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","tls":{}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_oc_token_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"x","token":{"nope":1}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].token.nope: json: unknown field "nope""#
        );
    }

    #[test]
    fn parity_oc_token_badmode() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","token":{"mode":"bogus","secret":"abc"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: unsupported openconnect software token mode: bogus"#
        );
    }

    #[test]
    fn parity_oc_token_nosecret() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","token":{"mode":"totp"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: software token requires a secret"#
        );
    }

    #[test]
    fn parity_oc_token_path_conflict() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","token":{"secret":"abc","secret_path":"/nonexistent"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: token secret and secret path cannot both be configured"#
        );
    }

    #[test]
    fn parity_openconnect_min() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"vpn.example.com"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_c_addr_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"address":"notprefix"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].address: (netip.ParsePrefix("notprefix"): no '/' | json: cannot unmarshal string into Go value of type []netip.Prefix)"#
        );
    }

    #[test]
    fn parity_ovpn_c_badfield_nested() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"nope":1}}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].tls.nope: json: unknown field "nope""#);
    }

    #[test]
    fn parity_ovpn_c_conflict() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","servers":[{"server":"1.2.3.4"}]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: `server` is conflict with `servers`"#
        );
    }

    #[test]
    fn parity_ovpn_c_full_static() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: ClientOptions.DataChannel.Cipher is required in static_key mode"#
        );
    }

    #[test]
    fn parity_ovpn_c_legacy_outbound() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"openvpn","tag":"ovpn","server":"1.2.3.4","server_port":1194}]}"#)).unwrap_err();
        assert_eq!(err, r#"outbounds[0]: unknown outbound type: openvpn"#);
    }

    #[test]
    fn parity_ovpn_c_mode_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].mode: json: cannot unmarshal number into Go struct field OpenVPNClientEndpointOptions.mode of type string"#
        );
    }

    #[test]
    fn parity_ovpn_c_mtu_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mtu":"abc"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].mtu: json: cannot unmarshal string into Go struct field OpenVPNClientEndpointOptions.OpenVPNEndpointOptions.mtu of type uint32"#
        );
    }

    #[test]
    fn parity_ovpn_c_net_badenum() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"network":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_c_no_tag_badfield() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","server":"1.2.3.4","nope":1}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].nope: json: unknown field "nope""#);
    }

    #[test]
    fn parity_ovpn_c_notag() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","server":"1.2.3.4","server_port":1194,"tls":{}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[0]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_c_servers_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","servers":[{"server":"1.2.3.4","server_port":"x"}]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].servers[0].server_port: json: cannot unmarshal string into Go struct field OpenVPNRemoteOptions.servers.ServerOptions.server_port of type uint16"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_addr() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `peer_address` for the IPv4 tunnel address in `static_key` mode"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_addr_key() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"static_key":"<static>"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `peer_address` for the IPv4 tunnel address in `static_key` mode"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_full2() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cipher":"aes-128-cbc"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: ClientOptions.DataChannel.Cipher must use a canonical OpenVPN cipher name"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_kd_tls() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaa","key_direction":"bogus","tls":null}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unsupported key direction: bogus (expected "server" or "client")"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_peer() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `static_key` or `static_key_path`"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_tlsemt() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaa","tls":{}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.DataChannel.Cipher is required in static_key mode"#
        );
    }

    #[test]
    fn parity_ovpn_c_static_tlsset() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaa","tls":{"server_name":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: `tls` options are not supported in `static_key` mode"#
        );
    }

    #[test]
    fn parity_ovpn_c_tls_ca() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_c_tls_ca_addr() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"address":["10.8.0.6/24"]}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_c_tls_cert() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"address":["10.8.0.6/24"]}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].tls.key: json: unknown field "key""#);
    }

    #[test]
    fn parity_ovpn_c_tls_empty() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_c_tls_empty_cwrap() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"control_wrap":{}}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_c_tls_full() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"insecure":true},"address":["10.8.0.6/24"]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].tls.insecure: json: unknown field "insecure""#
        );
    }

    #[test]
    fn parity_ovpn_c_tls_netbad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"network":"bogus","tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"address":["10.8.0.6/24"]}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].tls.key: json: unknown field "key""#);
    }

    #[test]
    fn parity_ovpn_c_tls_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].tls: json: cannot unmarshal number into Go struct field OpenVPNClientEndpointOptions.tls of type option.OpenVPNOutboundTLSOptions"#
        );
    }

    #[test]
    fn parity_ovpn_c_unknown_nested_s0() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","servers":[{"server":"1.2.3.4","nope":1}]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].servers[0].nope: json: unknown field "nope""#
        );
    }

    #[test]
    fn parity_ovpn_client_badmode() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: unsupported mode: bogus (expected "tls" or "static_key")"#
        );
    }

    #[test]
    fn parity_ovpn_client_min() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_client_noserver() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `server` or `servers`"#
        );
    }

    #[test]
    fn parity_ovpn_client_servers() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","servers":[{"server":"1.2.3.4","server_port":1194}]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_client_static() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `address` in `static_key` mode"#
        );
    }

    #[test]
    fn parity_ovpn_client_tls() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"tls"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_ovpn_client_unknown() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"unknown_field":1}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].unknown_field: json: unknown field "unknown_field""#
        );
    }

    #[test]
    fn parity_ovpn_s_full_static() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"mode":"static_key","address":["10.8.0.1/24"],"peer_address":"10.8.0.2","static_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: `remote` and `remote_port` are required for a UDP static-key server"#
        );
    }

    #[test]
    fn parity_ovpn_s_listen() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_ovpn_s_mtu_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"mtu":"abc"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].mtu: json: cannot unmarshal string into Go struct field OpenVPNServerEndpointOptions.OpenVPNEndpointOptions.mtu of type uint32"#
        );
    }

    #[test]
    fn parity_ovpn_s_net_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"network":"bogus","tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"address":["10.8.0.1/24"]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: unsupported network: bogus"#
        );
    }

    #[test]
    fn parity_ovpn_s_noaddr_tls() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_ovpn_s_static() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"mode":"static_key","address":["10.8.0.1/24"],"static_key":"<static>"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing `peer_address` for the IPv4 static-key tunnel"#
        );
    }

    #[test]
    fn parity_ovpn_s_static_full2() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"mode":"static_key","address":["10.8.0.1/24"],"peer_address":"10.8.0.2","static_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","remote":"1.2.3.4","remote_port":1194}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_s_static_pushty() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"peer_address":"10.8.0.2","static_key":"aaaa","mode":"static_key","remote":"1.2.3.4","remote_port":1194,"push":{}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_s_static_tlsemt() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"peer_address":"10.8.0.2","static_key":"aaaa","mode":"static_key","remote":"1.2.3.4","remote_port":1194,"tls":{}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_s_tls_cert() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"address":["10.8.0.1/24"]}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ovpn_s_tls_empty() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"tls":{}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_ovpn_s_tls_vccbogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"tls":{"verify_client_certificate":"bogus","certificate":"x","key":"y"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[o]: invalid client certificate policy bogus, allowed values: require, optional, none"#
        );
    }

    #[test]
    fn parity_ovpn_server_min() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_ovpn_server_nolisten() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_q_c_allow_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"allow_compression":"bogus","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: invalid allow-compression value"#
        );
    }

    #[test]
    fn parity_q_c_allow_no_lz4() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"allow_compression":"no","compression":"lz4","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: allow-compression no conflicts with statically enabled compression"#
        );
    }

    #[test]
    fn parity_q_c_authretry() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"auth_retry":"bogus","tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: ClientOptions.Authentication.AuthRetry must be none, nointeract, or interact"#
        );
    }

    #[test]
    fn parity_q_c_badkey_material() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"garbage"}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_c_bindnum() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"bind_interface":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].bind_interface: json: cannot unmarshal number into Go struct field OpenVPNClientEndpointOptions.DialerOptions.AbstractDialerOptions.bind_interface of type string"#
        );
    }

    #[test]
    fn parity_q_c_certkey_mismatch() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","client_certificate":"y"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: certificate and key must both be set or both omitted"#
        );
    }

    #[test]
    fn parity_q_c_cipher_vs_auth() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"data_ciphers":["bogus"],"auth_retry":"bogus","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.DataChannel.Ciphers[0] must use a canonical OpenVPN cipher name"#
        );
    }

    #[test]
    fn parity_q_c_comp_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"compression":"bogus","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unsupported compression option: compress bogus"#
        );
    }

    #[test]
    fn parity_q_c_cto_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"connect_timeout":"zz"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].connect_timeout: time: invalid duration "zz""#
        );
    }

    #[test]
    fn parity_q_c_ddr() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"domain_resolver":"nosuch"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_q_c_eku_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","remote_certificate_eku":"bogus"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unsupported remote-cert-eku value: bogus"#
        );
    }

    #[test]
    fn parity_q_c_eku_dot() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","remote_certificate_eku":"1.2.999.1"}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_c_expanded_none() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","remote_certificate_tls":"bogus"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: invalid `tls.remote_certificate_tls`: bogus"#
        );
    }

    #[test]
    fn parity_q_c_frag_tcp() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"network":"tcp","fragment":100,"tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: option is not supported yet: fragment with tcp remote"#
        );
    }

    #[test]
    fn parity_q_c_groups_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","groups":"BOGUS"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unsupported tls-groups name: BOGUS"#
        );
    }

    #[test]
    fn parity_q_c_grouptoken_empty() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","groups":""}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_c_kd_static_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaa","key_direction":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unsupported key direction: bogus (expected "server" or "client")"#
        );
    }

    #[test]
    fn parity_q_c_kd_tls_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"key_direction":"bogus","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: `key_direction` is only supported in `static_key` mode; use `tls.control_wrap.direction` for `tls_auth`"#
        );
    }

    #[test]
    fn parity_q_c_ku_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","remote_certificate_ku":["zz"]}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: strconv.ParseUint: parsing "zz": invalid syntax"#
        );
    }

    #[test]
    fn parity_q_c_ku_empty() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","remote_certificate_ku":[""]}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: empty key usage hex"#
        );
    }

    #[test]
    fn parity_q_c_ku_nohex() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","remote_certificate_ku":["AB"]}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_c_netbogus_tls() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"network":"bogus","tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: unsupported openvpn protocol"#
        );
    }

    #[test]
    fn parity_q_c_netstrat() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"network_strategy":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].network_strategy: unknown network strategy: bogus"#
        );
    }

    #[test]
    fn parity_q_c_noport() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_q_c_noport2() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: option is not supported yet: empty remote port at index 0"#
        );
    }

    #[test]
    fn parity_q_c_ns_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","ns_certificate_type":"bogus"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.TLS.NSCertificateType must be server or client"#
        );
    }

    #[test]
    fn parity_q_c_ping_half() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"ping_interval":"0.5s","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.Timing.PingInterval must be zero or at least 1s"#
        );
    }

    #[test]
    fn parity_q_c_ping_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"ping_interval":5,"tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].ping_interval: json: cannot unmarshal number into Go struct field OpenVPNClientEndpointOptions.ping_interval of type string"#
        );
    }

    #[test]
    fn parity_q_c_prof_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","certificate_profile":"bogus"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unknown tls-cert-profile value: bogus"#
        );
    }

    #[test]
    fn parity_q_c_reneg_conf() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"renegotiate_interval":"3600s","renegotiate_disabled":true,"tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.Timing.RenegotiationInterval conflicts with RenegotiationDisabled"#
        );
    }

    #[test]
    fn parity_q_c_reneg_neg() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"renegotiate_interval":"-1s","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.Timing.RenegotiationInterval must not be negative"#
        );
    }

    #[test]
    fn parity_q_c_rmarkneg() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"routing_mark":-1}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].routing_mark: invalid number or string mark: json: cannot unmarshal number into Go value of type string"#
        );
    }

    #[test]
    fn parity_q_c_snatype_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","server_name_type":"bogus"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: ClientOptions.TLS.VerifyX509Type must be subject, name, or name-prefix"#
        );
    }

    #[test]
    fn parity_q_c_tlscipher_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","cipher":"BOGUS"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unsupported tls-cipher name: BOGUS"#
        );
    }

    #[test]
    fn parity_q_c_tlsversion_maxbad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","version_min":"1.3","version_max":"1.2"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: tls-version-min bigger than tls-version-max"#
        );
    }

    #[test]
    fn parity_q_c_vermin_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","version_min":"9.9"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[o]: unknown tls-version parameter: 9.9"#
        );
    }

    #[test]
    fn parity_q_cipher_upper() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mode":"static_key","address":["10.8.0.2/24"],"peer_address":"10.8.0.1","static_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cipher":"AES-128-CBC"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_cwrap_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","client_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n","control_wrap":{"nope":1}}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].tls.control_wrap.nope: json: unknown field "nope""#
        );
    }

    #[test]
    fn parity_q_oc_bindnum() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"example.com","bind_interface":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].bind_interface: json: cannot unmarshal number into Go struct field OpenConnectEndpointOptions.DialerOptions.AbstractDialerOptions.bind_interface of type string"#
        );
    }

    #[test]
    fn parity_q_oc_flavor_noserver() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","flavor":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openconnect[oc]: missing openconnect server"#
        );
    }

    #[test]
    fn parity_q_peer_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"peer_address":"bogus","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].peer_address: ParseAddr("bogus"): unable to parse IP"#
        );
    }

    #[test]
    fn parity_q_peer_empty() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"peer_address":"","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].peer_address: ParseAddr(""): unable to parse IP"#
        );
    }

    #[test]
    fn parity_q_push_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"push":{"nope":1}}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].push.nope: json: unknown field "nope""#);
    }

    #[test]
    fn parity_q_route_gw_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-client","tag":"o","server":"1.2.3.4","server_port":1194,"route_gateway":"zz","tls":{"certificate":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].route_gateway: ParseAddr("zz"): unable to parse IP"#
        );
    }

    #[test]
    fn parity_q_s_bindnum() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"bind_interface":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].bind_interface: json: cannot unmarshal number into Go struct field OpenVPNServerEndpointOptions.ListenOptions.bind_interface of type string"#
        );
    }

    #[test]
    fn parity_q_s_dnsaddr_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"tls":{"certificate":"x","key":"y"},"push":{"dns_servers":[{"addresses":["notaddr"]}]}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[o]: invalid push.dns_servers[0].addresses[0]: notaddr"#
        );
    }

    #[test]
    fn parity_q_s_dnsaddr_port0() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"tls":{"certificate":"x","key":"y"},"push":{"dns_servers":[{"addresses":["1.1.1.1:0"]}]}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[o]: invalid push.dns_servers[0].addresses[0]: 1.1.1.1:0"#
        );
    }

    #[test]
    fn parity_q_s_empty_addr() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","address":[],"tls":{"certificate":"x","key":"y"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_q_s_push_dsn_bogus() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"tls":{"certificate":"x","key":"y"},"push":{"dns_servers":[{"dnssec":"bogus"}]}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_s_push_prio_bad() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"tls":{"certificate":"x","key":"y"},"push":{"dns_servers":[{"priority":200,"addresses":["1.1.1.1"]}]}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_s_static_ciphempty() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"mode":"static_key","peer_address":"10.8.0.2","static_key":"aaaa","remote":"1.2.3.4","remote_port":1194,"cipher":"bogus"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_s_tls_empty2() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.0.0.1/24"],"tls":{}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_q_s_topnet_both() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"d"}],"endpoints":[{"type":"openvpn-server","tag":"o","address":["10.8.0.1/24"],"topology":"bogus","network":"bogus","tls":{"certificate":"x","key":"y"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[o]: invalid topology bogus, allowed values: subnet, p2p, net30"#
        );
    }

    #[test]
    fn parity_q_s_topology_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"topology":"bogus","tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: invalid topology bogus, allowed values: subnet, p2p, net30"#
        );
    }

    #[test]
    fn parity_q_s_users_empty() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"users":[]}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_server_proxy_proto() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"proxy_protocol":true}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_server_sniff() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"sniff":true}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_srv_detour() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"detour":"direct"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_srv_domain_strategy() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"domain_strategy":"prefer_ipv4"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_srv_fastopen() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"fast_open":true}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].fast_open: json: unknown field "fast_open""#
        );
    }

    #[test]
    fn parity_q_srv_networking() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"sniff_override_destination":true}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_srv_tfo() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"tfo":true}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].tfo: json: unknown field "tfo""#);
    }

    #[test]
    fn parity_q_tls_ca_only() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n"}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_tls_sni_only() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"server_name":"x"}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: tls mode: either certificate-authority or peer-fingerprint must be configured"#
        );
    }

    #[test]
    fn parity_q_ts_ssh_false() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","ssh_server":false}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_q_users_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"address":["10.8.0.1/24"],"tls":{"certificate":"-----BEGIN CERTIFICATE-----\nMIIBRjCB7qADAgECAhQH9Vr8fWuip/rOWYKeozPEichRSjAKBggqhkjOPQQDAjAU\nMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwOTIyMTkwNDM5WhcNMzYwOTIwMTkw\nNDM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpgN0WxquuVIPbMbFMYARGvmSUHh+DE\nu3KR+CHCkJRurp4b+cbQn14M+ZVmox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SH\nBH8AAAEwCgYIKoZIzj0EAwIDRwAwRAIgfwHG/s+ea0AknE0TTE0cpJlngSFUMWsN\nk3fPLif9HHYCICbBbJOH0nhIxC50+OHBGLQpy2R50rct6tQ+lv7eWCnh\n-----END CERTIFICATE-----\n","key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu/LscQrPjs/jAXaB\noqn00aUbJD5H5b5aCmn4xfIzjhKhRANCAASd8JJPvCrfrRP7JOZcbn30AzTYmfpg\nN0WxquuVIPbMbFMYARGvmSUHh+DEu3KR+CHCkJRurp4b+cbQn14M+ZVm\n-----END PRIVATE KEY-----\n"},"users":[{"nope":1}]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].users[0].nope: json: unknown field "nope""#
        );
    }

    #[test]
    fn parity_r_addr_arrelem() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"address":["ok/24"]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].address: (json: cannot unmarshal array into Go value of type **netip.Prefix | netip.ParsePrefix("ok/24"): ParseAddr("ok"): unable to parse IP)"#
        );
    }

    #[test]
    fn parity_r_c_ping() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"ping_interval":"abc"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].ping_interval: time: invalid duration "abc""#
        );
    }

    #[test]
    fn parity_r_c_routes_elem() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"routes":["bad"]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].routes: (json: cannot unmarshal array into Go value of type **netip.Prefix | netip.ParsePrefix("bad"): no '/')"#
        );
    }

    #[test]
    fn parity_r_cwrap_empty() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"certificate":"x","control_wrap":{}}}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_r_fingerprint() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"tls":{"peer_fingerprint":["zz"]}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: ClientOptions.TLS.PeerFingerprint[0] must be canonical lowercase hex"#
        );
    }

    #[test]
    fn parity_r_kd_bogus() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"key_direction":"bogus"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_r_listen_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":5,"listen_port":1194}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].listen: json: cannot unmarshal number into Go struct field OpenVPNServerEndpointOptions.ListenOptions.listen of type string"#
        );
    }

    #[test]
    fn parity_r_mssfix() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"mss_fix_disabled":true}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-client[ovpn]: missing `tls` options"#
        );
    }

    #[test]
    fn parity_r_oc_form_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openconnect","tag":"oc","server":"x","form_entries":"y"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].form_entries: json: cannot unmarshal string into Go struct field OpenConnectEndpointOptions.form_entries of type []option.OpenConnectFormEntryOptions"#
        );
    }

    #[test]
    fn parity_r_pullfilters_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"pull_filters":"x"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].pull_filters: json: cannot unmarshal string into Go struct field OpenVPNClientEndpointOptions.pull_filters of type []option.OpenVPNPullFilterOptions"#
        );
    }

    #[test]
    fn parity_r_push_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"push":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].push: json: cannot unmarshal number into Go struct field OpenVPNServerEndpointOptions.push of type option.OpenVPNPushOptions"#
        );
    }

    #[test]
    fn parity_r_s_push_dns() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"push":{"dns":["notaddr"]}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].push.dns: (json: cannot unmarshal array into Go value of type **netip.Addr | ParseAddr("notaddr"): unable to parse IP)"#
        );
    }

    #[test]
    fn parity_r_servers_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"servers":"x"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].servers: json: cannot unmarshal string into Go struct field OpenVPNClientEndpointOptions.servers of type []option.OpenVPNRemoteOptions"#
        );
    }

    #[test]
    fn parity_r_statickey_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"static_key":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].static_key: (json: cannot unmarshal number into Go value of type string | json: cannot unmarshal number into Go value of type []string)"#
        );
    }

    #[test]
    fn parity_r_statickey_obj() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-client","tag":"ovpn","server":"1.2.3.4","server_port":1194,"static_key":{"a":1}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].static_key: (json: cannot unmarshal object into Go value of type string | json: cannot unmarshal object into Go value of type []string)"#
        );
    }

    #[test]
    fn parity_r_ts_ctrl() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","control_url":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].control_url: json: cannot unmarshal number into Go struct field TailscaleEndpointOptions.control_url of type string"#
        );
    }

    #[test]
    fn parity_r_ts_ssh_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","ssh_server":"x"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].ssh_server: json: cannot unmarshal string into Go struct field TailscaleEndpointOptions.ssh_server of type option._TailscaleSSHServerOptions"#
        );
    }

    #[test]
    fn parity_r_users_pw() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"users":[{"username":"u","password":"p"}]}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"initialize endpoint[0] openvpn-server[ovpns]: missing server address"#
        );
    }

    #[test]
    fn parity_r_users_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"openvpn-server","tag":"ovpns","listen":"127.0.0.1","listen_port":1194,"users":"x"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].users: json: cannot unmarshal string into Go struct field OpenVPNServerEndpointOptions.users of type []auth.User"#
        );
    }

    #[test]
    fn parity_tailscale_min() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ts_adv_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","advertise_routes":"x"}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].advertise_routes: json: cannot unmarshal string into Go struct field TailscaleEndpointOptions.advertise_routes of type []netip.Prefix"#
        );
    }

    #[test]
    fn parity_ts_authkey_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","auth_key":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].auth_key: json: cannot unmarshal number into Go struct field TailscaleEndpointOptions.auth_key of type string"#
        );
    }

    #[test]
    fn parity_ts_badfield() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","nope":1}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].nope: json: unknown field "nope""#);
    }

    #[test]
    fn parity_ts_full() {
        let result = validate(&cfg(
            r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","auth_key":"tskey-auth-123","hostname":"owrt"}]}"#,
        ));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn parity_ts_hostname_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","hostname":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].hostname: json: cannot unmarshal number into Go struct field TailscaleEndpointOptions.hostname of type string"#
        );
    }

    #[test]
    fn parity_ts_mtu_str() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","mtu":"abc"}]}"#)).unwrap_err();
        assert_eq!(err, r#"endpoints[0].mtu: json: unknown field "mtu""#);
    }

    #[test]
    fn parity_ts_relay_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","relay_server_static_endpoints":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].relay_server_static_endpoints: json: cannot unmarshal number into Go struct field TailscaleEndpointOptions.relay_server_static_endpoints of type []netip.AddrPort"#
        );
    }

    #[test]
    fn parity_ts_ssh_num() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","ssh_server":5}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].ssh_server: json: cannot unmarshal number into Go struct field TailscaleEndpointOptions.ssh_server of type option._TailscaleSSHServerOptions"#
        );
    }

    #[test]
    fn parity_ts_ssh_obj_bad() {
        let err = validate(&cfg(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"tailscale","tag":"ts","ssh_server":{"nope":1}}]}"#)).unwrap_err();
        assert_eq!(
            err,
            r#"endpoints[0].ssh_server.nope: json: unknown field "nope""#
        );
    }
}

// ---------------------------------------------------------------------------
// lx: the fork's root block (option/lx.go) — decode + `ResolveLX`
// ---------------------------------------------------------------------------

/// Warnings collected during the last `validate()` call (deprecation notices
/// the reference logs but does not treat as errors).
static WARNINGS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn record_warnings(warnings: Vec<String>) {
    if warnings.is_empty() {
        return;
    }
    if let Ok(mut slot) = WARNINGS.lock() {
        slot.extend(warnings);
    }
}

/// Drain the warnings collected by the last `validate()` call.
pub fn take_warnings() -> Vec<String> {
    WARNINGS
        .lock()
        .map(|mut slot| std::mem::take(&mut *slot))
        .unwrap_or_default()
}

/// `check` equivalent that also reports reference warnings.
pub fn validate_with_warnings(root: &Value) -> Result<Vec<String>, String> {
    validate(root)?;
    Ok(take_warnings())
}

/// Decoded `lx.wg` durations in nanoseconds (`None` = absent).
#[derive(Clone, Default)]
struct LxBlock {
    idle_suspend: Option<i64>,
    idle_suspend_reachable: Option<i64>,
    idle_teardown: Option<i64>,
    lazy_build: bool,
    build_max: i64,
    build_overflow: String,
    masque_idle_timeout: Option<i64>,
}

/// Duration field of the lx block: Go duration strings only (badoption.Duration).
fn lx_duration(value: Option<&Value>, at: &str, field: &str) -> Result<Option<i64>, String> {
    let go_field = format!("lx.wg.{field}");
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    check_duration_field(value, at, "LXWGOptions", &go_field)?;
    let Some(text) = value.as_str() else {
        return Ok(None);
    };
    go_parse_duration(text)?;
    Ok(Some(go_duration_ns_or_zero(text)))
}

fn lx_masque_duration(value: Option<&Value>, at: &str, field: &str) -> Result<Option<i64>, String> {
    let go_field = format!("lx.masque.{field}");
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    check_duration_field(value, at, "LXMASQUEOptions", &go_field)?;
    let Some(text) = value.as_str() else {
        return Ok(None);
    };
    go_parse_duration(text)?;
    Ok(Some(go_duration_ns_or_zero(text)))
}

/// `check` accepts a null block; anything else must be an object.
/// `go_path` is the full Go field path (`_Options.lx`, `LXOptions.lx.wg`).
fn lx_object<'a>(
    value: Option<&'a Value>,
    at: &str,
    go_path: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(other) => Err(format!(
            "{at}: json: cannot unmarshal {} into Go struct field {go_path} of type {}",
            json_kind(other),
            go_type(go_path)
        )),
    }
}

/// `option.LXOptions` / `option.LXWGOptions` / `option.LXMASQUEOptions`.
fn go_type(go_path: &str) -> &'static str {
    if go_path.ends_with("lx.masque") {
        "option.LXMASQUEOptions"
    } else if go_path.ends_with("lx.wg") {
        "option.LXWGOptions"
    } else {
        "option.LXOptions"
    }
}

/// `lx` decode + the `resolveLXValues` chain, in reference order.
fn validate_lx(value: Option<&Value>) -> Result<Option<LxBlock>, String> {
    let Some(lx) = lx_object(value, "lx", "_Options.lx")? else {
        return Ok(None);
    };
    let mut block = LxBlock::default();
    for (key, entry) in lx {
        match key.as_str() {
            "wg" => {
                let Some(wg) = lx_object(Some(entry), "lx.wg", "LXOptions.lx.wg")? else {
                    continue;
                };
                for (field, item) in wg {
                    match field.as_str() {
                        "idle_suspend" => {
                            block.idle_suspend =
                                lx_duration(Some(item), "lx.wg.idle_suspend", field)?
                        }
                        "idle_suspend_reachable" => {
                            block.idle_suspend_reachable =
                                lx_duration(Some(item), "lx.wg.idle_suspend_reachable", field)?
                        }
                        "idle_teardown" => {
                            block.idle_teardown =
                                lx_duration(Some(item), "lx.wg.idle_teardown", field)?
                        }
                        "lazy_build" => {
                            check_bool_field(
                                item,
                                &format!("lx.wg.{field}"),
                                "LXWGOptions",
                                &format!("lx.wg.{field}"),
                            )?;
                            block.lazy_build = item.as_bool().unwrap_or(false);
                        }
                        "build_max" => {
                            check_int_field(
                                item,
                                &format!("lx.wg.{field}"),
                                "LXWGOptions",
                                &format!("lx.wg.{field}"),
                            )?;
                            block.build_max = item.as_i64().unwrap_or(0);
                        }
                        "build_overflow" => {
                            check_string_field(
                                item,
                                &format!("lx.wg.{field}"),
                                "LXWGOptions",
                                &format!("lx.wg.{field}"),
                            )?;
                            block.build_overflow = item.as_str().unwrap_or("").to_string();
                        }
                        other => {
                            return Err(format!("lx.wg.{other}: json: unknown field \"{other}\""));
                        }
                    }
                }
            }
            "masque" => {
                let Some(masque) = lx_object(Some(entry), "lx.masque", "LXOptions.lx.masque")?
                else {
                    continue;
                };
                for (field, item) in masque {
                    match field.as_str() {
                        "idle_timeout" => {
                            block.masque_idle_timeout =
                                lx_masque_duration(Some(item), "lx.masque.idle_timeout", field)?
                        }
                        other => {
                            return Err(format!(
                                "lx.masque.{other}: json: unknown field \"{other}\""
                            ));
                        }
                    }
                }
            }
            other => return Err(format!("lx.{other}: json: unknown field \"{other}\"")),
        }
    }
    Ok(Some(block))
}

/// `resolveLXValues`: the post-decode validation chain (no `decode config at`).
fn resolve_lx_values(block: &LxBlock) -> Result<(), String> {
    let suspend = block.idle_suspend.unwrap_or(0);
    let reachable = block.idle_suspend_reachable.unwrap_or(0);
    if suspend < 0 {
        return Err("lx.wg.idle_suspend must be >= 0".to_string());
    }
    if reachable < 0 {
        return Err("lx.wg.idle_suspend_reachable must be >= 0".to_string());
    }
    if block.idle_teardown.is_some_and(|value| value < 0) {
        return Err("lx.wg.idle_teardown must be >= 0".to_string());
    }
    if suspend == 0 {
        if reachable > 0 {
            return Err("lx.wg.idle_suspend_reachable requires lx.wg.idle_suspend".to_string());
        }
        if block.idle_teardown.is_some() {
            return Err("lx.wg.idle_teardown requires lx.wg.idle_suspend".to_string());
        }
        if block.lazy_build {
            return Err("lx.wg.lazy_build requires lx.wg.idle_suspend".to_string());
        }
    }
    if reachable > 0 && reachable < suspend {
        return Err("lx.wg.idle_suspend_reachable must be >= lx.wg.idle_suspend".to_string());
    }
    if block.build_max < 0 {
        return Err("lx.wg.build_max must be >= 0".to_string());
    }
    match block.build_overflow.as_str() {
        "" | "wait" | "build" => {}
        _ => return Err("lx.wg.build_overflow must be \"wait\" or \"build\"".to_string()),
    }
    if block.masque_idle_timeout.is_some_and(|value| value < 0) {
        return Err("lx.masque.idle_timeout must be >= 0".to_string());
    }
    Ok(())
}

/// Deprecated `route.lx_idle_*` aliases: same value folds silently, a
/// different value conflicts, and the folded block is validated again.
/// Returns one deprecation warning per alias that folded.
fn resolve_lx_aliases(lx: &mut LxBlock, route: &Value) -> Result<Vec<String>, String> {
    let Some(route) = route.as_object() else {
        return Ok(Vec::new());
    };
    let folded = lx;
    let mut warnings = Vec::new();
    for (legacy, field) in [
        ("lx_idle_suspend", "idle_suspend"),
        ("lx_idle_suspend_reachable", "idle_suspend_reachable"),
        ("lx_idle_teardown", "idle_teardown"),
    ] {
        let Some(value) = route.get(legacy) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let at = format!("route.{legacy}");
        check_duration_field(value, &at, "RouteOptions", &format!("route.{legacy}"))?;
        let Some(text) = value.as_str() else { continue };
        go_parse_duration(text)?;
        let nanos = go_duration_ns_or_zero(text);
        let current = match field {
            "idle_suspend" => folded.idle_suspend,
            "idle_suspend_reachable" => folded.idle_suspend_reachable,
            _ => folded.idle_teardown,
        };
        if let Some(current) = current
            && current != nanos
        {
            return Err(format!("route.{legacy} conflicts with lx.wg.{field}"));
        }
        match field {
            "idle_suspend" => folded.idle_suspend = Some(nanos),
            "idle_suspend_reachable" => folded.idle_suspend_reachable = Some(nanos),
            _ => folded.idle_teardown = Some(nanos),
        }
        warnings.push(format!("route.{legacy} is deprecated, use lx.wg.{field}"));
    }
    Ok(warnings)
}

/// Type-specific field checks and init-chain messages for DNS servers
/// (option/dns.go plus each transport's `NewXxx` chain).
///
/// `seen` carries the `(tag, type)` pairs collected so far, so groups can
/// resolve their members.
fn validate_dns_server_fields(
    ty: &str,
    server: &Map<String, Value>,
    i: usize,
    tag: &str,
    seen: &[(String, &'static str, usize)],
) -> Result<(), String> {
    let at = format!("dns.servers[{i}]");
    let init = format!("initialize DNS server[{i}]");
    let at = at.as_str();
    let listable_strings = |value: &Value, at: &str| -> Result<Vec<String>, String> {
        match value {
            Value::Null => Ok(Vec::new()),
            Value::String(text) => Ok(vec![text.clone()]),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    match item {
                        Value::String(text) => out.push(text.clone()),
                        other => {
                            return Err(format!(
                                "{at}[{index}]: json: cannot unmarshal {} into Go value of type string",
                                json_kind(other)
                            ));
                        }
                    }
                }
                Ok(out)
            }
            other => Err(format!(
                "{at}: json: cannot unmarshal {} into Go value of type string",
                json_kind(other)
            )),
        }
    };
    match ty {
        "local" | "dhcp" | "mdns" => {
            if let Some(value) = server.get("prefer_go") {
                check_bool_field(
                    value,
                    &format!("{at}.prefer_go"),
                    "LocalDNSServerOptions",
                    "prefer_go",
                )?;
            }
            if let Some(value) = server.get("neighbor_domain") {
                for entry in listable_strings(value, &format!("{at}.neighbor_domain"))? {
                    if !entry.starts_with('.') {
                        return Err(format!(
                            "{init} {ty}[{tag}]: neighbor_domain entry must start with '.': {entry}"
                        ));
                    }
                }
            }
            if let Some(field) = server.get("interface") {
                // badoption.Listable[string] (mdns) and a plain string (dhcp)
                if field.as_str().is_none() && !matches!(field, Value::Array(_) | Value::Null) {
                    return Err(format!(
                        "{at}.interface: (json: cannot unmarshal {} into Go value of type string | json: cannot unmarshal {} into Go value of type []string)",
                        json_kind(field),
                        json_kind(field)
                    ));
                }
                if matches!(field, Value::Array(_)) {
                    listable_strings(field, &format!("{at}.interface"))?;
                }
            }
        }
        "h3" => {
            // reference `RemoteHTTPSDNSServerOptions` for h3: a server name or
            // insecure TLS is required
            let tls = server.get("tls").and_then(Value::as_object);
            let insecure = tls
                .and_then(|tls| tls.get("insecure"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let server_name = tls
                .and_then(|tls| tls.get("server_name"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| server.get("server").and_then(Value::as_str).unwrap_or(""));
            if server_name.is_empty() && !insecure {
                return Err(format!(
                    "{init} h3[{tag}]: missing server_name or insecure=true"
                ));
            }
        }
        "resolved" => {
            if let Some(value) = server.get("service") {
                check_string_field(
                    value,
                    &format!("{at}.service"),
                    "ResolvedDNSServerOptions",
                    "service",
                )?;
            }
            if let Some(value) = server.get("accept_default_resolvers") {
                check_bool_field(
                    value,
                    &format!("{at}.accept_default_resolvers"),
                    "ResolvedDNSServerOptions",
                    "accept_default_resolvers",
                )?;
            }
            if !cfg!(target_os = "linux") {
                return Err(format!(
                    "{init} resolved[{tag}]: resolved DNS server is only supported on Linux"
                ));
            }
        }
        "tailscale" | "openvpn" | "openconnect" => {
            let endpoint = server.get("endpoint").and_then(Value::as_str).unwrap_or("");
            if endpoint.is_empty() {
                if let Some(message) = dns_endpoint_tag_error(ty, i, tag) {
                    return Err(message);
                }
            } else if !seen.iter().any(|(known, _, _)| known == endpoint) {
                // endpoints live in their own section; only the tag shape is
                // checked here (the reference reports "endpoint not found" at
                // start, after the DNS server exists)
            }
            for field in ["accept_default_resolvers", "accept_search_domain"] {
                if let Some(value) = server.get(field) {
                    check_bool_field(
                        value,
                        &format!("{at}.{field}"),
                        "TailscaleDNSServerOptions",
                        field,
                    )?;
                }
            }
        }
        "group" => {
            // the group transport prefixes its own `group[tag]: ...` message
            let group = |message: String| {
                format!("initialize DNS server[{i}] group[{tag}]: group[{tag}]: {message}")
            };
            let servers = match server.get("servers") {
                None | Some(Value::Null) => Vec::new(),
                Some(value) => listable_strings(value, &format!("{at}.servers"))?,
            };
            if servers.is_empty() {
                return Err(group(
                    "servers is required and must not be empty".to_string(),
                ));
            }
            let mut unique: Vec<&str> = Vec::new();
            for entry in &servers {
                if entry == tag {
                    return Err(group("group cannot contain itself".to_string()));
                }
                if unique.contains(&entry.as_str()) {
                    return Err(group(format!("duplicate server: {entry}")));
                }
                unique.push(entry);
            }
            if let Some(value) = server.get("mode") {
                check_string_field(
                    value,
                    &format!("{at}.mode"),
                    "GroupDNSServerOptions",
                    "mode",
                )?;
                let mode = value.as_str().unwrap_or("");
                if !matches!(mode, "" | "stable" | "fastest" | "parallel") {
                    return Err(group(format!(
                        "unknown mode: {mode} (expected stable, fastest or parallel)"
                    )));
                }
            }
            for field in ["error_ttl", "win_ttl"] {
                if let Some(value) = server.get(field) {
                    check_duration_field(
                        value,
                        &format!("{at}.{field}"),
                        "GroupDNSServerOptions",
                        field,
                    )?;
                }
            }
        }
        "https" => {
            if let Some(value) = server.get("method") {
                check_string_field(
                    value,
                    &format!("{at}.method"),
                    "RemoteHTTPSDNSServerOptions",
                    "method",
                )?;
            }
            if let Some(value) = server.get("headers") {
                check_http_header(value, &format!("{at}.headers"), "badoption", "headers")?;
            }
        }
        "hosts" => {
            if let Some(value) = server.get("path") {
                let _ = listable_strings(value, &format!("{at}.path"))?;
            }
        }
        _ => {}
    }
    Ok(())
}
