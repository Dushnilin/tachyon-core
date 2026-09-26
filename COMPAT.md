# Compatibility matrix

Goal: **full schema compatibility** with sing-box (Leadaxe/sing-box-lx feature set).
Policy: the reference `check` decodes strictly — unknown fields anywhere are
rejected. `tachyon-core check` mirrors this at the top level and inside `log`,
`experimental`, `route`, plus all verified enums/types (inbound/outbound/
endpoint/transport/dns-server/rule-action/log-level/uTLS fingerprint/ss method);
per-protocol outbound field allowlists — landed for hysteria2/tuic (F2);
other protocols still only verify fields we checked empirically.
Raw JSON outbounds from subscriptions are accepted verbatim when they use a
known `type`; an unknown `type` fails the same way `sing-box check` fails.

Known gaps vs reference `check` (documented, no fixtures yet):

- unknown fields *inside* protocol objects for non-hy2/tuic types (e.g.
  `direct` + `server`) — reference rejects, we accept; hy2/tuic in/out now
  have full nested allowlists;
- PEM/x509 content of server certificates — reference parses at check time,
  we only verify presence of certificate/key fields.

Status legend: `planned` · `partial` · `done` · `divergent` (documented difference)

## CLI

| Command | Surface used by Tachyon | Status |
|---|---|---|
| `version` | `generator.uc` regex `sing-box version ([^\s]+)` | scaffold |
| `check -c` | `watchdog.uc`, installer preflight | done (schema + semantic validation) |
| `run` | service runtime | planned |
| `format`, `upgrade` | config maintenance | planned |
| `generate uuid\|rand\|reality-keypair\|wg-keypair\|tls-keypair` | `server/service.uc`, `warp_generator.uc` | planned |
| `rule-set compile\|decompile\|upgrade` | `updates.uc` | planned |
| `api`, `dns` | diagnostics | planned |
| `lxd` | lx daemon | planned |

## Top-level sections

| Section | Status | Notes |
|---|---|---|
| `log` | partial | level/output/timestamp/disabled live; `time` (unix epoch format) ignored |
| `dns` | partial | udp/tcp/tls/https/fakeip + rule walk live; predefined rules, groups (lx) planned; `evaluate`/`respond` warn+inert |
| `ntp` | partial | SNTP client + write_to_system; no interval edge cases yet |
| `certificate` | planned | |
| `endpoints` | planned | sing-box 1.12+, incl. AWG fields |
| `inbounds` | partial | tproxy/direct/mixed/redirect data plane live (F1); server half planned |
| `outbounds` | planned | see protocol table |
| `route` | partial | matchers + actions live; dial defaults `auto_detect_interface`/`default_interface`/`default_mark`/`default_domain_resolver` live (Linux SO_MARK/SO_BINDTODEVICE; non-Linux mark/interface inert); reject flood counter; `default_domain_strategy` rejected like leadaxe; per-outbound `domain_resolver` dial field not yet; rule_set/SRS F3 |
| `services` | planned | |
| `experimental` | planned | cache_file, clash_api |
| `http_clients` | planned | 1.14+ gate |

## Outbound protocols

| Type | Status | Notes |
|---|---|---|
| `direct`, `selector`, `urltest`, `block`, `dns` | planned | urltest `mode: round_robin` (lx) |
| `socks`, `http`, `shadowsocks` | planned | |
| `vmess`, `vless`, `trojan` | planned | |
| `hysteria2`, `tuic` | runtime interop green (quinn dial vs ref sing-box over SOCKS5 TCP; hy2 ALPN `h3`, tuic ALPN empty + EKM auth; check-parity full field allowlists) | ring-free QUIC crypto (`core-crypto` + `core-tls::quic`); outbound dial in `core-runtime/outbound/{quic,hysteria2,tuic}.rs`; `hy2_tuic_interop` SING_BOX_REF-gated |
| `wireguard` (+ AWG 2/3 fields) | planned | lx/extended schema at endpoint root |
| `xhttp` transport | planned | lx `with_xhttp` |
| `masque` / `warp` | planned | lx |
| `anytls`, `snell`, `mieru`, `sudoku`, `openvpn`, `tailscale` | planned | extended/lx |
| `chain` | planned | lx multi-hop |
| `fptn` (tachyon extension) | partial | `fptn:`/`fptnb:` token outbound: parse + check-time expansion into per-server outbounds + urltest group (`tests/golden/ext/`); runtime + clash_api exposure planned — the reference rejects `type: fptn` as unknown, so this type has no differential parity |

## Inbound types

| Type | Status | Notes |
|---|---|---|
| `tproxy` (v4/v6), `direct`, `mixed`, `redirect` | done | Tachyon data plane (F1: TCP+UDP, OOB orig-dst, hijack-dns) |
| `socks`, `http`, `mixed` server, … | planned | server half |
| `tun` | planned | `stack: system` first, userspace stack later (divergent vs gvisor) |

## Version gates

| Gate | Fields | Status |
|---|---|---|
| 1.14+ | `dns.optimistic`, `route.default_http_client`, `http_clients`, cache `store_dns` | planned |
| 1.15+ | cache `buffer_size`, `flush_interval` | planned |

## Experimental

| Feature | Status | Notes |
|---|---|---|
| `cache_file` (bbolt, store_fakeip/store_dns) | planned | must read/write upstream `cache.db` |
| `clash_api` | planned | external_controller :9090, Yacd UI, secret |
