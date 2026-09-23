# Compatibility matrix

Goal: **full schema compatibility** with sing-box (Leadaxe/sing-box-lx feature set).
Policy: unknown fields are ignored with a debug warning (upstream default behaviour);
strict mode is opt-in. Raw JSON outbounds from subscriptions are accepted verbatim;
an unknown `type` must fail the same way `sing-box check` fails.

Status legend: `planned` · `partial` · `done` · `divergent` (documented difference)

## CLI

| Command | Surface used by Tachyon | Status |
|---|---|---|
| `version` | `generator.uc` regex `sing-box version ([^\s]+)` | scaffold |
| `check -c` | `watchdog.uc`, installer preflight | scaffold (JSON parse only) |
| `run` | service runtime | planned |
| `format`, `upgrade` | config maintenance | planned |
| `generate uuid\|rand\|reality-keypair\|wg-keypair\|tls-keypair` | `server/service.uc`, `warp_generator.uc` | planned |
| `rule-set compile\|decompile\|upgrade` | `updates.uc` | planned |
| `api`, `dns` | diagnostics | planned |
| `lxd` | lx daemon | planned |

## Top-level sections

| Section | Status | Notes |
|---|---|---|
| `log` | planned | |
| `dns` | planned | incl. FakeIP, predefined rules, groups (lx) |
| `ntp` | planned | |
| `certificate` | planned | |
| `endpoints` | planned | sing-box 1.12+, incl. AWG fields |
| `inbounds` | planned | tproxy/direct/mixed/redirect + server half |
| `outbounds` | planned | see protocol table |
| `route` | planned | all matchers, rule_set, actions |
| `services` | planned | |
| `experimental` | planned | cache_file, clash_api |
| `http_clients` | planned | 1.14+ gate |

## Outbound protocols

| Type | Status | Notes |
|---|---|---|
| `direct`, `selector`, `urltest`, `block`, `dns` | planned | urltest `mode: round_robin` (lx) |
| `socks`, `http`, `shadowsocks` | planned | |
| `vmess`, `vless`, `trojan` | planned | |
| `hysteria2`, `tuic` | planned | quinn |
| `wireguard` (+ AWG 2/3 fields) | planned | lx/extended schema at endpoint root |
| `xhttp` transport | planned | lx `with_xhttp` |
| `masque` / `warp` | planned | lx |
| `anytls`, `snell`, `mieru`, `sudoku`, `openvpn`, `tailscale` | planned | extended/lx |
| `chain` | planned | lx multi-hop |

## Inbound types

| Type | Status | Notes |
|---|---|---|
| `tproxy` (v4/v6), `direct`, `mixed`, `redirect` | planned | Tachyon data plane |
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
