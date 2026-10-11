# Changelog

All notable changes to tachyon-core. The version is the workspace version in
`Cargo.toml`; a tag that disagrees with it is refused by the release workflow.

## 0.0.7

Point release delivering native Brutal congestion control for Hysteria2, resilient non-fatal action: resolve with real IP destination rewriting for ByeDPI/Zapret, pure-Rust Tailscale mesh outbound, UDP L7 protocol sniffing, and OpenWrt runtime hardening.

### Fixes & Improvements

- **Hysteria2 Brutal Congestion Control**:
  - Implemented native Brutal congestion controller factory and pacing engine in Quinn, pacing packet transmission at the configured `up_mbps` rate without halving or backing off the congestion window upon packet loss.
  - Neutralizes ISP packet throttling and artificial packet drop injected by TSPU filters on Hysteria2 tunnels.
- **Routing Engine & ByeDPI / Zapret Interop**:
  - Made DNS failures in `action: resolve` non-fatal: routing evaluation proceeds to fallback and section outbounds rather than aborting client TCP sessions at the router stage.
  - Replaced target destination with resolved IP while preserving the original hostname in `ctx.domain`, ensuring SOCKS outbounds (such as ByeDPI `ciadpi`) receive clean IP targets (`ATYP 0x01`/`0x04`) and permanently eliminating FakeIP loopback loops on OpenWrt routers.
  - Added support for `hosts` and `local`/`neighbor` server types in `lookup_via`.
- **Pure-Rust Tailscale Outbound**:
  - Completed end-to-end user-space Tailscale mesh client support with STUN, coordinator authentication, netmap syncing, and direct P2P UDP packet transmission without C-crypto dependencies.
- **Protocol Sniffing & Framing Hardening**:
  - Added UDP L7 packet sniffing for QUIC (v1/v2 Initial and fragmented ClientHello), DNS, STUN, and BitTorrent.
  - Handled empty TLS record frames gracefully without terminating the connection processor.
  - Cleared intermediate plaintext buffers on authentication tag mismatch in software AES-GCM.
  - Fixed composite duration parsing (e.g. `1m30s`, `300ms`) and supported `udp_timeout` and `ip_version` routing rule options.
  - Aligned Clash API `/rules` and `/connections` outputs with the sing-box reference schema.

## 0.0.6

Point release delivering zero-downtime atomic in-place configuration reload via SIGHUP, DNS query loop prevention with UDP retransmission, process-stable randomized TLS fingerprints, and Trojan server address type framing fixes.

### Fixes & Improvements

- **Zero-Downtime Atomic In-Place SIGHUP Reload**:
  - Implemented true in-place configuration swapping when inbound listeners remain unchanged, keeping existing listener sockets open and active TCP connections uninterrupted.
  - Preserved outbound latency measurements (`delay_history`), selector selections, and `urltest` group latencies across reloads by tag mapping, permanently eliminating `N/A` latency resets in Clash API and dashboard clients.
  - Migrated active DNS cache entries, resolved server bootstrap IP addresses, reverse DNS records, and FakeIP LRU address-to-domain mapping pools across reloads without state flushing.
  - Added atomic rollback: invalid configurations, syntax errors, or unresolvable server references fail gracefully with running listeners and routes completely untouched.
- **DNS Resolver Hardening & Retransmission**:
  - Eliminated fallback to system resolver (`lookup_host`) when a configured `domain_resolver` fails or returns no records, preventing recursive forwarding amplification loops between `dnsmasq` and `sing-box` on port 53.
  - Added UDP query retransmission loop (1.5s interval bounded by query timeout) to gracefully recover from dropped DNS packets on lossy PPPoE links.
- **Process-Stable Random & Randomized uTLS Fingerprints**:
  - Enabled runtime construction and execution for `tls.utls.fingerprint: "random"` and `"randomized"`, including under REALITY outbounds (PR #11 by @Screamshow).
  - Selected profile remains stable per-process across outbounds, reloads, and handshakes, with cipher suite and extension shuffling preserving HTTP/2 ALPN and hybrid group pairs.
- **Trojan Inbound Server Address Types & IPv6 Support**:
  - Isolated SOCKS ATYP translation strictly to the Trojan protocol boundary, preserving standard binary framing for VLESS and VMess transports (PR #10 by @MaksSt).
  - Fixed TLS streaming to domain and IPv6 target destinations on the Trojan server inbound, backed by wire regression test suites.

## 0.0.5

### DNS: интернет пропадал на роутере с большим конфигом
- Адрес DoH-сервера, который разрешается через `domain_resolver`, теперь кэшируется на минуту, а одновременные разрешения идут по одному. Раньше десятки узлов в один момент слали одинаковый запрос на bootstrap, апстрим часть A-запросов дропал, каждый ждал полный таймаут, потом ядро уходило в системный резолвер, то есть в dnsmasq, а он обратно в ядро. Получалась петля, dnsmasq упирался в лимит запросов.
- Один упавший тип записи (A или AAAA) больше не валит весь bootstrap-запрос.
- В предупреждении про fallback теперь настоящая причина.

### mieru: клиент и сервер (TCP)
- Outbound и inbound `mieru`, проверено в обе стороны с настоящими `mieru`/`mita` 3.38.0 (небольшие запросы и файл 100 КБ байт-в-байт).
- Нет UDP-транспорта и мультиплексирования на клиенте, скорость не измерялась.

## 0.0.4

### XHTTP: большой пинг
- Сокет теперь возвращается в пул после `POST` (пустое тело с `Content-Length: 0` больше не оставляет соединение висеть).
- Починена инвертированная проверка в xmux, из-за которой каждый запрос открывал новое соединение.
- Пинг по xhttp-узлам упал до нормальных значений, double-hop узлы больше не висят в `N/A`.

### DNS
- Remote rule-set теперь работает внутри DNS-правил (#8).
- `evaluate` / `respond`: порядок правил и обратное сопоставление FakeIP сохраняются.
- DoH у Cloudflare: исправлен `Content-Length`.

### Перезапуск и UDP (спасибо @MaksSt, PR #9)
- Порты инбаундов освобождаются при SIGHUP и при остановке: UDP, QUIC, Hysteria2, tproxy (#5).
- Если новая конфигурация не стартует, откатываемся на прежнюю.
- XUDP / VLESS UDP, ответы TProxy с адреса назначения, session id у Hysteria2.
- Таймаут блокирующих воркеров в CLI.

Спасибо @Screamshow за PR #7 и разбор DNS: нужные части поведения закрыты тестами, часть правок уже была в нашей реализации.

Новых зависимостей нет, размер бинарников в пределах бюджета.

## 0.0.3

Point release addressing compound headless rules matching in RuleSet, outbound proxy routing mark tagging, zero-downtime SIGHUP reload, and MIPS toolchain musl linker stability.

### Fixes & Improvements

- **Compound Headless Rule Matching in RuleSets**:
  - Fixed matching logic in `RuleSetIndex` and `PlainRule::matches`: composite rule match criteria (e.g. `network: udp` and `port_range`) are now evaluated with strict `AND` semantics and stored in a composite fallback chain instead of independent `OR` checks.
  - Eliminates false matching of DNS queries against port-restricted rules (such as Discord Voice UDP 50000-65535).
- **Socket Mark on All Proxy Outbounds**:
  - Ensured `apply_dial_defaults` applies `routing_mark` (`0x08000000`) across all outbound proxy transports (VLESS, Trojan, Shadowsocks, VMess, ShadowTLS, Naive, Snell), preventing TProxy packet re-injection loopback in nftables `TachyonTable`.
- **MIPS & MIPSEL Musl Linker Stability**:
  - Bundled `libgcc_eh.a` with `_dl_find_object` stubs into `libunwind.a` for clean musl target linking across MIPS softfloat and MIPSEL architectures.
- **SIGHUP Reload (Zero Downtime)**:
  - Implemented in-place configuration reload on `SIGHUP` signal (`run_reloadable`) in `core-runtime` without process exit or socket collisions.

## 0.0.2

Point release improving network compatibility, DNS resilience, protocol framing, and TLS fingerprint fidelity.

### Fixes & Improvements

- **DNS Resolver Resiliency**:
  - Added automatic fallback to system resolver (`tokio::net::lookup_host`) when a configured `domain_resolver` (bootstrap DNS, e.g. UDP port 53) times out or is unreachable. Fixes DNS failure on ISPs (such as PPPoE WANs) that drop external UDP port 53.
  - Implemented routing target resolution for DNS `Action::Evaluate`, resolving and routing DNS evaluation queries through the specified server rather than dropping or ignoring the rule.
  - Corrected DNS rule iteration to skip `match_response` rules during initial query evaluation, preventing response-matching rules from misrouting outgoing queries.
- **VLESS Vision Direct Raw Transport**:
  - Implemented receive-side transition to raw transport upon receiving `CommandPaddingDirect`. Buffered content and padding are drained before switching the read path to the raw underlying stream, resolving inner TLS 1.3 HTTPS stalls behind REALITY/Vision (Closes #1).
- **Browser TLS Fingerprints & RFC 8879 Certificate Compression**:
  - Refreshed browser ClientHello fingerprint fixtures for modern Firefox (148), Safari (26.3), and Chrome with exact key-share tables and hybrid ML-KEM/X25519 alignment.
  - Added native RFC 8879 certificate compression support (zlib, Brotli, Zstd) using pure-Rust decoders (Closes #2).
- **Sing-Box Compatible XHTTP Forms**:
  - Accepted `session_id_table` and `session_id_length` aliases, numeric values for range fields, named session alphabets (`hex`, `Base62`), and default fallback for zero uplink chunk sizes (Closes #3).
- **AF_ALG & TUN Portability**:
  - Replaced unchecked `msg_iovlen` casts with checked conversions across target architectures, and cleaned up TUN identity IP-address conversions (PR #4).

## 0.0.1

The first tagged build. A routing core for OpenWrt: the client stack end to
end, plus the server half of the four TCP proxy protocols.

### What runs

- **Inbounds**: `mixed` (HTTP, SOCKS4/4a, SOCKS5 with UDP ASSOCIATE), `direct`,
  `redirect` (Linux `REDIRECT`), `tproxy` (v4/v6 with `IP_TRANSPARENT`), `tun`
  (pure-Rust `/dev/net/tun` with `smoltcp` userspace TCP/IP stack, transparent TCP proxying, UDP NAT with remote/client source preservation, table 2022 policy routing + fwmark, GRO/GSO virtio_net_hdr parsing and TSO segmentation, dual-stack IPv4/IPv6 and ICMP/ICMPv6 echo responder), and the
  server inbounds `vless`, `trojan`, `vmess`, `shadowsocks`, `hysteria2`, `tuic`
  and `wireguard`.
- **Server inbounds** accept the TCP command and the UDP command, over a `tls`
  block with our own handshake — TLS 1.3, X25519, three cipher suites, ALPN, no
  resumption, HelloRetryRequest handled the same way the client does.
- **Outbounds**: `direct`, `block`, `socks`, `http`, `shadowsocks`, `vless`,
  `vmess`, `trojan`, `hysteria2`, `tuic`, `anytls`, `naive`, `snell`, `masque`
  (warp), `fptn`, `urltest`, `selector`, and the `wireguard` and
  `openvpn-client` endpoints, WireGuard with AmneziaWG 2.0/3.x shapes included.
- **Transports**: `ws`, `httpupgrade`, `grpc`, `http`, `xhttp` with `xmux`,
  all three `packet_encoding` modes, uTLS fingerprints and REALITY.
- **DNS**: `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `fakeip`, `local`,
  `hosts`, `group`, `mdns`, `dhcp` and `resolved`; logical rules, `rule_set`, hijack-DNS,
  `reverse_mapping`, `client_subnet`.
- **Routing**: the matcher set including `route.find_neighbor` for
  `source_mac_address` and `source_hostname`, sniffing, and the SRS rule-set
  reader.
- **Experimental**: `clash_api` REST with websocket streaming, delay history, and `external_ui`
  download, and a `cache.db` that Go bbolt can read with auto-flush on timeout and buffer size.
- **OpenWrt Integration**: procd init script, UCI configuration, automatic `RLIMIT_NOFILE`
  raising, and full CLI flag compatibility (`-D`, `-C`, multiple `-c`).

### Measurements

Taken on 2026-10-02 with the same toolchain the release workflow uses:
`cargo build --release` against a musl target, `RUSTFLAGS="-C linker=rust-lld
-C link-self-contained=yes"`, release profile (`opt-level = "z"`, LTO,
`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`).

| | tachyon-core | sing-box-lx 1.14.2-lx.2 | |
|---|:---:|:---:|---|
| binary, aarch64 | **5.37 MiB** | 67.6 MiB | 12.6× smaller |
| binary, armv7 | **5.57 MiB** | 68.2 MiB | 12.2× smaller |
| binary, x86_64 | **6.85 MiB** | 75.9 MiB | 11.1× smaller |
| idle RSS, mixed + direct | **2.4 MiB** | 42.7 MiB | 17.8× less |

The earlier figures in this repository -- 3.5 MiB for aarch64, 19× smaller --
came from a `cargo zigbuild` run, which is not what builds the released binary,
so they were not numbers the release could reproduce. Zig is not in the release
image; `rust-lld` is. The honest numbers are the ones above, and the tree grew
into them: a full TLS 1.3 *server* stack and the server UDP path are new since
that measurement.

CI keeps a hard ceiling of 12 MiB on every architecture it builds, mipsel and
mips included, which the largest of the above clears by 43%.

### Platforms

Static musl builds for the OpenWrt targets: `x86_64`, `aarch64`, `armv7`,
`armv6`, `riscv64`, `mipsel` and `mips`. The two MIPS targets are tier-3 and
their standard library is built from source; they are built and size-checked,
but nothing in this release has been *run* under qemu-user.

The cryptography is pure Rust throughout — no `ring`, no `aws-lc-rs`, no CGO —
so the same source builds for 32-bit softfloat MIPS.

### Known gaps

Stated plainly, because a release note that hides them is worth less than one
that names them:

- No `lxd` daemon, no libbox/Android bindings.
- Tailscale and openconnect not implemented.
- The vless, trojan and vmess server sides do not speak mux (`packetaddr`/`xudp`),
  Vision's server splice, or the legacy vmess CFB body.
- `insecure: true` with no certificate on a server inbound is refused: it needs
  an ephemeral key pair, and nothing here can sign a certificate.
- `COMPAT.md` predates most of this work and does not describe the tree.

### Fixes worth naming

Four of these were live defects rather than missing features, and all four were
found by measuring our own client against our own server:

- vmess `security: auto` became `none` whenever the outbound had a `tls` block,
  so any TLS vmess config carried its payload unencrypted.
- The server-side TLS record layer sealed writes larger than one record, and the
  length in the header is a `u16`: a long write wrapped round to a short length
  and the client read a truncated ciphertext out of the middle of it.
- An inline `certificate`/`key` on a server inbound was read only as a string,
  where the reference reads a `Listable[string]` — the form nearly every config
  actually uses.
- The vmess UDP client consumed one byte of the server's answer instead of two,
  and read the rest as the length of the first datagram.
