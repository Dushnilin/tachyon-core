<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-10.0_--_12.8_MiB-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core/releases/tag/v0.0.1)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-4.2_MiB_idle-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-36%2F39_Wins-10B981?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
[![Interactive Report](https://img.shields.io/badge/Dashboard-HTML_Report-6366F1?style=for-the-badge&logo=html5&logoColor=white)](BENCHMARK.html)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md) | [**📊 Latest Benchmark**](BENCHMARK.md) | [**🌐 Interactive HTML**](BENCHMARK.html)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚡ Overview

**tachyon-core** is a proxy core for routers and embedded systems, written from scratch in pure **Rust**. It takes the **same JSON config** and the **same CLI** as sing-box, but without the Go runtime: the same `/etc/sing-box/config.json`, the same `check -c` / `version` / `run`, and the same binary, which reports a compatible version string when installed under the name `sing-box`.

The full [sing-box-lx](https://github.com/Leadaxe/sing-box-lx) feature set is supported: XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, uTLS, REALITY, ShadowTLS, DNS groups, post-quantum encryption, native Tailscale, and zero-copy mmap rule-sets.

All numbers come from real static musl builds measured against reference Go cores (`sing-box-lx` 1.14.2-lx.12, `Xray-core`, `Mihomo`) and the modular C stack `steer`, in a single-core router profile (1 worker, CPU pinning). Full graphs: **[BENCHMARK.md](BENCHMARK.md)** and **[BENCHMARK.html](BENCHMARK.html)**.

**Averages across all target architectures:**

| | tachyon-core | Go cores (sing-box-lx / Xray / Mihomo) | Advantage |
|---|:---:|:---:|:---:|
| **Binary size** | **10.0–12.8 MiB** (4.7–5.3 MB in archive) | ~70 MiB | **~6.5× smaller** |
| **Idle RAM** | **4.2 MiB** | ~41 MiB | **~10× less** |
| **RAM under load** | **~10 MiB** | ~65 MiB | **~6× less** |
| **GC pauses** | **0.00 ms** | 2–15 ms | **no jitter at all** |
| **Cold start** | **22 ms** | ~210 ms | **7–12× faster** |
| **C / CGO dependencies** | **0** | CGO / BoringSSL | **builds on any MIPS** |

> **Direct advantage #1 — memory.** ~10× less at idle on a 128 MB router is the difference between "OOM-killer at the worst possible moment" and having headroom for conntrack, Wi-Fi, and LuCI.
>
> **Direct advantage #2 — flash.** 10.0–12.8 MiB (4.7–5.3 MB in archive) against ~70 MiB: the core installs straight into the internal `/usr/bin/` flash of a 16/32/128 MB router, with no USB drive and no extroot. A Go binary physically does not fit.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚔️ Why Rust and Not Go

| | sing-box / sing-box-lx / Xray (Go) | tachyon-core (Rust) |
|---|---|---|
| **Garbage collector** | Continuous heap scans plus Stop-The-World phases: CPU spikes and **2–15 ms pauses** on weak router CPUs. Audible as micro-stutter in VoIP and ping spikes in games | No collector at all. RAII reclaims memory deterministically, the instant a socket goes out of scope. **0.00 ms pauses**, flat latency graph |
| **Scheduler and pools** | Internal thread pools, goroutine stacks, `mheap` reservations: ~41 MiB when fully idle, past 100 MiB at 10k connections, then OOM-Killer | Nothing is pre-reserved. 4.2 MiB idle, ~10 MiB peak |
| **Crypto on MIPS** | BoringSSL/CGO breaks builds on 32-bit softfloat MIPS (MediaTek MT7621, ath79), and `gc` emits unoptimized code | The crypto provider is pure RustCrypto throughout (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`). Zero external C files, no `libssl.so` linkage |
| **Data pipeline** | userspace copies between client socket and tunnel | `bytes::Bytes` buffer pools plus `splice` and the `drive_transparent` driver — forwarding with no intermediate copies |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Performance

<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

### End-to-end routing test (SOCKS5 Inbound → Direct Outbound), 1 CPU core

| Core | Binary | Cold start | RAM (Idle / Peak) | Latency p50 / p99 | Throughput | CPU |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **tachyon-core** | **11.61 MiB** | **22.3 ms** 🥇 | **4.2 / 4.6 MiB** 🥇 | **170.0 / 221.4 µs** 🥇 | **51.7 Gbps** | 0.163 s/G |
| `steer` (C, 3 procs) | 1.76 MiB | 141.9 ms | 5.1 / 5.4 MiB | 173.6 / 221.7 µs | 8.0–9.6 Gbps | 1.067 s/G |
| `xray-core` (Go, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 / 233.4 µs | 53.1 Gbps | 0.158 s/G |
| `mihomo` (Go, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 / 251.3 µs | 48.2 Gbps | 0.174 s/G |
| `sing-box-lx` (Go, reference) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 / 232.8 µs | 51.5 Gbps | 0.166 s/G |

> **Direct advantage #3 — cold start.** 22 ms against ~210 ms: on a router, where the service comes up on every reboot or network restart, that is the difference between "working" and "a minute of waiting".
>
> On pure loopback throughput `xray-core` edged ahead (53.1 vs 51.7 Gbps), which is within noise. The real tachyon advantage here is not gigabytes per second but memory, start-up, and latency: **the lowest p50 and p99 of all five cores** at 4.2 MiB instead of 25–41 MiB.

### Multi-protocol benchmark

**36 wins out of 39 protocols, 3 ties, 0 losses.** Averages of the 1s/8s runs, Gbit/s:

| Protocol | Tachyon | Sing-box-lx | Xray | Mihomo | Steer | Advantage |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Hysteria 2 (QUIC)** | **3.2 / 4.2** | 1.8 / 1.8 | — | 2.3 / 1.9 | 1.8 / 1.8 | **~2.3×** |
| **NaiveProxy (H2)** | **2.4 / 4.2** | 1.4 / 2.1 | — | — | — | **~2×** |
| **TUIC v5 (QUIC)** | **3.9 / 4.6** | 2.5 / 1.9 | — | 2.4 / 2.0 | — | **~2×** |
| Mieru (TCP) | — | 2.1 / 2.5 | — | 2.1 / 2.4 | — | not in the tree |
| **WireGuard** | **7.2 / 8.5** | 4.1 / 4.8 | 3.8 / 4.2 | 3.9 / 4.4 | — | **~1.8×** |
| **AmneziaWG** | **7.0 / 8.1** | 4.0 / 4.6 | 3.6 / 4.1 | 3.8 / 4.2 | — | **~1.8×** |
| **MASQUE (WARP)** | **4.8 / 6.4** | 3.1 / 3.9 | — | — | — | **~1.6×** |
| **ShadowTLS v3** | **5.6 / 7.1** | 3.8 / 4.6 | — | 3.4 / 4.1 | — | **~1.5×** |
| **VMess + WS + TLS** | **4.3 / 5.6** | 3.0 / 3.3 | 2.0 / 2.0 | 2.1 / 2.2 | 2.0 / 2.1 | **~1.7×** |
| **VLESS + gRPC + TLS** | **2.6 / 4.6** | 1.6 / 2.5 | 1.7 / 2.8 | 1.7 / 3.2 | 1.4 / 1.7 | **~1.4×** |
| VLESS (Plain) | 23.3 / 31.9 | 24.7 / 33.5 | 8.2 / 9.1 | — | 8.2 / 8.7 | parity |
| VLESS + TLS + Vision | 3.4 / 3.7 | 3.2 / 3.5 | 2.2 / 2.8 | 3.3 / 3.5 | 2.7 / 3.1 | parity |

> **Direct advantage #4 — QUIC protocols.** Hysteria2 and TUIC are where the gap is widest: ~2–2.3× the speed at half the peak RSS (12–25 MiB against 50–53 MiB).
>
> **Direct advantage #5 — XHTTP.** The built-in `H2Pool` connection pool removes repeated TLS handshakes per stream. Time to first byte: **408 µs against ~30 ms** for the Go cores — **~75× faster**. On multiplexed streams, 4.4+ Gbit/s.
>
> All 39 protocols with per-protocol p50/p99 and RSS: **[BENCHMARK.md](BENCHMARK.md)**.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Core Capabilities

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

**Inbounds.** Transparent interception: Linux **TProxy** (IPv4/IPv6) via `IP_TRANSPARENT` with the real destination recovered from OOB `IP_RECVORIGDSTADDR`; **Redirect** (NAT) via `SO_ORIGINAL_DST`; **Mixed SOCKS/HTTP** with full CONNECT, SOCKS4/4a/5, UDP ASSOCIATE, 407, and keep-alive; **Direct**; **TUN** (`/dev/net/tun`, userspace TCP stack on `smoltcp`, GSO segmentation, policy routing in a separate table 2022). Server stack: VLESS, Trojan, VMess (AEAD), Shadowsocks (AEAD), AnyTLS, Naive, Hysteria2, TUIC, with a pure-Rust TLS 1.3 implementation and UDP over the same TCP connection.

Full field reference — **[docs/reference/](docs/reference/README.md)**: every inbound and outbound type, the shared option blocks (listen, dialer, TLS, transports, multiplex), defaults and limitations.

**Outbounds.** `direct`, `block`, `socks`, `http`. Shadowsocks (all AEAD ciphers, 2022 specification, UoT, TLS transport). VLESS (`flow: xtls-rprx-vision`, all `packet_encoding`, `h2mux`, uTLS). VMess (AEAD and legacy, `h2mux`). Trojan (SHA224). Hysteria2 (`quinn` engine, salamander and gecko obfuscation, BBR and Cubic). TUIC v5. AnyTLS. Naive (HTTP/2 and HTTP/3, `Padding`, `-connect-authority`, `[len:u16][pad:u8]` framing). Snell v4/v6. ShadowTLS v3. MASQUE (WARP). FPTN. Dispatch: `urltest` and `selector` (`round_robin`, `least_test`, `least_ping`).

**Tunnel endpoints.** AmneziaWG 2.0/3.x and WireGuard — full pipeline with junk packets at session start (`jc`, `jmin`, `jmax`, `s1–s4`, `h1–h4`) and initialization disguised as DNS, STUN, SIP, and QUIC Initial. OpenVPN client: `static_key` over UDP and TCP, with compression and fragmentation.

**Transports and anti-DPI.** TCP, WebSocket (`max_early_data`), HTTPUpgrade, gRPC, HTTP/2, QUIC/HTTP-3. **XHTTP**: HTTP/1.1 chunked, `stream-up`, `packet-up`, `stream-one`, plus the `H2Pool` of up to 4 parallel sockets with least-loaded stream balancing, extended stream windows (4 MiB stream / 16 MiB connection), validated against Xray 26.9+ servers. **Pure-Rust uTLS**: 13 byte-exact browser profiles and its own ClientHello. **Pure-Rust REALITY** with end-to-end `splice`. **Post-quantum cryptography**: hybrid ML-KEM-768 key exchange (`X25519MLKEM768`) against Store Now, Decrypt Later attacks.

**Smart DNS.** `udp`, `tcp`, `tls` (DoT), `https` (DoH), `quic` (DoQ), `h3` (DoH3), `fakeip`, `local`, `hosts` (file and inline), `mdns`. DNS `group` resolvers with `stable` / `fastest` / `parallel` strategies over rolling win/error statistics and a survival fallback. `dns.reverse_mapping` for applying domain rules to direct IP hits. `dns.client_subnet` (EDNS0). `Arc<str>` LRU cache with optimistic serving of stale entries and a FakeIP pool on `198.18.0.0/15`.

**Routing and inspection.** Rule matchers: `inbound`, `network`, `protocol`, domain (suffix, keyword, regex, exact), `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `user`, `user_id` (via `/proc/net/*` and socket descriptors), `clash_mode`, `rule_set`, `rule_set_ipcidr_match_source`. Neighbour table and DHCP leases (`find_neighbor`) for `source_mac_address` and `source_hostname`. PeekStream sniffer: TLS SNI, HTTP Host, QUIC SNI, DNS, BitTorrent, SSH, RDP — without losing leading bytes. Binary SRS v5 rules: compile, decompile, match, and remote list sync.

**System dialer.** Netns with a `CLONE_NEWNET` holder child process and conflict-free dialing. `protect_path` passes socket descriptors to VPN daemons over `SCM_RIGHTS`. Multipath TCP, Happy Eyeballs RFC 6555, fwmark (`routing_mark`), interface binding (`bind_interface`), and protection against packet storms on connection reset.

**API and state.** Clash REST API: `/version`, `/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/providers/*`, WebSocket traffic, secret token, CORS, `clash_mode`, and built-in Yacd / Metacubexd panels under `/ui`. `cache.db` is an honest pure-Rust B+tree, byte-compatible with Go bbolt. Built-in NTP client and the `http_clients` registry.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 Drop-In Compatibility with sing-box

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

```bash
tachyon-core check -c /etc/sing-box/config.json                    # config validation (247/0 across the corpus)
tachyon-core version                                              # upstream-compatible version string
tachyon-core run -c /etc/sing-box/config.json                     # run
tachyon-core rule-set compile rules.json -o rules.srs            # SRS v5, both directions
```

| Command | Purpose | Status |
|---|---|:---:|
| `check -c <path>` | Pre-start config validation in `watchdog.uc` | **Done** |
| `version` | Version detection in `generator.uc` | **Done** |
| `run -c <path>` | Service process start | **Done** |
| `rule-set compile\|decompile` | Binary `.srs` rules (SRS v5) | **Done** |
| `rule-set match\|format` | Rule matching and formatting | **Done** |
| `api` | Control and monitoring via Clash API | **Done** |
| `generate reality-keypair` | REALITY keys | Planned |
| `generate wg-keypair` | WireGuard / AmneziaWG keys | Planned |

> Compatibility with the sing-box config format is a **temporary migration aid** — see the roadmap below.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🚀 Building

Requires Rust 1.89+ (edition 2024).

```bash
# Release build (all protocols, Clash API, DNS groups, Tailscale, mmap, ~11 MiB)
cargo build --workspace --release

# Size limit check (<= 12 MiB) and the test suite
bash scripts/size.sh
cargo test --workspace

# Cross-compiling static musl binaries
cargo install cargo-zigbuild
cargo zigbuild --target aarch64-unknown-linux-musl --release     # ARM64: NanoPi R3S/R4S, Flint 2, RPi 4/5
cargo zigbuild --target armv7-unknown-linux-musleabihf --release # ARMv7: IPQ4019, AX1800, Keenetic Hopper
cargo zigbuild --target x86_64-unknown-linux-musl --release      # Mini-PCs, Proxmox, x86 routers
```

Symbols are stripped automatically (`strip = "symbols"`): **10.0–12.8 MiB** (4.7–5.3 MB in archive).

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Roadmap

Features are split into phases with automatic differential testing against the reference `sing-box-lx`.

| Phase | Area | Status |
|:---:|---|:---:|
| **F0** | Foundation: differential `check` and `version` tests across the whole corpus (247/0) | **Done** |
| **F1** | Data plane v1: tproxy/redirect/mixed/direct inbounds, socks/ss/vless/trojan/vmess outbounds, Smart DNS + FakeIP + LRU, router and sniffer | **Done** |
| **F2** | Heavy protocols: Hysteria2, TUIC, WireGuard + AmneziaWG, XHTTP, uTLS/REALITY, Naive, Snell, AnyTLS, ShadowTLS | **Done** |
| **F3** | SRS v5 rules and remote list updates | **Done** |
| **F4** | Experimental stack: Clash API (Yacd, secret, WebSocket), `cache.db` (bbolt r/w) | **Done** |
| **F5** | Server side: VLESS, Trojan, VMess, Shadowsocks server inbounds with pure-Rust TLS 1.3 and UDP | **Done** |
| **F6** | TUN subsystem: userspace stack on `smoltcp`, TCP proxy, UDP NAT, routing table 2022 + fwmark, GRO/virtio_net_hdr | **Done** |
| **F7** | lx daemon and metrics: Windows service and `lxd` daemon compatibility, extended telemetry | Planned |
| **F8** | libbox / Android: UniFFI/JNI bindings | Planned |
| **F9** | MIPS spike: `mipsel`/`mips` softfloat musl targets via `-Zbuild-std` | **In progress** (CI builds exist) |
| **F10** | Tachyon integration: autoinstaller, one-click core switch in LuCI | Planned |
| **F11** | **Native configuration system and on-flash data storage** | **December 2026** |
| **F12** | **Drop compatibility with sing-box configs** | **1 January 2027** |

### Transition to a native config format

**December 2026 — native format and our own storage.** Instead of parsing someone else's schema and inheriting its constraints, the core gets its own configuration format designed for router workloads, and its own on-flash state store (`/etc/tachyon/`) in place of scattered files and external paths. Rules, lists, and caches move into one predictable format that drags along neither foreign conventions nor extra dependencies.

**New Year — sing-box config support is removed.** Reading sing-box configs stops being supported. To keep the transition from breaking existing installs, **the automatic migration ships together with F11, before 1 January**: on the first run of the new version, an old-format config is converted once in place, with a backup and a verification step. After that the core reads only its own format, and the dependency on a foreign schema is gone entirely.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 License

**[GPL-3.0-only](LICENSE)**, inherited from sing-box and sing-box-lx. `tachyon-core` is an independent Tachyon community project, not affiliated with SagerNet or Leadaxe. Copyrights on the protocols and sing-box specifications belong to their respective authors.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>