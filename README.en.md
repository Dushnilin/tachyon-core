<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Release](https://img.shields.io/github/v/release/Dushnilin/tachyon-core?style=for-the-badge&color=C084FC&logo=github)](https://github.com/Dushnilin/tachyon-core/releases/latest)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-6.9_--_10.2_MiB_(3.7_MiB_tar.gz)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core/releases/latest)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-4.2_MiB_idle-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-36%2F39_Wins-10B981?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
[![Interactive Report](https://img.shields.io/badge/Dashboard-HTML_Report-6366F1?style=for-the-badge&logo=html5&logoColor=white)](BENCHMARK.html)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-Proprietary-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md) | [**📦 Download Builds (Releases)**](https://github.com/Dushnilin/tachyon-core/releases/latest) | [**📊 Latest Benchmark**](BENCHMARK.md) | [**🌐 Interactive HTML**](BENCHMARK.html)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

> [!IMPORTANT]
> **📦 Release Distribution Model Starting with `v0.1.3` (Builds-Only Releases)**
>
> The source tree in this public repository (`Dushnilin/tachyon-core`) is **frozen at the historical `v0.1.2` snapshot**.
> Starting with version **`v0.1.3`**, all new source code development takes place in a private repository, and only **prebuilt release binaries (static builds across 11 target architectures), `SHA256SUMS` checksums, documentation, changelogs, and benchmark reports** are automatically pulled and published here via GitHub Actions.

## ⚡ Overview

**tachyon-core** is an independent, high-performance network routing and tunneling core for routers, servers, and embedded systems, written from scratch in 100% pure **Rust** with zero Go or C/C++ code. It supports standard JSON configuration schemas and CLI subcommands (`check -c` / `version` / `run` / `generate` / `rule-set`) for drop-in operation in existing OpenWrt environments without the Go runtime or garbage collector.

It implements a complete stack of modern networking and transport protocols: XHTTP (`H2Pool` + `HTTP/1.1`), AmneziaWG 2.0/3.x (with multi-worker `WgPool`, extended `H1–H4` headers, and `I1–I5` framing), MASQUE/WARP (RFC 9484), Mieru (TCP/UDP), Hysteria2, TUIC v5, AnyTLS, Naive, ShadowTLS v3, uTLS (13 TLS ClientHello profiles), REALITY (with X.509v1 certificate and key pinning support), DNS groups, post-quantum `X25519MLKEM768` key exchange, native Tailscale, zero-copy mmap rule-sets, and the **Adaptive Hardware Engine (`HardwareProfile`)**, which dynamically tunes worker threads, QUIC/TCP windows, and socket buffers to match your router's RAM tier and real-time memory pressure.

All benchmark numbers come from real static musl builds measured against Go cores (`Xray-core`, `Mihomo`, `sing-box`) and the modular C stack `steer`, in a single-core router profile (1 worker, CPU pinning). Full results across all 39 protocols: **[BENCHMARK.md](BENCHMARK.md)** and **[BENCHMARK.html](BENCHMARK.html)**.

**Averages across all target architectures:**

| | tachyon-core | Go network cores | Advantage |
|---|:---:|:---:|:---:|
| **Binary size** | **6.9–10.2 MiB** (3.2–4.2 MiB in `.tar.gz`) | 35–76 MiB | **~8–10× smaller** |
| **Idle RAM** | **4.2 MiB** | 25–41 MiB | **~10× less** |
| **RAM under load** | **~10 MiB** | 48–85 MiB | **~6× less** |
| **GC pauses** | **0.00 ms** | 2–15 ms | **no jitter at all** |
| **Cold start** | **22 ms** | 160–270 ms | **7–12× faster** |
| **Adaptive profile** | **4 RAM tiers + 3 pressure levels** | fixed buffers | **auto-tuned from 64 MB to 8+ GB** |
| **C / CGO dependencies** | **0** | CGO / BoringSSL | **builds on any MIPS / ARMv6** |

> **Direct advantage #1 — memory.** ~10× less at idle on a 64–128 MB router is the difference between "OOM-killer at the worst possible moment" and having headroom for conntrack, Wi-Fi, and LuCI.
>
> **Direct advantage #2 — flash.** 6.9–10.2 MiB unpacked (3.2–4.2 MiB in `.tar.gz`) against 35–76 MiB: the core installs straight into the internal `/usr/bin/` flash of a 16/32/128 MB router, with no USB drive and no extroot.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚔️ Why Rust and Not Go

| | Go network cores | tachyon-core (Rust) |
|---|---|---|
| **Garbage collector** | Continuous heap scans plus Stop-The-World phases: CPU spikes and **2–15 ms pauses** on weak router CPUs. Audible as micro-stutter in VoIP and ping spikes in games | No collector at all. RAII reclaims memory deterministically, the instant a socket goes out of scope. **0.00 ms pauses**, flat latency graph |
| **Scheduler and pools** | Internal thread pools, goroutine stacks, `mheap` reservations: 25–41 MiB when fully idle, past 100 MiB at 10k connections, then OOM-Killer | Nothing is pre-reserved. 4.2 MiB idle, ~10 MiB peak, plus live `/proc/meminfo` pressure monitoring that shrinks caches and buffers automatically |
| **Crypto on MIPS** | BoringSSL/CGO breaks builds on 32-bit softfloat MIPS (MediaTek MT7621, ath79), and `gc` emits unoptimized code | Pure-Rust crypto provider throughout (`oxitls` + `AF_ALG`, `aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`) with hardware NEON/AES-NI acceleration. Zero external C files, no `libssl.so` linkage |
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
| **tachyon-core** | **6.99–10.2 MiB** | **22.3 ms** 🥇 | **4.2 / 4.6 MiB** 🥇 | **170.0 / 221.4 µs** 🥇 | **51.7 Gbps** | 0.163 s/G |
| `steer` (C, 3 procs) | 1.76 MiB | 141.9 ms | 5.1 / 5.4 MiB | 173.6 / 221.7 µs | 8.0–9.6 Gbps | 1.067 s/G |
| `xray-core` (Go, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 / 233.4 µs | 53.1 Gbps | 0.158 s/G |
| `mihomo` (Go, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 / 251.3 µs | 48.2 Gbps | 0.174 s/G |
| `sing-box` (Go) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 / 232.8 µs | 51.5 Gbps | 0.166 s/G |

> **Direct advantage #3 — cold start.** 22 ms against ~210 ms: on a router, where the service comes up on every reboot or network restart, that is the difference between "working" and "a minute of waiting".
>
> On pure loopback throughput `xray-core` edged ahead (53.1 vs 51.7 Gbps), which is within noise. The real tachyon advantage here is not gigabytes per second but memory, start-up, and latency: **the lowest p50 and p99 of all five cores** at 4.2 MiB instead of 25–41 MiB.

### Multi-protocol benchmark (2026-10-14 run)

**36 wins out of 39 protocols (39/39 `OK`), 3 ties, 0 losses.** Throughput (1 stream / 8 streams), Gbit/s:

| Protocol | Tachyon | Sing-box | Xray | Mihomo | Steer | Advantage |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Shadowsocks AES-128-GCM** | **6.95 / 16.60** | 2.59 / 4.79 | 5.71 / 11.17 | 2.49 / 5.03 | 0.01 / 0.11 | **~3.5×** |
| **AnyTLS (H2MUX TLS)** | **6.16 / 14.86** | 5.52 / 10.95 | — | — | — | **~1.4×** |
| **Mieru (TCP / UDP)** | **6.46 / 13.01** | — | — | 5.20 / 5.71 | — | **~2.3×** (client + server) |
| **VMess + HTTP/2 + TLS** | **2.48 / 11.31** | 1.58 / 2.09 | — | 1.21 / 3.06 | — | **~5.4×** |
| **VLESS + HTTP/2 + TLS** | **2.38 / 10.51** | 1.45 / 2.04 | — | 1.46 / 7.52 | — | **~5.2×** |
| **NaiveProxy (HTTP/2 TLS)** | **2.80 / 10.47** | 2.49 / 2.41 | — | — | — | **~4.3×** |
| **Trojan + gRPC + TLS** | **2.80 / 10.45** | 1.40 / 1.92 | 1.55 / 2.47 | 1.45 / 2.23 | 1.63 / 2.09 | **~5.4×** |
| **VLESS + gRPC + TLS** | **2.78 / 9.99** | 1.74 / 2.22 | 1.68 / 2.62 | 1.54 / 2.06 | 1.75 / 2.16 | **~4.5×** |
| **VLESS + XHTTP + TLS** | **1.36 / 9.33** | 1.08 / 9.14 | 0.99 / 2.38 | — | 1.21 / 1.57 | **~73× lower p50** (`408 µs`) |
| **VMess + WS + TLS** | **3.47 / 7.87** | 3.18 / 6.55 | 2.07 / 4.28 | 2.16 / 4.45 | 2.85 / 2.91 | **~1.2–1.8×** |
| **TUIC v5 (QUIC)** | **4.03 / 7.64** | 3.52 / 2.76 | — | 3.08 / 2.72 | — | **~2.8×** |
| **Hysteria 2 (QUIC)** | **3.30 / 6.84** | 2.59 / 3.21 | — | 3.19 / 3.88 | 1.22 / 0.55 | **~2.1×** |
| **VLESS + TLS + Vision** | **3.23 / 7.22** | 3.31 / 6.78 | 2.26 / 5.63 | 3.24 / 6.98 | 3.91 / 4.36 | **8s leader** (`7.1M` RSS) |
| **ShadowTLS v3** | **48.47 / 45.53** | — | — | — | — | **zero-copy splice** (`5.8M` RSS) |
| **VLESS (Plain)** | **25.31 / 30.97** | 25.25 / 30.89 | 8.66 / 16.90 | — | 4.24 / 5.27 | **leader** (`5.4M` vs `42.4M` RSS) |

> **Direct advantage #4 — HTTP/2, gRPC, and QUIC.** On multiplexed transports (`HTTP/2`, `gRPC`, `NaiveProxy`, `Hysteria2`, `TUIC v5`), throughput is **2.1–5.4× higher** at a fraction of the peak RSS (7–22 MiB on QUIC/TLS vs 48–55 MiB on Go cores).
>
> **Direct advantage #5 — XHTTP.** The built-in `H2Pool` (XMUX) connection pool eliminates repeated TLS handshakes per request in `packet-up` and `stream-up` modes. Time to first byte: **408 µs against ~29,800 µs** on Go cores — **~73× faster**, reaching **9.33 Gbit/s** across 8 streams.
>
> Full 39-protocol breakdown with p50/p99 latency and peak RSS: **[BENCHMARK.md](BENCHMARK.md)** and **[BENCHMARK.html](BENCHMARK.html)**.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Core Capabilities

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

**Inbounds (client & server).** Transparent interception: Linux **TProxy** (IPv4/IPv6) via `IP_TRANSPARENT` with the real destination recovered from OOB `IP_RECVORIGDSTADDR`; **Redirect** (NAT) via `SO_ORIGINAL_DST`; **Mixed SOCKS/HTTP** with full CONNECT, SOCKS4/4a/5, UDP ASSOCIATE, 407, and keep-alive; **Direct**; **TUN** (`/dev/net/tun`, userspace TCP stack on `smoltcp` with adaptive `TACHYON_SMOL_TCP_BUF` window, GSO segmentation, policy routing in a separate table 2022). Full server stack (**12 protocols**): **VLESS**, **Trojan**, **VMess** (AEAD), **Shadowsocks** (AEAD, 2022, multi-user relay), **AnyTLS**, **Naive**, **Hysteria2** (full hy2 client compatibility, `Hysteria-CC-RX`/`Hysteria-Padding` headers, UDP sessions), **TUIC v5**, **ShadowTLS v3**, **MASQUE** (RFC 9484 CONNECT-IP over HTTP/3), **Mieru** (TCP/UDP), **AmneziaWG / WireGuard** responder, and **FPTN** — backed by a pure-Rust TLS 1.3 implementation.

Full field reference — **[docs/reference/](docs/reference/README.md)**: every inbound and outbound type, the shared option blocks (listen, dialer, TLS, transports, multiplex), defaults and limitations.

**Outbounds.** `direct`, `block`, `socks`, `http`. **Shadowsocks** (all AEAD ciphers, 2022 specification, UoT, TLS transport). **VLESS** (`flow: xtls-rprx-vision`, all `packet_encoding`, `h2mux`, uTLS). **VMess** (AEAD and legacy, `h2mux`). **Trojan** (SHA224). **Hysteria2** (`quinn` engine, BBR and Cubic congestion control, `routing_mark`/`bind_interface`). **TUIC v5** (with automatic stale UDP session eviction). **AnyTLS**. **Naive** (HTTP/2 and HTTP/3, `Padding`, `-connect-authority`, `[len:u16][pad:u8]` framing). **Snell v4/v6**. **ShadowTLS v3**. **MASQUE (WARP)**. **Mieru** (TCP and UDP). **FPTN**. **Tor**, **SSH**, **Desync** (TCP stream segmentation), **Chain** (`detour` chains). Dispatch: `urltest` and `selector` (`round_robin`, `least_test`, `least_ping`).

**Tunnel endpoints.** **AmneziaWG 2.0/3.x** and **WireGuard** — lock-free multi-worker `WgPool` with 5-tuple flow hashing, extended session header parameters (`jc`, `jmin`, `jmax`, `s1–s4`, `h1–h4`), and `i1–i5` handshake framing generators. **Tailscale** (`tsnet` endpoint). **OpenVPN client**: `static_key` over UDP and TCP, with compression and fragmentation.

**Transport layer and cryptography.** TCP, WebSocket (`max_early_data`), HTTPUpgrade, gRPC, HTTP/2, QUIC/HTTP-3. **XHTTP**: HTTP/1.1 chunked, `stream-up`, `packet-up`, `stream-one`, plus the `H2Pool` (XMUX) connection pool with HTTP/2 stream multiplexing, least-loaded balancing, and extended stream windows (16 MiB stream / 64 MiB connection). **Pure-Rust uTLS**: 13 byte-exact TLS ClientHello profiles and custom handshake templates. **Pure-Rust REALITY** with end-to-end `splice`, X.509v1 certificate support, and `PinVerifier`. **Post-quantum cryptography**: hybrid ML-KEM-768 key exchange (`X25519MLKEM768`).

**Adaptive Hardware Engine (`HardwareProfile`).** At startup the core detects total RAM and CPU cores, selecting one of 4 hardware profiles (`Constrained ≤128 MB`, `Router 129–512 MB`, `Midrange 513–2048 MB`, `DesktopServer >2048 MB`), while monitoring `/proc/meminfo` (`MemAvailable`) and `cgroup` limits. Tokio worker threads, `splice` and TCP/UDP relay buffers, HTTP/2 and QUIC stream/connection windows (`Hysteria2`, `TUIC`, `MASQUE`), UDP NAT session caps, DNS cache capacity, and `smoltcp` buffers scale automatically in real time.

**Smart DNS.** `udp`, `tcp`, `tls` (DoT), `https` (DoH), `quic` (DoQ), `h3` (DoH3), `fakeip`, `local`, `hosts` (file and inline), `mdns`. DNS `group` resolvers with `stable` / `fastest` / `parallel` strategies over rolling win/error statistics and a survival fallback. `dns.reverse_mapping` for applying domain rules to direct IP hits. `dns.client_subnet` (EDNS0). `Arc<str>` LRU cache with optimistic serving of stale entries and a FakeIP pool on `198.18.0.0/15`.

**Routing and inspection.** Rule matchers: `inbound`, `network`, `protocol`, domain (suffix, keyword, regex, exact), `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `user`, `user_id` (via `/proc/net/*` and socket descriptors), `clash_mode`, `rule_set`, `rule_set_ipcidr_match_source`. Neighbour table and DHCP leases (`find_neighbor`) for `source_mac_address` and `source_hostname`. PeekStream sniffer: TLS SNI, HTTP Host, QUIC SNI, DNS, BitTorrent, SSH, RDP — without losing leading bytes. Binary SRS v5 rules: compile, decompile, match, and remote list sync.

**System dialer.** Netns with a `CLONE_NEWNET` holder child process and conflict-free dialing. `protect_path` passes socket descriptors to daemons over `SCM_RIGHTS`. Multipath TCP, Happy Eyeballs RFC 6555, fwmark (`routing_mark`), interface binding (`bind_interface`), non-blocking `connect` with explicit timeouts, and protection against packet storms on connection reset.

**API and state.** Clash REST API: `/version`, `/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/providers/*`, URL-encoded slash (`%2F`) support in proxy and group names, WebSocket traffic, secret token, CORS, `clash_mode`, and built-in Yacd / Metacubexd panels under `/ui`. `cache.db` is a pure-Rust B+tree, byte-compatible with the bbolt format. Built-in NTP client and the `http_clients` registry.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 Command-Line Interface (CLI) & Compatibility

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

```bash
tachyon-core check -c /etc/sing-box/config.json                    # configuration validation
tachyon-core version                                              # print core version
tachyon-core run -c /etc/sing-box/config.json                     # start service
tachyon-core rule-set compile rules.json -o rules.srs            # compile SRS v5 rules
tachyon-core generate reality-keypair                             # generate X25519 keypair for REALITY
tachyon-core generate wg-keypair                                  # generate WireGuard / AmneziaWG keypair
tachyon-core generate tls-keypair example.com -m 12               # self-signed ECDSA P-256 TLS cert/key (PEM)
```

| Command | Purpose | Status |
|---|---|:---:|
| `check -c <path>` | Pre-start config validation in `watchdog.uc` | **Done** |
| `version` | Version detection in `generator.uc` | **Done** |
| `run -c <path>` | Service process start | **Done** |
| `format -c <path>` / `merge` | JSON configuration formatting and merging | **Done** |
| `rule-set compile\|decompile\|upgrade` | Binary `.srs` rules (SRS v5) and remote list upgrade | **Done** |
| `rule-set match\|format` | Rule matching and formatting | **Done** |
| `api` | Control and monitoring via Clash API | **Done** |
| `generate reality-keypair` | X25519 keypair for REALITY | **Done** |
| `generate wg-keypair` | WireGuard / AmneziaWG keypair | **Done** |
| `generate tls-keypair <sni> [-m <months>]` | Pure-Rust self-signed ECDSA P-256 TLS certificate and key | **Done** |
| `generate uuid` / `generate rand` | UUID v4 and random key generator (`--hex` / `--base64`) | **Done** |
| `tools synech` / `tools fptn-decode` | ECH ConfigList generator and FPTN token decoder | **Done** |

> Backward compatibility with legacy JSON config files is a **temporary migration aid** — see the roadmap below.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📦 Release Builds & Installation

> [!NOTE]
> **Builds-Only Distribution from `v0.1.3`:** this public repository is the official binary release distribution channel for `tachyon-core`. Source code is maintained and built in a private repository and automatically published here via GitHub Actions together with `SHA256SUMS`.

Prebuilt static binaries with zero external dependencies (`musl`, `strip = "symbols"`) are published on the **[Releases](https://github.com/Dushnilin/tachyon-core/releases/latest)** page for all router and server platforms:

| Architecture (Asset) | Target Triple | Target Hardware | Archive Size |
|---|---|---|:---:|
| **`aarch64`** | `aarch64-unknown-linux-musl` | MediaTek Filogic 820/830/880, Flint 2, NanoPi R3S/R4S/R6S, IPQ807x/60xx/50xx, RPi 4/5 | **~3.7 MiB** |
| **`armv7`** | `armv7-unknown-linux-musleabihf` | Qualcomm IPQ4019, MediaTek MT7622/MT7623, Marvell Armada 385, Keenetic Hopper/Peak | **~3.8 MiB** |
| **`armv6`** | `arm-unknown-linux-musleabi` | Raspberry Pi Zero / 1, Broadcom BCM2835 | **~3.9 MiB** |
| **`mipsel`** | `mipsel-unknown-linux-musl` (`+soft-float`) | MediaTek MT7621, MT7628, Ralink RT305x/RT5350, Keenetic Extra/Viva/Giga/Speedster | **~4.2 MiB** |
| **`mips`** | `mips-unknown-linux-musl` (`+soft-float`) | Qualcomm Atheros AR71xx / AR934x / QCA95xx (`ath79` Big-Endian) | **~4.2 MiB** |
| **`riscv64`** | `riscv64gc-unknown-linux-musl` | StarFive VisionFive 2, Milk-V, SiFive | **~3.9 MiB** |
| **`x86_64` / `linux-amd64`** | `x86_64-unknown-linux-musl` | Mini-PCs (Intel N100/N5105), Proxmox, x86 OpenWrt, VPS and dedicated servers | **~3.9 MiB** |
| **`windows-amd64`** | `x86_64-pc-windows-msvc` | Windows x64 desktops and servers | **~3.4 MiB** |
| **`darwin-arm64` / `amd64`** | `aarch64` / `x86_64-apple-darwin` | macOS (Apple Silicon M1–M4 and Intel) | **~3.2–3.5 MiB** |

Quick install or upgrade on an OpenWrt router (or Linux server):

```bash
# Example for ARM64 (aarch64): download, unpack, and install
ARCH="aarch64"
VER="v0.1.3"
wget -O /tmp/tachyon-core.tar.gz "https://github.com/Dushnilin/tachyon-core/releases/download/${VER}/tachyon-core-${ARCH}-${VER}.tar.gz"
tar -xzf /tmp/tachyon-core.tar.gz -C /usr/bin/
mv -f "/usr/bin/tachyon-core-${ARCH}-${VER}" /usr/bin/tachyon-core
chmod +x /usr/bin/tachyon-core
/usr/bin/tachyon-core version
```

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Roadmap

| Phase | Area | Status |
|:---:|---|:---:|
| **F0** | Foundation: configuration schema validator `check` and `version` CLI (247/0 corpus tests) | **Done** |
| **F1** | Data plane v1: tproxy/redirect/mixed/direct inbounds, socks/ss/vless/trojan/vmess outbounds, Smart DNS + FakeIP + LRU, router and sniffer | **Done** |
| **F2** | Transport protocols: Hysteria2, TUIC, WireGuard + AmneziaWG, XHTTP, uTLS/REALITY, Naive, Snell, AnyTLS, ShadowTLS | **Done** |
| **F3** | SRS v5 rules and remote list updates | **Done** |
| **F4** | Experimental stack: Clash API (Yacd, secret, WebSocket), `cache.db` (bbolt r/w) | **Done** |
| **F5** | Server side: all 12 server inbounds (VLESS, Trojan, VMess, SS, Hy2, TUIC, AnyTLS, Naive, ShadowTLS, MASQUE, Mieru, AWG) with pure-Rust TLS 1.3 and UDP | **Done** |
| **F6** | TUN subsystem: userspace stack on `smoltcp`, TCP proxy, UDP NAT, routing table 2022 + fwmark, GRO/virtio_net_hdr | **Done** |
| **F7** | System daemon and metrics: Windows service and daemon compatibility, extended telemetry | Planned |
| **F8** | Mobile bindings: UniFFI/JNI bindings | Planned |
| **F9** | MIPS softfloat musl: static `mipsel` and `mips` (`+soft-float`) builds via `-Zbuild-std` | **Done** |
| **F10** | Tachyon integration + adaptive `HardwareProfile` engine (4 RAM tiers, 3 pressure levels) and transition to builds-only public distribution (`v0.1.3+`) | **Done** |
| **F11** | **Native configuration system and on-flash data storage** | **December 2026** |
| **F12** | **Complete transition to native Tachyon configuration format** | **1 January 2027** |

### Transition to a native config format

**December 2026 — native format and our own storage.** The core gets its own configuration format designed specifically for router workloads, and its own on-flash state store (`/etc/tachyon/`) in place of scattered files and external paths. Rules, lists, and caches move into one predictable compact format.

**1 January 2027 — migration completed.** To keep the transition from breaking existing installs, **the automatic migration ships together with F11, before 1 January**: on the first run of the new version, an existing config is converted once in place, with a backup and a verification step. After that the core operates exclusively on its native format.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 License

Starting with version **`v0.1.3`**, **tachyon-core** is distributed as prebuilt executable binaries under the proprietary **[TACHYON CORE BINARY LICENSE v1.0](LICENSE)** (`Copyright (c) 2026 Dushnilin. All rights reserved.`).

- You are granted a free license to download, install, and run unmodified official release binaries for personal non-commercial use and internal network infrastructure operations.
- **Redistribution, repackaging, bundling into third-party firmware or packages, commercial use, sale, reverse engineering, modification, creation of derivative works, or removal of copyright notices is strictly prohibited** without prior written permission from the copyright holder.
- Historical releases up to and including `v0.1.2` remain governed by the GPL-3.0-only license under which they were originally published.

## ⚖️ Legal Notice & Disclaimer

1. **Purpose of the Software.** `tachyon-core` is a general-purpose technical networking utility designed for network traffic routing, load balancing, network diagnostics, information security, and establishing secure corporate or personal communication channels (VPN).
2. **Compliance with Applicable Laws.** The Software was **not created, is not intended, and is not distributed** for the purpose of violating the laws of the Russian Federation (including Federal Law No. 149-FZ) or any other jurisdiction, nor for obtaining unauthorized access to restricted information resources.
3. **Use at Your Own Risk.** The author and copyright holder do not provide any proxy/VPN servers, network nodes, subscriptions, access keys, or routing lists. The Software is provided `"AS IS"` without warranty of any kind. Any installation, configuration, and operation of the Software is performed by the user strictly on their own initiative, **at their own risk**, and under their sole responsibility. The copyright holder assumes no liability for user actions, configurations, or any consequences arising from the use of the Software.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>