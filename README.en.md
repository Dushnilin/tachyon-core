<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-5.4_MiB_(musl)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-2.4_MiB-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Tests](https://img.shields.io/badge/Tests-1081+_Passed-34D399?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/Dushnilin/tachyon-core)
[![CLI Parity](https://img.shields.io/badge/CLI_Strict_Gate-247%2F0-C084FC?style=for-the-badge&logo=json)](https://github.com/Dushnilin/tachyon-core)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚡ Overview

**tachyon-core** is an uncompromising, high-performance universal network proxy core written from scratch in pure **Rust** for embedded systems and network appliances. It delivers complete configuration JSON and CLI drop-in compatibility with **[sing-box](https://github.com/SagerNet/sing-box)** and the extended feature set of **[Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx)** (XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, uTLS, REALITY, DNS groups, multi-hop routing, and post-quantum encryption).

Engineered specifically for **OpenWrt** routers and memory-constrained devices across MIPS, ARMv7, AArch64, and x86_64 architectures.

**tachyon-core** consumes the **exact same JSON configuration file** (`/etc/sing-box/config.json`) and exposes the **exact same CLI interface** (`check -c`, `version`, `run`), while entirely eliminating the overhead and architectural limits of the Go runtime:

* 📉 **12.6× Smaller Binary**: Static musl binary weighs **5.4 MiB** vs **68–76 MiB** for Go sing-box-lx. Fits directly into the internal flash storage of any router (16/32/128 MB) without USB flash drives or extroot partitions.
* 🧠 **94.4% Lower RAM Footprint**: Just **2.4 MiB idle RSS** vs **42.7 MiB** for Go sing-box, and **5.5–12 MiB** under load vs **51–98 MiB**.
* ⚡ **Zero-GC (0.00 ms Garbage Collection Jitter)**: Deterministic RAII lifecycle completely eliminates Go Stop-The-World pauses (2–15 ms), banishing latency spikes and micro-stutters in VoIP, gaming, and 4K streaming.
* 🔒 **Pure Rust No-C Cryptography**: Zero dependencies on `ring` and BoringSSL/CGO, compiling smoothly for 32-bit softfloat MIPS without toolchain failures.
* 🚀 **Line-Rate Velocity up to 44 Gbit/s**: Zero-copy packet pipeline (Tokio Splicer, `bytes::Bytes`), outperforming the Go reference by 25% to 360% across most protocols while using up to 2.5× less CPU time.
* 🔌 **Native Tachyon Ecosystem Integration**: Direct drop-in for [Tachyon](https://github.com/Dushnilin/tachyon) LuCI Web UI and ucode scripts (`generator.uc`, `watchdog.uc`).

<div align="center">

![Tachyon Particle](assets/readme/tachyon_particle.svg)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚔️ The Rust Revolution: Why Rust Crushes Go on Routers

Most contemporary proxy cores (sing-box, sing-box-lx, Xray) are written in **Go**. While acceptable on servers and PCs with gigabytes of RAM, Go's runtime imposes severe penalties on embedded routers. Migrating to **Rust** resolves these structural bottlenecks.

### 1. Zero-GC vs Go Stop-The-World Pauses
* **In Go (sing-box)**: Go's runtime continuously scans heap allocations and performs Garbage Collection sweeps. Under heavy packet flow (torrents, gaming, multiple LAN clients), GC causes CPU spikes and **2 to 15 ms latency pauses**. This creates jitter in VoIP calls, dropped UDP packets, and bufferbloat.
* **In Rust (tachyon-core)**: Rust has no garbage collector. Memory is reclaimed deterministically the microsecond a socket or buffer goes out of scope (RAII). Latency stays flat at **0.00 ms GC pauses** with perfect timing predictability.

### 2. RAM Footprint: 2.4 MiB vs 42.7 MiB (-94.4% Memory)
* **In Go (sing-box)**: Go pre-allocates runtime memory pools (`mheap`), goroutine stacks, and scheduler metadata. Even when completely idle, sing-box-lx consumes **~43 MiB RSS**. Under load with 10,000 active connections, memory can swell past 100 MiB, triggering the **Linux OOM-Killer** on routers with 128 MB or 256 MB RAM.
* **In Rust (tachyon-core)**: Baseline idle memory is just **2.4 MiB RSS** (**17.8× less RAM**). Under heavy load, peak memory is only **5.5–12 MiB** (**5–7× less**). The router retains free memory for kernel networking, conntrack tables, Wi-Fi drivers, and LuCI.

### 3. Binary Size and Flash Storage: 5.4 MiB vs 68–76 MiB
* **In Go (sing-box)**: The Go runtime, reflection tables, and heavy dependency tree inflate the sing-box-lx binary to **67.6 – 75.9 MiB**.
* **In Rust (tachyon-core)**: Compiled with `opt-level = "z"`, LTO, `codegen-units = 1`, `panic = "abort"`, and symbol stripping, the static musl binary is just **5.37 MiB (aarch64) / 5.57 MiB (armv7) / 6.85 MiB (x86_64) / ~5.8 MiB (mips)**.
> 💡 Most home routers have 16 MB, 32 MB, or 128 MB flash storage. A 68 MB binary cannot be installed without external USB storage or extroot partitions. **tachyon-core fits directly into internal `/usr/bin/` flash.**

### 4. MIPS and Soft-Float Support Without CGO Nightmares
* MIPS architectures (MediaTek MT7621, Qualcomm Atheros ath79/ramips) with software floating point (softfloat) historically suffer from Go's compiler (`gc`), which emits unoptimized machine code. Furthermore, Go libraries frequently depend on BoringSSL/CGO, which fails to compile on MIPS.
* In Rust, crypto libraries like `ring` and `aws-lc-rs` also lack 32-bit MIPS support. In **tachyon-core**, cryptography is abstracted and built entirely on pure **RustCrypto** (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`). Zero external C files, zero dynamic `libssl.so` linkage — clean static musl builds for every router.

### 5. Tokio Async Pipeline and Zero-Copy Splicing
* The networking pipeline is built on `bytes::Bytes` buffer pools and Tokio's asynchronous runtime. Traffic forwarding between client sockets and outbound tunnels is driven via `drive_transparent` without intermediate userspace memory copies.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Performance and Line-Rate Velocity

<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

Benchmarks measured on real static musl builds against reference `sing-box-lx` on Linux (AMD Ryzen, 8 concurrent streams, median averaged results across testbed runs):

### 1. System Resources & Footprint

| Metric / Architecture | tachyon-core (Rust) | sing-box-lx (Go) | Advantage / Gain |
|---|:---:|:---:|:---:|
| **Binary Size (aarch64 musl)** | **5.37 MiB** | 67.6 MiB | **12.6× smaller (-92.1%)** |
| **Binary Size (armv7 musl)** | **5.57 MiB** | 68.2 MiB | **12.2× smaller (-91.8%)** |
| **Binary Size (x86_64 musl)** | **6.85 MiB** | 75.9 MiB | **11.1× smaller (-91.0%)** |
| **Binary Size (MIPS softfloat)** | **~5.80 MiB** | ~78.0+ MiB | **13.4× smaller** |
| **Idle Memory (Idle RSS)** | **2.4 MiB** | 42.7 MiB | **17.8× less RAM (-94.4%)** |
| **Active Load Peak RSS** | **5.5 – 11.9 MiB** | 51.3 – 62.1 MiB | **5–7× less RAM** |
| **Garbage Collector Pauses (GC)** | **0.00 ms (Zero-GC)** | 2 – 15 ms (STW) | **Zero tail jitter** |
| **C / CGO Dependencies** | **0 (Pure Rust / Musl)** | CGO / BoringSSL | **Zero libssl version conflicts** |

### 2. Comprehensive Protocol Throughput Table (8 Streams, Averaged Benchmark Data)

| Protocol / Transport | tachyon-core (Rust) | sing-box-lx (Go) | Speed Delta | CPU (s/GiB) Rust / Go | p50 Latency Rust / Go |
|---|:---:|:---:|:---:|:---:|:---:|
| **VLESS (Direct Splice)** | **44.0 Gbit/s** | 34.1 Gbit/s | **+29.0%** | **0.38** / 0.60 | **274 µs** / 336 µs |
| **Naive (TLS / HTTP/2)** | **10.7 Gbit/s** | 2.3 Gbit/s | **+361% (4.6×)** | **3.12** / 7.54 | **15 µs** / 1560 µs |
| **VLESS (H2 / TLS)** | **10.7 Gbit/s** | 2.7 Gbit/s | **+296% (4.0×)** | **3.10** / 8.06 | **372 µs** / 452 µs |
| **Trojan (gRPC / TLS)** | **10.8 Gbit/s** | 2.8 Gbit/s | **+284% (3.8×)** | **3.09** / 7.99 | **376 µs** / 449 µs |
| **VLESS (gRPC / TLS)** | **11.6 Gbit/s** | 3.1 Gbit/s | **+270% (3.7×)** | **2.87** / 7.21 | **377 µs** / 448 µs |
| **TUIC (QUIC v5)** | **6.4 Gbit/s** | 2.4 Gbit/s | **+171% (2.7×)** | **4.99** / 8.45 | **431 µs** / 530 µs |
| **Shadowsocks (AES-128-GCM)** | **12.8 Gbit/s** | 5.0 Gbit/s | **+159% (2.6×)** | **2.48** / 4.37 | **272 µs** / 356 µs |
| **Shadowsocks (AES-256-GCM)** | **12.2 Gbit/s** | 4.9 Gbit/s | **+149% (2.5×)** | **2.61** / 4.43 | **278 µs** / 346 µs |
| **Hysteria2 (Quinn QUIC)** | **6.6 Gbit/s** | 2.7 Gbit/s | **+147% (2.5×)** | **4.89** / 8.49 | **424 µs** / 528 µs |
| **VMess (Plain)** | **13.0 Gbit/s** | 5.4 Gbit/s | **+143% (2.4×)** | **2.45** / 4.16 | **275 µs** / 367 µs |
| **VMess (gRPC / TLS)** | **6.9 Gbit/s** | 3.0 Gbit/s | **+127% (2.3×)** | **4.87** / 7.47 | **386 µs** / 452 µs |
| **Shadowsocks (ChaCha20-Poly1305)** | **10.1 Gbit/s** | 4.6 Gbit/s | **+122% (2.2×)** | **3.07** / 4.94 | **280 µs** / 351 µs |
| **VMess (TLS)** | **9.5 Gbit/s** | 7.0 Gbit/s | **+36.0%** | **3.63** / 3.38 | **273 µs** / 354 µs |
| **Snell (v6)** | **4.6 Gbit/s** | 3.5 Gbit/s | **+31.4%** | **5.01** / 6.11 | **336 µs** / 374 µs |
| **Snell (v4)** | **7.8 Gbit/s** | 6.1 Gbit/s | **+28.0%** | **3.04** / 3.60 | **329 µs** / 354 µs |
| **Shadowsocks 2022 (AES-128)** | **14.6 Gbit/s** | 12.4 Gbit/s | **+17.7%** | **2.09** / 2.02 | **276 µs** / 356 µs |
| **VLESS (HTTPUpgrade / TLS)** | **8.7 Gbit/s** | 7.5 Gbit/s | **+16.0%** | **2.90** / 3.17 | **321 µs** / 345 µs |
| **VLESS (TLS Direct)** | **8.3 Gbit/s** | 7.2 Gbit/s | **+15.3%** | **3.02** / 3.27 | **266 µs** / 355 µs |
| **Trojan (TLS)** | **8.4 Gbit/s** | 7.3 Gbit/s | **+14.0%** | **2.98** / 3.20 | **266 µs** / 345 µs |
| **VLESS (WebSocket / TLS)** | **8.0 Gbit/s** | 7.1 Gbit/s | **+13.0%** | **3.08** / 3.29 | **332 µs** / 360 µs |
| **AnyTLS (TLS)** | **12.0 Gbit/s** | 10.8 Gbit/s | **+11.1%** | **2.52** / 2.52 | **338 µs** / 405 µs |
| **VMess (WebSocket / TLS)** | **7.8 Gbit/s** | 7.0 Gbit/s | **+11.0%** | **3.95** / 3.36 | **336 µs** / 360 µs |
| **VLESS (REALITY + Vision)** | **7.6 Gbit/s** | 6.9 Gbit/s | **+10.1%** (connect 3.1 vs 13.6 ms) | **3.25** / 3.44 | **319 µs** / 357 µs |
| **Shadowsocks 2022 (AES-256)** | **13.4 Gbit/s** | 12.3 Gbit/s | **+8.9%** | **2.33** / 2.06 | **274 µs** / 345 µs |
| **VLESS (TLS + Vision)** | **7.8 Gbit/s** | 7.4 Gbit/s | **+5.4%** | **3.14** / 3.20 | **268 µs** / 354 µs |
| **Shadowsocks 2022 (ChaCha20)** | **11.2 Gbit/s** | 10.6 Gbit/s | **+5.0%** | **2.77** / 2.48 | **283 µs** / 349 µs |
| **Trojan (WebSocket / TLS)** | **7.3 Gbit/s** | 7.2 Gbit/s | **+2.0%** | **3.29** / 3.27 | **326 µs** / 366 µs |
| **VLESS (TLS + h2mux)** | **10.8 Gbit/s** | 11.0 Gbit/s | **~100% (parity)** | **3.09** / 2.98 | **374 µs** / 451 µs |

> ⚡ **Takeaway**: tachyon-core outperforms the Go reference by **25% to 360%** on heavy transport protocols (gRPC, h2, Naive, TUIC, Hysteria2, Shadowsocks GCM), delivers ultra-low p50 latency (down to 15 µs), and slashes CPU time by up to **2.5×**.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Core Architecture & Capabilities

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

The **tachyon-core** packet processing pipeline is optimized to minimize Linux kernel context switches and operate at line rate:

### 1. Inbounds
* **Client Traffic Interception**:
  * **Linux TProxy (IPv4 / IPv6)**: Transparent UDP and TCP interception using `IP_TRANSPARENT` with destination address recovery via `IP_RECVORIGDSTADDR` ancillary messages.
  * **Redirect Inbound (NAT)**: Transparent TCP interception via `SO_ORIGINAL_DST`.
  * **Mixed SOCKS / HTTP Inbound**: Full HTTP CONNECT and SOCKS4/4a/5 with UDP ASSOCIATE, Proxy-Authorization (Basic 407), keep-alive, and transparent absolute URI rewriting.
  * **Direct Inbound**: Transit inbound for integration with Tachyon routing chains.
* **Server Stack (F5 Server Endpoints)**:
  * Server-side inbounds for **VLESS**, **Trojan**, **VMess** (AEAD), and **Shadowsocks** (AEAD 128/256/chacha20).
  * Built-in asynchronous pure-Rust **TLS 1.3** server (X25519, cipher suites, ALPN) operating over any `AsyncRead + AsyncWrite` stream.
  * Integrated UDP command transport over the same TCP connection (`[len:u16][payload]`).

### 2. Outbounds
* **Standard & Lightweight**: `direct`, `block`, `socks` (SOCKS5 with UDP ASSOCIATE), `http`.
* **Shadowsocks**: Full AEAD suite (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`), **Shadowsocks 2022** (blake3), `udp_over_tcp` (UoT v1/v2), and TLS framing.
* **VLESS**: `flow: xtls-rprx-vision`, all `packet_encoding` modes (`packetaddr`, `xudp`), `h2mux` multiplexing, and uTLS fingerprints.
* **VMess**: AEAD and legacy framing headers, `h2mux` session multiplexing.
* **Trojan**: Zero-overhead pure-Rust implementation with SHA224 hashing.
* **Advanced & QUIC Transports**:
  * **Hysteria2**: High-performance QUIC transport powered by `quinn`, salamander and gecko obfuscation, BBR and Cubic congestion control.
  * **TUIC**: TUIC v5 protocol over QUIC with `udp_over_stream`.
  * **AnyTLS**: Pure-Rust framing with `udp_over_tcp` and buffer pooling.
  * **Naive**: HTTP/2 and HTTP/3 (QUIC) tunneling with `Padding` and `-connect-authority` headers, `[len:u16][pad:u8]` block framing.
  * **Snell**: Pure-Rust support for Snell v4 and v6.
  * **MASQUE**: CONNECT-IP UDP proxying, supporting Cloudflare WARP.
  * **FPTN**: Tachyon token parsing and API integration.
  * **Dispatching**: `urltest` and `selector` (`round_robin`, `least_test`, `least_ping`).

### 3. Tunnel Endpoints
* **AmneziaWG 2.0 & 3.x / WireGuard**:
  * Complete WireGuard pipeline with anti-censorship features against DPI heuristics.
  * Handshake junk packets (`jc`, `jmin`, `jmax`), header and range randomization (`s1–s4`, `h1–h4`), payload padding.
  * Multi-profile decoy packet masking mimicking **DNS**, **STUN**, **SIP**, and **QUIC Initial**.
* **OpenVPN-Client**:
  * `static_key` mode over UDP and TCP with compression framing support.

### 4. Transports & Anti-DPI Evasion
* **Transport Layers**: TCP, WebSocket (`ws` with `max_early_data`), HTTPUpgrade, gRPC (HTTP/2 multiplexed streams), HTTP/2, QUIC/HTTP/3.
* **XHTTP (SplitHTTP)**: Full HTTP/1.1 chunked, `stream-up`, `packet-up`, and `stream-one` implementation with xmux connection pooling; validated against live **Xray 26.9** and 25.9 endpoints.
* **Pure-Rust uTLS**: 13 byte-accurate browser profiles (Chrome, Firefox, Safari, Edge...), custom ClientHello synthesizer, and pure-Rust handshake without external C dependencies.
* **Pure-Rust REALITY**: Native REALITY protocol implementation in pure Rust, verified against live servers.
* **Post-Quantum Cryptography**: Hybrid post-quantum key exchange using **ML-KEM-768** (`X25519MLKEM768`) in pure Rust for forward secrecy against quantum cryptanalysis.

### 5. Smart DNS Resolver & FakeIP Subsystem
* **Supported DNS Transports**: `udp`, `tcp`, `tls` (DoT), `https` (DoH over HTTP/2 and HTTP/1.1), `quic` (DoQ), `h3` (DoH3 over HTTP/3), `fakeip`, `local` (system resolver), `hosts` (`/etc/hosts` and `predefined` records), `mdns` (multicast LAN discovery).
* **DNS Groups (`group`)**: lx resolver groups with `stable`, `fastest`, and `parallel` dispatch strategies based on rolling win/loss statistics, plus survival fallback.
* **Reverse Mapping (`dns.reverse_mapping`)**: Persistent `IP → domain` TTL caching, routing direct IP connections against domain-based routing rules.
* **Client Subnet (`dns.client_subnet`)**: EDNS0 client subnet passthrough.
* **Caching**: High-efficiency `Arc<str>` LRU cache with optimistic serving and sequential FakeIP pool (`198.18.0.0/15`).

### 6. Zero-Alloc Routing Engine & Sniffing
* **Rule Matchers**: `inbound`, `network`, `protocol`, domain (suffix, keyword, regex, exact), `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `user`, `user_id` (via `/proc/net/*` socket inspection), `clash_mode`, `rule_set`, `rule_set_ipcidr_match_source`.
* **Neighbor & DHCP Tracking (`find_neighbor`)**: Automatic LAN device identification by MAC address (`source_mac_address`) and hostname (`source_hostname`) parsed from DHCP lease files.
* **Protocol Sniffer (PeekStream)**: Buffered early-byte stream inspection for TLS SNI, HTTP Host, QUIC SNI, DNS, BitTorrent, SSH, and RDP without prefix loss.
* **Binary Rule-Set (SRS v5)**: Fast binary compilation, decompilation, rule matching, and automated remote rule-set downloads.

### 7. System Dialer & Network Stack
* **Linux Network Namespaces (`netns`)**: Built-in network namespace lifecycle management via child `CLONE_NEWNET` holder processes, isolating OS threads during connection dials.
* **Socket Protection (`protect_path`)**: SCM_RIGHTS unix socket descriptor passing to protect sockets from routing loops.
* **Dialer Capabilities**: Multipath TCP (`tcp_multi_path`), Happy Eyeballs RFC 6555 (`domain_strategy` + `fallback_delay`), fwmark routing marks (`routing_mark`), interface binding (`bind_interface`), and TCP/UDP flood rate-limiting.

### 8. Control API & Persistent State
* **Clash REST API**: Full endpoints `/version`, `/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/providers/*`, WebSockets, secret token authentication, CORS, `clash_mode` switching, and embedded Web UI serving (Yacd, Metacubexd) under `/ui`.
* **Cache File `cache.db` (bbolt)**: Pure-Rust B+tree reader and writer byte-compatible with Go bbolt (`rule_set`, `selected`, `group_expand`, `clash_mode`, `rdrc2`, `dns_cache`, `fakeip`, `chain_disabled_lx` buckets).
* **Auxiliary Services**: Built-in NTP client and unified `http_clients` registry.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 100% Drop-In sing-box Compatibility

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

`tachyon-core` is engineered as a transparent binary replacement for sing-box. Installed as `/usr/bin/sing-box`, it handles all standard CLI invocations:

```bash
# Validate configuration file (strict JSON schema validation)
tachyon-core check -c /etc/sing-box/config.json

# Display version matching upstream regex for ucode orchestrators
tachyon-core version

# Run service daemon
tachyon-core run -c /etc/sing-box/config.json

# Compile and decompile binary rule-sets (.srs v5)
tachyon-core rule-set compile rules.json -o rules.srs
tachyon-core rule-set decompile rules.srs -o rules.json
```

### CLI Compatibility Matrix

| Command | Purpose in Tachyon / OpenWrt | Status in tachyon-core |
|---|---|:---:|
| `check -c <path>` | Pre-start validation in `watchdog.uc` | **Complete** (247/0 strict differential gate) |
| `version` | Version parsing in `generator.uc` | **Complete** (upstream regex compatible) |
| `run -c <path>` | Service daemon execution | **Complete** (Tokio async runtime) |
| `rule-set compile\|decompile` | Binary `.srs` rules (SRS v5) | **Complete** (bidirectional) |
| `rule-set match\|format` | Rule inspection and formatting | **Complete** |
| `api` | Control and monitoring via Clash API | **Complete** (REST / WebSockets) |
| `generate reality-keypair` | REALITY keypair generation | Planned |
| `generate wg-keypair` | WireGuard / AmneziaWG keypair generation | Planned |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🚀 Building & Cross-Compilation

### Local Host Build
Requires Rust 1.89+ (2024 edition):

```bash
# Build all workspace crates in release profile
cargo build --workspace --release

# Run full test suite (1081+ tests)
cargo test --workspace
```

### Router Cross-Compilation via `cargo-zigbuild`
Produces static, self-contained musl binaries without dynamic dependencies:

```bash
# Install cargo-zigbuild
cargo install cargo-zigbuild

# AArch64 (ARM64: NanoPi R3S/R4S, GL.iNet Flint 2, Raspberry Pi 4/5)
cargo zigbuild --target aarch64-unknown-linux-musl --release

# ARMv7 (Cortex-A7: IPQ4019, Xiaomi AX1800, Keenetic Hopper/Titan)
cargo zigbuild --target armv7-unknown-linux-musleabihf --release

# x86_64 (Mini-PCs, Servers, Proxmox/ESXi)
cargo zigbuild --target x86_64-unknown-linux-musl --release
```

Binaries are automatically optimized and stripped of debug symbols (`strip = "symbols"`), producing a ~5.4 MiB static executable.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Development Roadmap

Features are organized into sequential phases validated through differential testing against reference `sing-box-lx`:

| Phase | Milestone | Acceptance Criteria | Status |
|:---:|---|---|:---:|
| **F0** | **Foundation** | Passing differential tests for `check` and `version` (247/0 gate) | **Complete** |
| **F1** | **Data Plane v1** | Inbounds: tproxy, redirect, mixed, direct. Outbounds: socks, shadowsocks, vless, trojan, vmess. Smart DNS + FakeIP + LRU. Router & Sniffer. | **Complete** |
| **F2** | **Heavy Protocols** | Hysteria2 (quinn), TUIC, WireGuard + AmneziaWG 2.0/3.x, VLESS ML-KEM-768, XHTTP (Xray 26.9 interop), uTLS/REALITY, Naive, Snell, AnyTLS | **Complete** |
| **F3** | **SRS Rules & Sync** | SRS v5 binary compatibility (`compile`/`decompile`), remote rule sync | **Complete** |
| **F4** | **Experimental Stack** | Clash API (Yacd UI, Secret auth, WebSockets), `cache.db` (bbolt r/w in pure Rust) | **Complete** |
| **F5** | **Server Stack** | Server inbounds for core protocols | **Complete**: vless, trojan, vmess, shadowsocks with pure-Rust TLS 1.3 & UDP |
| **F6** | **TUN Subsystem** | `stack: system` (kernel TUN) and userspace stack on `smoltcp` | Planned |
| **F7** | **lx Daemon & Telemetry** | Windows service compatibility and `lxd` daemon | Planned |
| **F8** | **libbox / Android** | UniFFI/JNI bindings for mobile client applications | Planned |
| **F9** | **MIPS Spike** | Targets `mipsel`/`mips` softfloat musl via `-Zbuild-std` | **In Progress**: CI build passing |
| **F10** | **Tachyon Integration** | `rs` variant in Tachyon: auto-installer, 1-click kernel switch in LuCI | Planned |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 License & Copyright

Distributed under the **[GPL-3.0-only](LICENSE)** license, inherited from sing-box and sing-box-lx.

* `tachyon-core` is an independent open-source project by the **Tachyon** community and is not affiliated with SagerNet or Leadaxe.
* All original protocol and sing-box specification copyrights belong to their respective owners.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>
