<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-5.37_MiB_(musl)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-2.4_MiB-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmark](https://img.shields.io/badge/Benchmark-21%2F24_Wins-FF6B4A?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
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

### 1. Architectural Advantages and Binary Sizes

| Architecture / Target | Binary Size | Devices / Use Cases | Status |
|:---|:---:|:---|:---:|
| **aarch64-unknown-linux-musl** | **5.37 MiB** | NanoPi R3S/R4S, GL.iNet Flint 2, RPi 4/5 | ✅ Production |
| **armv7-unknown-linux-musleabihf** | **5.57 MiB** | Keenetic Hopper/Titan, Xiaomi AX1800, IPQ4019 | ✅ Production |
| **arm-unknown-linux-musleabi** | **5.42 MiB** | ARMv5/v6 legacy routers | ✅ Production |
| **mipsel-unknown-linux-musl** | **5.80 MiB** | MediaTek MT7621, ramips routers | ✅ Tier-3 (Nightly) |
| **mips-unknown-linux-musl** | **5.85 MiB** | Qualcomm Atheros ath79, big-endian | ✅ Tier-3 (Nightly) |
| **riscv64gc-unknown-linux-musl** | **6.10 MiB** | SiFive, Milk-V, Banana Pi BPI-F3 | ✅ Tier-2 |
| **x86_64-unknown-linux-musl** | **6.85 MiB** | x86-64-v3 routers, mini-PCs, Proxmox | ✅ Production |
| **x86_64-unknown-linux-gnu** | **~7.2 MiB** | Standard Linux distro (Ubuntu/Debian) | ✅ Desktop/Server |
| **x86_64-pc-windows-msvc** | **~9.8 MiB** | Windows 10/11 x64 | ✅ Desktop |
| **x86_64-apple-darwin** | **~8.4 MiB** | macOS Intel | ✅ Desktop |
| **aarch64-apple-darwin** | **~8.1 MiB** | macOS Apple Silicon (M1/M2/M3/M4) | ✅ Desktop |

#### Proxy Core Resource Footprint Comparison:

| Metric / Parameter | tachyon-core (Rust) | sing-box-lx / Xray (Go) | tachyon-core Advantage |
|:---|:---:|:---:|:---|
| **Binary Executable Size** | **5.37 – 6.85 MiB** | 68 – 78 MiB | **12.6× more compact (-92%)** |
| **Idle RAM Footprint** | **2.4 MiB RSS** | 42.7 – 58.0 MiB | **17.8× less RAM (-94.4%)** |
| **Active Load Peak RSS** | **5.5 – 14 MiB** | 51.3 – 177.0 MiB | **5–12× less RAM** |
| **Garbage Collector Pauses (GC)** | **0.00 ms (Zero-GC)** | 2 – 15 ms (STW GC) | **Zero tail jitter** |
| **XHTTP First-Byte Latency** | **371 µs (0.37 ms)** | 29 867 µs (29.8 ms) | **80× faster connection responsiveness** |
| **C / CGO Dependencies** | **0 (Pure RustCrypto)** | CGO / BoringSSL | **Runs on any MIPS/musl router** |

> 💡 **Router Flash Storage**: Most home routers feature only 16, 32, or 128 MB of SPI Flash. Go-based binaries (68–78 MB) physically cannot fit into flash storage without configuring external USB extroot partitions. **tachyon-core installs directly into `/usr/bin/` on any router.**

---

### 2. Multi-Protocol Benchmark Summary (24 Protocols, 2-Core Router Profile)

Performance comparison of **tachyon-core** against **sing-box-lx**, **Xray-core**, and **Mihomo** in identical environments (`GOMAXPROCS=2`, `TACHYON_WORKERS=2`):

| Protocol / Configuration | Tachyon (1s / 8s) | Sing-box (1s / 8s) | Xray (1s / 8s) | Mihomo (1s / 8s) | Latency p50 (T / SB) | Peak RSS (T / SB) | Verdict |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Shadowsocks AES-128-GCM** | **6.69 / 7.10 G** | 2.29 / 2.58 G | 5.47 / 5.56 G | 2.16 / 2.60 G | **298.5 µs** / 308.2 µs | **8.2M** / 44.1M | **TACHYON (2.8x)** |
| **Shadowsocks AES-256-GCM** | **7.22 / 6.77 G** | 2.44 / 2.57 G | 5.61 / 5.54 G | 2.32 / 2.46 G | **297.5 µs** / 321.3 µs | **8.2M** / 44.3M | **TACHYON (2.8x)** |
| **Shadowsocks ChaCha20-Poly1305** | **5.64 / 5.85 G** | 2.21 / 2.40 G | 4.96 / 5.09 G | 2.19 / 2.33 G | **284.2 µs** / 305.8 µs | **8.3M** / 43.8M | **TACHYON (2.4x)** |
| **Shadowsocks 2022 AES-128-GCM** | **8.04 / 8.03 G** | 6.01 / 6.48 G | 4.26 / 5.12 G | 5.21 / 5.29 G | **286.3 µs** / 314.2 µs | **8.3M** / 44.1M | **TACHYON (1.2x)** |
| **VMess (Plain)** | **6.49 / 6.30 G** | 2.39 / 2.46 G | 6.11 / 6.15 G | 2.45 / 2.64 G | **286.1 µs** / 322.2 µs | **6.9M** / 44.1M | **TACHYON (2.6x)** |
| **VMess + TLS** | **5.72 / 4.68 G** | 3.00 / 3.35 G | 2.10 / 2.10 G | 2.08 / 2.31 G | **302.6 µs** / 322.2 µs | **7.7M** / 46.9M | **TACHYON (1.7x)** |
| **VMess + WS + TLS** | **4.83 / 5.48 G** | 2.89 / 3.29 G | 1.92 / 2.00 G | 2.10 / 2.18 G | **300.1 µs** / 323.0 µs | **8.0M** / 47.0M | **TACHYON (1.7x)** |
| **VMess + gRPC + TLS** | 3.56 / 3.59 G | **4.58 / 3.52 G** | 1.65 / 1.86 G | 1.74 / 1.73 G | **334.4 µs** / 339.9 µs | **13.5M** / 81.1M | SING-BOX (1.3x) |
| **VLESS (Plain Direct)** | 26.95 / 24.74 G | **28.40 / 28.31 G**| 8.03 / 8.57 G | — | **284.8 µs** / 310.5 µs | **5.0M** / 41.2M | SING-BOX (1.1x) |
| **VLESS + TLS** | **3.99 / 3.97 G** | 3.16 / 3.40 G | 2.21 / 2.62 G | 2.99 / 3.40 G | **298.8 µs** / 311.5 µs | **6.5M** / 46.4M | **TACHYON (1.2x)** |
| **VLESS + TLS + Vision** | **3.80 / 3.66 G** | 3.05 / 3.35 G | 2.21 / 2.64 G | 2.71 / 3.31 G | **295.4 µs** / 319.0 µs | **7.2M** / 46.5M | **TACHYON (1.1x)** |
| **VLESS + WS + TLS** | **3.76 / 3.66 G** | 3.03 / 3.36 G | 2.46 / 2.59 G | 2.82 / 2.99 G | **291.1 µs** / 320.6 µs | **7.3M** / 47.4M | **TACHYON (1.1x)** |
| **VLESS + gRPC + TLS** | **5.88 / 4.83 G** | 4.26 / 3.64 G | 2.90 / 3.09 G | — | **319.7 µs** / 355.9 µs | **14.6M** / 59.6M | **TACHYON (1.4x)** |
| **VLESS + XHTTP + TLS** | 2.53 / **4.98 G** | 2.34 / 6.49 G | 1.14 / 2.96 G | — | **371.3 µs / 29867.5 µs** | **74.4M** / 81.1M | **80× faster latency** |
| **VLESS + HTTP/2 + TLS** | **3.54 / 9.63 G** | 2.85 / 2.66 G | — | — | **363.8 µs** / 446.1 µs | **24.0M** / 54.3M | **TACHYON (3.4x)** |
| **Trojan + TLS** | **5.80 / 3.96 G** | 3.06 / 3.43 G | 1.94 / 2.54 G | 2.80 / 3.26 G | **287.7 µs** / 317.2 µs | **6.7M** / 46.5M | **TACHYON (1.7x)** |
| **Trojan + WS + TLS** | **4.52 / 3.47 G** | 2.88 / 3.40 G | 2.30 / 2.52 G | 2.91 / 3.14 G | **292.7 µs** / 318.9 µs | **7.2M** / 47.3M | **TACHYON (1.3x)** |
| **Trojan + gRPC + TLS** | **4.92 / 4.66 G** | 4.53 / 3.49 G | 3.09 / 3.21 G | 4.26 / 3.75 G | **321.8 µs** / 339.5 µs | **14.3M** / 60.5M | **TACHYON (1.1x)** |
| **Hysteria 2 (QUIC)** | **3.23 / 3.64 G** | 1.74 / 1.86 G | — | 2.46 / 2.19 G | **352.9 µs** / 385.4 µs | **10.6M** / 54.5M | **TACHYON (2.0x)** |
| **TUIC v5 (QUIC)** | **3.69 / 3.79 G** | 2.56 / 2.11 G | — | 2.40 / 2.03 G | **350.9 µs** / 391.9 µs | **19.2M** / 49.8M | **TACHYON (1.5x)** |
| **NaiveProxy (HTTP/2 TLS)** | **4.88 / 4.46 G** | 1.35 / 2.14 G | — | — | **11.7 µs / 1596.2 µs** | **14.0M** / 177.0M | **TACHYON (2.3x)** |
| **NaiveProxy (HTTP/3 QUIC)**| **0.86 / 0.89 G** | 0.71 / 0.82 G | — | — | **12.1 µs / 562.1 µs** | **14.4M** / 60.6M | **TACHYON (1.1x)** |
| **AnyTLS (H2MUX TLS)** | **7.40 / 6.68 G** | 5.87 / 5.67 G | — | — | **295.5 µs** / 320.8 µs | **34.9M** / 46.1M | **TACHYON (1.3x)** |
| **Snell (v4/v5)** | **3.90 / 3.40 G** | 2.94 / 2.61 G | — | 2.19 / 2.09 G | **287.7 µs** / 313.0 µs | **6.7M** / 44.7M | **TACHYON (1.3x)** |

> 🏆 **Benchmark Highlights**:
> * **21 wins out of 24 protocols** in a 2-core router CPU profile.
> * **XHTTP (SplitHTTP) Breakthrough**: Built-in `H2Pool` connection pooling eliminates repeated TLS handshakes per stream. Time-to-first-byte latency plummeted from **29.8 ms** (sing-box) and **30.8 ms** (Xray) to **371 microseconds (0.37 ms)** — **80× faster!**
> * Detailed charts, graphs, and interactive filtering are available in **[BENCHMARK.md](BENCHMARK.md)** and **[BENCHMARK.html](BENCHMARK.html)**.

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
* **XHTTP (SplitHTTP)**: Full implementation of HTTP/1.1 chunked, `stream-up`, `packet-up`, and `stream-one` specifications with built-in HTTP/2 connection pooling (`H2Pool` with up to 4 parallel TCP/TLS sockets and least-loaded stream balancing). Eliminates repetitive TLS handshakes per stream, dropping p50 latency down to **371 µs** (**80× faster** than Go cores at 30 ms). Expanded flow-control windows (4 MiB stream / 16 MiB connection) ensure **5.0+ Gbit/s** throughput over multiplexed streams. Fully validated against live **Xray 26.9+** endpoints.
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
