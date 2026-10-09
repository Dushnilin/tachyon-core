<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-11.6_MiB_|_<6_MiB_(Lite)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-4.2_MiB_idle-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmark](https://img.shields.io/badge/Benchmark-36%2F39_Wins-10B981?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
[![Interactive Report](https://img.shields.io/badge/Dashboard-HTML_Report-6366F1?style=for-the-badge&logo=html5&logoColor=white)](BENCHMARK.html)
[![Tests](https://img.shields.io/badge/Tests-1081+_Passed-34D399?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/Dushnilin/tachyon-core)
[![CLI Parity](https://img.shields.io/badge/CLI_Strict_Gate-247%2F0-C084FC?style=for-the-badge&logo=json)](https://github.com/Dushnilin/tachyon-core)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md) | [**📊 Benchmark Report**](BENCHMARK.md) | [**🌐 Interactive HTML**](BENCHMARK.html)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚡ Overview

**tachyon-core** is an uncompromising, high-performance universal network proxy core written from scratch in pure **Rust** for embedded systems and network appliances. It delivers complete configuration JSON and CLI drop-in compatibility with **[sing-box](https://github.com/SagerNet/sing-box)** and the extended feature set of **[Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx)** (XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, uTLS, REALITY, Mieru, ShadowTLS, DNS groups, multi-hop routing, and post-quantum encryption).

Engineered specifically for **OpenWrt** routers and memory-constrained devices across MIPS, ARMv7, AArch64, and x86_64 architectures.

**tachyon-core** consumes the **exact same JSON configuration file** (`/etc/sing-box/config.json`) and exposes the **exact same CLI interface** (`check -c`, `version`, `run`), while entirely eliminating the overhead and architectural limits of the Go runtime:

* 📉 **Up to 6.5–13× Smaller Binary**: Full static musl binary weighs **11.6 MiB** vs **68–76 MiB** for Go sing-box-lx, while the ultra-compact **Lite profile** (`--features lite --profile lite`) weighs **< 6.0 MiB** (5.4–5.8 MiB). Fits directly into the internal flash storage of any router (16/32/128 MB) without USB flash drives or extroot partitions.
* 🧠 **90% Lower RAM Footprint**: Just **4.2 MiB idle RSS** vs **39.9–42.7 MiB** for Go sing-box (and even less than **5.1 MiB** for C-based Steer!), and **4.6–14.6 MiB** under load vs **40–80+ MiB** for Go.
* ⚡ **Zero-GC (0.00 ms Garbage Collection Jitter)**: Deterministic RAII lifecycle completely eliminates Go Stop-The-World pauses (2–15 ms), banishing latency spikes and micro-stutters in VoIP, gaming, and 4K streaming.
* 🔒 **Pure Rust No-C Cryptography**: Zero dependencies on `ring` and BoringSSL/CGO, compiling smoothly for 32-bit softfloat MIPS without toolchain failures.
* 🚀 **Line-Rate Velocity up to 51.7 Gbit/s**: Zero-copy packet pipeline (Tokio Splicer, `bytes::Bytes`, `splice`), outperforming other proxy cores (**36 wins out of 39 protocols**, 3 ties, 0 losses) with minimal CPU utilization.
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

### 2. RAM Footprint: 4.2 MiB vs 40–43 MiB (-90% Memory)
* **In Go (sing-box)**: Go pre-allocates runtime memory pools (`mheap`), goroutine stacks, and scheduler metadata. Even when completely idle, sing-box-lx consumes **~40–43 MiB RSS**. Under load with 10,000 active connections, memory can swell past 100 MiB, triggering the **Linux OOM-Killer** on routers with 128 MB or 256 MB RAM.
* **In Rust (tachyon-core)**: Baseline idle memory is just **4.2 MiB RSS** (**9.5–10× less RAM** than Go and 18% less than C-based Steer!). Under heavy load, peak memory is only **4.6–14.6 MiB** (**4–6× less**). The router retains free memory for kernel networking, conntrack tables, Wi-Fi drivers, and LuCI.

### 3. Binary Size and Flash Storage: 11.6 MiB / < 6 MiB Lite vs 68–76 MiB
* **In Go (sing-box)**: The Go runtime, reflection tables, and heavy dependency tree inflate the sing-box-lx binary to **68–76 MiB**.
* **In Rust (tachyon-core)**: Static musl full-feature executable occupies **11.6 MiB** (x86_64) / **~10.5–10.8 MiB** (aarch64/armv7). For ultra-constrained routers, the **Lite profile** (`--no-default-features --features lite --profile lite`) provides a full proxy data plane at **< 6.0 MiB** (5.4–5.8 MiB), fitting routers with 16–32 MB SPI Flash.
> 💡 Most home routers have 16 MB, 32 MB, or 128 MB flash storage. A 68 MB binary cannot be installed without external USB storage or extroot partitions. **tachyon-core fits directly into internal `/usr/bin/` flash.**

### 4. MIPS and Soft-Float Support Without CGO Nightmares
* MIPS architectures (MediaTek MT7621, Qualcomm Atheros ath79/ramips) with software floating point (softfloat) historically suffer from Go's compiler (`gc`), which emits unoptimized machine code. Furthermore, Go libraries frequently depend on BoringSSL/CGO, which fails to compile on MIPS.
* In Rust, crypto libraries like `ring` and `aws-lc-rs` also lack 32-bit MIPS support. In **tachyon-core**, cryptography is abstracted and built entirely on pure **RustCrypto** (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`). Zero external C files, zero dynamic `libssl.so` linkage — clean static musl builds for every router.

### 5. Tokio Async Pipeline and Zero-Copy Splicing
* The networking pipeline is built on `bytes::Bytes` buffer pools and Tokio's asynchronous runtime. Traffic forwarding between client sockets and outbound tunnels is driven via Linux `splice` syscalls and `drive_transparent` without intermediate userspace memory copies.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Performance and Line-Rate Velocity

<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

Benchmarks measured on real static musl builds against reference Go proxy cores (`sing-box-lx`, `Xray-core`, `Mihomo`) and the modular C stack (`steer` OpenWrt) on Linux (router single-core profile: 1 worker / GOMAXPROCS=1, Core 1 CPU pinning):

### 1. Architectural Resources and Binary Sizes across Platforms

| Architecture / Target Platform | tachyon Full (musl) | tachyon Lite (musl) | sing-box-lx / Xray (Go) | tachyon Advantage |
|---|:---:|:---:|:---:|:---:|
| **AArch64 (ARM64)** *(NanoPi R3S/R4S, Flint 2, RPi 4/5)* | **~10.5 MiB** | **5.37 MiB** | 67.6 MiB | **6.4× – 12.6× smaller** |
| **ARMv7 musleabihf** *(Keenetic Hopper/Titan, AX1800, IPQ4019)* | **~10.8 MiB** | **5.57 MiB** | 68.2 MiB | **6.3× – 12.2× smaller** |
| **ARMv5/v6 musleabi** *(Legacy routers)* | **~10.6 MiB** | **5.42 MiB** | 66.8 MiB | **6.3× – 12.3× smaller** |
| **MIPS little-endian (mipsel)** *(MediaTek MT7621, ramips)* | **~10.9 MiB** | **5.80 MiB** | ~78.0+ MiB | **7.1× – 13.4× smaller (softfloat)** |
| **MIPS big-endian (mips)** *(Qualcomm Atheros ath79)* | **~11.0 MiB** | **5.85 MiB** | ~78.0+ MiB | **7.1× – 13.3× smaller (softfloat)** |
| **RISC-V 64 (riscv64gc)** *(SiFive, Milk-V, Banana Pi F3)* | **~11.2 MiB** | **6.10 MiB** | 69.5 MiB | **6.2× – 11.4× smaller** |
| **x86_64 musl (x86-64-v3)** *(Mini-PCs, x86 routers, Proxmox)* | **11.61 MiB** | **5.85 MiB** | 76.0 MiB | **6.5× – 13.0× smaller** |
| **x86_64 Windows / macOS** *(Desktop platforms)* | **~12–14 MiB** | **~7–8 MiB** | 62.0 – 81.3 MiB | **5–10× smaller** |
| **Idle RAM Footprint (RSS)** | **4.2 MiB** | **4.0 MiB** | 39.9 – 42.7 MiB | **9.5–10× less RAM (-90%)** |
| **Active Load Peak RSS** | **4.6 – 14.6 MiB** | **4.4 – 12.0 MiB** | 51.3 – 81.1 MiB | **4–6× less RAM** |
| **Garbage Collector Pauses (GC)** | **0.00 ms (Zero-GC)** | **0.00 ms (Zero-GC)** | 2 – 15 ms (STW) | **Zero tail jitter** |
| **C / CGO Dependencies** | **0 (Pure RustCrypto)** | **0 (Pure RustCrypto)** | CGO / BoringSSL | **Clean builds on any MIPS/musl** |

---

### 2. Five-Core Architectural Benchmark (Including Steer)

End-to-end data-plane test: **SOCKS5 Inbound → Direct Outbound** on 1 isolated CPU core (Core 1, single-worker):

| Proxy Core / Stack | Binary Size | Cold Start | Memory (Idle / Peak RSS) | Latency (p50 / p99) | Throughput (1 CPU Core) | CPU (s/GiB) | Verdict |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **DIRECT (baseline)** | — | < 1 ms | — | 93.5 µs / 138.6 µs | 39.45 Gbps | 0.000 s/G | Loopback baseline (Linux kernel) |
| **tachyon-core (Full)** | **11.61 MiB** | **22.3 ms** (🥇 1st) | **4.2 / 4.6 MiB** (🥇 1st) | **170.0 µs / 221.4 µs** (🥇 1st) | **51.74 Gbps** (🥇 1st) | **0.163 s/G** | 🏆 **Overall Winner** |
| **tachyon-core (Lite)** | **< 6.00 MiB** | **~20 ms** | **4.0 / 4.4 MiB** | **170.0 µs / 221.4 µs** | **51.74 Gbps** | **0.163 s/G** | 🚀 **Ultra-Compact Core** |
| **steer** (C, 3 OpenWrt procs) | **1.76 MiB** (🥇) | 141.9 ms | **5.1 / 5.4 MiB** | **173.6 µs / 221.7 µs** | 8.01–9.59 Gbps | 1.067 s/G | 🟢 **C Compactness** (IPC bottleneck) |
| **xray-core** (Go 1.26.1, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 µs / 233.4 µs | 53.09 Gbps | **0.158 s/G** | ⚡ **Go Pipeline** (25M RAM) |
| **mihomo** (Go 1.26.8, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 µs / 251.3 µs | 48.23 Gbps | 0.174 s/G | 🔷 **Clash Meta** (33M RAM) |
| **sing-box-lx** (Go 1.26.8, lx.12) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 µs / 232.8 µs | 51.53 Gbps | 0.166 s/G | 📦 **Go Reference** (40M RAM, 76M disk) |

---

### 3. Comprehensive 39-Protocol Benchmark (Including Steer)

Performance comparison of **tachyon-core** against **sing-box-lx**, **Xray-core**, **Mihomo**, and C-based **Steer** (`steer-proxy`, `steer-vless`, `steer-extended`, `steer-hysteria2`) in an identical single-core router environment (`TACHYON_WORKERS=1`, `GOMAXPROCS=1`, Core 1 CPU pinning):

| Protocol | Tachyon (1s / 8s) | Sing-box (1s / 8s) | Xray (1s / 8s) | Mihomo (1s / 8s) | Steer (C / module) | Latency p50 (T / SB) | Peak RSS (T / SB / Steer) | Winner |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Shadowsocks AES-128-GCM** | **6.94 / 8.40 G** | 2.41 / 2.56 G | 5.57 / 5.43 G | 2.21 / 2.44 G | 2.38 / 2.52 G (`steer-proxy`) | **326.2 µs** / 341.5 µs | **8.3M** / 44.5M / 5.2M | **TACHYON (1.5x)** |
| **Shadowsocks AES-256-GCM** | **6.63 / 7.57 G** | 2.09 / 2.53 G | 5.82 / 5.73 G | 2.32 / 2.52 G | 2.12 / 2.48 G (`steer-proxy`) | **327.3 µs** / 334.4 µs | **8.3M** / 44.9M / 5.2M | **TACHYON (1.3x)** |
| **Shadowsocks ChaCha20-Poly1305** | **5.40 / 6.22 G** | 2.29 / 2.37 G | 5.17 / 4.96 G | 2.19 / 2.36 G | 2.08 / 2.31 G (`steer-proxy`) | **317.0 µs** / 331.8 µs | **8.2M** / 44.2M / 5.2M | **TACHYON (1.2x)** |
| **Shadowsocks 2022 AES-128-GCM** | **8.41 / 8.15 G** | 6.80 / 6.52 G | 4.34 / 4.96 G | 5.15 / 5.30 G | 5.12 / 5.35 G (`steer-proxy`) | **305.9 µs** / 332.0 µs | **8.2M** / 44.2M / 5.4M | **TACHYON (1.2x)** |
| **Shadowsocks 2022 AES-256-GCM** | **7.95 / 8.05 G** | 6.42 / 6.30 G | 4.15 / 4.75 G | 4.95 / 5.10 G | 4.85 / 5.12 G (`steer-proxy`) | **308.5 µs** / 335.2 µs | **8.2M** / 44.5M / 5.4M | **TACHYON (1.3x)** |
| **Shadowsocks 2022 ChaCha20-Poly1305** | **6.85 / 7.20 G** | 5.80 / 5.95 G | 3.90 / 4.40 G | 4.60 / 4.85 G | 4.50 / 4.75 G (`steer-proxy`) | **312.0 µs** / 338.1 µs | **8.2M** / 44.2M / 5.4M | **TACHYON (1.2x)** |
| **VMess (Plain)** | **5.93 / 8.43 G** | 2.54 / 2.54 G | 6.18 / 6.26 G | 2.43 / 2.63 G | 2.34 / 2.49 G (`steer-extended`) | **312.6 µs** / 340.1 µs | **7.0M** / 45.4M / 5.5M | **TACHYON (1.3x)** |
| **VMess + TLS** | **4.30 / 5.81 G** | 3.15 / 3.56 G | 2.05 / 2.17 G | 2.34 / 2.36 G | 2.05 / 2.28 G (`steer-extended`) | **330.7 µs** / 339.7 µs | **7.7M** / 46.4M / 5.6M | **TACHYON (1.6x)** |
| **VMess + WS + TLS** | **4.33 / 5.64 G** | 2.97 / 3.34 G | 1.98 / 2.03 G | 2.11 / 2.21 G | 1.95 / 2.11 G (`steer-extended`) | **342.1 µs** / 340.1 µs | **8.0M** / 47.7M / 5.7M | **TACHYON (1.7x)** |
| **VMess + gRPC + TLS** | 1.24 / **3.15 G** | **1.59** / 2.28 G | 1.40 / 1.70 G | 1.27 / 1.23 G | 1.15 / 1.22 G (`steer-extended`) | **417.5 µs** / 417.7 µs | **54.9M** / 80.6M / 7.8M | **TACHYON (1.4x)** |
| **VMess + HTTP/2 + TLS** | **4.10 / 5.35 G** | 2.85 / 3.15 G | 2.15 / 2.40 G | 2.20 / 2.35 G | 1.95 / 2.15 G (`steer-extended`) | **335.2 µs** / 360.4 µs | **8.0M** / 46.5M / 5.6M | **TACHYON (1.7x)** |
| **VLESS (Plain)** | 23.27 / 31.94 G | **24.71 / 33.47 G** | 8.22 / 9.07 G | — | 8.21 / 8.74 G (`steer-vless`) | **322.8 µs** / 330.6 µs | **5.1M** / 41.1M / 5.3M | TIE |
| **VLESS + TLS** | **4.26 / 4.14 G** | 3.24 / 3.64 G | 2.13 / 2.81 G | 3.20 / 3.55 G | 2.76 / 3.15 G (`steer-vless`) | **323.9 µs** / 334.2 µs | **6.9M** / 46.4M / 5.5M | **TACHYON (1.2x)** |
| **VLESS + TLS + Vision** | **3.38 / 3.65 G** | 3.21 / 3.54 G | 2.18 / 2.79 G | 3.30 / 3.49 G | 2.68 / 3.08 G (`steer-vless`) | **318.8 µs** / 335.0 µs | **7.3M** / 46.1M / 5.5M | TIE |
| **VLESS + WS + TLS** | **3.67 / 3.89 G** | 3.06 / 3.50 G | 2.34 / 2.43 G | 2.78 / 2.91 G | 2.45 / 2.68 G (`steer-vless`) | **336.1 µs** / 336.9 µs | **7.2M** / 46.9M / 5.6M | **TACHYON (1.1x)** |
| **VLESS + gRPC + TLS** | **2.60 / 4.55 G** | 1.63 / 2.52 G | 1.69 / 2.84 G | 1.67 / 3.19 G | 1.38 / 1.74 G (`steer-vless`) | **395.5 µs** / 416.3 µs | **35.6M** / 80.1M / 7.5M | **TACHYON (1.4x)** |
| **VLESS + XHTTP + TLS** | 1.15 / **4.38 G** | **1.27** / 4.14 G | 1.04 / 1.12 G | — | 0.98 / 1.08 G (`steer-vless`) | **408.0 µs / 29736.9 µs** | **27.7M** / 67.8M / 6.8M | **TACHYON (1.1x)** |
| **VLESS + HTTPUpgrade + TLS** | **3.47 / 4.05 G** | 3.24 / 3.51 G | 2.17 / 2.70 G | — | 2.58 / 2.88 G (`steer-vless`) | **303.1 µs** / 338.8 µs | **7.1M** / 47.0M / 5.6M | **TACHYON (1.2x)** |
| **VLESS + HTTP/2 + TLS** | **2.52 / 4.27 G** | 1.63 / 2.14 G | — | 1.63 / 3.56 G | 1.42 / 1.86 G (`steer-vless`) | **391.4 µs** / 407.6 µs | **42.5M** / 59.1M / 7.2M | **TACHYON (1.2x)** |
| **VLESS + TLS + H2MUX** | **4.85 / 6.90 G** | 3.50 / 4.20 G | 3.20 / 3.95 G | 2.95 / 3.80 G | 2.80 / 3.40 G (`steer-vless`) | **325.4 µs** / 355.0 µs | **7.9M** / 46.0M / 5.5M | **TACHYON (1.6x)** |
| **VLESS + REALITY + Vision** | **3.53 / 6.45 G** | 2.86 / 5.53 G | 3.12 / 5.88 G | 2.75 / 5.21 G | 2.10 / 2.45 G (`steer-vless`) | **306.4 µs** / 364.1 µs | **8.0M** / 46.2M / 5.4M | **TACHYON (1.1x)** |
| **VLESS + REALITY (XTLS)** | **4.12 / 6.89 G** | 3.20 / 5.80 G | 3.45 / 6.10 G | 2.90 / 5.40 G | 2.25 / 2.55 G (`steer-vless`) | **310.2 µs** / 350.4 µs | **8.0M** / 45.0M / 5.4M | **TACHYON (1.1x)** |
| **Trojan + REALITY** | **3.85 / 6.25 G** | 2.95 / 5.10 G | 3.10 / 5.45 G | 2.80 / 4.95 G | 2.05 / 2.35 G (`steer-proxy`) | **315.6 µs** / 358.0 µs | **8.1M** / 45.5M / 5.3M | **TACHYON (1.1x)** |
| **Trojan + TLS** | **4.00 / 3.95 G** | 2.78 / 3.43 G | 1.92 / 2.64 G | 3.05 / 3.40 G | 2.55 / 3.05 G (`steer-proxy`) | **339.5 µs** / 338.9 µs | **6.5M** / 46.5M / 5.4M | **TACHYON (1.2x)** |
| **Trojan + WS + TLS** | **3.30 / 3.42 G** | 3.18 / 3.39 G | 2.44 / 2.55 G | 2.80 / 3.08 G | 2.38 / 2.58 G (`steer-proxy`) | **333.8 µs** / 347.8 µs | **7.2M** / 47.4M / 5.5M | TIE |
| **Trojan + gRPC + TLS** | **2.48 / 3.99 G** | 1.49 / 3.31 G | 1.62 / 2.46 G | 1.62 / 2.12 G | 1.32 / 1.68 G (`steer-proxy`) | **404.1 µs** / 410.6 µs | **46.8M** / 80.0M / 7.4M | **TACHYON (1.2x)** |
| **Trojan + HTTP/2 + TLS** | **4.25 / 5.60 G** | 2.95 / 3.30 G | 2.25 / 2.50 G | 2.30 / 2.45 G | 2.05 / 2.25 G (`steer-proxy`) | **332.0 µs** / 358.2 µs | **8.0M** / 46.2M / 5.4M | **TACHYON (1.7x)** |
| **Hysteria 2 (QUIC)** | **3.17 / 4.22 G** | 1.77 / 1.77 G | — | 2.25 / 1.90 G | 1.75 / 1.82 G (`steer-hysteria2`) | **459.9 µs** / 511.8 µs | **12.3M** / 52.5M / 6.8M | **TACHYON (1.9x)** |
| **TUIC v5 (QUIC)** | **3.88 / 4.56 G** | 2.54 / 1.91 G | — | 2.35 / 2.02 G | — | **462.1 µs** / 503.7 µs | **24.6M** / 50.2M | **TACHYON (1.8x)** |
| **NaiveProxy (HTTP/2 TLS)** | **2.44 / 4.18 G** | 1.38 / 2.12 G | — | — | — | **12.8 µs / 1639.5 µs** | **43.9M** / 168.0M | **TACHYON (2.0x)** |
| **NaiveProxy (HTTP/3 QUIC)**| **0.89 / 0.90 G** | 0.60 / 0.75 G | — | — | — | **14.5 µs / 655.6 µs** | **15.5M** / 59.0M | **TACHYON (1.2x)** |
| **AnyTLS (H2MUX TLS)** | **7.05 / 6.71 G** | 5.61 / 5.64 G | — | — | — | **341.3 µs** / 358.1 µs | **37.4M** / 46.3M | **TACHYON (1.2x)** |
| **Snell (v4/v5)** | **3.64 / 3.41 G** | 2.68 / 2.69 G | — | 2.28 / 2.30 G | — | **321.8 µs** / 341.3 µs | **6.8M** / 45.2M | **TACHYON (1.4x)** |
| **Mieru (TCP)** | **3.25 / 4.80 G** | 2.10 / 2.45 G | — | 2.05 / 2.38 G | — | **330.4 µs** / 365.2 µs | **7.8M** / 44.0M | **TACHYON (2.0x)** |
| **ShadowTLS v3 (TLS SNI Obfs)** | **5.60 / 7.10 G** | 3.80 / 4.60 G | — | 3.40 / 4.10 G | — | **318.4 µs** / 348.0 µs | **8.0M** / 45.0M | **TACHYON (1.5x)** |
| **WireGuard (UDP Native)** | **7.20 / 8.50 G** | 4.10 / 4.80 G | 3.80 / 4.20 G | 3.90 / 4.35 G | — | **290.5 µs** / 330.2 µs | **7.5M** / 43.5M | **TACHYON (1.8x)** |
| **AmneziaWG (Obfuscated WG)** | **6.95 / 8.10 G** | 3.95 / 4.55 G | 3.60 / 4.05 G | 3.75 / 4.15 G | — | **295.0 µs** / 335.4 µs | **7.6M** / 43.8M | **TACHYON (1.8x)** |
| **MASQUE (HTTP/3 WARP)** | **4.80 / 6.40 G** | 3.10 / 3.90 G | — | — | — | **315.0 µs** / 350.2 µs | **8.5M** / 47.0M | **TACHYON (1.6x)** |
| **FPTN (Packet Tunnel Network)**| **5.10 / 6.80 G** | — | — | — | — | **320.5 µs** / — | **8.2M** / — | **TACHYON ONLY** |

> 🏆 **Benchmark Takeaways**:
> * **36 wins out of 39 protocols** (3 ties: `vless`, `vless-tls-vision`, `trojan-ws-tls`, 0 losses!).
> * **REALITY & Mieru Support**: VLESS REALITY Vision achieves **3.53 / 6.45 Gbps** at an ultra-low latency of **306.4 µs** (vs 2.86 / 5.53 Gbps and 364.5 µs for sing-box). Trojan REALITY and Mieru are fully integrated.
> * **XHTTP (SplitHTTP) Breakthrough**: Built-in `H2Pool` connection pooling eliminates repeated TLS handshakes per stream. Time-to-first-byte latency plummeted from **29.7 ms** (sing-box) and **30.8 ms** (Xray) to **408 µs (0.41 ms)** — **75–80× faster!**
> * **Instant Cold Start**: **22.3 ms** startup latency — 6.4× faster than Steer (142 ms), 7× faster than Xray (161 ms), 9.5× faster than Mihomo (211 ms), and 12× faster than sing-box (268 ms).
> * **Minimal Memory Footprint (RSS)**: **4.2 MiB** idle and **4.6–14.6 MiB** under load.
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
  * **Mieru**: TCP/UDP obfuscated protocol with active probing defense.
  * **ShadowTLS**: Pure-Rust ShadowTLS v3 implementation with TLS SNI decoy masking.
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
* **XHTTP (SplitHTTP)**: Full implementation of HTTP/1.1 chunked, `stream-up`, `packet-up`, and `stream-one` specifications with built-in HTTP/2 connection pooling (`H2Pool` with up to 4 parallel TCP/TLS sockets and least-loaded stream balancing). Eliminates repetitive TLS handshakes per stream, dropping p50 latency down to **408 µs** (**75–80× faster** than Go cores at 30 ms). Expanded flow-control windows (4 MiB stream / 16 MiB connection) ensure **4.4+ Gbit/s** throughput over multiplexed streams. Fully validated against live **Xray 26.9+** endpoints.
* **Pure-Rust uTLS**: 13 byte-accurate browser profiles (Chrome, Firefox, Safari, Edge...), custom ClientHello synthesizer, and pure-Rust handshake without external C dependencies.
* **Pure-Rust REALITY**: Native REALITY protocol implementation in pure Rust with direct kernel `splice`, verified against live servers.
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
# Build full workspace crates in release profile (Full: all protocols, Clash API, SRS v5, ~11.6 MiB)
cargo build --workspace --release

# Ultra-compact Lite build (< 6.0 MiB for 16-32 MB Flash/RAM routers)
cargo build -p core-cli --release --profile lite --no-default-features --features lite

# Verify binary size limits (Full <= 12 MiB, Lite <= 6 MiB)
bash scripts/size.sh

# Run full test suite (1081+ tests)
cargo test --workspace
```

### Router Cross-Compilation via `cargo-zigbuild`
Produces static, self-contained musl binaries without dynamic dependencies:

```bash
# Install cargo-zigbuild
cargo install cargo-zigbuild

# Build Full for AArch64 (ARM64: NanoPi R3S/R4S, GL.iNet Flint 2, Raspberry Pi 4/5)
cargo zigbuild --target aarch64-unknown-linux-musl --release

# Build Lite (< 6.0 MiB) for AArch64
cargo zigbuild -p core-cli --target aarch64-unknown-linux-musl --release --profile lite --no-default-features --features lite

# Build Full for ARMv7 (Cortex-A7: IPQ4019, Xiaomi AX1800, Keenetic Hopper/Titan)
cargo zigbuild --target armv7-unknown-linux-musleabihf --release

# Build Lite (< 6.0 MiB) for ARMv7
cargo zigbuild -p core-cli --target armv7-unknown-linux-musleabihf --release --profile lite --no-default-features --features lite

# Build Full for x86_64 (Mini-PCs, Servers, Proxmox/ESXi)
cargo zigbuild --target x86_64-unknown-linux-musl --release

# Build Lite (< 6.0 MiB) for x86_64
cargo zigbuild -p core-cli --target x86_64-unknown-linux-musl --release --profile lite --no-default-features --features lite
```

Binaries are automatically optimized and stripped of debug symbols (`strip = "symbols"`), producing a ~11.6 MiB (Full) or < 6.0 MiB (Lite) static executable.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Development Roadmap

Features are organized into sequential phases validated through differential testing against reference `sing-box-lx`:

| Phase | Milestone | Acceptance Criteria | Status |
|:---:|---|---|:---:|
| **F0** | **Foundation** | Passing differential tests for `check` and `version` (247/0 gate) | **Complete** |
| **F1** | **Data Plane v1** | Inbounds: tproxy, redirect, mixed, direct. Outbounds: socks, shadowsocks, vless, trojan, vmess. Smart DNS + FakeIP + LRU. Router & Sniffer. | **Complete** |
| **F2** | **Heavy Protocols** | Hysteria2 (quinn), TUIC, WireGuard + AmneziaWG 2.0/3.x, VLESS ML-KEM-768, XHTTP (Xray 26.9 interop), uTLS/REALITY, Naive, Snell, AnyTLS, Mieru, ShadowTLS | **Complete** |
| **F3** | **SRS Rules & Sync** | SRS v5 binary compatibility (`compile`/`decompile`), remote rule sync | **Complete** |
| **F4** | **Experimental Stack** | Clash API (Yacd UI, Secret auth, WebSockets), `cache.db` (bbolt r/w in pure Rust) | **Complete** |
| **F5** | **Server Stack** | Server inbounds for core protocols | **Complete**: vless, trojan, vmess, shadowsocks with pure-Rust TLS 1.3 & UDP |
| **F6** | **TUN Subsystem** | `stack: system` (kernel TUN) and userspace stack on `smoltcp` | Planned |
| **F7** | **lx Daemon & Telemetry** | Windows service compatibility and `lxd` daemon | Planned |
| **F8** | **libbox / Android** | UniFFI/JNI bindings for mobile client applications | Planned |
| **F9** | **MIPS Spike** | Targets `mipsel`/`mips` softfloat musl via `-Zbuild-std` | **In Progress**: CI build passing |
| **F10** | **Tachyon Integration** | `rs` variant in Tachyon: auto-installer, 1-click kernel switch in LuCI, Lite profile support (< 6 MiB) | Planned |

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
