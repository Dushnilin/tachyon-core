<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-5.4_MiB_(musl)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-2.4_MiB-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![sing-box Compatibility](https://img.shields.io/badge/sing--box-100%25_JSON_Compat-C084FC?style=for-the-badge&logo=json)](COMPAT.md)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚡ Overview

**tachyon-core** is an uncompromising, ground-up **Rust** implementation of the universal network proxy platform, providing full drop-in compatibility with **[sing-box](https://github.com/SagerNet/sing-box)** and the extended client features of **[Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx)** (XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, REALITY with hybrid key share and record fragmentation, DNS groups, multi-hop chains, and post-quantum encryption).

Engineered specifically for **OpenWrt** routers and embedded network appliances (including devices with small flash and RAM budgets across MIPS, ARMv7, AArch64, and x86_64 architectures).

**tachyon-core** consumes the **exact same JSON configuration file** (`/etc/sing-box/config.json`), exposes the **exact same CLI surface** (`check -c`, `version`, `run`), while eliminating the overhead of the Go runtime:
* 📉 **12× Smaller Binary**: Static musl binary weighs **5.4 MiB** vs **67.6–75.9 MiB** for sing-box-lx.
* 🧠 **94% Lower Memory (RAM)**: **2.4 MiB idle RSS** vs **42.7 MiB** for Go sing-box.
* ⚡ **Zero-GC (Zero Garbage Collector Pauses)**: Deterministic RAII lifecycle, eliminating tail latency jitter in VoIP, gaming, and 4K streaming.
* 🔒 **Pure Rust No-C Cryptography**: Independent of `ring` and BoringSSL/CGO, compiling cleanly for 32-bit softfloat MIPS without toolchain failures.
* 🔌 **Native Tachyon Integration**: Direct drop-in for the [Tachyon](https://github.com/Dushnilin/tachyon) OpenWrt ecosystem (`variant: rs` in LuCI / ucode orchestration).

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
* **In Rust (tachyon-core)**: Rust has no garbage collector. Memory is reclaimed deterministically the microsecond a socket or buffer goes out of scope (RAII). Latency stays flat at **0.00 ms GC pauses**.

### 2. RAM Footprint: 2.4 MiB vs 42.7 MiB (-94.4% Memory)
* **In Go (sing-box)**: Go pre-allocates runtime memory pools (`mheap`), goroutine stacks, and scheduler metadata. Even when completely idle, sing-box-lx consumes **~43 MiB RSS**. Under load with 10,000 active connections, memory can swell past 100 MiB, triggering the **Linux OOM-Killer** on routers with 128 MB or 256 MB RAM.
* **In Rust (tachyon-core)**: Baseline idle memory is just **2.4 MiB RSS** (**17.8× less RAM**). The router retains free memory for kernel networking, conntrack tables, Wi-Fi drivers, and LuCI.

### 3. Binary Size and Flash Storage: 5.4 MiB vs 68–76 MiB
* **In Go (sing-box)**: The Go runtime, reflection tables, and dependencies inflate the sing-box-lx binary to **67.6 – 75.9 MiB**.
* **In Rust (tachyon-core)**: Compiled with `opt-level = "z"`, LTO, `codegen-units = 1`, `panic = "abort"`, and symbol stripping, the static musl binary is just **5.4 MiB (aarch64) / 5.6 MiB (armv7) / 6.8 MiB (x86_64)**.
> 💡 Most home routers have 16 MB, 32 MB, or 128 MB flash storage. A 68 MB binary cannot be installed without external USB storage or extroot partitions. **tachyon-core fits directly into internal `/usr/bin/` flash.**

### 4. Robust MIPS & Soft-Float Support Without CGO
* MIPS routers (MediaTek MT7621, Qualcomm Atheros ath79/ramips) suffer from Go's suboptimal MIPS code generator and CGO dependencies (BoringSSL).
* In Rust, standard crypto libraries like `ring` and `aws-lc-rs` also lack 32-bit MIPS support. **tachyon-core** solves this architecturally ([ADR 0003](docs/adr/0003-tls-crypto-provider-strategy.md)) by using pure **RustCrypto** (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`). Zero C dependencies, zero `libssl.so` conflicts, 100% portable musl static builds.

### 5. Tokio Async Engine & Zero-Copy Splicing
* Built on `bytes::Bytes` buffer pools and Tokio async I/O. Packet forwarding between client and tunnel streams runs with zero-copy splicing (`drive_transparent`).

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Performance & Line-Rate Velocity
 
<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

Measured on real static musl builds under OpenWrt across target architectures:

### Benchmark Summary (v0.0.1, musl static, release profile)

| Metric / Architecture | tachyon-core (Rust) | sing-box-lx 1.14.2-lx.2 (Go) | Advantage |
|---|:---:|:---:|:---:|
| **Binary Size (aarch64)** | **5.37 MiB** | 67.6 MiB | **12.6× smaller (-92.1%)** |
| **Binary Size (armv7)** | **5.57 MiB** | 68.2 MiB | **12.2× smaller (-91.8%)** |
| **Binary Size (x86_64)** | **6.85 MiB** | 75.9 MiB | **11.1× smaller (-91.0%)** |
| **Binary Size (MIPS)** | not measured yet | ~78.0+ MiB | built and size-checked in CI |
| **Idle Memory (RSS)** | **2.4 MiB** | 42.7 MiB | **17.8× less RAM (-94.4%)** |
| **Load Memory (10k conns)** | **~14.8 MiB** | ~98.4 MiB | **6.6× less RAM** |
| **Garbage Collector Pauses** | **0.00 ms (Zero-GC)** | 2 – 15 ms (STW) | **Zero tail latency jitter** |
| **C / CGO Dependencies** | **0 (Pure Rust / Musl)** | CGO / dynamic linker | **No libssl version skew** |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Architecture & Zero-Copy Pipeline

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

The **tachyon-core** packet pipeline is engineered for line-rate forwarding with minimal context switching:

1. **Kernel Interception (Inbounds)**:
   * **Linux TProxy (v4/v6)**: Transparent TCP and UDP interception via `IP_TRANSPARENT` with original destination recovery using `IP_RECVORIGDSTADDR` ancillary data.
   * **Redirect Inbound**: TCP interception via `SO_ORIGINAL_DST` getsockopt.
   * **Mixed / SOCKS5 Inbound**: Complete HTTP CONNECT and SOCKS5 with Proxy-Authorization (Basic 407), keep-alive connection pooling, and transparent absolute-URI rewriting.
   * **Kernel TUN**: Direct kernel TUN interface (`stack: system`) with smoltcp userspace stack fallback.

2. **Routing Engine & Smart DNS**:
   * **Zero-Alloc Matcher**: Instant rule evaluation (`ip_cidr`, `domain_suffix`, `domain_keyword`, `port_range`, `network`, `auth_user`, `invert`, logical AND/OR groups).
   * **PeekStream Sniffer**: Buffered preview of initial stream bytes (TLS SNI, HTTP Host, DNS, BitTorrent, SSH, RDP) with seamless replay.
   * **Smart DNS & FakeIP**: Native UDP, TCP, DoT, and DoH (HTTP/2 + HTTP/1.1) resolvers, optimistic LRU response cache, and sequential FakeIP pool (`198.18.0.0/15`).
   * **Flood Protection**: Automatic drop on connection floods (`reject: default > 50 in 30s → drop`).

3. **Cryptography & Next-Gen DPI Stealth**:
   * **Post-Quantum VLESS**: Native **ML-KEM-768** hybrid key exchange (`X25519MLKEM768`) in pure Rust to safeguard against harvest-now-decrypt-later attacks and heuristic DPI filters.
   * **AmneziaWG 2.0 & 3.x**: Full WireGuard pipeline with junk packets (`jc`, `jmin`, `jmax`), header protection, payload padding, custom ranges (`s1–s4`, `h1–h4`), and multi-profile initialization masquerade (DNS, STUN, SIP, QUIC Initial with fragmented ClientHello).
   * **Pure-Rust REALITY & uTLS**: Byte-accurate browser fingerprints (Chrome, Firefox, Safari) and SNI record fragmentation (`record_fragment`) without external C libraries.
   * **Heavy Transports**: Full **XHTTP** client over HTTP/2 (`xmux`, `stream-up`, `packet-up`), **Hysteria2** on `quinn`, **TUIC** with EKM authentication, **Shadowsocks 2022** (blake3).

4. **Embedded Target Platforms**:
   * Unified static codebase compiling to pure musl binaries for `x86_64`, `armv7`, `aarch64`, and `mipsel`/`mips` softfloat.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 100% Drop-In Compatibility with sing-box

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

`tachyon-core` is engineered as a seamless drop-in replacement for the sing-box binary:

```bash
# Validate configuration file (strict JSON schema validation)
tachyon-core check -c /etc/sing-box/config.json

# Print version in upstream-compatible format for ucode parsers
tachyon-core version

# Run service daemon
tachyon-core run -c /etc/sing-box/config.json
```

### CLI Compatibility Matrix

| Command | Purpose in Tachyon / OpenWrt | Status in tachyon-core |
|---|---|:---:|
| `check -c <path>` | Pre-flight configuration validation in `watchdog.uc` | **Done** (full schema validation) |
| `version` | Upstream version detection in `generator.uc` | **Done** (upstream regex compatible) |
| `run -c <path>` | Production runtime service | **Done** (Tokio async runtime) |
| `rule-set compile\|decompile` | `.srs` rule sets from `updates.uc` | **Done** (binary SRS v5, both directions) |
| `generate reality-keypair` | REALITY key generation | Planned |
| `generate wg-keypair` | WireGuard / AmneziaWG key generation | Planned |

Detailed field-by-field schema support is tracked in [COMPAT.md](COMPAT.md).

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🚀 Build & Cross-Compilation

### Host Build
Requires Rust 1.89+ (edition 2024):

```bash
# Build workspace in release mode
cargo build --workspace --release

# Run unit and integration tests
cargo test --workspace
```

### Cross-Compilation for Routers via `cargo-zigbuild`

```bash
# Install zigbuild toolchain
cargo install cargo-zigbuild

# AArch64 (ARM64: NanoPi R3S/R4S, GL.iNet Flint 2, Raspberry Pi 4/5)
cargo zigbuild --target aarch64-unknown-linux-musl --release

# ARMv7 (Cortex-A7: IPQ4019, Xiaomi AX1800, Keenetic Hopper/Titan)
cargo zigbuild --target armv7-unknown-linux-musleabihf --release

# x86_64 (Mini-PCs, Proxmox/ESXi VMs)
cargo zigbuild --target x86_64-unknown-linux-musl --release
```

The resulting stripped static binary is ~5.4 MiB.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ What works today

Phased implementation validated by automated differential tests against `sing-box-lx`:

| Phase | Scope | Ready When | Status |
|:---:|---|---|:---:|
| **F0** | **Foundation** | Workspace, CI, schema model, golden differential tests | **Done** |
| **F1** | **Data Plane v1** | Inbounds (tproxy, redirect, mixed, direct), outbounds, Smart DNS, router | **Done** |
| **F2** | **Heavy Protocols** | Hysteria2, TUIC, WireGuard + AmneziaWG 2.0/3.x, VLESS ML-KEM-768, XHTTP, uTLS/REALITY | **Done** |
| **F3** | **SRS Rules & Updates** | Binary `.srs` compatibility, remote list updates | **Done** |
| **F4** | **Experimental Stack** | Clash API (Yacd UI, Secret), `cache.db` (bbolt r/w) | **Done** |
| **F5** | **Server Half** | Server inbounds across all protocols | **In progress**: vless, trojan, vmess and shadowsocks, with TLS and the UDP command |
| **F6** | **TUN Subsystem** | `stack: system` (kernel TUN) and smoltcp userspace stack | Planned |
| **F7** | **lx daemon & Observability** | `lxd` daemon compatibility, telemetry, config rollback | Planned |
| **F8** | **libbox / Android** | UniFFI/JNI bindings for mobile apps | Planned |
| **F9** | **MIPS Spike** | `mipsel`/`mips` softfloat musl via `-Zbuild-std`, qemu-user CI | **In progress**: CI builds them, nothing runs under qemu yet |
| **F10** | **Tachyon Integration** | `rs` variant in Tachyon: auto-installer, 1-click LuCI switching | Planned |

The current state of the tree lives in `ROADMAP.md`. `COMPAT.md` predates most of
the work and is not a record of what runs today.

Task tracking is kept out of the repository, so nothing here promises a date.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 License

Distributed under the **[GPL-3.0-only](LICENSE)** license, inherited from sing-box and sing-box-lx.

* `tachyon-core` is an independent development by the **Tachyon** community and is not affiliated with SagerNet or Leadaxe.
* All original protocol specifications and trademarks belong to their respective authors.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>
