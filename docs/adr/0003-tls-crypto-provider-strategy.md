# ADR 0003: TLS crypto provider strategy (ring does not support MIPS)

Date: 2026-09-23

## Context

`ring` and `aws-lc-rs` — the two rustls providers — do not target 32-bit MIPS
(OpenWrt's old routers: mipsel_24kc/mips, softfloat musl). A full-parity core
must still do TLS/REALITY/QUIC there. Spinning a separate crypto stack per
arch would fork the codebase.

## Decision

- Abstract crypto behind the rustls `CryptoProvider` interface from day one.
- **Default provider: pure Rust ("RustCrypto")** — `aes-gcm`, `chacha20poly1305`,
  `sha2`, `hmac`, `hkdf`, `x25519-dalek`, `ed25519-dalek`, `p256`, `ml_kem`.
  These compile for every tier-2/tier-3 target we care about (x86_64, armv7,
  aarch64, mips/mipsel softfloat) with no assembly and no C toolchain coupling.
- Optional cargo feature `ring-asm` enables `ring` as a faster provider on the
  arches it supports (x86/x86_64/arm/aarch64); it is **off for MIPS builds**
  and never required for correctness.
- System OpenSSL (`openssl` crate) is rejected as the default: it makes the
  router binary depend on `libssl.so` and drags version skew across OpenWrt
  releases. Kept only as a documented escape hatch, not built by default.

## Consequences

- All TLS/QUIC code paths must go through the provider abstraction — no
  direct `ring::` imports in protocol crates (enforced by code review;
  later `cargo deny` ban list).
- Performance on MIPS relies on portable software AES/SHA — same class of
  cost as the Go reference; QUIC throughput on softfloat is a known limit,
  measured in F9.
- F0 spike exit criterion: one TLS 1.3 handshake completed in tests with the
  pure-Rust provider against a real endpoint.
