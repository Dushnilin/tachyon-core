# ADR 0002: Router-first build strategy

Date: 2026-09-23

## Context

Target devices are OpenWrt routers, including old ones with small flash (often
mipsel_24kc/mips, softfloat musl). Rust has no prebuilt MIPS artifacts (tier 3),
`ring`/`aws-lc-rs` do not support MIPS, and gvisor has no Rust equivalent for a
userspace TCP stack.

## Decision

- Ship **x86_64 / armv7 / aarch64 musl** first (tier-2 friendly targets), MIPS
  lands as a dedicated spike (F9) with nightly `-Zbuild-std` and a custom
  mips32r2 softfloat musl target JSON.
- Abstract the TLS crypto provider from day one so MIPS can fall back to the
  system OpenSSL (`openssl` crate) or a pure-Rust provider when ring is
  unavailable.
- For TUN, implement `stack: system` (kernel TUN) as the primary path; the
  userspace stack is a later phase built on `smoltcp`, with divergence from
  gvisor documented in COMPAT.md.
- Enforce size/RAM budgets in CI: stripped binary ≤ 12 MiB (stretch 8 MiB),
  reference-config startup RSS ≤ 15 MiB.

## Consequences

- Release profile: `opt-level = "z"`, LTO, `codegen-units = 1`, `panic = "abort"`,
  `strip = "symbols"`.
- Cargo feature gates mirror lx build tags; a `tiny` profile drops the server
  half, lxd and clash UI assets for flash-constrained devices.
