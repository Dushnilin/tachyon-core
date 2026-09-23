# ADR 0004: uTLS-style fingerprints and REALITY client

Date: 2026-09-23

## Context

Parity with sing-box-lx requires:

- TLS ClientHello fingerprints (`tls.utls.fingerprint`: chrome, firefox,
  safari, …), including hybrid `X25519MLKEM768` key share (`key_share:
  classical | hybrid`) that current Xray servers demand;
- the REALITY client handshake (custom key share, `short_id`, auth,
  ClientHello fragmentation / `record_fragment`).

There is no maintained 1:1 port of refraction-networking/utls to Rust; the
ecosystem splits between CGO/C-backed impersonation clients (bad for MIPS,
defeats the static-musl goal) and pure-Rust Hello builders.

## Decision

- **Pure-Rust ClientHello builder**: assemble the TLS 1.3 ClientHello
  ourselves (byte-level control over extension order and key_share) with
  presets vendored from the sing-box-lx/utls-lx fingerprint tables
  (GPL-3.0 compatible: this project is GPL-3.0).
- **Hybrid post-quantum share** via the pure-Rust `ml_kem` crate composed
  with `x25519-dalek` (X25519MLKEM768 = ML-KEM-768 share prepended, as
  Xray/utls encode it).
- **REALITY client** implemented as an explicit handshake over our Hello
  builder + rustls for the established session (server auth via the
  reality public key, `short_id` match, then transparent splice).
- Rejected: `tls-client`/boring-based impersonation (pulls C, no MIPS),
  wrapping a bundled utls fork through FFI (build complexity, flash cost).

## Consequences

- F0 spike exit criterion: fingerprint bytes for at least `chrome` match the
  reference on a captured ClientHello diff, and a REALITY handshake completes
  against a live Xray ≥ v26.9.9 test server (tracked as F2 verification too).
- Fragmentation (`fragment`, `record_fragment`) is implemented on the same
  layer, so REALITY fragmentation support comes for free (leadaxe feature 017).
- Preset table maintenance: synced from upstream tables when fingerprints
  drift; divergence noted in COMPAT.md.
