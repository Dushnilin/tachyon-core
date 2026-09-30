//! TLS integration layer (F0 spike ADR-0003/0004).
//!
//! The default provider is pure Rust (`core-crypto`, a vendored
//! `rustls-rustcrypto`/oxitls fork with QUIC support) so the same binary
//! builds for MIPS softfloat targets where `ring`/`aws-lc-rs` do not exist.

pub mod fingerprints;
pub mod hello;
pub mod keyshare;
pub mod quic;
pub mod record;
pub mod tls13;

pub use rustls;

/// Install the pure-Rust crypto provider as the process-wide rustls default.
///
/// Idempotent: returns `true` when this call performed the installation.
pub fn install_default_provider() -> bool {
    core_crypto::provider().install_default().is_ok()
}
