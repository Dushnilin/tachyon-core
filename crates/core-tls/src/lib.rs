//! TLS integration layer (F0 spike ADR-0003/0004).
//!
//! The default provider is pure Rust (`rustls-rustcrypto`) so the same binary
//! builds for MIPS softfloat targets where `ring`/`aws-lc-rs` do not exist.

pub use rustls;

/// Install the pure-Rust crypto provider as the process-wide rustls default.
///
/// Idempotent: returns `true` when this call performed the installation.
pub fn install_default_provider() -> bool {
    rustls_rustcrypto::provider().install_default().is_ok()
}
