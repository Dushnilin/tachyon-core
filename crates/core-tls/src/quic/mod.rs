//! Ring-free QUIC crypto backend for quinn.
//!
//! Port of `quinn-proto`'s `crypto/rustls.rs` + `crypto/ring_like.rs`, which
//! are feature-gated behind `rustls-ring`/`ring` upstream. With
//! `quinn = { default-features = false }` those modules are not compiled, so
//! we reimplement them over `core-crypto` (pure-Rust rustls provider with
//! `quic: Some(..)` suites) and RustCrypto primitives (`aes-gcm`, `hmac`,
//! `hkdf`). No `ring`, no C.

pub mod rustcrypto;
pub mod rustls_backend;

pub use rustcrypto::{Aes256GcmKey, HandshakeTokenKeyRustCrypto, HmacSha256Key};
pub use rustls_backend::{
    HandshakeData, NoInitialCipherSuite, QuicClientConfig, QuicServerConfig, QuinnHeaderKey,
    QuinnPacketKey, TlsSession, configured_provider, initial_keys, initial_suite_from_provider,
};
