//! How a server's certificate is trusted.
//!
//! Two separate questions, deliberately two separate methods: does the chain
//! lead somewhere we trust, and did the holder of the leaf key sign the
//! handshake. REALITY replaces the first -- the server presents a certificate
//! borrowed from the site it fronts, and trust comes from an HMAC of its
//! Ed25519 key -- while the second stays exactly as it is, because a REALITY
//! server signs the handshake with that same borrowed key.

use std::fmt::Debug;
use std::io;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};

/// The trust decision for one connection. There is no default: a caller has to
/// say how it trusts a server, so "no verification" cannot happen by omission.
pub trait CertVerifier: Debug + Send + Sync {
    /// Does the leaf chain to a trust anchor and fit the name we asked for?
    fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
    ) -> io::Result<()>;

    /// Did the leaf's key sign these bytes with that scheme?
    fn verify_handshake_signature(
        &self,
        signed: &[u8],
        leaf: &CertificateDer<'_>,
        scheme: u16,
        signature: &[u8],
    ) -> io::Result<()>;
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The verification algorithm for a TLS signature scheme, or `None` for one we do
/// not accept. The table is the provider's, so a scheme the provider cannot
/// check is not accepted here either.
fn algorithm_for(scheme: u16) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    core_crypto::verify::ALGORITHMS
        .mapping
        .iter()
        .find(|(candidate, _)| u16::from(*candidate) == scheme)
        .and_then(|(_, algorithms)| algorithms.first().copied())
}

/// The ordinary case: a real chain to a real trust anchor, verified by
/// `rustls-webpki`. The chain check goes through rustls' verifier; the handshake
/// signature is checked here, because rustls keeps the constructor of the
/// structure that carries it private and there is no other way in.
pub struct WebpkiVerifier {
    chain: Arc<dyn ServerCertVerifier>,
}

impl WebpkiVerifier {
    pub fn new(roots: Arc<RootCertStore>) -> io::Result<Self> {
        let chain = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots,
            Arc::new(core_crypto::provider()),
        )
        .build()
        .map_err(|e| bad(format!("cannot build the webpki verifier: {e:?}")))?;
        Ok(WebpkiVerifier { chain })
    }

    /// The Mozilla root store, which is what the reference ships with.
    pub fn mozilla_roots() -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::new(Arc::new(roots))
    }
}

impl Debug for WebpkiVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebpkiVerifier")
    }
}

impl CertVerifier for WebpkiVerifier {
    fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
    ) -> io::Result<()> {
        self.chain
            .verify_server_cert(leaf, chain, server_name, &[], UnixTime::now())
            .map(|_| ())
            .map_err(|e| bad(format!("certificate chain rejected: {e}")))
    }

    fn verify_handshake_signature(
        &self,
        signed: &[u8],
        leaf: &CertificateDer<'_>,
        scheme: u16,
        signature: &[u8],
    ) -> io::Result<()> {
        let algorithm = algorithm_for(scheme).ok_or_else(|| {
            bad(format!(
                "signature scheme {scheme:#06x} is not one we accept"
            ))
        })?;
        let cert = webpki::EndEntityCert::try_from(leaf)
            .map_err(|e| bad(format!("the leaf certificate does not parse: {e}")))?;
        cert.verify_signature(algorithm, signed, signature)
            .map_err(|e| bad(format!("CertificateVerify signature rejected: {e}")))
    }
}
