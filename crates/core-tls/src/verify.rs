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

    /// The REALITY auth key, once the key exchange has produced one.
    ///
    /// A REALITY server is trusted *because of* that key, and the key only
    /// exists after the hello went out, so it cannot be a constructor argument.
    /// The default does nothing, which is the right answer for every verifier
    /// that does not care.
    fn set_reality_auth_key(&self, _auth_key: &[u8; 32]) {}

    /// Did the leaf's key sign these bytes with that scheme?
    fn verify_handshake_signature(
        &self,
        signed: &[u8],
        leaf: &CertificateDer<'_>,
        scheme: u16,
        signature: &[u8],
    ) -> io::Result<()>;
}

/// The verifier a config with `insecure: true` asks for: the chain is not
/// checked. It is a named type rather than a flag on [`WebpkiVerifier`] so that
/// "no verification" is always a decision somebody wrote down.
#[derive(Debug)]
pub struct AcceptsAnything;

impl CertVerifier for AcceptsAnything {
    fn verify_chain(
        &self,
        _leaf: &CertificateDer<'_>,
        _chain: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn verify_handshake_signature(
        &self,
        _signed: &[u8],
        _leaf: &CertificateDer<'_>,
        _scheme: u16,
        _signature: &[u8],
    ) -> io::Result<()> {
        Ok(())
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_der() -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/certs/localhost.crt");
        let pem = std::fs::read(path).expect("the certificate fixture");
        rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..]))
            .next()
            .expect("one certificate")
            .expect("it parses")
            .to_vec()
    }

    /// The signature really is the third element of the outer sequence. The
    /// fixture is ECDSA P-256, so what comes out has to be a well-formed DER
    /// SEQUENCE of exactly two INTEGERs -- a walk that was off by one byte
    /// would not come out like that.
    #[test]
    fn the_signature_comes_out_of_the_certificate() {
        let signature = certificate_signature(&fixture_der()).expect("the signature");
        let mut body = Der::new(&signature);
        let mut integers = Der::new(body.take(0x30).expect("a SEQUENCE"));
        let first = integers.take(0x02).expect("an INTEGER");
        let second = integers.take(0x02).expect("a second INTEGER");
        assert!(integers.is_empty(), "two INTEGERs and nothing else");
        assert!(!first.is_empty() && !second.is_empty());
    }

    /// And the walk refuses rather than guessing: a short buffer, a wrong tag.
    #[test]
    fn a_malformed_certificate_is_refused() {
        let der = fixture_der();
        assert!(certificate_signature(&der[..20]).is_err());
        assert!(certificate_signature(&[]).is_err());
        let mut wrong = der.clone();
        wrong[0] = 0x31;
        assert!(certificate_signature(&wrong).is_err());
    }

    /// The leaf here is RSA, so there is no Ed25519 key in it -- which is the
    /// point: a REALITY check on a certificate of the wrong type has to fall
    /// through to the ordinary one rather than trust it.
    #[test]
    fn an_rsa_certificate_has_no_ed25519_key() {
        let cert = rustls::pki_types::CertificateDer::from(fixture_der());
        let spki = webpki::EndEntityCert::try_from(&cert)
            .expect("the certificate parses")
            .subject_public_key_info();
        assert!(ed25519_public_key(&spki).is_none());
    }

    /// The rule itself, on the two byte strings it reads: the leaf's Ed25519 key
    /// HMAC'd under the auth key has to equal the leaf's own signature.
    #[test]
    fn the_reality_rule_is_an_hmac_of_the_key_under_the_auth_key() {
        let auth = [1u8; 32];
        let public = [2u8; 32];
        assert_eq!(hmac_sha512(&auth, &public).len(), 64);
        assert_eq!(hmac_sha512(&auth, &public), hmac_sha512(&auth, &public));
        assert_ne!(
            hmac_sha512(&auth, &public),
            hmac_sha512(&[3u8; 32], &public)
        );
        assert_ne!(hmac_sha512(&auth, &public), hmac_sha512(&auth, &[4u8; 32]));
    }
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

/// A REALITY server fronts a site it does not own, so its certificate chains to
/// nothing anybody trusts. It proves itself with a key the config named
/// instead: the X25519 exchange with the server's public key produced an auth
/// key, and the leaf is trusted when its own Ed25519 key, HMAC'd under that auth
/// key, equals the leaf's own signature. Anything else falls through to the
/// ordinary chain check, so a certificate that does happen to chain still
/// works.
#[derive(Debug)]
pub struct RealityVerifier {
    fallback: Box<dyn CertVerifier>,
    auth_key: std::sync::Mutex<Option<[u8; 32]>>,
}

impl RealityVerifier {
    pub fn new(fallback: Box<dyn CertVerifier>) -> Self {
        RealityVerifier {
            fallback,
            auth_key: std::sync::Mutex::new(None),
        }
    }
}

impl CertVerifier for RealityVerifier {
    fn set_reality_auth_key(&self, auth_key: &[u8; 32]) {
        if let Ok(mut slot) = self.auth_key.lock() {
            *slot = Some(*auth_key);
        }
    }

    fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
    ) -> io::Result<()> {
        let auth_key = self.auth_key.lock().ok().and_then(|slot| *slot);
        match auth_key {
            Some(key) => {
                let der = webpki::EndEntityCert::try_from(leaf)
                    .map_err(|e| bad(format!("the leaf certificate does not parse: {e}")))?
                    .subject_public_key_info();
                let Some(public) = ed25519_public_key(&der) else {
                    return self.fallback.verify_chain(leaf, chain, server_name);
                };
                let signature = certificate_signature(leaf)
                    .map_err(|e| bad(format!("the leaf signature: {e}")))?;
                if hmac_sha512(&key, &public) == signature {
                    Ok(())
                } else {
                    // not the server we named: let the ordinary answer stand
                    self.fallback.verify_chain(leaf, chain, server_name)
                }
            }
            None => self.fallback.verify_chain(leaf, chain, server_name),
        }
    }

    fn verify_handshake_signature(
        &self,
        signed: &[u8],
        leaf: &CertificateDer<'_>,
        scheme: u16,
        signature: &[u8],
    ) -> io::Result<()> {
        // a REALITY server signs the handshake with the very key it borrowed, so
        // this check is the same one every TLS client makes
        self.fallback
            .verify_handshake_signature(signed, leaf, scheme, signature)
    }
}

/// `HMAC-SHA512` under `key` over `message`.
fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// The 32-byte Ed25519 key inside a SubjectPublicKeyInfo, or `None` for any
/// other algorithm -- a REALITY leaf is Ed25519, and anything else is somebody
/// else's certificate.
fn ed25519_public_key(spki: &[u8]) -> Option<[u8; 32]> {
    // OID 1.3.101.112 in bytes, then a NULL, then the key in a BIT STRING whose
    // first content byte counts the unused bits
    const ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let at = spki
        .windows(ED25519.len())
        .position(|window| window == ED25519)?;
    let mut reader = Der::new(&spki[at + ED25519.len()..]);
    reader.take(0x05).ok()?; // the algorithm's NULL
    let mut bits = Der::new(reader.take(0x03).ok()?);
    bits.take(0x00).ok()?; // no unused bits
    bits.take_remaining().try_into().ok()
}

/// The signature a certificate carries: the third element of the outer
/// SEQUENCE, as raw bytes out of its BIT STRING.
///
/// Hand-rolled rather than pulled from a crate: it is four reads of a
/// length-prefixed structure, and this project does not take a dependency to
/// look at one field.
fn certificate_signature(der: &[u8]) -> io::Result<Vec<u8>> {
    let mut outer = Der::new(der);
    let mut body = Der::new(outer.take(0x30)?);
    body.take(0x30).ok(); // tbsCertificate
    body.take(0x30).ok(); // signatureAlgorithm
    let bits = body.take(0x03)?;
    if bits.first() != Some(&0x00) {
        return Err(bad("a signature with unused bits is not a signature"));
    }
    Ok(bits[1..].to_vec())
}

/// Just enough DER to walk one level of a structure: a tag, a definite length,
/// and the content.
struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The content of the next element, which must carry `tag`.
    fn take(&mut self, tag: u8) -> io::Result<&'a [u8]> {
        if self.data.first().copied() != Some(tag) {
            return Err(bad(format!("expected tag {tag:#04x} in DER")));
        }
        // the length is counted from its own first byte, which is one past the tag
        let (len, head) = der_length(&self.data[1..])?;
        let start = 1 + head;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| bad("a DER length runs past the buffer"))?;
        let content = &self.data[start..end];
        self.data = &self.data[end..];
        Ok(content)
    }

    fn take_remaining(&mut self) -> &'a [u8] {
        let rest = self.data;
        self.data = &[];
        rest
    }
}

/// The length at the front of `data` and how many bytes it took.
fn der_length(data: &[u8]) -> io::Result<(usize, usize)> {
    let first = *data.first().ok_or_else(|| bad("a DER length is missing"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 {
        return Err(bad("a DER length is indefinite or absurd"));
    }
    let bytes = data
        .get(1..1 + count)
        .ok_or_else(|| bad("a DER length runs past the buffer"))?;
    let mut len = 0usize;
    for byte in bytes {
        len = (len << 8) | *byte as usize;
    }
    Ok((len, 1 + count))
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
