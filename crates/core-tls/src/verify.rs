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

    /// The two shapes an Ed25519 SubjectPublicKeyInfo comes in, and the second is
    /// the one that matters: RFC 8410 says the algorithm's parameters are absent,
    /// and Go's `x509` -- which is what a REALITY server's certificate is built by
    /// -- leaves them out. Requiring the NULL that RFC 5758 stacks add means
    /// finding no key in a perfectly good one, and then falling through to a chain
    /// check on a certificate nobody signed.
    #[test]
    fn an_ed25519_key_is_found_with_or_without_the_algorithms_null() {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("entropy");
        // BIT STRING: tag, length, the unused-bit count, the key
        let mut bits = vec![0x03, 0x21, 0x00];
        bits.extend_from_slice(&key);

        // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }
        let without_null = [
            vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70],
            bits.clone(),
        ]
        .concat();
        assert_eq!(
            ed25519_public_key(&without_null),
            Some(key),
            "the shape Go emits"
        );

        // the same, with the NULL the other half of the world adds
        let with_null = [
            vec![
                0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00,
            ],
            bits,
        ]
        .concat();
        assert_eq!(
            ed25519_public_key(&with_null),
            Some(key),
            "the RFC 5758 shape"
        );
    }

    /// And a key of another algorithm is not an Ed25519 key, however it is spelled.
    #[test]
    fn another_algorithm_is_not_an_ed25519_key() {
        // P-256: OID 1.2.840.10045.2.1 with a 65-byte uncompressed point
        let spki = [
            vec![
                0x30, 0x4a, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            ],
            vec![0x03, 0x42, 0x00],
            vec![4u8; 65],
        ]
        .concat();
        assert!(ed25519_public_key(&spki).is_none());
    }

    /// The leaf here is not Ed25519, so there is no key in it -- which is the
    /// point: a REALITY check on a certificate of the wrong type has to fall
    /// through to the ordinary one rather than trust it.
    #[test]
    fn a_certificate_of_another_algorithm_has_no_ed25519_key() {
        let cert = rustls::pki_types::CertificateDer::from(fixture_der());
        let spki = webpki::EndEntityCert::try_from(&cert)
            .expect("the certificate parses")
            .subject_public_key_info();
        assert!(ed25519_public_key(&spki).is_none());
    }

    /// The verdict is what a caller has to report, because a REALITY server that
    /// does not recognise us hands us the site it hides behind and the handshake
    /// still succeeds. So: unknown before the check, and a reason after it.
    #[test]
    fn the_verdict_says_why_a_certificate_was_not_taken_on_reality_terms() {
        let der = fixture_der();
        let leaf = rustls::pki_types::CertificateDer::from(der);
        let name = ServerName::try_from("example.com").expect("a name");
        let verifier = RealityVerifier::new(Box::new(AcceptsAnything));
        assert_eq!(verifier.verdict(), "not checked yet");

        // no auth key yet: the key exchange has not run, so this cannot be REALITY
        verifier
            .verify_chain(&leaf, &[], &name)
            .expect("the fallback accepts anything");
        assert_eq!(verifier.verdict(), "the key exchange produced no auth key");

        // with one, the certificate here is ECDSA, so there is no Ed25519 key to
        // check against -- which is exactly the "not the node we named" case
        verifier.set_reality_auth_key(&[9u8; 32]);
        verifier
            .verify_chain(&leaf, &[], &name)
            .expect("the fallback accepts anything");
        assert_eq!(verifier.verdict(), "the certificate carries no Ed25519 key");
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
#[derive(Debug, Clone)]
pub struct RealityVerifier {
    fallback: std::sync::Arc<dyn CertVerifier>,
    auth_key: std::sync::Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    verdict: std::sync::Arc<std::sync::Mutex<&'static str>>,
}

impl RealityVerifier {
    pub fn new(fallback: Box<dyn CertVerifier>) -> Self {
        RealityVerifier {
            fallback: std::sync::Arc::from(fallback),
            auth_key: std::sync::Arc::new(std::sync::Mutex::new(None)),
            verdict: std::sync::Arc::new(std::sync::Mutex::new("not checked yet")),
        }
    }

    /// What the last certificate check concluded, in one line.
    ///
    /// A REALITY server that does not recognise its client does not fail: it
    /// hands the connection to the site it hides behind, and the client ends up
    /// talking TLS to that site with a perfectly valid certificate for it. Nothing
    /// about that looks wrong from here, which is why this exists -- a caller can
    /// put one line in a log instead of leaving the user with a tunnel that
    /// quietly goes somewhere else.
    pub fn verdict(&self) -> &'static str {
        self.verdict.lock().map(|v| *v).unwrap_or("unreadable")
    }

    fn set_verdict(&self, what: &'static str) {
        if let Ok(mut slot) = self.verdict.lock() {
            *slot = what;
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
                    self.set_verdict("the certificate carries no Ed25519 key");
                    return self.fallback.verify_chain(leaf, chain, server_name);
                };
                let signature = certificate_signature(leaf)
                    .map_err(|e| bad(format!("the leaf signature: {e}")))?;
                if hmac_sha512(&key, &public) == signature {
                    self.set_verdict("the borrowed certificate checks out");
                    Ok(())
                } else {
                    // not the server we named: let the ordinary answer stand
                    self.set_verdict("the borrowed certificate is not signed under our auth key");
                    self.fallback.verify_chain(leaf, chain, server_name)
                }
            }
            None => {
                self.set_verdict("the key exchange produced no auth key");
                self.fallback.verify_chain(leaf, chain, server_name)
            }
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
///
/// The algorithm's parameters are optional and the two halves of the world
/// disagree: RFC 8410 says they should be *absent*, and Go's `x509` -- which is
/// what a REALITY server's certificate comes from -- leaves them out. Requiring
/// the NULL that RFC 5758 stacks add means silently finding no key, and then
/// falling through to a chain check on a certificate nobody signed.
fn ed25519_public_key(spki: &[u8]) -> Option<[u8; 32]> {
    // OID 1.3.101.112 in bytes, then the key in a BIT STRING whose first content
    // byte counts the unused bits
    const ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let at = spki
        .windows(ED25519.len())
        .position(|window| window == ED25519)?;
    let mut after = &spki[at + ED25519.len()..];
    if after.first() == Some(&0x05) {
        let mut null = Der::new(after);
        null.take(0x05).ok()?;
        after = null.take_remaining();
    }
    let mut reader = Der::new(after);
    let content = reader.take(0x03).ok()?;
    // The first content byte of a BIT STRING counts the unused bits, and a key
    // leaves none of them. It is a content byte, not a length, so it is skipped
    // as one -- reading it as a length is how this returned None for every
    // certificate, including the good ones.
    content.strip_prefix(&[0x00])?.try_into().ok()
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
    pub fn mozilla_store() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots
    }

    /// The Mozilla root store, which is what the reference ships with.
    pub fn mozilla_roots() -> io::Result<Self> {
        Self::new(Arc::new(Self::mozilla_store()))
    }

    /// The underlying rustls verifier, for [PinVerifier] to wrap.
    pub fn into_inner(self) -> Arc<dyn ServerCertVerifier> {
        self.chain
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

/// Trust by certificate fingerprint rather than by chain.
///
/// Two pins exist because they answer two different questions.
/// `certificate_sha256` hashes the whole DER end-entity certificate, which is
/// what a proxy link carries and what upstream added in 1.15.
/// `certificate_public_key_sha256` hashes only the SPKI, so a reissued
/// certificate with the same key still matches - and it is the older field,
/// present before 1.15 and the only one lx accepts. Neither can stand in for
/// the other: they are different byte strings over the same certificate.
///
/// The chain check still runs. A pin narrows what is trusted, it does not widen
/// it: presenting a pinned certificate that does not chain to a known root is
/// exactly the case a pin exists to catch.
pub struct PinVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// SHA-256 over the whole DER leaf, when pinned.
    certificate_sha256: Vec<[u8; 32]>,
    /// SHA-256 over the SPKI, when pinned.
    public_key_sha256: Vec<[u8; 32]>,
}

impl PinVerifier {
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        certificate_sha256: Vec<[u8; 32]>,
        public_key_sha256: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            inner,
            certificate_sha256,
            public_key_sha256,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.certificate_sha256.is_empty() && self.public_key_sha256.is_empty()
    }
}

impl Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinVerifier")
            .field("certificate_sha256", &self.certificate_sha256.len())
            .field("public_key_sha256", &self.public_key_sha256.len())
            .finish()
    }
}

/// SHA-256 over the certificate's SubjectPublicKeyInfo, DER bytes and all.
///
/// The SPKI is not a field we can address directly: a certificate is
/// `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }` and the
/// SPKI sits inside `tbsCertificate`. So this walks the DER tags far enough to
/// reach it and hashes the whole element, header included, which is what the
/// reference hashes too - hashing a stripped inner slice would produce a
/// different digest and never match a value written by anything else.
pub fn spki_sha256(der: &[u8]) -> io::Result<[u8; 32]> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (cert, _) = der_element(der, 0).ok_or_else(|| bad("certificate does not parse"))?;
    // Walk into the Certificate's value first: its length covers the whole
    // element, so re-parsing from offset 0 would hand back the Certificate
    // itself and the next "element" would be the tbs's own length bytes.
    let (cert_body, _) = der_content(cert).ok_or_else(|| bad("certificate does not parse"))?;
    let (tbs, _) = der_element(cert_body, 0).ok_or_else(|| bad("tbsCertificate does not parse"))?;
    let (body, _) = der_content(tbs).ok_or_else(|| bad("tbsCertificate does not parse"))?;

    // The fields of tbsCertificate, in order:
    //   [0] version (EXPLICIT, optional), serialNumber INTEGER,
    //   signature AlgorithmIdentifier, issuer Name, validity Validity,
    //   subject Name, subjectPublicKeyInfo.
    // So the SPKI is the 7th element when a version is present and the 6th when
    // it is not. Counting to it positionally rather than matching tags is what
    // keeps this honest: issuer, subject and validity are all SEQUENCE, so a
    // tag match finds the wrong one of the three.
    let versioned = body.first().is_some_and(|t| *t == 0xa0);
    let want = if versioned { 6 } else { 5 };

    let mut rest = body;
    for index in 0..=want {
        let (element, next) = der_element(rest, 0).ok_or_else(|| {
            bad("certificate pin: tbsCertificate ends before subjectPublicKeyInfo")
        })?;
        if index == want {
            let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(element).into();
            return Ok(digest);
        }
        rest = next;
    }

    Err(bad(
        "certificate pin: subjectPublicKeyInfo not found in the certificate",
    ))
}

/// The value part of a DER element, i.e. the element without its tag and length.
fn der_content(element: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *element.get(1)?;
    let value_at = if first & 0x80 == 0 {
        2usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        2 + count
    };
    Some((element.get(value_at..)?, &[]))
}

/// One DER element starting at : (the whole element, the rest after it).
/// Returns the element *including* its tag and length, because that is what the
/// SPKI hash covers.
fn der_element(input: &[u8], at: usize) -> Option<(&[u8], &[u8])> {
    let first = *input.get(at + 1)?;
    let len;
    let value_at;
    if first & 0x80 == 0 {
        len = first as usize;
        value_at = at + 2;
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut acc = 0usize;
        for i in 0..count {
            acc = (acc << 8) | *input.get(at + 2 + i)? as usize;
        }
        len = acc;
        value_at = at + 2 + count;
    }
    let value_end = value_at.checked_add(len)?;
    let element = input.get(at..value_end)?;
    let rest = input.get(value_end..)?;
    Some((element, rest))
}

impl CertVerifier for PinVerifier {
    fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
    ) -> io::Result<()> {
        self.inner
            .verify_server_cert(leaf, chain, server_name, &[], UnixTime::now())
            .map_err(|e| bad(format!("certificate chain rejected: {e}")))?;

        let der = leaf.as_ref();
        if !self.certificate_sha256.is_empty() {
            let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(der).into();
            if !self.certificate_sha256.contains(&digest) {
                return Err(bad(
                    "server certificate does not match tls.certificate_sha256",
                ));
            }
        }
        if !self.public_key_sha256.is_empty() {
            let digest = spki_sha256(der)?;
            if !self.public_key_sha256.contains(&digest) {
                return Err(bad(
                    "server public key does not match tls.certificate_public_key_sha256",
                ));
            }
        }
        Ok(())
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
