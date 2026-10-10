//! Outbound TLS client: rustls with the pure-Rust crypto provider.
//!
//! uTLS fingerprints and REALITY land in F2 (ADR-0004); uTLS degrades with a
//! warning, REALITY is rejected because silent fallback would be misleading.

use std::io;
use std::sync::Arc;

use core_tls::rustls;
use rustls_pemfile::certs;
use rustls_pemfile::private_key;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::inbound::AnyStream;

const DANGEROUS_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::ED25519,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
];

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        DANGEROUS_SCHEMES.to_vec()
    }
}

/// A uTLS fingerprint, resolved from the name the config used.
#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub name: String,
    pub template: core_tls::hello::Template,
}

/// Read a pin field: one base64 SHA-256, or a list of them, as the reference
/// accepts. The value is the same either way - the field says what is hashed,
/// not how many entries are allowed.
fn decode_pin_list(
    tls: &serde_json::Map<String, Value>,
    field: &str,
    at: &str,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let Some(value) = tls.get(field) else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }

    let mut raw = Vec::new();
    match value {
        Value::Array(items) => {
            for item in items {
                let s = item
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{at}: tls.{field} entries must be strings"))?;
                raw.push(s.to_string());
            }
        }
        Value::String(s) => raw.push(s.clone()),
        other => {
            return Err(anyhow::anyhow!(
                "{at}: tls.{field} must be a string or a list of strings, got {other}"
            ));
        }
    }

    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let bytes = base64_decode(entry).ok_or_else(|| {
            anyhow::anyhow!("{at}: tls.{field} entry {entry:?} is not valid base64")
        })?;
        let len = bytes.len();
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!("{at}: tls.{field} entry {entry:?} is {len} bytes, a SHA-256 pin is 32")
        })?;
        out.push(digest);
    }
    Ok(out)
}

/// Standard base64, with or without padding. The reference writes padded values;
/// a hand-edited config often loses the padding, and rejecting that would make
/// the pin unusable rather than merely untidy.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for c in input.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = TABLE.iter().position(|t| *t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// REALITY: the server's public key and the short id that opens the session id
/// seal. The verification of the borrowed certificate is not part of this yet,
/// which is why enabling it is still refused further down.
#[derive(Clone, Debug)]
pub struct Reality {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: Option<Fingerprint>,
}

#[derive(Clone, Debug)]
pub struct TlsOptions {
    server_name: String,
    insecure: bool,
    disable_sni: bool,
    alpn: Vec<Vec<u8>>,
    min_tls13: bool,
    max_tls12: bool,
    ca_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// `certificate_sha256`: SHA-256 over the whole DER end-entity certificate.
    /// Upstream added this in 1.15; the reference calls the value a "pcs" and it
    /// is what proxy links carry.
    certificate_sha256: Vec<[u8; 32]>,
    /// `certificate_public_key_sha256`: SHA-256 over the SPKI, the public key
    /// alone. A different value from the above, so it is a second field rather
    /// than an older spelling of the first - but the only pin field that exists
    /// before 1.15, and the only one lx accepts.
    certificate_public_key_sha256: Vec<[u8; 32]>,
    /// Our own ClientHello instead of rustls': a captured browser fingerprint
    /// and the handshake written for it.
    fingerprint: Option<Fingerprint>,
    reality: Option<Reality>,
    /// Which stack does the handshake and the record layer. Our own reads
    /// records in place out of a fixed buffer; rustls shifts plaintext between
    /// two of its own buffers, and that came to a third of the client CPU on a
    /// busy websocket. `None` means "decide", see [`TlsOptions::own_stack`].
    stack: Option<bool>,
    fragment: bool,
    cipher_suites: Vec<String>,
}

impl TlsOptions {
    /// SNI / certificate name (config `server_name`, defaulting to the server).
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Parse outbound `tls` options; `None` when TLS is absent or disabled.
    pub fn from_outbound(
        obj: &serde_json::Map<String, Value>,
        server: &str,
        at: &str,
    ) -> anyhow::Result<Option<Self>> {
        let Some(tls) = obj.get("tls").and_then(Value::as_object) else {
            return Ok(None);
        };
        if tls.get("enabled").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }

        let server_name = tls
            .get("server_name")
            .and_then(Value::as_str)
            .unwrap_or(server)
            .to_string();
        let insecure = tls
            .get("insecure")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let disable_sni = tls
            .get("disable_sni")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let alpn = tls
            .get("alpn")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|v| v.as_str().map(str::as_bytes).map(<[u8]>::to_vec))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| anyhow::anyhow!("{at}: tls.alpn entries must be strings"))
            })
            .transpose()?
            .unwrap_or_default();

        let min_tls13 = match tls.get("min_version").and_then(Value::as_str) {
            None | Some("") => false,
            Some("1.2") => false,
            Some("1.3") => true,
            Some(other) => anyhow::bail!("{at}: tls.min_version {other:?} not supported"),
        };
        let max_tls12 = match tls.get("max_version").and_then(Value::as_str) {
            None | Some("") => false,
            Some("1.2") => true,
            Some("1.3") => false,
            Some(other) => anyhow::bail!("{at}: tls.max_version {other:?} not supported"),
        };

        let mut ca_certs = Vec::new();
        if let Some(pem) = tls.get("certificate").and_then(Value::as_str) {
            load_pem_certs(pem.as_bytes(), &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate: {e}"))?;
        }
        if let Some(path) = tls.get("certificate_path").and_then(Value::as_str) {
            let raw = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
            load_pem_certs(&raw, &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
        }

        let certificate_sha256 = decode_pin_list(tls, "certificate_sha256", at)?;
        let certificate_public_key_sha256 =
            decode_pin_list(tls, "certificate_public_key_sha256", at)?;

        let fingerprint = match tls.get("utls").and_then(Value::as_object) {
            Some(u) if u.get("enabled").and_then(Value::as_bool) == Some(true) => {
                let name = u
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .unwrap_or("chrome")
                    .to_string();
                let template = core_tls::fingerprints::by_name(&name).ok_or_else(|| {
                    anyhow::anyhow!("{at}: tls.utls.fingerprint: {name:?} is not a known browser")
                })?;
                Some(Fingerprint { name, template })
            }
            _ => None,
        };
        let reality = match tls.get("reality").and_then(Value::as_object) {
            Some(r) if r.get("enabled").and_then(Value::as_bool) == Some(true) => {
                let public_key =
                    parse_reality_key(r.get("public_key").and_then(Value::as_str).ok_or_else(
                        || anyhow::anyhow!("{at}: tls.reality.public_key is required"),
                    )?)
                    .map_err(|e| anyhow::anyhow!("{at}: tls.reality.public_key: {e}"))?;
                let short_id =
                    parse_short_id(r.get("short_id").and_then(Value::as_str).unwrap_or(""))
                        .map_err(|e| anyhow::anyhow!("{at}: tls.reality.short_id: {e}"))?;
                let fingerprint = match r.get("fingerprint").and_then(Value::as_str) {
                    Some(name) => {
                        let template = core_tls::fingerprints::by_name(name).ok_or_else(|| {
                            anyhow::anyhow!(
                                "{at}: tls.reality.fingerprint: {name:?} is not a known browser"
                            )
                        })?;
                        Some(Fingerprint {
                            name: name.to_string(),
                            template,
                        })
                    }
                    None => None,
                };
                Some(Reality {
                    public_key,
                    short_id,
                    fingerprint,
                })
            }
            _ => None,
        };

        let stack = match tls.get("stack").and_then(Value::as_str) {
            Some("core") | Some("own") => Some(true),
            Some("rustls") => Some(false),
            Some(other) => {
                return Err(anyhow::anyhow!(
                    "{at}: tls.stack: {other:?} is not one of core, own, rustls"
                ));
            }
            None => None,
        };

        let fragment = tls
            .get("fragment")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || tls
                .get("record_fragment")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let cipher_suites = tls
            .get("cipher_suites")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(Self {
            fingerprint,
            reality,
            stack,
            server_name,
            insecure,
            disable_sni,
            alpn,
            min_tls13,
            max_tls12,
            ca_certs,
            certificate_sha256,
            certificate_public_key_sha256,
            fragment,
            cipher_suites,
        }))
    }

    pub async fn connect(&self, stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        self.connect_with_defaults(stream, &[]).await
    }

    /// TLS over any stream — the runtime fetches (rule-sets, providers) may
    /// be dialed through a proxy outbound, so the socket is not a `TcpStream`.
    pub async fn connect_stream<S>(
        &self,
        stream: S,
        default_alpn: &[&[u8]],
    ) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.handshake(stream, default_alpn).await
    }

    /// Like [`connect`], but offers `default_alpn` when the config set none —
    /// transports such as grpc/http need `h2` and sing-box injects it there.
    pub async fn connect_with_defaults(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
    ) -> io::Result<TlsStream<TcpStream>> {
        self.handshake(stream, default_alpn).await
    }

    async fn handshake<S>(&self, stream: S, default_alpn: &[&[u8]]) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.min_tls13 {
            &[&rustls::version::TLS13]
        } else if self.max_tls12 {
            &[&rustls::version::TLS12]
        } else {
            rustls::ALL_VERSIONS
        };
        let alpn: Vec<Vec<u8>> = if !self.alpn.is_empty() {
            self.alpn.clone()
        } else {
            default_alpn.iter().map(|a| a.to_vec()).collect()
        };

        let connector = TlsConnector::from(self.client_config(versions, &alpn)?);
        let name = if self.disable_sni {
            rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::V4(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
            ))
        } else {
            rustls::pki_types::ServerName::try_from(self.server_name.clone()).map_err(|_| {
                io::Error::other(format!("invalid server_name {:?}", self.server_name))
            })?
        };
        connector.connect(name, stream).await
    }

    fn root_store(&self) -> io::Result<rustls::RootCertStore> {
        // No `ca` in the config means "no pin", not "trust nothing": an empty
        // store here failed every DoH query and every plain-rustls handshake
        // with `invalid peer certificate: UnknownIssuer`, so no domain ever
        // resolved. `establish` already fell back to the Mozilla roots.
        if self.ca_certs.is_empty() {
            return Ok(core_tls::verify::WebpkiVerifier::mozilla_store());
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in &self.ca_certs {
            roots
                .add(cert.clone())
                .map_err(|e| io::Error::other(format!("bad CA certificate: {e}")))?;
        }
        Ok(roots)
    }

    /// The `ClientConfig` for these options, shared across connects. Building
    /// one re-parses every CA certificate, which does not belong on the
    /// connect path — the cache key is everything that changes the result.
    fn client_config(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[Vec<u8>],
    ) -> io::Result<Arc<rustls::ClientConfig>> {
        use std::collections::HashMap;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher as _};
        use std::sync::{Mutex, OnceLock};

        type Key = (bool, bool, bool, Vec<Vec<u8>>, Vec<String>, u64);
        static CACHE: OnceLock<Mutex<HashMap<Key, Arc<rustls::ClientConfig>>>> = OnceLock::new();

        let mut ca = DefaultHasher::new();
        for cert in &self.ca_certs {
            cert.as_ref().hash(&mut ca);
        }
        let key = (
            self.min_tls13,
            self.max_tls12,
            self.insecure,
            alpn.to_vec(),
            self.cipher_suites.clone(),
            ca.finish(),
        );
        let cache = CACHE.get_or_init(Mutex::default);
        if let Some(config) = cache.lock().expect("tls config cache").get(&key) {
            return Ok(Arc::clone(config));
        }

        let provider = if !self.cipher_suites.is_empty() {
            let suites: Vec<_> = self
                .cipher_suites
                .iter()
                .filter_map(|s| core_crypto::resolve_cipher_suite(s))
                .collect();
            if !suites.is_empty() {
                Arc::new(core_crypto::provider_with_suites(suites))
            } else {
                Arc::new(core_crypto::provider())
            }
        } else {
            Arc::new(core_crypto::provider())
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| io::Error::other(format!("tls: protocol versions: {e}")))?;
        let mut config = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(self.root_store()?)
                .with_no_client_auth()
        };
        config.alpn_protocols = alpn.to_vec();
        let config = Arc::new(config);
        cache
            .lock()
            .expect("tls config cache")
            .insert(key, Arc::clone(&config));
        Ok(config)
    }

    /// QUIC client config for quinn (hysteria2 / tuic): TLS 1.3 only, early
    /// data on, ALPN from `tls.alpn` or `default_alpn`.
    pub fn quic_config(
        &self,
        default_alpn: &[&[u8]],
    ) -> io::Result<core_tls::quic::QuicClientConfig> {
        let provider = if !self.cipher_suites.is_empty() {
            let suites: Vec<_> = self
                .cipher_suites
                .iter()
                .filter_map(|s| core_crypto::resolve_cipher_suite(s))
                .collect();
            if !suites.is_empty() {
                Arc::new(core_crypto::provider_with_suites(suites))
            } else {
                core_tls::quic::configured_provider()
            }
        } else {
            core_tls::quic::configured_provider()
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| io::Error::other(format!("QUIC TLS provider: {e}")))?;
        let mut config = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(self.root_store()?)
                .with_no_client_auth()
        };
        if !self.alpn.is_empty() {
            config.alpn_protocols = self.alpn.clone();
        } else {
            config.alpn_protocols = default_alpn.iter().map(|a| a.to_vec()).collect();
        }
        config.enable_early_data = true;
        core_tls::quic::QuicClientConfig::try_from_rustls(Arc::new(config))
            .map_err(|e| io::Error::other(format!("QUIC initial suite: {e}")))
    }

    /// The fingerprint this handshake would present, and the REALITY parameters
    /// that go with it, if the config asked for our own ClientHello.
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint
            .as_ref()
            .or_else(|| self.reality.as_ref().and_then(|r| r.fingerprint.as_ref()))
    }

    pub fn reality(&self) -> Option<&Reality> {
        self.reality.as_ref()
    }

    /// Whose TLS does the handshake and the record layer.
    ///
    /// A fingerprint or REALITY settles it: neither can be presented through
    /// rustls. Past that the config decides (`tls.stack`), and by default ours
    /// does, because it decrypts in place out of one fixed buffer where rustls
    /// moves plaintext between two of its own -- on a busy websocket that was a
    /// third of the client CPU. The one thing ours cannot do is TLS 1.2 on the
    /// client, so a config pinned to 1.2 stays on rustls.
    fn own_stack(&self) -> bool {
        if self.fragment {
            return true;
        }
        if self.fingerprint().is_some() {
            return true;
        }
        if let Some(stack) = self.stack {
            return stack;
        }
        !self.max_tls12
    }

    /// Establish the connection, with our own TLS when a fingerprint is
    /// configured and the library's otherwise.
    ///
    /// Both are returned as the same boxed stream, so nothing downstream has to
    /// know which one it got: that is the only reason the signature is this
    /// rather than two functions at every call site.
    pub async fn establish<S>(&self, stream: S, default_alpn: &[&[u8]]) -> io::Result<AnyStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut alpn: Vec<&[u8]> = if self.alpn.is_empty() {
            default_alpn.to_vec()
        } else {
            self.alpn.iter().map(|p| p.as_slice()).collect()
        };
        if alpn.is_empty() && (self.reality.is_some() || self.fingerprint.is_some()) {
            alpn = vec![b"h2", b"http/1.1"];
        }
        if !self.own_stack() {
            return Ok(Box::new(self.connect_stream(stream, default_alpn).await?));
        }
        // With no fingerprint named, present chrome: ours always writes its own
        // hello, so there is a template to pick either way.
        let (name, template) = match self.fingerprint() {
            Some(f) => (f.name.clone(), f.template.clone()),
            None => ("chrome".to_string(), core_tls::fingerprints::chrome()),
        };
        // a REALITY server is trusted by its own borrowed certificate under the
        // auth key, so the ordinary chain check is the fallback, not the answer
        let plain: Box<dyn core_tls::verify::CertVerifier> = if self.insecure {
            Box::new(core_tls::verify::AcceptsAnything)
        } else {
            let roots = if self.ca_certs.is_empty() {
                core_tls::verify::WebpkiVerifier::mozilla_roots()
            } else {
                let mut store = rustls::RootCertStore::empty();
                for cert in &self.ca_certs {
                    store
                        .add(cert.clone())
                        .map_err(|e| io::Error::other(format!("trust store: {e}")))?;
                }
                core_tls::verify::WebpkiVerifier::new(Arc::new(store))
            };
            let base = roots.map_err(|e| io::Error::other(format!("trust store: {e}")))?;
            // A pin narrows what is trusted, so it wraps the chain check rather
            // than replacing it: a pinned certificate that does not chain to a
            // known root is still refused. With no pin configured this stays the
            // plain verifier and the handshake path is unchanged.
            let base: Box<dyn core_tls::verify::CertVerifier> =
                if self.certificate_sha256.is_empty()
                    && self.certificate_public_key_sha256.is_empty()
                {
                    Box::new(base)
                } else {
                    Box::new(core_tls::verify::PinVerifier::new(
                        base.into_inner(),
                        self.certificate_sha256.clone(),
                        self.certificate_public_key_sha256.clone(),
                    ))
                };
            base
        };
        let reality = self.reality.as_ref();
        let seal = reality.map(|r| core_tls::client::RealitySeal {
            public_key: &r.public_key,
            short_id: &r.short_id,
        });
        // Kept as a concrete type so the verdict can be reported: a REALITY server
        // that does not recognise its client answers with the site it hides
        // behind, and the handshake then *succeeds* against a certificate that
        // has nothing to do with the node. Without this line that failure is
        // invisible, and the tunnel simply goes somewhere else.
        let (verifier, reality_verifier): (Box<dyn core_tls::verify::CertVerifier>, _) =
            if reality.is_some() {
                let v = core_tls::verify::RealityVerifier::new(plain);
                (Box::new(v.clone()), Some(v))
            } else {
                (plain, None)
            };
        let cipher_suites: Vec<u16> = self
            .cipher_suites
            .iter()
            .filter_map(|s| core_crypto::resolve_cipher_suite_id(s))
            .collect();
        let config = core_tls::client::Config {
            template: &template,
            server_name: if self.disable_sni {
                ""
            } else {
                &self.server_name
            },
            alpn: &alpn,
            verifier: &*verifier,
            reality: seal,
            fragment: self.fragment,
            cipher_suites,
        };
        let mut handshake = core_tls::client::Handshake::new(config)?;
        let mut stream = stream;
        let result = handshake
            .run(&mut stream)
            .await
            .map_err(|e| io::Error::other(format!("{name} handshake: {e}")));
        if let Some(v) = reality_verifier.as_ref() {
            crate::logging::debug(format_args!(
                "REALITY {}: {}",
                self.server_name,
                v.verdict()
            ));
        }
        result?;
        let connection = core_tls::client::Connection::new(&mut handshake)?;
        let alpn = handshake.alpn.clone();
        crate::logging::debug(format_args!(
            "tls: established {} sni={} alpn=[{}]",
            name,
            self.server_name,
            alpn.iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
                .join(",")
        ));
        let tls_stream = Box::new(crate::tls_utls::FingerprintStream::new(stream, connection));
        Ok(Box::new(crate::inbound::AlpnStream::new(tls_stream, alpn)))
    }

    pub async fn wrap(&self, stream: TcpStream) -> io::Result<AnyStream> {
        self.establish(stream, &[]).await
    }

    pub async fn wrap_with_defaults(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
    ) -> io::Result<AnyStream> {
        self.establish(stream, default_alpn).await
    }

    /// Replace whatever `tls.alpn` said: a transport that knows which protocol
    /// it will speak on this connection narrows the offer itself.
    pub(crate) fn set_alpn(&mut self, alpn: &[&[u8]]) {
        self.alpn = alpn.iter().map(|a| a.to_vec()).collect();
    }
}

/// A REALITY public key: 32 bytes of X25519, base64url without padding.
fn parse_reality_key(value: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|_| format!("{value:?} is not 32 bytes"))
}

/// A REALITY short id: an even number of hex digits, at most 16.
fn parse_short_id(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > 16 || !value.len().is_multiple_of(2) {
        return Err(format!("{value:?} must be 1..8 bytes of hex"));
    }
    (0..value.len() / 2)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("{value:?} is not hex"))
        })
        .collect()
}

/// TLS wrap for runtime fetches without a `tls` block: any proxy stream, any
/// certificate (the reference fetches through the same accept-any path).
pub(crate) async fn wrap_probe_stream<S>(stream: S, server_name: &str) -> io::Result<AnyStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| io::Error::other(format!("invalid fetch server_name {server_name:?}")))?;
    Ok(Box::new(connector.connect(name, stream).await?))
}

/// TLS wrap for runtime probes (urltest): any proxy stream, any certificate.
pub(crate) async fn wrap_probe(stream: AnyStream, server_name: &str) -> io::Result<AnyStream> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| io::Error::other(format!("invalid probe server_name {server_name:?}")))?;
    Ok(Box::new(connector.connect(name, stream).await?))
}

fn load_pem_certs(
    mut pem: &[u8],
    out: &mut Vec<rustls::pki_types::CertificateDer<'static>>,
) -> io::Result<()> {
    for cert in certs(&mut pem) {
        out.push(cert.map_err(|e| io::Error::other(format!("bad PEM: {e}")))?);
    }
    Ok(())
}

/// Load a PEM private key (unused yet; inbound TLS server lands in F5).
#[allow(dead_code)]
fn load_pem_key(mut pem: &[u8]) -> io::Result<()> {
    private_key(&mut pem)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn options(value: Value) -> anyhow::Result<Option<TlsOptions>> {
        let obj = value.as_object().expect("an object").clone();
        TlsOptions::from_outbound(&obj, "example.com", "443")
    }

    /// The whole point of the change: a fingerprint in the config is a table we
    /// resolve now, and the hello it produces is ours.
    #[test]
    fn a_fingerprint_resolves_to_a_table() {
        let tls = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "firefox"}}
        }))
        .expect("valid")
        .expect("tls present");
        let fingerprint = tls.fingerprint().expect("a fingerprint");
        assert_eq!(fingerprint.name, "firefox");
        assert!(
            fingerprint
                .template
                .extensions
                .iter()
                .any(|e| matches!(e, core_tls::hello::Ext::KeyShare(_)))
        );
        assert!(tls.reality().is_none());
    }

    #[test]
    fn random_fingerprints_survive_runtime_construction() {
        for name in ["random", "randomized"] {
            let tls = options(json!({
                "server": "example.com",
                "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": name}}
            }))
            .expect("a validator-accepted fingerprint must also start")
            .expect("TLS present");
            assert_eq!(tls.fingerprint().unwrap().name, name);
            assert!(tls.own_stack());
        }
    }

    /// An empty fingerprint is chrome, the way the reference reads it, and a
    /// name it does not know is refused rather than quietly downgraded: the
    /// whole point of asking for a browser is getting that browser.
    #[test]
    fn the_fingerprint_name_is_not_guessed_at() {
        let chrome = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "utls": {"enabled": true}}
        }))
        .expect("valid")
        .expect("tls present");
        assert_eq!(chrome.fingerprint().expect("a fingerprint").name, "chrome");

        let err = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "netscape"}}
        }))
        .expect_err("an unknown browser is an error");
        assert!(err.to_string().contains("netscape"), "{err}");
    }

    /// REALITY's public key is 32 bytes of X25519 and its short id is up to
    /// eight bytes of hex; both are parsed the way the reference writes them.
    #[test]
    fn the_reality_parameters_are_parsed_like_the_reference_writes_them() {
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let tls = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "reality": {
                "enabled": true, "public_key": key, "short_id": "1234abcd"
            }}
        }))
        .expect("valid")
        .expect("tls present");
        let reality = tls.reality().expect("reality");
        assert_eq!(reality.short_id, vec![0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(reality.public_key.len(), 32);

        // no short id is legal: the server may have none configured
        let none = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "reality": {"enabled": true, "public_key": key}}
        }))
        .expect("valid")
        .expect("tls present");
        assert!(none.reality().expect("reality").short_id.is_empty());

        for bad in ["123", "1234567890abcdef01", "zz"] {
            let value = json!({
                "server": "example.com",
                "tls": {"enabled": true, "reality": {
                    "enabled": true, "public_key": key, "short_id": bad
                }}
            });
            assert!(options(value).is_err(), "short_id {bad:?} was accepted");
        }
    }

    #[test]
    fn a_reality_key_that_is_not_32_bytes_is_refused() {
        for bad in ["", "AAAA", "not base64 at all!"] {
            let value = json!({
                "server": "example.com",
                "tls": {"enabled": true, "reality": {"enabled": true, "public_key": bad}}
            });
            assert!(options(value).is_err(), "public_key {bad:?} was accepted");
        }
    }
}
