//! Port of `quinn-proto/src/crypto/rustls.rs` over `core-crypto`.
//!
//! Upstream gates this module behind `rustls-ring`/`rustls-aws-lc-rs` and
//! implements Retry integrity with `ring::aead`. We:
//! - resolve the provider via `core_crypto::provider()` (QUIC-capable suites),
//! - seal/open Retry tags with `aes-gcm` AES-128-GCM (RFC 9001 §5.8),
//! - drop `platform-verifier` / post-quantum-test cfgs we do not carry.

use std::{any::Any, io, sync::Arc};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use bytes::BytesMut;
pub use rustls::Error;
use rustls::{
    self, CipherSuite,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    quic::{Connection, HeaderProtectionKey, KeyChange, PacketKey, Secrets, Suite, Version},
};

use quinn_proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};

/// Map quinn's [`Side`] onto rustls's (orphan rules block the `From` impl).
fn rustls_side(s: Side) -> rustls::Side {
    match s {
        Side::Client => rustls::Side::Client,
        Side::Server => rustls::Side::Server,
    }
}

/// Newtype so we can implement quinn's `HeaderKey` for a rustls header key
/// (orphan rules block `impl crypto::HeaderKey for Box<dyn HeaderProtectionKey>`).
pub struct QuinnHeaderKey(Box<dyn HeaderProtectionKey>);

impl From<Box<dyn HeaderProtectionKey>> for QuinnHeaderKey {
    fn from(k: Box<dyn HeaderProtectionKey>) -> Self {
        Self(k)
    }
}

impl crypto::HeaderKey for QuinnHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.0
            .decrypt_in_place(
                &sample[..self.0.sample_len()],
                &mut first[0],
                &mut rest[pn_offset - 1..pn_end],
            )
            .unwrap();
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.0
            .encrypt_in_place(
                &sample[..self.0.sample_len()],
                &mut first[0],
                &mut rest[pn_offset - 1..pn_end],
            )
            .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.0.sample_len()
    }
}

/// Newtype so we can implement quinn's `PacketKey` for a rustls packet key.
pub struct QuinnPacketKey(Box<dyn PacketKey>);

impl From<Box<dyn PacketKey>> for QuinnPacketKey {
    fn from(k: Box<dyn PacketKey>) -> Self {
        Self(k)
    }
}

impl crypto::PacketKey for QuinnPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.0.tag_len());
        let tag = self.0.encrypt_in_place(packet, header, payload).unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .0
            .decrypt_in_place(packet, header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

/// A rustls TLS session driving a QUIC connection.
pub struct TlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    inner: Connection,
    suite: Suite,
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.inner.alpn_protocol().map(|x| x.into()),
            server_name: match self.inner {
                Connection::Client(_) => None,
                Connection::Server(ref session) => session.server_name().map(|x| x.into()),
            },
        }))
    }

    /// For the rustls `TlsSession`, the `Any` type is `Vec<rustls::pki_types::CertificateDer>`
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_certificates().map(|v| -> Box<dyn Any> {
            Box::new(
                v.iter()
                    .map(|v| v.clone().into_owned())
                    .collect::<Vec<CertificateDer<'static>>>(),
            )
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((
            Box::new(QuinnHeaderKey::from(keys.header)),
            Box::new(QuinnPacketKey::from(keys.packet)),
        ))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                TransportError {
                    code: TransportErrorCode::PROTOCOL_VIOLATION,
                    frame: None,
                    reason: format!("TLS error: {e}"),
                }
            }
        })?;
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.server_name().is_some(),
            };
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

        Some(Keys {
            header: KeyPair {
                local: Box::new(QuinnHeaderKey::from(keys.local.header)),
                remote: Box::new(QuinnHeaderKey::from(keys.remote.header)),
            },
            packet: KeyPair {
                local: Box::new(QuinnPacketKey::from(keys.local.packet)),
                remote: Box::new(QuinnPacketKey::from(keys.remote.packet)),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(QuinnPacketKey::from(keys.local)),
            remote: Box::new(QuinnPacketKey::from(keys.remote)),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let (nonce, key) = match self.version {
            Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
            Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
            _ => unreachable!(),
        };

        let (aad, tag_bytes) = pseudo_packet.split_at_mut(tag_start);
        retry_open(&key, &nonce, aad, tag_bytes)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner
            .export_keying_material(output, label, Some(context))
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

const RETRY_INTEGRITY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// AES-128-GCM open for Retry integrity (RFC 9001 §5.8), fixed key/nonce.
fn retry_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    tag_and_maybe_ciphertext: &[u8],
) -> bool {
    // Retry payload before the tag is empty for the integrity check: `aad` is
    // the pseudo-packet up to the tag, and the tag itself is what remains.
    // Upstream calls `open_in_place` with the whole buffer where ciphertext
    // length is 0 and the last 16 bytes are the tag.
    let cipher = match Aes128Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // `tag_and_maybe_ciphertext` here is only the 16-byte tag (ciphertext empty).
    if tag_and_maybe_ciphertext.len() != 16 {
        return false;
    }
    let mut buf: Vec<u8> = Vec::new();
    let n = match cipher.encrypt(&Nonce::from(*nonce), Payload { msg: &buf, aad }) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Compare computed tag against the received one in constant time via eq.
    buf = n;
    let computed = &buf[..16];
    let received = tag_and_maybe_ciphertext;
    // Constant-time-ish: length already checked equal.
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= computed[i] ^ received[i];
    }
    diff == 0
}

/// AES-128-GCM seal for generating a server Retry tag.
fn retry_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    let cipher = Aes128Gcm::new_from_slice(key).expect("16-byte key");
    let out = cipher
        .encrypt(&Nonce::from(*nonce), Payload { msg: &[], aad })
        .expect("aes-gcm encrypt of empty plaintext");
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[..16]);
    tag
}

/// Authentication data for (rustls) TLS session
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client, if any (always `None` outgoing)
    pub server_name: Option<String>,
}

/// A QUIC-compatible TLS client configuration over the pure-Rust provider.
pub struct QuicClientConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl QuicClientConfig {
    /// Wrap a custom [`rustls::ClientConfig`] (must enable TLS 1.3).
    pub fn try_from_rustls(inner: Arc<rustls::ClientConfig>) -> Result<Self, NoInitialCipherSuite> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }

    /// Initialize a QUIC-compatible client config with a custom certificate
    /// verifier (e.g. accept-any for `tls.insecure`, or WebPki/root store).
    pub fn new(verifier: Arc<dyn ServerCertVerifier>) -> Self {
        let inner = Self::inner(verifier);
        Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .expect("core-crypto provides TLS13_AES_128_GCM_SHA256"),
            inner: Arc::new(inner),
        }
    }

    /// Initialize with a separate initial cipher suite (must be AES-128-GCM).
    pub fn with_initial(
        inner: Arc<rustls::ClientConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self { inner, initial }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    pub(crate) fn inner(verifier: Arc<dyn ServerCertVerifier>) -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("core-crypto supports TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        config.enable_early_data = true;
        config
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        Ok(Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            inner: rustls::quic::Connection::Client(
                rustls::quic::ClientConnection::new(
                    self.inner.clone(),
                    version,
                    ServerName::try_from(server_name)
                        .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?
                        .to_owned(),
                    to_vec(params),
                )
                .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?,
            ),
            suite: self.initial,
        }))
    }
}

/// The initial cipher suite (AES-128-GCM-SHA256) is not available
#[derive(Clone, Debug)]
pub struct NoInitialCipherSuite {
    /// Whether the initial cipher suite was supplied by the caller
    specific: bool,
}

impl std::fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self.specific {
            true => "invalid cipher suite specified",
            false => "no initial cipher suite found",
        })
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// A QUIC-compatible TLS server configuration over the pure-Rust provider.
pub struct QuicServerConfig {
    inner: Arc<rustls::ServerConfig>,
    initial: Suite,
}

impl QuicServerConfig {
    /// Build from a certificate chain and private key.
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        let inner = Self::inner(cert_chain, key)?;
        Ok(Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .expect("core-crypto provides TLS13_AES_128_GCM_SHA256"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize with a separate initial cipher suite (must be AES-128-GCM).
    pub fn with_initial(
        inner: Arc<rustls::ServerConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self { inner, initial }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    pub(crate) fn inner(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<rustls::ServerConfig, rustls::Error> {
        let mut inner = rustls::ServerConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("core-crypto supports TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        inner.max_early_data_size = u32::MAX;
        Ok(inner)
    }
}

impl TryFrom<rustls::ServerConfig> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ServerConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ServerConfig>> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ServerConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            inner: rustls::quic::Connection::Server(
                rustls::quic::ServerConnection::new(self.inner.clone(), version, to_vec(params))
                    .expect("TLS1.3-only server config"),
            ),
            suite: self.initial,
        })
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, *dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        let (nonce, key) = match version {
            Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
            Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
            _ => unreachable!(),
        };

        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        retry_seal(&key, &nonce, &pseudo_packet)
    }
}

/// Find the QUIC-capable AES-128-GCM-SHA256 suite in a provider.
pub fn initial_suite_from_provider(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => suite.quic_suite(),
            _ => None,
        })
}

/// The pure-Rust provider (`core-crypto`) with QUIC-capable suites.
pub fn configured_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(core_crypto::provider())
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

/// Derive QUIC initial keys for a connection ID / side.
pub fn initial_keys(version: Version, dst_cid: ConnectionId, side: Side, suite: &Suite) -> Keys {
    let keys = suite.keys(&dst_cid, rustls_side(side), version);
    Keys {
        header: KeyPair {
            local: Box::new(QuinnHeaderKey::from(keys.local.header)),
            remote: Box::new(QuinnHeaderKey::from(keys.remote.header)),
        },
        packet: KeyPair {
            local: Box::new(QuinnPacketKey::from(keys.local.packet)),
            remote: Box::new(QuinnPacketKey::from(keys.remote.packet)),
        },
    }
}

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}
