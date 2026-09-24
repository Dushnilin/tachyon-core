//! Ring-free QUIC backend smoke tests: suite selection, initial-key
//! protect/unprotect round-trip, Retry integrity tag, HMAC/token keys,
//! and an in-memory TLS 1.3 handshake driven through quinn-proto's
//! `crypto::Session` traits.

use std::sync::Arc;

use core_tls::quic::{
    HandshakeTokenKeyRustCrypto, HmacSha256Key, QuicClientConfig, QuicServerConfig,
    configured_provider, initial_keys, initial_suite_from_provider,
};
use core_tls::rustls;
use quinn_proto::crypto::{ClientConfig as _, ServerConfig as _, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// Accept-any verifier for the smoke test (mirrors runtime `tls.insecure`).
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn load_certs() -> (
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert_pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/certs/localhost.crt"
    ))
    .expect("read localhost.crt");
    let key_pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/certs/localhost.key"
    ))
    .expect("read localhost.key");

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .expect("parse certs");
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("parse key")
        .expect("key present");
    (certs, key)
}

/// Protocol-default transport parameters (empty decode yields defaults).
fn default_params() -> TransportParameters {
    TransportParameters::read(Side::Client, &mut &[][..]).expect("empty params decode to defaults")
}

#[test]
fn provider_exposes_quic_capable_aes128_suite() {
    let provider = configured_provider();
    let suite = initial_suite_from_provider(&provider).expect("AES-128-GCM quic suite");
    assert_eq!(
        suite.suite.common.suite,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
    );
}

#[test]
fn initial_keys_protect_and_unprotect() {
    let provider = configured_provider();
    let suite = initial_suite_from_provider(&provider).expect("suite");
    let dst = ConnectionId::new(&[0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b]);

    let client = initial_keys(rustls::quic::Version::V1, dst, Side::Client, &suite);
    let server = initial_keys(rustls::quic::Version::V1, dst, Side::Server, &suite);

    // Long-header-ish layout: header = first + version + cid fields + 4-byte PN.
    // Sample for header protection starts at pn_offset + 4 (RFC 9001 5.4.2).
    let pn_offset = 18;
    let header_len = pn_offset + 4;
    let payload_len = 64;

    let make_plaintext = |xor: u8| -> (Vec<u8>, Vec<u8>) {
        let mut pkt = vec![0u8; header_len + payload_len + 16];
        let mut plain = vec![0u8; payload_len];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i as u8) ^ xor;
        }
        pkt[header_len..header_len + payload_len].copy_from_slice(&plain);
        (pkt, plain)
    };

    // Client -> server.
    let (mut buf, plain) = make_plaintext(0xa5);
    client.packet.local.encrypt(0, &mut buf, header_len);
    client.header.local.encrypt(pn_offset, &mut buf);
    assert_ne!(
        &buf[..header_len],
        &vec![0u8; header_len],
        "header protected"
    );

    server.header.remote.decrypt(pn_offset, &mut buf);
    let mut payload = bytes::BytesMut::from(&buf[header_len..]);
    server
        .packet
        .remote
        .decrypt(0, &buf[..header_len], &mut payload)
        .expect("server decrypts client packet");
    assert_eq!(payload.as_ref(), plain.as_slice(), "plaintext restored");

    // Server -> client.
    let (mut buf2, plain2) = make_plaintext(0x5a);
    server.packet.local.encrypt(0, &mut buf2, header_len);
    server.header.local.encrypt(pn_offset, &mut buf2);

    client.header.remote.decrypt(pn_offset, &mut buf2);
    let mut payload2 = bytes::BytesMut::from(&buf2[header_len..]);
    client
        .packet
        .remote
        .decrypt(0, &buf2[..header_len], &mut payload2)
        .expect("client decrypts server packet");
    assert_eq!(
        payload2.as_ref(),
        plain2.as_slice(),
        "server->client restored"
    );
}

#[test]
fn retry_tag_roundtrip() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Nonce};

    let (certs, key) = load_certs();
    let server_cfg = QuicServerConfig::new(certs, key).expect("server config");

    let orig_dst = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let packet: &[u8] = &[
        0xf0, 0x00, 0x00, 0x00, 0x01, // long header, v1
        0x00, // token length 0
        0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, // scid
        0x00,
    ];

    let tag = server_cfg.retry_tag(0x0000_0001, &orig_dst, packet);
    assert_eq!(tag.len(), 16);

    // RFC 9001 5.8: fixed V1 key/nonce, AAD = pseudo-packet.
    let mut pseudo = Vec::new();
    pseudo.push(orig_dst.len() as u8);
    pseudo.extend_from_slice(&orig_dst);
    pseudo.extend_from_slice(packet);

    let key_v1: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    let nonce_v1: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];
    let cipher = Aes128Gcm::new_from_slice(&key_v1).expect("key");
    let expected = cipher
        .encrypt(
            &Nonce::from(nonce_v1),
            Payload {
                msg: &[],
                aad: &pseudo,
            },
        )
        .expect("encrypt");
    assert_eq!(
        tag.as_slice(),
        expected.as_slice(),
        "retry tag matches RFC 9001 5.8"
    );
}

#[test]
fn hmac_and_token_key_sign_verify() {
    use quinn_proto::crypto::{HandshakeTokenKey as _, HmacKey as _};

    let mac = HmacSha256Key::new(b"sixty-four-byte-master-key-for-hmac-tests!!!!");
    let mut sig = vec![0u8; mac.signature_len()];
    mac.sign(b"stateless-reset", &mut sig);
    assert_eq!(sig.len(), 32);
    mac.verify(b"stateless-reset", &sig).expect("verify ok");
    assert!(mac.verify(b"tampered", &sig).is_err());

    let token = HandshakeTokenKeyRustCrypto::new([7u8; 64]);
    let aead = token.aead_from_hkdf(b"random");
    let mut sealed = b"token-payload".to_vec();
    aead.seal(&mut sealed, b"aad").expect("seal");
    assert_ne!(sealed, b"token-payload");
    let opened = aead.open(&mut sealed, b"aad").expect("open");
    assert_eq!(opened, b"token-payload");
}

/// Drain one side's `write_handshake` across key changes, the way
/// quinn's `write_crypto` loop does. Returns one chunk per encryption
/// level: rustls requires `read_hs` to see levels in separate calls
/// (otherwise `KeyEpochWithPendingFragment`).
fn drain_write(session: &mut dyn Session) -> Vec<Vec<u8>> {
    let mut segments = Vec::new();
    loop {
        let mut chunk = Vec::new();
        let keys = session.write_handshake(&mut chunk);
        let got_bytes = !chunk.is_empty();
        if got_bytes {
            segments.push(chunk);
        }
        if keys.is_some() {
            // Level boundary: more data may follow under the new keys.
            continue;
        }
        if !got_bytes {
            // Nothing written and no key change: done.
            break;
        }
        // Bytes but no key change: loop again; the next iteration
        // breaks if it comes back empty with no keys.
    }
    segments
}

/// Feed each encryption-level chunk to `read_handshake` separately.
fn feed_levels(session: &mut dyn Session, chunks: &[Vec<u8>]) {
    for chunk in chunks {
        session
            .read_handshake(chunk)
            .expect("peer accepts flight chunk");
    }
}

#[test]
fn in_memory_client_server_handshake() {
    let (certs, key) = load_certs();
    let server_crypto = Arc::new(QuicServerConfig::new(certs, key).expect("server config"));
    let client_crypto = Arc::new(QuicClientConfig::new(Arc::new(AcceptAny)));

    let params = default_params();

    let mut client = client_crypto
        .clone()
        .start_session(0x0000_0001, "localhost", &params)
        .expect("client session");
    let mut server = server_crypto.clone().start_session(0x0000_0001, &params);

    // 1. ClientHello (Initial level only).
    let flight1 = drain_write(client.as_mut());
    assert!(!flight1.is_empty(), "client emitted ClientHello");
    let f1_len: usize = flight1.iter().map(Vec::len).sum();
    assert!(f1_len > 0);

    // 2. Server processes CH, emits SH [+ EE/Cert/CV/Finished across levels].
    feed_levels(server.as_mut(), &flight1);
    let flight2 = drain_write(server.as_mut());
    assert!(!flight2.is_empty(), "server emitted flight");

    // 3. Client processes each level separately, then emits Finished.
    feed_levels(client.as_mut(), &flight2);
    let flight3 = drain_write(client.as_mut());

    // 4. Server accepts client Finished; optional trailing server data.
    if !flight3.is_empty() {
        feed_levels(server.as_mut(), &flight3);
        let flight4 = drain_write(server.as_mut());
        if !flight4.is_empty() {
            feed_levels(client.as_mut(), &flight4);
            let _ = drain_write(client.as_mut());
        }
    }

    assert!(!server.is_handshaking(), "server handshake complete");
    assert!(!client.is_handshaking(), "client handshake complete");
}
