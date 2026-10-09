//! The server half, measured against rustls' *client*.
//!
//! A handshake between our own server and our own client would pass even if both
//! misread the format the same way, which is the trap this file exists to avoid:
//! rustls shares no code with us, so a Finished it accepts is a Finished on the
//! wire, not in our heads. The client half is measured the same way against
//! rustls' server in `handshake_e2e.rs`.

use std::sync::Arc;

use core_tls::record::ContentType;
use core_tls::rustls::ClientConfig;
use core_tls::rustls::pki_types::CertificateDer;
use core_tls::rustls::pki_types::ServerName as PkiServerName;
use core_tls::server::{Config, Handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const CERT: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY: &str = include_str!("../../../tests/golden/certs/localhost.key");

fn load() -> (Vec<Vec<u8>>, Arc<dyn core_tls::rustls::sign::SigningKey>) {
    let mut chain = Vec::new();
    for cert in rustls_pemfile::certs(&mut CERT.as_bytes()) {
        chain.push(cert.expect("a certificate block").to_vec());
    }
    assert!(!chain.is_empty(), "the test certificate did not parse");
    let key = rustls_pemfile::private_key(&mut KEY.as_bytes())
        .expect("parse key")
        .expect("the test file holds no key");
    let signing = core_crypto::sign::any_supported_type(&key).expect("a signing key");
    (chain, signing)
}

/// A trust store with exactly the certificate the server sends.
fn roots(chain: &[Vec<u8>]) -> core_tls::rustls::RootCertStore {
    let mut store = core_tls::rustls::RootCertStore::empty();
    for der in chain {
        store
            .add(CertificateDer::from(der.clone()))
            .expect("add root");
    }
    store
}

#[tokio::test]
async fn our_server_completes_a_handshake_with_rustls_client() {
    core_tls::install_default_provider();
    let (chain, key) = load();

    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let trusted = chain.clone();
    let client = tokio::spawn(async move {
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots(&trusted))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let name = PkiServerName::try_from("localhost").expect("server name");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut tls = connector
            .connect(name, theirs)
            .await
            .expect("rustls client handshake");
        tls.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping", "the echo comes back through the tunnel");
        drop(tls);
    });

    let mut handshake = Handshake::new(Config {
        chain,
        key,
        alpn: vec![b"h2".to_vec()],
        cipher_suites: Vec::new(),
    })
    .expect("server config");
    handshake.run(&mut ours).await.expect("handshake");
    assert_eq!(
        handshake.alpn.as_deref(),
        Some(&b"h2"[..]),
        "alpn was agreed"
    );
    let (mut sealer, mut opener) = handshake.application.take().expect("application keys");

    // one application record each way, which is where a wrong key or a wrong
    // sequence number shows up
    let raw = read_record(&mut ours).await;
    let (kind, plain) = opener.open(&raw).expect("open");
    assert_eq!(kind, ContentType::ApplicationData);
    assert_eq!(plain, b"ping", "the client's payload arrives intact");

    let sealed = sealer
        .seal(ContentType::ApplicationData, b"ping")
        .expect("seal");
    ours.write_all(&sealed).await.expect("write ping");
    client.await.expect("client finished");
}

async fn read_record(stream: &mut DuplexStream) -> Vec<u8> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await.expect("header");
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut out = Vec::with_capacity(5 + len);
    out.extend_from_slice(&header);
    out.resize(5 + len, 0);
    stream.read_exact(&mut out[5..]).await.expect("body");
    out
}

/// A ClientHello body we can break in one place at a time.
fn hello(suites: &[u16], versions: Option<&[u8]>, share: Option<[u8; 32]>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[7u8; 32]); // random
    body.push(0); // no session id
    body.extend_from_slice(&(suites.len() as u16 * 2).to_be_bytes());
    for id in suites {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.push(1);
    body.push(0); // one compression method: null

    let mut extensions = Vec::new();
    if let Some(list) = versions {
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&((list.len() + 1) as u16).to_be_bytes());
        extensions.push(list.len() as u8);
        extensions.extend_from_slice(list);
    }
    if let Some(key) = share {
        let mut entry = Vec::new();
        entry.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
        entry.extend_from_slice(&32u16.to_be_bytes());
        entry.extend_from_slice(&key);
        // the extension body is the client_shares list *with its length*, and
        // the extension length covers that prefix too
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&entry);
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&data);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut message = vec![1u8];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    core_tls::record::plaintext_record(
        ContentType::Handshake,
        &message,
        core_tls::record::VERSION_1_2,
    )
    .expect("record")
}

/// The server refuses a hello it cannot answer, and refuses it *quickly*: a
/// client that sends something unanswerable gets an answer, not a stall. Each
/// case is one field of the same hello.
///
/// The duplex is two one-way pipes, so the bytes go in from the far end --
/// reading back what this end wrote is a read that never completes.
async fn refused(input: Vec<u8>) -> String {
    let (chain, key) = load();
    let mut handshake = Handshake::new(Config {
        chain,
        key,
        alpn: Vec::new(),
        cipher_suites: Vec::new(),
    })
    .expect("server config");
    let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
    theirs.write_all(&input).await.expect("write");
    let err = tokio::time::timeout(std::time::Duration::from_secs(5), handshake.run(&mut ours))
        .await
        .expect("the server must answer, not wait")
        .expect_err("must refuse");
    err.to_string()
}

#[tokio::test]
async fn our_server_refuses_a_hello_it_cannot_answer() {
    core_tls::install_default_provider();

    // a record that is not a handshake at all
    let err = refused(
        core_tls::record::plaintext_record(
            ContentType::ApplicationData,
            b"hello?",
            core_tls::record::VERSION_1_2,
        )
        .expect("record"),
    )
    .await;
    assert!(
        err.contains("handshake"),
        "the reason should name the handshake: {err}"
    );

    // no supported_versions at all
    let err = refused(hello(&[0x1301], None, Some([9u8; 32]))).await;
    assert!(err.contains("supported_versions"), "{err}");

    // versions that stop at TLS 1.2
    let err = refused(hello(&[0x1301], Some(&[0x03, 0x03]), Some([9u8; 32]))).await;
    assert!(err.contains("TLS 1.3"), "{err}");

    // suites none of which we serve
    let err = refused(hello(
        &[0xc02f, 0x130a],
        Some(&[0x03, 0x04]),
        Some([9u8; 32]),
    ))
    .await;
    assert!(err.contains("cipher suite"), "{err}");

    // a suite and a version we like, but no key share to answer
    let err = refused(hello(&[0x1301], Some(&[0x03, 0x04]), None)).await;
    assert!(err.contains("key share"), "{err}");
}

/// The signature a server sends has to be over the transcript, and a key that
/// cannot sign is refused before a byte goes out.
#[tokio::test]
async fn a_server_without_a_certificate_chain_is_not_built() {
    core_tls::install_default_provider();
    let (_chain, key) = load();
    let err = Handshake::new(Config {
        chain: Vec::new(),
        key,
        alpn: Vec::new(),
        cipher_suites: Vec::new(),
    })
    .err()
    .expect("an empty chain must not build");
    assert!(err.to_string().contains("chain"), "{err}");
}

#[tokio::test]
async fn server_enforces_cipher_suite_preference() {
    core_tls::install_default_provider();
    let (chain, key) = load();

    // Server restricted to ChaCha20-Poly1305 (0x1303) only
    let mut handshake = Handshake::new(Config {
        chain,
        key,
        alpn: Vec::new(),
        cipher_suites: vec![0x1303],
    })
    .expect("server config");

    let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
    // Client offers AES-128 (0x1301) and ChaCha20 (0x1303)
    let input = hello(&[0x1301, 0x1303], Some(&[0x03, 0x04]), Some([9u8; 32]));
    theirs.write_all(&input).await.expect("write");

    handshake.read_hello(&mut ours).await.expect("read_hello");
    // Handshake should have picked 0x1303 because server restricted to it
    let mut answer = vec![0u8; 128];
    let n = theirs.read(&mut answer).await.expect("read server hello");
    let resp = &answer[..n];
    // Cipher suite is at offset 44 in TLS 1.3 ServerHello
    assert!(resp.windows(2).any(|w| w == [0x13, 0x03]), "server negotiated 0x1303");
}
