//! The runtime's own TLS stack, over a real socket-shaped transport.
//!
//! `FingerprintStream` is the only place our record layer meets an async caller,
//! and it is the one part of it that cannot be checked by the core-tls tests: it
//! has no server to talk to there. It had a bug of exactly that kind -- it
//! reported the length of the *sealed* record, tag and all, as the number of
//! plaintext bytes it had taken, and every caller that trusts the contract
//! (tokio's `write_all` first) then sliced its own buffer out of range. Nothing
//! local noticed; the first real outbound through a REALITY node panicked the
//! process.
//!
//! So this drives the whole shape: our handshake against rustls' server, our
//! record layer, and the adapter, with the server on its own task.

use std::sync::Arc;

use core_runtime::tls_utls::FingerprintStream;
use core_tls::client::{Config, Connection, Handshake};
use core_tls::fingerprints;
use core_tls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use core_tls::rustls::{RootCertStore, ServerConfig};
use core_tls::verify::WebpkiVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

/// The certificate the repository already carries: self signed for `localhost`,
/// valid until 2036.
fn fixture() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(dir.join("localhost.crt")).expect("the certificate fixture"),
    ))
    .collect::<Result<_, _>>()
    .expect("the certificate fixture parses");
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(dir.join("localhost.key")).expect("the key fixture"),
    ))
    .expect("the key fixture parses")
    .expect("the key fixture holds one key");
    (certs, key)
}

/// The adapter takes the bytes it was given and gives the peer back what was
/// under them, through a handshake of our own.
#[tokio::test]
async fn application_data_goes_out_and_comes_back_through_our_own_stack() {
    core_tls::install_default_provider();
    let (certs, key) = fixture();
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .expect("a server config from one certificate");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("add the root");
    let verifier = WebpkiVerifier::new(Arc::new(roots)).expect("a verifier");
    let template = fingerprints::by_name("chrome").expect("a chrome table");

    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        let mut stream = acceptor
            .accept(server_io)
            .await
            .expect("the server handshake");
        // one request, one answer, over the records our client writes
        let mut request = [0u8; 5];
        stream.read_exact(&mut request).await.expect("the request");
        assert_eq!(&request, b"ping!");
        stream.write_all(b"pong!").await.expect("the answer");
        stream.flush().await.expect("flush");
    });

    let alpn: [&[u8]; 1] = [b"h2"];
    let config = Config {
        template: &template,
        server_name: "localhost",
        alpn: &alpn,
        verifier: &verifier,
        reality: None,
    };
    let mut handshake = Handshake::new(config).expect("a handshake");
    handshake.run(&mut client_io).await.expect("the handshake");
    let connection = Connection::new(&mut handshake).expect("application keys");

    let mut stream = FingerprintStream::new(client_io, connection);
    // the whole point: `write_all` slices its buffer by what poll_write reports,
    // so a writer that over-reports takes the process down right here
    stream.write_all(b"ping!").await.expect("the request");
    stream.flush().await.expect("flush");

    let mut answer = [0u8; 5];
    stream.read_exact(&mut answer).await.expect("the answer");
    assert_eq!(&answer, b"pong!");
    server.await.expect("the server task");
}

/// An empty write is not a record: reporting zero is the honest answer, and a
/// caller that loops on it must not be handed one.
#[tokio::test]
async fn an_empty_write_seals_nothing() {
    core_tls::install_default_provider();
    let (certs, key) = fixture();
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .expect("a server config from one certificate");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("add the root");
    let verifier = WebpkiVerifier::new(Arc::new(roots)).expect("a verifier");
    let template = fingerprints::by_name("chrome").expect("a chrome table");

    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut stream = acceptor
            .accept(server_io)
            .await
            .expect("the server handshake");
        let mut request = [0u8; 2];
        stream.read_exact(&mut request).await.expect("the request");
        assert_eq!(&request, b"hi");
    });

    let alpn: [&[u8]; 1] = [b"h2"];
    let config = Config {
        template: &template,
        server_name: "localhost",
        alpn: &alpn,
        verifier: &verifier,
        reality: None,
    };
    let mut handshake = Handshake::new(config).expect("a handshake");
    handshake.run(&mut client_io).await.expect("the handshake");
    let connection = Connection::new(&mut handshake).expect("application keys");
    let mut stream = FingerprintStream::new(client_io, connection);

    assert_eq!(stream.write(b"").await.expect("an empty write"), 0);
    stream.write_all(b"hi").await.expect("the request");
    server.await.expect("the server task");
}

// Helpers for the two tests below: our client on one side of a duplex, a rustls
// server on the other, and a `FingerprintStream` over the client side.
async fn pair(
    payload_from_server: usize,
) -> (
    FingerprintStream<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<()>,
) {
    core_tls::install_default_provider();
    let (certs, key) = fixture();
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .expect("a server config from one certificate");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("add the root");
    let verifier = WebpkiVerifier::new(Arc::new(roots)).expect("a verifier");
    let template = fingerprints::by_name("chrome").expect("a chrome table");

    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut stream = acceptor
            .accept(server_io)
            .await
            .expect("the server handshake");
        let body: Vec<u8> = (0..payload_from_server).map(|i| i as u8).collect();
        stream.write_all(&body).await.expect("the answer");
        stream.flush().await.expect("flush");
    });

    let alpn: [&[u8]; 1] = [b"h2"];
    let config = Config {
        template: &template,
        server_name: "localhost",
        alpn: &alpn,
        verifier: &verifier,
        reality: None,
    };
    let mut handshake = Handshake::new(config).expect("a handshake");
    handshake.run(&mut client_io).await.expect("the handshake");
    let connection = Connection::new(&mut handshake).expect("application keys");
    (FingerprintStream::new(client_io, connection), server)
}

/// A record is up to 2^14 bytes; a reader with a small buffer must still get all
/// of it. This is the tail-drop: the adapter used to hand over what fitted and
/// throw the rest away, so a large record lost everything past the first read.
#[tokio::test]
async fn a_record_larger_than_the_readers_buffer_is_not_truncated() {
    let size = 40 * 1024;
    let (mut stream, server) = pair(size).await;

    let mut got: Vec<u8> = Vec::with_capacity(size);
    let mut chunk = [0u8; 1024];
    while got.len() < size {
        let n = stream.read(&mut chunk).await.expect("a read");
        assert!(n > 0, "the stream ended after {} bytes", got.len());
        got.extend_from_slice(&chunk[..n]);
    }
    let expected: Vec<u8> = (0..size).map(|i| i as u8).collect();
    assert_eq!(got, expected, "every byte of every record");
    server.await.expect("the server task");
}

/// The server writes in pieces with a yield between, so records arrive split. A
/// reader must reassemble them -- and must not, at any point, decide it has
/// "enough" bytes and stop reading the socket.
#[tokio::test]
async fn records_split_across_reads_are_reassembled() {
    let size = 20 * 1024;
    let (mut stream, _server) = pair(size).await;

    let mut got: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 777];
    while got.len() < size {
        let n = stream.read(&mut chunk).await.expect("a read");
        assert!(n > 0, "the stream ended after {} bytes", got.len());
        got.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(got.len(), size);
    assert_eq!(got[0], 0);
    assert_eq!(got[size - 1], (size - 1) as u8);
}
