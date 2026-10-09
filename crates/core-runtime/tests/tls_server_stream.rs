//! The server-side TLS stream with the proxy protocols taken away.
//!
//! `server_inbounds.rs` measures the four of them end to end, which is where a
//! bug in the record layer shows up as "no payload came back" and nothing says
//! which of the two halves dropped it. This file is the same handshake with
//! nothing around it but `read` and `write`, so a failure here points at the
//! stream and nowhere else -- and the other side is rustls' client, which shares
//! no code with our server.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use core_runtime::inbound::tls::ServerTls;
use core_tls::rustls::ClientConfig;
use core_tls::rustls::pki_types::CertificateDer;
use core_tls::rustls::pki_types::ServerName as PkiServerName;

const CERT: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY: &str = include_str!("../../../tests/golden/certs/localhost.key");

fn server_tls() -> ServerTls {
    core_tls::install_default_provider();
    ServerTls::from_config(
        &json!({
            "enabled": true,
            "certificate": CERT.lines().collect::<Vec<&str>>(),
            "key": KEY.lines().collect::<Vec<&str>>(),
            "alpn": ["tachyon"],
        }),
        "test",
    )
    .expect("the test certificate parses")
}

/// rustls' client, trusting exactly the certificate we send.
fn client_config() -> ClientConfig {
    // rustls' own builders reach for a process-wide provider that this crate
    // does not install from a cargo feature, so it has to be there before any
    // of them runs -- and these tests share one process.
    core_tls::install_default_provider();
    let mut config = ClientConfig::builder()
        .with_root_certificates({
            let mut store = core_tls::rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut CERT.as_bytes()) {
                store
                    .add(CertificateDer::from(
                        cert.expect("a certificate block").to_vec(),
                    ))
                    .expect("add root");
            }
            store
        })
        .with_no_client_auth();
    config.alpn_protocols = vec![b"tachyon".to_vec()];
    config
}

/// A connected pair of loopback sockets: ours to hand to the server, theirs for
/// rustls.
async fn loopback() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let accepted = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.expect("accept");
        assert_eq!(peer.ip().to_string(), "127.0.0.1");
        socket
    });
    let theirs = tokio::net::TcpStream::connect(addr).await.expect("connect");
    (accepted.await.expect("accept task"), theirs)
}

/// Both halves of one connection: our server stream on one end, rustls' client
/// on the other.
///
/// A real socket rather than `tokio::io::duplex`, which has one buffer for both
/// directions: a megabyte test with a writer that writes before it reads
/// deadlocks on it and looks like a stream that hangs.
async fn pair() -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
) {
    let (ours, theirs) = loopback().await;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config()));
    let name = PkiServerName::try_from("localhost").expect("server name");
    let client = tokio::spawn(async move {
        connector
            .connect(name, theirs)
            .await
            .expect("rustls client handshake")
    });
    let server = server_tls().accept(ours).await.expect("our handshake");
    (client.await.expect("client task"), server)
}

/// A payload the length a chat message has, in both directions.
#[tokio::test]
async fn a_short_payload_survives_both_ways() {
    let (mut client, mut server) = pair().await;
    let up = b"hello from rustls";
    client.write_all(up).await.expect("client write");
    let mut got = vec![0u8; up.len()];
    server.read_exact(&mut got).await.expect("server read");
    assert_eq!(&got, up);

    let down = b"and hello from us";
    server.write_all(down).await.expect("server write");
    let mut back = vec![0u8; down.len()];
    client.read_exact(&mut back).await.expect("client read");
    assert_eq!(&back, down);
}

/// A megabyte each way. This is the one that matters: a record layer that only
/// copes with a payload smaller than its own buffer passes the test above, and
/// the sequence number stops matching somewhere past the first megabyte -- which
/// a client sees as a connection that dies once the download gets going.
#[tokio::test]
async fn a_megabyte_survives_both_ways() {
    const SIZE: usize = 1024 * 1024;
    let (mut client, mut server) = pair().await;

    let up = tokio::spawn(async move {
        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        client.write_all(&payload).await.expect("client write");
        // rustls keeps plaintext of its own until it can put it on the wire,
        // and a client that writes a megabyte before reading anything has to
        // ask for it -- otherwise the server waits for bytes the client is
        // holding, and the connection stands still.
        client.flush().await.expect("client flush");
        let mut back = vec![0u8; SIZE];
        client.read_exact(&mut back).await.expect("client read");
        back
    });
    let down = tokio::spawn(async move {
        let mut up = vec![0u8; SIZE];
        server.read_exact(&mut up).await.expect("server read");
        assert!(
            up.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8),
            "the megabyte came back in the wrong order"
        );
        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 253) as u8).collect();
        server.write_all(&payload).await.expect("server write");
        payload
    });

    let back = up.await.expect("client task");
    let sent = down.await.expect("server task");
    assert!(
        back.iter().enumerate().all(|(i, b)| *b == (i % 253) as u8),
        "the megabyte we sent came back changed"
    );
    assert_eq!(back.len(), sent.len());
}

/// ALPN is not decoration: an inbound that offers it and a client that insists
/// on one of those names have to agree, or the client treats the connection as
/// a protocol error.
#[tokio::test]
async fn the_negotiated_protocol_is_the_one_the_client_offered() {
    let mut config = client_config();
    config.alpn_protocols = vec![b"nope".to_vec(), b"tachyon".to_vec()];
    let (theirs, ours) = loopback().await;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = PkiServerName::try_from("localhost").expect("server name");
    let client = tokio::spawn(async move {
        connector
            .connect(name, theirs)
            .await
            .expect("rustls client handshake")
    });
    server_tls().accept(ours).await.expect("our handshake");
    let client = client.await.expect("client task");
    let negotiated = client.get_ref().1.alpn_protocol();
    assert_eq!(
        negotiated,
        Some(b"tachyon".as_slice()),
        "alpn came back as {negotiated:?}"
    );
}

/// A client that closes must not leave our side reading: `poll_read` has to say
/// end-of-file rather than wait for a record that is never coming, and the
/// close_notify we answer with is what makes rustls call it a clean end rather
/// than a truncation.
#[tokio::test]
async fn a_closed_client_is_an_end_of_file_and_not_a_truncation() {
    let (mut client, mut server) = pair().await;
    client.shutdown().await.expect("client shutdown");
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "our side hung on a closed client");
    assert!(buf.is_empty());
    // and our own shutdown is accepted rather than complained about
    tokio::time::timeout(Duration::from_secs(5), server.shutdown())
        .await
        .expect("our shutdown did not finish")
        .expect("our shutdown failed");
    let mut tail = Vec::new();
    let left = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut tail)).await;
    assert!(
        matches!(left, Ok(Ok(0))),
        "the client did not see a clean end: {left:?}"
    );
}

#[tokio::test]
async fn inbound_server_enforces_cipher_suites() {
    core_tls::install_default_provider();
    let tls = ServerTls::from_config(
        &json!({
            "enabled": true,
            "certificate": CERT.lines().collect::<Vec<&str>>(),
            "key": KEY.lines().collect::<Vec<&str>>(),
            "alpn": ["tachyon"],
            "cipher_suites": ["TLS_CHACHA20_POLY1305_SHA256"],
        }),
        "test",
    )
    .expect("the test certificate parses");

    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn(async move {
        let name = PkiServerName::try_from("localhost").expect("server name");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config()));
        connector
            .connect(name, theirs)
            .await
            .expect("rustls client handshake")
    });
    tls.accept(ours).await.expect("our handshake");
    let client = client.await.expect("client task");
    let suite = client.get_ref().1.negotiated_cipher_suite();
    assert_eq!(
        suite.map(|s| s.suite()),
        Some(core_tls::rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        "server selected restricted suite"
    );
}
