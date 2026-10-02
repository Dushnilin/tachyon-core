//! F0 spike A (ADR-0003): a TLS 1.3 handshake must complete with the
//! pure-Rust provider — no ring, no aws-lc, no C. This is the property that
//! keeps MIPS targets viable.

use std::io::{Read, Write};
use std::net::TcpStream;

use core_tls::rustls::pki_types::ServerName;
use core_tls::rustls::{ClientConfig, ClientConnection, StreamOwned};

#[test]
fn tls_handshake_with_pure_rust_provider() {
    core_tls::install_default_provider();

    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server = ServerName::try_from("example.com").expect("server name");
    let conn = ClientConnection::new(config.into(), server).expect("client connection");
    // A sandbox without egress cannot answer this, and a gate that goes red for
    // that reason teaches nothing. The handshake itself is covered hermetically
    // in `handshake_e2e.rs`, against rustls' own server side; this one adds a
    // server that is not us at all, when there is one to talk to.
    let Ok(sock) = TcpStream::connect("example.com:443") else {
        eprintln!("skipped: no egress to example.com:443");
        return;
    };
    let mut tls = StreamOwned::new(conn, sock);

    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .expect("write request");

    let mut response = String::new();
    tls.read_to_string(&mut response).expect("read response");
    assert!(
        response.starts_with("HTTP/1.1"),
        "expected HTTP response, got: {:?}",
        &response[..response.len().min(64)]
    );
}
