//! The handshake, end to end, against a server that is not us.
//!
//! Our client state machine on one side, rustls' on the other, and a real
//! certificate in between: the point is not that the parts pass their own tests
//! but that a hello built from a captured fingerprint completes a handshake
//! with an implementation that shares none of our code.
//!
//! The two sides talk through a buffer rather than a socket. Both are
//! transport-agnostic -- rustls reads and writes TLS, we read and write
//! records -- so the exchange is a loop instead of two threads, which makes it
//! deterministic and keeps it out of the timing races a loopback test has.

use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use core_tls::client::{self, Config, Handshake};
use core_tls::fingerprints;
use core_tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use core_tls::rustls::{self, RootCertStore, ServerConfig};
use core_tls::verify::{CertVerifier, WebpkiVerifier};

/// The certificate the repository already carries for its own golden tests: self
/// signed for `localhost`, valid until 2036. A checked-in certificate is the
/// only kind that can be a test fixture -- one generated per run would need a
/// signing backend, and every pure-Rust one we could add is a dependency this
/// project does not want.
fn fixture() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(
        std::fs::File::open(dir.join("localhost.crt")).expect("the certificate fixture"),
    ))
    .collect::<Result<_, _>>()
    .expect("the certificate fixture parses");
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        std::fs::File::open(dir.join("localhost.key")).expect("the key fixture"),
    ))
    .expect("the key fixture parses")
    .expect("the key fixture holds one key");
    assert_eq!(certs.len(), 1, "one certificate, no chain");
    (certs, key)
}

fn roots_trusting(cert: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("add the root");
    roots
}

/// What the client sees of the other side, and what it says back.
#[derive(Default)]
struct Pipe {
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.incoming.len());
        buf[..n].copy_from_slice(&self.incoming[..n]);
        self.incoming.drain(..n);
        Ok(n)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Outcome {
    leaf: Option<CertificateDer<'static>>,
    client_alpn: Option<Vec<u8>>,
    server_alpn: Option<Vec<u8>>,
    server_finished: bool,
}

/// Pump one handshake through, and report what each side made of it.
fn shake(
    verifier: &dyn CertVerifier,
    fingerprint: &str,
    server_name: &str,
) -> Result<Outcome, String> {
    core_tls::install_default_provider();
    let (certs, key) = fixture();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut server = rustls::ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;

    let template =
        fingerprints::by_name(fingerprint).ok_or_else(|| format!("no table for {fingerprint}"))?;
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let client_config = Config {
        template: &template,
        server_name,
        alpn: &alpn,
        verifier,
    };
    let mut client = Handshake::new(client_config).map_err(|e| e.to_string())?;
    let mut pipe = Pipe::default();
    client.start(&mut pipe).map_err(|e| e.to_string())?;

    // the client's three reads, in order; each one gets everything the server
    // has written so far, and whole records only
    let mut step = 0;
    let mut failure = None;
    for _ in 0..16 {
        let from_client = std::mem::take(&mut pipe.outgoing);
        server
            .read_tls(&mut from_client.as_slice())
            .map_err(|e| e.to_string())?;
        // read_tls only buffers: the state machine moves when the buffered
        // packets are handed to it
        server
            .process_new_packets()
            .map_err(|e| format!("the server rejected our flight: {e}"))?;
        let mut from_server = Vec::new();
        while server.wants_write() {
            server
                .write_tls(&mut from_server)
                .map_err(|e| e.to_string())?;
        }
        pipe.incoming.extend_from_slice(&from_server);

        let outcome = match step {
            0 => client.read_server_hello(&mut pipe),
            1 => client.read_flight(&mut pipe),
            _ => client.send_finished(&mut pipe),
        };
        if let Err(e) = outcome {
            failure = Some(e.to_string());
            break;
        }
        step += 1;
        if step == 3 {
            break;
        }
    }
    // let the server have the last of it: our Finished and the compatibility
    // record in front of it
    let from_client = std::mem::take(&mut pipe.outgoing);
    let _ = server.read_tls(&mut from_client.as_slice());
    let _ = server.process_new_packets();

    if let Some(e) = failure {
        return Err(e);
    }
    if step != 3 {
        return Err("the exchange did not finish".to_string());
    }
    Ok(Outcome {
        leaf: client.leaf().cloned(),
        client_alpn: client.alpn.clone(),
        server_alpn: server.alpn_protocol().map(|p| p.to_vec()),
        server_finished: !server.is_handshaking(),
    })
}

/// The whole thing: our hello, the server's flight, our Finished, and both sides
/// agreeing afterwards.
#[test]
fn the_handshake_completes_against_a_rustls_server() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let done = shake(&verifier, "chrome", "localhost").expect("the handshake");
    assert_eq!(done.leaf.as_ref(), Some(&certs[0]), "we kept the leaf");
    assert_eq!(
        done.client_alpn,
        Some(b"h2".to_vec()),
        "the server chose h2"
    );
    assert_eq!(
        done.server_alpn,
        Some(b"h2".to_vec()),
        "and the server agreed"
    );
    assert!(done.server_finished, "the server finished its side too");
}

/// A verifier that trusts nobody must stop the handshake, and the server must
/// notice. The Finished check on its own would pass here: it only proves the
/// peer holds the same keys, not that anybody vouched for them.
#[test]
fn a_verifier_that_says_no_stops_the_handshake() {
    #[derive(Debug)]
    struct TrustsNobody;
    impl CertVerifier for TrustsNobody {
        fn verify_chain(
            &self,
            _leaf: &CertificateDer<'_>,
            _chain: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
        ) -> io::Result<()> {
            Err(io::Error::other("this test trusts nobody"))
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
    let err =
        shake(&TrustsNobody, "chrome", "localhost").expect_err("a refused chain must not pass");
    assert!(
        err.contains("trusts nobody"),
        "the failure must say why: {err}"
    );
}

/// A name the certificate does not carry must fail: the chain is fine, the
/// hostname is not, and the two are checked separately.
#[test]
fn a_name_the_certificate_does_not_carry_is_refused() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let err = shake(&verifier, "chrome", "not-localhost.example")
        .expect_err("a name outside the certificate must not pass");
    assert!(
        err.contains("certificate chain rejected"),
        "the failure must name the chain: {err}"
    );
}

/// The fingerprint decides which key shares go out, and the server may pick any
/// group from them. These tables offer the hybrid plus plain X25519 -- and, for
/// firefox, a p256 point as well -- while the provider's server side supports
/// only the classical groups, so every run here exercises the "not the first
/// group we offered" path.
#[test]
fn the_server_may_pick_a_later_group_from_our_share() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    shake(&verifier, "chrome", "localhost").expect("chrome");
    shake(&verifier, "firefox", "localhost").expect("firefox offers three groups");
    shake(&verifier, "safari", "localhost").expect("safari");
}

/// The handshake is only half of it: after it, application data has to flow
/// through the same record layer, with the record sequence numbers carrying on
/// from the handshake and the two directions on their own keys.
#[test]
fn application_data_flows_after_the_handshake() {
    core_tls::install_default_provider();
    let (certs, key) = fixture();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .expect("a server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut server = rustls::ServerConnection::new(Arc::new(config)).expect("a server connection");
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let template = fingerprints::by_name("chrome").expect("a chrome table");
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let client_config = Config {
        template: &template,
        server_name: "localhost",
        alpn: &alpn,
        verifier: &verifier,
    };
    let mut client = Handshake::new(client_config).expect("a handshake");
    let mut pipe = Pipe::default();

    // the handshake, then take the application keys
    client.start(&mut pipe).expect("client hello");
    let mut step = 0;
    for _ in 0..16 {
        let from_client = std::mem::take(&mut pipe.outgoing);
        server
            .read_tls(&mut from_client.as_slice())
            .expect("to server");
        server.process_new_packets().expect("server processes");
        let mut from_server = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut from_server).expect("from server");
        }
        pipe.incoming.extend_from_slice(&from_server);
        let outcome = match step {
            0 => client.read_server_hello(&mut pipe),
            1 => client.read_flight(&mut pipe),
            _ => client.send_finished(&mut pipe),
        };
        outcome.expect("a handshake step");
        step += 1;
        if step == 3 {
            break;
        }
    }
    let from_client = std::mem::take(&mut pipe.outgoing);
    server
        .read_tls(&mut from_client.as_slice())
        .expect("finished to server");
    server
        .process_new_packets()
        .expect("server takes the finished");
    assert!(!server.is_handshaking(), "the server is done too");
    let mut connection = client::Connection::new(&mut client).expect("application keys");

    // our write reaches the server
    connection
        .write(&mut pipe, b"GET / HTTP/1.1\r\n\r\n")
        .expect("write");
    let to_server = std::mem::take(&mut pipe.outgoing);
    server
        .read_tls(&mut to_server.as_slice())
        .expect("app data to server");
    server
        .process_new_packets()
        .expect("server processes app data");
    let mut plain = [0u8; 64];
    let n = server.reader().read(&mut plain).expect("server reads");
    assert_eq!(&plain[..n], b"GET / HTTP/1.1\r\n\r\n");

    // and the server's write reaches us
    server
        .writer()
        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .expect("server writes");
    let mut from_server = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut from_server).expect("server seals");
    }
    pipe.incoming.extend_from_slice(&from_server);
    let mut got = [0u8; 64];
    let n = connection.read(&mut pipe, &mut got).expect("read");
    assert_eq!(&got[..n], b"HTTP/1.1 204 No Content\r\n\r\n");

    // a second record in the other direction keeps the sequence numbers apart
    connection.write(&mut pipe, b"second").expect("write again");
    let to_server = std::mem::take(&mut pipe.outgoing);
    server
        .read_tls(&mut to_server.as_slice())
        .expect("second to server");
    server.process_new_packets().expect("server processes");
    let n = server
        .reader()
        .read(&mut plain)
        .expect("server reads again");
    assert_eq!(&plain[..n], b"second");
}
