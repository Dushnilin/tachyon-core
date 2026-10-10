//! The handshake, end to end, against a server that is not us.
//!
//! Our client state machine on one side, rustls' on the other, and a real
//! certificate in between: the point is not that the parts pass their own tests
//! but that a hello built from a captured fingerprint completes a handshake
//! with an implementation that shares none of our code.
//!
//! The two sides talk through `tokio::io::duplex`, with the server on its own
//! task, so the exchange is the real asynchronous one the runtime does -- the
//! same path a socket takes, with no timing races a loopback port would add.

use std::io::{Read, Write};
use std::sync::Arc;

use core_tls::client::{self, Config, Handshake, Record};
use core_tls::fingerprints;
use core_tls::hello::parse_record;
use core_tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use core_tls::rustls::{self, RootCertStore, ServerConfig};
use core_tls::verify::{CertVerifier, WebpkiVerifier};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[derive(Debug)]
struct TestCompressor(u16);

impl rustls::compress::CertCompressor for TestCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        _: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        let mut out = Vec::new();
        match self.0 {
            1 => {
                let mut writer =
                    flate2::write::ZlibEncoder::new(out, flate2::Compression::default());
                writer.write_all(&input).unwrap();
                out = writer.finish().unwrap();
            }
            2 => {
                brotli::BrotliCompress(
                    &mut &input[..],
                    &mut out,
                    &brotli::enc::BrotliEncoderParams::default(),
                )
                .unwrap();
            }
            3 => {
                out = ruzstd::encoding::compress_to_vec(
                    &input[..],
                    ruzstd::encoding::CompressionLevel::Fastest,
                );
            }
            _ => unreachable!(),
        }
        assert!(out.len() < input.len(), "fixture must actually compress");
        Ok(out)
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        self.0.into()
    }
}

#[tokio::test]
async fn modern_profiles_accept_compressed_certificates_and_verify_finished() {
    static COMPRESSORS: [TestCompressor; 3] =
        [TestCompressor(1), TestCompressor(2), TestCompressor(3)];
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).unwrap();
    for compressor in &COMPRESSORS {
        let done = shake_compressed(&verifier, "firefox", "localhost", Some(compressor))
            .await
            .expect("compressed certificate handshake and Finished verification");
        assert_eq!(done.leaf.as_ref(), Some(&certs[0]));
    }
}

/// The certificate the repository already carries for its own golden tests: self
/// signed for `localhost`, valid until 2036. A checked-in certificate is the
/// only kind that can be a test fixture -- one generated per run would need a
/// signing backend, and every pure-Rust one we could add is a dependency this
/// project does not want.
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
    assert_eq!(certs.len(), 1, "one certificate, no chain");
    (certs, key)
}

fn roots_trusting(cert: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("add the root");
    roots
}

fn server() -> ServerConfig {
    let (certs, key) = fixture();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a server config from one certificate");
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

/// One round of the server's side: take whatever the socket has, let rustls
/// process it, and write out what it wants. rustls' own state machine is
/// synchronous, so the socket is what has to be adapted -- and a `Vec` is
/// enough, because the plaintext it produces is what the test looks at.
async fn server_round(
    conn: &mut rustls::ServerConnection,
    sock: &mut DuplexStream,
    scratch: &mut [u8],
) -> std::io::Result<(usize, Vec<u8>)> {
    let n = sock.read(scratch).await?;
    if n > 0 {
        conn.read_tls(&mut &scratch[..n])?;
    }
    conn.process_new_packets()
        .map_err(|e| std::io::Error::other(format!("the server rejected the flight: {e}")))?;
    let mut out = Vec::new();
    while conn.wants_write() {
        let mut chunk = Vec::new();
        conn.write_tls(&mut chunk)?;
        out.extend_from_slice(&chunk);
    }
    if !out.is_empty() {
        sock.write_all(&out).await?;
    }
    let mut plain = Vec::new();
    let mut small = [0u8; 4096];
    while let Ok(n) = conn.reader().read(&mut small) {
        if n == 0 {
            break;
        }
        plain.extend_from_slice(&small[..n]);
    }
    Ok((n, plain))
}

#[derive(Debug)]
struct Outcome {
    leaf: Option<CertificateDer<'static>>,
    client_alpn: Option<Vec<u8>>,
    server_alpn: Option<Vec<u8>>,
}

/// Pump one handshake through, and report what the client made of it.
async fn shake(
    verifier: &dyn CertVerifier,
    fingerprint: &str,
    server_name: &str,
) -> Result<Outcome, String> {
    shake_compressed(verifier, fingerprint, server_name, None).await
}

async fn shake_compressed(
    verifier: &dyn CertVerifier,
    fingerprint: &str,
    server_name: &str,
    compressor: Option<&'static dyn rustls::compress::CertCompressor>,
) -> Result<Outcome, String> {
    core_tls::install_default_provider();
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut sock = server_side;
        let mut config = server();
        if let Some(compressor) = compressor {
            config.cert_compressors = vec![compressor];
        }
        let mut conn =
            rustls::ServerConnection::new(Arc::new(config)).expect("a server connection");
        let mut scratch = [0u8; 4096];
        // reading drives the handshake: the flight goes out, the client's
        // Finished comes back
        while conn.is_handshaking() {
            match server_round(&mut conn, &mut sock, &mut scratch).await {
                Ok((0, _)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        if conn.is_handshaking() {
            return Err("the server did not finish its handshake".to_string());
        }
        Ok(conn.alpn_protocol().map(|p| p.to_vec()))
    });

    let template =
        fingerprints::by_name(fingerprint).ok_or_else(|| format!("no table for {fingerprint}"))?;
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let config = Config {
        template: &template,
        server_name,
        alpn: &alpn,
        verifier,
        reality: None,
        fragment: false,
        cipher_suites: Vec::new(),
    };
    let mut client = Handshake::new(config).map_err(|e| e.to_string())?;
    let mut sock = client_side;
    let ours = client.run(&mut sock).await.map_err(|e| e.to_string());
    // A refused handshake has to close our side before the server task is
    // awaited: it is parked on a read that will never get anything, and the
    // socket still being alive here is exactly the bug this line is about.
    let theirs = match ours {
        Ok(()) => server.await,
        Err(e) => {
            drop(sock);
            let _ = server.await;
            return Err(e);
        }
    };

    match theirs {
        Ok(Ok(server_alpn)) => Ok(Outcome {
            leaf: client.leaf().cloned(),
            client_alpn: client.alpn.clone(),
            server_alpn,
        }),
        Ok(Err(e)) => Err(format!("the server said nothing: {e}")),
        Err(e) => Err(format!("the server task failed: {e}")),
    }
}

/// The whole thing: our hello, the server's flight, our Finished, and both sides
/// agreeing afterwards.
#[tokio::test]
async fn the_handshake_completes_against_a_rustls_server() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let done = shake(&verifier, "chrome", "localhost")
        .await
        .expect("the handshake");
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
}

#[tokio::test]
async fn random_policies_complete_tls_and_negotiate_h2() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).unwrap();
    for name in ["random", "randomized"] {
        let done = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            shake(&verifier, name, "localhost"),
        )
        .await
        .expect("bounded handshake")
        .expect("random profile handshake");
        assert_eq!(done.leaf.as_ref(), Some(&certs[0]));
        assert_eq!(done.client_alpn, Some(b"h2".to_vec()));
        assert_eq!(done.server_alpn, Some(b"h2".to_vec()));
    }
}

/// A verifier that trusts nobody must stop the handshake. The Finished check on
/// its own would pass here: it only proves the peer holds the same keys, not
/// that anybody vouched for them.
#[tokio::test]
async fn a_verifier_that_says_no_stops_the_handshake() {
    #[derive(Debug)]
    struct TrustsNobody;
    impl CertVerifier for TrustsNobody {
        fn verify_chain(
            &self,
            _leaf: &CertificateDer<'_>,
            _chain: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
        ) -> std::io::Result<()> {
            Err(std::io::Error::other("this test trusts nobody"))
        }
        fn verify_handshake_signature(
            &self,
            _signed: &[u8],
            _leaf: &CertificateDer<'_>,
            _scheme: u16,
            _signature: &[u8],
        ) -> std::io::Result<()> {
            Ok(())
        }
    }
    let err = shake(&TrustsNobody, "chrome", "localhost")
        .await
        .expect_err("a refused chain must not pass");
    assert!(
        err.contains("trusts nobody"),
        "the failure must say why: {err}"
    );
}

/// A name the certificate does not carry must fail: the chain is fine, the
/// hostname is not, and the two are checked separately.
#[tokio::test]
async fn a_name_the_certificate_does_not_carry_is_refused() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let err = shake(&verifier, "chrome", "not-localhost.example")
        .await
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
#[tokio::test]
async fn the_server_may_pick_a_later_group_from_our_share() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    shake(&verifier, "chrome", "localhost")
        .await
        .expect("chrome");
    shake(&verifier, "firefox", "localhost")
        .await
        .expect("firefox offers three groups");
    shake(&verifier, "safari", "localhost")
        .await
        .expect("safari");
}

/// The handshake is only half of it: after it, application data has to flow
/// through the same record layer, with the record sequence numbers carrying on
/// from the handshake and the two directions on their own keys.
#[tokio::test]
async fn application_data_flows_after_the_handshake() {
    core_tls::install_default_provider();
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut sock = server_side;
        let mut conn =
            rustls::ServerConnection::new(Arc::new(server())).expect("a server connection");
        let mut scratch = [0u8; 4096];
        let mut request = Vec::new();
        while conn.is_handshaking() {
            match server_round(&mut conn, &mut sock, &mut scratch).await {
                Ok((0, _)) | Err(_) => break,
                // the client's first request can land in the very round that
                // finishes the handshake, and it is decrypted here
                Ok((_, plain)) => {
                    if !plain.is_empty() {
                        request = plain;
                    }
                }
            }
        }
        // the request, then an answer
        while request.is_empty() {
            let (_, plain) = server_round(&mut conn, &mut sock, &mut scratch)
                .await
                .expect("the request");
            request = plain;
        }
        conn.writer()
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .expect("the answer");
        let mut out = Vec::new();
        while conn.wants_write() {
            let mut chunk = Vec::new();
            conn.write_tls(&mut chunk).expect("seal the answer");
            out.extend_from_slice(&chunk);
        }
        sock.write_all(&out).await.expect("the answer goes out");
        String::from_utf8_lossy(&request).to_string()
    });

    let template = fingerprints::by_name("chrome").expect("a chrome table");
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let config = Config {
        template: &template,
        server_name: "localhost",
        alpn: &alpn,
        verifier: &verifier,
        reality: None,
        fragment: false,
        cipher_suites: Vec::new(),
    };
    let mut client = Handshake::new(config).expect("a handshake");
    let mut sock = client_side;
    let deadline = std::time::Duration::from_secs(20);
    tokio::time::timeout(deadline, client.run(&mut sock))
        .await
        .expect("the handshake does not hang")
        .expect("the handshake");
    let mut connection = client::Connection::new(&mut client).expect("application keys");

    let record = connection
        .write_record(b"GET / HTTP/1.1\r\n\r\n")
        .expect("seal");
    sock.write_all(&record).await.expect("the request goes out");

    // and the answer comes back, decrypted
    let mut raw = Vec::new();
    let mut at = 0usize;
    let mut chunk = [0u8; 4096];
    let mut answer: Option<Vec<u8>> = None;
    while answer.is_none() {
        // A server sends its session tickets at this level, before any data, so
        // the buffer can hold a post-handshake record before the answer: step over
        // whatever is whole and look at the next, and only read when what is left
        // is not a record yet.
        loop {
            match connection
                .read_record_in_place(&mut raw[at..])
                .expect("open the record")
            {
                Some(Record::Data {
                    start,
                    end,
                    record_end,
                }) => {
                    let data = raw[at + start..at + end].to_vec();
                    at += record_end;
                    if !data.is_empty() {
                        answer = Some(data);
                        break;
                    }
                }
                Some(Record::Skip { record_end }) => at += record_end,
                None => break,
            }
        }
        if answer.is_some() {
            break;
        }
        let n = sock.read(&mut chunk).await.expect("read the socket");
        assert_ne!(n, 0, "the server closed before answering");
        raw.extend_from_slice(&chunk[..n]);
    }
    let answer = answer.expect("the answer came");
    assert_eq!(answer, b"HTTP/1.1 204 No Content\r\n\r\n");
    let request = tokio::time::timeout(deadline, server)
        .await
        .expect("the server task does not hang")
        .expect("the server task");
    assert_eq!(request, "GET / HTTP/1.1\r\n\r\n");
}

/// The client half of REALITY, checked against the server's half computed here.
///
/// A REALITY server never answers this handshake in a way we could test without
/// one, but the *seal* can be checked from the outside: the test holds the
/// server's X25519 private key, reads the X25519 share out of the hello we sent,
/// runs the exchange itself, derives the auth key from the hello's own random
/// and opens the session id. If any of that disagreed with the server's own
/// arithmetic by one byte, the seal would not open.
#[tokio::test]
async fn a_reality_session_id_opens_under_the_servers_own_arithmetic() {
    reality_session_id_opens("chrome").await;
    reality_session_id_opens("randomized").await;
    reality_session_id_opens("random").await;
}

async fn reality_session_id_opens(fingerprint: &str) {
    use core_tls::keyshare::X25519MLKEM768;
    use core_tls::reality;

    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let template = fingerprints::by_name(fingerprint).expect("a profile");
    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let server_public: [u8; 32] = *x25519_dalek::PublicKey::from(&server_secret).as_bytes();
    let short_id = b"\x12\x34\xab\xcd";

    let (mut client_side, mut server_side) = tokio::io::duplex(64 * 1024);
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let config = Config {
        template: &template,
        server_name: "www.gstatic.com",
        alpn: &alpn,
        verifier: &verifier,
        reality: Some(core_tls::client::RealitySeal {
            public_key: &server_public,
            short_id,
        }),
        fragment: false,
        cipher_suites: Vec::new(),
    };
    let mut client = Handshake::new(config).expect("a handshake");
    client.start(&mut client_side).await.expect("hello");

    // everything the server would read out of the record
    let mut header = [0u8; 5];
    server_side
        .read_exact(&mut header)
        .await
        .expect("record header");
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = vec![0u8; len];
    server_side
        .read_exact(&mut record)
        .await
        .expect("record body");
    let mut full = header.to_vec();
    full.extend_from_slice(&record);

    let parsed = parse_record(&full).expect("a ClientHello");
    assert_eq!(parsed.sni, "www.gstatic.com");
    assert_eq!(
        parsed.session_id.len(),
        32,
        "REALITY needs the compat space"
    );

    // the session id on the wire is ciphertext: only the server can read the
    // version, the time and the short id out of it
    let id = &full[reality::SESSION_ID_OFFSET..reality::SESSION_ID_OFFSET + 32];
    assert_ne!(
        &id[..3],
        &reality::VERSION,
        "the session id went out unsealed"
    );

    // the X25519 share we offered is the tail of the hybrid entry
    let key_share = parsed
        .template
        .extensions
        .iter()
        .find_map(|e| match e {
            core_tls::hello::Ext::KeyShare(body) => Some(body.clone()),
            _ => None,
        })
        .expect("the profile key share");
    let shares = core_tls::keyshare::entries(&key_share).expect("the share list");
    // the server scans the shares and takes the first plain X25519, not the
    // hybrid's half, so that is the key the exchange has to be run with
    let offered: [u8; 32] = shares
        .iter()
        .find(|(group, _)| *group == core_tls::keyshare::X25519)
        .expect("the plain share")
        .1
        .try_into()
        .expect("32 bytes");
    if fingerprint != "random" {
        let (_, hybrid) = shares
            .iter()
            .find(|(group, _)| *group == X25519MLKEM768)
            .expect("the hybrid share");
        assert_ne!(&hybrid[1184..], &offered[..], "two independent keys");
    }

    // the server's half of the exchange, computed here
    let shared = server_secret.diffie_hellman(&offered.into());
    let random: [u8; 32] = full[11..43].try_into().expect("32 bytes of random");
    let auth_key = reality::auth_key(shared.as_bytes(), &random);

    // and the seal opens, which is the whole claim
    let opened = reality::open_session_id(&full, &auth_key).expect("the session id opens");
    assert_eq!(&opened[..3], &reality::VERSION);
    assert_eq!(&opened[8..12], short_id);
    let time = u32::from_be_bytes(opened[4..8].try_into().expect("4 bytes"));
    assert!(time > 1_700_000_000, "a plausible unix time, got {time}");
    // the auth key we used is the one the handshake says it used
    assert_eq!(client.auth_key().expect("an auth key"), auth_key);
}

#[tokio::test]
async fn client_cipher_suites_override_emits_only_specified_suites() {
    let (certs, _) = fixture();
    let verifier = WebpkiVerifier::new(Arc::new(roots_trusting(&certs[0]))).expect("a verifier");
    let template = fingerprints::by_name("chrome").expect("a chrome table");

    let (mut client_side, mut server_side) = tokio::io::duplex(64 * 1024);
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let config = Config {
        template: &template,
        server_name: "localhost",
        alpn: &alpn,
        verifier: &verifier,
        reality: None,
        fragment: false,
        cipher_suites: vec![0x1303], // ChaCha20 only
    };
    let mut client = Handshake::new(config).expect("a handshake");
    client.start(&mut client_side).await.expect("hello");

    let mut header = [0u8; 5];
    server_side.read_exact(&mut header).await.expect("header");
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    server_side.read_exact(&mut body).await.expect("body");

    let parsed =
        core_tls::hello::parse_record(&[&header[..], &body[..]].concat()).expect("parse hello");
    // Should only have 0x1303 (2 bytes)
    assert_eq!(parsed.template.cipher_suites, vec![0x13, 0x03]);
}
