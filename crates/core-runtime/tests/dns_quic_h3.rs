//! The two QUIC DNS transports against local servers: `type: quic` (DoQ,
//! RFC 9250) and `type: h3` (DoH over HTTP/3), plus the `dns.headers` the
//! reference clones onto every DoH request.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use core_runtime::dns::codec;
use core_runtime::dns::transport::{Dialer, ServerConfig, exchange};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use serde_json::{Value, json};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const ANSWER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const PROBE: &str = "x-tachyon-probe";

/// What the h3 responder saw: `<probe>|<content-type>` of the POST.
type Seen = Arc<std::sync::Mutex<Option<String>>>;

/// Build an A answer for a raw query, the way the test responders do.
fn answer_to(raw: &[u8]) -> Vec<u8> {
    let query = Message::from_vec(raw).expect("parse query");
    codec::synth_address(&query, ANSWER.into(), 60).expect("encode answer")
}

/// A quinn server config over the localhost test certificate with one ALPN.
fn quic_server_config(alpn: &[u8]) -> quinn::ServerConfig {
    core_tls::install_default_provider();
    let certs: Vec<_> = rustls_pemfile::certs(&mut CERT_PEM.as_bytes())
        .collect::<Result<_, _>>()
        .expect("parse cert");
    let key = rustls_pemfile::private_key(&mut KEY_PEM.as_bytes())
        .expect("key read")
        .expect("key present");
    let mut cfg = core_tls::rustls::ServerConfig::builder_with_provider(
        core_tls::quic::configured_provider(),
    )
    .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
    .expect("tls 1.3")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("server cert");
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let crypto = core_tls::quic::QuicServerConfig::try_from(cfg).expect("quic crypto");
    quinn::ServerConfig::new(
        Arc::new(crypto),
        Arc::new(core_tls::quic::HandshakeTokenKeyRustCrypto::new([7u8; 64])),
    )
}

/// A QUIC endpoint answering one query per accepted connection.
async fn spawn_quic(alpn: &'static [u8], mode: &'static str) -> (SocketAddr, Seen) {
    let seen: Seen = Arc::new(std::sync::Mutex::new(None));
    let spawn_seen = Arc::clone(&seen);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind quic");
    let runtime = quinn::default_runtime().expect("quinn runtime");
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[9u8; 32]))),
        Some(quic_server_config(alpn)),
        socket,
        runtime,
    )
    .expect("quic endpoint");
    let addr = endpoint.local_addr().expect("endpoint addr");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let seen = Arc::clone(&spawn_seen);
            tokio::spawn(async move {
                let connection = match incoming.accept() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("quic server: accept: {e}");
                        return None;
                    }
                };
                let connection = match connection.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("quic server: handshake: {e}");
                        return None;
                    }
                };
                if mode == "doq" {
                    serve_doq(connection).await
                } else {
                    serve_h3(connection, seen).await
                }
            });
        }
    });
    (addr, seen)
}

/// DoQ: one bidi stream, two-octet length prefix, exactly as the client sends.
async fn serve_doq(connection: quinn::Connection) -> Option<()> {
    let (mut send, mut recv) = match connection.accept_bi().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("doq server: accept_bi: {e}");
            return None;
        }
    };
    let mut len = [0u8; 2];
    if let Err(e) = recv.read_exact(&mut len).await {
        eprintln!("doq server: read len: {e}");
        return None;
    }
    let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
    if let Err(e) = recv.read_exact(&mut query).await {
        eprintln!("doq server: read query: {e}");
        return None;
    }
    let answer = answer_to(&query);
    if let Err(e) = send.write_all(&(answer.len() as u16).to_be_bytes()).await {
        eprintln!("doq server: write len: {e}");
        return None;
    }
    if let Err(e) = send.write_all(&answer).await {
        eprintln!("doq server: write answer: {e}");
        return None;
    }
    if let Err(e) = send.finish() {
        eprintln!("doq server: finish: {e}");
        return None;
    }
    // quinn closes the connection as soon as the last handle drops, which
    // would race the answer off the wire: hold it until the client is done.
    let _ = connection.closed().await;
    Some(())
}

/// DoH over HTTP/3: answer the single POST, remembering its headers.
async fn serve_h3(connection: quinn::Connection, seen: Seen) -> Option<()> {
    let mut conn = h3::server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await
        .ok()?;
    while let Some(resolver) = conn.accept().await.ok()? {
        let (request, mut stream) = resolver.resolve_request().await.ok()?;
        let probe = request.headers().get(PROBE).and_then(|v| v.to_str().ok());
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        *seen.lock().expect("seen lock") =
            Some(format!("{}|{}", probe.unwrap_or("-"), content_type.unwrap_or("-")));
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.ok()? {
            body.extend_from_slice(bytes::Buf::chunk(&chunk));
        }
        let answer = answer_to(&body);
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/dns-message")
            .body(())
            .ok()?;
        stream.send_response(response).await.ok()?;
        stream.send_data(bytes::Bytes::from(answer)).await.ok()?;
        stream.finish().await.ok()?;
    }
    Some(())
}

/// The client under test: an `insecure` TLS block (the test cert is not in
/// the system roots) pointed at the local responder.
fn client(kind: &str, addr: SocketAddr, headers: Value) -> ServerConfig {
    let mut server = json!({
        "type": kind,
        "tag": kind,
        "server": "127.0.0.1",
        "server_port": addr.port(),
        "tls": {"enabled": true, "insecure": true, "server_name": "localhost"}
    });
    server
        .as_object_mut()
        .expect("server object")
        .insert("headers".to_string(), headers);
    ServerConfig::build(&server, "dns.servers[0]").expect("server config")
}

async fn roundtrip(kind: &'static str, alpn: &'static [u8], mode: &'static str, headers: Value) {
    let (addr, seen) = spawn_quic(alpn, mode).await;
    let server = client(kind, addr, headers);
    let dialer = Dialer { router: None };
    let query = codec::build_query(0x1234, "quic.test", RecordType::A).expect("query");
    let raw = exchange(&server, addr, &query, &dialer)
        .await
        .expect("exchange");
    let message = codec::parse_message(&raw).expect("decode response");
    assert_eq!(message.queries.len(), 1, "question echoed");
    assert_eq!(message.answers.len(), 1, "one answer");
    assert_eq!(message.answers[0].data.to_string(), ANSWER.to_string());
    // the responder echoes the id it saw on the wire, and the reference sends
    // `Id = 0` for https / h3 / quic
    assert_eq!(message.metadata.id, 0, "wire query id must be 0");
    if mode == "h3" {
        let seen = seen.lock().expect("seen lock").clone().expect("h3 ran");
        assert_eq!(seen, "yes|application/dns-message", "headers on the wire");
    }
}

#[tokio::test]
async fn doq_transport_queries_a_local_server() {
    roundtrip("quic", b"doq", "doq", json!(null)).await;
}

#[tokio::test]
async fn h3_transport_queries_a_local_server() {
    // the configured content-type must lose to application/dns-message, as it
    // does in the reference (Header.Set after the clone)
    roundtrip(
        "h3",
        b"h3",
        "h3",
        json!({PROBE: "yes", "content-type": "text/plain"}),
    )
    .await;
}
