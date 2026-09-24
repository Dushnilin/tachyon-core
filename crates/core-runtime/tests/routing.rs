//! Routing engine integration: rule walk, actions, sniff, hijack-dns.

use std::net::{Ipv4Addr, SocketAddr};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use core_runtime::dns::codec;

/// Serialize box instances: the dns service is process-global.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_udp_dns(answer_ip: Ipv4Addr) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = hickory_proto::op::Message::from_vec(&buf[..n]) else {
                continue;
            };
            let resp = codec::synth_address(&query, answer_ip.into(), 60).expect("answer");
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
        }
    });
    addr
}

fn box_cfg(outbounds: Value, route: Value) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": outbounds,
        "route": route
    })
}

async fn start_box(cfg: Value) -> (core_runtime::BoxInstance, SocketAddr) {
    let instance = core_runtime::start(&cfg).await.expect("start box");
    let addr = instance
        .inbound_addrs()
        .iter()
        .find(|(tag, _)| tag == "mixed-in")
        .map(|(_, addr)| *addr)
        .expect("mixed inbound addr");
    (instance, addr)
}

/// SOCKS5 CONNECT handshake; returns the stream + reply code.
async fn socks_connect(inbound: SocketAddr, dest: Target) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00];
    match dest {
        Target::V4(ip, port) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
            request.extend_from_slice(&port.to_be_bytes());
        }
        Target::Domain(ref host, port) => {
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[0], 0x05, "socks version");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd");
    (stream, reply[1])
}

enum Target {
    V4(std::net::Ipv4Addr, u16),
    Domain(String, u16),
}

fn direct_and_block() -> Value {
    json!([
        {"type": "direct", "tag": "out"},
        {"type": "block", "tag": "blk"}
    ])
}

async fn assert_echo_roundtrip(mut stream: TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.expect("write");
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(buf, payload);
}

fn v4_of(addr: SocketAddr) -> std::net::Ipv4Addr {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => panic!("expected v4 test addr"),
    }
}

// ---------------------------------------------------------------------------
// Port rule → outbound; final block fails non-matching ports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn port_rule_routes_to_direct() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        direct_and_block(),
        json!({
            "rules": [{"action": "route", "outbound": "out", "port": [echo.port()]}],
            "final": "blk"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    let (_, code) = socks_connect(inbound, Target::V4(v4_of(echo), echo.port())).await;
    assert_eq!(code, 0x00, "matching port must route to direct");

    let (_, code) = socks_connect(inbound, Target::V4(v4_of(echo), 1)).await;
    assert_eq!(code, 0x01, "non-matching port must hit final block");

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// Domain rule + override redirect (route options applied in the route action)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn domain_rule_override_redirects() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        direct_and_block(),
        json!({
            "rules": [
                {
                    "action": "route",
                    "outbound": "out",
                    "domain_suffix": [".redirect.test"],
                    "override_address": "127.0.0.1",
                    "override_port": echo.port()
                }
            ],
            "final": "blk"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    let stream = socks_connect(inbound, Target::Domain("foo.redirect.test".into(), 12345)).await;
    assert_eq!(stream.1, 0x00, "matching domain must route to direct");
    assert_echo_roundtrip(stream.0, b"redir").await;

    let (_, code) = socks_connect(inbound, Target::Domain("other.test".into(), 12345)).await;
    assert_eq!(code, 0x01, "non-matching domain must hit final block");

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// route-options continues the walk (non-terminal); second rule matches on port
// ---------------------------------------------------------------------------

#[tokio::test]
async fn route_options_continue_then_route() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        direct_and_block(),
        json!({
            "rules": [
                {
                    "action": "route-options",
                    "domain_suffix": [".redirect.test"],
                    "override_address": "127.0.0.1",
                    "override_port": echo.port()
                },
                {"action": "route", "outbound": "out", "port": [echo.port()]}
            ],
            "final": "blk"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    // After override the port is echo.port(), so the second rule matches.
    let (stream, code) =
        socks_connect(inbound, Target::Domain("foo.redirect.test".into(), 12345)).await;
    assert_eq!(code, 0x00, "route-options + matching route must succeed");
    assert_echo_roundtrip(stream, b"cont").await;

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// Reject action → SOCKS 0x01 (general failure, synthetic error)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reject_rule_fails_connect() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        json!([{"type": "direct", "tag": "out"}]),
        json!({
            "rules": [{"action": "reject", "port": [echo.port()]}],
            "final": "out"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    // Echo is listening, but the reject rule must fail the CONNECT.
    let (_, code) = socks_connect(inbound, Target::V4(v4_of(echo), echo.port())).await;
    assert_eq!(code, 0x01, "reject must fail CONNECT");

    // A non-matching port falls through to final direct (dial may fail — any code).
    let _ = socks_connect(inbound, Target::V4(v4_of(echo), 1)).await;

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// Unknown outbound tag → connection-time error (not build-time)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_outbound_tag_fails_connection() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        json!([{"type": "direct", "tag": "out"}]),
        json!({
            "rules": [{"action": "route", "outbound": "missing", "port": [echo.port()]}],
            "final": "out"
        }),
    );
    // Build succeeds (tag checked at connection time).
    let (instance, inbound) = start_box(cfg).await;

    let (_, code) = socks_connect(inbound, Target::V4(v4_of(echo), echo.port())).await;
    assert_eq!(code, 0x01, "unknown outbound must fail CONNECT");

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// direct action is a non-terminal no-op (falls through to final block)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_action_continues_to_final() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        direct_and_block(),
        json!({
            "rules": [{"action": "direct"}],
            "final": "blk"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    let (_, code) = socks_connect(inbound, Target::V4(v4_of(echo), echo.port())).await;
    assert_eq!(code, 0x01, "direct must not terminate; final block applies");

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// invert flips a port reject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invert_flips_match() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        json!([{"type": "direct", "tag": "out"}]),
        json!({
            "rules": [{"action": "reject", "port": [echo.port()], "invert": true}],
            "final": "out"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    // invert: reject matches everything EXCEPT echo.port → echo must pass.
    let (stream, code) = socks_connect(inbound, Target::V4(v4_of(echo), echo.port())).await;
    assert_eq!(code, 0x00, "inverted reject must not match echo port");
    assert_echo_roundtrip(stream, b"inv").await;

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// Logical AND: domain + port must both match
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logical_and_requires_both() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        direct_and_block(),
        json!({
            "rules": [{
                "type": "logical", "mode": "and",
                "action": "route", "outbound": "out",
                "override_address": "127.0.0.1",
                "override_port": echo.port(),
                "rules": [
                    {"domain_suffix": [".redirect.test"]},
                    {"port": [12345]}
                ]
            }],
            "final": "blk"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    let (stream, code) =
        socks_connect(inbound, Target::Domain("x.redirect.test".into(), 12345)).await;
    assert_eq!(code, 0x00, "logical and must match");
    assert_echo_roundtrip(stream, b"logi").await;

    let (_, code) = socks_connect(inbound, Target::Domain("x.redirect.test".into(), 9999)).await;
    assert_eq!(code, 0x01, "port mismatch must fail logical and");

    let (_, code) = socks_connect(inbound, Target::Domain("x.other.test".into(), 12345)).await;
    assert_eq!(code, 0x01, "domain mismatch must fail logical and");

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// TLS sniff: SNI selects the outbound; prefix is replayed upstream
// ---------------------------------------------------------------------------

fn client_hello(sni: &str) -> Vec<u8> {
    let template = core_tls::hello::Template {
        record_version: [0x03, 0x01],
        client_version: [0x03, 0x03],
        cipher_suites: vec![0x00, 0x2f],
        compression: vec![0x00],
        extensions: vec![core_tls::hello::Ext::Sni],
    };
    core_tls::hello::build(&template, &[0x11; 32], &[], sni, None).expect("client hello")
}

#[tokio::test]
async fn tls_sniff_routes_by_sni() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = box_cfg(
        direct_and_block(),
        json!({
            "rules": [
                {"action": "sniff"},
                {"action": "route", "outbound": "out", "domain": "sni.test"}
            ],
            "final": "blk"
        }),
    );
    let (instance, inbound) = start_box(cfg).await;

    let hello = client_hello("sni.test");
    let (stream, code) = socks_connect(inbound, Target::V4(v4_of(echo), echo.port())).await;
    assert_eq!(code, 0x00, "sniffed SNI must route to direct");

    // Prefix (the ClientHello) is replayed to the echo upstream.
    assert_echo_roundtrip(stream, &hello).await;

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// hijack-dns: TCP length-prefixed queries answered via the dns section
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hijack_dns_answers_queries() {
    let _g = test_guard().await;
    let mock = spawn_udp_dns(Ipv4Addr::new(9, 9, 9, 9)).await;
    let cfg = json!({
        "log": {"level": "warn"},
        "dns": {
            "servers": [{
                "type": "udp", "tag": "u",
                "server": "127.0.0.1", "server_port": mock.port()
            }],
            "final": "u"
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {
            "rules": [{"action": "hijack-dns", "port": [53]}],
            "final": "out"
        }
    });
    let (instance, inbound) = start_box(cfg).await;

    let (mut stream, code) = socks_connect(inbound, Target::V4(Ipv4Addr::LOCALHOST, 53)).await;
    assert_eq!(code, 0x00, "hijack-dns must accept CONNECT");

    let query =
        codec::build_query(0x1234, "hijack.test", hickory_proto::rr::RecordType::A).expect("query");
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await.expect("send query");

    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.expect("resp len");
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.expect("resp body");
    let ips = codec::answer_ips(&body).expect("parse answer");
    assert!(
        ips.iter()
            .any(|ip| *ip == std::net::IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        "expected mock answer, got {ips:?}"
    );

    instance.shutdown();
}

// ---------------------------------------------------------------------------
// route-options udp_timeout / empty route option action rejected at build
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_route_option_action_rejected() {
    let _g = test_guard().await;
    let res = core_runtime::start(&box_cfg(
        json!([{"type": "direct", "tag": "out"}]),
        json!({
            "rules": [{"action": "route-options"}],
            "final": "out"
        }),
    ))
    .await;
    let err = match res {
        Ok(_) => panic!("empty route option action must fail"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("empty route option action"),
        "{err}"
    );
}
