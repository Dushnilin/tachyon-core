//! Inbound integration: direct (override), redirect, tproxy, plain-http proxy,
//! UDP forward + UDP hijack-dns.

use std::net::SocketAddr;

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

/// Minimal origin server for plain-http forward tests: one request per
/// connection, replies with a fixed body echoing the path.
async fn spawn_http_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                            if head.len() > 16 * 1024 {
                                return;
                            }
                        }
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let mut content_len = 0usize;
                for line in text.lines() {
                    if let Some((name, value)) = line.split_once(':')
                        && name.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = value.trim().parse().unwrap_or(0);
                    }
                }
                if content_len > 0 {
                    let mut body = vec![0u8; content_len];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                }
                let request_line = text.lines().next().unwrap_or_default().to_string();
                let path = request_line.split_whitespace().nth(1).unwrap_or("?");
                let body = format!("hello from origin path={path}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                // Leave the connection open briefly; client reads then drops.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            });
        }
    });
    addr
}

fn base_cfg(inbounds: Value, outbounds: Value, route: Value) -> Value {
    json!({
        "log": {"level": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route
    })
}

async fn start_box(cfg: Value) -> core_runtime::BoxInstance {
    core_runtime::start(&cfg).await.expect("start box")
}

fn inbound_addr(instance: &core_runtime::BoxInstance, tag: &str) -> SocketAddr {
    instance
        .inbound_addrs()
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, a)| *a)
        .unwrap_or_else(|| panic!("no inbound {tag}"))
}

async fn read_response(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    // Head is complete; keep reading until Content-Length body
                    // arrives or the peer closes (tests use Connection: close).
                    if let Some(text) = std::str::from_utf8(&buf).ok()
                        && (text.contains("Connection: close") || !text.contains("Content-Length"))
                    {
                        // fall through to keep reading until EOF
                    }
                }
            }
            Ok(Err(_)) => break,
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn direct_inbound_override_to_echo() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "direct",
                "tag": "direct-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "override_address": "127.0.0.1",
                "override_port": echo.port()
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "direct-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect direct");
    stream.write_all(b"hello-direct").await.expect("write");
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read echo");
    assert_eq!(&buf[..n], b"hello-direct");
    instance.shutdown();
}

#[tokio::test]
async fn direct_inbound_override_port_only() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    // Destination without override_port would be the inbound's own address
    // (127.0.0.1:0 → whatever port we got); override_port only keeps the
    // original address (127.0.0.1) and swaps the port to the echo.
    let cfg = base_cfg(
        json!([
            {
                "type": "direct",
                "tag": "direct-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "override_port": echo.port()
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "direct-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect direct");
    stream.write_all(b"port-only").await.expect("write");
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read echo");
    assert_eq!(&buf[..n], b"port-only");
    instance.shutdown();
}

#[tokio::test]
async fn redirect_inbound_without_nat_closes_connection() {
    let _g = test_guard().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "redirect",
                "tag": "redir-in",
                "listen": "127.0.0.1",
                "listen_port": 0
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "redir-in");

    // Without iptables REDIRECT there is no original destination: on Linux
    // SO_ORIGINAL_DST fails with ENOENT, elsewhere unsupported — either way
    // the connection is accepted then closed before route.
    let mut stream = TcpStream::connect(addr).await.expect("connect redirect");
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("close timeout")
        .expect("read after accept");
    assert_eq!(n, 0, "expected connection close without NAT entry");
    instance.shutdown();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tproxy_inbound_linux_accepts_and_routes() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    // IP_TRANSPARENT requires CAP_NET_ADMIN; without it bind fails with
    // EPERM — skip rather than fail so unprivileged CI still runs.
    let cfg = base_cfg(
        json!([
            {
                "type": "tproxy",
                "tag": "tproxy-in",
                "listen": "127.0.0.1",
                "listen_port": 0
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({
            "rules": [{
                "inbound": ["tproxy-in"],
                "action": "route",
                "outbound": "out",
                "override_address": "127.0.0.1",
                "override_port": echo.port()
            }],
            "final": "out"
        }),
    );
    let instance = match core_runtime::start(&cfg).await {
        Ok(i) => i,
        Err(err) if err.to_string().contains("Operation not permitted") => {
            eprintln!("tproxy test skipped: {err}");
            return;
        }
        Err(err) => panic!("tproxy start failed: {err}"),
    };
    let addr = inbound_addr(&instance, "tproxy-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect tproxy");
    stream.write_all(b"hello-tproxy").await.expect("write");
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read echo");
    assert_eq!(&buf[..n], b"hello-tproxy");
    instance.shutdown();
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn tproxy_inbound_non_linux_bind_fails() {
    let _g = test_guard().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "tproxy",
                "tag": "tproxy-in",
                "listen": "127.0.0.1",
                "listen_port": 0
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let err = match core_runtime::start(&cfg).await {
        Ok(_) => panic!("tproxy must fail off Linux"),
        Err(err) => format!("{err:#}"),
    };
    assert!(
        err.to_lowercase().contains("linux") || err.to_lowercase().contains("unsupported"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn mixed_plain_http_get_forward() {
    let _g = test_guard().await;
    let origin = spawn_http_origin().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 0
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "mixed-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect mixed");
    let req = format!(
        "GET http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let resp = read_response(&mut stream).await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200, got: {resp:?}"
    );
    assert!(
        resp.contains("hello from origin path=/hello"),
        "body missing, got: {resp:?}"
    );
    instance.shutdown();
}

#[tokio::test]
async fn mixed_plain_http_post_forward() {
    let _g = test_guard().await;
    let origin = spawn_http_origin().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 0
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "mixed-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect mixed");
    let body = "name=value&x=1";
    let req = format!(
        "POST http://127.0.0.1:{}/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        origin.port(),
        body.len(),
        body
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let resp = read_response(&mut stream).await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200, got: {resp:?}"
    );
    assert!(
        resp.contains("hello from origin path=/submit"),
        "body missing, got: {resp:?}"
    );
    instance.shutdown();
}

#[tokio::test]
async fn mixed_plain_http_relative_uri_rejected() {
    let _g = test_guard().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 0
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "mixed-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect mixed");
    stream
        .write_all(b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write request");
    let resp = read_response(&mut stream).await;
    assert!(
        resp.starts_with("HTTP/1.1 400"),
        "expected 400 for origin-form URI, got: {resp:?}"
    );
    instance.shutdown();
}

#[tokio::test]
async fn mixed_http_proxy_auth_when_users_configured() {
    let _g = test_guard().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "users": [{"username": "u", "password": "p"}]
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "mixed-in");

    let mut stream = TcpStream::connect(addr).await.expect("connect mixed");
    stream
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write request");
    let resp = read_response(&mut stream).await;
    assert!(
        resp.starts_with("HTTP/1.1 407"),
        "expected 407 without Proxy-Authorization, got: {resp:?}"
    );
    instance.shutdown();
}

// ---------------------------------------------------------------------------
// UDP paths: direct inbound forward through direct outbound; hijack-dns
// ---------------------------------------------------------------------------

async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if sock.send_to(&buf[..n], from).await.is_err() {
                return;
            }
        }
    });
    addr
}

async fn spawn_udp_dns(answer: std::net::Ipv4Addr) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp dns");
    let addr = sock.local_addr().expect("udp dns addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = hickory_proto::op::Message::from_vec(&buf[..n]) else {
                continue;
            };
            let resp = codec::synth_address(&query, answer.into(), 60).expect("answer");
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
        }
    });
    addr
}

#[tokio::test]
async fn direct_inbound_udp_forwards_to_echo() {
    let _g = test_guard().await;
    let echo = spawn_udp_echo().await;
    let cfg = base_cfg(
        json!([
            {
                "type": "direct",
                "tag": "direct-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "network": "udp",
                "override_address": "127.0.0.1",
                "override_port": echo.port()
            }
        ]),
        json!([{"type": "direct", "tag": "out"}]),
        json!({"final": "out"}),
    );
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "direct-in");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client.send_to(b"udp-hello", addr).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("udp reply timeout")
    .expect("udp reply");
    assert_eq!(&buf[..n], b"udp-hello");
    instance.shutdown();
}

#[tokio::test]
async fn direct_inbound_udp_hijack_dns() {
    let _g = test_guard().await;
    let mock = spawn_udp_dns(std::net::Ipv4Addr::new(9, 9, 9, 9)).await;
    let cfg = json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [{
                "type": "udp", "tag": "u",
                "server": "127.0.0.1", "server_port": mock.port()
            }],
            "final": "u"
        },
        "inbounds": [
            {
                "type": "direct", "tag": "dns-in",
                "listen": "127.0.0.1", "listen_port": 0,
                "network": "udp"
            }
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {
            "rules": [{"action": "hijack-dns", "inbound": ["dns-in"]}],
            "final": "out"
        }
    });
    let instance = start_box(cfg).await;
    let addr = inbound_addr(&instance, "dns-in");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let query = codec::build_query(0x4242, "udp-hijack.test", hickory_proto::rr::RecordType::A)
        .expect("query");
    client.send_to(&query, addr).await.expect("send query");
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("dns reply timeout")
    .expect("dns reply");
    let ips = codec::answer_ips(&buf[..n]).expect("parse answer");
    assert!(
        ips.iter()
            .any(|ip| *ip == std::net::IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9))),
        "expected mock answer, got {ips:?}"
    );
    instance.shutdown();
}
