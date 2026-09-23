//! Outbound interop: our mixed inbound doubles as the upstream proxy so
//! client -> box A (socks/http outbound) -> box B (mixed) -> echo is a full
//! self-interop loop over each outbound protocol.

use std::net::SocketAddr;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn spawn_box(config: Value) -> SocketAddr {
    let instance = core_runtime::start(&config).await.expect("start box");
    let addr = instance.inbound_addrs()[0].1;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        instance.shutdown();
    });
    addr
}

async fn socks_exchange(inbound: SocketAddr, echo: SocketAddr) -> (TcpStream, [u8; 4]) {
    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    let std::net::IpAddr::V4(v4) = echo.ip() else {
        panic!("expected v4 echo addr");
    };
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd");
    (stream, reply)
}

async fn assert_tunnel(mut stream: TcpStream) {
    stream.write_all(b"relay").await.expect("write");
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"relay");
}

fn upbox(upstream: SocketAddr, outbound_type: &str) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": outbound_type, "tag": "up", "server": "127.0.0.1", "server_port": upstream.port()}
        ],
        "route": {"final": "up"}
    })
}

#[tokio::test]
async fn socks_outbound_via_second_box() {
    let echo = spawn_echo().await;
    let downstream = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    }))
    .await;
    let inbound = spawn_box(upbox(downstream, "socks")).await;

    let (stream, reply) = socks_exchange(inbound, echo).await;
    assert_eq!(reply[1], 0x00, "socks chain must succeed");
    assert_tunnel(stream).await;
}

#[tokio::test]
async fn http_outbound_via_second_box() {
    let echo = spawn_echo().await;
    let downstream = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    }))
    .await;
    let inbound = spawn_box(upbox(downstream, "http")).await;

    let (stream, reply) = socks_exchange(inbound, echo).await;
    assert_eq!(reply[1], 0x00, "http chain must succeed");
    assert_tunnel(stream).await;
}

#[tokio::test]
async fn selector_defaults_to_first_member() {
    let echo = spawn_echo().await;
    let downstream = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    }))
    .await;
    let inbound = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "socks", "tag": "via-b", "server": "127.0.0.1", "server_port": downstream.port()},
            {"type": "selector", "tag": "sel", "outbounds": ["via-b", "direct"]}
        ],
        "route": {"final": "sel"}
    }))
    .await;

    let (stream, reply) = socks_exchange(inbound, echo).await;
    assert_eq!(reply[1], 0x00);
    assert_tunnel(stream).await;
}

#[tokio::test]
async fn selector_default_field_selects_direct() {
    let echo = spawn_echo().await;
    let inbound = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "socks", "tag": "via-b", "server": "127.0.0.1", "server_port": 1},
            {"type": "selector", "tag": "sel", "outbounds": ["via-b", "direct"], "default": "direct"}
        ],
        "route": {"final": "sel"}
    }))
    .await;

    let (stream, reply) = socks_exchange(inbound, echo).await;
    assert_eq!(reply[1], 0x00, "default direct member must dial");
    assert_tunnel(stream).await;
}

#[tokio::test]
async fn socks_outbound_auth_handshake() {
    let echo = spawn_echo().await;
    let downstream = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0,
             "users": [{"username": "alice", "password": "s3cret"}]}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    }))
    .await;
    let inbound = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": "socks", "tag": "up", "server": "127.0.0.1",
             "server_port": downstream.port(), "username": "alice", "password": "s3cret"}
        ],
        "route": {"final": "up"}
    }))
    .await;

    let (stream, reply) = socks_exchange(inbound, echo).await;
    assert_eq!(reply[1], 0x00, "authed socks chain must succeed");
    assert_tunnel(stream).await;
}

async fn spawn_http204() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 204");
    let addr = listener.local_addr().expect("204 addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

async fn try_relay(inbound: SocketAddr, echo: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(inbound).await else {
        return false;
    };
    if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }
    let mut auth = [0u8; 2];
    if stream.read_exact(&mut auth).await.is_err() || auth != [0x05, 0x00] {
        return false;
    }
    let std::net::IpAddr::V4(v4) = echo.ip() else {
        return false;
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    if stream.write_all(&request).await.is_err() {
        return false;
    }
    let mut reply = [0u8; 4];
    if stream.read_exact(&mut reply).await.is_err() || reply[1] != 0x00 {
        return false;
    }
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.is_ok()
}

#[tokio::test]
async fn urltest_selects_working_member() {
    use std::time::Duration;

    let echo = spawn_echo().await;
    let probe_target = spawn_http204().await;
    let downstream = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    }))
    .await;
    let inbound = spawn_box(json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "socks", "tag": "dead", "server": "127.0.0.1", "server_port": 1},
            {"type": "socks", "tag": "live", "server": "127.0.0.1", "server_port": downstream.port()},
            {"type": "urltest", "tag": "auto", "outbounds": ["dead", "live"],
             "url": format!("http://127.0.0.1:{}/generate_204", probe_target.port()),
             "interval": "1h", "tolerance": 50}
        ],
        "route": {"final": "auto"}
    }))
    .await;

    // The first member is a dead proxy; the roundtrip only works once the
    // background probe settles the selection on the live member.
    let mut ok = false;
    for _ in 0..50 {
        if try_relay(inbound, echo).await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "urltest never selected the live member");
}
