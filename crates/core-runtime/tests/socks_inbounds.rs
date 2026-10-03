//! SOCKS4/4a on `mixed`, and the standalone `socks` / `http` inbounds.

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
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

async fn start(kind: &str, users: Value) -> core_runtime::BoxInstance {
    let mut inbound = json!({
        "type": kind, "tag": "in", "listen": "127.0.0.1", "listen_port": 0
    });
    if !users.is_null() {
        inbound["users"] = users;
    }
    let cfg = json!({
        "log": {"level": "error"},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    });
    core_runtime::start(&cfg).await.expect("start box")
}

fn addr_of(i: &core_runtime::BoxInstance) -> SocketAddr {
    i.inbound_addrs()
        .iter()
        .find(|(t, _)| t == "in")
        .map(|(_, a)| *a)
        .expect("inbound addr")
}

async fn connect(addr: SocketAddr) -> TcpStream {
    let s = timeout(T, TcpStream::connect(addr))
        .await
        .expect("connect timeout")
        .expect("connect");
    assert_eq!(s.peer_addr().expect("peer_addr"), addr);
    s
}

fn socks4_req(port: u16, ip: [u8; 4], user: &str, host: Option<&str>) -> Vec<u8> {
    let mut r = vec![4, 1];
    r.extend_from_slice(&port.to_be_bytes());
    r.extend_from_slice(&ip);
    r.extend_from_slice(user.as_bytes());
    r.push(0);
    if let Some(h) = host {
        r.extend_from_slice(h.as_bytes());
        r.push(0);
    }
    r
}

async fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    timeout(T, s.read_exact(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    buf
}

async fn echo_roundtrip(s: &mut TcpStream) {
    s.write_all(b"ping-socks4").await.expect("write");
    assert_eq!(read_n(s, 11).await, b"ping-socks4");
}

async fn expect_closed(s: &mut TcpStream) {
    let mut b = [0u8; 16];
    match timeout(T, s.read(&mut b)).await.expect("close timeout") {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("expected close, got {n} bytes: {:?}", &b[..n]),
    }
}

#[tokio::test]
async fn mixed_socks4_connect() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let i = start("mixed", Value::Null).await;
    let mut s = connect(addr_of(&i)).await;
    s.write_all(&socks4_req(echo.port(), [127, 0, 0, 1], "", None))
        .await
        .expect("write");
    let rep = read_n(&mut s, 8).await;
    assert_eq!(rep[0], 0);
    assert_eq!(rep[1], 90, "reply: {rep:?}");
    echo_roundtrip(&mut s).await;
    i.shutdown();
}

#[tokio::test]
async fn mixed_socks4a_domain() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let i = start("mixed", Value::Null).await;
    let mut s = connect(addr_of(&i)).await;
    s.write_all(&socks4_req(
        echo.port(),
        [0, 0, 0, 1],
        "",
        Some("localhost"),
    ))
    .await
    .expect("write");
    let rep = read_n(&mut s, 8).await;
    assert_eq!(rep[1], 90, "reply: {rep:?}");
    echo_roundtrip(&mut s).await;
    i.shutdown();
}

#[tokio::test]
async fn mixed_socks4_user_check() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let i = start("mixed", json!([{"username": "alice", "password": ""}])).await;

    let mut ok = connect(addr_of(&i)).await;
    ok.write_all(&socks4_req(echo.port(), [127, 0, 0, 1], "alice", None))
        .await
        .expect("write");
    assert_eq!(read_n(&mut ok, 8).await[1], 90);
    echo_roundtrip(&mut ok).await;

    let mut bad = connect(addr_of(&i)).await;
    bad.write_all(&socks4_req(echo.port(), [127, 0, 0, 1], "mallory", None))
        .await
        .expect("write");
    assert_eq!(read_n(&mut bad, 8).await[1], 91);
    i.shutdown();
}

#[tokio::test]
async fn socks_inbound_takes_socks4_and_5_refuses_http() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let i = start("socks", Value::Null).await;
    let addr = addr_of(&i);

    let mut v4 = connect(addr).await;
    v4.write_all(&socks4_req(echo.port(), [127, 0, 0, 1], "", None))
        .await
        .expect("write");
    assert_eq!(read_n(&mut v4, 8).await[1], 90);
    echo_roundtrip(&mut v4).await;

    let mut v5 = connect(addr).await;
    v5.write_all(&[5, 1, 0]).await.expect("write");
    assert_eq!(read_n(&mut v5, 2).await, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    v5.write_all(&req).await.expect("write");
    assert_eq!(read_n(&mut v5, 10).await[1], 0);
    echo_roundtrip(&mut v5).await;

    let mut http = connect(addr).await;
    http.write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    expect_closed(&mut http).await;
    i.shutdown();
}

#[tokio::test]
async fn http_inbound_connect_refuses_socks() {
    let _g = test_guard().await;
    let echo = spawn_echo().await;
    let i = start("http", Value::Null).await;
    let addr = addr_of(&i);

    let mut h = connect(addr).await;
    let req = format!(
        "CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n",
        p = echo.port()
    );
    h.write_all(req.as_bytes()).await.expect("write");
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.extend(read_n(&mut h, 1).await);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{:?}",
        String::from_utf8_lossy(&head)
    );
    echo_roundtrip(&mut h).await;

    let mut s5 = connect(addr).await;
    s5.write_all(&[5, 1, 0]).await.expect("write");
    expect_closed(&mut s5).await;

    let mut s4 = connect(addr).await;
    s4.write_all(&socks4_req(echo.port(), [127, 0, 0, 1], "", None))
        .await
        .expect("write");
    expect_closed(&mut s4).await;
    i.shutdown();
}
