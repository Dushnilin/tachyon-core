//! Loopback contract for the data plane skeleton:
//! mixed inbound (SOCKS5 / HTTP CONNECT) -> router -> direct/block outbound.

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

fn box_value(listen_port: u16, outbounds: Value) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": listen_port}
        ],
        "outbounds": outbounds,
        "route": {"final": "out"}
    })
}

async fn start_box(outbounds: Value) -> (core_runtime::BoxInstance, SocketAddr) {
    let instance = core_runtime::start(&box_value(0, outbounds))
        .await
        .expect("start box");
    let addr = instance
        .inbound_addrs()
        .iter()
        .find(|(tag, _)| tag == "mixed-in")
        .map(|(_, addr)| *addr)
        .expect("mixed inbound addr");
    (instance, addr)
}

#[tokio::test]
async fn socks5_connect_via_direct() {
    let echo = spawn_echo().await;
    let (instance, inbound) = start_box(json!([{"type": "direct", "tag": "out"}])).await;

    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.expect("auth reply");
    assert_eq!(reply, [0x05, 0x00]);

    let ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("expected v4 echo addr in test"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0x00, "socks connect must succeed");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd");

    stream.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"ping");

    instance.shutdown();
}

#[tokio::test]
async fn http_connect_via_direct() {
    let echo = spawn_echo().await;
    let (instance, inbound) = start_box(json!([{"type": "direct", "tag": "out"}])).await;

    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        echo.port()
    );
    stream.write_all(request.as_bytes()).await.expect("request");
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.expect("response");
        response.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");

    stream.write_all(b"pong").await.expect("write");
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"pong");

    instance.shutdown();
}

#[tokio::test]
async fn socks5_auth_userpass() {
    let echo = spawn_echo().await;
    let instance = core_runtime::start(&json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0,
             "users": [{"username": "u", "password": "p"}]}
        ],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {"final": "out"}
    }))
    .await
    .expect("start box");
    let inbound = instance.inbound_addrs()[0].1;

    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x02, 0x00, 0x02])
        .await
        .expect("greeting");
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.expect("auth reply");
    assert_eq!(reply, [0x05, 0x02]);

    stream
        .write_all(&[0x01, 0x01, b'u', 0x01, b'p'])
        .await
        .expect("auth");
    let mut verdict = [0u8; 2];
    stream.read_exact(&mut verdict).await.expect("auth verdict");
    assert_eq!(verdict[1], 0x00);

    let ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("expected v4 echo addr in test"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0x00);

    instance.shutdown();
}

#[tokio::test]
async fn block_outbound_refuses() {
    let (instance, inbound) = start_box(json!([{"type": "block", "tag": "out"}])).await;

    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.expect("auth reply");
    assert_eq!(reply, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&9u16.to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0x01, "block must fail the CONNECT");

    instance.shutdown();
}
