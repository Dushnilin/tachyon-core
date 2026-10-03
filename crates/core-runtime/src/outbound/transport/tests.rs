//! Websocket transport tests. The early-data path rewrites the upgrade request,
//! so the wire format is what matters here.

use super::*;
use tokio::io::AsyncReadExt;

/// Reads the upgrade request, replies 101 and hands the request head back.
async fn ws_server(listener: tokio::net::TcpListener) -> String {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).await.expect("read head");
        head.push(byte[0]);
    }
    let key = String::from_utf8_lossy(&head)
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: ").map(str::to_string))
        .expect("key");
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(WS_GUID);
    let accept = base64_std(&hash.finalize());
    socket
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("reply");
    String::from_utf8_lossy(&head).into_owned()
}

fn ws_transport(max_early_data: usize) -> Transport {
    Transport {
        kind: Kind::Ws {
            path: "/t".into(),
            host: None,
            headers: vec![("X-Test".into(), "1".into())],
            max_early_data,
        },
    }
}

async fn connect_with(
    listener: tokio::net::TcpListener,
    max_early_data: usize,
    early: &[u8],
) -> (String, usize) {
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move { ws_server(listener).await });
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (stream, consumed) = ws_transport(max_early_data)
        .connect(
            tcp,
            None,
            "example.com",
            port,
            early,
            &crate::outbound::dial::DialOptions::default(),
        )
        .await
        .expect("handshake");
    drop(stream);
    (server.await.expect("join"), consumed)
}

#[tokio::test]
async fn early_data_rides_in_the_upgrade_request() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let payload = b"the first protocol write".to_vec();
    let expected = base64_std(&payload);
    let (head, consumed) = connect_with(listener, 2048, &payload).await;
    assert_eq!(consumed, payload.len(), "the whole write went early");
    assert!(head.starts_with("GET /t HTTP/1.1\r\n"));
    assert!(head.contains("X-Test: 1\r\n"), "other headers survive");
    assert!(
        head.contains(&format!("Sec-WebSocket-Protocol: {expected}\r\n")),
        "the payload is base64'd into the protocol header, got:\n{head}"
    );
}

#[tokio::test]
async fn without_the_budget_nothing_rides_along() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let (head, consumed) = connect_with(listener, 0, b"ignored").await;
    assert_eq!(consumed, 0);
    assert!(
        !head.contains("Sec-WebSocket-Protocol"),
        "a plain upgrade keeps the header out, got:\n{head}"
    );
}

#[tokio::test]
async fn only_the_budget_rides_along() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let payload = b"0123456789abcdef";
    let (head, consumed) = connect_with(listener, 10, payload).await;
    assert_eq!(consumed, 10, "the caller writes the rest itself");
    assert!(head.contains(&format!(
        "Sec-WebSocket-Protocol: {}\r\n",
        base64_std(&payload[..10])
    )));
}

#[tokio::test]
async fn a_configured_protocol_header_is_replaced() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move { ws_server(listener).await });
    let transport = Transport {
        kind: Kind::Ws {
            path: "/".into(),
            host: None,
            headers: vec![("Sec-WebSocket-Protocol".into(), "chat".into())],
            max_early_data: 2048,
        },
    };
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    drop(
        transport
            .connect(
                tcp,
                None,
                "example.com",
                port,
                b"payload",
                &crate::outbound::dial::DialOptions::default(),
            )
            .await
            .expect("handshake"),
    );
    let head = server.await.expect("join");
    assert!(
        !head.contains("Sec-WebSocket-Protocol: chat"),
        "a subprotocol the user configured would collide with the early data"
    );
}
