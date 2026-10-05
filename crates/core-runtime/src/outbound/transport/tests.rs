//! Websocket transport tests. The early-data path rewrites the upgrade request,
//! so the wire format is what matters here.

use super::*;
use std::future::poll_fn;
use std::task::{Context, Poll};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
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

/// A socket that hands out at most `piece` bytes per read, so a websocket frame
/// is guaranteed to land across many reads. `widest` records the largest buffer
/// a read was ever asked for: that is how the direct path is told apart from
/// the staging one, which can only ever ask for `WS_READ`.
struct Trickle {
    data: Vec<u8>,
    at: usize,
    piece: usize,
    widest: Arc<AtomicUsize>,
}

impl AsyncRead for Trickle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        me.widest.fetch_max(out.remaining(), Ordering::Relaxed);
        let n = (me.data.len() - me.at).min(me.piece).min(out.remaining());
        out.put_slice(&me.data[me.at..me.at + n]);
        me.at += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Trickle {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Once a frame is known and nothing is left to unmask, `poll_read` hands the
/// caller's own buffer to the socket instead of staging the payload and copying
/// it out. `poll_more` reserves exactly `WS_READ` and reads into whatever is
/// spare, so a read through it can never ask for more than that -- which makes
/// "asked for more than WS_READ" proof that the direct path ran. Without this
/// the widest request stays at WS_READ and the payload pays a memmove per read.
#[tokio::test]
async fn an_unmasked_payload_is_read_straight_into_the_callers_buffer() {
    const LEN: usize = 200_000;
    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let mut wire = vec![0x82, 127];
    wire.extend_from_slice(&(LEN as u64).to_be_bytes());
    wire.extend_from_slice(&payload);
    let widest = Arc::new(AtomicUsize::new(0));
    let stream: crate::inbound::AnyStream = Box::new(Trickle {
        data: wire,
        at: 0,
        piece: 64 * 1024,
        widest: widest.clone(),
    });
    let mut ws = WsStream::new(stream);
    let mut out = vec![0u8; 1 << 20];
    let mut got = 0;
    while got < out.len() {
        // one big caller buffer: that is what makes a wide socket read possible
        let mut buf = ReadBuf::new(&mut out[got..]);
        poll_fn(|cx| Pin::new(&mut ws).poll_read(cx, &mut buf))
            .await
            .expect("read frame");
        let filled = buf.filled().len();
        if filled == 0 {
            break;
        }
        got += filled;
    }
    assert_eq!(got, LEN, "a split frame must come back whole");
    assert!(out[..got] == payload, "and in order");
    assert!(
        widest.load(Ordering::Relaxed) > WS_READ,
        "no read ever asked for more than {WS_READ} bytes, so the payload was staged"
    );
}

/// A masked frame still has to be unmasked, so it cannot take the direct path:
/// the payload has to be staged, which is the one case where the read buffer
/// outgrows its allocation. Sized past `WS_READ` so that growth is what is
/// being tested, not a payload that happens to fit.
#[tokio::test]
async fn a_masked_frame_bigger_than_the_buffer_still_reads_out_whole() {
    const LEN: usize = WS_READ + 1000;
    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let key = [0xde, 0xad, 0xbe, 0xef];
    let mut wire = vec![0x82, 127 | 0x80];
    wire.extend_from_slice(&(LEN as u64).to_be_bytes());
    wire.extend_from_slice(&key);
    wire.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect::<Vec<u8>>(),
    );
    let stream: crate::inbound::AnyStream = Box::new(Trickle {
        data: wire,
        at: 0,
        piece: 4096,
        widest: Arc::new(AtomicUsize::new(0)),
    });
    let mut ws = WsStream::new(stream);
    let mut got = Vec::new();
    ws.read_to_end(&mut got).await.expect("read frame");
    assert_eq!(got.len(), LEN, "the masking key must still be applied");
    assert!(got == payload, "and the payload must come back in order");
}
