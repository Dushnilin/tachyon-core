//! Mux.Cool: a multiplexed client against a real h2 server, so the session
//! handshake, the per-stream request and the stream response are all exercised
//! over the wire.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use core_runtime::inbound::{AnyStream, Target};
use core_runtime::outbound::mux;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the server saw on a stream after the request head.
#[derive(Debug, Default)]
struct Seen {
    flags: u16,
    destination: String,
    payload: Vec<u8>,
}

/// One h2 session: a CONNECT to the magic address, then one CONNECT per
/// multiplexed stream.
async fn serve(mut socket: tokio::net::TcpStream, seen: Arc<std::sync::Mutex<Vec<Seen>>>) {
    // the session handshake rides in front of the h2 preface
    let mut handshake = [0u8; 2];
    if socket.read_exact(&mut handshake).await.is_err() {
        return;
    }
    let mut connection = match h2::server::handshake(socket).await {
        Ok(connection) => connection,
        Err(_) => return,
    };
    // h2mux has no session request: the first CONNECT is already a stream
    let Some(Ok((_request, mut reply))) = connection.accept().await else {
        return;
    };
    // the connection has to keep being polled for stream data to arrive
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
    });
    // answer 200 with the one-byte stream status, then read the payload
    let response = http::Response::builder()
        .status(200)
        .body(())
        .expect("response");
    let mut reply = reply.send_response(response, false).expect("send response");
    let _ = reply.send_data(Bytes::from_static(&[0]), true);
    // the tunnel never half-closes here, so the first chunk is the whole story
    let mut body = _request.into_body();
    let mut payload = Vec::new();
    match tokio::time::timeout(std::time::Duration::from_secs(5), body.data()).await {
        Ok(Some(Ok(chunk))) => payload.extend_from_slice(&chunk),
        _ => return,
    }
    // [flags:u16][addr type][len][addr][port:u16][payload] — the version
    // byte belongs to the session handshake, not to a stream request
    if payload.len() > 8 {
        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        let name_len = usize::from(payload[3]);
        let end = 4 + name_len;
        if payload.len() < end + 2 {
            return;
        }
        let destination = String::from_utf8_lossy(&payload[4..end]).into_owned();
        seen.lock().expect("seen").push(Seen {
            flags,
            destination,
            payload: payload[end + 2..].to_vec(),
        });
    }
}

#[tokio::test]
async fn a_multiplexed_stream_carries_its_request_and_the_reply() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sessions = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn({
        let seen = Arc::clone(&seen);
        let sessions = Arc::clone(&sessions);
        async move {
            while sessions.fetch_add(1, Ordering::SeqCst) < 8 {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let seen = Arc::clone(&seen);
                tokio::spawn(serve(socket, seen));
            }
        }
    });

    let options = mux::MuxOptions::parse(&serde_json::json!({"enabled": true}), "multiplex")
        .expect("options");
    let client = mux::Client::new(options).expect("client");
    client
        .set_dialer(Arc::new(move || {
            Box::pin(async move {
                let socket = tokio::net::TcpStream::connect(("127.0.0.1", port as u16))
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                Ok(Box::new(socket) as AnyStream)
            })
        }))
        .await;

    let mut stream = client
        .open(&Target::Domain("example.com".into(), 443))
        .await
        .expect("open a stream");
    stream.write_all(b"ping").await.expect("write");
    // the one-byte stream response is consumed transparently, so the next read
    // only returns once the server sends something
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await;

    let seen = seen.lock().expect("seen");
    assert_eq!(seen.len(), 1, "the server saw one stream request");
    let record = &seen[0];
    assert_eq!(record.flags, 0, "a tcp stream carries no flags");
    assert_eq!(record.destination, "example.com");
    assert_eq!(record.payload, b"ping", "the request rode with the payload");
    server.abort();
}
