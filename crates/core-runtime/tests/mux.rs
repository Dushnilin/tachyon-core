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
async fn handle_stream(
    request: http::Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<Bytes>,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
) {
    let response = http::Response::builder()
        .status(200)
        .body(())
        .expect("response");
    let mut reply = reply.send_response(response, false).expect("send response");
    let _ = reply.send_data(Bytes::from_static(&[0]), true);
    let mut body = request.into_body();
    let mut payload = Vec::new();
    match tokio::time::timeout(std::time::Duration::from_secs(5), body.data()).await {
        Ok(Some(Ok(chunk))) => payload.extend_from_slice(&chunk),
        _ => return,
    }
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
    while let Some(Ok((request, reply))) = connection.accept().await {
        let seen = Arc::clone(&seen);
        tokio::spawn(handle_stream(request, reply, seen));
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

#[tokio::test]
async fn multiple_streams_reuse_the_same_session_up_to_min_streams() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let connections_accepted = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn({
        let seen = Arc::clone(&seen);
        let conns = Arc::clone(&connections_accepted);
        async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                conns.fetch_add(1, Ordering::SeqCst);
                let seen = Arc::clone(&seen);
                tokio::spawn(serve(socket, seen));
            }
        }
    });

    let options = mux::MuxOptions::parse(
        &serde_json::json!({"enabled": true, "min_streams": 4, "max_connections": 2}),
        "multiplex",
    )
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

    // Open 3 streams concurrently while min_streams is 4: they must all share 1 underlying connection
    let mut s1 = client
        .open(&Target::Domain("stream1.com".into(), 443))
        .await
        .expect("s1");
    let mut s2 = client
        .open(&Target::Domain("stream2.com".into(), 443))
        .await
        .expect("s2");
    let mut s3 = client
        .open(&Target::Domain("stream3.com".into(), 443))
        .await
        .expect("s3");

    s1.write_all(b"p1").await.expect("w1");
    s2.write_all(b"p2").await.expect("w2");
    s3.write_all(b"p3").await.expect("w3");

    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), s1.read(&mut buf)).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), s2.read(&mut buf)).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), s3.read(&mut buf)).await;

    assert_eq!(
        connections_accepted.load(Ordering::SeqCst),
        1,
        "all 3 concurrent streams reused the single physical connection"
    );
    let records = seen.lock().expect("seen");
    assert_eq!(records.len(), 3, "server received all 3 streams");
    server.abort();
}

#[tokio::test]
async fn default_multiplex_reuses_single_connection_up_to_default_min_streams() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let connections_accepted = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn({
        let seen = Arc::clone(&seen);
        let conns = Arc::clone(&connections_accepted);
        async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                conns.fetch_add(1, Ordering::SeqCst);
                let seen = Arc::clone(&seen);
                tokio::spawn(serve(socket, seen));
            }
        }
    });

    let options = mux::MuxOptions::parse(
        &serde_json::json!({"enabled": true, "protocol": "h2mux", "max_connections": 1}),
        "multiplex",
    )
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

    // Open 4 streams concurrently with default options (min_streams = 8): must reuse 1 connection
    let mut streams = Vec::new();
    for i in 0..4 {
        let s = client
            .open(&Target::Domain(format!("s{i}.com"), 443))
            .await
            .expect("stream");
        streams.push(s);
    }

    for (i, s) in streams.iter_mut().enumerate() {
        s.write_all(format!("ping{i}").as_bytes())
            .await
            .expect("write");
    }
    for s in streams.iter_mut() {
        let mut buf = [0u8; 8];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), s.read(&mut buf)).await;
    }

    assert_eq!(
        connections_accepted.load(Ordering::SeqCst),
        1,
        "default options reused 1 physical connection across 4 streams"
    );
    let records = seen.lock().expect("seen");
    assert_eq!(records.len(), 4, "server received all 4 streams");
    server.abort();
}
