//! Relay accounting regression: the tracked relay must count bytes, honour
//! `DELETE /connections/{id}` and still propagate half-close like
//! `copy_bidirectional` does.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use core_runtime::clash_state;
use core_runtime::inbound::{Conn, pump_conn_tracked};

fn meta(destination: &str) -> clash_state::ConnMeta {
    clash_state::ConnMeta {
        network: "tcp",
        inbound: "mixed-in".into(),
        source: "192.168.1.10:5000".into(),
        host: "example.com".into(),
        destination: destination.into(),
        chains: vec!["direct".into()],
        rule: "port".into(),
        rule_payload: "443".into(),
        process_path: String::new(),
    }
}

#[tokio::test]
async fn tracked_relay_counts_and_propagates_half_close() {
    let (client, mut caller) = tokio::io::duplex(64 * 1024);
    let (upstream, mut server) = tokio::io::duplex(64 * 1024);

    // echo server: mirror everything, then close on EOF
    let echo = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match server.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if server.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let tracker = clash_state::ConnHandle::open(meta("halfclose.example.com:443"));
    let id = tracker.id();
    let relay = tokio::spawn(async move {
        pump_conn_tracked(client, Conn::Plain(Box::new(upstream)), &[], Some(&tracker)).await
    });

    caller
        .write_all(b"hello tracked relay")
        .await
        .expect("write");
    let mut buf = vec![0u8; 19];
    caller.read_exact(&mut buf).await.expect("echo back");
    assert_eq!(&buf, b"hello tracked relay");

    // half-close must reach the echo server so it finishes and the relay ends
    caller.shutdown().await.expect("shutdown");
    let mut tail = Vec::new();
    caller.read_to_end(&mut tail).await.expect("drain");
    assert!(tail.is_empty(), "expected a clean EOF");
    tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay finished")
        .expect("relay task")
        .expect("relay result");
    echo.await.expect("echo task");

    // the registry entry is gone once the relay returned
    let (views, up, down) = clash_state::snapshot();
    assert!(
        !views.iter().any(|view| view.id == id.to_string()),
        "entry removed after the relay ended"
    );
    assert!(up >= 19 && down >= 19, "bytes counted: up={up} down={down}");
}

#[tokio::test]
async fn tracked_relay_stops_on_api_close() {
    let (client, mut caller) = tokio::io::duplex(4096);
    let (upstream, _server) = tokio::io::duplex(4096);
    let tracker = clash_state::ConnHandle::open(meta("dropped.example.com:443"));
    let id = tracker.id();

    let relay = tokio::spawn(async move {
        pump_conn_tracked(client, Conn::Plain(Box::new(upstream)), &[], Some(&tracker)).await
    });
    // give the relay a moment to park on the read
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(clash_state::close(id), "entry was registered");
    let result = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay returned after the API close")
        .expect("relay task");
    assert_eq!(
        result.unwrap_err().to_string(),
        "connection closed by clash api"
    );
    // the peer sees EOF rather than a reset mid-stream
    let mut buf = Vec::new();
    assert_eq!(caller.read_to_end(&mut buf).await.expect("drain"), 0);
}

#[tokio::test]
async fn untracked_relay_matches_copy_bidirectional() {
    let (client, mut caller) = tokio::io::duplex(64 * 1024);
    let (upstream, mut server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok(n) = server.read(&mut buf).await {
            if n == 0 || server.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let relay = tokio::spawn(async move {
        pump_conn_tracked(client, Conn::Plain(Box::new(upstream)), &[], None).await
    });
    caller.write_all(b"plain").await.expect("write");
    let mut buf = [0u8; 5];
    caller.read_exact(&mut buf).await.expect("echo");
    assert_eq!(&buf, b"plain");
    caller.shutdown().await.expect("shutdown");
    let mut tail = Vec::new();
    caller.read_to_end(&mut tail).await.expect("drain");
    assert!(tail.is_empty());
    relay.await.expect("relay task").expect("relay result");
}
