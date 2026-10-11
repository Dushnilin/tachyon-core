//! The `splice(2)` relay: bare TCP on both ends must take the kernel path and
//! still behave exactly like the userspace loop — every byte intact in both
//! directions, the sniffed prefix first, half-close propagated, `DELETE
//! /connections/{id}` honoured, counters right.
//!
//! Linux only: `splice` does not exist elsewhere, and everywhere else the
//! userspace loop is what runs (covered by `relay_tracking.rs`).
#![cfg(target_os = "linux")]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use core_runtime::clash_state;
use core_runtime::inbound::{Conn, pump_conn_tracked};

const LIMIT: Duration = Duration::from_secs(30);

fn meta(destination: &str) -> clash_state::ConnMeta {
    clash_state::ConnMeta {
        network: "tcp",
        inbound: "redirect-in".into(),
        source: "192.168.1.10:5000".into(),
        host: "example.com".into(),
        destination: destination.into(),
        chains: vec!["direct".into()],
        rule: "port".into(),
        rule_payload: "443".into(),
        process_path: String::new(),
    }
}

/// A connected loopback pair: `(accepted, connected)`.
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (connected, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let connected = connected.expect("connect");
    let (accepted, _) = accepted.expect("accept");
    assert_eq!(connected.peer_addr().expect("peer"), addr);
    assert_eq!(
        accepted.peer_addr().expect("peer"),
        connected.local_addr().expect("local")
    );
    (accepted, connected)
}

/// Deterministic, non-repeating bytes so a lost, reordered or duplicated chunk
/// cannot hide behind a constant fill.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 11) as u8
        })
        .collect()
}

#[tokio::test]
async fn splice_moves_every_byte_both_ways_and_counts_them() {
    // relay side: `relay_client` faces the caller, `relay_upstream` the server
    let (relay_client, caller) = pair().await;
    let (relay_upstream, server) = pair().await;
    let tracker = clash_state::ConnHandle::open(meta("splice-bytes.example.com:443"));
    let id = tracker.id();

    const UP: usize = 12 * 1024 * 1024 + 7;
    const DOWN: usize = 12 * 1024 * 1024 + 13;
    let prefix = b"sniffed-prefix".to_vec();
    let up = pattern(UP, 1);
    let down = pattern(DOWN, 2);

    let relay = tokio::spawn({
        let prefix = prefix.clone();
        async move {
            pump_conn_tracked(
                relay_client,
                Conn::Plain(Box::new(relay_upstream)),
                &prefix,
                Some(&tracker),
            )
            .await
        }
    });

    // far end: reads the whole upload while writing the whole download, then
    // half-closes; the caller does the mirror image
    let (mut server_r, mut server_w) = server.into_split();
    let server_task = tokio::spawn({
        let down = down.clone();
        async move {
            let write = async move {
                server_w.write_all(&down).await.expect("server write");
                server_w.shutdown().await.expect("server shutdown");
            };
            let read = async move {
                let mut got = Vec::new();
                server_r.read_to_end(&mut got).await.expect("server read");
                got
            };
            let ((), got) = tokio::join!(write, read);
            got
        }
    });

    let (mut caller_r, mut caller_w) = caller.into_split();
    let write = {
        let up = up.clone();
        async move {
            caller_w.write_all(&up).await.expect("caller write");
            caller_w.shutdown().await.expect("caller shutdown");
        }
    };
    let read = async move {
        let mut got = Vec::new();
        caller_r.read_to_end(&mut got).await.expect("caller read");
        got
    };
    let ((), got_down) = tokio::time::timeout(LIMIT, async { tokio::join!(write, read) })
        .await
        .expect("caller side timed out");
    let got_up = tokio::time::timeout(LIMIT, server_task)
        .await
        .expect("server side timed out")
        .expect("server task");

    // the prefix goes upstream first, then the caller's bytes, untouched
    assert_eq!(got_up.len(), prefix.len() + UP);
    assert_eq!(&got_up[..prefix.len()], &prefix[..]);
    assert!(got_up[prefix.len()..] == up[..], "upload corrupted");
    assert!(got_down == down, "download corrupted");

    tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay finished")
        .expect("relay task")
        .expect("relay result");

    let (views, total_up, total_down) = clash_state::snapshot();
    assert!(
        !views.iter().any(|view| view.id == id.to_string()),
        "entry removed after the relay ended"
    );
    assert!(
        total_up >= (prefix.len() + UP) as u64 && total_down >= DOWN as u64,
        "bytes counted: up={total_up} down={total_down}"
    );
}

/// Without a registry to feed there still must be a relay: a build (or a run)
/// with the connection view off must not fall back to the userspace loop.
#[tokio::test]
async fn splice_runs_without_a_tracker_and_moves_every_byte() {
    let (relay_client, caller) = pair().await;
    let (relay_upstream, server) = pair().await;

    const UP: usize = 4 * 1024 * 1024 + 5;
    const DOWN: usize = 4 * 1024 * 1024 + 9;
    let up = pattern(UP, 7);
    let down = pattern(DOWN, 8);

    let relay = tokio::spawn(async move {
        pump_conn_tracked(
            relay_client,
            Conn::Plain(Box::new(relay_upstream)),
            &[],
            None,
        )
        .await
    });

    let (mut server_r, mut server_w) = server.into_split();
    let server_task = tokio::spawn({
        let down = down.clone();
        async move {
            let write = async move {
                server_w.write_all(&down).await.expect("server write");
                server_w.shutdown().await.expect("server shutdown");
            };
            let read = async move {
                let mut got = Vec::new();
                server_r.read_to_end(&mut got).await.expect("server read");
                got
            };
            let ((), got) = tokio::join!(write, read);
            got
        }
    });

    let (mut caller_r, mut caller_w) = caller.into_split();
    let write = {
        let up = up.clone();
        async move {
            caller_w.write_all(&up).await.expect("caller write");
            caller_w.shutdown().await.expect("caller shutdown");
        }
    };
    let read = async move {
        let mut got = Vec::new();
        caller_r.read_to_end(&mut got).await.expect("caller read");
        got
    };
    let ((), got_down) = tokio::time::timeout(LIMIT, async { tokio::join!(write, read) })
        .await
        .expect("caller side timed out");
    let got_up = tokio::time::timeout(LIMIT, server_task)
        .await
        .expect("server side timed out")
        .expect("server task");

    assert_eq!(got_up, up, "upload corrupted");
    assert_eq!(got_down, down, "download corrupted");

    tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay finished")
        .expect("relay task")
        .expect("relay result");
}

#[tokio::test]
async fn splice_propagates_half_close_without_losing_the_tail() {
    let (relay_client, mut caller) = pair().await;
    let (relay_upstream, mut server) = pair().await;
    let tracker = clash_state::ConnHandle::open(meta("splice-halfclose.example.com:443"));

    let relay = tokio::spawn(async move {
        pump_conn_tracked(
            relay_client,
            Conn::Plain(Box::new(relay_upstream)),
            &[],
            Some(&tracker),
        )
        .await
    });

    // caller sends and half-closes at once; the server answers only after it has
    // seen EOF, so the answer proves the half-close crossed the relay while the
    // reverse direction was still open
    caller.write_all(b"request").await.expect("write");
    caller.shutdown().await.expect("shutdown");

    let mut seen = Vec::new();
    tokio::time::timeout(LIMIT, server.read_to_end(&mut seen))
        .await
        .expect("server saw EOF")
        .expect("server read");
    assert_eq!(seen, b"request");
    server.write_all(b"late reply").await.expect("reply");
    server.shutdown().await.expect("server shutdown");

    let mut reply = Vec::new();
    tokio::time::timeout(LIMIT, caller.read_to_end(&mut reply))
        .await
        .expect("caller saw EOF")
        .expect("caller read");
    assert_eq!(reply, b"late reply");
    tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay finished")
        .expect("relay task")
        .expect("relay result");
}

#[tokio::test]
async fn splice_stops_on_api_close_and_the_peer_sees_eof() {
    let (relay_client, mut caller) = pair().await;
    let (relay_upstream, _server) = pair().await;
    let tracker = clash_state::ConnHandle::open(meta("splice-dropped.example.com:443"));
    let id = tracker.id();

    let relay = tokio::spawn(async move {
        pump_conn_tracked(
            relay_client,
            Conn::Plain(Box::new(relay_upstream)),
            &[],
            Some(&tracker),
        )
        .await
    });
    // an idle connection parks on the first byte; the API close must still reach it
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(clash_state::close(id), "entry was registered");
    let result = tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay returned after the API close")
        .expect("relay task");
    assert_eq!(
        result.unwrap_err().to_string(),
        "connection closed by clash api"
    );
    let mut buf = Vec::new();
    let n = tokio::time::timeout(LIMIT, caller.read_to_end(&mut buf))
        .await
        .expect("caller saw the close")
        .unwrap_or(0);
    assert_eq!(n, 0);
}

#[tokio::test]
async fn splice_survives_a_peer_that_vanishes_mid_transfer() {
    let (relay_client, mut caller) = pair().await;
    let (relay_upstream, server) = pair().await;
    let tracker = clash_state::ConnHandle::open(meta("splice-vanish.example.com:443"));

    let relay = tokio::spawn(async move {
        pump_conn_tracked(
            relay_client,
            Conn::Plain(Box::new(relay_upstream)),
            &[],
            Some(&tracker),
        )
        .await
    });

    // a server that disappears while the caller is still sending must end the
    // relay (an error is fine, a hang is not)
    drop(server);
    let junk = pattern(256 * 1024, 3);
    let _ = tokio::time::timeout(Duration::from_secs(5), caller.write_all(&junk)).await;
    let _ = tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay must not hang after the peer is gone");
}
