//! Live FPTN interop against an FPTN.ONLINE server (manual only — never CI).
//!
//! Reads a real subscription token from `FPTN_TOKEN`, dials the first
//! member server, brings up the smoltcp stack and performs an HTTP
//! round-trip through the tunnel:
//!
//! ```bash
//! FPTN_TOKEN='fptnb:…' cargo test -p core-runtime --test fptn_live -- --ignored --nocapture
//! ```

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use core_runtime::inbound::Target;
use core_runtime::outbound::fptn::Fptn;

fn member_outbound(token: &str) -> Value {
    let root = json!({ "outbounds": [{ "type": "fptn", "tag": "vpn", "token": token }] });
    let expanded = core_config::fptn::expand(&root)
        .expect("expand")
        .expect("token outbound present");
    expanded["outbounds"]
        .as_array()
        .expect("outbounds array")
        .iter()
        .find(|o| o["type"] == "fptn")
        .cloned()
        .expect("member outbound")
}

#[tokio::test]
#[ignore = "requires FPTN_TOKEN and network access"]
async fn live_fptn_http_roundtrip() {
    let Ok(token) = std::env::var("FPTN_TOKEN") else {
        eprintln!("FPTN_TOKEN not set; skipping live fptn test");
        return;
    };
    let member = member_outbound(&token);
    let obj = member.as_object().expect("member is an object");
    let fptn = Fptn::build(obj, "fptn-live").expect("build outbound");

    let target = Target::Ip("1.1.1.1:80".parse().expect("target"));
    let mut conn = tokio::time::timeout(Duration::from_secs(30), fptn.connect(&target))
        .await
        .expect("connect timed out")
        .expect("connect through fptn");
    eprintln!("== connected");

    tokio::time::timeout(
        Duration::from_secs(15),
        conn.write_all(b"GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n"),
    )
    .await
    .expect("write request timed out")
    .expect("write request");
    eprintln!("== request written");
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(15), conn.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response");
    let text = String::from_utf8_lossy(&buf[..n]);
    eprintln!("== response: {}", &text[..text.len().min(200)]);
    assert!(text.starts_with("HTTP/"), "unexpected response: {text:?}");
}

/// Keep-alive survival: an idle tunnel must emit pings and not false-timeout
/// (a dead stack task is silently rebuilt by the next dial, so liveness is
/// asserted via `tunnel_alive` and then proved by a fresh exchange through
/// the same tunnel). The first connection is deliberately left to idle —
/// remote HTTP servers close idle TCP, which says nothing about the tunnel.
#[tokio::test]
#[ignore = "requires FPTN_TOKEN and network access"]
async fn live_fptn_keepalive_idle_survival() {
    async fn exchange(fptn: &Fptn) {
        let target = Target::Ip("1.1.1.1:80".parse().expect("target"));
        let mut conn = tokio::time::timeout(Duration::from_secs(30), fptn.connect(&target))
            .await
            .expect("connect timed out")
            .expect("connect through fptn");
        tokio::time::timeout(Duration::from_secs(15), async {
            conn.write_all(b"GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n")
                .await
                .expect("write request");
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await.expect("read response");
            let text = String::from_utf8_lossy(&buf[..n]);
            assert!(text.starts_with("HTTP/"), "unexpected response: {text:?}");
        })
        .await
        .expect("exchange timed out");
    }

    let Ok(token) = std::env::var("FPTN_TOKEN") else {
        eprintln!("FPTN_TOKEN not set; skipping live fptn test");
        return;
    };
    let member = member_outbound(&token);
    let obj = member.as_object().expect("member is an object");
    let fptn = Fptn::build(obj, "fptn-ka").expect("build outbound");

    exchange(&fptn).await;
    eprintln!("== baseline exchange ok; idling 40s (keepalive pings at ~15s/~30s)");

    tokio::time::sleep(Duration::from_secs(40)).await;

    assert!(
        fptn.tunnel_alive(),
        "tunnel stack died during the idle window (keep-alive false timeout?)"
    );
    exchange(&fptn).await;
    eprintln!("== tunnel alive and exchanging after 40s idle — keepalive ok");
}
