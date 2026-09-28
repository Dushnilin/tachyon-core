//! The vless outbound must apply the flow it was configured with: a plain
//! outbound sends the payload straight through, Vision frames it.

use std::time::Duration;

use serde_json::json;
use tokio::io::AsyncReadExt;

use super::Vless;
use crate::inbound::Target;

/// b831381d-6324-4d53-ad4f-8cda48b30811
const UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];
const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn config(port: u16, flow: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut outbound = json!({
        "type": "vless",
        "tag": "v",
        "server": "127.0.0.1",
        "server_port": port,
        "uuid": UUID_TEXT,
    });
    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }
    outbound.as_object().expect("object").clone()
}

/// Serves one connection and returns everything the client sent.
async fn serve(listener: tokio::net::TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut seen = vec![0u8; 4096];
    let mut filled = 0;
    while filled < seen.len() {
        // the head and the first payload bytes arrive together
        match tokio::time::timeout(Duration::from_millis(300), socket.read(&mut seen[filled..]))
            .await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => filled += n,
            Ok(Err(_)) => break,
        }
    }
    seen.truncate(filled);
    seen
}

/// `[0x00][uuid][0x00 addons_len][0x01 command][port:u16][addr_type][addr]`
fn request_head() -> Vec<u8> {
    let mut head = vec![0x00];
    head.extend_from_slice(&UUID);
    head.extend_from_slice(&[0x00, 0x01]);
    head.extend_from_slice(&(80u16).to_be_bytes());
    head.extend_from_slice(&[0x02, 11]);
    head.extend_from_slice(b"example.com");
    head
}

#[tokio::test]
async fn plain_flow_sends_the_payload_unframed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(serve(listener));

    let vless = Vless::build(&config(port, ""), "outbounds[0]").expect("build");
    let mut stream = vless
        .connect(&Target::Domain("example.com".into(), 80))
        .await
        .expect("connect");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    drop(stream);

    let seen = server.await.expect("join");
    let head = request_head();
    assert_eq!(&seen[..head.len()], &head[..], "the request head");
    assert_eq!(&seen[head.len()..], b"GET / HTTP/1.1\r\n\r\n", "no framing");
}

#[tokio::test]
async fn vision_frames_the_payload_behind_the_uuid() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(serve(listener));

    let vless = Vless::build(&config(port, "xtls-rprx-vision"), "outbounds[0]").expect("build");
    let mut stream = vless
        .connect(&Target::Domain("example.com".into(), 80))
        .await
        .expect("connect");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    drop(stream);

    let seen = server.await.expect("join");
    let head = request_head();
    assert_eq!(
        &seen[..head.len()],
        &head[..],
        "the request head is untouched"
    );

    // the payload arrives as [uuid][command][content_len][pad_len][content][pad]
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let start = head.len();
    assert_eq!(
        &seen[start..start + 16],
        &UUID[..],
        "the vision prefix repeats the uuid"
    );
    let frame = &seen[start + 16..];
    assert_eq!(frame[0], 1, "commandPaddingEnd");
    let content = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    assert_eq!(content, payload.len(), "the whole write is one block");
    assert_eq!(&frame[5..5 + content], &payload[..]);
}

#[test]
fn an_unknown_flow_is_rejected() {
    let err = match Vless::build(&config(443, "xtls-rprx-direct"), "outbounds[0]") {
        Ok(_) => panic!("an unknown flow must be rejected"),
        Err(error) => error.to_string(),
    };
    assert!(err.contains("xtls-rprx-direct"), "got {err}");
}
