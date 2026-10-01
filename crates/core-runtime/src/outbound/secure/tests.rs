//! The vless outbound must apply the flow it was configured with: a plain
//! outbound sends the payload straight through, Vision frames it.

use std::time::Duration;

use serde_json::json;
use tokio::io::AsyncReadExt;

use super::Vless;

/// trojan's destination block is `M.SocksaddrSerializer`, whose family bytes
/// are 1 = IPv4, 4 = IPv6 and 3 = FQDN (sing's `common/metadata/family.go`).
/// A domain written as 2 is what every trojan server on the wire rejects, and
/// this pins the byte so it cannot come back.
#[test]
fn trojan_writes_the_socksaddr_family_bytes() {
    use crate::inbound::Target;
    let domain = Target::Domain("example.com".to_string(), 443);
    let block = crate::outbound::proxy::encode_target_with(&domain, 0x03).expect("encode domain");
    assert_eq!(
        block,
        [
            0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb
        ],
        "domain, then port 443"
    );
    // and the IPv4 and IPv6 bytes are the ones the serializer uses
    let v4 = Target::Ip("1.2.3.4:80".parse().expect("addr"));
    assert_eq!(
        crate::outbound::proxy::encode_target_with(&v4, 0x03).expect("encode v4"),
        [0x01, 1, 2, 3, 4, 0x00, 0x50]
    );
    let v6 = Target::Ip("[2001:db8::1]:80".parse().expect("addr"));
    let encoded = crate::outbound::proxy::encode_target_with(&v6, 0x03).expect("encode v6");
    assert_eq!(encoded[0], 0x04, "IPv6 keeps 4, not 3");
    assert_eq!(encoded.len(), 1 + 16 + 2);
    assert_eq!(&encoded[17..], &[0x00, 0x50]);
}

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

/// `[0x00][uuid][0x00 addons_len][command][port:u16][addr_type][len][addr]`
fn request_head_with(command: u8) -> Vec<u8> {
    let mut head = vec![0x00];
    head.extend_from_slice(&UUID);
    head.extend_from_slice(&[0x00, command]);
    head.extend_from_slice(&(80u16).to_be_bytes());
    head.extend_from_slice(&[0x02, 11]);
    head.extend_from_slice(b"example.com");
    head
}

fn request_head() -> Vec<u8> {
    request_head_with(1)
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

/// A vless udp relay: the request head carries the `Mux` command and the
/// destination, and each datagram then rides the stream framed by xudp.
#[tokio::test]
async fn udp_relay_frames_datagrams_over_one_stream() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = vec![0u8; 34];
        socket.read_exact(&mut head).await.expect("request head");
        // the first xudp frame names the destination
        let mut meta_len = [0u8; 2];
        socket.read_exact(&mut meta_len).await.expect("meta len");
        let mut meta = vec![0u8; u16::from_be_bytes(meta_len) as usize];
        socket.read_exact(&mut meta).await.expect("meta");
        let mut data_len = [0u8; 2];
        socket.read_exact(&mut data_len).await.expect("data len");
        let mut data = vec![0u8; u16::from_be_bytes(data_len) as usize];
        socket.read_exact(&mut data).await.expect("data");
        // answer: the vless response head, then an xudp keep frame
        let mut reply = vec![0x00, 0x00];
        reply.extend_from_slice(&4u16.to_be_bytes());
        reply.extend_from_slice(&[0, 0, 2, 1]);
        let echoed = data.iter().rev().copied().collect::<Vec<u8>>();
        reply.extend_from_slice(&(echoed.len() as u16).to_be_bytes());
        reply.extend_from_slice(&echoed);
        socket.write_all(&reply).await.expect("reply");
        (head, meta, data)
    });

    let mut outbound = config(port, "");
    outbound.insert("packet_encoding".into(), json!("xudp"));
    let vless = Vless::build(&outbound, "outbounds[0]").expect("build");
    let sock = vless
        .connect_udp(&Target::Domain("example.com".into(), 53))
        .await
        .expect("udp relay");
    sock.send(b"ping").await.expect("send");

    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .expect("answer in time")
        .expect("recv");
    assert_eq!(
        &buf[..read],
        b"gnip",
        "the relay echoes what the server sent"
    );

    let (head, meta, data) = server.await.expect("join");
    let mut expected = request_head_with(3);
    expected[19..21].copy_from_slice(&53u16.to_be_bytes());
    assert_eq!(head, expected, "the request head names the udp target");
    assert_eq!(&meta[..5], &[0, 0, 1, 1, 2], "new, opt, udp");
    assert_eq!(&meta[5..7], &[0x02, 11], "domain with its length");
    assert_eq!(&meta[7..18], b"example.com");
    assert_eq!(&meta[18..20], &53u16.to_be_bytes());
    assert_eq!(&data, b"ping");
}
