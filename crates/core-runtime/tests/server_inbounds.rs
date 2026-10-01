//! Server inbounds (F5), end to end: our own client against our own server over
//! a real socket. No fixture stands in for either side.

use std::net::SocketAddr;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

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

fn inbound_addr(instance: &core_runtime::BoxInstance, tag: &str) -> SocketAddr {
    instance
        .inbound_addrs()
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, a)| *a)
        .unwrap_or_else(|| panic!("no inbound {tag}"))
}

fn cfg(inbound: Value, outbounds: Value) -> Value {
    json!({
        "log": {"level": "error"},
        "inbounds": [inbound],
        "outbounds": outbounds,
        "route": {"final": "direct"}
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("port")
        .local_addr()
        .expect("addr")
        .port()
}

/// A vless client speaking the raw protocol: no TLS, no transport, so the test
/// is about the server half and nothing else.
async fn vless_request(
    server: SocketAddr,
    uuid: &str,
    target: SocketAddr,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(server).await?;
    let uuid = parse_uuid(uuid);
    let mut head = Vec::with_capacity(32 + payload.len());
    head.push(0x00); // version
    head.extend_from_slice(&uuid);
    head.push(0x00); // addons length
    head.push(0x01); // command: tcp
    match target.ip() {
        std::net::IpAddr::V4(v4) => {
            head.push(0x01);
            head.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            head.push(0x04);
            head.extend_from_slice(&v6.octets());
        }
    }
    head.extend_from_slice(&target.port().to_be_bytes());
    head.extend_from_slice(payload);
    stream.write_all(&head).await?;
    // the server answers `[version][addonsLen]` in front of the first payload
    let mut answer = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while answer.len() < 2 + payload.len() && std::time::Instant::now() < deadline {
        let Ok(read) =
            tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf))
                .await
        else {
            continue;
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(n) => answer.extend_from_slice(&buf[..n]),
        }
    }
    Ok(answer)
}

fn parse_uuid(raw: &str) -> [u8; 16] {
    let hex: String = raw.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("uuid");
    }
    out
}

#[tokio::test]
async fn vless_server_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let port = free_port();
    let instance = core_runtime::start(&cfg(
        json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"name": "alice", "uuid": uuid}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start box");
    let server = inbound_addr(&instance, "vless-in");

    let got = vless_request(server, uuid, echo, b"through-the-vless-server")
        .await
        .expect("vless request");
    // two answer-head bytes, then the echo
    assert_eq!(&got[..2], &[0x00, 0x00], "the answer head is missing");
    assert_eq!(
        String::from_utf8_lossy(&got[2..]),
        "through-the-vless-server"
    );
    drop(instance);
}

#[tokio::test]
async fn vless_server_refuses_an_unknown_uuid() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let port = free_port();
    let instance = core_runtime::start(&cfg(
        json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"name": "alice", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start box");
    let server = inbound_addr(&instance, "vless-in");

    let stranger = "00000000-0000-4000-8000-000000000000";
    // a refused connection is either an error or an empty answer; what it must
    // never be is the payload coming back
    if let Ok(got) = vless_request(server, stranger, echo, b"nope").await {
        assert!(
            got.is_empty(),
            "a refused connection must not carry the payload: {got:?}"
        );
    }
    drop(instance);
}

#[tokio::test]
async fn vless_server_checks_the_flow_against_the_user() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let port = free_port();
    // the user asks for vision, the client does not offer it
    let instance = core_runtime::start(&cfg(
        json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"name": "alice", "uuid": uuid, "flow": "xtls-rprx-vision"}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start box");
    let server = inbound_addr(&instance, "vless-in");

    let got = vless_request(server, uuid, echo, b"vision please")
        .await
        .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a flow mismatch must not carry the payload: {got:?}"
    );
    drop(instance);
}

#[tokio::test]
async fn a_vless_inbound_needs_users() {
    let _guard = test_guard().await;
    let err = core_runtime::start(&cfg(
        json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": free_port()
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .err()
    .expect("no users should not start");
    // `with_context` wraps the reason, so the whole chain is what says it
    let chain = format!("{err:#}");
    assert!(chain.contains("missing users"), "{chain}");
}

#[tokio::test]
async fn a_vless_inbound_refuses_an_empty_user_list() {
    let _guard = test_guard().await;
    let err = core_runtime::start(&cfg(
        json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": []
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .err()
    .expect("an empty user list should not start");
    let chain = format!("{err:#}");
    assert!(chain.contains("must not be empty"), "{chain}");
}
