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

/// A trojan client speaking the raw protocol: `[56-byte SHA224 hex][CRLF]
/// [command][atyp][addr][port][CRLF]`, the same bytes our outbound writes and
/// the reference's server reads.
async fn trojan_request(
    server: SocketAddr,
    password: &str,
    target: SocketAddr,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    use sha2::Digest as _;
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(server).await?;
    let hash: String = sha2::Sha224::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut head = Vec::new();
    head.extend_from_slice(hash.as_bytes());
    head.extend_from_slice(b"\r\n");
    head.push(0x01);
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
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(payload);
    stream.write_all(&head).await?;
    // trojan has no answer head: what comes back is the target's own payload
    let mut answer = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while answer.len() < payload.len() && std::time::Instant::now() < deadline {
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

#[tokio::test]
async fn trojan_server_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let password = "hunter2";
    let instance = core_runtime::start(&cfg(
        json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": [{"name": "bob", "password": password}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start box");
    let server = inbound_addr(&instance, "trojan-in");

    let got = trojan_request(server, password, echo, b"through-the-trojan-server")
        .await
        .expect("trojan request");
    // trojan writes no answer head, so this is exactly the echo
    assert_eq!(String::from_utf8_lossy(&got), "through-the-trojan-server");
    drop(instance);
}

#[tokio::test]
async fn trojan_server_refuses_a_wrong_password() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let instance = core_runtime::start(&cfg(
        json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": [{"name": "bob", "password": "hunter2"}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start box");
    let server = inbound_addr(&instance, "trojan-in");

    let got = trojan_request(server, "wrong", echo, b"nope")
        .await
        .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a refused connection must not carry the payload: {got:?}"
    );
    drop(instance);
}

#[tokio::test]
async fn trojan_server_refuses_two_users_with_one_password() {
    let _guard = test_guard().await;
    let err = core_runtime::start(&cfg(
        json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": [
                {"name": "bob", "password": "same"},
                {"name": "eve", "password": "same"}
            ]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .err()
    .expect("two users with one password should not start");
    let chain = format!("{err:#}");
    assert!(chain.contains("password used by"), "{chain}");
}

#[tokio::test]
async fn trojan_server_refuses_an_unknown_command() {
    let _guard = test_guard().await;
    use tokio::io::AsyncWriteExt as _;
    let instance = core_runtime::start(&cfg(
        json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": [{"name": "bob", "password": "hunter2"}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start box");
    let server = inbound_addr(&instance, "trojan-in");

    let mut stream = tokio::net::TcpStream::connect(server)
        .await
        .expect("connect");
    let hash: String = {
        use sha2::Digest as _;
        sha2::Sha224::digest(b"hunter2")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let mut head = Vec::from(hash.as_bytes());
    head.extend_from_slice(b"\r\n");
    head.push(0x7e); // not tcp, not udp, not mux
    head.extend_from_slice(&[0x01, 127, 0, 0, 1, 0x00, 0x50]);
    head.extend_from_slice(b"\r\n");
    stream.write_all(&head).await.expect("write");
    // the server closes without routing anything; a reset on the way out is the
    // same answer as a clean close, and what matters is that no payload came
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut buf),
    )
    .await
    .expect("the server closes an unknown command");
    assert!(buf.is_empty(), "nothing may come back: {buf:?}");
    drop(instance);
}

/// A server inbound measured against our own client: two boxes in one process,
/// the second one a SOCKS front door to an outbound aimed at the first. The
/// handshake and both framed directions are the production code on both sides.
async fn through_our_own_client(
    server_inbound: Value,
    client_outbound: Value,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let echo = spawn_echo().await;
    let tag = server_inbound["tag"]
        .as_str()
        .expect("the server inbound needs a tag")
        .to_string();
    let server = core_runtime::start(&cfg(
        server_inbound,
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .expect("start server");
    let server_addr = inbound_addr(&server, &tag);
    let mut outbound = client_outbound
        .as_object()
        .expect("the client outbound must be an object")
        .clone();
    outbound.insert("server".into(), json!("127.0.0.1"));
    outbound.insert("server_port".into(), json!(server_addr.port()));
    let client = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": free_port()
        }],
        "outbounds": [Value::Object(outbound)],
        "route": {"final": "out"}
    }))
    .await
    .expect("start client");
    let socks = inbound_addr(&client, "mixed-in");

    let mut stream = tokio::net::TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00], "socks greeting");
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.map_err(io_shutdown)?;
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.map_err(io_shutdown)?;
    if reply[1] != 0x00 {
        return Err(io_shutdown(std::io::Error::other(format!(
            "socks connect refused: {reply:?}"
        ))));
    }
    stream.write_all(payload).await?;
    // the echo comes back through the server's own framing, so it arrives in
    // whatever pieces the socket hands over
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut buf = [0u8; 4096];
    while got.len() < payload.len() && std::time::Instant::now() < deadline {
        let Ok(read) =
            tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf))
                .await
        else {
            continue;
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    drop(client);
    drop(server);
    Ok(got)
}

fn vmess_server(uuid: &str) -> Value {
    json!({
        "type": "vmess",
        "tag": "vmess-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "users": [{"name": "carol", "uuid": uuid}]
    })
}

fn vmess_client(uuid: &str) -> Value {
    json!({"type": "vmess", "tag": "out", "uuid": uuid})
}

fn io_shutdown(err: std::io::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, err.to_string())
}

#[tokio::test]
async fn vmess_server_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let got = through_our_own_client(
        vmess_server(uuid),
        vmess_client(uuid),
        b"through-the-vmess-server",
    )
    .await
    .expect("vmess round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-the-vmess-server");
}

#[tokio::test]
async fn vmess_server_refuses_an_unknown_uuid() {
    let _guard = test_guard().await;
    // No payload may come back. That is all a client can observe here: our own
    // socks front door flushes its success reply even when the dial fails, so
    // the handshake alone proves nothing. The auth id arithmetic itself is
    // covered by the unit tests in `inbound::vmess`.
    let got = through_our_own_client(
        vmess_server("b831381d-6324-4d53-ad4f-8cda48b30811"),
        vmess_client("00000000-0000-4000-8000-000000000000"),
        b"nope",
    )
    .await
    .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a refused connection must not carry the payload: {got:?}"
    );
}

#[tokio::test]
async fn a_vmess_inbound_needs_users() {
    let _guard = test_guard().await;
    let err = core_runtime::start(&cfg(
        json!({
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "127.0.0.1",
            "listen_port": free_port()
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .err()
    .expect("no users should not start");
    let chain = format!("{err:#}");
    assert!(chain.contains("missing users"), "{chain}");
}

fn ss_server(method: &str, password: &str) -> Value {
    json!({
        "type": "shadowsocks",
        "tag": "ss-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "method": method,
        "password": password
    })
}

fn ss_client(method: &str, password: &str) -> Value {
    json!({"type": "shadowsocks", "tag": "out", "method": method, "password": password})
}

/// Both AEAD families, each measured against our own client: the 2022 one with
/// its sealed head and the legacy one with a bare address in the first chunk.
/// The 2022 methods take a pre-shared key, so their password is base64.
#[tokio::test]
async fn shadowsocks_server_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    for (method, password) in [
        ("2022-blake3-aes-128-gcm", "QUFBQUFBQUFBQUFBQUFBQQ=="),
        (
            "2022-blake3-chacha20-poly1305",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
        ),
        ("aes-128-gcm", "hunter2"),
        ("chacha20-ietf-poly1305", "hunter2"),
    ] {
        let got = through_our_own_client(
            ss_server(method, password),
            ss_client(method, password),
            b"through-the-shadowsocks-server",
        )
        .await
        .unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(
            String::from_utf8_lossy(&got),
            "through-the-shadowsocks-server",
            "{method}"
        );
    }
}

#[tokio::test]
async fn shadowsocks_server_refuses_a_wrong_password() {
    let _guard = test_guard().await;
    for (method, right, wrong) in [
        (
            "2022-blake3-aes-128-gcm",
            "QUFBQUFBQUFBQUFBQUFBQQ==",
            "QkJCQkJCQkJCQkJCQkJCQg==",
        ),
        ("aes-128-gcm", "hunter2", "wrong"),
    ] {
        let got =
            through_our_own_client(ss_server(method, right), ss_client(method, wrong), b"nope")
                .await
                .unwrap_or_default();
        assert!(got.is_empty(), "{method}: {got:?}");
    }
}

#[tokio::test]
async fn a_shadowsocks_2022_server_wants_a_key_of_its_own_length() {
    let _guard = test_guard().await;
    let err = core_runtime::start(&cfg(
        ss_server("2022-blake3-aes-128-gcm", "c2hvcnQ="),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .err()
    .expect("a five-byte 2022 key should not start");
    let chain = format!("{err:#}");
    assert!(chain.contains("must be 16 bytes"), "{chain}");
}

#[tokio::test]
async fn a_shadowsocks_inbound_refuses_the_multi_user_shape() {
    let _guard = test_guard().await;
    let err = core_runtime::start(&cfg(
        json!({
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "127.0.0.1",
            "listen_port": free_port(),
            "method": "2022-blake3-aes-128-gcm",
            "users": [{"name": "dave", "password": "QUFBQUFBQUFBQUFBQUFBQQ=="}]
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    ))
    .await
    .err()
    .expect("a multi-user shadowsocks server should not start");
    let chain = format!("{err:#}");
    assert!(chain.contains("multi-user"), "{chain}");
}
