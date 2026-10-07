//! Our server inbounds (F5) measured against the reference *as the client*.
//! The other direction already has a test -- our client against the reference's
//! server -- and between them they are the only thing that catches a wire
//! format we got wrong. Everything here is plain TCP except the grpc+tls case,
//! which needs the listener's ALPN to be right: Vision is left out on purpose,
//! since it wants more than a handshake from this side.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "hunter2";
/// the 2022 pre-shared key is base64 of sixteen `A`s
const KEY_2022: &str = "QUFBQUFBQUFBQUFBQUFBQQ==";

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

/// The reference needs a moment before its door answers, and how long that is
/// depends on the machine: on Windows it is up in time, in a container it is
/// not, and a test that assumes otherwise fails for a reason that has nothing
/// to do with the code under it.
async fn wait_listening(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

struct RefClient(Child);

impl Drop for RefClient {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The reference in front: a SOCKS door, and whatever outbound the test names.
fn start_ref(ref_bin: &str, outbound: Value) -> (RefClient, SocketAddr) {
    let port = free_port();
    let config = json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "front", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
        "route": {"final": "up"}
    });
    let path = std::env::temp_dir().join(format!(
        "tc-server-interop-{}-{}.json",
        std::process::id(),
        port
    ));
    std::fs::write(&path, serde_json::to_string(&config).expect("serialize"))
        .expect("write ref config");
    let child = Command::new(ref_bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reference sing-box");
    (RefClient(child), SocketAddr::from(([127, 0, 0, 1], port)))
}

async fn socks_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    let mut stream = TcpStream::connect(proxy).await.expect("connect front");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.expect("auth reply");
    assert_eq!(greeting, [0x05, 0x00], "{label}: socks greeting");

    let ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("expected a v4 echo address"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd");
    assert_eq!(reply[1], 0x00, "{label}: CONNECT must succeed");

    stream.write_all(b"roundtrip").await.expect("write");
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"roundtrip", "{label}: payload must echo");
}

/// Our inbound, the reference pointing at it, and the bytes to prove it.
async fn assert_server_serves(
    ref_bin: &str,
    inbound_type: &str,
    label: &str,
    server_extra: Value,
    make_client: impl Fn(u16) -> Value,
) {
    let echo = spawn_echo().await;
    let listen_port = free_port();
    let mut server = server_extra.as_object().expect("object").clone();
    server.insert("type".into(), json!(inbound_type));
    server.insert("tag".into(), json!("server-in"));
    server.insert("listen".into(), json!("127.0.0.1"));
    server.insert("listen_port".into(), json!(listen_port));

    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [Value::Object(server)],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .unwrap_or_else(|e| panic!("{label}: start our server: {e:#}"));

    let (_client, front) = start_ref(ref_bin, make_client(listen_port));
    assert!(
        wait_listening(front.port()).await,
        "{label}: the reference did not start"
    );
    let result =
        tokio::time::timeout(Duration::from_secs(15), socks_roundtrip(front, echo, label)).await;
    instance.shutdown();
    result.unwrap_or_else(|_| panic!("{label}: timed out"));
}

macro_rules! server_test {
    ($name:ident, $label:literal, $type:literal, $extra:expr, $client:expr) => {
        #[tokio::test]
        async fn $name() {
            let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
                return;
            };
            assert_server_serves(&ref_bin.to_string_lossy(), $type, $label, $extra, |port| {
                $client(port)
            })
            .await;
        }
    };
}

server_test!(
    vless_server_serves_the_reference_client,
    "vless",
    "vless",
    json!({"users": [{"name": "u", "uuid": UUID}]}),
    |port| json!({"type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port, "uuid": UUID})
);

server_test!(
    vless_grpc_server_serves_the_reference_client,
    "vless+grpc",
    "vless",
    json!({"users": [{"name": "u", "uuid": UUID}],
           "transport": {"type": "grpc", "service_name": "interop"}}),
    |port| json!({"type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port, "uuid": UUID,
                  "transport": {"type": "grpc", "service_name": "interop"}})
);

// The same over TLS: the reference's grpc client is grpc-go, which refuses a
// connection where the server negotiated no `h2`, so this is the case that
// proves the inbound put `h2` on the listener's ALPN.
server_test!(
    vless_grpc_tls_server_serves_the_reference_client,
    "vless+grpc+tls",
    "vless",
    json!({"users": [{"name": "u", "uuid": UUID}],
           "transport": {"type": "grpc", "service_name": "interop"},
           "tls": {"enabled": true,
                   "certificate_path": format!("{}/../../tests/golden/certs/localhost.crt", env!("CARGO_MANIFEST_DIR")),
                   "key_path": format!("{}/../../tests/golden/certs/localhost.key", env!("CARGO_MANIFEST_DIR"))}}),
    |port| json!({"type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port, "uuid": UUID,
                  "transport": {"type": "grpc", "service_name": "interop"},
                  "tls": {"enabled": true, "server_name": "localhost", "insecure": true}})
);

// XHTTP: the reference's own client (packet-up, which is what `auto` resolves
// to without REALITY) over cleartext, which is where its decideHTTPVersion
// falls back to HTTP/1.1 and the wire is this server's.
server_test!(
    vless_xhttp_server_serves_the_reference_client,
    "vless+xhttp",
    "vless",
    json!({"users": [{"name": "u", "uuid": UUID}],
           "transport": {"type": "xhttp", "path": "/bench"}}),
    |port| json!({"type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port, "uuid": UUID,
                  "transport": {"type": "xhttp", "path": "/bench"}})
);

// ...and the same over TLS, where the client has to be told to ask for
// HTTP/1.1: on its own it would offer h2, and this server's XHTTP is HTTP/1.1
// only. The listener puts http/1.1 in its own ALPN either way, so what this
// case proves is that the two meet on the one protocol both speak.
server_test!(
    vless_xhttp_tls_server_serves_the_reference_client,
    "vless+xhttp+tls",
    "vless",
    json!({"users": [{"name": "u", "uuid": UUID}],
           "transport": {"type": "xhttp", "path": "/bench"},
           "tls": {"enabled": true,
                   "certificate_path": format!("{}/../../tests/golden/certs/localhost.crt", env!("CARGO_MANIFEST_DIR")),
                   "key_path": format!("{}/../../tests/golden/certs/localhost.key", env!("CARGO_MANIFEST_DIR"))}}),
    |port| json!({"type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port, "uuid": UUID,
                  "transport": {"type": "xhttp", "path": "/bench"},
                  "tls": {"enabled": true, "server_name": "localhost", "insecure": true,
                          "alpn": ["http/1.1"]}})
);

server_test!(
    trojan_server_serves_the_reference_client,
    "trojan",
    "trojan",
    json!({"users": [{"name": "u", "password": PASSWORD}]}),
    |port| json!({"type": "trojan", "tag": "up", "server": "127.0.0.1", "server_port": port, "password": PASSWORD})
);

server_test!(
    vmess_server_serves_the_reference_client,
    "vmess",
    "vmess",
    json!({"users": [{"name": "u", "uuid": UUID}]}),
    |port| json!({"type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port, "uuid": UUID})
);

server_test!(
    shadowsocks_2022_server_serves_the_reference_client,
    "shadowsocks+2022",
    "shadowsocks",
    json!({"method": "2022-blake3-aes-128-gcm", "password": KEY_2022}),
    |port| json!({"type": "shadowsocks", "tag": "up", "server": "127.0.0.1", "server_port": port,
                  "method": "2022-blake3-aes-128-gcm", "password": KEY_2022})
);

server_test!(
    shadowsocks_legacy_server_serves_the_reference_client,
    "shadowsocks+legacy",
    "shadowsocks",
    json!({"method": "aes-128-gcm", "password": PASSWORD}),
    |port| json!({"type": "shadowsocks", "tag": "up", "server": "127.0.0.1", "server_port": port,
                  "method": "aes-128-gcm", "password": PASSWORD})
);
