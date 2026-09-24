//! Transport interop: vless/vmess/trojan over ws and httpupgrade against the
//! reference sing-box server. Skipped unless SING_BOX_REF is set (the Docker
//! gate and CI always set it).
//!
//! One sequential test: parallel spawns would race for probe-allocated ports.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const VLESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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

struct RefServer(Child);

impl Drop for RefServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_ref(ref_bin: &str, config: &Value) -> RefServer {
    let path = std::env::temp_dir().join(format!(
        "tc-transport-ref-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        serde_json::to_string(config).expect("serialize config"),
    )
    .expect("write ref config");
    let child = Command::new(ref_bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reference sing-box");
    RefServer(child)
}

async fn wait_listening(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn socks_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [0x05, 0x00]);

    let std::net::IpAddr::V4(v4) = echo.ip() else {
        panic!("expected v4 echo addr");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
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

    let payload = vec![0x5Au8; 40_000];
    stream.write_all(&payload).await.expect("bulk write");
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.expect("bulk read");
    assert_eq!(echoed, payload, "{label}: bulk payload must echo");
}

async fn assert_transport(ref_bin: &str, label: &str, make: impl Fn(u16) -> (Value, Value)) {
    let (inbound, outbound) = make(free_port());
    let echo = spawn_echo().await;
    let _server = start_ref(
        ref_bin,
        &json!({
            "log": {"level": "error"},
            "inbounds": [inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }),
    );
    let listen_port = inbound
        .get("listen_port")
        .and_then(Value::as_u64)
        .expect("port");
    assert!(
        wait_listening(listen_port as u16).await,
        "{label}: reference server did not start"
    );

    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [outbound],
        "route": {"final": "up"}
    }))
    .await
    .expect("start tachyon-core");
    let proxy = instance.inbound_addrs()[0].1;

    let result =
        tokio::time::timeout(Duration::from_secs(20), socks_roundtrip(proxy, echo, label)).await;
    assert!(result.is_ok(), "{label}: timed out");

    instance.shutdown();
}

#[tokio::test]
async fn interop_transports() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let ref_bin = ref_bin.to_string_lossy().into_owned();

    let ws = || json!({"type": "ws", "path": "/ws-path"});
    let hu = || json!({"type": "httpupgrade", "path": "/hu-path"});

    assert_transport(&ref_bin, "vless+ws", |port| {
        (
            json!({
                "type": "vless", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": VLESS_UUID}], "transport": ws()
            }),
            json!({
                "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VLESS_UUID, "transport": ws()
            }),
        )
    })
    .await;
    assert_transport(&ref_bin, "vless+ws+tls", |port| {
        (
            json!({
                "type": "vless", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": VLESS_UUID}], "transport": ws(),
                "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
            }),
            json!({
                "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VLESS_UUID, "transport": ws(),
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            }),
        )
    })
    .await;
    assert_transport(&ref_bin, "vless+httpupgrade", |port| {
        (
            json!({
                "type": "vless", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": VLESS_UUID}], "transport": hu()
            }),
            json!({
                "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VLESS_UUID, "transport": hu()
            }),
        )
    })
    .await;
    assert_transport(&ref_bin, "vless+httpupgrade+tls", |port| {
        (
            json!({
                "type": "vless", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": VLESS_UUID}], "transport": hu(),
                "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
            }),
            json!({
                "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VLESS_UUID, "transport": hu(),
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            }),
        )
    })
    .await;
    assert_transport(&ref_bin, "vmess+ws", |port| {
        (
            json!({
                "type": "vmess", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"name": "u", "uuid": VLESS_UUID}], "transport": ws()
            }),
            json!({
                "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VLESS_UUID, "transport": ws()
            }),
        )
    })
    .await;
    assert_transport(&ref_bin, "trojan+ws+tls", |port| {
        (
            json!({
                "type": "trojan", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"password": "trojan-secret"}], "transport": ws(),
                "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
            }),
            json!({
                "type": "trojan", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "password": "trojan-secret", "transport": ws(),
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            }),
        )
    })
    .await;
}
