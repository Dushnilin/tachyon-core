//! TLS-based outbound interop: vless + trojan against the reference
//! sing-box acting as TLS server (test cert fixture, insecure client).
//! Skipped unless SING_BOX_REF is set (docker gate and CI set it).

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
        "tc-tls-ref-{}-{}.json",
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
}

async fn assert_outbound(
    ref_bin: &str,
    inbound_type: &str,
    label: &str,
    make_outbound: impl Fn(u16) -> Value,
) {
    let ref_port = free_port();
    let echo = spawn_echo().await;
    let users = match inbound_type {
        "vless" => json!([{"uuid": VLESS_UUID}]),
        "trojan" => json!([{"password": "trojan-secret"}]),
        "anytls" => json!([{"password": "anytls-secret"}]),
        "naive" => json!([{"username": "naive-user", "password": "naive-secret"}]),
        other => panic!("unsupported inbound type {other}"),
    };
    let _server = start_ref(
        ref_bin,
        &json!({
            "log": {"level": "error"},
            "inbounds": [
                {"type": inbound_type, "listen": "127.0.0.1", "listen_port": ref_port,
                 "users": users,
                 "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}}
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }),
    );
    assert!(
        wait_listening(ref_port).await,
        "{label}: reference server did not start"
    );

    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [make_outbound(ref_port)],
        "route": {"final": "up"}
    }))
    .await
    .expect("start tachyon-core");
    let proxy = instance.inbound_addrs()[0].1;

    let result =
        tokio::time::timeout(Duration::from_secs(15), socks_roundtrip(proxy, echo, label)).await;
    assert!(result.is_ok(), "{label}: timed out");

    instance.shutdown();
}

#[tokio::test]
async fn interop_vless_tls() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_outbound(&ref_bin.to_string_lossy(), "vless", "vless+tls", |port| {
        json!({
            "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "uuid": VLESS_UUID,
            "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
        })
    })
    .await;
}

/// Both were on the roadmap as full parity with nothing but `check` behind
/// them -- which is exactly how the vless Vision flow went unnoticed until the
/// reference was actually run. These run the reference as the server.
#[tokio::test]
async fn interop_anytls_tls() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_outbound(&ref_bin.to_string_lossy(), "anytls", "anytls+tls", |port| {
        json!({
            "type": "anytls", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "password": "anytls-secret",
            "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
        })
    })
    .await;
}

/// Naive is two things on top of an HTTP/2 CONNECT: the `Padding` header the
/// reference answers 400 without, and the eight-block framing its `naiveH2Conn`
/// embeds. Both are here, and the reference's own naive inbound is the judge.
#[tokio::test]
async fn interop_naive_tls() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    // the reference refuses `insecure` on a naive outbound (and so do we), so
    // the test certificate is trusted as a CA instead
    assert_outbound(&ref_bin.to_string_lossy(), "naive", "naive+tls", |port| {
        json!({
            "type": "naive", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "username": "naive-user", "password": "naive-secret",
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "certificate_path": format!("{}/../../tests/golden/certs/localhost.crt", env!("CARGO_MANIFEST_DIR"))
            }
        })
    })
    .await;
}

#[tokio::test]
async fn interop_trojan_tls() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_outbound(&ref_bin.to_string_lossy(), "trojan", "trojan+tls", |port| {
        json!({
            "type": "trojan", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "password": "trojan-secret",
            "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
        })
    })
    .await;
}
