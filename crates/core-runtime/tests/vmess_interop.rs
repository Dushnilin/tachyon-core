//! vmess outbound interop against the reference sing-box running as a vmess
//! server. Skipped unless SING_BOX_REF points at the reference binary (the
//! Docker gate and CI always set it).
//!
//! One sequential test: parallel spawns would race for probe-allocated ports.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const VMESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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
        "tc-vmess-ref-{}-{}.json",
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
    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("connect to tachyon-core");
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

    // Multi-frame roundtrip to exercise the 15000-byte write split and the
    // download frame assembler across several chunks.
    let payload = vec![0xA5u8; 40_000];
    stream.write_all(&payload).await.expect("bulk write");
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.expect("bulk read");
    assert_eq!(echoed, payload, "{label}: bulk payload must echo");

    // Half-close: the echo must finish cleanly and EOF must propagate.
    stream.shutdown().await.expect("shutdown");
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).await.expect("drain");
    assert!(tail.is_empty(), "{label}: expected clean EOF");
}

async fn assert_variant(
    ref_bin: &str,
    label: &str,
    users: Value,
    make_outbound: impl Fn(u16) -> Value,
) {
    let ref_port = free_port();
    let echo = spawn_echo().await;
    let _server = start_ref(
        ref_bin,
        &json!({
            "log": {"level": "error"},
            "inbounds": [
                {"type": "vmess", "listen": "127.0.0.1", "listen_port": ref_port,
                 "users": users}
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
        tokio::time::timeout(Duration::from_secs(20), socks_roundtrip(proxy, echo, label)).await;
    assert!(result.is_ok(), "{label}: timed out");

    instance.shutdown();
}

#[tokio::test]
async fn interop_vmess_variants() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let ref_bin = ref_bin.to_string_lossy().into_owned();
    let aead_users = json!([{"name": "u", "uuid": VMESS_UUID}]);
    let legacy_users = json!([{"name": "u", "uuid": VMESS_UUID, "alterId": 1}]);
    assert_variant(&ref_bin, "auto default", aead_users.clone(), |port| {
        json!({
            "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "uuid": VMESS_UUID
        })
    })
    .await;
    assert_variant(&ref_bin, "aes-128-gcm", aead_users.clone(), |port| {
        json!({
            "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "uuid": VMESS_UUID, "security": "aes-128-gcm"
        })
    })
    .await;
    assert_variant(&ref_bin, "chacha20-poly1305", aead_users.clone(), |port| {
        json!({
            "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "uuid": VMESS_UUID, "security": "chacha20-poly1305"
        })
    })
    .await;
    assert_variant(&ref_bin, "none", aead_users.clone(), |port| {
        json!({
            "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "uuid": VMESS_UUID, "security": "none"
        })
    })
    .await;
    assert_variant(
        &ref_bin,
        "global padding + authenticated length",
        aead_users.clone(),
        |port| {
            json!({
                "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VMESS_UUID, "security": "aes-128-gcm",
                "global_padding": true, "authenticated_length": true
            })
        },
    )
    .await;
    assert_variant(
        &ref_bin,
        "aes-128-cfb legacy body (aead header)",
        aead_users.clone(),
        |port| {
            json!({
                "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VMESS_UUID, "security": "aes-128-cfb"
            })
        },
    )
    .await;
    assert_variant(
        &ref_bin,
        "full legacy alterId 1",
        legacy_users.clone(),
        |port| {
            json!({
                "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": VMESS_UUID, "security": "aes-128-cfb", "alter_id": 1
            })
        },
    )
    .await;
    assert_variant(&ref_bin, "legacy header + gcm body", legacy_users, |port| {
        json!({
            "type": "vmess", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "uuid": VMESS_UUID, "security": "aes-128-gcm", "alter_id": 1
        })
    })
    .await;
}
