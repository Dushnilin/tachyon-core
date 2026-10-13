//! hysteria2 + tuic outbound interop: our box dials the reference sing-box
//! acting as hy2/tuic server (test cert fixture, insecure client, TCP path).
//! Skipped unless SING_BOX_REF is set (docker gate and CI set it).

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Serialize box instances: the dns service is process-global.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const TUIC_UUID: &str = "00000000-0000-0000-0000-000000000000";

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
        "tc-hy2tuic-ref-{}-{}.json",
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
    // hy2/tuic are UDP/QUIC inbounds — a TCP probe never succeeds.
    // One datagram + a short pause: enough for the ref process to bind UDP.
    let Ok(sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(("127.0.0.1", port)).await.is_err() {
        return false;
    }
    if sock.send(b"ping").await.is_err() {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    true
}

async fn socks_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    eprintln!("{label}: socks connect");
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    eprintln!("{label}: greeting");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    eprintln!("{label}: auth {auth:?}");
    assert_eq!(auth, [0x05, 0x00]);

    let std::net::IpAddr::V4(v4) = echo.ip() else {
        panic!("expected v4 echo addr");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    eprintln!("{label}: connect request");
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    eprintln!("{label}: reply {reply:?}");
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
    make_ref_inbound: impl Fn(u16) -> Value,
    make_outbound: impl Fn(u16) -> Value,
) {
    let _guard = test_guard().await;
    eprintln!("{label}: starting ref");
    let ref_port = free_port();
    let echo = spawn_echo().await;
    let _server = start_ref(
        ref_bin,
        &json!({
            "log": {"level": "error"},
            "inbounds": [make_ref_inbound(ref_port)],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }),
    );
    assert!(
        wait_listening(ref_port).await,
        "{label}: reference server did not start"
    );
    eprintln!("{label}: ref up on {ref_port}");

    eprintln!("{label}: starting box");
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
    eprintln!("{label}: box up, proxy {proxy}");

    eprintln!("{label}: socks roundtrip");
    let result =
        tokio::time::timeout(Duration::from_secs(20), socks_roundtrip(proxy, echo, label)).await;
    eprintln!("{label}: roundtrip result ok={}", result.is_ok());
    assert!(result.is_ok(), "{label}: timed out");
    eprintln!("{label}: roundtrip ok, shutting down");

    instance.shutdown();
    eprintln!("{label}: done");
    let _ = inbound_type;
}

#[tokio::test]
async fn interop_hysteria2() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_outbound(
        &ref_bin.to_string_lossy(),
        "hysteria2",
        "hysteria2",
        |port| {
            json!({
                "type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"password": "interop-pass"}],
                "up_mbps": 10, "down_mbps": 10,
                "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
            })
        },
        |port| {
            json!({
                "type": "hysteria2", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "up_mbps": 10, "down_mbps": 10, "password": "interop-pass",
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            })
        },
    )
    .await;
}

#[tokio::test]
async fn interop_tuic() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_outbound(
        &ref_bin.to_string_lossy(),
        "tuic",
        "tuic",
        |port| {
            json!({
                "type": "tuic", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": TUIC_UUID, "password": "interop-pass"}],
                "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
            })
        },
        |port| {
            json!({
                "type": "tuic", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "uuid": TUIC_UUID, "password": "interop-pass",
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            })
        },
    )
    .await;
}
