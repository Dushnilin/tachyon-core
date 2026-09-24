//! WireGuard endpoint interop: our box dials the reference sing-box acting as
//! a WireGuard responder; a TCP flow through the tunnel must roundtrip.
//! Topology: ref = listener (10.66.66.1/24), us = initiator (10.66.66.2/24),
//! route.final = endpoint tag; ref routes tunnel traffic via direct.
//! Skipped unless SING_BOX_REF is set (docker gate and CI set it).

use std::net::{IpAddr, SocketAddr};
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn x25519_pub(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sk)).to_bytes()
}

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind echo");
    let port = listener.local_addr().expect("echo addr").port();
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
    port
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

fn lan_ip() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(IpAddr::V4(v4)),
        _ => None,
    }
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
        "tc-wg-ref-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        serde_json::to_string(config).expect("serialize config"),
    )
    .expect("write ref config");
    let err_path = path.with_extension("err");
    let err = std::fs::File::create(&err_path).expect("ref stderr file");
    let out = err.try_clone().expect("clone ref log file");
    let child = Command::new(ref_bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::from(out))
        .stderr(err)
        .spawn()
        .expect("spawn reference sing-box");
    RefServer(child)
}

async fn wait_listening(port: u16) -> bool {
    // WireGuard is UDP — a TCP probe never succeeds. One datagram + a short
    // pause: enough for the ref process to bind its UDP socket.
    let Ok(sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(("127.0.0.1", port)).await.is_err() {
        return false;
    }
    if sock.send(b"ping").await.is_err() {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    true
}

async fn socks_roundtrip(proxy: SocketAddr, target: SocketAddr, label: &str) -> Result<(), String> {
    eprintln!("{label}: socks connect");
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| format!("connect inbound: {e}"))?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("greeting: {e}"))?;
    let mut auth = [0u8; 2];
    stream
        .read_exact(&mut auth)
        .await
        .map_err(|e| format!("auth reply: {e}"))?;
    if auth != [0x05, 0x00] {
        return Err(format!("socks auth failed: {auth:?}"));
    }

    let IpAddr::V4(v4) = target.ip() else {
        return Err("expected v4 target".into());
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| format!("socks request: {e}"))?;
    let mut reply = [0u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| format!("connect reply: {e}"))?;
    let mut bnd = [0u8; 6];
    stream
        .read_exact(&mut bnd)
        .await
        .map_err(|e| format!("bnd: {e}"))?;
    if reply[1] != 0x00 {
        return Err(format!("CONNECT failed: reply {reply:?}"));
    }

    stream
        .write_all(b"roundtrip")
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 9];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("echo read: {e}"))?;
    if &buf != b"roundtrip" {
        return Err(format!("payload mismatch: {buf:?}"));
    }
    Ok(())
}

#[tokio::test]
async fn interop_wireguard() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let ref_bin = ref_bin.to_string_lossy().into_owned();

    let our_priv = [0x11u8; 32];
    let ref_priv = [0x22u8; 32];
    let our_pub = b64(&x25519_pub(&our_priv));
    let ref_pub = b64(&x25519_pub(&ref_priv));

    let ref_port = free_port();
    let echo_port = spawn_echo().await;
    eprintln!("wireguard: starting ref on {ref_port}, echo on {echo_port}");
    let _server = start_ref(
        &ref_bin,
        &json!({
            "log": {"level": "debug"},
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg",
                "private_key": b64(&ref_priv),
                "address": ["10.66.66.1/24"],
                "listen_port": ref_port,
                "peers": [{
                    "public_key": our_pub,
                    "allowed_ips": ["0.0.0.0/0", "10.66.66.2/32"]
                }]
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        }),
    );
    assert!(
        wait_listening(ref_port).await,
        "wireguard: reference server did not start"
    );
    eprintln!("wireguard: ref up on {ref_port}");

    let instance = core_runtime::start(&json!({
        "log": {"level": "debug"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg",
            "private_key": b64(&our_priv),
            "address": ["10.66.66.2/24"],
            "peers": [{
                "address": "127.0.0.1",
                "port": ref_port,
                "public_key": ref_pub,
                "allowed_ips": ["0.0.0.0/0"]
            }]
        }],
        "route": {"final": "wg"}
    }))
    .await
    .expect("start tachyon-core");
    let proxy = instance.inbound_addrs()[0].1;
    eprintln!("wireguard: box up, proxy {proxy}");

    // Primary target: the host LAN address — a "remote" destination from the
    // reference's point of view. Fallback: loopback.
    let mut attempts: Vec<SocketAddr> = Vec::new();
    if let Some(ip) = lan_ip() {
        attempts.push(SocketAddr::new(ip, echo_port));
    }
    attempts.push(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), echo_port));

    let mut ok = false;
    for target in attempts {
        eprintln!("wireguard: roundtrip via {target}");
        let result = tokio::time::timeout(
            Duration::from_secs(25),
            socks_roundtrip(proxy, target, "wg"),
        )
        .await;
        match result {
            Ok(Ok(())) => {
                ok = true;
                break;
            }
            Ok(Err(e)) => eprintln!("wireguard: attempt {target} failed: {e}"),
            Err(_) => eprintln!("wireguard: attempt {target} timed out"),
        }
    }

    instance.shutdown();
    assert!(ok, "wireguard: all roundtrip attempts failed");
    eprintln!("wireguard: roundtrip ok, shutting down");
}
