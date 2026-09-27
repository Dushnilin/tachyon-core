//! snell outbound interop: our box (v4 and v6 clients) dials the reference
//! sing-box snell inbound. lx supports inbound versions 5/6 — the v5 server
//! shares the v4 request/record/reply framing (same `snell.RequestVersion`,
//! header layout and `ParseReply`), v6 speaks the three framing modes
//! (`default`/`unshaped`/`unsafe-raw`) over the same request protocol, so
//! this pins wire compatibility. Skipped unless SING_BOX_REF is set (docker
//! gate and CI set it).

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const PSK: &str = "interop-psk-12345678";

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

async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if sock.send_to(&buf[..n], from).await.is_err() {
                return;
            }
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
        "tc-snell-ref-{}-{}.json",
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

async fn wait_ref_up(port: u16) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn socks_handshake(proxy: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [0x05, 0x00]);
    stream
}

fn v4_of(addr: SocketAddr) -> std::net::Ipv4Addr {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => panic!("expected v4 addr"),
    }
}

async fn socks_roundtrip(proxy: SocketAddr, echo: SocketAddr, payload: &[u8], label: &str) {
    let mut stream = socks_handshake(proxy).await;
    eprintln!("{label}: socks connect request");
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4_of(echo).octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd");
    assert_eq!(reply[1], 0x00, "{label}: CONNECT must succeed");
    eprintln!("{label}: CONNECT ok, writing payload");

    stream.write_all(payload).await.expect("write");
    eprintln!("{label}: payload written, reading echo");
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(buf, payload, "{label}: payload must echo");
}

/// SOCKS5 UDP ASSOCIATE roundtrip through the mixed inbound → snell outbound.
async fn socks_udp_roundtrip(proxy: SocketAddr, echo: SocketAddr, payload: &[u8], label: &str) {
    let mut ctrl = socks_handshake(proxy).await;
    // UDP ASSOCIATE to 0.0.0.0:0 — the server replies with its relay address.
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate request");
    let mut reply = [0u8; 4];
    ctrl.read_exact(&mut reply).await.expect("associate reply");
    assert_eq!(reply[1], 0x00, "{label}: UDP ASSOCIATE must succeed");
    let relay = match reply[3] {
        0x01 => {
            let mut bnd = [0u8; 6];
            ctrl.read_exact(&mut bnd).await.expect("bnd v4");
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(bnd[0], bnd[1], bnd[2], bnd[3])),
                u16::from_be_bytes([bnd[4], bnd[5]]),
            )
        }
        0x04 => {
            let mut bnd = [0u8; 18];
            ctrl.read_exact(&mut bnd).await.expect("bnd v6");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bnd[..16]);
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                u16::from_be_bytes([bnd[16], bnd[17]]),
            )
        }
        0x03 => {
            let mut len = [0u8; 1];
            ctrl.read_exact(&mut len).await.expect("bnd len");
            let mut host = vec![0u8; len[0] as usize];
            ctrl.read_exact(&mut host).await.expect("bnd host");
            let mut port = [0u8; 2];
            ctrl.read_exact(&mut port).await.expect("bnd port");
            let host = String::from_utf8(host).expect("bnd utf8");
            SocketAddr::new(
                host.parse().expect("bnd host addr"),
                u16::from_be_bytes(port),
            )
        }
        other => panic!("{label}: unexpected bnd atyp {other}"),
    };

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01];
    datagram.extend_from_slice(&v4_of(echo).octets());
    datagram.extend_from_slice(&echo.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    sock.send_to(&datagram, relay).await.expect("udp send");

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{label}: udp reply timeout"))
        .expect("udp reply");
    assert!(n >= 4, "{label}: short udp reply");
    assert_eq!(&buf[..3], &[0x00, 0x00, 0x00], "{label}: udp rsv");
    let header = match buf[3] {
        0x01 => 4 + 6,
        0x04 => 4 + 18,
        0x03 => 5 + buf[4] as usize,
        other => panic!("{label}: unexpected udp reply atyp {other}"),
    };
    assert_eq!(&buf[header..n], payload, "{label}: udp payload must echo");
    // Keep the control stream alive until after the exchange.
    drop(ctrl);
}

#[allow(clippy::too_many_arguments)]
async fn assert_snell(
    ref_bin: &str,
    label: &str,
    version: u8,
    obfs_mode: &str,
    mode: &str,
    reuse: bool,
    rounds: usize,
    with_udp: bool,
) {
    let ref_port = free_port();
    let echo = spawn_echo().await;
    let udp_echo = spawn_udp_echo().await;
    // Version-scoped inbound options (reference `SnellInboundOptions`):
    // v5 takes obfs, v6 takes the framing mode. Fields of the other version
    // are omitted entirely.
    let ref_inbound = if version == 6 {
        json!({
            "type": "snell", "listen": "127.0.0.1", "listen_port": ref_port,
            "version": 6, "psk": PSK, "mode": mode
        })
    } else {
        json!({
            "type": "snell", "listen": "127.0.0.1", "listen_port": ref_port,
            "version": 5, "psk": PSK, "obfs_mode": obfs_mode
        })
    };
    let _server = start_ref(
        ref_bin,
        &json!({
            "log": {"level": "error"},
            "inbounds": [ref_inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }),
    );
    assert!(
        wait_ref_up(ref_port).await,
        "{label}: reference snell server did not start"
    );

    // Our outbound carries both option families: the runtime keeps only the
    // fields of `version` (mirroring `UnmarshallExcluded`).
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [{
            "type": "snell", "tag": "up", "server": "127.0.0.1", "server_port": ref_port,
            "version": version, "psk": PSK,
            "obfs_mode": obfs_mode, "obfs_host": "www.bing.com",
            "mode": mode,
            "reuse": reuse, "network": ["tcp", "udp"]
        }],
        "route": {"final": "up"}
    }))
    .await
    .expect("start tachyon-core");
    let proxy = instance.inbound_addrs()[0].1;

    for round in 0..rounds {
        let payload = format!("{label}-{round}").into_bytes();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            socks_roundtrip(proxy, echo, &payload, label),
        )
        .await;
        assert!(result.is_ok(), "{label}: tcp round {round} timed out");
        result.unwrap();
    }

    if with_udp {
        let payload = b"snell-udp-interop";
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            socks_udp_roundtrip(proxy, udp_echo, payload, label),
        )
        .await;
        assert!(result.is_ok(), "{label}: udp roundtrip timed out");
        result.unwrap();
    }

    instance.shutdown();
}

#[tokio::test]
async fn interop_snell_plain() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_snell(
        &ref_bin.to_string_lossy(),
        "snell-none",
        4,
        "none",
        "",
        false,
        1,
        true,
    )
    .await;
}

#[tokio::test]
async fn interop_snell_obfs_http_reuse() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    // Two sequential roundtrips: the first must release its session back to
    // the pool, the second must take it again (or dial fresh if the server
    // dropped the connection — both are legal, the traffic must flow).
    assert_snell(
        &ref_bin.to_string_lossy(),
        "snell-http",
        4,
        "http",
        "",
        true,
        2,
        false,
    )
    .await;
}

#[tokio::test]
async fn interop_snell_obfs_tls_reuse() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_snell(
        &ref_bin.to_string_lossy(),
        "snell-tls",
        4,
        "tls",
        "",
        true,
        2,
        false,
    )
    .await;
}

#[tokio::test]
async fn interop_snell_v6_default() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    // Profile-shaped records with salt blocks and record prefixes; two dials
    // (reuse off) exercise fresh profiles, UDP rides the same framer.
    assert_snell(
        &ref_bin.to_string_lossy(),
        "snell-v6-default",
        6,
        "none",
        "default",
        false,
        2,
        true,
    )
    .await;
}

#[tokio::test]
async fn interop_snell_v6_unshaped_reuse() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_snell(
        &ref_bin.to_string_lossy(),
        "snell-v6-unshaped",
        6,
        "none",
        "unshaped",
        true,
        2,
        true,
    )
    .await;
}

#[tokio::test]
async fn interop_snell_v6_unsafe_raw() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_snell(
        &ref_bin.to_string_lossy(),
        "snell-v6-raw",
        6,
        "none",
        "unsafe-raw",
        false,
        1,
        false,
    )
    .await;
}
