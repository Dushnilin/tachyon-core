//! Server inbounds (F5), end to end: our own client against our own server over
//! a real socket. No fixture stands in for either side.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

async fn spawn_echo() -> SocketAddr {
    spawn_echo_at("127.0.0.1:0").await
}

async fn spawn_echo_at(listen: &str) -> SocketAddr {
    let listener = TcpListener::bind(listen).await.expect("bind echo");
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

/// A UDP echo, so a datagram that comes back came back through the server
/// inbound rather than out of a buffer somewhere in the test.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
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

/// Reload must release a direct UDP listener even while its reverse session is alive.
#[tokio::test]
async fn direct_udp_reload_releases_port_with_a_live_session() {
    let _guard = test_guard().await;
    let echo = spawn_udp_echo().await;
    let mut config = json!({
        "log": {"disabled": true},
        "inbounds": [{"type":"direct", "tag":"test", "listen":"127.0.0.1",
            "listen_port":0, "network":"udp", "override_address":"127.0.0.1",
            "override_port":echo.port()}],
        "outbounds": [{"type":"direct", "tag":"direct"}],
        "route": {"final":"direct"}
    });
    let mut instance = core_runtime::start(&config)
        .await
        .expect("start direct UDP");
    let addr = inbound_addr(&instance, "test");
    config["inbounds"][0]["listen_port"] = json!(addr.port());
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let mut buf = [0u8; 64];
    for _ in 0..3 {
        client.send_to(b"active UDP", addr).await.expect("send");
        let (n, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("reply deadline")
        .expect("reply");
        assert_eq!(&buf[..n], b"active UDP");
        assert_eq!(peer, addr);
        instance.shutdown_wait().await;
        instance = core_runtime::start(&config)
            .await
            .expect("reload releases live UDP listener");
    }
    instance.shutdown_wait().await;
}

#[cfg(target_os = "linux")]
fn can_run_tproxy_test() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").expect("process capabilities");
    let capabilities = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("CapEff:\t")
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        })
        .expect("effective capabilities");
    // IP_TRANSPARENT accepts CAP_NET_ADMIN or CAP_NET_RAW on Linux.
    if capabilities & ((1 << 12) | (1 << 13)) != 0 {
        return true;
    }
    assert!(
        std::env::var_os("TACHYON_REQUIRE_NET_ADMIN").is_none(),
        "privileged TProxy regression gate requires CAP_NET_ADMIN or CAP_NET_RAW"
    );
    eprintln!("SKIP transparent UDP: requires CAP_NET_ADMIN or CAP_NET_RAW");
    false
}

/// A connected transparent reply socket receives subsequent client datagrams.
/// Repeated packets and shutdown must exercise the entire listener, not only
/// the first send from the shared socket. Requires Linux CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tproxy_udp_forwards_repeated_datagrams_and_releases_session_sockets() {
    if !can_run_tproxy_test() {
        return;
    }
    let _guard = test_guard().await;
    let echo = spawn_udp_echo().await;
    let config = json!({
        "log": {"disabled": true},
        "inbounds": [{"type": "tproxy", "tag": "test", "listen": "127.0.0.1",
            "listen_port": 0, "network": "udp"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": "test", "action": "route",
            "outbound": "direct", "override_port": echo.port()}]}
    });
    let mut instance = core_runtime::start(&config).await.expect("start tproxy");
    let addr = inbound_addr(&instance, "test");
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let mut buf = [0u8; 2048];
    for size in [20, 74, 1200, 74, 20] {
        let payload = vec![size as u8; size];
        client.send_to(&payload, addr).await.expect("send");
        let (n, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("reply in time")
        .expect("recv");
        assert_eq!(peer, addr);
        assert_eq!(&buf[..n], payload);
    }
    instance.shutdown_wait().await;
    let rebound = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(socket) = UdpSocket::bind(addr).await {
                break socket;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("transparent session socket released");
    drop(rebound);
}

/// Incoming media must keep the same UDP session and its client receive pump alive.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tproxy_receive_only_media_keeps_the_client_receive_pump_alive() {
    if !can_run_tproxy_test() {
        return;
    }
    let _guard = test_guard().await;
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("media server");
    let config = json!({
        "log": {"disabled": true},
        "inbounds": [{"type":"tproxy", "tag":"test", "listen":"127.0.0.1",
            "listen_port":0, "network":"udp", "udp_timeout":"100ms"}],
        "outbounds": [{"type":"direct", "tag":"direct"}],
        "route":{"rules":[{"inbound":"test", "action":"route", "outbound":"direct",
            "override_port":server.local_addr().expect("server addr").port()}]}
    });
    let mut instance = core_runtime::start(&config).await.expect("start tproxy");
    let addr = inbound_addr(&instance, "test");
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    client.send_to(b"start", addr).await.expect("first send");
    let mut buf = [0; 64];
    let (_, upstream) = server.recv_from(&mut buf).await.expect("first packet");
    // The server streams beyond several idle timeouts, then the client speaks.
    for sequence in 0..20u8 {
        server
            .send_to(&[sequence], upstream)
            .await
            .expect("media packet");
        let (n, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("media deadline")
        .expect("media receive");
        assert_eq!(peer, addr);
        assert_eq!(&buf[..n], &[sequence]);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    client
        .send_to(b"resume", addr)
        .await
        .expect("client resumes");
    let (n, resumed_peer) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server.recv_from(&mut buf),
    )
    .await
    .expect("receive pump survived active incoming media")
    .expect("resumed receive");
    assert_eq!(&buf[..n], b"resume");
    assert_eq!(
        resumed_peer, upstream,
        "active media flow changed its NAT session"
    );
    instance.shutdown_wait().await;
}

/// SOCKS5 UDP ASSOCIATE against the client's mixed inbound, and the socket to
/// send from plus the address to send to -- which is the relay the reply named
/// and not the destination inside the datagram. The control connection has to
/// stay open for the relay to live, so it goes to a task of its own.
async fn socks_udp_associate(socks: SocketAddr) -> (UdpSocket, SocketAddr) {
    let mut stream = TcpStream::connect(socks).await.expect("connect");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("greeting back");
    assert_eq!(greeting, [0x05, 0x00], "socks greeting");
    // UDP ASSOCIATE still carries an address: 0.0.0.0:0 asks the server to
    // pick one, which is what every client sends.
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .expect("associate reply");
    assert_eq!(reply[1], 0x00, "associate refused: {reply:?}");
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&reply[4..8]).expect("bnd addr"),
        )),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    tokio::spawn(async move {
        // hold the control connection open: the relay dies with it
        let mut sink = tokio::io::sink();
        let mut stream = stream;
        let _ = tokio::io::copy(&mut stream, &mut sink).await;
    });
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    (socket, relay)
}

/// A SOCKS5 UDP datagram header plus the payload.
fn socks_udp_request(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0x01];
    match dest.ip() {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
    out.extend_from_slice(&dest.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The same, aimed at a name instead of an address.
#[allow(dead_code)]
fn socks_udp_name_request(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0x03, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// What is left of a SOCKS5 UDP datagram once the header is off. The length is
/// checked rather than trusted: a server that framed the payload wrongly shows
/// up here as a short or long read instead of as nothing at all.
fn socks_udp_payload(datagram: &[u8]) -> Vec<u8> {
    assert!(datagram.len() > 4, "a socks udp reply with no address");
    let atyp = datagram[3];
    let at = match atyp {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => {
            let len = *datagram.get(4).expect("domain length") as usize;
            4 + 1 + len + 2
        }
        other => panic!("a socks udp reply with address type {other:#04x}"),
    };
    datagram
        .get(at..)
        .expect("a socks udp reply shorter than its header")
        .to_vec()
}

/// One datagram through a server inbound's UDP command: our client opens a SOCKS
/// UDP relay into it, and the echo behind the server answers. The client is told
/// to use the length-prefixed packet encoding, which is the one that puts
/// `[len:u16][payload]` on the wire -- the framing `vmess.Service`'s
/// `serverPacketConn` speaks.
async fn udp_round_trip(
    server_inbound: Value,
    client_outbound: Value,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let replies = udp_round_trips(server_inbound, client_outbound, &[payload], Some("")).await?;
    Ok(replies.into_iter().next().expect("one reply"))
}

async fn udp_round_trips(
    server_inbound: Value,
    client_outbound: Value,
    payloads: &[&[u8]],
    packet_encoding: Option<&str>,
) -> std::io::Result<Vec<Vec<u8>>> {
    let echo = spawn_udp_echo().await;
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
    if let Some(encoding) = packet_encoding {
        outbound.insert("packet_encoding".into(), json!(encoding));
    }
    let client = core_runtime::start(&json!({
        "log": {"level": "debug"},
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

    let (socket, relay) = socks_udp_associate(inbound_addr(&client, "mixed-in")).await;
    let mut replies = Vec::new();
    let mut buf = vec![0u8; 65535];
    for payload in payloads {
        // Send to the relay, so an answer cannot bypass the proxy under test.
        socket
            .send_to(&socks_udp_request(echo, payload), relay)
            .await?;
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP reply deadline")
            })??;
        replies.push(socks_udp_payload(&buf[..n]));
    }
    drop(client);
    drop(server);
    Ok(replies)
}

/// The default client uses VLESS command 3 (XUDP), including for Vision.
/// Exercise New and consecutive Keep frames through real client/server sockets.
#[tokio::test]
async fn a_vless_server_carries_default_xudp_repeated_datagrams() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let large = vec![0x5a; 1400];
    let payloads: &[&[u8]] = &[b"first", b"second", &large, b"after media"];
    for flow in ["", "xtls-rprx-vision"] {
        let got = udp_round_trips(
            vless_server(uuid, flow),
            vless_client(uuid, flow),
            payloads,
            None,
        )
        .await
        .expect("default XUDP round trips");
        assert_eq!(got, payloads);
    }
}

/// The UDP command on the three server inbounds that speak it: one datagram out
/// to a real echo and back, through the production code on both sides.
#[tokio::test]
async fn a_vless_server_carries_a_udp_datagram() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let got = udp_round_trip(
        vless_server(uuid, ""),
        vless_client(uuid, ""),
        b"a datagram",
    )
    .await
    .expect("vless udp round trip");
    assert_eq!(String::from_utf8_lossy(&got), "a datagram");
}

#[tokio::test]
async fn a_trojan_server_carries_a_udp_datagram() {
    let _guard = test_guard().await;
    // trojan is TLS-only in both directions, so the client's refusal to dial a
    // cleartext server is part of what makes this a real round trip.
    let mut server = json!({
        "type": "trojan",
        "tag": "trojan-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "users": [{"name": "bob", "password": "hunter2"}]
    });
    server["tls"] = server_tls();
    let mut client = json!({"type": "trojan", "tag": "out", "password": "hunter2"});
    client["tls"] = client_tls();
    let got = udp_round_trip(server, client, b"a datagram")
        .await
        .expect("trojan udp round trip");
    assert_eq!(String::from_utf8_lossy(&got), "a datagram");
}

#[tokio::test]
async fn a_vmess_server_carries_a_udp_datagram() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let got = udp_round_trip(vmess_server(uuid), vmess_client(uuid), b"a datagram")
        .await
        .expect("vmess udp round trip");
    assert_eq!(String::from_utf8_lossy(&got), "a datagram");
}

/// A datagram larger than a DNS reply, so the length prefix is exercised on a
/// value that is not a round dozen.
#[tokio::test]
async fn a_large_datagram_survives_the_length_prefix() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let payload: Vec<u8> = (0..1400u32).map(|i| (i % 251) as u8).collect();
    let got = udp_round_trip(vless_server(uuid, ""), vless_client(uuid, ""), &payload)
        .await
        .expect("vless udp round trip");
    assert_eq!(got, payload);
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

/// The hand-written vless client that used to live here wrote the address as
/// `[atyp][addr][port]`, which is how our own server read it -- so the two agreed
/// with each other and disagreed with every other vless client, and the test was
/// green throughout. The vless cases below use the real client instead.

#[tokio::test]
async fn vless_server_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let got = through_our_own_client(
        vless_server(uuid, ""),
        vless_client(uuid, ""),
        b"through-the-vless-server",
    )
    .await
    .expect("vless round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-the-vless-server");
}

#[tokio::test]
async fn vless_server_refuses_an_unknown_uuid() {
    let _guard = test_guard().await;
    let got = through_our_own_client(
        vless_server("b831381d-6324-4d53-ad4f-8cda48b30811", ""),
        vless_client("00000000-0000-4000-8000-000000000000", ""),
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
async fn vless_server_checks_the_flow_against_the_user() {
    let _guard = test_guard().await;
    // the user asks for vision, the client does not offer it
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let got = through_our_own_client(
        vless_server(uuid, "xtls-rprx-vision"),
        vless_client(uuid, ""),
        b"vision please",
    )
    .await
    .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a flow mismatch must not carry the payload: {got:?}"
    );
}

/// The server used to accept `xtls-rprx-vision` and then read the frames as
/// payload, so the client's first bytes came back as garbage or an EOF.
#[tokio::test]
async fn vless_server_speaks_vision_to_our_own_client() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let got = through_our_own_client(
        vless_server(uuid, "xtls-rprx-vision"),
        vless_client(uuid, "xtls-rprx-vision"),
        b"vision both ways",
    )
    .await
    .expect("vision round trip");
    assert_eq!(String::from_utf8_lossy(&got), "vision both ways");
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
    through_our_own_client_to(
        server_inbound,
        client_outbound,
        core_runtime::inbound::Target::Ip(echo),
        payload,
    )
    .await
}

async fn through_our_own_client_to(
    server_inbound: Value,
    client_outbound: Value,
    target: core_runtime::inbound::Target,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    use core_runtime::inbound::Target;

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
    let mut request = vec![0x05, 0x01, 0x00];
    match &target {
        Target::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
        },
        Target::Domain(host, _) => {
            request.extend_from_slice(&[3, u8::try_from(host.len()).expect("SOCKS domain length")]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
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

/// sing-box puts `zero` on a vmess outbound that sits on TLS: the body is the
/// bare stream, no frames. The server used to read it as chunks and wait for the
/// rest of a frame that was never coming.
#[tokio::test]
async fn vmess_server_carries_a_zero_security_body() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut client = vmess_client(uuid);
    client["security"] = json!("zero");
    let got = through_our_own_client(vmess_server(uuid), client, b"bare body")
        .await
        .expect("vmess zero round trip");
    assert_eq!(String::from_utf8_lossy(&got), "bare body");
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

fn vless_server(uuid: &str, flow: &str) -> Value {
    let mut user = json!({"name": "alice", "uuid": uuid});
    if !flow.is_empty() {
        user["flow"] = json!(flow);
    }
    json!({
        "type": "vless",
        "tag": "vless-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "users": [user]
    })
}

fn vless_client(uuid: &str, flow: &str) -> Value {
    let mut outbound = json!({"type": "vless", "tag": "out", "uuid": uuid});
    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }
    outbound
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

/// The test certificate, by path. `CARGO_MANIFEST_DIR` rather than a relative
/// one: the runtime reads these files itself, and the working directory of a
/// test binary is not something to rely on.
fn cert_file(name: &str) -> String {
    format!(
        "{}/../../tests/golden/certs/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// `tls` on a server inbound, the way a user writes it: the two files and
/// nothing else.
fn server_tls() -> Value {
    json!({
        "enabled": true,
        "certificate_path": cert_file("localhost.crt"),
        "key_path": cert_file("localhost.key"),
    })
}

/// The client side of the same handshake. No fingerprint is configured, so this
/// is rustls' client -- which is the point: the server half shares no code with
/// it, so a payload that comes back is a handshake that happened on the wire.
fn client_tls() -> Value {
    json!({"enabled": true, "server_name": "localhost", "insecure": true})
}

#[tokio::test]
async fn hysteria2_shutdown_releases_port_with_live_connections() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let mut config = cfg(
        json!({
            "type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1",
            "listen_port": 0, "password": "reload-test", "tls": {
                "enabled": true,
                "certificate": [include_str!("../../../tests/golden/certs/localhost.crt")],
                "key": [include_str!("../../../tests/golden/certs/localhost.key")]
            }
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    );
    let mut instance = core_runtime::start(&config).await.expect("start hy2");
    let addr = inbound_addr(&instance, "hy2");
    config["inbounds"][0]["listen_port"] = json!(addr.port());
    let client_config = json!({
        "type": "hysteria2", "server": "127.0.0.1", "server_port": addr.port(),
        "password": "reload-test", "tls": client_tls()
    });

    for _ in 0..3 {
        let client = core_runtime::outbound::hysteria2::Hysteria2::build(
            client_config.as_object().expect("client config"),
            "reload client",
        )
        .expect("build hy2 client");
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.connect(&core_runtime::inbound::Target::Ip(echo)),
        )
        .await
        .expect("connect timeout")
        .expect("connect hy2");
        stream.write_all(b"live").await.expect("write echo");
        let mut payload = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut payload),
        )
        .await
        .expect("echo timeout")
        .expect("read echo");
        assert_eq!(&payload, b"live");

        let udp = client
            .connect_udp(&core_runtime::inbound::Target::Ip(udp_echo))
            .await
            .expect("connect hy2 udp");
        udp.send(b"udp").await.expect("send udp");
        let mut datagram = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut datagram))
            .await
            .expect("udp timeout")
            .expect("receive udp");
        assert_eq!(&datagram[..n], b"udp");

        tokio::time::timeout(std::time::Duration::from_secs(10), instance.shutdown_wait())
            .await
            .expect("shutdown timeout");
        // Keep both the old client and its stream alive while rebinding: active
        // QUIC connections used to retain the server socket after task abort.
        instance = core_runtime::start(&config)
            .await
            .expect("rebind live hy2 port");
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut payload))
                .await
                .expect("old stream did not close");
        assert!(matches!(closed, Ok(0) | Err(_)), "old stream still live");
    }
    instance.shutdown_wait().await;
}

#[tokio::test]
async fn hysteria2_server_with_salamander_obfs_roundtrip() {
    let _guard = test_guard().await;
    let echo = spawn_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let config = cfg(
        json!({
            "type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1",
            "listen_port": 0, "password": "salamander-test", "tls": {
                "enabled": true,
                "certificate": [include_str!("../../../tests/golden/certs/localhost.crt")],
                "key": [include_str!("../../../tests/golden/certs/localhost.key")]
            },
            "obfs": {
                "type": "salamander",
                "password": "obfs-secret-password"
            }
        }),
        json!([{"type": "direct", "tag": "direct"}]),
    );
    let mut instance = core_runtime::start(&config)
        .await
        .expect("start hy2 with obfs");
    let addr = inbound_addr(&instance, "hy2");
    let client_config = json!({
        "type": "hysteria2", "server": "127.0.0.1", "server_port": addr.port(),
        "password": "salamander-test", "tls": client_tls(),
        "obfs": {
            "type": "salamander",
            "password": "obfs-secret-password"
        }
    });

    let client = core_runtime::outbound::hysteria2::Hysteria2::build(
        client_config.as_object().expect("client config"),
        "obfs client",
    )
    .expect("build hy2 client");

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.connect(&core_runtime::inbound::Target::Ip(echo)),
    )
    .await
    .expect("connect timeout")
    .expect("connect hy2");
    stream.write_all(b"live-obfs").await.expect("write echo");
    let mut payload = [0u8; 9];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_exact(&mut payload),
    )
    .await
    .expect("echo timeout")
    .expect("read echo");
    assert_eq!(&payload, b"live-obfs");

    let udp = client
        .connect_udp(&core_runtime::inbound::Target::Ip(udp_echo))
        .await
        .expect("connect hy2 udp");
    udp.send(b"udp-obfs").await.expect("send udp");
    let mut datagram = [0u8; 16];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut datagram))
        .await
        .expect("udp timeout")
        .expect("receive udp");
    assert_eq!(&datagram[..n], b"udp-obfs");

    instance.shutdown_wait().await;
}

#[tokio::test]
async fn vless_server_over_tls_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["tls"] = server_tls();
    let mut client = vless_client(uuid, "");
    client["tls"] = client_tls();
    let got = through_our_own_client(server, client, b"through-tls")
        .await
        .expect("vless over tls round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-tls");
}

/// gRPC is the h2 POST stream, plain TCP: prior knowledge, no upgrade.
#[tokio::test]
async fn vless_server_over_grpc_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "grpc", "service_name": "bench"});
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "grpc", "service_name": "bench"});
    let got = through_our_own_client(server, client, b"through-grpc")
        .await
        .expect("vless over grpc round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-grpc");
}

/// The same over TLS, which is where the ALPN matters: the server has to
/// offer and pick `h2`, or the client's h2 handshake never starts.
#[tokio::test]
async fn vless_server_over_grpc_and_tls_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "grpc", "service_name": "bench"});
    server["tls"] = server_tls();
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "grpc", "service_name": "bench"});
    client["tls"] = client_tls();
    let got = through_our_own_client(server, client, b"through-grpc-tls")
        .await
        .expect("vless over grpc and tls round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-grpc-tls");
}

/// The service name is part of the path the server compares: a client asking
/// for another one gets the reference's 404 and no tunnel at all.
#[tokio::test]
async fn a_grpc_server_refuses_a_client_with_another_service_name() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "grpc", "service_name": "bench"});
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "grpc", "service_name": "other"});
    let got = through_our_own_client(server, client, b"nope")
        .await
        .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a refused grpc stream must not carry the payload: {got:?}"
    );
}

/// XHTTP is several connections stitched into one stream: a download GET and
/// the sequenced upload POSTs. The default mode is packet-up, which is what
/// `auto` resolves to.
#[tokio::test]
async fn vless_server_over_xhttp_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let got = through_our_own_client(server, client, b"through-xhttp")
        .await
        .expect("vless over xhttp round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-xhttp");
}

/// The same over TLS, where the ALPN matters the other way round from gRPC:
/// the listener has to offer `http/1.1` or the two negotiate nothing.
#[tokio::test]
async fn vless_server_over_xhttp_and_tls_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    server["tls"] = server_tls();
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/bench"});
    client["tls"] = client_tls();
    let got = through_our_own_client(server, client, b"through-xhttp-tls")
        .await
        .expect("vless over xhttp and tls round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-xhttp-tls");
}

/// stream-one: the whole session on one bidirectional POST to the bare path.
#[tokio::test]
async fn vless_server_over_xhttp_stream_one_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/bench", "mode": "stream-one"});
    let got = through_our_own_client(server, client, b"through-stream-one")
        .await
        .expect("vless over xhttp stream-one round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-stream-one");
}

/// stream-up: one streamed POST for the upload direction plus the download
/// GET. The download goes out first here, but the server is built so that
/// the other order -- the upload arriving on its own connection before the
/// GET -- births the session just the same.
#[tokio::test]
async fn vless_server_over_xhttp_stream_up_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/bench", "mode": "stream-up"});
    let got = through_our_own_client(server, client, b"through-stream-up")
        .await
        .expect("vless over xhttp stream-up round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-stream-up");
}

/// The path is the first thing the server compares: another one is a 404 and
/// no tunnel at all.
#[tokio::test]
async fn a_xhttp_server_refuses_another_path() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/other"});
    let got = through_our_own_client(server, client, b"nope")
        .await
        .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a refused xhttp session must not carry the payload: {got:?}"
    );
}

#[tokio::test]
async fn vless_server_over_xhttp_h2_stream_one_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let mut s_tls = server_tls();
    s_tls["alpn"] = json!(["h2"]);
    server["tls"] = s_tls;

    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/bench", "mode": "stream-one"});
    let mut c_tls = client_tls();
    c_tls["alpn"] = json!(["h2"]);
    client["tls"] = c_tls;

    let got = through_our_own_client(server, client, b"through-h2-stream-one")
        .await
        .expect("vless over xhttp h2 stream-one round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-h2-stream-one");
}

#[tokio::test]
async fn vless_server_over_xhttp_h2_packet_up_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["transport"] = json!({"type": "xhttp", "path": "/bench"});
    let mut s_tls = server_tls();
    s_tls["alpn"] = json!(["h2"]);
    server["tls"] = s_tls;

    let mut client = vless_client(uuid, "");
    client["transport"] = json!({"type": "xhttp", "path": "/bench", "mode": "packet-up"});
    let mut c_tls = client_tls();
    c_tls["alpn"] = json!(["h2"]);
    client["tls"] = c_tls;

    let got = through_our_own_client(server, client, b"through-h2-packet-up")
        .await
        .expect("vless over xhttp h2 packet-up round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-h2-packet-up");
}

#[tokio::test]
async fn trojan_server_over_tls_carries_domain_and_ipv6_targets() {
    use core_runtime::inbound::Target;

    let _guard = test_guard().await;
    let ipv4 = spawn_echo().await;
    let ipv6 = spawn_echo_at("[::1]:0").await;
    // Encode a numeric hostname as a domain to avoid external DNS dependencies.
    for target in [
        Target::Domain("127.0.0.1".into(), ipv4.port()),
        Target::Ip(ipv6),
    ] {
        let mut server = json!({
            "type": "trojan", "tag": "trojan-in", "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": [{"name": "bob", "password": "hunter2"}]
        });
        server["tls"] = server_tls();
        let mut client = json!({"type": "trojan", "tag": "out", "password": "hunter2"});
        client["tls"] = client_tls();
        let got =
            through_our_own_client_to(server, client, target.clone(), b"trojan-address-over-tls")
                .await
                .unwrap_or_else(|e| panic!("{target:?}: {e}"));
        assert_eq!(got, b"trojan-address-over-tls", "{target:?}");
    }
}

#[tokio::test]
async fn trojan_server_over_tls_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let mut server = json!({
        "type": "trojan",
        "tag": "trojan-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "users": [{"name": "bob", "password": "hunter2"}]
    });
    server["tls"] = server_tls();
    let mut client = json!({"type": "trojan", "tag": "out", "password": "hunter2"});
    client["tls"] = client_tls();
    let got = through_our_own_client(server, client, b"through-tls")
        .await
        .expect("trojan over tls round trip");
    // trojan writes no answer head, so this is exactly the echo
    assert_eq!(String::from_utf8_lossy(&got), "through-tls");
}

#[tokio::test]
async fn vmess_server_over_tls_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vmess_server(uuid);
    server["tls"] = server_tls();
    let mut client = vmess_client(uuid);
    client["tls"] = client_tls();
    let got = through_our_own_client(server, client, b"through-tls")
        .await
        .expect("vmess over tls round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-tls");
}

#[tokio::test]
async fn shadowsocks_server_over_tls_carries_our_own_client_traffic() {
    let _guard = test_guard().await;
    let mut server = ss_server("aes-128-gcm", "hunter2");
    server["tls"] = server_tls();
    let mut client = ss_client("aes-128-gcm", "hunter2");
    client["tls"] = client_tls();
    let got = through_our_own_client(server, client, b"through-tls")
        .await
        .expect("shadowsocks over tls round trip");
    assert_eq!(String::from_utf8_lossy(&got), "through-tls");
}

/// A plaintext client against a TLS server gets nothing back. Without this the
/// first three tests could pass for the wrong reason -- a server that answered
/// every connection regardless of what was on it would satisfy them too.
#[tokio::test]
async fn a_vless_server_over_tls_answers_a_plaintext_client_with_nothing() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["tls"] = server_tls();
    let got = through_our_own_client(server, vless_client(uuid, ""), b"nope")
        .await
        .unwrap_or_default();
    assert!(
        got.is_empty(),
        "a plaintext client must not be served: {got:?}"
    );
}

/// `enabled: false` is a block that is off, not a broken one -- the server comes
/// up in the clear, and a client with no `tls` is served.
#[tokio::test]
async fn a_disabled_inbound_tls_block_starts_in_the_clear() {
    let _guard = test_guard().await;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let mut server = vless_server(uuid, "");
    server["tls"] = json!({"enabled": false});
    let got = through_our_own_client(server, vless_client(uuid, ""), b"in-the-clear")
        .await
        .expect("a disabled tls block is not tls");
    assert_eq!(String::from_utf8_lossy(&got), "in-the-clear");
}

/// What the reference answers `insecure` without a certificate with is a
/// throwaway key pair it builds itself. We cannot sign one yet, so the server
/// says so by name instead of coming up with nothing to answer with.
#[tokio::test]
async fn an_inbound_tls_without_a_certificate_does_not_start() {
    let _guard = test_guard().await;
    for tls in [
        json!({"enabled": true}),
        json!({"enabled": true, "insecure": true}),
        json!({"enabled": true, "acme": {"domain": "example.com"}}),
        json!({"enabled": true, "certificate_path": cert_file("absent.crt")}),
    ] {
        let mut server = vless_server("b831381d-6324-4d53-ad4f-8cda48b30811", "");
        server["tls"] = tls.clone();
        let err = core_runtime::start(&cfg(server, json!([{"type": "direct", "tag": "direct"}])))
            .await
            .err()
            .unwrap_or_else(|| panic!("{tls} should not start"));
        let chain = format!("{err:#}");
        assert!(chain.contains("tls:"), "{tls}: {chain}");
    }
}
