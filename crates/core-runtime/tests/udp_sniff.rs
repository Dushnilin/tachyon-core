//! Packet sniffing on UDP flows: the `sniff` action looks at the datagrams
//! (dns, quic, stun, bittorrent, dtls, ntp) and leaves them untouched, and the
//! hub holds a flow whose QUIC ClientHello spans more than one datagram.

use std::net::SocketAddr;
use std::time::Duration;

use core_runtime::dns::codec::{self, build_query};
use core_runtime::inbound::Target;
use core_runtime::route::{ConnContext, Decision, Router};
use core_tls::rustls::Side;
use core_tls::rustls::quic::{Suite, Version};
use hickory_proto::rr::RecordType;
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Serialize box instances: the dns service is process-global.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

fn hex(text: &str) -> Vec<u8> {
    let text = text.trim().as_bytes();
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(std::str::from_utf8(&text[2 * i..2 * i + 2]).unwrap(), 16).unwrap()
        })
        .collect()
}

/// Published client Initials: RFC 9001 A.2 (v1) and RFC 9369 A.2 (v2), both
/// a ClientHello for example.com.
fn rfc_initials() -> [Vec<u8>; 2] {
    [
        hex(include_str!("data/quic-initial-rfc9001.hex")),
        hex(include_str!("data/quic-initial-rfc9369.hex")),
    ]
}

fn context(inbound: &str, port: u16) -> ConnContext {
    ConnContext::new(
        inbound,
        "127.0.0.1:30000".parse().unwrap(),
        Target::Ip(SocketAddr::from(([127, 0, 0, 1], port))),
        "udp",
    )
}

fn router(rules: Value) -> std::sync::Arc<Router> {
    Router::new(&json!({
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct"}
    }))
    .unwrap()
}

async fn sniffed(router: &Router, packet: &[u8]) -> (Decision, Option<String>, Option<String>) {
    let mut ctx = context("in", 4000);
    let decision = router.route_packet(&mut ctx, &[packet]).await.unwrap();
    (decision, ctx.protocol, ctx.domain)
}

#[tokio::test]
async fn dns_on_a_nonstandard_port_is_hijacked_after_sniff() {
    let router = router(json!([
        {"action": "sniff", "inbound": "in"},
        {"protocol": "dns", "action": "hijack-dns"}
    ]));
    let query = build_query(123, "example.com", RecordType::A).unwrap();
    let original = query.clone();
    let mut ctx = context("in", 1603);
    assert!(matches!(
        router.route_packet(&mut ctx, &[&query]).await.unwrap(),
        Decision::HijackDns
    ));
    assert_eq!(ctx.protocol.as_deref(), Some("dns"));
    assert_eq!(query, original);
    assert!(ctx.sniff_prefix.is_empty());
}

#[tokio::test]
async fn rfc_initials_give_quic_and_the_sni() {
    let router = router(json!([
        {"action": "sniff"},
        {"domain": "example.com", "action": "reject"}
    ]));
    for packet in rfc_initials() {
        let original = packet.clone();
        let mut ctx = context("in", 443);
        assert!(router.route_packet(&mut ctx, &[&packet]).await.is_err());
        assert_eq!(ctx.protocol.as_deref(), Some("quic"));
        assert_eq!(ctx.domain.as_deref(), Some("example.com"));
        assert_eq!(packet, original);
    }
}

#[tokio::test]
async fn scope_and_sniffer_list_are_respected() {
    let quic = &rfc_initials()[0];
    let query = build_query(1, "example.com", RecordType::A).unwrap();
    for sniff in [
        json!({"action": "sniff", "sniffer": ["dns"]}),
        json!({"action": "sniff", "sniffer": ["tls"]}),
        json!({"action": "sniff", "inbound": "other"}),
    ] {
        let router = router(json!([sniff]));
        let (_, protocol, _) = sniffed(&router, quic).await;
        assert_eq!(protocol, None);
    }
    let only_quic = router(json!([{"action": "sniff", "sniffer": ["quic"]}]));
    assert_eq!(sniffed(&only_quic, quic).await.1.as_deref(), Some("quic"));
    assert_eq!(sniffed(&only_quic, &query).await.1, None);

    // a protocol another sniff already found is kept
    let mut ctx = context("in", 443);
    ctx.protocol = Some("existing".into());
    only_quic.route_packet(&mut ctx, &[quic]).await.unwrap();
    assert_eq!(ctx.protocol.as_deref(), Some("existing"));
}

fn stun() -> Vec<u8> {
    let mut p = vec![0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42];
    p.extend_from_slice(&[7; 12]); // transaction id
    p.extend_from_slice(&[0x80, 0x22, 0x00, 0x04, b't', b'e', b's', b't']);
    p
}

fn utp() -> Vec<u8> {
    // ST_SYN, version 1, one selective-ack extension of 4 bytes
    let mut p = vec![0x41, 0x01];
    p.extend_from_slice(&[0; 18]);
    p.extend_from_slice(&[0x00, 0x04, 0, 0, 0, 0]);
    p
}

fn udp_tracker() -> Vec<u8> {
    let mut p = 0x0417_2710_1980u64.to_be_bytes().to_vec();
    p.extend_from_slice(&[0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
    p
}

fn dtls() -> Vec<u8> {
    let mut p = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    p.push(1); // ClientHello
    p
}

fn ntp() -> Vec<u8> {
    let mut p = vec![0x23]; // LI 0, version 4, mode 3
    p.resize(48, 0);
    p
}

#[tokio::test]
async fn every_packet_sniffer_names_its_protocol() {
    let router = router(json!([{"action": "sniff"}]));
    let query = build_query(7, "example.com", RecordType::AAAA).unwrap();
    for (packet, want) in [
        (query, "dns"),
        (rfc_initials()[1].clone(), "quic"),
        (stun(), "stun"),
        (utp(), "bittorrent"),
        (udp_tracker(), "bittorrent"),
        (dtls(), "dtls"),
        (ntp(), "ntp"),
    ] {
        let original = packet.clone();
        let (decision, protocol, _) = sniffed(&router, &packet).await;
        assert!(matches!(decision, Decision::Outbound(_)));
        assert_eq!(protocol.as_deref(), Some(want), "{want}");
        assert_eq!(packet, original);
    }
}

#[tokio::test]
async fn near_misses_are_left_alone() {
    let router = router(json!([{"action": "sniff"}]));
    let mut late_ntp = ntp();
    late_ntp[4] = 0x7f; // root delay far past 16 s
    let mut server_ntp = ntp();
    server_ntp[0] = 0x24; // mode 4 is the answer, not the request
    let mut stun_no_cookie = stun();
    stun_no_cookie[4] = 0;
    let mut stun_short_body = stun();
    stun_short_body[3] = 0x40;
    let mut utp_v2 = utp();
    utp_v2[0] = 0x42;
    let mut utp_broken_chain = utp();
    utp_broken_chain[20] = 0x01; // claims another extension, then ends
    let mut dtls_13 = dtls();
    dtls_13[2] = 0xfc;
    let mut tracker_announce = udp_tracker();
    tracker_announce[11] = 1;
    let quic = &rfc_initials()[0];
    let mut bad_tag = quic.clone();
    *bad_tag.last_mut().unwrap() ^= 1;
    let mut unknown_version = quic.clone();
    unknown_version[4] = 99;
    let mut short_header = quic.clone();
    short_header[0] = 0x40;
    for packet in [
        late_ntp,
        server_ntp,
        stun_no_cookie,
        stun_short_body,
        utp_v2,
        utp_broken_chain,
        dtls_13,
        tracker_announce,
        bad_tag,
        unknown_version,
        short_header,
        vec![0xc0; 1200],
        b"ordinary UDP payload".to_vec(),
        Vec::new(),
    ] {
        let (_, protocol, _) = sniffed(&router, &packet).await;
        assert_eq!(protocol, None, "{packet:02x?}");
    }
}

#[tokio::test]
async fn no_truncation_of_a_real_packet_panics() {
    let router = router(json!([{"action": "sniff"}]));
    let query = build_query(9, "example.com", RecordType::A).unwrap();
    for packet in [rfc_initials()[0].clone(), query, stun(), utp(), ntp()] {
        for len in 0..packet.len() {
            let mut ctx = context("in", 4000);
            router
                .route_packet(&mut ctx, &[&packet[..len]])
                .await
                .unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Through a real UDP inbound
// ---------------------------------------------------------------------------

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

async fn spawn_udp_dns(answer: std::net::Ipv4Addr) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp dns");
    let addr = sock.local_addr().expect("udp dns addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = hickory_proto::op::Message::from_vec(&buf[..n]) else {
                continue;
            };
            let resp = codec::synth_address(&query, answer.into(), 60).expect("answer");
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
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

async fn recv(client: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let (n, from) = tokio::time::timeout(wait, client.recv_from(&mut buf))
        .await
        .ok()?
        .expect("udp recv");
    assert!(from.ip().is_loopback(), "reply from {from}");
    buf.truncate(n);
    Some(buf)
}

/// The query goes to a direct inbound that forwards to an echo server, so
/// without the sniff it would come back as itself, unanswered.
#[tokio::test]
async fn a_dns_query_to_any_port_is_answered_once_sniffed() {
    let _g = test_guard().await;
    let echo = spawn_udp_echo().await;
    let mock = spawn_udp_dns(std::net::Ipv4Addr::new(9, 9, 9, 9)).await;
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [{"type": "udp", "tag": "u", "server": "127.0.0.1", "server_port": mock.port()}],
            "final": "u"
        },
        "inbounds": [{
            "type": "direct", "tag": "udp-in",
            "listen": "127.0.0.1", "listen_port": 0, "network": "udp",
            "override_address": "127.0.0.1", "override_port": echo.port()
        }],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"}
            ],
            "final": "out"
        }
    }))
    .await
    .expect("start box");
    let addr = inbound_addr(&instance, "udp-in");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let query = build_query(0x5151, "sniffed.test", RecordType::A).unwrap();
    client.send_to(&query, addr).await.expect("send query");
    let answer = recv(&client, Duration::from_secs(2))
        .await
        .expect("dns reply");
    let ips = codec::answer_ips(&answer).expect("parse answer");
    assert_eq!(ips, [std::net::IpAddr::from([9, 9, 9, 9])]);

    // anything else on the same inbound still goes to the echo
    let other = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    other.send_to(b"plain", addr).await.expect("send");
    assert_eq!(
        recv(&other, Duration::from_secs(2)).await.as_deref(),
        Some(&b"plain"[..])
    );
    instance.shutdown();
}

fn suite() -> Suite {
    core_tls::quic::initial_suite_from_provider(&core_tls::quic::configured_provider())
        .expect("initial suite")
}

fn put_varint(out: &mut Vec<u8>, v: usize) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        _ => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
    }
}

/// A ClientHello for `sni`, padded to the size a post-quantum key share
/// gives Chrome's: too big for one Initial.
fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut ext = vec![0x00, 0x00];
    ext.extend_from_slice(&(name.len() as u16 + 5).to_be_bytes());
    ext.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name);
    ext.extend_from_slice(&[0x00, 0x15, 0x06, 0x00]);
    ext.resize(ext.len() + 0x600, 0);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut msg = vec![0x01];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// One padded v1 client Initial carrying a CRYPTO frame at `offset`.
fn initial(suite: &Suite, dcid: &[u8], pn: u32, offset: usize, data: &[u8]) -> Vec<u8> {
    let keys = suite.keys(dcid, Side::Client, Version::V1);
    let mut payload = vec![0x06];
    put_varint(&mut payload, offset);
    put_varint(&mut payload, data.len());
    payload.extend_from_slice(data);
    let mut header = vec![0xc3];
    header.extend_from_slice(&1u32.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.extend_from_slice(&[0, 0]);
    let fixed = header.len() + 2 + 4 + 16;
    payload.resize(payload.len().max(1200 - fixed), 0);
    header.extend_from_slice(&((4 + payload.len() + 16) as u16 | 0x4000).to_be_bytes());
    let pn_at = header.len();
    header.extend_from_slice(&pn.to_be_bytes());
    let tag = keys
        .local
        .packet
        .encrypt_in_place(u64::from(pn), &header, &mut payload)
        .unwrap();
    let mut packet = header;
    packet.extend_from_slice(&payload);
    packet.extend_from_slice(tag.as_ref());
    let sample = packet[pn_at + 4..pn_at + 4 + keys.local.header.sample_len()].to_vec();
    let (first, rest) = packet.split_at_mut(1);
    keys.local
        .header
        .encrypt_in_place(&sample, &mut first[0], &mut rest[pn_at - 1..pn_at + 3])
        .unwrap();
    packet
}

fn split_hello(suite: &Suite, dcid: &[u8], sni: &str) -> [Vec<u8>; 2] {
    let hello = client_hello(sni);
    let half = hello.len() / 2;
    [
        initial(suite, dcid, 0, 0, &hello[..half]),
        initial(suite, dcid, 1, half, &hello[half..]),
    ]
}

/// A hello that needs two datagrams: the flow is held until the second one
/// names the server, then both go out in order. When the second never comes
/// the first goes out anyway once the sniff timeout is over.
#[tokio::test]
async fn a_split_quic_hello_is_routed_by_its_sni() {
    let _g = test_guard().await;
    let echo = spawn_udp_echo().await;
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "direct", "tag": "quic-in",
            "listen": "127.0.0.1", "listen_port": 0, "network": "udp",
            "override_address": "127.0.0.1", "override_port": echo.port()
        }],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {
            "rules": [
                {"action": "sniff", "timeout": "200ms"},
                {"domain": "blocked.example", "action": "reject"}
            ],
            "final": "out"
        }
    }))
    .await
    .expect("start box");
    let addr = inbound_addr(&instance, "quic-in");
    let suite = suite();

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let [one, two] = split_hello(&suite, &[0x11; 8], "allowed.example");
    client.send_to(&one, addr).await.expect("send");
    client.send_to(&two, addr).await.expect("send");
    assert_eq!(recv(&client, Duration::from_secs(2)).await, Some(one));
    assert_eq!(recv(&client, Duration::from_secs(2)).await, Some(two));

    let blocked = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let [one, two] = split_hello(&suite, &[0x22; 8], "blocked.example");
    blocked.send_to(&one, addr).await.expect("send");
    blocked.send_to(&two, addr).await.expect("send");
    assert_eq!(recv(&blocked, Duration::from_millis(600)).await, None);

    let stalled = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let [one, _] = split_hello(&suite, &[0x33; 8], "blocked.example");
    stalled.send_to(&one, addr).await.expect("send");
    assert_eq!(recv(&stalled, Duration::from_secs(2)).await, Some(one));
    instance.shutdown();
}
