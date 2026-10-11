use core_runtime::inbound::Target;
use core_runtime::route::{ConnContext, Decision, Router};
use serde_json::{Value, json};

// Published client Initial vectors: RFC 9001 A.2 and RFC 9369 A.2.
fn packets() -> [Vec<u8>; 2] {
    [
        include_str!("data/quic-initial-rfc9001.hex"),
        include_str!("data/quic-initial-rfc9369.hex"),
    ]
    .map(|hex| {
        hex.trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    })
}

fn context() -> ConnContext {
    ConnContext::new(
        "in",
        "127.0.0.1:30000".parse().unwrap(),
        Target::Ip("127.0.0.1:443".parse().unwrap()),
        "udp",
    )
}

fn router(sniff: Value, reject: bool) -> std::sync::Arc<Router> {
    let mut rules = vec![sniff];
    if reject {
        rules.push(json!({"protocol":"quic","action":"reject"}));
    }
    Router::new(&json!({"outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"rules":rules,"final":"direct"}}))
    .unwrap()
}

#[tokio::test]
async fn authenticated_v1_v2_initials_match_quic_rejection() {
    let router = router(json!({"action":"sniff"}), true);
    for packet in packets() {
        let original = packet.clone();
        let mut ctx = context();
        assert!(router.route_packet(&mut ctx, &packet).await.is_err());
        assert_eq!(ctx.protocol.as_deref(), Some("quic"));
        assert_eq!(packet, original);
        assert!(ctx.sniff_prefix.is_empty());
    }
}

#[tokio::test]
async fn configured_quic_and_inbound_scope_are_respected() {
    let packet = &packets()[0];
    for sniff in [
        json!({"action":"sniff","sniffer":["dns"]}),
        json!({"action":"sniff","sniffer":["tls"]}),
        json!({"action":"sniff","inbound":"other"}),
    ] {
        let router = router(sniff, true);
        let mut ctx = context();
        assert!(matches!(
            router.route_packet(&mut ctx, packet).await.unwrap(),
            Decision::Outbound(_)
        ));
        assert!(ctx.protocol.is_none());
    }
    let router = router(json!({"action":"sniff","sniffer":["quic"]}), false);
    let mut ctx = context();
    assert!(matches!(
        router.route_packet(&mut ctx, packet).await.unwrap(),
        Decision::Outbound(_)
    ));
    assert_eq!(ctx.protocol.as_deref(), Some("quic"));
    ctx.protocol = Some("existing".into());
    router.route_packet(&mut ctx, packet).await.unwrap();
    assert_eq!(ctx.protocol.as_deref(), Some("existing"));
}

#[tokio::test]
async fn invalid_initials_and_arbitrary_udp_are_not_quic() {
    let router = router(json!({"action":"sniff"}), true);
    let packet = &packets()[0];
    for len in 0..packet.len() {
        let mut ctx = context();
        assert!(matches!(
            router.route_packet(&mut ctx, &packet[..len]).await.unwrap(),
            Decision::Outbound(_)
        ));
        assert!(ctx.protocol.is_none());
    }
    let mut bad_tag = packet.clone();
    *bad_tag.last_mut().unwrap() ^= 1;
    let mut bad_cid = packet.clone();
    bad_cid[5] = 255;
    let mut bad_length = packet.clone();
    bad_length[16] = 0xff;
    let mut unknown_version = packet.clone();
    unknown_version[4] = 99;
    let mut short_header = packet.clone();
    short_header[0] = 0x40;
    for packet in [
        bad_tag,
        bad_cid,
        bad_length,
        unknown_version,
        short_header,
        vec![0xc0; 1200],
        b"ordinary UDP".to_vec(),
    ] {
        let mut ctx = context();
        assert!(matches!(
            router.route_packet(&mut ctx, &packet).await.unwrap(),
            Decision::Outbound(_)
        ));
        assert!(ctx.protocol.is_none());
    }
}
