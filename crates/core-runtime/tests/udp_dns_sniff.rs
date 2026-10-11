use core_runtime::dns::codec::build_query;
use core_runtime::inbound::Target;
use core_runtime::route::{ConnContext, Decision, Router};
use hickory_proto::rr::RecordType;
use serde_json::{Value, json};

fn context() -> ConnContext {
    ConnContext::new(
        "source-dns-in",
        "127.0.0.1:30000".parse().unwrap(),
        Target::Ip("127.0.0.1:1603".parse().unwrap()),
        "udp",
    )
}

fn router(sniff: Option<Value>) -> std::sync::Arc<Router> {
    let mut rules = Vec::new();
    if let Some(rule) = sniff {
        rules.push(rule);
    }
    rules.push(json!({"protocol":"dns", "action":"hijack-dns"}));
    Router::new(&json!({
        "outbounds":[{"type":"direct", "tag":"direct"}],
        "route":{"rules":rules,"final":"direct"}
    }))
    .unwrap()
}

#[tokio::test]
async fn dns_on_nonstandard_port_is_hijacked_after_sniff() {
    let router = router(Some(json!({"action":"sniff", "inbound":"source-dns-in"})));
    let query = build_query(123, "example.com", RecordType::A).unwrap();
    let original = query.clone();
    let mut ctx = context();
    assert!(matches!(
        router.route_packet(&mut ctx, &query).await.unwrap(),
        Decision::HijackDns
    ));
    assert_eq!(ctx.protocol.as_deref(), Some("dns"));
    assert_eq!(query, original);
    assert!(ctx.sniff_prefix.is_empty());
}

#[tokio::test]
async fn packet_sniff_respects_action_scope_and_configured_sniffers() {
    let query = build_query(123, "example.com", RecordType::A).unwrap();
    for sniff in [
        None,
        Some(json!({"action":"sniff", "inbound":"other"})),
        Some(json!({"action":"sniff", "sniffer":["tls"]})),
    ] {
        let router = router(sniff);
        let mut ctx = context();
        assert!(matches!(
            router.route_packet(&mut ctx, &query).await.unwrap(),
            Decision::Outbound(_)
        ));
        assert!(ctx.protocol.is_none());
    }
    let router = router(Some(json!({"action":"sniff", "sniffer":["dns"]})));
    assert!(matches!(
        router.route_packet(&mut context(), &query).await.unwrap(),
        Decision::HijackDns
    ));
}

#[tokio::test]
async fn malformed_or_non_dns_datagrams_keep_the_original_route() {
    let router = router(Some(json!({"action":"sniff"})));
    let query = build_query(123, "example.com", RecordType::A).unwrap();
    for packet in [
        &[][..],
        b"ordinary UDP payload",
        &query[..11],
        &query[..query.len() - 1],
    ] {
        let mut ctx = context();
        assert!(matches!(
            router.route_packet(&mut ctx, packet).await.unwrap(),
            Decision::Outbound(_)
        ));
        assert!(ctx.protocol.is_none());
    }
}
