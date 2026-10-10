//! `route.find_neighbor`: a client is routed by the name its DHCP lease gives
//! it and by its MAC, and a `local` DNS server answers `<host>.lan` out of the
//! same tables — the feature a router exists for.

use std::net::{IpAddr, SocketAddr};

use core_runtime::dns::{DnsService, QueryMeta};
use core_runtime::route::neighbor;
use core_runtime::route::{ConnContext, Decision, Router};
use serde_json::json;

const LEASES: &str = "\
# a comment, the way odhcpd writes its own leases
1900000000 aa:bb:cc:dd:ee:01 192.168.7.10 tv 01:aa:bb:cc:dd:ee:01
1900000000 aa:bb:cc:dd:ee:02 192.168.7.11 laptop 01:aa:bb:cc:dd:ee:02
1900000000 aa:bb:cc:dd:ee:03 192.168.7.12 * 01:aa:bb:cc:dd:ee:03
";

/// A lease file of our own, so the test never reads the host's real one.
fn lease_file(name: &str) -> String {
    let path = std::env::temp_dir().join(format!("tachyon-neighbor-{name}.leases"));
    std::fs::write(&path, LEASES).expect("write leases");
    path.to_string_lossy().into_owned()
}

fn ip(raw: &str) -> IpAddr {
    raw.parse().expect("ip")
}

/// A router with the two rules a router would actually write: route the device
/// that calls itself `tv`, and the one with that MAC.
fn router(leases: &str) -> std::sync::Arc<Router> {
    Router::new(&json!({
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "proxy"}
        ],
        "route": {
            "final": "direct",
            "rules": [
                {"source_hostname": ["tv"], "action": "route", "outbound": "proxy"},
                {"source_mac_address": ["aa:bb:cc:dd:ee:02"], "action": "route", "outbound": "proxy"}
            ],
            "dhcp_lease_files": [leases]
        }
    }))
    .expect("router")
}

/// A connection as the inbound would hand it over: `source` is the client.
fn context(source: &str) -> ConnContext {
    ConnContext::new(
        "in",
        SocketAddr::new(ip(source), 40000),
        core_runtime::inbound::Target::Domain("example.com".into(), 443),
        "tcp",
    )
}

async fn routed_tag(router: &Router, source: &str) -> String {
    let mut ctx = context(source);
    let Decision::Outbound(index) = router.route_raw(&mut ctx).await.expect("route") else {
        panic!("an outbound decision");
    };
    router
        .inner()
        .outbound_table()
        .find(|(candidate, _, _)| *candidate == index)
        .map(|(_, tag, _)| tag.to_string())
        .expect("a tag")
}

#[tokio::test]
async fn a_lease_name_and_a_mac_both_pick_the_outbound() {
    let router = router(&lease_file("rules"));
    // the rule set asked for the tables, so the resolver is running
    let resolver = neighbor::current().expect("the resolver the rules asked for");
    assert_eq!(
        resolver.lookup_hostname(ip("192.168.7.10")).as_deref(),
        Some("tv")
    );

    assert_eq!(routed_tag(&router, "192.168.7.10").await, "proxy");
    assert_eq!(routed_tag(&router, "192.168.7.11").await, "proxy");
    // a lease with `*` has no name, and the rule only knows `tv`
    assert_eq!(routed_tag(&router, "192.168.7.12").await, "direct");
    // a client the tables have never seen
    assert_eq!(routed_tag(&router, "192.168.7.99").await, "direct");
}

#[tokio::test]
async fn the_local_server_answers_the_neighbor_suffix() {
    let leases = lease_file("dns");
    // the resolver is process-wide, so the DNS service reads the same tables
    let _router = router(&leases);
    let service = DnsService::build(&json!({
        "dns": {
            "servers": [
                {"type": "local", "tag": "lan", "neighbor_domain": [".lan"]}
            ],
            "final": "lan",
            "disable_cache": true
        }
    }))
    .expect("dns section")
    .expect("dns present");

    let query = core_runtime::dns::codec::build_query(
        0x4242,
        "tv.lan",
        core_runtime::dns::codec::parse_record_type("A").expect("A"),
    )
    .expect("query");
    let response = service
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("exchange");
    assert_eq!(
        core_runtime::dns::codec::answer_ips(&response).expect("decode"),
        vec![ip("192.168.7.10")],
        "the neighbour table answered, not the system resolver"
    );

    // a name nobody has does not come out of the tables
    let query = core_runtime::dns::codec::build_query(
        0x4243,
        "nosuchdevice.lan",
        core_runtime::dns::codec::parse_record_type("A").expect("A"),
    )
    .expect("query");
    let response = service
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("exchange");
    assert!(
        core_runtime::dns::codec::answer_ips(&response)
            .expect("decode")
            .is_empty(),
        "an unknown neighbour is not invented"
    );
}

#[tokio::test]
async fn a_dns_rule_can_ask_for_the_clients_name() {
    let _router = router(&lease_file("dnsrule"));
    let service = DnsService::build(&json!({
        "dns": {
            "servers": [
                {"type": "hosts", "tag": "local", "predefined": {"a.test": ["10.0.0.1"]}},
                {"type": "hosts", "tag": "other", "predefined": {"a.test": ["10.0.0.2"]}}
            ],
            "rules": [
                {"source_hostname": ["tv"], "server": "other"},
                {"source_hostname": ["laptop"], "server": "local"}
            ],
            "final": "local",
            "disable_cache": true
        }
    }))
    .expect("dns section")
    .expect("dns present");

    let query = core_runtime::dns::codec::build_query(
        0x4242,
        "a.test",
        core_runtime::dns::codec::parse_record_type("A").expect("A"),
    )
    .expect("query");
    // the asking client is the leased `tv`, so the first rule sends it to
    // `other`
    let meta = QueryMeta {
        source: Some(ip("192.168.7.10")),
        ..QueryMeta::default()
    };
    let response = service
        .exchange(&meta, &query, true)
        .await
        .expect("exchange");
    assert_eq!(
        core_runtime::dns::codec::answer_ips(&response).expect("decode"),
        vec![ip("10.0.0.2")]
    );
}
