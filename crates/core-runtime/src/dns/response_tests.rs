//! Focused regressions for the response rules emitted by Tachyon 1.5.1.
use super::*;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

fn service(rules: Value, extra: Value) -> Arc<DnsService> {
    let mut root = json!({
        "route":{"rule_set":[{"type":"inline","tag":"addresses","rules":[{"ip_cidr":"203.0.113.0/24"}]}]},
        "dns":{"servers":[
            {"type":"hosts","tag":"real","path":[],"predefined":{"probe.example":["203.0.113.7"]}},
            {"type":"hosts","tag":"later","path":[],"predefined":{"probe.example":["192.0.2.7"]}},
            {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}],
            "rules":rules,"final":"real","reverse_mapping":true}
    });
    for (key, value) in extra.as_object().unwrap() {
        root["dns"][key] = value.clone();
    }
    DnsService::build(&root).unwrap().unwrap()
}

async fn answer(svc: &Arc<DnsService>, source: &str, name: &str, id: u16) -> Vec<u8> {
    let meta = QueryMeta {
        source: Some(source.parse().unwrap()),
        ..Default::default()
    };
    svc.exchange(
        &meta,
        &codec::build_query(id, name, RecordType::A).unwrap(),
        true,
    )
    .await
    .unwrap()
}

fn assert_ip(raw: &[u8], ip: &str, id: u16) {
    assert_eq!(
        codec::answer_ips(raw).unwrap(),
        vec![ip.parse::<IpAddr>().unwrap()]
    );
    assert_eq!(codec::parse_message(raw).unwrap().id, id);
}

fn evaluate() -> Value {
    json!({"action":"evaluate","server":"real"})
}
fn response_route() -> Value {
    json!({"match_response":true,"rule_set":"addresses","action":"route","server":"fake","rewrite_ttl":60})
}

#[tokio::test]
async fn tachyon_excluded_clients_keep_logical_response_route() {
    // apply_excluded_source_ips moves match_response into the first child,
    // while server, action and rewrite_ttl stay on the logical parent.
    let rules = json!([
        {"action":"evaluate","server":"real","source_ip_cidr":"192.0.2.9/32","invert":true},
        {"type":"logical","mode":"and","action":"route","server":"fake","rewrite_ttl":60,
         "rules":[{"match_response":true,"rule_set":"addresses"},
                  {"source_ip_cidr":"192.0.2.9/32","invert":true}]}
    ]);
    let svc = service(rules, json!({}));
    for (client, expected) in [
        ("192.0.2.8", "198.18.0.2"),
        ("192.0.2.9", "203.0.113.7"),
        ("192.0.2.8", "198.18.0.2"),
    ] {
        for id in [123, 456] {
            assert_ip(
                &answer(&svc, client, "probe.example", id).await,
                expected,
                id,
            );
        }
    }
    assert_eq!(svc.reverse_domain("198.18.0.2".parse().unwrap()), None);
    assert_eq!(
        svc.reverse_domain("203.0.113.7".parse().unwrap())
            .as_deref(),
        Some("probe.example")
    );
}

#[tokio::test]
async fn simple_ip_rule_set_still_routes_and_misses() {
    for (cidr, expected) in [
        ("203.0.113.0/24", "198.18.0.2"),
        ("198.51.100.0/24", "203.0.113.7"),
    ] {
        // Build the registry with the selected list before creating the service.
        let root = json!({"route":{"rule_set":[{"type":"inline","tag":"addresses","rules":[{"ip_cidr":cidr}]}]},
            "dns":{"servers":[{"type":"hosts","tag":"real","path":[],"predefined":{"probe.example":["203.0.113.7"]}},
                {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}],"rules":[evaluate(),response_route()],"final":"real"}});
        let svc = DnsService::build(&root).unwrap().unwrap();
        assert_ip(
            &answer(&svc, "192.0.2.8", "probe.example", 7).await,
            expected,
            7,
        );
    }
}

#[tokio::test]
async fn evaluate_obeys_forward_order_and_later_query_rules() {
    for (rules, expected) in [
        (json!([response_route(), evaluate()]), "203.0.113.7"),
        (
            json!([evaluate(),{"domain":"probe.example","action":"route","server":"later"},response_route()]),
            "192.0.2.7",
        ),
        (
            json!([{"action":"route","server":"later"},evaluate(),response_route()]),
            "192.0.2.7",
        ),
        (
            json!([evaluate(),{"match_response":true,"rule_set":"addresses","action":"route-options","rewrite_ttl":42},
            {"action":"route","server":"later"}]),
            "192.0.2.7",
        ),
    ] {
        let svc = service(rules.clone(), json!({}));
        let raw = answer(&svc, "192.0.2.8", "probe.example", 9).await;
        assert_ip(&raw, expected, 9);
        if rules[1]["action"] == "route-options" {
            assert_eq!(codec::parse_message(&raw).unwrap().answers[0].ttl, 42);
        }
        if expected == "192.0.2.7" {
            assert_eq!(svc.reverse_domain("203.0.113.7".parse().unwrap()), None);
            assert_eq!(
                svc.reverse_domain("192.0.2.7".parse().unwrap()).as_deref(),
                Some("probe.example")
            );
        }
    }
}

#[test]
fn nested_response_and_or_invert_and_unavailable() {
    let query = codec::parse_query(&codec::build_query(1, "probe.example", RecordType::A).unwrap())
        .unwrap()
        .1;
    let meta = QueryMeta {
        source: Some("192.0.2.8".parse().unwrap()),
        ..Default::default()
    };
    for (mode, invert, expected) in [
        ("and", false, true),
        ("or", false, true),
        ("and", true, false),
        ("or", true, false),
    ] {
        let rule=rules::Rule::build(&json!({"type":"logical","mode":mode,"invert":invert,
            "rules":[{"source_ip_cidr":"192.0.2.0/24"},{"type":"logical","mode":"or",
            "rules":[{"match_response":true,"ip_cidr":"203.0.113.0/24"},{"match_response":true,"ip_cidr":"2001:db8::/32"}]}],
            "action":"route","server":"fake","rewrite_ttl":42,"disable_cache":true}),"rule").unwrap();
        for ip in ["203.0.113.7", "2001:db8::7"] {
            assert_eq!(
                rule.matches_response(&meta, &query, &[ip.parse().unwrap()]),
                expected
            );
        }
        assert!(
            matches!(rule.action,Action::Route { ref server,rewrite_ttl:Some(42),disable_cache:true } if server=="fake")
        );
    }
    for invert in [false, true] {
        let rule = rules::Rule::build(
            &json!({"type":"logical","mode":"and","invert":invert,
            "rules":[{"type":"logical","mode":"or","invert":true,
                "rules":[{"match_response":true,"ip_cidr":"198.18.0.0/15","invert":true}]}]}),
            "rule",
        )
        .unwrap();
        assert!(!rule.matches(&meta, &query));
    }
    let leaf = rules::Rule::build(
        &json!({"match_response":true,"ip_cidr":"198.18.0.0/15","invert":true}),
        "leaf",
    )
    .unwrap();
    assert!(leaf.matches_response(&meta, &query, &["203.0.113.7".parse().unwrap()]));
    assert!(!leaf.matches_response(&meta, &query, &["198.18.0.8".parse().unwrap()]));
    let miss = QueryMeta {
        source: Some("198.51.100.8".parse().unwrap()),
        ..Default::default()
    };
    for (mode, invert, expected) in [
        ("and", false, false),
        ("and", true, true),
        ("or", false, true),
        ("or", true, false),
    ] {
        let rule=rules::Rule::build(&json!({"type":"logical","mode":mode,"invert":invert,
            "rules":[{"source_ip_cidr":"192.0.2.0/24"},{"match_response":true,"ip_cidr":"203.0.113.0/24"}]}),"rule").unwrap();
        assert_eq!(
            rule.matches_response(&miss, &query, &["203.0.113.7".parse().unwrap()]),
            expected
        );
    }
}

#[test]
fn logical_parents_preserve_evaluate_and_reject_options() {
    let eval = rules::Rule::build(
        &json!({"type":"logical","mode":"and","rules":[{"query_type":"A"}],
        "action":"evaluate","server":"real","rewrite_ttl":42,"disable_cache":true}),
        "rule",
    )
    .unwrap();
    assert!(
        matches!(eval.action,Action::Evaluate { ref server,rewrite_ttl:Some(42),disable_cache:true } if server=="real")
    );
    let reject = rules::Rule::build(
        &json!({"type":"logical","mode":"or","rules":[{"query_type":"AAAA"}],
        "action":"reject","method":"drop"}),
        "rule",
    )
    .unwrap();
    assert_eq!(reject.reject_method, RejectMethod::Drop);
}

#[tokio::test]
async fn latest_evaluation_is_local_to_each_request() {
    let svc = service(
        json!([
            {"domain":"probe.example","action":"evaluate","server":"real"},
            {"domain":"probe.example","action":"evaluate","server":"later"},{"action":"respond"}
        ]),
        json!({}),
    );
    assert_ip(
        &answer(&svc, "192.0.2.8", "probe.example", 12).await,
        "192.0.2.7",
        12,
    );
    let q = codec::build_query(13, "other.example", RecordType::A).unwrap();
    assert!(
        svc.exchange(&QueryMeta::default(), &q, true)
            .await
            .unwrap_err()
            .to_string()
            .contains("without evaluated response")
    );
    assert_eq!(svc.reverse_domain("203.0.113.7".parse().unwrap()), None);
}

#[tokio::test]
async fn evaluate_cache_ttl_ids_and_concurrent_response_isolation() {
    for disable_cache in [false, true] {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let worker = tokio::spawn(async move {
            let mut buf = [0; 512];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                seen.fetch_add(1, Ordering::SeqCst);
                let (q, info) = codec::parse_query(&buf[..n]).unwrap();
                let ip = if info.name == "probe.example" {
                    "203.0.113.7"
                } else {
                    "192.0.2.7"
                };
                let raw = codec::synth_addresses(&q, &[ip.parse().unwrap()], 60).unwrap();
                socket.send_to(&raw, peer).await.unwrap();
            }
        });
        let svc = service(
            json!([
                {"type":"logical","mode":"and","rules":[{"query_type":"A"}],
                    "action":"evaluate","server":"real","disable_cache":disable_cache,"rewrite_ttl":42},
                {"action":"respond"}
            ]),
            json!({"servers":[{"type":"udp","tag":"real","server":"127.0.0.1","server_port":port}]}),
        );
        for (id, other_id) in [(123, 456), (789, 987)] {
            let (first, other) = tokio::join!(
                answer(&svc, "192.0.2.8", "probe.example", id),
                answer(&svc, "192.0.2.8", "other.example", other_id)
            );
            assert_ip(&first, "203.0.113.7", id);
            assert_ip(&other, "192.0.2.7", other_id);
            for raw in [first, other] {
                assert_eq!(codec::parse_message(&raw).unwrap().answers[0].ttl, 42);
            }
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            if disable_cache { 4 } else { 2 }
        );
        if !disable_cache {
            let ip = "203.0.113.7".parse().unwrap();
            let expires = svc
                .reverse
                .as_ref()
                .unwrap()
                .read()
                .unwrap()
                .get(&ip)
                .unwrap()
                .expires;
            let raw = answer(&svc, "192.0.2.8", "probe.example", 1001).await;
            assert_eq!(
                svc.reverse
                    .as_ref()
                    .unwrap()
                    .read()
                    .unwrap()
                    .get(&ip)
                    .unwrap()
                    .expires,
                expires
            );
            svc.record_reverse_at(&raw, false, Instant::now() - Duration::from_secs(43));
            assert_eq!(svc.reverse_domain(ip), None);
        }
        assert_eq!(
            svc.reverse_domain("192.0.2.7".parse().unwrap()).as_deref(),
            Some("other.example")
        );
        worker.abort();
    }
}

#[tokio::test]
async fn evaluated_fakeip_keeps_transport_mapping_and_resolution_guard() {
    let svc = service(
        json!([{"action":"evaluate","server":"fake"},{"action":"respond"}]),
        json!({}),
    );
    let raw = answer(&svc, "192.0.2.8", "probe.example", 11).await;
    assert_ip(&raw, "198.18.0.2", 11);
    assert_eq!(svc.reverse_domain("198.18.0.2".parse().unwrap()), None);
    assert_eq!(
        svc.fakeip_domain("198.18.0.2".parse().unwrap()).as_deref(),
        Some("probe.example")
    );
    let q = codec::build_query(12, "probe.example", RecordType::A).unwrap();
    assert!(
        svc.exchange(&QueryMeta::default(), &q, false)
            .await
            .is_err()
    );
}
