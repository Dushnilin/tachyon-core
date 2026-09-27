//! F1 exit gate: the Tachyon-generated router config (minus AWG/hy2/xhttp)
//! starts, binds every inbound, and answers DNS through hijack-dns + FakeIP.

use std::net::SocketAddr;

use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use core_runtime::dns::codec;

/// Serialize box instances: the dns service is process-global.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

const F1_FIXTURE: &str = include_str!("../../../tests/golden/tachyon/f1-exit-gate.json");

/// Rewrite the fixture for the test host: loopback-only listens on ephemeral
/// ports, drop tproxy off Linux (reference binds fail there too), quiet log.
fn adapt_for_test(root: &mut Value) {
    if let Some(log) = root.get_mut("log").and_then(Value::as_object_mut) {
        log.insert("level".into(), Value::String("error".into()));
    }
    let inbounds = root
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .expect("fixture inbounds");
    inbounds.retain(|ib| {
        ib.get("type").and_then(Value::as_str) != Some("tproxy") || cfg!(target_os = "linux")
    });
    for ib in inbounds.iter_mut() {
        // Force IPv4 loopback: some Windows hosts reject ::1 binds (WSAEACCES)
        // when IPv6 is partially disabled; docker/Linux keeps full coverage.
        ib["listen"] = Value::String("127.0.0.1".into());
        ib["listen_port"] = Value::from(0u16);
    }
    // The fixture listens on the router's LAN address (192.168.1.1:9090);
    // rewrite to an ephemeral loopback port on the test host.
    if let Some(controller) = root
        .get_mut("experimental")
        .and_then(|exp| exp.get_mut("clash_api"))
        .and_then(|ca| ca.get_mut("external_controller"))
    {
        *controller = Value::String("127.0.0.1:0".into());
    }
}

fn inbound_addr(instance: &core_runtime::BoxInstance, tag: &str) -> SocketAddr {
    instance
        .inbound_addrs()
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, a)| *a)
        .unwrap_or_else(|| panic!("no inbound {tag}"))
}

#[tokio::test]
async fn f1_exit_gate_starts_and_answers_fakeip_dns() {
    let _g = test_guard().await;
    let mut root: Value = serde_json::from_str(F1_FIXTURE).expect("parse f1 fixture");
    adapt_for_test(&mut root);

    let expected: Vec<String> = root["inbounds"]
        .as_array()
        .expect("inbounds array")
        .iter()
        .filter_map(|ib| ib.get("tag").and_then(Value::as_str).map(str::to_string))
        .collect();
    let expected_count = expected.len();

    let instance = core_runtime::start(&root).await.expect("f1 fixture start");
    assert_eq!(
        instance.inbound_addrs().len(),
        expected_count,
        "every configured inbound must bind"
    );
    for tag in &expected {
        let _ = inbound_addr(&instance, tag);
    }
    assert!(
        instance.clash_api_addr().is_some(),
        "fixture has experimental.clash_api; controller must bind"
    );

    // UDP DNS through the direct inbound → hijack-dns → FakeIP pool
    // (domain_suffix google.com routes to fakeip-server; no upstream needed).
    let dns_addr = inbound_addr(&instance, "dns-in");
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let query = codec::build_query(0xF1F1, "www.google.com", hickory_proto::rr::RecordType::A)
        .expect("query");
    client.send_to(&query, dns_addr).await.expect("send query");
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("dns reply timeout")
    .expect("dns reply");
    let ips = codec::answer_ips(&buf[..n]).expect("parse answer");
    assert!(
        ips.iter().any(|ip| match ip {
            std::net::IpAddr::V4(v4) => v4.octets()[0] == 198 && v4.octets()[1] == 18,
            std::net::IpAddr::V6(_) => false,
        }),
        "expected FakeIP 198.18.0.0/15 answer, got {ips:?}"
    );

    instance.shutdown();
}
