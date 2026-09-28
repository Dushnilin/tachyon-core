//! `dns.rules[type=logical]` must build end to end: the matcher lives in
//! `dns::Rule` but the construction path is in `DnsService::build`, so this
//! guards the wiring that the config layer already accepted.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use core_runtime::dns::{DnsService, QueryMeta};
use serde_json::json;
use tokio::sync::Mutex;

/// the dns service is process-global; serialise against the other suites
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

#[tokio::test]
async fn logical_dns_rule_routes_by_composition() {
    let _g = test_guard().await;
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = listener.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = listener.send_to(&buf[..n], from).await;
        }
    });

    let service: Arc<DnsService> = core_runtime::dns::DnsService::build(&json!({
        "dns": {
            "servers": [
                {"type": "udp", "tag": "backend", "server": "127.0.0.1", "server_port": addr.port()}
            ],
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "action": "route",
                    "server": "backend",
                    "rules": [
                        {"domain_suffix": ["composed.test"]},
                        {"query_type": ["A"]}
                    ]
                }
            ],
            "final": "backend"
        }
    }))
    .expect("build dns service")
    .expect("dns section present");

    let query = core_runtime::dns::codec::build_query(
        0x5151,
        "host.composed.test",
        hickory_proto::rr::RecordType::A,
    )
    .expect("query");
    let reply = service
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("exchange through the logical rule");
    let message = core_runtime::dns::codec::parse_message(&reply).expect("decode");
    assert_eq!(message.id, 0x5151);
    assert_eq!(message.queries.len(), 1);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "exactly one upstream query");

    // a query that fails the second sub-rule must not be routed by the group
    let aaaa = core_runtime::dns::codec::build_query(
        0x5152,
        "host.composed.test",
        hickory_proto::rr::RecordType::AAAA,
    )
    .expect("query");
    let _ = service
        .exchange(&QueryMeta::default(), &aaaa, true)
        .await
        .expect("final server answers the non-matching query");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "the AAAA query falls through to the final server"
    );
}
