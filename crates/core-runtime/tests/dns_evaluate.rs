//! `action: evaluate` is a pre-fetch for the rules that come after it, so a
//! transport that cannot stage an answer leaves nothing staged instead of
//! failing the query itself.

use std::net::IpAddr;
use std::sync::Arc;

use core_runtime::dns::{DnsService, QueryMeta};
use serde_json::json;
use tokio::sync::Mutex;

/// the dns service is process-global; serialise against the other suites
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

#[tokio::test]
async fn a_failed_evaluate_does_not_fail_the_query() {
    let _g = test_guard().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let dead_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    let service: Arc<DnsService> = DnsService::build(&json!({
        "dns": {
            "servers": [
                {"type": "tcp", "tag": "dead", "server": "127.0.0.1", "server_port": dead_port},
                {"type": "fakeip", "tag": "fakeip-server", "inet4_range": "198.18.0.0/15"}
            ],
            "rules": [
                {"action": "evaluate", "server": "dead", "domain_suffix": ["stage.test"]},
                {"action": "route", "server": "fakeip-server", "domain_suffix": ["stage.test"]}
            ],
            "final": "fakeip-server"
        }
    }))
    .expect("build dns service")
    .expect("dns section present");

    let query = core_runtime::dns::codec::build_query(
        0x6161,
        "host.stage.test",
        hickory_proto::rr::RecordType::A,
    )
    .expect("query");
    let reply = service
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("the rule after evaluate still answers");
    let message = core_runtime::dns::codec::parse_message(&reply).expect("decode");
    assert_eq!(message.id, 0x6161);

    let answer = core_runtime::dns::codec::answer_ips(&reply).expect("answer ips");
    assert_eq!(answer.len(), 1, "one fakeip answer, got {answer:?}");
    let IpAddr::V4(ip) = answer[0] else {
        panic!("expected a fakeip v4 address, got {}", answer[0]);
    };
    let octets = ip.octets();
    assert_eq!(
        (octets[0], octets[1]),
        (198, 18),
        "the query fell through to the fakeip rule, got {ip}"
    );
}
