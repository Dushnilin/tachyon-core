//! `type: hosts` and `type: local` DNS servers answer without a network round
//! trip, so both are covered here against a live dns service.

use core_runtime::dns::{DnsService, QueryMeta};
use hickory_proto::rr::RecordType;
use serde_json::json;

async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

fn service(dns: serde_json::Value) -> std::sync::Arc<DnsService> {
    DnsService::build(&json!({ "dns": dns }))
        .expect("build")
        .expect("dns section")
}

fn query(name: &str, qtype: RecordType) -> Vec<u8> {
    core_runtime::dns::codec::build_query(0x4242, name, qtype).expect("query")
}

fn addresses(raw: &[u8]) -> Vec<String> {
    core_runtime::dns::codec::answer_ips(raw)
        .expect("answers")
        .iter()
        .map(|ip| ip.to_string())
        .collect()
}

#[tokio::test]
async fn a_hosts_server_answers_from_its_predefined_entries() {
    let _g = test_guard().await;
    let service = service(json!({
        "servers": [{
            "type": "hosts",
            "tag": "hosts",
            "predefined": {
                "static.test": "10.1.2.3",
                "dual.test": ["10.4.5.6", "fd00::5"],
            }
        }],
        "final": "hosts"
    }));

    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("static.test", RecordType::A),
            true,
        )
        .await
        .expect("a record");
    assert_eq!(addresses(&raw), vec!["10.1.2.3"]);

    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("dual.test", RecordType::A),
            true,
        )
        .await
        .expect("a records");
    assert_eq!(addresses(&raw), vec!["10.4.5.6"]);

    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("dual.test", RecordType::AAAA),
            true,
        )
        .await
        .expect("aaaa records");
    assert_eq!(addresses(&raw), vec!["fd00::5"]);

    // an unknown name is NXDOMAIN, not an empty NOERROR
    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("nope.test", RecordType::A),
            true,
        )
        .await
        .expect("nxdomain");
    let meta = core_runtime::dns::codec::response_meta(&raw).expect("meta");
    assert_eq!(
        meta.rcode,
        hickory_proto::op::ResponseCode::NXDomain,
        "NXDOMAIN"
    );
    assert!(addresses(&raw).is_empty());
}

#[tokio::test]
async fn a_hosts_server_reads_the_configured_files() {
    let _g = test_guard().await;
    let path = std::env::temp_dir().join("tachyon-hosts-test");
    std::fs::write(
        &path,
        "# a comment\n10.9.8.7 first.test alias.test\n\nnot-an-ip second.test\n",
    )
    .expect("write hosts file");

    let service = service(json!({
        "servers": [{
            "type": "hosts",
            "tag": "hosts",
            "path": path.to_string_lossy(),
        }],
        "final": "hosts"
    }));

    for name in ["first.test", "alias.test", "FIRST.TEST"] {
        let raw = service
            .exchange(&QueryMeta::default(), &query(name, RecordType::A), true)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(addresses(&raw), vec!["10.9.8.7"], "{name}");
    }

    // a malformed line is skipped, not fatal
    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("second.test", RecordType::A),
            true,
        )
        .await
        .expect("second");
    let meta = core_runtime::dns::codec::response_meta(&raw).expect("meta");
    assert_eq!(
        meta.rcode,
        hickory_proto::op::ResponseCode::NXDomain,
        "the unparsable line yields NXDOMAIN"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_local_server_uses_the_system_resolver() {
    let _g = test_guard().await;
    let service = service(json!({
        "servers": [{"type": "local", "tag": "local"}],
        "final": "local"
    }));
    // localhost resolves everywhere, and a nonsense name resolves nowhere
    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("localhost", RecordType::A),
            true,
        )
        .await
        .expect("localhost");
    assert!(!addresses(&raw).is_empty(), "localhost must resolve");

    let raw = service
        .exchange(
            &QueryMeta::default(),
            &query("nxdomain.invalid", RecordType::A),
            true,
        )
        .await
        .expect("nxdomain");
    let meta = core_runtime::dns::codec::response_meta(&raw).expect("meta");
    assert_eq!(
        meta.rcode,
        hickory_proto::op::ResponseCode::NXDomain,
        "NXDOMAIN"
    );
}
