//! Issue #8: a DNS rule gated on a *remote* rule-set has to match. Only the
//! router's registry is ever handed to the downloader, so a DNS service built
//! against its own private copy keeps a remote set with an empty body forever
//! and the rule can never fire.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use core_runtime::dns::{DnsService, QueryMeta};
use hickory_proto::op::Message;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

/// Serialize box instances: the dns service is process-global.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

/// A udp resolver that always answers the same address, so the test can tell
/// which of the two servers the query landed on.
async fn spawn_udp_dns(answer_ip: Ipv4Addr) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let resp = core_runtime::dns::codec::synth_address(&query, answer_ip.into(), 60)
                .expect("encode answer");
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
        }
    });
    addr
}

/// A bare HTTP/1.1 server that hands the compiled `.srs` to the fetcher.
async fn spawn_srs(body: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let addr = listener.local_addr().expect("http addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn a_remote_rule_set_reaches_the_dns_rules() {
    let _g = test_guard().await;

    let picked = spawn_udp_dns(Ipv4Addr::new(5, 6, 7, 8)).await;
    let fallback = spawn_udp_dns(Ipv4Addr::new(1, 2, 3, 4)).await;

    let compiled = core_config::srs::compile(
        &json!({"rules": [{"domain_suffix": ["remote-rule.test"]}]}),
        2,
    )
    .expect("compile rule-set");
    let served = spawn_srs(compiled).await;

    let root = json!({
        "log": {"level": "error"},
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {
            "final": "out",
            "rule_set": [{
                "type": "remote",
                "tag": "rs",
                "url": format!("http://{served}/rs.srs"),
                "update_interval": "24h"
            }]
        },
        "dns": {
            "servers": [
                {"type": "udp", "tag": "picked", "server": "127.0.0.1",
                 "server_port": picked.port()},
                {"type": "udp", "tag": "final", "server": "127.0.0.1",
                 "server_port": fallback.port()}
            ],
            "final": "final",
            "rules": [{"action": "route", "rule_set": ["rs"], "server": "picked"}]
        }
    });

    let mut instance = core_runtime::start(&root).await.expect("start");
    let svc: std::sync::Arc<DnsService> = instance.dns().expect("dns section");

    let query = core_runtime::dns::codec::build_query(
        0x8008,
        "a.remote-rule.test",
        hickory_proto::rr::RecordType::A,
    )
    .expect("query");
    let answer = svc
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("exchange");
    let ips = core_runtime::dns::codec::answer_ips(&answer).expect("parse answer");

    assert_eq!(
        ips,
        vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))],
        "the remote rule-set must route to `picked`, got {ips:?}"
    );

    instance.shutdown_wait().await;
}
