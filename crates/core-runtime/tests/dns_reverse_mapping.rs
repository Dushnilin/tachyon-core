//! `dns.reverse_mapping`: every A/AAAA answer remembers `ip → domain` for the
//! record's TTL, so a connection that dials the IP straight away still matches
//! domain rules. Off by default, exactly as in the reference.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use core_runtime::dns::codec::{build_query, parse_message};
use core_runtime::dns::{DnsService, QueryMeta};
use hickory_proto::rr::RecordType;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn service(reverse_mapping: bool) -> Arc<DnsService> {
    DnsService::build(&json!({
        "dns": {
            "reverse_mapping": reverse_mapping,
            "servers": [{
                "type": "hosts",
                "tag": "h",
                "predefined": {
                    "a.test": "10.1.2.3",
                    "aaaa.test": "2001:db8::1",
                    "site.test": "127.0.0.1"
                }
            }],
            "final": "h"
        }
    }))
    .expect("build")
    .expect("dns section")
}

async fn ask(svc: &Arc<DnsService>, name: &str, qtype: RecordType) -> usize {
    let query = build_query(7, name, qtype).expect("query");
    let reply = svc
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("exchange");
    parse_message(&reply).expect("decode").answers.len()
}

#[tokio::test]
async fn answers_are_remembered_until_their_ttl() {
    let svc = service(true);
    assert_eq!(ask(&svc, "a.test", RecordType::A).await, 1);
    assert_eq!(ask(&svc, "aaaa.test", RecordType::AAAA).await, 1);

    assert_eq!(
        svc.reverse_domain(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
            .as_deref(),
        Some("a.test")
    );
    assert_eq!(
        svc.reverse_domain("2001:db8::1".parse::<IpAddr>().expect("v6"))
            .as_deref(),
        Some("aaaa.test")
    );
    // an IP no answer mentioned stays unknown
    assert_eq!(
        svc.reverse_domain(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 4))),
        None
    );
    // and an NXDOMAIN answer records nothing
    assert_eq!(ask(&svc, "missing.test", RecordType::A).await, 0);
    assert_eq!(
        svc.reverse_domain(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 5))),
        None
    );
}

#[tokio::test]
async fn the_option_off_records_nothing() {
    let svc = service(false);
    ask(&svc, "a.test", RecordType::A).await;
    assert_eq!(
        svc.reverse_domain(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        None,
        "reverse_mapping defaults to off"
    );
}

// ---------------------------------------------------------------------------
// End to end: a domain rule sees the name behind an IP destination.
// ---------------------------------------------------------------------------

/// The dns service is process-global; serialise against the other suites.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

/// SOCKS5 CONNECT to an IPv4 destination; returns the reply code.
async fn socks_connect(inbound: std::net::SocketAddr, ip: Ipv4Addr, port: u16) -> u8 {
    let mut stream = TcpStream::connect(inbound).await.expect("connect inbound");
    stream.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[0], 0x05, "socks version");
    reply[1]
}

#[tokio::test]
async fn a_domain_rule_matches_an_ip_the_resolver_answered() {
    let _g = test_guard().await;
    let (echo_addr, echo) = spawn_echo().await;

    let cfg = json!({
        "log": {"level": "warn"},
        "dns": {
            "reverse_mapping": true,
            "servers": [{"type": "hosts", "tag": "h", "predefined": {"site.test": "127.0.0.1"}}],
            "final": "h"
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": "direct", "tag": "out"},
            {"type": "block", "tag": "blk"}
        ],
        "route": {
            "rules": [{"action": "route", "outbound": "out", "domain_suffix": [".test"]}],
            "final": "blk"
        }
    });
    let instance = core_runtime::start(&cfg).await.expect("start box");
    let inbound = instance
        .inbound_addrs()
        .iter()
        .find(|(tag, _)| tag == "mixed-in")
        .map(|(_, addr)| *addr)
        .expect("mixed inbound addr");

    // warm the mapping the way a real resolver would
    let dns = core_runtime::dns::current().expect("dns service installed");
    let query = build_query(7, "site.test", RecordType::A).expect("query");
    dns.exchange(&QueryMeta::default(), &query, true)
        .await
        .expect("warm");
    assert_eq!(
        dns.reverse_domain(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .as_deref(),
        Some("site.test")
    );

    // the domain rule matches the IP destination through the mapping
    let code = socks_connect(inbound, Ipv4Addr::new(127, 0, 0, 1), echo_addr.port()).await;
    assert_eq!(code, 0x00, "mapped IP must take the domain rule's outbound");

    // an IP nobody answered for still falls through to the final block
    let code = socks_connect(inbound, Ipv4Addr::new(127, 0, 0, 2), echo_addr.port()).await;
    assert_eq!(code, 0x01, "unmapped IP must fall through to final");

    instance.shutdown();
    echo.abort();
}
