//! Tests for in-place hot reload without connection dropping or port closing.

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn socks5_handshake(stream: &mut TcpStream, target: SocketAddr) {
    // SOCKS5 greeting: no auth
    stream.write_all(&[5, 1, 0]).await.expect("socks5 greeting");
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.expect("socks5 method");
    assert_eq!(resp, [5, 0]);

    // Connect request
    let mut req = vec![5, 1, 0, 1]; // IPv4
    let SocketAddr::V4(v4) = target else {
        panic!("need v4")
    };
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&req).await.expect("socks5 req");

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("socks5 reply");
    assert_eq!(reply[0], 5);
    assert_eq!(reply[1], 0, "status succeeded");
}

#[tokio::test]
async fn hot_reload_preserves_live_tcp_connections() {
    let echo = spawn_echo().await;

    // 1. Initial config with mixed inbound
    let root1 = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {"final": "direct-out"}
    });

    let mut instance = core_runtime::start(&root1).await.expect("start box");
    let in_addr = instance.inbound_addrs()[0].1;

    // 2. Open a TCP connection through SOCKS5 before reload
    let mut client = TcpStream::connect(in_addr)
        .await
        .expect("connect to inbound");
    socks5_handshake(&mut client, echo).await;

    // Send and receive bytes
    client.write_all(b"hello_before_reload").await.unwrap();
    let mut buf = vec![0u8; "hello_before_reload".len()];
    timeout(T, client.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hello_before_reload");

    // 3. New config: inbounds IDENTICAL (same port and type), but routes/outbounds modified
    let root2 = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": in_addr.port()
        }],
        "outbounds": [
            {"type": "direct", "tag": "d1"},
            {"type": "direct", "tag": "direct-out"},
            {"type": "selector", "tag": "sel", "outbounds": ["direct-out", "d1"]}
        ],
        "route": {
            "rules": [
                {"port": [echo.port()], "outbound": "direct-out"}
            ],
            "final": "direct-out"
        }
    });

    // 4. Perform hot reload in-place
    instance
        .reload_in_place(&root2)
        .await
        .expect("reload in place");

    // 5. Assert the EXISTING connection was NOT dropped and is still fully alive!
    client.write_all(b"hello_after_reload").await.unwrap();
    let mut buf2 = vec![0u8; "hello_after_reload".len()];
    timeout(T, client.read_exact(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf2, b"hello_after_reload");

    // 6. Assert a NEW connection works through the updated routes
    let mut client2 = TcpStream::connect(in_addr).await.expect("connect client 2");
    socks5_handshake(&mut client2, echo).await;
    client2.write_all(b"new_connection_ok").await.unwrap();
    let mut buf3 = vec![0u8; "new_connection_ok".len()];
    timeout(T, client2.read_exact(&mut buf3))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf3, b"new_connection_ok");

    instance.shutdown();
}

#[tokio::test]
async fn hot_reload_preserves_selector_urltest_and_dns_cache() {
    let _echo = spawn_echo().await;

    let root1 = json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {"tag": "fakedns", "type": "fakeip", "inet4_range": "198.18.0.0/15"}
            ]
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "d1"},
            {"type": "direct", "tag": "d2"},
            {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2"]},
            {"type": "urltest", "tag": "ut", "outbounds": ["d1", "d2"], "interval": "10m"}
        ],
        "route": {"final": "sel"}
    });

    let mut instance = core_runtime::start(&root1).await.expect("start box");
    let router = instance.router();
    let in_addr = instance.inbound_addrs()[0].1;

    // Record delay on d2, select d2 in selector
    let d2 = router.index_of("d2").unwrap();
    router.record_delay(d2, 88);
    router.select_member("sel", "d2").unwrap();

    // Check DNS fakeip allocation
    let dns = instance.dns().expect("dns configured");
    let fake_addr = dns.resolve("example.com").await.expect("resolve fakeip");
    assert!(!fake_addr.is_empty());
    let fake_ip = fake_addr[0];
    assert_eq!(dns.fakeip_domain(fake_ip), Some("example.com".to_string()));

    // Hot reload with new config keeping inbounds
    let root2 = json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {"tag": "fakedns", "type": "fakeip", "inet4_range": "198.18.0.0/15"}
            ]
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": in_addr.port()
        }],
        "outbounds": [
            {"type": "direct", "tag": "d3"},
            {"type": "direct", "tag": "d2"},
            {"type": "direct", "tag": "d1"},
            {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2", "d3"]},
            {"type": "urltest", "tag": "ut", "outbounds": ["d1", "d2", "d3"], "interval": "10m"}
        ],
        "route": {"final": "d2"}
    });

    instance
        .reload_in_place(&root2)
        .await
        .expect("reload in place");

    // 1. Selector preserved
    let sel_idx = router.index_of("sel").unwrap();
    assert_eq!(router.delay_history(sel_idx).unwrap().1, 88);

    // 2. Delay history on d2 preserved despite reordering
    let new_d2 = router.index_of("d2").unwrap();
    assert_eq!(router.delay_history(new_d2).unwrap().1, 88);

    // 3. FakeIP state preserved across reload
    let new_dns = instance.dns().expect("new dns configured");
    assert_eq!(
        new_dns.fakeip_domain(fake_ip),
        Some("example.com".to_string())
    );

    instance.shutdown();
}

#[tokio::test]
async fn hot_reload_failure_keeps_running_instance_untouched() {
    let echo = spawn_echo().await;

    let root1 = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {"final": "direct-out"}
    });

    let mut instance = core_runtime::start(&root1).await.expect("start box");
    let in_addr = instance.inbound_addrs()[0].1;

    let mut client = TcpStream::connect(in_addr).await.expect("connect client");
    socks5_handshake(&mut client, echo).await;
    client.write_all(b"working_before").await.unwrap();
    let mut buf = vec![0u8; "working_before".len()];
    timeout(T, client.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"working_before");

    // Invalid config with broken dns / unknown outbound reference
    let invalid_root = json!({
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": in_addr.port()
        }],
        "dns": {
            "servers": [
                {"tag": "remote", "type": "udp", "server": "8.8.8.8"}
            ],
            "final": "non_existent_dns_server"
        },
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {"final": "direct-out"}
    });

    // Reload must fail cleanly
    let err = instance.reload_in_place(&invalid_root).await.unwrap_err();
    assert!(
        err.to_string().contains("dns") || err.to_string().contains("server"),
        "expected dns error: {err:#}"
    );

    // The existing connection was NOT touched and still functions!
    client
        .write_all(b"still_working_after_failure")
        .await
        .unwrap();
    let mut buf2 = vec![0u8; "still_working_after_failure".len()];
    timeout(T, client.read_exact(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf2, b"still_working_after_failure");

    instance.shutdown();
}
