//! End-to-end Clash API coverage for the F4 data views: the controller is
//! bound on loopback and driven with raw HTTP requests.

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use core_runtime::clash_state;
use std::sync::Arc;

use core_runtime::route::Router;

/// clash_state is process-global: serialize the end-to-end view test.
/// async-aware guard: clash_state is process-global
fn guard() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn api_config() -> Value {
    serde_json::json!({
        "log": {"level": "error", "disabled": true},
        "inbounds": [
            {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"domain_suffix": ["ads.example"], "action": "reject"},
                {"port": [443], "outbound": "direct"}
            ],
            "final": "direct"
        },
        "experimental": {
            "clash_api": {"external_controller": "127.0.0.1:0"}
        }
    })
}

/// One request/response exchange; chunked replies are read until the terminal
/// chunk, everything else by content length.
async fn request(addr: std::net::SocketAddr, raw: &str) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(raw.as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    let mut byte = [0u8; 1024];
    // read the head
    let head_end = loop {
        if let Some(index) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        let n = stream.read(&mut byte).await.expect("read head");
        assert!(n > 0, "connection closed before the head completed");
        buf.extend_from_slice(&byte[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    if chunked {
        // read a couple of chunks (the streams keep producing)
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        loop {
            let read = tokio::time::timeout_at(deadline, stream.read(&mut byte)).await;
            match read {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&byte[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
    } else {
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);
        while buf.len() < head_end + length {
            let n = stream.read(&mut byte).await.expect("read body");
            assert!(n > 0, "connection closed mid-body");
            buf.extend_from_slice(&byte[..n]);
        }
    }
    let body = buf[head_end..].to_vec();
    (head, body)
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
}

fn patch(path: &str, body: &str) -> String {
    format!(
        "PATCH {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn data_views_answer_over_http() {
    let _g = guard().lock().await;
    let router: Arc<Router> = Router::new(&api_config()).expect("router");
    let api = core_runtime::clash_api::ClashApi::build(&api_config())
        .expect("api")
        .expect("clash api present");
    let (addr, handle) = api.bind_and_spawn(router).await.expect("bind controller");
    // keep the accept loop alive for the whole test
    let _controller = handle;

    // /rules mirrors the config conditions
    let (head, body) = request(addr, &get("/rules")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let rules: Value = serde_json::from_slice(&body).expect("rules json");
    let list = rules["rules"].as_array().expect("rules array");
    assert_eq!(list.len(), 2, "{rules}");
    // reference shape: type/payload/proxy with the sing-box description
    assert_eq!(list[0]["type"], "default");
    assert_eq!(list[0]["payload"], "domain_suffix=ads.example");
    assert_eq!(list[0]["proxy"], "reject");
    assert_eq!(list[1]["payload"], "port=443");
    assert_eq!(list[1]["proxy"], "route(direct)");

    // /connections starts empty and reports the totals
    let (head, body) = request(addr, &get("/connections")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let connections: Value = serde_json::from_slice(&body).expect("connections json");
    assert!(
        connections["connections"]
            .as_array()
            .expect("list")
            .is_empty()
    );
    assert!(connections["uploadTotal"].as_u64().is_some());

    // an entry appears while it is held, then DELETE drops it
    let handle_conn = clash_state::ConnHandle::open(clash_state::ConnMeta {
        network: "tcp",
        inbound: "mixed/mixed-in".into(),
        source: "192.168.1.10:5000".into(),
        host: "example.com".into(),
        destination: "example.com:443".into(),
        chains: vec!["direct".into()],
        rule: "port=443 => route(direct)".into(),
        rule_payload: String::new(),
        process_path: String::new(),
    });
    let id = handle_conn.id();
    let id_str = id.to_string();
    let (_, body) = request(addr, &get("/connections")).await;
    let connections: Value = serde_json::from_slice(&body).expect("connections json");
    let list = connections["connections"].as_array().expect("list");
    let entry = list
        .iter()
        .find(|entry| entry["id"].as_str() == Some(id_str.as_str()))
        .expect("our entry is listed");
    // reference `TrackerMetadata`: type/tag, no IP for a domain destination
    assert_eq!(entry["metadata"]["type"], "mixed/mixed-in");
    assert_eq!(entry["metadata"]["host"], "example.com");
    assert_eq!(entry["metadata"]["destinationIP"], "");
    assert_eq!(entry["metadata"]["destinationPort"], "443");
    assert_eq!(entry["metadata"]["dnsMode"], "normal");
    assert_eq!(entry["chains"][0], "direct");
    assert_eq!(entry["rule"], "port=443 => route(direct)");
    assert_eq!(entry["rulePayload"], "");

    let (head, _) = request(
        addr,
        &format!("DELETE /connections/{id} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");
    // the entry stays registered while the relay holds it; a released id 404s
    drop(handle_conn);
    let (head, _) = request(
        addr,
        &format!("DELETE /connections/{id} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");

    // /configs reports and patches the log level
    let (head, body) = request(addr, &get("/configs")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let configs: Value = serde_json::from_slice(&body).expect("configs json");
    assert_eq!(configs["mode"], "rule");
    let (head, _) = request(addr, &patch("/configs", r#"{"log-level":"debug"}"#)).await;
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");
    assert_eq!(
        core_runtime::logging::level().map(core_runtime::logging::Level::level_name),
        Some("debug")
    );
    let (head, _) = request(addr, &patch("/configs", r#"{"log-level":"nope"}"#)).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    // the reference answers a config upload with 204 and changes nothing
    let (head, _) = request(
        addr,
        "PUT /configs HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");

    // the reference has no provider runtime either: an empty list, not a 404
    let (head, body) = request(addr, &get("/providers/proxies")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(String::from_utf8_lossy(&body), r#"{"providers":{}}"#);
    let (head, body) = request(addr, &get("/providers/rules")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(String::from_utf8_lossy(&body), r#"{"providers":[]}"#);

    // the clash mode is switchable and reported back
    let (head, _) = request(addr, &patch("/configs", r#"{"mode":"global"}"#)).await;
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");
    let (_, body) = request(addr, &get("/configs")).await;
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(
        body.contains(r#""mode":"global""#),
        "the mode did not take: {body}"
    );
    let (head, _) = request(addr, &patch("/configs", r#"{"mode":"script"}"#)).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    // /logs and /traffic stream chunked JSON
    let (head, body) = request(addr, &get("/logs")).await;
    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "{head}"
    );
    assert!(
        String::from_utf8_lossy(&body).contains("\"payload\""),
        "{body:?}"
    );
    let (head, body) = request(addr, &get("/traffic")).await;
    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "{head}"
    );
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"up\""), "{text}");
}
