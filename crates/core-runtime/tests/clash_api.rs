//! F4 slice: `experimental.clash_api` REST surface — auth, CORS, proxies
//! view, selector switching, delay errors. Behaviour mirrors the reference
//! (`sing-box 1.14.2-lx.3`, probed live).

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("json body")
    }
}

async fn read_response(stream: &mut TcpStream) -> Response {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.expect("read head");
        assert!(n > 0, "connection closed before response head");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("status number");
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().expect("content-length");
            }
            headers.push((name, value));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await.expect("read body");
    }
    Response {
        status,
        headers,
        body,
    }
}

async fn send(stream: &mut TcpStream, request: &str) -> Response {
    stream.write_all(request.as_bytes()).await.expect("write");
    read_response(stream).await
}

async fn request(addr: std::net::SocketAddr, request: &str) -> Response {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    send(&mut stream, request).await
}

const SECRET: &str = "s3cr3t";

fn authed(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\r\n")
}

fn anonymous(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")
}

#[tokio::test]
async fn clash_api_rest_surface() {
    let config = serde_json::json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:0",
            "secret": SECRET
        }},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"},
            {"type": "direct", "tag": "backup"},
            {"type": "selector", "tag": "sel", "outbounds": ["direct-out", "backup"]}
        ],
        "route": {"final": "direct-out"}
    });
    let instance = core_runtime::start(&config).await.expect("start");
    let addr = instance.clash_api_addr().expect("clash-api bound");

    // --- authentication -------------------------------------------------
    let res = request(addr, &anonymous("/version")).await;
    assert_eq!(res.status, 401);
    assert_eq!(res.json()["message"], "Unauthorized");
    assert_eq!(res.header("content-type"), Some("application/json"));
    assert_eq!(res.header("vary"), Some("Origin"));

    let res = request(addr, &authed("/version")).await;
    assert_eq!(res.status, 200);
    let version = res.json();
    assert!(
        version["version"]
            .as_str()
            .is_some_and(|v| v.starts_with("tachyon-core ")),
        "{version}"
    );
    assert_eq!(version["premium"], true);
    assert_eq!(version["meta"], true);

    // websocket upgrades may authenticate with ?token=
    let res = request(
        addr,
        "GET /version?token=s3cr3t HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    let res = request(
        addr,
        "GET /version?token=s3cr3t HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 401);

    // --- CORS -----------------------------------------------------------
    let res = request(
        addr,
        "GET /version HTTP/1.1\r\nHost: x\r\nOrigin: http://dashboard\r\nAuthorization: Bearer s3cr3t\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("access-control-allow-origin"), Some("*"));

    // preflight: intercepted before auth and routing
    let res = request(
        addr,
        "OPTIONS /version HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nAccess-Control-Request-Method: GET\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("access-control-allow-origin"), Some("*"));
    assert_eq!(res.header("access-control-allow-methods"), Some("GET"));
    assert_eq!(res.header("access-control-max-age"), Some("300"));
    assert!(res.header("access-control-allow-headers").is_none());

    let res = request(
        addr,
        "OPTIONS /version HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: Authorization\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(
        res.header("access-control-allow-headers"),
        Some("Authorization")
    );

    // disallowed method or header: bare 200 with Vary only
    let res = request(
        addr,
        "OPTIONS /version HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nAccess-Control-Request-Method: TRACE\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert!(res.header("access-control-allow-origin").is_none());

    let res = request(
        addr,
        "OPTIONS /version HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: x-custom\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert!(res.header("access-control-allow-origin").is_none());

    // unknown path: preflight still intercepted
    let res = request(
        addr,
        "OPTIONS /nope HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nAccess-Control-Request-Method: GET\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("access-control-allow-origin"), Some("*"));

    // --- routing / methods ---------------------------------------------
    let res = request(addr, &anonymous("/nope")).await;
    assert_eq!(res.status, 404);
    assert_eq!(res.text(), "404 page not found\n");
    assert_eq!(
        res.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(res.header("x-content-type-options"), Some("nosniff"));

    // direct route: 405 before auth
    let res = request(addr, "POST /version HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 405);
    assert_eq!(res.header("allow"), Some("GET"));
    assert!(res.header("content-type").is_none());

    // plain OPTIONS: 405 with reversed Allow list on multi-method paths
    let res = request(addr, "OPTIONS /version HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 405);
    assert_eq!(res.header("allow"), Some("GET"));

    // mounted route: auth first, then method check
    let res = request(addr, "PATCH /proxies/sel HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 401);

    let res = request(
        addr,
        "DELETE /proxies HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer s3cr3t\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 405);
    assert_eq!(res.header("allow"), Some("GET"));

    let res = request(
        addr,
        "PATCH /proxies/sel HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer s3cr3t\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 405);
    assert_eq!(res.header("allow"), Some("GET"));
    let allows: Vec<&str> = res
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("allow"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(allows, vec!["GET", "PUT"]);

    // --- proxies view ---------------------------------------------------
    let res = request(addr, &authed("/proxies")).await;
    assert_eq!(res.status, 200);
    // reference writes proxies via w.Write: Go sniffs JSON as text/plain
    assert_eq!(
        res.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    let view = res.json();
    let proxies = &view["proxies"];
    assert_eq!(proxies["GLOBAL"]["type"], "Fallback");
    assert_eq!(proxies["GLOBAL"]["udp"], true);
    assert_eq!(proxies["GLOBAL"]["now"], "direct-out");
    assert_eq!(proxies["GLOBAL"]["all"], serde_json::json!(["sel"]));
    assert_eq!(proxies["direct-out"]["type"], "Direct");
    assert_eq!(proxies["backup"]["type"], "Direct");
    assert_eq!(proxies["sel"]["type"], "Selector");
    assert_eq!(proxies["sel"]["now"], "direct-out");
    assert_eq!(
        proxies["sel"]["all"],
        serde_json::json!(["direct-out", "backup"])
    );

    let res = request(addr, &authed("/proxies/sel")).await;
    assert_eq!(res.status, 200);
    assert_eq!(
        res.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    let info = serde_json::from_slice::<Value>(&res.body).expect("proxy info");
    assert_eq!(info["type"], "Selector");
    assert_eq!(info["now"], "direct-out");

    let res = request(addr, &authed("/proxies/nope")).await;
    assert_eq!(res.status, 404);
    assert_eq!(res.json()["message"], "Resource not found");

    // --- selector switching --------------------------------------------
    let put = |body: &str| {
        format!(
            "PUT /proxies/sel HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let res = request(addr, &put(r#"{"name":"backup"}"#)).await;
    assert_eq!(res.status, 204);
    assert!(res.header("content-length").is_none());
    let res = request(addr, &authed("/proxies/sel")).await;
    let info = serde_json::from_slice::<Value>(&res.body).expect("proxy info");
    assert_eq!(info["now"], "backup");

    let res = request(addr, &put(r#"{"name":"missing"}"#)).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json()["message"], "Selector update error: not found");

    let res = request(addr, &put(r#"{"name":123}"#)).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json()["message"], "Body invalid");

    let res = request(addr, &put("xx")).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json()["message"], "Body invalid");

    let body = r#"{"name":"x"}"#;
    let res = request(
        addr,
        &format!(
            "PUT /proxies/direct-out HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json()["message"], "Must be a Selector");

    // --- delay ----------------------------------------------------------
    let res = request(addr, &authed("/proxies/sel/delay")).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json()["message"], "Body invalid");

    let res = request(addr, &authed("/proxies/sel/delay?timeout=0")).await;
    assert_eq!(res.status, 504);
    assert_eq!(res.json()["message"], "Timeout");

    let res = request(
        addr,
        &authed("/proxies/sel/delay?timeout=500&url=ftp%3A%2F%2Fexample.com%2Fx"),
    )
    .await;
    assert_eq!(res.status, 503);
    assert_eq!(res.json()["message"], "An error occurred in the delay test");

    // --- keep-alive: two requests on one connection ---------------------
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let res = send(&mut stream, &authed("/version")).await;
    assert_eq!(res.status, 200);
    let res = send(&mut stream, &authed("/version")).await;
    assert_eq!(res.status, 200);

    instance.shutdown();
}

#[tokio::test]
async fn providers_configs_and_mode() {
    let config = serde_json::json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:0",
            "secret": SECRET
        }},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "direct", "tag": "out"}],
        "route": {
            "final": "out",
            "rules": [
                {"clash_mode": ["global"], "outbound": "out"}
            ]
        }
    });
    let instance = core_runtime::start(&config).await.expect("start");
    let addr = instance.clash_api_addr().expect("clash-api bound");

    // --- providers: the reference has no provider runtime either --------
    let res = request(addr, &authed("/providers/proxies")).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["providers"], serde_json::json!({}));
    let res = request(addr, &authed("/providers/rules")).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["providers"], serde_json::json!([]));

    // --- GET /configs reports the live mode -----------------------------
    let res = request(addr, &authed("/configs")).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["mode"], "rule");

    // --- PATCH /configs switches it ------------------------------------
    let patch = |mode: &str| {
        let body = format!("{{\"mode\":\"{mode}\"}}");
        format!(
            "PATCH /configs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let res = request(addr, &patch("global")).await;
    assert_eq!(res.status, 204, "a mode switch answers 204");
    let res = request(addr, &authed("/configs")).await;
    assert_eq!(res.json()["mode"], "global");

    let res = request(addr, &patch("script")).await;
    assert_eq!(res.status, 400, "an unknown mode is a bad request");
    let res = request(addr, &authed("/configs")).await;
    assert_eq!(
        res.json()["mode"],
        "global",
        "the mode survived the refusal"
    );

    // --- PUT /configs is a no-op with 204, like the reference ----------
    let res = request(
        addr,
        &format!("PUT /configs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\nContent-Length: 0\r\n\r\n"),
    )
    .await;
    assert_eq!(res.status, 204);
    instance.shutdown();
}

/// A websocket upgrade request: the headers a browser sends.
fn ws_request(path: &str, auth: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: x\r\n{auth}Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

/// One server text frame, decoded.
async fn read_frame(stream: &mut TcpStream) -> Value {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.expect("frame head");
    assert_eq!(head[0], 0x81, "FIN + text opcode");
    assert_eq!(head[1] & 0x80, 0, "server frames are unmasked");
    let len = match head[1] & 0x7f {
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await.expect("len16");
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).await.expect("len64");
            u64::from_be_bytes(ext) as usize
        }
        short => short as usize,
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.expect("frame body");
    serde_json::from_slice(&payload).expect("frame is JSON")
}

#[tokio::test]
async fn streaming_endpoints_upgrade_to_websocket() {
    let config = serde_json::json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:0",
            "secret": SECRET
        }},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "direct", "tag": "direct-out"}],
        "route": {"final": "direct-out"}
    });
    let instance = core_runtime::start(&config).await.expect("start");
    let addr = instance.clash_api_addr().expect("clash-api bound");

    // --- /connections: handshake, then a snapshot frame ----------------
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(ws_request("/connections?token=s3cr3t&interval=50", "").as_bytes())
        .await
        .expect("write upgrade");
    let res = read_response(&mut stream).await;
    assert_eq!(res.status, 101);
    assert_eq!(res.header("upgrade"), Some("websocket"));
    assert_eq!(
        res.header("sec-websocket-accept"),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "the RFC 6455 1.3 sample key"
    );
    // the reference hijacks before it can write the CORS middleware's
    // headers, so the 101 carries none of them
    assert_eq!(res.header("access-control-allow-origin"), None);
    let snapshot = read_frame(&mut stream).await;
    assert!(snapshot["connections"].is_array(), "{snapshot}");
    assert!(snapshot.get("downloadTotal").is_some(), "{snapshot}");

    // --- /traffic: Bearer auth, one frame per second -------------------
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            ws_request("/traffic", &format!("Authorization: Bearer {SECRET}\r\n")).as_bytes(),
        )
        .await
        .expect("write upgrade");
    let res = read_response(&mut stream).await;
    assert_eq!(res.status, 101);
    let traffic = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
        .await
        .expect("traffic frame within the interval");
    assert!(
        traffic.get("up").is_some() && traffic.get("down").is_some(),
        "{traffic}"
    );

    // --- /logs: the level is checked before the handshake --------------
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(ws_request("/logs?level=bogus&token=s3cr3t", "").as_bytes())
        .await
        .expect("write upgrade");
    let res = read_response(&mut stream).await;
    assert_eq!(res.status, 400, "a bad level never upgrades");

    // --- a broken handshake is refused by the upgrader -----------------
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            "GET /logs?token=s3cr3t HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\n\r\n"
                .as_bytes(),
        )
        .await
        .expect("write upgrade");
    let res = read_response(&mut stream).await;
    assert_eq!(res.status, 400);
    assert_eq!(
        res.text(),
        "handshake error: bad \"Sec-WebSocket-Key\" header"
    );

    // --- auth runs before the upgrade ----------------------------------
    let res = request(addr, &ws_request("/connections", "")).await;
    assert_eq!(res.status, 401, "no token, no handshake");
    assert_eq!(res.json()["message"], "Unauthorized");

    instance.shutdown();
}

/// A stored (uncompressed) zip holding `files` — a dashboard bundle, ready
/// to be served to the download.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, body) in files {
        let offset = out.len() as u32;
        // local header + payload
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        // central directory record
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // version made by
        central.extend_from_slice(&0u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // stored
        central.extend_from_slice(&0u16.to_le_bytes()); // time
        central.extend_from_slice(&0u16.to_le_bytes()); // date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc
        central.extend_from_slice(&(body.len() as u32).to_le_bytes());
        central.extend_from_slice(&(body.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // central disk
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

/// One-shot HTTP server answering every request with `body`.
async fn serve_once(body: Vec<u8>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.flush().await;
        }
    });
    addr
}

#[tokio::test]
async fn external_ui_is_downloaded_and_mounted_under_ui() {
    let bundle = stored_zip(&[
        ("bundle/index.html", b"<!doctype html><title>dash</title>"),
        ("bundle/static/app.js", b"window.dash = 1;\n"),
    ]);
    let origin = serve_once(bundle).await;

    let dir = std::env::temp_dir().join(format!("tachyon-ui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = serde_json::json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:0",
            "external_ui": dir.to_string_lossy(),
            "external_ui_download_url": format!("http://{origin}/ui.zip")
        }},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "direct", "tag": "direct-out"}],
        "route": {"final": "direct-out"}
    });
    // the bundle is unpacked before the controller starts listening
    let instance = core_runtime::start(&config).await.expect("start");
    let addr = instance.clash_api_addr().expect("clash-api bound");

    assert_eq!(
        std::fs::read(dir.join("index.html")).expect("index.html"),
        b"<!doctype html><title>dash</title>"
    );
    assert_eq!(
        std::fs::read(dir.join("static/app.js")).expect("app.js"),
        b"window.dash = 1;\n",
        "the shared top directory was trimmed"
    );

    // a navigation is sent to the dashboard, an API call is not
    let res = request(addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 307);
    assert_eq!(res.header("location"), Some("/ui/"));
    let res = request(
        addr,
        "GET / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n",
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["hello"], "clash");

    // /ui moves permanently, /ui/ and its assets are served from the bundle
    let res = request(addr, "GET /ui HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 301);
    assert_eq!(res.header("location"), Some("/ui/"));

    let res = request(addr, "GET /ui/ HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("content-type"), Some("text/html; charset=utf-8"));
    assert!(res.text().contains("<title>dash</title>"), "{}", res.text());

    let res = request(addr, "GET /ui/static/app.js HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 200);
    assert_eq!(
        res.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );

    // nothing outside the mount, and no single-page fallback hiding a miss
    let res = request(addr, "GET /app.js HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 404);
    let res = request(addr, "GET /ui/missing.js HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(res.status, 404);

    instance.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
