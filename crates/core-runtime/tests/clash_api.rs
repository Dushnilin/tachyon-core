//! F4 slice: `experimental.clash_api` REST surface — auth, CORS, proxies
//! view, selector switching, delay errors. Behaviour mirrors the reference
//! (`sing-box 1.14.2-lx.3`, probed live).

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
