//! Minimal HTTP/1.1 client for the runtime's own fetches: remote rule-sets,
//! provider updates and the clash-api UI download. It dials through the router
//! so a `detour` (or the deprecated `download_detour`) reaches the same
//! outbounds as user traffic.
//!
//! Scope: HTTP/1.1 with `content-length`/chunked bodies and redirect
//! following. HTTP/2 is not negotiated — the reference also falls back to
//! HTTP/1.1 for these fetches unless an `h2` ALPN is forced.

use std::io;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::AnyStream;
use crate::route::Target;
use crate::tls_client::TlsOptions;

/// Reference `defaultHTTPTimeout` + `rule-set` fetch budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REDIRECTS: usize = 10;
const MAX_BODY: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(raw: &str) -> io::Result<Self> {
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| io::Error::other(format!("invalid URL {raw:?}")))?;
        let secure = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            other => {
                return Err(io::Error::other(format!(
                    "unsupported URL scheme {other:?}"
                )));
            }
        };
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        // strip userinfo and the fragment; the path is kept verbatim
        let authority = match authority.rsplit_once('@') {
            Some((_, host)) => host,
            None => authority,
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => (
                host.to_string(),
                port.parse()
                    .map_err(|_| io::Error::other(format!("invalid port in URL {raw:?}")))?,
            ),
            _ => (authority.to_string(), if secure { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(io::Error::other(format!("invalid URL {raw:?}")));
        }
        let path = match path.find('#') {
            Some(at) => &path[..at],
            None => path,
        };
        let path = if path.is_empty() { "/" } else { path };
        Ok(Self {
            secure,
            host: host.trim_matches(['[', ']']).to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// `host[:port]` for the `Host` header (the default port stays implicit).
    pub fn authority(&self) -> String {
        let default = if self.secure { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolve a `Location` header against this URL.
    pub fn join(&self, location: &str) -> io::Result<Url> {
        if location.contains("://") {
            return Url::parse(location);
        }
        let base = if self.secure { "https" } else { "http" };
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{base}://{rest}"));
        }
        if location.starts_with('/') {
            return Url::parse(&format!("{base}://{}{location}", self.authority()));
        }
        let directory = match self.path.rfind('/') {
            Some(at) => &self.path[..=at],
            None => "/",
        };
        Url::parse(&format!(
            "{base}://{}{directory}{location}",
            self.authority()
        ))
    }
}

/// `option.HTTPClientOptions`, reduced to the fields the fetches honour.
#[derive(Debug, Clone, Default)]
pub struct HttpClient {
    /// Outbound tag the request is dialed through (`None` = router default).
    pub detour: Option<String>,
    pub tls: Option<std::sync::Arc<TlsOptions>>,
    pub headers: Vec<(String, String)>,
}

impl HttpClient {
    pub fn from_config(obj: Option<&Value>, at: &str) -> anyhow::Result<Self> {
        let Some(obj) = obj.and_then(Value::as_object) else {
            return Ok(Self::default());
        };
        let detour = obj
            .get("detour")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty())
            .map(str::to_string);
        let tls = match obj.get("tls").and_then(Value::as_object) {
            Some(tls) => {
                // reuse the outbound TLS parser: only `tls` matters here
                let mut wrapper = serde_json::Map::new();
                wrapper.insert("tls".into(), Value::Object(tls.clone()));
                let server = obj
                    .get("server_name")
                    .and_then(Value::as_str)
                    .unwrap_or("localhost");
                TlsOptions::from_outbound(&wrapper, server, at)?.map(std::sync::Arc::new)
            }
            None => None,
        };
        let headers = obj
            .get("headers")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| {
                        let pair = entry.as_object()?;
                        let key = pair.get("key")?.as_str()?.to_string();
                        let value = pair.get("value")?.as_str()?.to_string();
                        Some((key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            detour,
            tls,
            headers,
        })
    }

    /// `GET url` with redirects followed; the response body is bounded.
    pub async fn get(
        &self,
        router: &crate::route::Router,
        url: &str,
        extra_headers: &[(String, String)],
    ) -> io::Result<Response> {
        let mut current = Url::parse(url)?;
        for _ in 0..=MAX_REDIRECTS {
            let response = self.request(router, &current, extra_headers).await?;
            match response.status {
                301 | 302 | 303 | 307 | 308 => {
                    let Some(location) = response.header("location") else {
                        return Ok(response);
                    };
                    current = current.join(location)?;
                }
                _ => return Ok(response),
            }
        }
        Err(io::Error::other(format!(
            "too many redirects fetching {url:?}"
        )))
    }

    async fn request(
        &self,
        router: &crate::route::Router,
        url: &Url,
        extra_headers: &[(String, String)],
    ) -> io::Result<Response> {
        let host = url.host.clone();
        let target = Target::Domain(host, url.port);
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, self.dial(router, &target))
            .await
            .map_err(|_| io::Error::other(format!("connect to {} timed out", url.authority())))??;

        let stream: AnyStream = if url.secure {
            match &self.tls {
                Some(tls) => Box::new(tls.connect_stream(conn, &[b"http/1.1"]).await?),
                None => crate::tls_client::wrap_probe_stream(conn, &url.host).await?,
            }
        } else {
            conn
        };

        let mut head = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sing-box {}\r\nAccept: */*\r\n",
            url.path,
            url.authority(),
            env!("CARGO_PKG_VERSION")
        );
        for (key, value) in self.headers.iter().chain(extra_headers) {
            head.push_str(&format!("{key}: {value}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");

        let mut stream = stream;
        tokio::time::timeout(IO_TIMEOUT, async {
            stream.write_all(head.as_bytes()).await?;
            stream.flush().await?;
            read_response(&mut stream).await
        })
        .await
        .map_err(|_| io::Error::other(format!("fetching {} timed out", url.path)))?
    }

    async fn dial(&self, router: &crate::route::Router, target: &Target) -> io::Result<AnyStream> {
        let conn = match &self.detour {
            Some(tag) => match router.index_of(tag) {
                Some(index) => router.connect_index(index, target).await,
                None => {
                    return Err(io::Error::other(format!(
                        "http client detour {tag:?} not found"
                    )));
                }
            },
            None => router.connect(target).await,
        }?;
        conn.into_plain()
    }
}

async fn read_response(stream: &mut AnyStream) -> io::Result<Response> {
    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    // head
    let head_end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::other("connection closed before response head"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = find_head_end(&buffer) {
            break at;
        }
        if buffer.len() > 64 * 1024 {
            return Err(io::Error::other("response head too large"));
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    // the head ends with the CRLFCRLF separator itself
    let rest = buffer[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::other(format!("bad status line {status_line:?}")))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let chunked = find("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let length = find("content-length").and_then(|v| v.parse::<usize>().ok());

    let body = if chunked {
        decode_chunked(rest, stream).await?
    } else {
        let mut body = rest;
        if let Some(length) = length {
            while body.len() < length {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            body.truncate(length);
        } else {
            loop {
                if body.len() > MAX_BODY {
                    return Err(io::Error::other("response body too large"));
                }
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
        }
        body
    };
    if body.len() > MAX_BODY {
        return Err(io::Error::other("response body too large"));
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// `transfer-encoding: chunked`: size line, data, CRLF, until a zero chunk.
async fn decode_chunked(initial: Vec<u8>, stream: &mut AnyStream) -> io::Result<Vec<u8>> {
    let mut buffer = initial;
    let mut body = Vec::new();
    let mut scratch = [0u8; 8 * 1024];
    loop {
        let (size, start) = loop {
            let Some(at) = find_crlf(&buffer) else {
                let read = stream.read(&mut scratch).await?;
                if read == 0 {
                    return Err(io::Error::other("truncated chunked body"));
                }
                buffer.extend_from_slice(&scratch[..read]);
                continue;
            };
            let line = String::from_utf8_lossy(&buffer[..at]).to_string();
            let token = line.split(';').next().unwrap_or("").trim().to_string();
            let size = usize::from_str_radix(&token, 16)
                .map_err(|_| io::Error::other(format!("bad chunk size {line:?}")))?;
            break (size, at + 2);
        };
        if size == 0 {
            return Ok(body);
        }
        let needed = start + size + 2;
        while buffer.len() < needed {
            let read = stream.read(&mut scratch).await?;
            if read == 0 {
                return Err(io::Error::other("truncated chunked body"));
            }
            buffer.extend_from_slice(&scratch[..read]);
        }
        body.extend_from_slice(&buffer[start..start + size]);
        buffer.drain(..needed);
        if body.len() > MAX_BODY {
            return Err(io::Error::other("response body too large"));
        }
    }
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const CRLF: &str = "\r\n";

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("url")
    }

    #[test]
    fn url_parsing() {
        let parsed = url("https://example.com/a/b?c=d");
        assert!(parsed.secure);
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/a/b?c=d");
        assert_eq!(parsed.authority(), "example.com");
        assert_eq!(url("http://1.2.3.4:8080").port, 8080);
        assert_eq!(url("http://1.2.3.4:8080").authority(), "1.2.3.4:8080");
        assert_eq!(url("https://[::1]:8443/x").host, "::1");
        assert_eq!(url("https://host").path, "/");
        assert!(Url::parse("ftp://host/x").is_err());
        assert!(Url::parse("host/x").is_err());
    }

    #[test]
    fn url_join() {
        let base = url("https://a.test/x/y?q=1");
        assert_eq!(base.join("/abs").unwrap().path, "/abs");
        assert_eq!(base.join("rel").unwrap().path, "/x/rel");
        assert_eq!(base.join("//b.test/z").unwrap().host, "b.test");
        assert_eq!(base.join("https://c.test/w").unwrap().host, "c.test");
    }

    #[test]
    fn client_config_parsing() {
        let value = serde_json::json!({
            "detour": "proxy",
            "headers": [{"key": "X-Test", "value": "1"}]
        });
        let client = HttpClient::from_config(Some(&value), "test").expect("client");
        assert_eq!(client.detour.as_deref(), Some("proxy"));
        assert_eq!(
            client.headers,
            vec![("X-Test".to_string(), "1".to_string())]
        );
        let insecure = serde_json::json!({"tls": {"enabled": true, "insecure": true}});
        let client = HttpClient::from_config(Some(&insecure), "test").expect("client");
        assert!(client.tls.is_some());
        let empty = HttpClient::from_config(None, "test").expect("client");
        assert!(empty.detour.is_none() && empty.tls.is_none());
    }

    #[test]
    fn chunked_body_decoding() {
        // 5 "hello", 6 " world", then the terminating zero chunk
        let data: Vec<u8> = ["5", "hello", "6", " world", "0", ""]
            .join(CRLF)
            .into_bytes();
        let mut buffer = data.clone();
        let mut body = Vec::new();
        for _ in 0..4 {
            let Some(at) = find_crlf(&buffer) else {
                panic!("no CRLF in {:?}", String::from_utf8_lossy(&buffer));
            };
            let line = String::from_utf8_lossy(&buffer[..at]).to_string();
            let size = usize::from_str_radix(line.trim(), 16).expect("size");
            if size == 0 {
                break;
            }
            let start = at + 2;
            let needed = start + size + 2;
            body.extend_from_slice(&buffer[start..start + size]);
            buffer.drain(..needed);
        }
        assert_eq!(body, b"hello world");
    }

    async fn serve_once(response: String) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        (format!("http://{addr}/ruleset.srs"), handle)
    }

    async fn test_router() -> Arc<crate::route::Router> {
        crate::route::Router::new(&serde_json::json!({
            "log": {"level": "error"},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .expect("router")
    }

    #[tokio::test]
    async fn get_reads_status_headers_and_body() {
        let router = test_router().await;
        let (url, server) = serve_once(
            [
                "HTTP/1.1 200 OK",
                "Content-Length: 5",
                "Etag: \"abc\"",
                "",
                "hello",
            ]
            .join(CRLF),
        )
        .await;
        let response = HttpClient::default()
            .get(&router, &url, &[])
            .await
            .expect("get");
        server.await.ok();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header("etag"), Some("\"abc\""));
    }

    #[tokio::test]
    async fn chunked_bodies_are_decoded() {
        let router = test_router().await;
        let (url, server) = serve_once(
            [
                "HTTP/1.1 200 OK",
                "Transfer-Encoding: chunked",
                "",
                "5",
                "hello",
                "6",
                " world",
                "0",
                "",
                "",
            ]
            .join(CRLF),
        )
        .await;
        let response = HttpClient::default()
            .get(&router, &url, &[])
            .await
            .expect("get");
        server.await.ok();
        assert_eq!(response.body, b"hello world");
    }

    #[tokio::test]
    async fn redirects_are_followed() {
        let router = test_router().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let target = format!("http://{addr}/final.srs");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept");
            let mut head = [0u8; 1024];
            let _ = first.read(&mut head).await;
            let _ = first
                .write_all(
                    format!("HTTP/1.1 302 Found{CRLF}Location: {target}{CRLF}Content-Length: 0{CRLF}{CRLF}")
                        .as_bytes(),
                )
                .await;
            let (mut second, _) = listener.accept().await.expect("accept");
            let _ = second.read(&mut head).await;
            let _ = second
                .write_all(
                    format!("HTTP/1.1 200 OK{CRLF}Content-Length: 2{CRLF}{CRLF}ok").as_bytes(),
                )
                .await;
        });
        let response = HttpClient::default()
            .get(&router, &format!("http://{addr}/start.srs"), &[])
            .await
            .expect("get");
        server.await.ok();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }
}
