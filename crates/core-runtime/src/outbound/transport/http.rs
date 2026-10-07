//! v2ray "http" transport: on plain TCP it is HTTP/1.1 with a raw streaming
//! body (no framing, terminated by connection close); over TLS it negotiates
//! ALPN `h2` and streams the body through one HTTP/2 DATA pipe. Mirrors
//! sing-box `transport/v2rayhttp` (default method PUT, v2fly default
//! authority `www.example.com` on the h2 path).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::AnyStream;
use crate::outbound::shadowsocks::crypto::random_bytes;

use super::authority;
use super::h2io::{H2Io, H2Stream, rdbg};

/// Headers that must not be forwarded on HTTP/2 (connection-scoped + host
/// comes from the request authority).
const H2_SKIP: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect(
    stream: AnyStream,
    secure: bool,
    server: &str,
    port: u16,
    hosts: &[String],
    path: &str,
    method: &str,
    headers: &[(String, String)],
) -> io::Result<AnyStream> {
    if secure {
        connect_h2(stream, hosts, path, method, headers).await
    } else {
        connect_h1(stream, server, port, hosts, path, method, headers)
    }
}

fn pick_host(hosts: &[String], default: &str) -> io::Result<String> {
    match hosts {
        [] => Ok(default.to_string()),
        [only] => Ok(only.clone()),
        many => {
            let mut b = [0u8; 1];
            random_bytes(&mut b)?;
            Ok(many[usize::from(b[0]) % many.len()].clone())
        }
    }
}

async fn connect_h2(
    stream: AnyStream,
    hosts: &[String],
    path: &str,
    method: &str,
    headers: &[(String, String)],
) -> io::Result<AnyStream> {
    let (send_request, connection) = super::h2io::client_builder()
        .handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("http: h2 handshake: {e}")))?;
    let conn_task = tokio::spawn(async move {
        let _ = rdbg::counted(connection).await;
    });
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("http: h2 ready: {e}")))?;

    // v2fly compatibility: an empty host list means www.example.com.
    let authority = pick_host(hosts, "www.example.com")?;
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("https://{authority}{path}"));
    for (name, value) in headers {
        if H2_SKIP.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder
        .body(())
        .map_err(|e| io::Error::other(format!("http: build request: {e}")))?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("http: send_request: {e}")))?;

    Ok(Box::new(H2Io {
        h2: H2Stream::new(response, send, conn_task),
    }))
}

fn connect_h1(
    stream: AnyStream,
    server: &str,
    port: u16,
    hosts: &[String],
    path: &str,
    method: &str,
    headers: &[(String, String)],
) -> io::Result<AnyStream> {
    let host = pick_host(hosts, &authority(server, port))?;
    Ok(Box::new(Http1Stream {
        inner: stream,
        method: method.to_string(),
        path: path.to_string(),
        headers: headers.to_vec(),
        host,
        head_done: false,
        stage: None,
        resp: RespState::Head(Vec::new()),
    }))
}

struct Stage {
    buf: Vec<u8>,
    pos: usize,
    report: usize,
}

enum RespState {
    Head(Vec<u8>),
    Ready { cache: Vec<u8> },
}

pub(crate) struct Http1Stream {
    inner: AnyStream,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    host: String,
    /// Request head already staged — every later write is raw payload.
    head_done: bool,
    /// Head + first payload pending flush (HTTP/1.1 one-shot request write).
    stage: Option<Stage>,
    resp: RespState,
}

fn write_head(
    out: &mut Vec<u8>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    host: &str,
) {
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    let mut has_host = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !has_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(host.as_bytes());
        out.push(b'\r');
        out.push(b'\n');
    }
    out.extend_from_slice(b"\r\n");
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Validate `HTTP/1.x <code> ...`; returns the status text used in errors.
fn check_status(head: &[u8]) -> io::Result<()> {
    let text = String::from_utf8_lossy(head);
    let status_line = text.split("\r\n").next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let code = parts.next().unwrap_or("");
    let detail = parts.next().unwrap_or("");
    if code != "200" {
        return Err(io::Error::other(format!(
            "v2ray-http: unexpected status: {code} {detail}"
        )));
    }
    Ok(())
}

impl AsyncRead for Http1Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.resp {
                RespState::Head(acc) => {
                    if let Some(end) = find_head_end(acc) {
                        check_status(&acc[..end])?;
                        let cache = acc[end..].to_vec();
                        this.resp = RespState::Ready { cache };
                        continue;
                    }
                    let mut tmp = [0u8; 8192];
                    let mut probe = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut probe))?;
                    if probe.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::other(
                            "v2ray-http: connection closed before response",
                        )));
                    }
                    acc.extend_from_slice(probe.filled());
                }
                RespState::Ready { cache } => {
                    if !cache.is_empty() {
                        let n = out.remaining().min(cache.len());
                        out.put_slice(&cache[..n]);
                        cache.drain(..n);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, out);
                }
            }
        }
    }
}

impl AsyncWrite for Http1Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            if let Some(stage) = &mut this.stage {
                if stage.pos < stage.buf.len() {
                    let n =
                        ready!(Pin::new(&mut this.inner).poll_write(cx, &stage.buf[stage.pos..]))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::other("v2ray-http: write stalled")));
                    }
                    stage.pos += n;
                    continue;
                }
                let report = this.stage.take().map_or(0, |s| s.report);
                return Poll::Ready(Ok(report));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if this.head_done {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            let mut v = Vec::with_capacity(128 + buf.len());
            write_head(&mut v, &this.method, &this.path, &this.headers, &this.host);
            v.extend_from_slice(buf);
            this.head_done = true;
            this.stage = Some(Stage {
                buf: v,
                pos: 0,
                report: buf.len(),
            });
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(stage) = &mut this.stage {
            while stage.pos < stage.buf.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &stage.buf[stage.pos..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::other("v2ray-http: write stalled")));
                }
                stage.pos += n;
            }
            this.stage = None;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(stage) = &mut this.stage {
            while stage.pos < stage.buf.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &stage.buf[stage.pos..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::other("v2ray-http: write stalled")));
                }
                stage.pos += n;
            }
            this.stage = None;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_includes_host_once() {
        let mut out = Vec::new();
        write_head(
            &mut out,
            "PUT",
            "/tunnel",
            &[("X-Test".into(), "1".into())],
            "example.com:80",
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("PUT /tunnel HTTP/1.1\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert_eq!(text.matches("Host: ").count(), 1);
        assert!(text.contains("Host: example.com:80\r\n"));

        let mut out = Vec::new();
        write_head(&mut out, "PUT", "/", &[("host".into(), "cfg".into())], "x");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("host: cfg\r\n"));
        assert!(!text.contains("Host: x\r\n"));
    }

    #[test]
    fn status_codes() {
        assert!(check_status(b"HTTP/1.1 200 OK\r\n\r\n").is_ok());
        assert!(check_status(b"HTTP/1.0 200 Connection established\r\n\r\n").is_ok());
        let err = check_status(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap_err();
        assert!(err.to_string().contains("403 Forbidden"));
    }

    #[test]
    fn head_end_finder() {
        assert_eq!(find_head_end(b"a\r\n\r\nb"), Some(5));
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(19));
        assert_eq!(find_head_end(b"nope"), None);
    }
}
