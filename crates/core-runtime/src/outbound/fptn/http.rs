//! FPTN control plane — `POST /api/v1/login` and `GET /api/v1/dns` over the
//! pinned TLS session.
//!
//! The reference `ApiClient` posts `{"username","password"}` JSON, retries
//! 503 up to five times and stores `access_token` for the `Authorization:
//! Bearer` header of the WebSocket handshake; `ConnectionManager::GetDns`
//! fetches the provider resolver with an unauthenticated GET (five attempts,
//! 100ms apart). There is no HTTP client dependency in this crate, so the
//! exchanges are hand-rolled HTTP/1.1; the response body is either
//! `Content-Length`-framed, chunked, or read to EOF.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use crate::inbound::AnyStream;

const LOGIN_PATH: &str = "/api/v1/login";
const DNS_PATH: &str = "/api/v1/dns";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_DELAY: Duration = Duration::from_millis(500);
/// Reference `GetDns` retry spacing.
const DNS_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const RETRIES: usize = 5;
/// Reference `FPTN_SERVER_DEFAULT_ADDRESS_IP6` (CMakeLists.txt) — used when
/// the response omits `dns_ipv6`.
const DEFAULT_DNS_IPV6: &str = "fc00:1::1";

/// Full login exchange: TLS (session id + pin) → POST → token extraction.
/// Returns the JWT bearer token.
pub(crate) async fn login(
    server: SocketAddr,
    sni: &str,
    md5: &str,
    username: &str,
    password: &str,
    obfuscation: super::Obfuscation,
) -> io::Result<String> {
    let body = serde_json::json!({ "username": username, "password": password }).to_string();
    let host = server.to_string();
    let mut last_503 = 0usize;
    for attempt in 1..=RETRIES {
        let tls = super::tls::connect(server, sni, md5, obfuscation).await?;
        let mut stream: AnyStream = Box::new(tls);
        let (status, payload) = match timeout(
            LOGIN_TIMEOUT,
            post_json(&mut stream, &host, LOGIN_PATH, &body),
        )
        .await
        {
            Err(_) => {
                // A silent server right after the handshake is the
                // obfuscator-disarm race (see `tls::connect`); a fresh
                // connection usually wins it.
                if attempt < RETRIES {
                    sleep(RETRY_DELAY).await;
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fptn login: request timed out",
                ));
            }
            Ok(result) => result?,
        };
        match status {
            200 => return extract_token(&payload),
            401 | 403 => {
                return Err(io::Error::other(format!(
                    "fptn login: credentials rejected (HTTP {status})"
                )));
            }
            503 => {
                last_503 = attempt;
                if attempt < RETRIES {
                    sleep(RETRY_DELAY).await;
                    continue;
                }
            }
            _ => {}
        }
        return Err(io::Error::other(format!(
            "fptn login: unexpected HTTP {status}: {}",
            snippet(&payload)
        )));
    }
    Err(io::Error::other(format!(
        "fptn login: service unavailable (HTTP 503 after {last_503} attempts)"
    )))
}

/// Provider resolver addresses: reference `ConnectionManager::GetDns` —
/// unauthenticated `GET /api/v1/dns`, five attempts with 100ms spacing;
/// returns `(dns_ipv4, dns_ipv6)`.
pub(crate) async fn get_dns(
    server: SocketAddr,
    sni: &str,
    md5: &str,
    obfuscation: super::Obfuscation,
) -> io::Result<(String, String)> {
    let host = server.to_string();
    let mut last = String::from("not attempted");
    for attempt in 1..=RETRIES {
        if attempt > 1 {
            sleep(DNS_RETRY_DELAY).await;
        }
        let outcome = async {
            let tls = super::tls::connect(server, sni, md5, obfuscation).await?;
            let mut stream: AnyStream = Box::new(tls);
            let (status, payload) = timeout(DNS_TIMEOUT, get(&mut stream, &host, DNS_PATH))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))??;
            if status != 200 {
                return Err(io::Error::other(format!(
                    "HTTP {status}: {}",
                    snippet(&payload)
                )));
            }
            parse_dns(&payload)
        }
        .await;
        match outcome {
            Ok(dns) => return Ok(dns),
            Err(e) => last = e.to_string(),
        }
    }
    Err(io::Error::other(format!(
        "fptn dns: unavailable after {RETRIES} attempts: {last}"
    )))
}

/// POST one JSON body over an established stream; `(status, body)`.
pub(crate) async fn post_json(
    stream: &mut AnyStream,
    host: &str,
    path: &str,
    body: &str,
) -> io::Result<(u16, String)> {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_response(stream).await
}

/// GET one path over an established stream; `(status, body)`.
pub(crate) async fn get(
    stream: &mut AnyStream,
    host: &str,
    path: &str,
) -> io::Result<(u16, String)> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_response(stream).await
}

async fn read_response(stream: &mut AnyStream) -> io::Result<(u16, String)> {
    let head = read_head(stream).await?;
    let status = parse_status(&head)?;
    let (content_length, chunked) = parse_length_headers(&head);
    let payload = if chunked {
        read_chunked(stream).await?
    } else if let Some(len) = content_length {
        read_exact(stream, len).await?
    } else {
        read_to_eof(stream).await?
    };
    Ok((status, payload))
}

fn extract_token(payload: &str) -> io::Result<String> {
    let value: Value = serde_json::from_str(payload)
        .map_err(|e| io::Error::other(format!("fptn login: invalid JSON response: {e}")))?;
    value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::other(format!(
                "fptn login: response has no access_token: {}",
                snippet(payload)
            ))
        })
}

/// `{"dns": "<v4>", "dns_ipv6": "<v6>" }` — the server always sends both
/// (`Server::HandleApiDns`); a missing/empty `dns_ipv6` falls back to the
/// reference default.
fn parse_dns(payload: &str) -> io::Result<(String, String)> {
    let value: Value = serde_json::from_str(payload)
        .map_err(|e| io::Error::other(format!("fptn dns: invalid JSON response: {e}")))?;
    let dns = value
        .get("dns")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            io::Error::other(format!(
                "fptn dns: response has no dns: {}",
                snippet(payload)
            ))
        })?
        .to_owned();
    let dns_ipv6 = value
        .get("dns_ipv6")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_DNS_IPV6)
        .to_owned();
    Ok((dns, dns_ipv6))
}

fn snippet(payload: &str) -> &str {
    let payload = payload.trim();
    if payload.len() <= 200 {
        payload
    } else {
        &payload[..200]
    }
}

fn parse_status(head: &str) -> io::Result<u16> {
    let status_line = head.lines().next().unwrap_or_default();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("fptn login: bad status line {status_line:?}")))?;
    Ok(code)
}

fn parse_length_headers(head: &str) -> (Option<usize>, bool) {
    let mut content_length = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "content-length" {
            content_length = value.trim().parse::<usize>().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    (content_length, chunked)
}

async fn read_head(stream: &mut AnyStream) -> io::Result<String> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::other("fptn login: response head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

async fn read_exact(stream: &mut AnyStream, len: usize) -> io::Result<String> {
    if len > MAX_BODY {
        return Err(io::Error::other("fptn login: response body too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn read_to_eof(stream: &mut AnyStream) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_BODY {
            return Err(io::Error::other("fptn login: response body too large"));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn read_chunked(stream: &mut AnyStream) -> io::Result<String> {
    let mut out = Vec::new();
    loop {
        let line = read_line(stream).await?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| io::Error::other(format!("fptn login: bad chunk size {line:?}")))?;
        if size == 0 {
            // Trailer section up to the final empty line (usually immediate).
            loop {
                let trailer = read_line(stream).await?;
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > MAX_BODY {
            return Err(io::Error::other("fptn login: response body too large"));
        }
        let mut buf = vec![0u8; size];
        stream.read_exact(&mut buf).await?;
        out.extend_from_slice(&buf);
        let crlf = read_line(stream).await?;
        if !crlf.is_empty() {
            return Err(io::Error::other("fptn login: missing chunk terminator"));
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

async fn read_line(stream: &mut AnyStream) -> io::Result<String> {
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            break;
        }
        if line.len() > 8192 {
            return Err(io::Error::other("fptn login: line too long"));
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Server shape (`Server::HandleApiDns`): both fields present.
    #[test]
    fn parses_dns_response() {
        let (v4, v6) =
            parse_dns(r#"{"dns": "172.20.255.1", "dns_ipv6": "fc00:1::1" }"#).expect("parse");
        assert_eq!(v4, "172.20.255.1");
        assert_eq!(v6, "fc00:1::1");
    }

    /// Missing/empty `dns_ipv6` falls back to the reference default.
    #[test]
    fn dns_ipv6_defaults_to_reference_constant() {
        let (_, v6) = parse_dns(r#"{"dns": "10.0.0.1"}"#).expect("parse");
        assert_eq!(v6, DEFAULT_DNS_IPV6);
        let (_, v6) = parse_dns(r#"{"dns": "10.0.0.1", "dns_ipv6": ""}"#).expect("parse");
        assert_eq!(v6, DEFAULT_DNS_IPV6);
    }

    #[test]
    fn dns_requires_ipv4_field() {
        assert!(parse_dns(r#"{"dns_ipv6": "fc00:1::1"}"#).is_err());
        assert!(parse_dns(r#"{"dns": ""}"#).is_err());
        assert!(parse_dns("<html>503</html>").is_err());
    }
}
