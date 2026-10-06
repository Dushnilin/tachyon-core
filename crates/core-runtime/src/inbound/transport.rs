//! Server-side transports.
//!
//! A transport takes the request off the front of the stream and leaves the
//! protocol bytes where the protocol expects to find them: after a websocket
//! handshake the rest of the connection is frames, after an httpupgrade `101`
//! it is raw. Nothing above this module knows a transport exists -- `handle`
//! gets an `AsyncRead + AsyncWrite` either way.
//!
//! Only what a listener can actually serve lives here. `grpc`, `xhttp` and `quic`
//! are still refused by the config validator with a message saying so, because a
//! listener that binds a port and then hangs on every connection is worse than one
//! that refuses to start.

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::AnyStream;
use crate::outbound::transport::WsStream;

/// Enough for any request line plus headers, and no more: a handshake is a few
/// hundred bytes, and a peer that sends more than this is not one.
const MAX_HEAD: usize = 8 * 1024;

/// What a listener wraps the connection in before the protocol reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Ws,
    HttpUpgrade,
}

impl Kind {
    fn parse(at: &str, ty: &str) -> anyhow::Result<Self> {
        Ok(match ty {
            "ws" => Kind::Ws,
            "httpupgrade" => Kind::HttpUpgrade,
            other => anyhow::bail!(
                "{at}: server transport {other} is not implemented yet (ws and \
                 httpupgrade are; grpc, xhttp and quic are not)"
            ),
        })
    }
}

#[derive(Debug)]
pub(crate) struct Transport {
    kind: Kind,
    /// Path the request line must carry. `/` when the config gave none, which is
    /// also what the reference treats an absent path as.
    path: String,
}

impl Transport {
    /// Read `transport` off a server inbound. `None` when it has none, which is
    /// the plain-TCP case every protocol has always used.
    pub(crate) fn from_inbound(obj: &Value, at: &str) -> anyhow::Result<Option<Self>> {
        let Some(transport) = obj.get("transport").filter(|t| !t.is_null()) else {
            return Ok(None);
        };
        let transport = transport
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}.transport: must be an object"))?;
        let ty = transport
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}.transport: missing type"))?;
        let kind = Kind::parse(at, ty)?;
        let path = match transport.get("path").and_then(Value::as_str) {
            None => "/".to_string(),
            Some(p) => {
                if !p.starts_with('/') {
                    anyhow::bail!("{at}.transport.path: must start with a slash, got {p:?}");
                }
                p.to_string()
            }
        };
        Ok(Some(Self { kind, path }))
    }

    /// Unwrap the request off `stream`, leaving protocol bytes behind.
    pub(crate) async fn accept(&self, stream: AnyStream) -> anyhow::Result<AnyStream> {
        let mut stream = stream;
        let head = read_head(&mut stream).await?;
        let (method, target, headers) = parse_head(&head)?;
        if !path_matches(&target, &self.path) {
            anyhow::bail!("ws: path {target:?} does not match {:?}", self.path);
        }
        match self.kind {
            Kind::Ws => {
                let key = match crate::ws::validate(&headers) {
                    Ok(key) => key,
                    Err(rejection) => {
                        // The status the reference answers with, so a browser or a
                        // scanner sees the same thing it would from sing-box.
                        use tokio::io::AsyncWriteExt as _;
                        stream.write_all(rejection.response().as_bytes()).await?;
                        stream.flush().await?;
                        anyhow::bail!("ws: {}", rejection.reason());
                    }
                };
                let _ = method;
                crate::ws::accept(&mut stream, &key).await?;
                Ok(Box::new(WsStream::server(stream)))
            }
            Kind::HttpUpgrade => {
                use tokio::io::AsyncWriteExt as _;
                // httpupgrade is the same 101 with no frames after it: the rest of
                // the connection is the protocol, byte for byte.
                stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Connection: Upgrade\r\n\
                          Upgrade: websocket\r\n\r\n",
                    )
                    .await?;
                stream.flush().await?;
                Ok(stream)
            }
        }
    }
}

/// Read up to the end of the request head, inclusive of the blank line.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("http: connection closed inside the request head");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD {
            anyhow::bail!("http: request head over {MAX_HEAD} bytes");
        }
    }
}

/// The method, the request target and the headers. Header names are kept as they
/// arrived; [`crate::ws::validate`] compares them case-insensitively.
type RequestHead = (String, String, Vec<(String, String)>);

fn parse_head(bytes: &[u8]) -> anyhow::Result<RequestHead> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("http: empty request"))?;
    let mut parts = request.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("http: no method in {request:?}"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("http: no target in {request:?}"))?
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((method, target, headers))
}

/// The request target against the configured path, query and all. A config path
/// may or may not carry a query itself; when it does, the incoming query has to
/// match too, which is what sing-box does.
fn path_matches(target: &str, configured: &str) -> bool {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    match configured.split_once('?') {
        Some((p, q)) => path == p && query == Some(q),
        None => path == configured && query.is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws_request(path: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\n\
             Host: 127.0.0.1:18443\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        )
    }

    #[test]
    fn a_request_head_is_split_into_method_target_and_headers() {
        let (method, target, headers) =
            parse_head(ws_request("/bench").as_bytes()).expect("parsed");
        assert_eq!(method, "GET");
        assert_eq!(target, "/bench");
        let find = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(find("upgrade"), Some("websocket"));
        assert_eq!(find("sec-websocket-key"), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(find("host"), Some("127.0.0.1:18443"));
    }

    #[test]
    fn the_path_has_to_match_the_configured_one() {
        assert!(path_matches("/bench", "/bench"));
        assert!(path_matches("/", "/"));
        assert!(!path_matches("/bench", "/"));
        assert!(!path_matches("/other", "/bench"));
        assert!(!path_matches("/bench/", "/bench"));
        // a query on either side has to agree
        assert!(path_matches("/bench?ed=2048", "/bench?ed=2048"));
        assert!(!path_matches("/bench?ed=2048", "/bench"));
        assert!(!path_matches("/bench", "/bench?ed=2048"));
    }

    #[test]
    fn a_listener_reads_its_transport_out_of_the_config() {
        let obj = serde_json::json!({"transport": {"type": "ws", "path": "/bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Ws);
        assert_eq!(t.path, "/bench");

        // no transport at all is the plain-TCP case, not an error
        assert!(
            Transport::from_inbound(&serde_json::json!({}), "inbounds[0]")
                .expect("none")
                .is_none()
        );

        // the ones we cannot serve are refused, by name
        for ty in ["grpc", "xhttp", "quic", "http"] {
            let obj = serde_json::json!({"transport": {"type": ty}});
            let err = Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("not implemented")
                .to_string();
            assert!(err.contains(ty), "{ty}: {err}");
            assert!(err.contains("not implemented yet"), "{ty}: {err}");
        }

        // a path without a leading slash is a typo worth catching at startup
        let obj = serde_json::json!({"transport": {"type": "ws", "path": "bench"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("no slash")
                .to_string()
                .contains("must start with a slash")
        );
    }
}
