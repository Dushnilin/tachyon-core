//! Server-side transports.
//!
//! A transport takes the request off the front of the stream and leaves the
//! protocol bytes where the protocol expects to find them: after a websocket
//! handshake the rest of the connection is frames, after an httpupgrade `101`
//! it is raw, after gRPC it is the request body of one `POST` stream, and
//! XHTTP is the one that is not one connection at all -- a download `GET`, the
//! sequenced upload `POST`s, and one bidirectional `POST` for `stream-one`,
//! all stitched into one byte stream through a session table. Nothing above
//! this module knows a transport exists -- `handle` gets an
//! `AsyncRead + AsyncWrite` either way.
//!
//! Only what a listener can actually serve lives here. `http` and `quic` are
//! still refused by the config validator with a message saying so, because a
//! listener that binds a port and then hangs on every connection is worse than
//! one that refuses to start. The XHTTP half is HTTP/1.1 only -- the wire our
//! own client speaks, and the one a reference client falls back to on a
//! cleartext dial -- so an `h2` XHTTP server is the piece still missing there.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

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
    Grpc,
    Xhttp,
}

impl Kind {
    fn parse(at: &str, ty: &str) -> anyhow::Result<Self> {
        Ok(match ty {
            "ws" => Kind::Ws,
            "httpupgrade" => Kind::HttpUpgrade,
            "grpc" => Kind::Grpc,
            "xhttp" => Kind::Xhttp,
            other => anyhow::bail!(
                "{at}: server transport {other} is not implemented yet (ws, \
                 httpupgrade, grpc and xhttp are; http and quic are not)"
            ),
        })
    }
}

/// Every live XHTTP session of this listener, keyed by session id. One
/// session spans several connections, so it cannot live on any of them.
type SessionTable = Arc<Mutex<HashMap<String, Arc<XhttpSession>>>>;

#[derive(Debug)]
pub(crate) struct Transport {
    kind: Kind,
    /// Path the request line must carry. `/` when the config gave none, which is
    /// also what the reference treats an absent path as.
    path: String,
    /// `service_name` for gRPC, empty for the transports that have none.
    service: String,
    /// XHTTP only: where the session id lives and under which key. The
    /// placement engine is the reference's (`session_placement`), and the
    /// default keys are its too: `x_session` everywhere but in a header, where
    /// it is `X-Session`.
    session: Place,
    session_key: String,
    /// Where the packet sequence number lives. The server never reads the
    /// number -- order is the connection's -- but it has to know whether one
    /// is there at all: a `GET` with a session and no sequence is the download
    /// stream, and with one it is an upload written with `uplink_http_method:
    /// GET`.
    seq: Place,
    seq_key: String,
    /// Every live XHTTP session of this listener, keyed by session id.
    sessions: SessionTable,
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
        let service = transport
            .get("service_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // The placement fields are XHTTP's; the other transports read the
        // object above for their one field and never look at these. Their
        // defaults are the reference's (`metaConfig`), and an unsupported
        // value refuses at startup rather than after the first connection.
        let place = |key: &str, what: &str| -> anyhow::Result<Place> {
            let raw = transport.get(key).and_then(Value::as_str).unwrap_or("");
            Place::parse(at, what, raw)
        };
        let session = place("session_placement", "session placement")?;
        let seq = place("seq_placement", "seq placement")?;
        let session_key = match transport.get("session_key").and_then(Value::as_str) {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => match session {
                Place::Header => "X-Session".to_string(),
                _ => "x_session".to_string(),
            },
        };
        let seq_key = match transport.get("seq_key").and_then(Value::as_str) {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => match seq {
                Place::Header => "X-Seq".to_string(),
                _ => "x_seq".to_string(),
            },
        };
        if kind == Kind::Xhttp
            && let Some(raw) = transport
                .get("uplink_data_placement")
                .and_then(Value::as_str)
            && !matches!(raw, "" | "body" | "auto")
        {
            anyhow::bail!(
                "{at}.transport: uplink_data_placement {raw:?} is not served yet, \
                 only the payload in the body"
            );
        }
        Ok(Some(Self {
            kind,
            path,
            service,
            session,
            session_key,
            seq,
            seq_key,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    /// Unwrap the request off `stream`, leaving protocol bytes behind.
    pub(crate) async fn accept(&self, stream: AnyStream) -> anyhow::Result<Accepted> {
        // gRPC does not read an HTTP/1.1 request head at all: the stream
        // already IS the HTTP/2 request, preface and all, so everything
        // happens inside the h2 handshake.
        if self.kind == Kind::Grpc {
            return Accepted::grpc(stream, &self.service).await;
        }
        // XHTTP reads the head itself: which request this is -- the download,
        // an upload packet, or a whole stream-one session -- decides what
        // happens to the connection, and a connection that is only attaching
        // to a session never hands a stream over at all.
        if self.kind == Kind::Xhttp {
            if crate::inbound::stream_alpn(&stream) == Some(b"h2") {
                return Accepted::xhttp_h2(stream, self).await;
            }
            return self.xhttp_accept(stream).await.map(Accepted::Once);
        }
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
                Ok(Accepted::Once(Box::new(WsStream::server(stream))))
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
                Ok(Accepted::Once(stream))
            }
            // returned before the request head above
            Kind::Grpc => unreachable!("grpc returns before the request head"),
            Kind::Xhttp => unreachable!("xhttp returns before the request head"),
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

/// What [`Transport::accept`] hands to the protocol: one session, or a
/// connection that hands out a session per stream.
pub(crate) enum Accepted {
    /// The single session this connection carries -- every transport except
    /// gRPC. When the session ends, so does the connection.
    Once(AnyStream),
    /// A gRPC connection: one session per stream, the connection outliving
    /// them. Clients pool these -- sing-box reuses the TCP a finished session
    /// ran on for the next one -- so closing the connection together with the
    /// first session breaks every later session: the client writes into the
    /// pooled corpse and fails with a closed pipe before it ever reaches us.
    /// Boxed: an h2 `Connection` is far bigger than the pipe it wraps.
    Grpc(Box<GrpcAccept>),
    /// An XHTTP HTTP/2 connection: one session per stream (stream-one), or multiplexed.
    XhttpH2(Box<XhttpH2Accept>),
}

impl Accepted {
    /// The gRPC half: the h2 handshake, preface and all, once per connection.
    async fn grpc(stream: AnyStream, service: &str) -> anyhow::Result<Self> {
        let conn = crate::outbound::transport::h2io::server_builder()
            .handshake(stream)
            .await
            .map_err(|e| anyhow::anyhow!("grpc: h2 handshake: {e}"))?;
        Ok(Self::Grpc(Box::new(GrpcAccept {
            conn: Some(conn),
            service: service.to_string(),
            first: true,
        })))
    }

    /// The XHTTP HTTP/2 half: handshake, and accept streams on the path.
    async fn xhttp_h2(stream: AnyStream, transport: &Transport) -> anyhow::Result<Self> {
        let conn = crate::outbound::transport::h2io::server_builder()
            .handshake(stream)
            .await
            .map_err(|e| anyhow::anyhow!("xhttp h2: handshake: {e}"))?;
        Ok(Self::XhttpH2(Box::new(XhttpH2Accept {
            conn: Some(conn),
            path: transport.path.clone(),
            session_place: transport.session,
            session_key: transport.session_key.clone(),
            seq_place: transport.seq,
            seq_key: transport.seq_key.clone(),
            sessions: Arc::clone(&transport.sessions),
            first: true,
        })))
    }
}

/// The accept half of a gRPC connection: one stream at a time, each on the
/// reference's wire -- `transport/v2raygrpclite/server.go` (and, when
/// `force_lite` is off, its grpc-go server): same checks, same status, same
/// framing, and like grpc-go every stream is a session of the one connection.
pub(crate) struct GrpcAccept {
    conn: Option<h2::server::Connection<AnyStream, Bytes>>,
    service: String,
    /// No stream handed out yet. The failures that can still happen before
    /// the first one belong to the connection itself and to the caller's log;
    /// after the first stream a dead connection just ends the loop, and the
    /// sessions already running go down with their own stream.
    first: bool,
}

impl GrpcAccept {
    /// The next stream, as protocol bytes. `None` means the connection is
    /// over.
    async fn next(&mut self) -> anyhow::Result<Option<AnyStream>> {
        loop {
            let Some(conn) = self.conn.as_mut() else {
                return Ok(None);
            };
            let (request, mut responder) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                Some(Err(err)) if self.first => anyhow::bail!("grpc: h2 accept: {err}"),
                Some(Err(_)) => return Ok(None),
                None if self.first => {
                    anyhow::bail!("grpc: the connection ended before a request")
                }
                None => return Ok(None),
            };
            let first = std::mem::replace(&mut self.first, false);
            let path = request.uri().path().to_string();
            let method = request.method().as_str().to_string();
            let content_type = request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if let Some(reason) = grpc_rejection(&path, &method, &content_type, &self.service) {
                // The status the reference answers a bad request with, so a scanner
                // sees the same thing it would from sing-box.
                let _ = responder.send_response(grpc_rejection_response(), true);
                if first {
                    // The status is queued on the connection and only a driver
                    // flushes it, and the reference lets the client hang up on a
                    // rejection: drive the connection until it does, 404ing
                    // anything else that gets asked in the meantime.
                    let conn = self
                        .conn
                        .take()
                        .expect("grpc: the connection is there before the first stream");
                    let _ = grpc_drive(conn).await;
                    anyhow::bail!("grpc: {reason} (path {path:?}, method {method})");
                }
                // Past the first stream a bad request is one 404'd stream, not
                // the end of the connection: the next one may still be good.
                continue;
            }
            // The 200 goes out before the protocol reads a byte of the body, the same
            // way `ServeHTTP` writes its header before it hands the connection over:
            // the far end waits for initial metadata before it will deliver messages.
            let send = responder
                .send_response(grpc_accept_response(), false)
                .map_err(|e| anyhow::anyhow!("grpc: response: {e}"))?;
            let recv = request.into_body();
            return Ok(Some(crate::outbound::transport::grpc::server(recv, send)));
        }
    }
}

/// Run the sessions [`Transport::accept`] gave out. Everything but gRPC
/// carries one session and awaits it right here; a gRPC connection is driven
/// by `accept` itself -- flow control, window updates and everything already
/// queued go out under it -- so its sessions run as tasks while the loop keeps
/// taking the next stream off the connection.
pub(crate) async fn serve_sessions<F, Fut>(accepted: Accepted, make: F) -> io::Result<()>
where
    F: Fn(AnyStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    match accepted {
        Accepted::Once(stream) => {
            make(stream).await;
            Ok(())
        }
        Accepted::Grpc(mut grpc) => {
            let mut sessions = Vec::new();
            while let Some(stream) = grpc.next().await.map_err(io::Error::other)? {
                sessions.push(tokio::spawn(make(stream)));
            }
            for session in sessions {
                let _ = session.await;
            }
            Ok(())
        }
        Accepted::XhttpH2(mut xhttp) => {
            let mut sessions = Vec::new();
            while let Some(stream) = xhttp.next().await.map_err(io::Error::other)? {
                sessions.push(tokio::spawn(make(stream)));
            }
            for session in sessions {
                let _ = session.await;
            }
            Ok(())
        }
    }
}

pub(crate) struct XhttpH2Accept {
    conn: Option<h2::server::Connection<AnyStream, Bytes>>,
    path: String,
    session_place: Place,
    session_key: String,
    seq_place: Place,
    seq_key: String,
    sessions: SessionTable,
    first: bool,
}

impl XhttpH2Accept {
    async fn next(&mut self) -> anyhow::Result<Option<AnyStream>> {
        loop {
            let Some(conn) = self.conn.as_mut() else {
                return Ok(None);
            };
            let (request, mut responder) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                Some(Err(err)) if self.first => anyhow::bail!("xhttp h2: accept: {err}"),
                Some(Err(_)) => return Ok(None),
                None if self.first => {
                    anyhow::bail!("xhttp h2: the connection ended before a request")
                }
                None => return Ok(None),
            };
            let first = std::mem::replace(&mut self.first, false);
            let target = request
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or_else(|| request.uri().path());
            let method = request.method().as_str().to_string();

            let (path, query) = match target.split_once('?') {
                Some((path, query)) => (path, Some(query)),
                None => (target, None),
            };
            let rest = match path.strip_prefix(self.path.as_str()) {
                Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
                _ => {
                    let response = http::Response::builder().status(404).body(()).unwrap();
                    let _ = responder.send_response(response, true);
                    if first {
                        let conn = self
                            .conn
                            .take()
                            .expect("xhttp: connection exists before first stream");
                        let _ = xhttp_h2_drive(conn).await;
                        anyhow::bail!(
                            "xhttp h2: rejected {method} {target:?} (expected path {})",
                            self.path
                        );
                    }
                    continue;
                }
            };

            let trimmed = rest.trim_matches('/');
            let segments: Vec<&str> = if trimmed.is_empty() {
                Vec::new()
            } else {
                trimmed.split('/').collect()
            };

            let header_pairs: Vec<(String, String)> = request
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|val| (k.as_str().to_string(), val.to_string()))
                })
                .collect();

            let sid = match self.session_place {
                Place::Path => segments.first().map(|id| id.to_string()),
                Place::Query => query.and_then(|q| lookup_param(q, &self.session_key)),
                Place::Header => lookup_header(&header_pairs, &self.session_key),
                Place::Cookie => lookup_cookie(&header_pairs, &self.session_key),
            };
            let seq = match self.seq_place {
                Place::Path => {
                    segments.len()
                        > if self.session_place == Place::Path {
                            1
                        } else {
                            0
                        }
                }
                Place::Query => query.is_some_and(|q| lookup_param(q, &self.seq_key).is_some()),
                Place::Header => lookup_header(&header_pairs, &self.seq_key).is_some(),
                Place::Cookie => lookup_cookie(&header_pairs, &self.seq_key).is_some(),
            };

            match (&method[..], sid) {
                ("GET", Some(sid)) if !seq => {
                    let mut table = self.sessions.lock().expect("xhttp table poisoned");
                    if let Some(existing) = table.get(&sid) {
                        let session = Arc::clone(existing);
                        drop(table);
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .body(())
                            .unwrap();
                        let send = responder
                            .send_response(response, false)
                            .map_err(|e| anyhow::anyhow!("xhttp h2: response: {e}"))?;
                        spawn_h2_download_pump(send, session);
                        continue;
                    }
                    let (session, up_rx, down_tx) = XhttpSession::new();
                    let bridge = xhttp_bridge(up_rx, down_tx);
                    table.insert(sid.clone(), Arc::clone(&session));
                    drop(table);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/octet-stream")
                        .body(())
                        .unwrap();
                    let send = responder
                        .send_response(response, false)
                        .map_err(|e| anyhow::anyhow!("xhttp h2: response: {e}"))?;
                    spawn_h2_download_pump(send, session);
                    return Ok(Some(Box::new(XhttpStream {
                        inner: bridge,
                        listed: Some((Arc::clone(&self.sessions), sid)),
                    })));
                }
                ("POST", None) if segments.is_empty() => {
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let send = responder
                        .send_response(response, false)
                        .map_err(|e| anyhow::anyhow!("xhttp h2: response: {e}"))?;
                    let recv = request.into_body();
                    let h2_stream = crate::outbound::transport::h2io::H2Stream::server(recv, send);
                    return Ok(Some(Box::new(crate::outbound::transport::h2io::H2Io {
                        h2: h2_stream,
                    })));
                }
                ("POST", Some(sid)) => {
                    let mut table = self.sessions.lock().expect("xhttp table poisoned");
                    let (session, is_new, up_rx, down_tx) = if let Some(existing) = table.get(&sid)
                    {
                        (Arc::clone(existing), false, None, None)
                    } else {
                        let (session, up_rx, down_tx) = XhttpSession::new();
                        table.insert(sid.clone(), Arc::clone(&session));
                        (session, true, Some(up_rx), Some(down_tx))
                    };
                    drop(table);

                    spawn_h2_upload_sink(request.into_body(), responder, session);

                    if is_new {
                        let bridge = xhttp_bridge(up_rx.unwrap(), down_tx.unwrap());
                        return Ok(Some(Box::new(XhttpStream {
                            inner: bridge,
                            listed: Some((Arc::clone(&self.sessions), sid)),
                        })));
                    }
                    continue;
                }
                _ => {
                    let response = http::Response::builder().status(404).body(()).unwrap();
                    let _ = responder.send_response(response, true);
                    continue;
                }
            }
        }
    }
}

fn spawn_h2_download_pump(mut send: h2::SendStream<Bytes>, session: Arc<XhttpSession>) {
    tokio::spawn(async move {
        if let Some(mut rx) = session.take_down() {
            while let Some(chunk) = rx.recv().await {
                let mut data = Bytes::from(chunk);
                while !data.is_empty() {
                    let to_send = data.len();
                    send.reserve_capacity(to_send);
                    let avail = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                        Some(Ok(n)) => n,
                        _ => return,
                    };
                    let take = to_send.min(avail);
                    let part = data.split_to(take);
                    if send.send_data(part, false).is_err() {
                        return;
                    }
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        }
    });
}

fn spawn_h2_upload_sink(
    mut recv: h2::RecvStream,
    mut responder: h2::server::SendResponse<Bytes>,
    session: Arc<XhttpSession>,
) {
    tokio::spawn(async move {
        while let Some(chunk) = recv.data().await {
            match chunk {
                Ok(bytes) => {
                    let len = bytes.len();
                    let _ = recv.flow_control().release_capacity(len);
                    if session.push(bytes.to_vec()).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = recv.trailers().await;
        let response = http::Response::builder().status(200).body(()).unwrap();
        let _ = responder.send_response(response, true);
    });
}

fn xhttp_h2_drive(
    mut conn: h2::server::Connection<AnyStream, Bytes>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(next) = conn.accept().await {
            match next {
                Ok((_, mut responder)) => {
                    let response = http::Response::builder().status(404).body(()).unwrap();
                    let _ = responder.send_response(response, true);
                }
                Err(_) => return,
            }
        }
    })
}

/// Keep a rejected connection running until the far end gives up on it.
/// `accept` drives the whole state machine while it waits -- flow control,
/// window updates and everything already queued go out under it -- so the
/// queued 404 leaves under this loop, and anything else asked for on the way
/// gets the same answer.
fn grpc_drive(mut conn: h2::server::Connection<AnyStream, Bytes>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(next) = conn.accept().await {
            match next {
                Ok((request, mut responder)) => {
                    crate::logging::debug(format_args!(
                        "grpc: rejected connection, {} -> 404",
                        request.uri().path()
                    ));
                    let _ = responder.send_response(grpc_rejection_response(), true);
                }
                Err(_) => return,
            }
        }
    })
}

/// What the reference answers a bad request with: a bare 404 and the end of
/// the stream (`invalidRequest`).
fn grpc_rejection_response() -> http::Response<()> {
    http::Response::builder()
        .status(404)
        .body(())
        .expect("a 404 builds")
}

/// The headers `ServeHTTP` writes before it hands the connection over.
fn grpc_accept_response() -> http::Response<()> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("a 200 builds")
}

/// The three checks `ServeHTTP` makes, first failure named. `None` means serve.
fn grpc_rejection(
    path: &str,
    method: &str,
    content_type: &str,
    service: &str,
) -> Option<&'static str> {
    // the reference compares the decoded `:path` against `grpcname.Path`, and
    // the client may send the escaped form (the plain-form wire escapes the
    // service segment, `a%2Fb`)
    let decoded = path_unescape(path).unwrap_or_else(|| path.to_string());
    if decoded != grpc_service_path(service) {
        return Some("path does not match the service name");
    }
    if method != "POST" {
        return Some("not a POST");
    }
    if !content_type.starts_with("application/grpc") {
        return Some("content type is not application/grpc");
    }
    None
}

/// The decoded `:path` a gRPC request must carry for `service` -- the
/// reference's `grpcname.Path`: the plain form is `/service/Tun`, and a
/// leading `/` in `service_name` is Xray's custom path where everything up to
/// the last `/` is the service and the tail is the stream name minus a
/// `|multi` suffix (SPEC 093).
fn grpc_service_path(service: &str) -> String {
    if !service.starts_with('/') {
        return format!("/{service}/Tun");
    }
    // Go clamps the split index to 1 but takes the stream from the original
    // last slash, so `/` is `//` and `/Tun` is `//Tun`.
    let last = service.rfind('/').unwrap_or(0);
    let body_last = last.max(1);
    let body = &service[1..body_last];
    let ending = &service[(last + 1).min(service.len())..];
    let stream = ending.split('|').next().unwrap_or(ending);
    format!("/{body}/{stream}")
}

/// Go's `url.PathUnescape`: `None` when a `%` is not followed by two hex
/// digits, which is where the reference falls back to the raw string too.
fn path_unescape(path: &str) -> Option<String> {
    if !path.contains('%') {
        return Some(path.to_string());
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex(*bytes.get(i + 1)?)?;
            let lo = hex(*bytes.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Where a value lives when the reference's placement engine puts it somewhere
/// other than in the path. The names and the defaults are its (`metaConfig`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Place {
    Path,
    Query,
    Header,
    Cookie,
}

impl Place {
    fn parse(at: &str, what: &str, raw: &str) -> anyhow::Result<Self> {
        Ok(match raw {
            "" | "path" => Place::Path,
            "query" => Place::Query,
            "header" => Place::Header,
            "cookie" => Place::Cookie,
            other => anyhow::bail!("{at}: unsupported {what}: {other}"),
        })
    }
}

/// How many messages each direction of a session may hold. Backpressure, not
/// a buffer: a stalled download stops the protocol writing instead of eating
/// memory, and a stalled protocol stops the uploads instead of queueing them.
const XHTTP_QUEUE: usize = 64;

/// One XHTTP session. It outlives the connections that carry it -- that is
/// the whole point of the transport: the download is one connection, each
/// upload packet is a request on another, and the protocol above sees one
/// byte stream.
#[derive(Debug)]
struct XhttpSession {
    /// `None` once the session is over: that is what ends the protocol's read
    /// side, and what an upload has to find before it attaches.
    up: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// handed to the download (or stream-one) connection when it takes the
    /// session; a second one finds it already taken.
    down: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

impl XhttpSession {
    /// The session plus the two ends: the receiver for [`XhttpStream`]'s read
    /// half, the sender for its write half.
    fn new() -> (Arc<Self>, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>) {
        let (up_tx, up_rx) = mpsc::channel(XHTTP_QUEUE);
        let (down_tx, down_rx) = mpsc::channel(XHTTP_QUEUE);
        (
            Arc::new(Self {
                up: Mutex::new(Some(up_tx)),
                down: Mutex::new(Some(down_rx)),
            }),
            up_rx,
            down_tx,
        )
    }

    /// One upload chunk towards the protocol. The lock is held only to clone
    /// the sender; the await must not sit on it.
    async fn push(&self, chunk: Vec<u8>) -> io::Result<()> {
        let sender = self.up.lock().expect("xhttp session poisoned").clone();
        match sender {
            Some(tx) => tx
                .send(chunk)
                .await
                .map_err(|_| io::Error::other("xhttp: the session is over")),
            None => Err(io::Error::other("xhttp: the session is over")),
        }
    }

    fn close_up(&self) {
        *self.up.lock().expect("xhttp session poisoned") = None;
    }

    fn take_down(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.down.lock().expect("xhttp session poisoned").take()
    }
}

/// The byte stream the protocol sees. One in-memory pipe: the read half is
/// everything the upload connections delivered, the write half is handed to
/// the download connection through the bridge task.
struct XhttpStream {
    inner: tokio::io::DuplexStream,
    /// the table entry to drop when this ends. `None` for a session nothing
    /// can attach to (stream-one), which never enters the table.
    listed: Option<(SessionTable, String)>,
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        if let Some((table, sid)) = &self.listed
            && let Ok(mut table) = table.lock()
        {
            table.remove(sid);
        }
    }
}

impl Transport {
    /// Serve one XHTTP connection. Three shapes arrive here: the download
    /// `GET` that takes the session, an upload `POST` that attaches to one
    /// (or births it, if the upload wins the race), and the single
    /// bidirectional `POST` of stream-one, whose session nothing attaches to.
    async fn xhttp_accept(&self, mut stream: AnyStream) -> anyhow::Result<AnyStream> {
        let raw = read_head(&mut stream).await?;
        let end =
            head_end(&raw).ok_or_else(|| anyhow::anyhow!("xhttp: request head has no end"))?;
        let (method, target, headers) = parse_head(&raw[..end])?;
        let pending = raw[end..].to_vec();

        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target.as_str(), None),
        };
        let rest = match path.strip_prefix(self.path.as_str()) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
            _ => {
                return xhttp_reject(
                    stream,
                    format!(
                        "path {path:?} does not match the configured {:?}",
                        self.path
                    ),
                )
                .await;
            }
        };
        let trimmed = rest.trim_matches('/');
        let segments: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };
        let sid = self.session_id(&segments, query, &headers);
        let seq = self.seq_present(&segments, query, &headers);

        match (&method[..], sid) {
            // the download stream: a GET with a session and no packet number.
            // A GET that carries a sequence is an upload sent with
            // `uplink_http_method: GET`, which falls through below.
            ("GET", Some(sid)) if !seq => self.xhttp_download(stream, sid).await,
            // a GET with no session is a request nothing serves
            ("GET", None) if segments.is_empty() => {
                xhttp_reject(stream, "a GET needs a session id".to_string()).await
            }
            // stream-one: the whole session on one POST to the bare path
            (_, None) if segments.is_empty() => {
                let (session, up_rx, down_tx) = XhttpSession::new();
                let protocol_end = xhttp_bridge(up_rx, down_tx);
                tokio::spawn(xhttp_stream_one_task(stream, pending, headers, session));
                // never listed: a stream-one session lives on this one
                // connection and nothing can attach to it
                Ok(Box::new(XhttpStream {
                    inner: protocol_end,
                    listed: None,
                }))
            }
            // an upload: attach to the session, or birth it when the client
            // sent its POST before its GET
            (_, Some(sid)) => self.xhttp_upload(stream, pending, headers, sid).await,
            _ => xhttp_reject(stream, format!("no XHTTP session at {path:?}")).await,
        }
    }

    /// The session id, wherever this listener's placement says it lives.
    fn session_id(
        &self,
        segments: &[&str],
        query: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<String> {
        match self.session {
            Place::Path => segments.first().map(|id| id.to_string()),
            Place::Query => query.and_then(|q| lookup_param(q, &self.session_key)),
            Place::Header => lookup_header(headers, &self.session_key),
            Place::Cookie => lookup_cookie(headers, &self.session_key),
        }
    }

    /// Is a packet sequence number on this request? The server never reads
    /// the number -- order is the connection's -- but a `GET` with a session
    /// and no sequence is the download, and with one it is an upload.
    fn seq_present(
        &self,
        segments: &[&str],
        query: Option<&str>,
        headers: &[(String, String)],
    ) -> bool {
        match self.seq {
            // session in the path: the sequence is the segment after it
            Place::Path => segments.len() > if self.session == Place::Path { 1 } else { 0 },
            Place::Query => query.is_some_and(|q| lookup_param(q, &self.seq_key).is_some()),
            Place::Header => lookup_header(headers, &self.seq_key).is_some(),
            Place::Cookie => lookup_cookie(headers, &self.seq_key).is_some(),
        }
    }

    /// The download `GET`: birth the session and hand its response side to
    /// this connection. A second GET for a session that already has one is
    /// refused by the task -- the first one owns the response body.
    async fn xhttp_download(&self, conn: AnyStream, sid: String) -> anyhow::Result<AnyStream> {
        let mut table = self.sessions.lock().expect("xhttp table poisoned");
        if let Some(existing) = table.get(&sid) {
            // the upload arrived first; the tunnel is already running on that
            // connection's stream and this one only feeds it down
            let session = Arc::clone(existing);
            drop(table);
            tokio::spawn(xhttp_download_task(conn, session));
            anyhow::bail!("xhttp: a download attached to session {sid:?}");
        }
        let (session, up_rx, down_tx) = XhttpSession::new();
        let bridge = xhttp_bridge(up_rx, down_tx);
        table.insert(sid.clone(), Arc::clone(&session));
        drop(table);
        tokio::spawn(xhttp_download_task(conn, session));
        Ok(Box::new(XhttpStream {
            inner: bridge,
            listed: Some((Arc::clone(&self.sessions), sid)),
        }))
    }

    /// An upload connection: the 200, the body into the session, the next
    /// request if the pooled connection carries one, and the end when it does
    /// not. An attach returns no stream -- the caller's task ends here and
    /// the bytes go to the session that returned a stream earlier.
    async fn xhttp_upload(
        &self,
        conn: AnyStream,
        pending: Vec<u8>,
        headers: Vec<(String, String)>,
        sid: String,
    ) -> anyhow::Result<AnyStream> {
        let mut table = self.sessions.lock().expect("xhttp table poisoned");
        if let Some(existing) = table.get(&sid) {
            let session = Arc::clone(existing);
            drop(table);
            tokio::spawn(xhttp_upload_task(conn, pending, headers, session));
            // the tunnel lives on the connection that returned the stream;
            // this one only carries bytes into it
            anyhow::bail!("xhttp: an upload attached to session {sid:?}");
        }
        let (session, up_rx, down_tx) = XhttpSession::new();
        let bridge = xhttp_bridge(up_rx, down_tx);
        table.insert(sid.clone(), Arc::clone(&session));
        drop(table);
        tokio::spawn(xhttp_upload_task(conn, pending, headers, session));
        Ok(Box::new(XhttpStream {
            inner: bridge,
            listed: Some((Arc::clone(&self.sessions), sid)),
        }))
    }
}

/// The in-memory pipe one session runs on: enough for a few writes in each
/// direction without waiting for the far end of the room.
const XHTTP_PIPE: usize = 64 * 1024;

/// The session's moving parts: one end of a pipe for the protocol, and two
/// tasks -- this bridge between the pipe and the session channels, and the
/// connection task that was spawned with it.
fn xhttp_bridge(
    up_rx: mpsc::Receiver<Vec<u8>>,
    down_tx: mpsc::Sender<Vec<u8>>,
) -> tokio::io::DuplexStream {
    let (protocol_end, bridge_end) = tokio::io::duplex(XHTTP_PIPE);
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(bridge_end);
        let up = async {
            let mut up_rx = up_rx;
            while let Some(chunk) = up_rx.recv().await
                && wr.write_all(&chunk).await.is_ok()
            {}
            // no more uploads: half-close the half the protocol reads, which
            // is its EOF. The write half stays open for the download.
            let _ = wr.shutdown().await;
        };
        let down = async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if down_tx.send(buf[..n].to_vec()).await.is_err() {
                            return;
                        }
                    }
                }
            }
        };
        // Either direction ending ends the bridge and drops the other half of
        // it: a closed download must stop the uploads feeding it, and a
        // closed upload side must end the download task's read.
        tokio::select! {
            _ = up => {}
            _ = down => {}
        }
    });
    protocol_end
}

/// The 404 a request nothing serves gets, so a scanner sees the status before
/// the connection ends.
async fn xhttp_reject(mut conn: AnyStream, reason: String) -> anyhow::Result<AnyStream> {
    let _ = conn
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        .await;
    let _ = conn.flush().await;
    anyhow::bail!("xhttp: {reason}")
}

/// The download connection: the 200, then everything the protocol writes, in
/// order, until the session or the connection ends. The connection is also
/// read: a client that vanished sends nothing but a FIN, and writing is how a
/// server learns about that only when it happens to have data.
async fn xhttp_download_task(conn: AnyStream, session: Arc<XhttpSession>) {
    let Some(mut down) = session.take_down() else {
        // the session already has a download; the first one owns the response
        let mut conn = conn;
        let _ = conn
            .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };
    let (mut rd, mut wr) = tokio::io::split(conn);
    if wr.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
        session.close_up();
        return;
    }
    tokio::select! {
        _ = async {
            while let Some(chunk) = down.recv().await {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        } => {}
        _ = async {
            // the client should send nothing on a download connection; what
            // it does send is stray, and the EOF at the end is the session's
            // lifeline ending
            let mut scratch = [0u8; 1];
            while let Ok(n) = rd.read(&mut scratch).await && n > 0 {}
        } => {}
    }
    drop(down);
    session.close_up();
    let _ = wr.shutdown().await;
}

/// One upload connection's life: answer, deliver the body, answer the next
/// request, until the connection closes. A pooled packet-up connection ends
/// like this every time the reference closes it, which is not an error.
async fn xhttp_upload_task(
    mut conn: AnyStream,
    mut pending: Vec<u8>,
    mut headers: Vec<(String, String)>,
    session: Arc<XhttpSession>,
) {
    loop {
        let framing = match request_framing(&headers) {
            Ok(framing) => framing,
            Err(err) => {
                crate::logging::debug(format_args!("xhttp upload: {err}"));
                return;
            }
        };
        // The 200 first, before a byte of the body is read: a streamed upload
        // reads its response head while the body is still going up, and an
        // answer that waited for the body to end would deadlock stream-up
        // against itself.
        if conn
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        if let Err(err) = pump_request_body(&mut conn, &mut pending, framing, &session).await {
            crate::logging::debug(format_args!("xhttp upload: {err}"));
            return;
        }
        match next_request(&mut conn, &mut pending).await {
            Ok(Some(head)) => {
                let end = match head_end(&head) {
                    Some(end) => end,
                    None => return,
                };
                match parse_head(&head[..end]) {
                    Ok((_method, _target, parsed)) => headers = parsed,
                    Err(err) => {
                        crate::logging::debug(format_args!("xhttp upload: {err}"));
                        return;
                    }
                }
            }
            // the pooled connection was closed: the normal end of an upload
            // connection, not a failure
            Ok(None) => return,
            Err(err) => {
                crate::logging::debug(format_args!("xhttp upload: {err}"));
                return;
            }
        }
    }
}

/// The stream-one connection: the 200 goes out before the body is read (the
/// response IS the download, so waiting for the upload to end first would
/// deadlock both halves against each other), then the body feeds the
/// protocol's read side while its writes go back down the response.
async fn xhttp_stream_one_task(
    conn: AnyStream,
    mut pending: Vec<u8>,
    headers: Vec<(String, String)>,
    session: Arc<XhttpSession>,
) {
    let framing = match request_framing(&headers) {
        Ok(framing) => framing,
        Err(err) => {
            crate::logging::debug(format_args!("xhttp stream-one: {err}"));
            return;
        }
    };
    let mut down = match session.take_down() {
        Some(down) => down,
        None => return,
    };
    let (mut rd, mut wr) = tokio::io::split(conn);
    if wr.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
        session.close_up();
        return;
    }
    tokio::select! {
        _ = async {
            if let Err(err) = pump_request_body(&mut rd, &mut pending, framing, &session).await {
                crate::logging::debug(format_args!("xhttp stream-one: {err}"));
            }
            // the client is done sending: that is its half-close, and the
            // protocol above is what has to see it
            session.close_up();
        } => {}
        _ = async {
            while let Some(chunk) = down.recv().await {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        } => {}
    }
    session.close_up();
    let _ = wr.shutdown().await;
}

/// The body of one request, delivered to the session as it arrives. Reads
/// stop exactly at the body's end: whatever came after it -- the next
/// request on a pooled connection -- stays in `pending` for
/// [`next_request`].
async fn pump_request_body<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
    mut state: ReqBody,
    session: &XhttpSession,
) -> io::Result<()> {
    loop {
        match state {
            ReqBody::Done => return Ok(()),
            ReqBody::Length(0) => state = ReqBody::Done,
            ReqBody::Length(remaining) => {
                pull(conn, pending, 1).await?;
                let take = (remaining as usize).min(pending.len());
                let chunk: Vec<u8> = pending.drain(..take).collect();
                let remaining = remaining - take as u64;
                session.push(chunk).await?;
                state = if remaining == 0 {
                    ReqBody::Done
                } else {
                    ReqBody::Length(remaining)
                };
            }
            ReqBody::ChunkSize => {
                let line = read_line(conn, pending).await?;
                let text = String::from_utf8_lossy(&line);
                let size = text.split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(size, 16)
                    .map_err(|_| io::Error::other(format!("xhttp: bad chunk size {text:?}")))?;
                state = if size == 0 {
                    ReqBody::ChunkTrailer
                } else {
                    ReqBody::ChunkData(size)
                };
            }
            ReqBody::ChunkData(remaining) => {
                pull(conn, pending, 1).await?;
                let take = (remaining as usize).min(pending.len());
                let chunk: Vec<u8> = pending.drain(..take).collect();
                let remaining = remaining - take as u64;
                session.push(chunk).await?;
                state = if remaining == 0 {
                    ReqBody::ChunkCrlf
                } else {
                    ReqBody::ChunkData(remaining)
                };
            }
            ReqBody::ChunkCrlf => {
                let line = read_line(conn, pending).await?;
                if !line.is_empty() {
                    return Err(io::Error::other("xhttp: junk between a chunk and its CRLF"));
                }
                state = ReqBody::ChunkSize;
            }
            ReqBody::ChunkTrailer => {
                // the trailer has to be consumed even though nobody reads it:
                // on a keep-alive connection it sits in front of the next
                // request
                loop {
                    let line = read_line(conn, pending).await?;
                    if line.is_empty() {
                        state = ReqBody::Done;
                        break;
                    }
                }
            }
        }
    }
}

/// How the request body is delimited on the way in: RFC 9112 §6, the three
/// framings, decided off the headers the way the reference's client writes
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqBody {
    Done,
    Length(u64),
    /// chunked: reading a size line
    ChunkSize,
    /// chunked: reading `n` more bytes of the current chunk
    ChunkData(u64),
    /// chunked: reading the CRLF that closes a chunk
    ChunkCrlf,
    /// chunked: past the zero chunk, reading the trailer fields
    ChunkTrailer,
}

fn request_framing(headers: &[(String, String)]) -> io::Result<ReqBody> {
    if let Some(te) = lookup_header(headers, "transfer-encoding")
        && te
            .to_ascii_lowercase()
            .split(',')
            .any(|token| token.trim() == "chunked")
    {
        return Ok(ReqBody::ChunkSize);
    }
    match lookup_header(headers, "content-length") {
        Some(cl) => {
            let n: u64 = cl
                .parse()
                .map_err(|_| io::Error::other(format!("xhttp: bad content-length {cl:?}")))?;
            Ok(if n == 0 {
                ReqBody::Done
            } else {
                ReqBody::Length(n)
            })
        }
        None => Ok(ReqBody::Done),
    }
}

/// Make sure `pending` holds at least `want` bytes, reading from the socket
/// for the rest. More than `want` may arrive -- the overread is the next
/// request's bytes and stays in `pending`.
async fn pull<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
    want: usize,
) -> io::Result<()> {
    let mut buf = [0u8; 8 * 1024];
    while pending.len() < want {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::other("xhttp: connection closed inside a body"));
        }
        pending.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

/// One CRLF-delimited line, without the CRLF.
async fn read_line<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    loop {
        if let Some(end) = pending.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = pending.drain(..end).collect();
            let _ = pending.drain(..2);
            return Ok(line);
        }
        if pending.len() > MAX_HEAD {
            return Err(io::Error::other("xhttp: line too long"));
        }
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::other("xhttp: connection closed inside a line"));
        }
        pending.push(buf[0]);
    }
}

/// The next request head: from what the previous body left behind first, then
/// from the socket. `Ok(None)` is the clean close of a pooled connection.
async fn next_request(conn: &mut AnyStream, pending: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 1024];
    loop {
        if let Some(end) = head_end(pending) {
            let rest = pending.split_off(end);
            let head = std::mem::take(pending);
            *pending = rest;
            return Ok(Some(head));
        }
        if pending.len() > MAX_HEAD {
            return Err(io::Error::other("http: request head over {MAX_HEAD} bytes"));
        }
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Where the request head ends, blank line inclusive.
fn head_end(buf: &[u8]) -> Option<usize> {
    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(end + 4);
    }
    buf.windows(2).position(|w| w == b"\n\n").map(|end| end + 2)
}

/// A query parameter: `key=value`, raw, because the reference's own client
/// writes it without escaping.
fn lookup_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_string())
    })
}

fn lookup_header(headers: &[(String, String)], key: &str) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .and_then(|(_, value)| (!value.is_empty()).then(|| value.clone()))
}

/// One `name=value` inside a `cookie` header.
fn lookup_cookie(headers: &[(String, String)], key: &str) -> Option<String> {
    let cookie = lookup_header(headers, "cookie")?;
    cookie.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (name, value) = pair.split_once('=')?;
        (name.trim() == key && !value.is_empty()).then(|| value.trim().to_string())
    })
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

        // grpc is served now, with its service name
        let obj = serde_json::json!({"transport": {"type": "grpc", "service_name": "bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Grpc);
        assert_eq!(t.service, "bench");

        // xhttp is served now, on its default placements
        let obj = serde_json::json!({"transport": {"type": "xhttp", "path": "/bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Xhttp);
        assert_eq!(t.path, "/bench");
        assert_eq!(t.session, Place::Path);
        assert_eq!(t.session_key, "x_session");
        assert_eq!(t.seq, Place::Path);
        assert_eq!(t.seq_key, "x_seq");

        // the ones we cannot serve are refused, by name
        for ty in ["quic", "http"] {
            let obj = serde_json::json!({"transport": {"type": ty}});
            let err = Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("not implemented")
                .to_string();
            assert!(err.contains(ty), "{ty}: {err}");
            assert!(err.contains("not implemented yet"), "{ty}: {err}");
        }

        // an xhttp value the reference does not have either refuses at startup
        let obj =
            serde_json::json!({"transport": {"type": "xhttp", "session_placement": "nowhere"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("unsupported placement")
                .to_string()
                .contains("unsupported session placement")
        );
        // ...and so does an uplink payload this server cannot read
        let obj =
            serde_json::json!({"transport": {"type": "xhttp", "uplink_data_placement": "header"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("body only")
                .to_string()
                .contains("uplink_data_placement")
        );

        // a path without a leading slash is a typo worth catching at startup
        let obj = serde_json::json!({"transport": {"type": "ws", "path": "bench"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("no slash")
                .to_string()
                .contains("must start with a slash")
        );
    }

    /// The placement engine, the way the reference's client writes requests:
    /// the session id in the path (default), in a query parameter, in a
    /// header, in a cookie -- and the sequence number counted wherever its own
    /// placement says, which is how a `GET` is told apart from an upload.
    #[test]
    fn xhttp_session_ids_follow_the_configured_placement() {
        let at = "inbounds[0]";
        let transport = |extra: serde_json::Value| {
            let mut obj = serde_json::json!({"transport": {"type": "xhttp", "path": "/bench"}});
            obj["transport"] = match extra {
                serde_json::Value::Object(map) => {
                    let mut base = serde_json::json!({"type": "xhttp", "path": "/bench"});
                    for (k, v) in map {
                        base[k] = v;
                    }
                    base
                }
                other => other,
            };
            Transport::from_inbound(&obj, at)
                .expect("read")
                .expect("present")
        };
        let no_headers: Vec<(String, String)> = Vec::new();
        let header = |name: &str, value: &str| vec![(name.to_string(), value.to_string())];

        // default: path placement, sid is the segment under the path
        let t = transport(serde_json::json!({}));
        assert_eq!(
            t.session_id(&["8f14e45f-ceea-467f-a1d6-1f6ef4b7f8f4"], None, &no_headers),
            Some("8f14e45f-ceea-467f-a1d6-1f6ef4b7f8f4".to_string())
        );
        assert_eq!(
            t.session_id(&["sid", "7"], None, &no_headers),
            Some("sid".to_string()),
            "the sequence segment does not eat the session id"
        );
        assert!(t.seq_present(&["sid", "7"], None, &no_headers));
        assert!(!t.seq_present(&["sid"], None, &no_headers));
        assert_eq!(t.session_id(&[], None, &no_headers), None);

        // query placement: the session comes from its key, and with the
        // sequence in the path its segment is everything under the path --
        // there is no session segment to skip
        let t = transport(serde_json::json!({"session_placement": "query"}));
        assert_eq!(
            t.session_id(&[], Some("x_session=sid&x=1"), &no_headers),
            Some("sid".to_string())
        );
        assert_eq!(t.session_id(&[], Some("x_session="), &no_headers), None);
        assert!(!t.seq_present(&[], Some("x_session=sid"), &no_headers));
        assert!(t.seq_present(&["3"], Some("x_session=sid"), &no_headers));

        // ...and a sequence in the query is found under its own key
        let t =
            transport(serde_json::json!({"session_placement": "query", "seq_placement": "query"}));
        assert!(!t.seq_present(&[], Some("x_session=sid"), &no_headers));
        assert!(t.seq_present(&[], Some("x_session=sid&x_seq=3"), &no_headers));

        // header placement: the default key is the canonical X-Session
        let t = transport(
            serde_json::json!({"session_placement": "header", "seq_placement": "header"}),
        );
        assert_eq!(
            t.session_id(&[], None, &header("X-Session", "sid")),
            Some("sid".to_string())
        );
        assert_eq!(
            t.session_id(&[], None, &header("x-session", "sid")),
            Some("sid".to_string()),
            "header names are case-insensitive, as on the wire"
        );
        assert_eq!(t.session_id(&[], None, &no_headers), None);
        assert!(t.seq_present(&[], None, &header("X-Seq", "3")));

        // cookie placement, and a configured key beats the default one
        let t = transport(serde_json::json!({
            "session_placement": "cookie",
            "session_key": "tok"
        }));
        assert_eq!(
            t.session_id(&[], None, &header("cookie", "a=1; tok=sid; b=2")),
            Some("sid".to_string())
        );
        assert_eq!(t.session_id(&[], None, &header("cookie", "a=1")), None);
    }

    /// The body of a request comes in three framings, and the boundary has to
    /// be exact: what follows the body belongs to the next request on a
    /// pooled connection.
    #[tokio::test]
    async fn xhttp_request_bodies_stop_at_their_framing() {
        async fn read_body(raw: Vec<u8>, headers: Vec<(&str, &str)>) -> Vec<u8> {
            let headers: Vec<(String, String)> = headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let framing = request_framing(&headers).expect("framing");
            let (session, _up_rx, _down_tx) = XhttpSession::new();
            let mut pending = raw;
            let mut conn = std::io::Cursor::new(Vec::new());
            pump_request_body(&mut conn, &mut pending, framing, &session)
                .await
                .expect("pumped");
            // whatever was behind the body is still there, unparsed
            pending
        }

        // content-length stops after n bytes and leaves the rest alone
        assert_eq!(
            read_body(
                b"helloHTTP/1.1 102 Continue\r\n\r\n".to_vec(),
                vec![("content-length", "5")],
            )
            .await,
            b"HTTP/1.1 102 Continue\r\n\r\n"
        );

        // chunked: chunks until the zero chunk, trailer included
        assert_eq!(
            read_body(
                b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-t: 1\r\n\r\nNEXT".to_vec(),
                vec![("transfer-encoding", "chunked")],
            )
            .await,
            b"NEXT"
        );

        // no framing header is no body, not a body to the close
        assert_eq!(read_body(b"as-is".to_vec(), vec![]).await, b"as-is");
    }

    /// The reference's `grpcname` form table, verbatim: what the decoded
    /// `:path` has to be for each shape of `service_name`.
    #[test]
    fn grpc_service_paths_follow_the_reference_table() {
        for (service, path) in [
            ("TunService", "/TunService/Tun"),
            ("a/b", "/a/b/Tun"),
            ("/a/b/Tun", "/a/b/Tun"),
            ("/a/b/Stream", "/a/b/Stream"),
            ("/a b/Tun", "/a b/Tun"),
            ("/a/b/Tun|TunMulti", "/a/b/Tun"),
            ("/Tun", "//Tun"),
            ("", "//Tun"),
            ("/", "//"),
        ] {
            assert_eq!(grpc_service_path(service), path, "service {service:?}");
        }
    }

    #[test]
    fn a_grpc_request_is_checked_the_way_serve_http_checks_it() {
        assert_eq!(
            grpc_rejection("/bench/Tun", "POST", "application/grpc", "bench"),
            None
        );
        // the plain-form wire escapes the service segment; both spellings decode
        // to what the reference compares against
        assert_eq!(
            grpc_rejection("/a%2Fb/Tun", "POST", "application/grpc", "a/b"),
            None
        );
        assert_eq!(
            grpc_rejection("/a/b/Tun", "POST", "application/grpc", "a/b"),
            None
        );
        assert_eq!(
            grpc_rejection("//Tun", "POST", "application/grpc", ""),
            None
        );
        // content type is a prefix check, as in Go
        assert_eq!(
            grpc_rejection("/bench/Tun", "POST", "application/grpc+proto", "bench"),
            None
        );

        assert!(
            grpc_rejection("/other/Tun", "POST", "application/grpc", "bench").is_some(),
            "wrong path must be refused"
        );
        assert!(
            grpc_rejection("/bench/Tun", "GET", "application/grpc", "bench").is_some(),
            "GET must be refused"
        );
        assert!(
            grpc_rejection("/bench/Tun", "POST", "text/plain", "bench").is_some(),
            "wrong content type must be refused"
        );
        // a broken escape is compared raw, like the reference's fallback
        assert_eq!(path_unescape("%zz"), None);
        assert_eq!(path_unescape("/a%2Fb").as_deref(), Some("/a/b"));
        assert_eq!(path_unescape("/plain").as_deref(), Some("/plain"));
    }
}
