//! XHTTP (Xray "splithttp") client transport — HTTP/1.1.
//!
//! Wire semantics ported from the reference client (sing-box-lx
//! `transport/v2rayxhttp`, SPEC 002 / PARAM_MAP): a per-dial session id
//! targets `<path>/<sessionId>` (download GET) and packet-up uploads POST to
//! `<path>/<sessionId>/<seq>`; placement/keys move session/seq/payload into
//! query/header/cookie; every request carries X-Padding (Referer legacy or
//! the configurable obfs placements, `repeat-x`/`tokenish`).
//!
//! Modes: packet-up (GET download + sequential POST packets), stream-up
//! (streamed POST upload + GET download), stream-one (one bidirectional
//! stream), auto (REALITY → stream-one, otherwise packet-up — REALITY is not
//! implemented yet, so auto currently resolves to packet-up).
//!
//! HTTP/1.1 and nothing else, because that is what the reference speaks. It
//! refuses h2 on this transport even when the server offers it, on purpose, and
//! the two connections the protocol wants — a `Connection: close` download GET
//! and keep-alive pooled upload POSTs — are why the transport layer hands us a
//! dialer: HTTP/1.1 does not multiplex, so a second request means a second
//! connection, and ALPN is decided per connection.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::h1io;
use crate::inbound::AnyStream;

/// Opens one more connection to the same server, with the same TCP options, the
/// same TLS and the same ALPN as the first.
pub(crate) type Dialer =
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>> + Send + Sync;

/// Hop-by-hop headers: connection-scoped in HTTP/2 and HTTP/1.1 alike, so none
/// of them may be copied from the config onto the wire.
const HOP_BY_HOP: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XPlacement {
    Cookie,
    Header,
    Query,
    QueryInHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PadMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range(pub u64, pub u64);

impl Range {
    fn parse(s: &str, def: Range) -> anyhow::Result<Self> {
        if s.is_empty() {
            return Ok(def);
        }
        let parts: Vec<&str> = s.split('-').collect();
        let (lo, hi) = match parts.as_slice() {
            [a] => (*a, *a),
            [a, b] => (*a, *b),
            _ => anyhow::bail!("invalid range {s:?}"),
        };
        let lo: u64 = lo
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid range {s:?}"))?;
        let hi: u64 = hi
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid range {s:?}"))?;
        Ok(Range(lo.min(hi), lo.max(hi)))
    }

    fn rand(&self) -> u64 {
        if self.0 == self.1 {
            return self.0;
        }
        let mut b = [0u8; 8];
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut b);
        self.0 + u64::from_le_bytes(b) % (self.1 - self.0 + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UplinkPlacement {
    Body,
    Header,
    Cookie,
}

/// Normalized placement/key/method selection (reference `metaConfig`).
#[derive(Debug, Clone)]
struct Meta {
    session_placement: Placement,
    session_key: String,
    seq_placement: Placement,
    seq_key: String,
    session_table: String,
    session_len: Range,
    uplink_data: UplinkPlacement,
    uplink_key: String,
    uplink_chunk: Range,
    uplink_method: String,
    x_obfs: bool,
    x_key: String,
    x_header: String,
    x_placement: XPlacement,
    x_method: PadMethod,
    sc_max_each_post: Range,
    sc_min_interval_ms: Range,
}

impl Meta {
    fn resolve(t: &Map<String, Value>, mode: Mode) -> anyhow::Result<Self> {
        let s = |k: &str| match t.get(k) {
            Some(Value::String(value)) => value.trim().to_string(),
            Some(Value::Number(value)) => value.to_string(),
            _ => String::new(),
        };
        let placement = |k: &str, what: &str| -> anyhow::Result<Placement> {
            match s(k).as_str() {
                "" | "path" => Ok(Placement::Path),
                "query" => Ok(Placement::Query),
                "header" => Ok(Placement::Header),
                "cookie" => Ok(Placement::Cookie),
                other => anyhow::bail!("v2ray-xhttp: unsupported {what}: {other}"),
            }
        };
        let session_placement = placement("session_placement", "session placement")?;
        let seq_placement = placement("seq_placement", "seq placement")?;
        let uplink_raw = s("uplink_data_placement");
        let uplink_data = match uplink_raw.as_str() {
            "" | "auto" | "body" => UplinkPlacement::Body,
            "header" => UplinkPlacement::Header,
            "cookie" => UplinkPlacement::Cookie,
            other => anyhow::bail!("v2ray-xhttp: unsupported uplink data placement: {other}"),
        };
        // header/cookie payload is a packet-up-only shape (hard gate).
        if !matches!(uplink_data, UplinkPlacement::Body) && mode != Mode::PacketUp {
            anyhow::bail!(
                "v2ray-xhttp: uplink_data_placement can be {uplink_raw} only in packet-up mode"
            );
        }
        let x_placement = match s("x_padding_placement").as_str() {
            "" | "queryInHeader" => XPlacement::QueryInHeader,
            "cookie" => XPlacement::Cookie,
            "header" => XPlacement::Header,
            "query" => XPlacement::Query,
            other => anyhow::bail!("v2ray-xhttp: unsupported x padding placement: {other}"),
        };
        let x_method = match s("x_padding_method").as_str() {
            "" | "repeat-x" => PadMethod::RepeatX,
            "tokenish" => PadMethod::Tokenish,
            other => anyhow::bail!("v2ray-xhttp: unsupported x padding method: {other}"),
        };
        // Key defaults are placement-asymmetric: canonical `X-*` for headers,
        // lowercase `x_*` for query/cookie (PARAM_MAP §2).
        let session_key = match s("session_key") {
            v if !v.is_empty() => v,
            _ => match session_placement {
                Placement::Header => "X-Session".to_string(),
                _ => "x_session".to_string(),
            },
        };
        let seq_key = match s("seq_key") {
            v if !v.is_empty() => v,
            _ => match seq_placement {
                Placement::Header => "X-Seq".to_string(),
                _ => "x_seq".to_string(),
            },
        };
        let uplink_key = match s("uplink_data_key") {
            v if !v.is_empty() => v,
            _ => match uplink_data {
                UplinkPlacement::Cookie => "x_data".to_string(),
                _ => "X-Data".to_string(),
            },
        };
        let sc_max_each_post =
            Range::parse(&s("sc_max_each_post_bytes"), Range(1_000_000, 1_000_000))?;
        let uplink_chunk = match s("uplink_chunk_size") {
            v if !v.is_empty() && v != "0" && v != "0-0" => Range::parse(&v, Range(3000, 4000))?,
            _ => match uplink_data {
                UplinkPlacement::Cookie => Range(2048, 3072),
                UplinkPlacement::Header => Range(3000, 4000),
                UplinkPlacement::Body => sc_max_each_post,
            },
        };
        // lx soft fallback: GET only makes sense for packet-up uploads; a
        // non-GET method must carry a body in stream modes.
        let mut uplink_method = s("uplink_http_method").to_uppercase();
        if uplink_method.is_empty() {
            uplink_method = "POST".to_string();
        }
        if uplink_method == "GET" && mode != Mode::PacketUp {
            crate::logging::warn(format_args!(
                "v2ray-xhttp: uplink_http_method GET outside packet-up mode; falling back to POST"
            ));
            uplink_method = "POST".to_string();
        }
        Ok(Self {
            session_placement,
            session_key,
            seq_placement,
            seq_key,
            session_table: if t.contains_key("session_table") {
                s("session_table")
            } else {
                s("session_id_table")
            },
            session_len: Range::parse(
                &if t.contains_key("session_length") {
                    s("session_length")
                } else {
                    s("session_id_length")
                },
                Range(0, 0),
            )?,
            uplink_data,
            uplink_key,
            uplink_chunk,
            uplink_method,
            x_obfs: t.get("x_padding_obfs_mode").and_then(Value::as_bool) == Some(true),
            x_key: match s("x_padding_key") {
                v if !v.is_empty() => v,
                _ => "x_padding".to_string(),
            },
            x_header: match s("x_padding_header") {
                v if !v.is_empty() => v,
                _ => "X-Padding".to_string(),
            },
            x_placement,
            x_method,
            sc_max_each_post,
            sc_min_interval_ms: Range::parse(&s("sc_min_posts_interval_ms"), Range(30, 30))?,
        })
    }
}

struct PooledClient {
    client: h2::client::SendRequest<Bytes>,
    active_streams: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

struct H2PoolState {
    clients: Vec<PooledClient>,
    active_dials: usize,
}

pub(crate) struct H2Pool {
    state: tokio::sync::Mutex<H2PoolState>,
    notify: tokio::sync::Notify,
}

pub(crate) enum H2Acquire {
    Ready(
        h2::client::SendRequest<Bytes>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ),
    NeedDial,
}

pub(crate) struct TrackedStream {
    inner: AnyStream,
    counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl tokio::io::AsyncRead for TrackedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl H2Pool {
    pub(crate) fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(H2PoolState {
                clients: Vec::new(),
                active_dials: 0,
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    pub(crate) async fn acquire(&self, max_conns: usize) -> H2Acquire {
        loop {
            let (candidate, active_streams) = {
                let mut guard = self.state.lock().await;

                if guard.clients.len() + guard.active_dials < max_conns {
                    guard.active_dials += 1;
                    return H2Acquire::NeedDial;
                }

                if guard.clients.is_empty()
                    || (guard.clients.len() < max_conns && guard.active_dials > 0)
                {
                    drop(guard);
                    self.notify.notified().await;
                    continue;
                }

                let (_idx, best) = guard
                    .clients
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, c)| {
                        c.active_streams.load(std::sync::atomic::Ordering::Relaxed)
                    })
                    .expect("non-empty");

                let client = best.client.clone();
                let active = best.active_streams.clone();
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                (client, active)
            };

            let client = candidate;
            match client.ready().await {
                Ok(client) => {
                    return H2Acquire::Ready(client, active_streams);
                }
                Err(_) => {
                    active_streams.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    let mut guard = self.state.lock().await;
                    guard
                        .clients
                        .retain(|c| !std::sync::Arc::ptr_eq(&c.active_streams, &active_streams));
                    drop(guard);
                    self.notify.notify_waiters();
                }
            }
        }
    }

    pub(crate) async fn finish_dial(
        &self,
        client: Option<h2::client::SendRequest<Bytes>>,
        max_conns: usize,
    ) -> Option<std::sync::Arc<std::sync::atomic::AtomicUsize>> {
        let mut guard = self.state.lock().await;
        guard.active_dials = guard.active_dials.saturating_sub(1);
        let mut counter = None;
        if let Some(c) = client {
            let cnt = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1));
            if guard.clients.len() >= max_conns {
                guard.clients.remove(0);
            }
            guard.clients.push(PooledClient {
                client: c,
                active_streams: cnt.clone(),
            });
            counter = Some(cnt);
        }
        drop(guard);
        self.notify.notify_waiters();
        counter
    }
}

#[derive(Clone)]
pub(crate) struct XhttpConfig {
    host: Option<String>,
    path: String,
    mode: Mode,
    headers: Vec<(String, String)>,
    padding: Range,
    no_grpc_header: bool,
    meta: Meta,
    /// keep-alive connections shared by the upload POSTs of every dial of this
    /// transport
    pool: std::sync::Arc<super::xmux::Pool>,
    h2_pool: std::sync::Arc<H2Pool>,
}

impl XhttpConfig {
    pub(crate) fn parse(t: &Map<String, Value>) -> anyhow::Result<Self> {
        let mode = match t.get("mode").and_then(Value::as_str).unwrap_or("") {
            "" | "auto" => Mode::Auto,
            "packet-up" => Mode::PacketUp,
            "stream-up" => Mode::StreamUp,
            "stream-one" => Mode::StreamOne,
            other => anyhow::bail!("v2ray-xhttp: unknown mode: {other}"),
        };
        let mut path = t
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let host = t
            .get("host")
            .and_then(Value::as_str)
            .filter(|h| !h.is_empty())
            .map(str::to_string);
        let mut headers = Vec::new();
        if let Some(Value::Object(map)) = t.get("headers") {
            for (k, v) in map {
                let v = v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("v2ray-xhttp: transport header {k:?} must be a string")
                })?;
                headers.push((k.clone(), v.to_string()));
            }
        }
        Ok(Self {
            host,
            path,
            mode,
            headers,
            padding: Range::parse(
                t.get("x_padding_bytes")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                Range(100, 1000),
            )?,
            no_grpc_header: t.get("no_grpc_header").and_then(Value::as_bool) == Some(true),
            meta: Meta::resolve(t, mode)?,
            pool: super::xmux::Pool::new(super::xmux::XmuxConfig::parse(
                t.get("xmux"),
                "v2ray-xhttp.xmux",
            )?),
            h2_pool: std::sync::Arc::new(H2Pool::new()),
        })
    }

    pub(crate) async fn connect_h2_stream(
        &self,
        tls: Option<&crate::tls_client::TlsOptions>,
        server: &str,
        port: u16,
        dial: &crate::outbound::dial::DialOptions,
    ) -> io::Result<Option<AnyStream>> {
        let Some(tls) = tls else {
            return Ok(None);
        };
        let mode = self.resolved_mode(true, true);
        if mode != Mode::StreamOne {
            return Ok(None);
        }

        let authority = self.host.clone().unwrap_or_else(|| {
            if server.contains(':') && !server.starts_with('[') {
                format!("[{server}]:{port}")
            } else {
                format!("{server}:{port}")
            }
        });
        let scheme = "https";
        let request = self.build_request(
            scheme,
            &authority,
            &self.meta.uplink_method,
            None,
            None,
            true,
        )?;

        let max_conns = self.pool.max_connections();
        let acq = self.h2_pool.acquire(max_conns).await;
        match acq {
            H2Acquire::Ready(mut send_req, counter) => {
                let (response, send) = send_req
                    .send_request(request, false)
                    .map_err(|e| io::Error::other(format!("xhttp: send_request: {e}")))?;
                let stream: AnyStream = Box::new(super::h2io::H2Io {
                    h2: super::h2io::H2Stream::shared(response, send),
                });
                Ok(Some(Box::new(TrackedStream {
                    inner: stream,
                    counter,
                })))
            }
            H2Acquire::NeedDial => {
                let res = async {
                    let tcp = crate::outbound::dial::connect_tcp(server, port, dial).await?;
                    let alpn: &[&[u8]] = &[b"h2", b"http/1.1"];
                    let stream: AnyStream = tls.wrap_with_defaults(tcp, alpn).await?;
                    let is_h2 = crate::inbound::stream_alpn(&stream) == Some(b"h2");
                    if !is_h2 {
                        return Err(io::Error::other("xhttp: server did not negotiate h2"));
                    }
                    let (send_request, connection) = super::h2io::client_builder()
                        .handshake(stream)
                        .await
                        .map_err(|e| io::Error::other(format!("xhttp: h2 handshake: {e}")))?;
                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            crate::logging::debug(format_args!("xhttp h2 connection: {e}"));
                        }
                    });
                    Ok(send_request)
                }
                .await;

                match res {
                    Ok(send_request) => {
                        let counter = self
                            .h2_pool
                            .finish_dial(Some(send_request.clone()), max_conns)
                            .await
                            .expect("counter present");
                        let mut send_req = send_request
                            .ready()
                            .await
                            .map_err(|e| io::Error::other(format!("xhttp: h2 ready: {e}")))?;
                        let (response, send) = send_req
                            .send_request(request, false)
                            .map_err(|e| io::Error::other(format!("xhttp: send_request: {e}")))?;
                        let stream: AnyStream = Box::new(super::h2io::H2Io {
                            h2: super::h2io::H2Stream::shared(response, send),
                        });
                        Ok(Some(Box::new(TrackedStream {
                            inner: stream,
                            counter,
                        })))
                    }
                    Err(e) => {
                        self.h2_pool.finish_dial(None, max_conns).await;
                        Err(e)
                    }
                }
            }
        }
    }

    fn resolved_mode(&self, tls: bool, is_h2: bool) -> Mode {
        match self.mode {
            // In reference sing-box (scratch/dialer.go:333), auto resolves to packet-up
            // (stream-one is only for REALITY).
            Mode::Auto => Mode::PacketUp,
            other => {
                let _ = (tls, is_h2);
                other
            }
        }
    }

    /// True when the transport will run its HTTP/1.1 request paths: everything
    /// but stream-one goes through `h1io`, so the connection must not negotiate
    /// h2 even when `tls.alpn` asks for it — a server that picks `h2` closes
    /// on our plaintext HTTP/1.1 request instead of answering it.
    pub(crate) fn h1_only(&self, secure: bool) -> bool {
        self.resolved_mode(secure, true) != Mode::StreamOne
    }
}

/// One xhttp tunnel: a download source and an upload sink. Over HTTP/1.1 those
/// are two connections, not two streams on one.
pub(crate) struct XhttpConn {
    split: Box<SplitConn>,
}

pub(crate) async fn connect(
    stream: AnyStream,
    secure: bool,
    server: &str,
    port: u16,
    cfg: &XhttpConfig,
    dialer: std::sync::Arc<Dialer>,
) -> io::Result<AnyStream> {
    let is_h2 = crate::inbound::stream_alpn(&stream) == Some(b"h2");
    let authority = cfg.host.clone().unwrap_or_else(|| {
        if server.contains(':') && !server.starts_with('[') {
            format!("[{server}]:{port}")
        } else {
            format!("{server}:{port}")
        }
    });
    let scheme = if secure { "https" } else { "http" };
    let mode = cfg.resolved_mode(secure, is_h2);
    crate::logging::debug(format_args!(
        "xhttp: connect {server}:{port} secure={secure} is_h2={is_h2} mode={mode:?}"
    ));

    // Over HTTP/2, stream-one uses a single bidirectional h2 stream, multiplexed
    // across pooled h2 connections (XMUX).
    if is_h2 && mode == Mode::StreamOne {
        let request = cfg.build_request(
            scheme,
            &authority,
            &cfg.meta.uplink_method,
            None,
            None,
            true,
        )?;

        let (send_request, connection) = super::h2io::client_builder()
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("xhttp: h2 handshake: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                crate::logging::debug(format_args!("xhttp h2 connection: {e}"));
            }
        });

        let max_conns = cfg.pool.max_connections();
        cfg.h2_pool
            .finish_dial(Some(send_request.clone()), max_conns)
            .await;

        let mut send_request = send_request
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("xhttp: h2 ready: {e}")))?;
        let (response, send) = send_request
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("xhttp: send_request: {e}")))?;
        return Ok(Box::new(super::h2io::H2Io {
            h2: super::h2io::H2Stream::shared(response, send),
        }));
    }

    let mut this = SplitConn::new(cfg);

    // stream-one is one bidirectional request on one connection: the body goes
    // up and the response comes back down it, so there is no separate download.
    if mode == Mode::StreamOne {
        let request = cfg.build_request(
            scheme,
            &authority,
            &cfg.meta.uplink_method,
            None,
            None,
            true,
        )?;
        let (io, resp) = h1io::Stream::start(stream, &request, &authority, true).await?;
        let failure = Failure::default();
        this.up = Up::Stream(Box::new(StreamUp {
            io,
            failure: failure.clone(),
        }));
        this.spawn_upload_download(resp, failure);
        return Ok(Box::new(XhttpConn {
            split: Box::new(this),
        }));
    }

    // The download GET is a long request, so it takes a connection of its own
    // with `Connection: close` — the reference says outright that a download GET
    // never shares one. The connection the caller dialled is exactly that, so
    // nothing extra is opened for it.
    let mut io = stream;
    let request = cfg.build_request(
        scheme,
        &authority,
        "GET",
        Some(&this.session_id),
        None,
        false,
    )?;
    let (head, pending) = h1io::send(&mut io, &request, &authority, b"", true)
        .await
        .map_err(|e| io::Error::other(format!("xhttp: download: {e}")))?;
    h1io::expect_ok(&head, "download")?;
    this.spawn_pump(h1io::Body::new(io, &head, pending));

    match mode {
        Mode::StreamUp => {
            let request = cfg.build_request(
                scheme,
                &authority,
                &cfg.meta.uplink_method,
                Some(&this.session_id),
                None,
                true,
            )?;
            let io = (dialer)().await?;
            let (io, resp) = h1io::Stream::start(io, &request, &authority, false).await?;
            let failure = Failure::default();
            this.up = Up::Stream(Box::new(StreamUp {
                io,
                failure: failure.clone(),
            }));
            // the upload's own response carries nothing back: it only says
            // whether the server took the request
            this.spawn_upload_ack(resp, failure);
        }
        // packet-up (and auto→packet-up)
        _ => {
            let (client_write, worker_read) = tokio::io::duplex(128 * 1024);
            let failure = Failure::default();
            let writer = PostWriter {
                cfg: cfg.clone(),
                scheme: scheme.to_string(),
                authority: authority.clone(),
                session_id: this.session_id.clone(),
                seq: 0,
                dialer,
            };
            let bytes_written = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
            let bytes_flushed = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
            let flush_notify = std::sync::Arc::new(tokio::sync::Notify::new());
            let task = tokio::spawn(packet_upload_worker(
                worker_read,
                writer,
                failure.clone(),
                std::sync::Arc::clone(&bytes_flushed),
                std::sync::Arc::clone(&flush_notify),
            ));
            this.up = Up::Packets(Box::new(PacketsUp {
                io: client_write,
                failure,
                bytes_written,
                bytes_flushed,
                flush_notify,
                flush_wait: None,
                task,
            }));
        }
    }
    Ok(Box::new(XhttpConn {
        split: Box::new(this),
    }))
}

/// What an upload request's response said, once the task behind it has seen it.
///
/// The error lives behind a lock rather than in the write path because it
/// arrives on somebody else's task: a refused upload POST shows up as the next
/// `poll_write` failing, not as the write that was already in flight.
#[derive(Clone, Default)]
struct Failure(std::sync::Arc<std::sync::Mutex<Option<io::Error>>>);

impl Failure {
    fn set(&self, e: io::Error) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(e);
        }
    }

    fn take(&self) -> Option<io::Error> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// One streamed upload POST: the request body goes up while a task reads the
/// response.
struct StreamUp {
    io: h1io::Stream,
    failure: Failure,
}

struct PostWriter {
    cfg: XhttpConfig,
    scheme: String,
    authority: String,
    session_id: String,
    seq: u64,
    dialer: std::sync::Arc<Dialer>,
}

impl PostWriter {
    /// A keep-alive connection for one upload POST, out of the pool when there
    /// is a free one and dialled when there is not.
    async fn connection(&self) -> io::Result<(std::sync::Arc<super::xmux::Client>, AnyStream)> {
        if let Some(client) = self.cfg.pool.acquire().await {
            if let Some(io) = client.take() {
                return Ok((client, io));
            }
            self.cfg.pool.release(&client).await;
        }
        let io = (self.dialer)().await?;
        let client = self.cfg.pool.insert(io).await;
        // `insert` parks the connection in the pool, and the pool is the only
        // owner, so it comes back out through the same door
        let io = client
            .take()
            .ok_or_else(|| io::Error::other("xhttp: pooled connection unavailable"))?;
        Ok((client, io))
    }

    /// Send one upload chunk as a single sequenced POST (reference
    /// `packetConn.sendPacket`).
    async fn send_packet(&mut self, chunk: &[u8]) -> io::Result<()> {
        let seq = self.seq;
        self.seq += 1;
        // One line per packet-up POST: which sequence number went out and how much
        // of the caller's stream it carried. XHTTP turns every write into a packet,
        // so this is the only place that can say whether what left matches what was
        // handed in -- and a server that reads one buffer and parses the request out
        // of it is very sensitive to a head arriving twice.
        crate::logging::debug(format_args!(
            "xhttp POST seq={seq} session={} bytes={} placement={:?}",
            self.session_id,
            chunk.len(),
            self.cfg.meta.uplink_data
        ));
        let payload = match self.cfg.meta.uplink_data {
            UplinkPlacement::Body => Some(Bytes::copy_from_slice(chunk)),
            UplinkPlacement::Header | UplinkPlacement::Cookie => None,
        };
        let mut req = self.cfg.build_request(
            &self.scheme,
            &self.authority,
            &self.cfg.meta.uplink_method,
            Some(&self.session_id),
            Some(&seq.to_string()),
            payload.is_some(),
        )?;
        // header/cookie payload: base64url chunks under <key>-<i> / <key>_<i>.
        // Only when the payload is not in the body: with `Body` placement the same
        // bytes in a header as well reach the far end twice, and Xray 26.9 reads
        // both (25.9 only reads the body, which is why this looked healthy).
        let mut pieces: Vec<&str> = Vec::new();
        let b64 = if payload.is_none() {
            base64_url(chunk)
        } else {
            String::new()
        };
        if payload.is_none() {
            let chunk_size = self.cfg.meta.uplink_chunk.rand().max(1) as usize;
            let bytes = b64.as_bytes();
            let mut at = 0;
            while at < bytes.len() {
                let end = (at + chunk_size).min(bytes.len());
                pieces.push(std::str::from_utf8(&bytes[at..end]).expect("base64 ascii"));
                at = end;
            }
            if pieces.is_empty() {
                pieces.push("");
            }
        }
        for (i, piece) in pieces.iter().enumerate() {
            let name = match self.cfg.meta.uplink_data {
                UplinkPlacement::Cookie => format!("{}_{}", self.cfg.meta.uplink_key, i),
                _ => format!("{}-{}", self.cfg.meta.uplink_key, i),
            };
            let hname = http::HeaderName::try_from(name.as_str())
                .map_err(|e| io::Error::other(format!("xhttp: header name: {e}")))?;
            let hvalue = http::HeaderValue::try_from(*piece)
                .map_err(|e| io::Error::other(format!("xhttp: header value: {e}")))?;
            if let UplinkPlacement::Cookie = self.cfg.meta.uplink_data {
                if let Some(h) = req.headers_mut().get_mut("cookie") {
                    let mut v = h.as_bytes().to_vec();
                    v.extend_from_slice(format!("; {}={}", name, piece).as_bytes());
                    *h = v
                        .try_into()
                        .map_err(|e| io::Error::other(format!("xhttp: cookie: {e}")))?;
                    continue;
                }
                req.headers_mut().insert("cookie", hvalue);
            } else {
                req.headers_mut().insert(hname, hvalue);
            }
        }
        let payload = payload.unwrap_or_default();

        let (client, io) = self.connection().await?;
        // one HTTP request against the pool's h_max_request_times: a packet-up
        // stream issues one POST per write, and a connection that ignored those
        // would outlive the limit the server was told about
        client.take_request();
        let mut body = match Self::post(io, &req, &self.authority, &payload).await {
            Ok((head, body)) => {
                if let Err(e) = h1io::expect_ok(&head, "upload") {
                    self.cfg.pool.release(&client).await;
                    return Err(e);
                }
                body
            }
            Err(e) => {
                self.cfg.pool.release(&client).await;
                return Err(e);
            }
        };
        // Drain the (usually empty) response body, so the connection is whole
        // again and can carry the next POST.
        let drained = body.drain().await;
        if drained.is_ok()
            && let Some(io) = body.into_inner()
        {
            client.give(io);
        }
        self.cfg.pool.release(&client).await;
        drained
    }

    /// One `Content-Length` POST plus its response head, over one connection.
    /// The connection comes back inside the body, and only out of it once the
    /// body has been drained.
    async fn post(
        io: AnyStream,
        request: &http::Request<()>,
        authority: &str,
        payload: &[u8],
    ) -> io::Result<(h1io::Head, h1io::Body)> {
        let mut io = io;
        let (head, pending) = h1io::send(&mut io, request, authority, payload, false)
            .await
            .map_err(|e| io::Error::other(format!("xhttp: send packet: {e}")))?;
        let body = h1io::Body::new(io, &head, pending);
        Ok((head, body))
    }
}

struct SplitConn {
    pending: BytesMut,
    dl: mpsc::Receiver<io::Result<Vec<u8>>>,
    dl_task: tokio::task::JoinHandle<()>,
    up: Up,
    session_id: String,
}

/// One packet-up upload stream: pipe into background upload worker.
struct PacketsUp {
    io: tokio::io::DuplexStream,
    failure: Failure,
    bytes_written: std::sync::Arc<portable_atomic::AtomicU64>,
    bytes_flushed: std::sync::Arc<portable_atomic::AtomicU64>,
    flush_notify: std::sync::Arc<tokio::sync::Notify>,
    flush_wait: Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
    task: tokio::task::JoinHandle<()>,
}

enum Up {
    Stream(Box<StreamUp>),
    Packets(Box<PacketsUp>),
    None,
}

impl SplitConn {
    fn new(cfg: &XhttpConfig) -> Self {
        let session_id = new_session_id(&cfg.meta);
        let (_, dl) = mpsc::channel(4);
        Self {
            pending: BytesMut::new(),
            dl,
            dl_task: tokio::spawn(async {}),
            up: Up::None,
            session_id,
        }
    }

    /// Feed the download channel from a response body, until it ends or the
    /// reader goes away.
    fn spawn_pump(&mut self, body: h1io::Body) {
        let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>(4);
        self.dl = rx;
        self.dl_task = tokio::spawn(pump(body, tx));
    }

    /// The upload request's response when it *is* the download stream, which is
    /// what stream-one does: one request, body up and body down.
    fn spawn_upload_download(
        &mut self,
        task: JoinHandle<io::Result<h1io::Body>>,
        failure: Failure,
    ) {
        let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>(4);
        self.dl = rx;
        self.dl_task = tokio::spawn(async move {
            match task.await {
                Ok(Ok(body)) => pump(body, tx).await,
                Ok(Err(e)) => {
                    failure.set(e);
                    let _ = tx.send(Err(failure.take().expect("just set"))).await;
                }
                Err(e) => {
                    let e = io::Error::other(format!("xhttp: upload: {e}"));
                    failure.set(io::Error::other(e.to_string()));
                    let _ = tx.send(Err(e)).await;
                }
            }
        });
    }

    /// The upload request's response when nothing comes back through it, which
    /// is stream-up: the download has a connection of its own, so this response
    /// only says whether the server took the request. Drain it and keep a
    /// failure for the next write.
    fn spawn_upload_ack(&mut self, task: JoinHandle<io::Result<h1io::Body>>, failure: Failure) {
        self.dl_task = tokio::spawn(async move {
            let mut body = match task.await {
                Ok(Ok(body)) => body,
                Ok(Err(e)) => {
                    failure.set(e);
                    return;
                }
                Err(e) => {
                    failure.set(io::Error::other(format!("xhttp: upload: {e}")));
                    return;
                }
            };
            if let Err(e) = body.drain().await {
                failure.set(e);
            }
        });
    }
}

/// Read a response body into the download channel. Channel close is EOF.
async fn pump(mut body: h1io::Body, tx: mpsc::Sender<io::Result<Vec<u8>>>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match body.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        if tx.send(Ok(buf[..n].to_vec())).await.is_err() {
            return;
        }
    }
}

impl AsyncRead for XhttpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let split = &mut *self.split;
        loop {
            if !split.pending.is_empty() {
                let n = out.remaining().min(split.pending.len());
                out.put_slice(&split.pending[..n]);
                let _ = split.pending.split_to(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(split.dl.poll_recv(cx)) {
                Some(Ok(chunk)) => split.pending.extend_from_slice(&chunk),
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => return Poll::Ready(Ok(())), // EOF
            }
        }
    }
}

impl AsyncWrite for XhttpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let split = &mut *self.split;
        match &mut split.up {
            Up::Stream(state) => {
                // a refused upload POST is reported here, not on the write that
                // was already in flight when the answer came back
                if let Some(e) = state.failure.take() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_write(cx, buf)
            }
            Up::Packets(state) => {
                if let Some(e) = state.failure.take() {
                    return Poll::Ready(Err(e));
                }
                let res = Pin::new(&mut state.io).poll_write(cx, buf);
                if let Poll::Ready(Ok(n)) = &res {
                    state
                        .bytes_written
                        .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
                }
                res
            }
            Up::None => Poll::Ready(Err(io::Error::other("xhttp: no upload stream"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let split = &mut *self.split;
        match &mut split.up {
            Up::Stream(state) => Pin::new(&mut state.io).poll_flush(cx),
            Up::Packets(state) => {
                if let Some(e) = state.failure.take() {
                    return Poll::Ready(Err(e));
                }
                let written = state
                    .bytes_written
                    .load(std::sync::atomic::Ordering::Relaxed);
                let flushed = state
                    .bytes_flushed
                    .load(std::sync::atomic::Ordering::Relaxed);
                if flushed >= written {
                    state.flush_wait = None;
                    return Pin::new(&mut state.io).poll_flush(cx);
                }
                if state.flush_wait.is_none() {
                    let notify = std::sync::Arc::clone(&state.flush_notify);
                    state.flush_wait = Some(Box::pin(async move {
                        notify.notified().await;
                    }));
                }
                if let Some(fut) = &mut state.flush_wait {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            state.flush_wait = None;
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Pending
                }
            }
            Up::None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let split = &mut *self.split;
        match &mut split.up {
            Up::Stream(state) => {
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
            }
            Up::Packets(state) => {
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
            }
            Up::None => {}
        }
        split.dl_task.abort();
        Poll::Ready(Ok(()))
    }
}

impl Drop for SplitConn {
    fn drop(&mut self) {
        self.dl_task.abort();
        if let Up::Packets(state) = &mut self.up {
            state.task.abort();
        }
    }
}

/// Background worker reading from the write pipe and uploading sequential POST packets.
async fn packet_upload_worker(
    mut reader: tokio::io::DuplexStream,
    mut writer: PostWriter,
    failure: Failure,
    bytes_flushed: std::sync::Arc<portable_atomic::AtomicU64>,
    flush_notify: std::sync::Arc<tokio::sync::Notify>,
) {
    let max_each = writer.cfg.meta.sc_max_each_post.rand().max(1) as usize;
    let min_interval = std::time::Duration::from_millis(writer.cfg.meta.sc_min_interval_ms.rand());
    let mut buf = vec![0u8; max_each];
    let mut last_post: Option<std::time::Instant> = None;

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                failure.set(e);
                break;
            }
        };

        if let Some(last) = last_post
            && min_interval > std::time::Duration::ZERO
        {
            let elapsed = std::time::Instant::now().saturating_duration_since(last);
            if elapsed < min_interval {
                tokio::time::sleep(min_interval - elapsed).await;
            }
        }
        last_post = Some(std::time::Instant::now());

        if let Err(e) = writer.send_packet(&buf[..n]).await {
            crate::logging::debug(format_args!("xhttp packet upload failed: {e}"));
            failure.set(e);
            break;
        }

        bytes_flushed.fetch_add(n as u64, std::sync::atomic::Ordering::Release);
        flush_notify.notify_waiters();
    }
    flush_notify.notify_waiters();
}

impl XhttpConfig {
    /// Construct one xhttp request: placement engine (session/seq) first,
    /// then X-Padding (reference `newRequest` → `applyMeta` → `applyXPadding`).
    fn build_request(
        &self,
        scheme: &str,
        authority: &str,
        method: &str,
        session: Option<&str>,
        seq: Option<&str>,
        has_body: bool,
    ) -> io::Result<http::Request<()>> {
        let mut path = self.path.clone();
        let mut query: Vec<(String, String)> = Vec::new();
        let mut extra_headers: Vec<(String, String)> = Vec::new();

        let m = &self.meta;
        // stream-one targets the bare path (no session id segment).
        if let Some(sid) = session {
            match m.session_placement {
                Placement::Path => {
                    if !path.ends_with('/') {
                        path.push('/');
                    }
                    path.push_str(sid);
                }
                Placement::Query => query.push((m.session_key.clone(), sid.to_string())),
                Placement::Header => extra_headers.push((m.session_key.clone(), sid.to_string())),
                Placement::Cookie => {
                    extra_headers.push(("cookie".to_string(), format!("{}={}", m.session_key, sid)))
                }
            }
        } else if !path.ends_with('/') {
            // stream-one: the reference client and Xray server expect the path to end
            // with a trailing slash when matching the route.
            path.push('/');
        }
        if let Some(seq) = seq {
            match m.seq_placement {
                Placement::Path => {
                    if !path.ends_with('/') {
                        path.push('/');
                    }
                    path.push_str(seq);
                }
                Placement::Query => query.push((m.seq_key.clone(), seq.to_string())),
                Placement::Header => extra_headers.push((m.seq_key.clone(), seq.to_string())),
                Placement::Cookie => {
                    extra_headers.push(("cookie".to_string(), format!("{}={}", m.seq_key, seq)))
                }
            }
        }

        // X-Padding.
        let pad = self.gen_padding();
        if m.x_obfs {
            match m.x_placement {
                XPlacement::Header => extra_headers.push((m.x_header.clone(), pad.clone())),
                XPlacement::Query => query.push((m.x_key.clone(), pad.clone())),
                XPlacement::Cookie => {
                    extra_headers.push(("cookie".to_string(), format!("{}={}", m.x_key, pad)))
                }
                XPlacement::QueryInHeader => extra_headers.push((
                    m.x_header.clone(),
                    format!("{scheme}://{authority}{path}?{}={pad}", m.x_key),
                )),
            }
        } else if !pad.is_empty() {
            // Legacy Xray: padding as ?x_padding= inside a Referer header. The
            // filler is a literal '0' rather than the configured method's
            // characters, because the server validates the *length* and the byte
            // is free -- and the reference is explicit that this exact default is
            // the one that has been live-verified against Xray. A zero length
            // sends no header at all, which is also what the reference does.
            extra_headers.push((
                "referer".to_string(),
                format!(
                    "{scheme}://{authority}{path}?x_padding={}",
                    "0".repeat(pad.len())
                ),
            ));
        }

        let mut uri = format!("{scheme}://{authority}{path}");
        if !query.is_empty() {
            uri.push('?');
            let parts: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
            uri.push_str(&parts.join("&"));
        }

        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in &self.headers {
            if HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        for (name, value) in extra_headers {
            builder = builder.header(name.as_str(), value);
        }
        // A streamed body (stream-one, stream-up) announces itself as gRPC by
        // default — reference `applyGRPCHeader` — and reverse proxies key
        // response streaming on that. A packet-up upload is not a stream: the
        // reference sends a plain `application/octet-stream` there, which is what
        // its HTTP client puts on a body it is given, so that is what goes on the
        // wire. Announcing gRPC on a per-packet upload is a claim nobody made.
        if has_body && !self.no_grpc_header {
            let content_type = match self.mode {
                Mode::PacketUp => "application/octet-stream",
                _ => "application/grpc",
            };
            builder = builder.header("content-type", content_type);
        }
        builder
            .body(())
            .map_err(|e| io::Error::other(format!("xhttp: build request: {e}")))
    }

    fn gen_padding(&self) -> String {
        let target = self.padding.rand() as usize;
        match self.meta.x_method {
            PadMethod::RepeatX => "X".repeat(target),
            PadMethod::Tokenish => tokenish(target),
        }
    }
}

/// Random dashed-UUID session id (default), or `session_table` /
/// `session_length` drawn characters (reference `newSessionID`).
fn new_session_id(meta: &Meta) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    if meta.session_table.is_empty() || meta.session_len.0 == 0 {
        let mut b = [0u8; 16];
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut b);
        let mut h = String::with_capacity(36);
        for (i, v) in b.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                h.push('-');
            }
            h.push(HEX[(v >> 4) as usize] as char);
            h.push(HEX[(v & 0x0f) as usize] as char);
        }
        return h;
    }
    let table: Vec<char> = core_config::xhttp_session_table(&meta.session_table)
        .chars()
        .collect();
    let len = meta.session_len.rand() as usize;
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 8];
    for _ in 0..len {
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut buf);
        out.push(table[u64::from_le_bytes(buf) as usize % table.len()]);
    }
    out
}

pub(crate) const HUF_BITS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

/// HPACK-Huffman-encoded byte length of `s` (RFC 7541 Appendix B).
fn huffman_len(s: &str) -> usize {
    let bits: usize = s.bytes().map(|b| HUF_BITS[b as usize] as usize).sum();
    bits.div_ceil(8)
}

/// base62 token whose HPACK-Huffman-encoded length lands within ±2 of
/// `target` (reference `GenerateTokenishPaddingBase62`): random base62 of
/// roughly the right raw length, then filler `X`/`Z` (8-bit Huffman codes,
/// stable length) tune the encoded size in, bounded by 150 iterations.
fn tokenish(target: usize) -> String {
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let rng_byte = || -> u8 {
        let mut b = [0u8; 1];
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut b);
        b[0]
    };
    // base62 chars are ~0.8 huffman bytes of entropy each on average.
    let len = target.div_ceil(4) * 5;
    let mut out: String = (0..len)
        .map(|_| BASE62[rng_byte() as usize % 62] as char)
        .collect();
    for _ in 0..150 {
        let enc = huffman_len(&out);
        if enc.abs_diff(target) <= 2 {
            return out;
        }
        if enc < target.saturating_sub(2) {
            out.push(if rng_byte() % 2 == 0 { 'X' } else { 'Z' });
        } else if enc > target + 2 && !out.is_empty() {
            out.pop();
        } else {
            // encoded within ±2 of a neighbor slot — keep rotating the body
            let idx = rng_byte() as usize % out.len();
            out.replace_range(
                idx..idx + 1,
                &(BASE62[rng_byte() as usize % 62] as char).to_string(),
            );
        }
    }
    out
}

fn base64_url(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(entries: Value) -> XhttpConfig {
        let t = entries.as_object().expect("object").clone();
        XhttpConfig::parse(&t).expect("parse")
    }

    #[test]
    fn meta_defaults() {
        let c = cfg(json!({}));
        assert_eq!(c.mode, Mode::Auto);
        assert_eq!(c.path, "/");
        assert_eq!(c.padding, Range(100, 1000));
        assert_eq!(c.meta.session_placement, Placement::Path);
        assert_eq!(c.meta.session_key, "x_session"); // header default not used for path
        assert_eq!(c.meta.uplink_method, "POST");
        assert_eq!(c.meta.uplink_data, UplinkPlacement::Body);
        assert_eq!(c.meta.x_method, PadMethod::RepeatX);
        assert!(!c.meta.x_obfs);
    }

    #[test]
    fn meta_header_key_defaults_are_asymmetric() {
        let c = cfg(json!({"session_placement": "header", "seq_placement": "cookie"}));
        assert_eq!(c.meta.session_key, "X-Session");
        assert_eq!(c.meta.seq_key, "x_seq");
    }

    #[test]
    fn request_path_session_and_seq() {
        let c = cfg(json!({"path": "/xhttp"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID1"), None, false)
            .unwrap();
        assert_eq!(req.uri().path(), "/xhttp/SID1");
        let req = c
            .build_request("https", "srv:443", "POST", Some("SID1"), Some("7"), true)
            .unwrap();
        assert_eq!(req.uri().path(), "/xhttp/SID1/7");
    }

    #[test]
    fn request_header_and_query_placements() {
        let c = cfg(json!({"path": "/up/", "session_placement": "header"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        // trailing slash preserved (load-bearing for reverse proxies)
        assert_eq!(req.uri().path(), "/up/");
        assert_eq!(req.headers().get("X-Session").unwrap(), "SID");

        let c = cfg(json!({"seq_placement": "query"}));
        let req = c
            .build_request("https", "srv:443", "POST", Some("SID"), Some("3"), true)
            .unwrap();
        assert!(req.uri().query().unwrap().contains("x_seq=3"));
    }

    #[test]
    fn request_cookie_placement() {
        let c = cfg(json!({"session_placement": "cookie"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        assert_eq!(req.headers().get("cookie").unwrap(), "x_session=SID");
    }

    #[test]
    fn padding_legacy_referer() {
        let c = cfg(json!({"x_padding_bytes": "50-50", "path": "/x"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        let referer = req.headers().get("referer").unwrap();
        assert!(
            referer
                .to_str()
                .unwrap()
                .starts_with("https://srv:443/x/SID?x_padding=")
        );
        let pad = referer.to_str().unwrap().rsplit('=').next().unwrap();
        assert_eq!(pad.len(), 50);
        // the legacy default fills with '0', not the obfs method's characters: the
        // server validates the length, and '0' is the byte the reference's
        // live-verified default uses
        assert!(pad.bytes().all(|b| b == b'0'));
    }

    /// A packet-up upload is a packet, not a stream: the reference sends
    /// `application/octet-stream` there and reserves the gRPC content type for
    /// the streamed modes, and a production node refused ours until it did.
    #[test]
    fn a_packet_up_upload_is_octet_stream_and_a_stream_is_grpc() {
        let packet = cfg(json!({"mode": "packet-up"}));
        let req = packet
            .build_request("https", "srv:443", "POST", Some("SID"), Some("0"), true)
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/octet-stream"
        );
        let stream = cfg(json!({"mode": "stream-one"}));
        let req = stream
            .build_request("https", "srv:443", "POST", None, None, true)
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/grpc"
        );
    }

    #[test]
    fn padding_obfs_header_and_tokenish() {
        let c = cfg(json!({
            "x_padding_obfs_mode": true,
            "x_padding_placement": "header",
            "x_padding_method": "tokenish",
            "x_padding_bytes": "100-100"
        }));
        let req = c
            .build_request("https", "srv:443", "GET", Some("S"), None, false)
            .unwrap();
        let pad = req.headers().get("X-Padding").unwrap().to_str().unwrap();
        // tokenish tunes the Huffman length into the reference's ±2 window.
        assert!((98..=102).contains(&huffman_len(pad)));
        assert!(!pad.bytes().all(|b| b == b'X'));
        assert!(pad.bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn grpc_header_toggle() {
        let c = cfg(json!({}));
        let req = c
            .build_request("https", "srv:443", "POST", None, None, true)
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/grpc"
        );
        let c = cfg(json!({"no_grpc_header": true}));
        let req = c
            .build_request("https", "srv:443", "POST", None, None, true)
            .unwrap();
        assert!(req.headers().get("content-type").is_none());
    }

    #[test]
    fn get_falls_back_to_post_outside_packet_up() {
        let c = cfg(json!({"mode": "stream-one", "uplink_http_method": "get"}));
        assert_eq!(c.meta.uplink_method, "POST");
        let c = cfg(json!({"mode": "packet-up", "uplink_http_method": "get"}));
        assert_eq!(c.meta.uplink_method, "GET");
    }

    #[test]
    fn uplink_header_rejected_outside_packet_up() {
        let err = XhttpConfig::parse(
            json!({"mode": "stream-up", "uplink_data_placement": "header"})
                .as_object()
                .unwrap(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn base64_url_alphabet() {
        assert_eq!(base64_url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64_url(&[]), "");
    }

    #[test]
    fn session_id_uuid_shape() {
        let id = new_session_id(&cfg(json!({})).meta);
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
    }

    /// Read one HTTP/1.1 request head off a raw stream.
    async fn read_request_head(io: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            assert_eq!(
                io.read(&mut byte).await.expect("read head"),
                1,
                "eof in head"
            );
            raw.push(byte[0]);
        }
        String::from_utf8(raw).expect("utf8 head")
    }

    /// Wire test over in-process raw HTTP/1.1 peers: the client must send a
    /// `Connection: close` download GET on the connection it was handed, and the
    /// seq-numbered upload POST on a second connection from the dialer, each with
    /// padding. The download body must flow back through the conn.
    #[tokio::test]
    async fn wire_packet_up_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timeout = std::time::Duration::from_secs(10);

        let (client_io, mut get_io) = tokio::io::duplex(1 << 16);
        let (post_tx, mut post_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let post_tx = post_tx.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(1 << 16);
                post_tx.send(server).expect("server side");
                Ok(Box::new(client) as AnyStream)
            })
        });
        let c = cfg(json!({"path": "/xhttp", "x_padding_bytes": "20-40"}));
        let stream: AnyStream = Box::new(client_io);

        let server = tokio::spawn(async move {
            // --- download GET: its own connection, closed after the response ---
            let head = read_request_head(&mut get_io).await;
            let line = head.lines().next().unwrap().to_string();
            assert!(line.starts_with("GET /xhttp/"), "got {line:?}");
            assert!(line.ends_with(" HTTP/1.1"), "got {line:?}");
            let path = line.split(' ').nth(1).unwrap();
            assert_eq!(path.matches('/').count(), 2, "got {path:?}");
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains("\r\nconnection: close\r\n"), "got {head:?}");
            assert!(lower.contains("\r\nhost: srv:443\r\n"), "got {head:?}");
            assert!(lower.contains("x_padding="), "padding missing: {head:?}");
            get_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .unwrap();

            // --- upload POST seq=0: a second connection from the dialer ---
            let mut post_io = post_rx.recv().await.expect("dialled connection");
            let head = read_request_head(&mut post_io).await;
            let line = head.lines().next().unwrap().to_string();
            assert!(line.starts_with("POST /xhttp/"), "got {line:?}");
            assert!(line.contains("/0 HTTP/1.1"), "got {line:?}");
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains("\r\ncontent-length: 4\r\n"), "got {head:?}");
            assert!(
                !lower.contains("connection: close"),
                "upload must keep alive"
            );
            assert!(
                !lower.contains("x-data-"),
                "the payload rides the body, a header copy arrives twice: {head:?}"
            );
            let mut body = [0u8; 4];
            post_io.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ping");
            post_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            // keep both ends open until the client has read everything
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(get_io);
            drop(post_io);
        });

        let mut conn = tokio::time::timeout(
            timeout,
            super::connect(stream, false, "srv", 443, &c, dialer),
        )
        .await
        .expect("connect timed out")
        .expect("connect");
        tokio::time::timeout(timeout, async {
            conn.write_all(b"ping").await.expect("write");
            conn.flush().await.expect("flush");
            let mut buf = vec![0u8; 5];
            conn.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"hello");
        })
        .await
        .expect("roundtrip timed out");
        tokio::time::timeout(timeout, server)
            .await
            .expect("server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn wire_packet_up_keep_alive_reuse() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timeout = std::time::Duration::from_secs(10);

        let (client_io, mut get_io) = tokio::io::duplex(1 << 16);
        let (post_tx, mut post_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let post_tx = post_tx.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(1 << 16);
                post_tx.send(server).expect("server side");
                Ok(Box::new(client) as AnyStream)
            })
        });
        let c = cfg(json!({"path": "/xhttp", "x_padding_bytes": "20-40"}));
        let stream: AnyStream = Box::new(client_io);

        let server = tokio::spawn(async move {
            // GET
            let _ = read_request_head(&mut get_io).await;
            get_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();

            // POST 0
            let mut post_io = post_rx.recv().await.expect("dialled connection 0");
            let head0 = read_request_head(&mut post_io).await;
            assert!(head0.contains("/0 HTTP/1.1"));
            let mut body0 = [0u8; 4];
            post_io.read_exact(&mut body0).await.unwrap();
            assert_eq!(&body0, b"ping");
            post_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            eprintln!("SERVER: POST 0 complete");

            // POST 1: MUST arrive on the SAME post_io, not a new dial!
            let head1 = read_request_head(&mut post_io).await;
            eprintln!(
                "SERVER: POST 1 read: {}",
                head1.lines().next().unwrap_or("")
            );
            assert!(head1.contains("/1 HTTP/1.1"), "got {head1:?}");
            let mut body1 = [0u8; 4];
            post_io.read_exact(&mut body1).await.unwrap();
            assert_eq!(&body1, b"pong");
            post_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            eprintln!("SERVER: POST 1 complete");

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            drop(get_io);
            drop(post_io);
        });

        let mut conn = tokio::time::timeout(
            timeout,
            super::connect(stream, false, "srv", 443, &c, dialer),
        )
        .await
        .expect("connect timed out")
        .expect("connect");

        tokio::time::timeout(timeout, async {
            conn.write_all(b"ping").await.expect("write 0");
            conn.flush().await.expect("flush 0");
            eprintln!("CLIENT: write 0 done");
            conn.write_all(b"pong").await.expect("write 1");
            conn.flush().await.expect("flush 1");
            eprintln!("CLIENT: write 1 done");
        })
        .await
        .expect("writes timed out");

        tokio::time::timeout(timeout, server)
            .await
            .expect("server timed out")
            .unwrap();
    }
}
