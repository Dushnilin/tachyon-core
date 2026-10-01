//! XHTTP (Xray "splithttp") client transport — HTTP/2.
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
//! HTTP/2 only: TLS dials offer `h2` (like grpc/http), cleartext dials use
//! h2c prior knowledge (the reference speaks HTTP/1.1 cleartext — documented
//! divergence, tracked in the roadmap).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use h2::SendStream;
use h2::client::ResponseFuture;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::h2io::{H2Io, H2Stream};
use crate::inbound::AnyStream;

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

/// The stream handed back to the caller: it releases its pooled connection when
/// it is dropped, which is the only place a stream knows it is finished.
struct Pooled {
    inner: AnyStream,
    pool: std::sync::Arc<super::xmux::Pool>,
    client: std::sync::Arc<super::xmux::Client>,
}

impl Pooled {
    fn wrap(
        cfg: &XhttpConfig,
        inner: AnyStream,
        client: std::sync::Arc<super::xmux::Client>,
    ) -> AnyStream {
        Box::new(Self {
            inner,
            pool: std::sync::Arc::clone(&cfg.pool),
            client,
        })
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        // Drop cannot await, so the release is handed to the runtime; a
        // connection whose task is already gone is aborted right here.
        let pool = std::sync::Arc::clone(&self.pool);
        let client = std::sync::Arc::clone(&self.client);
        tokio::spawn(async move {
            pool.release(&client).await;
        });
    }
}

impl tokio::io::AsyncRead for Pooled {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl tokio::io::AsyncWrite for Pooled {
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
        let s = |k: &str| {
            t.get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
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
            v if !v.is_empty() => Range::parse(&v, Range(3000, 4000))?,
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
            session_table: s("session_table"),
            session_len: Range::parse(&s("session_length"), Range(0, 0))?,
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

#[derive(Clone)]
pub(crate) struct XhttpConfig {
    host: Option<String>,
    path: String,
    mode: Mode,
    headers: Vec<(String, String)>,
    padding: Range,
    no_grpc_header: bool,
    meta: Meta,
    /// XHTTP connection reuse, shared by every dial of this transport
    pool: std::sync::Arc<super::xmux::Pool>,
    /// the pooled connection this stream runs on, filled in per dial
    client: Option<std::sync::Arc<super::xmux::Client>>,
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
            client: None,
        })
    }

    /// A copy of the config bound to the pooled connection a stream runs on.
    fn with_client(&self, client: std::sync::Arc<super::xmux::Client>) -> Self {
        let mut copy = self.clone();
        copy.client = Some(client);
        copy
    }

    fn resolved_mode(&self, tls: bool) -> Mode {
        match self.mode {
            // auto: Reality → stream-one, otherwise packet-up. Reality is not
            // implemented yet, so auto is packet-up until it lands (F2).
            Mode::Auto => Mode::PacketUp,
            other => {
                let _ = tls;
                other
            }
        }
    }
}

/// One xhttp connection: a download source and an upload sink over a single
/// h2 connection.
pub(crate) struct XhttpConn {
    split: Box<SplitConn>,
}

pub(crate) async fn connect(
    stream: AnyStream,
    secure: bool,
    server: &str,
    port: u16,
    cfg: &XhttpConfig,
) -> io::Result<AnyStream> {
    // a pooled connection is reused whenever one can take another stream; the
    // connection task belongs to the pool entry, not to the stream
    let (send_request, client) = match cfg.pool.acquire().await {
        Some(client) => (client.send.clone(), client),
        None => {
            let (send_request, connection) = h2::client::handshake(stream)
                .await
                .map_err(|e| io::Error::other(format!("xhttp: h2 handshake: {e}")))?;
            let client = cfg
                .pool
                .insert(
                    send_request.clone(),
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
                .await;
            (send_request, client)
        }
    };

    // from here on the config carries this stream's connection, so every
    // request it issues is accounted against the pool's limits
    let cfg = &cfg.with_client(std::sync::Arc::clone(&client));
    let authority = cfg.host.clone().unwrap_or_else(|| {
        if server.contains(':') && !server.starts_with('[') {
            format!("[{server}]:{port}")
        } else {
            format!("{server}:{port}")
        }
    });
    let scheme = if secure { "https" } else { "http" };
    let mode = cfg.resolved_mode(secure);

    match mode {
        Mode::StreamOne => {
            let (response, send) = issue(
                send_request,
                cfg,
                scheme,
                &authority,
                &cfg.meta.uplink_method,
                None,
                None,
                true,
            )
            .await?;
            let body: AnyStream = Box::new(H2Io {
                h2: H2Stream::shared(response, send),
            });
            Ok(Pooled::wrap(cfg, body, client))
        }
        Mode::StreamUp => {
            let mut this = SplitConn::new(cfg, send_request.clone());
            // Download: GET with the session id, no seq.
            let (dl_resp, _) = issue(
                send_request.clone(),
                cfg,
                scheme,
                &authority,
                "GET",
                Some(&this.session_id),
                None,
                false,
            )
            .await?;
            this.spawn_download(dl_resp);
            // Upload: one streamed POST using the configured method.
            let (_, send) = issue(
                send_request,
                cfg,
                scheme,
                &authority,
                &cfg.meta.uplink_method,
                Some(&this.session_id),
                None,
                true,
            )
            .await?;
            this.up = Up::Stream(send);
            let body: AnyStream = Box::new(XhttpConn {
                split: Box::new(this),
            });
            Ok(Pooled::wrap(cfg, body, client))
        }
        _ => {
            // packet-up (and auto→packet-up)
            let mut this = SplitConn::new(cfg, send_request);
            let (dl_resp, _) = issue(
                this.send_request(),
                cfg,
                scheme,
                &authority,
                "GET",
                Some(&this.session_id),
                None,
                false,
            )
            .await?;
            this.spawn_download(dl_resp);
            this.up = Up::Packets(Box::new(PacketsState {
                writer: Some(PostWriter {
                    send_request: this.send_request(),
                    cfg: cfg.clone(),
                    scheme: scheme.to_string(),
                    authority: authority.clone(),
                    session_id: this.session_id.clone(),
                    seq: 0,
                    last_post: None,
                }),
                in_flight: None,
            }));
            let body: AnyStream = Box::new(XhttpConn {
                split: Box::new(this),
            });
            Ok(Pooled::wrap(cfg, body, client))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn issue(
    send_request: h2::client::SendRequest<Bytes>,
    cfg: &XhttpConfig,
    scheme: &str,
    authority: &str,
    method: &str,
    session: Option<&str>,
    seq: Option<String>,
    body: bool,
) -> io::Result<(ResponseFuture, SendStream<Bytes>)> {
    let mut ready = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("xhttp: h2 ready: {e}")))?;
    // one HTTP request against the pool's h_max_request_times: a packet-up
    // stream issues one POST per write, and a connection that ignored those
    // would outlive the limit the server was told about
    if let Some(client) = &cfg.client {
        client.take_request();
    }
    let request = cfg.build_request(scheme, authority, method, session, seq.as_deref(), body)?;
    let (response, send) = ready
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("xhttp: send request: {e}")))?;
    Ok((response, send))
}

struct PostWriter {
    send_request: h2::client::SendRequest<Bytes>,
    cfg: XhttpConfig,
    scheme: String,
    authority: String,
    session_id: String,
    seq: u64,
    last_post: Option<std::time::Instant>,
}

impl PostWriter {
    /// Send one upload chunk as a single sequenced POST (reference
    /// `packetConn.sendPacket`).
    async fn send_packet(&mut self, chunk: &[u8]) -> io::Result<()> {
        // Anti-burst throttle: enforce the minimum inter-post interval.
        let interval = std::time::Duration::from_millis(self.cfg.meta.sc_min_interval_ms.rand());
        let now = std::time::Instant::now();
        if let Some(last) = self.last_post
            && interval > std::time::Duration::ZERO
        {
            let earliest = last + interval;
            if earliest > now {
                tokio::time::sleep(earliest - now).await;
            }
        }
        self.last_post = Some(std::time::Instant::now());

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
        let chunk_size = self.cfg.meta.uplink_chunk.rand().max(1) as usize;
        let b64 = base64_url(chunk);
        let mut pieces: Vec<&str> = Vec::new();
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
        let send_request = self.send_request.clone();
        let mut ready = send_request
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("xhttp: h2 ready: {e}")))?;
        let (response, mut send) = ready
            .send_request(req, false)
            .map_err(|e| io::Error::other(format!("xhttp: send packet: {e}")))?;
        send.send_data(payload, true)
            .map_err(|e| io::Error::other(format!("xhttp: packet body: {e}")))?;
        let resp = response
            .await
            .map_err(|e| io::Error::other(format!("xhttp: upload: {e}")))?;
        if resp.status().as_u16() != 200 {
            return Err(io::Error::other(format!(
                "v2ray-xhttp: unexpected upload status: {}",
                resp.status()
            )));
        }
        // Drain the (usually empty) response body.
        let mut body = resp.into_body();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| io::Error::other(format!("xhttp: upload body: {e}")))?;
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        Ok(())
    }
}

struct SplitConn {
    pending: BytesMut,
    dl: mpsc::Receiver<io::Result<Vec<u8>>>,
    dl_task: tokio::task::JoinHandle<()>,
    up: Up,
    session_id: String,
    send_request: h2::client::SendRequest<Bytes>,
}

type InFlight = Option<Pin<Box<dyn Future<Output = io::Result<(PostWriter, usize)>> + Send>>>;

/// One packet-up write in progress: the writer plus its bounded POST run.
struct PacketsState {
    writer: Option<PostWriter>,
    in_flight: InFlight,
}

enum Up {
    Stream(SendStream<Bytes>),
    Packets(Box<PacketsState>),
    None,
}

impl SplitConn {
    fn new(cfg: &XhttpConfig, send_request: h2::client::SendRequest<Bytes>) -> Self {
        let session_id = new_session_id(&cfg.meta);
        let (_, dl) = mpsc::channel(4);
        Self {
            pending: BytesMut::new(),
            dl,
            dl_task: tokio::spawn(async {}),
            up: Up::None,
            session_id,
            send_request,
        }
    }

    fn send_request(&self) -> h2::client::SendRequest<Bytes> {
        self.send_request.clone()
    }

    fn spawn_download(&mut self, response: ResponseFuture) {
        let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>(4);
        self.dl = rx;
        self.dl_task = tokio::spawn(async move {
            let resp = match response.await {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx
                        .send(Err(io::Error::other(format!("xhttp: download: {e}"))))
                        .await;
                    return;
                }
            };
            if resp.status().as_u16() != 200 {
                let _ = tx
                    .send(Err(io::Error::other(format!(
                        "v2ray-xhttp: unexpected download status: {}",
                        resp.status()
                    ))))
                    .await;
                return;
            }
            let mut body = resp.into_body();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(chunk) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if tx.send(Ok(chunk.to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(io::Error::other(format!("xhttp: download: {e}"))))
                            .await;
                        return;
                    }
                }
            }
            // Channel close = EOF.
        });
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
            Up::Stream(send) => {
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                send.reserve_capacity(buf.len());
                let cap = match ready!(send.poll_capacity(cx)) {
                    Some(Ok(cap)) => cap,
                    Some(Err(e)) => {
                        return Poll::Ready(Err(io::Error::other(format!("xhttp: capacity: {e}"))));
                    }
                    None => return Poll::Ready(Err(io::Error::other("xhttp: stream closed"))),
                };
                let n = cap.min(buf.len());
                send.send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(|e| io::Error::other(format!("xhttp: send: {e}")))?;
                Poll::Ready(Ok(n))
            }
            Up::Packets(state) => {
                // Split like the reference Write: sc_max_each_post_bytes
                // bounds one POST; the whole buffer is reported written
                // once every POST completed.
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                if state.in_flight.is_none() {
                    let writer = state.writer.take().expect("post writer present");
                    let data = buf.to_vec();
                    state.in_flight =
                        Some(Box::pin(async move { write_packets(writer, data).await }));
                }
                match state
                    .in_flight
                    .as_mut()
                    .expect("set above")
                    .as_mut()
                    .poll(cx)
                {
                    Poll::Ready(Ok((writer, n))) => {
                        state.writer = Some(writer);
                        state.in_flight = None;
                        Poll::Ready(Ok(n.min(buf.len())))
                    }
                    Poll::Ready(Err(e)) => {
                        state.in_flight = None;
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            Up::None => Poll::Ready(Err(io::Error::other("xhttp: no upload stream"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let split = &mut *self.split;
        if let Up::Stream(send) = &mut split.up
            && let Err(e) = send.send_data(Bytes::new(), true)
        {
            return Poll::Ready(Err(io::Error::other(format!("xhttp: end stream: {e}"))));
        }
        split.dl_task.abort();
        Poll::Ready(Ok(()))
    }
}

impl Drop for SplitConn {
    fn drop(&mut self) {
        self.dl_task.abort();
    }
}

/// Sequential throttled POST upload (reference `packetConn.Write`).
async fn write_packets(mut writer: PostWriter, data: Vec<u8>) -> io::Result<(PostWriter, usize)> {
    let mut max_each = writer.cfg.meta.sc_max_each_post.rand();
    if max_each == 0 {
        max_each = data.len().max(1) as u64;
    }
    let mut written = 0usize;
    while written < data.len() {
        let end = ((written as u64) + max_each).min(data.len() as u64) as usize;
        writer.send_packet(&data[written..end]).await?;
        written = end;
    }
    Ok((writer, data.len()))
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
            if H2_SKIP.contains(&name.to_ascii_lowercase().as_str()) {
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
    let table: Vec<char> = meta.session_table.chars().collect();
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

    /// Wire test over an in-process h2 server: the client must speak
    /// GET-download + seq-numbered POST uploads with padding, and the
    /// download body must flow back through the conn.
    #[tokio::test]
    async fn wire_packet_up_roundtrip() {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let c = cfg(json!({"path": "/xhttp", "x_padding_bytes": "20-40"}));
        let client = tokio::spawn(async move {
            let stream: AnyStream = Box::new(client_io);
            super::connect(stream, false, "srv", 443, &c).await
        });

        let mut conn = client.await.unwrap().expect("connect");
        let server = tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.expect("h2 server");

            // --- download GET ---
            let (req, mut respond) = server.accept().await.expect("stream").expect("http");
            assert_eq!(req.method(), "GET");
            assert!(req.uri().path().starts_with("/xhttp/"));
            assert!(req.uri().path().matches('/').count() == 2);
            let referer = req.headers().get("referer").expect("referer padding");
            assert!(referer.to_str().unwrap().contains("x_padding="));
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(b"hello"), false).unwrap();
            send.send_data(Bytes::new(), true).unwrap();

            // --- upload POST seq=0 ---
            let (req, mut respond) = server.accept().await.expect("stream").expect("http");
            assert_eq!(req.method(), "POST");
            assert!(req.uri().path().ends_with("/0"));
            let mut body = req.into_body();
            let mut uploaded = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                let _ = body.flow_control().release_capacity(chunk.len());
                uploaded.extend_from_slice(&chunk);
            }
            assert_eq!(&uploaded, b"ping");
            let response = http::Response::builder().status(200).body(()).unwrap();
            let respond = respond.send_response(response, true).unwrap();
            // Drive the server connection so the response frames flush
            // before the task (and the connection) is dropped.
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(500), server.accept()).await;
            drop(respond);
        });

        let writer = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            conn.write_all(b"ping").await.expect("write");
            let mut buf = vec![0u8; 5];
            conn.read_exact(&mut buf).await.expect("read");
            buf
        });

        server.await.unwrap();
        let buf = writer.await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
