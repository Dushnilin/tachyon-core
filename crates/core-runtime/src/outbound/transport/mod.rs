//! v2ray-style stream transports (ws, httpupgrade, grpc, http) and the
//! shared outbound dial tail: TCP → optional TLS → transport → protocol.

pub(crate) mod grpc;
pub(crate) mod h1io;
pub(crate) mod h2io;
pub(crate) mod h3io;
mod http;
pub(crate) mod xhttp;
pub(crate) mod xmux;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use serde_json::Value;
use sha1::Digest as _;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::inbound::AnyStream;
use crate::outbound::proxy::base64_std;
use crate::outbound::shadowsocks::crypto::random_bytes;
use crate::tls_client::TlsOptions;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

#[derive(Default, Clone)]
pub(crate) struct Transport {
    kind: Kind,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Default)]
enum Kind {
    #[default]
    None,
    Ws {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
        /// `max_early_data`: bytes of the first write that ride in the upgrade
        /// request instead of a websocket frame
        max_early_data: usize,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
    },
    Grpc {
        service_name: String,
    },
    Http {
        host: Vec<String>,
        path: String,
        method: String,
        headers: Vec<(String, String)>,
    },
    Xhttp(Box<xhttp::XhttpConfig>),
}

fn parse_headers(value: Option<&Value>, at: &str) -> anyhow::Result<Vec<(String, String)>> {
    let Some(headers) = value else {
        return Ok(Vec::new());
    };
    match headers {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let v = v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("{at}: transport header {k:?} must be a string")
                })?;
                Ok((k.clone(), v.to_string()))
            })
            .collect(),
        Value::Array(items) => {
            items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let item = item.as_object().ok_or_else(|| {
                        anyhow::anyhow!("{at}: transport headers[{i}] must be an object")
                    })?;
                    let name = item.get("name").and_then(Value::as_str).ok_or_else(|| {
                        anyhow::anyhow!("{at}: transport headers[{i}].name missing")
                    })?;
                    let value = item.get("value").and_then(Value::as_str).ok_or_else(|| {
                        anyhow::anyhow!("{at}: transport headers[{i}].value missing")
                    })?;
                    Ok((name.to_string(), value.to_string()))
                })
                .collect()
        }
        _ => Err(anyhow::anyhow!(
            "{at}: transport headers must be an object or an array"
        )),
    }
}

fn parse_host_list(value: Option<&Value>, at: &str) -> anyhow::Result<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(host)) => Ok(vec![host.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: transport host entries must be strings"))
            })
            .collect(),
        Some(_) => Err(anyhow::anyhow!(
            "{at}: transport host must be a string or an array of strings"
        )),
    }
}

/// `host:port` authority, bracketing IPv6 literals.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl Transport {
    /// Parse the outbound `transport` object (absent/null → no transport).
    pub(crate) fn parse(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let Some(transport) = obj.get("transport") else {
            return Ok(Self { kind: Kind::None });
        };
        let Some(transport) = transport.as_object() else {
            anyhow::bail!("{at}: transport must be an object");
        };
        let ty = transport
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: transport missing type"))?;
        let kind = match ty {
            "ws" => Kind::Ws {
                path: transport
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/")
                    .to_string(),
                host: transport
                    .get("host")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                headers: parse_headers(transport.get("headers"), at)?,
                max_early_data: transport
                    .get("max_early_data")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize,
            },
            "httpupgrade" => Kind::HttpUpgrade {
                path: transport
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/")
                    .to_string(),
                host: transport
                    .get("host")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                headers: parse_headers(transport.get("headers"), at)?,
            },
            "grpc" => {
                warn_unimplemented_grpc_fields(transport, at);
                Kind::Grpc {
                    service_name: transport
                        .get("service_name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                }
            }
            "http" => {
                warn_unimplemented_http_fields(transport, at);
                let mut method = transport
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("PUT")
                    .to_string();
                if method.is_empty() {
                    method = "PUT".to_string();
                }
                let mut path = transport
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/")
                    .to_string();
                if !path.starts_with('/') {
                    path.insert(0, '/');
                }
                Kind::Http {
                    host: parse_host_list(transport.get("host"), at)?,
                    path,
                    method,
                    headers: parse_headers(transport.get("headers"), at)?,
                }
            }
            "xhttp" => Kind::Xhttp(Box::new(xhttp::XhttpConfig::parse(transport)?)),
            other => anyhow::bail!("{at}: transport type {other:?} not implemented yet"),
        };
        Ok(Self { kind })
    }

    /// The ALPN this transport asks for when the config sets none.
    ///
    /// XHTTP is HTTP/1.1 and nothing else: the reference refuses h2 there even
    /// when the server offers it, on purpose (`transport/v2rayxhttp/http1.go`,
    /// lx SPEC 104) — a non-nil empty `TLSNextProto` map turns HTTP/2 off for
    /// the whole transport. Offering `h2` instead is what made Xray 26.9 hand
    /// the far end our request head plus the payload twice.
    fn default_alpn(&self, secure: bool) -> &'static [&'static [u8]] {
        match &self.kind {
            Kind::Grpc { .. } => &[b"h2"],
            Kind::Xhttp(_) => &[b"h2", b"http/1.1"],
            Kind::Http { .. } if secure => &[b"h2"],
            _ => &[],
        }
    }

    /// Dial the full outbound stream: TCP → optional TLS → transport.
    /// `early` is the first protocol write; a transport that can carry it in
    /// its handshake (ws early data) takes as much as it declared and reports
    /// the count so the caller writes only the rest.
    ///
    /// `dial` is here for the transports that need more than the one connection
    /// they were handed. HTTP/1.1 does not multiplex, so XHTTP opens a second
    /// connection per concurrent request — and ALPN, which decides what a
    /// connection speaks, is chosen per connection, so it cannot be settled once
    /// for the whole transport.
    pub(crate) async fn connect(
        &self,
        tcp: TcpStream,
        tls: Option<&TlsOptions>,
        server: &str,
        port: u16,
        early: &[u8],
        dial: &crate::outbound::dial::DialOptions,
    ) -> io::Result<(AnyStream, usize)> {
        let default_alpn = self.default_alpn(tls.is_some());
        let stream: AnyStream = match tls {
            Some(tls) => tls.wrap_with_defaults(tcp, default_alpn).await?,
            None => Box::new(tcp),
        };
        let (stream, consumed) = match &self.kind {
            Kind::None => (stream, 0),
            Kind::Ws {
                path,
                host,
                headers,
                max_early_data,
            } => {
                let host = host.as_deref().unwrap_or(server);
                ws_handshake(stream, path, host, headers, early, *max_early_data).await?
            }
            Kind::HttpUpgrade {
                path,
                host,
                headers,
            } => {
                let host = host.as_deref().unwrap_or(server);
                (httpupgrade_handshake(stream, path, host, headers).await?, 0)
            }
            Kind::Grpc { service_name } => {
                let sni = tls.map(TlsOptions::server_name).unwrap_or(server);
                (
                    grpc::connect(stream, service_name, &authority(sni, port), tls.is_some())
                        .await?,
                    0,
                )
            }
            Kind::Http {
                host,
                path,
                method,
                headers,
            } => (
                http::connect(
                    stream,
                    tls.is_some(),
                    server,
                    port,
                    host,
                    path,
                    method,
                    headers,
                )
                .await?,
                0,
            ),
            Kind::Xhttp(cfg) => {
                let dialer = self.dialer(tls, server, port, dial);
                (
                    xhttp::connect(stream, tls.is_some(), server, port, cfg, dialer).await?,
                    0,
                )
            }
        };
        Ok((stream, consumed))
    }

    /// A closure that opens one more connection to the same server with the same
    /// TCP options, the same TLS and the same ALPN as the first one.
    fn dialer(
        &self,
        tls: Option<&TlsOptions>,
        server: &str,
        port: u16,
        dial: &crate::outbound::dial::DialOptions,
    ) -> Arc<xhttp::Dialer> {
        let server = server.to_string();
        let dial = dial.clone();
        let tls = tls.cloned();
        let alpn = self.default_alpn(tls.is_some());
        Arc::new(move || {
            let server = server.clone();
            let dial = dial.clone();
            let tls = tls.clone();
            Box::pin(async move {
                let tcp = crate::outbound::dial::connect_tcp(&server, port, &dial).await?;
                let stream: AnyStream = match tls {
                    Some(tls) => tls.wrap_with_defaults(tcp, alpn).await?,
                    None => Box::new(tcp),
                };
                Ok(stream)
            }) as Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>>
        })
    }
}

/// `transport.grpc` keepalive knobs: the h2 layer does not send PINGs yet, so
/// the values are parsed (validating the duration) and reported as a gap.
fn warn_unimplemented_grpc_fields(transport: &serde_json::Map<String, Value>, at: &str) {
    let mut warned = false;
    for key in ["idle_timeout", "ping_timeout", "permit_without_stream"] {
        if transport.contains_key(key) && !warned {
            crate::logging::warn(format_args!(
                "{at}: transport grpc keepalive options are not implemented yet; ignoring"
            ));
            warned = true;
        }
    }
}

/// `transport.http` idle/ping timeouts: same story as the grpc knobs.
fn warn_unimplemented_http_fields(transport: &serde_json::Map<String, Value>, at: &str) {
    for key in ["idle_timeout", "ping_timeout"] {
        if transport.contains_key(key) {
            crate::logging::warn(format_args!(
                "{at}: transport http {key} is not implemented yet; ignoring"
            ));
        }
    }
}

async fn read_response_head(stream: &mut AnyStream) -> io::Result<String> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("transport response head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn append_headers(request: &mut String, headers: &[(String, String)]) {
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
}

/// Websocket upgrade. When `max_early_data` is set the first bytes of the
/// tunnel ride along in `Sec-WebSocket-Protocol` (base64), which saves a round
/// trip; the server still answers 101 and everything after it is normal
/// framing. Returns how many bytes of `early` were consumed.
async fn ws_handshake(
    mut stream: AnyStream,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    early: &[u8],
    max_early_data: usize,
) -> io::Result<(AnyStream, usize)> {
    let mut key_bytes = [0u8; 16];
    random_bytes(&mut key_bytes)?;
    let key = base64_std(&key_bytes);
    // one reserved String, pushed into: format! starts empty and doubles its
    // way to a ~150 byte head, which is seven allocations for one handshake
    let mut request =
        String::with_capacity(160 + path.len() + host.len() + key.len() + headers.len() * 48);
    request.push_str("GET ");
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(host);
    request.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    request.push_str(&key);
    request.push_str("\r\nSec-WebSocket-Version: 13\r\n");
    // the early data owns the protocol header, so a configured one is dropped
    let carried = early.len().min(max_early_data);
    for (name, value) in headers {
        if carried > 0 && name.eq_ignore_ascii_case("sec-websocket-protocol") {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if carried > 0 {
        request.push_str("Sec-WebSocket-Protocol: ");
        request.push_str(&base64_std(&early[..carried]));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let response = read_response_head(&mut stream).await?;
    let status = response.lines().next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(io::Error::other(format!("ws handshake failed: {status}")));
    }
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(WS_GUID);
    let expected = base64_std(&hash.finalize());
    if !response
        .to_ascii_lowercase()
        .contains(&expected.to_ascii_lowercase())
    {
        return Err(io::Error::other("ws handshake: bad Sec-WebSocket-Accept"));
    }
    Ok((Box::new(WsStream::new(stream)), carried))
}

async fn httpupgrade_handshake(
    mut stream: AnyStream,
    path: &str,
    host: &str,
    headers: &[(String, String)],
) -> io::Result<AnyStream> {
    let mut request = String::with_capacity(80 + path.len() + host.len() + headers.len() * 48);
    request.push_str("GET ");
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(host);
    request.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");
    append_headers(&mut request, headers);
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    let response = read_response_head(&mut stream).await?;
    let status = response.lines().next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(io::Error::other(format!(
            "httpupgrade handshake failed: {status}"
        )));
    }
    // The reference's net/http hijack race needs a brief pause on loopback
    // so the server finishes hijacking before the first VLESS byte lands.
    // 1 ms clears the hijack window while staying well under the connect_ms
    // threshold (1.5x + 2 ms).
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    Ok(stream)
}

/// RFC 6455 websocket carrying the protocol bytes as binary messages; frames
/// are concatenated into a byte stream in each direction.
///
/// Reading keeps a read-ahead buffer: the socket (usually a TLS stream) is read
/// in big gulps, frame headers are parsed out of the buffer, and the payload is
/// unmasked where it lies and copied once, to the caller. Writing builds a
/// frame in one reusable buffer and masks it word by word.
pub(crate) struct WsStream {
    inner: AnyStream,
    /// bytes off the wire not consumed yet: `rbuf[rpos..]`, its length being the
    /// filled part. Allocated once at [`WS_READ`] and grown only if it ever fills
    /// up: a buffer that follows the traffic means a realloc, and every realloc
    /// over glibc's mmap threshold is a fresh mmap and munmap pair on the hot
    /// path.
    rbuf: Vec<u8>,
    rpos: usize,
    /// payload of the data frame being handed out that is still to come, its
    /// masking key and how far into the payload the key has rotated
    left: usize,
    mask: Option<[u8; 4]>,
    mask_at: usize,
    eof: bool,
    /// Payload of a ping awaiting a pong reply.
    pong: Option<Vec<u8>>,
    /// Whole frames waiting to go out (data, pongs, close), and how much of
    /// them is written. Frames are only ever appended whole.
    wbuf: Vec<u8>,
    wpos: usize,
    /// Caller bytes consumed by the data frame currently flushing.
    consumed: Option<usize>,
    close_sent: bool,
    /// A client masks what it sends and a server does not (RFC 6455 5.3), so one
    /// codec serves both ends with this single bit between them. Reading needs no
    /// such flag: a frame says for itself whether it is masked.
    mask_out: bool,
}

/// What one read asks the socket for at least.
const WS_READ: usize = 32 * 1024;

/// Enough for any frame header, and no more: the biggest one is a 14-byte extended
/// length. A read at a frame boundary asks for just this, so the payload is never
/// staged on its way to a caller that would only copy it straight out again.
const HEAD_PROBE: usize = 16;

/// A frame header parsed out of the buffer.
struct FrameHead {
    opcode: u8,
    len: usize,
    mask: Option<[u8; 4]>,
    /// header bytes in the buffer
    size: usize,
}

fn parse_head(bytes: &[u8]) -> io::Result<Option<FrameHead>> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let opcode = bytes[0] & 0x0F;
    let masked = bytes[1] & 0x80 != 0;
    let small = usize::from(bytes[1] & 0x7F);
    let ext = match small {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let size = 2 + ext + if masked { 4 } else { 0 };
    if bytes.len() < size {
        return Ok(None);
    }
    let len = match ext {
        2 => usize::from(u16::from_be_bytes([bytes[2], bytes[3]])),
        8 => usize::try_from(u64::from_be_bytes(
            bytes[2..10].try_into().expect("8 bytes"),
        ))
        .map_err(|_| io::Error::other("ws: frame too large"))?,
        _ => small,
    };
    let mask = masked.then(|| bytes[2 + ext..2 + ext + 4].try_into().expect("4 bytes"));
    Ok(Some(FrameHead {
        opcode,
        len,
        mask,
        size,
    }))
}

/// XOR `buf` with the masking key, `at` bytes into the payload. Eight bytes at
/// a time: a byte loop with a modulo is what made masking the hot spot.
fn xor_mask(buf: &mut [u8], mut mask: [u8; 4], at: usize) {
    mask.rotate_left(at % 4);
    let word = u32::from_ne_bytes(mask);
    let wide = u64::from(word) | (u64::from(word) << 32);
    let (words, rest) = buf.as_chunks_mut::<8>();
    for word in words {
        *word = (u64::from_ne_bytes(*word) ^ wide).to_ne_bytes();
    }
    for (i, byte) in rest.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
}

impl WsStream {
    /// The client end: what it sends is masked, as RFC 6455 §5.3 requires.
    pub(crate) fn new(inner: AnyStream) -> Self {
        Self::with_masking(inner, true)
    }

    /// The server end: same codec, no mask on the way out. Frames coming *in* are
    /// masked either way, and the reader has always known how to unmask them, so
    /// one codec serves both directions and the handshake is the only difference.
    pub(crate) fn server(inner: AnyStream) -> Self {
        Self::with_masking(inner, false)
    }

    fn with_masking(inner: AnyStream, mask_out: bool) -> Self {
        Self {
            mask_out,
            inner,
            rbuf: Vec::with_capacity(WS_READ),
            rpos: 0,
            left: 0,
            mask: None,
            mask_at: 0,
            eof: false,
            pong: None,
            wbuf: Vec::new(),
            wpos: 0,
            consumed: None,
            close_sent: false,
        }
    }

    /// Read more of the wire into the buffer; `false` on a clean end.
    fn poll_more(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        // Only a masked payload fills this buffer, and a server never masks: what
        // gets staged here is a frame header, or the head of a payload when a mask
        // is in play. So the common case has room and never reallocates.
        if self.rbuf.len() == self.rbuf.capacity() {
            if self.rpos > 0 {
                let end = self.rbuf.len();
                self.rbuf.copy_within(self.rpos..end, 0);
                self.rbuf.truncate(end - self.rpos);
                self.rpos = 0;
            }
            if self.rbuf.len() == self.rbuf.capacity() {
                self.rbuf.reserve(WS_READ);
            }
        }
        let have = self.rbuf.len();
        // At a frame boundary only the head is wanted, and it is at most 14 bytes.
        // Reading a whole buffer's worth here staged the payload as well, and the
        // caller then copied that out to reach it: an extra pass over every frame,
        // which showed up as a sixth of the client CPU. Once a head is in, read in
        // full -- that is the masked case, where the payload has to be staged.
        let room = if have == 0 {
            HEAD_PROBE.min(self.rbuf.capacity())
        } else {
            self.rbuf.capacity() - have
        };
        let mut read = ReadBuf::uninit(&mut self.rbuf.spare_capacity_mut()[..room]);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
        let got = read.filled().len();
        if got == 0 {
            return Poll::Ready(Ok(false));
        }
        // SAFETY: the reader initialised exactly `got` bytes of the spare
        // capacity, starting at `have`.
        unsafe { self.rbuf.set_len(have + got) };
        Poll::Ready(Ok(true))
    }

    /// Drain the queued frames into the socket.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ws: frame write stalled",
                )));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    /// Append one whole frame to the write queue, masked unless this is the
    /// server end.
    fn push_frame(&mut self, opcode: u8, payload: &[u8]) {
        let mut mask = [0u8; 4];
        if self.mask_out {
            let _ = random_bytes(&mut mask);
        }
        let len = payload.len();
        self.wbuf.reserve(14 + len);
        self.wbuf.push(0x80 | opcode);
        let masked_bit = if self.mask_out { 0x80 } else { 0 };
        if len < 126 {
            self.wbuf.push(masked_bit | len as u8);
        } else if len <= usize::from(u16::MAX) {
            self.wbuf.push(masked_bit | 126);
            self.wbuf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            self.wbuf.push(masked_bit | 127);
            self.wbuf.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if self.mask_out {
            self.wbuf.extend_from_slice(&mask);
            let from = self.wbuf.len();
            self.wbuf.extend_from_slice(payload);
            xor_mask(&mut self.wbuf[from..], mask, 0);
        } else {
            self.wbuf.extend_from_slice(payload);
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            let avail = me.rbuf.len() - me.rpos;
            if me.left > 0 {
                if avail > 0 {
                    let n = avail.min(me.left).min(out.remaining());
                    let chunk = &mut me.rbuf[me.rpos..me.rpos + n];
                    if let Some(mask) = me.mask {
                        xor_mask(chunk, mask, me.mask_at);
                        me.mask_at += n;
                    }
                    out.put_slice(chunk);
                    me.rpos += n;
                    me.left -= n;
                    return Poll::Ready(Ok(()));
                }
                // Nothing staged and nothing to unmask: hand the caller's own
                // buffer to the socket. Staging the payload and then copying it
                // out cost a memmove per read on top of the one rustls already
                // does, and on this path the payload is most of the traffic.
                if me.mask.is_none() && out.remaining() > 0 {
                    let n = me.left.min(out.remaining());
                    let mut direct = ReadBuf::new(out.initialize_unfilled_to(n));
                    ready!(Pin::new(&mut me.inner).poll_read(cx, &mut direct))?;
                    let got = direct.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ws: payload ended mid-frame",
                        )));
                    }
                    me.left -= got;
                    out.advance(got);
                    return Poll::Ready(Ok(()));
                }
            } else if let Some(head) = parse_head(&me.rbuf[me.rpos..])? {
                let is_control = head.opcode >= 0x8;
                if is_control {
                    // a control payload is at most 125 bytes: take it whole
                    if head.len > 125 {
                        return Poll::Ready(Err(io::Error::other("ws: oversized control frame")));
                    }
                    if avail >= head.size + head.len {
                        let start = me.rpos + head.size;
                        let mut payload = me.rbuf[start..start + head.len].to_vec();
                        if let Some(mask) = head.mask {
                            xor_mask(&mut payload, mask, 0);
                        }
                        me.rpos = start + head.len;
                        match head.opcode {
                            OP_CLOSE => me.eof = true,
                            OP_PING => me.pong = Some(payload),
                            _ => {}
                        }
                        continue;
                    }
                } else {
                    me.rpos += head.size;
                    me.left = head.len;
                    me.mask = head.mask;
                    me.mask_at = 0;
                    continue;
                }
            }
            match ready!(me.poll_more(cx))? {
                true => {}
                false if me.rbuf.len() == me.rpos && me.left == 0 => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                false => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ws: connection closed mid-frame",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        loop {
            ready!(me.poll_drain(cx))?;
            if let Some(consumed) = me.consumed.take() {
                return Poll::Ready(Ok(consumed));
            }
            if let Some(payload) = me.pong.take() {
                me.push_frame(OP_PONG, &payload);
                continue;
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let take = buf.len().min(65535);
            me.push_frame(OP_BINARY, &buf[..take]);
            me.consumed = Some(take);
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if !me.close_sent {
            me.close_sent = true;
            me.push_frame(OP_CLOSE, &[]);
        }
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
