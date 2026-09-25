//! v2ray-style stream transports (ws, httpupgrade, grpc, http) and the
//! shared outbound dial tail: TCP → optional TLS → transport → protocol.

mod grpc;
pub(crate) mod h2io;
mod http;
pub(crate) mod xhttp;

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
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

#[derive(Default)]
pub(crate) struct Transport {
    kind: Kind,
}

#[derive(Default)]
enum Kind {
    #[default]
    None,
    Ws {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
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
            "ws" => {
                if transport
                    .get("max_early_data")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    > 0
                {
                    crate::logging::warn(format_args!(
                        "{at}: transport ws max_early_data is not implemented yet; ignoring"
                    ));
                }
                Kind::Ws {
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
                }
            }
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

    /// Dial the full outbound stream: TCP → optional TLS → transport.
    pub(crate) async fn connect(
        &self,
        tcp: TcpStream,
        tls: Option<&TlsOptions>,
        server: &str,
        port: u16,
    ) -> io::Result<AnyStream> {
        // sing-box defaults ALPN to h2 for grpc/http when the user set none.
        let default_alpn: &[&[u8]] = match &self.kind {
            Kind::Grpc { .. } | Kind::Xhttp(_) => &[b"h2"],
            Kind::Http { .. } if tls.is_some() => &[b"h2"],
            _ => &[],
        };
        let stream: AnyStream = match tls {
            Some(tls) => tls.wrap_with_defaults(tcp, default_alpn).await?,
            None => Box::new(tcp),
        };
        match &self.kind {
            Kind::None => Ok(stream),
            Kind::Ws {
                path,
                host,
                headers,
            } => {
                let host = host.as_deref().unwrap_or(server);
                ws_handshake(stream, path, host, headers).await
            }
            Kind::HttpUpgrade {
                path,
                host,
                headers,
            } => {
                let host = host.as_deref().unwrap_or(server);
                httpupgrade_handshake(stream, path, host, headers).await
            }
            Kind::Grpc { service_name } => {
                let sni = tls.map(TlsOptions::server_name).unwrap_or(server);
                grpc::connect(stream, service_name, &authority(sni, port), tls.is_some()).await
            }
            Kind::Http {
                host,
                path,
                method,
                headers,
            } => {
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
                .await
            }
            Kind::Xhttp(cfg) => xhttp::connect(stream, tls.is_some(), server, port, cfg).await,
        }
    }
}

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

async fn ws_handshake(
    mut stream: AnyStream,
    path: &str,
    host: &str,
    headers: &[(String, String)],
) -> io::Result<AnyStream> {
    let mut key_bytes = [0u8; 16];
    random_bytes(&mut key_bytes)?;
    let key = base64_std(&key_bytes);
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    append_headers(&mut request, headers);
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
    Ok(Box::new(WsStream::new(stream)))
}

async fn httpupgrade_handshake(
    mut stream: AnyStream,
    path: &str,
    host: &str,
    headers: &[(String, String)],
) -> io::Result<AnyStream> {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    );
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
    Ok(stream)
}

/// RFC 6455 websocket carrying the protocol bytes as binary messages; frames
/// are concatenated into a byte stream in each direction.
pub(crate) struct WsStream {
    inner: AnyStream,
    state: WsRead,
    buffer: Vec<u8>,
    pos: usize,
    eof: bool,
    /// Payload of a ping awaiting a pong reply.
    pong: Option<Vec<u8>>,
    /// Queued frames not yet flushed (control pongs, close frame).
    outbox: VecDeque<Vec<u8>>,
    /// Frame currently being flushed (bytes, offset).
    flushing: Option<(Vec<u8>, usize)>,
    /// Caller bytes consumed by the data frame currently flushing.
    consumed: Option<usize>,
    close_sent: bool,
}

enum WsRead {
    /// Collecting the 2-byte frame header.
    Header { buf: Vec<u8> },
    /// Collecting the 2/8-byte extended length.
    ExtLen {
        b0: u8,
        masked: bool,
        wide: usize,
        buf: Vec<u8>,
    },
    /// Collecting the 4-byte masking key (never sent by our peers, but the
    /// parser tolerates it).
    Mask {
        opcode: u8,
        len: usize,
        buf: Vec<u8>,
    },
    /// Collecting the payload.
    Payload {
        opcode: u8,
        len: usize,
        mask: Option<[u8; 4]>,
        buf: Vec<u8>,
    },
}

impl WsStream {
    fn new(inner: AnyStream) -> Self {
        Self {
            inner,
            state: WsRead::Header { buf: Vec::new() },
            buffer: Vec::new(),
            pos: 0,
            eof: false,
            pong: None,
            outbox: VecDeque::new(),
            flushing: None,
            consumed: None,
            close_sent: false,
        }
    }

    /// Drive the frame parser until a data frame is buffered, the stream
    /// ends, or the socket pends.
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match std::mem::replace(&mut self.state, WsRead::Header { buf: Vec::new() }) {
                WsRead::Header { mut buf } => match poll_fill(&mut self.inner, cx, &mut buf, 2) {
                    Poll::Ready(Ok(true)) => {
                        let opcode = buf[0] & 0x0F;
                        let masked = buf[1] & 0x80 != 0;
                        let small = usize::from(buf[1] & 0x7F);
                        self.state = match small {
                            126 => WsRead::ExtLen {
                                b0: buf[0],
                                masked,
                                wide: 2,
                                buf: Vec::new(),
                            },
                            127 => WsRead::ExtLen {
                                b0: buf[0],
                                masked,
                                wide: 8,
                                buf: Vec::new(),
                            },
                            _ if masked => WsRead::Mask {
                                opcode,
                                len: small,
                                buf: Vec::new(),
                            },
                            _ => WsRead::Payload {
                                opcode,
                                len: small,
                                mask: None,
                                buf: Vec::new(),
                            },
                        };
                    }
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ws: connection closed mid-frame",
                        )));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        self.state = WsRead::Header { buf };
                        return Poll::Pending;
                    }
                },
                WsRead::ExtLen {
                    b0,
                    masked,
                    wide,
                    mut buf,
                } => match poll_fill(&mut self.inner, cx, &mut buf, wide) {
                    Poll::Ready(Ok(true)) => {
                        let opcode = b0 & 0x0F;
                        let len = if wide == 2 {
                            usize::from(u16::from_be_bytes(buf[..2].try_into().expect("2 bytes")))
                        } else {
                            usize::try_from(u64::from_be_bytes(
                                buf[..8].try_into().expect("8 bytes"),
                            ))
                            .map_err(|_| io::Error::other("ws: frame too large"))?
                        };
                        self.state = if masked {
                            WsRead::Mask {
                                opcode,
                                len,
                                buf: Vec::new(),
                            }
                        } else {
                            WsRead::Payload {
                                opcode,
                                len,
                                mask: None,
                                buf: Vec::new(),
                            }
                        };
                    }
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ws: connection closed mid-frame",
                        )));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        self.state = WsRead::ExtLen {
                            b0,
                            masked,
                            wide,
                            buf,
                        };
                        return Poll::Pending;
                    }
                },
                WsRead::Mask {
                    opcode,
                    len,
                    mut buf,
                } => match poll_fill(&mut self.inner, cx, &mut buf, 4) {
                    Poll::Ready(Ok(true)) => {
                        self.state = WsRead::Payload {
                            opcode,
                            len,
                            mask: Some(buf[..4].try_into().expect("4 bytes")),
                            buf: Vec::new(),
                        };
                    }
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ws: connection closed mid-frame",
                        )));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        self.state = WsRead::Mask { opcode, len, buf };
                        return Poll::Pending;
                    }
                },
                WsRead::Payload {
                    opcode,
                    len,
                    mut mask,
                    mut buf,
                } => {
                    match poll_fill(&mut self.inner, cx, &mut buf, len) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ws: connection closed mid-frame",
                            )));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            self.state = WsRead::Payload {
                                opcode,
                                len,
                                mask,
                                buf,
                            };
                            return Poll::Pending;
                        }
                    }
                    if let Some(mask) = mask.take() {
                        for (i, byte) in buf.iter_mut().enumerate() {
                            *byte ^= mask[i % 4];
                        }
                    }
                    match opcode {
                        OP_CLOSE => {
                            self.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        OP_PING => {
                            self.pong = Some(std::mem::take(&mut buf));
                        }
                        OP_PONG => {}
                        _ => {
                            self.buffer = buf;
                            self.pos = 0;
                            return Poll::Ready(Ok(()));
                        }
                    }
                    self.state = WsRead::Header { buf: Vec::new() };
                }
            }
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some((frame, off)) = &mut self.flushing {
                while *off < frame.len() {
                    let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &frame[*off..]))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "ws: frame write stalled",
                        )));
                    }
                    *off += n;
                }
                self.flushing = None;
                continue;
            }
            match self.outbox.pop_front() {
                Some(frame) => self.flushing = Some((frame, 0)),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pos < self.buffer.len() {
                let n = out.remaining().min(self.buffer.len() - self.pos);
                out.put_slice(&self.buffer[self.pos..self.pos + n]);
                self.pos += n;
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            ready!(self.as_mut().poll_frame(cx))?;
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.as_mut().poll_drain(cx))?;
            if self.flushing.is_some() || !self.outbox.is_empty() {
                continue;
            }
            if let Some(consumed) = self.consumed.take() {
                return Poll::Ready(Ok(consumed));
            }
            if let Some(payload) = self.pong.take() {
                self.outbox.push_back(build_masked(OP_PONG, &payload));
                continue;
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let take = buf.len().min(65535);
            self.outbox.push_back(build_masked(OP_BINARY, &buf[..take]));
            self.consumed = Some(take);
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.close_sent {
            self.close_sent = true;
            self.outbox.push_back(build_masked(OP_CLOSE, &[]));
        }
        ready!(self.as_mut().poll_drain(cx))?;
        let inner = &mut self.as_mut().inner;
        Pin::new(&mut **inner).poll_shutdown(cx)
    }
}

/// Client frames must be masked (RFC 6455 §5.3); a random key per frame.
fn build_masked(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut mask = [0u8; 4];
    let _ = random_bytes(&mut mask);
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.push(0x80 | opcode);
    let flag = 0x80;
    let len = payload.len();
    if len < 126 {
        frame.push(flag | len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(flag | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(flag | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// Fill `buf` to `need` bytes; `Ok(false)` on clean EOF with an empty buffer.
fn poll_fill(
    inner: &mut AnyStream,
    cx: &mut Context<'_>,
    buf: &mut Vec<u8>,
    need: usize,
) -> Poll<io::Result<bool>> {
    while buf.len() < need {
        let missing = need - buf.len();
        let mut scratch = vec![0u8; missing];
        let mut read_buf = ReadBuf::new(&mut scratch);
        match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(false));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ws: stream closed mid-frame",
                    )));
                }
                buf.extend_from_slice(&scratch[..n]);
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(true))
}
