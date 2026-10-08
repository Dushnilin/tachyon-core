//! NaiveProxy outbound: HTTP/2 `CONNECT` over TLS (ALPN `h2`), with optional
//! UDP over the sing `uot` framing.
//!
//! The tunnel authority is the requested destination (NaiveProxy servers act
//! as a TCP forward proxy), the proxy identity travels in
//! `proxy-authorization: Basic`, and the TLS SNI comes from `tls.server_name`
//! or the server address. UDP needs `udp_over_tcp`: the client opens a tunnel
//! to the reserved magic address, writes the uot request header, and then
//! exchanges bare datagrams.
//!
//! What makes it naive rather than a plain HTTP CONNECT is the `Padding`
//! header -- the reference answers 400 without one, and puts one on the response
//! too -- and the framing of the first eight blocks in each direction:
//! `[len:u16 BE][pad:u8][data][pad zero bytes]`. The reference's `naiveH2Conn`
//! embeds `paddingConn` and reads through `readWithPadding`, so the frames are
//! real on the wire even though nothing ever writes `paddingConn{...}`.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use serde_json::{Map, Value};
use tokio::io::AsyncWriteExt;

use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::proxy::{base64_std, server_endpoint};
use crate::outbound::quic::{CongestionKind, udp_loopback_pair};
use crate::outbound::transport::h2io::{H2Io, H2Stream};
use crate::outbound::uot::{UOT_DEFAULT_VERSION, magic_authority, request_header, spawn_bridge};
use crate::tls_client::TlsOptions;

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Blocks in each direction that carry the naive framing (`paddingCount`).
const PADDING_COUNT: usize = 8;

/// A `Padding` header value: 30 to 62 bytes, the first sixteen drawn from a
/// punctuation set and the rest tildes, so the header reads as proxy noise.
fn padding_header() -> String {
    const NOISE: &[u8] = b"!#$()+<>?@[]^`{}";
    let mut random = [0u8; 8];
    let _ = getrandom::fill(&mut random);
    let mut bits = u64::from_le_bytes(random) % 33 + 30;
    let len = bits as usize;
    let mut bytes = vec![b'~'; len];
    for slot in bytes[..16].iter_mut() {
        *slot = NOISE[(bits & 15) as usize];
        bits >>= 4;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// What the read side still owes the peer: a header, the data it announced,
/// the padding behind it, or nothing at all once the eight blocks are past.
#[derive(Clone, Copy)]
enum ReadStep {
    Header,
    /// the block's data has arrived; only its padding is left
    Data {
        pad: usize,
    },
    Padding,
    Raw,
}

/// The eight blocks are past: read on, or frame no more writes.
fn next_step(blocks: usize) -> ReadStep {
    if blocks >= PADDING_COUNT {
        ReadStep::Raw
    } else {
        ReadStep::Header
    }
}

/// The naive framing around a tunnel, both directions: the first eight writes
/// and the first eight blocks read carry `[len:u16][pad:u8]` in front of the
/// data and `pad` zero bytes behind it. The reference splits what it sends at
/// 65535 bytes first (`writeChunked`), which changes nothing here -- a block is
/// whatever its header announces.
struct Padded<S> {
    inner: S,
    // write side
    write_blocks: usize,
    flushing: Option<(Vec<u8>, usize)>,
    consumed: usize,
    // read side
    read_blocks: usize,
    step: ReadStep,
    staging: Vec<u8>,
    staging_filled: usize,
    staging_want: usize,
    payload: Vec<u8>,
    pos: usize,
}

impl<S> Padded<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            write_blocks: 0,
            flushing: None,
            consumed: 0,
            read_blocks: 0,
            step: ReadStep::Header,
            staging: Vec::new(),
            staging_filled: 0,
            staging_want: 3,
            payload: Vec::new(),
            pos: 0,
        }
    }
}

/// Fill `staging` to `want` bytes across as many `Pending`s as it takes.
fn poll_fill<S: tokio::io::AsyncRead + Unpin>(
    inner: &mut S,
    cx: &mut std::task::Context<'_>,
    staging: &mut Vec<u8>,
    filled: &mut usize,
    want: usize,
) -> std::task::Poll<std::io::Result<()>> {
    if *filled == 0 {
        staging.clear();
        staging.resize(want.max(1), 0);
    }
    while *filled < want {
        let mut read_buf = tokio::io::ReadBuf::new(&mut staging[*filled..]);
        match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            std::task::Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "naive: stream closed inside the padding",
                    )));
                }
                *filled += n;
            }
            std::task::Poll::Ready(Err(err)) => return std::task::Poll::Ready(Err(err)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    }
    std::task::Poll::Ready(Ok(()))
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Padded<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.pos < this.payload.len() {
                let n = out.remaining().min(this.payload.len() - this.pos);
                out.put_slice(&this.payload[this.pos..this.pos + n]);
                this.pos += n;
                return std::task::Poll::Ready(Ok(()));
            }
            this.payload.clear();
            this.pos = 0;
            if let ReadStep::Raw = this.step {
                std::task::ready!(std::pin::Pin::new(&mut this.inner).poll_read(cx, out))?;
                return std::task::Poll::Ready(Ok(()));
            }
            // one piece of a block at a time, and only once all of it has
            // arrived: a half-read header would step the framing over bytes
            // still in flight
            std::task::ready!(poll_fill(
                &mut this.inner,
                cx,
                &mut this.staging,
                &mut this.staging_filled,
                this.staging_want,
            ))?;
            let block = std::mem::take(&mut this.staging);
            this.staging_filled = 0;
            this.read_blocks += 1;
            match this.step {
                ReadStep::Header => {
                    let len = usize::from(u16::from_be_bytes([block[0], block[1]]));
                    let pad = usize::from(block[2]);
                    this.step = ReadStep::Data { pad };
                    this.staging_want = len;
                }
                ReadStep::Data { pad } => {
                    this.payload = block;
                    if pad == 0 {
                        // nothing to swallow: the next thing is a header, or the
                        // stream is done with the framing
                        this.step = next_step(this.read_blocks);
                        this.staging_want = 3;
                    } else {
                        this.step = ReadStep::Padding;
                        this.staging_want = pad;
                    }
                }
                ReadStep::Padding => {
                    this.step = next_step(this.read_blocks);
                    this.staging_want = 3;
                }
                ReadStep::Raw => unreachable!("handled above"),
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Padded<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        loop {
            if let Some((frame, off)) = &mut this.flushing {
                while *off < frame.len() {
                    let n = std::task::ready!(
                        std::pin::Pin::new(&mut this.inner).poll_write(cx, &frame[*off..],)
                    )?;
                    if n == 0 {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "naive: padded write stalled",
                        )));
                    }
                    *off += n;
                }
                this.flushing = None;
                return std::task::Poll::Ready(Ok(this.consumed));
            }
            if buf.is_empty() {
                return std::task::Poll::Ready(Ok(0));
            }
            if this.write_blocks >= PADDING_COUNT {
                return std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            let mut random = [0u8; 1];
            let _ = getrandom::fill(&mut random);
            let pad = usize::from(random[0]);
            let mut frame = Vec::with_capacity(3 + buf.len() + pad);
            frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            frame.push(pad as u8);
            frame.extend_from_slice(buf);
            frame.resize(frame.len() + pad, 0);
            this.write_blocks += 1;
            this.flushing = Some((frame, 0));
            this.consumed = buf.len();
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Config knobs that only tune the reference (cronet) client internals.
const TUNING_FIELDS: &[&str] = &[
    "insecure_concurrency",
    "stream_receive_window",
    "quic_session_receive_window",
];

#[derive(Debug)]
pub struct Naive {
    server: String,
    port: u16,
    tls: TlsOptions,
    /// ready-made `proxy-authorization` value
    authorization: Option<String>,
    extra_headers: Vec<(String, String)>,
    /// `None` → UDP unsupported; `Some(1|2)` → uot framing version
    uot_version: Option<u8>,
    /// `quic: true` runs the tunnel over HTTP/3 instead of HTTP/2
    quic: bool,
    quic_tunnel: crate::outbound::quic::QuicTunnelOptions,
    congestion: crate::outbound::quic::CongestionKind,
    dial: crate::outbound::dial::DialOptions,
}

impl Naive {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let Some(tls) = TlsOptions::from_outbound(obj, &server, at)? else {
            anyhow::bail!("{at}: naive outbound requires tls");
        };
        // the reference refuses a naive tunnel that skips certificate checking
        if obj
            .get("tls")
            .and_then(|tls| tls.get("insecure"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            anyhow::bail!("{at}: insecure is not supported on naive outbound");
        }
        if obj
            .get("tls")
            .and_then(|tls| tls.get("disable_sni"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            anyhow::bail!("{at}: disable_sni is not supported on naive outbound");
        }
        let quic = obj.get("quic").and_then(Value::as_bool).unwrap_or(false);
        // the switch runs whether or not quic is on, like the reference
        let congestion = match obj
            .get("quic_congestion_control")
            .and_then(Value::as_str)
            .unwrap_or("")
        {
            "" | "bbr" | "bbr2" => CongestionKind::Bbr,
            "cubic" => CongestionKind::Cubic,
            "reno" => CongestionKind::NewReno,
            other => anyhow::bail!("{at}: unknown quic congestion control: {other}"),
        };
        for field in TUNING_FIELDS {
            if obj.get(*field).is_some_and(|value| !value.is_null()) {
                logging::warn(format_args!(
                    "naive outbound {at}: {field} only tunes the reference client (ignored)"
                ));
            }
        }
        if obj
            .get("quic_congestion_control")
            .is_some_and(|value| !value.is_null())
        {
            logging::warn(format_args!(
                "naive outbound {at}: quic_congestion_control requires quic (ignored)"
            ));
        }
        let authorization = match (
            obj.get("username").and_then(Value::as_str),
            obj.get("password").and_then(Value::as_str),
        ) {
            (Some(username), Some(password)) => {
                let mut raw = Vec::new();
                raw.extend_from_slice(username.as_bytes());
                raw.push(b':');
                raw.extend_from_slice(password.as_bytes());
                Some(format!("Basic {}", base64_std(&raw)))
            }
            _ => None,
        };
        let mut extra_headers = Vec::new();
        if let Some(Value::Object(headers)) = obj.get("extra_headers") {
            for (name, value) in headers {
                // reference keeps the first value of each list
                let first = match value {
                    Value::String(text) => Some(text.clone()),
                    Value::Array(items) => {
                        items.first().and_then(Value::as_str).map(str::to_string)
                    }
                    _ => None,
                };
                let Some(first) = first else { continue };
                extra_headers.push((name.to_ascii_lowercase(), first));
            }
        }
        let uot_version = match obj.get("udp_over_tcp") {
            Some(Value::Bool(enabled)) => enabled.then_some(UOT_DEFAULT_VERSION),
            Some(Value::Object(map)) => {
                let enabled = map.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                if !enabled {
                    None
                } else {
                    let version = map
                        .get("version")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(u8::MAX as u64) as u8;
                    Some(if version == 0 {
                        UOT_DEFAULT_VERSION
                    } else {
                        version
                    })
                }
            }
            _ => None,
        };
        if let Some(version) = uot_version
            && version != 1
            && version != UOT_DEFAULT_VERSION
        {
            anyhow::bail!("{at}: unknown udp over tcp protocol version: {version}");
        }
        Ok(Self {
            server,
            port,
            tls,
            authorization,
            extra_headers,
            uot_version,
            quic,
            quic_tunnel: crate::outbound::quic::QuicTunnelOptions::parse(
                obj,
                at,
                crate::outbound::quic::QuicTunnelDefaults::tuic(),
            )?,
            congestion,
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        self.tunnel(&authority_of(target)?).await
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let Some(version) = self.uot_version else {
            return Err(io::Error::other(
                "naive: UDP is not supported unless UDP over TCP is enabled",
            ));
        };
        let (local, peer) = udp_loopback_pair().await?;
        let mut stream = self.tunnel(&magic_authority(version)).await?;
        if version != 1 {
            let header = request_header(true, target)?;
            stream.write_all(&header).await?;
        }
        spawn_bridge(stream, peer);
        Ok(local)
    }

    /// One h2 CONNECT stream: handshake, request, wrapped as raw pipes.
    async fn tunnel(&self, authority: &str) -> io::Result<AnyStream> {
        if self.quic {
            return self.tunnel_quic(authority).await;
        }
        self.tunnel_h2(authority).await
    }

    /// The same CONNECT over HTTP/3, which is what `quic: true` asks for.
    async fn tunnel_quic(&self, authority: &str) -> io::Result<AnyStream> {
        let addr = crate::outbound::quic::resolve_host(&self.server, self.port).await?;
        let sock = crate::outbound::quic::bind_udp(addr)?;
        let (ep_config, transport) = self.quic_tunnel.build_configs(self.congestion, None, true);
        let mut endpoint = quinn::Endpoint::new(
            ep_config,
            None,
            sock,
            quinn::default_runtime().ok_or_else(|| io::Error::other("naive: no quinn runtime"))?,
        )?;
        let quic_tls = self.tls.quic_config(&[b"h3"])?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(addr, self.tls.server_name())
            .map_err(|e| io::Error::other(format!("naive: quic connect: {e}")))?;
        let connection = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| io::Error::other("naive: quic connect timeout"))?
            .map_err(|e| io::Error::other(format!("naive: quic connect: {e}")))?;
        let (mut h3_connection, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .map_err(|e| io::Error::other(format!("naive: h3 handshake: {e}")))?;
        let conn_task = tokio::spawn(async move {
            // the h3 connection is polled by hand; `wait_idle` never returns
            let _ = h3_connection.wait_idle().await;
        });
        // The h3 crate always writes :scheme and :path, and RFC 9114 4.3.1
        // says both must be absent on a plain CONNECT — the reference server
        // rejects that shape with H3_MESSAGE_ERROR before ServeHTTP ever
        // sees it. Carrying a :protocol makes the request an extended
        // CONNECT (4.4), where :scheme/:path are required; the server's
        // handler only reads method and headers, so the token itself is
        // ignored on the other end.
        let mut builder = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://{authority}"))
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .header("padding", padding_header())
            .header("-connect-authority", authority);
        if let Some(authorization) = &self.authorization {
            builder = builder.header("proxy-authorization", authorization.clone());
        }
        for (name, value) in &self.extra_headers {
            builder = builder.header(name.clone(), value.clone());
        }
        let request = builder
            .body(())
            .map_err(|e| io::Error::other(format!("naive: build request: {e}")))?;
        let request_stream =
            tokio::time::timeout(CONNECT_TIMEOUT, send_request.send_request(request))
                .await
                .map_err(|_| io::Error::other("naive: h3 request timeout"))?
                .map_err(|e| io::Error::other(format!("naive: h3 request: {e}")))?;
        let inner = crate::outbound::transport::h3io::H3Stream::new(
            request_stream,
            send_request,
            conn_task,
        )
        .await?;
        Ok(Box::new(Padded::new(inner)))
    }

    /// One h2 CONNECT stream: handshake, request, wrapped as raw pipes.
    async fn tunnel_h2(&self, authority: &str) -> io::Result<AnyStream> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            crate::outbound::dial::connect_tcp(&self.server, self.port, &self.dial),
        )
        .await
        .map_err(|_| io::Error::other("naive: connect timeout"))??;
        let stream = self.tls.wrap_with_defaults(tcp, &[b"h2"]).await?;
        let (send_request, connection) = crate::outbound::transport::h2io::client_builder()
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("naive: h2 handshake: {e}")))?;
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut send_request = send_request
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("naive: h2 ready: {e}")))?;
        let mut builder = http::Request::builder()
            .method("CONNECT")
            .uri(authority.to_string())
            .header("padding", padding_header())
            .header("-connect-authority", authority.to_string());
        if let Some(authorization) = &self.authorization {
            builder = builder.header("proxy-authorization", authorization.clone());
        }
        for (name, value) in &self.extra_headers {
            builder = builder.header(name.clone(), value.clone());
        }
        let request = builder
            .body(())
            .map_err(|e| io::Error::other(format!("naive: build request: {e}")))?;
        let (response, send) = send_request
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("naive: send request: {e}")))?;
        // Read the head here rather than leaving it to the first read: a server
        // that refuses the CONNECT resets the stream, and the copy loop then
        // fails on the write side with a closed stream and no reason at all.
        let response = tokio::time::timeout(CONNECT_TIMEOUT, response)
            .await
            .map_err(|_| io::Error::other("naive: h2 response timeout"))?
            .map_err(|e| io::Error::other(format!("naive: h2 response: {e}")))?;
        if response.status() != http::StatusCode::OK {
            return Err(io::Error::other(format!(
                "naive: server refused the tunnel: {}",
                response.status()
            )));
        }
        Ok(Box::new(Padded::new(H2Io {
            h2: H2Stream::from_response(response, send, Some(conn_task)),
        })))
    }
}

/// CONNECT authority for a target (`host:port`, IPv6 bracketed).
fn authority_of(target: &Target) -> io::Result<String> {
    Ok(match target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) => format!("{v4}:{}", addr.port()),
            IpAddr::V6(v6) => format!("[{v6}]:{}", addr.port()),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "naive",
            "tag": "nv",
            "server": "example.com",
            "server_port": 443,
            "tls": {"enabled": true, "server_name": "cdn.example.com"},
        });
        let map = base.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("object") {
            map.insert(key.clone(), value.clone());
        }
        map.clone()
    }

    #[test]
    fn build_requires_tls() {
        let mut map = obj(json!({}));
        map.remove("tls");
        let err = Naive::build(&map, "outbounds[0]").unwrap_err().to_string();
        assert_eq!(err, "outbounds[0]: naive outbound requires tls");
        let mut map = obj(json!({}));
        map.insert("tls".to_string(), json!({"enabled": false}));
        assert!(Naive::build(&map, "outbounds[0]").is_err());
    }

    #[test]
    fn build_accepts_the_quic_transport() {
        let naive = Naive::build(&obj(json!({"quic": true})), "outbounds[0]").expect("quic");
        assert!(naive.quic);
        assert!(
            !Naive::build(&obj(json!({})), "outbounds[0]")
                .expect("plain")
                .quic
        );
        assert!(
            Naive::build(
                &obj(json!({"quic": true, "quic_congestion_control": "reno"})),
                "outbounds[0]"
            )
            .is_ok()
        );
        let err = Naive::build(
            &obj(json!({"quic": true, "quic_congestion_control": "wombat"})),
            "outbounds[0]",
        )
        .map(|_| ())
        .expect_err("unknown congestion control")
        .to_string();
        assert!(err.contains("unknown quic congestion control"), "got {err}");
    }

    #[test]
    fn build_authorization_and_headers() {
        let naive = Naive::build(
            &obj(json!({
                "username": "user",
                "password": "pass",
                "extra_headers": {"X-Padding": ["one", "two"], "X-Skip": 7},
            })),
            "outbounds[0]",
        )
        .expect("build");
        // base64("user:pass")
        assert_eq!(naive.authorization.as_deref(), Some("Basic dXNlcjpwYXNz"));
        assert_eq!(
            naive.extra_headers,
            vec![("x-padding".to_string(), "one".to_string())]
        );
        // tls.server_name is the SNI, the tunnel authority is the destination
        assert_eq!(naive.tls.server_name(), "cdn.example.com");
    }

    #[test]
    fn build_udp_over_tcp_versions() {
        assert_eq!(
            Naive::build(&obj(json!({})), "at")
                .expect("build")
                .uot_version,
            None
        );
        assert_eq!(
            Naive::build(&obj(json!({"udp_over_tcp": true})), "at")
                .expect("build")
                .uot_version,
            Some(2)
        );
        assert_eq!(
            Naive::build(&obj(json!({"udp_over_tcp": {"enabled": true}})), "at")
                .expect("build")
                .uot_version,
            Some(2)
        );
        assert_eq!(
            Naive::build(
                &obj(json!({"udp_over_tcp": {"enabled": true, "version": 1}})),
                "at"
            )
            .expect("build")
            .uot_version,
            Some(1)
        );
        assert_eq!(
            Naive::build(
                &obj(json!({"udp_over_tcp": {"enabled": false, "version": 2}})),
                "at"
            )
            .expect("build")
            .uot_version,
            None
        );
        let err = Naive::build(
            &obj(json!({"udp_over_tcp": {"enabled": true, "version": 3}})),
            "at",
        )
        .unwrap_err()
        .to_string();
        assert_eq!(err, "at: unknown udp over tcp protocol version: 3");
    }

    #[test]
    fn authority_of_targets() {
        assert_eq!(
            authority_of(&Target::Domain("example.com".into(), 80)).expect("authority"),
            "example.com:80"
        );
        assert_eq!(
            authority_of(&Target::Ip("1.2.3.4:443".parse().expect("addr"))).expect("authority"),
            "1.2.3.4:443"
        );
        assert_eq!(
            authority_of(&Target::Ip("[::1]:443".parse().expect("addr"))).expect("authority"),
            "[::1]:443"
        );
    }
}
