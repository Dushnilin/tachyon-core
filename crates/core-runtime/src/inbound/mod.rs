use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::clash_state;
use crate::logging;
use crate::outbound::shadowsocks::stream::{SsReader, SsWriter};
use crate::route::{ConnContext, Decision, Router, hijack_dns};

pub mod direct;
pub mod mixed;
pub mod proxy;
pub mod redirect;
pub mod tproxy;
pub(crate) mod udp;
pub mod vmess;

/// Object-safe stream for dial results (TCP, TLS, future transports).
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}
pub type AnyStream = Box<dyn ProxyStream>;
pub type AnyRead = Box<dyn AsyncRead + Send + Unpin>;
pub type AnyWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// An established upstream connection: raw streams or a shadowsocks codec.
pub enum Conn {
    Plain(AnyStream),
    Shadowsocks(Box<SsReader<AnyRead>>, SsWriter<AnyWrite>),
}

// A `Conn` is a finished upstream stream; the runtime fetches (rule-sets,
// provider updates) read and write one directly.
impl Conn {
    /// Box a plain upstream stream; shadowsocks connections cannot be split
    /// into a reader/writer pair, so they are rejected here.
    pub fn into_plain(self) -> io::Result<AnyStream> {
        match self {
            Conn::Plain(stream) => Ok(stream),
            Conn::Shadowsocks(_, _) => Err(io::Error::other(
                "runtime fetch does not support the shadowsocks codec stream",
            )),
        }
    }
}

/// SOCKS reply state on the client side of a mixed inbound connection.
enum LazyReply {
    /// HTTP CONNECT path: no SOCKS reply is due.
    None,
    /// SOCKS success reply waiting to be flushed on first payload I/O.
    Pending(Vec<u8>),
    /// Success reply flushed.
    Sent,
    /// Terminal: success flushed, or failure written, or never applicable.
    Done,
}

/// Client stream that flushes the SOCKS success reply as soon as the upstream
/// connection is up (reference `ConnHandshakeSuccess`, called by the router the
/// moment the dial returns), and defensively on the first read/write as well
/// (reference `LazyConn`) for a path that establishes the upstream silently.
pub struct ClientConn {
    inner: AnyStream,
    reply: LazyReply,
    /// the socket's address, kept here because a boxed stream has none to ask:
    /// `direct` needs it to work out its destination, and only ever holds a
    /// real socket there
    local: Option<SocketAddr>,
}

impl ClientConn {
    /// SOCKS path: success `reply` bytes flush on first payload I/O.
    pub fn socks(inner: TcpStream, reply: Vec<u8>) -> Self {
        let local = inner.local_addr().ok();
        Self {
            inner: Box::new(inner),
            reply: LazyReply::Pending(reply),
            local,
        }
    }

    /// HTTP CONNECT path: the 200 response is written by the caller.
    pub fn http(inner: TcpStream) -> Self {
        let local = inner.local_addr().ok();
        Self {
            inner: Box::new(inner),
            reply: LazyReply::None,
            local,
        }
    }

    /// A stream that carries a protocol frame of its own -- what the server
    /// inbounds hand over once they have unwrapped the request.
    pub fn framed(inner: AnyStream, local: SocketAddr) -> Self {
        Self {
            inner,
            reply: LazyReply::None,
            local: Some(local),
        }
    }

    /// The upstream is up: flush the success reply now (reference
    /// `ConnHandshakeSuccess`, called by the router right after the dial).
    ///
    /// The lazy first-payload flush stays as a second chance, for a path that
    /// establishes the upstream without saying so -- but a client that waits for
    /// this reply cannot be the one to trigger it.
    pub async fn established(&mut self) -> io::Result<()> {
        match std::mem::replace(&mut self.reply, LazyReply::Done) {
            LazyReply::Pending(bytes) => match self.inner.write_all(&bytes).await {
                Ok(()) => {
                    self.reply = LazyReply::Sent;
                    Ok(())
                }
                Err(e) => {
                    self.reply = LazyReply::Done;
                    Err(e)
                }
            },
            other => {
                self.reply = other;
                Ok(())
            }
        }
    }

    /// Write a SOCKS failure reply if the success reply is still pending
    /// (reference `HandshakeFailure`).
    pub async fn fail(&mut self, err: &io::Error) -> io::Result<()> {
        if matches!(self.reply, LazyReply::Pending(_)) {
            let code = reply_code_for_error(err);
            self.reply = LazyReply::Done;
            self.inner.write_all(&socks_failure_reply(code)).await?;
        }
        Ok(())
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local
            .ok_or_else(|| io::Error::other("this stream has no socket address"))
    }

    fn poll_flush_reply(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut bytes = match std::mem::replace(&mut self.reply, LazyReply::Done) {
                LazyReply::Pending(bytes) => bytes,
                other => {
                    self.reply = other;
                    return Poll::Ready(Ok(()));
                }
            };
            match Pin::new(&mut self.inner).poll_write(cx, &bytes) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::other("socks reply write stalled")));
                }
                Poll::Ready(Ok(n)) => {
                    bytes.drain(..n);
                    if bytes.is_empty() {
                        self.reply = LazyReply::Sent;
                        return Poll::Ready(Ok(()));
                    }
                    self.reply = LazyReply::Pending(bytes);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.reply = LazyReply::Pending(bytes);
                    return Poll::Pending;
                }
            }
        }
    }
}

use std::pin::Pin;

impl AsyncRead for ClientConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_reply(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_read(cx, buf),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ClientConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_flush_reply(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_write(cx, buf),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// SOCKS5 success reply bound to the proxy-side local address
/// (reference `LazyConn` success reply).
pub fn socks_success_reply(local: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x05, 0x00, 0x00];
    match local {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}

pub fn socks_failure_reply(code: u8) -> Vec<u8> {
    vec![0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Reference `ReplyCodeForError`: map OS errnos only (raw_os_error), so
/// synthetic errors like block/reject stay0x01 (general failure).
fn reply_code_for_error(err: &io::Error) -> u8 {
    match err.raw_os_error() {
        // ENETUNREACH / WSAENETUNREACH
        Some(101) | Some(10051) => 0x03,
        // EHOSTUNREACH / WSAEHOSTUNREACH
        Some(113) | Some(10065) => 0x04,
        // ECONNREFUSED / WSAECONNREFUSED
        Some(111) | Some(10061) => 0x05,
        // EPERM / WSAEACCES
        Some(1) | Some(10013) => 0x02,
        _ => 0x01,
    }
}

/// Clash connection-view metadata for a routed connection: inbound, source,
/// destination, matched rule and the outbound chain.
pub fn clash_meta(
    ctx: &ConnContext,
    router: &Router,
    outbound_index: usize,
) -> clash_state::ConnMeta {
    let host = match &ctx.destination {
        Target::Ip(addr) => addr.ip().to_string(),
        Target::Domain(host, _) => host.clone(),
    };
    let mut chains = Vec::new();
    let mut index = Some(outbound_index);
    // expand selector groups into their selected member (one level, like the
    // reference chain display for group proxies)
    for _ in 0..8 {
        let Some(current) = index else { break };
        let Some((_, tag, outbound)) = router.outbound_table().find(|(i, _, _)| *i == current)
        else {
            break;
        };
        chains.push(tag.to_string());
        index = match outbound {
            crate::route::Outbound::Selector(selector) => router.index_of(selector.now()),
            _ => None,
        };
    }
    let (rule, rule_payload) = ctx
        .matched_rule
        .clone()
        .unwrap_or_else(|| ("".to_string(), String::new()));
    clash_state::ConnMeta {
        network: ctx.network,
        inbound: ctx.inbound.clone().unwrap_or_default(),
        source: ctx.source.to_string(),
        host,
        destination: ctx.destination.to_string(),
        chains,
        rule,
        rule_payload,
    }
}

/// Relay the client stream into an established upstream connection, replaying
/// any sniff-read `prefix` upstream first. With a `tracker` the connection is
/// registered in the Clash connection view: byte counters feed `/connections`
/// and `/traffic`, and `DELETE /connections/{id}` can drop it.
pub async fn pump_conn_tracked<S>(
    mut client: S,
    conn: Conn,
    prefix: &[u8],
    tracker: Option<&clash_state::ConnHandle>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match conn {
        Conn::Plain(mut upstream) => {
            if !prefix.is_empty() {
                upstream.write_all(prefix).await?;
                if let Some(tracker) = tracker {
                    tracker.add_upload(prefix.len() as u64);
                }
            }
            match tracker {
                Some(tracker) => {
                    relay_tracked(&mut client, &mut upstream, tracker).await?;
                }
                None => {
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                }
            }
            Ok(())
        }
        Conn::Shadowsocks(mut reader, mut writer) => {
            if !prefix.is_empty() {
                writer.write_chunk(prefix).await?;
            }
            let (mut client_read, mut client_write) = tokio::io::split(client);
            let mut up_buf = vec![0u8; 0x3FFF];
            let mut down_buf = vec![0u8; 0x3FFF];
            let up = async {
                loop {
                    let n = client_read.read(&mut up_buf).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    writer.write_chunk(&up_buf[..n]).await?;
                    if let Some(tracker) = tracker {
                        tracker.add_upload(n as u64);
                    }
                }
            };
            let down = async {
                loop {
                    match reader.read(&mut down_buf).await {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            client_write.write_all(&down_buf[..n]).await?;
                            if let Some(tracker) = tracker {
                                tracker.add_download(n as u64);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                            return Ok(());
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            match tracker {
                Some(tracker) => {
                    let signal = tracker.close_signal();
                    let relay = async { tokio::try_join!(up, down).map(|_| ()) };
                    tokio::pin!(relay);
                    tokio::select! {
                        result = &mut relay => result,
                        _ = signal.wait() => Err(closed_by_api()),
                    }
                }
                None => tokio::try_join!(up, down).map(|_| ()),
            }
        }
    }
}

/// Controller asked to drop the connection (`DELETE /connections/{id}`).
fn closed_by_api() -> io::Error {
    io::Error::other("connection closed by clash api")
}

/// Counted bidirectional relay that aborts when the API closes the entry.
async fn relay_tracked<S, U>(
    client: &mut S,
    upstream: &mut U,
    tracker: &clash_state::ConnHandle,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let signal = tracker.close_signal();
    let mut up_buf = vec![0u8; 32 * 1024];
    let mut down_buf = vec![0u8; 32 * 1024];
    let mut up_done = false;
    let mut down_done = false;
    while !(up_done && down_done) {
        tokio::select! {
            biased;
            _ = signal.wait() => return Err(closed_by_api()),
            read = client.read(&mut down_buf), if !down_done => match read {
                // half-close: like copy_bidirectional, tell the peer we are done
                Ok(0) => {
                    down_done = true;
                    upstream.shutdown().await?;
                }
                Ok(n) => {
                    upstream.write_all(&down_buf[..n]).await?;
                    tracker.add_upload(n as u64);
                }
                Err(e) => return Err(e),
            },
            read = upstream.read(&mut up_buf), if !up_done => match read {
                Ok(0) => {
                    up_done = true;
                    client.shutdown().await?;
                }
                Ok(n) => {
                    client.write_all(&up_buf[..n]).await?;
                    tracker.add_download(n as u64);
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(addr) => addr.port(),
            Target::Domain(_, port) => *port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(addr) => write!(f, "{addr}"),
            Target::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

pub fn require_u16(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<u16> {
    obj.get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("{at}: missing or invalid {key}"))
}

/// Common `listen` / `listen_port` parsing for inbound listeners.
pub(crate) fn parse_listen(
    obj: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<(std::net::IpAddr, u16)> {
    let port = require_u16(obj, "listen_port", at)?;
    let host = obj
        .get("listen")
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1");
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("{at}: invalid listen address {host:?}"))?;
    Ok((ip, port))
}

/// True when `network` includes `tcp` (absent = tcp+udp default → true).
pub(crate) fn network_includes_tcp(obj: &serde_json::Map<String, Value>) -> bool {
    match obj.get("network").and_then(Value::as_str) {
        None | Some("") => true,
        Some(n) => n
            .split(',')
            .map(str::trim)
            .any(|part| part.eq_ignore_ascii_case("tcp")),
    }
}

pub(crate) fn network_includes_udp(obj: &serde_json::Map<String, Value>) -> bool {
    match obj.get("network").and_then(Value::as_str) {
        None | Some("") => true,
        Some(n) => n
            .split(',')
            .map(str::trim)
            .any(|part| part.eq_ignore_ascii_case("udp")),
    }
}

/// Route one accepted transparent connection (direct / redirect / tproxy):
/// no SOCKS reply, destination already resolved by the inbound.
pub(crate) async fn drive_transparent(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    destination: Target,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    drive_framed(ClientConn::http(stream), peer, destination, tag, router).await
}

/// The same routing decision for a stream that already carries its own frame.
pub(crate) async fn drive_framed(
    mut client: ClientConn,
    peer: SocketAddr,
    destination: Target,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    let mut ctx = ConnContext::new(tag, peer, destination, "tcp");
    let decision = match router.route(&mut client, &mut ctx).await {
        Ok(decision) => decision,
        Err(err) => return Err(err),
    };
    match decision {
        Decision::HijackDns => {
            logging::info(format_args!(
                "inbound {tag} {peer} HIJACK-DNS {}",
                ctx.destination
            ));
            hijack_dns(&mut client, &ctx).await
        }
        Decision::Outbound(idx) => {
            let dest = ctx.destination.clone();
            let conn = router.connect_index(idx, &dest).await?;
            logging::info(format_args!("inbound {tag} {peer} CONNECT {dest}"));
            let tracker = clash_state::ConnHandle::open(clash_meta(&ctx, router, idx));
            pump_conn_tracked(client, conn, &ctx.sniff_prefix, Some(&tracker)).await
        }
    }
}

/// Copy both directions until one side closes.
pub async fn pump<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// Dial the proxy target through the router's default outbound.
pub async fn dial(router: &Arc<Router>, target: &Target) -> io::Result<Conn> {
    router.connect(target).await
}
