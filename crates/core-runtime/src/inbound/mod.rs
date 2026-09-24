use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::logging;
use crate::outbound::shadowsocks::stream::{SsReader, SsWriter};
use crate::route::{ConnContext, Decision, Router, hijack_dns};

pub mod direct;
pub mod mixed;
pub mod redirect;
pub mod tproxy;
pub(crate) mod udp;

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

/// Client stream that flushes the SOCKS success reply lazily (reference
/// `LazyConn`): the first read/write emits the reply, then passes through.
/// Sniffing therefore triggers the success reply before the client sends
/// its payload — no handshake deadlock.
pub struct ClientConn {
    inner: TcpStream,
    reply: LazyReply,
}

impl ClientConn {
    /// SOCKS path: success `reply` bytes flush on first payload I/O.
    pub fn socks(inner: TcpStream, reply: Vec<u8>) -> Self {
        Self {
            inner,
            reply: LazyReply::Pending(reply),
        }
    }

    /// HTTP CONNECT path: the 200 response is written by the caller.
    pub fn http(inner: TcpStream) -> Self {
        Self {
            inner,
            reply: LazyReply::None,
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
        self.inner.local_addr()
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

/// Relay the client stream into an established upstream connection,
/// replaying any sniff-read `prefix` upstream first.
pub async fn pump_conn<S>(mut client: S, conn: Conn, prefix: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match conn {
        Conn::Plain(mut upstream) => {
            if !prefix.is_empty() {
                upstream.write_all(prefix).await?;
            }
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
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
                }
            };
            let down = async {
                loop {
                    match reader.read(&mut down_buf).await {
                        Ok(0) => return Ok(()),
                        Ok(n) => client_write.write_all(&down_buf[..n]).await?,
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                            return Ok(());
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            tokio::try_join!(up, down).map(|_| ())
        }
    }
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
    let mut client = ClientConn::http(stream);
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
            pump_conn(client, conn, &ctx.sniff_prefix).await
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
