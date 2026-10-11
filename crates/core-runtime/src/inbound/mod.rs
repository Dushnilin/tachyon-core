use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::clash_state;
use crate::logging;
use crate::outbound::shadowsocks::stream::{SsReader, SsWriter};
use crate::route::{ConnContext, Decision, Router, hijack_dns};

pub mod anytls;
pub mod direct;
pub mod fptn;
pub mod hysteria2;
pub mod mieru;
pub mod mixed;
pub mod mux;
pub mod naive;
pub mod proxy;
pub mod redirect;
pub mod shadowsocks;
pub mod shadowtls;
pub mod tls;
pub mod tproxy;
pub(crate) mod transport;
pub mod tuic;
pub mod tun;
pub(crate) mod udp;
pub mod vmess;

#[cfg(target_os = "linux")]
mod relay;

/// A TCP listener on `addr`, with `SO_REUSEADDR`.
///
/// The reference's Go runtime sets it on every listener, and without it a
/// rebind right after a reload loses to a TIME_WAIT socket the previous
/// instance left behind — one half of issue #5's `Address in use`. Off
/// Windows, where `SO_REUSEADDR` means "let two sockets own the port".
pub(crate) fn bind_tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    let listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(listener)
}

/// A UDP socket on `addr`, with the same `SO_REUSEADDR` treatment.
pub(crate) fn bind_udp(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

/// An error from a serving loop: log it loudly and pause, never end the loop.
///
/// Every inbound used to `return` on the first `accept` failure, which drops
/// the socket — the process stays `running` while the port goes dark, which
/// is how issue #5 reported it. `tproxy` and `direct` were worse: their TCP
/// and UDP halves are `select!`ed, so one transient error took both down.
/// We own this socket, so nothing that fails on it is permanent; `EMFILE` and
/// friends clear up, and a socket that really is gone is worth shouting about
/// once a second rather than dying silently.
pub(crate) async fn serve_stalled(scope: &str, err: &io::Error) {
    logging::error(format_args!("{scope}: {err}; keeping the listener up"));
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

/// Object-safe stream for dial results (TCP, TLS, future transports).
///
/// `Any` is here so the relay can recognise a bare `TcpStream` behind the box
/// and hand both ends to the kernel (`splice`) instead of copying.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any {
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any> ProxyStream for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
pub type AnyStream = Box<dyn ProxyStream>;
pub type AnyRead = Box<dyn AsyncRead + Send + Unpin>;
pub type AnyWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Vision's peer can stop outer TLS encryption independently of our writes.
/// Switch only the read side, preserving bytes already buffered by TLS.
pub(crate) fn enable_vision_direct_read(stream: &mut AnyStream) -> bool {
    let stream = (**stream).as_any_mut();
    if let Some(alpn) = stream.downcast_mut::<AlpnStream>() {
        return enable_vision_direct_read(&mut alpn.inner);
    }
    if let Some(vless) = stream.downcast_mut::<crate::outbound::secure::VlessStream>() {
        return vless.enable_vision_direct_read();
    }
    if let Some(tls) = stream.downcast_mut::<crate::tls_utls::FingerprintStream<TcpStream>>() {
        tls.enable_direct_read();
        return true;
    }
    false
}

/// A stream carrying its negotiated ALPN protocol from the TLS handshake.
pub struct AlpnStream {
    inner: AnyStream,
    alpn: Option<Vec<u8>>,
}

impl AlpnStream {
    pub fn new(inner: AnyStream, alpn: Option<Vec<u8>>) -> Self {
        Self { inner, alpn }
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }
}

impl AsyncRead for AlpnStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AlpnStream {
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

/// Retrieve the negotiated ALPN protocol, if this stream carried a TLS handshake.
pub fn stream_alpn(stream: &AnyStream) -> Option<&[u8]> {
    let any = (**stream).as_any();
    if let Some(a) = any.downcast_ref::<AlpnStream>() {
        return a.alpn();
    }
    if let Some(t) = any.downcast_ref::<crate::inbound::tls::TlsStream<tokio::net::TcpStream>>() {
        return t.alpn.as_deref();
    }
    None
}

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

    /// A stream that carries a SOCKS5 request of its own (mieru): the success
    /// `reply` is flushed once the upstream is up.
    pub fn socks_stream(inner: AnyStream, local: SocketAddr, reply: Vec<u8>) -> Self {
        Self {
            inner,
            reply: LazyReply::Pending(reply),
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

    /// The bare client socket, when nothing sits between us and it and no SOCKS
    /// reply is still owed: only then may the kernel move its bytes directly.
    #[cfg(target_os = "linux")]
    fn raw_tcp(&self) -> Option<&TcpStream> {
        if matches!(self.reply, LazyReply::Pending(_)) {
            return None;
        }
        (&*self.inner as &dyn std::any::Any).downcast_ref::<TcpStream>()
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
    // reference `TrackerMetadata`: the sniffed domain wins over the
    // destination's own name, an IP destination has no host at all
    let host = match (&ctx.domain, &ctx.destination) {
        (Some(domain), _) if !domain.is_empty() => domain.clone(),
        (_, Target::Domain(host, _)) => host.clone(),
        _ => String::new(),
    };
    let mut chains = Vec::new();
    let mut index = Some(outbound_index);
    let inner = router.inner();
    // expand selector groups into their selected member (one level, like the
    // reference chain display for group proxies)
    for _ in 0..8 {
        let Some(current) = index else { break };
        let Some((_, tag, outbound)) = inner.outbound_table().find(|(i, _, _)| *i == current)
        else {
            break;
        };
        chains.push(tag.to_string());
        index = match outbound {
            crate::route::Outbound::Selector(selector) => router.index_of(selector.now()),
            crate::route::Outbound::Urltest(urltest) => router.index_of(urltest.now()),
            _ => None,
        };
    }
    let tag = ctx.inbound.clone().unwrap_or_default();
    let inbound = match inner.inbound_type(&tag) {
        Some(ty) if tag.is_empty() => ty.to_string(),
        Some(ty) => format!("{ty}/{tag}"),
        None => tag,
    };
    clash_state::ConnMeta {
        network: ctx.network,
        inbound,
        source: ctx.source.to_string(),
        host,
        destination: ctx.destination.to_string(),
        chains,
        rule: ctx.matched_rule.clone().unwrap_or_else(|| "final".into()),
        rule_payload: String::new(),
        process_path: ctx.process.as_ref().map(process_label).unwrap_or_default(),
    }
}

/// Reference `processPath`: the path with its owner in brackets, or just the
/// uid when the path is unknown.
fn process_label(info: &crate::route::process::ProcessInfo) -> String {
    match (info.path.as_str(), &info.user_name, info.user_id) {
        ("", _, Some(uid)) => uid.to_string(),
        ("", _, None) => String::new(),
        (path, Some(name), _) if !name.is_empty() => format!("{path} ({name})"),
        (path, _, Some(uid)) => format!("{path} ({uid})"),
        (path, _, None) => path.to_string(),
    }
}

/// The bare TCP socket behind a relay client, if there is one: a socket that
/// was accepted as is (`redirect`, `tproxy`), or a `ClientConn` with nothing
/// between it and the socket and no SOCKS reply still owed.
#[cfg(target_os = "linux")]
fn client_raw_tcp(client: &dyn std::any::Any) -> Option<&TcpStream> {
    if let Some(tcp) = client.downcast_ref::<TcpStream>() {
        return Some(tcp);
    }
    client.downcast_ref::<ClientConn>()?.raw_tcp()
}

/// Relay the client stream into an established upstream connection, replaying
/// any sniff-read `prefix` upstream first. With a `tracker` the connection is
/// registered in the Clash connection view: byte counters feed `/connections`
/// and `/traffic`, and `DELETE /connections/{id}` can drop it.
///
/// Socket to socket on Linux goes through `splice(2)` (see `relay`); every other
/// shape of stream takes the userspace loops below.
pub async fn pump_conn_tracked<S>(
    mut client: S,
    conn: Conn,
    prefix: &[u8],
    tracker: Option<&clash_state::ConnHandle>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any,
{
    match conn {
        Conn::Plain(mut upstream) => {
            // A tracker is not a precondition here: the kernel path is what
            // the plain relay exists for, and in a bench (or a build with the
            // connection view off) it used to be skipped entirely because
            // nothing to count meant no splice at all.
            #[cfg(target_os = "linux")]
            if let Some(client_tcp) = client_raw_tcp(&client) {
                let up = &*upstream as &dyn std::any::Any;
                if let Some(upstream_tcp) = up.downcast_ref::<TcpStream>() {
                    return relay::relay(client_tcp, upstream_tcp, prefix, tracker, false).await;
                }
                // a plain vless client: the kernel moves the bytes once the
                // relay has eaten the two-byte answer head
                if let Some(upstream_tcp) = up
                    .downcast_ref::<crate::outbound::secure::VlessStream>()
                    .and_then(|v| v.raw_pending())
                {
                    return relay::relay(client_tcp, upstream_tcp, prefix, tracker, true).await;
                }
            }

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
                    copy_bidirectional_pooled(&mut client, &mut upstream).await?;
                }
            }
            Ok(())
        }
        Conn::Shadowsocks(mut reader, mut writer) => {
            if !prefix.is_empty() {
                writer.write_chunk(prefix).await?;
            }
            let chunk_size = usize::from(writer.max_chunk());
            let ss_buf_size = match relay_buf().checked_div(chunk_size) {
                Some(whole) => (whole * chunk_size).max(chunk_size),
                None => relay_buf(),
            };
            let mut up_buf = take_buf();
            up_buf.resize(ss_buf_size, 0);
            let mut down_buf = take_buf();
            down_buf.resize(ss_buf_size, 0);
            let (mut client_read, mut client_write) = tokio::io::split(client);
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
            let result = match tracker {
                Some(tracker) => {
                    let signal = tracker.close_signal();
                    let relay = async { tokio::try_join!(up, down).map(|_| ()) };
                    tokio::pin!(relay);
                    tokio::select! {
                        biased;
                        result = &mut relay => result,
                        _ = signal.wait() => Err(closed_by_api()),
                    }
                }
                None => tokio::try_join!(up, down).map(|_| ()),
            };
            give_buf(up_buf);
            give_buf(down_buf);
            result
        }
    }
}

/// Controller asked to drop the connection (`DELETE /connections/{id}`).
fn closed_by_api() -> io::Error {
    io::Error::other("connection closed by clash api")
}

/// Each direction of a userspace relay moves up to this much per read. Sized
/// to two whole shadowsocks 2022 chunks (2 * 65535 ~ 128 KiB) so a steady transfer
/// costs one write per two chunks or eight TLS records, halving syscalls on routers.
///
/// Buffers are recycled through `BUF_POOL`, so active connections allocate zero heap
/// slices and peak memory is bounded to `POOL_CAP * relay_buf()` (2 MiB).
fn relay_buf() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        if let Ok(val) = std::env::var("TACHYON_RELAY_BUF")
            && let Ok(n) = val.parse::<usize>()
            && n > 0
        {
            return n;
        }
        2 * 65535
    })
}

/// Relay buffers waiting for the next connection. A connection takes two and
/// gives them back on close: at 128 KiB each is an mmap/munmap pair on glibc,
/// and a steady connection rate pays that per connection. Capped so a burst
/// cannot pin memory (16 x 128 KiB = 2 MiB).
static BUF_POOL: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
const POOL_CAP: usize = 16;

fn take_buf() -> Vec<u8> {
    let mut pool = BUF_POOL.lock().unwrap_or_else(|e| e.into_inner());
    match pool.pop() {
        Some(mut buf) => {
            buf.resize(relay_buf(), 0);
            buf
        }
        None => vec![0u8; relay_buf()],
    }
}

fn give_buf(mut buf: Vec<u8>) {
    if buf.capacity() < relay_buf() / 2 || buf.capacity() > relay_buf() * 2 {
        return;
    }
    buf.clear();
    let mut pool = BUF_POOL.lock().unwrap_or_else(|e| e.into_inner());
    if pool.len() < POOL_CAP {
        pool.push(buf);
    }
}

/// The client side of a relay, counting what crosses it for the connection
/// view: bytes read from it are upload, bytes written to it are download.
struct Counted<'a, S> {
    inner: &'a mut S,
    tracker: &'a clash_state::ConnHandle,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &poll {
            self.tracker
                .add_upload((buf.filled().len() - before) as u64);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut *self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(n)) = &poll {
            self.tracker.add_download(*n as u64);
        }
        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

struct PooledBuffer {
    buf: Option<Vec<u8>>,
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
}

impl PooledBuffer {
    fn new(buf: Vec<u8>) -> Self {
        Self {
            buf: Some(buf),
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
        }
    }

    #[inline]
    fn buffer(&mut self) -> &mut [u8] {
        self.buf.as_deref_mut().expect("pooled buffer present")
    }

    fn poll_fill_buf<R>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
    {
        let cap = self.cap;
        let mut read_buf = ReadBuf::new(self.buffer());
        read_buf.set_filled(cap);

        let res = reader.as_mut().poll_read(cx, &mut read_buf);
        if let Poll::Ready(Ok(())) = res {
            let filled_len = read_buf.filled().len();
            self.read_done = self.cap == filled_len;
            self.cap = filled_len;
        }
        res
    }

    fn poll_write_buf<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        let (pos, cap) = (self.pos, self.cap);
        let buf_len = self.buffer().len();
        match writer.as_mut().poll_write(cx, &self.buffer()[pos..cap]) {
            Poll::Pending => {
                if !self.read_done && cap < buf_len {
                    ready!(self.poll_fill_buf(cx, reader.as_mut()))?;
                }
                Poll::Pending
            }
            res => res,
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            let buf_len = self.buffer().len();
            if self.cap < buf_len && !self.read_done {
                match self.poll_fill_buf(cx, reader.as_mut()) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        if self.pos == self.cap {
                            if self.need_flush {
                                ready!(writer.as_mut().poll_flush(cx))?;
                                self.need_flush = false;
                            }
                            return Poll::Pending;
                        }
                    }
                }
            }

            while self.pos < self.cap {
                let i = ready!(self.poll_write_buf(cx, reader.as_mut(), writer.as_mut()))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                }
            }

            self.pos = 0;
            self.cap = 0;

            if self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            give_buf(buf);
        }
    }
}

enum TransferState {
    Running(PooledBuffer),
    ShuttingDown(u64),
    Done(u64),
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

async fn copy_bidirectional_pooled<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = TransferState::Running(PooledBuffer::new(take_buf()));
    let mut b_to_a = TransferState::Running(PooledBuffer::new(take_buf()));
    std::future::poll_fn(|cx| {
        let res_a = transfer_one_direction(cx, &mut a_to_b, a, b)?;
        let res_b = transfer_one_direction(cx, &mut b_to_a, b, a)?;
        let amt_a = ready!(res_a);
        let amt_b = ready!(res_b);
        Poll::Ready(Ok((amt_a, amt_b)))
    })
    .await
}

/// Counted bidirectional relay that aborts when the API closes the entry.
///
/// Both directions are driven by one poll-based copy, so a write that cannot
/// finish yet never holds up the other direction.
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
    let mut counted = Counted {
        inner: client,
        tracker,
    };
    tokio::select! {
        biased;
        result = copy_bidirectional_pooled(
            &mut counted,
            upstream,
        ) => result.map(|_| ()),
        _ = signal.wait() => Err(closed_by_api()),
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
        Err(err) => {
            let _ = client.fail(&err).await;
            return Err(err);
        }
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
            let conn = match router.connect_index(idx, &dest).await {
                Ok(conn) => conn,
                Err(err) => {
                    let _ = client.fail(&err).await;
                    return Err(err);
                }
            };
            client.established().await?;
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
