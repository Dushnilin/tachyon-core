//! shadowsocks as a server inbound (F5). Both AEAD families come out of the
//! outbound's own crypto: the legacy 2017 one (HKDF-SHA1 subkeys, a bare
//! address in the first chunk) and the 2022 one (blake3 session subkeys, a
//! sealed head with a timestamp and a length). Reference:
//! `sing-shadowsocks/shadowaead.Service.newConnection` and
//! `shadowaead_2022.Service.newConnection`.
//!
//! TCP only, one method and one password. The multi-user (`users`), relay
//! (`destinations`) and `managed` shapes are refused by name, and with them the
//! UDP packet commands.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;

use super::tls::ServerTls;
use crate::inbound::{
    AnyRead, AnyStream, AnyWrite, ClientConn, Target, drive_framed, parse_listen,
};
use crate::logging;
use crate::outbound::shadowsocks::crypto::{
    AEAD_TAG, Cipher, Method, derive_subkey, master_key, random_bytes,
};
use crate::route::Router;

/// The 2022 head carries the client's clock; the reference allows 30 seconds.
const TIMESTAMP_WINDOW_SECS: i64 = 30;

pub struct Shadowsocks {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    method: Method,
    master_key: Arc<Vec<u8>>,
    tls: Option<Arc<ServerTls>>,
}

impl Shadowsocks {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("shadowsocks")
            .to_string();
        let at = format!("inbound[{tag}]");
        for (field, why) in [
            ("users", "multi-user shadowsocks servers"),
            ("destinations", "shadowsocks relays"),
            ("managed", "managed shadowsocks servers"),
        ] {
            if object.contains_key(field) {
                anyhow::bail!("{at}: {why} are not implemented by this server");
            }
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .and_then(Method::parse)
            .ok_or_else(|| anyhow::anyhow!("{at}: method not implemented"))?;
        let password = object
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?;
        let key = master_key(method, password).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        // the 2022 family takes a pre-shared key of the method's own length and
        // refuses anything else, the way `shadowaead_2022.NewService` does
        if method.is_2022() && key.len() != method.key_len() {
            anyhow::bail!(
                "{at}: the 2022 pre-shared key must be {} bytes, got {}",
                method.key_len(),
                key.len()
            );
        }
        let listen = parse_listen(object, &at)?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            method,
            master_key: Arc::new(key),
            tls: ServerTls::from_inbound(obj, &at)?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let method = self.method;
                    let master_key = Arc::clone(&self.master_key);
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let tls = self.tls.clone();
                    tokio::spawn(async move {
                        let local = stream.local_addr().unwrap_or(peer);
                        let result = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(stream) => {
                                    handle(stream, peer, local, method, master_key, tag, router)
                                        .await
                                }
                                Err(err) => Err(err),
                            },
                            None => {
                                handle(stream, peer, local, method, master_key, tag, router).await
                            }
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("shadowsocks {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::debug(format_args!("shadowsocks accept: {err}"));
                    return;
                }
            }
        }
    }
}

/// The head, and whatever the client pipelined behind it.
struct Head {
    destination: Target,
    /// plaintext already decrypted and not consumed by the head
    prefix: Vec<u8>,
    /// the request cipher's counter, which the payload stream carries on from
    counter: u64,
}

async fn handle<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    method: Method,
    master_key: Arc<Vec<u8>>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut salt = vec![0u8; method.salt_len()];
    stream.read_exact(&mut salt).await?;
    let mut cipher = Cipher::new(method, &derive_subkey(method, &master_key, &salt));
    let mut counter = 0u64;
    let head = if method.is_2022() {
        read_2022_head(&mut stream, &mut cipher, &mut counter).await?
    } else {
        read_legacy_head(&mut stream, &mut cipher, &mut counter).await?
    };

    let (read_half, write_half) = tokio::io::split(stream);
    // whatever the head already decrypted is the first thing the reader hands
    // out: it sits at the front of the read buffer as an unread payload
    let prefix_len = head.prefix.len();
    let framed: AnyStream = Box::new(ServerStream {
        read: ChunkReader {
            inner: Box::new(read_half) as AnyRead,
            cipher,
            counter: head.counter,
            rbuf: head.prefix,
            rpos: prefix_len,
            rend: prefix_len,
            pos: 0,
            pend: prefix_len,
            want: 2 + AEAD_TAG,
            want_length: true,
            read_buf: read_buf(method),
        },
        write: ServerWriter {
            inner: Box::new(write_half) as AnyWrite,
            method,
            master_key,
            request_salt: salt,
            // the response salt is only drawn once there is something to send,
            // which is what the reference does
            session: None,
            flushing: None,
            spare: Vec::new(),
            consumed: 0,
        },
    });
    logging::info(format_args!(
        "shadowsocks inbound connection to {}",
        head.destination
    ));
    drive_framed(
        ClientConn::framed(framed, local),
        peer,
        head.destination,
        &tag,
        &router,
    )
    .await
}

/// `[type=0][epoch u64][varLen u16]`, then `varLen` bytes holding the address,
/// the padding length, the padding and whatever payload the client pipelined
/// behind them. Neither block carries a length prefix: the 2022 client seals
/// them straight off the session key (`shadowio.Writer.Encrypt`), and only what
/// follows them is chunked.
async fn read_2022_head<S>(
    stream: &mut S,
    cipher: &mut Cipher,
    counter: &mut u64,
) -> io::Result<Head>
where
    S: AsyncRead + Unpin,
{
    let fixed = read_sealed(stream, cipher, counter, 11).await?;
    if fixed.first() != Some(&0) {
        return Err(io::Error::other("bad header type"));
    }
    let epoch = i64::from_be_bytes(fixed[1..9].try_into().expect("8 bytes"));
    if (now_secs() - epoch).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(io::Error::other("bad timestamp"));
    }
    let var_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    if var_len < 2 {
        return Err(io::Error::other("bad header"));
    }
    let var = read_sealed(stream, cipher, counter, var_len).await?;
    let (destination, at) = decode_target(&var)?;
    let padding_len = var
        .get(at..at + 2)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        .ok_or_else(|| io::Error::other("bad padding length"))?;
    // the padding has to be there, and at least a byte of it: that is all the
    // reference asks for
    if at + 2 + padding_len > var.len() || (padding_len == 0 && var.len() == at + 2) {
        return Err(io::Error::other("no padding"));
    }
    Ok(Head {
        destination,
        prefix: var[at + 2 + padding_len..].to_vec(),
        counter: *counter,
    })
}

/// The legacy head is the bare address; the client puts it in the first chunk.
async fn read_legacy_head<S>(
    stream: &mut S,
    cipher: &mut Cipher,
    counter: &mut u64,
) -> io::Result<Head>
where
    S: AsyncRead + Unpin,
{
    let first = read_chunk(stream, cipher, counter).await?;
    let (destination, at) = decode_target(&first)?;
    Ok(Head {
        destination,
        prefix: first[at..].to_vec(),
        counter: *counter,
    })
}

/// SOCKS5-style address with the port last, as `SocksaddrSerializer` reads it.
/// Returns the target and how many bytes it took.
fn decode_target(buf: &[u8]) -> io::Result<(Target, usize)> {
    let short = || io::Error::new(io::ErrorKind::UnexpectedEof, "short address");
    match buf.first() {
        Some(0x01) => {
            let raw = buf.get(1..7).ok_or_else(short)?;
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&raw[..4]);
            Ok((
                Target::Ip(SocketAddr::from((
                    Ipv4Addr::from(octets),
                    u16::from_be_bytes([raw[4], raw[5]]),
                ))),
                7,
            ))
        }
        Some(0x03) => {
            let len = usize::from(*buf.get(1).ok_or_else(short)?);
            let host = buf.get(2..2 + len).ok_or_else(short)?;
            let port = buf.get(2 + len..4 + len).ok_or_else(short)?;
            Ok((
                Target::Domain(
                    String::from_utf8_lossy(host).into_owned(),
                    u16::from_be_bytes([port[0], port[1]]),
                ),
                4 + len,
            ))
        }
        Some(0x04) => {
            let raw = buf.get(1..19).ok_or_else(short)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[..16]);
            Ok((
                Target::Ip(SocketAddr::from((
                    Ipv6Addr::from(octets),
                    u16::from_be_bytes([raw[16], raw[17]]),
                ))),
                19,
            ))
        }
        _ => Err(io::Error::other("bad address type")),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// One chunk: a sealed length followed by a sealed payload, the counters
/// running 0, 1, 2, ... over the two halves.
async fn read_chunk<S>(
    stream: &mut S,
    cipher: &mut Cipher,
    counter: &mut u64,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut sealed = vec![0u8; 2 + AEAD_TAG];
    stream.read_exact(&mut sealed).await?;
    cipher.open(*counter, &mut sealed)?;
    *counter += 1;
    let len = usize::from(u16::from_be_bytes([sealed[0], sealed[1]]));
    if len == 0 {
        return Err(io::Error::other("zero-length chunk"));
    }
    read_sealed(stream, cipher, counter, len).await
}

/// A block sealed straight off the session key, with no length in front of it.
async fn read_sealed<S>(
    stream: &mut S,
    cipher: &mut Cipher,
    counter: &mut u64,
    len: usize,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut payload = vec![0u8; len + AEAD_TAG];
    stream.read_exact(&mut payload).await?;
    cipher.open(*counter, &mut payload)?;
    *counter += 1;
    Ok(payload)
}

/// Seal one chunk onto `out`, the way `shadowaead.Writer.WriteChunk` does.
fn write_chunk(cipher: &mut Cipher, counter: &mut u64, out: &mut Vec<u8>, data: &[u8]) {
    let head = out.len();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    cipher
        .seal_at(*counter, out, head)
        .expect("seal cannot fail");
    *counter += 1;
    write_sealed(cipher, counter, out, data);
}

/// A block sealed straight off the session key, with no length in front of it:
/// the 2022 head and the first payload on either side of it. Sealed where it
/// lands, so there is no copy to seal and another to append.
fn write_sealed(cipher: &mut Cipher, counter: &mut u64, out: &mut Vec<u8>, data: &[u8]) {
    let at = out.len();
    out.extend_from_slice(data);
    cipher.seal_at(*counter, out, at).expect("seal cannot fail");
    *counter += 1;
}

/// The payload side: the request cipher carried on from where the head left
/// it, plus whatever the head had already decrypted.
struct ChunkReader {
    inner: AnyRead,
    cipher: Cipher,
    counter: u64,
    /// Bytes off the wire that nothing has consumed yet: `rbuf[rpos..rend]`.
    /// Reads take as much as fits, so several chunks come in per syscall and
    /// each is opened where it sits.
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// the plaintext being handed out: `rbuf[pos..pend]`
    pos: usize,
    pend: usize,
    /// the sealed block that has to be complete before it is opened, and
    /// whether it is a length rather than a payload
    want: usize,
    want_length: bool,
    /// what `rbuf` is grown to when the first record is waited for
    read_buf: usize,
}

/// Read buffer floor, several records deep: `poll_fill` reads as much as the
/// buffer has room for in one syscall, so a bigger buffer means fewer syscalls
/// per GiB -- with 33 KiB the steady state was one record per `recvfrom` while
/// a peer with a large buffer drained four or five records per `read`. Grown
/// to only when the first chunk is waited for.
const READ_BUF: usize = 256 * 1024;
/// Every sealed block carries a tag; the wire overhead of one chunk is its length
/// block, the tag on that block and the tag on the payload.
const BLOCK_OVERHEAD: usize = 2 + AEAD_TAG + AEAD_TAG;

/// Read buffer big enough for one whole record of `method` plus the length block
/// of the next one.
///
/// `poll_fill` is asked for a *payload* (`payload_len + AEAD_TAG`), but what it
/// needs is room for the record that payload belongs to. Sizing to the payload
/// leaves a 2022 buffer one length block short of its own record, so every record
/// costs a full copy of its payload on the way to the front of the buffer plus a
/// syscall and a wakeup. Legacy records are small enough that two of them fit,
/// which is why only 2022 paid it.
fn read_buf(method: Method) -> usize {
    (usize::from(method.max_chunk()) + BLOCK_OVERHEAD).max(READ_BUF)
}
/// Most plaintext one write turns into a frame, sized to the relay's read so a
/// frame of several records leaves as one syscall: at 64 KiB a 2022 frame was
/// one record no matter how much the relay had read.
const WRITE_FRAME: usize = 128 * 1024;

/// How much of `avail` one frame takes: whole chunks, and as much of
/// [`WRITE_FRAME`] as fits in them.
///
/// `WRITE_FRAME` is a multiple of neither chunk size -- it is 128 KiB against
/// `0x3FFF` and against `0xFFFF` -- so cutting a frame at it left a tail that
/// went out as a record of its own. That is two more AEAD invocations for
/// nothing, a few bytes of wire, and a peer that has to open a second record
/// where it expected one. Cutting on a chunk boundary instead
/// leaves the remainder with the caller, and the relay -- which keeps what a
/// partial write did not take -- coalesces it with the next read into a full
/// chunk. A write that genuinely holds less than one chunk still goes out whole:
/// holding it back would stall anything that waits for an answer.
fn frame_take(avail: usize, max_chunk: usize) -> usize {
    let room = WRITE_FRAME.max(max_chunk);
    let whole = avail.min(room) / max_chunk * max_chunk;
    whole.max(max_chunk).min(avail)
}

impl AsyncRead for ChunkReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.pos >= this.pend {
            // a block is only opened once every byte of it has arrived: the
            // counter moves with it, and a half-read block must not be able to
            // step over the bytes still in flight
            ready!(poll_fill(
                &mut this.inner,
                cx,
                &mut this.rbuf,
                &mut this.rpos,
                &mut this.rend,
                this.want,
                this.read_buf
            ))?;
            let at = this.rpos;
            this.cipher
                .open_slice(this.counter, &mut this.rbuf[at..at + this.want])?;
            this.counter += 1;
            if this.want_length {
                let len = usize::from(u16::from_be_bytes([this.rbuf[at], this.rbuf[at + 1]]));
                if len == 0 {
                    return Poll::Ready(Err(io::Error::other("zero-length chunk")));
                }
                this.rpos += this.want;
                this.want_length = false;
                this.want = len + AEAD_TAG;
                continue;
            }
            this.pos = at;
            this.pend = at + this.want - AEAD_TAG;
            this.rpos += this.want;
            this.want_length = true;
            this.want = 2 + AEAD_TAG;
        }
        let n = out.remaining().min(this.pend - this.pos);
        out.put_slice(&this.rbuf[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// Make `rbuf[*rpos..*rend]` at least `want` bytes across as many `Pending`s as
/// it takes. Only called with no payload left to hand out, so moving the unread
/// bytes to the front disturbs nothing.
#[allow(clippy::too_many_arguments)]
fn poll_fill(
    inner: &mut AnyRead,
    cx: &mut Context<'_>,
    rbuf: &mut Vec<u8>,
    rpos: &mut usize,
    rend: &mut usize,
    want: usize,
    read_buf: usize,
) -> Poll<io::Result<()>> {
    if *rend - *rpos >= want {
        return Poll::Ready(Ok(()));
    }
    if *rpos > 0 {
        rbuf.copy_within(*rpos..*rend, 0);
        *rend -= *rpos;
        *rpos = 0;
    }
    if rbuf.len() < want {
        rbuf.resize((want + 2 + AEAD_TAG).max(read_buf), 0);
    }
    while *rend < want {
        let mut read_buf = ReadBuf::new(&mut rbuf[*rend..]);
        match std::pin::Pin::new(&mut **inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream closed mid-chunk",
                    )));
                }
                *rend += n;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

struct ServerStream {
    read: ChunkReader,
    write: ServerWriter,
}

impl AsyncRead for ServerStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

/// The response side: a fresh salt, chunks under a subkey derived from it, and
/// for the 2022 family a sealed head that echoes the request salt. Both go out
/// with the first payload, which is the only shape a client can read.
struct ServerWriter {
    inner: AnyWrite,
    method: Method,
    master_key: Arc<Vec<u8>>,
    request_salt: Vec<u8>,
    /// the response cipher, drawn on the first write
    session: Option<(Cipher, u64)>,
    /// a frame being drained, and how much of the payload it covers
    flushing: Option<(Vec<u8>, usize)>,
    /// the last drained frame's buffer, kept for the next one
    spare: Vec<u8>,
    consumed: usize,
}

impl ServerWriter {
    /// The response salt, the 2022 head, and the first payload.
    fn open(&self, payload: &[u8]) -> io::Result<(Cipher, u64, Vec<u8>)> {
        let mut salt = vec![0u8; self.method.salt_len()];
        random_bytes(&mut salt)?;
        let subkey = derive_subkey(self.method, &self.master_key, &salt);
        let mut cipher = Cipher::new(self.method, &subkey);
        let mut counter = 0u64;
        let mut out = salt;
        // the 2022 head goes out as a bare sealed block, the way the client
        // reads it; the legacy one has no head at all
        let seal_first =
            |cipher: &mut Cipher, counter: &mut u64, out: &mut Vec<u8>, data: &[u8]| {
                if self.method.is_2022() {
                    write_sealed(cipher, counter, out, data);
                } else {
                    write_chunk(cipher, counter, out, data);
                }
            };
        if self.method.is_2022() {
            let mut head = Vec::with_capacity(11 + self.request_salt.len());
            head.push(0x01); // header type: server
            head.extend_from_slice(&now_secs().to_be_bytes());
            head.extend_from_slice(&self.request_salt);
            head.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            write_sealed(&mut cipher, &mut counter, &mut out, &head);
        }
        seal_first(&mut cipher, &mut counter, &mut out, payload);
        Ok((cipher, counter, out))
    }
}

impl AsyncWrite for ServerWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        loop {
            if let Some((frame, off)) = &mut this.flushing {
                while *off < frame.len() {
                    let n = ready!(
                        std::pin::Pin::new(&mut *this.inner).poll_write(cx, &frame[*off..])
                    )?;
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "shadowsocks: chunk write stalled",
                        )));
                    }
                    *off += n;
                }
                if let Some((frame, _)) = this.flushing.take() {
                    this.spare = frame;
                }
                return Poll::Ready(Ok(this.consumed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let mut frame = std::mem::take(&mut this.spare);
            frame.clear();
            let max_chunk = usize::from(this.method.max_chunk());
            match &mut this.session {
                None => {
                    // the salt and the 2022 head go with the first payload,
                    // which stays one chunk
                    let take = buf.len().min(max_chunk);
                    let (cipher, counter, bytes) = this.open(&buf[..take])?;
                    this.session = Some((cipher, counter));
                    frame = bytes;
                    this.consumed = take;
                }
                Some((cipher, counter)) => {
                    let take = frame_take(buf.len(), max_chunk);
                    for segment in buf[..take].chunks(max_chunk) {
                        write_chunk(cipher, counter, &mut frame, segment);
                    }
                    this.consumed = take;
                }
            }
            this.flushing = Some((frame, 0));
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    /// Hands out one prepared slice per `poll_read` and counts the calls, so a
    /// test can see how many times the reader had to go back to the socket for
    /// one record.
    struct OneSlicePerRead {
        slices: VecDeque<Vec<u8>>,
        polls: Arc<AtomicUsize>,
    }

    impl tokio::io::AsyncRead for OneSlicePerRead {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            match self.slices.pop_front() {
                Some(slice) => {
                    let take = slice.len().min(out.remaining());
                    out.put_slice(&slice[..take]);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Ready(Ok(())),
            }
        }
    }

    /// One record of `payload` bytes, sealed the way the writer seals it.
    fn record(cipher: &Cipher, counter: &mut u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let head = out.len();
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        cipher
            .seal_at(*counter, &mut out, head)
            .expect("seal length block");
        *counter += 1;
        let body = out.len();
        out.extend_from_slice(payload);
        cipher
            .seal_at(*counter, &mut out, body)
            .expect("seal payload");
        *counter += 1;
        out
    }

    /// Drive `records` max-size records of `method` through the reader, with the
    /// socket handing over one record per read.
    ///
    /// This is where a 2022 record that does not fit in the buffer shows up: the
    /// reader consumes the length block, finds the payload 18 bytes short of the
    /// buffer, moves the whole payload to the front and reads the missing bytes --
    /// which are the *next* record's header. The stream desyncs from there and the
    /// tag check fails. Legacy never gets there, because two of its records fit.
    fn read_records(method: Method, records: usize) -> (usize, usize) {
        let cipher = Cipher::new(method, &vec![9u8; method.key_len()]);
        let max_chunk = usize::from(method.max_chunk());
        let one = max_chunk + BLOCK_OVERHEAD;
        let mut counter = 0u64;
        let mut wire = Vec::new();
        for round in 0..records {
            wire.extend_from_slice(&record(
                &cipher,
                &mut counter,
                &vec![round as u8; max_chunk],
            ));
        }
        let mut slices = VecDeque::new();
        for chunk in wire.chunks(one) {
            slices.push_back(chunk.to_vec());
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let mut reader = ChunkReader {
            inner: Box::new(OneSlicePerRead {
                slices,
                polls: Arc::clone(&polls),
            }) as AnyRead,
            cipher,
            counter: 0,
            rbuf: Vec::new(),
            rpos: 0,
            rend: 0,
            pos: 0,
            pend: 0,
            want: 2 + AEAD_TAG,
            want_length: true,
            read_buf: read_buf(method),
        };

        let mut cx = Context::from_waker(Waker::noop());
        let mut out = vec![0u8; max_chunk];
        let mut got: Vec<u8> = Vec::new();
        while got.len() < records * max_chunk {
            let filled = {
                let mut buf = ReadBuf::new(&mut out);
                match std::pin::Pin::new(&mut reader).poll_read(&mut cx, &mut buf) {
                    Poll::Ready(Ok(())) => buf.filled().len(),
                    Poll::Ready(Err(err)) => panic!("{method:?}: read failed: {err}"),
                    Poll::Pending => panic!("{method:?}: a ready reader went pending"),
                }
            };
            got.extend_from_slice(&out[..filled]);
        }
        for round in 0..records {
            let at = round * max_chunk;
            assert!(
                got[at..at + max_chunk]
                    .iter()
                    .all(|byte| *byte == round as u8),
                "{method:?}: record {round} came back wrong, the framing slipped"
            );
        }
        (got.len(), polls.load(Ordering::Relaxed))
    }

    #[test]
    fn a_max_size_record_of_every_method_survives_the_round_trip() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
            Method::Blake3Aes128Gcm,
            Method::Blake3Aes256Gcm,
            Method::Blake3ChaCha20Poly1305,
        ] {
            let (got, polls) = read_records(method, 4);
            assert_eq!(got, 4 * usize::from(method.max_chunk()));
            assert!(
                polls <= 4,
                "{method:?}: one read per record is enough, took {polls}"
            );
        }
    }

    /// Frames leave in whole chunks, so a 64 KiB read does not turn into a full
    /// record plus a record holding one byte.
    #[test]
    fn a_frame_is_whole_chunks() {
        for (method, chunk) in [
            (Method::Aes128Gcm, 0x3FFFu32),
            (Method::Blake3Aes256Gcm, 0xFFFFu32),
        ] {
            let chunk = chunk as usize;
            let room = 64 * 1024usize;
            // a full relay read
            let take = frame_take(room, chunk);
            assert_eq!(take % chunk, 0, "{method:?}: frame cut mid-chunk");
            assert!(
                take >= chunk && take <= room.max(chunk),
                "{method:?}: frame_take took {take}"
            );
            // and what is left over is a remainder, not a record: the next read
            // coalesces with it
            let first = take;
            let leftover = room - first;
            let next = frame_take(leftover + room, chunk);
            assert_eq!(next % chunk, 0, "{method:?}: second frame cut mid-chunk");
            // less than one chunk still goes out, or nothing would ever move
            assert_eq!(frame_take(1, chunk), 1);
            assert_eq!(frame_take(chunk - 1, chunk), chunk - 1);
            assert_eq!(frame_take(chunk, chunk), chunk);
        }
    }

    /// The buffer a method needs, spelled out: one whole record.
    #[test]
    fn the_read_buffer_holds_a_whole_record() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
            Method::Blake3Aes128Gcm,
            Method::Blake3Aes256Gcm,
            Method::Blake3ChaCha20Poly1305,
        ] {
            let record = usize::from(method.max_chunk()) + BLOCK_OVERHEAD;
            assert!(
                read_buf(method) >= record,
                "{method:?} needs room for a {record}-byte record, got {}",
                read_buf(method)
            );
        }
    }

    /// Not a test: what each layer of the write path costs per GiB against the
    /// bare cipher, so a matrix cell's `user_s_per_gib` over the crypto floor
    /// can be attributed instead of guessed at.
    ///
    ///     cargo test --release -p core-runtime --lib inbound::shadowsocks::tests::write_path_costs -- --ignored --nocapture
    #[test]
    #[ignore = "microbenchmark, run by hand"]
    fn write_path_costs() {
        use crate::fastchacha::ChaChaPoly;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        use std::time::Instant;

        const PAYLOAD: usize = 65535;
        const GIB: u64 = 1u64 << 30;
        let payload = vec![0x5Au8; PAYLOAD];
        let key = vec![7u8; 32];

        let report = |label: &str, secs: f64, bytes: u64| {
            let gib = bytes as f64 / GIB as f64;
            println!("{label:34} {:7.3} s/GiB", secs / gib);
        };

        // 1. the bare cipher, seal in place, tag thrown away
        {
            let fast = ChaChaPoly::new(&key);
            let nonce = [0u8; 12];
            let mut buf = payload.clone();
            let mut ctr = 0u64;
            for _ in 0..32 {
                fast.seal(&nonce, &[], &mut buf);
                buf.truncate(PAYLOAD);
                ctr += 1;
            }
            let n = GIB / PAYLOAD as u64;
            let t = Instant::now();
            for _ in 0..n {
                std::hint::black_box(fast.seal(&nonce, &[], &mut buf));
                buf.truncate(PAYLOAD);
                ctr += 1;
            }
            std::hint::black_box(ctr);
            report(
                "raw ChaChaPoly::seal",
                t.elapsed().as_secs_f64(),
                n * PAYLOAD as u64,
            );
        }

        let method = Method::Blake3ChaCha20Poly1305;
        let mut cipher = Cipher::new(method, &key);

        // 2. the ss wrapper: one chunk sealed where it lands in a frame
        {
            let mut counter = 0u64;
            let mut frame = Vec::with_capacity(PAYLOAD + 128);
            for _ in 0..32 {
                frame.clear();
                write_chunk(&mut cipher, &mut counter, &mut frame, &payload);
            }
            let n = GIB / PAYLOAD as u64;
            let t = Instant::now();
            for _ in 0..n {
                frame.clear();
                write_chunk(&mut cipher, &mut counter, &mut frame, &payload);
            }
            std::hint::black_box(&frame);
            report(
                "Cipher + write_chunk (copy)",
                t.elapsed().as_secs_f64(),
                n * PAYLOAD as u64,
            );
        }

        // 3. the whole ServerWriter: frame_take, seal, drain to the socket
        {
            struct Sink;
            impl AsyncWrite for Sink {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<io::Result<usize>> {
                    Poll::Ready(Ok(buf.len()))
                }
                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }
            let mut writer = ServerWriter {
                inner: Box::new(Sink) as AnyWrite,
                method,
                master_key: Arc::new(key.clone()),
                request_salt: vec![9u8; method.salt_len()],
                session: Some((Cipher::new(method, &key), 0)),
                flushing: None,
                spare: Vec::new(),
                consumed: 0,
            };
            let mut cx = Context::from_waker(Waker::noop());
            let mut pin = Pin::new(&mut writer);
            for _ in 0..32 {
                let n = match AsyncWrite::poll_write(pin.as_mut(), &mut cx, &payload) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => panic!("write failed: {e}"),
                    Poll::Pending => panic!("a ready sink went pending"),
                };
                std::hint::black_box(n);
            }
            let n = GIB / PAYLOAD as u64;
            let t = Instant::now();
            for _ in 0..n {
                let got = match AsyncWrite::poll_write(pin.as_mut(), &mut cx, &payload) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => panic!("write failed: {e}"),
                    Poll::Pending => panic!("a ready sink went pending"),
                };
                assert_eq!(got, PAYLOAD);
            }
            report(
                "ServerWriter::poll_write",
                t.elapsed().as_secs_f64(),
                n * PAYLOAD as u64,
            );
        }
    }

    /// The read side of the same question: one opened record against the whole
    /// ChunkReader (fill, open where it sits, hand out).
    ///
    ///     cargo test --release -p core-runtime --lib inbound::shadowsocks::tests::read_path_costs -- --ignored --nocapture
    #[test]
    #[ignore = "microbenchmark, run by hand"]
    fn read_path_costs() {
        use std::time::Instant;

        const PAYLOAD: usize = 65535;
        const GIB: u64 = 1u64 << 30;
        let payload = vec![0x5Au8; PAYLOAD];
        let key = vec![7u8; 32];
        let method = Method::Blake3ChaCha20Poly1305;
        let records = GIB / PAYLOAD as u64;

        let report = |label: &str, secs: f64, bytes: u64| {
            let gib = bytes as f64 / GIB as f64;
            println!("{label:34} {:7.3} s/GiB", secs / gib);
        };

        // 1. one block opened where it sits: the open runs in full every time
        // even against the already-plain buffer, so the loop needs no re-seal
        // and no copy
        {
            let mut cipher = Cipher::new(method, &key);
            let mut block = Vec::new();
            let mut ctr = 0u64;
            write_sealed(&mut cipher, &mut ctr, &mut block, &payload);
            let n = GIB / PAYLOAD as u64;
            let t = Instant::now();
            for _ in 0..n {
                // every open after the first fails the tag and runs the full
                // path anyway, which is the cost being measured
                let _ = cipher.open_slice(0, &mut block);
                std::hint::black_box(&block);
            }
            report(
                "Cipher::open_slice (in place)",
                t.elapsed().as_secs_f64(),
                n * PAYLOAD as u64,
            );
        }

        // 2. the whole ChunkReader over the wire the peer would have sent:
        // length block + payload per record
        {
            struct Slab {
                data: Vec<u8>,
                pos: usize,
            }
            impl AsyncRead for Slab {
                fn poll_read(
                    mut self: std::pin::Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    out: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    let n = out.remaining().min(self.data.len() - self.pos);
                    out.put_slice(&self.data[self.pos..self.pos + n]);
                    self.pos += n;
                    Poll::Ready(Ok(()))
                }
            }
            let mut wire = Vec::new();
            {
                let mut peer = Cipher::new(method, &key);
                let mut ctr = 0u64;
                let mut frame = Vec::new();
                for _ in 0..records {
                    frame.clear();
                    write_chunk(&mut peer, &mut ctr, &mut frame, &payload);
                    wire.extend_from_slice(&frame);
                }
            }
            let run = |warm: bool| -> f64 {
                let mut reader = ChunkReader {
                    inner: Box::new(Slab {
                        data: wire.clone(),
                        pos: 0,
                    }) as AnyRead,
                    cipher: Cipher::new(method, &key),
                    counter: 0,
                    rbuf: Vec::new(),
                    rpos: 0,
                    rend: 0,
                    pos: 0,
                    pend: 0,
                    want: 2 + AEAD_TAG,
                    want_length: true,
                    read_buf: read_buf(method),
                };
                let mut cx = Context::from_waker(std::task::Waker::noop());
                let mut scratch = vec![0u8; 64 * 1024];
                let target = records * PAYLOAD as u64;
                let mut got = 0u64;
                let t = Instant::now();
                while got < target {
                    let mut out = ReadBuf::new(&mut scratch);
                    match std::pin::Pin::new(&mut reader).poll_read(&mut cx, &mut out) {
                        Poll::Ready(Ok(())) => {
                            let n = out.filled().len();
                            assert!(n > 0, "the slab held less than the wire");
                            got += n as u64;
                        }
                        Poll::Ready(Err(e)) => panic!("read failed: {e}"),
                        Poll::Pending => panic!("a full slab went pending"),
                    }
                }
                if warm {
                    return 0.0;
                }
                t.elapsed().as_secs_f64()
            };
            let secs = run(true) + run(false);
            report("ChunkReader::poll_read", secs, records * PAYLOAD as u64);
        }
    }

    /// Both halves of the relay in one process over a real async channel: the
    /// isolated layer costs plus tokio scheduling plus the copy each direction
    /// does. Half of the total is what one side of a matrix cell should cost,
    /// so a cell's user sitting above it is environment, not code.
    ///
    ///     cargo test --release -p core-runtime --lib inbound::shadowsocks::tests::duplex_relay_costs -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "microbenchmark, run by hand"]
    async fn duplex_relay_costs() {
        use std::time::Instant;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const PAYLOAD: usize = 65535;
        const GIB: u64 = 1u64 << 30;
        let payload = vec![0x5Au8; PAYLOAD];
        let key = vec![7u8; 32];
        let method = Method::Blake3ChaCha20Poly1305;
        let records = GIB / PAYLOAD as u64;

        async fn pass(method: Method, records: u64, payload: Vec<u8>, key: &[u8]) {
            let (wr, rd) = tokio::io::duplex(256 * 1024);
            let mut writer = ServerWriter {
                inner: Box::new(wr) as AnyWrite,
                method,
                master_key: Arc::new(key.to_vec()),
                request_salt: vec![9u8; method.salt_len()],
                session: Some((Cipher::new(method, key), 0)),
                flushing: None,
                spare: Vec::new(),
                consumed: 0,
            };
            let mut reader = ChunkReader {
                inner: Box::new(rd) as AnyRead,
                cipher: Cipher::new(method, key),
                counter: 0,
                rbuf: Vec::new(),
                rpos: 0,
                rend: 0,
                pos: 0,
                pend: 0,
                want: 2 + AEAD_TAG,
                want_length: true,
                read_buf: read_buf(method),
            };
            let target = records * PAYLOAD as u64;
            let w = tokio::spawn(async move {
                for _ in 0..records {
                    writer.write_all(&payload).await.expect("write");
                }
            });
            let r = tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let mut got = 0u64;
                while got < target {
                    let n = reader.read(&mut buf).await.expect("read");
                    assert!(n > 0, "the channel closed short");
                    got += n as u64;
                }
            });
            w.await.expect("writer task");
            r.await.expect("reader task");
        }

        pass(method, 32, payload.clone(), &key).await;
        let t = Instant::now();
        pass(method, records, payload.clone(), &key).await;
        let secs = t.elapsed().as_secs_f64();
        println!(
            "duplex relay (seal + open + tokio) {:7.3} s/GiB total, {:7.3} per side",
            secs,
            secs / 2.0
        );
    }
}
