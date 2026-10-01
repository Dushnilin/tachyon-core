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

use crate::inbound::{
    AnyRead, AnyStream, AnyWrite, ClientConn, Target, drive_framed, parse_listen,
};
use crate::logging;
use crate::outbound::shadowsocks::crypto::{
    Cipher, Method, derive_subkey, master_key, random_bytes,
};
use crate::route::Router;

/// The 2022 head carries the client's clock; the reference allows 30 seconds.
const TIMESTAMP_WINDOW_SECS: i64 = 30;

const AEAD_TAG: usize = 16;

pub struct Shadowsocks {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    method: Method,
    master_key: Arc<Vec<u8>>,
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
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let method = self.method;
                    let master_key = Arc::clone(&self.master_key);
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    tokio::spawn(async move {
                        if let Err(err) =
                            handle(stream, peer, method, master_key, tag, router).await
                        {
                            eprintln!("SS-SERVER-ERR {peer}: {err}");
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

async fn handle(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    method: Method,
    master_key: Arc<Vec<u8>>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()> {
    let mut salt = vec![0u8; method.salt_len()];
    stream.read_exact(&mut salt).await?;
    let mut cipher = Cipher::new(method, &derive_subkey(method, &master_key, &salt));
    let mut counter = 0u64;
    let head = if method.is_2022() {
        read_2022_head(&mut stream, &mut cipher, &mut counter).await?
    } else {
        read_legacy_head(&mut stream, &mut cipher, &mut counter).await?
    };

    let local = stream.local_addr().unwrap_or(peer);
    let (read_half, write_half) = tokio::io::split(stream);
    let framed: AnyStream = Box::new(ServerStream {
        read: ChunkReader {
            inner: Box::new(read_half) as AnyRead,
            cipher,
            counter: head.counter,
            pending: head.prefix,
            pos: 0,
            staging: Vec::new(),
            staging_want: 2 + AEAD_TAG,
            staging_filled: 0,
            staging_length: true,
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
async fn read_2022_head(
    stream: &mut tokio::net::TcpStream,
    cipher: &mut Cipher,
    counter: &mut u64,
) -> io::Result<Head> {
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
async fn read_legacy_head(
    stream: &mut tokio::net::TcpStream,
    cipher: &mut Cipher,
    counter: &mut u64,
) -> io::Result<Head> {
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
async fn read_chunk(
    stream: &mut tokio::net::TcpStream,
    cipher: &mut Cipher,
    counter: &mut u64,
) -> io::Result<Vec<u8>> {
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
async fn read_sealed(
    stream: &mut tokio::net::TcpStream,
    cipher: &mut Cipher,
    counter: &mut u64,
    len: usize,
) -> io::Result<Vec<u8>> {
    let mut payload = vec![0u8; len + AEAD_TAG];
    stream.read_exact(&mut payload).await?;
    cipher.open(*counter, &mut payload)?;
    *counter += 1;
    Ok(payload)
}

/// Seal one chunk onto `out`, the way `shadowaead.Writer.WriteChunk` does.
fn write_chunk(cipher: &mut Cipher, counter: &mut u64, out: &mut Vec<u8>, data: &[u8]) {
    let mut head = (data.len() as u16).to_be_bytes().to_vec();
    cipher.seal(*counter, &mut head).expect("seal cannot fail");
    *counter += 1;
    out.extend_from_slice(&head);
    write_sealed(cipher, counter, out, data);
}

/// A block sealed straight off the session key, with no length in front of it:
/// the 2022 head and the first payload on either side of it.
fn write_sealed(cipher: &mut Cipher, counter: &mut u64, out: &mut Vec<u8>, data: &[u8]) {
    let mut block = data.to_vec();
    cipher.seal(*counter, &mut block).expect("seal cannot fail");
    *counter += 1;
    out.extend_from_slice(&block);
}

/// The payload side: the request cipher carried on from where the head left
/// it, plus whatever the head had already decrypted.
struct ChunkReader {
    inner: AnyRead,
    cipher: Cipher,
    counter: u64,
    /// plaintext not yet handed out
    pending: Vec<u8>,
    pos: usize,
    /// a sealed block on its way in, how long it has to be, and how much of it
    /// has actually arrived
    staging: Vec<u8>,
    staging_want: usize,
    staging_filled: usize,
    /// whether the block being read is a length rather than a payload
    staging_length: bool,
}

impl AsyncRead for ChunkReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.pos >= this.pending.len() {
            // a block is only opened once every byte of it has arrived: the
            // counter moves with it, and a half-read block must not be able to
            // step over the bytes still in flight
            ready!(poll_read_exact(
                &mut this.inner,
                cx,
                &mut this.staging,
                &mut this.staging_filled,
                this.staging_want
            ))?;
            let mut block = std::mem::take(&mut this.staging);
            this.staging_filled = 0;
            this.cipher.open(this.counter, &mut block)?;
            this.counter += 1;
            if this.staging_length {
                let len = usize::from(u16::from_be_bytes([block[0], block[1]]));
                if len == 0 {
                    return Poll::Ready(Err(io::Error::other("zero-length chunk")));
                }
                this.staging_length = false;
                this.staging_want = len + AEAD_TAG;
                continue;
            }
            this.staging_length = true;
            this.staging_want = 2 + AEAD_TAG;
            this.pending = block;
            this.pos = 0;
        }
        let n = out.remaining().min(this.pending.len() - this.pos);
        out.put_slice(&this.pending[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// Fill `staging` to `want` bytes across as many `Pending`s as it takes, and
/// leave what has arrived in place for the next call.
fn poll_read_exact(
    inner: &mut AnyRead,
    cx: &mut Context<'_>,
    staging: &mut Vec<u8>,
    filled: &mut usize,
    want: usize,
) -> Poll<io::Result<()>> {
    if *filled == 0 {
        staging.clear();
        staging.resize(want, 0);
    }
    while *filled < want {
        let mut read_buf = ReadBuf::new(&mut staging[*filled..]);
        match std::pin::Pin::new(&mut **inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream closed mid-chunk",
                    )));
                }
                *filled += n;
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
                this.flushing = None;
                return Poll::Ready(Ok(this.consumed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let take = buf.len().min(usize::from(this.method.max_chunk()));
            let mut frame = Vec::with_capacity(take + 2 * AEAD_TAG + 2);
            match &mut this.session {
                None => {
                    let (cipher, counter, bytes) = this.open(&buf[..take])?;
                    this.session = Some((cipher, counter));
                    frame = bytes;
                }
                Some((cipher, counter)) => write_chunk(cipher, counter, &mut frame, &buf[..take]),
            }
            this.flushing = Some((frame, 0));
            this.consumed = take;
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}
