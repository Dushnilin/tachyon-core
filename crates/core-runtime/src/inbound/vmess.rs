//! vmess as a server inbound (F5). The request header is the mirror of what
//! `outbound::vmess` seals, so every piece comes from there: the same KDF
//! salts, the same auth id, the same framing -- with the request and response
//! keys swapped, because on the other side of the connection they are the
//! other way round. Reference: `sing-vmess.Service.NewConnection` and
//! `rawServerConn.writeResponse`.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpListener;

use super::tls::ServerTls;
use super::transport::Transport;
use super::udp::{relay_stream_datagrams, udp_destination};
use crate::inbound::{AnyStream, AnyWrite, ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::outbound::vmess::framing::{BodyWriter, FrameAssembler, WRITE_CHUNK, write_batch};
use crate::outbound::vmess::kdf::{cmd_key, crc32_ieee, kdf, kdf16, parse_uuid};
use crate::outbound::vmess::wire::{derive_response_keys, gcm_open, gcm_seal};
use crate::route::Router;

const SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const SALT_HDR_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const SALT_HDR_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const SALT_HDR_KEY: &[u8] = b"VMess Header AEAD Key";
const SALT_HDR_IV: &[u8] = b"VMess Header AEAD Nonce";
const SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";

const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;

/// `[version][addonsLen]`, what the UDP command answers with instead of the
/// sealed response header: the packet path has no codec, so there is nothing
/// to key a header with.
const PACKET_RESPONSE_HEAD: [u8; 2] = [0x00, 0x00];
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;

/// The auth id carries the client's clock, so the reference allows two minutes
/// either way and remembers what it has seen for the same window.
const AUTH_WINDOW_SECS: i64 = 120;

/// The edge belongs to the window, one second past it does not.
fn timestamp_fresh(now: i64, timestamp: i64) -> bool {
    (now - timestamp).abs() <= AUTH_WINDOW_SECS
}

/// One configured user. The auth id is an AES block encrypted under a key only
/// this user's uuid produces, so a server tries every user and checks whether
/// the decrypted block is a well-formed, fresh timestamp.
#[derive(Clone)]
struct User {
    name: String,
    key: [u8; 16],
    auth_key: [u8; 16],
}

/// `replay.NewSimple(120s)`: one decrypted id may be used once.
#[derive(Default)]
struct Replay {
    seen: Mutex<HashMap<[u8; 16], i64>>,
}

impl Replay {
    /// `true` when this id is new, which is the only case the caller accepts.
    fn check(&self, id: &[u8; 16]) -> bool {
        let now = unix_now();
        let mut seen = self.seen.lock().expect("replay filter poisoned");
        seen.retain(|_, at| now - *at <= AUTH_WINDOW_SECS);
        !seen.contains_key(id) && seen.insert(*id, now).is_none()
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

pub struct Vmess {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    users: Arc<Vec<User>>,
    replay: Arc<Replay>,
    tls: Option<Arc<ServerTls>>,
    transport: Option<Arc<Transport>>,
}

impl Vmess {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("vmess")
            .to_string();
        let at = format!("inbound[{tag}]");
        let list = object
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing users"))?;
        if list.is_empty() {
            anyhow::bail!("{at}: users is required and must not be empty");
        }
        let mut users = Vec::with_capacity(list.len());
        for (index, entry) in list.iter().enumerate() {
            let raw = entry
                .get("uuid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{at}.users[{index}]: missing uuid"))?;
            let uuid = parse_uuid(raw).map_err(|e| anyhow::anyhow!("{at}.users[{index}]: {e}"))?;
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let key = cmd_key(&uuid);
            users.push(User {
                name: if name.is_empty() {
                    index.to_string()
                } else {
                    name
                },
                auth_key: kdf16(&key, &[SALT_AUTH_ID]),
                key,
            });
        }
        let listen = parse_listen(object, &at)?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            users: Arc::new(users),
            replay: Arc::new(Replay::default()),
            tls: ServerTls::from_inbound(obj, &at)?,
            transport: Transport::from_inbound(obj, &at)?.map(Arc::new),
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
                    let users = Arc::clone(&self.users);
                    let replay = Arc::clone(&self.replay);
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let tls = self.tls.clone();
                    let transport = self.transport.clone();
                    tokio::spawn(async move {
                        let local = stream.local_addr().unwrap_or(peer);
                        let result = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(stream) => {
                                    wrapped(
                                        stream, transport, peer, local, users, replay, tag, router,
                                    )
                                    .await
                                }
                                Err(err) => Err(err),
                            },
                            None => {
                                wrapped(stream, transport, peer, local, users, replay, tag, router)
                                    .await
                            }
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("vmess {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::debug(format_args!("vmess accept: {err}"));
                    return;
                }
            }
        }
    }
}

/// Take the transport off the front of the connection, if the listener has one,
/// and hand what is left to the protocol. The order is the reference's: TLS first
/// (the handshake is inside it), then the transport, then the protocol header.
#[allow(clippy::too_many_arguments)]
async fn wrapped<S>(
    stream: S,
    transport: Option<Arc<Transport>>,
    peer: SocketAddr,
    local: SocketAddr,
    users: Arc<Vec<User>>,
    replay: Arc<Replay>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match transport {
        None => handle(stream, peer, local, users, replay, tag, router).await,
        Some(transport) => {
            let stream: AnyStream = Box::new(stream);
            match transport.accept(stream).await {
                Ok(stream) => handle(stream, peer, local, users, replay, tag, router).await,
                Err(err) => Err(io::Error::other(err)),
            }
        }
    }
}

/// What the request header carries once it is open.
struct Request {
    user: User,
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_header: u8,
    option: u8,
    security: u8,
    command: u8,
    destination: Target,
}

async fn handle<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: Arc<Vec<User>>,
    replay: Arc<Replay>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = read_request(&mut stream, &users, &replay).await?;
    if request.command != COMMAND_TCP && request.command != COMMAND_UDP {
        return Err(io::Error::other(format!(
            "command {} is not implemented by this server",
            request.command
        )));
    }
    // legacy: aes-128-cfb under a key hashed from the auth id's timestamp
    if request.security == crate::outbound::vmess::SEC_LEGACY {
        return Err(io::Error::other(
            "aes-128-cfb with a SHA1 key is not implemented by this server",
        ));
    }
    // 3 and 4 seal the body; 5 (none) and 6 (zero) leave it in the clear. sing-box
    // picks zero for a vmess outbound that sits on TLS, and without the option
    // bit for chunked bodies the payload is the bare stream, no frames at all.
    if !matches!(request.security, 3..=6) {
        return Err(io::Error::other(format!(
            "vmess security {} is not implemented by this server",
            request.security
        )));
    }
    let bare_body = matches!(request.security, 5 | 6) && request.option & OPT_CHUNK_STREAM == 0;
    let (response_key, response_iv) =
        derive_response_keys(&request.request_key, &request.request_iv);
    // The answer is four bytes -- `[responseHeader][option][0][0]` -- behind an
    // AEAD length block. The client reads it before anything else, so it goes
    // out now; the reference defers it to the first write, which only a client
    // that speaks first can tell apart.
    let answer = seal_response_header(
        &response_key,
        &response_iv,
        request.response_header,
        request.option,
    );

    if request.command == COMMAND_UDP {
        // vmess datagrams ride the raw stream, not the body codec: `[len:u16]`
        // in front of each one delimits itself, so the codec that carries a TCP
        // stream has nothing to do here. What the client reads first is the bare
        // `[version][addonsLen]` pair rather than the sealed header above --
        // `serverPacketConn` writes those two bytes and nothing else, because
        // there is no codec here to key them with.
        let dest = udp_destination(&request.destination)?;
        logging::info(format_args!(
            "vmess [{}] inbound packet connection to {dest}",
            request.user.name
        ));
        stream.write_all(&PACKET_RESPONSE_HEAD).await?;
        let (reader, writer) = tokio::io::split(stream);
        return relay_stream_datagrams(
            reader,
            Arc::new(tokio::sync::Mutex::new(Box::new(writer) as AnyWrite)),
            peer,
            dest,
            &tag,
            &router,
        )
        .await;
    }

    // The client reads it before anything else, so it goes out now; the
    // reference defers it to the first write, which only a client that speaks
    // first can tell apart.
    stream.write_all(&answer).await?;

    let global_padding = request.option & OPT_GLOBAL_PADDING != 0;
    let chunk_masking = request.option & OPT_CHUNK_MASKING != 0;
    let authenticated_length = request.option & OPT_AUTHENTICATED_LENGTH != 0;
    let framed: AnyStream = if bare_body {
        Box::new(stream)
    } else {
        Box::new(ServerStream {
            inner: Box::new(stream),
            // what the client writes is keyed with the request keys on both sides
            read: FrameAssembler::new(
                request.security,
                &request.request_key,
                &request.request_iv,
                &request.request_key,
                &request.request_iv,
                global_padding,
                chunk_masking,
                authenticated_length,
                None,
            ),
            write: WriterState {
                body: BodyWriter::new(
                    request.security,
                    &response_key,
                    &response_iv,
                    global_padding,
                    chunk_masking,
                    authenticated_length,
                ),
                flushing: None,
                spare: Vec::new(),
                consumed: 0,
            },
        })
    };
    logging::info(format_args!(
        "vmess [{}] inbound connection to {}",
        request.user.name, request.destination
    ));
    drive_framed(
        ClientConn::framed(framed, local),
        peer,
        request.destination,
        &tag,
        &router,
    )
    .await
}

/// authID || GCM(length, AAD=authID) || connNonce(8) || GCM(header, AAD=authID).
async fn read_request<S>(stream: &mut S, users: &[User], replay: &Replay) -> io::Result<Request>
where
    S: AsyncRead + Unpin,
{
    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await?;
    let (user, decoded, timestamp) = find_user(users, &auth_id)?;
    if !timestamp_fresh(unix_now(), timestamp) {
        return Err(io::Error::other("bad timestamp"));
    }
    if !replay.check(&decoded) {
        return Err(io::Error::other("replayed request"));
    }

    let mut sealed_len = [0u8; 18];
    stream.read_exact(&mut sealed_len).await?;
    let mut conn_nonce = [0u8; 8];
    stream.read_exact(&mut conn_nonce).await?;

    let len_key = kdf16(&user.key, &[SALT_HDR_LEN_KEY, &auth_id, &conn_nonce]);
    let len_nonce = nonce(&user.key, SALT_HDR_LEN_IV, &auth_id, &conn_nonce);
    let mut length = sealed_len.to_vec();
    gcm_open(&len_key, &len_nonce, &auth_id, &mut length)?;
    let header_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if header_len < 38 {
        return Err(io::Error::other("bad header"));
    }
    let mut sealed_header = vec![0u8; header_len + 16];
    stream.read_exact(&mut sealed_header).await?;
    let hdr_key = kdf16(&user.key, &[SALT_HDR_KEY, &auth_id, &conn_nonce]);
    let hdr_nonce = nonce(&user.key, SALT_HDR_IV, &auth_id, &conn_nonce);
    gcm_open(&hdr_key, &hdr_nonce, &auth_id, &mut sealed_header)?;
    parse_header(&user, &sealed_header)
}

fn nonce(key: &[u8; 16], salt: &[u8], auth_id: &[u8; 16], conn_nonce: &[u8; 8]) -> [u8; 12] {
    kdf(key, &[salt, auth_id, conn_nonce])[..12]
        .try_into()
        .expect("kdf output is 32 bytes")
}

/// The auth id decrypts to `i64 seconds || 4 random || crc32 of the first 12`
/// under this user's key, so a wrong user leaves no valid checksum behind.
fn find_user(users: &[User], auth_id: &[u8; 16]) -> io::Result<(User, [u8; 16], i64)> {
    use aes::cipher::{BlockDecrypt as _, KeyInit as _};
    for user in users {
        let cipher = aes::Aes128::new_from_slice(&user.auth_key).expect("aes key length");
        let mut block = aes::Block::clone_from_slice(auth_id);
        cipher.decrypt_block(&mut block);
        let decoded: [u8; 16] = block.into();
        let checksum = u32::from_be_bytes([decoded[12], decoded[13], decoded[14], decoded[15]]);
        if crc32_ieee(&decoded[..12]) != checksum {
            continue;
        }
        let timestamp = i64::from_be_bytes(decoded[..8].try_into().expect("8 bytes"));
        return Ok((user.clone(), decoded, timestamp));
    }
    Err(io::Error::other("bad request"))
}

fn parse_header(user: &User, header: &[u8]) -> io::Result<Request> {
    if header.first() != Some(&1) {
        return Err(io::Error::other("bad version"));
    }
    if header.len() < 38 {
        return Err(io::Error::other("bad header"));
    }
    let request_iv: [u8; 16] = header[1..17].try_into().expect("16 bytes");
    let request_key: [u8; 16] = header[17..33].try_into().expect("16 bytes");
    let response_header = header[33];
    let option = header[34];
    let padding_len = usize::from(header[35] >> 4);
    let security = header[35] & 0x0f;
    let command = header[37];
    match command {
        1..=3 => {}
        other => return Err(io::Error::other(format!("unknown command: {other}"))),
    }
    // the address follows the fixed 38 bytes, port first (`portFirst` serializer)
    let mut at = 38usize;
    let port = u16::from_be_bytes([header[at], header[at + 1]]);
    at += 2;
    let destination = match header.get(at) {
        Some(0x01) => {
            let addr: [u8; 4] = header
                .get(at + 1..at + 5)
                .ok_or_else(|| io::Error::other("bad header"))?
                .try_into()
                .expect("4 bytes");
            at += 5;
            Target::Ip(SocketAddr::from((addr, port)))
        }
        Some(0x02) => {
            let len = usize::from(
                *header
                    .get(at + 1)
                    .ok_or_else(|| io::Error::other("bad header"))?,
            );
            let host = header
                .get(at + 2..at + 2 + len)
                .ok_or_else(|| io::Error::other("bad header"))?;
            at += 2 + len;
            Target::Domain(String::from_utf8_lossy(host).into_owned(), port)
        }
        Some(0x03) => {
            let addr: [u8; 16] = header
                .get(at + 1..at + 17)
                .ok_or_else(|| io::Error::other("bad header"))?
                .try_into()
                .expect("16 bytes");
            at += 17;
            Target::Ip(SocketAddr::from((addr, port)))
        }
        _ => return Err(io::Error::other("bad address type")),
    };
    // padding and the trailing four bytes are skipped unread, exactly as the
    // reference does -- the header is authenticated with AEAD either way
    if at + padding_len + 4 > header.len() {
        return Err(io::Error::other("bad padding"));
    }
    Ok(Request {
        user: user.clone(),
        request_key,
        request_iv,
        response_header,
        option,
        security,
        command,
        destination,
    })
}

fn seal_response_header(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    response_header: u8,
    option: u8,
) -> Vec<u8> {
    let len_key = kdf16(response_key, &[SALT_RESP_LEN_KEY]);
    let len_nonce: [u8; 12] = kdf(response_iv, &[SALT_RESP_LEN_IV])[..12]
        .try_into()
        .expect("kdf output is 32 bytes");
    let length = gcm_seal(&len_key, &len_nonce, &[], &4u16.to_be_bytes());
    let hdr_key = kdf16(response_key, &[SALT_RESP_KEY]);
    let hdr_nonce: [u8; 12] = kdf(response_iv, &[SALT_RESP_IV])[..12]
        .try_into()
        .expect("kdf output is 32 bytes");
    let payload = gcm_seal(&hdr_key, &hdr_nonce, &[], &[response_header, option, 0, 0]);
    let mut out = Vec::with_capacity(length.len() + payload.len());
    out.extend_from_slice(&length);
    out.extend_from_slice(&payload);
    out
}

/// The framed connection: reads with the request keys, writes with the response
/// keys, which is the client's `VmessStream` with the two sides swapped.
struct ServerStream {
    inner: AnyStream,
    read: FrameAssembler,
    write: WriterState,
}

struct WriterState {
    body: BodyWriter,
    /// a frame being drained onto the socket, and how far it has got
    flushing: Option<(Vec<u8>, usize)>,
    /// the frame buffer between writes: a batch is 60 KiB, so a fresh one per
    /// `poll_write` is an allocation and a cold page fault every 60 KiB of stream
    spare: Vec<u8>,
    consumed: usize,
}

impl AsyncRead for ServerStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        this.read.poll_read(&mut this.inner, cx, buf)
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        loop {
            if let Some((frame, off)) = &mut this.write.flushing {
                while *off < frame.len() {
                    let n = ready!(
                        std::pin::Pin::new(&mut *this.inner).poll_write(cx, &frame[*off..])
                    )?;
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "vmess: frame write stalled",
                        )));
                    }
                    *off += n;
                }
                if let Some((frame, _)) = this.write.flushing.take() {
                    this.write.spare = frame;
                }
                return Poll::Ready(Ok(this.write.consumed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let batch = buf.len().min(write_batch());
            let mut frame = std::mem::take(&mut this.write.spare);
            frame.clear();
            let mut taken = 0;
            while taken < batch {
                let take = (batch - taken).min(WRITE_CHUNK);
                this.write
                    .body
                    .frame_into(&buf[taken..taken + take], &mut frame)?;
                taken += take;
            }
            this.write.flushing = Some((frame, 0));
            this.write.consumed = taken;
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
    use aes::cipher::{BlockEncrypt as _, KeyInit as _};

    fn user(raw: &str) -> User {
        let key = cmd_key(&parse_uuid(raw).expect("uuid"));
        User {
            name: raw.to_string(),
            auth_key: kdf16(&key, &[SALT_AUTH_ID]),
            key,
        }
    }

    /// What a client puts on the wire: `seconds || random || crc32`, sealed
    /// under the user's auth key.
    fn auth_id(user: &User, timestamp: i64) -> [u8; 16] {
        let mut plain = [0u8; 16];
        plain[..8].copy_from_slice(&timestamp.to_be_bytes());
        plain[8..12].copy_from_slice(&[1, 2, 3, 4]);
        let checksum = crc32_ieee(&plain[..12]);
        plain[12..].copy_from_slice(&checksum.to_be_bytes());
        let cipher = aes::Aes128::new_from_slice(&user.auth_key).expect("aes key length");
        let mut block = aes::Block::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    #[test]
    fn the_auth_id_picks_out_the_user_it_belongs_to() {
        let users = vec![
            user("b831381d-6324-4d53-ad4f-8cda48b30811"),
            user("00000000-0000-4000-8000-000000000000"),
        ];
        let now = unix_now();
        for entry in &users {
            let (found, _, timestamp) = find_user(&users, &auth_id(entry, now)).expect("found");
            assert_eq!(found.name, entry.name);
            assert_eq!(timestamp, now);
        }
    }

    #[test]
    fn a_corrupted_auth_id_matches_nobody() {
        let users = vec![user("b831381d-6324-4d53-ad4f-8cda48b30811")];
        let mut id = auth_id(&users[0], unix_now());
        id[3] ^= 0x01;
        assert!(
            find_user(&users, &id).is_err(),
            "a flipped bit must not find a user"
        );
    }

    #[test]
    fn the_timestamp_window_keeps_its_edge() {
        let now = 1_000_000;
        assert!(timestamp_fresh(now, now));
        assert!(timestamp_fresh(now, now - AUTH_WINDOW_SECS));
        assert!(timestamp_fresh(now, now + AUTH_WINDOW_SECS));
        assert!(!timestamp_fresh(now, now - AUTH_WINDOW_SECS - 1));
        assert!(!timestamp_fresh(now, now + AUTH_WINDOW_SECS + 1));
    }

    #[test]
    fn a_decrypted_id_serves_once() {
        let replay = Replay::default();
        let id = [7u8; 16];
        assert!(replay.check(&id), "the first use is fine");
        assert!(!replay.check(&id), "the second use is a replay");
        assert!(replay.check(&[8u8; 16]), "a different id is unaffected");
    }
}
