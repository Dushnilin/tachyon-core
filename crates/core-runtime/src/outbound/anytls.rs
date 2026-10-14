//! AnyTLS outbound: TLS transport plus the anytls session/stream framing.
//!
//! After the TLS handshake the client sends
//! `[sha256(password)][padding_len u16][padding]`, a settings frame, and then
//! multiplexes streams as `[cmd][stream id u32][length u16][data]` frames:
//! `SYN` opens a stream, `PSH` carries payload, `FIN` closes it. The first
//! payload of a stream is the SOCKS-style destination address; UDP rides the
//! same streams through the sing `uot` framing.
//!
//! The session pool caps the number of live TLS sessions: below the cap every
//! stream dials its own session (parallel TCP flows), and once the cap is hit
//! new streams share the least-loaded live session -- 1000 idle connections
//! cost a handful of sessions instead of one TLS handshake each. There is no
//! record padding (the server accepts a client without it).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::proxy::{encode_target, server_endpoint};
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::uot::{UOT_MAGIC, magic_authority, request_header, spawn_bridge};
use crate::tls_client::TlsOptions;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const FRAME_HEADER: usize = 7;
/// frame payloads carry a u16 length, so the frame takes the whole field
const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const CLIENT_VERSION: &str = "tachyon-core/anytls";
/// Concurrent TLS sessions: below it a stream dials its own, at it streams
/// share the least-loaded one. One session per connection made 1000 idle
/// connections cost 1000 handshakes and ~1 GiB of RSS.
const MAX_SESSIONS: usize = 8;
/// Frames buffered per stream before the session reader waits on it.
const STREAM_QUEUE: usize = 64;
/// reference session-pool knobs; the cap above does that job here
const POOL_FIELDS: &[&str] = &[
    "idle_session_check_interval",
    "idle_session_timeout",
    "min_idle_session",
];

/// `util.StringMap` payload: `key=value` lines joined with `\n`.
fn settings_payload(client_metadata: Option<&str>) -> Vec<u8> {
    let client = client_metadata.unwrap_or(CLIENT_VERSION);
    [format!("client={client}"), "v=2".to_string()]
        .join("\n")
        .into_bytes()
}

/// `[cmd][sid u32][len u16][data]`
fn encode_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER + data.len());
    frame.push(cmd);
    frame.extend_from_slice(&sid.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn parse_header(header: &[u8; FRAME_HEADER]) -> (u8, u32, usize) {
    let cmd = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    (cmd, sid, len)
}

/// peer version from a settings payload (`v=` line)
fn settings_version(data: &[u8]) -> Option<u8> {
    let text = String::from_utf8_lossy(data);
    text.split('\n')
        .find_map(|line| line.strip_prefix("v=")?.trim().parse::<u8>().ok())
}

/// One anytls session: the TLS connection plus its stream registry.
struct Session {
    writer: AsyncMutex<WriteHalf<AnyStream>>,
    streams: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    /// stream ids start at 1 (`session.OpenStream`)
    next_sid: AtomicU32,
    reserved: std::sync::atomic::AtomicUsize,
    alive: AtomicBool,
    peer_version: AtomicU8,
    /// recycled payload buffers: frames are handed to streams from here and
    /// returned once fully read, so steady-state dispatch allocates nothing.
    free: Mutex<Vec<Vec<u8>>>,
}

impl Session {
    /// TLS + password greeting + settings frame, then spawn the frame reader.
    async fn open(
        server: &str,
        port: u16,
        tls: &TlsOptions,
        password_sha256: &[u8; 32],
        client_metadata: Option<&str>,
        tag: &str,
        dial: &crate::outbound::dial::DialOptions,
    ) -> io::Result<Arc<Self>> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            crate::outbound::dial::connect_tcp(server, port, dial),
        )
        .await
        .map_err(|_| io::Error::other("anytls: connect timeout"))??;
        let stream = match tls.wrap_with_defaults(tcp, &[]).await {
            Err(e) if crate::tls_client::is_tls13_unsupported(&e) && tls.reality().is_none() => {
                tls.mark_tls12(server, port);
                let tcp = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    crate::outbound::dial::connect_tcp(server, port, dial),
                )
                .await
                .map_err(|_| io::Error::other("anytls: connect timeout"))??;
                tls.wrap_with_defaults(tcp, &[]).await?
            }
            res => res?,
        };
        Self::establish(stream, password_sha256, client_metadata, tag).await
    }

    /// Greeting + settings over an established transport (TLS in production).
    async fn establish(
        stream: AnyStream,
        password_sha256: &[u8; 32],
        client_metadata: Option<&str>,
        tag: &str,
    ) -> io::Result<Arc<Self>> {
        let (reader, mut writer) = tokio::io::split(stream);
        // greeting: sha256(password) followed by the padding length
        let mut greeting = Vec::with_capacity(34);
        greeting.extend_from_slice(password_sha256);
        greeting.extend_from_slice(&0u16.to_be_bytes());
        writer.write_all(&greeting).await?;
        let settings = encode_frame(CMD_SETTINGS, 0, &settings_payload(client_metadata));
        writer.write_all(&settings).await?;
        writer.flush().await?;
        let session = Arc::new(Self {
            writer: AsyncMutex::new(writer),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            reserved: std::sync::atomic::AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            peer_version: AtomicU8::new(0),
            free: Mutex::new(Vec::new()),
        });
        tokio::spawn(read_loop(reader, Arc::clone(&session), tag.to_string()));
        Ok(session)
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn unreserve(&self) {
        let mut cur = self.reserved.load(Ordering::Acquire);
        while cur > 0 {
            match self.reserved.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// A buffer pre-sized to at least `min_len` for the next frame payload:
    /// recycled buffers retain their initialized length so `give_buf` + reuse
    /// never zeroes 32-64 KiB of memory before `read_exact` overwrites it.
    fn take_buf_sized(&self, min_len: usize) -> Vec<u8> {
        let mut buf = self.free.lock().expect("free").pop().unwrap_or_default();
        if buf.len() < min_len {
            buf.resize(min_len, 0);
        }
        buf
    }

    /// Hand a fully-read payload buffer back for reuse without clearing its
    /// initialized length.
    fn give_buf(&self, buf: Vec<u8>) {
        let mut free = self.free.lock().expect("free");
        if free.len() < 128 {
            free.push(buf);
        }
    }

    /// `SYN` a new stream and register its receive queue.
    #[allow(dead_code)]
    async fn open_stream(&self) -> io::Result<(u32, mpsc::Receiver<Vec<u8>>)> {
        self.open_stream_with_payload(&[]).await
    }

    /// `SYN` a new stream and optionally coalesce its initial `PSH` target
    /// frame into the same TLS write and flush.
    async fn open_stream_with_payload(
        &self,
        payload: &[u8],
    ) -> io::Result<(u32, mpsc::Receiver<Vec<u8>>)> {
        if !self.is_alive() {
            return Err(io::Error::other("anytls: session is closed"));
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        self.streams.lock().expect("streams").insert(sid, tx);
        let mut buf = Vec::with_capacity(
            FRAME_HEADER
                + if payload.is_empty() {
                    0
                } else {
                    FRAME_HEADER + payload.len()
                },
        );
        buf.push(CMD_SYN);
        buf.extend_from_slice(&sid.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        if !payload.is_empty() {
            buf.push(CMD_PSH);
            buf.extend_from_slice(&sid.to_be_bytes());
            buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            buf.extend_from_slice(payload);
        }
        let res = {
            let mut writer = self.writer.lock().await;
            match writer.write_all(&buf).await {
                Ok(()) => writer.flush().await,
                Err(e) => Err(e),
            }
        };
        if let Err(e) = res {
            self.streams.lock().expect("streams").remove(&sid);
            return Err(e);
        }
        Ok((sid, rx))
    }

    async fn write_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> io::Result<()> {
        let frame = encode_frame(cmd, sid, data);
        let mut writer = self.writer.lock().await;
        writer.write_all(&frame).await?;
        writer.flush().await
    }

    /// `PSH` payload, chunked to the frame length limit: one writer lock and
    /// one flush for the whole write, not one per frame.
    async fn send_data(&self, sid: u32, data: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        for chunk in data.chunks(MAX_FRAME_PAYLOAD) {
            let mut hdr = [0u8; FRAME_HEADER];
            hdr[0] = CMD_PSH;
            hdr[1..5].copy_from_slice(&sid.to_be_bytes());
            hdr[5..7].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            writer.write_all(&hdr).await?;
            writer.write_all(chunk).await?;
        }
        writer.flush().await
    }

    async fn send_fin(&self, sid: u32) -> io::Result<()> {
        self.write_frame(CMD_FIN, sid, &[]).await
    }

    /// Unregister a stream, without touching the wire.
    fn unregister(self: &Arc<Self>, sid: u32) {
        self.streams.lock().expect("streams").remove(&sid);
        self.unreserve();
    }

    /// Teardown from `Drop`, where awaiting is not possible: hand the `FIN`
    /// frame to a detached task (the stream is unregistered right away).
    fn close_stream(self: &Arc<Self>, sid: u32) {
        self.unregister(sid);
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let session = Arc::clone(self);
        tokio::spawn(async move {
            let _ = session.send_fin(sid).await;
        });
    }
}

/// Non-blocking poll to check if the next frame header is already buffered in
/// the TLS reader without waiting on the socket.
fn try_read_immediate(
    reader: &mut tokio::io::ReadHalf<AnyStream>,
    dst: &mut [u8],
) -> io::Result<usize> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut filled = 0;
    while filled < dst.len() {
        let mut rb = ReadBuf::new(&mut dst[filled..]);
        match Pin::new(&mut *reader).poll_read(&mut cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    break;
                }
                filled += n;
            }
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => break,
        }
    }
    Ok(filled)
}

/// Frame dispatch loop; exits when the TLS connection breaks.
async fn read_loop(mut reader: tokio::io::ReadHalf<AnyStream>, session: Arc<Session>, tag: String) {
    let mut header = [0u8; FRAME_HEADER];
    let mut hdr_filled = 0usize;
    let mut payload: Vec<u8> = vec![0u8; MAX_FRAME_PAYLOAD];
    let mut cached_stream: Option<(u32, mpsc::Sender<Vec<u8>>)> = None;
    'session: loop {
        if hdr_filled < FRAME_HEADER
            && let Err(e) = reader.read_exact(&mut header[hdr_filled..]).await
        {
            logging::debug(format_args!("anytls[{tag}]: session read: {e}"));
            break;
        }
        hdr_filled = 0;
        let (cmd, sid, len) = parse_header(&header);
        // a payload bound for a live stream reads straight into its recycled
        // buffer: the scratch copy below is only for frames nobody takes
        if cmd == CMD_PSH && len > 0 {
            let sender = match &cached_stream {
                Some((cached_sid, tx)) if *cached_sid == sid && !tx.is_closed() => Some(tx.clone()),
                _ => {
                    let tx = session.streams.lock().expect("streams").get(&sid).cloned();
                    if let Some(ref tx) = tx {
                        cached_stream = Some((sid, tx.clone()));
                    }
                    tx
                }
            };
            if let Some(sender) = sender {
                let mut buf = session.take_buf_sized(len.max(65536));
                if let Err(e) = reader.read_exact(&mut buf[..len]).await {
                    logging::debug(format_args!("anytls[{tag}]: session payload: {e}"));
                    break;
                }
                let mut filled_len = len;
                while filled_len <= 49152 {
                    let n = match try_read_immediate(&mut reader, &mut header) {
                        Ok(n) => n,
                        Err(e) => {
                            logging::debug(format_args!("anytls[{tag}]: session read: {e}"));
                            break 'session;
                        }
                    };
                    if n < FRAME_HEADER {
                        hdr_filled = n;
                        break;
                    }
                    let (cmd2, sid2, len2) = parse_header(&header);
                    if cmd2 != CMD_PSH || sid2 != sid || len2 == 0 || filled_len + len2 > 65536 {
                        hdr_filled = FRAME_HEADER;
                        break;
                    }
                    if buf.len() < filled_len + len2 {
                        buf.resize(filled_len + len2, 0);
                    }
                    if let Err(e) = reader
                        .read_exact(&mut buf[filled_len..filled_len + len2])
                        .await
                    {
                        logging::debug(format_args!("anytls[{tag}]: session payload: {e}"));
                        break 'session;
                    }
                    filled_len += len2;
                }
                buf.truncate(filled_len);
                if sender.send(buf).await.is_err() {
                    cached_stream = None;
                }
                continue;
            }
        }
        if len > payload.len() {
            payload.resize(len, 0);
        }
        if len > 0
            && let Err(e) = reader.read_exact(&mut payload[..len]).await
        {
            logging::debug(format_args!("anytls[{tag}]: session payload: {e}"));
            break;
        }
        match cmd {
            CMD_PSH => {
                if len == 0 {
                    continue;
                }
                let sender = session.streams.lock().expect("streams").get(&sid).cloned();
                if let Some(sender) = sender {
                    let mut buf = session.take_buf_sized(len);
                    buf[..len].copy_from_slice(&payload[..len]);
                    buf.truncate(len);
                    let _ = sender.send(buf).await;
                }
            }
            CMD_FIN => {
                if cached_stream.as_ref().is_some_and(|(id, _)| *id == sid) {
                    cached_stream = None;
                }
                session.unregister(sid);
            }
            // the server confirms (or rejects) stream setup for protocol v2
            CMD_SYNACK => {
                if len > 0 {
                    let message = String::from_utf8_lossy(&payload[..len]).into_owned();
                    logging::warn(format_args!(
                        "anytls[{tag}]: remote rejected stream: {message}"
                    ));
                    if cached_stream.as_ref().is_some_and(|(id, _)| *id == sid) {
                        cached_stream = None;
                    }
                    session.streams.lock().expect("streams").remove(&sid);
                }
            }
            CMD_HEART_REQUEST => {
                let _ = session.write_frame(CMD_HEART_RESPONSE, sid, &[]).await;
            }
            CMD_ALERT => {
                if len > 0 {
                    let message = String::from_utf8_lossy(&payload[..len]).into_owned();
                    logging::error(format_args!("anytls[{tag}]: alert from server: {message}"));
                }
                break;
            }
            CMD_SERVER_SETTINGS | CMD_SETTINGS => {
                if let Some(version) = settings_version(&payload[..len]) {
                    session.peer_version.store(version, Ordering::Relaxed);
                }
            }
            // padding records and scheme updates are shaping hints we ignore
            CMD_WASTE | CMD_UPDATE_PADDING | CMD_HEART_RESPONSE => {}
            _ => {}
        }
    }
    session.alive.store(false, Ordering::Release);
    session.streams.lock().expect("streams").clear();
}

/// One multiplexed stream, seen by the router as a plain byte pipe.
struct Stream {
    session: Arc<Session>,
    sid: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    pos: usize,
    /// in-flight write (frames are async), with its promised byte count
    write_fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    write_report: usize,
    fin_sent: bool,
}

impl Stream {
    fn new(session: Arc<Session>, sid: u32, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            session,
            sid,
            rx,
            pending: Vec::new(),
            pos: 0,
            write_fut: None,
            write_report: 0,
            fin_sent: false,
        }
    }

    /// Start the frame write for `data` and poll it to completion.
    fn poll_frame_write(
        &mut self,
        cx: &mut Context<'_>,
        data: Option<Vec<u8>>,
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_none() {
            let Some(data) = data else {
                return Poll::Ready(Ok(0));
            };
            self.write_report = data.len();
            let session = Arc::clone(&self.session);
            let sid = self.sid;
            self.write_fut = Some(Box::pin(async move {
                let result = session.send_data(sid, &data).await;
                // the payload buffer came from the pool; hand it back the
                // moment the bytes are on the wire
                session.give_buf(data);
                result
            }));
        }
        let result = {
            let fut = self.write_fut.as_mut().expect("future set above");
            fut.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.write_fut = None;
                let report = std::mem::take(&mut self.write_report);
                Poll::Ready(result.map(|()| report))
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos >= self.pending.len() {
            // fully read: recycle the buffer for the next dispatch
            let spent = std::mem::take(&mut self.pending);
            if !spent.is_empty() {
                self.session.give_buf(spent);
            }
            self.pos = 0;
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(chunk)) => {
                    self.pending = chunk;
                }
                // stream or session gone: EOF
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
        loop {
            let available = self.pending.len() - self.pos;
            let n = out.remaining().min(available);
            out.put_slice(&self.pending[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos < self.pending.len() || out.remaining() == 0 {
                break;
            }
            let spent = std::mem::take(&mut self.pending);
            if !spent.is_empty() {
                self.session.give_buf(spent);
            }
            self.pos = 0;
            match self.rx.try_recv() {
                Ok(chunk) => {
                    self.pending = chunk;
                }
                Err(_) => break,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_some() {
            // a previous write is still in flight; the caller retries later
            return self.poll_frame_write(cx, None);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // the same pool the read side uses: one alloc per connection, not
        // per write
        let mut owned = self.session.take_buf_sized(buf.len());
        owned[..buf.len()].copy_from_slice(buf);
        owned.truncate(buf.len());
        self.poll_frame_write(cx, Some(owned))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_fut.is_some() {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_sent {
            if self.write_fut.is_some() {
                return Poll::Pending;
            }
            self.fin_sent = true;
            let session = Arc::clone(&self.session);
            let sid = self.sid;
            self.write_fut = Some(Box::pin(async move { session.send_fin(sid).await }));
        }
        if self.write_fut.is_some() {
            let result = {
                let fut = self.write_fut.as_mut().expect("future set above");
                fut.as_mut().poll(cx)
            };
            match result {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    self.write_fut = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    return Poll::Ready(Err(e));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.fin_sent {
            // the FIN is already on the wire: just unregister so the session
            // goes back to the pool
            self.session.unregister(self.sid);
        } else {
            self.session.close_stream(self.sid);
        }
        let spent = std::mem::take(&mut self.pending);
        if !spent.is_empty() {
            self.session.give_buf(spent);
        }
    }
}

impl std::fmt::Debug for AnyTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTls")
            .field("tag", &self.tag)
            .field("server", &self.server)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

pub struct AnyTls {
    tag: String,
    server: String,
    port: u16,
    tls: TlsOptions,
    password_sha256: [u8; 32],
    client_metadata: Option<String>,
    /// live sessions, at most `MAX_SESSIONS`: each takes streams once the
    /// cap turns fresh dials into sharing (a single session serializes every
    /// stream through one read loop and one TCP flow)
    sessions: Mutex<Vec<Arc<Session>>>,
    dial: crate::outbound::dial::DialOptions,
}

impl AnyTls {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let Some(tls) = TlsOptions::from_outbound(obj, &server, at)? else {
            anyhow::bail!("{at}: anytls outbound requires tls");
        };
        if obj
            .get("tcp_fast_open")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            anyhow::bail!("{at}: tcp_fast_open is not supported with anytls outbound");
        }
        for field in POOL_FIELDS {
            if obj.get(*field).is_some_and(|value| !value.is_null()) {
                logging::warn(format_args!(
                    "anytls outbound {at}: {field} only shapes the reference session pool (ignored)"
                ));
            }
        }
        let password_sha256 = Sha256::digest(
            obj.get("password")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes(),
        )
        .into();
        let client_metadata = obj
            .get("client_metadata")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        Ok(Self {
            tag: at.to_string(),
            server,
            port,
            tls,
            password_sha256,
            client_metadata,
            sessions: Mutex::new(Vec::new()),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    /// A session for the next stream: reuse any idle session first, open a
    /// dedicated session while below `MAX_SESSIONS`, and share the
    /// least-loaded live session once at the cap.
    async fn session(&self) -> io::Result<Arc<Session>> {
        let shared = {
            let mut pool = self.sessions.lock().expect("sessions");
            pool.retain(|s| s.is_alive());
            if let Some(idle) = pool
                .iter()
                .find(|s| s.reserved.load(Ordering::Acquire) == 0)
                .cloned()
            {
                idle.reserved.fetch_add(1, Ordering::AcqRel);
                Some(idle)
            } else if pool.len() >= MAX_SESSIONS {
                let best = pool
                    .iter()
                    .min_by_key(|s| s.reserved.load(Ordering::Acquire))
                    .cloned();
                if let Some(s) = &best {
                    s.reserved.fetch_add(1, Ordering::AcqRel);
                }
                best
            } else {
                None
            }
        };
        if let Some(session) = shared {
            return Ok(session);
        }
        let session = Session::open(
            &self.server,
            self.port,
            &self.tls,
            &self.password_sha256,
            self.client_metadata.as_deref(),
            &self.tag,
            &self.dial,
        )
        .await?;
        session.reserved.store(1, Ordering::Release);
        let mut pool = self.sessions.lock().expect("sessions");
        pool.retain(|s| s.is_alive());
        pool.push(Arc::clone(&session));
        Ok(session)
    }

    /// Drop a session from the pool so the next dial builds a fresh one.
    async fn invalidate(&self, session: &Arc<Session>) {
        self.sessions
            .lock()
            .expect("sessions")
            .retain(|current| !Arc::ptr_eq(current, session));
    }

    /// One multiplexed stream carrying `address` as its first payload.
    async fn open_stream(&self, session: &Arc<Session>, address: &Target) -> io::Result<AnyStream> {
        let target_bytes = match encode_target(address) {
            Ok(b) => b,
            Err(e) => {
                session.unreserve();
                return Err(e);
            }
        };
        let (sid, rx) = match session.open_stream_with_payload(&target_bytes).await {
            Ok(v) => v,
            Err(e) => {
                session.unreserve();
                return Err(e);
            }
        };
        Ok(Box::new(Stream::new(Arc::clone(session), sid, rx)))
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.session().await?;
            match self.open_stream(&session, target).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    self.invalidate(&session).await;
                    last_error = Some(e);
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("anytls: dial failed")))
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        let (local, peer) = udp_loopback_pair().await?;
        let session = self.session().await?;
        // uot: the stream targets the reserved magic address, the real
        // destination travels in the request header
        let magic = Target::Domain(UOT_MAGIC.to_string(), 0);
        let mut init_payload = match encode_target(&magic) {
            Ok(b) => b,
            Err(e) => {
                session.unreserve();
                return Err(e);
            }
        };
        match request_header(true, target) {
            Ok(hdr) => init_payload.extend_from_slice(&hdr),
            Err(e) => {
                session.unreserve();
                return Err(e);
            }
        }
        let (sid, rx) = match session.open_stream_with_payload(&init_payload).await {
            Ok(v) => v,
            Err(e) => {
                session.unreserve();
                return Err(e);
            }
        };
        let stream = Stream::new(Arc::clone(&session), sid, rx);
        spawn_bridge(Box::new(stream), peer);
        Ok(local)
    }

    /// Magic authority helper kept next to its users for readability.
    #[allow(dead_code)]
    fn uot_authority(version: u8) -> String {
        magic_authority(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpStream;

    fn obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "anytls",
            "tag": "at",
            "server": "example.com",
            "server_port": 8443,
            "password": "secret",
            "tls": {"enabled": true, "server_name": "example.com"},
        });
        let map = base.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("object") {
            map.insert(key.clone(), value.clone());
        }
        map.clone()
    }

    #[test]
    fn build_requires_tls_and_rejects_tfo() {
        let mut map = obj(json!({}));
        map.remove("tls");
        assert_eq!(
            AnyTls::build(&map, "outbounds[0]").unwrap_err().to_string(),
            "outbounds[0]: anytls outbound requires tls"
        );
        assert_eq!(
            AnyTls::build(&obj(json!({"tcp_fast_open": true})), "at")
                .unwrap_err()
                .to_string(),
            "at: tcp_fast_open is not supported with anytls outbound"
        );
    }

    #[test]
    fn build_hashes_password_and_keeps_metadata() {
        let anytls = AnyTls::build(
            &obj(json!({"client_metadata": "curl/8", "min_idle_session": 3})),
            "at",
        )
        .expect("build");
        assert_eq!(
            anytls.password_sha256,
            <[u8; 32]>::from(Sha256::digest(b"secret")),
            "password is hashed with sha256"
        );
        assert_eq!(anytls.client_metadata.as_deref(), Some("curl/8"));
        assert_eq!(anytls.port, 8443);
    }

    #[test]
    fn frames_match_the_wire_layout() {
        let frame = encode_frame(CMD_PSH, 0x0102_0304, &[1, 2, 3]);
        assert_eq!(frame, vec![2, 1, 2, 3, 4, 0, 3, 1, 2, 3]);
        let (cmd, sid, len) = parse_header(&frame[..FRAME_HEADER].try_into().expect("header"));
        assert_eq!((cmd, sid, len), (CMD_PSH, 0x0102_0304, 3));
        // control frames carry no payload
        let syn = encode_frame(CMD_SYN, 1, &[]);
        assert_eq!(syn, vec![1, 0, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn settings_payload_and_version() {
        let payload = settings_payload(None);
        let text = String::from_utf8(payload.clone()).expect("utf8");
        assert!(text.contains("v=2"), "{text}");
        assert!(text.contains("client=tachyon-core/anytls"), "{text}");
        assert_eq!(settings_version(&payload), Some(2));
        let custom = settings_payload(Some("curl/8"));
        assert!(
            String::from_utf8(custom.clone())
                .expect("utf8")
                .contains("client=curl/8")
        );
        assert_eq!(settings_version(b"v=1\nclient=x"), Some(1));
        assert_eq!(settings_version(b"client=x"), None);
    }

    #[test]
    fn uot_authority_matches_the_reference() {
        assert_eq!(AnyTls::uot_authority(2), "sp.v2.udp-over-tcp.arpa:0");
        assert_eq!(AnyTls::uot_authority(1), "sp.udp-over-tcp.arpa:0");
    }

    /// End-to-end session test against an in-process mock anytls server:
    /// greeting, settings, SYN/PSH/FIN exchange and the reader loop.
    #[tokio::test]
    async fn session_streams_carry_payload_and_fin() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.expect("accept");
            // greeting: sha256(password) + padding length
            let mut greeting = [0u8; 34];
            conn.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(&greeting[..32], &Sha256::digest(b"secret")[..]);
            assert_eq!(&greeting[32..], &[0, 0]);
            // settings frame
            let mut header = [0u8; FRAME_HEADER];
            conn.read_exact(&mut header).await.expect("settings header");
            let (cmd, sid, len) = parse_header(&header);
            assert_eq!((cmd, sid), (CMD_SETTINGS, 0));
            let mut payload = vec![0u8; len];
            conn.read_exact(&mut payload)
                .await
                .expect("settings payload");
            assert_eq!(settings_version(&payload), Some(2));
            // server settings (v2) so the client records the peer version
            conn.write_all(&encode_frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
                .await
                .expect("server settings");
            // SYN, then the destination payload
            conn.read_exact(&mut header).await.expect("syn header");
            let (cmd, sid, len) = parse_header(&header);
            assert_eq!(cmd, CMD_SYN);
            assert_eq!(len, 0);
            conn.read_exact(&mut header).await.expect("psh header");
            let (cmd, payload_sid, len) = parse_header(&header);
            assert_eq!((cmd, payload_sid), (CMD_PSH, sid));
            let mut address = vec![0u8; len];
            conn.read_exact(&mut address).await.expect("address");
            // socks5-style: 0x03 len host port
            assert_eq!(address[0], 0x03);
            assert_eq!(&address[2..2 + address[1] as usize], b"example.com");
            // echo one chunk back, then close the stream
            conn.write_all(&encode_frame(CMD_PSH, sid, b"pong"))
                .await
                .expect("echo");
            conn.read_exact(&mut header).await.expect("fin header");
            let (cmd, fin_sid, len) = parse_header(&header);
            assert_eq!((cmd, fin_sid, len), (CMD_FIN, sid, 0));
            conn.write_all(&encode_frame(CMD_FIN, sid, &[]))
                .await
                .expect("fin back");
            sid
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let session = Session::establish(
            Box::new(client),
            &<[u8; 32]>::from(Sha256::digest(b"secret")),
            None,
            "test",
        )
        .await
        .expect("session");
        let (sid, _rx) = session.open_stream().await.expect("open stream");
        assert_eq!(sid, 1);
        let mut stream = Stream::new(Arc::clone(&session), sid, _rx);
        let address =
            encode_target(&Target::Domain("example.com".to_string(), 80)).expect("address");
        stream.write_all(&address).await.expect("write address");
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.expect("read echo");
        assert_eq!(&buf[..n], b"pong");
        stream.shutdown().await.expect("shutdown");
        assert_eq!(server.await.expect("server task"), 1);
    }

    #[tokio::test]
    async fn dead_session_refuses_new_streams() {
        let (client, server) = tokio::io::duplex(1024);
        let session = Session::establish(Box::new(client), &[0u8; 32], None, "test")
            .await
            .expect("session");
        drop(server);
        // the reader notices the closed transport and marks the session dead
        for _ in 0..50 {
            if !session.is_alive() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!session.is_alive(), "session should be dead");
        let err = session.open_stream().await.unwrap_err();
        assert_eq!(err.to_string(), "anytls: session is closed");
    }
}
