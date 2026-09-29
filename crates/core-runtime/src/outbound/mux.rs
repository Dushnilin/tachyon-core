//! Mux.Cool multiplexing over a vmess stream (reference `sing-mux`).
//!
//! The session is a CONNECT request to the magic destination
//! `sp.mux.sing-box.arpa:444`, in front of which sits the protocol handshake
//! `[version][protocol]`, and each multiplexed stream is another CONNECT whose
//! body is the tunnel. A stream's own request `[version][flags][addr][port]`
//! and the one-byte response are handled transparently.
//!
//! Only `h2mux` (the reference default) is implemented; `smux` and `yamux` are
//! separate session formats and are refused rather than half-emulated.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

use crate::inbound::{AnyStream, Target};

/// `mux.Destination`
pub const MUX_DESTINATION: &str = "sp.mux.sing-box.arpa";
const MUX_PORT: u16 = 444;

const PROTOCOL_H2MUX: u8 = 2;
const PROTOCOL_SMUX: u8 = 0;
const PROTOCOL_YAMUX: u8 = 1;

const VERSION0: u8 = 0;

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;
const STATUS_SUCCESS: u8 = 0;

/// `padConn` writes this many padded frames before going plain.
const FIRST_PADDINGS: u32 = 16;
const TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Default)]
pub struct MuxOptions {
    pub protocol: String,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
}

impl MuxOptions {
    /// `option.MultiplexOptions`; the reference defaults `min_streams` to 8
    /// when neither stream nor connection count is bounded.
    pub fn parse(value: &serde_json::Value, at: &str) -> anyhow::Result<Self> {
        let Some(map) = value.as_object() else {
            anyhow::bail!("{at}: multiplex must be an object");
        };
        if map.get("enabled").and_then(serde_json::Value::as_bool) != Some(true) {
            return Ok(Self::default());
        }
        let protocol = map
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        if !matches!(protocol.as_str(), "" | "h2mux" | "smux" | "yamux") {
            anyhow::bail!("{at}: unknown protocol: {protocol}");
        }
        let number = |name: &str| -> usize {
            map.get(name)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize
        };
        let max_connections = number("max_connections");
        let min_streams = number("min_streams");
        let max_streams = number("max_streams");
        let min_streams = if max_streams == 0 && max_connections == 0 && min_streams == 0 {
            8
        } else {
            min_streams
        };
        Ok(Self {
            protocol,
            max_connections,
            min_streams,
            max_streams,
            padding: map
                .get("padding")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }

    fn protocol_id(&self) -> anyhow::Result<u8> {
        match self.protocol.as_str() {
            "" | "h2mux" => Ok(PROTOCOL_H2MUX),
            "smux" => Ok(PROTOCOL_SMUX),
            "yamux" => Ok(PROTOCOL_YAMUX),
            other => anyhow::bail!("unknown protocol: {other}"),
        }
    }
}

/// How a new session is dialled: the vmess outbound hands over a closure that
/// opens the underlying stream to the magic destination.
pub type Dialer = dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<AnyStream>> + Send>>
    + Send
    + Sync;

/// One multiplexed stream, seen by the router as a plain byte pipe.
pub struct MuxStream {
    inner: AnyStream,
    /// the stream request goes out with the first write
    request: Option<Vec<u8>>,
    /// the one-byte response is consumed on the first read
    response_pending: bool,
    buf: BytesMut,
    eof: bool,
    client: Arc<Client>,
    session: Arc<Session>,
    /// keeps the shared connection task alive for as long as the stream is
    _conn_task: Arc<ConnectionTask>,
}

impl MuxStream {
    fn new(
        inner: AnyStream,
        request: Vec<u8>,
        client: Arc<Client>,
        session: Arc<Session>,
        conn_task: Arc<ConnectionTask>,
    ) -> Self {
        Self {
            inner,
            request: Some(request),
            response_pending: true,
            buf: BytesMut::new(),
            eof: false,
            client,
            session,
            _conn_task: conn_task,
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.response_pending {
                let mut status = [0u8; 1];
                match std::pin::Pin::new(&mut this.inner)
                    .poll_read(cx, &mut ReadBuf::new(&mut status))
                {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => {
                        return std::task::Poll::Ready(Err(e));
                    }
                    std::task::Poll::Ready(Ok(())) => {
                        if status[0] != STATUS_SUCCESS {
                            // the reference reads a varbin message here and
                            // only puts it in the error text
                            return std::task::Poll::Ready(Err(io::Error::other(
                                "mux: remote error",
                            )));
                        }
                        this.response_pending = false;
                    }
                }
            }
            if !this.buf.is_empty() {
                let n = out.remaining().min(this.buf.len());
                out.put_slice(&this.buf[..n]);
                this.buf.advance(n);
                return std::task::Poll::Ready(Ok(()));
            }
            if this.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 8192];
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut ReadBuf::new(&mut scratch))
            {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(())) => {
                    let filled = scratch
                        .iter()
                        .position(|byte| *byte != 0)
                        .unwrap_or(scratch.len());
                    let filled = filled.max(usize::from(scratch.iter().any(|b| *b != 0)));
                    if filled == 0 {
                        this.eof = true;
                    } else {
                        this.buf.extend_from_slice(&scratch[..filled]);
                    }
                }
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Some(request) = this.request.take() {
            // the request rides in front of the first write, like the reference
            let mut first = request.clone();
            first.extend_from_slice(buf);
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &first) {
                std::task::Poll::Ready(Ok(_)) => {
                    return std::task::Poll::Ready(Ok(buf.len()));
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => {
                    this.request = Some(request);
                    return std::task::Poll::Pending;
                }
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.client.release(&self.session);
    }
}

/// One h2 session plus its live stream count.
struct Session {
    /// h2 needs `&mut` to open a stream, so the client handle is behind a lock
    send: Mutex<h2::client::SendRequest<Bytes>>,
    /// the task is shared by every stream of the session, so the last stream to
    /// go closes it
    conn_task: Arc<ConnectionTask>,
    streams: AtomicU32,
    closed: AtomicBool,
}

/// Aborts the h2 connection task when the last reference goes away.
struct ConnectionTask(Option<tokio::task::JoinHandle<()>>);

impl ConnectionTask {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

impl Session {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// `padConn`: the first [`FIRST_PADDINGS`] frames carry
/// `[data_len:u16][pad_len:u16][data][pad]`, then the stream goes plain.
struct PadStream {
    inner: AnyStream,
    write_padding: u32,
    read_padding: u32,
    /// bytes of the current frame's data still to hand out
    read_remaining: usize,
    /// padding bytes of the current frame still to skip
    padding_remaining: usize,
}

impl PadStream {
    fn new(inner: AnyStream) -> Self {
        Self {
            inner,
            write_padding: 0,
            read_padding: 0,
            read_remaining: 0,
            padding_remaining: 0,
        }
    }

    /// 256..=767 random bytes, like the reference.
    fn pad_len() -> usize {
        256 + random_below(512)
    }
}

impl AsyncRead for PadStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.read_remaining > 0 {
                let n = out.remaining().min(this.read_remaining);
                let mut scratch = vec![0u8; n];
                match std::pin::Pin::new(&mut this.inner)
                    .poll_read(cx, &mut ReadBuf::new(&mut scratch))
                {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {
                        let filled = scratch.iter().position(|byte| *byte != 0).unwrap_or(n);
                        if filled == 0 {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        out.put_slice(&scratch[..filled]);
                        this.read_remaining -= filled;
                        return std::task::Poll::Ready(Ok(()));
                    }
                }
            }
            if this.padding_remaining > 0 {
                let mut scratch = vec![0u8; this.padding_remaining.min(4096)];
                match std::pin::Pin::new(&mut this.inner)
                    .poll_read(cx, &mut ReadBuf::new(&mut scratch))
                {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {
                        let filled = scratch.len();
                        if filled == 0 {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        this.padding_remaining -= filled;
                    }
                }
                continue;
            }
            if this.read_padding >= FIRST_PADDINGS {
                return std::pin::Pin::new(&mut this.inner).poll_read(cx, out);
            }
            let mut header = [0u8; 4];
            let mut filled = 0;
            while filled < header.len() {
                let mut scratch = [0u8; 1];
                match std::pin::Pin::new(&mut this.inner)
                    .poll_read(cx, &mut ReadBuf::new(&mut scratch))
                {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {
                        if scratch[0] == 0 {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        header[filled] = scratch[0];
                        filled += 1;
                    }
                }
            }
            this.read_padding += 1;
            this.read_remaining = usize::from(u16::from_be_bytes([header[0], header[1]]));
            this.padding_remaining = usize::from(u16::from_be_bytes([header[2], header[3]]));
        }
    }
}

impl AsyncWrite for PadStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.write_padding >= FIRST_PADDINGS {
            return std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let pad = Self::pad_len();
        let mut frame = Vec::with_capacity(4 + buf.len() + pad);
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(pad as u16).to_be_bytes());
        frame.extend_from_slice(buf);
        frame.resize(4 + buf.len() + pad, 0);
        this.write_padding += 1;
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &frame) {
            std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(Ok(buf.len())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => {
                // the frame is gone; the count stays advanced, like the
                // reference, which also counts before the write lands
                std::task::Poll::Pending
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The multiplexed client: a session pool over the vmess stream.
pub struct Client {
    options: MuxOptions,
    /// `packet_encoding: packetaddr` names the destination per datagram
    packet_addr: bool,
    /// dials the underlying stream, used to open a new session
    dialer: Mutex<Option<Arc<Dialer>>>,
    sessions: Mutex<Vec<Arc<Session>>>,
}

impl Client {
    pub fn new(options: MuxOptions, packet_addr: bool) -> anyhow::Result<Arc<Self>> {
        options.protocol_id()?;
        Ok(Arc::new(Self {
            options,
            packet_addr,
            dialer: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
        }))
    }

    /// The vmess outbound hands over how to open the underlying stream.
    pub async fn set_dialer(&self, dialer: Arc<Dialer>) {
        *self.dialer.lock().await = Some(dialer);
    }

    pub async fn has_dialer(&self) -> bool {
        self.dialer.lock().await.is_some()
    }

    /// `Client.openStream`: pick a session, or open one.
    pub async fn open(self: &Arc<Self>, target: &Target) -> io::Result<MuxStream> {
        if self.options.protocol != "h2mux" && !self.options.protocol.is_empty() {
            return Err(io::Error::other(format!(
                "vmess: multiplex protocol {:?} is not supported",
                self.options.protocol
            )));
        }
        let mut guard = self.sessions.lock().await;
        guard.retain(|session| !session.is_closed());
        let picked = self.select_session(&guard);
        let session = match picked {
            Some(session) => session,
            None => self.open_session(&mut guard).await?,
        };
        session.streams.fetch_add(1, Ordering::SeqCst);
        let conn_task = Arc::clone(&session.conn_task);

        let request = http::Request::builder()
            .method("CONNECT")
            .uri(format!(
                "https://{}",
                crate::outbound::quic::dest_string(target)
            ))
            .header("version", VERSION0.to_string())
            .body(())
            .map_err(|e| io::Error::other(format!("vmess: mux request: {e}")))?;
        let (response, send) = session
            .send
            .lock()
            .await
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("vmess: mux send: {e}")))?;
        let stream: AnyStream = Box::new(crate::outbound::transport::h2io::H2Io {
            h2: crate::outbound::transport::h2io::H2Stream::shared(response, send),
        });
        let stream = if self.options.padding {
            Box::new(PadStream::new(stream)) as AnyStream
        } else {
            stream
        };
        Ok(MuxStream::new(
            stream,
            encode_stream_request(target, self.packet_addr),
            Arc::clone(self),
            session,
            conn_task,
        ))
    }

    /// `Client.selectSession`
    fn select_session(&self, sessions: &[Arc<Session>]) -> Option<Arc<Session>> {
        let session = sessions
            .iter()
            .filter(|session| {
                // h2 reports the flow-control window; a closed one cannot take
                // more work
                !session.is_closed()
            })
            .min_by_key(|session| session.streams.load(Ordering::SeqCst))?;
        let streams = session.streams.load(Ordering::SeqCst);
        if streams == 0 {
            return Some(Arc::clone(session));
        }
        if self.options.max_connections > 0 {
            if sessions.len() >= self.options.max_connections
                || (streams as usize) < self.options.min_streams
            {
                return Some(Arc::clone(session));
            }
        } else if self.options.max_streams > 0 && (streams as usize) < self.options.max_streams {
            return Some(Arc::clone(session));
        }
        None
    }

    async fn open_session(&self, guard: &mut Vec<Arc<Session>>) -> io::Result<Arc<Session>> {
        let dialer = {
            let transport = self.dialer.lock().await;
            transport.clone()
        }
        .ok_or_else(|| io::Error::other("vmess: multiplex has no transport"))?;
        let stream = dialer().await?;
        let mut stream: AnyStream = stream;
        // the session handshake rides in front of the h2 preface
        let mut request = vec![VERSION0, PROTOCOL_H2MUX];
        if self.options.padding {
            request.push(1);
            let pad = 256 + random_below(512);
            request.extend_from_slice(&(pad as u16).to_be_bytes());
            request.resize(request.len() + pad, 0);
        }
        stream.write_all(&request).await?;

        let (send_request, connection) =
            tokio::time::timeout(TCP_TIMEOUT, h2::client::handshake(stream))
                .await
                .map_err(|_| io::Error::other("vmess: mux h2 handshake timeout"))?
                .map_err(|e| io::Error::other(format!("vmess: mux h2 handshake: {e}")))?;
        let conn_task = Arc::new(ConnectionTask::new(tokio::spawn(async move {
            let _ = connection.await;
        })));
        let session = Arc::new(Session {
            send: Mutex::new(
                send_request
                    .ready()
                    .await
                    .map_err(|e| io::Error::other(format!("vmess: mux h2 ready: {e}")))?,
            ),
            conn_task,
            streams: AtomicU32::new(0),
            closed: AtomicBool::new(false),
        });
        guard.push(Arc::clone(&session));
        Ok(session)
    }

    fn release(&self, session: &Arc<Session>) {
        session.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `EncodeStreamRequest`; a packetaddr stream names the mux magic address
/// instead of the real one, so the server can demultiplex by destination.
fn encode_stream_request(target: &Target, packet_addr: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 24);
    out.push(VERSION0);
    let mut flags = FLAG_UDP;
    if packet_addr {
        flags |= FLAG_ADDR;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    let named = if packet_addr {
        mux_target()
    } else {
        target.clone()
    };
    out.extend_from_slice(&crate::outbound::packet::put_addr_port_bytes(&named));
    out
}

fn random_below(limit: usize) -> usize {
    if limit <= 1 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    (u64::from_le_bytes(bytes) % limit as u64) as usize
}

/// The address the session is opened against.
pub fn mux_target() -> Target {
    let _ = MUX_PORT;
    Target::Domain(MUX_DESTINATION.to_string(), MUX_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_to_eight_streams_per_session() {
        let options = MuxOptions::parse(&serde_json::json!({"enabled": true}), "at").expect("ok");
        assert_eq!(options.min_streams, 8);
        assert_eq!(options.protocol, "");
        assert!(!options.padding);
        assert_eq!(options.protocol_id().expect("h2mux"), PROTOCOL_H2MUX);
    }

    #[test]
    fn an_explicit_bound_replaces_the_default() {
        let options = MuxOptions::parse(
            &serde_json::json!({"enabled": true, "max_streams": 4}),
            "at",
        )
        .expect("ok");
        assert_eq!(options.max_streams, 4);
        assert_eq!(options.min_streams, 0);
    }

    #[test]
    fn disabled_multiplex_carries_nothing() {
        let options = MuxOptions::parse(&serde_json::json!({"enabled": false}), "at").expect("ok");
        assert_eq!(options.min_streams, 0);
        assert_eq!(options.max_connections, 0);
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        let err = MuxOptions::parse(
            &serde_json::json!({"enabled": true, "protocol": "mptcp"}),
            "at",
        )
        .map(|_| ())
        .expect_err("unknown protocol")
        .to_string();
        assert!(err.contains("unknown protocol: mptcp"), "got {err}");
        assert_eq!(
            MuxOptions::parse(
                &serde_json::json!({"enabled": true, "protocol": "smux"}),
                "at"
            )
            .expect("ok")
            .protocol_id()
            .expect("smux"),
            PROTOCOL_SMUX
        );
    }

    #[test]
    fn the_stream_request_names_the_destination() {
        let target = Target::Domain("example.com".into(), 443);
        let request = encode_stream_request(&target, false);
        assert_eq!(request[0], VERSION0);
        assert_eq!(u16::from_be_bytes([request[1], request[2]]), FLAG_UDP);
        assert_eq!(&request[3..5], &[0x02, 11], "domain with its length");
        assert_eq!(&request[5..16], b"example.com");
        assert_eq!(&request[16..], &443u16.to_be_bytes());

        // a packetaddr stream names the mux magic address instead
        let request = encode_stream_request(&target, true);
        assert_eq!(
            u16::from_be_bytes([request[1], request[2]]),
            FLAG_UDP | FLAG_ADDR
        );
        assert_eq!(
            &request[3..5],
            &[0x02, 20],
            "the magic name's length: {}",
            MUX_DESTINATION
        );
        assert_eq!(&request[5..25], b"sp.mux.sing-box.arpa");
    }

    #[tokio::test]
    async fn smux_and_yamux_are_refused_rather_than_half_done() {
        let options = MuxOptions::parse(
            &serde_json::json!({"enabled": true, "protocol": "yamux"}),
            "at",
        )
        .expect("ok");
        let client = Client::new(options, false).expect("client");
        let err = match client
            .open(&Target::Domain("example.com".into(), 443))
            .await
        {
            Ok(_) => panic!("yamux is not implemented and must say so"),
            Err(error) => error.to_string(),
        };
        assert!(err.contains("not supported"), "got {err}");
    }
}
