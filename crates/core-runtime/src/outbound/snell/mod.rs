//! snell outbound: record tunnel over argon2-derived AES-128-GCM with
//! optional HTTP/TLS obfs and connection reuse (reference sing-snell
//! `snellv4` client: eager request record, reply on connect, zero-chunk EOF)
//! plus the v6 framing modes (`unsafe-raw`, `unshaped`, profile-shaped
//! `default`) sharing the same request/reply protocol.

mod crypto;
mod obfs;
mod pool;
mod profile;
mod record;
mod request;
mod v6;

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::proxy::server_endpoint;
use crate::outbound::quic::udp_loopback_pair;

use self::crypto::MAX_PAYLOAD_LEN;
use self::obfs::{ObfsMode, ObfsStream, parse_obfs_mode};
use self::pool::{Pool, Session};
use self::profile::Profile;
use self::record::{RecordReader, RecordWriter, now_unix, poll_flush};
use self::request::{
    ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6, CMD_CONNECT_V2, CMD_UDP, UDP_FORWARD, parse_reply,
    read_udp_response_address, write_request, write_udp_request_address,
};
use self::v6::{MAX_PAYLOAD_V6, Mode, V6Reader, V6Writer, parse_mode};

type BoxedObfs = ObfsStream<AnyStream>;
type ObfsWrite = tokio::io::WriteHalf<BoxedObfs>;
type ObfsRead = tokio::io::ReadHalf<BoxedObfs>;
type SnellWriter = WriterLayer<ObfsWrite>;
type SnellReader = ReaderLayer<ObfsRead>;
type SharedSession = Arc<Session<ObfsWrite, ObfsRead>>;
type SnellPool = Pool<ObfsWrite, ObfsRead>;

/// Version-dispatching record writer: v4 `RecordWriter` or v6 `V6Writer`
/// (the pool and stream plumbing stay mode-agnostic).
pub(crate) enum WriterLayer<W> {
    V4(RecordWriter<W>),
    V6(V6Writer<W>),
}

impl<W> WriterLayer<W> {
    fn emit(&mut self, now_unix: i64, data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        match self {
            Self::V4(writer) => writer.emit(now_unix, data),
            Self::V6(writer) => writer.emit(now_unix, data),
        }
    }

    fn emit_packet(&mut self, now_unix: i64, data: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::V4(writer) => writer.emit_packet(now_unix, data),
            Self::V6(writer) => writer.emit_packet(now_unix, data),
        }
    }
}

impl<W: AsyncWrite + Unpin> WriterLayer<W> {
    async fn write_all(&mut self, records: Vec<Vec<u8>>) -> io::Result<()> {
        match self {
            Self::V4(writer) => writer.write_all(records).await,
            Self::V6(writer) => writer.write_all(records).await,
        }
    }

    fn inner_mut(&mut self) -> &mut W {
        match self {
            Self::V4(writer) => &mut writer.inner,
            Self::V6(writer) => writer.inner_mut(),
        }
    }
}

/// Version-dispatching record reader (see `WriterLayer`).
pub(crate) enum ReaderLayer<R> {
    V4(RecordReader<R>),
    V6(V6Reader<R>),
}

impl<R: AsyncRead + Unpin> ReaderLayer<R> {
    fn poll_read_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        match self {
            Self::V4(reader) => reader.poll_read_record(cx),
            Self::V6(reader) => reader.poll_read_record(cx),
        }
    }

    async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::V4(reader) => reader.read_record().await,
            Self::V6(reader) => reader.read_record().await,
        }
    }
}

/// snell outbound (reference `snellv4.Client`/`snellv6.Client` +
/// `option.SnellOutboundOptions`).
pub struct Snell {
    server: String,
    port: u16,
    psk: Vec<u8>,
    user_key: Vec<u8>,
    want_tcp: bool,
    want_udp: bool,
    obfs_mode: ObfsMode,
    obfs_host: String,
    version: u8,
    mode: Mode,
    profile: Option<Arc<Profile>>,
    pool: Option<Arc<SnellPool>>,
    dial: crate::outbound::dial::DialOptions,
}

impl Snell {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;

        let version = match obj.get("version") {
            Some(Value::Number(n)) => n
                .as_i64()
                .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
                .unwrap_or(0),
            _ => 0,
        };
        match version {
            0 => anyhow::bail!("{at}: snell: missing version"),
            4 | 6 => {}
            v => anyhow::bail!("{at}: snell: unsupported version: {v}"),
        }

        let psk = obj.get("psk").and_then(Value::as_str).unwrap_or("");
        if psk.is_empty() {
            anyhow::bail!("{at}: snell: missing pre-shared key");
        }
        let user_key = obj.get("userkey").and_then(Value::as_str).unwrap_or("");
        if user_key.len() > 255 {
            anyhow::bail!("{at}: snell: user key too long");
        }

        // Version-scoped options (reference `option.SnellOutboundOptions`
        // `UnmarshallExcluded`): v4 reads obfs fields and ignores `mode`,
        // v6 reads `mode` and ignores the obfs fields entirely.
        let (obfs_mode, obfs_host, mode, profile) = if version == 6 {
            let raw_mode = obj.get("mode").and_then(Value::as_str).unwrap_or("");
            let mode = parse_mode(raw_mode)
                .ok_or_else(|| anyhow::anyhow!("{at}: snell: unknown v6 mode: {raw_mode}"))?;
            // The shaping profile only exists for the default mode
            // (reference `snellv6.NewClient`).
            let profile = if mode == Mode::Default {
                let profile =
                    Profile::new(psk.as_bytes()).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
                Some(Arc::new(profile))
            } else {
                None
            };
            (ObfsMode::None, String::new(), mode, profile)
        } else {
            let raw_mode = obj.get("obfs_mode").and_then(Value::as_str).unwrap_or("");
            let obfs_mode = parse_obfs_mode(raw_mode)
                .ok_or_else(|| anyhow::anyhow!("{at}: snell: unknown obfs mode: {raw_mode}"))?;
            let obfs_host = obj
                .get("obfs_host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            (obfs_mode, obfs_host, Mode::Default, None)
        };
        let reuse = obj.get("reuse").and_then(Value::as_bool).unwrap_or(false);
        let (want_tcp, want_udp) = network_flags(obj);

        Ok(Self {
            server,
            port,
            psk: psk.as_bytes().to_vec(),
            user_key: user_key.as_bytes().to_vec(),
            want_tcp,
            want_udp,
            obfs_mode,
            obfs_host,
            version: version as u8,
            mode,
            profile,
            pool: reuse.then(SnellPool::new),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    async fn dial_halves(&self) -> io::Result<(SnellWriter, SnellReader)> {
        let tcp = crate::outbound::dial::connect_tcp(&self.server, self.port, &self.dial).await?;
        let obfs = BoxedObfs::new(Box::new(tcp), self.obfs_mode, &self.obfs_host, "/");
        let (reader, writer) = tokio::io::split(obfs);
        Ok(if self.version == 6 {
            (
                WriterLayer::V6(V6Writer::new(
                    writer,
                    self.mode,
                    &self.psk,
                    self.profile.clone(),
                )),
                ReaderLayer::V6(V6Reader::new(
                    reader,
                    self.mode,
                    &self.psk,
                    self.profile.clone(),
                )),
            )
        } else {
            (
                WriterLayer::V4(RecordWriter::new(writer, &self.psk)),
                ReaderLayer::V4(RecordReader::new(reader, &self.psk)),
            )
        })
    }

    async fn dial_session(&self) -> io::Result<SharedSession> {
        let (writer, reader) = self.dial_halves().await?;
        Ok(Arc::new(Session::new(writer, reader)))
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if !self.want_tcp {
            return Err(io::Error::other("snell: tcp not enabled in network field"));
        }
        let session = match self.pool.as_ref().and_then(|pool| pool.take()) {
            Some(session) => session,
            None => self.dial_session().await?,
        };
        let (mut writer, reader) = session
            .take_halves()
            .ok_or_else(|| io::Error::other("snell: session busy"))?;

        // Reference `clientConn.writeRequest(nil)`: the request record is
        // written eagerly but the reply is read lazily on the first read —
        // the server only answers on the first upstream data (or error), so
        // reading here would deadlock against the reference server.
        let request = write_request(CMD_CONNECT_V2, &self.user_key, Some(target))?;
        let records = match writer.emit(now_unix(), &request) {
            Ok(records) => records,
            Err(e) => {
                session.put_halves(writer, reader);
                session.close();
                return Err(e);
            }
        };
        if let Err(e) = writer.write_all(records).await {
            session.put_halves(writer, reader);
            session.close();
            return Err(e);
        }
        Ok(Box::new(SnellStream::new(
            writer,
            reader,
            session,
            self.pool.clone(),
            true,
        )))
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        if !self.want_udp {
            return Err(io::Error::other("snell: udp not enabled in network field"));
        }
        // UDP always dials a fresh tunnel (reference `Outbound.DialContext`
        // network=udp bypasses the reuse pool).
        let (mut writer, mut reader) = self.dial_halves().await?;
        let request = write_request(CMD_UDP, &self.user_key, None)?;
        let leftover = read_reply(&mut writer, &mut reader, &request).await?;
        if !leftover.is_empty() {
            return Err(io::Error::other("snell: unexpected udp reply payload"));
        }

        let (local, peer) = udp_loopback_pair().await?;
        let peer = Arc::new(peer);
        let forward_target = target.clone();
        // Forward frame cap: reference `WritePacket` — v4 `MaxPayloadLen`
        // (0x3fff), v6 `maxPayload` (0xffff).
        let max_packet = if self.version == 6 {
            MAX_PAYLOAD_V6
        } else {
            MAX_PAYLOAD_LEN
        };

        let send_sock = Arc::clone(&peer);
        tokio::spawn(async move {
            let mut writer = writer;
            let mut buf = vec![0u8; 65_535];
            loop {
                match tokio::time::timeout(DEFAULT_UDP_TIMEOUT, send_sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let packet = match forward_packet(&forward_target, &buf[..n], max_packet) {
                            Ok(packet) => packet,
                            Err(e) => {
                                logging::debug(format_args!("snell udp send: {e}"));
                                continue;
                            }
                        };
                        let record = match writer.emit_packet(now_unix(), &packet) {
                            Ok(record) => record,
                            Err(e) => {
                                logging::debug(format_args!("snell udp send: {e}"));
                                continue;
                            }
                        };
                        if let Err(e) = writer.write_all(vec![record]).await {
                            logging::debug(format_args!("snell udp send: {e}"));
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        logging::debug(format_args!("snell udp recv: {e}"));
                        break;
                    }
                    Err(_) => break,
                }
            }
        });

        let recv_sock = Arc::clone(&peer);
        tokio::spawn(async move {
            let mut reader = reader;
            loop {
                let record =
                    match tokio::time::timeout(DEFAULT_UDP_TIMEOUT, reader.read_record()).await {
                        Ok(Ok(Some(record))) => record,
                        Ok(Ok(None)) => break,
                        Ok(Err(e)) => {
                            logging::debug(format_args!("snell udp recv: {e}"));
                            break;
                        }
                        Err(_) => break,
                    };
                if record.len() < 8 {
                    logging::debug(format_args!("snell udp recv: udp response too short"));
                    break;
                }
                // Non-IP address types are silently skipped (reference
                // `clientPacketConn.ReadPacket`).
                if !matches!(record[0], ADDRESS_TYPE_IPV4 | ADDRESS_TYPE_IPV6) {
                    continue;
                }
                match read_udp_response_address(&record) {
                    Ok((_, offset)) => {
                        if recv_sock.send(&record[offset..]).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => logging::debug(format_args!("snell udp recv: {e}")),
                }
            }
        });

        Ok(local)
    }
}

impl Drop for Snell {
    /// Config reload tears down pooled tunnels promptly (reference
    /// `Client.Close` → `pool.Close`).
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            pool.shutdown();
        }
    }
}

/// Write the handshake record and read the reply record; returns bytes cached
/// after the reply opcode (reference `readResponse` + `reuse.ParseReply`).
async fn read_reply(
    writer: &mut SnellWriter,
    reader: &mut SnellReader,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let records = writer.emit(now_unix(), request)?;
    writer.write_all(records).await?;
    let reply = reader
        .read_record()
        .await
        .map_err(|e| io::Error::other(format!("snell: read reply: {e}")))?;
    let reply =
        reply.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "snell: no reply"))?;
    Ok(parse_reply(&reply)?.unwrap_or_default())
}

/// `[0x01][source address][payload]` forward frame (reference `WritePacket`),
/// rejected past `max_packet` (version-dependent payload cap).
fn forward_packet(target: &Target, payload: &[u8], max_packet: usize) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(1 + 32 + payload.len());
    packet.push(UDP_FORWARD);
    write_udp_request_address(&mut packet, target)?;
    packet.extend_from_slice(payload);
    if packet.len() > max_packet {
        return Err(io::Error::other("snell: payload length exceeds maximum"));
    }
    Ok(packet)
}

/// Absent/empty `network` enables both directions (reference
/// `option.NetworkList.Build`: `strings.Join` of an empty list is "").
fn network_flags(obj: &serde_json::Map<String, Value>) -> (bool, bool) {
    match obj.get("network") {
        None | Some(Value::Null) => (true, true),
        Some(Value::String(value)) => match value.as_str() {
            "" => (true, true),
            "tcp" => (true, false),
            "udp" => (false, true),
            _ => (false, false),
        },
        Some(Value::Array(items)) => {
            if items.is_empty() || items.iter().all(|item| item.as_str() == Some("")) {
                return (true, true);
            }
            let tcp = items.iter().any(|item| item.as_str() == Some("tcp"));
            let udp = items.iter().any(|item| item.as_str() == Some("udp"));
            (tcp, udp)
        }
        Some(_) => (false, false),
    }
}

/// Established snell TCP tunnel: record reader/writer over the (optionally
/// pooled) session, with reply leftover cache and zero-chunk shutdown.
pub struct SnellStream {
    writer: Option<SnellWriter>,
    reader: Option<SnellReader>,
    session: SharedSession,
    pool: Option<Arc<SnellPool>>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    pending: VecDeque<(Vec<u8>, usize)>,
    fatal: Option<io::Error>,
    read_eof: bool,
    shutdown_done: bool,
    reply_pending: bool,
}

impl SnellStream {
    fn new(
        writer: SnellWriter,
        reader: SnellReader,
        session: SharedSession,
        pool: Option<Arc<SnellPool>>,
        reply_pending: bool,
    ) -> Self {
        Self {
            writer: Some(writer),
            reader: Some(reader),
            session,
            pool,
            leftover: Vec::new(),
            leftover_pos: 0,
            pending: VecDeque::new(),
            fatal: None,
            read_eof: false,
            shutdown_done: false,
            reply_pending,
        }
    }

    fn check_fatal(&self) -> Option<io::Error> {
        self.fatal
            .as_ref()
            .map(|e| io::Error::new(e.kind(), e.to_string()))
    }

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let writer = match self.writer.as_mut() {
            Some(writer) => writer,
            None => return Poll::Ready(Err(io::Error::other("snell: stream closed"))),
        };
        let result = poll_flush(cx, writer.inner_mut(), &mut self.pending);
        if let Poll::Ready(Err(e)) = &result {
            self.fatal = Some(io::Error::new(e.kind(), e.to_string()));
        }
        result
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.check_fatal() {
            return Poll::Ready(Err(error));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Bytes cached after the reply opcode arrive before record payloads.
        if this.leftover_pos < this.leftover.len() {
            let len = (this.leftover.len() - this.leftover_pos).min(buf.remaining());
            let start = this.leftover_pos;
            buf.put_slice(&this.leftover[start..start + len]);
            this.leftover_pos += len;
            return Poll::Ready(Ok(()));
        }
        if this.read_eof {
            return Poll::Ready(Ok(()));
        }
        // The reply record is consumed lazily (reference `clientConn.Read` →
        // `readResponse`): only this first read triggers it, any bytes cached
        // after the opcode become the first delivered payload.
        if this.reply_pending {
            let record = {
                let reader = match this.reader.as_mut() {
                    Some(reader) => reader,
                    None => return Poll::Ready(Err(io::Error::other("snell: stream closed"))),
                };
                match reader.poll_read_record(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        this.fatal = Some(io::Error::new(e.kind(), e.to_string()));
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.reply_pending = false;
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(Some(record))) => record,
                }
            };
            match parse_reply(&record) {
                Ok(None) => this.reply_pending = false,
                Ok(Some(cache)) => {
                    this.reply_pending = false;
                    if !cache.is_empty() {
                        let len = cache.len().min(buf.remaining());
                        buf.put_slice(&cache[..len]);
                        if len < cache.len() {
                            this.leftover = cache;
                            this.leftover_pos = len;
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    this.fatal = Some(io::Error::new(e.kind(), e.to_string()));
                    return Poll::Ready(Err(e));
                }
            }
        }
        let reader = match this.reader.as_mut() {
            Some(reader) => reader,
            None => return Poll::Ready(Err(io::Error::other("snell: stream closed"))),
        };
        match reader.poll_read_record(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                this.fatal = Some(io::Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(None)) => {
                this.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Some(payload))) => {
                let len = payload.len().min(buf.remaining());
                buf.put_slice(&payload[..len]);
                if len < payload.len() {
                    this.leftover = payload;
                    this.leftover_pos = len;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.check_fatal() {
            return Poll::Ready(Err(error));
        }
        if !this.pending.is_empty() {
            match this.flush_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let writer = match this.writer.as_mut() {
            Some(writer) => writer,
            None => return Poll::Ready(Err(io::Error::other("snell: stream closed"))),
        };
        match writer.emit(now_unix(), buf) {
            Ok(records) => {
                this.pending
                    .extend(records.into_iter().map(|record| (record, 0)));
            }
            Err(e) => {
                this.fatal = Some(io::Error::new(e.kind(), e.to_string()));
                return Poll::Ready(Err(e));
            }
        }
        // Data is accepted once queued; the next poll flushes what remains.
        match this.flush_pending(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.check_fatal() {
            return Poll::Ready(Err(error));
        }
        if !this.pending.is_empty() {
            return this.flush_pending(cx);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.check_fatal() {
            return Poll::Ready(Err(error));
        }
        if !this.shutdown_done {
            // Reference `CloseWrite`: a zero-length record ends the client
            // stream (queued once — later polls only flush).
            let writer = match this.writer.as_mut() {
                Some(writer) => writer,
                None => return Poll::Ready(Err(io::Error::other("snell: stream closed"))),
            };
            match writer.emit(now_unix(), &[]) {
                Ok(records) => {
                    this.pending
                        .extend(records.into_iter().map(|record| (record, 0)));
                    this.shutdown_done = true;
                }
                Err(e) => {
                    this.fatal = Some(io::Error::new(e.kind(), e.to_string()));
                    return Poll::Ready(Err(e));
                }
            }
        }
        this.flush_pending(cx)
    }
}

impl Drop for SnellStream {
    fn drop(&mut self) {
        // Reuse requires the full drain: request sent (always, eager), zero
        // chunk flushed, server EOF observed, no fatal error. Otherwise the
        // session dies with the stream (reference `Release(false)`).
        let reusable =
            self.fatal.is_none() && self.pending.is_empty() && self.shutdown_done && self.read_eof;
        let halves = match (self.writer.take(), self.reader.take()) {
            (Some(writer), Some(reader)) => Some((writer, reader)),
            _ => None,
        };
        if let Some((writer, reader)) = halves {
            self.session.put_halves(writer, reader);
            if reusable && let Some(pool) = &self.pool {
                pool.insert(Arc::clone(&self.session));
            } else {
                self.session.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(pairs: &[(&str, Value)]) -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn build(extra: &[(&str, Value)]) -> anyhow::Result<Snell> {
        let mut pairs: Vec<(&str, Value)> = vec![
            ("server", Value::String("127.0.0.1".into())),
            (
                "server_port",
                Value::Number(serde_json::Number::from(9990u32)),
            ),
            ("psk", Value::String("psk-for-build-tests".into())),
        ];
        pairs.extend_from_slice(extra);
        Snell::build(&opts(&pairs), "snell[out]")
    }

    /// v6 rejects unknown modes at build time (reference `snellv6.ParseMode`).
    #[test]
    fn build_rejects_unknown_v6_mode() {
        let err = build(&[
            ("version", Value::Number(6.into())),
            ("mode", Value::String("bogus".into())),
        ])
        .err()
        .expect("bad mode must fail");
        assert!(
            err.to_string()
                .contains("snell[out]: snell: unknown v6 mode: bogus"),
            "unexpected error: {err}"
        );
    }

    /// Version-scoped options: v6 reads `mode`, ignores `obfs_mode`.
    #[test]
    fn build_v6_default_builds_profile_and_ignores_obfs() {
        let snell = build(&[
            ("version", Value::Number(6.into())),
            ("mode", Value::String("default".into())),
            ("obfs_mode", Value::String("http".into())),
            ("obfs_host", Value::String("www.example.com".into())),
        ])
        .expect("v6 default");
        assert_eq!(snell.version, 6);
        assert_eq!(snell.mode, Mode::Default);
        assert!(snell.profile.is_some(), "default mode builds a profile");
        assert_eq!(snell.obfs_mode, ObfsMode::None, "v6 never obfuscates");
        assert!(snell.obfs_host.is_empty());
    }

    /// The shaping profile only exists for the default mode (reference
    /// `snellv6.NewClient`).
    #[test]
    fn build_v6_unshaped_skips_profile() {
        let snell = build(&[
            ("version", Value::Number(6.into())),
            ("mode", Value::String("unshaped".into())),
        ])
        .expect("v6 unshaped");
        assert_eq!(snell.mode, Mode::Unshaped);
        assert!(snell.profile.is_none());
    }

    /// v4 ignores the `mode` field entirely (reference
    /// `option.SnellOutboundOptions` v4 branch) and still parses obfs.
    #[test]
    fn build_v4_ignores_mode_field() {
        let snell = build(&[
            ("version", Value::Number(4.into())),
            ("mode", Value::String("bogus".into())),
            ("obfs_mode", Value::String("tls".into())),
            ("obfs_host", Value::String("www.bing.com".into())),
        ])
        .expect("v4 build");
        assert_eq!(snell.version, 4);
        assert_eq!(snell.mode, Mode::Default);
        assert!(snell.profile.is_none());
        assert_eq!(snell.obfs_mode, ObfsMode::Tls);
        assert_eq!(snell.obfs_host, "www.bing.com");
    }
}
