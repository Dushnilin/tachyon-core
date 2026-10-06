//! snell obfs client stream (reference `obfs.go`): passthrough, HTTP upgrade
//! request, or a fake TLS ClientHello — followed by application-data records
//! in TLS mode.

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncRead, AsyncWrite};

use super::crypto::random_bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObfsMode {
    None,
    Http,
    Tls,
}

/// Reference `ParseObfsMode` (case-insensitive).
pub(crate) fn parse_obfs_mode(name: &str) -> Option<ObfsMode> {
    match name.to_ascii_lowercase().as_str() {
        "" | "none" => Some(ObfsMode::None),
        "http" => Some(ObfsMode::Http),
        "tls" => Some(ObfsMode::Tls),
        _ => None,
    }
}

const DEFAULT_OBFS_HOST: &str = "bing.com";
const DEFAULT_OBFS_URI: &str = "/";
const DEFAULT_TLS_OBFS_HOST: &str = "cloudfront.net";

// Reference TLS obfs sizing constants (Surge encode/decode offsets).
const TLS_CLIENT_HELLO_PAYLOAD_LEN: usize = 0x400;
const TLS_RECORD_PAYLOAD_LEN: usize = 0x4000;
const TLS_CLIENT_RECORD_OVERHEAD: usize = 0xd4;
const TLS_CLIENT_HANDSHAKE_OVERHEAD: usize = 0xd0;
const TLS_CLIENT_EXTENSIONS_OVERHEAD: usize = 0x4f;
const TLS_SERVER_HELLO_PAYLOAD_OFFSET: usize = 0x6b;
const TLS_RECORD_HEADER_LEN: usize = 5;

/// One WebSocket key + Firefox user agent per process (reference
/// `httpObfsClientFingerprint` OnceValue).
fn http_fingerprint() -> &'static (String, String) {
    static FINGERPRINT: OnceLock<(String, String)> = OnceLock::new();
    FINGERPRINT.get_or_init(|| {
        let mut key = [0u8; 16];
        let _ = random_bytes(&mut key);
        let os_minor = random_range(9, 6);
        let firefox = random_range(22, 43);
        (
            format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{os_minor}; rv:64.0) Gecko/20100101 Firefox/{firefox}.0"),
            BASE64.encode(key),
        )
    })
}

/// Uniform value in `[min, min + span)` from one random byte (the reference
/// uses `math/rand`; distribution equivalence is enough for a fingerprint).
fn random_range(min: u32, span: u32) -> u32 {
    let mut byte = [0u8; 1];
    if random_bytes(&mut byte).is_err() {
        return min;
    }
    min + u32::from(byte[0]) % span
}

enum TlsReadStage {
    /// Skip `remaining` framing bytes, then read the 2 byte length.
    Discard,
    Length,
    /// `remaining` payload bytes of the current record.
    Payload,
}

pub(crate) struct ObfsStream<S> {
    inner: S,
    mode: ObfsMode,
    host: String,
    uri: String,
    // HTTP write side
    http_request_sent: bool,
    // HTTP read side: scan for the first "\r\n\r\n".
    http_head_done: bool,
    http_matched: usize,
    // TLS write side
    tls_hello_sent: bool,
    // Bytes of the current logical write waiting to reach the wire.
    pending: Vec<u8>,
    pending_pos: usize,
    accepted: Option<usize>,
    // TLS read side
    tls_stage: TlsReadStage,
    tls_discard: usize,
    tls_len: [u8; 2],
    tls_len_filled: usize,
    tls_payload_remaining: usize,
    tls_scratch: [u8; 512],
}

impl<S> ObfsStream<S> {
    pub(crate) fn new(inner: S, mode: ObfsMode, host: &str, uri: &str) -> Self {
        let mut stream = Self {
            inner,
            mode,
            host: host.to_string(),
            uri: uri.to_string(),
            http_request_sent: false,
            http_head_done: false,
            http_matched: 0,
            tls_hello_sent: false,
            pending: Vec::new(),
            pending_pos: 0,
            accepted: None,
            tls_stage: TlsReadStage::Discard,
            tls_discard: TLS_SERVER_HELLO_PAYLOAD_OFFSET - 2,
            tls_len: [0; 2],
            tls_len_filled: 0,
            tls_payload_remaining: 0,
            tls_scratch: [0; 512],
        };
        if mode == ObfsMode::None {
            stream.http_head_done = true;
        }
        stream
    }
}

impl<S: AsyncWrite + Unpin> ObfsStream<S> {
    fn build_first_write(&mut self, buf: &[u8]) -> io::Result<()> {
        match self.mode {
            ObfsMode::None | ObfsMode::Http => {
                if self.mode == ObfsMode::Http && !self.http_request_sent {
                    self.http_request_sent = true;
                    let host = if self.host.is_empty() {
                        DEFAULT_OBFS_HOST
                    } else {
                        &self.host
                    };
                    let uri = if self.uri.is_empty() {
                        DEFAULT_OBFS_URI
                    } else {
                        &self.uri
                    };
                    let (user_agent, key) = http_fingerprint();
                    let head = format!(
                        "GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {}\r\nSec-WebSocket-Key: {key}\r\n\r\n",
                        buf.len()
                    );
                    self.pending = head.into_bytes();
                    self.pending.extend_from_slice(buf);
                } else {
                    self.pending = buf.to_vec();
                }
            }
            ObfsMode::Tls => {
                if !self.tls_hello_sent {
                    self.tls_hello_sent = true;
                    self.pending = build_client_hello(&self.host, buf)?;
                } else {
                    self.pending = build_records(buf);
                }
            }
        }
        Ok(())
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snell: obfs: failed to write whole frame",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        let accepted = self.accepted.take().unwrap_or(0);
        Poll::Ready(Ok(accepted))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.accepted.is_some() {
            return self.poll_pending(cx);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.mode == ObfsMode::None {
            // Nothing to frame: forward straight to the transport instead of
            // staging a full copy of every pump chunk in `pending`.
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        self.build_first_write(buf)?;
        self.accepted = Some(buf.len());
        self.poll_pending(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.accepted.is_some() {
            match self.poll_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.accepted.is_some() {
            match self.poll_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> ObfsStream<S> {
    fn poll_http_head(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        const TERMINATOR: &[u8] = b"\r\n\r\n";
        while !self.http_head_done {
            let mut byte = [0u8; 1];
            let mut read_buf = tokio::io::ReadBuf::new(&mut byte);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell: obfs: http head closed",
                        )));
                    }
                    let value = byte[0];
                    if let Some(&expected) = TERMINATOR.get(self.http_matched) {
                        if value == expected {
                            self.http_matched += 1;
                        } else if value == TERMINATOR[0] {
                            self.http_matched = 1;
                        } else {
                            self.http_matched = 0;
                        }
                    }
                    if self.http_matched == TERMINATOR.len() {
                        self.http_head_done = true;
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_tls_read(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.tls_stage {
                TlsReadStage::Discard => {
                    if self.tls_discard == 0 {
                        self.tls_stage = TlsReadStage::Length;
                        self.tls_len_filled = 0;
                        continue;
                    }
                    let want = self.tls_discard.min(self.tls_scratch.len());
                    let mut read_buf = tokio::io::ReadBuf::new(&mut self.tls_scratch[..want]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "snell: obfs: tls record closed",
                                )));
                            }
                            self.tls_discard -= n;
                        }
                    }
                }
                TlsReadStage::Length => {
                    let mut read_buf =
                        tokio::io::ReadBuf::new(&mut self.tls_len[self.tls_len_filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "snell: obfs: tls record closed",
                                )));
                            }
                            self.tls_len_filled += n;
                        }
                    }
                    if self.tls_len_filled == 2 {
                        let payload_len = u16::from_be_bytes(self.tls_len) as usize;
                        if payload_len == 0 {
                            // Empty record: next header uses the 5 byte form.
                            self.tls_stage = TlsReadStage::Discard;
                            self.tls_discard = TLS_RECORD_HEADER_LEN - 2;
                            continue;
                        }
                        self.tls_payload_remaining = payload_len;
                        self.tls_stage = TlsReadStage::Payload;
                    }
                }
                TlsReadStage::Payload => {
                    if out.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let want = self.tls_payload_remaining.min(out.len());
                    let mut read_buf = tokio::io::ReadBuf::new(&mut out[..want]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "snell: obfs: tls record closed",
                                )));
                            }
                            self.tls_payload_remaining -= n;
                            if self.tls_payload_remaining == 0 {
                                self.tls_stage = TlsReadStage::Discard;
                                self.tls_discard = TLS_RECORD_HEADER_LEN - 2;
                            }
                            return Poll::Ready(Ok(n));
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.mode {
            ObfsMode::None => Pin::new(&mut self.inner).poll_read(cx, buf),
            ObfsMode::Http => {
                match self.poll_http_head(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
            ObfsMode::Tls => {
                let target = buf.initialize_unfilled();
                match self.poll_tls_read(cx, target) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(n)) => {
                        buf.advance(n);
                        Poll::Ready(Ok(()))
                    }
                }
            }
        }
    }
}

// -------------------------------------------------------- TLS client hello ----

/// Reference `tlsObfsClientConn.Write` first write: a ClientHello carrying the
/// first 0x400 payload bytes as the session ticket, then the rest as records.
fn build_client_hello(host: &str, payload_all: &[u8]) -> io::Result<Vec<u8>> {
    let host = if host.is_empty() {
        DEFAULT_TLS_OBFS_HOST
    } else {
        host
    };
    let payload_len = payload_all.len().min(TLS_CLIENT_HELLO_PAYLOAD_LEN);
    let payload = &payload_all[..payload_len];

    let mut random = [0u8; 28];
    random_bytes(&mut random)?;
    let mut session_id = [0u8; 32];
    random_bytes(&mut session_id)?;
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    let mut out = Vec::with_capacity(
        TLS_CLIENT_RECORD_OVERHEAD + host.len() + payload_all.len() + TLS_RECORD_HEADER_LEN,
    );
    out.extend_from_slice(&[0x16, 0x03, 0x01]);
    out.extend_from_slice(
        &u16::try_from(TLS_CLIENT_RECORD_OVERHEAD + host.len() + payload.len())
            .map_err(|_| io::Error::other("snell: obfs: client hello too long"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(
        &u16::try_from(TLS_CLIENT_HANDSHAKE_OVERHEAD + host.len() + payload.len())
            .map_err(|_| io::Error::other("snell: obfs: client hello too long"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&time.to_be_bytes());
    out.extend_from_slice(&random);
    out.push(0x20);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&0x0038u16.to_be_bytes());
    out.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(
        &u16::try_from(TLS_CLIENT_EXTENSIONS_OVERHEAD + host.len() + payload.len())
            .map_err(|_| io::Error::other("snell: obfs: client hello too long"))?
            .to_be_bytes(),
    );
    // session_ticket (0x0023) with the payload.
    out.extend_from_slice(&0x0023u16.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    // server_name (0x0000).
    out.extend_from_slice(&0x0000u16.to_be_bytes());
    out.extend_from_slice(&(host.len() as u16 + 5).to_be_bytes());
    out.extend_from_slice(&(host.len() as u16 + 3).to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&[
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, //
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, //
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03, //
        0x00, 0x16, 0x00, 0x00, //
        0x00, 0x17, 0x00, 0x00,
    ]);
    out.extend_from_slice(&build_records(&payload_all[payload_len..]));
    Ok(out)
}

/// Reference `appendRecords`: `[0x17 0x03 0x03 u16 len]` chunks of ≤ 0x4000.
fn build_records(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let len = rest.len().min(TLS_RECORD_PAYLOAD_LEN);
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&rest[..len]);
        rest = &rest[len..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AsyncRead over a byte slice.
    struct SliceReader(std::io::Cursor<Vec<u8>>);
    impl AsyncRead for SliceReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            use std::io::Read;
            let n = self.0.read(buf.initialize_unfilled())?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    /// AsyncWrite capturing every byte.
    #[derive(Default)]
    struct VecWriter(Vec<u8>);
    impl AsyncWrite for VecWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().0.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn write_all(stream: &mut ObfsStream<VecWriter>, data: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let fut = stream.write_all(data);
        futures_lite_wait(fut).expect("obfs write");
    }

    /// Minimal executor for the sync test context: drive the future with a
    /// noop waker (both writers complete immediately).
    fn futures_lite_wait<F: std::future::Future>(fut: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(fut);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("test future pending"),
        }
    }

    #[test]
    fn parse_obfs_mode_is_case_insensitive() {
        assert_eq!(parse_obfs_mode(""), Some(ObfsMode::None));
        assert_eq!(parse_obfs_mode("NONE"), Some(ObfsMode::None));
        assert_eq!(parse_obfs_mode("Http"), Some(ObfsMode::Http));
        assert_eq!(parse_obfs_mode("TLS"), Some(ObfsMode::Tls));
        assert_eq!(parse_obfs_mode("http2"), None);
    }

    #[test]
    fn http_first_write_prepends_upgrade_request() {
        let mut stream = ObfsStream::new(VecWriter::default(), ObfsMode::Http, "", "");
        write_all(&mut stream, b"payload-bytes");
        let wire = stream.inner.0;
        let head_end = wire
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head terminator")
            + 4;
        let head = String::from_utf8_lossy(&wire[..head_end]).to_string();
        assert!(
            head.starts_with("GET / HTTP/1.1\r\nHost: bing.com\r\n"),
            "{head}"
        );
        assert!(head.contains("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10."));
        assert!(head.contains("Upgrade: websocket\r\nConnection: Upgrade\r\n"));
        assert!(head.contains("Content-Length: 13\r\n"));
        assert!(head.contains("Sec-WebSocket-Key: "));
        assert!(head.ends_with("\r\n\r\n"));
        assert_eq!(&wire[head_end..], b"payload-bytes");

        // Second write goes through untouched.
        let mut stream2 = ObfsStream::new(
            VecWriter::default(),
            ObfsMode::Http,
            "example.com",
            "/index",
        );
        write_all(&mut stream2, b"first");
        write_all(&mut stream2, b"second");
        let wire2 = stream2.inner.0;
        assert!(wire2.ends_with(b"firstsecond"));
        let head2 = String::from_utf8_lossy(&wire2).to_string();
        assert!(head2.starts_with("GET /index HTTP/1.1\r\nHost: example.com\r\n"));
    }

    #[test]
    fn http_read_skips_head_then_passes_through() {
        let mut stream = ObfsStream::new(
            SliceReader(std::io::Cursor::new(
                b"HTTP/1.1 101 Switching Protocols\r\nX-A: b\r\n\r\ndata-after".to_vec(),
            )),
            ObfsMode::Http,
            "",
            "",
        );
        let out = futures_lite_wait(read_chunk(&mut stream, 64));
        assert_eq!(out, b"data-after");
    }

    async fn read_chunk(stream: &mut ObfsStream<SliceReader>, len: usize) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; len];
        let n = stream.read(&mut buf).await.expect("read");
        buf.truncate(n);
        buf
    }

    #[test]
    fn tls_hello_lengths_are_consistent() {
        let host = "www.example.com";
        let payload = vec![0x5au8; 1500];
        let hello = build_client_hello(host, &payload).expect("hello");
        // Record header: 0x16 0x03 0x01 + len.
        assert_eq!(&hello[0..3], &[0x16, 0x03, 0x01]);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, 0xd4 + host.len() + 0x400);
        // Handshake header.
        assert_eq!(&hello[5..7], &[0x01, 0x00]);
        let hs_len = u16::from_be_bytes([hello[7], hello[8]]) as usize;
        assert_eq!(hs_len, 0xd0 + host.len() + 0x400);
        assert_eq!(record_len, hs_len + 4);
        // Extensions length precedes the extension data: version(2) + time(4)
        // + random(28) + session id(1+32) + cipher suites(2+0x38) +
        // compression(1+1) after the 9 byte record+handshake headers.
        let ext_len_offset = 5 + 4 + 2 + 4 + 28 + 1 + 32 + 2 + 0x38 + 1 + 1;
        assert_eq!(ext_len_offset, 136);
        let ext_len =
            u16::from_be_bytes([hello[ext_len_offset], hello[ext_len_offset + 1]]) as usize;
        assert_eq!(ext_len, 0x4f + host.len() + 0x400);
        // Payload sits at 0x8e (the session ticket).
        assert_eq!(&hello[0x8e..0x8e + 0x400], &payload[..0x400]);
        // The remainder of the payload is wrapped in an application-data record.
        let tail = &hello[5 + 4 + hs_len..];
        assert_eq!(&tail[0..3], &[0x17, 0x03, 0x03]);
        let tail_len = u16::from_be_bytes([tail[3], tail[4]]) as usize;
        assert_eq!(tail_len, 1500 - 0x400);
        assert_eq!(&tail[5..], &payload[0x400..]);
        // SNI carries the host.
        let sni = host.as_bytes();
        assert!(
            hello.windows(sni.len()).any(|w| w == sni),
            "host must appear in the hello"
        );
    }

    #[test]
    fn tls_first_write_then_records() {
        let mut stream = ObfsStream::new(VecWriter::default(), ObfsMode::Tls, "", "");
        write_all(&mut stream, b"abc");
        let wire = stream.inner.0.clone();
        assert_eq!(&wire[0..3], &[0x16, 0x03, 0x01], "first write is a hello");
        // Default host appears in the hello.
        assert!(wire.windows(14).any(|w| w == b"cloudfront.net"));

        write_all(&mut stream, b"defgh");
        let wire2 = &stream.inner.0[wire.len()..];
        assert_eq!(&wire2[0..3], &[0x17, 0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([wire2[3], wire2[4]]), 5);
        assert_eq!(&wire2[5..], b"defgh");
    }

    #[test]
    fn tls_read_parses_hello_then_records() {
        // Server hello template (as the reference server writes) + one record.
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x16, 0x03, 0x01]);
        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&[0x16, 0x03, 0x01]);
        server_hello.extend_from_slice(&91u16.to_be_bytes());
        server_hello.extend_from_slice(&[0x02, 0x00, 0x00, 0x57, 0x03, 0x03]);
        server_hello.extend_from_slice(&0u32.to_be_bytes());
        server_hello.extend_from_slice(&[7u8; 28]);
        server_hello.push(0x20);
        server_hello.extend_from_slice(&[9u8; 32]);
        server_hello.extend_from_slice(&[0xcc, 0xa8, 0x00, 0x00, 0x00]);
        server_hello.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        server_hello.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        server_hello.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        server_hello.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        server_hello.extend_from_slice(&[0x16, 0x03, 0x03]);
        server_hello.extend_from_slice(&5u16.to_be_bytes());
        server_hello.extend_from_slice(b"first");
        // application-data record with the payload.
        server_hello.extend_from_slice(&[0x17, 0x03, 0x03]);
        server_hello.extend_from_slice(&6u16.to_be_bytes());
        server_hello.extend_from_slice(b"second");

        let mut stream = ObfsStream::new(
            SliceReader(std::io::Cursor::new(server_hello)),
            ObfsMode::Tls,
            "",
            "",
        );
        let out = futures_lite_wait(read_chunk(&mut stream, 64));
        assert_eq!(out, b"first");
        let out = futures_lite_wait(read_chunk(&mut stream, 64));
        assert_eq!(out, b"second");
    }

    #[test]
    fn none_mode_is_passthrough() {
        let mut stream = ObfsStream::new(VecWriter::default(), ObfsMode::None, "x", "y");
        write_all(&mut stream, b"plain");
        assert_eq!(stream.inner.0, b"plain");
    }
}
