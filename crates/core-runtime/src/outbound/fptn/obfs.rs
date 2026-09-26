//! Official "TLS Obfuscation" strategy (`CensorshipStrategy::kTlsObfuscator`)
//! — the wire format fptn-server detects from the first bytes, after which it
//! skips the session-id, probing and reality checks entirely.
//!
//! Frame layout (big-endian, mirrors `tls_obfuscator2.cpp`):
//!
//! ```text
//! 0x17 0x03 0x03 | u16 content_length | u64 random | u32 timestamp
//!   | u8 xor_key | u16 payload_len | u16 padding_len
//!   | payload (each byte XOR xor_key) | random padding
//! ```
//!
//! with `content_length == 17 + payload_len + padding_len` and
//! `content_length <= 16384`. The 5-byte prefix imitates a TLS
//! `application_data` record, so a middlebox sees an ordinary TLS flow. Only
//! the handshake is wrapped: the server clears its obfuscator right after
//! `async_handshake`, and the client flips to pass-through once its own
//! handshake completes ([`ObfsStream::handle`] is flipped by the caller).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::outbound::shadowsocks::crypto::random_bytes;

use super::tls::unix_now;

/// `1 + 1 + 1 + 2` record prefix + `8 + 4 + 1 + 2 + 2` obfuscator fields.
const HEADER_LEN: usize = 22;
/// `content_length` ceiling enforced by the server.
const MAX_CONTENT: usize = 16384;
const PADDING_MIN: u16 = 4095;
const PADDING_MAX: u16 = 8192;
/// Timestamp window the server accepts, widened a little for clock skew.
const TIME_WINDOW: u32 = 300;
/// Largest payload that still fits beside the mandatory padding.
const MAX_PAYLOAD: usize = MAX_CONTENT - 17 - PADDING_MIN as usize;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("fptn obfs: {msg}"))
}

/// Wrap one handshake flight into a single obfuscated frame.
fn obfuscate(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > MAX_PAYLOAD {
        return Err(bad("handshake flight too large"));
    }
    let payload_len = data.len() as u16;
    let mut pad_range = [0u8; 2];
    random_bytes(&mut pad_range)?;
    let span = PADDING_MAX - PADDING_MIN;
    let padding_len = PADDING_MIN + u16::from(pad_range[0]) % (span + 1);
    let content_length = 17 + payload_len + padding_len;

    let mut frame = Vec::with_capacity(HEADER_LEN + data.len() + padding_len as usize);
    frame.extend_from_slice(&[0x17, 0x03, 0x03]);
    frame.extend_from_slice(&content_length.to_be_bytes());
    let mut random_data = [0u8; 8];
    random_bytes(&mut random_data)?;
    frame.extend_from_slice(&random_data);
    frame.extend_from_slice(&unix_now().to_be_bytes());
    let mut key = [0u8; 1];
    random_bytes(&mut key)?;
    frame.push(key[0]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&padding_len.to_be_bytes());
    frame.extend(data.iter().map(|b| b ^ key[0]));
    let mut padding = vec![0u8; padding_len as usize];
    random_bytes(&mut padding)?;
    frame.extend_from_slice(&padding);
    Ok(frame)
}

fn timestamp_ok(raw: u32) -> bool {
    let now = unix_now();
    raw <= now.saturating_add(TIME_WINDOW) && raw.saturating_add(TIME_WINDOW) >= now
}

/// TCP stream that obfuscates everything written and deobfuscates everything
/// read until the shared flag flips to plain mode.
pub(crate) struct ObfsStream<S> {
    inner: S,
    plain: Arc<AtomicBool>,
    /// Raw socket bytes awaiting deobfuscation.
    rbuf: Vec<u8>,
    /// Obfuscated frames queued for the socket (partial writes).
    outq: Vec<u8>,
    /// Caller bytes currently sitting in `outq`.
    queued: Option<usize>,
    /// Plaintext ready for the TLS layer.
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> ObfsStream<S> {
    /// Wrap `inner`; the returned flag is set to `true` once the TLS
    /// handshake is done, after which both directions pass through raw.
    pub(crate) fn new(inner: S) -> (Self, Arc<AtomicBool>) {
        let plain = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                plain: Arc::clone(&plain),
                rbuf: Vec::new(),
                outq: Vec::new(),
                queued: None,
                out: Vec::new(),
                out_pos: 0,
            },
            plain,
        )
    }

    fn is_plain(&self) -> bool {
        self.plain.load(Ordering::Relaxed)
    }

    /// Move every complete obfuscated record in `rbuf` into `out`.
    fn drain_records(&mut self) -> io::Result<()> {
        while self.rbuf.len() >= HEADER_LEN {
            let header = &self.rbuf[..HEADER_LEN];
            if header[0] != 0x17 || header[1] != 0x03 || header[2] != 0x03 {
                return Err(bad("unexpected record prefix"));
            }
            let content_length = u16::from_be_bytes([header[3], header[4]]) as usize;
            let timestamp = u32::from_be_bytes([header[13], header[14], header[15], header[16]]);
            let xor_key = header[17];
            let payload_len = u16::from_be_bytes([header[18], header[19]]) as usize;
            let padding_len = u16::from_be_bytes([header[20], header[21]]) as usize;
            if content_length > MAX_CONTENT || content_length < 17 + payload_len + padding_len {
                return Err(bad("inconsistent frame header"));
            }
            if !timestamp_ok(timestamp) {
                return Err(bad("stale frame timestamp"));
            }
            let total = HEADER_LEN + payload_len + padding_len;
            if self.rbuf.len() < total {
                return Ok(());
            }
            for byte in &mut self.rbuf[HEADER_LEN..HEADER_LEN + payload_len] {
                *byte ^= xor_key;
            }
            self.out
                .extend_from_slice(&self.rbuf[HEADER_LEN..HEADER_LEN + payload_len]);
            self.rbuf.drain(..total);
        }
        Ok(())
    }

    /// Hand queued plaintext to the TLS layer.
    fn drain_out(&mut self, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let available = &self.out[self.out_pos..];
        let n = available.len().min(buf.remaining());
        buf.put_slice(&available[..n]);
        self.out_pos += n;
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.out_pos < me.out.len() {
                return me.drain_out(buf);
            }
            if me.is_plain() {
                // Anything still buffered arrived after the last obfuscated
                // record, so it is already plain.
                if !me.rbuf.is_empty() {
                    let n = me.rbuf.len().min(buf.remaining());
                    buf.put_slice(&me.rbuf[..n]);
                    me.rbuf.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut me.inner).poll_read(cx, buf);
            }
            me.drain_records()?;
            if me.out_pos < me.out.len() {
                return me.drain_out(buf);
            }
            let mut chunk = [0u8; 16 * 1024];
            let mut tmp = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut me.inner).poll_read(cx, &mut tmp))?;
            let filled = tmp.filled().len();
            if filled == 0 {
                return if me.rbuf.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "fptn obfs: connection closed mid-frame",
                    )))
                };
            }
            me.rbuf.extend_from_slice(tmp.filled());
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.is_plain() || buf.is_empty() {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        if me.outq.is_empty() {
            // A queued `Some` without bytes cannot happen (we only keep it
            // while `outq` is non-empty), so rebuild from the caller's buf.
            me.outq = obfuscate(buf)?;
            me.queued = Some(buf.len());
        }
        while !me.outq.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.outq) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::other("fptn obfs: write stall")));
                }
                Poll::Ready(Ok(n)) => {
                    me.outq.drain(..n);
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(me.queued.take().unwrap_or(0)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        while !me.outq.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.outq) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::other("fptn obfs: write stall")));
                }
                Poll::Ready(Ok(n)) => {
                    me.outq.drain(..n);
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deobfuscate(buf: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            assert!(buf.len() - pos >= HEADER_LEN, "truncated header");
            let header = &buf[pos..pos + HEADER_LEN];
            assert_eq!(&header[..3], &[0x17, 0x03, 0x03]);
            let content_length = u16::from_be_bytes([header[3], header[4]]) as usize;
            let xor_key = header[17];
            let payload_len = u16::from_be_bytes([header[18], header[19]]) as usize;
            let padding_len = u16::from_be_bytes([header[20], header[21]]) as usize;
            assert_eq!(content_length, 17 + payload_len + padding_len);
            assert!(content_length <= MAX_CONTENT);
            let total = HEADER_LEN + payload_len + padding_len;
            assert!(buf.len() - pos >= total, "truncated frame");
            for byte in &buf[pos + HEADER_LEN..pos + HEADER_LEN + payload_len] {
                out.push(byte ^ xor_key);
            }
            pos += total;
        }
        Ok(out)
    }

    #[test]
    fn round_trip() {
        let payload = b"client hello flight".to_vec();
        let frame = obfuscate(&payload).expect("obfuscate");
        assert_eq!(frame[0], 0x17);
        assert_eq!(&frame[1..3], &[0x03, 0x03]);
        assert_eq!(deobfuscate(&frame).unwrap(), payload);
    }

    #[test]
    fn multiple_frames_concatenate() {
        let mut wire = Vec::new();
        for part in [&b"one"[..], b"two", b"three"] {
            wire.extend(obfuscate(part).expect("obfuscate"));
        }
        assert_eq!(deobfuscate(&wire).unwrap(), b"onetwothree");
    }

    #[test]
    fn rejects_oversized_payload() {
        let big = vec![0u8; MAX_PAYLOAD + 1];
        assert!(obfuscate(&big).is_err());
        assert!(obfuscate(&vec![0u8; MAX_PAYLOAD]).is_ok());
    }

    #[test]
    fn rejects_foreign_bytes() {
        // Long enough to fill a header, but not an obfuscator2 frame.
        let (mut stream, _) = ObfsStream::new(std::io::Cursor::new(Vec::<u8>::new()));
        stream.rbuf.extend_from_slice(b"plain TLS-ish bytes......");
        assert!(stream.drain_records().is_err());
    }

    #[test]
    fn partial_frame_waits_for_more_bytes() {
        let frame = obfuscate(b"hello").expect("obfuscate");
        let (mut stream, _) = ObfsStream::new(std::io::Cursor::new(Vec::<u8>::new()));
        stream.rbuf.extend_from_slice(&frame[..frame.len() - 1]);
        assert!(stream.drain_records().is_ok());
        assert!(stream.out.is_empty());
        stream.rbuf.push(*frame.last().expect("frame"));
        assert!(stream.drain_records().is_ok());
        assert_eq!(stream.out.as_slice(), b"hello");
    }
}
