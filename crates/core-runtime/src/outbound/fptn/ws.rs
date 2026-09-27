//! FPTN WebSocket — handshake plus message-mode framing.
//!
//! fptn-server reads one protobuf `Message` per binary WebSocket message
//! (beast `async_read` message semantics), so frames must not be merged into
//! a byte stream: [`WsMsgStream`] exposes exactly that boundary and answers
//! server pings with pongs in line with the RFC.

use std::io;
use std::time::Instant;

use sha1::Digest as _;
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::AnyStream;
use crate::outbound::proxy::base64_std;
use crate::outbound::shadowsocks::crypto::random_bytes;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;
/// Defensive cap on a single inbound frame (official frames stay ≤ ~64 KiB).
const MAX_FRAME: usize = 16 * 1024 * 1024;
const HEAD_CAP: usize = 16 * 1024;

/// Message-mode WebSocket over an established (TLS) stream.
pub(crate) struct WsMsgStream {
    inner: AnyStream,
    rbuf: Vec<u8>,
    pos: usize,
    /// Instant of the last frame in either direction (data or control) —
    /// the reference client's `keep_alive_pings` clock.
    last_activity: Instant,
}

impl WsMsgStream {
    /// RFC 6455 opening handshake (`GET <path>` with `Connection: Upgrade`).
    pub(crate) async fn handshake(
        mut inner: AnyStream,
        path: &str,
        host: &str,
        headers: &[(String, String)],
    ) -> io::Result<Self> {
        let mut key_bytes = [0u8; 16];
        random_bytes(&mut key_bytes)?;
        let key = base64_std(&key_bytes);
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        inner.write_all(request.as_bytes()).await?;

        let response = read_head(&mut inner).await?;
        let status = response.lines().next().unwrap_or_default();
        if !status.contains(" 101 ") {
            return Err(io::Error::other(format!(
                "fptn ws handshake failed: {status}"
            )));
        }
        let mut hash = Sha1::new();
        hash.update(key.as_bytes());
        hash.update(WS_GUID);
        let expected = base64_std(&hash.finalize());
        if !response
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase())
        {
            return Err(io::Error::other(
                "fptn ws handshake: bad Sec-WebSocket-Accept",
            ));
        }
        Ok(Self {
            inner,
            rbuf: Vec::new(),
            pos: 0,
            last_activity: Instant::now(),
        })
    }

    /// Last frame timestamp in either direction (beast treats reads and
    /// writes alike for its keep-alive timer).
    pub(crate) fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Send a keep-alive ping (reference client: `keep_alive_pings = true`).
    pub(crate) async fn send_ping(&mut self) -> io::Result<()> {
        self.send_control(OP_PING, &[]).await
    }

    /// Send one binary message (client frames are masked per RFC 6455).
    pub(crate) async fn send_binary(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut mask = [0u8; 4];
        random_bytes(&mut mask)?;
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | OP_BINARY); // FIN + binary
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Read the next complete data message; `Ok(None)` on a clean close.
    /// Control frames are consumed transparently (pings answered in-line).
    pub(crate) async fn read_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut acc: Option<Vec<u8>> = None;
        loop {
            let (fin, opcode, payload) = match self.read_frame().await? {
                Some(frame) => frame,
                None => return Ok(None),
            };
            match opcode {
                OP_BINARY | 0x1 | 0x0 => {
                    let buf = acc.get_or_insert_with(Vec::new);
                    buf.extend_from_slice(&payload);
                    if fin {
                        self.compact();
                        return Ok(acc.take());
                    }
                }
                OP_PING => self.send_control(OP_PONG, &payload).await?,
                OP_PONG => {}
                OP_CLOSE => {
                    // Best-effort close reply; the peer is going away anyway.
                    let _ = self.send_control(OP_CLOSE, &[]).await;
                    self.compact();
                    return Ok(None);
                }
                other => {
                    return Err(io::Error::other(format!(
                        "fptn ws: unexpected opcode {other:#x}"
                    )));
                }
            }
        }
    }

    /// Parse one frame; `Ok(None)` on EOF at a frame boundary.
    async fn read_frame(&mut self) -> io::Result<Option<(bool, u8, Vec<u8>)>> {
        if !self.fill(2, true).await? {
            return Ok(None);
        }
        let b0 = self.rbuf[self.pos];
        let b1 = self.rbuf[self.pos + 1];
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7f) as usize;
        let mut at = self.pos + 2;
        let len = match len7 {
            126 => {
                self.fill(at - self.pos + 2, false).await?;
                let mut b = [0u8; 2];
                b.copy_from_slice(&self.rbuf[at..at + 2]);
                at += 2;
                u16::from_be_bytes(b) as usize
            }
            127 => {
                self.fill(at - self.pos + 8, false).await?;
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.rbuf[at..at + 8]);
                at += 8;
                u64::from_be_bytes(b) as usize
            }
            n => n,
        };
        if len > MAX_FRAME {
            return Err(io::Error::other("fptn ws: frame too large"));
        }
        let mask = if masked {
            self.fill(at - self.pos + 4, false).await?;
            let mut m = [0u8; 4];
            m.copy_from_slice(&self.rbuf[at..at + 4]);
            at += 4;
            Some(m)
        } else {
            None
        };
        self.fill(at - self.pos + len, false).await?;
        // Frame fully buffered: advance the read cursor past it so the next
        // `read_frame` starts at the following frame (`compact` drops `..pos`).
        self.pos = at + len;
        let mut payload = self.rbuf[at..at + len].to_vec();
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Ok(Some((fin, opcode, payload)))
    }

    /// Send a control frame (pong / close reply).
    async fn send_control(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut mask = [0u8; 4];
        random_bytes(&mut mask)?;
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode);
        frame.push(0x80 | payload.len() as u8); // control payloads ≤ 125
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Ensure `n` bytes are readable from `pos`. `allow_eof` (only valid at
    /// a frame boundary) turns a clean EOF into `false`; any other EOF while
    /// expecting bytes is a truncated frame.
    async fn fill(&mut self, n: usize, allow_eof: bool) -> io::Result<bool> {
        while self.rbuf.len() - self.pos < n {
            let mut chunk = [0u8; 16_384];
            let read = self.inner.read(&mut chunk).await?;
            if read == 0 {
                if allow_eof && self.rbuf.len() == self.pos {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fptn ws: connection closed mid-frame",
                ));
            }
            self.rbuf.extend_from_slice(&chunk[..read]);
            // Any inbound bytes (pong, ping, partial frame) count as life.
            self.last_activity = Instant::now();
        }
        Ok(true)
    }

    /// Drop consumed bytes after a message completes (keeps the buffer flat).
    fn compact(&mut self) {
        if self.pos > 0 {
            self.rbuf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

async fn read_head(stream: &mut AnyStream) -> io::Result<String> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > HEAD_CAP {
            return Err(io::Error::other("fptn ws: response head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Server-to-client binary frame (unmasked per RFC 6455).
    fn server_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x80 | OP_BINARY];
        let len = payload.len();
        if len < 126 {
            frame.push(len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    /// Two messages buffered in one read must come back in order — a read
    /// cursor that never advances would replay the first frame forever.
    #[tokio::test]
    async fn reads_consecutive_messages_from_one_buffer() {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut wire = server_frame(b"first");
        wire.extend_from_slice(&server_frame(b"second"));
        b.write_all(&wire).await.expect("write frames");
        let mut stream = WsMsgStream {
            inner: Box::new(a),
            rbuf: Vec::new(),
            pos: 0,
            last_activity: Instant::now(),
        };
        let m1 = stream.read_message().await.expect("msg 1");
        assert_eq!(m1.as_deref(), Some(&b"first"[..]));
        let m2 = stream.read_message().await.expect("msg 2");
        assert_eq!(m2.as_deref(), Some(&b"second"[..]));
    }

    /// Extended 16-bit length frames also advance the cursor correctly.
    #[tokio::test]
    async fn reads_large_consecutive_frames() {
        let (a, mut b) = tokio::io::duplex(256 * 1024);
        let big1 = vec![0xAB; 70_000];
        let big2 = vec![0xCD; 100];
        let mut wire = server_frame(&big1);
        wire.extend_from_slice(&server_frame(&big2));
        b.write_all(&wire).await.expect("write frames");
        let mut stream = WsMsgStream {
            inner: Box::new(a),
            rbuf: Vec::new(),
            pos: 0,
            last_activity: Instant::now(),
        };
        assert_eq!(stream.read_message().await.expect("msg 1"), Some(big1));
        assert_eq!(stream.read_message().await.expect("msg 2"), Some(big2));
    }

    /// Keep-alive pings are masked client control frames; sending one must
    /// refresh the activity clock the stack's timeout branch consults.
    #[tokio::test]
    async fn sends_masked_ping_and_tracks_activity() {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut stream = WsMsgStream {
            inner: Box::new(a),
            rbuf: Vec::new(),
            pos: 0,
            last_activity: Instant::now() - std::time::Duration::from_secs(300),
        };
        stream.send_ping().await.expect("ping");
        assert!(stream.last_activity().elapsed() < std::time::Duration::from_secs(1));

        let mut head = [0u8; 2];
        b.read_exact(&mut head).await.expect("frame head");
        assert_eq!(head[0], 0x80 | OP_PING);
        assert_eq!(head[1] & 0x80, 0x80, "client frames must be masked");
        assert_eq!(head[1] & 0x7f, 0, "keep-alive ping carries no payload");
        let mut mask = [0u8; 4];
        b.read_exact(&mut mask).await.expect("mask key");
        assert_ne!(mask, [0u8; 4]);
    }
}
