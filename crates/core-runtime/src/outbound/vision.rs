//! VLESS `flow: xtls-rprx-vision` (Xray's Vision).
//!
//! Vision frames the payload instead of encrypting it: the client writes the
//! user UUID once, then wraps every write as
//! `[command, content_len:u16, padding_len:u16, content, padding]`, and strips
//! the same framing on the way back. Padding keeps small writes looking like
//! TLS record traffic, which is the point of the flow.
//!
//! Ported from `sing-vmess/vless/vision.go`. The XTLS "direct" mode (writing
//! through the TLS layer without re-encrypting, chosen once a TLS 1.3 handshake
//! is seen) is deliberately not implemented: it needs a handle to the raw
//! connection below the cipher. A server handed a `commandPaddingEnd` stream
//! serves the client exactly the same way, so only splice-style servers differ.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::AnyStream;

/// `commandPaddingEnd`; the reference never sends `commandPaddingDirect`
/// from here, and the client always closes a block with End.
const PADDING_END: u8 = 1;

/// Keep small writes padded to roughly a TLS record, as the reference does.
const TLS_PADDING_FLOOR: usize = 900;
const TLS_PADDING_SPREAD: usize = 500;
const PLAIN_PADDING_SPREAD: usize = 256;

pub struct VisionStream {
    inner: AnyStream,
    uuid: [u8; 16],
    /// the UUID goes out in front of the first padded block
    write_uuid: bool,
    /// once a TLS handshake has passed through, padding grows to record size
    saw_tls: bool,
    // inbound framing state, straight from the reference field names
    remaining_content: i64,
    remaining_padding: i64,
    current_command: u8,
    /// bytes read from `inner` but not framed yet
    raw: Vec<u8>,
    /// framed payload waiting for the caller
    payload: Vec<u8>,
    eof: bool,
}

impl VisionStream {
    pub fn new(inner: AnyStream, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            write_uuid: true,
            saw_tls: false,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            raw: Vec::new(),
            payload: Vec::new(),
            eof: false,
        }
    }

    fn random_below(limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let mut byte = [0u8; 8];
        getrandom::fill(&mut byte).unwrap_or_default();
        (u64::from_le_bytes(byte) % limit as u64) as usize
    }

    /// `VisionConn.padding`.
    fn frame(&self, content: &[u8], command: u8) -> Vec<u8> {
        let content_len = content.len();
        let padding_len = if content_len < TLS_PADDING_FLOOR && self.saw_tls {
            Self::random_below(TLS_PADDING_SPREAD) + TLS_PADDING_FLOOR - content_len
        } else {
            Self::random_below(PLAIN_PADDING_SPREAD)
        };
        let mut out = Vec::with_capacity(content_len + padding_len + 21);
        if self.write_uuid {
            out.extend_from_slice(&self.uuid);
        }
        out.push(command);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len, 0);
        out
    }

    /// The reference filters the first packets to tell TLS 1.3 from TLS 1.2; we
    /// only need the coarse "is TLS involved" answer for the padding profile.
    fn looks_like_tls(buffer: &[u8]) -> bool {
        buffer.len() > 5 && (buffer[0] == 0x16 || (buffer[0] == 0x01 && buffer[5] == 0x01))
    }

    /// `VisionConn.unPadding` over `raw`, moving payload into `self.payload`.
    fn unpad(&mut self) {
        let mut index = 0usize;
        if self.remaining_content == -1
            && self.remaining_padding == -1
            && self.raw.len() >= 21
            && self.raw[..16] == self.uuid
        {
            index = 16;
            self.remaining_content = 0;
            self.remaining_padding = 0;
            self.current_command = 0;
        }
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            // a peer that does not frame at all: the reference decides that from
            // the first bytes, so a short read must wait rather than guess
            if index == 0 && self.raw.len() < 21 && !self.eof {
                return;
            }
            self.payload.extend_from_slice(&self.raw[index..]);
            self.raw.clear();
            return;
        }
        while index < self.raw.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.current_command == PADDING_END {
                    self.payload.extend_from_slice(&self.raw[index..]);
                    index = self.raw.len();
                    break;
                }
                if self.raw.len() < index + 5 {
                    break;
                }
                let header = self.raw[index..index + 5].to_vec();
                self.current_command = header[0];
                self.remaining_content = i64::from(u16::from_be_bytes([header[1], header[2]]));
                self.remaining_padding = i64::from(u16::from_be_bytes([header[3], header[4]]));
                index += 5;
            } else if self.remaining_content > 0 {
                let end = (self.remaining_content as usize).min(self.raw.len() - index);
                self.payload
                    .extend_from_slice(&self.raw[index..index + end]);
                self.remaining_content -= end as i64;
                index += end;
            } else {
                let end = (self.remaining_padding as usize).min(self.raw.len() - index);
                self.remaining_padding -= end as i64;
                index += end;
            }
        }
        self.raw.drain(..index);
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            this.unpad();
            if !this.payload.is_empty() {
                let take = this.payload.len().min(out.remaining());
                out.put_slice(&this.payload[..take]);
                this.payload.drain(..take);
                return std::task::Poll::Ready(Ok(()));
            }
            if this.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 8192];
            let mut buf = ReadBuf::new(&mut scratch);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                std::task::Poll::Ready(Ok(())) => {
                    let chunk = buf.filled().to_vec();
                    if chunk.is_empty() {
                        this.eof = true;
                        // a closed peer may still leave a tail in the framing
                        this.unpad();
                    } else {
                        if !this.saw_tls {
                            this.saw_tls = VisionStream::looks_like_tls(&chunk);
                        }
                        this.raw.extend_from_slice(&chunk);
                    }
                }
                std::task::Poll::Ready(Err(error)) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Pending => {
                    // a partial frame stays in  for the next poll
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.saw_tls {
            this.saw_tls = VisionStream::looks_like_tls(buf);
        }
        let framed = this.frame(buf, PADDING_END);
        // the uuid only goes out with the first frame
        let uuid_written = this.write_uuid;
        if uuid_written {
            this.write_uuid = false;
        }
        let _ = uuid_written;
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &framed) {
            std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(Ok(buf.len())),
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn uuid() -> [u8; 16] {
        [7u8; 16]
    }

    fn pair() -> (VisionStream, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(8192);
        let boxed: AnyStream = Box::new(client);
        (VisionStream::new(boxed, uuid()), server)
    }

    #[test]
    fn first_frame_carries_the_uuid_then_the_header() {
        let (vision, _) = pair();
        let frame = vision.frame(b"hello", PADDING_END);
        assert_eq!(&frame[..16], &uuid()[..], "the uuid is written once");
        assert_eq!(frame[16], PADDING_END, "command");
        assert_eq!(u16::from_be_bytes([frame[17], frame[18]]), 5);
        let padding = u16::from_be_bytes([frame[19], frame[20]]) as usize;
        assert_eq!(&frame[21..26], b"hello");
        assert_eq!(frame.len(), 21 + 5 + padding);
        assert!(
            frame[26..].iter().all(|byte| *byte == 0),
            "padding is zeroed"
        );
    }

    #[test]
    fn padding_grows_to_a_tls_record_only_after_tls() {
        let (mut vision, _) = pair();
        let small = vision.frame(b"x", PADDING_END);
        let padding = u16::from_be_bytes([small[19], small[20]]) as usize;
        assert!(
            padding < PLAIN_PADDING_SPREAD,
            "before a handshake is seen the padding stays plain"
        );
        vision.saw_tls = true;
        let padded = vision.frame(&[0u8; 100], PADDING_END);
        let padding = u16::from_be_bytes([padded[19], padded[20]]) as usize;
        assert!(
            (TLS_PADDING_FLOOR - 100..TLS_PADDING_FLOOR + TLS_PADDING_SPREAD).contains(&padding),
            "with TLS the padding fills the record, got {padding}"
        );
    }

    #[test]
    fn unpadding_strips_headers_and_padding() {
        let (source, _) = pair();
        let mut bytes = source.frame(b"first", 0u8);
        // the uuid is written once, so the second frame has no prefix
        bytes.extend_from_slice(&source.frame(b"second", PADDING_END)[16..]);

        let (mut sink, _) = pair();
        sink.raw = bytes;
        sink.unpad();
        assert_eq!(&sink.payload, b"firstsecond");
        assert!(sink.raw.is_empty(), "the framing is fully consumed");
    }

    #[test]
    fn uuid_is_stripped_from_the_first_inbound_frame() {
        let (source, _) = pair();
        let framed = source.frame(b"payload", PADDING_END);
        let mut bytes = uuid().to_vec();
        bytes.extend_from_slice(&framed[16..]);

        let (mut sink, _) = pair();
        sink.raw = bytes;
        sink.unpad();
        assert_eq!(&sink.payload, b"payload");
    }

    #[test]
    fn unframed_traffic_passes_through() {
        let (mut sink, _) = pair();
        sink.raw = b"plain bytes".to_vec();
        sink.eof = true;
        sink.unpad();
        assert_eq!(&sink.payload, b"plain bytes");
    }

    #[test]
    fn tls_detection() {
        assert!(VisionStream::looks_like_tls(&[
            0x16, 0x03, 0x01, 0x00, 0x05, 0x00
        ]));
        assert!(VisionStream::looks_like_tls(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x01
        ]));
        assert!(!VisionStream::looks_like_tls(b"GET / HTTP/1.1"));
    }

    #[tokio::test]
    async fn reads_back_what_the_peer_wrote() {
        // two frames, delivered in pieces
        let framed = {
            let (writer, _) = pair();
            let mut bytes = writer.frame(b"alpha", 0u8);
            bytes.extend_from_slice(&writer.frame(b"beta", PADDING_END)[16..]);
            bytes
        };
        let (client, server) = tokio::io::duplex(4096);
        let mut sink = VisionStream::new(Box::new(client), uuid());
        let mut server = server;
        tokio::spawn(async move {
            for chunk in framed.chunks(7) {
                let _ = server.write_all(chunk).await;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            let _ = server.shutdown().await;
        });
        let mut out = Vec::new();
        sink.read_to_end(&mut out)
            .await
            .expect("read through the framing");
        assert_eq!(out, b"alphabeta");
    }
}
