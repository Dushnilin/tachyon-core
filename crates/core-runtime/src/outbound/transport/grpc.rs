//! gRPC (v2ray "gun") transport client: HTTP/2 prior-knowledge (or ALPN `h2`
//! over TLS) carrying a bidirectional `POST /{service_name}/Tun` stream of
//! gRPC `Hunk` messages — the wire format shared by sing-box's full grpc-go
//! client and the gun-lite implementation:
//!
//! ```text
//! 00 <u32be len> 0A <varint data_len> <data>
//! ```
//!
//! (`00` = uncompressed, `len` = protobuf payload size, `0A` = protobuf
//! field 1 length-delimited, varint = byte length of the payload bytes.)

use std::io;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::AnyStream;

use super::h2io::{H2Io, H2Stream};

pub(super) async fn connect(
    stream: AnyStream,
    service_name: &str,
    authority: &str,
    secure: bool,
) -> io::Result<AnyStream> {
    let (send_request, connection) = super::h2io::client_builder()
        .handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("grpc: h2 handshake: {e}")))?;
    let conn_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("grpc: h2 ready: {e}")))?;

    let scheme = if secure { "https" } else { "http" };
    let path = format!("/{service_name}/Tun");
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("{scheme}://{authority}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "grpc-go/1.48.0")
        .body(())
        .map_err(|e| io::Error::other(format!("grpc: build request: {e}")))?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("grpc: send_request: {e}")))?;

    Ok(Box::new(GrpcStream {
        io: H2Io {
            h2: H2Stream::new(response, send, conn_task),
        },
        data_left: 0,
        skip: 0,
    }))
}

pub(crate) struct GrpcStream {
    io: H2Io,
    /// Payload bytes of the current Hunk still to be handed out. The payload is
    /// served straight out of the h2 receive buffer as it arrives; a whole
    /// message is never gathered, copied or allocated for.
    data_left: usize,
    /// Bytes of the current message that follow its payload (unknown protobuf
    /// fields, normally none), dropped before the next message starts.
    skip: usize,
}

impl GrpcStream {
    fn encode_frame(data: &[u8]) -> Vec<u8> {
        let mut varint = [0u8; 10];
        let vl = write_varint(data.len() as u64, &mut varint);
        let inner_len = 1 + vl + data.len();
        let mut out = Vec::with_capacity(5 + inner_len);
        out.push(0);
        out.extend_from_slice(&(inner_len as u32).to_be_bytes());
        out.push(0x0A);
        out.extend_from_slice(&varint[..vl]);
        out.extend_from_slice(data);
        out
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            let pending = &mut this.io.h2.pending;
            if this.data_left > 0 {
                if !pending.is_empty() {
                    let n = out.remaining().min(this.data_left).min(pending.len());
                    out.put_slice(&pending[..n]);
                    pending.advance(n);
                    this.data_left -= n;
                    return Poll::Ready(Ok(()));
                }
            } else if this.skip > 0 {
                let n = this.skip.min(pending.len());
                if n > 0 {
                    pending.advance(n);
                    this.skip -= n;
                    continue;
                }
            } else if let Some((data, skip)) = start_hunk(pending)? {
                this.data_left = data;
                this.skip = skip;
                continue;
            }
            if this.io.h2.is_eof() {
                if !this.io.h2.pending.is_empty() || this.data_left > 0 || this.skip > 0 {
                    return Poll::Ready(Err(io::Error::other("grpc: stream ended mid-frame")));
                }
                return Poll::Ready(Ok(()));
            }
            ready!(this.io.h2.poll_recv_more(cx))?;
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.io.h2.has_out() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let frame = Self::encode_frame(buf);
            self.io.h2.stage(frame, buf.len());
        }
        ready!(self.io.h2.poll_flush_out(cx))?;
        Poll::Ready(Ok(self.io.h2.take_report()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.io.h2.poll_flush_out(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.io.h2.poll_shutdown(cx)
    }
}

fn write_varint(mut v: u64, out: &mut [u8; 10]) -> usize {
    let mut i = 0;
    while v >= 0x80 {
        out[i] = v as u8 | 0x80;
        v >>= 7;
        i += 1;
    }
    out[i] = v as u8;
    i + 1
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut i = 0;
    loop {
        let b = *buf.get(i)?;
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
        i += 1;
        if i >= 10 {
            return None;
        }
    }
}

/// Consume the header of the next Hunk (5-byte gRPC prefix, protobuf tag and
/// length varint) and return `(payload_len, trailing_len)`: the payload bytes
/// that follow in the buffer, and any bytes of the message after them. Only
/// the header has to be buffered; the payload is served as it arrives.
fn start_hunk(raw: &mut Bytes) -> io::Result<Option<(usize, usize)>> {
    if raw.len() < 5 {
        return Ok(None);
    }
    if raw[0] != 0 {
        return Err(io::Error::other("grpc: compressed frames unsupported"));
    }
    let len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
    if len == 0 {
        return Err(io::Error::other("grpc: empty Hunk payload"));
    }
    // tag (1) + varint (at most 10) is all that has to be present.
    let want = len.min(11);
    let have = (raw.len() - 5).min(want);
    if have == 0 {
        return Ok(None);
    }
    let head = &raw[5..5 + have];
    if head[0] != 0x0A {
        return Err(io::Error::other("grpc: unexpected Hunk payload tag"));
    }
    let Some((vlen, vl)) = read_varint(&head[1..]) else {
        if have < want {
            return Ok(None);
        }
        return Err(io::Error::other("grpc: bad Hunk length varint"));
    };
    let used = 1 + vl;
    let vlen = usize::try_from(vlen)
        .ok()
        .filter(|v| used.checked_add(*v).is_some_and(|end| end <= len))
        .ok_or_else(|| io::Error::other("grpc: truncated Hunk payload"))?;
    raw.advance(5 + used);
    Ok(Some((vlen, len - used - vlen)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_roundtrip() {
        let mut both = GrpcStream::encode_frame(b"hello");
        both.extend_from_slice(&GrpcStream::encode_frame(&[0x5A; 40000]));
        let mut raw = Bytes::from(both);
        let (n, skip) = start_hunk(&mut raw).unwrap().expect("first hunk");
        assert_eq!((n, skip), (5, 0));
        assert_eq!(&raw[..n], &b"hello"[..]);
        raw.advance(n);
        let (n, skip) = start_hunk(&mut raw).unwrap().expect("second hunk");
        assert_eq!((n, skip), (40000, 0));
        assert!(raw[..n].iter().all(|b| *b == 0x5A));
        raw.advance(n);
        assert!(raw.is_empty());
        assert!(start_hunk(&mut raw).unwrap().is_none());
    }

    #[test]
    fn hunk_partial_buffer() {
        let frame = GrpcStream::encode_frame(b"partial");
        let mut raw = Bytes::copy_from_slice(&frame[..4]);
        assert!(start_hunk(&mut raw).unwrap().is_none());
        let mut raw = Bytes::from(frame);
        assert_eq!(start_hunk(&mut raw).unwrap().unwrap(), (7, 0));
        assert_eq!(&raw[..], &b"partial"[..]);
    }

    #[test]
    fn hunk_header_only_is_enough() {
        let frame = GrpcStream::encode_frame(&[7u8; 1000]);
        let mut raw = Bytes::copy_from_slice(&frame[..8]);
        assert_eq!(start_hunk(&mut raw).unwrap().unwrap(), (1000, 0));
        assert!(raw.is_empty());
    }

    #[test]
    fn hunk_trailing_fields_are_skipped() {
        // Payload: data field (3 bytes) followed by 2 bytes of an unknown field.
        let mut raw = Bytes::copy_from_slice(&b"\x00\x00\x00\x00\x07\x0a\x03abc\x10\x01"[..]);
        assert_eq!(start_hunk(&mut raw).unwrap().unwrap(), (3, 2));
    }

    #[test]
    fn hunk_rejects_compression_flag() {
        let mut raw = Bytes::copy_from_slice(&b"\x01\x00\x00\x00\x01\x0a\x01x"[..]);
        assert!(start_hunk(&mut raw).is_err());
    }

    #[test]
    fn hunk_rejects_overlong_data() {
        let mut raw = Bytes::copy_from_slice(&b"\x00\x00\x00\x00\x03\x0a\x09x"[..]);
        assert!(start_hunk(&mut raw).is_err());
    }

    #[test]
    fn varint_boundaries() {
        for v in [0u64, 1, 127, 128, 300, 16383, 16384, 40000, u64::MAX] {
            let mut buf = [0u8; 10];
            let n = write_varint(v, &mut buf);
            assert_eq!(read_varint(&buf[..n]), Some((v, n)), "v={v}");
        }
    }
}
