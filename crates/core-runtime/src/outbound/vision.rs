//! VLESS `flow: xtls-rprx-vision` (Xray's Vision).
//!
//! Vision frames the payload instead of encrypting it: every write is wrapped as
//! `[command:u8, content_len:u16, padding_len:u16, content, padding]`, and strips
//! the same framing on the way back. Padding keeps the small writes of a TLS
//! handshake looking like record traffic, which is the point of the flow.
//! Note that the user UUID belongs strictly to the VLESS protocol request header,
//! not the Vision stream framing.
//!
//! The framing is *transient*, and getting that wrong breaks the flow in both
//! directions. `CommandPaddingEnd` does not mean "this frame is the last one",
//! it means "the framing stops here, treat the rest of the stream as raw"; the
//! sender only sends it once, on the way out of the padding phase, and writes
//! nothing but payload after that. So the writer here sends
//! `CommandPaddingContinue` on every frame of the phase and exactly one
//! `CommandPaddingEnd` on the transition, and the phase ends either at the
//! first TLS 1.3 application-data record or, for traffic that never looked
//! like TLS, after `PACKETS_TO_FILTER` writes. `XtlsUnpadding` in the
//! reference is the other half: `Continue` keeps parsing frames, anything else
//! hands the rest through untouched.
//!
//! Ported from `sing-vmess/vless/vision.go`. The XTLS "direct" mode (writing
//! through the TLS layer without re-encrypting, chosen once a TLS 1.3 handshake
//! is seen) is deliberately not implemented: it needs a handle to the raw
//! connection below the cipher. Receiving `CommandPaddingDirect` switches the
//! peer's read direction to raw transport after its final padded frame.

use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::AnyStream;

/// The three commands of the reference (`proxy.go`). Only Continue and End are
/// ever sent; Direct would need the raw connection underneath.
const PADDING_CONTINUE: u8 = 0x00;
const PADDING_END: u8 = 0x01;
const PADDING_DIRECT: u8 = 0x02;

/// Keep small writes padded to roughly a TLS record, as the reference does.
const TLS_PADDING_FLOOR: usize = 900;
const TLS_PADDING_SPREAD: usize = 500;
const PLAIN_PADDING_SPREAD: usize = 256;

/// The reference's `numberOfPacketToFilter`: how many writes of traffic that
/// never looked like TLS stay in the padding phase before the compatibility
/// escape hatch ends it.
const PACKETS_TO_FILTER: usize = 8;

/// Content is a `u16` on the wire, so a bigger write is more than one frame.
const MAX_CONTENT: usize = u16::MAX as usize;

/// How much is asked of the inner stream per read. It lands straight in the
/// framing buffer, so there is nothing to copy it out of.
const READ_CHUNK: usize = 32 * 1024;

/// TLS 1.3 application data, `TlsApplicationDataStart` in the reference. Its
/// arrival is what takes the padding phase out.
const TLS_APP_DATA: [u8; 3] = [0x17, 0x03, 0x03];

pub struct VisionStream {
    inner: AnyStream,
    /// the reference's `isPadding`: framing covers the first packets only, and
    /// every write after the transition is the payload itself
    padding: bool,
    /// once a TLS handshake has passed through, padding grows to record size
    saw_tls: bool,
    /// the reference's `numberOfPacketToFilter`
    packets_to_filter: usize,
    /// a frame handed to the inner stream that it has not taken whole yet
    framed: Vec<u8>,
    /// how much of `framed` is already on the wire
    framed_at: usize,
    /// bytes of the caller's buffer the frame in flight stands for
    pending: usize,
    /// user UUID sent on the very first frame (reference XtlsPadding)
    uuid: Option<[u8; 16]>,
    /// expected user UUID on the first incoming frame (reference XtlsUnpadding)
    expected_uuid: Option<[u8; 16]>,
    // inbound framing state, straight from the reference field names
    remaining_content: i64,
    remaining_padding: i64,
    current_command: u8,
    /// bytes read from `inner` but not framed yet
    raw: BytesMut,
    /// framed payload waiting for the caller
    payload: BytesMut,
    eof: bool,
    direct_read: bool,
}

impl VisionStream {
    pub fn new(inner: AnyStream, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            padding: true,
            saw_tls: false,
            packets_to_filter: PACKETS_TO_FILTER,
            framed: Vec::new(),
            framed_at: 0,
            pending: 0,
            uuid: Some(uuid),
            expected_uuid: Some(uuid),
            remaining_content: 0,
            remaining_padding: 0,
            current_command: PADDING_CONTINUE,
            raw: BytesMut::new(),
            payload: BytesMut::new(),
            eof: false,
            direct_read: false,
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

    /// `VisionConn.padding`, built into `self.framed` so the phase costs no
    /// allocation per write.
    fn build_frame(&mut self, content: &[u8], command: u8) {
        let padding_len = if content.len() < TLS_PADDING_FLOOR && self.saw_tls {
            Self::random_below(TLS_PADDING_SPREAD) + TLS_PADDING_FLOOR - content.len()
        } else {
            Self::random_below(PLAIN_PADDING_SPREAD)
        };
        self.framed.clear();
        let uuid_len = if self.uuid.is_some() { 16 } else { 0 };
        self.framed.reserve(uuid_len + 5 + content.len() + padding_len);
        if let Some(uuid) = self.uuid.take() {
            self.framed.extend_from_slice(&uuid);
        }
        self.framed.push(command);
        self.framed
            .extend_from_slice(&(content.len() as u16).to_be_bytes());
        self.framed
            .extend_from_slice(&(padding_len as u16).to_be_bytes());
        self.framed.extend_from_slice(content);
        self.framed.resize(self.framed.len() + padding_len, 0);
    }

    /// The reference filters the first packets to tell TLS 1.3 from TLS 1.2;
    /// we only need the coarse "is TLS involved" answer for the padding profile.
    fn looks_like_tls(buffer: &[u8]) -> bool {
        buffer.len() > 5 && (buffer[0] == 0x16 || (buffer[0] == 0x01 && buffer[5] == 0x01))
    }

    /// One complete TLS record, `IsCompleteRecord` in the reference: a partial
    /// record must not be what takes the padding phase out.
    fn is_tls_app_data(buffer: &[u8]) -> bool {
        if buffer.len() < 5 || buffer[..3] != TLS_APP_DATA {
            return false;
        }
        let body = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
        buffer.len() >= 5 + body
    }

    /// `VisionConn.Write`'s choice of command for the frame it is about to
    /// build, and the decision to leave the padding phase for good.
    fn next_command(&mut self, content: &[u8]) -> u8 {
        let command = if self.saw_tls && Self::is_tls_app_data(content) {
            PADDING_END
        } else if !self.saw_tls && self.packets_to_filter <= 1 {
            // traffic that never turned out to be TLS leaves the phase early, for
            // compatibility with receivers that gave up waiting
            PADDING_END
        } else {
            PADDING_CONTINUE
        };
        if command != PADDING_CONTINUE {
            self.padding = false;
        }
        command
    }

    /// `VisionConn.filterTLS`, run once per write on the way out.
    fn filter(&mut self, buffer: &[u8]) {
        if !self.saw_tls {
            self.saw_tls = Self::looks_like_tls(buffer);
        }
        if self.packets_to_filter > 0 {
            self.packets_to_filter -= 1;
        }
    }

    /// `VisionConn.unPadding` over `raw`, moving payload into `self.payload`.
    fn unpad(&mut self) {
        let mut index = 0usize;
        while index < self.raw.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if let Some(expected) = self.expected_uuid {
                    if self.raw.len() < index + 21 {
                        if self.eof {
                            self.payload.extend_from_slice(&self.raw[index..]);
                            index = self.raw.len();
                        }
                        break;
                    }
                    if self.raw[index..index + 16] == expected {
                        index += 16;
                        self.expected_uuid = None;
                    } else if self.raw[index] <= PADDING_DIRECT {
                        // Peer omitted UUID (e.g. tests or older peer)
                        self.expected_uuid = None;
                    } else {
                        // Peer is not framing vision; fallback to raw stream
                        self.expected_uuid = None;
                        self.current_command = 0xFF;
                        self.payload.extend_from_slice(&self.raw[index..]);
                        index = self.raw.len();
                        break;
                    }
                }
                // any command but Continue ends the framing, and whatever
                // follows it is payload
                if self.current_command != PADDING_CONTINUE {
                    self.payload.extend_from_slice(&self.raw[index..]);
                    index = self.raw.len();
                    break;
                }
                if self.raw.len() < index + 5 {
                    if self.eof {
                        self.payload.extend_from_slice(&self.raw[index..]);
                        index = self.raw.len();
                    }
                    break;
                }
                let header = &self.raw[index..index + 5];
                // Non-vision fallback: if the command byte is unknown (> 2),
                // the peer is not framing; pass remaining raw bytes through.
                if header[0] > PADDING_DIRECT {
                    self.current_command = 0xFF;
                    self.payload.extend_from_slice(&self.raw[index..]);
                    index = self.raw.len();
                    break;
                }
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
        // split_to moves the consumption point instead of memmoving the
        // remainder to the front of the buffer on every unpad
        if index > 0 {
            let _ = self.raw.split_to(index);
        }
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
            if !this.direct_read
                && this.current_command == PADDING_DIRECT
                && this.remaining_content == 0
                && this.remaining_padding == 0
            {
                if !crate::inbound::enable_vision_direct_read(&mut this.inner) {
                    return std::task::Poll::Ready(Err(io::Error::other(
                        "Vision Direct requires a raw-capable TLS stream",
                    )));
                }
                this.direct_read = true;
            }
            if !this.payload.is_empty() {
                let take = this.payload.len().min(out.remaining());
                out.put_slice(&this.payload[..take]);
                let _ = this.payload.split_to(take);
                return std::task::Poll::Ready(Ok(()));
            }
            if this.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            if this.raw.capacity() - this.raw.len() < READ_CHUNK {
                this.raw.reserve(READ_CHUNK);
            }
            // read straight into the framing buffer: a staging array and a copy
            // out of it per read is what the server TLS path stopped doing
            let base = this.raw.len();
            let got = {
                let spare = this.raw.spare_capacity_mut();
                let mut buf = ReadBuf::uninit(&mut spare[..READ_CHUNK]);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                    std::task::Poll::Ready(Ok(())) => buf.filled().len(),
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error));
                    }
                    std::task::Poll::Pending => {
                        // a partial frame stays in `raw` for the next poll
                        return std::task::Poll::Pending;
                    }
                }
            };
            if got == 0 {
                this.eof = true;
                // a closed peer may still leave a tail in the framing
                this.unpad();
            } else {
                // SAFETY: `got` bytes past `base` were just initialised by the
                // read above, inside the buffer `spare` pointed into
                unsafe { this.raw.set_len(base + got) };
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
        loop {
            // a frame the inner stream has only taken part of: the rest of it
            // still has to go out before anything else may be framed
            if this.framed_at < this.framed.len() {
                match std::pin::Pin::new(&mut this.inner)
                    .poll_write(cx, &this.framed[this.framed_at..])
                {
                    std::task::Poll::Ready(Ok(0)) => {
                        return std::task::Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    std::task::Poll::Ready(Ok(n)) => {
                        this.framed_at += n;
                        if this.framed_at == this.framed.len() {
                            this.framed.clear();
                            this.framed_at = 0;
                            let done = this.pending;
                            this.pending = 0;
                            return std::task::Poll::Ready(Ok(done));
                        }
                        // the frame is still going out: reporting the payload
                        // written now would drop the tail of the frame
                        continue;
                    }
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error));
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            if this.pending > 0 {
                let done = this.pending;
                this.pending = 0;
                return std::task::Poll::Ready(Ok(done));
            }
            if buf.is_empty() {
                return std::task::Poll::Ready(Ok(0));
            }
            if !this.padding {
                // the phase is over: the payload goes out as it is, with no
                // header, no padding and no copy
                return std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            // one frame per `u16` of content
            let take = buf.len().min(MAX_CONTENT);
            this.filter(&buf[..take]);
            let command = this.next_command(&buf[..take]);
            this.build_frame(&buf[..take], command);
            this.pending = take;
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
        let mut v = VisionStream::new(boxed, uuid());
        v.uuid = None;
        v.expected_uuid = None;
        (v, server)
    }

    /// A frame built by hand, the way the reference puts it on the wire.
    fn wire_frame(command: u8, content: &[u8], padding: usize) -> BytesMut {
        let mut out = Vec::new();
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
        BytesMut::from(out.as_slice())
    }

    /// A frame as it goes on the wire.
    fn frame_of(stream: &mut VisionStream, content: &[u8]) -> Vec<u8> {
        stream.build_frame(content, PADDING_CONTINUE);
        stream.framed.clone()
    }

    fn padding_of(frame: &[u8]) -> usize {
        usize::from(u16::from_be_bytes([frame[3], frame[4]]))
    }

    #[test]
    fn first_frame_carries_the_five_byte_header() {
        let (mut vision, _) = pair();
        let frame = frame_of(&mut vision, b"hello");
        assert_eq!(frame[0], PADDING_CONTINUE, "command");
        assert_eq!(u16::from_be_bytes([frame[1], frame[2]]), 5);
        let padding = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        assert_eq!(&frame[5..10], b"hello");
        assert_eq!(frame.len(), 5 + 5 + padding);
        assert!(
            frame[10..].iter().all(|byte| *byte == 0),
            "padding is zeroed"
        );
    }

    #[test]
    fn frames_start_with_five_byte_header() {
        let (mut vision, _) = pair();
        vision.build_frame(b"one", PADDING_CONTINUE);
        let first = vision.framed.clone();
        vision.build_frame(b"two", PADDING_CONTINUE);
        let second = vision.framed.clone();
        assert_eq!(first[0], PADDING_CONTINUE);
        assert_eq!(u16::from_be_bytes([first[1], first[2]]), 3);
        assert_eq!(second[0], PADDING_CONTINUE);
        assert_eq!(u16::from_be_bytes([second[1], second[2]]), 3);
    }

    #[test]
    fn padding_grows_to_a_tls_record_only_after_tls() {
        let (mut vision, _) = pair();
        let small = frame_of(&mut vision, b"x");
        let padding = padding_of(&small);
        assert!(
            padding < PLAIN_PADDING_SPREAD,
            "before a handshake is seen the padding stays plain"
        );
        vision.saw_tls = true;
        let padded = frame_of(&mut vision, &[0u8; 100]);
        let padding = padding_of(&padded);
        assert!(
            (TLS_PADDING_FLOOR - 100..TLS_PADDING_FLOOR + TLS_PADDING_SPREAD).contains(&padding),
            "with TLS the padding fills the record, got {padding}"
        );
    }

    /// The bug that made vision unusable in both directions: End on every frame
    /// tells the peer to stop parsing, so the second frame's header and padding
    /// reach the application.
    #[test]
    fn the_padding_phase_is_transient_and_then_writes_are_raw() {
        let (mut source, _) = pair();
        let mut wire = BytesMut::new();
        let mut commands = Vec::new();
        let mut writes = 0usize;
        while source.padding && writes < PACKETS_TO_FILTER + 2 {
            // spaces, so `looks_like_tls` does not mistake the payload for a
            // handshake and hold the phase open
            let payload = vec![b' '; 32];
            source.filter(&payload);
            let command = source.next_command(&payload);
            commands.push(command);
            source.build_frame(&payload, command);
            wire.extend_from_slice(&source.framed);
            writes += 1;
        }
        assert!(
            writes <= PACKETS_TO_FILTER,
            "the phase ends inside the filter window, took {writes} writes"
        );
        assert_eq!(
            commands.iter().filter(|c| **c == PADDING_END).count(),
            1,
            "End goes out exactly once, got {commands:?}"
        );
        assert_eq!(
            *commands.last().expect("at least one write"),
            PADDING_END,
            "and it is the last frame of the phase"
        );
        assert!(!source.padding, "the phase stays ended");

        // the peer sees every payload byte and no framing past the phase
        let (mut sink, _) = pair();
        sink.raw = wire;
        sink.unpad();
        assert_eq!(sink.payload.len(), writes * 32);
        assert!(sink.raw.is_empty(), "the framing is fully consumed");
    }

    /// A reader must treat anything but Continue as "framing over", which is
    /// what the reference does with End and with Direct.
    #[test]
    fn any_command_but_continue_hands_the_rest_through() {
        for command in [PADDING_END, 0x02] {
            let mut wire = wire_frame(PADDING_CONTINUE, b"framed", 4);
            wire.extend_from_slice(&wire_frame(command, b"last", 2));
            wire.extend_from_slice(b"raw tail");
            let (mut sink, _) = pair();
            sink.raw = wire;
            sink.unpad();
            assert_eq!(
                &sink.payload[..],
                &b"framedlastraw tail"[..],
                "command {command} must end the framing"
            );
            assert!(sink.raw.is_empty());
        }
    }

    /// The transition the reference keys on: the first complete TLS 1.3
    /// application-data record.
    #[test]
    fn tls_application_data_ends_the_phase_and_a_partial_record_does_not() {
        let (mut vision, _) = pair();
        vision.saw_tls = true;
        let mut record = TLS_APP_DATA.to_vec();
        record.extend_from_slice(&40u16.to_be_bytes());
        record.extend_from_slice(&[0u8; 40]);
        assert!(VisionStream::is_tls_app_data(&record));
        assert_eq!(vision.next_command(&record), PADDING_END);
        assert!(
            !VisionStream::is_tls_app_data(&record[..20]),
            "half a record is not a reason to stop padding"
        );
    }

    /// A frame larger than a `u16` is two frames, and no byte of the second is
    /// dropped on the floor.
    #[tokio::test]
    async fn content_larger_than_a_u16_is_framed_in_pieces() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut source = VisionStream::new(Box::new(a), uuid());
        let mut sink = VisionStream::new(Box::new(b), uuid());
        let payload = vec![0xABu8; MAX_CONTENT + 100];
        let want = payload.len();
        let writer = tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < payload.len() {
                sent += source.write(&payload[sent..]).await.expect("write");
            }
        });
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sink.read_to_end(&mut got),
        )
        .await
        .expect("no hang")
        .expect("read back");
        writer.await.expect("writer");
        assert_eq!(got.len(), want, "no byte of an oversized write is lost");
        assert!(got.iter().all(|byte| *byte == 0xAB), "and none is mangled");
    }

    /// A frame the socket takes in pieces must still go out whole: reporting
    /// success while the tail of the frame is unwritten loses it.
    #[tokio::test]
    async fn a_partially_written_frame_is_finished() {
        let (client, server) = tokio::io::duplex(64);
        let boxed: AnyStream = Box::new(client);
        let mut vision = VisionStream::new(boxed, uuid());
        let mut server = server;
        let want = 40usize;
        let writer = tokio::spawn(async move {
            let payload = vec![0x5Au8; want];
            let mut sent = 0usize;
            while sent < payload.len() {
                sent += vision.write(&payload[sent..]).await.expect("write");
            }
        });
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.read_to_end(&mut got),
        )
        .await
        .expect("no hang")
        .expect("read back");
        writer.await.expect("writer");

        assert_eq!(&got[..16], &uuid(), "uuid prefix");
        assert_eq!(got[16], PADDING_CONTINUE, "command");
        assert_eq!(
            usize::from(u16::from_be_bytes([got[17], got[18]])),
            want,
            "content length"
        );
        let padding = usize::from(u16::from_be_bytes([got[19], got[20]]));
        assert_eq!(
            got.len(),
            16 + 5 + want + padding,
            "the frame went out whole, padding and all"
        );
        assert!(got[21..21 + want].iter().all(|byte| *byte == 0x5A));
    }

    #[test]
    fn unpadding_strips_headers_and_padding() {
        let mut bytes = wire_frame(PADDING_CONTINUE, b"first", 3);
        bytes.extend_from_slice(&wire_frame(PADDING_CONTINUE, b"second", 5));

        let (mut sink, _) = pair();
        sink.raw = bytes;
        sink.unpad();
        assert_eq!(&sink.payload[..], &b"firstsecond"[..]);
        assert!(sink.raw.is_empty(), "the framing is fully consumed");
    }

    #[test]
    fn first_inbound_frame_unpads_cleanly() {
        let framed = wire_frame(PADDING_CONTINUE, b"payload", 1);
        let (mut sink, _) = pair();
        sink.raw = framed;
        sink.unpad();
        assert_eq!(&sink.payload[..], &b"payload"[..]);
    }

    #[test]
    fn unframed_traffic_passes_through() {
        let (mut sink, _) = pair();
        sink.raw = BytesMut::from(&b"plain bytes"[..]);
        sink.eof = true;
        sink.unpad();
        assert_eq!(&sink.payload[..], &b"plain bytes"[..]);
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
        let mut framed = wire_frame(PADDING_CONTINUE, b"alpha", 2);
        framed.extend_from_slice(&wire_frame(PADDING_CONTINUE, b"beta", 7));
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
