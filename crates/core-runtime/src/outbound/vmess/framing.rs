//! VMess body framing: SHAKE128 length masking/padding, body AEAD
//! (aes-128-gcm / chacha20-poly1305 with BE16-counter nonces), the
//! authenticated-length (`auth_len`) variant, the legacy aes-128-cfb body
//! with FNV1a-32 chunk checksums, and the incremental frame assembler for
//! the download direction.

use std::io;
use std::task::{Context, Poll};

use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::{BufDecryptor, BufEncryptor};
use chacha20poly1305::ChaCha20Poly1305;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, ReadBuf};

use crate::fastgcm::Gcm;
use crate::inbound::AnyStream;
use crate::outbound::shadowsocks::crypto::random_bytes;
use crate::outbound::vmess::kdf::{chacha_key, fnv1a32, kdf16};

pub(crate) const WRITE_CHUNK: usize = 15000;
/// How much of one `write` is framed into one buffer: four full chunks, which
/// is what the relay hands over at a time.
pub(crate) const WRITE_BATCH: usize = 4 * WRITE_CHUNK;
const CIPHER_OVERHEAD: usize = 16;
const MAX_PADDING: u16 = 64;

/// Read-ahead the frame buffer aims for: enough that one read brings in several
/// chunks rather than the two bytes of a length block.
const READ_CHUNK: usize = 32 * 1024;
/// Hard ceiling on the frame buffer: one whole chunk (a `u16` of ciphertext plus
/// its tag) behind the length block, plus the read-ahead.
///
/// The buffer used to be grown with `Vec::reserve` every time it filled, and
/// `reserve` rounds up to twice the capacity -- so a connection that carried a
/// gigabyte ended up holding a buffer to match, hundreds of megabytes of pages
/// that had to be faulted in and copied. It is now sized in one step, to what
/// the read needs and never past this.
const FRAME_ROOM: usize = 2 + CIPHER_OVERHEAD + u16::MAX as usize + READ_CHUNK;

/// Only these two securities seal the body; `none` frames it in the clear.
fn has_aead(security: u8) -> bool {
    security == super::SEC_AES128_GCM || security == super::SEC_CHACHA20_POLY1305
}

pub(crate) type CfbEncrypt = BufEncryptor<Aes128>;
pub(crate) type CfbDecrypt = BufDecryptor<Aes128>;

/// `GenerateChunkNonce`: nonce = BE16(counter) || iv[2..12].
fn chunk_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// Body cipher; chacha keys expand via `GenerateChacha20Poly1305Key`.
pub(crate) enum BodyAead {
    Aes(Box<Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl BodyAead {
    pub(crate) fn new(security: u8, key16: &[u8; 16]) -> Self {
        if security == super::SEC_CHACHA20_POLY1305 {
            Self::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&chacha_key(key16)).expect("chacha key length"),
            ))
        } else {
            Self::Aes(Box::new(Gcm::new(key16)))
        }
    }

    /// Keyed with KDF16(key, "auth_len"); cipher type follows the body security.
    pub(crate) fn auth_len(security: u8, key16: &[u8; 16]) -> Self {
        Self::new(security, &kdf16(key16, &[b"auth_len"]))
    }

    pub(crate) fn seal(&self, counter: u16, iv: &[u8; 16], buf: &mut Vec<u8>) -> io::Result<()> {
        self.seal_from(counter, iv, buf, 0)
    }

    /// Seal `buf[from..]` where it lies and append the tag: a frame is built in
    /// one buffer instead of a copy of the plaintext per chunk.
    pub(crate) fn seal_from(
        &self,
        counter: u16,
        iv: &[u8; 16],
        buf: &mut Vec<u8>,
        from: usize,
    ) -> io::Result<()> {
        let nonce = chunk_nonce(iv, counter);
        let tag: [u8; 16] = match self {
            BodyAead::Aes(cipher) => cipher.seal(&nonce, &[], &mut buf[from..]),
            BodyAead::ChaCha(cipher) => cipher
                .encrypt_in_place_detached((&nonce).into(), &[], &mut buf[from..])
                .map_err(|_| io::Error::other("seal failed"))?
                .into(),
        };
        buf.extend_from_slice(&tag);
        Ok(())
    }

    /// Open one `[ciphertext || tag]` block where it lies, leaving the plaintext
    /// in its place, and say how many bytes of it there are.
    ///
    /// A block, not a buffer: the assembler reads ahead, so the length block sits
    /// at the front of a buffer that already holds the chunk behind it, and a
    /// version that truncated the buffer would throw that read-ahead away on
    /// every chunk.
    pub(crate) fn open(&self, counter: u16, iv: &[u8; 16], block: &mut [u8]) -> io::Result<usize> {
        if block.len() < CIPHER_OVERHEAD {
            return Err(io::Error::other("chunk too short"));
        }
        let nonce = chunk_nonce(iv, counter);
        let split = block.len() - CIPHER_OVERHEAD;
        let (data, tag) = block.split_at_mut(split);
        let tag: [u8; 16] = (*tag).try_into().expect("tag is 16 bytes");
        let ok = match self {
            BodyAead::Aes(cipher) => cipher.open(&nonce, &[], data, &tag),
            BodyAead::ChaCha(cipher) => cipher
                .decrypt_in_place_detached((&nonce).into(), &[], data, (&tag).into())
                .is_ok(),
        };
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk auth failed",
            ));
        }
        Ok(split)
    }
}

/// Per-direction SHAKE128 stream seeded with that direction's IV; draws pad
/// lengths first, then masks, sharing one instance when both are enabled.
pub(crate) struct Shake(Shake128Reader);

impl Shake {
    pub(crate) fn new(seed: &[u8; 16]) -> Self {
        let mut hash = Shake128::default();
        hash.update(seed);
        Self(hash.finalize_xof())
    }

    pub(crate) fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.0.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}

/// Upload frame builder (stream-chunk, auth-len, or legacy checksum variant).
pub(crate) struct BodyWriter {
    body: Option<BodyAead>,
    body_iv: [u8; 16],
    body_count: u16,
    auth: Option<BodyAead>,
    auth_iv: [u8; 16],
    auth_count: u16,
    shake: Option<Shake>,
    global_padding: bool,
    chunk_masking: bool,
    authenticated_length: bool,
    /// Legacy body: CFB-128 stream over requestKey/requestIV; frames carry a
    /// FNV1a-32 checksum prefix instead of AEAD protection.
    cfb: Option<CfbEncrypt>,
    checksum: bool,
}

impl BodyWriter {
    pub(crate) fn new(
        security: u8,
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
        global_padding: bool,
        chunk_masking: bool,
        authenticated_length: bool,
    ) -> Self {
        let legacy = security == super::SEC_LEGACY;
        Self {
            body: has_aead(security).then(|| BodyAead::new(security, request_key)),
            body_iv: *request_iv,
            body_count: 0,
            auth: (!legacy && authenticated_length)
                .then(|| BodyAead::auth_len(security, request_key)),
            auth_iv: *request_iv,
            auth_count: 0,
            shake: (!legacy && (global_padding || chunk_masking)).then(|| Shake::new(request_iv)),
            global_padding: !legacy && global_padding,
            chunk_masking: !legacy && chunk_masking,
            authenticated_length: !legacy && authenticated_length,
            cfb: legacy.then(|| {
                CfbEncrypt::new_from_slices(request_key, request_iv).expect("cfb key/iv length")
            }),
            checksum: legacy,
        }
    }

    /// One frame for one chunk of plaintext (`data.len() <= WRITE_CHUNK`),
    /// appended to `out`, so several chunks of one write leave in one buffer and
    /// one syscall, and the plaintext is sealed where it lies.
    pub(crate) fn frame_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        debug_assert!(!data.is_empty() && data.len() <= WRITE_CHUNK);

        if self.checksum {
            let from = out.len();
            out.extend_from_slice(&(data.len() as u16).wrapping_add(4).to_be_bytes());
            out.extend_from_slice(&fnv1a32(data).to_be_bytes());
            out.extend_from_slice(data);
            if let Some(cfb) = &mut self.cfb {
                cfb.encrypt(&mut out[from..]);
            }
            return Ok(());
        }

        let ct_len = data.len()
            + if self.body.is_some() {
                CIPHER_OVERHEAD
            } else {
                0
            };
        let mut pad_len: u16 = 0;
        if self.global_padding
            && let Some(shake) = &mut self.shake
        {
            pad_len = shake.next_u16() % MAX_PADDING;
        }

        out.reserve(2 + CIPHER_OVERHEAD + ct_len + usize::from(pad_len));
        if self.authenticated_length {
            let stored = (ct_len as u16)
                .wrapping_add(pad_len)
                .wrapping_sub(CIPHER_OVERHEAD as u16);
            let mut len_block = stored.to_be_bytes().to_vec();
            if let Some(auth) = &mut self.auth {
                auth.seal(self.auth_count, &self.auth_iv, &mut len_block)?;
                self.auth_count = self.auth_count.wrapping_add(1);
            }
            out.extend_from_slice(&len_block);
        } else {
            let mut len16 = (ct_len as u16).wrapping_add(pad_len);
            if self.chunk_masking
                && let Some(shake) = &mut self.shake
            {
                len16 ^= shake.next_u16();
            }
            out.extend_from_slice(&len16.to_be_bytes());
        }
        let from = out.len();
        out.extend_from_slice(data);
        if let Some(body) = &self.body {
            body.seal_from(self.body_count, &self.body_iv, out, from)?;
        }
        self.body_count = self.body_count.wrapping_add(1);
        if pad_len > 0 {
            let at = out.len();
            out.resize(at + usize::from(pad_len), 0);
            random_bytes(&mut out[at..])?;
        }
        Ok(())
    }
}

/// Download frame parser mirroring `StreamChunkReader` / `AEADChunkReader`
/// plus the body AEAD layer (or the legacy CFB + checksum variant). A zero
/// data length is the end of stream; a clean EOF at a frame boundary also
/// ends the stream (servers close TCP).
pub(crate) struct FrameAssembler {
    body: Option<BodyAead>,
    body_iv: [u8; 16],
    body_count: u16,
    auth: Option<BodyAead>,
    auth_iv: [u8; 16],
    auth_count: u16,
    shake: Option<Shake>,
    global_padding: bool,
    chunk_masking: bool,
    authenticated_length: bool,
    /// Legacy body: continuing CFB decrypt stream (response header stream for
    /// legacy headers, fresh response-key stream for AEAD headers).
    cfb: Option<CfbDecrypt>,
    checksum: bool,
    state: AssembleState,
    /// The frame being assembled, and how much of it has been handed to the
    /// caller. One buffer for the whole connection: the length block, the sealed
    /// chunk and the length block of the next chunk all land here, and the chunk
    /// is opened where it lies. The old assembler kept a separate read-ahead
    /// buffer, a fresh `Vec` per chunk and another one per length block, and
    /// copied the payload out of the read-ahead before opening it -- four
    /// allocations and a full copy of every byte, per chunk, per direction.
    frame: Vec<u8>,
    /// the first byte of `frame` the framing has not consumed yet
    start: usize,
    /// the opened payload is `frame[pos..end]`, while the state is `Frame`
    pos: usize,
    end: usize,
    /// where the next record starts: past the tag and the padding, which the
    /// payload range stops short of
    next: usize,
}

enum AssembleState {
    /// Collecting the length block (2 raw bytes or 18 auth-len bytes) at the
    /// front of `frame`.
    Len,
    /// `frame` owes `total` sealed bytes after the length block, `pad` of them
    /// padding.
    Data { total: usize, pad: usize },
    /// A whole chunk is assembled and opened at `frame[pos..]`, waiting for the
    /// caller to take it.
    Frame,
    Eof,
}

impl FrameAssembler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        security: u8,
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
        global_padding: bool,
        chunk_masking: bool,
        authenticated_length: bool,
        cfb: Option<CfbDecrypt>,
    ) -> Self {
        let legacy = security == super::SEC_LEGACY;
        Self {
            body: has_aead(security).then(|| BodyAead::new(security, response_key)),
            body_iv: *response_iv,
            body_count: 0,
            auth: (!legacy && authenticated_length)
                .then(|| BodyAead::auth_len(security, request_key)),
            auth_iv: *request_iv,
            auth_count: 0,
            shake: (!legacy && (global_padding || chunk_masking)).then(|| Shake::new(response_iv)),
            global_padding: !legacy && global_padding,
            chunk_masking: !legacy && chunk_masking,
            authenticated_length: !legacy && authenticated_length,
            cfb,
            checksum: legacy,
            state: AssembleState::Len,
            frame: Vec::new(),
            start: 0,
            pos: 0,
            end: 0,
            next: 0,
        }
    }

    pub(crate) fn poll_read(
        &mut self,
        inner: &mut AnyStream,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // a whole chunk is sitting in `frame`, opened: hand out as much of it
            // as the caller's buffer takes and keep the rest for the next poll
            if matches!(self.state, AssembleState::Frame) && self.pos < self.end {
                let n = out.remaining().min(self.end - self.pos);
                out.put_slice(&self.frame[self.pos..self.pos + n]);
                self.pos += n;
                return Poll::Ready(Ok(()));
            }
            let Self {
                body,
                body_iv,
                body_count,
                auth,
                auth_iv,
                auth_count,
                shake,
                global_padding,
                chunk_masking,
                authenticated_length,
                cfb,
                checksum,
                state,
                frame,
                start,
                pos,
                end,
                next,
            } = self;
            let len_block = if *authenticated_length {
                2 + CIPHER_OVERHEAD
            } else {
                2
            };
            match std::mem::replace(state, AssembleState::Eof) {
                // the chunk is out of the caller's hands. Whatever the read brought
                // in behind it stays where it is: the next length block is already
                // sitting at `end`, and moving that to the front is a copy of the
                // rest of the stream on every single chunk.
                AssembleState::Frame => {
                    *start = *next;
                    *pos = 0;
                    *end = 0;
                    *state = AssembleState::Len;
                }
                AssembleState::Eof => return Poll::Ready(Ok(())),
                AssembleState::Len => {
                    match fill(inner, cx, frame, start, len_block) {
                        Poll::Ready(Ok(true)) => {}
                        // a clean EOF at a frame boundary is how a vmess stream ends
                        Poll::Ready(Ok(false)) => continue,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            *state = AssembleState::Len;
                            return Poll::Pending;
                        }
                    }
                    let at = *start;
                    // the length block is opened where it lies; the read-ahead
                    // behind it is not touched
                    if let Some(cfb) = cfb {
                        cfb.decrypt(&mut frame[at..at + len_block]);
                    }
                    let mut length = if *authenticated_length {
                        if let Some(auth) = auth {
                            auth.open(*auth_count, auth_iv, &mut frame[at..at + len_block])?;
                            *auth_count = auth_count.wrapping_add(1);
                        }
                        u16::from_be_bytes([frame[at], frame[at + 1]])
                            .wrapping_add(CIPHER_OVERHEAD as u16)
                    } else {
                        u16::from_be_bytes([frame[at], frame[at + 1]])
                    };
                    let mut pad = 0usize;
                    if *global_padding
                        && let Some(shake) = shake
                    {
                        pad = usize::from(shake.next_u16() % MAX_PADDING);
                    }
                    if *chunk_masking
                        && !*authenticated_length
                        && let Some(shake) = shake
                    {
                        length ^= shake.next_u16();
                    }
                    match usize::from(length).checked_sub(pad) {
                        Some(0) => {
                            *state = AssembleState::Eof;
                        }
                        Some(_) => {
                            *state = AssembleState::Data {
                                total: usize::from(length),
                                pad,
                            };
                        }
                        None => {
                            return Poll::Ready(Err(io::Error::other(
                                "bad length chunk: length below padding",
                            )));
                        }
                    }
                }
                AssembleState::Data { total, pad } => {
                    match fill(inner, cx, frame, start, len_block + total) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "stream closed mid-chunk",
                            )));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            *state = AssembleState::Data { total, pad };
                            return Poll::Pending;
                        }
                    }
                    let Some(ct_len) = total.checked_sub(pad) else {
                        return Poll::Ready(Err(io::Error::other(
                            "bad chunk: length below padding",
                        )));
                    };
                    let head = *start;
                    if let Some(cfb) = cfb {
                        cfb.decrypt(&mut frame[head + len_block..head + len_block + total]);
                    }
                    // the payload starts after the length block, and after the
                    // checksum when the legacy variant carries one
                    let mut plain_at = head + len_block;
                    let mut plain_len = ct_len;
                    if *checksum {
                        if ct_len < 4 {
                            return Poll::Ready(Err(io::Error::other("checksum chunk too short")));
                        }
                        let expected = u32::from_be_bytes([
                            frame[plain_at],
                            frame[plain_at + 1],
                            frame[plain_at + 2],
                            frame[plain_at + 3],
                        ]);
                        if fnv1a32(&frame[plain_at + 4..head + len_block + total]) != expected {
                            return Poll::Ready(Err(io::Error::other(
                                "vmess: invalid chunk checksum",
                            )));
                        }
                        plain_at += 4;
                        plain_len -= 4;
                    }
                    if let Some(body) = body {
                        // the tag sits right after the ciphertext and before the
                        // padding, so the sealed block is exactly `ct_len` long
                        plain_len = body
                            .open(*body_count, body_iv, &mut frame[plain_at..plain_at + ct_len])
                            .map_err(|e| io::Error::other(format!("body-chunk: {e}")))?;
                    }
                    *body_count = body_count.wrapping_add(1);
                    *pos = plain_at;
                    *end = plain_at + plain_len;
                    *next = head + len_block + total;
                    *state = AssembleState::Frame;
                }
            }
        }
    }
}

/// Make `frame[*at..]` hold `need` bytes, reading into the free space behind it.
///
/// The tail is left where it is: a vmess stream is a chain of frames, so the bytes
/// behind the one being opened are the next frame, and moving them to the front on
/// every chunk would be a copy of the rest of the stream. Compaction happens only
/// when the buffer is full, and it is what gives the consumed prefix back.
///
/// Growth is the last resort and it is bounded. Growing on every short read, the
/// way this used to, meant `Vec::reserve` rounding up to twice the capacity each
/// time the read-ahead ran out ahead of the consumed prefix: a connection that
/// carried a gigabyte ended up with a buffer to match, and every step of that was
/// a realloc, a copy and a fresh run of pages to fault in. Sizing it once, to what
/// the read needs and never past [`FRAME_ROOM`], is the whole difference between a
/// 96 KiB buffer and the 681 MiB the same path used to report.
///
/// Returns `Ok(false)` on a clean EOF with nothing buffered, which is how a vmess
/// stream ends; a short tail is an error.
fn fill(
    inner: &mut AnyStream,
    cx: &mut Context<'_>,
    frame: &mut Vec<u8>,
    at: &mut usize,
    need: usize,
) -> Poll<io::Result<bool>> {
    while frame.len() - *at < need {
        if *at == frame.len() {
            // everything buffered has been consumed: start over, nothing to move
            frame.clear();
            *at = 0;
        } else if *at > 0 {
            // give the consumed prefix back before thinking of growing. The tail
            // is at most one frame, so this is cheap and it is what keeps the
            // buffer from having to grow at all.
            let len = frame.len();
            frame.copy_within(*at..len, 0);
            frame.truncate(len - *at);
            *at = 0;
        }
        // enough room to make this read worth a syscall, and never past the
        // ceiling. `reserve_exact`, because `reserve` rounds up to twice the
        // capacity and that is what used to walk the buffer up with the stream.
        let want = need
            .saturating_add(READ_CHUNK)
            .min(FRAME_ROOM)
            .max(need);
        if frame.capacity() < want {
            frame.reserve_exact(want - frame.len());
        }
        let len = frame.len();
        let got = {
            let mut buf = ReadBuf::uninit(frame.spare_capacity_mut());
            match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => buf.filled().len(),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        };
        if got == 0 {
            return if *at == frame.len() {
                // a clean EOF at a frame boundary is how a vmess stream ends
                Poll::Ready(Ok(false))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed mid-frame",
                )))
            };
        }
        // SAFETY: `got` bytes past `len` were just initialised by the read above,
        // inside the buffer `spare_capacity_mut` pointed at
        unsafe { frame.set_len(len + got) };
    }
    Poll::Ready(Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn key16(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    /// The assembler behind a real `AsyncRead`, so a test can read it to the end
    /// instead of driving the poll loop by hand.
    struct Assembled {
        reader: FrameAssembler,
        inner: AnyStream,
    }

    impl AsyncRead for Assembled {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.reader.poll_read(&mut this.inner, cx, out)
        }
    }

    /// Frames from a writer that shares the assembler's keys, fed in through a
    /// socket-shaped stream cut up by `how`.
    async fn round_trip(
        security: u8,
        authenticated_length: bool,
        rounds: usize,
        chunk: usize,
    ) -> Vec<u8> {
        let mut writer = BodyWriter::new(
            security,
            &key16(1),
            &key16(2),
            /* global_padding */ false,
            /* chunk_masking */ false,
            authenticated_length,
        );
        let mut wire = Vec::new();
        for round in 0..rounds {
            writer
                .frame_into(&vec![round as u8; 1000], &mut wire)
                .expect("frame");
        }
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let size = if chunk == 0 { wire.len().max(1) } else { chunk };
        let feed = async move {
            for piece in wire.chunks(size) {
                server.write_all(piece).await.expect("feed");
            }
            server.shutdown().await.expect("shutdown");
        };
        let mut stream = Assembled {
            // one key pair stands in for both directions: the framing does not
            // care which is which, only that the two halves agree -- and the real
            // client and server do not, the body uses the response key while an
            // authenticated length block uses the request key
            reader: FrameAssembler::new(
                security,
                &key16(1),
                &key16(2),
                &key16(1),
                &key16(2),
                false,
                false,
                authenticated_length,
                /* cfb */ None,
            ),
            inner: Box::new(client),
        };
        let read = async {
            let mut out = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read_to_end(&mut out),
            )
            .await
            .expect("no hang")
            .expect("read through the framing");
            out
        };
        let (_, out) = tokio::join!(feed, read);
        for round in 0..rounds {
            let at = round * 1000;
            assert!(
                out[at..at + 1000].iter().all(|byte| *byte == round as u8),
                "round {round} came back wrong"
            );
        }
        out
    }

    /// A clean EOF on a frame boundary ends the stream. It used to be reported as
    /// "the length block has arrived", and the assembler then read a length out of
    /// an empty buffer and took the process down with it.
    #[tokio::test]
    async fn a_clean_eof_at_a_frame_boundary_ends_the_stream() {
        let out = round_trip(super::super::SEC_AES128_GCM, false, 3, 0).await;
        assert_eq!(out.len(), 3000);
    }

    /// The same stream, cut up the way a socket cuts it. The read-ahead must not
    /// lose a chunk, whatever the split is.
    #[tokio::test]
    async fn frames_survive_any_split_of_the_stream() {
        for chunk in [1usize, 2, 3, 17, 999, 1000, 1001, 1018, 4096] {
            let out = round_trip(super::super::SEC_AES128_GCM, false, 4, chunk).await;
            assert_eq!(out.len(), 4000, "chunk size {chunk}: bytes went missing");
        }
    }

    /// The variant with an authenticated length block: an 18-byte block at the
    /// front of a buffer that already holds the chunk behind it. Opening it must
    /// not truncate the read-away.
    #[tokio::test]
    async fn the_authenticated_length_variant_reads_whole_frames() {
        for chunk in [1usize, 19, 1018, 4096] {
            let out = round_trip(super::super::SEC_AES128_GCM, true, 4, chunk).await;
            assert_eq!(
                out.len(),
                4000,
                "chunk size {chunk}: bytes went missing"
            );
        }
    }

    /// The other body cipher, for the same reason.
    #[tokio::test]
    async fn the_chacha_body_reads_whole_frames() {
        let out = round_trip(super::super::SEC_CHACHA20_POLY1305, false, 4, 1000).await;
        assert_eq!(out.len(), 4000);
    }

    /// The frame buffer must not follow the stream. It used to be grown with
    /// `Vec::reserve` every time the read-ahead ran out ahead of the consumed
    /// prefix, and `reserve` rounds up to twice the capacity -- so a connection
    /// that carried a lot ended up with a buffer to match. A hundred megabytes
    /// through the assembler is what it takes to see it: the peak the benchmark
    /// reported for this path was 681 MiB.
    #[tokio::test(flavor = "current_thread")]
    async fn the_frame_buffer_does_not_follow_the_stream() {
        let (mut writer, mut reader) = pool(super::super::SEC_AES128_GCM);
        let (client, mut server) = tokio::io::duplex(1 << 20);
        // ~100 MiB of payload in 15 KB chunks
        let rounds = 7000usize;
        let feed = async move {
            let mut wire: Vec<u8> = Vec::new();
            for round in 0..rounds {
                writer
                    .frame_into(&vec![round as u8; 15000], &mut wire)
                    .expect("frame");
                if wire.len() >= 1 << 20 {
                    server.write_all(&wire).await.expect("feed");
                    wire.clear();
                }
            }
            server.write_all(&wire).await.expect("feed");
            server.shutdown().await.expect("shutdown");
        };
        let read = async {
            let mut inner: AnyStream = Box::new(client);
            let mut peak = 0usize;
            let mut scratch = vec![0u8; 64 * 1024];
            loop {
                let mut cx = Context::from_waker(Waker::noop());
                let mut buf = ReadBuf::new(&mut scratch);
                match reader.poll_read(&mut inner, &mut cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        if buf.filled().is_empty() {
                            break;
                        }
                        peak = peak.max(reader.frame.capacity());
                    }
                    Poll::Ready(Err(err)) => panic!("read failed: {err}"),
                    // the feeder has not written its first megabyte yet
                    Poll::Pending => tokio::task::yield_now().await,
                }
            }
            peak
        };
        let (_, peak) = tokio::join!(feed, read);
        assert!(
            peak <= FRAME_ROOM,
            "the frame buffer grew to {peak} bytes over {rounds} frames,              the ceiling is {FRAME_ROOM}"
        );
    }

    /// One set of keys for both halves: the framing does not care which is which.
    fn pool(security: u8) -> (BodyWriter, FrameAssembler) {
        let writer = BodyWriter::new(
            security,
            &key16(1),
            &key16(2),
            false,
            false,
            false,
        );
        let reader = FrameAssembler::new(
            security,
            &key16(1),
            &key16(2),
            &key16(1),
            &key16(2),
            false,
            false,
            false,
            None,
        );
        (writer, reader)
    }

    /// A flipped byte anywhere in a frame has to be caught, not passed on.
    #[tokio::test]
    async fn a_corrupted_frame_is_refused() {
        let mut writer = BodyWriter::new(
            super::super::SEC_AES128_GCM,
            &key16(1),
            &key16(2),
            false,
            false,
            false,
        );
        let mut wire = Vec::new();
        writer.frame_into(&[7u8; 1000], &mut wire).expect("frame");
        let at = wire.len() / 2;
        wire[at] ^= 0x01;
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let feed = async move {
            let _ = server.write_all(&wire).await;
        };
        let mut stream = Assembled {
            reader: FrameAssembler::new(
                super::super::SEC_AES128_GCM,
                &key16(1),
                &key16(2),
                &key16(1),
                &key16(2),
                false,
                false,
                false,
                None,
            ),
            inner: Box::new(client),
        };
        let read = async {
            let mut out = Vec::new();
            stream.read_to_end(&mut out).await
        };
        let (_, result) = tokio::join!(feed, read);
        assert!(result.is_err(), "a mangled frame must not pass as payload");
    }
}
