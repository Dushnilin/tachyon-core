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

    pub(crate) fn open(&self, counter: u16, iv: &[u8; 16], buf: &mut Vec<u8>) -> io::Result<()> {
        if buf.len() < CIPHER_OVERHEAD {
            return Err(io::Error::other("chunk too short"));
        }
        let nonce = chunk_nonce(iv, counter);
        let split = buf.len() - CIPHER_OVERHEAD;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[split..]);
        buf.truncate(split);
        let ok = match self {
            BodyAead::Aes(cipher) => cipher.open(&nonce, &[], buf, &tag),
            BodyAead::ChaCha(cipher) => cipher
                .decrypt_in_place_detached((&nonce).into(), &[], buf, (&tag).into())
                .is_ok(),
        };
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk auth failed",
            ));
        }
        Ok(())
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
    pending: Vec<u8>,
    pos: usize,
    ahead: Ahead,
}

enum AssembleState {
    /// Collecting the length block (2 raw bytes or 18 auth-len bytes).
    Len {
        buf: Vec<u8>,
    },
    /// Collecting ciphertext + padding of a known total length.
    Data {
        buf: Vec<u8>,
        total: usize,
        pad: usize,
    },
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
            state: AssembleState::Len { buf: Vec::new() },
            pending: Vec::new(),
            pos: 0,
            ahead: Ahead::default(),
        }
    }

    pub(crate) fn poll_read(
        &mut self,
        inner: &mut AnyStream,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pos < self.pending.len() {
                let n = out.remaining().min(self.pending.len() - self.pos);
                out.put_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                return Poll::Ready(Ok(()));
            }
            self.pending.clear();
            self.pos = 0;
            match std::mem::replace(&mut self.state, AssembleState::Eof) {
                AssembleState::Eof => return Poll::Ready(Ok(())),
                AssembleState::Len { mut buf } => {
                    let need = if self.authenticated_length {
                        2 + CIPHER_OVERHEAD
                    } else {
                        2
                    };
                    let start = buf.len();
                    match poll_take(inner, cx, &mut self.ahead, &mut buf, need) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            self.state = AssembleState::Eof;
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            self.state = AssembleState::Len { buf };
                            return Poll::Pending;
                        }
                    }
                    if let Some(cfb) = &mut self.cfb {
                        cfb.decrypt(&mut buf[start..]);
                    }
                    let mut length = if self.authenticated_length {
                        if let Some(auth) = &mut self.auth {
                            auth.open(self.auth_count, &self.auth_iv, &mut buf)?;
                            self.auth_count = self.auth_count.wrapping_add(1);
                        }
                        u16::from_be_bytes([buf[0], buf[1]]).wrapping_add(CIPHER_OVERHEAD as u16)
                    } else {
                        u16::from_be_bytes([buf[0], buf[1]])
                    };
                    let mut pad = 0usize;
                    if self.global_padding
                        && let Some(shake) = &mut self.shake
                    {
                        pad = usize::from(shake.next_u16() % MAX_PADDING);
                    }
                    if self.chunk_masking
                        && !self.authenticated_length
                        && let Some(shake) = &mut self.shake
                    {
                        length ^= shake.next_u16();
                    }
                    match usize::from(length).checked_sub(pad) {
                        Some(0) => {
                            self.state = AssembleState::Eof;
                        }
                        Some(_) => {
                            self.state = AssembleState::Data {
                                buf: Vec::with_capacity(usize::from(length)),
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
                AssembleState::Data {
                    mut buf,
                    total,
                    pad,
                } => {
                    let start = buf.len();
                    match poll_take(inner, cx, &mut self.ahead, &mut buf, total) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "stream closed mid-chunk",
                            )));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            self.state = AssembleState::Data { buf, total, pad };
                            return Poll::Pending;
                        }
                    }
                    if let Some(cfb) = &mut self.cfb {
                        cfb.decrypt(&mut buf[start..]);
                    }
                    let Some(ct_len) = total.checked_sub(pad) else {
                        return Poll::Ready(Err(io::Error::other(
                            "bad chunk: length below padding",
                        )));
                    };
                    buf.truncate(ct_len);
                    if self.checksum {
                        if buf.len() < 4 {
                            return Poll::Ready(Err(io::Error::other("checksum chunk too short")));
                        }
                        let expected = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        if fnv1a32(&buf[4..]) != expected {
                            return Poll::Ready(Err(io::Error::other(
                                "vmess: invalid chunk checksum",
                            )));
                        }
                        buf.drain(..4);
                    }
                    if let Some(body) = &self.body {
                        body.open(self.body_count, &self.body_iv, &mut buf)
                            .map_err(|e| io::Error::other(format!("body-chunk: {e}")))?;
                    }
                    self.body_count = self.body_count.wrapping_add(1);
                    self.pending = buf;
                    self.state = AssembleState::Len { buf: Vec::new() };
                }
            }
        }
    }
}

/// What one read off the socket brings in. The old assembler asked for exactly
/// the two length bytes and then exactly the chunk, which is two syscalls per
/// chunk; reading ahead turns a busy stream into roughly one per 32 KiB.
const READ_AHEAD: usize = 32 * 1024;

/// Bytes read from the socket and not yet taken by a frame. The storage is
/// allocated on the first read, so an idle connection holds none.
#[derive(Default)]
struct Ahead {
    data: Vec<u8>,
    pos: usize,
    end: usize,
}

/// Fill `buf` to `need` bytes, from the read-ahead first and the socket after.
/// Returns `Ok(false)` on a clean EOF while `buf` is still empty; any
/// mid-stream EOF is an error.
fn poll_take(
    inner: &mut AnyStream,
    cx: &mut Context<'_>,
    ahead: &mut Ahead,
    buf: &mut Vec<u8>,
    need: usize,
) -> Poll<io::Result<bool>> {
    while buf.len() < need {
        if ahead.pos < ahead.end {
            let n = (need - buf.len()).min(ahead.end - ahead.pos);
            buf.extend_from_slice(&ahead.data[ahead.pos..ahead.pos + n]);
            ahead.pos += n;
            continue;
        }
        if ahead.data.is_empty() {
            ahead.data = vec![0u8; READ_AHEAD];
        }
        let mut read_buf = ReadBuf::new(&mut ahead.data);
        match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(false));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream closed mid-frame",
                    )));
                }
                ahead.pos = 0;
                ahead.end = n;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(true))
}
