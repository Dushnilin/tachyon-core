//! snell v6 record layer (reference sing-snell `snellv6/{mode,handshake,
//! record,shaped,packet}.go`): three framing modes over the shared request
//! protocol — `unsafe-raw` (plain headers), `unshaped` (v4-style salt+AEAD
//! with zero padding) and `default` (profile-shaped records with salt block,
//! record prefixes, seeded padding and payload mixing). Poll-based, mirroring
//! the v4 record layer so the stream/pool plumbing stays mode-agnostic.

use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::Aes128Gcm;
use tokio::io::{AsyncRead, AsyncWrite};

use super::crypto::{
    AEAD_TAG_LEN, HEADER_PLAIN_LEN, HEADER_VERSION, NONCE_LEN, SALT_LEN, derive_key,
    increase_nonce, new_aead, open_in_place, open_region_aad, random_bytes, seal_region,
    seal_region_aad,
};
use super::profile::Profile;
use super::record::{Fill, ReadAhead, poll_flush};

pub(crate) const MAX_PAYLOAD_V6: usize = 0xffff;
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + AEAD_TAG_LEN;

// ------------------------------------------------------------------ mode ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Default,
    Unshaped,
    UnsafeRaw,
}

/// Reference `ParseMode`: case-sensitive, empty means default.
pub(crate) fn parse_mode(name: &str) -> Option<Mode> {
    match name {
        "" | "default" => Some(Mode::Default),
        "unshaped" => Some(Mode::Unshaped),
        "unsafe-raw" => Some(Mode::UnsafeRaw),
        _ => None,
    }
}

// --------------------------------------------------------------- helpers ----

fn put_header(header: &mut [u8], padding_len: usize, payload_len: usize) {
    header[0] = HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
}

/// Parsed plaintext header: version and reserved bytes are checked per mode.
fn parse_header_lengths(header: &[u8]) -> io::Result<(usize, usize)> {
    if header[0] != HEADER_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snell: bad header version {}", header[0]),
        ));
    }
    Ok((
        usize::from(u16::from_be_bytes([header[3], header[4]])),
        usize::from(u16::from_be_bytes([header[5], header[6]])),
    ))
}

// --------------------------------------------------------------- writer ----

pub(crate) struct V6Writer<W> {
    inner: W,
    mode: Mode,
    psk: Vec<u8>,
    profile: Option<Arc<Profile>>,
    initialized: bool,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    seq: u32,
    chunk_size: i64,
    last_write_unix: i64,
}

impl<W> V6Writer<W> {
    pub(crate) fn new(inner: W, mode: Mode, psk: &[u8], profile: Option<Arc<Profile>>) -> Self {
        Self {
            inner,
            mode,
            psk: psk.to_vec(),
            profile,
            initialized: false,
            cipher: None,
            nonce: [0; NONCE_LEN],
            salt: [0; SALT_LEN],
            salt_sent: false,
            seq: 0,
            chunk_size: 0,
            last_write_unix: 0,
        }
    }

    fn initialize(&mut self) -> io::Result<()> {
        if self.initialized {
            return Ok(());
        }
        self.initialized = true;
        if self.mode == Mode::UnsafeRaw {
            return Ok(());
        }
        random_bytes(&mut self.salt)?;
        let key = derive_key(&self.psk, &self.salt)?;
        self.cipher = Some(new_aead(&key));
        self.nonce = [0; NONCE_LEN];
        Ok(())
    }

    fn cipher(&self) -> io::Result<&Aes128Gcm> {
        self.cipher
            .as_ref()
            .ok_or_else(|| io::Error::other("snell: v6 writer not initialized"))
    }

    fn profile(&self) -> io::Result<&Arc<Profile>> {
        self.profile
            .as_ref()
            .ok_or_else(|| io::Error::other("snell: v6 profile missing"))
    }

    /// Reference `shapedWriter.payloadLimitFor`: dynamic chunk window with
    /// second-granular idle reset; advances state per record.
    fn payload_limit_for(&mut self, now_unix: i64) -> io::Result<i64> {
        let profile = Arc::clone(self.profile()?);
        if self.last_write_unix == 0 || now_unix - self.last_write_unix > profile.idle_reset_sec {
            self.chunk_size = profile.chunk_initial;
        }
        if self.chunk_size == 0 {
            self.chunk_size = profile.chunk_initial;
        }
        let mut payload_limit = profile.chunk_payload_limit(self.seq, self.chunk_size);
        if self.seq == 0 {
            payload_limit = go_min(payload_limit, profile.first_record_cap);
        }
        self.chunk_size = profile.next_chunk_size(self.chunk_size);
        self.last_write_unix = now_unix;
        Ok(go_max(1, go_min(payload_limit, MAX_PAYLOAD_V6 as i64)))
    }

    /// `unsafe-raw` record: `[plain header][payload]` appended into `out`.
    fn raw_record_into(&self, payload: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(start + HEADER_PLAIN_LEN, 0u8);
        put_header(&mut out[start..], 0, payload.len());
        out.extend_from_slice(payload);
    }

    fn raw_record(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_PLAIN_LEN + payload.len());
        self.raw_record_into(payload, &mut out);
        out
    }

    /// `unshaped` record: `[salt?][sealed header][sealed payload]` — the zero
    /// chunk stops after the header (reference `WriteZeroChunk`). Appended
    /// into `out`; the steady state allocates nothing per record.
    fn unshaped_record_into(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let cipher = self.cipher()?.clone();
        if !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        let header_start = out.len();
        out.resize(header_start + HEADER_PLAIN_LEN, 0u8);
        put_header(&mut out[header_start..], 0, payload.len());
        let mut tag = [0u8; AEAD_TAG_LEN];
        seal_region(&cipher, &self.nonce, &mut out[header_start..], &mut tag)?;
        increase_nonce(&mut self.nonce);
        out.extend_from_slice(&tag);
        if !payload.is_empty() {
            let payload_start = out.len();
            out.extend_from_slice(payload);
            seal_region(&cipher, &self.nonce, &mut out[payload_start..], &mut tag)?;
            increase_nonce(&mut self.nonce);
            out.extend_from_slice(&tag);
        }
        Ok(())
    }

    fn unshaped_record(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut out =
            Vec::with_capacity(SALT_LEN + HEADER_CIPHER_LEN + payload.len() + AEAD_TAG_LEN);
        self.unshaped_record_into(payload, &mut out)?;
        Ok(out)
    }

    /// `default` shaped record (reference `shapedWriter.makeSliceRecord`):
    /// `[salt block?][prefix][sealed header AAD=prefix][padding][sealed
    /// payload AAD=padding mixed with padding]`. Appended into `out` — the
    /// hot path never builds a per-record Vec.
    fn shaped_record_into(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let profile = Arc::clone(self.profile()?);
        let cipher = self.cipher()?.clone();
        let prefix_len = profile.record_prefix_len(self.seq) as usize;
        let mut salt_block_len = 0usize;
        let mut salt_prefix_len = 0i64;
        if !self.salt_sent {
            salt_block_len = profile.salt_block_len as usize;
            salt_prefix_len = profile.salt_block_len - SALT_LEN as i64;
        }
        let padding_len = profile.padding_len(
            self.seq,
            payload.len() as i64,
            prefix_len as i64,
            salt_prefix_len,
            salt_block_len as i64,
        ) as usize;

        if salt_block_len > 0 {
            let salt_start = out.len();
            out.resize(salt_start + salt_block_len, 0u8);
            profile.fill_padding(u32::MAX, &mut out[salt_start..salt_start + salt_block_len]);
            profile.write_salt_block(
                &self.salt,
                &mut out[salt_start..salt_start + salt_block_len],
            );
            self.salt_sent = true;
        }
        let prefix_start = out.len();
        out.resize(prefix_start + prefix_len, 0u8);
        profile.fill_padding(self.seq, &mut out[prefix_start..prefix_start + prefix_len]);

        let mut header = [0u8; HEADER_PLAIN_LEN];
        put_header(&mut header, padding_len, payload.len());
        let mut tag = [0u8; AEAD_TAG_LEN];
        seal_region_aad(
            &cipher,
            &self.nonce,
            &mut header,
            &out[prefix_start..prefix_start + prefix_len],
            &mut tag,
        )?;
        increase_nonce(&mut self.nonce);
        out.extend_from_slice(&header);
        out.extend_from_slice(&tag);

        let padding_start = out.len();
        out.resize(padding_start + padding_len, 0u8);
        profile.fill_padding(
            self.seq,
            &mut out[padding_start..padding_start + padding_len],
        );

        if !payload.is_empty() {
            let payload_start = out.len();
            out.extend_from_slice(payload);
            let (before, after) = out.split_at_mut(payload_start);
            seal_region_aad(
                &cipher,
                &self.nonce,
                after,
                &before[padding_start..padding_start + padding_len],
                &mut tag,
            )?;
            increase_nonce(&mut self.nonce);
            out.extend_from_slice(&tag);
            let (before, after) = out.split_at_mut(payload_start);
            profile.mix_padding_payload(
                self.seq,
                &mut before[padding_start..padding_start + padding_len],
                after,
            );
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }

    fn shaped_record(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.shaped_record_into(payload, &mut out)?;
        Ok(out)
    }

    /// Split `data` into records for one caller write (reference `Write`): the
    /// shaped limit is computed per record; raw/unshaped split at 0xffff. An
    /// empty write emits the zero-length EOF record.
    pub(crate) fn emit(&mut self, now_unix: i64, data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.initialize()?;
        match self.mode {
            Mode::UnsafeRaw => {
                if data.is_empty() {
                    return Ok(vec![self.raw_record(&[])]);
                }
                let mut records = Vec::new();
                let mut rest = data;
                while !rest.is_empty() {
                    let len = rest.len().min(MAX_PAYLOAD_V6);
                    records.push(self.raw_record(&rest[..len]));
                    rest = &rest[len..];
                }
                Ok(records)
            }
            Mode::Unshaped => {
                if data.is_empty() {
                    return Ok(vec![self.unshaped_record(&[])?]);
                }
                let mut records = Vec::new();
                let mut rest = data;
                while !rest.is_empty() {
                    let len = rest.len().min(MAX_PAYLOAD_V6);
                    records.push(self.unshaped_record(&rest[..len])?);
                    rest = &rest[len..];
                }
                Ok(records)
            }
            Mode::Default => {
                if data.is_empty() {
                    // Reference `WriteZeroChunk`: advance the chunk window,
                    // then emit a payload-less record.
                    self.payload_limit_for(now_unix)?;
                    return Ok(vec![self.shaped_record(&[])?]);
                }
                let mut records = Vec::new();
                let mut rest = data;
                while !rest.is_empty() {
                    let limit = self.payload_limit_for(now_unix)?;
                    let len = rest.len().min(limit as usize);
                    records.push(self.shaped_record(&rest[..len])?);
                    rest = &rest[len..];
                }
                Ok(records)
            }
        }
    }

    /// One datagram = one record, erroring instead of splitting (reference
    /// `WritePacketBuffer`; the shaped window still advances).
    pub(crate) fn emit_packet(&mut self, now_unix: i64, data: &[u8]) -> io::Result<Vec<u8>> {
        self.initialize()?;
        if data.len() > MAX_PAYLOAD_V6 {
            return Err(io::Error::other("snell: payload length exceeds maximum"));
        }
        if self.mode == Mode::Default {
            self.payload_limit_for(now_unix)?;
            return self.shaped_record(data);
        }
        let mut records = self.emit(now_unix, data)?;
        records
            .pop()
            .ok_or_else(|| io::Error::other("snell: empty v6 packet record"))
    }

    /// Hot-path twin of `emit`: the records are appended straight into the
    /// caller's reused buffer — no per-record Vecs, no intermediate Vec of
    /// records.
    pub(crate) fn emit_into(
        &mut self,
        out: &mut Vec<u8>,
        now_unix: i64,
        data: &[u8],
    ) -> io::Result<()> {
        self.initialize()?;
        match self.mode {
            Mode::UnsafeRaw => {
                if data.is_empty() {
                    self.raw_record_into(&[], out);
                    return Ok(());
                }
                let mut rest = data;
                while !rest.is_empty() {
                    let len = rest.len().min(MAX_PAYLOAD_V6);
                    self.raw_record_into(&rest[..len], out);
                    rest = &rest[len..];
                }
                Ok(())
            }
            Mode::Unshaped => {
                if data.is_empty() {
                    return self.unshaped_record_into(&[], out);
                }
                let mut rest = data;
                while !rest.is_empty() {
                    let len = rest.len().min(MAX_PAYLOAD_V6);
                    self.unshaped_record_into(&rest[..len], out)?;
                    rest = &rest[len..];
                }
                Ok(())
            }
            Mode::Default => {
                if data.is_empty() {
                    // Reference `WriteZeroChunk`: advance the chunk window,
                    // then emit a payload-less record.
                    self.payload_limit_for(now_unix)?;
                    return self.shaped_record_into(&[], out);
                }
                let mut rest = data;
                while !rest.is_empty() {
                    let limit = self.payload_limit_for(now_unix)?;
                    let len = rest.len().min(limit as usize);
                    self.shaped_record_into(&rest[..len], out)?;
                    rest = &rest[len..];
                }
                Ok(())
            }
        }
    }
}

impl<W: AsyncWrite + Unpin> V6Writer<W> {
    pub(crate) async fn write_all(&mut self, records: Vec<Vec<u8>>) -> io::Result<()> {
        let mut pending: std::collections::VecDeque<(Vec<u8>, usize)> =
            records.into_iter().map(|r| (r, 0)).collect();
        std::future::poll_fn(|cx| poll_flush(cx, &mut self.inner, &mut pending)).await
    }

    pub(crate) fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

// --------------------------------------------------------------- reader ----

enum Stage {
    Header,
    Body,
}

pub(crate) struct V6Reader<R> {
    cache: ReadAhead<R>,
    mode: Mode,
    psk: Vec<u8>,
    profile: Option<Arc<Profile>>,
    initialized: bool,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    seq: u32,
    record_seq: u32,
    stage: Stage,
    head: Vec<u8>,
    head_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    padding_len: usize,
    payload_len: usize,
    zero_chunk: bool,
    eof: bool,
    fatal: Option<(io::ErrorKind, String)>,
}

impl<R> V6Reader<R> {
    pub(crate) fn new(inner: R, mode: Mode, psk: &[u8], profile: Option<Arc<Profile>>) -> Self {
        Self {
            cache: ReadAhead::new(inner),
            mode,
            psk: psk.to_vec(),
            profile,
            initialized: false,
            cipher: None,
            nonce: [0; NONCE_LEN],
            seq: 0,
            record_seq: 0,
            stage: Stage::Header,
            head: Vec::new(),
            head_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            padding_len: 0,
            payload_len: 0,
            zero_chunk: false,
            eof: false,
            fatal: None,
        }
    }

    fn fail(&mut self, kind: io::ErrorKind, msg: String) -> io::Error {
        self.fatal = Some((kind, msg.clone()));
        io::Error::new(kind, msg)
    }

    fn profile(&self) -> io::Result<&Arc<Profile>> {
        self.profile
            .as_ref()
            .ok_or_else(|| io::Error::other("snell: v6 profile missing"))
    }

    fn header_len(&self) -> io::Result<usize> {
        Ok(match self.mode {
            Mode::UnsafeRaw => HEADER_PLAIN_LEN,
            Mode::Unshaped => HEADER_CIPHER_LEN,
            Mode::Default => {
                self.profile()?.record_prefix_len(self.seq) as usize + HEADER_CIPHER_LEN
            }
        })
    }

    fn rearm_header(&mut self) -> io::Result<()> {
        let needed = self.header_len()?;
        self.head.resize(needed, 0u8);
        self.head_filled = 0;
        self.zero_chunk = false;
        self.stage = Stage::Header;
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> V6Reader<R> {
    /// Per-mode first-read setup (reference `readFirstRecord`): raw starts
    /// immediately, unshaped consumes the 16-byte salt, default consumes the
    /// profile salt block.
    fn initialize(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.initialized {
            return Poll::Ready(Ok(()));
        }
        let salt_len = match self.mode {
            Mode::UnsafeRaw => {
                self.initialized = true;
                return Poll::Ready(Ok(()));
            }
            Mode::Unshaped => SALT_LEN,
            Mode::Default => self
                .profile
                .as_ref()
                .map(|p| p.salt_block_len as usize)
                .unwrap_or(SALT_LEN),
        };
        if self.head.len() != salt_len {
            self.head.resize(salt_len, 0u8);
            self.head_filled = 0;
        }
        match self
            .cache
            .poll_fill(cx, &mut self.head, &mut self.head_filled)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                let e = self.fail(e.kind(), e.to_string());
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(Fill::Eof)) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Fill::Done)) => {
                let salt = match self.mode {
                    Mode::Unshaped => {
                        let mut salt = [0u8; SALT_LEN];
                        salt.copy_from_slice(&self.head[..SALT_LEN]);
                        salt
                    }
                    _ => self.profile()?.extract_salt(&self.head[..salt_len]),
                };
                let key = derive_key(&self.psk, &salt)?;
                self.cipher = Some(new_aead(&key));
                self.nonce = [0; NONCE_LEN];
                self.initialized = true;
                self.rearm_header()?;
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Read the next decrypted record payload into `out` (cleared first);
    /// `Ok(None)` is the zero-chunk EOF (or a clean close at a record
    /// boundary). The reader keeps its body buffer across records, so the
    /// steady state allocates nothing per record.
    pub(crate) fn poll_read_record(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<u8>,
    ) -> Poll<io::Result<Option<()>>> {
        self.poll_read_record_inner(cx, out)
    }

    /// Read the next decrypted record payload into `out`; `Ok(None)` is the
    /// zero-chunk EOF (or a clean close at a record boundary).
    fn poll_read_record_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<u8>,
    ) -> Poll<io::Result<Option<()>>> {
        loop {
            if let Some((kind, msg)) = &self.fatal {
                return Poll::Ready(Err(io::Error::new(*kind, msg.clone())));
            }
            if self.eof {
                return Poll::Ready(Ok(None));
            }
            match self.initialize(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    let e = self.fail(e.kind(), e.to_string());
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    if self.eof {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
            match self.stage {
                Stage::Header => match self.poll_read_header(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        let e = self.fail(e.kind(), e.to_string());
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(None)),
                    Poll::Ready(Ok(Some(()))) => {}
                },
                Stage::Body => match self.poll_read_body(cx, out) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        let e = self.fail(e.kind(), e.to_string());
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(payload)) => return Poll::Ready(Ok(payload)),
                },
            }
        }
    }

    fn poll_read_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<()>>> {
        let needed = match self.header_len() {
            Ok(needed) => needed,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if self.head.len() != needed {
            self.head.resize(needed, 0u8);
            self.head_filled = 0;
        }
        match self
            .cache
            .poll_fill(cx, &mut self.head, &mut self.head_filled)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Fill::Eof)) => {
                self.eof = true;
                Poll::Ready(Ok(None))
            }
            Poll::Ready(Ok(Fill::Done)) => self.parse_header(),
        }
    }

    fn parse_header(&mut self) -> Poll<io::Result<Option<()>>> {
        match self.mode {
            Mode::UnsafeRaw => {
                let (padding_len, payload_len) = match parse_header_lengths(&self.head) {
                    Ok(lengths) => lengths,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                if self.head[1] != 0 || self.head[2] != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: reserved header octet is non-zero",
                    )));
                }
                if padding_len != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: unexpected padding in non-default record",
                    )));
                }
                if payload_len == 0 {
                    if let Err(e) = self.rearm_header() {
                        return Poll::Ready(Err(e));
                    }
                    return Poll::Ready(Ok(None));
                }
                self.padding_len = 0;
                self.payload_len = payload_len;
                if self.body.len() != payload_len {
                    // Resize, not replace: the capacity survives and the
                    // next record reuses it.
                    self.body.resize(payload_len, 0u8);
                }
                self.body_filled = 0;
                self.stage = Stage::Body;
                Poll::Ready(Ok(Some(())))
            }
            Mode::Unshaped => {
                let cipher = match &self.cipher {
                    Some(cipher) => cipher.clone(),
                    None => {
                        return Poll::Ready(Err(io::Error::other("snell: v6 reader not ready")));
                    }
                };
                if open_in_place(&cipher, &self.nonce, &mut self.head).is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: open record header",
                    )));
                }
                increase_nonce(&mut self.nonce);
                let (padding_len, payload_len) = match parse_header_lengths(&self.head) {
                    Ok(lengths) => lengths,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                if self.head[1] != 0 || self.head[2] != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: reserved header octet is non-zero",
                    )));
                }
                if padding_len != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: unexpected padding in non-default record",
                    )));
                }
                if payload_len == 0 {
                    if let Err(e) = self.rearm_header() {
                        return Poll::Ready(Err(e));
                    }
                    return Poll::Ready(Ok(None));
                }
                self.padding_len = 0;
                self.payload_len = payload_len;
                if self.body.len() != payload_len + AEAD_TAG_LEN {
                    self.body.resize(payload_len + AEAD_TAG_LEN, 0u8);
                }
                self.body_filled = 0;
                self.stage = Stage::Body;
                Poll::Ready(Ok(Some(())))
            }
            Mode::Default => {
                let (profile, cipher) = match (self.profile.clone(), self.cipher.clone()) {
                    (Some(profile), Some(cipher)) => (profile, cipher),
                    _ => {
                        return Poll::Ready(Err(io::Error::other("snell: v6 reader not ready")));
                    }
                };
                let prefix_len = match profile.record_prefix_len(self.seq).try_into() {
                    Ok(len) => len,
                    Err(_) => return Poll::Ready(Err(io::Error::other("snell: bad prefix len"))),
                };
                // head = [prefix (AAD) | sealed header]: open the sealed
                // half in place — no split_off, nothing allocated per record.
                if self.head.len() != prefix_len + HEADER_CIPHER_LEN {
                    return Poll::Ready(Err(io::Error::other("snell: bad shaped header length")));
                }
                let opened = {
                    let (aad, sealed) = self.head.split_at_mut(prefix_len);
                    open_region_aad(&cipher, &self.nonce, sealed, aad)
                };
                if opened.is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: open shaped header",
                    )));
                }
                increase_nonce(&mut self.nonce);
                let sealed = &self.head[prefix_len..];
                if sealed[0] != HEADER_VERSION {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("snell: bad header version {}", sealed[0]),
                    )));
                }
                // The shaped reader ignores the two reserved header bytes.
                let padding_len = usize::from(u16::from_be_bytes([sealed[3], sealed[4]]));
                let payload_len = usize::from(u16::from_be_bytes([sealed[5], sealed[6]]));
                self.record_seq = self.seq;
                self.seq = self.seq.wrapping_add(1);
                let body_len = padding_len + payload_len + AEAD_TAG_LEN;
                if payload_len == 0 {
                    let body_len = padding_len;
                    if body_len > 0 {
                        // Zero chunk may still carry shaped padding: consume
                        // it before reporting tunnel EOF.
                        self.padding_len = padding_len;
                        self.payload_len = 0;
                        self.zero_chunk = true;
                        if self.body.len() != body_len {
                            self.body.resize(body_len, 0u8);
                        }
                        self.body_filled = 0;
                        self.stage = Stage::Body;
                        return Poll::Ready(Ok(Some(())));
                    }
                    if let Err(e) = self.rearm_header() {
                        return Poll::Ready(Err(e));
                    }
                    return Poll::Ready(Ok(None));
                }
                self.padding_len = padding_len;
                self.payload_len = payload_len;
                if self.body.len() != body_len {
                    self.body.resize(body_len, 0u8);
                }
                self.body_filled = 0;
                self.stage = Stage::Body;
                Poll::Ready(Ok(Some(())))
            }
        }
    }

    fn poll_read_body(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Vec<u8>,
    ) -> Poll<io::Result<Option<()>>> {
        match self
            .cache
            .poll_fill(cx, &mut self.body, &mut self.body_filled)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Fill::Eof)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snell: unexpected EOF",
            ))),
            Poll::Ready(Ok(Fill::Done)) => match self.mode {
                Mode::UnsafeRaw => {
                    self.body_filled = 0;
                    out.clear();
                    out.extend_from_slice(&self.body);
                    if let Err(e) = self.rearm_header() {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(Some(())))
                }
                Mode::Unshaped => {
                    let cipher = match &self.cipher {
                        Some(cipher) => cipher.clone(),
                        None => {
                            return Poll::Ready(Err(io::Error::other(
                                "snell: v6 reader not ready",
                            )));
                        }
                    };
                    if open_in_place(&cipher, &self.nonce, &mut self.body).is_err() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell: open record payload",
                        )));
                    }
                    increase_nonce(&mut self.nonce);
                    self.body_filled = 0;
                    out.clear();
                    out.extend_from_slice(&self.body);
                    if let Err(e) = self.rearm_header() {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(Some(())))
                }
                Mode::Default => {
                    if self.zero_chunk {
                        self.body_filled = 0;
                        if let Err(e) = self.rearm_header() {
                            return Poll::Ready(Err(e));
                        }
                        return Poll::Ready(Ok(None));
                    }
                    let (profile, cipher) = match (self.profile.clone(), self.cipher.clone()) {
                        (Some(profile), Some(cipher)) => (profile, cipher),
                        _ => {
                            return Poll::Ready(Err(io::Error::other(
                                "snell: v6 reader not ready",
                            )));
                        }
                    };
                    let padding_len = self.padding_len;
                    // The writer sealed with the raw padding as AAD, then
                    // swapped the two regions: unmix first, open second.
                    {
                        let (padding, rest) = self.body.split_at_mut(padding_len);
                        profile.mix_padding_payload(self.record_seq, padding, rest);
                    }
                    let opened = {
                        let (padding, rest) = self.body.split_at_mut(padding_len);
                        open_region_aad(&cipher, &self.nonce, rest, padding)
                    };
                    if opened.is_err() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell: open shaped payload",
                        )));
                    }
                    increase_nonce(&mut self.nonce);
                    self.body_filled = 0;
                    out.clear();
                    out.extend_from_slice(&self.body[padding_len..padding_len + self.payload_len]);
                    if let Err(e) = self.rearm_header() {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(Some(())))
                }
            },
        }
    }

    pub(crate) async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        let found = std::future::poll_fn(|cx| match self.poll_read_record_inner(cx, &mut out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(found)) => Poll::Ready(Ok(found.is_some())),
        })
        .await?;
        Ok(found.then_some(out))
    }
}

fn go_min(a: i64, b: i64) -> i64 {
    if a < b { a } else { b }
}

fn go_max(a: i64, b: i64) -> i64 {
    if a > b { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::super::record::now_unix;
    use super::*;
    use std::pin::Pin;
    use tokio::io::ReadBuf;

    const GOLDEN: &str = include_str!("../../../tests/data/snellv6_golden.json");
    const PSK: &[u8] = b"deadbeefdeadbeefdeadbeefdeadbeef";
    const PAYLOAD1: &[u8] = b"Hello, snell v6 shaped record!";
    const PAYLOAD2_LEN: usize = 1400;

    fn golden() -> serde_json::Value {
        serde_json::from_str(GOLDEN).expect("golden json")
    }

    fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn profile() -> Arc<Profile> {
        Arc::new(Profile::new(PSK).expect("profile"))
    }

    fn fixed_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = index as u8;
        }
        salt
    }

    /// Writer pinned to the golden wire vectors: fixed salt, matching key.
    fn fixed_writer(mode: Mode, profile: Option<Arc<Profile>>) -> V6Writer<tokio::io::Sink> {
        let mut writer: V6Writer<tokio::io::Sink> =
            V6Writer::new(tokio::io::sink(), mode, PSK, profile);
        writer.initialize().expect("init");
        writer.salt = fixed_salt();
        writer.cipher = Some(new_aead(&derive_key(PSK, &writer.salt).expect("key")));
        writer.nonce = [0; NONCE_LEN];
        writer
    }

    fn payload2() -> Vec<u8> {
        vec![0x5a; PAYLOAD2_LEN]
    }

    /// Mirror of the dump harness: deterministic shaped record stream against
    /// the reference output for fixed salt/key/nonce.
    #[test]
    fn shaped_records_match_reference_wire() {
        let g = golden();
        let profile = profile();
        let mut writer = fixed_writer(Mode::Default, Some(profile.clone()));

        let wire: Vec<String> = [PAYLOAD1.to_vec(), payload2(), Vec::new()]
            .iter()
            .map(|payload| {
                let record = writer.shaped_record(payload).expect("record");
                encode(&record)
            })
            .collect();
        let expected: Vec<String> = g["wire"]["shaped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(wire, expected, "shaped wire records");
        assert_eq!(
            writer.seq,
            g["wire"]["shapedSeqAfter"].as_u64().unwrap() as u32
        );
        assert_eq!(
            writer.salt_sent,
            g["wire"]["shapedSaltSent"].as_bool().unwrap()
        );
    }

    #[test]
    fn unshaped_records_match_reference_wire() {
        let g = golden();
        let mut writer = fixed_writer(Mode::Unshaped, None);

        let r1 = writer.unshaped_record(PAYLOAD1).expect("record");
        let r2 = writer.unshaped_record(&payload2()).expect("record");
        let zero = writer.unshaped_record(&[]).expect("zero chunk");
        let expected = g["wire"]["unshaped"].as_array().unwrap();
        // The dump records raw unshaped records; the 16-byte salt rides
        // ahead of the first record on the wire (reference `writeFirstRecord`).
        assert_eq!(&r1[..SALT_LEN], &fixed_salt()[..], "unshaped salt prefix");
        assert_eq!(
            encode(&r1[SALT_LEN..]),
            expected[0].as_str().unwrap(),
            "unshaped r1"
        );
        assert_eq!(encode(&r2), expected[1].as_str().unwrap(), "unshaped r2");
        // The zero chunk is written standalone in the reference (header only).
        assert_eq!(
            encode(&zero),
            expected[2].as_str().unwrap(),
            "unshaped zero"
        );
        assert_eq!(
            encode(&writer.nonce),
            g["wire"]["unshapedNonce"].as_str().unwrap(),
            "unshaped nonce"
        );
    }

    /// `Write` splits a 0x10010-byte payload into 0xffff records (reference
    /// `unshapedSplit` golden, salt stripped from the first record).
    #[test]
    fn unshaped_write_splits_at_max_payload() {
        let g = golden();
        let mut writer = fixed_writer(Mode::Unshaped, None);
        let mut big = vec![0u8; MAX_PAYLOAD_V6 + 0x10];
        for (index, byte) in big.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let records = writer.emit(now_unix(), &big).expect("emit");
        assert_eq!(records.len(), 2, "split into two records");
        let mut wire = records.concat();
        wire.drain(..SALT_LEN);
        assert_eq!(
            encode(&wire),
            g["wire"]["unshapedSplit"].as_str().unwrap(),
            "unshaped split stream"
        );
    }

    #[test]
    fn raw_records_match_reference_wire() {
        let g = golden();
        let mut writer: V6Writer<tokio::io::Sink> =
            V6Writer::new(tokio::io::sink(), Mode::UnsafeRaw, PSK, None);
        writer.initialize().expect("init");
        let r1 = writer.raw_record(PAYLOAD1);
        let zero = writer.raw_record(&[]);
        let expected = g["wire"]["raw"].as_array().unwrap();
        assert_eq!(encode(&r1), expected[0].as_str().unwrap(), "raw record");
        assert_eq!(encode(&zero), expected[1].as_str().unwrap(), "raw zero");
    }

    /// AsyncRead over a byte slice for driving readers in tests.
    struct SliceReader(std::io::Cursor<Vec<u8>>);

    impl AsyncRead for SliceReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            use std::io::Read;
            let n = self.0.read(buf.initialize_unfilled())?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    async fn read_all(reader: &mut V6Reader<SliceReader>) -> Vec<Option<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            match reader.read_record().await {
                Ok(Some(rec)) => out.push(Some(rec)),
                Ok(None) => {
                    out.push(None);
                    break;
                }
                Err(e) => panic!("reader error: {e}"),
            }
            if out.len() > 64 {
                panic!("too many records");
            }
        }
        out
    }

    /// Records concatenated up to (excluding) the trailing EOF marker.
    fn concat(decoded: &[Option<Vec<u8>>]) -> Vec<u8> {
        decoded.iter().flatten().flatten().cloned().collect()
    }

    fn shaped_stream(profile: &Arc<Profile>, records: &[&[u8]]) -> Vec<u8> {
        let mut writer: V6Writer<tokio::io::Sink> =
            V6Writer::new(tokio::io::sink(), Mode::Default, PSK, Some(profile.clone()));
        writer.initialize().expect("init");
        let mut wire = Vec::new();
        for record in records {
            let chunks = writer.emit(now_unix(), record).expect("emit");
            wire.extend(chunks.concat());
        }
        wire.extend(writer.emit(now_unix(), &[]).expect("eof").concat());
        wire
    }

    #[tokio::test]
    async fn shaped_roundtrip_with_zero_chunk_eof() {
        let profile = profile();
        let payload_a = b"shaped roundtrip payload".to_vec();
        let payload_b = vec![0x77u8; 4000];
        let wire = shaped_stream(&profile, &[&payload_a, &payload_b]);
        let mut reader = V6Reader::new(
            SliceReader(std::io::Cursor::new(wire)),
            Mode::Default,
            PSK,
            Some(profile),
        );
        let decoded = read_all(&mut reader).await;
        assert_eq!(decoded.last(), Some(&None), "trailing zero-chunk EOF");
        let mut expect = payload_a.clone();
        expect.extend_from_slice(&payload_b);
        // A large write splits across per-record payload limits: the records
        // must reassemble to the original byte stream.
        assert_eq!(concat(&decoded), expect);
    }

    #[tokio::test]
    async fn shaped_roundtrip_request_then_reply_leftover() {
        // Client wire then server wire in opposite directions: simulate the
        // request record stream being read by a matching reader (both sides
        // derive keys from their own salt blocks).
        let profile = profile();
        let request = b"connect request bytes".to_vec();
        let wire = shaped_stream(&profile, &[&request]);
        let mut reader = V6Reader::new(
            SliceReader(std::io::Cursor::new(wire)),
            Mode::Default,
            PSK,
            Some(profile),
        );
        let first = reader.read_record().await.expect("record");
        assert_eq!(first.as_deref(), Some(request.as_slice()));
        assert_eq!(reader.read_record().await.expect("eof"), None);
    }

    #[tokio::test]
    async fn unshaped_roundtrip_and_reuse() {
        let payload_a = b"unshaped one".to_vec();
        let payload_b = vec![0x21u8; 90_000]; // splits into 0xffff records
        let mut writer: V6Writer<tokio::io::Sink> =
            V6Writer::new(tokio::io::sink(), Mode::Unshaped, PSK, None);
        writer.initialize().expect("init");
        let mut wire = Vec::new();
        wire.extend(writer.emit(now_unix(), &payload_a).expect("a").concat());
        wire.extend(writer.emit(now_unix(), &payload_b).expect("b").concat());
        wire.extend(writer.emit(now_unix(), &[]).expect("eof").concat());

        let mut reader = V6Reader::new(
            SliceReader(std::io::Cursor::new(wire)),
            Mode::Unshaped,
            PSK,
            None,
        );
        let decoded = read_all(&mut reader).await;
        assert_eq!(decoded.first(), Some(&Some(payload_a.clone())));
        let mut expect = payload_a.clone();
        expect.extend_from_slice(&payload_b);
        assert_eq!(concat(&decoded), expect, "unshaped stream reassembles");
        assert_eq!(decoded.last(), Some(&None));
    }

    #[tokio::test]
    async fn raw_roundtrip_zero_chunk_and_rearm() {
        let payload = b"raw payload".to_vec();
        let mut writer: V6Writer<tokio::io::Sink> =
            V6Writer::new(tokio::io::sink(), Mode::UnsafeRaw, PSK, None);
        writer.initialize().expect("init");
        let mut wire = Vec::new();
        wire.extend(writer.emit(now_unix(), &payload).expect("emit").concat());
        wire.extend(writer.emit(now_unix(), &[]).expect("eof").concat());
        // Second round on the same writer (no state): another record.
        wire.extend(writer.emit(now_unix(), b"more").expect("emit2").concat());

        let mut reader = V6Reader::new(
            SliceReader(std::io::Cursor::new(wire)),
            Mode::UnsafeRaw,
            PSK,
            None,
        );
        let first = reader.read_record().await.expect("first");
        assert_eq!(first.as_deref(), Some(payload.as_slice()));
        assert_eq!(reader.read_record().await.expect("eof"), None);
        // The zero chunk rearms: the next record on the wire is still read.
        let second = reader.read_record().await.expect("second");
        assert_eq!(second.as_deref(), Some(b"more".as_slice()));
    }

    #[tokio::test]
    async fn shaped_reader_rejects_tampered_header() {
        let profile = profile();
        let wire = shaped_stream(&profile, &[b"secret"]);
        let mut tampered = wire.clone();
        // Flip a byte inside the sealed header region (past salt block).
        let index = profile.salt_block_len as usize + profile.record_prefix_len(0) as usize + 4;
        tampered[index] ^= 0xff;
        let mut reader = V6Reader::new(
            SliceReader(std::io::Cursor::new(tampered)),
            Mode::Default,
            PSK,
            Some(profile),
        );
        let err = reader.read_record().await.expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = reader.read_record().await.expect_err("must stick");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_mode_matches_reference() {
        assert_eq!(parse_mode(""), Some(Mode::Default));
        assert_eq!(parse_mode("default"), Some(Mode::Default));
        assert_eq!(parse_mode("unshaped"), Some(Mode::Unshaped));
        assert_eq!(parse_mode("unsafe-raw"), Some(Mode::UnsafeRaw));
        assert_eq!(parse_mode("Default"), None);
        assert_eq!(parse_mode("UNSHAPED"), None);
        assert_eq!(parse_mode("raw"), None);
    }
}
