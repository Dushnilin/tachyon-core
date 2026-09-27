//! snell v4 record framing (reference `snellv4/record.go`): the writer seals
//! payload slices into salt/header/padding/payload records with the Surge
//! payload-limit growth window; the reader inverts the framing.
//!
//! Both sides expose poll-based primitives so the connection stream can drive
//! them from `AsyncRead`/`AsyncWrite` implementations.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::Aes128Gcm;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::{
    AEAD_TAG_LEN, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, HEADER_VERSION, MAX_PAYLOAD_LEN, NONCE_LEN,
    SALT_LEN, derive_key, increase_nonce, new_aead, open_in_place, random_bytes, random_int31,
    seal_in_place,
};

pub(crate) const FRAME_SIZE: usize = 1460;
pub(crate) const FIRST_RECORD_OVERHEAD: usize = 55;
pub(crate) const RESET_RECORD_OVERHEAD: usize = 39;
pub(crate) const INITIAL_PADDING_MIN: usize = 0x100;
pub(crate) const INITIAL_PADDING_SPAN: usize = 0x100;
const FRAME_PAYLOAD_RESET_INTERVAL: i64 = 31;

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- writer ----

pub(crate) struct RecordWriter<W> {
    pub(super) inner: W,
    psk: Vec<u8>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    initial_padding: usize,
    payload_limit: i64,
    last_write_unix: i64,
}

impl<W> RecordWriter<W> {
    pub(crate) fn new(inner: W, psk: &[u8]) -> Self {
        Self {
            inner,
            psk: psk.to_vec(),
            cipher: None,
            nonce: [0; NONCE_LEN],
            salt: [0; SALT_LEN],
            salt_sent: false,
            initial_padding: 0,
            payload_limit: 0,
            last_write_unix: 0,
        }
    }

    fn initialize(&mut self) -> io::Result<()> {
        if self.cipher.is_some() {
            return Ok(());
        }
        random_bytes(&mut self.salt)?;
        let key = derive_key(&self.psk, &self.salt)?;
        let mut delta = [0u8; 1];
        random_bytes(&mut delta)?;
        self.cipher = Some(new_aead(&key));
        self.nonce = [0; NONCE_LEN];
        self.initial_padding = INITIAL_PADDING_MIN + (delta[0] as usize % INITIAL_PADDING_SPAN);
        Ok(())
    }

    /// Reference `payloadLimitFor`.
    fn payload_limit_for(&self, now_unix: i64) -> i64 {
        if !self.salt_sent {
            return (FRAME_SIZE - FIRST_RECORD_OVERHEAD) as i64 - self.initial_padding as i64;
        }
        if self.last_write_unix != 0
            && now_unix - self.last_write_unix < FRAME_PAYLOAD_RESET_INTERVAL
            && self.payload_limit > 0
        {
            return self.payload_limit;
        }
        (FRAME_SIZE - RESET_RECORD_OVERHEAD) as i64
    }

    /// Reference `advancePayloadLimit`: one growth step per caller write.
    fn advance_payload_limit(&mut self, payload_limit: i64, now_unix: i64) {
        self.last_write_unix = now_unix;
        if payload_limit < MAX_PAYLOAD_LEN as i64 {
            let next = payload_limit + (FRAME_SIZE - RESET_RECORD_OVERHEAD) as i64;
            self.payload_limit = next.min(MAX_PAYLOAD_LEN as i64);
        } else {
            self.payload_limit = MAX_PAYLOAD_LEN as i64;
        }
    }

    fn frame_padding_len(&self, payload_len: usize) -> usize {
        if self.salt_sent || payload_len == 0 {
            0
        } else {
            self.initial_padding
        }
    }

    fn limit_checked(&self, now_unix: i64) -> io::Result<i64> {
        let payload_limit = self.payload_limit_for(now_unix);
        if payload_limit <= 0 || payload_limit > MAX_PAYLOAD_LEN as i64 {
            return Err(io::Error::other("snell: invalid v4 payload limit"));
        }
        Ok(payload_limit)
    }

    /// Split `data` into records for one caller write (reference
    /// `Write`/`writeBytesLocked`): the limit is computed and advanced once,
    /// then the whole slice is split with that limit. An empty `data` write
    /// emits the zero-length EOF record after advancing the window.
    pub(crate) fn emit(&mut self, now_unix: i64, data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.initialize()?;
        let payload_limit = self.limit_checked(now_unix)?;
        self.advance_payload_limit(payload_limit, now_unix);
        if data.is_empty() {
            return Ok(vec![self.make_record(&[], 0)?]);
        }
        let mut records = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            let len = rest.len().min(payload_limit as usize);
            let padding_len = self.frame_padding_len(len);
            records.push(self.make_record(&rest[..len], padding_len)?);
            rest = &rest[len..];
        }
        Ok(records)
    }

    /// One datagram = one record, erroring instead of splitting (reference
    /// `WritePacketBuffer`).
    pub(crate) fn emit_packet(&mut self, now_unix: i64, data: &[u8]) -> io::Result<Vec<u8>> {
        self.initialize()?;
        let payload_limit = self.limit_checked(now_unix)?;
        if data.len() > payload_limit as usize || data.len() > MAX_PAYLOAD_LEN {
            return Err(io::Error::other("snell: payload length exceeds maximum"));
        }
        self.advance_payload_limit(payload_limit, now_unix);
        let padding_len = self.frame_padding_len(data.len());
        self.make_record(data, padding_len)
    }

    /// Reference `makeSliceRecordLocked`: [salt?][sealed header][padding][payload].
    fn make_record(&mut self, payload: &[u8], padding_len: usize) -> io::Result<Vec<u8>> {
        self.initialize()?;
        if payload.len() > MAX_PAYLOAD_LEN || padding_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::other("snell: v4 record exceeds maximum"));
        }
        if payload.is_empty() && padding_len != 0 {
            return Err(io::Error::other(
                "snell: zero-length v4 record carries padding",
            ));
        }
        let salt_len = if !self.salt_sent { SALT_LEN } else { 0 };
        let payload_cipher_len = if payload.is_empty() {
            0
        } else {
            payload.len() + AEAD_TAG_LEN
        };
        let mut out =
            Vec::with_capacity(salt_len + HEADER_CIPHER_LEN + padding_len + payload_cipher_len);

        if salt_len > 0 {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }

        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut header = header.to_vec();
        seal_in_place(
            self.cipher.as_ref().expect("snell: writer initialized"),
            &self.nonce,
            &mut header,
        )?;
        increase_nonce(&mut self.nonce);
        out.extend_from_slice(&header);

        let padding_start = out.len();
        out.resize(padding_start + padding_len, 0u8);
        if !payload.is_empty() {
            let mut payload_cipher = payload.to_vec();
            seal_in_place(
                self.cipher.as_ref().expect("snell: writer initialized"),
                &self.nonce,
                &mut payload_cipher,
            )?;
            increase_nonce(&mut self.nonce);
            out.extend_from_slice(&payload_cipher);

            if padding_len > 0 {
                let payload_start = padding_start + padding_len;
                let (head, tail) = out.split_at_mut(payload_start);
                fill_padding(&mut head[padding_start..], tail)?;
                let limit = padding_len.min(payload_cipher_len);
                for index in (0..limit).step_by(2) {
                    out.swap(padding_start + index, payload_start + index);
                }
            }
        }
        Ok(out)
    }
}

impl<W: AsyncWrite + Unpin> RecordWriter<W> {
    /// Flush complete records, one inner write per record (reference record
    /// write granularity — obfs framing depends on it).
    pub(crate) async fn write_all(&mut self, records: Vec<Vec<u8>>) -> io::Result<()> {
        let mut pending: VecDeque<(Vec<u8>, usize)> = records.into_iter().map(|r| (r, 0)).collect();
        std::future::poll_fn(|cx| poll_flush(cx, &mut self.inner, &mut pending)).await
    }
}

/// Drain `pending` records into `inner`, tracking partial writes.
pub(crate) fn poll_flush<W: AsyncWrite + Unpin>(
    cx: &mut Context<'_>,
    inner: &mut W,
    pending: &mut VecDeque<(Vec<u8>, usize)>,
) -> Poll<io::Result<()>> {
    while let Some((record, pos)) = pending.front_mut() {
        while *pos < record.len() {
            match Pin::new(&mut *inner).poll_write(cx, &record[*pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snell: failed to write whole record",
                    )));
                }
                Poll::Ready(Ok(n)) => *pos += n,
            }
        }
        pending.pop_front();
    }
    Poll::Ready(Ok(()))
}

// ---------------------------------------------------------------- reader ----

enum ReadStage {
    Salt,
    Header,
    Body,
}

pub(crate) struct RecordReader<R> {
    inner: R,
    psk: Vec<u8>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    stage: ReadStage,
    head: Vec<u8>,
    head_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    padding_len: usize,
    payload_len: usize,
    eof: bool,
    fatal: Option<(io::ErrorKind, String)>,
}

/// Result of reading exactly `buf.len()` bytes: done, or clean EOF with no
/// bytes read at a record boundary.
pub(crate) enum Fill {
    Done,
    Eof,
}

pub(crate) fn poll_fill<R: AsyncRead + Unpin>(
    cx: &mut Context<'_>,
    inner: &mut R,
    buf: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<Fill>> {
    while *filled < buf.len() {
        let mut read_buf = ReadBuf::new(&mut buf[*filled..]);
        match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(if *filled == 0 {
                        Ok(Fill::Eof)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell: unexpected EOF",
                        ))
                    });
                }
                *filled += n;
            }
        }
    }
    Poll::Ready(Ok(Fill::Done))
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    pub(crate) fn new(inner: R, psk: &[u8]) -> Self {
        Self {
            inner,
            psk: psk.to_vec(),
            cipher: None,
            nonce: [0; NONCE_LEN],
            stage: ReadStage::Salt,
            head: Vec::new(),
            head_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            padding_len: 0,
            payload_len: 0,
            eof: false,
            fatal: None,
        }
    }

    fn fail(&mut self, kind: io::ErrorKind, msg: String) -> io::Error {
        self.fatal = Some((kind, msg.clone()));
        io::Error::new(kind, msg)
    }

    /// Read the next decrypted record payload; `Ok(None)` is the zero-chunk
    /// EOF (or a clean close at a record boundary).
    pub(crate) fn poll_read_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            if let Some((kind, msg)) = &self.fatal {
                return Poll::Ready(Err(io::Error::new(*kind, msg.clone())));
            }
            if self.eof {
                return Poll::Ready(Ok(None));
            }
            match self.stage {
                ReadStage::Salt => {
                    if self.head.len() != SALT_LEN {
                        self.head.resize(SALT_LEN, 0u8);
                    }
                    match poll_fill(cx, &mut self.inner, &mut self.head, &mut self.head_filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            let e = self.fail(e.kind(), e.to_string());
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(Fill::Eof)) => {
                            self.eof = true;
                            return Poll::Ready(Ok(None));
                        }
                        Poll::Ready(Ok(Fill::Done)) => {
                            let key = match derive_key(&self.psk, &self.head[..SALT_LEN]) {
                                Ok(key) => key,
                                Err(e) => {
                                    let e = self.fail(e.kind(), e.to_string());
                                    return Poll::Ready(Err(e));
                                }
                            };
                            self.cipher = Some(new_aead(&key));
                            self.nonce = [0; NONCE_LEN];
                            self.head.resize(HEADER_CIPHER_LEN, 0u8);
                            self.head_filled = 0;
                            self.stage = ReadStage::Header;
                        }
                    }
                }
                ReadStage::Header => {
                    match poll_fill(cx, &mut self.inner, &mut self.head, &mut self.head_filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            let e = self.fail(e.kind(), e.to_string());
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(Fill::Eof)) => {
                            self.eof = true;
                            return Poll::Ready(Ok(None));
                        }
                        Poll::Ready(Ok(Fill::Done)) => {
                            let opened = open_in_place(
                                self.cipher.as_ref().expect("snell: reader initialized"),
                                &self.nonce,
                                &mut self.head,
                            );
                            if opened.is_err() {
                                let e = self.fail(
                                    io::ErrorKind::InvalidData,
                                    "snell: open record header".to_string(),
                                );
                                return Poll::Ready(Err(e));
                            }
                            increase_nonce(&mut self.nonce);
                            if self.head.len() != HEADER_PLAIN_LEN || self.head[0] != HEADER_VERSION
                            {
                                let version = self.head.first().copied().unwrap_or(0);
                                let e = self.fail(
                                    io::ErrorKind::InvalidData,
                                    format!("snell: bad header version {version}"),
                                );
                                return Poll::Ready(Err(e));
                            }
                            self.padding_len =
                                u16::from_be_bytes([self.head[3], self.head[4]]) as usize;
                            self.payload_len =
                                u16::from_be_bytes([self.head[5], self.head[6]]) as usize;
                            if self.payload_len == 0 {
                                // Zero-chunk tunnel EOF — header only on the
                                // wire (reference `WriteZeroChunk`), not a
                                // transport EOF: rearm the Header stage so the
                                // pooled reader continues the same cipher
                                // stream on the next reuse round.
                                self.head.resize(HEADER_CIPHER_LEN, 0u8);
                                self.head_filled = 0;
                                self.stage = ReadStage::Header;
                                return Poll::Ready(Ok(None));
                            }
                            self.body =
                                vec![0u8; self.padding_len + self.payload_len + AEAD_TAG_LEN];
                            self.body_filled = 0;
                            self.stage = ReadStage::Body;
                        }
                    }
                }
                ReadStage::Body => {
                    match poll_fill(cx, &mut self.inner, &mut self.body, &mut self.body_filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            let e = self.fail(e.kind(), e.to_string());
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(Fill::Eof)) => {
                            self.eof = true;
                            return Poll::Ready(Ok(None));
                        }
                        Poll::Ready(Ok(Fill::Done)) => {
                            let payload_end = self.padding_len + self.payload_len + AEAD_TAG_LEN;
                            let payload_cipher_len = self.payload_len + AEAD_TAG_LEN;
                            let limit = self.padding_len.min(payload_cipher_len);
                            for index in (0..limit).step_by(2) {
                                self.body.swap(index, self.padding_len + index);
                            }
                            let mut payload_cipher =
                                self.body[self.padding_len..payload_end].to_vec();
                            let opened = open_in_place(
                                self.cipher.as_ref().expect("snell: reader initialized"),
                                &self.nonce,
                                &mut payload_cipher,
                            );
                            if opened.is_err() {
                                let e = self.fail(
                                    io::ErrorKind::InvalidData,
                                    "snell: open record payload".to_string(),
                                );
                                return Poll::Ready(Err(e));
                            }
                            increase_nonce(&mut self.nonce);
                            self.head.resize(HEADER_CIPHER_LEN, 0u8);
                            self.head_filled = 0;
                            self.stage = ReadStage::Header;
                            return Poll::Ready(Ok(Some(payload_cipher)));
                        }
                    }
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    pub(crate) async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        std::future::poll_fn(|cx| self.poll_read_record(cx)).await
    }
}

// -------------------------------------------------------------- padding ----

/// Reference `fillPadding`: pad toward a target ones/zeros ratio of the sealed
/// payload cipher; random bytes when the ratio is out of bounds.
fn fill_padding(padding: &mut [u8], payload_cipher: &[u8]) -> io::Result<()> {
    if padding.is_empty() {
        return Ok(());
    }
    let payload_count_len = payload_cipher.len() & !3;
    let payload_ones = payload_cipher[..payload_count_len]
        .iter()
        .map(|b| b.count_ones())
        .sum::<u32>() as i64;
    let payload_zeros = 8 * payload_cipher.len() as i64 - payload_ones;
    if payload_zeros <= 0 {
        return random_bytes(padding);
    }
    let ratio = payload_ones as f64 / payload_zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return random_bytes(padding);
    }
    let target_ratio_base = if payload_zeros < payload_ones {
        0.4
    } else {
        1.6
    };
    let random_value = f64::from(random_int31()?);
    let target_ratio = target_ratio_base + random_value / 2147483647.0 / 10.0;
    let total_bits = 8 * (padding.len() + payload_cipher.len());
    let target_ones =
        (total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - payload_ones as f64) as i64;
    if target_ones < 0 || target_ones > 8 * padding.len() as i64 {
        return random_bytes(padding);
    }
    fill_padding_with_bit_count(padding, target_ones as usize)
}

/// Reference `fillPaddingWithBitCount`: place `one_bits` bits and shuffle them
/// front-to-back with the reference division mapping (modulo bias kept).
fn fill_padding_with_bit_count(padding: &mut [u8], one_bits: usize) -> io::Result<()> {
    let total_bits = 8 * padding.len();
    if one_bits > total_bits {
        return Err(io::Error::other("snell: invalid padding bit count"));
    }
    let mut bitset = vec![0u8; total_bits];
    bitset[..one_bits].fill(1);
    let mut position = 0usize;
    let mut remaining = total_bits;
    while remaining != 1 {
        let random_value = random_int31()?;
        let divisor = 0x7fff_ffffusize.checked_div(remaining).unwrap_or(0);
        let swap_index = position + (random_value as usize) / (divisor + 1);
        bitset.swap(swap_index, position);
        position += 1;
        remaining -= 1;
    }
    padding.fill(0);
    for (index, bit) in bitset.iter().enumerate() {
        if *bit == 1 {
            padding[index / 8] |= 1 << (index % 8);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AsyncRead over a byte slice for driving the reader in tests.
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

    fn writer(psk: &[u8]) -> RecordWriter<tokio::io::Sink> {
        RecordWriter::new(tokio::io::sink(), psk)
    }

    async fn read_all(reader: &mut RecordReader<SliceReader>) -> Vec<Option<Vec<u8>>> {
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
            if out.len() > 16 {
                panic!("too many records");
            }
        }
        out
    }

    #[tokio::test]
    async fn record_roundtrip() {
        let psk = b"deadbeefdeadbeefdeadbeefdeadbeef";
        let mut w = writer(psk);
        let records = w.emit(now_unix(), b"hello snell world").expect("emit");
        assert_eq!(records.len(), 1);
        let first = &records[0];
        // First record carries the salt and stays within one frame.
        assert!(first.len() > SALT_LEN + HEADER_CIPHER_LEN);
        assert!(
            first.len() <= FRAME_SIZE,
            "first record {} > frame",
            first.len()
        );

        let wire = records.concat();
        let mut reader = RecordReader::new(SliceReader(std::io::Cursor::new(wire)), psk);
        let decoded = read_all(&mut reader).await;
        assert_eq!(decoded, vec![Some(b"hello snell world".to_vec()), None]);
    }

    #[tokio::test]
    async fn record_roundtrip_multi_write_grows_limit() {
        let psk = b"psk-2";
        let mut w = writer(psk);
        let now = now_unix();
        let payload_a = vec![0x41u8; 500];
        let payload_b = vec![0x42u8; 1500];
        let records_a = w.emit(now, &payload_a).expect("emit a");
        let records_b = w.emit(now, &payload_b).expect("emit b");
        assert_eq!(records_a.len(), 1);
        assert_eq!(records_b.len(), 1);

        let wire: Vec<u8> = records_a
            .concat()
            .into_iter()
            .chain(records_b.concat())
            .collect();
        let mut reader = RecordReader::new(SliceReader(std::io::Cursor::new(wire)), psk);
        let decoded = read_all(&mut reader).await;
        assert_eq!(decoded, vec![Some(payload_a), Some(payload_b), None]);
    }

    #[tokio::test]
    async fn large_payload_splits_into_multiple_records() {
        let psk = b"psk-3";
        let mut w = writer(psk);
        let payload = vec![0x77u8; 4000];
        let records = w.emit(now_unix(), &payload).expect("emit");
        assert!(records.len() > 1, "4000 bytes must split");
        let wire = records.concat();
        let mut reader = RecordReader::new(SliceReader(std::io::Cursor::new(wire)), psk);
        let decoded = read_all(&mut reader).await;
        // One entry per record; the stream must reassemble the exact payload.
        assert!(decoded.len() >= 3, "records + eof, got {}", decoded.len());
        assert_eq!(decoded.last(), Some(&None));
        let mut joined = Vec::new();
        for chunk in decoded.iter().flatten() {
            joined.extend_from_slice(chunk);
        }
        assert_eq!(joined, payload);
    }

    #[tokio::test]
    async fn empty_write_emits_zero_chunk() {
        let psk = b"psk-4";
        let mut w = writer(psk);
        let now = now_unix();
        let records = w.emit(now, b"data").expect("emit data");
        let eof_records = w.emit(now, b"").expect("emit eof");
        assert_eq!(eof_records.len(), 1);

        let wire: Vec<u8> = records
            .concat()
            .into_iter()
            .chain(eof_records.concat())
            .collect();
        let mut reader = RecordReader::new(SliceReader(std::io::Cursor::new(wire)), psk);
        let decoded = read_all(&mut reader).await;
        assert_eq!(decoded, vec![Some(b"data".to_vec()), None]);
    }

    #[test]
    fn payload_limit_growth_matches_reference() {
        let mut w = writer(b"p");
        w.initialize().expect("init");
        w.salt_sent = true;
        w.last_write_unix = 1_000;
        // Within the 31s window with no stored limit → base reset limit.
        assert_eq!(w.payload_limit_for(1_005), 1421);
        w.advance_payload_limit(1421, 1_005);
        assert_eq!(w.payload_limit, 2842);
        assert_eq!(w.payload_limit_for(1_006), 2842);
        // Past the window (last advance stamped 1_005) → base again.
        assert_eq!(w.payload_limit_for(1_005 + 31), 1421);
        // First record (salt not sent) → 1405 - initial padding.
        w.salt_sent = false;
        let limit = w.payload_limit_for(2_000);
        assert!((1405 - 511..=1405 - 256).contains(&limit), "limit {limit}");
    }

    #[test]
    fn fill_padding_with_bit_count_places_exact_ones() {
        let mut padding = [0u8; 32];
        fill_padding_with_bit_count(&mut padding, 100).expect("fill");
        let ones: u32 = padding.iter().map(|b| b.count_ones()).sum();
        assert_eq!(ones, 100);

        let mut padding = [0u8; 16];
        fill_padding_with_bit_count(&mut padding, 0).expect("fill");
        assert_eq!(padding, [0u8; 16]);

        let mut padding = [0u8; 16];
        fill_padding_with_bit_count(&mut padding, 128).expect("fill");
        assert_eq!(padding, [0xffu8; 16]);

        let mut padding = [0u8; 16];
        assert!(fill_padding_with_bit_count(&mut padding, 129).is_err());
    }

    #[tokio::test]
    async fn reader_rejects_tampered_payload() {
        let psk = b"psk-5";
        let mut w = writer(psk);
        let mut wire = w.emit(now_unix(), b"secret").expect("emit").concat();
        // Flip a byte inside the sealed payload (past salt + header).
        let index = SALT_LEN + HEADER_CIPHER_LEN + 4;
        wire[index] ^= 0xff;
        let mut reader = RecordReader::new(SliceReader(std::io::Cursor::new(wire)), psk);
        let err = reader.read_record().await.expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // The error sticks.
        let err = reader.read_record().await.expect_err("must fail again");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
