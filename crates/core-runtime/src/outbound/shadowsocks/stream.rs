use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::crypto::{AEAD_TAG, Cipher, Method, derive_subkey, master_key, random_bytes};
use crate::inbound::{AnyRead, AnyStream, AnyWrite, Target};

/// Read buffer floor, several records deep: `need` reads as much as the buffer
/// has room for in one syscall, so a bigger buffer means fewer syscalls per GiB
/// -- with 33 KiB the steady state was one record per `recvfrom` while a peer
/// with a large buffer drained four or five records per `read`. Allocated only
/// when the first byte of the response is about to be read.
const READ_BUF: usize = 256 * 1024;
/// Every sealed block carries a tag; the wire overhead of one chunk is its length
/// block, the tag on that block and the tag on the payload.
const BLOCK_OVERHEAD: usize = 2 + AEAD_TAG + AEAD_TAG;
/// Largest frame a connection keeps between writes. The relay hands over 128 KiB
/// at a time, which seals to a little more than that, so the steady state stays
/// well under this and the buffer is never dropped.
const WRITE_BUF_KEEP: usize = 256 * 1024;

/// Read buffer big enough for one whole record of `method` plus the length block
/// of the next one.
///
/// The reader asks for a *payload* (`payload_len + AEAD_TAG`), but what it needs
/// is room for the record that payload belongs to. Sizing to the payload leaves a
/// 2022 buffer one length block short of its own record: `need(18)` consumes the
/// header, `need(65551)` then finds 18 bytes missing and moves the whole 65533-byte
/// payload to the front before it can read them -- a full copy of every byte, every
/// record, plus a syscall and a wakeup it would not have needed. Legacy records are
/// small enough that two of them fit, which is why only 2022 paid it.
fn read_buf(method: Method) -> usize {
    (usize::from(method.max_chunk()) + BLOCK_OVERHEAD).max(READ_BUF)
}

/// shadowsocks outbound: AEAD (2017) and AEAD-2022 ciphers over TCP.
pub struct Shadowsocks {
    server: String,
    port: u16,
    method: Method,
    master_key: Arc<Vec<u8>>,
    dial: crate::outbound::dial::DialOptions,
    tls: Option<crate::tls_client::TlsOptions>,
}

impl Shadowsocks {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let server = obj
            .get("server")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing server"))?
            .to_string();
        let port = obj
            .get("server_port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .ok_or_else(|| anyhow::anyhow!("{at}: missing server_port"))?;
        let method = obj
            .get("method")
            .and_then(Value::as_str)
            .and_then(Method::parse)
            .ok_or_else(|| anyhow::anyhow!("{at}: method not implemented"))?;
        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?;
        let key =
            master_key(method, password).map_err(|e| anyhow::anyhow!("{at}: bad password: {e}"))?;
        // TLS wraps the whole shadowsocks session, salt and head included, the
        // way the reference dials it: `tls` is a container on the outbound and
        // not a separate transport.
        let tls = crate::tls_client::TlsOptions::from_outbound(obj, &server, at)?;
        Ok(Self {
            server,
            port,
            method,
            master_key: Arc::new(key),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
            tls,
        })
    }

    pub async fn connect(
        &self,
        target: &Target,
    ) -> io::Result<(SsReader<AnyRead>, SsWriter<AnyWrite>)> {
        let tcp = crate::outbound::dial::connect_tcp(&self.server, self.port, &self.dial).await?;
        let mut stream: AnyStream = match &self.tls {
            Some(tls) => tls.wrap_with_defaults(tcp, &[]).await?,
            None => Box::new(tcp),
        };
        let mut salt = vec![0u8; self.method.salt_len()];
        random_bytes(&mut salt)?;
        let subkey = derive_subkey(self.method, &self.master_key, &salt);
        let is_2022 = self.method.is_2022();

        let mut out = Vec::with_capacity(salt.len() + 256);
        out.extend_from_slice(&salt);
        let mut writer_counter = 0u64;
        let mut addr = crate::outbound::proxy::encode_target(target)?;
        if is_2022 {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| io::Error::other(format!("clock: {e}")))?
                .as_secs();
            let mut rand = [0u8; 1];
            random_bytes(&mut rand)?;
            let pad_len = 1 + usize::from(rand[0] & 0x7F);
            let mut padding = vec![0u8; pad_len];
            random_bytes(&mut padding)?;

            let var_len = addr.len() + 2 + padding.len();
            let mut fixed = Vec::with_capacity(11 + 16);
            fixed.push(0x00);
            fixed.extend_from_slice(&timestamp.to_be_bytes());
            fixed.extend_from_slice(
                &(u16::try_from(var_len).map_err(|_| io::Error::other("header too large"))?)
                    .to_be_bytes(),
            );
            let request_cipher = Cipher::new(self.method, &subkey);
            request_cipher.seal(writer_counter, &mut fixed)?;
            writer_counter += 1;
            out.extend_from_slice(&fixed);

            addr.extend_from_slice(&(padding.len() as u16).to_be_bytes());
            addr.extend_from_slice(&padding);
            request_cipher.seal(writer_counter, &mut addr)?;
            writer_counter += 1;
            out.extend_from_slice(&addr);
        }
        stream.write_all(&out).await?;

        let (read_half, write_half) = tokio::io::split(stream);
        let mut writer = SsWriter {
            inner: Box::new(write_half) as AnyWrite,
            cipher: Cipher::new(self.method, &subkey),
            counter: writer_counter,
            max_chunk: self.method.max_chunk(),
            buf: Vec::new(),
        };
        if !is_2022 {
            writer.write_chunk(&addr).await?;
        }
        let reader = SsReader {
            inner: Box::new(read_half) as AnyRead,
            method: self.method,
            master_key: Arc::clone(&self.master_key),
            cipher: None,
            counter: 0,
            rbuf: Vec::new(),
            rpos: 0,
            rend: 0,
            pos: 0,
            pend: 0,
            pending_len: None,
            request_salt: salt,
            read_buf: read_buf(self.method),
            state: if is_2022 {
                ReaderState::ResponseSalt
            } else {
                ReaderState::ChunksAfterSalt
            },
        };
        Ok((reader, writer))
    }
}

pub struct SsWriter<W> {
    inner: W,
    cipher: Cipher,
    counter: u64,
    max_chunk: u16,
    buf: Vec<u8>,
}

impl<W: tokio::io::AsyncWrite + Unpin> SsWriter<W> {
    /// Seal `plaintext` as one or more chunks into the reused buffer and send the
    /// lot with a single write: no temporary vectors, one syscall per call
    /// instead of one per 16 KiB.
    pub async fn write_chunk(&mut self, plaintext: &[u8]) -> io::Result<()> {
        // sized before the frame is built: growing into it reallocates and copies,
        // and `Vec`'s doubling lands above `WRITE_BUF_KEEP`, so the buffer used to
        // be dropped and regrown on every single write
        let chunks = plaintext.len().div_ceil(usize::from(self.max_chunk)).max(1);
        let need = plaintext.len() + chunks * BLOCK_OVERHEAD;
        if self.buf.capacity() < need {
            self.buf.reserve_exact(need - self.buf.len());
        }
        self.buf.clear();
        for segment in plaintext.chunks(usize::from(self.max_chunk)) {
            let head = self.buf.len();
            self.buf
                .extend_from_slice(&(segment.len() as u16).to_be_bytes());
            self.cipher.seal_at(self.counter, &mut self.buf, head)?;
            self.counter += 1;

            let body = self.buf.len();
            self.buf.extend_from_slice(segment);
            self.cipher.seal_at(self.counter, &mut self.buf, body)?;
            self.counter += 1;
        }
        self.inner.write_all(&self.buf).await?;
        // a one-off big write must not pin its buffer for the connection's life
        if self.buf.capacity() > WRITE_BUF_KEEP {
            self.buf = Vec::new();
        }
        Ok(())
    }
}

pub struct SsReader<R> {
    inner: R,
    method: Method,
    master_key: Arc<Vec<u8>>,
    cipher: Option<Cipher>,
    counter: u64,
    /// what `rbuf` is grown to when the first record is waited for
    read_buf: usize,
    /// Bytes off the wire that nothing has consumed yet: `rbuf[rpos..rend]`.
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// The decrypted payload being handed out, in place: `rbuf[pos..pend]`.
    pos: usize,
    pend: usize,
    /// Length block already opened, payload not yet fully buffered: the record
    /// is half-parsed and `fill` owes the caller its payload.
    pending_len: Option<usize>,
    request_salt: Vec<u8>,
    state: ReaderState,
}

enum ReaderState {
    /// 2022 only: read the response salt, then the fixed header chunk.
    ResponseSalt,
    /// Legacy: read the response salt, then plain length chunks.
    ChunksAfterSalt,
    Chunks,
}

impl<R: tokio::io::AsyncRead + Unpin> SsReader<R> {
    /// Make `rbuf[rpos..rend]` at least `n` bytes long, reading as much as the
    /// buffer has room for in each call so several chunks arrive per syscall.
    /// Only called once the previous payload has been handed out whole, so
    /// moving the unread bytes to the front disturbs nothing.
    async fn need(&mut self, n: usize, eof: &'static str) -> io::Result<()> {
        if self.rend - self.rpos >= n {
            return Ok(());
        }
        if self.rpos > 0 {
            self.rbuf.copy_within(self.rpos..self.rend, 0);
            self.rend -= self.rpos;
            self.rpos = 0;
        }
        if self.rbuf.len() < n {
            self.rbuf.resize((n + 2 + AEAD_TAG).max(self.read_buf), 0);
        }
        while self.rend < n {
            let got = self.inner.read(&mut self.rbuf[self.rend..]).await?;
            if got == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, eof));
            }
            self.rend += got;
        }
        Ok(())
    }

    fn establish_response_cipher(&mut self, salt: &[u8]) {
        let subkey = derive_subkey(self.method, &self.master_key, salt);
        self.cipher = Some(Cipher::new(self.method, &subkey));
        self.counter = 0;
    }

    /// Open the `len` bytes at `rpos` in place and step past them.
    fn open_next(&mut self, len: usize) -> io::Result<()> {
        let at = self.rpos;
        self.cipher
            .as_ref()
            .expect("cipher established")
            .open_slice(self.counter, &mut self.rbuf[at..at + len])?;
        self.counter += 1;
        self.rpos += len;
        Ok(())
    }

    /// One `[len][payload]` pair: the length block, then the payload it names.
    async fn take_chunk(&mut self) -> io::Result<()> {
        self.need(2 + 16, "stream closed mid-chunk").await?;
        let head = self.rpos;
        self.open_next(2 + 16)?;
        let payload_len = usize::from(u16::from_be_bytes([self.rbuf[head], self.rbuf[head + 1]]));
        self.take_payload(payload_len).await
    }

    async fn take_payload(&mut self, payload_len: usize) -> io::Result<()> {
        if payload_len == 0 {
            return Err(io::Error::other("zero-length chunk"));
        }
        self.need(payload_len + 16, "stream closed mid-chunk")
            .await?;
        self.pos = self.rpos;
        self.pend = self.rpos + payload_len;
        self.open_next(payload_len + 16)
    }

    async fn take_salt(&mut self) -> io::Result<Vec<u8>> {
        let len = self.request_salt.len();
        self.need(len, "stream closed mid-salt").await?;
        let salt = self.rbuf[self.rpos..self.rpos + len].to_vec();
        self.rpos += len;
        Ok(salt)
    }

    /// Make the next decrypted chunk payload readable at `rbuf[pos..pend]`.
    async fn fill(&mut self) -> io::Result<()> {
        match self.state {
            ReaderState::ResponseSalt => {
                self.state = ReaderState::Chunks;
                let salt = self.take_salt().await?;
                self.establish_response_cipher(&salt);
                let salt_len = salt.len();
                let header_len = 11 + salt_len;
                self.need(header_len + 16, "stream closed mid-chunk")
                    .await?;
                let at = self.rpos;
                self.open_next(header_len + 16)?;
                let chunk = &self.rbuf[at..at + header_len];
                if chunk[0] != 0x01 {
                    return Err(io::Error::other("bad response header type"));
                }
                if chunk[9..9 + salt_len] != self.request_salt[..] {
                    return Err(io::Error::other("response salt mismatch"));
                }
                let payload_len = usize::from(u16::from_be_bytes([
                    chunk[header_len - 2],
                    chunk[header_len - 1],
                ]));
                self.take_payload(payload_len).await
            }
            ReaderState::ChunksAfterSalt => {
                self.state = ReaderState::Chunks;
                let salt = self.take_salt().await?;
                self.establish_response_cipher(&salt);
                self.take_chunk().await
            }
            ReaderState::Chunks => {
                if let Some(payload_len) = self.pending_len.take() {
                    self.take_payload(payload_len).await
                } else {
                    self.take_chunk().await
                }
            }
        }
    }

    /// The next record without touching the socket: false when a byte it needs
    /// is not buffered yet. Opening the length block that turns out to be
    /// short is not thrown away -- its length is parked in `pending_len` and
    /// the next `fill` picks the payload up from there.
    fn try_fill_buffered(&mut self) -> io::Result<bool> {
        if !matches!(self.state, ReaderState::Chunks) || self.cipher.is_none() {
            return Ok(false);
        }
        if self.pending_len.is_none() {
            if self.rend - self.rpos < 2 + AEAD_TAG {
                return Ok(false);
            }
            let head = self.rpos;
            self.open_next(2 + AEAD_TAG)?;
            let payload_len =
                usize::from(u16::from_be_bytes([self.rbuf[head], self.rbuf[head + 1]]));
            if payload_len == 0 {
                return Err(io::Error::other("zero-length chunk"));
            }
            self.pending_len = Some(payload_len);
        }
        let payload_len = self.pending_len.expect("set above");
        if self.rend - self.rpos < payload_len + AEAD_TAG {
            return Ok(false);
        }
        self.pending_len = None;
        self.pos = self.rpos;
        self.pend = self.rpos + payload_len;
        self.open_next(payload_len + AEAD_TAG)?;
        Ok(true)
    }

    /// Hand out as much of `out` as complete buffered records allow: the relay
    /// writes whole multiples of a record to the socket only if this fills past
    /// one record, and one record per `write` is one syscall per record.
    pub async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut got = 0;
        loop {
            if self.pos == self.pend {
                if got == 0 {
                    self.fill().await?;
                } else if !self.try_fill_buffered()? {
                    break;
                }
            }
            let n = (out.len() - got).min(self.pend - self.pos);
            out[got..got + n].copy_from_slice(&self.rbuf[self.pos..self.pos + n]);
            self.pos += n;
            got += n;
            if got == out.len() {
                break;
            }
        }
        Ok(got)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Instant;

    struct Slab {
        data: Vec<u8>,
        pos: usize,
    }
    impl tokio::io::AsyncRead for Slab {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            out: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = out.remaining().min(self.data.len() - self.pos);
            out.put_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    /// The outbound reader the client relay drives, against the bare open and
    /// against the inbound ChunkReader's numbers: the client half of a matrix
    /// cell in isolation.
    ///
    ///     cargo test --release -p core-runtime --lib outbound::shadowsocks::stream::tests::ssreader_costs -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "microbenchmark, run by hand"]
    async fn ssreader_costs() {
        const PAYLOAD: usize = 65535;
        const GIB: u64 = 1u64 << 30;
        let payload = vec![0x5Au8; PAYLOAD];
        let key = vec![7u8; 32];
        let records = GIB / PAYLOAD as u64;

        for method in [Method::Blake3Aes128Gcm, Method::Blake3ChaCha20Poly1305] {
            // the wire the peer would have sent: length block + payload
            let mut wire = Vec::new();
            {
                let peer = Cipher::new(method, &key);
                let mut ctr = 0u64;
                for _ in 0..records {
                    let at = wire.len();
                    wire.extend_from_slice(&(PAYLOAD as u16).to_be_bytes());
                    peer.seal_at(ctr, &mut wire, at).expect("seal");
                    ctr += 1;
                    let at = wire.len();
                    wire.extend_from_slice(&payload);
                    peer.seal_at(ctr, &mut wire, at).expect("seal");
                    ctr += 1;
                }
            }

            // the bare open, in place, run in full every time against the
            // already-plain block: no re-seal, no copy
            {
                let cipher = Cipher::new(method, &key);
                let peer = Cipher::new(method, &key);
                let mut block = payload.clone();
                peer.seal_at(0, &mut block, 0).expect("seal");
                let n = GIB / PAYLOAD as u64;
                let t = Instant::now();
                for _ in 0..n {
                    let _ = cipher.open_slice(0, &mut block);
                }
                let secs = t.elapsed().as_secs_f64();
                let gib = (n * PAYLOAD as u64) as f64 / GIB as f64;
                println!(
                    "{method:?} open_slice (in place)   {:7.3} s/GiB",
                    secs / gib
                );
            }

            // stage B: the reader's own machinery (need, open, two blocks per
            // record) without the copy into the relay's buffer
            {
                let mut reader = SsReader {
                    inner: Box::new(Slab {
                        data: wire.clone(),
                        pos: 0,
                    }) as AnyRead,
                    method,
                    master_key: Arc::new(key.clone()),
                    cipher: Some(Cipher::new(method, &key)),
                    counter: 0,
                    rbuf: Vec::new(),
                    rpos: 0,
                    rend: 0,
                    pos: 0,
                    pend: 0,
                    pending_len: None,
                    request_salt: vec![9u8; method.salt_len()],
                    read_buf: read_buf(method),
                    state: ReaderState::Chunks,
                };
                for _ in 0..2 {
                    reader.fill().await.expect("warm fill");
                }
                let n = records - 2;
                let t = Instant::now();
                for _ in 0..n {
                    reader.fill().await.expect("fill");
                }
                let secs = t.elapsed().as_secs_f64();
                let gib = (records.saturating_sub(2)) as f64 * PAYLOAD as f64 / GIB as f64;
                println!(
                    "{method:?} SsReader::fill (no copy)  {:7.3} s/GiB",
                    secs / gib
                );
            }

            let mut reader = SsReader {
                inner: Box::new(Slab { data: wire, pos: 0 }) as AnyRead,
                method,
                master_key: Arc::new(key.clone()),
                cipher: Some(Cipher::new(method, &key)),
                counter: 0,
                rbuf: Vec::new(),
                rpos: 0,
                rend: 0,
                pos: 0,
                pend: 0,
                pending_len: None,
                request_salt: vec![9u8; method.salt_len()],
                read_buf: read_buf(method),
                state: ReaderState::Chunks,
            };
            let mut buf = vec![0u8; 64 * 1024];
            let mut got = 0u64;
            let warm = 2 * PAYLOAD as u64;
            while got < warm {
                got += reader.read(&mut buf).await.expect("warm read") as u64;
            }
            // one read may straddle two records, so the warm phase can carry a
            // byte or two into the timed one: count from where warm stopped,
            // never from zero, or the tail asks the slab for bytes it split off
            let target = records * PAYLOAD as u64;
            let t = Instant::now();
            while got < target {
                let n = reader.read(&mut buf).await.expect("read");
                assert!(n > 0, "the slab ran short");
                got += n as u64;
            }
            let secs = t.elapsed().as_secs_f64();
            let gib = (target - warm) as f64 / GIB as f64;
            println!(
                "{method:?} SsReader::read          {:7.3} s/GiB",
                secs / gib
            );
        }
    }
}
