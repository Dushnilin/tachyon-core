use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::crypto::{Cipher, Method, derive_subkey, master_key, random_bytes};
use crate::inbound::{AnyRead, AnyStream, AnyWrite, Target};

/// Read buffer of a connection: two legacy chunks (`0x3FFF` + tag each) and the
/// length blocks between them, so one `read` usually brings in whole chunks.
/// It is only allocated when the first byte of the response is about to be read.
const READ_BUF: usize = 33 * 1024;
/// Largest write buffer a connection keeps between writes. The relay hands over
/// 32 KiB at a time, which seals to a little more than that.
const WRITE_BUF_KEEP: usize = 40 * 1024;

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
            request_salt: salt,
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
    /// Bytes off the wire that nothing has consumed yet: `rbuf[rpos..rend]`.
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// The decrypted payload being handed out, in place: `rbuf[pos..pend]`.
    pos: usize,
    pend: usize,
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
            self.rbuf.resize(n.max(READ_BUF), 0);
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
            ReaderState::Chunks => self.take_chunk().await,
        }
    }

    pub async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.pend {
            self.fill().await?;
        }
        let n = out.len().min(self.pend - self.pos);
        out[..n].copy_from_slice(&self.rbuf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}
