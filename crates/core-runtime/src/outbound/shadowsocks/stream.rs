use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::crypto::{Cipher, Method, derive_subkey, master_key, random_bytes};
use crate::inbound::{AnyRead, AnyWrite, Target};

/// shadowsocks outbound: AEAD (2017) and AEAD-2022 ciphers over TCP.
pub struct Shadowsocks {
    server: String,
    port: u16,
    method: Method,
    master_key: Arc<Vec<u8>>,
    dial: crate::outbound::dial::DialOptions,
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
        Ok(Self {
            server,
            port,
            method,
            master_key: Arc::new(key),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(
        &self,
        target: &Target,
    ) -> io::Result<(SsReader<AnyRead>, SsWriter<AnyWrite>)> {
        let mut stream =
            crate::outbound::dial::connect_tcp(&self.server, self.port, &self.dial).await?;
        let mut salt = vec![0u8; self.method.salt_len()];
        random_bytes(&mut salt)?;
        let subkey = derive_subkey(self.method, &self.master_key, &salt);
        let is_2022 = self.method.is_2022();

        let mut out = Vec::with_capacity(salt.len() + 256);
        out.extend_from_slice(&salt);
        let mut writer_counter = 0u64;
        let mut addr = encode_target(target)?;
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

        let (read_half, write_half) = stream.into_split();
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
            pending: Vec::new(),
            pos: 0,
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

fn encode_target(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match target {
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        },
        Target::Domain(host, _) => {
            out.push(0x03);
            let raw = host.as_bytes();
            if raw.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
}

pub struct SsWriter<W> {
    inner: W,
    cipher: Cipher,
    counter: u64,
    max_chunk: u16,
    buf: Vec<u8>,
}

impl<W: tokio::io::AsyncWrite + Unpin> SsWriter<W> {
    pub async fn write_chunk(&mut self, plaintext: &[u8]) -> io::Result<()> {
        for segment in plaintext.chunks(usize::from(self.max_chunk)) {
            self.buf.clear();

            let mut len_part = Vec::with_capacity(2 + 16);
            len_part.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            self.cipher.seal(self.counter, &mut len_part)?;
            self.counter += 1;
            self.buf.extend_from_slice(&len_part);

            let mut payload_part = Vec::with_capacity(segment.len() + 16);
            payload_part.extend_from_slice(segment);
            self.cipher.seal(self.counter, &mut payload_part)?;
            self.counter += 1;
            self.buf.extend_from_slice(&payload_part);

            self.inner.write_all(&self.buf).await?;
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
    pending: Vec<u8>,
    pos: usize,
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
    async fn read_exact_len(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            let n = self.inner.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed mid-chunk",
                ));
            }
            filled += n;
        }
        Ok(buf)
    }

    fn establish_response_cipher(&mut self, salt: &[u8]) {
        let subkey = derive_subkey(self.method, &self.master_key, salt);
        self.cipher = Some(Cipher::new(self.method, &subkey));
        self.counter = 0;
    }

    fn open_chunk(&self, counter: u64, buf: &mut Vec<u8>) -> io::Result<()> {
        self.cipher
            .as_ref()
            .expect("cipher established")
            .open(counter, buf)
    }

    /// Fill `pending` with the next decrypted chunk payload.
    async fn fill(&mut self) -> io::Result<()> {
        match self.state {
            ReaderState::ResponseSalt => {
                self.state = ReaderState::Chunks;
                let mut salt = vec![0u8; self.request_salt.len()];
                self.read_exact_into(&mut salt).await?;
                self.establish_response_cipher(&salt);
                let salt_len = salt.len();
                let header_len = 11 + salt_len;
                let mut chunk = self.read_exact_len(header_len + 16).await?;
                self.open_chunk(self.counter, &mut chunk)?;
                self.counter += 1;
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
                if payload_len == 0 {
                    return Err(io::Error::other("zero-length chunk"));
                }
                let mut payload = self.read_exact_len(payload_len + 16).await?;
                self.open_chunk(self.counter, &mut payload)?;
                self.counter += 1;
                self.pending = payload;
                Ok(())
            }
            ReaderState::ChunksAfterSalt => {
                self.state = ReaderState::Chunks;
                let mut salt = vec![0u8; self.request_salt.len()];
                self.read_exact_into(&mut salt).await?;
                self.establish_response_cipher(&salt);
                let mut chunk = self.read_exact_len(2 + 16).await?;
                self.open_chunk(self.counter, &mut chunk)?;
                self.counter += 1;
                let payload_len = usize::from(u16::from_be_bytes([chunk[0], chunk[1]]));
                if payload_len == 0 {
                    return Err(io::Error::other("zero-length chunk"));
                }
                let mut payload = self.read_exact_len(payload_len + 16).await?;
                self.open_chunk(self.counter, &mut payload)?;
                self.counter += 1;
                self.pending = payload;
                Ok(())
            }
            ReaderState::Chunks => {
                let mut chunk = self.read_exact_len(2 + 16).await?;
                self.open_chunk(self.counter, &mut chunk)?;
                self.counter += 1;
                let payload_len = usize::from(u16::from_be_bytes([chunk[0], chunk[1]]));
                if payload_len == 0 {
                    return Err(io::Error::other("zero-length chunk"));
                }
                let mut payload = self.read_exact_len(payload_len + 16).await?;
                self.open_chunk(self.counter, &mut payload)?;
                self.counter += 1;
                self.pending = payload;
                Ok(())
            }
        }
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.inner.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed mid-salt",
                ));
            }
            filled += n;
        }
        Ok(())
    }

    pub async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.pending.len() {
            self.pending.clear();
            self.pos = 0;
            self.fill().await?;
        }
        let avail = self.pending.len() - self.pos;
        let n = out.len().min(avail);
        out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}
