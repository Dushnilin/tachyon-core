//! vmess outbound: AEAD request header (alterId == 0) with AES-128-GCM,
//! chacha20-poly1305, or no body encryption, plus optional chunk masking,
//! global padding, and authenticated length. Legacy CFB headers, transports,
//! and UDP packet commands are not implemented yet.

mod framing;
pub(crate) mod kdf;
mod wire;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use cfb_mode::cipher::KeyIvInit;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::inbound::{AnyStream, Target};
use crate::outbound::packet::{CMD_TCP, PacketEncoding, ResponseHeaderStream, spawn_packet_bridge};
use crate::outbound::proxy::server_endpoint;
use crate::outbound::shadowsocks::crypto::random_bytes;
use crate::outbound::transport::Transport;
use crate::outbound::vmess::framing::{
    BodyWriter, CfbDecrypt, CfbEncrypt, FrameAssembler, WRITE_CHUNK,
};
use crate::outbound::vmess::wire::{
    derive_response_keys, legacy_header_hash, legacy_response_keys, legacy_time_iv,
    response_header_keys, seal_request_header, unix_now,
};
use crate::tls_client::TlsOptions;

pub(crate) const SEC_LEGACY: u8 = 1;
pub(crate) const SEC_AES128_GCM: u8 = 3;
pub(crate) const SEC_CHACHA20_POLY1305: u8 = 4;
pub(crate) const SEC_NONE: u8 = 5;

const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;

pub struct Vmess {
    server: String,
    port: u16,
    cmd_key: [u8; 16],
    security: u8,
    global_padding: bool,
    authenticated_length: bool,
    alter_key: Option<[u8; 16]>,
    transport: Transport,
    tls: Option<TlsOptions>,
    /// how datagrams are framed on the stream, see `packet`
    packet_encoding: PacketEncoding,
}

impl Vmess {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let uuid_raw = obj
            .get("uuid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing uuid"))?;
        let uuid = kdf::parse_uuid(uuid_raw).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        let cmd_key = kdf::cmd_key(&uuid);

        let alter_id = obj.get("alter_id").and_then(Value::as_u64).unwrap_or(0);
        let alter_key = match alter_id {
            0 => None,
            _ => Some(kdf::alter_key(&uuid)),
        };
        if obj
            .get("multiplex")
            .and_then(|m| m.get("enabled"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            anyhow::bail!("{at}: vmess multiplex not implemented yet");
        }
        let packet_encoding =
            PacketEncoding::parse(obj.get("packet_encoding").and_then(Value::as_str), at)?;

        let tls = TlsOptions::from_outbound(obj, &server, at)?;
        let security = match obj
            .get("security")
            .and_then(Value::as_str)
            .unwrap_or("auto")
        {
            "" | "auto" => {
                if tls.is_some() {
                    SEC_NONE
                } else {
                    SEC_AES128_GCM
                }
            }
            "none" | "zero" => SEC_NONE,
            "aes-128-gcm" => SEC_AES128_GCM,
            "chacha20-poly1305" => SEC_CHACHA20_POLY1305,
            "aes-128-cfb" => SEC_LEGACY,
            other => anyhow::bail!("{at}: vmess security {other:?} not supported"),
        };
        Ok(Self {
            server,
            port,
            cmd_key,
            security,
            global_padding: obj
                .get("global_padding")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            authenticated_length: obj
                .get("authenticated_length")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            alter_key,
            transport: Transport::parse(obj, at)?,
            tls,
            packet_encoding,
        })
    }

    /// The sealed request head for `command` (1 tcp, 2 udp, 3 mux).
    fn request(
        &self,
        command: u8,
        target: &Target,
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
        response_header: u8,
    ) -> io::Result<Vec<u8>> {
        let mut option = 0u8;
        if self.security == SEC_AES128_GCM || self.security == SEC_CHACHA20_POLY1305 {
            option |= OPT_CHUNK_STREAM | OPT_CHUNK_MASKING;
            if self.global_padding {
                option |= OPT_GLOBAL_PADDING;
            }
            if self.authenticated_length {
                option |= OPT_AUTHENTICATED_LENGTH;
            }
        } else if self.security == SEC_LEGACY {
            option |= OPT_CHUNK_STREAM;
        }

        let header = wire::build_request_header(
            request_iv,
            request_key,
            response_header,
            option,
            self.security,
            command,
            target,
        )?;
        if let Some(alter_key) = &self.alter_key {
            // Legacy header: HMAC-MD5(alterKey, ts) || CFB(cmdKey, md5(ts x4)).
            let timestamp = unix_now()?;
            let mut request = Vec::with_capacity(16 + header.len());
            request.extend_from_slice(&legacy_header_hash(alter_key, timestamp));
            let mut encrypted = header;
            let mut cfb = CfbEncrypt::new_from_slices(&self.cmd_key, &legacy_time_iv(timestamp))
                .map_err(|_| io::Error::other("cfb init"))?;
            cfb.encrypt(&mut encrypted);
            request.extend_from_slice(&encrypted);
            Ok(request)
        } else {
            seal_request_header(&self.cmd_key, &header)
        }
    }

    /// A datagram relay. vmess packets ride the raw stream after the request
    /// head, not the body cipher, so only the response header is consumed.
    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let mut request_key = [0u8; 16];
        let mut request_iv = [0u8; 16];
        let mut response_header = [0u8; 1];
        random_bytes(&mut request_key)?;
        random_bytes(&mut request_iv)?;
        random_bytes(&mut response_header)?;
        let mode = self.packet_encoding;
        let first = self.request(
            mode.command(),
            &mode.request_target(target),
            &request_key,
            &request_iv,
            response_header[0],
        )?;
        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let tcp = crate::dns::connect_tcp(self.server.as_str(), self.port).await?;
        let (mut stream, consumed) = self
            .transport
            .connect(tcp, self.tls.as_ref(), &self.server, self.port, &first)
            .await?;
        stream.write_all(&first[consumed..]).await?;
        let stream: AnyStream = Box::new(ResponseHeaderStream::new(stream));
        spawn_packet_bridge(stream, peer, mode, target.clone());
        Ok(local)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let mut request_key = [0u8; 16];
        let mut request_iv = [0u8; 16];
        let mut response_header = [0u8; 1];
        random_bytes(&mut request_key)?;
        random_bytes(&mut request_iv)?;
        random_bytes(&mut response_header)?;

        let first = self.request(
            CMD_TCP,
            target,
            &request_key,
            &request_iv,
            response_header[0],
        )?;
        let tcp = crate::dns::connect_tcp(self.server.as_str(), self.port).await?;
        // a ws transport with early data carries the request in the upgrade head
        let (mut stream, consumed) = self
            .transport
            .connect(tcp, self.tls.as_ref(), &self.server, self.port, &first)
            .await?;
        stream.write_all(&first[consumed..]).await?;

        let (response_key, response_iv) = derive_response_keys(&request_key, &request_iv);
        let (len_key, len_nonce, hdr_key, hdr_nonce) =
            response_header_keys(&response_key, &response_iv);
        let legacy_resp_cfb = if self.alter_key.is_some() {
            let (rk, riv) = legacy_response_keys(&request_key, &request_iv);
            Some(CfbDecrypt::new_from_slices(&rk, &riv).map_err(|_| io::Error::other("cfb init"))?)
        } else {
            None
        };
        Ok(Box::new(VmessStream {
            inner: stream,
            security: self.security,
            response_header: response_header[0],
            len_key,
            len_nonce,
            hdr_key,
            hdr_nonce,
            request_key,
            request_iv,
            response_key,
            response_iv,
            global_padding: self.global_padding,
            authenticated_length: self.authenticated_length,
            legacy_resp_cfb,
            read: if self.alter_key.is_some() {
                ReadPhase::LegacyRespHeader { buf: Vec::new() }
            } else {
                ReadPhase::RespLen { buf: Vec::new() }
            },
            write: match self.security {
                SEC_NONE => WritePhase::Raw,
                _ => WritePhase::Framed(Box::new(WriterState {
                    body: BodyWriter::new(
                        self.security,
                        &request_key,
                        &request_iv,
                        self.global_padding,
                        true,
                        self.authenticated_length,
                    ),
                    flushing: None,
                    consumed: 0,
                })),
            },
        }))
    }
}

struct VmessStream {
    inner: AnyStream,
    security: u8,
    response_header: u8,
    len_key: [u8; 16],
    len_nonce: [u8; 12],
    hdr_key: [u8; 16],
    hdr_nonce: [u8; 12],
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_key: [u8; 16],
    response_iv: [u8; 16],
    global_padding: bool,
    authenticated_length: bool,
    /// CFB stream for the legacy 4-byte response header (alterId > 0);
    /// continued into the body for the legacy security.
    legacy_resp_cfb: Option<CfbDecrypt>,
    read: ReadPhase,
    write: WritePhase,
}

enum ReadPhase {
    /// Raw passthrough (security none over TCP).
    Raw,
    /// AEAD response header: 18-byte encrypted length block.
    RespLen { buf: Vec<u8> },
    /// AEAD response header payload of `need` bytes.
    RespPayload { buf: Vec<u8>, need: usize },
    /// Legacy response header: 4 CFB-decrypted bytes (alterId > 0).
    LegacyRespHeader { buf: Vec<u8> },
    /// Body frames via the per-security assembler.
    Body(Box<FrameAssembler>),
}

enum WritePhase {
    Raw,
    Framed(Box<WriterState>),
}

struct WriterState {
    body: BodyWriter,
    flushing: Option<(Vec<u8>, usize)>,
    consumed: usize,
}

enum HeaderStep {
    RespLen(Vec<u8>),
    RespPayload(Vec<u8>, usize),
    LegacyRespHeader(Vec<u8>),
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if matches!(this.read, ReadPhase::Raw) {
                return Pin::new(&mut this.inner).poll_read(cx, out);
            }
            let step = match std::mem::replace(&mut this.read, ReadPhase::Raw) {
                ReadPhase::Raw => unreachable!("raw handled above"),
                ReadPhase::RespLen { buf } => HeaderStep::RespLen(buf),
                ReadPhase::RespPayload { buf, need } => HeaderStep::RespPayload(buf, need),
                ReadPhase::LegacyRespHeader { buf } => HeaderStep::LegacyRespHeader(buf),
                ReadPhase::Body(assembler) => {
                    this.read = ReadPhase::Body(assembler);
                    let ReadPhase::Body(assembler) = &mut this.read else {
                        unreachable!("just stored")
                    };
                    return assembler.poll_read(&mut this.inner, cx, out);
                }
            };
            match step {
                HeaderStep::RespLen(mut buf) => {
                    match poll_fill(&mut this.inner, cx, &mut buf, 18) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::other(
                                "vmess: connection closed before response header",
                            )));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            this.read = ReadPhase::RespLen { buf };
                            return Poll::Pending;
                        }
                    }
                    wire::gcm_open(&this.len_key, &this.len_nonce, &[], &mut buf)
                        .map_err(|e| io::Error::other(format!("resp-len: {e}")))?;
                    let header_len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
                    this.read = ReadPhase::RespPayload {
                        buf: Vec::with_capacity(header_len + 16),
                        need: header_len + 16,
                    };
                }
                HeaderStep::RespPayload(mut buf, need) => {
                    match poll_fill(&mut this.inner, cx, &mut buf, need) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::other(
                                "vmess: connection closed before response header payload",
                            )));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            this.read = ReadPhase::RespPayload { buf, need };
                            return Poll::Pending;
                        }
                    }
                    wire::gcm_open(&this.hdr_key, &this.hdr_nonce, &[], &mut buf)
                        .map_err(|e| io::Error::other(format!("resp-payload: {e}")))?;
                    if buf.first() != Some(&this.response_header) {
                        return Poll::Ready(Err(io::Error::other(
                            "vmess: unexpected response header",
                        )));
                    }
                    this.read = if this.security == SEC_NONE {
                        ReadPhase::Raw
                    } else {
                        // AEAD header with a legacy body: the download CFB
                        // stream starts fresh with the sha256-derived keys.
                        let cfb = (this.security == SEC_LEGACY).then(|| {
                            CfbDecrypt::new_from_slices(&this.response_key, &this.response_iv)
                                .expect("cfb key/iv length")
                        });
                        let assembler = FrameAssembler::new(
                            this.security,
                            &this.request_key,
                            &this.request_iv,
                            &this.response_key,
                            &this.response_iv,
                            this.global_padding,
                            true,
                            this.authenticated_length,
                            cfb,
                        );
                        ReadPhase::Body(Box::new(assembler))
                    };
                }
                HeaderStep::LegacyRespHeader(mut buf) => {
                    match poll_fill(&mut this.inner, cx, &mut buf, 4) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::other(
                                "vmess: connection closed before response header",
                            )));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            this.read = ReadPhase::LegacyRespHeader { buf };
                            return Poll::Pending;
                        }
                    }
                    if let Some(cfb) = &mut this.legacy_resp_cfb {
                        cfb.decrypt(&mut buf);
                    }
                    if buf.first() != Some(&this.response_header) {
                        return Poll::Ready(Err(io::Error::other(
                            "vmess: unexpected response header",
                        )));
                    }
                    this.read = if this.security == SEC_NONE {
                        ReadPhase::Raw
                    } else {
                        // Legacy headers derive response keys with MD5; the
                        // CFB stream continues only into a legacy body.
                        let (rk, riv) = legacy_response_keys(&this.request_key, &this.request_iv);
                        let cfb = if this.security == SEC_LEGACY {
                            this.legacy_resp_cfb.take()
                        } else {
                            None
                        };
                        let assembler = FrameAssembler::new(
                            this.security,
                            &this.request_key,
                            &this.request_iv,
                            &rk,
                            &riv,
                            this.global_padding,
                            true,
                            this.authenticated_length,
                            cfb,
                        );
                        ReadPhase::Body(Box::new(assembler))
                    };
                }
            }
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let WritePhase::Raw = this.write else {
            let state = match &mut this.write {
                WritePhase::Framed(state) => state,
                WritePhase::Raw => unreachable!("raw handled above"),
            };
            loop {
                if let Some((frame, off)) = &mut state.flushing {
                    while *off < frame.len() {
                        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &frame[*off..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "vmess: frame write stalled",
                            )));
                        }
                        *off += n;
                    }
                    state.flushing = None;
                    return Poll::Ready(Ok(state.consumed));
                }
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                let take = buf.len().min(WRITE_CHUNK);
                let frame = state.body.frame(&buf[..take])?;
                state.flushing = Some((frame, 0));
                state.consumed = take;
            }
        };
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Fill `buf` to `need` bytes; `Ok(false)` on clean EOF with an empty buffer.
fn poll_fill(
    inner: &mut AnyStream,
    cx: &mut Context<'_>,
    buf: &mut Vec<u8>,
    need: usize,
) -> Poll<io::Result<bool>> {
    while buf.len() < need {
        let start = buf.len();
        buf.resize(need, 0);
        let mut read_buf = ReadBuf::new(&mut buf[start..]);
        match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                buf.truncate(start + n);
                if n == 0 {
                    if start == 0 {
                        return Poll::Ready(Ok(false));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vmess: stream closed mid-header",
                    )));
                }
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {
                buf.truncate(start);
                return Poll::Pending;
            }
        }
    }
    Poll::Ready(Ok(true))
}
