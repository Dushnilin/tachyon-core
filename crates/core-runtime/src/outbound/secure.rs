use std::io;

use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::inbound::{AnyStream, Target};
use crate::outbound::packet::{CMD_TCP, PacketEncoding, spawn_packet_bridge};
use crate::outbound::proxy::server_endpoint;
use crate::outbound::transport::Transport;
use crate::tls_client::TlsOptions;

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
            out.push(0x02);
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

/// vless address block: port first, then ATYP (1=v4, 2=domain, 3=v6) + addr.
fn encode_vless_target(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x03);
                out.extend_from_slice(&v6.octets());
            }
        },
        Target::Domain(host, _) => {
            out.push(0x02);
            let raw = host.as_bytes();
            if raw.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
        }
    }
    Ok(out)
}

fn parse_uuid(raw: &str) -> io::Result<[u8; 16]> {
    let hex: String = raw.chars().filter(|c| *c != '-').collect();
    if hex.len() != 16 * 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(io::Error::other("invalid uuid"));
    }
    let mut uuid = [0u8; 16];
    for (i, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| io::Error::other("invalid uuid"))?;
    }
    Ok(uuid)
}

/// vless outbound (TCP command, with the `xtls-rprx-vision` flow).
pub struct Vless {
    server: String,
    port: u16,
    uuid: [u8; 16],
    transport: Transport,
    tls: Option<TlsOptions>,
    /// `flow: xtls-rprx-vision` — the payload is framed, see `vision`.
    vision: bool,
    /// how datagrams are framed on the stream, see `packet`
    packet_encoding: PacketEncoding,
}

impl Vless {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let uuid_raw = obj
            .get("uuid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing uuid"))?;
        let uuid = parse_uuid(uuid_raw).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        let flow = obj.get("flow").and_then(Value::as_str).unwrap_or("");
        let vision = match flow {
            "" => false,
            "xtls-rprx-vision" => true,
            other => anyhow::bail!("{at}: vless flow {other:?} is not supported"),
        };
        let transport = Transport::parse(obj, at)?;
        let tls = TlsOptions::from_outbound(obj, &server, at)?;
        let packet_encoding =
            PacketEncoding::parse(obj.get("packet_encoding").and_then(Value::as_str), at)?;
        Ok(Self {
            server,
            port,
            uuid,
            transport,
            tls,
            vision,
            packet_encoding,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        self.dial(CMD_TCP, target).await
    }

    /// A datagram relay: the request head names the destination (or the
    /// packetaddr magic name) and the framing takes over from there.
    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let mode = self.packet_encoding;
        let stream = self
            .dial(mode.command(), &mode.request_target(target))
            .await?;
        spawn_packet_bridge(stream, peer, mode, target.clone());
        Ok(local)
    }

    async fn dial(&self, command: u8, target: &Target) -> io::Result<AnyStream> {
        let mut header = Vec::with_capacity(24 + 8);
        header.push(0x00);
        header.extend_from_slice(&self.uuid);
        header.push(0x00);
        header.push(command);
        header.extend_from_slice(&encode_vless_target(target)?);
        let tcp = crate::dns::connect_tcp(self.server.as_str(), self.port).await?;
        // a ws transport with early data carries the request in the upgrade head
        let (mut stream, consumed) = self
            .transport
            .connect(tcp, self.tls.as_ref(), &self.server, self.port, &header)
            .await?;
        stream.write_all(&header[consumed..]).await?;
        let framed: AnyStream = Box::new(VlessStream {
            inner: stream,
            header_pending: true,
            need: 2,
            buf: Vec::new(),
        });
        if self.vision {
            // Vision frames the payload that follows the request header
            Ok(Box::new(crate::outbound::vision::VisionStream::new(
                framed, self.uuid,
            )))
        } else {
            Ok(framed)
        }
    }
}

/// vless response ([version][addonsLen][addons]) is sent lazily by servers on
/// the first upstream write, so it is consumed transparently on first read.
pub struct VlessStream {
    inner: AnyStream,
    header_pending: bool,
    need: usize,
    buf: Vec<u8>,
}

impl tokio::io::AsyncRead for VlessStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        if this.header_pending {
            let mut probe = [0u8; 1];
            while this.buf.len() < this.need {
                let mut read_buf = tokio::io::ReadBuf::new(&mut probe);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    std::task::Poll::Ready(Ok(())) => {
                        if read_buf.filled().is_empty() {
                            return std::task::Poll::Ready(Err(io::Error::other(
                                "vless: connection closed before response",
                            )));
                        }
                        this.buf.push(probe[0]);
                        if this.buf.len() == 2 {
                            if this.buf[0] != 0x00 {
                                return std::task::Poll::Ready(Err(io::Error::other(
                                    "bad vless response version",
                                )));
                            }
                            this.need += usize::from(this.buf[1]);
                        }
                    }
                    std::task::Poll::Ready(Err(err)) => return std::task::Poll::Ready(Err(err)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            this.header_pending = false;
            this.buf.clear();
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl tokio::io::AsyncWrite for VlessStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
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

/// trojan outbound: TLS is mandatory; password is SHA224-hex authenticated.
pub struct Trojan {
    server: String,
    port: u16,
    password_hash: String,
    transport: Transport,
    tls: Option<TlsOptions>,
}

impl Trojan {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?;
        use sha2::Digest;
        let digest = sha2::Sha224::digest(password.as_bytes());
        let password_hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let transport = Transport::parse(obj, at)?;
        let tls = TlsOptions::from_outbound(obj, &server, at)?;
        Ok(Self {
            server,
            port,
            password_hash,
            transport,
            tls,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        self.dial(0x01, target).await
    }

    /// trojan has one datagram form: the request head names the target and
    /// every packet is length-prefixed on the same stream.
    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let stream = self.dial(0x03, target).await?;
        spawn_packet_bridge(stream, peer, PacketEncoding::LengthPrefixed, target.clone());
        Ok(local)
    }

    async fn dial(&self, command: u8, target: &Target) -> io::Result<AnyStream> {
        let Some(tls) = &self.tls else {
            return Err(io::Error::other("trojan requires TLS"));
        };
        let mut header = Vec::with_capacity(64);
        header.extend_from_slice(self.password_hash.as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(command);
        header.extend_from_slice(&encode_target(target)?);
        header.extend_from_slice(b"\r\n");
        let tcp = crate::dns::connect_tcp(self.server.as_str(), self.port).await?;
        let (mut stream, consumed) = self
            .transport
            .connect(tcp, Some(tls), &self.server, self.port, &header)
            .await?;
        stream.write_all(&header[consumed..]).await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests;
