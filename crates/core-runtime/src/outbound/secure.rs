use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::inbound::{AnyStream, Target};
use crate::outbound::mux;
use crate::outbound::packet::{CMD_TCP, PacketEncoding, spawn_packet_bridge};
use crate::outbound::proxy::server_endpoint;
use crate::outbound::transport::Transport;
use crate::tls_client::TlsOptions;

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

/// vless wants a canonical UUID and nothing else, which is not what vmess and
/// tuic want: those fall back to a UUIDv5 of the raw string
/// (`vmess::kdf::parse_uuid`). Two functions on purpose -- sharing one would
/// either hand vless a UUID nobody configured, or refuse vmess names.
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

/// The only flow the reference accepts (`vless.NewClient`).
const FLOW: &str = "xtls-rprx-vision";

/// vless outbound (TCP command, with the `xtls-rprx-vision` flow).
#[derive(Clone)]
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
    /// Mux.Cool session pool; `None` when multiplexing is off
    mux: Option<Arc<mux::Client>>,
    dial: crate::outbound::dial::DialOptions,
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
        let multiplex = match obj.get("multiplex") {
            Some(value) if !value.is_null() => {
                mux::MuxOptions::parse(value, &format!("{at}.multiplex"))?
            }
            _ => mux::MuxOptions::default(),
        };
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
            mux: if multiplex.min_streams > 0
                || multiplex.max_connections > 0
                || multiplex.max_streams > 0
            {
                Some(mux::Client::new(multiplex)?)
            } else {
                None
            },
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if let Some(mux) = &self.mux {
            if !mux.has_dialer().await {
                // a session is opened against the magic destination through the
                // same request machinery a normal connection uses
                let copy = self.clone();
                mux.set_dialer(Arc::new(move || {
                    let copy = copy.clone();
                    let target = mux::mux_target();
                    Box::pin(async move { copy.connect_direct(&target).await })
                }))
                .await;
            }
            let stream = mux.open(target).await?;
            return Ok(Box::new(stream));
        }
        self.connect_direct(target).await
    }

    async fn connect_direct(&self, target: &Target) -> io::Result<AnyStream> {
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
        let header = request_head(&self.uuid, command, target, self.vision)?;
        // a ws transport with early data carries the request in the upgrade head
        let (mut stream, consumed) = self
            .transport
            .connect_or_dial(
                self.tls.as_ref(),
                &self.server,
                self.port,
                &header,
                &self.dial,
            )
            .await?;
        // The request head goes out on its own, ahead of any payload.
        //
        // This used to be glued to the caller's first write, because a transport
        // that turns writes into packets -- XHTTP packet-up, one sequenced POST per
        // write -- would otherwise deliver the head as a packet with nothing in it.
        // That reasoning was wrong, and the cost was a corrupted tunnel on Xray
        // 26.9: a POST carrying the head *and* the first payload is read back twice,
        // so the far end receives the payload two times. Xray 25.9 tolerates it,
        // which is exactly why it looked healthy for as long as it did.
        //
        // Measured against a real Xray with the stand in tests/spikes/xhttp, one
        // 13-byte payload and a 26-byte head:
        //
        // | client | Xray 25.9 | Xray 26.9 |
        // |---|---|---|
        // | sing-box-lx 1.14.2-lx.11 | `firstLen = 26`, passes | `firstLen = 26`, passes |
        // | glued head + payload | `firstLen = 39`, passes | `firstLen = 156`, fails |
        //
        // The reference splits them and reads `firstLen` back equal to the head on
        // both versions, so splitting is the shape both accept. Over a plain TCP or
        // TLS stream the bytes on the wire are identical either way -- only the POST
        // framing changes -- and the server parses the head out of the byte stream
        // rather than deciding where the request ends from the first packet.
        if !header[consumed..].is_empty() {
            stream.write_all(&header[consumed..]).await?;
            stream.flush().await?;
        }
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

/// `[version][uuid][addonsLen][addons][command][addr][port]`, reference
/// `WriteRequest`. The flow travels in the addons as protobuf field 1, and a
/// server with `flow` on the user refuses a request without it.
fn request_head(
    uuid: &[u8; 16],
    command: u8,
    target: &Target,
    vision: bool,
) -> io::Result<Vec<u8>> {
    let mut addons = Vec::new();
    if vision {
        addons.push(0x0a); // field 1, wire type 2
        addons.push(FLOW.len() as u8); // 17 bytes, so a one-byte uvarint
        addons.extend_from_slice(FLOW.as_bytes());
    }
    let mut header = Vec::with_capacity(24 + addons.len());
    header.push(0x00);
    header.extend_from_slice(uuid);
    header.push(addons.len() as u8);
    header.extend_from_slice(&addons);
    header.push(command);
    header.extend_from_slice(&encode_vless_target(target)?);
    Ok(header)
}

/// vless response ([version][addonsLen][addons]) is sent lazily by servers on
/// the first upstream write, so it is consumed transparently on first read.
pub struct VlessStream {
    inner: AnyStream,
    header_pending: bool,
    need: usize,
    buf: Vec<u8>,
}

impl VlessStream {
    /// The bare socket underneath, while the response head has not been touched:
    /// the relay can then eat the head itself and hand the rest to the kernel.
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_pending(&self) -> Option<&tokio::net::TcpStream> {
        if !self.header_pending || !self.buf.is_empty() {
            return None;
        }
        (&*self.inner as &dyn std::any::Any).downcast_ref::<tokio::net::TcpStream>()
    }
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
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // The request head has already gone out, on its own write, so there is
        // nothing left to queue here and a plain passthrough is right: buffering
        // the caller's first write to pair it with the head is what this type used
        // to do, and it is what doubled the packet on Xray 26.9.
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
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
    dial: crate::outbound::dial::DialOptions,
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
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
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
        // trojan uses `M.SocksaddrSerializer`, so the family bytes are the
        // SOCKS ones: 1 = IPv4, 4 = IPv6, 3 = domain
        header.extend_from_slice(&crate::outbound::proxy::encode_target_with(target, 0x03)?);
        header.extend_from_slice(b"\r\n");
        let (mut stream, consumed) = self
            .transport
            .connect_or_dial(Some(tls), &self.server, self.port, &header, &self.dial)
            .await?;
        stream.write_all(&header[consumed..]).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests;
