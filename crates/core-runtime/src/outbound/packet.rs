//! UDP over a vless/vmess stream.
//!
//! The reference offers three packet encodings and they differ only in how a
//! datagram is framed on the stream:
//!
//! - *length-prefixed* (`packet_encoding: ""`): `[len:u16][data]`. The request
//!   head carries the destination and the `UDP` command.
//! - *xudp* (the default): a meta block that names the destination once, then
//!   bare `Keep` frames. The request head uses the `Mux` command.
//! - *packetaddr*: the destination precedes every datagram, and the request
//!   head is addressed to the `sp.packet-addr.v2fly.arpa` magic name.
//!
//! Ported from sing-vmess `vless.PacketConn` / `vmess.NewXUDPConn` and Xray's
//! `common/xudp`.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::inbound::{AnyStream, Target};

pub(crate) const CMD_TCP: u8 = 1;
pub(crate) const CMD_UDP: u8 = 2;
pub(crate) const CMD_MUX: u8 = 3;

/// `packetaddr.SeqPacketMagicAddress`
pub(crate) const SEQ_PACKET_MAGIC: &str = "sp.packet-addr.v2fly.arpa";

const MAX_DATAGRAM: usize = 65_535;
/// the largest address: type + 16 bytes + port
const MAX_ADDR_PORT: usize = 19;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PacketEncoding {
    /// `[len:u16][data]`
    LengthPrefixed,
    Xudp,
    /// `[address][port][data]`
    PacketAddr,
}

impl PacketEncoding {
    /// The reference reads an absent `packet_encoding` as xudp, and an empty
    /// string as the plain length-prefixed form; anything else is rejected.
    pub(crate) fn parse(value: Option<&str>, at: &str) -> anyhow::Result<Self> {
        match value {
            None | Some("xudp") => Ok(PacketEncoding::Xudp),
            Some("") => Ok(PacketEncoding::LengthPrefixed),
            Some("packetaddr") => Ok(PacketEncoding::PacketAddr),
            Some(other) => anyhow::bail!("{at}: unknown packet encoding: {other}"),
        }
    }

    /// The command byte the request head carries for this mode.
    pub(crate) fn command(self) -> u8 {
        match self {
            PacketEncoding::LengthPrefixed => CMD_UDP,
            _ => CMD_MUX,
        }
    }

    /// packetaddr addresses the request to the magic name, the others name the
    /// real destination.
    pub(crate) fn request_target(self, target: &Target) -> Target {
        match self {
            PacketEncoding::PacketAddr => {
                Target::Domain(SEQ_PACKET_MAGIC.to_string(), target.port())
            }
            _ => target.clone(),
        }
    }
}

/// `AddressSerializer.WriteAddrPort`: address first, then the port.
pub(crate) fn put_addr_port(out: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    match target {
        Target::Domain(host, port) => {
            if host.len() > 255 {
                return Err(io::Error::other("packet encoding: domain too long"));
            }
            out.push(0x02);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                out.push(0x03);
                out.extend_from_slice(&v6.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
    Ok(())
}

/// The serialized address, for callers that only need the bytes.
pub(crate) fn put_addr_port_bytes(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_ADDR_PORT);
    put_addr_port(&mut out, target).expect("address fits");
    out
}

/// `AddressSerializer.ReadAddrPort`
pub(crate) fn take_addr_port(buf: &[u8]) -> io::Result<(Target, &[u8])> {
    let Some(&ty) = buf.first() else {
        return Err(io::Error::other("packet encoding: truncated address"));
    };
    let need = match ty {
        0x01 => 7,
        0x03 => 19,
        0x02 => match buf.get(1) {
            Some(&len) => 4 + len as usize,
            None => return Err(io::Error::other("packet encoding: truncated domain length")),
        },
        _ => return Err(io::Error::other("packet encoding: unknown address type")),
    };
    if buf.len() < need {
        return Err(io::Error::other("packet encoding: truncated address"));
    }
    let target = match ty {
        0x01 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Target::Ip(std::net::SocketAddr::from((octets, port)))
        }
        0x03 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Target::Ip(std::net::SocketAddr::from((octets, port)))
        }
        _ => {
            let len = buf[1] as usize;
            let host = String::from_utf8_lossy(&buf[2..2 + len]).into_owned();
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Target::Domain(host, port)
        }
    };
    Ok((target, &buf[need..]))
}

/// Frames outgoing datagrams; the xudp writer remembers that the destination
/// was already named.
pub(crate) struct PacketWriter {
    mode: PacketEncoding,
    named: bool,
}

impl PacketWriter {
    pub(crate) fn new(mode: PacketEncoding) -> Self {
        Self { mode, named: false }
    }

    pub(crate) fn frame(&mut self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::other("datagram too large"));
        }
        let mut out = Vec::with_capacity(payload.len() + MAX_ADDR_PORT + 16);
        match self.mode {
            PacketEncoding::LengthPrefixed => {
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            PacketEncoding::PacketAddr => {
                // the address rides inside the length-prefixed frame, so the
                // stream framing stays unambiguous
                let mut body = Vec::with_capacity(MAX_ADDR_PORT + payload.len());
                put_addr_port(&mut body, target)?;
                body.extend_from_slice(payload);
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(&body);
            }
            PacketEncoding::Xudp => {
                let mut meta = Vec::with_capacity(MAX_ADDR_PORT + 8);
                meta.extend_from_slice(&[0, 0]); // mux session id
                if self.named {
                    meta.extend_from_slice(&[2, 1]); // Keep, opt
                } else {
                    meta.extend_from_slice(&[1, 1, 2]); // New, opt, udp
                    put_addr_port(&mut meta, target)?;
                    self.named = true;
                }
                out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
                out.extend_from_slice(&meta);
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
        }
        Ok(out)
    }
}

/// Parses incoming datagrams. A server may name a new destination mid-session;
/// the relay is bound to one, so the name is read and dropped.
pub(crate) struct PacketReader {
    mode: PacketEncoding,
}

impl PacketReader {
    pub(crate) fn new(mode: PacketEncoding) -> Self {
        Self { mode }
    }

    pub(crate) async fn read(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> io::Result<Vec<u8>> {
        loop {
            match self.mode {
                PacketEncoding::LengthPrefixed => {
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await?;
                    let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
                    stream.read_exact(&mut payload).await?;
                    return Ok(payload);
                }
                PacketEncoding::PacketAddr => {
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await?;
                    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                    stream.read_exact(&mut body).await?;
                    let (_target, rest) = take_addr_port(&body)?;
                    return Ok(rest.to_vec());
                }
                PacketEncoding::Xudp => {
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await?;
                    let meta_len = u16::from_be_bytes(len) as usize;
                    if meta_len < 4 {
                        return Err(io::Error::other("xudp: meta too short"));
                    }
                    let mut meta = vec![0u8; meta_len];
                    stream.read_exact(&mut meta).await?;
                    let keep = meta[2] == 2;
                    let mut payload = Vec::new();
                    read_xudp_data(stream, &mut payload).await?;
                    // a fin (4) or an option-only frame carries no datagram
                    if keep && !payload.is_empty() {
                        return Ok(payload);
                    }
                }
            }
        }
    }
}

/// The meta flags the payload behind a `len:u16` prefix.
async fn read_xudp_data(
    stream: &mut (impl AsyncRead + Unpin),
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len > 0 {
        out.resize(len, 0);
        stream.read_exact(out).await?;
    }
    Ok(())
}

pub(crate) fn spawn_packet_bridge(
    stream: AnyStream,
    peer: UdpSocket,
    mode: PacketEncoding,
    target: Target,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let out_socket = Arc::new(peer);
    let in_socket = Arc::clone(&out_socket);
    let mut out = PacketWriter::new(mode);
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let Ok(n) = in_socket.recv(&mut buf).await else {
                break;
            };
            let Ok(framed) = out.frame(&target, &buf[..n]) else {
                break;
            };
            if writer.write_all(&framed).await.is_err() {
                break;
            }
        }
    });
    let mut input = PacketReader::new(mode);
    tokio::spawn(async move {
        loop {
            let Ok(packet) = input.read(&mut reader).await else {
                break;
            };
            if out_socket.send(&packet).await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn feed(framed: Vec<u8>, mode: PacketEncoding) -> Vec<Vec<u8>> {
        let (client, server) = tokio::io::duplex(8192);
        let writer = tokio::spawn(async move {
            let mut sink = client;
            sink.write_all(&framed).await.expect("write");
            sink.shutdown().await.expect("shutdown");
        });
        let mut server = server;
        let mut input = PacketReader::new(mode);
        let mut packets = Vec::new();
        while let Ok(packet) = input.read(&mut server).await {
            packets.push(packet);
        }
        writer.await.expect("join");
        packets
    }

    #[tokio::test]
    async fn length_prefixed_roundtrip() {
        let target = Target::Domain("example.com".into(), 53);
        let mut out = PacketWriter::new(PacketEncoding::LengthPrefixed);
        let framed = [
            out.frame(&target, b"payload").expect("frame"),
            out.frame(&target, b"second").expect("frame"),
        ]
        .concat();
        assert_eq!(
            feed(framed, PacketEncoding::LengthPrefixed).await,
            [b"payload".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn xudp_names_the_destination_once() {
        let target = Target::Domain("example.com".into(), 53);
        let mut out = PacketWriter::new(PacketEncoding::Xudp);
        let first = out.frame(&target, b"a").expect("frame");
        let second = out.frame(&target, b"b").expect("frame");
        // [meta len][session][New][opt][udp][addr][port][data len][data]
        assert_eq!(
            u16::from_be_bytes([first[0], first[1]]) as usize,
            2 + 3 + 15
        );
        assert_eq!(&first[2..4], &[0, 0], "mux session id");
        assert_eq!(&first[4..7], &[1, 1, 2], "new, opt, udp");
        assert_eq!(&first[7..9], &[0x02, 11], "domain with its length");
        assert_eq!(&first[9..20], b"example.com");
        assert_eq!(&first[20..22], &53u16.to_be_bytes());
        assert_eq!(&first[22..24], &1u16.to_be_bytes());
        assert_eq!(&first[24..], b"a");

        // the follow-up frame keeps the session and names nothing
        assert_eq!(&second[2..6], &[0, 0, 2, 1], "keep, opt");
        assert_eq!(&second[6..8], &1u16.to_be_bytes());
        assert_eq!(&second[8..], b"b");
    }

    /// A server only ever sends `Keep` frames; the first `New` frame is ours.
    fn inbound_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = 4u16.to_be_bytes().to_vec();
        out.extend_from_slice(&[0, 0, 2, 1]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn xudp_roundtrip() {
        let framed = [inbound_frame(b"first"), inbound_frame(b"second")].concat();
        assert_eq!(
            feed(framed, PacketEncoding::Xudp).await,
            [b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[tokio::test]
    async fn packetaddr_prefixes_every_datagram() {
        let target = Target::Ip("10.0.0.1:5353".parse().expect("addr"));
        let mut out = PacketWriter::new(PacketEncoding::PacketAddr);
        let framed = [
            out.frame(&target, b"a").expect("frame"),
            out.frame(&target, b"b").expect("frame"),
        ]
        .concat();
        assert_eq!(
            feed(framed, PacketEncoding::PacketAddr).await,
            [b"a".to_vec(), b"b".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_server_may_rename_the_destination_mid_session() {
        // Keep meta with the udp flag set: the address is read and dropped
        let meta = [0u8, 0, 2, 1, 2, 0x01, 9, 9, 9, 9, 0, 53];
        let mut framed = (meta.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&meta);
        framed.extend_from_slice(&3u16.to_be_bytes());
        framed.extend_from_slice(b"xyz");
        assert_eq!(feed(framed, PacketEncoding::Xudp).await, [b"xyz".to_vec()]);
    }

    #[tokio::test]
    async fn an_option_only_xudp_frame_is_skipped() {
        let mut empty = 4u16.to_be_bytes().to_vec();
        empty.extend_from_slice(&[0, 0, 2, 1]);
        empty.extend_from_slice(&0u16.to_be_bytes());
        let framed = [empty, inbound_frame(b"xyz")].concat();
        assert_eq!(feed(framed, PacketEncoding::Xudp).await, [b"xyz".to_vec()]);
    }

    #[test]
    fn addresses_roundtrip() {
        for target in [
            Target::Ip("1.2.3.4:53".parse().expect("v4")),
            Target::Ip("[2001:db8::1]:53".parse().expect("v6")),
            Target::Domain("a.example".into(), 853),
        ] {
            let mut bytes = Vec::new();
            put_addr_port(&mut bytes, &target).expect("write");
            let (parsed, rest) = take_addr_port(&bytes).expect("read");
            assert!(rest.is_empty());
            assert_eq!(parsed.to_string(), target.to_string());
        }
    }

    #[test]
    fn encodings_pick_their_command() {
        assert_eq!(
            PacketEncoding::parse(None, "at").expect("default"),
            PacketEncoding::Xudp
        );
        assert_eq!(
            PacketEncoding::parse(Some(""), "at").expect("empty"),
            PacketEncoding::LengthPrefixed
        );
        assert!(
            PacketEncoding::parse(Some("none"), "at").is_err(),
            "the reference has no \"none\" spelling"
        );
        assert_eq!(PacketEncoding::LengthPrefixed.command(), CMD_UDP);
        assert_eq!(PacketEncoding::Xudp.command(), CMD_MUX);
        assert_eq!(PacketEncoding::PacketAddr.command(), CMD_MUX);
        let target = Target::Ip("1.2.3.4:53".parse().expect("addr"));
        assert_eq!(
            PacketEncoding::PacketAddr
                .request_target(&target)
                .to_string(),
            "sp.packet-addr.v2fly.arpa:53"
        );
        assert!(PacketEncoding::parse(Some("bogus"), "at").is_err());
    }
}
