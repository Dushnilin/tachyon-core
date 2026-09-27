//! UDP over TCP (sing `uot`) framing, shared by the naive and anytls outbounds.
//!
//! Version 2 opens the tunnel to a reserved magic address, writes
//! `[is_connect][addr type][addr][port]` and then exchanges bare datagrams;
//! version 1 (legacy) sends datagrams without a request header.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::inbound::{AnyStream, Target};

/// uot v2 magic destination (version 0/2).
pub(crate) const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
/// uot v1 (legacy) magic destination.
pub(crate) const UOT_LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";
/// uot v2, the version the reference defaults to.
pub(crate) const UOT_DEFAULT_VERSION: u8 = 2;

const DATAGRAM_BUF: usize = 65_535;

/// `uot.WriteRequest`: `[is_connect][addr type][addr][port]`.
pub(crate) fn request_header(is_connect: bool, target: &Target) -> io::Result<Vec<u8>> {
    let mut out = vec![u8::from(is_connect)];
    match target {
        Target::Domain(host, port) => {
            if host.len() > 255 {
                return Err(io::Error::other("uot: target domain too long"));
            }
            out.push(0x02);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) => {
                out.push(0x00);
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                out.push(0x01);
                out.extend_from_slice(&v6.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
    Ok(out)
}

/// Magic authority for a uot version (`uot.RequestDestination`).
pub(crate) fn magic_authority(version: u8) -> String {
    if version == 1 {
        format!("{UOT_LEGACY_MAGIC}:0")
    } else {
        format!("{UOT_MAGIC}:0")
    }
}

/// Bidirectional datagram bridge between a loopback socket pair and the
/// tunnel stream, so `connect_udp` can hand out a plain `UdpSocket`.
pub(crate) fn spawn_bridge(stream: AnyStream, peer: UdpSocket) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let peer_send = Arc::new(peer);
    let peer_recv = Arc::clone(&peer_send);
    tokio::spawn(async move {
        let mut buf = vec![0u8; DATAGRAM_BUF];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if peer_send.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; DATAGRAM_BUF];
        while let Ok(n) = peer_recv.recv(&mut buf).await {
            if writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_headers_match_the_reference() {
        let v4 =
            request_header(true, &Target::Ip("10.0.0.1:53".parse().expect("addr"))).expect("v4");
        assert_eq!(v4, vec![0x01, 0x00, 10, 0, 0, 1, 0, 53]);

        let mut expected = vec![0x00, 0x01];
        expected.extend_from_slice(&[0u8; 15]);
        expected.push(1);
        expected.extend_from_slice(&5353u16.to_be_bytes());
        assert_eq!(
            request_header(false, &Target::Ip("[::1]:5353".parse().expect("addr"))).expect("v6"),
            expected
        );

        let domain =
            request_header(true, &Target::Domain("dns.example.com".into(), 53)).expect("fqdn");
        assert_eq!(&domain[..3], &[0x01, 0x02, 15]);
        assert_eq!(&domain[3..18], b"dns.example.com");
        assert_eq!(&domain[18..], &53u16.to_be_bytes());
    }

    #[test]
    fn magic_authorities() {
        assert_eq!(magic_authority(1), "sp.udp-over-tcp.arpa:0");
        assert_eq!(magic_authority(2), "sp.v2.udp-over-tcp.arpa:0");
    }
}
