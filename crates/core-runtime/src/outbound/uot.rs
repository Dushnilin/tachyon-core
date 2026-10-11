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

/// One UDP payload at its largest: an IPv4 datagram carries 65_535 bytes and a
/// uot header byte comes out of that, so this is the most a read can return.
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
    spawn_bridge_with_timeout(stream, peer, crate::outbound::packet::udp_bridge_timeout());
}

fn spawn_bridge_with_timeout(stream: AnyStream, peer: UdpSocket, timeout: std::time::Duration) {
    let (activity, idle) = tokio::sync::watch::channel(tokio::time::Instant::now());
    let sent = activity.clone();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let peer_send = Arc::new(peer);
    let peer_recv = Arc::clone(&peer_send);
    let downstream = async move {
        let mut buf = vec![0u8; DATAGRAM_BUF];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    activity.send_replace(tokio::time::Instant::now());
                    if peer_send.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };
    let upstream = async move {
        let mut buf = vec![0u8; DATAGRAM_BUF];
        while let Ok(n) = peer_recv.recv(&mut buf).await {
            sent.send_replace(tokio::time::Instant::now());
            if writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    };
    tokio::spawn(async move {
        tokio::select! {
            _ = downstream => {},
            _ = upstream => {},
            _ = crate::outbound::packet::wait_bridge_idle(idle, timeout) => {}
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

    #[tokio::test]
    async fn bridge_uses_scoped_route_idle_timeout() {
        let (client, peer) = crate::outbound::quic::udp_loopback_pair().await.unwrap();
        let address = peer.local_addr().unwrap();
        let (stream, _remote) = tokio::io::duplex(1024);
        crate::outbound::packet::UDP_BRIDGE_TIMEOUT
            .scope(std::time::Duration::from_millis(50), async {
                spawn_bridge(Box::new(stream), peer);
            })
            .await;
        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            UdpSocket::bind(address).await.is_ok(),
            "route timeout ignored"
        );
    }

    #[tokio::test]
    async fn bridge_releases_abandoned_udp_socket_with_open_tunnel() {
        for _ in 0..16 {
            let (client, peer) = crate::outbound::quic::udp_loopback_pair().await.unwrap();
            let address = peer.local_addr().unwrap();
            let (stream, _remote) = tokio::io::duplex(1024);
            spawn_bridge_with_timeout(Box::new(stream), peer, std::time::Duration::from_millis(50));
            drop(client);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(
                UdpSocket::bind(address).await.is_ok(),
                "idle UOT socket retained"
            );
        }
    }

    #[tokio::test]
    async fn receive_only_bridge_survives_multiple_idle_windows() {
        let (client, peer) = crate::outbound::quic::udp_loopback_pair().await.unwrap();
        let (stream, mut remote) = tokio::io::duplex(1024);
        spawn_bridge_with_timeout(
            Box::new(stream),
            peer,
            std::time::Duration::from_millis(150),
        );
        let mut buf = [0u8; 1];
        for _ in 0..12 {
            remote.write_all(b"x").await.unwrap();
            let n =
                tokio::time::timeout(std::time::Duration::from_millis(100), client.recv(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buf[..n], b"x");
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
    }

    #[tokio::test]
    async fn bridge_releases_udp_socket_after_remote_eof() {
        for _ in 0..32 {
            let (client, peer) = crate::outbound::quic::udp_loopback_pair().await.unwrap();
            let address = peer.local_addr().unwrap();
            let (stream, remote) = tokio::io::duplex(1024);
            spawn_bridge(Box::new(stream), peer);
            drop(remote);
            drop(client);
            let released = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    if UdpSocket::bind(address).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                released.is_ok(),
                "bridge retained UDP socket after remote EOF"
            );
        }
    }
}
