//! HTTP/2 CONNECT-IP shim (reference `transport/masque/client_h2.go`).
//!
//! WARP's h2 CONNECT-IP is a *plain* CONNECT (only `:method` +
//! `:authority`, the tunnel keyed off the `cf-connect-proto` header) — an
//! extended CONNECT with `:protocol` triggers PROTOCOL_ERROR there. HTTP/2
//! has no native datagrams, so proxied packets travel as capsule DATAGRAM
//! frames (type 0) inside the CONNECT stream's DATA frames; unlike the h3
//! path there is no context-ID and no route/address capsule exchange, so
//! incoming validation is structural only. TTL/checksum handling mirrors
//! the h3 path minus IHL options (reference `composeH2Datagram`).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::h3::take_capsule;
use super::profile::Profile;
use super::tls::MasqueTls;
use crate::outbound::quic::put_varint;

/// Capsule type 0 carries an HTTP datagram (RFC 9297 §2.4).
const CAPSULE_DATAGRAM: u64 = 0;
/// One IP packet becomes one DATA frame, which must fit the default
/// SETTINGS_MAX_FRAME_SIZE (16384) minus the capsule header.
const MAX_H2_PACKET: usize = 16_000;
/// Receive window announced in SETTINGS_INITIAL_WINDOW_SIZE.
const H2_INITIAL_WINDOW: u32 = 8 << 20;

pub(crate) struct H2Conn {
    send: h2::SendStream<Bytes>,
    rx: mpsc::Receiver<Vec<u8>>,
    conn_task: tokio::task::JoinHandle<()>,
}

impl H2Conn {
    /// Dial TCP + TLS (ALPN h2), run the manual HTTP/2 handshake and the
    /// plain CONNECT request (reference `ConnectTunnelH2`).
    pub(crate) async fn connect(
        tls: &MasqueTls,
        profile: &Profile,
        uri: &str,
        server: SocketAddr,
    ) -> io::Result<H2Conn> {
        let request = parse_connect_uri(uri)?;

        let tcp = TcpStream::connect(server)
            .await
            .map_err(|e| io::Error::other(format!("masque h2: dial tcp: {e}")))?;
        tcp.set_nodelay(true).ok();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            tls.tcp_config()
                .map_err(|e| io::Error::other(format!("masque h2: tls config: {e}")))?,
        ));
        let name = tls.server_name_hint()?;
        let stream = connector
            .connect(name, tcp)
            .await
            .map_err(|e| io::Error::other(format!("masque h2: tls handshake: {e}")))?;

        let mut connection = h2::client::Builder::new();
        connection.initial_window_size(H2_INITIAL_WINDOW);
        connection.initial_connection_window_size(H2_INITIAL_WINDOW);
        let (send_request, conn) = connection
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("masque h2: h2 handshake: {e}")))?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut send_request = send_request
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("masque h2: h2 ready: {e}")))?;

        // Plain CONNECT: authority-form URI, no :scheme/:path/:protocol.
        let authority: http::uri::Authority = request
            .authority
            .parse()
            .map_err(|e| io::Error::other(format!("masque h2: authority: {e}")))?;
        let mut builder = http::Request::builder()
            .method("CONNECT")
            .uri(http::Uri::from(authority))
            .header("capsule-protocol", "?1")
            // The official WARP client sends an empty User-Agent.
            .header("user-agent", "");
        if !profile.h2_connect_proto.is_empty() {
            builder = builder
                .header("cf-connect-proto", profile.h2_connect_proto)
                .header("pq-enabled", "false");
        }
        let request = builder
            .body(())
            .map_err(|e| io::Error::other(format!("masque h2: build request: {e}")))?;
        let (response, send) = send_request
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("masque h2: write CONNECT headers: {e}")))?;

        let response = response
            .await
            .map_err(|e| io::Error::other(format!("masque h2: read response: {e}")))?;
        let status = response.status().as_u16();
        if !(200..=299).contains(&status) {
            return Err(io::Error::other(format!(
                "connect-ip: server responded with {status}"
            )));
        }
        let recv = response.into_body();

        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        tokio::spawn(recv_loop(recv, tx));

        Ok(H2Conn {
            send,
            rx,
            conn_task,
        })
    }

    /// Next structurally valid inbound IP packet. Validation here is only
    /// shape-level (reference `validateProxiedPacket`): the h2 shim performs
    /// no address/route policy — unlike h3 it never learns assignments.
    pub(crate) async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        self.rx.recv().await.ok_or_else(|| {
            self.close();
            io::Error::other("masque h2: tunnel closed")
        })
    }

    /// Send one outbound IP packet as a capsule DATAGRAM inside a single
    /// DATA frame. Compose failures drop the packet silently; unlike h3
    /// there is no datagram-too-large path (the configured MTU is capped at
    /// 16000 at build time).
    pub(crate) async fn write_packet(&mut self, pkt: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
        if pkt.is_empty() {
            return Ok(None);
        }
        let data = match compose_h2_datagram(pkt) {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };
        let mut frame = Vec::with_capacity(data.len() + 8);
        put_varint(&mut frame, CAPSULE_DATAGRAM);
        put_varint(&mut frame, data.len() as u64);
        frame.extend_from_slice(data);
        write_data(&mut self.send, Bytes::from(frame)).await?;
        Ok(None)
    }

    pub(crate) fn close(&mut self) {
        self.send.send_reset(h2::Reason::CANCEL);
        self.conn_task.abort();
    }
}

impl Drop for H2Conn {
    fn drop(&mut self) {
        self.close();
    }
}

/// Reassemble capsule frames across DATA chunks and hand complete datagram
/// capsules (type 0) to the pump; other capsule types are skipped
/// (reference `receiveDatagram`).
async fn recv_loop(mut recv: h2::RecvStream, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = Vec::new();
    loop {
        let chunk = std::future::poll_fn(|cx| recv.poll_data(cx)).await;
        match chunk {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                let _ = recv.flow_control().release_capacity(len);
                buf.extend_from_slice(&chunk);
                loop {
                    match take_capsule(&mut buf) {
                        Ok(Some((capsule_type, payload))) => {
                            if capsule_type != CAPSULE_DATAGRAM {
                                continue;
                            }
                            if validate_packet(&payload).is_err() {
                                continue;
                            }
                            if tx.send(payload).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            crate::logging::debug(format_args!("masque h2: capsule: {e}"));
                            return;
                        }
                    }
                }
            }
            Some(Err(e)) => {
                crate::logging::debug(format_args!("masque h2: recv: {e}"));
                return;
            }
            None => return, // stream ended: ReadPacket sees the closed channel
        }
    }
}

/// Send one frame's worth of data, respecting stream flow control.
async fn write_data(send: &mut h2::SendStream<Bytes>, frame: Bytes) -> io::Result<()> {
    let mut pos = 0;
    while pos < frame.len() {
        let remaining = frame.len() - pos;
        send.reserve_capacity(remaining);
        let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(cap)) => cap,
            Some(Err(e)) => {
                return Err(io::Error::other(format!("masque h2: capacity: {e}")));
            }
            None => {
                return Err(io::Error::other("masque h2: stream closed for writing"));
            }
        };
        if cap == 0 {
            continue;
        }
        let n = cap.min(remaining);
        let chunk = Bytes::copy_from_slice(&frame[pos..pos + n]);
        send.send_data(chunk, false)
            .map_err(|e| io::Error::other(format!("masque h2: send_data: {e}")))?;
        pos += n;
    }
    Ok(())
}

/// Structural check for a proxied packet (reference `validateProxiedPacket`).
fn validate_packet(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Err(io::Error::other("connect-ip: empty packet"));
    }
    match data[0] >> 4 {
        4 => {
            if data.len() < 20 {
                return Err(io::Error::other(
                    "connect-ip: malformed datagram: too short",
                ));
            }
        }
        6 => {
            if data.len() < 40 {
                return Err(io::Error::other(
                    "connect-ip: malformed datagram: too short",
                ));
            }
        }
        v => {
            return Err(io::Error::other(format!(
                "connect-ip: unknown IP version: {v}"
            )));
        }
    }
    Ok(())
}

/// TTL/hop-limit decrement for the h2 leg: fixed 20-byte IPv4 header like
/// the reference (options are not checksummed here), no context-ID
/// (reference `composeH2Datagram`). Returns the packet itself on success.
fn compose_h2_datagram(b: &mut [u8]) -> io::Result<&mut [u8]> {
    match b.first().map(|v| v >> 4) {
        None => return Err(io::Error::other("connect-ip: empty packet")),
        Some(4) => {
            if b.len() < 20 {
                return Err(io::Error::other("connect-ip: IPv4 packet too short"));
            }
            let ttl = b[8];
            if ttl <= 1 {
                return Err(io::Error::other("connect-ip: datagram TTL too small"));
            }
            b[8] = ttl - 1;
            let sum = ipv4_header_checksum(&b[..20]);
            b[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        Some(6) => {
            if b.len() < 40 {
                return Err(io::Error::other("connect-ip: IPv6 packet too short"));
            }
            let hop = b[7];
            if hop <= 1 {
                return Err(io::Error::other("connect-ip: datagram Hop Limit too small"));
            }
            b[7] = hop - 1;
        }
        Some(v) => {
            return Err(io::Error::other(format!(
                "connect-ip: unknown IP version: {v}"
            )));
        }
    }
    Ok(b)
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i == 10 {
            continue; // checksum field itself
        }
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parsed pieces of the CONNECT-IP request URI (shared shape with h3).
struct ConnectUri {
    authority: String,
}

fn parse_connect_uri(uri: &str) -> io::Result<ConnectUri> {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return Err(io::Error::other(format!(
            "connect-ip: parse connect uri: {uri}"
        )));
    };
    if scheme.is_empty() {
        return Err(io::Error::other(format!(
            "connect-ip: parse connect uri: {uri}"
        )));
    }
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(io::Error::other(format!(
            "connect-ip: parse connect uri: {uri}"
        )));
    }
    Ok(ConnectUri {
        authority: h2_authority(authority),
    })
}

/// Go `authorityFromURL`: keep an explicit port, otherwise force `:443`.
fn h2_authority(authority: &str) -> String {
    if let Some((head, port)) = authority.rsplit_once(':')
        && !head.is_empty()
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return authority.to_string();
    }
    format!("{authority}:443")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_port_rules() {
        assert_eq!(
            h2_authority("cloudflareaccess.com"),
            "cloudflareaccess.com:443"
        );
        assert_eq!(h2_authority("example.com:8443"), "example.com:8443");
        assert_eq!(h2_authority("[::1]"), "[::1]:443");
        assert_eq!(h2_authority("[::1]:8443"), "[::1]:8443");
    }

    #[test]
    fn uri_parse_for_h2() {
        let u = parse_connect_uri("https://cloudflareaccess.com").unwrap();
        assert_eq!(u.authority, "cloudflareaccess.com:443");
        let u = parse_connect_uri("https://example.com:8443/path").unwrap();
        assert_eq!(u.authority, "example.com:8443");
        assert!(parse_connect_uri("no-scheme").is_err());
    }

    #[test]
    fn compose_h2_decrements_ttl_and_checksums() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let data = compose_h2_datagram(&mut pkt).unwrap();
        assert_eq!(data[8], 63);
        let sum = ipv4_header_checksum(&data[..20]);
        let mut acc: u32 = 0;
        for i in (0..20).step_by(2) {
            acc += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        }
        while acc >> 16 > 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        assert_eq!(acc, 0xffff);
        assert_eq!(sum, sum); // checksum computed without panics
    }

    #[test]
    fn compose_h2_rejects_ttl_one() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[8] = 1;
        assert!(compose_h2_datagram(&mut pkt).is_err());
    }

    #[test]
    fn structural_validation() {
        assert!(validate_packet(&[]).is_err());
        assert!(validate_packet(&[0x40; 19]).is_err());
        assert!(validate_packet(&[0x40; 20]).is_ok());
        assert!(validate_packet(&[0x60; 40]).is_ok());
        assert!(validate_packet(&[0x40; 40]).is_ok()); // v4 len>=20 ok
        assert!(validate_packet(&[0x70; 40]).is_err());
    }
}
