//! Inbound MUX session termination for `sing-mux` (h2mux over VLESS / VMess / Trojan).
//!
//! Clients that negotiate multiplexing open a tunnel to the magic destination
//! `sp.mux.sing-box.arpa:444` (or send command byte `COMMAND_MUX`), run the
//! session handshake `[version 0][protocol 2]`, and then multiplex individual
//! proxy streams as HTTP/2 CONNECT requests carrying `[flags: u16][target_addr]`
//! and receiving a 1-byte success response `0x00`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

use crate::inbound::{ClientConn, Target, drive_framed};
use crate::logging;
use crate::outbound::mux::{MUX_DESTINATION, MUX_PORT};
use crate::outbound::transport::h2io::{H2Io, H2Stream, server_builder};
use crate::route::Router;

const VERSION0: u8 = 0;
const PROTOCOL_H2MUX: u8 = 2;
const STATUS_SUCCESS: u8 = 0;

/// Check whether the destination target matches the magic `sing-mux` destination.
pub fn is_mux_target(target: &Target) -> bool {
    match target {
        Target::Domain(host, port) => {
            *port == MUX_PORT && host.eq_ignore_ascii_case(MUX_DESTINATION)
        }
        _ => false,
    }
}

/// Serve a multiplexed H2MUX inbound session.
pub async fn serve_mux(
    mut stream: crate::inbound::AnyStream,
    peer: SocketAddr,
    local: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    // 1. Read session handshake: [version, protocol]
    let mut session_head = [0u8; 2];
    stream.read_exact(&mut session_head).await?;
    if session_head[0] != VERSION0 {
        return Err(io::Error::other(format!(
            "mux: unsupported version {}",
            session_head[0]
        )));
    }
    if session_head[1] != PROTOCOL_H2MUX {
        return Err(io::Error::other(format!(
            "mux: unsupported protocol {}",
            session_head[1]
        )));
    }

    // Check optional padding byte: if 1, read pad length and skip
    let mut check_pad = [0u8; 1];
    // We do a peek or timed read; if next byte is 1, read pad length
    // In sing-box: padding flag byte is present only when padding is configured
    // For H2, H2 preface starts with "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" which starts with 'P' (0x50).
    // If the next byte is 1 (padding flag), it is followed by 2 bytes length.
    stream.read_exact(&mut check_pad).await?;
    if check_pad[0] == 1 {
        let mut pad_len_buf = [0u8; 2];
        stream.read_exact(&mut pad_len_buf).await?;
        let pad_len = u16::from_be_bytes(pad_len_buf) as usize;
        let mut skip_buf = vec![0u8; pad_len];
        stream.read_exact(&mut skip_buf).await?;
    } else {
        // If not padding, `check_pad[0]` is the first byte of H2 client preface ('P')
        // We prepend it back into the stream
        stream = Box::new(PrefixedStream::new(vec![check_pad[0]], stream));
    }

    // 2. Perform HTTP/2 server handshake
    let mut connection = server_builder()
        .handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("mux h2 handshake: {e}")))?;

    logging::info(format_args!(
        "mux inbound {tag}: accepted h2 session from {peer}"
    ));

    // 3. Accept multiplexed streams
    while let Some(result) = connection.accept().await {
        let (request, mut respond) = match result {
            Ok(v) => v,
            Err(e) => {
                logging::warn(format_args!("mux inbound {tag} accept error: {e}"));
                break;
            }
        };

        // Send HTTP 200 OK response to establish tunnel
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .map_err(|e| io::Error::other(e.to_string()))?;
        let send_stream = match respond.send_response(response, false) {
            Ok(s) => s,
            Err(e) => {
                logging::warn(format_args!("mux inbound {tag} send_response error: {e}"));
                continue;
            }
        };

        let recv_stream = request.into_body();
        let mut h2_io = H2Io {
            h2: H2Stream::server(recv_stream, send_stream),
        };

        let router = Arc::clone(router);
        let tag = tag.to_string();

        tokio::spawn(async move {
            // Read stream request: 2 bytes flags, then Target
            let mut flags = [0u8; 2];
            if let Err(e) = h2_io.read_exact(&mut flags).await {
                logging::warn(format_args!("mux inbound {tag} read flags error: {e}"));
                return;
            }

            let target = match read_sing_addr_port(&mut h2_io).await {
                Ok(t) => t,
                Err(e) => {
                    logging::warn(format_args!("mux inbound {tag} read target error: {e}"));
                    return;
                }
            };

            // Write 1-byte STATUS_SUCCESS (0) to client
            if let Err(e) = h2_io.write_all(&[STATUS_SUCCESS]).await {
                logging::warn(format_args!("mux inbound {tag} write success error: {e}"));
                return;
            }

            let flag_val = u16::from_be_bytes(flags);
            let is_packetaddr = (flag_val & 2 != 0)
                || (matches!(&target, Target::Domain(h, _) if h == crate::outbound::packet::SEQ_PACKET_MAGIC));
            let is_udp = (flag_val & 1 != 0) || is_packetaddr;

            if is_udp {
                logging::info(format_args!(
                    "mux inbound {tag} UDP stream (packetaddr={is_packetaddr}) from {peer} to {target}"
                ));
                let (mut h2_read, h2_write) = tokio::io::split(h2_io);
                let writer: Arc<tokio::sync::Mutex<crate::inbound::AnyWrite>> =
                    Arc::new(tokio::sync::Mutex::new(Box::new(h2_write)));
                let frame = if is_packetaddr {
                    crate::inbound::udp::DatagramFrame::PacketAddr
                } else {
                    crate::inbound::udp::DatagramFrame::LengthPrefixed
                };
                let hub = crate::inbound::udp::UdpHub::new(
                    Arc::clone(&router),
                    crate::inbound::udp::DEFAULT_UDP_TIMEOUT,
                    frame,
                );
                let _stop_hub = crate::inbound::udp::StopHub(Arc::clone(&hub));
                let reply = crate::inbound::udp::Reply::Stream(writer);
                let mut len_buf = [0u8; 2];
                loop {
                    if let Err(err) = h2_read.read_exact(&mut len_buf).await {
                        if err.kind() == std::io::ErrorKind::UnexpectedEof && len_buf == [0, 0] {
                            break;
                        }
                        break;
                    }
                    let pkt_len = u16::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; pkt_len];
                    if h2_read.read_exact(&mut payload).await.is_err() {
                        break;
                    }
                    if is_packetaddr {
                        if let Ok((dest_target, data)) =
                            crate::outbound::packet::take_addr_port(&payload)
                            && let Ok(dest_addr) =
                                crate::inbound::udp::udp_destination(&dest_target)
                        {
                            let _ = hub.handle(reply.clone(), peer, dest_addr, data, &tag).await;
                        }
                    } else if let Ok(dest_addr) = crate::inbound::udp::udp_destination(&target) {
                        let _ = hub
                            .handle(reply.clone(), peer, dest_addr, &payload, &tag)
                            .await;
                    }
                }
            } else {
                logging::info(format_args!(
                    "mux inbound {tag} stream from {peer} to {target}"
                ));

                let client = ClientConn::framed(Box::new(h2_io), local);
                let _ = drive_framed(client, peer, target, &tag, &router).await;
            }
        });
    }

    Ok(())
}

/// Read sing-box address format: 0x01 ipv4, 0x04 ipv6, 0x03 domain.
async fn read_sing_addr_port<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(Target::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                u16::from_be_bytes(port),
            )))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(Target::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes(port),
            )))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let s = String::from_utf8(host)
                .map_err(|e| io::Error::other(format!("invalid domain: {e}")))?;
            Ok(Target::Domain(s, u16::from_be_bytes(port)))
        }
        other => Err(io::Error::other(format!("unknown sing addr atyp: {other}"))),
    }
}

/// Helper stream that yields prefixed bytes before reading from inner stream.
struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: crate::inbound::AnyStream,
}

impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: crate::inbound::AnyStream) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mux_target() {
        assert!(is_mux_target(&Target::Domain(
            "sp.mux.sing-box.arpa".to_string(),
            444
        )));
        assert!(!is_mux_target(&Target::Domain(
            "sp.mux.sing-box.arpa".to_string(),
            443
        )));
        assert!(!is_mux_target(&Target::Domain(
            "google.com".to_string(),
            444
        )));
        assert!(!is_mux_target(&Target::Ip(
            "127.0.0.1:444".parse().unwrap()
        )));
    }
}
