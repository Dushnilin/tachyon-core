//! Execution engine for TCP and UDP DPI desynchronization.

use std::io;
use std::time::Duration;

use socket2::SockRef;
use tokio::io::Interest;
use tokio::net::{TcpStream, UdpSocket};

use super::config::{DesyncConfig, DesyncMode, SplitPos};
use super::packet::{compute_midsld_or_fallback, find_http_host, find_sni, is_tls_client_hello};
use super::payload::{FAKE_QUIC_INITIAL, FAKE_STUN_BINDING_REQUEST};

/// Set TTL / Hop Limit on a socket reference (supports both IPv4 and IPv6).
pub fn set_socket_ttl_ref(sock: &SockRef, ttl: u8, is_ipv6: bool) -> io::Result<()> {
    if is_ipv6 {
        sock.set_unicast_hops_v6(ttl as u32)
    } else {
        sock.set_ttl_v4(ttl as u32)
    }
}

/// Query current TTL / Hop Limit from a socket reference.
pub fn get_socket_ttl_ref(sock: &SockRef, is_ipv6: bool) -> u8 {
    if is_ipv6 {
        sock.unicast_hops_v6().unwrap_or(64) as u8
    } else {
        sock.ttl_v4().unwrap_or(64) as u8
    }
}

/// Write data to a non-blocking TCP stream without requiring mutable reference.
pub async fn write_all_stream(stream: &TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = match stream.try_write(data) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                stream
                    .async_io(Interest::WRITABLE, || stream.try_write(data))
                    .await?
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        data = &data[n..];
    }
    Ok(())
}

/// Calculate the split position for the given payload based on configuration.
pub fn compute_split_offset(prefix: &[u8], split_pos: &SplitPos) -> usize {
    if prefix.len() <= 1 {
        return 1;
    }

    match split_pos {
        SplitPos::Byte(n) => (*n).clamp(1, prefix.len().saturating_sub(1)),
        SplitPos::Sni => {
            if let Some(m) = find_sni(prefix) {
                m.sni_ext_offset.clamp(1, prefix.len().saturating_sub(1))
            } else if let Some(m) = find_http_host(prefix) {
                m.host_offset.clamp(1, prefix.len().saturating_sub(1))
            } else {
                1
            }
        }
        SplitPos::MidSld => {
            if let Some(m) = find_sni(prefix) {
                m.midsld_offset.clamp(1, prefix.len().saturating_sub(1))
            } else if let Some(m) = find_http_host(prefix) {
                m.midsld_offset.clamp(1, prefix.len().saturating_sub(1))
            } else {
                compute_midsld_or_fallback(prefix)
            }
        }
    }
}

/// Apply DPI desynchronization strategy to the initial TCP payload.
pub async fn apply_desync_tcp(
    stream: &TcpStream,
    prefix: &[u8],
    config: &DesyncConfig,
) -> io::Result<()> {
    if prefix.is_empty() || config.mode == DesyncMode::None {
        return write_all_stream(stream, prefix).await;
    }

    // Force TCP_NODELAY so segments are emitted immediately without Nagle coalescing
    let _ = stream.set_nodelay(true);

    let sock = SockRef::from(stream);
    let is_ipv6 = stream.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let orig_ttl = get_socket_ttl_ref(&sock, is_ipv6);

    match config.mode {
        DesyncMode::Split => {
            let pos = compute_split_offset(prefix, &config.split_pos);
            write_all_stream(stream, &prefix[..pos]).await?;
            if config.split_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(config.split_delay_ms)).await;
            }
            write_all_stream(stream, &prefix[pos..]).await?;
        }

        DesyncMode::Fake => {
            let fake = &config.fake_payload[..];
            let _ = set_socket_ttl_ref(&sock, config.fake_ttl, is_ipv6);
            for _ in 0..config.repeats {
                let _ = write_all_stream(stream, fake).await;
            }
            let _ = set_socket_ttl_ref(&sock, orig_ttl, is_ipv6);
            write_all_stream(stream, prefix).await?;
        }

        DesyncMode::FakeSplit => {
            let fake = &config.fake_payload[..];
            let _ = set_socket_ttl_ref(&sock, config.fake_ttl, is_ipv6);
            for _ in 0..config.repeats {
                let _ = write_all_stream(stream, fake).await;
            }
            let _ = set_socket_ttl_ref(&sock, orig_ttl, is_ipv6);

            let pos = compute_split_offset(prefix, &config.split_pos);
            write_all_stream(stream, &prefix[..pos]).await?;
            if config.split_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(config.split_delay_ms)).await;
            }
            write_all_stream(stream, &prefix[pos..]).await?;
        }

        DesyncMode::Disorder => {
            let pos = compute_split_offset(prefix, &config.split_pos);
            // Send fragment 1 with TTL=1: dropped by intermediate hop, causes server to retransmit
            let _ = set_socket_ttl_ref(&sock, 1, is_ipv6);
            let _ = write_all_stream(stream, &prefix[..pos]).await;
            let _ = set_socket_ttl_ref(&sock, orig_ttl, is_ipv6);
            write_all_stream(stream, &prefix[pos..]).await?;
        }

        DesyncMode::TlsRec => {
            let pos = compute_split_offset(prefix, &config.split_pos);
            if is_tls_client_hello(prefix) && pos > 0 {
                let rec_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
                let hs_len = rec_len.min(prefix.len().saturating_sub(5));
                if pos < hs_len {
                    let part1 = &prefix[5..5 + pos];
                    let part2 = &prefix[5 + pos..5 + hs_len];

                    let len1 = part1.len() as u16;
                    let hdr1 = [0x16, prefix[1], prefix[2], (len1 >> 8) as u8, len1 as u8];
                    write_all_stream(stream, &hdr1).await?;
                    write_all_stream(stream, part1).await?;

                    if config.split_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(config.split_delay_ms)).await;
                    }

                    let len2 = part2.len() as u16;
                    let hdr2 = [0x16, prefix[1], prefix[2], (len2 >> 8) as u8, len2 as u8];
                    write_all_stream(stream, &hdr2).await?;
                    write_all_stream(stream, part2).await?;
                } else {
                    write_all_stream(stream, prefix).await?;
                }
            } else {
                // Fallback to TCP split if not TLS
                write_all_stream(stream, &prefix[..pos]).await?;
                if config.split_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(config.split_delay_ms)).await;
                }
                write_all_stream(stream, &prefix[pos..]).await?;
            }
        }

        DesyncMode::Oob => {
            let pos = compute_split_offset(prefix, &config.split_pos);
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = stream.as_raw_fd();
                let oob_byte = *b"a";
                unsafe {
                    libc::send(fd, oob_byte.as_ptr() as *const _, 1, libc::MSG_OOB);
                }
            }
            write_all_stream(stream, &prefix[..pos]).await?;
            if config.split_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(config.split_delay_ms)).await;
            }
            write_all_stream(stream, &prefix[pos..]).await?;
        }

        DesyncMode::None => {
            write_all_stream(stream, prefix).await?;
        }
    }

    Ok(())
}

/// Apply UDP DPI desynchronization (QUIC / STUN bursts) to a connected UDP socket.
pub async fn apply_desync_udp(
    socket: &UdpSocket,
    target_port: u16,
    config: &DesyncConfig,
) -> io::Result<()> {
    if !config.udp_fake || config.udp_repeats == 0 {
        return Ok(());
    }

    let sock = SockRef::from(socket);
    let is_ipv6 = socket.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let orig_ttl = get_socket_ttl_ref(&sock, is_ipv6);

    let fake_data: &[u8] = if target_port == 443 {
        &FAKE_QUIC_INITIAL
    } else if (50000..=50099).contains(&target_port) || target_port == 3478 || target_port == 1400 {
        &FAKE_STUN_BINDING_REQUEST
    } else {
        &FAKE_QUIC_INITIAL
    };

    let _ = set_socket_ttl_ref(&sock, config.udp_fake_ttl, is_ipv6);
    for _ in 0..config.udp_repeats {
        let _ = socket.send(fake_data).await;
    }
    let _ = set_socket_ttl_ref(&sock, orig_ttl, is_ipv6);

    Ok(())
}
