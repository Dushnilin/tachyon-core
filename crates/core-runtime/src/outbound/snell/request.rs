//! snell request/reply and address codecs (reference `request.go` +
//! `address.go`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::inbound::Target;

pub(crate) const REQUEST_VERSION: u8 = 0x01;
pub(crate) const CMD_PING: u8 = 0x00;
pub(crate) const CMD_CONNECT: u8 = 0x01;
pub(crate) const CMD_CONNECT_V2: u8 = 0x05;
pub(crate) const CMD_UDP: u8 = 0x06;

pub(crate) const REPLY_TUNNEL: u8 = 0x00;
pub(crate) const REPLY_ERROR: u8 = 0x02;

pub(crate) const UDP_FORWARD: u8 = 0x01;
pub(crate) const ADDRESS_TYPE_IPV4: u8 = 0x04;
pub(crate) const ADDRESS_TYPE_IPV6: u8 = 0x06;

fn socks_string(out: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| io::Error::other("snell: host too long"))?;
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

fn read_socks_string(buf: &[u8], pos: &mut usize) -> io::Result<Vec<u8>> {
    let len = *buf
        .get(*pos)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "snell: short socks string"))?
        as usize;
    *pos += 1;
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= buf.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "snell: short socks string"))?;
    let value = buf[*pos..end].to_vec();
    *pos = end;
    Ok(value)
}

/// CONNECT destinations are host strings even for literal IPs (reference
/// `WriteConnectAddress`).
fn target_host(target: &Target) -> String {
    match target {
        Target::Domain(host, _) => host.clone(),
        Target::Ip(addr) => addr.ip().to_string(),
    }
}

fn target_port(target: &Target) -> u16 {
    match target {
        Target::Domain(_, port) => *port,
        Target::Ip(addr) => addr.port(),
    }
}

/// `[0x01][cmd][id len][id][connect address?]` (reference `Request.Write`).
pub(crate) fn write_request(
    cmd: u8,
    client_id: &[u8],
    target: Option<&Target>,
) -> io::Result<Vec<u8>> {
    let id_len =
        u8::try_from(client_id.len()).map_err(|_| io::Error::other("snell: client id too long"))?;
    let mut out = Vec::with_capacity(3 + client_id.len() + 32);
    out.push(REQUEST_VERSION);
    out.push(cmd);
    out.push(id_len);
    out.extend_from_slice(client_id);
    match cmd {
        CMD_CONNECT | CMD_CONNECT_V2 => {
            let target = target.ok_or_else(|| io::Error::other("snell: missing destination"))?;
            socks_string(&mut out, target_host(target).as_bytes())?;
            out.extend_from_slice(&target_port(target).to_be_bytes());
        }
        CMD_PING | CMD_UDP => {}
        other => {
            return Err(io::Error::other(format!(
                "snell: unsupported command {other}"
            )));
        }
    }
    Ok(out)
}

/// Reply frame: `0x00` tunnel (remainder cached as first payload), `0x02`
/// error (code + socks string message, no trailing data), anything else is an
/// unexpected opcode (reference `reuse.ParseReply`).
pub(crate) fn parse_reply(record: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let (&reply, rest) = record
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "snell: empty reply"))?;
    match reply {
        REPLY_TUNNEL => Ok(if rest.is_empty() {
            None
        } else {
            Some(rest.to_vec())
        }),
        REPLY_ERROR => Err(parse_server_error(rest)),
        other => Err(io::Error::other(format!(
            "snell: unexpected reply opcode {other}"
        ))),
    }
}

/// Reference `ReadServerError`: `[code][socks message]`, trailing data rejected.
fn parse_server_error(rest: &[u8]) -> io::Error {
    let (code, body) = match rest.split_first() {
        Some(v) => v,
        None => return io::Error::other("snell: server error: empty reply"),
    };
    let mut pos = 0usize;
    let message = match read_socks_string(body, &mut pos) {
        Ok(message) => message,
        Err(_) => return io::Error::other("snell: server error: short message"),
    };
    if pos != body.len() {
        return io::Error::other("snell: server error reply has trailing data");
    }
    io::Error::other(format!(
        "snell: server error {code}: {}",
        String::from_utf8_lossy(&message)
    ))
}

/// UDP target address: literal IPs are prefixed with `0x00` + family byte
/// (reference `WriteUDPRequestAddress`).
pub(crate) fn write_udp_request_address(out: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    match target {
        Target::Domain(host, port) => {
            socks_string(out, host.as_bytes())?;
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(addr) => {
            out.push(0x00);
            match addr.ip() {
                IpAddr::V4(v4) => {
                    out.push(ADDRESS_TYPE_IPV4);
                    out.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    out.push(ADDRESS_TYPE_IPV6);
                    out.extend_from_slice(&v6.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(())
}

/// UDP response source: `[family][addr][port][payload]` (reference
/// `ReadUDPResponseAddress`); returns the source and the payload offset.
pub(crate) fn read_udp_response_address(buf: &[u8]) -> io::Result<(SocketAddr, usize)> {
    let (&family, rest) = buf
        .split_first()
        .ok_or_else(|| io::Error::other("snell: udp response too short"))?;
    match family {
        ADDRESS_TYPE_IPV4 => {
            if rest.len() < 6 {
                return Err(io::Error::other("snell: udp response too short"));
            }
            let ip = IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]));
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok((SocketAddr::new(ip, port), 7))
        }
        ADDRESS_TYPE_IPV6 => {
            if rest.len() < 18 {
                return Err(io::Error::other("snell: udp response too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok((SocketAddr::new(ip, port), 19))
        }
        _ => Err(io::Error::other("snell: udp response address type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::Domain("example.com".to_string(), 443)
    }

    #[test]
    fn connect_v2_request_layout() {
        let req = write_request(CMD_CONNECT_V2, b"user-key", Some(&target())).expect("write");
        assert_eq!(req[0], REQUEST_VERSION);
        assert_eq!(req[1], CMD_CONNECT_V2);
        assert_eq!(req[2], 8);
        assert_eq!(&req[3..11], b"user-key");
        assert_eq!(req[11], 11, "host len");
        assert_eq!(&req[12..23], b"example.com");
        assert_eq!(&req[23..25], &443u16.to_be_bytes());
        assert_eq!(req.len(), 25);
    }

    #[test]
    fn connect_v2_literal_ip_is_host_string() {
        let target = Target::Ip("192.0.2.7:80".parse().expect("addr"));
        let req = write_request(CMD_CONNECT_V2, b"", Some(&target)).expect("write");
        assert_eq!(
            req,
            [
                1, 5, 0, 9, b'1', b'9', b'2', b'.', b'0', b'.', b'2', b'.', b'7', 0, 80
            ]
        );
    }

    #[test]
    fn udp_request_has_no_destination() {
        let req = write_request(CMD_UDP, b"id", None).expect("write");
        assert_eq!(req, [1, 6, 2, b'i', b'd']);
    }

    #[test]
    fn ping_request() {
        let req = write_request(CMD_PING, b"", None).expect("write");
        assert_eq!(req, [1, 0, 0]);
    }

    #[test]
    fn reply_tunnel_and_cache() {
        assert_eq!(parse_reply(&[0]).expect("tunnel"), None);
        assert_eq!(
            parse_reply(&[0, 9, 8, 7]).expect("tunnel cached"),
            Some(vec![9, 8, 7])
        );
    }

    #[test]
    fn reply_error_shapes() {
        let err = parse_reply(&[2, 1, 4, b'b', b'a', b'd', b'!']).expect_err("error");
        assert_eq!(err.to_string(), "snell: server error 1: bad!");
        let trailing = parse_reply(&[2, 1, 2, b'o', b'k', 9]).expect_err("trailing");
        assert_eq!(
            trailing.to_string(),
            "snell: server error reply has trailing data"
        );
        let unexpected = parse_reply(&[7]).expect_err("opcode");
        assert_eq!(unexpected.to_string(), "snell: unexpected reply opcode 7");
        assert!(parse_reply(&[]).is_err());
    }

    #[test]
    fn udp_request_address_domain_and_ip() {
        let mut out = Vec::new();
        write_udp_request_address(&mut out, &target()).expect("write");
        assert_eq!(
            out,
            [
                11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 1, 187
            ]
        );

        let mut out = Vec::new();
        let ip: Target = Target::Ip("198.51.100.9:53".parse().expect("addr"));
        write_udp_request_address(&mut out, &ip).expect("write");
        assert_eq!(out, [0, 4, 198, 51, 100, 9, 0, 53]);

        let mut out = Vec::new();
        let ip6: Target = Target::Ip("[2001:db8::1]:53".parse().expect("addr"));
        write_udp_request_address(&mut out, &ip6).expect("write");
        assert_eq!(out[0], 0);
        assert_eq!(out[1], 6);
        assert_eq!(out.len(), 2 + 16 + 2);
    }

    #[test]
    fn udp_response_address_parse() {
        let mut buf = vec![4, 192, 0, 2, 1];
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(b"payload");
        let (addr, offset) = read_udp_response_address(&buf).expect("parse");
        assert_eq!(addr, "192.0.2.1:443".parse().expect("addr"));
        assert_eq!(&buf[offset..], b"payload");

        let mut buf = vec![6];
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&53u16.to_be_bytes());
        buf.extend_from_slice(b"d");
        let (addr, offset) = read_udp_response_address(&buf).expect("parse");
        assert_eq!(addr, "[2001:db8::1]:53".parse().expect("addr"));
        assert_eq!(&buf[offset..], b"d");

        assert!(read_udp_response_address(&[8, 1, 2]).is_err());
        assert!(read_udp_response_address(&[9, 1, 2, 3, 4, 5, 6, 7, 8]).is_err());
        assert!(read_udp_response_address(&[]).is_err());
    }
}
