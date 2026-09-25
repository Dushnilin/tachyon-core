//! CONNECT-IP (RFC 9484) client-side datapath: address/route capsules, TTL and
//! hop-limit compose, IPv4 header checksum, ICMP packet-too-big replies and
//! incoming datagram validation. Ported from the Go reference `connectip`
//! package (vendored from connect-ip-go, MIT), including the SPEC 022 #6
//! fix that recomputes the IPv4 checksum over the full IHL header so options
//! are covered.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::outbound::quic::{put_varint, read_varint};

pub(crate) const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
pub(crate) const CAPSULE_ADDRESS_REQUEST: u64 = 2;
pub(crate) const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

pub(crate) const IP_PROTO_ICMP: u8 = 1;
pub(crate) const IP_PROTO_ICMPV6: u8 = 58;

/// IPv6 minimum link MTU (RFC 8200); also the MTU quoted in ICMP packet-too-big
/// replies in both directions.
pub(crate) const MIN_MTU: u16 = 1280;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Empty,
    Truncated,
    UnknownIpVersion(u8),
    PacketTooShort(&'static str),
    InvalidHeaderLength(u8),
    TtlTooSmall(u8),
    HopLimitTooSmall(u8),
    SourceNotAllowed(IpAddr),
    DestinationNotAllowed { dst: IpAddr, proto: u8 },
    BadPrefixLength { bits: u8, max: u8 },
    NonZeroPrefixBits,
    StartAfterEnd,
    UnknownCapsule(u64),
    UnsupportedContextId(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty => write!(f, "connect-ip: empty packet"),
            Error::Truncated => write!(f, "connect-ip: truncated"),
            Error::UnknownIpVersion(v) => write!(f, "connect-ip: unknown IP versions: {v}"),
            Error::PacketTooShort(what) => write!(f, "connect-ip: {what}"),
            Error::InvalidHeaderLength(n) => {
                write!(f, "connect-ip: invalid IPv4 header length: {n}")
            }
            Error::TtlTooSmall(t) => write!(f, "connect-ip: datagram TTL too small: {t}"),
            Error::HopLimitTooSmall(h) => {
                write!(f, "connect-ip: datagram Hop Limit too small: {h}")
            }
            Error::SourceNotAllowed(ip) => {
                write!(f, "connect-ip: datagram source address not allowed: {ip}")
            }
            Error::DestinationNotAllowed { dst, proto } => write!(
                f,
                "connect-ip: datagram destination address / protocol not allowed: {dst} (protocol: {proto})"
            ),
            Error::BadPrefixLength { bits, max } => write!(
                f,
                "connect-ip: prefix length {bits} exceeds IP address length ({max})"
            ),
            Error::NonZeroPrefixBits => write!(
                f,
                "connect-ip: lower bits not covered by prefix length are not all zero"
            ),
            Error::StartAfterEnd => write!(f, "connect-ip: start IP is greater than end IP"),
            Error::UnknownCapsule(t) => write!(f, "connect-ip: unknown capsule type: {t}"),
            Error::UnsupportedContextId(c) => {
                write!(f, "connect-ip: unsupported context ID: {c}")
            }
        }
    }
}

impl std::error::Error for Error {}

fn ip_version(b: &[u8]) -> u8 {
    b[0] >> 4
}

/// Recompute the IPv4 header checksum over `header` (the caller passes
/// `header[:IHL*4]`, so options are covered). The checksum field itself
/// (offset 10..12) is skipped. Mirrors Go `calculateIPv4Checksum`.
pub(crate) fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i != 10 {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        }
        i += 2;
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ones-complement checksum (RFC 1071) over `buf`, big-endian word order,
/// trailing odd byte zero-padded on the right. Used for ICMP/ICMPv6.
fn ones_complement_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u32::from(u16::from_be_bytes([buf[i], buf[i + 1]]));
        i += 2;
    }
    if i < buf.len() {
        sum += u32::from(buf[i]) << 8;
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Decrement TTL (v4) or hop limit (v6) in place and refresh the IPv4 header
/// checksum. Returns the reason the packet must be dropped instead.
pub(crate) fn decrement_hop_limit(b: &mut [u8]) -> Result<(), Error> {
    if b.is_empty() {
        return Err(Error::Empty);
    }
    match ip_version(b) {
        4 => {
            if b.len() < IPV4_HEADER_LEN {
                return Err(Error::PacketTooShort("IPv4 packet too short"));
            }
            let ihl = usize::from(b[0] & 0x0f) * 4;
            if ihl < IPV4_HEADER_LEN || ihl > b.len() {
                return Err(Error::InvalidHeaderLength(ihl as u8));
            }
            let ttl = b[8];
            if ttl <= 1 {
                return Err(Error::TtlTooSmall(ttl));
            }
            b[8] = ttl - 1;
            let csum = calculate_ipv4_checksum(&b[..ihl]);
            b[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        6 => {
            if b.len() < IPV6_HEADER_LEN {
                return Err(Error::PacketTooShort("IPv6 packet too short"));
            }
            let hop = b[7];
            if hop <= 1 {
                return Err(Error::HopLimitTooSmall(hop));
            }
            b[7] = hop - 1;
        }
        v => return Err(Error::UnknownIpVersion(v)),
    }
    Ok(())
}

/// Compose the outgoing CONNECT-IP datagram payload: context ID 0 varint
/// followed by the (mutated) IP packet. Mutates `b` in place via
/// [`decrement_hop_limit`].
pub(crate) fn compose_datagram(b: &mut [u8]) -> Result<Vec<u8>, Error> {
    decrement_hop_limit(b)?;
    let mut out = Vec::with_capacity(1 + b.len());
    put_varint(&mut out, 0);
    out.extend_from_slice(b);
    Ok(out)
}

/// Snapshot of the datagram as the application sent it, capped at [`MIN_MTU`],
/// for quoting in an ICMP packet-too-big reply after compose mutated the
/// packet (SPEC 021 A3).
pub(crate) fn snapshot_head(b: &[u8]) -> Vec<u8> {
    let snap = b.len().min(usize::from(MIN_MTU));
    b[..snap].to_vec()
}

/// Strip the context ID varint from a received datagram payload and return the
/// IP packet. Only context ID 0 (IP payloads) is proxied.
pub(crate) fn parse_context_id(buf: &[u8]) -> Result<&[u8], Error> {
    let (ctx, n) = read_varint(buf).ok_or(Error::Truncated)?;
    if ctx != 0 {
        return Err(Error::UnsupportedContextId(ctx));
    }
    Ok(&buf[n..])
}

/// Build an ICMP packet-too-big reply quoting `orig` (the pre-mutation
/// snapshot): v4 destination-unreachable/code 4, v6 packet-too-big, `mtu`
/// carried in the body. Returns the complete reply IP packet.
pub(crate) fn compose_icmp_too_large(orig: &[u8], mtu: u16) -> Result<Vec<u8>, Error> {
    if orig.is_empty() {
        return Err(Error::Empty);
    }
    let mtu = u32::from(mtu);
    match ip_version(orig) {
        4 => {
            if orig.len() < IPV4_HEADER_LEN {
                return Err(Error::PacketTooShort("IPv4 packet too short"));
            }
            let quote_len = orig.len().min(IPV4_HEADER_LEN + 8);
            let mut icmp = Vec::with_capacity(8 + quote_len);
            icmp.extend_from_slice(&[3, 4, 0, 0]);
            icmp.extend_from_slice(&mtu.to_be_bytes());
            icmp.extend_from_slice(&orig[..quote_len]);
            let csum = ones_complement_checksum(&icmp);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());

            let mut header = [0u8; IPV4_HEADER_LEN];
            header[0] = 0x45;
            let ip_len = (IPV4_HEADER_LEN + icmp.len()) as u16;
            header[2..4].copy_from_slice(&ip_len.to_be_bytes());
            header[8] = 64;
            header[9] = IP_PROTO_ICMP;
            header[12..16].copy_from_slice(&orig[16..20]);
            header[16..20].copy_from_slice(&orig[12..16]);
            let csum = calculate_ipv4_checksum(&header);
            header[10..12].copy_from_slice(&csum.to_be_bytes());

            let mut out = Vec::with_capacity(header.len() + icmp.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(&icmp);
            Ok(out)
        }
        6 => {
            if orig.len() < IPV6_HEADER_LEN {
                return Err(Error::PacketTooShort("IPv6 packet too short"));
            }
            // 1232 = MIN_MTU(1280) - IPv6 header(40) - ICMPv6 header(8): the
            // most quoted data that keeps the reply within the min IPv6 MTU.
            let quote_len = orig.len().min(1232);
            let mut icmp = Vec::with_capacity(8 + quote_len);
            icmp.extend_from_slice(&[2, 0, 0, 0]);
            icmp.extend_from_slice(&mtu.to_be_bytes());
            icmp.extend_from_slice(&orig[..quote_len]);

            let mut psh = [0u8; 40];
            psh[0..16].copy_from_slice(&orig[24..40]);
            psh[16..32].copy_from_slice(&orig[8..24]);
            psh[32..36].copy_from_slice(&(icmp.len() as u32).to_be_bytes());
            psh[39] = IP_PROTO_ICMPV6;
            let mut psh_msg = Vec::with_capacity(40 + icmp.len());
            psh_msg.extend_from_slice(&psh);
            psh_msg.extend_from_slice(&icmp);
            let csum = ones_complement_checksum(&psh_msg);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());

            let mut header = [0u8; IPV6_HEADER_LEN];
            header[0] = 6 << 4;
            header[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
            header[6] = IP_PROTO_ICMPV6;
            header[7] = 64;
            header[8..24].copy_from_slice(&orig[24..40]);
            header[24..40].copy_from_slice(&orig[8..24]);

            let mut out = Vec::with_capacity(header.len() + icmp.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(&icmp);
            Ok(out)
        }
        v => Err(Error::UnknownIpVersion(v)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn new(addr: IpAddr, len: u8) -> Self {
        Prefix { addr, len }
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let bits = self.len.min(32);
                if bits == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - bits);
                (u32::from(net) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let bits = self.len.min(128);
                let net = u128::from(net);
                let a = u128::from(a);
                if bits == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - bits);
                (net & mask) == (a & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    pub start: IpAddr,
    pub end: IpAddr,
    /// Internet protocol number allowed for this range; 0 = all protocols.
    pub proto: u8,
}

impl Route {
    pub fn contains(&self, addr: IpAddr, proto: u8, is_icmp: bool) -> bool {
        match (self.start, self.end, addr) {
            (IpAddr::V4(s), IpAddr::V4(e), IpAddr::V4(a)) => {
                if u32::from(s) > u32::from(a) || u32::from(a) > u32::from(e) {
                    return false;
                }
            }
            (IpAddr::V6(s), IpAddr::V6(e), IpAddr::V6(a)) => {
                if u128::from(s) > u128::from(a) || u128::from(a) > u128::from(e) {
                    return false;
                }
            }
            _ => return false,
        }
        is_icmp || self.proto == 0 || self.proto == proto
    }
}

/// Validate an incoming proxied packet against the tunnel policy, mirroring Go
/// `handleIncomingProxiedPacket`: source against `peers` (when set),
/// destination against assigned addresses first, then advertised local routes.
pub(crate) fn validate_incoming(
    packet: &[u8],
    assigned: &[Prefix],
    routes: &[Route],
    peers: Option<&[Prefix]>,
) -> Result<(), Error> {
    if packet.is_empty() {
        return Err(Error::Empty);
    }
    let version = ip_version(packet);
    let (src, dst, proto) = match version {
        4 => {
            if packet.len() < IPV4_HEADER_LEN {
                return Err(Error::PacketTooShort("malformed datagram: too short"));
            }
            (
                IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
                IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()),
                packet[9],
            )
        }
        6 => {
            if packet.len() < IPV6_HEADER_LEN {
                return Err(Error::PacketTooShort("malformed datagram: too short"));
            }
            (
                IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
                IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
                packet[6],
            )
        }
        v => return Err(Error::UnknownIpVersion(v)),
    };

    if let Some(peers) = peers
        && !peers.iter().any(|p| p.contains(src))
    {
        return Err(Error::SourceNotAllowed(src));
    }

    let mut allowed = !assigned.is_empty() && assigned.iter().any(|p| p.contains(dst));
    if !allowed {
        let is_icmp =
            (version == 4 && proto == IP_PROTO_ICMP) || (version == 6 && proto == IP_PROTO_ICMPV6);
        allowed = routes.iter().any(|r| r.contains(dst, proto, is_icmp));
    }
    if !allowed {
        return Err(Error::DestinationNotAllowed { dst, proto });
    }
    Ok(())
}

/// Read one capsule (type varint, length varint, payload) from `rest`,
/// advancing it past the payload. Returns the raw payload slice.
pub(crate) fn read_capsule<'a>(rest: &mut &'a [u8]) -> Result<(u64, &'a [u8]), Error> {
    let (typ, n) = read_varint(rest).ok_or(Error::Truncated)?;
    let after_type = &rest[n..];
    let (len, n) = read_varint(after_type).ok_or(Error::Truncated)?;
    let payload_start = &after_type[n..];
    let len = usize::try_from(len).map_err(|_| Error::Truncated)?;
    if payload_start.len() < len {
        return Err(Error::Truncated);
    }
    *rest = &payload_start[len..];
    Ok((typ, &payload_start[..len]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssignedAddress {
    pub request_id: u64,
    pub addr: IpAddr,
    pub prefix_len: u8,
}

fn max_bits(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn parse_record_addr(payload: &[u8], pos: &mut usize) -> Result<AssignedAddress, Error> {
    let (request_id, n) = read_varint(&payload[*pos..]).ok_or(Error::Truncated)?;
    *pos += n;
    let ver = *payload.get(*pos).ok_or(Error::Truncated)?;
    *pos += 1;
    let addr_len = match ver {
        4 => 4,
        6 => 16,
        v => return Err(Error::UnknownIpVersion(v)),
    };
    let bytes = payload.get(*pos..*pos + addr_len).ok_or(Error::Truncated)?;
    *pos += addr_len;
    let addr = match ver {
        4 => IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap()),
        _ => IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap()),
    };
    let prefix_len = *payload.get(*pos).ok_or(Error::Truncated)?;
    *pos += 1;
    let max = max_bits(addr);
    if prefix_len > max {
        return Err(Error::BadPrefixLength {
            bits: prefix_len,
            max,
        });
    }
    let candidate = Prefix::new(addr, prefix_len);
    if candidate.masked() != addr {
        return Err(Error::NonZeroPrefixBits);
    }
    Ok(AssignedAddress {
        request_id,
        addr,
        prefix_len,
    })
}

impl Prefix {
    fn masked(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => {
                let bits = self.len.min(32);
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
            }
            IpAddr::V6(a) => {
                let bits = self.len.min(128);
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
            }
        }
    }
}

/// Parse the payload of an ADDRESS_ASSIGN capsule (RFC 9484 §2.2).
pub(crate) fn parse_address_assign(payload: &[u8]) -> Result<Vec<AssignedAddress>, Error> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        out.push(parse_record_addr(payload, &mut pos)?);
    }
    Ok(out)
}

/// Encode a full ADDRESS_ASSIGN capsule (type, length, entries). Used by the
/// round-trip tests and client-side assignment replies.
pub(crate) fn encode_address_assign(addrs: &[AssignedAddress]) -> Vec<u8> {
    let mut body = Vec::new();
    for a in addrs {
        put_varint(&mut body, a.request_id);
        match a.addr {
            IpAddr::V4(_) => body.push(4),
            IpAddr::V6(_) => body.push(6),
        }
        match a.addr {
            IpAddr::V4(v) => body.extend_from_slice(&v.octets()),
            IpAddr::V6(v) => body.extend_from_slice(&v.octets()),
        }
        body.push(a.prefix_len);
    }
    let mut out = Vec::new();
    put_varint(&mut out, CAPSULE_ADDRESS_ASSIGN);
    put_varint(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

/// Parse the payload of a ROUTE_ADVERTISEMENT capsule (RFC 9484 §2.3).
pub(crate) fn parse_route_advertisement(payload: &[u8]) -> Result<Vec<Route>, Error> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        let ver = *payload.get(pos).ok_or(Error::Truncated)?;
        pos += 1;
        let addr_len = match ver {
            4 => 4,
            6 => 16,
            v => return Err(Error::UnknownIpVersion(v)),
        };
        let start_bytes = payload.get(pos..pos + addr_len).ok_or(Error::Truncated)?;
        pos += addr_len;
        let end_bytes = payload.get(pos..pos + addr_len).ok_or(Error::Truncated)?;
        pos += addr_len;
        let proto = *payload.get(pos).ok_or(Error::Truncated)?;
        pos += 1;
        let (start, end) = match ver {
            4 => (
                IpAddr::from(<[u8; 4]>::try_from(start_bytes).unwrap()),
                IpAddr::from(<[u8; 4]>::try_from(end_bytes).unwrap()),
            ),
            _ => (
                IpAddr::from(<[u8; 16]>::try_from(start_bytes).unwrap()),
                IpAddr::from(<[u8; 16]>::try_from(end_bytes).unwrap()),
            ),
        };
        if route_start_after_end(start, end) {
            return Err(Error::StartAfterEnd);
        }
        out.push(Route { start, end, proto });
    }
    Ok(out)
}

fn route_start_after_end(start: IpAddr, end: IpAddr) -> bool {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => u32::from(s) > u32::from(e),
        (IpAddr::V6(s), IpAddr::V6(e)) => u128::from(s) > u128::from(e),
        (s, e) => s > e,
    }
}

/// Encode a full ROUTE_ADVERTISEMENT capsule (type, length, entries).
pub(crate) fn encode_route_advertisement(routes: &[Route]) -> Vec<u8> {
    let mut body = Vec::new();
    for r in routes {
        match r.start {
            IpAddr::V4(_) => body.push(4),
            IpAddr::V6(_) => body.push(6),
        }
        match (r.start, r.end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                body.extend_from_slice(&s.octets());
                body.extend_from_slice(&e.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                body.extend_from_slice(&s.octets());
                body.extend_from_slice(&e.octets());
            }
            _ => unreachable!("route family mismatch"),
        }
        body.push(r.proto);
    }
    let mut out = Vec::new();
    put_varint(&mut out, CAPSULE_ROUTE_ADVERTISEMENT);
    put_varint(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    fn v6(a: [u8; 16]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(a))
    }

    /// Go `TestIPv4Checksum`: well-formed header with the checksum field zeroed.
    fn rfc792_header() -> [u8; 20] {
        [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ]
    }

    #[test]
    fn checksum_vector_rfc792() {
        assert_eq!(calculate_ipv4_checksum(&rfc792_header()), 0xb861);
    }

    #[test]
    fn checksum_skips_field_bytes() {
        let mut a = rfc792_header();
        let mut b = rfc792_header();
        a[10..12].copy_from_slice(&[0xde, 0xad]);
        b[10..12].copy_from_slice(&[0xbe, 0xef]);
        assert_eq!(calculate_ipv4_checksum(&a), calculate_ipv4_checksum(&b));
        assert_eq!(calculate_ipv4_checksum(&a), 0xb861);
    }

    /// Go `TestIPv4ChecksumWithOptions`: IHL=6 header with a Router Alert
    /// option; the option word must be folded in (SPEC 022 #6).
    #[test]
    fn checksum_covers_ihl6_options() {
        let header: [u8; 24] = [
            0x46, 0x00, 0x00, 0x77, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0x94, 0x04, 0x00, 0x00,
        ];
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            if i != 10 {
                sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
            }
            i += 2;
        }
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let want = !(sum as u16);
        assert_eq!(calculate_ipv4_checksum(&header), want);
        assert_ne!(calculate_ipv4_checksum(&header[..20]), want);
    }

    #[test]
    fn compose_decrements_ttl_and_prefixes_context_id() {
        let mut pkt = rfc792_header();
        let orig_csum = calculate_ipv4_checksum(&pkt);
        pkt[10..12].copy_from_slice(&orig_csum.to_be_bytes());
        pkt[8] = 64;
        let composed = compose_datagram(&mut pkt).unwrap();
        assert_eq!(composed[0], 0);
        assert_eq!(&composed[1..], &pkt[..]);
        assert_eq!(pkt[8], 63);
        let csum = u16::from_be_bytes([pkt[10], pkt[11]]);
        assert_ne!(csum, orig_csum);
        assert_eq!(calculate_ipv4_checksum(&pkt[..20]), csum);
    }

    #[test]
    fn compose_rejects_ttl_and_hop_limit_of_one() {
        let mut pkt = rfc792_header();
        pkt[8] = 1;
        assert_eq!(compose_datagram(&mut pkt), Err(Error::TtlTooSmall(1)));
        let mut pkt = rfc792_header();
        pkt[8] = 0;
        assert_eq!(compose_datagram(&mut pkt), Err(Error::TtlTooSmall(0)));

        let mut v6pkt = [0u8; 40];
        v6pkt[0] = 0x60;
        v6pkt[7] = 1;
        assert_eq!(
            compose_datagram(&mut v6pkt),
            Err(Error::HopLimitTooSmall(1))
        );
        v6pkt[7] = 64;
        assert_eq!(compose_datagram(&mut v6pkt).unwrap()[8], 63);
    }

    #[test]
    fn compose_rejects_bad_headers() {
        let mut short = [0x45u8; 10];
        assert_eq!(
            compose_datagram(&mut short),
            Err(Error::PacketTooShort("IPv4 packet too short"))
        );
        let mut empty: [u8; 0] = [];
        assert_eq!(compose_datagram(&mut empty), Err(Error::Empty));
        let mut weird = [0x30u8; 40];
        assert_eq!(
            compose_datagram(&mut weird),
            Err(Error::UnknownIpVersion(3))
        );

        // IHL below the minimum (4 words -> 16 bytes).
        let mut ihl4 = rfc792_header();
        ihl4[0] = 0x44;
        assert_eq!(
            compose_datagram(&mut ihl4),
            Err(Error::InvalidHeaderLength(16))
        );

        // IHL overruns the buffer.
        let mut ihl15 = [0x4fu8; 24];
        ihl15[8] = 64;
        assert_eq!(
            compose_datagram(&mut ihl15),
            Err(Error::InvalidHeaderLength(60))
        );
    }

    fn valid_cksum(buf: &[u8]) -> bool {
        ones_complement_checksum(buf) == 0
    }

    #[test]
    fn icmp_v4_too_large_shape() {
        let mut orig = [0u8; 60];
        orig[0] = 0x45;
        orig[9] = IP_PROTO_ICMP;
        orig[12..16].copy_from_slice(&[192, 168, 0, 1]);
        orig[16..20].copy_from_slice(&[192, 168, 0, 199]);
        let reply = compose_icmp_too_large(&orig, MIN_MTU).unwrap();
        assert_eq!(reply.len(), 20 + 8 + 28);
        assert_eq!(reply[0], 0x45);
        let ip_len = u16::from_be_bytes([reply[2], reply[3]]);
        assert_eq!(usize::from(ip_len), reply.len());
        assert_eq!(reply[8], 64);
        assert_eq!(reply[9], IP_PROTO_ICMP);
        assert_eq!(&reply[12..16], &orig[16..20]);
        assert_eq!(&reply[16..20], &orig[12..16]);
        assert!(valid_cksum(&reply[..20]));
        let icmp = &reply[20..];
        assert_eq!(icmp[0], 3);
        assert_eq!(icmp[1], 4);
        assert_eq!(
            u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]),
            1280
        );
        assert_eq!(&icmp[8..], &orig[..28]);
        assert!(valid_cksum(icmp));
    }

    #[test]
    fn icmp_v4_quote_capped_at_28_bytes() {
        let mut orig = [0u8; 100];
        orig[0] = 0x45;
        orig[16..20].copy_from_slice(&[10, 0, 0, 1]);
        orig[12..16].copy_from_slice(&[10, 0, 0, 2]);
        let reply = compose_icmp_too_large(&orig, MIN_MTU).unwrap();
        assert_eq!(reply.len(), 20 + 8 + 28);
        assert_eq!(&reply[28..], &orig[..28]);
    }

    #[test]
    fn icmp_v6_too_large_shape() {
        let mut orig = [0u8; 60];
        orig[0] = 0x60;
        orig[6] = IP_PROTO_ICMPV6;
        orig[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        orig[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let reply = compose_icmp_too_large(&orig, MIN_MTU).unwrap();
        assert_eq!(reply.len(), 40 + 8 + 60);
        assert_eq!(reply[0], 0x60);
        let payload_len = u16::from_be_bytes([reply[4], reply[5]]);
        assert_eq!(usize::from(payload_len), reply.len() - 40);
        assert_eq!(reply[6], IP_PROTO_ICMPV6);
        assert_eq!(reply[7], 64);
        assert_eq!(&reply[8..24], &orig[24..40]);
        assert_eq!(&reply[24..40], &orig[8..24]);
        let icmp = &reply[40..];
        assert_eq!(icmp[0], 2);
        assert_eq!(icmp[1], 0);
        assert_eq!(
            u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]),
            1280
        );
        assert_eq!(&icmp[8..], &orig[..60]);
        let mut psh = [0u8; 40];
        psh[0..16].copy_from_slice(&orig[24..40]);
        psh[16..32].copy_from_slice(&orig[8..24]);
        psh[32..36].copy_from_slice(&(icmp.len() as u32).to_be_bytes());
        psh[39] = IP_PROTO_ICMPV6;
        let mut check = Vec::with_capacity(40 + icmp.len());
        check.extend_from_slice(&psh);
        check.extend_from_slice(icmp);
        assert!(valid_cksum(&check));
    }

    #[test]
    fn icmp_errors() {
        assert_eq!(compose_icmp_too_large(&[], MIN_MTU), Err(Error::Empty));
        assert_eq!(
            compose_icmp_too_large(&[0x45; 10], MIN_MTU),
            Err(Error::PacketTooShort("IPv4 packet too short"))
        );
        assert_eq!(
            compose_icmp_too_large(&[0x60; 30], MIN_MTU),
            Err(Error::PacketTooShort("IPv6 packet too short"))
        );
        assert_eq!(
            compose_icmp_too_large(&[0x30; 40], MIN_MTU),
            Err(Error::UnknownIpVersion(3))
        );
    }

    #[test]
    fn snapshot_caps_at_min_mtu() {
        let big = vec![0xaa; 2000];
        assert_eq!(snapshot_head(&big).len(), 1280);
        let small = vec![0xaa; 100];
        assert_eq!(snapshot_head(&small).len(), 100);
    }

    #[test]
    fn parse_context_id_strips_varint() {
        let mut buf = vec![0u8];
        buf.extend_from_slice(&[0x45, 0x00]);
        assert_eq!(parse_context_id(&buf).unwrap(), &[0x45, 0x00]);
        assert_eq!(parse_context_id(&[]), Err(Error::Truncated));
        assert_eq!(
            parse_context_id(&[0x40, 0x01]),
            Err(Error::UnsupportedContextId(1))
        );
        // Truncated two-byte varint.
        assert_eq!(parse_context_id(&[0x40]), Err(Error::Truncated));
    }

    #[test]
    fn route_advertisement_roundtrip() {
        let routes = [Route {
            start: v4([0, 0, 0, 0]),
            end: v4([255, 255, 255, 255]),
            proto: 0,
        }];
        let encoded = encode_route_advertisement(&routes);
        assert_eq!(
            encoded,
            vec![0x03, 0x0a, 0x04, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x00]
        );
        let mut rest = encoded.as_slice();
        let (typ, payload) = read_capsule(&mut rest).unwrap();
        assert_eq!(typ, CAPSULE_ROUTE_ADVERTISEMENT);
        assert!(rest.is_empty());
        let parsed = parse_route_advertisement(payload).unwrap();
        assert_eq!(parsed, routes);
    }

    #[test]
    fn address_assign_roundtrip() {
        let addrs = [
            AssignedAddress {
                request_id: 0,
                addr: v4([172, 16, 0, 2]),
                prefix_len: 32,
            },
            AssignedAddress {
                request_id: 1,
                addr: v6([0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                prefix_len: 128,
            },
        ];
        let encoded = encode_address_assign(&addrs);
        let mut rest = encoded.as_slice();
        let (typ, payload) = read_capsule(&mut rest).unwrap();
        assert_eq!(typ, CAPSULE_ADDRESS_ASSIGN);
        assert!(rest.is_empty());
        let parsed = parse_address_assign(payload).unwrap();
        assert_eq!(parsed, addrs);
        // Byte layout: entry1 = [rid 0x00][ver 4][4 bytes][32],
        // entry2 = [rid 0x01][ver 6][16 bytes][128].
        assert_eq!(&encoded[..2], &[0x01, 0x1a]);
        assert_eq!(encoded[2], 0x00);
        assert_eq!(encoded[3], 4);
        assert_eq!(&encoded[4..8], &[172, 16, 0, 2]);
        assert_eq!(encoded[8], 32);
        assert_eq!(encoded[9], 0x01);
        assert_eq!(encoded[10], 6);
        assert_eq!(encoded[27], 128);
    }

    #[test]
    fn address_assign_validates_prefixes() {
        // Prefix length exceeds address length.
        let mut payload = vec![0x00, 4, 172, 16, 0, 2, 33];
        assert_eq!(
            parse_address_assign(&payload),
            Err(Error::BadPrefixLength { bits: 33, max: 32 })
        );
        // Lower bits not covered by the prefix must be zero.
        payload[6] = 24;
        assert_eq!(
            parse_address_assign(&payload),
            Err(Error::NonZeroPrefixBits)
        );
        // Unknown IP version byte.
        payload[1] = 5;
        assert_eq!(
            parse_address_assign(&payload),
            Err(Error::UnknownIpVersion(5))
        );
        // Truncated entries.
        assert_eq!(parse_address_assign(&[0x00]), Err(Error::Truncated));
        assert_eq!(
            parse_address_assign(&[0x00, 4, 1, 2]),
            Err(Error::Truncated)
        );
        assert_eq!(
            parse_address_assign(&[0x00, 4, 1, 2, 3, 4]),
            Err(Error::Truncated)
        );
        assert_eq!(parse_address_assign(&[]).unwrap(), vec![]);
    }

    #[test]
    fn route_advertisement_validates_entries() {
        let payload = [0x04, 0, 0, 0, 2, 0, 0, 0, 1, 0];
        assert_eq!(
            parse_route_advertisement(&payload),
            Err(Error::StartAfterEnd)
        );
        let payload = [0x05, 0, 0, 0, 1, 0, 0, 0, 2, 0];
        assert_eq!(
            parse_route_advertisement(&payload),
            Err(Error::UnknownIpVersion(5))
        );
        assert_eq!(
            parse_route_advertisement(&[0x04, 0, 0, 0]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn read_capsule_header_bounds() {
        let data = [0x03, 0x0a, 0x04, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x00];
        let mut rest = data.as_slice();
        let (typ, payload) = read_capsule(&mut rest).unwrap();
        assert_eq!(typ, 3);
        assert_eq!(payload.len(), 10);

        assert_eq!(read_capsule(&mut &[][..]), Err(Error::Truncated));
        // Length varint missing.
        assert_eq!(read_capsule(&mut &[0x03][..]), Err(Error::Truncated));
        // Declared payload longer than what is present.
        assert_eq!(
            read_capsule(&mut &[0x03, 0x0a, 0x00][..]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn validate_incoming_assigned_destination() {
        let assigned = [Prefix::new(v4([172, 16, 0, 2]), 32)];
        let mut pkt = [0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[172, 16, 0, 2]);
        assert!(validate_incoming(&pkt, &assigned, &[], None).is_ok());
        // Destination outside the assigned prefix falls through to routes.
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            validate_incoming(&pkt, &assigned, &[], None),
            Err(Error::DestinationNotAllowed {
                dst: v4([10, 0, 0, 1]),
                proto: 6
            })
        );
    }

    #[test]
    fn validate_incoming_routes_and_protocol_rules() {
        let routes = [Route {
            start: v4([0, 0, 0, 0]),
            end: v4([255, 255, 255, 255]),
            proto: 6,
        }];
        let mut pkt = [0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // UDP against a TCP-only route: rejected.
        assert!(validate_incoming(&pkt, &[], &routes, None).is_err());
        // ICMP is allowed regardless of route protocol.
        pkt[9] = IP_PROTO_ICMP;
        assert!(validate_incoming(&pkt, &[], &routes, None).is_ok());
        // proto 0 allows everything.
        let routes = [Route {
            start: v4([0, 0, 0, 0]),
            end: v4([255, 255, 255, 255]),
            proto: 0,
        }];
        pkt[9] = 17;
        assert!(validate_incoming(&pkt, &[], &routes, None).is_ok());
        // Destination outside the route range: rejected.
        pkt[16..20].copy_from_slice(&[9, 9, 9, 9]);
        let routes = [Route {
            start: v4([8, 8, 8, 0]),
            end: v4([8, 8, 8, 255]),
            proto: 0,
        }];
        assert_eq!(
            validate_incoming(&pkt, &[], &routes, None),
            Err(Error::DestinationNotAllowed {
                dst: v4([9, 9, 9, 9]),
                proto: 17
            })
        );
    }

    #[test]
    fn validate_incoming_v6_icmp_allowed() {
        let routes = [Route {
            start: v6([0; 16]),
            end: v6([0xff; 16]),
            proto: 6,
        }];
        let mut pkt = [0u8; 48];
        pkt[0] = 0x60;
        pkt[6] = IP_PROTO_ICMPV6;
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(validate_incoming(&pkt, &[], &routes, None).is_ok());
        // UDP (17) against the TCP-only route: rejected.
        pkt[6] = 17;
        assert!(validate_incoming(&pkt, &[], &routes, None).is_err());
    }

    #[test]
    fn validate_incoming_peer_source_check() {
        let peers = [Prefix::new(v4([172, 16, 0, 0]), 24)];
        let mut pkt = [0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 1;
        pkt[12..16].copy_from_slice(&[172, 16, 0, 9]);
        pkt[16..20].copy_from_slice(&[1, 2, 3, 4]);
        let assigned = [Prefix::new(v4([1, 2, 3, 4]), 32)];
        assert!(validate_incoming(&pkt, &assigned, &[], Some(&peers)).is_ok());
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            validate_incoming(&pkt, &assigned, &[], Some(&peers)),
            Err(Error::SourceNotAllowed(v4([10, 0, 0, 1])))
        );
    }

    #[test]
    fn validate_incoming_error_shapes() {
        assert_eq!(validate_incoming(&[], &[], &[], None), Err(Error::Empty));
        let short = [0x45u8; 10];
        assert_eq!(
            validate_incoming(&short, &[], &[], None),
            Err(Error::PacketTooShort("malformed datagram: too short"))
        );
        assert_eq!(
            validate_incoming(&[0x30; 40], &[], &[], None),
            Err(Error::UnknownIpVersion(3))
        );
    }

    #[test]
    fn prefix_contains_matching_and_cross_family() {
        let p = Prefix::new(v4([172, 16, 0, 2]), 32);
        assert!(p.contains(v4([172, 16, 0, 2])));
        assert!(!p.contains(v4([172, 16, 0, 3])));
        assert!(!p.contains(v6([0; 16])));
        let p = Prefix::new(v4([192, 168, 1, 130]), 24);
        assert!(p.contains(v4([192, 168, 1, 1])));
        assert!(p.contains(v4([192, 168, 1, 255])));
        assert!(!p.contains(v4([192, 168, 2, 1])));
        let p = Prefix::new(
            v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            32,
        );
        assert!(p.contains(v6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ])));
        assert!(!p.contains(v6([
            0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ])));
        let p = Prefix::new(v4([10, 0, 0, 0]), 0);
        assert!(p.contains(v4([1, 2, 3, 4])));
    }

    #[test]
    fn ones_complement_checksum_reference_behavior() {
        // Known RFC-style check: checksum field filled so the whole buffer
        // sums to zero.
        let mut buf = rfc792_header();
        let csum = calculate_ipv4_checksum(&buf);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
        assert!(valid_cksum(&buf));
        // Odd-length buffers pad the trailing byte on the right.
        let odd = [0x45u8, 0x00, 0x01];
        assert_eq!(
            ones_complement_checksum(&odd),
            !(0x4500u32.wrapping_add(0x0100) as u16)
        );
    }
}
