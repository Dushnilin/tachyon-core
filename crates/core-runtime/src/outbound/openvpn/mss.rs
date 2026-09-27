//! OpenVPN MSS clamp — port of sing-openvpn `mss_clamp.go` + the
//! `calculateDataPayloadBudget` / `calculateMSSClamp` helpers from
//! `client_data.go` / `mss_budget.go`.
//!
//! Upstream gates `mss_fixup` on the `--mssfix` option value and casts the
//! signed budget to `uint16_t`; the IPv6 path subtracts `40 - 20` so the cap
//! is always expressed as an IPv4 MSS.

const IPV4_HEADER_MIN_LENGTH: usize = 20;
const IPV6_HEADER_LENGTH: usize = 40;
const IP_PROTOCOL_TCP: u8 = 6;
const TCP_HEADER_MIN_LENGTH: usize = 20;
const TCP_CHECKSUM_OFFSET: usize = 16;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_OPTION_KIND_END: u8 = 0;
const TCP_OPTION_KIND_NOP: u8 = 1;
const TCP_OPTION_KIND_MSS: u8 = 2;
const TCP_MSS_OPTION_LENGTH: usize = 4;

pub const MSS_FIX_MODE_MTU: &str = "mtu";
pub const MSS_FIX_MODE_FIXED: &str = "fixed";
pub const DEFAULT_MSS_FIX: u32 = 1492;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MssClamp {
    pub enabled: bool,
    pub maximum_segment_size: u16,
}

impl MssClamp {
    /// In-place clamp; returns `true` when an MSS option was rewritten.
    pub fn apply_in_place(&self, packet: &mut [u8]) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(first) = packet.first().copied() else {
            return false;
        };
        let mut effective = self.maximum_segment_size;
        if first >> 4 == 6 {
            effective =
                effective.wrapping_sub((IPV6_HEADER_LENGTH - IPV4_HEADER_MIN_LENGTH) as u16);
        }
        let Some(tcp_offset) = locate_tcp_syn_segment(packet) else {
            return false;
        };
        clamp_tcp_syn_segment_mss(&mut packet[tcp_offset..], effective)
    }
}

/// `locateTCPSYNSegment`: validated (unfragmented, full-length) TCP SYN only.
fn locate_tcp_syn_segment(packet: &[u8]) -> Option<usize> {
    if packet.is_empty() {
        return None;
    }
    let ip_header_length = match packet[0] >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER_MIN_LENGTH {
                return None;
            }
            if u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
                || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
            {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < IPV4_HEADER_MIN_LENGTH || ihl > packet.len() {
                return None;
            }
            if packet[9] != IP_PROTOCOL_TCP {
                return None;
            }
            ihl
        }
        6 => {
            if packet.len() < IPV6_HEADER_LENGTH {
                return None;
            }
            if u16::from_be_bytes([packet[4], packet[5]]) as usize + IPV6_HEADER_LENGTH
                != packet.len()
            {
                return None;
            }
            if packet[6] != IP_PROTOCOL_TCP {
                return None;
            }
            IPV6_HEADER_LENGTH
        }
        _ => return None,
    };
    if packet.len() <= ip_header_length {
        return None;
    }
    let tcp_segment = &packet[ip_header_length..];
    if tcp_segment.len() < TCP_HEADER_MIN_LENGTH {
        return None;
    }
    if tcp_segment[13] & TCP_FLAG_SYN == 0 {
        return None;
    }
    Some(ip_header_length)
}

/// `clampTCPSYNSegmentMSS`: rewrite the MSS option when it advertises more.
fn clamp_tcp_syn_segment_mss(tcp_segment: &mut [u8], maximum_segment_size: u16) -> bool {
    let data_offset = (tcp_segment[12] >> 4) as usize * 4;
    if data_offset < TCP_HEADER_MIN_LENGTH || data_offset > tcp_segment.len() {
        return false;
    }
    let mut clamped = false;
    let mut option_offset = TCP_HEADER_MIN_LENGTH;
    while option_offset < data_offset {
        let kind = tcp_segment[option_offset];
        if kind == TCP_OPTION_KIND_END {
            break;
        }
        if kind == TCP_OPTION_KIND_NOP {
            option_offset += 1;
            continue;
        }
        if option_offset + 1 >= data_offset {
            break;
        }
        let option_length = tcp_segment[option_offset + 1] as usize;
        if option_length < 2 || option_offset + option_length > data_offset {
            break;
        }
        if kind != TCP_OPTION_KIND_MSS || option_length != TCP_MSS_OPTION_LENGTH {
            option_offset += option_length;
            continue;
        }
        let value_offset = option_offset + 2;
        let advertised_mss =
            u16::from_be_bytes([tcp_segment[value_offset], tcp_segment[value_offset + 1]]);
        if advertised_mss > maximum_segment_size {
            tcp_segment[value_offset..value_offset + 2]
                .copy_from_slice(&maximum_segment_size.to_be_bytes());
            update_tcp_checksum_for_field_rewrite(
                tcp_segment,
                value_offset,
                advertised_mss,
                maximum_segment_size,
            );
            clamped = true;
        }
        option_offset += option_length;
    }
    clamped
}

fn update_tcp_checksum_for_field_rewrite(
    tcp_segment: &mut [u8],
    field_offset: usize,
    previous_value: u16,
    updated_value: u16,
) {
    let (mut previous_value, mut updated_value) = (previous_value, updated_value);
    if !field_offset.is_multiple_of(2) {
        previous_value = previous_value.swap_bytes();
        updated_value = updated_value.swap_bytes();
    }
    let current_checksum = u16::from_be_bytes([
        tcp_segment[TCP_CHECKSUM_OFFSET],
        tcp_segment[TCP_CHECKSUM_OFFSET + 1],
    ]);
    let updated_checksum =
        incrementally_update_checksum16(current_checksum, previous_value, updated_value);
    tcp_segment[TCP_CHECKSUM_OFFSET..TCP_CHECKSUM_OFFSET + 2]
        .copy_from_slice(&updated_checksum.to_be_bytes());
}

fn incrementally_update_checksum16(current_checksum: u16, old_word: u16, new_word: u16) -> u16 {
    let mut sum = u32::from(!current_checksum) + u32::from(!old_word) + u32::from(new_word);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// `calculateDataPayloadBudget`: largest payload whose encoded size fits.
///
/// `encoded_len(payload_len)` mirrors `dataCodec.EncodedLength`. Go returns a
/// signed budget (negative when even the fixed header does not fit) which is
/// then cast to `uint16_t` — reproduced with wrapping casts.
pub fn calculate_data_payload_budget(
    packet_size: i64,
    encoded_len: impl Fn(usize) -> usize,
    packet_header_size: i64,
    fixed_payload_size: usize,
) -> i64 {
    let minimum_packet_length = packet_header_size + encoded_len(fixed_payload_size) as i64;
    if minimum_packet_length >= packet_size {
        return packet_size - minimum_packet_length;
    }
    let mut minimum_payload_size: i64 = 1;
    let mut maximum_payload_size: i64 = packet_size;
    while minimum_payload_size < maximum_payload_size {
        let candidate_payload_size =
            minimum_payload_size + (maximum_payload_size - minimum_payload_size + 1) / 2;
        let encoded_packet_length = packet_header_size
            + encoded_len((fixed_payload_size as i64 + candidate_payload_size) as usize) as i64;
        if encoded_packet_length <= packet_size {
            minimum_payload_size = candidate_payload_size;
        } else {
            maximum_payload_size = candidate_payload_size - 1;
        }
    }
    minimum_payload_size
}

/// `calculateMSSClamp`.
pub fn calculate_mss_clamp(
    mss_fix: u32,
    mss_fix_mode: &str,
    framing_payload_overhead: usize,
    encoded_len: impl Fn(usize) -> usize,
    packet_header_size: usize,
    outer_transport_overhead: usize,
) -> MssClamp {
    if mss_fix == 0 {
        return MssClamp::default();
    }
    if mss_fix_mode == MSS_FIX_MODE_FIXED {
        return MssClamp {
            enabled: true,
            maximum_segment_size: mss_fix
                .wrapping_sub((IPV4_HEADER_MIN_LENGTH + TCP_HEADER_MIN_LENGTH) as u32)
                as u16,
        };
    }
    let mut packet_header_size = packet_header_size as i64;
    if mss_fix_mode == MSS_FIX_MODE_MTU {
        packet_header_size += outer_transport_overhead as i64;
    }
    let payload_budget = calculate_data_payload_budget(
        i64::from(mss_fix),
        encoded_len,
        packet_header_size,
        IPV4_HEADER_MIN_LENGTH + TCP_HEADER_MIN_LENGTH + framing_payload_overhead,
    );
    MssClamp {
        enabled: true,
        maximum_segment_size: payload_budget as u16,
    }
}

/// `openVPNOuterTransportOverhead`: IP + TCP/UDP header of the outer tunnel.
pub fn outer_transport_overhead(protocol: &str, remote_is_ipv6: bool) -> usize {
    let ip_header_size = if remote_is_ipv6 {
        IPV6_HEADER_LENGTH
    } else {
        IPV4_HEADER_MIN_LENGTH
    };
    if protocol.starts_with("tcp") {
        ip_header_size + TCP_HEADER_MIN_LENGTH
    } else {
        ip_header_size + 8
    }
}

/// `dataTransportHeaderSize`: framing bytes accounted in budget math only.
pub fn transport_header_size(protocol: &str) -> usize {
    if protocol.starts_with("tcp") { 2 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_rewrites_larger_mss_ipv4() {
        // Build a correct v4+TCP SYN with MSS=1460, 24-byte TCP header.
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[3] = 44; // total length
        pkt[9] = 6;
        pkt[12] = 192;
        pkt[16] = 10;
        // tcp at 20
        pkt[32] = 0x60; // data offset 6 (24 bytes)
        pkt[33] = 0x02; // SYN
        pkt[40] = 0x02; // MSS kind
        pkt[41] = 0x04; // len
        pkt[42] = 0x05;
        pkt[43] = 0xb4; // 1460
        let mut clamp = MssClamp {
            enabled: true,
            maximum_segment_size: 1400,
        };
        assert!(clamp.apply_in_place(&mut pkt));
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1400);
        // second apply: advertised == cap → no rewrite
        clamp.maximum_segment_size = 1400;
        assert!(!clamp.apply_in_place(&mut pkt));
    }

    #[test]
    fn clamp_skips_non_syn_and_disabled() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[3] = 44;
        pkt[9] = 6;
        pkt[32] = 0x60;
        pkt[33] = 0x10; // ACK only
        let clamp = MssClamp {
            enabled: true,
            maximum_segment_size: 1000,
        };
        assert!(!clamp.apply_in_place(&mut pkt));
        let off = MssClamp::default();
        assert!(!off.apply_in_place(&mut pkt));
    }

    #[test]
    fn clamp_ipv6_subtracts_twenty() {
        let mut pkt = vec![0u8; 64];
        pkt[0] = 0x60; // v6
        pkt[4] = 0;
        pkt[5] = 24; // payload len 24 (tcp 24)
        pkt[6] = 6; // next header tcp
        pkt[40 + 12] = 0x60; // data offset 6
        pkt[40 + 13] = 0x02; // SYN
        pkt[40 + 20] = 0x02;
        pkt[40 + 21] = 0x04;
        pkt[40 + 22] = 0x05;
        pkt[40 + 23] = 0xb4; // 1460
        let clamp = MssClamp {
            enabled: true,
            maximum_segment_size: 1400,
        };
        assert!(clamp.apply_in_place(&mut pkt));
        // IPv6 effective cap = 1400 - 20 = 1380
        assert_eq!(u16::from_be_bytes([pkt[62], pkt[63]]), 1380);
    }

    #[test]
    fn budget_matches_reference_shapes() {
        // Identity codec: encoded_len(n) = n + 8 + 20 + 16 (hmac+iv style flat).
        let encoded = |n: usize| n + 44;
        // fixed = 40, header = 0, packet = 1492 → budget = 1492 - (40+44) = 1408
        assert_eq!(calculate_data_payload_budget(1492, encoded, 0, 40), 1408);
        // when the fixed part alone overflows: negative signed budget
        assert_eq!(calculate_data_payload_budget(10, encoded, 0, 40), -74);
    }

    #[test]
    fn mss_clamp_modes() {
        let encoded = |n: usize| n + 44;
        // fixed mode: 1492 - 40 = 1452
        let fixed = calculate_mss_clamp(1492, MSS_FIX_MODE_FIXED, 0, encoded, 0, 0);
        assert_eq!(
            fixed,
            MssClamp {
                enabled: true,
                maximum_segment_size: 1452
            }
        );
        // disabled by zero
        assert_eq!(
            calculate_mss_clamp(0, MSS_FIX_MODE_MTU, 0, encoded, 0, 0),
            MssClamp::default()
        );
        // mtu mode: header 0 + outer udp4 (28) ; fixed=40+0
        let mtu = calculate_mss_clamp(1492, MSS_FIX_MODE_MTU, 0, encoded, 0, 28);
        // budget: binary search payload s.t. 28 + (40+s+44) <= 1492 → s = 1380
        assert_eq!(mtu.maximum_segment_size, 1380);
        // no mode string (explicit mss_fix, mode ""): header stays unchanged
        let bare = calculate_mss_clamp(1492, "", 0, encoded, 0, 28);
        assert_eq!(bare.maximum_segment_size, 1408);
    }

    #[test]
    fn outer_overhead_shapes() {
        assert_eq!(outer_transport_overhead("udp", false), 28);
        assert_eq!(outer_transport_overhead("udp4", false), 28);
        assert_eq!(outer_transport_overhead("tcp", false), 40);
        assert_eq!(outer_transport_overhead("udp6", true), 48);
        assert_eq!(outer_transport_overhead("tcp6", true), 60);
        assert_eq!(transport_header_size("udp"), 0);
        assert_eq!(transport_header_size("tcp4"), 2);
    }
}
