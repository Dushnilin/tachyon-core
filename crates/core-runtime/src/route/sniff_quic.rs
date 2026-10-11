//! Recognize client QUIC v1/v2 Initial packets using packet authentication.
//! Header shape alone is insufficient to distinguish QUIC from arbitrary UDP.

use core_tls::rustls::{
    Side,
    quic::{Suite, Version},
};
use std::sync::OnceLock;

fn varint(packet: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *packet.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = packet.get(*pos..pos.checked_add(len)?)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *pos += len;
    usize::try_from(value).ok()
}

pub(super) fn is_quic_initial(packet: &[u8]) -> bool {
    authenticated_initial(packet).is_some()
}

fn authenticated_initial(packet: &[u8]) -> Option<()> {
    // RFC 9000 section 14.1: client datagrams carrying Initials are >= 1200.
    if packet.len() < 1200 || packet.len() > 65_535 {
        return None;
    }
    let first = *packet.first()?;
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let wire_version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
    let version = match (wire_version, (first >> 4) & 3) {
        (1, 0) => Version::V1,
        (0x6b33_43cf, 1) => Version::V2,
        _ => return None,
    };
    let dcid_len = usize::from(*packet.get(5)?);
    if dcid_len > 20 {
        return None;
    }
    let dcid = packet.get(6..6 + dcid_len)?;
    let mut pos = 6 + dcid_len;
    let scid_len = usize::from(*packet.get(pos)?);
    if scid_len > 20 {
        return None;
    }
    pos += 1;
    packet.get(pos..pos + scid_len)?;
    pos += scid_len;
    let token_len = varint(packet, &mut pos)?;
    pos = pos.checked_add(token_len)?;
    packet.get(..pos)?;
    let length = varint(packet, &mut pos)?;
    let end = pos.checked_add(length)?;
    let protected = packet.get(..end)?;
    static SUITE: OnceLock<Option<Suite>> = OnceLock::new();
    let suite = SUITE
        .get_or_init(|| {
            core_tls::quic::initial_suite_from_provider(&core_tls::quic::configured_provider())
        })
        .as_ref()?;
    let keys = suite.keys(dcid, Side::Server, version);
    let sample_end = pos.checked_add(4 + keys.remote.header.sample_len())?;
    let sample = protected.get(pos + 4..sample_end)?;
    let mut header = protected.get(..pos + 4)?.to_vec();
    let (first, rest) = header.split_at_mut(1);
    keys.remote
        .header
        .decrypt_in_place(sample, &mut first[0], &mut rest[pos - 1..])
        .ok()?;
    if header[0] & 0x0c != 0 {
        return None;
    }
    let pn_len = usize::from((header[0] & 3) + 1);
    let pn = header[pos..pos + pn_len]
        .iter()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    header.truncate(pos + pn_len);
    let mut payload = protected.get(header.len()..)?.to_vec();
    keys.remote
        .packet
        .decrypt_in_place(pn, &header, &mut payload)
        .ok()?;
    Some(())
}
