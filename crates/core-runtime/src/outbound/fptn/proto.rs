//! FPTN wire codec — hand-rolled protobuf for `protocol/protocol.proto`
//! (MIT, fptn-project/fptn). One `Message` per WebSocket binary frame.
//!
//! Field numbers: `Message{protocol_version=1, msg_type=2, error=3,
//! packet=4, ip_addresses=5, batch=6}`, `IPPacket{payload=1}`,
//! `IPAssignment{address_ipv4=1, address_ipv6=2}`,
//! `BatchIPPacket{packets=1}` (each entry is a nested `Message` carrying
//! `MSG_IP_PACKET`). The reference client defaults to its YAFF serializer;
//! the server accepts plain protobuf whenever `X-Serializer` is not `yaff`.

use std::io;

const MSG_ERROR: u64 = 0;
const MSG_IP_PACKET: u64 = 1;
const MSG_IP_ASSIGNMENT: u64 = 2;
const MSG_BATCH_IP_PACKET: u64 = 3;

/// Value written to `protocol_version`; the reference build defines it as 1.
const PROTOCOL_VERSION: u64 = 1;

fn err(msg: &str) -> io::Error {
    io::Error::other(format!("fptn: {msg}"))
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> io::Result<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos).ok_or_else(|| err("truncated varint"))?;
        *pos += 1;
        if shift >= 64 {
            return Err(err("varint too long"));
        }
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
    }
}

fn put_key(out: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

/// `field` (varint) → key byte + value.
fn put_field_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    put_key(out, field, 0);
    put_varint(out, value);
}

fn put_bytes_field(out: &mut Vec<u8>, field: u32, data: &[u8]) {
    put_key(out, field, 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Nested `Message` carrying one raw IP packet as `MSG_IP_PACKET`.
fn encode_inner(payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(payload.len() + 16);
    put_field_varint(&mut inner, 1, PROTOCOL_VERSION);
    put_field_varint(&mut inner, 2, MSG_IP_PACKET);
    let mut packet = Vec::with_capacity(payload.len() + 8);
    put_bytes_field(&mut packet, 1, payload); // IPPacket.payload
    put_bytes_field(&mut inner, 4, &packet); // Message.packet
    inner
}

/// `Message{msg_type=MSG_BATCH_IP_PACKET, batch{packets=[...]}}`.
pub(crate) fn encode_batch(packets: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    if packets.is_empty() {
        return Err(err("empty packet batch"));
    }
    let mut batch = Vec::new();
    for payload in packets {
        put_bytes_field(&mut batch, 1, &encode_inner(payload));
    }
    let mut msg = Vec::with_capacity(batch.len() + 32);
    put_field_varint(&mut msg, 1, PROTOCOL_VERSION);
    put_field_varint(&mut msg, 2, MSG_BATCH_IP_PACKET);
    put_bytes_field(&mut msg, 6, &batch);
    Ok(msg)
}

/// Walk one protobuf message, invoking `f(field, wire, body)` for each entry
/// where `body` covers the value: the varint itself for wire 0 and the length
/// prefixed slice (payload, without the length) for wire 2.
fn for_each_field<'a, F>(mut buf: &'a [u8], mut f: F) -> io::Result<()>
where
    F: FnMut(u32, u8, &'a [u8]) -> io::Result<bool>,
{
    while !buf.is_empty() {
        let mut pos = 0usize;
        let key = read_varint(buf, &mut pos)?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x7) as u8;
        match wire {
            0 => {
                let start = pos;
                read_varint(buf, &mut pos)?;
                if !f(field, wire, &buf[start..pos])? {
                    return Ok(());
                }
                buf = &buf[pos..];
            }
            2 => {
                let len = read_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len).ok_or_else(|| err("length overflow"))?;
                if end > buf.len() {
                    return Err(err("truncated bytes field"));
                }
                if !f(field, wire, &buf[pos..end])? {
                    return Ok(());
                }
                buf = &buf[end..];
            }
            // Fixed32/fixed64 (wire 5/1) never appear in this schema; skip them
            // defensively so unknown fields do not break the parse.
            5 => {
                if buf.len() < pos + 4 {
                    return Err(err("truncated fixed32"));
                }
                if !f(field, wire, &buf[pos..pos + 4])? {
                    return Ok(());
                }
                buf = &buf[pos + 4..];
            }
            1 => {
                if buf.len() < pos + 8 {
                    return Err(err("truncated fixed64"));
                }
                if !f(field, wire, &buf[pos..pos + 8])? {
                    return Ok(());
                }
                buf = &buf[pos + 8..];
            }
            other => return Err(err(&format!("unsupported wire type {other}"))),
        }
    }
    Ok(())
}

fn decode_varint_bytes(body: &[u8]) -> io::Result<u64> {
    let mut pos = 0;
    let v = read_varint(body, &mut pos)?;
    if pos != body.len() {
        return Err(err("bad varint field"));
    }
    Ok(v)
}

/// `Message{msg_type=MSG_BATCH_IP_PACKET}` → the raw IP payloads, in order.
pub(crate) fn decode_batch(buf: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut msg_type = None;
    let mut error_msg: Option<String> = None;
    let mut batch: Option<&[u8]> = None;
    let mut packet: Option<&[u8]> = None;
    for_each_field(buf, |field, wire, body| {
        match (field, wire) {
            (2, 0) => msg_type = Some(decode_varint_bytes(body)?),
            (3, 2) if error_msg.is_none() => {
                error_msg = Some(extract_error_message(body).unwrap_or_default());
            }
            (4, 2) => packet = Some(body),
            (6, 2) => batch = Some(body),
            _ => {}
        }
        Ok(true)
    })?;
    if msg_type == Some(MSG_ERROR) {
        return Err(err(&format!(
            "server error: {}",
            error_msg.unwrap_or_else(|| "unknown".into())
        )));
    }
    if msg_type == Some(MSG_IP_ASSIGNMENT) {
        // The server may repeat the assignment after the handshake; the
        // reference `RunReader` silently drops non-batch messages, and
        // `FptnConn::read_packet` skips empty results the same way.
        return Ok(Vec::new());
    }
    // Single-packet `Message{packet}` is accepted defensively (old servers).
    if batch.is_none()
        && let Some(packet) = packet
    {
        return ippacket_payload(packet).map(|p| vec![p]);
    }
    let batch = batch.ok_or_else(|| err("message has no batch"))?;
    if msg_type != Some(MSG_BATCH_IP_PACKET) {
        return Err(err("unexpected message type"));
    }
    let mut out = Vec::new();
    for_each_field(batch, |field, wire, body| {
        if field == 1
            && wire == 2
            && let Ok(mut entries) = extract_payload(body)
        {
            out.append(&mut entries);
        }
        Ok(true)
    })?;
    Ok(out)
}

/// Nested `Message{packet{payload}}` → the raw IP packet bytes.
fn extract_payload(inner: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for_each_field(inner, |field, wire, body| {
        if field == 4 && wire == 2 {
            out.push(ippacket_payload(body)?);
        }
        Ok(true)
    })?;
    Ok(out)
}

/// `IPPacket{payload=1}` → the raw IP packet bytes.
fn ippacket_payload(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut payload = None;
    for_each_field(body, |field, wire, b| {
        if field == 1 && wire == 2 {
            payload = Some(b.to_vec());
        }
        Ok(payload.is_none())
    })?;
    payload.ok_or_else(|| err("packet has no payload"))
}

/// Nested `ErrorMessage{error_type, error_msg}` → the human-readable part.
fn extract_error_message(body: &[u8]) -> Option<String> {
    let mut msg = None;
    for_each_field(body, |field, wire, b| {
        if field == 2 && wire == 2 {
            msg = Some(String::from_utf8_lossy(b).into_owned());
        }
        Ok(true)
    })
    .ok()?;
    msg
}

/// `Message{msg_type=MSG_IP_ASSIGNMENT, ip_addresses{...}}` → (v4, v6).
/// Both addresses must be non-empty, exactly like the reference client.
pub(crate) fn decode_ip_assignment(buf: &[u8]) -> io::Result<(String, String)> {
    let mut msg_type = None;
    let mut assignment: Option<&[u8]> = None;
    for_each_field(buf, |field, wire, body| {
        match (field, wire) {
            (2, 0) => msg_type = Some(decode_varint_bytes(body)?),
            (5, 2) => assignment = Some(body),
            _ => {}
        }
        Ok(true)
    })?;
    if msg_type != Some(MSG_IP_ASSIGNMENT) {
        return Err(err("expected MSG_IP_ASSIGNMENT"));
    }
    let assignment = assignment.ok_or_else(|| err("message has no ip_addresses"))?;
    let mut v4 = None;
    let mut v6 = None;
    for_each_field(assignment, |field, wire, body| {
        match (field, wire) {
            (1, 2) => v4 = Some(String::from_utf8_lossy(body).into_owned()),
            (2, 2) => v6 = Some(String::from_utf8_lossy(body).into_owned()),
            _ => {}
        }
        Ok(true)
    })?;
    let v4 = v4.unwrap_or_default();
    let v6 = v6.unwrap_or_default();
    if v4.is_empty() || v6.is_empty() {
        return Err(err("IPv4 or IPv6 address is empty"));
    }
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, u64::MAX] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos).unwrap(), v);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn batch_roundtrip() {
        let packets = vec![b"pkt-one".to_vec(), vec![0x45; 60], b"\x60\x00".to_vec()];
        let wire = encode_batch(&packets).unwrap();
        let got = decode_batch(&wire).unwrap();
        assert_eq!(got, packets);
    }

    /// A full reference batch window (`kMaxBatchSize = 32`) round-trips in
    /// one message — the shape `flush_leg` now produces.
    #[test]
    fn batch_roundtrip_full_window() {
        let packets: Vec<Vec<u8>> = (0..32).map(|i| vec![0x45; 20 + i]).collect();
        let wire = encode_batch(&packets).unwrap();
        assert_eq!(decode_batch(&wire).unwrap(), packets);
    }

    #[test]
    fn batch_rejects_error_message() {
        // Message{protocol_version=1, msg_type=MSG_ERROR, error{error_msg}}.
        let mut error = Vec::new();
        put_bytes_field(&mut error, 2, b"session expired");
        let mut msg = Vec::new();
        put_field_varint(&mut msg, 1, PROTOCOL_VERSION);
        put_field_varint(&mut msg, 2, MSG_ERROR);
        put_bytes_field(&mut msg, 3, &error);
        let e = decode_batch(&msg).unwrap_err();
        assert!(e.to_string().contains("session expired"), "{e}");
    }

    #[test]
    fn batch_ignores_repeated_assignment() {
        // The server repeats the assignment after the handshake; the reader
        // must skip it, matching the reference RunReader's silent ignore.
        let mut assignment = Vec::new();
        put_bytes_field(&mut assignment, 1, b"172.16.0.2");
        put_bytes_field(&mut assignment, 2, b"fd00::2");
        let mut msg = Vec::new();
        put_field_varint(&mut msg, 1, PROTOCOL_VERSION);
        put_field_varint(&mut msg, 2, MSG_IP_ASSIGNMENT);
        put_bytes_field(&mut msg, 5, &assignment);
        assert!(decode_batch(&msg).unwrap().is_empty());
    }

    #[test]
    fn ip_assignment_roundtrip() {
        let mut assignment = Vec::new();
        put_bytes_field(&mut assignment, 1, b"172.16.0.2");
        put_bytes_field(&mut assignment, 2, b"fd00::2");
        let mut msg = Vec::new();
        put_field_varint(&mut msg, 1, PROTOCOL_VERSION);
        put_field_varint(&mut msg, 2, MSG_IP_ASSIGNMENT);
        put_bytes_field(&mut msg, 5, &assignment);
        assert_eq!(
            decode_ip_assignment(&msg).unwrap(),
            ("172.16.0.2".to_string(), "fd00::2".to_string())
        );
    }

    #[test]
    fn ip_assignment_requires_both_addresses() {
        let mut assignment = Vec::new();
        put_bytes_field(&mut assignment, 1, b"172.16.0.2");
        let mut msg = Vec::new();
        put_key(&mut msg, 2, 0);
        put_varint(&mut msg, MSG_IP_ASSIGNMENT);
        put_bytes_field(&mut msg, 5, &assignment);
        assert!(decode_ip_assignment(&msg).is_err());
    }
}
