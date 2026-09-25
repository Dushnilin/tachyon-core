//! QPACK (RFC 9204) field section codec for the MASQUE HTTP/3 leg.
//!
//! Static-only: the client never advertises dynamic table capacity
//! (SETTINGS_QPACK_MAX_TABLE_CAPACITY defaults to 0), so conformant
//! servers send Required Insert Count = 0 sections with static or
//! literal references. Dynamic representations are rejected.

use super::hpack::{Field, HpackError, read_int_from, read_string, write_int, write_string};
use super::static_tables::QPACK_STATIC;

/// Field section decoding failure (maps to `QPACK_DECOMPRESSION_FAILED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum QpackError {
    Truncated,
    Dynamic,
    BadIndex(u64),
    BadString,
    BadPrefix,
}

impl From<HpackError> for QpackError {
    fn from(e: HpackError) -> Self {
        match e {
            HpackError::Truncated => QpackError::Truncated,
            HpackError::BadHuffman | HpackError::BadString => QpackError::BadString,
            HpackError::IntegerTooLarge => QpackError::BadIndex(0),
            _ => QpackError::BadPrefix,
        }
    }
}

type Result<T> = std::result::Result<T, QpackError>;

/// Encode a field section: Required Insert Count 0, Base 0, static or
/// literal field lines only.
pub(super) fn qpack_encode(fields: &[Field]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for f in fields {
        if let Some(i) = QPACK_STATIC
            .iter()
            .position(|(n, v)| *n == f.name && *v == f.value)
        {
            write_prefixed(&mut out, 0xC0, 6, i as u64);
            continue;
        }
        if let Some(i) = QPACK_STATIC.iter().position(|(n, _)| *n == f.name) {
            write_prefixed(&mut out, 0x50, 4, i as u64);
        } else {
            write_literal_name(&mut out, f.name.as_bytes());
        }
        write_string(&mut out, f.value.as_bytes());
    }
    out
}

/// Decode a field section produced by a capacity-0 encoder.
pub(super) fn qpack_decode(block: &[u8]) -> Result<Vec<Field>> {
    let mut pos = 0usize;
    let first = *block.get(pos).ok_or(QpackError::Truncated)?;
    pos += 1;
    if first != 0 {
        return Err(QpackError::Dynamic);
    }
    let base = *block.get(pos).ok_or(QpackError::Truncated)?;
    pos += 1;
    if base & 0x80 != 0 {
        return Err(QpackError::BadPrefix);
    }

    let mut out = Vec::new();
    while pos < block.len() {
        let b = block[pos];
        pos += 1;
        if b & 0x80 != 0 {
            if b & 0x40 == 0 {
                return Err(QpackError::Dynamic);
            }
            let idx = read_int_from(b & 0x3f, block, &mut pos, 6)?;
            out.push(static_field(idx)?);
        } else if b & 0xc0 == 0x40 {
            if b & 0x10 == 0 {
                return Err(QpackError::Dynamic);
            }
            let idx = read_int_from(b & 0x0f, block, &mut pos, 4)?;
            let name = static_name(idx)?;
            let value = read_string(block, &mut pos)?;
            let value = String::from_utf8(value).map_err(|_| QpackError::BadString)?;
            out.push(Field { name, value });
        } else if b & 0xe0 == 0x20 {
            let huffman = b & 0x08 != 0;
            let len = read_int_from(b & 0x07, block, &mut pos, 3)?;
            let name = read_sliced(block, &mut pos, len as usize, huffman)?;
            let value = read_string(block, &mut pos)?;
            let name = String::from_utf8(name).map_err(|_| QpackError::BadString)?;
            let value = String::from_utf8(value).map_err(|_| QpackError::BadString)?;
            out.push(Field { name, value });
        } else {
            return Err(QpackError::Dynamic);
        }
    }
    Ok(out)
}

fn static_field(idx: u64) -> Result<Field> {
    let (name, value) = QPACK_STATIC
        .get(idx as usize)
        .ok_or(QpackError::BadIndex(idx))?;
    Ok(Field::new(name, value))
}

fn static_name(idx: u64) -> Result<String> {
    let (name, _) = QPACK_STATIC
        .get(idx as usize)
        .ok_or(QpackError::BadIndex(idx))?;
    Ok(name.to_string())
}

fn read_sliced(block: &[u8], pos: &mut usize, len: usize, huffman: bool) -> Result<Vec<u8>> {
    let end = pos.checked_add(len).ok_or(QpackError::BadString)?;
    if end > block.len() {
        return Err(QpackError::Truncated);
    }
    let raw = block[*pos..end].to_vec();
    *pos = end;
    if huffman {
        super::huffman::huffman_decode(&raw).map_err(|_| QpackError::BadString)
    } else {
        Ok(raw)
    }
}

fn write_prefixed(out: &mut Vec<u8>, first_or: u8, prefix: u8, value: u64) {
    let start = out.len();
    write_int(out, prefix, value);
    out[start] |= first_or;
}

fn write_literal_name(out: &mut Vec<u8>, name: &[u8]) {
    let start = out.len();
    write_int(out, 3, name.len() as u64);
    out[start] |= 0x20;
    out.extend_from_slice(name);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fields(pairs: &[(&str, &str)]) -> Vec<Field> {
        pairs.iter().map(|(n, v)| Field::new(n, v)).collect()
    }

    #[test]
    fn b1_literal_name_reference_roundtrip() {
        let block = hex("0000510b2f696e6465782e68746d6c");
        assert_eq!(
            qpack_decode(&block).unwrap(),
            fields(&[(":path", "/index.html")])
        );
        assert_eq!(
            qpack_encode(&fields(&[(":path", "/index.html")])),
            block,
            "RFC 9204 B.1 must be our exact encoding"
        );
    }

    #[test]
    fn indexed_static_fields() {
        assert_eq!(
            qpack_decode(&hex("0000c1")).unwrap(),
            fields(&[(":path", "/")])
        );
        assert_eq!(
            qpack_decode(&hex("0000ff23")).unwrap(),
            fields(&[("x-frame-options", "sameorigin")])
        );
        let block = qpack_encode(&fields(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":status", "200"),
        ]));
        assert_eq!(block, hex("0000cfd7d9"));
        assert_eq!(
            qpack_decode(&block).unwrap(),
            fields(&[
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":status", "200")
            ])
        );
    }

    #[test]
    fn literal_name_reference_with_huffman_value() {
        assert_eq!(
            qpack_decode(&hex("00005f1586a8eb10649cbf")).unwrap(),
            fields(&[("cache-control", "no-cache")])
        );
        assert_eq!(
            qpack_decode(&hex("00002f0125a849e95ba97d7f0c637573746f6d2d76616c7565")).unwrap(),
            fields(&[("custom-key", "custom-value")])
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let input = fields(&[
            (":method", "CONNECT"),
            (":protocol", "cf-connect-ip"),
            (":scheme", "https"),
            (":path", "/.well-known/masque/ip/172.16.0.1/12345/"),
            (":authority", "engage.cloudflareclient.com"),
            ("capsule-protocol", "?1"),
            ("content-type", "application/json"),
        ]);
        let block = qpack_encode(&input);
        assert_eq!(qpack_decode(&block).unwrap(), input);
    }

    #[test]
    fn rejects_dynamic_and_invalid_prefixes() {
        assert_eq!(qpack_decode(&hex("0181")), Err(QpackError::Dynamic));
        assert_eq!(qpack_decode(&hex("000080")), Err(QpackError::Dynamic));
        assert_eq!(qpack_decode(&hex("000010")), Err(QpackError::Dynamic));
        assert_eq!(qpack_decode(&hex("000000")), Err(QpackError::Dynamic));
        assert_eq!(qpack_decode(&hex("0080")), Err(QpackError::BadPrefix));
        assert_eq!(qpack_decode(&hex("00")), Err(QpackError::Truncated));
        assert_eq!(
            qpack_decode(&hex("0000ff63")),
            Err(QpackError::BadIndex(162))
        );
    }
}
