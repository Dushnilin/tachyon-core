//! HPACK codec (RFC 7541) for the MASQUE HTTP/2 leg.
//!
//! The decoder implements the full field set including the dynamic table
//! (servers opportunistically insert non-static values, see x/net/hpack
//! `shouldIndex`); the encoder is static-table-only with raw strings.

use std::collections::VecDeque;

use super::huffman::huffman_decode;
use super::static_tables::HPACK_STATIC;

/// A decoded or to-be-encoded header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Field {
    pub name: String,
    pub value: String,
}

impl Field {
    pub(super) fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// Header block decoding failure (maps to HTTP/2 `COMPRESSION_ERROR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HpackError {
    Truncated,
    IndexZero,
    BadIndex(u64),
    BadString,
    BadHuffman,
    TableSizeTooLarge(u64),
    IntegerTooLarge,
}

type Result<T> = std::result::Result<T, HpackError>;

const DEFAULT_MAX_TABLE_SIZE: usize = 4096;

/// Connection-scoped HPACK decoder. Dynamic entry size is `name + value + 32`
/// (RFC 7541 4.1); index 62 addresses the most recently inserted entry.
pub(super) struct HpackDecoder {
    dyn_table: VecDeque<(String, String)>,
    size: usize,
    max_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    pub(super) fn new() -> Self {
        Self::with_max_size(DEFAULT_MAX_TABLE_SIZE)
    }

    pub(super) fn with_max_size(max_size: usize) -> Self {
        Self {
            dyn_table: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    pub(super) fn dynamic_size(&self) -> usize {
        self.size
    }

    pub(super) fn decode(&mut self, block: &[u8]) -> Result<Vec<Field>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                let idx = read_int(block, &mut pos, 7)?;
                out.push(self.indexed(idx)?);
            } else if b & 0x40 != 0 {
                let name = self.literal_name(block, &mut pos, 6)?;
                let value = read_string(block, &mut pos)?;
                let value = String::from_utf8(value).map_err(|_| HpackError::BadString)?;
                self.insert(name.clone(), value.clone());
                out.push(Field { name, value });
            } else if b & 0x20 != 0 {
                let new_max = read_int(block, &mut pos, 5)?;
                if new_max > DEFAULT_MAX_TABLE_SIZE as u64 {
                    return Err(HpackError::TableSizeTooLarge(new_max));
                }
                self.set_max_size(new_max as usize);
            } else {
                let name = self.literal_name(block, &mut pos, 4)?;
                let value = read_string(block, &mut pos)?;
                let value = String::from_utf8(value).map_err(|_| HpackError::BadString)?;
                out.push(Field { name, value });
            }
        }
        Ok(out)
    }

    fn indexed(&self, idx: u64) -> Result<Field> {
        if idx == 0 {
            return Err(HpackError::IndexZero);
        }
        if idx <= HPACK_STATIC.len() as u64 {
            let (name, value) = HPACK_STATIC[idx as usize - 1];
            return Ok(Field::new(name, value));
        }
        self.dyn_field(idx).ok_or(HpackError::BadIndex(idx))
    }

    fn literal_name(&self, block: &[u8], pos: &mut usize, prefix: u8) -> Result<String> {
        let idx = read_int(block, pos, prefix)?;
        if idx == 0 {
            let raw = read_string(block, pos)?;
            return String::from_utf8(raw).map_err(|_| HpackError::BadString);
        }
        if idx <= HPACK_STATIC.len() as u64 {
            return Ok(HPACK_STATIC[idx as usize - 1].0.to_string());
        }
        self.dyn_field(idx)
            .map(|f| f.name)
            .ok_or(HpackError::BadIndex(idx))
    }

    fn dyn_field(&self, idx: u64) -> Option<Field> {
        let pos = (idx - HPACK_STATIC.len() as u64 - 1) as usize;
        self.dyn_table
            .get(pos)
            .map(|(name, value)| Field::new(name, value))
    }

    fn insert(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.max_size {
            self.dyn_table.clear();
            self.size = 0;
            return;
        }
        while self.size + entry_size > self.max_size {
            if let Some((n, v)) = self.dyn_table.pop_back() {
                self.size -= n.len() + v.len() + 32;
            } else {
                break;
            }
        }
        self.dyn_table.push_front((name, value));
        self.size += entry_size;
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        while self.size > self.max_size {
            if let Some((n, v)) = self.dyn_table.pop_back() {
                self.size -= n.len() + v.len() + 32;
            } else {
                break;
            }
        }
    }
}

/// Static-table-only encoder: exact static matches become indexed fields,
/// otherwise literal fields (no dynamic insertion, raw strings).
pub(super) fn hpack_encode(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        if let Some(i) = HPACK_STATIC
            .iter()
            .position(|(n, v)| *n == f.name && *v == f.value)
        {
            out.push(0x80 | (i as u8 + 1));
            continue;
        }
        let name_idx = HPACK_STATIC.iter().position(|(n, _)| *n == f.name);
        match name_idx {
            Some(i) => {
                write_int(&mut out, 4, i as u64 + 1);
            }
            None => {
                out.push(0x00);
                write_string(&mut out, f.name.as_bytes());
            }
        }
        write_string(&mut out, f.value.as_bytes());
    }
    out
}

pub(super) fn read_int(block: &[u8], pos: &mut usize, prefix: u8) -> Result<u64> {
    let first = *block.get(*pos).ok_or(HpackError::Truncated)?;
    *pos += 1;
    let mask = (1u64 << prefix) - 1;
    let mut value = u64::from(first) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let b = *block.get(*pos).ok_or(HpackError::Truncated)?;
        *pos += 1;
        value = value
            .checked_add(u64::from(b & 0x7f) << shift)
            .ok_or(HpackError::IntegerTooLarge)?;
        shift += 7;
        if shift > 56 {
            return Err(HpackError::IntegerTooLarge);
        }
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

pub(super) fn read_string(block: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let first = *block.get(*pos).ok_or(HpackError::Truncated)?;
    *pos += 1;
    let huffman = first & 0x80 != 0;
    let len = read_int_from(first & 0x7f, block, pos, 7)?;
    let len = len as usize;
    let end = pos.checked_add(len).ok_or(HpackError::BadString)?;
    if end > block.len() {
        return Err(HpackError::Truncated);
    }
    let raw = &block[*pos..end];
    *pos = end;
    if huffman {
        huffman_decode(raw).map_err(|_| HpackError::BadHuffman)
    } else {
        Ok(raw.to_vec())
    }
}

pub(super) fn read_int_from(first: u8, block: &[u8], pos: &mut usize, prefix: u8) -> Result<u64> {
    let mask = (1u64 << prefix) - 1;
    let mut value = u64::from(first) & mask;
    if value < mask || prefix == 0 {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let b = *block.get(*pos).ok_or(HpackError::Truncated)?;
        *pos += 1;
        value = value
            .checked_add(u64::from(b & 0x7f) << shift)
            .ok_or(HpackError::IntegerTooLarge)?;
        shift += 7;
        if shift > 56 {
            return Err(HpackError::IntegerTooLarge);
        }
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

pub(super) fn write_int(out: &mut Vec<u8>, prefix: u8, value: u64) {
    let mask = (1u64 << prefix) - 1;
    if value < mask {
        out.push(value as u8);
        return;
    }
    out.push(mask as u8);
    let mut rem = value - mask;
    while rem >= 128 {
        out.push(0x80 | (rem & 0x7f) as u8);
        rem >>= 7;
    }
    out.push(rem as u8);
}

pub(super) fn write_string(out: &mut Vec<u8>, raw: &[u8]) {
    write_int(out, 7, raw.len() as u64);
    out.extend_from_slice(raw);
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
    fn c2_1_literal_with_indexing() {
        let mut d = HpackDecoder::new();
        let got = d
            .decode(&hex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"))
            .unwrap();
        assert_eq!(got, fields(&[("custom-key", "custom-header")]));
        assert_eq!(d.dynamic_size(), 55);
    }

    #[test]
    fn c2_2_literal_without_indexing() {
        let mut d = HpackDecoder::new();
        let got = d.decode(&hex("040c2f73616d706c652f70617468")).unwrap();
        assert_eq!(got, fields(&[(":path", "/sample/path")]));
        assert_eq!(d.dynamic_size(), 0);
    }

    #[test]
    fn c2_3_literal_never_indexed() {
        let mut d = HpackDecoder::new();
        let got = d
            .decode(&hex("100870617373776f726406736563726574"))
            .unwrap();
        assert_eq!(got, fields(&[("password", "secret")]));
        assert_eq!(d.dynamic_size(), 0);
    }

    #[test]
    fn c2_4_indexed_static() {
        let mut d = HpackDecoder::new();
        assert_eq!(d.decode(&hex("82")).unwrap(), fields(&[(":method", "GET")]));
    }

    #[test]
    fn c5_response_chain_with_eviction() {
        let mut d = HpackDecoder::with_max_size(256);

        let first = d
            .decode(&hex("4803333032580770726976617465611d\
             4d6f6e2c203231204f63742032303133\
             2032303a31333a323120474d546e1768\
             747470733a2f2f7777772e6578616d70\
             6c652e636f6d"))
            .unwrap();
        assert_eq!(
            first,
            fields(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(d.dynamic_size(), 222);

        let second = d.decode(&hex("4803333037c1c0bf")).unwrap();
        assert_eq!(
            second,
            fields(&[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(d.dynamic_size(), 222);

        let third = d
            .decode(&hex("88c1611d4d6f6e2c203231204f637420\
             323031332032303a31333a323220474d\
             54c05a04677a69707738666f6f3d4153\
             444a4b48514b425a584f5157454f5049\
             5541585157454f49553b206d61782d61\
             67653d333630303b2076657273696f6e\
             3d31"))
            .unwrap();
        assert_eq!(
            third,
            fields(&[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                (
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
                ),
            ])
        );
        assert_eq!(d.dynamic_size(), 215);
    }

    #[test]
    fn c4_huffman_requests() {
        let mut d = HpackDecoder::new();

        let first = d
            .decode(&hex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
            .unwrap();
        assert_eq!(
            first,
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ])
        );
        assert_eq!(d.dynamic_size(), 57);

        let second = d.decode(&hex("828684be5886a8eb10649cbf")).unwrap();
        assert_eq!(
            second,
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ])
        );
        assert_eq!(d.dynamic_size(), 110);
    }

    #[test]
    fn encode_static_indexed_and_literals() {
        let out = hpack_encode(&fields(&[
            (":scheme", "https"),
            (":method", "CONNECT"),
            (":authority", "1.2.3.4:443"),
            ("capsule-protocol", "?1"),
        ]));
        assert_eq!(
            out,
            vec![0x87] // :scheme https (static 7)
                .into_iter()
                .chain(hex("0207434f4e4e454354")) // :method CONNECT (name idx 2)
                .chain(hex("010b312e322e332e343a343433")) // :authority (name idx 1)
                .chain(hex("001063617073756c652d70726f746f636f6c023f31")) // capsule-protocol
                .collect::<Vec<u8>>()
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
        ]);
        let block = hpack_encode(&input);
        let mut d = HpackDecoder::new();
        assert_eq!(d.decode(&block).unwrap(), input);
        assert_eq!(d.dynamic_size(), 0);
    }

    #[test]
    fn rejects_invalid_indices_and_truncation() {
        let mut d = HpackDecoder::new();
        assert_eq!(d.decode(&hex("80")), Err(HpackError::IndexZero));
        assert_eq!(d.decode(&hex("ff")), Err(HpackError::Truncated));
        assert_eq!(d.decode(&hex("02")), Err(HpackError::Truncated));
        assert_eq!(d.decode(&hex("000161")), Err(HpackError::Truncated));
        assert_eq!(
            d.decode(&hex("3fe21f")),
            Err(HpackError::TableSizeTooLarge(4097))
        );
    }

    #[test]
    fn rejects_bad_huffman_padding() {
        let mut d = HpackDecoder::new();
        assert_eq!(d.decode(&hex("00")), Err(HpackError::Truncated));
        assert_eq!(d.decode(&hex("0083000000")), Err(HpackError::BadHuffman));
    }
}
