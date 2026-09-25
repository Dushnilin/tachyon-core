//! AmneziaWG 2.0 obfuscation parameters: junk packets (jc/jmin/jmax), message
//! paddings (s1–s4), magic-header ranges (h1–h4) and CPS junk chains
//! (i1–i5). Wire semantics ported from the reference device layer
//! (Leadaxe/wireguard-go `device/{magic-header,obf*,noise-protocol,send,
//! receive}.go`, AWG options from sing-box-lx `option/wireguard_awg.go`).
//!
//! AWG 3.x features (header protection, content padding addition, timing
//! overrides, random trailers, masquerade sugar) are detected but rejected
//! explicitly — the runtime must never silently downgrade to plain
//! WireGuard when obfuscation was configured.

use std::sync::Arc;

use anyhow::anyhow;
use serde_json::{Map, Value};

use super::noise::HeaderRange;

pub const AWG_FIELDS: &[&str] = &[
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "id",
    "ip",
    "ib",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
];

const AWG3_FIELDS: &[&str] = &[
    "id",
    "ip",
    "ib",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
];

pub const INIT: usize = 0;
pub const RESPONSE: usize = 1;
pub const COOKIE: usize = 2;
pub const TRANSPORT: usize = 3;

pub const STD_HEADERS: [HeaderRange; 4] = [(1, 1), (2, 2), (3, 3), (4, 4)];

const CHARS52: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS10: &[u8; 10] = b"0123456789";
const MAX_CHAIN_VALUE: u64 = 1 << 20;
const MAX_JUNK_COUNT: u64 = 65_535;

/// One obfuscation primitive from a CPS spec (`<b 0x…>`, `<t>`, `<r N>`,
/// `<rc N>`, `<rd N>`, `<d>`, `<ds>`, `<dz N>`).
#[derive(Debug, Clone)]
pub enum Obf {
    Bytes(Vec<u8>),
    Timestamp,
    Rand(usize),
    RandChar(usize),
    RandDigit(usize),
    Data,
    DataString,
    DataSize(usize),
}

impl Obf {
    fn obfuscated_len(&self, src_len: usize) -> usize {
        match self {
            Obf::Bytes(b) => b.len(),
            Obf::Timestamp => 4,
            Obf::Rand(n) | Obf::RandChar(n) | Obf::RandDigit(n) | Obf::DataSize(n) => *n,
            Obf::Data => src_len,
            // base64.RawStdEncoding.EncodedLen
            Obf::DataString => src_len.div_ceil(3) * 4 - (3 - src_len % 3) % 3,
        }
    }

    fn obfuscate(&self, dst: &mut [u8], src: &[u8]) {
        match self {
            Obf::Bytes(b) => dst[..b.len()].copy_from_slice(b),
            Obf::Timestamp => {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                dst[..4].copy_from_slice(&secs.to_be_bytes());
            }
            Obf::Rand(n) | Obf::RandChar(n) | Obf::RandDigit(n) => {
                fill_random(&mut dst[..*n]);
                if let Obf::RandChar(_) = self {
                    for b in &mut dst[..*n] {
                        *b = CHARS52[*b as usize % 52];
                    }
                } else if let Obf::RandDigit(_) = self {
                    for b in &mut dst[..*n] {
                        *b = DIGITS10[*b as usize % 10];
                    }
                }
            }
            Obf::Data => dst[..src.len()].copy_from_slice(src),
            Obf::DataString => {
                // Raw std base64 of the (empty) source — len 0 for CPS junk.
                let enc = base64_raw_std(src);
                dst[..enc.len()].copy_from_slice(&enc);
            }
            Obf::DataSize(n) => {
                let mut l = src.len() as u64;
                for i in (0..*n).rev() {
                    dst[i] = l as u8;
                    l >>= 8;
                }
            }
        }
    }
}

/// A compiled i1–i5 chain; each tag contributes a sequential chunk.
pub type JunkChain = Vec<Obf>;

pub fn compile_chain(spec: &str, at: &str) -> anyhow::Result<JunkChain> {
    let mut out = Vec::new();
    let mut errs: Vec<String> = Vec::new();
    let mut remaining = spec;
    while let Some(start) = remaining.find('<') {
        let Some(end_rel) = remaining[start..].find('>') else {
            errs.push("missing enclosing >".to_string());
            break;
        };
        let end = start + end_rel;
        let tag = &remaining[start + 1..end];
        let mut parts = tag.split_ascii_whitespace();
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        let built: Result<Obf, String> = match key {
            "b" => decode_hex(val).map(Obf::Bytes),
            "t" => Ok(Obf::Timestamp),
            "r" => parse_len(val).map(Obf::Rand),
            "rc" => parse_len(val).map(Obf::RandChar),
            "rd" => parse_len(val).map(Obf::RandDigit),
            "d" => Ok(Obf::Data),
            "ds" => Ok(Obf::DataString),
            "dz" => parse_len(val).map(Obf::DataSize),
            "" => Err("empty tag".to_string()),
            other => Err(format!("unknown tag <{other}>")),
        };
        match built {
            Ok(o) => out.push(o),
            Err(e) => {
                errs.push(format!("failed to build <{key}>: {e}"));
            }
        }
        remaining = &remaining[end + 1..];
    }
    if !errs.is_empty() {
        return Err(anyhow!("{at}: CPS chain {spec:?}: {}", errs.join("; ")));
    }
    Ok(out)
}

pub fn chain_len(chain: &[Obf]) -> usize {
    chain.iter().map(|o| o.obfuscated_len(0)).sum()
}

pub fn render_chain(chain: &[Obf]) -> Vec<u8> {
    let mut out = vec![0u8; chain_len(chain)];
    let mut written = 0;
    for o in chain {
        let l = o.obfuscated_len(0);
        o.obfuscate(&mut out[written..written + l], &[]);
        written += l;
    }
    out
}

/// AmneziaWG endpoint parameters; `None` when no AWG field is set (plain
/// WireGuard).
#[derive(Debug, Clone)]
pub struct AwgParams {
    pub junk_count: u32,
    pub junk_min: u32,
    pub junk_max: u32,
    /// s1..s4: random junk prepended to init/response/cookie/transport.
    pub paddings: [usize; 4],
    /// h1..h4 magic-header ranges for init/response/cookie/transport.
    pub headers: [HeaderRange; 4],
    /// i1..i5 CPS junk datagrams sent before the handshake initiation.
    pub ipackets: [Option<JunkChain>; 5],
}

impl AwgParams {
    pub fn header(&self, kind: usize) -> HeaderRange {
        self.headers[kind]
    }

    pub fn padding(&self, kind: usize) -> usize {
        self.paddings[kind]
    }

    pub fn from_obj(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Option<Self>> {
        if !AWG_FIELDS.iter().any(|f| awg_field_present(obj.get(*f))) {
            return Ok(None);
        }
        for f in AWG3_FIELDS {
            if awg_field_present(obj.get(*f)) {
                return Err(anyhow!(
                    "{at}: AmneziaWG 3.x field `{f}` is not implemented yet"
                ));
            }
        }
        let junk_count = uint_field(obj, "jc", 0, at)?;
        let junk_min = uint_field(obj, "jmin", 0, at)?;
        let junk_max = uint_field(obj, "jmax", 0, at)?;
        if junk_count > MAX_JUNK_COUNT {
            return Err(anyhow!("{at}: jc must be <= {MAX_JUNK_COUNT}"));
        }
        let (junk_min, junk_max) = (junk_min.min(junk_max), junk_min.max(junk_max));
        let mut paddings = [0usize; 4];
        for (i, slot) in paddings.iter_mut().enumerate() {
            let v = uint_field(obj, &format!("s{}", i + 1), 0, at)?;
            if v > MAX_CHAIN_VALUE {
                return Err(anyhow!("{at}: s{} must be <= {MAX_CHAIN_VALUE}", i + 1));
            }
            *slot = v as usize;
        }
        let mut headers = STD_HEADERS;
        for (i, slot) in headers.iter_mut().enumerate() {
            *slot = header_range(obj, &format!("h{}", i + 1), (i + 1) as u32, at)?;
        }
        let mut ipackets: [Option<JunkChain>; 5] = [None, None, None, None, None];
        for (i, slot) in ipackets.iter_mut().enumerate() {
            match obj.get(&format!("i{}", i + 1)) {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) if s.trim().is_empty() => {}
                Some(Value::String(s)) => *slot = Some(compile_chain(s, at)?),
                Some(_) => return Err(anyhow!("{at}: i{} must be a string", i + 1)),
            }
        }
        Ok(Some(Self {
            junk_count: junk_count as u32,
            junk_min: junk_min as u32,
            junk_max: junk_max as u32,
            paddings,
            headers,
            ipackets,
        }))
    }
}

pub fn awg_field_present(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|v| v != 0.0),
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Bool(b)) => *b,
        Some(_) => true,
    }
}

/// `normalizeAWGRange` from sing-box-lx `option/wireguard_awg.go`: `"N"`,
/// `"N-M"`, JSON number, or unset (0 / "" / null → default).
fn header_range(
    obj: &Map<String, Value>,
    key: &str,
    default: u32,
    at: &str,
) -> anyhow::Result<HeaderRange> {
    let Some(v) = obj.get(key) else {
        return Ok((default, default));
    };
    let spec: Option<String> = match v {
        Value::Null => None,
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= u32::MAX as u64 => {
                if x == 0 {
                    None
                } else {
                    Some(x.to_string())
                }
            }
            _ => return Err(anyhow!("{at}.{key}: invalid range {n}: expected uint32")),
        },
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        other => {
            return Err(anyhow!(
                "{at}.{key}: invalid range {other}: expected uint32 or \"min-max\" string"
            ));
        }
    };
    let Some(spec) = spec else {
        return Ok((default, default));
    };
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() > 2 {
        return Err(anyhow!(
            "{at}.{key}: invalid range {spec:?}: expected uint32 or \"min-max\""
        ));
    }
    let start = parse_u32(parts[0].trim())
        .ok_or_else(|| anyhow!("{at}.{key}: invalid range {spec:?}: parse {:?}", parts[0]))?;
    let end = if parts.len() == 2 {
        parse_u32(parts[1].trim())
            .ok_or_else(|| anyhow!("{at}.{key}: invalid range {spec:?}: parse {:?}", parts[1]))?
    } else {
        start
    };
    if end < start {
        return Err(anyhow!(
            "{at}.{key}: invalid range {spec:?}: range start > end"
        ));
    }
    if end == 0 {
        return Ok((default, default));
    }
    Ok((start, end))
}

fn uint_field(obj: &Map<String, Value>, key: &str, default: u64, at: &str) -> anyhow::Result<u64> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|v| v.min(u32::MAX as u64))
            .ok_or_else(|| anyhow!("{at}.{key}: must be a non-negative integer <= {}", u32::MAX)),
        Some(_) => Err(anyhow!("{at}.{key}: must be a non-negative integer")),
    }
}

fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_len(val: &str) -> Result<usize, String> {
    if val.is_empty() {
        return Err("empty argument".to_string());
    }
    let n: u64 = val
        .parse()
        .map_err(|_| format!("failed to parse {val:?}"))?;
    if n > MAX_CHAIN_VALUE {
        return Err(format!("{n} exceeds the supported size"));
    }
    Ok(n as usize)
}

fn decode_hex(val: &str) -> Result<Vec<u8>, String> {
    let val = val.trim().trim_start_matches("0x");
    if val.is_empty() {
        return Err("empty argument".to_string());
    }
    if !val.len().is_multiple_of(2) {
        return Err("odd amount of symbols".to_string());
    }
    let bytes = val.as_bytes();
    let mut out = Vec::with_capacity(val.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or("invalid hex")?;
        let lo = (pair[1] as char).to_digit(16).ok_or("invalid hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub(crate) fn fill_random(buf: &mut [u8]) {
    use getrandom::fill as gr_fill;
    gr_fill(buf).expect("getrandom");
}

/// Junk size in `jmin..=jmax` (inclusive), mirroring `magicHeader.Generate`.
pub fn junk_size(min: u32, max: u32) -> usize {
    if max <= min {
        return min as usize;
    }
    let span = (max - min + 1) as u64;
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    (min as u64 + u64::from_le_bytes(buf) % span) as usize
}

fn base64_raw_std(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63]);
        out.push(ALPHABET[(n >> 12) as usize & 63]);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63]);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63]);
        }
    }
    out
}

/// Port of `Device.DeterminePacketTypeAndPadding` (Leadaxe/wireguard-go
/// `device/receive.go`): find the message kind by exact size, s-padding and
/// magic-header range; returns `(kind, padding)`. Plain WireGuard: paddings
/// are 0 and ranges are the standard 1–4.
pub fn demux(awg: Option<&AwgParams>, buf: &[u8]) -> Option<(u8, usize)> {
    let table = [
        (
            super::noise::MSG_INITIATION,
            super::noise::INITIATION_LEN,
            true,
            INIT,
        ),
        (
            super::noise::MSG_RESPONSE,
            super::noise::RESPONSE_LEN,
            true,
            RESPONSE,
        ),
        (
            super::noise::MSG_COOKIE_REPLY,
            super::noise::COOKIE_REPLY_LEN,
            true,
            COOKIE,
        ),
        (super::noise::MSG_TRANSPORT, 16, false, TRANSPORT),
    ];
    for (kind, base_len, exact, idx) in table {
        let pad = awg.map(|a| a.padding(idx)).unwrap_or(0);
        let (lo, hi) = awg.map(|a| a.header(idx)).unwrap_or(STD_HEADERS[idx]);
        let ok = if exact {
            buf.len() == pad + base_len
        } else {
            buf.len() >= pad + base_len
        };
        if !ok {
            continue;
        }
        let Some(word) = super::noise::type_word(&buf[pad..]) else {
            continue;
        };
        if word >= lo && word <= hi {
            return Some((kind, pad));
        }
    }
    None
}

/// Shared AWG params across stack tasks.
pub type SharedParams = Arc<AwgParams>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(entries: &[(&str, Value)]) -> Map<String, Value> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn chain_parse_and_render() {
        let chain = compile_chain("<b 0xdeadbeef><r 4><t>", "x").expect("chain");
        assert_eq!(chain_len(&chain), 4 + 4 + 4);
        let out = render_chain(&chain);
        assert_eq!(&out[..4], &[0xde, 0xad, 0xbe, 0xef]);
        // timestamp block decodes to a sane unix time
        let ts = u32::from_be_bytes(out[8..12].try_into().unwrap());
        assert!(ts > 1_700_000_000);
    }

    #[test]
    fn chain_tag_kinds() {
        let chain = compile_chain("<rc 6><rd 5><dz 3><ds><d>", "x").expect("chain");
        assert_eq!(chain_len(&chain), 6 + 5 + 3);
        let out = render_chain(&chain);
        assert!(out[..6].iter().all(|b| CHARS52.contains(b)));
        assert!(out[6..11].iter().all(|b| DIGITS10.contains(b)));
        assert_eq!(&out[11..14], &[0, 0, 0]);
        assert!(compile_chain("<b 0xde><q 4>", "x").is_err());
        assert!(compile_chain("<b 0xabc>", "x").is_err());
        assert!(compile_chain("no tags", "x").is_ok());
    }

    #[test]
    fn header_range_forms() {
        let o = obj(&[
            ("h1", json!(43613244)),
            ("h2", json!("43613244-384550127")),
            ("h3", json!(0)),
            ("h4", json!("3")),
        ]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        assert_eq!(a.header(INIT), (43613244, 43613244));
        assert_eq!(a.header(RESPONSE), (43613244, 384550127));
        assert_eq!(a.header(COOKIE), (3, 3));
        assert_eq!(a.header(TRANSPORT), (3, 3));
    }

    #[test]
    fn awg3_fields_rejected() {
        let o = obj(&[("jc", json!(3)), ("header_protection_key", json!("abc"))]);
        let err = AwgParams::from_obj(&o, "x").expect_err("rejected");
        assert!(err.to_string().contains("header_protection_key"));
    }

    #[test]
    fn plain_endpoint_is_none() {
        let o = obj(&[("private_key", json!("abc"))]);
        assert!(AwgParams::from_obj(&o, "x").expect("ok").is_none());
    }

    #[test]
    fn demux_plain_and_awg() {
        // plain transport packet, type word = [4,0,0,0]
        let mut pkt = vec![4, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xaa];
        assert_eq!(demux(None, &pkt), Some((4, 0)));
        pkt[0] = 9;
        assert_eq!(demux(None, &pkt), None);

        // AWG: s1=10 padding + h1 in 100..=200, init is 148 bytes
        let o = obj(&[("s1", json!(10)), ("h1", json!("100-200"))]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        let mut init = vec![0u8; 10 + 148];
        init[..10].fill(0xEE);
        init[10..14].copy_from_slice(&150u32.to_le_bytes());
        assert_eq!(demux(Some(&a), &init), Some((1, 10)));
        init[10..14].copy_from_slice(&250u32.to_le_bytes());
        assert_eq!(demux(Some(&a), &init), None);
        // wrong size (standard 148) must not match when padding is set
        init.truncate(148);
        assert_eq!(demux(Some(&a), &init), None);
    }

    #[test]
    fn junk_size_bounds() {
        for _ in 0..100 {
            let n = junk_size(60, 120);
            assert!((60..=120).contains(&n));
        }
        assert_eq!(junk_size(5, 5), 5);
    }
}
