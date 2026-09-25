//! AmneziaWG obfuscation parameters: the AWG 2.0 surface (junk packets
//! jc/jmin/jmax, message paddings s1–s4, magic-header ranges h1–h4, CPS junk
//! chains i1–i5) and the AWG 3.x surface (header protection key,
//! content-padding addition, random trailers, disabled cookies, ranged
//! timing overrides). Wire semantics ported from the reference device layer
//! (Leadaxe/wireguard-go branch `lx-awg2-v005`, port of amneziawg-go v3.1;
//! options per sing-box-lx `option/wireguard_awg.go` + SPEC 080).
//!
//! Masquerade sugar (`id`/`ip`/`ib` — declarative I1 generators) is detected
//! and rejected explicitly: it must never silently degrade to plain junk.

use std::sync::Arc;

use anyhow::anyhow;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
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

/// Masquerade profiles are declarative I1 generators (SPEC 009); not
/// implemented — rejected explicitly so obfuscation can't silently change.
const UNSUPPORTED_FIELDS: &[&str] = &["id", "ip", "ib"];

pub const INIT: usize = 0;
pub const RESPONSE: usize = 1;
pub const COOKIE: usize = 2;
pub const TRANSPORT: usize = 3;

pub const STD_HEADERS: [HeaderRange; 4] = [(1, 1), (2, 2), (3, 3), (4, 4)];

/// `DefaultUdpWindow` (reference constants.go): the size of the largest
/// datagram seen on a peer starts at this and only grows.
pub const DEFAULT_UDP_WINDOW: u32 = 500;

const CHARS52: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS10: &[u8; 10] = b"0123456789";
const MAX_CHAIN_VALUE: u64 = 1 << 20;
const MAX_JUNK_COUNT: u64 = 65_535;
const HEADER_NONCE_LEN: usize = 12;

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
    /// AWG 3.x header-protection key (`awg genkey`); masks the whole
    /// handshake message / the 16-byte transport header with a ChaCha20
    /// keystream salted by the first 12 bytes of the datagram.
    pub header_protection: Option<[u8; 32]>,
    /// AWG 3.x: extra zero padding inside the AEAD payload of every data
    /// packet, picked from the range per packet.
    pub content_padding: Option<HeaderRange>,
    /// AWG 3.x timing overrides (seconds), picked per use.
    pub rekey_after_time: Option<HeaderRange>,
    pub rekey_timeout: Option<HeaderRange>,
    pub reject_after_time: Option<HeaderRange>,
    pub keepalive_timeout: Option<HeaderRange>,
    pub max_handshake_attempts: Option<HeaderRange>,
    /// AWG 3.1: random tail on handshake datagrams (and the data-packet
    /// padding when content padding is unset).
    pub random_trailers: bool,
    /// AWG 3.1: never send or honor cookie replies.
    pub disable_cookies: bool,
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
        for f in UNSUPPORTED_FIELDS {
            if awg_field_present(obj.get(*f)) {
                return Err(anyhow!(
                    "{at}: AmneziaWG field `{f}` (masquerade profile) is not implemented yet"
                ));
            }
        }
        let junk_count = uint_field(obj, "jc", 0, at)?;
        let junk_min = uint_field(obj, "jmin", 0, at)?;
        let junk_max = uint_field(obj, "jmax", 0, at)?;
        if junk_count > MAX_JUNK_COUNT {
            return Err(anyhow!("{at}: jc must be <= {MAX_JUNK_COUNT}"));
        }
        if junk_max < junk_min {
            return Err(anyhow!(
                "{at}: amneziawg: jmin ({junk_min}) must be <= jmax ({junk_max})"
            ));
        }
        let mut paddings = [0usize; 4];
        for (i, slot) in paddings.iter_mut().enumerate() {
            let v = uint_field(obj, &format!("s{}", i + 1), 0, at)?;
            if v > MAX_CHAIN_VALUE {
                return Err(anyhow!("{at}: s{} must be <= {MAX_CHAIN_VALUE}", i + 1));
            }
            *slot = v as usize;
        }
        let header_protection = match obj.get("header_protection_key") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.trim().is_empty() => None,
            Some(Value::String(s)) => {
                let key = parse_header_key(s.trim(), at)?;
                for (i, pad) in paddings.iter().enumerate() {
                    if *pad < HEADER_NONCE_LEN {
                        return Err(anyhow!(
                            "{at}: amneziawg: s{}={} is too short for header_protection_key: \
                             each of s1-s4 must be at least 12 bytes (the padding carries the \
                             header cipher nonce)",
                            i + 1,
                            pad
                        ));
                    }
                }
                Some(key)
            }
            Some(_) => {
                return Err(anyhow!(
                    "{at}: header_protection_key must be a base64 string"
                ));
            }
        };
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
        let bool_field = |key: &str| -> anyhow::Result<bool> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(false),
                Some(Value::Bool(b)) => Ok(*b),
                Some(_) => Err(anyhow!("{at}.{key}: must be a boolean")),
            }
        };
        Ok(Some(Self {
            junk_count: junk_count as u32,
            junk_min: junk_min as u32,
            junk_max: junk_max as u32,
            paddings,
            headers,
            ipackets,
            header_protection,
            content_padding: opt_range(obj, "content_padding_addition", at)?,
            rekey_after_time: opt_range(obj, "rekey_after_time", at)?,
            rekey_timeout: opt_range(obj, "rekey_timeout", at)?,
            reject_after_time: opt_range(obj, "reject_after_time", at)?,
            keepalive_timeout: opt_range(obj, "keepalive_timeout", at)?,
            max_handshake_attempts: opt_range(obj, "max_handshake_attempts", at)?,
            random_trailers: bool_field("random_trailers")?,
            disable_cookies: bool_field("disable_cookies")?,
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

/// Optional ranged knob (`AWGRange`): unset means `None` (the caller keeps
/// its WireGuard default).
fn opt_range(obj: &Map<String, Value>, key: &str, at: &str) -> anyhow::Result<Option<HeaderRange>> {
    if !awg_field_present(obj.get(key)) {
        return Ok(None);
    }
    // A range that normalizes to unset ("0" / "") means "not configured".
    let probe = header_range(obj, key, u32::MAX, at)?;
    if probe == (u32::MAX, u32::MAX) {
        return Ok(None);
    }
    Ok(Some(probe))
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

fn parse_header_key(spec: &str, at: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = super::super::shadowsocks::crypto::decode_base64_std(spec).map_err(|e| {
        anyhow!(
            "{at}: amneziawg: decode header_protection_key \
                 (expected base64, as printed by `awg genkey`): {e}"
        )
    })?;
    let key: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
        anyhow!(
            "{at}: amneziawg: header_protection_key must decode to 32 bytes, got {}",
            v.len()
        )
    })?;
    if key == [0u8; 32] {
        return Err(anyhow!(
            "{at}: amneziawg: header_protection_key is all zeros (the device treats that as \
             \"off\"); omit the field instead"
        ));
    }
    Ok(key)
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

/// Uniform pick in `lo..=hi` (`UintRange.PickOne` / `magicHeader.Generate`).
pub fn pick_range(range: HeaderRange) -> u32 {
    let (lo, hi) = range;
    debug_assert!(lo <= hi);
    if lo == hi {
        return lo;
    }
    let span = hi as u64 - lo as u64 + 1;
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    lo + (u64::from_le_bytes(buf) % span) as u32
}

/// `PickOne` over an optional range; unset → the WireGuard default.
pub fn pick_opt(range: Option<HeaderRange>, default: u32) -> u32 {
    match range {
        Some(r) => pick_range(r),
        None => default,
    }
}

/// Ranged timing override in seconds, picked per use.
pub fn pick_secs(range: Option<HeaderRange>, default_secs: u64) -> std::time::Duration {
    std::time::Duration::from_secs(pick_opt(range, default_secs as u32) as u64)
}

/// Junk size in `jmin..=jmax` (inclusive), mirroring `JunkPackets`.
pub fn junk_size(min: u32, max: u32) -> usize {
    if max <= min {
        return min as usize;
    }
    pick_range((min, max)) as usize
}

/// `randomTrailer`: random tail length below the peer's UDP window budget.
pub fn trailer_len(udp_window: u32, datagram_size: usize) -> usize {
    let window = udp_window as usize;
    if window <= datagram_size {
        return 0;
    }
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    (u64::from_le_bytes(buf) % (window - datagram_size) as u64) as usize
}

/// Transport plaintext padding for one data packet (`randomPaddingAddition`
/// and friends): the AWG 3.x content-padding addition, else a random trailer
/// when trailers are on, else the WireGuard multiple-of-16 pad. Clamped by
/// the peer's UDP window exactly like the reference.
pub fn transport_padding(a: &AwgParams, udp_window: u32, pkt_len: usize, s4: usize) -> usize {
    let datagram_size = s4 + 16 + pkt_len;
    let addition = match a.content_padding {
        Some(r) => Some(pick_range(r) as usize),
        None if a.random_trailers => Some(trailer_len(udp_window, datagram_size)),
        None => None,
    };
    match addition {
        Some(n) => {
            let space = (udp_window as usize).saturating_sub(datagram_size);
            n.min(space)
        }
        None => (16 - pkt_len % 16) % 16,
    }
}

/// AWG 3.x header protection keystream (ChaCha20 keyed by the
/// `header_protection_key`, nonce = the first 12 bytes of the datagram —
/// the s-padding). XOR is symmetric: mask on TX, unmask on RX. Returns
/// `false` when the key is unset.
pub fn mask_header(key: &[u8; 32], nonce12: &[u8], data: &mut [u8]) -> bool {
    if data.len() < HEADER_NONCE_LEN || nonce12.len() < HEADER_NONCE_LEN {
        return false;
    }
    let nonce: [u8; HEADER_NONCE_LEN] = nonce12.try_into().expect("len checked");
    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    cipher.apply_keystream(data);
    true
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

/// Port of `Device.DeterminePacketTypeAndPadding` + `classifyTransportByIndex`
/// (reference receive.go, SPEC 081): classify a datagram into
/// `(kind, s-padding)`. The type word sits at the kind's padding offset and
/// is unmasked with the AWG 3.x keystream (all-zero mask when the key is
/// unset). Fixed-size messages match exactly — or exceed their size when
/// random trailers are on (the caller trims). `known_index` recognizes live
/// receiver indices so a data datagram can't be claimed by a handshake
/// candidate's random type word.
pub fn demux(
    awg: Option<&AwgParams>,
    buf: &[u8],
    known_index: &dyn Fn(u32) -> bool,
) -> Option<(u8, usize)> {
    // 16 bytes: mask_header draws a full ChaCha20 block-sized prefix so the
    // first 8 keystream bytes cover the transport type word + receiver index.
    let mut ks = [0u8; 16];
    if let Some(key) = awg.and_then(|a| a.header_protection.as_ref()) {
        if buf.len() < HEADER_NONCE_LEN {
            return None;
        }
        mask_header(key, &buf[..HEADER_NONCE_LEN], &mut ks);
    }
    // Unmasked word at a padding offset (keystream starts at the message).
    let word_at = |pad: usize| -> Option<u32> {
        let raw = buf.get(pad..pad + 4)?;
        let m = u32::from_le_bytes(raw.try_into().expect("4 bytes"));
        Some(m ^ u32::from_le_bytes(ks[..4].try_into().expect("4 bytes")))
    };
    let (s4, h4) = match awg {
        Some(a) => (a.padding(TRANSPORT), a.header(TRANSPORT)),
        None => (0, STD_HEADERS[TRANSPORT]),
    };
    let in_range = |w: u32, r: HeaderRange| w >= r.0 && w <= r.1;

    // SPEC 081: a live receiver index behind a transport type word is a data
    // datagram, whatever its total size.
    if buf.len() >= s4 + 16
        && let Some(w) = word_at(s4)
        && in_range(w, h4)
    {
        let idx_raw = buf.get(s4 + 4..s4 + 8)?;
        let masked = u32::from_le_bytes(idx_raw.try_into().expect("4 bytes"));
        let idx = masked ^ u32::from_le_bytes(ks[4..8].try_into().expect("4 bytes"));
        if known_index(idx) {
            return Some((super::noise::MSG_TRANSPORT, s4));
        }
    }

    let trailers = awg.is_some_and(|a| a.random_trailers);
    for (kind, base, idx) in [
        (
            super::noise::MSG_INITIATION,
            super::noise::INITIATION_LEN,
            INIT,
        ),
        (
            super::noise::MSG_RESPONSE,
            super::noise::RESPONSE_LEN,
            RESPONSE,
        ),
        (
            super::noise::MSG_COOKIE_REPLY,
            super::noise::COOKIE_REPLY_LEN,
            COOKIE,
        ),
    ] {
        let pad = awg.map(|a| a.padding(idx)).unwrap_or(0);
        let range = awg.map(|a| a.header(idx)).unwrap_or(STD_HEADERS[idx]);
        let expected = pad + base;
        let size_ok = buf.len() == expected || (trailers && buf.len() > expected);
        if size_ok
            && let Some(w) = word_at(pad)
            && in_range(w, range)
        {
            return Some((kind, pad));
        }
    }
    if buf.len() >= s4 + 16
        && let Some(w) = word_at(s4)
        && in_range(w, h4)
    {
        return Some((super::noise::MSG_TRANSPORT, s4));
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

    const NO_INDEX: &dyn Fn(u32) -> bool = &|_| false;

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
    fn awg3_full_parse() {
        let o = obj(&[
            ("s1", json!(16)),
            ("s2", json!(16)),
            ("s3", json!(16)),
            ("s4", json!(16)),
            (
                "header_protection_key",
                json!("pBNb5h0hRWf3C6dpIVR2Tb7YwpH4THRscWhF1RV4Xgc="),
            ),
            ("content_padding_addition", json!("10-100")),
            ("rekey_after_time", json!("100-120")),
            ("random_trailers", json!(true)),
            ("disable_cookies", json!(true)),
        ]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        assert!(a.header_protection.is_some());
        assert_eq!(a.content_padding, Some((10, 100)));
        assert_eq!(a.rekey_after_time, Some((100, 120)));
        assert!(a.random_trailers && a.disable_cookies);
    }

    #[test]
    fn awg3_rejections() {
        // short padding with a header key
        let o = obj(&[
            ("s1", json!(8)),
            ("s2", json!(16)),
            ("s3", json!(16)),
            ("s4", json!(16)),
            (
                "header_protection_key",
                json!("pBNb5h0hRWf3C6dpIVR2Tb7YwpH4THRscWhF1RV4Xgc="),
            ),
        ]);
        let err = AwgParams::from_obj(&o, "x").expect_err("short padding");
        assert!(err.to_string().contains("s1=8 is too short"));
        // zero key
        let o = obj(&[(
            "header_protection_key",
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        )]);
        let err = AwgParams::from_obj(&o, "x").expect_err("zero key");
        assert!(err.to_string().contains("all zeros"));
        // bad base64
        let o = obj(&[("header_protection_key", json!("not-base64!!"))]);
        let err = AwgParams::from_obj(&o, "x").expect_err("bad b64");
        assert!(err.to_string().contains("decode header_protection_key"));
        // short key
        let o = obj(&[("header_protection_key", json!("AAAA"))]);
        let err = AwgParams::from_obj(&o, "x").expect_err("short key");
        assert!(err.to_string().contains("must decode to 32 bytes, got 3"));
        // masquerade sugar stays rejected
        let o = obj(&[("id", json!("example.com"))]);
        let err = AwgParams::from_obj(&o, "x").expect_err("masquerade");
        assert!(err.to_string().contains("masquerade"));
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
        assert_eq!(demux(None, &pkt, NO_INDEX), Some((4, 0)));
        pkt[0] = 9;
        assert_eq!(demux(None, &pkt, NO_INDEX), None);

        // AWG: s1=10 padding + h1 in 100..=200, init is 148 bytes
        let o = obj(&[("s1", json!(10)), ("h1", json!("100-200"))]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        let mut init = vec![0u8; 10 + 148];
        init[..10].fill(0xEE);
        init[10..14].copy_from_slice(&150u32.to_le_bytes());
        assert_eq!(demux(Some(&a), &init, NO_INDEX), Some((1, 10)));
        init[10..14].copy_from_slice(&250u32.to_le_bytes());
        assert_eq!(demux(Some(&a), &init, NO_INDEX), None);
        // wrong size (standard 148) must not match when padding is set
        init.truncate(148);
        assert_eq!(demux(Some(&a), &init, NO_INDEX), None);
    }

    #[test]
    fn demux_header_protection_roundtrip() {
        let o = obj(&[
            ("s1", json!(16)),
            ("s2", json!(16)),
            ("s3", json!(16)),
            ("s4", json!(16)),
            ("h1", json!("100-200")),
            (
                "header_protection_key",
                json!("pBNb5h0hRWf3C6dpIVR2Tb7YwpH4THRscWhF1RV4Xgc="),
            ),
        ]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        let key_bytes = a.header_protection.expect("key");

        // Build a masked init: [16 random][148-byte message masked with
        // ChaCha20(key, nonce = first 12 bytes of the datagram)].
        let mut init = vec![0u8; 16 + 148];
        fill_random(&mut init[..16]);
        init[16..20].copy_from_slice(&150u32.to_le_bytes());
        let nonce = init[..12].to_vec();
        assert!(mask_header(&key_bytes, &nonce, &mut init[16..]));
        assert_eq!(demux(Some(&a), &init, NO_INDEX), Some((1, 16)));

        // Wrong key → the type word decodes to garbage → unknown.
        let mut wrong = init.clone();
        let (nonce_slice, rest) = wrong.split_at_mut(12);
        assert!(mask_header(&[0x43u8; 32], nonce_slice, &mut rest[4..]));
        assert_eq!(demux(Some(&a), &wrong, NO_INDEX), None);
    }

    #[test]
    fn demux_transport_by_index() {
        let o = obj(&[
            ("s1", json!(12)),
            ("s2", json!(12)),
            ("s3", json!(12)),
            ("s4", json!(12)),
            ("h4", json!("400-500")),
            (
                "header_protection_key",
                json!("pBNb5h0hRWf3C6dpIVR2Tb7YwpH4THRscWhF1RV4Xgc="),
            ),
        ]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        let key = a.header_protection.expect("key");
        let mut pkt = vec![0u8; 12 + 16 + 8];
        fill_random(&mut pkt);
        let nonce = pkt[..12].to_vec();
        pkt[12..16].copy_from_slice(&450u32.to_le_bytes());
        pkt[16..20].copy_from_slice(&777u32.to_le_bytes());
        // masked like a real transport datagram (first 16 bytes of message)
        let mut header = pkt[12..28].to_vec();
        assert!(mask_header(&key, &nonce, &mut header));
        pkt[12..28].copy_from_slice(&header);

        // with the index known it takes the SPEC 081 fast path
        let known: &dyn Fn(u32) -> bool = &|i| i == 777;
        assert_eq!(demux(Some(&a), &pkt, known), Some((4, 12)));
        // unknown index → the reference-order fallback still classifies it
        assert_eq!(demux(Some(&a), &pkt, NO_INDEX), Some((4, 12)));

        // a live index does NOT bypass the magic range check
        let mut bad = pkt.clone();
        bad[12..16].copy_from_slice(&999u32.to_le_bytes());
        let mut header = bad[12..28].to_vec();
        assert!(mask_header(&key, &nonce, &mut header));
        bad[12..28].copy_from_slice(&header);
        assert_eq!(demux(Some(&a), &bad, known), None);
    }

    #[test]
    fn trailers_relax_handshake_size() {
        let o = obj(&[
            ("s1", json!(12)),
            ("h1", json!(5)),
            ("random_trailers", json!(true)),
        ]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        let mut init = vec![0u8; 12 + 148 + 40];
        init[12..16].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(demux(Some(&a), &init, NO_INDEX), Some((1, 12)));
        // without trailers an oversized init is unknown
        let o2 = obj(&[("s1", json!(12)), ("h1", json!(5))]);
        let a2 = AwgParams::from_obj(&o2, "x").expect("awg").expect("set");
        assert_eq!(demux(Some(&a2), &init, NO_INDEX), None);
    }

    #[test]
    fn transport_padding_rules() {
        let base = obj(&[]);
        let plain = AwgParams::from_obj(&base, "x").expect("plain");
        let plain = plain.unwrap_or(AwgParams {
            junk_count: 0,
            junk_min: 0,
            junk_max: 0,
            paddings: [0; 4],
            headers: STD_HEADERS,
            ipackets: [None, None, None, None, None],
            header_protection: None,
            content_padding: None,
            rekey_after_time: None,
            rekey_timeout: None,
            reject_after_time: None,
            keepalive_timeout: None,
            max_handshake_attempts: None,
            random_trailers: false,
            disable_cookies: false,
        });
        // plain: multiple-of-16 pad
        assert_eq!(transport_padding(&plain, 500, 40, 0), 8);
        assert_eq!(transport_padding(&plain, 500, 32, 0), 0);

        // content padding: picked inside the range, clamped by the window
        let o = obj(&[("content_padding_addition", json!("10-100"))]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        for _ in 0..50 {
            let n = transport_padding(&a, 500, 40, 12);
            assert!((10..=100).contains(&n));
        }
        // window clamp: datagram 12+16+40=68, window 80 → max 12 bytes
        let n = transport_padding(&a, 80, 40, 12);
        assert!(n <= 12);

        // trailers without content padding: random below the window budget
        let o = obj(&[("random_trailers", json!(true))]);
        let a = AwgParams::from_obj(&o, "x").expect("awg").expect("set");
        for _ in 0..50 {
            let n = transport_padding(&a, 500, 40, 0);
            assert!(n < 500 - 56);
        }
    }

    #[test]
    fn mask_roundtrip_and_nonce_short() {
        let key = [9u8; 32];
        let nonce = [0x11u8; 12];
        let mut data = vec![1u8; 37];
        let orig = data.clone();
        assert!(mask_header(&key, &nonce, &mut data));
        assert_ne!(data, orig);
        assert!(mask_header(&key, &nonce, &mut data));
        assert_eq!(data, orig);
        let mut tiny = [0u8; 11];
        assert!(!mask_header(&key, &nonce, &mut tiny));
    }

    #[test]
    fn junk_size_bounds() {
        for _ in 0..100 {
            let n = junk_size(60, 120);
            assert!((60..=120).contains(&n));
        }
        assert_eq!(junk_size(5, 5), 5);
    }

    #[test]
    fn picks_and_defaults() {
        assert_eq!(pick_opt(None, 42), 42);
        assert_eq!(pick_opt(Some((7, 7)), 42), 7);
        for _ in 0..50 {
            let v = pick_opt(Some((10, 20)), 42);
            assert!((10..=20).contains(&v));
        }
        assert_eq!(pick_secs(None, 120).as_secs(), 120);
    }
}
