//! Parser for the VLESS `encryption` spec string (SPEC 032):
//! `mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding>…].<key>…`
//! — ported from sing-box-lx `protocol/vless/lx_encryption.go` +
//! `encryption/common.go` (`ParsePadding`). Shared by the check pass and the
//! runtime so a malformed spec fails identically at both.

/// Wire appearance: AEAD headers shaped like TLSv1.3 (`native`), XOR-ed by the
/// public keys (`xorpub`), or fully random (`random`).
pub const XOR_MODE_NATIVE: u32 = 0;
pub const XOR_MODE_XOR_PUB: u32 = 1;
pub const XOR_MODE_RANDOM: u32 = 2;

/// The only handshake method that exists today.
pub const ENCRYPTION_PREFIX: &str = "mlkem768x25519plus";

pub const KEY_LEN_X25519: usize = 32;
pub const KEY_LEN_MLKEM768: usize = 1184;

/// Keys are base64 of 32 or 1184 bytes, so they are always longer than a
/// padding block like `100-111-1111`.
const PADDING_SEGMENT_MAX_LEN: usize = 20;

#[derive(Debug, Clone)]
pub struct ClientEncryptionSpec {
    pub keys: Vec<Vec<u8>>,
    pub xor_mode: u32,
    pub seconds: u32,
    pub padding: String,
}

/// `0rtt` enables ticket reuse (seconds > 0); `1rtt` is always a full
/// handshake.
pub fn parse_client_encryption(raw: &str) -> Result<ClientEncryptionSpec, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty encryption string".to_string());
    }
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() < 4 {
        return Err(format!(
            "invalid encryption string: expected at least method.appearance.rtt.key, got {} segments",
            parts.len()
        ));
    }
    if parts[0] != ENCRYPTION_PREFIX {
        return Err(format!(
            "unsupported encryption method: {} (only {ENCRYPTION_PREFIX} exists)",
            parts[0]
        ));
    }
    let xor_mode = match parts[1] {
        "native" => XOR_MODE_NATIVE,
        "xorpub" => XOR_MODE_XOR_PUB,
        "random" => XOR_MODE_RANDOM,
        other => {
            return Err(format!(
                "unknown encryption appearance: {other} (expected native|xorpub|random)"
            ));
        }
    };
    let seconds = match parts[2] {
        "0rtt" => 1,
        "1rtt" => 0,
        other => {
            return Err(format!(
                "unknown encryption RTT mode: {other} (expected 0rtt|1rtt)"
            ));
        }
    };

    // Remaining segments are padding blocks first, then keys. Once a key is
    // seen the padding phase is over — that is how the reference tells the
    // two apart, since both are dot-separated and otherwise unlabelled.
    let mut padding_parts: Vec<&str> = Vec::new();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut padding_phase = true;
    for segment in &parts[3..] {
        let segment = segment.trim();
        if segment.is_empty() {
            return Err("empty segment in encryption string".to_string());
        }
        if padding_phase && segment.len() < PADDING_SEGMENT_MAX_LEN {
            padding_parts.push(segment);
            continue;
        }
        let data = base64_url_decode(segment)
            .ok_or_else(|| format!("invalid encryption key (not base64url): {segment}"))?;
        if data.len() != KEY_LEN_X25519 && data.len() != KEY_LEN_MLKEM768 {
            return Err(format!(
                "invalid encryption key length: {} (expected {KEY_LEN_X25519} or {KEY_LEN_MLKEM768})",
                data.len()
            ));
        }
        keys.push(data);
        padding_phase = false;
    }
    if keys.is_empty() {
        return Err("no encryption keys in encryption string".to_string());
    }
    Ok(ClientEncryptionSpec {
        keys,
        xor_mode,
        seconds,
        padding: padding_parts.join("."),
    })
}

/// base64 URL-safe without padding (`base64.RawURLEncoding`).
pub fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in bytes {
        let v = ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Raw encoding: at most 6 leftover bits; more means a broken tail.
    if bits >= 8 {
        return None;
    }
    Some(out)
}

/// `probability-from-to` triples (reference `ParsePadding`): odd-indexed
/// blocks are gaps, even are lengths; the first block has floor rules.
pub fn parse_padding(padding: &str) -> Result<Vec<[i64; 3]>, String> {
    if padding.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<[i64; 3]> = Vec::new();
    let mut max_len: i64 = 0;
    for (i, s) in padding.split('.').enumerate() {
        let x: Vec<&str> = s.split('-').collect();
        if x.len() < 3 || x[0].is_empty() || x[1].is_empty() || x[2].is_empty() {
            return Err(format!("invalid padding lenth/gap parameter: {s}"));
        }
        let mut y = [0i64; 3];
        for (slot, raw) in y.iter_mut().zip(&x) {
            *slot = raw
                .parse()
                .map_err(|_| format!("invalid padding lenth/gap parameter: {s}"))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err("first padding length must not be smaller than 35".to_string());
        }
        if i % 2 == 0 {
            max_len += y[1].max(y[2]);
        }
        out.push(y);
    }
    if max_len > 18 + 65535 {
        return Err("total padding length must not be larger than 65553".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_spec() {
        let key = key64(32, 1);
        let spec = parse_client_encryption(&format!("mlkem768x25519plus.native.0rtt.{key}"))
            .expect("parse");
        assert_eq!(spec.xor_mode, XOR_MODE_NATIVE);
        assert_eq!(spec.seconds, 1);
        assert_eq!(spec.keys.len(), 1);
        assert_eq!(spec.keys[0].len(), 32);
        assert_eq!(spec.padding, "");
    }

    #[test]
    fn parses_mlkem_and_padding() {
        let k32 = key64(32, 2);
        let k1184 = key64(1184, 3);
        let spec = parse_client_encryption(&format!(
            "mlkem768x25519plus.xorpub.1rtt.100-111-1111.75-0-111.{k32}.{k1184}"
        ))
        .expect("parse");
        assert_eq!(spec.xor_mode, XOR_MODE_XOR_PUB);
        assert_eq!(spec.seconds, 0);
        assert_eq!(spec.keys.len(), 2);
        assert_eq!(spec.keys[0].len(), 32);
        assert_eq!(spec.keys[1].len(), 1184);
        assert_eq!(spec.padding, "100-111-1111.75-0-111");
        assert_eq!(parse_padding(&spec.padding).unwrap().len(), 2);
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_client_encryption("").is_err());
        assert!(parse_client_encryption("none").is_err());
        assert!(parse_client_encryption("mlkem768x25519plus.native.0rtt").is_err());
        assert!(parse_client_encryption("foo.native.0rtt.aaaaaaaaaa").is_err());
        assert!(parse_client_encryption("mlkem768x25519plus.bogus.0rtt.aaaaaaaaaa").is_err());
        assert!(parse_client_encryption("mlkem768x25519plus.native.2rtt.aaaaaaaaaa").is_err());
        assert!(parse_client_encryption("mlkem768x25519plus.native.0rtt.!!").is_err());
        // wrong key length (3 bytes decoded)
        assert!(parse_client_encryption("mlkem768x25519plus.native.0rtt.aaaaaaaa").is_err());
        // no keys
        assert!(parse_client_encryption("mlkem768x25519plus.native.0rtt.100-111-1111").is_err());
        // padding rules
        assert_eq!(
            parse_padding("0-111-1111").unwrap_err(),
            "first padding length must not be smaller than 35"
        );
        assert!(parse_padding("bad").is_err());
        assert!(parse_padding("").is_ok());
    }

    fn key64(n: usize, fill: u8) -> String {
        let v = vec![fill; n];
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &b in &v {
            acc = (acc << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[(acc >> bits) as usize & 63] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[(acc << (6 - bits)) as usize & 63] as char);
        }
        out
    }
}
