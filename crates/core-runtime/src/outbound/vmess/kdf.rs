//! VMess key derivation: nested HMAC-SHA256 KDF (sing-vmess `kdf.go`),
//! command keys, UUID parsing with v5 fallback, and small hash helpers.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Mirrors Go's `hMacCreator` chain: each level is HMAC keyed by its value
/// using the parent level as the hash function; the innermost is
/// HMAC-SHA256 keyed with `KDFSaltConstVMessAEADKDF`.
enum KdfHash {
    Sha256,
    Hmac { key: Vec<u8>, parent: Box<KdfHash> },
}

impl KdfHash {
    const BLOCK: usize = 64;

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        match self {
            KdfHash::Sha256 => Sha256::digest(data).into(),
            KdfHash::Hmac { key, parent } => {
                let mut k = key.clone();
                if k.len() > Self::BLOCK {
                    k = parent.hash(&k).to_vec();
                }
                k.resize(Self::BLOCK, 0);
                let mut ipad = [0x36u8; Self::BLOCK];
                let mut opad = [0x5cu8; Self::BLOCK];
                for (i, byte) in k.iter().enumerate() {
                    ipad[i] ^= byte;
                    opad[i] ^= byte;
                }
                let mut inner = ipad.to_vec();
                inner.extend_from_slice(data);
                let inner = parent.hash(&inner);
                let mut outer = opad.to_vec();
                outer.extend_from_slice(&inner);
                parent.hash(&outer)
            }
        }
    }
}

/// sing-vmess `KDF(key, salt, path...)`: chain root + salt + path elements.
pub(crate) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut level = KdfHash::Hmac {
        key: b"VMess AEAD KDF".to_vec(),
        parent: Box::new(KdfHash::Sha256),
    };
    for elem in path {
        level = KdfHash::Hmac {
            key: elem.to_vec(),
            parent: Box::new(level),
        };
    }
    level.hash(key)
}

pub(crate) fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    full[..16].try_into().expect("kdf output is 32 bytes")
}

/// `Key(user)`: MD5(uuid || "c48619fe-...").
pub(crate) fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(uuid);
    hash.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hash.finalize().into()
}

/// `GenerateChacha20Poly1305Key`: 32 bytes = MD5(k) || MD5(MD5(k)).
pub(crate) fn chacha_key(key16: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(key16);
    let second = Md5::digest(first);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

pub(crate) fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Canonical hyphenated UUIDs parse directly; anything else becomes
/// `uuid.NewV5(uuid.Nil, raw)` (SHA1 of NIL || name with version/variant bits).
pub(crate) fn parse_uuid(raw: &str) -> Result<[u8; 16], std::io::Error> {
    let bytes = raw.as_bytes();
    let canonical = bytes.len() == 36
        && bytes[..8].iter().all(u8::is_ascii_hexdigit)
        && bytes[9..13].iter().all(u8::is_ascii_hexdigit)
        && bytes[14..18].iter().all(u8::is_ascii_hexdigit)
        && bytes[19..23].iter().all(u8::is_ascii_hexdigit)
        && bytes[24..36].iter().all(u8::is_ascii_hexdigit)
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-';
    if canonical {
        let hex: String = raw.chars().filter(|c| *c != '-').collect();
        let mut uuid = [0u8; 16];
        for (i, byte) in uuid.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| std::io::Error::other("invalid uuid"))?;
        }
        return Ok(uuid);
    }
    let mut hash = Sha1::new();
    hash.update([0u8; 16]);
    hash.update(raw.as_bytes());
    let sum = hash.finalize();
    let mut uuid: [u8; 16] = sum[..16].try_into().expect("sha1 output is 20 bytes");
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_reference_vector() {
        let out = kdf(
            b"Demo Key for KDF Value Test",
            &[
                b"Demo Path for KDF Value Test",
                b"Demo Path for KDF Value Test2",
                b"Demo Path for KDF Value Test3",
            ],
        );
        assert_eq!(
            out,
            [
                0x53, 0xe9, 0xd7, 0xe1, 0xbd, 0x7b, 0xd2, 0x50, 0x22, 0xb7, 0x1e, 0xad, 0x07, 0xd8,
                0xa5, 0x96, 0xef, 0xc8, 0xa8, 0x45, 0xc7, 0x88, 0x86, 0x52, 0xfd, 0x68, 0x4b, 0x49,
                0x03, 0xdc, 0x88, 0x92
            ]
        );
    }

    #[test]
    fn kdf16_is_prefix_of_kdf() {
        let key = [7u8; 16];
        assert_eq!(
            kdf16(&key, &[b"salt", b"path"]),
            kdf(&key, &[b"salt", b"path"])[..16]
        );
    }

    #[test]
    fn cmd_key_matches_manual_derivation() {
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").expect("parse");
        let mut hash = Md5::new();
        hash.update(uuid);
        hash.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let expected: [u8; 16] = hash.finalize().into();
        assert_eq!(cmd_key(&uuid), expected);
    }

    #[test]
    fn fnv1a_known_vectors() {
        assert_eq!(fnv1a32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn uuid_v5_sets_version_and_variant() {
        let a = parse_uuid("not a uuid").expect("v5 fallback");
        let b = parse_uuid("not a uuid").expect("v5 fallback");
        assert_eq!(a, b, "v5 must be deterministic");
        assert_eq!(a[6] >> 4, 0x5);
        assert_eq!(a[8] >> 6, 0b10);
        assert_ne!(a, parse_uuid("another uuid").unwrap());
    }
}
