use base64::Engine as _;
use std::io;

use crate::fastgcm::Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use hkdf::Hkdf;
use md5::Digest;
use md5::Md5;
use sha1::Sha1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3ChaCha20Poly1305,
}

impl Method {
    pub fn parse(name: &str) -> Option<Method> {
        match name {
            "aes-128-gcm" => Some(Method::Aes128Gcm),
            "aes-256-gcm" => Some(Method::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(Method::ChaCha20Poly1305),
            "2022-blake3-aes-128-gcm" => Some(Method::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Method::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Method::Blake3ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm | Method::Blake3Aes128Gcm => 16,
            Method::Aes256Gcm
            | Method::ChaCha20Poly1305
            | Method::Blake3Aes256Gcm
            | Method::Blake3ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Method::Blake3Aes128Gcm | Method::Blake3Aes256Gcm | Method::Blake3ChaCha20Poly1305
        )
    }

    /// Max unencrypted payload per chunk (0x3FFF legacy, 0xFFFF for 2022).
    pub fn max_chunk(self) -> u16 {
        if self.is_2022() { u16::MAX } else { 0x3FFF }
    }
}

pub(crate) enum Cipher {
    Aes(Box<Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Cipher {
    pub(crate) fn new(method: Method, key: &[u8]) -> Cipher {
        match method {
            Method::Aes128Gcm
            | Method::Blake3Aes128Gcm
            | Method::Aes256Gcm
            | Method::Blake3Aes256Gcm => Cipher::Aes(Box::new(Gcm::new(key))),
            Method::ChaCha20Poly1305 | Method::Blake3ChaCha20Poly1305 => {
                Cipher::ChaCha(Box::new(ChaCha20Poly1305::new(key.into())))
            }
        }
    }

    pub(crate) fn seal(&self, counter: u64, buf: &mut Vec<u8>) -> io::Result<()> {
        self.seal_at(counter, buf, 0)
    }

    /// Seal `buf[from..]` in place and append its tag. What comes before `from`
    /// is left alone, so a whole run of chunks can be built in one buffer.
    pub(crate) fn seal_at(&self, counter: u64, buf: &mut Vec<u8>, from: usize) -> io::Result<()> {
        let nonce = counter_nonce(counter);
        let body = &mut buf[from..];
        let tag: [u8; 16] = match self {
            Cipher::Aes(cipher) => cipher.seal(&nonce, &[], body),
            Cipher::ChaCha(cipher) => cipher
                .encrypt_in_place_detached((&nonce).into(), &[], body)
                .map_err(|_| io::Error::other("seal failed"))?
                .into(),
        };
        buf.extend_from_slice(&tag);
        Ok(())
    }

    /// Open a `[ciphertext || tag]` block where it sits: the first `len - 16`
    /// bytes are plaintext afterwards.
    pub(crate) fn open_slice(&self, counter: u64, block: &mut [u8]) -> io::Result<()> {
        if block.len() < 16 {
            return Err(io::Error::other("chunk too short"));
        }
        let split = block.len() - 16;
        let (data, tag) = block.split_at_mut(split);
        let tag: [u8; 16] = (&*tag).try_into().expect("tag is 16 bytes");
        let nonce = counter_nonce(counter);
        let ok = match self {
            Cipher::Aes(cipher) => cipher.open(&nonce, &[], data, &tag),
            Cipher::ChaCha(cipher) => cipher
                .decrypt_in_place_detached((&nonce).into(), &[], data, (&tag).into())
                .is_ok(),
        };
        if ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk auth failed",
            ))
        }
    }

    pub(crate) fn open(&self, counter: u64, buf: &mut Vec<u8>) -> io::Result<()> {
        if buf.len() < 16 {
            return Err(io::Error::other("chunk too short"));
        }
        let split = buf.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[split..]);
        buf.truncate(split);
        let nonce = counter_nonce(counter);
        let ok = match self {
            Cipher::Aes(cipher) => cipher.open(&nonce, &[], buf, &tag),
            Cipher::ChaCha(cipher) => cipher
                .decrypt_in_place_detached((&nonce).into(), &[], buf, (&tag).into())
                .is_ok(),
        };
        if ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk auth failed",
            ))
        }
    }
}

/// 12-byte little-endian operation counter.
fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// OpenSSL EVP_BytesToKey with MD5 (legacy password-to-key derivation).
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut prev: Vec<u8> = Vec::new();
    let mut out = Vec::with_capacity(key_len + 16);
    while out.len() < key_len {
        let mut hash = Md5::new();
        hash.update(&prev);
        hash.update(password);
        prev = hash.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

fn hkdf_sha1_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut okm = vec![0u8; key.len()];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("hkdf length is valid");
    okm
}

fn blake3_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(key.len() + salt.len());
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key("shadowsocks 2022 session subkey", &material);
    derived[..key.len()].to_vec()
}

pub fn derive_subkey(method: Method, master_key: &[u8], salt: &[u8]) -> Vec<u8> {
    if method.is_2022() {
        blake3_subkey(master_key, salt)
    } else {
        hkdf_sha1_subkey(master_key, salt)
    }
}

/// Decode the configured password into the master key.
pub fn master_key(method: Method, password: &str) -> io::Result<Vec<u8>> {
    if method.is_2022() {
        decode_base64_std(password)
    } else {
        Ok(evp_bytes_to_key(password.as_bytes(), method.key_len()))
    }
}

/// Standard base64 with padding, as the reference decodes it: a length that is
/// not a multiple of four and anything outside the alphabet are errors.
pub(crate) fn decode_base64_std(input: &str) -> io::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    getrandom::fill(buf).map_err(|e| io::Error::other(format!("rng: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_matches_known_vector() {
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(key, md5_hex(b"password"));
    }

    fn md5_hex(input: &[u8]) -> Vec<u8> {
        let mut hash = Md5::new();
        hash.update(input);
        hash.finalize().to_vec()
    }

    #[test]
    fn base64_roundtrip() {
        let decoded = decode_base64_std("MTIzNDU2Nzg5MGFiY2RlZg==").expect("decode");
        assert_eq!(decoded, b"1234567890abcdef");
        assert!(decode_base64_std("AAAAA").is_err());
        assert!(decode_base64_std("!!??").is_err());
    }

    #[test]
    fn method_specs() {
        assert_eq!(
            Method::parse("2022-blake3-aes-128-gcm").unwrap().key_len(),
            16
        );
        assert!(Method::parse("rc4-md5").is_none());
        assert!(!Method::parse("aes-256-gcm").unwrap().is_2022());
        assert_eq!(Method::Blake3Aes256Gcm.max_chunk(), u16::MAX);
    }
}
