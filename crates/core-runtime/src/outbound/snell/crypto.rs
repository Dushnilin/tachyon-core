//! snell v4 record crypto: Argon2id key derivation (reference `DeriveKey`),
//! AES-128-GCM seal/open in place, and the little-endian nonce counter.

use std::io;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const AEAD_TAG_LEN: usize = 16;
pub(crate) const HEADER_VERSION: u8 = 0x04;
pub(crate) const HEADER_PLAIN_LEN: usize = 7;
pub(crate) const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + AEAD_TAG_LEN;
pub(crate) const MAX_PAYLOAD_LEN: usize = 0x3fff;

/// Reference `DeriveKey`: argon2id(t=3, m=8KiB, p=1, 32 bytes) → first 16.
pub(crate) fn derive_key(psk: &[u8], salt: &[u8]) -> io::Result<[u8; 16]> {
    let params = Params::new(8, 3, 1, Some(32))
        .map_err(|e| io::Error::other(format!("snell: argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(psk, salt, &mut out)
        .map_err(|e| io::Error::other(format!("snell: argon2 derive: {e}")))?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&out[..16]);
    Ok(key)
}

pub(crate) fn new_aead(key: &[u8; 16]) -> Aes128Gcm {
    Aes128Gcm::new_from_slice(key).expect("snell: aes-128-gcm key")
}

/// Reference `IncreaseNonce`: per-byte ++ with carry (little-endian counter).
pub(crate) fn increase_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Seal `data` in place, appending the 16 byte tag (empty AAD).
pub(crate) fn seal_in_place(
    cipher: &Aes128Gcm,
    nonce: &[u8; NONCE_LEN],
    data: &mut Vec<u8>,
) -> io::Result<()> {
    cipher
        .encrypt_in_place(Nonce::from_slice(nonce), &[], data)
        .map_err(|_| io::Error::other("snell: seal record"))
}

/// Open `data` (ciphertext + tag) in place, truncating to the plaintext.
pub(crate) fn open_in_place(
    cipher: &Aes128Gcm,
    nonce: &[u8; NONCE_LEN],
    data: &mut Vec<u8>,
) -> io::Result<()> {
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), &[], data)
        .map_err(|_| io::Error::other("snell: open record"))
}

pub(crate) fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    getrandom::fill(buf).map_err(|e| io::Error::other(format!("snell: rng: {e}")))
}

/// Uniform 31-bit random (reference `randomInt31`: LE u32 masked to 31 bits).
pub(crate) fn random_int31() -> io::Result<u32> {
    let mut buf = [0u8; 4];
    random_bytes(&mut buf)?;
    Ok(u32::from_le_bytes(buf) & 0x7fff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// argon2id(t=3, m=8KiB, p=1, 32B)[:16] against the reference
    /// `golang.org/x/crypto/argon2.IDKey` (generated via a Go one-liner).
    #[test]
    fn derive_key_matches_reference_argon2id() {
        let key = derive_key(b"test-psk-12345678", b"0123456789abcdef").expect("derive");
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "1bb35490956b11c16e9caab07de23b13");
        let key =
            derive_key(b"deadbeefdeadbeefdeadbeefdeadbeef", b"0123456789abcdef").expect("derive");
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "ad66d2025b1dabb78f61d0acce6d816d");
    }

    #[test]
    fn derive_key_truncates_to_first_16_of_32() {
        // The full hash must be 32 bytes: a different psk must change the key.
        let a = derive_key(b"psk-a", b"0123456789abcdef").expect("derive");
        let b = derive_key(b"psk-b", b"0123456789abcdef").expect("derive");
        assert_ne!(a, b);
        let c = derive_key(b"psk-a", b"fedcba9876543210").expect("derive");
        assert_ne!(a, c);
    }

    #[test]
    fn increase_nonce_is_little_endian_counter() {
        let mut nonce = [0u8; NONCE_LEN];
        increase_nonce(&mut nonce);
        assert_eq!(nonce[0], 1);
        assert_eq!(nonce[11], 0);

        nonce = [0xff; NONCE_LEN];
        increase_nonce(&mut nonce);
        assert_eq!(nonce, [0; NONCE_LEN]);

        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 0xff;
        increase_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);
        assert_eq!(nonce[11], 0);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = derive_key(b"psk", b"0123456789abcdef").expect("derive");
        let cipher = new_aead(&key);
        let mut nonce = [0u8; NONCE_LEN];
        let mut data = b"snell record".to_vec();
        seal_in_place(&cipher, &nonce, &mut data).expect("seal");
        assert_eq!(data.len(), 12 + AEAD_TAG_LEN);
        open_in_place(&cipher, &nonce, &mut data).expect("open");
        assert_eq!(data, b"snell record");
        // Tampering must fail.
        increase_nonce(&mut nonce);
        let mut bad = b"snell record".to_vec();
        seal_in_place(&cipher, &nonce, &mut bad).expect("seal");
        bad[0] ^= 0xff;
        assert!(open_in_place(&cipher, &nonce, &mut bad).is_err());
    }
}
