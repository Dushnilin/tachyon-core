//! Port of `quinn-proto/src/crypto/ring_like.rs` over RustCrypto.
//!
//! Upstream implements `HmacKey`/`HandshakeTokenKey`/`AeadKey` for `ring`
//! (or `aws-lc-rs`) types. Those features pull `ring`, so we implement the
//! same traits on our own types built from `hmac`/`hkdf`/`aes-gcm`.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::Mac;
use quinn_proto::crypto::{self, CryptoError};
use sha2::Sha256;

/// HMAC-SHA256 key implementing quinn's [`crypto::HmacKey`].
///
/// Used for stateless-reset tokens and address-validation tokens.
pub struct HmacSha256Key {
    key: hmac::Hmac<Sha256>,
}

impl HmacSha256Key {
    /// Build from raw key material (any length; HMAC pads internally).
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: <hmac::Hmac<Sha256> as Mac>::new_from_slice(key)
                .expect("hmac accepts any key length"),
        }
    }
}

impl crypto::HmacKey for HmacSha256Key {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut mac = self.key.clone();
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let n = signature_out.len().min(tag.len());
        signature_out[..n].copy_from_slice(&tag[..n]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut mac = self.key.clone();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| CryptoError)
    }
}

/// AES-256-GCM key with the zero nonce, implementing quinn's
/// [`crypto::AeadKey`].
///
/// Handshake tokens are sealed with a fixed all-zero nonce (single-use key
/// derived per token), matching upstream `ring_like`.
pub struct Aes256GcmKey {
    cipher: Aes256Gcm,
}

impl Aes256GcmKey {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key_bytes).expect("32-byte key"),
        }
    }

    fn nonce() -> Nonce<U12> {
        Nonce::from([0u8; 12])
    }
}

impl crypto::AeadKey for Aes256GcmKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let out = self
            .cipher
            .encrypt(
                &Self::nonce(),
                Payload {
                    msg: data.as_slice(),
                    aad: additional_data,
                },
            )
            .map_err(|_| CryptoError)?;
        *data = out;
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        const TAG_LEN: usize = 16;
        if data.len() < TAG_LEN {
            return Err(CryptoError);
        }
        let split = data.len() - TAG_LEN;
        let (buf, tag) = data.split_at_mut(split);
        let tag = aes_gcm::Tag::from_slice(tag);
        self.cipher
            .decrypt_in_place_detached(&Self::nonce(), additional_data, buf, tag)
            .map_err(|_| CryptoError)?;
        Ok(buf)
    }
}

/// HKDF-SHA256 master key implementing quinn's [`crypto::HandshakeTokenKey`].
///
/// Mirrors upstream: `Salt::new(HKDF_SHA256, &[]).extract(master)` then
/// `prk.expand([random_bytes])` → 32-byte AES-256-GCM key. Empty salt is
/// equivalent to the zero salt for HMAC (keys pad to the block size), so
/// `Hkdf::new(Some(&[]), master)` matches.
pub struct HandshakeTokenKeyRustCrypto {
    master: [u8; 64],
}

impl HandshakeTokenKeyRustCrypto {
    /// Build from a random 64-byte master key.
    pub fn new(master: [u8; 64]) -> Self {
        Self { master }
    }
}

impl crypto::HandshakeTokenKey for HandshakeTokenKeyRustCrypto {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&[]), &self.master);
        let mut okm = [0u8; 32];
        // expand failure is impossible: 32 ≤ 255×32.
        hk.expand(random_bytes, &mut okm)
            .expect("hkdf expand to 32 bytes");
        Box::new(Aes256GcmKey::new(&okm))
    }
}
