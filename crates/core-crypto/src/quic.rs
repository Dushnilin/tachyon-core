//! RFC 9001 §5.4 QUIC header protection implementation.
//!
//! Header protection derives a 5-byte mask from a 16-byte sample of packet
//! ciphertext, then XORs specific bits of the first byte and the packet-number
//! bytes.  The operation is identical for encryption and decryption (XOR is
//! self-inverse); only the order of reading the packet-number length differs.
#![allow(clippy::duplicate_mod)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aead::AeadInPlace;
use chacha20poly1305::KeyInit;
use rustls::crypto::cipher::{self, AeadKey, Iv};
use rustls::{Error, quic};

// ── AES re-exports via aes-gcm ────────────────────────────────────────────────
use aes_gcm::aes::{
    Aes128, Aes256,
    cipher::{BlockEncrypt, generic_array::GenericArray},
};

// ── ChaCha20 stream cipher ────────────────────────────────────────────────────
use chacha20::{
    ChaCha20 as ChaCha20Core,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
};

/// Size of the header-protection sample in bytes (RFC 9001 §5.4.2).
const SAMPLE_LEN: usize = 16;

/// Maximum packet-number length in bytes (RFC 9000 §17.1).
const MAX_PN_LEN: usize = 4;

/// Number of mask bytes produced (RFC 9001 §5.4.1: 1 first-byte + 4 PN bytes).
const MASK_LEN: usize = 5;

// ── Cipher-suite discriminant ─────────────────────────────────────────────────

/// Which cipher to use for header protection.
///
/// RFC 9001 §5.4.3: AES-based header protection uses AES-ECB (one block).
/// RFC 9001 §5.4.4: ChaCha20-based header protection uses ChaCha20 keystream.
#[derive(Clone, Copy, Debug)]
pub enum HeaderCipher {
    /// AES-128-ECB; key is 16 bytes.
    Aes128,
    /// AES-256-ECB; key is 32 bytes.
    Aes256,
    /// ChaCha20; key is 32 bytes.
    ChaCha20,
}

// ── HeaderProtectionKey ───────────────────────────────────────────────────────

/// QUIC header-protection key (RFC 9001 §5.4).
pub struct HeaderProtectionKey {
    key: AeadKey,
    cipher: HeaderCipher,
    /// The AES key schedule, expanded once. `derive_mask` runs per packet, and the
    /// key does not change under it.
    aes: Option<HeaderAes>,
}

/// An AES key for the one block header protection encrypts.
enum HeaderAes {
    Aes128(Box<Aes128>),
}

impl HeaderProtectionKey {
    /// Construct a new header-protection key with the specified cipher variant.
    pub fn new(key: AeadKey, cipher: HeaderCipher) -> Self {
        let aes = match cipher {
            HeaderCipher::Aes128 => {
                let kb = key.as_ref();
                kb.get(..16)
                    .map(|k| HeaderAes::Aes128(Box::new(Aes128::new(GenericArray::from_slice(k)))))
            }
            _ => None,
        };
        Self { key, cipher, aes }
    }

    /// Derive the 5-byte mask from `sample` using the configured cipher.
    ///
    /// Returns `Err` if `sample` is not exactly `SAMPLE_LEN` bytes long.
    fn derive_mask(&self, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::General(
                "QUIC header protection: sample must be 16 bytes".into(),
            ));
        }

        match self.cipher {
            HeaderCipher::Aes128 => {
                // RFC 9001 §5.4.3 — AES-128-ECB
                let key_bytes = self.key.as_ref();
                if key_bytes.len() < 16 {
                    return Err(Error::General(
                        "QUIC header protection: AES-128 key must be 16 bytes".into(),
                    ));
                }
                let Some(HeaderAes::Aes128(cipher)) = &self.aes else {
                    return Err(Error::General(
                        "QUIC header protection: AES-128 key must be 16 bytes".into(),
                    ));
                };
                let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                let mask: [u8; MASK_LEN] = block[..MASK_LEN]
                    .try_into()
                    .map_err(|_| Error::General("invariant: AES block >= 5 bytes".into()))?;
                Ok(mask)
            }

            HeaderCipher::Aes256 => {
                // RFC 9001 §5.4.3 — AES-256-ECB
                let key_bytes = self.key.as_ref();
                if key_bytes.len() < 32 {
                    return Err(Error::General(
                        "QUIC header protection: AES-256 key must be 32 bytes".into(),
                    ));
                }
                let cipher = Aes256::new(GenericArray::from_slice(&key_bytes[..32]));
                let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                let mask: [u8; MASK_LEN] = block[..MASK_LEN]
                    .try_into()
                    .map_err(|_| Error::General("invariant: AES block >= 5 bytes".into()))?;
                Ok(mask)
            }

            HeaderCipher::ChaCha20 => {
                // RFC 9001 §5.4.4 — ChaCha20 header protection
                // counter = sample[0..4] as little-endian u32
                // nonce   = sample[4..16]
                let counter_bytes: [u8; 4] = sample[0..4]
                    .try_into()
                    .map_err(|_| Error::General("invariant: sample >= 4 bytes".into()))?;
                let counter = u32::from_le_bytes(counter_bytes);

                let nonce_bytes: &[u8; 12] = sample[4..16]
                    .try_into()
                    .map_err(|_| Error::General("invariant: sample[4..16] is 12 bytes".into()))?;

                let key_bytes = self.key.as_ref();
                if key_bytes.len() < 32 {
                    return Err(Error::General(
                        "QUIC header protection: ChaCha20 key must be 32 bytes".into(),
                    ));
                }

                let key_array: &[u8; 32] = key_bytes[..32]
                    .try_into()
                    .map_err(|_| Error::General("invariant: key >= 32 bytes".into()))?;

                let mut stream = ChaCha20Core::new(key_array.into(), nonce_bytes.into());

                // `seek` takes a byte offset; each block is 64 bytes.
                // The counter in RFC 9001 §5.4.4 is a block counter.
                let byte_offset: u64 = u64::from(counter).checked_mul(64).ok_or_else(|| {
                    Error::General("QUIC header protection: counter overflow".into())
                })?;
                stream
                    .try_seek(byte_offset)
                    .map_err(|_| Error::General("QUIC header protection: seek failed".into()))?;

                let mut mask = [0u8; MASK_LEN];
                stream.apply_keystream(&mut mask);
                Ok(mask)
            }
        }
    }

    /// Apply (or remove) header protection in-place using the given mask.
    ///
    /// `masked` controls whether we read the packet-number length *before* or
    /// *after* unmasking the first byte:
    ///   - `false` (encrypt): read from original `first` (before modification).
    ///   - `true`  (decrypt): read from `first ^ mask_byte` (after unmasking).
    ///
    /// Both operations are otherwise identical XOR applications.
    fn xor_in_place(
        mask: &[u8; MASK_LEN],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        if packet_number.len() > MAX_PN_LEN {
            return Err(Error::General(
                "QUIC header protection: packet number too long".into(),
            ));
        }

        // RFC 9001 §5.4.1 — Header Protection Application
        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f_u8 // long header: 4 bits masked
        } else {
            0x1f_u8 // short header: 5 bits masked
        };

        let (first_mask, pn_mask) = mask.split_first().expect("invariant: MASK_LEN >= 1");

        // When decrypting (unmasking), read PN length from the already-unmasked byte.
        let first_plain = if masked {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        // Infallible from this point — first and packet_number are now mutated.
        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask.iter()).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    /// Encrypt (protect) the QUIC packet header in-place.
    ///
    /// Reads the packet-number length from `first` *before* masking,
    /// then XORs `first` and `packet_number` with the derived mask.
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let mask = self.derive_mask(sample)?;
        Self::xor_in_place(&mask, first, packet_number, false)
    }

    /// Decrypt (remove protection from) the QUIC packet header in-place.
    ///
    /// Reads the packet-number length from `first` *after* unmasking,
    /// then XORs `first` and `packet_number` with the derived mask.
    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let mask = self.derive_mask(sample)?;
        Self::xor_in_place(&mask, first, packet_number, true)
    }

    /// Expected sample length for the key's algorithm (always 16 bytes).
    #[inline]
    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

// ── PacketKey ─────────────────────────────────────────────────────────────────

/// Which AEAD protects QUIC packet payloads.
///
/// Initial packets always use AES-128-GCM (RFC 9001 §5.2); handshake and 1-RTT
/// packets use the negotiated suite's AEAD, so the packet key must dispatch on
/// the suite rather than assume ChaCha20-Poly1305.
#[derive(Clone, Copy, Debug)]
pub enum PacketCipher {
    /// AES-128-GCM; key is 16 bytes.
    Aes128Gcm,
    /// AES-256-GCM; key is 32 bytes.
    Aes256Gcm,
    /// ChaCha20-Poly1305; key is 32 bytes.
    ChaCha20Poly1305,
}

/// QUIC packet key (RFC 9001 §5.3).
pub struct PacketKey {
    /// Computes unique nonces for each packet.
    iv: Iv,
    /// The cipher with its key schedule already expanded.
    ///
    /// quinn calls `encrypt_in_place`/`decrypt_in_place` once per packet, and at a
    /// few Gbit/s over loopback that is a quarter of a million packets a second.
    /// Building the AEAD here instead meant an AES key schedule *and* a fresh
    /// `polyval` `mulx` power ladder on every one of them, while the same key lives
    /// for the whole connection. This is the only AEAD in the tree that was not
    /// already holding its expanded key: shadowsocks, vmess and the TLS record
    /// layer all use [`crate::fastgcm::Gcm`], which does.
    ready: Ready,
}

/// The payload cipher, ready to use.
enum Ready {
    Aes128(crate::fastgcm::Gcm),
    Aes256(crate::fastgcm::Gcm),
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
}

impl PacketKey {
    /// Construct a new packet key from the given AEAD key and IV.
    ///
    /// `AeadKey` only has a public 32-byte constructor, while rustls hands
    /// AES-128 keys with `used == 16`. Normalize to the cipher's key length
    /// here so `as_ref` padding never reaches `new_from_slice`.
    pub fn new(cipher: PacketCipher, key: AeadKey, iv: Iv) -> Self {
        let want = match cipher {
            PacketCipher::Aes128Gcm => 16,
            PacketCipher::Aes256Gcm | PacketCipher::ChaCha20Poly1305 => 32,
        };
        let kb = key.as_ref();
        let n = kb.len().min(want);
        let mut buf = [0u8; 32];
        buf[..n].copy_from_slice(&kb[..n]);
        let ready = match cipher {
            PacketCipher::Aes128Gcm => Ready::Aes128(crate::fastgcm::Gcm::new(&buf[..n])),
            PacketCipher::Aes256Gcm => Ready::Aes256(crate::fastgcm::Gcm::new(&buf[..n])),
            PacketCipher::ChaCha20Poly1305 => Ready::ChaCha(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&buf[..n])
                    .expect("chacha key length"),
            ),
        };
        Self { iv, ready }
    }
}

/// Build the per-packet nonce (RFC 9001 §5.3): `iv XOR packet_number`.
fn nonce(iv: &Iv, packet_number: u64) -> [u8; 12] {
    cipher::Nonce::new(iv, packet_number).0
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = nonce(&self.iv, packet_number);
        let tag = match &self.ready {
            Ready::Aes128(cipher) | Ready::Aes256(cipher) => cipher.seal(&nonce, aad, payload),
            Ready::ChaCha(cipher) => cipher
                .encrypt_in_place_detached((&nonce).into(), aad, payload)
                .map_err(|_| Error::EncryptError)?
                .into(),
        };
        Ok(quic::Tag::from(tag.as_ref()))
    }

    /// Decrypt a QUIC packet.
    ///
    /// Takes the packet `header`, used as additional authenticated data, and the
    /// `payload`, which includes the authentication tag. On success the
    /// plaintext is found in `payload`, up to the returned length.
    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = nonce(&self.iv, packet_number);
        let plain_len = payload
            .len()
            .checked_sub(self.tag_len())
            .ok_or(Error::DecryptError)?;
        let (ciphertext, tag_bytes) = payload.split_at_mut(plain_len);
        let tag: [u8; 16] = tag_bytes.try_into().map_err(|_| Error::DecryptError)?;

        let ok = match &self.ready {
            Ready::Aes128(cipher) | Ready::Aes256(cipher) => {
                cipher.open(&nonce, aad, ciphertext, &tag)
            }
            Ready::ChaCha(cipher) => cipher
                .decrypt_in_place_detached((&nonce).into(), aad, ciphertext, (&tag).into())
                .is_ok(),
        };
        if !ok {
            return Err(Error::DecryptError);
        }
        Ok(&payload[..plain_len])
    }

    /// Tag length for the underlying AEAD algorithm (all supported AEADs use 16).
    #[inline]
    fn tag_len(&self) -> usize {
        16
    }

    fn integrity_limit(&self) -> u64 {
        1 << 36
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }
}

// ── KeyBuilder ────────────────────────────────────────────────────────────────

/// QUIC algorithm builder that produces [`PacketKey`] and [`HeaderProtectionKey`].
///
/// Holds no back-reference to the owning suite, so it can be named from a suite
/// `static` without a reference cycle.
pub struct KeyBuilder {
    /// Which AEAD protects packet payloads.
    packet: PacketCipher,
    /// Which cipher protects packet headers.
    header: HeaderCipher,
    /// AEAD key length in bytes for this algorithm.
    key_len: usize,
}

impl KeyBuilder {
    /// Builder for AES-128-GCM (`TLS13_AES_128_GCM_SHA256`).
    pub const AES_128: Self = Self {
        packet: PacketCipher::Aes128Gcm,
        header: HeaderCipher::Aes128,
        key_len: 16,
    };

    /// Builder for AES-256-GCM (`TLS13_AES_256_GCM_SHA384`).
    pub const AES_256: Self = Self {
        packet: PacketCipher::Aes256Gcm,
        header: HeaderCipher::Aes256,
        key_len: 32,
    };

    /// Builder for ChaCha20-Poly1305 (`TLS13_CHACHA20_POLY1305_SHA256`).
    pub const CHACHA20: Self = Self {
        packet: PacketCipher::ChaCha20Poly1305,
        header: HeaderCipher::ChaCha20,
        key_len: 32,
    };
}

impl rustls::quic::Algorithm for KeyBuilder {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey::new(self.packet, key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey::new(key, self.header))
    }

    fn aead_key_len(&self) -> usize {
        self.key_len
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::AeadKey;
    // Bring trait methods into scope, including for `dyn` trait objects.
    use rustls::quic::HeaderProtectionKey as QuicHpk;
    use rustls::quic::PacketKey as QuicPk;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build an `AeadKey` from a hex string (pads to MAX_LEN = 32 bytes).
    fn key_from_hex(hex: &str) -> AeadKey {
        let bytes = decode_hex(hex);
        let mut buf = [0u8; 32]; // AeadKey::MAX_LEN
        let copy_len = bytes.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        AeadKey::from(buf)
    }

    fn decode_hex(hex: &str) -> alloc::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex string"))
            .collect()
    }

    fn mask_from_hex(hex: &str) -> [u8; MASK_LEN] {
        let v = decode_hex(hex);
        v.try_into()
            .expect("hex must be exactly 5 bytes (10 hex chars)")
    }

    fn iv_from_hex(hex: &str) -> Iv {
        let v = decode_hex(hex);
        let buf: [u8; 12] = v.try_into().expect("hex must be exactly 12 bytes");
        Iv::from(buf)
    }

    /// AEAD key of the exact decoded length (AES-128 keys are 16 bytes).
    ///
    /// `AeadKey` only has a public `From<[u8; 32]>` constructor; shorter keys
    /// are left-aligned with zero padding, and `PacketKey::new` truncates to
    /// the cipher's real key length.
    fn aead_key(hex: &str) -> AeadKey {
        key_from_hex(hex)
    }

    // ── RFC 9001 Appendix A.2 — AES-128 test vector ───────────────────────────
    //
    // Header protection key : 9f50449e04a0e810283a1e9933adedd2
    // Sample                 : d1b1c98dd7689fb8ec11d242b123dc9b
    // Expected mask          : 437b9aec36

    #[test]
    fn test_aes128_mask_rfc9001_appendix_a2() {
        let hpk = HeaderProtectionKey::new(
            key_from_hex("9f50449e04a0e810283a1e9933adedd2"),
            HeaderCipher::Aes128,
        );
        let sample = decode_hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mask = hpk
            .derive_mask(&sample)
            .expect("derive_mask should succeed");
        assert_eq!(mask, mask_from_hex("437b9aec36"), "AES-128 mask mismatch");
    }

    // ── RFC 9001 Appendix A.5 — ChaCha20 test vector ─────────────────────────
    //
    // Header protection key : 25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4
    // Sample                 : 5e5cd55c41f69080575d7999c25a5bfb
    // Expected mask          : aefefe7d03

    #[test]
    fn test_chacha20_mask_rfc9001_appendix_a5() {
        let hpk = HeaderProtectionKey::new(
            key_from_hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            HeaderCipher::ChaCha20,
        );
        let sample = decode_hex("5e5cd55c41f69080575d7999c25a5bfb");
        let mask = hpk
            .derive_mask(&sample)
            .expect("derive_mask should succeed");
        assert_eq!(mask, mask_from_hex("aefefe7d03"), "ChaCha20 mask mismatch");
    }

    // ── Round-trip: encrypt then decrypt restores original header ─────────────

    fn roundtrip(cipher: HeaderCipher, key_hex: &str) {
        let hpk = HeaderProtectionKey::new(key_from_hex(key_hex), cipher);

        // Craft a synthetic short-header first byte and 4-byte packet number.
        // Short header: bit 7 == 0; bits 0-1 = 0b11 => pn_length = 4.
        let original_first: u8 = 0b0100_0011;
        let original_pn: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

        // Use the RFC 9001 AES-128 sample (always 16 bytes).
        let sample = decode_hex("d1b1c98dd7689fb8ec11d242b123dc9b");

        let mut first = original_first;
        let mut pn = original_pn;

        // Encrypt (protect).
        hpk.encrypt_in_place(&sample, &mut first, &mut pn)
            .expect("encrypt should succeed");

        // After encryption the bytes must differ.
        assert!(
            first != original_first || pn != original_pn,
            "encrypt must change something"
        );

        // Decrypt (remove protection).
        hpk.decrypt_in_place(&sample, &mut first, &mut pn)
            .expect("decrypt should succeed");

        assert_eq!(first, original_first, "first byte must be restored");
        assert_eq!(pn, original_pn, "packet number must be restored");
    }

    #[test]
    fn roundtrip_aes128() {
        roundtrip(HeaderCipher::Aes128, "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn roundtrip_aes256() {
        roundtrip(
            HeaderCipher::Aes256,
            "9f50449e04a0e810283a1e9933adedd29f50449e04a0e810283a1e9933adedd2",
        );
    }

    #[test]
    fn roundtrip_chacha20() {
        roundtrip(
            HeaderCipher::ChaCha20,
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
        );
    }

    // ── sample_len ────────────────────────────────────────────────────────────

    #[test]
    fn sample_len_is_16_for_all_ciphers() {
        for cipher in [
            HeaderCipher::Aes128,
            HeaderCipher::Aes256,
            HeaderCipher::ChaCha20,
        ] {
            let hpk = HeaderProtectionKey::new(
                key_from_hex("9f50449e04a0e810283a1e9933adedd29f50449e04a0e810283a1e9933adedd2"),
                cipher,
            );
            assert_eq!(
                hpk.sample_len(),
                16,
                "sample_len must be 16 for {:?}",
                cipher
            );
        }
    }

    // ── error cases ───────────────────────────────────────────────────────────

    #[test]
    fn derive_mask_rejects_short_sample() {
        let hpk = HeaderProtectionKey::new(
            key_from_hex("9f50449e04a0e810283a1e9933adedd2"),
            HeaderCipher::Aes128,
        );
        assert!(
            hpk.derive_mask(&[0u8; 15]).is_err(),
            "sample shorter than 16 bytes must fail"
        );
        assert!(
            hpk.derive_mask(&[0u8; 17]).is_err(),
            "sample longer than 16 bytes must fail"
        );
    }

    #[test]
    fn encrypt_rejects_long_packet_number() {
        let hpk = HeaderProtectionKey::new(
            key_from_hex("9f50449e04a0e810283a1e9933adedd2"),
            HeaderCipher::Aes128,
        );
        let sample = decode_hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mut first: u8 = 0x43;
        let mut pn = [0u8; 5]; // 5 bytes — exceeds MAX_PN_LEN
        assert!(
            hpk.encrypt_in_place(&sample, &mut first, &mut pn).is_err(),
            "packet number > 4 bytes must fail"
        );
    }

    // ── RFC 9001 Appendix A — packet protection vectors ───────────────────────
    //
    // A.3 Server Initial, AES-128-GCM:
    //   key = cf3a5331653c364c88f0f379b6067e37
    //   iv  = 0ac1493ca1905853b0bba03e
    //   unprotected header (pn = 1, 2-byte encoding) =
    //     c1000000010008f067a5502a4262b50040750001
    //   Expected ciphertext+tag (protected packet minus protected header):
    //     5a482cd0991cd25b0aac406a5816b6394100f37a...2158407dd074ee

    #[test]
    fn test_aes128_packet_key_rfc9001_appendix_a3() {
        let key = aead_key("cf3a5331653c364c88f0f379b6067e37");
        let iv = iv_from_hex("0ac1493ca1905853b0bba03e");
        let pk = PacketKey::new(PacketCipher::Aes128Gcm, key, iv);

        let aad = decode_hex("c1000000010008f067a5502a4262b50040750001");
        let mut payload = decode_hex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
             88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
             0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
             020304",
        );
        let tag = pk
            .encrypt_in_place(1, &aad, &mut payload)
            .expect("encrypt should succeed");
        let mut sealed = payload.clone();
        sealed.extend_from_slice(tag.as_ref());

        assert_eq!(
            sealed,
            decode_hex(
                "5a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3\
                 8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df35\
                 48e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd937\
                 95d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc421584\
                 07dd074ee"
            ),
            "AES-128-GCM payload protection mismatch"
        );
    }

    // A.5 ChaCha20-Poly1305 short header packet:
    //   key = c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8
    //   iv  = e0459b3474bdd0e44a41c144
    //   pn  = 654360564, unprotected header = 4200bff4, plaintext = 01
    //   Expected ciphertext+tag = 655e5cd55c41f69080575d7999c25a5bfb

    #[test]
    fn test_chacha_packet_key_rfc9001_appendix_a5() {
        let key = aead_key("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
        let iv = iv_from_hex("e0459b3474bdd0e44a41c144");
        let pk = PacketKey::new(PacketCipher::ChaCha20Poly1305, key, iv);

        let aad = decode_hex("4200bff4");
        let mut payload = decode_hex("01");
        let tag = pk
            .encrypt_in_place(654360564, &aad, &mut payload)
            .expect("encrypt should succeed");
        let mut sealed = payload;
        sealed.extend_from_slice(tag.as_ref());

        assert_eq!(
            sealed,
            decode_hex("655e5cd55c41f69080575d7999c25a5bfb"),
            "ChaCha20-Poly1305 payload protection mismatch"
        );
    }

    #[test]
    fn test_packet_key_roundtrip_all_ciphers() {
        // Each AEAD requires its exact key length: AES-128 = 16, others = 32.
        let cases = [
            (PacketCipher::Aes128Gcm, "000102030405060708090a0b0c0d0e0f"),
            (
                PacketCipher::Aes256Gcm,
                "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            ),
            (
                PacketCipher::ChaCha20Poly1305,
                "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            ),
        ];
        for (cipher, key_hex) in cases {
            let key = aead_key(key_hex);
            let iv = Iv::from([0x11u8; 12]);
            let pk = PacketKey::new(cipher, key, iv);

            let aad = b"header bytes";
            let plaintext = b"the quick brown fox";

            let mut sealed = plaintext.to_vec();
            let tag = pk
                .encrypt_in_place(7, aad, &mut sealed)
                .expect("encrypt should succeed");
            sealed.extend_from_slice(tag.as_ref());

            let plain = pk
                .decrypt_in_place(7, aad, &mut sealed)
                .expect("decrypt should succeed");
            assert_eq!(plain, plaintext, "round-trip mismatch for {cipher:?}");
        }
    }

    // ── long-header masking (bits 0x0f) ───────────────────────────────────────

    #[test]
    fn long_header_uses_0x0f_mask_bits() {
        let hpk = HeaderProtectionKey::new(
            key_from_hex("9f50449e04a0e810283a1e9933adedd2"),
            HeaderCipher::Aes128,
        );
        let sample = decode_hex("d1b1c98dd7689fb8ec11d242b123dc9b");

        // Long header: bit 7 set; pn_length = 1 (bits 0-1 = 0b00).
        let original_first: u8 = 0b1100_0000;
        let mut first = original_first;
        let mut pn = [0xAB_u8; 4];
        let original_pn = pn;

        hpk.encrypt_in_place(&sample, &mut first, &mut pn)
            .expect("encrypt should succeed for long-header test");
        hpk.decrypt_in_place(&sample, &mut first, &mut pn)
            .expect("decrypt should succeed for long-header test");

        assert_eq!(first, original_first);
        assert_eq!(pn, original_pn);
    }
}
