//! Payload seal/open for the v4 record codec on the `fastgcm` backend.
//!
//! The record writer hands over up to [`BATCH_MAX`] records at a time; each
//! one goes through `core_crypto::fastgcm::Gcm`, which keeps eight counter
//! blocks in flight for the CTR encrypt and folds eight GHASH blocks against
//! the powers of H per reduction — AES-NI and PCLMULQDQ on x86_64, AESE and
//! PMULL on aarch64 (the router path that used to run `aes-gcm`'s serial
//! fallback, since the previous backend was x86_64-only), RustCrypto
//! elsewhere. The batched entry points and the byte-identical-to-`aes-gcm`
//! contract stay as they were, so `record.rs` does not notice.

use core_crypto::fastgcm::Gcm;
use std::io;

use super::crypto::{AEAD_TAG_LEN, NONCE_LEN};

/// Records handed to the sealer in one group.
pub(crate) const BATCH_MAX: usize = 4;

/// Seals the payload regions `out[r.0..r.1]` in place under `nonces`,
/// writing each record's tag. `count` entries are live; regions must not
/// overlap. The output is byte-identical to sealing each region with
/// `Aes128Gcm` on its own.
pub(crate) struct BatchSealer {
    gcm: Gcm,
}

impl BatchSealer {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        Self { gcm: Gcm::new(key) }
    }

    pub(crate) fn seal(
        &self,
        out: &mut [u8],
        ranges: &[(usize, usize); BATCH_MAX],
        count: usize,
        nonces: &[[u8; NONCE_LEN]; BATCH_MAX],
        tags: &mut [[u8; AEAD_TAG_LEN]; BATCH_MAX],
    ) {
        for i in 0..count {
            let (start, end) = ranges[i];
            tags[i] = self.gcm.seal(&nonces[i], &[], &mut out[start..end]);
        }
    }
}

/// The decrypting twin of [`BatchSealer`]: tag verified in constant time,
/// ciphertext decrypted only after the check so GHASH always sees the wire
/// bytes.
pub(crate) struct FastOpener {
    gcm: Gcm,
}

impl FastOpener {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        Self { gcm: Gcm::new(key) }
    }

    /// Open `region` (ciphertext immediately followed by its 16 byte tag)
    /// in place. The signature and failure mode mirror `crypto::open_region`
    /// so the reader swaps one call.
    pub(crate) fn open(&self, nonce: &[u8; NONCE_LEN], region: &mut [u8]) -> io::Result<()> {
        if region.len() < AEAD_TAG_LEN {
            return Err(io::Error::other("snell: open record"));
        }
        let ct_len = region.len() - AEAD_TAG_LEN;
        let mut expected = [0u8; AEAD_TAG_LEN];
        expected.copy_from_slice(&region[ct_len..]);
        if !self.gcm.open(nonce, &[], &mut region[..ct_len], &expected) {
            return Err(io::Error::other("snell: open record"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

    use super::*;

    /// A deterministic filler so runs compare the same bytes.
    fn fill(buf: &mut [u8], seed: u8) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
    }

    /// The batched seal must be byte-identical to per-record `aes-gcm`
    /// sealing for every record count and the size classes the payload
    /// window produces (odd tails, block boundaries, full 16 KiB records).
    #[test]
    fn batch_matches_serial_aes_gcm() {
        let key = [0x42u8; 16];
        let sealer = BatchSealer::new(&key);
        let gcm = Aes128Gcm::new_from_slice(&key).expect("key");

        for &size in &[1usize, 15, 16, 17, 64, 1400, 1421, 16_383] {
            for count in 1..=BATCH_MAX {
                let mut ranges = [(0usize, 0usize); BATCH_MAX];
                let mut out = Vec::new();
                for (i, range) in ranges.iter_mut().enumerate().take(count) {
                    let start = out.len();
                    out.resize(start + size, 0u8);
                    fill(&mut out[start..], (i as u8) ^ size as u8);
                    *range = (start, out.len());
                }
                let mut serial = out.clone();
                let mut nonces = [[0u8; NONCE_LEN]; BATCH_MAX];
                let mut expected = [[0u8; AEAD_TAG_LEN]; BATCH_MAX];
                for i in 0..count {
                    nonces[i][0] = i as u8 + 1;
                    nonces[i][11] = size as u8;
                    let (start, end) = ranges[i];
                    let tag = gcm
                        .encrypt_in_place_detached(
                            Nonce::from_slice(&nonces[i]),
                            &[],
                            &mut serial[start..end],
                        )
                        .expect("serial seal");
                    expected[i].copy_from_slice(&tag);
                }

                let mut tags = [[0u8; AEAD_TAG_LEN]; BATCH_MAX];
                sealer.seal(&mut out, &ranges, count, &nonces, &mut tags);

                assert_eq!(out, serial, "ciphertext diverged: size={size} n={count}");
                for i in 0..count {
                    assert_eq!(
                        tags[i], expected[i],
                        "tag diverged: size={size} n={count} i={i}"
                    );
                }
            }
        }
    }

    /// Full-width records with independent nonces across a batch: the
    /// steady-state shape the writer hits once the payload window has grown.
    #[test]
    fn batch_full_records_with_distinct_nonces() {
        let key = [0x07u8; 16];
        let sealer = BatchSealer::new(&key);
        let gcm = Aes128Gcm::new_from_slice(&key).expect("key");

        let size = 16_383;
        let count = BATCH_MAX;
        let mut ranges = [(0usize, 0usize); BATCH_MAX];
        let mut out = Vec::new();
        for (i, range) in ranges.iter_mut().enumerate().take(count) {
            let start = out.len();
            out.resize(start + size, 0u8);
            fill(&mut out[start..], 0xA0 + i as u8);
            *range = (start, out.len());
        }
        let mut serial = out.clone();
        let mut nonces = [[0u8; NONCE_LEN]; BATCH_MAX];
        let mut expected = [[0u8; AEAD_TAG_LEN]; BATCH_MAX];
        for i in 0..count {
            nonces[i][0] = 0x11 * (i as u8 + 1);
            nonces[i][6] = 0x5C;
            let (start, end) = ranges[i];
            let tag = gcm
                .encrypt_in_place_detached(
                    Nonce::from_slice(&nonces[i]),
                    &[],
                    &mut serial[start..end],
                )
                .expect("serial seal");
            expected[i].copy_from_slice(&tag);
        }

        let mut tags = [[0u8; AEAD_TAG_LEN]; BATCH_MAX];
        sealer.seal(&mut out, &ranges, count, &nonces, &mut tags);

        assert_eq!(out, serial);
        assert_eq!(tags, expected);
    }

    /// The opener must restore exactly the plaintext `aes-gcm` produced and
    /// reject a flipped tag bit.
    #[test]
    fn opener_roundtrip_and_tag_reject() {
        let key = [0x07u8; 16];
        let opener = FastOpener::new(&key);
        let gcm = Aes128Gcm::new_from_slice(&key).expect("key");

        for &size in &[1usize, 15, 16, 17, 64, 1400, 1421, 16_383] {
            let mut nonce = [0u8; NONCE_LEN];
            nonce[0] = size as u8;
            nonce[11] = 0x5A;
            let mut plain = vec![0u8; size];
            fill(&mut plain, size as u8);
            let mut ct = plain.clone();
            let tag = gcm
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut ct)
                .expect("encrypt");
            let mut region = ct;
            region.extend_from_slice(&tag);
            opener.open(&nonce, &mut region).expect("open");
            assert_eq!(
                &region[..size],
                &plain[..],
                "plaintext diverged: size={size}"
            );

            let mut bad = region;
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(
                opener.open(&nonce, &mut bad).is_err(),
                "tag accepted: size={size}"
            );
        }
    }

    /// What a four-record batch costs against per-record `aes-gcm` sealing.
    /// Run with `cargo test --release -p core-runtime --lib seal_batch_speed
    /// -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn seal_batch_speed() {
        let key = [0x42u8; 16];
        let sealer = BatchSealer::new(&key);
        let gcm = Aes128Gcm::new_from_slice(&key).expect("key");

        let size = 16_383;
        let count = BATCH_MAX;
        let iters = 2_000usize;
        let mut ranges = [(0usize, 0usize); BATCH_MAX];
        let mut out = Vec::new();
        for (i, range) in ranges.iter_mut().enumerate().take(count) {
            let start = out.len();
            out.resize(start + size, 0u8);
            fill(&mut out[start..], i as u8);
            *range = (start, out.len());
        }
        let mut nonces = [[0u8; NONCE_LEN]; BATCH_MAX];
        for (i, nonce) in nonces.iter_mut().enumerate().take(count) {
            nonce[0] = i as u8;
        }

        let mut serial = out.clone();
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            for i in 0..count {
                let (s, e) = ranges[i];
                let _ = gcm
                    .encrypt_in_place_detached(
                        Nonce::from_slice(&nonces[i]),
                        &[],
                        &mut serial[s..e],
                    )
                    .expect("seal");
            }
        }
        let serial_dt = t0.elapsed();

        let mut tags = [[0u8; AEAD_TAG_LEN]; BATCH_MAX];
        let t1 = std::time::Instant::now();
        for _ in 0..iters {
            sealer.seal(&mut out, &ranges, count, &nonces, &mut tags);
        }
        let batch_dt = t1.elapsed();

        let gib = (iters * count * size) as f64 / (1u64 << 30) as f64;
        let msg = format!(
            "serial: {:.3} s/GiB   batch: {:.3} s/GiB   speedup {:.2}x\n",
            serial_dt.as_secs_f64() / gib,
            batch_dt.as_secs_f64() / gib,
            serial_dt.as_secs_f64() / batch_dt.as_secs_f64()
        );
        let _ = std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/bench/seal-speed.txt"
            ),
            &msg,
        );
        print!("{msg}");
    }
}
