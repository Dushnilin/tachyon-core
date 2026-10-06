//! Batched payload seal/open for the v4 record codec: CTR on the `ctr`
//! backend, GHASH evaluated four blocks at a time on precomputed powers of H.
//!
//! GCM's GHASH is a serial carry-less multiply chain: a single 16 KiB record
//! keeps one chain of dependent multiplies running with nothing else to
//! overlap against, and on the hot path that chain alone showed up as half
//! the user time. Because the reduction is linear, four consecutive blocks
//! expand algebraically into products against H^4..H^1 — five multiplies
//! whose only serial dependency is one accumulator step per four blocks, so
//! the out-of-order core keeps them in flight and the per-block cost drops
//! towards the port throughput instead of the multiply latency. The
//! polynomial math mirrors the `polyval` crate's CLMUL backend, with the
//! byte reversals `ghash` applies to run GHASH over POLYVAL's reversed field
//! representation.

use aes::Aes128;
use aes::cipher::{
    consts::U16, generic_array::GenericArray, BlockEncrypt, InnerIvInit, KeyInit, StreamCipherCore,
};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce};
#[cfg(target_arch = "x86_64")]
use subtle::ConstantTimeEq;
use std::io;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::crypto::{AEAD_TAG_LEN, NONCE_LEN};

/// Records sealed together in one interleaved GHASH pass.
pub(crate) const BATCH_MAX: usize = 4;

/// GCM block size (coincides with the tag length, kept separate on purpose).
const BLOCK_LEN: usize = 16;

pub(crate) struct BatchSealer {
    #[cfg(target_arch = "x86_64")]
    aes: Aes128,
    /// `H, H^2, H^3, H^4` in POLYVAL form, stored as bytes so the struct
    /// stays valid on machines whose CPUID reports no carry-less multiply.
    #[cfg(target_arch = "x86_64")]
    powers: [[u8; 16]; 4],
    key: [u8; 16],
}

type PayloadCtr<'a> = ctr::CtrCore<&'a Aes128, ctr::flavors::Ctr32BE>;

/// The decrypting twin of [`BatchSealer`]: same H powers, tag verified in
/// constant time, ciphertext decrypted after the hash so GHASH always sees
/// the wire bytes.
pub(crate) struct FastOpener {
    key: [u8; 16],
    #[cfg(target_arch = "x86_64")]
    aes: Aes128,
    #[cfg(target_arch = "x86_64")]
    powers: [[u8; 16]; 4],
}

/// `H, H^2, H^3, H^4` for `key`, zeros when the CPU has no PCLMUL (the
/// caller falls back to `aes-gcm` in that case).
fn powers_for(key: &[u8; 16]) -> [[u8; 16]; 4] {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            let h1 = ghash_polyval_key(key);
            return unsafe { compute_powers(h1) };
        }
    }
    [[0u8; 16]; 4]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,ssse3")]
unsafe fn compute_powers(h1: [u8; 16]) -> [[u8; 16]; 4] {
    unsafe {
        let one = _mm_loadu_si128(h1.as_ptr() as *const __m128i);
        let two = polyval_mul(one, one);
        let three = polyval_mul(two, one);
        let four = polyval_mul(two, two);
        let mut out = [[0u8; 16]; 4];
        for (slot, value) in out.iter_mut().zip([one, two, three, four]) {
            _mm_storeu_si128(slot.as_mut_ptr() as *mut __m128i, value);
        }
        out
    }
}

impl BatchSealer {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            aes: Aes128::new(GenericArray::from_slice(key)),
            #[cfg(target_arch = "x86_64")]
            powers: powers_for(key),
            key: *key,
        }
    }

    /// Seal the payload regions `out[r.0..r.1]` in place under `nonces`,
    /// writing each record's tag. `count` entries are live; regions must not
    /// overlap. The output is byte-identical to sealing each region with
    /// `Aes128Gcm` on its own — the batching only changes how the GHASH
    /// chains are scheduled.
    pub(crate) fn seal(
        &self,
        out: &mut [u8],
        ranges: &[(usize, usize); BATCH_MAX],
        count: usize,
        nonces: &[[u8; NONCE_LEN]; BATCH_MAX],
        tags: &mut [[u8; AEAD_TAG_LEN]; BATCH_MAX],
    ) {
        if count == 0 {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("pclmulqdq")
                && std::is_x86_feature_detected!("ssse3")
            {
                unsafe {
                    self.seal_fast(out, ranges, count, nonces, tags);
                }
                return;
            }
        }
        self.seal_serial(out, ranges, count, nonces, tags);
    }

    /// Per-record reference path: the same `aes-gcm` call the writer made
    /// before batching existed, kept as the fallback for targets without
    /// the carry-less multiply instructions.
    fn seal_serial(
        &self,
        out: &mut [u8],
        ranges: &[(usize, usize); BATCH_MAX],
        count: usize,
        nonces: &[[u8; NONCE_LEN]; BATCH_MAX],
        tags: &mut [[u8; AEAD_TAG_LEN]; BATCH_MAX],
    ) {
        let gcm = Aes128Gcm::new_from_slice(&self.key).expect("snell: aes-128-gcm key");
        for i in 0..count {
            let (start, end) = ranges[i];
            let tag = gcm
                .encrypt_in_place_detached(Nonce::from_slice(&nonces[i]), &[], &mut out[start..end])
                .expect("snell: seal record");
            tags[i].copy_from_slice(&tag);
        }
    }

    /// Per record: CTR encrypts in place, then GHASH hashes the ciphertext
    /// four blocks at a time against the H powers and the tag falls out of
    /// the accumulator XOR the counter's first block.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "pclmulqdq,ssse3")]
    unsafe fn seal_fast(
        &self,
        out: &mut [u8],
        ranges: &[(usize, usize); BATCH_MAX],
        count: usize,
        nonces: &[[u8; NONCE_LEN]; BATCH_MAX],
        tags: &mut [[u8; AEAD_TAG_LEN]; BATCH_MAX],
    ) {
        unsafe {
            let h1 = _mm_loadu_si128(self.powers[0].as_ptr() as *const __m128i);
            let h2 = _mm_loadu_si128(self.powers[1].as_ptr() as *const __m128i);
            let h3 = _mm_loadu_si128(self.powers[2].as_ptr() as *const __m128i);
            let h4 = _mm_loadu_si128(self.powers[3].as_ptr() as *const __m128i);
            let rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

            for i in 0..count {
                let (start, end) = ranges[i];
                let mut j0 = GenericArray::<u8, U16>::default();
                j0[..NONCE_LEN].copy_from_slice(&nonces[i]);
                j0[15] = 1;
                let mut ctr = PayloadCtr::inner_iv_init(&self.aes, &j0);
                let mut mask = GenericArray::<u8, U16>::default();
                ctr.write_keystream_block(&mut mask);
                ctr.apply_keystream_partial((&mut out[start..end]).into());

                let y = ghash_4way(h1, h2, h3, h4, rev, &out[start..end]);
                let mut tag = [0u8; AEAD_TAG_LEN];
                let finished = _mm_shuffle_epi8(y, rev);
                _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, finished);
                for byte in 0..AEAD_TAG_LEN {
                    tags[i][byte] = tag[byte] ^ mask[byte];
                }
            }
        }
    }
}

/// GHASH's `H = E_K(0)` mapped into POLYVAL's field: `mulx(reverse(H))`,
/// exactly what `ghash::GHash::new` computes.
#[cfg(target_arch = "x86_64")]
fn ghash_polyval_key(key: &[u8; 16]) -> [u8; 16] {
    let aes = Aes128::new(GenericArray::from_slice(key));
    let mut h = [0u8; AEAD_TAG_LEN];
    aes.encrypt_block(GenericArray::from_mut_slice(&mut h));
    h.reverse();
    mulx(&h)
}

/// The `mulX_POLYVAL()` doubling from RFC 8452 Appendix A.
#[cfg(target_arch = "x86_64")]
fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;
    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

/// Carry-less `a * b` over GF(2^128) as the unreduced 256-bit product in
/// four 64-bit limbs (the Karatsuba assembly `polyval`'s backend uses
/// before reduction).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn clmul256(a: __m128i, b: __m128i) -> [__m128i; 4] {
    unsafe {
        let b0 = b;
        let b1 = _mm_shuffle_epi32(b, 0x0E);
        let b2 = _mm_xor_si128(b0, b1);
        let a0 = a;
        let a1 = _mm_shuffle_epi32(a, 0x0E);
        let a2 = _mm_xor_si128(a0, a1);
        let t0 = _mm_clmulepi64_si128(a0, b0, 0x00);
        let t1 = _mm_clmulepi64_si128(a, b, 0x11);
        let t2 = _mm_clmulepi64_si128(a2, b2, 0x00);
        let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
        [
            t0,
            _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2),
            _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E)),
            _mm_shuffle_epi32(t1, 0x0E),
        ]
    }
}

/// Shift-and-xor reduction of a 256-bit product down to one field element
/// (mirrors `polyval`'s CLMUL backend). Linear over GF(2), which is what
/// lets four products XOR together before a single reduction.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn reduce256(v: [__m128i; 4]) -> __m128i {
    unsafe {
        let [v0, v1, v2, v3] = v;
        let v2 = xor5(
            v2,
            v0,
            _mm_srli_epi64(v0, 1),
            _mm_srli_epi64(v0, 2),
            _mm_srli_epi64(v0, 7),
        );
        let v1 = xor4(
            v1,
            _mm_slli_epi64(v0, 63),
            _mm_slli_epi64(v0, 62),
            _mm_slli_epi64(v0, 57),
        );
        let v3 = xor5(
            v3,
            v1,
            _mm_srli_epi64(v1, 1),
            _mm_srli_epi64(v1, 2),
            _mm_srli_epi64(v1, 7),
        );
        let v2 = xor4(
            v2,
            _mm_slli_epi64(v1, 63),
            _mm_slli_epi64(v1, 62),
            _mm_slli_epi64(v1, 57),
        );
        _mm_unpacklo_epi64(v2, v3)
    }
}

/// One POLYVAL multiplication step: `y <- (y ^ x) * h` over GF(2^128) in
/// the reversed field representation, three carry-less multiplies and the
/// shift-and-xor reduction (mirrors `polyval`'s CLMUL backend).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn polyval_mul(y: __m128i, h: __m128i) -> __m128i {
    unsafe { reduce256(clmul256(y, h)) }
}

/// GHASH over `data` with the block chain expanded four blocks at a time:
/// `y_out = y_in * H^4 ^ x0 * H^4 ^ x1 * H^3 ^ x2 * H^2 ^ x3 * H`, five
/// multiplies whose products XOR in unreduced form before one reduction.
/// Full groups of four run the algebraic form, the odd tail and the length
/// block finish serially, and the result includes the length block (GCM's
/// final GHASH step).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,ssse3")]
unsafe fn ghash_4way(
    h1: __m128i,
    h2: __m128i,
    h3: __m128i,
    h4: __m128i,
    rev: __m128i,
    data: &[u8],
) -> __m128i {
    unsafe {
        let mut y = _mm_setzero_si128();
        let full = data.len() / BLOCK_LEN;
        let groups = full / 4;
        for g in 0..groups {
            let base = g * 4 * BLOCK_LEN;
            let mut prod = clmul256(y, h4);
            for k in 0..4 {
                let raw = _mm_loadu_si128(data.as_ptr().add(base + k * BLOCK_LEN) as *const __m128i);
                let x = _mm_shuffle_epi8(raw, rev);
                let hk = match k {
                    0 => h4,
                    1 => h3,
                    2 => h2,
                    _ => h1,
                };
                let p = clmul256(x, hk);
                prod = [
                    _mm_xor_si128(prod[0], p[0]),
                    _mm_xor_si128(prod[1], p[1]),
                    _mm_xor_si128(prod[2], p[2]),
                    _mm_xor_si128(prod[3], p[3]),
                ];
            }
            y = reduce256(prod);
        }
        for b in (groups * 4)..full {
            let raw = _mm_loadu_si128(data.as_ptr().add(b * BLOCK_LEN) as *const __m128i);
            let x = _mm_shuffle_epi8(raw, rev);
            y = polyval_mul(_mm_xor_si128(y, x), h1);
        }
        let rem = data.len() % BLOCK_LEN;
        if rem > 0 {
            let mut last = [0u8; BLOCK_LEN];
            core::ptr::copy_nonoverlapping(
                data.as_ptr().add(full * BLOCK_LEN),
                last.as_mut_ptr(),
                rem,
            );
            let raw = _mm_loadu_si128(last.as_ptr() as *const __m128i);
            let x = _mm_shuffle_epi8(raw, rev);
            y = polyval_mul(_mm_xor_si128(y, x), h1);
        }
        let mut lengths = [0u8; BLOCK_LEN];
        lengths[8..].copy_from_slice(&((data.len() as u64) << 3).to_be_bytes());
        let raw = _mm_loadu_si128(lengths.as_ptr() as *const __m128i);
        let x = _mm_shuffle_epi8(raw, rev);
        polyval_mul(_mm_xor_si128(y, x), h1)
    }
}

impl FastOpener {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        Self {
            key: *key,
            #[cfg(target_arch = "x86_64")]
            aes: Aes128::new(GenericArray::from_slice(key)),
            #[cfg(target_arch = "x86_64")]
            powers: powers_for(key),
        }
    }

    /// Open `region` (ciphertext immediately followed by its 16 byte tag)
    /// in place: GHASH over the still-sealed bytes, constant-time tag
    /// compare, then CTR. The signature and failure mode mirror
    /// `crypto::open_region` so the reader swaps one call.
    pub(crate) fn open(&self, nonce: &[u8; NONCE_LEN], region: &mut [u8]) -> io::Result<()> {
        if region.len() < AEAD_TAG_LEN {
            return Err(io::Error::other("snell: open record"));
        }
        let ct_len = region.len() - AEAD_TAG_LEN;
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            return unsafe { self.open_fast(nonce, region, ct_len) };
        }
        let cipher = Aes128Gcm::new_from_slice(&self.key).expect("snell: aes-128-gcm key");
        let (ct, tag) = region.split_at_mut(ct_len);
        let tag = aes_gcm::aead::Tag::<Aes128Gcm>::from_slice(tag);
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce), &[], ct, tag)
            .map_err(|_| io::Error::other("snell: open record"))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "pclmulqdq,ssse3")]
    unsafe fn open_fast(
        &self,
        nonce: &[u8; NONCE_LEN],
        region: &mut [u8],
        ct_len: usize,
    ) -> io::Result<()> {
        unsafe {
            let mut j0 = GenericArray::<u8, U16>::default();
            j0[..NONCE_LEN].copy_from_slice(nonce);
            j0[15] = 1;
            let mut ctr = PayloadCtr::inner_iv_init(&self.aes, &j0);
            let mut mask = GenericArray::<u8, U16>::default();
            ctr.write_keystream_block(&mut mask);

            let h1 = _mm_loadu_si128(self.powers[0].as_ptr() as *const __m128i);
            let h2 = _mm_loadu_si128(self.powers[1].as_ptr() as *const __m128i);
            let h3 = _mm_loadu_si128(self.powers[2].as_ptr() as *const __m128i);
            let h4 = _mm_loadu_si128(self.powers[3].as_ptr() as *const __m128i);
            let rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

            let y = ghash_4way(h1, h2, h3, h4, rev, &region[..ct_len]);
            let mut expected = [0u8; AEAD_TAG_LEN];
            let finished = _mm_shuffle_epi8(y, rev);
            _mm_storeu_si128(expected.as_mut_ptr() as *mut __m128i, finished);
            for byte in 0..AEAD_TAG_LEN {
                expected[byte] ^= mask[byte];
            }
            if !bool::from(expected.ct_eq(&region[ct_len..])) {
                return Err(io::Error::other("snell: open record"));
            }
            ctr.apply_keystream_partial((&mut region[..ct_len]).into());
            Ok(())
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn xor4(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(_mm_xor_si128(a, b), _mm_xor_si128(c, d)) }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn xor5(a: __m128i, b: __m128i, c: __m128i, d: __m128i, e: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, xor4(b, c, d, e)) }
}

#[cfg(test)]
mod tests {
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
                for i in 0..count {
                    let start = out.len();
                    out.resize(start + size, 0u8);
                    fill(&mut out[start..], (i as u8) ^ size as u8);
                    ranges[i] = (start, out.len());
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
                    assert_eq!(tags[i], expected[i], "tag diverged: size={size} n={count} i={i}");
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
        for i in 0..count {
            let start = out.len();
            out.resize(start + size, 0u8);
            fill(&mut out[start..], 0xA0 + i as u8);
            ranges[i] = (start, out.len());
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

    /// The four-block algebraic expansion must equal the serial carry-less
    /// chain for every size class: full groups, odd tails, empty data.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ghash_4way_matches_serial_chain() {
        if !(std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3"))
        {
            return;
        }
        let key = [0x42u8; 16];
        let powers = powers_for(&key);
        unsafe {
            let h1 = _mm_loadu_si128(powers[0].as_ptr() as *const __m128i);
            let h2 = _mm_loadu_si128(powers[1].as_ptr() as *const __m128i);
            let h3 = _mm_loadu_si128(powers[2].as_ptr() as *const __m128i);
            let h4 = _mm_loadu_si128(powers[3].as_ptr() as *const __m128i);
            let rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

            for &size in &[0usize, 1, 15, 16, 17, 63, 64, 65, 1400, 1421, 16_383] {
                let mut data = vec![0u8; size];
                fill(&mut data, size as u8);

                let mut y = _mm_setzero_si128();
                let full = size / BLOCK_LEN;
                for b in 0..full {
                    let raw = _mm_loadu_si128(data.as_ptr().add(b * BLOCK_LEN) as *const __m128i);
                    let x = _mm_shuffle_epi8(raw, rev);
                    y = polyval_mul(_mm_xor_si128(y, x), h1);
                }
                let rem = size % BLOCK_LEN;
                if rem > 0 {
                    let mut last = [0u8; BLOCK_LEN];
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(full * BLOCK_LEN),
                        last.as_mut_ptr(),
                        rem,
                    );
                    let raw = _mm_loadu_si128(last.as_ptr() as *const __m128i);
                    let x = _mm_shuffle_epi8(raw, rev);
                    y = polyval_mul(_mm_xor_si128(y, x), h1);
                }
                let mut lengths = [0u8; BLOCK_LEN];
                lengths[8..].copy_from_slice(&((size as u64) << 3).to_be_bytes());
                let raw = _mm_loadu_si128(lengths.as_ptr() as *const __m128i);
                let x = _mm_shuffle_epi8(raw, rev);
                let serial = polyval_mul(_mm_xor_si128(y, x), h1);

                let fast = ghash_4way(h1, h2, h3, h4, rev, &data);
                let mut got = [0u8; 16];
                let mut want = [0u8; 16];
                _mm_storeu_si128(got.as_mut_ptr() as *mut __m128i, fast);
                _mm_storeu_si128(want.as_mut_ptr() as *mut __m128i, serial);
                assert_eq!(got, want, "ghash diverged: size={size}");
            }
        }
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
            assert_eq!(&region[..size], &plain[..], "plaintext diverged: size={size}");

            let mut bad = region;
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(opener.open(&nonce, &mut bad).is_err(), "tag accepted: size={size}");
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
        for i in 0..count {
            let start = out.len();
            out.resize(start + size, 0u8);
            fill(&mut out[start..], i as u8);
            ranges[i] = (start, out.len());
        }
        let mut nonces = [[0u8; NONCE_LEN]; BATCH_MAX];
        for i in 0..count {
            nonces[i][0] = i as u8;
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
        let _ = std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/bench/seal-speed.txt"), &msg);
        print!("{msg}");
    }
}
