//! AES-GCM on AES-NI and PCLMULQDQ, written here so the hot path does not
//! depend on `ring` and does not go through the generic `aes-gcm` plumbing.
//!
//! The x86_64 path keeps eight blocks in flight: the counter blocks are
//! encrypted together, and the eight ciphertext blocks are folded into GHASH
//! with the powers H^8..H^1, so the carry-less products are summed first and
//! the polynomial is reduced once per 128 bytes. Everything else (other
//! architectures, a CPU without the instructions) goes to RustCrypto's
//! `aes-gcm`, which is the oracle the tests compare against.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Tag};

pub enum Gcm {
    #[cfg(target_arch = "x86_64")]
    Ni(Box<ni::Ni>),
    Soft128(Box<Aes128Gcm>),
    Soft256(Box<Aes256Gcm>),
}

impl Gcm {
    /// `key` is 16 or 32 bytes; the callers derive it with a fixed length.
    pub fn new(key: &[u8]) -> Gcm {
        #[cfg(target_arch = "x86_64")]
        if ni::available() {
            return Gcm::Ni(Box::new(ni::Ni::new(key)));
        }
        match key.len() {
            16 => Gcm::Soft128(Box::new(Aes128Gcm::new(key.into()))),
            32 => Gcm::Soft256(Box::new(Aes256Gcm::new(key.into()))),
            n => panic!("aes-gcm key must be 16 or 32 bytes, got {n}"),
        }
    }

    /// Encrypt `buf` in place and return the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        match self {
            #[cfg(target_arch = "x86_64")]
            Gcm::Ni(ni) => ni.seal(nonce, aad, buf),
            Gcm::Soft128(c) => c
                .encrypt_in_place_detached(nonce.into(), aad, buf)
                .expect("gcm length is in range")
                .into(),
            Gcm::Soft256(c) => c
                .encrypt_in_place_detached(nonce.into(), aad, buf)
                .expect("gcm length is in range")
                .into(),
        }
    }

    /// Decrypt `buf` in place. On a bad tag nothing of the plaintext is left
    /// in `buf` and the answer is `false`.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        match self {
            #[cfg(target_arch = "x86_64")]
            Gcm::Ni(ni) => ni.open(nonce, aad, buf, tag),
            Gcm::Soft128(c) => c
                .decrypt_in_place_detached(nonce.into(), aad, buf, Tag::from_slice(tag))
                .is_ok(),
            Gcm::Soft256(c) => c
                .decrypt_in_place_detached(nonce.into(), aad, buf, Tag::from_slice(tag))
                .is_ok(),
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod ni {
    #![allow(unused_unsafe)]

    use core::arch::x86_64::*;

    /// Round keys and the powers of H. `h[i]` is H^(i+1) in the byte-reversed
    /// domain the multiplication works in.
    pub struct Ni {
        rk: [__m128i; 16],
        nr: usize,
        h: [__m128i; 8],
    }

    pub(super) fn available() -> bool {
        is_x86_feature_detected!("aes")
            && is_x86_feature_detected!("pclmulqdq")
            && is_x86_feature_detected!("sse4.1")
            && is_x86_feature_detected!("ssse3")
    }

    /// Unreduced 256-bit sum of carry-less products: low, middle, high.
    type Acc = (__m128i, __m128i, __m128i);

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn zero() -> __m128i {
        unsafe { _mm_setzero_si128() }
    }

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn bswap(x: __m128i) -> __m128i {
        unsafe {
            _mm_shuffle_epi8(
                x,
                _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            )
        }
    }

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn load(p: *const u8) -> __m128i {
        unsafe { _mm_loadu_si128(p as *const __m128i) }
    }

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn store(p: *mut u8, v: __m128i) {
        unsafe { _mm_storeu_si128(p as *mut __m128i, v) }
    }

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn mul_acc(a: __m128i, b: __m128i, acc: &mut Acc) {
        unsafe {
            acc.0 = _mm_xor_si128(acc.0, _mm_clmulepi64_si128::<0x00>(a, b));
            let mid = _mm_xor_si128(
                _mm_clmulepi64_si128::<0x10>(a, b),
                _mm_clmulepi64_si128::<0x01>(a, b),
            );
            acc.1 = _mm_xor_si128(acc.1, mid);
            acc.2 = _mm_xor_si128(acc.2, _mm_clmulepi64_si128::<0x11>(a, b));
        }
    }

    /// Fold the 256-bit sum back into GF(2^128): shift left one bit (the
    /// operands are bit-reflected), then reduce by x^128 + x^7 + x^2 + x + 1.
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn reduce(acc: Acc) -> __m128i {
        unsafe {
            let (lo, mid, hi) = acc;
            let mut t3 = _mm_xor_si128(lo, _mm_slli_si128::<8>(mid));
            let mut t6 = _mm_xor_si128(hi, _mm_srli_si128::<8>(mid));

            let c3 = _mm_srli_epi32::<31>(t3);
            let c6 = _mm_srli_epi32::<31>(t6);
            t3 = _mm_slli_epi32::<1>(t3);
            t6 = _mm_slli_epi32::<1>(t6);
            let carry = _mm_srli_si128::<12>(c3);
            t3 = _mm_or_si128(t3, _mm_slli_si128::<4>(c3));
            t6 = _mm_or_si128(t6, _mm_slli_si128::<4>(c6));
            t6 = _mm_or_si128(t6, carry);

            let a = _mm_slli_epi32::<31>(t3);
            let b = _mm_slli_epi32::<30>(t3);
            let c = _mm_slli_epi32::<25>(t3);
            let mut r = _mm_xor_si128(_mm_xor_si128(a, b), c);
            let r_hi = _mm_srli_si128::<4>(r);
            r = _mm_slli_si128::<12>(r);
            t3 = _mm_xor_si128(t3, r);

            let d = _mm_srli_epi32::<1>(t3);
            let e = _mm_srli_epi32::<2>(t3);
            let f = _mm_srli_epi32::<7>(t3);
            let s = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(d, e), f), r_hi);
            t3 = _mm_xor_si128(t3, s);
            _mm_xor_si128(t6, t3)
        }
    }

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn gfmul(a: __m128i, b: __m128i) -> __m128i {
        unsafe {
            let mut acc = (zero(), zero(), zero());
            mul_acc(a, b, &mut acc);
            reduce(acc)
        }
    }

    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn mix(k: __m128i) -> __m128i {
        unsafe {
            let mut k = k;
            let mut s = _mm_slli_si128::<4>(k);
            k = _mm_xor_si128(k, s);
            s = _mm_slli_si128::<4>(s);
            k = _mm_xor_si128(k, s);
            s = _mm_slli_si128::<4>(s);
            _mm_xor_si128(k, s)
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn expand128(key: &[u8]) -> [__m128i; 16] {
        unsafe {
            let mut rk = [zero(); 16];
            let mut k = load(key.as_ptr());
            rk[0] = k;
            macro_rules! step {
                ($i:expr, $rc:expr) => {
                    let t = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<$rc>(k));
                    k = _mm_xor_si128(mix(k), t);
                    rk[$i] = k;
                };
            }
            step!(1, 0x01);
            step!(2, 0x02);
            step!(3, 0x04);
            step!(4, 0x08);
            step!(5, 0x10);
            step!(6, 0x20);
            step!(7, 0x40);
            step!(8, 0x80);
            step!(9, 0x1b);
            step!(10, 0x36);
            rk
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn expand256(key: &[u8]) -> [__m128i; 16] {
        unsafe {
            let mut rk = [zero(); 16];
            let mut a = load(key.as_ptr());
            let mut b = load(key.as_ptr().add(16));
            rk[0] = a;
            rk[1] = b;
            macro_rules! step {
                ($i:expr, $rc:expr) => {
                    let t = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<$rc>(b));
                    a = _mm_xor_si128(mix(a), t);
                    rk[$i] = a;
                    let t2 = _mm_shuffle_epi32::<0xaa>(_mm_aeskeygenassist_si128::<0>(a));
                    b = _mm_xor_si128(mix(b), t2);
                    rk[$i + 1] = b;
                };
            }
            step!(2, 0x01);
            step!(4, 0x02);
            step!(6, 0x04);
            step!(8, 0x08);
            step!(10, 0x10);
            step!(12, 0x20);
            step!(14, 0x40);
            rk
        }
    }

    /// `N` keystream blocks for counters `ctr..ctr+N` of the 96-bit nonce in
    /// `base` (its last four bytes zero).
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn keystream<const N: usize, const NR: usize>(
        rk: &[__m128i; 16],
        base: __m128i,
        ctr: u32,
    ) -> [__m128i; N] {
        unsafe {
            let mut b = [zero(); N];
            for (i, blk) in b.iter_mut().enumerate() {
                let c = ctr.wrapping_add(i as u32).swap_bytes() as i32;
                *blk = _mm_xor_si128(_mm_insert_epi32::<3>(base, c), rk[0]);
            }
            for r in rk.iter().take(NR).skip(1) {
                for blk in b.iter_mut() {
                    *blk = _mm_aesenc_si128(*blk, *r);
                }
            }
            for blk in b.iter_mut() {
                *blk = _mm_aesenclast_si128(*blk, rk[NR]);
            }
            b
        }
    }

    /// Keystream for the 1..=8 blocks of a tail, as cheap as the count allows.
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
    unsafe fn tail_keystream<const NR: usize>(
        rk: &[__m128i; 16],
        base: __m128i,
        ctr: u32,
        n: usize,
    ) -> [__m128i; 8] {
        unsafe {
            let mut out = [zero(); 8];
            match n {
                1 => out[..1].copy_from_slice(&keystream::<1, NR>(rk, base, ctr)),
                2..=4 => out[..4].copy_from_slice(&keystream::<4, NR>(rk, base, ctr)),
                _ => out = keystream::<8, NR>(rk, base, ctr),
            }
            out
        }
    }

    impl Ni {
        pub(super) fn new(key: &[u8]) -> Ni {
            assert!(available());
            // SAFETY: `available` just confirmed every instruction used below.
            unsafe {
                let (rk, nr) = match key.len() {
                    16 => (expand128(key), 10),
                    32 => (expand256(key), 14),
                    n => panic!("aes-gcm key must be 16 or 32 bytes, got {n}"),
                };
                let mut me = Ni {
                    rk,
                    nr,
                    h: [zero(); 8],
                };
                let e0 = match nr {
                    10 => keystream::<1, 10>(&me.rk, zero(), 0)[0],
                    _ => keystream::<1, 14>(&me.rk, zero(), 0)[0],
                };
                // E(0) with the counter slot zero is exactly the block cipher
                // applied to the zero block.
                let h1 = bswap(e0);
                me.h[0] = h1;
                for i in 1..8 {
                    me.h[i] = gfmul(me.h[i - 1], h1);
                }
                me
            }
        }

        pub(super) fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
            // SAFETY: a `Ni` exists only when the CPU has the features.
            unsafe {
                match self.nr {
                    10 => self.seal_n::<10>(nonce, aad, buf),
                    _ => self.seal_n::<14>(nonce, aad, buf),
                }
            }
        }

        pub(super) fn open(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            buf: &mut [u8],
            tag: &[u8; 16],
        ) -> bool {
            // SAFETY: as above.
            let ok = unsafe {
                match self.nr {
                    10 => self.open_n::<10>(nonce, aad, buf, tag),
                    _ => self.open_n::<14>(nonce, aad, buf, tag),
                }
            };
            if !ok {
                buf.fill(0);
            }
            ok
        }

        /// Fold up to eight blocks (already byte-reversed) into `x`.
        #[inline]
        #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
        unsafe fn ghash(&self, x: __m128i, blocks: &[__m128i]) -> __m128i {
            unsafe {
                let n = blocks.len();
                let mut acc = (zero(), zero(), zero());
                for (i, b) in blocks.iter().enumerate() {
                    let b = if i == 0 { _mm_xor_si128(*b, x) } else { *b };
                    mul_acc(b, self.h[n - 1 - i], &mut acc);
                }
                reduce(acc)
            }
        }

        /// GHASH over `data`, zero-padded to a whole block at the end.
        #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
        unsafe fn ghash_bytes(&self, mut x: __m128i, data: &[u8]) -> __m128i {
            unsafe {
                for chunk in data.chunks(128) {
                    let mut blk = [zero(); 8];
                    let n = chunk.len().div_ceil(16);
                    for (i, slot) in blk.iter_mut().enumerate().take(n) {
                        let part = &chunk[i * 16..chunk.len().min(i * 16 + 16)];
                        let mut t = [0u8; 16];
                        t[..part.len()].copy_from_slice(part);
                        *slot = bswap(load(t.as_ptr()));
                    }
                    x = self.ghash(x, &blk[..n]);
                }
                x
            }
        }

        #[inline]
        #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
        unsafe fn base(nonce: &[u8; 12]) -> __m128i {
            unsafe {
                let mut t = [0u8; 16];
                t[..12].copy_from_slice(nonce);
                load(t.as_ptr())
            }
        }

        /// Length block, final GHASH step and the tag mask E(J0).
        #[inline]
        #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
        unsafe fn finish<const NR: usize>(
            &self,
            x: __m128i,
            base: __m128i,
            aad_len: usize,
            data_len: usize,
        ) -> __m128i {
            unsafe {
                let mut lens = [0u8; 16];
                lens[..8].copy_from_slice(&(aad_len as u64 * 8).to_be_bytes());
                lens[8..].copy_from_slice(&(data_len as u64 * 8).to_be_bytes());
                let x = self.ghash(x, &[bswap(load(lens.as_ptr()))]);
                let mask = keystream::<1, NR>(&self.rk, base, 1)[0];
                _mm_xor_si128(bswap(x), mask)
            }
        }

        #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
        unsafe fn seal_n<const NR: usize>(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            buf: &mut [u8],
        ) -> [u8; 16] {
            unsafe {
                let base = Self::base(nonce);
                let mut x = self.ghash_bytes(zero(), aad);
                let len = buf.len();
                let ptr = buf.as_mut_ptr();
                let mut ctr = 2u32;
                let mut off = 0;
                while len - off >= 128 {
                    let ks = keystream::<8, NR>(&self.rk, base, ctr);
                    ctr = ctr.wrapping_add(8);
                    let mut c = [zero(); 8];
                    for i in 0..8 {
                        let p = ptr.add(off + 16 * i);
                        let v = _mm_xor_si128(load(p), ks[i]);
                        store(p, v);
                        c[i] = bswap(v);
                    }
                    x = self.ghash(x, &c);
                    off += 128;
                }
                if off < len {
                    let n = (len - off).div_ceil(16);
                    let ks = tail_keystream::<NR>(&self.rk, base, ctr, n);
                    for (i, k) in ks.iter().enumerate().take(n) {
                        let s = off + 16 * i;
                        let e = len.min(s + 16);
                        let mut t = [0u8; 16];
                        t[..e - s].copy_from_slice(&buf[s..e]);
                        store(t.as_mut_ptr(), _mm_xor_si128(load(t.as_ptr()), *k));
                        buf[s..e].copy_from_slice(&t[..e - s]);
                    }
                    x = self.ghash_bytes(x, &buf[off..]);
                }
                let tag = self.finish::<NR>(x, base, aad.len(), len);
                let mut out = [0u8; 16];
                store(out.as_mut_ptr(), tag);
                out
            }
        }

        #[target_feature(enable = "aes,pclmulqdq,sse2,sse4.1,ssse3")]
        unsafe fn open_n<const NR: usize>(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            buf: &mut [u8],
            tag: &[u8; 16],
        ) -> bool {
            unsafe {
                let base = Self::base(nonce);
                let mut x = self.ghash_bytes(zero(), aad);
                let len = buf.len();
                let ptr = buf.as_mut_ptr();
                let mut ctr = 2u32;
                let mut off = 0;
                while len - off >= 128 {
                    let ks = keystream::<8, NR>(&self.rk, base, ctr);
                    ctr = ctr.wrapping_add(8);
                    let mut c = [zero(); 8];
                    for i in 0..8 {
                        let p = ptr.add(off + 16 * i);
                        let v = load(p);
                        c[i] = bswap(v);
                        store(p, _mm_xor_si128(v, ks[i]));
                    }
                    x = self.ghash(x, &c);
                    off += 128;
                }
                if off < len {
                    // The tag covers the ciphertext, so hash before decrypting.
                    x = self.ghash_bytes(x, &buf[off..]);
                    let n = (len - off).div_ceil(16);
                    let ks = tail_keystream::<NR>(&self.rk, base, ctr, n);
                    for (i, k) in ks.iter().enumerate().take(n) {
                        let s = off + 16 * i;
                        let e = len.min(s + 16);
                        let mut t = [0u8; 16];
                        t[..e - s].copy_from_slice(&buf[s..e]);
                        store(t.as_mut_ptr(), _mm_xor_si128(load(t.as_ptr()), *k));
                        buf[s..e].copy_from_slice(&t[..e - s]);
                    }
                }
                let want = self.finish::<NR>(x, base, aad.len(), len);
                let diff = _mm_xor_si128(want, load(tag.as_ptr()));
                _mm_testz_si128(diff, diff) == 1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Cheap deterministic bytes; the point is coverage of lengths, not entropy.
    fn fill(seed: &mut u64, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                *seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (*seed >> 33) as u8
            })
            .collect()
    }

    fn reference(key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut buf = pt.to_vec();
        let tag: [u8; 16] = match key.len() {
            16 => Aes128Gcm::new(key.into())
                .encrypt_in_place_detached(nonce.into(), aad, &mut buf)
                .unwrap()
                .into(),
            _ => Aes256Gcm::new(key.into())
                .encrypt_in_place_detached(nonce.into(), aad, &mut buf)
                .unwrap()
                .into(),
        };
        (buf, tag)
    }

    #[test]
    fn nist_test_case_2() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let gcm = Gcm::new(&key);
        let mut buf = [0u8; 16];
        let tag = gcm.seal(&nonce, &[], &mut buf);
        assert_eq!(buf.to_vec(), hex("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(tag.to_vec(), hex("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    #[test]
    fn matches_rustcrypto_for_every_length() {
        let mut seed = 7;
        for key_len in [16usize, 32] {
            let key = fill(&mut seed, key_len);
            let gcm = Gcm::new(&key);
            for len in (0..=600).chain([1023, 1024, 1025, 4095, 15000, 16384, 65535]) {
                let aad_len = len % 41;
                let nonce: [u8; 12] = fill(&mut seed, 12).try_into().unwrap();
                let aad = fill(&mut seed, aad_len);
                let pt = fill(&mut seed, len);
                let (want_ct, want_tag) = reference(&key, &nonce, &aad, &pt);

                let mut buf = pt.clone();
                let tag = gcm.seal(&nonce, &aad, &mut buf);
                assert_eq!(buf, want_ct, "ciphertext, key {key_len} len {len}");
                assert_eq!(tag, want_tag, "tag, key {key_len} len {len}");

                assert!(gcm.open(&nonce, &aad, &mut buf, &tag), "open len {len}");
                assert_eq!(buf, pt, "plaintext, key {key_len} len {len}");
            }
        }
    }

    #[test]
    fn rejects_a_flipped_bit_and_wipes_the_buffer() {
        let mut seed = 11;
        for key_len in [16usize, 32] {
            let key = fill(&mut seed, key_len);
            let gcm = Gcm::new(&key);
            let nonce = [3u8; 12];
            for len in [0usize, 1, 15, 16, 127, 128, 129, 1000] {
                let pt = fill(&mut seed, len);
                let mut buf = pt.clone();
                let tag = gcm.seal(&nonce, b"aad", &mut buf);

                let mut bad_tag = tag;
                bad_tag[5] ^= 1;
                let mut copy = buf.clone();
                assert!(!gcm.open(&nonce, b"aad", &mut copy, &bad_tag));
                assert!(copy.iter().all(|b| *b == 0), "plaintext leaked, len {len}");

                if len > 0 {
                    let mut copy = buf.clone();
                    copy[len / 2] ^= 0x40;
                    assert!(!gcm.open(&nonce, b"aad", &mut copy, &tag));
                }
                let mut copy = buf.clone();
                assert!(!gcm.open(&nonce, b"other", &mut copy, &tag));
                assert!(gcm.open(&nonce, b"aad", &mut buf, &tag));
                assert_eq!(buf, pt);
            }
        }
    }

    #[test]
    #[ignore]
    fn throughput() {
        let key = [9u8; 16];
        let gcm = Gcm::new(&key);
        let mut buf = vec![5u8; 16 * 1024];
        let rounds = 100_000;
        let t = std::time::Instant::now();
        let mut n = 0u64;
        for i in 0..rounds {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let tag = gcm.seal(&nonce, &[], &mut buf);
            n += buf.len() as u64 + tag.len() as u64;
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "fastgcm seal: {:.2} GiB/s",
            n as f64 / secs / (1u64 << 30) as f64
        );
    }
}
