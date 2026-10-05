//! ChaCha20-Poly1305 (RFC 8439) with the MAC run alongside the cipher.
//!
//! RustCrypto's AEAD makes two passes: ChaCha20 over the buffer, then Poly1305
//! over the result, and on this class of CPU neither pass is fast enough to
//! hide the other (2.7 GiB/s each, 1.3 GiB/s together). Here the x86_64 path
//! runs eight ChaCha blocks at a time with each state word in its own YMM
//! register, and feeds Poly1305 blocks to the scalar multiplier while those
//! vector rounds are in flight: the two use different execution ports, so the
//! out-of-order core overlaps them instead of adding them up.
//!
//! The first call to the block function yields block 0 (the Poly1305 key) and
//! blocks 1..7 (the first 448 bytes of keystream), which is why the bulk loop
//! starts at 448. Everything else (short messages, other CPUs, no AVX2) goes to
//! RustCrypto's `chacha20poly1305`, which is also the oracle the tests use.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::panic,
    clippy::unwrap_used,
    unsafe_op_in_unsafe_fn,
    unused_unsafe
)]

use chacha20::{
    ChaCha20 as ChaCha20Core,
    cipher::{KeyIvInit, StreamCipher},
};

/// Below this the eight-block setup costs more than it saves.
#[cfg(target_arch = "x86_64")]
const FAST_MIN: usize = 256;

/// Keeps the 32-bit block counter from wrapping (it never does at TLS, QUIC or
/// proxy record sizes).
#[cfg(target_arch = "x86_64")]
const FAST_MAX: usize = 1 << 24;

pub struct ChaChaPoly {
    key: [u8; 32],
    #[cfg(target_arch = "x86_64")]
    words: Option<[u32; 8]>,
}

impl ChaChaPoly {
    /// `key` is 32 bytes.
    pub fn new(key: &[u8]) -> ChaChaPoly {
        assert!(key.len() == 32, "chacha20-poly1305 key must be 32 bytes");
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        #[cfg(target_arch = "x86_64")]
        let words = if avx2::available() {
            let mut w = [0u32; 8];
            for (i, c) in key.chunks_exact(4).enumerate() {
                w[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            Some(w)
        } else {
            None
        };
        ChaChaPoly {
            key: k,
            #[cfg(target_arch = "x86_64")]
            words,
        }
    }

    /// Encrypt `buf` in place and return the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        if let Some(words) = &self.words
            && (FAST_MIN..=FAST_MAX).contains(&buf.len())
        {
            // SAFETY: `available()` confirmed AVX2 when `words` was set
            return unsafe { avx2::seal(words, nonce, aad, buf) };
        }
        let mut cipher = ChaCha20Core::new((&self.key).into(), nonce.into());
        let mut poly_key = [0u8; 64];
        cipher.apply_keystream(&mut poly_key);
        let mut poly = poly::Poly::new(&poly_key[..32]);
        cipher.apply_keystream(buf);
        poly.update_padded(aad);
        poly.update_padded(buf);
        poly.finish(aad.len(), buf.len())
    }

    /// Decrypt `buf` in place. On a bad tag the buffer is zeroed and the answer
    /// is `false`.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        #[cfg(target_arch = "x86_64")]
        if let Some(words) = &self.words
            && (FAST_MIN..=FAST_MAX).contains(&buf.len())
        {
            // SAFETY: `available()` confirmed AVX2 when `words` was set
            return unsafe { avx2::open(words, nonce, aad, buf, tag) };
        }
        let mut cipher = ChaCha20Core::new((&self.key).into(), nonce.into());
        let mut poly_key = [0u8; 64];
        cipher.apply_keystream(&mut poly_key);
        let mut poly = poly::Poly::new(&poly_key[..32]);
        poly.update_padded(aad);
        poly.update_padded(buf);
        let want = poly.finish(aad.len(), buf.len());
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(tag) {
            diff |= a ^ b;
        }
        if diff != 0 {
            buf.fill(0);
            return false;
        }
        cipher.apply_keystream(buf);
        true
    }
}

pub(crate) mod poly {
    /// Poly1305 over radix 2^64: the accumulator is `h0 + h1*2^64 + h2*2^128`
    /// with `h2` a few bits, reduced lazily modulo 2^130 - 5.
    #[derive(Clone, Copy)]
    pub struct Poly {
        pub(super) h0: u64,
        pub(super) h1: u64,
        pub(super) h2: u64,
        pub(super) r0: u64,
        pub(super) r1: u64,
        r2_0: u64,
        r2_1: u64,
        r2_2: u64,
        s0: u64,
        s1: u64,
    }

    impl Poly {
        pub(super) fn new(key: &[u8]) -> Poly {
            let word = |i: usize| u64::from_le_bytes(key[i..i + 8].try_into().unwrap());
            let r0 = word(0) & 0x0fff_fffc_0fff_ffff;
            let r1 = word(8) & 0x0fff_fffc_0fff_fffc;

            // Precompute r^2 mod (2^130 - 5)
            let p0 = u128::from(r0) * u128::from(r0);
            let p1 = 2 * u128::from(r0) * u128::from(r1);
            let p2 = u128::from(r1) * u128::from(r1);
            let mid = p1 + (p0 >> 64);
            let hi = p2 + (mid >> 64);
            let t0 = p0 as u64;
            let t1 = mid as u64;
            let t2 = hi as u64;
            let t3 = (hi >> 64) as u64;
            let top = u128::from(t2 >> 2) | (u128::from(t3) << 62);
            let low = u128::from(t0) | (u128::from(t1) << 64);
            let (sum, carry) = low.overflowing_add(top * 5);
            let r2_0 = sum as u64;
            let r2_1 = (sum >> 64) as u64;
            let r2_2 = (t2 & 3) + u64::from(carry);

            Poly {
                h0: 0,
                h1: 0,
                h2: 0,
                r0,
                r1,
                r2_0,
                r2_1,
                r2_2,
                s0: word(16),
                s1: word(24),
            }
        }

        /// One 16-byte block with the 2^128 bit set: `(h + m + 2^128) * r`.
        ///
        /// By value, and the accumulator is a tuple rather than a field: the fused
        /// loop keeps the whole MAC state in registers for the length of a 512-byte
        /// window, and a `&mut self` version sends it through the stack on every
        /// absorb.
        #[inline(always)]
        pub(super) fn step(h: (u64, u64, u64), m0: u64, m1: u64, r0: u64, r1: u64) -> (u64, u64, u64) {
            let (a0, c) = h.0.overflowing_add(m0);
            let (a1, c1) = h.1.overflowing_add(m1);
            let (a1, c2) = a1.overflowing_add(u64::from(c));
            let a2 = h.2 + u64::from(c1) + u64::from(c2) + 1;

            let (r0, r1) = (u128::from(r0), u128::from(r1));
            let p0 = u128::from(a0) * r0;
            let p1 = u128::from(a0) * r1 + u128::from(a1) * r0;
            let p2 = u128::from(a1) * r1 + u128::from(a2) * r0;
            let p3 = u128::from(a2) * r1;

            let mid = p1 + (p0 >> 64);
            let hi = p2 + (mid >> 64);
            let (t0, t1, t2) = (p0 as u64, mid as u64, hi as u64);
            let t3 = p3 + (hi >> 64);

            // 2^130 = 5: what is above bit 130 comes back in times five
            let top = u128::from(t2 >> 2) | (t3 << 62);
            let low = u128::from(t0) | (u128::from(t1) << 64);
            let (sum, carry) = low.overflowing_add(top * 5);
            (sum as u64, (sum >> 64) as u64, (t2 & 3) + u64::from(carry))
        }

        /// Two 16-byte blocks absorbed simultaneously:
        /// ((h + m0) * r^2 + m1 * r) mod (2^130 - 5)
        #[inline(always)]
        fn block2(
            &self,
            h: (u64, u64, u64),
            m0_0: u64,
            m0_1: u64,
            m1_0: u64,
            m1_1: u64,
        ) -> (u64, u64, u64) {
            let (a0, c0) = h.0.overflowing_add(m0_0);
            let (a1, c1) = h.1.overflowing_add(m0_1);
            let (a1, c2) = a1.overflowing_add(u64::from(c0));
            let a2 = h.2 + u64::from(c1) + u64::from(c2) + 1;

            let b0 = m1_0;
            let b1 = m1_1;

            let (r0, r1) = (u128::from(self.r0), u128::from(self.r1));
            let pb0 = u128::from(b0) * r0;
            let pb1 = u128::from(b0) * r1 + u128::from(b1) * r0;
            let pb2 = u128::from(b1) * r1 + r0;
            let pb3 = u128::from(self.r1);

            let (r2_0, r2_1, r2_2) = (
                u128::from(self.r2_0),
                u128::from(self.r2_1),
                u128::from(self.r2_2),
            );
            let pa0 = u128::from(a0) * r2_0;
            let pa1_0 = u128::from(a0) * r2_1;
            let pa1_1 = u128::from(a1) * r2_0;
            let pa2_0 = u128::from(a0) * r2_2;
            let pa2_1 = u128::from(a1) * r2_1;
            let pa2_2 = u128::from(a2) * r2_0;
            let pa3 = u128::from(a1) * r2_2 + u128::from(a2) * r2_1;
            let pa4 = a2 * self.r2_2;
            let pextra = u128::from(pa4 * 5) << 62;

            // Weight 2^0:
            let (p0, c0) = pa0.overflowing_add(pb0);

            // Weight 2^64:
            let (s1_a, c1_a) = pa1_0.overflowing_add(pa1_1);
            let (s1_b, c1_b) = pb1.overflowing_add(pextra);
            let (mut p1, c1_c) = s1_a.overflowing_add(s1_b);
            let mut carry1 = u64::from(c1_a) + u64::from(c1_b) + u64::from(c1_c);

            // Weight 2^128:
            let (s2_a, c2_a) = pa2_0.overflowing_add(pa2_1);
            let (s2_b, c2_b) = pa2_2.overflowing_add(pb2);
            let (s2_c, c2_c) = s2_a.overflowing_add(s2_b);
            let (p2, c2_d) = s2_c.overflowing_add(u128::from(c0));
            let carry2 = u64::from(c2_a) + u64::from(c2_b) + u64::from(c2_c) + u64::from(c2_d);

            if carry2 > 0 {
                let (np1, c) = p1.overflowing_add(u128::from(carry2 * 5) << 62);
                p1 = np1;
                carry1 += u64::from(c);
            }

            // Weight 2^192:
            let p3 = pa3 + pb3 + u128::from(carry1);

            // Carry propagation:
            let (mid, mid_carry) = p1.overflowing_add(p0 >> 64);
            let (hi, hi_carry) = p2.overflowing_add(mid >> 64);
            let t0 = p0 as u64;
            let t1 = mid as u64;
            let t2 = hi as u64;
            let t3 = p3 + (hi >> 64) + u128::from(mid_carry) + (u128::from(hi_carry) << 64);

            // Reduction modulo 2^130 - 5:
            let top_lo = u128::from(t2 >> 2) | (t3 << 62);
            let top_hi = (t3 >> 66) as u64;
            let tl_0 = top_lo as u64;
            let tl_1 = (top_lo >> 64) as u64;
            let p_top0 = u128::from(tl_0) * 5;
            let p_top1 = u128::from(tl_1) * 5 + (p_top0 >> 64);
            let prod_lo = u128::from(p_top0 as u64) | (u128::from(p_top1 as u64) << 64);
            let prod_hi = (p_top1 >> 64) as u64 + top_hi * 5;

            let low = u128::from(t0) | (u128::from(t1) << 64);
            let (sum, carry) = low.overflowing_add(prod_lo);
            let h2_raw = (t2 & 3) + u64::from(carry) + prod_hi;

            // Fold h2 if >= 4 so self.h2 stays within [0..4]
            let fold_h2 = u128::from((h2_raw >> 2) * 5);
            let (sum_final, c_final) = sum.overflowing_add(fold_h2);
            (
                sum_final as u64,
                (sum_final >> 64) as u64,
                (h2_raw & 3) + u64::from(c_final),
            )
        }

        /// Two blocks out of the buffer, in one carry chain. Only the last absorb of
        /// a window uses it: the pair needs nine 128-bit products with about twenty
        /// of them live at once, and on sixteen YMM registers that sends the MAC
        /// state through the stack.
        #[inline(always)]
        pub(super) unsafe fn pair(poly: &Poly, p: *const u8, h: (u64, u64, u64)) -> (u64, u64, u64) {
            let m0 = u64::from_le((p as *const u64).read_unaligned());
            let m1 = u64::from_le((p.add(8) as *const u64).read_unaligned());
            let m2 = u64::from_le((p.add(16) as *const u64).read_unaligned());
            let m3 = u64::from_le((p.add(24) as *const u64).read_unaligned());
            poly.block2(h, m0, m1, m2, m3)
        }

        /// `n` whole blocks starting at `p`.
        #[inline(always)]
        pub(super) unsafe fn blocks(&mut self, p: *const u8, mut n: usize) {
            let mut ptr = p;
            while n >= 2 {
                let h = Self::pair(self, ptr, (self.h0, self.h1, self.h2));
                (self.h0, self.h1, self.h2) = h;
                ptr = ptr.add(32);
                n -= 2;
            }
            if n == 1 {
                let m0 = u64::from_le((ptr as *const u64).read_unaligned());
                let m1 = u64::from_le((ptr.add(8) as *const u64).read_unaligned());
                let h = Self::step((self.h0, self.h1, self.h2), m0, m1, self.r0, self.r1);
                (self.h0, self.h1, self.h2) = h;
            }
        }

        /// `data` zero-padded to a multiple of 16, as the AEAD construction has it.
        pub fn update_padded(&mut self, data: &[u8]) {
            let whole = data.len() / 16 * 16;
            // SAFETY: `whole` bytes are in `data`
            unsafe { self.blocks(data.as_ptr(), whole / 16) };
            let rest = &data[whole..];
            if !rest.is_empty() {
                let mut last = [0u8; 16];
                last[..rest.len()].copy_from_slice(rest);
                let h = Self::step(
                    (self.h0, self.h1, self.h2),
                    u64::from_le_bytes(last[..8].try_into().unwrap()),
                    u64::from_le_bytes(last[8..].try_into().unwrap()),
                    self.r0,
                    self.r1,
                );
                (self.h0, self.h1, self.h2) = h;
            }
        }

        pub fn finish(mut self, aad_len: usize, ct_len: usize) -> [u8; 16] {
            let h = Self::step(
                (self.h0, self.h1, self.h2),
                aad_len as u64,
                ct_len as u64,
                self.r0,
                self.r1,
            );
            (self.h0, self.h1, self.h2) = h;
            // full reduction: take h + 5 when that reaches 2^130
            let (g0, c) = self.h0.overflowing_add(5);
            let (g1, c) = self.h1.overflowing_add(u64::from(c));
            let g2 = self.h2 + u64::from(c);
            let take = (g2 >> 2).wrapping_neg();
            let h0 = (self.h0 & !take) | (g0 & take);
            let h1 = (self.h1 & !take) | (g1 & take);
            let (t0, c) = h0.overflowing_add(self.s0);
            let t1 = h1.wrapping_add(self.s1).wrapping_add(u64::from(c));
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&t0.to_le_bytes());
            tag[8..].copy_from_slice(&t1.to_le_bytes());
            tag
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use core::arch::x86_64::*;
    use super::poly::Poly;

    pub(super) fn available() -> bool {
        #[cfg(any(feature = "std", test))]
        {
            std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("bmi2")
        }
        #[cfg(not(any(feature = "std", test)))]
        {
            cfg!(all(target_feature = "avx2", target_feature = "bmi2"))
        }
    }

    /// One quarter round: `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12;`
    /// and the same again with 8 and 7.
    ///
    /// The rotates by 16 and 8 are a byte shuffle, because a `pshufb` mask can
    /// rotate the four bytes of a 32-bit word and 16 and 24 are whole bytes; the
    /// 12 and the 7 are not, and go through a shift and an or. `_mm256_rol_epi32`
    /// would be one instruction for all four, and LLVM emits it in EVEX form --
    /// `vprold` with the AVX512VL prefix -- which is a `SIGILL` on every core
    /// without AVX-512, this one included. Tried, measured, thrown away.
    macro_rules! quarter {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr, $r16:ident, $r8:ident) => {
            $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
            $x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256($x[$d], $x[$a]), $r16);
            $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
            let t = _mm256_xor_si256($x[$b], $x[$c]);
            $x[$b] = _mm256_or_si256(_mm256_slli_epi32::<12>(t), _mm256_srli_epi32::<20>(t));
            $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
            $x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256($x[$d], $x[$a]), $r8);
            $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
            let t = _mm256_xor_si256($x[$b], $x[$c]);
            $x[$b] = _mm256_or_si256(_mm256_slli_epi32::<7>(t), _mm256_srli_epi32::<25>(t));
        };
    }

    /// The initial state of eight consecutive blocks: word `i` of every block in
    /// one register, the counter offset by the lane.
    #[target_feature(enable = "avx2,bmi2")]
    unsafe fn setup(key: &[u32; 8], nonce: &[u8; 12], counter: u32) -> [__m256i; 16] {
        let n = |i: usize| u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
        let one = |v: u32| _mm256_set1_epi32(v as i32);
        [
            one(0x6170_7865),
            one(0x3320_646e),
            one(0x7962_2d32),
            one(0x6b20_6574),
            one(key[0]),
            one(key[1]),
            one(key[2]),
            one(key[3]),
            one(key[4]),
            one(key[5]),
            one(key[6]),
            one(key[7]),
            _mm256_add_epi32(one(counter), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7)),
            one(n(0)),
            one(n(1)),
            one(n(2)),
        ]
    }

    /// Twenty rounds over eight blocks. With `FUSE` the scalar unit also absorbs
    /// exactly 32 Poly1305 blocks (512 bytes) from `pp`: three after chosen
    /// quarter rounds of each double round, two at the end. A fixed schedule keeps
    /// the loop free of branches and puts the scalar work between the vector
    /// instructions, where the out-of-order core can overlap it.
    ///
    /// Thirty single absorbs and one pair, and nothing else: the pair computes
    /// `((h + m0) * r^2 + m1 * r)` in one carry chain, which needs nine 128-bit
    /// products with about twenty of them live at once, and on sixteen YMM
    /// registers that means the MAC state round-trips through the stack. Measured
    /// on the desktop, this schedule fuses at 1.58 GiB/s; spreading the window over
    /// sixteen pair absorbs drops it to 0.92, and the same sixteen absorbs done as
    /// two plain multiplies each reach only 1.16. Two lanes pay off as vectors,
    /// where both chains fit in one register -- not as precomputed scalar powers,
    /// which shorten nothing: the accumulator chain is the length it always was.
    #[target_feature(enable = "avx2,bmi2")]
    unsafe fn rounds<const FUSE: bool>(
        init: &[__m256i; 16],
        poly: &mut Poly,
        pp: *const u8,
    ) -> [__m256i; 16] {
        // opaque on purpose: as a visible constant the optimizer rewrites the
        // 16-bit rotate into two shuffles, and shuffles are what the core has
        // the fewest ports for
        let r16 = core::hint::black_box(_mm256_setr_epi8(
            2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11,
            8, 9, 14, 15, 12, 13,
        ));
        let r8 = _mm256_setr_epi8(
            3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8,
            9, 10, 15, 12, 13, 14,
        );
        let mut x = *init;
        // the MAC state is kept in registers for the whole call: three words of
        // accumulator and two of r, out of `poly` once and back into it once
        let (mut h0, mut h1, mut h2) = (poly.h0, poly.h1, poly.h2);
        let (r0, r1) = (poly.r0, poly.r1);
        let mut h = (h0, h1, h2);
        for it in 0..10 {
            quarter!(x, 0, 4, 8, 12, r16, r8);
            quarter!(x, 1, 5, 9, 13, r16, r8);
            if FUSE {
                h = absorb(pp.add(48 * it), h, r0, r1);
            }
            quarter!(x, 2, 6, 10, 14, r16, r8);
            quarter!(x, 3, 7, 11, 15, r16, r8);
            if FUSE {
                h = absorb(pp.add(48 * it + 16), h, r0, r1);
            }
            quarter!(x, 0, 5, 10, 15, r16, r8);
            quarter!(x, 1, 6, 11, 12, r16, r8);
            if FUSE {
                h = absorb(pp.add(48 * it + 32), h, r0, r1);
            }
            quarter!(x, 2, 7, 8, 13, r16, r8);
            quarter!(x, 3, 4, 9, 14, r16, r8);
        }
        if FUSE {
            h = super::poly::Poly::pair(poly, pp.add(480), h);
        }
        for i in 0..16 {
            x[i] = _mm256_add_epi32(x[i], init[i]);
        }
        (h0, h1, h2) = h;
        poly.h0 = h0;
        poly.h1 = h1;
        poly.h2 = h2;
        x
    }

    /// One 16-byte block of MAC read straight out of the buffer.
    #[inline(always)]
    unsafe fn absorb(
        p: *const u8,
        h: (u64, u64, u64),
        r0: u64,
        r1: u64,
    ) -> (u64, u64, u64) {
        let m0 = u64::from_le((p as *const u64).read_unaligned());
        let m1 = u64::from_le((p.add(8) as *const u64).read_unaligned());
        super::poly::Poly::step(h, m0, m1, r0, r1)
    }

    /// 8x8 transpose of 32-bit words: row `i` in, block `i` out.
    #[target_feature(enable = "avx2,bmi2")]
    unsafe fn transpose(r: &[__m256i]) -> [__m256i; 8] {
        let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
        let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
        let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
        let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
        let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
        let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
        let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
        let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);
        [
            _mm256_permute2x128_si256::<0x20>(u0, u4),
            _mm256_permute2x128_si256::<0x20>(u1, u5),
            _mm256_permute2x128_si256::<0x20>(u2, u6),
            _mm256_permute2x128_si256::<0x20>(u3, u7),
            _mm256_permute2x128_si256::<0x31>(u0, u4),
            _mm256_permute2x128_si256::<0x31>(u1, u5),
            _mm256_permute2x128_si256::<0x31>(u2, u6),
            _mm256_permute2x128_si256::<0x31>(u3, u7),
        ]
    }

    /// Write the 512 bytes of keystream at `dst`, XORed into what is there when
    /// `XOR` is set.
    #[target_feature(enable = "avx2,bmi2")]
    unsafe fn emit<const XOR: bool>(x: &[__m256i; 16], dst: *mut u8) {
        let lo = transpose(&x[..8]);
        let hi = transpose(&x[8..]);
        for b in 0..8 {
            let p = dst.add(64 * b) as *mut __m256i;
            let (mut a, mut c) = (lo[b], hi[b]);
            if XOR {
                a = _mm256_xor_si256(a, _mm256_loadu_si256(p));
                c = _mm256_xor_si256(c, _mm256_loadu_si256(p.add(1)));
            }
            _mm256_storeu_si256(p, a);
            _mm256_storeu_si256(p.add(1), c);
        }
    }

    /// Keystream blocks `counter..counter + 8`.
    #[target_feature(enable = "avx2,bmi2")]
    pub(super) unsafe fn keystream(key: &[u32; 8], nonce: &[u8; 12], counter: u32) -> [u8; 512] {
        let init = setup(key, nonce, counter);
        let mut dummy = Poly::new(&[0u8; 32]);
        let x = rounds::<false>(&init, &mut dummy, core::ptr::null());
        let mut ks = [0u8; 512];
        emit::<false>(&x, ks.as_mut_ptr());
        ks
    }

    fn xor_into(dst: &mut [u8], ks: &[u8]) {
        for (d, k) in dst.iter_mut().zip(ks) {
            *d ^= k;
        }
    }

    #[target_feature(enable = "avx2,bmi2")]
    pub(super) unsafe fn seal(
        key: &[u32; 8],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> [u8; 16] {
        let len = buf.len();
        let ks = keystream(key, nonce, 0);
        let mut poly = Poly::new(&ks[..32]);
        poly.update_padded(aad);

        // block 0 was the MAC key; blocks 1..7 cover the first 448 bytes
        let first = len.min(448);
        xor_into(&mut buf[..first], &ks[64..64 + first]);
        let mut done = first;
        // how far the MAC has read: it trails the cipher, one window of 512
        // bytes at a time, and starts once there is a whole window produced
        let mut fed = 0usize;
        let mut counter = 8u32;

        let base = buf.as_mut_ptr();
        if len - done >= 512 {
            let init = setup(key, nonce, counter);
            let x = rounds::<false>(&init, &mut poly, core::ptr::null());
            emit::<true>(&x, base.add(done));
            done += 512;
            counter += 8;
        }
        while len - done >= 512 {
            let init = setup(key, nonce, counter);
            let x = rounds::<true>(&init, &mut poly, base.add(fed));
            emit::<true>(&x, base.add(done));
            fed += 512;
            done += 512;
            counter += 8;
        }
        if done < len {
            let ks = keystream(key, nonce, counter);
            xor_into(&mut buf[done..], &ks[..len - done]);
        }
        poly.update_padded(&buf[fed..]);
        poly.finish(aad.len(), len)
    }

    #[target_feature(enable = "avx2,bmi2")]
    pub(super) unsafe fn open(
        key: &[u32; 8],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let len = buf.len();
        let ks = keystream(key, nonce, 0);
        let mut poly = Poly::new(&ks[..32]);
        poly.update_padded(aad);

        let first = len.min(448);
        poly.update_padded(&buf[..first]);
        xor_into(&mut buf[..first], &ks[64..64 + first]);
        let mut done = first;
        let mut counter = 8u32;

        let base = buf.as_mut_ptr();
        while len - done >= 512 {
            // the MAC reads this chunk's ciphertext while its keystream is
            // computed; the XOR that overwrites it comes after
            let init = setup(key, nonce, counter);
            let x = rounds::<true>(&init, &mut poly, base.add(done));
            emit::<true>(&x, base.add(done));
            done += 512;
            counter += 8;
        }
        if done < len {
            poly.update_padded(&buf[done..]);
            let ks = keystream(key, nonce, counter);
            xor_into(&mut buf[done..], &ks[..len - done]);
        }
        let want = poly.finish(aad.len(), len);
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(tag) {
            diff |= a ^ b;
        }
        if diff != 0 {
            buf.fill(0);
            return false;
        }
        true
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::std_instead_of_core
)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use aead::AeadInPlace;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn agrees_with_rustcrypto_across_lengths() {
        let key = pattern(32, 3);
        let fast = ChaChaPoly::new(&key);
        let soft = ChaCha20Poly1305::new(key.as_slice().into());
        let lens = (0..1400usize)
            .chain([2047, 2048, 4095, 4096, 16384, 16385, 16399, 65535, 65536]);
        for len in lens {
            for aad_len in [0usize, 5, 16, 33] {
                let nonce: [u8; 12] = pattern(12, len as u8).try_into().unwrap();
                let aad = pattern(aad_len, 9);
                let plain = pattern(len, len as u8);

                let mut a = plain.clone();
                let tag_a = fast.seal(&nonce, &aad, &mut a);
                let mut b = plain.clone();
                let tag_b: [u8; 16] = soft
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut b)
                    .unwrap()
                    .into();
                assert_eq!(a, b, "ciphertext, len {len} aad {aad_len}");
                assert_eq!(tag_a, tag_b, "tag, len {len} aad {aad_len}");

                assert!(fast.open(&nonce, &aad, &mut a, &tag_a), "open, len {len}");
                assert_eq!(a, plain, "plaintext, len {len}");
            }
        }
    }

    #[test]
    fn a_bad_tag_or_bad_data_is_refused() {
        let fast = ChaChaPoly::new(&pattern(32, 1));
        let nonce = [7u8; 12];
        for len in [300usize, 448, 449, 960, 5000] {
            let mut data = pattern(len, 2);
            let tag = fast.seal(&nonce, b"aad", &mut data);

            let mut bad_tag = tag;
            bad_tag[3] ^= 1;
            let mut copy = data.clone();
            assert!(!fast.open(&nonce, b"aad", &mut copy, &bad_tag));
            assert!(copy.iter().all(|b| *b == 0), "nothing of it is left");

            let mut copy = data.clone();
            copy[len - 1] ^= 0x80;
            assert!(!fast.open(&nonce, b"aad", &mut copy, &tag));

            let mut copy = data.clone();
            assert!(!fast.open(&nonce, b"aaX", &mut copy, &tag));
        }
    }

    /// The two halves alone: the keystream and the scalar MAC.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[ignore]
    fn halves() {
        let key = [3u32; 8];
        let nonce = [1u8; 12];
        let n = 400_000usize;
        let start = std::time::Instant::now();
        let mut sink = 0u8;
        for i in 0..n {
            // SAFETY: only run on hosts with AVX2
            sink ^= unsafe { avx2::keystream(&key, &nonce, i as u32) }[7];
        }
        let secs = start.elapsed().as_secs_f64();
        std::hint::black_box(sink);
        println!("keystream: {:.2} GiB/s", (n * 512) as f64 / (1u64 << 30) as f64 / secs);

        let data = pattern(16384, 4);
        let mut poly = poly::Poly::new(&[0x55u8; 32]);
        let start = std::time::Instant::now();
        for _ in 0..40_000 {
            // SAFETY: the whole buffer is read
            unsafe { poly.blocks(data.as_ptr(), data.len() / 16) };
        }
        let secs = start.elapsed().as_secs_f64();
        std::hint::black_box(poly.finish(0, 0));
        println!("poly1305 scalar: {:.2} GiB/s", (40_000 * 16384) as f64 / (1u64 << 30) as f64 / secs);
    }

    /// `cargo test -p core-crypto --release --features std fastchacha -- --ignored --nocapture`
    /// What the `poly1305` crate's own AVX2 backend does here, against the
    /// hand-written 130-bit scalar above. The crate's backend is four blocks at a
    /// time in 130-bit limbs (Goll and Gueron), and it is already in the dependency
    /// tree with `chacha20poly1305` -- so the question is not whether the code
    /// exists but whether it beats the scalar on this core.
    #[test]
    #[ignore]
    fn crate_backend() {
        use poly1305::Poly1305;

        let key = [3u8; 32];
        let buf = vec![9u8; 64 * 1024];
        let n = 2000usize;

        let run = |label: &str, f: &mut dyn FnMut()| {
            for _ in 0..10 {
                f();
            }
            let start = std::time::Instant::now();
            for _ in 0..n {
                f();
            }
            let secs = start.elapsed().as_secs_f64();
            println!(
                "{label:26} {:.2} GiB/s",
                (n * buf.len()) as f64 / (1u64 << 30) as f64 / secs
            );
        };

        run("poly1305 crate, 4 lanes", &mut || {
            let mac = Poly1305::new(&key.into());
            let tag = mac.compute_unpadded(&buf);
            std::hint::black_box(tag);
        });
        run("ours, one chain", &mut || {
            let mut mac = poly::Poly::new(&key);
            mac.update_padded(&buf);
            std::hint::black_box(mac.finish(0, buf.len()));
        });
    }

    #[test]
    #[ignore]
    fn throughput() {
        let fast = ChaChaPoly::new(&pattern(32, 5));
        let nonce = [1u8; 12];
        for size in [1024usize, 4096, 16384, 65535] {
            let mut buf = pattern(size, 1);
            let n = (1usize << 30) / size;
            let start = std::time::Instant::now();
            let mut tag = [0u8; 16];
            for _ in 0..n {
                tag = fast.seal(&nonce, &[], &mut buf);
            }
            let secs = start.elapsed().as_secs_f64();
            std::hint::black_box(tag);
            println!(
                "fastchacha seal {size:>6}: {:.2} GiB/s",
                (n * size) as f64 / (1u64 << 30) as f64 / secs
            );
            let start = std::time::Instant::now();
            for _ in 0..n {
                std::hint::black_box(fast.open(&nonce, &[], &mut buf, &tag));
            }
            let secs = start.elapsed().as_secs_f64();
            println!(
                "fastchacha open {size:>6}: {:.2} GiB/s (bad tag, buffer zeroed)",
                (n * size) as f64 / (1u64 << 30) as f64 / secs
            );
        }
    }
}
