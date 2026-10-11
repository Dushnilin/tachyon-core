//! AES-GCM on AES-NI and PCLMULQDQ (x86_64) or AESE and PMULL (aarch64),
//! written here so the hot path does not depend on `ring` and does not go
//! through the generic `aes-gcm` plumbing.
//!
//! Both SIMD paths keep eight blocks in flight: the counter blocks are
//! encrypted together, and the eight ciphertext blocks are folded into GHASH
//! with the powers H^8..H^1, so the carry-less products are summed first and
//! the polynomial is reduced once per 128 bytes. Everything else (other
//! architectures, a CPU without the instructions) goes to RustCrypto's
//! `aes-gcm`, which is the oracle the tests compare against.

// The crate warns on casts, `panic!` and friends for the protocol code; here
// the casts are lengths and counters that are range-checked by construction and
// the panics are key-length contracts.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::panic,
    clippy::unwrap_used
)]

use aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Tag};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

pub enum Gcm {
    #[cfg(target_arch = "x86_64")]
    Ni(Box<ni::Ni>),
    #[cfg(target_arch = "aarch64")]
    V8(Box<v8::V8>),
    Soft128(Box<Aes128Gcm>),
    Soft256(Box<Aes256Gcm>),
    /// The kernel Crypto API path with the software cipher underneath:
    /// payloads at or above the calibrated cutoff go to `AF_ALG` (so a board
    /// with a DMA crypto engine can offload the block cipher), smaller ones
    /// stay here. The variant only exists when the process-wide probe in
    /// [`crate::afalg`] passed, so on a machine without a usable `AF_ALG`
    /// `Gcm::new` never produces it.
    #[cfg(all(target_os = "linux", feature = "std"))]
    Alg(crate::afalg::AfalgGcm),
}

impl Gcm {
    /// `key` is 16 or 32 bytes; the callers derive it with a fixed length.
    pub fn new(key: &[u8]) -> Gcm {
        // The probe self-tests and calibrates exactly once per process; a
        // kernel without AF_ALG, a seccomp filter that blocks it, or a
        // driver that loses the race to our own SIMD all answer 0 = off.
        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            let thr = crate::afalg::threshold();
            if thr > 0
                && let Ok(a) = crate::afalg::AfalgGcm::new(key, thr)
            {
                return Gcm::Alg(a);
            }
        }
        Gcm::new_software(key)
    }

    /// The SIMD and RustCrypto path with no `AF_ALG` probe: what [`Gcm::new`]
    /// falls back to, and what the kernel path's tests compare against.
    pub(crate) fn new_software(key: &[u8]) -> Gcm {
        #[cfg(target_arch = "x86_64")]
        if ni::available() {
            return Gcm::Ni(Box::new(ni::Ni::new(key)));
        }
        #[cfg(target_arch = "aarch64")]
        if v8::available() {
            return Gcm::V8(Box::new(v8::V8::new(key)));
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
            #[cfg(target_arch = "aarch64")]
            Gcm::V8(v8) => v8.seal(nonce, aad, buf),
            Gcm::Soft128(c) => c
                .encrypt_in_place_detached(nonce.into(), aad, buf)
                .expect("gcm length is in range")
                .into(),
            Gcm::Soft256(c) => c
                .encrypt_in_place_detached(nonce.into(), aad, buf)
                .expect("gcm length is in range")
                .into(),
            #[cfg(all(target_os = "linux", feature = "std"))]
            Gcm::Alg(a) => a.seal(nonce, aad, buf),
        }
    }

    /// Decrypt `buf` in place. On a bad tag nothing of the plaintext is left
    /// in `buf` and the answer is `false`.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        match self {
            #[cfg(target_arch = "x86_64")]
            Gcm::Ni(ni) => ni.open(nonce, aad, buf, tag),
            #[cfg(target_arch = "aarch64")]
            Gcm::V8(v8) => v8.open(nonce, aad, buf, tag),
            // RustCrypto checks the tag before decrypting and leaves the
            // ciphertext in place on failure; the contract above is a zeroed
            // buffer, which the other backends already keep.
            Gcm::Soft128(c) => soft_wipe(
                c.decrypt_in_place_detached(nonce.into(), aad, buf, Tag::from_slice(tag))
                    .is_ok(),
                buf,
            ),
            Gcm::Soft256(c) => soft_wipe(
                c.decrypt_in_place_detached(nonce.into(), aad, buf, Tag::from_slice(tag))
                    .is_ok(),
                buf,
            ),
            #[cfg(all(target_os = "linux", feature = "std"))]
            Gcm::Alg(a) => a.open(nonce, aad, buf, tag),
        }
    }
}

fn soft_wipe(ok: bool, buf: &mut [u8]) -> bool {
    if !ok {
        buf.fill(0);
    }
    ok
}

#[cfg(target_arch = "aarch64")]
mod v8 {
    #![allow(unused_unsafe)]

    use core::arch::aarch64::*;
    use core::mem;

    /// Round keys (at most 15 for AES-256) and the powers of H, structured
    /// exactly like the x86 module: `h[i]` is H^(i+1) in the byte-reversed
    /// domain the multiplication works in.
    pub struct V8 {
        rk: [uint8x16_t; 15],
        nr: usize,
        h: [uint8x16_t; 8],
    }

    pub(super) fn available() -> bool {
        // FEAT_AES and FEAT_PMULL (the 64-bit polynomial multiply) travel
        // together on every core that has them, which is how the RustCrypto
        // pmull backend probes as well.
        #[cfg(any(feature = "std", test))]
        {
            std::arch::is_aarch64_feature_detected!("aes")
        }
        // without `std` there is no probe: only what the build already assumes
        #[cfg(not(any(feature = "std", test)))]
        {
            cfg!(target_feature = "aes")
        }
    }

    /// Unreduced 256-bit sum of carry-less products: low, middle, high.
    type Acc = (uint8x16_t, uint8x16_t, uint8x16_t);

    const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn zero() -> uint8x16_t {
        unsafe { vdupq_n_u8(0) }
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn bswap(x: uint8x16_t) -> uint8x16_t {
        unsafe { vextq_u8(vrev64q_u8(x), vrev64q_u8(x), 8) }
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn load(p: *const u8) -> uint8x16_t {
        unsafe { vld1q_u8(p) }
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn store(p: *mut u8, v: uint8x16_t) {
        unsafe { vst1q_u8(p, v) }
    }

    /// Accumulate `a*b` into the unreduced 256-bit sum. Splitting each operand
    /// into 64-bit halves: a*b = a0b0 ^ ((a0b1 ^ a1b0) << 64) ^ (a1b1 << 128).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn mul_acc(a: uint8x16_t, b: uint8x16_t, acc: &mut Acc) {
        unsafe {
            let a64 = vreinterpretq_u64_u8(a);
            let b64 = vreinterpretq_u64_u8(b);
            let a0 = vgetq_lane_u64(a64, 0);
            let a1 = vgetq_lane_u64(a64, 1);
            let b0 = vgetq_lane_u64(b64, 0);
            let b1 = vgetq_lane_u64(b64, 1);
            let lo: uint8x16_t = mem::transmute(vmull_p64(a0, b0));
            let hi: uint8x16_t = mem::transmute(vmull_p64(a1, b1));
            let m01: uint8x16_t = mem::transmute(vmull_p64(a0, b1));
            let m10: uint8x16_t = mem::transmute(vmull_p64(a1, b0));
            acc.0 = veorq_u8(acc.0, lo);
            acc.1 = veorq_u8(acc.1, veorq_u8(m01, m10));
            acc.2 = veorq_u8(acc.2, hi);
        }
    }

    /// Fold the 256-bit sum back into GF(2^128): shift left one bit (the
    /// operands are bit-reflected), then reduce by x^128 + x^7 + x^2 + x + 1.
    /// The same sequence as the x86 `reduce`, in NEON shifts.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn reduce(acc: Acc) -> uint8x16_t {
        unsafe {
            let (lo, mid, hi) = acc;
            let z = vdupq_n_u8(0);
            let mut t3 = veorq_u8(lo, vextq_u8(z, mid, 8));
            let mut t6 = veorq_u8(hi, vextq_u8(mid, z, 8));

            let c3 = vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(t3), 31));
            let c6 = vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(t6), 31));
            t3 = vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(t3), 1));
            t6 = vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(t6), 1));
            let carry = vextq_u8(c3, z, 12);
            // A byte shift left by n is a window at 16-n of (zero : x).
            t3 = vorrq_u8(t3, vextq_u8(z, c3, 12));
            t6 = vorrq_u8(t6, vextq_u8(z, c6, 12));
            t6 = vorrq_u8(t6, carry);

            let a = vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(t3), 31));
            let b = vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(t3), 30));
            let c = vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(t3), 25));
            let mut r = veorq_u8(veorq_u8(a, b), c);
            let r_hi = vextq_u8(r, z, 4);
            r = vextq_u8(z, r, 4);
            t3 = veorq_u8(t3, r);

            let d = vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(t3), 1));
            let e = vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(t3), 2));
            let f = vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(t3), 7));
            let s = veorq_u8(veorq_u8(veorq_u8(d, e), f), r_hi);
            t3 = veorq_u8(t3, s);
            veorq_u8(t6, t3)
        }
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn gfmul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        unsafe {
            let mut acc = (zero(), zero(), zero());
            mul_acc(a, b, &mut acc);
            reduce(acc)
        }
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn sub_word(input: u32) -> u32 {
        unsafe {
            let v = vreinterpretq_u8_u32(vdupq_n_u32(input));
            // AESE with a zero key is SubBytes+ShiftRows; ShiftRows is a no-op
            // here because every column of the register holds the same word.
            let s = vaeseq_u8(v, vdupq_n_u8(0));
            vgetq_lane_u32(vreinterpretq_u32_u8(s), 0)
        }
    }

    /// The FIPS key schedule, scalar: key expansion runs once per handshake,
    /// never in the bulk path, so the columns are plain `u32`s.
    #[target_feature(enable = "aes,neon")]
    unsafe fn expand(key: &[u8]) -> ([uint8x16_t; 15], usize) {
        unsafe {
            let nk = key.len() / 4;
            let nr = match key.len() {
                16 => 10,
                32 => 14,
                n => panic!("aes-gcm key must be 16 or 32 bytes, got {n}"),
            };
            let nwords = 4 * (nr + 1);
            const _: () = assert!(mem::align_of::<uint8x16_t>() >= mem::align_of::<u32>());
            let mut rk = [vdupq_n_u8(0); 15];
            let columns = core::slice::from_raw_parts_mut(rk.as_mut_ptr() as *mut u32, 60);
            for (i, chunk) in key.chunks_exact(4).enumerate() {
                columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
            }
            for i in nk..nwords {
                let mut word = columns[i - 1];
                if i % nk == 0 {
                    word = sub_word(word).rotate_right(8) ^ ROUND_CONSTS[i / nk - 1];
                } else if nk > 6 && i % nk == 4 {
                    word = sub_word(word);
                }
                columns[i] = columns[i - nk] ^ word;
            }
            (rk, nr)
        }
    }

    /// `N` keystream blocks for counters `ctr..ctr+N` of the 96-bit nonce in
    /// `base` (its last four bytes zero).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn keystream<const N: usize, const NR: usize>(
        rk: &[uint8x16_t; 15],
        base: uint8x16_t,
        ctr: u32,
    ) -> [uint8x16_t; N] {
        unsafe {
            let mut b = [zero(); N];
            for (i, blk) in b.iter_mut().enumerate() {
                let c = ctr.wrapping_add(i as u32).swap_bytes();
                *blk = vreinterpretq_u8_u32(vsetq_lane_u32(c, vreinterpretq_u32_u8(base), 3));
            }
            // AESE folds its round key in first, so there is no separate
            // initial add-round-key; every middle round is AESE+AESMC and the
            // last round is AESE plus a final XOR.
            for r in 0..NR - 1 {
                for blk in b.iter_mut() {
                    *blk = vaesmcq_u8(vaeseq_u8(*blk, rk[r]));
                }
            }
            for blk in b.iter_mut() {
                *blk = vaeseq_u8(*blk, rk[NR - 1]);
                *blk = veorq_u8(*blk, rk[NR]);
            }
            b
        }
    }

    /// Keystream for the 1..=8 blocks of a tail, as cheap as the count allows.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn tail_keystream<const NR: usize>(
        rk: &[uint8x16_t; 15],
        base: uint8x16_t,
        ctr: u32,
        n: usize,
    ) -> [uint8x16_t; 8] {
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

    impl V8 {
        pub(super) fn new(key: &[u8]) -> V8 {
            assert!(available());
            // SAFETY: `available` just confirmed the instructions used below.
            unsafe {
                let (rk, nr) = expand(key);
                let mut me = V8 {
                    rk,
                    nr,
                    h: [vdupq_n_u8(0); 8],
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
            // SAFETY: a `V8` exists only when the CPU has the features.
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
        #[target_feature(enable = "aes,neon")]
        unsafe fn ghash(&self, x: uint8x16_t, blocks: &[uint8x16_t]) -> uint8x16_t {
            unsafe {
                let n = blocks.len();
                let mut acc = (zero(), zero(), zero());
                for (i, b) in blocks.iter().enumerate() {
                    let b = if i == 0 { veorq_u8(*b, x) } else { *b };
                    mul_acc(b, self.h[n - 1 - i], &mut acc);
                }
                reduce(acc)
            }
        }

        /// GHASH over `data`, zero-padded to a whole block at the end.
        #[target_feature(enable = "aes,neon")]
        unsafe fn ghash_bytes(&self, mut x: uint8x16_t, data: &[u8]) -> uint8x16_t {
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
        #[target_feature(enable = "aes,neon")]
        unsafe fn base(nonce: &[u8; 12]) -> uint8x16_t {
            unsafe {
                let mut t = [0u8; 16];
                t[..12].copy_from_slice(nonce);
                load(t.as_ptr())
            }
        }

        /// Length block, final GHASH step and the tag mask E(J0).
        #[inline]
        #[target_feature(enable = "aes,neon")]
        unsafe fn finish<const NR: usize>(
            &self,
            x: uint8x16_t,
            base: uint8x16_t,
            aad_len: usize,
            data_len: usize,
        ) -> uint8x16_t {
            unsafe {
                let mut lens = [0u8; 16];
                lens[..8].copy_from_slice(&(aad_len as u64 * 8).to_be_bytes());
                lens[8..].copy_from_slice(&(data_len as u64 * 8).to_be_bytes());
                let x = self.ghash(x, &[bswap(load(lens.as_ptr()))]);
                let mask = keystream::<1, NR>(&self.rk, base, 1)[0];
                veorq_u8(bswap(x), mask)
            }
        }

        #[target_feature(enable = "aes,neon")]
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
                        let v = veorq_u8(load(p), ks[i]);
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
                        store(t.as_mut_ptr(), veorq_u8(load(t.as_ptr()), *k));
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

        #[target_feature(enable = "aes,neon")]
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
                        store(p, veorq_u8(v, ks[i]));
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
                        store(t.as_mut_ptr(), veorq_u8(load(t.as_ptr()), *k));
                        buf[s..e].copy_from_slice(&t[..e - s]);
                    }
                }
                let want = self.finish::<NR>(x, base, aad.len(), len);
                let diff = veorq_u8(want, load(tag.as_ptr()));
                // Branchless all-bytes-zero test: OR the register together
                // with progressively smaller rotations of itself.
                let d1 = vorrq_u8(diff, vextq_u8(diff, diff, 8));
                let d2 = vorrq_u8(d1, vextq_u8(d1, d1, 4));
                let d3 = vorrq_u8(d2, vextq_u8(d2, d2, 2));
                let d4 = vorrq_u8(d3, vextq_u8(d3, d3, 1));
                vgetq_lane_u8(d4, 0) == 0
            }
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
        #[cfg(any(feature = "std", test))]
        {
            std::is_x86_feature_detected!("aes")
                && std::is_x86_feature_detected!("pclmulqdq")
                && std::is_x86_feature_detected!("sse4.1")
                && std::is_x86_feature_detected!("ssse3")
        }
        // without `std` there is no probe: only what the build already assumes
        #[cfg(not(any(feature = "std", test)))]
        {
            cfg!(all(
                target_feature = "aes",
                target_feature = "pclmulqdq",
                target_feature = "sse4.1",
                target_feature = "ssse3"
            ))
        }
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
    pub(super) unsafe fn bswap(x: __m128i) -> __m128i {
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
    pub(super) unsafe fn mul_acc(a: __m128i, b: __m128i, acc: &mut Acc) {
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
    pub(super) unsafe fn reduce(acc: Acc) -> __m128i {
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
    pub(super) unsafe fn gfmul(a: __m128i, b: __m128i) -> __m128i {
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
    use alloc::vec::Vec;

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
            let soft = match key_len {
                16 => Gcm::Soft128(Box::new(Aes128Gcm::new(key.as_slice().into()))),
                _ => Gcm::Soft256(Box::new(Aes256Gcm::new(key.as_slice().into()))),
            };
            // Gcm::new never lands on the RustCrypto path on a PCLMUL host, so
            // the fallback a MIPS or old-x86 router runs is checked by name.
            for gcm in [Gcm::new(&key), soft] {
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
                        assert!(copy.iter().all(|b| *b == 0), "ciphertext left, len {len}");
                    }
                    let mut copy = buf.clone();
                    assert!(!gcm.open(&nonce, b"other", &mut copy, &tag));
                    assert!(copy.iter().all(|b| *b == 0), "aad mismatch left, len {len}");
                    assert!(gcm.open(&nonce, b"aad", &mut buf, &tag));
                    assert_eq!(buf, pt);
                }
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

    /// The x86 `bswap`/`mul_acc`/`reduce` math restated on plain `u128`s:
    /// byte 0 of a vector is bits 0..7 of the little-endian integer, which is
    /// how both `__m128i` and `uint8x16_t` sit in memory.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    mod v8_ref {
        pub(super) fn bswap(x: u128) -> u128 {
            let b = x.to_le_bytes();
            let mut r = [0u8; 16];
            for i in 0..16 {
                r[i] = b[15 - i];
            }
            u128::from_le_bytes(r)
        }

        fn clmul64(a: u64, b: u64) -> u128 {
            let mut r = 0u128;
            for i in 0..64 {
                if (b >> i) & 1 == 1 {
                    r ^= u128::from(a) << i;
                }
            }
            r
        }

        pub(super) fn mul_acc(a: u128, b: u128) -> (u128, u128, u128) {
            let lo = clmul64(a as u64, b as u64);
            let mid = clmul64(a as u64, (b >> 64) as u64) ^ clmul64((a >> 64) as u64, b as u64);
            let hi = clmul64((a >> 64) as u64, (b >> 64) as u64);
            (lo, mid, hi)
        }

        fn lane_srli(x: u128, n: u32) -> u128 {
            let mut r = 0u128;
            for k in 0..4u32 {
                let lane = (x >> (32 * k)) & 0xFFFF_FFFF;
                r |= (lane >> n) << (32 * k);
            }
            r
        }

        fn lane_slli(x: u128, n: u32) -> u128 {
            let mut r = 0u128;
            for k in 0..4u32 {
                let lane = (x >> (32 * k)) & 0xFFFF_FFFF;
                r |= ((lane << n) & 0xFFFF_FFFF) << (32 * k);
            }
            r
        }

        pub(super) fn reduce(acc: (u128, u128, u128)) -> u128 {
            let (lo, mid, hi) = acc;
            let mut t3 = lo ^ (mid << 64);
            let mut t6 = hi ^ (mid >> 64);

            let c3 = lane_srli(t3, 31);
            let c6 = lane_srli(t6, 31);
            t3 = lane_slli(t3, 1);
            t6 = lane_slli(t6, 1);
            let carry = c3 >> 96;
            t3 |= c3 << 32;
            t6 |= c6 << 32;
            t6 |= carry;

            let a = lane_slli(t3, 31);
            let b = lane_slli(t3, 30);
            let c = lane_slli(t3, 25);
            let mut r = a ^ b ^ c;
            let r_hi = r >> 32;
            r <<= 96;
            t3 ^= r;

            let d = lane_srli(t3, 1);
            let e = lane_srli(t3, 2);
            let f = lane_srli(t3, 7);
            t3 ^= d ^ e ^ f ^ r_hi;
            t6 ^ t3
        }

        pub(super) fn gfmul(a: u128, b: u128) -> u128 {
            reduce(mul_acc(a, b))
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn u128_reference_matches_the_x86_backend() {
        use super::ni;
        use core::arch::x86_64::__m128i;
        use core::mem::transmute;

        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        };

        for i in 0..500u32 {
            let mut ra = [0u8; 16];
            let mut rb = [0u8; 16];
            let mut rc = [0u8; 16];
            for byte in ra.iter_mut().chain(rb.iter_mut()).chain(rc.iter_mut()) {
                *byte = next() as u8;
            }
            let a = u128::from_le_bytes(ra);
            let b = u128::from_le_bytes(rb);
            let c = u128::from_le_bytes(rc);

            let got: u128 = unsafe { transmute(ni::bswap(transmute::<[u8; 16], __m128i>(ra))) };
            assert_eq!(got, v8_ref::bswap(a), "bswap case {i}, a={a:032x}");

            let va: __m128i = unsafe { transmute(a) };
            let vb: __m128i = unsafe { transmute(b) };

            let mut acc: (__m128i, __m128i, __m128i) = unsafe {
                (
                    transmute::<u128, __m128i>(0u128),
                    transmute::<u128, __m128i>(0u128),
                    transmute::<u128, __m128i>(0u128),
                )
            };
            unsafe { ni::mul_acc(va, vb, &mut acc) };
            let got_acc: (u128, u128, u128) = unsafe {
                (
                    transmute::<__m128i, u128>(acc.0),
                    transmute::<__m128i, u128>(acc.1),
                    transmute::<__m128i, u128>(acc.2),
                )
            };
            assert_eq!(
                got_acc,
                v8_ref::mul_acc(a, b),
                "mul_acc case {i}, a={a:032x} b={b:032x}"
            );

            let triple = (a, b, c);
            let in_triple: (__m128i, __m128i, __m128i) = unsafe {
                (
                    transmute::<u128, __m128i>(triple.0),
                    transmute::<u128, __m128i>(triple.1),
                    transmute::<u128, __m128i>(triple.2),
                )
            };
            let got: u128 = unsafe { transmute(ni::reduce(in_triple)) };
            assert_eq!(
                got,
                v8_ref::reduce(triple),
                "reduce case {i}, in={triple:032x?}"
            );

            let got: u128 = unsafe { transmute(ni::gfmul(va, vb)) };
            assert_eq!(
                got,
                v8_ref::gfmul(a, b),
                "gfmul case {i}, a={a:032x} b={b:032x}"
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn v8_math_matches_the_x86_sequence() {
        use super::v8;
        use core::arch::aarch64::uint8x16_t;
        use core::mem::transmute;

        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        };

        for i in 0..500u32 {
            let mut ra = [0u8; 16];
            let mut rb = [0u8; 16];
            let mut rc = [0u8; 16];
            for byte in ra.iter_mut().chain(rb.iter_mut()).chain(rc.iter_mut()) {
                *byte = next() as u8;
            }
            let a = u128::from_le_bytes(ra);
            let b = u128::from_le_bytes(rb);
            let c = u128::from_le_bytes(rc);

            let got: u128 = unsafe { transmute(v8::bswap(transmute::<[u8; 16], uint8x16_t>(ra))) };
            assert_eq!(got, v8_ref::bswap(a), "bswap case {i}, a={a:032x}");

            let va: uint8x16_t = unsafe { transmute(a) };
            let vb: uint8x16_t = unsafe { transmute(b) };

            let mut acc: (uint8x16_t, uint8x16_t, uint8x16_t) = unsafe {
                (
                    transmute::<u128, uint8x16_t>(0u128),
                    transmute::<u128, uint8x16_t>(0u128),
                    transmute::<u128, uint8x16_t>(0u128),
                )
            };
            unsafe { v8::mul_acc(va, vb, &mut acc) };
            let got_acc: (u128, u128, u128) = unsafe {
                (
                    transmute::<uint8x16_t, u128>(acc.0),
                    transmute::<uint8x16_t, u128>(acc.1),
                    transmute::<uint8x16_t, u128>(acc.2),
                )
            };
            assert_eq!(
                got_acc,
                v8_ref::mul_acc(a, b),
                "mul_acc case {i}, a={a:032x} b={b:032x}"
            );

            let triple = (a, b, c);
            let in_triple: (uint8x16_t, uint8x16_t, uint8x16_t) = unsafe {
                (
                    transmute::<u128, uint8x16_t>(triple.0),
                    transmute::<u128, uint8x16_t>(triple.1),
                    transmute::<u128, uint8x16_t>(triple.2),
                )
            };
            let got: u128 = unsafe { transmute(v8::reduce(in_triple)) };
            assert_eq!(
                got,
                v8_ref::reduce(triple),
                "reduce case {i}, in={triple:032x?}"
            );

            let got: u128 = unsafe { transmute(v8::gfmul(va, vb)) };
            assert_eq!(
                got,
                v8_ref::gfmul(a, b),
                "gfmul case {i}, a={a:032x} b={b:032x}"
            );
        }
    }
}
