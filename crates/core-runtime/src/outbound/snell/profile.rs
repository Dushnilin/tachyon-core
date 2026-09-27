//! snell v6 shaped-mode profile derivation (reference sing-snell
//! `snellv6/profile.go`, `snellv6/salt.go`, `snellv6/mixing.go`): the PSK is
//! expanded into a deterministic parameter set (padding generators, chunk and
//! write-target policies, salt-block shuffling) plus the PRF primitives that
//! consume it. Everything is SplitMix64-based integer math — no floating point.

use std::io;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use super::crypto::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, SALT_LEN};

// ------------------------------------------------------------------ prf ----

const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;
const MAX_EXTRA_PADDING: i64 = 0x02da;
const SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_SALT: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_FIRST_CAP: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PAD: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_V: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_V: u32 = 39;

const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

const PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

const BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

fn prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

/// Reference `pick`: uniform value in `lo..=hi` (modulo bias preserved).
fn pick(raw: u32, lo: i64, hi: i64) -> i64 {
    lo + (u64::from(raw) % (hi - lo + 1) as u64) as i64
}

fn pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    lo + raw % (hi - lo + 1)
}

fn go_min(a: i64, b: i64) -> i64 {
    if a < b { a } else { b }
}

fn go_max(a: i64, b: i64) -> i64 {
    if a > b { a } else { b }
}

/// Cross-slice byte swap used by the mix generators (reference: the mix
/// functions exchange `padding[i]` and `payloadCipher[i]` in place).
fn swap_across(a: &mut [u8], b: &mut [u8], index: usize) {
    std::mem::swap(&mut a[index], &mut b[index]);
}

// ------------------------------------------------------------ namespaces ----

#[derive(Clone, Copy)]
pub(super) struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

fn derive_namespace(secret: &[u8], label: u32, seed_const: u64) -> u64 {
    let s0 = u64::from_le_bytes(secret[0..8].try_into().expect("snell: secret slice"));
    let s1 = u64::from_le_bytes(secret[8..16].try_into().expect("snell: secret slice"));
    let s2 = u64::from_le_bytes(secret[16..24].try_into().expect("snell: secret slice"));
    let s3 = u64::from_le_bytes(secret[24..32].try_into().expect("snell: secret slice"));
    let mixed = u64::from(label).wrapping_mul(DOMAIN_MUL)
        ^ seed_const.wrapping_add(NAMESPACE_ADD)
        ^ s0
        ^ s1.wrapping_add(GOLDEN_GAMMA)
        ^ s2.rotate_left(17)
        ^ s3.rotate_right(11);
    splitmix64(mixed)
}

fn new_namespaces(secret: &[u8]) -> Namespaces {
    Namespaces {
        profile: derive_namespace(secret, LABEL_PROFILE_ID, NS_SEED_PROFILE),
        prefix: derive_namespace(secret, LABEL_PADDING, NS_SEED_PREFIX),
        motif: derive_namespace(secret, LABEL_MOTIF, NS_SEED_MOTIF),
        salt: derive_namespace(secret, LABEL_SALT, NS_SEED_SALT),
        mix: derive_namespace(secret, LABEL_MIX_MODE, NS_SEED_MIX),
        chunk: derive_namespace(secret, LABEL_CHUNK_POLICY, NS_SEED_CHUNK),
        write: derive_namespace(secret, LABEL_WRITE_POLICY, NS_SEED_WRITE),
    }
}

impl Namespaces {
    fn for_label(&self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN | LABEL_PREFIX_MAX
            | LABEL_RECORD_PREFIX | LABEL_PAYLOAD_PAD => self.prefix,
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY | LABEL_CHUNK_INITIAL | LABEL_CHUNK_MAX | LABEL_CHUNK_STEP
            | LABEL_CHUNK_JITTER | LABEL_CHUNK_BUCKET | LABEL_CHUNK_SIZE | LABEL_CHUNK_JITTER_V => {
                self.chunk
            }
            LABEL_WRITE_POLICY | LABEL_WRITE_FIRST | LABEL_WRITE_BUCKET | LABEL_WRITE_SEQ
            | LABEL_WRITE_JITTER | LABEL_WRITE_TARGET | LABEL_WRITE_JITTER_V | LABEL_WRITE_NEXT => {
                self.write
            }
            _ => self.profile,
        }
    }

    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        prf32_fold(self.for_label(label), label, u64::from(a), u64::from(b))
    }

    fn prf_bytes(&self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ u64::from(a)
                .wrapping_mul(DOMAIN_MUL)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ u64::from(label).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (output.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        let mut offset = 0;
        while offset < output.len() {
            seed = seed.wrapping_add(GOLDEN_GAMMA);
            let block = splitmix64(seed);
            for shift in (0..64).step_by(8) {
                if offset >= output.len() {
                    break;
                }
                output[offset] = (block >> shift) as u8;
                offset += 1;
            }
        }
    }

    fn prf_static(&self, label: u32, domain: u32) -> u32 {
        prf32_fold(self.for_label(label), label, 0, u64::from(domain))
    }
}

// --------------------------------------------------------------- profile ----

pub(crate) struct Profile {
    pub(super) namespaces: Namespaces,

    pub(super) generator: u32,
    pub(super) pad_min: i64,
    pub(super) pad_max: i64,
    pub(super) pad_count: u32,
    pub(super) pad_interval: u32,
    pub(super) small_limit: i64,
    pub(super) bit_min: u32,
    pub(super) bit_max: u32,
    pub(super) prefix_min_record: i64,
    pub(super) prefix_max_record: i64,
    pub(super) mix_mode: u32,
    pub(super) mix_rounds: u32,
    pub(super) mix_stride: i64,
    pub(super) mix_offset_base: i64,
    pub(super) mix_block: i64,
    pub(super) chunk_policy: u32,
    pub(super) chunk_initial: i64,
    pub(super) first_record_cap: i64,
    pub(super) chunk_max: i64,
    pub(super) chunk_step: i64,
    pub(super) chunk_jitter: i64,
    pub(super) idle_reset_sec: i64,
    pub(super) write_policy: u32,
    pub(super) write_first: u32,
    pub(super) chunk_buckets: [i64; 8],
    pub(super) write_buckets: [i64; 8],
    pub(super) write_seq: [i64; 8],
    pub(super) write_jitter: i64,
    pub(super) write_jitter_pct: i64,
    pub(super) g1: i64,
    pub(super) g2: i64,
    pub(super) g3: i64,
    pub(super) g4: i64,
    pub(super) g5: i64,
    pub(super) g6: i64,

    pub(super) salt_block_len: i64,
    pub(super) mix_stride_handshake: u32,
    pub(super) mix_rounds_handshake: u32,

    // Reference `recordPrefixMax`/`padMaxHeadroom` headroom metadata:
    // validated against the golden dump, mirrored for parity reporting.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) record_prefix_max: i64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) pad_max_headroom: i64,
}

fn profile_secret(psk: &[u8]) -> io::Result<[u8; 32]> {
    let mut input = Vec::with_capacity(PROFILE_SEED.len() + psk.len());
    input.extend_from_slice(&PROFILE_SEED);
    input.extend_from_slice(psk);
    let mut hasher =
        Blake2bVar::new(32).map_err(|e| io::Error::other(format!("snell: blake2b: {e}")))?;
    hasher.update(&input);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|e| io::Error::other(format!("snell: blake2b: {e}")))?;
    Ok(out)
}

impl Profile {
    pub(crate) fn new(psk: &[u8]) -> io::Result<Self> {
        let secret = profile_secret(psk)?;
        let ns = new_namespaces(&secret);

        let pad_min = pick(ns.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = go_min(
            pad_min + pick(ns.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0),
            MAX_EXTRA_PADDING,
        );

        let mut prefix_min_hs = pick(
            ns.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let mut prefix_max_hs = go_min(
            prefix_min_hs
                + pick(
                    ns.prf_static(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN),
                    0x10,
                    0xa0,
                ),
            0x80,
        );
        prefix_min_hs = go_min(prefix_min_hs, prefix_max_hs);
        prefix_max_hs = go_max(prefix_max_hs, prefix_min_hs);
        let salt_prefix_len = pick(
            ns.prf_static(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN),
            prefix_min_hs,
            prefix_max_hs,
        );
        let salt_block_len = SALT_LEN as i64 + salt_prefix_len;

        let mix_rounds_hs = pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN), 1, 4);
        let mix_stride_hs = pick(
            ns.prf_static(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
            0x11,
            0xfb,
        );

        let mut prefix_min_record = pick(ns.prf_static(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let mut prefix_max_record = go_min(
            prefix_min_record + pick(ns.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0),
            0x80,
        );
        prefix_min_record = go_min(prefix_min_record, prefix_max_record);
        prefix_max_record = go_max(prefix_max_record, prefix_min_record);

        let chunk_initial = go_max(
            0x60,
            go_min(
                pick(ns.prf_static(LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4),
                0x05b4,
            ),
        );
        let first_record_cap = go_max(
            0x100,
            go_min(
                pick(
                    ns.prf_static(LABEL_CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN),
                    0x100,
                    0x300,
                ),
                go_min(chunk_initial, 0x300),
            ),
        );
        let chunk_max = go_max(
            pick(ns.prf_static(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff),
            chunk_initial,
        );

        let mut profile = Self {
            namespaces: ns,
            generator: ns.prf_static(LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: pick_u32(ns.prf_static(LABEL_PAD_COUNT, 0), 2, 8),
            pad_interval: pick_u32(ns.prf_static(LABEL_PAD_INTERVAL, 0), 2, 0x0b),
            small_limit: pick(ns.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300),
            bit_min: pick_u32(ns.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: pick_u32(ns.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min_record,
            prefix_max_record,
            mix_mode: ns.prf_static(LABEL_MIX_MODE, 0) % 3,
            mix_rounds: pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: pick(ns.prf_static(LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset_base: pick(ns.prf_static(LABEL_MIX_OFFSET_BASE, 0), 0, 15),
            mix_block: pick(ns.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: ns.prf_static(LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: go_min(
                pick(ns.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000),
                0x0b68,
            ),
            chunk_jitter: go_min(
                pick(ns.prf_static(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0),
                0x0b6,
            ),
            idle_reset_sec: pick(ns.prf_static(LABEL_IDLE_RESET, 0), 0x0c, 0x5a),
            write_policy: ns.prf_static(LABEL_WRITE_POLICY, 0) % 3,
            write_first: pick_u32(ns.prf_static(LABEL_WRITE_FIRST, 0), 4, 8),
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_seq: [0; 8],
            write_jitter: pick(ns.prf_static(LABEL_WRITE_JITTER, 0), 0x08, 0x60),
            write_jitter_pct: pick(ns.prf_static(LABEL_WRITE_POLICY, 0x504c), 8, 0x30),
            g1: pick(ns.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80),
            g2: pick(ns.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60),
            g3: pick(ns.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60),
            g4: pick(ns.prf_static(LABEL_GENERATOR, 4), 0x00, 0x09),
            g5: pick(ns.prf_static(LABEL_GENERATOR, 5), 0x01, 0x08),
            g6: pick(ns.prf_static(LABEL_GENERATOR, 6), 0x07, 0x17),
            salt_block_len,
            mix_stride_handshake: mix_stride_hs as u32,
            mix_rounds_handshake: mix_rounds_hs,
            record_prefix_max: prefix_max_record,
            pad_max_headroom: pad_max + MAX_EXTRA_PADDING,
        };

        for index in 0..8usize {
            profile.chunk_buckets[index] = pick(
                ns.prf_static(LABEL_CHUNK_BUCKET, index as u32),
                0x1000,
                chunk_max,
            );
            profile.write_buckets[index] = pick(
                ns.prf_static(LABEL_WRITE_BUCKET, index as u32),
                0x140,
                0x05b4,
            );
            profile.write_seq[index] =
                pick(ns.prf_static(LABEL_WRITE_SEQ, index as u32), 0x168, 0x05b4);
        }

        Ok(profile)
    }

    pub(crate) fn record_prefix_len(&self, seq: u32) -> i64 {
        pick(
            self.namespaces.prf32(LABEL_RECORD_PREFIX, seq, 0),
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    pub(crate) fn chunk_payload_limit(&self, seq: u32, chunk_size: i64) -> i64 {
        let mut chunk_size = if chunk_size == 0 {
            self.chunk_initial
        } else {
            chunk_size
        };
        match self.chunk_policy {
            1 => {
                let index = (self
                    .namespaces
                    .prf32(LABEL_CHUNK_SIZE, seq, chunk_size as u32)
                    % 8) as usize;
                chunk_size = self.chunk_buckets[index];
            }
            2 => {
                let raw = self
                    .namespaces
                    .prf32(LABEL_CHUNK_JITTER_V, seq, chunk_size as u32);
                chunk_size += (raw % (self.chunk_jitter as u32 * 2 + 1)) as i64 - self.chunk_jitter;
            }
            _ => {}
        }
        go_max(0x40, go_min(chunk_size, self.chunk_max))
    }

    pub(crate) fn next_chunk_size(&self, chunk_size: i64) -> i64 {
        if chunk_size == 0 {
            return self.chunk_initial;
        }
        go_min(chunk_size + self.chunk_step, self.chunk_max)
    }

    pub(crate) fn padding_len(
        &self,
        seq: u32,
        payload_len: i64,
        prefix_len: i64,
        salt_prefix_len: i64,
        total_len: i64,
    ) -> i64 {
        let mut padding_len = 0;
        if seq < self.pad_count
            || (payload_len > 0 && payload_len <= self.small_limit)
            || (self.pad_interval > 0 && seq.is_multiple_of(self.pad_interval))
        {
            padding_len = pick(
                self.namespaces
                    .prf32(LABEL_PAYLOAD_PAD, seq, payload_len as u32),
                self.pad_min,
                self.pad_max,
            );
        }
        let payload_tag_len = if payload_len > 0 {
            AEAD_TAG_LEN as i64
        } else {
            0
        };
        let frame_len = total_len
            + prefix_len
            + HEADER_CIPHER_LEN as i64
            + padding_len
            + payload_len
            + payload_tag_len;
        let target_len = self.write_target(seq, frame_len);
        if target_len > frame_len {
            padding_len += go_min(target_len - frame_len, MAX_EXTRA_PADDING);
        }
        if total_len > 0 {
            padding_len = self.first_record_padding_len(
                padding_len,
                prefix_len,
                salt_prefix_len,
                payload_len,
            );
        }
        go_min(padding_len, 0xffff)
    }

    fn write_target(&self, seq: u32, frame_len: i64) -> i64 {
        if frame_len > 0x05b3 {
            if frame_len <= 0xffff {
                return frame_len;
            }
            return 0xffff;
        }
        let mut target_len = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[(self
                .namespaces
                .prf32(LABEL_WRITE_TARGET, seq, frame_len as u32)
                % 8) as usize]
        };
        if self.write_policy == 2 {
            let raw = self.namespaces.prf32(LABEL_WRITE_JITTER_V, seq, 0);
            let jitter = (raw % (self.write_jitter as u32 * 2 + 1)) as i64 - self.write_jitter;
            target_len = go_max(target_len + jitter, 1);
        }
        let spread = go_min(MAX_EXTRA_PADDING, frame_len * self.write_jitter_pct / 100);
        if self
            .namespaces
            .prf32(LABEL_WRITE_TARGET, seq, spread as u32)
            & 1
            == 0
        {
            if target_len + spread <= 0xffff {
                target_len += spread;
            } else {
                target_len = 0xffff;
            }
        } else {
            let half = spread >> 1;
            if target_len > half {
                target_len -= half;
            }
        }
        while target_len >= 0 && frame_len > target_len {
            let mut next_len =
                self.write_buckets[(self
                    .namespaces
                    .prf32(LABEL_WRITE_NEXT, seq, target_len as u32)
                    % 8) as usize];
            if next_len <= target_len {
                next_len = target_len + self.pad_max;
                if next_len > 0xffff {
                    return 0xffff;
                }
            }
            target_len = next_len;
        }
        target_len
    }

    fn first_record_padding_len(
        &self,
        padding_len: i64,
        prefix_len: i64,
        salt_prefix_len: i64,
        payload_len: i64,
    ) -> i64 {
        let overhead_len = salt_prefix_len + prefix_len + padding_len;
        let threshold_input = if payload_len == 0 {
            payload_len + 0x27
        } else {
            payload_len + 0x37
        };
        let threshold = go_max((threshold_input * 25 + 0x4a) / 75, 0xc0);
        if overhead_len >= threshold {
            return padding_len;
        }
        let mut target_padding_len = threshold - salt_prefix_len - prefix_len;
        let max_padding_len = self.pad_max + MAX_EXTRA_PADDING;
        if max_padding_len <= target_padding_len {
            target_padding_len = max_padding_len;
        }
        if target_padding_len > 0xfffe {
            return padding_len;
        }
        target_padding_len
    }

    pub(crate) fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.namespaces.prf_bytes(LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                let bit_count = pick_u32(
                    self.namespaces.prf32(LABEL_BIT_PERCENT, seq, 0),
                    self.bit_min,
                    self.bit_max,
                );
                let mut rotate = 1i64;
                let scaled = i64::from(bit_count) * 8;
                if scaled > 0x31 {
                    rotate = 7;
                    if scaled <= 0x02ed {
                        rotate = (scaled + 0x32) / 100;
                    }
                }
                for (index, value) in output.iter_mut().enumerate() {
                    let raw = value.wrapping_add(index as u8);
                    let table_row = go_max(rotate, 1) as usize;
                    let table_value =
                        BIT_ROTATE_TABLE[table_row * 16 + usize::from((raw ^ *value) & 0x0f)];
                    *value = table_value.rotate_left(u32::from((raw ^ (*value >> 4)) & 0x07));
                }
            }
            1 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let bucket = i64::from(*value) % (self.g1 + self.g2 + self.g3);
                    if bucket < self.g1 {
                        *value = pick(u32::from(value.wrapping_add(index as u8)), 0x20, 0x7e) as u8;
                    } else if bucket < self.g1 + self.g2 {
                        *value = pick(u32::from(*value ^ (index as u8)), 0x80, 0xbf) as u8;
                    } else {
                        *value = pick(
                            u32::from(value.wrapping_add((index as u8).wrapping_mul(7))),
                            0xc0,
                            0xff,
                        ) as u8;
                    }
                }
            }
            2 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let low = (i64::from(*value & 0x0f) + self.g4 + (index as i64 & 1)) % 10;
                    let high = (i64::from(*value) + ((index as i64 & 3) << 4) + 0x30) & 0xf0;
                    *value = (high | low) as u8;
                }
            }
            _ => {
                let mut motif = [0u8; 32];
                self.namespaces.prf_bytes(LABEL_MOTIF, seq, &mut motif);
                let mut motif_len = (self.g5 * 4) as usize;
                if motif_len == 0 {
                    motif_len = 4;
                }
                let period = go_max(self.g6, 5) as usize;
                let mut block_offset = 0usize;
                let mut motif_offset = 0usize;
                for (index, value) in output.iter_mut().enumerate() {
                    if block_offset < period - 3 {
                        *value = ((self.g5 + 3) * index as i64) as u8 ^ motif[motif_offset % 32];
                    } else if block_offset < period - 1 {
                        *value = 0x30 | (i64::from(*value) % 10) as u8;
                    }
                    block_offset += 1;
                    if block_offset == period {
                        block_offset = 0;
                    }
                    motif_offset += 1;
                    if motif_offset == motif_len {
                        motif_offset = 0;
                    }
                }
            }
        }
    }

    pub(crate) fn mix_padding_payload(&self, seq: u32, padding: &mut [u8], payload: &mut [u8]) {
        let n = go_min(padding.len() as i64, payload.len() as i64) as usize;
        if n == 0 {
            return;
        }
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => self.mix_fixed_stride(round, padding, payload, n),
                1 => self.mix_alternating_block(round, padding, payload, n),
                _ => self.mix_prf_stride(seq, round, padding, payload, n),
            }
        }
    }

    fn mix_fixed_stride(&self, round: u32, padding: &mut [u8], payload: &mut [u8], n: usize) {
        let stride = go_max(self.mix_stride + i64::from(round % 3), 1);
        if stride == 1 {
            for i in 0..n {
                swap_across(padding, payload, i);
            }
            return;
        }
        let mut off = (self.mix_offset_base % stride) as usize;
        while off < n {
            swap_across(padding, payload, off);
            off += stride as usize;
        }
    }

    fn mix_alternating_block(&self, round: u32, padding: &mut [u8], payload: &mut [u8], n: usize) {
        let block = self.mix_block as usize;
        let mut off = (round as usize & 1) * block;
        while off + block <= n {
            for i in off..off + block {
                swap_across(padding, payload, i);
            }
            off += block * 2;
        }
    }

    fn mix_prf_stride(
        &self,
        seq: u32,
        round: u32,
        padding: &mut [u8],
        payload: &mut [u8],
        n: usize,
    ) {
        let stride = go_max(self.mix_stride + i64::from(round % 3), 1);
        let raw = self.namespaces.prf32(LABEL_MIX_OFFSET, seq, round);
        let mut off = ((u64::from(raw) + self.mix_offset_base as u64) % stride as u64) as usize;
        if stride == 1 {
            for i in 0..n {
                swap_across(padding, payload, i);
            }
            return;
        }
        while off < n {
            swap_across(padding, payload, off);
            off += stride as usize;
        }
    }

    fn salt_shuffle_prf(&self, domain: u32, index: u32) -> u32 {
        let rdx = u64::from(index).wrapping_mul(COEF_B).wrapping_add(ADD_B);
        let rdi = self.namespaces.salt ^ SALT_NS_XOR;
        let rsi = u64::from(domain).wrapping_mul(COEF_A).wrapping_add(ADD_A);
        let y = splitmix64((rdx ^ rdi) ^ rsi);
        (y ^ (y >> 32)) as u32
    }

    fn shuffle_perm(&self, rounds: u8, length: usize) -> Vec<u8> {
        let mut out: Vec<u8> = (0..length).map(|index| index as u8).collect();
        if length == 0 {
            return out;
        }
        let rounds = if rounds == 0 { 1 } else { rounds };
        for round in 0..u32::from(rounds) {
            let domain = MIX_HANDSHAKE_DOMAIN.wrapping_add(round);
            for i in 0..length {
                let span = (length - i) as u64;
                let raw = u64::from(self.salt_shuffle_prf(domain, i as u32));
                let j = i + (raw % span) as usize;
                out.swap(i, j);
            }
        }
        out
    }

    fn salt_mask(&self, index: u32) -> u8 {
        let prf = prf32_fold(
            self.namespaces.salt,
            LABEL_MOTIF,
            u64::from(MIX_HANDSHAKE_DOMAIN),
            u64::from(index),
        );
        (index as u8).wrapping_mul(self.mix_stride_handshake as u8) ^ prf as u8
    }

    pub(crate) fn extract_salt(&self, block: &[u8]) -> [u8; SALT_LEN] {
        let perm = self.shuffle_perm(self.mix_rounds_handshake as u8, block.len());
        let mut out = [0u8; SALT_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.salt_mask(index as u32) ^ block[perm[index] as usize];
        }
        out
    }

    pub(crate) fn write_salt_block(&self, salt: &[u8; SALT_LEN], block: &mut [u8]) {
        let perm = self.shuffle_perm(self.mix_rounds_handshake as u8, block.len());
        for (index, byte) in salt.iter().enumerate() {
            block[perm[index] as usize] = self.salt_mask(index as u32) ^ byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = include_str!("../../../tests/data/snellv6_golden.json");
    const PSK: &[u8] = b"deadbeefdeadbeefdeadbeefdeadbeef";

    fn golden() -> serde_json::Value {
        serde_json::from_str(GOLDEN).expect("golden json")
    }

    fn decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn profile_secret_matches_reference() {
        let secret = profile_secret(PSK).expect("secret");
        assert_eq!(encode(&secret), golden()["secret"].as_str().unwrap());
    }

    #[test]
    fn namespaces_match_reference() {
        let secret = profile_secret(PSK).expect("secret");
        let ns = new_namespaces(&secret);
        let golden = golden();
        let g = &golden["namespaces"];
        for (name, value) in [
            ("profile", ns.profile),
            ("prefix", ns.prefix),
            ("motif", ns.motif),
            ("salt", ns.salt),
            ("mix", ns.mix),
            ("chunk", ns.chunk),
            ("write", ns.write),
        ] {
            assert_eq!(format!("{value:016x}"), g[name].as_str().unwrap(), "{name}");
        }
    }

    #[test]
    fn profile_fields_match_reference() {
        let p = Profile::new(PSK).expect("profile");
        let g = &golden()["fields"];
        macro_rules! field {
            ($name:literal, $value:expr) => {
                assert_eq!(serde_json::json!($value), g[$name], "field {}", $name);
            };
        }
        field!("generator", p.generator);
        field!("padMin", p.pad_min);
        field!("padMax", p.pad_max);
        field!("padCount", p.pad_count);
        field!("padInterval", p.pad_interval);
        field!("smallLimit", p.small_limit);
        field!("bitMin", p.bit_min);
        field!("bitMax", p.bit_max);
        field!("prefixMinRecord", p.prefix_min_record);
        field!("prefixMaxRecord", p.prefix_max_record);
        field!("mixMode", p.mix_mode);
        field!("mixRounds", p.mix_rounds);
        field!("mixStride", p.mix_stride);
        field!("mixOffsetBase", p.mix_offset_base);
        field!("mixBlock", p.mix_block);
        field!("chunkPolicy", p.chunk_policy);
        field!("chunkInitial", p.chunk_initial);
        field!("firstRecordCap", p.first_record_cap);
        field!("chunkMax", p.chunk_max);
        field!("chunkStep", p.chunk_step);
        field!("chunkJitter", p.chunk_jitter);
        field!("idleResetSec", p.idle_reset_sec);
        field!("writePolicy", p.write_policy);
        field!("writeFirst", p.write_first);
        field!("writeJitter", p.write_jitter);
        field!("writeJitterPct", p.write_jitter_pct);
        field!("g1", p.g1);
        field!("g2", p.g2);
        field!("g3", p.g3);
        field!("g4", p.g4);
        field!("g5", p.g5);
        field!("g6", p.g6);
        field!("saltBlockLen", p.salt_block_len);
        field!("mixStrideHandshake", p.mix_stride_handshake);
        field!("mixRoundsHandshake", p.mix_rounds_handshake);
        field!("recordPrefixMax", p.record_prefix_max);
        field!("padMaxHeadroom", p.pad_max_headroom);
        for (name, value) in [
            ("chunkBuckets", p.chunk_buckets),
            ("writeBuckets", p.write_buckets),
            ("writeSeq", p.write_seq),
        ] {
            let expected: Vec<i64> = g[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap())
                .collect();
            assert_eq!(value.to_vec(), expected, "{name}");
        }
    }

    #[test]
    fn prf_static_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        let g = &golden()["prfStatic"];
        for (key, value) in g.as_object().unwrap() {
            let (label, domain) = key.split_once(':').expect("key");
            let got = p
                .namespaces
                .prf_static(label.parse().unwrap(), domain.parse().unwrap());
            assert_eq!(u64::from(got), value.as_u64().unwrap(), "prfStatic {key}");
        }
    }

    #[test]
    fn prf32_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        let g = &golden()["prf32"];
        for (key, value) in g.as_object().unwrap() {
            let (kind, arg) = key.split_once(':').expect("key");
            let arg: u32 = arg.parse().unwrap();
            let got = match kind {
                "recordPrefix" => p.namespaces.prf32(LABEL_RECORD_PREFIX, arg, 0),
                "payloadPad" => p.namespaces.prf32(LABEL_PAYLOAD_PAD, 9, arg),
                "chunkSize" => p.namespaces.prf32(LABEL_CHUNK_SIZE, arg, 1024),
                "chunkJitterV" => p.namespaces.prf32(LABEL_CHUNK_JITTER_V, arg, 1024),
                "writeTarget" => p.namespaces.prf32(LABEL_WRITE_TARGET, arg, 600),
                "writeNext" => p.namespaces.prf32(LABEL_WRITE_NEXT, arg, 300),
                "mixOffset" => p.namespaces.prf32(LABEL_MIX_OFFSET, arg, 2),
                "bitPercent" => p.namespaces.prf32(LABEL_BIT_PERCENT, arg, 0),
                "writeJitterV" => p.namespaces.prf32(LABEL_WRITE_JITTER_V, arg, 0),
                other => panic!("unknown prf32 sample {other}"),
            };
            assert_eq!(u64::from(got), value.as_u64().unwrap(), "prf32 {key}");
        }
    }

    #[test]
    fn prf_bytes_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        let g = &golden()["prfBytes"];
        for (seq, value) in g.as_object().unwrap() {
            let mut buf = [0u8; 64];
            p.namespaces
                .prf_bytes(LABEL_PADDING, seq.parse().unwrap(), &mut buf);
            assert_eq!(encode(&buf), value.as_str().unwrap(), "prfBytes {seq}");
        }
    }

    #[test]
    fn record_prefix_len_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        for (seq, value) in golden()["recordPrefixLen"].as_object().unwrap() {
            let seq: u32 = seq.parse().unwrap();
            assert_eq!(
                p.record_prefix_len(seq),
                value.as_i64().unwrap(),
                "recordPrefixLen {seq}"
            );
        }
    }

    #[test]
    fn padding_len_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        for entry in golden()["paddingLen"].as_array().unwrap() {
            let got = p.padding_len(
                entry["seq"].as_u64().unwrap() as u32,
                entry["payloadLen"].as_i64().unwrap(),
                entry["prefixLen"].as_i64().unwrap(),
                entry["saltPrefixLen"].as_i64().unwrap(),
                entry["totalLen"].as_i64().unwrap(),
            );
            assert_eq!(got, entry["out"].as_i64().unwrap(), "paddingLen {entry}");
        }
    }

    #[test]
    fn write_target_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        for entry in golden()["writeTarget"].as_array().unwrap() {
            let got = p.write_target(
                entry["seq"].as_u64().unwrap() as u32,
                entry["frameLen"].as_i64().unwrap(),
            );
            assert_eq!(got, entry["out"].as_i64().unwrap(), "writeTarget {entry}");
        }
    }

    #[test]
    fn first_record_padding_len_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        for entry in golden()["firstRecordPaddingLen"].as_array().unwrap() {
            let got = p.first_record_padding_len(
                entry["paddingLen"].as_i64().unwrap(),
                entry["prefixLen"].as_i64().unwrap(),
                entry["saltPrefixLen"].as_i64().unwrap(),
                entry["payloadLen"].as_i64().unwrap(),
            );
            assert_eq!(got, entry["out"].as_i64().unwrap(), "firstRecord {entry}");
        }
    }

    #[test]
    fn chunk_limits_match_reference() {
        let p = Profile::new(PSK).expect("profile");
        for entry in golden()["chunkPayloadLimit"].as_array().unwrap() {
            let got = p.chunk_payload_limit(
                entry["seq"].as_u64().unwrap() as u32,
                entry["chunkSize"].as_i64().unwrap(),
            );
            assert_eq!(got, entry["out"].as_i64().unwrap(), "chunkPayload {entry}");
        }
        for entry in golden()["nextChunkSize"].as_array().unwrap() {
            let got = p.next_chunk_size(entry["chunkSize"].as_i64().unwrap());
            assert_eq!(got, entry["out"].as_i64().unwrap(), "nextChunk {entry}");
        }
    }

    #[test]
    fn fill_padding_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        for (key, value) in golden()["fillPadding"].as_object().unwrap() {
            let (seq, length) = key.split_once(':').expect("key");
            let mut buf = vec![0u8; length.parse().unwrap()];
            p.fill_padding(seq.parse().unwrap(), &mut buf);
            assert_eq!(encode(&buf), value.as_str().unwrap(), "fillPadding {key}");
        }
    }

    #[test]
    fn salt_block_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        let g = &golden()["saltBlock"];
        let salt_vec = decode(g["salt"].as_str().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);
        let mut block = decode(g["block"].as_str().unwrap());
        p.write_salt_block(&salt, &mut block);
        assert_eq!(
            encode(&block),
            g["written"].as_str().unwrap(),
            "writeSaltBlock"
        );
        let extracted = p.extract_salt(&decode(g["block"].as_str().unwrap()));
        assert_eq!(
            encode(&extracted),
            g["extracted"].as_str().unwrap(),
            "extractSalt"
        );
        // extractSalt(writeSaltBlock(salt)) must round-trip.
        assert_eq!(p.extract_salt(&block), salt, "salt round-trip");
    }

    #[test]
    fn shuffle_perm_and_masks_match_reference() {
        let p = Profile::new(PSK).expect("profile");
        let golden = golden();
        let perm = p.shuffle_perm(p.mix_rounds_handshake as u8, p.salt_block_len as usize);
        let expected: Vec<u8> = golden["shufflePerm"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(perm, expected, "shufflePerm");
        for entry in golden["saltShufflePRF"].as_array().unwrap() {
            let got = p.salt_shuffle_prf(
                entry["domain"].as_u64().unwrap() as u32,
                entry["index"].as_u64().unwrap() as u32,
            );
            assert_eq!(
                u64::from(got),
                entry["out"].as_u64().unwrap(),
                "saltShufflePRF {entry}"
            );
        }
        for entry in golden["saltMask"].as_array().unwrap() {
            let got = p.salt_mask(entry["index"].as_u64().unwrap() as u32);
            assert_eq!(
                u32::from(got),
                entry["out"].as_u64().unwrap() as u32,
                "saltMask {entry}"
            );
        }
    }

    #[test]
    fn mix_padding_payload_matches_reference() {
        let p = Profile::new(PSK).expect("profile");
        let pad: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let payload: Vec<u8> = (0..96).map(|i| (0x40 + i) as u8).collect();
        for entry in golden()["mixPaddingPayload"].as_array().unwrap() {
            let mut pad_out = pad.clone();
            let mut payload_out = payload.clone();
            p.mix_padding_payload(
                entry["seq"].as_u64().unwrap() as u32,
                &mut pad_out,
                &mut payload_out,
            );
            assert_eq!(encode(&pad_out), entry["pad"].as_str().unwrap(), "mix pad");
            assert_eq!(
                encode(&payload_out),
                entry["cipher"].as_str().unwrap(),
                "mix cipher"
            );
        }
    }
}
