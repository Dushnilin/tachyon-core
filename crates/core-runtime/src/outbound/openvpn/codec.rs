//! OpenVPN static-key data codec — port of sing-openvpn
//! `data_codec_static.go` (+ `loadStaticKeyMaterialFromSource`).
//!
//! Wire layout (no opcode byte — static mode never has one):
//! `[HMAC][IV][packet_id BE32][timestamp BE32][PKCS7 payload]`.

use std::cell::RefCell;

use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit as KeyInit04};
use hmac::Hmac;
// aria / camellia / cast5 / des / sm4 ship the inout-era `cipher` 0.5 API.
use cipher05::common::{Block as Block05, BlockSizeUser as BlockSizeUser05, KeyInit as KeyInit05};
use cipher05::{BlockCipherDecrypt as BlockDecrypt05, BlockCipherEncrypt as BlockEncrypt05};

use super::replay::{ReplayWindow, replay_window_parameters};

const STATIC_KEY_MARKER_BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
const STATIC_KEY_MARKER_END: &str = "-----END OpenVPN Static key V1-----";

// ---------------------------------------------------------------------------
// auth (HMAC digest) selection — `staticHMACFactory`
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Ripemd160,
    Md5,
    None,
}

impl AuthKind {
    /// `staticHMACFactory` name table (`""` defaults to SHA1).
    pub fn parse(name: &str) -> Result<Self, String> {
        Ok(match name {
            "" | "SHA1" => Self::Sha1,
            "SHA224" => Self::Sha224,
            "SHA256" => Self::Sha256,
            "SHA384" => Self::Sha384,
            "SHA512" => Self::Sha512,
            "RIPEMD160" => Self::Ripemd160,
            "MD5" => Self::Md5,
            "NONE" => Self::None,
            _ => return Err("unsupported static key auth".to_string()),
        })
    }

    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Ripemd160 => 20,
            Self::Md5 => 16,
            Self::None => 0,
        }
    }
}

/// A keyed HMAC kept across packets: `new_from_slice` does the ipad/opad
/// hashing once per session instead of once per packet, and only the
/// message is fed in on each use.
pub enum CachedMac {
    Sha1(Hmac<sha1::Sha1>),
    Sha224(Hmac<sha2::Sha224>),
    Sha256(Hmac<sha2::Sha256>),
    Sha384(Hmac<sha2::Sha384>),
    Sha512(Hmac<sha2::Sha512>),
    Ripemd160(Hmac<ripemd::Ripemd160>),
    Md5(Hmac<md5::Md5>),
    None,
}

impl CachedMac {
    pub fn new(auth: AuthKind, key: &[u8]) -> Self {
        fn keyed<M: hmac::digest::KeyInit>(key: &[u8]) -> M {
            <M as hmac::digest::KeyInit>::new_from_slice(key).expect("hmac key length")
        }
        match auth {
            AuthKind::Sha1 => Self::Sha1(keyed(key)),
            AuthKind::Sha224 => Self::Sha224(keyed(key)),
            AuthKind::Sha256 => Self::Sha256(keyed(key)),
            AuthKind::Sha384 => Self::Sha384(keyed(key)),
            AuthKind::Sha512 => Self::Sha512(keyed(key)),
            AuthKind::Ripemd160 => Self::Ripemd160(keyed(key)),
            AuthKind::Md5 => Self::Md5(keyed(key)),
            AuthKind::None => Self::None,
        }
    }

    /// HMAC `data`, writing the tag into `out` and returning its length
    /// (0 for `AuthKind::None`). The tag lands on the caller's stack buffer
    /// — no per-packet `Vec`.
    pub fn compute_into(&mut self, data: &[u8], out: &mut [u8; 64]) -> usize {
        use hmac::digest::FixedOutputReset;
        fn go<M>(mac: &mut M, data: &[u8], out: &mut [u8; 64]) -> usize
        where
            M: hmac::Mac + FixedOutputReset,
        {
            hmac::digest::Update::update(mac, data);
            let tag = mac.finalize_reset().into_bytes();
            out[..tag.len()].copy_from_slice(&tag);
            tag.len()
        }
        match self {
            Self::Sha1(m) => go(m, data, out),
            Self::Sha224(m) => go(m, data, out),
            Self::Sha256(m) => go(m, data, out),
            Self::Sha384(m) => go(m, data, out),
            Self::Sha512(m) => go(m, data, out),
            Self::Ripemd160(m) => go(m, data, out),
            Self::Md5(m) => go(m, data, out),
            Self::None => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// block ciphers — `staticCipherKeySize` + `newStaticCipherBlock`
// ---------------------------------------------------------------------------

enum BlockCipher {
    None,
    Aes128(RefCell<aes::Aes128>),
    Aes192(RefCell<aes::Aes192>),
    Aes256(RefCell<aes::Aes256>),
    Blowfish(Box<blowfish::Blowfish>),
    Des(des::Des),
    TdesEde2(des::TdesEde2),
    TdesEde3(des::TdesEde3),
    Cast5(cast5::Cast5),
    Aria128(aria::Aria128),
    Aria192(aria::Aria192),
    Aria256(aria::Aria256),
    Camellia128(camellia::Camellia128),
    Camellia192(camellia::Camellia192),
    Camellia256(camellia::Camellia256),
    Seed(RefCell<kisaseed::SEED>),
    Sm4(sm4::Sm4),
}

/// `staticCipherKeySize` (0 → `NONE`).
pub fn cipher_key_size(cipher_name: &str) -> Result<usize, String> {
    Ok(match cipher_name {
        "BF-CBC" | "CAST5-CBC" | "AES-128-CBC" | "ARIA-128-CBC" | "CAMELLIA-128-CBC"
        | "SEED-CBC" | "SM4-CBC" => 16,
        "DES-CBC" => 8,
        "DES-EDE-CBC" => 16,
        "DES-EDE3-CBC" => 24,
        "AES-192-CBC" | "ARIA-192-CBC" | "CAMELLIA-192-CBC" => 24,
        "AES-256-CBC" | "ARIA-256-CBC" | "CAMELLIA-256-CBC" => 32,
        "NONE" => 0,
        _ => return Err("unsupported static key cipher".to_string()),
    })
}

impl BlockCipher {
    /// `newStaticCipherBlock` over the first `key_size` bytes of a key slot.
    fn new(cipher_name: &str, key_material: &[u8]) -> Result<Self, String> {
        let key_size = cipher_key_size(cipher_name)?;
        if cipher_name == "NONE" {
            return Ok(Self::None);
        }
        if key_size == 0 || key_size > key_material.len() {
            return Err("invalid static key cipher key size".to_string());
        }
        let key = &key_material[..key_size];
        Ok(match cipher_name {
            "BF-CBC" => Self::Blowfish(Box::new(
                blowfish::Blowfish::new_from_slice(key).map_err(|_| bad_key_length())?,
            )),
            "DES-CBC" => Self::Des(des::Des::new_from_slice(key).map_err(|_| bad_key_length())?),
            // Go expands the 16-byte DES-EDE key to K1|K2|K1 — identical to
            // two-key triple DES.
            "DES-EDE-CBC" => {
                Self::TdesEde2(des::TdesEde2::new_from_slice(key).map_err(|_| bad_key_length())?)
            }
            "DES-EDE3-CBC" => {
                Self::TdesEde3(des::TdesEde3::new_from_slice(key).map_err(|_| bad_key_length())?)
            }
            "CAST5-CBC" => {
                Self::Cast5(cast5::Cast5::new_from_slice(key).map_err(|_| bad_key_length())?)
            }
            "AES-128-CBC" => Self::Aes128(RefCell::new(
                aes::Aes128::new_from_slice(key).map_err(|_| bad_key_length())?,
            )),
            "AES-192-CBC" => Self::Aes192(RefCell::new(
                aes::Aes192::new_from_slice(key).map_err(|_| bad_key_length())?,
            )),
            "AES-256-CBC" => Self::Aes256(RefCell::new(
                aes::Aes256::new_from_slice(key).map_err(|_| bad_key_length())?,
            )),
            "ARIA-128-CBC" => {
                Self::Aria128(aria::Aria128::new_from_slice(key).map_err(|_| bad_key_length())?)
            }
            "ARIA-192-CBC" => {
                Self::Aria192(aria::Aria192::new_from_slice(key).map_err(|_| bad_key_length())?)
            }
            "ARIA-256-CBC" => {
                Self::Aria256(aria::Aria256::new_from_slice(key).map_err(|_| bad_key_length())?)
            }
            "CAMELLIA-128-CBC" => Self::Camellia128(
                camellia::Camellia128::new_from_slice(key).map_err(|_| bad_key_length())?,
            ),
            "CAMELLIA-192-CBC" => Self::Camellia192(
                camellia::Camellia192::new_from_slice(key).map_err(|_| bad_key_length())?,
            ),
            "CAMELLIA-256-CBC" => Self::Camellia256(
                camellia::Camellia256::new_from_slice(key).map_err(|_| bad_key_length())?,
            ),
            "SEED-CBC" => Self::Seed(RefCell::new(
                kisaseed::SEED::new_from_slice(key).map_err(|_| bad_key_length())?,
            )),
            "SM4-CBC" => Self::Sm4(sm4::Sm4::new_from_slice(key).map_err(|_| bad_key_length())?),
            _ => return Err("unsupported static key cipher".to_string()),
        })
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Blowfish(_)
            | Self::Des(_)
            | Self::TdesEde2(_)
            | Self::TdesEde3(_)
            | Self::Cast5(_) => 8,
            _ => 16,
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        macro_rules! enc {
            ($cipher:expr) => {{
                enc05($cipher, block);
            }};
        }
        match self {
            Self::None => {}
            Self::Aes128(c) => enc04(c, block),
            Self::Aes192(c) => enc04(c, block),
            Self::Aes256(c) => enc04(c, block),
            Self::Blowfish(c) => enc05(c.as_ref(), block),
            Self::Des(c) => enc!(c),
            Self::TdesEde2(c) => enc!(c),
            Self::TdesEde3(c) => enc!(c),
            Self::Cast5(c) => enc!(c),
            Self::Aria128(c) => enc!(c),
            Self::Aria192(c) => enc!(c),
            Self::Aria256(c) => enc!(c),
            Self::Camellia128(c) => enc!(c),
            Self::Camellia192(c) => enc!(c),
            Self::Camellia256(c) => enc!(c),
            Self::Seed(c) => enc04(c, block),
            Self::Sm4(c) => enc!(c),
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        macro_rules! dec {
            ($cipher:expr) => {{
                dec05($cipher, block);
            }};
        }
        match self {
            Self::None => {}
            Self::Aes128(c) => dec04(c, block),
            Self::Aes192(c) => dec04(c, block),
            Self::Aes256(c) => dec04(c, block),
            Self::Blowfish(c) => dec05(c.as_ref(), block),
            Self::Des(c) => dec!(c),
            Self::TdesEde2(c) => dec!(c),
            Self::TdesEde3(c) => dec!(c),
            Self::Cast5(c) => dec!(c),
            Self::Aria128(c) => dec!(c),
            Self::Aria192(c) => dec!(c),
            Self::Aria256(c) => dec!(c),
            Self::Camellia128(c) => dec!(c),
            Self::Camellia192(c) => dec!(c),
            Self::Camellia256(c) => dec!(c),
            Self::Seed(c) => dec04(c, block),
            Self::Sm4(c) => dec!(c),
        }
    }

    /// In-place CBC encryption over `data` (length is a block multiple).
    fn cbc_encrypt(&self, iv: &[u8], data: &mut [u8]) {
        let block_size = self.block_size();
        if block_size == 0 {
            return;
        }
        debug_assert!(block_size <= 16, "every cipher here has a <=16 byte block");
        let mut previous = [0u8; 16];
        previous[..block_size].copy_from_slice(&iv[..block_size]);
        for chunk in data.chunks_exact_mut(block_size) {
            for (byte, prev) in chunk.iter_mut().zip(previous[..block_size].iter()) {
                *byte ^= *prev;
            }
            self.encrypt_block(chunk);
            previous[..block_size].copy_from_slice(chunk);
        }
    }

    /// In-place CBC decryption over `data` (length is a block multiple).
    fn cbc_decrypt(&self, iv: &[u8], data: &mut [u8]) {
        let block_size = self.block_size();
        if block_size == 0 {
            return;
        }
        debug_assert!(block_size <= 16, "every cipher here has a <=16 byte block");
        let mut previous = [0u8; 16];
        previous[..block_size].copy_from_slice(&iv[..block_size]);
        let mut ciphertext = [0u8; 16];
        for chunk in data.chunks_exact_mut(block_size) {
            ciphertext[..block_size].copy_from_slice(chunk);
            self.decrypt_block(chunk);
            for (byte, prev) in chunk.iter_mut().zip(previous[..block_size].iter()) {
                *byte ^= *prev;
            }
            previous[..block_size].copy_from_slice(&ciphertext[..block_size]);
        }
    }
}

/// `cipher` 0.4 family (aes 0.8, kisaseed): `&mut self` methods behind a RefCell.
fn enc04<C: BlockSizeUser + BlockEncrypt>(cipher: &RefCell<C>, block: &mut [u8]) {
    let mut b = GenericArray::clone_from_slice(block);
    cipher.borrow_mut().encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

fn dec04<C: BlockSizeUser + BlockDecrypt>(cipher: &RefCell<C>, block: &mut [u8]) {
    let mut b = GenericArray::clone_from_slice(block);
    cipher.borrow_mut().decrypt_block(&mut b);
    block.copy_from_slice(&b);
}

/// `cipher` 0.5 family (aria, camellia, cast5, des, sm4).
fn enc05<C: BlockSizeUser05 + BlockEncrypt05>(cipher: &C, block: &mut [u8]) {
    let mut b: Block05<C> = clone_block05::<C>(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(b.as_ref());
}

fn dec05<C: BlockSizeUser05 + BlockDecrypt05>(cipher: &C, block: &mut [u8]) {
    let mut b: Block05<C> = clone_block05::<C>(block);
    cipher.decrypt_block(&mut b);
    block.copy_from_slice(b.as_ref());
}

fn clone_block05<C>(block: &[u8]) -> Block05<C>
where
    C: BlockSizeUser05,
{
    let mut out = Block05::<C>::default();
    out.as_mut_slice().copy_from_slice(block);
    out
}

/// Unreachable: the key length was validated by `cipher_key_size`.
fn bad_key_length() -> String {
    unreachable!("static key cipher key length was validated by cipher_key_size")
}

// ---------------------------------------------------------------------------
// key material — `loadStaticKeyMaterialFromSource` / `splitStaticKeyMaterial`
// ---------------------------------------------------------------------------

/// Load a static key from inline content or a file path; accepts raw 256
/// bytes, a PEM block, or 512 hex characters (whitespace tolerated).
pub fn load_static_key_material(
    content: Option<&str>,
    path: Option<&str>,
) -> Result<Vec<u8>, String> {
    let raw: Vec<u8> = match (content, path) {
        (Some(text), _) => text.as_bytes().to_vec(),
        (None, Some(file_path)) => {
            std::fs::read(file_path).map_err(|e| format!("read static key {file_path}: {e}"))?
        }
        (None, None) => return Err("missing openvpn static key".to_string()),
    };
    if raw.is_empty() {
        return Err("missing openvpn static key".to_string());
    }
    if raw.len() == 256 {
        return Ok(raw);
    }
    let mut static_key_text = String::from_utf8_lossy(&raw).into_owned();
    if let Some(begin_index) = static_key_text.find(STATIC_KEY_MARKER_BEGIN) {
        static_key_text =
            static_key_text[begin_index + STATIC_KEY_MARKER_BEGIN.len()..].to_string();
        let Some(end_index) = static_key_text.find(STATIC_KEY_MARKER_END) else {
            return Err("invalid static key end marker".to_string());
        };
        static_key_text.truncate(end_index);
    }
    let hex_content: String = static_key_text.split_whitespace().collect();
    if hex_content.len() != 512 {
        return Err("static key must contain exactly 256 bytes".to_string());
    }
    decode_hex(&hex_content)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit {byte:?}")),
    }
}

struct KeySlot {
    cipher_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

/// `splitStaticKeyMaterial`: 256 bytes → two 128-byte slots.
fn split_static_key_material(material: &[u8]) -> [KeySlot; 2] {
    [
        KeySlot {
            cipher_key: material[0..64].to_vec(),
            hmac_key: material[64..128].to_vec(),
        },
        KeySlot {
            cipher_key: material[128..192].to_vec(),
            hmac_key: material[192..256].to_vec(),
        },
    ]
}

/// `resolveStaticKeyDirection`: (send, receive, receive-fallback).
fn resolve_static_key_direction(key_direction: i32) -> (usize, usize, Option<usize>) {
    if key_direction == 1 || key_direction == 2 {
        (1, 0, Some(1))
    } else if key_direction < 0 {
        (0, 0, Some(1))
    } else {
        (0, 1, Some(0))
    }
}

// ---------------------------------------------------------------------------
// PKCS7 — `pkcs7Pad` / `pkcs7Unpad`
// ---------------------------------------------------------------------------

fn pkcs7_pad(payload: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 {
        return Err("invalid block size".to_string());
    }
    let mut padding_size = block_size - payload.len() % block_size;
    if padding_size == 0 {
        padding_size = block_size;
    }
    let mut padded = Vec::with_capacity(payload.len() + padding_size);
    padded.extend_from_slice(payload);
    padded.resize(payload.len() + padding_size, padding_size as u8);
    Ok(padded)
}

fn pkcs7_unpad_inplace(payload: &mut Vec<u8>, block_size: usize) -> Result<(), String> {
    if block_size == 0 || payload.is_empty() || !payload.len().is_multiple_of(block_size) {
        return Err("invalid static key payload padding".to_string());
    }
    let padding_size = payload[payload.len() - 1] as usize;
    if padding_size == 0 || padding_size > block_size || padding_size > payload.len() {
        return Err("invalid static key payload padding".to_string());
    }
    let padding_start = payload.len() - padding_size;
    if payload[padding_start..]
        .iter()
        .any(|b| *b as usize != padding_size)
    {
        return Err("invalid static key payload padding".to_string());
    }
    payload.truncate(padding_start);
    Ok(())
}

#[cfg(test)]
fn pkcs7_unpad(payload: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    let mut buf = payload.to_vec();
    pkcs7_unpad_inplace(&mut buf, block_size)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// codec — `staticKeyDataCodec`
// ---------------------------------------------------------------------------

struct DecodeCandidate {
    cipher: BlockCipher,
    hmac_key: Vec<u8>,
}

pub struct StaticCodec {
    send_cipher: BlockCipher,
    send_mac: CachedMac,
    receive_candidates: Vec<DecodeCandidate>,
    receive_macs: Vec<CachedMac>,
    hmac_size: usize,
    send_timestamp: u32,
    replay: ReplayWindow,
    next_packet_id: u32,
}

impl StaticCodec {
    /// `newStaticKeyDataCodec`; errors are terminal session-configuration
    /// failures (mirrors `errClientSessionConfiguration`).
    pub fn new(
        material: &[u8],
        key_direction: i32,
        cipher_name: &str,
        auth_name: &str,
        replay_window_size: u32,
        replay_window_time: std::time::Duration,
    ) -> Result<Self, String> {
        if material.len() != 256 {
            return Err("static key must contain exactly 256 bytes".to_string());
        }
        let auth = AuthKind::parse(auth_name)?;
        let hmac_size = auth.size();
        let key_slots = split_static_key_material(material);
        let (send_index, receive_index, fallback_index) =
            resolve_static_key_direction(key_direction);
        let send_cipher = BlockCipher::new(cipher_name, &key_slots[send_index].cipher_key)?;
        let receive_cipher = BlockCipher::new(cipher_name, &key_slots[receive_index].cipher_key)?;
        let send_hmac_key = if hmac_size > 0 {
            key_slots[send_index].hmac_key[..hmac_size].to_vec()
        } else {
            Vec::new()
        };
        let send_mac = CachedMac::new(auth, &send_hmac_key);
        let mut receive_candidates = vec![DecodeCandidate {
            cipher: receive_cipher,
            hmac_key: if hmac_size > 0 {
                key_slots[receive_index].hmac_key[..hmac_size].to_vec()
            } else {
                Vec::new()
            },
        }];
        if let Some(fallback_index) = fallback_index
            && fallback_index != receive_index
        {
            let fallback_cipher =
                BlockCipher::new(cipher_name, &key_slots[fallback_index].cipher_key)?;
            receive_candidates.push(DecodeCandidate {
                cipher: fallback_cipher,
                hmac_key: if hmac_size > 0 {
                    key_slots[fallback_index].hmac_key[..hmac_size].to_vec()
                } else {
                    Vec::new()
                },
            });
        }
        let (window_size, window_time) =
            replay_window_parameters(replay_window_size, replay_window_time);
        let receive_macs = receive_candidates
            .iter()
            .map(|c| CachedMac::new(auth, &c.hmac_key))
            .collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        Ok(Self {
            send_cipher,
            send_mac,
            receive_candidates,
            receive_macs,
            hmac_size,
            send_timestamp: now,
            replay: ReplayWindow::new(window_size, window_time),
            next_packet_id: 1,
        })
    }

    /// `EncodedLength` (budget/MSS math only).
    pub fn encoded_length(&self, payload_length: usize) -> usize {
        let plain_length = 8 + payload_length;
        let protected_length = if self.send_cipher.block_size() > 0 {
            let block_size = self.send_cipher.block_size();
            block_size + (plain_length / block_size + 1) * block_size
        } else {
            plain_length
        };
        self.hmac_size + protected_length
    }

    /// Next outgoing packet with the session packet-id sequence
    /// (`NewDataPacketIDs`: first id is 1).
    pub fn encode_next(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
        self.encode(packet_id, payload)
    }

    /// `Encode`.
    pub fn encode(&mut self, packet_id: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
        if packet_id == 0 {
            return Err("invalid static key packet id".to_string());
        }
        let mut plain_payload = Vec::with_capacity(8 + payload.len());
        plain_payload.extend_from_slice(&packet_id.to_be_bytes());
        plain_payload.extend_from_slice(&self.send_timestamp.to_be_bytes());
        plain_payload.extend_from_slice(payload);
        let mut protected_payload = plain_payload;
        let block_size = self.send_cipher.block_size();
        if block_size > 0 {
            protected_payload = pkcs7_pad(&protected_payload, block_size)?;
            let mut iv = vec![0u8; block_size];
            getrandom::fill(&mut iv).map_err(|e| format!("getrandom: {e}"))?;
            self.send_cipher.cbc_encrypt(&iv, &mut protected_payload);
            let mut with_iv = iv;
            with_iv.append(&mut protected_payload);
            protected_payload = with_iv;
        }
        if self.hmac_size > 0 {
            // one buffer for the whole packet: tag and payload written in,
            // no intermediate `Vec` from the mac and no regrowth past it
            let mut tag = [0u8; 64];
            let n = self.send_mac.compute_into(&protected_payload, &mut tag);
            let mut encoded = Vec::with_capacity(n + protected_payload.len());
            encoded.extend_from_slice(&tag[..n]);
            encoded.extend_from_slice(&protected_payload);
            return Ok(encoded);
        }
        Ok(protected_payload)
    }

    /// `Decode`: candidate fallback then replay check (terminal on replay).
    pub fn decode(&mut self, payload: &[u8]) -> Result<(u32, Vec<u8>), String> {
        let mut decode_error: Option<String> = None;
        for candidate_index in 0..self.receive_candidates.len() {
            match self.decode_with_candidate(payload, candidate_index) {
                Ok((packet_id, timestamp, decoded)) => {
                    if !self.replay.accept_long_form(packet_id, timestamp) {
                        return Err("replayed static key data packet".to_string());
                    }
                    return Ok((packet_id, decoded));
                }
                Err(err) => decode_error = Some(err),
            }
        }
        Err(decode_error.unwrap_or_else(|| "invalid static key payload".to_string()))
    }

    fn decode_with_candidate(
        &mut self,
        payload: &[u8],
        candidate_index: usize,
    ) -> Result<(u32, u32, Vec<u8>), String> {
        if self.hmac_size > 0 {
            if payload.len() < self.hmac_size {
                return Err("invalid static key payload".to_string());
            }
            let (received_mac, rest) = payload.split_at(self.hmac_size);
            let mut tag = [0u8; 64];
            let n = self.receive_macs[candidate_index].compute_into(rest, &mut tag);
            if !constant_time_eq(received_mac, &tag[..n]) {
                return Err("invalid static key payload hmac".to_string());
            }
            let block_size = self.receive_candidates[candidate_index].cipher.block_size();
            let plain_payload = if block_size > 0 {
                if rest.len() < block_size * 2 || !rest.len().is_multiple_of(block_size) {
                    return Err("invalid static key payload".to_string());
                }
                let iv = &rest[..block_size];
                let mut buf = rest[block_size..].to_vec();
                self.receive_candidates[candidate_index]
                    .cipher
                    .cbc_decrypt(iv, &mut buf);
                pkcs7_unpad_inplace(&mut buf, block_size)?;
                buf
            } else {
                rest.to_vec()
            };
            return Self::finish_decode(plain_payload);
        }
        let block_size = self.receive_candidates[candidate_index].cipher.block_size();
        let plain_payload = if block_size > 0 {
            if payload.len() < block_size * 2 || !payload.len().is_multiple_of(block_size) {
                return Err("invalid static key payload".to_string());
            }
            let iv = &payload[..block_size];
            let mut buf = payload[block_size..].to_vec();
            self.receive_candidates[candidate_index]
                .cipher
                .cbc_decrypt(iv, &mut buf);
            pkcs7_unpad_inplace(&mut buf, block_size)?;
            buf
        } else {
            payload.to_vec()
        };
        Self::finish_decode(plain_payload)
    }

    fn finish_decode(mut plain_payload: Vec<u8>) -> Result<(u32, u32, Vec<u8>), String> {
        if plain_payload.len() < 8 {
            return Err("invalid static key payload".to_string());
        }
        let packet_id = u32::from_be_bytes(plain_payload[..4].try_into().expect("4 bytes"));
        if packet_id == 0 {
            return Err("invalid static key packet id".to_string());
        }
        let timestamp = u32::from_be_bytes(plain_payload[4..8].try_into().expect("4 bytes"));
        plain_payload.drain(..8);
        Ok((packet_id, timestamp, plain_payload))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_key(byte: u8) -> Vec<u8> {
        vec![byte; 256]
    }

    #[test]
    fn auth_sizes_and_names() {
        assert_eq!(AuthKind::parse("").unwrap(), AuthKind::Sha1);
        assert_eq!(AuthKind::parse("SHA1").unwrap().size(), 20);
        assert_eq!(AuthKind::parse("SHA224").unwrap().size(), 28);
        assert_eq!(AuthKind::parse("SHA256").unwrap().size(), 32);
        assert_eq!(AuthKind::parse("SHA384").unwrap().size(), 48);
        assert_eq!(AuthKind::parse("SHA512").unwrap().size(), 64);
        assert_eq!(AuthKind::parse("RIPEMD160").unwrap().size(), 20);
        assert_eq!(AuthKind::parse("MD5").unwrap().size(), 16);
        assert_eq!(AuthKind::parse("NONE").unwrap().size(), 0);
        assert!(AuthKind::parse("SHA3").is_err());
    }

    #[test]
    fn cipher_names_and_key_sizes() {
        for name in [
            "BF-CBC",
            "DES-CBC",
            "DES-EDE-CBC",
            "DES-EDE3-CBC",
            "CAST5-CBC",
            "AES-128-CBC",
            "AES-192-CBC",
            "AES-256-CBC",
            "ARIA-128-CBC",
            "ARIA-192-CBC",
            "ARIA-256-CBC",
            "CAMELLIA-128-CBC",
            "CAMELLIA-192-CBC",
            "CAMELLIA-256-CBC",
            "SEED-CBC",
            "SM4-CBC",
            "NONE",
        ] {
            cipher_key_size(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        assert!(cipher_key_size("AES-512-CBC").is_err());
        assert_eq!(cipher_key_size("NONE").unwrap(), 0);
    }

    #[test]
    fn direction_slot_resolution() {
        assert_eq!(resolve_static_key_direction(-1), (0, 0, Some(1)));
        assert_eq!(resolve_static_key_direction(0), (0, 1, Some(0)));
        assert_eq!(resolve_static_key_direction(1), (1, 0, Some(1)));
        assert_eq!(resolve_static_key_direction(2), (1, 0, Some(1)));
    }

    #[test]
    fn key_material_raw_pem_hex() {
        // ASCII raw passthrough (256 bytes of a single byte value).
        let raw_ascii = "K".repeat(256);
        let raw_bytes: Vec<u8> = raw_ascii.as_bytes().to_vec();
        assert_eq!(
            load_static_key_material(Some(&raw_ascii), None).unwrap(),
            raw_bytes
        );

        // hex text (512 chars)
        let material: Vec<u8> = (0..256u16).map(|i| i as u8).collect();
        let hex: String = material.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            load_static_key_material(Some(&hex), None).unwrap(),
            material
        );

        // PEM wrapping
        let pem = format!(
            "comment\n{STATIC_KEY_MARKER_BEGIN}\n{}\n{STATIC_KEY_MARKER_END}\n",
            hex.as_bytes()
                .chunks(32)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(
            load_static_key_material(Some(&pem), None).unwrap(),
            material
        );

        // empty → missing
        assert_eq!(
            load_static_key_material(Some(""), None).unwrap_err(),
            "missing openvpn static key"
        );
        // bad hex length
        assert_eq!(
            load_static_key_material(Some(&hex[..510]), None).unwrap_err(),
            "static key must contain exactly 256 bytes"
        );
        // missing end marker
        assert_eq!(
            load_static_key_material(Some(&format!("{STATIC_KEY_MARKER_BEGIN}\n{hex}")), None)
                .unwrap_err(),
            "invalid static key end marker"
        );
        // no source at all
        assert_eq!(
            load_static_key_material(None, None).unwrap_err(),
            "missing openvpn static key"
        );
        // raw 256 bytes from a file path
        let temp = std::env::temp_dir().join(format!("tachyon-ovpn-key-{}", std::process::id()));
        std::fs::write(&temp, &material).unwrap();
        let from_path = load_static_key_material(None, Some(temp.to_str().unwrap())).unwrap();
        std::fs::remove_file(&temp).ok();
        assert_eq!(from_path, material);
    }

    #[test]
    fn pkcs7_roundtrip_and_errors() {
        let padded = pkcs7_pad(b"hello", 8).unwrap();
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[5..], &[3, 3, 3]);
        let padded = pkcs7_pad(&[0u8; 8], 8).unwrap();
        assert_eq!(padded.len(), 16);
        assert_eq!(pkcs7_unpad(&padded, 8).unwrap(), vec![0u8; 8]);
        assert!(pkcs7_unpad(&[0u8; 7], 8).is_err());
        assert!(pkcs7_unpad(&[0u8; 8], 8).is_err()); // zero padding byte
        assert!(pkcs7_unpad(&[1u8, 0, 0, 0, 0, 0, 0, 3], 8).is_err()); // mismatch
        assert!(pkcs7_pad(b"x", 0).is_err());
    }

    #[test]
    fn cross_direction_roundtrip() {
        let material = hex_key(0x5a);
        // A is configured "server"-like (direction 0): sends slot0, receives slot1.
        let mut a = StaticCodec::new(
            &material,
            0,
            "AES-256-CBC",
            "SHA1",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        // B direction 1: sends slot1, receives slot0 (+ fallback slot1).
        let mut b = StaticCodec::new(
            &material,
            1,
            "AES-256-CBC",
            "SHA1",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        let packet = a.encode(1, b"client to server").unwrap();
        let (id, payload) = b.decode(&packet).unwrap();
        assert_eq!(id, 1);
        assert_eq!(payload, b"client to server");

        let packet = b.encode(1, b"server to client").unwrap();
        let (id, payload) = a.decode(&packet).unwrap();
        assert_eq!(id, 1);
        assert_eq!(payload, b"server to client");

        // Replay: the same datagram again is rejected.
        let mut b2 = StaticCodec::new(
            &material,
            1,
            "AES-256-CBC",
            "SHA1",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        b2.decode(&packet).unwrap();
        assert_eq!(
            b2.decode(&packet).unwrap_err(),
            "replayed static key data packet"
        );
    }

    #[test]
    fn direction_both_decodes_both_slots() {
        let material = hex_key(0x33);
        let mut a = StaticCodec::new(
            &material,
            -1,
            "AES-128-CBC",
            "SHA256",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        // Self roundtrip: send slot0, receive candidates slot0 + slot1.
        let packet = a.encode(7, b"payload").unwrap();
        let mut a = StaticCodec::new(
            &material,
            -1,
            "AES-128-CBC",
            "SHA256",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        let (id, payload) = a.decode(&packet).unwrap();
        assert_eq!((id, payload.as_slice()), (7, &b"payload"[..]));

        // Peer sending from slot1 also decodes via the fallback candidate.
        let mut peer = StaticCodec::new(
            &material,
            1,
            "AES-128-CBC",
            "SHA256",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        let packet = peer.encode(1, b"from slot1").unwrap();
        let (id, payload) = a.decode(&packet).unwrap();
        assert_eq!((id, payload.as_slice()), (1, &b"from slot1"[..]));
    }

    #[test]
    fn none_cipher_roundtrip() {
        let material = hex_key(0x01);
        let mut a = StaticCodec::new(
            &material,
            -1,
            "NONE",
            "NONE",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        let packet = a.encode(1, b"plain").unwrap();
        // No hmac, no cipher: 8-byte header + payload.
        assert_eq!(packet.len(), 8 + 5);
        let mut b = StaticCodec::new(
            &material,
            -1,
            "NONE",
            "NONE",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        let (id, payload) = b.decode(&packet).unwrap();
        assert_eq!((id, payload.as_slice()), (1, &b"plain"[..]));
    }

    #[test]
    fn all_ciphers_roundtrip() {
        let material = hex_key(0x77);
        for name in [
            "BF-CBC",
            "DES-CBC",
            "DES-EDE-CBC",
            "DES-EDE3-CBC",
            "CAST5-CBC",
            "AES-128-CBC",
            "AES-192-CBC",
            "AES-256-CBC",
            "ARIA-128-CBC",
            "ARIA-192-CBC",
            "ARIA-256-CBC",
            "CAMELLIA-128-CBC",
            "CAMELLIA-192-CBC",
            "CAMELLIA-256-CBC",
            "SEED-CBC",
            "SM4-CBC",
            "NONE",
        ] {
            for auth in ["", "SHA224", "SHA384", "SHA512", "RIPEMD160", "MD5", "NONE"] {
                let mut a = StaticCodec::new(
                    &material,
                    -1,
                    name,
                    auth,
                    64,
                    std::time::Duration::from_secs(15),
                )
                .unwrap_or_else(|e| panic!("{name}/{auth}: {e}"));
                let packet = a
                    .encode(3, b"interop payload")
                    .unwrap_or_else(|e| panic!("{name}/{auth} encode: {e}"));
                let mut b = StaticCodec::new(
                    &material,
                    -1,
                    name,
                    auth,
                    64,
                    std::time::Duration::from_secs(15),
                )
                .unwrap();
                let (id, payload) = b
                    .decode(&packet)
                    .unwrap_or_else(|e| panic!("{name}/{auth} decode: {e}"));
                assert_eq!(id, 3, "{name}/{auth}");
                assert_eq!(payload, b"interop payload", "{name}/{auth}");
                // encoded length matches the wire size for the budget math
                let fresh = StaticCodec::new(
                    &material,
                    -1,
                    name,
                    auth,
                    64,
                    std::time::Duration::from_secs(15),
                )
                .unwrap();
                assert_eq!(
                    fresh.encoded_length(b"interop payload".len()),
                    packet.len(),
                    "{name}/{auth} encoded_length"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_truncated_and_garbage() {
        let material = hex_key(0x22);
        let mut codec = StaticCodec::new(
            &material,
            0,
            "AES-256-CBC",
            "SHA1",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        assert!(codec.decode(&[0u8; 4]).is_err());
        assert!(codec.decode(&[0xffu8; 40]).is_err());
        // valid packet with the hmac byte flipped
        let mut packet = codec.encode(1, b"x").unwrap();
        packet[0] ^= 0xff;
        assert_eq!(
            codec.decode(&packet).unwrap_err(),
            "invalid static key payload hmac"
        );
    }

    #[test]
    fn packet_id_zero_rejected() {
        let material = hex_key(0x11);
        let mut codec = StaticCodec::new(
            &material,
            -1,
            "AES-128-CBC",
            "SHA1",
            64,
            std::time::Duration::from_secs(15),
        )
        .unwrap();
        assert_eq!(
            codec.encode(0, b"x").unwrap_err(),
            "invalid static key packet id"
        );
    }

    #[test]
    fn bad_material_and_options_are_terminal() {
        assert!(
            StaticCodec::new(
                &[0u8; 100],
                -1,
                "AES-128-CBC",
                "SHA1",
                64,
                std::time::Duration::from_secs(15)
            )
            .is_err()
        );
        assert!(
            StaticCodec::new(
                &hex_key(1),
                -1,
                "AES-128-CBC",
                "SHA3",
                64,
                std::time::Duration::from_secs(15)
            )
            .is_err()
        );
        assert!(
            StaticCodec::new(
                &hex_key(1),
                -1,
                "ROT13",
                "SHA1",
                64,
                std::time::Duration::from_secs(15)
            )
            .is_err()
        );
    }
}
