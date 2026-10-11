//! WireGuard initiator handshake (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`)
//! and transport packets, verbatim from <https://www.wireguard.com/protocol/>.
//!
//! Pure crypto/state machine: no sockets, no timers — the driver lives in
//! `mod.rs`. Initiator only; we never answer handshakes.

use blake2::digest::typenum::U16;
use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, AeadInPlace, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag, XChaCha20Poly1305, XNonce};
use x25519_dalek::{PublicKey, StaticSecret};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
pub const TRANSPORT_HEADER_LEN: usize = 16;
/// `offsetof(handshake_initiation, mac1)`.
const MAC1_OFFSET_INIT: usize = 116;
/// `offsetof(handshake_initiation, mac2)`.
const MAC2_OFFSET_INIT: usize = 132;
/// `offsetof(handshake_response, mac1)`.
const MAC1_OFFSET_RESP: usize = 60;

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

/// Inclusive `lo..=hi` range for an AWG magic-header type word. Plain
/// WireGuard is the single-value range `N..=N` (types 1–4).
pub type HeaderRange = (u32, u32);

pub const HDR_INIT: HeaderRange = (MSG_INITIATION as u32, MSG_INITIATION as u32);
pub const HDR_RESPONSE: HeaderRange = (MSG_RESPONSE as u32, MSG_RESPONSE as u32);
pub const HDR_COOKIE: HeaderRange = (MSG_COOKIE_REPLY as u32, MSG_COOKIE_REPLY as u32);
pub const HDR_TRANSPORT: HeaderRange = (MSG_TRANSPORT as u32, MSG_TRANSPORT as u32);

/// `magicHeader.Generate()` (Leadaxe/wireguard-go device/magic-header.go):
/// uniform pick inside the inclusive range.
pub fn gen_type(range: HeaderRange) -> u32 {
    let (lo, hi) = range;
    debug_assert!(lo <= hi);
    if lo == hi {
        return lo;
    }
    let span = (hi - lo + 1) as u64;
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("getrandom");
    lo + (u64::from_le_bytes(buf) % span) as u32
}

/// First 4 bytes of a datagram as the LE type word the device layer checks.
pub fn type_word(msg: &[u8]) -> Option<u32> {
    if msg.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes(msg[..4].try_into().expect("4 bytes")))
}

fn hash(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data).into()
}

/// `HASH(a || b)` — incremental, no intermediate buffer.
fn hash_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// RFC 2104 HMAC over BLAKE2s-256 (block size 64); `hmac`-crate types built
/// on blake2's variable-core wrappers do not satisfy its `KeyInit` bounds.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&hash(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner_h = Blake2s256::new();
    inner_h.update(ipad);
    inner_h.update(data);
    let inner: [u8; 32] = inner_h.finalize().into();
    let mut outer_h = Blake2s256::new();
    outer_h.update(opad);
    outer_h.update(inner);
    outer_h.finalize().into()
}

/// `MAC(key, input)`: keyed BLAKE2s truncated to 16 bytes.
fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("mac key");
    Mac::update(&mut m, data);
    Mac::finalize(m).into_bytes().into()
}

/// One KDF step: `temp = HMAC(ck, data); ck' = HMAC(temp, 0x1)`.
fn mix_key(ck: &[u8; 32], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(ck, data);
    let ck2 = hmac(&temp, &[0x01]);
    (temp, ck2)
}

/// `key = HMAC(temp, ck || 0x2)`.
fn key2(temp: &[u8; 32], ck: &[u8; 32]) -> [u8; 32] {
    let mut msg = [0u8; 33];
    msg[..32].copy_from_slice(ck);
    msg[32] = 0x02;
    hmac(temp, &msg)
}

fn aead_seal(key: &[u8; 32], counter: u64, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("aead seal")
}

fn aead_open(key: &[u8; 32], counter: u64, ciphertext: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .ok()
}

/// `TAI64N()` — 12-byte timestamp; the +10 constant matches wireguard-go.
pub fn tai64n_now() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    let secs = 0x4000_0000_0000_0000u64 + now.as_secs() + 10;
    out[..8].copy_from_slice(&secs.to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

/// `HASH(LABEL_MAC1 || peer.static_public)` — the mac1 MAC key.
pub fn mac1_key(peer_static_public: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(LABEL_MAC1.len() + 32);
    buf.extend_from_slice(LABEL_MAC1);
    buf.extend_from_slice(peer_static_public);
    hash(&buf)
}

fn dh(sk_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*sk_bytes);
    let pk = PublicKey::from(*pub_bytes);
    sk.diffie_hellman(&pk).to_bytes()
}

fn random_u32_nonzero() -> u32 {
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("getrandom");
        let v = u32::from_le_bytes(b);
        if v != 0 {
            return v;
        }
    }
}

fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

/// In-progress initiator handshake. One per attempt; retransmissions reuse it.
pub struct Handshake {
    ck: [u8; 32],
    h: [u8; 32],
    e_priv: [u8; 32],
    our_static_priv: [u8; 32],
    pub sender_index: u32,
    /// Built initiation message (mac1 present; mac2 filled after a cookie).
    initiation: Vec<u8>,
}

impl Handshake {
    pub fn initiation(&self) -> &[u8] {
        &self.initiation
    }

    /// The mac1 we sent — the AAD for a cookie reply addressed to us.
    pub fn mac1(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.initiation[MAC1_OFFSET_INIT..MAC2_OFFSET_INIT]);
        out
    }

    /// Fill mac2 into the initiation after a cookie reply arrives.
    pub fn set_cookie(&mut self, cookie: &[u8; 16]) {
        let m2 = mac(cookie, &self.initiation[..MAC2_OFFSET_INIT]);
        self.initiation[MAC2_OFFSET_INIT..].copy_from_slice(&m2);
    }
}

/// Build a handshake initiation. `tai64n` is fixed by the caller so
/// retransmissions carry an identical timestamp. `type_word` is the AWG
/// magic header for the initiation (pass 1 / `gen_type(HDR_INIT)` range
/// value for plain WireGuard).
pub fn build_initiation(
    our_static_priv: &[u8; 32],
    our_static_pub: &[u8; 32],
    peer_static_pub: &[u8; 32],
    cookie: Option<&[u8; 16]>,
    tai64n: &[u8; 12],
    type_word: u32,
) -> Handshake {
    let sender_index = random_u32_nonzero();
    let e_priv = random_32();
    let e_pub = PublicKey::from(&StaticSecret::from(e_priv));

    let ck0 = hash(CONSTRUCTION);
    let mut h = {
        let inner = {
            let mut v = Vec::with_capacity(32 + IDENTIFIER.len());
            v.extend_from_slice(&ck0);
            v.extend_from_slice(IDENTIFIER);
            hash(&v)
        };
        let mut v = Vec::with_capacity(32 + 32);
        v.extend_from_slice(&inner);
        v.extend_from_slice(peer_static_pub);
        hash(&v)
    };

    let mut msg = Vec::with_capacity(INITIATION_LEN);
    msg.extend_from_slice(&type_word.to_le_bytes());
    msg.extend_from_slice(&sender_index.to_le_bytes());
    msg.extend_from_slice(e_pub.as_bytes());
    h = hash_concat(&h, e_pub.as_bytes());

    // es
    let (_, ck1) = mix_key(&ck0, e_pub.as_bytes());
    let (temp, ck2) = mix_key(&ck1, &dh(&e_priv, peer_static_pub));
    let key = key2(&temp, &ck2);
    let enc_static = aead_seal(&key, 0, our_static_pub, &h);
    debug_assert_eq!(enc_static.len(), 48);
    msg.extend_from_slice(&enc_static);
    h = hash_concat(&h, &enc_static);

    // ss
    let (temp, ck3) = mix_key(&ck2, &dh(our_static_priv, peer_static_pub));
    let key = key2(&temp, &ck3);
    let enc_ts = aead_seal(&key, 0, tai64n, &h);
    debug_assert_eq!(enc_ts.len(), 28);
    msg.extend_from_slice(&enc_ts);
    h = hash_concat(&h, &enc_ts);
    debug_assert_eq!(h.len(), 32);

    // mac1 / mac2
    let m1 = mac(&mac1_key(peer_static_pub), &msg[..MAC1_OFFSET_INIT]);
    let m2 = match cookie {
        Some(c) => mac(c, &msg[..MAC2_OFFSET_INIT]),
        None => [0u8; 16],
    };
    msg.extend_from_slice(&m1);
    msg.extend_from_slice(&m2);
    debug_assert_eq!(msg.len(), INITIATION_LEN);

    Handshake {
        ck: ck3,
        h,
        e_priv,
        our_static_priv: *our_static_priv,
        sender_index,
        initiation: msg,
    }
}

/// Process a handshake response; returns the transport session.
pub fn process_response(
    hs: &Handshake,
    msg: &[u8],
    our_static_pub: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<Session, &'static str> {
    if msg.len() != RESPONSE_LEN {
        return Err("short handshake response");
    }
    // The magic-header word was range-validated by the caller's demux.
    // Handshake response layout: [4..8] = responder's sender index,
    // [8..12] = receiver (our initiation sender index).
    let receiver_index = u32::from_le_bytes(msg[8..12].try_into().unwrap());
    if receiver_index != hs.sender_index {
        return Err("handshake response receiver index mismatch");
    }
    // mac1 is keyed by the *receiver's* static public — that is ours here.
    let expect = mac(&mac1_key(our_static_pub), &msg[..MAC1_OFFSET_RESP]);
    if msg[60..76] != expect {
        return Err("handshake response mac1 mismatch");
    }

    let mut e_r = [0u8; 32];
    e_r.copy_from_slice(&msg[12..44]);
    let enc_nothing = &msg[44..60];

    let mut h = hash_concat(&hs.h, &e_r);
    let (_, ck1) = mix_key(&hs.ck, &e_r);
    // ee
    let (_, ck2) = mix_key(&ck1, &dh(&hs.e_priv, &e_r));
    // se
    let (_, ck3) = mix_key(&ck2, &dh(&hs.our_static_priv, &e_r));
    // psk (all-zero when absent)
    let zero_psk = [0u8; 32];
    let psk = psk.unwrap_or(&zero_psk);
    let (temp, ck4) = mix_key(&ck3, psk);

    let temp2 = key2(&temp, &ck4);
    let mut m3 = [0u8; 33];
    m3[..32].copy_from_slice(&temp2);
    m3[32] = 0x03;
    let key = hmac(&temp, &m3);
    h = hash_concat(&h, &temp2);

    let plain = aead_open(&key, 0, enc_nothing, &h).ok_or("response decrypt failed")?;
    if !plain.is_empty() {
        return Err("unexpected response payload");
    }
    h = hash_concat(&h, enc_nothing);
    let _ = h;

    // Data keys (initiator): sending = temp2', receiving = temp3'.
    let temp1 = hmac(&ck4, &[]);
    let send_key = hmac(&temp1, &[0x01]);
    let mut tail = [0u8; 33];
    tail[..32].copy_from_slice(&send_key);
    tail[32] = 0x02;
    let recv_key = hmac(&temp1, &tail);

    let remote_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    Ok(Session {
        local_index: hs.sender_index,
        remote_index,
        send_cipher: ChaCha20Poly1305::new(Key::from_slice(&send_key)),
        recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&recv_key)),
        send_counter: 0,
        recv_max: 0,
        recv_any: false,
        recv_bitmap: [0u64; 32],
        awg_transport: HDR_TRANSPORT,
    })
}

/// Result of successfully consuming a handshake initiation as responder.
pub struct InitiationResult {
    pub sender_index: u32,
    pub sender_static_pub: [u8; 32],
    pub e_pub: [u8; 32],
    pub ck: [u8; 32],
    pub h: [u8; 32],
    /// Authenticated TAI64N timestamp for the responder's replay check.
    pub timestamp: [u8; 12],
}

/// Process an incoming handshake initiation as a responder.
pub fn process_initiation(
    our_static_priv: &[u8; 32],
    our_static_pub: &[u8; 32],
    msg: &[u8],
) -> Result<InitiationResult, &'static str> {
    if msg.len() < INITIATION_LEN {
        return Err("short handshake initiation");
    }
    // Verify mac1: keyed by our static public key
    let m1 = mac(&mac1_key(our_static_pub), &msg[..MAC1_OFFSET_INIT]);
    if msg[MAC1_OFFSET_INIT..MAC2_OFFSET_INIT] != m1 {
        return Err("handshake initiation mac1 mismatch");
    }

    let sender_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    let mut e_pub = [0u8; 32];
    e_pub.copy_from_slice(&msg[8..40]);

    let ck0 = hash(CONSTRUCTION);
    let mut h = {
        let inner = {
            let mut v = Vec::with_capacity(32 + IDENTIFIER.len());
            v.extend_from_slice(&ck0);
            v.extend_from_slice(IDENTIFIER);
            hash(&v)
        };
        let mut v = Vec::with_capacity(32 + 32);
        v.extend_from_slice(&inner);
        v.extend_from_slice(our_static_pub);
        hash(&v)
    };

    h = hash_concat(&h, &e_pub);
    let (_, ck1) = mix_key(&ck0, &e_pub);

    // es: DH(our_static_priv, e_pub)
    let (temp, ck2) = mix_key(&ck1, &dh(our_static_priv, &e_pub));
    let key = key2(&temp, &ck2);
    let enc_static = &msg[40..88];
    let plain_static =
        aead_open(&key, 0, enc_static, &h).ok_or("initiation static decrypt failed")?;
    if plain_static.len() != 32 {
        return Err("invalid decrypted static key length");
    }
    let mut sender_static_pub = [0u8; 32];
    sender_static_pub.copy_from_slice(&plain_static);
    h = hash_concat(&h, enc_static);

    // ss: DH(our_static_priv, sender_static_pub)
    let (temp, ck3) = mix_key(&ck2, &dh(our_static_priv, &sender_static_pub));
    let key_ts = key2(&temp, &ck3);
    let enc_ts = &msg[88..116];
    let ts = aead_open(&key_ts, 0, enc_ts, &h).ok_or("initiation timestamp decrypt failed")?;
    let timestamp = ts
        .try_into()
        .map_err(|_| "invalid initiation timestamp length")?;
    h = hash_concat(&h, enc_ts);

    Ok(InitiationResult {
        sender_index,
        sender_static_pub,
        e_pub,
        ck: ck3,
        h,
        timestamp,
    })
}

/// Build a handshake response as responder and return the response message
/// along with the derived transport session.
pub fn build_response(
    init_res: &InitiationResult,
    _our_static_priv: &[u8; 32],
    psk: Option<&[u8; 32]>,
    type_word: u32,
) -> (Vec<u8>, Session) {
    let r_sender_index = random_u32_nonzero();
    let e_priv = random_32();
    let e_pub = PublicKey::from(&StaticSecret::from(e_priv));

    let mut h = hash_concat(&init_res.h, e_pub.as_bytes());
    let (_, ck1) = mix_key(&init_res.ck, e_pub.as_bytes());

    // ee: DH(e_priv, init_res.e_pub)
    let (_, ck2) = mix_key(&ck1, &dh(&e_priv, &init_res.e_pub));

    // se: DH(e_priv, init_res.sender_static_pub)
    let (_, ck3) = mix_key(&ck2, &dh(&e_priv, &init_res.sender_static_pub));

    // psk
    let zero_psk = [0u8; 32];
    let psk = psk.unwrap_or(&zero_psk);
    let (temp, ck4) = mix_key(&ck3, psk);

    let temp2 = key2(&temp, &ck4);
    let mut m3 = [0u8; 33];
    m3[..32].copy_from_slice(&temp2);
    m3[32] = 0x03;
    let key = hmac(&temp, &m3);
    h = hash_concat(&h, &temp2);

    let enc_nothing = aead_seal(&key, 0, &[], &h);
    debug_assert_eq!(enc_nothing.len(), 16);
    h = hash_concat(&h, &enc_nothing);
    let _ = h;

    let mut msg = Vec::with_capacity(RESPONSE_LEN);
    msg.extend_from_slice(&type_word.to_le_bytes());
    msg.extend_from_slice(&r_sender_index.to_le_bytes());
    msg.extend_from_slice(&init_res.sender_index.to_le_bytes());
    msg.extend_from_slice(e_pub.as_bytes());
    msg.extend_from_slice(&enc_nothing);

    // mac1: keyed by initiator's static public key
    let m1 = mac(
        &mac1_key(&init_res.sender_static_pub),
        &msg[..MAC1_OFFSET_RESP],
    );
    msg.extend_from_slice(&m1);
    // mac2: 16 bytes of zero
    msg.extend_from_slice(&[0u8; 16]);
    debug_assert_eq!(msg.len(), RESPONSE_LEN);

    // Data keys (responder): sending = temp3', receiving = temp2'.
    let temp1 = hmac(&ck4, &[]);
    let send_key_initiator = hmac(&temp1, &[0x01]);
    let mut tail = [0u8; 33];
    tail[..32].copy_from_slice(&send_key_initiator);
    tail[32] = 0x02;
    let recv_key_initiator = hmac(&temp1, &tail);

    let session = Session {
        local_index: r_sender_index,
        remote_index: init_res.sender_index,
        send_cipher: ChaCha20Poly1305::new(Key::from_slice(&recv_key_initiator)),
        recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&send_key_initiator)),
        send_counter: 0,
        recv_max: 0,
        recv_any: false,
        recv_bitmap: [0u64; 32],
        awg_transport: HDR_TRANSPORT,
    };

    (msg, session)
}

/// Valid transport counters stop below this (spec `REJECT_AFTER_MESSAGES`).
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
const RECV_WINDOW: u64 = 2048;

pub struct Session {
    pub local_index: u32,
    pub remote_index: u32,
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_counter: u64,
    /// Highest accepted receive counter; bit `i` = counter `recv_max - i`.
    recv_max: u64,
    recv_any: bool,
    recv_bitmap: [u64; 32],
    /// AWG magic-header range for transport type words (plain WG: `4..=4`).
    awg_transport: HeaderRange,
}

impl Session {
    /// Switch the transport header to an AWG magic-header range.
    pub fn set_awg_transport(&mut self, range: HeaderRange) {
        self.awg_transport = range;
    }

    /// Seal one inner packet into a transport message (pads to 16 bytes).
    pub fn seal(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let pad = (16 - (packet.len() % 16)) % 16;
        self.seal_raw(packet, packet.len() + pad)
    }

    /// Seal with an explicit final plaintext length (AWG 3.x content
    /// padding / trailers replace the multiple-of-16 alignment).
    pub fn seal_raw(&mut self, packet: &[u8], padded_len: usize) -> Option<Vec<u8>> {
        if self.send_counter > REJECT_AFTER_MESSAGES {
            return None;
        }
        debug_assert!(padded_len >= packet.len());
        let counter = self.send_counter;
        self.send_counter += 1;
        let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + padded_len + 16);
        msg.extend_from_slice(&gen_type(self.awg_transport).to_le_bytes());
        msg.extend_from_slice(&self.remote_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(packet);
        msg.resize(TRANSPORT_HEADER_LEN + padded_len, 0);
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let tag = self
            .send_cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &[],
                &mut msg[TRANSPORT_HEADER_LEN..],
            )
            .ok()?;
        msg.extend_from_slice(&tag);
        Some(msg)
    }

    /// Open a transport message addressed to us; enforces the replay window.
    /// Returns the padded plaintext — trim via the inner IP header.
    pub fn open(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        let mut plain = Vec::new();
        self.open_into(msg, &mut plain).then_some(plain)
    }

    /// Same as [`Self::open`], but decrypts into a caller-provided scratch
    /// buffer so a hot path can recycle instead of allocating per packet.
    /// On success `out` holds the plaintext; on failure it is untouched.
    pub fn open_into(&mut self, msg: &[u8], out: &mut Vec<u8>) -> bool {
        if msg.len() < TRANSPORT_HEADER_LEN + 16 {
            return false;
        }
        let word = match type_word(msg) {
            Some(word) => word,
            None => return false,
        };
        let (lo, hi) = self.awg_transport;
        if word < lo || word > hi {
            return false;
        }
        let receiver = u32::from_le_bytes(msg[4..8].try_into().unwrap());
        if receiver != self.local_index {
            return false;
        }
        let counter = u64::from_le_bytes(msg[8..16].try_into().unwrap());
        if counter > REJECT_AFTER_MESSAGES || !self.accept_counter(counter) {
            return false;
        }
        let body = &msg[TRANSPORT_HEADER_LEN..];
        let (ciphertext, tag) = body.split_at(body.len() - 16);
        // The one copy that is not going away: the plaintext must outlive
        // the recv buffer, and the AEAD opens in place.
        out.clear();
        out.extend_from_slice(ciphertext);
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        self.recv_cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], out, Tag::from_slice(tag))
            .is_ok()
    }

    fn accept_counter(&mut self, counter: u64) -> bool {
        if !self.recv_any {
            self.recv_any = true;
            self.recv_max = counter;
            self.recv_bitmap[0] |= 1;
            return true;
        }
        if counter > self.recv_max {
            let diff = counter - self.recv_max;
            if diff >= RECV_WINDOW {
                self.recv_bitmap = [0; 32];
            } else {
                self.shift_older(diff as u32);
            }
            self.recv_max = counter;
            self.recv_bitmap[0] |= 1;
            return true;
        }
        let i = self.recv_max - counter;
        if i >= RECV_WINDOW {
            return false;
        }
        let bit = i as usize;
        let word = self.recv_bitmap[bit / 64];
        if word & (1u64 << (bit % 64)) != 0 {
            return false;
        }
        self.recv_bitmap[bit / 64] |= 1u64 << (bit % 64);
        true
    }

    /// Move existing bits to higher positions (they become "older").
    /// `new[i] = old[i - diff]` over the 2048-bit window.
    fn shift_older(&mut self, diff: u32) {
        let words = (diff / 64) as usize;
        let bits = diff % 64;
        let mut new = [0u64; 32];
        for (w, out) in new.iter_mut().enumerate() {
            let src = w as isize - words as isize;
            if src < 0 {
                continue;
            }
            let src = src as usize;
            let mut v = self.recv_bitmap[src] << bits;
            if bits > 0 && src > 0 {
                v |= self.recv_bitmap[src - 1] >> (64 - bits);
            }
            *out = v;
        }
        self.recv_bitmap = new;
    }
}

/// Decrypt a cookie reply; returns the mac2 key cookie.
pub fn decrypt_cookie(
    msg: &[u8],
    peer_static_pub: &[u8; 32],
    last_mac1: &[u8; 16],
    expect_receiver: u32,
) -> Result<[u8; 16], &'static str> {
    if msg.len() != COOKIE_REPLY_LEN {
        return Err("short cookie reply");
    }
    // The magic-header word was range-validated by the caller's demux.
    let receiver = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    if receiver != expect_receiver {
        return Err("cookie reply receiver index mismatch");
    }
    let mut key_in = Vec::with_capacity(LABEL_COOKIE.len() + 32);
    key_in.extend_from_slice(LABEL_COOKIE);
    key_in.extend_from_slice(peer_static_pub);
    let key = hash(&key_in);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&msg[8..32]),
            Payload {
                msg: &msg[32..64],
                aad: last_mac1,
            },
        )
        .map_err(|_| "cookie decrypt failed")?;
    if plain.len() != 16 {
        return Err("bad cookie length");
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&plain);
    Ok(out)
}

/// Trim transport padding using the inner IPv4/IPv6 total length.
pub fn trim_ip_padding(padded: &[u8]) -> &[u8] {
    if padded.len() < 20 {
        return padded;
    }
    match padded[0] >> 4 {
        4 => {
            let total = u16::from_be_bytes([padded[2], padded[3]]) as usize;
            if total >= 20 && total <= padded.len() {
                &padded[..total]
            } else {
                padded
            }
        }
        6 => {
            if padded.len() < 40 {
                return padded;
            }
            let payload = u16::from_be_bytes([padded[4], padded[5]]) as usize;
            let total = 40 + payload;
            if total <= padded.len() {
                &padded[..total]
            } else {
                padded
            }
        }
        _ => padded,
    }
}

/// Classify a received WireGuard message; `None` for unknown types.
/// The classification is by the leading magic-header word; plain WireGuard
/// keeps types 1–4.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiation_layout() {
        let priv_a = [7u8; 32];
        let pub_a = PublicKey::from(&StaticSecret::from(priv_a));
        let priv_b = [9u8; 32];
        let pub_b = PublicKey::from(&StaticSecret::from(priv_b));
        let hs = build_initiation(
            &priv_a,
            pub_a.as_bytes(),
            pub_b.as_bytes(),
            None,
            &tai64n_now(),
            MSG_INITIATION as u32,
        );
        let msg = hs.initiation().to_vec();
        assert_eq!(msg.len(), INITIATION_LEN);
        assert_eq!(msg[0], MSG_INITIATION);
        assert_eq!(&msg[1..4], &[0, 0, 0]);
        assert_ne!(&msg[4..8], &[0, 0, 0, 0]);
        // mac1 present (non-zero), mac2 zeros without a cookie.
        assert_ne!(&msg[116..132], &[0u8; 16][..]);
        assert_eq!(&msg[132..148], &[0u8; 16][..]);

        // With a cookie the mac2 field changes; mac1 stays stable.
        let mut with_cookie = build_initiation(
            &priv_a,
            pub_a.as_bytes(),
            pub_b.as_bytes(),
            None,
            &tai64n_now(),
            1,
        );
        // Same inputs → rebuild produces different ephemeral; instead patch.
        let cookie = [3u8; 16];
        with_cookie.set_cookie(&cookie);
        assert_ne!(&with_cookie.initiation()[132..148], &[0u8; 16][..]);
    }

    #[test]
    fn transport_roundtrip() {
        let mut a = Session {
            local_index: 1,
            remote_index: 2,
            send_cipher: ChaCha20Poly1305::new(Key::from_slice(&[1u8; 32])),
            recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&[2u8; 32])),
            send_counter: 0,
            recv_max: 0,
            recv_any: false,
            recv_bitmap: [0; 32],
            awg_transport: HDR_TRANSPORT,
        };
        let mut b = Session {
            local_index: 2,
            remote_index: 1,
            send_cipher: ChaCha20Poly1305::new(Key::from_slice(&[2u8; 32])),
            recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&[1u8; 32])),
            send_counter: 0,
            recv_max: 0,
            recv_any: false,
            recv_bitmap: [0; 32],
            awg_transport: HDR_TRANSPORT,
        };
        let pkt = b"hello wireguard tunnel packet";
        let msg = a.seal(pkt).expect("seal");
        assert_eq!(msg[0], MSG_TRANSPORT);
        assert_eq!(&msg[4..8], &2u32.to_le_bytes());
        let out = b.open(&msg).expect("open");
        assert_eq!(&out[..pkt.len()], pkt);
        assert!(out[pkt.len()..].iter().all(|b| *b == 0));
        assert_eq!(out.len() % 16, 0);
        // replay rejected
        assert!(b.open(&msg).is_none());
        // wrong receiver index rejected
        let mut other = msg.clone();
        other[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(b.open(&other).is_none());
    }

    #[test]
    fn recv_window_out_of_order() {
        let mut s = Session {
            local_index: 1,
            remote_index: 2,
            send_cipher: ChaCha20Poly1305::new(Key::from_slice(&[0u8; 32])),
            recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&[0u8; 32])),
            send_counter: 0,
            recv_max: 0,
            recv_any: false,
            recv_bitmap: [0; 32],
            awg_transport: HDR_TRANSPORT,
        };
        assert!(s.accept_counter(5));
        assert!(s.accept_counter(3));
        assert!(s.accept_counter(9));
        assert!(!s.accept_counter(5));
        assert!(!s.accept_counter(3));
        assert!(s.accept_counter(4));
        assert!(s.accept_counter(100));
        assert!(s.accept_counter(6));
        assert!(!s.accept_counter(6));
        // far jump clears the window
        assert!(s.accept_counter(5000));
        assert!(!s.accept_counter(5000));
        // edge of the 2048-counter window: i < 2048 accepted, i >= 2048 not
        assert!(s.accept_counter(5000 - 2047));
        assert!(!s.accept_counter(5000 - 2048));
    }

    #[test]
    fn trim_padding_ip4() {
        let mut pkt = vec![0x45u8, 0];
        pkt.extend_from_slice(&24u16.to_be_bytes()); // total length 24
        pkt.resize(32, 0); // padded to 32
        assert_eq!(trim_ip_padding(&pkt).len(), 24);
    }

    /// Mirror of wireguard-go's ConsumeMessageInitiation + CreateMessageResponse,
    /// used to check `process_response` against the reference construction.
    #[test]
    fn response_from_wireguard_go_mirror() {
        let priv_a = [0x11u8; 32]; // initiator (us)
        let priv_b = [0x22u8; 32]; // responder (reference)
        let pub_a = PublicKey::from(&StaticSecret::from(priv_a));
        let pub_b = PublicKey::from(&StaticSecret::from(priv_b));
        let hs = build_initiation(
            &priv_a,
            pub_a.as_bytes(),
            pub_b.as_bytes(),
            None,
            &tai64n_now(),
            1,
        );
        let msg = hs.initiation().to_vec();

        // --- ConsumeMessageInitiation (responder side, from wireguard-go) ---
        let ck0 = hash(CONSTRUCTION);
        let mut h = hash_concat(&hash_concat(&ck0, IDENTIFIER), pub_b.as_bytes());
        h = hash_concat(&h, &msg[8..40]); // mixHash(initiator ephemeral)
        let mut ck = mix_key(&ck0, &msg[8..40]).1;

        // decrypt static: KDF2(ck, ss = DH(priv_b, e_i))
        let (prk, ck1) = mix_key(
            &ck,
            &dh(&priv_b, &<[u8; 32]>::try_from(&msg[8..40]).unwrap()),
        );
        let key = key2(&prk, &ck1);
        ck = ck1;
        let enc_static = &msg[40..88];
        let plain_static = aead_open(&key, 0, enc_static, &h).expect("consume: static decrypt");
        assert_eq!(plain_static, pub_a.as_bytes());
        h = hash_concat(&h, enc_static);

        // decrypt timestamp: KDF2(ck, precomputedStaticStatic = DH(priv_b, pub_a))
        let (prk, ck2) = mix_key(&ck, &dh(&priv_b, pub_a.as_bytes()));
        let key = key2(&prk, &ck2);
        ck = ck2;
        let enc_ts = &msg[88..116];
        let plain_ts = aead_open(&key, 0, enc_ts, &h).expect("consume: timestamp decrypt");
        assert_eq!(plain_ts.len(), 12);
        h = hash_concat(&h, enc_ts);

        // mac1 check: keyed by the responder's own static public.
        let m1 = mac(&mac1_key(pub_b.as_bytes()), &msg[..MAC1_OFFSET_INIT]);
        assert_eq!(msg[MAC1_OFFSET_INIT..MAC2_OFFSET_INIT], m1);

        // --- CreateMessageResponse (responder side) with a forced ephemeral ---
        let sender_index = 0xDEAD_BEEFu32;
        let e_r_priv = [0x33u8; 32];
        let e_r_pub = PublicKey::from(&StaticSecret::from(e_r_priv));
        h = hash_concat(&h, e_r_pub.as_bytes());
        ck = mix_key(&ck, e_r_pub.as_bytes()).1;
        // ee = DH(e_r, e_i)
        ck = mix_key(
            &ck,
            &dh(&e_r_priv, &<[u8; 32]>::try_from(&msg[8..40]).unwrap()),
        )
        .1;
        // se = DH(e_r, static_a)
        ck = mix_key(&ck, &dh(&e_r_priv, pub_a.as_bytes())).1;
        // KDF3 psk step
        let zero_psk = [0u8; 32];
        let (prk, ck4) = mix_key(&ck, &zero_psk);
        let tau = key2(&prk, &ck4);
        let mut m3 = [0u8; 33];
        m3[..32].copy_from_slice(&tau);
        m3[32] = 0x03;
        let key = hmac(&prk, &m3);
        h = hash_concat(&h, &tau);
        let empty_ct = aead_seal(&key, 0, &[], &h);
        assert_eq!(empty_ct.len(), 16);

        let mut resp = Vec::with_capacity(RESPONSE_LEN);
        resp.push(MSG_RESPONSE);
        resp.extend_from_slice(&[0, 0, 0]);
        resp.extend_from_slice(&sender_index.to_le_bytes());
        resp.extend_from_slice(&hs.sender_index.to_le_bytes());
        resp.extend_from_slice(e_r_pub.as_bytes());
        resp.extend_from_slice(&empty_ct);
        let m1 = mac(&mac1_key(pub_a.as_bytes()), &resp[..60]);
        resp.extend_from_slice(&m1);
        resp.extend_from_slice(&[0u8; 16]);
        assert_eq!(resp.len(), RESPONSE_LEN);

        let session = process_response(&hs, &resp, pub_a.as_bytes(), None)
            .expect("process_response against wireguard-go mirror");
        assert_eq!(session.remote_index, sender_index);

        // With a psk: consume state is unaffected (psk enters only the
        // response KDF3 step), so rebuild the response from the same h/ck.
        let hs2 = build_initiation(
            &priv_a,
            pub_a.as_bytes(),
            pub_b.as_bytes(),
            None,
            &tai64n_now(),
            1,
        );
        let msg2 = hs2.initiation().to_vec();
        let mut h = hash_concat(&hash_concat(&ck0, IDENTIFIER), pub_b.as_bytes());
        h = hash_concat(&h, &msg2[8..40]);
        let mut ck = mix_key(&ck0, &msg2[8..40]).1;
        let (prk, ck1) = mix_key(
            &ck,
            &dh(&priv_b, &<[u8; 32]>::try_from(&msg2[8..40]).unwrap()),
        );
        let key = key2(&prk, &ck1);
        ck = ck1;
        let enc_static = &msg2[40..88];
        assert!(aead_open(&key, 0, enc_static, &h).is_some());
        h = hash_concat(&h, enc_static);
        let (prk, ck2) = mix_key(&ck, &dh(&priv_b, pub_a.as_bytes()));
        let key = key2(&prk, &ck2);
        ck = ck2;
        let enc_ts = &msg2[88..116];
        let plain_ts = aead_open(&key, 0, enc_ts, &h).expect("psk path: timestamp decrypt");
        assert_eq!(plain_ts.len(), 12);
        h = hash_concat(&h, enc_ts);

        let sender_index = 0xBEEF_0001u32;
        let psk = [7u8; 32];
        let e_r_priv = [0x44u8; 32];
        let e_r_pub = PublicKey::from(&StaticSecret::from(e_r_priv));
        h = hash_concat(&h, e_r_pub.as_bytes());
        ck = mix_key(&ck, e_r_pub.as_bytes()).1;
        ck = mix_key(
            &ck,
            &dh(&e_r_priv, &<[u8; 32]>::try_from(&msg2[8..40]).unwrap()),
        )
        .1;
        ck = mix_key(&ck, &dh(&e_r_priv, pub_a.as_bytes())).1;
        let (prk, ck4) = mix_key(&ck, &psk);
        let tau = key2(&prk, &ck4);
        let mut m3 = [0u8; 33];
        m3[..32].copy_from_slice(&tau);
        m3[32] = 0x03;
        let key = hmac(&prk, &m3);
        h = hash_concat(&h, &tau);
        let empty_ct = aead_seal(&key, 0, &[], &h);

        let mut resp = Vec::with_capacity(RESPONSE_LEN);
        resp.push(MSG_RESPONSE);
        resp.extend_from_slice(&[0, 0, 0]);
        resp.extend_from_slice(&sender_index.to_le_bytes());
        resp.extend_from_slice(&hs2.sender_index.to_le_bytes());
        resp.extend_from_slice(e_r_pub.as_bytes());
        resp.extend_from_slice(&empty_ct);
        let m1 = mac(&mac1_key(pub_a.as_bytes()), &resp[..60]);
        resp.extend_from_slice(&m1);
        resp.extend_from_slice(&[0u8; 16]);

        let session = process_response(&hs2, &resp, pub_a.as_bytes(), Some(&psk))
            .expect("process_response with psk");
        assert_eq!(session.remote_index, sender_index);
    }

    /// Response captured from the reference binary: state, mac1, mirror
    /// derivation and `process_response` must all agree with wireguard-go.
    #[test]
    fn reference_response_vector() {
        fn dec(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let init = dec(
            "01000000166a1eda0be52a1eb11f52cf8ba370b7a8b0cbe5207841b98d7b06d484a3944b91883b6d03ead7aad26305af2ac564c19cb75d75cb95ecf1ef5bc4e5b4fd9c1eb79789238b015eb4be2f8927917755537291e39471d4b094aaaa876bc8b40f7372205e0411573445f19e769e343568c7840957e02b641b028a9bcf7e8e9884fb00000000000000000000000000000000",
        );
        let msg = dec(
            "02000000fae8310a166a1edac4413ee0d4c755c340025ad2bcdf21bb63b22989c5c87535bb48e45f64d58a16f15b50603cc874edbbfbfab3833ec65e9730c5777ed056cab8520d9d0c6f9a5700000000000000000000000000000000",
        );
        let dumped_h = dec("47c25c9cf6e89642431a351bac4a4dcbcbc025ca15941cb86fb778090e1a5ef4");
        let dumped_ck = dec("b1ba1729443f2000825f5d9898a85cb9915ed83973b27455c61c7ba247f1a70b");
        let dumped_epriv = dec("f101e5a2570dd9e6da66eeb3db57b3ccf92ba6e7aed39822b6eaca669de38295");
        let sender_index = 3659426326u32;
        let priv_a = [0x11u8; 32];
        let priv_b = [0x22u8; 32];
        let pub_a = PublicKey::from(&StaticSecret::from(priv_a));
        let pub_b = PublicKey::from(&StaticSecret::from(priv_b));
        let mut h32 = [0u8; 32];
        h32.copy_from_slice(&dumped_h);
        let mut ck32 = [0u8; 32];
        ck32.copy_from_slice(&dumped_ck);
        let mut ep32 = [0u8; 32];
        ep32.copy_from_slice(&dumped_epriv);

        // 1) mac1 of the captured response must key off our public key.
        let m1 = mac(&mac1_key(pub_a.as_bytes()), &msg[..60]);
        assert_eq!(msg[60..76], m1, "mac1 mismatch");

        // 2) mirror-consume the captured initiation and compare with the
        //    runtime handshake state.
        let ck0 = hash(CONSTRUCTION);
        let mut h = hash_concat(&hash_concat(&ck0, IDENTIFIER), pub_b.as_bytes());
        h = hash_concat(&h, &init[8..40]);
        let mut ck = mix_key(&ck0, &init[8..40]).1;
        let (prk, ck1) = mix_key(
            &ck,
            &dh(&priv_b, &<[u8; 32]>::try_from(&init[8..40]).unwrap()),
        );
        let key = key2(&prk, &ck1);
        ck = ck1;
        let es = aead_open(&key, 0, &init[40..88], &h).expect("consume static");
        assert_eq!(&es[..], pub_a.as_bytes());
        h = hash_concat(&h, &init[40..88]);
        let (prk, ck2) = mix_key(&ck, &dh(&priv_b, pub_a.as_bytes()));
        let key = key2(&prk, &ck2);
        ck = ck2;
        assert!(
            aead_open(&key, 0, &init[88..116], &h).is_some(),
            "consume timestamp"
        );
        h = hash_concat(&h, &init[88..116]);
        assert_eq!(h, h32, "mirror-consume hash != runtime hs.h");
        assert_eq!(ck, ck32, "mirror-consume chain != runtime hs.ck");

        // 3) mirror-create the response with the responder's captured
        //    ephemeral, computing both DHs from the initiator side
        //    (DH is symmetric: ee = DH(e_i, e_r), se = DH(s_i, e_r)).
        let mut e_r = [0u8; 32];
        e_r.copy_from_slice(&msg[12..44]);
        h = hash_concat(&h, &e_r);
        ck = mix_key(&ck, &e_r).1;
        ck = mix_key(&ck, &dh(&ep32, &e_r)).1; // ee
        ck = mix_key(&ck, &dh(&priv_a, &e_r)).1; // se
        let zero_psk = [0u8; 32];
        let (prk, ck4) = mix_key(&ck, &zero_psk);
        let tau = key2(&prk, &ck4);
        let mut m3 = [0u8; 33];
        m3[..32].copy_from_slice(&tau);
        m3[32] = 0x03;
        let key = hmac(&prk, &m3);
        h = hash_concat(&h, &tau);
        let expect_enc = aead_seal(&key, 0, &[], &h);

        // 4) replay the captured message through process_response.
        let hs2 = Handshake {
            ck: ck32,
            h: h32,
            e_priv: ep32,
            our_static_priv: priv_a,
            sender_index,
            initiation: init.clone(),
        };
        let session = process_response(&hs2, &msg, pub_a.as_bytes(), None)
            .expect("process_response against reference capture");
        assert_eq!(
            session.remote_index,
            u32::from_le_bytes(msg[4..8].try_into().unwrap()),
            "remote index"
        );

        // 5) mirror derivation must reproduce the reference's encrypted field
        //    byte for byte — validates KDF3 against the reference binary.
        assert_eq!(
            expect_enc.as_slice(),
            &msg[44..60],
            "mirror-created response differs from reference"
        );
    }

    #[test]
    fn test_responder_handshake_roundtrip() {
        let priv_init = [0x33u8; 32];
        let priv_resp = [0x44u8; 32];
        let pub_init = *PublicKey::from(&StaticSecret::from(priv_init)).as_bytes();
        let pub_resp = *PublicKey::from(&StaticSecret::from(priv_resp)).as_bytes();

        let hs = build_initiation(
            &priv_init,
            &pub_init,
            &pub_resp,
            None,
            &tai64n_now(),
            HDR_INIT.0,
        );

        // Responder consumes initiation
        let init_res =
            process_initiation(&priv_resp, &pub_resp, hs.initiation()).expect("process_initiation");
        assert_eq!(init_res.sender_static_pub, pub_init);
        assert_eq!(init_res.sender_index, hs.sender_index);

        // Responder builds response
        let (resp_msg, mut resp_session) =
            build_response(&init_res, &priv_resp, None, HDR_RESPONSE.0);

        // Initiator consumes response
        let mut init_session =
            process_response(&hs, &resp_msg, &pub_init, None).expect("process_response");

        assert_eq!(init_session.remote_index, resp_session.local_index);
        assert_eq!(resp_session.remote_index, init_session.local_index);

        // Transport: initiator -> responder
        let plain_msg = b"hello from wireguard client";
        let sealed_by_init = init_session.seal(plain_msg).expect("init seal");
        let opened_by_resp = resp_session.open(&sealed_by_init).expect("resp open");
        assert_eq!(&opened_by_resp[..plain_msg.len()], plain_msg);

        // Transport: responder -> initiator
        let reply_msg = b"hello from wireguard server";
        let sealed_by_resp = resp_session.seal(reply_msg).expect("resp seal");
        let opened_by_init = init_session.open(&sealed_by_resp).expect("init open");
        assert_eq!(&opened_by_init[..reply_msg.len()], reply_msg);
    }
}
