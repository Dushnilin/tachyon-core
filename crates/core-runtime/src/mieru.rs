//! mieru (enfein/mieru v3) over TCP, written from the wire format.
//!
//! One TCP connection carries one session. Each direction is a run of
//! segments sealed with XChaCha20-Poly1305 under a key derived from the user
//! name, the password and a two-minute time salt. The 24-byte nonce goes out
//! in clear once, in front of the first segment of a direction, and every
//! later seal (metadata or payload) steps it by one. The last four nonce bytes
//! carry a hint (`sha256(user || nonce[..16])[..4]`) so a server can pick the
//! user without trying every key.
//!
//! The payload of a session is a SOCKS5 request / reply pair, without the
//! method negotiation (that is what the reference `apis/client` sends).
//!
//! Left out on purpose: the UDP transport, low-entropy encoding and traffic
//! patterns. A reference peer that has none of them switched on talks to this
//! file as is.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::sync::mpsc;

use crate::fastchacha::ChaChaPoly;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const META_LEN: usize = 32;
/// Bytes a server needs before it can pick the user: nonce + metadata + tag.
pub const FIRST_READ: usize = NONCE_LEN + META_LEN + TAG_LEN;

const MAX_PDU: usize = 32 * 1024;
const MAX_OPEN_PAYLOAD: usize = 1024;
const KEY_ITER: u32 = 64;
const KEY_REFRESH_SECS: i64 = 120;
const WINDOW_SLOTS: u16 = 256;

const OPEN_REQUEST: u8 = 2;
const OPEN_RESPONSE: u8 = 3;
const CLOSE_REQUEST: u8 = 4;
const CLOSE_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_CLIENT_TO_SERVER: u8 = 8;
const ACK_SERVER_TO_CLIENT: u8 = 9;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("mieru: {msg}"))
}

fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- keys

/// `sha256(password || 0x00 || username)`.
pub fn hashed_password(user: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update([0u8]);
    h.update(user.as_bytes());
    h.finalize().into()
}

/// PBKDF2-HMAC-SHA256, 64 rounds, one 32-byte block.
fn pbkdf2_block(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let prf = |data: &[&[u8]]| -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(password).expect("hmac takes any key length");
        for part in data {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    };
    let mut u = prf(&[salt, &1u32.to_be_bytes()]);
    let mut out = u;
    for _ in 1..KEY_ITER {
        u = prf(&[&u]);
        for (o, x) in out.iter_mut().zip(u) {
            *o ^= x;
        }
    }
    out
}

/// Key for the salt window starting at `window` (unix seconds, multiple of 120).
pub fn key_for_window(hashed: &[u8; 32], window: i64) -> [u8; 32] {
    type KeyCacheEntry = ([u8; 32], i64, [u8; 32]);
    static CACHE: std::sync::Mutex<[KeyCacheEntry; 8]> =
        std::sync::Mutex::new([([0u8; 32], i64::MIN, [0u8; 32]); 8]);
    if let Ok(guard) = CACHE.lock() {
        for (h, w, k) in guard.iter() {
            if *w == window && h == hashed {
                return *k;
            }
        }
    }
    let salt: [u8; 32] = Sha256::digest((window as u64).to_be_bytes()).into();
    let key = pbkdf2_block(hashed, &salt);
    if let Ok(mut guard) = CACHE.lock() {
        guard.rotate_right(1);
        guard[0] = (*hashed, window, key);
    }
    key
}

/// The window a client uses now: unix time rounded to the nearest two
/// minutes, halves up (what Go's `time.Round` does).
fn current_window() -> i64 {
    (unix_secs() + KEY_REFRESH_SECS / 2).div_euclid(KEY_REFRESH_SECS) * KEY_REFRESH_SECS
}

/// The three windows a server tries, oldest first.
fn window_candidates() -> [i64; 3] {
    let w = current_window();
    [w - KEY_REFRESH_SECS, w, w + KEY_REFRESH_SECS]
}

pub fn client_key(user: &str, password: &str) -> [u8; 32] {
    key_for_window(&hashed_password(user, password), current_window())
}

fn nonce_hint(user: &str, nonce: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(user.as_bytes());
    h.update(&nonce[..16]);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

// -------------------------------------------------------------- cipher

/// One direction of a connection: key plus the running nonce.
struct Dir {
    key: [u8; 32],
    fast: Option<([u8; 16], ChaChaPoly)>,
    user: String,
    nonce: Option<[u8; NONCE_LEN]>,
    rng: u64,
}

impl Dir {
    fn new(key: &[u8; 32], user: &str) -> Self {
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        let rng = u64::from_le_bytes(seed).max(1);
        Self {
            key: *key,
            fast: None,
            user: user.to_string(),
            nonce: None,
            rng,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Generate `0..=max` printable ASCII padding bytes on the stack without
    /// per-segment `getrandom` syscalls or heap allocations.
    fn next_padding(&mut self, max: u8) -> ([u8; 64], usize) {
        let len = (self.next_u64() as usize) % (max as usize + 1);
        let mut p = [0u8; 64];
        let mut i = 0;
        while i < len {
            let mut w = self.next_u64();
            for _ in 0..8 {
                if i >= len {
                    break;
                }
                p[i] = 0x20 + ((w as u8) % 0x5f);
                w >>= 8;
                i += 1;
            }
        }
        (p, len)
    }

    fn step(nonce: &mut [u8; NONCE_LEN]) {
        for b in nonce.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    fn cipher(&mut self, nonce: &[u8; NONCE_LEN]) -> (&ChaChaPoly, [u8; 12]) {
        let prefix: [u8; 16] = nonce[..16].try_into().expect("16 bytes");
        let need_rekey = self.fast.as_ref().is_none_or(|(p, _)| *p != prefix);
        if need_rekey {
            let subkey = chacha20::hchacha::<chacha20::cipher::consts::U10>(
                chacha20::Key::from_slice(&self.key),
                (&prefix).into(),
            );
            self.fast = Some((prefix, ChaChaPoly::new(subkey.as_slice())));
        }
        let mut n12 = [0u8; 12];
        n12[4..].copy_from_slice(&nonce[16..]);
        (&self.fast.as_ref().expect("set above").1, n12)
    }

    /// Seal `plain` onto `out`, nonce first when this is the first seal.
    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) {
        let nonce = match self.nonce.as_mut() {
            Some(n) => {
                Self::step(n);
                *n
            }
            None => {
                let mut n = [0u8; NONCE_LEN];
                let _ = getrandom::fill(&mut n);
                if !self.user.is_empty() {
                    let hint = nonce_hint(&self.user, &n);
                    n[NONCE_LEN - 4..].copy_from_slice(&hint);
                }
                self.nonce = Some(n);
                out.extend_from_slice(&n);
                n
            }
        };
        let start = out.len();
        out.extend_from_slice(plain);
        let (cipher, n12) = self.cipher(&nonce);
        let tag = cipher.seal(&n12, &[], &mut out[start..]);
        out.extend_from_slice(&tag);
    }

    /// Open `ct` (ciphertext + tag) in place and return the plaintext slice.
    fn open_in_place<'a>(
        &mut self,
        first_nonce: Option<&[u8]>,
        ct: &'a mut [u8],
    ) -> io::Result<&'a [u8]> {
        let nonce = if let Some(n) = self.nonce.as_mut() {
            Self::step(n);
            *n
        } else {
            let first = first_nonce.ok_or_else(|| bad("segment without a nonce"))?;
            let mut n = [0u8; NONCE_LEN];
            n.copy_from_slice(first);
            self.nonce = Some(n);
            n
        };
        if ct.len() < TAG_LEN {
            return Err(bad("short ciphertext"));
        }
        let split = ct.len() - TAG_LEN;
        let (body, tag_slice) = ct.split_at_mut(split);
        let tag: [u8; TAG_LEN] = (&*tag_slice).try_into().expect("16 bytes");
        let (cipher, n12) = self.cipher(&nonce);
        if !cipher.open(&n12, &[], body, &tag) {
            return Err(bad("authentication failed"));
        }
        Ok(body)
    }

    /// Open `ct` (ciphertext + tag). `first_nonce` is the clear nonce that
    /// leads the first segment of the direction, `None` afterwards.
    fn open(&mut self, first_nonce: Option<&[u8]>, ct: &[u8]) -> io::Result<Vec<u8>> {
        let mut buf = ct.to_vec();
        let len = self.open_in_place(first_nonce, &mut buf)?.len();
        buf.truncate(len);
        Ok(buf)
    }
}

/// Server side: find which user and which time salt sealed the first
/// `FIRST_READ` bytes of a connection. Returns the user index and the key.
pub fn discover(users: &[(String, [u8; 32])], head: &[u8]) -> Option<(usize, [u8; 32])> {
    if head.len() < FIRST_READ {
        return None;
    }
    let nonce = &head[..NONCE_LEN];
    let ct = &head[NONCE_LEN..FIRST_READ];
    for (i, (name, hashed)) in users.iter().enumerate() {
        if nonce_hint(name, nonce) != nonce[NONCE_LEN - 4..] {
            continue;
        }
        for window in window_candidates() {
            let key = key_for_window(hashed, window);
            let mut dir = Dir::new(&key, name);
            if dir.open(Some(nonce), ct).is_ok() {
                return Some((i, key));
            }
        }
    }
    None
}

// ------------------------------------------------------------ metadata

#[derive(Clone, Debug, PartialEq, Eq)]
enum Meta {
    Session {
        proto: u8,
        session_id: u32,
        seq: u32,
        status: u8,
        payload_len: u16,
        suffix_len: u8,
    },
    Data {
        proto: u8,
        session_id: u32,
        seq: u32,
        un_ack: u32,
        window: u16,
        fragment: u8,
        prefix_len: u8,
        payload_len: u16,
        suffix_len: u8,
    },
}

impl Meta {
    fn marshal(&self) -> [u8; META_LEN] {
        let mut b = [0u8; META_LEN];
        let minutes = (unix_secs() / 60) as u32;
        b[2..6].copy_from_slice(&minutes.to_be_bytes());
        match *self {
            Meta::Session {
                proto,
                session_id,
                seq,
                status,
                payload_len,
                suffix_len,
            } => {
                b[0] = proto;
                b[6..10].copy_from_slice(&session_id.to_be_bytes());
                b[10..14].copy_from_slice(&seq.to_be_bytes());
                b[14] = status;
                b[15..17].copy_from_slice(&payload_len.to_be_bytes());
                b[17] = suffix_len;
            }
            Meta::Data {
                proto,
                session_id,
                seq,
                un_ack,
                window,
                fragment,
                prefix_len,
                payload_len,
                suffix_len,
            } => {
                b[0] = proto;
                b[6..10].copy_from_slice(&session_id.to_be_bytes());
                b[10..14].copy_from_slice(&seq.to_be_bytes());
                b[14..18].copy_from_slice(&un_ack.to_be_bytes());
                b[18..20].copy_from_slice(&window.to_be_bytes());
                b[20] = fragment;
                b[21] = prefix_len;
                b[22..24].copy_from_slice(&payload_len.to_be_bytes());
                b[24] = suffix_len;
            }
        }
        b
    }

    /// `check_time` is what the reference does to every received metadata:
    /// the timestamp must be within a minute of ours.
    fn parse(b: &[u8], check_time: bool) -> io::Result<Self> {
        if b.len() != META_LEN {
            return Err(bad("metadata length"));
        }
        if check_time {
            let theirs = u32::from_be_bytes([b[2], b[3], b[4], b[5]]) as i64;
            if (unix_secs() / 60 - theirs).abs() > 1 {
                return Err(bad("metadata timestamp out of range"));
            }
        }
        let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        match b[0] {
            p @ (OPEN_REQUEST | OPEN_RESPONSE | CLOSE_REQUEST | CLOSE_RESPONSE) => {
                let payload_len = u16_at(15);
                if payload_len as usize > MAX_OPEN_PAYLOAD {
                    return Err(bad("session payload too large"));
                }
                Ok(Meta::Session {
                    proto: p,
                    session_id: u32_at(6),
                    seq: u32_at(10),
                    status: b[14],
                    payload_len,
                    suffix_len: b[17],
                })
            }
            p @ (DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT) => Ok(Meta::Data {
                proto: p,
                session_id: u32_at(6),
                seq: u32_at(10),
                un_ack: u32_at(14),
                window: u16_at(18),
                fragment: b[20],
                prefix_len: b[21],
                payload_len: u16_at(22),
                suffix_len: b[24],
            }),
            10 | 11 => Err(bad("low-entropy segments are not supported")),
            _ => Err(bad("unknown protocol")),
        }
    }

    /// Bytes that follow the sealed metadata on the wire.
    fn body_len(&self) -> usize {
        let (prefix, payload, suffix) = match *self {
            Meta::Session {
                payload_len,
                suffix_len,
                ..
            } => (0, payload_len as usize, suffix_len as usize),
            Meta::Data {
                prefix_len,
                payload_len,
                suffix_len,
                ..
            } => (
                prefix_len as usize,
                payload_len as usize,
                suffix_len as usize,
            ),
        };
        prefix + if payload > 0 { payload + TAG_LEN } else { 0 } + suffix
    }
}

// ----------------------------------------------------- segment coding

/// Seal a session segment (open/close) onto `out`.
fn put_session(
    send: &mut Dir,
    out: &mut Vec<u8>,
    proto: u8,
    session_id: u32,
    seq: u32,
    status: u8,
    payload: &[u8],
) {
    let (suffix, suffix_len) = send.next_padding(63);
    let meta = Meta::Session {
        proto,
        session_id,
        seq,
        status,
        payload_len: payload.len() as u16,
        suffix_len: suffix_len as u8,
    };
    send.seal(&meta.marshal(), out);
    if !payload.is_empty() {
        send.seal(payload, out);
    }
    out.extend_from_slice(&suffix[..suffix_len]);
}

/// Seal a data segment onto `out`.
fn put_data(
    send: &mut Dir,
    out: &mut Vec<u8>,
    proto: u8,
    session_id: u32,
    seq: u32,
    un_ack: u32,
    payload: &[u8],
) {
    let (prefix, prefix_len) = send.next_padding(31);
    let (suffix, suffix_len) = send.next_padding(31);
    let meta = Meta::Data {
        proto,
        session_id,
        seq,
        un_ack,
        window: WINDOW_SLOTS,
        fragment: 0,
        prefix_len: prefix_len as u8,
        payload_len: payload.len() as u16,
        suffix_len: suffix_len as u8,
    };
    send.seal(&meta.marshal(), out);
    out.extend_from_slice(&prefix[..prefix_len]);
    if !payload.is_empty() {
        send.seal(payload, out);
    }
    out.extend_from_slice(&suffix[..suffix_len]);
}

const DEC_BUF_CAP: usize = 256 * 1024;
const DEC_MIN_SPACE: usize = 96 * 1024;

/// Receive side of one direction: buffers bytes, yields whole segments.
struct Decoder {
    recv: Dir,
    rbuf: Vec<u8>,
    rstart: usize,
    rend: usize,
    pending: Option<Meta>,
    check_time: bool,
}

impl Decoder {
    fn new(key: &[u8; 32], user: &str, head: Vec<u8>, check_time: bool) -> Self {
        let rend = head.len();
        let mut rbuf = head;
        if rbuf.len() < DEC_BUF_CAP {
            rbuf.resize(DEC_BUF_CAP, 0);
        }
        Self {
            recv: Dir::new(key, user),
            rbuf,
            rstart: 0,
            rend,
            pending: None,
            check_time,
        }
    }

    fn read_slice(&mut self) -> &mut [u8] {
        if self.rstart == self.rend {
            self.rstart = 0;
            self.rend = 0;
        } else if self.rbuf.len() - self.rend < DEC_MIN_SPACE && self.rstart > 0 {
            self.rbuf.copy_within(self.rstart..self.rend, 0);
            self.rend -= self.rstart;
            self.rstart = 0;
        }
        if self.rbuf.len() - self.rend < DEC_MIN_SPACE {
            self.rbuf.resize(self.rend + DEC_MIN_SPACE, 0);
        }
        &mut self.rbuf[self.rend..]
    }

    fn advance_read(&mut self, n: usize) {
        self.rend += n;
    }

    #[cfg(test)]
    fn push(&mut self, bytes: &[u8]) {
        let dst = self.read_slice();
        if dst.len() >= bytes.len() {
            dst[..bytes.len()].copy_from_slice(bytes);
            self.rend += bytes.len();
        } else {
            let need = self.rend + bytes.len();
            if self.rbuf.len() < need {
                self.rbuf.resize(need, 0);
            }
            self.rbuf[self.rend..need].copy_from_slice(bytes);
            self.rend = need;
        }
    }

    fn avail(&self) -> &[u8] {
        &self.rbuf[self.rstart..self.rend]
    }

    /// Nothing buffered and no half-read segment.
    fn idle(&self) -> bool {
        self.avail().is_empty() && self.pending.is_none()
    }

    fn consume(&mut self, n: usize) {
        self.rstart += n;
        if self.rstart == self.rend {
            self.rstart = 0;
            self.rend = 0;
        }
    }

    /// Decode one whole segment in place and return its metadata + plaintext slice.
    fn next_slice(&mut self) -> io::Result<Option<(Meta, &[u8])>> {
        if self.pending.is_none() {
            let lead = if self.recv.nonce.is_none() {
                NONCE_LEN
            } else {
                0
            };
            let need = lead + META_LEN + TAG_LEN;
            if self.avail().len() < need {
                return Ok(None);
            }
            let first_nonce: Option<[u8; NONCE_LEN]> = if lead > 0 {
                Some(
                    self.rbuf[self.rstart..self.rstart + NONCE_LEN]
                        .try_into()
                        .expect("24 bytes"),
                )
            } else {
                None
            };
            let ct_slice = &mut self.rbuf[self.rstart + lead..self.rstart + need];
            let plain = self
                .recv
                .open_in_place(first_nonce.as_ref().map(|n| &n[..]), ct_slice)?;
            let meta = Meta::parse(plain, self.check_time)?;
            self.consume(need);
            self.pending = Some(meta);
        }
        let meta = self.pending.clone().expect("set just above");
        let body = meta.body_len();
        if self.avail().len() < body {
            return Ok(None);
        }
        let (prefix, payload_len) = match meta {
            Meta::Session { payload_len, .. } => (0usize, payload_len as usize),
            Meta::Data {
                prefix_len,
                payload_len,
                ..
            } => (prefix_len as usize, payload_len as usize),
        };
        let p_start = self.rstart + prefix;
        let p_end = p_start + payload_len;
        if payload_len > 0 {
            let end = p_end + TAG_LEN;
            let _ = self
                .recv
                .open_in_place(None, &mut self.rbuf[p_start..end])?;
        }
        self.consume(body);
        self.pending = None;
        Ok(Some((meta, &self.rbuf[p_start..p_end])))
    }

    /// One whole segment, or `None` when more bytes are needed.
    #[cfg(test)]
    fn next(&mut self) -> io::Result<Option<(Meta, Vec<u8>)>> {
        match self.next_slice()? {
            Some((meta, slice)) => Ok(Some((meta, slice.to_vec()))),
            None => Ok(None),
        }
    }
}

// ----------------------------------------------------- server underlay

enum Out {
    Data(u32, Vec<u8>),
    Close(u32),
}

struct Live {
    tx: mpsc::Sender<Vec<u8>>,
    seq: u32,
}

fn take_pool_buf(free: &std::sync::Mutex<Vec<Vec<u8>>>, data: &[u8]) -> Vec<u8> {
    let mut buf = free.lock().expect("free").pop().unwrap_or_default();
    if buf.len() < data.len() {
        buf.resize(data.len(), 0);
    } else {
        buf.truncate(data.len());
    }
    buf[..data.len()].copy_from_slice(data);
    buf
}

fn give_pool_buf(free: &std::sync::Mutex<Vec<Vec<u8>>>, buf: Vec<u8>) {
    let mut guard = free.lock().expect("free");
    if guard.len() < 128 {
        guard.push(buf);
    }
}

pub struct MieruServerStream {
    sid: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    pos: usize,
    out_tx: mpsc::Sender<Out>,
    free: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    closed: bool,
}

impl AsyncRead for MieruServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos >= self.pending.len() {
            let spent = std::mem::take(&mut self.pending);
            if !spent.is_empty() {
                give_pool_buf(&self.free, spent);
            }
            self.pos = 0;
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(chunk)) => self.pending = chunk,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
        loop {
            let avail = self.pending.len() - self.pos;
            let n = out.remaining().min(avail);
            out.put_slice(&self.pending[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos < self.pending.len() || out.remaining() == 0 {
                break;
            }
            let spent = std::mem::take(&mut self.pending);
            if !spent.is_empty() {
                give_pool_buf(&self.free, spent);
            }
            self.pos = 0;
            match self.rx.try_recv() {
                Ok(chunk) => self.pending = chunk,
                Err(_) => break,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MieruServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(2 * MAX_PDU);
        match self.out_tx.try_reserve() {
            Ok(permit) => {
                let owned = take_pool_buf(&self.free, &buf[..n]);
                permit.send(Out::Data(self.sid, owned));
                Poll::Ready(Ok(n))
            }
            Err(mpsc::error::TrySendError::Full(())) => {
                let tx = self.out_tx.clone();
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    if tx.reserve().await.is_ok() {
                        waker.wake();
                    }
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            let sid = self.sid;
            let tx = self.out_tx.clone();
            if tx.try_send(Out::Close(sid)).is_err()
                && tokio::runtime::Handle::try_current().is_ok()
            {
                tokio::spawn(async move {
                    let _ = tx.send(Out::Close(sid)).await;
                });
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MieruServerStream {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let sid = self.sid;
            let tx = self.out_tx.clone();
            if tx.try_send(Out::Close(sid)).is_err()
                && tokio::runtime::Handle::try_current().is_ok()
            {
                tokio::spawn(async move {
                    let _ = tx.send(Out::Close(sid)).await;
                });
            }
        }
        let spent = std::mem::take(&mut self.pending);
        if !spent.is_empty() {
            give_pool_buf(&self.free, spent);
        }
    }
}

fn emit(
    o: Out,
    live: &mut HashMap<u32, Live>,
    send: &mut Dir,
    wbuf: &mut Vec<u8>,
    free: &std::sync::Mutex<Vec<Vec<u8>>>,
) {
    match o {
        Out::Data(sid, bytes) => {
            if let Some(l) = live.get_mut(&sid) {
                for chunk in bytes.chunks(MAX_PDU) {
                    put_data(send, wbuf, DATA_SERVER_TO_CLIENT, sid, l.seq, 0, chunk);
                    l.seq = l.seq.wrapping_add(1);
                }
            }
            give_pool_buf(free, bytes);
        }
        Out::Close(sid) => {
            if let Some(l) = live.remove(&sid) {
                put_session(send, wbuf, CLOSE_REQUEST, sid, l.seq, 0, &[]);
            }
        }
    }
}

/// Serve one client connection that may carry many sessions (the reference
/// client reuses an underlay). Every session the client opens is handed to
/// `accept` as a stream. Returns when the connection ends.
pub async fn serve_underlay<S, F>(
    stream: S,
    key: &[u8; 32],
    user: &str,
    head: Vec<u8>,
    mut accept: F,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(MieruServerStream),
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut dec = Decoder::new(key, user, head, true);
    let mut send = Dir::new(key, user);
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(128);
    let mut live: HashMap<u32, Live> = HashMap::new();
    let mut wbuf = Vec::with_capacity(128 * 1024);
    let free = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    loop {
        while let Some((meta, payload)) = dec.next_slice()? {
            match meta {
                Meta::Session {
                    proto,
                    session_id: sid,
                    ..
                } => match proto {
                    OPEN_REQUEST => {
                        if sid == 0 {
                            return Err(bad("session id 0"));
                        }
                        if let Entry::Vacant(e) = live.entry(sid) {
                            let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                            let app = MieruServerStream {
                                sid,
                                rx,
                                pending: Vec::new(),
                                pos: 0,
                                out_tx: out_tx.clone(),
                                free: std::sync::Arc::clone(&free),
                                closed: false,
                            };
                            accept(app);
                            put_session(&mut send, &mut wbuf, OPEN_RESPONSE, sid, 0, 0, &[]);
                            e.insert(Live { tx, seq: 1 });
                        }
                        if !payload.is_empty()
                            && let Some(l) = live.get(&sid)
                        {
                            let buf = take_pool_buf(&free, payload);
                            let _ = l.tx.send(buf).await;
                        }
                    }
                    CLOSE_REQUEST => {
                        let seq = live.remove(&sid).map_or(0, |l| l.seq);
                        put_session(&mut send, &mut wbuf, CLOSE_RESPONSE, sid, seq, 0, &[]);
                    }
                    CLOSE_RESPONSE => {
                        live.remove(&sid);
                    }
                    _ => {}
                },
                Meta::Data {
                    proto,
                    session_id: sid,
                    ..
                } => {
                    if proto == DATA_CLIENT_TO_SERVER
                        && !payload.is_empty()
                        && let Some(l) = live.get(&sid)
                    {
                        let buf = take_pool_buf(&free, payload);
                        let _ = l.tx.send(buf).await;
                    }
                }
            }
        }
        if !wbuf.is_empty() {
            wr.write_all(&wbuf).await?;
            wr.flush().await?;
            wbuf.clear();
        }
        tokio::select! {
            n = rd.read(dec.read_slice()) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                dec.advance_read(n);
            }
            Some(o) = out_rx.recv() => {
                emit(o, &mut live, &mut send, &mut wbuf, &free);
                while wbuf.len() < 256 * 1024 {
                    let Ok(o) = out_rx.try_recv() else {
                        break;
                    };
                    emit(o, &mut live, &mut send, &mut wbuf, &free);
                }
            }
        }
    }
}

// -------------------------------------------------------------- stream

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// A mieru session over a byte stream.
pub struct MieruStream<S> {
    inner: S,
    role: Role,
    send: Dir,
    dec: Decoder,
    session_id: u32,
    next_seq: u32,
    received: u32,
    plain: Vec<u8>,
    pstart: usize,
    wbuf: Vec<u8>,
    wstart: usize,
    open_sent: bool,
    closed_by_peer: bool,
    close_sent: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> MieruStream<S> {
    fn new(inner: S, role: Role, key: &[u8; 32], user: &str, head: Vec<u8>) -> Self {
        let mut session_id = 0;
        if role == Role::Client {
            while session_id == 0 {
                let mut b = [0u8; 4];
                let _ = getrandom::fill(&mut b);
                session_id = u32::from_be_bytes(b);
            }
        }
        Self {
            inner,
            role,
            send: Dir::new(key, user),
            dec: Decoder::new(key, user, head, role == Role::Server),
            session_id,
            next_seq: 0,
            received: 0,
            plain: Vec::with_capacity(64 * 1024),
            pstart: 0,
            wbuf: Vec::with_capacity(128 * 1024),
            wstart: 0,
            open_sent: false,
            closed_by_peer: false,
            close_sent: false,
        }
    }

    pub fn client(inner: S, user: &str, password: &str) -> Self {
        Self::new(
            inner,
            Role::Client,
            &client_key(user, password),
            user,
            Vec::new(),
        )
    }

    pub fn client_with_hash(inner: S, user: &str, hashed: &[u8; 32]) -> Self {
        let key = key_for_window(hashed, current_window());
        Self::new(inner, Role::Client, &key, user, Vec::new())
    }

    /// `head` is what `discover` already read off the socket.
    pub fn server(inner: S, key: &[u8; 32], user: &str, head: Vec<u8>) -> Self {
        Self::new(inner, Role::Server, key, user, head)
    }

    fn queue_session(&mut self, proto: u8, payload: &[u8], status: u8) {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        put_session(
            &mut self.send,
            &mut self.wbuf,
            proto,
            self.session_id,
            seq,
            status,
            payload,
        );
    }

    fn queue_data(&mut self, payload: &[u8]) {
        let proto = match self.role {
            Role::Client => DATA_CLIENT_TO_SERVER,
            Role::Server => DATA_SERVER_TO_CLIENT,
        };
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        put_data(
            &mut self.send,
            &mut self.wbuf,
            proto,
            self.session_id,
            seq,
            self.received,
            payload,
        );
    }

    /// Decode one whole segment directly into `out` when possible, spilling any
    /// remainder into `self.plain`. `Ok(false)`: need more bytes.
    fn parse_segment_into(&mut self, out: &mut ReadBuf<'_>) -> io::Result<bool> {
        let Some((meta, payload)) = self.dec.next_slice()? else {
            return Ok(false);
        };
        self.received = self.received.wrapping_add(1);
        let mut reply_proto: Option<u8> = None;
        let keep = match meta {
            Meta::Session {
                proto, session_id, ..
            } => match proto {
                OPEN_REQUEST => {
                    if self.role != Role::Server || session_id == 0 {
                        return Err(bad("unexpected open request"));
                    }
                    if self.session_id == 0 {
                        self.session_id = session_id;
                        reply_proto = Some(OPEN_RESPONSE);
                    }
                    true
                }
                OPEN_RESPONSE => {
                    if self.role != Role::Client {
                        return Err(bad("unexpected open response"));
                    }
                    true
                }
                CLOSE_REQUEST => {
                    if !self.close_sent {
                        reply_proto = Some(CLOSE_RESPONSE);
                    }
                    self.closed_by_peer = true;
                    false
                }
                _ => {
                    self.closed_by_peer = true;
                    false
                }
            },
            Meta::Data { proto, .. } => {
                matches!(proto, DATA_CLIENT_TO_SERVER | DATA_SERVER_TO_CLIENT)
            }
        };
        if keep && !payload.is_empty() {
            if self.pstart == self.plain.len() {
                let n = out.remaining().min(payload.len());
                out.put_slice(&payload[..n]);
                if n < payload.len() {
                    self.plain.clear();
                    self.pstart = 0;
                    self.plain.extend_from_slice(&payload[n..]);
                }
            } else {
                self.plain.extend_from_slice(payload);
            }
        }
        if let Some(proto) = reply_proto {
            self.queue_session(proto, &[], 0);
        }
        Ok(true)
    }

    fn poll_flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wstart < self.wbuf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wstart..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.wstart += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wstart = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MieruStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let initial_rem = out.remaining();
        loop {
            if this.pstart < this.plain.len() {
                let n = out.remaining().min(this.plain.len() - this.pstart);
                out.put_slice(&this.plain[this.pstart..this.pstart + n]);
                this.pstart += n;
                if this.pstart == this.plain.len() {
                    this.plain.clear();
                    this.pstart = 0;
                }
                if out.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            while !this.closed_by_peer && out.remaining() > 0 && this.pstart == this.plain.len() {
                if !this.parse_segment_into(out)? {
                    break;
                }
                let _ = this.poll_flush_wbuf(cx);
            }
            if out.remaining() < initial_rem || this.closed_by_peer {
                return Poll::Ready(Ok(()));
            }
            let mut rb = ReadBuf::new(this.dec.read_slice());
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let got = rb.filled().len();
                    if got == 0 {
                        if this.dec.idle() {
                            this.closed_by_peer = true;
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.dec.advance_read(got);
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MieruStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.close_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.wbuf.len() - this.wstart > 4 * MAX_PDU {
            match this.poll_flush_wbuf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let consumed = if this.role == Role::Client && !this.open_sent {
            // The first bytes ride in the open request.
            let n = buf.len().min(MAX_OPEN_PAYLOAD);
            this.open_sent = true;
            this.queue_session(OPEN_REQUEST, &buf[..n], 0);
            n
        } else {
            let n = buf.len().min(2 * MAX_PDU);
            for chunk in buf[..n].chunks(MAX_PDU) {
                this.queue_data(chunk);
            }
            n
        };
        match this.poll_flush_wbuf(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(consumed)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_wbuf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            if this.role == Role::Client && !this.open_sent {
                this.open_sent = true;
                this.queue_session(OPEN_REQUEST, &[], 0);
            }
            if !this.closed_by_peer && this.session_id != 0 {
                this.queue_session(CLOSE_REQUEST, &[], 0);
            }
            this.close_sent = true;
        }
        match this.poll_flush_wbuf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// --------------------------------------------------------------- socks5

/// `05 01 00 ATYP ADDR PORT`, the request that opens a session.
pub fn socks5_request(host: &str, ip: Option<std::net::IpAddr>, port: u16) -> io::Result<Vec<u8>> {
    let mut out = vec![0x05, 0x01, 0x00];
    match ip {
        Some(std::net::IpAddr::V4(a)) => {
            out.push(0x01);
            out.extend_from_slice(&a.octets());
        }
        Some(std::net::IpAddr::V6(a)) => {
            out.push(0x04);
            out.extend_from_slice(&a.octets());
        }
        None => {
            if host.is_empty() || host.len() > 255 {
                return Err(bad("target host length"));
            }
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn pbkdf2_matches_the_rfc_shape() {
        // 64 rounds of HMAC-SHA256 against a straight re-computation.
        let k = pbkdf2_block(b"password", b"salt");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"password").unwrap();
        mac.update(b"salt");
        mac.update(&1u32.to_be_bytes());
        let mut u: [u8; 32] = mac.finalize().into_bytes().into();
        let mut t = u;
        for _ in 1..64 {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"password").unwrap();
            m.update(&u);
            u = m.finalize().into_bytes().into();
            for (a, b) in t.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        assert_eq!(k, t);
    }

    #[test]
    fn window_rounds_half_up() {
        // 59 s past a boundary rounds down, 60 s rounds up.
        let w = |t: i64| (t + KEY_REFRESH_SECS / 2).div_euclid(KEY_REFRESH_SECS) * KEY_REFRESH_SECS;
        assert_eq!(w(59), 0);
        assert_eq!(w(60), 120);
        assert_eq!(w(119), 120);
        assert_eq!(w(179), 120);
        assert_eq!(w(180), 240);
    }

    #[test]
    fn metadata_round_trips() {
        let m = Meta::Data {
            proto: DATA_CLIENT_TO_SERVER,
            session_id: 7,
            seq: 9,
            un_ack: 3,
            window: 256,
            fragment: 0,
            prefix_len: 5,
            payload_len: 100,
            suffix_len: 6,
        };
        assert_eq!(Meta::parse(&m.marshal(), true).unwrap(), m);
        assert_eq!(m.body_len(), 5 + 100 + TAG_LEN + 6);
        let s = Meta::Session {
            proto: OPEN_REQUEST,
            session_id: 1,
            seq: 0,
            status: 0,
            payload_len: 0,
            suffix_len: 4,
        };
        assert_eq!(Meta::parse(&s.marshal(), true).unwrap(), s);
        assert_eq!(s.body_len(), 4);
    }

    #[test]
    fn stale_timestamp_is_refused() {
        let mut b = Meta::Session {
            proto: OPEN_REQUEST,
            session_id: 1,
            seq: 0,
            status: 0,
            payload_len: 0,
            suffix_len: 0,
        }
        .marshal();
        let old = ((unix_secs() / 60) as u32).wrapping_sub(10);
        b[2..6].copy_from_slice(&old.to_be_bytes());
        assert!(Meta::parse(&b, true).is_err());
        assert!(Meta::parse(&b, false).is_ok());
    }

    #[tokio::test]
    async fn sessions_round_trip_and_close() {
        let users = vec![
            ("alice".to_string(), hashed_password("alice", "pw-a")),
            ("bob".to_string(), hashed_password("bob", "pw-b")),
        ];
        let (c, mut s) = duplex(1 << 20);
        let mut client = MieruStream::client(c, "bob", "pw-b");
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let big2 = big.clone();
        let server = tokio::spawn(async move {
            let mut head = vec![0u8; FIRST_READ];
            s.read_exact(&mut head).await.unwrap();
            let (idx, key) = discover(&users, &head).expect("user found");
            assert_eq!(users[idx].0, "bob");
            let mut st = MieruStream::server(s, &key, "bob", head);
            let mut got = vec![0u8; 5 + big2.len()];
            st.read_exact(&mut got).await.unwrap();
            assert_eq!(&got[..5], b"hello");
            assert_eq!(&got[5..], &big2[..]);
            st.write_all(b"reply").await.unwrap();
            st.flush().await.unwrap();
            let mut rest = Vec::new();
            st.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            st.shutdown().await.unwrap();
        });
        client.write_all(b"hello").await.unwrap();
        client.write_all(&big).await.unwrap();
        client.flush().await.unwrap();
        let mut r = [0u8; 5];
        client.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, b"reply");
        client.shutdown().await.unwrap();
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_password_is_not_discovered() {
        let users = vec![("alice".to_string(), hashed_password("alice", "right"))];
        let (c, mut s) = duplex(1 << 16);
        let mut client = MieruStream::client(c, "alice", "wrong");
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        let mut head = vec![0u8; FIRST_READ];
        s.read_exact(&mut head).await.unwrap();
        assert!(discover(&users, &head).is_none());
    }

    #[tokio::test]
    async fn one_underlay_carries_two_sessions() {
        let key = client_key("bob", "pw");
        let (mut c, s) = duplex(1 << 20);
        let server = tokio::spawn(async move {
            serve_underlay(s, &key, "bob", Vec::new(), |mut app| {
                tokio::spawn(async move {
                    let mut b = [0u8; 5];
                    app.read_exact(&mut b).await.unwrap();
                    app.write_all(&b.to_ascii_uppercase()).await.unwrap();
                });
            })
            .await
        });
        let mut send = Dir::new(&key, "bob");
        let mut buf = Vec::new();
        put_session(&mut send, &mut buf, OPEN_REQUEST, 1, 0, 0, b"ping1");
        put_session(&mut send, &mut buf, OPEN_REQUEST, 2, 0, 0, b"ping2");
        c.write_all(&buf).await.unwrap();
        let mut dec = Decoder::new(&key, "bob", Vec::new(), false);
        let mut seen = std::collections::HashMap::new();
        let mut tmp = [0u8; 4096];
        while seen.len() < 2 {
            let n = c.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            dec.push(&tmp[..n]);
            while let Some((m, p)) = dec.next().unwrap() {
                if let Meta::Data { session_id, .. } = m {
                    seen.insert(session_id, p);
                }
            }
        }
        assert_eq!(seen[&1], b"PING1");
        assert_eq!(seen[&2], b"PING2");
        drop(c);
        let _ = server.await;
    }
}
