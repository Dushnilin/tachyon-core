//! AES-GCM through the kernel Crypto API (`AF_ALG`), so a board that ships a
//! DMA crypto engine (NXP CAAM, MediaTek EIP93, …) can push the block cipher
//! onto it instead of burning main-CPU cycles.
//!
//! The contract with `algif_aead`, read out of the linux v6.6 and v6.18
//! sources and confirmed against a live kernel:
//!
//! * everything — `ALG_SET_OP`, `ALG_SET_IV` (12-byte nonce),
//!   `ALG_SET_AEAD_ASSOCLEN` — rides as control messages on **sendmsg**;
//!   the recv side parses nothing;
//! * one sendmsg carries `aad || pt` (encrypt) or `aad || ct || tag`
//!   (decrypt) as plain iovecs, no concatenation copy;
//! * recvmsg returns `aad || ct || tag` (the AAD is echoed verbatim) or
//!   `aad || pt` — see `_aead_recvmsg`: outlen is `used ± authsize` and
//!   `used` includes the AAD;
//! * the receive iovecs must total **exactly** the output length:
//!   `aead_recvmsg` loops `while (msg_data_left(msg))`, and a second
//!   iteration with no fresh sendmsg lands in `af_alg_wait_for_data`, which
//!   uses `MAX_SCHEDULE_TIMEOUT` — it ignores `SO_RCVTIMEO` and never
//!   returns. Exact iov totals make one pass and exit;
//! * a failed tag check surfaces as `EBADMSG` from recvmsg (by then the
//!   user buffer already holds AAD||CT junk, so [`AfalgGcm::open`] zeroes
//!   it).
//!
//! Nothing here runs blind. [`threshold`] self-tests a known-answer against
//! RustCrypto and then races the software path at the record sizes the proxy
//! seals; only the first size the kernel wins becomes the cutoff. A kernel
//! without `AF_ALG` (Docker's default seccomp profile blocks the socket
//! call), a software-only driver, or an ARM CE driver that loses to our own
//! SIMD all simply get `0` — off for the whole process — and the proxy never
//! notices. `TACHYON_AF_ALG=off` forces that by hand.

// The kernel and libc spell `msg_controllen` / `msg_iovlen` differently per
// target (usize, u32, i32 across glibc/musl), so every write adapts with
// `as _`; where that lands on the same type the cast is identity and this
// lint fires — the adaptation is the whole point. The fd/length casts are
// range-checked by construction (kernel structs, checked iov totals).
#![allow(
    trivial_numeric_casts,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use alloc::boxed::Box;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::{Mutex, OnceLock};
use alloc::vec;

/// `AF_ALG` in linux's socket family table (38, stable since v4.10) — libc
/// does not name it on every target this crate builds for.
const AF_ALG: libc::c_int = 38;
/// Kernel UAPI `include/uapi/linux/if_alg.h`; 279 is equally stable.
const SOL_ALG: libc::c_int = 279;
const ALG_SET_KEY: libc::c_int = 1;
const ALG_SET_IV: libc::c_int = 2;
const ALG_SET_OP: libc::c_int = 3;
const ALG_SET_AEAD_ASSOCLEN: libc::c_int = 4;
const ALG_SET_AEAD_AUTHSIZE: libc::c_int = 5;
const ALG_OP_ENCRYPT: u32 = 1;
const ALG_OP_DECRYPT: u32 = 0;

/// Biggest AAD echoed into a stack scratch buffer; larger AADs take the heap
/// path. Everything this crate speaks with — TLS 1.3's 5-byte header, a
/// shadowsocks chunk header, a QUIC short header — is far below this.
const STACK_AAD: usize = 128;

/// Smallest payload routed to the kernel for this process: below it the
/// syscall pair costs more than the AES it saves. `0` as the process-wide
/// answer means off; `0` as an instance answer (how tests and calibration
/// build one) means "always kernel".
static THRESHOLD: OnceLock<usize> = OnceLock::new();

/// The payload size at which seal/open switch to the kernel for this
/// process. `0` = the backend is off (no `AF_ALG`, self-test failed, or the
/// software cipher won the calibration).
pub fn threshold() -> usize {
    *THRESHOLD.get_or_init(calibrate)
}

/// One keyed `gcm(aes)` parent socket plus the accepted child every
/// operation runs on. The parent stays open because it owns the tfm the
/// child borrowed (`af_alg_release_parent` is refcounted, but keeping both
/// costs one fd and no thought).
struct Conn {
    parent: RawFd,
    child: RawFd,
}

impl Conn {
    fn new(key: &[u8]) -> io::Result<Conn> {
        let parent = unsafe { libc::socket(AF_ALG, libc::SOCK_SEQPACKET, 0) };
        if parent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa: libc::sockaddr_alg = unsafe { core::mem::zeroed() };
        sa.salg_family = AF_ALG as libc::sa_family_t;
        put_name(sa.salg_type.as_mut_ptr().cast(), sa.salg_type.len(), b"aead");
        put_name(sa.salg_name.as_mut_ptr().cast(), sa.salg_name.len(), b"gcm(aes)");
        let rc = unsafe {
            libc::bind(
                parent,
                &sa as *const libc::sockaddr_alg as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(close_err(parent, io::Error::last_os_error()));
        }

        let rc = unsafe {
            libc::setsockopt(
                parent,
                SOL_ALG,
                ALG_SET_KEY,
                key.as_ptr().cast(),
                key.len() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(close_err(parent, io::Error::last_os_error()));
        }

        // The kernel takes the authsize from `optlen`, not from the value:
        // `type->setauthsize(ask->private, optlen)` in af_alg.c.
        let rc = unsafe { libc::setsockopt(parent, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, core::ptr::null(), 16) };
        if rc < 0 {
            return Err(close_err(parent, io::Error::last_os_error()));
        }

        let child = unsafe { libc::accept(parent, core::ptr::null_mut(), core::ptr::null_mut()) };
        if child < 0 {
            return Err(close_err(parent, io::Error::last_os_error()));
        }

        Ok(Conn { parent, child })
    }

    /// Encrypt `buf` in place, return the tag. Sendmsg gets
    /// `aad || pt`; recvmsg gets `aad || ct || tag` back.
    fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> io::Result<[u8; 16]> {
        self.send(true, nonce, aad, buf, &[])?;
        let mut tag = [0u8; 16];
        recv_payload(self.child, aad.len(), buf, Some(&mut tag))?;
        Ok(tag)
    }

    /// Decrypt `buf` in place; `Err` is either the kernel saying EBADMSG or
    /// something going wrong with the socket — the caller turns both into
    /// "no plaintext".
    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> io::Result<()> {
        self.send(false, nonce, aad, buf, tag)?;
        recv_payload(self.child, aad.len(), buf, None)
    }

    /// One sendmsg: control messages (op, assoclen, iv) plus the payload as
    /// scatter iovecs so aad and data are never concatenated in userspace.
    fn send(&self, enc: bool, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> io::Result<()> {
        let expect = aad.len() + buf.len() + tag.len();

        // op(4) + assoc(4) + iv(4 + 12) — all three, always: af_alg_sendmsg
        // only refreshes ctx->enc / ctx->iv / ctx->aead_assoclen when a
        // control message is present, and a stale one poisons the next op.
        let mut cbuf = [0u8; 128];
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_control = cbuf.as_mut_ptr().cast();
        // The three control messages occupy at most 80 bytes on 64-bit and
        // 64 on 32-bit linux — `cbuf` has headroom for either. Field casts:
        // `msg_controllen` is `usize` on glibc, `u32` on musl.
        msg.msg_controllen =
            unsafe { libc::CMSG_SPACE(4) + libc::CMSG_SPACE(4) + libc::CMSG_SPACE(4 + 12) } as _;
        unsafe { fill_cmsgs(&mut msg, enc, aad.len() as u32, nonce)? };

        let mut iov = [libc::iovec { iov_base: core::ptr::null_mut(), iov_len: 0 }; 3];
        let mut n = 0;
        push_iov_const(&mut iov, &mut n, aad);
        push_iov_const(&mut iov, &mut n, buf);
        push_iov_const(&mut iov, &mut n, tag);
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = n as _;

        loop {
            let sent = unsafe { libc::sendmsg(self.child, &msg, 0) };
            if sent >= 0 {
                return if sent as usize == expect {
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::WriteZero, "short afalg sendmsg"))
                };
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.child);
            libc::close(self.parent);
        }
    }
}

fn close_err(fd: RawFd, e: io::Error) -> io::Error {
    unsafe { libc::close(fd) };
    e
}

/// The kernel backend: sockets plus the software cipher small payloads fall
/// back to. `seal`/`open` mirror [`crate::fastgcm::Gcm`]'s exactly, so the
/// variant is a drop-in.
///
/// Operations on one instance serialize through the mutex: two threads
/// interleaving sendmsg/recvmsg on the same child socket would cross their
/// records (the kernel's own `ctx->write` guard only rejects a concurrent
/// send with `EBUSY`).
pub struct AfalgGcm {
    conn: Mutex<Conn>,
    /// Payloads below this go to the embedded software cipher; `0` routes
    /// everything to the kernel (how tests and calibration build one).
    threshold: usize,
    sw: Box<crate::fastgcm::Gcm>,
}

impl AfalgGcm {
    /// Bind, set key and authsize, accept the ops socket. Any failure — no
    /// `AF_ALG`, seccomp, no `gcm(aes)` — is an `Err` and the caller keeps
    /// the software path.
    ///
    /// # Errors
    ///
    /// Whatever `socket`/`bind`/`setsockopt`/`accept` reports — most often
    /// `EPERM` when a seccomp filter blocks `AF_ALG`, or `ENOENT` when the
    /// kernel has no `gcm(aes)` template. Callers treat every error alike:
    /// fall back to the software cipher.
    pub fn new(key: &[u8], threshold: usize) -> io::Result<Self> {
        let conn = Conn::new(key)?;
        Ok(Self {
            conn: Mutex::new(conn),
            threshold,
            sw: Box::new(crate::fastgcm::Gcm::new_software(key)),
        })
    }

    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        if buf.len() < self.threshold {
            return self.sw.seal(nonce, aad, buf);
        }
        let conn = self.lock();
        conn.encrypt(nonce, aad, buf).expect("afalg seal")
    }

    /// On any failure (the tag check, or a broken socket) nothing of the
    /// plaintext is left in `buf` and the answer is `false`.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        if buf.len() < self.threshold {
            return self.sw.open(nonce, aad, buf, tag);
        }
        let conn = self.lock();
        match conn.decrypt(nonce, aad, buf, tag) {
            Ok(()) => true,
            Err(_) => {
                buf.fill(0);
                false
            }
        }
    }

    /// A poisoned mutex means a sibling thread panicked mid-record; the
    /// socket itself is fine, so carry on rather than poison every later
    /// connection.
    fn lock(&self) -> std::sync::MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The kernel UAPI stores these as byte arrays, but libc spells the element
/// type per target — go through a raw pointer so both spellings work. The
/// destination is already zeroed, so only the name bytes are copied.
fn put_name(dst: *mut u8, cap: usize, src: &[u8]) {
    let n = src.len().min(cap);
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n) };
}

fn push_iov(iov: &mut [libc::iovec], n: &mut usize, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    iov[*n] = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    *n += 1;
}

/// Send side: the kernel only reads these buffers, so an immutable slice is
/// enough — the raw pointer just carries it across the syscall.
fn push_iov_const(iov: &mut [libc::iovec], n: &mut usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    iov[*n] = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    *n += 1;
}

/// Build OP, ASSOCLEN and IV control messages inside `msg`'s already-set
/// control buffer, in that order. Every pointer here is derived from `msg`,
/// which the caller owns for the duration.
unsafe fn fill_cmsgs(msg: &mut libc::msghdr, enc: bool, assoc: u32, nonce: &[u8; 12]) -> io::Result<()> {
    unsafe {
    let mut c = libc::CMSG_FIRSTHDR(msg);
    if c.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no cmsg"));
    }
    (*c).cmsg_level = SOL_ALG;
    (*c).cmsg_type = ALG_SET_OP;
    (*c).cmsg_len = libc::CMSG_LEN(4) as _;
    *libc::CMSG_DATA(c).cast::<u32>() = if enc { ALG_OP_ENCRYPT } else { ALG_OP_DECRYPT };

    c = libc::CMSG_NXTHDR(msg, c);
    if c.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no cmsg"));
    }
    (*c).cmsg_level = SOL_ALG;
    (*c).cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    (*c).cmsg_len = libc::CMSG_LEN(4) as _;
    *libc::CMSG_DATA(c).cast::<u32>() = assoc;

    c = libc::CMSG_NXTHDR(msg, c);
    if c.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no cmsg"));
    }
    (*c).cmsg_level = SOL_ALG;
    (*c).cmsg_type = ALG_SET_IV;
    (*c).cmsg_len = libc::CMSG_LEN(4 + 12) as _;
    let iv = libc::CMSG_DATA(c);
    // struct af_alg_iv { __u32 ivlen; __u8 iv[]; }
    iv.cast::<u32>().write_unaligned(12);
    core::ptr::copy_nonoverlapping(nonce.as_ptr(), iv.add(4), 12);
    }
    Ok(())
}

/// Collect the kernel's `aad || (pt-space)` into `buf` (and the tag when
/// encrypting) with a single recvmsg whose iovs total exactly the output
/// length — see the module docs for why exact is not negotiable.
fn recv_payload(fd: RawFd, aad_len: usize, buf: &mut [u8], tag: Option<&mut [u8]>) -> io::Result<()> {
    let mut tag = tag;
    let tag_len = tag.as_ref().map_or(0, |t| t.len());
    let total = aad_len + buf.len() + tag_len;

    if aad_len <= STACK_AAD {
        // The AAD echo lands in a scratch prefix of the first iov; ct (or
        // pt) goes straight into buf, the tag straight into its slot.
        let mut echo = [0u8; STACK_AAD];
        let mut dummy = [0u8; 1];
        let mut iov = [libc::iovec { iov_base: core::ptr::null_mut(), iov_len: 0 }; 3];
        let mut n = 0;
        push_iov(&mut iov, &mut n, &mut echo[..aad_len]);
        push_iov(&mut iov, &mut n, buf);
        if let Some(t) = tag.as_deref_mut() {
            push_iov(&mut iov, &mut n, t);
        }
        if n == 0 {
            // Zero-length output: decrypting an empty record with no AAD.
            // An empty iov list makes `aead_recvmsg`'s
            // `while (msg_data_left(msg))` skip the cipher entirely, which
            // leaves the TX data queued and poisons the *next* sendmsg with
            // EINVAL. One dummy byte forces exactly one pass; the kernel
            // caps extraction at outlen=0 (`usedpages < outlen` is false
            // and get_rsgl extracts nothing), writes nothing into it, and
            // returns 0 — which is exactly `total`.
            iov[0] = libc::iovec {
                iov_base: dummy.as_mut_ptr().cast(),
                iov_len: 1,
            };
            n = 1;
        }
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = n as _;
        recv_exact(fd, &mut msg, total)?;
        return Ok(());
    }

    // Wide AAD: one contiguous block, then one copy out of it.
    let mut heap = vec![0u8; total];
    let iov = [libc::iovec {
        iov_base: heap.as_mut_ptr().cast(),
        iov_len: total,
    }];
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1 as _;
    recv_exact(fd, &mut msg, total)?;
    buf.copy_from_slice(&heap[aad_len..aad_len + buf.len()]);
    if let Some(t) = tag.as_mut() {
        t.copy_from_slice(&heap[aad_len + buf.len()..]);
    }
    Ok(())
}

fn recv_exact(fd: RawFd, msg: &mut libc::msghdr, expect: usize) -> io::Result<()> {
    loop {
        let n = unsafe { libc::recvmsg(fd, msg, 0) };
        if n >= 0 {
            return if n as usize == expect {
                Ok(())
            } else {
                // Can only happen if the kernel returned a short pass, which
                // the exact iov total rules out; treat it as a failure so a
                // wrong assumption surfaces as a dropped connection, never
                // as silent garbage.
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short afalg recvmsg"))
            };
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Pick the backend for this process: self-test against RustCrypto, then
/// race the software path at the record sizes the proxy actually seals.
/// Runs once, before the first `Gcm::new` returns.
fn calibrate() -> usize {
    if matches!(std::env::var("TACHYON_AF_ALG").as_deref(), Ok("0") | Ok("off")) {
        return 0;
    }
    if matches!(std::env::var("TACHYON_AF_ALG").as_deref(), Ok("1") | Ok("on") | Ok("force")) {
        // Testing valve: route every non-empty payload through the kernel
        // even when the software cipher would have won the race, so the
        // whole test suite runs on `Gcm::Alg`. If AF_ALG is unavailable the
        // socket simply fails to open and `Gcm::new` stays on software.
        return 1;
    }

    let key = [0x42u8; 16];
    if !self_test() {
        return 0;
    }
    // Threshold 0 = every op goes to the kernel, which is the point here.
    let alg = match AfalgGcm::new(&key, 0) {
        Ok(a) => a,
        Err(_) => return 0,
    };

    let sw = &alg.sw;
    let nonce = [7u8; 12];
    let aad = [0x11u8; 16];
    // Ascending record sizes: the first one where the kernel wins becomes
    // the cutoff; nothing smaller ever goes to it. Iterations are tuned so
    // the whole calibration stays in the low milliseconds — it runs on the
    // first connection of a process.
    for &(size, iters) in &[(256usize, 1500u32), (1024, 800), (1440, 600), (4096, 300), (16384, 150)] {
        let mut buf = vec![0x5Au8; size];

        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            let tag = alg.seal(&nonce, &aad, &mut buf);
            core::hint::black_box(tag);
        }
        let t_alg = t0.elapsed();

        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            let t = sw.seal(&nonce, &aad, &mut buf);
            core::hint::black_box(t);
        }
        let t_sw = t0.elapsed();

        if t_alg <= t_sw {
            return size;
        }
    }
    0
}

/// Known-answer, roundtrip and corruption checks against the RustCrypto
/// oracle — both key sizes, AAD under and over the stack threshold (the two
/// recv layouts), a corrupted tag, a wrong nonce. If the kernel disagrees on
/// a single byte (wrong echo layout, wrong iv, wrong tag) the backend stays
/// off for the whole process.
fn self_test() -> bool {
    for key in [&[0x42u8; 16][..], &[0x43u8; 32][..]] {
        let alg = match AfalgGcm::new(key, 0) {
            Ok(a) => a,
            Err(_) => return false,
        };
        let nonce = [7u8; 12];
        let plain = *b"the quick brown fox jumps";
        for aad in [&b"wintertide"[..], &[0xA5u8; 200][..]] {
            let mut expect = plain;
            let want_tag = oracle_seal(key, &nonce, aad, &mut expect);

            let mut buf = plain;
            let got_tag = alg.seal(&nonce, aad, &mut buf);
            if buf != expect || got_tag != want_tag {
                return false;
            }
            if !alg.open(&nonce, aad, &mut buf, &want_tag) || buf != plain {
                return false;
            }

            // Corrupted tag: rejected, and nothing of the plaintext stays.
            let mut bad = want_tag;
            bad[0] ^= 1;
            let mut buf2 = expect;
            if alg.open(&nonce, aad, &mut buf2, &bad) || buf2.iter().any(|&b| b != 0) {
                return false;
            }

            // Wrong nonce: rejected too — GCM's tag covers it.
            let mut buf3 = expect;
            let mut nonce2 = nonce;
            nonce2[11] ^= 1;
            if alg.open(&nonce2, aad, &mut buf3, &want_tag) {
                return false;
            }
        }
    }
    true
}

/// The oracle: RustCrypto on the same key. Any layout mistake in the kernel
/// path shows up as a mismatch here.
fn oracle_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    let nonce = GenericArray::from_slice(nonce);
    match key.len() {
        16 => Aes128Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(nonce, aad, buf)
            .expect("oracle seal")
            .into(),
        _ => Aes256Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(nonce, aad, buf)
            .expect("oracle seal")
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// An always-kernel instance (`threshold = 0`), or `None` when the
    /// environment has no `AF_ALG` — Docker's default seccomp profile blocks
    /// the socket call — in which case the tests pass trivially.
    fn alg(key: &[u8]) -> Option<AfalgGcm> {
        match AfalgGcm::new(key, 0) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("afalg: unavailable ({e}), skipping kernel-path tests");
                None
            }
        }
    }

    #[test]
    fn roundtrip_shapes() {
        let Some(a) = alg(&[9u8; 16]) else {
            return;
        };
        let nonce = [3u8; 12];
        for &(pt_len, aad_len) in &[
            (0usize, 0usize),
            (1, 0),
            (15, 13),
            (16, 8),
            (17, 64),
            (1440, 18),
            (16384, 5),
            (100, 200),
        ] {
            let aad = vec![0x5Cu8; aad_len];
            let plain: Vec<u8> = (0..pt_len).map(|i| (i.wrapping_mul(7) + 1) as u8).collect();
            let mut buf = plain.clone();
            let tag = a.seal(&nonce, &aad, &mut buf);
            if pt_len > 0 {
                assert_ne!(buf, plain, "ciphertext must differ, pt_len={pt_len}");
            }
            assert!(
                a.open(&nonce, &aad, &mut buf, &tag),
                "open failed pt_len={pt_len} aad_len={aad_len}"
            );
            assert_eq!(buf, plain, "roundtrip mismatch pt_len={pt_len} aad_len={aad_len}");
        }
    }

    #[test]
    fn aes256_roundtrip() {
        let Some(a) = alg(&[9u8; 32]) else {
            return;
        };
        let nonce = [4u8; 12];
        let aad = b"tls13 header";
        let mut buf = vec![0x77u8; 4096];
        let tag = a.seal(&nonce, aad, &mut buf);
        assert!(a.open(&nonce, aad, &mut buf, &tag));
        assert_eq!(buf, vec![0x77u8; 4096]);
    }

    /// The kernel and the software cipher must be interchangeable: same
    /// bytes out, and each accepts what the other produced.
    #[test]
    fn kernel_matches_software() {
        let Some(a) = alg(&[0x77u8; 16]) else {
            return;
        };
        let sw = crate::fastgcm::Gcm::new_software(&[0x77u8; 16]);
        let nonce = [5u8; 12];
        for &(pt_len, aad_len) in &[(1usize, 0usize), (1440, 18), (4096, 64), (16384, 5)] {
            let aad = vec![0x33u8; aad_len];
            let plain: Vec<u8> = (0..pt_len).map(|i| (i.wrapping_mul(31) + 9) as u8).collect();

            let mut from_k = plain.clone();
            let mut from_s = plain.clone();
            let tag_k = a.seal(&nonce, &aad, &mut from_k);
            let tag_s = sw.seal(&nonce, &aad, &mut from_s);
            assert_eq!(tag_k, tag_s, "tag mismatch pt_len={pt_len}");
            assert_eq!(from_k, from_s, "ciphertext mismatch pt_len={pt_len}");

            let mut back = from_s;
            assert!(a.open(&nonce, &aad, &mut back, &tag_s));
            assert_eq!(back, plain);
        }
    }

    #[test]
    fn corruption_rejected() {
        let Some(a) = alg(&[0x77u8; 16]) else {
            return;
        };
        let nonce = [6u8; 12];
        let aad = b"assoc";
        let mut buf = vec![0xABu8; 1440];
        let tag = a.seal(&nonce, aad, &mut buf);

        // Flip a bit in the tag.
        let mut bad_tag = tag;
        bad_tag[3] ^= 0x40;
        let mut b1 = buf.clone();
        assert!(!a.open(&nonce, aad, &mut b1, &bad_tag));
        assert!(b1.iter().all(|&x| x == 0), "failed open must leave no plaintext");

        // Flip a bit in the ciphertext.
        let mut bad_ct = buf.clone();
        bad_ct[700] ^= 0x01;
        assert!(!a.open(&nonce, aad, &mut bad_ct, &tag));
        assert!(bad_ct.iter().all(|&x| x == 0));
    }

    /// Any answer from the process-wide probe is a legal answer; this just
    /// proves it terminates and caches.
    #[test]
    fn threshold_probe() {
        let a = threshold();
        let b = threshold();
        assert_eq!(a, b);
    }
}
