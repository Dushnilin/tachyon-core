//! The REALITY client, as far as it lives inside the ClientHello (ADR-0004).
//!
//! A REALITY client looks like a browser and proves itself with a key the server
//! already knows. The details come from `XTLS/Xray-core`
//! `transport/internet/reality/reality.go`, which is what the servers implement.
//! They are also the kind of detail that has to be measured against a real
//! server rather than reasoned about: the sealing below is checked here for the
//! properties it must have, and the end-to-end check -- our client accepted by
//! the reference's REALITY server -- is the gate that says the constants are
//! right.
//!
//! Three pieces, all of them in the hello itself:
//!
//! * the **session id** carries a version triple, the current time and the short
//!   id, and its first 16 bytes are then sealed so that only a server holding
//!   the private key for the public key we named can read them back;
//! * the **auth key** is what that seal uses, derived from the X25519 exchange
//!   with the server's key;
//! * the **public key** is named in the config, and is the server's.

use std::io;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::tls13::{self, Hash};

/// The version triple REALITY clients write. The first byte is the major version
/// and the second the minor; the third is a build number the servers ignore.
pub const VERSION: [u8; 3] = [26, 3, 27];

/// Where a field sits inside a ClientHello *record*: the 5-byte record header
/// and the 4-byte handshake header are both counted, which is why the same
/// number is 39 in xray, where the record is not part of the message.
const RECORD_HEADER: usize = 5 + 4;
/// 2 bytes of client version, then 32 of random, then 1 of session id length.
const RANDOM_OFFSET: usize = RECORD_HEADER + 2;
/// The session id: 32 bytes of compat space right after the random.
pub const SESSION_ID_OFFSET: usize = RANDOM_OFFSET + 32 + 1;
/// The nonce the seal uses: the last 12 bytes of the hello's own random.
const NONCE_OFFSET: usize = RANDOM_OFFSET + 20;
const NONCE_LEN: usize = 12;

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The 32-byte session id before it is sealed: version, time, short id.
///
/// `[3]` stays zero and `[16..32]` stays zero; the sealed 16 bytes overwrite the
/// first half afterwards, which is why the short id is placed at `[8..16]` and
/// not at the front.
pub fn session_id(short_id: &[u8], unix_time: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..3].copy_from_slice(&VERSION);
    id[4..8].copy_from_slice(&unix_time.to_be_bytes());
    let take = short_id.len().min(8);
    id[8..8 + take].copy_from_slice(&short_id[..take]);
    id
}

/// The auth key: the X25519 shared secret with the server's key, through
/// HKDF-SHA256 with the hello's own first 20 random bytes as the salt and
/// "REALITY" as the info.
pub fn auth_key(shared_secret: &[u8], random: &[u8; 32]) -> [u8; 32] {
    let derived = tls13::hkdf(Hash::Sha256, &random[..20], shared_secret, b"REALITY", 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    key
}

/// Seal a built ClientHello in place: the first 16 bytes of its session id are
/// replaced by an AES-256-GCM seal of themselves, and the whole 32-byte result
/// is written back over the original session id.
///
/// The additional authenticated data is the entire hello with those 16 bytes
/// zeroed, so the seal also covers everything else about the hello: a middlebox
/// that changes the SNI or the extensions breaks it, which is the point.
pub fn seal_hello(hello: &mut [u8], auth_key: &[u8; 32]) -> io::Result<()> {
    if hello.len() < SESSION_ID_OFFSET + 32 {
        return Err(bad("the hello is too short to carry a session id"));
    }
    let length = hello[SESSION_ID_OFFSET - 1] as usize;
    if length != 32 {
        return Err(bad("a REALITY session id is 32 bytes of compat space"));
    }
    let start = SESSION_ID_OFFSET;
    let end = start + 32;
    let nonce_bytes: [u8; NONCE_LEN] = hello
        .get(NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN)
        .ok_or_else(|| bad("the hello has no random for a nonce"))?
        .try_into()
        .expect("12 bytes");

    // The AAD is the hello with the *whole* session id zeroed -- all 32 bytes,
    // not just the sealed half. The server can only rebuild it from the hello it
    // received, and there the id is ciphertext; the plaintext's own second half
    // is zeros, which is what the server checks after opening it.
    let mut aad = hello.to_vec();
    aad[start..end].fill(0);

    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|_| bad("bad auth key"))?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &hello[start..start + 16],
                aad: &aad,
            },
        )
        .map_err(|_| err_seal())?;
    if sealed.len() != 32 {
        return Err(bad("the seal is not the size the session id wants"));
    }
    hello[start..end].copy_from_slice(&sealed);
    Ok(())
}

/// Open a sealed session id, for the check that it can be read back. The client
/// never does this; the test that the seal round trips does.
pub fn open_session_id(hello: &[u8], auth_key: &[u8; 32]) -> io::Result<[u8; 16]> {
    if hello.len() < SESSION_ID_OFFSET + 32 {
        return Err(bad("the hello is too short to carry a session id"));
    }
    let nonce_bytes: [u8; NONCE_LEN] = hello
        .get(NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN)
        .ok_or_else(|| bad("the hello has no random for a nonce"))?
        .try_into()
        .expect("12 bytes");
    let mut aad = hello.to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].fill(0);
    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|_| bad("bad auth key"))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
                aad: &aad,
            },
        )
        .map_err(|_| bad("the session id does not open under that auth key"))?;
    plain
        .try_into()
        .map_err(|_| bad("the opened session id is not 16 bytes"))
}

fn err_seal() -> io::Error {
    bad("the session id could not be sealed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprints;
    use crate::hello;
    use crate::keyshare::{Shares, X25519MLKEM768};

    /// A hello built from the chrome table, which is what a REALITY client
    /// presents: the browser's fingerprint, with a session id to be sealed.
    fn chrome_hello() -> Vec<u8> {
        let template = fingerprints::by_name("chrome").expect("a chrome table");
        let key_share = template
            .extensions
            .iter()
            .find_map(|e| match e {
                hello::Ext::KeyShare(body) => Some(body.clone()),
                _ => None,
            })
            .expect("the chrome key share");
        let shares = Shares::for_body(&key_share).expect("our keys");
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).expect("entropy");
        let sni = "www.gstatic.com";
        let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let id = session_id(b"\x12\x34\xab\xcd", 1_760_000_000);
        hello::build(&template, &random, &id, sni, &alpn, Some(&shares)).expect("build the hello")
    }

    #[test]
    fn the_session_id_carries_the_version_the_time_and_the_short_id() {
        let id = session_id(b"\x12\x34\xab\xcd", 1_760_000_000);
        assert_eq!(&id[..3], &VERSION);
        assert_eq!(id[3], 0, "the fourth byte is zero");
        assert_eq!(&id[4..8], &1_760_000_000u32.to_be_bytes());
        assert_eq!(&id[8..12], b"\x12\x34\xab\xcd");
        assert!(id[12..].iter().all(|b| *b == 0), "the rest is for the seal");
    }

    #[test]
    fn a_short_id_longer_than_eight_bytes_is_truncated_not_rejected() {
        let id = session_id(&[9u8; 16], 1);
        assert_eq!(&id[8..16], &[9u8; 8]);
    }

    /// The seal round trips under the same key, and covers the whole hello: a
    /// middlebox that changes anything else about it leaves a session id the
    /// server cannot read.
    #[test]
    fn the_seal_covers_the_whole_hello() {
        let mut hello_bytes = chrome_hello();
        let key = [7u8; 32];
        let before = hello_bytes.clone();
        seal_hello(&mut hello_bytes, &key).expect("seal");
        assert_ne!(&hello_bytes[..], &before[..], "the session id changed");
        assert_eq!(hello_bytes.len(), before.len(), "and nothing else did");

        let opened = open_session_id(&hello_bytes, &key).expect("open under the same key");
        let plaintext = &before[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 16];
        assert_eq!(&opened[..], plaintext, "the first 16 bytes come back");

        // one changed byte anywhere in the hello and it no longer opens
        for at in [0usize, 40, 100, hello_bytes.len() - 1] {
            let mut broken = hello_bytes.clone();
            broken[at] ^= 0x01;
            assert!(
                open_session_id(&broken, &key).is_err(),
                "a changed byte at {at} still opened"
            );
        }
        // and the wrong key does not open it either
        assert!(open_session_id(&hello_bytes, &[8u8; 32]).is_err());
    }

    /// The nonce comes from the hello's own random, so two hellos with different
    /// randomness never produce the same session id.
    #[test]
    fn two_hellos_do_not_seal_to_the_same_session_id() {
        let mut a = chrome_hello();
        let mut b = chrome_hello();
        let key = [3u8; 32];
        seal_hello(&mut a, &key).expect("seal");
        seal_hello(&mut b, &key).expect("seal");
        assert_ne!(
            &a[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
            &b[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32]
        );
    }

    /// The auth key is the shared secret under a KDF, so it is 32 bytes that
    /// depend on both the secret and the hello's random -- and a different
    /// random gives a different key, which is what binds the seal to this hello.
    #[test]
    fn the_auth_key_depends_on_the_secret_and_the_random() {
        let random = [1u8; 32];
        let key = auth_key(b"a shared secret", &random);
        assert_eq!(key.len(), 32);
        assert_ne!(key, auth_key(b"another secret", &random));
        assert_ne!(key, auth_key(b"a shared secret", &[2u8; 32]));
    }

    /// A hello whose session id is not the 32 bytes of compat space REALITY
    /// needs is refused rather than sealed into the wrong place.
    #[test]
    fn a_hello_without_a_full_session_id_is_refused() {
        let template = fingerprints::by_name("chrome").expect("a chrome table");
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).expect("entropy");
        let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let short = session_id(b"\x00", 1);
        let record = hello::build(
            &template,
            &random,
            &short[..16],
            "www.gstatic.com",
            &alpn,
            None,
        )
        .expect("build");
        let mut record = record;
        assert!(seal_hello(&mut record, &[1u8; 32]).is_err());
    }

    /// The REALITY secret is the X25519 half of the exchange we are about to
    /// offer, so both sides must arrive at the same 32 bytes: ours from the
    /// hybrid we send, the server's from the X25519 key at the tail of that
    /// same share.
    #[test]
    fn the_reality_secret_is_the_x25519_half_of_the_hybrid() {
        let template = fingerprints::by_name("chrome").expect("a chrome table");
        let key_share = template
            .extensions
            .iter()
            .find_map(|e| match e {
                hello::Ext::KeyShare(body) => Some(body.clone()),
                _ => None,
            })
            .expect("the chrome key share");
        let shares = Shares::for_body(&key_share).expect("our keys");
        let offered = shares.public(X25519MLKEM768).expect("the hybrid share");
        assert_eq!(offered.len(), 1216, "ek(1184) then the X25519 key(32)");
        let server = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let server_public: [u8; 32] = *x25519_dalek::PublicKey::from(&server).as_bytes();
        let ours = shares
            .reality_secret(&server_public)
            .expect("the X25519 half of the hybrid");
        // the server's side, from the very key we put on the wire
        let on_wire: [u8; 32] = offered[1184..].try_into().expect("32 bytes");
        let theirs = server.diffie_hellman(&on_wire.into());
        assert_eq!(&ours[..], theirs.as_bytes());
    }
}
