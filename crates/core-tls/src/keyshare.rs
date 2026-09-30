//! The keys behind a ClientHello's `key_share` extension.
//!
//! The vendored fingerprint tables carry a real client's key share so every
//! other byte of the hello matches, but a captured key is useless to us: the
//! server picks a group and we have to finish the exchange with it. So the
//! *group list* comes from the capture and the share data comes from keys
//! generated here.
//!
//! The hybrid layout is the one the reference client actually sends, measured
//! from its captures and confirmed against refraction-networking/utls
//! `key_schedule.go`: for `X25519MLKEM768` the client share is the ML-KEM-768
//! **encapsulation key** (1184 bytes) followed by the X25519 share (32), and
//! the server answers with the ML-KEM-768 **ciphertext** (1088) followed by its
//! X25519 share (32). The shared secret is the ML-KEM secret then the X25519
//! one, in that order.
//!
//! Chrome and Firefox also offer a second, plain X25519 share, and it is a
//! *different* key from the hybrid's X25519 half -- utls generates a separate
//! one "in line with Chrome" -- so we do the same.

use std::io;

use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};

pub const X25519MLKEM768: u16 = 0x11ec;
pub const X25519: u16 = 0x001d;
pub const SECP256R1: u16 = 0x0017;

/// ML-KEM-768 encapsulation key / ciphertext, the two sizes a share can hold.
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
const X_LEN: usize = 32;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A GREASE value (RFC 8701): reserved, and a fresh one per handshake.
pub fn is_grease(value: u16) -> bool {
    (value & 0x0f) == 0x0a && (value >> 8) as u8 == (value & 0xff) as u8
}

/// A fresh GREASE value the way BoringSSL picks one: a random byte repeated,
/// with the low nibble set.
///
/// `used` collects the values already written into this hello, because Chrome
/// sends *two* GREASE extensions and a repeated id is a duplicate extension,
/// which every server rejects. A failure to read entropy would leave every
/// handshake with the same GREASE, which is legal, so it is not worth failing a
/// connection over; the 16 reserved values cannot all be taken by one hello, so
/// neither can the retries run out.
pub fn unique_grease(used: &mut Vec<u16>) -> u16 {
    for _ in 0..16 {
        let mut byte = [0u8; 1];
        let _ = RngCore::try_fill_bytes(&mut OsRng, &mut byte);
        // the byte's *high* nibble, repeated, with the low one set to 0xa
        let v = (byte[0] & 0xf0) as u16;
        let value = (v << 8 | v) | 0x0a0a;
        if !used.contains(&value) {
            used.push(value);
            return value;
        }
    }
    0x0a0a
}

/// The `(group, key_exchange)` entries of a `key_share` extension body.
pub fn entries(body: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let list_len = body
        .get(..2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .ok_or_else(|| err("short key_share"))?;
    let end = 2 + list_len;
    if body.len() < end {
        return Err(err("short key_share list"));
    }
    let mut out = Vec::new();
    let mut off = 2;
    while off + 4 <= end {
        let group = u16::from_be_bytes([body[off], body[off + 1]]);
        let key_len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        off += 4;
        let key = body
            .get(off..off + key_len)
            .ok_or_else(|| err("short key"))?;
        off += key_len;
        out.push((group, key));
    }
    Ok(out)
}

struct Hybrid {
    /// kept so the test can play the server's side; a client never needs it
    #[allow(dead_code)]
    ek: EncapsulationKey<MlKem768Params>,
    dk: DecapsulationKey<MlKem768Params>,
    x: x25519_dalek::StaticSecret,
}

/// One key per group a template's `key_share` lists, ready to be written into a
/// hello and to finish the exchange the server picks.
pub struct Shares {
    /// group -> our public share, in the order the template lists them
    entries: Vec<(u16, Vec<u8>)>,
    hybrid: Option<Hybrid>,
    x25519: Option<x25519_dalek::StaticSecret>,
    p256: Option<p256::ecdh::EphemeralSecret>,
}

impl Shares {
    /// Generate a share for every non-GREASE group in a captured `key_share`
    /// body. A group we have no key for is an error rather than a silent
    /// fallback: offering a share we cannot complete would fail the handshake
    /// later, further from the cause.
    pub fn for_body(body: &[u8]) -> io::Result<Self> {
        let mut shares = Shares {
            entries: Vec::new(),
            hybrid: None,
            x25519: None,
            p256: None,
        };
        for (group, _) in entries(body)? {
            if is_grease(group) {
                continue;
            }
            let share = match group {
                X25519MLKEM768 => {
                    let (dk, ek) = <MlKem768 as KemCore>::generate(&mut OsRng);
                    let x = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                    let mut share = Vec::with_capacity(MLKEM768_EK_LEN + X_LEN);
                    share.extend_from_slice(ek.as_bytes().as_slice());
                    share.extend_from_slice(x25519_dalek::PublicKey::from(&x).as_bytes());
                    shares.hybrid = Some(Hybrid { ek, dk, x });
                    share
                }
                X25519 => {
                    let x = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                    let share = *x25519_dalek::PublicKey::from(&x).as_bytes();
                    shares.x25519 = Some(x);
                    share.to_vec()
                }
                SECP256R1 => {
                    let secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
                    let share = secret
                        .public_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec();
                    shares.p256 = Some(secret);
                    share
                }
                other => return Err(err(format!("no key for key share group 0x{other:04x}"))),
            };
            shares.entries.push((group, share));
        }
        Ok(shares)
    }

    /// The `key_share` body to write: the template's group list in the
    /// template's order, with our data in place of the captured data. A GREASE
    /// group keeps its captured data (a byte of noise) and gets a fresh reserved
    /// id, as BoringSSL does. `grease_used` carries the values the rest of the
    /// hello already spent, so two GREASE ids cannot collide.
    pub fn body(&self, template: &[u8], grease_used: &mut Vec<u16>) -> io::Result<Vec<u8>> {
        let mut list = Vec::new();
        for (group, data) in entries(template)? {
            let grease = is_grease(group);
            let id = if grease {
                unique_grease(grease_used)
            } else {
                group
            };
            let share: &[u8] = if grease {
                data
            } else {
                self.entries
                    .iter()
                    .find(|(g, _)| *g == group)
                    .map(|(_, s)| s.as_slice())
                    .ok_or_else(|| err(format!("no key for key share group 0x{group:04x}")))?
            };
            list.extend_from_slice(&id.to_be_bytes());
            list.extend_from_slice(&(share.len() as u16).to_be_bytes());
            list.extend_from_slice(share);
        }
        if list.len() > u16::MAX as usize {
            return Err(err("key share list too long"));
        }
        let mut body = Vec::with_capacity(list.len() + 2);
        body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        body.extend_from_slice(&list);
        Ok(body)
    }

    /// The REALITY shared secret with a server's X25519 key: the X25519 half of
    /// the exchange, not the ML-KEM one. A REALITY server proves itself with an
    /// ed25519 key that has nothing to do with ML-KEM, so the classical half is
    /// the one both sides have to agree on.
    ///
    /// *Which* X25519 half is the part that has to match the server. It scans
    /// our key shares and takes the first plain X25519, falling back to the tail
    /// of the hybrid -- so with a browser-shaped hello, where the two are
    /// deliberately different keys, the hybrid's half is the one the server will
    /// not use. Picking the hybrid first would produce an auth key the server
    /// cannot derive, and it would say so by quietly proxying us to its decoy
    /// site instead of failing.
    pub fn reality_secret(&self, server_key: &[u8; 32]) -> io::Result<[u8; 32]> {
        let peer = x25519_dalek::PublicKey::from(*server_key);
        let secret = match self.reality_ecdhe() {
            Some(x) => x.diffie_hellman(&peer),
            None => return Err(err("no X25519 key was offered")),
        };
        if !secret.was_contributory() {
            return Err(err("the REALITY server key is a low-order point"));
        }
        Ok(secret.to_bytes())
    }

    /// The key the server will use for REALITY: the plain share when the hello
    /// offers one, the hybrid's X25519 half otherwise.
    fn reality_ecdhe(&self) -> Option<&x25519_dalek::StaticSecret> {
        self.x25519
            .as_ref()
            .or_else(|| self.hybrid.as_ref().map(|h| &h.x))
    }

    /// The public share we wrote for `group`, if we offered it.
    pub fn public(&self, group: u16) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(g, _)| *g == group)
            .map(|(_, share)| share.as_slice())
    }

    /// The shared secret for the group the server chose, in the order RFC 8446
    /// and draft-ietf-tls-ecdhe-mlkem require: ML-KEM first, then X25519.
    pub fn complete(&self, group: u16, peer: &[u8]) -> io::Result<Vec<u8>> {
        match group {
            X25519MLKEM768 => {
                let hybrid = self
                    .hybrid
                    .as_ref()
                    .ok_or_else(|| err("the hybrid group was never offered"))?;
                if peer.len() != MLKEM768_CT_LEN + X_LEN {
                    return Err(err("server hybrid share is not 1120 bytes"));
                }
                let ciphertext: [u8; MLKEM768_CT_LEN] = peer[..MLKEM768_CT_LEN]
                    .try_into()
                    .expect("length checked above");
                let pq = hybrid
                    .dk
                    .decapsulate(&ciphertext.into())
                    .map_err(|()| err("ml-kem decapsulation rejected"))?;
                let x = x25519_secret(&hybrid.x, &peer[MLKEM768_CT_LEN..])?;
                Ok([pq.as_slice(), &x].concat())
            }
            X25519 => {
                let secret = self
                    .x25519
                    .as_ref()
                    .ok_or_else(|| err("the X25519 group was never offered"))?;
                x25519_secret(secret, peer)
            }
            SECP256R1 => {
                let secret = self
                    .p256
                    .as_ref()
                    .ok_or_else(|| err("the secp256r1 group was never offered"))?;
                let peer = p256::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| err("bad secp256r1 point"))?;
                Ok(secret.diffie_hellman(&peer).raw_secret_bytes().to_vec())
            }
            other => Err(err(format!("no key for group 0x{other:04x}"))),
        }
    }
}

fn x25519_secret(secret: &x25519_dalek::StaticSecret, peer: &[u8]) -> io::Result<Vec<u8>> {
    let peer: [u8; X_LEN] = peer.try_into().map_err(|_| err("bad X25519 share"))?;
    let shared = secret.diffie_hellman(&peer.into());
    if !shared.was_contributory() {
        return Err(err("X25519 share is a low-order point"));
    }
    Ok(shared.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Encapsulate;
    use x25519_dalek::StaticSecret;

    fn body_of(groups: &[(u16, usize)]) -> Vec<u8> {
        let mut list = Vec::new();
        for (group, len) in groups {
            list.extend_from_slice(&group.to_be_bytes());
            list.extend_from_slice(&(*len as u16).to_be_bytes());
            list.extend_from_slice(&vec![0u8; *len]);
        }
        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        body
    }

    /// The chrome shape: GREASE, the hybrid, plain X25519.
    fn chrome_template() -> Vec<u8> {
        body_of(&[
            (0x4a4a, 1),
            (X25519MLKEM768, MLKEM768_EK_LEN + X_LEN),
            (X25519, X_LEN),
        ])
    }

    #[test]
    fn the_built_body_keeps_the_template_shape() {
        let template = chrome_template();
        let shares = Shares::for_body(&template).expect("shares");
        let body = shares.body(&template, &mut Vec::new()).expect("body");

        // the same length, the same groups in the same order
        assert_eq!(body.len(), template.len());
        let groups: Vec<u16> = entries(&body).unwrap().iter().map(|(g, _)| *g).collect();
        assert_eq!(groups.len(), 3);
        assert!(is_grease(groups[0]), "the GREASE group stays GREASE");
        assert_eq!(groups[1], X25519MLKEM768);
        assert_eq!(groups[2], X25519);
        let lens: Vec<usize> = entries(&body)
            .unwrap()
            .iter()
            .map(|(_, k)| k.len())
            .collect();
        assert_eq!(lens, vec![1, MLKEM768_EK_LEN + X_LEN, X_LEN]);
    }

    #[test]
    fn the_plain_x25519_share_is_not_the_hybrids_x25519() {
        // Chrome uses a separate key for the standalone share, and so do we:
        // reusing one key for both is the fingerprint of a client that copied
        // the standard library instead of the browser.
        let template = chrome_template();
        let shares = Shares::for_body(&template).expect("shares");
        let body = shares.body(&template, &mut Vec::new()).expect("body");
        let entries = entries(&body).unwrap();
        let hybrid_x = &entries[1].1[MLKEM768_EK_LEN..];
        let plain_x = entries[2].1;
        assert_ne!(hybrid_x, plain_x);
    }

    #[test]
    fn the_hybrid_secret_is_mlkem_then_x25519() {
        let template = chrome_template();
        let shares = Shares::for_body(&template).expect("shares");
        let hybrid = shares.hybrid.as_ref().expect("hybrid");

        // the server's side, against the very key the client offered
        let peer_x = StaticSecret::random_from_rng(OsRng);
        let peer_x_pub = *x25519_dalek::PublicKey::from(&peer_x).as_bytes();
        let (ciphertext, server_pq) = hybrid.ek.encapsulate(&mut OsRng).expect("encapsulate");
        let server_share = [ciphertext.as_slice(), &peer_x_pub[..]].concat();
        let server_x = peer_x.diffie_hellman(&x25519_dalek::PublicKey::from(&hybrid.x));
        let expected = [server_pq.as_slice(), server_x.as_bytes()].concat();

        assert_eq!(
            shares
                .complete(X25519MLKEM768, &server_share)
                .expect("secret"),
            expected
        );
    }

    /// The secret a REALITY handshake is keyed on comes from the *plain* X25519
    /// share when the hello offers one, because that is the share the server
    /// picks. The hybrid's own X25519 half is a different key and would produce
    /// an auth key the server cannot derive.
    #[test]
    fn the_reality_secret_prefers_the_plain_share() {
        let template = chrome_template();
        let shares = Shares::for_body(&template).expect("shares");
        let server = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let server_public: [u8; 32] = *x25519_dalek::PublicKey::from(&server).as_bytes();
        let ours = shares.reality_secret(&server_public).expect("a secret");
        let plain: [u8; 32] = shares
            .public(X25519)
            .expect("the plain share")
            .try_into()
            .expect("32 bytes");
        let hybrid_tail: [u8; 32] = shares
            .public(X25519MLKEM768)
            .expect("the hybrid")
            .get(MLKEM768_EK_LEN..)
            .expect("its X25519 tail")
            .try_into()
            .expect("32 bytes");
        assert_eq!(&ours[..], server.diffie_hellman(&plain.into()).as_bytes());
        assert_ne!(
            &ours[..],
            server.diffie_hellman(&hybrid_tail.into()).as_bytes()
        );
    }

    /// With no plain share in the hello, the hybrid's X25519 half is the only one
    /// a server can find, so that is what has to be used.
    #[test]
    fn a_hello_without_a_plain_share_uses_the_hybrids_half() {
        let template = body_of(&[(X25519MLKEM768, MLKEM768_EK_LEN + X_LEN)]);
        let shares = Shares::for_body(&template).expect("shares");
        let server = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let server_public: [u8; 32] = *x25519_dalek::PublicKey::from(&server).as_bytes();
        let ours = shares.reality_secret(&server_public).expect("a secret");
        let tail: [u8; 32] = shares
            .public(X25519MLKEM768)
            .expect("the hybrid")
            .get(MLKEM768_EK_LEN..)
            .expect("its X25519 tail")
            .try_into()
            .expect("32 bytes");
        assert_eq!(&ours[..], server.diffie_hellman(&tail.into()).as_bytes());
    }

    #[test]
    fn a_wrong_length_share_is_rejected() {
        let template = chrome_template();
        let shares = Shares::for_body(&template).expect("shares");
        assert!(shares.complete(X25519MLKEM768, &[0u8; 1121]).is_err());
        assert!(shares.complete(X25519, &[0u8; 31]).is_err());
        assert!(shares.complete(SECP256R1, &[0u8; 65]).is_err());
    }

    #[test]
    fn a_group_we_cannot_answer_is_an_error_at_build_time() {
        let template = body_of(&[(0x0018, 97)]);
        let err = Shares::for_body(&template)
            .err()
            .expect("a group we cannot answer is an error");
        assert!(err.to_string().contains("0x0018"), "{err}");
    }

    /// Chrome sends two GREASE extensions, and a repeated id is a duplicate
    /// extension that every server rejects -- so the draws have to differ.
    #[test]
    fn grease_values_never_repeat_within_one_hello() {
        for _ in 0..64 {
            let mut used = Vec::new();
            let first = unique_grease(&mut used);
            let second = unique_grease(&mut used);
            let third = unique_grease(&mut used);
            assert_ne!(first, second);
            assert_ne!(second, third);
            assert_ne!(first, third);
        }
    }

    #[test]
    fn grease_values_are_the_reserved_shape() {
        for _ in 0..64 {
            let value = unique_grease(&mut Vec::new());
            assert!(is_grease(value), "{value:#06x} is not GREASE");
        }
        for value in [0x0a0a, 0xfafa, 0x1a1a, 0x0a0b, 0x0a00, 0x001d] {
            assert_eq!(
                is_grease(value),
                value == 0x0a0a || value == 0xfafa || value == 0x1a1a
            );
        }
    }
}
