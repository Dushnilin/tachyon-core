//! The TLS 1.3 key schedule (RFC 8446 §7.1) and the record keys it feeds.
//!
//! This is what makes an own handshake possible: everything here is
//! HKDF-SHA256/384, both already in the tree, so the ClientHello can be ours
//! (`super::fingerprints`) without forking anything.
//!
//! The schedule takes a *transcript hash*, not the messages: the handshake
//! layer keeps the running hash anyway, and the RFC prints hashes rather than
//! kilobytes of messages, so that is also what the tests use. Every value
//! below is RFC 8448 §3, the "simple 1-RTT handshake".

use hmac::{Mac, SimpleHmac};
use sha2::{Digest, Sha256, Sha384};

/// Which hash the negotiated suite uses. TLS 1.3 pairs it with the cipher: the
/// SHA-256 suites and the SHA-384 ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    /// The digest length in bytes: 32 for SHA-256, 48 for SHA-384.
    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => {
                let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(key)
                    .expect("hmac takes a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Hash::Sha384 => {
                let mut mac = <SimpleHmac<Sha384> as Mac>::new_from_slice(key)
                    .expect("hmac takes a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// `HKDF-Extract`.
    fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.hmac(salt, ikm)
    }

    /// `HKDF-Expand`.
    fn expand(self, prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(length + self.output_len());
        let mut previous: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while out.len() < length {
            // the two MAC types differ, so each arm finishes on its own
            previous = match self {
                Hash::Sha256 => {
                    let mut mac =
                        <SimpleHmac<Sha256> as Mac>::new_from_slice(prk).expect("any key length");
                    mac.update(&previous);
                    mac.update(info);
                    mac.update(&[counter]);
                    mac.finalize().into_bytes().to_vec()
                }
                Hash::Sha384 => {
                    let mut mac =
                        <SimpleHmac<Sha384> as Mac>::new_from_slice(prk).expect("any key length");
                    mac.update(&previous);
                    mac.update(info);
                    mac.update(&[counter]);
                    mac.finalize().into_bytes().to_vec()
                }
            };
            out.extend_from_slice(&previous);
            counter = counter.wrapping_add(1);
        }
        out.truncate(length);
        out
    }

    /// The empty-string digest every `derived` step hashes.
    fn empty_digest(self) -> Vec<u8> {
        self.digest(&[])
    }
}

/// `HKDF-Expand-Label` (RFC 8446 §7.1): every label carries the `tls13 ` prefix.
pub fn expand_label(
    hash: Hash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut full = Vec::with_capacity(6 + label.len());
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hash.expand(secret, &info, length)
}

/// `Derive-Secret(Secret, Label, Transcript-Hash)`.
/// `HKDF(salt, ikm)` then `HKDF-Expand(info, length)`: RFC 5869 in full, for
/// the one key that is not part of the TLS schedule (REALITY's auth key, which
/// is derived outside it).
pub fn hkdf(hash: Hash, salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    hash.expand(&hash.extract(salt, ikm), info, length)
}

pub fn derive_secret(hash: Hash, secret: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    expand_label(hash, secret, label, transcript, hash.output_len())
}

/// The key and iv for one direction, with the sequence number folded into the
/// nonce (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    pub key: Vec<u8>,
    pub iv: [u8; 12],
}

impl TrafficKeys {
    /// The per-record nonce: the iv with the sequence number XORed into its
    /// tail.
    pub fn nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let start = nonce.len() - 8;
        for (offset, byte) in sequence.to_be_bytes().iter().enumerate() {
            nonce[start + offset] ^= byte;
        }
        nonce
    }
}

/// The key schedule, in the order TLS 1.3 walks it.
#[derive(Debug, Clone)]
pub struct KeySchedule {
    pub hash: Hash,
    early_secret: Vec<u8>,
    handshake_secret: Vec<u8>,
    master_secret: Vec<u8>,
    /// Transcript hash through ServerHello.
    handshake_transcript: Vec<u8>,
    /// Transcript hash through the server's Finished.
    application_transcript: Vec<u8>,
}

impl KeySchedule {
    /// `psk` is the early secret's IKM: zeros when there is no PSK, which is
    /// the only case a proxy client has.
    pub fn new(hash: Hash, psk: &[u8]) -> Self {
        // no PSK means the all-zero IKM of the hash length, which is not the
        // same as an empty message
        let zeros = vec![0u8; hash.output_len()];
        let early_secret = hash.extract(&zeros, if psk.is_empty() { &zeros } else { psk });
        Self {
            hash,
            early_secret,
            handshake_secret: Vec::new(),
            master_secret: Vec::new(),
            handshake_transcript: Vec::new(),
            application_transcript: Vec::new(),
        }
    }

    /// The `derived` secret a later step salts with: `Derive-Secret(secret,
    /// "derived", Hash(""))`.
    fn derived(&self, secret: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, secret, b"derived", &self.hash.empty_digest())
    }

    /// `HKDF-Extract(derived-from-early, ECDHE)`, once ServerHello is in.
    pub fn enter_handshake(&mut self, shared_secret: &[u8], transcript_hash: &[u8]) {
        let derived = self.derived(&self.early_secret);
        self.handshake_secret = self.hash.extract(&derived, shared_secret);
        self.handshake_transcript = transcript_hash.to_vec();
    }

    pub fn client_handshake_traffic(&self) -> Vec<u8> {
        derive_secret(
            self.hash,
            &self.handshake_secret,
            b"c hs traffic",
            &self.handshake_transcript,
        )
    }

    pub fn server_handshake_traffic(&self) -> Vec<u8> {
        derive_secret(
            self.hash,
            &self.handshake_secret,
            b"s hs traffic",
            &self.handshake_transcript,
        )
    }

    /// The master secret, from the transcript through the server's Finished.
    pub fn enter_application(&mut self, transcript_hash: &[u8]) {
        let derived = self.derived(&self.handshake_secret);
        self.master_secret = self
            .hash
            .extract(&derived, &vec![0u8; self.hash.output_len()]);
        self.application_transcript = transcript_hash.to_vec();
    }

    pub fn client_application_traffic(&self) -> Vec<u8> {
        derive_secret(
            self.hash,
            &self.master_secret,
            b"c ap traffic",
            &self.application_transcript,
        )
    }

    /// The server's application secret, which is the one secret that also
    /// covers the client's Finished: the client's comes from the transcript
    /// through the server's Finished, the server's from the transcript through
    /// ours.
    pub fn server_application_traffic_after_client_finished(
        &self,
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        derive_secret(
            self.hash,
            &self.master_secret,
            b"s ap traffic",
            transcript_hash,
        )
    }

    pub fn server_application_traffic(&self) -> Vec<u8> {
        derive_secret(
            self.hash,
            &self.master_secret,
            b"s ap traffic",
            &self.application_transcript,
        )
    }

    /// The `finished` base key for a traffic secret.
    pub fn finished_key(secret: &[u8], hash: Hash) -> Vec<u8> {
        expand_label(hash, secret, b"finished", &[], hash.output_len())
    }

    /// The `Finished` verify data: HMAC of the finished key over the
    /// transcript.
    pub fn finished(secret: &[u8], transcript: &[u8], hash: Hash) -> Vec<u8> {
        hash.hmac(&Self::finished_key(secret, hash), transcript)
    }

    /// The traffic keys for one direction. RFC 8446 fixes the iv at 12 bytes
    /// for every suite, so the length is not a parameter.
    pub fn traffic_keys(secret: &[u8], hash: Hash, key_len: usize) -> TrafficKeys {
        let iv = expand_label(hash, secret, b"iv", &[], 12);
        TrafficKeys {
            key: expand_label(hash, secret, b"key", &[], key_len),
            iv: iv.try_into().expect("TLS 1.3 iv is 12 bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    }

    fn unhex12(text: &str) -> [u8; 12] {
        unhex(text).try_into().expect("12 bytes")
    }

    /// RFC 8448 §3: SHA-256, AES-128-GCM, one X25519 exchange. The RFC prints
    /// the ECDHE result as the handshake IKM, which is what we feed in, and
    /// every transcript as its hash.
    #[test]
    fn rfc8448_secrets_and_traffic_keys() {
        let hash = Hash::Sha256;
        let mut schedule = KeySchedule::new(hash, &[]);
        assert_eq!(
            schedule.early_secret,
            unhex("33ad0a1c607ec03b09e6cd9893680ce2 10adf300aa1f2660e1b22e10f170f92a"),
            "early secret"
        );

        schedule.enter_handshake(
            &unhex("8bd4054fb55b9d63fdfbacf9f04b9f0d 35e6d63f537563efd46272900f89492d"),
            &unhex("860c06edc07858ee8e78f0e7428c58ed d6b43f2ca3e6e95f02ed063cf0e1cad8"),
        );
        assert_eq!(
            schedule.handshake_secret,
            unhex("1dc826e93606aa6fdc0aadc12f741b01 046aa6b99f691ed221a9f0ca043fbeac"),
            "handshake secret"
        );
        let client_hs = schedule.client_handshake_traffic();
        let server_hs = schedule.server_handshake_traffic();
        assert_eq!(
            client_hs,
            unhex("b3eddb126e067f35a780b3abf45e2d8f 3b1a950738f52e9600746a0e27a55a21"),
            "client handshake traffic secret"
        );
        assert_eq!(
            server_hs,
            unhex("b67b7d69 0cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
            "server handshake traffic secret"
        );

        // the `derived` secret, which the master step salts with
        assert_eq!(
            schedule.derived(&schedule.handshake_secret),
            unhex("43de77e0c77713859a944db9db2590b5 3190a65b3ee2e4f12dd7a0bb7ce254b4"),
            "derived from the handshake secret"
        );

        // the handshake write keys the server would use for AES-128-GCM
        let write = KeySchedule::traffic_keys(&server_hs, hash, 16);
        assert_eq!(
            write.key,
            unhex("3fce516009c21727d0f2e4e86ee403bc"),
            "handshake write key"
        );
        assert_eq!(write.iv, unhex12("5d313eb2671276ee13000b30"), "write iv");
        assert_eq!(
            KeySchedule::finished_key(&server_hs, hash),
            unhex("008d3b66f816ea559f96b537e885c3 1fc068bf492c652f01f288a1d8cdc19fc8"),
            "the finished key the label builds"
        );

        // and the client side reads the same keys, so a swap is a failure
        let read = KeySchedule::traffic_keys(&client_hs, hash, 16);
        assert_eq!(
            read.key,
            unhex("dbfaa693d1762c5b666af5d950258d01"),
            "handshake read key"
        );
        assert_eq!(read.iv, unhex12("5bd3c71b836e0b76bb73265f"), "read iv");

        schedule.enter_application(&unhex(
            "9608102a0f1ccc6db6250b7b7e417b1a 000eaada3daae4777a7686c9ff83df13",
        ));
        assert_eq!(
            schedule.client_application_traffic(),
            unhex("9e40646ce79a7f9dc05af8889bce6552 875afa0b06df0087f792ebb7c17504a5"),
            "client application traffic secret"
        );
        let server_ap = schedule.server_application_traffic();
        assert_eq!(
            server_ap,
            unhex("a11af9f05531f856ad47116b45a95032 8204b4f44bfb6b3a4b4f1f3fcb631643"),
            "server application traffic secret"
        );
        let app = KeySchedule::traffic_keys(&server_ap, hash, 16);
        assert_eq!(
            app.key,
            unhex("9f02283b6c9c07efc26bb9f2ac92e356"),
            "application write key"
        );
        assert_eq!(app.iv, unhex12("cf782b88dd83549aadf1e984"), "application iv");

        let client_ap =
            KeySchedule::traffic_keys(&schedule.client_application_traffic(), hash, 16);
        assert_eq!(
            client_ap.key,
            unhex("17422dda596ed5d9acd890e3c63f5051"),
            "application read key (the client writes with this)"
        );
    }

    /// The nonce is the iv with the record sequence in its tail, which is what
    /// keeps records from repeating a (key, nonce) pair.
    #[test]
    fn the_nonce_carries_the_record_sequence() {
        let keys = TrafficKeys {
            key: vec![0; 16],
            iv: unhex12("5d313eb2671276ee13000b30"),
        };
        assert_eq!(keys.nonce(0), keys.iv, "record 0 leaves the iv alone");
        let one = keys.nonce(1);
        assert_eq!(one[11], keys.iv[11] ^ 1);
        assert_eq!(one[..11], keys.iv[..11], "only the tail moves");
        // the counter lands in the last eight bytes, and only there
        let counter = 0x0102_0304_0506_0708u64;
        let big = keys.nonce(counter);
        assert_eq!(&big[..4], &keys.iv[..4], "the head of the iv is untouched");
        for (offset, byte) in counter.to_be_bytes().iter().enumerate() {
            assert_eq!(big[4 + offset], keys.iv[4 + offset] ^ byte);
        }
    }

    /// The SHA-384 suites the fingerprints also offer.
    #[test]
    fn sha384_suites_get_48_byte_secrets() {
        let hash = Hash::Sha384;
        let schedule = KeySchedule::new(hash, &[]);
        assert_eq!(schedule.early_secret.len(), 48);
        let keys = KeySchedule::traffic_keys(&schedule.early_secret, hash, 32);
        assert_eq!(keys.key.len(), 32, "AES-256-GCM key length");
        assert_eq!(keys.iv.len(), 12, "every TLS 1.3 suite has a 12-byte iv");
    }
}
