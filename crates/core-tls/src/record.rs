//! The TLS 1.3 record layer (RFC 8446 §5): the framing around a handshake.
//!
//! Only what a client needs, and nothing cryptographic: the AEAD comes from the
//! provider (`core_crypto::tls13_seal`/`tls13_open`), the key and the nonce come
//! from [`crate::tls13`], and what is left is the framing, the additional
//! authenticated data, and the inner plaintext's trailing type byte.
//!
//! A sealed record is `0x17 0x03 0x03 len ciphertext||tag`, and its AAD is the
//! five-byte header. The plaintext inside carries its own type byte last, with
//! any padding after it -- so the length of a record says nothing about how much
//! handshake message is in it, and the handshake layer reassembles.

use std::io;

use rustls::CipherSuite;

use crate::tls13::TrafficKeys;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The content types that appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_byte(byte: u8) -> io::Result<Self> {
        match byte {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            other => Err(err(format!("unknown content type {other}"))),
        }
    }
}

/// The version a record header carries: 0x0303 for everything but the
/// compatibility ClientHello, which is written as 0x0301.
pub const VERSION_1_2: [u8; 2] = [0x03, 0x01];
pub const VERSION_1_3: [u8; 2] = [0x03, 0x03];

/// RFC 8446 §5.1: 2^14 bytes of plaintext, and 2^14 + 256 with expansion.
pub const MAX_FRAGMENT: usize = 16384;

/// An unencrypted record, the only kind sent before the handshake keys exist.
pub fn plaintext_record(
    kind: ContentType,
    payload: &[u8],
    version: [u8; 2],
) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_FRAGMENT + 256 {
        return Err(err("plaintext record over the length limit"));
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind as u8);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Take the next record off the front of `input`, leaving the rest.
///
/// The payload is returned as it arrived: for a sealed record that still
/// includes the tag, because the AAD is the header and the tag is checked by
/// the AEAD.
pub fn take_record(input: &mut &[u8]) -> io::Result<(u8, [u8; 2], Vec<u8>)> {
    if input.len() < 5 {
        return Err(err("short record header"));
    }
    let kind = input[0];
    let version = [input[1], input[2]];
    let len = u16::from_be_bytes([input[3], input[4]]) as usize;
    if input.len() < 5 + len {
        return Err(err("short record"));
    }
    let payload = input[5..5 + len].to_vec();
    *input = &input[5 + len..];
    Ok((kind, version, payload))
}

/// Write `payload` under `keys`, as a sealed record.
pub struct Sealer {
    suite: CipherSuite,
    keys: TrafficKeys,
    seq: u64,
}

impl Sealer {
    pub fn new(suite: CipherSuite, keys: TrafficKeys) -> Self {
        Sealer {
            suite,
            keys,
            seq: 0,
        }
    }

    /// Swap in the next level's keys without resetting the sequence number:
    /// the handshake and application levels of one connection number their
    /// records from a single counter (RFC 8446 §5.3).
    pub fn set_keys(&mut self, keys: TrafficKeys) {
        self.keys = keys;
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn seal(&mut self, kind: ContentType, payload: &[u8]) -> io::Result<Vec<u8>> {
        // Checked here rather than left to the arithmetic below: the length in
        // the header is a u16, so an oversized payload wraps round to a short
        // one and the peer reads a truncated record out of the middle of a long
        // ciphertext -- which arrives as a tag that does not verify.
        if payload.len() > MAX_FRAGMENT {
            return Err(err("plaintext over the record length limit"));
        }
        // the inner plaintext: the content, its type, then zero padding
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(kind as u8);

        let nonce = self.keys.nonce(self.seq);
        let length = (inner.len() + 16) as u16;
        let aad = header(ContentType::ApplicationData, length);
        let sealed = core_crypto::tls13_seal(self.suite, &self.keys.key, &nonce, &aad, &inner)
            .ok_or_else(|| err("the cipher suite cannot seal a record"))?;
        if self.seq == u64::MAX {
            return Err(err("record sequence number exhausted"));
        }
        self.seq += 1;
        let mut out = Vec::with_capacity(5 + sealed.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

/// Read sealed records written by a [`Sealer`].
pub struct Opener {
    suite: CipherSuite,
    keys: TrafficKeys,
    seq: u64,
}

impl Opener {
    pub fn new(suite: CipherSuite, keys: TrafficKeys) -> Self {
        Opener {
            suite,
            keys,
            seq: 0,
        }
    }

    pub fn set_keys(&mut self, keys: TrafficKeys) {
        self.keys = keys;
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Open one record, returning its content type and plaintext with the type
    /// byte and any padding removed.
    pub fn open(&mut self, record: &[u8]) -> io::Result<(ContentType, Vec<u8>)> {
        if record.len() < 5 {
            return Err(err("short record header"));
        }
        if record[0] != ContentType::ApplicationData as u8 {
            return Err(err(format!(
                "a sealed record is always application_data outside, got {:#04x}",
                record[0]
            )));
        }
        let aad = &record[..5];
        let nonce = self.keys.nonce(self.seq);
        let inner = core_crypto::tls13_open(self.suite, &self.keys.key, &nonce, aad, &record[5..])
            .ok_or_else(|| err("record tag did not verify"))?;
        // the last non-zero byte is the content type; everything after it is
        // padding, and a record of only zeros is malformed
        let at = inner
            .iter()
            .rposition(|b| *b != 0)
            .ok_or_else(|| err("record has no content type"))?;
        let kind = ContentType::from_byte(inner[at])?;
        if self.seq == u64::MAX {
            return Err(err("record sequence number exhausted"));
        }
        self.seq += 1;
        Ok((kind, inner[..at].to_vec()))
    }
}

fn header(kind: ContentType, length: u16) -> [u8; 5] {
    let mut out = [0u8; 5];
    out[0] = kind as u8;
    out[1..3].copy_from_slice(&VERSION_1_3);
    out[3..5].copy_from_slice(&length.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::{Hash, KeySchedule};

    const SUITES: [CipherSuite; 3] = [
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ];

    /// A payload over 2^14 cannot go into one record, and the length field
    /// cannot hold it either -- so it has to be refused rather than wrapped
    /// round into a header that says something else entirely.
    #[test]
    fn an_oversized_payload_is_refused_rather_than_truncated() {
        let suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
        let mut sealer = Sealer::new(suite, keys(suite));
        assert!(
            sealer
                .seal(ContentType::ApplicationData, &vec![0u8; MAX_FRAGMENT])
                .is_ok()
        );
        let err = sealer
            .seal(ContentType::ApplicationData, &vec![0u8; MAX_FRAGMENT + 1])
            .expect_err("a record over 2^14 was sealed");
        assert!(err.to_string().contains("length limit"), "{err}");
    }

    fn keys(suite: CipherSuite) -> TrafficKeys {
        let hash = match suite {
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Hash::Sha384,
            _ => Hash::Sha256,
        };
        let key_len = core_crypto::tls13_key_len(suite).expect("a TLS 1.3 suite");
        KeySchedule::traffic_keys(b"a traffic secret we made up", hash, key_len, 12)
    }

    /// A message survives the round trip in every suite, at every sequence
    /// number, and the ciphertext is not the plaintext.
    #[test]
    fn every_suite_round_trips() {
        for suite in SUITES {
            let mut sealer = Sealer::new(suite, keys(suite));
            let mut opener = Opener::new(suite, keys(suite));
            for round in 0..4u8 {
                let payload = vec![round; 100 + round as usize];
                let record = sealer.seal(ContentType::Handshake, &payload).expect("seal");
                assert_ne!(&record[5..], &payload[..], "the record is not in the clear");
                let (kind, back) = opener.open(&record).expect("open");
                assert_eq!(kind, ContentType::Handshake);
                assert_eq!(back, payload, "seq {}", sealer.seq() - 1);
            }
        }
    }

    /// The nonce is the sequence number, so a record cannot be replayed into a
    /// different slot or reordered without the tag failing.
    #[test]
    fn a_reordered_record_does_not_open() {
        let suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
        let mut sealer = Sealer::new(suite, keys(suite));
        let _first = sealer.seal(ContentType::Handshake, b"one").expect("seal");
        let second = sealer.seal(ContentType::Handshake, b"two").expect("seal");
        let mut opener = Opener::new(suite, keys(suite));
        assert!(opener.open(&second).is_err(), "record 2 opened as record 1");
    }

    #[test]
    fn a_tampered_record_does_not_open() {
        let suite = CipherSuite::TLS13_AES_256_GCM_SHA384;
        let mut sealer = Sealer::new(suite, keys(suite));
        let mut opener = Opener::new(suite, keys(suite));
        let record = sealer
            .seal(ContentType::Handshake, b"payload")
            .expect("seal");
        for byte in [5, record.len() - 1] {
            let mut broken = record.clone();
            broken[byte] ^= 0x01;
            assert!(opener.open(&broken).is_err(), "a flipped byte opened");
        }
        // and a header byte is authenticated too
        let mut broken = record.clone();
        broken[3] ^= 0x01;
        assert!(opener.open(&broken).is_err(), "a rewritten length opened");
    }

    /// The key length in the suite table is what the AEAD takes; a wrong one
    /// must fail rather than truncate.
    #[test]
    fn a_wrong_key_length_is_refused() {
        let suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
        let short = KeySchedule::traffic_keys(b"secret", Hash::Sha256, 8, 12);
        let mut sealer = Sealer::new(suite, short);
        assert!(sealer.seal(ContentType::Handshake, b"x").is_err());
    }

    /// Padding inside a record is legal and must not reach the handshake.
    #[test]
    fn padding_is_stripped() {
        let suite = CipherSuite::TLS13_CHACHA20_POLY1305_SHA256;
        let sealer = Sealer::new(suite, keys(suite));
        let mut opener = Opener::new(suite, keys(suite));
        // hand-build a padded inner plaintext, since `seal` does not pad
        let mut inner = b"hello".to_vec();
        inner.push(ContentType::ApplicationData as u8);
        inner.extend_from_slice(&[0u8; 40]);
        let nonce = sealer.keys.nonce(0);
        let aad = header(ContentType::ApplicationData, (inner.len() + 16) as u16);
        let sealed =
            core_crypto::tls13_seal(suite, &sealer.keys.key, &nonce, &aad, &inner).expect("seal");
        let mut record = aad.to_vec();
        record.extend_from_slice(&sealed);
        let (kind, back) = opener.open(&record).expect("open");
        assert_eq!(kind, ContentType::ApplicationData);
        assert_eq!(back, b"hello");
    }

    #[test]
    fn a_record_of_only_padding_is_rejected() {
        let suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
        let sealer = Sealer::new(suite, keys(suite));
        let mut opener = Opener::new(suite, keys(suite));
        let inner = vec![0u8; 32];
        let nonce = sealer.keys.nonce(0);
        let aad = header(ContentType::ApplicationData, (inner.len() + 16) as u16);
        let sealed =
            core_crypto::tls13_seal(suite, &sealer.keys.key, &nonce, &aad, &inner).expect("seal");
        let mut record = aad.to_vec();
        record.extend_from_slice(&sealed);
        assert!(opener.open(&record).is_err());
    }

    /// Reading records off a buffer is what the handshake layer does, and it
    /// has to leave the rest of the buffer alone.
    #[test]
    fn records_come_off_a_buffer_one_at_a_time() {
        let mut stream = plaintext_record(ContentType::Handshake, b"first", VERSION_1_2)
            .expect("record")
            .to_vec();
        let tail =
            plaintext_record(ContentType::Handshake, b"second", VERSION_1_3).expect("record");
        stream.extend_from_slice(&tail);
        stream.extend_from_slice(b"leftover");

        let mut input = stream.as_slice();
        let (kind, version, payload) = take_record(&mut input).expect("first record");
        assert_eq!(kind, ContentType::Handshake as u8);
        assert_eq!(version, VERSION_1_2);
        assert_eq!(payload, b"first");
        let (_, _, payload) = take_record(&mut input).expect("second record");
        assert_eq!(payload, b"second");
        assert_eq!(input, b"leftover");
        assert!(
            take_record(&mut input).is_err(),
            "a partial record must not parse"
        );
    }
}
