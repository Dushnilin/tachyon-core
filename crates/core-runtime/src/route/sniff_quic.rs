//! QUIC client Initial sniffer (reference `common/sniff/quic.go`): strip the
//! header protection, open the Initial with the keys anyone can derive from
//! the DCID, reassemble the CRYPTO frames by offset and read the SNI out of
//! the ClientHello.
//!
//! Header shape alone says nothing -- any UDP payload can start with 0xc0 --
//! so nothing is called QUIC before the AEAD tag checks out. A ClientHello
//! with a post-quantum key share (Chrome, Firefox) is ~1.8 KB and does not fit
//! one 1200-byte datagram: the caller hands every datagram of the flow seen so
//! far, and [`Quic::NeedMore`] asks for the next one.

use std::sync::OnceLock;

use core_tls::rustls::Side;
use core_tls::rustls::quic::{Suite, Version};

/// RFC 9000 14.1: a datagram carrying a client Initial is padded to 1200.
const MIN_INITIAL_DATAGRAM: usize = 1200;
/// More CRYPTO than any ClientHello needs is a flood, not a handshake.
const MAX_CRYPTO: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Quic {
    NoMatch,
    /// An authenticated Initial whose ClientHello is still incomplete.
    NeedMore,
    /// The whole ClientHello, and its SNI when it carried one.
    Hello(Option<String>),
}

pub(super) fn sniff(datagrams: &[&[u8]]) -> Quic {
    let mut crypto = Crypto::default();
    let Some((first, rest)) = datagrams.split_first() else {
        return Quic::NoMatch;
    };
    let Some(dcid) = open_datagram(first, None, &mut crypto) else {
        return Quic::NoMatch;
    };
    // later datagrams of the same client keep the original DCID until the
    // server answers; anything else in the flow (0-RTT, junk) is ignored
    for datagram in rest {
        open_datagram(datagram, Some(&dcid), &mut crypto);
    }
    crypto.client_hello()
}

fn suite() -> Option<&'static Suite> {
    static SUITE: OnceLock<Option<Suite>> = OnceLock::new();
    SUITE
        .get_or_init(|| {
            core_tls::quic::initial_suite_from_provider(&core_tls::quic::configured_provider())
        })
        .as_ref()
}

fn varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*pos..pos.checked_add(len)?)?;
    let mut v = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        v = (v << 8) | u64::from(*byte);
    }
    *pos += len;
    Some(v)
}

fn varint_usize(b: &[u8], pos: &mut usize) -> Option<usize> {
    usize::try_from(varint(b, pos)?).ok()
}

/// Open every client Initial coalesced into one datagram and feed their
/// CRYPTO frames to `crypto`. Returns the DCID when at least one Initial
/// authenticated (and, with `want`, carried that DCID).
fn open_datagram(datagram: &[u8], want: Option<&[u8]>, crypto: &mut Crypto) -> Option<Vec<u8>> {
    if datagram.len() < MIN_INITIAL_DATAGRAM {
        return None;
    }
    let mut rest = datagram;
    let mut opened: Option<Vec<u8>> = None;
    // long headers only: a short header runs to the end of the datagram
    while rest.first().is_some_and(|b| b & 0x80 != 0) {
        let Some((len, dcid, initial)) = long_header(rest) else {
            break;
        };
        if let Some(initial) = initial {
            let ours = want.is_none_or(|w| w == dcid);
            if ours && open_initial(&rest[..len], &initial, dcid, crypto).is_some() {
                opened.get_or_insert_with(|| dcid.to_vec());
            } else if opened.is_none() {
                // an Initial that does not open is not QUIC, or not this flow
                return None;
            }
        }
        rest = &rest[len..];
    }
    opened
}

struct Initial {
    version: Version,
    /// offset of the packet number field
    pn_at: usize,
}

/// Length of the long-header packet at the front of `b`, its DCID, and the
/// Initial bookkeeping when it is a client Initial of a version we know.
fn long_header(b: &[u8]) -> Option<(usize, &[u8], Option<Initial>)> {
    let first = *b.first()?;
    if first & 0x40 == 0 {
        return None; // fixed bit: Initials never grease it (RFC 9287 3)
    }
    let wire = u32::from_be_bytes(b.get(1..5)?.try_into().ok()?);
    let ty = (first >> 4) & 3;
    // RFC 9369 3.2 shuffles the type bits: v2 Initial is 1, Retry is 0
    let (version, is_initial, is_retry) = match wire {
        1 => (Version::V1, ty == 0, ty == 3),
        0x6b33_43cf => (Version::V2, ty == 1, ty == 0),
        _ => return None,
    };
    if is_retry {
        return None; // never sent by a client
    }
    let dcid_len = usize::from(*b.get(5)?);
    if dcid_len > 20 {
        return None;
    }
    let dcid = b.get(6..6 + dcid_len)?;
    let mut pos = 6 + dcid_len;
    let scid_len = usize::from(*b.get(pos)?);
    if scid_len > 20 {
        return None;
    }
    pos += 1 + scid_len;
    if is_initial {
        let token = varint_usize(b, &mut pos)?;
        pos = pos.checked_add(token)?;
    }
    let length = varint_usize(b, &mut pos)?;
    let end = pos.checked_add(length)?;
    b.get(..end)?;
    let initial = is_initial.then_some(Initial {
        version,
        pn_at: pos,
    });
    Some((end, dcid, initial))
}

fn open_initial(packet: &[u8], initial: &Initial, dcid: &[u8], crypto: &mut Crypto) -> Option<()> {
    let keys = suite()?.keys(dcid, Side::Server, initial.version);
    let pn_at = initial.pn_at;
    // RFC 9001 5.4.2: the sample starts 4 bytes into the packet number field
    let sample = packet.get(pn_at + 4..pn_at + 4 + keys.remote.header.sample_len())?;
    let mut header = packet.get(..pn_at + 4)?.to_vec();
    let (first, rest) = header.split_at_mut(1);
    keys.remote
        .header
        .decrypt_in_place(sample, &mut first[0], &mut rest[pn_at - 1..])
        .ok()?;
    if header[0] & 0x0c != 0 {
        return None; // reserved bits must be zero once unmasked
    }
    let pn_len = usize::from(header[0] & 3) + 1;
    // nothing has been received in this space yet, so the truncated packet
    // number decodes to itself (RFC 9000 A.3 with an expected number of 0)
    let pn = header[pn_at..pn_at + pn_len]
        .iter()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    header.truncate(pn_at + pn_len);
    let mut payload = packet.get(header.len()..)?.to_vec();
    let plain = keys
        .remote
        .packet
        .decrypt_in_place(pn, &header, &mut payload)
        .ok()?;
    frames(plain, crypto)
}

/// RFC 9000 12.4: an Initial carries PADDING, PING, ACK, CRYPTO and
/// CONNECTION_CLOSE only; anything else is a protocol violation.
fn frames(b: &[u8], crypto: &mut Crypto) -> Option<()> {
    let mut pos = 0;
    while pos < b.len() {
        match varint(b, &mut pos)? {
            0x00 | 0x01 => {}
            ty @ (0x02 | 0x03) => {
                varint(b, &mut pos)?; // largest acknowledged
                varint(b, &mut pos)?; // delay
                let ranges = varint(b, &mut pos)?;
                varint(b, &mut pos)?; // first range
                for _ in 0..ranges {
                    varint(b, &mut pos)?; // gap
                    varint(b, &mut pos)?; // range length
                }
                if ty == 0x03 {
                    for _ in 0..3 {
                        varint(b, &mut pos)?; // ECT0, ECT1, ECN-CE
                    }
                }
            }
            0x06 => {
                let offset = varint_usize(b, &mut pos)?;
                let len = varint_usize(b, &mut pos)?;
                let data = b.get(pos..pos.checked_add(len)?)?;
                pos += len;
                crypto.add(offset, data)?;
            }
            0x1c => {
                varint(b, &mut pos)?; // error code
                varint(b, &mut pos)?; // frame type
                let reason = varint_usize(b, &mut pos)?;
                pos = pos.checked_add(reason)?;
                b.get(..pos)?;
            }
            _ => return None,
        }
    }
    Some(())
}

/// CRYPTO stream fragments, kept by offset: browsers deliberately send them
/// out of order and overlapping.
#[derive(Default)]
struct Crypto {
    fragments: Vec<(usize, Vec<u8>)>,
    total: usize,
}

impl Crypto {
    fn add(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        if offset.checked_add(data.len())? > MAX_CRYPTO {
            return None;
        }
        self.total += data.len();
        if self.total > MAX_CRYPTO {
            return None;
        }
        self.fragments.push((offset, data.to_vec()));
        Some(())
    }

    /// The contiguous prefix of the stream from offset 0.
    fn prefix(&mut self) -> Vec<u8> {
        self.fragments.sort_by_key(|(offset, _)| *offset);
        let mut out = Vec::new();
        for (offset, data) in &self.fragments {
            if *offset > out.len() {
                break;
            }
            let skip = out.len() - offset;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }

    fn client_hello(&mut self) -> Quic {
        let stream = self.prefix();
        if stream.len() < 4 {
            return Quic::NeedMore;
        }
        if stream[0] != 0x01 {
            return Quic::NoMatch; // the first handshake message is ClientHello
        }
        let body =
            (usize::from(stream[1]) << 16) | (usize::from(stream[2]) << 8) | usize::from(stream[3]);
        let need = 4 + body;
        if stream.len() < need {
            return Quic::NeedMore;
        }
        // the TLS parser reads records, so give the message one
        let Ok(rec_len) = u16::try_from(need) else {
            return Quic::Hello(None);
        };
        let mut record = Vec::with_capacity(5 + need);
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&stream[..need]);
        let sni = core_tls::hello::parse_record(&record)
            .ok()
            .map(|hello| hello.sni)
            .filter(|sni| !sni.is_empty());
        Quic::Hello(sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_reassembles_out_of_order_and_overlapping_fragments() {
        let mut c = Crypto::default();
        c.add(4, b"efgh").unwrap();
        c.add(0, b"abcdef").unwrap();
        c.add(10, b"kl").unwrap();
        assert_eq!(c.prefix(), b"abcdefgh");
        c.add(8, b"ij").unwrap();
        assert_eq!(c.prefix(), b"abcdefghijkl");
    }

    #[test]
    fn crypto_refuses_a_flood() {
        let mut c = Crypto::default();
        assert!(c.add(MAX_CRYPTO, b"x").is_none());
        assert!(c.add(0, &vec![0; MAX_CRYPTO]).is_some());
        assert!(c.add(0, b"x").is_none());
    }

    #[test]
    fn a_hello_split_across_datagrams_asks_for_more() {
        let mut c = Crypto::default();
        c.add(0, &[0x01, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(c.client_hello(), Quic::NeedMore);
        let mut c = Crypto::default();
        c.add(0, &[0x02, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(c.client_hello(), Quic::NoMatch);
    }

    fn put_varint(out: &mut Vec<u8>, v: usize) {
        match v {
            0..=63 => out.push(v as u8),
            64..=16383 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
            _ => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        }
    }

    /// A ClientHello carrying `sni` and a padding extension of `pad` bytes.
    fn client_hello(sni: &str, pad: usize) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(name.len() as u16 + 5).to_be_bytes());
        ext.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        ext.extend_from_slice(&[0x00, 0x15]);
        ext.extend_from_slice(&(pad as u16).to_be_bytes());
        ext.resize(ext.len() + pad, 0);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut msg = vec![0x01];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        put_varint(&mut f, offset);
        put_varint(&mut f, data.len());
        f.extend_from_slice(data);
        f
    }

    /// One padded v1 client Initial datagram, encrypted the way a client
    /// would: the keys are the same ones the sniffer derives from the DCID.
    fn initial(dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
        let keys = suite().unwrap().keys(dcid, Side::Client, Version::V1);
        let mut header = vec![0xc3];
        header.extend_from_slice(&1u32.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.extend_from_slice(&[0, 0]); // no SCID, no token
        let mut payload = frames.to_vec();
        let fixed = header.len() + 2 + 4 + 16;
        payload.resize(payload.len().max(MIN_INITIAL_DATAGRAM - fixed), 0);
        header.extend_from_slice(&((4 + payload.len() + 16) as u16 | 0x4000).to_be_bytes());
        let pn_at = header.len();
        header.extend_from_slice(&pn.to_be_bytes());
        let tag = keys
            .local
            .packet
            .encrypt_in_place(u64::from(pn), &header, &mut payload)
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        let sample = packet[pn_at + 4..pn_at + 4 + keys.local.header.sample_len()].to_vec();
        let (first, rest) = packet.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(&sample, &mut first[0], &mut rest[pn_at - 1..pn_at + 3])
            .unwrap();
        packet
    }

    #[test]
    fn a_post_quantum_sized_hello_comes_together_over_two_datagrams() {
        let dcid = [0x5a; 8];
        let hello = client_hello("split.example", 1500);
        let one = initial(&dcid, 0, &crypto_frame(0, &hello[..900]));
        let two = initial(&dcid, 1, &crypto_frame(900, &hello[900..]));
        assert_eq!(sniff(&[&one]), Quic::NeedMore);
        assert_eq!(
            sniff(&[&one, &two]),
            Quic::Hello(Some("split.example".into()))
        );
        // the second half on its own is QUIC, just not readable yet
        assert_eq!(sniff(&[&two]), Quic::NeedMore);
        // another connection's Initial does not fill this one in
        let other = initial(&[0x33; 8], 1, &crypto_frame(900, &hello[900..]));
        assert_eq!(sniff(&[&one, &other]), Quic::NeedMore);
    }

    #[test]
    fn crypto_frames_out_of_order_in_one_datagram() {
        let hello = client_hello("swap.example", 64);
        let mut frames = crypto_frame(40, &hello[40..]);
        frames.extend_from_slice(&[0x01, 0x00, 0x00]); // PING, PADDING
        frames.extend_from_slice(&crypto_frame(0, &hello[..40]));
        let datagram = initial(&[1, 2, 3, 4], 7, &frames);
        assert_eq!(
            sniff(&[&datagram]),
            Quic::Hello(Some("swap.example".into()))
        );
        let mut tampered = datagram.clone();
        tampered[40] ^= 1;
        assert_eq!(sniff(&[&tampered]), Quic::NoMatch);
    }

    #[test]
    fn a_frame_an_initial_may_not_carry_is_not_quic() {
        // STREAM (0x08) never travels in an Initial
        let datagram = initial(&[9; 8], 0, &[0x08, 0x00, 0x00]);
        assert_eq!(sniff(&[&datagram]), Quic::NoMatch);
    }
}
