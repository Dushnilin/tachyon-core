//! OpenVPN data-channel compression and fragmentation framing.
//!
//! Ported from `sing-openvpn/data_channel_{compression,fragmentation}.go`, which
//! itself follows upstream OpenVPN's `comp.h` / `compstub.c` / `lzo.c` /
//! `lz4.c` / `compv2`.
//!
//! Compression framing is one extra head byte (or a two-byte escape for the v2
//! algorithms) in front of the tunnelled IP packet; fragmentation then splits
//! that framed payload across several data-channel packets behind a four-byte
//! header, and the peer reassembles them.

use std::collections::HashMap;

const LZO_COMPRESS_BYTE: u8 = 0x66;
const LZ4_COMPRESS_BYTE: u8 = 0x69;
const NO_COMPRESS_BYTE: u8 = 0xfa;
const NO_COMPRESS_BYTE_SWAP: u8 = 0xfb;
const COMPRESS_V2_INDICATOR: u8 = 0x50;
const COMPRESS_V2_SUBTYPE_NONE: u8 = 0x00;
const COMPRESS_V2_SUBTYPE_LZ4: u8 = 0x01;

const FRAGMENT_TYPE_WHOLE: u32 = 0;
const FRAGMENT_TYPE_PARTIAL: u32 = 1;
const FRAGMENT_TYPE_LAST: u32 = 2;
const FRAGMENT_TYPE_MASK: u32 = 0x0000_0003;
const FRAGMENT_SEQUENCE_MASK: u32 = 0x0000_00ff;
const FRAGMENT_SEQUENCE_SHIFT: u32 = 2;
const FRAGMENT_ID_MASK: u32 = 0x0000_001f;
const FRAGMENT_ID_SHIFT: u32 = 10;
const FRAGMENT_SIZE_MASK: u32 = 0x0000_3fff;
const FRAGMENT_SIZE_SHIFT: u32 = 15;
const FRAGMENT_SIZE_ROUND_SHIFT: u32 = 2;
const FRAGMENT_MAX_PARTS: u32 = 32;
const FRAGMENT_RECEIVE_WINDOW: u32 = 25;
const FRAGMENT_REASSEMBLY_MAX_BYTES: usize = 4 << 20;
const FRAGMENT_REASSEMBLY_MAX_PACKET: usize = (1 << 16) - 1;

/// upper bound on a tunnelled packet, so a hostile peer cannot make us
/// allocate without limit
const MAX_DECOMPRESSED: usize = 1 << 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum Algorithm {
    #[default]
    None,
    Stub,
    Lzo,
    Lz4,
    StubV2,
    Lz4V2,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Compression {
    pub algorithm: Algorithm,
    pub swap: bool,
    pub adaptive: bool,
    pub asymmetric: bool,
}

impl Compression {
    /// `--compress`: upstream folds it into the same comp.alg/comp.flags pair,
    /// so a later directive overrides an earlier one.
    pub(crate) fn apply_compress(&mut self, value: &str) -> Result<(), String> {
        self.algorithm = match value {
            "" | "stub" => {
                self.swap = true;
                Algorithm::Stub
            }
            "stub-v2" => Algorithm::StubV2,
            "lzo" => {
                self.adaptive = false;
                self.swap = false;
                Algorithm::Lzo
            }
            "lz4" => {
                self.swap = true;
                Algorithm::Lz4
            }
            "lz4-v2" => Algorithm::Lz4V2,
            "migrate" | "none" | "no" | "disabled" | "off" => {
                *self = Compression::default();
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unsupported compression directive compress {other}"
                ));
            }
        };
        Ok(())
    }

    /// `--comp-lzo`: every variant clears COMP_F_SWAP first.
    pub(crate) fn apply_comp_lzo(&mut self, value: &str) -> Result<(), String> {
        self.swap = false;
        self.algorithm = match value {
            "" | "adaptive" => {
                self.adaptive = true;
                self.asymmetric = false;
                Algorithm::Lzo
            }
            "yes" => {
                self.adaptive = false;
                self.asymmetric = false;
                Algorithm::Lzo
            }
            "asym" => {
                self.adaptive = false;
                self.asymmetric = true;
                Algorithm::Lzo
            }
            "no" => {
                self.adaptive = false;
                Algorithm::Stub
            }
            "none" | "disabled" | "off" => {
                *self = Compression::default();
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unsupported compression directive comp-lzo {other}"
                ));
            }
        };
        Ok(())
    }

    pub(crate) fn resolve(compression: &str, compression_lzo: &str) -> Result<Self, String> {
        let mut settings = Compression::default();
        let compression = compression.trim();
        if !compression.is_empty() {
            settings.apply_compress(compression)?;
        }
        let compression_lzo = compression_lzo.trim();
        if !compression_lzo.is_empty() {
            settings.apply_comp_lzo(compression_lzo)?;
        }
        Ok(settings)
    }

    fn framing_enabled(&self) -> bool {
        self.algorithm != Algorithm::None
    }

    /// COMP_PREFIX_LEN: the head byte the v1 algorithms always carry. The v2
    /// algorithms prepend their indicator only when a payload needs escaping.
    fn framing_overhead(&self) -> usize {
        match self.algorithm {
            Algorithm::Stub | Algorithm::Lzo | Algorithm::Lz4 => 1,
            _ => 0,
        }
    }
}

struct Incoming {
    max_size: usize,
    parts: HashMap<u32, Vec<u8>>,
    bytes: usize,
    /// set once the `Last` fragment arrived; a gap before it is not an error
    last_id: Option<u32>,
}

pub(crate) struct Framing {
    compression: Compression,
    fragment_size: usize,
    outgoing_sequence: u32,
    incoming: HashMap<u32, Incoming>,
    incoming_bytes: usize,
    incoming_sequence: Option<u32>,
}

impl Framing {
    /// `newDataChannelFraming`: `None` when neither compression nor
    /// fragmentation is in play, which is the common case.
    pub(crate) fn new(compression: Compression, fragment: u32) -> Option<Self> {
        let fragment_size = fragment as usize;
        if !compression.framing_enabled() && fragment_size == 0 {
            return None;
        }
        let mut seed = [0u8; 4];
        getrandom::fill(&mut seed).unwrap_or_default();
        Some(Self {
            compression,
            fragment_size,
            outgoing_sequence: u32::from_le_bytes(seed) & FRAGMENT_SEQUENCE_MASK,
            incoming: HashMap::new(),
            incoming_bytes: 0,
            incoming_sequence: None,
        })
    }

    /// The bytes the framing adds to every tunnelled packet, fed into the MSS
    /// budget so `mss_fix` still lands under the interface MTU.
    pub(crate) fn payload_overhead(&self) -> usize {
        let mut overhead = self.compression.framing_overhead();
        if self.fragment_size > 0 {
            overhead += 4;
        }
        overhead
    }

    pub(crate) fn encode(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let framed = match self.compression.algorithm {
            Algorithm::Stub => apply_stub(payload, self.compression.swap),
            // upstream lz4_compress falls back to the swapped stub when the
            // payload does not shrink, and we never compress at all
            Algorithm::Lz4 => apply_stub(payload, true),
            // ponytail: LZO outbound always takes the "no compress" branch the
            // reference also takes whenever compression does not pay off; a
            // pure-rust LZO compressor would only save bandwidth
            Algorithm::Lzo => apply_stub(payload, false),
            Algorithm::StubV2 | Algorithm::Lz4V2 => escape_v2_stub(payload),
            Algorithm::None => payload.to_vec(),
        };
        if self.fragment_size == 0 {
            return vec![framed];
        }
        self.encode_fragments(framed)
    }

    fn encode_fragments(&mut self, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let size = self.fragment_size & !((1 << FRAGMENT_SIZE_ROUND_SHIFT) - 1);
        if size == 0 || payload.len() <= size {
            return vec![fragment_header(&payload, FRAGMENT_TYPE_WHOLE, 0, 0, 0)];
        }
        let sequence = self.outgoing_sequence;
        self.outgoing_sequence = (self.outgoing_sequence + 1) & FRAGMENT_SEQUENCE_MASK;
        let mut fragments = Vec::new();
        let mut offset = 0usize;
        let mut id = 0u32;
        while offset < payload.len() {
            if id >= FRAGMENT_MAX_PARTS {
                return vec![fragment_header(&payload, FRAGMENT_TYPE_WHOLE, 0, 0, 0)];
            }
            let take = size.min(payload.len() - offset);
            let last = offset + take >= payload.len();
            let max_size = if last {
                (size >> FRAGMENT_SIZE_ROUND_SHIFT) as u32
            } else {
                0
            };
            fragments.push(fragment_header(
                &payload[offset..offset + take],
                if last {
                    FRAGMENT_TYPE_LAST
                } else {
                    FRAGMENT_TYPE_PARTIAL
                },
                sequence,
                id,
                max_size,
            ));
            offset += take;
            id += 1;
        }
        fragments
    }

    /// `None` means the payload is a fragment of a packet still being
    /// reassembled, so the caller has nothing to hand up yet.
    pub(crate) fn decode(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let mut framed = payload.to_vec();
        if self.fragment_size > 0 {
            let Some(complete) = self.decode_fragment(&mut framed)? else {
                return Ok(None);
            };
            framed = complete;
        }
        let out = match self.compression.algorithm {
            Algorithm::Stub => unframe_stub(&framed, self.compression.swap)?,
            Algorithm::Lz4 => decode_lz4_v1(&framed)?,
            Algorithm::Lzo => decode_lzo(&framed)?,
            Algorithm::StubV2 | Algorithm::Lz4V2 => self.unwrap_v2(&framed)?,
            Algorithm::None => framed,
        };
        Ok(Some(out))
    }

    fn decode_fragment(&mut self, payload: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        if payload.len() < 4 {
            return Err("fragment header not found".into());
        }
        let flags = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let kind = (flags >> FRAGMENT_TYPE_SHIFT) & FRAGMENT_TYPE_MASK;
        let fragment = payload.split_off(4);
        match kind {
            FRAGMENT_TYPE_WHOLE => {
                if (flags >> FRAGMENT_SEQUENCE_SHIFT) & FRAGMENT_SEQUENCE_MASK != 0
                    || (flags >> FRAGMENT_ID_SHIFT) & FRAGMENT_ID_MASK != 0
                {
                    return Err("spurious fragment header flags".into());
                }
                Ok(Some(fragment))
            }
            FRAGMENT_TYPE_PARTIAL | FRAGMENT_TYPE_LAST => {
                let sequence = (flags >> FRAGMENT_SEQUENCE_SHIFT) & FRAGMENT_SEQUENCE_MASK;
                let id = (flags >> FRAGMENT_ID_SHIFT) & FRAGMENT_ID_MASK;
                let max_size = ((flags >> FRAGMENT_SIZE_SHIFT) & FRAGMENT_SIZE_MASK)
                    << FRAGMENT_SIZE_ROUND_SHIFT;
                self.store_fragment(
                    sequence,
                    id,
                    max_size as usize,
                    kind == FRAGMENT_TYPE_LAST,
                    fragment,
                )
            }
            other => Err(format!("unknown fragment type {other}")),
        }
    }

    fn store_fragment(
        &mut self,
        sequence: u32,
        id: u32,
        max_size: usize,
        last: bool,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        if payload.len() > FRAGMENT_REASSEMBLY_MAX_PACKET {
            return Err("fragment exceeds maximum reassembled packet size".into());
        }
        self.advance_window(sequence);
        let payload_len = payload.len();
        let previous = self
            .incoming
            .get(&sequence)
            .and_then(|entry| entry.parts.get(&id))
            .map_or(0, Vec::len);
        let additional = payload_len - previous;
        let buffered = self.incoming.get(&sequence).map_or(0, |entry| entry.bytes);
        if buffered + additional > FRAGMENT_REASSEMBLY_MAX_PACKET {
            self.drop_sequence(sequence);
            return Err("fragmented packet exceeds maximum IP packet size".into());
        }
        // the reassembly budget evicts the oldest sequences first
        while self.incoming_bytes + additional > FRAGMENT_REASSEMBLY_MAX_BYTES {
            let Some(oldest) = self.incoming.keys().min().copied() else {
                break;
            };
            self.drop_sequence(oldest);
            if oldest == sequence {
                return Err("fragment reassembly memory limit exceeded".into());
            }
        }
        let entry = self.incoming.entry(sequence).or_insert_with(|| Incoming {
            max_size: if max_size > 0 { max_size } else { payload_len },
            parts: HashMap::new(),
            bytes: 0,
            last_id: None,
        });
        if max_size > 0 {
            entry.max_size = max_size;
        } else if entry.max_size == 0 {
            entry.max_size = payload_len;
        }
        entry.parts.insert(id, payload);
        entry.bytes += additional;
        self.incoming_bytes += additional;
        if last {
            entry.last_id = Some(id);
        }
        let Some(last_id) = entry.last_id else {
            return Ok(None);
        };
        if (0..=last_id).any(|part| !entry.parts.contains_key(&part)) {
            // a gap in the middle is a packet still in flight, not an error
            return Ok(None);
        }
        let entry = self.incoming.remove(&sequence).expect("entry");
        self.incoming_bytes -= entry.bytes;
        let mut out = Vec::with_capacity(entry.bytes);
        for part in 0..=last_id {
            if let Some(bytes) = entry.parts.get(&part) {
                out.extend_from_slice(bytes);
            }
        }
        Ok(Some(out))
    }

    fn drop_sequence(&mut self, sequence: u32) {
        if let Some(entry) = self.incoming.remove(&sequence) {
            self.incoming_bytes -= entry.bytes;
        }
    }

    /// The peer keeps at most `FRAGMENT_RECEIVE_WINDOW` sequences in flight; a
    /// jump that far means it restarted, so the buffers are dropped.
    fn advance_window(&mut self, sequence: u32) {
        let Some(previous) = self.incoming_sequence else {
            self.incoming_sequence = Some(sequence);
            return;
        };
        let difference = sequence_difference(sequence, previous);
        if difference.abs() >= FRAGMENT_RECEIVE_WINDOW as i32 {
            self.incoming.clear();
            self.incoming_bytes = 0;
            self.incoming_sequence = Some(sequence);
            return;
        }
        if difference <= 0 {
            return;
        }
        self.incoming_sequence = Some(sequence);
        let stale: Vec<u32> = self
            .incoming
            .keys()
            .copied()
            .filter(|buffered| {
                let delta = sequence_difference(*buffered, sequence);
                delta <= -(FRAGMENT_RECEIVE_WINDOW as i32) || delta > 0
            })
            .collect();
        for buffered in stale {
            self.drop_sequence(buffered);
        }
    }

    fn unwrap_v2(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.is_empty() || payload[0] != COMPRESS_V2_INDICATOR {
            return Ok(payload.to_vec());
        }
        if payload.len() < 2 {
            return Err("truncated v2 compression header".into());
        }
        match payload[1] {
            COMPRESS_V2_SUBTYPE_NONE => Ok(payload[2..].to_vec()),
            COMPRESS_V2_SUBTYPE_LZ4 => {
                if self.compression.algorithm != Algorithm::Lz4V2 {
                    return Err("compressed lz4 v2 payload is not supported".into());
                }
                decompress_lz4_block(&payload[2..])
            }
            other => Err(format!("invalid v2 compression sub-type {other}")),
        }
    }
}

const FRAGMENT_TYPE_SHIFT: u32 = 0;

/// Signed distance between two fragment sequence numbers, wrapped at 8 bits.
fn sequence_difference(a: u32, b: u32) -> i32 {
    let difference = a.wrapping_sub(b) & FRAGMENT_SEQUENCE_MASK;
    if difference > FRAGMENT_SEQUENCE_MASK / 2 {
        (difference as i32) - (FRAGMENT_SEQUENCE_MASK as i32 + 1)
    } else {
        difference as i32
    }
}

/// Upstream stub_compress moves the head byte to the tail under COMP_F_SWAP
/// and prepends the plain marker otherwise.
fn apply_stub(payload: &[u8], swap: bool) -> Vec<u8> {
    if !swap {
        let mut out = Vec::with_capacity(payload.len() + 1);
        out.push(NO_COMPRESS_BYTE);
        out.extend_from_slice(payload);
        return out;
    }
    if payload.is_empty() {
        return vec![NO_COMPRESS_BYTE_SWAP];
    }
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(NO_COMPRESS_BYTE_SWAP);
    out.extend_from_slice(&payload[1..]);
    out.push(payload[0]);
    out
}

fn unframe_stub(payload: &[u8], swap: bool) -> Result<Vec<u8>, String> {
    let Some(&marker) = payload.first() else {
        return Err("missing compression marker".into());
    };
    let expected = if swap {
        NO_COMPRESS_BYTE_SWAP
    } else {
        NO_COMPRESS_BYTE
    };
    if marker != expected {
        return Err("invalid compression stub marker".into());
    }
    if swap {
        return Ok(unswap_v1_head(payload));
    }
    Ok(payload[1..].to_vec())
}

/// lz4_decompress restores the swapped head byte from the tail.
fn unswap_v1_head(payload: &[u8]) -> Vec<u8> {
    if payload.len() <= 1 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(payload.len() - 1);
    out.push(payload[payload.len() - 1]);
    out.extend_from_slice(&payload[1..payload.len() - 1]);
    out
}

fn escape_v2_stub(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() || payload[0] != COMPRESS_V2_INDICATOR {
        return payload.to_vec();
    }
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.push(COMPRESS_V2_INDICATOR);
    out.push(COMPRESS_V2_SUBTYPE_NONE);
    out.extend_from_slice(payload);
    out
}

fn decode_lz4_v1(payload: &[u8]) -> Result<Vec<u8>, String> {
    let Some(&marker) = payload.first() else {
        return Err("missing compression marker".into());
    };
    match marker {
        NO_COMPRESS_BYTE_SWAP => Ok(unswap_v1_head(payload)),
        LZ4_COMPRESS_BYTE => {
            // upstream unswaps before handing the block to LZ4_decompress_safe
            let unswapped = unswap_v1_head(payload);
            decompress_lz4_block(&unswapped[1..])
        }
        _ => Err("invalid lz4 compression marker".into()),
    }
}

fn decode_lzo(payload: &[u8]) -> Result<Vec<u8>, String> {
    let Some(&marker) = payload.first() else {
        return Err("missing compression marker".into());
    };
    match marker {
        NO_COMPRESS_BYTE => Ok(payload[1..].to_vec()),
        // ponytail: LZO has no pure-rust decompressor we can depend on, and a
        // peer only sends this when it was configured to compress outbound
        LZO_COMPRESS_BYTE => Err("lzo compressed payload is not supported".into()),
        _ => Err("invalid lzo compression marker".into()),
    }
}

fn decompress_lz4_block(block: &[u8]) -> Result<Vec<u8>, String> {
    if block.is_empty() {
        return Err("empty lz4 block".into());
    }
    let out = lz4_flex::block::decompress(block, MAX_DECOMPRESSED)
        .map_err(|_| "lz4 block decompression failed".to_string())?;
    if out.is_empty() {
        return Err("lz4 block decompression produced empty output".into());
    }
    Ok(out)
}

fn fragment_header(payload: &[u8], kind: u32, sequence: u32, id: u32, max_size: u32) -> Vec<u8> {
    let mut flags = (kind & FRAGMENT_TYPE_MASK) << FRAGMENT_TYPE_SHIFT;
    flags |= (sequence & FRAGMENT_SEQUENCE_MASK) << FRAGMENT_SEQUENCE_SHIFT;
    flags |= (id & FRAGMENT_ID_MASK) << FRAGMENT_ID_SHIFT;
    if kind == FRAGMENT_TYPE_LAST {
        flags |= (max_size & FRAGMENT_SIZE_MASK) << FRAGMENT_SIZE_SHIFT;
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framing(compression: Compression, fragment: u32) -> Framing {
        Framing::new(compression, fragment).expect("framing enabled")
    }

    #[test]
    fn directives_fold_like_upstream() {
        let mut settings = Compression::default();
        settings.apply_compress("stub").expect("stub");
        assert_eq!(settings.algorithm, Algorithm::Stub);
        assert!(settings.swap);
        // --comp-lzo clears the swap flag for every variant
        settings.apply_comp_lzo("yes").expect("lzo");
        assert_eq!(settings.algorithm, Algorithm::Lzo);
        assert!(!settings.swap);
        // a later --compress wins again
        settings.apply_compress("lz4-v2").expect("lz4-v2");
        assert_eq!(settings.algorithm, Algorithm::Lz4V2);
        // and an off value resets everything
        settings.apply_compress("off").expect("off");
        assert_eq!(settings, Compression::default());
        assert!(settings.apply_compress("zstd").is_err());
    }

    #[test]
    fn no_compression_and_no_fragment_means_no_framing() {
        assert!(Framing::new(Compression::default(), 0).is_none());
    }

    #[test]
    fn stub_framing_roundtrips() {
        for swap in [false, true] {
            let mut settings = Compression::default();
            settings.apply_compress("stub").expect("stub");
            settings.swap = swap;
            let mut codec = framing(settings, 0);
            let payload = vec![0x45, 1, 2, 3, 4, 5];
            let framed = codec.encode(&payload);
            assert_eq!(framed.len(), 1);
            assert_eq!(
                framed[0][0],
                if swap {
                    NO_COMPRESS_BYTE_SWAP
                } else {
                    NO_COMPRESS_BYTE
                }
            );
            assert_eq!(
                codec.decode(&framed[0]).expect("decode").expect("payload"),
                payload
            );
        }
    }

    #[test]
    fn the_swapped_stub_moves_the_head_byte_to_the_tail() {
        let mut settings = Compression::default();
        settings.apply_compress("stub").expect("stub");
        assert!(settings.swap);
        let mut codec = framing(settings, 0);
        let framed = codec.encode(b"abcd");
        assert_eq!(
            framed[0],
            vec![NO_COMPRESS_BYTE_SWAP, b'b', b'c', b'd', b'a']
        );
    }

    #[test]
    fn lz4_outbound_takes_the_swapped_stub() {
        let mut settings = Compression::default();
        settings.apply_compress("lz4").expect("lz4");
        let mut codec = framing(settings, 0);
        let framed = codec.encode(b"payload");
        assert_eq!(framed[0][0], NO_COMPRESS_BYTE_SWAP);
        assert_eq!(
            codec.decode(&framed[0]).expect("decode").expect("payload"),
            b"payload"
        );
    }

    #[test]
    fn lz4_v2_escapes_only_a_0x50_payload() {
        let mut settings = Compression::default();
        settings.apply_compress("lz4-v2").expect("lz4-v2");
        let mut codec = framing(settings, 0);
        let plain = codec.encode(b"payload");
        assert_eq!(plain[0], b"payload", "a normal payload is untouched");
        assert_eq!(
            codec.decode(&plain[0]).expect("decode").expect("payload"),
            b"payload"
        );

        let escaped = codec.encode(&[0x50, 0x01, 1, 2, 3]);
        assert_eq!(
            &escaped[0][..2],
            &[COMPRESS_V2_INDICATOR, COMPRESS_V2_SUBTYPE_NONE]
        );
        assert_eq!(
            codec.decode(&escaped[0]).expect("decode").expect("payload"),
            vec![0x50, 0x01, 1, 2, 3]
        );
    }

    #[test]
    fn lz4_v2_unwraps_a_compressed_block() {
        // a stored (uncompressed) lz4 block: token 0xf0 then the literals
        let block = [0x30, 0x41, 0x42, 0x43];
        let mut payload = vec![COMPRESS_V2_INDICATOR, COMPRESS_V2_SUBTYPE_LZ4];
        payload.extend_from_slice(&block);
        let mut settings = Compression::default();
        settings.apply_compress("lz4-v2").expect("lz4-v2");
        let mut codec = framing(settings, 0);
        assert_eq!(
            codec.decode(&payload).expect("decode").expect("payload"),
            b"ABC"
        );
    }

    #[test]
    fn lzo_takes_the_no_compress_marker_both_ways() {
        let mut settings = Compression::default();
        settings.apply_comp_lzo("adaptive").expect("lzo");
        let mut codec = framing(settings, 0);
        let framed = codec.encode(b"payload");
        assert_eq!(framed[0][0], NO_COMPRESS_BYTE);
        assert_eq!(
            codec.decode(&framed[0]).expect("decode").expect("payload"),
            b"payload"
        );
        // a compressed lzo payload is refused rather than mis-parsed
        assert!(codec.decode(&[LZO_COMPRESS_BYTE, 1, 2, 3]).is_err());
    }

    #[test]
    fn a_short_payload_gets_a_whole_fragment_header() {
        let mut settings = Compression::default();
        settings.apply_compress("stub").expect("stub");
        settings.swap = false;
        let mut codec = framing(settings, 1300);
        let framed = codec.encode(b"small");
        assert_eq!(framed.len(), 1);
        // the fragment header comes first, then the stub marker and the payload
        assert_eq!(&framed[0][..4], &[0, 0, 0, FRAGMENT_TYPE_WHOLE as u8]);
        assert_eq!(framed[0][4], NO_COMPRESS_BYTE);
        assert_eq!(&framed[0][5..], b"small");
        assert_eq!(codec.payload_overhead(), 1 + 4);
    }

    #[test]
    fn large_payloads_are_split_and_reassembled() {
        let mut settings = Compression::default();
        settings.apply_compress("stub").expect("stub");
        let mut sender = framing(settings, 68);
        let mut receiver = framing(settings, 68);
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let fragments = sender.encode(&payload);
        assert!(fragments.len() > 1, "the payload has to be split");
        let mut out = Vec::new();
        for fragment in &fragments {
            if let Some(decoded) = receiver.decode(fragment).expect("decode") {
                out = decoded;
            }
        }
        assert_eq!(out, payload);
    }

    #[test]
    fn a_gap_leaves_the_packet_in_flight_instead_of_failing() {
        let mut settings = Compression::default();
        settings.apply_compress("stub").expect("stub");
        let mut sender = framing(settings, 68);
        let mut receiver = framing(settings, 68);
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let fragments = sender.encode(&payload);
        assert!(fragments.len() >= 3);
        let last = fragments.len() - 1;
        // the last fragment arrives before the middle ones
        assert!(receiver.decode(&fragments[last]).expect("decode").is_none());
        assert!(receiver.decode(&fragments[0]).expect("decode").is_none());
        // the rest turns up and the packet completes
        let mut done = None;
        for fragment in &fragments[1..last] {
            if let Some(payload) = receiver.decode(fragment).expect("decode") {
                done = Some(payload);
            }
        }
        assert_eq!(done.expect("complete"), payload);
    }

    #[test]
    fn a_sequence_jump_clears_stale_buffers() {
        let mut settings = Compression::default();
        settings.apply_compress("stub").expect("stub");
        let mut sender = framing(settings, 68);
        let mut receiver = framing(settings, 68);
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let first = sender.encode(&payload);
        assert!(receiver.decode(&first[0]).expect("decode").is_none());
        // the peer restarts its sequence space, so the stale buffer is dropped
        sender.outgoing_sequence = 200;
        let second = sender.encode(&payload);
        let mut done = None;
        for fragment in &second {
            if let Some(payload) = receiver.decode(fragment).expect("decode") {
                done = Some(payload);
            }
        }
        assert_eq!(done.expect("the second packet completes"), payload);
        assert!(receiver.incoming.is_empty(), "the buffer was released");
    }
}
