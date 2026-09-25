//! QUIC Initial masquerade (SPEC 009, `ip=quic`): a standalone ≥1200-byte
//! QUIC v1 Initial carrying a realistic ClientHello cut into out-of-order
//! CRYPTO fragments. Ported from sing-box-lx `transport/wireguard/
//! {quic_initial_awg,quic_clienthello_awg,quic_crypto_awg}.go` — which mirror
//! the project's QUIC sniffer (RFC 9001 §5 Initial encryption verbatim).
//!
//! The DPI bypass is structural: the first CRYPTO frame on the wire has
//! offset ≠ 0, so a line-rate parser that assumes offset 0 reads garbage and
//! fails open, while a real server reassembles by offset. All layout
//! randomness (DCID, TLS random, ephemeral key, cut points, wire order) is
//! per-call.
//!
//! Browser hint: `chrome`/`firefox` select the generic ClientHello — the
//! reference does the same for builds without uTLS (the stub file), which is
//! the behavior parity target.

use aes::cipher::KeyInit;
use anyhow::anyhow;

use super::awg::{self, JunkChain, Obf};

// ---------------------------------------------------------------------------
// RFC 9000 §16 variable-length integer.
// ---------------------------------------------------------------------------

fn append_quic_varint(dst: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        dst.push(v as u8);
    } else if v < 1 << 14 {
        dst.extend_from_slice(&[(v >> 8) as u8 | 0x40, v as u8]);
    } else if v < 1 << 30 {
        dst.extend_from_slice(&[
            (v >> 24) as u8 | 0x80,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]);
    } else {
        dst.extend_from_slice(&v.to_be_bytes());
    }
}

fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Uniform random in `[0, n)`.
fn rand_int(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut b = [0u8; 8];
    awg::fill_random(&mut b);
    (u64::from_le_bytes(b) % n as u64) as usize
}

// ---------------------------------------------------------------------------
// RFC 9001 §5 Initial encryption (mirror of qtls / common/sniff).
// ---------------------------------------------------------------------------

const QUIC_VERSION_1: u32 = 0x1;

/// QUIC v1 Initial salt (RFC 9001 §5.2).
const QUIC_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// HKDF-Expand-Label (RFC 8446 §7.1) with the `tls13 ` prefix.
fn hkdf_expand_label(secret: &[u8], context: &[u8], label: &str, length: usize) -> Vec<u8> {
    let label_bytes = format!("tls13 {label}");
    let mut info = Vec::with_capacity(3 + label_bytes.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(label_bytes.len() as u8);
    info.extend_from_slice(label_bytes.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(secret).expect("prk len");
    let mut out = vec![0u8; length];
    hk.expand(&info, &mut out).expect("hkdf expand");
    out
}

/// Initial key/iv/hp from the DCID (RFC 9001 §5.1/§5.2).
fn derive_initial_keys(dcid: &[u8]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    use hkdf::Hkdf;
    let initial = Hkdf::<sha2::Sha256>::new(Some(&QUIC_SALT_V1), dcid);
    let mut initial_secret = [0u8; 32];
    initial.expand(&[], &mut initial_secret).expect("expand");
    let client_secret = hkdf_expand_label(&initial_secret, &[], "client in", 32);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hkdf_expand_label(&client_secret, &[], "quic key", 16));
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&hkdf_expand_label(&client_secret, &[], "quic iv", 12));
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hkdf_expand_label(&client_secret, &[], "quic hp", 16));
    (key, iv, hp)
}

/// AES-128-GCM with the TLS-1.3 XORed nonce (`qtls.AEADAESGCMTLS13`): the
/// 8-byte sequence number XORs onto `iv[4..12]`.
fn seal_initial(key: &[u8; 16], iv: &[u8; 12], pn: u64, payload: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = *iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("key");
    cipher
        .encrypt(&nonce.into(), Payload { msg: payload, aad })
        .expect("seal")
}

/// AES-ECB single block (the header-protection mask generator).
fn aes_ecb_block(key: &[u8; 16], block: &[u8]) -> [u8; 16] {
    use aes::cipher::BlockEncrypt;
    use aes::cipher::generic_array::GenericArray;
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut arr = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut arr);
    arr.into()
}

/// Seal the payload and apply header protection in place (RFC 9001 §5.4,
/// pn_len fixed at 1, packet number 0).
fn encrypt_initial(
    header: &[u8],
    payload: &[u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    hp: &[u8; 16],
    pn_offset: usize,
) -> anyhow::Result<Vec<u8>> {
    let ciphertext = seal_initial(key, iv, 0, payload, header);
    let mut packet = header.to_vec();
    packet.extend_from_slice(&ciphertext);

    // Mask sample: 16 ciphertext bytes starting 4 after the pn field.
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > packet.len() {
        return Err(anyhow!(
            "amneziawg: QUIC Initial too short to sample for header protection"
        ));
    }
    let mask = aes_ecb_block(hp, &packet[sample_offset..sample_offset + 16]);
    packet[0] ^= mask[0] & 0x0f; // long header: low 4 bits of the first byte
    packet[pn_offset] ^= mask[1];
    Ok(packet)
}

// ---------------------------------------------------------------------------
// TLS 1.3 ClientHello (generic, ~294 bytes, padded to the etalon).
// ---------------------------------------------------------------------------

const QUIC_CH_TARGET_LEN: usize = 294;
const QUIC_CH_MIN_LEN: usize = 291;

fn append_vec16(dst: &mut Vec<u8>, body: &[u8]) {
    dst.extend_from_slice(&(body.len() as u16).to_be_bytes());
    dst.extend_from_slice(body);
}

fn append_extension(dst: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    dst.extend_from_slice(&ext_type.to_be_bytes());
    dst.extend_from_slice(&(data.len() as u16).to_be_bytes());
    dst.extend_from_slice(data);
}

fn append_quic_transport_params() -> Vec<u8> {
    let mut p = Vec::new();
    let mut param = |id: u64, value: &[u8]| {
        append_quic_varint(&mut p, id);
        append_quic_varint(&mut p, value.len() as u64);
        p.extend_from_slice(value);
    };
    let varint = |v: u64| {
        let mut b = Vec::new();
        append_quic_varint(&mut b, v);
        b
    };
    param(0x01, &varint(30_000));
    param(0x04, &varint(0x00C0_0000));
    param(0x05, &varint(0x0010_0000));
    param(0x06, &varint(0x0010_0000));
    param(0x07, &varint(0x0010_0000));
    param(0x08, &varint(100));
    param(0x09, &varint(100));
    param(0x0E, &varint(8));
    param(0x03, &varint(1472));
    p
}

fn build_generic_client_hello(
    sni: &str,
    tls_random: &[u8; 32],
    x25519_pub: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    if sni.is_empty() {
        return Err(anyhow!(
            "amneziawg: ip=quic requires a non-empty id (SNI) for the ClientHello"
        ));
    }

    let mut exts = Vec::new();
    // supported_groups: x25519
    let mut groups = Vec::new();
    append_vec16(&mut groups, &[0x00, 0x1d]);
    append_extension(&mut exts, 0x000a, &groups);
    // signature_algorithms
    let sig_algs: &[u8] = &[
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02,
        0x01,
    ];
    let mut sig_vec = Vec::new();
    append_vec16(&mut sig_vec, sig_algs);
    append_extension(&mut exts, 0x000d, &sig_vec);
    // server_name
    let mut sni_entry = vec![0x00];
    append_vec16(&mut sni_entry, sni.as_bytes());
    let mut sni_list = Vec::new();
    append_vec16(&mut sni_list, &sni_entry);
    append_extension(&mut exts, 0x0000, &sni_list);
    // key_share: x25519
    let mut ks = Vec::new();
    ks.extend_from_slice(&0x001du16.to_be_bytes());
    append_vec16(&mut ks, x25519_pub);
    let mut ks_vec = Vec::new();
    append_vec16(&mut ks_vec, &ks);
    append_extension(&mut exts, 0x0033, &ks_vec);
    // quic_transport_params
    append_extension(&mut exts, 0x0039, &append_quic_transport_params());
    // GREASE
    append_extension(&mut exts, 0x0a0a, &[0x00, 0x00, 0x00]);
    // psk_key_exchange_modes
    append_extension(&mut exts, 0x002d, &[0x01, 0x01]);
    // ALPN h3
    let mut alpn = Vec::new();
    append_vec16(&mut alpn, &[0x02, b'h', b'3']);
    append_extension(&mut exts, 0x0010, &alpn);
    // compress_certificate: brotli
    append_extension(&mut exts, 0x001b, &[0x02, 0x00, 0x02]);
    // supported_versions: TLS 1.3
    append_extension(&mut exts, 0x002b, &[0x02, 0x03, 0x04]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(tls_random);
    body.push(0x00); // session_id empty
    append_vec16(&mut body, &[0x13, 0x01]); // cipher_suites
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    const HANDSHAKE_HDR: usize = 4;
    const EXTS_LEN_PREFIX: usize = 2;
    const PAD_EXT_HDR: usize = 4;
    let current = HANDSHAKE_HDR + body.len() + EXTS_LEN_PREFIX + exts.len();
    let pad = QUIC_CH_TARGET_LEN.saturating_sub(current + PAD_EXT_HDR);
    append_extension(&mut exts, 0x0015, &vec![0u8; pad]);

    append_vec16(&mut body, &exts);

    let mut out = Vec::with_capacity(HANDSHAKE_HDR + body.len());
    out.push(0x01);
    let blen = body.len();
    out.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    out.extend_from_slice(&body);

    if out.len() < QUIC_CH_MIN_LEN {
        return Err(anyhow!(
            "amneziawg: ClientHello assembled shorter than the minimum fragmentable length"
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Fragment plan + wire order.
// ---------------------------------------------------------------------------

const QUIC_INITIAL_TOTAL_LEN: usize = 1250;
const QUIC_PACKET_NUMBER_LEN: usize = 1;
const QUIC_AEAD_TAG_LEN: usize = 16;
const QUIC_DCID_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Crypto,
    Ping,
    Padding,
}

#[derive(Debug, Clone, Copy)]
struct PlanEntry {
    kind: FrameKind,
    crypto_idx: usize,
    pad_len: usize,
    pad_flex: bool,
}

#[derive(Debug, Clone)]
struct CryptoFragment {
    offset: u64,
    data: Vec<u8>,
}

/// Slice the ClientHello into `n` contiguous fragments at random interior cut
/// points (reference `planFragmentsN`); returned in offset order (I4).
fn plan_fragments_n(ch: &[u8], n: usize) -> anyhow::Result<Vec<CryptoFragment>> {
    if n < 2 {
        return Err(anyhow!("amneziawg: need ≥2 CRYPTO fragments"));
    }
    if ch.len() < n {
        return Err(anyhow!(
            "amneziawg: ClientHello too short for the requested fragment count"
        ));
    }
    use std::collections::HashSet;
    let mut cut_set: HashSet<usize> = HashSet::with_capacity(n - 1);
    let interior = ch.len() - 1;
    while cut_set.len() < n - 1 {
        cut_set.insert(1 + rand_int(interior));
    }
    let mut cuts: Vec<usize> = Vec::with_capacity(n + 1);
    cuts.push(0);
    cuts.extend(cut_set.iter().copied());
    cuts.push(ch.len());
    cuts.sort_unstable();

    let mut frags = Vec::with_capacity(n);
    for i in 0..n {
        frags.push(CryptoFragment {
            offset: cuts[i] as u64,
            data: ch[cuts[i]..cuts[i + 1]].to_vec(),
        });
    }
    Ok(frags)
}

/// Out-of-order wire plan with I1–I3 by construction (reference
/// `randomizedWirePlan`): the offset-0 fragment is never first, PINGs and
/// PADDING runs weave into the gaps after crypto frames, one PADDING is flex.
fn randomized_wire_plan(n_frags: usize, pings: usize) -> anyhow::Result<Vec<PlanEntry>> {
    if n_frags < 2 {
        return Err(anyhow!(
            "amneziawg: need ≥2 CRYPTO fragments for a wire plan"
        ));
    }
    let pings = pings.max(1);

    let mut order: Vec<usize> = (0..n_frags).collect();
    for i in (1..n_frags).rev() {
        let j = rand_int(i + 1);
        order.swap(i, j);
    }
    if order[0] == 0 {
        order.swap(0, 1);
    }

    let crypto_entries: Vec<PlanEntry> = order
        .into_iter()
        .map(|idx| PlanEntry {
            kind: FrameKind::Crypto,
            crypto_idx: idx,
            pad_len: 0,
            pad_flex: false,
        })
        .collect();

    let pad_runs = pings + 2;
    let flex_pick = rand_int(pad_runs);
    let mut fillers = Vec::with_capacity(pings + pad_runs);
    for _ in 0..pings {
        fillers.push(PlanEntry {
            kind: FrameKind::Ping,
            crypto_idx: 0,
            pad_len: 0,
            pad_flex: false,
        });
    }
    for i in 0..pad_runs {
        let (pad_len, pad_flex) = if i == flex_pick {
            (0, true)
        } else {
            (8 + rand_int(48), false)
        };
        fillers.push(PlanEntry {
            kind: FrameKind::Padding,
            crypto_idx: 0,
            pad_len,
            pad_flex,
        });
    }

    let mut gaps: Vec<Vec<PlanEntry>> = vec![Vec::new(); n_frags];
    for f in fillers {
        let slot = rand_int(n_frags);
        gaps[slot].push(f);
    }
    let mut plan = Vec::with_capacity(n_frags + gaps.iter().map(Vec::len).sum::<usize>());
    for (i, c) in crypto_entries.into_iter().enumerate() {
        plan.push(c);
        plan.append(&mut gaps[i]);
    }
    Ok(plan)
}

fn append_crypto_frame(dst: &mut Vec<u8>, f: &CryptoFragment) {
    dst.push(0x06);
    append_quic_varint(dst, f.offset);
    append_quic_varint(dst, f.data.len() as u64);
    dst.extend_from_slice(&f.data);
}

fn plan_fixed_len(frags: &[CryptoFragment], plan: &[PlanEntry]) -> (usize, bool) {
    let mut total = 0;
    let mut flex = false;
    for e in plan {
        match e.kind {
            FrameKind::Crypto => {
                let f = &frags[e.crypto_idx];
                total += 1 + varint_len(f.offset) + varint_len(f.data.len() as u64) + f.data.len();
            }
            FrameKind::Ping => total += 1,
            FrameKind::Padding => {
                if e.pad_flex {
                    flex = true;
                } else {
                    total += e.pad_len;
                }
            }
        }
    }
    (total, flex)
}

fn build_initial_payload(
    frags: &[CryptoFragment],
    plan: &[PlanEntry],
    target_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let (fixed, has_flex) = plan_fixed_len(frags, plan);
    if !has_flex {
        return Err(anyhow!(
            "amneziawg: wire plan has no flex PADDING run to absorb slack"
        ));
    }
    let flex_len = target_len
        .checked_sub(fixed)
        .ok_or_else(|| anyhow!("amneziawg: QUIC Initial frames overflow the length field"))?;

    let mut out = Vec::with_capacity(target_len);
    for e in plan {
        match e.kind {
            FrameKind::Crypto => append_crypto_frame(&mut out, &frags[e.crypto_idx]),
            FrameKind::Ping => out.push(0x01),
            FrameKind::Padding => {
                let n = if e.pad_flex { flex_len } else { e.pad_len };
                out.extend(std::iter::repeat_n(0u8, n));
            }
        }
    }
    if out.len() != target_len {
        return Err(anyhow!(
            "amneziawg: QUIC Initial payload did not land on the length field"
        ));
    }
    Ok(out)
}

/// Assemble one complete QUIC v1 Initial datagram (reference
/// `buildInitialPacket`): fresh DCID/random/key/layout per call, pn_len=1,
/// pn=0.
fn build_initial_packet(sni: &str, browser: &str) -> anyhow::Result<Vec<u8>> {
    // chrome/firefox fall back to the generic CH (reference no-uTLS stub).
    let _ = browser;

    let mut dcid = [0u8; QUIC_DCID_LEN];
    awg::fill_random(&mut dcid);
    let mut tls_random = [0u8; 32];
    awg::fill_random(&mut tls_random);
    let mut e_priv = [0u8; 32];
    awg::fill_random(&mut e_priv);
    let e_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(e_priv));

    let client_hello = build_generic_client_hello(sni, &tls_random, e_pub.as_bytes())?;

    const FRAGMENTS: usize = 6;
    const PINGS: usize = 2;
    let frags = plan_fragments_n(&client_hello, FRAGMENTS)?;
    let plan = randomized_wire_plan(frags.len(), PINGS)?;

    let total_len = QUIC_INITIAL_TOTAL_LEN;
    const HEADER_FIXED: usize = 1 + 4 + 1 + 1 + 1; // first + version + dcidLen + scidLen + tokenLen
    const LEN_FIELD_WIDTH: usize = 2;
    let header_len = HEADER_FIXED + QUIC_DCID_LEN + LEN_FIELD_WIDTH + QUIC_PACKET_NUMBER_LEN;
    let payload_len = total_len - header_len - QUIC_AEAD_TAG_LEN;
    let length_field = QUIC_PACKET_NUMBER_LEN + payload_len + QUIC_AEAD_TAG_LEN;
    if !((1 << 6)..(1 << 14)).contains(&length_field) {
        return Err(anyhow!(
            "amneziawg: QUIC Initial length field outside 2-byte varint range"
        ));
    }

    let payload = build_initial_payload(&frags, &plan, payload_len)?;

    let mut header = Vec::with_capacity(header_len);
    header.push(0xC0 | (QUIC_PACKET_NUMBER_LEN as u8 - 1));
    header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    header.push(QUIC_DCID_LEN as u8);
    header.extend_from_slice(&dcid);
    header.push(0x00); // SCID length 0
    header.push(0x00); // token length 0
    append_quic_varint(&mut header, length_field as u64);
    let pn_offset = header.len();
    header.push(0x00); // packet number 0

    let (key, iv, hp) = derive_initial_keys(&dcid);
    let packet = encrypt_initial(&header, &payload, &key, &iv, &hp, pn_offset)?;
    if packet.len() != total_len {
        return Err(anyhow!(
            "amneziawg: QUIC Initial assembled to unexpected size"
        ));
    }
    Ok(packet)
}

/// Compile the QUIC Initial decoy into a single static-bytes CPS chain.
pub(crate) fn quic_initial_chain(domain: &str, browser: &str) -> anyhow::Result<JunkChain> {
    let packet = build_initial_packet(domain, browser)?;
    Ok(vec![Obf::Bytes(packet)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_and_lengths() {
        for (v, width) in [
            (0u64, 1),
            (63, 1),
            (64, 2),
            (16383, 2),
            (16384, 4),
            (1232, 2),
        ] {
            assert_eq!(varint_len(v), width);
            let mut b = Vec::new();
            append_quic_varint(&mut b, v);
            assert_eq!(b.len(), width);
        }
        let mut b = Vec::new();
        append_quic_varint(&mut b, 1232);
        assert_eq!(b, vec![0x44, 0xD0]);
    }

    #[test]
    fn client_hello_shape() {
        let mut rng = [0u8; 32];
        awg::fill_random(&mut rng);
        let ch = build_generic_client_hello("warp.example.com", &rng, &[7u8; 32]).unwrap();
        assert_eq!(ch[0], 0x01); // ClientHello
        assert_eq!(&ch[1..4], &[0x00, 0x01, 0x22]); // u24 length 294-4 = 290
        assert_eq!(ch.len(), QUIC_CH_TARGET_LEN);
        assert!(windows_find(&ch, b"warp.example.com"));
        assert!(windows_find(&ch, b"h3"));
        // key_share carries the 32-byte key
        assert!(windows_find(&ch, &[7u8; 32]));
    }

    fn windows_find(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Reverse-parser round-trip: unmask the header, derive the Initial keys
    /// from the DCID, decrypt, walk the CRYPTO frames, reassemble — the
    /// reassembled ClientHello must be contiguous and contain the SNI.
    #[test]
    fn initial_decrypt_reassemble() {
        let sni = "mask.example.org";
        let packet = build_initial_packet(sni, "").unwrap();
        assert_eq!(packet.len(), QUIC_INITIAL_TOTAL_LEN);

        // DCID is plaintext in the long header.
        let dcid: [u8; 8] = packet[6..14].try_into().unwrap();
        let (key, iv, hp) = derive_initial_keys(&dcid);

        // Unmask: AES-ECB(hp, ct[pn_offset+4..+20]); first byte low 4 bits, pn byte.
        let pn_offset = 18usize;
        let mask = aes_ecb_block(&hp, &packet[pn_offset + 4..pn_offset + 20]);
        let mut plain = packet.clone();
        plain[0] ^= mask[0] & 0x0f;
        plain[pn_offset] ^= mask[1];
        assert_eq!(plain[0] & 0x80, 0x80); // long header
        assert_eq!(&plain[1..5], &QUIC_VERSION_1.to_be_bytes());

        let payload = {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
            let nonce = iv; // pn = 0 → the XORed nonce is exactly the IV
            cipher
                .decrypt(
                    &nonce.into(),
                    Payload {
                        msg: &plain[19..],
                        aad: &plain[..19],
                    },
                )
                .expect("initial decrypt")
        };

        // Frame walk: collect CRYPTO (offset, data); check invariants I1–I4.
        let mut first_crypto_offset: Option<u64> = None;
        let mut frags: Vec<(u64, &[u8])> = Vec::new();
        let mut i = 0;
        while i < payload.len() {
            match payload[i] {
                0x00 => i += 1, // PADDING
                0x01 => i += 1, // PING
                0x06 => {
                    i += 1;
                    let (off, n) = read_varint(&payload[i..]);
                    i += n;
                    let (len, n2) = read_varint(&payload[i..]);
                    i += n2;
                    if first_crypto_offset.is_none() {
                        first_crypto_offset = Some(off);
                    }
                    frags.push((off, &payload[i..i + len as usize]));
                    i += len as usize;
                }
                other => panic!("unexpected frame byte {other:#x} at {i}"),
            }
        }
        // I1: first CRYPTO on the wire has offset ≠ 0.
        assert_ne!(first_crypto_offset, Some(0));
        // I4: reassembles contiguously from 0.
        frags.sort_by_key(|(off, _)| *off);
        assert_eq!(frags[0].0, 0);
        let mut expected_off = 0u64;
        let mut reassembled = Vec::new();
        for (off, data) in &frags {
            assert_eq!(*off, expected_off, "fragment gap/overlap");
            expected_off += data.len() as u64;
            reassembled.extend_from_slice(data);
        }
        // The reassembled ClientHello carries the SNI and matches the builder.
        assert!(windows_find(&reassembled, sni.as_bytes()));
        // (random differs per call — verify structural equality by re-parse)
        assert_eq!(reassembled[0], 0x01);
        let blen = ((reassembled[1] as usize) << 16)
            | ((reassembled[2] as usize) << 8)
            | reassembled[3] as usize;
        assert_eq!(reassembled.len(), 4 + blen);
    }

    fn read_varint(b: &[u8]) -> (u64, usize) {
        let first = b[0];
        let (len, value_base) = match first >> 6 {
            0 => (1, (first & 0x3f) as u64),
            1 => (2, (first & 0x3f) as u64),
            2 => (4, (first & 0x3f) as u64),
            _ => (8, (first & 0x3f) as u64),
        };
        let mut v = value_base;
        for byte in &b[1..len] {
            v = (v << 8) | *byte as u64;
        }
        (v, len)
    }
}

#[cfg(test)]
mod mirror {
    use super::*;

    #[test]
    fn enc_dec_mirror() {
        let dcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (key, iv, hp) = derive_initial_keys(&dcid);
        eprintln!("M key {:02x?}", key);
        let mut header = Vec::new();
        header.push(0xC0);
        header.extend_from_slice(&1u32.to_be_bytes());
        header.push(8);
        header.extend_from_slice(&dcid);
        header.push(0);
        header.push(0);
        append_quic_varint(&mut header, 1232);
        assert_eq!(header.len(), 18);
        header.push(0x00);
        let payload = vec![0x42u8; 100];
        let pkt = encrypt_initial(&header, &payload, &key, &iv, &hp, 18).unwrap();
        // bisect 1: AES-ECB known vector (FIPS-197 appendix C.1)
        let z = aes_ecb_block(&[0u8; 16], &[0u8; 16]);
        eprintln!(
            "M ecb(0,0) = {:02x?} (want 66e94bd4ef8a2c3b884cfa59ca342b2e)",
            z
        );
        // bisect 2: plain GCM roundtrip with the same helpers
        {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let c = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
            let sealed = c
                .encrypt(
                    &iv.into(),
                    Payload {
                        msg: &payload,
                        aad: &header,
                    },
                )
                .unwrap();
            eprintln!("M sealed len {}", sealed.len());
            let opened = c
                .decrypt(
                    &iv.into(),
                    Payload {
                        msg: &sealed,
                        aad: &header,
                    },
                )
                .expect("direct gcm roundtrip");
            assert_eq!(opened, payload);
            eprintln!(
                "M direct gcm roundtrip OK; ct match = {}",
                sealed == pkt[19..]
            );
        }
        let mask = aes_ecb_block(&hp, &pkt[22..38]);
        eprintln!("M mask {:02x?}", mask);
        let mut plain = pkt.clone();
        plain[0] ^= mask[0] & 0x0f;
        plain[18] ^= mask[1];
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
        let mut nonce = iv;
        for i in 0..8 {
            nonce[4 + i] ^= 0u8;
        }
        let out = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &plain[19..],
                    aad: &plain[..19],
                },
            )
            .expect("mirror decrypt");
        assert_eq!(out, payload);
        eprintln!("M MIRROR OK");
    }
}
