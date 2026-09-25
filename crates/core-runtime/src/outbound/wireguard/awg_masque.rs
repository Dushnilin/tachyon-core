//! AmneziaWG masquerade profiles (SPEC 009): WireSock-style declarative
//! `id`/`ip`/`ib` sugar compiled into i1/i2 CPS junk chains.
//!
//! Wire semantics ported from sing-box-lx `transport/wireguard/{masque_awg,
//! pseudo_gen_awg,stun_request_awg,sip_invite_awg}.go`. Like the reference,
//! every decoy is a self-contained packet (the CPS renders with a nil
//! source): DNS/STUN use `<r N>` entropy tags for fresh per-packet fields;
//! the SIP dialog identifiers must match across i1/i2, so both halves are
//! baked into static bytes at build time.
//!
//! The QUIC profile (fragmented Initial with a real ClientHello) is not
//! ported yet — `ip=quic` is rejected explicitly.

use anyhow::anyhow;

use super::awg::{self, JunkChain, Obf};

const PG_CONS: &[&str] = &[
    "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "z",
];
const PG_VOW: &[&str] = &["a", "e", "i", "o", "u"];
const PG_ONSET: &[&str] = &[
    "br", "tr", "cr", "dr", "fr", "gr", "pr", "st", "sp", "sk", "sl", "sm", "sn", "bl", "cl", "fl",
    "gl", "pl", "tw", "sh",
];
const PG_CODA: &[&str] = &["lk", "sk", "st", "nk", "sh", "nt", "rk", "ng"];
const PG_TLD: &[&str] = &["com", "net", "org", "io", "co"];

/// Uniform pick in `[0, n)` from the engine RNG.
fn pg_intn(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut b = [0u8; 8];
    awg::fill_random(&mut b);
    (u64::from_le_bytes(b) % n as u64) as usize
}

fn pg_pick(seq: &[&'static str]) -> &'static str {
    seq[pg_intn(seq.len())]
}

fn pg_chance(pct: u32) -> bool {
    pg_intn(100) < pct as usize
}

/// Pronounceable syllabic word (reference `pgWord`).
fn pg_word() -> String {
    let mut b = String::new();
    b.push_str(pg_pick(PG_CONS));
    b.push_str(pg_pick(PG_VOW));
    let blocks = 2 + pg_intn(2);
    for _ in 0..blocks {
        if pg_chance(60) {
            b.push_str(pg_pick(PG_CONS));
        } else {
            b.push_str(pg_pick(PG_ONSET));
        }
        b.push_str(pg_pick(PG_VOW));
    }
    if pg_chance(50) {
        if pg_chance(30) {
            b.push_str(pg_pick(PG_CODA));
        } else {
            b.push_str(pg_pick(PG_CONS));
        }
    }
    b
}

fn pg_user() -> String {
    let u = pg_word();
    if pg_chance(30) {
        format!("{u}_{}", pg_word())
    } else {
        u
    }
}

fn pg_hex(n: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    (0..n).map(|_| HEX[pg_intn(16)] as char).collect()
}

fn pg_digits(n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(n);
    out.push((b'1' + pg_intn(9) as u8) as char);
    for _ in 1..n {
        out.push((b'0' + pg_intn(10) as u8) as char);
    }
    out
}

/// Pseudo domain only — never an IP or `sip.`-prefixed (reference
/// `pgDomainHost`).
fn pg_domain_host() -> String {
    if pg_intn(100) < 60 {
        format!("{}.{}.{}", pg_word(), pg_word(), pg_pick(PG_TLD))
    } else {
        format!("{}.{}", pg_word(), pg_pick(PG_TLD))
    }
}

fn sip_capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) if f.is_ascii_lowercase() => f.to_ascii_uppercase().to_string() + c.as_str(),
        Some(f) => f.to_string() + c.as_str(),
        None => String::new(),
    }
}

/// Strict LDH hostname check (mirror of the reference `validateMasqueDomain`).
pub(crate) fn validate_masque_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("amneziawg: id (masquerade domain) is required when ip/ib is set".to_string());
    }
    let name = domain.strip_suffix('.').unwrap_or(domain);
    if name.is_empty() || name.len() > 253 {
        return Err(format!(
            "amneziawg: invalid masquerade domain {domain:?}: empty or longer than 253 bytes"
        ));
    }
    if name.starts_with('.') {
        return Err(format!(
            "amneziawg: invalid masquerade domain {domain:?}: leading dot"
        ));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: label longer than 63 bytes"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: label with leading/trailing hyphen"
            ));
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(format!(
                "amneziawg: invalid masquerade domain {domain:?}: illegal character (only a-z A-Z 0-9 - _ allowed)"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS — EDNS OPT query (QR=0).
// ---------------------------------------------------------------------------

const DNS_OPT_UDP_SIZE: u16 = 1232;
const DNS_OPT_COVER_CODE: u16 = 0xFDE9;
const DNS_COVER_LEN: usize = 40;
const DNS_QTYPE_HTTPS: u16 = 0x0041;

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn encode_dns_name(domain: &str) -> Vec<u8> {
    let name = domain.strip_suffix('.').unwrap_or(domain);
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0x00);
    out
}

fn dns_query_chain(domain: &str) -> JunkChain {
    let qname = encode_dns_name(domain);
    let mut question = qname;
    question.extend_from_slice(&be16(DNS_QTYPE_HTTPS));
    question.extend_from_slice(&[0x00, 0x01]);

    const OPT_OPTION_HDR_LEN: u16 = 4;
    let opt_len = DNS_COVER_LEN as u16;
    let rd_length = OPT_OPTION_HDR_LEN + opt_len;

    let mut opt: Vec<u8> = vec![
        0x00, // NAME: root label
        0x00, 0x29, // TYPE = OPT
    ];
    opt.extend_from_slice(&be16(DNS_OPT_UDP_SIZE));
    opt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
    opt.extend_from_slice(&be16(rd_length));
    opt.extend_from_slice(&be16(DNS_OPT_COVER_CODE));
    opt.extend_from_slice(&be16(opt_len));

    // Header: <r 2> TXID + static flags/counts.
    let mut header = Vec::new();
    header.extend_from_slice(&[0x01, 0x00]); // RD=1 query
    header.extend_from_slice(&be16(1)); // QDCOUNT
    header.extend_from_slice(&be16(0)); // ANCOUNT
    header.extend_from_slice(&be16(0)); // NSCOUNT
    header.extend_from_slice(&be16(1)); // ARCOUNT

    vec![
        Obf::Rand(2),
        Obf::Bytes(header),
        Obf::Bytes(question),
        Obf::Bytes(opt),
        Obf::Rand(DNS_COVER_LEN),
    ]
}

// ---------------------------------------------------------------------------
// STUN — WebRTC Binding Request with MESSAGE-INTEGRITY + FINGERPRINT.
// ---------------------------------------------------------------------------

const STUN_TYPE_BINDING_REQUEST: u16 = 0x0001;
const STUN_ATTR_USERNAME: u16 = 0x0006;
const STUN_ATTR_MSG_INTEGRITY: u16 = 0x0008;
const STUN_ATTR_PRIORITY: u16 = 0x0024;
const STUN_ATTR_SOFTWARE: u16 = 0x8022;
const STUN_ATTR_ICE_CONTROLLING: u16 = 0x802A;
const STUN_ATTR_FINGERPRINT: u16 = 0x8028;
const STUN_FINGERPRINT_XOR: u32 = 0x5354_554E;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_SOFTWARE_PRODUCT: &[u8] = b"libwebrtc";

fn append_stun_attr(dst: &mut Vec<u8>, typ: u16, val: &[u8]) {
    dst.extend_from_slice(&typ.to_be_bytes());
    dst.extend_from_slice(&(val.len() as u16).to_be_bytes());
    dst.extend_from_slice(val);
    while !dst.len().is_multiple_of(4) {
        dst.push(0x00);
    }
}

fn stun_ice_username(seed: &[u8]) -> Vec<u8> {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(9);
    for i in 0..4 {
        out.push(HEX[seed[i] as usize % 16]);
    }
    out.push(b':');
    for i in 4..8 {
        out.push(HEX[seed[i] as usize % 16]);
    }
    out
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn build_stun_binding_request() -> Vec<u8> {
    let mut txn = [0u8; 12];
    awg::fill_random(&mut txn);
    let mut ufrag = [0u8; 8];
    awg::fill_random(&mut ufrag);
    let mut tie = [0u8; 8];
    awg::fill_random(&mut tie);
    let mut prio = [0u8; 4];
    awg::fill_random(&mut prio);
    let mut integrity_key = [0u8; 16];
    awg::fill_random(&mut integrity_key);

    let username = stun_ice_username(&ufrag);

    let mut attrs = Vec::new();
    append_stun_attr(&mut attrs, STUN_ATTR_USERNAME, &username);
    append_stun_attr(&mut attrs, STUN_ATTR_ICE_CONTROLLING, &tie);
    append_stun_attr(&mut attrs, STUN_ATTR_PRIORITY, &prio);
    append_stun_attr(&mut attrs, STUN_ATTR_SOFTWARE, STUN_SOFTWARE_PRODUCT);

    const MI_ATTR_TOTAL: usize = 24;
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&STUN_TYPE_BINDING_REQUEST.to_be_bytes());
    header.extend_from_slice(&(attrs.len() as u16 + MI_ATTR_TOTAL as u16).to_be_bytes());
    header.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    header.extend_from_slice(&txn);

    let mut pre_mi = header;
    pre_mi.extend_from_slice(&attrs);
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(&integrity_key).expect("hmac key");
    Mac::update(&mut mac, &pre_mi);
    let mi = mac.finalize().into_bytes();
    let mut with_mi = pre_mi;
    append_stun_attr(&mut with_mi, STUN_ATTR_MSG_INTEGRITY, &mi);

    const FP_ATTR_TOTAL: usize = 8;
    let mi_len = u16::from_be_bytes([with_mi[2], with_mi[3]]);
    let fp_len = mi_len + FP_ATTR_TOTAL as u16;
    with_mi[2..4].copy_from_slice(&fp_len.to_be_bytes());
    let crc = crc32_ieee(&with_mi) ^ STUN_FINGERPRINT_XOR;

    let mut pkt = with_mi;
    append_stun_attr(&mut pkt, STUN_ATTR_FINGERPRINT, &crc.to_be_bytes());
    pkt
}

fn stun_request_chain() -> JunkChain {
    vec![Obf::Bytes(build_stun_binding_request())]
}

// ---------------------------------------------------------------------------
// SIP — INVITE (i1) + 100 Trying (i2), one dialog.
// ---------------------------------------------------------------------------

struct SipDialog {
    callee_host: String,
    caller_dom: String,
    ua_host: String,
    from_user: String,
    to_user: String,
    from_disp: String,
    to_disp: String,
    branch: String,
    tag: String,
    call_id: String,
    cseq: String,
}

fn new_sip_dialog(domain: &str) -> SipDialog {
    let caller_dom = domain.strip_suffix('.').unwrap_or(domain).to_string();
    let caller_dom = if caller_dom.is_empty() {
        pg_domain_host()
    } else {
        caller_dom
    };
    let from_user = pg_user();
    let to_user = pg_user();
    SipDialog {
        callee_host: pg_domain_host(),
        ua_host: format!("pc{}.{caller_dom}", pg_digits(2)),
        caller_dom,
        from_disp: sip_capitalize(&from_user),
        to_disp: sip_capitalize(&to_user),
        from_user,
        to_user,
        branch: pg_hex(16),
        tag: pg_digits(10),
        call_id: pg_hex(14),
        cseq: pg_digits(6),
    }
}

fn sip_invite_bytes(d: &SipDialog) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(&format!(
        "INVITE sip:{}@{} SIP/2.0\r\n",
        d.to_user, d.callee_host
    ));
    s.push_str(&format!(
        "Via: SIP/2.0/UDP {};branch=z9hG4bK{}\r\n",
        d.ua_host, d.branch
    ));
    s.push_str("Max-Forwards: 70\r\n");
    s.push_str(&format!(
        "To: {} <sip:{}@{}>\r\n",
        d.to_disp, d.to_user, d.callee_host
    ));
    s.push_str(&format!(
        "From: {} <sip:{}@{}>;tag={}\r\n",
        d.from_disp, d.from_user, d.caller_dom, d.tag
    ));
    s.push_str(&format!("Call-ID: {}@{}\r\n", d.call_id, d.ua_host));
    s.push_str(&format!("CSeq: {} INVITE\r\n", d.cseq));
    s.push_str(&format!("Contact: <sip:{}@{}>\r\n", d.from_user, d.ua_host));
    s.push_str("Content-Type: application/sdp\r\n");
    s.push_str("Content-Length: 0\r\n\r\n");
    s.into_bytes()
}

fn sip_trying_bytes(d: &SipDialog) -> Vec<u8> {
    let mut s = String::new();
    s.push_str("SIP/2.0 100 Trying\r\n");
    s.push_str(&format!(
        "Via: SIP/2.0/UDP {};branch=z9hG4bK{}\r\n",
        d.ua_host, d.branch
    ));
    s.push_str(&format!(
        "To: {} <sip:{}@{}>\r\n",
        d.to_disp, d.to_user, d.callee_host
    ));
    s.push_str(&format!(
        "From: {} <sip:{}@{}>;tag={}\r\n",
        d.from_disp, d.from_user, d.caller_dom, d.tag
    ));
    s.push_str(&format!("Call-ID: {}@{}\r\n", d.call_id, d.ua_host));
    s.push_str(&format!("CSeq: {} INVITE\r\n", d.cseq));
    s.push_str("Content-Length: 0\r\n\r\n");
    s.into_bytes()
}

fn sip_chains(d: &SipDialog) -> (JunkChain, JunkChain) {
    (
        vec![Obf::Bytes(sip_invite_bytes(d))],
        vec![Obf::Bytes(sip_trying_bytes(d))],
    )
}

/// Compile the `id`/`ip`/`ib` sugar into i1 (+i2 for `ip=sip`) CPS chains.
/// `Ok(None)` when no masquerade is configured. Validation mirrors
/// `masqueI1` in the reference so runtime rejects exactly what `check`
/// rejects; the QUIC profile is an explicit not-implemented error.
pub(crate) fn masque_i1_i2(
    id: &str,
    ip: &str,
    ib: &str,
    explicit_i1: bool,
    explicit_i2: bool,
    at: &str,
) -> anyhow::Result<Option<(JunkChain, JunkChain)>> {
    if id.is_empty() && ip.is_empty() && ib.is_empty() {
        return Ok(None);
    }
    if explicit_i1 {
        return Err(anyhow!(
            "{at}: amneziawg: id/ip/ib masquerade conflicts with an explicit i1; use one or the other"
        ));
    }
    let proto = ip.trim().to_lowercase();
    if proto.is_empty() {
        return Err(anyhow!(
            "{at}: amneziawg: ip (masquerade protocol) is required when id/ib is set; one of quic|dns|stun|sip"
        ));
    }
    let domain = id.trim();
    if !domain.is_empty() {
        validate_masque_domain(domain).map_err(|m| anyhow!("{at}: {m}"))?;
    }
    let browser = ib.trim().to_lowercase();
    if !browser.is_empty() {
        if !matches!(browser.as_str(), "chrome" | "firefox" | "curl") {
            return Err(anyhow!(
                "{at}: amneziawg: unknown masquerade browser {ib:?}; one of chrome|firefox|curl"
            ));
        }
        if proto != "quic" {
            return Err(anyhow!(
                "{at}: amneziawg: ib (browser) is only meaningful with ip=quic, got ip={proto:?}"
            ));
        }
    }
    let _ = browser;
    match proto.as_str() {
        "quic" => {
            if domain.is_empty() {
                return Err(anyhow!(
                    "{at}: amneziawg: id (masquerade domain) is required for ip=quic (it becomes the ClientHello SNI)"
                ));
            }
            Ok(Some((
                super::awg_quic::quic_initial_chain(domain, &browser)?,
                Vec::new(),
            )))
        }
        "stun" => Ok(Some((stun_request_chain(), Vec::new()))),
        "dns" => {
            let domain = if domain.is_empty() {
                pg_domain_host()
            } else {
                domain.to_string()
            };
            Ok(Some((dns_query_chain(&domain), Vec::new())))
        }
        "sip" => {
            if explicit_i2 {
                return Err(anyhow!(
                    "{at}: amneziawg: id/ip/ib masquerade (ip=sip) fills i2; an explicit i2 conflicts with it"
                ));
            }
            let d = new_sip_dialog(domain);
            Ok(Some(sip_chains(&d)))
        }
        other => Err(anyhow!(
            "{at}: amneziawg: unknown masquerade protocol {other:?}; one of quic|dns|stun|sip"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudogen_shapes() {
        for _ in 0..20 {
            let d = pg_domain_host();
            assert!(!d.starts_with("sip."));
            assert!(!d.contains(".."));
            assert!(d.contains('.'));
            let u = pg_user();
            assert!(!u.is_empty());
            assert!(u.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
        assert_eq!(pg_digits(0), "");
        assert_ne!(pg_digits(10).chars().next().unwrap(), '0');
        assert_eq!(pg_hex(4).len(), 4);
    }

    #[test]
    fn domain_validation() {
        assert!(validate_masque_domain("good.example.com").is_ok());
        assert!(validate_masque_domain("a_b-c.example.io").is_ok());
        assert!(validate_masque_domain("").is_err());
        assert!(validate_masque_domain("..bad..").is_err());
        assert!(validate_masque_domain("-lead.example.com").is_err());
    }

    #[test]
    fn dns_chain_shape() {
        let chain = dns_query_chain("hello.example.com");
        let len = awg::chain_len(&chain);
        // 12 header + qname + 4 question + 11 opt prefix + 4 opt hdr + 40 cover
        let qname_len = "hello.example.com".len() + 2;
        assert_eq!(len, 12 + qname_len + 4 + 11 + 4 + 40);
        let out = awg::render_chain(&chain);
        // QR=0, opcode 0, RD=1
        assert_eq!(out[2], 0x01);
        assert_eq!(&out[4..6], &1u16.to_be_bytes());
        assert_eq!(&out[10..12], &1u16.to_be_bytes());
    }

    #[test]
    fn stun_chain_shape_and_crypto() {
        let chain = stun_request_chain();
        assert_eq!(chain.len(), 1);
        let pkt = match &chain[0] {
            Obf::Bytes(b) => b.clone(),
            _ => panic!("bytes"),
        };
        assert_eq!(&pkt[0..2], &STUN_TYPE_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&pkt[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
        // FINGERPRINT: crc over everything before the attr, xor the magic.
        let fp_at = pkt.len() - 8;
        let crc = crc32_ieee(&pkt[..fp_at]) ^ STUN_FINGERPRINT_XOR;
        assert_eq!(&pkt[fp_at + 4..fp_at + 8], &crc.to_be_bytes());
    }

    #[test]
    fn sip_dialog_identity_shared() {
        let d = new_sip_dialog("caller.example.com");
        let (i1, i2) = sip_chains(&d);
        let invite = match &i1[0] {
            Obf::Bytes(b) => String::from_utf8(b.clone()).unwrap(),
            _ => panic!("bytes"),
        };
        let trying = match &i2[0] {
            Obf::Bytes(b) => String::from_utf8(b.clone()).unwrap(),
            _ => panic!("bytes"),
        };
        assert!(invite.starts_with("INVITE sip:"));
        assert!(trying.starts_with("SIP/2.0 100 Trying\r\n"));
        // dialog identity shared verbatim
        assert!(trying.contains(&format!("Call-ID: {}@{}", d.call_id, d.ua_host)));
        assert!(invite.contains(&format!("Call-ID: {}@{}", d.call_id, d.ua_host)));
        assert!(invite.contains(&format!(";tag={}", d.tag)));
        assert!(trying.contains(&format!(";tag={}", d.tag)));
        assert!(invite.ends_with("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn masque_dispatch() {
        // nothing set → None
        assert!(
            masque_i1_i2("", "", "", false, false, "x")
                .unwrap()
                .is_none()
        );
        // explicit i1 conflict
        assert!(masque_i1_i2("d", "dns", "", true, false, "x").is_err());
        // missing protocol
        assert!(masque_i1_i2("d", "", "", false, false, "x").is_err());
        // quic: empty id rejected (SNI required), with id → ok
        assert!(masque_i1_i2("", "quic", "", false, false, "x").is_err());
        assert!(masque_i1_i2("d.example.com", "quic", "", false, false, "x").is_ok());
        // browser only meaningful with quic
        assert!(masque_i1_i2("d", "dns", "chrome", false, false, "x").is_err());
        // sip fills i2; explicit i2 conflicts
        let r = masque_i1_i2("caller.example.com", "sip", "", false, false, "x")
            .unwrap()
            .unwrap();
        assert_eq!(r.0.len(), 1);
        assert_eq!(r.1.len(), 1);
        assert!(masque_i1_i2("d", "sip", "", false, true, "x").is_err());
        // dns ok
        assert!(masque_i1_i2("", "dns", "", false, false, "x").is_ok());
        // stun ok
        assert!(masque_i1_i2("", "stun", "", false, false, "x").is_ok());
    }
}
