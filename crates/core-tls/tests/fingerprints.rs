//! Every vendored fingerprint rebuilds its own capture byte-for-byte.
//!
//! The captures are what the reference sent as a uTLS client
//! (tests/spikes/clienthello/captures, taken on sing-box-lx 1.14.2-lx.3). A
//! template that rebuilds its capture is the whole claim of ADR-0004: the
//! fingerprint is data we vendored, not a guess.

use std::path::PathBuf;

use core_tls::fingerprints;
use core_tls::hello::{build, parse_record};

fn capture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(if matches!(name, "chrome" | "firefox" | "safari") {
            "../../tests/spikes/clienthello/captures-sing-box-x"
        } else {
            "../../tests/spikes/clienthello/captures"
        })
        .join(format!("{name}.bin"))
}

fn alpn_of(hello: &core_tls::hello::ParsedHello) -> Vec<Vec<u8>> {
    hello
        .template
        .extensions
        .iter()
        .find_map(|ext| match ext {
            core_tls::hello::Ext::Static(0x0010, body) => Some(body.clone()),
            _ => None,
        })
        .map(|body| {
            // skip the 2-byte list length, then read the length-prefixed names
            let mut out = Vec::new();
            let mut off = 2;
            while off < body.len() {
                let len = body[off] as usize;
                off += 1;
                out.push(body[off..off + len].to_vec());
                off += len;
            }
            out
        })
        .unwrap_or_default()
}

/// The names the reference maps to a table of their own, and which therefore
/// have a capture to be diffed against. The six `chrome_*` aliases share the
/// chrome table in the reference, and `HelloChrome_Auto` picks a Chrome version
/// per handshake (three handshakes from one process give three different
/// hellos: tests/spikes/clienthello/chrome_stability.sh), so an alias capture
/// is some *other* version and cannot be diffed against our table.
const CANONICAL: &[&str] = &[
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
];

#[test]
fn every_table_rebuilds_its_capture() {
    for name in CANONICAL {
        let Some(template) = fingerprints::by_name(name) else {
            panic!("{name} has no table");
        };
        let path = capture(name);
        let data = std::fs::read(&path).expect("capture");
        let hello = parse_record(&data).expect("parse");

        let alpn = alpn_of(&hello);
        let alpn: Vec<&[u8]> = alpn.iter().map(|p| p.as_slice()).collect();
        let rebuilt = build(
            &template,
            &hello.random,
            &hello.session_id,
            &hello.sni,
            &alpn,
            None,
        )
        .expect("build");
        assert!(
            same_except_grease(&rebuilt, &data),
            "{name}: the rebuilt hello differs from the capture outside GREASE"
        );
    }
}

#[test]
fn modern_profiles_keep_hybrid_groups_shares_and_configured_alpn() {
    use core_tls::hello::Ext;
    use core_tls::keyshare::{MLKEM768_EK_LEN, Shares, X25519, X25519MLKEM768};
    for name in ["chrome", "firefox", "safari"] {
        let template = fingerprints::by_name(name).expect("modern profile");
        let again = fingerprints::by_name(name).expect("stable profile");
        assert_eq!(template.extensions, again.extensions);
        assert_eq!(template.cipher_suites, again.cipher_suites);
        let groups = template
            .extensions
            .iter()
            .find_map(|e| match e {
                Ext::Static(10, body) => Some(
                    body[2..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .expect("supported groups");
        let key_body = template
            .extensions
            .iter()
            .find_map(|e| match e {
                Ext::KeyShare(body) => Some(body),
                _ => None,
            })
            .expect("key shares");
        let shares = Shares::for_body(key_body).expect("fresh keys");
        assert!(groups.contains(&X25519MLKEM768));
        assert!(shares.public(X25519MLKEM768).is_some());
        if name == "firefox" {
            assert_eq!(
                shares.public(X25519).unwrap(),
                &shares.public(X25519MLKEM768).unwrap()[MLKEM768_EK_LEN..]
            );
        }
        let hello = build(
            &template,
            &[7; 32],
            &[0; 32],
            "example.com",
            &[b"h2"],
            Some(&shares),
        )
        .expect("build modern hello");
        assert_eq!(
            alpn_of(&parse_record(&hello).unwrap()),
            vec![b"h2".to_vec()]
        );
    }
}

#[test]
fn the_names_the_reference_accepts_all_resolve() {
    for name in fingerprints::NAMES {
        assert!(fingerprints::by_name(name).is_some(), "{name} has no table");
    }
    assert!(
        fingerprints::by_name("nope").is_none(),
        "an unknown name resolves to nothing"
    );
    assert!(
        fingerprints::by_name("").is_some(),
        "an empty fingerprint is chrome, as in the reference"
    );
}

#[test]
fn random_policies_are_process_stable_and_random_is_a_browser() {
    for name in ["random", "randomized"] {
        let first = fingerprints::by_name(name).unwrap();
        for _ in 0..16 {
            let next = fingerprints::by_name(name).unwrap();
            assert_eq!(first.cipher_suites, next.cipher_suites);
            assert_eq!(first.extensions, next.extensions);
        }
    }
    let random = fingerprints::by_name("random").unwrap();
    assert!(
        ["chrome", "firefox", "edge", "safari", "ios"]
            .iter()
            .any(|name| {
                let browser = fingerprints::by_name(name).unwrap();
                browser.cipher_suites == random.cipher_suites
                    && browser.extensions == random.extensions
            })
    );
}

/// The modern chrome hello must still offer the hybrid share current Xray
/// servers demand (SPEC 083/089), and its session id must be 32 bytes of
/// compat space for REALITY to seal into.
#[test]
fn chrome_carries_a_hybrid_key_share_and_a_32_byte_session_id() {
    let template = fingerprints::by_name("chrome").expect("chrome");
    let data = std::fs::read(capture("chrome")).expect("capture");
    let hello = parse_record(&data).expect("parse");
    assert_eq!(hello.session_id.len(), 32);
    let groups = template
        .extensions
        .iter()
        .find_map(|ext| match ext {
            core_tls::hello::Ext::KeyShare(body) => core_tls::hello::key_share_group(body).ok(),
            _ => None,
        })
        .expect("chrome offers a key share");
    assert!(
        groups.contains(&0x11ec),
        "X25519MLKEM768 present, got {groups:04x?}"
    );
    assert!(groups.contains(&0x001d), "plain X25519 present too");
}

/// GREASE: a reserved value a client picks at random per handshake, so even the
/// reference never repeats its own hello. Everything else must match exactly.
fn is_grease(value: u16) -> bool {
    let low = (value & 0x0f) as u8;
    low == 0x0a && (value >> 8) as u8 == (value & 0xff) as u8
}

/// Mask the GREASE values inside one extension body, so two hellos that differ
/// only in them compare equal.
fn mask_body(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    // a list of u16 values: supported_groups, key_share group ids
    let u16_list = matches!(id, 0x000a | 0x0023 | 0x0033 | 0x001d);
    if u16_list {
        for pair in out.chunks_mut(2) {
            if pair.len() == 2 {
                let value = u16::from_be_bytes([pair[0], pair[1]]);
                if is_grease(value) {
                    pair.copy_from_slice(&0x0a0au16.to_be_bytes());
                }
            }
        }
    }
    out
}

/// The two hellos agree once GREASE is set aside.
fn same_except_grease(rebuilt: &[u8], capture: &[u8]) -> bool {
    let (Ok(left), Ok(right)) = (parse_record(rebuilt), parse_record(capture)) else {
        return false;
    };
    let mask = |data: &[u8]| -> Vec<u16> {
        data.chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| {
                let value = u16::from_be_bytes([c[0], c[1]]);
                if is_grease(value) { 0x0a0a } else { value }
            })
            .collect()
    };
    if left.template.record_version != right.template.record_version
        || left.template.client_version != right.template.client_version
        || left.random != right.random
        // the session id is the compatibility field: its length is the claim
        // (REALITY seals its auth key into it), its content is per-handshake
        || left.session_id.len() != right.session_id.len()
        || left.sni != right.sni
        || left.template.compression != right.template.compression
        || mask(&left.template.cipher_suites) != mask(&right.template.cipher_suites)
        || left.template.extensions.len() != right.template.extensions.len()
    {
        return false;
    }
    let mut diffs = Vec::new();
    for (i, (a, b)) in left
        .template
        .extensions
        .iter()
        .zip(right.template.extensions.iter())
        .enumerate()
    {
        if !same_extension(a, b) {
            diffs.push(format!("#{i} rebuilt={a:?} capture={b:?}"));
        }
    }
    if !diffs.is_empty() {
        eprintln!("DIFF {diffs:?}");
        return false;
    }
    true
}

fn same_extension(a: &core_tls::hello::Ext, b: &core_tls::hello::Ext) -> bool {
    use core_tls::hello::Ext;
    match (a, b) {
        (Ext::Static(id_a, body_a), Ext::Static(id_b, body_b)) => {
            (is_grease(*id_a) && is_grease(*id_b))
                || (id_a == id_b && mask_body(*id_a, body_a) == mask_body(*id_b, body_b))
        }
        (Ext::Sni, Ext::Sni) | (Ext::Alpn, Ext::Alpn) => true,
        (Ext::KeyShare(a), Ext::KeyShare(b)) => mask_body(0x0033, a) == mask_body(0x0033, b),
        _ => false,
    }
}
