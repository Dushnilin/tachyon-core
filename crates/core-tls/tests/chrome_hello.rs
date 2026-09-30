//! F0 spike B (ADR-0004): byte-level diff against a captured utls chrome
//! ClientHello from sing-box-lx v1.14.1-lx.8.

use std::path::PathBuf;

use core_tls::hello::{Ext, build, key_share_group, parse_record};
use core_tls::keyshare::{self, Shares, X25519};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/spikes/clienthello/chrome_lx8.bin")
}

fn ext_id(e: &Ext) -> u16 {
    match e {
        Ext::Static(id, _) => *id,
        Ext::Sni => 0,
        Ext::Alpn => 0x10,
        Ext::KeyShare(_) => 0x33,
    }
}

#[test]
fn parses_captured_chrome_hello() {
    let data = std::fs::read(fixture()).expect("fixture");
    let hello = parse_record(&data).expect("parse");
    assert_eq!(hello.sni, "www.gstatic.com");
    assert_eq!(hello.session_id.len(), 32);
    assert_eq!(hello.template.record_version, [0x03, 0x01]);
    assert_eq!(hello.template.client_version, [0x03, 0x03]);
    assert!(!hello.template.cipher_suites.is_empty());
    assert_eq!(
        hello.template.compression,
        vec![0x00],
        "chrome uses null compression only"
    );
    let ext_ids: Vec<u16> = hello.template.extensions.iter().map(ext_id).collect();
    assert!(ext_ids.contains(&0x002b), "supported_versions present");
    assert!(ext_ids.contains(&0x0010), "ALPN present");
    assert!(ext_ids.contains(&0x0033), "key_share present");

    let ks = hello
        .template
        .extensions
        .iter()
        .find_map(|e| match e {
            Ext::KeyShare(body) => Some(body.clone()),
            _ => None,
        })
        .expect("key_share body");
    let groups = key_share_group(&ks).expect("groups");
    assert!(
        groups.contains(&0x11ec),
        "hybrid X25519MLKEM768 share present (modern chrome), got {groups:?}"
    );
    assert!(
        groups.contains(&0x6a6a) || groups.iter().any(|g| g & 0x0f0f == 0x0a0a),
        "GREASE key share present, got {groups:?}"
    );
}

/// The two hellos agree once GREASE is set aside: a GREASE value is reserved
/// and drawn fresh per handshake, which is why the reference never repeats its
/// own hello either.
#[test]
fn rebuilds_captured_hello_byte_for_byte() {
    let data = std::fs::read(fixture()).expect("fixture");
    let hello = parse_record(&data).expect("parse");
    let rebuilt = build(
        &hello.template,
        &hello.random,
        &hello.session_id,
        &hello.sni,
        &[b"h2", b"http/1.1"],
        None,
    )
    .expect("build");
    assert_eq!(
        rebuilt.len(),
        data.len(),
        "a fresh GREASE id must not change the length"
    );

    let left = parse_record(&rebuilt).expect("parse rebuilt");
    assert_eq!(left.random, hello.random);
    assert_eq!(left.session_id, hello.session_id);
    assert_eq!(left.sni, hello.sni);
    assert_eq!(left.template.cipher_suites, hello.template.cipher_suites);
    assert_eq!(
        left.template.extensions.len(),
        hello.template.extensions.len()
    );
    for (a, b) in left
        .template
        .extensions
        .iter()
        .zip(hello.template.extensions.iter())
    {
        let same = match (a, b) {
            (Ext::Static(id_a, body_a), Ext::Static(id_b, body_b)) => {
                (keyshare::is_grease(*id_a) && keyshare::is_grease(*id_b))
                    || (id_a == id_b && body_a == body_b)
            }
            (Ext::Sni, Ext::Sni) | (Ext::Alpn, Ext::Alpn) => true,
            (Ext::KeyShare(a), Ext::KeyShare(b)) => {
                // only the GREASE group id moves
                a.len() == b.len()
                    && keyshare::entries(a)
                        .expect("built key share")
                        .into_iter()
                        .zip(keyshare::entries(b).expect("captured key share"))
                        .all(|((ga, da), (gb, db))| {
                            da == db
                                && (ga == gb
                                    || (keyshare::is_grease(ga) && keyshare::is_grease(gb)))
                        })
            }
            _ => false,
        };
        assert!(same, "extension differs: rebuilt={a:?} capture={b:?}");
    }
}

#[test]
fn rebuild_with_fresh_randomness_differs_only_in_random_fields() {
    let data = std::fs::read(fixture()).expect("fixture");
    let hello = parse_record(&data).expect("parse");
    let mut random = [0x42u8; 32];
    random[0] = 0x43;
    let session_id: Vec<u8> = (0..32).map(|i| 0xA0 + i as u8).collect();
    let ks = hello
        .template
        .extensions
        .iter()
        .find_map(|e| match e {
            Ext::KeyShare(body) => Some(body.clone()),
            _ => None,
        })
        .expect("key_share body");
    let shares = Shares::for_body(&ks).expect("our own keys");
    let built = build(
        &hello.template,
        &random,
        &session_id,
        &hello.sni,
        &[b"h2", b"http/1.1"],
        Some(&shares),
    )
    .expect("build");
    assert_ne!(built, data, "fresh randomness must change the bytes");
    assert_eq!(
        built.len(),
        data.len(),
        "our own keys must be the same size as the captured ones"
    );

    let reparsed = parse_record(&built).expect("reparse built");
    assert_eq!(reparsed.random, random);
    assert_eq!(reparsed.session_id, session_id);
    assert_eq!(
        reparsed.x25519_public.as_ref().map(|k| k.as_slice()),
        shares.public(X25519),
        "the plain X25519 share on the wire is the one we generated"
    );
    assert_ne!(
        reparsed.x25519_public, hello.x25519_public,
        "and it is ours, not the captured key"
    );
    assert_eq!(reparsed.sni, hello.sni);
    assert_eq!(
        reparsed.template.cipher_suites,
        hello.template.cipher_suites
    );
    // the extension list is the same, GREASE ids aside: they are drawn fresh
    let ids: Vec<u16> = reparsed
        .template
        .extensions
        .iter()
        .map(|e| ungrease(ext_id(e)))
        .collect();
    let orig_ids: Vec<u16> = hello
        .template
        .extensions
        .iter()
        .map(|e| ungrease(ext_id(e)))
        .collect();
    assert_eq!(ids, orig_ids);
}

fn ungrease(id: u16) -> u16 {
    if keyshare::is_grease(id) { 0x0a0a } else { id }
}
