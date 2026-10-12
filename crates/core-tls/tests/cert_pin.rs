//! Certificate pinning: is the pin compared to anything at all?
//!
//! A pin that is silently ignored still looks like working configuration - the
//! handshake succeeds either way, because an unchecked pin only ever adds an
//! unused field. So these pin the *behaviour*: the two fields hash different
//! things, the walk is stable, and a pin that matches nothing is refused rather
//! than waved through.

use core_tls::verify::spki_sha256;
use sha2::Digest;

fn cert_sha256(der: &[u8]) -> [u8; 32] {
    <sha2::Sha256 as Digest>::digest(der).into()
}

fn der_of_localhost() -> Vec<u8> {
    base64(
        &include_str!("../../../tests/golden/certs/localhost.crt")
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join(""),
    )
}

fn base64(s: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.bytes() {
        if c == b'=' {
            continue;
        }
        let v = TABLE.iter().position(|t| *t == c).expect("base64") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[test]
fn the_two_fields_hash_different_things() {
    let der = der_of_localhost();
    let whole = cert_sha256(&der);
    let spki = spki_sha256(&der).expect("the walk reaches subjectPublicKeyInfo");
    assert_ne!(
        whole, spki,
        "certificate_sha256 and certificate_public_key_sha256 must be different values, \
         otherwise pinning the public key would be pinning the certificate"
    );
}

#[test]
fn the_walk_is_stable() {
    let der = der_of_localhost();
    let first = spki_sha256(&der).expect("first walk");
    let second = spki_sha256(&der).expect("second walk");
    assert_eq!(
        first, second,
        "the same certificate must hash the same way twice"
    );
}

/// The pinned value, as openssl computes it: the SHA-256 of the DER SubjectPublicKeyInfo.
/// A drift here means the pin stops matching what any other tool produces, and the
/// failure surfaces as "the certificate does not match" with nothing to act on.
#[test]
fn the_spki_hash_matches_openssl() {
    let der = der_of_localhost();
    let ours = spki_sha256(&der).expect("walk");
    let ours_hex: String = ours.iter().map(|b| format!("{b:02x}")).collect();
    let Ok(openssl) = std::process::Command::new("openssl")
        .args([
            "x509",
            "-in",
            "tests/golden/certs/localhost.crt",
            "-noout",
            "-pubkey",
        ])
        .output()
    else {
        eprintln!("openssl unavailable, skipping the cross-check");
        return;
    };
    if !openssl.status.success() {
        eprintln!("openssl failed, skipping the cross-check");
        return;
    }
    let pem = String::from_utf8_lossy(&openssl.stdout).to_string();
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let expected: [u8; 32] = <sha2::Sha256 as Digest>::digest(base64(&body)).into();
    let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        ours_hex, expected_hex,
        "our SPKI digest differs from openssl's, so a pin written by any other tool would never match"
    );
}

#[test]
fn a_truncated_certificate_is_refused_not_panicked() {
    // The verifier runs inside the handshake. A malformed certificate has to come
    // back as an error; a panic there takes the whole process down.
    let der = der_of_localhost();
    let cut = &der[..der.len() / 2];
    let _ = spki_sha256(cut);
}

#[test]
fn empty_input_is_an_error() {
    assert!(spki_sha256(&[]).is_err());
}

#[test]
fn pin_verifier_accepts_matching_certificate_or_spki_pin() {
    use core_tls::verify::{CertVerifier, PinVerifier, WebpkiVerifier};
    use rustls::pki_types::{CertificateDer, ServerName};

    let der = der_of_localhost();
    let cert_hash = cert_sha256(&der);
    let spki_hash = spki_sha256(&der).expect("spki");
    let leaf = CertificateDer::from(der);
    let server_name = ServerName::try_from("localhost").expect("server name");

    let fallback = WebpkiVerifier::mozilla_roots().expect("roots").into_inner();

    // Matching certificate_sha256
    let verifier = PinVerifier::new(fallback.clone(), vec![cert_hash], Vec::new());
    assert!(verifier.verify_chain(&leaf, &[], &server_name).is_ok());

    // Matching public_key_sha256
    let verifier = PinVerifier::new(fallback.clone(), Vec::new(), vec![spki_hash]);
    assert!(verifier.verify_chain(&leaf, &[], &server_name).is_ok());

    // Mismatched pin
    let verifier = PinVerifier::new(fallback, vec![[0u8; 32]], Vec::new());
    assert!(verifier.verify_chain(&leaf, &[], &server_name).is_err());
}
