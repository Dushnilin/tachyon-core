//! FPTN reality mode: fake handshake with a captured browser ClientHello,
//! then the real handshake inside TlsObfuscator2 frames.
//!
//! Reference flow (`ApiClient::PerformFakeHandshake2` /
//! `WebsocketClient::PerformFakeHandshake2` + `GenerateHandshakePacket`, and
//! the server side `Session::IsRealityHandshake` / `Session::PerformFakeHandshake2`):
//!
//! 1. Raw TCP: send a decoy ClientHello re-stamped from a CamouflageTLS
//!    capture (fresh random, decoy session id, configured SNI).
//! 2. Drain the server's fake flight (`WaitForServerTlsHello`: 6 s budget,
//!    completeness gate, 300 ms quiet period).
//! 3. Send the TLS compatibility ChangeCipherSpec, wait 150 ms.
//! 4. Attach TlsObfuscator2, wait 150 ms, run the real rustls handshake
//!    (regular FPTN session id + MD5 pin) through the obfuscator, flip to
//!    plain afterwards — the official `set_obfuscator(nullptr)`.
//!
//! The decoy session id is `GenerateDecoyTlsSessionId2`: 32 random bytes with
//! `SHA1(htonl(now))[..4]` at offset **14** (mode 2; the deprecated mode 1
//! used offset 10 and is rejected by [`super::Obfuscation::parse`]). The
//! server's `IsDecoyHandshakeSessionID2` scans `now ± 120 s`.
//!
//! Capture templates come from CamouflageTLS (MIT) — see
//! `templates/NOTICE` and `scripts/extract_camouflage_templates.py`.

use std::io;
use std::time::Duration;

use core_tls::hello;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::tls::{fptn_decoy_session_id, unix_now};

/// SNI lengths carried by the capture tables (61 entries per browser,
/// `sni_length` 4..=64) — the official `GetRandomHandshakeRecord` needs an
/// exact-length entry, so the reference client only works in this range too.
pub(crate) const SNI_LEN: std::ops::RangeInclusive<usize> = 4..=64;

/// `WaitForServerTlsHello(..., 6s)` call sites in the reference client.
const FLIGHT_BUDGET: Duration = Duration::from_secs(6);
/// Quiet period after the completeness gate (`kQuietMs`).
const FLIGHT_QUIET: Duration = Duration::from_millis(300);
/// Poll interval while draining (`kPollInterval`).
const FLIGHT_POLL: Duration = Duration::from_millis(50);
/// `MakeClientChangeCipherSpec()`.
const CCS: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
/// Sleep between the decoy flight and the obfuscated real handshake
/// (`PerformFakeHandshake2` after the CCS write).
const POST_CCS_DELAY: Duration = Duration::from_millis(150);
/// `kMinTls13ServerFlightAppDataBytes`.
const MIN_TLS13_APPDATA: usize = 512;

/// Browser camouflage profile (`CensorshipStrategy::kSniRealityMode*`).
///
/// Discriminant order must match `TEMPLATES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityProfile {
    Chrome145,
    Chrome146,
    Chrome147,
    Chrome148,
    Chrome149,
    Firefox149,
    Firefox150,
    Firefox151,
    Yandex24,
    Yandex25,
    Yandex26_3,
    Yandex26_4,
    Safari26_4,
    Safari26_5,
}

impl RealityProfile {
    /// Parse an `obfuscation` value: `reality_<name>`, the official enum
    /// name, or the official strategy number.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let profile = match raw {
            "reality_chrome145" | "kSniRealityModeChrome145" | "20" => Self::Chrome145,
            "reality_chrome146" | "kSniRealityModeChrome146" | "21" => Self::Chrome146,
            "reality_chrome147" | "kSniRealityModeChrome147" | "22" => Self::Chrome147,
            "reality_chrome148" | "kSniRealityModeChrome148" | "23" => Self::Chrome148,
            "reality_chrome149" | "kSniRealityModeChrome149" | "24" => Self::Chrome149,
            "reality_firefox149" | "kSniRealityModeFirefox149" | "60" => Self::Firefox149,
            "reality_firefox150" | "kSniRealityModeFirefox150" | "61" => Self::Firefox150,
            "reality_firefox151" | "kSniRealityModeFirefox151" | "62" => Self::Firefox151,
            "reality_yandex24" | "kSniRealityModeYandex24" | "80" => Self::Yandex24,
            "reality_yandex25" | "kSniRealityModeYandex25" | "81" => Self::Yandex25,
            "reality_yandex26_3" | "kSniRealityModeYandex26_3" | "82" => Self::Yandex26_3,
            "reality_yandex26_4" | "kSniRealityModeYandex26_4" | "83" => Self::Yandex26_4,
            "reality_safari26_4" | "kSniRealityModeSafari26_4" | "100" => Self::Safari26_4,
            "reality_safari26_5" | "kSniRealityModeSafari26_5" | "101" => Self::Safari26_5,
            _ => return None,
        };
        Some(profile)
    }

    fn index(self) -> usize {
        match self {
            Self::Chrome145 => 0,
            Self::Chrome146 => 1,
            Self::Chrome147 => 2,
            Self::Chrome148 => 3,
            Self::Chrome149 => 4,
            Self::Firefox149 => 5,
            Self::Firefox150 => 6,
            Self::Firefox151 => 7,
            Self::Yandex24 => 8,
            Self::Yandex25 => 9,
            Self::Yandex26_3 => 10,
            Self::Yandex26_4 => 11,
            Self::Safari26_4 => 12,
            Self::Safari26_5 => 13,
        }
    }
}

/// One `[u16le count] ([u16le len] [record])*` blob per profile, extracted
/// from the CamouflageTLS version tables (see `templates/NOTICE`).
const TEMPLATES: [&[u8]; 14] = [
    include_bytes!("reality/templates/chrome145.bin"),
    include_bytes!("reality/templates/chrome146.bin"),
    include_bytes!("reality/templates/chrome147.bin"),
    include_bytes!("reality/templates/chrome148.bin"),
    include_bytes!("reality/templates/chrome149.bin"),
    include_bytes!("reality/templates/firefox149.bin"),
    include_bytes!("reality/templates/firefox150.bin"),
    include_bytes!("reality/templates/firefox151.bin"),
    include_bytes!("reality/templates/yandex24.bin"),
    include_bytes!("reality/templates/yandex25.bin"),
    include_bytes!("reality/templates/yandex26_3.bin"),
    include_bytes!("reality/templates/yandex26_4.bin"),
    include_bytes!("reality/templates/safari26_4.bin"),
    include_bytes!("reality/templates/safari26_5.bin"),
];

/// One random captured record of `profile` — mirrors the reference
/// `GetRandomHandshakeRecord` choice among the five captures per entry
/// (GREASE value, ECH-GREASE length and extension order vary).
fn pick_record(profile: RealityProfile) -> io::Result<&'static [u8]> {
    let blob = TEMPLATES[profile.index()];
    if blob.len() < 2 {
        return Err(io::Error::other("fptn reality: empty template blob"));
    }
    let count = u16::from_le_bytes([blob[0], blob[1]]) as usize;
    if count == 0 {
        return Err(io::Error::other("fptn reality: no template records"));
    }
    let mut seed = [0u8; 2];
    crate::outbound::shadowsocks::crypto::random_bytes(&mut seed)
        .map_err(|_| io::Error::other("fptn reality: system random unavailable"))?;
    let mut idx = u16::from_le_bytes(seed) as usize % count;
    let mut off = 2usize;
    loop {
        if off + 2 > blob.len() {
            return Err(io::Error::other("fptn reality: truncated template blob"));
        }
        let len = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
        let start = off + 2;
        let end = start + len;
        let record = blob
            .get(start..end)
            .ok_or_else(|| io::Error::other("fptn reality: truncated template record"))?;
        if idx == 0 {
            return Ok(record);
        }
        idx -= 1;
        off = end;
    }
}

/// Decoy ClientHello for one connection: captured template re-stamped with a
/// fresh random and the mode-2 decoy session id (the captured key share stays
/// verbatim — the fake handshake never completes on our side).
fn decoy_hello(profile: RealityProfile, sni: &str) -> io::Result<Vec<u8>> {
    if !SNI_LEN.contains(&sni.len()) {
        return Err(io::Error::other(format!(
            "fptn reality: sni must be {}..={} bytes, got {}",
            SNI_LEN.start(),
            SNI_LEN.end(),
            sni.len()
        )));
    }
    let record = pick_record(profile)?;
    let parsed = hello::parse_record(record)?;
    let mut random = [0u8; 32];
    crate::outbound::shadowsocks::crypto::random_bytes(&mut random)
        .map_err(|_| io::Error::other("fptn reality: system random unavailable"))?;
    let session_id = fptn_decoy_session_id(unix_now());
    hello::build(&parsed.template, &random, &session_id, sni, None)
}

/// Full fake handshake on a fresh TCP stream: decoy hello → drain the fake
/// flight → CCS → 150 ms (reference `PerformFakeHandshake2`).
pub(crate) async fn fake_handshake(
    stream: &mut TcpStream,
    profile: RealityProfile,
    sni: &str,
) -> io::Result<()> {
    let hello_bytes = decoy_hello(profile, sni)?;
    stream.write_all(&hello_bytes).await?;
    wait_server_flight(stream, FLIGHT_BUDGET).await?;
    stream.write_all(&CCS).await?;
    tokio::time::sleep(POST_CCS_DELAY).await;
    Ok(())
}

/// Mirror of `common::network::WaitForServerTlsHello`: phase 1 reads until
/// [`is_server_hello_complete`], phase 2 keeps reading until 300 ms of quiet;
/// on deadline a record-aligned flight is still accepted
/// ([`is_record_aligned_server_flight`]).
async fn wait_server_flight<R: AsyncRead + Unpin>(
    stream: &mut R,
    budget: Duration,
) -> io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut data: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 16 * 1024];
    let mut complete = false;
    let mut last_data = tokio::time::Instant::now();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let poll = FLIGHT_POLL.min(deadline - now);
        match tokio::time::timeout(poll, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                if !data.is_empty() {
                    return Ok(data);
                }
                break;
            }
            Ok(Ok(n)) => {
                data.extend_from_slice(&buf[..n]);
                last_data = tokio::time::Instant::now();
                if !complete && is_server_hello_complete(&data) {
                    complete = true;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if complete && last_data.elapsed() >= FLIGHT_QUIET {
                    return Ok(data);
                }
            }
        }
    }
    if is_record_aligned_server_flight(&data) {
        return Ok(data);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "fptn reality: no server flight received ({} bytes in {} ms)",
            data.len(),
            budget.as_millis()
        ),
    ))
}

/// `IsServerHelloComplete`: walk the record layer; TLS 1.3 needs ServerHello
/// plus ≥ 512 bytes of ApplicationData ending on a record boundary, TLS 1.2
/// needs ServerHelloDone.
fn is_server_hello_complete(data: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut found_server_hello = false;
    let mut is_tls13 = false;
    let mut handshake_done = false;
    let mut app_data_bytes = 0usize;

    while pos + 5 <= data.len() {
        let content_type = data[pos];
        let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        if pos + 5 + record_len > data.len() {
            // Incomplete record: wait for the full payload.
            return false;
        }

        if content_type == 22 {
            let mut hpos = pos + 5;
            let hend = hpos + record_len;
            while hpos + 4 <= hend {
                let msg_type = data[hpos];
                let msg_len = ((data[hpos + 1] as usize) << 16)
                    | ((data[hpos + 2] as usize) << 8)
                    | data[hpos + 3] as usize;
                if hpos + 4 + msg_len > hend {
                    return false;
                }
                if msg_type == 2 {
                    found_server_hello = true;
                    is_tls13 = is_tls13_server_hello(&data[hpos + 4..hpos + 4 + msg_len]);
                }
                if found_server_hello && !is_tls13 && msg_type == 14 {
                    handshake_done = true;
                }
                hpos += 4 + msg_len;
            }
        }

        if found_server_hello && is_tls13 && content_type == 23 {
            app_data_bytes += record_len;
        }

        pos += 5 + record_len;
    }

    if found_server_hello && is_tls13 {
        handshake_done = pos == data.len() && app_data_bytes >= MIN_TLS13_APPDATA;
    }

    found_server_hello && handshake_done
}

/// `detail::IsTls13ServerHello`: ServerHello body carries
/// `supported_versions = 0x0304`.
fn is_tls13_server_hello(body: &[u8]) -> bool {
    if body.len() < 36 {
        return false;
    }
    let mut p = 2 + 32; // legacy_version + random
    if p >= body.len() {
        return false;
    }
    let sid_len = body[p] as usize;
    p += 1;
    if p + sid_len + 5 > body.len() {
        return false;
    }
    p += sid_len;
    p += 2; // cipher_suite
    p += 1; // compression_method
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(body.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + ext_len > ext_end {
            break;
        }
        if ext_type == 0x002b && ext_len >= 2 {
            let ver = u16::from_be_bytes([body[p], body[p + 1]]);
            if ver == 0x0304 {
                return true;
            }
        }
        p += ext_len;
    }
    false
}

/// `IsRecordAlignedServerFlight`: whole records, first record is a
/// ServerHello handshake record.
fn is_record_aligned_server_flight(data: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut found_server_hello = false;
    while pos + 5 <= data.len() {
        let len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        if pos + 5 + len > data.len() {
            return false;
        }
        if data[pos] == 22 && pos + 5 < data.len() && data[pos + 5] == 2 {
            found_server_hello = true;
        }
        pos += 5 + len;
    }
    found_server_hello && pos == data.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::fptn::tls;

    /// Synthetic ServerHello body: legacy 0x0303, random, session id, cipher,
    /// compression, extensions (optional `supported_versions`).
    fn server_hello_body(tls13: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42u8; 32]);
        body.push(0); // empty legacy session id
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0); // null compression
        let mut exts = Vec::new();
        if tls13 {
            exts.extend_from_slice(&0x002bu16.to_be_bytes());
            exts.extend_from_slice(&2u16.to_be_bytes());
            exts.extend_from_slice(&[0x03, 0x04]);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        body
    }

    fn hs_record(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![msg_type, 0, 0, 0];
        let len = body.len() as u32;
        msg[1] = (len >> 16) as u8;
        msg[2] = (len >> 8) as u8;
        msg[3] = len as u8;
        msg.extend_from_slice(body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    fn ccs_record() -> Vec<u8> {
        CCS.to_vec()
    }

    fn appdata_record(payload_len: usize) -> Vec<u8> {
        let mut rec = vec![0x17, 0x03, 0x03];
        rec.extend_from_slice(&(payload_len as u16).to_be_bytes());
        rec.extend(std::iter::repeat_n(0x5au8, payload_len));
        rec
    }

    #[test]
    fn tls13_flight_completes_only_above_512_appdata() {
        let mut flight = hs_record(2, &server_hello_body(true));
        flight.extend_from_slice(&ccs_record());
        flight.extend_from_slice(&appdata_record(300));
        assert!(!is_server_hello_complete(&flight), "500 < 512");
        flight.extend_from_slice(&appdata_record(300));
        assert!(is_server_hello_complete(&flight), "600 >= 512 and aligned");

        // A truncated trailing record blocks the completeness gate.
        let mut truncated = flight.clone();
        truncated.pop();
        assert!(!is_server_hello_complete(&truncated));
        assert!(!is_record_aligned_server_flight(&truncated));
    }

    #[test]
    fn tls12_flight_completes_at_server_hello_done() {
        let mut flight = hs_record(2, &server_hello_body(false));
        flight.extend_from_slice(&hs_record(14, &[]));
        assert!(is_server_hello_complete(&flight));
        assert!(!is_server_hello_complete(&hs_record(
            2,
            &server_hello_body(false)
        )));
    }

    #[test]
    fn aligned_fallback_accepts_partial_but_framed_flights() {
        let only_sh = hs_record(2, &server_hello_body(false));
        assert!(is_record_aligned_server_flight(&only_sh));
        // Not complete (no SHD / appdata), but frame-aligned: accepted at deadline.
        assert!(!is_server_hello_complete(&only_sh));
        assert!(!is_record_aligned_server_flight(&[0x16, 0x03, 0x03, 0x00]));
    }

    #[tokio::test]
    async fn drain_returns_complete_flight_after_quiet_period() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let mut flight = hs_record(2, &server_hello_body(true));
        flight.extend_from_slice(&ccs_record());
        flight.extend_from_slice(&appdata_record(600));
        let sent = flight.clone();
        let writer = tokio::spawn(async move {
            server.write_all(&sent).await.expect("write flight");
        });
        let got = wait_server_flight(&mut client, Duration::from_secs(2))
            .await
            .expect("flight");
        assert_eq!(got, flight);
        writer.await.expect("writer");
    }

    #[tokio::test]
    async fn drain_accepts_eof_with_partial_flight() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut partial = hs_record(2, &server_hello_body(false));
        partial.extend_from_slice(&[0x16, 0x03, 0x03, 0x00]); // dangling header
        server.write_all(&partial).await.expect("write");
        server.flush().await.expect("flush");
        drop(server);
        let got = wait_server_flight(&mut client, Duration::from_secs(2))
            .await
            .expect("eof returns what arrived");
        assert_eq!(got, partial);
    }

    #[tokio::test]
    async fn drain_times_out_on_garbage() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        server.write_all(b"not tls at all").await.expect("write");
        let err = wait_server_flight(&mut client, Duration::from_millis(150))
            .await
            .expect_err("garbage is not a flight");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn all_templates_parse_and_build_with_decoy_stamps() {
        for profile in [
            RealityProfile::Chrome145,
            RealityProfile::Chrome146,
            RealityProfile::Chrome147,
            RealityProfile::Chrome148,
            RealityProfile::Chrome149,
            RealityProfile::Firefox149,
            RealityProfile::Firefox150,
            RealityProfile::Firefox151,
            RealityProfile::Yandex24,
            RealityProfile::Yandex25,
            RealityProfile::Yandex26_3,
            RealityProfile::Yandex26_4,
            RealityProfile::Safari26_4,
            RealityProfile::Safari26_5,
        ] {
            for sni_len in [*SNI_LEN.start(), 13, *SNI_LEN.end()] {
                let sni = "a".repeat(sni_len);
                let built = decoy_hello(profile, &sni).expect("decoy hello");
                let parsed = hello::parse_record(&built).expect("rebuilt hello parses");
                assert_eq!(parsed.sni, sni, "{profile:?} sni {sni_len}");
                assert_eq!(parsed.session_id.len(), 32);
                let sid: [u8; 32] = parsed.session_id.as_slice().try_into().unwrap();
                assert!(tls::is_decoy_session_id(&sid, unix_now()));
                assert!(
                    parsed.random != [0u8; 32],
                    "{profile:?} random must be fresh"
                );
            }
        }
    }

    #[test]
    fn sni_outside_capture_range_is_rejected() {
        let err = decoy_hello(RealityProfile::Chrome149, "abc").expect_err("len 3");
        assert!(err.to_string().contains("4..=64"), "{err}");
        let long = "x".repeat(65);
        assert!(decoy_hello(RealityProfile::Chrome149, &long).is_err());
    }

    #[test]
    fn profile_parse_covers_official_names_and_numbers() {
        assert_eq!(
            RealityProfile::parse("kSniRealityModeChrome145"),
            Some(RealityProfile::Chrome145)
        );
        assert_eq!(
            RealityProfile::parse("reality_firefox151"),
            Some(RealityProfile::Firefox151)
        );
        assert_eq!(RealityProfile::parse("24"), Some(RealityProfile::Chrome149));
        assert_eq!(
            RealityProfile::parse("101"),
            Some(RealityProfile::Safari26_5)
        );
        assert_eq!(
            RealityProfile::parse("reality"),
            None,
            "bare alias is Obfuscation-level"
        );
        assert_eq!(RealityProfile::parse("kSniRealityMode"), None);
        assert_eq!(RealityProfile::parse("tls"), None);
    }
}
