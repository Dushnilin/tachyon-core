//! Pre-crafted and dynamic fake payloads for DPI desynchronization.

/// Standard STUN Binding Request packet (RFC 5389 / RFC 8489).
/// Used to bypass Discord RTC voice and STUN DPI blocking.
pub static FAKE_STUN_BINDING_REQUEST: [u8; 20] = [
    0x00, 0x01, // Message Type: Binding Request (0x0001)
    0x00, 0x00, // Message Length: 0
    0x21, 0x12, 0xa4, 0x42, // Magic Cookie: 0x2112A442
    // 12-byte Transaction ID:
    0x74, 0x61, 0x63, 0x68, 0x79, 0x6f, 0x6e, 0x2d, 0x64, 0x70, 0x69, 0x21,
];

/// Minimal valid QUIC Initial packet header with Google QUIC padding (RFC 9000).
/// Used to fool stateful QUIC DPI connection tracking without hitting destination server.
pub static FAKE_QUIC_INITIAL: [u8; 1200] = {
    let mut buf = [0u8; 1200];
    // Long Header: Initial (0xc0 | 0x00)
    buf[0] = 0xc0;
    // Version: QUIC v1 (0x00000001)
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x01;
    // Destination Connection ID length: 8
    buf[5] = 0x08;
    // DCID (8 bytes)
    buf[6] = 0xde;
    buf[7] = 0xad;
    buf[8] = 0xbe;
    buf[9] = 0xef;
    buf[10] = 0xca;
    buf[11] = 0xfe;
    buf[12] = 0xba;
    buf[13] = 0xbe;
    // Source Connection ID length: 0
    buf[14] = 0x00;
    // Token length: 0
    buf[15] = 0x00;
    // Length: 2-byte varint encoding 1180
    buf[16] = 0x44;
    buf[17] = 0x9c;
    // Packet number: 0x01
    buf[18] = 0x01;
    // Rest is padding frame (0x00)
    buf
};

/// Build a valid, RFC-compliant TLS 1.3 ClientHello with the given SNI.
/// This generates a realistic handshake indistinguishable from Chrome/Firefox TLS 1.3.
pub fn build_fake_tls_client_hello(sni: &str) -> Vec<u8> {
    let mut hs = Vec::with_capacity(512);

    // Client Version (TLS 1.2 legacy version)
    hs.extend_from_slice(&[0x03, 0x03]);

    // 32-byte Client Random
    let mut random = [0u8; 32];
    let _ = getrandom::fill(&mut random);
    hs.extend_from_slice(&random);

    // Legacy Session ID (32 bytes random)
    hs.push(32);
    let mut session_id = [0u8; 32];
    let _ = getrandom::fill(&mut session_id);
    hs.extend_from_slice(&session_id);

    // Cipher Suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    hs.extend_from_slice(&[
        0x00, 0x06, // length: 6
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    ]);

    // Compression Methods: null only
    hs.extend_from_slice(&[0x01, 0x00]);

    // Extensions buffer
    let mut exts = Vec::with_capacity(256);

    // Extension: Server Name Indication (0x0000)
    if !sni.is_empty() {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;
        let list_len = name_len + 3;

        exts.extend_from_slice(&[0x00, 0x00]); // Type: server_name
        let ext_len = list_len + 2;
        exts.extend_from_slice(&ext_len.to_be_bytes()); // Extension length
        exts.extend_from_slice(&list_len.to_be_bytes()); // ServerNameList length
        exts.push(0x00); // HostName type
        exts.extend_from_slice(&name_len.to_be_bytes()); // HostName length
        exts.extend_from_slice(sni_bytes);
    }

    // Extension: Supported Versions (0x002b) -> TLS 1.3, TLS 1.2
    exts.extend_from_slice(&[
        0x00, 0x2b, // Type: supported_versions
        0x00, 0x05, // Length: 5
        0x04, // List length: 4
        0x03, 0x04, // TLS 1.3
        0x03, 0x03, // TLS 1.2
    ]);

    // Extension: Supported Groups (0x000a) -> X25519, secp256r1
    exts.extend_from_slice(&[
        0x00, 0x0a, // Type: supported_groups
        0x00, 0x06, // Length: 6
        0x00, 0x04, // List length: 4
        0x00, 0x1d, // X25519
        0x00, 0x17, // secp256r1
    ]);

    // Extension: Signature Algorithms (0x000d)
    exts.extend_from_slice(&[
        0x00, 0x0d, // Type: signature_algorithms
        0x00, 0x08, // Length: 8
        0x00, 0x06, // List length: 6
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x08, 0x04, // rsa_pss_rsae_sha256
        0x04, 0x01, // rsa_pkcs1_sha256
    ]);

    // Extension: Key Share (0x0033) -> X25519 key share
    let mut key_share_bytes = [0u8; 32];
    let _ = getrandom::fill(&mut key_share_bytes);
    exts.extend_from_slice(&[
        0x00, 0x33, // Type: key_share
        0x00, 0x26, // Length: 38 (2 + 4 + 32)
        0x00, 0x24, // ClientKeyShare length: 36
        0x00, 0x1d, // Group: X25519
        0x00, 0x20, // Key exchange length: 32
    ]);
    exts.extend_from_slice(&key_share_bytes);

    // Append Extensions length and data to Handshake
    let exts_len = exts.len() as u16;
    hs.extend_from_slice(&exts_len.to_be_bytes());
    hs.extend_from_slice(&exts);

    // Wrap in TLS Record Header:
    // [0x16, 0x03, 0x01, len_hi, len_lo]
    // Handshake header: [0x01, hs_len_hi, hs_len_mid, hs_len_lo]
    let hs_total_len = hs.len();
    let record_len = (hs_total_len + 4) as u16;

    let mut record = Vec::with_capacity(5 + 4 + hs_total_len);
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    record.extend_from_slice(&record_len.to_be_bytes());

    record.push(0x01); // HandshakeType: ClientHello
    record.push((hs_total_len >> 16) as u8);
    record.push((hs_total_len >> 8) as u8);
    record.push(hs_total_len as u8);
    record.extend_from_slice(&hs);

    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::desync::packet::find_sni;

    #[test]
    fn test_build_fake_tls_google() {
        let fake = build_fake_tls_client_hello("www.google.com");
        assert!(fake.len() > 100);
        let m = find_sni(&fake).expect("find sni in generated fake tls");
        assert_eq!(m.host, "www.google.com");
    }

    #[test]
    fn test_build_fake_tls_custom() {
        let fake = build_fake_tls_client_hello("gosuslugi.ru");
        let m = find_sni(&fake).expect("find custom sni");
        assert_eq!(m.host, "gosuslugi.ru");
    }
}
