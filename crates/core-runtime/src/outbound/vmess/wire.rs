//! VMess wire primitives: AES auth ID, request header construction and AEAD
//! sealing (`SealVMessAEADHeader`), response header decryption.

use std::io;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, AeadInPlace, Payload};
use aes_gcm::{Aes128Gcm, Tag};
use sha2::{Digest as _, Sha256};

use crate::inbound::Target;
use crate::outbound::shadowsocks::crypto::random_bytes;
use crate::outbound::vmess::kdf::{crc32_ieee, fnv1a32, kdf, kdf16};

const SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const SALT_HDR_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const SALT_HDR_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const SALT_HDR_KEY: &[u8] = b"VMess Header AEAD Key";
const SALT_HDR_IV: &[u8] = b"VMess Header AEAD Nonce";

pub(crate) fn gcm_seal(key16: &[u8], nonce12: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key16).expect("gcm key length");
    let nonce: [u8; 12] = nonce12.try_into().expect("nonce length");
    cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("gcm seal cannot fail for valid key/nonce")
}

pub(crate) fn gcm_open(
    key16: &[u8],
    nonce12: &[u8],
    aad: &[u8],
    ciphertext: &mut Vec<u8>,
) -> io::Result<()> {
    if ciphertext.len() < 16 {
        return Err(io::Error::other("ciphertext too short"));
    }
    let cipher = Aes128Gcm::new_from_slice(key16).map_err(|e| io::Error::other(e.to_string()))?;
    let nonce: [u8; 12] = nonce12
        .try_into()
        .map_err(|_| io::Error::other("nonce length"))?;
    let split = ciphertext.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[split..]);
    cipher
        .decrypt_in_place_detached(
            (&nonce).into(),
            aad,
            &mut ciphertext[..split],
            Tag::from_slice(&tag),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "gcm auth failed"))?;
    ciphertext.truncate(split);
    Ok(())
}

pub(crate) fn unix_now() -> io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| io::Error::other(format!("clock: {e}")))
}

/// Legacy header user hash: `HMAC-MD5(alterKey, BE64(timestamp))`.
pub(crate) fn legacy_header_hash(alter_key: &[u8; 16], timestamp: u64) -> [u8; 16] {
    use hmac::Mac;
    type HmacMd5 = hmac::Hmac<md5::Md5>;
    let mut mac = <HmacMd5 as Mac>::new_from_slice(alter_key).expect("hmac key length");
    Mac::update(&mut mac, &timestamp.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// Legacy header CFB IV: `MD5(BE64(timestamp) repeated 4 times)`.
pub(crate) fn legacy_time_iv(timestamp: u64) -> [u8; 16] {
    let mut input = [0u8; 32];
    for slot in input.chunks_mut(8) {
        slot.copy_from_slice(&timestamp.to_be_bytes());
    }
    md5::Md5::digest(input).into()
}

/// `CreateAuthID`: BE64(time) || rand4 || BE32(crc32(first 12)), AES-ECB
/// encrypted with KDF16(cmdKey, "AES Auth ID Encryption").
pub(crate) fn create_auth_id(cmd_key: &[u8; 16]) -> io::Result<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&unix_now()?.to_be_bytes());
    random_bytes(&mut plain[8..12])?;
    let crc = crc32_ieee(&plain[..12]);
    plain[12..].copy_from_slice(&crc.to_be_bytes());
    let key = kdf16(cmd_key, &[SALT_AUTH_ID]);
    let cipher = aes::Aes128::new_from_slice(&key).expect("aes key length");
    let mut block = aes::Block::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

/// Plaintext request header (`rawClientConn.encodeHeader`): version, IV,
/// key, response marker, option, padding<<4|security, reserved, command=TCP,
/// port-then-address, random padding, FNV1a-32 checksum.
pub(crate) fn build_request_header(
    request_iv: &[u8; 16],
    request_key: &[u8; 16],
    response_header: u8,
    option: u8,
    security: u8,
    target: &Target,
) -> io::Result<Vec<u8>> {
    let mut rand = [0u8; 1];
    random_bytes(&mut rand)?;
    let pad_len = usize::from(rand[0] % 16);

    let mut header = Vec::with_capacity(38 + 259 + pad_len + 4);
    header.push(1);
    header.extend_from_slice(request_iv);
    header.extend_from_slice(request_key);
    header.push(response_header);
    header.push(option);
    header.push(((pad_len as u8) << 4) | security);
    header.push(0);
    header.push(1);
    header.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                header.push(0x01);
                header.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                header.push(0x03);
                header.extend_from_slice(&v6.octets());
            }
        },
        Target::Domain(host, _) => {
            let raw = host.as_bytes();
            if raw.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            header.push(0x02);
            header.push(raw.len() as u8);
            header.extend_from_slice(raw);
        }
    }
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        random_bytes(&mut pad)?;
        header.extend_from_slice(&pad);
    }
    let checksum = fnv1a32(&header);
    header.extend_from_slice(&checksum.to_be_bytes());
    Ok(header)
}

/// `SealVMessAEADHeader`: authID || GCM(len, AAD=authID) || connNonce(8) ||
/// GCM(header, AAD=authID). alters only for the AEAD path (alterId == 0).
pub(crate) fn seal_request_header(cmd_key: &[u8; 16], header: &[u8]) -> io::Result<Vec<u8>> {
    let auth_id = create_auth_id(cmd_key)?;
    let mut conn_nonce = [0u8; 8];
    random_bytes(&mut conn_nonce)?;

    let len_key = kdf16(cmd_key, &[SALT_HDR_LEN_KEY, &auth_id, &conn_nonce]);
    let len_nonce: [u8; 12] = kdf(cmd_key, &[SALT_HDR_LEN_IV, &auth_id, &conn_nonce])[..12]
        .try_into()
        .expect("kdf output is 32 bytes");
    let sealed_len = gcm_seal(
        &len_key,
        &len_nonce,
        &auth_id,
        &u16::try_from(header.len())
            .map_err(|_| io::Error::other("header too large"))?
            .to_be_bytes(),
    );

    let hdr_key = kdf16(cmd_key, &[SALT_HDR_KEY, &auth_id, &conn_nonce]);
    let hdr_nonce: [u8; 12] = kdf(cmd_key, &[SALT_HDR_IV, &auth_id, &conn_nonce])[..12]
        .try_into()
        .expect("kdf output is 32 bytes");
    let sealed_hdr = gcm_seal(&hdr_key, &hdr_nonce, &auth_id, header);

    let mut out = Vec::with_capacity(16 + 18 + 8 + sealed_hdr.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&sealed_hdr);
    Ok(out)
}

/// AEAD response keys: `SHA256(requestKey)[..16]` / `SHA256(requestIV)[..16]`.
pub(crate) fn derive_response_keys(
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    let key = Sha256::digest(request_key);
    let iv = Sha256::digest(request_iv);
    (
        key[..16].try_into().expect("sha256 output is 32 bytes"),
        iv[..16].try_into().expect("sha256 output is 32 bytes"),
    )
}

/// Legacy response keys (alterId > 0): `MD5(requestKey)` / `MD5(requestIV)`.
pub(crate) fn legacy_response_keys(
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    (
        md5::Md5::digest(request_key).into(),
        md5::Md5::digest(request_iv).into(),
    )
}

/// Precomputed GCM key/nonce pairs for the AEAD response header.
pub(crate) type ResponseHeaderKeys = ([u8; 16], [u8; 12], [u8; 16], [u8; 12]);

pub(crate) fn response_header_keys(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
) -> ResponseHeaderKeys {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce: [u8; 12] = kdf(response_iv, &[b"AEAD Resp Header Len IV"])[..12]
        .try_into()
        .expect("kdf output is 32 bytes");
    let hdr_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let hdr_nonce: [u8; 12] = kdf(response_iv, &[b"AEAD Resp Header IV"])[..12]
        .try_into()
        .expect("kdf output is 32 bytes");
    (len_key, len_nonce, hdr_key, hdr_nonce)
}
