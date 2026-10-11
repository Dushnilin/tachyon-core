//! NaCl's XSalsa20-Poly1305 secretbox wire primitive, required by DERP.
//! Reuses the workspace's Poly1305 and constant-time comparison; no new crate.
//! The caller supplies the X25519/HSalsa20 precomputed box key.

use alloc::vec::Vec;
use p256::elliptic_curve::subtle::ConstantTimeEq;
use poly1305::{Poly1305, universal_hash::KeyInit};

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("Salsa20 word has four bytes"))
}

fn state(key: &[u8; 32], input: &[u8; 16]) -> [u32; 16] {
    let sigma = b"expand 32-byte k";
    [
        word(&sigma[..4]),
        word(&key[..4]),
        word(&key[4..8]),
        word(&key[8..12]),
        word(&key[12..16]),
        word(&sigma[4..8]),
        word(&input[..4]),
        word(&input[4..8]),
        word(&input[8..12]),
        word(&input[12..]),
        word(&sigma[8..12]),
        word(&key[16..20]),
        word(&key[20..24]),
        word(&key[24..28]),
        word(&key[28..]),
        word(&sigma[12..]),
    ]
}

fn rounds(mut x: [u32; 16]) -> [u32; 16] {
    for _ in 0..10 {
        for [a, b, c, d] in [
            [0, 4, 8, 12],
            [5, 9, 13, 1],
            [10, 14, 2, 6],
            [15, 3, 7, 11],
            [0, 1, 2, 3],
            [5, 6, 7, 4],
            [10, 11, 8, 9],
            [15, 12, 13, 14],
        ] {
            x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
            x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
            x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
            x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
        }
    }
    x
}

/// NaCl crypto_box_beforenm: HSalsa20(shared X25519 secret, zero input).
pub fn box_key(shared: &[u8; 32]) -> [u8; 32] {
    hsalsa20(shared, &[0; 16])
}

fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let x = rounds(state(key, input));
    let mut out = [0; 32];
    for (offset, index) in [0, 5, 10, 15, 6, 7, 8, 9].into_iter().enumerate() {
        out[offset * 4..offset * 4 + 4].copy_from_slice(&x[index].to_le_bytes());
    }
    out
}

fn stream_xor(key: &[u8; 32], nonce: &[u8; 24], bytes: &mut [u8]) {
    let subkey = hsalsa20(key, nonce[..16].try_into().expect("XSalsa20 nonce prefix"));
    let mut input = [0; 16];
    input[..8].copy_from_slice(&nonce[16..]);
    for (counter, chunk) in bytes.chunks_mut(64).enumerate() {
        input[8..].copy_from_slice(&(counter as u64).to_le_bytes());
        let s = state(&subkey, &input);
        let x = rounds(s);
        let mut block = [0; 64];
        for i in 0..16 {
            block[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(s[i]).to_le_bytes());
        }
        for (dst, value) in chunk.iter_mut().zip(block) {
            *dst ^= value;
        }
    }
}

/// NaCl crypto_secretbox_easy: tag first, then ciphertext.
pub fn seal(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let mut buffer = alloc::vec![0; 32 + plaintext.len()];
    buffer[32..].copy_from_slice(plaintext);
    stream_xor(key, nonce, &mut buffer);
    let poly_key: [u8; 32] = buffer[..32]
        .try_into()
        .expect("XSalsa20 authentication key");
    let tag = Poly1305::new(&poly_key.into()).compute_unpadded(&buffer[32..]);
    buffer[16..32].copy_from_slice(&tag);
    buffer.drain(..16);
    buffer
}

/// Authenticate before exposing plaintext. Truncated and modified boxes fail.
pub fn open(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 {
        return None;
    }
    let mut poly_key = [0; 32];
    stream_xor(key, nonce, &mut poly_key);
    let tag = Poly1305::new(&poly_key.into()).compute_unpadded(&ciphertext[16..]);
    if !bool::from(tag.as_slice().ct_eq(&ciphertext[..16])) {
        return None;
    }
    let mut buffer = alloc::vec![0; 32 + ciphertext.len() - 16];
    buffer[32..].copy_from_slice(&ciphertext[16..]);
    stream_xor(key, nonce, &mut buffer);
    buffer.drain(..32);
    Some(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libsodium_secretbox_wire_vector() {
        // test/default/secretbox.c and secretbox.exp, libsodium (ISC).
        let key = [
            27, 39, 85, 100, 115, 233, 133, 212, 98, 205, 81, 25, 122, 154, 70, 199, 96, 9, 84,
            158, 172, 100, 116, 242, 6, 196, 238, 8, 68, 246, 131, 137,
        ];
        let nonce = [
            105, 105, 110, 233, 85, 182, 43, 115, 205, 98, 189, 168, 117, 252, 115, 214, 130, 25,
            224, 3, 107, 122, 11, 55,
        ];
        let message = [
            190, 7, 95, 197, 60, 129, 242, 213, 207, 20, 19, 22, 235, 235, 12, 123, 82, 40, 197,
            42, 76, 98, 203, 212, 75, 102, 132, 155, 100, 36, 79, 252, 229, 236, 186, 175, 51, 189,
            117, 26, 26, 199, 40, 212, 94, 108, 97, 41, 108, 220, 60, 1, 35, 53, 97, 244, 29, 182,
            108, 206, 49, 74, 219, 49, 14, 59, 232, 37, 12, 70, 240, 109, 206, 234, 58, 127, 161,
            52, 128, 87, 226, 246, 85, 106, 214, 177, 49, 138, 2, 74, 131, 143, 33, 175, 31, 222,
            4, 137, 119, 235, 72, 245, 159, 253, 73, 36, 202, 28, 96, 144, 46, 82, 240, 160, 137,
            188, 118, 137, 112, 64, 224, 130, 249, 55, 118, 56, 72, 100, 94, 7, 5,
        ];
        let ciphertext = [
            243, 255, 199, 112, 63, 148, 0, 229, 42, 125, 251, 75, 61, 51, 5, 217, 142, 153, 59,
            159, 72, 104, 18, 115, 194, 150, 80, 186, 50, 252, 118, 206, 72, 51, 46, 167, 22, 77,
            150, 164, 71, 111, 184, 197, 49, 161, 24, 106, 192, 223, 193, 124, 152, 220, 232, 123,
            77, 167, 240, 17, 236, 72, 201, 114, 113, 210, 194, 15, 155, 146, 143, 226, 39, 13,
            111, 184, 99, 213, 23, 56, 180, 142, 238, 227, 20, 167, 204, 138, 185, 50, 22, 69, 72,
            229, 38, 174, 144, 34, 67, 104, 81, 122, 207, 234, 189, 107, 179, 115, 43, 192, 233,
            218, 153, 131, 43, 97, 202, 1, 182, 222, 86, 36, 74, 158, 136, 213, 249, 179, 121, 115,
            246, 34, 164, 61, 20, 166, 89, 155, 31, 101, 76, 180, 90, 116, 227, 85, 165,
        ];
        assert_eq!(seal(&key, &nonce, &message), ciphertext);
        assert_eq!(
            open(&key, &nonce, &ciphertext).expect("valid known-answer box"),
            message
        );
    }

    #[test]
    fn authentication_rejects_tampering_and_short_boxes() {
        let key = [7; 32];
        let nonce = [9; 24];
        for length in [0, 1, 31, 32, 63, 64, 65, 1400] {
            let plaintext = alloc::vec![42; length];
            let mut box_ = seal(&key, &nonce, &plaintext);
            assert_eq!(open(&key, &nonce, &box_).expect("valid box"), plaintext);
            box_[0] ^= 1;
            assert!(open(&key, &nonce, &box_).is_none());
        }
        assert!(open(&key, &nonce, &[0; 15]).is_none());
    }
}
