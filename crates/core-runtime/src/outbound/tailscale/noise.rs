//! Noise_IK_25519_ChaChaPoly_BLAKE2s protocol implementation for Tailscale.
//!
//! Tailscale uses Noise_IK over HTTPS 443 (SPEC 111) to secure controlplane
//! communication (registration and map synchronization).

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use x25519_dalek::{PublicKey, StaticSecret};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// State for encrypting/decrypting payload with ChaCha20-Poly1305 and a counter nonce.
#[derive(Clone, Debug)]
pub struct CipherState {
    k: Option<[u8; 32]>,
    n: u64,
}

impl CipherState {
    pub fn new(key: Option<[u8; 32]>) -> Self {
        Self { k: key, n: 0 }
    }

    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    pub fn set_key(&mut self, key: [u8; 32]) {
        self.k = Some(key);
        self.n = 0;
    }

    fn make_nonce(n: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        // 4 bytes 0 + 8 bytes counter in little-endian (Noise spec)
        nonce_bytes[4..].copy_from_slice(&n.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let Some(key_bytes) = self.k else {
            return plaintext.to_vec();
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = Self::make_nonce(self.n);
        self.n = self.n.checked_add(1).expect("nonce overflow");

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, ad, &mut buffer)
            .expect("encryption error");
        buffer.extend_from_slice(tag.as_slice());
        buffer
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(key_bytes) = self.k else {
            return Ok(ciphertext.to_vec());
        };
        if ciphertext.len() < 16 {
            anyhow::bail!("ciphertext too short for auth tag");
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = Self::make_nonce(self.n);
        self.n = self.n.checked_add(1).expect("nonce overflow");

        let split_pos = ciphertext.len() - 16;
        let mut buffer = ciphertext[..split_pos].to_vec();
        let tag = Tag::from_slice(&ciphertext[split_pos..]);

        cipher
            .decrypt_in_place_detached(&nonce, ad, &mut buffer, tag)
            .map_err(|_| anyhow::anyhow!("noise auth tag verification failed"))?;
        Ok(buffer)
    }
}

/// Noise symmetric state tracking chaining key `ck` and handshake hash `h`.
#[derive(Clone, Debug)]
pub struct SymmetricState {
    pub h: [u8; 32],
    pub ck: [u8; 32],
    pub cs: CipherState,
}

impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= 32 {
            let mut buf = [0u8; 32];
            buf[..protocol_name.len()].copy_from_slice(protocol_name);
            buf
        } else {
            let mut hasher = Blake2s256::new();
            hasher.update(protocol_name);
            hasher.finalize().into()
        };
        let ck = h;
        Self {
            h,
            ck,
            cs: CipherState::new(None),
        }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    pub fn mix_key(&mut self, ikm: &[u8]) {
        let (new_ck, temp_k) = hkdf2(&self.ck, ikm);
        self.ck = new_ck;
        self.cs.set_key(temp_k);
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = self.cs.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&ciphertext);
        ciphertext
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let plaintext = self.cs.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    pub fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::new(Some(k1)), CipherState::new(Some(k2)))
    }
}

fn blake2s_hash(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data).into()
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&blake2s_hash(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner_h = Blake2s256::new();
    inner_h.update(ipad);
    inner_h.update(data);
    let inner: [u8; 32] = inner_h.finalize().into();
    let mut outer_h = Blake2s256::new();
    outer_h.update(opad);
    outer_h.update(inner);
    outer_h.finalize().into()
}

/// Noise standard HKDF2 using BLAKE2s.
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(ck, ikm);
    let k1 = hmac_blake2s(&prk, &[0x01]);
    let mut m2 = Vec::with_capacity(33);
    m2.extend_from_slice(&k1);
    m2.push(0x02);
    let k2 = hmac_blake2s(&prk, &m2);
    (k1, k2)
}

/// Noise_IK Initiator State Machine.
pub struct NoiseIkInitiator {
    s: StaticSecret,
    s_pub: PublicKey,
    rs: PublicKey,
    e: Option<StaticSecret>,
    e_pub: Option<PublicKey>,
    sym: SymmetricState,
}

impl NoiseIkInitiator {
    pub fn new(s: StaticSecret, rs: PublicKey, prologue: &[u8]) -> Self {
        let s_pub = PublicKey::from(&s);
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(prologue);
        // Pre-message: responder static public key
        sym.mix_hash(rs.as_bytes());

        Self {
            s,
            s_pub,
            rs,
            e: None,
            e_pub: None,
            sym,
        }
    }

    /// Generates handshake message 1 (`-> e, es, s, ss, payload`).
    pub fn write_msg1(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut e_bytes = [0u8; 32];
        getrandom::fill(&mut e_bytes).expect("getrandom ephemeral key");
        let e = StaticSecret::from(e_bytes);
        let e_pub = PublicKey::from(&e);

        self.e = Some(e);
        self.e_pub = Some(e_pub);

        let mut out = Vec::with_capacity(32 + 48 + payload.len() + 16);

        // e
        out.extend_from_slice(e_pub.as_bytes());
        self.sym.mix_hash(e_pub.as_bytes());

        // es
        let es = self.e.as_ref().unwrap().diffie_hellman(&self.rs);
        self.sym.mix_key(es.as_bytes());

        // s
        let enc_s = self.sym.encrypt_and_hash(self.s_pub.as_bytes());
        out.extend_from_slice(&enc_s);

        // ss
        let ss = self.s.diffie_hellman(&self.rs);
        self.sym.mix_key(ss.as_bytes());

        // payload
        let enc_payload = self.sym.encrypt_and_hash(payload);
        out.extend_from_slice(&enc_payload);

        out
    }

    /// Processes handshake message 2 (`<- e, ee, se, payload`) and produces transport ciphers.
    pub fn read_msg2(&mut self, msg: &[u8]) -> anyhow::Result<(Vec<u8>, (CipherState, CipherState))> {
        if msg.len() < 32 + 16 {
            anyhow::bail!("handshake message 2 is too short");
        }
        let re_bytes: [u8; 32] = msg[..32].try_into().unwrap();
        let re_pub = PublicKey::from(re_bytes);
        self.sym.mix_hash(re_pub.as_bytes());

        let e = self.e.take().ok_or_else(|| anyhow::anyhow!("missing ephemeral key"))?;
        let ee = e.diffie_hellman(&re_pub);
        self.sym.mix_key(ee.as_bytes());

        let se = self.s.diffie_hellman(&re_pub);
        self.sym.mix_key(se.as_bytes());

        let payload = self.sym.decrypt_and_hash(&msg[32..])?;
        let (tx, rx) = self.sym.split();
        Ok((payload, (tx, rx)))
    }
}

/// Noise_IK Responder (for testing and bidirectional handshake simulation).
pub struct NoiseIkResponder {
    s: StaticSecret,
    #[allow(dead_code)]
    s_pub: PublicKey,
    sym: SymmetricState,
}

impl NoiseIkResponder {
    pub fn new(s: StaticSecret, prologue: &[u8]) -> Self {
        let s_pub = PublicKey::from(&s);
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(prologue);
        sym.mix_hash(s_pub.as_bytes());

        Self { s, s_pub, sym }
    }

    pub fn read_msg1(&mut self, msg: &[u8]) -> anyhow::Result<(PublicKey, Vec<u8>, PublicKey)> {
        if msg.len() < 32 + 48 + 16 {
            anyhow::bail!("handshake message 1 is too short");
        }
        let e_bytes: [u8; 32] = msg[..32].try_into().unwrap();
        let e_pub = PublicKey::from(e_bytes);
        self.sym.mix_hash(e_pub.as_bytes());

        let es = self.s.diffie_hellman(&e_pub);
        self.sym.mix_key(es.as_bytes());

        let s_bytes = self.sym.decrypt_and_hash(&msg[32..80])?;
        let s_pub = PublicKey::from(<[u8; 32]>::try_from(s_bytes.as_slice()).unwrap());

        let ss = self.s.diffie_hellman(&s_pub);
        self.sym.mix_key(ss.as_bytes());

        let payload = self.sym.decrypt_and_hash(&msg[80..])?;
        Ok((s_pub, payload, e_pub))
    }

    pub fn write_msg2(
        &mut self,
        client_e: &PublicKey,
        client_s: &PublicKey,
        payload: &[u8],
    ) -> (Vec<u8>, (CipherState, CipherState)) {
        let mut e_bytes = [0u8; 32];
        getrandom::fill(&mut e_bytes).expect("getrandom");
        let re = StaticSecret::from(e_bytes);
        let re_pub = PublicKey::from(&re);

        let mut out = Vec::with_capacity(32 + payload.len() + 16);
        out.extend_from_slice(re_pub.as_bytes());
        self.sym.mix_hash(re_pub.as_bytes());

        let ee = re.diffie_hellman(client_e);
        self.sym.mix_key(ee.as_bytes());

        let se = re.diffie_hellman(client_s);
        self.sym.mix_key(se.as_bytes());

        let enc_payload = self.sym.encrypt_and_hash(payload);
        out.extend_from_slice(&enc_payload);

        let (rx, tx) = self.sym.split();
        (out, (tx, rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_ik_handshake_roundtrip() {
        let mut client_s_bytes = [0u8; 32];
        client_s_bytes[0] = 1;
        let client_s = StaticSecret::from(client_s_bytes);

        let mut server_s_bytes = [0u8; 32];
        server_s_bytes[0] = 2;
        let server_s = StaticSecret::from(server_s_bytes);
        let server_pub = PublicKey::from(&server_s);

        let prologue = b"ts2021";

        let mut client = NoiseIkInitiator::new(client_s, server_pub, prologue);
        let mut server = NoiseIkResponder::new(server_s, prologue);

        let client_hello = b"register-request-early-payload";
        let msg1 = client.write_msg1(client_hello);

        let (rec_client_pub, rec_payload, client_e_pub) = server.read_msg1(&msg1).unwrap();
        assert_eq!(rec_payload, client_hello);

        let server_reply = b"register-response-payload";
        let (msg2, (mut server_tx, mut server_rx)) =
            server.write_msg2(&client_e_pub, &rec_client_pub, server_reply);

        let (reply, (mut client_tx, mut client_rx)) = client.read_msg2(&msg2).unwrap();
        assert_eq!(reply, server_reply);

        // Verify transport cipher exchange
        let ping = b"hello from client over noise";
        let encrypted_ping = client_tx.encrypt_with_ad(&[], ping);
        let decrypted_ping = server_rx.decrypt_with_ad(&[], &encrypted_ping).unwrap();
        assert_eq!(decrypted_ping, ping);

        let pong = b"pong from server over noise";
        let encrypted_pong = server_tx.encrypt_with_ad(&[], pong);
        let decrypted_pong = client_rx.decrypt_with_ad(&[], &encrypted_pong).unwrap();
        assert_eq!(decrypted_pong, pong);
    }
}
