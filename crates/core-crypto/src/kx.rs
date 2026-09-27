#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crypto::{SharedSecret, SupportedKxGroup};
use ml_kem::EncodedSizeUser;
use ml_kem::kem::Decapsulate;
use paste::paste;
use rustls::crypto;

/// ML-KEM-768 encapsulation key length (FIPS 203).
const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
const MLKEM768_CT_LEN: usize = 1088;
/// X25519 public key / shared secret length (RFC 7748).
const X25519_LEN: usize = 32;

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        let pub_key = (&priv_key).into();
        Ok(Box::new(X25519KeyExchange { priv_key, pub_key }))
    }
}

pub struct X25519KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl crypto::ActiveKeyExchange for X25519KeyExchange {
    fn complete(self: Box<X25519KeyExchange>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(self
            .priv_key
            .diffie_hellman(&peer_array.into())
            .as_ref()
            .into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

macro_rules! impl_kx {
    ($name:ident, $kx_name:ty, $secret:ty, $public_key:ty) => {
        paste! {

            #[derive(Debug)]
            #[allow(non_camel_case_types)]
            pub struct $name;

            impl crypto::SupportedKxGroup for $name {
                fn name(&self) -> rustls::NamedGroup {
                    $kx_name
                }

                fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
                    let priv_key = $secret::random(&mut rand_core::OsRng);
                    let pub_key: $public_key = (&priv_key).into();
                    Ok(Box::new([<$name KeyExchange>] {
                        priv_key,
                        pub_key: pub_key.to_sec1_bytes(),
                    }))
                }
            }

            #[allow(non_camel_case_types)]
            pub struct [<$name KeyExchange>] {
                priv_key: $secret,
                pub_key:  Box<[u8]>,
            }

            impl crypto::ActiveKeyExchange for [<$name KeyExchange>] {
                fn complete(
                    self: Box<[<$name KeyExchange>]>,
                    peer: &[u8],
                ) -> Result<SharedSecret, rustls::Error> {
                    let their_pub = $public_key::from_sec1_bytes(peer)
                        .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
                    Ok(self
                        .priv_key
                        .diffie_hellman(&their_pub)
                        .raw_secret_bytes()
                        .as_slice()
                        .into())
                }

                fn pub_key(&self) -> &[u8] {
                    &self.pub_key
                }

                fn group(&self) -> rustls::NamedGroup {
                    $name.name()
                }
            }
        }
    };
}

impl_kx! {SecP256R1, rustls::NamedGroup::secp256r1, p256::ecdh::EphemeralSecret, p256::PublicKey}
impl_kx! {SecP384R1, rustls::NamedGroup::secp384r1, p384::ecdh::EphemeralSecret, p384::PublicKey}

/// `X25519MLKEM768` (0x11ec, draft-ietf-tls-ecdhe-mlkem-05) — the group the
/// reference client offers first in `supported_groups`/`key_share`, and the
/// one Chrome 131+ offers first. Pure Rust (`ml-kem` + `x25519-dalek`); an
/// aws-lc-rs backed variant would violate the no-C-crypto build gate.
///
/// Wire layout (per draft §3): client share = ML-KEM-768 encapsulation key
/// (1184) ‖ X25519 share (32) = 1216 bytes; server share = ML-KEM-768
/// ciphertext (1088) ‖ X25519 (32); shared secret = ML-KEM ‖ X25519 (64).
/// The classical X25519 half is additionally offered as a separate
/// `key_share` entry via [`crypto::ActiveKeyExchange::hybrid_component`],
/// letting servers without ML-KEM select it without a HelloRetryRequest.
#[derive(Debug)]
pub struct X25519MLKEM768;

impl crypto::SupportedKxGroup for X25519MLKEM768 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519MLKEM768
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let (dk, ek) = <ml_kem::MlKem768 as ml_kem::KemCore>::generate(&mut rand_core::OsRng);
        let x_priv = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        let x_pub = x25519_dalek::PublicKey::from(&x_priv);
        let mut pub_key = Vec::with_capacity(MLKEM768_EK_LEN + X25519_LEN);
        pub_key.extend_from_slice(ek.as_bytes().as_slice());
        pub_key.extend_from_slice(x_pub.as_bytes());
        Ok(Box::new(X25519MLKEM768KeyExchange {
            dk,
            x_priv,
            x_pub: *x_pub.as_bytes(),
            pub_key,
        }))
    }

    fn usable_for_version(&self, version: rustls::ProtocolVersion) -> bool {
        version == rustls::ProtocolVersion::TLSv1_3
    }
}

pub struct X25519MLKEM768KeyExchange {
    dk: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
    x_priv: x25519_dalek::EphemeralSecret,
    x_pub: [u8; X25519_LEN],
    pub_key: Vec<u8>,
}

fn invalid_key_share() -> rustls::Error {
    rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare)
}

impl crypto::ActiveKeyExchange for X25519MLKEM768KeyExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        if peer.len() != MLKEM768_CT_LEN + X25519_LEN {
            return Err(invalid_key_share());
        }
        let ct: [u8; MLKEM768_CT_LEN] = peer[..MLKEM768_CT_LEN]
            .try_into()
            .map_err(|_| invalid_key_share())?;
        let pq_secret = self
            .dk
            .decapsulate(&ct.into())
            .map_err(|()| invalid_key_share())?;
        let x_peer: [u8; X25519_LEN] = peer[MLKEM768_CT_LEN..]
            .try_into()
            .map_err(|_| invalid_key_share())?;
        let x_secret = self.x_priv.diffie_hellman(&x_peer.into());
        if !x_secret.was_contributory() {
            return Err(invalid_key_share());
        }
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(pq_secret.as_slice());
        secret.extend_from_slice(x_secret.as_ref());
        Ok(secret.into())
    }

    fn hybrid_component(&self) -> Option<(rustls::NamedGroup, &[u8])> {
        Some((rustls::NamedGroup::X25519, &self.x_pub))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer: &[u8],
    ) -> Result<SharedSecret, rustls::Error> {
        let x_peer: [u8; X25519_LEN] = peer.try_into().map_err(|_| invalid_key_share())?;
        let x_secret = self.x_priv.diffie_hellman(&x_peer.into());
        if !x_secret.was_contributory() {
            return Err(invalid_key_share());
        }
        Ok(x_secret.as_ref().into())
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519MLKEM768
    }
}

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::{Encapsulate, EncapsulationKey};
    use ml_kem::{Encoded, MlKem768Params};

    #[test]
    fn x25519mlkem768_round_trip() {
        let group = X25519MLKEM768;
        assert!(group.usable_for_version(rustls::ProtocolVersion::TLSv1_3));
        assert!(!group.usable_for_version(rustls::ProtocolVersion::TLSv1_2));

        let kx = group.start().expect("start");
        assert_eq!(kx.group(), rustls::NamedGroup::X25519MLKEM768);
        let our = kx.pub_key().to_vec();
        assert_eq!(our.len(), MLKEM768_EK_LEN + X25519_LEN);
        let (_, component) = kx.hybrid_component().expect("hybrid component");
        assert_eq!(component, &our[MLKEM768_EK_LEN..]);

        // Server side: encapsulate to the offered ML-KEM key and run the
        // classical X25519 DH with its own ephemeral key.
        let ek_bytes: [u8; MLKEM768_EK_LEN] = our[..MLKEM768_EK_LEN].try_into().expect("ek len");
        let ek_raw: Encoded<EncapsulationKey<MlKem768Params>> = ek_bytes.into();
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_raw);
        let (ct, pq_secret) = ek.encapsulate(&mut rand_core::OsRng).expect("encapsulate");
        let server_x = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        let server_x_pub = x25519_dalek::PublicKey::from(&server_x);
        let client_x: [u8; X25519_LEN] = our[MLKEM768_EK_LEN..].try_into().expect("x share");
        let x_secret = server_x.diffie_hellman(&client_x.into());

        let mut server_share = Vec::with_capacity(MLKEM768_CT_LEN + X25519_LEN);
        server_share.extend_from_slice(ct.as_slice());
        server_share.extend_from_slice(server_x_pub.as_bytes());
        assert_eq!(server_share.len(), MLKEM768_CT_LEN + X25519_LEN);

        let shared = kx.complete(&server_share).expect("complete");
        let mut expected = pq_secret.as_slice().to_vec();
        expected.extend_from_slice(x_secret.as_ref());
        assert_eq!(shared.secret_bytes(), expected.as_slice());
        assert_eq!(shared.secret_bytes().len(), 64);

        // Malformed peer shares are rejected, not panics.
        let kx2 = group.start().expect("start");
        assert!(kx2.complete(&server_share[..10]).is_err());
    }

    #[test]
    fn x25519mlkem768_component_fallback() {
        let group = X25519MLKEM768;
        let kx = group.start().expect("start");
        let (name, component) = kx.hybrid_component().expect("component");
        assert_eq!(name, rustls::NamedGroup::X25519);
        assert_eq!(component.len(), X25519_LEN);

        let server_x = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        let server_x_pub = x25519_dalek::PublicKey::from(&server_x);
        let client_x: [u8; X25519_LEN] = component.try_into().expect("component len");
        let expected = server_x.diffie_hellman(&client_x.into());
        let shared = kx
            .complete_hybrid_component(server_x_pub.as_bytes())
            .expect("component complete");
        assert_eq!(shared.secret_bytes(), expected.as_ref());
        assert_eq!(shared.secret_bytes().len(), X25519_LEN);

        // Wrong-length and non-contributory classical shares are rejected.
        let kx2 = group.start().expect("start");
        assert!(
            kx2.complete_hybrid_component(&[0u8; X25519_LEN - 1])
                .is_err()
        );
        let kx3 = group.start().expect("start");
        assert!(kx3.complete_hybrid_component(&[0u8; X25519_LEN]).is_err());
        let kx4 = group.start().expect("start");
        let short = [0u8; MLKEM768_CT_LEN];
        assert!(kx4.complete(&short).is_err());
    }
}
