//! Authenticated Tailscale discovery, using the existing NaCl box primitive.
//! Wire format: tailscale.com/disco (BSD-3-Clause), not a linked runtime.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const HEADER: usize = 6 + 32 + 24;

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Ping {
        id: [u8; 12],
        node: Option<[u8; 32]>,
    },
    Pong {
        id: [u8; 12],
        source: SocketAddr,
    },
    CallMeMaybe(Vec<SocketAddr>),
}

pub fn fresh_key() -> io::Result<StaticSecret> {
    let mut key = [0; 32];
    getrandom::fill(&mut key)
        .map_err(|_| io::Error::other("tailscale: discovery entropy unavailable"))?;
    Ok(StaticSecret::from(key))
}

pub fn sender(packet: &[u8]) -> Option<[u8; 32]> {
    if packet.len() < HEADER + 16 || !packet.starts_with(MAGIC) {
        return None;
    }
    packet[6..38].try_into().ok()
}

fn address(bytes: &[u8]) -> Option<SocketAddr> {
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(..16)?).ok()?);
    let ip = ip
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ip));
    let port = u16::from_be_bytes(bytes.get(16..18)?.try_into().ok()?);
    Some(SocketAddr::new(ip, port))
}

fn append_address(bytes: &mut Vec<u8>, address: SocketAddr) {
    let ip = match address.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    bytes.extend_from_slice(&ip.octets());
    bytes.extend_from_slice(&address.port().to_be_bytes());
}

fn payload(message: &Message) -> Vec<u8> {
    let mut bytes = match message {
        Message::Ping { .. } => vec![1, 0],
        Message::Pong { .. } => vec![2, 0],
        Message::CallMeMaybe(_) => vec![3, 0],
    };
    match message {
        Message::Ping { id, node } => {
            bytes.extend_from_slice(id);
            if let Some(node) = node {
                bytes.extend_from_slice(node);
            }
        }
        Message::Pong { id, source } => {
            bytes.extend_from_slice(id);
            append_address(&mut bytes, *source);
        }
        Message::CallMeMaybe(endpoints) => {
            for endpoint in endpoints.iter().take(8) {
                append_address(&mut bytes, *endpoint);
            }
        }
    }
    bytes
}

fn parse(bytes: &[u8]) -> Option<Message> {
    if bytes.get(1) != Some(&0) {
        return None;
    }
    let data = bytes.get(2..)?;
    match bytes.first()? {
        1 if data.len() >= 12 => Some(Message::Ping {
            id: data[..12].try_into().ok()?,
            node: data
                .get(12..44)
                .and_then(|node| <[u8; 32]>::try_from(node).ok())
                .filter(|node| *node != [0; 32]),
        }),
        2 if data.len() >= 30 => Some(Message::Pong {
            id: data[..12].try_into().ok()?,
            source: address(&data[12..30])?,
        }),
        3 if data.len().is_multiple_of(18) && data.len() <= 8 * 18 => Some(Message::CallMeMaybe(
            data.as_chunks::<18>()
                .0
                .iter()
                .filter_map(|bytes| address(bytes))
                .collect(),
        )),
        _ => None,
    }
}

fn seal_nonce(
    secret: &StaticSecret,
    recipient: &[u8; 32],
    nonce: &[u8; 24],
    message: &Message,
) -> Option<Vec<u8>> {
    let shared = secret.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return None;
    }
    let key = core_crypto::nacl::box_key(shared.as_bytes());
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(PublicKey::from(secret).as_bytes());
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&core_crypto::nacl::seal(&key, nonce, &payload(message)));
    Some(bytes)
}

pub fn seal(secret: &StaticSecret, recipient: &[u8; 32], message: &Message) -> Option<Vec<u8>> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).ok()?;
    seal_nonce(secret, recipient, &nonce, message)
}

pub fn open(secret: &StaticSecret, packet: &[u8]) -> Option<Message> {
    let sender = sender(packet)?;
    let shared = secret.diffie_hellman(&PublicKey::from(sender));
    if !shared.was_contributory() {
        return None;
    }
    let nonce = packet[38..HEADER].try_into().ok()?;
    let key = core_crypto::nacl::box_key(shared.as_bytes());
    parse(&core_crypto::nacl::open(&key, nonce, &packet[HEADER..])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_tailscale_disco_and_nacl_box_ping_vector() {
        // Generated with tailscale.com/disco v1.86.5 and x/crypto/nacl/box.
        // Fixed test keys/nonces only. Go is not part of the runtime.
        let hex = "5453f09f92ac73b2d8b76aa9b53660032bc8f5d8bee3a3ae4e3b3a7fd49ade81f7347a34aa68070707070707070707070707070707070707070707070707406cc15e2bbab3c87a911f026898ac8b541513e2ee3f79c5d6b45f876e8b5969de57e6331e364382c704f83091b1daf902ae4b0a667ac9f6b983b2a18388";
        let mut expected = vec![0; hex.len() / 2];
        super::super::control::from_hex(hex, &mut expected).unwrap();
        let alice = StaticSecret::from([11; 32]);
        let bob = StaticSecret::from([22; 32]);
        let message = Message::Ping {
            id: [3; 12],
            node: Some([4; 32]),
        };
        assert_eq!(
            seal_nonce(&alice, PublicKey::from(&bob).as_bytes(), &[7; 24], &message).unwrap(),
            expected
        );
        assert_eq!(open(&bob, &expected), Some(message));
    }

    #[test]
    fn discovery_authenticates_each_message_and_rejects_tampering() {
        let alice = StaticSecret::from([11; 32]);
        let bob = StaticSecret::from([22; 32]);
        let bob_public = *PublicKey::from(&bob).as_bytes();
        for message in [
            Message::Ping {
                id: [3; 12],
                node: Some([4; 32]),
            },
            Message::Pong {
                id: [3; 12],
                source: "192.0.2.1:41641".parse().unwrap(),
            },
            Message::CallMeMaybe(vec![
                "192.0.2.1:41641".parse().unwrap(),
                "[2001:db8::1]:42".parse().unwrap(),
            ]),
        ] {
            let mut packet = seal_nonce(&alice, &bob_public, &[7; 24], &message).unwrap();
            assert_eq!(open(&bob, &packet), Some(message));
            *packet.last_mut().unwrap() ^= 1;
            assert!(open(&bob, &packet).is_none());
            assert!(open(&StaticSecret::from([99; 32]), &packet).is_none());
        }
        assert!(seal(&alice, &[0; 32], &Message::CallMeMaybe(vec![])).is_none());
        assert!(open(&bob, MAGIC).is_none());
        assert!(parse(&[1, 1, 0]).is_none());
    }
}
