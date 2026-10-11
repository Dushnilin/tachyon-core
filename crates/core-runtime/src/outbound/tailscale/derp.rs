//! Tailscale DERP (Designated Encrypted Relay for Packets) framing and client.
//!
//! When peers cannot establish direct UDP connectivity due to strict NAT/firewalls,
//! WireGuard packets are relayed via DERP servers.

use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_SERVER_KEY: u8 = 0x01;
pub const FRAME_CLIENT_INFO: u8 = 0x02;
pub const FRAME_SERVER_INFO: u8 = 0x03;
pub const FRAME_SEND_PACKET: u8 = 0x04;
pub const FRAME_RECV_PACKET: u8 = 0x05;
pub const FRAME_KEEP_ALIVE: u8 = 0x06;
pub const FRAME_NOTE_PREFERRED: u8 = 0x07;
pub const FRAME_PEER_GONE: u8 = 0x08;
pub const FRAME_PING: u8 = 0x12;
pub const FRAME_PONG: u8 = 0x13;

pub const DERP_MAGIC: &[u8] = b"DERP\xf0\x9f\x94\x91";

/// Encodes a client registration frame (`0x02`).
pub fn encode_client_info(client_key: &[u8; 32], info_json: &[u8]) -> Vec<u8> {
    let payload_len = 32 + info_json.len();
    let mut buf = Vec::with_capacity(5 + payload_len);
    buf.push(FRAME_CLIENT_INFO);
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(client_key);
    buf.extend_from_slice(info_json);
    buf
}

/// Encodes a WireGuard packet to be forwarded to a target peer (`0x04`).
pub fn encode_send_packet(dst_key: &[u8; 32], packet: &[u8]) -> Vec<u8> {
    let payload_len = 32 + packet.len();
    let mut buf = Vec::with_capacity(5 + payload_len);
    buf.push(FRAME_SEND_PACKET);
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(dst_key);
    buf.extend_from_slice(packet);
    buf
}

/// Encodes a keepalive frame (`0x06`).
pub fn encode_keepalive() -> [u8; 5] {
    [FRAME_KEEP_ALIVE, 0, 0, 0, 0]
}

/// Encodes a note-preferred frame (`0x07`).
pub fn encode_note_preferred(preferred: bool) -> [u8; 6] {
    [
        FRAME_NOTE_PREFERRED,
        0,
        0,
        0,
        1,
        if preferred { 1 } else { 0 },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerpFrame {
    ServerInfo(Vec<u8>),
    RecvPacket { src_key: [u8; 32], data: Vec<u8> },
    KeepAlive,
    PeerGone([u8; 32]),
    Other { frame_type: u8, data: Vec<u8> },
}

/// Reads a single DERP frame from an asynchronous stream.
pub async fn read_derp_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<DerpFrame> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await?;
    let frame_type = header[0];
    let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;

    if length > 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("derp frame length too large: {length}"),
        ));
    }

    let mut payload = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut payload).await?;
    }

    match frame_type {
        FRAME_SERVER_INFO => Ok(DerpFrame::ServerInfo(payload)),
        FRAME_RECV_PACKET => {
            if payload.len() < 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FRAME_RECV_PACKET too short for node key",
                ));
            }
            let mut src_key = [0u8; 32];
            src_key.copy_from_slice(&payload[..32]);
            Ok(DerpFrame::RecvPacket {
                src_key,
                data: payload[32..].to_vec(),
            })
        }
        FRAME_KEEP_ALIVE => Ok(DerpFrame::KeepAlive),
        FRAME_PEER_GONE => {
            if payload.len() < 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FRAME_PEER_GONE too short for node key",
                ));
            }
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            Ok(DerpFrame::PeerGone(peer_key))
        }
        _ => Ok(DerpFrame::Other {
            frame_type,
            data: payload,
        }),
    }
}

/// Information about a DERP Region and its nodes.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: u16,
    #[serde(rename = "RegionCode")]
    pub region_code: String,
    #[serde(rename = "RegionName", default)]
    pub region_name: String,
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<DerpNode>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DerpNode {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: u16,
    #[serde(rename = "HostName")]
    pub host_name: String,
    #[serde(rename = "DERPPort", alias = "Port", default = "default_derp_port")]
    pub port: u16,
    #[serde(rename = "IPv4", default)]
    pub ipv4: Option<String>,
    #[serde(rename = "IPv6", default)]
    pub ipv6: Option<String>,
    #[serde(rename = "STUNOnly", default)]
    pub stun_only: bool,
}

fn default_derp_port() -> u16 {
    443
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct DerpMap {
    #[serde(rename = "Regions", default)]
    pub regions: HashMap<String, DerpRegion>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_derp_framing_roundtrip() {
        let client_key = [7u8; 32];
        let info = b"{\"version\": 1}";
        let client_frame = encode_client_info(&client_key, info);
        assert_eq!(client_frame[0], FRAME_CLIENT_INFO);
        let len = u32::from_be_bytes(client_frame[1..5].try_into().unwrap());
        assert_eq!(len as usize, 32 + info.len());

        let dst_key = [9u8; 32];
        let packet = b"wireguard-type4-data-packet";
        let send_frame = encode_send_packet(&dst_key, packet);

        // Convert send frame to recv frame to test read_derp_frame
        let mut sim_recv_frame = send_frame.clone();
        sim_recv_frame[0] = FRAME_RECV_PACKET;

        let mut cursor = std::io::Cursor::new(sim_recv_frame);
        let frame = read_derp_frame(&mut cursor).await.unwrap();
        match frame {
            DerpFrame::RecvPacket { src_key, data } => {
                assert_eq!(src_key, dst_key);
                assert_eq!(data, packet);
            }
            _ => panic!("unexpected frame"),
        }
    }
}
