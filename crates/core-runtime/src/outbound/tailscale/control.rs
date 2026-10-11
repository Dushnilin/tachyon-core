//! Tailscale Control Plane client (SPEC 111 HTTPS 443 coordination).
//!
//! Handles registration, machine/node key persistence, Noise_IK establishment,
//! and MapResponse peer/DERP streaming.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::PublicKey;

use crate::outbound::tailscale::derp::DerpMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hostinfo {
    #[serde(rename = "OS", default = "default_os")]
    pub os: String,
    #[serde(rename = "Hostname", default)]
    pub hostname: String,
    #[serde(rename = "RoutableIPs", default)]
    pub routable_ips: Vec<String>,
}

fn default_os() -> String {
    "linux".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthObj {
    #[serde(rename = "AuthKey")]
    pub auth_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "Auth", skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthObj>,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
    #[serde(rename = "Ephemeral")]
    pub ephemeral: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeObj {
    #[serde(rename = "ID")]
    pub id: u64,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "DERP", default)]
    pub derp: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "Node", default)]
    pub node: Option<NodeObj>,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: Option<bool>,
    #[serde(rename = "AuthURL", default)]
    pub auth_url: Option<String>,
    #[serde(rename = "Error", default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "Compress")]
    pub compress: String,
    #[serde(rename = "KeepAlive")]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "Stream")]
    pub stream: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerObj {
    #[serde(rename = "ID")]
    pub id: u64,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Option<Vec<String>>,
    #[serde(rename = "DERP", default)]
    pub derp: Option<Value>,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapResponse {
    #[serde(rename = "Node", default)]
    pub node: Option<NodeObj>,
    #[serde(rename = "Peers", default)]
    pub peers: Option<Vec<PeerObj>>,
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<DerpMap>,
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: Option<bool>,
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[allow(clippy::result_unit_err)]
pub fn from_hex(s: &str, out: &mut [u8]) -> Result<(), ()> {
    if s.len() != out.len() * 2 {
        return Err(());
    }
    for (pair, byte) in s.as_bytes().as_chunks::<2>().0.iter().zip(out.iter_mut()) {
        let digit = |value: u8| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err(()),
        };
        *byte = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(())
}

pub fn parse_key_hex(s: &str) -> Option<[u8; 32]> {
    let clean = s
        .trim()
        .strip_prefix("mkey:")
        .or_else(|| s.trim().strip_prefix("nodekey:"))
        .unwrap_or(s.trim());
    if clean.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    from_hex(clean, &mut out).ok()?;
    Some(out)
}

/// Converts a public key into the Tailscale `"nodekey:<hex>"` format.
pub fn node_key_str(pk: &PublicKey) -> String {
    format!("nodekey:{}", to_hex(pk.as_bytes()))
}

/// Converts a public key into the Tailscale `"mkey:<hex>"` format.
pub fn machine_key_str(pk: &PublicKey) -> String {
    format!("mkey:{}", to_hex(pk.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_map_response_parsing() {
        let register_json = r#"{
            "Node": {
                "ID": 1001,
                "Key": "nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                "AllowedIPs": ["100.64.0.1/32"],
                "Endpoints": ["1.2.3.4:41641"]
            },
            "MachineAuthorized": true
        }"#;

        let reg_resp: RegisterResponse = serde_json::from_str(register_json).unwrap();
        assert_eq!(reg_resp.machine_authorized, Some(true));
        let node = reg_resp.node.unwrap();
        assert_eq!(node.id, 1001);
        assert_eq!(node.addresses.len(), 2);
        assert_eq!(node.addresses[0], "100.64.0.1/32");

        let map_json = r#"{
            "Peers": [
                {
                    "ID": 2002,
                    "Key": "nodekey:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "Name": "peer-server",
                    "Addresses": ["100.64.0.2/32"],
                    "AllowedIPs": ["100.64.0.2/32", "192.168.10.0/24"],
                    "Endpoints": ["5.6.7.8:41641"],
                    "DERP": 1,
                    "Online": true
                }
            ],
            "DERPMap": {
                "Regions": {
                    "1": {
                        "RegionID": 1,
                        "RegionCode": "nyc",
                        "Nodes": [
                            {
                                "Name": "1a",
                                "RegionID": 1,
                                "HostName": "derp1a.tailscale.com",
                                "Port": 443
                            }
                        ]
                    }
                }
            }
        }"#;

        let map_resp: MapResponse = serde_json::from_str(map_json).unwrap();
        let peers = map_resp.peers.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name.as_deref(), Some("peer-server"));
        assert_eq!(peers[0].allowed_ips.len(), 2);

        let derp_map = map_resp.derp_map.unwrap();
        assert!(derp_map.regions.contains_key("1"));
        let region = &derp_map.regions["1"];
        assert_eq!(region.region_code, "nyc");
        assert_eq!(region.nodes[0].host_name, "derp1a.tailscale.com");
    }

    #[test]
    fn test_key_hex_conversion() {
        let pk_bytes = [42u8; 32];
        let pk = PublicKey::from(pk_bytes);
        let formatted = node_key_str(&pk);
        assert!(formatted.starts_with("nodekey:"));
        let parsed = parse_key_hex(&formatted).unwrap();
        assert_eq!(parsed, pk_bytes);
    }
}
