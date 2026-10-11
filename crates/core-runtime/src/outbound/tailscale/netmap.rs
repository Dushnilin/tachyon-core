//! Incremental control maps, MagicDNS and fail-closed packet authorization.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

use serde_json::Value;
use smoltcp::wire::{IpAddress, IpCidr};

use super::control::parse_key_hex;
use super::derp::DerpMap;

#[derive(Clone)]
pub struct Peer {
    pub id: u64,
    pub key: [u8; 32],
    pub disco_key: Option<[u8; 32]>,
    pub name: String,
    pub addresses: Vec<IpCidr>,
    pub allowed: Vec<IpCidr>,
    pub endpoints: Vec<SocketAddr>,
    pub home_derp: u16,
    pub expired: bool,
    expires_at: Option<u64>,
}

impl Peer {
    fn parse(value: &Value) -> io::Result<Self> {
        let id = value
            .get("ID")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("tailscale: peer ID missing"))?;
        let key = value
            .get("Key")
            .and_then(Value::as_str)
            .and_then(parse_key_hex)
            .ok_or_else(|| invalid("tailscale: peer key missing"))?;
        if key == [0; 32] {
            return Err(invalid("tailscale: zero peer key"));
        }
        let disco_key = discovery_key(value.get("DiscoKey"))?;
        let name = value
            .get("Name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let addresses = prefixes(value.get("Addresses"))?;
        let allowed = match value.get("AllowedIPs") {
            Some(value) => prefixes(Some(value))?,
            None => addresses.clone(),
        };
        let endpoints = value
            .get("Endpoints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|value| value.parse().ok())
            .collect();
        let home_derp = value
            .get("HomeDERP")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .filter(|region| *region != 0)
            .or_else(|| {
                value
                    .get("DERP")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<SocketAddr>().ok())
                    .map(|addr| addr.port())
            })
            .unwrap_or(0);
        let expired = value
            .get("Expired")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || value.get("MachineAuthorized").and_then(Value::as_bool) == Some(false);
        let expires_at = value
            .get("KeyExpiry")
            .and_then(Value::as_str)
            .map(expiry)
            .transpose()?
            .flatten();
        Ok(Self {
            id,
            key,
            disco_key,
            name,
            addresses,
            allowed,
            endpoints,
            home_derp,
            expired,
            expires_at,
        })
    }

    pub fn owns_source(&self, ip: IpAddr) -> bool {
        !self.is_expired()
            && self
                .allowed
                .iter()
                .any(|cidr| cidr.prefix_len() != 0 && cidr.contains_addr(&IpAddress::from(ip)))
    }
    pub fn is_expired(&self) -> bool {
        self.expired
            || self
                .expires_at
                .is_some_and(|expiry| expiry <= unix_seconds())
    }
}

fn discovery_key(value: Option<&Value>) -> io::Result<Option<[u8; 32]>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| invalid("tailscale: invalid discovery key"))?;
    let hex = text
        .strip_prefix("discokey:")
        .ok_or_else(|| invalid("tailscale: invalid discovery key prefix"))?;
    let mut key = [0; 32];
    super::control::from_hex(hex, &mut key)
        .map_err(|_| invalid("tailscale: invalid discovery key"))?;
    Ok((key != [0; 32]).then_some(key))
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Go time.Time's UTC wire form, including optional fractional seconds. No new
// date/time crate is needed just to enforce a node-key deadline.
fn expiry(text: &str) -> io::Result<Option<u64>> {
    if text == "0001-01-01T00:00:00Z" {
        return Ok(None);
    }
    let b = text.as_bytes();
    if !text.is_ascii()
        || b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return Err(invalid("tailscale: invalid UTC key expiry"));
    }
    let number = |range: std::ops::Range<usize>| -> io::Result<i64> {
        let part = &text[range];
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("tailscale: invalid key expiry digits"));
        }
        part.parse()
            .map_err(|_| invalid("tailscale: invalid key expiry digits"))
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(invalid("tailscale: invalid key expiry date"));
    }
    if b.len() > 20
        && (b[19] != b'.'
            || b.len() == 21
            || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)
            || b.len() > 30)
    {
        return Err(invalid("tailscale: invalid key expiry fraction"));
    }
    let y = year - i64::from(month <= 2);
    let era = y / 400;
    let yoe = y - era * 400;
    let shifted = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * shifted + 2) / 5 + day - 1;
    let day = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let seconds = day * 86400 + hour * 3600 + minute * 60 + second;
    Ok(Some(u64::try_from(seconds).map_err(|_| {
        invalid("tailscale: expiry predates the Unix epoch")
    })?))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn prefixes(value: Option<&Value>) -> io::Result<Vec<IpCidr>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| invalid("tailscale: invalid peer addresses"))?;
    array
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| invalid("tailscale: invalid peer CIDR"))
        })
        .collect()
}

#[derive(Clone, Default)]
pub struct Netmap {
    pub own_addresses: Vec<IpCidr>,
    pub own_name: String,
    pub peers: BTreeMap<u64, Peer>,
    pub derp: DerpMap,
    /// Chosen by the control owner and shared with the packet transport.
    pub home_derp: u16,
    pub dns: Value,
    filters: Vec<Value>,
    own_expiry: Option<u64>,
    own_preferred_derp: u16,
}

impl Netmap {
    /// Apply to a clone: malformed/dangerous updates cannot partially alter a
    /// working map. Missing Node, DNSConfig and PacketFilter mean unchanged.
    pub fn update(&mut self, map: &Value) -> io::Result<()> {
        if map
            .get("TKAInfo")
            .and_then(|info| info.get("Disabled"))
            .and_then(Value::as_bool)
            == Some(false)
            || map.get("TKAEnabled").and_then(Value::as_bool) == Some(true)
        {
            return Err(invalid(
                "tailscale: tailnet lock requires signed-netmap support",
            ));
        }
        let mut next = self.clone();
        if let Some(node) = map.get("Node").filter(|value| !value.is_null()) {
            let node = Peer::parse(node)?;
            if node.is_expired() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "tailscale: local node is not authorized",
                ));
            }
            next.own_addresses = node.addresses;
            next.own_name = node.name;
            next.own_expiry = node.expires_at;
            next.own_preferred_derp = node.home_derp;
        }
        if let Some(peers) = map.get("Peers").and_then(Value::as_array) {
            next.peers.clear();
            for peer in peers {
                let peer = Peer::parse(peer)?;
                next.peers.insert(peer.id, peer);
            }
        }
        if let Some(peers) = map.get("PeersChanged").and_then(Value::as_array) {
            for peer in peers {
                let peer = Peer::parse(peer)?;
                next.peers.insert(peer.id, peer);
            }
        }
        if let Some(ids) = map.get("PeersRemoved").and_then(Value::as_array) {
            for id in ids {
                if let Some(id) = id.as_u64() {
                    next.peers.remove(&id);
                }
            }
        }
        if let Some(patches) = map.get("PeersChangedPatch").and_then(Value::as_array) {
            for patch in patches {
                let id = patch
                    .get("NodeID")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("tailscale: peer patch ID missing"))?;
                let Some(peer) = next.peers.get_mut(&id) else {
                    continue;
                };
                if let Some(key) = patch.get("DiscoKey").filter(|value| !value.is_null()) {
                    peer.disco_key = discovery_key(Some(key))?;
                }
                if let Some(key) = patch.get("Key").filter(|value| !value.is_null()) {
                    peer.key = key
                        .as_str()
                        .and_then(parse_key_hex)
                        .filter(|key| *key != [0; 32])
                        .ok_or_else(|| invalid("tailscale: invalid patched peer key"))?;
                }
                if let Some(region) = patch
                    .get("DERPRegion")
                    .and_then(Value::as_u64)
                    .filter(|id| *id != 0)
                {
                    peer.home_derp = u16::try_from(region)
                        .map_err(|_| invalid("tailscale: invalid patched DERP region"))?;
                }
                if let Some(endpoints) = patch
                    .get("Endpoints")
                    .and_then(Value::as_array)
                    .filter(|endpoints| !endpoints.is_empty())
                {
                    peer.endpoints = endpoints
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .and_then(|value| value.parse().ok())
                                .ok_or_else(|| invalid("tailscale: invalid patched endpoint"))
                        })
                        .collect::<io::Result<_>>()?;
                }
                if let Some(deadline) = patch.get("KeyExpiry").filter(|value| !value.is_null()) {
                    peer.expires_at = expiry(
                        deadline
                            .as_str()
                            .ok_or_else(|| invalid("tailscale: invalid patched expiry"))?,
                    )?;
                }
            }
        }
        if let Some(derp) = map.get("DERPMap").filter(|value| !value.is_null()) {
            next.derp = serde_json::from_value(derp.clone())
                .map_err(|_| invalid("tailscale: invalid DERP map"))?;
        }
        if let Some(dns) = map.get("DNSConfig").filter(|value| !value.is_null()) {
            next.dns = dns.clone();
        }
        if let Some(filter) = map.get("PacketFilter").filter(|value| !value.is_null()) {
            next.filters = filter
                .as_array()
                .ok_or_else(|| invalid("tailscale: invalid packet filter"))?
                .clone();
        }
        if next.peers.len() > 16384 {
            return Err(invalid("tailscale: peer table exceeds limit"));
        }
        *self = next;
        Ok(())
    }

    pub fn active_clone(&self) -> Self {
        let mut map = self.clone();
        if map
            .own_expiry
            .is_some_and(|expiry| expiry <= unix_seconds())
        {
            map.own_addresses.clear();
            map.peers.clear();
            map.dns = Value::Null;
            map.filters.clear();
        } else {
            map.peers.retain(|_, peer| !peer.is_expired());
        }
        map
    }

    pub fn lookup(&self, name: &str) -> Option<Vec<IpAddr>> {
        if self
            .own_expiry
            .is_some_and(|expiry| expiry <= unix_seconds())
        {
            return None;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let proxied = self.dns.get("Proxied").and_then(Value::as_bool) == Some(true);
        if proxied {
            let names = std::iter::once((self.own_name.as_str(), &self.own_addresses)).chain(
                self.peers
                    .values()
                    .filter(|peer| !peer.is_expired())
                    .map(|peer| (peer.name.as_str(), &peer.addresses)),
            );
            for (hostname, addresses) in names {
                let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
                let short = hostname.split('.').next().unwrap_or("");
                if name == hostname || (!short.is_empty() && name == short) {
                    return Some(addresses.iter().map(|cidr| cidr.address().into()).collect());
                }
            }
        }
        let mut addresses = Vec::new();
        for record in self
            .dns
            .get("ExtraRecords")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if record
                .get("Name")
                .and_then(Value::as_str)
                .is_some_and(|value| value.trim_end_matches('.').eq_ignore_ascii_case(&name))
                && let Some(ip) = record
                    .get("Value")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok())
            {
                addresses.push(ip);
            }
        }
        if !addresses.is_empty() {
            return Some(addresses);
        }
        if proxied
            && self
                .dns
                .get("Domains")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|domain| {
                    name == domain.trim_end_matches('.')
                        || name.ends_with(&format!(".{}", domain.trim_end_matches('.')))
                })
        {
            return Some(Vec::new());
        }
        None
    }

    pub fn resolver(&self, name: &str) -> Option<SocketAddr> {
        if self
            .own_expiry
            .is_some_and(|expiry| expiry <= unix_seconds())
        {
            return None;
        }
        let routes = self.dns.get("Routes").and_then(Value::as_object);
        let mut best = None;
        if let Some(routes) = routes {
            for (suffix, resolvers) in routes {
                let suffix = suffix.trim_end_matches('.');
                if (name == suffix || name.ends_with(&format!(".{suffix}")))
                    && best.as_ref().is_none_or(|(len, _)| suffix.len() > *len)
                {
                    best = Some((suffix.len(), resolvers));
                }
            }
        }
        let resolvers = best
            .map(|(_, value)| value)
            .or_else(|| self.dns.get("Resolvers"))
            .or_else(|| self.dns.get("FallbackResolvers"))?;
        resolvers
            .as_array()?
            .iter()
            .filter_map(|value| value.get("Addr").and_then(Value::as_str))
            .find_map(|value| {
                value
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| SocketAddr::new(ip, 53))
                    .or_else(|| value.parse().ok())
            })
            .filter(|addr| addr.ip().to_string() != "100.100.100.100")
    }

    /// Stateless ACL evaluation for a NEW incoming flow. Established replies
    /// require a matching tuple in the engine, not a blanket bypass.
    pub fn permits(&self, source: IpAddr, destination: IpAddr, protocol: u8, port: u16) -> bool {
        self.filters.iter().any(|rule| {
            let protocols = rule.get("IPProto").and_then(Value::as_array);
            let protocol_matches = match protocols {
                Some(list) if !list.is_empty() => {
                    list.iter().any(|v| v.as_u64() == Some(u64::from(protocol)))
                }
                _ => matches!(protocol, 1 | 6 | 17 | 58),
            };
            protocol_matches
                && rule
                    .get("SrcIPs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|range| contains(range, source))
                && rule
                    .get("DstPorts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|target| {
                        target
                            .get("IP")
                            .and_then(Value::as_str)
                            .is_some_and(|range| contains(range, destination))
                            && target.get("Ports").is_some_and(|ports| {
                                let first = ports.get("First").and_then(Value::as_u64).unwrap_or(0);
                                let last = ports.get("Last").and_then(Value::as_u64).unwrap_or(0);
                                (first..=last).contains(&u64::from(port))
                            })
                    })
        })
    }

    pub fn choose_home_derp(&self) -> u16 {
        let usable = |id: u16| {
            self.derp
                .regions
                .get(&id.to_string())
                .is_some_and(|region| region.nodes.iter().any(|node| !node.stun_only))
        };
        if self.home_derp != 0 && usable(self.home_derp) {
            return self.home_derp;
        }
        if self.own_preferred_derp != 0 && usable(self.own_preferred_derp) {
            return self.own_preferred_derp;
        }
        self.derp
            .regions
            .keys()
            .filter_map(|id| id.parse::<u16>().ok())
            .filter(|id| usable(*id))
            .min()
            .unwrap_or(0)
    }
}

fn contains(range: &str, ip: IpAddr) -> bool {
    if range == "*" {
        return true;
    }
    if let Ok(cidr) = range.parse::<IpCidr>() {
        return cidr.contains_addr(&IpAddress::from(ip));
    }
    if let Ok(address) = range.parse::<IpAddr>() {
        return address == ip;
    }
    if let Some((first, last)) = range.split_once('-')
        && let (Ok(first), Ok(last)) = (first.parse::<IpAddr>(), last.parse::<IpAddr>())
        && std::mem::discriminant(&first) == std::mem::discriminant(&ip)
        && std::mem::discriminant(&last) == std::mem::discriminant(&ip)
    {
        return first <= ip && ip <= last;
    }
    // Capability grants and unknown source forms never grant access.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn control_and_transport_keep_the_registered_home_relay() {
        let region = |id| {
            json!({"RegionID":id,"RegionCode":"test","Nodes":[{
                "Name":"test","RegionID":id,"HostName":"relay.example","DERPPort":443
            }]})
        };
        let mut map = Netmap::default();
        map.update(&json!({
            "Node":{"ID":1,"Key":format!("nodekey:{}","11".repeat(32)),
                "Addresses":["100.64.0.1/32"],"HomeDERP":0,"DERP":"127.3.3.40:22"},
            "DERPMap":{"Regions":{"1":region(1),"22":region(22)}}
        }))
        .unwrap();
        assert_eq!(
            map.choose_home_derp(),
            22,
            "a legacy self-node relay must win over the lowest region ID"
        );
        map.home_derp = map.choose_home_derp();
        assert_eq!(map.active_clone().home_derp, 22);
        map.update(&json!({"DERPMap":{"Regions":{"1":region(1)}}}))
            .unwrap();
        assert_eq!(
            map.choose_home_derp(),
            1,
            "a removed relay must not remain selected"
        );
    }

    #[test]
    fn utc_expiry_and_expired_keys_fail_closed() {
        assert_eq!(expiry("1970-01-01T00:00:00Z").unwrap(), Some(0));
        assert_eq!(
            expiry("2000-02-29T12:34:56.123456789Z").unwrap(),
            Some(951827696)
        );
        assert_eq!(expiry("0001-01-01T00:00:00Z").unwrap(), None);
        for value in [
            "2025-02-29T00:00:00Z",
            "2000-02-29T24:00:00Z",
            "2000-02-29T00:00:00.Z",
            "not a time",
        ] {
            assert!(expiry(value).is_err());
        }
        let mut value = initial();
        value["Peers"][0]["KeyExpiry"] = json!("1970-01-01T00:00:01Z");
        let mut map = Netmap::default();
        map.update(&value).unwrap();
        assert!(map.active_clone().peers.is_empty());
        assert!(!map.peers[&2].owns_source("100.64.0.2".parse().unwrap()));
    }

    fn initial() -> Value {
        json!({
            "Node": {"ID":1,"Key":format!("nodekey:{}", "11".repeat(32)),"Name":"router.example.ts.net.","Addresses":["100.64.0.1/32"]},
            "Peers": [{"ID":2,"Key":format!("nodekey:{}", "22".repeat(32)),"Name":"peer.example.ts.net.","Addresses":["100.64.0.2/32"]}],
            "DNSConfig":{"Proxied":true,"Domains":["example.ts.net"]},
            "PacketFilter":[{"SrcIPs":["100.64.0.2/32"],"DstPorts":[{"IP":"192.168.0.0/24","Ports":{"First":443,"Last":443}}],"IPProto":[6]}]
        })
    }

    #[test]
    fn partial_updates_preserve_dns_self_and_acl_but_remove_peers() {
        let mut map = Netmap::default();
        map.update(&initial()).unwrap();
        map.update(&json!({"KeepAlive":true})).unwrap();
        assert_eq!(
            map.lookup("peer").unwrap(),
            vec!["100.64.0.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(map.lookup("router.example.ts.net").unwrap().len(), 1);
        map.update(&json!({"PeersRemoved":[2]})).unwrap();
        assert_eq!(map.lookup("peer.example.ts.net").unwrap().len(), 0);
        assert!(map.lookup("peer").is_none());
    }

    #[test]
    fn peer_patches_rotate_keys_endpoints_and_expiry_atomically() {
        let mut map = Netmap::default();
        map.update(&initial()).unwrap();
        map.update(&json!({"PeersChangedPatch":[{"NodeID":999,"Key":"ignored"},{"NodeID":2,"Key":format!("nodekey:{}","33".repeat(32)),"DERPRegion":4,"Endpoints":["127.0.0.1:41641"]}]})).unwrap();
        assert_eq!(map.peers[&2].key, [0x33; 32]);
        assert_eq!(map.peers[&2].home_derp, 4);
        assert_eq!(
            map.peers[&2].endpoints,
            vec!["127.0.0.1:41641".parse::<SocketAddr>().unwrap()]
        );
        assert!(
            map.update(
                &json!({"PeersChangedPatch":[{"NodeID":2,"Key":"not a key","DERPRegion":5}]})
            )
            .is_err()
        );
        assert_eq!(map.peers[&2].home_derp, 4);
        map.update(&json!({"PeersChangedPatch":[{"NodeID":2,"KeyExpiry":"1970-01-01T00:00:01Z"}]}))
            .unwrap();
        assert!(map.active_clone().peers.is_empty());
    }

    #[test]
    fn packet_filter_denies_other_sources_protocols_and_ports() {
        let mut map = Netmap::default();
        map.update(&initial()).unwrap();
        let source = "100.64.0.2".parse().unwrap();
        let destination = "192.168.0.3".parse().unwrap();
        assert!(map.permits(source, destination, 6, 443));
        assert!(!map.permits(source, destination, 17, 443));
        assert!(!map.permits(source, destination, 6, 22));
        assert!(!map.permits("100.64.0.3".parse().unwrap(), destination, 6, 443));
        map.update(&json!({"PacketFilter":[]})).unwrap();
        assert!(!map.permits(source, destination, 6, 443));
    }

    #[test]
    fn unauthorized_and_locked_maps_fail_without_partial_changes() {
        let mut map = Netmap::default();
        map.update(&initial()).unwrap();
        assert!(
            map.update(&json!({"TKAInfo":{"Disabled":false},"Peers":[]}))
                .is_err()
        );
        assert_eq!(map.peers.len(), 1);
        let mut invalid = initial();
        invalid["Node"]["MachineAuthorized"] = Value::Bool(false);
        assert!(map.update(&invalid).is_err());
        assert_eq!(map.peers.len(), 1);
    }
}
