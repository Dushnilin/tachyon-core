//! DNS server transports: udp / tcp / tls (DoT) / https (DoH) / quic (DoQ) /
//! h3 (DoH over HTTP/3) / fakeip — one exchange per query.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use portable_atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::inbound::AnyStream;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::outbound::transport::h2io::{H2Io, H2Stream};
use crate::outbound::urltest::parse_duration;
use crate::tls_client::TlsOptions;

pub(crate) const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// MagicDNS and split DNS from a running native Tailscale endpoint.
    Tailscale,
    Udp,
    Tcp,
    Tls,
    Https,
    /// DNS over QUIC (RFC 9250), ALPN `doq`
    Quic,
    /// DNS over HTTP/3 (DoH with `h3`), ALPN `h3`
    H3,
    Fakeip,
    /// the system resolver
    Local,
    /// the hosts file(s) plus inline `predefined` entries
    Hosts,
    /// mDNS: one multicast query per interface, answers merged
    Mdns,
    /// lx `group`: several member servers behind one tag
    Group,
    /// DHCP-provided DNS resolver
    Dhcp,
    /// systemd-resolved local stub resolver
    Resolved,
}

pub struct ServerConfig {
    pub tag: String,
    pub kind: Kind,
    pub server: String,
    pub port: u16,
    pub tls: Option<TlsOptions>,
    pub path: String,
    pub domain_resolver: Option<String>,
    pub timeout: Duration,
    pub inet4: Option<IpPrefix>,
    pub inet6: Option<IpPrefix>,
    pub store: Option<Arc<FakeIpStore>>,
    /// Outbound tag the transport is dialed through (`dns.server.detour`).
    pub detour: Option<String>,
    /// `type: hosts` — files to read and inline `predefined` entries
    pub hosts: Option<Hosts>,
    /// `dns.headers` for https / h3: sent with every request
    pub headers: Vec<(String, String)>,
    /// `type: group`: the lx group this tag stands for, with its members'
    /// tags and its own budget. Present only for a group.
    pub group: Option<Arc<super::group::Group>>,
    /// `type: local` with `neighbor_domain`: the suffixes a `<host><suffix>`
    /// name is answered from the neighbour tables under.
    pub neighbor_domain: Vec<String>,
    /// `type: mdns`: the interfaces to query, empty for all of them
    pub mdns_interfaces: Vec<String>,
}

/// The `hosts` server's sources: the files it reads and the inline entries,
/// which take precedence (reference `dns/transport/hosts`).
#[derive(Debug, Clone, Default)]
pub struct Hosts {
    pub paths: Vec<String>,
    pub predefined: Vec<(String, Vec<std::net::IpAddr>)>,
}

impl Hosts {
    /// `mDNS.CanonicalName`: the name lower-cased with a trailing dot.
    fn canonical(name: &str) -> String {
        super::codec::normalize_name(&name.to_ascii_lowercase())
    }

    /// The reference caches a parsed file for five seconds and reloads it when
    /// the size or mtime changed; a lookup goes straight to disk here, which is
    /// the same answer without the bookkeeping.
    pub fn lookup(&self, name: &str) -> Vec<std::net::IpAddr> {
        let canonical = Self::canonical(name);
        for (key, addrs) in &self.predefined {
            if Self::canonical(key) == canonical {
                return addrs.clone();
            }
        }
        for path in &self.paths {
            if let Ok(text) = std::fs::read_to_string(path) {
                for (name, addrs) in parse_hosts(&text) {
                    if name == canonical {
                        return addrs;
                    }
                }
            }
        }
        Vec::new()
    }

    /// `Transport.PreferredDomain`: the transport claims the name when it knows
    /// it, which keeps a hosts server ahead of a real one.
    pub fn knows(&self, name: &str) -> bool {
        !self.lookup(name).is_empty()
    }
}

/// The platform's hosts file.
fn default_hosts_path() -> String {
    if cfg!(windows) {
        "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string()
    } else {
        "/etc/hosts".to_string()
    }
}

/// One hosts file: `[addr][name...]` per line, `#` starts a comment.
pub fn parse_hosts(text: &str) -> Vec<(String, Vec<std::net::IpAddr>)> {
    let mut by_name: Vec<(String, Vec<std::net::IpAddr>)> = Vec::new();
    for line in text.lines() {
        let line = match line.find('#') {
            Some(at) => &line[..at],
            None => line,
        };
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let Ok(addr) = fields[0].parse::<std::net::IpAddr>() else {
            continue;
        };
        for name in &fields[1..] {
            let canonical = Hosts::canonical(name);
            match by_name.iter_mut().find(|(key, _)| *key == canonical) {
                Some((_, addrs)) => addrs.push(addr),
                None => by_name.push((canonical, vec![addr])),
            }
        }
    }
    by_name
}

/// Minimal CIDR prefix (host bits masked off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

impl IpPrefix {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let (addr, bits) = raw
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("missing /prefix length"))?;
        let addr = IpAddr::from_str(addr)?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| anyhow::anyhow!("bad prefix length"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            anyhow::bail!("prefix length {bits} exceeds {max}");
        }
        Ok(Self { addr, bits })
    }

    /// `addr/prefix` rendering (Clash rule payloads, log lines).
    pub fn to_cidr(&self) -> String {
        format!("{}/{}", self.addr, self.bits)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_v4(u32::from(net), self.bits) == mask_v4(u32::from(ip), self.bits)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_v6(u128::from(net), self.bits) == mask_v6(u128::from(ip), self.bits)
            }
            _ => false,
        }
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }
}

fn mask_v4(addr: u32, bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        addr & u32::MAX << (32 - bits)
    }
}

fn mask_v6(addr: u128, bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        addr & u128::MAX << (128 - bits)
    }
}

fn host_mask_v4(bits: u8) -> u32 {
    if bits == 0 {
        u32::MAX
    } else {
        !(u32::MAX << (32 - bits))
    }
}

fn host_mask_v6(bits: u8) -> u128 {
    if bits == 0 {
        u128::MAX
    } else {
        !(u128::MAX << (128 - bits))
    }
}

fn broadcast_v4(net: Ipv4Addr, bits: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(net) | host_mask_v4(bits))
}

fn broadcast_v6(net: Ipv6Addr, bits: u8) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(net) | host_mask_v6(bits))
}

/// In-memory fakeip address pool, mirroring sing-box's store: domain-address
/// maps both ways, sequential allocation starting at network+2 with wrap.
pub struct FakeIpStore {
    v4: Option<IpPrefix>,
    v6: Option<IpPrefix>,
    state: Mutex<FakeIpState>,
    cache: RwLock<Option<crate::cache_file::SharedCacheFile>>,
}

/// Fake-ip maps are keyed by things that never stop arriving (names) or get
/// overwritten on a pool wrap (addresses): capped, oldest first out, with the
/// paired record dropped on either side so forward and reverse never disagree.
const FAKEIP_MAP_CAPACITY: usize = 16384;

struct FakeIpState {
    cur4: Option<Ipv4Addr>,
    cur6: Option<Ipv6Addr>,
    addr_to_domain: std::collections::HashMap<IpAddr, String>,
    domain_to_v4: lru::LruCache<String, Ipv4Addr>,
    domain_to_v6: lru::LruCache<String, Ipv6Addr>,
}

impl FakeIpStore {
    pub fn new(v4: Option<IpPrefix>, v6: Option<IpPrefix>) -> Self {
        let cur4 = v4.and_then(|p| {
            if p.is_v4() {
                let IpAddr::V4(net) = p.addr else {
                    unreachable!()
                };
                Some(Ipv4Addr::from(u32::from(net) + 1))
            } else {
                None
            }
        });
        let cur6 = v6.and_then(|p| {
            if !p.is_v4() {
                let IpAddr::V6(net) = p.addr else {
                    unreachable!()
                };
                Some(Ipv6Addr::from(u128::from(net) + 1))
            } else {
                None
            }
        });
        Self {
            v4: v4.filter(IpPrefix::is_v4),
            v6: v6.filter(|p| !p.is_v4()),
            cache: RwLock::new(None),
            state: Mutex::new(FakeIpState {
                cur4,
                cur6,
                addr_to_domain: std::collections::HashMap::new(),
                domain_to_v4: lru::LruCache::new(
                    std::num::NonZeroUsize::new(FAKEIP_MAP_CAPACITY).expect("nonzero"),
                ),
                domain_to_v6: lru::LruCache::new(
                    std::num::NonZeroUsize::new(FAKEIP_MAP_CAPACITY).expect("nonzero"),
                ),
            }),
        }
    }

    pub fn prefixes(&self) -> (Option<IpPrefix>, Option<IpPrefix>) {
        (self.v4, self.v6)
    }

    /// The domain/address buckets use the reference Go cache representation.
    /// Metadata is four big-endian length-prefixed netip binary fields.
    pub fn attach_cache(&self, cache: Option<crate::cache_file::SharedCacheFile>) {
        let cache = cache.filter(|cache| cache.lock().expect("cache").options().store_fakeip);
        if let Some(cache) = &cache {
            let mut cache = cache.lock().expect("cache");
            let mut state = self.state.lock().expect("fakeip state");
            let mut changes = Vec::new();

            for (bucket, v6) in [("fakeip_domain4", false), ("fakeip_domain6", true)] {
                for domain in cache.keys(bucket) {
                    let Some(ip) = cache
                        .get(bucket, domain.as_bytes())
                        .and_then(|raw| cached_ip(&raw))
                        .filter(|ip| self.contains(*ip))
                    else {
                        // Purge invalid/out-of-subnet forward record
                        changes.push((bucket, domain.into_bytes(), None));
                        continue;
                    };

                    let rev = cache
                        .get("fakeip_address", &ip_bytes(ip))
                        .and_then(|raw| String::from_utf8(raw).ok());
                    if let Some(rev_domain) = rev {
                        if rev_domain != domain {
                            // Asymmetry on disk: IP claimed by another domain. Prune stale forward record.
                            changes.push((bucket, domain.into_bytes(), None));
                            continue;
                        }
                    } else {
                        // Reverse record is missing on disk: heal it guaranteed!
                        changes.push((
                            "fakeip_address",
                            ip_bytes(ip),
                            Some(domain.as_bytes().to_vec()),
                        ));
                    }

                    let (evicted, superseded) = Self::remember(&mut state, ip, &domain);
                    if let Some((ev_d, ev_ip)) = evicted {
                        let ev_bucket = if ev_ip.is_ipv4() {
                            "fakeip_domain4"
                        } else {
                            "fakeip_domain6"
                        };
                        changes.push((ev_bucket, ev_d.into_bytes(), None));
                        changes.push(("fakeip_address", ip_bytes(ev_ip), None));
                    }
                    if let Some(prev) = superseded {
                        changes.push((bucket, prev.into_bytes(), None));
                    }
                    match ip {
                        IpAddr::V4(ip) if !v6 => {
                            state.cur4 = Some(state.cur4.map_or(ip, |cur| cur.max(ip)))
                        }
                        IpAddr::V6(ip) if v6 => {
                            state.cur6 = Some(state.cur6.map_or(ip, |cur| cur.max(ip)))
                        }
                        _ => {}
                    }
                }
            }

            // Prune orphaned reverse records on disk
            for addr_bytes in cache.raw_keys("fakeip_address") {
                if addr_bytes == b"fakeip_metadata" {
                    continue;
                }
                if let Some(ip) = cached_ip(&addr_bytes) {
                    if !self.contains(ip) {
                        changes.push(("fakeip_address", addr_bytes, None));
                        continue;
                    }
                    let bucket = if ip.is_ipv4() {
                        "fakeip_domain4"
                    } else {
                        "fakeip_domain6"
                    };
                    let dom = cache
                        .get("fakeip_address", &addr_bytes)
                        .and_then(|raw| String::from_utf8(raw).ok());
                    let valid_fwd = dom.as_ref().is_some_and(|d| {
                        cache
                            .get(bucket, d.as_bytes())
                            .and_then(|raw| cached_ip(&raw))
                            == Some(ip)
                    });
                    if !valid_fwd {
                        changes.push(("fakeip_address", addr_bytes, None));
                    }
                }
            }

            if let Some(raw) = cache.get("fakeip_address", b"fakeip_metadata")
                && let Some((cur4, cur6)) = self.decode_metadata(&raw)
            {
                state.cur4 = cur4;
                state.cur6 = cur6;
            }
            if !changes.is_empty() {
                changes.push((
                    "fakeip_address",
                    b"fakeip_metadata".to_vec(),
                    Some(self.encode_metadata(&state)),
                ));
                cache.apply_changes(changes);
            }
        }
        *self.cache.write().expect("fakeip cache") = cache;
    }

    /// One paired insert into both maps: the LRU recency push, the reverse
    /// record, and the cleanup on whichever side the insert evicts. What a
    /// fresh allocation in `create` does, replayed for records found on disk.
    /// Returns (evicted_pair, superseded_domain).
    fn remember(
        state: &mut FakeIpState,
        ip: IpAddr,
        domain: &str,
    ) -> (Option<(String, IpAddr)>, Option<String>) {
        let evicted = match ip {
            IpAddr::V4(addr) => state
                .domain_to_v4
                .push(domain.to_string(), addr)
                .map(|(d, a)| (d, IpAddr::V4(a))),
            IpAddr::V6(addr) => state
                .domain_to_v6
                .push(domain.to_string(), addr)
                .map(|(d, a)| (d, IpAddr::V6(a))),
        };
        if let Some((_, evicted_addr)) = &evicted {
            state.addr_to_domain.remove(evicted_addr);
        }
        let superseded = if let Some(previous) = state.addr_to_domain.insert(ip, domain.to_string())
            && previous != domain
        {
            // a pool wrap reissues an address an earlier domain still claims;
            // drop that claim or forward and reverse disagree
            match ip {
                IpAddr::V4(_) => {
                    state.domain_to_v4.pop(&previous);
                }
                IpAddr::V6(_) => {
                    state.domain_to_v6.pop(&previous);
                }
            }
            Some(previous)
        } else {
            None
        };
        (evicted, superseded)
    }

    fn persist(
        &self,
        state: &FakeIpState,
        ip: IpAddr,
        domain: &str,
        evicted: Option<(String, IpAddr)>,
        superseded: Option<String>,
    ) {
        let cache = self.cache.read().expect("fakeip cache").clone();
        let Some(cache) = cache else { return };
        let mut cache = cache.lock().expect("cache");
        let address = ip_bytes(ip);
        let bucket = if ip.is_ipv4() {
            "fakeip_domain4"
        } else {
            "fakeip_domain6"
        };
        // Router flash protection: if the exact pair already lives on disk and nothing was evicted, skip!
        let already_fwd = cache.get(bucket, domain.as_bytes()).as_deref() == Some(&address);
        let already_rev =
            cache.get("fakeip_address", &address).as_deref() == Some(domain.as_bytes());
        if already_fwd && already_rev && evicted.is_none() && superseded.is_none() {
            return;
        }

        let mut changes = Vec::new();
        // 1. Evicted pair must be atomically deleted from both maps on disk:
        if let Some((ev_domain, ev_ip)) = evicted {
            let ev_bucket = if ev_ip.is_ipv4() {
                "fakeip_domain4"
            } else {
                "fakeip_domain6"
            };
            changes.push((ev_bucket, ev_domain.into_bytes(), None));
            changes.push(("fakeip_address", ip_bytes(ev_ip), None));
        }
        // 2. Superseded domain previously had this IP address:
        if let Some(prev) = superseded {
            changes.push((bucket, prev.into_bytes(), None));
        }
        // 3. Any previous domain associated with this IP on disk:
        if let Some(previous) = cache.get("fakeip_address", &address)
            && previous != domain.as_bytes()
        {
            changes.push((bucket, previous, None));
        }
        // 4. Any previous IP associated with this domain on disk:
        if let Some(old_ip_bytes) = cache.get(bucket, domain.as_bytes())
            && old_ip_bytes != address
        {
            changes.push(("fakeip_address", old_ip_bytes, None));
        }
        // 5. Store both forward and reverse atomically:
        if !already_rev {
            changes.push((
                "fakeip_address",
                address.clone(),
                Some(domain.as_bytes().to_vec()),
            ));
        }
        if !already_fwd {
            changes.push((bucket, domain.as_bytes().to_vec(), Some(address)));
        }
        changes.push((
            "fakeip_address",
            b"fakeip_metadata".to_vec(),
            Some(self.encode_metadata(state)),
        ));
        cache.apply_changes(changes);
    }

    fn heal_disk_hit_if_needed(
        &self,
        state: &FakeIpState,
        ip: IpAddr,
        domain: &str,
        evicted: Option<(String, IpAddr)>,
        superseded: Option<String>,
    ) {
        let cache = self.cache.read().expect("fakeip cache").clone();
        let Some(cache) = cache else { return };
        let mut cache = cache.lock().expect("cache");
        let address = ip_bytes(ip);
        let has_rev = cache
            .get("fakeip_address", &address)
            .is_some_and(|d| d == domain.as_bytes());

        // Router flash protection: if reverse record exists and nothing was evicted, skip!
        if has_rev && evicted.is_none() && superseded.is_none() {
            return;
        }

        let mut changes = Vec::new();
        if let Some((ev_domain, ev_ip)) = evicted {
            let ev_bucket = if ev_ip.is_ipv4() {
                "fakeip_domain4"
            } else {
                "fakeip_domain6"
            };
            changes.push((ev_bucket, ev_domain.into_bytes(), None));
            changes.push(("fakeip_address", ip_bytes(ev_ip), None));
        }
        if let Some(prev) = superseded {
            let bucket = if ip.is_ipv4() {
                "fakeip_domain4"
            } else {
                "fakeip_domain6"
            };
            changes.push((bucket, prev.into_bytes(), None));
        }
        if !has_rev {
            changes.push(("fakeip_address", address, Some(domain.as_bytes().to_vec())));
        }
        changes.push((
            "fakeip_address",
            b"fakeip_metadata".to_vec(),
            Some(self.encode_metadata(state)),
        ));
        cache.apply_changes(changes);
    }

    fn persist_evictions(
        &self,
        state: &FakeIpState,
        evicted: Option<(String, IpAddr)>,
        superseded: Option<String>,
    ) {
        if evicted.is_none() && superseded.is_none() {
            return;
        }
        let cache = self.cache.read().expect("fakeip cache").clone();
        let Some(cache) = cache else { return };
        let mut cache = cache.lock().expect("cache");
        let mut changes = Vec::new();
        if let Some((ev_domain, ev_ip)) = evicted {
            let ev_bucket = if ev_ip.is_ipv4() {
                "fakeip_domain4"
            } else {
                "fakeip_domain6"
            };
            changes.push((ev_bucket, ev_domain.into_bytes(), None));
            changes.push(("fakeip_address", ip_bytes(ev_ip), None));
        }
        if let Some(prev) = superseded {
            changes.push(("fakeip_domain4", prev.clone().into_bytes(), None));
            changes.push(("fakeip_domain6", prev.into_bytes(), None));
        }
        changes.push((
            "fakeip_address",
            b"fakeip_metadata".to_vec(),
            Some(self.encode_metadata(state)),
        ));
        cache.apply_changes(changes);
    }

    fn prefix_bytes(prefix: Option<IpPrefix>) -> Vec<u8> {
        match prefix {
            Some(prefix) => {
                let mut bytes = ip_bytes(prefix.addr);
                bytes.push(prefix.bits);
                bytes
            }
            None => vec![255],
        }
    }

    fn encode_metadata(&self, state: &FakeIpState) -> Vec<u8> {
        let fields = [
            Self::prefix_bytes(self.v4),
            Self::prefix_bytes(self.v6),
            state
                .cur4
                .map(|ip| ip.octets().to_vec())
                .unwrap_or_default(),
            state
                .cur6
                .map(|ip| ip.octets().to_vec())
                .unwrap_or_default(),
        ];
        let mut output = Vec::new();
        for field in fields {
            output.extend_from_slice(&(field.len() as u16).to_be_bytes());
            output.extend_from_slice(&field);
        }
        output
    }

    fn decode_metadata(&self, mut raw: &[u8]) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let mut fields = Vec::new();
        for _ in 0..4 {
            let len = u16::from_be_bytes(raw.get(..2)?.try_into().ok()?) as usize;
            fields.push(raw.get(2..2 + len)?);
            raw = raw.get(2 + len..)?;
        }
        if !raw.is_empty()
            || fields[0] != Self::prefix_bytes(self.v4)
            || fields[1] != Self::prefix_bytes(self.v6)
        {
            return None;
        }
        let cur4 = match cached_ip(fields[2]) {
            Some(IpAddr::V4(ip)) if self.contains(IpAddr::V4(ip)) => Some(ip),
            None if fields[2].is_empty() && self.v4.is_none() => None,
            _ => return None,
        };
        let cur6 = match cached_ip(fields[3]) {
            Some(IpAddr::V6(ip)) if self.contains(IpAddr::V6(ip)) => Some(ip),
            None if fields[3].is_empty() && self.v6.is_none() => None,
            _ => return None,
        };
        Some((cur4, cur6))
    }

    /// Migrate active FakeIP state from an earlier pool if the prefixes match.
    pub fn migrate_from(&self, old: &FakeIpStore) {
        if self.prefixes() != old.prefixes() {
            return;
        }
        let old_state = old.state.lock().expect("old fakeip state");
        let mut new_state = self.state.lock().expect("new fakeip state");
        new_state.cur4 = old_state.cur4;
        new_state.cur6 = old_state.cur6;
        new_state.addr_to_domain = old_state.addr_to_domain.clone();
        for (d, ip) in old_state.domain_to_v4.iter() {
            new_state.domain_to_v4.put(d.clone(), *ip);
        }
        for (d, ip) in old_state.domain_to_v6.iter() {
            new_state.domain_to_v6.put(d.clone(), *ip);
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.v4.is_some_and(|p| p.contains(ip)) || self.v6.is_some_and(|p| p.contains(ip))
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        let memory = self
            .state
            .lock()
            .expect("fakeip state")
            .addr_to_domain
            .get(&ip)
            .cloned();
        if memory.is_some() {
            return memory;
        }
        if !self.contains(ip) {
            return None;
        }
        let cache = self.cache.read().expect("fakeip cache").clone()?;
        let value = cache
            .lock()
            .expect("cache")
            .get("fakeip_address", &ip_bytes(ip))?;
        let domain = String::from_utf8(value)
            .ok()
            .filter(|domain| !domain.is_empty())?;
        // A record that only lives on disk is one flush failure away from a
        // TPROXY connection reset; mirror it into memory and heal persistence while we are here.
        let mut state = self.state.lock().expect("fakeip state");
        let (evicted, superseded) = Self::remember(&mut state, ip, &domain);
        if evicted.is_some() || superseded.is_some() {
            self.persist_evictions(&state, evicted, superseded);
        }
        Some(domain)
    }

    pub fn lookup_address(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let mut state = self.state.lock().expect("fakeip state");
        let memory = if v6 {
            state.domain_to_v6.get(domain).map(|a| IpAddr::V6(*a))
        } else {
            state.domain_to_v4.get(domain).map(|a| IpAddr::V4(*a))
        };
        if let Some(ip) = memory {
            if state.addr_to_domain.get(&ip).is_some_and(|d| d == domain) {
                return Some(ip);
            }
            state.addr_to_domain.insert(ip, domain.to_string());
            return Some(ip);
        }
        drop(state);
        let cache = self.cache.read().expect("fakeip cache").clone()?;
        let bucket = if v6 {
            "fakeip_domain6"
        } else {
            "fakeip_domain4"
        };
        let value = cache
            .lock()
            .expect("cache")
            .get(bucket, domain.as_bytes())?;
        let ip = cached_ip(&value).filter(|ip| ip.is_ipv6() == v6 && self.contains(*ip))?;
        // Check if reciprocal reverse entry on disk belongs to another domain:
        let cache_guard = cache.lock().expect("cache");
        let rev = cache_guard.get("fakeip_address", &ip_bytes(ip));
        if let Some(rev) = rev
            && rev != domain.as_bytes()
        {
            return None;
        }
        Some(ip)
    }

    pub fn create(&self, domain: &str, v6: bool) -> io::Result<IpAddr> {
        if let Some(ip) = self.lookup_address(domain, v6) {
            let mut state = self.state.lock().expect("fakeip state");
            let in_memory_ok = state
                .addr_to_domain
                .get(&ip)
                .is_some_and(|known| known == domain);
            if !in_memory_ok {
                let (evicted, superseded) = Self::remember(&mut state, ip, domain);
                self.heal_disk_hit_if_needed(&state, ip, domain, evicted, superseded);
            }
            return Ok(ip);
        }
        let mut state = self.state.lock().expect("fakeip state");
        if v6 {
            if let Some(existing) = state.domain_to_v6.get(domain).copied() {
                let ip = IpAddr::V6(existing);
                let (evicted, superseded) = Self::remember(&mut state, ip, domain);
                self.persist(&state, ip, domain, evicted, superseded);
                return Ok(ip);
            }
            let prefix = self
                .v6
                .ok_or_else(|| io::Error::other("fakeip: inet6_range not configured"))?;
            let cur = state
                .cur6
                .ok_or_else(|| io::Error::other("fakeip: no inet6 range"))?;
            let next = next_v6(cur, prefix);
            state.cur6 = Some(next);
            let ip = IpAddr::V6(next);
            let (evicted, superseded) = Self::remember(&mut state, ip, domain);
            self.persist(&state, ip, domain, evicted, superseded);
            Ok(ip)
        } else {
            if let Some(existing) = state.domain_to_v4.get(domain).copied() {
                let ip = IpAddr::V4(existing);
                let (evicted, superseded) = Self::remember(&mut state, ip, domain);
                self.persist(&state, ip, domain, evicted, superseded);
                return Ok(ip);
            }
            let prefix = self
                .v4
                .ok_or_else(|| io::Error::other("fakeip: inet4_range not configured"))?;
            let cur = state
                .cur4
                .ok_or_else(|| io::Error::other("fakeip: no inet4 range"))?;
            let next = next_v4(cur, prefix);
            state.cur4 = Some(next);
            let ip = IpAddr::V4(next);
            let (evicted, superseded) = Self::remember(&mut state, ip, domain);
            self.persist(&state, ip, domain, evicted, superseded);
            Ok(ip)
        }
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn cached_ip(raw: &[u8]) -> Option<IpAddr> {
    match raw.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(raw).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?))),
        _ => None,
    }
}

fn next_v4(cur: Ipv4Addr, prefix: IpPrefix) -> Ipv4Addr {
    let IpAddr::V4(net) = prefix.addr else {
        return cur;
    };
    let last = broadcast_v4(net, prefix.bits);
    let next = Ipv4Addr::from(u32::from(cur).wrapping_add(1));
    if next == last || !prefix.contains(IpAddr::V4(next)) {
        Ipv4Addr::from(u32::from(net) + 2)
    } else {
        next
    }
}

fn next_v6(cur: Ipv6Addr, prefix: IpPrefix) -> Ipv6Addr {
    let IpAddr::V6(net) = prefix.addr else {
        return cur;
    };
    let last = broadcast_v6(net, prefix.bits);
    let next = Ipv6Addr::from(u128::from(cur).wrapping_add(1));
    if next == last || !prefix.contains(IpAddr::V6(next)) {
        Ipv6Addr::from(u128::from(net) + 2)
    } else {
        next
    }
}

impl ServerConfig {
    pub fn build(obj: &Value, at: &str) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let kind_raw = map
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing type"))?;
        let kind = match kind_raw {
            "tailscale" => Kind::Tailscale,
            "udp" => Kind::Udp,
            "tcp" => Kind::Tcp,
            "tls" => Kind::Tls,
            "https" => Kind::Https,
            "quic" => Kind::Quic,
            "h3" => Kind::H3,
            "fakeip" => Kind::Fakeip,
            "local" => Kind::Local,
            "hosts" => Kind::Hosts,
            "mdns" => Kind::Mdns,
            "group" => Kind::Group,
            "dhcp" => Kind::Dhcp,
            "resolved" => Kind::Resolved,
            other => anyhow::bail!("{at}: dns server type {other:?} not implemented yet"),
        };
        let hosts = match kind {
            Kind::Hosts => {
                let mut sources = Hosts::default();
                match map.get("path") {
                    Some(Value::String(path)) => sources.paths.push(path.clone()),
                    Some(Value::Array(list)) => {
                        sources
                            .paths
                            .extend(list.iter().filter_map(Value::as_str).map(str::to_string));
                    }
                    None => sources.paths.push(default_hosts_path()),
                    Some(_) => anyhow::bail!("{at}.path: must be a string or a list"),
                }
                if let Some(Value::Object(entries)) = map.get("predefined") {
                    for (name, value) in entries {
                        let addrs = match value {
                            Value::String(text) => match text.parse() {
                                Ok(addr) => vec![addr],
                                Err(_) => continue,
                            },
                            Value::Array(list) => list
                                .iter()
                                .filter_map(Value::as_str)
                                .filter_map(|t| t.parse().ok())
                                .collect(),
                            _ => continue,
                        };
                        sources.predefined.push((name.clone(), addrs));
                    }
                }
                Some(sources)
            }
            _ => None,
        };
        let tag = map
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let server = map
            .get(if kind == Kind::Tailscale {
                "endpoint"
            } else {
                "server"
            })
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let port = map
            .get("server_port")
            .and_then(Value::as_u64)
            .map(|p| p as u16)
            .unwrap_or(match kind {
                Kind::Udp | Kind::Tcp | Kind::Tls | Kind::Resolved => 53,
                Kind::Https | Kind::H3 => 443,
                Kind::Quic => 853,
                Kind::Fakeip
                | Kind::Tailscale
                | Kind::Local
                | Kind::Hosts
                | Kind::Mdns
                | Kind::Group
                | Kind::Dhcp => 0,
            });
        // dns tls/https/quic/h3 servers implicitly use TLS: the reference
        // forces `enabled` on when the key is absent, and builds a client with
        // the system roots and the server name when there is no `tls` block at
        // all. Synthesising the block here gives us exactly that.
        let owned;
        let map_ref: &serde_json::Map<String, Value> =
            if matches!(kind, Kind::Tls | Kind::Https | Kind::Quic | Kind::H3) {
                let mut m = map.clone();
                let entry = m
                    .entry("tls")
                    .or_insert_with(|| Value::Object(Default::default()));
                if let Value::Object(t) = entry
                    && !t.contains_key("enabled")
                {
                    t.insert("enabled".to_string(), Value::Bool(true));
                }
                owned = m;
                &owned
            } else {
                map
            };
        let tls = TlsOptions::from_outbound(map_ref, &server, at)?;
        let path = map
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("/dns-query")
            .to_string();
        let domain_resolver = map
            .get("domain_resolver")
            .and_then(Value::as_str)
            .map(str::to_string);
        let timeout = parse_duration(
            map.get("timeout"),
            DEFAULT_DNS_TIMEOUT,
            &format!("{at}: timeout"),
        )?;

        let (inet4, inet6) = if kind == Kind::Fakeip {
            let inet4 = match map.get("inet4_range") {
                None | Some(Value::Null) => None,
                Some(v) => Some(IpPrefix::parse(v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("{at}: inet4_range must be a string")
                })?)?),
            };
            let inet6 = match map.get("inet6_range") {
                None | Some(Value::Null) => None,
                Some(v) => Some(IpPrefix::parse(v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("{at}: inet6_range must be a string")
                })?)?),
            };
            if inet4.is_none() && inet6.is_none() {
                anyhow::bail!("{at}: at least one of inet4_range or inet6_range must be set");
            }
            (inet4, inet6)
        } else {
            (None, None)
        };
        // fakeip, local, hosts, mdns and group never dial a server, so they need no
        // address
        let needs_server = !matches!(
            kind,
            Kind::Fakeip
                | Kind::Tailscale
                | Kind::Local
                | Kind::Hosts
                | Kind::Mdns
                | Kind::Group
                | Kind::Dhcp
                | Kind::Resolved
        );
        if needs_server && server.is_empty() {
            anyhow::bail!("{at}: missing server");
        }
        if kind == Kind::Tailscale && server.is_empty() {
            anyhow::bail!("{at}: tailscale DNS requires endpoint");
        }
        let detour = map
            .get("detour")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty())
            .map(str::to_string);

        let store = if kind == Kind::Fakeip {
            Some(Arc::new(FakeIpStore::new(inet4, inet6)))
        } else {
            None
        };

        let headers = match map.get("headers") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Object(entries)) => {
                let mut out = Vec::with_capacity(entries.len());
                for (name, value) in entries {
                    let value = value
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("{at}.headers.{name}: must be a string"))?;
                    // the h1 transport writes the head by hand, so a CR or LF
                    // in a name or value would inject headers of its own
                    if name.is_empty()
                        || name.contains('\r')
                        || name.contains('\n')
                        || name.contains(':')
                        || value.contains('\r')
                        || value.contains('\n')
                    {
                        anyhow::bail!("{at}.headers.{name}: invalid header name or value");
                    }
                    out.push((name.clone(), value.to_string()));
                }
                out
            }
            Some(_) => anyhow::bail!("{at}.headers: must be an object"),
        };
        let group = match kind {
            Kind::Group => {
                let members = match map.get("servers") {
                    Some(Value::String(tag)) => vec![tag.clone()],
                    Some(Value::Array(list)) => list
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect(),
                    None | Some(Value::Null) => Vec::new(),
                    Some(_) => anyhow::bail!("{at}.servers: must be a string or a list"),
                };
                if members.is_empty() {
                    anyhow::bail!("{at}: servers is required and must not be empty");
                }
                let mode_raw = map.get("mode").and_then(Value::as_str).unwrap_or("");
                let mode = super::group::Mode::parse(mode_raw).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown mode: {mode_raw} (expected stable, fastest or parallel)"
                    )
                })?;
                Some(super::group::Group::new(
                    tag.clone(),
                    members,
                    mode,
                    parse_duration(
                        map.get("error_ttl"),
                        Duration::ZERO,
                        &format!("{at}: error_ttl"),
                    )?,
                    parse_duration(
                        map.get("win_ttl"),
                        Duration::ZERO,
                        &format!("{at}: win_ttl"),
                    )?,
                    timeout,
                ))
            }
            _ => None,
        };
        let neighbor_domain = match map.get("neighbor_domain") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(entry)) => vec![entry.clone()],
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(_) => anyhow::bail!("{at}.neighbor_domain: must be a string or a list"),
        };
        let mdns_interfaces = match map.get("interface") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(entry)) => vec![entry.clone()],
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(_) => anyhow::bail!("{at}.interface: must be a string or a list"),
        };
        Ok(Self {
            tag,
            kind,
            server,
            port,
            tls,
            path,
            domain_resolver,
            timeout,
            inet4,
            inet6,
            store,
            detour,
            headers,
            hosts,
            group,
            neighbor_domain,
            mdns_interfaces,
        })
    }

    pub fn is_fakeip(&self) -> bool {
        self.kind == Kind::Fakeip
    }
}

/// How a transport reaches the wire: a detour outbound when the config set
/// `detour`, otherwise a direct dial to the resolved address.
#[derive(Clone, Default)]
pub struct Dialer {
    pub router: Option<Arc<crate::route::Router>>,
}

impl Dialer {
    async fn tcp(&self, cfg: &ServerConfig, addr: SocketAddr) -> io::Result<AnyStream> {
        let Some(router) = &self.router else {
            let tcp = TcpStream::connect(addr).await?;
            let _ = tcp.set_nodelay(true);
            return Ok(Box::new(tcp));
        };
        let target = crate::inbound::Target::Ip(addr);
        match &cfg.detour {
            Some(tag) => {
                let index = router
                    .index_of(tag)
                    .ok_or_else(|| io::Error::other(format!("dns: detour {tag:?} not found")))?;
                router.connect_index(index, &target).await?.into_plain()
            }
            None => {
                if addr.ip().is_loopback() {
                    let tcp = TcpStream::connect(addr).await?;
                    let _ = tcp.set_nodelay(true);
                    return Ok(Box::new(tcp));
                }
                router.connect(&target).await?.into_plain()
            }
        }
    }

    /// TLS over the dialed stream (the detour may be a proxy outbound, so the
    /// socket is not necessarily a `TcpStream`).
    async fn tls(
        &self,
        cfg: &ServerConfig,
        addr: SocketAddr,
        tls: &TlsOptions,
        alpn: &[&[u8]],
    ) -> io::Result<(AnyStream, Option<Vec<u8>>)> {
        let stream = self.tcp(cfg, addr).await?;
        let connected = tls.connect_stream(stream, alpn).await?;
        let negotiated = connected.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Ok((Box::new(connected), negotiated))
    }

    async fn udp(&self, cfg: &ServerConfig, addr: SocketAddr) -> io::Result<UdpSocket> {
        let Some(router) = &self.router else {
            let bind: SocketAddr = if addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let sock = UdpSocket::bind(bind).await?;
            sock.connect(addr).await?;
            return Ok(sock);
        };
        let target = crate::inbound::Target::Ip(addr);
        match &cfg.detour {
            Some(tag) => {
                let index = router
                    .index_of(tag)
                    .ok_or_else(|| io::Error::other(format!("dns: detour {tag:?} not found")))?;
                router.connect_udp_index(index, &target).await
            }
            None => {
                if addr.ip().is_loopback() {
                    let bind: SocketAddr = if addr.is_ipv4() {
                        "0.0.0.0:0".parse().unwrap()
                    } else {
                        "[::]:0".parse().unwrap()
                    };
                    let sock = UdpSocket::bind(bind).await?;
                    sock.connect(addr).await?;
                    return Ok(sock);
                }
                router
                    .connect_udp_index(router.default_index(), &target)
                    .await
            }
        }
    }
}

/// Run one query against a resolved server address.
pub async fn exchange(
    cfg: &ServerConfig,
    addr: SocketAddr,
    query: &[u8],
    dialer: &Dialer,
) -> io::Result<Vec<u8>> {
    let fut = async {
        match cfg.kind {
            Kind::Tailscale => {
                let router = dialer.router.as_ref().ok_or_else(|| {
                    io::Error::other("dns: Tailscale endpoint registry unavailable")
                })?;
                let inner = router.inner();
                let endpoint = inner
                    .outbound_table()
                    .find_map(|(_, tag, outbound)| match outbound {
                        crate::route::Outbound::Tailscale(endpoint) if tag == cfg.server => {
                            Some(endpoint.clone())
                        }
                        _ => None,
                    })
                    .ok_or_else(|| io::Error::other("dns: Tailscale endpoint not found"))?;
                endpoint.dns_exchange(query).await
            }
            // mdns has no server address: the router runs it before it gets here
            Kind::Mdns => Err(io::Error::other("dns: mdns server has no address")),
            Kind::Udp => exchange_udp(dialer, cfg, addr, query).await,
            Kind::Tcp => {
                let stream = dialer.tcp(cfg, addr).await?;
                exchange_stream(stream, query).await
            }
            Kind::Tls => {
                let tls = cfg
                    .tls
                    .as_ref()
                    .ok_or_else(|| io::Error::other("dns: tls server without tls options"))?;
                let (stream, _) = dialer.tls(cfg, addr, tls, &[]).await?;
                exchange_stream(stream, query).await
            }
            Kind::Https => exchange_doh(cfg, addr, query, dialer).await,
            Kind::Quic => exchange_doq(cfg, addr, query, dialer).await,
            Kind::H3 => exchange_h3(cfg, addr, query, dialer).await,
            Kind::Fakeip
            | Kind::Local
            | Kind::Hosts
            | Kind::Group
            | Kind::Dhcp
            | Kind::Resolved => Err(io::Error::other(
                "dns: this transport answers without reaching the wire",
            )),
        }
    };
    tokio::time::timeout(cfg.timeout, fut)
        .await
        .map_err(|_| io::Error::other(format!("dns: timeout after {:?}", cfg.timeout)))?
}

async fn exchange_udp(
    dialer: &Dialer,
    cfg: &ServerConfig,
    addr: SocketAddr,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let socket = dialer.udp(cfg, addr).await?;
    let send_query = || async {
        match socket.send(query).await {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(107) || e.raw_os_error() == Some(10057) => {
                socket.send_to(query, addr).await.map(|_| ())
            }
            Err(e) => Err(e),
        }
    };
    send_query().await?;

    let mut buf = vec![0u8; 65535];
    let retransmit_interval = Duration::from_millis(1500);
    const MAX_UDP_RETRIES: usize = 2; // 1 initial + 2 retries = 3 attempts total (~4.5s)
    let mut retries = 0;
    loop {
        let recv_fut = async {
            match socket.recv(&mut buf).await {
                Ok(n) => Ok(n),
                Err(e) if e.raw_os_error() == Some(107) || e.raw_os_error() == Some(10057) => {
                    let (n, _from) = socket.recv_from(&mut buf).await?;
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        };
        match tokio::time::timeout(retransmit_interval, recv_fut).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                retries += 1;
                if retries > MAX_UDP_RETRIES {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "dns: udp exchange timed out after maximum retries",
                    ));
                }
                let _ = send_query().await;
            }
        }
    }
}

async fn exchange_stream(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    if query.len() > u16::MAX as usize {
        return Err(io::Error::other("dns: query too large for tcp framing"));
    }
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn exchange_doh(
    cfg: &ServerConfig,
    addr: SocketAddr,
    query: &[u8],
    dialer: &Dialer,
) -> io::Result<Vec<u8>> {
    // the reference posts these with `Id = 0`, as RFC 8484/9250 allow
    let wire = wire_query(query);
    let query = wire.as_slice();

    // Reuse the pooled h2 connection the way the reference hands requests to
    // its shared http2.Transport (dns/transport/https_transport.go): a full
    // TLS + h2 handshake per query burned the router's CPU and filled
    // TIME_WAIT against one DoH server until nothing resolved at all.
    if let Some((id, send)) = doh_h2_checkout(&cfg.tag) {
        match doh_h2_exchange(cfg, send, query).await {
            Ok(body) => return Ok(body),
            Err(e) => {
                doh_h2_discard(&cfg.tag, id);
                crate::logging::debug(format_args!(
                    "dns: DoH h2 connection for {:?} dropped after error: {e}",
                    cfg.tag
                ));
            }
        }
    }

    let tls = cfg
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::other("dns: https server without tls options"))?;
    let (tls, negotiated) = dialer
        .tls(cfg, addr, tls, &[b"h2"])
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH tls: {e}")))?;

    match negotiated.as_deref() {
        Some(b"h2") => {
            let (send, conn) = h2::client::handshake(tls)
                .await
                .map_err(|e| io::Error::other(format!("dns: DoH h2 handshake: {e}")))?;
            let task = tokio::spawn(async move {
                let _ = conn.await;
            });
            let send = send
                .ready()
                .await
                .map_err(|e| io::Error::other(format!("dns: DoH h2 ready: {e}")))?;
            // keep it for the next query; a concurrent dial may have raced
            // us to the pool, and only one connection per server is kept
            {
                let mut pool = doh_h2_pool().lock().unwrap_or_else(|e| e.into_inner());
                if !pool.contains_key(&cfg.tag) {
                    pool.insert(
                        cfg.tag.clone(),
                        DohH2Conn {
                            id: DOH_H2_NEXT.fetch_add(1, Ordering::Relaxed),
                            send: send.clone(),
                            _task: task,
                        },
                    );
                }
            }
            doh_h2_exchange(cfg, send, query).await
        }
        _ => exchange_doh_h1(cfg, tls, query).await,
    }
}

/// One pooled DoH h2 connection: a send handle for new streams plus the
/// driver task that must outlive every stream on it.
struct DohH2Conn {
    id: u64,
    send: h2::client::SendRequest<bytes::Bytes>,
    _task: tokio::task::JoinHandle<()>,
}

static DOH_H2_NEXT: AtomicU64 = AtomicU64::new(1);

fn doh_h2_pool() -> &'static Mutex<HashMap<String, DohH2Conn>> {
    static POOL: std::sync::OnceLock<Mutex<HashMap<String, DohH2Conn>>> =
        std::sync::OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The pooled connection for `tag` if there is one: its id (so a later
/// discard cannot remove someone else's fresh connection) and a send handle,
/// which h2 multiplexes onto the shared connection.
fn doh_h2_checkout(tag: &str) -> Option<(u64, h2::client::SendRequest<bytes::Bytes>)> {
    doh_h2_pool()
        .lock()
        .ok()?
        .get(tag)
        .map(|conn| (conn.id, conn.send.clone()))
}

/// Drop `id`'s connection for `tag` and stop its driver. A stale id is
/// someone else's fresh connection and stays in the pool.
fn doh_h2_discard(tag: &str, id: u64) {
    let task = {
        let mut pool = doh_h2_pool().lock().unwrap_or_else(|e| e.into_inner());
        match pool.get(tag) {
            Some(conn) if conn.id == id => pool.remove(tag).map(|conn| conn._task),
            _ => None,
        }
    };
    if let Some(task) = task {
        task.abort();
    }
}

/// One DoH request/response stream over an h2 connection, pooled or fresh.
async fn doh_h2_exchange(
    cfg: &ServerConfig,
    send_request: h2::client::SendRequest<bytes::Bytes>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH h2 ready: {e}")))?;
    let authority = doh_authority(cfg);
    let request = doh_request(cfg, &authority, query.len())?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("dns: DoH send: {e}")))?;

    let mut io = H2Io {
        // `shared`: the connection outlives the stream — the pool owns it
        h2: H2Stream::shared(response, send),
    };
    io.write_all(query).await?;
    io.shutdown().await?;
    let mut body = Vec::new();
    io.read_to_end(&mut body).await?;
    if body.is_empty() {
        return Err(io::Error::other("dns: empty DoH response"));
    }
    Ok(body)
}

/// The per-query h2 path: the stream owns the connection and takes the
/// driver down with it on drop. Kept for tests; production goes through the
/// pooled [`doh_h2_exchange`].
#[cfg(test)]
async fn exchange_doh_h2(
    cfg: &ServerConfig,
    stream: AnyStream,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let authority = doh_authority(cfg);
    let (send_request, connection) = h2::client::handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH h2 handshake: {e}")))?;
    let conn_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH h2 ready: {e}")))?;

    let request = doh_request(cfg, &authority, query.len())?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("dns: DoH send: {e}")))?;

    let mut io = H2Io {
        h2: H2Stream::new(response, send, conn_task),
    };
    io.write_all(query).await?;
    io.shutdown().await?;
    let mut body = Vec::new();
    io.read_to_end(&mut body).await?;
    if body.is_empty() {
        return Err(io::Error::other("dns: empty DoH response"));
    }
    Ok(body)
}

async fn exchange_doh_h1(
    cfg: &ServerConfig,
    mut stream: AnyStream,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let authority = doh_authority(cfg);
    let mut extra = String::new();
    for (name, value) in &cfg.headers {
        if name.eq_ignore_ascii_case("content-type") || name.eq_ignore_ascii_case("accept") {
            continue;
        }
        extra.push_str(name);
        extra.push_str(": ");
        extra.push_str(value);
        extra.push_str("\r\n");
    }
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        cfg.path,
        query.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(query);
    stream.write_all(&request).await?;

    // Read head, then exactly Content-Length body bytes.
    let mut raw = Vec::with_capacity(1024 + query.len());
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::other("dns: DoH connection closed before head"));
        }
        raw.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_head_end(&raw) {
            break pos;
        }
    };
    let head_text = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let status_line = head_text.split("\r\n").next().unwrap_or("");
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(io::Error::other(format!(
            "dns: DoH unexpected status: {status_line}"
        )));
    }
    let mut content_length = None;
    for line in head_text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
            {
                return Err(io::Error::other(
                    "dns: DoH chunked responses not implemented (h1 fallback)",
                ));
            }
        }
    }
    let len = content_length
        .ok_or_else(|| io::Error::other("dns: DoH response without Content-Length"))?;
    let mut body = raw.split_off(head_end);
    while body.len() < len {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::other("dns: DoH truncated body"));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Ok(body)
}

/// DNS over QUIC (RFC 9250): one query per bidirectional stream, framed with
/// the same two-octet length prefix TCP uses.
async fn exchange_doq(
    cfg: &ServerConfig,
    addr: SocketAddr,
    query: &[u8],
    dialer: &Dialer,
) -> io::Result<Vec<u8>> {
    if query.len() > u16::MAX as usize {
        return Err(io::Error::other("dns: query too large for DoQ framing"));
    }
    // RFC 9250: the DNS ID is 0 on a QUIC stream
    let wire = wire_query(query);
    let query = wire.as_slice();
    let tls = cfg
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::other("dns: quic server without tls options"))?;
    let endpoint = quic_endpoint(cfg, addr, tls, &[b"doq"], dialer).await?;
    let connection = endpoint
        .connect(addr, tls.server_name())
        .map_err(|e| io::Error::other(format!("dns: DoQ connect: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("dns: DoQ handshake: {e}")))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| io::Error::other(format!("dns: DoQ stream: {e}")))?;

    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    send.write_all(&framed).await?;
    send.shutdown().await?;

    let mut len = [0u8; 2];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| io::Error::other(format!("dns: DoQ read: {e}")))?;
    let mut response = vec![0u8; u16::from_be_bytes(len) as usize];
    recv.read_exact(&mut response)
        .await
        .map_err(|e| io::Error::other(format!("dns: DoQ read: {e}")))?;

    // the endpoint owns the socket: dropping it closes the connection, which
    // is what we want after a single query
    drop(connection);
    drop(endpoint);
    Ok(response)
}

/// The DNS ID the reference sends over https / h3 / quic: always 0
/// (`exMessage.Id = 0` in `dns/transport`); `exchange_inner` restamps the
/// client's own ID on the response on the way out.
fn wire_query(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    if wire.len() >= 2 {
        wire[0] = 0;
        wire[1] = 0;
    }
    wire
}

/// DNS over HTTP/3: the same POST DoH sends, carried over QUIC.
async fn exchange_h3(
    cfg: &ServerConfig,
    addr: SocketAddr,
    query: &[u8],
    dialer: &Dialer,
) -> io::Result<Vec<u8>> {
    let wire = wire_query(query);
    let query = wire.as_slice();
    let tls = cfg
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::other("dns: h3 server without tls options"))?;
    let endpoint = quic_endpoint(cfg, addr, tls, &[b"h3"], dialer).await?;
    let connection = endpoint
        .connect(addr, tls.server_name())
        .map_err(|e| io::Error::other(format!("dns: h3 connect: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("dns: h3 handshake: {e}")))?;
    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| io::Error::other(format!("dns: h3 handshake: {e}")))?;
    let conn_task = tokio::spawn(async move {
        // the h3 connection is driven by this future; it only ends once the
        // connection is gone
        let _ = h3_connection.wait_idle().await;
    });

    let authority = doh_authority(cfg);
    let request = doh_request(cfg, &authority, query.len())?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| io::Error::other(format!("dns: h3 send: {e}")))?;

    // the body goes out before the response head: a DoH server does not
    // answer until the POST body has arrived
    stream
        .send_data(bytes::Bytes::copy_from_slice(query))
        .await
        .map_err(|e| io::Error::other(format!("dns: h3 write: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| io::Error::other(format!("dns: h3 finish: {e}")))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| io::Error::other(format!("dns: h3 response: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "dns: h3 unexpected status: {}",
            response.status()
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|e| io::Error::other(format!("dns: h3 read: {e}")))?
    {
        body.extend_from_slice(bytes::Buf::chunk(&chunk));
    }

    conn_task.abort();
    drop(endpoint);
    if body.is_empty() {
        return Err(io::Error::other("dns: empty h3 response"));
    }
    Ok(body)
}

/// A QUIC endpoint over the socket the dialer picked: direct by default, and
/// through `dns.server.detour` when the config named one.
async fn quic_endpoint(
    cfg: &ServerConfig,
    addr: SocketAddr,
    tls: &TlsOptions,
    alpn: &[&[u8]],
    dialer: &Dialer,
) -> io::Result<quinn::Endpoint> {
    let socket = dialer.udp(cfg, addr).await?.into_std()?;
    socket.set_nonblocking(true)?;
    let mut reset = [0u8; 32];
    let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut reset);
    let endpoint_config = quinn::EndpointConfig::new(Arc::new(
        crate::outbound::quic::HmacSha256Wrapper::new(&reset),
    ));
    let mut endpoint = quinn::Endpoint::new(
        endpoint_config,
        None,
        socket,
        quinn::default_runtime()
            .ok_or_else(|| io::Error::other("dns: no async QUIC runtime available"))?,
    )?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(tls.quic_config(alpn)?)));
    Ok(endpoint)
}

/// The DoH request head: `dns.headers` are cloned onto the request the way
/// the reference does it, with Content-Type and Accept overwritten after.
/// `content-length` is optional in h2/h3, but cloudflare-dns.com answers 400
/// to a POST without it while google and quad9 do not care.
fn doh_request(
    cfg: &ServerConfig,
    authority: &str,
    body_len: usize,
) -> io::Result<http::Request<()>> {
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}{}", cfg.path));
    for (name, value) in &cfg.headers {
        if name.eq_ignore_ascii_case("content-type") || name.eq_ignore_ascii_case("accept") {
            continue;
        }
        request = request.header(name.as_str(), value.as_str());
    }
    request
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", body_len.to_string())
        .body(())
        .map_err(|e| io::Error::other(format!("dns: DoH request: {e}")))
}

fn doh_authority(cfg: &ServerConfig) -> String {
    let host = match &cfg.tls {
        Some(tls) => tls.server_name().to_string(),
        None => cfg.server.clone(),
    };
    // the reference appends the port whenever it is not the scheme default
    if cfg.port == 443 {
        host
    } else {
        format!("{host}:{}", cfg.port)
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

pub fn is_ip_literal(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parse_and_contains() {
        let p = IpPrefix::parse("198.18.0.0/15").unwrap();
        assert!(p.contains("198.18.0.1".parse().unwrap()));
        assert!(p.contains("198.19.255.255".parse().unwrap()));
        assert!(!p.contains("198.20.0.1".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));
    }

    #[test]
    fn fakeip_allocates_sequentially_and_stably() {
        let store = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
        let a = store.create("b.example", false).unwrap();
        let b = store.create("c.example", false).unwrap();
        assert_eq!(a.to_string(), "198.18.0.2");
        assert_eq!(b.to_string(), "198.18.0.3");
        assert_eq!(store.create("b.example", false).unwrap(), a);
        assert_eq!(store.lookup_domain(a).as_deref(), Some("b.example"));
        assert_eq!(store.lookup_address("c.example", false), Some(b));
        assert!(store.contains(a));
        assert!(!store.contains("198.17.0.1".parse().unwrap()));
    }

    #[test]
    fn an_mdns_server_needs_no_address_and_takes_an_interface_list() {
        let cfg = ServerConfig::build(
            &serde_json::json!({"type": "mdns", "tag": "m", "interface": "eth0"}),
            "dns.servers[0]",
        )
        .expect("mdns server");
        assert_eq!(cfg.kind, Kind::Mdns);
        assert_eq!(cfg.mdns_interfaces, vec!["eth0".to_string()]);
        let list = ServerConfig::build(
            &serde_json::json!({"type": "mdns", "tag": "m", "interface": ["eth0", "eth1"]}),
            "dns.servers[0]",
        )
        .expect("mdns server with a list");
        assert_eq!(list.mdns_interfaces.len(), 2);
        // and no interface at all means every one of them
        let all = ServerConfig::build(&serde_json::json!({"type": "mdns"}), "dns.servers[0]")
            .expect("mdns server with no interface");
        assert!(all.mdns_interfaces.is_empty());
    }

    #[test]
    fn fakeip_wrap_around() {
        let store = FakeIpStore::new(Some(IpPrefix::parse("10.0.0.0/30").unwrap()), None);
        // /30: usable base+2 .. broadcast-1 → only 10.0.0.2
        let a = store.create("one", false).unwrap();
        assert_eq!(a.to_string(), "10.0.0.2");
        // next allocation wraps back to base+2 but domain map keeps stability
        let b = store.create("two", false).unwrap();
        assert_eq!(b.to_string(), "10.0.0.2");
    }

    #[tokio::test]
    async fn doh_h2_sends_content_length() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(tcp).await.expect("server handshake");
            let mut seen = None;
            let mut readers = Vec::new();
            while let Some(res) = std::future::poll_fn(|cx| conn.poll_accept(cx)).await {
                let Ok((req, mut respond)) = res else { break };
                seen = Some((req.uri().path().to_string(), req.headers().clone()));
                readers.push(tokio::spawn(async move {
                    let mut body = Vec::new();
                    let mut stream = req.into_body();
                    while let Some(Ok(chunk)) = stream.data().await {
                        let _ = stream.flow_control().release_capacity(chunk.len());
                        body.extend_from_slice(&chunk);
                    }
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(vec![0x01u8; 8].into(), true);
                    }
                    body
                }));
            }
            let mut bodies = Vec::new();
            for reader in readers {
                if let Ok(body) = reader.await {
                    bodies.push(body);
                }
            }
            (seen, bodies)
        });

        let cfg = ServerConfig::build(
            &serde_json::json!({
                "type": "https",
                "tag": "d",
                "server": "127.0.0.1",
                "server_port": 443,
                "path": "/dns-query",
                "tls": {"enabled": true, "server_name": "example.test"}
            }),
            "dns.servers[0]",
        )
        .expect("server cfg");
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let stream: AnyStream = Box::new(tcp);
        let query = crate::dns::codec::build_query(
            0x1111,
            "www.google.com",
            hickory_proto::rr::RecordType::A,
        )
        .expect("query");
        let wire = wire_query(&query);
        let answer = tokio::time::timeout(
            Duration::from_secs(10),
            exchange_doh_h2(&cfg, stream, &wire),
        )
        .await
        .expect("doh exchange timed out")
        .expect("doh exchange");
        assert!(!answer.is_empty());

        let (seen, bodies) = server.await.expect("server task");
        let (path, headers) = seen.expect("one request");
        assert_eq!(path, "/dns-query");
        assert_eq!(
            headers.get("content-type").map(|v| v.to_str().unwrap()),
            Some("application/dns-message")
        );
        assert_eq!(
            headers.get("accept").map(|v| v.to_str().unwrap()),
            Some("application/dns-message")
        );
        assert_eq!(bodies.len(), 1);
        let declared: usize = headers
            .get("content-length")
            .expect("content-length")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, bodies[0].len());
    }
}
