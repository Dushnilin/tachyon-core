//! `route.find_neighbor`: who is on the other end of this connection.
//!
//! The reference reads the kernel's neighbour table over rtnetlink, watches the
//! DHCP lease files and answers `source_mac_address` / `source_hostname` rule
//! items from the result (reference `route/neighbor_resolver*`). It is the
//! feature a router exists for: route the device that calls itself `tv` or that
//! has that MAC, without a static address list.
//!
//! Two deliberate simplifications, both invisible to the rules:
//!
//! * the neighbour table comes from `/proc/net/arp` re-read every few seconds
//!   instead of a netlink subscription. The kernel exports the same IPv4 table
//!   there, and a router's neighbour set changes slowly; IPv6 neighbours are
//!   covered by the lease files and by EUI-64, not by the table.
//! * lease files are polled for a changed size or mtime instead of watched with
//!   inotify, for the same reason.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::logging;

/// The one resolver of the process, like the reference's platform-wide
/// neighbour table: the router fills `source_mac_address` from it and the
/// `local` DNS transport answers `neighbor_domain` out of it.
static RESOLVER: OnceLock<RwLock<Option<Arc<NeighborResolver>>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<Arc<NeighborResolver>>> {
    RESOLVER.get_or_init(|| RwLock::new(None))
}

pub fn install(resolver: Arc<NeighborResolver>) {
    *slot().write().expect("neighbor resolver") = Some(resolver);
}

pub fn current() -> Option<Arc<NeighborResolver>> {
    slot().read().expect("neighbor resolver").clone()
}

/// The lease files a Linux router is known to keep, in the reference's order.
const DEFAULT_LEASE_FILES: &[&str] = &[
    "/tmp/dhcp.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
    "/var/lib/kea/kea-leases4.csv",
    "/var/lib/kea/kea-leases6.csv",
];

/// Re-read cadence for the neighbour table and the lease files.
const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

/// A hardware address, kept as the six bytes every format agrees on.
pub type MacAddr = [u8; 6];

/// The canonical text form Go's `net.HardwareAddr.String()` produces, which is
/// what `source_mac_address` rules compare against.
pub fn mac_string(mac: &MacAddr) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Default)]
struct Tables {
    /// Neighbour table: IPv4 → MAC.
    neighbor: HashMap<IpAddr, MacAddr>,
    /// Lease files: IP → MAC, IP → hostname, MAC → hostname.
    lease_mac: HashMap<IpAddr, MacAddr>,
    ip_hostname: HashMap<IpAddr, String>,
    mac_hostname: HashMap<MacAddr, String>,
    /// Lease file stamps, so an unchanged file is not re-parsed.
    stamps: HashMap<PathBuf, Option<(u64, SystemTime)>>,
}

pub struct NeighborResolver {
    lease_files: Vec<PathBuf>,
    tables: RwLock<Tables>,
}

impl NeighborResolver {
    /// `newNeighborResolver`: an empty list means the well-known lease files
    /// that exist and are not empty.
    pub fn new(lease_files: &[String]) -> Arc<Self> {
        let lease_files: Vec<PathBuf> = if lease_files.is_empty() {
            DEFAULT_LEASE_FILES
                .iter()
                .filter(|path| std::fs::metadata(path).is_ok_and(|meta| meta.len() > 0))
                .map(PathBuf::from)
                .collect()
        } else {
            lease_files.iter().map(PathBuf::from).collect()
        };
        Arc::new(Self {
            lease_files,
            tables: RwLock::new(Tables::default()),
        })
    }

    /// Load once, then keep both tables fresh in the background.
    pub fn start(self: &Arc<Self>) {
        self.reload(true);
        let resolver = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                resolver.reload(false);
            }
        });
    }

    fn reload(&self, force: bool) {
        let mut tables = self.tables.write().expect("neighbor tables");
        tables.neighbor = read_arp_table();
        for path in &self.lease_files {
            let stamp = file_stamp(path);
            if !force && tables.stamps.get(path) == Some(&stamp) {
                continue;
            }
            tables.stamps.insert(path.clone(), stamp);
            match std::fs::read_to_string(path) {
                Ok(text) => parse_lease_file(path, &text, &mut tables),
                Err(error) => {
                    logging::warn(format_args!("neighbor: read {}: {error}", path.display()))
                }
            }
        }
    }

    /// The client's MAC: the neighbour table, then the leases, then the
    /// address itself when it is a modified EUI-64.
    pub fn lookup_mac(&self, address: IpAddr) -> Option<MacAddr> {
        let tables = self.tables.read().expect("neighbor tables");
        tables
            .neighbor
            .get(&address)
            .or_else(|| tables.lease_mac.get(&address))
            .copied()
            .or_else(|| mac_from_eui64(address))
    }

    /// The client's DHCP hostname, directly or through its MAC.
    pub fn lookup_hostname(&self, address: IpAddr) -> Option<String> {
        let tables = self.tables.read().expect("neighbor tables");
        if let Some(hostname) = tables.ip_hostname.get(&address) {
            return Some(hostname.clone());
        }
        let mac = tables
            .neighbor
            .get(&address)
            .or_else(|| tables.lease_mac.get(&address))
            .copied()
            .or_else(|| mac_from_eui64(address))?;
        tables.mac_hostname.get(&mac).cloned()
    }

    /// Every address a hostname answers with, for the `local` transport's
    /// `neighbor_domain` lookups. Link-local answers are left out: a DNS AAAA
    /// record cannot carry the interface zone.
    pub fn lookup_addresses(&self, hostname: &str) -> Vec<IpAddr> {
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
        if hostname.is_empty() {
            return Vec::new();
        }
        let tables = self.tables.read().expect("neighbor tables");
        let mut out: Vec<IpAddr> = Vec::new();
        let mut push = |address: IpAddr| {
            if is_scoped_ipv6(address) || out.contains(&address) {
                return;
            }
            out.push(address);
        };
        for (address, name) in &tables.ip_hostname {
            if name.eq_ignore_ascii_case(&hostname) {
                push(*address);
            }
        }
        for (mac, name) in &tables.mac_hostname {
            if !name.eq_ignore_ascii_case(&hostname) {
                continue;
            }
            for (address, entry) in tables.lease_mac.iter().chain(tables.neighbor.iter()) {
                if entry == mac {
                    push(*address);
                }
            }
        }
        out
    }
}

fn file_stamp(path: &Path) -> Option<(u64, SystemTime)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// `/proc/net/arp`: `IP address HW type Flags HW address Mask Device`.
fn read_arp_table() -> HashMap<IpAddr, MacAddr> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string("/proc/net/arp") else {
        return out;
    };
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (Ok(address), Some(mac)) = (fields[0].parse::<IpAddr>(), parse_mac(fields[3])) else {
            continue;
        };
        // an incomplete entry carries a zero MAC
        if mac == [0; 6] {
            continue;
        }
        out.insert(address, mac);
    }
    out
}

pub fn parse_mac(raw: &str) -> Option<MacAddr> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == ':' || *c == '-')
        .collect();
    let bytes: Vec<u8> = cleaned
        .split([':', '-'])
        .filter(|part| !part.is_empty())
        .filter_map(|part| u8::from_str_radix(part, 16).ok())
        .collect();
    (bytes.len() == 6).then(|| {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes);
        mac
    })
}

/// Modified EUI-64: `xx:xx:xx:ff:fe:xx:xx:xx:xx:xx` carries the MAC with its
/// first bit flipped.
fn mac_from_eui64(address: IpAddr) -> Option<MacAddr> {
    let IpAddr::V6(v6) = address else {
        return None;
    };
    let bytes = v6.octets();
    if bytes[11] != 0xff || bytes[12] != 0xfe {
        return None;
    }
    Some([
        bytes[8] ^ 0x02,
        bytes[9],
        bytes[10],
        bytes[13],
        bytes[14],
        bytes[15],
    ])
}

fn is_scoped_ipv6(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

fn record(tables: &mut Tables, address: IpAddr, mac: Option<MacAddr>, hostname: &str) {
    if let Some(mac) = mac {
        tables.lease_mac.insert(address, mac);
    }
    if !hostname.is_empty() && hostname != "*" && hostname != "-" {
        tables.ip_hostname.insert(address, hostname.to_string());
        if let Some(mac) = mac {
            tables.mac_hostname.insert(mac, hostname.to_string());
        }
    }
}

/// The format follows the file name, exactly as the reference does.
fn parse_lease_file(path: &Path, text: &str, tables: &mut Tables) {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    match name.as_deref() {
        Some("dhcpd_leases") => parse_bootpd(text, tables),
        Some("kea-leases4.csv") => parse_kea4(text, tables),
        Some("kea-leases6.csv") => parse_kea6(text, tables),
        Some("dhcpd.leases") => parse_isc_dhcpd(text, tables),
        _ => parse_dnsmasq_odhcpd(text, tables),
    }
}

/// dnsmasq's `leases` file and odhcpd's commented lease blocks — the OpenWrt
/// pair, so this is the format that matters on a router.
fn parse_dnsmasq_odhcpd(text: &str, tables: &mut Tables) {
    let now = now_unix();
    for line in text.lines() {
        if line.starts_with("duid ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            parse_odhcpd_line(rest, now, tables);
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Ok(expiry) = fields[0].parse::<i64>() else {
            continue;
        };
        if expiry != 0 && expiry < now {
            continue;
        }
        let Some(address) = fields[2].parse::<IpAddr>().ok().map(unmap) else {
            continue;
        };
        let mac = if fields[1].contains(':') {
            parse_mac(fields[1])
        } else {
            // a DUID instead of a MAC: odhcpd records it in the client id
            fields.get(4).and_then(|duid| mac_from_duid(duid))
        };
        record(tables, address, mac, fields[3]);
    }
}

/// `odhcpd` lease lines: `duid iaid ipv4 hostname valid address...`.
fn parse_odhcpd_line(line: &str, now: i64, tables: &mut Tables) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return;
    }
    let Ok(valid) = fields[4].parse::<i64>() else {
        return;
    };
    if valid == 0 || (valid > 0 && valid < now) {
        return;
    }
    let mut hostname = fields[3];
    if hostname == "-" || hostname.starts_with("broken\\x20") {
        hostname = "";
    }
    if fields.get(2) == Some(&"ipv4") && fields.len() >= 8 {
        let Some(mac) = parse_mac(fields[1]) else {
            return;
        };
        let Some(address) = fields[7]
            .split('/')
            .next()
            .and_then(|raw| raw.parse::<IpAddr>().ok())
            .map(unmap)
        else {
            return;
        };
        record(tables, address, Some(mac), hostname);
        return;
    }
    let mac = mac_from_duid(fields[1]);
    for field in fields.iter().skip(7) {
        let Some(address) = field
            .split('/')
            .next()
            .and_then(|raw| raw.parse::<IpAddr>().ok())
            .map(unmap)
        else {
            continue;
        };
        record(tables, address, mac, hostname);
    }
}

/// ISC dhcpd's block format; only an active binding counts.
fn parse_isc_dhcpd(text: &str, tables: &mut Tables) {
    let mut address = None;
    let mut mac = None;
    let mut hostname = String::new();
    let mut active = false;
    let mut in_lease = false;
    for line in text.lines().map(str::trim) {
        if in_lease {
            if line == "}" {
                match (active, address) {
                    (true, Some(address)) => record(tables, address, mac, &hostname),
                    _ => {
                        if let Some(address) = address {
                            tables.lease_mac.remove(&address);
                            tables.ip_hostname.remove(&address);
                        }
                    }
                }
                in_lease = false;
                continue;
            }
            if let Some(rest) = line.strip_prefix("hardware ethernet ") {
                mac = parse_mac(rest.trim_end_matches(';'));
            } else if let Some(rest) = line.strip_prefix("client-hostname ") {
                let name = rest.trim_end_matches(';').trim_matches('"');
                if !name.is_empty() {
                    hostname = name.to_string();
                }
            } else if let Some(rest) = line.strip_prefix("binding state ") {
                active = rest.trim_end_matches(';') == "active";
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("lease ") {
            let raw = rest.trim_end_matches('{').trim();
            address = raw.parse::<IpAddr>().ok().map(unmap);
            in_lease = address.is_some();
            mac = None;
            hostname = String::new();
            active = false;
        }
    }
}

/// Kea's CSV leases. Both files are comma separated with a header, and only a
/// released (state 0) lease counts.
fn parse_kea4(text: &str, tables: &mut Tables) {
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            continue; // header
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 10 || fields[9] != "0" {
            continue;
        }
        let Some(address) = fields[0].parse::<IpAddr>().ok().map(unmap) else {
            continue;
        };
        let Some(mac) = parse_mac(fields[1]) else {
            continue;
        };
        record(
            tables,
            address,
            Some(mac),
            fields.get(8).copied().unwrap_or_default(),
        );
    }
}

fn parse_kea6(text: &str, tables: &mut Tables) {
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            continue; // header
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 14 || fields[13] != "0" {
            continue;
        }
        let Some(address) = fields[0].parse::<IpAddr>().ok().map(unmap) else {
            continue;
        };
        // column 12 is the hardware address, and it is empty for a client that
        // only ever identified itself with a DUID
        let mac = match fields[12].is_empty() {
            true => mac_from_duid(&fields[1].replace(':', "")),
            false => parse_mac(fields[12]),
        };
        record(tables, address, mac, fields[11]);
    }
}

/// bootpd's `dhcpd_leases` blocks (macOS).
fn parse_bootpd(text: &str, tables: &mut Tables) {
    let now = now_unix();
    let mut name = String::new();
    let mut address = None;
    let mut mac = None;
    let mut lease = 0i64;
    let mut in_block = false;
    for line in text.lines().map(str::trim) {
        if line == "{" {
            in_block = true;
            name = String::new();
            address = None;
            mac = None;
            lease = 0;
            continue;
        }
        if line == "}" && in_block {
            if let (Some(mac), Some(address)) = (mac, address)
                && (lease == 0 || lease >= now)
            {
                record(tables, address, Some(mac), &name);
            }
            in_block = false;
            continue;
        }
        if !in_block {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "name" => name = value.to_string(),
            "ip_address" => address = value.parse::<IpAddr>().ok().map(unmap),
            "hw_address" => mac = value.strip_prefix("1,").and_then(parse_mac),
            "lease" => {
                lease = i64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            _ => {}
        }
    }
}

/// A DHCP unique identifier, which for DUID-LLT and DUID-LL carries the MAC.
fn mac_from_duid(duid: &str) -> Option<MacAddr> {
    let cleaned: String = duid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() < 8 {
        return None;
    }
    let byte = |index: usize| u8::from_str_radix(&cleaned[index..index + 2], 16).ok();
    let word = |index: usize| u16::from_str_radix(&cleaned[index..index + 4], 16).ok();
    if word(4) != Some(1) {
        return None; // not an ethernet DUID
    }
    // DUID-LLT keeps a time and a link field before the MAC, DUID-LL does not
    let start = match word(0)? {
        1 => 8,
        3 => 4,
        _ => return None,
    };
    if cleaned.len() < start * 2 + 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (offset, slot) in mac.iter_mut().enumerate() {
        *slot = byte((start + offset) * 2)?;
    }
    Some(mac)
}

/// A DNS answer cannot carry an IPv4-mapped IPv6 address.
fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> Tables {
        Tables::default()
    }

    #[test]
    fn mac_text_is_the_go_form() {
        assert_eq!(
            mac_string(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            parse_mac("AA-BB-CC-DD-EE-FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parse_mac("not a mac"), None);
    }

    #[test]
    fn dnsmasq_leases_are_read() {
        let now = now_unix();
        let text = format!(
            "# odhcpd comment\n\
             {lease} aa:bb:cc:dd:ee:01 192.168.1.10 tv 01:aa:bb:cc:dd:ee:01\n\
             {lease} aa:bb:cc:dd:ee:02 192.168.1.11 * *\n\
             {expired} aa:bb:cc:dd:ee:03 192.168.1.12 old 01:aa:bb:cc:dd:ee:03\n\
             duid 00:03:00:01:aa:bb:cc:dd:ee:04\n",
            lease = now + 3600,
            expired = now - 10,
        );
        let mut state = tables();
        parse_dnsmasq_odhcpd(&text, &mut state);
        assert_eq!(
            state
                .ip_hostname
                .get(&"192.168.1.10".parse().expect("ip"))
                .map(String::as_str),
            Some("tv")
        );
        assert_eq!(
            state
                .lease_mac
                .get(&"192.168.1.10".parse().expect("ip"))
                .copied(),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])
        );
        // a `*` hostname is not a name
        assert!(
            !state
                .ip_hostname
                .contains_key(&"192.168.1.11".parse().expect("ip"))
        );
        // an expired lease is dropped
        assert!(
            !state
                .ip_hostname
                .contains_key(&"192.168.1.12".parse().expect("ip"))
        );
    }

    #[test]
    fn odhcpd_duid_lines_yield_a_mac() {
        let now = now_unix();
        // odhcpd writes the client's DUID twice: the identifier first and its
        // ethernet DUID-LL in the link field the reference reads
        let line = format!(
            "00:01:00:00:11:22 00:03:00:01:aa:bb:cc:dd:ee:05 00000001 printer {now2} 0 0 2001:db8::5/64",
            now2 = now + 60
        );
        let mut state = tables();
        parse_odhcpd_line(&line, now, &mut state);
        let address: IpAddr = "2001:db8::5".parse().expect("ip");
        assert_eq!(
            state.lease_mac.get(&address).copied(),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05])
        );
        assert_eq!(
            state.ip_hostname.get(&address).map(String::as_str),
            Some("printer")
        );
    }

    #[test]
    fn isc_dhcpd_blocks_need_an_active_binding() {
        let text = "\
lease 192.168.1.20 {
  hardware ethernet aa:bb:cc:dd:ee:20;
  client-hostname \"nas\";
  binding state active;
}
lease 192.168.1.21 {
  hardware ethernet aa:bb:cc:dd:ee:21;
  client-hostname \"gone\";
  binding state released;
}
";
        let mut state = tables();
        parse_isc_dhcpd(text, &mut state);
        assert_eq!(
            state
                .ip_hostname
                .get(&"192.168.1.20".parse().expect("ip"))
                .map(String::as_str),
            Some("nas")
        );
        assert!(
            !state
                .ip_hostname
                .contains_key(&"192.168.1.21".parse().expect("ip"))
        );
    }

    #[test]
    fn eui64_addresses_carry_their_mac() {
        // fe80::aabb:ccff:fedd:eeff is EUI-64, with the first bit flipped
        let address: IpAddr = "fe80::aabb:ccff:fedd:eeff".parse().expect("ip");
        assert_eq!(
            mac_from_eui64(address),
            Some([0xa8, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(mac_from_eui64("2001:db8::1".parse().expect("ip")), None);
        assert_eq!(mac_from_eui64("192.168.1.1".parse().expect("ip")), None);
    }

    #[test]
    fn kea_csv_leases_are_read() {
        // the reference reads the state from the tenth column and the hostname
        // from the ninth, so the fixture is laid out the way it expects
        let text = "\
address,hwaddr,client_id,subnet_id,valid_lft,cltt,subnet,alias,hostname,state
192.168.1.40,aa:bb:cc:dd:ee:40,01:aa,1,3600,1750000000,0,iot.lan,iot,0
192.168.1.41,aa:bb:cc:dd:ee:41,01:ab,1,3600,1750000000,0,stale.lan,stale,1
";
        let mut state = tables();
        parse_kea4(text, &mut state);
        assert_eq!(
            state
                .ip_hostname
                .get(&"192.168.1.40".parse().expect("ip"))
                .map(String::as_str),
            Some("iot")
        );
        assert!(
            !state
                .ip_hostname
                .contains_key(&"192.168.1.41".parse().expect("ip")),
            "a state other than 0 is not a lease"
        );
    }

    #[test]
    fn hostname_lookup_walks_through_the_mac() {
        let resolver = NeighborResolver::new(&[]);
        {
            let mut state = resolver.tables.write().expect("tables");
            state.neighbor.insert(
                "192.168.1.30".parse().expect("ip"),
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x30],
            );
            state
                .mac_hostname
                .insert([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x30], "console".to_string());
        }
        assert_eq!(
            resolver.lookup_mac("192.168.1.30".parse().expect("ip")),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x30])
        );
        assert_eq!(
            resolver
                .lookup_hostname("192.168.1.30".parse().expect("ip"))
                .as_deref(),
            Some("console")
        );
        assert_eq!(
            resolver.lookup_addresses("console"),
            vec!["192.168.1.30".parse::<IpAddr>().expect("ip")]
        );
        assert!(resolver.lookup_addresses("nothing").is_empty());
    }

    #[test]
    fn link_local_answers_are_left_out() {
        let resolver = NeighborResolver::new(&[]);
        {
            let mut state = resolver.tables.write().expect("tables");
            state
                .ip_hostname
                .insert("fe80::1".parse().expect("ip"), "link".to_string());
            state
                .ip_hostname
                .insert("2001:db8::1".parse().expect("ip"), "link".to_string());
        }
        assert_eq!(
            resolver.lookup_addresses("link"),
            vec!["2001:db8::1".parse::<IpAddr>().expect("ip")],
            "an AAAA record cannot carry the zone"
        );
    }
}
