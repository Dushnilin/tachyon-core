//! Compiler from high-level rule-sets to flat TSRS memory-mapped binary image.

use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;

use super::format::*;
use crate::route::rule_set::{list, ports};

pub struct RuleSetCompiler {
    domains: HashSet<String>,
    suffixes: HashSet<String>,
    keywords: HashSet<String>,
    dest_v4: HashSet<Ipv4Entry>,
    dest_v6: HashSet<Ipv6Entry>,
    dest_ports: HashSet<PortRangeEntry>,
    total_rules: usize,
}

impl Default for RuleSetCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSetCompiler {
    pub fn new() -> Self {
        Self {
            domains: HashSet::new(),
            suffixes: HashSet::new(),
            keywords: HashSet::new(),
            dest_v4: HashSet::new(),
            dest_v6: HashSet::new(),
            dest_ports: HashSet::new(),
            total_rules: 0,
        }
    }

    /// Compile a list of headless rule JSON values directly into a TSRS binary image.
    pub fn compile(&mut self, rules: &[Value]) -> anyhow::Result<Vec<u8>> {
        let mut compiler = Self::new();
        compiler.feed_rules(rules);
        Ok(compiler.finish())
    }

    pub fn set_total_rules(&mut self, count: usize) {
        self.total_rules = count;
    }

    pub fn add_domain(&mut self, domain: &str) {
        if !domain.is_empty() {
            self.domains.insert(domain.to_lowercase());
        }
    }

    pub fn remove_domain(&mut self, domain: &str) {
        self.domains.remove(&domain.to_lowercase());
    }

    pub fn add_suffix(&mut self, suffix: &str) {
        let s = suffix.trim_start_matches('.').to_lowercase();
        if !s.is_empty() {
            self.suffixes.insert(s);
        }
    }

    pub fn remove_suffix(&mut self, suffix: &str) {
        let s = suffix.trim_start_matches('.').to_lowercase();
        self.suffixes.remove(&s);
    }

    pub fn add_keyword(&mut self, keyword: &str) {
        if !keyword.is_empty() {
            self.keywords.insert(keyword.to_lowercase());
        }
    }

    pub fn remove_keyword(&mut self, keyword: &str) {
        self.keywords.remove(&keyword.to_lowercase());
    }

    pub fn add_cidr(&mut self, cidr: &str) {
        let Some((base, bits_str)) = cidr.split_once('/') else {
            if let Ok(ip) = cidr.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        self.dest_v4.insert(Ipv4Entry {
                            addr: u32::from(v4),
                            prefix_len: 32,
                            _pad: [0; 3],
                        });
                    }
                    IpAddr::V6(v6) => {
                        self.dest_v6.insert(Ipv6Entry {
                            addr: u128::from(v6),
                            prefix_len: 128,
                            _pad: [0; 7],
                        });
                    }
                }
            }
            return;
        };

        let Ok(bits) = bits_str.parse::<u8>() else {
            return;
        };
        if let Ok(base_ip) = base.parse::<IpAddr>() {
            match base_ip {
                IpAddr::V4(v4) => {
                    let len = bits.min(32);
                    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                    self.dest_v4.insert(Ipv4Entry {
                        addr: u32::from(v4) & mask,
                        prefix_len: len,
                        _pad: [0; 3],
                    });
                }
                IpAddr::V6(v6) => {
                    let len = bits.min(128);
                    let mask = if len == 0 {
                        0
                    } else {
                        u128::MAX << (128 - len)
                    };
                    self.dest_v6.insert(Ipv6Entry {
                        addr: u128::from(v6) & mask,
                        prefix_len: len,
                        _pad: [0; 7],
                    });
                }
            }
        }
    }

    #[allow(clippy::collapsible_if)]
    pub fn remove_cidr(&mut self, cidr: &str) {
        if let Some((base, bits_str)) = cidr.split_once('/') {
            if let Ok(bits) = bits_str.parse::<u8>() {
                if let Ok(ip) = base.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(v4) => {
                            let len = bits.min(32);
                            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                            self.dest_v4.remove(&Ipv4Entry {
                                addr: u32::from(v4) & mask,
                                prefix_len: len,
                                _pad: [0; 3],
                            });
                        }
                        IpAddr::V6(v6) => {
                            let len = bits.min(128);
                            let mask = if len == 0 {
                                0
                            } else {
                                u128::MAX << (128 - len)
                            };
                            self.dest_v6.remove(&Ipv6Entry {
                                addr: u128::from(v6) & mask,
                                prefix_len: len,
                                _pad: [0; 7],
                            });
                        }
                    }
                }
            }
        }
    }

    pub fn add_port(&mut self, port: u16) {
        self.dest_ports.insert(PortRangeEntry {
            start: port,
            end: port,
        });
    }

    pub fn add_port_range(&mut self, start: u16, end: u16) {
        if start <= end {
            self.dest_ports.insert(PortRangeEntry { start, end });
        }
    }

    pub fn remove_port_range(&mut self, start: u16, end: u16) {
        self.dest_ports.remove(&PortRangeEntry { start, end });
    }

    /// Feed headless rule JSON objects (as found in sing-box .srs or rule-set source).
    pub fn feed_rules(&mut self, rules: &[Value]) {
        self.total_rules += rules.len();
        for rule in rules {
            if let Some(obj) = rule.as_object() {
                // domains
                for d in list(obj.get("domain")) {
                    self.add_domain(&d);
                }
                // suffixes
                for s in list(obj.get("domain_suffix")) {
                    self.add_suffix(&s);
                }
                // keywords
                for k in list(obj.get("domain_keyword")) {
                    self.add_keyword(&k);
                }
                // IP CIDRs
                for c in list(obj.get("ip_cidr")) {
                    self.add_cidr(&c);
                }
                for c in list(obj.get("ipcidr")) {
                    self.add_cidr(&c);
                }
                // Ports
                for p in ports(obj.get("port")) {
                    self.add_port(p);
                }
                for range_str in list(obj.get("port_range")) {
                    #[allow(clippy::collapsible_if)]
                    if let Some((start, end)) = range_str.split_once('-') {
                        if let (Ok(s), Ok(e)) =
                            (start.trim().parse::<u16>(), end.trim().parse::<u16>())
                        {
                            self.add_port_range(s, e);
                        }
                    }
                }
            }
        }
    }

    /// Compile into binary .tsrs image.
    pub fn finish(self) -> Vec<u8> {
        let mut string_table = Vec::new();

        // 1. Sort domains alphabetically
        let mut sorted_domains: Vec<String> = self.domains.into_iter().collect();
        sorted_domains.sort_unstable();
        let mut domain_entries = Vec::with_capacity(sorted_domains.len());
        for d in &sorted_domains {
            let offset = string_table.len() as u32;
            let bytes = d.as_bytes();
            string_table.extend_from_slice(bytes);
            domain_entries.push(DomainEntry {
                offset,
                len: bytes.len() as u16,
                _pad: 0,
            });
        }

        // 2. Sort suffixes alphabetically
        let mut sorted_suffixes: Vec<String> = self.suffixes.into_iter().collect();
        sorted_suffixes.sort_unstable();
        let mut suffix_entries = Vec::with_capacity(sorted_suffixes.len());
        for s in &sorted_suffixes {
            let offset = string_table.len() as u32;
            let bytes = s.as_bytes();
            string_table.extend_from_slice(bytes);
            suffix_entries.push(DomainEntry {
                offset,
                len: bytes.len() as u16,
                _pad: 0,
            });
        }

        // 3. Sort keywords
        let mut sorted_keywords: Vec<String> = self.keywords.into_iter().collect();
        sorted_keywords.sort_unstable();
        let mut keyword_entries = Vec::with_capacity(sorted_keywords.len());
        for k in &sorted_keywords {
            let offset = string_table.len() as u32;
            let bytes = k.as_bytes();
            string_table.extend_from_slice(bytes);
            keyword_entries.push(DomainEntry {
                offset,
                len: bytes.len() as u16,
                _pad: 0,
            });
        }

        // 4. Sort IPv4 CIDRs: by prefix_len first (descending), then addr
        let mut sorted_v4: Vec<Ipv4Entry> = self.dest_v4.into_iter().collect();
        sorted_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len).then(a.addr.cmp(&b.addr)));

        // 5. Sort IPv6 CIDRs
        let mut sorted_v6: Vec<Ipv6Entry> = self.dest_v6.into_iter().collect();
        sorted_v6.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len).then(a.addr.cmp(&b.addr)));

        // 6. Sort port ranges
        let mut sorted_ports: Vec<PortRangeEntry> = self.dest_ports.into_iter().collect();
        sorted_ports.sort_unstable();

        // Compute table offsets
        let header_len = HEADER_SIZE;
        let mut offset = header_len;

        // Alignment helper
        fn align_8(pos: usize) -> usize {
            (pos + 7) & !7
        }

        offset = align_8(offset);
        let domains_offset = offset as u32;
        let domains_count = domain_entries.len() as u32;
        offset += domain_entries.len() * std::mem::size_of::<DomainEntry>();

        offset = align_8(offset);
        let suffixes_offset = offset as u32;
        let suffixes_count = suffix_entries.len() as u32;
        offset += suffix_entries.len() * std::mem::size_of::<DomainEntry>();

        offset = align_8(offset);
        let keywords_offset = offset as u32;
        let keywords_count = keyword_entries.len() as u32;
        offset += keyword_entries.len() * std::mem::size_of::<DomainEntry>();

        offset = align_8(offset);
        let dest_v4_offset = offset as u32;
        let dest_v4_count = sorted_v4.len() as u32;
        offset += sorted_v4.len() * std::mem::size_of::<Ipv4Entry>();

        offset = align_8(offset);
        let dest_v6_offset = offset as u32;
        let dest_v6_count = sorted_v6.len() as u32;
        offset += sorted_v6.len() * std::mem::size_of::<Ipv6Entry>();

        offset = align_8(offset);
        let dest_ports_offset = offset as u32;
        let dest_ports_count = sorted_ports.len() as u32;
        offset += sorted_ports.len() * std::mem::size_of::<PortRangeEntry>();

        offset = align_8(offset);
        let string_table_offset = offset as u32;
        let string_table_len = string_table.len() as u32;
        offset += string_table.len();

        let header = Header {
            magic: *TSRS_MAGIC,
            version: TSRS_VERSION,
            flags: 1, // Delta enabled
            total_rules: self.total_rules as u32,
            domains_offset,
            domains_count,
            suffixes_offset,
            suffixes_count,
            keywords_offset,
            keywords_count,
            dest_v4_offset,
            dest_v4_count,
            dest_v6_offset,
            dest_v6_count,
            dest_ports_offset,
            dest_ports_count,
            string_table_offset,
            string_table_len,
        };

        let mut output = vec![0u8; offset];

        // Write header
        unsafe {
            std::ptr::copy_nonoverlapping(
                &header as *const Header as *const u8,
                output.as_mut_ptr(),
                HEADER_SIZE,
            );
        }

        // Write domain entries
        if !domain_entries.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    domain_entries.as_ptr() as *const u8,
                    output.as_mut_ptr().add(domains_offset as usize),
                    domain_entries.len() * std::mem::size_of::<DomainEntry>(),
                );
            }
        }

        // Write suffix entries
        if !suffix_entries.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    suffix_entries.as_ptr() as *const u8,
                    output.as_mut_ptr().add(suffixes_offset as usize),
                    suffix_entries.len() * std::mem::size_of::<DomainEntry>(),
                );
            }
        }

        // Write keyword entries
        if !keyword_entries.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    keyword_entries.as_ptr() as *const u8,
                    output.as_mut_ptr().add(keywords_offset as usize),
                    keyword_entries.len() * std::mem::size_of::<DomainEntry>(),
                );
            }
        }

        // Write IPv4 entries
        if !sorted_v4.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sorted_v4.as_ptr() as *const u8,
                    output.as_mut_ptr().add(dest_v4_offset as usize),
                    sorted_v4.len() * std::mem::size_of::<Ipv4Entry>(),
                );
            }
        }

        // Write IPv6 entries
        if !sorted_v6.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sorted_v6.as_ptr() as *const u8,
                    output.as_mut_ptr().add(dest_v6_offset as usize),
                    sorted_v6.len() * std::mem::size_of::<Ipv6Entry>(),
                );
            }
        }

        // Write port entries
        if !sorted_ports.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sorted_ports.as_ptr() as *const u8,
                    output.as_mut_ptr().add(dest_ports_offset as usize),
                    sorted_ports.len() * std::mem::size_of::<PortRangeEntry>(),
                );
            }
        }

        // Write string table
        if !string_table.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    string_table.as_ptr(),
                    output.as_mut_ptr().add(string_table_offset as usize),
                    string_table.len(),
                );
            }
        }

        output
    }
}
