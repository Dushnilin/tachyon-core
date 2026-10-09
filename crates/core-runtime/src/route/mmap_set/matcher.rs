//! Zero-copy matcher running directly over memory-mapped TSRS buffers.

use super::format::*;
use crate::route::ConnContext;
use crate::route::rule::domain_host;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug)]
pub struct MmapView<'a> {
    pub(crate) header: &'a Header,
    pub(crate) domains: &'a [DomainEntry],
    pub(crate) suffixes: &'a [DomainEntry],
    pub(crate) keywords: &'a [DomainEntry],
    pub(crate) dest_v4: &'a [Ipv4Entry],
    pub(crate) dest_v6: &'a [Ipv6Entry],
    pub(crate) dest_ports: &'a [PortRangeEntry],
    pub(crate) string_table: &'a [u8],
}

impl<'a> MmapView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let header = Header::parse(bytes)?;

        // Safety: all entries are Plain Old Data (repr(C)) and offsets are validated against total len.
        let string_start = header.string_table_offset as usize;
        let string_end = string_start + header.string_table_len as usize;
        if string_end > bytes.len() {
            return None;
        }
        let string_table = &bytes[string_start..string_end];

        let domains = Self::slice_at::<DomainEntry>(
            bytes,
            header.domains_offset as usize,
            header.domains_count as usize,
        )?;

        let suffixes = Self::slice_at::<DomainEntry>(
            bytes,
            header.suffixes_offset as usize,
            header.suffixes_count as usize,
        )?;

        let keywords = Self::slice_at::<DomainEntry>(
            bytes,
            header.keywords_offset as usize,
            header.keywords_count as usize,
        )?;

        let dest_v4 = Self::slice_at::<Ipv4Entry>(
            bytes,
            header.dest_v4_offset as usize,
            header.dest_v4_count as usize,
        )?;

        let dest_v6 = Self::slice_at::<Ipv6Entry>(
            bytes,
            header.dest_v6_offset as usize,
            header.dest_v6_count as usize,
        )?;

        let dest_ports = Self::slice_at::<PortRangeEntry>(
            bytes,
            header.dest_ports_offset as usize,
            header.dest_ports_count as usize,
        )?;

        // Return parsed view
        // Store header reference
        let header_ref = unsafe { &*(bytes.as_ptr() as *const Header) };

        Some(Self {
            header: header_ref,
            domains,
            suffixes,
            keywords,
            dest_v4,
            dest_v6,
            dest_ports,
            string_table,
        })
    }

    fn slice_at<T>(bytes: &'a [u8], offset: usize, count: usize) -> Option<&'a [T]> {
        if count == 0 {
            return Some(&[]);
        }
        let byte_len = count * std::mem::size_of::<T>();
        if offset + byte_len > bytes.len() {
            return None;
        }
        let ptr = bytes[offset..].as_ptr() as *const T;
        Some(unsafe { std::slice::from_raw_parts(ptr, count) })
    }

    pub fn rule_count(&self) -> usize {
        self.header.total_rules as usize
    }

    /// Match a live connection context with 0 bytes heap allocation.
    pub fn matches(&self, ctx: &ConnContext) -> bool {
        // 1. Match destination domain
        if let Some(host) = domain_host(ctx) {
            #[allow(clippy::collapsible_if)]
            if self.matches_domain(&host) {
                return true;
            }
        }

        // 2. Match destination IP CIDR
        if let crate::inbound::Target::Ip(addr) = &ctx.destination {
            #[allow(clippy::collapsible_if)]
            if self.matches_ip(addr.ip()) {
                return true;
            }
        }

        // 3. Match destination Port
        let port = ctx.destination.port();
        if port != 0 && self.matches_port(port) {
            return true;
        }

        false
    }

    /// Match exact domain, suffix, or keyword.
    pub fn matches_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();

        // Exact domain binary search O(log N)
        if !self.domains.is_empty() {
            let found = self.domains.binary_search_by(|entry| {
                entry
                    .as_str(self.string_table)
                    .unwrap_or("")
                    .cmp(&domain_lower)
            });
            if found.is_ok() {
                return true;
            }
        }

        // Domain suffix matching by walking label parents
        if !self.suffixes.is_empty() {
            let mut curr = domain_lower.as_str();
            loop {
                let found = self.suffixes.binary_search_by(|entry| {
                    entry.as_str(self.string_table).unwrap_or("").cmp(curr)
                });
                if found.is_ok() {
                    return true;
                }
                if let Some(pos) = curr.find('.') {
                    curr = &curr[pos + 1..];
                } else {
                    break;
                }
            }
        }

        // Keyword search
        if !self.keywords.is_empty() {
            for entry in self.keywords {
                if let Some(kw) = entry.as_str(self.string_table) {
                    #[allow(clippy::collapsible_if)]
                    if domain_lower.contains(kw) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Match IP against IPv4 and IPv6 CIDR tables.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let target = u32::from(v4);
                for entry in self.dest_v4 {
                    let mask = if entry.prefix_len == 0 {
                        0
                    } else {
                        u32::MAX << (32 - entry.prefix_len)
                    };
                    if (target & mask) == entry.addr {
                        return true;
                    }
                }
                false
            }
            IpAddr::V6(v6) => {
                let target = u128::from(v6);
                for entry in self.dest_v6 {
                    let mask = if entry.prefix_len == 0 {
                        0
                    } else {
                        u128::MAX << (128 - entry.prefix_len)
                    };
                    if (target & mask) == entry.addr {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Match destination port against sorted port ranges.
    pub fn matches_port(&self, port: u16) -> bool {
        if self.dest_ports.is_empty() {
            return false;
        }
        // partition_point gives first range where start > port
        let idx = self.dest_ports.partition_point(|range| range.start <= port);
        if idx > 0 && port <= self.dest_ports[idx - 1].end {
            return true;
        }
        false
    }
}
