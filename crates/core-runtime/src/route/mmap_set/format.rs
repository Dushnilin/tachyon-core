//! Binary format definitions for Tachyon Memory-Mapped Rule-Sets (TSRS)
//! and incremental Delta updates (TDLT).

pub const TSRS_MAGIC: &[u8; 4] = b"TSRS";
pub const TSRS_VERSION: u32 = 1;

pub const TDLT_MAGIC: &[u8; 4] = b"TDLT";
pub const TDLT_VERSION: u32 = 1;

/// Fixed 64-byte file header for .tsrs rule-set files.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub magic: [u8; 4],   // b"TSRS"
    pub version: u32,     // 1
    pub flags: u32,       // flags (bit 0: delta_enabled)
    pub total_rules: u32, // total logical/source rules count

    pub domains_offset: u32, // byte offset to sorted DomainEntry table
    pub domains_count: u32,  // count of exact domain entries

    pub suffixes_offset: u32, // byte offset to sorted SuffixEntry table
    pub suffixes_count: u32,  // count of domain suffix entries

    pub keywords_offset: u32, // byte offset to KeywordEntry table
    pub keywords_count: u32,  // count of keyword entries

    pub dest_v4_offset: u32, // byte offset to sorted Ipv4Entry table
    pub dest_v4_count: u32,  // count of IPv4 CIDR entries

    pub dest_v6_offset: u32, // byte offset to sorted Ipv6Entry table
    pub dest_v6_count: u32,  // count of IPv6 CIDR entries

    pub dest_ports_offset: u32, // byte offset to sorted PortRangeEntry table
    pub dest_ports_count: u32,  // count of port range entries

    pub string_table_offset: u32, // byte offset to contiguous string buffer
    pub string_table_len: u32,    // length of string buffer
}

pub const HEADER_SIZE: usize = std::mem::size_of::<Header>();

impl Header {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        let header: Self = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Header) };
        if &header.magic != TSRS_MAGIC || header.version != TSRS_VERSION {
            return None;
        }
        Some(header)
    }
}

/// 8-byte domain table entry pointing into string table.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainEntry {
    pub offset: u32,
    pub len: u16,
    pub _pad: u16,
}

impl DomainEntry {
    pub fn as_str<'a>(&self, string_table: &'a [u8]) -> Option<&'a str> {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        if end <= string_table.len() {
            std::str::from_utf8(&string_table[start..end]).ok()
        } else {
            None
        }
    }
}

/// 8-byte IPv4 network CIDR (masked address + prefix length).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Entry {
    pub addr: u32, // Host endian, already masked with prefix_len
    pub prefix_len: u8,
    pub _pad: [u8; 3],
}

/// 24-byte IPv6 network CIDR (masked address + prefix length).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Entry {
    pub addr: u128, // Host endian, already masked with prefix_len
    pub prefix_len: u8,
    pub _pad: [u8; 7],
}

/// 4-byte inclusive port range `[start, end]`. Single port has `start == end`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRangeEntry {
    pub start: u16,
    pub end: u16,
}
