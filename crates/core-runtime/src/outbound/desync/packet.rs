//! Zero-copy protocol inspection and TLS/HTTP mutation for DPI desynchronization.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniMatch<'a> {
    pub host: &'a str,
    pub sni_ext_offset: usize,
    pub host_offset: usize,
    pub host_len: usize,
    pub midsld_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMatch<'a> {
    pub host: &'a str,
    pub host_offset: usize,
    pub host_len: usize,
    pub midsld_offset: usize,
}

/// Detect if `buf` starts with a TLS Handshake record containing a ClientHello.
#[inline]
pub fn is_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 9
        && buf[0] == 0x16 // Handshake
        && buf[1] == 0x03 // Major version 3 (SSLv3 / TLS 1.x)
        && buf[5] == 0x01 // ClientHello
}

/// Parse TLS ClientHello without allocating and locate SNI offsets.
pub fn find_sni(buf: &[u8]) -> Option<SniMatch<'_>> {
    if !is_tls_client_hello(buf) {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        // Incomplete record, but we can still parse if we have at least the headers
        if buf.len() < 43 {
            return None;
        }
    }

    // Skip ClientHello header:
    // 5 bytes TLS record header
    // 4 bytes Handshake header (type + 3-byte len)
    // 2 bytes client_version
    // 32 bytes random
    let mut pos = 5 + 4 + 2 + 32;
    if pos >= buf.len() {
        return None;
    }

    // Session ID
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > buf.len() {
        return None;
    }

    // Cipher Suites
    let cipher_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos + 1 > buf.len() {
        return None;
    }

    // Compression Methods
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        return None;
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(buf.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let ext_data = pos + 4;
        let next_ext = ext_data + ext_len;

        if ext_type == 0x0000 {
            // Server Name Indication (RFC 6066)
            let sni_ext_offset = pos;
            if ext_data + 2 <= buf.len() {
                let list_len = u16::from_be_bytes([buf[ext_data], buf[ext_data + 1]]) as usize;
                let mut name_pos = ext_data + 2;
                let list_end = (name_pos + list_len).min(buf.len());

                while name_pos + 3 <= list_end {
                    let name_type = buf[name_pos];
                    let name_len =
                        u16::from_be_bytes([buf[name_pos + 1], buf[name_pos + 2]]) as usize;
                    let host_offset = name_pos + 3;

                    if name_type == 0 && host_offset + name_len <= buf.len() {
                        let host_bytes = &buf[host_offset..host_offset + name_len];
                        if let Ok(host) = std::str::from_utf8(host_bytes) {
                            let midsld_rel = calculate_midsld(host);
                            let midsld_offset = host_offset + midsld_rel;
                            return Some(SniMatch {
                                host,
                                sni_ext_offset,
                                host_offset,
                                host_len: name_len,
                                midsld_offset,
                            });
                        }
                    }
                    name_pos = host_offset + name_len;
                }
            }
            return None;
        }

        pos = next_ext;
    }

    None
}

/// Calculate the offset of the middle of the second-level domain (SLD) within a hostname.
/// e.g. "rr1---sn-ab5sznzl.googlevideo.com" -> SLD is "googlevideo", split in the middle.
/// Pure stack-based scanning with zero heap allocations.
pub fn calculate_midsld(host: &str) -> usize {
    let bytes = host.as_bytes();
    let mut dot_indices = [0usize; 4];
    let mut dot_count = 0;

    for (i, &b) in bytes.iter().enumerate().rev() {
        if b == b'.' {
            dot_indices[dot_count] = i;
            dot_count += 1;
            if dot_count == 4 {
                break;
            }
        }
    }

    if dot_count == 0 {
        return host.len() / 2;
    }

    let last_dot = dot_indices[0];
    let tld = &host[last_dot + 1..];

    let (sld_start, sld_end) = if dot_count >= 2 {
        let second_dot = dot_indices[1];
        let maybe_second_tld = &host[second_dot + 1..last_dot];
        if dot_count >= 3 && is_common_second_level_tld(tld, maybe_second_tld) {
            let third_dot = dot_indices[2];
            (third_dot + 1, second_dot)
        } else {
            (second_dot + 1, last_dot)
        }
    } else {
        (0, last_dot)
    };

    let sld_len = sld_end.saturating_sub(sld_start);
    let sld_half = (sld_len / 2).max(1);
    sld_start + sld_half
}

#[inline]
fn is_common_second_level_tld(tld: &str, sld: &str) -> bool {
    (sld.eq_ignore_ascii_case("co") && tld.eq_ignore_ascii_case("uk"))
        || (sld.eq_ignore_ascii_case("com") && tld.eq_ignore_ascii_case("ru"))
        || (sld.eq_ignore_ascii_case("net") && tld.eq_ignore_ascii_case("ru"))
        || (sld.eq_ignore_ascii_case("org") && tld.eq_ignore_ascii_case("ru"))
        || (sld.eq_ignore_ascii_case("co") && tld.eq_ignore_ascii_case("jp"))
        || (sld.eq_ignore_ascii_case("com") && tld.eq_ignore_ascii_case("br"))
        || (sld.eq_ignore_ascii_case("com") && tld.eq_ignore_ascii_case("au"))
}

/// Check if `buf` starts with standard HTTP request method.
pub fn is_http_request(buf: &[u8]) -> bool {
    buf.starts_with(b"GET ")
        || buf.starts_with(b"POST ")
        || buf.starts_with(b"HEAD ")
        || buf.starts_with(b"PUT ")
        || buf.starts_with(b"DELETE ")
        || buf.starts_with(b"OPTIONS ")
        || buf.starts_with(b"CONNECT ")
}

/// Parse HTTP Host header from request with zero allocations.
pub fn find_http_host(buf: &[u8]) -> Option<HttpMatch<'_>> {
    if !is_http_request(buf) {
        return None;
    }

    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n") {
        if line.is_empty() {
            break;
        }
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case("host:") {
            let host_val = line[5..].trim();
            let host_only = host_val.split(':').next().unwrap_or(host_val);
            let host_offset = match text.find(host_val) {
                Some(off) => off,
                None => continue,
            };
            let midsld_rel = calculate_midsld(host_only);
            let midsld_offset = host_offset + midsld_rel;
            return Some(HttpMatch {
                host: host_only,
                host_offset,
                host_len: host_only.len(),
                midsld_offset,
            });
        }
    }

    None
}

/// Helper to compute midsld offset or fall back to half buffer length.
pub fn compute_midsld_or_fallback(buf: &[u8]) -> usize {
    if let Some(m) = find_sni(buf) {
        m.midsld_offset
    } else if let Some(m) = find_http_host(buf) {
        m.midsld_offset
    } else {
        (buf.len() / 2).max(1)
    }
}

/// Split a single TLS record into two RFC-compliant TLS records.
/// Record 1 contains bytes [0..split_pos] of the handshake payload.
/// Record 2 contains the remaining bytes.
pub fn split_tls_record(buf: &[u8], split_pos: usize) -> Option<Vec<u8>> {
    if !is_tls_client_hello(buf) {
        return None;
    }

    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let hs_payload = &buf[5..5 + rec_len.min(buf.len() - 5)];

    if split_pos == 0 || split_pos >= hs_payload.len() {
        return None;
    }

    let (part1, part2) = hs_payload.split_at(split_pos);
    let mut out = Vec::with_capacity(buf.len() + 5);

    // Record 1
    out.push(0x16);
    out.push(buf[1]);
    out.push(buf[2]);
    let len1 = part1.len() as u16;
    out.extend_from_slice(&len1.to_be_bytes());
    out.extend_from_slice(part1);

    // Record 2
    out.push(0x16);
    out.push(buf[1]);
    out.push(buf[2]);
    let len2 = part2.len() as u16;
    out.extend_from_slice(&len2.to_be_bytes());
    out.extend_from_slice(part2);

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_midsld() {
        assert_eq!(calculate_midsld("youtube.com"), 3); // "you|tube.com" -> sld "youtube" (len 7, half 3)
        assert_eq!(calculate_midsld("googlevideo.com"), 5); // "googl|evideo.com" -> sld "googlevideo" (len 11, half 5)
        let host = "rr1---sn-h0je7nel.googlevideo.com";
        let off = calculate_midsld(host);
        assert_eq!(&host[off..off + 5], "evide");
    }

    #[test]
    fn test_http_host_detection() {
        let req = b"GET / HTTP/1.1\r\nHost: rutracker.org\r\nUser-Agent: curl/8.0\r\n\r\n";
        let m = find_http_host(req).expect("host match");
        assert_eq!(m.host, "rutracker.org");
        assert!(m.midsld_offset > m.host_offset);
    }
}
