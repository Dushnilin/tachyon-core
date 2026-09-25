//! Go `net/netip` parse-error emulation for config parity.
//!
//! Ports `ParseAddr`/`ParsePrefix` (go1.26) including their exact error texts:
//! `netip.ParsePrefix("x/32"): ParseAddr("x"): unable to parse IP`, etc.

#[derive(Clone, Debug)]
pub struct ParsedAddr {
    pub is_v6: bool,
    pub zone: String,
}

fn go_quote(s: &str) -> String {
    format!("{s:?}")
}

fn addr_err(in_: &str, msg: &str, at: Option<&str>) -> String {
    match at {
        Some(at) if !at.is_empty() => format!(
            "ParseAddr({}): {} (at {})",
            go_quote(in_),
            msg,
            go_quote(at)
        ),
        _ => format!("ParseAddr({}): {}", go_quote(in_), msg),
    }
}

pub fn parse_addr(s: &str) -> Result<ParsedAddr, String> {
    for c in s.bytes() {
        match c {
            b'.' => return parse_ipv4(s),
            b':' => return parse_ipv6(s),
            b'%' => return Err(addr_err(s, "missing IPv6 address", None)),
            _ => {}
        }
    }
    Err(addr_err(s, "unable to parse IP", None))
}

fn parse_ipv4(s: &str) -> Result<ParsedAddr, String> {
    parse_ipv4_fields(s, s).map(|_| ParsedAddr {
        is_v6: false,
        zone: String::new(),
    })
}

fn parse_ipv4_fields(full: &str, sub: &str) -> Result<[u8; 4], String> {
    let b = sub.as_bytes();
    let mut val: i64 = 0;
    let mut pos = 0usize;
    let mut dig_len = 0usize;
    let mut fields = [0u8; 4];
    for i in 0..b.len() {
        let c = b[i];
        if c.is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(addr_err(
                    full,
                    "IPv4 field has octet with leading zero",
                    None,
                ));
            }
            val = val * 10 + i64::from(c - b'0');
            dig_len += 1;
            if val > 255 {
                return Err(addr_err(full, "IPv4 field has value >255", None));
            }
        } else if c == b'.' {
            if i == 0 || i == b.len() - 1 || b[i - 1] == b'.' {
                return Err(addr_err(
                    full,
                    "IPv4 field must have at least one digit",
                    Some(&sub[i..]),
                ));
            }
            if pos == 3 {
                return Err(addr_err(full, "IPv4 address too long", None));
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(addr_err(full, "unexpected character", Some(&sub[i..])));
        }
    }
    if pos < 3 {
        return Err(addr_err(full, "IPv4 address too short", None));
    }
    fields[3] = val as u8;
    Ok(fields)
}

fn parse_ipv6(in_: &str) -> Result<ParsedAddr, String> {
    let mut s: &str = in_;
    let mut zone = "";
    if let Some(i) = s.find('%') {
        zone = &s[i + 1..];
        s = &s[..i];
        if zone.is_empty() {
            return Err(addr_err(in_, "zone must be a non-empty string", None));
        }
    }

    let mut ip = [0u8; 16];
    let mut ellipsis: i32 = -1;

    if s.len() >= 2 && s.as_bytes()[0] == b':' && s.as_bytes()[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(ParsedAddr {
                is_v6: true,
                zone: zone.to_string(),
            });
        }
    }

    let mut i = 0usize;
    'outer: while i < 16 {
        let b = s.as_bytes();
        let mut off = 0usize;
        let mut acc: u32 = 0;
        while off < b.len() {
            let c = b[off];
            let d = if c.is_ascii_digit() {
                u32::from(c - b'0')
            } else if (b'a'..=b'f').contains(&c) {
                u32::from(c - b'a' + 10)
            } else if (b'A'..=b'F').contains(&c) {
                u32::from(c - b'A' + 10)
            } else {
                break;
            };
            acc = (acc << 4) + d;
            off += 1;
            if off > 4 {
                return Err(addr_err(
                    in_,
                    "each group must have 4 or less digits",
                    Some(s),
                ));
            }
            if acc > u16::MAX as u32 {
                return Err(addr_err(in_, "IPv6 field has value >=2^16", Some(s)));
            }
        }
        if off == 0 {
            return Err(addr_err(
                in_,
                "each colon-separated field must have at least one digit",
                Some(s),
            ));
        }

        if off < b.len() && b[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return Err(addr_err(
                    in_,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    Some(s),
                ));
            }
            if i + 4 > 16 {
                return Err(addr_err(
                    in_,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    Some(s),
                ));
            }
            let mut end = in_.len();
            if !zone.is_empty() {
                end -= zone.len() + 1;
            }
            let v4sub = &in_[end - s.len()..end];
            let f = parse_ipv4_fields(in_, v4sub)?;
            ip[i..i + 4].copy_from_slice(&f);
            i += 4;
            s = "";
            break 'outer;
        }

        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;

        s = &s[off..];
        if s.is_empty() {
            break;
        }

        if s.as_bytes()[0] != b':' {
            return Err(addr_err(in_, "unexpected character, want colon", Some(s)));
        }
        if s.len() == 1 {
            return Err(addr_err(
                in_,
                "colon must be followed by more characters",
                Some(s),
            ));
        }
        s = &s[1..];

        if s.as_bytes()[0] == b':' {
            if ellipsis >= 0 {
                return Err(addr_err(in_, "multiple :: in address", Some(s)));
            }
            ellipsis = i as i32;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }

    if !s.is_empty() {
        return Err(addr_err(in_, "trailing garbage after address", Some(s)));
    }

    if i < 16 {
        if ellipsis < 0 {
            return Err(addr_err(in_, "address string too short", None));
        }
        let ellipsis = ellipsis as usize;
        let n = 16 - i;
        if ellipsis < i {
            let mut j = i - 1;
            loop {
                ip[j + n] = ip[j];
                if j == ellipsis {
                    break;
                }
                j -= 1;
            }
        }
        ip[ellipsis..ellipsis + n].fill(0);
    } else if ellipsis >= 0 {
        return Err(addr_err(
            in_,
            "the :: must expand to at least one field of zeros",
            None,
        ));
    }

    Ok(ParsedAddr {
        is_v6: true,
        zone: zone.to_string(),
    })
}

fn prefix_err(s: &str, msg: String) -> String {
    format!("netip.ParsePrefix({}): {}", go_quote(s), msg)
}

/// Port of Go `netip.ParsePrefix`: validates a CIDR string, returning the exact
/// Go error text on failure. On success returns the parsed address.
pub fn parse_prefix(s: &str) -> Result<ParsedAddr, String> {
    let Some(i) = s.rfind('/') else {
        return Err(prefix_err(s, "no '/'".to_string()));
    };
    let addr = &s[..i];
    let ip = parse_addr(addr).map_err(|e| prefix_err(s, e))?;
    if ip.is_v6 && !ip.zone.is_empty() {
        return Err(prefix_err(
            s,
            "IPv6 zones cannot be present in a prefix".to_string(),
        ));
    }
    let bits_str = &s[i + 1..];
    let b = bits_str.as_bytes();
    if b.len() > 1 && !matches!(b[0], b'1'..=b'9') {
        return Err(prefix_err(
            s,
            format!("bad bits after slash: {}", go_quote(bits_str)),
        ));
    }
    let bits: i64 = match bits_str.parse::<i64>() {
        Ok(v) => v,
        Err(_) => {
            return Err(prefix_err(
                s,
                format!("bad bits after slash: {}", go_quote(bits_str)),
            ));
        }
    };
    let max_bits: i64 = if ip.is_v6 { 128 } else { 32 };
    if bits < 0 || bits > max_bits {
        return Err(prefix_err(s, "prefix length out of range".to_string()));
    }
    Ok(ip)
}

/// Masque `ip`/`ipv6` prefix check: appends `/32` (ip) or `/128` (ipv6) when
/// the value has no slash, then validates with Go `netip.ParsePrefix` semantics.
pub fn check_masque_prefix(v: &str, is_v6_field: bool) -> Result<(), String> {
    let full = if v.contains('/') {
        v.to_string()
    } else if is_v6_field {
        format!("{v}/128")
    } else {
        format!("{v}/32")
    };
    parse_prefix(&full).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_valid() {
        assert!(parse_prefix("172.16.0.2/32").is_ok());
        assert!(parse_prefix("1::/128").is_ok());
        assert!(parse_prefix("::/0").is_ok());
        assert!(parse_prefix("2606:4700:110:1234::/64").is_ok());
        assert!(parse_prefix("fd00::/8").is_ok());
        assert!(parse_prefix("1:2:3:4:5:6:7:8/128").is_ok());
        assert!(parse_prefix("fe80::1/64").is_ok());
    }

    #[test]
    fn prefix_errors() {
        assert_eq!(
            parse_prefix("fe80::1%eth0/64").unwrap_err(),
            r#"netip.ParsePrefix("fe80::1%eth0/64"): IPv6 zones cannot be present in a prefix"#
        );
        assert_eq!(
            parse_prefix("12345::1/128").unwrap_err(),
            r#"netip.ParsePrefix("12345::1/128"): ParseAddr("12345::1"): each group must have 4 or less digits (at "12345::1")"#
        );
        assert_eq!(
            parse_prefix("2606:4700:110:::1/48").unwrap_err(),
            r#"netip.ParsePrefix("2606:4700:110:::1/48"): ParseAddr("2606:4700:110:::1"): each colon-separated field must have at least one digit (at ":1")"#
        );
        assert_eq!(
            parse_prefix("10.0.0.256/32").unwrap_err(),
            r#"netip.ParsePrefix("10.0.0.256/32"): ParseAddr("10.0.0.256"): IPv4 field has value >255"#
        );
        assert_eq!(
            parse_prefix("10.0.0/24").unwrap_err(),
            r#"netip.ParsePrefix("10.0.0/24"): ParseAddr("10.0.0"): IPv4 address too short"#
        );
        assert_eq!(
            parse_prefix("bogus").unwrap_err(),
            r#"netip.ParsePrefix("bogus"): no '/'"#
        );
    }

    #[test]
    fn addr_zone_ok() {
        let a = parse_addr("fe80::1%eth0").unwrap();
        assert!(a.is_v6);
        assert_eq!(a.zone, "eth0");
    }

    #[test]
    fn ellipsis_suffix_no_panic() {
        // regression: `::` at end left ellipsis == i and underflowed the shift loop
        assert!(parse_prefix("1::/128").is_ok());
        assert!(parse_prefix("::/0").is_ok());
        assert!(parse_prefix("fd00::/8").is_ok());
        assert!(parse_prefix("1:2:3::/64").is_ok());
        assert!(parse_prefix("::1/128").is_ok());
    }
}
