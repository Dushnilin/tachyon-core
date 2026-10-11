use std::io;

use crate::keyshare;

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ext {
    Static(u16, Vec<u8>),
    Sni,
    /// The protocol list the caller configured, in the fingerprint's own order.
    Alpn,
    KeyShare(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Template {
    pub record_version: [u8; 2],
    pub client_version: [u8; 2],
    pub cipher_suites: Vec<u8>,
    pub compression: Vec<u8>,
    pub extensions: Vec<Ext>,
}

#[derive(Debug)]
pub struct ParsedHello {
    pub template: Template,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub sni: String,
    pub x25519_public: Option<[u8; 32]>,
}

fn u16_at(b: &[u8], off: usize) -> io::Result<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| err("u16 oob"))
}

fn take<'a>(b: &'a [u8], off: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    let s = b.get(*off..*off + n).ok_or_else(|| err("take oob"))?;
    *off += n;
    Ok(s)
}

pub fn parse_record(data: &[u8]) -> io::Result<ParsedHello> {
    if data.len() < 5 || data[0] != 0x16 {
        return Err(err("not a handshake record"));
    }
    let rec_ver = [data[1], data[2]];
    let rec_len = u16_at(data, 3)? as usize;
    if data.len() < 5 + rec_len {
        return Err(err("short record"));
    }
    let hs = &data[5..5 + rec_len];
    // `16 03 01 00 00` is a whole record with nothing in it; indexing it was
    // a panic, and release builds abort on panic
    if hs.first() != Some(&0x01) {
        return Err(err("not a ClientHello"));
    }
    let mut off = 4;
    let client_version: [u8; 2] = take(hs, &mut off, 2)?.try_into().unwrap();
    let random: [u8; 32] = take(hs, &mut off, 32)?.try_into().unwrap();
    let sid_len = take(hs, &mut off, 1)?[0] as usize;
    let session_id = take(hs, &mut off, sid_len)?.to_vec();
    let cs_len = u16_at(hs, off)? as usize;
    off += 2;
    let cipher_suites = take(hs, &mut off, cs_len)?.to_vec();
    let comp_len = take(hs, &mut off, 1)?[0] as usize;
    let compression = take(hs, &mut off, comp_len)?.to_vec();
    let ext_total = u16_at(hs, off)? as usize;
    off += 2;
    let ext_end = off + ext_total;
    if hs.len() < ext_end {
        return Err(err("short extensions"));
    }
    let mut extensions = Vec::new();
    let mut sni = String::new();
    let mut x25519_public = None;
    while off < ext_end {
        let id = u16_at(hs, off)?;
        off += 2;
        let len = u16_at(hs, off)? as usize;
        off += 2;
        let body = take(hs, &mut off, len)?.to_vec();
        match id {
            0x0000 => {
                sni = parse_sni(&body)?;
                extensions.push(Ext::Sni);
            }
            0x0033 => {
                x25519_public = extract_x25519(&body)?;
                extensions.push(Ext::KeyShare(body));
            }
            _ => extensions.push(Ext::Static(id, body)),
        }
    }
    Ok(ParsedHello {
        template: Template {
            record_version: rec_ver,
            client_version,
            cipher_suites,
            compression,
            extensions,
        },
        random,
        session_id,
        sni,
        x25519_public,
    })
}

fn parse_sni(body: &[u8]) -> io::Result<String> {
    if body.len() < 5 {
        return Err(err("short sni"));
    }
    let list_len = u16_at(body, 0)? as usize;
    if body.len() < 2 + list_len {
        return Err(err("short sni list"));
    }
    if body[2] != 0 {
        return Err(err("sni type not host"));
    }
    let name_len = u16_at(body, 3)? as usize;
    let name = body
        .get(5..5 + name_len)
        .ok_or_else(|| err("short sni name"))?;
    String::from_utf8(name.to_vec()).map_err(|_| err("sni not utf8"))
}

fn extract_x25519(body: &[u8]) -> io::Result<Option<[u8; 32]>> {
    for (group, key) in keyshare::entries(body)? {
        if group == keyshare::X25519 && key.len() == 32 {
            return Ok(Some(key.try_into().expect("32 bytes")));
        }
    }
    Ok(None)
}

pub fn build(
    template: &Template,
    random: &[u8; 32],
    session_id: &[u8],
    sni: &str,
    alpn: &[&[u8]],
    shares: Option<&keyshare::Shares>,
) -> io::Result<Vec<u8>> {
    let mut hs = Vec::new();
    hs.extend_from_slice(&template.client_version);
    hs.extend_from_slice(random);
    if session_id.len() > 32 {
        return Err(err("session_id too long"));
    }
    hs.push(session_id.len() as u8);
    hs.extend_from_slice(session_id);
    hs.extend_from_slice(&(template.cipher_suites.len() as u16).to_be_bytes());
    hs.extend_from_slice(&template.cipher_suites);
    hs.push(template.compression.len() as u8);
    hs.extend_from_slice(&template.compression);

    let mut exts = Vec::new();
    // GREASE ids must not repeat inside one hello. The key share keeps the
    // captured GREASE id (it has to equal supported_groups' -- servers check),
    // so reserve it here before the extension list draws from the pool.
    let mut grease_used = Vec::new();
    for e in &template.extensions {
        if let Ext::Static(0x000a, body) = e {
            for w in body.as_chunks::<2>().0 {
                let v = u16::from_be_bytes([w[0], w[1]]);
                if keyshare::is_grease(v) {
                    grease_used.push(v);
                }
            }
            break;
        }
    }
    for e in &template.extensions {
        let (id, body): (u16, Vec<u8>) = match e {
            // a GREASE extension id is reserved and fresh per handshake, the
            // way BoringSSL draws one
            Ext::Static(id, body) => (
                if keyshare::is_grease(*id) {
                    keyshare::unique_grease(&mut grease_used)
                } else {
                    *id
                },
                body.clone(),
            ),
            // an empty name is `disable_sni`: the extension is left out rather
            // than sent with a zero-length host, which is not the same thing
            Ext::Sni if sni.is_empty() => continue,
            Ext::Sni => (0x0000, build_sni(sni)?),
            Ext::Alpn if alpn.is_empty() => continue,
            Ext::Alpn => (0x0010, build_alpn(alpn)?),
            Ext::KeyShare(raw) => (
                0x0033,
                match shares {
                    Some(s) => s.body(raw)?,
                    None => raw.clone(),
                },
            ),
        };
        exts.extend_from_slice(&id.to_be_bytes());
        exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&body);
    }
    hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs.extend_from_slice(&exts);

    let mut handshake = Vec::with_capacity(4 + hs.len());
    handshake.push(0x01);
    handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hs);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16);
    record.extend_from_slice(&template.record_version);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}

fn build_sni(name: &str) -> io::Result<Vec<u8>> {
    let n = name.as_bytes();
    if n.len() > u16::MAX as usize {
        return Err(err("sni too long"));
    }
    let mut b = Vec::with_capacity(5 + n.len());
    b.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
    b.push(0x00);
    b.extend_from_slice(&(n.len() as u16).to_be_bytes());
    b.extend_from_slice(n);
    Ok(b)
}

/// The ALPN extension body: a 16-bit list length and then the protocols, in
/// the order the caller configured. The extension's own length is the framing
/// the builder writes around this.
fn build_alpn(alpn: &[&[u8]]) -> io::Result<Vec<u8>> {
    let total: usize = alpn.iter().map(|p| p.len() + 1).sum();
    if total > u16::MAX as usize {
        return Err(err("alpn list too long"));
    }
    let mut b = Vec::with_capacity(2 + total);
    b.extend_from_slice(&(total as u16).to_be_bytes());
    for protocol in alpn {
        if protocol.len() > u8::MAX as usize || protocol.is_empty() {
            return Err(err("alpn protocol must be 1..=255 bytes"));
        }
        b.push(protocol.len() as u8);
        b.extend_from_slice(protocol);
    }
    Ok(b)
}

pub fn key_share_group(body: &[u8]) -> io::Result<Vec<u16>> {
    Ok(keyshare::entries(body)?
        .into_iter()
        .map(|(group, _)| group)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sniffers hand this parser whatever a client sent. It may refuse,
    /// it may not panic: release builds abort on panic.
    #[test]
    fn no_input_makes_the_parser_panic() {
        assert!(parse_record(&[0x16, 0x03, 0x01, 0x00, 0x00]).is_err());
        let mut sni = vec![0x00, 0x00];
        let body = build_sni("example.com").unwrap();
        sni.extend_from_slice(&(body.len() as u16).to_be_bytes());
        sni.extend_from_slice(&body);
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[7; 32]);
        hs.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        hs.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hs.extend_from_slice(&sni);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((hs.len() + 4) as u16).to_be_bytes());
        record.push(0x01);
        record.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&hs);
        assert_eq!(parse_record(&record).unwrap().sni, "example.com");
        for len in 0..record.len() {
            let _ = parse_record(&record[..len]);
        }
        for at in 0..record.len() {
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                let mut bent = record.clone();
                bent[at] = value;
                let _ = parse_record(&bent);
            }
        }
    }
}
