use std::io;

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ext {
    Static(u16, Vec<u8>),
    Sni,
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
    if hs[0] != 0x01 {
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
    if body.len() < 2 {
        return Err(err("short key_share"));
    }
    let shares_len = u16_at(body, 0)? as usize;
    let mut off = 2;
    let end = 2 + shares_len;
    if body.len() < end {
        return Err(err("short key_share list"));
    }
    while off + 4 <= end {
        let group = u16_at(body, off)?;
        let key_len = u16_at(body, off + 2)? as usize;
        off += 4;
        let key = body
            .get(off..off + key_len)
            .ok_or_else(|| err("short key"))?;
        off += key_len;
        if group == 0x001d && key_len == 32 {
            return Ok(Some(key.try_into().unwrap()));
        }
    }
    Ok(None)
}

pub fn build(
    template: &Template,
    random: &[u8; 32],
    session_id: &[u8],
    sni: &str,
    key_share_override: Option<&[u8; 32]>,
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
    for e in &template.extensions {
        let (id, body): (u16, Vec<u8>) = match e {
            Ext::Static(id, body) => (*id, body.clone()),
            Ext::Sni => (0x0000, build_sni(sni)?),
            Ext::KeyShare(raw) => (
                0x0033,
                match key_share_override {
                    Some(k) => build_key_share(k)?,
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

fn build_key_share(public: &[u8; 32]) -> io::Result<Vec<u8>> {
    let mut b = Vec::with_capacity(38);
    b.extend_from_slice(&(36u16).to_be_bytes());
    b.extend_from_slice(&(0x001du16).to_be_bytes());
    b.extend_from_slice(&(32u16).to_be_bytes());
    b.extend_from_slice(public);
    Ok(b)
}

pub fn key_share_group(body: &[u8]) -> io::Result<Vec<u16>> {
    if body.len() < 2 {
        return Err(err("short key_share"));
    }
    let shares_len = u16_at(body, 0)? as usize;
    let mut off = 2;
    let end = 2 + shares_len;
    let mut groups = Vec::new();
    while off + 4 <= end && off + 4 <= body.len() {
        let group = u16_at(body, off)?;
        let key_len = u16_at(body, off + 2)? as usize;
        off += 4 + key_len;
        groups.push(group);
    }
    Ok(groups)
}
