//! Every hello we send has to survive the parser a real server uses.
//!
//! rustls and our own reader are forgiving: they read what they know and skip the
//! rest. The uTLS fork a REALITY or uTLS server parses hellos with is not. Two of
//! its rules have bitten us for real:
//!
//! * a **duplicate** extension id is a parse failure outright (`seenExts`), and
//! * every extension it *knows* must be consumed **exactly** — a byte left over
//!   (`if !extData.Empty() { return false }`) fails the whole hello.
//!
//! So this is a mirror of `clientHelloMsg.unmarshal` from the fork
//! (`Leadaxe/utls-lx` `handshake_messages.go`), not of our builder. Every table
//! we ship is run through it, with a real random, a real SNI, real ALPN and real
//! key shares. If a table stops satisfying the server's parser, this is where it
//! says so, before a live server refuses a connection with "error decoding
//! message".

use core_tls::fingerprints;
use core_tls::hello;
use core_tls::keyshare::Shares;

/// The extension ids the fork's client-hello switch knows. Everything else is
/// skipped without a length check, so it cannot fail the parse on its own.
const KNOWN: &[u16] = &[
    0x0000, // server_name
    0x0005, // status_request
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x000d, // signature_algorithms
    0x0010, // ALPN
    0x0012, // signed_certificate_timestamp
    0x0017, // extended_master_secret
    0x0023, // session_ticket
    0x0029, // pre_shared_key
    0x002a, // early_data
    0x002b, // supported_versions
    0x002c, // cookie
    0x002d, // psk_key_exchange_modes
    0x0032, // signature_algorithms_cert
    0x0033, // key_share
    0x0039, // quic_transport_parameters
    0xff01, // renegotiation_info
    0xfe0d, // encrypted_client_hello
];

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }
    fn empty(&self) -> bool {
        self.b.is_empty()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.b.len() < n {
            return Err(format!("wanted {n} bytes, {} left", self.b.len()));
        }
        let (head, tail) = self.b.split_at(n);
        self.b = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    /// u16 length prefix, and the content after it.
    fn u16_prefixed(&mut self) -> Result<Reader<'a>, String> {
        let n = self.u16()? as usize;
        Ok(Reader::new(self.take(n)?))
    }
    /// u8 length prefix, and the content after it.
    fn u8_prefixed(&mut self) -> Result<Reader<'a>, String> {
        let n = self.u8()? as usize;
        Ok(Reader::new(self.take(n)?))
    }
    /// Consume a u16-prefixed list of u16s, and reject an empty one the way the
    /// fork does for curves and signature algorithms.
    fn list_of_u16(&mut self) -> Result<Vec<u16>, String> {
        let mut list = self.u16_prefixed()?;
        if list.empty() {
            return Err("an empty u16 list".into());
        }
        let mut out = Vec::new();
        while !list.empty() {
            out.push(list.u16()?);
        }
        Ok(out)
    }
}

/// The parse, in the fork's order and with the fork's rejections.
fn unmarshal(hello: &[u8]) -> Result<Vec<u16>, String> {
    let mut s = Reader::new(hello);
    s.take(4)?; // type and the uint24 length
    s.u16()?; // legacy_version
    s.take(32)?; // random
    let session_id = s.u8_prefixed()?;
    if session_id.empty() && false {
        // the fork allows a zero-length session id; nothing to check
    }
    s.list_of_u16()?; // cipher_suites
    s.u8_prefixed()?; // compression_methods
    if s.empty() {
        return Ok(Vec::new());
    }
    let mut extensions = s.u16_prefixed()?;
    if !s.empty() {
        return Err("bytes after the extensions block".into());
    }

    let mut seen: Vec<u16> = Vec::new();
    let mut order: Vec<u16> = Vec::new();
    while !extensions.empty() {
        let id = extensions.u16()?;
        let mut data = extensions.u16_prefixed()?;
        if seen.contains(&id) {
            return Err(format!("extension {id:#06x} appears twice"));
        }
        seen.push(id);
        order.push(id);

        match id {
            0x0000 => {
                let mut names = data.u16_prefixed()?;
                if names.empty() {
                    return Err("an empty server_name list".into());
                }
                let mut found = false;
                while !names.empty() {
                    let name_type = names.u8()?;
                    let name = names.u16_prefixed()?;
                    if name.empty() {
                        return Err("an empty server_name".into());
                    }
                    if name_type == 0 {
                        if found {
                            return Err("two host_name entries".into());
                        }
                        found = true;
                    }
                }
            }
            0x0005 => {
                data.u8()?; // status_type
                data.u16_prefixed()?; // responder_id_list
                data.u16_prefixed()?; // request_extensions
            }
            0x000a => {
                data.list_of_u16()?;
            }
            0x000b => {
                if data.u8_prefixed()?.empty() {
                    return Err("no ec_point_formats".into());
                }
            }
            0x000d | 0x0032 => {
                data.list_of_u16()?;
            }
            0x0010 => {
                let mut protos = data.u16_prefixed()?;
                if protos.empty() {
                    return Err("an empty ALPN list".into());
                }
                while !protos.empty() {
                    if protos.u8_prefixed()?.empty() {
                        return Err("an empty ALPN protocol".into());
                    }
                }
            }
            0x0012 | 0x0017 | 0x002a | 0x0023 | 0xff01 => {
                if id == 0xff01 {
                    data.u8_prefixed()?;
                } else if id == 0x0023 {
                    data.take(data.b.len())?; // the whole ticket is read
                }
                // 0x0012, 0x0017 and 0x002a carry nothing and must be empty
            }
            0x002b => {
                let mut vers = data.u8_prefixed()?;
                if vers.empty() {
                    return Err("no supported_versions".into());
                }
                while !vers.empty() {
                    vers.u16()?;
                }
            }
            0x002c => {
                if data.u16_prefixed()?.empty() {
                    return Err("an empty cookie".into());
                }
            }
            0x002d => {
                data.u8_prefixed()?;
            }
            0x0033 => {
                let mut shares = data.u16_prefixed()?;
                while !shares.empty() {
                    shares.u16()?; // group
                    if shares.u16_prefixed()?.empty() {
                        return Err("a key share with no key".into());
                    }
                }
            }
            0x0039 | 0xfe0d => {
                data.take(data.b.len())?;
            }
            0x0029 => return Err("we do not send pre_shared_key".into()),
            _ => {
                // The two lists have to agree. An id in `KNOWN` that fell through
                // to here would be skipped *without* its length checked, which is
                // exactly the bug this file exists to keep out.
                assert!(
                    !KNOWN.contains(&id),
                    "extension {id:#06x} is listed as known but has no parser here"
                );
                continue;
            }
        }
        if !data.empty() {
            return Err(format!(
                "extension {id:#06x} has {} bytes its parser did not read",
                data.b.len()
            ));
        }
    }
    Ok(order)
}

fn build_with(name: &str, alpn: &[&[u8]], sni: &str) -> Vec<u8> {
    let template = fingerprints::by_name(name).expect("a table");
    let key_share = template.extensions.iter().find_map(|e| match e {
        hello::Ext::KeyShare(body) => Some(body.clone()),
        _ => None,
    });
    let shares = key_share.map(|body| Shares::for_body(&body).expect("our keys"));
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).expect("entropy");
    hello::build(&template, &random, &[0x5a; 32], sni, alpn, shares.as_ref())
        .expect("build a hello")
}

fn build(name: &str) -> Vec<u8> {
    build_with(name, &[b"h2", b"http/1.1"], "www.gstatic.com")
}

#[test]
fn every_table_satisfies_a_servers_parser() {
    // three shapes, because they are three real configurations: an ALPN list a
    // caller asked for, no ALPN at all (every vless/trojan node that does not
    // name any), and `disable_sni`
    let shapes: [(&str, &[&[u8]], &str); 3] = [
        ("alpn", &[b"h2", b"http/1.1"], "www.gstatic.com"),
        ("no alpn", &[], "www.gstatic.com"),
        ("no sni", &[b"h2"], ""),
    ];
    let mut bad = Vec::new();
    for name in fingerprints::NAMES {
        assert!(
            fingerprints::by_name(name).is_some(),
            "missing profile {name}"
        );
        for (shape, alpn, sni) in shapes {
            let record = build_with(name, alpn, sni);
            if let Err(why) = unmarshal(&record[5..]) {
                bad.push(format!("{name} ({shape}): {why}"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a server would refuse these hellos:\n  {}",
        bad.join("\n  ")
    );
}

/// The specific case that cost us a live connection: an ALPN extension with an
/// empty protocol list is a parse failure for the server, so a caller that named
/// no protocol must get no extension at all.
#[test]
fn no_alpn_means_no_alpn_extension() {
    let with = build_with("chrome", &[], "example.com");
    let order = unmarshal(&with[5..]).expect("a parseable hello");
    assert!(
        !order.contains(&0x0010),
        "an empty ALPN list went on the wire: {:?}",
        order
    );
    let with = build_with("chrome", &[b"h2"], "example.com");
    assert!(unmarshal(&with[5..]).expect("parseable").contains(&0x0010));
}

#[test]
fn the_parser_mirror_rejects_what_a_server_rejects() {
    // a duplicate extension id: the fork fails the whole hello on it
    let good = build("chrome");
    let body = &good[5..];
    let dupe = {
        // append a second copy of the first extension by rebuilding the block
        let mut s = Reader::new(body);
        s.take(4).unwrap();
        s.u16().unwrap();
        s.take(32).unwrap();
        let sid = s.u8_prefixed().unwrap();
        let sid_len = sid.b.len();
        let suites = s.u16_prefixed().unwrap();
        let suites_len = suites.b.len();
        let comp = s.u8_prefixed().unwrap();
        let comp_len = comp.b.len();
        let mut out = Vec::new();
        out.extend_from_slice(&body[..4 + 2 + 32 + 1 + sid_len + 2 + suites_len + 1 + comp_len]);
        let exts = s.u16_prefixed().unwrap();
        let first = {
            let mut e = Reader::new(exts.b);
            let id = e.u16().unwrap();
            let body = e.u16_prefixed().unwrap();
            let mut raw = Vec::new();
            raw.extend_from_slice(&id.to_be_bytes());
            raw.extend_from_slice(&(body.b.len() as u16).to_be_bytes());
            raw.extend_from_slice(body.b);
            raw
        };
        let mut block = first.clone();
        block.extend_from_slice(exts.b);
        out.extend_from_slice(&(block.len() as u16).to_be_bytes());
        out.extend_from_slice(&block);
        let mut fixed = vec![0x16, 0x03, 0x01];
        fixed.extend_from_slice(&(out.len() as u16).to_be_bytes());
        fixed.extend_from_slice(&out);
        fixed
    };
    assert!(unmarshal(&dupe[5..]).is_err(), "a duplicate must not pass");
    assert!(unmarshal(&good[5..]).is_ok());
}
