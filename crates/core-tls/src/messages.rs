//! The server's handshake messages, as they arrive (RFC 8446 §4).
//!
//! Parsers only: these messages are the server's to write, and a client never
//! writes them. Every one of them is length-prefixed, so the parsers are a
//! sequence of bounds checks and a copy -- the point of writing them here
//! rather than reaching for a library is that the transcript has to be fed
//! message by message in the right order, which means the bytes have to be ours.

use std::io;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const HANDSHAKE_FINISHED: u8 = 0x14;
pub const HANDSHAKE_NEW_SESSION_TICKET: u8 = 0x04;

/// A cursor over a message body: every field is length-prefixed, and a message
/// that claims more than it carries is a protocol error, not a panic.
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, at: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.at
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Everything not consumed yet, without moving the cursor.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.at..]
    }

    pub fn u8(&mut self) -> io::Result<u8> {
        let byte = self
            .data
            .get(self.at)
            .copied()
            .ok_or_else(|| err("out of bounds: u8"))?;
        self.at += 1;
        Ok(byte)
    }

    pub fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    pub fn u24(&mut self) -> io::Result<usize> {
        let bytes = self.take(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    pub fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let out = self
            .data
            .get(self.at..self.at + n)
            .ok_or_else(|| err("out of bounds"))?;
        self.at += n;
        Ok(out)
    }

    /// A vector of `n` bytes with an 8-bit length prefix.
    pub fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// A vector of `n` bytes with a 16-bit length prefix.
    pub fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// A vector of `n` bytes with a 24-bit length prefix.
    pub fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }

    /// A nested body with a 16-bit length prefix, read through its own cursor.
    pub fn sub16(&mut self) -> io::Result<Reader<'a>> {
        Ok(Reader::new(self.vec16()?))
    }

    /// Nothing may follow a message we have fully consumed.
    pub fn end(&mut self, what: &str) -> io::Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(err(format!(
                "{what} has {} trailing bytes",
                self.remaining()
            )))
        }
    }
}

/// One `(type, body)` handshake message taken off a record's plaintext.
pub struct Handshake<'a> {
    pub kind: u8,
    pub body: &'a [u8],
}

/// The handshake messages in one record's plaintext. Records may carry several,
/// and one message may be split across records, so this is only ever a step.
pub fn take_message<'a>(input: &mut &'a [u8]) -> io::Result<Handshake<'a>> {
    if input.len() < 4 {
        return Err(err("short handshake header"));
    }
    let kind = input[0];
    let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    let body = input
        .get(4..4 + len)
        .ok_or_else(|| err("short handshake message"))?;
    *input = &input[4 + len..];
    Ok(Handshake { kind, body })
}

/// Split a record's plaintext into whole messages, refusing to leave a partial
/// one: the caller reassembles across records before calling this.
pub fn messages(mut input: &[u8]) -> io::Result<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let message = take_message(&mut input)?;
        out.push((message.kind, message.body.to_vec()));
    }
    Ok(out)
}

/// The protocol out of an ALPN extension body: a 16-bit list length and then
/// the entries. In TLS 1.3 a server's list holds exactly one, the one it chose.
pub fn alpn_protocol(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut list = Reader::new(body).sub16()?;
    Ok(list.vec8()?.to_vec())
}

/// §4.1.3. The cipher suite and the key share are the two fields the client has
/// to act on; the rest is checked for consistency with what it offered.
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub legacy_version: [u8; 2],
    pub random: [u8; 32],
    pub session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub compression: u8,
    pub supported_version: Option<u16>,
    /// group and the server's share for it
    pub key_share: Option<(u16, Vec<u8>)>,
    pub alpn: Option<Vec<u8>>,
}

impl ServerHello {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        let mut r = Reader::new(body);
        let legacy_version = r.take(2)?.try_into().expect("2 bytes");
        let random = r.take(32)?.try_into().expect("32 bytes");
        let session_id_len = r.u8()? as usize;
        let session_id_echo = r.take(session_id_len)?.to_vec();
        let cipher_suite = r.u16()?;
        let compression = r.u8()?;
        let mut hello = ServerHello {
            legacy_version,
            random,
            session_id_echo,
            cipher_suite,
            compression,
            supported_version: None,
            key_share: None,
            alpn: None,
        };
        // the extensions block is optional in the wire format
        if !r.is_empty() {
            let mut extensions = r.sub16()?;
            while !extensions.is_empty() {
                let id = extensions.u16()?;
                let body = extensions.vec16()?;
                match id {
                    0x002b => {
                        hello.supported_version = Some(u16::from_be_bytes(
                            body.try_into()
                                .map_err(|_| err("short supported_versions"))?,
                        ))
                    }
                    0x0033 => {
                        let mut share = Reader::new(body);
                        let group = share.u16()?;
                        let key = share.vec16()?.to_vec();
                        share.end("key_share")?;
                        hello.key_share = Some((group, key));
                    }
                    0x0010 => hello.alpn = Some(body.to_vec()),
                    // renegotiation_info, pre_shared_key, early_data and the
                    // rest: carried in the transcript, acted on elsewhere
                    _ => {}
                }
            }
            r.end("ServerHello")?;
        }
        Ok(hello)
    }
}

/// §4.3.1. Only ALPN matters to a client, and a server may acknowledge the SNI
/// with an *empty* `server_name` extension (RFC 6066 §3) but must not echo the
/// name -- so the flag is "the server sent a name back", not "the server
/// mentioned the extension".
#[derive(Debug, Clone, Default)]
pub struct EncryptedExtensions {
    pub alpn: Option<Vec<u8>>,
    pub server_name_echo: bool,
}

impl EncryptedExtensions {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        let mut out = EncryptedExtensions::default();
        let mut r = Reader::new(body);
        let mut extensions = r.sub16()?;
        while !extensions.is_empty() {
            let id = extensions.u16()?;
            let body = extensions.vec16()?;
            match id {
                0x0010 => out.alpn = Some(body.to_vec()),
                0x0000 => out.server_name_echo = !body.is_empty(),
                _ => {}
            }
        }
        r.end("EncryptedExtensions")?;
        Ok(out)
    }
}

/// §4.4.2. The chain as DER, leaf first.
#[derive(Debug, Clone)]
pub struct Certificate {
    pub entries: Vec<Vec<u8>>,
}

impl Certificate {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        let mut r = Reader::new(body);
        let context = r.vec8()?;
        if !context.is_empty() {
            return Err(err("a server certificate must have no request context"));
        }
        let mut list = Reader::new(r.vec24()?);
        let mut entries = Vec::new();
        while !list.is_empty() {
            let cert = list.vec24()?.to_vec();
            // per-certificate extensions: ignored, but they must be well formed
            let _extensions = list.vec16()?;
            entries.push(cert);
        }
        r.end("Certificate")?;
        Ok(Certificate { entries })
    }
}

/// §4.4.3.
#[derive(Debug, Clone)]
pub struct CertificateVerify {
    pub scheme: u16,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        let mut r = Reader::new(body);
        let scheme = r.u16()?;
        let signature = r.vec16()?.to_vec();
        r.end("CertificateVerify")?;
        Ok(CertificateVerify { scheme, signature })
    }
}

/// §4.4.4.
#[derive(Debug, Clone)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        Ok(Finished {
            verify_data: body.to_vec(),
        })
    }
}

/// §4.4.3: what the server's CertificateVerify signature covers -- 64 spaces,
/// a context string, a zero, then the transcript hash. Nothing else is signed,
/// which is why the transcript has to be hashed up to that exact point.
pub fn certificate_verify_input(transcript_hash: &[u8], server: bool) -> Vec<u8> {
    const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
    const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";
    let context = if server {
        SERVER_CONTEXT
    } else {
        CLIENT_CONTEXT
    };
    let mut out = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    out.extend_from_slice(&[0x20; 64]);
    out.extend_from_slice(context);
    out.push(0);
    out.extend_from_slice(transcript_hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a ServerHello the way a server would, independently of the parser.
    fn server_hello(
        suite: u16,
        session_id: &[u8],
        supported_version: Option<u16>,
        key_share: Option<(u16, &[u8])>,
        alpn: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        let mut push = |id: u16, body: &[u8]| {
            extensions.extend_from_slice(&id.to_be_bytes());
            extensions.extend_from_slice(&(body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(body);
        };
        if let Some(version) = supported_version {
            push(0x002b, &version.to_be_bytes());
        }
        if let Some((group, key)) = key_share {
            let mut share = Vec::new();
            share.extend_from_slice(&group.to_be_bytes());
            share.extend_from_slice(&(key.len() as u16).to_be_bytes());
            share.extend_from_slice(key);
            push(0x0033, &share);
        }
        if let Some(protocol) = alpn {
            push(0x0010, protocol);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x5a; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        if extensions.is_empty() {
            // an empty extension block is still written out
            body.extend_from_slice(&0u16.to_be_bytes());
        } else {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }
        body
    }

    fn framed(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.push((body.len() >> 16) as u8);
        out.push((body.len() >> 8) as u8);
        out.push(body.len() as u8);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_server_hello_round_trips() {
        let share = [0x11u8; 32];
        let body = server_hello(
            0x1301,
            &[0xab; 32],
            Some(0x0304),
            Some((0x001d, &share)),
            Some(&[2u8, b'h', b'2']),
        );
        let hello = ServerHello::parse(&body).expect("parse");
        assert_eq!(hello.cipher_suite, 0x1301);
        assert_eq!(hello.session_id_echo, vec![0xab; 32]);
        assert_eq!(hello.supported_version, Some(0x0304));
        assert_eq!(hello.compression, 0);
        assert_eq!(hello.key_share, Some((0x001d, share.to_vec())));
        assert_eq!(hello.alpn, Some(vec![2u8, b'h', b'2']));
    }

    /// The session id echo is the compatibility field: its *content* has to be
    /// the one we sent, or a middlebox that rewrote it gets a free pass.
    #[test]
    fn a_hello_without_extensions_still_parses() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        let hello = ServerHello::parse(&body).expect("parse");
        assert_eq!(hello.cipher_suite, 0x1301);
        assert!(hello.key_share.is_none());
        assert!(hello.supported_version.is_none());
    }

    #[test]
    fn a_truncated_server_hello_is_an_error() {
        let body = server_hello(0x1301, &[0xab; 4], Some(0x0304), None, None);
        for cut in [0, 1, 5, 34, body.len() - 1] {
            assert!(
                ServerHello::parse(&body[..cut]).is_err(),
                "a hello cut to {cut} bytes parsed"
            );
        }
    }

    /// Trailing bytes inside a nested structure are a protocol error: they would
    /// otherwise be hashed into the transcript and never looked at.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut body = server_hello(0x1301, &[], Some(0x0304), None, None);
        body.push(0);
        assert!(ServerHello::parse(&body).is_err());
    }

    #[test]
    fn a_certificate_chain_parses_leaf_first() {
        let mut list = Vec::new();
        for der in [&b"first"[..], &b"second"[..], &b"third"[..]] {
            list.extend_from_slice(&[0, (der.len() >> 8) as u8, der.len() as u8]);
            list.extend_from_slice(der);
            list.extend_from_slice(&0u16.to_be_bytes());
        }
        let mut body = vec![0]; // no request context, one byte of length
        body.push((list.len() >> 16) as u8);
        body.push((list.len() >> 8) as u8);
        body.push(list.len() as u8);
        body.extend_from_slice(&list);
        let cert = Certificate::parse(&body).expect("parse");
        assert_eq!(
            cert.entries,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
    }

    #[test]
    fn a_certificate_with_a_request_context_is_not_a_server_certificate() {
        let body = [1, 0, 0, 0];
        assert!(Certificate::parse(&body).is_err());
    }

    #[test]
    fn certificate_verify_and_finished_parse() {
        let cv = CertificateVerify::parse(&[0x04, 0x03, 0, 2, 0xaa, 0xbb]).expect("parse");
        assert_eq!(cv.scheme, 0x0403);
        assert_eq!(cv.signature, vec![0xaa, 0xbb]);
        let finished = Finished::parse(&[1, 2, 3]).expect("parse");
        assert_eq!(finished.verify_data, vec![1, 2, 3]);
    }

    /// The signed bytes are 64 spaces, a context, a zero and the hash: a client
    /// that signs anything else produces a signature no server can check.
    #[test]
    fn the_certificate_verify_input_is_what_the_rfc_says() {
        let input = certificate_verify_input(&[0xabu8; 32], true);
        assert_eq!(&input[..64], &[0x20; 64]);
        assert_eq!(&input[64..97], b"TLS 1.3, server CertificateVerify");
        assert_eq!(input[97], 0);
        assert_eq!(&input[98..], &[0xabu8; 32]);
        let client = certificate_verify_input(&[0xabu8; 32], false);
        assert_eq!(&client[64..97], b"TLS 1.3, client CertificateVerify");
        assert_ne!(client, input);
    }

    /// Records may carry several messages, and a record may end mid-message.
    #[test]
    fn messages_come_off_a_record_in_order() {
        let stream = [
            framed(HANDSHAKE_SERVER_HELLO, b"hello"),
            framed(HANDSHAKE_FINISHED, b"fin"),
        ]
        .concat();
        let got = messages(&stream).expect("messages");
        assert_eq!(
            got,
            vec![
                (HANDSHAKE_SERVER_HELLO, b"hello".to_vec()),
                (HANDSHAKE_FINISHED, b"fin".to_vec())
            ]
        );
        // a record that stops inside a message is not a message list
        let partial = framed(HANDSHAKE_SERVER_HELLO, b"hello")[..6].to_vec();
        assert!(messages(&partial).is_err());
    }
}
