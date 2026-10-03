//! The server half of a TLS 1.3 handshake (RFC 8446 §4.1), over any transport.
//!
//! The mirror of [`crate::client`]: a ClientHello in, a ServerHello and a
//! sealed flight out, then the client's Finished. No resumption, no
//! HelloRetryRequest, no client certificates -- the cases a proxy's inbound
//! actually meets.
//!
//! Every message joins the transcript as it is *processed*, never as it is
//! built, for the same reason the client is written that way: the transcript
//! hash is what CertificateVerify and Finished are computed over.

use std::sync::Arc;

use rustls::sign::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::Stream;
use crate::keyshare::{Shares, X25519};
use crate::messages;
use crate::record::{self, ContentType, Opener, Sealer};
use crate::tls13::{Hash, KeySchedule};

fn bad(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

fn entropy(into: &mut [u8]) -> std::io::Result<()> {
    getrandom::fill(into).map_err(|e| bad(format!("no entropy: {e}")))
}

/// What the caller configures. A server with no certificate cannot be built,
/// which is the same rule the client half keeps about trust.
pub struct Config {
    /// the chain to send, leaf first, DER
    pub chain: Vec<Vec<u8>>,
    /// the key the leaf belongs to
    pub key: Arc<dyn SigningKey>,
    /// protocols to pick from, in the order of preference; empty means none
    pub alpn: Vec<Vec<u8>>,
}

/// One handshake. [`Handshake::run`] is the whole thing.
pub struct Handshake {
    config: Config,
    shares: Shares,
    suite: u16,
    hash: Hash,
    key_len: usize,
    schedule: KeySchedule,
    /// the handshake messages in order, without their record headers
    transcript: Vec<u8>,
    /// plaintext of records already decrypted, not yet a whole message
    pending: Vec<u8>,
    /// the handshake keys, in both directions
    sealer: Option<Sealer>,
    opener: Option<Opener>,
    /// the protocol the client offered and we picked, if any
    pub alpn: Option<Vec<u8>>,
    /// the application keys, once the client's Finished is in
    pub application: Option<(Sealer, Opener)>,
}

impl Handshake {
    pub fn new(config: Config) -> std::io::Result<Self> {
        if config.chain.is_empty() {
            return Err(bad("a server needs a certificate chain"));
        }
        // The share is generated the same way the client's is: a key_share body
        // naming the groups we serve, with the captured bytes left as noise.
        let mut body = Vec::with_capacity(8);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&X25519.to_be_bytes());
        body.extend_from_slice(&32u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        Ok(Handshake {
            shares: Shares::for_body(&body)?,
            config,
            suite: 0x1301,
            hash: Hash::Sha256,
            key_len: 16,
            schedule: KeySchedule::new(Hash::Sha256, &[]),
            transcript: Vec::new(),
            pending: Vec::new(),
            sealer: None,
            opener: None,
            alpn: None,
            application: None,
        })
    }

    /// The whole handshake: read the hello, answer it, take the client's
    /// Finished, and leave the application keys ready.
    pub async fn run(&mut self, stream: &mut (dyn Stream + '_)) -> std::io::Result<()> {
        self.read_hello(stream).await?;
        self.write_flight(stream).await?;
        self.read_client_finished(stream).await
    }

    fn transcript_hash(&self) -> Vec<u8> {
        self.hash.digest(&self.transcript)
    }

    fn record(&mut self, kind: u8, body: &[u8]) {
        self.transcript.push(kind);
        self.transcript
            .extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        self.transcript.extend_from_slice(body);
    }

    /// The ClientHello: its suites, its key share, its session id, its ALPN.
    async fn read_hello(&mut self, stream: &mut (dyn Stream + '_)) -> std::io::Result<()> {
        let raw = read_record(stream).await?;
        if raw[0] != ContentType::Handshake as u8 {
            return Err(bad("the first record from the client is not a handshake"));
        }
        // the hello parser already reads the session id and the share out of the
        // record, which is the same walk this state machine would do by hand
        let parsed = crate::hello::parse_record(&raw)?;
        let framed = raw[5..].to_vec();
        // the transcript starts with the hello exactly as it arrived
        self.transcript = framed.clone();
        let message = messages::take_message(&mut { framed.as_slice() })?;
        let kind = message.kind;

        if kind != messages::HANDSHAKE_CLIENT_HELLO {
            return Err(bad("the first message is not a ClientHello"));
        }
        let hello = ClientHello::parse(message.body)?;

        // supported_versions: TLS 1.3 is the only thing here
        let versions = hello
            .extension(0x002b)
            .ok_or_else(|| bad("the client offered no supported_versions"))?;
        if !versions.windows(2).any(|pair| pair == [0x03, 0x04]) {
            return Err(bad("the client does not speak TLS 1.3"));
        }

        // cipher suites, in our order of preference
        self.suite = *hello
            .suites
            .iter()
            .find(|id| [0x1301u16, 0x1303, 0x1302].contains(id))
            .ok_or_else(|| bad("the client offered no cipher suite we serve"))?;
        let (hash, key_len) = match self.suite {
            0x1302 => (Hash::Sha384, 32),
            _ => (Hash::Sha256, 16),
        };
        self.hash = hash;
        self.key_len = key_len;

        // key share: X25519 only, which is all a proxy inbound needs
        let peer = parsed
            .x25519_public
            .ok_or_else(|| bad("the client sent no X25519 key share"))?;
        let secret = self.shares.complete(X25519, &peer)?;

        // ALPN: our order decides, and only if the client asked
        let offered = alpn_list(hello.extension(0x0010).unwrap_or_default());
        if let Some(ours) = self
            .config
            .alpn
            .iter()
            .find(|ours| offered.iter().any(|theirs| theirs == *ours))
        {
            self.alpn = Some(ours.clone());
        }

        // ServerHello, then the keys it implies
        let mut random = [0u8; 32];
        entropy(&mut random)?;
        let our_share = self
            .shares
            .public(X25519)
            .ok_or_else(|| bad("no share of our own for the group we serve"))?
            .to_vec();
        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x002b, &[0x03, 0x04]);
        let mut share = Vec::with_capacity(38);
        share.extend_from_slice(&X25519.to_be_bytes());
        share.extend_from_slice(&32u16.to_be_bytes());
        share.extend_from_slice(&our_share);
        push_extension(&mut extensions, 0x0033, &share);

        let mut server_hello = Vec::with_capacity(64 + hello.session_id.len());
        server_hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        server_hello.extend_from_slice(&random);
        server_hello.push(hello.session_id.len() as u8);
        server_hello.extend_from_slice(&hello.session_id);
        server_hello.extend_from_slice(&self.suite.to_be_bytes());
        server_hello.push(0x00); // no compression
        server_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        server_hello.extend_from_slice(&extensions);
        self.record(messages::HANDSHAKE_SERVER_HELLO, &server_hello);

        self.schedule
            .enter_handshake(&secret, &self.transcript_hash());
        let client = KeySchedule::traffic_keys(
            &self.schedule.client_handshake_traffic(),
            self.hash,
            self.key_len,
            12,
        );
        let server = KeySchedule::traffic_keys(
            &self.schedule.server_handshake_traffic(),
            self.hash,
            self.key_len,
            12,
        );
        self.opener = Some(Opener::new(self.suite_id(), client));
        self.sealer = Some(Sealer::new(self.suite_id(), server));

        // The hello goes out in the clear, and so does the compatibility
        // ChangeCipherSpec every client is told to ignore. The message header
        // goes inside the record, which is why it is framed here. The ServerHello
        // record carries 0x0303 -- the one TLS 1.3 message that is not in the
        // clear has to look like the version it is, and so does the CCS: Go's
        // crypto/tls (sing-box) rejects a 0x0301 record once 1.2 is in play.
        let mut framed_hello = vec![messages::HANDSHAKE_SERVER_HELLO];
        framed_hello.extend_from_slice(&(server_hello.len() as u32).to_be_bytes()[1..]);
        framed_hello.extend_from_slice(&server_hello);
        stream
            .write_all(&record::plaintext_record(
                ContentType::Handshake,
                &framed_hello,
                record::VERSION_1_3,
            )?)
            .await?;
        stream
            .write_all(&record::plaintext_record(
                ContentType::ChangeCipherSpec,
                &[0x01],
                record::VERSION_1_3,
            )?)
            .await?;
        stream.flush().await
    }

    fn suite_id(&self) -> rustls::CipherSuite {
        match self.suite {
            0x1302 => rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            0x1303 => rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            _ => rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        }
    }

    /// EncryptedExtensions, Certificate, CertificateVerify, Finished, sealed
    /// under the server's handshake keys.
    async fn write_flight(&mut self, stream: &mut (dyn Stream + '_)) -> std::io::Result<()> {
        // EncryptedExtensions: the ALPN we picked, if we picked one
        let mut extensions = Vec::new();
        if let Some(alpn) = self.alpn.clone() {
            let mut body = Vec::with_capacity(3 + alpn.len());
            // the list length covers each name plus its one-byte prefix, and
            // getting that wrong is a truncated extension rather than a
            // rejected protocol
            body.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
            body.push(alpn.len() as u8);
            body.extend_from_slice(&alpn);
            push_extension(&mut extensions, 0x0010, &body);
        }
        // the message body is the extensions vector *with its length prefix*, even
        // when it is empty: a body of zero bytes leaves the peer reading a u16
        // that is not there, which is a decode_error and nothing more useful
        let mut encrypted_extensions = (extensions.len() as u16).to_be_bytes().to_vec();
        encrypted_extensions.extend_from_slice(&extensions);
        self.record(
            messages::HANDSHAKE_ENCRYPTED_EXTENSIONS,
            &encrypted_extensions,
        );

        // Certificate: an empty request context, then the chain
        let mut chain = Vec::new();
        for der in &self.config.chain {
            chain.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
            chain.extend_from_slice(der);
            chain.extend_from_slice(&0u16.to_be_bytes());
        }
        let mut certificate = vec![0x00];
        certificate.extend_from_slice(&(chain.len() as u32).to_be_bytes()[1..]);
        certificate.extend_from_slice(&chain);
        self.record(messages::HANDSHAKE_CERTIFICATE, &certificate);

        // CertificateVerify over the transcript so far
        // `true` is the server's own context: the client passes the same flag to check
        // the signature we are about to write, so `false` here signs the client's
        // string and every peer rejects the flight
        let signed = messages::certificate_verify_input(&self.transcript_hash(), true);
        let signer = self
            .config
            .key
            .choose_scheme(&[
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
            ])
            .ok_or_else(|| bad("the certificate key cannot sign for TLS 1.3"))?;
        let scheme = signer.scheme();
        let signature = signer
            .sign(&signed)
            .map_err(|e| bad(format!("the certificate key failed to sign: {e}")))?;
        let mut verify = scheme.to_array().to_vec();
        verify.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        verify.extend_from_slice(&signature);
        self.record(messages::HANDSHAKE_CERTIFICATE_VERIFY, &verify);

        // Finished over the transcript through the CertificateVerify
        let finished = KeySchedule::finished(
            &self.schedule.server_handshake_traffic(),
            &self.transcript_hash(),
            self.hash,
        );
        self.record(messages::HANDSHAKE_FINISHED, &finished);

        // Both application secrets come from the transcript through *our* Finished,
        // not through the client's. RFC 8446 §7.1 derives the server's from the
        // client's Finished, and rustls -- the peer we are measured against --
        // derives both from the server's. The client's half of the codebase says
        // the same thing at the same decision.
        self.schedule.enter_application(&self.transcript_hash());
        let server_application = KeySchedule::traffic_keys(
            &self.schedule.server_application_traffic(),
            self.hash,
            self.key_len,
            12,
        );
        let client_application = KeySchedule::traffic_keys(
            &self.schedule.client_application_traffic(),
            self.hash,
            self.key_len,
            12,
        );

        let mut flight = Vec::new();
        push_message(
            &mut flight,
            messages::HANDSHAKE_ENCRYPTED_EXTENSIONS,
            &encrypted_extensions,
        );
        push_message(&mut flight, messages::HANDSHAKE_CERTIFICATE, &certificate);
        push_message(&mut flight, messages::HANDSHAKE_CERTIFICATE_VERIFY, &verify);
        push_message(&mut flight, messages::HANDSHAKE_FINISHED, &finished);

        let sealer = self.sealer.as_mut().expect("handshake keys are set");
        let mut offset = 0;
        while offset < flight.len() {
            let end = (offset + record::MAX_FRAGMENT).min(flight.len());
            let sealed = sealer.seal(ContentType::Handshake, &flight[offset..end])?;
            stream.write_all(&sealed).await?;
            offset = end;
        }
        stream.flush().await?;

        // both directions are ready; the read side keeps the handshake keys until the
        // client's Finished, and the keys do not change after it
        self.application = Some((
            Sealer::new(self.suite_id(), server_application),
            Opener::new(self.suite_id(), client_application),
        ));
        Ok(())
    }

    /// The client's Finished, and with it the application keys in both
    /// directions.
    async fn read_client_finished(
        &mut self,
        stream: &mut (dyn Stream + '_),
    ) -> std::io::Result<()> {
        let body = self.next_message(stream).await?;
        if body.0 != messages::HANDSHAKE_FINISHED {
            return Err(bad(format!(
                "the client's flight ended with message {} instead of a Finished",
                body.0
            )));
        }
        let expected = KeySchedule::finished(
            &self.schedule.client_handshake_traffic(),
            &self.transcript_hash(),
            self.hash,
        );
        let got = messages::Finished::parse(&body.1)?;
        if got.verify_data != expected {
            return Err(bad("the client's Finished did not verify"));
        }
        self.record(messages::HANDSHAKE_FINISHED, &body.1);
        // the application keys were derived in write_flight and do not move:
        // they hang off the transcript through *our* Finished, which is where
        // rustls derives them too
        Ok(())
    }

    /// The next handshake message, reassembled across records and decrypted at
    /// whatever level the handshake is on.
    async fn next_message(
        &mut self,
        stream: &mut (dyn Stream + '_),
    ) -> std::io::Result<(u8, Vec<u8>)> {
        loop {
            if self.pending.len() >= 4 {
                let len = ((self.pending[1] as usize) << 16)
                    | ((self.pending[2] as usize) << 8)
                    | self.pending[3] as usize;
                if self.pending.len() >= 4 + len {
                    let kind = self.pending[0];
                    let body = self.pending[4..4 + len].to_vec();
                    self.pending.drain(..4 + len);
                    return Ok((kind, body));
                }
            }
            let raw = read_record(stream).await?;
            match ContentType::from_byte(raw[0])? {
                ContentType::ChangeCipherSpec => continue,
                outer => {
                    let (kind, plaintext) = match &mut self.opener {
                        None => {
                            if outer != ContentType::Handshake {
                                return Err(bad(
                                    "a plaintext record from the client is not a handshake",
                                ));
                            }
                            (ContentType::Handshake, raw[5..].to_vec())
                        }
                        Some(opener) => opener.open(&raw)?,
                    };
                    match kind {
                        ContentType::Handshake => self.pending.extend_from_slice(&plaintext),
                        ContentType::Alert => {
                            // the level and the description, because "the client
                            // hung up" is not what an operator can act on
                            return Err(bad(format!("the client sent an alert {plaintext:?}")));
                        }
                        _ => return Err(bad("application data before the handshake finished")),
                    }
                }
            }
        }
    }
}

async fn read_record(stream: &mut (dyn Stream + '_)) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut out = Vec::with_capacity(5 + len);
    out.extend_from_slice(&header);
    out.resize(5 + len, 0);
    stream.read_exact(&mut out[5..]).await?;
    Ok(out)
}

fn push_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn push_message(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
}

/// The pieces of a ClientHello a server has to answer: the session id to echo,
/// the suites the client speaks, and what it offered in extensions.
struct ClientHello {
    session_id: Vec<u8>,
    suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    /// One walk in order: every field of a hello is length-prefixed, so the
    /// cursor and the prefixes are the whole grammar. Walking from the end
    /// backwards instead -- which is what this did first -- reads the tail of
    /// the last extension as a length and gives up on every hello.
    fn parse(body: &[u8]) -> std::io::Result<Self> {
        let mut reader = messages::Reader::new(body);
        let _legacy_version = reader.take(2)?;
        let _random = reader.take(32)?;
        let session_id = reader.vec8()?.to_vec();
        let suites_body = reader.sub16()?;
        let mut suites = Vec::new();
        let mut step = 0;
        while step + 1 < suites_body.remaining() {
            suites.push(u16::from_be_bytes([
                suites_body.rest()[step],
                suites_body.rest()[step + 1],
            ]));
            step += 2;
        }
        let _compression = reader.vec8()?;
        let mut extensions = Vec::new();
        if !reader.is_empty() {
            let mut list = reader.sub16()?;
            while !list.is_empty() {
                let kind = list.u16()?;
                let data = list.sub16()?;
                extensions.push((kind, data.rest().to_vec()));
            }
        }
        reader.end("ClientHello")?;
        Ok(ClientHello {
            session_id,
            suites,
            extensions,
        })
    }

    fn extension(&self, want: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(kind, _)| *kind == want)
            .map(|(_, data)| data.as_slice())
    }
}

/// The protocol names out of an ALPN extension body.
fn alpn_list(body: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = messages::Reader::new(body);
    let Ok(list) = reader.sub16() else {
        return Vec::new();
    };
    let mut inner = messages::Reader::new(list.rest());
    let mut out = Vec::new();
    while !inner.is_empty() {
        match inner.vec8() {
            Ok(name) => out.push(name.to_vec()),
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello with the fields the server reads, so the ServerHello it
    /// answers with can be looked at byte for byte.
    fn hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[1u8; 32]);
        body.push(32); // a session id, which the answer has to echo
        let session = [9u8; 32];
        body.extend_from_slice(&session);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.extend_from_slice(&[2, 0x03, 0x04]);
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&38u16.to_be_bytes()); // the entry plus this
        extensions.extend_from_slice(&36u16.to_be_bytes()); // the entry itself
        extensions.extend_from_slice(&0x001du16.to_be_bytes());
        extensions.extend_from_slice(&32u16.to_be_bytes());
        extensions.extend_from_slice(&[8u8; 32]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut message = vec![messages::HANDSHAKE_CLIENT_HELLO];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        record::plaintext_record(ContentType::Handshake, &message, record::VERSION_1_2)
            .expect("record")
    }

    /// The ServerHello record, its version and the session id it echoes. A
    /// record version of 0x0301 is what every peer here tolerates and what the
    /// RFC forbids, so nothing else in this crate would notice it.
    #[tokio::test]
    async fn the_server_hello_record_is_the_version_it_claims() {
        let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
        {
            use tokio::io::AsyncWriteExt;
            theirs
                .write_all(&hello())
                .await
                .expect("the hello goes in first");
        }

        let pem = include_bytes!("../../../tests/golden/certs/localhost.key");
        let der = rustls_pemfile::private_key(&mut pem.as_slice())
            .expect("parse the key")
            .expect("the file holds a key");
        let mut handshake = Handshake::new(Config {
            // read_hello never looks at the chain, so a byte that is not a
            // certificate saves building a real one here
            chain: vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]],
            key: core_crypto::sign::any_supported_type(&der).expect("a signing key"),
            alpn: Vec::new(),
        })
        .expect("server config");
        handshake
            .read_hello(&mut ours)
            .await
            .expect("read the hello");

        // the answer comes back out of the far end: a duplex is two one-way
        // pipes, so reading what this end wrote waits for a byte that will
        // never come
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 5];
        theirs.read_exact(&mut header).await.expect("the answer");
        assert_eq!(header[0], ContentType::Handshake as u8, "handshake record");
        assert_eq!(
            &header[1..3],
            &record::VERSION_1_3,
            "a ServerHello record says 0x0303, not 0x0301"
        );

        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        theirs.read_exact(&mut payload).await.expect("body");
        assert_eq!(payload[0], messages::HANDSHAKE_SERVER_HELLO);
        assert_eq!(&payload[1..4], &(118u32).to_be_bytes()[1..], "length");
        let body = &payload[4..];
        assert_eq!(&body[..2], &[0x03, 0x03], "legacy_version");
        assert_eq!(body[34], 32, "the session id length is echoed");
        assert_eq!(&body[35..67], &[9u8; 32], "the session id itself");
    }
}
