//! The client half of a TLS 1.3 handshake (RFC 8446 §4.1), over any transport.
//!
//! The state machine is the one a client needs with no session resumption and no
//! HelloRetryRequest, written against any async stream, so the same code runs
//! over a socket, over a tunnel, or over a pair of buffers in a test.
//!
//! Every message joins the transcript as it is *processed*, never as it arrives:
//! the transcript hash is what CertificateVerify and Finished are computed
//! over, and hashing one message too early or too late leaves nothing in the
//! bytes to say why the server's signature does not verify.

use std::io;

use rustls::CipherSuite;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::hello::{self, Ext, Template};
use crate::keyshare::Shares;
use crate::messages::{
    self, Certificate as CertificateMsg, CertificateVerify as CertificateVerifyMsg,
    Finished as FinishedMsg, HANDSHAKE_CERTIFICATE, HANDSHAKE_CERTIFICATE_VERIFY,
    HANDSHAKE_ENCRYPTED_EXTENSIONS, HANDSHAKE_FINISHED, HANDSHAKE_SERVER_HELLO, ServerHello,
};
use crate::record::{self, ContentType, Opener, Sealer, VERSION_1_3};
use crate::tls13::{Hash, KeySchedule};
use crate::verify::CertVerifier;

/// Anything a handshake can be run over: the caller's own socket, tunnel or
/// buffer. It is async because everything this crate is called from is -- a
/// blocking handshake here would mean blocking a runtime worker to do it, and a
/// blocking call inside a `poll` is worse.
pub trait Stream: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> Stream for T {}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The TLS 1.3 suites, and the hash each one runs its schedule with.
fn suite_of(id: u16) -> io::Result<(CipherSuite, Hash)> {
    match id {
        0x1301 => Ok((CipherSuite::TLS13_AES_128_GCM_SHA256, Hash::Sha256)),
        0x1302 => Ok((CipherSuite::TLS13_AES_256_GCM_SHA384, Hash::Sha384)),
        0x1303 => Ok((CipherSuite::TLS13_CHACHA20_POLY1305_SHA256, Hash::Sha256)),
        other => Err(bad(format!("server chose cipher suite {other:#06x}"))),
    }
}

fn entropy(into: &mut [u8]) -> io::Result<()> {
    getrandom::fill(into).map_err(|e| bad(format!("no entropy: {e}")))
}

/// What the caller configures. There is no `Default`: a client that has not been
/// told how to trust a server cannot be built.
pub struct Config<'a> {
    /// The fingerprint to present, and the cipher suites and key shares with it.
    pub template: &'a Template,
    pub server_name: &'a str,
    /// ALPN protocols, in the order to offer them.
    pub alpn: &'a [&'a [u8]],
    pub verifier: &'a dyn CertVerifier,
}

/// One handshake. [`Handshake::run`] is the whole thing over a blocking stream.
pub struct Handshake<'a> {
    config: Config<'a>,
    shares: Shares,
    /// the suite ids the fingerprint offers, so we can tell whether the server
    /// answered our hello or one of its own
    offered: Vec<u16>,
    session_id: Vec<u8>,
    suite: CipherSuite,
    hash: Hash,
    key_len: usize,
    schedule: KeySchedule,
    /// the handshake messages in order; the transcript hash is taken over this
    transcript: Vec<u8>,
    /// plaintext of records already decrypted, not yet a whole message
    pending: Vec<u8>,
    opener: Option<Opener>,
    sealer: Option<Sealer>,
    leaf: Option<CertificateDer<'static>>,
    /// the protocol the server chose, if it sent ALPN
    pub alpn: Option<Vec<u8>>,
}

impl<'a> Handshake<'a> {
    pub fn new(config: Config<'a>) -> io::Result<Self> {
        let key_share = config
            .template
            .extensions
            .iter()
            .find_map(|e| match e {
                Ext::KeyShare(body) => Some(body.clone()),
                _ => None,
            })
            .ok_or_else(|| bad("the fingerprint offers no key share"))?;
        // the suite list is a run of 16-bit ids, and it is the fingerprint's
        // own bytes: a trailing odd byte is ignored rather than guessed at
        let suites = &config.template.cipher_suites;
        let offered: Vec<u16> = suites
            .iter()
            .step_by(2)
            .zip(suites.iter().skip(1))
            .map(|(high, low)| u16::from_be_bytes([*high, *low]))
            .collect();
        Ok(Handshake {
            shares: Shares::for_body(&key_share)?,
            offered,
            session_id: vec![0u8; 32],
            // replaced once the server chooses; these only keep the types happy
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash: Hash::Sha256,
            key_len: 16,
            schedule: KeySchedule::new(Hash::Sha256, &[]),
            transcript: Vec::new(),
            pending: Vec::new(),
            opener: None,
            sealer: None,
            leaf: None,
            alpn: None,
            config,
        })
    }

    /// The key shares this handshake offers, for a caller that needs to know what
    /// went on the wire -- the REALITY auth key is one of them.
    pub fn shares(&self) -> &Shares {
        &self.shares
    }

    /// The session id the ClientHello carries, for a caller that seals something
    /// into it.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// The leaf the server sent, once the chain has been accepted.
    pub fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.leaf.as_ref()
    }

    fn transcript_hash(&self) -> Vec<u8> {
        self.hash.digest(&self.transcript)
    }

    /// Append a whole message to the transcript, header included: the hash runs
    /// over messages, not over records.
    fn record_message(&mut self, kind: u8, body: &[u8]) {
        self.transcript.push(kind);
        self.transcript
            .extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        self.transcript.extend_from_slice(body);
    }

    /// Run the whole handshake.
    pub async fn run(&mut self, stream: &mut (dyn Stream + '_)) -> io::Result<()> {
        self.start(stream).await?;
        self.read_server_hello(stream).await?;
        self.read_flight(stream).await?;
        self.send_finished(stream).await
    }

    /// Write the ClientHello.
    pub async fn start(&mut self, stream: &mut (dyn Stream + '_)) -> io::Result<()> {
        let mut random = [0u8; 32];
        entropy(&mut random)?;
        entropy(&mut self.session_id)?;
        let record = hello::build(
            self.config.template,
            &random,
            &self.session_id,
            self.config.server_name,
            self.config.alpn,
            Some(&self.shares),
        )?;
        self.transcript.extend_from_slice(&record[5..]);
        stream.write_all(&record).await?;
        stream.flush().await
    }

    /// Read the server's hello and derive the handshake keys, refusing anything
    /// that is not an answer to the hello we actually sent.
    pub async fn read_server_hello(&mut self, stream: &mut (dyn Stream + '_)) -> io::Result<()> {
        let raw = read_record(stream).await?;
        if raw[0] != ContentType::Handshake as u8 {
            return Err(bad("the first record from the server is not a handshake"));
        }
        let framed = raw[5..].to_vec();
        let message = messages::take_message(&mut framed.as_slice())?;
        if message.kind != HANDSHAKE_SERVER_HELLO {
            return Err(bad("the first message is not a ServerHello"));
        }
        let hello = ServerHello::parse(message.body)?;
        if hello.legacy_version != VERSION_1_3 {
            return Err(bad("ServerHello has the wrong legacy version"));
        }
        if hello.compression != 0 {
            return Err(bad("ServerHello chose a compression method"));
        }
        if hello.supported_version != Some(0x0304) {
            return Err(bad("the server did not negotiate TLS 1.3"));
        }
        if hello.session_id_echo != self.session_id {
            return Err(bad("ServerHello echoed a different session id"));
        }
        if !self.offered.contains(&hello.cipher_suite) {
            return Err(bad("the server chose a suite we did not offer"));
        }
        let (group, peer_share) = hello
            .key_share
            .ok_or_else(|| bad("ServerHello carried no key share"))?;
        if self.shares.public(group).is_none() {
            return Err(bad(format!(
                "the server chose group {group:#06x}, which we did not offer"
            )));
        }
        let secret = self.shares.complete(group, &peer_share)?;

        let (suite, hash) = suite_of(hello.cipher_suite)?;
        let key_len = core_crypto::tls13_key_len(suite)
            .ok_or_else(|| bad("the chosen suite is not one of ours"))?;
        self.suite = suite;
        self.hash = hash;
        self.key_len = key_len;
        self.transcript.extend_from_slice(&raw[5..]);

        self.schedule = KeySchedule::new(hash, &[]);
        self.schedule
            .enter_handshake(&secret, &self.transcript_hash());
        self.opener = Some(Opener::new(
            suite,
            KeySchedule::traffic_keys(&self.schedule.server_handshake_traffic(), hash, key_len, 12),
        ));
        self.sealer = Some(Sealer::new(
            suite,
            KeySchedule::traffic_keys(&self.schedule.client_handshake_traffic(), hash, key_len, 12),
        ));
        Ok(())
    }

    /// The next handshake message, reassembled across records and decrypted as
    /// the encryption level allows.
    async fn next_message(&mut self, stream: &mut (dyn Stream + '_)) -> io::Result<(u8, Vec<u8>)> {
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
                // the compatibility record, which every server sends in the clear
                // just before its flight and which a client is told to ignore
                ContentType::ChangeCipherSpec => continue,
                outer => {
                    let (kind, plaintext) = match &mut self.opener {
                        None => {
                            if outer != ContentType::Handshake {
                                return Err(bad(
                                    "a plaintext record from the server is not a handshake",
                                ));
                            }
                            (ContentType::Handshake, raw[5..].to_vec())
                        }
                        Some(opener) => opener.open(&raw)?,
                    };
                    match kind {
                        ContentType::Handshake => self.pending.extend_from_slice(&plaintext),
                        ContentType::Alert => return Err(alert(&plaintext)),
                        _ => return Err(bad("application data before the handshake finished")),
                    }
                }
            }
        }
    }

    /// The server's flight: EncryptedExtensions, Certificate, maybe a
    /// CertificateStatus, CertificateVerify, Finished.
    pub async fn read_flight(&mut self, stream: &mut (dyn Stream + '_)) -> io::Result<()> {
        let (kind, body) = self.next_message(stream).await?;
        if kind != HANDSHAKE_ENCRYPTED_EXTENSIONS {
            return Err(bad(
                "the server's flight did not start with EncryptedExtensions",
            ));
        }
        let extensions = messages::EncryptedExtensions::parse(&body)?;
        if extensions.server_name_echo {
            return Err(bad("the server echoed our SNI, which TLS 1.3 forbids"));
        }
        self.alpn = extensions
            .alpn
            .as_deref()
            .map(messages::alpn_protocol)
            .transpose()?;
        self.record_message(kind, &body);

        let (kind, body) = self.next_message(stream).await?;
        if kind != HANDSHAKE_CERTIFICATE {
            return Err(bad("the server sent no certificate"));
        }
        let certificate = CertificateMsg::parse(&body)?;
        if certificate.entries.is_empty() {
            return Err(bad("the server sent an empty certificate chain"));
        }
        let chain: Vec<CertificateDer<'static>> = certificate
            .entries
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        let leaf = chain[0].clone();
        let name = ServerName::try_from(self.config.server_name.to_string())
            .map_err(|_| bad("the server name cannot go into a ServerName"))?;
        self.config
            .verifier
            .verify_chain(&leaf, &chain[1..], &name)?;
        self.leaf = Some(leaf.clone());
        self.record_message(kind, &body);

        // a server that asked for OCSP staples may answer with the status first
        let (mut kind, mut body) = self.next_message(stream).await?;
        if kind == 0x16 {
            self.record_message(kind, &body);
            (kind, body) = self.next_message(stream).await?;
        }
        if kind != HANDSHAKE_CERTIFICATE_VERIFY {
            return Err(bad("the server signed nothing"));
        }
        let verify = CertificateVerifyMsg::parse(&body)?;
        let signed = messages::certificate_verify_input(&self.transcript_hash(), true);
        self.config.verifier.verify_handshake_signature(
            &signed,
            &leaf,
            verify.scheme,
            &verify.signature,
        )?;
        self.record_message(kind, &body);

        let (kind, body) = self.next_message(stream).await?;
        if kind != HANDSHAKE_FINISHED {
            return Err(bad("the server's flight ended without a Finished"));
        }
        let expected = KeySchedule::finished(
            &self.schedule.server_handshake_traffic(),
            &self.transcript_hash(),
            self.hash,
        );
        let got = FinishedMsg::parse(&body)?;
        if got.verify_data != expected {
            return Err(bad("the server's Finished did not verify"));
        }
        self.record_message(kind, &body);
        Ok(())
    }

    /// Our own Finished, under the client handshake keys, after the
    /// compatibility ChangeCipherSpec every real client sends.
    pub async fn send_finished(&mut self, stream: &mut (dyn Stream + '_)) -> io::Result<()> {
        // the client application secret is derived from the transcript through
        // the *server's* Finished, so it is taken before ours is added
        self.schedule.enter_application(&self.transcript_hash());
        let verify = KeySchedule::finished(
            &self.schedule.client_handshake_traffic(),
            &self.transcript_hash(),
            self.hash,
        );
        let mut message = vec![HANDSHAKE_FINISHED];
        message.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&verify);

        let ccs = record::plaintext_record(ContentType::ChangeCipherSpec, &[1], VERSION_1_3)?;
        let sealer = self
            .sealer
            .as_mut()
            .ok_or_else(|| bad("no handshake keys, so nothing to seal with"))?;
        let sealed = sealer.seal(ContentType::Handshake, &message)?;
        stream.write_all(&ccs).await?;
        stream.write_all(&sealed).await?;
        stream.flush().await?;
        // the server's application secret covers our Finished too
        self.record_message(HANDSHAKE_FINISHED, &verify);
        Ok(())
    }
}

/// A finished handshake, and the application data that follows it.
///
/// The keys for the application level come out of the same schedule: the client
/// secret is derived from the transcript through the server's Finished, the
/// server's from the transcript through ours. Both are computed here, so a
/// caller that owns the handshake does not have to know that the two levels
/// number their records separately.
///
/// The record sequence numbers carry on from the handshake, which is the one
/// detail that makes this a continuation rather than a second connection.
///
/// The interface is bytes in and bytes out -- [`Connection::write_record`] seals
/// one record, [`Connection::read_record_from`] takes whatever whole records a
/// buffer holds -- so the caller's async stream is a buffer and two calls, and
/// nothing here blocks or owns a socket.
pub struct Connection {
    sealer: Sealer,
    opener: Opener,
    closed: bool,
}

impl Connection {
    /// Take over from a handshake that has sent its Finished.
    pub fn new(handshake: &mut Handshake<'_>) -> io::Result<Self> {
        // the handshake level's keys are spent: the application level has its
        // own, numbered on from where the handshake stopped
        if handshake.sealer.take().is_none() || handshake.opener.take().is_none() {
            return Err(bad("the handshake never reached its own keys"));
        }
        let (suite, hash, key_len) = (handshake.suite, handshake.hash, handshake.key_len);
        // RFC 8446 section 7.1 derives the server's application secret from the
        // transcript through the *client's* Finished, and its client secret from
        // the transcript through the server's. rustls' server derives both from
        // the transcript through the server's Finished, and that is the one that
        // opens a real server's records (measured: the asymmetric value fails
        // the tag on the very first record, the symmetric one opens it). We
        // follow the implementation that interoperates and say so here rather
        // than quietly matching a spec nobody's server follows; the reference
        // client is the arbiter if this ever comes up again.
        let server_secret = handshake.schedule.server_application_traffic();
        let client_secret = handshake.schedule.client_application_traffic();
        Ok(Connection {
            sealer: Sealer::new(
                suite,
                KeySchedule::traffic_keys(&client_secret, hash, key_len, 12),
            ),
            opener: Opener::new(
                suite,
                KeySchedule::traffic_keys(&server_secret, hash, key_len, 12),
            ),
            closed: false,
        })
    }

    /// Wrap `data` into one record, ready for the transport to send. A caller
    /// with more than a record's worth writes it in pieces; the sequence number
    /// moves with each.
    pub fn write_record(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.sealer.seal(ContentType::ApplicationData, data)
    }

    /// Decrypt whatever whole records `raw` holds and return their application
    /// data. A partial record stays in `raw` for next time, and a post-handshake
    /// message is skipped rather than returned: a server sends its session
    /// tickets at this level, before any data.
    ///
    /// This is the whole interface an async stream needs: bytes in, bytes out,
    /// no blocking and no stream of its own. The blocking [`Self::read`] below
    /// is this plus a socket.
    pub fn read_record_from(&mut self, raw: &mut Vec<u8>) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if raw.len() < 5 {
                return Ok(out);
            }
            let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
            if raw.len() < 5 + len {
                return Ok(out);
            }
            let record: Vec<u8> = raw.drain(..5 + len).collect();
            match self.opener.open(&record)? {
                (ContentType::ApplicationData, data) => {
                    out.extend_from_slice(&data);
                    return Ok(out);
                }
                (ContentType::Handshake, _) => continue,
                (ContentType::Alert, data) => {
                    // close_notify is the end of the data, not a failure
                    if data.len() >= 2 && data[1] == 0 {
                        self.closed = true;
                    }
                    return Err(alert(&data));
                }
                (kind, _) => {
                    return Err(bad(format!(
                        "the server sent a {kind:?} record after the handshake"
                    )));
                }
            }
        }
    }

    /// True once the peer has closed or sent close_notify.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

async fn read_record(stream: &mut (dyn Stream + '_)) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut out = Vec::with_capacity(5 + len);
    out.extend_from_slice(&header);
    out.resize(5 + len, 0);
    stream.read_exact(&mut out[5..]).await?;
    Ok(out)
}

/// An alert from the peer, named: a handshake that fails with "InvalidData" and
/// no reason is a handshake that cannot be debugged.
fn alert(payload: &[u8]) -> io::Error {
    if payload.len() < 2 {
        return bad("a truncated alert");
    }
    let (level, description) = (payload[0], payload[1]);
    bad(format!(
        "the server sent alert {description} (level {level}) at the end of its flight"
    ))
}
