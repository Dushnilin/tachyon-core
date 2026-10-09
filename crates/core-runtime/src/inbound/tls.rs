//! TLS for the server inbounds: our own handshake, our own record layer.
//!
//! The client half is `tls_utls::FingerprintStream`; this is the same shape over
//! the keys the server side derived, so a vless or trojan inbound with a `tls`
//! block costs one handshake at accept time and nothing after that.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use core_tls::record::{ContentType, Opener, Sealer};
use core_tls::server::{Config, Handshake};

/// A chunk big enough to hold a whole record, so the ordinary case is one read
/// from the socket. A compile-time assertion, not a test: a runtime check of a
/// constant is a comment.
const CHUNK: usize = {
    assert!(core_tls::record::MAX_FRAGMENT + 512 <= 18 * 1024);
    18 * 1024
};

/// How long a client has to finish its half of the handshake. It runs inside the
/// accept task, so an endless one is a task that never ends and a socket that
/// never becomes readable again.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// `close_notify`: warning(1) plus description 0.
const CLOSE_NOTIFY: [u8; 2] = [1, 0];

/// What `tls` on an inbound gives us: the chain, the key and the protocols.
pub struct ServerTls {
    chain: Vec<Vec<u8>>,
    key: Arc<dyn core_tls::rustls::sign::SigningKey>,
    alpn: Vec<Vec<u8>>,
}

impl ServerTls {
    /// Parse the `tls` block of a server inbound; `None` when it is absent or
    /// says `enabled: false`. The gate lives here rather than in the caller so
    /// that a disabled block is never mistaken for a broken one.
    pub fn from_inbound(obj: &Value, at: &str) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(tls) = obj.get("tls").filter(|tls| !tls.is_null()) else {
            return Ok(None);
        };
        if tls
            .as_object()
            .and_then(|tls| tls.get("enabled"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Ok(None);
        }
        let mut this = Self::from_config(tls, at)?;
        // The transport type is part of the handshake, both ways: gRPC over
        // TLS is HTTP/2, and the reference appends `h2` to the listener's
        // ALPN before it serves (transport/v2ray/grpc.go), because a grpc-go
        // client that negotiates nothing refuses the connection outright. XHTTP
        // is the mirror image: this server speaks its HTTP/1.1 wire only, and
        // a reference XHTTP client left to itself asks for `h2`, so the
        // listener has to answer with `http/1.1` for the two to meet on one
        // protocol at all.
        let ty = obj
            .get("transport")
            .and_then(|t| t.get("type"))
            .and_then(Value::as_str);
        match ty {
            Some("grpc") if !this.alpn.iter().any(|p| p == b"h2") => {
                this.alpn.push(b"h2".to_vec());
            }
            Some("xhttp") => {
                if !this.alpn.iter().any(|p| p == b"h2") {
                    this.alpn.insert(0, b"h2".to_vec());
                }
                if !this.alpn.iter().any(|p| p == b"http/1.1") {
                    this.alpn.push(b"http/1.1".to_vec());
                }
            }
            _ => {}
        }
        Ok(Some(Arc::new(this)))
    }

    /// Read the block the way the reference's `common/tls.NewSTDServer` does:
    /// the certificate and the key, from the files or inline, and nothing else
    /// invented.
    pub fn from_config(tls: &Value, at: &str) -> anyhow::Result<Self> {
        let object = tls
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: tls: must be a JSON object"))?;
        if let Some(provider) = object.get("certificate_provider") {
            let ty = provider
                .as_object()
                .and_then(|p| p.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            anyhow::bail!(
                "{at}: tls: certificate_provider {ty:?} is not supported by this \
                 server yet (check accepts it, start does not)"
            );
        }
        if object.get("acme").is_some_and(|acme| !acme.is_null()) {
            anyhow::bail!("{at}: tls: acme is not supported by this server yet");
        }
        if object
            .get("insecure")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && !has_material(object, "certificate", "certificate_path")
        {
            // `check` lets this through: the reference answers it with a
            // throwaway key pair it builds out of the ClientHello. We have no
            // way to sign a certificate yet, and a server with no certificate
            // would have nothing to answer with, so it is refused by name.
            anyhow::bail!(
                "{at}: tls: insecure without a certificate needs an ephemeral \
                 key pair, which this server cannot generate"
            );
        }

        let certificate = match object.get("certificate_path").and_then(Value::as_str) {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls: read certificate: {e}"))?,
            None => listable(object, "certificate")
                .ok_or_else(|| anyhow::anyhow!("{at}: tls: missing certificate"))?,
        };
        let key_pem = match object.get("key_path").and_then(Value::as_str) {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls: read key: {e}"))?,
            None => {
                listable(object, "key").ok_or_else(|| anyhow::anyhow!("{at}: tls: missing key"))?
            }
        };

        let mut chain = Vec::new();
        for cert in rustls_pemfile::certs(&mut certificate.as_bytes()) {
            let der = cert.map_err(|e| anyhow::anyhow!("{at}: tls: certificate: {e}"))?;
            chain.push(der.to_vec());
        }
        if chain.is_empty() {
            anyhow::bail!("{at}: tls: the certificate holds no certificate");
        }
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("{at}: tls: key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("{at}: tls: the key file holds no key"))?;
        let signing = core_crypto::sign::any_supported_type(&key)
            .map_err(|e| anyhow::anyhow!("{at}: tls: parse x509 key pair: {e}"))?;

        // `alpn` is a Listable[string]: one name or a list of them
        let alpn = match object.get("alpn") {
            None => Vec::new(),
            Some(Value::String(one)) => vec![one.as_bytes().to_vec()],
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .map(|name| name.as_bytes().to_vec())
                .collect(),
            Some(_) => anyhow::bail!("{at}: tls: alpn: must be a string or a list"),
        };
        Ok(ServerTls {
            chain,
            key: signing,
            alpn,
        })
    }

    /// Build a quinn ServerConfig for QUIC server inbounds (hysteria2, tuic).
    pub fn build_quic_server_config(
        tls: &Value,
        default_alpn: &[&[u8]],
        at: &str,
    ) -> anyhow::Result<quinn::ServerConfig> {
        let object = tls
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: tls: must be a JSON object"))?;

        let certificate = match object.get("certificate_path").and_then(Value::as_str) {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls: read certificate: {e}"))?,
            None => listable(object, "certificate")
                .ok_or_else(|| anyhow::anyhow!("{at}: tls: missing certificate"))?,
        };
        let key_pem = match object.get("key_path").and_then(Value::as_str) {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls: read key: {e}"))?,
            None => {
                listable(object, "key").ok_or_else(|| anyhow::anyhow!("{at}: tls: missing key"))?
            }
        };

        let certs: Vec<_> = rustls_pemfile::certs(&mut certificate.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("{at}: tls: parse certificate: {e}"))?;
        if certs.is_empty() {
            anyhow::bail!("{at}: tls: the certificate holds no certificate");
        }
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("{at}: tls: parse key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("{at}: tls: the key file holds no key"))?;

        core_tls::install_default_provider();
        let mut cfg = core_tls::rustls::ServerConfig::builder_with_provider(
            core_tls::quic::configured_provider(),
        )
        .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("{at}: tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("{at}: tls: {e}"))?;

        let alpn: Vec<Vec<u8>> = match object.get("alpn") {
            None => default_alpn.iter().map(|p| p.to_vec()).collect(),
            Some(Value::String(one)) => vec![one.as_bytes().to_vec()],
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .map(|name| name.as_bytes().to_vec())
                .collect(),
            Some(_) => anyhow::bail!("{at}: tls: alpn: must be a string or a list"),
        };
        if !alpn.is_empty() {
            cfg.alpn_protocols = alpn;
        }

        let crypto = core_tls::quic::QuicServerConfig::try_from(cfg)
            .map_err(|e| anyhow::anyhow!("{at}: quic tls: {e:?}"))?;

        let mut server_config = quinn::ServerConfig::new(
            Arc::new(crypto),
            Arc::new(core_tls::quic::HandshakeTokenKeyRustCrypto::new([7u8; 64])),
        );
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
        ));
        server_config.transport_config(Arc::new(transport));
        Ok(server_config)
    }

    /// Run the handshake over `stream` and hand back a stream that carries
    /// application data.
    pub async fn accept<S>(&self, mut stream: S) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut handshake = Handshake::new(Config {
            chain: self.chain.clone(),
            key: Arc::clone(&self.key),
            alpn: self.alpn.clone(),
        })?;
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake.run(&mut stream)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tls handshake timed out",
                ));
            }
        }
        let alpn = handshake.alpn.clone();
        let (sealer, opener) = handshake
            .application
            .take()
            .ok_or_else(|| io::Error::other("the handshake left no application keys"))?;
        Ok(TlsStream {
            inner: stream,
            sealer,
            opener,
            raw: Vec::new(),
            rd: 0,
            pend_at: 0,
            pend_end: 0,
            wbuf: Vec::new(),
            wpos: 0,
            taken: 0,
            eof: false,
            closed: false,
            alpn,
        })
    }
}

/// A `Listable[string]`: one PEM block or a list of them, which the reference
/// joins with newlines before it hands the text to the parser. `None` for an
/// absent or empty value -- an empty `certificate` is no certificate, the same
/// way an empty path is no path.
fn listable(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    let joined = match object.get(key)? {
        Value::String(one) => one.clone(),
        Value::Array(list) => list
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<&str>>()
            .join("\n"),
        _ => return None,
    };
    (!joined.is_empty()).then_some(joined)
}

/// Does the block name a certificate by either of the two ways it can?
fn has_material(object: &serde_json::Map<String, Value>, inline: &str, path: &str) -> bool {
    listable(object, inline).is_some()
        || object
            .get(path)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
}

/// A stream carrying application data through our own TLS 1.3 record layer.
pub struct TlsStream<S> {
    inner: S,
    sealer: Sealer,
    opener: Opener,
    /// Transport bytes. Whole records are opened right where they lie, so the
    /// plaintext being handed over is `raw[pend_at..pend_end]` and nothing is
    /// allocated or copied per record on the way in.
    raw: Vec<u8>,
    /// where the first record that has not been opened yet starts
    rd: usize,
    pend_at: usize,
    pend_end: usize,
    /// sealed records waiting to go out, in order, and how much of them has
    /// been written: the sequence number is the record's position, so they
    /// cannot be reordered or interleaved
    wbuf: Vec<u8>,
    wpos: usize,
    /// how many bytes of the caller's buffer this call has already sealed, and
    /// therefore owes back once they are on the wire
    taken: usize,
    eof: bool,
    /// close_notify is due to go out once, at shutdown
    closed: bool,
    /// The ALPN protocol chosen by the server handshake, if any.
    pub alpn: Option<Vec<u8>>,
}

impl<S> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Push whatever is left of the sealed records into the transport.
    fn drain_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        // The loop stops on the length itself, not on what the write returns:
        // an empty slice reads as `Ok(0)`, which is the one thing a socket does
        // answer with without having written anything.
        while self.wpos < self.wbuf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the transport took no bytes of a sealed record",
                    )));
                }
                Poll::Ready(Ok(n)) => self.wpos += n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.pend_at < me.pend_end {
                let take = (me.pend_end - me.pend_at).min(buf.remaining());
                buf.put_slice(&me.raw[me.pend_at..me.pend_at + take]);
                me.pend_at += take;
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            // Whatever we already hold comes first and only then the socket: a
            // socket hands us half a record all the time, so asking it only when
            // the buffer was short spins over the same bytes forever.
            let avail = me.raw.len() - me.rd;
            if avail >= 5 {
                let len = u16::from_be_bytes([me.raw[me.rd + 3], me.raw[me.rd + 4]]) as usize;
                // RFC 8446 §5.2: more than 2^14 + 256 is a record_overflow
                if len > core_tls::record::MAX_FRAGMENT + 256 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls record over the length limit",
                    )));
                }
                if avail >= 5 + len {
                    let start = me.rd;
                    me.rd += 5 + len;
                    let (kind, plain) = me
                        .opener
                        .open_in_place(&mut me.raw[start..start + 5 + len])?;
                    match kind {
                        ContentType::ApplicationData if plain > 0 => {
                            me.pend_at = start + 5;
                            me.pend_end = start + 5 + plain;
                        }
                        // an alert ends the stream, close_notify or not: the
                        // reference has nothing left to say either way
                        ContentType::Alert => me.eof = true,
                        // a post-handshake message we do not keep, which is what
                        // the reference does with NewSessionTicket as well
                        _ => {}
                    }
                    continue;
                }
            }
            // Nothing is being handed over here, so what has been opened can go.
            if me.rd > 0 {
                me.raw.drain(..me.rd);
                me.rd = 0;
                me.pend_at = 0;
                me.pend_end = 0;
            }
            // Read straight into the buffer's spare room: no zeroed scratch
            // array and no second copy.
            me.raw.reserve(CHUNK);
            let have = me.raw.len();
            let mut read = ReadBuf::uninit(me.raw.spare_capacity_mut());
            match Pin::new(&mut me.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let got = read.filled().len();
                    if got == 0 {
                        me.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    // SAFETY: the reader initialised exactly `got` bytes of the
                    // spare capacity, starting at `have`.
                    unsafe { me.raw.set_len(have + got) };
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Records sealed into one write at most: a few of them leave in one syscall.
const WRITE_RECORDS: usize = 4;

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Nothing to seal is nothing written: reporting zero keeps a caller from
        // sealing an empty record.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // A record holds 2^14 bytes of plaintext and no more (RFC 8446 §5.1), so
        // a caller with a megabyte in hand gets a short write and comes back for
        // the rest. That is what `AsyncWrite` allows, and it is the only honest
        // answer: sealing the whole buffer anyway puts a length in the header
        // that does not describe it.
        if me.taken == 0 {
            let take = buf
                .len()
                .min(WRITE_RECORDS * core_tls::record::MAX_FRAGMENT);
            for piece in buf[..take].chunks(core_tls::record::MAX_FRAGMENT) {
                if let Err(err) =
                    me.sealer
                        .seal_into(ContentType::ApplicationData, piece, &mut me.wbuf)
                {
                    return Poll::Ready(Err(err));
                }
            }
            me.taken = take;
        }
        match me.drain_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        // only now are the promised bytes actually on the transport
        Poll::Ready(Ok(std::mem::take(&mut me.taken)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // poll_write only reports ready once the whole batch is out, so there is
        // never a part-written record to flush around
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // A close_notify is what tells the client the tunnel ended cleanly
        // instead of the transport dying under it. rustls treats its absence as
        // a truncation and complains.
        if !me.closed {
            me.closed = true;
            let _ = me
                .sealer
                .seal_into(ContentType::Alert, &CLOSE_NOTIFY, &mut me.wbuf);
        }
        match me.drain_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
