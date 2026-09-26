//! FPTN client TLS: MD5 certificate pinning plus the FPTN session id.
//!
//! The reference client stamps a 32-byte legacy session id whose last 4 bytes
//! are `SHA1(htonl(now))[..4]` (see `utils::SetHandshakeSessionID` /
//! `GenerateFptnKey`). fptn-server rejects any other value by proxying the
//! connection away (`Session::IsRealityHandshake`), so the hello must carry
//! it. rustls generates its own random session id with no override hook, so
//! this module wraps the process `CryptoProvider`'s `SecureRandom` and
//! answers the first 32-byte fill of a handshake — which is exactly
//! `SessionId::random` in `client/hs.rs::ClientHelloInput::new` — with the
//! FPTN id. `tests/session_id.rs` pins that ordering.
//!
//! Pinned states are recycled through a small pool: `fill` only injects while
//! `armed`, and a released state disarms, so a recycled config can never leak
//! its id into another handshake.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use core_tls::rustls;
use core_tls::rustls::pki_types::{CertificateDer, IpAddr as PkiIpAddr, ServerName, UnixTime};
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::obfs::ObfsStream;

const SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::ED25519,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
];

/// Server-side acceptance window: `IsFptnClientSessionID` scans
/// `now + 120 - shift` for `shift in 0..=240`, i.e. `now ± 120s`.
#[cfg(test)]
const SESSION_WINDOW: u32 = 240;
#[cfg(test)]
const HALF_WINDOW: i64 = SESSION_WINDOW as i64 / 2;

/// Pause between an obfuscated handshake and the first plaintext write; see
/// the comment at the flip in [`connect`]. The control plane pays it twice
/// per session (login + websocket), the data path never does.
const SETTLE_DELAY: Duration = Duration::from_millis(300);

/// `GenerateFptnKey`: SHA1 over the big-endian timestamp, first 4 bytes.
fn fptn_key(timestamp: u32) -> [u8; 4] {
    let mut hasher = Sha1::new();
    hasher.update(timestamp.to_be_bytes());
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// 32 random bytes with `SHA1(htonl(now))[..4]` in the last 4 bytes.
pub(crate) fn fptn_session_id(now: u32) -> [u8; 32] {
    let mut sid = [0u8; 32];
    crate::outbound::shadowsocks::crypto::random_bytes(&mut sid).expect("system random available");
    sid[28..32].copy_from_slice(&fptn_key(now));
    sid
}

/// Wall-clock seconds, the timestamp both the session id and the obfuscator
/// framing are derived from (server side: `TimeProvider::NowTimestamp`).
pub(crate) fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Mirror of the server check (unit-testable without a socket).
#[cfg(test)]
pub(crate) fn is_fptn_session_id(sid: &[u8], now: u32) -> bool {
    if sid.len() < 4 {
        return false;
    }
    let key: [u8; 4] = sid[sid.len() - 4..].try_into().expect("4 bytes");
    let base = now as i64 + HALF_WINDOW;
    (0..=SESSION_WINDOW).any(|shift| fptn_key((base - shift as i64) as u32) == key)
}

/// Pooled per-handshake injection state.
#[derive(Debug)]
struct FptnRandom {
    armed: AtomicBool,
    sid: Mutex<[u8; 32]>,
    inner: &'static dyn rustls::crypto::SecureRandom,
}

impl rustls::crypto::SecureRandom for FptnRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        if buf.len() == 32 && self.armed.swap(false, Ordering::Relaxed) {
            buf.copy_from_slice(&*self.sid.lock().unwrap_or_else(|e| e.into_inner()));
            return Ok(());
        }
        self.inner.fill(buf)
    }

    fn fips(&self) -> bool {
        self.inner.fips()
    }
}

fn pool() -> &'static Mutex<Vec<&'static FptnRandom>> {
    static POOL: OnceLock<Mutex<Vec<&'static FptnRandom>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Vec::new()))
}

/// Arm a pooled (or freshly leaked) state for one handshake.
fn acquire(sid: [u8; 32]) -> &'static FptnRandom {
    let mut free = pool().lock().unwrap_or_else(|e| e.into_inner());
    let state = free.pop().unwrap_or_else(|| {
        let base = core_tls::quic::configured_provider();
        Box::leak(Box::new(FptnRandom {
            armed: AtomicBool::new(false),
            sid: Mutex::new([0u8; 32]),
            inner: base.secure_random,
        }))
    });
    state
        .sid
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .copy_from_slice(&sid);
    state.armed.store(true, Ordering::Relaxed);
    state
}

fn release(state: &'static FptnRandom) {
    state.armed.store(false, Ordering::Relaxed);
    pool().lock().unwrap_or_else(|e| e.into_inner()).push(state);
}

struct ArmedGuard(&'static FptnRandom);

impl Drop for ArmedGuard {
    fn drop(&mut self) {
        release(self.0);
    }
}

/// Accept-any verifier unless an MD5 fingerprint is pinned: the reference
/// client compares the leaf digest (`GetCertificateMD5Fingerprint`) and
/// skips chain validation entirely; an empty pin disables verification.
#[derive(Debug)]
struct Md5PinVerifier {
    expected: String,
}

fn md5_hex(cert: &CertificateDer<'_>) -> Option<String> {
    let mut hasher = Md5::new();
    hasher.update(cert.as_ref());
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

impl rustls::client::danger::ServerCertVerifier for Md5PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.expected.is_empty() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        let got = md5_hex(end_entity).ok_or_else(|| {
            rustls::Error::General("fptn: failed to digest peer certificate".into())
        })?;
        if got == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "fptn: certificate MD5 mismatch: expected {}, got {got}",
                self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // The leaf MD5 pin authenticates the endpoint; the handshake
        // signature check would be circular against an untrusted chain.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SCHEMES.to_vec()
    }
}

/// rustls server name for the configured SNI; an empty SNI sends no
/// extension (an IP literal is never rendered into SNI), and the pin
/// verifier never consults the name anyway.
fn server_name(sni: &str) -> io::Result<ServerName<'static>> {
    if sni.is_empty() {
        return Ok(ServerName::IpAddress(PkiIpAddr::V4(
            Ipv4Addr::UNSPECIFIED.into(),
        )));
    }
    ServerName::try_from(sni.to_string())
        .map_err(|_| io::Error::other(format!("fptn: invalid sni {sni:?}")))
}

/// Client config for one connection: TLS 1.2–1.3 (the reference range),
/// ALPN `h2, http/1.1` (as `CreateNewSslCtx` advertises), the injected
/// session id and the MD5 pin.
fn client_config(md5: &str, state: &'static FptnRandom) -> io::Result<Arc<rustls::ClientConfig>> {
    let base = core_tls::quic::configured_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: base.cipher_suites.clone(),
        kx_groups: base.kx_groups.clone(),
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: state,
        key_provider: base.key_provider,
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("fptn: protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Md5PinVerifier {
            expected: md5.to_ascii_lowercase(),
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Boxed transport under TLS: plain TCP or the obfuscating wrapper
/// (`AnyStream` = `Box<dyn ProxyStream>` — a single trait, so it can be a
/// trait object where `AsyncRead + AsyncWrite` cannot).
pub(crate) type BoxStream = crate::inbound::AnyStream;
/// Established FPTN TLS session.
pub(crate) type FptnTls = TlsStream<BoxStream>;

/// TCP connect + TLS handshake with the FPTN session id and MD5 pin. With
/// `obfuscate` the handshake travels inside TlsObfuscator2 frames, which is
/// the official `kTlsObfuscator` strategy (the server then skips the
/// session-id / probing checks, and the flow survives TLS-fingerprint DPI).
pub(crate) async fn connect(
    server: SocketAddr,
    sni: &str,
    md5: &str,
    obfuscate: bool,
) -> io::Result<FptnTls> {
    let state = acquire(fptn_session_id(unix_now()));
    let _armed = ArmedGuard(state);
    let config = client_config(md5, state)?;
    let name = server_name(sni)?;
    let stream = TcpStream::connect(server).await?;
    let _ = stream.set_nodelay(true);
    let connector = TlsConnector::from(config);
    let tls = if obfuscate {
        let (obfs, plain) = ObfsStream::new(stream);
        let tls = connector
            .connect(name, Box::new(obfs) as BoxStream)
            .await
            .map_err(|e| io::Error::other(format!("fptn: tls handshake: {e}")))?;
        // The handshake is done: the server clears its obfuscator right after
        // ITS async_handshake, but bytes that reach the socket before that
        // moment are appended to the obfuscator's input buffer and never
        // delivered to TLS (they wait for a frame header that never comes).
        // The server then hangs waiting for the request while we wait for the
        // response. Measured: 0ms always loses the race, 100ms wins — give
        // the server a comfortable window before the first plaintext write.
        plain.store(true, Ordering::Relaxed);
        tokio::time::sleep(SETTLE_DELAY).await;
        tls
    } else {
        connector
            .connect(name, Box::new(stream) as BoxStream)
            .await
            .map_err(|e| io::Error::other(format!("fptn: tls handshake: {e}")))?
    };
    Ok(tls)
}

/// Diagnostic: format a session id as lowercase hex (error messages).
#[allow(dead_code)]
pub(crate) fn session_id_hex(sid: &[u8; 32]) -> String {
    sid.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_shape() {
        let now = 1_760_000_000;
        let sid = fptn_session_id(now);
        assert_eq!(sid.len(), 32);
        assert_eq!(&sid[28..32], &fptn_key(now));
        assert!(is_fptn_session_id(&sid, now));
        // Inside the server's ±120s window, outside it.
        assert!(is_fptn_session_id(&sid, now + 100));
        assert!(!is_fptn_session_id(&sid, now + 400));
        // A random id must not validate.
        let mut other = [0u8; 32];
        other[31] = 1;
        assert!(!is_fptn_session_id(&other, now));
    }

    #[test]
    fn md5_pin_matches_reference_format() {
        // Self-signed certificate bytes are not needed: digest stability is
        // what matters. A fixed input must produce the lowercase hex MD5.
        let cert = CertificateDer::from(b"not-a-cert".to_vec());
        let got = md5_hex(&cert).expect("digest");
        assert_eq!(got.len(), 32);
        assert!(
            got.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
        assert_eq!(got, "b29f43a593199f75d5aff6a58495d874");
    }

    /// The whole injection scheme hinges on rustls asking its `SecureRandom`
    /// for the 32-byte session id first; if a rustls upgrade ever changes
    /// that order this test fails before the server would.
    #[test]
    fn client_hello_carries_injected_session_id() {
        let sid = fptn_session_id(1_760_000_000);
        let state = acquire(sid);
        let config = client_config("", state).expect("config");
        let name = server_name("192.0.2.1").expect("server name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("connection");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write client hello");
        assert!(!buf.is_empty(), "rustls produced no handshake bytes");
        let hello = core_tls::hello::parse_record(&buf).expect("parse client hello");
        assert_eq!(
            hello.session_id.as_slice(),
            &sid,
            "session id was not the injected FPTN id"
        );
        release(state);
    }

    /// Manual wire probe: dump the exact ClientHello we emit and whatever the
    /// server answers. `cargo test -p core-runtime fptn::tls::tests::probe -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn probe_wire() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let server: SocketAddr = std::env::var("FPTN_SERVER")
            .unwrap_or_else(|_| "185.138.89.132:443".to_string())
            .parse()
            .expect("addr");
        let sid = fptn_session_id(unix_now());
        let state = acquire(sid);
        let config = client_config("", state).expect("config");
        let name = server_name("").expect("name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("conn");
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).expect("hello");
        let parsed = core_tls::hello::parse_record(&hello).expect("parse");
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        eprintln!("hello bytes = {}", hello.len());
        eprintln!("session_id len = {}", parsed.session_id.len());
        eprintln!("wire tail   = {}", hex(&parsed.session_id[28..]));
        eprintln!("expected    = {}", hex(&sid[28..]));
        eprintln!("sni = {:?}", parsed.sni);

        let mut sock = tokio::net::TcpStream::connect(server).await.expect("tcp");
        sock.write_all(&hello).await.expect("write hello");
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(std::time::Duration::from_secs(15), sock.read(&mut buf)).await {
            Ok(Ok(0)) => eprintln!("== server closed with no data"),
            Ok(Ok(n)) => eprintln!("== server sent {n} bytes: {}", hex(&buf[..n.min(48)])),
            Ok(Err(e)) => eprintln!("== read error: {e}"),
            Err(_) => eprintln!("== read timed out (no data)"),
        }
    }

    /// Same ClientHello, wrapped in the official TlsObfuscator2 framing —
    /// the server then skips the session-id / probing checks entirely.
    /// Decisive test for "plain path is filtered" vs "session id rejected".
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn probe_obfuscated() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let server: SocketAddr = std::env::var("FPTN_SERVER")
            .unwrap_or_else(|_| "185.138.89.132:443".to_string())
            .parse()
            .expect("addr");
        let sid = fptn_session_id(unix_now());
        let state = acquire(sid);
        let config = client_config("", state).expect("config");
        let name = server_name("").expect("name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("conn");
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).expect("hello");

        // TlsObfuscator2 frame: 22-byte header + xored payload + random padding.
        let payload_len = hello.len() as u16;
        let padding_len: u16 = 4095;
        let mut random_data = [0u8; 8];
        crate::outbound::shadowsocks::crypto::random_bytes(&mut random_data).expect("rand");
        let xor_key = 0x5Au8;
        let content_length = 17u16 + payload_len + padding_len;
        let mut frame = Vec::with_capacity(22 + hello.len() + padding_len as usize);
        frame.push(0x17);
        frame.push(0x03);
        frame.push(0x03);
        frame.extend_from_slice(&content_length.to_be_bytes());
        frame.extend_from_slice(&random_data);
        frame.extend_from_slice(&unix_now().to_be_bytes());
        frame.push(xor_key);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&padding_len.to_be_bytes());
        frame.extend(hello.iter().map(|b| b ^ xor_key));
        let mut pad = vec![0u8; padding_len as usize];
        crate::outbound::shadowsocks::crypto::random_bytes(&mut pad).expect("rand");
        frame.extend_from_slice(&pad);

        let mut sock = tokio::net::TcpStream::connect(server).await.expect("tcp");
        sock.write_all(&frame).await.expect("write frame");
        let mut buf = vec![0u8; 65536];
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        match tokio::time::timeout(std::time::Duration::from_secs(15), sock.read(&mut buf)).await {
            Ok(Ok(0)) => eprintln!("== server closed with no data"),
            Ok(Ok(n)) => {
                eprintln!("== server sent {n} bytes: {}", hex(&buf[..n.min(32)]));
                if n >= 22 {
                    let key = buf[14];
                    let payload = u16::from_be_bytes([buf[18], buf[19]]) as usize;
                    if n >= 22 + payload {
                        let plain: Vec<u8> =
                            buf[22..22 + payload].iter().map(|b| b ^ key).collect();
                        eprintln!(
                            "== deobfuscated {} bytes: {}",
                            plain.len(),
                            hex(&plain[..plain.len().min(16)])
                        );
                    }
                }
            }
            Ok(Err(e)) => eprintln!("== read error: {e}"),
            Err(_) => eprintln!("== read timed out (no data)"),
        }
    }

    /// Wire-level trace of a full obfuscated login attempt: handshake, flush,
    /// flip to plain, POST — every socket byte is logged (obfuscated frames
    /// carry content_length >= 4095+17, plain TLS/HTTP records are short).
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn probe_obfs_post() {
        use crate::inbound::AnyStream;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

        struct Tap<S> {
            inner: S,
            log: Arc<Mutex<Vec<String>>>,
        }
        impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let me = self.get_mut();
                let before = buf.filled().len();
                let out = Pin::new(&mut me.inner).poll_read(cx, buf);
                if let Poll::Ready(Ok(())) = &out {
                    let n = buf.filled().len() - before;
                    if n > 0 {
                        let hex: String = buf.filled()[before..]
                            .iter()
                            .take(32)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        me.log.lock().expect("log").push(format!("R {n:6} {hex}"));
                    }
                }
                out
            }
        }
        impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let me = self.get_mut();
                let n = buf.len();
                let hex: String = buf.iter().take(32).map(|b| format!("{b:02x}")).collect();
                me.log.lock().expect("log").push(format!("W {n:6} {hex}"));
                Pin::new(&mut me.inner).poll_write(cx, buf)
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }

        let server: SocketAddr = std::env::var("FPTN_SERVER")
            .unwrap_or_else(|_| "185.138.89.132:443".to_string())
            .parse()
            .expect("addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let state = acquire(fptn_session_id(unix_now()));
        let _armed = ArmedGuard(state);
        let config = client_config("", state).expect("config");
        let name = server_name("").expect("name");
        let tcp = TcpStream::connect(server).await.expect("tcp");
        let _ = tcp.set_nodelay(true);
        let tap = Tap {
            inner: tcp,
            log: Arc::clone(&log),
        };
        let (obfs, plain) = ObfsStream::new(tap);
        let mut tls = TlsConnector::from(config)
            .connect(name, Box::new(obfs) as AnyStream)
            .await
            .expect("handshake");
        eprintln!("== handshake done");
        log.lock().expect("log").push("STEP handshake_done".into());
        // Push any bytes rustls buffered at the end of the handshake while the
        // obfuscator is still armed (upstream flushes before nulling it too).
        tokio::time::timeout(std::time::Duration::from_secs(5), tls.flush())
            .await
            .expect("flush timeout")
            .expect("flush");
        eprintln!("== flushed in obfuscated mode");
        log.lock().expect("log").push("STEP flushed_obfs".into());
        plain.store(true, Ordering::Relaxed);
        log.lock().expect("log").push("STEP flipped_plain".into());
        let alpn = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        eprintln!("== negotiated alpn = {alpn:?}");
        let delay: u64 = std::env::var("FPTN_POST_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if delay > 0 {
            eprintln!("== delaying POST by {delay}ms");
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        let body = r#"{"username":"probe","password":"probe"}"#;
        let request = format!(
            "POST /api/v1/login HTTP/1.1\r\nHost: {server}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        log.lock().expect("log").push("STEP writing_post".into());
        tls.write_all(request.as_bytes()).await.expect("write post");
        log.lock().expect("log").push("STEP post_written".into());
        tls.flush().await.expect("post flush");
        eprintln!("== POST written, reading...");
        let mut head = vec![0u8; 16384];
        match tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut head)).await {
            Ok(Ok(0)) => eprintln!("== read EOF"),
            Ok(Ok(n)) => {
                let text = String::from_utf8_lossy(&head[..n]);
                eprintln!("== decrypted {n} bytes: {:?}", &text[..text.len().min(400)]);
            }
            Ok(Err(e)) => eprintln!("== read error: {e}"),
            Err(_) => eprintln!("== read timed out"),
        }
        eprintln!("== wire log:");
        for entry in log.lock().expect("log").iter() {
            eprintln!("   {entry}");
        }
    }
}
