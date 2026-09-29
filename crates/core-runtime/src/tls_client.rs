//! Outbound TLS client: rustls with the pure-Rust crypto provider.
//!
//! uTLS fingerprints and REALITY land in F2 (ADR-0004); uTLS degrades with a
//! warning, REALITY is rejected because silent fallback would be misleading.

use std::io;
use std::sync::Arc;

use core_tls::rustls;
use rustls_pemfile::certs;
use rustls_pemfile::private_key;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::inbound::AnyStream;
use crate::logging;

const DANGEROUS_SCHEMES: &[rustls::SignatureScheme] = &[
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

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        DANGEROUS_SCHEMES.to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct TlsOptions {
    server_name: String,
    insecure: bool,
    disable_sni: bool,
    alpn: Vec<Vec<u8>>,
    min_tls13: bool,
    max_tls12: bool,
    ca_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl TlsOptions {
    /// SNI / certificate name (config `server_name`, defaulting to the server).
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Parse outbound `tls` options; `None` when TLS is absent or disabled.
    pub fn from_outbound(
        obj: &serde_json::Map<String, Value>,
        server: &str,
        at: &str,
    ) -> anyhow::Result<Option<Self>> {
        let Some(tls) = obj.get("tls").and_then(Value::as_object) else {
            return Ok(None);
        };
        if tls.get("enabled").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }

        let server_name = tls
            .get("server_name")
            .and_then(Value::as_str)
            .unwrap_or(server)
            .to_string();
        let insecure = tls
            .get("insecure")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let disable_sni = tls
            .get("disable_sni")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let alpn = tls
            .get("alpn")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|v| v.as_str().map(str::as_bytes).map(<[u8]>::to_vec))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| anyhow::anyhow!("{at}: tls.alpn entries must be strings"))
            })
            .transpose()?
            .unwrap_or_default();

        let min_tls13 = match tls.get("min_version").and_then(Value::as_str) {
            None | Some("") => false,
            Some("1.2") => false,
            Some("1.3") => true,
            Some(other) => anyhow::bail!("{at}: tls.min_version {other:?} not supported"),
        };
        let max_tls12 = match tls.get("max_version").and_then(Value::as_str) {
            None | Some("") => false,
            Some("1.2") => true,
            Some("1.3") => false,
            Some(other) => anyhow::bail!("{at}: tls.max_version {other:?} not supported"),
        };

        let mut ca_certs = Vec::new();
        if let Some(pem) = tls.get("certificate").and_then(Value::as_str) {
            load_pem_certs(pem.as_bytes(), &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate: {e}"))?;
        }
        if let Some(path) = tls.get("certificate_path").and_then(Value::as_str) {
            let raw = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
            load_pem_certs(&raw, &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
        }

        if tls
            .get("utls")
            .and_then(Value::as_object)
            .is_some_and(|u| u.get("enabled").and_then(Value::as_bool) == Some(true))
        {
            logging::warn(format_args!(
                "{at}: uTLS fingerprinting is not implemented yet (F2); using plain TLS"
            ));
        }
        if tls
            .get("reality")
            .and_then(Value::as_object)
            .is_some_and(|r| r.get("enabled").and_then(Value::as_bool) == Some(true))
        {
            anyhow::bail!("{at}: REALITY is not implemented yet (F2)");
        }

        Ok(Some(Self {
            server_name,
            insecure,
            disable_sni,
            alpn,
            min_tls13,
            max_tls12,
            ca_certs,
        }))
    }

    pub async fn connect(&self, stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        self.connect_with_defaults(stream, &[]).await
    }

    /// TLS over any stream — the runtime fetches (rule-sets, providers) may
    /// be dialed through a proxy outbound, so the socket is not a `TcpStream`.
    pub async fn connect_stream<S>(
        &self,
        stream: S,
        default_alpn: &[&[u8]],
    ) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.handshake(stream, default_alpn).await
    }

    /// Like [`connect`], but offers `default_alpn` when the config set none —
    /// transports such as grpc/http need `h2` and sing-box injects it there.
    pub async fn connect_with_defaults(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
    ) -> io::Result<TlsStream<TcpStream>> {
        self.handshake(stream, default_alpn).await
    }

    async fn handshake<S>(&self, stream: S, default_alpn: &[&[u8]]) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.min_tls13 {
            &[&rustls::version::TLS13]
        } else if self.max_tls12 {
            &[&rustls::version::TLS12]
        } else {
            rustls::ALL_VERSIONS
        };

        let builder = rustls::ClientConfig::builder_with_protocol_versions(versions);
        let mut config = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(self.root_store()?)
                .with_no_client_auth()
        };
        if !self.alpn.is_empty() {
            config.alpn_protocols = self.alpn.clone();
        } else if !default_alpn.is_empty() {
            config.alpn_protocols = default_alpn.iter().map(|a| a.to_vec()).collect();
        }

        let connector = TlsConnector::from(Arc::new(config));
        let name = if self.disable_sni {
            rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::V4(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
            ))
        } else {
            rustls::pki_types::ServerName::try_from(self.server_name.clone()).map_err(|_| {
                io::Error::other(format!("invalid server_name {:?}", self.server_name))
            })?
        };
        connector.connect(name, stream).await
    }

    fn root_store(&self) -> io::Result<rustls::RootCertStore> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in &self.ca_certs {
            roots
                .add(cert.clone())
                .map_err(|e| io::Error::other(format!("bad CA certificate: {e}")))?;
        }
        Ok(roots)
    }

    /// QUIC client config for quinn (hysteria2 / tuic): TLS 1.3 only, early
    /// data on, ALPN from `tls.alpn` or `default_alpn`.
    pub fn quic_config(
        &self,
        default_alpn: &[&[u8]],
    ) -> io::Result<core_tls::quic::QuicClientConfig> {
        let builder =
            rustls::ClientConfig::builder_with_provider(core_tls::quic::configured_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| io::Error::other(format!("QUIC TLS provider: {e}")))?;
        let mut config = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(self.root_store()?)
                .with_no_client_auth()
        };
        if !self.alpn.is_empty() {
            config.alpn_protocols = self.alpn.clone();
        } else {
            config.alpn_protocols = default_alpn.iter().map(|a| a.to_vec()).collect();
        }
        config.enable_early_data = true;
        core_tls::quic::QuicClientConfig::try_from_rustls(Arc::new(config))
            .map_err(|e| io::Error::other(format!("QUIC initial suite: {e}")))
    }

    pub async fn wrap(&self, stream: TcpStream) -> io::Result<AnyStream> {
        Ok(Box::new(self.connect(stream).await?))
    }

    pub async fn wrap_with_defaults(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
    ) -> io::Result<AnyStream> {
        Ok(Box::new(
            self.connect_with_defaults(stream, default_alpn).await?,
        ))
    }
}

/// TLS wrap for runtime fetches without a `tls` block: any proxy stream, any
/// certificate (the reference fetches through the same accept-any path).
pub(crate) async fn wrap_probe_stream<S>(stream: S, server_name: &str) -> io::Result<AnyStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| io::Error::other(format!("invalid fetch server_name {server_name:?}")))?;
    Ok(Box::new(connector.connect(name, stream).await?))
}

/// TLS wrap for runtime probes (urltest): any proxy stream, any certificate.
pub(crate) async fn wrap_probe(stream: AnyStream, server_name: &str) -> io::Result<AnyStream> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| io::Error::other(format!("invalid probe server_name {server_name:?}")))?;
    Ok(Box::new(connector.connect(name, stream).await?))
}

fn load_pem_certs(
    mut pem: &[u8],
    out: &mut Vec<rustls::pki_types::CertificateDer<'static>>,
) -> io::Result<()> {
    for cert in certs(&mut pem) {
        out.push(cert.map_err(|e| io::Error::other(format!("bad PEM: {e}")))?);
    }
    Ok(())
}

/// Load a PEM private key (unused yet; inbound TLS server lands in F5).
#[allow(dead_code)]
fn load_pem_key(mut pem: &[u8]) -> io::Result<()> {
    private_key(&mut pem)?;
    Ok(())
}
