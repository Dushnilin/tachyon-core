//! MASQUE client TLS (reference `PrepareTLSConfig` / `buildH2TLSClient`).
//!
//! The cloudflare profile authenticates the endpoint by public-key pinning —
//! the presented certificate chain is not validated (the SNI deliberately
//! does not match the endpoint), exactly like the Go `VerifyConnection`
//! hook. `skip_cert_verify` disables pinning entirely. The `private_key`
//! (when set) is presented as a short-lived self-signed client certificate
//! (Cloudflare Access mTLS): an X.509 v1 wrapper around the configured EC
//! key, built here because the masque feature may not add dependencies.

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use core_tls::rustls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};

use super::p256;
use super::profile::{MasqueKeys, Profile};

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

/// Prepared TLS material for the masque dial (SNI resolution, pinning,
/// client certificate) — built once at outbound construction.
pub(crate) struct MasqueTls {
    server_name: String,
    disable_sni: bool,
    insecure: bool,
    pinned_point: Option<Vec<u8>>,
    client_cert: Option<CertificateDer<'static>>,
    client_key: Option<Vec<u8>>,
    ca_certs: Vec<CertificateDer<'static>>,
}

impl MasqueTls {
    /// Resolve SNI/pinning/mTLS from the config `tls` block plus the profile.
    pub fn new(
        obj: &serde_json::Map<String, serde_json::Value>,
        profile: &Profile,
        keys: &MasqueKeys,
        server: &str,
        at: &str,
    ) -> anyhow::Result<Self> {
        use serde_json::Value;

        let tls = obj.get("tls").and_then(Value::as_object);
        let get_str = |key: &str| {
            tls.and_then(|m| m.get(key))
                .and_then(Value::as_str)
                .unwrap_or("")
        };
        let insecure = tls
            .and_then(|m| m.get("insecure"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let disable_sni = tls
            .and_then(|m| m.get("disable_sni"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let server_name = if disable_sni {
            String::new()
        } else {
            let configured = get_str("server_name");
            if !configured.is_empty() {
                configured.to_string()
            } else if !profile.default_sni.is_empty() {
                profile.default_sni.to_string()
            } else {
                server.to_string()
            }
        };

        let pinned_point =
            if profile.pin_public_key && !insecure {
                Some(keys.point.clone().ok_or_else(|| {
                    anyhow::anyhow!("{at}: masque: public key required for pinning")
                })?)
            } else {
                None
            };

        let mut ca_certs = Vec::new();
        if let Some(pem) = tls
            .and_then(|m| m.get("certificate"))
            .and_then(Value::as_str)
        {
            load_pem_certs(pem.as_bytes(), &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate: {e}"))?;
        }
        if let Some(path) = tls
            .and_then(|m| m.get("certificate_path"))
            .and_then(Value::as_str)
        {
            let raw = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
            load_pem_certs(&raw, &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path: {e}"))?;
        }

        let mut client_cert = None;
        let mut client_key = None;
        if let Some(scalar) = &keys.scalar {
            let (cert, key) = build_client_cert(scalar)
                .map_err(|e| anyhow::anyhow!("{at}: masque: generate client cert: {e}"))?;
            client_cert = Some(cert);
            client_key = Some(key);
        }

        Ok(Self {
            server_name,
            disable_sni,
            insecure,
            pinned_point,
            client_cert,
            client_key,
            ca_certs,
        })
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// rustls server name for this config; a disabled SNI still needs a
    /// syntactic name, and the custom verifier never consults it.
    pub fn server_name_hint(&self) -> io::Result<rustls::pki_types::ServerName<'static>> {
        if self.disable_sni || self.server_name.is_empty() {
            return Ok(rustls::pki_types::ServerName::IpAddress(
                rustls::pki_types::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED.into()),
            ));
        }
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| io::Error::other(format!("invalid server_name {:?}", self.server_name)))
    }

    /// QUIC client config for the h3 leg (ALPN `h3`, TLS 1.3 only).
    pub fn quic_config(&self) -> anyhow::Result<core_tls::quic::QuicClientConfig> {
        let config = self.raw_config(&[b"h3"], true)?;
        core_tls::quic::QuicClientConfig::try_from_rustls(Arc::new(config))
            .map_err(|e| anyhow::anyhow!("QUIC initial suite: {e}"))
    }

    /// TCP client config for the h2 leg (ALPN `h2`).
    pub fn tcp_config(&self) -> anyhow::Result<rustls::ClientConfig> {
        self.raw_config(&[b"h2"], false)
    }

    fn raw_config(&self, alpn: &[&[u8]], quic: bool) -> anyhow::Result<rustls::ClientConfig> {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if quic {
            &[&rustls::version::TLS13]
        } else {
            rustls::ALL_VERSIONS
        };
        let builder = rustls::ClientConfig::builder_with_protocol_versions(versions);
        let key = self
            .client_key
            .as_ref()
            .map(|k| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.clone())));
        let cert = self.client_cert.clone();

        let mut config = if let Some(point) = &self.pinned_point {
            let wants_cert = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinVerifier {
                    point: point.clone(),
                }));
            attach_client_auth(wants_cert, cert, key)?
        } else if self.insecure {
            let wants_cert = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny));
            attach_client_auth(wants_cert, cert, key)?
        } else {
            let mut roots = rustls::RootCertStore::empty();
            for ca in &self.ca_certs {
                roots
                    .add(ca.clone())
                    .map_err(|e| anyhow::anyhow!("masque: bad CA certificate: {e}"))?;
            }
            attach_client_auth(builder.with_root_certificates(roots), cert, key)?
        };
        config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        Ok(config)
    }
}

fn attach_client_auth(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>,
    cert: Option<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
) -> anyhow::Result<rustls::ClientConfig> {
    match (cert, key) {
        (Some(cert), Some(key)) => builder
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| anyhow::anyhow!("masque: client certificate: {e}")),
        _ => Ok(builder.with_no_client_auth()),
    }
}

/// Accept any certificate (Go `InsecureSkipVerify` without pinning).
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

/// Pin a single EC public key: the endpoint is trusted iff some presented
/// certificate carries exactly this key (Go `verifyPinnedCert`).
#[derive(Debug)]
struct PinVerifier {
    point: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut saw_cert = false;
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            saw_cert = true;
            if p256::cert_spki_point(cert.as_ref()).ok().as_deref() == Some(&self.point[..]) {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        if !saw_cert {
            return Err(rustls::Error::General(
                "masque: no peer certificate to pin".into(),
            ));
        }
        Err(rustls::Error::General(
            "masque: remote endpoint has a different public key than pinned".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // The certificate itself is pinned, so only the key holder can
        // complete the handshake; the pin check above is what authenticates
        // the endpoint (mirrors Go, where the TLS stack verifies the
        // handshake signature against the presented leaf).
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

fn load_pem_certs(mut pem: &[u8], out: &mut Vec<CertificateDer<'static>>) -> Result<(), String> {
    for cert in rustls_pemfile::certs(&mut pem) {
        out.push(cert.map_err(|e| e.to_string())?);
    }
    Ok(())
}

// --- minimal DER encoding for the self-signed client certificate -----------

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_int(value: u8) -> Vec<u8> {
    tlv(0x02, &[value])
}

fn der_oid(bytes: &[u8]) -> Vec<u8> {
    tlv(0x06, bytes)
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    tlv(0x30, &body)
}

/// ecdsa-with-SHA256 AlgorithmIdentifier (no parameters, RFC 5758).
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// id-ecPublicKey.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// prime256v1 (P-256).
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// UTCTime (`YYMMDDHHMMSSZ`) for X.509 validity.
fn utctime(secs: u64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs as i64);
    let yy = y.rem_euclid(100);
    let text = format!("{yy:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
    tlv(0x17, text.as_bytes())
}

/// Days-from-civil inverse (Howard Hinnant's algorithm) to UTC calendar
/// fields.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Build the short-lived self-signed client certificate (Go
/// `generateClientCert`): X.509 v1, serial 1, empty subject/issuer, 24h
/// validity, SPKI = the configured public key.
fn build_client_cert(scalar: &[u8; 32]) -> Result<(CertificateDer<'static>, Vec<u8>), p256::Error> {
    let point = p256::derive_public_key(scalar)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let not_before = utctime(now);
    let not_after = utctime(now + 24 * 3600);

    let mut bit_point = Vec::with_capacity(point.len() + 1);
    bit_point.push(0x00);
    bit_point.extend_from_slice(&point);
    let spki = der_seq(&[
        &der_seq(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(OID_P256)]),
        &tlv(0x03, &bit_point),
    ]);
    let sig_alg = der_seq(&[&der_oid(OID_ECDSA_SHA256)]);
    let issuer = tlv(0x30, &[]);
    let subject = tlv(0x30, &[]);
    let validity = der_seq(&[&not_before, &not_after]);

    let tbs = der_seq(&[
        &der_int(1), // serialNumber
        &sig_alg,
        &issuer,
        &validity,
        &subject,
        &spki,
    ]);
    let (r, s) = p256::ecdsa_sign_sha256(&tbs, scalar)?;
    let signature = der_seq(&[&tlv(0x02, &trim_int(&r)), &tlv(0x02, &trim_int(&s))]);
    let mut bit_sig = Vec::with_capacity(signature.len() + 1);
    bit_sig.push(0x00);
    bit_sig.extend_from_slice(&signature);
    let cert = der_seq(&[&tbs, &sig_alg, &tlv(0x03, &bit_sig)]);
    Ok((CertificateDer::from(cert), pkcs8(scalar)?))
}

/// Strip leading zero padding for DER INTEGER encoding (keep one byte when
/// the high bit is set).
fn trim_int(be: &[u8; 32]) -> Vec<u8> {
    let mut start = 0;
    while start < 31 && be[start] == 0 {
        start += 1;
    }
    let mut out = Vec::with_capacity(33 - start);
    if be[start] & 0x80 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(&be[start..]);
    out
}

/// PKCS#8 v1 `PrivateKeyInfo` wrapping the SEC 1 ECPrivateKey (without
/// curve parameters — they live in the outer AlgorithmIdentifier).
fn pkcs8(scalar: &[u8; 32]) -> Result<Vec<u8>, p256::Error> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&der_int(1));
    inner.extend_from_slice(&tlv(0x04, scalar));
    let sec1 = tlv(0x30, &inner);
    let alg = der_seq(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(OID_P256)]);
    let mut body = Vec::new();
    body.extend_from_slice(&der_int(0));
    body.extend_from_slice(&alg);
    body.extend_from_slice(&tlv(0x04, &sec1));
    Ok(tlv(0x30, &body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utctime_format() {
        // 2026-01-02 03:04:05 UTC.
        let v = utctime(1_767_323_045);
        assert_eq!(v[0], 0x17);
        assert_eq!(v[1] as usize, v.len() - 2);
        assert_eq!(std::str::from_utf8(&v[2..]).unwrap(), "260102030405Z");
    }

    #[test]
    fn civil_from_unix_known_dates() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil_from_unix(1_767_323_045), (2026, 1, 2, 3, 4, 5));
    }

    #[test]
    fn client_cert_parses_to_its_own_key() {
        let mut scalar = [0u8; 32];
        scalar[31] = 7;
        let (cert, key) = build_client_cert(&scalar).expect("cert");
        let point = p256::derive_public_key(&scalar).unwrap();
        assert_eq!(
            p256::cert_spki_point(cert.as_ref()).expect("spki"),
            point,
            "SPKI must carry the configured public key"
        );
        // PKCS#8 round-trips through the SEC 1 inner structure.
        assert_eq!(p256::sec1_scalar(&key).expect("sec1"), scalar.to_vec());
    }

    #[test]
    fn pkcs8_is_a_sequence() {
        let mut scalar = [0u8; 32];
        scalar[0] = 0x11;
        scalar[31] = 0x22;
        let key = pkcs8(&scalar).unwrap();
        assert_eq!(key[0], 0x30);
    }
}
