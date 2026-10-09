//! ShadowTLS client outbound (v2 and v3).
//!
//! Impersonates a legitimate TLS server (e.g. gateway.icloud.com) via ClientHello
//! SNI, embedding authentication in the Session ID (HMAC-SHA1 of password).
//! Once verified, the ShadowTLS server transparently proxies payload to upstream.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::{AnyStream, Target};
use crate::outbound::dial::{self, DialOptions};
use crate::outbound::proxy::server_endpoint;
use crate::tls_client::TlsOptions;

type HmacSha1 = Hmac<Sha1>;

pub struct ShadowTls {
    tag: String,
    server: String,
    port: u16,
    version: u8,
    password: String,
    tls: Option<TlsOptions>,
    dial: DialOptions,
}

impl ShadowTls {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("shadowtls")
            .to_string();

        let (server, port) = server_endpoint(obj, at)?;

        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?
            .to_string();

        let version = match obj.get("version").and_then(Value::as_u64) {
            Some(2) => 2,
            Some(3) | None => 3,
            Some(v) => anyhow::bail!("{at}: unsupported shadowtls version {v} (expected 2 or 3)"),
        };

        let tls = TlsOptions::from_outbound(obj, &server, at)?;
        let dial = DialOptions::parse(obj)?;

        Ok(Self {
            tag,
            server,
            port,
            version,
            password,
            tls,
            dial,
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    /// Dial the ShadowTLS server, perform the stealth ClientHello handshake, and return the stream.
    pub async fn connect(&self, _target: &Target) -> io::Result<AnyStream> {
        let mut stream = dial::connect_tcp(&self.server, self.port, &self.dial).await?;

        let sni = self
            .tls
            .as_ref()
            .map(|t| t.server_name())
            .unwrap_or(&self.server);

        let client_hello = self.build_client_hello(sni)?;
        stream.write_all(&client_hello).await?;
        stream.flush().await?;

        // Read ServerHello header (5 bytes: 0x16 0x03 0x03 len)
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shadowtls: expected ServerHello record 0x16",
            ));
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; record_len];
        stream.read_exact(&mut body).await?;

        // Handshake succeeded; the stream is now directly connected to the upstream proxy/service
        Ok(Box::new(stream))
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        // UDP over TCP tunnel
        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let stream = self.connect(target).await?;
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut buf_in = vec![0u8; 65535];
            let mut buf_out = vec![0u8; 65535];
            loop {
                tokio::select! {
                    res = peer.recv(&mut buf_in) => {
                        let Ok(n) = res else { break };
                        if (writer.write_all(&buf_in[..n]).await).is_err() {
                            break;
                        }
                    }
                    res = reader.read(&mut buf_out) => {
                        let Ok(n) = res else { break };
                        if n == 0 || (peer.send(&buf_out[..n]).await).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(local)
    }

    /// Construct a TLS 1.3 ClientHello record carrying the ShadowTLS Session ID authentication.
    pub fn build_client_hello(&self, sni: &str) -> io::Result<Vec<u8>> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;

        let session_id = match self.version {
            2 => build_session_id_v2(&self.password, &random),
            _ => build_session_id_v3(&self.password, &random, sni.as_bytes()),
        }?;

        build_tls_client_hello(sni, &random, &session_id)
    }
}

/// ShadowTLS v2: Session ID contains HMAC-SHA1 of challenge random bytes + timestamp + random.
pub fn build_session_id_v2(password: &str, random: &[u8; 32]) -> io::Result<[u8; 32]> {
    let mut mac = HmacSha1::new_from_slice(password.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    mac.update(&random[..16]);
    let hmac = mac.finalize().into_bytes();

    let mut session_id = [0u8; 32];
    session_id[..20].copy_from_slice(&hmac);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    session_id[20..24].copy_from_slice(&now.to_be_bytes());

    let mut tail = [0u8; 8];
    getrandom::fill(&mut tail).map_err(|e| io::Error::other(e.to_string()))?;
    session_id[24..32].copy_from_slice(&tail);

    Ok(session_id)
}

/// ShadowTLS v3: First 28 bytes random, last 4 bytes HMAC-SHA1 of password over prefix.
pub fn build_session_id_v3(password: &str, random: &[u8; 32], sni: &[u8]) -> io::Result<[u8; 32]> {
    let mut session_id = [0u8; 32];
    session_id[..28].copy_from_slice(&random[..28]);

    let mut mac = HmacSha1::new_from_slice(password.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    mac.update(&session_id[..28]);
    mac.update(sni);
    let hmac = mac.finalize().into_bytes();

    session_id[28..32].copy_from_slice(&hmac[..4]);
    Ok(session_id)
}

/// Build a standard TLS 1.3 ClientHello record with SNI, ALPN, Supported Versions, and Session ID.
fn build_tls_client_hello(sni: &str, random: &[u8; 32], session_id: &[u8; 32]) -> io::Result<Vec<u8>> {
    let mut handshake = Vec::new();

    // Client version: TLS 1.2 compatibility
    handshake.extend_from_slice(&[0x03, 0x03]);
    // Random (32 bytes)
    handshake.extend_from_slice(random);

    // Legacy Session ID (32 bytes)
    handshake.push(32);
    handshake.extend_from_slice(session_id);

    // Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    let cipher_suites: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
    handshake.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&cipher_suites);

    // Legacy compression methods: 1 byte [0x00]
    handshake.push(1);
    handshake.push(0x00);

    // Extensions
    let mut extensions = Vec::new();

    // 1. SNI Extension (0x0000)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    let server_name_list_len = (sni_bytes.len() + 3) as u16;
    sni_ext.extend_from_slice(&server_name_list_len.to_be_bytes());
    sni_ext.push(0x00); // host_name type
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // 2. Supported Versions (0x002b) -> TLS 1.3 (0x0304)
    let supported_versions = [0x02, 0x03, 0x04];
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&supported_versions);

    // 3. ALPN Extension (0x0010) -> h2, http/1.1
    let alpn = [0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'];
    extensions.extend_from_slice(&0x0010u16.to_be_bytes());
    extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&alpn);

    // Append extensions length and extensions
    handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&extensions);

    // Wrap in Handshake header (type 1 = ClientHello, 3-byte length)
    let mut msg = Vec::new();
    msg.push(0x01); // ClientHello
    let hs_len = handshake.len() as u32;
    msg.push((hs_len >> 16) as u8);
    msg.push((hs_len >> 8) as u8);
    msg.push(hs_len as u8);
    msg.extend_from_slice(&handshake);

    // Wrap in TLS Record (type 0x16 = Handshake, version 0x0301, 2-byte length)
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version for compatibility
    record.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    record.extend_from_slice(&msg);

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shadowtls_build_valid() {
        let val = json!({
            "type": "shadowtls",
            "tag": "stls",
            "server": "127.0.0.1",
            "server_port": 443,
            "version": 3,
            "password": "secret-password",
            "tls": { "enabled": true, "server_name": "gateway.icloud.com" }
        });
        let stls = ShadowTls::build(val.as_object().unwrap(), "outbounds[0]").unwrap();
        assert_eq!(stls.tag(), "stls");
        assert_eq!(stls.server(), "127.0.0.1");
        assert_eq!(stls.port(), 443);
        assert_eq!(stls.version(), 3);
    }

    #[test]
    fn shadowtls_build_missing_password() {
        let val = json!({
            "type": "shadowtls",
            "tag": "stls",
            "server": "127.0.0.1",
            "server_port": 443
        });
        assert!(ShadowTls::build(val.as_object().unwrap(), "outbounds[0]").is_err());
    }

    #[test]
    fn shadowtls_client_hello_format() {
        let val = json!({
            "type": "shadowtls",
            "server": "1.2.3.4",
            "server_port": 8443,
            "version": 3,
            "password": "test",
            "tls": { "enabled": true, "server_name": "example.com" }
        });
        let stls = ShadowTls::build(val.as_object().unwrap(), "outbounds[0]").unwrap();
        let hello = stls.build_client_hello("example.com").unwrap();
        assert!(hello.len() > 64);
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);
        assert_eq!(hello[5], 0x01); // ClientHello handshake type
    }
}
