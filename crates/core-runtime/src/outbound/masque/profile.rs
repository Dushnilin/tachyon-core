//! MASQUE behaviour profiles (reference `transport/masque/profile.go`) and
//! key-material parsing.
//!
//! A profile selects the CONNECT-IP dial quirks: the `:protocol` value,
//! whether the server's `SETTINGS_ENABLE_CONNECT_PROTOCOL` is tolerated as
//! missing, the h2 `cf-connect-proto` header, default SNI/URI and whether the
//! endpoint is authenticated by public-key pinning instead of a certificate
//! chain.

use serde_json::{Map, Value};

use crate::outbound::shadowsocks::crypto::decode_base64_std;

use super::p256;

/// Cloudflare WARP MASQUE defaults.
pub(crate) const CLOUDFLARE_CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub(crate) const CLOUDFLARE_DEFAULT_SNI: &str = "www.cloudflare.com";
pub(crate) const CLOUDFLARE_CONNECT_URI: &str = "https://cloudflareaccess.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    /// `:protocol` of the Extended CONNECT request (`cf-connect-ip` for
    /// Cloudflare, `connect-ip` for RFC 9484).
    pub request_protocol: &'static str,
    /// Skip the "server enabled Extended CONNECT" check (WARP never sends
    /// the setting, violating the RFC).
    pub ignore_extended_connect: bool,
    /// Non-empty sends the HTTP/2 `cf-connect-proto` header (Cloudflare).
    pub h2_connect_proto: &'static str,
    pub default_sni: &'static str,
    pub default_uri: &'static str,
    /// Authenticate the endpoint by its ECDSA public key, not by a chain.
    pub pin_public_key: bool,
}

impl Profile {
    pub fn cloudflare() -> Self {
        Profile {
            request_protocol: "cf-connect-ip",
            ignore_extended_connect: true,
            h2_connect_proto: "cf-connect-ip",
            default_sni: CLOUDFLARE_DEFAULT_SNI,
            default_uri: CLOUDFLARE_CONNECT_URI,
            pin_public_key: true,
        }
    }

    pub fn standard() -> Self {
        Profile {
            request_protocol: "connect-ip",
            ignore_extended_connect: false,
            h2_connect_proto: "",
            default_sni: "",
            default_uri: "",
            pin_public_key: false,
        }
    }
}

/// Resolve a profile name; empty defaults to cloudflare (reference
/// `ParseProfile`).
pub(crate) fn parse_profile(name: &str) -> anyhow::Result<Profile> {
    match name {
        "" | "cloudflare" => Ok(Profile::cloudflare()),
        "standard" => Ok(Profile::standard()),
        other => anyhow::bail!("masque: unknown profile: {other}"),
    }
}

/// Parsed `private_key` / `public_key` material (base64 DER: SEC 1 via
/// `x509.ParseECPrivateKey`, PKIX via `x509.ParsePKIXPublicKey`).
#[derive(Clone, Debug, Default)]
pub(crate) struct MasqueKeys {
    /// EC private scalar, 32 bytes big-endian.
    pub scalar: Option<[u8; 32]>,
    /// Uncompressed public point `04 || X || Y`.
    pub point: Option<Vec<u8>>,
}

pub(crate) fn parse_keys(
    obj: &Map<String, Value>,
    profile: &Profile,
    at: &str,
) -> anyhow::Result<MasqueKeys> {
    let priv_raw = obj
        .get("private_key")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let pub_raw = obj
        .get("public_key")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());

    if profile.pin_public_key && (priv_raw.is_none() || pub_raw.is_none()) {
        anyhow::bail!(
            "{at}: masque: private_key and public_key are required for the cloudflare profile"
        );
    }

    let mut keys = MasqueKeys::default();
    if let Some(raw) = priv_raw {
        let der =
            decode_base64_std(raw).map_err(|e| anyhow::anyhow!("{at}: parse private_key: {e}"))?;
        let scalar = p256::sec1_scalar(&der)
            .map_err(|_| anyhow::anyhow!("{at}: parse private_key: invalid EC private key"))?;
        if scalar.len() > 32 && scalar[..scalar.len() - 32].iter().any(|&b| b != 0) {
            anyhow::bail!("{at}: parse private_key: scalar out of range");
        }
        let mut arr = [0u8; 32];
        let tail = &scalar[scalar.len().saturating_sub(32)..];
        arr[32 - tail.len()..].copy_from_slice(tail);
        // Validate the scalar (zero / >= n rejected) by deriving its point.
        p256::derive_public_key(&arr)
            .map_err(|e| anyhow::anyhow!("{at}: parse private_key: {e}"))?;
        keys.scalar = Some(arr);
    }
    if let Some(raw) = pub_raw {
        let der =
            decode_base64_std(raw).map_err(|e| anyhow::anyhow!("{at}: parse public_key: {e}"))?;
        let point = p256::pkix_point(&der)
            .map_err(|_| anyhow::anyhow!("{at}: parse public_key: invalid PKIX public key"))?;
        if point.len() != 65 || point.first() != Some(&0x04) {
            anyhow::bail!("{at}: parse public_key: public_key is not an ECDSA key");
        }
        keys.point = Some(point);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "masque",
            "server": "1.2.3.4",
            "server_port": 443,
            "ip": "172.16.0.2",
        })
        .as_object()
        .unwrap()
        .clone();
        if let Value::Object(m) = extra {
            for (k, v) in m {
                base.insert(k, v);
            }
        }
        base
    }

    #[test]
    fn parse_profile_names() {
        assert_eq!(parse_profile("").unwrap().request_protocol, "cf-connect-ip");
        assert_eq!(
            parse_profile("cloudflare").unwrap().request_protocol,
            "cf-connect-ip"
        );
        assert_eq!(
            parse_profile("standard").unwrap().request_protocol,
            "connect-ip"
        );
        assert!(parse_profile("other").is_err());
    }

    #[test]
    fn cloudflare_requires_both_keys() {
        let profile = parse_profile("cloudflare").unwrap();
        let e = parse_keys(&obj(json!({})), &profile, "outbounds[0]").unwrap_err();
        assert!(e.to_string().contains("private_key and public_key"));
    }

    #[test]
    fn standard_accepts_absent_keys() {
        let profile = parse_profile("standard").unwrap();
        let keys = parse_keys(&obj(json!({})), &profile, "outbounds[0]").unwrap();
        assert!(keys.scalar.is_none());
        assert!(keys.point.is_none());
    }
}
