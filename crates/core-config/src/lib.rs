pub mod validate;
pub mod vless_enc;

use serde::Deserialize;
use serde_json::Value;

/// Top-level sing-box configuration.
///
/// The schema is intentionally permissive at this stage: every sing-box
/// section is preserved verbatim so the compatibility matrix (COMPAT.md)
/// can be tightened field by field without losing information.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbounds: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbounds: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_clients: Option<Vec<Value>>,
}

pub fn parse_str(raw: &str) -> Result<Config, serde_json::Error> {
    serde_json::from_str(raw)
}

pub fn parse_slice(bytes: &[u8]) -> Result<Config, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Full `sing-box check` equivalent: schema parse + semantic validation.
pub fn check_str(raw: &str) -> Result<(), String> {
    parse_str(raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    validate::validate(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg = parse_str(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct"}]}"#).unwrap();
        let outbounds = cfg.outbounds.unwrap();
        assert_eq!(outbounds.len(), 1);
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse_str("{not json").is_err());
    }

    #[test]
    fn preserves_unknown_sections() {
        let cfg = parse_str(r#"{"futureSection":{"a":1},"inbounds":[]}"#).unwrap();
        assert!(cfg.inbounds.is_some());
    }
}
