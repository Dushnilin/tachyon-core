//! FPTN token outbounds: parse `fptn:`/`fptnb:` subscription tokens and
//! expand a token outbound into per-server outbounds plus a urltest group —
//! the same node set a subscription loader would produce.

use std::collections::HashSet;
use std::io::Read as _;

use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::validate::DIALER_OUT_FIELDS;

/// One `servers[]` entry of a decoded FPTN token.
#[derive(Debug)]
pub struct FptnServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub md5_fingerprint: String,
}

/// Decoded FPTN token payload. `censored_zone_servers` follows the official
/// client: accepted in the token and ignored.
#[derive(Debug)]
pub struct FptnToken {
    pub service_name: String,
    pub username: String,
    pub password: String,
    pub servers: Vec<FptnServer>,
}

fn want_string(value: Option<&Value>, ctx: &str) -> Result<String, String> {
    match value {
        Some(Value::String(s)) => Ok(s.clone()),
        None | Some(Value::Null) => Err(format!("missing {ctx}")),
        Some(_) => Err(format!("{ctx}: must be a string")),
    }
}

fn decode_token(token: &str) -> Result<Vec<u8>, String> {
    let trimmed = token.trim();
    let (body, compressed) = if let Some(body) = trimmed.strip_prefix("fptnb:") {
        (body, true)
    } else if let Some(body) = trimmed.strip_prefix("fptnb//") {
        (body, true)
    } else if let Some(body) = trimmed.strip_prefix("fptn://") {
        (body, false)
    } else if let Some(body) = trimmed.strip_prefix("fptn:") {
        (body, false)
    } else {
        return Err("unsupported token prefix (expected fptn: or fptnb:)".to_string());
    };
    let cleaned: String = body
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    if cleaned.is_empty() {
        return Err("missing token body".to_string());
    }
    let rem = cleaned.len() % 4;
    if rem == 1 {
        return Err("invalid base64 length".to_string());
    }
    let mut padded = cleaned;
    if rem != 0 {
        padded.push_str(&"=".repeat(4 - rem));
    }
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .map_err(|e| format!("invalid base64: {e}"))?;
    if compressed {
        let mut out = Vec::new();
        brotli::Decompressor::new(std::io::Cursor::new(bytes.as_slice()), 4096)
            .read_to_end(&mut out)
            .map_err(|e| format!("brotli decompress failed: {e}"))?;
        bytes = out;
    }
    Ok(bytes)
}

/// Decodes an `fptn:` (base64 JSON) or `fptnb:` (brotli + base64 JSON)
/// subscription token. Errors are bare; callers add their own context.
pub fn parse_token(token: &str) -> Result<FptnToken, String> {
    let bytes = decode_token(token)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "token payload must be a JSON object".to_string())?;
    match obj.get("version") {
        None | Some(Value::Null) | Some(Value::Number(_)) => {}
        Some(_) => return Err("version: must be an integer".to_string()),
    }
    let service_name = match obj.get("service_name") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err("service_name: must be a string".to_string()),
    };
    let username = want_string(obj.get("username"), "username")?;
    if username.is_empty() {
        return Err("username: must not be empty".to_string());
    }
    let password = want_string(obj.get("password"), "password")?;
    if password.is_empty() {
        return Err("password: must not be empty".to_string());
    }
    let list = match obj.get("servers") {
        Some(Value::Array(list)) => list,
        Some(Value::Null) | None => return Err("missing servers".to_string()),
        Some(_) => return Err("servers: must be an array".to_string()),
    };
    if list.is_empty() {
        return Err("servers: server list is empty".to_string());
    }
    let mut servers = Vec::with_capacity(list.len());
    let mut names = HashSet::new();
    for (i, entry) in list.iter().enumerate() {
        let ctx = format!("servers[{i}]");
        let item = entry
            .as_object()
            .ok_or_else(|| format!("{ctx}: must be an object"))?;
        let name = want_string(item.get("name"), &format!("{ctx}.name"))?;
        if name.is_empty() {
            return Err(format!("{ctx}.name: must not be empty"));
        }
        let host = want_string(item.get("host"), &format!("{ctx}.host"))?;
        if host.is_empty() {
            return Err(format!("{ctx}.host: must not be empty"));
        }
        let port = match item.get("port") {
            Some(Value::Number(n)) => match n.as_u64() {
                Some(p) if p >= 1 && p <= u64::from(u16::MAX) => p as u16,
                Some(_) => return Err(format!("{ctx}.port: out of range (1-65535)")),
                None => return Err(format!("{ctx}.port: must be an integer")),
            },
            Some(Value::Null) | None => return Err(format!("missing {ctx}.port")),
            Some(_) => return Err(format!("{ctx}.port: must be an integer")),
        };
        let md5_fingerprint = match item.get("md5_fingerprint") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(fp)) => {
                if !fp.is_empty() && !(fp.len() == 32 && fp.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return Err(format!("{ctx}.md5_fingerprint: expected 32 hex characters"));
                }
                fp.clone()
            }
            Some(_) => return Err(format!("{ctx}.md5_fingerprint: must be a string")),
        };
        if !names.insert(name.clone()) {
            return Err(format!("duplicate server name: {name}"));
        }
        servers.push(FptnServer {
            name,
            host,
            port,
            md5_fingerprint,
        });
    }
    Ok(FptnToken {
        service_name,
        username,
        password,
        servers,
    })
}

fn is_token_outbound(entry: &Value) -> bool {
    entry.get("type").and_then(Value::as_str) == Some("fptn") && entry.get("token").is_some()
}

/// Replaces every `{"type":"fptn","token":…}` outbound with one outbound per
/// token server (tag `<tag>/<name>`, dial fields carried over) plus a trailing
/// `urltest` group that keeps the original tag. Returns `Ok(None)` when the
/// config has no token outbounds.
pub fn expand(root: &Value) -> Result<Option<Value>, String> {
    let Some(root_obj) = root.as_object() else {
        return Ok(None);
    };
    let Some(outbounds) = root_obj.get("outbounds").and_then(Value::as_array) else {
        return Ok(None);
    };
    if !outbounds.iter().any(is_token_outbound) {
        return Ok(None);
    }
    let mut expanded: Vec<Value> = Vec::with_capacity(outbounds.len());
    for (i, entry) in outbounds.iter().enumerate() {
        if !is_token_outbound(entry) {
            expanded.push(entry.clone());
            continue;
        }
        let at = format!("outbounds[{i}]");
        let obj = entry.as_object().expect("token outbound is an object");
        let tag = match obj.get("tag") {
            None | Some(Value::Null) => "",
            Some(Value::String(s)) => s.as_str(),
            Some(_) => {
                return Err(format!(
                    "{at}.tag: json: cannot unmarshal into Go field of type string"
                ));
            }
        };
        let token = match obj.get("token") {
            Some(Value::String(s)) if !s.is_empty() => s.as_str(),
            Some(Value::String(_)) | None | Some(Value::Null) => {
                return Err(format!("{at}: missing token"));
            }
            Some(_) => return Err(format!("{at}.token: must be a string")),
        };
        let parsed = parse_token(token).map_err(|e| format!("{at}: fptn token: {e}"))?;
        let prefix = if tag.is_empty() { "fptn" } else { tag };
        let mut members = Vec::with_capacity(parsed.servers.len());
        for server in &parsed.servers {
            let member_tag = format!("{prefix}/{}", server.name);
            let mut outbound = Map::new();
            outbound.insert("type".into(), json!("fptn"));
            outbound.insert("tag".into(), json!(member_tag));
            outbound.insert("server".into(), json!(server.host));
            outbound.insert("server_port".into(), json!(server.port));
            outbound.insert("username".into(), json!(parsed.username));
            outbound.insert("password".into(), json!(parsed.password));
            if !server.md5_fingerprint.is_empty() {
                outbound.insert("md5_fingerprint".into(), json!(server.md5_fingerprint));
            }
            for key in DIALER_OUT_FIELDS {
                if let Some(value) = obj.get(*key) {
                    outbound.insert((*key).to_string(), value.clone());
                }
            }
            members.push(Value::String(member_tag));
            expanded.push(Value::Object(outbound));
        }
        let mut group = Map::new();
        group.insert("type".into(), json!("urltest"));
        group.insert("tag".into(), json!(tag));
        group.insert("outbounds".into(), Value::Array(members));
        expanded.push(Value::Object(group));
    }
    let mut result = root_obj.clone();
    result.insert("outbounds".into(), Value::Array(expanded));
    Ok(Some(Value::Object(result)))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    const FP: &str = "00112233445566778899aabbccddeeff";

    fn token_json(servers: Value) -> Value {
        json!({
            "version": 1,
            "service_name": "TEST.SERVICE",
            "username": "user1",
            "password": "secret1",
            "servers": servers,
        })
    }

    fn brotli_b64(payload: &[u8]) -> String {
        let mut compressed = Vec::new();
        brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22)
            .write_all(payload)
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(compressed)
    }

    fn token_brotli(servers: Value) -> String {
        let raw = serde_json::to_vec(&token_json(servers)).unwrap();
        format!("fptnb:{}", brotli_b64(&raw))
    }

    fn token_plain(servers: Value) -> String {
        let raw = serde_json::to_vec(&token_json(servers)).unwrap();
        format!(
            "fptn:{}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    fn two_servers() -> Value {
        json!([
            {
                "name": "Alpha-1",
                "host": "203.0.113.1",
                "port": 443,
                "md5_fingerprint": FP,
            },
            {"name": "Beta-2", "host": "example.org", "port": 8443},
        ])
    }

    #[test]
    fn parses_brotli_token() {
        let parsed = parse_token(&token_brotli(two_servers())).unwrap();
        assert_eq!(parsed.service_name, "TEST.SERVICE");
        assert_eq!(parsed.username, "user1");
        assert_eq!(parsed.password, "secret1");
        assert_eq!(parsed.servers.len(), 2);
        assert_eq!(parsed.servers[0].name, "Alpha-1");
        assert_eq!(parsed.servers[0].port, 443);
        assert_eq!(parsed.servers[0].md5_fingerprint, FP);
        assert_eq!(parsed.servers[1].host, "example.org");
        assert_eq!(parsed.servers[1].md5_fingerprint, "");
    }

    #[test]
    fn parses_plain_base64_token() {
        let parsed = parse_token(&token_plain(two_servers())).unwrap();
        assert_eq!(parsed.servers.len(), 2);
    }

    #[test]
    fn tolerates_missing_padding_and_whitespace() {
        let raw = serde_json::to_vec(&token_json(two_servers())).unwrap();
        let mut b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        b64 = b64.trim_end_matches('=').to_string();
        let token = format!("fptn:{}", &b64[..100]);
        assert!(parse_token(&token).is_err());
        let wrapped = format!("fptn:{b64}\n");
        assert!(parse_token(&wrapped).is_ok());
    }

    #[test]
    fn rejects_unknown_prefix() {
        let err = parse_token("quic://abc").unwrap_err();
        assert!(err.contains("unsupported token prefix"), "{err}");
    }

    #[test]
    fn rejects_bad_base64_and_json() {
        let err = parse_token("fptnb:!!!!").unwrap_err();
        assert!(err.contains("invalid base64"), "{err}");
        let raw = base64::engine::general_purpose::STANDARD.encode("not json");
        let err = parse_token(&format!("fptn:{raw}")).unwrap_err();
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn rejects_broken_payloads() {
        let raw = serde_json::to_vec(&json!({"servers": []})).unwrap();
        let err = parse_token(&format!("fptnb:{}", brotli_b64(&raw))).unwrap_err();
        assert!(err.contains("missing username"), "{err}");

        let raw = serde_json::to_vec(&token_json(json!([]))).unwrap();
        let err = parse_token(&format!("fptnb:{}", brotli_b64(&raw))).unwrap_err();
        assert!(err.contains("server list is empty"), "{err}");

        let raw = serde_json::to_vec(&token_json(json!([
            {"name": "dup", "host": "a", "port": 443},
            {"name": "dup", "host": "b", "port": 443},
        ])))
        .unwrap();
        let err = parse_token(&format!("fptnb:{}", brotli_b64(&raw))).unwrap_err();
        assert!(err.contains("duplicate server name: dup"), "{err}");

        let raw = serde_json::to_vec(&token_json(json!([
            {"name": "a", "host": "1.2.3.4", "port": 0},
        ])))
        .unwrap();
        let err = parse_token(&format!("fptnb:{}", brotli_b64(&raw))).unwrap_err();
        assert!(err.contains("port: out of range"), "{err}");

        let raw = serde_json::to_vec(&token_json(json!([
            {"name": "a", "host": "1.2.3.4", "port": 443, "md5_fingerprint": "xyz"},
        ])))
        .unwrap();
        let err = parse_token(&format!("fptnb:{}", brotli_b64(&raw))).unwrap_err();
        assert!(err.contains("32 hex characters"), "{err}");
    }

    fn fptn_config(token: &str) -> Value {
        json!({
            "log": {"level": "info"},
            "inbounds": [
                {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080},
            ],
            "outbounds": [
                {
                    "type": "fptn",
                    "tag": "vpn",
                    "token": token,
                    "detour": "direct",
                    "bind_interface": "lo",
                },
                {"type": "direct", "tag": "direct"},
            ],
            "route": {"final": "vpn"},
        })
    }

    #[test]
    fn expand_builds_members_and_group() {
        let root = fptn_config(&token_brotli(two_servers()));
        let expanded = expand(&root).unwrap().expect("fptn entry present");
        let list = expanded["outbounds"].as_array().unwrap();
        assert_eq!(list.len(), 4);
        assert_eq!(list[0]["type"], "fptn");
        assert_eq!(list[0]["tag"], "vpn/Alpha-1");
        assert_eq!(list[0]["server"], "203.0.113.1");
        assert_eq!(list[0]["server_port"], 443);
        assert_eq!(list[0]["username"], "user1");
        assert_eq!(list[0]["password"], "secret1");
        assert_eq!(list[0]["md5_fingerprint"], FP);
        assert_eq!(list[0]["detour"], "direct");
        assert_eq!(list[0]["bind_interface"], "lo");
        assert_eq!(list[1]["tag"], "vpn/Beta-2");
        assert_eq!(list[1]["server_port"], 8443);
        assert!(list[1].get("md5_fingerprint").is_none());
        assert_eq!(list[2]["type"], "urltest");
        assert_eq!(list[2]["tag"], "vpn");
        assert_eq!(list[2]["outbounds"], json!(["vpn/Alpha-1", "vpn/Beta-2"]));
        assert_eq!(list[3]["type"], "direct");
        assert_eq!(expanded["route"], root["route"]);
    }

    #[test]
    fn expand_noop_without_fptn() {
        let root = json!({"outbounds": [{"type": "direct", "tag": "d"}]});
        assert!(expand(&root).unwrap().is_none());
        let root = json!({"log": {"level": "info"}});
        assert!(expand(&root).unwrap().is_none());
        let root = json!("not an object");
        assert!(expand(&root).unwrap().is_none());
    }

    #[test]
    fn expand_keeps_handwritten_members() {
        let root = json!({"outbounds": [
            {"type": "fptn", "tag": "x", "server": "1.2.3.4", "server_port": 443,
             "username": "u", "password": "p"},
        ]});
        assert!(expand(&root).unwrap().is_none());
    }

    #[test]
    fn check_accepts_token_config() {
        let raw = serde_json::to_string(&fptn_config(&token_brotli(two_servers()))).unwrap();
        crate::check_str(&raw).unwrap();
    }

    #[test]
    fn check_rejects_token_form_errors() {
        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn"}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("missing token"), "{err}");

        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn", "token": ""}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("missing token"), "{err}");

        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn", "token": 42}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("token: must be a string"), "{err}");

        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn", "token": "fptnb:zz", "foo": 1}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("unknown field \"foo\""), "{err}");

        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn", "token": "fptnb:zz"}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("fptn token: invalid base64"), "{err}");
    }

    #[test]
    fn check_rejects_token_content_errors() {
        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn", "token": token_brotli(json!([]))}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("server list is empty"), "{err}");

        let bad = json!([
            {"name": "dup", "host": "a", "port": 443},
            {"name": "dup", "host": "b", "port": 443},
        ]);
        let raw = serde_json::to_string(&json!({
            "outbounds": [{"type": "fptn", "tag": "vpn", "token": token_brotli(bad)}]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("duplicate server name"), "{err}");
    }

    #[test]
    fn check_rejects_mixed_forms_and_duplicate_tags() {
        let raw = serde_json::to_string(&json!({
            "outbounds": [
                {"type": "fptn", "tag": "vpn", "server": "1.2.3.4", "server_port": 443,
                 "username": "u", "password": "p", "token": "fptn:zz"},
            ]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("unknown field \"token\""), "{err}");

        let raw = serde_json::to_string(&json!({
            "outbounds": [
                {"type": "fptn", "tag": "vpn", "token": token_brotli(two_servers())},
                {"type": "fptn", "tag": "vpn", "token": token_plain(two_servers())},
            ]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(
            err.contains("duplicate outbound/endpoint tag: vpn"),
            "{err}"
        );
    }

    #[test]
    fn check_accepts_two_groups_and_member_reference() {
        let raw = serde_json::to_string(&json!({
            "outbounds": [
                {"type": "fptn", "tag": "eu", "token": token_brotli(two_servers())},
                {"type": "fptn", "tag": "plain", "token": token_plain(two_servers())},
                {"type": "selector", "tag": "sel", "outbounds": ["eu/Alpha-1", "plain/Beta-2"]},
            ],
            "route": {"final": "sel"},
        }))
        .unwrap();
        crate::check_str(&raw).unwrap();
    }

    #[test]
    fn check_rejects_handwritten_member_shape() {
        let raw = serde_json::to_string(&json!({
            "outbounds": [
                {"type": "fptn", "tag": "x", "server": "1.2.3.4", "server_port": 443},
            ]
        }))
        .unwrap();
        let err = crate::check_str(&raw).unwrap_err();
        assert!(err.contains("missing username"), "{err}");
    }
}
