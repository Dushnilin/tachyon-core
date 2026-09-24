//! DNS rule matching: the subset of `dns.rules` matchers/actions used by
//! real configs, evaluated sequentially like sing-box.

use std::net::IpAddr;

use hickory_proto::rr::RecordType;
use serde_json::Value;

use super::codec::QueryInfo;

/// Per-query metadata visible to rule matchers.
#[derive(Debug, Default, Clone)]
pub struct QueryMeta {
    pub inbound: Option<String>,
    pub source: Option<IpAddr>,
    /// `"udp"` / `"tcp"`.
    pub network: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Action {
    Route {
        server: String,
        rewrite_ttl: Option<u32>,
        disable_cache: bool,
    },
    RouteOptions {
        rewrite_ttl: Option<u32>,
        disable_cache: bool,
    },
    Reject,
    /// `evaluate` — accepted for config compatibility; the exchange it would
    /// launch is only observed by `match_response` rules (known gap).
    Evaluate,
    /// `respond` — known gap (requires evaluated responses).
    Respond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectMethod {
    Refused,
    Drop,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub inbound: Vec<String>,
    pub query_type: Vec<RecordType>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub source_ip_cidr: Vec<super::transport::IpPrefix>,
    pub network: Vec<String>,
    pub invert: bool,
    pub match_response: bool,
    pub action: Action,
    pub reject_method: RejectMethod,
}

/// Options accumulated by `route` / `route-options` actions along the walk.
#[derive(Debug, Default, Clone)]
pub struct WalkOptions {
    pub rewrite_ttl: Option<u32>,
    pub disable_cache: bool,
}

impl Rule {
    pub fn build(obj: &Value, at: &str) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;

        let inbound = string_list(map, "inbound", at)?;
        let query_type = string_list(map, "query_type", at)?
            .into_iter()
            .map(|raw| {
                super::codec::parse_record_type(&raw)
                    .ok_or_else(|| anyhow::anyhow!("{at}: unknown query_type {raw:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let domain = string_list(map, "domain", at)?;
        let domain_suffix = string_list(map, "domain_suffix", at)?;
        let domain_keyword = string_list(map, "domain_keyword", at)?;
        let network = string_list(map, "network", at)?;
        if !string_list(map, "domain_regex", at)?.is_empty() {
            crate::logging::warn(format_args!(
                "{at}: domain_regex matcher is not implemented yet (rule inert)"
            ));
        }
        if map.get("rule_set").is_some_and(|v| !v.is_null()) {
            crate::logging::warn(format_args!(
                "{at}: rule_set matchers land in F3 (rule inert)"
            ));
        }
        let source_ip_cidr = string_list(map, "source_ip_cidr", at)?
            .into_iter()
            .map(|raw| {
                super::transport::IpPrefix::parse(&raw)
                    .map_err(|e| anyhow::anyhow!("{at}: bad source_ip_cidr {raw:?}: {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let invert = map.get("invert").and_then(Value::as_bool).unwrap_or(false);
        let match_response = match map.get("match_response") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(Value::String(_)) => true,
            Some(_) => anyhow::bail!("{at}: invalid match_response value"),
        };

        let action_raw = map.get("action").and_then(Value::as_str).unwrap_or("");
        let rewrite_ttl = map
            .get("rewrite_ttl")
            .and_then(Value::as_u64)
            .map(|t| t as u32);
        let disable_cache = map
            .get("disable_cache")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut reject_method = RejectMethod::Refused;
        let action = match action_raw {
            "" => {
                let server = map
                    .get("server")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("{at}: missing action or server"))?
                    .to_string();
                Action::Route {
                    server,
                    rewrite_ttl,
                    disable_cache,
                }
            }
            "route" => {
                let server = map
                    .get("server")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("{at}: route action requires server"))?
                    .to_string();
                Action::Route {
                    server,
                    rewrite_ttl,
                    disable_cache,
                }
            }
            "route-options" => Action::RouteOptions {
                rewrite_ttl,
                disable_cache,
            },
            "reject" => {
                reject_method = match map.get("method").and_then(Value::as_str) {
                    None | Some("") | Some("default") => RejectMethod::Refused,
                    Some("drop") => RejectMethod::Drop,
                    Some(other) => anyhow::bail!("{at}: unknown reject method {other:?}"),
                };
                Action::Reject
            }
            "evaluate" => Action::Evaluate,
            "respond" => Action::Respond,
            "predefined" => anyhow::bail!("{at}: predefined DNS action is not implemented yet"),
            other => anyhow::bail!("{at}: unknown dns rule action {other:?}"),
        };

        Ok(Self {
            inbound,
            query_type,
            domain,
            domain_suffix,
            domain_keyword,
            source_ip_cidr,
            network,
            invert,
            match_response,
            action,
            reject_method,
        })
    }

    pub fn matches(&self, meta: &QueryMeta, query: &QueryInfo) -> bool {
        let hit = self.matches_inner(meta, query);
        hit != self.invert
    }

    fn matches_inner(&self, meta: &QueryMeta, query: &QueryInfo) -> bool {
        if !self.inbound.is_empty() {
            let Some(inbound) = meta.inbound.as_deref() else {
                return false;
            };
            if !self.inbound.iter().any(|i| i == inbound) {
                return false;
            }
        }
        if !self.query_type.is_empty() && !self.query_type.contains(&query.qtype) {
            return false;
        }
        if !self.network.is_empty() {
            let Some(network) = meta.network.as_deref() else {
                return false;
            };
            if !self.network.iter().any(|n| n == network) {
                return false;
            }
        }
        if !self.source_ip_cidr.is_empty() {
            let Some(source) = meta.source else {
                return false;
            };
            if !self.source_ip_cidr.iter().any(|p| p.contains(source)) {
                return false;
            }
        }
        if !self.domain.is_empty() && !self.domain.iter().any(|d| d == &query.name) {
            return false;
        }
        if !self.domain_suffix.is_empty()
            && !self
                .domain_suffix
                .iter()
                .any(|suffix| domain_suffix_match(&query.name, suffix))
        {
            return false;
        }
        if !self.domain_keyword.is_empty()
            && !self
                .domain_keyword
                .iter()
                .any(|k| query.name.contains(k.as_str()))
        {
            return false;
        }
        true
    }
}

fn domain_suffix_match(name: &str, suffix: &str) -> bool {
    let suffix = super::codec::normalize_name(suffix);
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

fn string_list(
    map: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<Vec<String>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: {key} entries must be strings"))
            })
            .collect(),
        Some(_) => Err(anyhow::anyhow!("{at}: {key} must be a string or array")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info(name: &str, qtype: RecordType) -> QueryInfo {
        QueryInfo {
            id: 1,
            name: name.to_string(),
            qtype,
        }
    }

    #[test]
    fn domain_suffix_and_action_parse() {
        let rule = Rule::build(
            &json!({
                "action": "route", "server": "fakeip-server",
                "rewrite_ttl": 60, "domain_suffix": ["rambler.ru", "google.com"]
            }),
            "rules[0]",
        )
        .unwrap();
        let meta = QueryMeta::default();
        assert!(rule.matches(&meta, &info("w.rambler.ru", RecordType::A)));
        assert!(rule.matches(&meta, &info("rambler.ru", RecordType::A)));
        assert!(rule.matches(&meta, &info("www.google.com", RecordType::A)));
        assert!(!rule.matches(&meta, &info("rambler.com", RecordType::A)));
        assert!(!rule.matches(&meta, &info("notrambler.ru", RecordType::A)));
    }

    #[test]
    fn query_type_reject() {
        let rule = Rule::build(
            &json!({"action": "reject", "query_type": ["HTTPS", "SVCB"]}),
            "rules[1]",
        )
        .unwrap();
        let meta = QueryMeta::default();
        assert!(rule.matches(&meta, &info("x.test", RecordType::HTTPS)));
        assert!(!rule.matches(&meta, &info("x.test", RecordType::A)));
    }

    #[test]
    fn inbound_match() {
        let rule = Rule::build(
            &json!({"action": "route", "server": "d", "inbound": "dns-health-main-1-in"}),
            "rules[2]",
        )
        .unwrap();
        let mut meta = QueryMeta::default();
        assert!(!rule.matches(&meta, &info("x", RecordType::A)));
        meta.inbound = Some("dns-health-main-1-in".into());
        assert!(rule.matches(&meta, &info("x", RecordType::A)));
    }

    #[test]
    fn invert_flips() {
        let rule = Rule::build(
            &json!({"action": "reject", "domain": ["a.test"], "invert": true}),
            "rules[3]",
        )
        .unwrap();
        let meta = QueryMeta::default();
        assert!(!rule.matches(&meta, &info("a.test", RecordType::A)));
        assert!(rule.matches(&meta, &info("b.test", RecordType::A)));
    }
}
