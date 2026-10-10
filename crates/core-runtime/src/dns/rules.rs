//! DNS rule matching: the subset of `dns.rules` matchers/actions used by
//! real configs, evaluated sequentially like sing-box.

use std::net::IpAddr;

use base64::Engine as _;
use hickory_proto::rr::RecordType;
use regex::Regex;
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
    /// `evaluate` — evaluate query with the specified server.
    Evaluate {
        server: String,
    },
    /// `respond` — known gap (requires evaluated responses).
    Respond,
    /// `predefined`: a synthesized answer (rcode + answer/ns/extra records).
    Predefined(PredefinedResponse),
}

/// `option.DNSRouteActionPredefined`, already decoded into wire records.
#[derive(Debug, Clone, Default)]
pub struct PredefinedResponse {
    pub rcode: Option<u8>,
    pub answer: Vec<hickory_proto::rr::Record>,
    pub ns: Vec<hickory_proto::rr::Record>,
    pub extra: Vec<hickory_proto::rr::Record>,
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
    pub domain_regex: Vec<Regex>,
    pub source_ip_cidr: Vec<super::transport::IpPrefix>,
    /// `route.find_neighbor`: the asking client's hardware address and DHCP
    /// hostname.
    pub source_mac: Vec<crate::route::neighbor::MacAddr>,
    pub source_hostname: Vec<String>,
    pub network: Vec<String>,
    /// The rule sets this DNS rule consults.
    pub rule_sets: Vec<std::sync::Arc<crate::route::rule_set::RuleSet>>,
    pub invert: bool,
    pub match_response: bool,
    pub action: Action,
    pub reject_method: RejectMethod,
    /// `type: logical` — the sub rules and the `and`/`or` mode.
    pub sub_rules: Vec<Rule>,
    pub logical: bool,
    pub mode_or: bool,
}

/// Options accumulated by `route` / `route-options` actions along the walk.
#[derive(Debug, Default, Clone)]
pub struct WalkOptions {
    pub rewrite_ttl: Option<u32>,
    pub disable_cache: bool,
}

impl Rule {
    pub fn build(obj: &Value, at: &str) -> anyhow::Result<Self> {
        Self::build_with_rule_sets(obj, at, &crate::route::rule_set::RuleSetRegistry::new())
    }

    pub fn build_with_rule_sets(
        obj: &Value,
        at: &str,
        registry: &crate::route::rule_set::RuleSetRegistry,
    ) -> anyhow::Result<Self> {
        Self::build_nested(obj, at, registry, false)
    }

    /// `nested` marks a logical rule's sub rule: it is a pure matcher and may
    /// carry no action of its own.
    fn build_nested(
        obj: &Value,
        at: &str,
        registry: &crate::route::rule_set::RuleSetRegistry,
        _nested: bool,
    ) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        if obj.get("type").and_then(Value::as_str) == Some("logical") {
            return Self::build_logical(obj, at, registry);
        }

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
        let domain_regex = string_list(map, "domain_regex", at)?
            .into_iter()
            .map(|expr| {
                Regex::new(&expr)
                    .map_err(|e| anyhow::anyhow!("{at}: parse expression {expr:?}: {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let network = string_list(map, "network", at)?;
        let rule_set_tags = string_list(map, "rule_set", at)?;
        let rule_sets = registry.resolve(&rule_set_tags)?;
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
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .map(|t| t as u32);
        let disable_cache = map
            .get("disable_cache")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut reject_method = RejectMethod::Refused;
        let action = match action_raw {
            "route" | "" => match map.get("server").and_then(Value::as_str) {
                Some(server) => Action::Route {
                    server: server.to_string(),
                    rewrite_ttl,
                    disable_cache,
                },
                // a nested rule is only a matcher; the parent carries the action
                // an empty server means the dns final transport
                None => Action::Route {
                    server: String::new(),
                    rewrite_ttl,
                    disable_cache,
                },
            },
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
            "evaluate" => {
                let server = map
                    .get("server")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Action::Evaluate { server }
            }
            "respond" => Action::Respond,
            "predefined" => Action::Predefined(build_predefined(map, at)?),
            other => anyhow::bail!("{at}: unknown dns rule action {other:?}"),
        };

        Ok(Self {
            inbound,
            query_type,
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
            source_ip_cidr,
            source_mac: string_list(map, "source_mac_address", at)?
                .iter()
                .map(|raw| crate::route::neighbor::parse_mac(raw).unwrap_or([0; 6]))
                .collect(),
            source_hostname: string_list(map, "source_hostname", at)?,
            network,
            rule_sets,
            invert,
            match_response,
            action,
            reject_method,
            sub_rules: Vec::new(),
            logical: false,
            mode_or: false,
        })
    }

    pub fn matches(&self, meta: &QueryMeta, query: &QueryInfo) -> bool {
        let hit = self.matches_inner(meta, query);
        hit != self.invert
    }

    pub fn matches_response(&self, meta: &QueryMeta, query: &QueryInfo, ips: &[IpAddr]) -> bool {
        if !self.match_response {
            return false;
        }
        if !self.matches_query_meta(meta, query) {
            return false;
        }
        if self.rule_sets.is_empty() {
            return true;
        }
        let source = meta
            .source
            .map(|address| std::net::SocketAddr::new(address, 0))
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        for &ip in ips {
            let context = crate::route::ConnContext::new(
                meta.inbound.as_deref().unwrap_or(""),
                source,
                crate::inbound::Target::Ip(std::net::SocketAddr::new(ip, 0)),
                "udp",
            );
            if self.rule_sets.iter().any(|set| set.matches(&context)) {
                return true;
            }
        }
        false
    }

    fn matches_query_meta(&self, meta: &QueryMeta, query: &QueryInfo) -> bool {
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
        if !self.domain_regex.is_empty()
            && !self.domain_regex.iter().any(|re| re.is_match(&query.name))
        {
            return false;
        }
        true
    }

    /// `option.LogicalDNSRule`: the action lives on the parent, the sub rules
    /// are pure matchers (`DNS rule action is not supported in nested rules`).
    fn build_logical(
        obj: &Value,
        at: &str,
        registry: &crate::route::rule_set::RuleSetRegistry,
    ) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let mode = map.get("mode").and_then(Value::as_str).unwrap_or("and");
        if !matches!(mode, "and" | "or") {
            anyhow::bail!("{at}: bad option: logical rule mode {mode:?}");
        }
        let mut sub_rules = Vec::new();
        for (i, sub) in map
            .get("rules")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let sub_at = format!("{at}.rules[{i}]");
            if sub
                .as_object()
                .is_some_and(|object| object.contains_key("action"))
            {
                anyhow::bail!("{sub_at}: DNS rule action is not supported in nested rules");
            }
            sub_rules.push(Rule::build_nested(sub, &sub_at, registry, true)?);
        }
        let mut rule = Rule::build_with_rule_sets(
            &serde_json::json!({ "action": map.get("action").cloned().unwrap_or(Value::Null) }),
            at,
            registry,
        )?;
        rule.invert = map.get("invert").and_then(Value::as_bool).unwrap_or(false);
        rule.sub_rules = sub_rules;
        rule.logical = true;
        rule.mode_or = mode == "or";
        Ok(rule)
    }

    /// The rule-set view of a DNS query: domain, source and destination ports.
    fn matches_rule_sets(&self, meta: &QueryMeta, query: &QueryInfo) -> bool {
        if self.rule_sets.is_empty() {
            return false;
        }
        let source = meta
            .source
            .map(|address| std::net::SocketAddr::new(address, 0))
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        let context = crate::route::ConnContext::new(
            meta.inbound.as_deref().unwrap_or(""),
            source,
            crate::inbound::Target::Domain(query.name.clone(), 0),
            "udp",
        );
        self.rule_sets.iter().any(|set| set.matches(&context))
    }

    fn matches_inner(&self, meta: &QueryMeta, query: &QueryInfo) -> bool {
        if self.logical {
            return if self.mode_or {
                self.sub_rules.iter().any(|sub| sub.matches(meta, query))
            } else {
                !self.sub_rules.is_empty()
                    && self.sub_rules.iter().all(|sub| sub.matches(meta, query))
            };
        }
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
        if !self.source_mac.is_empty() || !self.source_hostname.is_empty() {
            // the neighbour tables, when they are running at all
            let found = meta.source.and_then(|source| {
                crate::route::neighbor::current().map(|resolver| {
                    (
                        resolver.lookup_mac(source),
                        resolver.lookup_hostname(source),
                    )
                })
            });
            let (mac, hostname) = found.unwrap_or((None, None));
            if !self.source_mac.is_empty() && !mac.is_some_and(|mac| self.source_mac.contains(&mac))
            {
                return false;
            }
            if !self.source_hostname.is_empty()
                && !hostname
                    .as_deref()
                    .is_some_and(|name| self.source_hostname.iter().any(|item| item == name))
            {
                return false;
            }
        }
        if !self.rule_sets.is_empty() && !self.matches_rule_sets(meta, query) {
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
        if !self.domain_regex.is_empty()
            && !self.domain_regex.iter().any(|re| re.is_match(&query.name))
        {
            return false;
        }
        true
    }
}

fn parse_rcode(val: &Value) -> Result<Option<u8>, String> {
    if let Some(n) = val.as_u64() {
        return Ok(Some(n as u8));
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if let Ok(n) = trimmed.parse::<u8>() {
            return Ok(Some(n));
        }
        match trimmed.to_ascii_uppercase().as_str() {
            "NOERROR" => Ok(Some(0)),
            "FORMERR" => Ok(Some(1)),
            "SERVFAIL" => Ok(Some(2)),
            "NXDOMAIN" => Ok(Some(3)),
            "NOTIMP" => Ok(Some(4)),
            "REFUSED" => Ok(Some(5)),
            "YXDOMAIN" => Ok(Some(6)),
            "YXRRSET" => Ok(Some(7)),
            "NXRRSET" => Ok(Some(8)),
            "NOTAUTH" => Ok(Some(9)),
            "NOTZONE" => Ok(Some(10)),
            other => Err(format!("unknown rcode {other:?}")),
        }
    } else {
        Err(format!("invalid rcode format {val:?}"))
    }
}

/// `option.DNSRouteActionPredefined`: rcode plus wire-encoded records.
fn build_predefined(
    map: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<PredefinedResponse> {
    let rcode = match map.get("rcode") {
        None | Some(Value::Null) => None,
        Some(val) => parse_rcode(val)
            .map_err(|err| anyhow::anyhow!("{at}: bad option: {err}"))?,
    };
    let records = |key: &str| -> anyhow::Result<Vec<hickory_proto::rr::Record>> {
        let list = match map.get(key) {
            None | Some(Value::Null) => return Ok(Vec::new()),
            Some(value) => value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("{at}.{key}: must be an array"))?,
        };
        let mut out = Vec::with_capacity(list.len());
        for (i, record) in list.iter().enumerate() {
            let record_at = format!("{at}.{key}[{i}]");
            out.push(
                crate::dns::codec::decode_record(record, &record_at)
                    .map_err(|error| anyhow::anyhow!("{record_at}: {error}"))?,
            );
        }
        Ok(out)
    };
    Ok(PredefinedResponse {
        rcode,
        answer: records("answer")?,
        ns: records("ns")?,
        extra: records("extra")?,
    })
}

/// Standard base64 with padding, as the reference decoder expects. Wrapped
/// lines are tolerated because base64 URLs arrive that way.
pub fn base64_decode(raw: &str) -> anyhow::Result<Vec<u8>> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, '=' | '\n' | '\r'))
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cleaned)
        .map_err(|e| anyhow::anyhow!("illegal base64 data: {e}"))
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
    #[test]
    fn logical_rules_combine_sub_rules() {
        let rule = Rule::build(
            &serde_json::json!({
                "type": "logical",
                "mode": "and",
                "action": "route",
                "server": "d",
                "rules": [
                    {"domain_suffix": ["rambler.ru"]},
                    {"query_type": ["A"]}
                ]
            }),
            "rules[0]",
        )
        .expect("logical and");
        assert!(rule.logical);
        let meta = QueryMeta::default();
        assert!(rule.matches(&meta, &info("x.rambler.ru", RecordType::A)));
        assert!(!rule.matches(&meta, &info("x.rambler.ru", RecordType::AAAA)));
        assert!(!rule.matches(&meta, &info("x.other.ru", RecordType::A)));

        let rule = Rule::build(
            &serde_json::json!({
                "type": "logical",
                "mode": "or",
                "action": "reject",
                "rules": [{"domain": ["a.test"]}, {"domain": ["b.test"]}]
            }),
            "rules[1]",
        )
        .expect("logical or");
        assert!(rule.matches(&meta, &info("a.test", RecordType::A)));
        assert!(rule.matches(&meta, &info("b.test", RecordType::A)));
        assert!(!rule.matches(&meta, &info("c.test", RecordType::A)));

        // invert wraps the whole logical rule
        let rule = Rule::build(
            &serde_json::json!({
                "type": "logical",
                "mode": "or",
                "invert": true,
                "action": "reject",
                "rules": [{"domain": ["a.test"]}]
            }),
            "rules[2]",
        )
        .expect("logical invert");
        assert!(!rule.matches(&meta, &info("a.test", RecordType::A)));
        assert!(rule.matches(&meta, &info("z.test", RecordType::A)));

        // a sub rule may not carry its own action
        let error = Rule::build(
            &serde_json::json!({
                "type": "logical",
                "action": "reject",
                "rules": [{"domain": ["a.test"], "action": "reject"}]
            }),
            "rules[3]",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DNS rule action is not supported in nested rules"),
            "{error}"
        );
        // and the mode is checked
        let error = Rule::build(
            &serde_json::json!({
                "type": "logical",
                "mode": "xor",
                "rules": [{"domain": ["a.test"]}]
            }),
            "rules[4]",
        )
        .unwrap_err();
        assert!(error.to_string().contains("logical rule mode"), "{error}");
    }

    #[test]
    fn predefined_action_decodes_records() {
        let rule = Rule::build(
            &serde_json::json!({
                "action": "predefined",
                "rcode": "3",
                "answer": [
                    {"type": "A", "name": "blocked.test", "ttl": 60, "value": "203.0.113.7"},
                    {"type": "TXT", "name": "blocked.test", "value": "hello"}
                ],
                "extra": [{"type": "AAAA", "name": "blocked.test", "value": "2001:db8::1"}]
            }),
            "rules[0]",
        )
        .expect("predefined");
        let Action::Predefined(response) = &rule.action else {
            panic!("expected a predefined action");
        };
        assert_eq!(response.rcode, Some(3));
        assert_eq!(response.answer.len(), 2);
        assert_eq!(response.answer[0].record_type(), RecordType::A);
        assert_eq!(response.answer[1].record_type(), RecordType::TXT);
        assert_eq!(response.extra.len(), 1);
        assert_eq!(response.extra[0].record_type(), RecordType::AAAA);

        // the answer is spliced into a real response
        let query = codec::parse_message(
            &codec::build_query(0x1234, "blocked.test", RecordType::A).expect("query"),
        )
        .expect("message");
        let raw = codec::predefined_response(&query, response).expect("response");
        let message = codec::parse_message(&raw).expect("decode");
        assert_eq!(message.answers.len(), 2);
        assert_eq!(message.id, 0x1234);

        // base64 wire records decode as well: host. A IN, 203.0.113.7
        let mut wire: Vec<u8> = vec![4, b'h', b'o', b's', b't', 0];
        wire.extend_from_slice(&1u16.to_be_bytes()); // A
        wire.extend_from_slice(&1u16.to_be_bytes()); // IN
        wire.extend_from_slice(&60u32.to_be_bytes()); // ttl
        wire.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        wire.extend_from_slice(&[203, 0, 113, 7]);
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wire);
        let decoded = codec::decode_record(&serde_json::json!(encoded), "r").expect("wire record");
        assert_eq!(decoded.record_type(), RecordType::A);
        assert_eq!(decoded.ttl, 60);

        // an unknown record type is a start error, not a silent drop
        let error = Rule::build(
            &serde_json::json!({
                "action": "predefined",
                "answer": [{"type": "SRV", "name": "x.test", "value": {"type": "SRV"}}]
            }),
            "rules[1]",
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported record type"),
            "{error}"
        );
    }

    use super::*;
    use crate::dns::codec;
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
