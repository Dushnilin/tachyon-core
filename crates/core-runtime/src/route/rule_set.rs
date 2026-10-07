//! F3 rule sets: the loaded sets and the headless-rule matcher.
//!
//! A rule set is a named list of headless rules (the same shape the SRS
//! container and the source JSON carry). A route rule that references one or
//! more tags matches when any referenced set matches the connection, exactly
//! like `route/rule.RuleSetItem`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use serde_json::Value;

use super::rule_set_index::{Fallbacks, RuleSetIndex};
use crate::inbound::Target;
use crate::route::ConnContext;

/// A loaded rule set: its tags and the compiled form of the rules it holds.
/// The body sits behind a lock so a remote update is visible to the rules that
/// already hold an `Arc` to this set (reference `RemoteRuleSet.access` +
/// callbacks).
#[derive(Debug)]
pub struct RuleSet {
    tags: Vec<String>,
    body: RwLock<RuleSetBody>,
}

/// What a set holds once compiled. `count` is the number of rules as loaded,
/// not the number of pools, so `rule_count` still answers what it always did.
#[derive(Debug, Default)]
struct RuleSetBody {
    index: RuleSetIndex,
    fallbacks: Fallbacks,
    count: usize,
}

impl RuleSet {
    pub fn new(tags: Vec<String>, rules: Vec<Value>) -> Self {
        let count = rules.len();
        let (index, fallbacks) = RuleSetIndex::compile(&rules);
        Self {
            tags,
            body: RwLock::new(RuleSetBody {
                index,
                fallbacks,
                count,
            }),
        }
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// The reference resolves `{tag}` per tag, so a multi-tag set matches under
    /// any of its names.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|known| known == tag)
    }

    /// `adapter.RuleSet.Match`: any headless rule of the set matches. The
    /// simple rules answer from the compiled pools; `logical` and `invert`
    /// rules from the compiled fallback tree.
    pub fn matches(&self, ctx: &ConnContext) -> bool {
        self.with(|body| body.index.matches(ctx) || body.fallbacks.matches(ctx))
    }

    pub fn rule_count(&self) -> usize {
        self.with(|body| body.count)
    }

    /// `RemoteRuleSet.loadBytes`: swap the rule list in one step.
    ///
    /// The new rules are compiled *before* the lock is taken. Compiling a geo
    /// list is not free, and a write lock held across it would stall every
    /// matching connection behind an HTTP update.
    pub fn replace_rules(&self, rules: Vec<Value>) {
        let count = rules.len();
        let (index, fallbacks) = RuleSetIndex::compile(&rules);
        let body = RuleSetBody {
            index,
            fallbacks,
            count,
        };
        match self.body.write() {
            Ok(mut current) => *current = body,
            Err(poisoned) => *poisoned.into_inner() = body,
        }
    }

    fn with<T>(&self, read: impl FnOnce(&RuleSetBody) -> T) -> T {
        match self.body.read() {
            Ok(body) => read(&body),
            Err(poisoned) => read(&poisoned.into_inner()),
        }
    }

    /// The compiled pools, for the CLI's `rule-set match` and for tests.
    pub fn index(&self) -> RuleSetIndexClone {
        self.with(|body| RuleSetIndexClone {
            index: body.index.clone(),
        })
    }

    /// How many rules had to keep the old interpreter (`logical` or `invert`).
    pub fn fallback_count(&self) -> usize {
        self.with(|body| body.fallbacks.len())
    }
}

/// A cheap handle for callers outside the lock: the index is immutable once
/// built, and cloning it costs one atomic bump per pool rather than a lock.
#[derive(Clone, Debug)]
pub struct RuleSetIndexClone {
    index: RuleSetIndex,
}

impl RuleSetIndexClone {
    pub fn domain_count(&self) -> usize {
        self.index.domain_count()
    }

    pub fn has_domain(&self, domain: &str) -> bool {
        self.index.has_domain(domain)
    }

    pub fn has_suffix(&self, suffix: &str) -> bool {
        self.index.has_suffix(suffix)
    }

    pub fn has_keyword(&self, host: &str) -> bool {
        self.index.has_keyword(host)
    }

    pub fn has_prefix(&self, address: std::net::IpAddr, bits: u32) -> bool {
        self.index.has_prefix(address, bits)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

/// The tag → set registry built from `route.rule_set`.
#[derive(Debug, Default)]
pub struct RuleSetRegistry {
    sets: HashMap<String, Arc<RuleSet>>,
    remotes: Option<Arc<tokio::sync::Mutex<super::rule_set_remote::RemoteRegistry>>>,
}

impl RuleSetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, set: Arc<RuleSet>) {
        for tag in set.tags() {
            self.sets.insert(tag.clone(), set.clone());
        }
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<RuleSet>> {
        self.sets.get(tag)
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Remote sets fetch during start; the registry keeps their state.
    pub fn attach_remotes(&mut self, remotes: super::rule_set_remote::RemoteRegistry) {
        if !remotes.is_empty() {
            self.remotes = Some(Arc::new(tokio::sync::Mutex::new(remotes)));
        }
    }

    /// `RemoteRuleSet.StartContext` for every remote set, then the updaters.
    pub async fn start_remote(
        &self,
        router: &Arc<crate::route::Router>,
        cache: Option<crate::cache_file::SharedCacheFile>,
    ) -> anyhow::Result<()> {
        let Some(remotes) = &self.remotes else {
            return Ok(());
        };
        remotes
            .lock()
            .await
            .start_all(router, cache.as_ref())
            .await?;
        remotes
            .lock()
            .await
            .spawn_updaters(Arc::clone(router), cache);
        Ok(())
    }

    /// `RuleSetItem.Start`: every referenced tag must exist.
    pub fn resolve(&self, tags: &[String]) -> anyhow::Result<Vec<Arc<RuleSet>>> {
        let mut out = Vec::with_capacity(tags.len());
        for tag in tags {
            match self.get(tag) {
                Some(set) => out.push(set.clone()),
                None => anyhow::bail!("rule-set not found: {tag}"),
            }
        }
        Ok(out)
    }
}

/// One headless rule against a connection.
pub fn match_rule(rule: &Value, ctx: &ConnContext) -> bool {
    let Some(rule) = rule.as_object() else {
        return false;
    };
    let matched = if rule.get("type").and_then(Value::as_str) == Some("logical") {
        let rules: Vec<Value> = rule
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        match rule.get("mode").and_then(Value::as_str).unwrap_or("and") {
            "or" => rules.iter().any(|sub| match_rule(sub, ctx)),
            _ => !rules.is_empty() && rules.iter().all(|sub| match_rule(sub, ctx)),
        }
    } else {
        match_default(rule, ctx)
    };
    matched != (rule.get("invert") == Some(&Value::Bool(true)))
}

fn match_default(rule: &serde_json::Map<String, Value>, ctx: &ConnContext) -> bool {
    let mut matched = false;
    if let Some(domain) = super::rule::domain_host(ctx) {
        matched |= list(rule.get("domain"))
            .iter()
            .any(|entry| entry == domain.as_ref());
        matched |= list(rule.get("domain_suffix"))
            .iter()
            .any(|entry| super::rule::domain_suffix_match(&domain, entry));
        matched |= list(rule.get("domain_keyword"))
            .iter()
            .any(|entry| domain.contains(entry.as_str()));
    }
    if let Target::Ip(addr) = &ctx.destination {
        matched |= list(rule.get("ip_cidr"))
            .iter()
            .any(|entry| prefix_contains(entry, addr.ip()));
    }
    matched |= list(rule.get("source_ip_cidr"))
        .iter()
        .any(|entry| prefix_contains(entry, ctx.source.ip()));
    let destination_port = ctx.destination.port();
    matched |= ports(rule.get("port")).contains(&destination_port);
    matched |= list(rule.get("port_range"))
        .iter()
        .any(|entry| port_range_contains(entry, destination_port));
    matched |= ports(rule.get("source_port"))
        .iter()
        .any(|entry| *entry == ctx.source.port());
    matched |= list(rule.get("source_port_range"))
        .iter()
        .any(|entry| port_range_contains(entry, ctx.source.port()));
    matched |= list(rule.get("network"))
        .iter()
        .any(|entry| *entry == ctx.network);
    matched
}

/// `badoption.Listable[uint16]`: the SRS container stores numbers.
/// Shared with the compiled index, which folds these lists once at load.
pub(crate) fn ports(value: Option<&Value>) -> Vec<u16> {
    match value {
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .into_iter()
            .collect(),
        Some(Value::String(text)) => text.parse().into_iter().collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_u64().and_then(|value| u16::try_from(value).ok()))
            .collect(),
        _ => Vec::new(),
    }
}

/// `badoption.Listable[string]`. Shared with the compiled index, which folds
/// these lists once at load instead of rebuilding them per lookup.
pub(crate) fn list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn prefix_contains(prefix: &str, address: std::net::IpAddr) -> bool {
    let Some((base, bits)) = prefix.split_once('/') else {
        return false;
    };
    let (Ok(base), Ok(bits)) = (base.parse::<std::net::IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (base, address) {
        (std::net::IpAddr::V4(base), std::net::IpAddr::V4(address)) => {
            let mask = match bits {
                0 => 0,
                n if n >= 32 => u32::MAX,
                n => u32::MAX << (32 - n),
            };
            u32::from(base) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(base), std::net::IpAddr::V6(address)) => {
            let mask = match bits {
                0 => 0,
                n if n >= 128 => u128::MAX,
                n => u128::MAX << (128 - n),
            };
            u128::from(base) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn port_range_contains(range: &str, port: u16) -> bool {
    let Some((from, to)) = range.split_once('-') else {
        return false;
    };
    match (from.trim().parse::<u16>(), to.trim().parse::<u16>()) {
        (Ok(from), Ok(to)) => port >= from && port <= to,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::SocketAddr;

    fn context(domain: &str) -> ConnContext {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse::<SocketAddr>().expect("source"),
            Target::Domain(domain.to_string(), 443),
            "tcp",
        )
    }

    fn ip_context(destination: &str) -> ConnContext {
        // a bare address means port 443 for the ip rules
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse::<SocketAddr>().expect("source"),
            Target::Ip(
                format!("{destination}:443")
                    .parse::<SocketAddr>()
                    .expect("destination"),
            ),
            "tcp",
        )
    }

    #[test]
    fn domain_matchers() {
        let rule = json!({"domain_suffix": ["a.com"]});
        assert!(match_rule(&rule, &context("a.com")));
        assert!(match_rule(&rule, &context("cdn.a.com")));
        assert!(!match_rule(&rule, &context("b.com")));
        // the suffix is label-boundary
        assert!(!match_rule(&rule, &context("nota.com")));
        assert!(match_rule(&json!({"domain": ["a.com"]}), &context("a.com")));
        assert!(!match_rule(
            &json!({"domain": ["a.com"]}),
            &context("b.a.com")
        ));
        assert!(match_rule(
            &json!({"domain_keyword": ["ads"]}),
            &context("x.ads.net")
        ));
        // invert flips the outcome
        let inverted = json!({"domain_suffix": ["a.com"], "invert": true});
        assert!(!match_rule(&inverted, &context("a.com")));
        assert!(match_rule(&inverted, &context("b.com")));
    }

    #[test]
    fn ip_and_port_matchers() {
        assert!(match_rule(
            &json!({"ip_cidr": ["10.0.0.0/8"]}),
            &ip_context("10.1.2.3")
        ));
        assert!(!match_rule(
            &json!({"ip_cidr": ["10.0.0.0/8"]}),
            &ip_context("11.0.0.1")
        ));
        assert!(match_rule(
            &json!({"source_ip_cidr": ["10.0.0.0/8"]}),
            &ip_context("1.1.1.1")
        ));
        assert!(match_rule(&json!({"port": [443, 8443]}), &context("a.com")));
        assert!(!match_rule(&json!({"port": [80]}), &context("a.com")));
        assert!(match_rule(&json!({"port": 443}), &context("a.com")));
        assert!(match_rule(
            &json!({"port_range": ["400-500"]}),
            &context("a.com")
        ));
        assert!(!match_rule(
            &json!({"port_range": ["500-600"]}),
            &context("a.com")
        ));
        assert!(match_rule(
            &json!({"source_port": [1234]}),
            &context("a.com")
        ));
    }

    #[test]
    fn logical_rules() {
        let rule = json!({
            "type": "logical",
            "mode": "and",
            "rules": [{"domain_suffix": ["a.com"]}, {"port": [443]}]
        });
        assert!(match_rule(&rule, &context("a.com")));
        assert!(!match_rule(&rule, &context("b.com")));
        let rule = json!({
            "type": "logical",
            "mode": "or",
            "rules": [{"domain": ["a.com"]}, {"domain": ["b.com"]}]
        });
        assert!(match_rule(&rule, &context("b.com")));
        assert!(!match_rule(&rule, &context("c.com")));
    }

    #[test]
    fn registry_resolves_every_tag() {
        let mut registry = RuleSetRegistry::new();
        registry.insert(Arc::new(RuleSet::new(
            vec!["one".into(), "two".into()],
            vec![json!({"domain_suffix": ["a.com"]})],
        )));
        assert!(registry.get("one").is_some());
        assert!(registry.get("two").is_some());
        assert!(registry.get("three").is_none());
        let sets = registry.resolve(&["one".to_string()]).expect("resolve");
        assert!(sets[0].matches(&context("a.com")));
        let error = registry.resolve(&["three".to_string()]).unwrap_err();
        assert_eq!(error.to_string(), "rule-set not found: three");
    }
}
