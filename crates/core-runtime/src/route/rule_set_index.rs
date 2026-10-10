//! A rule set, compiled once instead of parsed per connection.
//!
//! # Why this exists
//!
//! `RuleSet` used to hold `Vec<Value>` and walk it on every connection. Measured
//! on 2026-10-02 (release, x86_64) with a domain list shaped like a real geo
//! database -- one headless rule per domain, which is how the SRS containers emit
//! them -- a lookup that *missed*, so every rule was visited:
//!
//! | rules | before | after |
//! |---:|---:|---:|
//! | 1 000 | 393 µs | 158 ns |
//! | 50 000 | 21.6 ms | 161 ns |
//! | 200 000 | **102.5 ms** | **162 ns** |
//!
//! The lookup stopped depending on the size of the list. `ip_cidr` was worse per
//! rule because every CIDR string was re-parsed on every lookup (17.9 ms at
//! 50 000, now 55 ns). The cost was never comparisons: it was `list()` building
//! a fresh `Vec<String>` per rule per lookup and cloning every string out of it.
//!
//! It is also the *lighter* representation, which was the part worth measuring
//! because this project advertises idle RSS:
//!
//! | what the runtime holds, 200 000 domains | bytes | per entry |
//! |---|---:|---:|
//! | `Vec<Value>` | 98 066 340 | 490 |
//! | `HashSet<Box<str>>` | 12 536 356 | 63 |
//!
//! Each rule used to be a `Value::Object` wrapping a one-element array wrapping
//! a `String`: a map, an array and a heap allocation per domain.
//!
//! # What it costs to build
//!
//! A remote update recompiles the whole set, so this is a number a router pays.
//! It is done *before* the write lock is taken, so matching is never blocked by
//! an HTTP update: 1.2 ms for 1 000 rules, 77 ms for 50 000, 337 ms for 200 000.
//!
//! # Why the pools can be merged
//!
//! Two facts about the reference's headless rules, both visible in the old
//! `match_default`: a plain rule ORs its fields together rather than ANDing them,
//! and a rule set ORs its rules (`adapter.RuleSet.Match`: any headless rule
//! matching satisfies the set). OR over rules of OR over fields is a flat OR, so
//! every simple rule in a set can contribute its entries to shared pools and the
//! set can be tested pool by pool.
//!
//! What cannot be merged still does not join the pools: `logical` rules, and
//! anything with `invert`, where flattening would invert the wrong thing. They
//! are compiled instead into `FallbackRule`, a tree of the same structures, so
//! a connection costs comparisons rather than JSON walks.
//!
//! # Why not a trie
//!
//! `domain` is an exact match, so a hash set answers it in one probe; a trie
//! would add pointer chasing and a node per label to be slower. `domain_suffix`
//! needs "the host or any parent", and walking the host's labels is a handful of
//! hash probes -- three or four for a real domain -- which beats a trie at real
//! depths and needs no nodes at all. A trie only starts paying when a single
//! lookup has to test thousands of alternatives, which is not what a suffix is.
//! `domain_keyword` *is* substring search, so that one gets a real Aho-Corasick
//! automaton; `aho-corasick` is already in the tree through `regex`, so linking
//! it directly costs no binary size.
//!
//! # What is deliberately not changed
//!
//! Stored domains keep their original case and only the *query* is lowercased,
//! because that is what the old code did -- `domain_host()` lowercases and the
//! stored entries were compared raw, which means a mixed-case entry can never
//! match. `route/rule.rs` lowercases both sides, so the two engines disagree on
//! case today; that is a real divergence worth its own commit against the
//! reference, not something to smuggle into a performance change.
//!
//! `/0` also changes, and had to: the old code computed `u32::MAX << 32`, which
//! matches everything in release (the shift is masked) and panics in debug. A
//! prefix of length zero now masks to zero, which is what it means.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use serde_json::Value;

use crate::inbound::Target;
use crate::route::ConnContext;
use crate::route::rule::{domain_host, domain_suffix_match};
use crate::route::rule_set::{list, ports};

/// Masking, without pulling `num_traits` in for two shifts.
trait Network: Ord + Copy {
    fn mask(self, len: u32) -> Self;
}

impl Network for u32 {
    fn mask(self, len: u32) -> Self {
        match len {
            0 => 0,
            n if n >= 32 => self,
            n => self & (u32::MAX << (32 - n)),
        }
    }
}

impl Network for u128 {
    fn mask(self, len: u32) -> Self {
        match len {
            0 => 0,
            n if n >= 128 => self,
            n => self & (u128::MAX << (128 - n)),
        }
    }
}

/// CIDRs bucketed by prefix length, so a lookup binary-searches only the lengths
/// the set actually contains instead of walking every prefix.
#[derive(Debug, Clone, Default)]
struct PrefixSet<T> {
    /// Distinct prefix lengths, ascending. Parallel to `buckets`.
    lens: Vec<u32>,
    /// For each length, the masked networks, sorted and deduplicated.
    buckets: Vec<Vec<T>>,
    /// Length/network pairs as they arrive, before `build` groups them.
    pending: Vec<(u32, T)>,
}

impl<T: Network> PrefixSet<T> {
    fn insert(&mut self, network: T, len: u32) {
        self.pending.push((len, network.mask(len)));
    }

    fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    fn build(&mut self) {
        self.pending.sort_unstable();
        self.pending.dedup();
        self.lens = self.pending.iter().map(|(len, _)| *len).collect();
        // `pending` is sorted, so equal lengths are adjacent.
        self.lens.dedup();
        self.buckets = vec![Vec::new(); self.lens.len()];
        for (len, network) in self.pending.drain(..) {
            let at = self
                .lens
                .binary_search(&len)
                .expect("the length came out of this very list");
            self.buckets[at].push(network);
        }
        for bucket in &mut self.buckets {
            bucket.sort_unstable();
            bucket.dedup();
        }
    }

    fn contains(&self, address: T) -> bool {
        self.lens
            .iter()
            .enumerate()
            .any(|(at, &len)| self.buckets[at].binary_search(&address.mask(len)).is_ok())
    }

    /// Membership of one explicit `address/bits` pair, for the CLI and tests.
    fn contains_exact(&self, address: T, bits: u32) -> bool {
        let Ok(at) = self.lens.binary_search(&bits) else {
            return false;
        };
        self.buckets[at].binary_search(&address.mask(bits)).is_ok()
    }
}

/// Sorted ranges, binary-searched on the low end.
#[derive(Debug, Default, Clone)]
struct PortRanges(Vec<(u16, u16)>);

impl PortRanges {
    fn build(&mut self) {
        self.0.sort_unstable();
    }

    fn contains(&self, port: u16) -> bool {
        // `partition_point` gives the first range that could still contain it:
        // everything below starts too low.
        let at = self.0.partition_point(|(from, _)| *from <= port);
        at > 0 && port <= self.0[at - 1].1
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// The compiled form of every simple rule in one set.
#[derive(Debug, Default, Clone)]
pub struct RuleSetIndex {
    domains: HashSet<Box<str>>,
    /// Label-boundary suffixes: the host equals the suffix, or ends with `.` plus
    /// it. Reached by walking the host's labels, so no allocation.
    suffixes: HashSet<Box<str>>,
    /// A leading-dot suffix is the reference's "plain string suffix" form, which
    /// is not label-aligned, so it keeps its own (tiny) list.
    dot_suffixes: Vec<Box<str>>,
    /// Held until `build`, where the automaton wants them all at once.
    keywords_raw: Vec<String>,
    keywords: Option<AhoCorasick>,
    dest_v4: PrefixSet<u32>,
    dest_v6: PrefixSet<u128>,
    source_v4: PrefixSet<u32>,
    source_v6: PrefixSet<u128>,
    dest_ports: Vec<u16>,
    dest_port_ranges: PortRanges,
    source_ports: Vec<u16>,
    source_port_ranges: PortRanges,
    /// At most a couple of entries; a scan is cheaper than a set here.
    networks: Vec<Box<str>>,
    /// An empty index must never match, not even by accident.
    empty: bool,
}

/// The rules `compile` could not flatten, compiled into a tree that answers
/// without touching JSON.
///
/// The interpreter behind them (`route::rule_set::match_rule`) re-derived
/// everything per connection: a deep `Vec<Value>` clone for a `logical` rule,
/// eight `list()`/`ports()` allocations across its fields, CIDRs re-parsed
/// from strings, `domain_host` producing a `String`. On a real config with
/// `{ "invert": true, "domain": [...] }` geo lists that was a dozen
/// allocations and a parse per rule per connection. The tree keeps the
/// *same* acceptance rules -- the shapes are built from the same `list()`
/// and `ports()` calls, the same `insert_prefix` and `parse_ranges` the
/// pools use -- and `rule_set_compiled` runs it against the interpreter as
/// the oracle.
#[derive(Debug, Default, Clone)]
pub struct Fallbacks {
    rules: Vec<FallbackRule>,
}

impl Fallbacks {
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn matches(&self, ctx: &ConnContext) -> bool {
        self.rules.iter().any(|rule| rule.matches(ctx))
    }
}

/// One fallback rule. Both variants keep the interpreter's outer `invert`,
/// applied to the node's own outcome.
#[derive(Debug, Clone)]
enum FallbackRule {
    /// Malformed logical children are always false, unlike an empty object.
    Never,
    /// `type: logical`. `mode: or` is `any`, everything else -- including the
    /// default -- is `all` over a *non-empty* list: the interpreter's
    /// `!rules.is_empty() && rules.iter().all(..)` guard, kept because an
    /// empty `and` answers false here, not vacuous truth.
    Logical {
        all: bool,
        inverted: bool,
        rules: Vec<FallbackRule>,
    },
    /// A rule with `invert`, or any rule sitting inside a logical tree. The
    /// body is shaped like the pooled index, so matching is the same code
    /// over the same acceptance rules. Boxed because the pools make it far
    /// larger than the `Logical` arm, and a fallback rule is built once.
    Plain(Box<PlainRule>),
}

impl FallbackRule {
    fn compile(object: &serde_json::Map<String, Value>) -> Self {
        if object.get("type").and_then(Value::as_str) == Some("logical") {
            let subs = object
                .get("rules")
                .and_then(Value::as_array)
                .map(|subs| {
                    subs.iter()
                        .map(|sub| match sub.as_object() {
                            Some(object) => FallbackRule::compile(object),
                            // Preserve match_rule's rejection of non-objects.
                            None => FallbackRule::Never,
                        })
                        .collect()
                })
                .unwrap_or_default();
            return FallbackRule::Logical {
                all: object.get("mode").and_then(Value::as_str) != Some("or"),
                inverted: object.get("invert") == Some(&Value::Bool(true)),
                rules: subs,
            };
        }
        FallbackRule::Plain(Box::new(PlainRule::compile(object)))
    }

    fn matches(&self, ctx: &ConnContext) -> bool {
        match self {
            FallbackRule::Never => false,
            FallbackRule::Plain(rule) => rule.matches(ctx),
            FallbackRule::Logical {
                all,
                inverted,
                rules,
            } => {
                let matched = if *all {
                    !rules.is_empty() && rules.iter().all(|rule| rule.matches(ctx))
                } else {
                    rules.iter().any(|rule| rule.matches(ctx))
                };
                matched != *inverted
            }
        }
    }
}

/// One plain rule, folded the way `RuleSetIndex::add_rule` folds a simple
/// rule, but kept to itself because `invert` would invert the wrong thing if
/// it were merged into the shared pools.
#[derive(Debug, Clone, Default)]
struct PlainRule {
    inverted: bool,
    has_domains: bool,
    has_dest_ip: bool,
    has_source_ip: bool,
    has_dest_ports: bool,
    has_source_ports: bool,
    has_network: bool,
    domains: HashSet<Box<str>>,
    /// Kept as a list and tested with the interpreter's own
    /// `domain_suffix_match`: the label boundary, the leading-dot form and
    /// the degenerate empty suffix all behave exactly as before, which a
    /// label-walk over a set would not for the last one.
    suffixes: Vec<Box<str>>,
    keywords: Vec<Box<str>>,
    dest_v4: PrefixSet<u32>,
    dest_v6: PrefixSet<u128>,
    source_v4: PrefixSet<u32>,
    source_v6: PrefixSet<u128>,
    dest_ports: Vec<u16>,
    dest_port_ranges: PortRanges,
    source_ports: Vec<u16>,
    source_port_ranges: PortRanges,
    networks: Vec<Box<str>>,
}

impl PlainRule {
    fn compile(object: &serde_json::Map<String, Value>) -> Self {
        let mut rule = PlainRule {
            inverted: object.get("invert") == Some(&Value::Bool(true)),
            ..PlainRule::default()
        };
        for entry in list(object.get("domain")) {
            rule.domains.insert(entry.into_boxed_str());
        }
        rule.suffixes.extend(
            list(object.get("domain_suffix"))
                .into_iter()
                .map(String::into_boxed_str),
        );
        rule.keywords.extend(
            list(object.get("domain_keyword"))
                .into_iter()
                .map(String::into_boxed_str),
        );
        rule.has_domains = object.contains_key("domain")
            || object.contains_key("domain_suffix")
            || object.contains_key("domain_keyword");

        for entry in list(object.get("ip_cidr")) {
            insert_prefix(&mut rule.dest_v4, &mut rule.dest_v6, &entry);
        }
        rule.has_dest_ip = object.contains_key("ip_cidr");

        for entry in list(object.get("source_ip_cidr")) {
            insert_prefix(&mut rule.source_v4, &mut rule.source_v6, &entry);
        }
        rule.has_source_ip = object.contains_key("source_ip_cidr");

        rule.dest_ports.extend(ports(object.get("port")));
        rule.dest_port_ranges
            .0
            .extend(parse_ranges(list(object.get("port_range"))));
        rule.has_dest_ports = object.contains_key("port") || object.contains_key("port_range");

        rule.source_ports.extend(ports(object.get("source_port")));
        rule.source_port_ranges
            .0
            .extend(parse_ranges(list(object.get("source_port_range"))));
        rule.has_source_ports =
            object.contains_key("source_port") || object.contains_key("source_port_range");

        for entry in list(object.get("network")) {
            if !rule.networks.iter().any(|known| **known == *entry) {
                rule.networks.push(entry.into_boxed_str());
            }
        }
        rule.has_network = object.contains_key("network");

        rule.dest_ports.sort_unstable();
        rule.dest_ports.dedup();
        rule.source_ports.sort_unstable();
        rule.source_ports.dedup();
        rule.dest_port_ranges.build();
        rule.source_port_ranges.build();
        rule.dest_v4.build();
        rule.dest_v6.build();
        rule.source_v4.build();
        rule.source_v6.build();
        rule
    }

    fn matches(&self, ctx: &ConnContext) -> bool {
        // Destination criteria (domain or IP)
        if self.has_domains || self.has_dest_ip {
            let mut dest_matched = false;
            if let Some(host) = domain_host(ctx)
                && self.has_domains
            {
                dest_matched = self.domains.contains(host.as_ref())
                    || self
                        .suffixes
                        .iter()
                        .any(|entry| domain_suffix_match(&host, entry))
                    || self
                        .keywords
                        .iter()
                        .any(|entry| host.contains(entry.as_ref()));
            }
            if !dest_matched
                && self.has_dest_ip
                && let Target::Ip(addr) = &ctx.destination
            {
                dest_matched = match addr.ip() {
                    IpAddr::V4(v4) => self.dest_v4.contains(v4.into()),
                    IpAddr::V6(v6) => self.dest_v6.contains(v6.into()),
                };
            }
            if !dest_matched {
                return self.inverted;
            }
        }

        // Source IP criteria
        if self.has_source_ip {
            let matched_source = match ctx.source.ip() {
                IpAddr::V4(v4) => self.source_v4.contains(v4.into()),
                IpAddr::V6(v6) => self.source_v6.contains(v6.into()),
            };
            if !matched_source {
                return self.inverted;
            }
        }

        // Destination port criteria
        if self.has_dest_ports {
            let port = ctx.destination.port();
            let port_matched = self.dest_ports.binary_search(&port).is_ok()
                || self.dest_port_ranges.contains(port);
            if !port_matched {
                return self.inverted;
            }
        }

        // Source port criteria
        if self.has_source_ports {
            let source_port = ctx.source.port();
            let port_matched = self.source_ports.binary_search(&source_port).is_ok()
                || self.source_port_ranges.contains(source_port);
            if !port_matched {
                return self.inverted;
            }
        }

        // Network criteria
        if self.has_network && !self.networks.iter().any(|known| **known == *ctx.network) {
            return self.inverted;
        }

        !self.inverted
    }
}

impl RuleSetIndex {
    /// Flatten the simple rules into pools and hand back the ones that must keep
    /// the old interpreter.
    ///
    /// This is meant to run *outside* the set's lock, so a remote update never
    /// blocks matching on a geo list: the work happens first and the finished
    /// index is swapped in under the write lock.
    pub fn compile(rules: &[Value]) -> (Self, Fallbacks) {
        let mut index = RuleSetIndex::default();
        let mut fallbacks = Fallbacks::default();

        for rule in rules {
            let Some(object) = rule.as_object() else {
                // `match_rule` returned false for a non-object; dropping it is
                // the same answer without evaluating it again.
                continue;
            };
            let inverted = object.get("invert") == Some(&Value::Bool(true));
            let logical = object.get("type").and_then(Value::as_str) == Some("logical");
            let has_non_dest = object.contains_key("network")
                || object.contains_key("port")
                || object.contains_key("port_range")
                || object.contains_key("source_port")
                || object.contains_key("source_port_range")
                || object.contains_key("source_ip_cidr");
            if inverted || logical || has_non_dest {
                fallbacks.rules.push(FallbackRule::compile(object));
                continue;
            }
            index.add_rule(object);
        }

        index.build();
        index.empty = index.is_void();
        (index, fallbacks)
    }

    /// `match_default`, with every list folded into a shared pool.
    fn add_rule(&mut self, object: &serde_json::Map<String, Value>) {
        for entry in list(object.get("domain")) {
            self.domains.insert(entry.into_boxed_str());
        }
        for entry in list(object.get("domain_suffix")) {
            if entry.starts_with('.') {
                self.dot_suffixes.push(entry.into_boxed_str());
            } else if !entry.is_empty() {
                self.suffixes.insert(entry.into_boxed_str());
            }
        }
        self.keywords_raw.extend(list(object.get("domain_keyword")));

        for entry in list(object.get("ip_cidr")) {
            insert_prefix(&mut self.dest_v4, &mut self.dest_v6, &entry);
        }
        for entry in list(object.get("source_ip_cidr")) {
            insert_prefix(&mut self.source_v4, &mut self.source_v6, &entry);
        }

        self.dest_ports.extend(ports(object.get("port")));
        self.dest_port_ranges
            .0
            .extend(parse_ranges(list(object.get("port_range"))));
        self.source_ports.extend(ports(object.get("source_port")));
        self.source_port_ranges
            .0
            .extend(parse_ranges(list(object.get("source_port_range"))));

        for entry in list(object.get("network")) {
            if !self.networks.iter().any(|known| **known == *entry) {
                self.networks.push(entry.into_boxed_str());
            }
        }
    }

    fn build(&mut self) {
        self.dest_ports.sort_unstable();
        self.dest_ports.dedup();
        self.source_ports.sort_unstable();
        self.source_ports.dedup();
        self.dest_port_ranges.build();
        self.source_port_ranges.build();
        self.dest_v4.build();
        self.dest_v6.build();
        self.source_v4.build();
        self.source_v6.build();
        if !self.keywords_raw.is_empty() {
            // Only "does any pattern occur" is asked, so a leftmost-first
            // automaton is enough and no match offsets are ever collected.
            self.keywords = AhoCorasick::new(self.keywords_raw.drain(..)).ok();
        }
    }

    /// True when no pool can ever match: an empty set, or one whose every entry
    /// was unparsable.
    fn is_void(&self) -> bool {
        self.is_empty()
    }

    /// The pooled part of the set.
    pub fn matches(&self, ctx: &ConnContext) -> bool {
        if self.empty {
            return false;
        }
        if let Some(host) = host_of(ctx) {
            if self.domains.contains(host.as_ref()) {
                return true;
            }
            if self.suffix_hit(&host) {
                return true;
            }
            if self
                .keywords
                .as_ref()
                .is_some_and(|keywords| keywords.is_match(host.as_ref()))
            {
                return true;
            }
        }
        // `ip_cidr` was only consulted for an IP destination; a domain
        // destination never matched it, and still does not.
        if let Target::Ip(addr) = &ctx.destination {
            let hit = match addr.ip() {
                IpAddr::V4(v4) => self.dest_v4.contains(v4.into()),
                IpAddr::V6(v6) => self.dest_v6.contains(v6.into()),
            };
            if hit {
                return true;
            }
        }
        false
    }

    /// `domain_suffix`: the host equals the suffix, or ends with `.` plus it.
    /// Walking the labels is a handful of hash lookups, which beats a trie at
    /// real domain depths and needs no node per label.
    fn suffix_hit(&self, host: &str) -> bool {
        let mut rest = host;
        loop {
            if self.suffixes.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, after)) => rest = after,
                None => break,
            }
        }
        self.dot_suffixes
            .iter()
            .any(|suffix| host.ends_with(suffix.as_ref()))
    }

    /// How many entries the index holds.
    pub fn len(&self) -> usize {
        self.domains.len()
            + self.suffixes.len()
            + self.dot_suffixes.len()
            + self.keyword_count()
            + self.dest_v4.len()
            + self.dest_v6.len()
            + self.source_v4.len()
            + self.source_v6.len()
            + self.dest_ports.len()
            + self.dest_port_ranges.len()
            + self.source_ports.len()
            + self.source_port_ranges.len()
            + self.networks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    pub fn has_domain(&self, domain: &str) -> bool {
        self.domains.contains(domain)
    }

    pub fn has_suffix(&self, suffix: &str) -> bool {
        self.suffixes.contains(suffix)
            || self
                .dot_suffixes
                .iter()
                .any(|known| known.as_ref() == suffix)
    }

    /// Whether a host contains any indexed keyword.
    pub fn has_keyword(&self, host: &str) -> bool {
        self.keywords
            .as_ref()
            .is_some_and(|keywords| keywords.is_match(host))
    }

    /// Whether an address falls inside an indexed destination prefix.
    pub fn has_prefix(&self, address: IpAddr, bits: u32) -> bool {
        match address {
            IpAddr::V4(v4) => self.dest_v4.contains_exact(v4.into(), bits),
            IpAddr::V6(v6) => self.dest_v6.contains_exact(v6.into(), bits),
        }
    }

    fn keyword_count(&self) -> usize {
        self.keywords
            .as_ref()
            .map(AhoCorasick::patterns_len)
            .unwrap_or(0)
    }
}

/// `domain_host`, borrowed when it can be: the host is almost always lowercase
/// already, and allocating a `String` per connection to find that out is waste.
fn host_of(ctx: &ConnContext) -> Option<Cow<'_, str>> {
    let raw = match &ctx.domain {
        Some(domain) => domain.as_str(),
        None => match &ctx.destination {
            Target::Domain(host, _) => host.as_str(),
            Target::Ip(_) => return None,
        },
    };
    Some(if raw.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(raw.to_ascii_lowercase())
    } else {
        Cow::Borrowed(raw)
    })
}

/// The old `prefix_contains` acceptance rules, applied once instead of per
/// lookup: split on `/`, parse both halves, refuse a family mismatch.
fn insert_prefix(v4: &mut PrefixSet<u32>, v6: &mut PrefixSet<u128>, prefix: &str) {
    let Some((base, bits)) = prefix.split_once('/') else {
        return;
    };
    let (Ok(base), Ok(bits)) = (base.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return;
    };
    let bits = if bits >= base.len_bits() {
        base.len_bits()
    } else {
        bits
    };
    match base {
        IpAddr::V4(base) => v4.insert(u32::from(base), bits),
        IpAddr::V6(base) => v6.insert(u128::from(base), bits),
    }
}

/// `port_range_contains` acceptance rules, applied once instead of per lookup.
fn parse_ranges(entries: Vec<String>) -> Vec<(u16, u16)> {
    entries
        .iter()
        .filter_map(|entry| {
            let (from, to) = entry.split_once('-')?;
            match (from.trim().parse::<u16>(), to.trim().parse::<u16>()) {
                (Ok(from), Ok(to)) => Some((from, to)),
                _ => None,
            }
        })
        .collect()
}

/// `IpAddr::len_bits`, which is not stable everywhere this builds.
trait IpBits {
    fn len_bits(&self) -> u32;
}

impl IpBits for IpAddr {
    fn len_bits(&self) -> u32 {
        match self {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }
}
