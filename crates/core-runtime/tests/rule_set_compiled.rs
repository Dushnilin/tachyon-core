//! The compiled index must answer exactly what the old interpreter answered.
//!
//! `RuleSet` used to be `Vec<Value>` walked per connection, and `match_rule` is
//! still there -- now only for `logical` and `invert` rules. So the strongest
//! possible guard is to run both over the same corpus and demand agreement: the
//! interpreter is the oracle, not a hand-written expectation. Every semantic slip
//! in flattening rules into shared pools shows up here as a disagreement.

use std::net::SocketAddr;

use core_runtime::inbound::Target;
use core_runtime::route::ConnContext;
use core_runtime::route::rule_set::{RuleSet, match_rule};
use serde_json::{Value, json};

/// Every field the reference's headless rules carry, plus the shapes that must
/// *not* be flattened: `logical`, `invert`, and values no parser accepts.
fn corpus() -> Vec<Value> {
    vec![
        json!({"domain": ["a.com"]}),
        json!({"domain": "single-string.com"}),
        json!({"domain": []}),
        json!({"domain": [1, 2, "mixed.com"]}),
        json!({"domain_suffix": ["example.com"]}),
        json!({"domain_suffix": ["a.com"]}),
        json!({"domain_suffix": [".com"]}),
        json!({"domain_suffix": [".a.com"]}),
        json!({"domain_suffix": [""]}),
        json!({"domain_keyword": ["ads", "tracker"]}),
        json!({"domain_keyword": []}),
        json!({"ip_cidr": ["10.0.0.0/8"]}),
        json!({"ip_cidr": ["192.168.1.0/24", "0.0.0.0/0"]}),
        json!({"ip_cidr": ["2001:db8::/32"]}),
        json!({"ip_cidr": ["10.0.0.0"]}),
        json!({"ip_cidr": ["10.0.0.0/notanumber"]}),
        json!({"ip_cidr": ["10.0.0.0/33"]}),
        json!({"ip_cidr": ["2001:db8::/200"]}),
        json!({"ip_cidr": [123]}),
        json!({"source_ip_cidr": ["10.0.0.0/8"]}),
        json!({"source_ip_cidr": ["0.0.0.0/0"]}),
        json!({"port": [80, 443]}),
        json!({"port": 8443}),
        json!({"port": "9999"}),
        json!({"port": [70000]}),
        json!({"port_range": ["8000-9000"]}),
        json!({"port_range": ["100-200", "bad", "300-"]}),
        json!({"source_port": [1234]}),
        json!({"source_port_range": ["1000-2000"]}),
        json!({"network": ["tcp"]}),
        json!({"network": ["udp"]}),
        json!({"network": ["tcp", "udp"]}),
        // Several fields at once: a plain rule ORs them, which is what makes the
        // pools mergeable in the first place.
        json!({"domain": ["multi.com"], "port": [443], "network": ["tcp"]}),
        json!({"domain": ["split.com"], "ip_cidr": ["10.1.0.0/16"]}),
        // Not flattenable.
        json!({"invert": true, "domain": ["inverted.com"]}),
        json!({"invert": false, "domain": ["plain-invert-flag.com"]}),
        json!({"type": "logical", "mode": "or", "rules": [
            {"domain": ["logical-or.com"]},
            {"port": [8080]}
        ]}),
        json!({"type": "logical", "mode": "and", "rules": [
            {"domain": ["logical-and.com"]},
            {"port": [443]}
        ]}),
        json!({"type": "logical", "mode": "and", "rules": []}),
        json!({"type": "logical"}),
        // The tree shapes: invert on the logical node itself, a logical rule
        // inside a logical rule, an inverted sub-rule, and a sub-rule that is
        // not an object at all.
        json!({"type": "logical", "mode": "or", "invert": true, "rules": [
            {"domain": ["inverted-logical.com"]},
            {"port": [9999]}
        ]}),
        json!({"type": "logical", "mode": "and", "rules": [
            {"type": "logical", "mode": "or", "rules": [
                {"domain": ["nested.com"]},
                {"port": [8443]}
            ]},
            {"invert": true, "domain": ["never-nested.com"]}
        ]}),
        json!({"type": "logical", "mode": "or", "rules": [
            "not-an-object",
            {"domain": ["sub-with-junk.com"]}
        ]}),
        json!({}),
        json!({"unknown_field": ["ignored.com"]}),
        Value::String("not-an-object".into()),
        Value::Null,
        Value::Array(vec![]),
    ]
}

/// A connection to test against. `domain` sets the destination when `ip` is
/// `None`, and is also the sniffed name in that case -- which is how the
/// reference prefers it.
fn context(
    domain: Option<&str>,
    ip: Option<&str>,
    port: u16,
    source: &str,
    network: &'static str,
) -> ConnContext {
    ConnContext::new(
        "mixed-in",
        source.parse::<SocketAddr>().expect("source"),
        match ip {
            Some(ip) => Target::Ip(ip_target(ip, port)),
            None => Target::Domain(domain.expect("a domain or an ip").to_string(), port),
        },
        network,
    )
}

/// `SocketAddr` from a bare address and a port, bracketing IPv6.
fn ip_target(address: &str, port: u16) -> SocketAddr {
    let literal = if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    };
    literal.parse().expect("ip target")
}

fn contexts() -> Vec<ConnContext> {
    let mut out = Vec::new();

    // Domains, including the cases that separate a label boundary from a string
    // suffix, and the bare domain against its own parent.
    for host in [
        "a.com",
        "cdn.a.com",
        "deep.cdn.a.com",
        "nota.com",
        "xa.com",
        "single-string.com",
        "sub.single-string.com",
        "example.com",
        "cdn.example.com",
        "com",
        "mixed.com",
        "ads.example.net",
        "tracker.net",
        "no-ads-here.org",
        "logical-or.com",
        "logical-and.com",
        "inverted.com",
        "not-inverted.com",
        "plain-invert-flag.com",
        "multi.com",
        "split.com",
        "ignored.com",
        "UPPER.COM",
        "MiXeD.example.com",
        "inverted-logical.com",
        "nested.com",
        "never-nested.com",
        "sub-with-junk.com",
    ] {
        out.push(context(Some(host), None, 443, "10.0.0.2:1234", "tcp"));
        out.push(context(Some(host), None, 80, "192.168.1.50:5000", "udp"));
    }
    // Sniffed domain over an IP destination: the case that catches `ip_cidr`
    // being consulted for a domain target.
    let mut sniffed = context(None, Some("203.0.113.9"), 443, "10.0.0.2:1234", "tcp");
    sniffed.domain = Some("a.com".into());
    out.push(sniffed);

    // IP targets, v4 and v6, across the prefixes above.
    for ip in [
        "10.0.0.1",
        "10.255.255.254",
        "192.168.1.7",
        "203.0.113.9",
        "8.8.8.8",
        "0.0.0.0",
        "255.255.255.255",
        "2001:db8::1",
        "2001:db9::1",
        "::1",
    ] {
        out.push(context(None, Some(ip), 443, "10.0.0.2:1234", "tcp"));
        out.push(context(None, Some(ip), 8080, "203.0.113.1:1", "udp"));
    }
    // Source address and source port driven.
    for source in [
        "10.0.0.2:1234",
        "203.0.113.1:1",
        "10.0.0.2:1500",
        "8.8.8.8:65535",
    ] {
        out.push(context(Some("a.com"), None, 443, source, "tcp"));
    }
    // Port driven.
    for port in [80u16, 443, 3000, 8000, 8500, 9000, 9001, 8080, 8443, 9999] {
        out.push(context(Some("a.com"), None, port, "10.0.0.2:1234", "tcp"));
    }
    out
}

/// The invariant: one rule set holding the whole corpus must answer the same as
/// the interpreter answering rule by rule.
#[test]
fn compiled_index_agrees_with_the_interpreter() {
    let rules = corpus();
    let set = RuleSet::new(vec!["corpus".into()], rules.clone());
    let cases = contexts();

    let mut checked = 0usize;
    for ctx in &cases {
        let expected = rules.iter().any(|rule| match_rule(rule, ctx));
        let actual = set.matches(ctx);
        assert_eq!(
            actual, expected,
            "disagreement on {:?} -> {:?}\n  rule: {:?}",
            ctx.destination, ctx.network, ctx.domain,
        );
        checked += 1;
    }
    assert!(
        checked >= 80,
        "the corpus is too small to mean anything: {checked}"
    );
}

/// Same corpus, but one rule per set: the shape an SRS domain list actually has,
/// and the shape where flattening is worth the most.
#[test]
fn one_rule_per_set_agrees_with_the_interpreter() {
    let rules = corpus();
    let cases = contexts();
    for (at, rule) in rules.iter().enumerate() {
        let set = RuleSet::new(vec!["one".into()], vec![rule.clone()]);
        for ctx in &cases {
            assert_eq!(
                set.matches(ctx),
                match_rule(rule, ctx),
                "rule {at} ({rule}) disagrees on {:?} -> {:?}",
                ctx.destination,
                ctx.network
            );
        }
    }
}

/// Prefixes must behave at the edges, including the two the old code got wrong
/// or only got right by accident.
#[test]
fn prefix_edges() {
    let set = RuleSet::new(
        vec!["cidr".into()],
        vec![
            json!({"ip_cidr": ["10.0.0.0/8"]}),
            json!({"ip_cidr": ["192.168.1.0/24"]}),
            json!({"ip_cidr": ["172.16.0.0/12"]}),
            json!({"ip_cidr": ["2001:db8::/32"]}),
        ],
    );

    let all = RuleSet::new(
        vec!["all".into()],
        vec![
            json!({"ip_cidr": ["0.0.0.0/0"]}),
            json!({"ip_cidr": ["::/0"]}),
        ],
    );

    let ip = |addr: &str, port: u16| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Ip(ip_target(addr, port)),
            "tcp",
        )
    };

    // /0 matched everything in release and panicked in debug: the old code
    // computed `u32::MAX << 32`.
    assert!(all.matches(&ip("8.8.8.8", 443)), "0.0.0.0/0 matches any v4");
    assert!(all.matches(&ip("2001:db8::1", 443)), "::/0 matches any v6");
    // Boundary of each prefix: first and last address inside, first outside.
    assert!(set.matches(&ip("10.0.0.0", 443)));
    assert!(set.matches(&ip("10.255.255.255", 443)));
    assert!(!set.matches(&ip("11.0.0.0", 443)), "11/8 is outside 10/8");
    assert!(set.matches(&ip("192.168.1.0", 443)));
    assert!(set.matches(&ip("192.168.1.255", 443)));
    assert!(!set.matches(&ip("192.168.2.0", 443)), "outside /24");
    assert!(set.matches(&ip("172.16.0.0", 443)));
    assert!(set.matches(&ip("172.31.255.255", 443)));
    assert!(!set.matches(&ip("172.32.0.0", 443)), "outside 172.16/12");
    assert!(set.matches(&ip("2001:db8::1", 443)));
    assert!(!set.matches(&ip("2001:db9::1", 443)), "outside 2001:db8/32");
    // A v4 prefix never matches a v6 address and the other way round.
    assert!(
        !set.matches(&ip("::1", 443)),
        "10/8 is not in ::/0's absence"
    );
}

/// `domain_suffix` is label-boundary, `".suffix"` is a plain string suffix. The
/// two differ on exactly one input and getting it backwards would leak every
/// `notexample.com` into an `example.com` rule.
#[test]
fn suffix_is_label_bounded_but_dot_suffix_is_not() {
    let bare = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain_suffix": ["example.com"]})],
    );
    let dotted = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain_suffix": [".example.com"]})],
    );
    let domain = |host: &str| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Domain(host.to_string(), 443),
            "tcp",
        )
    };

    assert!(bare.matches(&domain("example.com")), "the host itself");
    assert!(bare.matches(&domain("cdn.example.com")), "a child");
    assert!(
        !bare.matches(&domain("notexample.com")),
        "not a label boundary"
    );
    assert!(
        !bare.matches(&domain("example.com.evil.net")),
        "suffix, not prefix"
    );

    assert!(
        !dotted.matches(&domain("example.com")),
        "a dot suffix skips the bare host"
    );
    assert!(dotted.matches(&domain("cdn.example.com")));
    assert!(
        !dotted.matches(&domain("notexample.com")),
        "still label bounded"
    );
}

/// `invert` and `logical` must not be flattened: `invert` inverts the whole rule,
/// so merging it into shared pools would invert the wrong thing.
#[test]
fn inverted_and_logical_rules_stay_on_the_interpreter() {
    let inverted = RuleSet::new(
        vec!["s".into()],
        vec![json!({"invert": true, "domain": ["a.com"]})],
    );
    assert_eq!(inverted.fallback_count(), 1, "invert kept as a fallback");
    assert!(
        inverted.index().is_empty(),
        "and contributed no pool entries"
    );

    let logical = RuleSet::new(
        vec!["s".into()],
        vec![json!({"type": "logical", "mode": "or", "rules": [
            {"domain": ["a.com"]},
            {"port": [443]}
        ]})],
    );
    assert_eq!(logical.fallback_count(), 1, "logical kept as a fallback");
    assert!(logical.index().is_empty());

    let mixed = RuleSet::new(
        vec!["s".into()],
        vec![
            json!({"domain": ["pooled.com"]}),
            json!({"invert": true, "domain": ["never.com"]}),
        ],
    );
    assert_eq!(
        mixed.fallback_count(),
        1,
        "only the inverted one is kept back"
    );
    assert!(mixed.index().has_domain("pooled.com"));
    assert!(
        !mixed.index().has_domain("never.com"),
        "and it pooled nothing"
    );
}

/// An empty set, or one whose every entry was unparsable, must never match.
/// A bare `{}` is deliberately not on this list: it is a rule with no
/// criteria at all, the interpreter answers true for it, and `corpus` pins
/// that same answer.
#[test]
fn nothing_to_match_means_no_match() {
    for rules in [
        vec![],
        vec![json!({"domain": []})],
        vec![json!({"ip_cidr": ["nonsense"]})],
        vec![json!({"port_range": ["nonsense"]})],
        vec![Value::Null],
    ] {
        let set = RuleSet::new(vec!["s".into()], rules.clone());
        for ctx in contexts().iter().take(20) {
            assert!(
                !set.matches(ctx),
                "{rules:?} matched {:?} -> {:?}",
                ctx.destination,
                ctx.network
            );
        }
        assert_eq!(
            set.rule_count(),
            rules.len(),
            "rule_count still counts as loaded"
        );
    }
}

/// Stored domains keep their case and only the query is lowercased, which is
/// what the old code did: `domain_host` lowercases and the entries were compared
/// raw. The consequence is that a mixed-case entry can *never* match, because
/// every query arrives lowercased. That is inherited behaviour, kept here on
/// purpose -- deciding whether the reference matches case-insensitively belongs
/// in its own commit against the reference, not inside a performance change.
#[test]
fn stored_case_is_left_alone_and_the_query_is_lowered() {
    let set = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain": ["Mixed.Example.COM"]})],
    );
    let domain = |host: &str| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Domain(host.to_string(), 443),
            "tcp",
        )
    };
    // The query is lowered, the entry is not: no match, exactly as before.
    assert!(!set.matches(&domain("mixed.example.com")));
    assert!(!set.matches(&domain("Mixed.Example.COM")));
    assert!(!set.matches(&domain("MIXED.EXAMPLE.COM")));
    // The entry is stored verbatim, which `has_domain` shows.
    assert!(set.index().has_domain("Mixed.Example.COM"));

    // A lowercase entry does match, and does so case-insensitively on the query.
    let lower = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain": ["mixed.example.com"]})],
    );
    assert!(lower.matches(&domain("mixed.example.com")));
    assert!(lower.matches(&domain("Mixed.Example.COM")));
    assert!(lower.matches(&domain("MIXED.EXAMPLE.COM")));
}

/// A remote update swaps the compiled form wholesale, and the new one is what
/// answers immediately after.
#[test]
fn a_remote_update_replaces_the_compiled_form() {
    let set = RuleSet::new(vec!["s".into()], vec![json!({"domain": ["old.com"]})]);
    let domain = |host: &str| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Domain(host.to_string(), 443),
            "tcp",
        )
    };
    assert!(set.matches(&domain("old.com")));

    set.replace_rules(vec![
        json!({"domain": ["new.com"]}),
        json!({"domain_suffix": ["suffix.com"]}),
    ]);
    assert!(!set.matches(&domain("old.com")), "the old entry is gone");
    assert!(set.matches(&domain("new.com")));
    assert!(set.matches(&domain("cdn.suffix.com")));
    assert_eq!(set.rule_count(), 2);
    assert_eq!(set.fallback_count(), 0);

    // And an update that empties the set empties the matching too.
    set.replace_rules(Vec::new());
    assert!(!set.matches(&domain("new.com")));
    assert_eq!(set.rule_count(), 0);
}

/// The pools must hold what went in, which is what `rule-set match` and the
/// remote-rule-set tests read.
#[test]
fn the_index_reports_what_it_holds() {
    let set = RuleSet::new(
        vec!["s".into()],
        vec![
            json!({"domain": ["a.com", "b.com"]}),
            json!({"domain_suffix": ["example.com", ".dot.com"]}),
            json!({"domain_keyword": ["ads"]}),
            json!({"ip_cidr": ["10.0.0.0/8"]}),
            json!({"port": [80, 443]}),
        ],
    );
    let index = set.index();
    assert_eq!(index.domain_count(), 2);
    assert!(index.has_domain("a.com") && index.has_domain("b.com"));
    assert!(!index.has_domain("c.com"));
    assert!(index.has_suffix("example.com"));
    assert!(
        index.has_suffix(".dot.com"),
        "a dot suffix is still a suffix"
    );
    assert!(index.has_keyword("cdn.ads.net"));
    assert!(!index.has_keyword("cdn.net"));
    assert!(index.has_prefix("10.1.2.3".parse().expect("ip"), 8));
    assert!(!index.has_prefix("11.1.2.3".parse().expect("ip"), 8));
    assert_eq!(index.len(), 2 + 2 + 1 + 1 + 2);
}
