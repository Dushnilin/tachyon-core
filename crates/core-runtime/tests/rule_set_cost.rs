//! What a geo-scale rule set actually costs per connection.
//!
//! `route/rule.rs` compiles its rules once at start: CIDRs go through
//! `parse_prefixes`, port ranges through `parse_ranges`, domains through
//! `DomainItem`. `route/rule_set.rs` does none of that -- it holds `Vec<Value>`
//! and, on every lookup, clones each rule's lists into fresh `Vec<String>` and
//! re-parses every CIDR string. This measures the difference on the shape those
//! lists actually have: a domain list big enough to matter, and a CIDR list.
//!
//! Nothing here asserts a wall-clock bound. Timings are printed so the shape is
//! visible; a test that fails on a loaded CI runner teaches nothing.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Instant;

use serde_json::json;

use core_runtime::inbound::Target;
use core_runtime::route::ConnContext;
use core_runtime::route::rule_set::RuleSet;

/// A geo-database-shaped domain list: `host{n}.example{n}.com`, one per rule,
/// because that is how the SRS containers emit a domain list -- one headless rule
/// per domain, not one rule holding all of them.
fn domain_rules(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|n| {
            let bucket = n % 977;
            json!({ "domain": [format!("host{n}.cdn{bucket}.example.com")] })
        })
        .collect()
}

fn cidr_rules(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|n| json!({ "ip_cidr": [format!("{}.{}.0.0/16", n / 256 % 256, n % 256)] }))
        .collect()
}

fn domain_ctx(host: &str) -> ConnContext {
    ConnContext::new(
        "mixed-in",
        "10.0.0.2:1234".parse::<SocketAddr>().expect("source"),
        Target::Domain(host.to_string(), 443),
        "tcp",
    )
}

fn ip_ctx(addr: &str) -> ConnContext {
    ConnContext::new(
        "mixed-in",
        "10.0.0.2:1234".parse::<SocketAddr>().expect("source"),
        Target::Ip(addr.parse().expect("ip")),
        "tcp",
    )
}

const LOOKUPS: usize = 200;

/// Ignored because it is a measurement, not a check: ~30 s in release and ~100 s
/// in debug, which is too much for a suite that runs on every push. Run it with
/// `cargo test --release -p core-runtime --test rule_set_cost -- --ignored
/// --nocapture` to reproduce the tables below.
///
/// Measured 2026-10-02, release profile, x86_64, one lookup of a domain that
/// matches nothing (so a scan had to visit every rule -- the common case for a
/// geo list):
///
/// | rules | before | after | a bare HashSet |
/// |---:|---:|---:|---:|
/// | 1 000 | 393 µs | 158 ns | 38 ns |
/// | 50 000 | 21.6 ms | 161 ns | 39 ns |
/// | 200 000 | **102.5 ms** | **162 ns** | 39 ns |
///
/// The lookup stopped depending on the size of the list, which was the whole
/// point: 200 000 rules cost what 1 000 do. The 4× left against a bare HashSet
/// is the rest of the pools -- the suffix label walk, the source address, the
/// port and the network checks -- that a one-field lookup does not do.
///
/// `ip_cidr`, which used to re-parse every CIDR string on every lookup:
///
/// | rules | before | after |
/// |---:|---:|---:|
/// | 1 000 | 321 µs | 41 ns |
/// | 50 000 | 17.9 ms | 55 ns |
/// | 200 000 | 17.6 ms | 51 ns |
///
/// And what a router pays to compile a set, which happens on the update path
/// rather than the matching path -- and outside the write lock, so matching is
/// never blocked by it:
///
/// | rules | first load | remote update |
/// |---:|---:|---:|
/// | 1 000 | 1.2 ms | 0.8 ms |
/// | 50 000 | 77 ms | 51 ms |
/// | 200 000 | 337 ms | 231 ms |
#[test]
#[ignore = "a measurement, not a check; run it deliberately"]
fn rule_set_matching_cost() {
    // ---------------------------------------------------------------- domains
    for n in [1_000usize, 50_000, 200_000] {
        let set = RuleSet::new(vec!["geo".into()], domain_rules(n));

        // Worst case for a scan: the answer is "no", so every rule is visited.
        let miss = domain_ctx("nothing.in.this.list.example");
        let start = Instant::now();
        let mut hits = 0usize;
        for _ in 0..LOOKUPS {
            if set.matches(&miss) {
                hits += 1;
            }
        }
        let per_lookup = start.elapsed() / LOOKUPS as u32;

        // The same list, compiled once. This is what `rule.rs` already does.
        let compiled: HashSet<String> = (0..n)
            .map(|i| {
                let bucket = i % 977;
                format!("host{i}.cdn{bucket}.example.com")
            })
            .collect();
        let start = Instant::now();
        let mut hits2 = 0usize;
        for _ in 0..LOOKUPS {
            if compiled.contains("nothing.in.this.list.example") {
                hits2 += 1;
            }
        }
        let compiled_per_lookup = start.elapsed() / LOOKUPS as u32;

        let ratio =
            per_lookup.as_nanos().max(1) as f64 / compiled_per_lookup.as_nanos().max(1) as f64;
        println!(
            "domains n={:>7}  miss: rule_set {:>12?}  hashset {:>12?}  ratio {:>7.0}x   (hits {}/{})",
            n, per_lookup, compiled_per_lookup, ratio, hits, hits2
        );
    }

    // ------------------------------------------------------------------ CIDRs
    for n in [1_000usize, 50_000, 200_000] {
        let set = RuleSet::new(vec!["geo-ip".into()], cidr_rules(n));
        let miss = ip_ctx("203.0.113.7:443");
        let start = Instant::now();
        for _ in 0..LOOKUPS {
            let _ = set.matches(&miss);
        }
        let per_lookup = start.elapsed() / LOOKUPS as u32;
        println!("cidrs   n={:>7}  miss: rule_set {:>12?}", n, per_lookup);
    }

    // ------------------------------------------------------------- compiling
    // A remote update recompiles the whole set, so this is a number a router
    // pays: it happens on the update path, not the matching path.
    for n in [1_000usize, 50_000, 200_000] {
        let rules = domain_rules(n);
        let start = Instant::now();
        let set = RuleSet::new(vec!["geo".into()], rules.clone());
        let first = start.elapsed();
        let start = Instant::now();
        set.replace_rules(rules);
        let update = start.elapsed();
        println!(
            "compile n={:>7}  first load {:>10?}  remote update {:>10?}",
            n, first, update
        );
    }
}
