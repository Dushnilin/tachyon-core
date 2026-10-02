//! Who pays in RAM: `Vec<Value>` as it is today, or a compiled structure.
//!
//! This matters because the project's headline number is idle RSS, and typed
//! tries sound like they trade RAM for CPU. Measured on the same 200k-domain
//! list: each rule is a `Value::Object` holding a one-element array holding one
//! `String`, which is a map plus an array plus a heap string per domain, against
//! a flat set of the same strings with no nesting at all.

const N: usize = 200_000;

fn domain(bucket_of: impl Fn(usize) -> usize, n: usize) -> String {
    format!("host{n}.cdn{}.example.com", bucket_of(n))
}

/// Deep size of a parsed JSON value, counted by walking it. No dependency: this
/// is a measurement, not a product.
fn value_bytes(value: &serde_json::Value) -> usize {
    let mut total = std::mem::size_of::<serde_json::Value>();
    match value {
        serde_json::Value::Object(map) => {
            // One map entry: key String + Value, plus the key's own heap buffer.
            total += map.len() * std::mem::size_of::<(String, serde_json::Value)>();
            for (key, child) in map {
                total += key.len();
                total += value_bytes(child);
            }
        }
        serde_json::Value::Array(items) => {
            total += items.len() * std::mem::size_of::<serde_json::Value>();
            for item in items {
                total += value_bytes(item);
            }
        }
        serde_json::Value::String(text) => total += text.len(),
        _ => {}
    }
    total
}

/// Measured 2026-10-02, release profile, 200 000 domains:
///
/// | what the runtime holds | bytes | per entry |
/// |---|---:|---:|
/// | `Vec<Value>` (today) | 98 066 340 | 490 |
/// | `HashSet<Arc<str>>` | 12 536 356 | 63 |
///
/// So the compiled form is **7.8× lighter**, not heavier. The intuition that
/// typed structures cost memory is what makes this worth measuring: each rule
/// today is a `Value::Object` wrapping a one-element array wrapping a `String`,
/// which is a map, an array and a heap allocation per domain. The project's
/// headline is idle RSS, and on this axis the current design is the expensive one.
///
/// Fast enough to keep in the suite (0.3 s), unlike `rule_set_cost`.
#[test]
fn rule_set_memory_cost() {
    // What the runtime holds now: a parsed JSON rule per domain.
    let as_values: Vec<serde_json::Value> = (0..N)
        .map(|n| serde_json::json!({ "domain": [domain(|n| n % 977, n)] }))
        .collect();
    let value_total: usize = as_values.iter().map(value_bytes).sum::<usize>()
        + as_values.capacity() * std::mem::size_of::<serde_json::Value>();

    // What a compiled structure would hold: the domains once, no nesting.
    let as_set: std::collections::HashSet<std::sync::Arc<str>> = (0..N)
        .map(|n| std::sync::Arc::from(domain(|n| n % 977, n)) as std::sync::Arc<str>)
        .collect();
    let set_total: usize = as_set
        .iter()
        .map(|s| std::mem::size_of::<std::sync::Arc<str>>() + s.len())
        .sum::<usize>()
        + as_set.capacity() * std::mem::size_of::<(std::sync::Arc<str>, ())>();

    println!("n={N}");
    println!(
        "  Vec<Value>         {value_total:>10} bytes  ({:.0} bytes/entry)",
        value_total as f64 / N as f64
    );
    println!(
        "  HashSet<Arc<str>> {set_total:>10} bytes  ({:.0} bytes/entry)",
        set_total as f64 / N as f64
    );
    println!(
        "  the compiled form uses {:.1}x less RAM, not more",
        value_total as f64 / set_total.max(1) as f64
    );
}
