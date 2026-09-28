//! F0 spike C (ADR-0005): round-trip against a Go bbolt-written golden file.
//!
//! `tests/spikes/bbolt/golden.db` is produced by `go run ./gen write` and is
//! committed. `core-experimental` must read it, and files it writes must be
//! readable by the Go implementation (verified when `go` is on PATH).

use std::path::PathBuf;
use std::process::Command;

use core_experimental::bbolt::{EntrySpec, NodeSpec};

fn spike_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/spikes/bbolt")
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 256) as u8).collect()
}

fn assert_content(db: &core_experimental::bbolt::Db) {
    assert_eq!(
        db.get(&["db-version"], b"value").unwrap().as_deref(),
        Some(&b"1"[..]),
        "db-version/value"
    );
    assert!(db.has_bucket(&["cache"]).unwrap(), "cache bucket");
    assert_eq!(
        db.get(&["cache"], b"k1").unwrap().as_deref(),
        Some(&b"v1"[..]),
        "cache/k1"
    );
    assert_eq!(
        db.get(&["cache"], b"k2").unwrap(),
        Some(pattern(3000)),
        "cache/k2"
    );
    assert!(db.has_bucket(&["cache", "sub"]).unwrap(), "cache/sub");
    assert_eq!(
        db.get(&["cache", "sub"], b"nested").unwrap().as_deref(),
        Some(&b"deep"[..]),
        "cache/sub/nested"
    );
    // a value spanning several overflow pages
    assert_eq!(db.get(&["cache"], b"big").unwrap(), Some(pattern(20000)));
    // a bucket wide enough to sit behind branch pages
    assert!(db.has_bucket(&["wide"]).unwrap(), "wide bucket");
    for i in 0..500u32 {
        let key = format!("key-{i:04}");
        assert_eq!(
            db.get(&["wide"], key.as_bytes()).unwrap(),
            Some(vec![i as u8]),
            "wide/{key}"
        );
    }
}

#[test]
fn reads_go_written_golden_db() {
    let path = spike_dir().join("golden.db");
    let db = core_experimental::bbolt::Db::open(&path).expect("open golden.db");
    assert_eq!(db.meta().page_size, 4096);
    assert_content(&db);
}

#[test]
fn writes_db_go_can_verify() {
    let sub = NodeSpec {
        entries: vec![EntrySpec::Kv("nested".into(), b"deep".to_vec())],
    };
    let cache = NodeSpec {
        entries: vec![
            EntrySpec::Kv("k1".into(), b"v1".to_vec()),
            EntrySpec::Kv("k2".into(), pattern(3000)),
            EntrySpec::Kv("big".into(), pattern(20000)),
            EntrySpec::Bucket {
                name: "sub".into(),
                seq: 0,
                node: sub,
            },
        ],
    };
    let wide = NodeSpec {
        entries: (0..500u32)
            .map(|i| EntrySpec::Kv(format!("key-{i:04}"), vec![i as u8]))
            .collect(),
    };
    let root = NodeSpec {
        entries: vec![
            EntrySpec::Bucket {
                name: "db-version".into(),
                seq: 0,
                node: NodeSpec {
                    entries: vec![EntrySpec::Kv("value".into(), b"1".to_vec())],
                },
            },
            EntrySpec::Bucket {
                name: "cache".into(),
                seq: 0,
                node: cache,
            },
            EntrySpec::Bucket {
                name: "wide".into(),
                seq: 0,
                node: wide,
            },
        ],
    };

    let out = std::env::temp_dir().join(format!("tachyon-bbolt-rust-{}.db", std::process::id()));
    core_experimental::bbolt::write(&out, &root).expect("write db");

    let db = core_experimental::bbolt::Db::open(&out).expect("re-open own db");
    assert_content(&db);

    let go = Command::new("go")
        .args(["run", "./gen", "verify"])
        .arg(&out)
        .current_dir(spike_dir())
        .output();
    match go {
        Ok(out_res) => {
            assert!(
                out_res.status.success(),
                "go verify failed: {}\n{}",
                String::from_utf8_lossy(&out_res.stdout),
                String::from_utf8_lossy(&out_res.stderr)
            );
        }
        Err(e) => {
            eprintln!("go not available ({e}); skipping go-verify leg");
        }
    }
    let _ = std::fs::remove_file(&out);
}
