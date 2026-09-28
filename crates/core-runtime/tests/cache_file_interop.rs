//! `experimental.cache_file` interop with the reference: a cache.db written by
//! go.etcd.io/bbolt must load into the runtime store, and the file the runtime
//! writes must satisfy the reference reader (verified when `go` is on PATH).

use std::path::PathBuf;
use std::process::Command;

use core_runtime::cache_file::{BUCKET_RULE_SET, BUCKET_SELECTED, CacheFile, CacheFileOptions};

fn spike_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/spikes/bbolt")
}

fn options(path: &std::path::Path) -> CacheFileOptions {
    CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().to_string(),
        ..CacheFileOptions::default()
    }
}

fn go(mode: &str, path: &PathBuf) -> Option<std::process::Output> {
    Command::new("go")
        .args(["run", "./gen", mode])
        .arg(path)
        .current_dir(spike_dir())
        .output()
        .ok()
}

#[test]
fn reference_cache_db_loads_and_our_write_passes_the_reference_reader() {
    let Some(written) = go("write-cache", &std::env::temp_dir().join("unused")) else {
        eprintln!("go not available; skipping the interop legs");
        return;
    };
    assert!(written.status.success(), "go write-cache failed");

    let go_path = std::env::temp_dir().join(format!("tachyon-go-cache-{}.db", std::process::id()));
    let Some(result) = go("write-cache", &go_path) else {
        return;
    };
    assert!(result.status.success(), "go write-cache failed");

    // the reference file loads: buckets, ordering and a multi-page value
    let store = CacheFile::open(options(&go_path))
        .expect("open reference cache")
        .expect("store");
    assert_eq!(
        store.get(BUCKET_RULE_SET, b"geosite-ru").map(|v| v.len()),
        Some(3000)
    );
    assert_eq!(
        store.get(BUCKET_RULE_SET, b"big").map(|v| v.len()),
        Some(200_000)
    );
    assert!(store.get(BUCKET_RULE_SET, b"removed").is_some());
    assert_eq!(
        store.keys(BUCKET_RULE_SET),
        vec![
            "big".to_string(),
            "geosite-ru".to_string(),
            "removed".to_string(),
        ],
        "the cursor order must be key order"
    );
    drop(store);

    // a selector choice from the reference file survives our round-trip
    let mut edited = CacheFile::open(options(&go_path))
        .expect("reopen")
        .expect("store");
    edited.put(BUCKET_SELECTED, b"proxy", b"node-a".to_vec());
    edited.delete(BUCKET_RULE_SET, b"removed");
    edited.flush().expect("flush");
    drop(edited);

    let Some(verify) = go("verify-cache", &go_path) else {
        return;
    };
    assert!(
        verify.status.success(),
        "the reference rejected our cache.db:\n{}\n{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let _ = std::fs::remove_file(&go_path);
}
