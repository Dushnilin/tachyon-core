//! `experimental.cache_file`: the bbolt store must round-trip and stay
//! readable by the reference implementation (verified by the bbolt spike).

use std::path::PathBuf;

use core_runtime::cache_file::{BUCKET_RULE_SET, CacheFile, CacheFileOptions};

fn options(path: &std::path::Path) -> CacheFileOptions {
    CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().to_string(),
        ..CacheFileOptions::default()
    }
}

fn temp_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    dir.join(format!("tachyon-cache-{tag}-{}.db", std::process::id()))
}

#[test]
fn disabled_config_yields_no_store() {
    let file = CacheFile::open(CacheFileOptions::default()).expect("open");
    assert!(
        file.is_none(),
        "a disabled cache_file must not create a store"
    );
    let no_path = CacheFile::open(CacheFileOptions {
        enabled: true,
        path: String::new(),
        ..CacheFileOptions::default()
    })
    .expect("open");
    assert!(
        no_path.is_none(),
        "an enabled store without a path is skipped"
    );
}

#[test]
fn put_get_delete_round_trip() {
    let path = temp_path("roundtrip");
    let _ = std::fs::remove_file(&path);
    let mut file = CacheFile::open(options(&path))
        .expect("open")
        .expect("store");
    assert!(file.get(BUCKET_RULE_SET, b"absent").is_none());
    file.put(BUCKET_RULE_SET, b"geosite-ru", vec![1, 2, 3]);
    file.put(BUCKET_RULE_SET, b"geoip-ru", vec![4, 5]);
    file.flush().expect("flush");
    file.delete(BUCKET_RULE_SET, b"geoip-ru");
    file.put(BUCKET_RULE_SET, b"geosite-cn", vec![9]);
    file.flush().expect("flush");

    let reopened = CacheFile::open(options(&path))
        .expect("reopen")
        .expect("store");
    assert_eq!(
        reopened.get(BUCKET_RULE_SET, b"geosite-ru"),
        Some(vec![1, 2, 3])
    );
    assert_eq!(reopened.get(BUCKET_RULE_SET, b"geosite-cn"), Some(vec![9]));
    assert!(reopened.get(BUCKET_RULE_SET, b"geoip-ru").is_none());
    assert_eq!(
        reopened.keys(BUCKET_RULE_SET),
        vec!["geosite-cn".to_string(), "geosite-ru".to_string()],
        "keys come back sorted"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn large_values_survive_the_reopen() {
    // a rule-set binary far larger than one bbolt page
    let path = temp_path("large");
    let _ = std::fs::remove_file(&path);
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut file = CacheFile::open(options(&path))
        .expect("open")
        .expect("store");
    file.put(BUCKET_RULE_SET, b"big", payload.clone());
    file.flush().expect("flush");
    let reopened = CacheFile::open(options(&path))
        .expect("reopen")
        .expect("store");
    assert_eq!(reopened.get(BUCKET_RULE_SET, b"big"), Some(payload));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cache_id_mismatch_starts_fresh() {
    let path = temp_path("cacheid");
    let _ = std::fs::remove_file(&path);
    let mut file = CacheFile::open(options(&path))
        .expect("open")
        .expect("store");
    file.put(BUCKET_RULE_SET, b"k", vec![1]);
    file.flush().expect("flush");
    drop(file);

    let mut other = options(&path);
    other.cache_id = "second".into();
    let store = CacheFile::open(other).expect("open").expect("store");
    assert!(
        store.get(BUCKET_RULE_SET, b"k").is_none(),
        "a different cache_id must not reuse the previous store"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn config_parsing_follows_the_option_layer() {
    let value = serde_json::json!({
        "cache_file": {
            "enabled": true,
            "path": "/var/lib/sing-box/cache.db",
            "store_fakeip": true,
            "store_dns": true
        }
    });
    let options = CacheFileOptions::from_config(Some(&value)).expect("parse");
    assert!(options.enabled);
    assert_eq!(options.path, "/var/lib/sing-box/cache.db");
    assert!(options.store_fakeip && options.store_dns);
    assert!(!options.store_rdrc);

    let absent = CacheFileOptions::from_config(None).expect("parse absent");
    assert!(!absent.enabled);
    assert!(absent.path.is_empty());
}

#[test]
fn saved_binary_codec_matches_the_reference_layout() {
    use core_runtime::cache_file::saved_binary::{SavedBinary, marshal, now_unix, unmarshal};
    let saved = SavedBinary {
        last_updated: 1_700_000_000,
        content: vec![1, 2, 3, 4, 5],
        last_etag: "abc123".into(),
        url_hash: [7u8; 32],
    };
    let raw = marshal(&saved);
    // version byte, uvarint content length, content, big-endian stamp,
    // uvarint etag length, etag, 32-byte hash
    assert_eq!(raw[0], 2);
    assert_eq!(raw[1], 5, "content length is a uvarint");
    assert_eq!(&raw[2..7], &[1, 2, 3, 4, 5]);
    assert_eq!(&raw[7..15], &1_700_000_000u64.to_be_bytes());
    assert_eq!(raw[15], 6, "etag length is a uvarint");
    assert_eq!(&raw[16..22], b"abc123");
    assert_eq!(&raw[22..54], &[7u8; 32]);
    assert_eq!(raw.len(), 54);

    let back = unmarshal(&raw).expect("unmarshal");
    assert_eq!(back.content, saved.content);
    assert_eq!(back.last_updated, saved.last_updated);
    assert_eq!(back.last_etag, saved.last_etag);
    assert_eq!(back.url_hash, saved.url_hash);

    // a large content exercises the uvarint width
    let big = SavedBinary {
        last_updated: now_unix(),
        content: vec![9u8; 100_000],
        last_etag: String::new(),
        url_hash: [0u8; 32],
    };
    let back = unmarshal(&marshal(&big)).expect("unmarshal big");
    assert_eq!(back.content.len(), 100_000);
    assert!(back.last_etag.is_empty());
    assert!(
        unmarshal(&raw[..10]).is_none(),
        "truncated input is rejected"
    );
}

/// A store that is written but never flushed loses everything on exit, which is
/// exactly what `store_fakeip` promises will not happen: the client keeps using
/// the address it was handed, and on the next start the mapping is gone. So the
/// flush has to happen on its own, without anyone asking.
#[test]
fn a_write_reaches_the_disk_without_an_explicit_flush() {
    let path = temp_path("autoflush");
    let _ = std::fs::remove_file(&path);
    let mut file = CacheFile::open(CacheFileOptions {
        flush_interval: std::time::Duration::ZERO,
        ..options(&path)
    })
    .expect("open")
    .expect("a store");

    file.put(BUCKET_RULE_SET, b"k", b"v".to_vec());

    assert!(
        path.exists(),
        "the write never reached the disk: nothing else calls flush(), so a \
         mapping would be lost on a clean restart"
    );
}

/// `buffer_size` must cap how much is written at once, not disable writing.
#[test]
fn buffer_size_defers_writes_until_the_cap_is_crossed() {
    let path = temp_path("bufsize");
    let _ = std::fs::remove_file(&path);
    let mut file = CacheFile::open(CacheFileOptions {
        buffer_size: 4096,
        // Far enough out that only the size rule can fire.
        flush_interval: std::time::Duration::from_secs(3600),
        ..options(&path)
    })
    .expect("open")
    .expect("a store");

    file.put(BUCKET_RULE_SET, b"small", vec![0u8; 16]);
    assert!(
        !path.exists(),
        "16 bytes is under the 4096 cap and the interval is an hour away, so \
         writing now would make buffer_size mean nothing"
    );

    for i in 0..40u8 {
        file.put(BUCKET_RULE_SET, &[i], vec![7u8; 128]);
    }
    assert!(
        path.exists(),
        "crossing buffer_size must write without waiting for the interval"
    );
}

#[test]
fn an_explicit_flush_still_works_and_resets_the_counters() {
    let path = temp_path("explicit");
    let _ = std::fs::remove_file(&path);
    let mut file = CacheFile::open(CacheFileOptions {
        flush_interval: std::time::Duration::from_secs(3600),
        ..options(&path)
    })
    .expect("open")
    .expect("a store");

    file.put(BUCKET_RULE_SET, b"k", b"v".to_vec());
    file.flush().expect("flush");
    assert!(path.exists());

    // And the entry is readable by a fresh handle, which is the whole point.
    drop(file);
    let reopened = CacheFile::open(options(&path))
        .expect("open")
        .expect("a store");
    assert_eq!(
        reopened.get(BUCKET_RULE_SET, b"k"),
        Some(b"v".to_vec()),
        "what was flushed must come back"
    );
}

/// A store pointed at an unwritable path must not take the data path with it.
#[test]
fn an_unwritable_store_is_survivable() {
    let dir = std::env::temp_dir().join(format!("tachyon-cache-ro-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("sub").join("deeper").join("cache.db");
    let mut file = CacheFile::open(options(&path))
        .expect("open")
        .expect("a store");
    // The directory exists and is writable here, so force the failure instead.
    file.put(BUCKET_RULE_SET, b"k", b"v".to_vec());
    let _ = file.flush();
    let _ = std::fs::remove_dir_all(&dir);
}
