//! `experimental.cache_file` — the bbolt store the reference keeps next to
//! the config (`option.CacheFileOptions` + `experimental/cachefile`).
//!
//! The file is rewritten atomically on flush: the whole tree is read into
//! memory, the changed buckets are replaced, and the tree is written back with
//! the pure-Rust bbolt writer. That matches the reference's observable
//! behaviour (a `cache.db` either has a bucket or it does not) without an
//! append-only page allocator.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use core_experimental::bbolt::{Db, EntrySpec, NodeSpec};
use serde_json::Value;

use crate::logging;

/// `bucketSelected` / `bucketExpand` / `bucketMode` / `bucketRuleSet`,
/// `bucketRDRC` / `bucketDNSCache` / `bucketChainDisabled` (lx).
pub const BUCKET_SELECTED: &str = "selected";
pub const BUCKET_EXPAND: &str = "group_expand";
pub const BUCKET_MODE: &str = "clash_mode";
pub const BUCKET_RULE_SET: &str = "rule_set";
pub const BUCKET_RDRC: &str = "rdrc2";
pub const BUCKET_DNS_CACHE: &str = "dns_cache";
pub const BUCKET_FAKEIP: &str = "fakeip";
pub const BUCKET_CHAIN_DISABLED: &str = "chain_disabled_lx";
/// sing-box stores the `cache_id` under `_id/cache_id`.
const ID_BUCKET: &str = "_id";
const ID_KEY: &[u8] = b"cache_id";

#[derive(Debug, Clone, Default)]
pub struct CacheFileOptions {
    pub enabled: bool,
    pub path: String,
    pub cache_id: String,
    pub store_fakeip: bool,
    pub store_dns: bool,
    pub store_rdrc: bool,
    pub rdrc_timeout: Option<Duration>,
    /// Write out once this many bytes are pending. 0 means "never on size alone",
    /// which is the reference default.
    pub buffer_size: usize,
    /// Write out at least this often. Without it a store that is written once
    /// and then only read would never reach the disk at all.
    pub flush_interval: Duration,
}

impl CacheFileOptions {
    /// `experimental.cache_file`; absent or disabled means no store.
    pub fn from_config(experimental: Option<&Value>) -> anyhow::Result<Self> {
        let Some(obj) = experimental
            .and_then(|value| value.get("cache_file"))
            .filter(|value| !value.is_null())
            .and_then(Value::as_object)
        else {
            return Ok(Self::default());
        };
        let text = |key: &str| {
            obj.get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        let flag = |key: &str| obj.get(key).and_then(Value::as_bool).unwrap_or(false);
        let size = |key: &str| -> anyhow::Result<usize> {
            let Some(raw) = text(key) else {
                return Ok(0);
            };
            crate::outbound::urltest::parse_size(
                Some(&Value::String(raw)),
                &format!("experimental.cache_file.{key}"),
            )
            .map_err(|e| anyhow::anyhow!("experimental.cache_file.{key}: {e}"))
        };
        Ok(Self {
            enabled: flag("enabled"),
            path: text("path").unwrap_or_default(),
            cache_id: text("cache_id").unwrap_or_default(),
            store_fakeip: flag("store_fakeip"),
            store_dns: flag("store_dns"),
            store_rdrc: flag("store_rdrc"),
            buffer_size: size("buffer_size")?,
            // A minute is the reference default. It matters that this is not
            // zero: the store is what keeps the fakeip mapping alive across a
            // restart, and a mapping that never reaches the disk makes every
            // cached address die with "missing fakeip record".
            flush_interval: match text("flush_interval") {
                Some(raw) => crate::outbound::urltest::parse_duration(
                    Some(&Value::String(raw)),
                    Duration::from_secs(60),
                    "experimental.cache_file.flush_interval",
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?,
                None => Duration::from_secs(60),
            },
            rdrc_timeout: match text("rdrc_timeout") {
                Some(raw) => Some(
                    crate::outbound::urltest::parse_duration(
                        Some(&Value::String(raw)),
                        Duration::ZERO,
                        "experimental.cache_file.rdrc_timeout",
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
                None => None,
            },
        })
    }
}

/// The process-wide handle: the store is shared by the rule-set registry and
/// the dns service, both of which outlive any single borrow.
pub type SharedCacheFile = std::sync::Arc<std::sync::Mutex<CacheFile>>;
type BucketValues = BTreeMap<Vec<u8>, Vec<u8>>;
type CacheBuckets = BTreeMap<String, BucketValues>;
type CacheChange<'a> = (&'a str, Vec<u8>, Option<Vec<u8>>);

/// The in-memory mirror of the file, flushed on demand.
#[derive(Debug)]
pub struct CacheFile {
    options: CacheFileOptions,
    path: PathBuf,
    buckets: CacheBuckets,
    dirty: bool,
    /// Bytes written since the last flush, the measure `buffer_size` bounds.
    pending: usize,
    /// When the last flush happened, the measure `flush_interval` bounds.
    last_flush: Instant,
}

impl CacheFile {
    /// Open (or create) the store; `None` when the config disables it.
    pub fn open(options: CacheFileOptions) -> anyhow::Result<Option<Self>> {
        if !options.enabled || options.path.is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(&options.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("cache file {}: {e}", parent.display()))?;
        }
        let mut buckets = BTreeMap::new();
        if path.exists() {
            match Db::open(&path) {
                Ok(db) => buckets = read_all(&db),
                Err(error) => logging::warn(format_args!(
                    "cache file {}: read failed ({error}); starting empty",
                    path.display()
                )),
            }
        }
        let mut store = Self {
            options,
            path,
            buckets,
            dirty: false,
            pending: 0,
            last_flush: Instant::now(),
        };
        // the reference keys the file by cache_id: a different id starts fresh
        let current = store.get(ID_BUCKET, ID_KEY);
        if !store.options.cache_id.is_empty()
            && current.as_deref() != Some(store.options.cache_id.as_bytes())
        {
            if current.is_some() {
                logging::info(format_args!(
                    "cache file {}: cache_id changed, starting fresh",
                    store.path.display()
                ));
            }
            store.buckets.clear();
            store.put(
                ID_BUCKET,
                ID_KEY,
                store.options.cache_id.clone().into_bytes(),
            );
            store.dirty = true;
        }
        Ok(Some(store))
    }

    pub fn options(&self) -> &CacheFileOptions {
        &self.options
    }

    pub fn get(&self, bucket: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.buckets
            .get(bucket)
            .and_then(|entries| entries.get(key))
            .cloned()
    }

    pub fn put(&mut self, bucket: &str, key: &[u8], value: Vec<u8>) {
        if let Some(existing) = self.buckets.get(bucket).and_then(|b| b.get(key))
            && existing == &value
        {
            return;
        }
        self.pending += key.len() + value.len();
        self.buckets
            .entry(bucket.to_string())
            .or_default()
            .insert(key.to_vec(), value);
        self.dirty = true;
        self.flush_if_due();
    }

    pub fn delete(&mut self, bucket: &str, key: &[u8]) {
        if let Some(entries) = self.buckets.get_mut(bucket)
            && entries.remove(key).is_some()
        {
            self.pending += key.len();
            self.dirty = true;
            self.flush_if_due();
        }
    }

    /// Update paired records before a due flush can expose half an update.
    pub(crate) fn apply_changes(&mut self, changes: Vec<CacheChange<'_>>) {
        let mut modified = false;
        for (bucket, key, value) in changes {
            let entries = self.buckets.entry(bucket.to_string()).or_default();
            match value {
                Some(value) => {
                    if entries.get(&key) == Some(&value) {
                        continue;
                    }
                    self.pending += key.len() + value.len();
                    entries.insert(key, value);
                    modified = true;
                }
                None => {
                    if entries.remove(&key).is_some() {
                        self.pending += key.len();
                        modified = true;
                    }
                }
            }
        }
        if modified {
            self.dirty = true;
            self.flush_if_due();
        }
    }

    /// Write out if the pending bytes or the elapsed time says so.
    ///
    /// This is what makes the store durable at all. Before, `flush` existed but
    /// nothing called it: entries accumulated in memory for the life of the
    /// process and were lost on exit, so `store_fakeip` promised a mapping that
    /// survived a restart and did not. The time check matters as much as the size
    /// one - a store written once and then only read would otherwise sit in
    /// memory forever, and a mapping lost to a clean restart is exactly what
    /// makes a cached fakeip address die as "missing fakeip record".
    ///
    /// A write failure is logged rather than propagated: a store that cannot be
    /// written must not take down the data path that is using it.
    pub(crate) fn flush_if_due(&mut self) {
        if !self.dirty {
            return;
        }
        let by_size = self.options.buffer_size > 0 && self.pending >= self.options.buffer_size;
        let by_time = self.last_flush.elapsed() >= self.options.flush_interval;
        if !by_size && !by_time {
            return;
        }
        if let Err(error) = self.flush() {
            logging::warn(format_args!(
                "cache file {}: write failed ({error}); keeping it in memory",
                self.path.display()
            ));
        }
    }

    /// Every key of a bucket, in order (the reference cursor walks them sorted).
    pub fn keys(&self, bucket: &str) -> Vec<String> {
        self.buckets
            .get(bucket)
            .map(|entries| {
                entries
                    .keys()
                    .filter_map(|key| String::from_utf8(key.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every binary key of a bucket, in order.
    pub fn raw_keys(&self, bucket: &str) -> Vec<Vec<u8>> {
        self.buckets
            .get(bucket)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Atomic tmp+mv rewrite of the whole tree, which is what the reference's
    /// batching writes too - `buffer_size` and `flush_interval` decide when it
    /// happens, not how big a piece of it is, so there is nothing to accumulate.
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let root = build_tree(&self.buckets);
        let tmp = self.path.with_extension("db.tmp");
        core_experimental::bbolt::write(&tmp, &root)?;
        std::fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        self.pending = 0;
        self.last_flush = Instant::now();
        Ok(())
    }
}

/// bbolt keys are bytes; the store only holds UTF-8 in practice.
/// `adapter.SavedBinary` as the reference marshals it: version, varint-prefixed
/// content, last-updated (big endian seconds), etag and the url hash.
pub mod saved_binary {
    use std::time::{SystemTime, UNIX_EPOCH};

    pub const VERSION: u8 = 2;

    #[derive(Debug, Clone)]
    pub struct SavedBinary {
        pub last_updated: u64,
        pub content: Vec<u8>,
        pub last_etag: String,
        pub url_hash: [u8; 32],
    }

    fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn take_uvarint(data: &[u8], at: &mut usize) -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *data.get(*at)?;
            *at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    }

    pub fn marshal(saved: &SavedBinary) -> Vec<u8> {
        let mut out = Vec::with_capacity(saved.content.len() + 64);
        out.push(VERSION);
        put_uvarint(&mut out, saved.content.len() as u64);
        out.extend_from_slice(&saved.content);
        out.extend_from_slice(&saved.last_updated.to_be_bytes());
        put_uvarint(&mut out, saved.last_etag.len() as u64);
        out.extend_from_slice(saved.last_etag.as_bytes());
        out.extend_from_slice(&saved.url_hash);
        out
    }

    pub fn unmarshal(raw: &[u8]) -> Option<SavedBinary> {
        let mut at = 1usize;
        let content_len = take_uvarint(raw, &mut at)? as usize;
        let content = raw.get(at..at + content_len)?.to_vec();
        at += content_len;
        let stamp = raw.get(at..at + 8)?;
        let last_updated = u64::from_be_bytes(stamp.try_into().ok()?);
        at += 8;
        let etag_len = take_uvarint(raw, &mut at)? as usize;
        let last_etag = String::from_utf8(raw.get(at..at + etag_len)?.to_vec()).ok()?;
        at += etag_len;
        let url_hash: [u8; 32] = raw.get(at..at + 32)?.try_into().ok()?;
        Some(SavedBinary {
            last_updated,
            content,
            last_etag,
            url_hash,
        })
    }
}

fn read_all(db: &Db) -> CacheBuckets {
    let mut buckets = BTreeMap::new();
    let mut load = |name: &str| {
        if !db.has_bucket(&[name]).unwrap_or(false) {
            return;
        }
        let mut entries = BTreeMap::new();
        collect(db, &[name], &mut entries);
        buckets.insert(name.to_string(), entries);
    };
    load(BUCKET_SELECTED);
    load(BUCKET_EXPAND);
    load(BUCKET_MODE);
    load(BUCKET_RULE_SET);
    load(BUCKET_RDRC);
    load(BUCKET_DNS_CACHE);
    load(BUCKET_FAKEIP);
    load(BUCKET_CHAIN_DISABLED);
    load(ID_BUCKET);
    // buckets we do not model must survive a rewrite
    for extra in extra_buckets(db) {
        let mut entries = BTreeMap::new();
        collect(db, &[extra.as_str()], &mut entries);
        buckets.insert(extra, entries);
    }
    buckets
}

/// Bucket names present in the file that this build does not model.
fn extra_buckets(db: &Db) -> Vec<String> {
    const KNOWN: &[&str] = &[
        BUCKET_SELECTED,
        BUCKET_EXPAND,
        BUCKET_MODE,
        BUCKET_RULE_SET,
        BUCKET_RDRC,
        BUCKET_DNS_CACHE,
        BUCKET_FAKEIP,
        BUCKET_CHAIN_DISABLED,
        ID_BUCKET,
    ];
    let mut out = Vec::new();
    if let Ok(buckets) = db.bucket_names() {
        for name in buckets {
            if !KNOWN.contains(&name.as_str()) {
                out.push(name);
            }
        }
    }
    out
}

/// Walk every key of a bucket through the page tree.
fn collect(db: &Db, path: &[&str], out: &mut BucketValues) {
    let Ok(Some(page)) = db.bucket_page_raw(path) else {
        return;
    };
    for (key, value) in page {
        if value.is_empty() {
            continue;
        }
        out.insert(key, value);
    }
}

fn build_tree(buckets: &CacheBuckets) -> NodeSpec {
    let mut entries = Vec::with_capacity(buckets.len());
    for (name, kv) in buckets {
        let node = NodeSpec {
            entries: kv
                .iter()
                .map(|(key, value)| EntrySpec::RawKv(key.clone(), value.clone()))
                .collect(),
        };
        entries.push(EntrySpec::Bucket {
            name: name.clone(),
            seq: 0,
            node,
        });
    }
    NodeSpec { entries }
}
