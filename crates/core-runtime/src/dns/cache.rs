//! Response cache for the DNS client: TTL-bounded LRU with optional
//! optimistic serving (return stale + background refresh).
//!
//! LRU, not first-in-first-out: eviction used to scan the whole map for the
//! smallest `inserted` (4096 iterations plus a key clone on every insert at
//! capacity) and, worse, a hot entry that was only *read* aged towards the
//! exit while unknown names churned past it. A hit now bumps the entry, and
//! eviction is the LRU crate's own O(1) pop.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::codec::ResponseMeta;

/// Arc'd fields: the key is cloned into the inflight map, the refresh set
/// and the cache itself, and a `String` clone per hop is what that costs.
#[derive(Clone)]
pub struct CacheKey {
    pub tag: Arc<str>,
    pub name: Arc<str>,
    pub qtype: u16,
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.tag == other.tag && self.name == other.name && self.qtype == other.qtype
    }
}
impl Eq for CacheKey {}
impl std::hash::Hash for CacheKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.tag.hash(state);
        self.name.hash(state);
        self.qtype.hash(state);
    }
}

pub struct CacheEntry {
    pub raw: Arc<[u8]>,
    pub inserted: Instant,
    /// Seconds the entry stays fresh (derived from the smallest TTL).
    pub ttl: Duration,
    /// Optimistic window bound (only when optimistic serving is enabled).
    pub optimistic_until: Option<Instant>,
}

pub enum CacheHit {
    Fresh(Arc<[u8]>),
    /// Stale-but-servable: caller must trigger a background refresh.
    Stale(Arc<[u8]>),
}

pub struct Cache {
    entries: LruCache<CacheKey, CacheEntry>,
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(capacity.max(16)).expect("max(16)")),
        }
    }

    /// The read that keeps a hot name alive: it bumps the entry to the front
    /// of the eviction order, so unknown names churning through the cache
    /// cannot push out a name that is being asked for.
    /// The read that keeps a hot name alive: it bumps the entry to the front
    /// of the eviction order, so unknown names churning through the cache
    /// cannot push out a name that is being asked for.
    ///
    /// The timestamp comes back with the hit: a caller that has to attribute
    /// the answer to a point in time (reverse mapping) needs the insert, not
    /// the hit, or repeated hits would keep pushing it forward.
    pub fn get(&mut self, key: &CacheKey, now: Instant) -> Option<(CacheHit, Instant)> {
        let entry = self.entries.get(key)?;
        let received = entry.inserted;
        let age = now.duration_since(entry.inserted);
        if age < entry.ttl {
            return Some((CacheHit::Fresh(Arc::clone(&entry.raw)), received));
        }
        if entry.optimistic_until.is_some_and(|until| now < until) {
            return Some((CacheHit::Stale(Arc::clone(&entry.raw)), received));
        }
        None
    }

    pub fn insert(
        &mut self,
        key: CacheKey,
        raw: impl Into<Arc<[u8]>>,
        meta: &ResponseMeta,
        optimistic_timeout: Option<Duration>,
    ) -> Instant {
        let ttl_secs = meta.min_answer_ttl.unwrap_or(60).max(1);
        let inserted = Instant::now();
        let optimistic_until = optimistic_timeout.map(|window| inserted + window);
        self.entries.put(
            key,
            CacheEntry {
                raw: raw.into(),
                inserted,
                ttl: Duration::from_secs(ttl_secs as u64),
                optimistic_until,
            },
        );
        inserted
    }

    /// Copy non-expired (or optimistically servable) entries into `target`.
    pub fn copy_valid_into(&self, target: &mut Cache, now: Instant) {
        for (k, v) in self.entries.iter() {
            let is_fresh = now.duration_since(v.inserted) < v.ttl;
            let is_optimistic = v.optimistic_until.is_some_and(|until| now < until);
            if is_fresh || is_optimistic {
                target.entries.put(
                    k.clone(),
                    CacheEntry {
                        raw: Arc::clone(&v.raw),
                        inserted: v.inserted,
                        ttl: v.ttl,
                        optimistic_until: v.optimistic_until,
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;

    fn meta(ttl: Option<u32>) -> ResponseMeta {
        ResponseMeta {
            rcode: ResponseCode::NoError,
            min_answer_ttl: ttl,
        }
    }

    fn key() -> CacheKey {
        CacheKey {
            tag: "t".into(),
            name: "a.test".into(),
            qtype: 1,
        }
    }

    #[test]
    fn fresh_then_miss() {
        let mut cache = Cache::new(16);
        let before = Instant::now();
        assert!(cache.get(&key(), before).is_none());
        cache.insert(key(), b"resp".to_vec(), &meta(Some(60)), None);
        // `insert` reads the clock itself, so the instant this test measures
        // from has to be taken after it: sampling before leaves the entry's own
        // timestamp a hair later, and the 61-second probe then lands just under
        // the 61 seconds it meant to be, which is a test that fails at random.
        let now = Instant::now();
        assert!(matches!(
            cache.get(&key(), now),
            Some((CacheHit::Fresh(_), _))
        ));
        assert!(cache.get(&key(), now + Duration::from_secs(61)).is_none());
    }

    #[test]
    fn optimistic_window() {
        let mut cache = Cache::new(16);
        cache.insert(
            key(),
            b"resp".to_vec(),
            &meta(Some(1)),
            Some(Duration::from_secs(300)),
        );
        let now = Instant::now();
        assert!(matches!(
            cache.get(&key(), now),
            Some((CacheHit::Fresh(_), _))
        ));
        assert!(matches!(
            cache.get(&key(), now + Duration::from_secs(2)),
            Some((CacheHit::Stale(_), _))
        ));
        assert!(cache.get(&key(), now + Duration::from_secs(400)).is_none());
    }

    #[test]
    fn evicts_oldest_over_capacity() {
        let mut cache = Cache::new(16);
        for i in 0..17 {
            let mut k = key();
            k.name = format!("h{i}.test").into();
            std::thread::sleep(Duration::from_millis(2));
            cache.insert(k, vec![i as u8], &meta(Some(60)), None);
        }
        assert_eq!(cache.entries.len(), 16);
        let oldest = CacheKey {
            tag: "t".into(),
            name: "h0.test".into(),
            qtype: 1,
        };
        assert!(cache.get(&oldest, Instant::now()).is_none());
    }

    /// The behaviour the scan did not have: reading an entry keeps it, and
    /// the eviction takes the least recently *used* one, not the least
    /// recently inserted.
    #[test]
    fn a_read_keeps_an_entry_alive_across_eviction() {
        let mut cache = Cache::new(16);
        for i in 0..16 {
            let mut k = key();
            k.name = format!("h{i}.test").into();
            cache.insert(k, vec![i as u8], &meta(Some(60)), None);
        }
        let probe = |name: &str| CacheKey {
            tag: "t".into(),
            name: name.into(),
            qtype: 1,
        };
        // touch the oldest insert
        assert!(matches!(
            cache.get(&probe("h0.test"), Instant::now()),
            Some((CacheHit::Fresh(_), _))
        ));
        let mut newest = key();
        newest.name = "h16.test".into();
        cache.insert(newest, vec![16], &meta(Some(60)), None);
        assert!(
            cache.get(&probe("h0.test"), Instant::now()).is_some(),
            "the touched entry survives"
        );
        assert!(
            cache.get(&probe("h1.test"), Instant::now()).is_none(),
            "the untouched one took the eviction"
        );
    }
}
