//! Response cache for the DNS client: TTL-bounded LRU with optional
//! optimistic serving (return stale + background refresh).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::codec::ResponseMeta;

#[derive(Clone)]
pub struct CacheKey {
    pub tag: String,
    pub name: String,
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
    entries: HashMap<CacheKey, CacheEntry>,
    capacity: usize,
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(16),
        }
    }

    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<CacheHit> {
        let entry = self.entries.get(key)?;
        let age = now.duration_since(entry.inserted);
        if age < entry.ttl {
            return Some(CacheHit::Fresh(Arc::clone(&entry.raw)));
        }
        if entry.optimistic_until.is_some_and(|until| now < until) {
            return Some(CacheHit::Stale(Arc::clone(&entry.raw)));
        }
        None
    }

    pub fn insert(
        &mut self,
        key: CacheKey,
        raw: impl Into<Arc<[u8]>>,
        meta: &ResponseMeta,
        optimistic_timeout: Option<Duration>,
    ) {
        let ttl_secs = meta.min_answer_ttl.unwrap_or(60).max(1);
        if self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        let inserted = Instant::now();
        let optimistic_until = optimistic_timeout.map(|window| inserted + window);
        self.entries.insert(
            key,
            CacheEntry {
                raw: raw.into(),
                inserted,
                ttl: Duration::from_secs(ttl_secs as u64),
                optimistic_until,
            },
        );
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.inserted)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        self.entries.remove(&oldest);
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
        assert!(matches!(cache.get(&key(), now), Some(CacheHit::Fresh(_))));
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
        assert!(matches!(cache.get(&key(), now), Some(CacheHit::Fresh(_))));
        assert!(matches!(
            cache.get(&key(), now + Duration::from_secs(2)),
            Some(CacheHit::Stale(_))
        ));
        assert!(cache.get(&key(), now + Duration::from_secs(400)).is_none());
    }

    #[test]
    fn evicts_oldest_over_capacity() {
        let mut cache = Cache::new(16);
        for i in 0..17 {
            let mut k = key();
            k.name = format!("h{i}.test");
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
}
