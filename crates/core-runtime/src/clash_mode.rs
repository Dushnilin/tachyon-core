//! The clash mode: `rule` (default), `global` or `direct`.
//!
//! The Clash UI switches it through `PATCH /configs {"mode": ...}` and rules
//! match on it, so it has to be process-global and cheap to read on the data
//! path.

use std::sync::{Mutex, OnceLock, RwLock};

use crate::cache_file::SharedCacheFile;

pub const RULE: &str = "rule";
pub const GLOBAL: &str = "global";
pub const DIRECT: &str = "direct";

static MODE: RwLock<&'static str> = RwLock::new(RULE);
static STORE: OnceLock<Mutex<Option<SharedCacheFile>>> = OnceLock::new();

/// The runtime hands the cache handle over so a mode change can be persisted,
/// the way the reference keeps `bucketMode`, and the mode that was in the cache
/// becomes the mode we start in.
pub fn attach_store(store: Option<SharedCacheFile>) {
    let slot = STORE.get_or_init(|| Mutex::new(None));
    *slot.lock().expect("clash mode store") = store;
    let guard = slot.lock().expect("store");
    let Some(store) = guard.as_ref() else {
        return;
    };
    let Ok(cache) = store.lock() else {
        return;
    };
    if let Some(mode) = cache.get(crate::cache_file::BUCKET_MODE, b"mode")
        && let Ok(mode) = String::from_utf8(mode)
    {
        set(mode.trim());
    }
}

fn persist() {
    let guard = STORE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("clash mode store");
    let Some(store) = guard.as_ref() else {
        return;
    };
    if let Ok(mut cache) = store.lock() {
        cache.put(
            crate::cache_file::BUCKET_MODE,
            b"mode",
            get().as_bytes().to_vec(),
        );
    }
}

/// `true` when the mode was one of the three the reference accepts.
pub fn set(name: &str) -> bool {
    let next = match name {
        "" => RULE,
        RULE => RULE,
        GLOBAL => GLOBAL,
        DIRECT => DIRECT,
        _ => return false,
    };
    match MODE.write() {
        Ok(mut guard) => {
            *guard = next;
        }
        Err(_) => return false,
    }
    persist();
    true
}

pub fn get() -> &'static str {
    match MODE.read() {
        Ok(guard) => *guard,
        Err(_) => RULE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_roundtrips_and_rejects_unknown_names() {
        assert!(set(GLOBAL));
        assert_eq!(get(), GLOBAL);
        assert!(set(DIRECT));
        assert_eq!(get(), DIRECT);
        assert!(set(""));
        assert_eq!(get(), RULE, "an empty name falls back to rule");
        assert!(!set("script"), "an unknown mode is refused");
        assert_eq!(get(), RULE, "a refused mode leaves the old one alone");
    }
}
