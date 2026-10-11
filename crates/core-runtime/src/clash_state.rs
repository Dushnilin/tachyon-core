//! Live connection registry and traffic counters behind the Clash API views
//! (`GET /connections`, `GET /traffic`, `DELETE /connections`).
//!
//! Every relayed TCP connection gets an entry with the routing metadata the
//! reference exposes: inbound, source, destination, rule, chain and the byte
//! counters. Entries also carry a close signal, so the controller can drop a
//! connection the way Clash does.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use portable_atomic::AtomicU64;

use tokio::sync::Notify;

/// Routing metadata for one relayed connection.
#[derive(Clone, Debug)]
pub struct ConnMeta {
    pub network: &'static str,
    /// `inboundType/inboundTag`, the reference `metadata.type`.
    pub inbound: String,
    pub source: String,
    /// The sniffed domain, else the destination's name, else empty.
    pub host: String,
    pub destination: String,
    pub chains: Vec<String>,
    /// `<rule> => <action>`, or `final` when no rule matched.
    pub rule: String,
    pub rule_payload: String,
    pub process_path: String,
}

struct Shared {
    id: u64,
    meta: ConnMeta,
    start: Instant,
    upload: AtomicU64,
    download: AtomicU64,
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

/// Cloneable close signal: the relay loop waits on it, the controller sets it.
#[derive(Clone)]
pub struct CloseSignal {
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CloseSignal {
    /// Resolves once the connection was closed through the API.
    pub async fn wait(&self) {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            self.notify.notified().await;
        }
    }
}

fn trigger(closed: &AtomicBool, notify: &Notify) {
    closed.store(true, Ordering::Release);
    notify.notify_waiters();
}

fn registry() -> &'static Mutex<HashMap<u64, Arc<Shared>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<Shared>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static UPLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Handle held by the relay loop; dropping it removes the entry.
pub struct ConnHandle {
    shared: Arc<Shared>,
}

impl ConnHandle {
    pub fn open(meta: ConnMeta) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(Shared {
            id,
            meta,
            start: Instant::now(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            closed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        });
        if let Ok(mut guard) = registry().lock() {
            guard.insert(id, Arc::clone(&shared));
        }
        Self { shared }
    }

    pub fn id(&self) -> u64 {
        self.shared.id
    }

    /// Close signal for `select!` in the relay loop.
    pub fn close_signal(&self) -> CloseSignal {
        CloseSignal {
            closed: Arc::clone(&self.shared.closed),
            notify: Arc::clone(&self.shared.notify),
        }
    }

    pub fn add_upload(&self, bytes: u64) {
        self.shared.upload.fetch_add(bytes, Ordering::Relaxed);
        UPLOAD_TOTAL.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.shared.download.fetch_add(bytes, Ordering::Relaxed);
        DOWNLOAD_TOTAL.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for ConnHandle {
    fn drop(&mut self) {
        if let Ok(mut guard) = registry().lock() {
            guard.remove(&self.shared.id);
        }
    }
}

/// One row of `GET /connections`.
pub struct ConnView {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: Instant,
    pub meta: ConnMeta,
}

/// Live entries plus the process-wide totals.
pub fn snapshot() -> (Vec<ConnView>, u64, u64) {
    let entries: Vec<Arc<Shared>> = registry()
        .lock()
        .map(|guard| guard.values().cloned().collect())
        .unwrap_or_default();
    let views = entries
        .into_iter()
        .map(|entry| ConnView {
            id: entry.id.to_string(),
            upload: entry.upload.load(Ordering::Relaxed),
            download: entry.download.load(Ordering::Relaxed),
            start: entry.start,
            meta: entry.meta.clone(),
        })
        .collect();
    (
        views,
        UPLOAD_TOTAL.load(Ordering::Relaxed),
        DOWNLOAD_TOTAL.load(Ordering::Relaxed),
    )
}

/// `DELETE /connections/{id}`; `false` when the id is unknown.
pub fn close(id: u64) -> bool {
    let entry = registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(&id).cloned());
    match entry {
        Some(entry) => {
            trigger(&entry.closed, &entry.notify);
            true
        }
        None => false,
    }
}

/// `DELETE /connections`.
pub fn close_all() -> usize {
    let entries: Vec<Arc<Shared>> = registry()
        .lock()
        .map(|guard| guard.values().cloned().collect())
        .unwrap_or_default();
    for entry in &entries {
        trigger(&entry.closed, &entry.notify);
    }
    entries.len()
}

/// Count UDP payload bytes so `/traffic` sees datagram traffic too.
pub fn add_udp(upload: u64, download: u64) {
    UPLOAD_TOTAL.fetch_add(upload, Ordering::Relaxed);
    DOWNLOAD_TOTAL.fetch_add(download, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> ConnMeta {
        unique_meta("example.com:443")
    }

    /// The registry is process-global: serialize the tests inside this binary.
    fn guard() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Distinct destination per call so parallel tests can find their entry.
    fn unique_meta(destination: &str) -> ConnMeta {
        ConnMeta {
            network: "tcp",
            inbound: "mixed-in".into(),
            source: "192.168.1.10:5000".into(),
            host: "example.com".into(),
            destination: destination.into(),
            chains: vec!["proxy".into()],
            rule: "DomainSuffix".into(),
            rule_payload: "example.com".into(),
            process_path: String::new(),
        }
    }

    #[tokio::test]
    async fn registry_tracks_counters_and_close() {
        let _serial = guard().lock().await;
        let handle = ConnHandle::open(meta());
        let signal = handle.close_signal();
        handle.add_upload(10);
        handle.add_download(20);
        let (views, up_total, down_total) = snapshot();
        let view = views
            .iter()
            .find(|v| v.meta.destination == "example.com:443")
            .expect("entry listed");
        assert_eq!((view.upload, view.download), (10, 20));
        assert_eq!(view.meta.rule, "DomainSuffix");
        assert!(up_total >= 10 && down_total >= 20);

        let id: u64 = view.id.parse().expect("id");
        assert_eq!(id, handle.id());
        assert!(close(id), "close reports the connection was found");
        tokio::select! {
            _ = signal.wait() => {}
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                panic!("close signal not delivered")
            }
        }
        assert!(!close(id + 10_000), "unknown ids report false");
    }

    #[tokio::test]
    async fn close_all_wakes_every_relay() {
        let _serial = guard().lock().await;
        let first = ConnHandle::open(meta());
        let second = ConnHandle::open(meta());
        let first_signal = first.close_signal();
        let second_signal = second.close_signal();
        assert!(close_all() >= 2, "both relays are registered");
        for signal in [first_signal, second_signal] {
            tokio::select! {
                _ = signal.wait() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                    panic!("close_all missed a relay")
                }
            }
        }
    }

    #[tokio::test]
    async fn dropping_the_handle_removes_the_entry() {
        let _serial = guard().lock().await;
        let destination = "dropped.example.com:443";
        assert!(
            !snapshot()
                .0
                .iter()
                .any(|view| view.meta.destination == destination)
        );
        {
            let _handle = ConnHandle::open(unique_meta(destination));
            assert_eq!(
                snapshot()
                    .0
                    .iter()
                    .filter(|view| view.meta.destination == destination)
                    .count(),
                1
            );
        }
        assert!(
            !snapshot()
                .0
                .iter()
                .any(|view| view.meta.destination == destination),
            "dropping the handle removes the entry"
        );
    }
}
