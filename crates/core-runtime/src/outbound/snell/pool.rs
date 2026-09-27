//! snell connection reuse pool (reference `snellv4/reuse.go`): keeps fully
//! established, fully drained sessions alive for `reuse` clients. A session
//! whose client side EOF'd with the zero-length record (and whose reply was
//! already read) can be served to the next request instead of dialing again.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::record::{RecordReader, RecordWriter};

pub(crate) const POOL_SIZE: usize = 10;
pub(crate) const POOL_MAX_AGE: Duration = Duration::from_secs(180);
const POOL_TICK: Duration = Duration::from_secs(20);

const STATE_READY: u32 = 0;
const STATE_ACTIVE: u32 = 1;
const STATE_CLOSED: u32 = 2;

/// The record-stream halves parked inside a session while it is idle.
type Halves<W, R> = (Option<RecordWriter<W>>, Option<RecordReader<R>>);

/// Shared half of a snell TCP session: one record stream per direction.
///
/// While the session is `Active` the halves live outside the session (in the
/// owning stream) — the state machine guarantees exclusivity, so no lock is
/// held across `.await`s. `Drop` hands them back before release/close.
pub(crate) struct Session<W, R> {
    state: AtomicU32,
    halves: Mutex<Halves<W, R>>,
    created: Instant,
}

impl<W, R> Session<W, R> {
    /// New sessions start `Active` (reference sets `StateActive` right after
    /// dialing); pooling happens later via `release`.
    pub(crate) fn new(writer: RecordWriter<W>, reader: RecordReader<R>) -> Self {
        Self {
            state: AtomicU32::new(STATE_ACTIVE),
            halves: Mutex::new((Some(writer), Some(reader))),
            created: Instant::now(),
        }
    }

    /// Claim an idle session for a new request. Fails if it is already
    /// serving someone or was closed.
    pub(crate) fn take(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_READY,
                STATE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Move the record stream out for use by the owning stream.
    pub(crate) fn take_halves(&self) -> Option<(RecordWriter<W>, RecordReader<R>)> {
        let mut halves = self.halves.lock().expect("snell: session poisoned");
        match (halves.0.take(), halves.1.take()) {
            (Some(writer), Some(reader)) => Some((writer, reader)),
            (writer, reader) => {
                halves.0 = writer;
                halves.1 = reader;
                None
            }
        }
    }

    /// Return the record stream after use (release or close path).
    pub(crate) fn put_halves(&self, writer: RecordWriter<W>, reader: RecordReader<R>) {
        let mut halves = self.halves.lock().expect("snell: session poisoned");
        halves.0 = Some(writer);
        halves.1 = Some(reader);
    }

    /// Mark the session drainable again (client sent EOF chunk and read the
    /// server's EOF). Fails if the session was closed concurrently.
    pub(crate) fn release(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_ACTIVE,
                STATE_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub(crate) fn close(&self) {
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.created.elapsed() >= POOL_MAX_AGE
    }
}

struct PoolState<W, R> {
    idle: VecDeque<Arc<Session<W, R>>>,
    closed: bool,
    ticking: bool,
}

/// Typed pool: snell sessions are the only tenants, so generics beat trait
/// objects here (the stream needs the concrete writer/reader to resume).
pub(crate) struct Pool<W, R> {
    state: Mutex<PoolState<W, R>>,
}

impl<W, R> Pool<W, R>
where
    W: Send + 'static,
    R: Send + 'static,
{
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(PoolState {
                idle: VecDeque::new(),
                closed: false,
                ticking: false,
            }),
        })
    }

    /// Pop the most recently used session that can still serve a request.
    pub(crate) fn take(&self) -> Option<Arc<Session<W, R>>> {
        let mut state = self.state.lock().expect("snell: pool poisoned");
        if state.closed {
            return None;
        }
        while let Some(session) = state.idle.pop_back() {
            if session.is_stale() {
                session.close();
                continue;
            }
            if session.take() {
                return Some(session);
            }
        }
        None
    }

    /// Park a drained session; the pool owns it from here (reference
    /// `ConnectionPool.PutConnection`: size limit, then oldest eviction).
    /// The expiry ticker starts lazily on the first insert (reference
    /// `MoveToPool` starts `ExpireLoop` on demand).
    pub(crate) fn insert(self: &Arc<Self>, session: Arc<Session<W, R>>) {
        let start_ticker = {
            let mut state = self.state.lock().expect("snell: pool poisoned");
            if state.closed || !session.release() {
                session.close();
                return;
            }
            state.idle.push_front(session);
            while state.idle.len() > POOL_SIZE {
                if let Some(evicted) = state.idle.pop_back() {
                    evicted.close();
                }
            }
            if state.ticking {
                false
            } else {
                state.ticking = true;
                true
            }
        };
        if start_ticker {
            let pool = Arc::clone(self);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(POOL_TICK);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    if !pool.prune() {
                        return;
                    }
                }
            });
        }
    }

    /// Periodic age sweep; returns false once the pool is empty or closed so
    /// the ticker task can exit (the next insert restarts it).
    fn prune(&self) -> bool {
        let mut state = self.state.lock().expect("snell: pool poisoned");
        if state.closed {
            state.ticking = false;
            return false;
        }
        let mut index = 0usize;
        while index < state.idle.len() {
            if state.idle[index].is_stale() {
                if let Some(stale) = state.idle.remove(index) {
                    stale.close();
                }
            } else {
                index += 1;
            }
        }
        if state.idle.is_empty() {
            state.ticking = false;
            return false;
        }
        true
    }

    pub(crate) fn shutdown(&self) {
        let mut state = self.state.lock().expect("snell: pool poisoned");
        state.closed = true;
        state.ticking = false;
        while let Some(session) = state.idle.pop_back() {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::snell::record::{RecordReader, RecordWriter};

    fn session() -> Session<tokio::io::Sink, tokio::io::Empty> {
        Session::new(
            RecordWriter::new(tokio::io::sink(), b"test-psk-12345678"),
            RecordReader::new(tokio::io::empty(), b"test-psk-12345678"),
        )
    }

    type TestPool = Pool<tokio::io::Sink, tokio::io::Empty>;

    #[tokio::test]
    async fn take_insert_roundtrip() {
        let pool = TestPool::new();
        assert!(pool.take().is_none());
        pool.insert(Arc::new(session()));
        let pooled = pool.take().expect("session back");
        assert!(!pooled.take(), "second take fails while active");
        // The owner returning a drained session releases it back to Ready.
        pool.insert(pooled.clone());
        let again = pool.take().expect("returned session");
        assert!(Arc::ptr_eq(&pooled, &again), "same session reused");
        pool.shutdown();
    }

    #[tokio::test]
    async fn pool_size_is_enforced() {
        let pool = TestPool::new();
        for _ in 0..(POOL_SIZE + 5) {
            pool.insert(Arc::new(session()));
        }
        let mut held = Vec::new();
        while let Some(pooled) = pool.take() {
            held.push(pooled);
        }
        assert_eq!(held.len(), POOL_SIZE);
        pool.shutdown();
    }

    #[tokio::test]
    async fn shutdown_empties_the_pool() {
        let pool = TestPool::new();
        pool.insert(Arc::new(session()));
        pool.shutdown();
        assert!(pool.take().is_none());
        // insert after shutdown closes instead of parking.
        pool.insert(Arc::new(session()));
        assert!(pool.take().is_none());
    }

    #[tokio::test]
    async fn closed_sessions_are_rejected() {
        let pool = TestPool::new();
        let pooled = Arc::new(session());
        pooled.close();
        pool.insert(pooled);
        assert!(pool.take().is_none());
        pool.shutdown();
    }
}
