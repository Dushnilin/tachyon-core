//! XHTTP connection reuse ("XMUX").
//!
//! Ported from `transport/v2rayxhttp/xmux.go`, which mirrors Xray's
//! `XmuxConfig`. Nothing here changes what goes on the wire — the server
//! identifies a session by its session id, not by the connection carrying it —
//! so pooling is purely a client-side policy. What it buys is behaving like an
//! Xray client (subscription configs routinely carry an xmux section) and not
//! paying a fresh TCP+TLS handshake for every stream.
//!
//! Each pooled connection carries the counters that decide when it retires: live
//! streams, handouts left, HTTP requests left and an expiry. Retiring is
//! deferred: a connection with live streams stays up until the last one leaves.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use portable_atomic::AtomicI64;

use tokio::sync::Mutex;

use crate::inbound::AnyStream;

/// `max_concurrency` bounds the streams one connection may carry,
/// `max_connections` the pool size; both zero mean unlimited. A zero
/// `c_max_reuse_times` / `h_max_request_times` / `h_max_reusable_secs` is
/// unlimited too, which is what an xmux section with only one field set leaves
/// for the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntRange(pub u64, pub u64);

impl IntRange {
    const fn zero() -> Self {
        Self(0, 0)
    }

    /// `"4"`, `"1-3"`, a number or a two-element array, like the reference.
    fn parse(value: &serde_json::Value, at: &str) -> anyhow::Result<Self> {
        let pair = match value {
            serde_json::Value::Null => return Ok(Self::zero()),
            serde_json::Value::String(text) => {
                let parts: Vec<&str> = text.split('-').collect();
                match parts.as_slice() {
                    [a] => (a.trim().to_string(), a.trim().to_string()),
                    [a, b] => (a.trim().to_string(), b.trim().to_string()),
                    _ => anyhow::bail!("{at}: invalid range {text:?}"),
                }
            }
            serde_json::Value::Number(number) => (number.to_string(), number.to_string()),
            serde_json::Value::Array(list) if list.len() == 2 => {
                (number_text(&list[0]), number_text(&list[1]))
            }
            _ => anyhow::bail!("{at}: must be a number, a range or a two-element array"),
        };
        let lo: u64 = pair
            .0
            .parse()
            .map_err(|_| anyhow::anyhow!("{at}: invalid range {:?}", pair.0))?;
        let hi: u64 = pair
            .1
            .parse()
            .map_err(|_| anyhow::anyhow!("{at}: invalid range {:?}", pair.1))?;
        Ok(Self(lo.min(hi), lo.max(hi)))
    }

    /// The range is rolled once, not per request.
    fn roll(&self) -> u64 {
        if self.0 == self.1 || self.1 == 0 {
            return self.0;
        }
        let mut bytes = [0u8; 8];
        let _ = getrandom::fill(&mut bytes);
        self.0 + u64::from_le_bytes(bytes) % (self.1 - self.0 + 1)
    }
}

fn number_text(value: &serde_json::Value) -> String {
    value.as_u64().map(|v| v.to_string()).unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XmuxConfig {
    pub max_concurrency: IntRange,
    pub max_connections: IntRange,
    pub c_max_reuse_times: IntRange,
    pub h_max_request_times: IntRange,
    pub h_max_reusable_secs: IntRange,
    /// `h_keep_alive_period`: Xray's HTTP/2 keep-alive ping. An HTTP/1.1
    /// connection has no ping to send, so the value is parsed and reported.
    pub keep_alive_period: i64,
}

impl Default for XmuxConfig {
    fn default() -> Self {
        Self {
            max_concurrency: IntRange::zero(),
            max_connections: IntRange(3, 3),
            c_max_reuse_times: IntRange::zero(),
            h_max_request_times: IntRange(600, 900),
            h_max_reusable_secs: IntRange(1800, 3000),
            keep_alive_period: 0,
        }
    }
}

impl XmuxConfig {
    /// Xray's all-or-nothing rule: an absent *or entirely empty* section takes
    /// the defaults, and a section with any field set is taken as written, so
    /// unset ranges stay zero (unlimited). lx.6 moved the default from
    /// `max_concurrency 1` to `max_connections 3`.
    pub(crate) fn parse(value: Option<&serde_json::Value>, at: &str) -> anyhow::Result<Self> {
        let Some(map) = value.and_then(serde_json::Value::as_object) else {
            return Ok(Self::default());
        };
        if map.is_empty() {
            return Ok(Self::default());
        }
        let max_concurrency = IntRange::parse(
            map.get("max_concurrency")
                .unwrap_or(&serde_json::Value::Null),
            &format!("{at}.max_concurrency"),
        )?;
        let max_connections = IntRange::parse(
            map.get("max_connections")
                .unwrap_or(&serde_json::Value::Null),
            &format!("{at}.max_connections"),
        )?;
        if max_concurrency.1 > 0 && max_connections.1 > 0 {
            anyhow::bail!(
                "{at}: xmux.max_connections cannot be specified together with xmux.max_concurrency"
            );
        }
        let config = Self {
            max_concurrency,
            max_connections,
            c_max_reuse_times: IntRange::parse(
                map.get("c_max_reuse_times")
                    .unwrap_or(&serde_json::Value::Null),
                &format!("{at}.c_max_reuse_times"),
            )?,
            h_max_request_times: IntRange::parse(
                map.get("h_max_request_times")
                    .unwrap_or(&serde_json::Value::Null),
                &format!("{at}.h_max_request_times"),
            )?,
            h_max_reusable_secs: IntRange::parse(
                map.get("h_max_reusable_secs")
                    .unwrap_or(&serde_json::Value::Null),
                &format!("{at}.h_max_reusable_secs"),
            )?,
            keep_alive_period: map
                .get("h_keep_alive_period")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
        };
        if config.keep_alive_period != 0 {
            crate::logging::warn(format_args!(
                "{at}.h_keep_alive_period: HTTP/1.1 has no keep-alive ping (ignored)"
            ));
        }
        Ok(config)
    }
}

/// One pooled connection: a keep-alive HTTP/1.1 connection plus its retirement
/// counters.
///
/// The connection is lent out one request at a time — that is what HTTP/1.1 is,
/// so `max_concurrency` has nothing left to bound here and the pooled unit is
/// the connection rather than a multiplexed stream on top of one.
pub(crate) struct Client {
    pub io: std::sync::Mutex<Option<AnyStream>>,
    open_usage: AtomicI32,
    left_usage: AtomicI32,
    left_requests: AtomicI64,
    unreusable_at: Option<Instant>,
    closed: AtomicBool,
}

impl Client {
    fn new(io: AnyStream, cfg: &XmuxConfig) -> Self {
        let reuse = cfg.c_max_reuse_times.roll();
        let requests = cfg.h_max_request_times.roll();
        let secs = cfg.h_max_reusable_secs.roll();
        Self {
            io: std::sync::Mutex::new(Some(io)),
            open_usage: AtomicI32::new(0),
            // the first handout is the connection's own creation
            left_usage: AtomicI32::new(if reuse > 0 { reuse as i32 - 1 } else { -1 }),
            left_requests: AtomicI64::new(if requests > 0 {
                requests as i64
            } else {
                i64::MAX
            }),
            unreusable_at: (secs > 0).then(|| Instant::now() + Duration::from_secs(secs)),
            closed: AtomicBool::new(false),
        }
    }

    /// Take the connection out for one request, or `None` when somebody else
    /// has it. An HTTP/1.1 connection serves one request at a time, so this is
    /// what keeps two uploads from interleaving on one socket.
    pub(crate) fn take(&self) -> Option<AnyStream> {
        self.io.lock().ok().and_then(|mut slot| slot.take())
    }

    /// Put it back for the next request, unless it has been retired.
    pub(crate) fn give(&self, io: AnyStream) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut slot) = self.io.lock() {
            *slot = Some(io);
        }
    }

    /// One HTTP request against `h_max_request_times`. A packet-up stream issues
    /// one POST per write, and a connection that ignored those would outlive the
    /// limit the server was told about.
    pub(crate) fn take_request(&self) {
        self.left_requests.fetch_sub(1, Ordering::SeqCst);
    }

    fn evict_cause(&self) -> Option<&'static str> {
        if self.closed.load(Ordering::SeqCst) {
            return Some("closed");
        }
        if self.left_usage.load(Ordering::SeqCst) == 0 {
            return Some("reuse");
        }
        if self.left_requests.load(Ordering::SeqCst) <= 0 {
            return Some("requests");
        }
        if self.unreusable_at.is_some_and(|at| Instant::now() > at) {
            return Some("expired");
        }
        None
    }

    fn acquire(&self) {
        self.open_usage.fetch_add(1, Ordering::SeqCst);
        if self.left_usage.load(Ordering::SeqCst) > 0 {
            self.left_usage.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn release(&self) {
        self.open_usage.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The pool itself.
pub(crate) struct Pool {
    config: XmuxConfig,
    /// rolled once at construction, like the reference
    concurrency: u64,
    connections: u64,
    clients: Mutex<Vec<Arc<Client>>>,
}

impl Pool {
    pub(crate) fn new(config: XmuxConfig) -> Arc<Self> {
        let concurrency = config.max_concurrency.roll();
        let connections = config.max_connections.roll();
        Arc::new(Self {
            config,
            concurrency,
            connections,
            clients: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn max_connections(&self) -> usize {
        if self.connections > 0 {
            self.connections as usize
        } else {
            3
        }
    }

    /// A pooled connection that is free and not retired, or `None` so the caller
    /// dials a fresh one.
    pub(crate) async fn acquire(self: &Arc<Self>) -> Option<Arc<Client>> {
        let mut guard = self.clients.lock().await;
        // eviction is deferred: a retired connection with a request on it stays
        // up until that request is over
        let mut evicted = Vec::new();
        guard.retain(|client| match client.evict_cause() {
            Some(_) => {
                evicted.push(Arc::clone(client));
                false
            }
            None => true,
        });
        for client in evicted {
            client.closed.store(true, Ordering::SeqCst);
        }
        if guard.is_empty() {
            return None;
        }
        if self.connections > 0 && guard.len() < self.connections as usize {
            return None;
        }
        let mut candidates: Vec<Arc<Client>> = Vec::with_capacity(guard.len());
        for client in guard.iter() {
            // `max_concurrency` counted streams on an HTTP/2 connection; over
            // HTTP/1.1 the equivalent ceiling is one request, which `take()`
            // already enforces. A value above one is therefore not a limit.
            if self.concurrency <= 1 || client.open_usage.load(Ordering::SeqCst) == 0 {
                candidates.push(Arc::clone(client));
            }
        }
        if candidates.is_empty() {
            return None;
        }
        let index = pick(candidates.len());
        let client = Arc::clone(&candidates[index]);
        client.acquire();
        Some(client)
    }

    /// Adds a freshly dialled connection, created for the caller.
    pub(crate) async fn insert(self: &Arc<Self>, io: AnyStream) -> Arc<Client> {
        let client = Arc::new(Client::new(io, &self.config));
        client.acquire();
        self.clients.lock().await.push(Arc::clone(&client));
        client
    }

    pub(crate) async fn release(&self, client: &Arc<Client>) {
        client.release();
        // a connection that fell out of the pool while it was still in use is
        // torn down only now that its last request is over
        if client.closed.load(Ordering::SeqCst) {
            let _ = client.take();
        }
    }
}

fn pick(len: usize) -> usize {
    if len <= 1 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    (u64::from_le_bytes(bytes) % len as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(value: serde_json::Value) -> IntRange {
        IntRange::parse(&value, "t").expect("range")
    }

    #[test]
    fn ranges_accept_every_spelling() {
        assert_eq!(range(serde_json::json!(4)), IntRange(4, 4));
        assert_eq!(range(serde_json::json!("1-3")), IntRange(1, 3));
        assert_eq!(
            range(serde_json::json!("3-1")),
            IntRange(1, 3),
            "order is normalised"
        );
        assert_eq!(range(serde_json::json!([600, 900])), IntRange(600, 900));
        assert_eq!(range(serde_json::Value::Null), IntRange::zero());
        assert!(IntRange::parse(&serde_json::json!("a-b"), "t").is_err());
    }

    #[test]
    fn an_absent_or_empty_section_takes_the_lx6_defaults() {
        let default = XmuxConfig::parse(None, "xmux").expect("parse");
        assert_eq!(
            default.max_connections,
            IntRange(3, 3),
            "lx.6 changed this from 1"
        );
        assert_eq!(default.max_concurrency, IntRange::zero());
        assert_eq!(default.h_max_request_times, IntRange(600, 900));
        assert_eq!(default.h_max_reusable_secs, IntRange(1800, 3000));
        let empty = XmuxConfig::parse(Some(&serde_json::json!({})), "xmux").expect("parse");
        assert_eq!(empty, default, "an empty object is the same as no section");
    }

    #[test]
    fn a_partly_filled_section_is_taken_as_written() {
        let config = XmuxConfig::parse(
            Some(&serde_json::json!({"c_max_reuse_times": "4-8"})),
            "xmux",
        )
        .expect("parse");
        assert_eq!(config.c_max_reuse_times, IntRange(4, 8));
        assert_eq!(
            config.max_connections,
            IntRange::zero(),
            "unset means unlimited"
        );
        assert_eq!(config.h_max_request_times, IntRange::zero());
    }

    #[test]
    fn max_connections_and_max_concurrency_are_exclusive() {
        let err = XmuxConfig::parse(
            Some(&serde_json::json!({
                "max_connections": 3,
                "max_concurrency": 4,
            })),
            "xmux",
        )
        .expect_err("exclusive")
        .to_string();
        assert!(err.contains("cannot be specified together"), "got {err}");
    }

    #[test]
    fn a_range_rolls_inside_its_bounds() {
        let single = IntRange(7, 7);
        assert_eq!(single.roll(), 7);
        for _ in 0..16 {
            let value = IntRange(5, 9).roll();
            assert!((5..=9).contains(&value), "rolled {value} out of range");
        }
    }
}
