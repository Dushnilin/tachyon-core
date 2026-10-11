//! urltest outbound: probes member outbounds with an HTTP request through
//! each and routes through the lowest-latency one, re-probing on an interval.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::inbound::{AnyStream, Conn, Target};
use crate::logging;
use crate::route::Router;
use crate::tls_client;

pub struct Urltest {
    shared: Arc<Shared>,
}

struct Shared {
    members: Vec<String>,
    resolved: OnceLock<Vec<usize>>,
    current: AtomicUsize,
    latencies: Mutex<Vec<Option<u64>>>,
    probe: UrlProbe,
    interval: Duration,
    tolerance_ms: u64,
}

struct UrlProbe {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

impl Urltest {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let members = obj
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing tags"))?
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: outbounds entries must be strings"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if members.is_empty() {
            anyhow::bail!("{at}: missing tags");
        }
        let probe = parse_probe_url(
            obj.get("url")
                .and_then(Value::as_str)
                .unwrap_or("https://www.gstatic.com/generate_204"),
            at,
        )?;
        let interval = parse_duration(
            obj.get("interval"),
            Duration::from_secs(180),
            format!("{at}: interval").as_str(),
        )?;
        let tolerance_ms = obj.get("tolerance").and_then(Value::as_u64).unwrap_or(50);
        Ok(Self {
            shared: Arc::new(Shared {
                members,
                resolved: OnceLock::new(),
                current: AtomicUsize::new(0),
                latencies: Mutex::new(Vec::new()),
                probe,
                interval,
                tolerance_ms,
            }),
        })
    }

    /// Resolve member tags against the built outbound table (at startup).
    pub fn resolve(&self, tags: &std::collections::HashMap<String, usize>) -> anyhow::Result<()> {
        let mut resolved = Vec::with_capacity(self.shared.members.len());
        for tag in &self.shared.members {
            let index = tags.get(tag).copied().ok_or_else(|| {
                anyhow::anyhow!("urltest member references unknown outbound {tag:?}")
            })?;
            resolved.push(index);
        }
        let _ = self
            .shared
            .latencies
            .lock()
            .map(|mut l| *l = vec![None; resolved.len()]);
        let _ = self.shared.resolved.set(resolved);
        Ok(())
    }

    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        let members = self
            .shared
            .resolved
            .get()
            .ok_or_else(|| io::Error::other("urltest members not resolved"))?;
        let index = self.shared.current.load(Ordering::Relaxed);
        let Some(member) = members.get(index) else {
            return Err(io::Error::other("urltest selection out of range"));
        };
        router.connect_index(*member, target).await
    }

    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        let members = self
            .shared
            .resolved
            .get()
            .ok_or_else(|| io::Error::other("urltest members not resolved"))?;
        let index = self.shared.current.load(Ordering::Relaxed);
        let Some(member) = members.get(index) else {
            return Err(io::Error::other("urltest selection out of range"));
        };
        router.connect_udp_index(*member, target).await
    }

    /// Member tags and the current selection (clash group view).
    pub fn all(&self) -> &[String] {
        &self.shared.members
    }

    pub fn now(&self) -> &str {
        self.shared
            .members
            .get(self.shared.current.load(Ordering::Relaxed))
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Switch to member by tag across reloads or runtime commands.
    pub fn select(&self, member: &str) -> bool {
        if let Some(pos) = self.shared.members.iter().position(|m| m == member) {
            self.shared.current.store(pos, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Copy measured latencies from an earlier urltest group if member tags match.
    pub fn copy_latencies_from(&self, old: &Urltest) {
        let old_latencies = old.shared.latencies.lock().expect("old latencies lock");
        let mut new_latencies = self.shared.latencies.lock().expect("new latencies lock");
        for (new_pos, member) in self.shared.members.iter().enumerate() {
            if let Some(old_pos) = old.shared.members.iter().position(|m| m == member)
                && let Some(Some(latency)) = old_latencies.get(old_pos)
                && new_pos < new_latencies.len()
            {
                new_latencies[new_pos] = Some(*latency);
            }
        }
    }

    /// Spawn the background probe loop (called once the router is shared).
    pub(crate) fn spawn(&self, router: Arc<Router>) -> tokio::task::JoinHandle<()> {
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            loop {
                probe_all(&shared, &router).await;
                tokio::time::sleep(shared.interval).await;
            }
        })
    }
}

async fn probe_all(shared: &Arc<Shared>, router: &Arc<Router>) {
    let Some(members) = shared.resolved.get() else {
        return;
    };
    // Reference probes every member concurrently and records each result as
    // it lands, so the clash history fills while the round is still running.
    // The pool is capped at 8: a 42-member subscription round all at once
    // saturates a router CPU and blows the per-probe budget, and the
    // statuses the UI shows would never fill — the same nodes answer in
    // ~1s when tested one at a time.
    let sem = Arc::new(tokio::sync::Semaphore::new(8));
    let mut set = tokio::task::JoinSet::new();
    for (pos, member) in members.iter().enumerate() {
        let shared = Arc::clone(shared);
        let router = Arc::clone(router);
        let sem = Arc::clone(&sem);
        let member = *member;
        set.spawn(async move {
            let permit = sem.acquire().await.expect("probe pool never closes");
            let ms = probe_member(&shared, &router, member).await;
            drop(permit);
            // Clash DelayHistory: every successful probe records its
            // post-dial delay; failures do not.
            if let Some(ms) = ms {
                router.record_delay(member, ms as u32);
            }
            (pos, ms)
        });
    }
    let mut results: Vec<Option<u64>> = vec![None; members.len()];
    while let Some(joined) = set.join_next().await {
        if let Ok((pos, ms)) = joined {
            results[pos] = ms;
        }
    }
    let mut latencies = shared.latencies.lock().expect("latencies lock");
    latencies.clone_from(&results);

    let Some((best_pos, best_ms)) = results
        .iter()
        .enumerate()
        .filter_map(|(pos, ms)| ms.map(|ms| (pos, ms)))
        .min_by_key(|(_, ms)| *ms)
    else {
        return;
    };
    let current = shared.current.load(Ordering::Relaxed);
    let switch = match results.get(current).copied().flatten() {
        Some(current_ms) => {
            best_pos != current && current_ms.saturating_sub(best_ms) > shared.tolerance_ms
        }
        None => best_pos != current,
    };
    if switch {
        shared.current.store(best_pos, Ordering::Relaxed);
    }
}

/// Logs every completed read/write of a probe connection with its size and
/// the gap since the previous one: a stalled TLS handshake shows up as one
/// huge `r` gap, a paced one as a run of small `r` entries.
///
/// With `watchdog`, an I/O gap past [`STALL`] aborts the attempt instead of
/// riding out the TCP retransmission timer — a fresh connection rolls the
/// dice again and usually answers in one clean RTT. The deadline lives in a
/// `Sleep` polled alongside the I/O: a parked read gets no poll, so a
/// check-on-poll guard would never fire exactly when it is needed.
struct Tap {
    inner: AnyStream,
    member: usize,
    last: Instant,
    watchdog: bool,
    stall: Pin<Box<tokio::time::Sleep>>,
}

const STALL: Duration = Duration::from_millis(1200);

impl Tap {
    fn new(inner: AnyStream, member: usize, watchdog: bool) -> Self {
        Self {
            inner,
            member,
            last: Instant::now(),
            watchdog,
            stall: Box::pin(tokio::time::sleep(STALL)),
        }
    }

    fn mark(&mut self, dir: &str, n: usize) {
        let now = Instant::now();
        let gap = now.duration_since(self.last).as_millis();
        self.last = now;
        if self.watchdog {
            self.stall
                .as_mut()
                .reset(tokio::time::Instant::now() + STALL);
        }
        logging::debug(format_args!(
            "urltest tap[{}]: {dir}{n} +{gap}ms",
            self.member
        ));
    }
}

impl AsyncRead for Tap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(&res, Poll::Ready(Ok(()))) {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.mark("r", n);
            }
            return res;
        }
        if this.watchdog && res.is_pending() && this.stall.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe read stalled",
            )));
        }
        res
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                this.mark("w", *n);
            }
            return res;
        }
        if this.watchdog && res.is_pending() && this.stall.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe write stalled",
            )));
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn probe_member(shared: &Shared, router: &Router, member: usize) -> Option<u64> {
    // Reference has recorded a 6390 ms probe, so its budget is at least
    // ~6.4 s; nodes that answer solo in 5-6 s must still fill the clash
    // history, or the UI shows them as dead while the reference shows them
    // alive. A stalled attempt is cut at STALL and retried on a fresh
    // connection inside the same budget — loss costs one clean re-roll
    // instead of riding the full retransmission timer. The budget is 14 s
    // so a heavy member gets its second attempt: a first attempt can burn
    // 6+ s (dial plus the stall cut), and the 7 s retry guard then needs
    // ~7 s left to still allow the re-roll.
    //
    // The dial itself is never cancelled: pooled transports (xhttp's H2
    // pool) reserve a slot before dialing and release it only on Ok/Err,
    // so a dropped connect leaks the reservation, every later connect
    // through that member parks forever, and the watchdog restarts the
    // whole process over the dead proxy port. The guard before a retry
    // keeps the budget timeout from landing mid-dial either — a dial
    // finishes within its own ~5 s cap, 7 s of budget covers it.
    let deadline = Instant::now() + Duration::from_secs(14);
    for attempt in 1..=3u8 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < Duration::from_millis(400)
            || (attempt > 1 && remaining < Duration::from_secs(7))
        {
            break;
        }
        match tokio::time::timeout(remaining, probe_once(shared, router, member, attempt)).await {
            Ok(ProbeAttempt::Done(ms)) => return Some(ms),
            Ok(ProbeAttempt::Retry) => {}
            Ok(ProbeAttempt::Fail) | Err(_) => break,
        }
    }
    None
}

/// One probe attempt: `Retry` only for losses a fresh connection can dodge,
/// `Fail` for answers that will not change on a re-roll.
enum ProbeAttempt {
    Done(u64),
    Retry,
    Fail,
}

async fn probe_once(shared: &Shared, router: &Router, member: usize, attempt: u8) -> ProbeAttempt {
    let start = Instant::now();
    let target = Target::Domain(shared.probe.host.clone(), shared.probe.port);
    let probe = async {
        let Ok(Conn::Plain(stream)) = router.connect_index(member, &target).await else {
            logging::debug(format_args!(
                "urltest probe[{member}]/a{attempt}: dial failed after {}ms",
                start.elapsed().as_millis()
            ));
            return ProbeAttempt::Fail;
        };
        let dial_ms = start.elapsed();
        let watchdog = attempt < 3;
        let tapped: AnyStream = Box::new(Tap::new(stream, member, watchdog));
        let mut stream: AnyStream = if shared.probe.tls {
            match tls_client::wrap_probe(tapped, &shared.probe.host).await {
                Ok(s) => s,
                Err(e) => {
                    logging::debug(format_args!(
                        "urltest probe[{member}]/a{attempt}: tls failed after {}ms: {e}",
                        dial_ms.as_millis()
                    ));
                    return if e.kind() == io::ErrorKind::TimedOut {
                        ProbeAttempt::Retry
                    } else {
                        ProbeAttempt::Fail
                    };
                }
            }
        } else {
            tapped
        };
        let tls_at = start.elapsed();
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            shared.probe.path, shared.probe.host
        );
        if stream.write_all(request.as_bytes()).await.is_err() {
            return ProbeAttempt::Retry;
        }
        // One read per chunk, not one per byte: the head crosses a boxed
        // stream plus a TLS record layer, and a byte-at-a-time loop pays
        // that round trip ~200 times for every probe in the round.
        let mut head = Vec::with_capacity(256);
        let mut buf = [0u8; 1024];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return ProbeAttempt::Retry,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
            if head.len() > 16 * 1024 {
                return ProbeAttempt::Fail;
            }
        }
        let head_at = start.elapsed();
        logging::debug(format_args!(
            "urltest probe[{member}]/a{attempt}: dial {}ms tls {}ms req {}ms total {}ms",
            dial_ms.as_millis(),
            tls_at.saturating_sub(dial_ms).as_millis(),
            head_at.saturating_sub(tls_at).as_millis(),
            head_at.as_millis()
        ));
        let head = String::from_utf8_lossy(&head);
        let Some(status) = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
        else {
            return ProbeAttempt::Fail;
        };
        if !status.starts_with('2') {
            return ProbeAttempt::Fail;
        }
        // The recorded delay starts after the dial, like the clash delay
        // click and the reference round do: the dial is TCP setup, not the
        // link the number describes, and including it doubled the history
        // on fast nodes (measured on the 42-member router group: round
        // 261-272 ms against the reference's 138-162, clicks 128-170 on
        // both cores). The full split stays in the debug log above.
        ProbeAttempt::Done(head_at.saturating_sub(dial_ms).as_millis() as u64)
    };
    probe.await
}

fn parse_probe_url(url: &str, at: &str) -> anyhow::Result<UrlProbe> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("{at}: url missing scheme"))?;
    let tls = match scheme {
        "http" => false,
        "https" => true,
        other => anyhow::bail!("{at}: url scheme {other:?} not supported"),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .map_err(|_| anyhow::anyhow!("{at}: url port invalid"))?,
        ),
        None => (authority, if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        anyhow::bail!("{at}: url host missing");
    }
    Ok(UrlProbe {
        tls,
        host: host.to_string(),
        port,
        path,
    })
}

/// badoption.Duration: Go `time.ParseDuration` strings (`1m30s`, `1.5h`,
/// `250us`, plus the `d` badoption adds), integers in nanoseconds (Go
/// time.Duration JSON semantics). A bare number string still reads as
/// seconds; `check` refuses it before `run` gets here anyway.
pub(crate) fn parse_duration(
    value: Option<&Value>,
    default: Duration,
    at: &str,
) -> anyhow::Result<Duration> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value {
        Value::Number(n) => {
            let nanos = n
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("{at}: invalid duration"))?;
            Ok(Duration::from_nanos(nanos))
        }
        Value::String(raw) => {
            let raw = raw.trim();
            if raw.is_empty() {
                return Ok(default);
            }
            if let Ok(seconds) = raw.parse::<f64>() {
                return Duration::try_from_secs_f64(seconds)
                    .map_err(|_| anyhow::anyhow!("{at}: invalid duration {raw:?}"));
            }
            go_duration(raw).map_err(|err| anyhow::anyhow!("{at}: {err}"))
        }
        other => anyhow::bail!("{at}: invalid duration value {other}"),
    }
}

/// `time.ParseDuration`: one or more `<number><unit>` segments. A negative
/// duration is a timeout that never waits, so it comes out as zero.
fn go_duration(raw: &str) -> Result<Duration, String> {
    let (negative, mut rest) = match raw.as_bytes().first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    if rest.is_empty() {
        return Err(format!("invalid duration {raw:?}"));
    }
    let mut nanos = 0f64;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        let number: f64 = rest[..digits]
            .parse()
            .map_err(|_| format!("invalid duration {raw:?}"))?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..unit_len] {
            "ns" => 1.0,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "d" => 86400e9,
            "" => return Err(format!("missing unit in duration {raw:?}")),
            other => return Err(format!("unknown duration unit {other:?} in {raw:?}")),
        };
        rest = &rest[unit_len..];
        nanos += (number * scale).round();
    }
    if negative {
        return Ok(Duration::ZERO);
    }
    if nanos >= u64::MAX as f64 {
        return Err(format!("invalid duration {raw:?}"));
    }
    Ok(Duration::from_nanos(nanos as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn probe_url_parsing() {
        let p = parse_probe_url("https://www.gstatic.com/generate_204", "t").expect("parse");
        assert!(p.tls);
        assert_eq!(p.host, "www.gstatic.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.path, "/generate_204");

        let p = parse_probe_url("http://127.0.0.1:8123/", "t").expect("parse");
        assert!(!p.tls);
        assert_eq!(p.port, 8123);
        assert_eq!(p.path, "/");

        assert!(parse_probe_url("ftp://x/", "t").is_err());
        assert!(parse_probe_url("nonsense", "t").is_err());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(
            parse_duration(Some(&json!("3m")), Duration::ZERO, "t").expect("ok"),
            Duration::from_secs(180)
        );
        assert_eq!(
            parse_duration(Some(&json!("500ms")), Duration::ZERO, "t").expect("ok"),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration(Some(&json!("2h")), Duration::ZERO, "t").expect("ok"),
            Duration::from_secs(7200)
        );
        assert_eq!(
            parse_duration(Some(&json!("3d")), Duration::ZERO, "t").expect("ok"),
            Duration::from_secs(3 * 86400)
        );
        assert_eq!(
            parse_duration(Some(&json!(30)), Duration::ZERO, "t").expect("ok"),
            Duration::from_nanos(30)
        );
        assert_eq!(
            parse_duration(None, Duration::from_secs(7), "t").expect("ok"),
            Duration::from_secs(7)
        );
        assert!(parse_duration(Some(&json!("3w")), Duration::ZERO, "t").is_err());
    }

    /// `check` takes every Go duration, so `run` has to read them too.
    #[test]
    fn compound_go_durations() {
        let read = |raw: &str| parse_duration(Some(&json!(raw)), Duration::ZERO, "t");
        assert_eq!(read("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(read("1h0m0s").unwrap(), Duration::from_secs(3600));
        assert_eq!(read("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(read("2s500ms").unwrap(), Duration::from_millis(2500));
        assert_eq!(read("250us").unwrap(), Duration::from_micros(250));
        assert_eq!(read("250\u{b5}s").unwrap(), Duration::from_micros(250));
        assert_eq!(read("40ns").unwrap(), Duration::from_nanos(40));
        assert_eq!(read("+1d2h").unwrap(), Duration::from_secs(93_600));
        assert_eq!(read("-5s").unwrap(), Duration::ZERO);
        assert_eq!(read("10").unwrap(), Duration::from_secs(10));
        for bad in ["1m30", "s", "-", "1..2s", "1x", "1e3s"] {
            assert!(read(bad).is_err(), "{bad}");
        }
    }
}

/// A byte size written the way the reference writes it: a number, or a number
/// with a unit suffix. `buffer_size` is the only user, and it is spelled "1MB"
/// in configs people copy from the docs, so the suffixes have to work.
pub(crate) fn parse_size(value: Option<&Value>, at: &str) -> anyhow::Result<usize> {
    let Some(value) = value else {
        return Ok(0);
    };
    match value {
        Value::Number(n) => n
            .as_u64()
            .map(|v| v as usize)
            .ok_or_else(|| anyhow::anyhow!("{at}: invalid size")),
        Value::String(raw) => {
            let raw = raw.trim();
            if raw.is_empty() {
                return Ok(0);
            }
            let split = raw
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(raw.len());
            let (digits, unit) = raw.split_at(split);
            let value: f64 = digits
                .parse()
                .map_err(|_| anyhow::anyhow!("{at}: invalid size {raw:?}"))?;
            // Binary, not decimal: these are buffer sizes, and "1MB" meaning
            // 1000 bytes would put a cap four orders of magnitude below what the
            // config says.
            let scale: f64 = match unit.trim().to_ascii_lowercase().as_str() {
                "" | "b" => 1.0,
                "k" | "kb" => 1024.0,
                "m" | "mb" => 1024.0 * 1024.0,
                "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
                other => anyhow::bail!("{at}: unknown size unit {other:?}"),
            };
            let bytes = value * scale;
            if bytes < 0.0 || !bytes.is_finite() {
                anyhow::bail!("{at}: size {raw:?} is out of range");
            }
            Ok(bytes as usize)
        }
        other => anyhow::bail!("{at}: invalid size value {other}"),
    }
}

#[cfg(test)]
mod size_tests {
    use super::parse_size;
    use serde_json::Value;

    fn parse(raw: &str) -> usize {
        parse_size(Some(&Value::String(raw.to_string())), "buffer_size").expect("parses")
    }

    #[test]
    fn plain_numbers_are_bytes() {
        assert_eq!(parse("0"), 0);
        assert_eq!(parse("512"), 512);
    }

    #[test]
    fn suffixes_are_binary() {
        assert_eq!(parse("1KB"), 1024);
        assert_eq!(parse("1MB"), 1024 * 1024);
        assert_eq!(parse("1mb"), 1024 * 1024);
        assert_eq!(parse("2 GB"), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn an_empty_value_is_zero() {
        assert_eq!(parse(""), 0);
    }

    #[test]
    fn garbage_is_an_error_not_a_silent_zero() {
        // A size that quietly becomes 0 would turn buffer_size into "never
        // flush on size", which looks like it works and never does.
        assert!(parse_size(Some(&Value::String("lots".into())), "buffer_size").is_err());
        assert!(parse_size(Some(&Value::String("1XB".into())), "buffer_size").is_err());
    }
}
