//! urltest outbound: probes member outbounds with an HTTP request through
//! each and routes through the lowest-latency one, re-probing on an interval.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::{AnyStream, Conn, Target};
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

async fn probe_all(shared: &Shared, router: &Router) {
    let Some(members) = shared.resolved.get() else {
        return;
    };
    let mut results: Vec<Option<u64>> = Vec::with_capacity(members.len());
    for member in members {
        results.push(probe_member(shared, router, *member).await);
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

async fn probe_member(shared: &Shared, router: &Router, member: usize) -> Option<u64> {
    let start = Instant::now();
    let target = Target::Domain(shared.probe.host.clone(), shared.probe.port);
    let probe = async {
        let Ok(Conn::Plain(stream)) = router.connect_index(member, &target).await else {
            return None;
        };
        let mut stream: AnyStream = if shared.probe.tls {
            tls_client::wrap_probe(stream, &shared.probe.host)
                .await
                .ok()?
        } else {
            stream
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            shared.probe.path, shared.probe.host
        );
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut head = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await.ok()?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 16 * 1024 {
                return None;
            }
        }
        let head = String::from_utf8_lossy(&head);
        let status = head.lines().next()?.split_whitespace().nth(1)?;
        if !status.starts_with('2') {
            return None;
        }
        Some(())
    };
    match tokio::time::timeout(Duration::from_secs(5), probe).await {
        Ok(Some(())) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
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

/// badoption.Duration: strings with ms/s/m/h suffixes, integers in
/// nanoseconds (Go time.Duration JSON semantics).
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
            let (digits, unit) = raw.split_at(
                raw.find(|c: char| !c.is_ascii_digit() && c != '.')
                    .unwrap_or(raw.len()),
            );
            let value: f64 = digits
                .parse()
                .map_err(|_| anyhow::anyhow!("{at}: invalid duration {raw:?}"))?;
            let scale = match unit {
                "" | "s" => 1.0,
                "ms" => 0.001,
                "m" => 60.0,
                "h" => 3600.0,
                "d" => 86400.0,
                other => anyhow::bail!("{at}: unknown duration unit {other:?}"),
            };
            Ok(Duration::from_secs_f64(value * scale))
        }
        other => anyhow::bail!("{at}: invalid duration value {other}"),
    }
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
}
