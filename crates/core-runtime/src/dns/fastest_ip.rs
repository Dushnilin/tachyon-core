//! Fastest IP ranking for DNS responses.
//!
//! When enabled, queries resolving multiple A / AAAA addresses probe TCP reachability
//! concurrently across the candidates. The first candidate to successfully connect
//! (or with the lowest handshake latency) is promoted to the first answer in the DNS response.
//!
//! Results are cached in an LRU cache to avoid repeated probing for frequent queries.
//! Reserved, private, loopback, and FakeIP benchmark addresses are filtered out.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Configuration for fastest IP ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastestIpConfig {
    pub enabled: bool,
    pub timeout: Duration,
    pub port: u16,
}

impl Default for FastestIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout: Duration::from_millis(200),
            port: 443,
        }
    }
}

/// Returns `true` if the IP address is reserved, private, loopback, or in the FakeIP range.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 198.18.0.0/15 (Benchmarking / FakeIP)
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 (Unique Local)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// LRU cache storing the fastest IP for domain names.
pub struct FastestIpCache {
    cache: RwLock<LruCache<String, (IpAddr, Instant)>>,
    ttl: Duration,
}

impl FastestIpCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            cache: RwLock::new(LruCache::new(cap)),
            ttl,
        }
    }

    pub fn get(&self, name: &str, candidates: &[IpAddr], now: Instant) -> Option<IpAddr> {
        let mut lock = self.cache.write().ok()?;
        if let Some((winner, inserted)) = lock.get(name)
            && now.duration_since(*inserted) < self.ttl
            && candidates.contains(winner)
        {
            return Some(*winner);
        }
        None
    }

    pub fn put(&self, name: String, winner: IpAddr, now: Instant) {
        if let Ok(mut lock) = self.cache.write() {
            lock.put(name, (winner, now));
        }
    }

    pub fn copy_into(&self, target: &FastestIpCache) {
        if let (Ok(src), Ok(mut dst)) = (self.cache.read(), target.cache.write()) {
            for (k, (v, inst)) in src.iter() {
                dst.put(k.clone(), (*v, *inst));
            }
        }
    }
}

/// Probes a list of socket addresses concurrently, returning the first one that connects.
pub async fn find_fastest_addr(addrs: &[SocketAddr], timeout: Duration) -> Option<SocketAddr> {
    if addrs.is_empty() {
        return None;
    }
    if addrs.len() == 1 {
        return Some(addrs[0]);
    }

    let mut set = tokio::task::JoinSet::new();
    for &addr in addrs {
        set.spawn(async move {
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => Some(addr),
                _ => None,
            }
        });
    }

    while let Some(res) = set.join_next().await {
        if let Ok(Some(winner)) = res {
            set.abort_all();
            return Some(winner);
        }
    }
    None
}

/// Probes a list of IP candidates concurrently on the configured port, returning the fastest IP.
pub async fn find_fastest_ip(ips: &[IpAddr], port: u16, timeout: Duration) -> Option<IpAddr> {
    let non_reserved: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|&ip| !is_reserved_ip(ip))
        .collect();
    if non_reserved.is_empty() {
        return None;
    }
    if non_reserved.len() == 1 {
        return Some(non_reserved[0]);
    }

    let addrs: Vec<SocketAddr> = non_reserved
        .iter()
        .map(|&ip| SocketAddr::new(ip, port))
        .collect();
    find_fastest_addr(&addrs, timeout)
        .await
        .map(|addr| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_reserved_ips() {
        assert!(is_reserved_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_reserved_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_reserved_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_reserved_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_reserved_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5)))); // FakeIP
        assert!(is_reserved_ip(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255)))); // FakeIP
        assert!(is_reserved_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        assert!(!is_reserved_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_reserved_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_reserved_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
    }

    #[test]
    fn test_fastest_ip_cache() {
        let cache = FastestIpCache::new(10, Duration::from_secs(60));
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.1".parse().unwrap();
        let now = Instant::now();

        assert_eq!(cache.get("example.com", &[ip1, ip2], now), None);
        cache.put("example.com".to_string(), ip2, now);

        assert_eq!(cache.get("example.com", &[ip1, ip2], now), Some(ip2));
        // If candidate list no longer contains ip2, it should return None
        assert_eq!(cache.get("example.com", &[ip1], now), None);

        // Expired after TTL
        let later = now + Duration::from_secs(61);
        assert_eq!(cache.get("example.com", &[ip1, ip2], later), None);
    }

    #[tokio::test]
    async fn test_find_fastest_addr() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listening_addr = listener.local_addr().unwrap();

        // An address that is unlikely to be listening
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let addrs = vec![dead_addr, listening_addr];
        let winner = find_fastest_addr(&addrs, Duration::from_millis(500)).await;
        assert_eq!(winner, Some(listening_addr));
    }
}
