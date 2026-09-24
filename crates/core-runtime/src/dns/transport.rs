//! DNS server transports: udp / tcp / tls (DoT) / https (DoH) / fakeip —
//! one exchange per query (no connection pooling yet).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::outbound::transport::h2io::{H2Io, H2Stream};
use crate::outbound::urltest::parse_duration;
use crate::tls_client::TlsOptions;

const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Tcp,
    Tls,
    Https,
    Fakeip,
}

pub struct ServerConfig {
    pub tag: String,
    pub kind: Kind,
    pub server: String,
    pub port: u16,
    pub tls: Option<TlsOptions>,
    pub path: String,
    pub domain_resolver: Option<String>,
    pub timeout: Duration,
    pub inet4: Option<IpPrefix>,
    pub inet6: Option<IpPrefix>,
    pub store: Option<Arc<FakeIpStore>>,
}

/// Minimal CIDR prefix (host bits masked off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

impl IpPrefix {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let (addr, bits) = raw
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("missing /prefix length"))?;
        let addr = IpAddr::from_str(addr)?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| anyhow::anyhow!("bad prefix length"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            anyhow::bail!("prefix length {bits} exceeds {max}");
        }
        Ok(Self { addr, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_v4(u32::from(net), self.bits) == mask_v4(u32::from(ip), self.bits)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_v6(u128::from(net), self.bits) == mask_v6(u128::from(ip), self.bits)
            }
            _ => false,
        }
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }
}

fn mask_v4(addr: u32, bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        addr & u32::MAX << (32 - bits)
    }
}

fn mask_v6(addr: u128, bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        addr & u128::MAX << (128 - bits)
    }
}

fn host_mask_v4(bits: u8) -> u32 {
    if bits == 0 {
        u32::MAX
    } else {
        !(u32::MAX << (32 - bits))
    }
}

fn host_mask_v6(bits: u8) -> u128 {
    if bits == 0 {
        u128::MAX
    } else {
        !(u128::MAX << (128 - bits))
    }
}

fn broadcast_v4(net: Ipv4Addr, bits: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(net) | host_mask_v4(bits))
}

fn broadcast_v6(net: Ipv6Addr, bits: u8) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(net) | host_mask_v6(bits))
}

/// In-memory fakeip address pool, mirroring sing-box's store: domain-address
/// maps both ways, sequential allocation starting at network+2 with wrap.
pub struct FakeIpStore {
    v4: Option<IpPrefix>,
    v6: Option<IpPrefix>,
    state: Mutex<FakeIpState>,
}

struct FakeIpState {
    cur4: Option<Ipv4Addr>,
    cur6: Option<Ipv6Addr>,
    addr_to_domain: std::collections::HashMap<IpAddr, String>,
    domain_to_v4: std::collections::HashMap<String, Ipv4Addr>,
    domain_to_v6: std::collections::HashMap<String, Ipv6Addr>,
}

impl FakeIpStore {
    pub fn new(v4: Option<IpPrefix>, v6: Option<IpPrefix>) -> Self {
        let cur4 = v4.and_then(|p| {
            if p.is_v4() {
                let IpAddr::V4(net) = p.addr else {
                    unreachable!()
                };
                Some(Ipv4Addr::from(u32::from(net) + 1))
            } else {
                None
            }
        });
        let cur6 = v6.and_then(|p| {
            if !p.is_v4() {
                let IpAddr::V6(net) = p.addr else {
                    unreachable!()
                };
                Some(Ipv6Addr::from(u128::from(net) + 1))
            } else {
                None
            }
        });
        Self {
            v4: v4.filter(IpPrefix::is_v4),
            v6: v6.filter(|p| !p.is_v4()),
            state: Mutex::new(FakeIpState {
                cur4,
                cur6,
                addr_to_domain: std::collections::HashMap::new(),
                domain_to_v4: std::collections::HashMap::new(),
                domain_to_v6: std::collections::HashMap::new(),
            }),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.v4.is_some_and(|p| p.contains(ip)) || self.v6.is_some_and(|p| p.contains(ip))
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        self.state
            .lock()
            .expect("fakeip state")
            .addr_to_domain
            .get(&ip)
            .cloned()
    }

    pub fn lookup_address(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let state = self.state.lock().expect("fakeip state");
        if v6 {
            state.domain_to_v6.get(domain).map(|a| IpAddr::V6(*a))
        } else {
            state.domain_to_v4.get(domain).map(|a| IpAddr::V4(*a))
        }
    }

    pub fn create(&self, domain: &str, v6: bool) -> io::Result<IpAddr> {
        let mut state = self.state.lock().expect("fakeip state");
        if v6 {
            if let Some(existing) = state.domain_to_v6.get(domain) {
                return Ok(IpAddr::V6(*existing));
            }
            let prefix = self
                .v6
                .ok_or_else(|| io::Error::other("fakeip: inet6_range not configured"))?;
            let cur = state
                .cur6
                .ok_or_else(|| io::Error::other("fakeip: no inet6 range"))?;
            let next = next_v6(cur, prefix);
            state.cur6 = Some(next);
            state.domain_to_v6.insert(domain.to_string(), next);
            state
                .addr_to_domain
                .insert(IpAddr::V6(next), domain.to_string());
            Ok(IpAddr::V6(next))
        } else {
            if let Some(existing) = state.domain_to_v4.get(domain) {
                return Ok(IpAddr::V4(*existing));
            }
            let prefix = self
                .v4
                .ok_or_else(|| io::Error::other("fakeip: inet4_range not configured"))?;
            let cur = state
                .cur4
                .ok_or_else(|| io::Error::other("fakeip: no inet4 range"))?;
            let next = next_v4(cur, prefix);
            state.cur4 = Some(next);
            state.domain_to_v4.insert(domain.to_string(), next);
            state
                .addr_to_domain
                .insert(IpAddr::V4(next), domain.to_string());
            Ok(IpAddr::V4(next))
        }
    }
}

fn next_v4(cur: Ipv4Addr, prefix: IpPrefix) -> Ipv4Addr {
    let IpAddr::V4(net) = prefix.addr else {
        return cur;
    };
    let last = broadcast_v4(net, prefix.bits);
    let next = Ipv4Addr::from(u32::from(cur).wrapping_add(1));
    if next == last || !prefix.contains(IpAddr::V4(next)) {
        Ipv4Addr::from(u32::from(net) + 2)
    } else {
        next
    }
}

fn next_v6(cur: Ipv6Addr, prefix: IpPrefix) -> Ipv6Addr {
    let IpAddr::V6(net) = prefix.addr else {
        return cur;
    };
    let last = broadcast_v6(net, prefix.bits);
    let next = Ipv6Addr::from(u128::from(cur).wrapping_add(1));
    if next == last || !prefix.contains(IpAddr::V6(next)) {
        Ipv6Addr::from(u128::from(net) + 2)
    } else {
        next
    }
}

impl ServerConfig {
    pub fn build(obj: &Value, at: &str) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let kind_raw = map
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing type"))?;
        let kind = match kind_raw {
            "udp" => Kind::Udp,
            "tcp" => Kind::Tcp,
            "tls" => Kind::Tls,
            "https" => Kind::Https,
            "fakeip" => Kind::Fakeip,
            other => anyhow::bail!("{at}: dns server type {other:?} not implemented yet"),
        };
        let tag = map
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let server = map
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let port = map
            .get("server_port")
            .and_then(Value::as_u64)
            .map(|p| p as u16)
            .unwrap_or(match kind {
                Kind::Udp | Kind::Tcp | Kind::Tls => 53,
                Kind::Https => 443,
                Kind::Fakeip => 0,
            });
        // dns tls/https servers implicitly use TLS: `enabled` defaults to true
        // for these types when the key is absent (as in sing-box configs).
        let owned;
        let map_ref: &serde_json::Map<String, Value> = if matches!(kind, Kind::Tls | Kind::Https)
            && map
                .get("tls")
                .and_then(Value::as_object)
                .is_some_and(|t| !t.contains_key("enabled"))
        {
            let mut m = map.clone();
            if let Some(Value::Object(t)) = m.get_mut("tls") {
                t.insert("enabled".to_string(), Value::Bool(true));
            }
            owned = m;
            &owned
        } else {
            map
        };
        let tls = TlsOptions::from_outbound(map_ref, &server, at)?;
        let path = map
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("/dns-query")
            .to_string();
        let domain_resolver = map
            .get("domain_resolver")
            .and_then(Value::as_str)
            .map(str::to_string);
        let timeout = parse_duration(
            map.get("timeout"),
            DEFAULT_DNS_TIMEOUT,
            &format!("{at}: timeout"),
        )?;

        let (inet4, inet6) = if kind == Kind::Fakeip {
            let inet4 = match map.get("inet4_range") {
                None | Some(Value::Null) => None,
                Some(v) => Some(IpPrefix::parse(v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("{at}: inet4_range must be a string")
                })?)?),
            };
            let inet6 = match map.get("inet6_range") {
                None | Some(Value::Null) => None,
                Some(v) => Some(IpPrefix::parse(v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("{at}: inet6_range must be a string")
                })?)?),
            };
            if inet4.is_none() && inet6.is_none() {
                anyhow::bail!("{at}: at least one of inet4_range or inet6_range must be set");
            }
            (inet4, inet6)
        } else {
            (None, None)
        };
        if kind != Kind::Fakeip && server.is_empty() {
            anyhow::bail!("{at}: missing server");
        }
        if map.get("detour").is_some_and(|d| !d.is_null()) {
            anyhow::bail!("{at}: dns server detour is not implemented yet");
        }

        let store = if kind == Kind::Fakeip {
            Some(Arc::new(FakeIpStore::new(inet4, inet6)))
        } else {
            None
        };

        Ok(Self {
            tag,
            kind,
            server,
            port,
            tls,
            path,
            domain_resolver,
            timeout,
            inet4,
            inet6,
            store,
        })
    }

    pub fn is_fakeip(&self) -> bool {
        self.kind == Kind::Fakeip
    }
}

/// Run one query against a resolved server address.
pub async fn exchange(cfg: &ServerConfig, addr: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let fut = async {
        match cfg.kind {
            Kind::Udp => exchange_udp(addr, query).await,
            Kind::Tcp => {
                let stream = TcpStream::connect(addr).await?;
                exchange_stream(stream, query).await
            }
            Kind::Tls => {
                let tcp = TcpStream::connect(addr).await?;
                let tls = cfg
                    .tls
                    .as_ref()
                    .ok_or_else(|| io::Error::other("dns: tls server without tls options"))?;
                let stream = tls.wrap(tcp).await?;
                exchange_stream(stream, query).await
            }
            Kind::Https => exchange_doh(cfg, addr, query).await,
            Kind::Fakeip => Err(io::Error::other(
                "dns: fakeip transport must not reach the wire",
            )),
        }
    };
    tokio::time::timeout(cfg.timeout, fut)
        .await
        .map_err(|_| io::Error::other(format!("dns: timeout after {:?}", cfg.timeout)))?
}

async fn exchange_udp(addr: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.send_to(query, addr).await?;
    let mut buf = vec![0u8; 65535];
    let (n, _from) = socket.recv_from(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn exchange_stream(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    if query.len() > u16::MAX as usize {
        return Err(io::Error::other("dns: query too large for tcp framing"));
    }
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn exchange_doh(cfg: &ServerConfig, addr: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr).await?;
    let tls = cfg
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::other("dns: https server without tls options"))?;
    let tls = tls
        .connect_with_defaults(tcp, &[b"h2"])
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH tls: {e}")))?;

    match tls.get_ref().1.alpn_protocol() {
        Some(b"h2") => exchange_doh_h2(cfg, tls, query).await,
        _ => exchange_doh_h1(cfg, tls, query).await,
    }
}

async fn exchange_doh_h2(
    cfg: &ServerConfig,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let authority = doh_authority(cfg);
    let (send_request, connection) = h2::client::handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH h2 handshake: {e}")))?;
    let conn_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("dns: DoH h2 ready: {e}")))?;

    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}{}", cfg.path))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(())
        .map_err(|e| io::Error::other(format!("dns: DoH request: {e}")))?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("dns: DoH send: {e}")))?;

    let mut io = H2Io {
        h2: H2Stream::new(response, send, conn_task),
    };
    io.write_all(query).await?;
    io.shutdown().await?;
    let mut body = Vec::new();
    io.read_to_end(&mut body).await?;
    if body.is_empty() {
        return Err(io::Error::other("dns: empty DoH response"));
    }
    Ok(body)
}

async fn exchange_doh_h1(
    cfg: &ServerConfig,
    mut stream: tokio_rustls::client::TlsStream<TcpStream>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let authority = doh_authority(cfg);
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        cfg.path,
        query.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(query);
    stream.write_all(&request).await?;

    // Read head, then exactly Content-Length body bytes.
    let mut raw = Vec::with_capacity(1024 + query.len());
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::other("dns: DoH connection closed before head"));
        }
        raw.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_head_end(&raw) {
            break pos;
        }
    };
    let head_text = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let status_line = head_text.split("\r\n").next().unwrap_or("");
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(io::Error::other(format!(
            "dns: DoH unexpected status: {status_line}"
        )));
    }
    let mut content_length = None;
    for line in head_text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
            {
                return Err(io::Error::other(
                    "dns: DoH chunked responses not implemented (h1 fallback)",
                ));
            }
        }
    }
    let len = content_length
        .ok_or_else(|| io::Error::other("dns: DoH response without Content-Length"))?;
    let mut body = raw.split_off(head_end);
    while body.len() < len {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::other("dns: DoH truncated body"));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Ok(body)
}

fn doh_authority(cfg: &ServerConfig) -> String {
    if let Some(tls) = &cfg.tls {
        return tls.server_name().to_string();
    }
    match cfg.port {
        443 => cfg.server.clone(),
        port => format!("{}:{port}", cfg.server),
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

pub fn is_ip_literal(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parse_and_contains() {
        let p = IpPrefix::parse("198.18.0.0/15").unwrap();
        assert!(p.contains("198.18.0.1".parse().unwrap()));
        assert!(p.contains("198.19.255.255".parse().unwrap()));
        assert!(!p.contains("198.20.0.1".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));
    }

    #[test]
    fn fakeip_allocates_sequentially_and_stably() {
        let store = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
        let a = store.create("b.example", false).unwrap();
        let b = store.create("c.example", false).unwrap();
        assert_eq!(a.to_string(), "198.18.0.2");
        assert_eq!(b.to_string(), "198.18.0.3");
        assert_eq!(store.create("b.example", false).unwrap(), a);
        assert_eq!(store.lookup_domain(a).as_deref(), Some("b.example"));
        assert_eq!(store.lookup_address("c.example", false), Some(b));
        assert!(store.contains(a));
        assert!(!store.contains("198.17.0.1".parse().unwrap()));
    }

    #[test]
    fn fakeip_wrap_around() {
        let store = FakeIpStore::new(Some(IpPrefix::parse("10.0.0.0/30").unwrap()), None);
        // /30: usable base+2 .. broadcast-1 → only 10.0.0.2
        let a = store.create("one", false).unwrap();
        assert_eq!(a.to_string(), "10.0.0.2");
        // next allocation wraps back to base+2 but domain map keeps stability
        let b = store.create("two", false).unwrap();
        assert_eq!(b.to_string(), "10.0.0.2");
    }
}
