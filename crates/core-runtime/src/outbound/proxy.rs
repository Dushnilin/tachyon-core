use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::inbound::{AnyStream, Conn, Target};
use crate::route::Router;

pub(crate) fn server_endpoint(
    obj: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<(String, u16)> {
    let server = obj
        .get("server")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{at}: missing server"))?
        .to_string();
    let port = obj
        .get("server_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .ok_or_else(|| anyhow::anyhow!("{at}: missing server_port"))?;
    Ok((server, port))
}

fn credentials(obj: &serde_json::Map<String, Value>) -> Option<(String, String)> {
    let username = obj.get("username").and_then(Value::as_str)?;
    let password = obj.get("password").and_then(Value::as_str)?;
    Some((username.to_string(), password.to_string()))
}

/// SOCKS-shaped address block: ATYP, address, then the port. SOCKS, anytls
/// and shadowsocks number a domain 3 and an IPv6 address 4; trojan numbers a
/// domain 2 and keeps 4 for IPv6, which is the only difference between them.
pub(crate) fn encode_target_with(target: &Target, domain_atyp: u8) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match target {
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        },
        Target::Domain(host, _) => {
            out.push(domain_atyp);
            let raw = host.as_bytes();
            if raw.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
}

/// The SOCKS numbering: a domain is 3.
pub(crate) fn encode_target(target: &Target) -> io::Result<Vec<u8>> {
    encode_target_with(target, 0x03)
}

/// socks outbound; `version` is 4 or 5 (5 by default), as in the reference.
pub struct Socks {
    server: String,
    port: u16,
    version: u8,
    credentials: Option<(String, String)>,
    pub dial: crate::outbound::dial::DialOptions,
}

impl Socks {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let version = match obj.get("version").and_then(Value::as_str) {
            None | Some("") => 5,
            Some("4") => 4,
            Some("5") => 5,
            Some(other) => anyhow::bail!("{at}: unknown socks version {other:?}"),
        };
        let (server, port) = server_endpoint(obj, at)?;
        Ok(Self {
            server,
            port,
            version,
            credentials: credentials(obj),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let stream =
            crate::outbound::dial::connect_tcp(self.server.as_str(), self.port, &self.dial).await?;
        if self.version == 4 {
            let mut stream = stream;
            self.connect_v4(&mut stream, target).await?;
            return Ok(Box::new(stream));
        }
        let mut stream = stream;
        self.connect_v5(&mut stream, target).await?;
        Ok(Box::new(stream))
    }

    /// SOCKS4/4a: the reference resolves the destination locally
    /// (`resolve: version == Version4`) and sends the IPv4 form; the 4a
    /// extension (a domain behind a 0.0.0.x address) is used when a name has
    /// no usable address.
    async fn connect_v4(&self, stream: &mut TcpStream, target: &Target) -> io::Result<()> {
        let request = match target {
            Target::Ip(addr) => socks4_request(target, Some(socks4_addr(addr.ip())?), None),
            Target::Domain(host, _) => socks4_request(target, resolve_ipv4(host).await, Some(host)),
        }?;
        stream.write_all(&request).await?;
        let mut reply = [0u8; 8];
        stream.read_exact(&mut reply).await?;
        if reply[1] != 0x5a {
            return Err(io::Error::other(format!(
                "socks4 connect failed: {}",
                reply[1]
            )));
        }
        Ok(())
    }

    async fn connect_v5(&self, stream: &mut TcpStream, target: &Target) -> io::Result<()> {
        self.handshake_v5(stream).await?;
        let mut request = vec![0x05, 0x01, 0x00];
        request.extend_from_slice(&encode_target(target)?);
        stream.write_all(&request).await?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[1] != 0x00 {
            return Err(io::Error::other(format!(
                "socks connect failed: {}",
                head[1]
            )));
        }
        let skip = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                usize::from(len[0])
            }
            _ => return Err(io::Error::other("bad address type from server")),
        };
        let mut bnd = vec![0u8; skip + 2];
        stream.read_exact(&mut bnd).await?;
        Ok(())
    }

    /// Method negotiation and, when the server asks for it, username/password
    /// auth. Shared by CONNECT and UDP ASSOCIATE.
    async fn handshake_v5(&self, stream: &mut TcpStream) -> io::Result<()> {
        let methods: &[u8] = if self.credentials.is_some() {
            &[0x02]
        } else {
            &[0x00]
        };
        stream.write_all(&[0x05, methods.len() as u8]).await?;
        stream.write_all(methods).await?;
        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await?;
        if auth[0] != 0x05 {
            return Err(io::Error::other("bad socks version from server"));
        }
        match auth[1] {
            0x00 => {}
            0x02 => {
                let Some((username, password)) = &self.credentials else {
                    return Err(io::Error::other("server requires auth"));
                };
                if username.len() > 255 || password.len() > 255 {
                    return Err(io::Error::other("credentials too long"));
                }
                let mut sub = vec![0x01, username.len() as u8];
                sub.extend_from_slice(username.as_bytes());
                sub.push(password.len() as u8);
                sub.extend_from_slice(password.as_bytes());
                stream.write_all(&sub).await?;
                let mut verdict = [0u8; 2];
                stream.read_exact(&mut verdict).await?;
                if verdict[1] != 0x00 {
                    return Err(io::Error::other("socks auth rejected"));
                }
            }
            _ => return Err(io::Error::other("no acceptable auth method")),
        }

        Ok(())
    }

    /// SOCKS5 UDP ASSOCIATE: the control connection names a relay endpoint and
    /// every datagram then carries its own `[RSV RSV FRAG][addr][port]` header.
    /// SOCKS4 has no datagram support at all.
    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        if self.version == 4 {
            return Err(io::Error::other("socks4 has no udp support"));
        }
        let mut control =
            crate::outbound::dial::connect_tcp(self.server.as_str(), self.port, &self.dial).await?;
        self.handshake_v5(&mut control).await?;
        // 0.0.0.0:0 asks the server for its default relay
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let bound = read_socks5_reply(&mut control).await?;
        let relay = match bound {
            // the server left the address empty; the port is the useful part
            Target::Ip(addr) if addr.ip().is_unspecified() => {
                format!("127.0.0.1:{}", addr.port())
            }
            other => other.to_string(),
        };
        let relay: std::net::SocketAddr = relay
            .parse()
            .map_err(|_| io::Error::other("socks: unusable udp relay address"))?;

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(relay).await?;
        // the control connection has to stay open for the whole session
        tokio::spawn(async move {
            let mut control = control;
            let mut sink = [0u8; 1];
            while let Ok(n) = control.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });

        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let out_socket = std::sync::Arc::new(peer);
        let in_socket = std::sync::Arc::clone(&out_socket);
        let target = target.clone();
        let socket = std::sync::Arc::new(socket);
        let out_relay = std::sync::Arc::clone(&socket);
        let in_relay = std::sync::Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let mut datagram = Vec::with_capacity(64_000);
            loop {
                let Ok(n) = in_socket.recv(&mut buf).await else {
                    break;
                };
                datagram.clear();
                datagram.extend_from_slice(&[0, 0, 0]);
                if crate::outbound::packet::put_addr_port(&mut datagram, &target).is_err() {
                    break;
                }
                datagram.extend_from_slice(&buf[..n]);
                if out_relay.send(&datagram).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok(n) = in_relay.recv(&mut buf).await else {
                    break;
                };
                if n < 4 || buf[2] != 0 {
                    // a fragment the relay did not reassemble
                    continue;
                }
                let Ok((_target, payload)) = crate::outbound::packet::take_addr_port(&buf[3..n])
                else {
                    continue;
                };
                if out_socket.send(payload).await.is_err() {
                    break;
                }
            }
        });
        Ok(local)
    }
}

/// The SOCKS4 address field: a plain IPv4 address, or the 0.0.0.1 marker with
/// the hostname appended when the name could not be resolved.
fn socks4_request(
    target: &Target,
    address: Option<std::net::Ipv4Addr>,
    hostname: Option<&str>,
) -> io::Result<Vec<u8>> {
    let mut request = vec![0x04, 0x01];
    request.extend_from_slice(&target.port().to_be_bytes());
    match address {
        Some(address) => request.extend_from_slice(&address.octets()),
        None => {
            let hostname = hostname.unwrap_or_default();
            if hostname.is_empty() {
                return Err(io::Error::other("socks4 needs an address or a name"));
            }
            if hostname.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            request.extend_from_slice(&[0, 0, 0, 1]);
            request.extend_from_slice(hostname.as_bytes());
        }
    }
    request.push(0x00);
    Ok(request)
}

fn socks4_addr(ip: std::net::IpAddr) -> io::Result<std::net::Ipv4Addr> {
    match ip {
        std::net::IpAddr::V4(v4) => Ok(v4),
        // a mapped address keeps the SOCKS4 encoding possible
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .ok_or_else(|| io::Error::other("socks4 cannot reach an IPv6 destination")),
    }
}

/// A/AAAA lookup for the SOCKS4 destination; `None` when only a name is known.
async fn resolve_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    let service = crate::dns::current()?;
    let addresses = service.resolve(host).await.ok()?;
    addresses.into_iter().find_map(|address| match address {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    })
}

/// http outbound: CONNECT tunnel, optionally wrapped in TLS.
pub struct HttpOut {
    server: String,
    port: u16,
    credentials: Option<(String, String)>,
    tls: Option<Arc<crate::tls_client::TlsOptions>>,
    pub dial: crate::outbound::dial::DialOptions,
}

impl HttpOut {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let tls = crate::tls_client::TlsOptions::from_outbound(obj, &server, at)?;
        Ok(Self {
            server,
            port,
            credentials: credentials(obj),
            tls: tls.map(Arc::new),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let tcp =
            crate::outbound::dial::connect_tcp(self.server.as_str(), self.port, &self.dial).await?;
        let mut stream: AnyStream = match &self.tls {
            Some(tls) => Box::new(tls.connect_stream(tcp, &[]).await?),
            None => Box::new(tcp),
        };
        let authority = match target {
            Target::Ip(addr) => addr.to_string(),
            Target::Domain(host, port) => format!("{host}:{port}"),
        };
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some((username, password)) = &self.credentials {
            use std::fmt::Write as _;
            let raw = format!("{username}:{password}");
            let encoded = base64_std(raw.as_bytes());
            let _ = write!(request, "Proxy-Authorization: Basic {encoded}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await?;
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            if response.len() > 16 * 1024 {
                return Err(io::Error::other("http proxy response too large"));
            }
        }
        let head = String::from_utf8_lossy(&response);
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default();
        if !status.starts_with('2') {
            return Err(io::Error::other(format!("http proxy refused: {status}")));
        }
        Ok(stream)
    }
}

pub(crate) fn base64_std(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// selector: first member by default (runtime switching arrives with clash_api).
pub struct Selector {
    raw_members: Vec<String>,
    default: Option<String>,
    resolved: Vec<usize>,
    current: AtomicUsize,
}

impl Selector {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let raw_members = obj
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing tags"))?
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: selector members must be strings"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if raw_members.is_empty() {
            anyhow::bail!("{at}: missing tags");
        }
        let default = obj
            .get("default")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(Self {
            raw_members,
            default,
            resolved: Vec::new(),
            current: AtomicUsize::new(0),
        })
    }

    /// Resolve member tags against the built outbound table (once, at startup).
    pub fn resolve(
        &mut self,
        tags: &std::collections::HashMap<String, usize>,
    ) -> anyhow::Result<()> {
        let mut resolved = Vec::with_capacity(self.raw_members.len());
        for tag in &self.raw_members {
            let index = tags.get(tag).copied().ok_or_else(|| {
                anyhow::anyhow!("selector member references unknown outbound {tag:?}")
            })?;
            resolved.push(index);
        }
        let current = match &self.default {
            Some(tag) => self
                .raw_members
                .iter()
                .position(|m| m == tag)
                .ok_or_else(|| anyhow::anyhow!("selector default {tag:?} is not a member"))?,
            None => 0,
        };
        self.resolved = resolved;
        self.current.store(current, Ordering::Relaxed);
        Ok(())
    }

    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        let index = self.current.load(Ordering::Relaxed);
        let Some(member) = self.resolved.get(index) else {
            return Err(io::Error::other("selector has no members"));
        };
        router.connect_index(*member, target).await
    }

    /// Switch to `member` by tag (clash `PUT /proxies/{name}`).
    pub fn select(&self, member: &str) -> bool {
        if let Some(pos) = self.raw_members.iter().position(|m| m == member) {
            self.current.store(pos, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Member tags and the current selection (clash group view).
    pub fn all(&self) -> &[String] {
        &self.raw_members
    }

    pub fn now(&self) -> &str {
        self.raw_members
            .get(self.current.load(Ordering::Relaxed))
            .map(String::as_str)
            .unwrap_or_default()
    }

    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        let index = self.current.load(Ordering::Relaxed);
        let Some(member) = self.resolved.get(index) else {
            return Err(io::Error::other("selector has no members"));
        };
        router.connect_udp_index(*member, target).await
    }
}

/// Reads a SOCKS5 reply head and returns the bound address.
async fn read_socks5_reply(stream: &mut TcpStream) -> io::Result<Target> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::other("bad socks version from server"));
    }
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "socks request failed: {}",
            head[1]
        )));
    }
    let mut body = Vec::new();
    match head[3] {
        0x01 => body.push(0x01),
        0x04 => body.push(0x03),
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            body.push(0x03);
            body.push(len[0]);
        }
        _ => return Err(io::Error::other("bad address type from server")),
    }
    let tail = match head[3] {
        0x01 => 6,
        0x04 => 18,
        _ => usize::from(body[1]) + 2,
    };
    let mut rest = vec![0u8; tail];
    stream.read_exact(&mut rest).await?;
    body.extend_from_slice(&rest);
    let (target, _) = crate::outbound::packet::take_addr_port(&body)?;
    Ok(target)
}

#[cfg(test)]
mod socks4_tests {
    use super::*;

    #[test]
    fn request_uses_the_resolved_address() {
        let target = Target::Ip("10.0.0.5:443".parse().expect("target"));
        let request =
            socks4_request(&target, Some("1.2.3.4".parse().expect("ip")), None).expect("request");
        assert_eq!(request, vec![0x04, 0x01, 0x01, 0xbb, 1, 2, 3, 4, 0x00]);
    }

    #[test]
    fn request_falls_back_to_4a() {
        let target = Target::Domain("host.test".into(), 80);
        let request = socks4_request(&target, None, Some("host.test")).expect("request");
        assert_eq!(&request[..8], &[0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1]);
        assert_eq!(&request[8..], b"host.test\x00");
        // no address and no name cannot be encoded
        let error = socks4_request(&target, None, None).unwrap_err();
        assert!(error.to_string().contains("address or a name"));
    }
}

#[cfg(test)]
mod udp_associate_tests {
    use super::*;
    use serde_json::json;

    /// A socks5 server that hands out one relay socket and echoes datagrams.
    async fn serve(listener: tokio::net::TcpListener) {
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("relay");
        let relay_port = relay.local_addr().expect("addr").port();
        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = relay.recv_from(&mut buf).await {
                assert_eq!(&buf[..3], &[0, 0, 0], "a datagram carries a header");
                let (target, payload) =
                    crate::outbound::packet::take_addr_port(&buf[3..n]).expect("address");
                let mut reply = vec![0, 0, 0];
                crate::outbound::packet::put_addr_port(&mut reply, &target).expect("address");
                reply.extend_from_slice(&payload.iter().rev().copied().collect::<Vec<u8>>());
                relay.send_to(&reply, from).await.expect("reply");
            }
        });

        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = [0u8; 2];
        socket.read_exact(&mut head).await.expect("greeting");
        let mut methods = vec![0u8; head[1] as usize];
        socket.read_exact(&mut methods).await.expect("methods");
        socket.write_all(&[0x05, 0x00]).await.expect("auth");
        let mut request = [0u8; 10];
        socket.read_exact(&mut request).await.expect("associate");
        assert_eq!(request[..3], [0x05, 0x03, 0x00], "udp associate");
        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        reply.extend_from_slice(&[127, 0, 0, 1]);
        reply.extend_from_slice(&relay_port.to_be_bytes());
        socket.write_all(&reply).await.expect("reply");
        // the client keeps the control connection open for the session
        let mut sink = [0u8; 1];
        while socket.read(&mut sink).await.unwrap_or(0) > 0 {}
        echo.abort();
    }

    #[tokio::test]
    async fn associate_relays_datagrams_through_the_named_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(serve(listener));

        let config = json!({
            "type": "socks",
            "tag": "s",
            "server": "127.0.0.1",
            "server_port": port,
            "version": "5",
        });
        let socks =
            Socks::build(config.as_object().expect("object"), "outbounds[0]").expect("build");
        let sock = socks
            .connect_udp(&Target::Domain("dns.example.com".into(), 53))
            .await
            .expect("associate");
        sock.send(b"ping").await.expect("send");

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .expect("in time")
            .expect("recv");
        assert_eq!(&buf[..n], b"gnip", "the relay echoes what it received");
        server.abort();
    }

    #[tokio::test]
    async fn socks4_has_no_datagrams() {
        let config = json!({
            "type": "socks",
            "tag": "s",
            "server": "127.0.0.1",
            "server_port": 1080,
            "version": "4",
        });
        let socks =
            Socks::build(config.as_object().expect("object"), "outbounds[0]").expect("build");
        let error = socks
            .connect_udp(&Target::Ip("1.2.3.4:53".parse().expect("addr")))
            .await
            .expect_err("socks4 has no udp")
            .to_string();
        assert!(error.contains("socks4"), "got {error}");
    }
}
