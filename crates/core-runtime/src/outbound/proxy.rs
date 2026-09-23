use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::inbound::Target;
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

fn encode_target(target: &Target) -> io::Result<Vec<u8>> {
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
            out.push(0x03);
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

/// socks outbound (SOCKS5 only; version 4/4a is rejected at build time).
pub struct Socks {
    server: String,
    port: u16,
    credentials: Option<(String, String)>,
}

impl Socks {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        if let Some(version) = obj.get("version").and_then(Value::as_str)
            && version != "5"
        {
            anyhow::bail!("{at}: socks version {version:?} not implemented yet");
        }
        let (server, port) = server_endpoint(obj, at)?;
        Ok(Self {
            server,
            port,
            credentials: credentials(obj),
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect((self.server.as_str(), self.port)).await?;
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
        Ok(stream)
    }
}

/// http outbound: CONNECT tunnel (TLS wrapping not implemented yet).
pub struct HttpOut {
    server: String,
    port: u16,
    credentials: Option<(String, String)>,
}

impl HttpOut {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        if let Some(tls) = obj.get("tls").and_then(Value::as_object)
            && tls.get("enabled").and_then(Value::as_bool) == Some(true)
        {
            anyhow::bail!("{at}: http outbound TLS not implemented yet");
        }
        let (server, port) = server_endpoint(obj, at)?;
        Ok(Self {
            server,
            port,
            credentials: credentials(obj),
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect((self.server.as_str(), self.port)).await?;
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

fn base64_std(input: &[u8]) -> String {
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

    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<TcpStream> {
        let index = self.current.load(Ordering::Relaxed);
        let Some(member) = self.resolved.get(index) else {
            return Err(io::Error::other("selector has no members"));
        };
        router.connect_index(*member, target).await
    }
}
