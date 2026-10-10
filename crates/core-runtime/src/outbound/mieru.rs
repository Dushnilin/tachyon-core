//! mieru outbound (TCP): see `crate::mieru` for the wire format.
//!
//! Config follows the `mbox` fork's shape: `server`, `server_port` or
//! `server_ports`, `transport`, `username`, `password`. `multiplexing` and
//! `traffic_pattern` are accepted for compatibility; every proxied connection
//! gets its own TCP connection and session, which any mieru server takes.

use std::io;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::{AnyStream, Target};
use crate::mieru::{MieruStream, socks5_request};
use crate::outbound::proxy::server_endpoint;

pub struct Mieru {
    server: String,
    ports: Vec<u16>,
    username: String,
    password: String,
    pub dial: crate::outbound::dial::DialOptions,
}

/// `"2090-2099"`, `"2090:2099"` or a bare `"2090"`.
fn parse_port_spec(spec: &str) -> Option<std::ops::RangeInclusive<u16>> {
    let spec = spec.trim();
    let (lo, hi) = match spec.split_once(['-', ':']) {
        Some((lo, hi)) => (lo.trim().parse().ok()?, hi.trim().parse().ok()?),
        None => {
            let p = spec.parse().ok()?;
            (p, p)
        }
    };
    (lo != 0 && lo <= hi).then_some(lo..=hi)
}

impl Mieru {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let transport = obj
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or("TCP");
        if !transport.eq_ignore_ascii_case("tcp") {
            anyhow::bail!("{at}: mieru: transport {transport:?} is not supported, only TCP");
        }
        let username = obj
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if username.is_empty() {
            anyhow::bail!("{at}: mieru: missing username");
        }
        if password.is_empty() {
            anyhow::bail!("{at}: mieru: missing password");
        }

        let (server, ports) = match obj.get("server_ports").filter(|v| !v.is_null()) {
            Some(list) => {
                let server = obj
                    .get("server")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("{at}: missing server"))?
                    .to_string();
                let items: Vec<String> = match list {
                    Value::Array(a) => a
                        .iter()
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect(),
                    Value::String(s) => vec![s.clone()],
                    other => vec![other.to_string()],
                };
                let mut ports = Vec::new();
                for item in &items {
                    let range = parse_port_spec(item).ok_or_else(|| {
                        anyhow::anyhow!("{at}: mieru: invalid server_ports entry {item:?}")
                    })?;
                    ports.extend(range);
                }
                if ports.is_empty() {
                    anyhow::bail!("{at}: mieru: server_ports is empty");
                }
                (server, ports)
            }
            None => {
                let (server, port) = server_endpoint(obj, at)?;
                (server, vec![port])
            }
        };

        Ok(Self {
            server,
            ports,
            username,
            password,
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    fn pick_port(&self) -> u16 {
        if self.ports.len() == 1 {
            return self.ports[0];
        }
        let mut b = [0u8; 4];
        let _ = getrandom::fill(&mut b);
        self.ports[u32::from_be_bytes(b) as usize % self.ports.len()]
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let tcp =
            crate::outbound::dial::connect_tcp(&self.server, self.pick_port(), &self.dial).await?;
        let _ = tcp.set_nodelay(true);
        let mut stream = MieruStream::client(tcp, &self.username, &self.password);

        let request = match target {
            Target::Ip(addr) => socks5_request("", Some(addr.ip()), addr.port())?,
            Target::Domain(host, port) => socks5_request(host, None, *port)?,
        };
        stream.write_all(&request).await?;
        stream.flush().await?;

        let reply =
            tokio::time::timeout(std::time::Duration::from_secs(15), read_reply(&mut stream))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "mieru: no reply from the server")
                })??;
        if reply != 0 {
            return Err(io::Error::new(
                reply_kind(reply),
                format!("mieru: server refused the connection (socks5 reply {reply})"),
            ));
        }
        Ok(Box::new(stream))
    }

    pub async fn connect_udp(&self, _target: &Target) -> io::Result<tokio::net::UdpSocket> {
        Err(io::Error::other("mieru: udp is not supported"))
    }
}

/// Read `05 REP 00 ATYP ADDR PORT`; return REP.
async fn read_reply<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<u8> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mieru: reply is not socks5",
        ));
    }
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut n = [0u8; 1];
            r.read_exact(&mut n).await?;
            n[0] as usize + 2
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mieru: reply has an unknown address type",
            ));
        }
    };
    let mut skip = vec![0u8; rest];
    r.read_exact(&mut skip).await?;
    Ok(head[1])
}

fn reply_kind(code: u8) -> io::ErrorKind {
    match code {
        0x02 => io::ErrorKind::PermissionDenied,
        0x05 => io::ErrorKind::ConnectionRefused,
        _ => io::ErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs() {
        assert_eq!(parse_port_spec("2090").unwrap(), 2090..=2090);
        assert_eq!(parse_port_spec("2090-2099").unwrap(), 2090..=2099);
        assert_eq!(parse_port_spec("2090:2099").unwrap(), 2090..=2099);
        assert!(parse_port_spec("0").is_none());
        assert!(parse_port_spec("9-3").is_none());
        assert!(parse_port_spec("x").is_none());
    }

    #[test]
    fn build_checks_fields() {
        let ok = serde_json::json!({
            "type": "mieru", "server": "example.com", "server_port": 2999,
            "transport": "TCP", "username": "u", "password": "p"
        });
        assert!(Mieru::build(ok.as_object().unwrap(), "outbounds[0]").is_ok());
        let udp = serde_json::json!({
            "type": "mieru", "server": "example.com", "server_port": 2999,
            "transport": "UDP", "username": "u", "password": "p"
        });
        assert!(Mieru::build(udp.as_object().unwrap(), "outbounds[0]").is_err());
        let ranges = serde_json::json!({
            "type": "mieru", "server": "example.com",
            "server_ports": ["2090-2092", "3000"], "username": "u", "password": "p"
        });
        let m = Mieru::build(ranges.as_object().unwrap(), "outbounds[0]").unwrap();
        assert_eq!(m.ports, vec![2090, 2091, 2092, 3000]);
        let none = serde_json::json!({"type": "mieru", "server": "x", "server_port": 1});
        assert!(Mieru::build(none.as_object().unwrap(), "outbounds[0]").is_err());
    }
}
