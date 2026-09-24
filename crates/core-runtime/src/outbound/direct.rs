use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::inbound::Target;

/// direct outbound: dial the target from the local host, optionally with
/// `routing_mark` (SO_MARK, Linux only — reference `control.RoutingMark`)
/// and `bind_interface` / `route.default_interface` (SO_BINDTODEVICE).
#[derive(Default, Clone)]
pub struct Direct {
    pub routing_mark: Option<u32>,
    pub bind_interface: Option<String>,
}

impl Direct {
    pub fn build(obj: &serde_json::Map<String, serde_json::Value>) -> Self {
        let routing_mark = obj
            .get("routing_mark")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as u32);
        let bind_interface = obj
            .get("bind_interface")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Self {
            routing_mark,
            bind_interface,
        }
    }

    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        let addr = resolve(target).await?;
        dial_tcp(addr, self.routing_mark, self.bind_interface.as_deref()).await
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let addr = resolve(target).await?;
        dial_udp(addr, self.routing_mark, self.bind_interface.as_deref()).await
    }
}

async fn resolve(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            // route.default_domain_resolver / dns section override system lookup.
            if let Some(dns) = crate::dns::current() {
                let addrs = match crate::dns::default_domain_resolver() {
                    Some(tag) => dns.resolve_via(&tag, host).await?,
                    None => dns.resolve(host).await?,
                };
                let ip = addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| io::Error::other(format!("no address for {host}")))?;
                return Ok(SocketAddr::new(ip, *port));
            }
            let mut addrs = tokio::net::lookup_host((host.as_str(), *port)).await?;
            addrs
                .next()
                .ok_or_else(|| io::Error::other(format!("no address for {host}")))
        }
    }
}

async fn dial_tcp(
    addr: SocketAddr,
    mark: Option<u32>,
    bind_interface: Option<&str>,
) -> io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    {
        if mark.is_some() || bind_interface.is_some() {
            let bind = bind_interface.map(str::to_string);
            let std = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
                use socket2::{Domain, Protocol, Socket, Type};
                let domain = if addr.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                if let Some(mark) = mark {
                    socket.set_mark(mark)?;
                }
                if let Some(iface) = &bind {
                    socket.bind_device(Some(iface.as_bytes()))?;
                }
                socket.connect(&addr.into())?;
                socket.set_nonblocking(true)?;
                Ok(socket.into())
            })
            .await
            .map_err(io::Error::other)??;
            return TcpStream::from_std(std);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (mark, bind_interface);
    TcpStream::connect(addr).await
}

async fn dial_udp(
    addr: SocketAddr,
    mark: Option<u32>,
    bind_interface: Option<&str>,
) -> io::Result<tokio::net::UdpSocket> {
    #[cfg(target_os = "linux")]
    {
        if mark.is_some() || bind_interface.is_some() {
            let bind = bind_interface.map(str::to_string);
            let std = tokio::task::spawn_blocking(move || -> io::Result<std::net::UdpSocket> {
                use socket2::{Domain, Protocol, Socket, Type};
                let domain = if addr.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
                if let Some(mark) = mark {
                    socket.set_mark(mark)?;
                }
                if let Some(iface) = &bind {
                    socket.bind_device(Some(iface.as_bytes()))?;
                }
                socket.connect(&addr.into())?;
                socket.set_nonblocking(true)?;
                Ok(socket.into())
            })
            .await
            .map_err(io::Error::other)??;
            return tokio::net::UdpSocket::from_std(std);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (mark, bind_interface);
    let domain = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = tokio::net::UdpSocket::bind(domain).await?;
    sock.connect(addr).await?;
    Ok(sock)
}
