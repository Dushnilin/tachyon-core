use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;
use tokio::net::{TcpListener, UdpSocket};

use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, UdpHub};
use crate::inbound::{
    Target, drive_transparent, network_includes_tcp, network_includes_udp, parse_listen,
};
use crate::logging;
use crate::outbound::urltest::parse_duration;
use crate::route::Router;

/// Inbound destination override (reference `DirectInboundOptions`).
enum Override {
    None,
    /// override_address + override_port
    Full(Target),
    /// override_address only — keep the original port
    AddrOnly(Target),
    /// override_port only — keep the original address
    PortOnly(u16),
}

impl Clone for Override {
    fn clone(&self) -> Self {
        match self {
            Override::None => Override::None,
            Override::Full(t) => Override::Full(t.clone()),
            Override::AddrOnly(t) => Override::AddrOnly(t.clone()),
            Override::PortOnly(p) => Override::PortOnly(*p),
        }
    }
}

/// direct inbound: accept raw TCP, destination = local address (the address
/// the client connected to) with optional override_address / override_port.
/// UDP (when `network` includes it) uses the same override rules with
/// destination = listen address (reference `NewPacketConnectionEx`).
pub struct Direct {
    listener: Option<TcpListener>,
    udp: Option<Arc<UdpSocket>>,
    tag: String,
    router: Arc<Router>,
    r#override: Override,
    udp_timeout: std::time::Duration,
}

impl Direct {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("direct");
        let at = format!("inbound[{tag}]");
        let want_tcp = network_includes_tcp(obj);
        let want_udp = network_includes_udp(obj);
        if !want_tcp && !want_udp {
            anyhow::bail!("{at}: network excludes both tcp and udp");
        }
        let (ip, port) = parse_listen(obj, &at)?;

        // When listen_port is 0 both protocols have to share one port. Bind
        // UDP first: Windows allocates ephemeral ports from a range that can be
        // excluded for UDP, and a TCP-first pick then fails the UDP bind with
        // WSAEACCES. Retrying covers ports that are free for UDP but taken for
        // TCP.
        let (listener, udp) = match (want_tcp, want_udp, port) {
            (true, true, 0) => {
                let mut last_error: Option<io::Error> = None;
                let mut bound = None;
                for _ in 0..8 {
                    let udp_sock = match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
                        Ok(sock) => sock,
                        Err(e) => {
                            last_error = Some(e);
                            break;
                        }
                    };
                    let chosen = udp_sock.local_addr()?.port();
                    match super::bind_tcp(SocketAddr::new(ip, chosen)) {
                        Ok(tcp) => {
                            bound = Some((Some(tcp), Some(Arc::new(udp_sock))));
                            break;
                        }
                        Err(e) => last_error = Some(e),
                    }
                }
                match bound {
                    Some(pair) => pair,
                    None => {
                        return Err(last_error
                            .unwrap_or_else(|| {
                                io::Error::other("direct inbound: no shared tcp/udp port")
                            })
                            .into());
                    }
                }
            }
            _ => {
                let listener = if want_tcp {
                    Some(super::bind_tcp(SocketAddr::new(ip, port))?)
                } else {
                    None
                };
                let bound_port = match &listener {
                    Some(l) => l.local_addr()?.port(),
                    None => port,
                };
                let udp = if want_udp {
                    Some(Arc::new(super::bind_udp(SocketAddr::new(ip, bound_port))?))
                } else {
                    None
                };
                (listener, udp)
            }
        };
        let bound_port = match (&listener, &udp) {
            (Some(l), _) => l.local_addr()?.port(),
            (None, Some(s)) => s.local_addr()?.port(),
            (None, None) => port,
        };

        let addr_override = obj.get("override_address").and_then(Value::as_str);
        let port_override = obj
            .get("override_port")
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok());
        let r#override = match (addr_override, port_override) {
            (Some(addr), Some(port)) => Override::Full(parse_override_addr(addr, port, &at)?),
            (Some(addr), None) => Override::AddrOnly(parse_override_addr(addr, 0, &at)?),
            (None, Some(port)) => Override::PortOnly(port),
            (None, None) => Override::None,
        };
        let udp_timeout = parse_duration(
            obj.get("udp_timeout"),
            DEFAULT_UDP_TIMEOUT,
            &format!("{at}: udp_timeout"),
        )?;

        logging::info(format_args!(
            "inbound direct[{tag}] listening at {ip}:{bound_port} (tcp={}, udp={})",
            listener.is_some(),
            udp.is_some()
        ));
        Ok(Self {
            listener,
            udp,
            tag: tag.to_string(),
            router,
            r#override,
            udp_timeout,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        if let Some(l) = &self.listener {
            return l.local_addr();
        }
        self.udp
            .as_ref()
            .map(|u| u.local_addr())
            .unwrap_or_else(|| Err(io::Error::other("direct inbound: no listener")))
    }

    pub(crate) fn shutdown_socket(&self) -> Option<std::sync::Weak<UdpSocket>> {
        self.udp.as_ref().map(Arc::downgrade)
    }

    pub async fn serve(self) {
        let Self {
            listener,
            udp,
            tag,
            router,
            r#override,
            udp_timeout,
        } = self;
        let (tcp_tag, tcp_router, tcp_override) =
            (tag.clone(), Arc::clone(&router), r#override.clone());
        let tcp = async move {
            let Some(listener) = listener else {
                std::future::pending::<()>().await;
                return;
            };
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let router = Arc::clone(&tcp_router);
                        let tag = tcp_tag.clone();
                        let r#override = tcp_override.clone();
                        let local = stream.local_addr().ok();
                        let destination = destination_for(&r#override, local);
                        tokio::spawn(async move {
                            if let Err(err) =
                                drive_transparent(stream, peer, destination, &tag, &router).await
                            {
                                logging::debug(format_args!("direct[{tag}] {peer}: {err}"));
                            }
                        });
                    }
                    Err(err) => {
                        super::serve_stalled(&format!("direct[{tcp_tag}] accept"), &err).await;
                    }
                }
            }
        };
        let udp_loop = async move {
            let Some(sock) = udp else {
                std::future::pending::<()>().await;
                return;
            };
            let hub = UdpHub::new(Arc::clone(&router), udp_timeout, DatagramFrame::Raw);
            let _stop_hub = StopHub(Arc::clone(&hub));
            let mut packets = tokio::task::JoinSet::new();
            let listen_addr = match sock.local_addr() {
                Ok(a) => a,
                Err(err) => {
                    logging::error(format_args!("direct[{tag}] udp local addr: {err}"));
                    return;
                }
            };
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let received = tokio::select! {
                    packet = sock.recv_from(&mut buf) => packet,
                    _ = packets.join_next(), if !packets.is_empty() => continue,
                };
                match received {
                    Ok((n, source)) => {
                        let dest = destination_for(&r#override, Some(listen_addr));
                        let Target::Ip(dest) = dest else {
                            continue;
                        };
                        if hub.try_existing(source, dest, &buf[..n]) {
                            continue;
                        }
                        let hub = Arc::clone(&hub);
                        let reply = Reply::Socket(Arc::downgrade(&sock));
                        let tag = tag.clone();
                        let payload = buf[..n].to_vec();
                        packets.spawn(async move {
                            if let Err(err) = hub.handle(reply, source, dest, &payload, &tag).await
                            {
                                logging::debug(format_args!("direct[{tag}] udp {source}: {err}"));
                            }
                        });
                    }
                    Err(err) => {
                        super::serve_stalled(&format!("direct[{tag}] udp recv"), &err).await;
                    }
                }
            }
        };
        tokio::select! {
            _ = tcp => {}
            _ = udp_loop => {}
        }
    }
}

struct StopHub(Arc<UdpHub>);

impl Drop for StopHub {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Reference `overrideOption` 1/2/3 applied to `OriginDestination`
/// (= local address of the accepted connection / listen address for UDP).
fn destination_for(r#override: &Override, local: Option<SocketAddr>) -> Target {
    let origin = local
        .map(Target::Ip)
        .unwrap_or_else(|| Target::Domain(String::new(), 0));
    match r#override {
        Override::None => origin,
        Override::Full(full) => full.clone(),
        Override::AddrOnly(addr) => {
            let mut resolved = addr.clone();
            if let (Target::Domain(_, port), Target::Ip(orig)) = (&mut resolved, &origin) {
                *port = orig.port();
            }
            if let (Target::Ip(dst), Target::Ip(orig)) = (&mut resolved, &origin) {
                let port = orig.port();
                *dst = SocketAddr::new(dst.ip(), port);
            }
            resolved
        }
        Override::PortOnly(port) => match origin {
            Target::Ip(mut addr) => {
                addr.set_port(*port);
                Target::Ip(addr)
            }
            Target::Domain(host, _) => Target::Domain(host, *port),
        },
    }
}

fn parse_override_addr(addr: &str, port: u16, at: &str) -> anyhow::Result<Target> {
    if let Ok(ip) = addr.parse::<IpAddr>() {
        Ok(Target::Ip(SocketAddr::new(ip, port)))
    } else if addr.is_empty() {
        Err(anyhow::anyhow!("{at}: override_address: empty"))
    } else {
        Ok(Target::Domain(addr.to_string(), port))
    }
}
