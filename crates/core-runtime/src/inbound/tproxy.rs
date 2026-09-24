use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use tokio::net::TcpListener;

use crate::inbound::{Target, drive_transparent, network_includes_udp, parse_listen};
use crate::logging;
use crate::route::Router;

/// tproxy inbound: TCP with `IP_TRANSPARENT` / `IPV6_TRANSPARENT`; destination
/// = local address of the accepted socket (TPROXY preserves the original
/// destination there). Requires Linux + CAP_NET_ADMIN; other platforms and
/// missing capability fail at bind (reference `tproxy_other.go`).
pub struct Tproxy {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
}

impl Tproxy {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("tproxy");
        let at = format!("inbound[{tag}]");
        if network_includes_udp(obj) {
            logging::warn(format_args!(
                "inbound tproxy[{tag}]: udp network not implemented yet (tcp only)"
            ));
        }
        let (ip, port) = parse_listen(obj, &at)?;
        let listener =
            bind_tproxy(SocketAddr::new(ip, port)).map_err(|err| anyhow::anyhow!("{at}: {err}"))?;
        logging::info(format_args!(
            "inbound tproxy[{tag}] listening at {ip}:{port}"
        ));
        Ok(Self {
            listener,
            tag: tag.to_string(),
            router,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let router = Arc::clone(&self.router);
                    let tag = self.tag.clone();
                    let destination = match stream.local_addr() {
                        Ok(addr) => Target::Ip(addr),
                        Err(err) => {
                            logging::error(format_args!(
                                "tproxy[{tag}] {peer}: local address: {err}"
                            ));
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(err) =
                            drive_transparent(stream, peer, destination, &tag, &router).await
                        {
                            logging::debug(format_args!("tproxy[{tag}] {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::warn(format_args!("tproxy[{}] accept: {err}", self.tag));
                    return;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_tproxy(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

#[cfg(not(target_os = "linux"))]
fn bind_tproxy(_addr: SocketAddr) -> io::Result<TcpListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tproxy is only supported on Linux",
    ))
}
