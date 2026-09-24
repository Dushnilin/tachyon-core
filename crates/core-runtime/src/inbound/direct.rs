use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;
use tokio::net::TcpListener;

use crate::inbound::{
    Target, drive_transparent, network_includes_tcp, network_includes_udp, parse_listen,
};
use crate::logging;
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

/// direct inbound: accept raw TCP, destination = local address (the address
/// the client connected to) with optional override_address / override_port.
pub struct Direct {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    r#override: Override,
}

impl Direct {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("direct");
        let at = format!("inbound[{tag}]");
        if !network_includes_tcp(obj) {
            anyhow::bail!("{at}: tcp network not requested (udp-only not implemented yet)");
        }
        if network_includes_udp(obj) {
            logging::warn(format_args!(
                "inbound direct[{tag}]: udp network not implemented yet (tcp only)"
            ));
        }
        let (ip, port) = parse_listen(obj, &at)?;
        let listener = TcpListener::bind(SocketAddr::new(ip, port)).await?;

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

        logging::info(format_args!(
            "inbound direct[{tag}] listening at {ip}:{port}"
        ));
        Ok(Self {
            listener,
            tag: tag.to_string(),
            router,
            r#override,
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
                    let local = stream.local_addr().ok();
                    let destination = self.destination(local);
                    tokio::spawn(async move {
                        if let Err(err) =
                            drive_transparent(stream, peer, destination, &tag, &router).await
                        {
                            logging::debug(format_args!("direct[{tag}] {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::warn(format_args!("direct[{}] accept: {err}", self.tag));
                    return;
                }
            }
        }
    }

    /// Reference `overrideOption` 1/2/3 applied to `OriginDestination`
    /// (= local address of the accepted connection).
    fn destination(&self, local: Option<SocketAddr>) -> Target {
        let origin = local
            .map(Target::Ip)
            .unwrap_or_else(|| Target::Domain(String::new(), 0));
        match &self.r#override {
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
