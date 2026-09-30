use std::io;

use tokio::net::TcpStream;

use crate::inbound::Target;

/// direct outbound: dial the target from the local host with the dialer
/// options the reference's `AbstractDialerOptions` carries (`routing_mark`,
/// `bind_interface` / `route.default_interface`, and the rest).
#[derive(Default, Clone)]
pub struct Direct {
    pub dial: crate::outbound::dial::DialOptions,
}

impl Direct {
    /// An option this platform cannot carry is an error, like every other
    /// outbound: the reference refuses to start rather than dial without it.
    pub fn build(
        obj: &serde_json::Map<String, serde_json::Value>,
        at: &str,
    ) -> anyhow::Result<Self> {
        crate::outbound::dial::DialOptions::parse(obj)
            .map(|dial| Self { dial })
            .map_err(|err| anyhow::anyhow!("{at}: {err}"))
    }

    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        let dial = &self.dial;
        match target {
            Target::Ip(addr) => crate::outbound::dial::connect_tcp_addr(*addr, dial).await,
            Target::Domain(host, port) => {
                crate::outbound::dial::connect_tcp(host, *port, dial).await
            }
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let dial = &self.dial;
        let addr = match target {
            Target::Ip(addr) => *addr,
            Target::Domain(host, port) => {
                let addrs = crate::outbound::dial::resolve(host, *port).await?;
                match addrs.into_iter().next() {
                    Some(addr) => addr,
                    None => return Err(io::Error::other(format!("no address for {host}"))),
                }
            }
        };
        crate::outbound::dial::connect_udp(addr, dial).await
    }
}
