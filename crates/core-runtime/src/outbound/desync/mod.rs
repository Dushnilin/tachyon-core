pub mod config;
pub mod engine;
pub mod packet;
pub mod payload;

pub use config::{DesyncConfig, DesyncMode, DesyncPreset, SplitPos};
pub use engine::{apply_desync_tcp, apply_desync_udp};

use std::io;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::inbound::{Conn, Target};

/// Dedicated DPI desynchronization outbound (`"type": "desync"`).
///
/// Combines the best battle-tested techniques from b4, zapret/zapret2, and ByeDPI
/// into a native, high-performance, pure-Rust desynchronization engine:
/// - Low-TTL fake packet injection (TCP & UDP)
/// - SNI & HTTP Host middle-SLD segmentation
/// - TTL=1 retransmission disorder
/// - RFC-compliant TLS record multi-splitting
///
/// Crucially, desync only touches the initial connection handshake (~500 bytes),
/// after which the connection runs at full line rate inside the Linux kernel via
/// zero-copy `splice(2)` without any throughput or latency penalty.
#[derive(Clone)]
pub struct Desync {
    pub dial: crate::outbound::dial::DialOptions,
    pub config: Arc<DesyncConfig>,
}

impl Desync {
    pub fn build(
        obj: &serde_json::Map<String, serde_json::Value>,
        at: &str,
    ) -> anyhow::Result<Self> {
        let dial = crate::outbound::dial::DialOptions::parse(obj)
            .map_err(|err| anyhow::anyhow!("{at}: {err}"))?;
        let config = DesyncConfig::from_json(obj).map_err(|err| anyhow::anyhow!("{at}: {err}"))?;
        Ok(Self {
            dial,
            config: Arc::new(config),
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<Conn> {
        let dial = &self.dial;
        let stream = match target {
            Target::Ip(addr) => crate::outbound::dial::connect_tcp_addr(*addr, dial).await?,
            Target::Domain(host, port) => {
                crate::outbound::dial::connect_tcp(host, *port, dial).await?
            }
        };
        Ok(Conn::Desync(Box::new(stream), self.config.clone()))
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        let dial = &self.dial;
        let (addr, port) = match target {
            Target::Ip(addr) => (*addr, addr.port()),
            Target::Domain(host, port) => {
                let addrs = crate::outbound::dial::resolve(host, *port).await?;
                match addrs.into_iter().next() {
                    Some(addr) => (addr, *port),
                    None => return Err(io::Error::other(format!("no address for {host}"))),
                }
            }
        };
        let socket = crate::outbound::dial::connect_udp(addr, dial).await?;
        if self.config.udp_fake {
            let _ = engine::apply_desync_udp(&socket, port, &self.config).await;
        }
        Ok(socket)
    }
}
