//! Shared UDP packet path for direct / tproxy inbounds: a small NAT-like
//! session table keyed by (source, destination) that either hijacks DNS
//! (one exchange per datagram) or forwards through a connected outbound UDP
//! socket with an idle-timeout reverse reader (reference `udpnat.Service`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::dns::QueryMeta;
use crate::inbound::Target;
use crate::logging;
use crate::route::{ConnContext, Decision, Router};

/// Idle timeout for an outbound UDP flow (sing-box `C.UDPTimeout` family;
/// route-options `udp_timeout` is applied per-flow when present).
pub(crate) const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

type FlowKey = (SocketAddr, SocketAddr);

struct Flow {
    kind: FlowKind,
    last_ms: AtomicU64,
}

enum FlowKind {
    /// `action: hijack-dns` — stateless per-query exchange.
    Dns,
    /// Connected outbound socket + reverse pump to the client.
    Outbound { sock: Arc<UdpSocket> },
}

impl Flow {
    fn touch(&self) {
        self.last_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        let last = self.last_ms.load(Ordering::Relaxed);
        Duration::from_millis(now_ms().saturating_sub(last))
    }
}

static START_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn now_ms() -> u64 {
    let epoch = START_EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

pub(crate) struct UdpHub {
    router: Arc<Router>,
    flows: Mutex<HashMap<FlowKey, Arc<Flow>>>,
    timeout: Duration,
}

impl UdpHub {
    pub fn new(router: Arc<Router>, timeout: Duration) -> Arc<Self> {
        let hub = Arc::new(Self {
            router,
            flows: Mutex::new(HashMap::new()),
            timeout: if timeout.is_zero() {
                DEFAULT_UDP_TIMEOUT
            } else {
                timeout
            },
        });
        let sweeper = Arc::clone(&hub);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                sweeper.sweep().await;
            }
        });
        hub
    }

    async fn sweep(&self) {
        let mut flows = self.flows.lock().await;
        let timeout = self.timeout;
        flows.retain(|_, flow| flow.idle() < timeout);
    }

    /// Handle one datagram received on `listen` from `source` toward `dest`.
    pub async fn handle(
        self: &Arc<Self>,
        listen: &Arc<UdpSocket>,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
    ) -> std::io::Result<()> {
        let key = (source, dest);
        let flow = {
            let map = self.flows.lock().await;
            if let Some(flow) = map.get(&key) {
                flow.touch();
                Arc::clone(flow)
            } else {
                drop(map);
                let flow = self.open_flow(listen, source, dest, tag).await?;
                flow.touch();
                let mut map = self.flows.lock().await;
                // Another packet may have won the race — keep the first.
                if let Some(existing) = map.get(&key) {
                    Arc::clone(existing)
                } else {
                    map.insert(key, Arc::clone(&flow));
                    flow
                }
            }
        };
        match &flow.kind {
            FlowKind::Dns => self.hijack_one(listen, source, dest, payload, tag).await,
            FlowKind::Outbound { sock } => {
                sock.send(payload).await?;
                Ok(())
            }
        }
    }

    async fn open_flow(
        self: &Arc<Self>,
        listen: &Arc<UdpSocket>,
        source: SocketAddr,
        dest: SocketAddr,
        tag: &str,
    ) -> std::io::Result<Arc<Flow>> {
        let mut ctx = ConnContext::new(tag, source, Target::Ip(dest), "udp");
        let decision = self.router.route_raw(&mut ctx).await?;
        logging::debug(format_args!(
            "udp {tag} {source} -> {} => {:?}",
            ctx.destination, decision
        ));
        let flow = match decision {
            Decision::HijackDns => Flow {
                kind: FlowKind::Dns,
                last_ms: AtomicU64::new(now_ms()),
            },
            Decision::Outbound(idx) => {
                let sock = self.router.connect_udp_index(idx, &ctx.destination).await?;
                let sock = Arc::new(sock);
                spawn_reverse(
                    Arc::clone(&sock),
                    Arc::clone(listen),
                    source,
                    tag,
                    self.timeout,
                    Arc::clone(self),
                    (source, dest),
                );
                Flow {
                    kind: FlowKind::Outbound { sock },
                    last_ms: AtomicU64::new(now_ms()),
                }
            }
        };
        Ok(Arc::new(flow))
    }

    async fn hijack_one(
        &self,
        listen: &Arc<UdpSocket>,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
    ) -> std::io::Result<()> {
        let dns = crate::dns::current()
            .ok_or_else(|| std::io::Error::other("hijack-dns: dns service not configured"))?;
        let meta = QueryMeta {
            inbound: Some(tag.to_string()),
            source: Some(source.ip()),
            network: Some("udp".to_string()),
        };
        let resp = dns.exchange(&meta, payload, true).await?;
        logging::debug(format_args!(
            "udp hijack-dns {tag} {source} -> {dest}: {}B reply",
            resp.len()
        ));
        listen.send_to(&resp, source).await?;
        Ok(())
    }

    async fn remove_flow(&self, key: FlowKey) {
        self.flows.lock().await.remove(&key);
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_reverse(
    outbound: Arc<UdpSocket>,
    listen: Arc<UdpSocket>,
    source: SocketAddr,
    tag: &str,
    idle: Duration,
    hub: Arc<UdpHub>,
    key: FlowKey,
) {
    let tag = tag.to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match tokio::time::timeout(idle, outbound.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if let Err(err) = listen.send_to(&buf[..n], source).await {
                        logging::debug(format_args!("udp reverse {tag} {source}: {err}"));
                        hub.remove_flow(key).await;
                        return;
                    }
                }
                Ok(Err(err)) => {
                    logging::debug(format_args!("udp reverse {tag} {source}: {err}"));
                    hub.remove_flow(key).await;
                    return;
                }
                Err(_) => {
                    // Idle timeout — drop the flow (reference udpnat purge).
                    hub.remove_flow(key).await;
                    return;
                }
            }
        }
    });
}
