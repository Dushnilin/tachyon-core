//! Shared UDP packet path for direct / tproxy inbounds: a small NAT-like
//! session table keyed by (source, destination) that either hijacks DNS
//! (one exchange per datagram) or forwards through a connected outbound UDP
//! socket with an idle-timeout reverse reader (reference `udpnat.Service`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::dns::QueryMeta;
use crate::inbound::{AnyWrite, Target};
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

/// How a reply datagram is framed before it goes back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DatagramFrame {
    /// the bare payload: direct and tproxy inbounds answer a socket
    Raw,
    /// a SOCKS5 UDP relay header in front of it (mixed inbound)
    Socks,
    /// `[len:u16][payload]`, which is what `vmess.Service`'s `serverPacketConn`
    /// reads and writes for the UDP command
    LengthPrefixed,
}

impl DatagramFrame {
    fn apply(self, dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
        match self {
            DatagramFrame::Raw => payload.to_vec(),
            DatagramFrame::Socks => socks_udp_datagram(dest, payload),
            DatagramFrame::LengthPrefixed => {
                let mut out = Vec::with_capacity(2 + payload.len());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
                out
            }
        }
    }
}

/// Where a reply datagram goes: back out of a socket the client is reading
/// from, or down a stream it is reading a length-prefixed sequence off.
#[derive(Clone)]
pub(crate) enum Reply {
    Socket(Arc<UdpSocket>),
    Stream(Arc<tokio::sync::Mutex<AnyWrite>>),
}

impl Reply {
    async fn send(&self, framed: Vec<u8>, source: SocketAddr) -> std::io::Result<()> {
        match self {
            Reply::Socket(socket) => socket.send_to(&framed, source).await.map(|_| ()),
            Reply::Stream(writer) => {
                let mut writer = writer.lock().await;
                writer.write_all(&framed).await
            }
        }
    }
}

pub(crate) struct UdpHub {
    router: Arc<Router>,
    flows: Mutex<HashMap<FlowKey, Arc<Flow>>>,
    timeout: Duration,
    /// how replies are framed before they go back
    frame: DatagramFrame,
}

impl UdpHub {
    pub fn new(router: Arc<Router>, timeout: Duration, frame: DatagramFrame) -> Arc<Self> {
        let hub = Arc::new(Self {
            router,
            flows: Mutex::new(HashMap::new()),
            timeout: if timeout.is_zero() {
                DEFAULT_UDP_TIMEOUT
            } else {
                timeout
            },
            frame,
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

    /// Handle one datagram received from `source` toward `dest`, and answer it
    /// through `reply`.
    pub async fn handle(
        self: &Arc<Self>,
        reply: Reply,
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
                let flow = self.open_flow(reply.clone(), source, dest, tag).await?;
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
            FlowKind::Dns => self.hijack_one(reply, source, dest, payload, tag).await,
            FlowKind::Outbound { sock } => {
                sock.send(payload).await?;
                Ok(())
            }
        }
    }

    async fn open_flow(
        self: &Arc<Self>,
        reply: Reply,
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
                    reply,
                    self.frame,
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
        reply: Reply,
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
        reply.send(self.frame.apply(dest, &resp), source).await?;
        Ok(())
    }

    async fn remove_flow(&self, key: FlowKey) {
        self.flows.lock().await.remove(&key);
    }
}

/// The UDP command of a proxy-protocol server inbound: `[len:u16][payload]` in
/// both directions over the connection the client already opened, with every
/// datagram going to the destination its request head named.
///
/// `vmess.Service`'s `serverPacketConn` byte for byte -- a length, the payload,
/// and no address in either direction, because the head carried it. The
/// reference's vless and trojan inbounds wrap this the same way, and their
/// inbounds listen on TCP only: there is no second socket to bind.
pub(crate) async fn relay_stream_datagrams<S>(
    mut reader: S,
    writer: Arc<tokio::sync::Mutex<AnyWrite>>,
    source: SocketAddr,
    dest: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let hub = UdpHub::new(
        Arc::clone(router),
        Duration::ZERO,
        DatagramFrame::LengthPrefixed,
    );
    let reply = Reply::Stream(writer);
    let mut len = [0u8; 2];
    loop {
        if let Err(err) = reader.read_exact(&mut len).await {
            // a client that closes between datagrams has simply finished; only
            // a half-read length is a protocol error
            return match err.kind() {
                std::io::ErrorKind::UnexpectedEof if len == [0, 0] => Ok(()),
                _ => Err(err),
            };
        }
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        reader.read_exact(&mut payload).await?;
        hub.handle(reply.clone(), source, dest, &payload, tag)
            .await?;
    }
}

/// The destination a UDP command's head has to name: an address, because the
/// datagrams that follow carry none.
pub(crate) fn udp_destination(destination: &Target) -> std::io::Result<SocketAddr> {
    match destination {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, _) => Err(std::io::Error::other(format!(
            "the udp command names the destination in its head, and {host:?} is not an address"
        ))),
    }
}

/// SOCKS5 UDP datagram header `[RSV][RSV][FRAG][ATYP][ADDR][PORT]` + payload.
fn socks_udp_datagram(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    match dest.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&dest.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[allow(clippy::too_many_arguments)]
fn spawn_reverse(
    outbound: Arc<UdpSocket>,
    reply: Reply,
    frame: DatagramFrame,
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
                    let packet = frame.apply(key.1, &buf[..n]);
                    if let Err(err) = reply.send(packet, source).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The datagrams of a UDP command carry no address, so the head has to name
    /// one. A name cannot be sent to, and a session that accepted one would
    /// answer nothing for as long as the client waited -- so it is refused with
    /// the name in the message instead.
    #[test]
    fn a_udp_command_destination_has_to_be_an_address() {
        assert_eq!(
            udp_destination(&Target::Ip("10.0.0.1:53".parse().expect("addr"))).expect("ip"),
            "10.0.0.1:53".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(
            udp_destination(&Target::Ip("[::1]:5353".parse().expect("addr"))).expect("v6"),
            "[::1]:5353".parse::<SocketAddr>().expect("addr")
        );
        let err = udp_destination(&Target::Domain("dns.example.com".into(), 53))
            .expect_err("a name was accepted");
        assert!(err.to_string().contains("dns.example.com"), "{err}");
    }

    /// The framing is the reference's `serverPacketConn`: a length and the
    /// payload, with the address nowhere in it.
    #[test]
    fn length_prefixed_frames_carry_no_address() {
        let dest = "10.0.0.1:53".parse::<SocketAddr>().expect("addr");
        assert_eq!(
            DatagramFrame::LengthPrefixed.apply(dest, b"hello"),
            b"\x00\x05hello".to_vec()
        );
        assert_eq!(DatagramFrame::Raw.apply(dest, b"hello"), b"hello".to_vec());
        let socks = DatagramFrame::Socks.apply(dest, b"hello");
        assert_eq!(&socks[..3], &[0, 0, 0]);
        assert_eq!(&socks[3..], b"\x01\x0a\x00\x00\x01\x00\x35hello");
    }

    /// A datagram the length describes has to arrive whole and nothing else:
    /// the relay reads exactly that many bytes, so a frame that is one byte
    /// short would eat the next frame's length.
    #[test]
    fn a_length_prefix_covers_its_whole_payload() {
        let dest = "10.0.0.1:53".parse::<SocketAddr>().expect("addr");
        for len in [1usize, 2, 255, 1400, 65_535] {
            let payload = vec![(len % 251) as u8; len];
            let framed = DatagramFrame::LengthPrefixed.apply(dest, &payload);
            assert_eq!(framed.len(), len + 2, "{len}");
            assert_eq!(
                u16::from_be_bytes([framed[0], framed[1]]) as usize,
                len,
                "{len}"
            );
            assert_eq!(&framed[2..], &payload[..], "{len}");
        }
    }
}
