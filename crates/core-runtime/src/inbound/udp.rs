//! Shared UDP packet path for direct / tproxy inbounds: a small NAT-like
//! session table keyed by (source, destination) that either hijacks DNS
//! (one exchange per datagram) or forwards through a connected outbound UDP
//! socket with an idle-timeout reverse reader (reference `udpnat.Service`).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use portable_atomic::AtomicU64;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;

use crate::dns::QueryMeta;
use crate::inbound::{AnyWrite, Target};
use crate::logging;
use crate::route::{ConnContext, Decision, Router};

/// Idle timeout for an outbound UDP flow (sing-box `C.UDPTimeout` family;
/// route-options `udp_timeout` is applied per-flow when present).
pub(crate) const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

type FlowKey = (SocketAddr, SocketAddr);

/// Packets held back while the outbound socket is not writable. The old
/// code spent one `to_vec()` plus one `tokio::spawn` per packet here, which
/// turns a temporary full send buffer into a task-and-memory avalanche.
/// Now one writer task drains a bounded backlog and the newest packet is
/// dropped at the cap -- a UDP proxy loses datagrams under pressure anyway,
/// the difference is only whether it also loses its budget.
const UDP_BACKLOG_MAX: usize = 64;

/// How many datagrams a flow may hold while a QUIC ClientHello comes
/// together. A post-quantum hello takes two; past this it is not coming.
const MAX_SNIFF_DATAGRAMS: usize = 8;

/// What [`UdpHub::open_flow`] made of a flow's datagrams so far.
enum Opened {
    Flow(Arc<Flow>),
    /// the sniff wants another datagram; route anyway after this long
    Wait(Duration),
}

struct Flow {
    kind: FlowKind,
    last_ms: AtomicU64,
    timeout: Duration,
    /// datagrams `try_send` refused; drained in order by the writer task
    backlog: Mutex<VecDeque<Vec<u8>>>,
    /// exactly one writer task is (or will be) draining `backlog`
    writing: AtomicBool,
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

    /// Hold a datagram the socket would not take and make sure one writer
    /// task will send it. The swap only wins when no writer is running, so
    /// there is never a second one; the writer's own re-check covers the
    /// race where it exits between this push and that swap.
    fn hold_back(self: &Arc<Self>, payload: &[u8]) {
        {
            let mut backlog = self.backlog.lock().expect("backlog");
            if backlog.len() < UDP_BACKLOG_MAX {
                backlog.push_back(payload.to_vec());
            }
        }
        if !self.writing.swap(true, Ordering::AcqRel) {
            let flow = Arc::clone(self);
            tokio::spawn(async move {
                flow.drain_backlog().await;
            });
        }
    }

    /// Send the backlog in order; release the flag once empty, re-checking
    /// once so a push that raced the release cannot be stranded with no
    /// writer looking at it.
    async fn drain_backlog(self: Arc<Self>) {
        loop {
            loop {
                let next = self.backlog.lock().expect("backlog").pop_front();
                let Some(pkt) = next else {
                    break;
                };
                if let FlowKind::Outbound { sock } = &self.kind {
                    let _ = sock.send(&pkt).await;
                }
            }
            self.writing.store(false, Ordering::Release);
            if self.backlog.lock().expect("backlog").is_empty() {
                return;
            }
            if self.writing.swap(true, Ordering::AcqRel) {
                // a pusher beat us to the flag and spawned its own writer
                return;
            }
            // we reclaimed the racing push ourselves
        }
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
    /// `[atyp][addr][port][payload]` (Shadowsocks AEAD UDP payload)
    Shadowsocks,
    /// `[len:u16][address][port][payload]` (PacketAddr mode in sing-box / v2fly)
    PacketAddr,
    /// Xray Mux.Cool Keep/Data reply, addressed by its session ID.
    Xudp(u16),
}

impl DatagramFrame {
    /// Frame `payload` for `dest` into `out` (cleared first).
    ///
    /// `Raw` needs no framing at all, so the send loops skip this entirely
    /// and hand `send` the recv-buffer slice — a `to_vec()` per datagram
    /// for a header of zero bytes.
    pub(crate) fn apply_into(self, dest: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
        out.clear();
        match self {
            DatagramFrame::Raw => out.extend_from_slice(payload),
            DatagramFrame::Socks => socks_udp_datagram(dest, payload, out),
            DatagramFrame::LengthPrefixed => {
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            DatagramFrame::Shadowsocks => ss_udp_datagram(dest, payload, out),
            DatagramFrame::PacketAddr => {
                let mut body =
                    Vec::with_capacity(crate::outbound::packet::MAX_ADDR_PORT + payload.len());
                let target = Target::Ip(dest);
                let _ = crate::outbound::packet::put_addr_port(&mut body, &target);
                body.extend_from_slice(payload);
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(&body);
            }
            DatagramFrame::Xudp(id) => {
                let meta_len = if dest.is_ipv4() { 12u16 } else { 24u16 };
                out.extend_from_slice(&meta_len.to_be_bytes());
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&[2, 1, 2]); // Keep, Data, UDP
                out.extend_from_slice(&dest.port().to_be_bytes());
                match dest.ip() {
                    IpAddr::V4(ip) => {
                        out.push(1);
                        out.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        out.push(3);
                        out.extend_from_slice(&ip.octets());
                    }
                }
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
        }
    }
}

fn ss_udp_datagram(dest: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.reserve(7 + payload.len());
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
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct TunReply {
    pub src: SocketAddr,
    pub dest: SocketAddr,
    pub payload: Vec<u8>,
}

/// Where a reply datagram goes: back out of a socket the client is reading
/// from, down a stream it is reading a length-prefixed sequence off, or back to
/// the TUN interface.
#[derive(Clone)]
pub(crate) enum Reply {
    /// Weak on purpose: a session task that outlives its inbound must not be
    /// what holds the listening socket open, or the next `bind` after a
    /// reload gets `EADDRINUSE` (issue #5). The inbound owns the only strong
    /// handle, so aborting `serve` closes the port.
    Socket(Weak<UdpSocket>),
    Stream(Arc<tokio::sync::Mutex<AnyWrite>>),
    #[allow(dead_code)]
    Tun {
        sender: tokio::sync::mpsc::Sender<TunReply>,
    },
    Shadowsocks {
        socket: Weak<UdpSocket>,
        method: crate::outbound::shadowsocks::crypto::Method,
        master_key: Arc<Vec<u8>>,
    },
}

/// A weak reply handle that is still backed by a socket.
fn live(socket: &Weak<UdpSocket>) -> io::Result<Arc<UdpSocket>> {
    socket
        .upgrade()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "udp socket is gone"))
}

impl Reply {
    async fn send(
        &self,
        framed: &[u8],
        source: SocketAddr,
        remote: SocketAddr,
    ) -> std::io::Result<()> {
        match self {
            Reply::Socket(socket) => live(socket)?.send_to(framed, source).await.map(|_| ()),
            Reply::Stream(writer) => {
                let mut writer = writer.lock().await;
                writer.write_all(framed).await
            }
            Reply::Tun { sender } => sender
                .send(TunReply {
                    src: remote,
                    dest: source,
                    payload: framed.to_vec(),
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tun reply channel closed")),
            Reply::Shadowsocks {
                socket,
                method,
                master_key,
            } => {
                let socket = live(socket)?;
                use crate::outbound::shadowsocks::crypto::{Cipher, derive_subkey, random_bytes};
                let mut salt = vec![0u8; method.salt_len()];
                random_bytes(&mut salt)?;
                let subkey = derive_subkey(*method, master_key, &salt);
                let cipher = Cipher::new(*method, &subkey.0[..subkey.1]);
                let mut body = framed.to_vec();
                cipher
                    .seal(0, &mut body)
                    .map_err(|e| io::Error::other(format!("ss udp seal: {e}")))?;
                let mut packet = salt;
                packet.extend_from_slice(&body);
                socket.send_to(&packet, source).await.map(|_| ())
            }
        }
    }
}

pub(crate) struct UdpHub {
    router: Arc<Router>,
    flows: RwLock<HashMap<FlowKey, Arc<Flow>>>,
    /// First packets for one tuple share an initialization gate, so a burst
    /// cannot create multiple proxy sessions whose idle tasks race each other.
    opening: Mutex<HashMap<FlowKey, Weak<tokio::sync::Mutex<()>>>>,
    /// Datagrams of flows not routed yet because a packet sniff asked for
    /// more, in arrival order. Touched only under the flow's opening gate.
    held: Mutex<HashMap<FlowKey, Vec<Vec<u8>>>>,
    reverse_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    timeout: Duration,
    /// how replies are framed before they go back
    frame: DatagramFrame,
}

impl UdpHub {
    pub fn new(router: Arc<Router>, timeout: Duration, frame: DatagramFrame) -> Arc<Self> {
        let hub = Arc::new(Self {
            router,
            flows: RwLock::new(HashMap::new()),
            opening: Mutex::new(HashMap::new()),
            held: Mutex::new(HashMap::new()),
            reverse_tasks: Mutex::new(Vec::new()),
            timeout: if timeout.is_zero() {
                DEFAULT_UDP_TIMEOUT
            } else {
                timeout
            },
            frame,
        });
        let sweeper = Arc::downgrade(&hub);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                let Some(sweeper) = sweeper.upgrade() else {
                    return; // the connection this hub belongs to is gone
                };
                sweeper.sweep().await;
            }
        });
        hub
    }

    /// Release per-flow reply sockets when a transparent listener is stopped.
    pub fn stop(&self) {
        for task in self.reverse_tasks.lock().expect("reverse tasks").drain(..) {
            task.abort();
        }
        self.flows.write().expect("flows").clear();
        self.held.lock().expect("held").clear();
    }

    async fn sweep(&self) {
        let mut flows = self.flows.write().expect("flows");
        flows.retain(|_, flow| flow.idle() < flow.timeout);
    }

    /// Fast path for the receive loops: an already-open outbound flow is fed
    /// straight from the reader — `try_send` with no copy and no per-packet
    /// task. Returns `false` when the flow is unknown (or is a DNS hijack,
    /// which needs the async exchange), and the caller should fall back to
    /// spawning the full [`UdpHub::handle`].
    pub fn try_existing(&self, source: SocketAddr, dest: SocketAddr, payload: &[u8]) -> bool {
        let flow = self
            .flows
            .read()
            .expect("flows")
            .get(&(source, dest))
            .cloned();
        let Some(flow) = flow else {
            return false;
        };
        let FlowKind::Outbound { sock } = &flow.kind else {
            return false;
        };
        // while a writer is draining the backlog, new packets go behind it:
        // a lucky try_send must not overtake the queued datagrams
        if flow.writing.load(Ordering::Acquire) {
            flow.hold_back(payload);
            flow.touch();
            return true;
        }
        match sock.try_send(payload) {
            Ok(_) => {
                flow.touch();
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                flow.hold_back(payload);
                flow.touch();
                true
            }
            Err(err) => {
                logging::debug(format_args!("udp fast path send: {err}"));
                flow.touch();
                true
            }
        }
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
        self.handle_routed(reply, source, dest, payload, tag, &Target::Ip(dest))
            .await
    }

    /// Preserve a named proxy destination in routing even though the flow key
    /// and the datagram reply use its resolved socket address.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_routed(
        self: &Arc<Self>,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
        target: &Target,
    ) -> std::io::Result<()> {
        let key = (source, dest);
        let found = {
            let map = self.flows.read().expect("flows");
            map.get(&key).cloned()
        };
        let flow = match found {
            Some(flow) => {
                flow.touch();
                flow
            }
            None => {
                let _gate = self.gate(key).lock_owned().await;
                let found = self.flows.read().expect("flows").get(&key).cloned();
                if let Some(existing) = found {
                    existing.touch();
                    existing
                } else {
                    let mut held = self
                        .held
                        .lock()
                        .expect("held")
                        .remove(&key)
                        .unwrap_or_default();
                    let first = held.is_empty();
                    held.push(payload.to_vec());
                    let force = held.len() >= MAX_SNIFF_DATAGRAMS;
                    match self
                        .open_flow(reply.clone(), source, dest, tag, target, &held, force)
                        .await?
                    {
                        Opened::Wait(timeout) => {
                            self.held.lock().expect("held").insert(key, held);
                            if first {
                                self.route_held_after(key, timeout, reply, tag, target);
                            }
                            return Ok(());
                        }
                        Opened::Flow(flow) => {
                            // the held ones go first; this datagram goes below
                            held.pop();
                            for earlier in &held {
                                self.deliver(&flow, reply.clone(), source, dest, earlier, tag)
                                    .await?;
                            }
                            flow
                        }
                    }
                }
            }
        };
        self.deliver(&flow, reply, source, dest, payload, tag).await
    }

    /// The opening gate of one tuple: first datagrams share it, so a burst
    /// cannot create multiple proxy sessions whose idle tasks race each other.
    fn gate(&self, key: FlowKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut opening = self.opening.lock().expect("opening");
        opening.retain(|_, gate| gate.strong_count() != 0);
        match opening.get(&key).and_then(Weak::upgrade) {
            Some(gate) => gate,
            None => {
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                opening.insert(key, Arc::downgrade(&gate));
                gate
            }
        }
    }

    async fn deliver(
        &self,
        flow: &Flow,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
    ) -> std::io::Result<()> {
        match &flow.kind {
            FlowKind::Dns => self.hijack_one(reply, source, dest, payload, tag).await,
            FlowKind::Outbound { sock } => {
                sock.send(payload).await?;
                Ok(())
            }
        }
    }

    /// The rest of a split ClientHello may never come: once the sniff
    /// timeout runs out, route the flow on what it has and send what it held.
    fn route_held_after(
        self: &Arc<Self>,
        key: FlowKey,
        timeout: Duration,
        reply: Reply,
        tag: &str,
        target: &Target,
    ) {
        let hub = Arc::downgrade(self);
        let tag = tag.to_string();
        let target = target.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let Some(hub) = hub.upgrade() else {
                return;
            };
            let (source, dest) = key;
            let _gate = hub.gate(key).lock_owned().await;
            // a later datagram may have completed the sniff meanwhile
            let Some(held) = hub.held.lock().expect("held").remove(&key) else {
                return;
            };
            let flow = match hub
                .open_flow(reply.clone(), source, dest, &tag, &target, &held, true)
                .await
            {
                Ok(Opened::Flow(flow)) => flow,
                Ok(Opened::Wait(_)) => return,
                Err(err) => {
                    logging::debug(format_args!("udp {tag} {source}: {err}"));
                    return;
                }
            };
            for datagram in &held {
                if let Err(err) = hub
                    .deliver(&flow, reply.clone(), source, dest, datagram, &tag)
                    .await
                {
                    logging::debug(format_args!("udp {tag} {source}: {err}"));
                    return;
                }
            }
        });
    }

    /// Route a new flow by its datagrams so far and open it. `force` routes
    /// even when the sniff would rather see another datagram.
    #[allow(clippy::too_many_arguments)]
    async fn open_flow(
        self: &Arc<Self>,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        tag: &str,
        target: &Target,
        datagrams: &[Vec<u8>],
        force: bool,
    ) -> std::io::Result<Opened> {
        let key = (source, dest);
        let mut ctx = ConnContext::new(tag, source, target.clone(), "udp");
        let views: Vec<&[u8]> = datagrams.iter().map(Vec::as_slice).collect();
        let decision = self.router.route_packet(&mut ctx, &views).await?;
        if !force && ctx.sniff_error == Some(crate::route::SniffError::NeedMore) {
            return Ok(Opened::Wait(
                ctx.sniff_timeout
                    .unwrap_or(crate::route::rule::DEFAULT_SNIFF_TIMEOUT),
            ));
        }
        logging::debug(format_args!(
            "udp {tag} {source} -> {} => {:?}",
            ctx.destination, decision
        ));
        let flow = match decision {
            Decision::HijackDns => Flow {
                kind: FlowKind::Dns,
                last_ms: AtomicU64::new(now_ms()),
                timeout: self.timeout,
                backlog: Mutex::new(VecDeque::new()),
                writing: AtomicBool::new(false),
            },
            Decision::Outbound(idx) => {
                let target = if ctx.udp_disable_domain_unmapping == Some(false)
                    && let Some(orig) = &ctx.origin_destination
                {
                    orig
                } else {
                    &ctx.destination
                };
                let timeout = ctx.udp_timeout.unwrap_or(self.timeout);
                let sock = self.router.connect_udp_index(idx, target).await?;
                let sock = Arc::new(sock);
                let task = spawn_reverse(
                    Arc::clone(&sock),
                    reply,
                    self.frame,
                    source,
                    tag,
                    timeout,
                    Arc::clone(self),
                    key,
                );
                let mut tasks = self.reverse_tasks.lock().expect("reverse tasks");
                tasks.retain(|task| !task.is_finished());
                tasks.push(task);
                Flow {
                    kind: FlowKind::Outbound { sock },
                    last_ms: AtomicU64::new(now_ms()),
                    timeout,
                    backlog: Mutex::new(VecDeque::new()),
                    writing: AtomicBool::new(false),
                }
            }
        };
        let flow = Arc::new(flow);
        self.flows
            .write()
            .expect("flows")
            .insert(key, Arc::clone(&flow));
        Ok(Opened::Flow(flow))
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
        if self.frame == DatagramFrame::Raw {
            reply.send(&resp, source, dest).await?;
        } else {
            let mut framed = Vec::new();
            self.frame.apply_into(dest, &resp, &mut framed);
            reply.send(&framed, source, dest).await?;
        }
        Ok(())
    }

    fn touch_flow(&self, key: FlowKey, socket: &Arc<UdpSocket>) -> bool {
        let flows = self.flows.read().expect("flows");
        let Some(flow) = flows.get(&key) else {
            return false;
        };
        if let FlowKind::Outbound { sock } = &flow.kind
            && Arc::ptr_eq(sock, socket)
        {
            flow.touch();
            return true;
        }
        false
    }

    fn flow_is_active(&self, key: FlowKey, socket: &Arc<UdpSocket>) -> bool {
        self.flows
            .read()
            .expect("flows")
            .get(&key)
            .is_some_and(|flow| {
                matches!(&flow.kind, FlowKind::Outbound {sock} if Arc::ptr_eq(sock, socket))
                    && flow.idle() < flow.timeout
            })
    }

    pub fn has_active_flow(&self, source: SocketAddr, dest: SocketAddr) -> bool {
        self.flows
            .read()
            .expect("flows")
            .get(&(source, dest))
            .is_some_and(|flow| flow.idle() < flow.timeout)
    }

    async fn remove_flow(&self, key: FlowKey, socket: &Arc<UdpSocket>) {
        let mut flows = self.flows.write().expect("flows");
        if flows.get(&key).is_some_and(
            |flow| matches!(&flow.kind, FlowKind::Outbound {sock} if Arc::ptr_eq(sock, socket)),
        ) {
            flows.remove(&key);
        }
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
        Target::Domain(host, port) => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                Ok(SocketAddr::new(ip, *port))
            } else {
                Err(std::io::Error::other(format!(
                    "the udp command names the destination in its head, and {host:?} is not an address"
                )))
            }
        }
    }
}

/// SOCKS5 UDP datagram header `[RSV][RSV][FRAG][ATYP][ADDR][PORT]` + payload,
/// appended to `out` (cleared by the caller through `apply_into`).
fn socks_udp_datagram(dest: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.reserve(10 + payload.len());
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
) -> tokio::task::AbortHandle {
    let tag = tag.to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        // framing buffer for non-Raw frames, kept across datagrams so the
        // capacity survives; Raw replies borrow `buf` directly and never
        // touch it
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(idle, outbound.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    // Both directions count as activity. A receive-only media
                    // flow must keep its established proxy/NAT session.
                    if !hub.touch_flow(key, &outbound) {
                        return;
                    }
                    let framed: &[u8] = if frame == DatagramFrame::Raw {
                        &buf[..n]
                    } else {
                        frame.apply_into(key.1, &buf[..n], &mut out);
                        &out
                    };
                    if let Err(err) = reply.send(framed, source, key.1).await {
                        logging::debug(format_args!("udp reverse {tag} {source}: {err}"));
                        hub.remove_flow(key, &outbound).await;
                        return;
                    }
                }
                Ok(Err(err)) => {
                    logging::debug(format_args!("udp reverse {tag} {source}: {err}"));
                    hub.remove_flow(key, &outbound).await;
                    return;
                }
                Err(_) => {
                    // Sending without replies is also a live UDP session.
                    if hub.flow_is_active(key, &outbound) {
                        continue;
                    }
                    // Idle timeout — drop the flow (reference udpnat purge).
                    hub.remove_flow(key, &outbound).await;
                    return;
                }
            }
        }
    })
    .abort_handle()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_test_router() -> Arc<Router> {
        Router::new(&serde_json::json!({
            "outbounds": [{"type": "direct", "tag": "out"}],
            "route": {"final": "out"}
        }))
        .expect("direct router")
    }

    #[tokio::test]
    async fn reverse_traffic_keeps_a_receive_only_udp_flow_alive() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let source = client.local_addr().expect("source");
        let dest = server.local_addr().expect("dest");
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_millis(100),
            DatagramFrame::Raw,
        );
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"start",
            "test",
        )
        .await
        .expect("open flow");
        let mut buf = [0; 64];
        let (_, upstream) = server.recv_from(&mut buf).await.expect("first packet");
        // The client does not transmit again, while the server remains active.
        for sequence in 0..12u8 {
            server
                .send_to(&[sequence], upstream)
                .await
                .expect("server reply");
            let n = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buf))
                .await
                .expect("reply deadline")
                .expect("reply");
            assert_eq!(&buf[..n], &[sequence]);
            hub.sweep().await;
            assert!(
                hub.flows
                    .read()
                    .expect("flows")
                    .contains_key(&(source, dest)),
                "active receive-only flow was swept at packet {sequence}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        hub.stop();
    }

    #[tokio::test]
    async fn an_old_reverse_task_cannot_remove_a_replacement_udp_flow() {
        let old = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("old"));
        let replacement = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("replacement"));
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_secs(1),
            DatagramFrame::Raw,
        );
        let key = (
            "127.0.0.1:30000".parse().expect("source"),
            "127.0.0.1:30001".parse().expect("dest"),
        );
        hub.flows.write().expect("flows").insert(
            key,
            Arc::new(Flow {
                kind: FlowKind::Outbound { sock: replacement },
                last_ms: AtomicU64::new(now_ms()),
                timeout: Duration::from_secs(1),
                backlog: Mutex::new(VecDeque::new()),
                writing: AtomicBool::new(false),
            }),
        );
        let task = spawn_reverse(
            old,
            Reply::Socket(Arc::downgrade(&reply)),
            DatagramFrame::Raw,
            key.0,
            "test",
            Duration::from_millis(20),
            Arc::clone(&hub),
            key,
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(task.is_finished(), "old reverse task must finish");
        assert!(
            hub.flows.read().expect("flows").contains_key(&key),
            "old timeout removed a newer flow with the same tuple"
        );
        hub.stop();
    }

    #[tokio::test]
    async fn sending_without_replies_keeps_the_same_udp_session() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server");
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let source = reply.local_addr().expect("source");
        let dest = server.local_addr().expect("dest");
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_millis(100),
            DatagramFrame::Raw,
        );
        let mut first_peer = None;
        let mut buf = [0; 64];
        for sequence in 0..12u8 {
            hub.handle(
                Reply::Socket(Arc::downgrade(&reply)),
                source,
                dest,
                &[sequence],
                "test",
            )
            .await
            .expect("send");
            let (_, peer) =
                tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                    .await
                    .expect("receive deadline")
                    .expect("receive");
            assert_eq!(
                peer,
                *first_peer.get_or_insert(peer),
                "active sender's NAT session changed"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        hub.stop();
    }

    #[tokio::test]
    async fn concurrent_first_datagrams_open_one_proxy_udp_session() {
        use std::sync::atomic::AtomicUsize;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
        let proxy = listener.local_addr().expect("proxy addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            let mut streams = Vec::new();
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept");
                count.fetch_add(1, Ordering::Relaxed);
                let mut header = [0; 19];
                stream
                    .read_exact(&mut header)
                    .await
                    .expect("VLESS Mux header");
                assert_eq!(header[18], crate::outbound::packet::CMD_MUX);
                stream.write_all(&[0, 0]).await.expect("VLESS response");
                streams.push(stream);
            }
        });
        let router = Router::new(&serde_json::json!({
            "outbounds": [{"type":"vless", "tag":"out", "server":"127.0.0.1",
                "server_port":proxy.port(), "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "route":{"final":"out"}
        }))
        .expect("router");
        let hub = UdpHub::new(router, Duration::from_secs(1), DatagramFrame::Raw);
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut requests = tokio::task::JoinSet::new();
        for sequence in 0..16u8 {
            let hub = Arc::clone(&hub);
            let reply = Arc::clone(&reply);
            let barrier = Arc::clone(&barrier);
            requests.spawn(async move {
                barrier.wait().await;
                hub.handle(
                    Reply::Socket(Arc::downgrade(&reply)),
                    "127.0.0.1:30000".parse().expect("source"),
                    "192.0.2.1:50000".parse().expect("dest"),
                    &[sequence],
                    "test",
                )
                .await
            });
        }
        barrier.wait().await;
        while let Some(request) = requests.join_next().await {
            request.expect("task").expect("send");
        }
        // connect_udp returns before the proxy's accept loop has drained its
        // listen backlog. Observe the sockets after that loop gets scheduled.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "first-packet burst opened duplicate proxy UDP sessions"
        );
        hub.stop();
        server.abort();
    }

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
        let mut out = Vec::new();
        DatagramFrame::LengthPrefixed.apply_into(dest, b"hello", &mut out);
        assert_eq!(out, b"\x00\x05hello".to_vec());
        DatagramFrame::Raw.apply_into(dest, b"hello", &mut out);
        assert_eq!(out, b"hello".to_vec());
        DatagramFrame::Socks.apply_into(dest, b"hello", &mut out);
        assert_eq!(&out[..3], &[0, 0, 0]);
        assert_eq!(&out[3..], b"\x01\x0a\x00\x00\x01\x00\x35hello");
    }

    /// A datagram the length describes has to arrive whole and nothing else:
    /// the relay reads exactly that many bytes, so a frame that is one byte
    /// short would eat the next frame's length.
    #[test]
    fn a_length_prefix_covers_its_whole_payload() {
        let dest = "10.0.0.1:53".parse::<SocketAddr>().expect("addr");
        for len in [1usize, 2, 255, 1400, 65_535] {
            let payload = vec![(len % 251) as u8; len];
            let mut framed = Vec::new();
            DatagramFrame::LengthPrefixed.apply_into(dest, &payload, &mut framed);
            assert_eq!(framed.len(), len + 2, "{len}");
            assert_eq!(
                u16::from_be_bytes([framed[0], framed[1]]) as usize,
                len,
                "{len}"
            );
            assert_eq!(&framed[2..], &payload[..], "{len}");
        }
    }

    #[test]
    fn packetaddr_frame_roundtrip() {
        let dest = "1.2.3.4:53".parse::<SocketAddr>().expect("addr");
        let payload = b"dns-packet";
        let mut framed = Vec::new();
        DatagramFrame::PacketAddr.apply_into(dest, payload, &mut framed);
        assert!(framed.len() > 2);
        let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(len, framed.len() - 2);
        let (got_target, got_payload) =
            crate::outbound::packet::take_addr_port(&framed[2..]).expect("take addr port");
        assert_eq!(got_target, Target::Ip(dest));
        assert_eq!(got_payload, payload);
    }
}
