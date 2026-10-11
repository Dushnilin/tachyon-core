//! WireGuard endpoint outbound — initiator-only datapath.
//!
//! One stack task per endpoint owns a `smoltcp` interface over a virtual
//! device; TCP goes through smoltcp, UDP is wrapped into IPv4 packets
//! directly. Handshake/crypto lives in [`noise`]; timers and the transport
//! session follow <https://www.wireguard.com/protocol/> (initiator side).

pub mod awg;
pub(crate) mod awg_masque;
pub(crate) mod awg_quic;
pub mod noise;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as PhyRxToken,
    TxToken as PhyTxToken,
};
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::socket::tcp::{
    RecvError as TcpRecvError, Socket as TcpSock, SocketBuffer as TcpBuffer,
};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::shadowsocks::crypto::decode_base64_std;
use crate::outbound::urltest::parse_duration;

const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_ATTEMPT_COUNT: u32 = 20;
const COOKIE_TTL: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLVE_RETRY: Duration = Duration::from_secs(30);

const DEFAULT_MTU: usize = 1408;
const DEFAULT_PORT: u16 = 51820;
const EPHEMERAL_BASE: u16 = 49152;

const SOCKET_BUF: usize = 65_536;
const SCRATCH_BUF: usize = 16_384;
const CALLER_BUF: usize = 65_536;
const CMD_QUEUE: usize = 256;
const REPLY_QUEUE: usize = 64;
const PENDING_MAX: usize = 512;
const EGRESS_BUF_MAX: usize = 1 << 20;
const MAX_DATAGRAM: usize = 65_535;

/// Endpoint fields accepted by check but not honored by the runtime.
const IGNORED_FIELDS: &[&str] = &[
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "workers",
    "routing_mark",
    "network_strategy",
    "reserved",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "netns",
    "protect_path",
];

fn jitter() -> Duration {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    Duration::from_millis(u16::from_le_bytes(b) as u64 % 333)
}

fn b64_key(value: &str, at: &str) -> anyhow::Result<[u8; 32]> {
    let raw = decode_base64_std(value).map_err(|e| anyhow::anyhow!("{at}: decode key: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{at}: key must be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

/// Persistent keepalive as an inclusive seconds range (`N`, `N-M`); AWG 3.x
/// re-picks from the range every time the timer arms.
fn parse_keepalive(value: Option<&Value>, at: &str) -> anyhow::Result<Option<(u32, u32)>> {
    let parse_part = |part: &str| -> anyhow::Result<u32> {
        part.trim()
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("{at}: invalid persistent_keepalive_interval {part:?}"))
    };
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let secs = n.as_u64().unwrap_or(0);
            Ok((secs > 0).then_some((secs as u32, secs as u32)))
        }
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            let (lo, hi) = match s.split_once('-') {
                Some((a, b)) => (parse_part(a)?, parse_part(b)?),
                None => match parse_part(s) {
                    Ok(v) => (v, v),
                    // Go duration string ("45s"), accepted by the lx.8 option
                    Err(_) => {
                        let d = parse_duration(value, Duration::ZERO, at)?;
                        let v = d.as_secs() as u32;
                        (v, v)
                    }
                },
            };
            let (lo, hi) = (lo.min(hi), lo.max(hi));
            Ok((lo > 0).then_some((lo, hi)))
        }
        Some(_) => anyhow::bail!("{at}: invalid persistent_keepalive_interval"),
    }
}

#[derive(Clone, Debug)]
struct PeerConfig {
    host: String,
    port: u16,
    public_key: [u8; 32],
    pre_shared_key: Option<[u8; 32]>,
    allowed_ips_v4: Vec<(u32, u8)>,
    allowed_ips_v6: Vec<(u128, u8)>,
    keepalive: Option<(u32, u32)>,
}

#[derive(Clone, Debug)]
struct WgConfig {
    tag: String,
    private_key: [u8; 32],
    public_key: [u8; 32],
    listen_port: u16,
    mtu: usize,
    local_cidrs: Vec<IpCidr>,
    local_addr_v4: Option<Ipv4Addr>,
    local_addr_v6: Option<Ipv6Addr>,
    peers: Vec<PeerConfig>,
    udp_timeout: Duration,
    /// AmneziaWG obfuscation; `None` for a plain WireGuard endpoint.
    awg: Option<awg::SharedParams>,
}

/// `UdpOpen` completion: local port + reply stream.
type UdpReply = oneshot::Sender<Result<(u16, mpsc::Receiver<Vec<u8>>), String>>;

enum Cmd {
    TcpConnect {
        id: u32,
        dst: SocketAddr,
        to_caller: mpsc::Sender<Vec<u8>>,
        resp: oneshot::Sender<Result<(), String>>,
    },
    TcpData {
        id: u32,
        bytes: Vec<u8>,
    },
    TcpClose {
        id: u32,
    },
    UdpOpen {
        target: SocketAddr,
        resp: UdpReply,
    },
    UdpSend {
        port: u16,
        bytes: Vec<u8>,
    },
    UdpClose {
        port: u16,
    },
}

#[derive(Debug)]
struct WgShared {
    cmd_tx: mpsc::Sender<Cmd>,
    next_id: AtomicU32,
}

/// WireGuard endpoint outbound (see module docs).
#[derive(Debug)]
pub struct WireGuard {
    cfg: WgConfig,
    shared: AsyncMutex<Option<Arc<WgShared>>>,
}

impl WireGuard {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        if obj.get("system").and_then(Value::as_bool) == Some(true) {
            anyhow::bail!("{at}: system wireguard is not implemented yet");
        }
        let awg = awg::AwgParams::from_obj(obj, at)?.map(Arc::new);
        for f in IGNORED_FIELDS {
            if obj.get(*f).is_some_and(|v| !v.is_null()) {
                logging::warn(format_args!(
                    "wireguard endpoint {at}: {f} is not implemented yet (ignored)"
                ));
            }
        }

        let raw_priv = obj
            .get("private_key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing private key"))?;
        let private_key = b64_key(raw_priv, at)?;
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key))
                .to_bytes();

        let listen_port = obj
            .get("listen_port")
            .and_then(Value::as_u64)
            .map(|v| v as u16)
            .unwrap_or(0);
        let mtu = obj
            .get("mtu")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MTU);

        let mut local_cidrs = Vec::new();
        if let Some(Value::Array(list)) = obj.get("address") {
            for (i, entry) in list.iter().enumerate() {
                let raw = entry
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{at}.address[{i}]: must be a string"))?;
                if let Ok(cidr) = raw.parse::<IpCidr>() {
                    local_cidrs.push(cidr);
                } else if let Ok(ip) = raw.parse::<Ipv4Addr>() {
                    local_cidrs.push(IpCidr::new(IpAddress::from(ip), 32));
                } else if let Ok(ip) = raw.parse::<Ipv6Addr>() {
                    local_cidrs.push(IpCidr::new(IpAddress::from(ip), 128));
                } else {
                    anyhow::bail!("{at}.address[{i}]: invalid address {raw:?}");
                }
            }
        }
        let mut local_addr_v4 = None;
        let mut local_addr_v6 = None;
        for c in &local_cidrs {
            match c.address() {
                IpAddress::Ipv4(ip) => {
                    if local_addr_v4.is_none() {
                        local_addr_v4 = Some(ip);
                    }
                }
                IpAddress::Ipv6(ip) => {
                    if local_addr_v6.is_none() {
                        local_addr_v6 = Some(ip);
                    }
                }
            }
        }
        if local_addr_v4.is_none() && local_addr_v6.is_none() {
            anyhow::bail!("{at}: missing ip address");
        }

        let mut peers = Vec::new();
        if let Some(value) = obj.get("peers")
            && !matches!(value, Value::Null | Value::Object(_))
        {
            let list = value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("{at}.peers: must be an array"))?;
            for (j, entry) in list.iter().enumerate() {
                if entry.is_null()
                    || entry.as_str().is_some_and(str::is_empty)
                    || entry.as_f64() == Some(0.0)
                {
                    continue;
                }
                let peer_at = format!("{at}.peers[{j}]");
                let peer = entry
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("{peer_at}: must be an object"))?;
                let host = peer
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let port = peer
                    .get("port")
                    .and_then(Value::as_u64)
                    .map(|v| v as u16)
                    .unwrap_or(DEFAULT_PORT);
                let raw_pub = peer
                    .get("public_key")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("{peer_at}: missing public key"))?;
                let public_key = b64_key(raw_pub, &peer_at)?;
                let pre_shared_key = match peer.get("pre_shared_key") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) if s.is_empty() => None,
                    Some(Value::String(s)) => Some(b64_key(s, &peer_at)?),
                    Some(_) => anyhow::bail!("{peer_at}.pre_shared_key: must be a string"),
                };
                let mut allowed_ips_v4 = Vec::new();
                let mut allowed_ips_v6 = Vec::new();
                if let Some(Value::Array(list)) = peer.get("allowed_ips") {
                    for (k, entry) in list.iter().enumerate() {
                        let raw = entry.as_str().ok_or_else(|| {
                            anyhow::anyhow!("{peer_at}.allowed_ips[{k}]: must be a string")
                        })?;
                        if let Ok(cidr) = raw.parse::<IpCidr>() {
                            match cidr.address() {
                                IpAddress::Ipv4(ip) => {
                                    let net = u32::from(ip);
                                    let bits = cidr.prefix_len();
                                    let net = if bits == 0 {
                                        0
                                    } else {
                                        net & (u32::MAX << (32 - bits))
                                    };
                                    allowed_ips_v4.push((net, bits));
                                }
                                IpAddress::Ipv6(ip) => {
                                    let net = u128::from(ip);
                                    let bits = cidr.prefix_len();
                                    let net = if bits == 0 {
                                        0
                                    } else {
                                        net & (u128::MAX << (128 - bits))
                                    };
                                    allowed_ips_v6.push((net, bits));
                                }
                            }
                        } else if let Ok(ip) = raw.parse::<Ipv4Addr>() {
                            allowed_ips_v4.push((u32::from(ip), 32));
                        } else if let Ok(ip) = raw.parse::<Ipv6Addr>() {
                            allowed_ips_v6.push((u128::from(ip), 128));
                        } else {
                            anyhow::bail!("{peer_at}.allowed_ips[{k}]: invalid prefix {raw:?}");
                        }
                    }
                }
                if allowed_ips_v4.is_empty() && allowed_ips_v6.is_empty() {
                    anyhow::bail!("{peer_at}: missing allowed ips");
                }
                let keepalive = parse_keepalive(
                    peer.get("persistent_keepalive_interval"),
                    &format!("{peer_at}.persistent_keepalive_interval"),
                )?;
                peers.push(PeerConfig {
                    host,
                    port,
                    public_key,
                    pre_shared_key,
                    allowed_ips_v4,
                    allowed_ips_v6,
                    keepalive,
                });
            }
        }

        let udp_timeout = parse_duration(obj.get("udp_timeout"), DEFAULT_UDP_TIMEOUT, at)?;

        Ok(Self {
            cfg: WgConfig {
                tag: at.to_string(),
                private_key,
                public_key,
                listen_port,
                mtu,
                local_cidrs,
                local_addr_v4,
                local_addr_v6,
                peers,
                udp_timeout,
                awg,
            },
            shared: AsyncMutex::new(None),
        })
    }

    async fn shared(&self) -> io::Result<Arc<WgShared>> {
        let mut guard = self.shared.lock().await;
        if let Some(shared) = guard.as_ref() {
            return Ok(Arc::clone(shared));
        }
        let sock = UdpSocket::bind(("0.0.0.0", self.cfg.listen_port))
            .await
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "wireguard[{}]: bind udp port {}: {e}",
                        self.cfg.tag, self.cfg.listen_port
                    ),
                )
            })?;
        let _ = socket2::SockRef::from(&sock)
            .set_recv_buffer_size(crate::outbound::quic::UDP_SOCKET_BUFFER);
        let _ = socket2::SockRef::from(&sock)
            .set_send_buffer_size(crate::outbound::quic::UDP_SOCKET_BUFFER);
        let sock_v6 = match UdpSocket::bind(("[::]", self.cfg.listen_port)).await {
            Ok(s) => {
                let _ = socket2::SockRef::from(&s)
                    .set_recv_buffer_size(crate::outbound::quic::UDP_SOCKET_BUFFER);
                let _ = socket2::SockRef::from(&s)
                    .set_send_buffer_size(crate::outbound::quic::UDP_SOCKET_BUFFER);
                Some(Arc::new(s))
            }
            Err(_) => None,
        };
        if self.cfg.listen_port > 0 {
            logging::info(format_args!(
                "wireguard[{}]: server listening on udp 0.0.0.0:{}",
                self.cfg.tag, self.cfg.listen_port
            ));
        }
        let (tx, rx) = mpsc::channel(CMD_QUEUE);
        let shared = Arc::new(WgShared {
            cmd_tx: tx,
            next_id: AtomicU32::new(1),
        });
        let cfg = Arc::new(self.cfg.clone());
        tokio::spawn(async move {
            if let Err(e) = run(cfg, Arc::new(sock), sock_v6, rx).await {
                logging::error(format_args!("wireguard stack exited: {e}"));
            }
        });
        *guard = Some(Arc::clone(&shared));
        Ok(shared)
    }

    pub async fn start_listen(&self) -> io::Result<()> {
        if self.cfg.listen_port > 0 {
            let _ = self.shared().await?;
        }
        Ok(())
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let dst = resolve_target(target).await?;
        let shared = self.shared().await?;
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (local, remote) = tokio::io::duplex(CALLER_BUF);
        let (caller_read, caller_write) = tokio::io::split(local);
        let (to_caller_tx, to_caller_rx) = mpsc::channel(REPLY_QUEUE);
        let (resp_tx, resp_rx) = oneshot::channel();

        shared
            .cmd_tx
            .send(Cmd::TcpConnect {
                id,
                dst,
                to_caller: to_caller_tx,
                resp: resp_tx,
            })
            .await
            .map_err(|_| io::Error::other("wireguard: stack task stopped"))?;

        // caller → stack: forward reads as TCP data chunks.
        let cmd_tx = Arc::clone(&shared).cmd_tx.clone();
        tokio::spawn(async move {
            let mut read = caller_read;
            let mut buf = vec![0u8; SCRATCH_BUF];
            loop {
                match read.read(&mut buf).await {
                    Ok(0) => {
                        let _ = cmd_tx.send(Cmd::TcpClose { id }).await;
                        break;
                    }
                    Ok(n) => {
                        if cmd_tx
                            .send(Cmd::TcpData {
                                id,
                                bytes: buf[..n].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = cmd_tx.send(Cmd::TcpClose { id }).await;
                        break;
                    }
                }
            }
        });

        // stack → caller: pump replies with per-connection backpressure.
        tokio::spawn(async move {
            let mut write = caller_write;
            let mut replies = to_caller_rx;
            while let Some(bytes) = replies.recv().await {
                if write.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = write.flush().await;
            }
        });

        match tokio::time::timeout(CONNECT_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(remote)),
            Ok(Ok(Err(e))) => Err(io::Error::other(format!("wireguard: {e}"))),
            Ok(Err(_)) => Err(io::Error::other("wireguard: stack task stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "wireguard: connect timeout",
            )),
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        let dst = resolve_target(target).await?;
        let shared = self.shared().await?;
        let (local, peer) = udp_loopback_pair().await?;
        let (resp_tx, resp_rx) = oneshot::channel();
        shared
            .cmd_tx
            .send(Cmd::UdpOpen {
                target: dst,
                resp: resp_tx,
            })
            .await
            .map_err(|_| io::Error::other("wireguard: stack task stopped"))?;
        let (port, mut replies) = match tokio::time::timeout(Duration::from_secs(10), resp_rx).await
        {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => return Err(io::Error::other(format!("wireguard: {e}"))),
            Ok(Err(_)) => return Err(io::Error::other("wireguard: stack task stopped")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "wireguard: udp session timeout",
                ));
            }
        };

        let peer = Arc::new(peer);
        let cmd_tx = shared.cmd_tx.clone();
        let udp_timeout = self.cfg.udp_timeout;

        // replies: stack → session channel → loopback peer socket.
        {
            let peer = Arc::clone(&peer);
            tokio::spawn(async move {
                while let Some(bytes) = replies.recv().await {
                    if peer.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
        }

        // sends: loopback peer socket → stack (mirrors the hysteria2 bridge).
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok(Ok(n)) = tokio::time::timeout(udp_timeout, peer.recv(&mut buf)).await {
                if cmd_tx
                    .send(Cmd::UdpSend {
                        port,
                        bytes: buf[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = cmd_tx.send(Cmd::UdpClose { port }).await;
        });

        Ok(local)
    }
}

struct TcpConn {
    handle: SocketHandle,
    #[allow(dead_code)]
    dst: SocketAddr,
    to_caller: mpsc::Sender<Vec<u8>>,
    resp: Option<oneshot::Sender<Result<(), String>>>,
    from_caller: VecDeque<Vec<u8>>,
    stash: Option<Vec<u8>>,
    created: Instant,
    caller_eof: bool,
}

struct UdpSess {
    target: SocketAddr,
    peer: usize,
    to_caller: mpsc::Sender<Vec<u8>>,
}

struct HsRuntime {
    hs: noise::Handshake,
    attempt: u32,
    started: Instant,
    retry_at: Instant,
}

struct PeerRt {
    endpoint: PeerConfig,
    /// AWG 3.x UDP window: the largest datagram seen on this peer in either
    /// direction; bounds content-padding additions and random trailers.
    udp_window: u32,
    resolved: Option<SocketAddr>,
    resolve_at: Option<Instant>,
    session: Option<noise::Session>,
    session_since: Option<Instant>,
    hs: Option<HsRuntime>,
    cookie: Option<([u8; 16], Instant)>,
    pending: VecDeque<Vec<u8>>,
    last_recv: Option<Instant>,
    last_sent: Option<Instant>,
    flush: bool,
    kick: bool,
}

impl PeerRt {
    fn new(endpoint: PeerConfig) -> Self {
        Self {
            endpoint,
            udp_window: awg::DEFAULT_UDP_WINDOW,
            resolved: None,
            resolve_at: None,
            session: None,
            session_since: None,
            hs: None,
            cookie: None,
            pending: VecDeque::new(),
            last_recv: None,
            last_sent: None,
            flush: false,
            kick: false,
        }
    }
}

struct WgDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    /// Recycled tx buffers: the pool behind `WgTxToken::consume`, so the
    /// per-packet `vec![0; len]` stops hitting the allocator on every IP
    /// packet the stack hands us.
    free: Vec<Vec<u8>>,
    mtu: usize,
}

impl WgDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            free: Vec::new(),
            mtu,
        }
    }
}

struct WgRxToken {
    buffer: Vec<u8>,
}

impl PhyRxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct WgTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    free: &'a mut Vec<Vec<u8>>,
}

impl PhyTxToken for WgTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = match self.free.pop() {
            Some(mut b) => {
                b.resize(len, 0);
                b
            }
            None => vec![0; len],
        };
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for WgDevice {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(move |buffer| {
            let rx = WgRxToken { buffer };
            let tx = WgTxToken {
                queue: &mut self.tx,
                free: &mut self.free,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken {
            queue: &mut self.tx,
            free: &mut self.free,
        })
    }
}

/// Longest-prefix match over the peer `allowed_ips_v4` tables.
fn lpm_v4(peers: &[PeerRt], ip: Ipv4Addr) -> Option<usize> {
    let addr = u32::from(ip);
    let mut best: Option<(u8, usize)> = None;
    for (i, peer) in peers.iter().enumerate() {
        for &(net, bits) in &peer.endpoint.allowed_ips_v4 {
            let hit = bits == 0 || (addr >> (32 - bits as u32)) == (net >> (32 - bits as u32));
            if hit && best.is_none_or(|(b, _)| bits > b) {
                best = Some((bits, i));
            }
        }
    }
    best.map(|(_, i)| i)
}

/// Longest-prefix match over the peer `allowed_ips_v6` tables.
fn lpm_v6(peers: &[PeerRt], ip: Ipv6Addr) -> Option<usize> {
    let addr = u128::from(ip);
    let mut best: Option<(u8, usize)> = None;
    for (i, peer) in peers.iter().enumerate() {
        for &(net, bits) in &peer.endpoint.allowed_ips_v6 {
            let hit = bits == 0 || (addr >> (128 - bits as u32)) == (net >> (128 - bits as u32));
            if hit && best.is_none_or(|(b, _)| bits > b) {
                best = Some((bits, i));
            }
        }
    }
    best.map(|(_, i)| i)
}

fn lpm_ip(peers: &[PeerRt], ip: IpAddr) -> Option<usize> {
    match ip {
        IpAddr::V4(v4) => lpm_v4(peers, v4),
        IpAddr::V6(v6) => lpm_v6(peers, v6),
    }
}

struct Stack {
    cfg: Arc<WgConfig>,
    sock: Arc<UdpSocket>,
    sock_v6: Option<Arc<UdpSocket>>,
    device: WgDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    peers: Vec<PeerRt>,
    index_peer: HashMap<u32, usize>,
    tcp: HashMap<u32, TcpConn>,
    udp: HashMap<u16, UdpSess>,
    next_port: u16,
    scratch: Vec<u8>,
}

impl Stack {
    fn lpm(&self, ip: IpAddr) -> Option<usize> {
        lpm_ip(&self.peers, ip)
    }

    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == u16::MAX {
            EPHEMERAL_BASE
        } else {
            port + 1
        };
        port
    }

    fn send_raw(&self, pi: usize, bytes: &[u8]) {
        let Some(addr) = self.peers[pi].resolved else {
            return;
        };
        let sock = match addr {
            SocketAddr::V6(_) => match &self.sock_v6 {
                Some(s) => s,
                None => {
                    logging::debug(format_args!(
                        "wireguard[{}]: no ipv6 socket for {addr}",
                        self.cfg.tag
                    ));
                    return;
                }
            },
            SocketAddr::V4(_) => &self.sock,
        };
        if let Err(e) = sock.try_send_to(bytes, addr)
            && e.kind() != io::ErrorKind::WouldBlock
        {
            logging::debug(format_args!("wireguard[{}]: udp send: {e}", self.cfg.tag));
        }
    }

    /// Send a handshake initiation with AWG dressing: CPS junk datagrams
    /// (i1–i5), junk packets (jc of jmin..=jmax bytes) and the s1 random
    /// prefix, mirroring `SendHandshakeInitiation` in the reference device.
    fn send_handshake_init(&self, pi: usize, init: &[u8]) {
        let Some(params) = self.cfg.awg.as_ref() else {
            self.send_raw(pi, init);
            return;
        };
        for chain in params.ipackets.iter().flatten() {
            let pkt = awg::render_chain(chain);
            if !pkt.is_empty() {
                self.send_raw(pi, &pkt);
            }
        }
        for _ in 0..params.junk_count {
            let n = awg::junk_size(params.junk_min, params.junk_max);
            if n == 0 {
                continue;
            }
            let mut buf = vec![0u8; n];
            awg::fill_random(&mut buf);
            self.send_raw(pi, &buf);
        }
        let pad = params.padding(awg::INIT);
        let window = self.peers[pi].udp_window;
        let mut pkt = vec![0u8; pad + init.len()];
        awg::fill_random(&mut pkt[..pad]);
        pkt[pad..].copy_from_slice(init);
        if params.random_trailers {
            let at = pkt.len();
            pkt.resize(at + awg::trailer_len(window, pad + init.len()), 0);
            awg::fill_random(&mut pkt[at..]);
        }
        if let Some(key) = &params.header_protection {
            // The keystream nonce is the first 12 bytes of the datagram —
            // the s1 random prefix; only the message itself is masked.
            let nonce = pkt[..12].to_vec();
            awg::mask_header(key, &nonce, &mut pkt[pad..pad + init.len()]);
        }
        self.send_raw(pi, &pkt);
    }

    fn send_handshake_resp(&self, pi: usize, resp: &[u8], src: SocketAddr) {
        let sock = match src {
            SocketAddr::V6(_) => self.sock_v6.as_ref(),
            SocketAddr::V4(_) => Some(&self.sock),
        };
        let Some(params) = self.cfg.awg.as_ref() else {
            if let Some(s) = sock {
                let _ = s.try_send_to(resp, src);
            }
            return;
        };
        let pad = params.padding(awg::RESPONSE);
        let window = self.peers[pi].udp_window;
        let mut pkt = vec![0u8; pad + resp.len()];
        awg::fill_random(&mut pkt[..pad]);
        pkt[pad..].copy_from_slice(resp);
        if params.random_trailers {
            let at = pkt.len();
            pkt.resize(at + awg::trailer_len(window, pad + resp.len()), 0);
            awg::fill_random(&mut pkt[at..]);
        }
        if let Some(key) = &params.header_protection {
            let nonce = pkt[..12].to_vec();
            awg::mask_header(key, &nonce, &mut pkt[pad..pad + resp.len()]);
        }
        if let Some(s) = sock {
            let _ = s.try_send_to(&pkt, src);
        }
    }

    /// Seal one transport datagram with AWG 3.x dressing: content padding or
    /// a random trailer inside the AEAD, the s4 random prefix in front, and
    /// the header masked by the header-protection keystream.
    fn seal_transport(&mut self, pi: usize, pkt: &[u8]) -> Option<Vec<u8>> {
        let params = self.cfg.awg.clone();
        let pad_len = params.as_ref().map(|a| {
            awg::transport_padding(
                a,
                self.peers[pi].udp_window,
                pkt.len(),
                a.padding(awg::TRANSPORT),
            )
        });
        let session = self.peers[pi].session.as_mut()?;
        let msg = match (&params, pad_len) {
            (None, _) => session.seal(pkt)?,
            (Some(_), Some(pad_len)) => session.seal_raw(pkt, pkt.len() + pad_len)?,
            (Some(_), None) => return None,
        };
        let mut out = msg;
        if let Some(a) = params.as_ref() {
            let s4 = a.padding(awg::TRANSPORT);
            if s4 > 0 {
                let mut dressed = vec![0u8; s4 + out.len()];
                awg::fill_random(&mut dressed[..s4]);
                dressed[s4..].copy_from_slice(&out);
                out = dressed;
            }
            if let Some(key) = &a.header_protection {
                let nonce = out[..12].to_vec();
                awg::mask_header(key, &nonce, &mut out[s4..s4 + 16]);
            }
            self.peers[pi].udp_window = self.peers[pi].udp_window.max(out.len() as u32);
        }
        Some(out)
    }

    /// Queue an IP packet to a peer: seal via the session or buffer until the
    /// handshake completes. Returns the packet back when it was sent and the
    /// caller may recycle it.
    fn xmit_to_peer(&mut self, pi: usize, pkt: Vec<u8>) -> Option<Vec<u8>> {
        let sealed = self.seal_transport(pi, &pkt);
        match sealed {
            Some(msg) => {
                self.send_raw(pi, &msg);
                self.peers[pi].last_sent = Some(Instant::now());
                Some(pkt)
            }
            None => {
                // Session missing or counter exhausted — drop the session and
                // queue for the next handshake.
                if self.peers[pi].session.is_some() {
                    self.peers[pi].session = None;
                    self.peers[pi].session_since = None;
                }
                if self.peers[pi].pending.len() >= PENDING_MAX {
                    self.peers[pi].pending.pop_front();
                }
                self.peers[pi].pending.push_back(pkt);
                self.peers[pi].kick = true;
                None
            }
        }
    }

    async fn resolve_peer(&mut self, pi: usize) {
        if self.peers[pi].endpoint.host.is_empty() {
            return;
        }
        if self.peers[pi]
            .resolve_at
            .is_some_and(|t| Instant::now() < t)
        {
            return;
        }
        let host = self.peers[pi].endpoint.host.clone();
        let port = self.peers[pi].endpoint.port;
        match resolve_host(&host, port).await {
            Ok(addr) => {
                self.peers[pi].resolved = Some(addr);
            }
            Err(e) => {
                logging::warn(format_args!(
                    "wireguard[{}]: resolve peer {host}:{port}: {e}",
                    self.cfg.tag
                ));
                self.peers[pi].resolve_at = Some(Instant::now() + RESOLVE_RETRY);
            }
        }
    }

    fn start_hs(&mut self, pi: usize) -> bool {
        if self.peers[pi].resolved.is_none() {
            return false;
        }
        let now = Instant::now();
        let cookie = self.peers[pi]
            .cookie
            .filter(|(_, exp)| now < *exp)
            .map(|(c, _)| c);
        let peer_pub = self.peers[pi].endpoint.public_key;
        let init_word = noise::gen_type(
            self.cfg
                .awg
                .as_ref()
                .map(|a| a.header(awg::INIT))
                .unwrap_or(noise::HDR_INIT),
        );
        let hs = noise::build_initiation(
            &self.cfg.private_key,
            &self.cfg.public_key,
            &peer_pub,
            cookie.as_ref(),
            &noise::tai64n_now(),
            init_word,
        );
        self.send_handshake_init(pi, hs.initiation());
        logging::debug(format_args!(
            "wireguard[{}]: initiation sent idx={} peer {pi}",
            self.cfg.tag, hs.sender_index
        ));
        self.index_peer.insert(hs.sender_index, pi);
        let retry_at = now + REKEY_TIMEOUT + jitter();
        self.peers[pi].hs = Some(HsRuntime {
            attempt: 1,
            started: now,
            retry_at,
            hs,
        });
        self.peers[pi].kick = false;
        true
    }

    fn process_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::TcpConnect {
                id,
                dst,
                to_caller,
                resp,
            } => {
                let Some(pi) = self.lpm(dst.ip()) else {
                    let _ = resp.send(Err(format!("no wireguard peer for {dst}")));
                    return;
                };
                let port = self.alloc_port();
                let mut socket = TcpSock::new(
                    TcpBuffer::new(vec![0; SOCKET_BUF]),
                    TcpBuffer::new(vec![0; SOCKET_BUF]),
                );
                socket.set_timeout(Some(SmolDuration::from_millis(
                    CONNECT_TIMEOUT.as_millis() as u64
                )));
                let smol_addr = match dst.ip() {
                    IpAddr::V4(v4) => IpAddress::Ipv4(v4),
                    IpAddr::V6(v6) => IpAddress::Ipv6(v6),
                };
                if let Err(e) = socket.connect(self.iface.context(), (smol_addr, dst.port()), port)
                {
                    let _ = resp.send(Err(format!("wireguard connect: {e:?}")));
                    return;
                }
                let handle = self.sockets.add(socket);
                self.tcp.insert(
                    id,
                    TcpConn {
                        handle,
                        dst,
                        to_caller,
                        resp: Some(resp),
                        from_caller: VecDeque::new(),
                        stash: None,
                        created: Instant::now(),
                        caller_eof: false,
                    },
                );
                self.peers[pi].kick = true;
            }
            Cmd::TcpData { id, bytes } => {
                let overflow = self.tcp.get(&id).is_some_and(|c| {
                    c.from_caller.iter().map(|b| b.len()).sum::<usize>() + bytes.len()
                        > EGRESS_BUF_MAX
                });
                if overflow {
                    if let Some(c) = self.tcp.remove(&id) {
                        self.sockets.remove(c.handle);
                        if let Some(resp) = c.resp {
                            let _ = resp.send(Err("outbound buffer overflow".into()));
                        }
                        drop(c.to_caller);
                    }
                    return;
                }
                if let Some(c) = self.tcp.get_mut(&id) {
                    c.from_caller.push_back(bytes);
                }
            }
            Cmd::TcpClose { id } => {
                if let Some(c) = self.tcp.get_mut(&id) {
                    c.caller_eof = true;
                    c.from_caller.clear();
                }
            }
            Cmd::UdpOpen { target, resp } => {
                let Some(pi) = self.lpm(target.ip()) else {
                    let _ = resp.send(Err(format!("no wireguard peer for {target}")));
                    return;
                };
                let port = self.alloc_port();
                let (tx, rx) = mpsc::channel(REPLY_QUEUE);
                self.udp.insert(
                    port,
                    UdpSess {
                        target,
                        peer: pi,
                        to_caller: tx,
                    },
                );
                self.peers[pi].kick = true;
                let _ = resp.send(Ok((port, rx)));
            }
            Cmd::UdpSend { port, bytes } => {
                let Some(sess) = self.udp.get(&port) else {
                    return;
                };
                let pi = sess.peer;
                let dport = sess.target.port();
                let pkt = match sess.target.ip() {
                    IpAddr::V4(target_ip) => {
                        let Some(src) = self.cfg.local_addr_v4 else {
                            return;
                        };
                        build_ipv4_udp(src, target_ip, port, dport, &bytes)
                    }
                    IpAddr::V6(target_ip) => {
                        let Some(src) = self.cfg.local_addr_v6 else {
                            return;
                        };
                        build_ipv6_udp(src, target_ip, port, dport, &bytes)
                    }
                };
                let _ = self.xmit_to_peer(pi, pkt);
            }
            Cmd::UdpClose { port } => {
                self.udp.remove(&port);
            }
        }
    }

    fn process_inbound(&mut self, buf: &[u8], src: SocketAddr) {
        // AWG-aware classification: the message may carry an s-padding
        // prefix, a masked magic-header type word and a random trailer.
        let known_index = |idx: u32| self.index_peer.contains_key(&idx);
        let Some((msg_type, padding)) = awg::demux(self.cfg.awg.as_deref(), buf, &known_index)
        else {
            return;
        };
        // Header protection unmasks the canonical header in place, so only
        // that path takes an owned copy; plain wireguard classifies and
        // decrypts straight out of the recv buffer.
        let mut owned: Option<Vec<u8>> = None;
        if let Some(a) = self.cfg.awg.as_ref()
            && let Some(key) = &a.header_protection
        {
            let mut msg = buf[padding..].to_vec();
            let canon = match msg_type {
                noise::MSG_INITIATION => noise::INITIATION_LEN,
                noise::MSG_RESPONSE => noise::RESPONSE_LEN,
                noise::MSG_COOKIE_REPLY => noise::COOKIE_REPLY_LEN,
                _ => noise::TRANSPORT_HEADER_LEN,
            };
            let end = canon.min(msg.len());
            awg::mask_header(key, &buf[..12], &mut msg[..end]);
            owned = Some(msg);
        }
        let mut msg: &[u8] = owned.as_deref().unwrap_or(&buf[padding..]);
        if msg_type != noise::MSG_TRANSPORT {
            // Fixed-size handshake kinds: drop the AWG 3.x random trailer.
            let canon = match msg_type {
                noise::MSG_INITIATION => noise::INITIATION_LEN,
                noise::MSG_RESPONSE => noise::RESPONSE_LEN,
                _ => noise::COOKIE_REPLY_LEN,
            };
            msg = &msg[..canon.min(msg.len())];
        }
        if msg.len() < 8 {
            return;
        }
        let recv_idx = u32::from_le_bytes(msg[4..8].try_into().expect("4 bytes"));
        if msg_type == noise::MSG_TRANSPORT
            && let Some(&pi) = self.index_peer.get(&recv_idx)
        {
            self.peers[pi].udp_window = self.peers[pi].udp_window.max(buf.len() as u32);
        }
        logging::debug(format_args!(
            "wireguard[{}]: recv type={msg_type} len={} idx={recv_idx} src={src}",
            self.cfg.tag,
            msg.len()
        ));
        match msg_type {
            noise::MSG_INITIATION => {
                self.on_initiation(msg, src);
            }
            // Handshake response layout: [4..8] = sender (responder),
            // [8..12] = receiver (our initiation sender index).
            noise::MSG_RESPONSE => {
                if msg.len() < 12 {
                    return;
                }
                let receiver = u32::from_le_bytes(msg[8..12].try_into().expect("4 bytes"));
                self.on_response(msg, receiver, src);
            }
            noise::MSG_COOKIE_REPLY => self.on_cookie(msg, recv_idx),
            noise::MSG_TRANSPORT => self.on_transport(msg, recv_idx, src),
            _ => {}
        }
    }

    fn on_initiation(&mut self, msg: &[u8], src: SocketAddr) {
        let Ok(init_res) =
            noise::process_initiation(&self.cfg.private_key, &self.cfg.public_key, msg)
        else {
            return;
        };
        let Some(pi) = self
            .peers
            .iter()
            .position(|p| p.endpoint.public_key == init_res.sender_static_pub)
        else {
            logging::debug(format_args!(
                "wireguard[{}]: handshake initiation from unknown peer",
                self.cfg.tag
            ));
            return;
        };
        let psk = self.peers[pi].endpoint.pre_shared_key;
        let resp_word = noise::gen_type(
            self.cfg
                .awg
                .as_ref()
                .map(|a| a.header(awg::RESPONSE))
                .unwrap_or(noise::HDR_RESPONSE),
        );
        let (resp_msg, mut session) =
            noise::build_response(&init_res, &self.cfg.private_key, psk.as_ref(), resp_word);
        if let Some(params) = self.cfg.awg.as_ref() {
            session.set_awg_transport(params.header(awg::TRANSPORT));
        }
        logging::debug(format_args!(
            "wireguard[{}]: handshake initiation accepted (peer {pi}) from {src}",
            self.cfg.tag
        ));
        self.peers[pi].resolved = Some(src);
        self.index_peer.insert(session.local_index, pi);
        self.peers[pi].session = Some(session);
        self.peers[pi].session_since = Some(Instant::now());
        self.peers[pi].last_recv = Some(Instant::now());
        self.peers[pi].hs = None;
        self.send_handshake_resp(pi, &resp_msg, src);
        self.peers[pi].last_sent = Some(Instant::now());
        self.peers[pi].flush = true;
    }

    fn on_response(&mut self, msg: &[u8], recv_idx: u32, src: SocketAddr) {
        let Some(&pi) = self.index_peer.get(&recv_idx) else {
            logging::debug(format_args!(
                "wireguard[{}]: response for unknown index {recv_idx} (known: {:?})",
                self.cfg.tag,
                self.index_peer.keys().collect::<Vec<_>>()
            ));
            return;
        };
        let Some(hsrt) = self.peers[pi].hs.take() else {
            return;
        };
        let psk = self.peers[pi].endpoint.pre_shared_key;
        match noise::process_response(&hsrt.hs, msg, &self.cfg.public_key, psk.as_ref()) {
            Ok(mut session) => {
                if let Some(params) = self.cfg.awg.as_ref() {
                    session.set_awg_transport(params.header(awg::TRANSPORT));
                }
                logging::debug(format_args!(
                    "wireguard[{}]: handshake complete (peer {pi})",
                    self.cfg.tag
                ));
                self.peers[pi].resolved = Some(src);
                self.index_peer.insert(session.local_index, pi);
                self.peers[pi].session = Some(session);
                self.peers[pi].session_since = Some(Instant::now());
                self.peers[pi].flush = true;
                self.peers[pi].kick = false;
            }
            Err(e) => {
                logging::debug(format_args!(
                    "wireguard[{}]: handshake response rejected: {e}",
                    self.cfg.tag
                ));
                // Keep the initiation: it is retransmitted until the
                // handshake times out, like wireguard-go does.
                self.peers[pi].hs = Some(hsrt);
                self.peers[pi].kick = true;
            }
        }
    }

    fn on_cookie(&mut self, msg: &[u8], recv_idx: u32) {
        if self.cfg.awg.as_ref().is_some_and(|a| a.disable_cookies) {
            return;
        }
        let Some(&pi) = self.index_peer.get(&recv_idx) else {
            return;
        };
        let Some(mut hsrt) = self.peers[pi].hs.take() else {
            return;
        };
        let peer_pub = self.peers[pi].endpoint.public_key;
        match noise::decrypt_cookie(msg, &peer_pub, &hsrt.hs.mac1(), recv_idx) {
            Ok(cookie) => {
                hsrt.hs.set_cookie(&cookie);
                self.send_handshake_init(pi, hsrt.hs.initiation());
                let now = Instant::now();
                hsrt.attempt += 1;
                hsrt.retry_at = now + REKEY_TIMEOUT + jitter();
                self.peers[pi].cookie = Some((cookie, now + COOKIE_TTL));
                self.peers[pi].hs = Some(hsrt);
            }
            Err(e) => {
                logging::debug(format_args!(
                    "wireguard[{}]: cookie reply rejected: {e}",
                    self.cfg.tag
                ));
                self.peers[pi].hs = Some(hsrt);
                self.peers[pi].kick = true;
            }
        }
    }

    fn on_transport(&mut self, msg: &[u8], recv_idx: u32, src: SocketAddr) {
        let Some(&pi) = self.index_peer.get(&recv_idx) else {
            return;
        };
        // Decrypt into a recycled buffer: the plaintext either leaves for the
        // caller channel or goes into device.rx, so a per-packet malloc here
        // would be pure churn — the pool behind device.free is the same one
        // the tx path refills.
        let mut plain = self.device.free.pop().unwrap_or_default();
        let opened = self.peers[pi]
            .session
            .as_mut()
            .is_some_and(|s| s.open_into(msg, &mut plain));
        if !opened {
            self.recycle(plain);
            return;
        }
        self.peers[pi].last_recv = Some(Instant::now());
        self.peers[pi].resolved = Some(src);
        if plain.is_empty() {
            return; // keepalive
        }
        let Some((src_ip, dst, proto, hdr_len)) = ip_info(&plain) else {
            self.recycle(plain);
            return;
        };
        let allowed = match src_ip {
            IpAddr::V4(v4) => {
                let src_u32 = u32::from(v4);
                self.peers[pi]
                    .endpoint
                    .allowed_ips_v4
                    .iter()
                    .any(|&(net, bits)| {
                        bits == 0 || (src_u32 >> (32 - bits as u32)) == (net >> (32 - bits as u32))
                    })
            }
            IpAddr::V6(v6) => {
                let src_u128 = u128::from(v6);
                self.peers[pi]
                    .endpoint
                    .allowed_ips_v6
                    .iter()
                    .any(|&(net, bits)| {
                        bits == 0
                            || (src_u128 >> (128 - bits as u32)) == (net >> (128 - bits as u32))
                    })
            }
        };
        if !allowed {
            logging::debug(format_args!(
                "wireguard[{}]: cryptokey routing dropped packet with src {src_ip} from peer {pi}",
                self.cfg.tag
            ));
            self.recycle(plain);
            return;
        }
        let is_local = match dst {
            IpAddr::V4(v4) => self.cfg.local_addr_v4 == Some(v4),
            IpAddr::V6(v6) => self.cfg.local_addr_v6 == Some(v6),
        };
        if !is_local {
            if let Some(dest_pi) = self.lpm(dst)
                && dest_pi != pi
            {
                let _ = self.xmit_to_peer(dest_pi, plain);
                return;
            }
            self.recycle(plain);
            return;
        }
        if proto == 17 && plain.len() >= hdr_len + 8 {
            let sport = u16::from_be_bytes([plain[hdr_len], plain[hdr_len + 1]]);
            let dport = u16::from_be_bytes([plain[hdr_len + 2], plain[hdr_len + 3]]);
            let sender = match self.udp.get(&dport) {
                Some(sess)
                    if sess.target.ip() == src_ip
                        && (sess.target.port() == sport || sess.target.port() == 0) =>
                {
                    Some(sess.to_caller.clone())
                }
                _ => None,
            };
            if let Some(sender) = sender {
                let out = plain[hdr_len + 8..].to_vec();
                self.recycle(plain);
                let _ = sender.try_send(out);
                return;
            }
        }
        self.device.rx.push_back(plain);
    }

    /// Return a buffer to the pool, capped like the tx path's refill.
    fn recycle(&mut self, buf: Vec<u8>) {
        if self.device.free.len() < 64 {
            self.device.free.push(buf);
        }
    }

    async fn flush_device_tx(&mut self) {
        while let Some(pkt) = self.device.tx.pop_front() {
            let pkt = match ip_dst(&pkt).and_then(|dst| self.lpm(dst)) {
                Some(pi) => self.xmit_to_peer(pi, pkt),
                None => Some(pkt),
            };
            if let Some(pkt) = pkt
                && self.device.free.len() < 64
            {
                self.device.free.push(pkt);
            }
        }
    }

    fn maintain_tcp(&mut self) {
        let ids: Vec<u32> = self.tcp.keys().copied().collect();
        for id in ids {
            let Some(mut conn) = self.tcp.remove(&id) else {
                continue;
            };
            let mut rbuf = std::mem::take(&mut self.scratch);
            let mut remote_closed = false;
            let mut caller_gone = false;
            let state = {
                let sock = self.sockets.get_mut::<TcpSock<'static>>(conn.handle);

                while let Some(front) = conn.from_caller.front_mut() {
                    match sock.send_slice(front) {
                        Ok(0) => break,
                        Ok(n) if n >= front.len() => {
                            conn.from_caller.pop_front();
                        }
                        Ok(n) => {
                            let rest = front.split_off(n);
                            *front = rest;
                        }
                        Err(_) => {
                            conn.from_caller.clear();
                            break;
                        }
                    }
                }

                if conn.stash.is_none() {
                    loop {
                        match sock.recv_slice(&mut rbuf) {
                            Ok(0) => break,
                            Ok(n) => match conn.to_caller.try_send(rbuf[..n].to_vec()) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(v)) => {
                                    conn.stash = Some(v);
                                    break;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    caller_gone = true;
                                    break;
                                }
                            },
                            Err(TcpRecvError::InvalidState) => break,
                            Err(TcpRecvError::Finished) => {
                                remote_closed = true;
                                break;
                            }
                        }
                    }
                }
                sock.state()
            };
            self.scratch = rbuf;

            if let Some(stash) = conn.stash.take() {
                match conn.to_caller.try_send(stash) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(v)) => conn.stash = Some(v),
                    Err(mpsc::error::TrySendError::Closed(_)) => caller_gone = true,
                }
            }
            if conn.to_caller.is_closed() {
                caller_gone = true;
            }

            if state == TcpState::Established
                && let Some(resp) = conn.resp.take()
            {
                let _ = resp.send(Ok(()));
                self.sockets
                    .get_mut::<TcpSock<'static>>(conn.handle)
                    .set_timeout(None);
            }

            let connect_failed = conn.resp.is_some()
                && (state == TcpState::Closed || conn.created.elapsed() >= CONNECT_TIMEOUT);
            let finished = state == TcpState::Closed
                || caller_gone
                || (conn.caller_eof && remote_closed && conn.stash.is_none());

            if connect_failed && let Some(resp) = conn.resp.take() {
                let _ = resp.send(Err(match state {
                    TcpState::Closed => "connection reset".to_string(),
                    _ => "connect timeout".to_string(),
                }));
            }
            if finished {
                if let Some(resp) = conn.resp.take() {
                    let _ = resp.send(Err("connection closed".into()));
                }
                self.sockets.remove(conn.handle);
            } else {
                self.tcp.insert(id, conn);
            }
        }
    }

    async fn maintain_peers(&mut self) {
        let now = Instant::now();
        for pi in 0..self.peers.len() {
            let traffic = self.peers[pi].kick || !self.peers[pi].pending.is_empty();
            if self.peers[pi].resolved.is_none() && traffic {
                self.resolve_peer(pi).await;
            }

            if let Some((_, exp)) = self.peers[pi].cookie
                && now >= exp
            {
                self.peers[pi].cookie = None;
            }

            let retry = self.peers[pi]
                .hs
                .as_ref()
                .filter(|h| now >= h.retry_at)
                .map(|h| (h.attempt, h.started, h.hs.initiation().to_vec()));
            if let Some((attempt, started, initiation)) = retry {
                // AWG 3.x: rekey_timeout / max_handshake_attempts ranges are
                // re-picked per attempt cycle.
                let rekey_timeout = self
                    .cfg
                    .awg
                    .as_ref()
                    .map(|a| awg::pick_secs(a.rekey_timeout, REKEY_TIMEOUT.as_secs()))
                    .unwrap_or(REKEY_TIMEOUT);
                let max_attempts = self
                    .cfg
                    .awg
                    .as_ref()
                    .map(|a| awg::pick_opt(a.max_handshake_attempts, REKEY_ATTEMPT_COUNT))
                    .unwrap_or(REKEY_ATTEMPT_COUNT);
                if attempt >= max_attempts || now.duration_since(started) >= REKEY_ATTEMPT_TIME {
                    self.peers[pi].hs = None;
                    self.peers[pi].pending.clear();
                } else {
                    self.send_handshake_init(pi, &initiation);
                    if let Some(hs) = &mut self.peers[pi].hs {
                        hs.attempt += 1;
                        hs.retry_at = now + rekey_timeout + jitter();
                    }
                }
            }

            // AWG 3.x: keychain expiry = reject_after_time.Hi.
            let reject_after = self
                .cfg
                .awg
                .as_ref()
                .and_then(|a| a.reject_after_time)
                .map(|(_, hi)| Duration::from_secs(hi as u64))
                .unwrap_or(REJECT_AFTER_TIME);
            if self.peers[pi].session.is_some()
                && let Some(lr) = self.peers[pi].last_recv
                && now.duration_since(lr) >= reject_after
            {
                self.peers[pi].session = None;
                self.peers[pi].session_since = None;
            }

            let want_session = self.peers[pi].kick || !self.peers[pi].pending.is_empty();
            if want_session && self.peers[pi].session.is_none() && self.peers[pi].hs.is_none() {
                self.start_hs(pi);
            }

            let rekey_after = self
                .cfg
                .awg
                .as_ref()
                .map(|a| awg::pick_secs(a.rekey_after_time, REKEY_AFTER_TIME.as_secs()))
                .unwrap_or(REKEY_AFTER_TIME);
            if self.peers[pi].session.is_some()
                && self.peers[pi].hs.is_none()
                && let Some(since) = self.peers[pi].session_since
                && now.duration_since(since) >= rekey_after
            {
                self.start_hs(pi);
            }

            if let Some(range) = self.peers[pi].endpoint.keepalive
                && self.peers[pi].session.is_some()
            {
                let interval = Duration::from_secs(awg::pick_opt(Some(range), 0) as u64);
                let due = self.peers[pi]
                    .last_sent
                    .is_none_or(|t| now.duration_since(t) >= interval);
                if due && self.peers[pi].hs.is_none() {
                    let confirm = self.seal_transport(pi, &[]);
                    if let Some(msg) = confirm {
                        self.send_raw(pi, &msg);
                        self.peers[pi].last_sent = Some(Instant::now());
                    }
                }
            }

            if self.peers[pi].flush && self.peers[pi].session.is_some() {
                self.peers[pi].flush = false;
                // Key confirmation: an empty transport packet right away.
                let confirm = self.seal_transport(pi, &[]);
                if let Some(msg) = confirm {
                    self.send_raw(pi, &msg);
                    self.peers[pi].last_sent = Some(Instant::now());
                }
                let pending: Vec<Vec<u8>> = std::mem::take(&mut self.peers[pi].pending)
                    .into_iter()
                    .collect();
                for pkt in pending {
                    let _ = self.xmit_to_peer(pi, pkt);
                }
            }
        }
    }

    fn next_deadline(&self) -> tokio::time::Instant {
        let now = Instant::now();
        let mut best: Option<Instant> = None;
        let mut consider = |t: Instant| {
            best = Some(match best {
                Some(b) if b < t => b,
                _ => t,
            });
        };
        for peer in &self.peers {
            if let Some(hs) = &peer.hs {
                consider(hs.retry_at);
            }
            if let Some((_, exp)) = peer.cookie {
                consider(exp);
            }
            if peer.session.is_some() {
                if let Some(since) = peer.session_since {
                    consider(since + REKEY_AFTER_TIME);
                }
                if let Some(lr) = peer.last_recv {
                    consider(lr + REJECT_AFTER_TIME);
                }
                if let Some(range) = peer.endpoint.keepalive {
                    let interval = Duration::from_secs(awg::pick_opt(Some(range), 0) as u64);
                    if let Some(sent) = peer.last_sent {
                        consider(sent + interval);
                    } else {
                        consider(now);
                    }
                }
            }
        }
        for conn in self.tcp.values() {
            if conn.resp.is_some() {
                consider(conn.created + CONNECT_TIMEOUT);
            }
        }
        let deadline = match best {
            Some(t) if t <= now => now + Duration::from_millis(50),
            Some(t) => t,
            None => now + Duration::from_secs(1),
        };
        tokio::time::Instant::from_std(deadline)
    }

    fn poll_stack(&mut self) -> PollResult {
        let now = SmolInstant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets)
    }
}

async fn run(
    cfg: Arc<WgConfig>,
    sock: Arc<UdpSocket>,
    sock_v6: Option<Arc<UdpSocket>>,
    mut rx: mpsc::Receiver<Cmd>,
) -> io::Result<()> {
    let mtu = cfg.mtu;
    let mut device = WgDevice::new(mtu);
    let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
    iconfig.random_seed = u64::from_le_bytes(seed);
    let mut iface = Interface::new(iconfig, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|list| {
        for cidr in &cfg.local_cidrs {
            let _ = list.push(*cidr);
        }
    });
    // Medium::Ip never consults the gateway, but default routes are required
    // so non-local destinations egress instead of being dropped.
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);
    let _ = iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::UNSPECIFIED);

    let mut stack = Stack {
        cfg,
        sock,
        sock_v6,
        device,
        iface,
        sockets: SocketSet::new(Vec::new()),
        peers: Vec::new(),
        index_peer: HashMap::new(),
        tcp: HashMap::new(),
        udp: HashMap::new(),
        next_port: EPHEMERAL_BASE,
        scratch: vec![0u8; SCRATCH_BUF],
    };
    // Peer configs live in cfg (Arc) — materialize runtime state.
    let peer_cfgs = stack.cfg.peers.clone();
    stack.peers = peer_cfgs.into_iter().map(PeerRt::new).collect();

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut buf_v6 = vec![0u8; MAX_DATAGRAM];
    loop {
        while let Ok((n, src)) = stack.sock.try_recv_from(&mut buf) {
            stack.process_inbound(&buf[..n], src);
        }
        let s6_recv = stack.sock_v6.clone();
        if let Some(s6) = &s6_recv {
            while let Ok((n, src)) = s6.try_recv_from(&mut buf_v6) {
                stack.process_inbound(&buf_v6[..n], src);
            }
        }
        while let Ok(cmd) = rx.try_recv() {
            stack.process_cmd(cmd);
        }
        stack.poll_stack();
        stack.flush_device_tx().await;
        stack.maintain_tcp();
        stack.maintain_peers().await;
        let deadline = stack.next_deadline();
        let sock = Arc::clone(&stack.sock);
        let s6_opt = stack.sock_v6.as_ref().map(Arc::clone);
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(cmd) => stack.process_cmd(cmd),
                None => return Ok(()),
            },
            res = sock.recv_from(&mut buf) => match res {
                Ok((n, src)) => stack.process_inbound(&buf[..n], src),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            },
            res = async {
                match &s6_opt {
                    Some(s) => s.recv_from(&mut buf_v6).await,
                    None => std::future::pending().await,
                }
            } => match res {
                Ok((n, src)) => stack.process_inbound(&buf_v6[..n], src),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            },
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

async fn resolve_host(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(dns) = crate::dns::current() {
        let addrs = match crate::dns::default_domain_resolver() {
            Some(tag) => dns.resolve_via(&tag, host).await?,
            None => dns.resolve(host).await?,
        };
        let ip = addrs
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other(format!("no address for {host}")))?;
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("no address for {host}")))
}

async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => resolve_host(host, *port).await,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wrap a payload into an IPv4/UDP packet (checksums: header computed, UDP
/// left zero — legal for IPv4).
pub(crate) fn build_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x00, // id
        0x00,
        0x00, // flags/frag
        64,   // ttl
        17,   // udp
        0x00,
        0x00, // checksum (filled below)
    ]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let csum = ipv4_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = csum as u8;
    let ulen = 8 + payload.len();
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // udp checksum: not used (IPv4)
    pkt.extend_from_slice(payload);
    pkt
}

fn ipv6_udp_checksum(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let ulen = (8 + payload.len()) as u32;
    sum += (ulen >> 16) & 0xffff;
    sum += ulen & 0xffff;
    sum += 17u32; // next header (UDP)

    sum += sport as u32;
    sum += dport as u32;
    sum += ulen & 0xffff;

    for chunk in payload.chunks(2) {
        let b1 = chunk[0];
        let b2 = *chunk.get(1).unwrap_or(&0);
        sum += u16::from_be_bytes([b1, b2]) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 { 0xffff } else { res }
}

/// Wrap a payload into an IPv6/UDP packet with RFC-compliant checksum.
pub(crate) fn build_ipv6_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ulen = 8 + payload.len();
    let total = 40 + ulen;
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[
        0x60, 0x00, 0x00, 0x00, // Version 6, Traffic Class 0, Flow Label 0
    ]);
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes()); // Payload Length
    pkt.push(17); // Next Header: UDP
    pkt.push(64); // Hop Limit
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes());
    let csum = ipv6_udp_checksum(src, dst, sport, dport, payload);
    pkt.extend_from_slice(&csum.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Parse an IP packet header (v4 or v6): `(src, dst, protocol, header_len)`.
fn ip_info(pkt: &[u8]) -> Option<(IpAddr, IpAddr, u8, usize)> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let hdr_len = (pkt[0] & 0x0f) as usize * 4;
            if hdr_len < 20 || pkt.len() < hdr_len {
                return None;
            }
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            Some((IpAddr::V4(src), IpAddr::V4(dst), pkt[9], hdr_len))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&pkt[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&pkt[24..40]);
            let proto = pkt[6]; // Next Header
            Some((
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                proto,
                40,
            ))
        }
        _ => None,
    }
}

fn ip_dst(pkt: &[u8]) -> Option<IpAddr> {
    ip_info(pkt).map(|(_, dst, _, _)| dst)
}

#[allow(dead_code)]
fn ipv4_info(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, usize)> {
    match ip_info(pkt)? {
        (IpAddr::V4(src), IpAddr::V4(dst), proto, hdr) => Some((src, dst, proto, hdr)),
        _ => None,
    }
}

#[allow(dead_code)]
fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    ipv4_info(pkt).map(|(_, dst, _, _)| dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wg_obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "wireguard",
            "tag": "wg",
            "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "address": ["10.66.66.2/24"],
            "peers": [{
                "address": "127.0.0.1",
                "port": 51820,
                "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "allowed_ips": ["0.0.0.0/0"],
                "persistent_keepalive_interval": 25
            }]
        });
        if let Value::Object(map) = extra {
            base.as_object_mut().unwrap().extend(map);
        }
        base.as_object().unwrap().clone()
    }

    #[test]
    fn build_valid_endpoint() {
        let wg = WireGuard::build(&wg_obj(json!({})), "endpoints[0]").expect("build");
        assert_eq!(wg.cfg.local_addr_v4, Some(Ipv4Addr::new(10, 66, 66, 2)));
        assert_eq!(wg.cfg.local_addr_v6, None);
        assert_eq!(wg.cfg.mtu, DEFAULT_MTU);
        assert_eq!(wg.cfg.peers.len(), 1);
        assert_eq!(wg.cfg.peers[0].port, DEFAULT_PORT);
        assert_eq!(wg.cfg.peers[0].keepalive, Some((25, 25)));
        assert_eq!(wg.cfg.peers[0].allowed_ips_v4, vec![(0, 0)]);
        assert!(wg.cfg.peers[0].allowed_ips_v6.is_empty());
    }

    #[test]
    fn build_valid_endpoint_ipv6() {
        let obj = wg_obj(json!({
            "address": ["fd00::2/64", "10.66.66.2/24"],
            "peers": [{
                "address": "[::1]",
                "port": 51820,
                "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "allowed_ips": ["::/0", "0.0.0.0/0"]
            }]
        }));
        let wg = WireGuard::build(&obj, "endpoints[0]").expect("build ipv6");
        assert_eq!(wg.cfg.local_addr_v4, Some(Ipv4Addr::new(10, 66, 66, 2)));
        assert!(wg.cfg.local_addr_v6.is_some());
        assert_eq!(wg.cfg.peers[0].allowed_ips_v4, vec![(0, 0)]);
        assert_eq!(wg.cfg.peers[0].allowed_ips_v6, vec![(0, 0)]);
    }

    #[test]
    fn build_rejects_system_and_awg() {
        WireGuard::build(&wg_obj(json!({"system": true})), "endpoints[0]").expect_err("system");
        // AWG 2.0 fields parse into obfuscation params.
        WireGuard::build(&wg_obj(json!({"jc": 4})), "endpoints[0]").expect("awg jc");
        WireGuard::build(&wg_obj(json!({"i1": "1"})), "endpoints[0]").expect("awg i1");
        // AWG 3.x-only features stay explicitly rejected.
        WireGuard::build(
            &wg_obj(json!({"header_protection_key": "x"})),
            "endpoints[0]",
        )
        .expect_err("awg hpk");
        // explicit zeroes are plain wireguard.
        WireGuard::build(&wg_obj(json!({"jc": 0})), "endpoints[0]").expect("zero jc");
    }

    #[test]
    fn build_requires_keys_and_allowed_ips() {
        let mut obj = wg_obj(json!({}));
        obj.remove("private_key");
        WireGuard::build(&obj, "endpoints[0]").expect_err("private key");

        let mut obj = wg_obj(json!({}));
        obj.insert(
            "peers".into(),
            json!([{
                "address": "127.0.0.1",
                "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
            }]),
        );
        WireGuard::build(&obj, "endpoints[0]").expect_err("allowed ips");
    }

    #[test]
    fn keepalive_forms() {
        let at = "t";
        assert_eq!(
            parse_keepalive(Some(&json!(30)), at).unwrap(),
            Some((30, 30))
        );
        assert_eq!(
            parse_keepalive(Some(&json!("30")), at).unwrap(),
            Some((30, 30))
        );
        assert_eq!(
            parse_keepalive(Some(&json!("30-60")), at).unwrap(),
            Some((30, 60))
        );
        assert_eq!(
            parse_keepalive(Some(&json!("45s")), at).unwrap(),
            Some((45, 45))
        );
        assert_eq!(parse_keepalive(Some(&json!(0)), at).unwrap(), None);
        assert_eq!(parse_keepalive(None, at).unwrap(), None);
    }

    #[test]
    fn lpm_longest_prefix_wins() {
        let peers = vec![
            PeerRt::new(PeerConfig {
                host: "a".into(),
                port: 1,
                public_key: [1; 32],
                pre_shared_key: None,
                allowed_ips_v4: vec![(0, 0)],
                allowed_ips_v6: vec![(0, 0)],
                keepalive: None,
            }),
            PeerRt::new(PeerConfig {
                host: "b".into(),
                port: 2,
                public_key: [2; 32],
                pre_shared_key: None,
                allowed_ips_v4: vec![(u32::from(Ipv4Addr::new(10, 1, 0, 0)), 16)],
                allowed_ips_v6: Vec::new(),
                keepalive: None,
            }),
            PeerRt::new(PeerConfig {
                host: "c".into(),
                port: 3,
                public_key: [3; 32],
                pre_shared_key: None,
                allowed_ips_v4: vec![(u32::from(Ipv4Addr::new(10, 1, 2, 0)), 24)],
                allowed_ips_v6: Vec::new(),
                keepalive: None,
            }),
        ];
        assert_eq!(lpm_v4(&peers, Ipv4Addr::new(8, 8, 8, 8)), Some(0));
        assert_eq!(lpm_v4(&peers, Ipv4Addr::new(10, 1, 9, 9)), Some(1));
        assert_eq!(lpm_v4(&peers, Ipv4Addr::new(10, 1, 2, 7)), Some(2));
        assert_eq!(lpm_v4(&peers, Ipv4Addr::new(10, 2, 0, 1)), Some(0));
        assert_eq!(
            lpm_v6(&peers, "2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            Some(0)
        );
    }

    #[test]
    fn ipv4_udp_roundtrip() {
        let src = Ipv4Addr::new(10, 66, 66, 2);
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let payload = b"hello tunnel";
        let pkt = build_ipv4_udp(src, dst, 40000, 53, payload);
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        let (got_src, got_dst, proto, hdr) = ip_info(&pkt).expect("parse");
        assert_eq!(got_src, IpAddr::V4(src));
        assert_eq!(got_dst, IpAddr::V4(dst));
        assert_eq!(proto, 17);
        assert_eq!(hdr, 20);
        let sport = u16::from_be_bytes([pkt[20], pkt[21]]);
        let dport = u16::from_be_bytes([pkt[22], pkt[23]]);
        assert_eq!((sport, dport), (40000, 53));
        assert_eq!(&pkt[28..], payload);
        let csum = u16::from_be_bytes([pkt[10], pkt[11]]);
        assert_ne!(csum, 0);
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
        assert_eq!(ip_dst(&pkt), Some(IpAddr::V4(dst)));
        assert!(ip_info(&[0u8; 10]).is_none());
    }

    #[test]
    fn ipv6_udp_roundtrip() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let payload = b"hello ipv6 tunnel";
        let pkt = build_ipv6_udp(src, dst, 40000, 53, payload);
        assert_eq!(pkt.len(), 40 + 8 + payload.len());
        let (got_src, got_dst, proto, hdr) = ip_info(&pkt).expect("parse");
        assert_eq!(got_src, IpAddr::V6(src));
        assert_eq!(got_dst, IpAddr::V6(dst));
        assert_eq!(proto, 17);
        assert_eq!(hdr, 40);
        let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
        let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
        assert_eq!((sport, dport), (40000, 53));
        assert_eq!(&pkt[48..], payload);
        let csum = u16::from_be_bytes([pkt[46], pkt[47]]);
        assert_ne!(csum, 0);
        assert_eq!(ip_dst(&pkt), Some(IpAddr::V6(dst)));
    }

    fn b64(data: &[u8]) -> String {
        const B64_ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                B64_ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                B64_ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[tokio::test]
    async fn wireguard_server_responder_accepts_initiation() {
        use std::net::IpAddr;

        let server_priv = [0x55u8; 32];
        let client_priv = [0x66u8; 32];
        let server_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(server_priv))
                .to_bytes();
        let client_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_priv))
                .to_bytes();

        let s_bind = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s_bind.local_addr().unwrap().port();
        drop(s_bind);

        let cfg_json = json!({
            "private_key": b64(&server_priv),
            "address": ["10.66.66.1/24"],
            "listen_port": port,
            "peers": [{
                "public_key": b64(&client_pub),
                "allowed_ips": ["10.66.66.2/32"]
            }]
        });
        let map = cfg_json.as_object().unwrap();
        let wg = WireGuard::build(map, "endpoints[0]").expect("build wg server");
        wg.start_listen().await.expect("start listen");

        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client sock");
        let server_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port);

        let hs = noise::build_initiation(
            &client_priv,
            &client_pub,
            &server_pub,
            None,
            &noise::tai64n_now(),
            noise::HDR_INIT.0,
        );
        client_sock
            .send_to(hs.initiation(), server_addr)
            .await
            .expect("send init");

        let mut resp_buf = vec![0u8; 1500];
        let (n, from) =
            tokio::time::timeout(Duration::from_secs(3), client_sock.recv_from(&mut resp_buf))
                .await
                .expect("timeout waiting for handshake response")
                .expect("recv response");
        assert_eq!(from.port(), port);

        let mut client_session = noise::process_response(&hs, &resp_buf[..n], &client_pub, None)
            .expect("client process response");

        // Send transport keepalive from client to server
        let plain = b"";
        let sealed = client_session.seal(plain).expect("seal");
        client_sock
            .send_to(&sealed, server_addr)
            .await
            .expect("send transport");
    }
}
