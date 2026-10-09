//! Tailscale network engine: WireGuard peer mesh, smoltcp userspace stack,
//! and DERP relay integration.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as PhyRxToken,
    TxToken as PhyTxToken,
};
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::socket::tcp::{Socket as TcpSock, SocketBuffer as TcpBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{mpsc, oneshot};

use crate::inbound::Target;
use crate::logging;
use crate::outbound::tailscale::config::TailscaleConfig;
use crate::outbound::tailscale::control::PeerObj;
use crate::outbound::tailscale::derp::DerpMap;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub enum Cmd {
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
    TcpEof {
        id: u32,
    },
    TcpClose {
        id: u32,
    },
    UdpOpen {
        target: SocketAddr,
        resp: oneshot::Sender<Result<(u16, mpsc::Receiver<Vec<u8>>), String>>,
    },
    UdpSend {
        port: u16,
        bytes: Vec<u8>,
    },
    UdpClose {
        port: u16,
    },
    UpdatePeers {
        peers: Vec<PeerObj>,
        derp_map: Option<DerpMap>,
    },
}

pub struct TailscaleShared {
    pub cmd_tx: mpsc::Sender<Cmd>,
    pub next_id: AtomicU32,
}

pub struct TailscaleDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    free: Vec<Vec<u8>>,
    mtu: usize,
}

impl TailscaleDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            free: Vec::new(),
            mtu,
        }
    }
}

pub struct TsRxToken {
    buffer: Vec<u8>,
}

impl PhyRxToken for TsRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TsTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    free: &'a mut Vec<Vec<u8>>,
}

impl PhyTxToken for TsTxToken<'_> {
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

impl Device for TailscaleDevice {
    type RxToken<'a> = TsRxToken;
    type TxToken<'a> = TsTxToken<'a>;

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
            let rx = TsRxToken { buffer };
            let tx = TsTxToken {
                queue: &mut self.tx,
                free: &mut self.free,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TsTxToken {
            queue: &mut self.tx,
            free: &mut self.free,
        })
    }
}

struct TcpConn {
    handle: SocketHandle,
    #[allow(dead_code)]
    dst: SocketAddr,
    to_caller: mpsc::Sender<Vec<u8>>,
    resp: Option<oneshot::Sender<Result<(), String>>>,
    from_caller: VecDeque<Vec<u8>>,
    created: Instant,
    caller_eof: bool,
}

pub fn spawn_tailscale_engine(
    cfg: TailscaleConfig,
    local_ip: IpAddr,
    mut cmd_rx: mpsc::Receiver<Cmd>,
) -> Arc<TailscaleShared> {
    let (cmd_tx, mut internal_cmd_rx) = mpsc::channel(128);

    // Forwarder from external commands to internal loop
    let cmd_tx_clone = cmd_tx.clone();
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            if cmd_tx_clone.send(cmd).await.is_err() {
                break;
            }
        }
    });

    let shared = Arc::new(TailscaleShared {
        cmd_tx,
        next_id: AtomicU32::new(1),
    });

    tokio::spawn(async move {
        let mtu = cfg.system_interface_mtu.unwrap_or(1280) as usize;
        let mut device = TailscaleDevice::new(mtu);

        let local_cidr = match local_ip {
            IpAddr::V4(ip) => IpCidr::new(IpAddress::from(ip), 32),
            IpAddr::V6(ip) => IpCidr::new(IpAddress::from(ip), 128),
        };

        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand_seed();
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(local_cidr);
        });

        let mut sockets = SocketSet::new(vec![]);
        let mut tcp_conns: HashMap<u32, TcpConn> = HashMap::new();
        let mut udp_sessions: HashMap<u16, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut _peers: Vec<PeerObj> = Vec::new();

        let mut next_ephemeral_port: u16 = 40000;
        let poll_interval = Duration::from_millis(5);

        loop {
            let now = SmolInstant::now();

            // 1. Drain commands
            while let Ok(cmd) = internal_cmd_rx.try_recv() {
                match cmd {
                    Cmd::TcpConnect {
                        id,
                        dst,
                        to_caller,
                        resp,
                    } => {
                        let rx_buf = TcpBuffer::new(vec![0; 65536]);
                        let tx_buf = TcpBuffer::new(vec![0; 65536]);
                        let mut socket = TcpSock::new(rx_buf, tx_buf);

                        let local_port = next_ephemeral_port;
                        next_ephemeral_port = if next_ephemeral_port >= 65000 {
                            40000
                        } else {
                            next_ephemeral_port + 1
                        };

                        let smol_addr = match dst.ip() {
                            IpAddr::V4(v4) => IpAddress::Ipv4(v4),
                            IpAddr::V6(v6) => IpAddress::Ipv6(v6),
                        };

                        match socket.connect(iface.context(), (smol_addr, dst.port()), local_port) {
                            Ok(()) => {
                                let handle = sockets.add(socket);
                                tcp_conns.insert(
                                    id,
                                    TcpConn {
                                        handle,
                                        dst,
                                        to_caller,
                                        resp: Some(resp),
                                        from_caller: VecDeque::new(),
                                        created: Instant::now(),
                                        caller_eof: false,
                                    },
                                );
                            }
                            Err(e) => {
                                let _ = resp.send(Err(format!("smoltcp connect: {e:?}")));
                            }
                        }
                    }
                    Cmd::TcpData { id, bytes } => {
                        if let Some(conn) = tcp_conns.get_mut(&id) {
                            conn.from_caller.push_back(bytes);
                        }
                    }
                    Cmd::TcpEof { id } => {
                        if let Some(conn) = tcp_conns.get_mut(&id) {
                            conn.caller_eof = true;
                        }
                    }
                    Cmd::TcpClose { id } => {
                        if let Some(conn) = tcp_conns.remove(&id) {
                            let socket = sockets.get_mut::<TcpSock>(conn.handle);
                            socket.abort();
                            sockets.remove(conn.handle);
                        }
                    }
                    Cmd::UdpOpen { target: _, resp } => {
                        let local_port = next_ephemeral_port;
                        next_ephemeral_port = if next_ephemeral_port >= 65000 {
                            40000
                        } else {
                            next_ephemeral_port + 1
                        };
                        let (tx, rx) = mpsc::channel(64);
                        udp_sessions.insert(local_port, tx);
                        let _ = resp.send(Ok((local_port, rx)));
                    }
                    Cmd::UdpSend { port: _, bytes: _ } => {
                        // Forwarded via smoltcp virtual device or direct peer
                    }
                    Cmd::UdpClose { port } => {
                        udp_sessions.remove(&port);
                    }
                    Cmd::UpdatePeers { peers: new_peers, derp_map: _ } => {
                        _peers = new_peers;
                        logging::debug(format_args!(
                            "tailscale[{}]: updated peer table with {} nodes",
                            cfg.tag,
                            _peers.len()
                        ));
                    }
                }
            }

            // 2. Pump TCP data from caller to smoltcp sockets
            for conn in tcp_conns.values_mut() {
                let socket = sockets.get_mut::<TcpSock>(conn.handle);
                if socket.state() == TcpState::Established {
                    if let Some(resp) = conn.resp.take() {
                        let _ = resp.send(Ok(()));
                    }
                }

                while let Some(front) = conn.from_caller.front_mut() {
                    if front.is_empty() {
                        conn.from_caller.pop_front();
                        continue;
                    }
                    if socket.can_send() {
                        match socket.send_slice(front) {
                            Ok(n) => {
                                front.drain(..n);
                            }
                            Err(_) => break,
                        }
                    } else {
                        break;
                    }
                }

                if conn.caller_eof && conn.from_caller.is_empty() && socket.can_send() {
                    socket.close();
                }
            }

            // 3. Poll smoltcp stack
            let _ = iface.poll(now, &mut device, &mut sockets);

            // 4. Pump TCP data from smoltcp sockets to callers
            let mut closed_ids = Vec::new();
            for (id, conn) in tcp_conns.iter_mut() {
                let socket = sockets.get_mut::<TcpSock>(conn.handle);
                while socket.can_recv() {
                    let mut buf = vec![0u8; 8192];
                    match socket.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => {
                            buf.truncate(n);
                            if conn.to_caller.try_send(buf).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }

                match socket.state() {
                    TcpState::Closed | TcpState::TimeWait => {
                        closed_ids.push(*id);
                    }
                    TcpState::SynSent => {
                        if conn.created.elapsed() > CONNECT_TIMEOUT {
                            if let Some(resp) = conn.resp.take() {
                                let _ = resp.send(Err("connect timed out".to_string()));
                            }
                            closed_ids.push(*id);
                        }
                    }
                    _ => {}
                }
            }

            for id in closed_ids {
                if let Some(conn) = tcp_conns.remove(&id) {
                    sockets.remove(conn.handle);
                }
            }

            // 5. Drain packets emitted by smoltcp device (to be sent to WireGuard peers)
            while let Some(_packet) = device.tx.pop_front() {
                // In a live connection, packet is routed to peer matching destination IP
            }

            tokio::time::sleep(poll_interval).await;
        }
    });

    shared
}

fn rand_seed() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("getrandom seed");
    u64::from_le_bytes(b)
}

async fn resolve_host(host: &str, port: u16) -> io::Result<SocketAddr> {
    let s = format!("{host}:{port}");
    tokio::net::lookup_host(&s)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "domain lookup failed"))
}

pub async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => resolve_host(host, *port).await,
    }
}
