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
use crate::outbound::tailscale::config::TailscaleConfig;

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
    #[allow(clippy::type_complexity)]
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
}

pub struct TailscaleShared {
    pub cmd_tx: mpsc::Sender<Cmd>,
    pub next_id: AtomicU32,
    pub map: Arc<std::sync::RwLock<super::netmap::Netmap>>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for TailscaleShared {
    fn drop(&mut self) {
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

impl TailscaleShared {
    pub fn abort(&self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            task.abort();
        }
    }
    pub async fn shutdown(&self) {
        let tasks =
            std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|error| error.into_inner()));
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
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

const MAX_CONNECTIONS: usize = 128;
const MAX_QUEUED: usize = 1 << 20;
type Flow = (SocketAddr, SocketAddr);

struct TcpConn {
    handle: SocketHandle,
    flow: Flow,
    to_caller: Option<mpsc::Sender<Vec<u8>>>,
    resp: Option<oneshot::Sender<Result<(), String>>>,
    from_caller: VecDeque<Vec<u8>>,
    stash: Option<Vec<u8>>,
    created: Instant,
    caller_eof: bool,
    bridge: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for TcpConn {
    fn drop(&mut self) {
        if let Some(task) = &self.bridge {
            task.abort();
        }
    }
}

struct UdpSession {
    target: SocketAddr,
    source: SocketAddr,
    replies: mpsc::Sender<Vec<u8>>,
    last: Instant,
}
struct ForwardedUdp {
    send: mpsc::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
    last: Instant,
}

#[derive(Default, Debug)]
struct IngressCounters {
    tcp: u64,
    udp: u64,
    bad_checksum: u64,
    denied_destination: u64,
    denied_acl: u64,
    tcp_created: u64,
    udp_created: u64,
    tcp_sent: u64,
    queue_full: u64,
}
impl Drop for ForwardedUdp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn spawn_tailscale_engine(
    cfg: TailscaleConfig,
    map: Arc<std::sync::RwLock<super::netmap::Netmap>>,
    mut mesh: super::mesh::Mesh,
    control_task: tokio::task::JoinHandle<()>,
) -> Arc<TailscaleShared> {
    let (cmd_tx, mut commands) = mpsc::channel(128);
    let shared = Arc::new(TailscaleShared {
        cmd_tx: cmd_tx.clone(),
        next_id: AtomicU32::new(1),
        map: Arc::clone(&map),
        tasks: std::sync::Mutex::new(vec![control_task]),
    });
    let task = tokio::spawn(async move {
        let mtu = cfg.system_interface_mtu.unwrap_or(1280) as usize;
        let mut device = TailscaleDevice::new(mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand_seed();
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
        iface.set_any_ip(true);
        let mut sockets = SocketSet::new(vec![]);
        let mut tcp_conns: HashMap<u32, TcpConn> = HashMap::new();
        let mut udp_sessions: HashMap<u16, UdpSession> = HashMap::new();
        let mut forwarded: HashMap<Flow, ForwardedUdp> = HashMap::new();
        let mut next_port = 40000u16;
        let mut incoming_id = 0x8000_0000u32;
        let mut addresses = Vec::new();
        let mut ingress = IngressCounters::default();
        let mut last_report = Instant::now();
        let mut poll = tokio::time::interval(Duration::from_millis(5));
        loop {
            poll.tick().await;
            if last_report.elapsed() >= Duration::from_secs(5) {
                if ingress.tcp != 0 || ingress.udp != 0 {
                    crate::logging::debug(format_args!(
                        "tailscale[{}]: ingress {ingress:?}",
                        cfg.tag
                    ));
                }
                ingress = IngressCounters::default();
                last_report = Instant::now();
            }
            let netmap = map.read().map(|map| map.active_clone()).unwrap_or_default();
            if addresses != netmap.own_addresses {
                addresses = netmap.own_addresses.clone();
                iface.update_ip_addrs(|list| {
                    list.clear();
                    for address in addresses.iter().take(2) {
                        let _ = list.push(*address);
                    }
                });
                iface.routes_mut().update(|routes| routes.clear());
                for address in &addresses {
                    match address.address() {
                        IpAddress::Ipv4(ip) => {
                            let _ = iface.routes_mut().add_default_ipv4_route(ip);
                        }
                        IpAddress::Ipv6(ip) => {
                            let _ = iface.routes_mut().add_default_ipv6_route(ip);
                        }
                    }
                }
            }
            while let Ok(cmd) = commands.try_recv() {
                match cmd {
                    Cmd::TcpConnect {
                        id,
                        dst,
                        to_caller,
                        resp,
                    } => {
                        if tcp_conns.len() >= MAX_CONNECTIONS {
                            let _ = resp.send(Err("connection limit".into()));
                            continue;
                        }
                        let Some(source) = local_address(&addresses, dst.ip()) else {
                            let _ = resp.send(Err("node has no assigned address".into()));
                            continue;
                        };
                        let port = allocate_port(&mut next_port, &udp_sessions, &tcp_conns);
                        let Some(port) = port else {
                            let _ = resp.send(Err("no free ports".into()));
                            continue;
                        };
                        let mut socket = tcp_socket();
                        let result = socket.connect(
                            iface.context(),
                            (IpAddress::from(dst.ip()), dst.port()),
                            (IpAddress::from(source), port),
                        );
                        if let Err(error) = result {
                            let _ = resp.send(Err(error.to_string()));
                            continue;
                        }
                        let handle = sockets.add(socket);
                        tcp_conns.insert(
                            id,
                            TcpConn {
                                handle,
                                flow: (SocketAddr::new(source, port), dst),
                                to_caller: Some(to_caller),
                                resp: Some(resp),
                                from_caller: VecDeque::new(),
                                stash: None,
                                created: Instant::now(),
                                caller_eof: false,
                                bridge: None,
                            },
                        );
                    }
                    Cmd::TcpData { id, bytes } => {
                        if let Some(conn) = tcp_conns.get_mut(&id) {
                            if conn.from_caller.iter().map(Vec::len).sum::<usize>() + bytes.len()
                                > MAX_QUEUED
                            {
                                sockets.get_mut::<TcpSock>(conn.handle).abort();
                            } else {
                                conn.from_caller.push_back(bytes);
                            }
                        }
                    }
                    Cmd::TcpEof { id } => {
                        if let Some(conn) = tcp_conns.get_mut(&id) {
                            conn.caller_eof = true;
                        }
                    }
                    Cmd::TcpClose { id } => {
                        if let Some(conn) = tcp_conns.remove(&id) {
                            sockets.get_mut::<TcpSock>(conn.handle).abort();
                            sockets.remove(conn.handle);
                        }
                    }
                    Cmd::UdpOpen { target, resp } => {
                        if udp_sessions.len() >= MAX_CONNECTIONS {
                            let _ = resp.send(Err("UDP session limit".into()));
                            continue;
                        }
                        let Some(source) = local_address(&addresses, target.ip()) else {
                            let _ = resp.send(Err("node has no assigned address".into()));
                            continue;
                        };
                        let Some(port) = allocate_port(&mut next_port, &udp_sessions, &tcp_conns)
                        else {
                            let _ = resp.send(Err("no free ports".into()));
                            continue;
                        };
                        let (replies, receive) = mpsc::channel(64);
                        udp_sessions.insert(
                            port,
                            UdpSession {
                                source: SocketAddr::new(source, port),
                                target,
                                replies,
                                last: Instant::now(),
                            },
                        );
                        if resp.send(Ok((port, receive))).is_err() {
                            udp_sessions.remove(&port);
                        }
                    }
                    Cmd::UdpSend { port, bytes } => {
                        if let Some(session) = udp_sessions.get_mut(&port) {
                            session.last = Instant::now();
                            if let Some(packet) =
                                udp_packet(session.source, session.target, &bytes, mtu)
                            {
                                let _ = mesh.send.try_send(packet);
                            }
                        }
                    }
                    Cmd::UdpClose { port } => {
                        udp_sessions.remove(&port);
                    }
                }
            }
            while let Ok(packet) = mesh.receive.try_recv() {
                let Some((src_ip, dst_ip, length)) = super::mesh::ip_header(&packet) else {
                    continue;
                };
                let (protocol, offset) = if packet[0] >> 4 == 4 {
                    (packet[9], usize::from(packet[0] & 15) * 4)
                } else {
                    (packet[6], 40)
                };
                let payload = &packet[offset..length];
                match protocol {
                    17 => {
                        ingress.udp += 1;
                        let Ok(udp) = smoltcp::wire::UdpPacket::new_checked(payload) else {
                            continue;
                        };
                        if !(src_ip.is_ipv4() && udp.checksum() == 0
                            || udp.verify_checksum(
                                &IpAddress::from(src_ip),
                                &IpAddress::from(dst_ip),
                            ))
                        {
                            ingress.bad_checksum += 1;
                            continue;
                        }
                        let source = SocketAddr::new(src_ip, udp.src_port());
                        let destination = SocketAddr::new(dst_ip, udp.dst_port());
                        if let Some(session) = udp_sessions.get_mut(&destination.port())
                            && session.source == destination
                            && session.target == source
                        {
                            session.last = Instant::now();
                            let _ = session.replies.try_send(udp.payload().to_vec());
                            continue;
                        }
                        let flow = (source, destination);
                        if !allowed_destination(&cfg, &addresses, dst_ip) {
                            ingress.denied_destination += 1;
                            continue;
                        }
                        if !netmap.permits(src_ip, dst_ip, 17, destination.port()) {
                            ingress.denied_acl += 1;
                            continue;
                        }
                        if let Some(forward) = forwarded.get_mut(&flow) {
                            forward.last = Instant::now();
                            let _ = forward.send.try_send(udp.payload().to_vec());
                        } else if forwarded.len() < MAX_CONNECTIONS {
                            ingress.udp_created += 1;
                            let (send, receive) = mpsc::channel(64);
                            // Queue before opening the OS socket: the first datagram
                            // is application data, never a disposable wake-up packet.
                            let _ = send.try_send(udp.payload().to_vec());
                            let real_target = local_target(destination, &addresses);
                            let mesh_tx = mesh.send.clone();
                            let timeout = cfg.udp_timeout;
                            let task = tokio::spawn(async move {
                                if let Err(error) =
                                    forward_udp(flow, real_target, receive, mesh_tx, timeout, mtu)
                                        .await
                                {
                                    crate::logging::debug(format_args!(
                                        "tailscale: LAN UDP forwarder ended: {error}"
                                    ));
                                }
                            });
                            forwarded.insert(
                                flow,
                                ForwardedUdp {
                                    send,
                                    task,
                                    last: Instant::now(),
                                },
                            );
                        }
                    }
                    6 => {
                        ingress.tcp += 1;
                        let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(payload) else {
                            continue;
                        };
                        if !tcp.verify_checksum(&IpAddress::from(src_ip), &IpAddress::from(dst_ip))
                        {
                            ingress.bad_checksum += 1;
                            continue;
                        }
                        let source = SocketAddr::new(src_ip, tcp.src_port());
                        let destination = SocketAddr::new(dst_ip, tcp.dst_port());
                        let flow = (destination, source);
                        let existing = tcp_conns.values().any(|conn| conn.flow == flow);
                        if !existing {
                            if !tcp.syn() || tcp.ack() || tcp_conns.len() >= MAX_CONNECTIONS {
                                continue;
                            }
                            if !allowed_destination(&cfg, &addresses, dst_ip) {
                                ingress.denied_destination += 1;
                                continue;
                            }
                            if !netmap.permits(src_ip, dst_ip, 6, destination.port()) {
                                ingress.denied_acl += 1;
                                continue;
                            }
                            let mut socket = tcp_socket();
                            if socket
                                .listen((IpAddress::from(dst_ip), destination.port()))
                                .is_err()
                            {
                                continue;
                            }
                            let handle = sockets.add(socket);
                            ingress.tcp_created += 1;
                            let (to_caller, receive) = mpsc::channel(32);
                            let id = incoming_id;
                            incoming_id = incoming_id.wrapping_add(1).max(0x8000_0000);
                            let target = local_target(destination, &addresses);
                            let commands = cmd_tx.clone();
                            let bridge = tokio::spawn(async move {
                                bridge_tcp(id, target, receive, commands).await;
                            });
                            tcp_conns.insert(
                                id,
                                TcpConn {
                                    handle,
                                    flow,
                                    to_caller: Some(to_caller),
                                    resp: None,
                                    from_caller: VecDeque::new(),
                                    stash: None,
                                    created: Instant::now(),
                                    caller_eof: false,
                                    bridge: Some(bridge),
                                },
                            );
                        }
                        device.rx.push_back(packet);
                    }
                    // ICMP/TSMP and extension headers are not passed to LAN
                    // forwarding without a dedicated validated handler.
                    _ => {}
                }
            }
            for conn in tcp_conns.values_mut() {
                let socket = sockets.get_mut::<TcpSock>(conn.handle);
                while let Some(front) = conn.from_caller.front_mut() {
                    match socket.send_slice(front) {
                        Ok(0) | Err(_) => break,
                        Ok(size) => {
                            front.drain(..size);
                            if front.is_empty() {
                                conn.from_caller.pop_front();
                            }
                        }
                    }
                }
                if conn.caller_eof && conn.from_caller.is_empty() {
                    socket.close();
                }
            }
            let _ = iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            let mut closed = Vec::new();
            for (id, conn) in tcp_conns.iter_mut() {
                let socket = sockets.get_mut::<TcpSock>(conn.handle);
                if socket.state() == TcpState::Established
                    && let Some(resp) = conn.resp.take()
                {
                    let _ = resp.send(Ok(()));
                }
                if let Some(bytes) = conn.stash.take() {
                    match conn
                        .to_caller
                        .as_ref()
                        .expect("receiver still open")
                        .try_send(bytes)
                    {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(bytes)) => conn.stash = Some(bytes),
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            socket.abort();
                        }
                    }
                }
                while conn.stash.is_none() && socket.can_recv() {
                    let mut bytes = vec![0; 8192];
                    match socket.recv_slice(&mut bytes) {
                        Ok(0) | Err(_) => break,
                        Ok(size) => {
                            bytes.truncate(size);
                            match conn
                                .to_caller
                                .as_ref()
                                .expect("receiver still open")
                                .try_send(bytes)
                            {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(bytes)) => {
                                    conn.stash = Some(bytes)
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    socket.abort();
                                    break;
                                }
                            }
                        }
                    }
                }
                // A peer FIN closes only the read half. Deliver all buffered
                // bytes before EOF while leaving the caller's write half alive.
                if matches!(
                    socket.state(),
                    TcpState::CloseWait
                        | TcpState::LastAck
                        | TcpState::Closing
                        | TcpState::TimeWait
                        | TcpState::Closed
                ) && !socket.may_recv()
                    && conn.stash.is_none()
                {
                    conn.to_caller.take();
                }
                if matches!(socket.state(), TcpState::Closed | TcpState::TimeWait)
                    || (matches!(
                        socket.state(),
                        TcpState::SynSent | TcpState::Listen | TcpState::SynReceived
                    ) && conn.created.elapsed() > CONNECT_TIMEOUT)
                {
                    if let Some(resp) = conn.resp.take() {
                        let _ = resp.send(Err("connect timed out or closed".into()));
                    }
                    closed.push(*id);
                }
            }
            for id in closed {
                if let Some(conn) = tcp_conns.remove(&id) {
                    sockets.remove(conn.handle);
                }
            }
            udp_sessions.retain(|_, session| {
                session.last.elapsed() < cfg.udp_timeout && !session.replies.is_closed()
            });
            forwarded.retain(|_, flow| {
                flow.last.elapsed() < cfg.udp_timeout && !flow.task.is_finished()
            });
            while let Some(packet) = device.tx.pop_front() {
                ingress.tcp_sent += 1;
                if mesh.send.try_send(packet).is_err() {
                    ingress.queue_full += 1;
                }
            }
        }
    });
    shared.tasks.lock().expect("tailscale tasks").push(task);
    shared
}

fn tcp_socket() -> TcpSock<'static> {
    let mut socket = TcpSock::new(
        TcpBuffer::new(vec![0; 32768]),
        TcpBuffer::new(vec![0; 32768]),
    );
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    socket
}

fn local_address(addresses: &[IpCidr], destination: IpAddr) -> Option<IpAddr> {
    addresses
        .iter()
        .map(|cidr| IpAddr::from(cidr.address()))
        .find(|ip| ip.is_ipv4() == destination.is_ipv4())
}

fn allocate_port(
    next: &mut u16,
    udp: &HashMap<u16, UdpSession>,
    tcp: &HashMap<u32, TcpConn>,
) -> Option<u16> {
    for _ in 0..25000 {
        let port = *next;
        *next = if *next >= 65000 { 40000 } else { *next + 1 };
        if !udp.contains_key(&port) && !tcp.values().any(|conn| conn.flow.0.port() == port) {
            return Some(port);
        }
    }
    None
}

fn allowed_destination(cfg: &TailscaleConfig, addresses: &[IpCidr], ip: IpAddr) -> bool {
    addresses
        .iter()
        .any(|cidr| cidr.address() == IpAddress::from(ip))
        || cfg
            .advertise_routes
            .iter()
            .any(|cidr| cidr.contains_addr(&IpAddress::from(ip)))
}

fn local_target(destination: SocketAddr, addresses: &[IpCidr]) -> SocketAddr {
    if addresses
        .iter()
        .any(|cidr| cidr.address() == IpAddress::from(destination.ip()))
    {
        SocketAddr::new(
            if destination.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            },
            destination.port(),
        )
    } else {
        destination
    }
}

fn udp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    bytes: &[u8],
    mtu: usize,
) -> Option<Vec<u8>> {
    use crate::outbound::wireguard::{build_ipv4_udp, build_ipv6_udp};
    let header = if source.is_ipv4() { 28 } else { 48 };
    if bytes.len() + header > mtu {
        return None;
    }
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Some(build_ipv4_udp(
            src,
            dst,
            source.port(),
            destination.port(),
            bytes,
        )),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Some(build_ipv6_udp(
            src,
            dst,
            source.port(),
            destination.port(),
            bytes,
        )),
        _ => None,
    }
}

async fn bridge_tcp(
    id: u32,
    target: SocketAddr,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    commands: mpsc::Sender<Cmd>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let stream =
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(target)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                crate::logging::debug(format_args!("tailscale: LAN TCP connect failed: {error}"));
                let _ = commands.send(Cmd::TcpClose { id }).await;
                return;
            }
            Err(_) => {
                crate::logging::debug(format_args!("tailscale: LAN TCP connect timed out"));
                let _ = commands.send(Cmd::TcpClose { id }).await;
                return;
            }
        };
    let _ = stream.set_nodelay(true);
    let (mut read, mut write) = stream.into_split();
    let reader_commands = commands.clone();
    let reader = tokio::spawn(async move {
        let mut bytes = vec![0; 8192];
        while let Ok(size) = read.read(&mut bytes).await {
            if size == 0 {
                break;
            }
            if reader_commands
                .send(Cmd::TcpData {
                    id,
                    bytes: bytes[..size].to_vec(),
                })
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = reader_commands.send(Cmd::TcpEof { id }).await;
    });
    struct Guard(tokio::task::JoinHandle<()>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut guard = Guard(reader);
    while let Some(bytes) = incoming.recv().await {
        if write.write_all(&bytes).await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
    // The peer may half-close its request before the LAN service responds.
    // Keep relaying the response until the LAN read half reaches EOF.
    let _ = (&mut guard.0).await;
}

async fn forward_udp(
    flow: Flow,
    target: SocketAddr,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::Sender<Vec<u8>>,
    timeout: Duration,
    mtu: usize,
) -> io::Result<()> {
    let socket = tokio::net::UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(target).await?;
    let mut bytes = vec![0; 65535];
    let idle = tokio::time::sleep(timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = &mut idle => return Ok(()),
            packet = incoming.recv() => {
                let Some(packet)=packet else{return Ok(());};
                socket.send(&packet).await?;
                idle.as_mut().reset(tokio::time::Instant::now()+timeout);
            }
            size = socket.recv(&mut bytes) => {
                let size=size?;
                if let Some(packet)=udp_packet(flow.1,flow.0,&bytes[..size],mtu) {let _=replies.try_send(packet);}
                idle.as_mut().reset(tokio::time::Instant::now()+timeout);
            }
        }
    }
}

fn rand_seed() -> u64 {
    let mut bytes = [0; 8];
    let _ = getrandom::fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "tailscale: domain lookup failed")
            }),
    }
}
