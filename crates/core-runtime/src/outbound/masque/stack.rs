//! MASQUE userspace stack — one smoltcp interface pumping IP packets over
//! the CONNECT-IP tunnel (reference `wireguard.DeviceOptions` + gVisor shell
//! in `protocol/masque/outbound.go`, ported onto the WireGuard stack shell).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::sync::{mpsc, oneshot};

use crate::logging;

use super::MasqueCfg;
use super::h2::H2Conn;
use super::h3::H3Conn;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

const EPHEMERAL_BASE: u16 = 49152;

const SOCKET_BUF: usize = 65_536;
const SCRATCH_BUF: usize = 16_384;
const CMD_QUEUE: usize = 256;
const REPLY_QUEUE: usize = 64;
const EGRESS_BUF_MAX: usize = 1 << 20;

/// Established CONNECT-IP tunnel, chosen by `vhttp`.
pub(crate) enum Leg {
    H3(H3Conn),
    H2(H2Conn),
}

impl Leg {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Leg::H3(conn) => conn.read_packet().await,
            Leg::H2(conn) => conn.read_packet().await,
        }
    }

    async fn write_packet(&mut self, pkt: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
        match self {
            Leg::H3(conn) => conn.write_packet(pkt).await,
            Leg::H2(conn) => conn.write_packet(pkt).await,
        }
    }

    fn close(&mut self) {
        match self {
            Leg::H3(conn) => conn.close(),
            Leg::H2(conn) => conn.close(),
        }
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        self.close();
    }
}

/// `UdpOpen` completion: local port + reply stream.
pub(crate) type UdpReply = oneshot::Sender<Result<(u16, mpsc::Receiver<Vec<u8>>), String>>;

pub(crate) enum Cmd {
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
    to_caller: mpsc::Sender<Vec<u8>>,
}

struct MasqueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl MasqueDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

struct MasqueRxToken {
    buffer: Vec<u8>,
}

impl PhyRxToken for MasqueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct MasqueTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl PhyTxToken for MasqueTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for MasqueDevice {
    type RxToken<'a> = MasqueRxToken;
    type TxToken<'a> = MasqueTxToken<'a>;

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
            let rx = MasqueRxToken { buffer };
            let tx = MasqueTxToken {
                queue: &mut self.tx,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(MasqueTxToken {
            queue: &mut self.tx,
        })
    }
}

struct Stack {
    cfg: Arc<MasqueCfg>,
    device: MasqueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<u32, TcpConn>,
    udp: HashMap<u16, UdpSess>,
    next_port: u16,
    scratch: Vec<u8>,
    /// Egress packets built outside smoltcp (UDP sessions) awaiting the leg.
    out_q: VecDeque<Vec<u8>>,
    last_activity: Instant,
}

impl Stack {
    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == u16::MAX {
            EPHEMERAL_BASE
        } else {
            port + 1
        };
        port
    }

    fn process_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::TcpConnect {
                id,
                dst,
                to_caller,
                resp,
            } => {
                if !dst.is_ipv4() {
                    let _ = resp.send(Err("masque: ipv6 target not supported".into()));
                    return;
                }
                let IpAddr::V4(dst_ip) = dst.ip() else {
                    let _ = resp.send(Err("masque: ipv6 target not supported".into()));
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
                if let Err(e) = socket.connect(
                    self.iface.context(),
                    (IpAddress::from(dst_ip), dst.port()),
                    port,
                ) {
                    let _ = resp.send(Err(format!("masque connect: {e:?}")));
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
                if !target.is_ipv4() {
                    let _ = resp.send(Err("masque: ipv6 target not supported".into()));
                    return;
                }
                let port = self.alloc_port();
                let (tx, rx) = mpsc::channel(REPLY_QUEUE);
                self.udp.insert(
                    port,
                    UdpSess {
                        target,
                        to_caller: tx,
                    },
                );
                let _ = resp.send(Ok((port, rx)));
            }
            Cmd::UdpSend { port, bytes } => {
                let Some(sess) = self.udp.get(&port) else {
                    return;
                };
                let IpAddr::V4(target_ip) = sess.target.ip() else {
                    return;
                };
                let dport = sess.target.port();
                let src = self.cfg.local_addr;
                let pkt = build_ipv4_udp(src, target_ip, port, dport, &bytes);
                self.out_q.push_back(pkt);
            }
            Cmd::UdpClose { port } => {
                self.udp.remove(&port);
            }
        }
    }

    /// Demux incoming tunnel packets: our virtual UDP sessions first, the
    /// smoltcp interface for everything else.
    fn on_tunnel_packet(&mut self, pkt: Vec<u8>) {
        let Some((src, dst, proto, hdr_len)) = ipv4_info(&pkt) else {
            return;
        };
        if !cidr_contains_v4(self.cfg.local_cidr, dst) {
            return;
        }
        if proto == 17 && pkt.len() >= hdr_len + 8 {
            let sport = u16::from_be_bytes([pkt[hdr_len], pkt[hdr_len + 1]]);
            let dport = u16::from_be_bytes([pkt[hdr_len + 2], pkt[hdr_len + 3]]);
            if let Some(sess) = self.udp.get(&dport)
                && sess.target.ip() == IpAddr::V4(src)
                && (sess.target.port() == sport || sess.target.port() == 0)
            {
                let payload = pkt[hdr_len + 8..].to_vec();
                let _ = sess.to_caller.try_send(payload);
                return;
            }
        }
        self.device.rx.push_back(pkt);
    }

    /// Write all queued packets into the tunnel; an ICMP too-big reply from
    /// the leg goes back into the stack.
    async fn flush_leg(&mut self, leg: &mut Leg) -> io::Result<()> {
        while let Some(mut pkt) = self
            .device
            .tx
            .pop_front()
            .or_else(|| self.out_q.pop_front())
        {
            match leg.write_packet(&mut pkt).await? {
                None => {}
                Some(icmp) => self.device.rx.push_back(icmp),
            }
        }
        Ok(())
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

    fn idle_expired(&self) -> bool {
        self.cfg
            .idle_timeout
            .is_some_and(|d| self.last_activity.elapsed() >= d)
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
        for conn in self.tcp.values() {
            if conn.resp.is_some() {
                consider(conn.created + CONNECT_TIMEOUT);
            }
        }
        if let Some(idle) = self.cfg.idle_timeout {
            consider(self.last_activity + idle);
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

/// One stack task: smoltcp over the CONNECT-IP leg, commands from the
/// outbound, tunnels packets in both directions. Exits when the caller side
/// drops (`rx` closed), the leg dies, or the idle window elapses — the next
/// dial rebuilds everything.
pub(crate) async fn run(
    cfg: Arc<MasqueCfg>,
    mut leg: Leg,
    mut rx: mpsc::Receiver<Cmd>,
) -> io::Result<()> {
    let mut device = MasqueDevice::new(cfg.mtu);
    let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
    let mut seed = [0u8; 8];
    crate::outbound::shadowsocks::crypto::random_bytes(&mut seed)?;
    iconfig.random_seed = u64::from_le_bytes(seed);
    let mut iface = Interface::new(iconfig, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|list| {
        let _ = list.push(cfg.local_cidr);
    });
    // Medium::Ip never consults the gateway, but a default route is required
    // so non-local destinations egress instead of being dropped.
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);

    let mut stack = Stack {
        cfg,
        device,
        iface,
        sockets: SocketSet::new(Vec::new()),
        tcp: HashMap::new(),
        udp: HashMap::new(),
        next_port: EPHEMERAL_BASE,
        scratch: vec![0u8; SCRATCH_BUF],
        out_q: VecDeque::new(),
        last_activity: Instant::now(),
    };

    loop {
        while let Ok(cmd) = rx.try_recv() {
            stack.process_cmd(cmd);
            stack.last_activity = Instant::now();
        }
        stack.poll_stack();
        stack.flush_leg(&mut leg).await?;
        stack.maintain_tcp();
        if stack.idle_expired() {
            logging::debug(format_args!(
                "masque[{}]: idle-suspend tunnel",
                stack.cfg.tag
            ));
            return Ok(());
        }
        let deadline = stack.next_deadline();
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(cmd) => {
                    stack.process_cmd(cmd);
                    stack.last_activity = Instant::now();
                }
                None => return Ok(()),
            },
            pkt = leg.read_packet() => match pkt {
                Ok(pkt) => {
                    stack.on_tunnel_packet(pkt);
                    stack.last_activity = Instant::now();
                }
                Err(e) => return Err(e),
            },
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

/// Wrap a payload into an IPv4/UDP packet (checksums: header computed, UDP
/// left zero — legal for IPv4).
fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
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

/// Membership test for an IPv4 address in the stack's local prefix
/// (smoltcp `IpCidr` has no `contains`).
fn cidr_contains_v4(cidr: IpCidr, ip: Ipv4Addr) -> bool {
    #[allow(unreachable_patterns)]
    match cidr.address() {
        IpAddress::Ipv4(net) => {
            let bits = cidr.prefix_len();
            if bits == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - bits as u32);
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        _ => false,
    }
}

/// Parse an IPv4 packet header: `(src, dst, protocol, header_len)`.
fn ipv4_info(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, usize)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let hdr_len = (pkt[0] & 0x0f) as usize * 4;
    if hdr_len < 20 || pkt.len() < hdr_len {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst, pkt[9], hdr_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_udp_roundtrip() {
        let src = Ipv4Addr::new(172, 16, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let payload = b"hello connect-ip";
        let pkt = build_ipv4_udp(src, dst, 40000, 53, payload);
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        let (got_src, got_dst, proto, hdr) = ipv4_info(&pkt).expect("parse");
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);
        assert_eq!(proto, 17);
        assert_eq!(hdr, 20);
        let sport = u16::from_be_bytes([pkt[20], pkt[21]]);
        let dport = u16::from_be_bytes([pkt[22], pkt[23]]);
        assert_eq!((sport, dport), (40000, 53));
        assert_eq!(&pkt[28..], payload);
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
        assert!(ipv4_info(&[0u8; 10]).is_none());
    }

    #[test]
    fn local_cidr_membership() {
        let cidr: IpCidr = "172.16.0.2/24".parse().expect("cidr");
        assert!(cidr_contains_v4(cidr, Ipv4Addr::new(172, 16, 0, 7)));
        assert!(!cidr_contains_v4(cidr, Ipv4Addr::new(172, 16, 1, 7)));
        let host: IpCidr = "172.16.0.2/32".parse().expect("cidr");
        assert!(cidr_contains_v4(host, Ipv4Addr::new(172, 16, 0, 2)));
        assert!(!cidr_contains_v4(host, Ipv4Addr::new(172, 16, 0, 3)));
    }
}
