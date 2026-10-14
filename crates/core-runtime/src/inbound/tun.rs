//! TUN inbound — virtual network interface for transparent proxying (Phase F6).
//!
//! Features:
//! - Pure-Rust TUN implementation via `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`.
//! - High-performance GRO/GSO offload support via `IFF_VNET_HDR` and `TUNSETOFFLOAD`.
//! - Userspace TCP/IP stack based on `smoltcp` supporting transparent TCP proxying without drop.
//! - Bidirectional UDP forwarding via `UdpHub` preserving original source and destination endpoints.
//! - ICMP (v4) and ICMPv6 echo responders for ping connectivity.
//! - Non-destructive policy routing (`auto_route`) using custom routing table (2022) and fwmark rules.
//! - IPv4 netmask configuration via `SIOCSIFNETMASK` and IPv6 addressing support.
//! - Strict compliance with the "None of them is silent" project convention.

#[allow(unused_imports)]
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
#[allow(unused_imports)]
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
#[allow(unused_imports)]
use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as PhyRxToken,
    TxToken as PhyTxToken,
};
#[allow(unused_imports)]
use smoltcp::socket::tcp::State as TcpState;
#[allow(unused_imports)]
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::time::Instant as SmolInstant;
#[allow(unused_imports)]
use smoltcp::wire::{HardwareAddress, Ipv4Address, Ipv6Address};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

#[allow(unused_imports)]
use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, TunReply, UdpHub};
#[allow(unused_imports)]
use crate::inbound::{ClientConn, Target, drive_framed};
use crate::logging;
use crate::outbound::urltest::parse_duration;
use crate::route::Router;

const DEFAULT_MTU: usize = 9000;
#[allow(dead_code)]
const SOCKET_BUF: usize = 65_536;
pub const VNET_HDR_LEN: usize = 10;
const DEFAULT_TABLE_INDEX: u32 = 2022;
const DEFAULT_RULE_INDEX: u32 = 9000;
#[allow(dead_code)]
const ROUTING_FWMARK: u32 = 0x2022;

const WARN_IGNORED_FIELDS: &[&str] = &[
    "netns",
    "dns_mode",
    "dns_address",
    "auto_redirect",
    "auto_redirect_input_mark",
    "auto_redirect_output_mark",
    "auto_redirect_reset_mark",
    "auto_redirect_nfqueue",
    "auto_redirect_iproute2_fallback_rule_index",
    "exclude_mptcp",
    "loopback_address",
    "route_address_set",
    "route_exclude_address_set",
    "include_interface",
    "exclude_interface",
    "include_uid",
    "include_uid_range",
    "exclude_uid",
    "exclude_uid_range",
    "include_android_user",
    "include_package",
    "exclude_package",
    "include_mac_address",
    "exclude_mac_address",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "platform",
    "endpoint_independent_nat",
];

/// virtio_net_hdr prefix used by Linux TUN with `IFF_VNET_HDR` for GRO/GSO offloading.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < VNET_HDR_LEN {
            return None;
        }
        Some(Self {
            flags: buf[0],
            gso_type: buf[1],
            hdr_len: u16::from_ne_bytes([buf[2], buf[3]]),
            gso_size: u16::from_ne_bytes([buf[4], buf[5]]),
            csum_start: u16::from_ne_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_ne_bytes([buf[8], buf[9]]),
        })
    }
}

/// Parse CIDR string (e.g. "172.19.0.1/30") into `(Ipv4Addr, u8)`.
pub(crate) fn parse_ipv4_cidr(s: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing prefix length in CIDR {s:?}"))?;
    let ip: Ipv4Addr = ip_str.parse()?;
    let prefix: u8 = prefix_str.parse()?;
    if prefix > 32 {
        anyhow::bail!("invalid IPv4 prefix length {prefix}");
    }
    Ok((ip, prefix))
}

/// Parse IPv6 CIDR string (e.g. "fdfe:dcba:9876::1/64") into `(Ipv6Addr, u8)`.
pub(crate) fn parse_ipv6_cidr(s: &str) -> anyhow::Result<(Ipv6Addr, u8)> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing prefix length in IPv6 CIDR {s:?}"))?;
    let ip: Ipv6Addr = ip_str.parse()?;
    let prefix: u8 = prefix_str.parse()?;
    if prefix > 128 {
        anyhow::bail!("invalid IPv6 prefix length {prefix}");
    }
    Ok((ip, prefix))
}

/// Convert prefix length (e.g. 30) to IPv4 netmask address.
#[allow(dead_code)]
pub(crate) fn prefix_to_ipv4_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else if prefix >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else {
        let mask = !((1u32 << (32 - prefix)) - 1);
        Ipv4Addr::from(mask)
    }
}

#[allow(dead_code)]
pub struct Tun {
    tag: String,
    interface_name: String,
    mtu: usize,
    gso: bool,
    vnet_hdr: bool,
    auto_route: bool,
    strict_route: bool,
    table_index: u32,
    rule_index: u32,
    ipv4_addrs: Vec<(Ipv4Addr, u8)>,
    ipv6_addrs: Vec<(Ipv6Addr, u8)>,
    router: Arc<Router>,
    udp_timeout: Duration,
    local_addr: SocketAddr,
    #[cfg(target_os = "linux")]
    async_fd: Arc<tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>>,
}

impl Tun {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("tun");
        let at = format!("inbound[{tag}]");

        // Log warnings for any unhonored fields from schema ("None of them is silent")
        for field in WARN_IGNORED_FIELDS {
            if obj.contains_key(*field) {
                logging::warn(format_args!(
                    "inbound tun[{tag}]: option {field:?} is not honored by runtime"
                ));
            }
        }

        let interface_name = obj
            .get("interface_name")
            .and_then(Value::as_str)
            .unwrap_or("tun0")
            .to_string();

        let mtu = obj
            .get("mtu")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .unwrap_or(DEFAULT_MTU);

        let gso = obj.get("gso").and_then(Value::as_bool).unwrap_or(false);
        let auto_route = obj
            .get("auto_route")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let strict_route = obj
            .get("strict_route")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let table_index = obj
            .get("iproute2_table_index")
            .and_then(Value::as_u64)
            .map(|v| v as u32)
            .unwrap_or(DEFAULT_TABLE_INDEX);

        let rule_index = obj
            .get("iproute2_rule_index")
            .and_then(Value::as_u64)
            .map(|v| v as u32)
            .unwrap_or(DEFAULT_RULE_INDEX);

        let udp_timeout = parse_duration(
            obj.get("udp_timeout"),
            DEFAULT_UDP_TIMEOUT,
            &format!("{at}: udp_timeout"),
        )?;

        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        let collect_addrs =
            |val: Option<&Value>, v4: &mut Vec<(Ipv4Addr, u8)>, v6: &mut Vec<(Ipv6Addr, u8)>| {
                if let Some(v) = val {
                    if let Some(s) = v.as_str() {
                        if let Ok(cidr) = parse_ipv4_cidr(s) {
                            v4.push(cidr);
                        } else if let Ok(cidr) = parse_ipv6_cidr(s) {
                            v6.push(cidr);
                        }
                    } else if let Some(arr) = v.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                if let Ok(cidr) = parse_ipv4_cidr(s) {
                                    v4.push(cidr);
                                } else if let Ok(cidr) = parse_ipv6_cidr(s) {
                                    v6.push(cidr);
                                }
                            }
                        }
                    }
                }
            };

        collect_addrs(obj.get("address"), &mut ipv4_addrs, &mut ipv6_addrs);
        collect_addrs(obj.get("inet4_address"), &mut ipv4_addrs, &mut ipv6_addrs);
        collect_addrs(obj.get("inet6_address"), &mut ipv4_addrs, &mut ipv6_addrs);

        let local_addr = ipv4_addrs
            .first()
            .map(|(ip, _)| SocketAddr::new(IpAddr::V4(*ip), 0))
            .or_else(|| {
                ipv6_addrs
                    .first()
                    .map(|(ip, _)| SocketAddr::new(IpAddr::V6(*ip), 0))
            })
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

        #[cfg(target_os = "linux")]
        {
            let (raw_fd, vnet_hdr) =
                linux::open_tun(&interface_name, mtu, &ipv4_addrs, &ipv6_addrs, gso)
                    .map_err(|err| anyhow::anyhow!("{at}: open tun {interface_name}: {err}"))?;
            let async_fd = Arc::new(tokio::io::unix::AsyncFd::new(raw_fd)?);

            if auto_route
                && let Err(e) = linux::setup_auto_route(
                    &interface_name,
                    strict_route,
                    table_index,
                    rule_index,
                    !ipv6_addrs.is_empty(),
                )
            {
                logging::warn(format_args!("inbound tun[{tag}]: auto_route warning: {e}"));
            }

            logging::info(format_args!(
                "inbound tun[{tag}] opened interface {interface_name} (mtu={mtu}, gso={vnet_hdr}, auto_route={auto_route}, v4={ipv4_addrs:?}, v6={ipv6_addrs:?})"
            ));
            Ok(Self {
                tag: tag.to_string(),
                interface_name,
                mtu,
                gso,
                vnet_hdr,
                auto_route,
                strict_route,
                table_index,
                rule_index,
                ipv4_addrs,
                ipv6_addrs,
                router,
                udp_timeout,
                local_addr,
                async_fd,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                tag,
                &interface_name,
                mtu,
                gso,
                auto_route,
                strict_route,
                table_index,
                rule_index,
                &ipv4_addrs,
                &ipv6_addrs,
                &router,
                udp_timeout,
                local_addr,
            );
            Err(anyhow::anyhow!("{at}: tun is only supported on Linux"))
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub async fn serve(self) {
        #[cfg(target_os = "linux")]
        {
            use tokio::sync::mpsc;

            let (tun_tx, mut tun_rx) = mpsc::channel::<TunReply>(1024);
            let hub = UdpHub::new(
                Arc::clone(&self.router),
                self.udp_timeout,
                DatagramFrame::Raw,
            );
            let _stop_hub = crate::inbound::udp::StopHub(Arc::clone(&hub));
            let reply = Reply::Tun { sender: tun_tx };

            let async_fd = Arc::clone(&self.async_fd);
            let async_fd_write = Arc::clone(&self.async_fd);
            let vnet_hdr = self.vnet_hdr;

            // Background worker: write UDP replies back into the TUN device
            tokio::spawn(async move {
                while let Some(reply) = tun_rx.recv().await {
                    match (reply.src, reply.dest) {
                        (SocketAddr::V4(src_v4), SocketAddr::V4(dst_v4)) => {
                            let pkt = build_ipv4_udp(
                                *src_v4.ip(),
                                *dst_v4.ip(),
                                src_v4.port(),
                                dst_v4.port(),
                                &reply.payload,
                            );
                            let _ = linux::write_packet(&async_fd_write, &pkt, vnet_hdr).await;
                        }
                        (SocketAddr::V6(src_v6), SocketAddr::V6(dst_v6)) => {
                            let pkt = build_ipv6_udp(
                                *src_v6.ip(),
                                *dst_v6.ip(),
                                src_v6.port(),
                                dst_v6.port(),
                                &reply.payload,
                            );
                            let _ = linux::write_packet(&async_fd_write, &pkt, vnet_hdr).await;
                        }
                        _ => {}
                    }
                }
            });

            // Initialize smoltcp stack for user-space TCP transparent proxying
            let mut device = TunDevice::new(self.mtu);
            let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
            let mut seed = [0u8; 8];
            crate::outbound::shadowsocks::crypto::random_bytes(&mut seed)
                .unwrap_or_else(|_| seed = [1, 2, 3, 4, 5, 6, 7, 8]);
            iconfig.random_seed = u64::from_le_bytes(seed);
            let mut iface = Interface::new(iconfig, &mut device, SmolInstant::now());
            iface.set_any_ip(true);

            let mut ip_addrs: Vec<smoltcp::wire::IpCidr> = Vec::new();
            for &(ip4, prefix) in &self.ipv4_addrs {
                ip_addrs.push(smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv4(ip4),
                    prefix,
                ));
            }
            for &(ip6, prefix) in &self.ipv6_addrs {
                ip_addrs.push(smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv6(ip6),
                    prefix,
                ));
            }
            if ip_addrs.is_empty() {
                ip_addrs.push(smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(172, 19, 0, 1)),
                    30,
                ));
            }
            // Add catch-all on-link CIDR so smoltcp can emit packets to any client IP directly over TUN
            ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::UNSPECIFIED),
                0,
            ));
            ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::UNSPECIFIED),
                0,
            ));

            iface.update_ip_addrs(|list| {
                for cidr in ip_addrs {
                    let _ = list.push(cidr);
                }
            });

            let mut sockets = SocketSet::new(Vec::new());
            let mut tcp_sessions: HashMap<(SocketAddr, SocketAddr), TunTcpSession> = HashMap::new();
            let mut scratch_buf = vec![0u8; SOCKET_BUF];

            let buf_size = if vnet_hdr {
                65536 + VNET_HDR_LEN
            } else {
                self.mtu + 64
            };
            let mut buf = vec![0u8; buf_size];
            let hdr_offset = if vnet_hdr { VNET_HDR_LEN } else { 0 };

            let notify = Arc::new(Notify::new());

            loop {
                let now = SmolInstant::now();
                let delay = match iface.poll_at(now, &sockets) {
                    Some(at) if at <= now => Duration::from_millis(1),
                    Some(at) => Duration::from_micros((at - now).total_micros())
                        .min(Duration::from_millis(50)),
                    None => Duration::from_millis(50),
                };

                tokio::select! {
                    read_res = linux::read_packet(&async_fd, &mut buf) => {
                        let n = match read_res {
                            Ok(0) => {
                                // EOF on TUN device; back off and retry to avoid 100% CPU
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            Ok(n) => n,
                            Err(e) => {
                                if e.kind() == io::ErrorKind::Interrupted {
                                    continue;
                                }
                                logging::error(format_args!("inbound tun[{}]: read error: {e}", self.tag));
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        };
                        if n <= hdr_offset + 20 {
                            continue;
                        }

                        let raw_packet = &buf[hdr_offset..n];
                        let tso_packets = if vnet_hdr && let Some(hdr) = VirtioNetHdr::parse(&buf[..VNET_HDR_LEN]) {
                            segment_tso_packet(&hdr, raw_packet)
                        } else {
                            Vec::new()
                        };

                        let dispatch_packet = |packet: &[u8], device: &mut TunDevice, sockets: &mut SocketSet<'static>, tcp_sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>| {
                            if packet.is_empty() {
                                return;
                            }
                            match packet[0] >> 4 {
                                4 => {
                                    handle_ipv4_packet(
                                        packet,
                                        &self.tag,
                                        &self.router,
                                        &hub,
                                        &reply,
                                        &async_fd,
                                        vnet_hdr,
                                        device,
                                        sockets,
                                        tcp_sessions,
                                        &notify,
                                    );
                                }
                                6 => {
                                    handle_ipv6_packet(
                                        packet,
                                        &self.tag,
                                        &self.router,
                                        &hub,
                                        &reply,
                                        &async_fd,
                                        vnet_hdr,
                                        device,
                                        sockets,
                                        tcp_sessions,
                                        &notify,
                                    );
                                }
                                _ => {}
                            }
                        };

                        if tso_packets.is_empty() {
                            dispatch_packet(raw_packet, &mut device, &mut sockets, &mut tcp_sessions);
                        } else {
                            for packet in &tso_packets {
                                dispatch_packet(packet, &mut device, &mut sockets, &mut tcp_sessions);
                            }
                        }

                        // Drive smoltcp stack immediately after packet arrival
                        drive_tun_stack(
                            &mut iface,
                            &mut device,
                            &mut sockets,
                            &mut tcp_sessions,
                            &async_fd,
                            vnet_hdr,
                            &mut scratch_buf,
                        ).await;
                    }
                    _ = notify.notified() => {
                        // Immediate wakeup when application writes data into TunStream
                        drive_tun_stack(
                            &mut iface,
                            &mut device,
                            &mut sockets,
                            &mut tcp_sessions,
                            &async_fd,
                            vnet_hdr,
                            &mut scratch_buf,
                        ).await;
                    }
                    _ = tokio::time::sleep(delay) => {
                        // Periodic/scheduled smoltcp timer poll for TCP retransmissions, ACKs, and session draining
                        drive_tun_stack(
                            &mut iface,
                            &mut device,
                            &mut sockets,
                            &mut tcp_sessions,
                            &async_fd,
                            vnet_hdr,
                            &mut scratch_buf,
                        ).await;
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
        }
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if self.auto_route {
                let _ = linux::cleanup_auto_route(
                    &self.interface_name,
                    self.table_index,
                    self.rule_index,
                    !self.ipv6_addrs.is_empty(),
                );
            }
        }
    }
}

/// A smoltcp Virtual Device feeding IP packets between TUN and user-space TCP stack.
#[allow(dead_code)]
pub(crate) struct TunDevice {
    pub(crate) mtu: usize,
    pub(crate) rx_queue: VecDeque<Vec<u8>>,
    pub(crate) tx_queue: VecDeque<Vec<u8>>,
}

impl TunDevice {
    #[allow(dead_code)]
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }
}

/// Cap on the queues between TUN and the userspace stack. A flood the stack
/// cannot drain must drop (the kernel retransmits TCP) rather than grow until
/// the OOM killer picks the daemon on a 128 MiB router.
pub(crate) const TUN_QUEUE_CAP: usize = 512;

impl Device for TunDevice {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.pop_front() {
            let rx = TunRxToken { packet };
            let tx = TunTxToken {
                queue: &mut self.tx_queue,
            };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() >= TUN_QUEUE_CAP {
            return None;
        }
        Some(TunTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

#[allow(dead_code)]
pub(crate) struct TunRxToken {
    packet: Vec<u8>,
}

impl PhyRxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[allow(dead_code)]
pub(crate) struct TunTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl PhyTxToken for TunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if self.queue.len() < TUN_QUEUE_CAP {
            self.queue.push_back(buffer);
        }
        result
    }
}

/// An active transparent TCP session bridged between `smoltcp` and Tachyon router.
#[allow(dead_code)]
pub(crate) struct TunTcpSession {
    pub(crate) handle: SocketHandle,
    pub(crate) source: SocketAddr,
    pub(crate) dest: SocketAddr,
    pub(crate) to_app: mpsc::Sender<Bytes>,
    pub(crate) from_app: mpsc::Receiver<Bytes>,
    /// Leftover of a chunk `send_slice` could not fully take; kept until the
    /// socket drains — dropping the tail would silently corrupt the TCP stream.
    pub(crate) pending_app: Option<Bytes>,
    pub(crate) created: Instant,
    pub(crate) app_closed: bool,
    pub(crate) established: bool,
}

/// AsyncRead + AsyncWrite stream adapter bridging mpsc channels to `ClientConn`.
#[allow(dead_code)]
pub(crate) struct TunStream {
    pub(crate) rx: mpsc::Receiver<Bytes>,
    pub(crate) tx: mpsc::Sender<Bytes>,
    pub(crate) notify: Arc<Notify>,
    pub(crate) current: Option<(Bytes, usize)>,
}

impl AsyncRead for TunStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut copied_any = false;
        loop {
            if let Some((chunk, offset)) = &mut self.current {
                let available = chunk.len() - *offset;
                if available > 0 {
                    let to_copy = available.min(buf.remaining());
                    buf.put_slice(&chunk[*offset..*offset + to_copy]);
                    *offset += to_copy;
                    copied_any = true;
                    if *offset >= chunk.len() {
                        self.current = None;
                    }
                    if buf.remaining() == 0 {
                        return std::task::Poll::Ready(Ok(()));
                    }
                } else {
                    self.current = None;
                }
            }

            if copied_any {
                match self.rx.try_recv() {
                    Ok(chunk) => {
                        if self.rx.len() >= 16 {
                            self.notify.notify_one();
                        }
                        self.current = Some((chunk, 0));
                    }
                    Err(_) => return std::task::Poll::Ready(Ok(())),
                }
            } else {
                match self.rx.poll_recv(cx) {
                    std::task::Poll::Ready(Some(chunk)) => {
                        if self.rx.len() >= 16 {
                            self.notify.notify_one();
                        }
                        self.current = Some((chunk, 0));
                    }
                    std::task::Poll::Ready(None) => {
                        return std::task::Poll::Ready(Ok(())); // EOF
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
        }
    }
}

impl AsyncWrite for TunStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => {
                self.notify.notify_one();
                std::task::Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Register on the channel's capacity instead of waking
                // ourselves: a self-wake spins the worker at 100% CPU until
                // the reader catches up. The one-shot reserve task drops its
                // permit before waking, so the writer can take the slot.
                let tx = self.tx.clone();
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    if tx.reserve().await.is_ok() {
                        waker.wake();
                    }
                });
                std::task::Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.notify.notify_one();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.notify.notify_one();
        std::task::Poll::Ready(Ok(()))
    }
}

/// Create a catch-all any-IP `smoltcp::iface::Interface` for virtual L3 tunnels (TUN, FPTN, MASQUE).
pub(crate) fn new_virtual_ip_iface(device: &mut TunDevice) -> Interface {
    let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
    let mut seed = [0u8; 8];
    crate::outbound::shadowsocks::crypto::random_bytes(&mut seed)
        .unwrap_or_else(|_| seed = [1, 2, 3, 4, 5, 6, 7, 8]);
    iconfig.random_seed = u64::from_le_bytes(seed);
    let mut iface = Interface::new(iconfig, device, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|list| {
        let _ = list.push(smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::UNSPECIFIED),
            0,
        ));
        let _ = list.push(smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::UNSPECIFIED),
            0,
        ));
    });
    iface
}

/// Ensure a listening virtual `smoltcp` `TcpSocket` and `drive_framed` task exist on a new SYN.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure_virtual_tcp_session(
    source: SocketAddr,
    dest: SocketAddr,
    is_syn: bool,
    tag: &str,
    router: &Arc<Router>,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    notify: &Arc<Notify>,
) {
    let key = (source, dest);
    if is_syn && !sessions.contains_key(&key) {
        let rx_buf = TcpSocketBuffer::new(vec![0u8; crate::smol_tcp_buf()]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; crate::smol_tcp_buf()]);
        let mut sock = TcpSocket::new(rx_buf, tx_buf);
        sock.set_nagle_enabled(false);
        sock.set_ack_delay(None);

        if sock.listen(dest).is_ok() {
            let handle = sockets.add(sock);
            let (to_app_tx, to_app_rx) = mpsc::channel(256);
            let (from_app_tx, from_app_rx) = mpsc::channel(256);

            let tun_stream = TunStream {
                rx: to_app_rx,
                tx: from_app_tx,
                notify: Arc::clone(notify),
                current: None,
            };

            let client = ClientConn::framed(Box::new(tun_stream), source);
            let router = Arc::clone(router);
            let tag = tag.to_string();

            tokio::spawn(async move {
                let _ = drive_framed(client, source, Target::Ip(dest), &tag, &router).await;
            });

            sessions.insert(
                key,
                TunTcpSession {
                    handle,
                    source,
                    dest,
                    to_app: to_app_tx,
                    from_app: from_app_rx,
                    pending_app: None,
                    created: Instant::now(),
                    app_closed: false,
                    established: false,
                },
            );
        }
    }
}

/// Accept a raw IPv4/IPv6 TCP packet into the virtual `smoltcp` TCP stack, spawning a `drive_framed` task on new SYNs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_virtual_tcp_packet(
    packet: &[u8],
    source: SocketAddr,
    dest: SocketAddr,
    is_syn: bool,
    tag: &str,
    router: &Arc<Router>,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    notify: &Arc<Notify>,
) {
    if device.rx_queue.len() >= TUN_QUEUE_CAP {
        return;
    }
    ensure_virtual_tcp_session(source, dest, is_syn, tag, router, sockets, sessions, notify);
    device.rx_queue.push_back(packet.to_vec());
}

/// Pump data between virtual `smoltcp` TCP sockets and application streams.
pub(crate) fn pump_virtual_tcp_sockets(
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    scratch: &mut [u8],
) {
    let mut finished = Vec::new();

    for (&key, session) in sessions.iter_mut() {
        let sock = sockets.get_mut::<TcpSocket<'static>>(session.handle);
        let state = sock.state();

        if state == TcpState::Established {
            if !session.established {
                session.established = true;
            }

            // Drain data from smoltcp socket to application stream only when
            // the channel has capacity, so recv_slice never consumes TCP bytes
            // that would be dropped on a full channel.
            while session.to_app.capacity() > 0 && sock.can_recv() {
                let mut filled = 0;
                while filled < scratch.len() && sock.can_recv() {
                    match sock.recv_slice(&mut scratch[filled..]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(_) => break,
                    }
                }
                if filled == 0 {
                    break;
                }
                let chunk = Bytes::copy_from_slice(&scratch[..filled]);
                if session.to_app.try_send(chunk).is_err() {
                    break;
                }
            }

            // Drain data from application stream to smoltcp socket
            while sock.can_send() {
                if let Some(front) = session.pending_app.take() {
                    match sock.send_slice(&front) {
                        Ok(n) if n < front.len() => {
                            session.pending_app = Some(front.slice(n..));
                            break;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                match session.from_app.try_recv() {
                    Ok(data) => match sock.send_slice(&data) {
                        Ok(n) if n < data.len() => {
                            session.pending_app = Some(data.slice(n..));
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        session.app_closed = true;
                        sock.close();
                        break;
                    }
                }
            }
        }

        if state == TcpState::Closed
            || state == TcpState::TimeWait
            || (session.app_closed && !sock.can_recv())
            || (!session.established && session.created.elapsed() >= Duration::from_secs(30))
        {
            finished.push(key);
        }
    }

    for key in finished {
        if let Some(session) = sessions.remove(&key) {
            sockets.remove(session.handle);
        }
    }
}

/// Poll `smoltcp` and pump data between virtual TCP sockets and application streams.
/// Outbound IP packets remain in `device.tx_queue` for the caller to flush.
pub(crate) fn pump_virtual_tcp_sessions(
    iface: &mut Interface,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    scratch: &mut [u8],
) {
    for _ in 0..16 {
        let now = SmolInstant::now();
        iface.poll_maintenance(now);
        while device.tx_queue.len() < TUN_QUEUE_CAP
            && iface.poll_ingress_single(now, device, sockets)
                != smoltcp::iface::PollIngressSingleResult::None
        {}
        pump_virtual_tcp_sockets(sockets, sessions, scratch);
        let now = SmolInstant::now();
        let mut progressed = false;
        while device.tx_queue.len() < TUN_QUEUE_CAP
            && iface.poll_egress(now, device, sockets)
                == smoltcp::iface::PollResult::SocketStateChanged
        {
            progressed = true;
        }
        if !progressed && device.rx_queue.is_empty() {
            break;
        }
    }
}

/// Drive smoltcp stack polling, I/O pumping and egress transmission to TUN.
#[cfg(target_os = "linux")]
async fn drive_tun_stack(
    iface: &mut Interface,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    async_fd: &Arc<tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>>,
    vnet_hdr: bool,
    scratch: &mut [u8],
) {
    pump_virtual_tcp_sessions(iface, device, sockets, sessions, scratch);

    // Flush any outbound TCP packets generated by smoltcp to the TUN interface
    while let Some(out_pkt) = device.tx_queue.pop_front() {
        let _ = linux::write_packet(async_fd, &out_pkt, vnet_hdr).await;
    }
}

/// Handle a single IPv4 packet arriving on TUN.
#[cfg(target_os = "linux")]
// Keep the explicit shared event-loop state here; grouping it would only change
// the handler interface without simplifying packet processing.
#[allow(clippy::too_many_arguments)]
fn handle_ipv4_packet(
    packet: &[u8],
    tag: &str,
    router: &Arc<Router>,
    hub: &Arc<UdpHub>,
    reply: &Reply,
    async_fd: &Arc<tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>>,
    vnet_hdr: bool,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    notify: &Arc<Notify>,
) {
    if packet.len() < 20 {
        return;
    }
    let ihl = ((packet[0] & 0x0f) * 4) as usize;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    let proto = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    match proto {
        // ICMP
        1 => {
            if packet.len() >= ihl + 8 {
                let icmp_type = packet[ihl];
                let icmp_code = packet[ihl + 1];
                // Echo Request (type 8, code 0)
                if icmp_type == 8 && icmp_code == 0 {
                    let mut reply_pkt = packet.to_vec();
                    reply_pkt[12..16].copy_from_slice(&dst_ip.octets());
                    reply_pkt[16..20].copy_from_slice(&src_ip.octets());
                    reply_pkt[10] = 0;
                    reply_pkt[11] = 0;
                    let ip_csum = ipv4_checksum(&reply_pkt[..ihl]);
                    reply_pkt[10] = (ip_csum >> 8) as u8;
                    reply_pkt[11] = ip_csum as u8;

                    reply_pkt[ihl] = 0; // Echo Reply (type 0)
                    reply_pkt[ihl + 2] = 0;
                    reply_pkt[ihl + 3] = 0;
                    let icmp_csum = ipv4_checksum(&reply_pkt[ihl..]);
                    reply_pkt[ihl + 2] = (icmp_csum >> 8) as u8;
                    reply_pkt[ihl + 3] = icmp_csum as u8;

                    let async_fd = Arc::clone(async_fd);
                    tokio::spawn(async move {
                        let _ = linux::write_packet(&async_fd, &reply_pkt, vnet_hdr).await;
                    });
                }
            }
        }
        // UDP
        17 => {
            if packet.len() >= ihl + 8 {
                let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
                if udp_len >= 8 && packet.len() >= ihl + udp_len {
                    let payload = &packet[ihl + 8..ihl + udp_len];
                    let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
                    let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);

                    if !hub.try_existing(source, dest, payload) {
                        let payload = payload.to_vec();
                        let hub = Arc::clone(hub);
                        let reply = reply.clone();
                        let tag = tag.to_string();
                        tokio::spawn(async move {
                            let _ = hub.handle(reply, source, dest, &payload, &tag).await;
                        });
                    }
                }
            }
        }
        // TCP
        6 if packet.len() >= ihl + 20 => {
            if device.rx_queue.len() >= TUN_QUEUE_CAP {
                return;
            }
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
            let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
            let key = (source, dest);

            let tcp_flags = packet[ihl + 13];
            let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;

            if is_syn && !sessions.contains_key(&key) {
                let rx_buf = TcpSocketBuffer::new(vec![0u8; crate::smol_tcp_buf()]);
                let tx_buf = TcpSocketBuffer::new(vec![0u8; crate::smol_tcp_buf()]);
                let mut sock = TcpSocket::new(rx_buf, tx_buf);

                if sock.listen(dest).is_ok() {
                    let handle = sockets.add(sock);
                    let (to_app_tx, to_app_rx) = mpsc::channel(64);
                    let (from_app_tx, from_app_rx) = mpsc::channel(64);

                    let tun_stream = TunStream {
                        rx: to_app_rx,
                        tx: from_app_tx,
                        notify: Arc::clone(notify),
                        current: None,
                    };

                    let client = ClientConn::framed(Box::new(tun_stream), source);
                    let router = Arc::clone(router);
                    let tag = tag.to_string();

                    tokio::spawn(async move {
                        let _ = drive_framed(client, source, Target::Ip(dest), &tag, &router).await;
                    });

                    sessions.insert(
                        key,
                        TunTcpSession {
                            handle,
                            source,
                            dest,
                            to_app: to_app_tx,
                            from_app: from_app_rx,
                            pending_app: None,
                            created: Instant::now(),
                            app_closed: false,
                            established: false,
                        },
                    );
                }
            }

            device.rx_queue.push_back(packet.to_vec());
        }
        _ => {}
    }
}

/// Handle a single IPv6 packet arriving on TUN.
#[cfg(target_os = "linux")]
// Mirrors the IPv4 handler and uses the same event-loop state.
#[allow(clippy::too_many_arguments)]
fn handle_ipv6_packet(
    packet: &[u8],
    tag: &str,
    router: &Arc<Router>,
    hub: &Arc<UdpHub>,
    reply: &Reply,
    async_fd: &Arc<tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>>,
    vnet_hdr: bool,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    notify: &Arc<Notify>,
) {
    if packet.len() < 40 {
        return;
    }
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&packet[8..24]);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&packet[24..40]);
    let src_ip = Ipv6Addr::from(src_bytes);
    let dst_ip = Ipv6Addr::from(dst_bytes);
    let proto = packet[6];
    let payload = &packet[40..];

    match proto {
        // ICMPv6
        58 => {
            if payload.len() >= 8 {
                let icmp_type = payload[0];
                let icmp_code = payload[1];
                // Echo Request (type 128, code 0)
                if icmp_type == 128 && icmp_code == 0 {
                    let mut reply_pkt = packet.to_vec();
                    reply_pkt[8..24].copy_from_slice(&dst_ip.octets());
                    reply_pkt[24..40].copy_from_slice(&src_ip.octets());
                    reply_pkt[40] = 129; // Echo Reply (type 129)
                    reply_pkt[42] = 0;
                    reply_pkt[43] = 0;
                    let csum = ipv6_icmp_checksum(dst_ip, src_ip, &reply_pkt[40..]);
                    reply_pkt[42] = (csum >> 8) as u8;
                    reply_pkt[43] = csum as u8;

                    let async_fd = Arc::clone(async_fd);
                    tokio::spawn(async move {
                        let _ = linux::write_packet(&async_fd, &reply_pkt, vnet_hdr).await;
                    });
                }
            }
        }
        // UDP
        17 => {
            if payload.len() >= 8 {
                let src_port = u16::from_be_bytes([payload[0], payload[1]]);
                let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
                let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                if udp_len >= 8 && payload.len() >= udp_len {
                    let data = &payload[8..udp_len];
                    let source = SocketAddr::new(IpAddr::V6(src_ip), src_port);
                    let dest = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);

                    if !hub.try_existing(source, dest, data) {
                        let data = data.to_vec();
                        let hub = Arc::clone(hub);
                        let reply = reply.clone();
                        let tag = tag.to_string();
                        tokio::spawn(async move {
                            let _ = hub.handle(reply, source, dest, &data, &tag).await;
                        });
                    }
                }
            }
        }
        // TCP
        6 if payload.len() >= 20 => {
            if device.rx_queue.len() >= TUN_QUEUE_CAP {
                return;
            }
            let src_port = u16::from_be_bytes([payload[0], payload[1]]);
            let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
            let source = SocketAddr::new(IpAddr::V6(src_ip), src_port);
            let dest = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
            let key = (source, dest);

            let tcp_flags = payload[13];
            let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;

            if is_syn && !sessions.contains_key(&key) {
                let rx_buf = TcpSocketBuffer::new(vec![0u8; crate::smol_tcp_buf()]);
                let tx_buf = TcpSocketBuffer::new(vec![0u8; crate::smol_tcp_buf()]);
                let mut sock = TcpSocket::new(rx_buf, tx_buf);

                if sock.listen(dest).is_ok() {
                    let handle = sockets.add(sock);
                    let (to_app_tx, to_app_rx) = mpsc::channel(64);
                    let (from_app_tx, from_app_rx) = mpsc::channel(64);

                    let tun_stream = TunStream {
                        rx: to_app_rx,
                        tx: from_app_tx,
                        notify: Arc::clone(notify),
                        current: None,
                    };

                    let client = ClientConn::framed(Box::new(tun_stream), source);
                    let router = Arc::clone(router);
                    let tag = tag.to_string();

                    tokio::spawn(async move {
                        let _ = drive_framed(client, source, Target::Ip(dest), &tag, &router).await;
                    });

                    sessions.insert(
                        key,
                        TunTcpSession {
                            handle,
                            source,
                            dest,
                            to_app: to_app_tx,
                            from_app: from_app_rx,
                            pending_app: None,
                            created: Instant::now(),
                            app_closed: false,
                            established: false,
                        },
                    );
                }
            }

            device.rx_queue.push_back(packet.to_vec());
        }
        _ => {}
    }
}

/// Segment a TSO super-packet into individual IP packets if GSO offloading is active.
#[allow(dead_code)]
pub(crate) fn segment_tso_packet(hdr: &VirtioNetHdr, raw_packet: &[u8]) -> Vec<Vec<u8>> {
    if hdr.gso_type == 0 || hdr.gso_size == 0 || (hdr.hdr_len as usize) >= raw_packet.len() {
        return vec![raw_packet.to_vec()];
    }

    let hdr_len = hdr.hdr_len as usize;
    let gso_size = hdr.gso_size as usize;
    let payload = &raw_packet[hdr_len..];

    if payload.len() <= gso_size {
        return vec![raw_packet.to_vec()];
    }

    let mut segments = Vec::new();
    let mut offset = 0;
    let mut seq = if raw_packet.len() >= 28 {
        u32::from_be_bytes([
            raw_packet[24],
            raw_packet[25],
            raw_packet[26],
            raw_packet[27],
        ])
    } else {
        0
    };

    while offset < payload.len() {
        let chunk_len = (payload.len() - offset).min(gso_size);
        let mut seg = Vec::with_capacity(hdr_len + chunk_len);
        seg.extend_from_slice(&raw_packet[..hdr_len]);
        seg.extend_from_slice(&payload[offset..offset + chunk_len]);

        // Update IPv4 total length and sequence number if IPv4 TCP
        if (seg[0] >> 4) == 4 && seg.len() >= 28 {
            let total_len = seg.len() as u16;
            seg[2..4].copy_from_slice(&total_len.to_be_bytes());
            seg[24..28].copy_from_slice(&seq.to_be_bytes());
            seg[10] = 0;
            seg[11] = 0;
            let ip_csum = ipv4_checksum(&seg[..20]);
            seg[10] = (ip_csum >> 8) as u8;
            seg[11] = ip_csum as u8;
        }

        segments.push(seg);
        offset += chunk_len;
        seq = seq.wrapping_add(chunk_len as u32);
    }

    segments
}

/// Compute IPv4 16-bit one's complement checksum.
pub(crate) fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Construct a raw IPv4 UDP packet.
#[allow(dead_code)]
pub(crate) fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];

    // IPv4 header (20 bytes)
    pkt[0] = 0x45; // Version 4, IHL 5
    pkt[1] = 0x00; // DSCP / ECN
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    pkt[4] = 0x00; // Identification
    pkt[5] = 0x00;
    pkt[6] = 0x40; // Flags: Don't Fragment (DF)
    pkt[7] = 0x00;
    pkt[8] = 64; // TTL
    pkt[9] = 17; // Protocol: UDP
    pkt[10] = 0; // Checksum placeholder
    pkt[11] = 0;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ip_csum = ipv4_checksum(&pkt[..20]);
    pkt[10] = (ip_csum >> 8) as u8;
    pkt[11] = ip_csum as u8;

    // UDP header (8 bytes)
    let udp_len = 8 + payload.len();
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[26] = 0; // Checksum optional for IPv4 UDP
    pkt[27] = 0;

    // Payload
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// Construct a raw IPv6 UDP packet with RFC-compliant checksum.
#[allow(dead_code)]
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
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes());
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

/// RFC 2460 IPv6 UDP checksum calculation.
#[allow(dead_code)]
pub(crate) fn ipv6_udp_checksum(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> u16 {
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

/// IPv6 ICMPv6 checksum calculation.
#[allow(dead_code)]
pub(crate) fn ipv6_icmp_checksum(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = payload.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += 58u32; // Next Header: ICMPv6

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

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::unix::AsyncFd;

    use super::{ROUTING_FWMARK, VNET_HDR_LEN, prefix_to_ipv4_netmask};

    const IFF_VNET_HDR: libc::c_int = 0x4000;
    const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
    const TUN_F_CSUM: libc::c_uint = 0x01;
    const TUN_F_TSO4: libc::c_uint = 0x02;
    const TUN_F_TSO6: libc::c_uint = 0x04;

    pub fn open_tun(
        name: &str,
        mtu: usize,
        v4_addrs: &[(Ipv4Addr, u8)],
        v6_addrs: &[(Ipv6Addr, u8)],
        gso: bool,
    ) -> io::Result<(RawFd, bool)> {
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, byte) in name_bytes[..copy_len].iter().enumerate() {
            ifreq.ifr_name[i] = *byte as libc::c_char;
        }

        let mut vnet_hdr = false;
        if gso {
            ifreq.ifr_ifru.ifru_flags =
                (libc::IFF_TUN | libc::IFF_NO_PI | IFF_VNET_HDR) as libc::c_short;
            let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF as _, &ifreq) };
            if ret >= 0 {
                vnet_hdr = true;
                let offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
                let _ = unsafe { libc::ioctl(fd, TUNSETOFFLOAD as _, offload) };
            }
        }

        if !vnet_hdr {
            ifreq.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
            let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF as _, &ifreq) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }
        }

        // Configure MTU and bring UP
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock >= 0 {
            ifreq.ifr_ifru.ifru_mtu = mtu as libc::c_int;
            let _ = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifreq) };

            let _ = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifreq) };
            unsafe {
                ifreq.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            }
            let _ = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifreq) };

            // Configure IPv4 address and netmask via SIOCSIFADDR and SIOCSIFNETMASK
            if let Some(&(ip, prefix)) = v4_addrs.first() {
                let mut addr_req: libc::ifreq = unsafe { std::mem::zeroed() };
                for (i, byte) in name_bytes[..copy_len].iter().enumerate() {
                    addr_req.ifr_name[i] = *byte as libc::c_char;
                }
                let sin: *mut libc::sockaddr_in =
                    unsafe { &mut addr_req.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in };
                unsafe {
                    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin).sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
                    let _ = libc::ioctl(sock, libc::SIOCSIFADDR as _, &addr_req);
                }

                // SIOCSIFNETMASK
                let mask = prefix_to_ipv4_netmask(prefix);
                let sin_mask: *mut libc::sockaddr_in = unsafe {
                    &mut addr_req.ifr_ifru.ifru_netmask as *mut _ as *mut libc::sockaddr_in
                };
                unsafe {
                    (*sin_mask).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin_mask).sin_addr.s_addr = u32::from_ne_bytes(mask.octets());
                    let _ = libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &addr_req);
                }
            }
            unsafe { libc::close(sock) };
        }

        // Configure IPv6 addresses if any
        for &(ip6, prefix) in v6_addrs {
            let _ = std::process::Command::new("ip")
                .args(["-6", "addr", "add", &format!("{ip6}/{prefix}"), "dev", name])
                .status();
        }

        Ok((fd, vnet_hdr))
    }

    /// Non-destructive routing: configure table `table` and policy rule without breaking WAN
    pub fn setup_auto_route(
        iface: &str,
        strict: bool,
        table: u32,
        pref: u32,
        has_v6: bool,
    ) -> io::Result<()> {
        let table_str = table.to_string();
        let pref_str = pref.to_string();
        let suppress_pref_str = (pref.saturating_sub(1)).to_string();
        let fwmark_str = format!("0x{ROUTING_FWMARK:x}");

        // 1. Route default to tun0 in custom table
        let status = std::process::Command::new("ip")
            .args([
                "route", "replace", "default", "dev", iface, "table", &table_str,
            ])
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "ip route replace default dev {iface} table {table} failed"
            )));
        }

        // 2. Suppress prefixlength 0 in main table so LAN/router local traffic works
        let _ = std::process::Command::new("ip")
            .args([
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "pref",
                &suppress_pref_str,
            ])
            .status();

        // 3. Direct traffic not marked with proxy fwmark into table 2022
        let _ = std::process::Command::new("ip")
            .args([
                "rule",
                "add",
                "not",
                "fwmark",
                &fwmark_str,
                "lookup",
                &table_str,
                "pref",
                &pref_str,
            ])
            .status();

        if strict {
            let _ = std::process::Command::new("ip")
                .args([
                    "route",
                    "add",
                    "blackhole",
                    "default",
                    "table",
                    &table_str,
                    "metric",
                    "1024",
                ])
                .status();
        }

        if has_v6 {
            let _ = std::process::Command::new("ip")
                .args([
                    "-6", "route", "replace", "default", "dev", iface, "table", &table_str,
                ])
                .status();
            let _ = std::process::Command::new("ip")
                .args([
                    "-6",
                    "rule",
                    "add",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                    "pref",
                    &suppress_pref_str,
                ])
                .status();
            let _ = std::process::Command::new("ip")
                .args([
                    "-6",
                    "rule",
                    "add",
                    "not",
                    "fwmark",
                    &fwmark_str,
                    "lookup",
                    &table_str,
                    "pref",
                    &pref_str,
                ])
                .status();
        }

        Ok(())
    }

    /// Clean up added ip rules and routes
    pub fn cleanup_auto_route(_iface: &str, table: u32, pref: u32, has_v6: bool) -> io::Result<()> {
        let table_str = table.to_string();
        let pref_str = pref.to_string();
        let suppress_pref_str = (pref.saturating_sub(1)).to_string();
        let fwmark_str = format!("0x{ROUTING_FWMARK:x}");

        let _ = std::process::Command::new("ip")
            .args([
                "rule",
                "del",
                "not",
                "fwmark",
                &fwmark_str,
                "lookup",
                &table_str,
                "pref",
                &pref_str,
            ])
            .status();
        let _ = std::process::Command::new("ip")
            .args([
                "rule",
                "del",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "pref",
                &suppress_pref_str,
            ])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["route", "flush", "table", &table_str])
            .status();

        if has_v6 {
            let _ = std::process::Command::new("ip")
                .args([
                    "-6",
                    "rule",
                    "del",
                    "not",
                    "fwmark",
                    &fwmark_str,
                    "lookup",
                    &table_str,
                    "pref",
                    &pref_str,
                ])
                .status();
            let _ = std::process::Command::new("ip")
                .args([
                    "-6",
                    "rule",
                    "del",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                    "pref",
                    &suppress_pref_str,
                ])
                .status();
            let _ = std::process::Command::new("ip")
                .args(["-6", "route", "flush", "table", &table_str])
                .status();
        }

        Ok(())
    }

    pub async fn read_packet(async_fd: &AsyncFd<RawFd>, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = async_fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_packet(
        async_fd: &AsyncFd<RawFd>,
        pkt: &[u8],
        vnet_hdr: bool,
    ) -> io::Result<usize> {
        if vnet_hdr {
            let zero_hdr = [0u8; VNET_HDR_LEN];
            loop {
                let mut guard = async_fd.writable().await?;
                match guard.try_io(|inner| {
                    let iov = [
                        libc::iovec {
                            iov_base: zero_hdr.as_ptr() as *mut libc::c_void,
                            iov_len: VNET_HDR_LEN,
                        },
                        libc::iovec {
                            iov_base: pkt.as_ptr() as *mut libc::c_void,
                            iov_len: pkt.len(),
                        },
                    ];
                    let n = unsafe { libc::writev(inner.as_raw_fd(), iov.as_ptr(), 2) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(res) => return res,
                    Err(_would_block) => continue,
                }
            }
        } else {
            write_raw(async_fd, pkt).await
        }
    }

    async fn write_raw(async_fd: &AsyncFd<RawFd>, data: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = async_fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_valid() {
        let (ip, prefix) = parse_ipv4_cidr("172.19.0.1/30").unwrap();
        assert_eq!(ip, Ipv4Addr::new(172, 19, 0, 1));
        assert_eq!(prefix, 30);
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_ipv4_cidr("172.19.0.1").is_err());
        assert!(parse_ipv4_cidr("172.19.0.1/33").is_err());
    }

    #[test]
    fn parse_ipv6_cidr_valid() {
        let (ip, prefix) = parse_ipv6_cidr("fdfe:dcba:9876::1/64").unwrap();
        assert_eq!(ip, "fdfe:dcba:9876::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 64);
    }

    #[test]
    fn prefix_to_netmask_calculation() {
        assert_eq!(
            prefix_to_ipv4_netmask(30),
            Ipv4Addr::new(255, 255, 255, 252)
        );
        assert_eq!(prefix_to_ipv4_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(
            prefix_to_ipv4_netmask(32),
            Ipv4Addr::new(255, 255, 255, 255)
        );
        assert_eq!(prefix_to_ipv4_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn virtio_net_hdr_size() {
        assert_eq!(std::mem::size_of::<VirtioNetHdr>(), VNET_HDR_LEN);
    }

    #[test]
    fn virtio_net_hdr_parsing() {
        let buf = [0x01, 0x02, 0x28, 0x00, 0xb8, 0x05, 0x00, 0x00, 0x00, 0x00];
        let hdr = VirtioNetHdr::parse(&buf).expect("parse");
        assert_eq!(hdr.flags, 1);
        assert_eq!(hdr.gso_type, 2);
        assert_eq!(hdr.hdr_len, 40);
        assert_eq!(hdr.gso_size, 1464);
    }

    #[test]
    fn ipv4_udp_packet_and_checksum() {
        let payload = b"ping test";
        let pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1234,
            5678,
            payload,
        );
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[9], 17); // UDP
        let csum = ipv4_checksum(&pkt[..20]);
        assert_eq!(csum, 0); // Self-cancelling with embedded csum
    }

    #[test]
    fn ipv6_udp_packet_builder() {
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let payload = b"ipv6 payload";
        let pkt = build_ipv6_udp(src, dst, 53, 54321, payload);
        assert_eq!(pkt.len(), 40 + 8 + payload.len());
        assert_eq!(pkt[0] >> 4, 6);
        assert_eq!(pkt[6], 17); // UDP
    }

    #[test]
    fn icmp_checksum_calc() {
        let header = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let csum = ipv4_checksum(&header);
        assert_ne!(csum, 0);
    }

    #[test]
    fn segment_tso_super_packet() {
        let hdr = VirtioNetHdr {
            flags: 0,
            gso_type: 1, // TCPv4
            hdr_len: 40,
            gso_size: 100,
            csum_start: 0,
            csum_offset: 0,
        };
        let mut raw = vec![0u8; 40 + 250];
        raw[0] = 0x45;
        let segments = segment_tso_packet(&hdr, &raw);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 40 + 100);
        assert_eq!(segments[1].len(), 40 + 100);
        assert_eq!(segments[2].len(), 40 + 50);
    }

    #[test]
    fn tun_device_smoltcp_capabilities() {
        let dev = TunDevice::new(1500);
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1500);
    }

    #[test]
    fn smoltcp_syn_ack_generation() {
        use smoltcp::wire::{
            IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl,
            TcpPacket, TcpRepr,
        };

        let mut device = TunDevice::new(1500);
        let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
        iconfig.random_seed = 12345678;
        let mut iface = Interface::new(iconfig, &mut device, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|list| {
            list.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(172, 19, 200, 1)),
                30,
            ))
            .unwrap();
        });

        let mut sockets = SocketSet::new(Vec::new());
        let rx_buf = TcpSocketBuffer::new(vec![0u8; 1024]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; 1024]);
        let mut sock = TcpSocket::new(rx_buf, tx_buf);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 200, 2)), 45000);
        assert!(sock.listen(dest).is_ok());
        sockets.add(sock);

        // Build TCP SYN packet
        let tcp_repr = TcpRepr {
            src_port: 12345,
            dst_port: 45000,
            control: TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(100),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(172, 19, 200, 1),
            dst_addr: Ipv4Address::new(172, 19, 200, 2),
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.header_len(),
            hop_limit: 64,
        };

        let mut pkt_bytes = vec![0u8; ip_repr.buffer_len() + tcp_repr.header_len()];
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut pkt_bytes);
        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::ignored());
        let mut tcp_packet = TcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_repr.emit(
            &mut tcp_packet,
            &IpAddress::Ipv4(ip_repr.src_addr),
            &IpAddress::Ipv4(ip_repr.dst_addr),
            &ChecksumCapabilities::ignored(),
        );

        device.rx_queue.push_back(pkt_bytes);
        let now = SmolInstant::now();
        let polled = iface.poll(now, &mut device, &mut sockets);
        println!(
            "iface.poll returned: {polled:?}, tx_queue len: {}",
            device.tx_queue.len()
        );
        assert!(
            !device.tx_queue.is_empty(),
            "expected SYN-ACK packet in tx_queue"
        );
    }
}
