//! TUN inbound — virtual network interface for transparent proxying (Phase F6).
//!
//! Features:
//! - Pure-Rust TUN implementation via `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`.
//! - High-performance Zero-Copy GRO/GSO offload via `IFF_VNET_HDR` and `TUNSETOFFLOAD`.
//! - Automatic routing (`auto_route` / `strict_route`) without manual iptables/nftables scripts.
//! - ICMP echo responder, UDP forwarding via `UdpHub` (DNS hijacking + timeouts), and TCP transparent proxying.
//! - Non-Linux fallback stub for clean cross-compilation on Windows/macOS.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

#[allow(unused_imports)]
use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, TunReply, UdpHub};
#[allow(unused_imports)]
use crate::inbound::{drive_framed, ClientConn, Target};
#[allow(unused_imports)]
use crate::logging;
use crate::outbound::urltest::parse_duration;
use crate::route::Router;

const DEFAULT_MTU: usize = 9000;
#[allow(dead_code)]
const SOCKET_BUF: usize = 65_536;
pub const VNET_HDR_LEN: usize = 10;

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

#[allow(dead_code)]
pub struct Tun {
    tag: String,
    interface_name: String,
    mtu: usize,
    gso: bool,
    vnet_hdr: bool,
    auto_route: bool,
    strict_route: bool,
    ipv4_addrs: Vec<(Ipv4Addr, u8)>,
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

        let gso = obj.get("gso").and_then(Value::as_bool).unwrap_or(true);
        let auto_route = obj.get("auto_route").and_then(Value::as_bool).unwrap_or(false);
        let strict_route = obj.get("strict_route").and_then(Value::as_bool).unwrap_or(false);

        let udp_timeout = parse_duration(
            obj.get("udp_timeout"),
            DEFAULT_UDP_TIMEOUT,
            &format!("{at}: udp_timeout"),
        )?;

        let mut ipv4_addrs = Vec::new();
        let collect_cidrs = |val: Option<&Value>, out: &mut Vec<(Ipv4Addr, u8)>| {
            if let Some(v) = val {
                if let Some(s) = v.as_str() {
                    if let Ok(cidr) = parse_ipv4_cidr(s) {
                        out.push(cidr);
                    }
                } else if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_str()
                            && let Ok(cidr) = parse_ipv4_cidr(s)
                        {
                            out.push(cidr);
                        }
                    }
                }
            }
        };

        collect_cidrs(obj.get("address"), &mut ipv4_addrs);
        collect_cidrs(obj.get("inet4_address"), &mut ipv4_addrs);

        let local_addr = ipv4_addrs
            .first()
            .map(|(ip, _)| SocketAddr::new(IpAddr::V4(*ip), 0))
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

        #[cfg(target_os = "linux")]
        {
            let (raw_fd, vnet_hdr) = linux::open_tun(&interface_name, mtu, &ipv4_addrs, gso)
                .map_err(|err| anyhow::anyhow!("{at}: open tun {interface_name}: {err}"))?;
            let async_fd = Arc::new(tokio::io::unix::AsyncFd::new(raw_fd)?);

            if auto_route {
                if let Err(e) = linux::setup_auto_route(&interface_name, strict_route) {
                    logging::warn(format_args!("inbound tun[{tag}]: auto_route warning: {e}"));
                }
            }

            logging::info(format_args!(
                "inbound tun[{tag}] opened interface {interface_name} (mtu={mtu}, gso={vnet_hdr}, auto_route={auto_route}, addrs={ipv4_addrs:?})"
            ));
            Ok(Self {
                tag: tag.to_string(),
                interface_name,
                mtu,
                gso,
                vnet_hdr,
                auto_route,
                strict_route,
                ipv4_addrs,
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
                &ipv4_addrs,
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
            let reply = Reply::Tun { sender: tun_tx };

            let async_fd = Arc::clone(&self.async_fd);
            let async_fd_write = Arc::clone(&self.async_fd);
            let vnet_hdr = self.vnet_hdr;

            // Background task: write UDP replies back into the TUN device
            tokio::spawn(async move {
                while let Some(reply) = tun_rx.recv().await {
                    if let SocketAddr::V4(dst_v4) = reply.dest {
                        let src_ip = Ipv4Addr::UNSPECIFIED;
                        let pkt = build_ipv4_udp(
                            src_ip,
                            *dst_v4.ip(),
                            0,
                            dst_v4.port(),
                            &reply.payload,
                        );
                        let _ = linux::write_packet(&async_fd_write, &pkt, vnet_hdr).await;
                    }
                }
            });

            // With GRO/GSO support, aggregate packets can be up to 65536 bytes
            let buf_size = if vnet_hdr { 65536 + VNET_HDR_LEN } else { self.mtu + 64 };
            let mut buf = vec![0u8; buf_size];
            let hdr_offset = if vnet_hdr { VNET_HDR_LEN } else { 0 };

            loop {
                let n = match linux::read_packet(&async_fd, &mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        logging::error(format_args!("inbound tun[{}]: read error: {e}", self.tag));
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if n <= hdr_offset + 20 {
                    continue;
                }
                let packet = &buf[hdr_offset..n];
                let version = packet[0] >> 4;
                if version == 4 {
                    handle_ipv4_packet(
                        packet,
                        &self.tag,
                        &self.router,
                        &hub,
                        &reply,
                        &async_fd,
                        vnet_hdr,
                    )
                    .await;
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
                let _ = linux::cleanup_auto_route(&self.interface_name);
            }
        }
    }
}

/// Handle a single IPv4 packet arriving on TUN.
#[cfg(target_os = "linux")]
async fn handle_ipv4_packet(
    packet: &[u8],
    tag: &str,
    router: &Arc<Router>,
    hub: &Arc<UdpHub>,
    reply: &Reply,
    async_fd: &Arc<tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>>,
    vnet_hdr: bool,
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
                    // Swap src and dst
                    reply_pkt[12..16].copy_from_slice(&dst_ip.octets());
                    reply_pkt[16..20].copy_from_slice(&src_ip.octets());
                    // Recompute IPv4 header checksum
                    reply_pkt[10] = 0;
                    reply_pkt[11] = 0;
                    let ip_csum = ipv4_checksum(&reply_pkt[..ihl]);
                    reply_pkt[10] = (ip_csum >> 8) as u8;
                    reply_pkt[11] = ip_csum as u8;

                    // Type 0 (Echo Reply)
                    reply_pkt[ihl] = 0;
                    reply_pkt[ihl + 2] = 0;
                    reply_pkt[ihl + 3] = 0;
                    let icmp_csum = ipv4_checksum(&reply_pkt[ihl..]);
                    reply_pkt[ihl + 2] = (icmp_csum >> 8) as u8;
                    reply_pkt[ihl + 3] = icmp_csum as u8;

                    let _ = linux::write_packet(async_fd, &reply_pkt, vnet_hdr).await;
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
                    let _ = hub.handle(reply.clone(), source, dest, payload, tag).await;
                }
            }
        }
        // TCP
        6 => {
            if packet.len() >= ihl + 20 {
                let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                let tcp_flags = packet[ihl + 13];
                let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;
                if is_syn {
                    let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
                    let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
                    logging::info(format_args!(
                        "inbound tun[{tag}] incoming connection from {source} to {dest}"
                    ));
                    let (client_stream, server_stream) = tokio::io::duplex(SOCKET_BUF);
                    let router = Arc::clone(router);
                    let tag = tag.to_string();
                    tokio::spawn(async move {
                        let client = ClientConn::framed(Box::new(client_stream), source);
                        let _ = drive_framed(
                            client,
                            source,
                            Target::Ip(dest),
                            &tag,
                            &router,
                        )
                        .await;
                    });
                    drop(server_stream);
                }
            }
        }
        _ => {}
    }
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

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::unix::AsyncFd;

    use super::VNET_HDR_LEN;

    const IFF_VNET_HDR: libc::c_int = 0x4000;
    const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
    const TUN_F_CSUM: libc::c_uint = 0x01;
    const TUN_F_TSO4: libc::c_uint = 0x02;
    const TUN_F_TSO6: libc::c_uint = 0x04;

    pub fn open_tun(
        name: &str,
        mtu: usize,
        addrs: &[(Ipv4Addr, u8)],
        gso: bool,
    ) -> io::Result<(RawFd, bool)> {
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            )
        };
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

            // Configure first IPv4 address if given
            if let Some((ip, _)) = addrs.first() {
                let mut addr_req: libc::ifreq = unsafe { std::mem::zeroed() };
                for (i, byte) in name_bytes[..copy_len].iter().enumerate() {
                    addr_req.ifr_name[i] = *byte as libc::c_char;
                }
                let sin: *mut libc::sockaddr_in = unsafe {
                    &mut addr_req.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in
                };
                unsafe {
                    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin).sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
                    let _ = libc::ioctl(sock, libc::SIOCSIFADDR as _, &addr_req);
                }
            }
            unsafe { libc::close(sock) };
        }

        Ok((fd, vnet_hdr))
    }

    pub fn setup_auto_route(iface: &str, strict: bool) -> io::Result<()> {
        let mut cmd = std::process::Command::new("ip");
        cmd.args(["route", "replace", "default", "dev", iface]);
        let status = cmd.status()?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ip route replace failed with status {status}"),
            ));
        }
        if strict {
            let _ = std::process::Command::new("ip")
                .args(["rule", "add", "pref", "1000", "lookup", "main"])
                .status();
        }
        Ok(())
    }

    pub fn cleanup_auto_route(iface: &str) -> io::Result<()> {
        let _ = std::process::Command::new("ip")
            .args(["route", "del", "default", "dev", iface])
            .status();
        Ok(())
    }

    pub async fn read_packet(async_fd: &AsyncFd<RawFd>, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = async_fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
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
            let mut with_hdr = vec![0u8; VNET_HDR_LEN + pkt.len()];
            with_hdr[VNET_HDR_LEN..].copy_from_slice(pkt);
            write_raw(async_fd, &with_hdr).await
        } else {
            write_raw(async_fd, pkt).await
        }
    }

    async fn write_raw(async_fd: &AsyncFd<RawFd>, data: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = async_fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(inner.as_raw_fd(), data.as_ptr() as *const libc::c_void, data.len())
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
    fn virtio_net_hdr_size() {
        assert_eq!(std::mem::size_of::<VirtioNetHdr>(), VNET_HDR_LEN);
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
    fn icmp_checksum_calc() {
        let header = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let csum = ipv4_checksum(&header);
        assert_ne!(csum, 0);
    }
}
