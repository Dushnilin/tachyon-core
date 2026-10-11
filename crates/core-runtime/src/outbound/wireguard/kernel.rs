//! Linux Kernel Netlink driver for WireGuard and AmneziaWG (Feature #13).
//!
//! Provides kernel offload capabilities for WireGuard and AmneziaWG data planes:
//! - Direct rtnetlink (`RTM_NEWLINK` / `RTM_DELLINK`) interface lifecycle management.
//! - Generic Netlink (`genetlink`) family resolution via `GENL_ID_CTRL`.
//! - Device and peer configuration via `WG_CMD_SET_DEVICE` with full key, endpoint,
//!   keepalive, and allowed-IP attributes.
//! - Native AmneziaWG obfuscation offload attributes (`jc`, `jmin`, `jmax`, `s1`, `s2`,
//!   `h1`, `h2`, `h3`, `h4`) for `amneziawg.ko` kernel module.
//! - Pure-Rust packet serialization with zero external C-dependencies.

#![allow(dead_code, unused_imports)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{PeerConfig, WgConfig};
use crate::logging;

// Netlink message flags and types
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_EXCL: u16 = 0x0200;
pub const NLM_F_CREATE: u16 = 0x0400;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;

pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_INFO_KIND: u16 = 1;

pub const GENL_ID_CTRL: u16 = 16;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// WireGuard Netlink commands and attributes
pub const WG_CMD_SET_DEVICE: u8 = 1;

pub const WGDEVICE_A_IFNAME: u16 = 2;
pub const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
pub const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
pub const WGDEVICE_A_FLAGS: u16 = 5;
pub const WGDEVICE_A_LISTEN_PORT: u16 = 6;
pub const WGDEVICE_A_PEERS: u16 = 8;
pub const WGDEVICE_F_REPLACE_PEERS: u32 = 1;

// AmneziaWG Netlink extension attributes (amneziawg.ko)
pub const WGDEVICE_A_JC: u16 = 9;
pub const WGDEVICE_A_JMIN: u16 = 10;
pub const WGDEVICE_A_JMAX: u16 = 11;
pub const WGDEVICE_A_S1: u16 = 12;
pub const WGDEVICE_A_S2: u16 = 13;
pub const WGDEVICE_A_H1: u16 = 14;
pub const WGDEVICE_A_H2: u16 = 15;
pub const WGDEVICE_A_H3: u16 = 16;
pub const WGDEVICE_A_H4: u16 = 17;

pub const WGPEER_A_PUBLIC_KEY: u16 = 1;
pub const WGPEER_A_PRESHARED_KEY: u16 = 2;
pub const WGPEER_A_FLAGS: u16 = 3;
pub const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
pub const WGPEER_A_ENDPOINT: u16 = 4;
pub const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
pub const WGPEER_A_ALLOWEDIPS: u16 = 9;

pub const WGALLOWEDIP_A_FAMILY: u16 = 1;
pub const WGALLOWEDIP_A_IPADDR: u16 = 2;
pub const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

pub const NLA_F_NESTED: u16 = 0x8000;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Pure-Rust buffer builder for Netlink datagrams.
#[derive(Debug, Default, Clone)]
pub struct NetlinkBuffer {
    data: Vec<u8>,
}

impl NetlinkBuffer {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(512),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
        }
    }

    /// Appends an nlmsghdr placeholder; returns offset to nlmsg_len.
    pub fn push_nlmsghdr(&mut self, nlmsg_type: u16, flags: u16, seq: u32, pid: u32) {
        let len_placeholder: u32 = 0;
        self.data.extend_from_slice(&len_placeholder.to_ne_bytes());
        self.data.extend_from_slice(&nlmsg_type.to_ne_bytes());
        self.data.extend_from_slice(&flags.to_ne_bytes());
        self.data.extend_from_slice(&seq.to_ne_bytes());
        self.data.extend_from_slice(&pid.to_ne_bytes());
    }

    /// Appends genlmsghdr (cmd, version, reserved).
    pub fn push_genlmsghdr(&mut self, cmd: u8, version: u8) {
        self.data.push(cmd);
        self.data.push(version);
        self.data.extend_from_slice(&0u16.to_ne_bytes());
    }

    /// Appends ifinfomsg (family, pad, type, index, flags, change).
    pub fn push_ifinfomsg(&mut self, family: u8, ifi_type: u16, index: i32, flags: u32) {
        self.data.push(family);
        self.data.push(0); // pad
        self.data.extend_from_slice(&ifi_type.to_ne_bytes());
        self.data.extend_from_slice(&index.to_ne_bytes());
        self.data.extend_from_slice(&flags.to_ne_bytes());
        self.data.extend_from_slice(&0u32.to_ne_bytes()); // change mask
    }

    /// Appends an attribute with arbitrary bytes and pads to 4-byte boundary.
    pub fn push_attr(&mut self, nla_type: u16, payload: &[u8]) {
        let unaligned_len = 4 + payload.len();
        assert!(unaligned_len <= u16::MAX as usize);
        let nla_len = unaligned_len as u16;

        self.data.extend_from_slice(&nla_len.to_ne_bytes());
        self.data.extend_from_slice(&nla_type.to_ne_bytes());
        self.data.extend_from_slice(payload);

        let pad = (4 - (payload.len() % 4)) % 4;
        for _ in 0..pad {
            self.data.push(0);
        }
    }

    pub fn push_u8(&mut self, nla_type: u16, val: u8) {
        self.push_attr(nla_type, &[val]);
    }

    pub fn push_u16(&mut self, nla_type: u16, val: u16) {
        self.push_attr(nla_type, &val.to_ne_bytes());
    }

    pub fn push_u32(&mut self, nla_type: u16, val: u32) {
        self.push_attr(nla_type, &val.to_ne_bytes());
    }

    pub fn push_str(&mut self, nla_type: u16, s: &str) {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // NUL-terminated
        self.push_attr(nla_type, &bytes);
    }

    /// Starts a nested attribute; returns offset of `nla_len`.
    pub fn start_nested(&mut self, nla_type: u16) -> usize {
        let offset = self.data.len();
        let placeholder: u16 = 0;
        self.data.extend_from_slice(&placeholder.to_ne_bytes());
        let nested_type = nla_type | NLA_F_NESTED;
        self.data.extend_from_slice(&nested_type.to_ne_bytes());
        offset
    }

    /// Closes a nested attribute and updates `nla_len`.
    pub fn end_nested(&mut self, offset: usize) {
        let len = (self.data.len() - offset) as u16;
        self.data[offset..offset + 2].copy_from_slice(&len.to_ne_bytes());
        // Align overall nested attribute
        let pad = (4 - (self.data.len() % 4)) % 4;
        for _ in 0..pad {
            self.data.push(0);
        }
    }

    /// Finalizes the message by writing the total length into the leading `nlmsg_len`.
    pub fn finish(mut self) -> Vec<u8> {
        let total_len = self.data.len() as u32;
        self.data[0..4].copy_from_slice(&total_len.to_ne_bytes());
        self.data
    }
}

/// Encodes `RTM_NEWLINK` message to create an interface of kind `kind` (`"amneziawg"` or `"wireguard"`).
pub fn encode_rtnetlink_newlink(iface: &str, kind: &str, seq: u32) -> Vec<u8> {
    let mut buf = NetlinkBuffer::new();
    buf.push_nlmsghdr(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        0,
    );
    buf.push_ifinfomsg(0, 0, 0, 0);
    buf.push_str(IFLA_IFNAME, iface);

    let linkinfo = buf.start_nested(IFLA_LINKINFO);
    buf.push_str(IFLA_INFO_KIND, kind);
    buf.end_nested(linkinfo);

    buf.finish()
}

/// Encodes `RTM_DELLINK` message to delete an interface.
pub fn encode_rtnetlink_dellink(iface: &str, seq: u32) -> Vec<u8> {
    let mut buf = NetlinkBuffer::new();
    buf.push_nlmsghdr(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
    buf.push_ifinfomsg(0, 0, 0, 0);
    buf.push_str(IFLA_IFNAME, iface);
    buf.finish()
}

/// Encodes `CTRL_CMD_GETFAMILY` to resolve generic netlink family name.
pub fn encode_genl_get_family(family_name: &str, seq: u32) -> Vec<u8> {
    let mut buf = NetlinkBuffer::new();
    buf.push_nlmsghdr(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
    buf.push_genlmsghdr(CTRL_CMD_GETFAMILY, 1);
    buf.push_str(CTRL_ATTR_FAMILY_NAME, family_name);
    buf.finish()
}

/// Parses the generic netlink family ID from a controller response.
pub fn parse_genl_family_id(reply: &[u8]) -> Option<u16> {
    // nlmsghdr (16 bytes) + genlmsghdr (4 bytes) = 20 bytes minimum
    if reply.len() < 20 {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= reply.len() {
        let nla_len = u16::from_ne_bytes([reply[offset], reply[offset + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([reply[offset + 2], reply[offset + 3]]) & !NLA_F_NESTED;
        if nla_len < 4 || offset + nla_len > reply.len() {
            break;
        }
        let payload = &reply[offset + 4..offset + nla_len];
        if nla_type == CTRL_ATTR_FAMILY_ID && payload.len() >= 2 {
            return Some(u16::from_ne_bytes([payload[0], payload[1]]));
        }
        let aligned = (nla_len + 3) & !3;
        offset += aligned;
    }
    None
}

/// Formats a `sockaddr` endpoint for `WGPEER_A_ENDPOINT`.
pub fn format_endpoint_sockaddr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut out = vec![0u8; 16];
            out[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&v4.ip().octets());
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = vec![0u8; 28];
            out[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            out[8..24].copy_from_slice(&v6.ip().octets());
            out
        }
    }
}

/// Encodes `WG_CMD_SET_DEVICE` for WireGuard / AmneziaWG kernel configuration.
pub(crate) fn encode_wg_set_device(
    family_id: u16,
    seq: u32,
    iface: &str,
    cfg: &WgConfig,
    resolved_peers: &[Option<SocketAddr>],
) -> Vec<u8> {
    let mut buf = NetlinkBuffer::with_capacity(1024);
    buf.push_nlmsghdr(family_id, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
    buf.push_genlmsghdr(WG_CMD_SET_DEVICE, 1);

    buf.push_str(WGDEVICE_A_IFNAME, iface);
    buf.push_attr(WGDEVICE_A_PRIVATE_KEY, &cfg.private_key);
    buf.push_u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    if cfg.listen_port > 0 {
        buf.push_u16(WGDEVICE_A_LISTEN_PORT, cfg.listen_port);
    }

    // AmneziaWG obfuscation attributes if present
    if let Some(awg) = &cfg.awg {
        buf.push_u32(WGDEVICE_A_JC, awg.junk_count);
        buf.push_u32(WGDEVICE_A_JMIN, awg.junk_min);
        buf.push_u32(WGDEVICE_A_JMAX, awg.junk_max);
        buf.push_u32(WGDEVICE_A_S1, awg.paddings[0] as u32);
        buf.push_u32(WGDEVICE_A_S2, awg.paddings[1] as u32);
        buf.push_u32(WGDEVICE_A_H1, awg.headers[0].0);
        buf.push_u32(WGDEVICE_A_H2, awg.headers[1].0);
        buf.push_u32(WGDEVICE_A_H3, awg.headers[2].0);
        buf.push_u32(WGDEVICE_A_H4, awg.headers[3].0);
    }

    // Peers
    let peers_attr = buf.start_nested(WGDEVICE_A_PEERS);
    for (i, peer) in cfg.peers.iter().enumerate() {
        let peer_entry = buf.start_nested(i as u16);
        buf.push_attr(WGPEER_A_PUBLIC_KEY, &peer.public_key);
        if let Some(psk) = peer.pre_shared_key {
            buf.push_attr(WGPEER_A_PRESHARED_KEY, &psk);
        }
        buf.push_u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
        if let Some(Some(ep)) = resolved_peers.get(i) {
            buf.push_attr(WGPEER_A_ENDPOINT, &format_endpoint_sockaddr(*ep));
        }
        if let Some((ka, _)) = peer.keepalive {
            buf.push_u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, ka as u16);
        }

        // Allowed IPs
        let allowed_ips_attr = buf.start_nested(WGPEER_A_ALLOWEDIPS);
        let mut ip_idx = 0u16;
        for (net, bits) in &peer.allowed_ips_v4 {
            let entry = buf.start_nested(ip_idx);
            buf.push_u16(WGALLOWEDIP_A_FAMILY, AF_INET);
            buf.push_attr(WGALLOWEDIP_A_IPADDR, &net.to_be_bytes());
            buf.push_u8(WGALLOWEDIP_A_CIDR_MASK, *bits);
            buf.end_nested(entry);
            ip_idx += 1;
        }
        for (net, bits) in &peer.allowed_ips_v6 {
            let entry = buf.start_nested(ip_idx);
            buf.push_u16(WGALLOWEDIP_A_FAMILY, AF_INET6);
            buf.push_attr(WGALLOWEDIP_A_IPADDR, &net.to_be_bytes());
            buf.push_u8(WGALLOWEDIP_A_CIDR_MASK, *bits);
            buf.end_nested(entry);
            ip_idx += 1;
        }
        buf.end_nested(allowed_ips_attr);

        buf.end_nested(peer_entry);
    }
    buf.end_nested(peers_attr);

    buf.finish()
}

/// Represents an active kernel WireGuard / AmneziaWG interface.
#[derive(Debug)]
pub struct KernelWireGuard {
    pub iface: String,
    pub created_link: bool,
}

impl Drop for KernelWireGuard {
    fn drop(&mut self) {
        if self.created_link {
            #[cfg(target_os = "linux")]
            let _ = linux::delete_interface(&self.iface);
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn setup_kernel_wireguard(
    cfg: &WgConfig,
    iface: &str,
) -> anyhow::Result<KernelWireGuard> {
    linux::setup(cfg, iface).await
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn setup_kernel_wireguard(
    _cfg: &WgConfig,
    _iface: &str,
) -> anyhow::Result<KernelWireGuard> {
    anyhow::bail!("system wireguard / amneziawg kernel offload is only supported on Linux");
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::time::Duration;

    pub async fn setup(cfg: &WgConfig, iface: &str) -> anyhow::Result<KernelWireGuard> {
        let is_awg = cfg.awg.is_some();
        let primary_kind = if is_awg { "amneziawg" } else { "wireguard" };

        // 1. Create network interface via rtnetlink or fallback
        let mut created_link = false;
        match create_interface(iface, primary_kind) {
            Ok(()) => {
                created_link = true;
            }
            Err(e) => {
                // If it already exists (EEXIST), proceed without taking ownership of deletion
                if e.raw_os_error() == Some(libc::EEXIST) {
                    logging::debug(format_args!(
                        "kernel wireguard: interface {iface} already exists, reconfiguring"
                    ));
                } else if is_awg {
                    // Try fallback to standard "wireguard" if amneziawg kernel module is absent
                    match create_interface(iface, "wireguard") {
                        Ok(()) => {
                            created_link = true;
                            logging::warn(format_args!(
                                "kernel wireguard: amneziawg.ko not present, falling back to wireguard.ko for {iface}"
                            ));
                        }
                        Err(e2) => {
                            if e2.raw_os_error() == Some(libc::EEXIST) {
                                logging::debug(format_args!(
                                    "kernel wireguard: interface {iface} already exists"
                                ));
                            } else {
                                anyhow::bail!(
                                    "failed to create kernel interface {iface}: {e} / {e2}"
                                );
                            }
                        }
                    }
                } else {
                    anyhow::bail!("failed to create kernel interface {iface}: {e}");
                }
            }
        }

        // 2. Resolve peer addresses
        let mut resolved_peers = Vec::new();
        for peer in &cfg.peers {
            if peer.host.is_empty() {
                resolved_peers.push(None);
            } else if let Ok(ip) = peer.host.parse::<IpAddr>() {
                resolved_peers.push(Some(SocketAddr::new(ip, peer.port)));
            } else {
                match tokio::net::lookup_host(format!("{}:{}", peer.host, peer.port)).await {
                    Ok(mut addrs) => resolved_peers.push(addrs.next()),
                    Err(e) => {
                        logging::warn(format_args!(
                            "kernel wireguard: failed to resolve peer {}: {e}",
                            peer.host
                        ));
                        resolved_peers.push(None);
                    }
                }
            }
        }

        // 3. Resolve Generic Netlink family ID
        let family_name = if is_awg { "amneziawg" } else { "wireguard" };
        let family_id = match resolve_genl_family(family_name) {
            Ok(id) => id,
            Err(_) if is_awg => resolve_genl_family("wireguard")
                .map_err(|e| anyhow::anyhow!("generic netlink wireguard family not found: {e}"))?,
            Err(e) => anyhow::bail!("generic netlink wireguard family not found: {e}"),
        };

        // 4. Send WG_CMD_SET_DEVICE configuration
        let set_dev_msg = encode_wg_set_device(family_id, 1, iface, cfg, &resolved_peers);
        send_netlink_request(libc::NETLINK_GENERIC, &set_dev_msg)?;

        // 5. Configure MTU, addresses and bring link UP
        configure_link_and_addresses(iface, cfg.mtu, cfg)?;

        Ok(KernelWireGuard {
            iface: iface.to_string(),
            created_link,
        })
    }

    pub fn create_interface(iface: &str, kind: &str) -> io::Result<()> {
        let msg = encode_rtnetlink_newlink(iface, kind, 1);
        send_netlink_request(libc::NETLINK_ROUTE, &msg)
    }

    pub fn delete_interface(iface: &str) -> io::Result<()> {
        let msg = encode_rtnetlink_dellink(iface, 1);
        send_netlink_request(libc::NETLINK_ROUTE, &msg)
    }

    fn resolve_genl_family(family_name: &str) -> io::Result<u16> {
        let req = encode_genl_get_family(family_name, 1);
        let reply = send_netlink_roundtrip(libc::NETLINK_GENERIC, &req)?;
        parse_genl_family_id(&reply).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("family {family_name} not found in genl reply"),
            )
        })
    }

    fn send_netlink_request(proto: libc::c_int, msg: &[u8]) -> io::Result<()> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        struct FdGuard(RawFd);
        impl Drop for FdGuard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = FdGuard(fd);

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

        let ret = unsafe {
            libc::sendto(
                fd,
                msg.as_ptr() as *const _,
                msg.len(),
                0,
                &sa as *const _ as *const _,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Wait for ACK or error response
        let mut buf = [0u8; 1024];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n >= 20 {
            let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
            if nlmsg_type == 2 {
                // NLMSG_ERROR
                let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                if err != 0 {
                    return Err(io::Error::from_raw_os_error(-err));
                }
            }
        }

        Ok(())
    }

    fn send_netlink_roundtrip(proto: libc::c_int, msg: &[u8]) -> io::Result<Vec<u8>> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        struct FdGuard(RawFd);
        impl Drop for FdGuard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = FdGuard(fd);

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

        let ret = unsafe {
            libc::sendto(
                fd,
                msg.as_ptr() as *const _,
                msg.len(),
                0,
                &sa as *const _ as *const _,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf = vec![0u8; 8192];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn configure_link_and_addresses(iface: &str, mtu: usize, cfg: &WgConfig) -> io::Result<()> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        struct SockGuard(RawFd);
        impl Drop for SockGuard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SockGuard(sock);

        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let iface_bytes = iface.as_bytes();
        let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, b) in iface_bytes[..copy_len].iter().enumerate() {
            ifreq.ifr_name[i] = *b as libc::c_char;
        }

        // 1. Set MTU
        if mtu > 0 {
            ifreq.ifr_ifru.ifru_mtu = mtu as libc::c_int;
            let _ = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifreq) };
        }

        // 2. Set IPv4 address and netmask if configured
        if let Some(v4) = cfg.local_addr_v4 {
            let sin: *mut libc::sockaddr_in =
                unsafe { &mut ifreq.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in };
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                let _ = libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifreq);
            }
            // SIOCSIFNETMASK
            let sin_mask: *mut libc::sockaddr_in =
                unsafe { &mut ifreq.ifr_ifru.ifru_netmask as *mut _ as *mut libc::sockaddr_in };
            unsafe {
                (*sin_mask).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin_mask).sin_addr.s_addr = u32::from_be(0xFFFFFFFF);
                let _ = libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifreq);
            }
        }

        // 3. Bring UP
        let _ = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifreq) };
        unsafe {
            ifreq.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let _ = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifreq);
        }

        // 4. Configure IPv6 address if present
        if let Some(v6) = cfg.local_addr_v6 {
            let _ = std::process::Command::new("ip")
                .args(["-6", "addr", "add", &format!("{v6}/128"), "dev", iface])
                .status();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_rtnetlink_newlink() {
        let msg = encode_rtnetlink_newlink("wg0", "wireguard", 42);
        assert!(msg.len() >= 32);
        let total_len = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]);
        assert_eq!(total_len as usize, msg.len());
        let nlmsg_type = u16::from_ne_bytes([msg[4], msg[5]]);
        assert_eq!(nlmsg_type, RTM_NEWLINK);
        let seq = u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_encode_genl_get_family() {
        let msg = encode_genl_get_family("amneziawg", 1);
        assert!(msg.len() >= 20);
        let nlmsg_type = u16::from_ne_bytes([msg[4], msg[5]]);
        assert_eq!(nlmsg_type, GENL_ID_CTRL);
        let cmd = msg[16];
        assert_eq!(cmd, CTRL_CMD_GETFAMILY);
    }

    #[test]
    fn test_parse_genl_family_id() {
        // Construct a synthetic controller response
        let mut buf = NetlinkBuffer::new();
        buf.push_nlmsghdr(GENL_ID_CTRL, 0, 1, 0);
        buf.push_genlmsghdr(CTRL_CMD_GETFAMILY, 1);
        buf.push_str(CTRL_ATTR_FAMILY_NAME, "wireguard");
        buf.push_u16(CTRL_ATTR_FAMILY_ID, 25);
        let wire = buf.finish();

        let id = parse_genl_family_id(&wire);
        assert_eq!(id, Some(25));
    }

    #[test]
    fn test_encode_wg_set_device_plain() {
        let cfg = WgConfig {
            tag: "wg-test".to_string(),
            private_key: [1u8; 32],
            public_key: [2u8; 32],
            listen_port: 51820,
            mtu: 1420,
            local_cidrs: Vec::new(),
            local_addr_v4: Some(Ipv4Addr::new(10, 0, 0, 2)),
            local_addr_v6: None,
            peers: vec![PeerConfig {
                host: "1.2.3.4".to_string(),
                port: 51820,
                public_key: [3u8; 32],
                pre_shared_key: Some([4u8; 32]),
                allowed_ips_v4: vec![(u32::from(Ipv4Addr::new(0, 0, 0, 0)), 0)],
                allowed_ips_v6: vec![],
                keepalive: Some((25, 25)),
            }],
            udp_timeout: std::time::Duration::from_secs(30),
            awg: None,
        };

        let resolved = vec![Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            51820,
        ))];
        let msg = encode_wg_set_device(30, 2, "wg0", &cfg, &resolved);
        assert!(msg.len() > 100);
        let total_len = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]);
        assert_eq!(total_len as usize, msg.len());
        let nlmsg_type = u16::from_ne_bytes([msg[4], msg[5]]);
        assert_eq!(nlmsg_type, 30);
    }

    #[test]
    fn test_encode_wg_set_device_awg() {
        let awg = crate::outbound::wireguard::awg::AwgParams {
            junk_count: 4,
            junk_min: 10,
            junk_max: 20,
            paddings: [15, 25, 0, 0],
            headers: [(1000, 1000), (2000, 2000), (3, 3), (4000, 4000)],
            ipackets: [None, None, None, None, None],
            header_protection: None,
            content_padding: None,
            rekey_after_time: None,
            rekey_timeout: None,
            reject_after_time: None,
            keepalive_timeout: None,
            max_handshake_attempts: None,
            random_trailers: false,
            disable_cookies: false,
        };

        let cfg = WgConfig {
            tag: "awg-test".to_string(),
            private_key: [5u8; 32],
            public_key: [6u8; 32],
            listen_port: 0,
            mtu: 1408,
            local_cidrs: Vec::new(),
            local_addr_v4: Some(Ipv4Addr::new(10, 8, 0, 2)),
            local_addr_v6: None,
            peers: vec![PeerConfig {
                host: "203.0.113.1".to_string(),
                port: 12345,
                public_key: [7u8; 32],
                pre_shared_key: None,
                allowed_ips_v4: vec![(u32::from(Ipv4Addr::new(10, 8, 0, 0)), 24)],
                allowed_ips_v6: vec![],
                keepalive: Some((20, 20)),
            }],
            udp_timeout: std::time::Duration::from_secs(30),
            awg: Some(std::sync::Arc::new(awg)),
        };

        let resolved = vec![Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            12345,
        ))];
        let msg = encode_wg_set_device(35, 3, "awg0", &cfg, &resolved);
        assert!(msg.len() > 150);
        let total_len = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]);
        assert_eq!(total_len as usize, msg.len());
    }
}
