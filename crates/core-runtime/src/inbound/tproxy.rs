use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use tokio::net::{TcpListener, UdpSocket};

use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, UdpHub};
use crate::inbound::{Target, drive_transparent, network_includes_udp, parse_listen};
use crate::logging;
use crate::outbound::urltest::parse_duration;
use crate::route::Router;

/// tproxy inbound: TCP with `IP_TRANSPARENT` / `IPV6_TRANSPARENT`; destination
/// = local address of the accepted socket (TPROXY preserves the original
/// destination there). UDP additionally sets `IP_RECVORIGDSTADDR` and recovers
/// the original destination from cmsg (reference `redir.TProxy` +
/// `GetOriginalDestinationFromOOB`). Requires Linux + CAP_NET_ADMIN; other
/// platforms and missing capability fail at bind (reference `tproxy_other.go`).
pub struct Tproxy {
    listener: Option<TcpListener>,
    udp: Option<Arc<UdpSocket>>,
    tag: String,
    router: Arc<Router>,
    udp_timeout: std::time::Duration,
}

impl Tproxy {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("tproxy");
        let at = format!("inbound[{tag}]");
        let want_tcp = !network_includes_udp(obj)
            || obj.get("network").and_then(Value::as_str).is_none_or(|n| {
                n.split(',')
                    .map(str::trim)
                    .any(|p| p.eq_ignore_ascii_case("tcp"))
            });
        let want_udp = network_includes_udp(obj);
        if !want_tcp && !want_udp {
            anyhow::bail!("{at}: network excludes both tcp and udp");
        }
        let (ip, port) = parse_listen(obj, &at)?;
        let addr = SocketAddr::new(ip, port);

        let listener = if want_tcp {
            Some(bind_tproxy(addr).map_err(|err| anyhow::anyhow!("{at}: {err}"))?)
        } else {
            None
        };
        let bound_port = match &listener {
            Some(l) => l.local_addr()?.port(),
            None => port,
        };
        let udp = if want_udp {
            let sock = bind_tproxy_udp(SocketAddr::new(ip, bound_port))
                .map_err(|err| anyhow::anyhow!("{at}: udp: {err}"))?;
            Some(Arc::new(sock))
        } else {
            None
        };
        let udp_timeout = parse_duration(
            obj.get("udp_timeout"),
            DEFAULT_UDP_TIMEOUT,
            &format!("{at}: udp_timeout"),
        )?;

        logging::info(format_args!(
            "inbound tproxy[{tag}] listening at {ip}:{bound_port} (tcp={}, udp={})",
            listener.is_some(),
            udp.is_some()
        ));
        Ok(Self {
            listener,
            udp,
            tag: tag.to_string(),
            router,
            udp_timeout,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        if let Some(l) = &self.listener {
            return l.local_addr();
        }
        self.udp
            .as_ref()
            .map(|u| u.local_addr())
            .unwrap_or_else(|| Err(io::Error::other("tproxy inbound: no listener")))
    }

    pub async fn serve(self) {
        let Self {
            listener,
            udp,
            tag,
            router,
            udp_timeout,
        } = self;
        let (tcp_tag, tcp_router) = (tag.clone(), Arc::clone(&router));
        let tcp = async move {
            let Some(listener) = listener else {
                std::future::pending::<()>().await;
                return;
            };
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let router = Arc::clone(&tcp_router);
                        let tag = tcp_tag.clone();
                        let destination = match stream.local_addr() {
                            Ok(addr) => Target::Ip(addr),
                            Err(err) => {
                                logging::error(format_args!(
                                    "tproxy[{tag}] {peer}: local address: {err}"
                                ));
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            if let Err(err) =
                                drive_transparent(stream, peer, destination, &tag, &router).await
                            {
                                logging::debug(format_args!("tproxy[{tag}] {peer}: {err}"));
                            }
                        });
                    }
                    Err(err) => {
                        logging::warn(format_args!("tproxy[{tcp_tag}] accept: {err}"));
                        return;
                    }
                }
            }
        };
        let udp_loop = async move {
            let Some(sock) = udp else {
                std::future::pending::<()>().await;
                return;
            };
            let hub = UdpHub::new(Arc::clone(&router), udp_timeout, DatagramFrame::Raw);
            let fallback = Target::Ip(match sock.local_addr() {
                Ok(a) => a,
                Err(_) => return,
            });
            let mut buf = vec![0u8; 64 * 1024];
            #[cfg(target_os = "linux")]
            let mut oob = vec![0u8; 256];
            loop {
                #[cfg(target_os = "linux")]
                let received: io::Result<(usize, SocketAddr, Option<SocketAddr>)> = {
                    use std::os::unix::io::AsRawFd;
                    match sock.readable().await {
                        Ok(()) => recvmsg_with_oob(sock.as_raw_fd(), &mut buf, &mut oob),
                        Err(err) => Err(err),
                    }
                };
                #[cfg(not(target_os = "linux"))]
                let received: io::Result<(usize, SocketAddr, Option<SocketAddr>)> = {
                    sock.recv_from(&mut buf)
                        .await
                        .map(|(n, source)| (n, source, None))
                };
                match received {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        // Ready guard from readable() already cleared readiness.
                        continue;
                    }
                    Err(err) => {
                        logging::warn(format_args!("tproxy[{tag}] udp recv: {err}"));
                        return;
                    }
                    Ok((n, source, orig)) => {
                        let dest = orig.unwrap_or_else(|| {
                            let Target::Ip(a) = &fallback else {
                                return source;
                            };
                            *a
                        });
                        let hub = Arc::clone(&hub);
                        let reply = Reply::Socket(Arc::clone(&sock));
                        let tag = tag.clone();
                        let payload = buf[..n].to_vec();
                        tokio::spawn(async move {
                            if let Err(err) = hub.handle(reply, source, dest, &payload, &tag).await
                            {
                                logging::debug(format_args!("tproxy[{tag}] udp {source}: {err}"));
                            }
                        });
                    }
                }
            }
        };
        tokio::select! {
            _ = tcp => {}
            _ = udp_loop => {}
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_tproxy(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

#[cfg(target_os = "linux")]
fn bind_tproxy_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    // reference redir.TProxy(fd, isIPv6, isUDP=true)
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
        set_raw_int(&socket, libc::IPPROTO_IP, IP_RECVORIGDSTADDR)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
        set_raw_int(&socket, libc::IPPROTO_IPV6, IPV6_RECVORIGDSTADDR)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_sock)
}

/// socket2 0.6 dropped `set_raw_opt`; use libc setsockopt on the raw fd.
#[cfg(target_os = "linux")]
fn set_raw_int(socket: &socket2::Socket, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let yes: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Blocking `recvmsg` with cmsg extraction; called from the async fn after
/// `readable()` so WouldBlock is retried by the caller.
fn recvmsg_with_oob(
    fd: i32,
    buf: &mut [u8],
    oob: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of_val(&addr) as libc::socklen_t;
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = addr_len;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = oob.as_mut_ptr() as *mut libc::c_void;
    #[allow(clippy::unnecessary_cast)]
    {
        msg.msg_controllen = oob.len() as _;
    }

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    addr_len = msg.msg_namelen;
    let source = sockaddr_to_socket(&addr, addr_len)?;
    let orig = extract_orig_dst(&msg)?;
    Ok((n as usize, source, orig))
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socket(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    use std::mem;
    unsafe {
        match i32::from(storage.ss_family) {
            libc::AF_INET if len as usize >= mem::size_of::<libc::sockaddr_in>() => {
                let sa = *(&storage as *const _ as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                let port = u16::from_be(sa.sin_port);
                Ok(SocketAddr::from((ip, port)))
            }
            libc::AF_INET6 if len as usize >= mem::size_of::<libc::sockaddr_in6>() => {
                let sa = *(&storage as *const _ as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                let port = u16::from_be(sa.sin6_port);
                Ok(SocketAddr::from((ip, port)))
            }
            family => Err(io::Error::other(format!("unexpected family {family}"))),
        }
    }
}

/// Reference `GetOriginalDestinationFromOOB` for IP_RECVORIGDSTADDR /
/// IPV6_RECVORIGDSTADDR control messages.
#[cfg(target_os = "linux")]
fn extract_orig_dst(msg: &libc::msghdr) -> io::Result<Option<SocketAddr>> {
    if msg.msg_controllen == 0 {
        return Ok(None);
    }
    let mut cmsg_ptr = msg.msg_control as *const libc::cmsghdr;
    // musl: msg_controllen/cmsg_len are u32; glibc: usize — keep casts for both.
    #[allow(clippy::unnecessary_cast)]
    let end = unsafe { (msg.msg_control as *const u8).add(msg.msg_controllen as usize) };
    while (cmsg_ptr as *const u8) < end {
        let cmsg = unsafe { &*cmsg_ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == 20
        /* IP_RECVORIGDSTADDR */
        {
            #[allow(clippy::unnecessary_cast)]
            let data = unsafe {
                std::slice::from_raw_parts(
                    libc::CMSG_DATA(cmsg) as *const u8,
                    cmsg.cmsg_len as usize - libc::CMSG_LEN(0) as usize,
                )
            };
            if data.len() >= 8 {
                let sa = unsafe { *(data.as_ptr() as *const libc::sockaddr_in) };
                let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                let port = u16::from_be(sa.sin_port);
                return Ok(Some(SocketAddr::from((ip, port))));
            }
        } else if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == 74 {
            #[allow(clippy::unnecessary_cast)]
            let data = unsafe {
                std::slice::from_raw_parts(
                    libc::CMSG_DATA(cmsg) as *const u8,
                    cmsg.cmsg_len as usize - libc::CMSG_LEN(0) as usize,
                )
            };
            if data.len() >= 24 {
                let sa = unsafe { *(data.as_ptr() as *const libc::sockaddr_in6) };
                let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                let port = u16::from_be(sa.sin6_port);
                return Ok(Some(SocketAddr::from((ip, port))));
            }
        }
        let next = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
        if next.is_null() {
            break;
        }
        cmsg_ptr = next;
    }
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn bind_tproxy(_addr: SocketAddr) -> io::Result<TcpListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tproxy is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
fn bind_tproxy_udp(_addr: SocketAddr) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tproxy is only supported on Linux",
    ))
}
