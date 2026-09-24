use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};

use crate::inbound::{Target, drive_transparent, network_includes_udp, parse_listen};
use crate::logging;
use crate::route::Router;

/// redirect inbound: TCP only; destination recovered with `SO_ORIGINAL_DST`
/// (Linux) / `/dev/pf` (Darwin); other platforms reject each connection
/// (reference `redir_other.go`).
pub struct Redirect {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
}

impl Redirect {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("redirect");
        let at = format!("inbound[{tag}]");
        if network_includes_udp(obj) {
            logging::warn(format_args!(
                "inbound redirect[{tag}]: udp network not implemented yet (tcp only)"
            ));
        }
        let (ip, port) = parse_listen(obj, &at)?;
        let listener = TcpListener::bind(SocketAddr::new(ip, port)).await?;
        logging::info(format_args!(
            "inbound redirect[{tag}] listening at {ip}:{port}"
        ));
        Ok(Self {
            listener,
            tag: tag.to_string(),
            router,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let router = Arc::clone(&self.router);
                    let tag = self.tag.clone();
                    tokio::spawn(async move {
                        let destination = match original_destination(&stream).await {
                            Ok(dest) => dest,
                            Err(err) => {
                                logging::error(format_args!(
                                    "redirect[{tag}] {peer}: get redirect destination: {err}"
                                ));
                                return;
                            }
                        };
                        logging::info(format_args!(
                            "inbound redirect[{tag}] {peer} -> {destination}"
                        ));
                        if let Err(err) =
                            drive_transparent(stream, peer, destination, &tag, &router).await
                        {
                            logging::debug(format_args!("redirect[{tag}] {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::warn(format_args!("redirect[{}] accept: {err}", self.tag));
                    return;
                }
            }
        }
    }
}

/// Reference `redir.GetOriginalDestination`.
async fn original_destination(stream: &TcpStream) -> io::Result<Target> {
    // getsockopt is non-blocking and O(μs); run inline.
    original_destination_blocking(stream)
}

#[cfg(target_os = "linux")]
fn original_destination_blocking(stream: &TcpStream) -> io::Result<Target> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::unix::io::AsRawFd;

    const SO_ORIGINAL_DST: libc::c_int = 80;

    let fd = stream.as_raw_fd();
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&storage) as libc::socklen_t;
    let peer = stream.peer_addr()?;
    let level = if peer.is_ipv4() {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    };
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            SO_ORIGINAL_DST,
            &mut storage as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            let sa = unsafe { *(&storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Ok(Target::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        libc::AF_INET6 => {
            let sa = unsafe { *(&storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Ok(Target::Ip(SocketAddr::new(IpAddr::V6(ip), port)))
        }
        family => Err(io::Error::other(format!(
            "unexpected address family {family}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn original_destination_blocking(_stream: &TcpStream) -> io::Result<Target> {
    // /dev/pf DIOCNATLOOK — deferred; fail closed like a missing NAT entry.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "get redirect destination: unsupported on this platform",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn original_destination_blocking(_stream: &TcpStream) -> io::Result<Target> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "get redirect destination: unsupported on this platform",
    ))
}
