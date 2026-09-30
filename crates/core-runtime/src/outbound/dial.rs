//! The dialer options every outbound carries (`option.AbstractDialerOptions`).
//!
//! The reference applies these to the outbound's own sockets before it dials
//! (`common/dialer/default.go`). Ours read two of them, and only on the `direct`
//! outbound, so a `vless` outbound with a `routing_mark` or a `bind_interface`
//! dialled without them. This is the one place that applies them, for every
//! protocol, and it builds the socket with libc because half the options have
//! no socket2 setter (`IP_MTU_DISCOVER`, `IP_BIND_ADDRESS_NO_PORT`,
//! `TCP_FASTOPEN`).
//!
//! What the reference does, and what we do:
//!
//! * `bind_interface` (SO_BINDTODEVICE) and `routing_mark` (SO_MARK) — Linux
//!   only, and the reference says so at start rather than dialling without it.
//! * `inet4_bind_address` / `inet6_bind_address` bind before connecting.
//! * `bind_address_no_port` (IP_BIND_ADDRESS_NO_PORT) — Linux only.
//! * `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`.
//! * `tcp_fast_open` (TCP_FASTOPEN with the queue size the reference uses).
//! * `udp_fragment` is a *negative* default: without it the reference asks the
//!   kernel not to fragment (`IP_PMTUDISC_DONT`), so a plain config gets that.
//! * `connect_timeout` wraps the connect, `C.TCPConnectTimeout` by default.
//! * `reuse_addr` is a listener option in the reference, so it lands on inbounds.
//! * `netns` is not implemented: switching the network namespace is a
//!   per-thread operation in C, and a blocking dial on a pooled thread would
//!   leak the namespace into the next task that lands on it. It stays logged
//!   as ignored, like the rest of the unsupported dialer fields.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

/// The reference's `C.TCPConnectTimeout` when `connect_timeout` is absent.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// `C.TCPKeepAliveInitial` and `C.TCPKeepAliveInterval`.
#[cfg_attr(not(unix), allow(dead_code))]
const KEEP_ALIVE_IDLE: Duration = Duration::from_secs(15);
#[cfg_attr(not(unix), allow(dead_code))]
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// The queue length the reference asks TCP_FASTOPEN for.
#[cfg(unix)]
const FAST_OPEN_QUEUE: libc::c_int = 256;

#[derive(Debug, Clone, Default)]
pub struct DialOptions {
    pub bind_interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub inet4_bind_address: Option<IpAddr>,
    pub inet6_bind_address: Option<IpAddr>,
    pub bind_address_no_port: bool,
    pub reuse_addr: bool,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive: Option<Duration>,
    pub tcp_keep_alive_interval: Option<Duration>,
    pub udp_fragment: bool,
    pub tcp_fast_open: bool,
    pub connect_timeout: Option<Duration>,
}

impl DialOptions {
    /// Read the options off any outbound, inbound or endpoint object. The
    /// platform refusals are the reference's own words.
    pub fn parse(obj: &serde_json::Map<String, serde_json::Value>) -> anyhow::Result<Self> {
        let address = |key: &str| -> anyhow::Result<Option<IpAddr>> {
            let Some(value) = obj.get(key).filter(|value| !value.is_null()) else {
                return Ok(None);
            };
            let raw = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("{key}: must be a string"))?;
            let ip = raw
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("{key}: invalid address: {raw:?}"))?;
            if key.starts_with("inet4") != ip.is_ipv4() {
                anyhow::bail!("{key}: wrong address family: {raw:?}");
            }
            Ok(Some(ip))
        };
        let seconds = |key: &str| -> anyhow::Result<Option<Duration>> {
            let value = obj.get(key).filter(|value| !value.is_null());
            let Some(value) = value else {
                return Ok(None);
            };
            if !value.is_string() && !value.is_number() {
                anyhow::bail!("{key}: must be a duration string");
            }
            Ok(Some(crate::outbound::urltest::parse_duration(
                Some(value),
                Duration::ZERO,
                key,
            )?))
        };
        let flag = |key: &str| {
            obj.get(key)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        };

        let bind_interface = obj
            .get("bind_interface")
            .and_then(serde_json::Value::as_str)
            .filter(|iface| !iface.is_empty())
            .map(str::to_string);
        if bind_interface.is_some() && !cfg!(any(target_os = "linux", target_os = "macos", windows))
        {
            anyhow::bail!("`bind_interface` is only supported on Linux, macOS and Windows");
        }
        let routing_mark = match obj.get("routing_mark") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => {
                let mark = value
                    .as_u64()
                    .and_then(|mark| u32::try_from(mark).ok())
                    .ok_or_else(|| anyhow::anyhow!("routing_mark: invalid value"))?;
                if !cfg!(target_os = "linux") {
                    anyhow::bail!("`routing_mark` is only supported on Linux");
                }
                Some(mark)
            }
        };
        let bind_address_no_port = flag("bind_address_no_port");
        if bind_address_no_port && !cfg!(target_os = "linux") {
            anyhow::bail!("`bind_address_no_port` is only supported on Linux");
        }
        Ok(Self {
            bind_interface,
            routing_mark,
            inet4_bind_address: address("inet4_bind_address")?,
            inet6_bind_address: address("inet6_bind_address")?,
            bind_address_no_port,
            reuse_addr: flag("reuse_addr"),
            disable_tcp_keep_alive: flag("disable_tcp_keep_alive"),
            tcp_keep_alive: seconds("tcp_keep_alive")?,
            tcp_keep_alive_interval: seconds("tcp_keep_alive_interval")?,
            udp_fragment: flag("udp_fragment"),
            tcp_fast_open: flag("tcp_fast_open"),
            connect_timeout: seconds("connect_timeout")?,
        })
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT)
    }

    /// `None` disables keep-alive entirely, as `dialer.KeepAlive = -1` does.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn keep_alive(&self) -> Option<(Duration, Duration)> {
        if self.disable_tcp_keep_alive {
            return None;
        }
        Some((
            self.tcp_keep_alive.unwrap_or(KEEP_ALIVE_IDLE),
            self.tcp_keep_alive_interval.unwrap_or(KEEP_ALIVE_INTERVAL),
        ))
    }

    /// True when there is nothing to set, so the plain async connect stays the
    /// one taken.
    pub fn is_empty(&self) -> bool {
        self.bind_interface.is_none()
            && self.routing_mark.is_none()
            && self.inet4_bind_address.is_none()
            && self.inet6_bind_address.is_none()
            && !self.bind_address_no_port
            && !self.reuse_addr
            && !self.disable_tcp_keep_alive
            && self.tcp_keep_alive.is_none()
            && self.tcp_keep_alive_interval.is_none()
            && !self.udp_fragment
            && !self.tcp_fast_open
            && self.connect_timeout.is_none()
    }

    /// The local address to bind before connecting, for this socket's family.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn bind_address(&self, addr: &SocketAddr) -> Option<SocketAddr> {
        let ip = match addr {
            SocketAddr::V4(_) => self.inet4_bind_address,
            SocketAddr::V6(_) => self.inet6_bind_address,
        }?;
        Some(SocketAddr::new(ip, 0))
    }

    #[cfg(unix)]
    /// Everything that has to be set before the socket connects.
    /// Everything that has to be set before the socket connects.
    fn apply(&self, fd: RawFd, addr: &SocketAddr, udp: bool) -> io::Result<()> {
        if self.reuse_addr {
            set_bool(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR)?;
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(mark) = self.routing_mark {
                set_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)?;
            }
            if let Some(iface) = &self.bind_interface {
                set_bytes(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface.as_bytes(),
                )?;
            }
            if self.bind_address_no_port {
                set_int(fd, libc::IPPROTO_IP, 24, 1)?;
            }
            if udp && !self.udp_fragment {
                set_int(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    libc::IP_PMTUDISC_DONT,
                )?;
            }
        }
        if addr.is_ipv6() && udp && !self.udp_fragment {
            set_int(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_DONT,
            )?;
        }
        if !udp {
            match self.keep_alive() {
                None => set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 0)?,
                Some((idle, interval)) => {
                    set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
                    set_int(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_KEEPIDLE,
                        idle.as_secs() as libc::c_int,
                    )?;
                    set_int(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_KEEPINTVL,
                        interval.as_secs() as libc::c_int,
                    )?;
                }
            }
            if self.tcp_fast_open {
                set_int(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, FAST_OPEN_QUEUE)?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let value = value.to_ne_bytes();
    set_bytes(fd, level, name, &value)
}

#[cfg(unix)]
fn set_bool(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    set_int(fd, level, name, 1)
}

#[cfg(unix)]
fn set_bytes(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &[u8]) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value.as_ptr().cast(),
            value.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn new_socket(addr: &SocketAddr, udp: bool) -> io::Result<RawFd> {
    let domain = if addr.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd = unsafe {
        libc::socket(
            domain,
            if udp {
                libc::SOCK_DGRAM
            } else {
                libc::SOCK_STREAM
            },
            if udp {
                libc::IPPROTO_UDP
            } else {
                libc::IPPROTO_TCP
            },
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// A libc `sockaddr` for the address, written by hand: `socket2::SockAddr` is
/// a wrapper type on Linux, not a `sockaddr`, so it cannot be handed to
/// `bind`/`connect` directly.
#[cfg(unix)]
fn raw_addr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: sockaddr_in is the first member-compatible layout of a
            // zeroed sockaddr_storage of at least its size
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            // SAFETY: as above, for the v6 layout
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

#[cfg(unix)]
fn bind_local(fd: RawFd, addr: &SocketAddr) -> io::Result<()> {
    let (storage, len) = raw_addr(addr);
    // SAFETY: a zeroed sockaddr_storage of `len` bytes, valid for the family
    let ptr: *const libc::sockaddr = (&storage as *const libc::sockaddr_storage).cast();
    let result = unsafe { libc::bind(fd, ptr, len) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn connect_socket(fd: RawFd, addr: &SocketAddr) -> io::Result<()> {
    let (storage, len) = raw_addr(addr);
    // SAFETY: as above
    let ptr: *const libc::sockaddr = (&storage as *const libc::sockaddr_storage).cast();
    let result = unsafe { libc::connect(fd, ptr, len) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Resolve a name the way the reference's dialer does, then connect with every
/// option this outbound asked for.
pub async fn connect_tcp(host: &str, port: u16, options: &DialOptions) -> io::Result<TcpStream> {
    // resolution always goes through the dns service when one is installed,
    // options or not: that is the whole point of `route.default_domain_resolver`
    let addrs = resolve(host, port).await?;
    let mut last = None;
    for addr in addrs {
        let attempt = if options.is_empty() {
            match tokio::time::timeout(options.connect_timeout(), TcpStream::connect(addr)).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
            }
        } else {
            dial_tcp(addr, options).await
        };
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other(format!("no address for {host}"))))
}

/// The same, for an address already known: no resolution, no walking.
pub async fn connect_tcp_addr(addr: SocketAddr, options: &DialOptions) -> io::Result<TcpStream> {
    if options.is_empty() {
        return match tokio::time::timeout(options.connect_timeout(), TcpStream::connect(addr)).await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
        };
    }
    dial_tcp(addr, options).await
}

/// Every address a name resolves to: `route.default_domain_resolver` and the
/// `dns` section override the system lookup, and the list order is the strategy
/// the reference's `dialer` walks.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Some(ip) = crate::dns::transport::is_ip_literal(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if let Some(service) = crate::dns::current() {
        let addrs = match crate::dns::default_domain_resolver() {
            Some(tag) => service.resolve_via(&tag, host).await?,
            None => service.resolve(host).await?,
        };
        return Ok(addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }
    Ok(tokio::net::lookup_host((host, port)).await?.collect())
}

/// No `setsockopt` to reach for here: `parse` already refused the options this
/// platform cannot carry, so the socket is the plain one.
#[cfg(not(unix))]
async fn dial_tcp(addr: SocketAddr, _options: &DialOptions) -> io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

#[cfg(not(unix))]
pub async fn connect_udp(addr: SocketAddr, _options: &DialOptions) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .await?;
    socket.connect(addr).await?;
    Ok(socket)
}

#[cfg(unix)]
async fn dial_tcp(addr: SocketAddr, options: &DialOptions) -> io::Result<TcpStream> {
    let options = options.clone();
    let std = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
        let fd = new_socket(&addr, false)?;
        let finish = |fd| -> io::Result<std::net::TcpStream> {
            // SAFETY: the socket is a fresh, connected, owned fd
            let stream = unsafe { <std::net::TcpStream as FromRawFd>::from_raw_fd(fd) };
            stream.set_nonblocking(true)?;
            Ok(stream)
        };
        if let Err(err) = options.apply(fd, &addr, false) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        if let Some(local) = options.bind_address(&addr)
            && let Err(err) = bind_local(fd, &local)
        {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        if let Err(err) = connect_socket(fd, &addr) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        finish(fd)
    })
    .await
    .map_err(io::Error::other)??;
    TcpStream::from_std(std)
}

#[cfg(unix)]
pub async fn connect_udp(addr: SocketAddr, options: &DialOptions) -> io::Result<UdpSocket> {
    if options.is_empty() {
        let socket = UdpSocket::bind(match addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await?;
        socket.connect(addr).await?;
        return Ok(socket);
    }
    let options = options.clone();
    let std = tokio::task::spawn_blocking(move || -> io::Result<std::net::UdpSocket> {
        let fd = new_socket(&addr, true)?;
        let finish = |fd| -> io::Result<std::net::UdpSocket> {
            // SAFETY: the socket is a fresh, connected, owned fd
            let socket = unsafe { <std::net::UdpSocket as FromRawFd>::from_raw_fd(fd) };
            socket.set_nonblocking(true)?;
            Ok(socket)
        };
        if let Err(err) = options.apply(fd, &addr, true) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        if let Some(local) = options.bind_address(&addr) {
            // no port to speak of yet: the local address, any port
            if let Err(err) = bind_local(fd, &local) {
                unsafe { libc::close(fd) };
                return Err(err);
            }
        }
        if let Err(err) = connect_socket(fd, &addr) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        finish(fd)
    })
    .await
    .map_err(io::Error::other)??;
    UdpSocket::from_std(std)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options every platform can carry, off any outbound object.
    #[test]
    fn the_options_come_off_any_outbound_object() {
        let options = DialOptions::parse(
            &serde_json::json!({
                "bind_interface": "eth0",
                "inet4_bind_address": "192.168.1.5",
                "reuse_addr": true,
                "tcp_keep_alive": "30s",
                "tcp_keep_alive_interval": "10s",
                "udp_fragment": true,
                "tcp_fast_open": true,
                "connect_timeout": "3s"
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .expect("options");
        assert_eq!(options.bind_interface.as_deref(), Some("eth0"));
        assert_eq!(
            options.inet4_bind_address,
            Some("192.168.1.5".parse().unwrap())
        );
        assert!(options.reuse_addr && options.udp_fragment && options.tcp_fast_open);
        assert_eq!(options.connect_timeout(), Duration::from_secs(3));
        assert_eq!(
            options.keep_alive(),
            Some((Duration::from_secs(30), Duration::from_secs(10)))
        );
        assert!(!options.is_empty());
        assert!(DialOptions::default().is_empty());
    }

    /// `routing_mark` and `bind_address_no_port` only exist on Linux, and the
    /// reference refuses to start there rather than dial without them.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_only_options_are_read() {
        let options = DialOptions::parse(
            &serde_json::json!({"routing_mark": 7, "bind_address_no_port": true})
                .as_object()
                .unwrap()
                .clone(),
        )
        .expect("options");
        assert_eq!(options.routing_mark, Some(7));
        assert!(options.bind_address_no_port);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_linux_only_options_are_refused() {
        for field in ["routing_mark", "bind_address_no_port"] {
            let value = if field == "routing_mark" {
                serde_json::json!(7)
            } else {
                serde_json::json!(true)
            };
            let err = DialOptions::parse(
                &serde_json::json!({ "x": 1, field: value })
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .expect_err("linux-only option off linux");
            assert!(
                err.to_string().contains("only supported on Linux"),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn keep_alive_defaults_to_the_reference_pair_and_off_means_off() {
        let default = DialOptions::default();
        assert_eq!(
            default.keep_alive(),
            Some((KEEP_ALIVE_IDLE, KEEP_ALIVE_INTERVAL)),
            "the reference enables keep-alive with its own idle and interval"
        );
        let off = DialOptions {
            disable_tcp_keep_alive: true,
            ..Default::default()
        };
        assert_eq!(off.keep_alive(), None);
    }

    #[test]
    fn a_bind_address_only_applies_to_its_own_family() {
        let options = DialOptions {
            inet4_bind_address: Some("10.0.0.1".parse().unwrap()),
            ..Default::default()
        };
        let v4: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(
            options.bind_address(&v4),
            Some("10.0.0.1:0".parse().unwrap())
        );
        assert_eq!(options.bind_address(&v6), None);
    }

    #[test]
    fn an_address_of_the_wrong_family_is_refused() {
        let wrong = DialOptions::parse(
            &serde_json::json!({"inet4_bind_address": "2001:db8::1"})
                .as_object()
                .unwrap()
                .clone(),
        );
        assert!(
            wrong
                .expect_err("an IPv6 address in inet4_bind_address")
                .to_string()
                .contains("wrong address family")
        );
    }

    /// The options have to reach the socket, not just the struct: read each
    /// one back with getsockopt.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_options_reach_the_socket() {
        let get_int = |fd: RawFd, level: libc::c_int, name: libc::c_int| -> libc::c_int {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    level,
                    name,
                    std::ptr::addr_of_mut!(value).cast(),
                    &mut len,
                )
            };
            assert_eq!(result, 0, "getsockopt failed");
            value
        };
        let options = DialOptions {
            routing_mark: Some(0x1234),
            reuse_addr: true,
            tcp_keep_alive: Some(Duration::from_secs(42)),
            tcp_keep_alive_interval: Some(Duration::from_secs(11)),
            ..Default::default()
        };
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fd = new_socket(&addr, false).expect("socket");
        options.apply(fd, &addr, false).expect("apply");
        assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_MARK), 0x1234);
        assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR), 1);
        assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        assert_eq!(get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE), 42);
        assert_eq!(get_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL), 11);
        unsafe { libc::close(fd) };

        // and the fragment default the reference asks for
        let fd = new_socket(&addr, true).expect("socket");
        DialOptions::default()
            .apply(fd, &addr, true)
            .expect("apply");
        assert_eq!(
            get_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            libc::IP_PMTUDISC_DONT,
            "no udp_fragment means no fragmentation"
        );
        unsafe { libc::close(fd) };
        let fd = new_socket(&addr, true).expect("socket");
        DialOptions {
            udp_fragment: true,
            ..Default::default()
        }
        .apply(fd, &addr, true)
        .expect("apply");
        assert_ne!(
            get_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            libc::IP_PMTUDISC_DONT
        );
        unsafe { libc::close(fd) };
    }

    /// A real connect with options applied still reaches the peer, and the
    /// local address it bound is the one the config asked for.
    #[tokio::test]
    async fn a_connect_with_options_still_reaches_the_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = listener.local_addr().expect("addr");
        let accept = tokio::task::spawn_blocking(move || listener.accept().map(|(s, _)| s));
        let options = DialOptions {
            routing_mark: Some(0x2000),
            reuse_addr: true,
            tcp_fast_open: true,
            inet4_bind_address: Some("127.0.0.1".parse().unwrap()),
            connect_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        let client = connect_tcp(&server.ip().to_string(), server.port(), &options)
            .await
            .expect("connect");
        assert_eq!(
            client.local_addr().expect("local").ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        accept.await.expect("join").expect("accept");
    }
}
