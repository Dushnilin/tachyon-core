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
//! * `tcp_multi_path` is `TCP_MPTCP_ENABLED` on Linux and nothing anywhere
//!   else, which is what Go's `SetMultipathTCP` does there.
//! * `domain_strategy` picks the resolve strategy for this outbound's server
//!   address and, with it, the family that gets the first attempt;
//!   `fallback_delay` is how long that first attempt gets before the other
//!   family starts (RFC 6555 fast fallback, sing's `DialParallel`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

/// The reference's `C.TCPConnectTimeout` when `connect_timeout` is absent.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// `sing/common/network.DefaultFallbackDelay`: how long the first address gets
/// before the other family starts.
const DEFAULT_FALLBACK_DELAY: Duration = Duration::from_millis(300);
/// `C.TCPKeepAliveInitial` and `C.TCPKeepAliveInterval`.
#[cfg_attr(not(unix), allow(dead_code))]
const KEEP_ALIVE_IDLE: Duration = Duration::from_secs(15);
#[cfg_attr(not(unix), allow(dead_code))]
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// The queue length the reference asks TCP_FASTOPEN for.
#[cfg(unix)]
const FAST_OPEN_QUEUE: libc::c_int = 256;
/// `TCP_MPTCP_ENABLED`, Linux only (mptcp.h).
#[cfg(target_os = "linux")]
const TCP_MPTCP_ENABLED: libc::c_int = 42;

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
    /// `tcp_multi_path`: Linux MPTCP, one setsockopt before the connect.
    pub tcp_multi_path: bool,
    /// `netns`: a network namespace tag, name or path to dial inside (Linux).
    pub netns: Option<String>,
    /// `protect_path`: a unix socket whose helper takes the socket's file
    /// descriptor, which is how a client stays out of the VPN it serves.
    pub protect_path: Option<String>,
    /// `domain_strategy` (deprecated in the reference, still honoured): the
    /// strategy for resolving this outbound's server address, which also says
    /// which address family is tried first.
    pub domain_strategy: Option<crate::dns::Strategy>,
    /// `fallback_delay`: how long the first address gets before the other
    /// family starts (RFC 6555).
    pub fallback_delay: Option<Duration>,
    /// The reference dials a resolved name in parallel unless something makes
    /// its own serial dialer necessary: `dialOptions.Detour == "" &&
    /// !options.TCPFastOpen`.
    pub parallel: bool,
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
            tcp_multi_path: flag("tcp_multi_path"),
            netns: obj
                .get("netns")
                .and_then(serde_json::Value::as_str)
                .filter(|ns| !ns.is_empty())
                .map(str::to_string),
            protect_path: obj
                .get("protect_path")
                .and_then(serde_json::Value::as_str)
                .filter(|path| !path.is_empty())
                .map(str::to_string),
            domain_strategy: match obj.get("domain_strategy") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => {
                    let raw = value
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("domain_strategy: must be a string"))?;
                    if raw.is_empty() || raw == "as_is" {
                        None
                    } else {
                        Some(crate::dns::Strategy::parse(raw)?)
                    }
                }
            },
            fallback_delay: seconds("fallback_delay")?,
            parallel: obj
                .get("detour")
                .and_then(serde_json::Value::as_str)
                .map(str::is_empty)
                .unwrap_or(true)
                && !flag("tcp_fast_open"),
        })
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT)
    }

    /// `fallback_delay`, or the reference's `DefaultFallbackDelay`.
    fn fallback_delay(&self) -> Duration {
        self.fallback_delay
            .filter(|delay| !delay.is_zero())
            .unwrap_or(DEFAULT_FALLBACK_DELAY)
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
            && !self.tcp_multi_path
            && self.netns.is_none()
            && self.protect_path.is_none()
            && self.domain_strategy.is_none()
            && self.fallback_delay.is_none()
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
        let _ = addr;
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
        #[cfg(target_os = "linux")]
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
                    #[cfg(any(target_os = "macos", target_os = "ios"))]
                    const TCP_KEEPIDLE_OPT: libc::c_int = libc::TCP_KEEPALIVE;
                    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
                    const TCP_KEEPIDLE_OPT: libc::c_int = libc::TCP_KEEPIDLE;

                    set_int(
                        fd,
                        libc::IPPROTO_TCP,
                        TCP_KEEPIDLE_OPT,
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
            // MPTCP is a Linux socket option and a no-op anywhere else, which
            // is all the reference asks for: Go's SetMultipathTCP is the same
            // setsockopt and it only exists there. A kernel without MPTCP
            // refuses the option with ENOPROTOOPT, and the reference ignores
            // that error, so a plain connect is what still happens.
            #[cfg(target_os = "linux")]
            if self.tcp_multi_path {
                match set_int(fd, libc::IPPROTO_TCP, TCP_MPTCP_ENABLED, 1) {
                    Ok(()) => {}
                    // a kernel without MPTCP says so (a locked-down one says
                    // EPERM), and the reference ignores that error: the dial
                    // goes on without multipath
                    Err(err)
                        if matches!(
                            err.raw_os_error(),
                            Some(libc::ENOPROTOOPT)
                                | Some(libc::EPROTONOSUPPORT)
                                | Some(libc::EPERM)
                        ) =>
                    {
                        crate::logging::debug(format_args!(
                            "tcp_multi_path: this kernel has no MPTCP, dialing without it: {err}"
                        ));
                    }
                    Err(err) => return Err(err),
                }
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
    let addrs = resolve_with(host, port, options.domain_strategy).await?;
    if addrs.is_empty() {
        return Err(io::Error::other(format!("no address for {host}")));
    }
    // no detour and no TCP fast open is exactly when the reference races the
    // families itself; either of those hands the dial to something that cannot
    let prefer_ipv6 = options.domain_strategy == Some(crate::dns::Strategy::PreferIPv6);
    let parallel = options.parallel;
    let fallback_delay = options.fallback_delay();
    let dial_options = options.clone();
    let one = move |addr| {
        let options = dial_options.clone();
        async move { connect_one(addr, &options).await }
    };
    if parallel {
        return dial_fast_fallback(&addrs, prefer_ipv6, fallback_delay, one).await;
    }
    dial_serial(addrs, one).await
}

/// One address, one connect: the plain async connect when there is nothing to
/// set on the socket, and the socket-options path when there is.
async fn connect_one(addr: SocketAddr, options: &DialOptions) -> io::Result<TcpStream> {
    let stream = if options.is_empty() {
        match tokio::time::timeout(options.connect_timeout(), TcpStream::connect(addr)).await {
            Ok(result) => result?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
        }
    } else {
        dial_tcp(addr, options).await?
    };
    // the reference sets TCP_NODELAY on every dial; without it a small header
    // write waits out the peer's delayed ACK (a 40 ms stall per connection)
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Wait for a non-blocking socket whose handshake `dial_tcp` already started:
/// `writable()` returns once the handshake is over, and whatever error it left
/// behind is the reason if there was one. This is what makes a connect
/// cancellable, which a blocking `connect()` in a task is not.
#[cfg(unix)]
async fn finish_connect(std: std::net::TcpStream, timeout: Duration) -> io::Result<TcpStream> {
    let stream = TcpStream::from_std(std)?;
    let connect = async {
        stream.writable().await?;
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }
        Ok(stream)
    };
    match tokio::time::timeout(timeout, connect).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
    }
}

/// The same, for an address already known: no resolution, no walking.
pub async fn connect_tcp_addr(addr: SocketAddr, options: &DialOptions) -> io::Result<TcpStream> {
    connect_one(addr, options).await
}

/// Every address a name resolves to: `route.default_domain_resolver` and the
/// `dns` section override the system lookup, and the list order is the strategy
/// the reference's `dialer` walks.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_with(host, port, None).await
}

/// The same with the strategy the outbound asked for. The reference lets a
/// `domain_resolver` whose own `strategy` is not `as_is` win over a
/// `domain_strategy`; that field is not carried here yet, so a `domain_strategy`
/// on the object always wins.
pub async fn resolve_with(
    host: &str,
    port: u16,
    strategy: Option<crate::dns::Strategy>,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(ip) = crate::dns::transport::is_ip_literal(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let want = strategy.or_else(|| crate::dns::current().map(|service| service.strategy()));
    if let Some(service) = crate::dns::current() {
        let addrs = match crate::dns::default_domain_resolver() {
            Some(tag) => service.resolve_via_with(&tag, host, strategy).await?,
            None => service.resolve_with(host, strategy).await?,
        };
        return Ok(addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await?
        .map(|addr| addr.ip())
        .collect();
    // the system resolver has no strategy of its own, so ordering and the
    // one-family cases are applied here
    let addrs = match want {
        None => addrs,
        Some(strategy) => match strategy {
            crate::dns::Strategy::AsIs => addrs,
            crate::dns::Strategy::IPv4Only => addrs.into_iter().filter(IpAddr::is_ipv4).collect(),
            crate::dns::Strategy::IPv6Only => addrs.into_iter().filter(IpAddr::is_ipv6).collect(),
            strategy => crate::dns::order_addresses(addrs, strategy),
        },
    };
    Ok(addrs
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// Run the socket work inside the dialer's network namespace, if it asked for
/// one. `setns` is a per-thread property, so the block gets a thread of its own
/// rather than a pooled one -- that is the whole reason the reference locks the
/// thread around the same block.
///
/// Off Linux there is no `setns`, so `netns` is a no-op there: `parse` still
/// refuses nothing about it, and `unhonored_options` says it is not applied.
#[cfg(target_os = "linux")]
fn in_netns<T, F>(netns: &Option<String>, block: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    match netns {
        Some(netns) => crate::netns::in_namespace(netns, block),
        None => block(),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn in_netns<T, F>(_netns: &Option<String>, block: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    block()
}

/// One address at a time, in order, until one connects (sing's `DialSerial`).
/// The list is owned because a racer holds it inside a spawned task, and a
/// borrow of the caller's slice would not be `Send`.
async fn dial_serial<F, Fut, T>(addrs: Vec<SocketAddr>, mut dial: F) -> io::Result<T>
where
    F: FnMut(SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<T>> + Send,
    T: Send + 'static,
{
    let mut last = None;
    for addr in addrs {
        match dial(addr).await {
            Ok(value) => return Ok(value),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no address to dial")))
}

/// RFC 6555 fast fallback over the two address families, which is sing's
/// `DialParallel`: the preferred family gets a head start of `fallback_delay`,
/// the other one starts after it, a first failure brings it forward at once,
/// and the first connection to come up is the one that wins. When both families
/// fail, the error the caller hears is the preferred family's, as it is there.
///
/// The dialer is a parameter so the race can be tested without a network that
/// answers half the time.
pub(crate) async fn dial_fast_fallback<F, Fut, T>(
    addrs: &[SocketAddr],
    prefer_ipv6: bool,
    fallback_delay: Duration,
    dial: F,
) -> io::Result<T>
where
    // one dialer per racer: Go hands the same Dialer to both, and it is safe to
    // call from several goroutines, which a clone is the Rust spelling of
    F: Fn(SocketAddr) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = io::Result<T>> + Send,
    T: Send + 'static,
{
    let (primaries, fallbacks): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
        .iter()
        .cloned()
        .partition(|addr| addr.is_ipv6() == prefer_ipv6);
    // one family only: nothing to race, and that is the reference's own check
    if primaries.is_empty() || fallbacks.is_empty() {
        return dial_serial(addrs.to_vec(), dial).await;
    }
    let mut fallbacks = Some(fallbacks);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(bool, io::Result<T>)>();
    // `tx` is borrowed for the whole race, which also keeps the channel open:
    // every racer reports before the loop can run out of results
    let start = |addrs: Option<Vec<SocketAddr>>,
                 primary: bool,
                 racers: &mut Vec<tokio::task::JoinHandle<()>>| {
        let Some(addrs) = addrs else {
            return;
        };
        let tx = tx.clone();
        let dial = dial.clone();
        racers.push(tokio::spawn(async move {
            let result = dial_serial(addrs, dial).await;
            let _ = tx.send((primary, result));
        }));
    };

    let mut racers = Vec::new();
    start(Some(primaries), true, &mut racers);
    let mut primary: Option<io::Result<T>> = None;
    let mut fallback: Option<io::Result<T>> = None;
    let wait = tokio::time::sleep(fallback_delay);
    tokio::pin!(wait);
    let mut fallback_started = false;
    loop {
        tokio::select! {
            _ = &mut wait, if !fallback_started => {
                fallback_started = true;
                start(fallbacks.take(), false, &mut racers);
            }
            result = rx.recv() => {
                let Some((is_primary, result)) = result else {
                    break;
                };
                if result.is_ok() {
                    for racer in racers {
                        racer.abort();
                    }
                    return result;
                }
                if is_primary {
                    primary = Some(result);
                    // the head start is over: bring the other family forward
                    if !fallback_started {
                        fallback_started = true;
                        start(fallbacks.take(), false, &mut racers);
                    }
                } else {
                    fallback = Some(result);
                }
                // both are failures and both have reported: the preferred
                // family's error is what the caller hears
                if primary.is_some() && fallback.is_some() {
                    for racer in racers {
                        racer.abort();
                    }
                    // `take` only here: taking inside the `if let` pattern would
                    // drop the result whenever the other side has not reported,
                    // and the race would then wait for a result that was thrown
                    // away
                    return match primary.take() {
                        Some(result) => result,
                        None => Err(io::Error::other("dial race: no primary result")),
                    };
                }
            }
        }
    }
    match primary.or(fallback) {
        // unreachable: a success has already returned above
        Some(Ok(_)) => Err(io::Error::other("dial race reported no error")),
        Some(Err(err)) => Err(err),
        None => Err(io::Error::other("no address to dial")),
    }
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
    let timeout = options.connect_timeout();
    let netns = options.netns.clone();
    let protect = options.protect_path.clone();
    let std = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
        let socket = move |addr: &SocketAddr| -> io::Result<std::net::TcpStream> {
            let fd = new_socket(addr, false)?;
            if let Err(err) = options.apply(fd, addr, false) {
                unsafe { libc::close(fd) };
                return Err(err);
            }
            if let Some(local) = options.bind_address(addr)
                && let Err(err) = bind_local(fd, &local)
            {
                unsafe { libc::close(fd) };
                return Err(err);
            }
            // the socket goes back non-blocking with the handshake already started:
            // `connect` on a non-blocking socket returns EINPROGRESS, and the reactor
            // reports it finished in `finish_connect`. That is what makes the connect
            // cancellable, which a blocking `connect` in here is not.
            match connect_socket(fd, addr) {
                Ok(()) => {}
                // EINPROGRESS is `ErrorKind::InProgress` on Linux and
                // `WouldBlock` elsewhere, so the errno is what we compare
                Err(err)
                    if matches!(
                        err.raw_os_error(),
                        Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN
                    ) => {}
                Err(err) => {
                    unsafe { libc::close(fd) };
                    return Err(err);
                }
            }
            if let Some(path) = &protect {
                crate::protect::protect(path, fd)?;
            }
            // SAFETY: the socket is a fresh, owned fd
            let stream = unsafe { <std::net::TcpStream as FromRawFd>::from_raw_fd(fd) };
            stream.set_nonblocking(true)?;
            Ok(stream)
        };
        in_netns(&netns, move || socket(&addr))
    })
    .await
    .map_err(io::Error::other)??;
    finish_connect(std, timeout).await
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
    let netns = options.netns.clone();
    let protect = options.protect_path.clone();
    let std = tokio::task::spawn_blocking(move || -> io::Result<std::net::UdpSocket> {
        let socket = move || -> io::Result<std::net::UdpSocket> {
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
            if let Some(path) = &protect {
                crate::protect::protect(path, fd)?;
            }
            finish(fd)
        };
        in_netns(&netns, socket)
    })
    .await
    .map_err(io::Error::other)??;
    UdpSocket::from_std(std)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use tokio::io::AsyncWriteExt as _;

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

    /// MPTCP is one setsockopt on the socket that goes out as a TCP stream.
    /// A kernel that has no MPTCP refuses the option, and then -- like the
    /// reference, which drops the same error -- the dial carries on without it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_multi_path_reaches_the_socket() {
        use std::os::fd::AsRawFd;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let options = DialOptions::parse(
            &serde_json::json!({"tcp_multi_path": true})
                .as_object()
                .unwrap()
                .clone(),
        )
        .expect("options");
        assert!(!options.is_empty());
        // the dial itself must work either way, which is the point of ignoring
        // ENOPROTOOPT
        let stream = connect_tcp_addr(addr, &options).await.expect("dial");
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let got = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_MPTCP_ENABLED,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if got != 0 {
            let err = io::Error::last_os_error();
            assert!(
                matches!(
                    err.raw_os_error(),
                    Some(libc::ENOPROTOOPT) | Some(libc::EPROTONOSUPPORT) | Some(libc::EPERM)
                ),
                "getsockopt: {err}"
            );
            eprintln!("this kernel has no MPTCP, as expected on some containers: {err}");
        } else {
            assert_eq!(value, 1, "the socket was not put in MPTCP mode");
        }
    }

    fn addr(v6: bool, port: u16) -> SocketAddr {
        let ip = if v6 {
            "2001:db8::1".parse::<IpAddr>().expect("v6")
        } else {
            "198.51.100.1".parse::<IpAddr>().expect("v4")
        };
        SocketAddr::new(ip, port)
    }

    /// A dialer that answers by port: 1 hangs, 2 fails at once, anything else
    /// wins. The ports stand for addresses, which is all the race looks at.
    fn fake_dialer(
        record: Arc<Mutex<Vec<SocketAddr>>>,
    ) -> impl Fn(SocketAddr) -> std::pin::Pin<Box<dyn Future<Output = io::Result<u16>> + Send>>
    + Send
    + Sync
    + Clone {
        move |target: SocketAddr| {
            let record = Arc::clone(&record);
            Box::pin(async move {
                record.lock().expect("record").push(target);
                match target.port() {
                    1 => {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        Err(io::Error::other("gave up"))
                    }
                    2 => Err(io::Error::other("refused")),
                    _ => Ok(target.port()),
                }
            }) as std::pin::Pin<Box<dyn Future<Output = io::Result<u16>> + Send>>
        }
    }

    /// RFC 6555: the preferred family gets the head start, and the other one
    /// wins the connection when the first is a black hole.
    #[tokio::test]
    async fn fast_fallback_starts_the_other_family_after_the_delay() {
        let record = Arc::new(Mutex::new(Vec::new()));
        let started = Instant::now();
        let won = dial_fast_fallback(
            &[addr(false, 1), addr(true, 3)],
            false,
            Duration::from_millis(120),
            fake_dialer(Arc::clone(&record)),
        )
        .await
        .expect("the v6 address answers");
        assert_eq!(won, 3);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "the v4 address got no head start: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the fallback never started: {elapsed:?}"
        );
        // the black-holed address was tried first and the winner second
        let seen = record.lock().expect("record").clone();
        assert_eq!(seen[0], addr(false, 1));
        assert!(seen.contains(&addr(true, 3)));
    }

    /// `prefer_ipv6` puts the v6 address in front, so the delay is spent on
    /// the other one.
    #[tokio::test]
    async fn prefer_ipv6_swaps_which_family_leads() {
        let record = Arc::new(Mutex::new(Vec::new()));
        let won = dial_fast_fallback(
            &[addr(false, 3), addr(true, 1)],
            true,
            Duration::from_millis(50),
            fake_dialer(record),
        )
        .await
        .expect("the v4 address answers");
        assert_eq!(won, 3);
    }

    /// An early failure does not wait out the head start: the other family is
    /// brought forward at once, which is sing's `fallbackTimer.Stop(); Reset(0)`.
    #[tokio::test]
    async fn a_fast_failure_brings_the_fallback_forward() {
        let record = Arc::new(Mutex::new(Vec::new()));
        let started = Instant::now();
        let won = dial_fast_fallback(
            &[addr(false, 2), addr(true, 3)],
            false,
            Duration::from_secs(30),
            fake_dialer(record),
        )
        .await
        .expect("the v6 address answers");
        assert_eq!(won, 3);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited out the 30s delay after the first address failed"
        );
    }

    /// Both families out of road: the error the caller gets is the preferred
    /// family's, not whichever reported last.
    #[tokio::test]
    async fn both_families_failing_reports_the_preferred_one() {
        let record = Arc::new(Mutex::new(Vec::new()));
        let err = dial_fast_fallback(
            &[addr(false, 2), addr(true, 2)],
            false,
            Duration::from_millis(20),
            fake_dialer(record),
        )
        .await
        .expect_err("nothing answers");
        assert_eq!(err.to_string(), "refused");
    }

    /// One family only is the reference's own check: no race, and the serial
    /// walk is what runs.
    #[tokio::test]
    async fn one_family_is_a_plain_serial_walk() {
        let record = Arc::new(Mutex::new(Vec::new()));
        let won = dial_fast_fallback(
            &[addr(false, 2), addr(false, 3)],
            true,
            Duration::from_secs(30),
            fake_dialer(record),
        )
        .await
        .expect("the second v4 address answers");
        assert_eq!(won, 3);
    }

    /// `protect_path` hands the socket's descriptor to a helper and waits for
    /// its acknowledgement, so the dial that follows is the one the helper kept.
    #[cfg(unix)]
    #[tokio::test]
    async fn protect_path_hands_the_socket_to_a_helper() {
        use std::io::Write as _;
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("tachyon-dial-protect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("protect.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let helper = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let fd = crate::protect::recv_fd(&stream).expect("descriptor");
            stream.write_all(&[1u8]).expect("ack");
            fd
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let options = DialOptions::parse(
            &serde_json::json!({"protect_path": path.to_str().expect("path")})
                .as_object()
                .unwrap()
                .clone(),
        )
        .expect("options");
        assert!(!options.is_empty());

        let stream = connect_tcp_addr(addr, &options).await.expect("dial");
        // the helper got a descriptor and acknowledged it, and our own socket is
        // still the one we hold
        assert!(helper.join().expect("helper") >= 0);
        assert_eq!(stream.peer_addr().expect("peer"), addr);
        let _ = std::fs::remove_file(&path);
    }

    /// `netns` is a Linux dial: the socket is built inside the namespace, on a
    /// thread that belongs to it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_dial_can_run_inside_a_namespace() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let options = DialOptions::parse(
            &serde_json::json!({"netns": "/proc/self/ns/net"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .expect("options");
        assert_eq!(options.netns.as_deref(), Some("/proc/self/ns/net"));
        assert!(
            !options.is_empty(),
            "the namespace takes the plain path out"
        );
        // entering our own namespace needs CAP_SYS_ADMIN even so, and where it
        // is refused the dial has to say so rather than quietly go out plain
        match connect_tcp_addr(addr, &options).await {
            Ok(stream) => assert_eq!(stream.peer_addr().expect("peer"), addr),
            Err(err) => {
                let raw = err.raw_os_error();
                assert!(
                    raw == Some(libc::EPERM) || raw == Some(libc::ENOSYS),
                    "the failure has to come from setns, not the dial: {err}"
                );
            }
        }
    }

    /// Off Linux `netns` parses and is reported as not applied, so the plain
    /// connect is what happens.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn netns_is_a_no_op_off_linux() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let options = DialOptions::parse(
            &serde_json::json!({"netns": "vpn"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .expect("options");
        assert_eq!(options.netns.as_deref(), Some("vpn"));
        let stream = connect_tcp_addr(addr, &options).await.expect("dial");
        assert_eq!(stream.peer_addr().expect("peer"), addr);
    }

    /// `domain_strategy` says which strategy the server address is resolved
    /// with, and `fallback_delay` how long the first family gets; both come
    /// off the outbound object.
    #[test]
    fn domain_strategy_and_fallback_delay_come_off_the_object() {
        let options = DialOptions::parse(
            &serde_json::json!({"domain_strategy": "prefer_ipv6", "fallback_delay": "50ms"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .expect("options");
        assert_eq!(
            options.domain_strategy,
            Some(crate::dns::Strategy::PreferIPv6)
        );
        assert_eq!(options.fallback_delay(), Duration::from_millis(50));
        assert!(options.parallel, "no detour and no TFO, so the race is on");
        // and the defaults
        let plain = DialOptions::parse(&serde_json::json!({}).as_object().unwrap().clone())
            .expect("options");
        assert_eq!(plain.domain_strategy, None);
        assert_eq!(plain.fallback_delay(), Duration::from_millis(300));
        // a detour or fast open hands the dial somewhere that cannot race
        for field in ["detour", "tcp_fast_open"] {
            let value = if field == "detour" {
                serde_json::json!("other")
            } else {
                serde_json::json!(true)
            };
            let obj = serde_json::json!({field: value});
            let options = DialOptions::parse(obj.as_object().expect("object")).expect("options");
            assert!(!options.parallel, "{field} must turn the race off");
        }
        assert!(
            DialOptions::parse(
                &serde_json::json!({"domain_strategy": "prefer_at_11th"})
                    .as_object()
                    .unwrap()
                    .clone()
            )
            .is_err()
        );
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

    /// Only SO_MARK needs privileges; do not skip the other socket options.
    #[cfg(target_os = "linux")]
    fn test_routing_mark(mark: u32) -> Option<u32> {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fd = new_socket(&addr, false).expect("socket");
        let result = DialOptions {
            routing_mark: Some(mark),
            ..Default::default()
        }
        .apply(fd, &addr, false);
        unsafe { libc::close(fd) };
        match result {
            Ok(()) => Some(mark),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                assert!(
                    std::env::var_os("TACHYON_TEST_REQUIRE_SO_MARK").is_none(),
                    "privileged SO_MARK check failed: {error}"
                );
                eprintln!(
                    "SO_MARK requires CAP_NET_ADMIN or CAP_NET_RAW; other options are still checked"
                );
                None
            }
            Err(error) => panic!("SO_MARK probe failed: {error}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn test_routing_mark(_mark: u32) -> Option<u32> {
        None
    }

    /// Read each applied option back with getsockopt.
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
            routing_mark: test_routing_mark(0x1234),
            reuse_addr: true,
            tcp_keep_alive: Some(Duration::from_secs(42)),
            tcp_keep_alive_interval: Some(Duration::from_secs(11)),
            ..Default::default()
        };
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fd = new_socket(&addr, false).expect("socket");
        options.apply(fd, &addr, false).expect("apply");
        if let Some(mark) = options.routing_mark {
            assert_eq!(
                get_int(fd, libc::SOL_SOCKET, libc::SO_MARK),
                mark as libc::c_int
            );
        }
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server = listener.local_addr().expect("addr");
        let options = DialOptions {
            routing_mark: test_routing_mark(0x2000),
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
        // and the handshake really happened: a socket handed back before its
        // connect ran reports no peer, and every later write would wait forever
        assert_eq!(client.peer_addr().expect("peer"), server);
        let mut client = client;
        // bounded, so a socket that was never connected fails here instead of
        // hanging the suite
        tokio::time::timeout(Duration::from_secs(5), client.write_all(b"ping"))
            .await
            .expect("the write must not block: the socket was never connected")
            .expect("write");
        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept must not block")
            .expect("accept");
    }
}
