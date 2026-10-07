use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::clash_state;
use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, UdpHub};
use crate::inbound::{
    ClientConn, Target, clash_meta, network_includes_udp, pump_conn_tracked, require_u16,
    socks_failure_reply, socks_success_reply,
};
use crate::logging;
use crate::route::{ConnContext, Decision, Router, hijack_dns};

/// Which protocols a listener of this shape speaks. `mixed` answers both, the
/// plain `socks` and `http` inbounds answer one and refuse the other, exactly as
/// the reference's separate inbounds do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    Mixed,
    Socks,
    Http,
}

impl Flavor {
    fn name(self) -> &'static str {
        match self {
            Flavor::Mixed => "mixed",
            Flavor::Socks => "socks",
            Flavor::Http => "http",
        }
    }
}

/// mixed inbound: SOCKS4/4a/5 + HTTP CONNECT on one port (and, with a flavor,
/// the same listener as the plain `socks` or `http` inbound).
pub struct Mixed {
    listener: TcpListener,
    tag: String,
    users: Vec<(String, String)>,
    router: Arc<Router>,
    /// Shared UDP ASSOCIATE relay hub (`network` allows UDP).
    udp: Option<Arc<UdpHub>>,
    flavor: Flavor,
}

impl Mixed {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        Self::bind_as(obj, router, Flavor::Mixed).await
    }

    pub async fn bind_as(obj: &Value, router: Arc<Router>, flavor: Flavor) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or(flavor.name());
        let at = format!("inbound[{tag}]");
        let port = require_u16(obj, "listen_port", &at)?;
        let host = obj
            .get("listen")
            .and_then(Value::as_str)
            .unwrap_or("127.0.0.1");
        let ip: IpAddr = host
            .parse()
            .map_err(|_| anyhow::anyhow!("{at}: invalid listen address {host:?}"))?;
        let listener = TcpListener::bind(SocketAddr::new(ip, port)).await?;
        let users = obj
            .get("users")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|u| {
                        let username = u.get("username")?.as_str()?.to_string();
                        let password = u.get("password")?.as_str()?.to_string();
                        Some((username, password))
                    })
                    .collect()
            })
            .unwrap_or_default();
        logging::info(format_args!(
            "inbound {}[{tag}] listening at {ip}:{port}",
            flavor.name()
        ));
        // an HTTP-only listener has no UDP ASSOCIATE to serve
        let udp = (flavor != Flavor::Http && network_includes_udp(obj)).then(|| {
            UdpHub::new(
                Arc::clone(&router),
                DEFAULT_UDP_TIMEOUT,
                DatagramFrame::Socks,
            )
        });
        Ok(Self {
            listener,
            tag: tag.to_string(),
            users,
            router,
            udp,
            flavor,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let router = Arc::clone(&self.router);
                    let users = self.users.clone();
                    let tag = self.tag.clone();
                    let udp = self.udp.clone();
                    let flavor = self.flavor;
                    tokio::spawn(async move {
                        if let Err(err) =
                            handle_conn(stream, peer, &tag, &users, &router, udp.as_ref(), flavor)
                                .await
                        {
                            logging::debug(format_args!("mixed[{tag}] {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::warn(format_args!("mixed[{}] accept: {err}", self.tag));
                    return;
                }
            }
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    users: &[(String, String)],
    router: &Arc<Router>,
    udp: Option<&Arc<UdpHub>>,
    flavor: Flavor,
) -> io::Result<()> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    match first[0] {
        0x05 if flavor != Flavor::Http => socks5(stream, peer, tag, users, router, udp).await,
        0x04 if flavor != Flavor::Http => socks4(stream, peer, tag, users, router).await,
        0x04 | 0x05 => Err(io::Error::other("socks request on an http inbound")),
        byte if flavor != Flavor::Socks => http(stream, byte, peer, tag, users, router).await,
        _ => Err(io::Error::other("not a socks request on a socks inbound")),
    }
}

/// SOCKS4 / SOCKS4a CONNECT: `[4][1][port:2][ip:4][userid]\0`, and for 4a an ip
/// of `0.0.0.x` followed by `[domain]\0`. The reply is `[0][code][port:2][ip:4]`
/// with 90 for granted and 91 for rejected, written once the upstream is up.
/// With users configured the userid has to name a user whose password is empty,
/// because SOCKS4 has nowhere to put one (the reference verifies `(userid, "")`).
async fn socks4(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    users: &[(String, String)],
    router: &Arc<Router>,
) -> io::Result<()> {
    const GRANTED: u8 = 90;
    const REJECTED: u8 = 91;
    let mut head = [0u8; 7];
    stream.read_exact(&mut head).await?;
    // best effort: the client may be gone already
    async fn reject(stream: &mut TcpStream) {
        let _ = stream.write_all(&[0u8, REJECTED, 0, 0, 0, 0, 0, 0]).await;
    }
    if head[0] != 1 {
        reject(&mut stream).await;
        return Err(io::Error::other("only CONNECT is supported"));
    }
    let port = u16::from_be_bytes([head[1], head[2]]);
    let ip = [head[3], head[4], head[5], head[6]];
    let userid = read_cstring(&mut stream).await?;
    let domain = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        Some(read_cstring(&mut stream).await?)
    } else {
        None
    };
    let mut auth_user = None;
    if !users.is_empty() {
        let name = String::from_utf8_lossy(&userid).into_owned();
        if !users.iter().any(|(u, p)| *u == name && p.is_empty()) {
            reject(&mut stream).await;
            return Err(io::Error::other("auth failed"));
        }
        auth_user = Some(name);
    }
    let target = match domain {
        Some(host) => Target::Domain(
            String::from_utf8(host).map_err(|_| io::Error::other("bad domain"))?,
            port,
        ),
        None => Target::Ip(SocketAddr::new(IpAddr::V4(ip.into()), port)),
    };
    let granted = [0u8, GRANTED, head[1], head[2], ip[0], ip[1], ip[2], ip[3]];

    // no lazy SOCKS5 reply on this connection: the reply is ours to write
    let mut client = ClientConn::http(stream);
    let mut ctx = ConnContext::new(tag, peer, target, "tcp");
    ctx.auth_user = auth_user;
    let decision = match router.route(&mut client, &mut ctx).await {
        Ok(decision) => decision,
        Err(err) => {
            let _ = client
                .write_all(&[0u8, REJECTED, head[1], head[2], ip[0], ip[1], ip[2], ip[3]])
                .await;
            return Err(err);
        }
    };
    match decision {
        Decision::HijackDns => {
            client.write_all(&granted).await?;
            hijack_dns(&mut client, &ctx).await
        }
        Decision::Outbound(idx) => {
            let dest = ctx.destination.clone();
            match router.connect_index(idx, &dest).await {
                Ok(conn) => {
                    client.write_all(&granted).await?;
                    logging::info(format_args!("socks[{tag}] {peer} CONNECT {dest}"));
                    let tracker = clash_state::ConnHandle::open(clash_meta(&ctx, router, idx));
                    pump_conn_tracked(client, conn, &ctx.sniff_prefix, Some(&tracker)).await
                }
                Err(err) => {
                    let _ = client
                        .write_all(&[0u8, REJECTED, head[1], head[2], ip[0], ip[1], ip[2], ip[3]])
                        .await;
                    Err(err)
                }
            }
        }
    }
}

/// A NUL-terminated field of a SOCKS4 request, without the NUL. Capped, because
/// the peer controls how long it runs.
async fn read_cstring(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    const MAX: usize = 1024;
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            return Ok(out);
        }
        if out.len() >= MAX {
            return Err(io::Error::other("socks4 field too long"));
        }
        out.push(byte[0]);
    }
}

async fn socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    users: &[(String, String)],
    router: &Arc<Router>,
    udp: Option<&Arc<UdpHub>>,
) -> io::Result<()> {
    let mut greeting = vec![0x05];
    let mut nmethods = [0u8; 1];
    stream.read_exact(&mut nmethods).await?;
    let mut methods = vec![0u8; usize::from(nmethods[0])];
    stream.read_exact(&mut methods).await?;
    greeting.extend_from_slice(&methods);

    let auth_ok = if users.is_empty() {
        methods.contains(&0x00)
    } else {
        methods.contains(&0x02)
    };
    if !auth_ok {
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(io::Error::other("no acceptable auth method"));
    }

    let mut auth_user: Option<String> = None;
    if users.is_empty() {
        stream.write_all(&[0x05, 0x00]).await?;
    } else {
        stream.write_all(&[0x05, 0x02]).await?;
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x01 {
            stream.write_all(&[0x01, 0x01]).await?;
            return Err(io::Error::other("unsupported auth subnegotiation"));
        }
        let mut username = vec![0u8; usize::from(head[1])];
        stream.read_exact(&mut username).await?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut password = vec![0u8; usize::from(plen[0])];
        stream.read_exact(&mut password).await?;
        let ok = users.iter().any(|(u, p)| {
            u.as_bytes() == username.as_slice() && p.as_bytes() == password.as_slice()
        });
        stream.write_all(&[0x01, u8::from(!ok)]).await?;
        if !ok {
            return Err(io::Error::other("auth failed"));
        }
        auth_user = String::from_utf8(username).ok();
    }

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::other("bad socks version in request"));
    }
    if head[1] == 0x03 {
        // UDP ASSOCIATE — the requested address is only a client hint; the
        // relay replies from its own socket and reads the real source from
        // each datagram (reference socks inbound `ListenPacket`).
        consume_socks_addr(&mut stream, head[3]).await?;
        let hub = match udp {
            Some(hub) => Arc::clone(hub),
            None => {
                stream.write_all(&socks_failure_reply(0x07)).await?;
                return Err(io::Error::other("udp not enabled in network field"));
            }
        };
        return socks_udp_associate(stream, peer, tag, hub).await;
    }
    if head[1] != 0x01 {
        stream.write_all(&socks_failure_reply(0x07)).await?;
        return Err(io::Error::other("only CONNECT is supported"));
    }
    let target = match head[3] {
        0x01 => {
            let mut raw = [0u8; 6];
            stream.read_exact(&mut raw).await?;
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            Target::Ip(SocketAddr::new(ip, port))
        }
        0x04 => {
            let mut raw = [0u8; 18];
            stream.read_exact(&mut raw).await?;
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&raw[0..16]).expect("fixed slice"),
            ));
            let port = u16::from_be_bytes([raw[16], raw[17]]);
            Target::Ip(SocketAddr::new(ip, port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut host).await?;
            let mut port_raw = [0u8; 2];
            stream.read_exact(&mut port_raw).await?;
            let host = String::from_utf8(host).map_err(|_| io::Error::other("bad domain"))?;
            Target::Domain(host, u16::from_be_bytes(port_raw))
        }
        _ => {
            stream
                .write_all(&crate::inbound::socks_failure_reply(0x08))
                .await?;
            return Err(io::Error::other("unsupported address type"));
        }
    };

    let local = stream.local_addr()?;
    let mut client = ClientConn::socks(stream, socks_success_reply(local));
    let mut ctx = ConnContext::new(tag, peer, target, "tcp");
    ctx.auth_user = auth_user;

    let decision = match router.route(&mut client, &mut ctx).await {
        Ok(decision) => decision,
        Err(err) => {
            let _ = client.fail(&err).await;
            return Err(err);
        }
    };

    match decision {
        Decision::HijackDns => {
            logging::info(format_args!(
                "mixed[{tag}] {peer} HIJACK-DNS {}",
                ctx.destination
            ));
            hijack_dns(&mut client, &ctx).await
        }
        Decision::Outbound(idx) => {
            let dest = ctx.destination.clone();
            match router.connect_index(idx, &dest).await {
                Ok(conn) => {
                    // The reference reports handshake success to the client
                    // connection the moment the upstream is up (route/conn.go,
                    // `N.ReportConnHandshakeSuccess`), not on the first payload.
                    // A client that waits for this reply before sending anything --
                    // curl through SOCKS, every browser -- would otherwise wait for
                    // a reply that only its own first packet can trigger.
                    client.established().await?;
                    logging::info(format_args!("mixed[{tag}] {peer} CONNECT {dest}"));
                    let tracker = clash_state::ConnHandle::open(clash_meta(&ctx, router, idx));
                    pump_conn_tracked(client, conn, &ctx.sniff_prefix, Some(&tracker)).await
                }
                Err(err) => {
                    let _ = client.fail(&err).await;
                    Err(err)
                }
            }
        }
    }
}

/// Consume a SOCKS5 address (ATYP + addr + port) from the control stream;
/// the ASSOCIATE hint is informational only (reference socks inbound).
async fn consume_socks_addr(stream: &mut TcpStream, atyp: u8) -> io::Result<()> {
    match atyp {
        0x01 => {
            let mut raw = [0u8; 6];
            stream.read_exact(&mut raw).await?;
        }
        0x04 => {
            let mut raw = [0u8; 18];
            stream.read_exact(&mut raw).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut rest).await?;
        }
        _ => {
            stream.write_all(&socks_failure_reply(0x08)).await?;
            return Err(io::Error::other("unsupported address type"));
        }
    }
    Ok(())
}

/// SOCKS5 UDP ASSOCIATE: answer with a relay socket, pump datagrams through
/// the shared hub, and tear the association down when the control
/// connection closes (RFC 1928 §7).
async fn socks_udp_associate(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    hub: Arc<UdpHub>,
) -> io::Result<()> {
    let local = stream.local_addr()?;
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?);
    let relay_addr = relay.local_addr()?;
    let bnd_ip = if local.ip().is_unspecified() {
        peer.ip()
    } else {
        local.ip()
    };
    let bnd = SocketAddr::new(bnd_ip, relay_addr.port());
    stream.write_all(&socks_success_reply(bnd)).await?;
    logging::info(format_args!("mixed[{tag}] UDP ASSOCIATE relay {bnd}"));

    let relay_task = {
        let relay = Arc::clone(&relay);
        let hub = Arc::clone(&hub);
        let tag = tag.to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match relay.recv_from(&mut buf).await {
                    Ok((n, source)) => match parse_socks_udp_datagram(&buf[..n]).await {
                        Some((dest, offset)) => {
                            if hub.try_existing(source, dest, &buf[offset..n]) {
                                continue;
                            }
                            if let Err(err) = hub
                                .handle(
                                    Reply::Socket(Arc::clone(&relay)),
                                    source,
                                    dest,
                                    &buf[offset..n],
                                    &tag,
                                )
                                .await
                            {
                                logging::debug(format_args!(
                                    "mixed[{tag}] udp relay {source}: {err}"
                                ));
                            }
                        }
                        None => logging::debug(format_args!(
                            "mixed[{tag}] udp relay: invalid datagram ({n}B)"
                        )),
                    },
                    Err(err) => {
                        logging::debug(format_args!("mixed[{tag}] udp relay recv: {err}"));
                        return;
                    }
                }
            }
        })
    };

    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    relay_task.abort();
    Ok(())
}

/// `[RSV][RSV][FRAG][ATYP][ADDR][PORT][payload]` → (destination, payload
/// offset). Domain targets resolve through the DNS service.
async fn parse_socks_udp_datagram(data: &[u8]) -> Option<(SocketAddr, usize)> {
    if data.len() < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
        return None;
    }
    let (ip, offset) = match data[3] {
        0x01 => {
            if data.len() < 10 {
                return None;
            }
            let octets: [u8; 4] = data[4..8].try_into().ok()?;
            (IpAddr::V4(octets.into()), 8)
        }
        0x04 => {
            if data.len() < 22 {
                return None;
            }
            let octets: [u8; 16] = data[4..20].try_into().ok()?;
            (IpAddr::V6(octets.into()), 20)
        }
        0x03 => {
            let len = *data.get(4)? as usize;
            let end = 5 + len + 2;
            if data.len() < end {
                return None;
            }
            let host = std::str::from_utf8(&data[5..5 + len]).ok()?;
            let ip = match host.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    let service = crate::dns::current()?;
                    *service.resolve(host).await.ok()?.first()?
                }
            };
            (ip, end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    Some((SocketAddr::new(ip, port), offset + 2))
}

/// Hop-by-hop headers removed before forwarding (RFC 9110 §7.6.1 +
/// reference `removeHopByHopHeaders`).
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

async fn http(
    mut stream: TcpStream,
    first_byte: u8,
    peer: SocketAddr,
    tag: &str,
    users: &[(String, String)],
    router: &Arc<Router>,
) -> io::Result<()> {
    let head = read_http_head(&mut stream, first_byte).await?;
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let uri = parts.next().unwrap_or_default().to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if !users.is_empty() && !proxy_auth_ok(&head_text, users) {
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"tachyon\"\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await?;
        return Err(io::Error::other("proxy auth failed"));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        return http_connect(stream, peer, tag, router, &uri).await;
    }

    http_forward(
        stream, peer, tag, router, &method, &uri, &version, &head_text,
    )
    .await
}

async fn http_connect(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
    authority: &str,
) -> io::Result<()> {
    let Some((host, port)) = authority.rsplit_once(':') else {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(io::Error::other("CONNECT without port"));
    };
    let port: u16 = port.parse().map_err(|_| io::Error::other("bad port"))?;
    let target = if host.parse::<IpAddr>().is_ok() {
        Target::Ip(SocketAddr::new(host.parse().expect("checked"), port))
    } else {
        Target::Domain(host.to_string(), port)
    };

    // Reference serves the 200 before route/dial; a later failure just closes.
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;

    let mut client = ClientConn::http(stream);
    let mut ctx = ConnContext::new(tag, peer, target, "tcp");

    let decision = router.route(&mut client, &mut ctx).await?;
    match decision {
        Decision::HijackDns => {
            logging::info(format_args!(
                "mixed[{tag}] {peer} HIJACK-DNS {}",
                ctx.destination
            ));
            hijack_dns(&mut client, &ctx).await
        }
        Decision::Outbound(idx) => {
            let dest = ctx.destination.clone();
            let conn = router.connect_index(idx, &dest).await?;
            logging::info(format_args!("mixed[{tag}] {peer} CONNECT {dest}"));
            let tracker = clash_state::ConnHandle::open(clash_meta(&ctx, router, idx));
            pump_conn_tracked(client, conn, &ctx.sniff_prefix, Some(&tracker)).await
        }
    }
}

/// Absolute-URI forward: `forwardDestination` (default port 80), route, rewrite
/// to origin-form, strip hop-by-hop; keep-alive loop with re-dial on host change.
#[allow(clippy::too_many_arguments)]
async fn http_forward(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
    method: &str,
    uri: &str,
    version: &str,
    head_text: &str,
) -> io::Result<()> {
    let Some((host, port, path)) = parse_forward_uri(uri) else {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(io::Error::other(format!("invalid request URI {uri:?}")));
    };
    let target = to_target(&host, port);

    let mut ctx = ConnContext::new(tag, peer, target, "tcp");
    ctx.protocol = Some("http".to_string());
    ctx.domain = Some(host);

    let decision = router.route_raw(&mut ctx).await?;
    let (idx, mut dest) = match decision {
        Decision::HijackDns => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Err(io::Error::other(
                "hijack-dns not supported for http forward",
            ));
        }
        Decision::Outbound(idx) => (idx, ctx.destination.clone()),
    };

    let mut conn = dial_plain(router, idx, &dest, &mut stream, tag, peer).await?;
    logging::info(format_args!(
        "mixed[{tag}] {peer} HTTP {method} {dest}{path}"
    ));

    // Owned request state so the keep-alive loop can rebind freely.
    let mut method = method.to_string();
    let mut path = path;
    let mut version = version.to_string();
    let mut head = head_text.to_string();
    loop {
        let body_len = content_length(&head);
        let body = read_exact_body(&mut stream, body_len).await?;
        let keep = request_wants_keep_alive(&version, &head);
        let rewritten = rewrite_request(&method, &path, &version, &head, &body, keep);
        if conn.write_all(&rewritten).await.is_err() {
            return Ok(());
        }

        let (resp_head, resp_body_len, resp_chunked) = match read_response_head(&mut conn).await {
            Ok(v) => v,
            Err(_) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Ok(());
            }
        };
        stream.write_all(&resp_head).await?;

        if resp_chunked {
            forward_chunked(&mut conn, &mut stream).await?;
        } else if let Some(len) = resp_body_len {
            copy_exact(&mut conn, &mut stream, len).await?;
        } else {
            tokio::io::copy(&mut conn, &mut stream).await?;
            return Ok(());
        }

        if !keep || !response_keep_alive(&String::from_utf8_lossy(&resp_head)) {
            return Ok(());
        }

        // Next request on the same client connection.
        let next = match read_http_head_any(&mut stream).await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        let next_text = String::from_utf8_lossy(&next).into_owned();
        let Some(parsed) = parse_request_line(&next_text) else {
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        };
        let next_target = to_target(&parsed.host, parsed.port);
        if next_target != dest {
            drop(conn);
            let mut nctx = ConnContext::new(tag, peer, next_target, "tcp");
            nctx.protocol = Some("http".to_string());
            nctx.domain = Some(parsed.host);
            let ndec = router.route_raw(&mut nctx).await?;
            let Decision::Outbound(nidx) = ndec else {
                return Ok(());
            };
            dest = nctx.destination.clone();
            conn = dial_plain(router, nidx, &dest, &mut stream, tag, peer).await?;
        }
        method = parsed.method;
        path = parsed.path;
        version = parsed.version;
        head = next_text;
    }
}

struct ParsedRequest {
    method: String,
    host: String,
    port: u16,
    path: String,
    version: String,
}

fn parse_request_line(head: &str) -> Option<ParsedRequest> {
    let request_line = head.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let uri = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    let (host, port, path) = parse_forward_uri(&uri)?;
    Some(ParsedRequest {
        method,
        host,
        port,
        path,
        version,
    })
}

fn to_target(host: &str, port: u16) -> Target {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Target::Ip(SocketAddr::new(ip, port))
    } else {
        Target::Domain(host.to_string(), port)
    }
}

async fn dial_plain(
    router: &Arc<Router>,
    idx: usize,
    dest: &Target,
    stream: &mut TcpStream,
    tag: &str,
    peer: SocketAddr,
) -> io::Result<crate::inbound::AnyStream> {
    match router.connect_index(idx, dest).await {
        Ok(crate::inbound::Conn::Plain(s)) => Ok(s),
        Ok(crate::inbound::Conn::Shadowsocks(..)) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Err(io::Error::other(
                "http forward over shadowsocks outbound not supported",
            ))
        }
        Err(err) => {
            logging::debug(format_args!("mixed[{tag}] {peer} dial {dest}: {err}"));
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            Err(err)
        }
    }
}

async fn copy_exact<S, D>(src: &mut S, dst: &mut D, mut left: u64) -> io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
    D: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = src.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    Ok(())
}

/// `http`/`ws` absolute-form URI → (host, port, path); default port 80;
/// path defaults to `/` (reference `forwardDestination`).
fn parse_forward_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("ws://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => (h.to_string(), p.parse().ok()?),
        Some((h, _)) => (h.to_string(), 80),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

fn content_length(head: &str) -> u64 {
    for line in head.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            return value.trim().parse::<u64>().unwrap_or(0);
        }
    }
    0
}

fn request_wants_keep_alive(version: &str, head: &str) -> bool {
    let connection = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("connection")
            .then(|| value.trim().to_ascii_lowercase())
    });
    if version.eq_ignore_ascii_case("HTTP/1.0") {
        connection
            .as_deref()
            .is_some_and(|v| v.contains("keep-alive"))
    } else {
        connection.as_deref() != Some("close")
    }
}

fn response_keep_alive(resp_head: &str) -> bool {
    for line in resp_head.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("connection")
        {
            return !value.trim().eq_ignore_ascii_case("close");
        }
    }
    true
}

fn rewrite_request(
    method: &str,
    path: &str,
    version: &str,
    head: &str,
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + body.len() + 64);
    out.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
    let mut connection_set = false;
    for line in head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("connection") {
            connection_set = true;
        }
        if HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !connection_set {
        if keep_alive {
            out.extend_from_slice(b"Connection: keep-alive\r\n");
        } else {
            out.extend_from_slice(b"Connection: close\r\n");
        }
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

async fn read_http_head(stream: &mut TcpStream, first_byte: u8) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [first_byte];
    loop {
        head.extend_from_slice(&byte);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("http header too large"));
        }
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if stream.read_exact(&mut byte).await.is_err() {
            if head.is_empty() {
                return Err(io::Error::other("empty http head"));
            }
            return Ok(head);
        }
    }
}

async fn read_http_head_any<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            if head.is_empty() {
                return Err(io::Error::other("eof"));
            }
            return Ok(head);
        }
        head.extend_from_slice(&byte);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("http header too large"));
        }
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

async fn read_exact_body<S>(stream: &mut S, len: u64) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut body = Vec::new();
    if len == 0 {
        return Ok(body);
    }
    let mut buf = vec![0u8; 16 * 1024];
    while (body.len() as u64) < len {
        let want = ((len - body.len() as u64) as usize).min(buf.len());
        let n = stream.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok(body)
}

async fn read_response_head<S>(stream: &mut S) -> io::Result<(Vec<u8>, Option<u64>, bool)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::other("eof in response head"));
        }
        head.extend_from_slice(&byte);
        if head.len() > 64 * 1024 {
            return Err(io::Error::other("response head too large"));
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut content_len = None;
    let mut chunked = false;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_len = value.trim().parse::<u64>().ok();
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    Ok((head, content_len, chunked))
}

async fn forward_chunked<S, D>(src: &mut S, dst: &mut D) -> io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
    D: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Forward every byte of the chunked body until the terminating 0-chunk.
    // Chunk framing is preserved verbatim (we never re-frame).
    let mut buf = vec![0u8; 16 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            dst.write_all(&pending).await?;
            return Ok(());
        }
        pending.extend_from_slice(&buf[..n]);
        dst.write_all(&buf[..n]).await?;
        // Look for the terminator only when it could plausibly be present.
        if pending.windows(5).any(|w| w == b"0\r\n\r\n") {
            // May be a false positive inside payload; require it at a
            // position that follows only CRLF-delimited chunk boundaries.
            // For parity with reference (raw pump until upstream closes the
            // message) we only stop if the last 5 bytes are the terminator.
            if pending.ends_with(b"0\r\n\r\n") {
                return Ok(());
            }
        }
        // Cap scan window so we do not grow unbounded on long streams.
        if pending.len() > 64 * 1024 {
            pending.drain(..pending.len() - 8 * 1024);
        }
    }
}

fn proxy_auth_ok(head_text: &str, users: &[(String, String)]) -> bool {
    for line in head_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let value = value.trim();
        let Some(b64) = value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))
        else {
            return false;
        };
        let Ok(raw) = crate::outbound::shadowsocks::crypto::decode_base64_std(b64.trim()) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(raw) else {
            return false;
        };
        let Some((u, p)) = decoded.split_once(':') else {
            return false;
        };
        return users.iter().any(|(eu, ep)| eu == u && ep == p);
    }
    false
}
