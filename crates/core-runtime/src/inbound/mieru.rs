//! mieru server inbound (TCP transport only).
//!
//! Accepts a connection, identifies the user from the first segment
//! (see [`crate::mieru::discover`]), then reads the SOCKS5 CONNECT request that
//! the client sends as the first application payload and hands the session to
//! the router.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::inbound::{ClientConn, Target, drive_framed, parse_listen, socks_success_reply};
use crate::logging;
use crate::mieru;
use crate::route::Router;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Mieru {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    users: Arc<Vec<(String, [u8; 32])>>,
}

impl Mieru {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("mieru")
            .to_string();
        let at = format!("inbound[{tag}]");

        if let Some(t) = object.get("transport").and_then(Value::as_str)
            && !t.eq_ignore_ascii_case("tcp")
        {
            anyhow::bail!("{at}: transport {t} is not supported (tcp only)");
        }
        let mut users = Vec::new();
        for u in object
            .get("users")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let name = u.get("name").and_then(Value::as_str).unwrap_or_default();
            let pass = u
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name.is_empty() || pass.is_empty() {
                anyhow::bail!("{at}: user needs name and password");
            }
            users.push((name.to_string(), mieru::hashed_password(name, pass)));
        }
        if users.is_empty() {
            anyhow::bail!("{at}: users must not be empty");
        }

        let listen = parse_listen(object, &at)?;
        let listener = super::bind_tcp(SocketAddr::from(listen))
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            users: Arc::new(users),
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
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let users = Arc::clone(&self.users);
                    tokio::spawn(async move {
                        if let Err(err) = handle(stream, peer, users, tag, router).await {
                            logging::debug(format_args!("mieru {peer}: {err}"));
                        }
                    });
                }
                Err(err) => super::serve_stalled("mieru accept", &err).await,
            }
        }
    }
}

async fn handle(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    users: Arc<Vec<(String, [u8; 32])>>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()> {
    let local = stream.local_addr().unwrap_or(peer);
    let mut head = vec![0u8; mieru::FIRST_READ];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut head))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "first segment timeout"))??;
    let Some((idx, key)) = mieru::discover(&users, &head) else {
        // Unknown user: swallow whatever comes, say nothing.
        let mut sink = [0u8; 1024];
        let _ = timeout(Duration::from_secs(5), stream.read(&mut sink)).await;
        return Err(io::Error::other("unknown user"));
    };
    // The reference client reuses one connection for several sessions.
    mieru::serve_underlay(stream, &key, &users[idx].0, head, |session| {
        let tag = tag.clone();
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(err) = handle_session(session, local, peer, &tag, &router).await {
                logging::debug(format_args!("mieru {peer}: {err}"));
            }
        });
    })
    .await
}

async fn handle_session(
    mut session: tokio::io::DuplexStream,
    local: SocketAddr,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    let target = timeout(HANDSHAKE_TIMEOUT, read_request(&mut session))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timeout"))??;
    let target = match target {
        Ok(t) => t,
        Err(code) => {
            let _ = session
                .write_all(&crate::inbound::socks_failure_reply(code))
                .await;
            let _ = session.shutdown().await;
            return Err(io::Error::other("unsupported request"));
        }
    };
    let client = ClientConn::socks_stream(Box::new(session), local, socks_success_reply(local));
    drive_framed(client, peer, target, tag, router).await
}

/// Reads `05 CMD 00 ATYP addr port`. `Ok(Err(code))` is a SOCKS reply code.
async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<Result<Target, u8>> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(io::Error::other("bad socks version"));
    }
    let host = match h[3] {
        1 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        4 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        3 => None,
        _ => return Ok(Err(0x08)),
    };
    let name = if host.is_none() {
        let mut l = [0u8; 1];
        r.read_exact(&mut l).await?;
        let mut b = vec![0u8; l[0] as usize];
        r.read_exact(&mut b).await?;
        Some(String::from_utf8(b).map_err(|_| io::Error::other("bad domain"))?)
    } else {
        None
    };
    let mut p = [0u8; 2];
    r.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);
    if h[1] != 1 {
        return Ok(Err(0x07));
    }
    Ok(Ok(match (host, name) {
        (Some(ip), _) => Target::Ip(SocketAddr::new(ip, port)),
        (None, Some(n)) => Target::Domain(n, port),
        _ => unreachable!(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_domain_and_ip() {
        let req = mieru::socks5_request("example.com", None, 443).unwrap();
        let t = read_request(&mut &req[..]).await.unwrap().unwrap();
        assert_eq!(t, Target::Domain("example.com".into(), 443));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req = mieru::socks5_request("1.2.3.4", Some(ip), 80).unwrap();
        let t = read_request(&mut &req[..]).await.unwrap().unwrap();
        assert_eq!(t, Target::Ip("1.2.3.4:80".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejects_udp_associate() {
        let req = [5u8, 3, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(read_request(&mut &req[..]).await.unwrap(), Err(0x07));
    }
}
