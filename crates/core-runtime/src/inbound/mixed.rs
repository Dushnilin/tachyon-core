use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::inbound::{Target, dial, pump, require_u16};
use crate::logging;
use crate::route::Router;

/// mixed inbound: SOCKS5 + HTTP CONNECT on one port.
pub struct Mixed {
    listener: TcpListener,
    tag: String,
    users: Vec<(String, String)>,
    router: Arc<Router>,
}

impl Mixed {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = obj.get("tag").and_then(Value::as_str).unwrap_or("mixed");
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
            "inbound mixed[{tag}] listening at {ip}:{port}"
        ));
        Ok(Self {
            listener,
            tag: tag.to_string(),
            users,
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
                    let users = self.users.clone();
                    let tag = self.tag.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_conn(stream, peer, &tag, &users, &router).await {
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
) -> io::Result<()> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    if first[0] == 0x05 {
        socks5(stream, peer, tag, users, router).await
    } else {
        http(stream, first[0], peer, tag, router).await
    }
}

async fn socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    users: &[(String, String)],
    router: &Arc<Router>,
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
    }

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::other("bad socks version in request"));
    }
    if head[1] != 0x01 {
        socks_reply(&mut stream, 0x07).await?;
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
            socks_reply(&mut stream, 0x08).await?;
            return Err(io::Error::other("unsupported address type"));
        }
    };

    match dial(router, &target).await {
        Ok(upstream) => {
            socks_reply(&mut stream, 0x00).await?;
            logging::info(format_args!("mixed[{tag}] {peer} CONNECT {target}"));
            pump(stream, upstream).await?;
            Ok(())
        }
        Err(err) => {
            socks_reply(&mut stream, 0x01).await?;
            Err(err)
        }
    }
}

async fn socks_reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

async fn http(
    mut stream: TcpStream,
    first_byte: u8,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [first_byte];
    loop {
        head.extend_from_slice(&byte);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("http header too large"));
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if stream.read_exact(&mut byte).await.is_err() {
            break;
        }
    }
    let request = String::from_utf8_lossy(&head);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();

    if !method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await?;
        logging::debug(format_args!(
            "mixed[{tag}] {peer}: plain http proxy not supported yet"
        ));
        return Ok(());
    }

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

    match dial(router, &target).await {
        Ok(upstream) => {
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            logging::info(format_args!("mixed[{tag}] {peer} CONNECT {target}"));
            pump(stream, upstream).await?;
            Ok(())
        }
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Err(io::Error::other("dial failed"))
        }
    }
}
