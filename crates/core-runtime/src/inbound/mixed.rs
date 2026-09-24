use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::inbound::{ClientConn, Target, pump_conn, require_u16, socks_success_reply};
use crate::logging;
use crate::route::{ConnContext, Decision, Router, hijack_dns};

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
        http(stream, first[0], peer, tag, users, router).await
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
    if head[1] != 0x01 {
        stream
            .write_all(&crate::inbound::socks_failure_reply(0x07))
            .await?;
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
                    logging::info(format_args!("mixed[{tag}] {peer} CONNECT {dest}"));
                    pump_conn(client, conn, &ctx.sniff_prefix).await
                }
                Err(err) => {
                    let _ = client.fail(&err).await;
                    Err(err)
                }
            }
        }
    }
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
            pump_conn(client, conn, &ctx.sniff_prefix).await
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
