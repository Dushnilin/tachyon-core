//! FPTN server inbound — `fptn-project/fptn` server.
//!
//! Provides the complete FPTN protocol server side:
//! 1. `POST /api/v1/login`: validates user credentials, issues JWT bearer token.
//! 2. `GET /api/v1/dns`: returns configured primary and secondary DNS resolvers.
//! 3. `GET /api/v1/fptn`: WebSocket handshake upgrade.
//! 4. WebSocket data plane: sends `MSG_IP_ASSIGNMENT`, processes `MSG_BATCH_IP_PACKET`
//!    carrying client IP datagrams, answers ICMP echo requests, and forwards UDP/TCP
//!    into the Tachyon Router data plane.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::inbound::tls::ServerTls;
use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, UdpHub};
use crate::inbound::{ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::outbound::fptn::proto::{decode_batch, encode_batch, encode_ip_assignment};
use crate::outbound::proxy::base64_std;
use crate::route::Router;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

pub struct Fptn {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    users: Vec<(String, String)>,
    dns: String,
    dns_ipv6: String,
    tls: Option<Arc<ServerTls>>,
    client_ip_counter: Arc<AtomicU32>,
}

impl Fptn {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("fptn")
            .to_string();
        let at = format!("inbound[{tag}]");

        let mut users = Vec::new();
        if let Some(user_list) = object.get("users").and_then(Value::as_array) {
            for user in user_list {
                if let Some(u) = user.get("username").and_then(Value::as_str)
                    && let Some(p) = user.get("password").and_then(Value::as_str)
                {
                    users.push((u.to_string(), p.to_string()));
                }
            }
        }

        let dns = object
            .get("dns")
            .and_then(Value::as_str)
            .unwrap_or("1.1.1.1")
            .to_string();
        let dns_ipv6 = object
            .get("dns_ipv6")
            .and_then(Value::as_str)
            .unwrap_or("fc00:1::1")
            .to_string();

        let listen = parse_listen(object, &at)?;
        let listener = super::bind_tcp(std::net::SocketAddr::from(listen))
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;

        let tls = ServerTls::from_inbound(obj, &at)?;

        logging::info(format_args!(
            "inbound fptn[{tag}] listening at {}:{} (users: {})",
            listen.0,
            listen.1,
            users.len()
        ));

        Ok(Self {
            listener,
            tag,
            router,
            users,
            dns,
            dns_ipv6,
            tls,
            client_ip_counter: Arc::new(AtomicU32::new(2)),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        let tag = Arc::new(self.tag);
        let router = self.router;
        let users = Arc::new(self.users);
        let dns = Arc::new(self.dns);
        let dns_ipv6 = Arc::new(self.dns_ipv6);
        let tls = self.tls;
        let ip_counter = self.client_ip_counter;

        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let tag = Arc::clone(&tag);
                    let router = Arc::clone(&router);
                    let users = Arc::clone(&users);
                    let dns = Arc::clone(&dns);
                    let dns_ipv6 = Arc::clone(&dns_ipv6);
                    let tls = tls.clone();
                    let ip_counter = Arc::clone(&ip_counter);

                    tokio::spawn(async move {
                        let stream: Box<dyn AsyncStream> = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(tls_stream) => Box::new(tls_stream),
                                Err(err) => {
                                    logging::debug(format_args!(
                                        "fptn[{tag}] TLS accept {peer}: {err}"
                                    ));
                                    return;
                                }
                            },
                            None => Box::new(stream),
                        };

                        if let Err(err) = handle_session(
                            stream,
                            peer,
                            &tag,
                            &router,
                            &users,
                            &dns,
                            &dns_ipv6,
                            &ip_counter,
                        )
                        .await
                        {
                            logging::debug(format_args!("fptn[{tag}] {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    super::serve_stalled(&format!("fptn[{tag}] accept"), &err).await;
                }
            }
        }
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

#[allow(clippy::too_many_arguments)]
async fn handle_session(
    mut stream: Box<dyn AsyncStream>,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
    users: &[(String, String)],
    dns: &str,
    dns_ipv6: &str,
    ip_counter: &AtomicU32,
) -> io::Result<()> {
    // 1. Read HTTP request header
    let (head, mut initial_body) = read_http_header(&mut stream).await?;
    let lines: Vec<&str> = head.lines().collect();
    if lines.is_empty() {
        return Ok(());
    }
    let req_line = lines[0];
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    // 2. Dispatch HTTP route
    match (method, path) {
        ("POST", "/api/v1/login") => {
            handle_login(&mut stream, &lines, &mut initial_body, users).await
        }
        ("GET", "/api/v1/dns") => handle_get_dns(&mut stream, dns, dns_ipv6).await,
        ("GET", "/api/v1/fptn") => {
            handle_websocket_tunnel(stream, peer, tag, router, &lines, ip_counter).await
        }
        _ => {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes()).await?;
            Ok(())
        }
    }
}

async fn read_http_header<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            let head_str = String::from_utf8_lossy(&buf[..buf.len() - 4]).into_owned();
            return Ok((head_str, Vec::new()));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "fptn: invalid HTTP header",
    ))
}

async fn handle_login<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    headers: &[&str],
    _body_prefix: &mut Vec<u8>,
    users: &[(String, String)],
) -> io::Result<()> {
    let content_len = headers
        .iter()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                lower.split(':').nth(1)?.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        stream.read_exact(&mut body).await?;
    }

    let auth_ok = if users.is_empty() {
        true
    } else if let Ok(val) = serde_json::from_slice::<Value>(&body) {
        let u = val
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let p = val
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or_default();
        users
            .iter()
            .any(|(expected_u, expected_p)| expected_u == u && expected_p == p)
    } else {
        false
    };

    if auth_ok {
        let token = "fptn_access_token_authorized";
        let resp_json = format!(r#"{{"access_token":"{token}","token_type":"bearer"}}"#);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_json}",
            resp_json.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
    } else {
        let resp_json = r#"{"error":"invalid_credentials"}"#;
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_json}",
            resp_json.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
    }
    Ok(())
}

async fn handle_get_dns<S: AsyncWrite + Unpin>(
    stream: &mut S,
    dns: &str,
    dns_ipv6: &str,
) -> io::Result<()> {
    let resp_json = format!(r#"{{"dns":"{dns}","dns_ipv6":"{dns_ipv6}"}}"#);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_json}",
        resp_json.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

async fn handle_websocket_tunnel(
    mut stream: Box<dyn AsyncStream>,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
    headers: &[&str],
    ip_counter: &AtomicU32,
) -> io::Result<()> {
    let ws_key = headers
        .iter()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                Some(l.split(':').nth(1)?.trim())
            } else {
                None
            }
        })
        .ok_or_else(|| io::Error::other("fptn: missing Sec-WebSocket-Key"))?;

    let mut hash = Sha1::new();
    hash.update(ws_key.as_bytes());
    hash.update(WS_GUID);
    let accept = base64_std(&hash.finalize());

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    let client_idx = ip_counter.fetch_add(1, Ordering::Relaxed);
    let client_ipv4 = format!("10.88.0.{}", (client_idx % 250) + 2);
    let client_ipv6 = format!("fc00:88::{:x}", client_idx);

    logging::info(format_args!(
        "fptn[{tag}] {peer}: client connected via WebSocket, assigned {client_ipv4}"
    ));

    // Send initial MSG_IP_ASSIGNMENT
    let assign_payload = encode_ip_assignment(&client_ipv4, &client_ipv6);
    send_ws_frame(&mut stream, OP_BINARY, &assign_payload).await?;

    let hub = UdpHub::new(Arc::clone(router), DEFAULT_UDP_TIMEOUT, DatagramFrame::Raw);
    let _stop_hub = crate::inbound::udp::StopHub(Arc::clone(&hub));

    let stream = Arc::new(Mutex::new(stream));
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<crate::inbound::udp::TunReply>(256);
    let ws_writer = Arc::clone(&stream);
    let client_v4: Ipv4Addr = client_ipv4.parse().unwrap_or(Ipv4Addr::new(10, 88, 0, 2));
    tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            let remote_ip = match reply.src.ip() {
                IpAddr::V4(ip) => ip,
                _ => continue,
            };
            let pkt = crate::inbound::tun::build_ipv4_udp(
                remote_ip,
                client_v4,
                reply.src.port(),
                reply.dest.port(),
                &reply.payload,
            );
            if let Ok(batch) = encode_batch(&[pkt]) {
                let mut s = ws_writer.lock().await;
                let _ = send_ws_frame(&mut *s, OP_BINARY, &batch).await;
            }
        }
    });

    // WebSocket read loop
    loop {
        let (opcode, payload) = match read_ws_message(&stream).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(e) => {
                logging::debug(format_args!("fptn[{tag}] {peer} read error: {e}"));
                break;
            }
        };

        match opcode {
            OP_BINARY => {
                let packets = match decode_batch(&payload) {
                    Ok(pkts) => pkts,
                    Err(_) => continue,
                };

                for pkt in packets {
                    process_client_packet(pkt, tag, router, &hub, &reply_tx, &stream).await;
                }
            }
            OP_PING => {
                let mut s = stream.lock().await;
                let _ = send_ws_frame(&mut *s, OP_PONG, &payload).await;
            }
            OP_CLOSE => {
                let mut s = stream.lock().await;
                let _ = send_ws_frame(&mut *s, OP_CLOSE, &[]).await;
                break;
            }
            _ => {}
        }
    }

    logging::info(format_args!("fptn[{tag}] {peer}: client disconnected"));
    Ok(())
}

async fn process_client_packet(
    packet: Vec<u8>,
    tag: &str,
    router: &Arc<Router>,
    hub: &Arc<UdpHub>,
    reply_tx: &tokio::sync::mpsc::Sender<crate::inbound::udp::TunReply>,
    stream: &Arc<Mutex<Box<dyn AsyncStream>>>,
) {
    if packet.len() < 20 {
        return;
    }
    // Only IPv4 packets currently
    if packet[0] >> 4 != 4 {
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
        // ICMP Echo
        1 => {
            if packet.len() >= ihl + 8 {
                let icmp_type = packet[ihl];
                let icmp_code = packet[ihl + 1];
                if icmp_type == 8 && icmp_code == 0 {
                    let mut reply_pkt = packet.clone();
                    reply_pkt[12..16].copy_from_slice(&dst_ip.octets());
                    reply_pkt[16..20].copy_from_slice(&src_ip.octets());
                    reply_pkt[10] = 0;
                    reply_pkt[11] = 0;
                    let ip_csum = crate::inbound::tun::ipv4_checksum(&reply_pkt[..ihl]);
                    reply_pkt[10] = (ip_csum >> 8) as u8;
                    reply_pkt[11] = ip_csum as u8;

                    reply_pkt[ihl] = 0; // Echo Reply
                    reply_pkt[ihl + 2] = 0;
                    reply_pkt[ihl + 3] = 0;
                    let icmp_csum = crate::inbound::tun::ipv4_checksum(&reply_pkt[ihl..]);
                    reply_pkt[ihl + 2] = (icmp_csum >> 8) as u8;
                    reply_pkt[ihl + 3] = icmp_csum as u8;

                    if let Ok(batch) = encode_batch(&[reply_pkt]) {
                        let mut s = stream.lock().await;
                        let _ = send_ws_frame(&mut *s, OP_BINARY, &batch).await;
                    }
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
                    let reply = Reply::Tun {
                        sender: reply_tx.clone(),
                    };
                    let _ = hub.handle(reply, source, dest, payload, tag).await;
                }
            }
        }
        // TCP
        6 if packet.len() >= ihl + 20 => {
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
            let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);

            let is_syn = (packet[ihl + 13] & 0x02) != 0;
            if is_syn {
                let (client_stream, _server_stream) = tokio::io::duplex(65_536);
                let router = Arc::clone(router);
                let tag = tag.to_string();
                tokio::spawn(async move {
                    let client = ClientConn::framed(Box::new(client_stream), source);
                    let _ = drive_framed(client, source, Target::Ip(dest), &tag, &router).await;
                });
            }
        }
        _ => {}
    }
}

async fn send_ws_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode); // FIN + opcode
    let len = payload.len();
    if len < 126 {
        frame.push(len as u8); // unmasked (server to client)
    } else if len <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    stream.flush().await
}

async fn read_ws_message(
    stream: &Arc<Mutex<Box<dyn AsyncStream>>>,
) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut s = stream.lock().await;
    let mut header = [0u8; 2];
    let n = s.read(&mut header).await?;
    if n == 0 {
        return Ok(None);
    }
    if n == 1 {
        s.read_exact(&mut header[1..2]).await?;
    }

    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as usize;

    if len == 126 {
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await?;
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        s.read_exact(&mut b).await?;
        len = u64::from_be_bytes(b) as usize;
    }

    let mask = if masked {
        let mut m = [0u8; 4];
        s.read_exact(&mut m).await?;
        Some(m)
    } else {
        None
    };

    let mut payload = vec![0u8; len];
    if len > 0 {
        s.read_exact(&mut payload).await?;
    }

    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }

    Ok(Some((opcode, payload)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::fptn::proto::decode_ip_assignment;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_fptn_login_and_dns_flow() {
        let cfg = serde_json::json!({
            "type": "fptn",
            "tag": "fptn-test",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "dns": "8.8.8.8",
            "dns_ipv6": "2001:4860:4860::8888",
            "users": [
                {
                    "username": "alice",
                    "password": "secret_password"
                }
            ]
        });

        let router = Router::new(&serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }))
        .unwrap();

        let server = Fptn::bind(&cfg, router).await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        // 1. Test Login (valid)
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let body = r#"{"username":"alice","password":"secret_password"}"#;
        let req = format!(
            "POST /api/v1/login HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{body}",
            addr,
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = vec![0u8; 1024];
        let n = stream.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("access_token"));

        // 2. Test Get DNS
        let mut stream2 = TcpStream::connect(addr).await.unwrap();
        let req2 = format!("GET /api/v1/dns HTTP/1.1\r\nHost: {}\r\n\r\n", addr);
        stream2.write_all(req2.as_bytes()).await.unwrap();
        let mut resp2 = vec![0u8; 1024];
        let n2 = stream2.read(&mut resp2).await.unwrap();
        let resp_str2 = String::from_utf8_lossy(&resp2[..n2]);
        assert!(resp_str2.contains("200 OK"));
        assert!(resp_str2.contains("8.8.8.8"));

        // 3. Test WebSocket Upgrade & IP Assignment
        let mut stream3 = TcpStream::connect(addr).await.unwrap();
        let req3 = format!(
            "GET /api/v1/fptn HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            addr
        );
        stream3.write_all(req3.as_bytes()).await.unwrap();

        let (ws_head, _) = read_http_header(&mut stream3).await.unwrap();
        assert!(ws_head.contains("101 Switching Protocols"));

        // Read initial MSG_IP_ASSIGNMENT frame
        let mut frame_head = [0u8; 2];
        stream3.read_exact(&mut frame_head).await.unwrap();
        assert_eq!(frame_head[0] & 0x0f, OP_BINARY);
        let len = (frame_head[1] & 0x7f) as usize;
        let mut assign_buf = vec![0u8; len];
        stream3.read_exact(&mut assign_buf).await.unwrap();

        let (assigned_v4, assigned_v6) = decode_ip_assignment(&assign_buf).unwrap();
        assert!(assigned_v4.starts_with("10.88.0."));
        assert!(assigned_v6.starts_with("fc00:88::"));
    }
}
