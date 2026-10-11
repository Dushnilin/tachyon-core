//! Hysteria2 server inbound: accepts QUIC connections with HTTP/3 auth (status 233),
//! forwards TCP streams (FRAME_TCP_REQUEST 0x401), and handles UDP datagrams
//! with reassembly and response routing.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::tls::ServerTls;
use super::udp::{DatagramFrame, Reply, TunReply, UdpHub};
use crate::inbound::{AnyStream, ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::outbound::hysteria2::{
    AUTH_STATUS_OK, FRAME_TCP_REQUEST, MAX_ADDRESS, parse_hy2_packet, read_exact_vec,
    read_varint_stream, send_hy2_packet,
};
use crate::outbound::quic::{
    Defragger, QuicStream, SalamanderRelay, salamander_open, salamander_seal,
};
use crate::route::Router;

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);
type H3ServerConnection = h3::server::Connection<h3_quinn::Connection, bytes::Bytes>;
const MAX_UDP_SESSIONS: usize = 1024;

struct Hy2UdpSession {
    hub: Arc<UdpHub>,
    reply: tokio::sync::mpsc::Sender<TunReply>,
    defragger: Defragger,
    last_activity: Instant,
    pump: tokio::task::JoinHandle<()>,
}

impl Hy2UdpSession {
    fn new(
        router: Arc<Router>,
        sid: u32,
        output: tokio::sync::mpsc::Sender<(u32, TunReply)>,
    ) -> Self {
        let (reply, mut replies) = tokio::sync::mpsc::channel(128);
        let pump = tokio::spawn(async move {
            while let Some(packet) = replies.recv().await {
                if output.send((sid, packet)).await.is_err() {
                    break;
                }
            }
        });
        Self {
            hub: UdpHub::new(router, DEFAULT_UDP_TIMEOUT, DatagramFrame::Raw),
            reply,
            defragger: Defragger::new(),
            last_activity: Instant::now(),
            pump,
        }
    }
}

impl Drop for Hy2UdpSession {
    fn drop(&mut self) {
        self.pump.abort();
        self.hub.stop();
    }
}

pub struct Hysteria2 {
    tag: String,
    router: Arc<Router>,
    endpoint: quinn::Endpoint,
    socket: Weak<dyn quinn::AsyncUdpSocket>,
    users: Arc<HashMap<String, String>>, // password -> username
    local_addr: SocketAddr,
    _relay: Option<SalamanderRelay>,
}

impl Hysteria2 {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let at = "inbounds[hysteria2]";
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let (ip, port) = parse_listen(map, at)?;
        let addr = SocketAddr::new(ip, port);

        let mut users = HashMap::new();
        if let Some(list) = obj.get("users").and_then(Value::as_array) {
            for (i, u) in list.iter().enumerate() {
                let password = u
                    .get("password")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("{at}.users[{i}]: missing password"))?
                    .to_string();
                let name = u
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                users.insert(password, if name.is_empty() { i.to_string() } else { name });
            }
        } else if let Some(pw) = obj.get("password").and_then(Value::as_str) {
            users.insert(pw.to_string(), "default".to_string());
        } else {
            anyhow::bail!("{at}: missing users or password");
        }

        let obfs_password = match obj.get("obfs") {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => {
                let ty = m.get("type").and_then(Value::as_str).unwrap_or("");
                match ty {
                    "salamander" => {
                        let pw = m.get("password").and_then(Value::as_str).unwrap_or("");
                        if pw.is_empty() {
                            anyhow::bail!("{at}: missing obfs password");
                        }
                        Some(pw.as_bytes().to_vec())
                    }
                    other => anyhow::bail!("{at}: unsupported obfs type: {other}"),
                }
            }
            Some(_) => anyhow::bail!("{at}: obfs must be an object"),
        };

        let tls_obj = obj
            .get("tls")
            .ok_or_else(|| anyhow::anyhow!("{at}: tls is required for hysteria2"))?;
        let server_config = ServerTls::build_quic_server_config(tls_obj, &[b"h3"], at)?;

        let runtime =
            quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("{at}: no quinn runtime"))?;

        let sock = std::net::UdpSocket::bind(addr)?;
        let sock = runtime.wrap_udp_socket(sock)?;
        let (sock, relay): (Arc<dyn quinn::AsyncUdpSocket>, Option<SalamanderRelay>) =
            if let Some(pw) = obfs_password {
                (
                    Arc::new(SalamanderUdpSocket {
                        inner: sock,
                        password: pw,
                    }),
                    None,
                )
            } else {
                (sock, None)
            };
        let socket = Arc::downgrade(&sock);
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[9u8; 32]))),
            Some(server_config),
            sock,
            runtime,
        )?;
        let local_addr = endpoint.local_addr()?;

        Ok(Self {
            tag,
            router,
            endpoint,
            socket,
            users: Arc::new(users),
            local_addr,
            _relay: relay,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub(crate) fn shutdown_endpoint(&self) -> (quinn::Endpoint, Weak<dyn quinn::AsyncUdpSocket>) {
        (self.endpoint.clone(), self.socket.clone())
    }

    pub async fn serve(self) {
        let tag = self.tag.clone();
        logging::info(format_args!(
            "hysteria2[{tag}] listening on {}",
            self.local_addr
        ));

        let mut connections = tokio::task::JoinSet::new();
        while let Some(incoming) = self.endpoint.accept().await {
            while connections.try_join_next().is_some() {}
            let router = Arc::clone(&self.router);
            let users = Arc::clone(&self.users);
            let tag = self.tag.clone();
            let local_addr = self.local_addr;

            connections.spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        logging::debug(format_args!("hysteria2[{tag}] handshake failed: {e}"));
                        return;
                    }
                };
                handle_hy2_connection(conn, router, users, tag, local_addr).await;
            });
        }
        connections.shutdown().await;
    }
}

async fn handle_hy2_connection(
    conn: quinn::Connection,
    router: Arc<Router>,
    users: Arc<HashMap<String, String>>,
    tag: String,
    local_addr: SocketAddr,
) {
    let peer = conn.remote_address();

    // Authenticate via HTTP/3 session
    let (user_name, _h3_connection) =
        match tokio::time::timeout(DEFAULT_AUTH_TIMEOUT, authenticate_hy2(&conn, &users)).await {
            Ok(Ok(name)) => name,
            Ok(Err(e)) => {
                logging::debug(format_args!("hysteria2[{tag}] {peer} auth failed: {e}"));
                conn.close(quinn::VarInt::from_u32(0), b"auth failed");
                return;
            }
            Err(_) => {
                logging::debug(format_args!("hysteria2[{tag}] {peer} auth timed out"));
                conn.close(quinn::VarInt::from_u32(0), b"auth timeout");
                return;
            }
        };

    logging::info(format_args!(
        "hysteria2[{tag}] {peer} authenticated as {user_name}"
    ));

    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<(u32, TunReply)>(128);

    // UDP reply sender back to QUIC datagrams
    let conn_udp_send = conn.clone();
    let packet_counter = Arc::new(AtomicU32::new(0));
    let packet_counter_clone = Arc::clone(&packet_counter);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        while let Some((sid, reply)) = reply_rx.recv().await {
            let src_str = reply.src.to_string();
            if let Err(err) = send_hy2_packet(
                &conn_udp_send,
                sid,
                &src_str,
                &reply.payload,
                &packet_counter_clone,
            ) {
                logging::debug(format_args!("hysteria2 UDP reply {sid}: {err}"));
            }
        }
    });

    // Accept bidirectional streams (TCP requests)
    let conn_bi = conn.clone();
    let router_bi = Arc::clone(&router);
    let tag_bi = tag.clone();
    let user_bi = user_name.clone();
    tasks.spawn(async move {
        let mut streams = tokio::task::JoinSet::new();
        loop {
            let (send, mut recv) = match conn_bi.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let router = Arc::clone(&router_bi);
            let tag = tag_bi.clone();
            let _user = user_bi.clone();
            while streams.try_join_next().is_some() {}
            streams.spawn(async move {
                let frame_type = match read_varint_stream(&mut recv).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if frame_type != FRAME_TCP_REQUEST {
                    return;
                }
                let dest_len = match read_varint_stream(&mut recv).await {
                    Ok(v) => v as usize,
                    Err(_) => return,
                };
                if dest_len > MAX_ADDRESS {
                    return;
                }
                let dest_bytes = match read_exact_vec(&mut recv, dest_len).await {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let dest_str = match std::str::from_utf8(&dest_bytes) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let pad_len = match read_varint_stream(&mut recv).await {
                    Ok(v) => v as usize,
                    Err(_) => return,
                };
                let _pad = match read_exact_vec(&mut recv, pad_len).await {
                    Ok(p) => p,
                    Err(_) => return,
                };

                let target = match parse_target_str(dest_str) {
                    Some(t) => t,
                    None => return,
                };

                // Send TCP response: status 0, msg_len 0, pad_len 0
                let mut send = send;
                let resp = [0u8, 0, 0];
                if send.write_all(&resp).await.is_err() {
                    return;
                }

                let stream: AnyStream = Box::new(QuicStream::new(send, recv));
                let client = ClientConn::framed(stream, local_addr);
                let _ = drive_framed(client, peer, target, &tag, &router).await;
            });
        }
        streams.shutdown().await;
    });

    // Accept datagrams (UDP)
    let conn_dg = conn.clone();
    let router_dg = Arc::clone(&router);
    let tag_dg = tag.clone();
    tasks.spawn(async move {
        // Session ID scopes both reassembly and the outbound UDP socket. Two
        // client sessions to the same destination must not share a reply channel.
        let mut sessions = HashMap::<u32, Hy2UdpSession>::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(30));
        loop {
            let data = tokio::select! {
                result = conn_dg.read_datagram() => match result { Ok(d) => d, Err(_) => break },
                _ = cleanup.tick() => {
                    sessions.retain(|_, session| session.last_activity.elapsed() < DEFAULT_UDP_TIMEOUT);
                    continue;
                }
            };
            let Some((sid, pid, frag_id, frag_total, dest, payload)) = parse_hy2_packet(&data)
            else {
                continue;
            };
            if !sessions.contains_key(&sid) && sessions.len() >= MAX_UDP_SESSIONS {
                continue;
            }
            let session = sessions.entry(sid).or_insert_with(|| {
                Hy2UdpSession::new(Arc::clone(&router_dg), sid, reply_tx.clone())
            });
            session.last_activity = Instant::now();
            let complete = session.defragger.feed(
                pid,
                frag_id,
                frag_total,
                bytes::Bytes::copy_from_slice(payload),
            );
            if let Some(pkt) = complete {
                let target = match parse_target_str(dest) {
                    Some(t) => t,
                    None => continue,
                };
                let dest_addr = match target {
                    Target::Ip(a) => a,
                    Target::Domain(h, p) => {
                        match crate::outbound::quic::resolve_host(&h, p).await {
                            Ok(a) => a,
                            Err(_) => continue,
                        }
                    }
                };
                let _ = session
                    .hub
                    .handle(
                        Reply::Tun {
                            sender: session.reply.clone(),
                        },
                        peer,
                        dest_addr,
                        &pkt,
                        &tag_dg,
                    )
                    .await;
            }
        }
    });

    // Wait until connection closes
    let _ = conn.closed().await;
    tasks.shutdown().await;
    logging::info(format_args!("hysteria2[{tag}] {peer} disconnected"));
}

async fn authenticate_hy2(
    conn: &quinn::Connection,
    users: &HashMap<String, String>,
) -> io::Result<(String, H3ServerConnection)> {
    let h3 = h3_quinn::Connection::new(conn.clone());
    let mut h3_conn: h3::server::Connection<_, bytes::Bytes> = h3::server::builder()
        .build(h3)
        .await
        .map_err(|e| io::Error::other(format!("h3 handshake failed: {e}")))?;

    let resolver = h3_conn
        .accept()
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("no request on h3"))?;

    let (request, mut stream) = resolver.resolve_request().await.map_err(io::Error::other)?;
    let auth_header = request
        .headers()
        .get("Hysteria-Auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    while let Some(_chunk) = stream.recv_data().await.map_err(io::Error::other)? {}

    let user_name = if let Some(name) = users.get(auth_header) {
        name.clone()
    } else {
        let resp = http::Response::builder()
            .status(401)
            .body(())
            .map_err(io::Error::other)?;
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return Err(io::Error::other("invalid hysteria2 auth"));
    };

    let response = http::Response::builder()
        .status(AUTH_STATUS_OK)
        .header("Hysteria-UDP", "true")
        .body(())
        .map_err(io::Error::other)?;

    stream
        .send_response(response)
        .await
        .map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)?;

    // Keep HTTP/3 alive until the QUIC connection closes: dropping it immediately
    // sends H3_NO_ERROR over the proxy transport. Leaking it with mem::forget
    // instead retains the UDP socket forever and prevents configuration reload.
    Ok((user_name, h3_conn))
}

fn parse_target_str(s: &str) -> Option<Target> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(Target::Ip(addr));
    }
    let (host, port_str) = s.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Some(Target::Ip(SocketAddr::new(ip, port)))
    } else {
        Some(Target::Domain(host.to_string(), port))
    }
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    password: Vec<u8>,
}

impl quinn::AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let sealed = salamander_seal(&self.password, transmit.contents);
        let sealed_transmit = quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &sealed,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&sealed_transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let res = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
            if res == 0 {
                return Poll::Ready(Ok(0));
            }
            let mut out_count = 0;
            for i in 0..res {
                let len = meta[i].len;
                if let Some(plain) = salamander_open(&self.password, &bufs[i][..len]) {
                    bufs[out_count][..plain.len()].copy_from_slice(&plain);
                    meta[out_count].addr = meta[i].addr;
                    meta[out_count].len = plain.len();
                    meta[out_count].stride = plain.len();
                    meta[out_count].ecn = meta[i].ecn;
                    meta[out_count].dst_ip = meta[i].dst_ip;
                    out_count += 1;
                }
            }
            if out_count > 0 {
                return Poll::Ready(Ok(out_count));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

    const CERT_PEM: &str = include_str!("../../../../tests/golden/certs/localhost.crt");
    const KEY_PEM: &str = include_str!("../../../../tests/golden/certs/localhost.key");

    #[tokio::test]
    async fn test_hysteria2_server_inbound_flow() {
        let _guard = TEST_MUTEX.lock().await;

        let cfg = serde_json::json!({
            "type": "hysteria2",
            "tag": "hy2-test",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "users": [
                {
                    "name": "alice",
                    "password": "secret_password"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate": CERT_PEM,
                "key": KEY_PEM
            }
        });

        // Target TCP echo server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let router = Router::new(&serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }))
        .unwrap();

        let server = Hysteria2::bind(&cfg, router).await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        // Now connect using Hysteria2 outbound client!
        let client_cfg = serde_json::json!({
            "type": "hysteria2",
            "tag": "hy2-out",
            "server": "127.0.0.1",
            "server_port": srv_addr.port(),
            "password": "secret_password",
            "tls": {
                "enabled": true,
                "insecure": true,
                "server_name": "localhost"
            }
        });

        let map = client_cfg.as_object().unwrap();
        let client = crate::outbound::hysteria2::Hysteria2::build(map, "outbounds[0]").unwrap();

        let target = Target::Ip(target_addr);
        let mut stream = client.connect(&target).await.unwrap();

        stream.write_all(b"hello hy2").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello hy2");

        // A reply with SID=0 used to hide the bug for the first Rust-client
        // session, but broke official clients and all later UDP sessions.
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = Target::Ip(echo.local_addr().unwrap());
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            for _ in 0..3 {
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..n], peer).await.unwrap();
            }
        });
        let first = client.connect_udp(&udp_target).await.unwrap();
        let second = client.connect_udp(&udp_target).await.unwrap();
        first.send(b"session-zero").await.unwrap();
        second.send(b"session-one").await.unwrap();
        let mut first_buf = [0u8; 64];
        let mut second_buf = [0u8; 64];
        let a = tokio::time::timeout(Duration::from_secs(3), first.recv(&mut first_buf))
            .await
            .unwrap()
            .unwrap();
        let b = tokio::time::timeout(Duration::from_secs(3), second.recv(&mut second_buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&first_buf[..a], b"session-zero");
        assert_eq!(&second_buf[..b], b"session-one");
        // Real media exceeds the QUIC datagram budget and requires response
        // fragmentation, not silent TooLarge drops in the server sender.
        let media = vec![0x5a; 1400];
        first.send(&media).await.unwrap();
        let mut media_buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), first.recv(&mut media_buf))
            .await
            .expect("large incoming media reply")
            .unwrap();
        assert_eq!(&media_buf[..n], media);
        echo_task.await.unwrap();
    }
}
