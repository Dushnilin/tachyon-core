//! Hysteria2 server inbound: accepts QUIC connections with HTTP/3 auth (status 233),
//! forwards TCP streams (FRAME_TCP_REQUEST 0x401), and handles UDP datagrams
//! with reassembly and response routing.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use serde_json::Value;

use super::tls::ServerTls;
use super::udp::{DatagramFrame, Reply, TunReply, UdpHub};
use crate::inbound::{AnyStream, ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::outbound::hysteria2::{
    AUTH_STATUS_OK, FRAME_TCP_REQUEST, MAX_ADDRESS, next_packet_id, pack_hy2, parse_hy2_packet,
    read_exact_vec, read_varint_stream,
};
use crate::outbound::quic::{
    Defragger, QuicStream, SalamanderRelay, salamander_open, salamander_seal,
};
use crate::route::Router;

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Hysteria2 {
    tag: String,
    router: Arc<Router>,
    endpoint: quinn::Endpoint,
    users: Arc<HashMap<String, String>>, // password -> username
    hub: Arc<UdpHub>,
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

        let (endpoint, local_addr, relay) = if let Some(pw) = obfs_password {
            // Bind loopback socket for Quinn
            let ep_bind = if addr.is_ipv4() {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            };
            let ep_sock = std::net::UdpSocket::bind(ep_bind)?;
            let ep = quinn::Endpoint::new(
                quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(
                    &[9u8; 32],
                ))),
                Some(server_config),
                ep_sock,
                runtime,
            )?;
            let ep_local = ep.local_addr()?;

            // Public listening socket with salamander obfs
            let public_sock = Arc::new(tokio::net::UdpSocket::bind(addr).await?);
            let actual_local = public_sock.local_addr()?;
            let loop_sock = Arc::new(tokio::net::UdpSocket::bind(ep_bind).await?);
            loop_sock.connect(ep_local).await?;

            let pw_in = pw.clone();
            let pub_in = Arc::clone(&public_sock);
            let loop_in = Arc::clone(&loop_sock);
            let in_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    let (n, _peer) = match pub_in.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if let Some(plain) = salamander_open(&pw_in, &buf[..n]) {
                        let _ = loop_in.send(&plain).await;
                    }
                }
            });

            let pw_out = pw;
            let pub_out = Arc::clone(&public_sock);
            let loop_out = Arc::clone(&loop_sock);
            let out_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    let n = match loop_out.recv(&mut buf).await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let sealed = salamander_seal(&pw_out, &buf[..n]);
                    let _ = pub_out.send(&sealed).await;
                }
            });

            let relay = SalamanderRelay {
                local: actual_local,
                handles: vec![in_task, out_task],
            };
            (ep, actual_local, Some(relay))
        } else {
            let sock = std::net::UdpSocket::bind(addr)?;
            let ep = quinn::Endpoint::new(
                quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(
                    &[9u8; 32],
                ))),
                Some(server_config),
                sock,
                runtime,
            )?;
            let local = ep.local_addr()?;
            (ep, local, None)
        };

        let hub = UdpHub::new(Arc::clone(&router), DEFAULT_UDP_TIMEOUT, DatagramFrame::Raw);

        Ok(Self {
            tag,
            router,
            endpoint,
            users: Arc::new(users),
            hub,
            local_addr,
            _relay: relay,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub async fn serve(self) {
        let tag = self.tag.clone();
        logging::info(format_args!(
            "hysteria2[{tag}] listening on {}",
            self.local_addr
        ));

        while let Some(incoming) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);
            let users = Arc::clone(&self.users);
            let hub = Arc::clone(&self.hub);
            let tag = self.tag.clone();
            let local_addr = self.local_addr;

            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        logging::debug(format_args!("hysteria2[{tag}] handshake failed: {e}"));
                        return;
                    }
                };
                handle_hy2_connection(conn, router, users, hub, tag, local_addr).await;
            });
        }
    }
}

async fn handle_hy2_connection(
    conn: quinn::Connection,
    router: Arc<Router>,
    users: Arc<HashMap<String, String>>,
    hub: Arc<UdpHub>,
    tag: String,
    local_addr: SocketAddr,
) {
    let peer = conn.remote_address();

    // Authenticate via HTTP/3 session
    let user_name =
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

    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<TunReply>(128);

    // UDP reply sender back to QUIC datagrams
    let conn_udp_send = conn.clone();
    let packet_counter = Arc::new(AtomicU32::new(0));
    let packet_counter_clone = Arc::clone(&packet_counter);
    let reply_handle = tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            let pid = next_packet_id(&packet_counter_clone);
            let dest_str = reply.dest.to_string();
            let pkt = pack_hy2(0, pid, 0, 1, &dest_str, &reply.payload);
            let _ = conn_udp_send.send_datagram(pkt.into());
        }
    });

    // Accept bidirectional streams (TCP requests)
    let conn_bi = conn.clone();
    let router_bi = Arc::clone(&router);
    let tag_bi = tag.clone();
    let user_bi = user_name.clone();
    let bi_handle = tokio::spawn(async move {
        loop {
            let (send, mut recv) = match conn_bi.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let router = Arc::clone(&router_bi);
            let tag = tag_bi.clone();
            let _user = user_bi.clone();
            tokio::spawn(async move {
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
    });

    // Accept datagrams (UDP)
    let conn_dg = conn.clone();
    let defragger = Arc::new(std::sync::Mutex::new(Defragger::new()));
    let hub_dg = Arc::clone(&hub);
    let tag_dg = tag.clone();
    let dg_handle = tokio::spawn(async move {
        loop {
            let data = match conn_dg.read_datagram().await {
                Ok(d) => d,
                Err(_) => break,
            };
            let Some((_sid, pid, frag_id, frag_total, dest, payload)) = parse_hy2_packet(&data)
            else {
                continue;
            };
            let complete = {
                let mut defrag = defragger.lock().expect("defragger");
                defrag.feed(
                    pid,
                    frag_id,
                    frag_total,
                    bytes::Bytes::copy_from_slice(payload),
                )
            };
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
                let _ = hub_dg
                    .handle(
                        Reply::Tun {
                            sender: reply_tx.clone(),
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
    bi_handle.abort();
    dg_handle.abort();
    reply_handle.abort();
    logging::info(format_args!("hysteria2[{tag}] {peer} disconnected"));
}

async fn authenticate_hy2(
    conn: &quinn::Connection,
    users: &HashMap<String, String>,
) -> io::Result<String> {
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

    // In Hysteria 2, HTTP/3 is only used for the initial handshake; proxy data is sent
    // over raw QUIC bi-streams and datagrams. If `h3_conn` is dropped, its Drop impl sends
    // an ApplicationClose (H3_NO_ERROR) frame over the entire QUIC connection.
    // Forgetting the HTTP/3 connection driver keeps the underlying QUIC transport alive.
    std::mem::forget(h3_conn);

    Ok(user_name)
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
    }
}
