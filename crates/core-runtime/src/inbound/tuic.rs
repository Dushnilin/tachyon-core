//! TUIC v5 server inbound: accepts QUIC connections, verifies EKM auth on uni-stream,
//! dispatches TCP CONNECT bidirectional streams to router, and handles UDP datagrams
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
use crate::outbound::quic::{Defragger, QuicStream, read_sing_addr_port};
use crate::outbound::tuic::{
    CMD_AUTHENTICATE, CMD_CONNECT, CMD_DISSOCIATE, CMD_HEARTBEAT, CMD_PACKET, TUIC_VERSION,
    next_packet_id, pack_tuic, parse_tuic_packet_with_target,
};
use crate::route::Router;

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Tuic {
    tag: String,
    router: Arc<Router>,
    endpoint: quinn::Endpoint,
    users: Arc<HashMap<[u8; 16], (String, String)>>, // uuid -> (name, password)
    hub: Arc<UdpHub>,
    local_addr: SocketAddr,
}

impl Tuic {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let at = "inbounds[tuic]";
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

        let users_list = obj
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing users"))?;
        if users_list.is_empty() {
            anyhow::bail!("{at}: users must not be empty");
        }

        let mut users = HashMap::new();
        for (i, u) in users_list.iter().enumerate() {
            let uuid_str = u
                .get("uuid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{at}.users[{i}]: missing uuid"))?;
            let uuid = crate::outbound::vmess::kdf::parse_uuid(uuid_str)
                .map_err(|e| anyhow::anyhow!("{at}.users[{i}]: {e}"))?;
            let password = u
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let name = u
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(uuid_str)
                .to_string();
            users.insert(uuid, (name, password));
        }

        let tls_obj = obj
            .get("tls")
            .ok_or_else(|| anyhow::anyhow!("{at}: tls is required for tuic"))?;
        let server_config = ServerTls::build_quic_server_config(tls_obj, &[], at)?;

        let sock = std::net::UdpSocket::bind(addr)?;
        let runtime =
            quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("{at}: no quinn runtime"))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[9u8; 32]))),
            Some(server_config),
            sock,
            runtime,
        )?;
        let local_addr = endpoint.local_addr()?;

        let hub = UdpHub::new(Arc::clone(&router), DEFAULT_UDP_TIMEOUT, DatagramFrame::Raw);

        Ok(Self {
            tag,
            router,
            endpoint,
            users: Arc::new(users),
            hub,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub async fn serve(self) {
        let tag = self.tag.clone();
        logging::info(format_args!("tuic[{tag}] listening on {}", self.local_addr));

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
                        logging::debug(format_args!("tuic[{tag}] handshake failed: {e}"));
                        return;
                    }
                };
                handle_tuic_connection(conn, router, users, hub, tag, local_addr).await;
            });
        }
    }
}

async fn handle_tuic_connection(
    conn: quinn::Connection,
    router: Arc<Router>,
    users: Arc<HashMap<[u8; 16], (String, String)>>,
    hub: Arc<UdpHub>,
    tag: String,
    local_addr: SocketAddr,
) {
    let peer = conn.remote_address();

    // Authenticate via client uni stream
    let (user_name, conn) =
        match tokio::time::timeout(DEFAULT_AUTH_TIMEOUT, authenticate_tuic(&conn, &users)).await {
            Ok(Ok(user_name)) => (user_name, conn),
            Ok(Err(e)) => {
                logging::debug(format_args!("tuic[{tag}] {peer} auth failed: {e}"));
                conn.close(quinn::VarInt::from_u32(0), b"auth failed");
                return;
            }
            Err(_) => {
                logging::debug(format_args!("tuic[{tag}] {peer} auth timed out"));
                conn.close(quinn::VarInt::from_u32(0), b"auth timeout");
                return;
            }
        };

    logging::info(format_args!(
        "tuic[{tag}] {peer} authenticated as {user_name}"
    ));

    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<TunReply>(128);

    // UDP reply sender back to QUIC datagrams
    let conn_udp_send = conn.clone();
    let packet_counter = Arc::new(AtomicU32::new(0));
    let packet_counter_clone = Arc::clone(&packet_counter);
    let reply_handle = tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            let pid = next_packet_id(&packet_counter_clone);
            let pkt = pack_tuic(0, pid, 1, 0, &Target::Ip(reply.src), &reply.payload);
            let _ = conn_udp_send.send_datagram(pkt.into());
        }
    });

    // Accept bidirectional streams (TCP CONNECT)
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
                let mut cmd_buf = [0u8; 2];
                if recv.read_exact(&mut cmd_buf).await.is_err() {
                    return;
                }
                if cmd_buf[0] != TUIC_VERSION || cmd_buf[1] != CMD_CONNECT {
                    return;
                }
                let target = match read_sing_addr_port(&mut recv).await {
                    Ok(t) => t,
                    Err(e) => {
                        logging::debug(format_args!("tuic[{tag}] read target failed: {e}"));
                        return;
                    }
                };

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
            if data.len() < 2 {
                continue;
            }
            if data[0] != TUIC_VERSION {
                continue;
            }
            match data[1] {
                CMD_HEARTBEAT => {
                    let _ = conn_dg.send_datagram(vec![TUIC_VERSION, CMD_HEARTBEAT].into());
                }
                CMD_PACKET => {
                    let body = &data[2..];
                    let Some((_sid, pid, frag_id, frag_total, target_opt, payload)) =
                        parse_tuic_packet_with_target(body)
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
                    if let (Some(pkt), Some(target)) = (complete, target_opt) {
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
                CMD_DISSOCIATE => {}
                _ => {}
            }
        }
    });

    // Wait until connection closes
    let _ = conn.closed().await;
    bi_handle.abort();
    dg_handle.abort();
    reply_handle.abort();
    logging::info(format_args!("tuic[{tag}] {peer} disconnected"));
}

async fn authenticate_tuic(
    conn: &quinn::Connection,
    users: &HashMap<[u8; 16], (String, String)>,
) -> io::Result<String> {
    let mut uni = conn.accept_uni().await.map_err(io::Error::other)?;
    let mut buf = [0u8; 50];
    uni.read_exact(&mut buf)
        .await
        .map_err(|e| io::Error::other(format!("auth read failed: {e}")))?;

    if buf[0] != TUIC_VERSION || buf[1] != CMD_AUTHENTICATE {
        return Err(io::Error::other("invalid tuic auth command"));
    }

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[2..18]);
    let ekm = &buf[18..50];

    let (name, password) = users
        .get(&uuid)
        .ok_or_else(|| io::Error::other("unknown tuic user"))?;

    let mut expected_ekm = [0u8; 32];
    conn.export_keying_material(&mut expected_ekm, &uuid, password.as_bytes())
        .map_err(|e| io::Error::other(format!("export ekm failed: {e:?}")))?;

    if ekm != expected_ekm {
        return Err(io::Error::other("tuic authentication failed: invalid ekm"));
    }

    Ok(name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

    const CERT_PEM: &str = include_str!("../../../../tests/golden/certs/localhost.crt");
    const KEY_PEM: &str = include_str!("../../../../tests/golden/certs/localhost.key");

    #[tokio::test]
    async fn test_tuic_server_inbound_flow() {
        let _guard = TEST_MUTEX.lock().await;

        let cfg = serde_json::json!({
            "type": "tuic",
            "tag": "tuic-test",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "users": [
                {
                    "name": "alice",
                    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
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

        let server = Tuic::bind(&cfg, router).await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        // Now connect using Tuic outbound client!
        let client_cfg = serde_json::json!({
            "type": "tuic",
            "tag": "tuic-out",
            "server": "127.0.0.1",
            "server_port": srv_addr.port(),
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "secret_password",
            "tls": {
                "enabled": true,
                "insecure": true,
                "server_name": "localhost"
            }
        });

        let map = client_cfg.as_object().unwrap();
        let client = crate::outbound::tuic::Tuic::build(map, "outbounds[0]").unwrap();

        let target = Target::Ip(target_addr);
        let mut stream = client.connect(&target).await.unwrap();

        stream.write_all(b"hello tuic").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello tuic");
    }
}
