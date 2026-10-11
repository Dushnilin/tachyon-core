//! Tailscale endpoint outbound implementation.
//!
//! Provides coordination over HTTPS 443 (SPEC 111) with controlplane.tailscale.com,
//! Noise_IK handshake, WireGuard peer mesh, and DERP relay routing.

pub mod config;
pub mod control;
pub mod control_wire;
pub mod coordinator;
pub mod derp;
pub mod disco;
pub mod engine;
pub mod mesh;
pub mod netmap;
pub mod noise;
pub mod relay;
pub mod state;

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::inbound::{AnyStream, Target};
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::tailscale::config::TailscaleConfig;
use crate::outbound::tailscale::engine::{
    Cmd, TailscaleShared, resolve_target, spawn_tailscale_engine,
};

const CALLER_BUF: usize = 65_536;
const REPLY_QUEUE: usize = 32;
const SCRATCH_BUF: usize = 16_384;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Tailscale endpoint outbound.
#[derive(Clone)]
pub struct Tailscale {
    cfg: TailscaleConfig,
    shared: Arc<AsyncMutex<Option<Arc<TailscaleShared>>>>,
}

impl std::fmt::Debug for Tailscale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale")
            .field("tag", &self.cfg.tag)
            .field("control_url", &self.cfg.control_url)
            .finish()
    }
}

impl Tailscale {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let cfg = TailscaleConfig::parse(obj, at)?;
        if cfg.system_interface
            || cfg.exit_node.is_some()
            || cfg.advertise_exit_node
            || cfg
                .advertise_routes
                .iter()
                .any(|route| route.prefix_len() == 0)
            || cfg.taildrop_directory.is_some()
            || cfg.relay_server_port.is_some()
            || !cfg.relay_server_static_endpoints.is_empty()
        {
            anyhow::bail!(
                "{at}: native tailscale currently supports userspace endpoints and subnet routes; system interfaces, exit nodes, Taildrop and hosting a relay are not supported"
            );
        }
        Ok(Self {
            cfg,
            shared: Arc::new(AsyncMutex::new(None)),
        })
    }

    pub async fn shared(&self) -> io::Result<Arc<TailscaleShared>> {
        let mut guard = self.shared.lock().await;
        if let Some(shared) = &*guard {
            return Ok(Arc::clone(shared));
        }

        let keys = state::load(self.cfg.state_directory.as_deref(), self.cfg.ephemeral)?;
        let map = Arc::new(std::sync::RwLock::new(netmap::Netmap::default()));
        let (updates, receive) = tokio::sync::watch::channel(0);
        let mesh = mesh::start(
            self.cfg.clone(),
            keys.node.clone(),
            Arc::clone(&map),
            receive,
        )
        .await?;
        let control = coordinator::spawn(
            self.cfg.clone(),
            keys.machine,
            keys.node,
            mesh.disco_public,
            Arc::clone(&map),
            updates,
        );
        let shared = spawn_tailscale_engine(self.cfg.clone(), map, mesh, control);

        *guard = Some(Arc::clone(&shared));
        Ok(shared)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let shared = self.shared().await?;
        let dst = self.resolve(target, &shared).await?;
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (local, remote) = tokio::io::duplex(CALLER_BUF);
        let (caller_read, caller_write) = tokio::io::split(local);
        let (to_caller_tx, mut to_caller_rx) = mpsc::channel(REPLY_QUEUE);
        let (resp_tx, resp_rx) = oneshot::channel();

        shared
            .cmd_tx
            .send(Cmd::TcpConnect {
                id,
                dst,
                to_caller: to_caller_tx,
                resp: resp_tx,
            })
            .await
            .map_err(|_| io::Error::other("tailscale: engine task stopped"))?;

        // caller → stack
        let cmd_tx = shared.cmd_tx.clone();
        tokio::spawn(async move {
            let mut read = caller_read;
            let mut buf = vec![0u8; SCRATCH_BUF];
            loop {
                match read.read(&mut buf).await {
                    Ok(0) => {
                        let _ = cmd_tx.send(Cmd::TcpEof { id }).await;
                        break;
                    }
                    Ok(n) => {
                        if cmd_tx
                            .send(Cmd::TcpData {
                                id,
                                bytes: buf[..n].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = cmd_tx.send(Cmd::TcpClose { id }).await;
                        break;
                    }
                }
            }
        });

        // stack → caller
        tokio::spawn(async move {
            let mut write = caller_write;
            while let Some(bytes) = to_caller_rx.recv().await {
                if write.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = write.flush().await;
            }
        });

        match tokio::time::timeout(CONNECT_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(remote)),
            Ok(Ok(Err(e))) => Err(io::Error::other(format!("tailscale: {e}"))),
            Ok(Err(_)) => Err(io::Error::other("tailscale: engine task stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tailscale: connect timeout",
            )),
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        let shared = self.shared().await?;
        let dst = self.resolve(target, &shared).await?;
        let (local, peer) = udp_loopback_pair().await?;
        let (resp_tx, resp_rx) = oneshot::channel();

        shared
            .cmd_tx
            .send(Cmd::UdpOpen {
                target: dst,
                resp: resp_tx,
            })
            .await
            .map_err(|_| io::Error::other("tailscale: engine task stopped"))?;

        let (port, mut replies) = match tokio::time::timeout(Duration::from_secs(10), resp_rx).await
        {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => return Err(io::Error::other(format!("tailscale: {e}"))),
            Ok(Err(_)) => return Err(io::Error::other("tailscale: engine task stopped")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tailscale: udp session timeout",
                ));
            }
        };

        let peer = Arc::new(peer);
        let cmd_tx = shared.cmd_tx.clone();
        let udp_timeout = self.cfg.udp_timeout;

        // replies: engine → loopback peer socket
        {
            let peer = Arc::clone(&peer);
            tokio::spawn(async move {
                while let Some(bytes) = replies.recv().await {
                    if peer.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
        }

        // sends: loopback peer socket → engine
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok(Ok(n)) = tokio::time::timeout(udp_timeout, peer.recv(&mut buf)).await {
                if cmd_tx
                    .send(Cmd::UdpSend {
                        port,
                        bytes: buf[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = cmd_tx.send(Cmd::UdpClose { port }).await;
        });

        Ok(local)
    }

    async fn resolve(
        &self,
        target: &Target,
        shared: &TailscaleShared,
    ) -> io::Result<std::net::SocketAddr> {
        if let Target::Domain(host, port) = target {
            let addresses = shared
                .map
                .read()
                .map_err(|_| io::Error::other("tailscale: map lock poisoned"))?
                .lookup(host);
            if let Some(addresses) = addresses {
                return addresses
                    .first()
                    .copied()
                    .map(|ip| std::net::SocketAddr::new(ip, *port))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "tailscale: MagicDNS name not found",
                        )
                    });
            }
        }
        resolve_target(target).await
    }

    pub async fn dns_exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let (message, info) = crate::dns::codec::parse_query(query)?;
        let shared = self.shared().await?;
        let (addresses, resolver) = {
            let map = shared
                .map
                .read()
                .map_err(|_| io::Error::other("tailscale: map lock poisoned"))?;
            (map.lookup(&info.name), map.resolver(&info.name))
        };
        if let Some(addresses) = addresses {
            if addresses.is_empty() {
                return crate::dns::codec::name_error(&message).map_err(io::Error::other);
            }
            return crate::dns::codec::synth_addresses(&message, &addresses, 60)
                .map_err(io::Error::other);
        }
        let resolver = resolver.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "tailscale: no resolver in the current netmap",
            )
        })?;
        let tailnet = shared
            .map
            .read()
            .map_err(|_| io::Error::other("tailscale: map lock poisoned"))?
            .peers
            .values()
            .any(|peer| peer.owns_source(resolver.ip()));
        let socket = if tailnet {
            self.connect_udp(&Target::Ip(resolver)).await?
        } else {
            let socket = UdpSocket::bind(if resolver.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            socket.connect(resolver).await?;
            socket
        };
        socket.send(query).await?;
        let mut bytes = vec![0; 65535];
        let size = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut bytes))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tailscale: DNS timeout"))??;
        bytes.truncate(size);
        let response = hickory_proto::op::Message::from_vec(&bytes).map_err(io::Error::other)?;
        if response.metadata.id != info.id || response.queries != message.queries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tailscale: DNS response identity mismatch",
            ));
        }
        Ok(bytes)
    }

    pub async fn shutdown(&self) {
        let shared = self.shared.lock().await.take();
        if let Some(shared) = shared {
            shared.shutdown().await;
        }
    }

    pub fn abort(&self) {
        if let Ok(shared) = self.shared.try_lock()
            && let Some(shared) = &*shared
        {
            shared.abort();
        }
    }

    pub fn inherit(&mut self, old: &Self) -> bool {
        if self.cfg != old.cfg {
            return false;
        }
        self.shared = Arc::clone(&old.shared);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::IpAddr;

    async fn pair() -> (Tailscale, Tailscale) {
        pair_for("127.0.0.1/32").await
    }

    async fn pair_for(route: &str) -> (Tailscale, Tailscale) {
        use std::sync::RwLock;
        use x25519_dalek::{PublicKey, StaticSecret};
        let a = Tailscale::build(
            json!({"tag":"a","ephemeral":true,"listen_port":0,"accept_routes":true})
                .as_object()
                .unwrap(),
            "a",
        )
        .unwrap();
        let b = Tailscale::build(
            json!({"tag":"b","ephemeral":true,"listen_port":0,"advertise_routes":[route]})
                .as_object()
                .unwrap(),
            "b",
        )
        .unwrap();
        let key_a = StaticSecret::from([10; 32]);
        let key_b = StaticSecret::from([11; 32]);
        let map_a = Arc::new(RwLock::new(netmap::Netmap::default()));
        let map_b = Arc::new(RwLock::new(netmap::Netmap::default()));
        let (_update_a, receive_a) = tokio::sync::watch::channel(0);
        let (_update_b, receive_b) = tokio::sync::watch::channel(0);
        let mesh_a = mesh::start(a.cfg.clone(), key_a.clone(), Arc::clone(&map_a), receive_a)
            .await
            .unwrap();
        let mesh_b = mesh::start(b.cfg.clone(), key_b.clone(), Arc::clone(&map_b), receive_b)
            .await
            .unwrap();
        let pub_a = control::node_key_str(&PublicKey::from(&key_a));
        let pub_b = control::node_key_str(&PublicKey::from(&key_b));
        let node_a = json!({"ID":1,"Key":pub_a,"DiscoKey":format!("discokey:{}",control::to_hex(&mesh_a.disco_public)),"Name":"a.example.ts.net.","Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"AllowedIPs":["100.64.0.1/32"],"Endpoints":[format!("127.0.0.1:{}",mesh_a.local_addr.port())]});
        let node_b = json!({"ID":2,"Key":pub_b,"DiscoKey":format!("discokey:{}",control::to_hex(&mesh_b.disco_public)),"Name":"b.example.ts.net.","Addresses":["100.64.0.2/32","fd7a:115c:a1e0::2/128"],"AllowedIPs":["100.64.0.2/32",route],"Endpoints":[format!("127.0.0.1:{}",mesh_b.local_addr.port())]});
        let dns = json!({"Proxied":true,"Domains":["example.ts.net"]});
        let filter = json!([{"SrcIPs":["100.64.0.1/32"],"DstPorts":[{"IP":route,"Ports":{"First":0,"Last":65535}}]}]);
        map_a
            .write()
            .unwrap()
            .update(&json!({"Node":node_a,"Peers":[node_b],"DNSConfig":dns}))
            .unwrap();
        map_b
            .write()
            .unwrap()
            .update(&json!({"Node":node_b,"Peers":[node_a],"DNSConfig":dns,"PacketFilter":filter}))
            .unwrap();
        let dummy_a = tokio::spawn(async move {
            let _sender = _update_a;
            std::future::pending::<()>().await
        });
        let dummy_b = tokio::spawn(async move {
            let _sender = _update_b;
            std::future::pending::<()>().await
        });
        let shared_a = spawn_tailscale_engine(a.cfg.clone(), map_a, mesh_a, dummy_a);
        let shared_b = spawn_tailscale_engine(b.cfg.clone(), map_b, mesh_b, dummy_b);
        *a.shared.lock().await = Some(shared_a);
        *b.shared.lock().await = Some(shared_b);
        tokio::time::sleep(Duration::from_millis(20)).await;
        (a, b)
    }

    #[tokio::test]
    async fn advertised_non_loopback_subnet_carries_tcp_and_first_udp_packet() {
        let ip = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .find_map(|interface| match interface.ip() {
                IpAddr::V4(ip)
                    if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() =>
                {
                    Some(ip)
                }
                _ => None,
            })
            .expect("test host must have an assigned non-loopback IPv4 address");
        let tcp = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind((ip, 0)).await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut bytes = [0; 6];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let udp_echo = tokio::spawn(async move {
            let mut bytes = [0; 128];
            let (size, source) = udp.recv_from(&mut bytes).await.unwrap();
            udp.send_to(&bytes[..size], source).await.unwrap();
        });
        let (a, b) = pair_for(&format!("{ip}/32")).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = a.connect(&Target::Ip(tcp_address)).await.unwrap();
            stream.write_all(b"subnet").await.unwrap();
            let mut bytes = [0; 6];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"subnet");
            let socket = a.connect_udp(&Target::Ip(udp_address)).await.unwrap();
            socket.send(b"first LAN datagram").await.unwrap();
            let mut bytes = [0; 128];
            let size = socket.recv(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..size], b"first LAN datagram");
            tcp_echo.await.unwrap();
            udp_echo.await.unwrap();
        })
        .await
        .unwrap();
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn native_udp_delivers_the_first_datagram_and_repeated_replies() {
        let (a, b) = pair().await;
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = echo.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 1500];
            for _ in 0..5 {
                let (size, source) = echo.recv_from(&mut bytes).await.unwrap();
                echo.send_to(&bytes[..size], source).await.unwrap();
            }
        });
        let socket = a.connect_udp(&Target::Ip(address)).await.unwrap();
        for sequence in 0..5u8 {
            let bytes = vec![sequence; 1172];
            socket.send(&bytes).await.unwrap();
            let mut reply = [0; 1500];
            let size = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply[..size], bytes);
        }
        task.await.unwrap();
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn native_tcp_reaches_lan_through_the_peer_mesh() {
        let (a, b) = pair().await;
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = echo.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut bytes = [0; 13];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"native tcp ok");
            stream.write_all(&bytes).await.unwrap();
        });
        let mut stream =
            tokio::time::timeout(Duration::from_secs(3), a.connect(&Target::Ip(address)))
                .await
                .unwrap()
                .unwrap();
        stream.write_all(b"native tcp ok").await.unwrap();
        let mut reply = [0; 13];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"native tcp ok");
        task.await.unwrap();
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn native_tcp_preserves_request_and_response_half_closes() {
        let (a, b) = pair().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"request before FIN");
            stream.write_all(b"response after FIN").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = a.connect(&Target::Ip(address)).await.unwrap();
            stream.write_all(b"request before FIN").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"response after FIN");
            task.await.unwrap();
        })
        .await
        .unwrap();
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn magicdns_preserves_the_client_transaction_id_and_both_families() {
        let (a, b) = pair().await;
        let query = crate::dns::codec::build_query(
            0x5432,
            "b.example.ts.net",
            hickory_proto::rr::RecordType::A,
        )
        .unwrap();
        let answer = a.dns_exchange(&query).await.unwrap();
        assert_eq!(&answer[..2], &[0x54, 0x32]);
        assert_eq!(
            crate::dns::codec::answer_ips(&answer).unwrap(),
            vec!["100.64.0.2".parse::<std::net::IpAddr>().unwrap()]
        );
        let query = crate::dns::codec::build_query(
            0x9876,
            "b.example.ts.net",
            hickory_proto::rr::RecordType::AAAA,
        )
        .unwrap();
        let answer = a.dns_exchange(&query).await.unwrap();
        assert_eq!(&answer[..2], &[0x98, 0x76]);
        assert_eq!(
            crate::dns::codec::answer_ips(&answer).unwrap(),
            vec!["fd7a:115c:a1e0::2".parse::<std::net::IpAddr>().unwrap()]
        );
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn test_tailscale_build_and_start() {
        let json_cfg = serde_json::json!({
            "type": "tailscale",
            "tag": "ts-out",
            "auth_key": "tskey-auth-test-key",
            "control_url": "https://controlplane.tailscale.com",
            "ephemeral": true,
            "hostname": "test-box",
            "listen_port": 0
        });

        let map = json_cfg.as_object().unwrap();
        let ts = Tailscale::build(map, "endpoints[0]").unwrap();
        assert_eq!(ts.cfg.tag, "ts-out");
        assert_eq!(ts.cfg.hostname.as_deref(), Some("test-box"));
        assert!(ts.cfg.ephemeral);

        // Test engine startup
        let shared = ts.shared().await.unwrap();
        assert_eq!(shared.next_id.load(Ordering::Relaxed), 1);
        ts.shutdown().await;
    }
}
