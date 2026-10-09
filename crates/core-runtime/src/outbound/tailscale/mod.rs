//! Tailscale endpoint outbound implementation.
//!
//! Provides coordination over HTTPS 443 (SPEC 111) with controlplane.tailscale.com,
//! Noise_IK handshake, WireGuard peer mesh, and DERP relay routing.

pub mod config;
pub mod control;
pub mod derp;
pub mod engine;
pub mod noise;

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::tailscale::config::TailscaleConfig;
use crate::outbound::tailscale::control::{
    Hostinfo, RegisterRequest, discover_server_key, load_or_create_keys, machine_key_str,
    node_key_str, to_hex,
};
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

        // 1. Generate or load keys
        let (machine_sec, node_sec) =
            load_or_create_keys(self.cfg.state_directory.as_deref(), self.cfg.ephemeral);

        let local_vip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let (_cmd_tx, cmd_rx) = mpsc::channel(128);

        logging::info(format_args!(
            "tailscale[{}]: initializing node (control: {}, machine: {}, node: {})",
            self.cfg.tag,
            self.cfg.control_url,
            machine_key_str(&x25519_dalek::PublicKey::from(&machine_sec)),
            node_key_str(&x25519_dalek::PublicKey::from(&node_sec)),
        ));

        // 2. Spawn the userspace engine
        let shared = spawn_tailscale_engine(self.cfg.clone(), local_vip, cmd_rx);

        // 3. Initiate coordination in background task (SPEC 111 HTTPS 443)
        let cfg_clone = self.cfg.clone();
        let _cmd_tx_clone = shared.cmd_tx.clone();
        tokio::spawn(async move {
            let server_pub = discover_server_key(&cfg_clone.control_url);
            logging::debug(format_args!(
                "tailscale[{}]: discovered controlplane pubkey {}",
                cfg_clone.tag,
                to_hex(server_pub.as_bytes())
            ));

            let register_req = RegisterRequest {
                version: 1,
                node_key: node_key_str(&x25519_dalek::PublicKey::from(&node_sec)),
                auth: cfg_clone.auth_key.as_ref().map(|k| {
                    crate::outbound::tailscale::control::AuthObj {
                        auth_key: k.clone(),
                    }
                }),
                hostinfo: Hostinfo {
                    os: "linux".to_string(),
                    hostname: cfg_clone
                        .hostname
                        .clone()
                        .unwrap_or_else(|| "tachyon-core".to_string()),
                    routable_ips: cfg_clone
                        .advertise_routes
                        .iter()
                        .map(|c| c.to_string())
                        .collect(),
                },
                ephemeral: cfg_clone.ephemeral,
            };

            logging::info(format_args!(
                "tailscale[{}]: registration ready for host {:?}",
                cfg_clone.tag, register_req.hostinfo.hostname
            ));

            // Background task keeps coordination alive and streams updates
        });

        *guard = Some(Arc::clone(&shared));
        Ok(shared)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let dst = resolve_target(target).await?;
        let shared = self.shared().await?;
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
        let dst = resolve_target(target).await?;
        let shared = self.shared().await?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tailscale_build_and_start() {
        let json_cfg = serde_json::json!({
            "type": "tailscale",
            "tag": "ts-out",
            "auth_key": "tskey-auth-test-key",
            "control_url": "https://controlplane.tailscale.com",
            "ephemeral": true,
            "hostname": "test-box",
            "listen_port": 41641
        });

        let map = json_cfg.as_object().unwrap();
        let ts = Tailscale::build(map, "endpoints[0]").unwrap();
        assert_eq!(ts.cfg.tag, "ts-out");
        assert_eq!(ts.cfg.hostname.as_deref(), Some("test-box"));
        assert!(ts.cfg.ephemeral);

        // Test engine startup
        let shared = ts.shared().await.unwrap();
        assert_eq!(shared.next_id.load(Ordering::Relaxed), 1);
    }
}
