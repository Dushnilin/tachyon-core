//! FPTN outbound — `fptn-project/fptn` client, full wire parity with the
//! reference `fptn-client` for the plain (non-obfuscator) path:
//!
//! 1. `POST /api/v1/login` for a JWT (retried on WebSocket rejection),
//! 2. TLS with the MD5 certificate pin *and* the FPTN session id stamped
//!    into the hello (`SHA1(htonl(now))[..4]`, server-enforced),
//! 3. WebSocket to `/api/v1/fptn` carrying one protobuf `Message` per
//!    binary frame (batch in, batch out),
//! 4. the assigned client IPv4 feeds the shared smoltcp stack shell —
//!    the server NATs destinations to that address, so incoming packets
//!    already land on the stack's `local_cidr`.

mod http;
mod obfs;
mod proto;
mod tls;
mod ws;

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::masque::resolve_host;
use crate::outbound::masque::resolve_target;
use crate::outbound::masque::stack::{self, Cmd, Leg, StackCfg};
use crate::outbound::quic::udp_loopback_pair;

const DEFAULT_MTU: usize = 1280;
const CALLER_BUF: usize = 65_536;
const SCRATCH_BUF: usize = 16_384;
const CMD_QUEUE: usize = 256;
const REPLY_QUEUE: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ASSIGN_TIMEOUT: Duration = Duration::from_secs(15);
const WS_PATH: &str = "/api/v1/fptn";

/// Censorship strategy (`CensorshipStrategy` in the official client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Obfuscation {
    /// `kSni`: plain TLS hello carrying the FPTN session id. The official
    /// default, but TLS-fingerprinting middleboxes filter it.
    None,
    /// `kTlsObfuscator`: handshake inside TlsObfuscator2 frames; the server
    /// then skips the session-id / probing / reality checks.
    Tls,
}

impl Obfuscation {
    fn parse(value: Option<&Value>, at: &str) -> anyhow::Result<Self> {
        match value {
            None | Some(Value::Null) => Ok(Self::Tls),
            Some(Value::String(raw)) => match raw.as_str() {
                "tls" | "tls_obfuscator" | "kTlsObfuscator" => Ok(Self::Tls),
                "none" | "sni" | "kSni" => Ok(Self::None),
                other => anyhow::bail!(
                    "{at}: invalid obfuscation: {other:?} (expected \"tls\" or \"none\")"
                ),
            },
            Some(_) => anyhow::bail!("{at}: obfuscation: must be a string"),
        }
    }
}

/// Runtime-side config (reference `settings.json` per-server entry after
/// token expansion).
#[derive(Debug)]
pub(crate) struct FptnCfg {
    pub tag: String,
    pub server: (String, u16),
    pub username: String,
    pub password: String,
    /// Lowercased 32-hex leaf digest; empty disables verification.
    pub md5: String,
    pub sni: String,
    pub obfuscation: Obfuscation,
    pub mtu: usize,
    pub udp_timeout: Duration,
    pub allow_tcp: bool,
    pub allow_udp: bool,
}

/// Live stack task handle (one tunnel per outbound).
#[derive(Debug)]
struct FptnShared {
    cmd_tx: mpsc::Sender<Cmd>,
    next_id: AtomicU32,
}

/// FPTN outbound (see module docs).
#[derive(Debug)]
pub struct Fptn {
    cfg: Arc<FptnCfg>,
    shared: AsyncMutex<Option<Arc<FptnShared>>>,
    /// Cached JWT; cleared and re-fetched when the WebSocket is rejected.
    jwt: AsyncMutex<Option<String>>,
    /// One `GET /api/v1/dns` probe per instance (logged, non-fatal).
    dns_probed: AtomicBool,
}

fn get_str<'a>(obj: &'a Map<String, Value>, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `network_list` (Listable[string]): absent/null = both networks.
fn parse_network_list(value: Option<&Value>) -> (bool, bool) {
    match value {
        None | Some(Value::Null) => (true, true),
        Some(Value::String(s)) => (s == "tcp", s == "udp"),
        Some(Value::Array(items)) => {
            let mut tcp = false;
            let mut udp = false;
            for item in items {
                match item.as_str() {
                    Some("tcp") => tcp = true,
                    Some("udp") => udp = true,
                    _ => {}
                }
            }
            (tcp, udp)
        }
        Some(_) => (true, true),
    }
}

impl Fptn {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let server = crate::outbound::proxy::server_endpoint(obj, at)?;
        let username = get_str(obj, "username").to_string();
        if username.is_empty() {
            anyhow::bail!("{at}: missing username");
        }
        let password = get_str(obj, "password").to_string();
        if password.is_empty() {
            anyhow::bail!("{at}: missing password");
        }
        let md5 = get_str(obj, "md5_fingerprint").to_ascii_lowercase();
        // Explicit `sni` wins; otherwise a hostname server is the SNI and an
        // IP-literal server sends none (the MD5 pin authenticates anyway).
        let sni = {
            let explicit = get_str(obj, "sni").to_string();
            if !explicit.is_empty() {
                explicit
            } else if server.0.parse::<IpAddr>().is_err() {
                server.0.clone()
            } else {
                String::new()
            }
        };
        let mtu = obj
            .get("mtu")
            .and_then(Value::as_u64)
            .filter(|m| *m != 0)
            .map(|m| m as usize)
            .unwrap_or(DEFAULT_MTU);
        let obfuscation = Obfuscation::parse(obj.get("obfuscation"), at)?;
        let (allow_tcp, allow_udp) = parse_network_list(obj.get("network_list"));

        Ok(Self {
            cfg: Arc::new(FptnCfg {
                tag: at.to_string(),
                server,
                username,
                password,
                md5,
                sni,
                obfuscation,
                mtu,
                udp_timeout: DEFAULT_UDP_TIMEOUT,
                allow_tcp,
                allow_udp,
            }),
            shared: AsyncMutex::new(None),
            jwt: AsyncMutex::new(None),
            dns_probed: AtomicBool::new(false),
        })
    }

    /// One WebSocket dial: TLS → handshake with `Authorization: Bearer` →
    /// IP assignment message. A rejected handshake (expired JWT) is retried
    /// once with a fresh login, mirroring the reference reconnect logic.
    async fn establish(&self, server: SocketAddr) -> io::Result<(ws::WsMsgStream, Ipv4Addr)> {
        let cached = self.jwt.lock().await.clone();
        let mut attempt = 0u8;
        let mut jwt = cached;
        loop {
            attempt += 1;
            if jwt.is_none() {
                jwt = Some(
                    http::login(
                        server,
                        &self.cfg.sni,
                        &self.cfg.md5,
                        &self.cfg.username,
                        &self.cfg.password,
                        self.cfg.obfuscation,
                    )
                    .await?,
                );
                *self.jwt.lock().await = jwt.clone();
            }
            match self
                .dial_ws(server, jwt.as_deref().unwrap_or_default())
                .await
            {
                Ok(assignment) => return Ok(assignment),
                Err(e) if attempt < 2 => {
                    logging::warn(format_args!(
                        "fptn[{}]: websocket handshake rejected ({e}); re-logging in",
                        self.cfg.tag
                    ));
                    *self.jwt.lock().await = None;
                    jwt = None;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn dial_ws(
        &self,
        server: SocketAddr,
        jwt: &str,
    ) -> io::Result<(ws::WsMsgStream, Ipv4Addr)> {
        let tls = tls::connect(
            server,
            &self.cfg.sni,
            &self.cfg.md5,
            self.cfg.obfuscation == Obfuscation::Tls,
        )
        .await?;
        let stream: AnyStream = Box::new(tls);
        let host = server.to_string();
        let headers = [(String::from("Authorization"), format!("Bearer {jwt}"))];
        let mut ws = ws::WsMsgStream::handshake(stream, WS_PATH, &host, &headers).await?;
        // The server speaks first: IP assignment before any packet batch.
        let msg = tokio::time::timeout(ASSIGN_TIMEOUT, ws.read_message())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fptn: ip assignment timeout"))?
            .map_err(|e| io::Error::other(format!("fptn: ip assignment read: {e}")))?
            .ok_or_else(|| io::Error::other("fptn: connection closed before ip assignment"))?;
        let (v4, v6) = proto::decode_ip_assignment(&msg)?;
        if v6.is_empty() {
            return Err(io::Error::other("fptn: server assigned no IPv6"));
        }
        let addr: Ipv4Addr = v4
            .parse()
            .map_err(|e| io::Error::other(format!("fptn: bad assigned IPv4 {v4:?}: {e}")))?;
        logging::info(format_args!(
            "fptn[{}]: tunnel up to {}:{} (client {})",
            self.cfg.tag, self.cfg.server.0, self.cfg.server.1, addr
        ));
        Ok((ws, addr))
    }

    /// True while the shared stack task is live. `shared()` silently
    /// rebuilds a dead tunnel on the next dial, so this is the only way to
    /// observe one (used by tests/diagnostics to catch keep-alive deaths).
    pub fn tunnel_alive(&self) -> bool {
        match self.shared.try_lock() {
            Ok(guard) => guard.as_ref().is_some_and(|s| !s.cmd_tx.is_closed()),
            Err(_) => true, // a dial holds the lock — the tunnel is (re)building
        }
    }

    /// Return the live stack task, building a tunnel lazily (reference
    /// `ensureSession`). A dead task is replaced on the next dial.
    async fn shared(&self) -> io::Result<Arc<FptnShared>> {
        let mut guard = self.shared.lock().await;
        if let Some(shared) = guard.as_ref()
            && !shared.cmd_tx.is_closed()
        {
            return Ok(Arc::clone(shared));
        }
        let server = resolve_host(&self.cfg.server.0, self.cfg.server.1).await?;
        let (ws, local_addr) = tokio::time::timeout(CONNECT_TIMEOUT, self.establish(server))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fptn: tunnel timeout"))??;
        let (tx, rx) = mpsc::channel(CMD_QUEUE);
        let shared = Arc::new(FptnShared {
            cmd_tx: tx,
            next_id: AtomicU32::new(1),
        });
        let stack_cfg = Arc::new(StackCfg {
            tag: self.cfg.tag.clone(),
            mtu: self.cfg.mtu,
            local_addr,
            local_cidr: IpCidr::new(IpAddress::Ipv4(local_addr), 32),
            idle_timeout: None,
        });
        let conn = FptnConn::new(ws);
        tokio::spawn(async move {
            if let Err(e) = stack::run(stack_cfg, Leg::Fptn(conn), rx).await {
                logging::error(format_args!("fptn stack exited: {e}"));
            }
        });
        *guard = Some(Arc::clone(&shared));
        // Reference `GetDns` is a plain GET with no auth; fetch the provider
        // resolver once per instance and log it — it is what a DNS-through-
        // tunnel config entry needs, and the lookup must not delay the dial.
        if !self.dns_probed.swap(true, Ordering::Relaxed) {
            let cfg = Arc::clone(&self.cfg);
            tokio::spawn(async move {
                match http::get_dns(server, &cfg.sni, &cfg.md5, cfg.obfuscation).await {
                    Ok((dns, dns_ipv6)) => logging::info(format_args!(
                        "fptn[{}]: provider dns {dns} / {dns_ipv6}",
                        cfg.tag
                    )),
                    Err(e) => logging::debug(format_args!(
                        "fptn[{}]: provider dns lookup failed: {e}",
                        cfg.tag
                    )),
                }
            });
        }
        Ok(shared)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if !self.cfg.allow_tcp {
            return Err(io::Error::other(
                "fptn: tcp network is not allowed by network_list",
            ));
        }
        let dst = resolve_target(target).await?;
        if !dst.is_ipv4() {
            return Err(io::Error::other("fptn: ipv6 targets are not supported yet"));
        }
        let shared = self.shared().await?;
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (local, remote) = tokio::io::duplex(CALLER_BUF);
        let (caller_read, caller_write) = tokio::io::split(local);
        let (to_caller_tx, to_caller_rx) = mpsc::channel(REPLY_QUEUE);
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
            .map_err(|_| io::Error::other("fptn: stack task stopped"))?;

        // caller → stack: forward reads as TCP data chunks.
        let cmd_tx = shared.cmd_tx.clone();
        tokio::spawn(async move {
            let mut read = caller_read;
            let mut buf = vec![0u8; SCRATCH_BUF];
            loop {
                match read.read(&mut buf).await {
                    Ok(0) => {
                        let _ = cmd_tx.send(Cmd::TcpClose { id }).await;
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

        // stack → caller: pump replies with per-connection backpressure.
        tokio::spawn(async move {
            let mut write = caller_write;
            let mut replies = to_caller_rx;
            while let Some(bytes) = replies.recv().await {
                if write.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = write.flush().await;
            }
        });

        match tokio::time::timeout(CONNECT_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(remote)),
            Ok(Ok(Err(e))) => Err(io::Error::other(format!("fptn: {e}"))),
            Ok(Err(_)) => Err(io::Error::other("fptn: stack task stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fptn: connect timeout",
            )),
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        if !self.cfg.allow_udp {
            return Err(io::Error::other(
                "fptn: udp network is not allowed by network_list",
            ));
        }
        let dst = resolve_target(target).await?;
        if !dst.is_ipv4() {
            return Err(io::Error::other("fptn: ipv6 targets are not supported yet"));
        }
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
            .map_err(|_| io::Error::other("fptn: stack task stopped"))?;
        let (port, mut replies) = match tokio::time::timeout(Duration::from_secs(10), resp_rx).await
        {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => return Err(io::Error::other(format!("fptn: {e}"))),
            Ok(Err(_)) => return Err(io::Error::other("fptn: stack task stopped")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fptn: udp session timeout",
                ));
            }
        };

        let peer = Arc::new(peer);
        let cmd_tx = shared.cmd_tx.clone();
        let udp_timeout = self.cfg.udp_timeout;

        // replies: stack → session channel → loopback peer socket.
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

        // sends: loopback peer socket → stack (mirrors the hysteria2 bridge).
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

/// Stack leg: IP packets carried in binary WebSocket messages, batched per
/// the reference client's `kMaxBatchSize = 32` and encoded by [`proto`].
pub struct FptnConn {
    ws: ws::WsMsgStream,
    pending: VecDeque<Vec<u8>>,
}

impl FptnConn {
    fn new(ws: ws::WsMsgStream) -> Self {
        Self {
            ws,
            pending: VecDeque::new(),
        }
    }

    pub(crate) async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        if let Some(pkt) = self.pending.pop_front() {
            return Ok(pkt);
        }
        loop {
            let msg = self
                .ws
                .read_message()
                .await?
                .ok_or_else(|| io::Error::other("fptn: tunnel closed"))?;
            let mut packets = proto::decode_batch(&msg)?;
            if packets.is_empty() {
                continue;
            }
            let first = packets.remove(0);
            self.pending.extend(packets);
            return Ok(first);
        }
    }

    /// Serialize a whole batch into one binary WebSocket message (the
    /// reference client's `RunSender` writes at most `kMaxBatchSize = 32`
    /// packets per frame).
    pub(crate) async fn write_batch(&mut self, packets: &[Vec<u8>]) -> io::Result<()> {
        let msg = proto::encode_batch(packets)?;
        self.ws.send_binary(&msg).await
    }

    /// Last frame timestamp in either direction (keep-alive clock).
    pub(crate) fn last_activity(&self) -> std::time::Instant {
        self.ws.last_activity()
    }

    /// Send a WebSocket keep-alive ping (`keep_alive_pings = true`).
    pub(crate) async fn keepalive(&mut self) -> io::Result<()> {
        self.ws.send_ping().await
    }

    /// The WebSocket (and its TLS session) closes when this leg drops.
    pub(crate) fn close(&mut self) {}
}

#[cfg(test)]
mod live {
    use super::*;

    /// Stage-by-stage live probe (manual): `FPTN_TOKEN=… cargo test -p
    /// core-runtime fptn::live -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "requires FPTN_TOKEN and network access"]
    async fn live_stages() {
        let Ok(token) = std::env::var("FPTN_TOKEN") else {
            eprintln!("FPTN_TOKEN not set; skipping");
            return;
        };
        let root =
            serde_json::json!({ "outbounds": [{ "type": "fptn", "tag": "vpn", "token": token }] });
        let expanded = core_config::fptn::expand(&root)
            .expect("expand")
            .expect("token outbound present");
        let member = expanded["outbounds"]
            .as_array()
            .expect("array")
            .iter()
            .find(|o| o["type"] == "fptn")
            .expect("member")
            .clone();
        let fptn = Fptn::build(member.as_object().expect("object"), "live").expect("build");
        let server = resolve_host(&fptn.cfg.server.0, fptn.cfg.server.1)
            .await
            .expect("resolve");
        eprintln!("== server {server} sni={:?}", fptn.cfg.sni);

        eprintln!("== stage 1: login");
        let jwt = http::login(
            server,
            &fptn.cfg.sni,
            &fptn.cfg.md5,
            &fptn.cfg.username,
            &fptn.cfg.password,
            fptn.cfg.obfuscation,
        )
        .await
        .expect("login");
        eprintln!("== login ok, token len {}", jwt.len());

        eprintln!("== stage 2: tls");
        let tls = tls::connect(
            server,
            &fptn.cfg.sni,
            &fptn.cfg.md5,
            fptn.cfg.obfuscation == Obfuscation::Tls,
        )
        .await
        .expect("tls");
        eprintln!("== tls ok");

        eprintln!("== stage 3: websocket handshake");
        let stream: AnyStream = Box::new(tls);
        let headers = [(String::from("Authorization"), format!("Bearer {jwt}"))];
        let mut ws = ws::WsMsgStream::handshake(stream, WS_PATH, &server.to_string(), &headers)
            .await
            .expect("ws handshake");
        eprintln!("== ws ok");

        eprintln!("== stage 4: ip assignment");
        let msg = ws
            .read_message()
            .await
            .expect("read assignment")
            .expect("eof");
        let (v4, v6) = proto::decode_ip_assignment(&msg).expect("assignment");
        eprintln!("== assigned {v4} / {v6}");

        eprintln!("== stage 5: provider dns (GET /api/v1/dns)");
        let (dns4, dns6) =
            http::get_dns(server, &fptn.cfg.sni, &fptn.cfg.md5, fptn.cfg.obfuscation)
                .await
                .expect("get_dns");
        eprintln!("== provider dns {dns4} / {dns6}");
    }
}
