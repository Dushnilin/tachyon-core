//! OpenVPN static-key endpoint outbound — initiator-only datapath.
//!
//! One supervisor task per endpoint owns a `smoltcp` interface over a virtual
//! device; TCP goes through smoltcp, UDP is wrapped into IPv4 packets
//! directly. The data channel codec lives in [`codec`]; MSS clamping in
//! [`mss`]; the wire layout, supervisor backoff, cursor advance and keepalive
//! timers mirror sing-openvpn (`client_session_static.go`,
//! `client_supervisor.go`, `client_restart.go`, `keepalive.go`).

mod codec;
mod mss;
mod replay;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as PhyRxToken,
    TxToken as PhyTxToken,
};
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::socket::tcp::{
    RecvError as TcpRecvError, Socket as TcpSock, SocketBuffer as TcpBuffer,
};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::urltest::parse_duration;

use self::codec::{AuthKind, StaticCodec, cipher_key_size, load_static_key_material};
use self::mss::{
    DEFAULT_MSS_FIX, MssClamp, calculate_mss_clamp, outer_transport_overhead, transport_header_size,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESP_TIMEOUT: Duration = Duration::from_secs(35);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// upstream read deadline: keepalive checks run at least this often.
const READ_TICK: Duration = Duration::from_secs(1);
/// smoltcp retransmission cadence while inner TCP connections are active.
const TCP_TICK: Duration = Duration::from_millis(50);

const DEFAULT_MTU: usize = 1500;
const EPHEMERAL_BASE: u16 = 49152;

const SOCKET_BUF: usize = 65_536;
const SCRATCH_BUF: usize = 16_384;
const CALLER_BUF: usize = 65_536;
const CMD_QUEUE: usize = 256;
const REPLY_QUEUE: usize = 64;
const EGRESS_BUF_MAX: usize = 1 << 20;
const MAX_DATAGRAM: usize = 65_535;

/// `dataChannelFraming` stays nil in this runtime (no compression, no
/// fragment), so the framing payload overhead fed into the MSS budget is 0.
const FRAMING_OVERHEAD: usize = 0;

/// upstream `openVPNDataChannelPingPayload`.
const PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

/// Endpoint fields accepted by check but not honored by the runtime.
const IGNORED_FIELDS: &[&str] = &[
    "name",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "topology",
    "username",
    "password",
    "auth_retry",
    "static_challenge",
    "static_challenge_echo",
    "route_no_pull",
    "pull_filters",
    "routes",
    "route_gateway",
    "route_metric",
    "redirect_gateway",
    "redirect_gateway_flags",
    "redirect_private",
    "renegotiate_interval",
    "renegotiate_disabled",
    "renegotiate_bytes",
    "renegotiate_packets",
    "tls_timeout",
    "handshake_window",
    "ping_restart_disabled",
    "explicit_exit_notify",
    "allow_compression",
];

const OVPN_CLIENT_PROTOCOLS: &[&str] = &["", "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"];
const OVPN_KEY_DIRECTIONS: &[&str] = &["", "server", "client"];
const COMPRESSION_OFF: &[&str] = &["none", "no", "disabled", "off", "migrate"];
const COMPRESSION_LZO_OFF: &[&str] = &["none", "disabled", "off"];

fn endpoint_str<'a>(obj: &'a Map<String, Value>, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("")
}

fn ep_bool_val(obj: &Map<String, Value>, key: &str) -> bool {
    obj.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn ep_u64_val(obj: &Map<String, Value>, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// `badoption.Listable` joined with `\n` (reference `materialSource`).
fn listable_join(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// `keyDirectionValue` (protocol/openvpn/endpoint.go).
fn key_direction_value(direction: &str) -> Result<i32, String> {
    if !OVPN_KEY_DIRECTIONS.contains(&direction) {
        return Err(format!(
            "unsupported key direction: {direction} (expected \"server\" or \"client\")"
        ));
    }
    Ok(match direction {
        "" => -1,
        "server" => 0,
        _ => 1,
    })
}

/// `resolveTransportProtocol` (client protocols, `""` defaults to `udp`).
fn resolve_protocol(protocol: &str) -> Result<String, String> {
    let resolved = if protocol.is_empty() { "udp" } else { protocol };
    if OVPN_CLIENT_PROTOCOLS.contains(&resolved) {
        Ok(resolved.to_string())
    } else {
        Err("unsupported openvpn protocol".to_string())
    }
}

#[derive(Clone, Debug)]
struct OvpnRemote {
    host: String,
    port: u16,
    /// per-remote `network`; empty → the endpoint-global protocol.
    protocol: String,
}

#[derive(Clone, Debug)]
struct OvpnConfig {
    tag: String,
    remotes: Vec<OvpnRemote>,
    global_protocol: String,
    local_cidrs: Vec<IpCidr>,
    local_addr: Ipv4Addr,
    mtu: usize,
    /// inline static key source (`None` → read from `material_path`).
    material_content: Option<String>,
    material_path: Option<String>,
    key_direction: i32,
    cipher: String,
    auth: String,
    replay_window_size: u32,
    replay_window_time: Duration,
    mss_fix: u32,
    mss_fix_mode: String,
    ping_interval: Duration,
    ping_restart: Duration,
    udp_timeout: Duration,
    block_ipv6: bool,
}

/// `UdpOpen` completion: local port + reply stream.
type UdpReply = oneshot::Sender<Result<(u16, mpsc::Receiver<Vec<u8>>), String>>;

enum Cmd {
    TcpConnect {
        id: u32,
        dst: SocketAddr,
        to_caller: mpsc::Sender<Vec<u8>>,
        resp: oneshot::Sender<Result<(), String>>,
    },
    TcpData {
        id: u32,
        bytes: Vec<u8>,
    },
    TcpClose {
        id: u32,
    },
    UdpOpen {
        target: SocketAddr,
        resp: UdpReply,
    },
    UdpSend {
        port: u16,
        bytes: Vec<u8>,
    },
    UdpClose {
        port: u16,
    },
}

#[derive(Debug)]
struct OvpnShared {
    cmd_tx: mpsc::Sender<Cmd>,
    next_id: AtomicU32,
    /// true while a data-channel session is pumping.
    ready: Arc<AtomicBool>,
}

/// OpenVPN static-key endpoint outbound (see module docs).
#[derive(Debug)]
pub struct OpenVpn {
    cfg: OvpnConfig,
    shared: AsyncMutex<Option<Arc<OvpnShared>>>,
}

impl OpenVpn {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        if obj.get("system").and_then(Value::as_bool) == Some(true) {
            anyhow::bail!("{at}: system openvpn is not implemented yet");
        }
        for f in IGNORED_FIELDS {
            if obj.get(*f).is_some_and(|v| !v.is_null()) {
                logging::warn(format_args!(
                    "openvpn endpoint {at}: {f} is not implemented yet (ignored)"
                ));
            }
        }

        let mode = endpoint_str(obj, "mode");
        let mode = if mode.is_empty() { "tls" } else { mode };
        if mode != "static_key" {
            anyhow::bail!("{at}: openvpn mode {mode} is not implemented yet");
        }

        // reference buildClientRemoteOptions: `server` xor `servers`.
        let server = endpoint_str(obj, "server");
        let servers = match obj.get("servers") {
            Some(Value::Array(items)) => items.len(),
            _ => 0,
        };
        if !server.is_empty() && servers > 0 {
            anyhow::bail!("{at}: `server` is conflict with `servers`");
        }
        if server.is_empty() && servers == 0 {
            anyhow::bail!("{at}: missing `server` or `servers`");
        }
        let network = endpoint_str(obj, "network");
        let global_protocol =
            resolve_protocol(network).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        // (host, port, per-remote `network`) — `servers` entries carry their own port.
        let mut raw_remotes: Vec<(String, u64, String)> = Vec::new();
        if !server.is_empty() {
            raw_remotes.push((
                server.to_string(),
                ep_u64_val(obj, "server_port"),
                network.to_string(),
            ));
        } else if let Some(Value::Array(items)) = obj.get("servers") {
            for entry in items {
                let Value::Object(remote) = entry else {
                    continue;
                };
                raw_remotes.push((
                    endpoint_str(remote, "server").to_string(),
                    remote
                        .get("server_port")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    endpoint_str(remote, "network").to_string(),
                ));
            }
        }
        if raw_remotes.is_empty() {
            anyhow::bail!("{at}: missing `server` or `servers`");
        }
        let mut remotes = Vec::with_capacity(raw_remotes.len());
        for (idx, (host, port, protocol)) in raw_remotes.into_iter().enumerate() {
            if host.is_empty()
                || host.contains([' ', '\t', '\r', '\n'])
                || host.starts_with('[')
                || host.ends_with(']')
            {
                anyhow::bail!(
                    "{at}: option is not supported yet: invalid remote host at index {idx}"
                );
            }
            if port == 0 {
                anyhow::bail!(
                    "{at}: option is not supported yet: empty remote port at index {idx}"
                );
            }
            if port > u16::MAX as u64 {
                anyhow::bail!("{at}: invalid remote port {port} at index {idx}");
            }
            let effective = if protocol.is_empty() {
                global_protocol.as_str()
            } else {
                protocol.as_str()
            };
            resolve_protocol(effective).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
            remotes.push(OvpnRemote {
                host,
                port: port as u16,
                protocol,
            });
        }

        // reference buildClientTunnelOptions: addresses (+ peer parity checks).
        let mut local_cidrs: Vec<IpCidr> = Vec::new();
        if let Some(Value::Array(items)) = obj.get("address") {
            for (i, entry) in items.iter().enumerate() {
                let raw = entry
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{at}: `address[{i}]` is invalid"))?;
                local_cidrs.push(
                    parse_cidr_entry(raw)
                        .ok_or_else(|| anyhow::anyhow!("{at}: `address[{i}]` is invalid"))?,
                );
            }
        }
        let local_addr = local_cidrs
            .first()
            .map(|cidr| match cidr.address() {
                IpAddress::Ipv4(ip) => ip,
            })
            .ok_or_else(|| anyhow::anyhow!("{at}: missing ipv4 address"))?;

        // reference buildStaticKeyClientOptions: material + key direction.
        let material_content = listable_join(obj.get("static_key"));
        let material_path = endpoint_str(obj, "static_key_path").to_string();
        if !material_content.is_empty() && !material_path.is_empty() {
            anyhow::bail!("{at}: material path and content are both set: static_key");
        }
        if material_content.is_empty() && material_path.is_empty() {
            anyhow::bail!("{at}: missing `static_key` or `static_key_path`");
        }
        let key_direction = key_direction_value(endpoint_str(obj, "key_direction"))
            .map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        if material_content.is_empty() {
            load_static_key_material(None, Some(&material_path))
                .map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        } else {
            load_static_key_material(Some(&material_content), None)
                .map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        }

        // data channel names (reference errors, check mirrors them).
        let cipher = endpoint_str(obj, "cipher").to_string();
        if cipher.is_empty() {
            anyhow::bail!("{at}: ClientOptions.DataChannel.Cipher is required in static_key mode");
        }
        cipher_key_size(&cipher).map_err(|_| {
            anyhow::anyhow!(
                "{at}: ClientOptions.DataChannel.Cipher is not supported in static_key mode: {cipher}"
            )
        })?;
        let auth = endpoint_str(obj, "auth").to_string();
        AuthKind::parse(&auth).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;

        // compression / fragment wire framing is not implemented (framing nil).
        let compression = endpoint_str(obj, "compression").trim();
        if !compression.is_empty() && !COMPRESSION_OFF.contains(&compression) {
            anyhow::bail!("{at}: openvpn compression is not implemented yet");
        }
        let compression_lzo = endpoint_str(obj, "compression_lzo").trim();
        if !compression_lzo.is_empty() && !COMPRESSION_LZO_OFF.contains(&compression_lzo) {
            anyhow::bail!("{at}: openvpn compression is not implemented yet");
        }
        if ep_u64_val(obj, "fragment") > 0 {
            anyhow::bail!("{at}: openvpn fragment is not implemented yet");
        }

        // reference NewClient MSS defaulting (client.go:100-111).
        let raw_mtu = ep_u64_val(obj, "mtu") as u32;
        let mut mss_fix = ep_u64_val(obj, "mss_fix") as u32;
        let mut mss_fix_mode = endpoint_str(obj, "mss_fix_mode").to_string();
        if mss_fix == 0 && !ep_bool_val(obj, "mss_fix_disabled") {
            let fragment = ep_u64_val(obj, "fragment") as u32;
            if fragment > 0 {
                mss_fix = fragment;
                mss_fix_mode = mss::MSS_FIX_MODE_MTU.to_string();
            } else if raw_mtu == 0 || raw_mtu == 1500 {
                mss_fix = DEFAULT_MSS_FIX;
                mss_fix_mode = mss::MSS_FIX_MODE_MTU.to_string();
            } else {
                mss_fix = raw_mtu;
                mss_fix_mode = mss::MSS_FIX_MODE_FIXED.to_string();
            }
        }

        let replay_window_size = ep_u64_val(obj, "replay_window") as u32;
        let replay_window_time = parse_duration(
            obj.get("replay_window_time"),
            replay::DEFAULT_REPLAY_WINDOW_TIME,
            at,
        )?;
        let ping_interval = parse_duration(obj.get("ping_interval"), Duration::ZERO, at)?;
        let ping_restart = if ep_bool_val(obj, "ping_restart_disabled") {
            Duration::ZERO
        } else {
            parse_duration(obj.get("ping_restart"), Duration::ZERO, at)?
        };
        let udp_timeout = parse_duration(obj.get("udp_timeout"), DEFAULT_UDP_TIMEOUT, at)?;
        let mtu = if raw_mtu > 0 {
            raw_mtu as usize
        } else {
            DEFAULT_MTU
        };
        if mtu > 65_535 {
            anyhow::bail!("{at}: invalid mtu {mtu}");
        }

        // reference resolveClientRemotes: remote_random shuffles once.
        if ep_bool_val(obj, "remote_random") && remotes.len() > 1 {
            for i in (1..remotes.len()).rev() {
                let j = secure_index(i + 1)
                    .map_err(|e| anyhow::anyhow!("{at}: remote_random shuffle: {e}"))?;
                remotes.swap(i, j);
            }
        }

        Ok(Self {
            cfg: OvpnConfig {
                tag: at.to_string(),
                remotes,
                global_protocol,
                local_cidrs,
                local_addr,
                mtu,
                material_content: (!material_content.is_empty()).then_some(material_content),
                material_path: (!material_path.is_empty()).then_some(material_path),
                key_direction,
                cipher,
                auth,
                replay_window_size,
                replay_window_time,
                mss_fix,
                mss_fix_mode,
                ping_interval,
                ping_restart,
                udp_timeout,
                block_ipv6: ep_bool_val(obj, "block_ipv6"),
            },
            shared: AsyncMutex::new(None),
        })
    }

    async fn shared(&self) -> io::Result<Arc<OvpnShared>> {
        let mut guard = self.shared.lock().await;
        if let Some(shared) = guard.as_ref() {
            return Ok(Arc::clone(shared));
        }
        let (tx, rx) = mpsc::channel(CMD_QUEUE);
        let shared = Arc::new(OvpnShared {
            cmd_tx: tx,
            next_id: AtomicU32::new(1),
            ready: Arc::new(AtomicBool::new(false)),
        });
        let cfg = self.cfg.clone();
        let ready = Arc::clone(&shared.ready);
        let tag = self.cfg.tag.clone();
        tokio::spawn(async move {
            if let Err(e) = run(cfg, rx, ready).await {
                logging::error(format_args!("openvpn[{tag}] stack exited: {e}"));
            }
        });
        *guard = Some(Arc::clone(&shared));
        Ok(shared)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let dst = resolve_target(target).await?;
        if !dst.is_ipv4() {
            return Err(io::Error::other(
                "openvpn: ipv6 targets are not supported yet",
            ));
        }
        let shared = self.shared().await?;
        if !shared.ready.load(Ordering::Acquire) {
            return Err(io::Error::other("openvpn: endpoint is not ready yet"));
        }
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
            .map_err(|_| io::Error::other("openvpn: stack task stopped"))?;

        // caller → stack: forward reads as TCP data chunks.
        let cmd_tx = Arc::clone(&shared).cmd_tx.clone();
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

        match tokio::time::timeout(RESP_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(remote)),
            Ok(Ok(Err(e))) => Err(io::Error::other(format!("openvpn: {e}"))),
            Ok(Err(_)) => Err(io::Error::other("openvpn: stack task stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "openvpn: connect timeout",
            )),
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        let dst = resolve_target(target).await?;
        if !dst.is_ipv4() {
            return Err(io::Error::other(
                "openvpn: ipv6 targets are not supported yet",
            ));
        }
        let shared = self.shared().await?;
        if !shared.ready.load(Ordering::Acquire) {
            return Err(io::Error::other("openvpn: endpoint is not ready yet"));
        }
        let (local, peer) = udp_loopback_pair().await?;
        let (resp_tx, resp_rx) = oneshot::channel();
        shared
            .cmd_tx
            .send(Cmd::UdpOpen {
                target: dst,
                resp: resp_tx,
            })
            .await
            .map_err(|_| io::Error::other("openvpn: stack task stopped"))?;
        let (port, mut replies) = match tokio::time::timeout(RESP_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => return Err(io::Error::other(format!("openvpn: {e}"))),
            Ok(Err(_)) => return Err(io::Error::other("openvpn: stack task stopped")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "openvpn: udp session timeout",
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
            let mut buf = vec![0u8; MAX_DATAGRAM];
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

/// unbiased index in `0..bound` (reference `secureShuffleClientRemotes`).
fn secure_index(bound: usize) -> Result<usize, String> {
    debug_assert!(bound > 0);
    let zone = u64::MAX - u64::MAX % bound as u64;
    loop {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| format!("getrandom: {e}"))?;
        let value = u64::from_le_bytes(b);
        if value < zone {
            return Ok((value % bound as u64) as usize);
        }
    }
}

/// `addr/prefix` or a bare IPv4 address (`/32`).
fn parse_cidr_entry(raw: &str) -> Option<IpCidr> {
    if let Ok(cidr) = raw.parse::<IpCidr>() {
        return Some(cidr);
    }
    raw.parse::<Ipv4Addr>()
        .ok()
        .map(|ip| IpCidr::new(IpAddress::from(ip), 32))
}
// ---------------------------------------------------------------------------
// data channel session
// ---------------------------------------------------------------------------

/// Everything the session needs from the resolved cursor position.
#[derive(Clone, Copy, Default)]
struct Cursor {
    remote_index: usize,
    /// index into the resolved address list of the current remote
    /// (`transportDialContextWithAddressIndex`).
    address_index: usize,
}

/// `nextConnectionCursor` (client_restart.go).
#[derive(Clone, Copy)]
enum Advance {
    /// `initialized`: the session came up, keep talking to the same peer.
    Stay,
    NextAddress,
    NextRemote,
}

fn advance_cursor(cursor: &mut Cursor, advance: Advance, remotes_len: usize) {
    match advance {
        Advance::Stay => {}
        Advance::NextAddress => cursor.address_index += 1,
        Advance::NextRemote => {
            cursor.remote_index = (cursor.remote_index + 1) % remotes_len;
            cursor.address_index = 0;
        }
    }
}

#[derive(Debug)]
enum EstablishError {
    /// retryable: move to the next resolved address.
    Retry(String),
    /// retryable: `ErrRemoteAddressExhausted`, rotate to the next remote.
    Exhausted(String),
    /// `setTerminalError`: the stack must not restart the session.
    Terminal(String),
}

enum Writer {
    Udp(Arc<UdpSocket>),
    Tcp(OwnedWriteHalf),
}

impl Writer {
    fn is_tcp(&self) -> bool {
        matches!(self, Writer::Tcp(_))
    }

    /// `proto/connection.go WritePackets`: TCP frames carry a 2-byte length
    /// prefix, UDP sends the packet as-is.
    async fn write_wire(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > u16::MAX as usize {
            return Err(io::Error::other("packet too large"));
        }
        match self {
            Writer::Udp(sock) => {
                sock.send(bytes).await?;
            }
            Writer::Tcp(stream) => {
                let mut frame = Vec::with_capacity(2 + bytes.len());
                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                frame.extend_from_slice(bytes);
                stream.write_all(&frame).await?;
            }
        }
        Ok(())
    }
}

struct Session {
    writer: Writer,
    codec: StaticCodec,
    clamp: MssClamp,
    protocol: String,
    remote: SocketAddr,
    ping_interval: Duration,
    ping_restart: Duration,
    last_in: Instant,
    last_out: Instant,
    /// inbound read tasks; aborted with the session.
    readers: Vec<JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}

impl Session {
    async fn write_wire(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_wire(bytes).await?;
        self.last_out = Instant::now();
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn matches(self, addr: &SocketAddr) -> bool {
        match self {
            Self::V4 => addr.is_ipv4(),
            Self::V6 => addr.is_ipv6(),
        }
    }
}

/// `udp4`/`udp6`/`tcp4`/`tcp6` constrain the dial network family.
fn protocol_family(protocol: &str) -> Option<Family> {
    if protocol.ends_with('4') {
        Some(Family::V4)
    } else if protocol.ends_with('6') {
        Some(Family::V6)
    } else {
        None
    }
}

/// `newDataChannelSession`: one resolved address per attempt, plus the
/// session codec and MSS clamp derived from the negotiated peer.
async fn establish(
    cfg: &Arc<OvpnConfig>,
    cursor: &Cursor,
) -> Result<(Session, mpsc::Receiver<Result<Vec<u8>, String>>), EstablishError> {
    let remote = &cfg.remotes[cursor.remote_index % cfg.remotes.len()];
    let protocol = if remote.protocol.is_empty() {
        cfg.global_protocol.clone()
    } else {
        remote.protocol.clone()
    };
    let resolved = match resolve_host_all(&remote.host, remote.port).await {
        Ok(resolved) => resolved,
        Err(e) => {
            return Err(EstablishError::Retry(format!(
                "resolve {}: {e}",
                remote.host
            )));
        }
    };
    let resolved: Vec<SocketAddr> = match protocol_family(&protocol) {
        Some(family) => resolved
            .into_iter()
            .filter(|addr| family.matches(addr))
            .collect(),
        None => resolved,
    };
    let Some(dst) = resolved.get(cursor.address_index).copied() else {
        return Err(EstablishError::Exhausted(
            "remote address list exhausted".to_string(),
        ));
    };
    let (writer, readers, frames) = if protocol.starts_with("tcp") {
        let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(dst)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(EstablishError::Retry(format!("connect {dst}: {e}")));
            }
            Err(_) => {
                return Err(EstablishError::Retry(format!("connect {dst}: timeout")));
            }
        };
        let _ = stream.set_nodelay(true);
        let (read, write) = stream.into_split();
        let (tx, rx) = mpsc::channel(REPLY_QUEUE);
        (Writer::Tcp(write), vec![spawn_tcp_reader(read, tx)], rx)
    } else if protocol.starts_with("udp") {
        let bind: SocketAddr = if dst.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let sock = match UdpSocket::bind(bind).await {
            Ok(sock) => sock,
            Err(e) => {
                return Err(EstablishError::Retry(format!("bind {bind}: {e}")));
            }
        };
        if let Err(e) = sock.connect(dst).await {
            return Err(EstablishError::Retry(format!("connect {dst}: {e}")));
        }
        let sock = Arc::new(sock);
        let (tx, rx) = mpsc::channel(REPLY_QUEUE);
        (
            Writer::Udp(Arc::clone(&sock)),
            vec![spawn_udp_reader(sock, tx)],
            rx,
        )
    } else {
        return Err(EstablishError::Terminal(format!(
            "unsupported openvpn protocol {protocol}"
        )));
    };
    let material = match load_static_key_material(
        cfg.material_content.as_deref(),
        cfg.material_path.as_deref(),
    ) {
        Ok(material) => material,
        Err(e) => {
            return Err(EstablishError::Terminal(format!(
                "client session configuration error: {e}"
            )));
        }
    };
    let codec = match StaticCodec::new(
        &material,
        cfg.key_direction,
        &cfg.cipher,
        &cfg.auth,
        cfg.replay_window_size,
        cfg.replay_window_time,
    ) {
        Ok(codec) => codec,
        Err(e) => {
            return Err(EstablishError::Terminal(format!(
                "client session configuration error: {e}"
            )));
        }
    };
    let clamp = calculate_mss_clamp(
        cfg.mss_fix,
        &cfg.mss_fix_mode,
        FRAMING_OVERHEAD,
        |payload_length| codec.encoded_length(payload_length),
        transport_header_size(&protocol),
        outer_transport_overhead(&protocol, dst.is_ipv6()),
    );
    let now = Instant::now();
    Ok((
        Session {
            writer,
            codec,
            clamp,
            protocol,
            remote: dst,
            ping_interval: cfg.ping_interval,
            ping_restart: cfg.ping_restart,
            last_in: now,
            last_out: now,
            readers,
        },
        frames,
    ))
}

/// Feed complete data-channel frames (TCP framing already stripped) to the
/// session; `Err` ends the session with the given reason.
fn spawn_udp_reader(
    sock: Arc<UdpSocket>,
    frames: mpsc::Sender<Result<Vec<u8>, String>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match sock.recv(&mut buf).await {
                Ok(n) => {
                    if frames.send(Ok(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    drop(frames.send(Err(e.to_string())));
                    break;
                }
            }
        }
    })
}

/// `proto/connection.go ReadPackets`: 2-byte big-endian length prefix, only
/// length 0 is invalid.
fn spawn_tcp_reader(
    mut read: OwnedReadHalf,
    frames: mpsc::Sender<Result<Vec<u8>, String>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; SCRATCH_BUF];
        let mut pending: Vec<u8> = Vec::new();
        loop {
            match read.read(&mut buf).await {
                Ok(0) => {
                    drop(frames.send(Err("connection closed".to_string())));
                    break;
                }
                Ok(n) => {
                    pending.extend_from_slice(&buf[..n]);
                    let extracted = match extract_tcp_frames(&mut pending) {
                        Ok(extracted) => extracted,
                        Err(e) => {
                            drop(frames.send(Err(e)));
                            break;
                        }
                    };
                    let mut closed = false;
                    for frame in extracted {
                        if frames.send(Ok(frame)).await.is_err() {
                            closed = true;
                            break;
                        }
                    }
                    if closed {
                        break;
                    }
                }
                Err(e) => {
                    drop(frames.send(Err(format!("read: {e}"))));
                    break;
                }
            }
        }
    })
}

fn extract_tcp_frames(buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
    let mut frames = Vec::new();
    loop {
        if buffer.len() < 2 {
            return Ok(frames);
        }
        let length = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
        if length == 0 {
            return Err("bad encapsulated packet length from peer".to_string());
        }
        if buffer.len() < 2 + length {
            return Ok(frames);
        }
        frames.push(buffer[2..2 + length].to_vec());
        buffer.drain(..2 + length);
    }
}

enum PumpStop {
    Shutdown,
    Failed(String),
}

/// Keepalive deadline: upstream re-evaluates at least every read deadline.
fn pump_deadline(stack: &Stack, sess: &Session) -> Instant {
    let now = Instant::now();
    let mut best = now + READ_TICK;
    if sess.ping_restart > Duration::ZERO {
        best = best.min(sess.last_in + sess.ping_restart);
    }
    if sess.ping_interval > Duration::ZERO {
        best = best.min(sess.last_out + sess.ping_interval);
    }
    if !stack.tcp.is_empty() {
        best = best.min(now + TCP_TICK);
    }
    best
}

/// `client_session_static.go`: one established data channel session.
async fn pump_session(
    stack: &mut Stack,
    sess: &mut Session,
    frames: &mut mpsc::Receiver<Result<Vec<u8>, String>>,
    rx: &mut mpsc::Receiver<Cmd>,
) -> PumpStop {
    loop {
        while let Ok(cmd) = rx.try_recv() {
            stack.process_cmd(cmd, sess);
        }
        stack.poll_stack();
        stack.collect_wire(sess);
        if let Err(e) = stack.flush_wire(sess).await {
            return PumpStop::Failed(e);
        }
        stack.maintain_tcp();
        let deadline = tokio::time::Instant::from_std(pump_deadline(stack, sess));
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(cmd) => stack.process_cmd(cmd, sess),
                None => return PumpStop::Shutdown,
            },
            frame = frames.recv() => match frame {
                None => return PumpStop::Shutdown,
                Some(Err(e)) => return PumpStop::Failed(e),
                Some(Ok(frame)) => {
                    if let Err(e) = stack.handle_packet(sess, &frame) {
                        return PumpStop::Failed(e);
                    }
                }
            },
            _ = tokio::time::sleep_until(deadline) => {
                let now = Instant::now();
                if sess.ping_restart > Duration::ZERO
                    && now.duration_since(sess.last_in) >= sess.ping_restart
                {
                    return PumpStop::Failed("ping-restart timeout".to_string());
                }
                if sess.ping_interval > Duration::ZERO
                    && now.duration_since(sess.last_out) >= sess.ping_interval
                {
                    match sess.codec.encode_next(&PING_PAYLOAD) {
                        Ok(frame) => {
                            if let Err(e) = sess.write_wire(&frame).await {
                                logging::debug(format_args!(
                                    "openvpn[{}]: keepalive ping: {e}",
                                    stack.cfg.tag
                                ));
                            }
                            // Upstream clears the pending ping after one
                            // attempt; the 1s read deadline paces retries.
                            sess.last_out = Instant::now();
                        }
                        Err(e) => {
                            logging::warn(format_args!(
                                "openvpn[{}]: keepalive encode: {e}",
                                stack.cfg.tag
                            ));
                        }
                    }
                }
            }
        }
    }
}

/// `client_supervisor.go`: establish, pump, wait, double the backoff.
async fn run(
    cfg: OvpnConfig,
    mut rx: mpsc::Receiver<Cmd>,
    ready: Arc<AtomicBool>,
) -> io::Result<()> {
    let tag = cfg.tag.clone();
    let cfg = Arc::new(cfg);
    let mut stack = Stack::new(Arc::clone(&cfg))?;
    let mut cursor = Cursor::default();
    let mut backoff = BACKOFF_INITIAL;
    loop {
        match establish(&cfg, &cursor).await {
            Ok((mut session, mut frames)) => {
                ready.store(true, Ordering::Release);
                backoff = BACKOFF_INITIAL;
                stack.reset_sessions();
                logging::info(format_args!(
                    "openvpn[{tag}]: tunnel established to {} over {}",
                    session.remote, session.protocol
                ));
                let stop = pump_session(&mut stack, &mut session, &mut frames, &mut rx).await;
                ready.store(false, Ordering::Release);
                match stop {
                    PumpStop::Shutdown => return Ok(()),
                    PumpStop::Failed(e) => {
                        logging::warn(format_args!(
                            "openvpn[{tag}]: session with {} ended: {e}",
                            session.remote
                        ));
                        advance_cursor(&mut cursor, Advance::Stay, cfg.remotes.len());
                    }
                }
            }
            Err(e) => {
                let (message, advance) = match e {
                    EstablishError::Terminal(message) => return Err(io::Error::other(message)),
                    EstablishError::Exhausted(message) => (message, Advance::NextRemote),
                    EstablishError::Retry(message) => (message, Advance::NextAddress),
                };
                logging::warn(format_args!(
                    "openvpn[{tag}]: session with {} failed: {message}",
                    cfg.remotes[cursor.remote_index % cfg.remotes.len()].host
                ));
                advance_cursor(&mut cursor, advance, cfg.remotes.len());
            }
        }
        if !wait_backoff(&mut rx, backoff).await {
            return Ok(());
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Sleep out the backoff while rejecting new sessions; `false` = shutdown.
async fn wait_backoff(rx: &mut mpsc::Receiver<Cmd>, backoff: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + backoff;
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => return false,
                Some(cmd) => reject_cmd(cmd),
            },
            _ = tokio::time::sleep_until(deadline) => return true,
        }
    }
}

fn reject_cmd(cmd: Cmd) {
    let message = "openvpn: endpoint is not ready yet".to_string();
    match cmd {
        Cmd::TcpConnect { resp, .. } => {
            let _ = resp.send(Err(message));
        }
        Cmd::UdpOpen { resp, .. } => {
            let _ = resp.send(Err(message));
        }
        Cmd::TcpData { .. } | Cmd::TcpClose { .. } | Cmd::UdpSend { .. } | Cmd::UdpClose { .. } => {
        }
    }
}

// ---------------------------------------------------------------------------
// virtual device + smoltcp stack
// ---------------------------------------------------------------------------

struct OvpnDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl OvpnDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

struct OvpnRxToken {
    buffer: Vec<u8>,
}

impl PhyRxToken for OvpnRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct OvpnTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl PhyTxToken for OvpnTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for OvpnDevice {
    type RxToken<'a> = OvpnRxToken;
    type TxToken<'a> = OvpnTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(move |buffer| {
            let rx = OvpnRxToken { buffer };
            let tx = OvpnTxToken {
                queue: &mut self.tx,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(OvpnTxToken {
            queue: &mut self.tx,
        })
    }
}

struct TcpConn {
    handle: SocketHandle,
    to_caller: mpsc::Sender<Vec<u8>>,
    resp: Option<oneshot::Sender<Result<(), String>>>,
    from_caller: VecDeque<Vec<u8>>,
    stash: Option<Vec<u8>>,
    created: Instant,
    caller_eof: bool,
}

struct UdpSess {
    target: SocketAddr,
    to_caller: mpsc::Sender<Vec<u8>>,
}

struct Stack {
    cfg: Arc<OvpnConfig>,
    device: OvpnDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<u32, TcpConn>,
    udp: HashMap<u16, UdpSess>,
    next_port: u16,
    scratch: Vec<u8>,
    /// encoded data-channel packets waiting for the transport.
    pending: VecDeque<Vec<u8>>,
}

impl Stack {
    fn new(cfg: Arc<OvpnConfig>) -> io::Result<Self> {
        let mut device = OvpnDevice::new(cfg.mtu);
        let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
        iconfig.random_seed = u64::from_le_bytes(seed);
        let mut iface = Interface::new(iconfig, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|list| {
            for cidr in &cfg.local_cidrs {
                let _ = list.push(*cidr);
            }
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);
        Ok(Self {
            cfg,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            next_port: EPHEMERAL_BASE,
            scratch: vec![0u8; SCRATCH_BUF],
            pending: VecDeque::new(),
        })
    }

    /// A fresh data-channel session invalidates every inner connection.
    fn reset_sessions(&mut self) {
        let handles: Vec<SocketHandle> = self.tcp.values().map(|c| c.handle).collect();
        for handle in handles {
            self.sockets.remove(handle);
        }
        self.tcp.clear();
        self.udp.clear();
        self.pending.clear();
        self.device.rx.clear();
        self.device.tx.clear();
    }

    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == u16::MAX {
            EPHEMERAL_BASE
        } else {
            port + 1
        };
        port
    }

    fn process_cmd(&mut self, cmd: Cmd, sess: &mut Session) {
        match cmd {
            Cmd::TcpConnect {
                id,
                dst,
                to_caller,
                resp,
            } => {
                let IpAddr::V4(dst_ip) = dst.ip() else {
                    let _ = resp.send(Err("ipv6 target not supported".into()));
                    return;
                };
                let port = self.alloc_port();
                let mut socket = TcpSock::new(
                    TcpBuffer::new(vec![0; SOCKET_BUF]),
                    TcpBuffer::new(vec![0; SOCKET_BUF]),
                );
                socket.set_timeout(Some(SmolDuration::from_millis(
                    CONNECT_TIMEOUT.as_millis() as u64
                )));
                if let Err(e) = socket.connect(
                    self.iface.context(),
                    (IpAddress::from(dst_ip), dst.port()),
                    port,
                ) {
                    let _ = resp.send(Err(format!("openvpn connect: {e:?}")));
                    return;
                }
                let handle = self.sockets.add(socket);
                self.tcp.insert(
                    id,
                    TcpConn {
                        handle,
                        to_caller,
                        resp: Some(resp),
                        from_caller: VecDeque::new(),
                        stash: None,
                        created: Instant::now(),
                        caller_eof: false,
                    },
                );
            }
            Cmd::TcpData { id, bytes } => {
                let overflow = self.tcp.get(&id).is_some_and(|c| {
                    c.from_caller.iter().map(|b| b.len()).sum::<usize>() + bytes.len()
                        > EGRESS_BUF_MAX
                });
                if overflow {
                    if let Some(c) = self.tcp.remove(&id) {
                        self.sockets.remove(c.handle);
                        if let Some(resp) = c.resp {
                            let _ = resp.send(Err("outbound buffer overflow".into()));
                        }
                        drop(c.to_caller);
                    }
                    return;
                }
                if let Some(c) = self.tcp.get_mut(&id) {
                    c.from_caller.push_back(bytes);
                }
            }
            Cmd::TcpClose { id } => {
                if let Some(c) = self.tcp.get_mut(&id) {
                    c.caller_eof = true;
                    c.from_caller.clear();
                }
            }
            Cmd::UdpOpen { target, resp } => {
                let IpAddr::V4(target_ip) = target.ip() else {
                    let _ = resp.send(Err("ipv6 target not supported".into()));
                    return;
                };
                let _ = target_ip;
                let port = self.alloc_port();
                let (tx, rx) = mpsc::channel(REPLY_QUEUE);
                self.udp.insert(
                    port,
                    UdpSess {
                        target,
                        to_caller: tx,
                    },
                );
                let _ = resp.send(Ok((port, rx)));
            }
            Cmd::UdpSend { port, bytes } => {
                let Some(session) = self.udp.get(&port) else {
                    return;
                };
                let target = session.target;
                let IpAddr::V4(target_ip) = target.ip() else {
                    return;
                };
                let packet =
                    build_ipv4_udp(self.cfg.local_addr, target_ip, port, target.port(), &bytes);
                self.enqueue_packet(sess, packet);
            }
            Cmd::UdpClose { port } => {
                self.udp.remove(&port);
            }
        }
    }

    /// `dataCodec.Encode` + `mssFixup`; errors drop the packet.
    fn enqueue_packet(&mut self, sess: &mut Session, mut packet: Vec<u8>) {
        sess.clamp.apply_in_place(&mut packet);
        match sess.codec.encode_next(&packet) {
            Ok(frame) => self.pending.push_back(frame),
            Err(e) => {
                logging::warn(format_args!(
                    "openvpn[{}]: encode data packet: {e}",
                    self.cfg.tag
                ));
            }
        }
    }

    fn collect_wire(&mut self, sess: &mut Session) {
        while let Some(packet) = self.device.tx.pop_front() {
            if self.cfg.block_ipv6 && packet.first().is_some_and(|b| b >> 4 == 6) {
                continue;
            }
            self.enqueue_packet(sess, packet);
        }
    }

    /// UDP write errors are dropped; a TCP write error ends the session.
    async fn flush_wire(&mut self, sess: &mut Session) -> Result<(), String> {
        while let Some(frame) = self.pending.pop_front() {
            if let Err(e) = sess.write_wire(&frame).await {
                if sess.writer.is_tcp() {
                    return Err(e.to_string());
                }
                logging::debug(format_args!("openvpn[{}]: udp send: {e}", self.cfg.tag));
            }
        }
        Ok(())
    }

    /// `handleIncomingDataPayloads`: decode, keepalive filtering, clamp, demux.
    fn handle_packet(&mut self, sess: &mut Session, frame: &[u8]) -> Result<(), String> {
        let (_packet_id, mut payload) = match sess.codec.decode(frame) {
            Ok(decoded) => decoded,
            Err(e) => {
                // proto/connection.go: TCP treats it as fatal, UDP drops it.
                if sess.writer.is_tcp() {
                    return Err(format!("fatal decryption error: {e}"));
                }
                return Ok(());
            }
        };
        sess.last_in = Instant::now();
        if payload.is_empty() || payload == PING_PAYLOAD {
            return Ok(());
        }
        sess.clamp.apply_in_place(&mut payload);
        if self.cfg.block_ipv6 && payload.first().is_some_and(|b| b >> 4 == 6) {
            return Ok(());
        }
        if let Some((src, dst, proto, hdr_len)) = ipv4_info(&payload) {
            if proto == 17 && dst == self.cfg.local_addr && payload.len() >= hdr_len + 8 {
                let sport = u16::from_be_bytes([payload[hdr_len], payload[hdr_len + 1]]);
                let dport = u16::from_be_bytes([payload[hdr_len + 2], payload[hdr_len + 3]]);
                if let Some(session) = self.udp.get(&dport)
                    && session.target.ip() == IpAddr::V4(src)
                    && (session.target.port() == sport || session.target.port() == 0)
                {
                    let _ = session.to_caller.try_send(payload[hdr_len + 8..].to_vec());
                    return Ok(());
                }
            }
            if dst != self.cfg.local_addr {
                return Ok(());
            }
        }
        self.device.rx.push_back(payload);
        Ok(())
    }

    fn maintain_tcp(&mut self) {
        let ids: Vec<u32> = self.tcp.keys().copied().collect();
        for id in ids {
            let Some(mut conn) = self.tcp.remove(&id) else {
                continue;
            };
            let mut rbuf = std::mem::take(&mut self.scratch);
            let mut remote_closed = false;
            let mut caller_gone = false;
            let state = {
                let sock = self.sockets.get_mut::<TcpSock<'static>>(conn.handle);
                while let Some(front) = conn.from_caller.front_mut() {
                    match sock.send_slice(front) {
                        Ok(0) => break,
                        Ok(n) if n >= front.len() => {
                            conn.from_caller.pop_front();
                        }
                        Ok(n) => {
                            let rest = front.split_off(n);
                            *front = rest;
                        }
                        Err(_) => {
                            conn.from_caller.clear();
                            break;
                        }
                    }
                }
                if conn.stash.is_none() {
                    loop {
                        match sock.recv_slice(&mut rbuf) {
                            Ok(0) => break,
                            Ok(n) => match conn.to_caller.try_send(rbuf[..n].to_vec()) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(v)) => {
                                    conn.stash = Some(v);
                                    break;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    caller_gone = true;
                                    break;
                                }
                            },
                            Err(TcpRecvError::InvalidState) => break,
                            Err(TcpRecvError::Finished) => {
                                remote_closed = true;
                                break;
                            }
                        }
                    }
                }
                sock.state()
            };
            self.scratch = rbuf;

            if let Some(stash) = conn.stash.take() {
                match conn.to_caller.try_send(stash) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(v)) => conn.stash = Some(v),
                    Err(mpsc::error::TrySendError::Closed(_)) => caller_gone = true,
                }
            }
            if conn.to_caller.is_closed() {
                caller_gone = true;
            }

            if state == TcpState::Established
                && let Some(resp) = conn.resp.take()
            {
                let _ = resp.send(Ok(()));
                self.sockets
                    .get_mut::<TcpSock<'static>>(conn.handle)
                    .set_timeout(None);
            }

            let connect_failed = conn.resp.is_some()
                && (state == TcpState::Closed || conn.created.elapsed() >= CONNECT_TIMEOUT);
            let finished = state == TcpState::Closed
                || caller_gone
                || (conn.caller_eof && remote_closed && conn.stash.is_none());

            if connect_failed && let Some(resp) = conn.resp.take() {
                let _ = resp.send(Err(match state {
                    TcpState::Closed => "connection reset".to_string(),
                    _ => "connect timeout".to_string(),
                }));
            }
            if finished {
                if let Some(resp) = conn.resp.take() {
                    let _ = resp.send(Err("connection closed".into()));
                }
                self.sockets.remove(conn.handle);
            } else {
                self.tcp.insert(id, conn);
            }
        }
    }

    fn poll_stack(&mut self) -> PollResult {
        let now = SmolInstant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets)
    }
}

// ---------------------------------------------------------------------------
// address resolution + packet helpers
// ---------------------------------------------------------------------------

async fn resolve_host_all(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<IpAddr> = if let Some(dns) = crate::dns::current() {
        match crate::dns::default_domain_resolver() {
            Some(tag) => dns.resolve_via(&tag, host).await?,
            None => dns.resolve(host).await?,
        }
    } else {
        tokio::net::lookup_host((host, port))
            .await?
            .map(|addr| addr.ip())
            .collect()
    };
    if addrs.is_empty() {
        return Err(io::Error::other(format!("no address for {host}")));
    }
    Ok(addrs
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            let addrs = resolve_host_all(host, *port).await?;
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| io::Error::other(format!("no address for {host}")))
        }
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wrap a payload into an IPv4/UDP packet (UDP checksum stays zero — legal
/// for IPv4).
fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        64,
        17,
        0x00,
        0x00,
    ]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let csum = ipv4_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = csum as u8;
    let ulen = 8 + payload.len();
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

/// Parse an IPv4 packet header: `(src, dst, protocol, header_len)`.
fn ipv4_info(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, usize)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let hdr_len = (pkt[0] & 0x0f) as usize * 4;
    if hdr_len < 20 || pkt.len() < hdr_len {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst, pkt[9], hdr_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn static_key() -> String {
        "K".repeat(256)
    }

    fn ovpn_obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "openvpn-client",
            "tag": "ovpn",
            "mode": "static_key",
            "server": "vpn.example.com",
            "server_port": 1194,
            "address": ["10.8.0.2/24"],
            "peer_address": "10.8.0.1",
            "cipher": "AES-256-CBC",
            "static_key": static_key(),
        });
        let map = base.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("object") {
            map.insert(key.clone(), value.clone());
        }
        map.clone()
    }

    fn build(obj: &Map<String, Value>) -> anyhow::Result<OpenVpn> {
        OpenVpn::build(obj, "endpoints[0]")
    }

    #[test]
    fn build_accepts_minimal_static_key_endpoint() {
        let ovpn = build(&ovpn_obj(json!({}))).expect("build");
        assert_eq!(ovpn.cfg.remotes.len(), 1);
        assert_eq!(ovpn.cfg.remotes[0].host, "vpn.example.com");
        assert_eq!(ovpn.cfg.remotes[0].port, 1194);
        // `network` defaults to udp
        assert_eq!(ovpn.cfg.global_protocol, "udp");
        assert_eq!(ovpn.cfg.local_addr, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(ovpn.cfg.key_direction, -1);
        // reference MSS defaulting: no mtu → 1492/mtu
        assert_eq!(ovpn.cfg.mss_fix, 1492);
        assert_eq!(ovpn.cfg.mss_fix_mode, mss::MSS_FIX_MODE_MTU);
        assert_eq!(ovpn.cfg.replay_window_size, 0);
        assert_eq!(ovpn.cfg.replay_window_time, Duration::from_secs(15));
        assert_eq!(ovpn.cfg.ping_interval, Duration::ZERO);
        assert_eq!(ovpn.cfg.ping_restart, Duration::ZERO);
    }

    #[test]
    fn build_rejects_tls_mode_and_system() {
        let err = build(&ovpn_obj(json!({"mode": "tls"})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: openvpn mode tls is not implemented yet");
        let err = build(&ovpn_obj(json!({"system": true})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: system openvpn is not implemented yet");
    }

    #[test]
    fn build_requires_exactly_one_remote_source() {
        let err = build(&ovpn_obj(json!({"server": ""})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: missing `server` or `servers`");
        let err = build(&ovpn_obj(
            json!({"servers": [{"server": "b.example.com", "server_port": 443}]}),
        ))
        .unwrap_err()
        .to_string();
        assert_eq!(err, "endpoints[0]: `server` is conflict with `servers`");
    }

    #[test]
    fn build_reads_servers_entries() {
        let ovpn = build(&ovpn_obj(json!({
            "server": "",
            "network": "tcp",
            "servers": [
                {"server": "a.example.com", "server_port": 443},
                {"server": "b.example.com", "server_port": 1195, "network": "udp"},
            ],
        })))
        .expect("build");
        assert_eq!(ovpn.cfg.remotes.len(), 2);
        assert_eq!(ovpn.cfg.remotes[0].port, 443);
        assert_eq!(ovpn.cfg.remotes[0].protocol, "");
        assert_eq!(ovpn.cfg.remotes[1].protocol, "udp");
        assert_eq!(ovpn.cfg.global_protocol, "tcp");
    }

    #[test]
    fn build_rejects_invalid_remotes() {
        let err = build(&ovpn_obj(json!({"server_port": 0})))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "endpoints[0]: option is not supported yet: empty remote port at index 0"
        );
        let err = build(&ovpn_obj(json!({"server": "bad host"})))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "endpoints[0]: option is not supported yet: invalid remote host at index 0"
        );
        let err = build(&ovpn_obj(json!({"network": "sctp"})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: unsupported openvpn protocol");
        let err = build(&ovpn_obj(json!({"server_port": 70000})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: invalid remote port 70000 at index 0");
    }

    #[test]
    fn build_requires_ipv4_tunnel_address() {
        let err = build(&ovpn_obj(json!({"address": []})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: missing ipv4 address");
        let err = build(&ovpn_obj(json!({"address": ["nonsense"]})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: `address[0]` is invalid");
    }

    #[test]
    fn build_accepts_bare_address() {
        let ovpn = build(&ovpn_obj(json!({"address": ["10.9.0.5"]}))).expect("build");
        assert_eq!(ovpn.cfg.local_addr, Ipv4Addr::new(10, 9, 0, 5));
        assert_eq!(ovpn.cfg.local_cidrs[0].prefix_len(), 32);
    }

    #[test]
    fn build_material_sources() {
        let err = build(&ovpn_obj(json!({"static_key_path": "/tmp/k"})))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "endpoints[0]: material path and content are both set: static_key"
        );
        let mut obj = ovpn_obj(json!({}));
        obj.remove("static_key");
        let err = build(&obj).unwrap_err().to_string();
        assert_eq!(
            err,
            "endpoints[0]: missing `static_key` or `static_key_path`"
        );
    }

    #[test]
    fn build_key_direction_table() {
        for (value, expected) in [("", -1), ("server", 0), ("client", 1)] {
            let ovpn = build(&ovpn_obj(json!({"key_direction": value}))).expect("build");
            assert_eq!(ovpn.cfg.key_direction, expected);
        }
        let err = build(&ovpn_obj(json!({"key_direction": "both"})))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "endpoints[0]: unsupported key direction: both (expected \"server\" or \"client\")"
        );
    }

    #[test]
    fn build_data_channel_names() {
        let mut obj = ovpn_obj(json!({}));
        obj.remove("cipher");
        let err = build(&obj).unwrap_err().to_string();
        assert_eq!(
            err,
            "endpoints[0]: ClientOptions.DataChannel.Cipher is required in static_key mode"
        );
        let err = build(&ovpn_obj(json!({"cipher": "CHACHA20"})))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "endpoints[0]: ClientOptions.DataChannel.Cipher is not supported in static_key mode: CHACHA20"
        );
        let err = build(&ovpn_obj(json!({"auth": "SHA3"})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: unsupported static key auth");
    }

    #[test]
    fn build_rejects_wire_framing_features() {
        for value in ["stub", "lzo", "lz4", "stub-v2", "lz4-v2", "yes"] {
            let err = build(&ovpn_obj(json!({"compression": value})))
                .unwrap_err()
                .to_string();
            assert_eq!(
                err, "endpoints[0]: openvpn compression is not implemented yet",
                "{value}"
            );
        }
        for value in ["none", "no", "disabled", "off", "migrate"] {
            build(&ovpn_obj(json!({"compression": value})))
                .unwrap_or_else(|e| panic!("{value}: {e}"));
        }
        // comp-lzo "no" means stub in upstream, so it also needs framing
        for value in ["adaptive", "yes", "asym", "no"] {
            let err = build(&ovpn_obj(json!({"compression_lzo": value})))
                .unwrap_err()
                .to_string();
            assert_eq!(
                err, "endpoints[0]: openvpn compression is not implemented yet",
                "{value}"
            );
        }
        let err = build(&ovpn_obj(json!({"fragment": 1300})))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "endpoints[0]: openvpn fragment is not implemented yet");
    }

    #[test]
    fn build_mss_defaulting_matches_reference() {
        // explicit mss_fix keeps the user mode untouched
        let ovpn = build(&ovpn_obj(json!({"mss_fix": 1300}))).expect("build");
        assert_eq!(
            (ovpn.cfg.mss_fix, ovpn.cfg.mss_fix_mode.as_str()),
            (1300, "")
        );
        // mtu 1500 → 1492/mtu
        let ovpn = build(&ovpn_obj(json!({"mtu": 1500}))).expect("build");
        assert_eq!(
            (ovpn.cfg.mss_fix, ovpn.cfg.mss_fix_mode.as_str()),
            (1492, "mtu")
        );
        // other mtu → fixed
        let ovpn = build(&ovpn_obj(json!({"mtu": 1400}))).expect("build");
        assert_eq!(
            (ovpn.cfg.mss_fix, ovpn.cfg.mss_fix_mode.as_str()),
            (1400, "fixed")
        );
        // disabled
        let ovpn = build(&ovpn_obj(json!({"mss_fix_disabled": true}))).expect("build");
        assert_eq!(ovpn.cfg.mss_fix, 0);
        // device MTU still defaults to 1500
        assert_eq!(
            build(&ovpn_obj(json!({}))).expect("build").cfg.mtu,
            DEFAULT_MTU
        );
        assert_eq!(
            build(&ovpn_obj(json!({"mtu": 1400})))
                .expect("build")
                .cfg
                .mtu,
            1400
        );
    }

    #[test]
    fn build_durations_and_timeouts() {
        let ovpn = build(&ovpn_obj(json!({
            "ping_interval": "10s",
            "ping_restart": "60s",
            "replay_window": 128,
            "udp_timeout": "30s",
        })))
        .expect("build");
        assert_eq!(ovpn.cfg.ping_interval, Duration::from_secs(10));
        assert_eq!(ovpn.cfg.ping_restart, Duration::from_secs(60));
        assert_eq!(ovpn.cfg.replay_window_size, 128);
        assert_eq!(ovpn.cfg.udp_timeout, Duration::from_secs(30));
        // nanosecond numbers are accepted like the other duration options
        let ovpn = build(&ovpn_obj(json!({"ping_interval": 5_000_000_000u64}))).expect("build");
        assert_eq!(ovpn.cfg.ping_interval, Duration::from_secs(5));
        // ping_restart_disabled wins over the value
        let ovpn = build(&ovpn_obj(json!({
            "ping_restart": 0,
            "ping_restart_disabled": true,
        })))
        .expect("build");
        assert_eq!(ovpn.cfg.ping_restart, Duration::ZERO);
    }

    #[test]
    fn build_randomizes_remote_order() {
        let servers = json!([
            {"server": "a.example.com", "server_port": 1194},
            {"server": "b.example.com", "server_port": 1194},
            {"server": "c.example.com", "server_port": 1194},
        ]);
        let mut shuffled = false;
        for _ in 0..16 {
            let ovpn = build(&ovpn_obj(json!({
                "server": "",
                "servers": servers.clone(),
                "remote_random": true,
            })))
            .expect("build");
            let order: Vec<&str> = ovpn
                .cfg
                .remotes
                .iter()
                .map(|remote| remote.host.as_str())
                .collect();
            assert_eq!(order.len(), 3);
            if order[0] != "a.example.com" {
                shuffled = true;
            }
        }
        assert!(shuffled, "remote_random never reordered the remotes");
    }

    #[test]
    fn cursor_advances_like_the_reference() {
        let mut cursor = Cursor::default();
        assert_eq!((cursor.remote_index, cursor.address_index), (0, 0));
        advance_cursor(&mut cursor, Advance::NextAddress, 2);
        assert_eq!((cursor.remote_index, cursor.address_index), (0, 1));
        // session became ready: stay on the same peer
        advance_cursor(&mut cursor, Advance::Stay, 2);
        assert_eq!((cursor.remote_index, cursor.address_index), (0, 1));
        // address list exhausted: rotate the remote and restart the index
        advance_cursor(&mut cursor, Advance::NextRemote, 2);
        assert_eq!((cursor.remote_index, cursor.address_index), (1, 0));
        advance_cursor(&mut cursor, Advance::NextRemote, 2);
        assert_eq!((cursor.remote_index, cursor.address_index), (0, 0));
    }

    #[test]
    fn tcp_framing_matches_reference() {
        // one frame plus a partial header
        let mut buffer = vec![0, 3, 1, 2, 3, 9];
        let frames = extract_tcp_frames(&mut buffer).expect("frames");
        assert_eq!(frames, vec![vec![1, 2, 3]]);
        assert_eq!(buffer, vec![9]);

        // two frames in one read, fully consumed
        let mut buffer = vec![0, 2, 7, 8, 0, 1, 42];
        let frames = extract_tcp_frames(&mut buffer).expect("frames");
        assert_eq!(frames, vec![vec![7, 8], vec![42]]);
        assert!(buffer.is_empty());

        // partial frame body stays buffered
        let mut buffer = vec![0, 4, 1, 2];
        let frames = extract_tcp_frames(&mut buffer).expect("frames");
        assert!(frames.is_empty());
        assert_eq!(buffer, vec![0, 4, 1, 2]);

        // only length 0 is invalid
        let mut buffer = vec![0, 0];
        assert_eq!(
            extract_tcp_frames(&mut buffer).unwrap_err(),
            "bad encapsulated packet length from peer"
        );
    }

    #[test]
    fn protocol_family_suffix() {
        assert!(matches!(protocol_family("udp4"), Some(Family::V4)));
        assert!(matches!(protocol_family("tcp6"), Some(Family::V6)));
        assert!(protocol_family("udp").is_none());
        assert!(protocol_family("tcp").is_none());
    }

    #[test]
    fn ipv4_udp_wrapper_and_parser() {
        let packet = build_ipv4_udp(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            40000,
            53,
            b"query",
        );
        assert_eq!(packet.len(), 20 + 8 + 5);
        let (src, dst, proto, hdr_len) = ipv4_info(&packet).expect("header");
        assert_eq!(src, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(dst, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(proto, 17);
        assert_eq!(hdr_len, 20);
        assert_eq!(&packet[hdr_len + 8..], b"query", "payload offset");
        assert_eq!(ipv4_info(&packet[..10]), None);
        assert_eq!(ipv4_info(&[0x60; 40]), None);
    }

    #[test]
    fn listable_join_and_key_direction() {
        assert_eq!(listable_join(None), "");
        assert_eq!(listable_join(Some(&json!("abc"))), "abc");
        assert_eq!(listable_join(Some(&json!(["a", "b"]))), "a\nb");
        assert_eq!(listable_join(Some(&json!(7))), "");
        assert_eq!(key_direction_value("").unwrap(), -1);
        assert_eq!(key_direction_value("server").unwrap(), 0);
        assert_eq!(key_direction_value("client").unwrap(), 1);
        assert!(key_direction_value("Server").is_err());
    }

    #[test]
    fn secure_index_stays_in_range() {
        for bound in [1usize, 2, 7, 64] {
            for _ in 0..32 {
                assert!(secure_index(bound).expect("index") < bound);
            }
        }
    }
}
