//! MASQUE (Cloudflare WARP) CONNECT-IP outbound.
//!
//! Ports the reference sing-box-lx `protocol/masque` behavior: profiles
//! (cloudflare/standard), h3/h2/vhttp-auto legs, in-process smoltcp stack,
//! CONNECT-IP capsules with TTL/checksum translation and ICMP too-big.
//!
//! Protocol layers live in submodules: h3 (minimal HTTP/3 client),
//! h2 (manual framer), qpack / hpack (header block codecs),
//! connectip (capsules + packet rewrite), tls (pinning + mTLS),
//! huffman / static_tables (generated RFC tables).

#![allow(dead_code)]

mod connectip;
mod h2;
mod h3;
mod hpack;
mod huffman;
mod p256;
mod profile;
mod qpack;
pub(crate) mod stack;
mod static_tables;
mod tls;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::proxy::server_endpoint;
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::urltest::parse_duration;

use profile::{MasqueKeys, Profile, parse_keys, parse_profile};
use stack::{Cmd, Leg, StackCfg, run};
use tls::MasqueTls;

const AUTO_H3: u8 = 0;
const AUTO_H2: u8 = 1;

/// SPEC 074 — `vhttp: auto` waits this long for the h3 handshake before
/// falling back to h2.
const AUTO_H3_TIMEOUT: Duration = Duration::from_secs(3);

const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(30);
const DEFAULT_MTU: usize = 1280;
const MAX_H2_MTU: usize = 16000;

const CALLER_BUF: usize = 65_536;
const SCRATCH_BUF: usize = 16_384;
const CMD_QUEUE: usize = 256;
const REPLY_QUEUE: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Dialer fields accepted by check but not honored by the masque runtime.
const IGNORED_FIELDS: &[&str] = &[
    "detour",
    "bind_interface",
    "routing_mark",
    "domain_resolver",
    "connect_timeout",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "fallback_delay",
    "udp_fragment",
];

/// Runtime-side config (reference `NewOutbound` after `resolveLegacyOptions`).
#[derive(Debug)]
pub(crate) struct MasqueCfg {
    pub tag: String,
    pub server: (String, u16),
    pub uri: String,
    pub profile: Profile,
    pub keys: MasqueKeys,
    /// Legacy-folded outbound object, read by [`MasqueTls::new`].
    pub tls_obj: Map<String, Value>,
    /// Configured transport: `"h3"` | `"h2"` (auto resolves to h3 first).
    pub network: &'static str,
    pub auto_mode: bool,
    pub auto_h3_delay: Duration,
    pub mtu: usize,
    pub local_addr: Option<Ipv4Addr>,
    pub local_cidr: Option<IpCidr>,
    pub local_addr_v6: Option<Ipv6Addr>,
    pub local_cidr_v6: Option<IpCidr>,
    pub keep_alive: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub udp_timeout: Duration,
    pub allow_tcp: bool,
    pub allow_udp: bool,
}

/// Live stack task handle (one tunnel per outbound).
#[derive(Debug)]
struct MasqueShared {
    cmd_tx: mpsc::Sender<Cmd>,
    next_id: AtomicU32,
}

/// MASQUE CONNECT-IP outbound (see module docs).
#[derive(Debug)]
pub struct Masque {
    cfg: Arc<MasqueCfg>,
    shared: AsyncMutex<Option<Arc<MasqueShared>>>,
    /// `vhttp: auto` winner: 0 = h3, 1 = h2.
    auto_net: AtomicU8,
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

/// QUIC keep-alive: absent/zero = the 30s default, positive = the configured
/// value, negative = disabled (reference `NewOutbound`).
fn parse_keep_alive(value: Option<&Value>, at: &str) -> anyhow::Result<Option<Duration>> {
    match value {
        None | Some(Value::Null) => Ok(Some(DEFAULT_KEEP_ALIVE)),
        Some(Value::String(s)) if s.trim().starts_with('-') => {
            // Validate the syntax, then disable.
            let magnitude = s.trim().trim_start_matches('-');
            let _ = parse_duration(
                Some(&Value::String(magnitude.to_string())),
                Duration::ZERO,
                at,
            )?;
            Ok(None)
        }
        Some(v) => {
            let d = parse_duration(Some(v), DEFAULT_KEEP_ALIVE, at)?;
            Ok(Some(if d.is_zero() { DEFAULT_KEEP_ALIVE } else { d }))
        }
    }
}

/// Idle-suspend window: absent/null/non-positive = never (no global
/// `lx.masque.idle_timeout` in this runtime).
fn parse_idle_timeout(value: Option<&Value>, at: &str) -> anyhow::Result<Option<Duration>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().starts_with('-') => {
            let magnitude = s.trim().trim_start_matches('-');
            let _ = parse_duration(
                Some(&Value::String(magnitude.to_string())),
                Duration::ZERO,
                at,
            )?;
            Ok(None)
        }
        Some(v) => {
            let d = parse_duration(Some(v), Duration::ZERO, at)?;
            Ok((!d.is_zero()).then_some(d))
        }
    }
}

/// Fold the deprecated flat fields onto `vhttp` / `tls` (SPEC 062): an
/// explicit new value wins, a legacy value alone is honoured, disagreement is
/// a hard error.
fn fold_legacy(mut obj: Map<String, Value>, at: &str) -> anyhow::Result<Map<String, Value>> {
    let mut used_legacy = false;

    let legacy_network = get_str(&obj, "network").to_string();
    if !legacy_network.is_empty() {
        let vhttp = get_str(&obj, "vhttp").to_string();
        if !vhttp.is_empty() && vhttp != legacy_network {
            anyhow::bail!(
                "{at}: masque: `vhttp` is {vhttp} but deprecated `network` is {legacy_network} — remove `network`"
            );
        }
        if vhttp.is_empty() {
            obj.insert("vhttp".into(), Value::String(legacy_network));
        }
        used_legacy = true;
    }

    // Read every flat field first: the `tls` mutable borrow below must not
    // overlap an immutable borrow of `obj`.
    let legacy_sni = get_str(&obj, "sni").to_string();
    let legacy_ffd = get_str(&obj, "fragment_fallback_delay").to_string();
    let skip_cert_verify = obj.get("skip_cert_verify").and_then(Value::as_bool) == Some(true);
    let flat_bools = [
        ("fragment", "fragment"),
        ("record_fragment", "record_fragment"),
    ]
    .into_iter()
    .map(|(flat, tls_key)| {
        (
            obj.get(flat).and_then(Value::as_bool) == Some(true),
            tls_key,
        )
    })
    .collect::<Vec<_>>();

    // Ensure a `tls` object exists for the remaining folds.
    if !matches!(obj.get("tls"), Some(Value::Object(_))) {
        obj.insert("tls".into(), Value::Object(Map::new()));
    }
    let tls = obj
        .get_mut("tls")
        .and_then(Value::as_object_mut)
        .expect("tls object");

    if !legacy_sni.is_empty() {
        let server_name = tls
            .get("server_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !server_name.is_empty() && server_name != legacy_sni {
            anyhow::bail!(
                "{at}: masque: `tls.server_name` is {server_name} but deprecated `sni` is {legacy_sni} — remove `sni`"
            );
        }
        if server_name.is_empty() {
            tls.insert("server_name".into(), Value::String(legacy_sni));
        }
        used_legacy = true;
    }

    // The bool fields cannot tell absent from explicit false: a legacy true
    // simply wins (reference comment in legacy_options_lx.go).
    if skip_cert_verify {
        tls.insert("insecure".into(), Value::Bool(true));
        used_legacy = true;
    }

    for (present, tls_key) in flat_bools {
        if present {
            tls.insert(tls_key.into(), Value::Bool(true));
            used_legacy = true;
        }
    }

    if !legacy_ffd.is_empty() {
        let tls_ffd = tls
            .get("fragment_fallback_delay")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !tls_ffd.is_empty() && tls_ffd != legacy_ffd {
            anyhow::bail!(
                "{at}: masque: `tls.fragment_fallback_delay` and deprecated `fragment_fallback_delay` disagree — remove the latter"
            );
        }
        if tls_ffd.is_empty() {
            tls.insert("fragment_fallback_delay".into(), Value::String(legacy_ffd));
        }
        used_legacy = true;
    }

    if used_legacy {
        logging::warn(format_args!(
            "masque {at}: deprecated legacy fields are in use (network/sni/skip_cert_verify/fragment*)"
        ));
    }
    Ok(obj)
}

fn parse_masque_prefix(raw: &str, at: &str) -> anyhow::Result<IpCidr> {
    let full = if raw.contains('/') {
        raw.to_string()
    } else if raw.contains(':') {
        format!("{raw}/128")
    } else {
        format!("{raw}/32")
    };
    full.parse::<IpCidr>()
        .map_err(|_| anyhow::anyhow!("{at}: parse ip: invalid prefix {full:?}"))
}

impl Masque {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let profile_name = get_str(obj, "profile");
        let profile = parse_profile(profile_name).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;

        // Legacy folding first: a deprecated flat field can fill `uri` / SNI.
        let obj = fold_legacy(obj.clone(), at)?;

        // SPEC 091: the uri check runs before resolveVHTTP.
        let mut uri = get_str(&obj, "uri").to_string();
        if uri.is_empty() {
            uri = profile.default_uri.to_string();
        }
        if uri.is_empty() {
            anyhow::bail!(
                "{at}: masque: uri is required for the standard profile — set it to the server's CONNECT-IP request URI, e.g. https://<host>/.well-known/masque/ip/*/*/"
            );
        }

        let mut network = get_str(&obj, "vhttp").to_string();
        let explicit = !network.is_empty();
        if network.is_empty() {
            network = "auto".to_string();
        }
        if network != "h3" && network != "h2" && network != "auto" {
            anyhow::bail!("{at}: masque: invalid vhttp: {network} (expected h3, h2 or auto)");
        }
        let mut auto_mode = network == "auto";
        if auto_mode && profile_name == "standard" {
            if explicit {
                logging::warn(format_args!(
                    "masque {at}: `vhttp: auto` has no h2 fallback on the standard profile — using h3 only"
                ));
            }
            auto_mode = false;
            network = "h3".to_string();
        }
        if auto_mode {
            network = "h3".to_string();
        }
        if network == "h2" && profile_name == "standard" {
            anyhow::bail!("{at}: masque: vhttp h2 is not implemented for the standard profile");
        }
        let network: &'static str = if network == "h2" { "h2" } else { "h3" };

        let mtu = obj
            .get("mtu")
            .and_then(Value::as_u64)
            .filter(|m| *m != 0)
            .map(|m| m as usize)
            .unwrap_or(DEFAULT_MTU);
        if (network == "h2" || auto_mode) && mtu > MAX_H2_MTU {
            anyhow::bail!("{at}: masque: mtu {mtu} too large for h2 (max {MAX_H2_MTU})");
        }

        let ip_raw = get_str(&obj, "ip");
        let ipv6_raw = get_str(&obj, "ipv6");
        if ip_raw.is_empty() && ipv6_raw.is_empty() {
            anyhow::bail!("{at}: masque: at least one of ip/ipv6 is required");
        }
        let (local_addr, local_cidr) = if !ip_raw.is_empty() {
            let cidr = parse_masque_prefix(ip_raw, at)?;
            match cidr.address() {
                IpAddress::Ipv4(ip) => (Some(ip), Some(cidr)),
                _ => anyhow::bail!("{at}: invalid ipv4 prefix in `ip`"),
            }
        } else {
            (None, None)
        };
        let (local_addr_v6, local_cidr_v6) = if !ipv6_raw.is_empty() {
            let cidr = parse_masque_prefix(ipv6_raw, at)?;
            match cidr.address() {
                IpAddress::Ipv6(ip) => (Some(ip), Some(cidr)),
                _ => anyhow::bail!("{at}: invalid ipv6 prefix in `ipv6`"),
            }
        } else {
            (None, None)
        };

        let keys = parse_keys(&obj, &profile, at)?;

        let server = server_endpoint(&obj, at)?;
        let keep_alive = parse_keep_alive(obj.get("keep_alive_period"), at)?;
        let idle_timeout = parse_idle_timeout(obj.get("idle_timeout"), at)?;
        let (allow_tcp, allow_udp) = parse_network_list(obj.get("network_list"));

        for f in IGNORED_FIELDS {
            if obj
                .get(*f)
                .is_some_and(|v| !v.is_null() && *v != Value::Bool(false))
            {
                logging::warn(format_args!(
                    "masque {at}: {f} is not implemented yet (ignored)"
                ));
            }
        }
        for f in ["fragment", "record_fragment", "fragment_fallback_delay"] {
            if obj
                .get(f)
                .is_some_and(|v| !v.is_null() && *v != Value::Bool(false))
            {
                logging::warn(format_args!(
                    "masque {at}: {f} is not implemented yet (ignored)"
                ));
            }
        }

        Ok(Self {
            cfg: Arc::new(MasqueCfg {
                tag: at.to_string(),
                server,
                uri,
                profile,
                keys,
                tls_obj: obj,
                network,
                auto_mode,
                auto_h3_delay: AUTO_H3_TIMEOUT,
                mtu,
                local_addr,
                local_cidr,
                local_addr_v6,
                local_cidr_v6,
                keep_alive,
                idle_timeout,
                udp_timeout: DEFAULT_UDP_TIMEOUT,
                allow_tcp,
                allow_udp,
            }),
            shared: AsyncMutex::new(None),
            auto_net: AtomicU8::new(AUTO_H3),
        })
    }

    fn make_tls(cfg: &MasqueCfg) -> io::Result<MasqueTls> {
        MasqueTls::new(
            &cfg.tls_obj,
            &cfg.profile,
            &cfg.keys,
            &cfg.server.0,
            &cfg.tag,
        )
        .map_err(|e| io::Error::other(e.to_string()))
    }

    async fn dial_h3(
        cfg: Arc<MasqueCfg>,
        server: SocketAddr,
        budget: Option<Duration>,
    ) -> io::Result<h3::H3Conn> {
        let tls = Self::make_tls(&cfg)?;
        h3::H3Conn::connect(&tls, &cfg.profile, &cfg.uri, server, cfg.keep_alive, budget).await
    }

    async fn dial_h2(cfg: Arc<MasqueCfg>, server: SocketAddr) -> io::Result<h2::H2Conn> {
        let tls = Self::make_tls(&cfg)?;
        h2::H2Conn::connect(&tls, &cfg.profile, &cfg.uri, server).await
    }

    fn remember(&self, network: u8) {
        if self.auto_net.swap(network, Ordering::Relaxed) != network {
            logging::debug(format_args!(
                "masque[{}]: vhttp auto remembers {}",
                self.cfg.tag,
                if network == AUTO_H2 { "h2" } else { "h3" }
            ));
        }
    }

    /// One dial attempt with the `vhttp: auto` fallback folded in
    /// (reference `connect`). Returns the leg that actually came up.
    async fn connect_leg(&self, server: SocketAddr) -> io::Result<Leg> {
        let cfg = Arc::clone(&self.cfg);
        let auto = cfg.auto_mode;
        let first = if !auto {
            cfg.network
        } else if self.auto_net.load(Ordering::Relaxed) == AUTO_H2 {
            "h2"
        } else {
            "h3"
        };
        logging::debug(format_args!(
            "masque[{}]: establishing {first} tunnel to {}:{}",
            cfg.tag, cfg.server.0, cfg.server.1
        ));

        if first == "h2" {
            let conn = Self::dial_h2(Arc::clone(&cfg), server).await;
            match conn {
                Ok(conn) => {
                    if auto {
                        self.remember(AUTO_H2);
                    }
                    logging::info(format_args!(
                        "masque[{}]: h2 tunnel established to {}:{}",
                        cfg.tag, cfg.server.0, cfg.server.1
                    ));
                    Ok(Leg::H2(conn))
                }
                Err(e) => {
                    logging::warn(format_args!(
                        "masque[{}]: h2 tunnel to {}:{} failed: {e}",
                        cfg.tag, cfg.server.0, cfg.server.1
                    ));
                    Err(e)
                }
            }
        } else if !auto {
            let conn = Self::dial_h3(cfg, server, None).await;
            match conn {
                Ok(conn) => {
                    logging::info(format_args!(
                        "masque[{}]: h3 tunnel established to {}:{}",
                        self.cfg.tag, self.cfg.server.0, self.cfg.server.1
                    ));
                    Ok(Leg::H3(conn))
                }
                Err(e) => {
                    logging::warn(format_args!(
                        "masque[{}]: h3 tunnel to {}:{} failed: {e}",
                        self.cfg.tag, self.cfg.server.0, self.cfg.server.1
                    ));
                    Err(e)
                }
            }
        } else {
            self.connect_auto(server).await
        }
    }

    /// `vhttp: auto`: try h3 detached under a wall-clock budget, fall back to
    /// h2 (reference SPEC 074). The late h3 result is drained in the
    /// background; a late success is closed.
    async fn connect_auto(&self, server: SocketAddr) -> io::Result<Leg> {
        let cfg = Arc::clone(&self.cfg);
        let budget = cfg.auto_h3_delay;
        let (done_tx, mut done_rx) = mpsc::channel::<io::Result<h3::H3Conn>>(1);
        let h3cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            let result = Self::dial_h3(h3cfg, server, Some(budget)).await;
            if let Err(mpsc::error::SendError(result)) = done_tx.send(result).await
                && let Ok(mut conn) = result
            {
                conn.close();
            }
        });

        let mut h3_err: Option<String>;
        let mut h3_consumed = false;
        tokio::select! {
            out = done_rx.recv() => {
                h3_consumed = true;
                match out {
                    Some(Ok(conn)) => {
                        self.remember(AUTO_H3);
                        logging::info(format_args!(
                            "masque[{}]: h3 tunnel established to {}:{}",
                            cfg.tag, cfg.server.0, cfg.server.1
                        ));
                        return Ok(Leg::H3(conn));
                    }
                    Some(Err(e)) => {
                        h3_err = Some(e.to_string());
                        logging::info(format_args!(
                            "masque[{}]: h3 to {}:{} did not come up ({}); falling back to h2",
                            cfg.tag, cfg.server.0, cfg.server.1,
                            h3_err.as_deref().unwrap_or_default()
                        ));
                    }
                    None => h3_err = Some("h3 leg task exited".to_string()),
                }
            }
            _ = tokio::time::sleep(budget) => {
                h3_err = Some(format!("h3 handshake exceeded {budget:?}"));
                logging::info(format_args!(
                    "masque[{}]: {} to {}:{}; falling back to h2 (h3 attempt abandoned)",
                    cfg.tag,
                    h3_err.as_deref().unwrap_or_default(),
                    cfg.server.0, cfg.server.1
                ));
            }
        }

        // h3 outcome known (consumed) or still pending in done_rx.
        let h2 = Self::dial_h2(Arc::clone(&cfg), server).await;
        match h2 {
            Ok(conn) => {
                if !h3_consumed {
                    // Drain the abandoned leg; close a late-established tunnel.
                    let server_info = (cfg.server.0.clone(), cfg.server.1);
                    tokio::spawn(async move {
                        if let Some(Ok(mut conn)) = done_rx.recv().await {
                            logging::debug(format_args!(
                                "masque: late h3 tunnel to {}:{} discarded (h2 already won)",
                                server_info.0, server_info.1
                            ));
                            conn.close();
                        }
                    });
                }
                self.remember(AUTO_H2);
                logging::info(format_args!(
                    "masque[{}]: h2 tunnel established to {}:{}",
                    cfg.tag, cfg.server.0, cfg.server.1
                ));
                Ok(Leg::H2(conn))
            }
            Err(h2_err) => {
                if !h3_consumed {
                    // Nothing better to offer: wait for the h3 leg now.
                    match done_rx.recv().await {
                        Some(Ok(conn)) => {
                            self.remember(AUTO_H3);
                            logging::info(format_args!(
                                "masque[{}]: h3 tunnel established to {}:{}",
                                cfg.tag, cfg.server.0, cfg.server.1
                            ));
                            return Ok(Leg::H3(conn));
                        }
                        Some(Err(e)) => h3_err = Some(e.to_string()),
                        None => h3_err = Some("h3 leg task exited".to_string()),
                    }
                }
                Err(io::Error::other(format!(
                    "masque: h3: {}; h2: {h2_err}",
                    h3_err.as_deref().unwrap_or("unknown")
                )))
            }
        }
    }

    /// Return the live stack task, building a tunnel lazily (reference
    /// `ensureSession`). A dead task is replaced on the next dial.
    async fn shared(&self) -> io::Result<Arc<MasqueShared>> {
        let mut guard = self.shared.lock().await;
        if let Some(shared) = guard.as_ref()
            && !shared.cmd_tx.is_closed()
        {
            return Ok(Arc::clone(shared));
        }
        let server = resolve_host(&self.cfg.server.0, self.cfg.server.1).await?;
        let leg = self.connect_leg(server).await?;
        let (tx, rx) = mpsc::channel(CMD_QUEUE);
        let shared = Arc::new(MasqueShared {
            cmd_tx: tx,
            next_id: AtomicU32::new(1),
        });
        let cfg = Arc::new(StackCfg {
            tag: self.cfg.tag.clone(),
            mtu: self.cfg.mtu,
            local_addr: self.cfg.local_addr,
            local_cidr: self.cfg.local_cidr,
            local_addr_v6: self.cfg.local_addr_v6,
            local_cidr_v6: self.cfg.local_cidr_v6,
            idle_timeout: self.cfg.idle_timeout,
        });
        tokio::spawn(async move {
            if let Err(e) = run(cfg, leg, rx).await {
                logging::error(format_args!("masque stack exited: {e}"));
            }
        });
        *guard = Some(Arc::clone(&shared));
        Ok(shared)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if !self.cfg.allow_tcp {
            return Err(io::Error::other(
                "masque: tcp network is not allowed by network_list",
            ));
        }
        let dst = resolve_target(target).await?;
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
            .map_err(|_| io::Error::other("masque: stack task stopped"))?;

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

        match tokio::time::timeout(CONNECT_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(remote)),
            Ok(Ok(Err(e))) => Err(io::Error::other(format!("masque: {e}"))),
            Ok(Err(_)) => Err(io::Error::other("masque: stack task stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "masque: connect timeout",
            )),
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        if !self.cfg.allow_udp {
            return Err(io::Error::other(
                "masque: udp network is not allowed by network_list",
            ));
        }
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
            .map_err(|_| io::Error::other("masque: stack task stopped"))?;
        let (port, mut replies) = match tokio::time::timeout(Duration::from_secs(10), resp_rx).await
        {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => return Err(io::Error::other(format!("masque: {e}"))),
            Ok(Err(_)) => return Err(io::Error::other("masque: stack task stopped")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "masque: udp session timeout",
                ));
            }
        };

        let peer = Arc::new(peer);
        let cmd_tx = shared.cmd_tx.clone();
        let udp_timeout = self.cfg.udp_timeout;

        let last_activity = Arc::new(portable_atomic::AtomicU64::new(
            crate::inbound::udp::now_ms(),
        ));
        let last_act_rx = Arc::clone(&last_activity);
        let last_act_tx = Arc::clone(&last_activity);

        // replies: stack → session channel → loopback peer socket.
        {
            let peer = Arc::clone(&peer);
            tokio::spawn(async move {
                while let Some(bytes) = replies.recv().await {
                    last_act_rx.store(
                        crate::inbound::udp::now_ms(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if peer.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
        }

        // sends: loopback peer socket → stack (mirrors the hysteria2 bridge).
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let check_interval = udp_timeout.min(Duration::from_secs(5));
            loop {
                match tokio::time::timeout(check_interval, peer.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        last_act_tx.store(
                            crate::inbound::udp::now_ms(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
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
                    Ok(Err(_)) => break,
                    Err(_) => {
                        let elapsed = crate::inbound::udp::now_ms()
                            .saturating_sub(last_act_tx.load(std::sync::atomic::Ordering::Relaxed));
                        if elapsed >= udp_timeout.as_millis() as u64 {
                            break;
                        }
                    }
                }
            }
            let _ = cmd_tx.send(Cmd::UdpClose { port }).await;
        });

        Ok(local)
    }
}

pub(crate) async fn resolve_host(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(dns) = crate::dns::current() {
        let addrs = match crate::dns::default_domain_resolver() {
            Some(tag) => dns.resolve_via(&tag, host).await?,
            None => dns.resolve(host).await?,
        };
        let ip = addrs
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other(format!("no address for {host}")))?;
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("no address for {host}")))
}

pub(crate) async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => resolve_host(host, *port).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "masque",
            "tag": "warp",
            "server": "1.2.3.4",
            "server_port": 443,
            "ip": "172.16.0.2",
            "private_key": "MHcCAQEEII0yRXpZqxtdgaDRKlsmWg1QDp+D5AWvSHg2WAaubf3woAoGCCqGSM49AwEHoUQDQgAE7IKkFW+4TVa3+LQyWrHAit6Q3J/FdgtrHn0+AioSqpCSojadOVInMjSDxN920+T1Rcplag2IRpgoCr7Fyp2tJA==",
            "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7IKkFW+4TVa3+LQyWrHAit6Q3J/FdgtrHn0+AioSqpCSojadOVInMjSDxN920+T1Rcplag2IRpgoCr7Fyp2tJA==",
        })
        .as_object()
        .unwrap()
        .clone();
        if let Value::Object(m) = extra {
            for (k, v) in m {
                base.insert(k, v);
            }
        }
        base
    }

    #[test]
    fn build_cloudflare_defaults() {
        let m = Masque::build(&obj(json!({})), "outbounds[0]").expect("build");
        assert_eq!(m.cfg.network, "h3");
        assert!(m.cfg.auto_mode);
        assert_eq!(m.cfg.mtu, DEFAULT_MTU);
        assert_eq!(m.cfg.local_addr, Some(Ipv4Addr::new(172, 16, 0, 2)));
        assert_eq!(m.cfg.local_addr_v6, None);
        assert_eq!(m.cfg.keep_alive, Some(DEFAULT_KEEP_ALIVE));
        assert!(m.cfg.idle_timeout.is_none());
        assert!((m.cfg.allow_tcp, m.cfg.allow_udp) == (true, true));
        assert_eq!(m.cfg.uri, profile::CLOUDFLARE_CONNECT_URI);
    }

    #[test]
    fn build_with_ipv6() {
        let m = Masque::build(
            &obj(json!({
                "ip": "172.16.0.2/32",
                "ipv6": "2606:4700:110:85f8:9410:3b14:6cf1:a62b/128",
            })),
            "outbounds[0]",
        )
        .expect("build with ipv6");
        assert_eq!(m.cfg.local_addr, Some(Ipv4Addr::new(172, 16, 0, 2)));
        assert_eq!(
            m.cfg.local_addr_v6,
            Some(
                "2606:4700:110:85f8:9410:3b14:6cf1:a62b"
                    .parse::<Ipv6Addr>()
                    .unwrap()
            )
        );
    }

    #[test]
    fn build_requires_uri_on_standard() {
        let e = Masque::build(
            &obj(json!({"profile": "standard", "private_key": null, "public_key": null})),
            "outbounds[0]",
        )
        .expect_err("uri");
        assert!(
            e.to_string()
                .contains("uri is required for the standard profile")
        );
    }

    #[test]
    fn build_standard_with_uri_and_h2_rejected() {
        let m = Masque::build(
            &obj(json!({
                "profile": "standard",
                "private_key": null,
                "public_key": null,
                "uri": "https://example.com/.well-known/masque/ip/*/*/",
            })),
            "outbounds[0]",
        )
        .expect("standard h3");
        assert_eq!(m.cfg.network, "h3");
        assert!(!m.cfg.auto_mode);

        let e = Masque::build(
            &obj(json!({
                "profile": "standard",
                "private_key": null,
                "public_key": null,
                "uri": "https://example.com/x",
                "vhttp": "h2",
            })),
            "outbounds[0]",
        )
        .expect_err("h2");
        assert!(e.to_string().contains("vhttp h2 is not implemented"));
    }

    #[test]
    fn legacy_network_folds_to_vhttp() {
        let m = Masque::build(&obj(json!({"network": "h2"})), "outbounds[0]").expect("fold");
        assert_eq!(m.cfg.network, "h2");
        assert!(!m.cfg.auto_mode);

        let e = Masque::build(
            &obj(json!({"network": "h2", "vhttp": "h3"})),
            "outbounds[0]",
        )
        .expect_err("conflict");
        assert!(e.to_string().contains("deprecated `network`"));
    }

    #[test]
    fn legacy_sni_and_skip_cert_verify_fold_into_tls() {
        let m = Masque::build(&obj(json!({"sni": "warp.example"})), "outbounds[0]").expect("sni");
        assert_eq!(
            m.cfg
                .tls_obj
                .get("tls")
                .and_then(|t| t.get("server_name"))
                .and_then(Value::as_str),
            Some("warp.example")
        );

        let m =
            Masque::build(&obj(json!({"skip_cert_verify": true})), "outbounds[0]").expect("skip");
        assert_eq!(
            m.cfg
                .tls_obj
                .get("tls")
                .and_then(|t| t.get("insecure"))
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn mtu_h2_cap() {
        let e = Masque::build(&obj(json!({"vhttp": "h2", "mtu": 20000})), "outbounds[0]")
            .expect_err("cap");
        assert!(e.to_string().contains("too large for h2"));
        let m = Masque::build(&obj(json!({"vhttp": "h2", "mtu": 16000})), "outbounds[0]")
            .expect("boundary");
        assert_eq!(m.cfg.mtu, 16000);
    }

    #[test]
    fn keep_alive_forms() {
        let at = "t";
        assert_eq!(
            parse_keep_alive(None, at).unwrap(),
            Some(DEFAULT_KEEP_ALIVE)
        );
        assert_eq!(
            parse_keep_alive(Some(&json!("45s")), at).unwrap(),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            parse_keep_alive(Some(&json!("0s")), at).unwrap(),
            Some(DEFAULT_KEEP_ALIVE)
        );
        assert_eq!(parse_keep_alive(Some(&json!("-1s")), at).unwrap(), None);
        assert_eq!(
            parse_idle_timeout(Some(&json!("2m")), at).unwrap(),
            Some(Duration::from_secs(120))
        );
        assert_eq!(parse_idle_timeout(None, at).unwrap(), None);
        assert_eq!(parse_idle_timeout(Some(&json!("0s")), at).unwrap(), None);
    }

    #[test]
    fn network_list_forms() {
        assert_eq!(parse_network_list(None), (true, true));
        assert_eq!(parse_network_list(Some(&json!(null))), (true, true));
        assert_eq!(parse_network_list(Some(&json!("tcp"))), (true, false));
        assert_eq!(parse_network_list(Some(&json!("udp"))), (false, true));
        assert_eq!(
            parse_network_list(Some(&json!(["tcp", "udp"]))),
            (true, true)
        );
        assert_eq!(parse_network_list(Some(&json!([]))), (false, false));
    }
}
