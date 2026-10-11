//! Shared QUIC plumbing for hysteria2 / tuic: transport options, endpoint
//! construction without ring-gated helpers, salamander obfs relay, varint and
//! sing address codecs, padding, and a stream duplex adapter.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::VarInt;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::inbound::Target;
use crate::logging;
use crate::outbound::shadowsocks::crypto::random_bytes;
use crate::outbound::urltest::parse_duration;

/// Reference `hysteria.MbpsToBps`.
pub(crate) const MBPS_TO_BPS: u64 = 125_000;
/// Reference `protocol.MaxUDPSize` (hy2).
pub(crate) const HY2_MAX_UDP: usize = 4096;
/// TUIC max datagram payload (0xffff).
pub(crate) const TUIC_MAX_UDP: usize = 0xffff;

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Default socket buffer size for UDP/QUIC (4 MiB).
/// Prevents kernel-level packet drops during high-throughput bursts.
pub(crate) const UDP_SOCKET_BUFFER: usize = 4 * 1024 * 1024;

/// Pool bounds for the per-outbound QUIC connection pool: one shared QUIC
/// connection serializes every stream through a single quinn driver task and
/// one UDP socket, which loses to the reference at 8 streams.
pub(crate) const POOL_MAX_CONNS: usize = 8;
/// Streams (or UDP sessions) one pooled connection takes before the pool
/// opens the next one.
pub(crate) const POOL_STREAMS_PER_CONN: u32 = 2;

/// Slot in a pooled QUIC connection; dropping it returns the slot, so the
/// pool sees how busy each connection is.
pub struct PoolLease {
    count: Arc<AtomicU32>,
}

impl PoolLease {
    pub(crate) fn new(count: Arc<AtomicU32>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self { count }
    }
}

impl Drop for PoolLease {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CongestionKind {
    Bbr,
    Cubic,
    NewReno,
    Brutal(u64), // bps
}

/// Hysteria Brutal Congestion Controller.
/// Paces transmission at a fixed bandwidth rate (bps) and sets the congestion window
/// proportional to (bandwidth * RTT * 1.5), without backing off on packet loss.
#[derive(Debug, Clone)]
pub struct Brutal {
    config: Arc<BrutalConfig>,
    current_mtu: u64,
    window: u64,
    bps: u64,
}

#[derive(Debug)]
pub struct BrutalConfig {
    pub bps: u64,
    pub initial_window: u64,
}

impl BrutalConfig {
    pub fn new(bps: u64) -> Self {
        let b_bytes_per_sec = bps / 8;
        let initial_50ms = (b_bytes_per_sec / 20).max(10 * 1200);
        Self {
            bps,
            initial_window: initial_50ms,
        }
    }
}

impl quinn::congestion::ControllerFactory for BrutalConfig {
    fn build(
        self: Arc<Self>,
        _now: std::time::Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        let mtu = (current_mtu as u64).max(1200);
        let init_win = self.initial_window.max(10 * mtu);
        Box::new(Brutal {
            config: Arc::clone(&self),
            current_mtu: mtu,
            window: init_win,
            bps: self.bps,
        })
    }
}

impl quinn::congestion::Controller for Brutal {
    fn on_congestion_event(
        &mut self,
        _now: std::time::Instant,
        _sent: std::time::Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // Brutal ignores loss! No congestion backoff or window reduction.
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = (new_mtu as u64).max(1200);
        let min_win = 10 * self.current_mtu;
        if self.window < min_win {
            self.window = min_win;
        }
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> quinn::congestion::ControllerMetrics {
        let mut m = quinn::congestion::ControllerMetrics::default();
        m.congestion_window = self.window;
        m.pacing_rate = Some(self.bps);
        m
    }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// Parsed `QUICOutFields` with per-protocol defaults applied at build time.
#[derive(Debug)]
pub(crate) struct QuicTunnelOptions {
    pub idle_timeout: Option<Duration>,
    pub keep_alive_period: Option<Duration>,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub max_concurrent_streams: Option<u64>,
    pub initial_packet_size: Option<u16>,
    pub disable_path_mtu_discovery: bool,
}

impl QuicTunnelOptions {
    pub fn parse(
        obj: &serde_json::Map<String, Value>,
        at: &str,
        defaults: QuicTunnelDefaults,
    ) -> anyhow::Result<Self> {
        let idle_timeout = match obj.get("idle_timeout") {
            Some(v) => Some(parse_duration(Some(v), defaults.idle_timeout, at)?),
            None => (defaults.idle_timeout != Duration::ZERO).then_some(defaults.idle_timeout),
        };
        let keep_alive_period = match obj.get("keep_alive_period") {
            Some(v) => Some(parse_duration(Some(v), defaults.keep_alive_period, at)?),
            None => {
                (defaults.keep_alive_period != Duration::ZERO).then_some(defaults.keep_alive_period)
            }
        };
        let stream_receive_window = match obj.get("stream_receive_window") {
            Some(v) => Some(parse_memory_bytes(Some(v), at)?),
            None => defaults.stream_receive_window,
        };
        let connection_receive_window = match obj.get("connection_receive_window") {
            Some(v) => Some(parse_memory_bytes(Some(v), at)?),
            None => defaults.connection_receive_window,
        };
        let max_concurrent_streams = obj
            .get("max_concurrent_streams")
            .and_then(Value::as_u64)
            .or(defaults.max_concurrent_streams);
        let initial_packet_size = match obj.get("initial_packet_size").and_then(Value::as_u64) {
            Some(v) => {
                let v = u16::try_from(v)
                    .map_err(|_| anyhow::anyhow!("{at}: invalid initial_packet_size"))?;
                if v < 1200 {
                    logging::warn(format_args!(
                        "{at}: initial_packet_size {v} < 1200 (ignored)"
                    ));
                    defaults.initial_packet_size
                } else {
                    Some(v)
                }
            }
            None => defaults.initial_packet_size,
        };
        let disable_path_mtu_discovery = obj
            .get("disable_path_mtu_discovery")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.disable_path_mtu_discovery);
        Ok(Self {
            idle_timeout,
            keep_alive_period,
            stream_receive_window,
            connection_receive_window,
            max_concurrent_streams,
            initial_packet_size,
            disable_path_mtu_discovery,
        })
    }

    /// Build `(EndpointConfig, TransportConfig)` for quinn.
    pub fn build_configs(
        &self,
        congestion: CongestionKind,
        uni_streams: Option<u64>,
        datagram_rx: bool,
    ) -> (quinn::EndpointConfig, quinn::TransportConfig) {
        let mut reset = [0u8; 32];
        let _ = random_bytes(&mut reset);
        let mut endpoint = quinn::EndpointConfig::new(Arc::new(
            crate::outbound::quic::HmacSha256Wrapper::new(&reset),
        ));
        if let Some(size) = self.initial_packet_size
            && let Err(e) = endpoint.max_udp_payload_size(size)
        {
            logging::warn(format_args!("initial_packet_size: {e}"));
        }

        let mut transport = quinn::TransportConfig::default();
        if let Some(idle) = self.idle_timeout {
            match quinn::IdleTimeout::try_from(idle) {
                Ok(t) => {
                    transport.max_idle_timeout(Some(t));
                }
                Err(_) => logging::warn(format_args!("idle_timeout out of range (ignored)")),
            }
        }
        transport.keep_alive_interval(self.keep_alive_period);
        if let Some(v) = self.stream_receive_window {
            transport.stream_receive_window(VarInt::from_u64(v).unwrap_or(VarInt::MAX));
        }
        if let Some(v) = self.connection_receive_window {
            transport.receive_window(VarInt::from_u64(v).unwrap_or(VarInt::MAX));
        }
        if let Some(v) = self.max_concurrent_streams {
            transport.max_concurrent_bidi_streams(VarInt::from_u64(v).unwrap_or(VarInt::MAX));
        }
        if let Some(v) = uni_streams {
            transport.max_concurrent_uni_streams(VarInt::from_u64(v).unwrap_or(VarInt::MAX));
        }
        if let Some(size) = self.initial_packet_size {
            transport.initial_mtu(size);
        }
        if self.disable_path_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        transport.datagram_receive_buffer_size(datagram_rx.then_some(2 * 1024 * 1024));
        transport.datagram_send_buffer_size(2 * 1024 * 1024);
        // Acking every second ack-eliciting packet, and every out-of-order arrival
        // on top of it, is quinn's default when no ack-frequency policy is set. On a
        // saturated loopback path with several streams that is an ACK-only packet
        // per couple of data packets: each one is its own transmit, its own
        // `poll_writable` round trip and its own `sendmsg`, and the reordering it
        // manufactures on the sender's side is what costs the sender its congestion
        // window. Eight keeps the ACK path amortised without letting a lost packet
        // wait for a timer.
        let mut ack = quinn::AckFrequencyConfig::default();
        ack.max_ack_delay(Some(Duration::from_millis(25)))
            .ack_eliciting_threshold(VarInt::from_u32(8))
            .reordering_threshold(VarInt::from_u32(4));
        transport.ack_frequency_config(Some(ack));
        transport.congestion_controller_factory(match congestion {
            CongestionKind::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            CongestionKind::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            CongestionKind::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
            CongestionKind::Brutal(bps) => Arc::new(BrutalConfig::new(bps)),
        });
        (endpoint, transport)
    }
}

/// Per-protocol QUIC defaults (reference hysteria / tuic clients).
pub(crate) struct QuicTunnelDefaults {
    pub idle_timeout: Duration,
    pub keep_alive_period: Duration,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub max_concurrent_streams: Option<u64>,
    pub initial_packet_size: Option<u16>,
    pub disable_path_mtu_discovery: bool,
}

impl QuicTunnelDefaults {
    /// hysteria2: idle 30s, keepalive 10s, stream 8 MiB, conn 20 MiB, BBR.
    pub fn hysteria2() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            keep_alive_period: Duration::from_secs(10),
            stream_receive_window: Some(8 * 1024 * 1024),
            connection_receive_window: Some(20 * 1024 * 1024),
            max_concurrent_streams: None,
            initial_packet_size: None,
            disable_path_mtu_discovery: false,
        }
    }

    /// tuic: idle 30s, no keepalive unless set, cubic, uni 1<<60.
    ///
    /// The receive windows stay at quinn's defaults. Raising them to hysteria2's
    /// 8 MiB / 20 MiB was tried and measured worse: one stream got faster, and
    /// eight got slower (0.88x -> 0.73x of the reference, CPU 1.15x -> 1.37x).
    /// A bigger credit means a bigger burst, and on the two cores this runs on the
    /// burst arrives as reordering and scheduler work rather than throughput.
    pub fn tuic() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            keep_alive_period: Duration::ZERO,
            stream_receive_window: None,
            connection_receive_window: None,
            max_concurrent_streams: None,
            initial_packet_size: None,
            disable_path_mtu_discovery: false,
        }
    }
}

/// MemoryBytes: number = raw bytes; string = digits + unit (1024 base).
pub(crate) fn parse_memory_bytes(value: Option<&Value>, at: &str) -> anyhow::Result<u64> {
    let Some(value) = value else {
        return Ok(0);
    };
    match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("{at}: invalid memory size")),
        Value::String(raw) => {
            let raw = raw.trim();
            let digits = raw.chars().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                anyhow::bail!("{at}: invalid memory size {raw:?}");
            }
            let n: u64 = raw[..digits]
                .parse()
                .map_err(|_| anyhow::anyhow!("{at}: invalid memory size {raw:?}"))?;
            let unit = raw[digits..].trim();
            let mult = match unit.to_ascii_lowercase().as_str() {
                "" | "b" => 1u64,
                "k" | "kb" => 1024,
                "mb" => 1024 * 1024,
                "gb" => 1024 * 1024 * 1024,
                "tb" => 1024u64.pow(4),
                other => anyhow::bail!("{at}: unsupported memory unit {other:?}"),
            };
            n.checked_mul(mult)
                .ok_or_else(|| anyhow::anyhow!("{at}: memory size overflow"))
        }
        other => anyhow::bail!("{at}: invalid memory size {other}"),
    }
}

/// QUIC varint (RFC 9000 §16).
pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    debug_assert!(v < (1 << 62));
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&(((v >> 8) as u8) | 0x40).to_be_bytes());
        out.push(v as u8);
    } else if v < (1 << 30) {
        out.push(((v >> 24) as u8) | 0x80);
        out.extend_from_slice(&((v >> 16) as u16).to_be_bytes());
        // 4-byte form: top byte already has 0x80, next two are mid, last is low.
        // Rebuild cleanly:
        out.truncate(out.len() - 3);
        out.push(((v >> 24) as u8) | 0x80);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else {
        out.push(((v >> 56) as u8) | 0xc0);
        for shift in [48, 40, 32, 24, 16, 8] {
            out.push((v >> shift) as u8);
        }
        out.push(v as u8);
    }
    let _ = &mut v;
}

/// Read a QUIC varint; returns `(value, bytes_consumed)`.
pub(crate) fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if buf.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        v = (v << 8) | u64::from(b);
    }
    Some((v, len))
}

/// Go `net.JoinHostPort` style destination string for hy2.
pub(crate) fn dest_string(target: &Target) -> String {
    match target {
        Target::Ip(addr) => addr.to_string(),
        Target::Domain(host, port) => {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        }
    }
}

/// sing `AddressSerializer` family bytes for tuic.
pub(crate) fn sing_addr_port_len(target: &Target) -> usize {
    match target {
        Target::Ip(SocketAddr::V4(_)) => 1 + 4 + 2,
        Target::Ip(SocketAddr::V6(_)) => 1 + 16 + 2,
        Target::Domain(h, _) => 1 + 1 + h.len() + 2,
    }
}

/// Encode a valid address+port (tuic `WriteAddrPort`).
pub(crate) fn put_sing_addr_port(out: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            out.push(0x02);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(h, p) => {
            out.push(0x00);
            out.push(h.len() as u8);
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(&p.to_be_bytes());
        }
    }
}

/// Empty address (tuic continuation fragments): single `0xff`, no port.
pub(crate) fn put_sing_addr_empty(out: &mut Vec<u8>) {
    out.push(0xff);
}

pub(crate) fn parse_sing_addr_port(slice: &[u8]) -> Option<(Target, usize)> {
    if slice.is_empty() {
        return None;
    }
    match slice[0] {
        0x01 => {
            if slice.len() < 7 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(slice[1], slice[2], slice[3], slice[4]);
            let port = u16::from_be_bytes([slice[5], slice[6]]);
            Some((
                Target::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))),
                7,
            ))
        }
        0x02 => {
            if slice.len() < 19 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&slice[1..17]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([slice[17], slice[18]]);
            Some((
                Target::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))),
                19,
            ))
        }
        0x00 => {
            if slice.len() < 2 {
                return None;
            }
            let len = slice[1] as usize;
            if slice.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&slice[2..2 + len]).ok()?;
            let port = u16::from_be_bytes([slice[2 + len], slice[3 + len]]);
            Some((Target::Domain(host.to_string(), port), 4 + len))
        }
        _ => None,
    }
}

pub(crate) async fn read_sing_addr_port<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Target> {
    let mut atype = [0u8; 1];
    reader.read_exact(&mut atype).await?;
    match atype[0] {
        0x01 => {
            let mut buf = [0u8; 6];
            reader.read_exact(&mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Target::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(
                ip, port,
            ))))
        }
        0x02 => {
            let mut buf = [0u8; 18];
            reader.read_exact(&mut buf).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Target::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip, port, 0, 0,
            ))))
        }
        0x00 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            reader.read_exact(&mut host).await?;
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let host_str = String::from_utf8(host).map_err(io::Error::other)?;
            Ok(Target::Domain(host_str, port))
        }
        other => Err(io::Error::other(format!("invalid address family: {other}"))),
    }
}

/// Random alphanumeric padding, half-open `[min, max)`.
pub(crate) fn random_padding(min: usize, max: usize) -> String {
    debug_assert!(max > min);
    let mut len_buf = [0u8; 8];
    if random_bytes(&mut len_buf).is_err() {
        return "x".repeat(min);
    }
    let span = (max - min) as u64;
    let n = min + (u64::from_le_bytes(len_buf) % span.max(1)) as usize;
    let mut out = String::with_capacity(n);
    let mut buf = vec![0u8; n];
    if random_bytes(&mut buf).is_err() {
        return "x".repeat(n);
    }
    for b in buf {
        out.push(PADDING_CHARS[(b as usize) % PADDING_CHARS.len()] as char);
    }
    out
}

pub(crate) fn blake2b256(data: &[u8]) -> [u8; 32] {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut h = Blake2bVar::new(32).expect("blake2b-32");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("blake2b-32 output");
    out
}

/// Salamander outbound seal: `salt8 || xor(payload, blake2b256(password||salt))`.
pub(crate) fn salamander_seal(password: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; 8];
    let _ = random_bytes(&mut salt);
    let mut key_input = password.to_vec();
    key_input.extend_from_slice(&salt);
    let key = blake2b256(&key_input);
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&salt);
    for (i, &b) in payload.iter().enumerate() {
        out.push(b ^ key[i % 32]);
    }
    out
}

/// Salamander inbound open; `None` when the packet is too short.
pub(crate) fn salamander_open(password: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() <= 8 {
        return None;
    }
    let mut key_input = password.to_vec();
    key_input.extend_from_slice(&packet[..8]);
    let key = blake2b256(&key_input);
    let mut out = Vec::with_capacity(packet.len() - 8);
    for (i, &b) in packet[8..].iter().enumerate() {
        out.push(b ^ key[i % 32]);
    }
    Some(out)
}

/// Gecko obfuscation: the salamander framing plus a fragmentation layer, from
/// `sing-quic/hysteria2/gecko.go`.
///
/// A packet whose first byte has the fragment flag set is split into 2..=8
/// chunks, each prefixed with `[flag][msg id][index<<4 | count][pad_len:u16]`
/// and padded with random bytes so the datagram looks like ordinary traffic.
/// The receiver reassembles by message id until every chunk arrived.
const GECKO_FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_DEFAULT_MIN_PACKET: usize = 512;
const GECKO_DEFAULT_MAX_PACKET: usize = 1200;
#[allow(dead_code)]
const GECKO_MAX_ON_WIRE: usize = 2048;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 4096;

/// Reassembles gecko fragments on the way in.
pub(crate) struct GeckoReassembler {
    chunks: HashMap<u8, GeckoEntry>,
    bytes: usize,
    last_sweep: Instant,
}

struct GeckoEntry {
    chunks: Vec<Option<Vec<u8>>>,
    total: usize,
    deadline: Instant,
}

impl GeckoReassembler {
    pub(crate) fn new() -> Self {
        Self {
            chunks: HashMap::new(),
            bytes: 0,
            last_sweep: Instant::now(),
        }
    }

    /// `Some(packet)` once every chunk of a message arrived.
    pub(crate) fn accept(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.is_empty() {
            return None;
        }
        if packet[0] & GECKO_FRAGMENT_FLAG == 0 {
            return Some(packet.to_vec());
        }
        if packet.len() < GECKO_HEADER_LEN {
            return None;
        }
        let message_id = packet[1];
        let index = usize::from(packet[2] >> 4);
        let total = usize::from(packet[2] & 0x0f);
        let pad = usize::from(u16::from_be_bytes([packet[3], packet[4]]));
        if !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&total) || index >= total {
            return None;
        }
        let start = GECKO_HEADER_LEN + pad;
        if start > packet.len() {
            return None;
        }
        self.sweep();
        if !self.chunks.contains_key(&message_id) && self.chunks.len() >= GECKO_MAX_REASSEMBLY {
            self.evict_oldest();
        }
        let now = Instant::now();
        let entry = self.chunks.entry(message_id).or_insert_with(|| GeckoEntry {
            chunks: (0..total).map(|_| None).collect(),
            total,
            deadline: now + GECKO_REASSEMBLY_TTL,
        });
        if entry.total != total {
            return None;
        }
        if index >= entry.chunks.len() || entry.chunks[index].is_some() {
            return None;
        }
        let chunk = packet[start..].to_vec();
        self.bytes += chunk.len();
        entry.chunks[index] = Some(chunk);
        if entry.chunks.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.chunks.remove(&message_id)?;
        let total_len: usize = entry.chunks.iter().flatten().map(Vec::len).sum();
        self.bytes -= total_len;
        // sized once: Vec::new() grew by reallocation as each fragment
        // arrived, copying the message again on every doubling
        let mut out = Vec::with_capacity(total_len);
        for chunk in entry.chunks.into_iter().flatten() {
            out.extend_from_slice(&chunk);
        }
        Some(out)
    }

    fn sweep(&mut self) {
        if self.last_sweep.elapsed() < GECKO_REASSEMBLY_TTL / 2 {
            return;
        }
        let now = Instant::now();
        self.chunks.retain(|_, entry| entry.deadline > now);
        self.last_sweep = now;
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .chunks
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(id, _)| *id)
        else {
            return;
        };
        if let Some(entry) = self.chunks.remove(&oldest) {
            self.bytes -= entry.chunks.iter().flatten().map(Vec::len).sum::<usize>();
        }
    }
}

/// Splits one packet into gecko frames, each already padded.
pub(crate) fn gecko_frames(
    payload: &[u8],
    message_id: u8,
    min_packet_size: usize,
    max_packet_size: usize,
) -> Vec<Vec<u8>> {
    let chunks = GECKO_MIN_CHUNKS + random_below(GECKO_MAX_CHUNKS - GECKO_MIN_CHUNKS + 1);
    let chunk_size = (payload.len() / chunks).max(1);
    let mut frames = Vec::with_capacity(chunks);
    for index in 0..chunks {
        let start = (index * chunk_size).min(payload.len());
        let end = if index + 1 < chunks {
            (start + chunk_size).min(payload.len())
        } else {
            payload.len()
        };
        let chunk = &payload[start..end];
        // the on-wire size is the salamander salt plus this header and chunk
        let base = 8 + GECKO_HEADER_LEN + chunk.len();
        let low = min_packet_size.max(base);
        let pad = if low > max_packet_size {
            0
        } else {
            low - base + random_below(max_packet_size - low + 1)
        };
        let mut frame = vec![0u8; GECKO_HEADER_LEN + pad + chunk.len()];
        frame[0] = GECKO_FRAGMENT_FLAG;
        frame[1] = message_id;
        frame[2] = (index as u8) << 4 | chunks as u8;
        frame[3..5].copy_from_slice(&(pad as u16).to_be_bytes());
        let _ = random_bytes(&mut frame[GECKO_HEADER_LEN..GECKO_HEADER_LEN + pad]);
        frame[GECKO_HEADER_LEN + pad..].copy_from_slice(chunk);
        frames.push(frame);
    }
    frames
}

fn random_below(limit: usize) -> usize {
    if limit <= 1 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    let _ = random_bytes(&mut bytes);
    (u64::from_le_bytes(bytes) % limit as u64) as usize
}

/// Randomly pick a port uniformly from a slice of inclusive `(start, end)` ranges.
pub(crate) fn pick_port_from_ranges(ranges: &[(u16, u16)]) -> u16 {
    if ranges.is_empty() {
        return 0;
    }
    let total: u32 = ranges
        .iter()
        .map(|(s, e)| (e.saturating_sub(*s) + 1) as u32)
        .sum();
    if total == 0 {
        return ranges[0].0;
    }
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    let mut idx = (u32::from_le_bytes(b) % total) as usize;
    for &(start, end) in ranges {
        let count = (end.saturating_sub(start) + 1) as usize;
        if idx < count {
            return start + idx as u16;
        }
        idx -= count;
    }
    ranges[0].0
}

/// Two-socket salamander/hop relay in front of a quinn endpoint.
///
/// * `sock_ep` — loopback, connected to the endpoint's local addr (plaintext side).
/// * `sock_srv` — wildcard, connected/directed to the real server (sealed or hopped side).
///
/// Returns the loopback address quinn should `connect()` to, plus task handles.
pub(crate) struct SalamanderRelay {
    pub local: SocketAddr,
    pub(crate) handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for SalamanderRelay {
    fn drop(&mut self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

/// Unified QUIC relay supporting port hopping, salamander obfs, and gecko fragmentation.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_hop_relay(
    server_ip: IpAddr,
    port_ranges: Vec<(u16, u16)>,
    initial_port: u16,
    hop_interval: Option<Duration>,
    hop_interval_max: Option<Duration>,
    obfs_password: Option<Vec<u8>>,
    gecko: Option<(usize, usize)>,
    endpoint_local: SocketAddr,
) -> io::Result<SalamanderRelay> {
    let ep_bind = if server_ip.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let sock_ep = Arc::new(tokio::net::UdpSocket::bind(ep_bind).await?);
    let _ = socket2::SockRef::from(&*sock_ep).set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = socket2::SockRef::from(&*sock_ep).set_send_buffer_size(UDP_SOCKET_BUFFER);
    sock_ep.connect(endpoint_local).await?;
    let local = sock_ep.local_addr()?;

    let srv_bind = if server_ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock_srv = Arc::new(tokio::net::UdpSocket::bind(srv_bind).await?);
    let _ = socket2::SockRef::from(&*sock_srv).set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = socket2::SockRef::from(&*sock_srv).set_send_buffer_size(UDP_SOCKET_BUFFER);

    let current_target = Arc::new(std::sync::RwLock::new(SocketAddr::new(
        server_ip,
        initial_port,
    )));
    let mut handles = Vec::new();

    if let Some(interval) = hop_interval
        && !port_ranges.is_empty()
        && interval > Duration::ZERO
    {
        let target = Arc::clone(&current_target);
        let ranges = port_ranges.clone();
        let hop_h = tokio::spawn(async move {
            loop {
                let sleep_dur = match hop_interval_max {
                    Some(max) if max > interval => {
                        let range_ms = (max - interval).as_millis() as u64;
                        if range_ms > 0 {
                            let mut b = [0u8; 8];
                            let _ = getrandom::fill(&mut b);
                            let add_ms = u64::from_le_bytes(b) % range_ms;
                            interval + Duration::from_millis(add_ms)
                        } else {
                            interval
                        }
                    }
                    _ => interval,
                };
                tokio::time::sleep(sleep_dur).await;
                let next_port = pick_port_from_ranges(&ranges);
                if let Ok(mut g) = target.write() {
                    *g = SocketAddr::new(server_ip, next_port);
                    logging::debug(format_args!("hysteria2: hopped port to {next_port}"));
                }
            }
        });
        handles.push(hop_h);
    }

    let pw_up = obfs_password.clone();
    let sock_ep_up = Arc::clone(&sock_ep);
    let sock_srv_up = Arc::clone(&sock_srv);
    let target_up = Arc::clone(&current_target);
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        let mut message_id = 0u8;
        loop {
            let Ok(n) = sock_ep_up.recv(&mut buf).await else {
                break;
            };
            let dst = *target_up.read().unwrap();
            if let Some((min_packet, max_packet)) = gecko {
                let min_p = if min_packet == 0 {
                    GECKO_DEFAULT_MIN_PACKET
                } else {
                    min_packet
                };
                let max_p = if max_packet == 0 {
                    GECKO_DEFAULT_MAX_PACKET
                } else {
                    max_packet
                };
                message_id = message_id.wrapping_add(1);
                for frame in gecko_frames(&buf[..n], message_id, min_p, max_p) {
                    let packet = if let Some(ref pw) = pw_up {
                        salamander_seal(pw, &frame)
                    } else {
                        frame
                    };
                    if sock_srv_up.send_to(&packet, dst).await.is_err() {
                        return;
                    }
                }
            } else if let Some(ref pw) = pw_up {
                let sealed = salamander_seal(pw, &buf[..n]);
                if sock_srv_up.send_to(&sealed, dst).await.is_err() {
                    break;
                }
            } else if sock_srv_up.send_to(&buf[..n], dst).await.is_err() {
                break;
            }
        }
    });
    handles.push(up);

    let pw_down = obfs_password.clone();
    let sock_ep_down = Arc::clone(&sock_ep);
    let sock_srv_down = Arc::clone(&sock_srv);
    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        let mut reassembler = GeckoReassembler::new();
        loop {
            let Ok((n, src)) = sock_srv_down.recv_from(&mut buf).await else {
                break;
            };
            if src.ip() != server_ip {
                continue;
            }
            if gecko.is_some() {
                let plain_data = if let Some(ref pw) = pw_down {
                    let Some(p) = salamander_open(pw, &buf[..n]) else {
                        continue;
                    };
                    p
                } else {
                    buf[..n].to_vec()
                };
                let Some(packet) = reassembler.accept(&plain_data) else {
                    continue;
                };
                if sock_ep_down.send(&packet).await.is_err() {
                    break;
                }
            } else if let Some(ref pw) = pw_down {
                let Some(plain) = salamander_open(pw, &buf[..n]) else {
                    continue;
                };
                if sock_ep_down.send(&plain).await.is_err() {
                    break;
                }
            } else if sock_ep_down.send(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    handles.push(down);

    Ok(SalamanderRelay { local, handles })
}

/// Two-socket relay that applies gecko on top of salamander, in both
/// directions. The salamander password is the same; only the framing differs.
#[allow(dead_code)]
pub(crate) async fn spawn_gecko_relay(
    server: SocketAddr,
    password: Vec<u8>,
    endpoint_local: SocketAddr,
    min_packet_size: usize,
    max_packet_size: usize,
) -> io::Result<SalamanderRelay> {
    spawn_hop_relay(
        server.ip(),
        Vec::new(),
        server.port(),
        None,
        None,
        Some(password),
        Some((min_packet_size, max_packet_size)),
        endpoint_local,
    )
    .await
}

#[allow(dead_code)]
pub(crate) async fn spawn_salamander_relay(
    server: SocketAddr,
    password: Vec<u8>,
    endpoint_local: SocketAddr,
) -> io::Result<SalamanderRelay> {
    spawn_hop_relay(
        server.ip(),
        Vec::new(),
        server.port(),
        None,
        None,
        Some(password),
        None,
        endpoint_local,
    )
    .await
}

/// Adapter so `HmacSha256Key` can be wrapped without orphan-rule issues at
/// the call site (the type already implements `quinn::crypto::HmacKey`).
pub(crate) struct HmacSha256Wrapper(core_tls::quic::HmacSha256Key);

impl HmacSha256Wrapper {
    pub fn new(key: &[u8]) -> Self {
        Self(core_tls::quic::HmacSha256Key::new(key))
    }
}

impl quinn::crypto::HmacKey for HmacSha256Wrapper {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        self.0.sign(data, signature_out);
    }

    fn signature_len(&self) -> usize {
        self.0.signature_len()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), quinn::crypto::CryptoError> {
        self.0.verify(data, signature)
    }
}

/// Resolve the outbound server address (dns section → system fallback).
pub(crate) async fn resolve_host(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Some(ip) = crate::dns::transport::is_ip_literal(host) {
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
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| io::Error::other(format!("no address for {host}")))
}

/// Bind a nonblocking UDP socket for a quinn endpoint with tuned buffers.
pub(crate) fn bind_udp(local: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let bind = if local.is_ipv4() {
        SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    };
    let sock = std::net::UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let sock_ref = socket2::SockRef::from(&sock);
    let _ = sock_ref.set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = sock_ref.set_send_buffer_size(UDP_SOCKET_BUFFER);
    Ok(sock)
}

/// Bind a loopback UDP socket (salamander plaintext side).
pub(crate) fn bind_udp_loopback(is_ipv4: bool) -> io::Result<std::net::UdpSocket> {
    let bind = if is_ipv4 {
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0))
    } else {
        SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0))
    };
    let sock = std::net::UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let sock_ref = socket2::SockRef::from(&sock);
    let _ = sock_ref.set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = sock_ref.set_send_buffer_size(UDP_SOCKET_BUFFER);
    Ok(sock)
}

/// Bidirectional quinn stream exposed as [`crate::inbound::AnyStream`].
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _lease: Option<PoolLease>,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            _lease: None,
        }
    }

    /// Same stream, holding a pool slot for as long as it lives.
    pub fn with_lease(send: quinn::SendStream, recv: quinn::RecvStream, lease: PoolLease) -> Self {
        Self {
            send,
            recv,
            _lease: Some(lease),
        }
    }

    pub fn split(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(Into::into)
    }
}

/// Incremental QUIC-varint reader for stream state machines.
#[derive(Debug, Default)]
pub(crate) struct VarintReader {
    buf: Vec<u8>,
}

impl VarintReader {
    /// Feed bytes; returns a complete value once enough prefix bytes arrive.
    pub fn push(&mut self, byte: u8) -> Option<u64> {
        if self.buf.is_empty() {
            let need = match byte >> 6 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 8,
            };
            self.buf.reserve(need);
        }
        self.buf.push(byte);
        if self.buf.len() >= self.needed() {
            let (v, _) = read_varint(&self.buf)?;
            self.buf.clear();
            return Some(v);
        }
        None
    }

    fn needed(&self) -> usize {
        self.buf.first().map_or(1, |&b| match b >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        })
    }
}

/// Per-session fragment reassembler (hy2 / tuic PACKET frames).
///
/// Fragments are `Bytes`: a slice of the datagram is shared by reference
/// count, so a single-fragment packet -- the overwhelmingly common case --
/// travels through without a copy at all; only the multi-fragment reassembly
/// copies, and then once, into the contiguous output.
pub(crate) struct Defragger {
    // packet_id → (total, slots)
    items: std::collections::HashMap<u16, FragSlots>,
}

type FragSlots = (u8, Vec<Option<bytes::Bytes>>);

impl Defragger {
    pub fn new() -> Self {
        Self {
            items: std::collections::HashMap::new(),
        }
    }

    /// Feed one fragment; returns the reassembled payload when complete.
    pub fn feed(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        data: bytes::Bytes,
    ) -> Option<bytes::Bytes> {
        if frag_total <= 1 {
            return Some(data);
        }
        if frag_id >= frag_total {
            return None;
        }
        let entry = self
            .items
            .entry(packet_id)
            .or_insert_with(|| (frag_total, vec![None; frag_total as usize]));
        if entry.0 != frag_total {
            *entry = (frag_total, vec![None; frag_total as usize]);
        }
        entry.1[frag_id as usize] = Some(data);
        if entry.1.iter().all(Option::is_some) {
            let (_, slots) = self.items.remove(&packet_id)?;
            let mut out = bytes::BytesMut::new();
            for slot in slots {
                out.extend_from_slice(&slot?);
            }
            return Some(out.freeze());
        }
        None
    }
}

/// Allocate a connected loopback UDP pair; returns `(local, peer)` where
/// `local` is handed to the hub and `peer` stays inside the bridge tasks.
pub(crate) async fn udp_loopback_pair() -> io::Result<(tokio::net::UdpSocket, tokio::net::UdpSocket)>
{
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let _ = socket2::SockRef::from(&a).set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = socket2::SockRef::from(&a).set_send_buffer_size(UDP_SOCKET_BUFFER);
    let _ = socket2::SockRef::from(&b).set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = socket2::SockRef::from(&b).set_send_buffer_size(UDP_SOCKET_BUFFER);
    a.connect(b.local_addr()?).await?;
    b.connect(a.local_addr()?).await?;
    Ok((a, b))
}

/// Map a connection/datagram error to io::Error with context.
pub(crate) fn io_from_quinn(e: quinn::ConnectionError) -> io::Error {
    io::Error::from(e)
}

pub(crate) fn io_from_datagram(e: quinn::SendDatagramError) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1 << 40] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let (got, n) = read_varint(&buf).expect("read");
            assert_eq!(got, v, "value {v}");
            assert_eq!(n, buf.len(), "len {v}");
        }
    }

    #[test]
    fn memory_bytes_parse() {
        assert_eq!(parse_memory_bytes(Some(&json!(1234)), "t").unwrap(), 1234);
        assert_eq!(
            parse_memory_bytes(Some(&json!("8MB")), "t").unwrap(),
            8 * 1024 * 1024
        );
        assert_eq!(parse_memory_bytes(Some(&json!("2k")), "t").unwrap(), 2048);
        assert!(parse_memory_bytes(Some(&json!("2xx")), "t").is_err());
    }

    #[test]
    fn gecko_frames_split_and_reassemble() {
        let payload: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
        let frames = gecko_frames(&payload, 7, 512, 1200);
        assert!((2..=8).contains(&frames.len()), "chunks: {}", frames.len());
        let mut reassembler = GeckoReassembler::new();
        let mut out = Vec::new();
        for frame in &frames {
            // every frame is a legal salamander payload plus padding
            assert_eq!(frame[0], GECKO_FRAGMENT_FLAG);
            assert_eq!(frame[1], 7, "the message id rides along");
            let pad = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
            assert!(GECKO_HEADER_LEN + pad <= frame.len());
            if let Some(packet) = reassembler.accept(frame) {
                out = packet;
            }
        }
        assert_eq!(out, payload);
        assert!(
            reassembler.chunks.is_empty(),
            "the reassembly buffer is released"
        );
    }

    #[test]
    fn gecko_frames_respect_the_size_range() {
        let payload = vec![0u8; 1000];
        for frame in gecko_frames(&payload, 1, 512, 1200) {
            // the wire size is the salamander salt plus this frame
            let wire = 8 + frame.len();
            assert!(
                (512..=1200).contains(&wire),
                "frame of {wire} bytes is outside the negotiated range"
            );
        }
    }

    #[test]
    fn gecko_passes_unfragmented_packets_through() {
        let mut reassembler = GeckoReassembler::new();
        assert_eq!(
            reassembler.accept(&[0x40, 1, 2, 3]).expect("plain"),
            vec![0x40, 1, 2, 3]
        );
    }

    #[test]
    fn gecko_rejects_malformed_frames() {
        let mut reassembler = GeckoReassembler::new();
        // shorter than the header
        assert!(reassembler.accept(&[GECKO_FRAGMENT_FLAG, 1]).is_none());
        // a chunk count outside 2..=8
        let mut frame = vec![GECKO_FRAGMENT_FLAG, 1, 1, 0, 0];
        frame.extend_from_slice(b"x");
        assert!(reassembler.accept(&frame).is_none());
        // an index past the declared count
        let mut frame = vec![GECKO_FRAGMENT_FLAG, 1, 0x22, 0, 0];
        frame.extend_from_slice(b"x");
        assert!(reassembler.accept(&frame).is_none());
        // a pad length past the end of the frame
        let frame = [GECKO_FRAGMENT_FLAG, 1, 2, 0xff, 0xff, b'x'];
        assert!(reassembler.accept(&frame).is_none());
    }

    #[test]
    fn salamander_roundtrip() {
        let pw = b"secret";
        let payload = b"hello salamander";
        let sealed = salamander_seal(pw, payload);
        assert!(sealed.len() > 8);
        let opened = salamander_open(pw, &sealed).expect("open");
        assert_eq!(opened, payload);
        assert!(salamander_open(pw, &sealed[..4]).is_none());
        assert!(salamander_open(b"wrong", &sealed).unwrap() != payload);
    }

    #[test]
    fn sing_addr_encodes() {
        let mut out = Vec::new();
        put_sing_addr_port(&mut out, &Target::Domain("example.com".into(), 443));
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], b"example.com".len() as u8);
        assert_eq!(out.len(), 1 + 1 + 11 + 2);

        let mut out = Vec::new();
        put_sing_addr_port(&mut out, &Target::Ip("1.2.3.4:53".parse().unwrap()));
        assert_eq!(out[0], 0x01);
        assert_eq!(out.len(), 1 + 4 + 2);

        let mut out = Vec::new();
        put_sing_addr_empty(&mut out);
        assert_eq!(out, vec![0xff]);
    }

    #[test]
    fn dest_string_formats() {
        assert_eq!(
            dest_string(&Target::Domain("example.com".into(), 443)),
            "example.com:443"
        );
        assert_eq!(
            dest_string(&Target::Ip("10.0.0.1:80".parse().unwrap())),
            "10.0.0.1:80"
        );
        assert_eq!(
            dest_string(&Target::Ip("[2001:db8::1]:443".parse().unwrap())),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn padding_lengths() {
        for _ in 0..32 {
            let s = random_padding(64, 512);
            assert!((64..512).contains(&s.len()));
            assert!(s.bytes().all(|b| PADDING_CHARS.contains(&b)));
        }
    }

    #[test]
    fn defragger_reassembles() {
        let mut d = Defragger::new();
        assert_eq!(
            d.feed(1, 0, 1, bytes::Bytes::from_static(b"one")),
            Some(bytes::Bytes::from_static(b"one"))
        );
        assert_eq!(d.feed(2, 0, 2, bytes::Bytes::from_static(b"ab")), None);
        assert_eq!(
            d.feed(2, 1, 2, bytes::Bytes::from_static(b"cd")),
            Some(bytes::Bytes::from_static(b"abcd"))
        );
    }
}
