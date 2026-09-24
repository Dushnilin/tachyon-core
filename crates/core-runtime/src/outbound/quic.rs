//! Shared QUIC plumbing for hysteria2 / tuic: transport options, endpoint
//! construction without ring-gated helpers, salamander obfs relay, varint and
//! sing address codecs, padding, and a stream duplex adapter.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::VarInt;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CongestionKind {
    Bbr,
    Cubic,
    NewReno,
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
        transport.datagram_receive_buffer_size(datagram_rx.then_some(65_536));
        transport.datagram_send_buffer_size(65_536);
        transport.congestion_controller_factory(match congestion {
            CongestionKind::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            CongestionKind::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            CongestionKind::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
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

/// Two-socket salamander relay in front of a quinn endpoint.
///
/// * `sock_ep` — loopback, connected to the endpoint's local addr (plaintext side).
/// * `sock_srv` — wildcard, connected to the real server (sealed side).
///
/// Returns the loopback address quinn should `connect()` to, plus task handles.
pub(crate) struct SalamanderRelay {
    pub local: SocketAddr,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for SalamanderRelay {
    fn drop(&mut self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

pub(crate) async fn spawn_salamander_relay(
    server: SocketAddr,
    password: Vec<u8>,
    endpoint_local: SocketAddr,
) -> io::Result<SalamanderRelay> {
    let ep_bind = if server.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let sock_ep = Arc::new(tokio::net::UdpSocket::bind(ep_bind).await?);
    sock_ep.connect(endpoint_local).await?;
    let local = sock_ep.local_addr()?;

    let srv_bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock_srv = Arc::new(tokio::net::UdpSocket::bind(srv_bind).await?);
    sock_srv.connect(server).await?;

    let pw_up = password.clone();
    let sock_ep_up = Arc::clone(&sock_ep);
    let sock_srv_up = Arc::clone(&sock_srv);
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok(n) = sock_ep_up.recv(&mut buf).await else {
                break;
            };
            let sealed = salamander_seal(&pw_up, &buf[..n]);
            if sock_srv_up.send(&sealed).await.is_err() {
                break;
            }
        }
    });
    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok(n) = sock_srv.recv(&mut buf).await else {
                break;
            };
            let Some(plain) = salamander_open(&password, &buf[..n]) else {
                continue;
            };
            if sock_ep.send(&plain).await.is_err() {
                break;
            }
        }
    });
    Ok(SalamanderRelay {
        local,
        handles: vec![up, down],
    })
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

/// Bind a nonblocking UDP socket for a quinn endpoint.
pub(crate) fn bind_udp(local: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let bind = if local.is_ipv4() {
        SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    };
    let sock = std::net::UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
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
    Ok(sock)
}

/// Bidirectional quinn stream exposed as [`crate::inbound::AnyStream`].
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
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
pub(crate) struct Defragger {
    // packet_id → (total, slots)
    items: std::collections::HashMap<u16, FragSlots>,
}

type FragSlots = (u8, Vec<Option<Vec<u8>>>);

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
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
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
            let mut out = Vec::new();
            for slot in slots {
                out.extend(slot?);
            }
            return Some(out);
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
        assert_eq!(d.feed(1, 0, 1, b"one".to_vec()), Some(b"one".to_vec()));
        assert_eq!(d.feed(2, 0, 2, b"ab".to_vec()), None);
        assert_eq!(d.feed(2, 1, 2, b"cd".to_vec()), Some(b"abcd".to_vec()));
    }
}
