//! hysteria2 outbound: shared lazy QUIC dial, HTTP/3 password auth, eager TCP
//! request header with lazy-compatible response read, datagram UDP relay with
//! fragmentation and two-socket salamander obfs (reference sing-quic client).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::Value;

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target, network_includes_tcp, network_includes_udp};
use crate::logging;
use crate::outbound::proxy::server_endpoint;
use crate::outbound::quic::{
    CongestionKind, Defragger, HY2_MAX_UDP, MBPS_TO_BPS, POOL_MAX_CONNS, POOL_STREAMS_PER_CONN,
    PoolLease, QuicStream, QuicTunnelDefaults, QuicTunnelOptions, SalamanderRelay, VarintReader,
    bind_udp, bind_udp_loopback, dest_string, io_from_datagram, io_from_quinn,
    pick_port_from_ranges, put_varint, random_padding, read_varint, resolve_host, spawn_hop_relay,
    udp_loopback_pair,
};
use crate::outbound::urltest::parse_duration;
use crate::tls_client::TlsOptions;

pub(crate) const AUTH_STATUS_OK: u16 = 233;
pub(crate) const FRAME_TCP_REQUEST: u64 = 0x401;
pub(crate) const MAX_ADDRESS: usize = 2048;
const MAX_MESSAGE: usize = 2048;
const MAX_PADDING: usize = 4096;
const DEFAULT_HANDSHAKE: Duration = Duration::from_secs(15);
const DEFAULT_CONNECT: Duration = Duration::from_secs(5);

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

pub struct Hysteria2 {
    server: String,
    port: u16,
    server_port_ranges: Vec<(u16, u16)>,
    hop_interval: Duration,
    hop_interval_max: Option<Duration>,
    password: String,
    receive_bps: u64,
    send_bps: u64,
    want_tcp: bool,
    want_udp: bool,
    obfs_password: Option<Vec<u8>>,
    /// `obfs.type: gecko` adds a fragmentation layer on top of salamander
    gecko: Option<(usize, usize)>,
    quic: QuicTunnelOptions,
    tls: TlsOptions,
    connect_timeout: Duration,
    shared: tokio::sync::Mutex<Vec<Arc<Hy2Shared>>>,
}

impl Hysteria2 {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;

        if obj
            .get("realm")
            .is_some_and(|v| v.as_object().is_some_and(|m| !m.is_empty()))
        {
            anyhow::bail!("{at}: realm is not implemented yet");
        }

        let mut gecko_sizes = None;
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
                    "gecko" => {
                        let pw = m.get("password").and_then(Value::as_str).unwrap_or("");
                        if pw.is_empty() {
                            anyhow::bail!("{at}: missing obfs password");
                        }
                        gecko_sizes = Some((
                            m.get("min_packet_size")
                                .and_then(Value::as_u64)
                                .unwrap_or(0) as usize,
                            m.get("max_packet_size")
                                .and_then(Value::as_u64)
                                .unwrap_or(0) as usize,
                        ));
                        // the reference rejects the range before dialling
                        let (min, max) = gecko_sizes.expect("gecko sizes");
                        let max = if max == 0 { 1200 } else { max };
                        let min = if min == 0 { 512 } else { min };
                        if min > max || max > 2048 {
                            anyhow::bail!("{at}: gecko packet size range {min}-{max} is invalid");
                        }
                        Some(pw.as_bytes().to_vec())
                    }
                    other => anyhow::bail!("{at}: unknown obfs type: {other}"),
                }
            }
            Some(_) => anyhow::bail!("{at}: obfs must be an object"),
        };

        let (server_port_ranges, port) = if let Some(ports) = obj.get("server_ports") {
            let mut ranges = Vec::new();
            let list = match ports {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for r in list {
                let (start, end) =
                    if let Some((a, b)) = r.split_once(':').or_else(|| r.split_once('-')) {
                        if let (Ok(s), Ok(e)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                            (s, e)
                        } else {
                            continue;
                        }
                    } else if let Ok(p) = r.trim().parse::<u16>() {
                        (p, p)
                    } else {
                        continue;
                    };
                if start > 0 && end >= start {
                    ranges.push((start, end));
                }
            }
            let first_port = ranges.first().map(|&(s, _)| s).unwrap_or(port);
            (ranges, first_port)
        } else {
            (Vec::new(), port)
        };

        let hop_interval = if !server_port_ranges.is_empty() {
            parse_duration(
                obj.get("hop_interval"),
                Duration::from_secs(30),
                &format!("{at}.hop_interval"),
            )?
        } else {
            parse_duration(
                obj.get("hop_interval"),
                Duration::ZERO,
                &format!("{at}.hop_interval"),
            )?
        };

        let hop_interval_max = if let Some(v) = obj.get("hop_interval_max") {
            Some(parse_duration(
                Some(v),
                hop_interval,
                &format!("{at}.hop_interval_max"),
            )?)
        } else {
            None
        };

        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?
            .to_string();

        let down_mbps = obj.get("down_mbps").and_then(Value::as_u64).unwrap_or(0);
        let receive_bps = down_mbps.saturating_mul(MBPS_TO_BPS);
        let up_mbps = obj.get("up_mbps").and_then(Value::as_u64).unwrap_or(0);
        let send_bps = up_mbps.saturating_mul(MBPS_TO_BPS);
        let brutal_debug = obj.get("brutal_debug").and_then(Value::as_bool) == Some(true);
        if send_bps > 0 && brutal_debug {
            logging::info(format_args!(
                "{at}: using hysteria brutal congestion control ({up_mbps} Mbps)"
            ));
        }
        if let Some(p) = obj.get("bbr_profile").and_then(Value::as_str)
            && !p.is_empty()
            && p != "standard"
        {
            logging::warn(format_args!(
                "{at}: bbr_profile {p:?} not implemented; using standard"
            ));
        }

        let tls = TlsOptions::from_outbound(obj, &server, at)?
            .ok_or_else(|| anyhow::anyhow!("{at}: TLS is required for hysteria2"))?;
        let quic = QuicTunnelOptions::parse(obj, at, QuicTunnelDefaults::hysteria2())?;
        let connect_timeout = parse_duration(
            obj.get("connect_timeout"),
            DEFAULT_CONNECT,
            &format!("{at}.connect_timeout"),
        )?;

        Ok(Self {
            server,
            port,
            server_port_ranges,
            hop_interval,
            hop_interval_max,
            password,
            receive_bps,
            send_bps,
            want_tcp: network_includes_tcp(obj),
            want_udp: network_includes_udp(obj),
            obfs_password,
            gecko: gecko_sizes,
            quic,
            tls,
            connect_timeout,
            shared: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    fn pick_port(&self) -> u16 {
        if self.server_port_ranges.is_empty() {
            self.port
        } else {
            pick_port_from_ranges(&self.server_port_ranges)
        }
    }

    fn next_hop_interval(&self) -> Duration {
        match self.hop_interval_max {
            Some(max) if max > self.hop_interval => {
                let range_ms = (max - self.hop_interval).as_millis() as u64;
                if range_ms > 0 {
                    let mut b = [0u8; 8];
                    let _ = getrandom::fill(&mut b);
                    let add_ms = u64::from_le_bytes(b) % range_ms;
                    self.hop_interval + Duration::from_millis(add_ms)
                } else {
                    self.hop_interval
                }
            }
            _ => self.hop_interval,
        }
    }

    async fn shared(&self) -> io::Result<Arc<Hy2Shared>> {
        let mut pool = self.shared.lock().await;
        let now = std::time::Instant::now();
        pool.retain(|s| {
            s.conn.close_reason().is_none() && s.hop_deadline.is_none_or(|dl| now < dl)
        });
        let best = pool
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.leases.load(Ordering::Relaxed));
        let shared = match best {
            Some((i, s))
                if s.leases.load(Ordering::Relaxed) < POOL_STREAMS_PER_CONN
                    || pool.len() >= POOL_MAX_CONNS =>
            {
                Arc::clone(&pool[i])
            }
            _ => {
                let s = self.dial().await?;
                s.start_demux();
                pool.push(Arc::clone(&s));
                Arc::clone(pool.last().expect("pushed"))
            }
        };
        Ok(shared)
    }

    async fn dial(&self) -> io::Result<Arc<Hy2Shared>> {
        let port = self.pick_port();
        let addr = resolve_host(&self.server, port).await?;
        let need_relay = !self.server_port_ranges.is_empty() || self.obfs_password.is_some();
        let sock = if need_relay {
            bind_udp_loopback(addr.is_ipv4())?
        } else {
            bind_udp(addr)?
        };
        let congestion = if self.send_bps > 0 {
            CongestionKind::Brutal(self.send_bps)
        } else {
            CongestionKind::Bbr
        };
        let (ep_config, transport) = self.quic.build_configs(congestion, None, self.want_udp);
        let mut endpoint = quinn::Endpoint::new(
            ep_config,
            None,
            sock,
            quinn::default_runtime()
                .ok_or_else(|| io::Error::other("hysteria2: no quinn runtime"))?,
        )?;
        let quic_tls = self.tls.quic_config(&[b"h3"])?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);

        let relay = if need_relay {
            let hop_interval = (!self.server_port_ranges.is_empty()).then_some(self.hop_interval);
            let relay = spawn_hop_relay(
                addr.ip(),
                self.server_port_ranges.clone(),
                port,
                hop_interval,
                self.hop_interval_max,
                self.obfs_password.clone(),
                self.gecko,
                endpoint.local_addr()?,
            )
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: relay: {e}")))?;
            Some(relay)
        } else {
            None
        };
        let target = relay.as_ref().map(|r| r.local).unwrap_or(addr);

        let connecting = endpoint
            .connect(target, self.tls.server_name())
            .map_err(|e| io::Error::other(format!("hysteria2: {e}")))?;
        let conn = tokio::time::timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "hysteria2: connect timeout after {:?}",
                        self.connect_timeout
                    ),
                )
            })?
            .map_err(|e| io::Error::other(format!("hysteria2: {e}")))?;

        let auth = tokio::time::timeout(
            DEFAULT_HANDSHAKE,
            h3_auth(&conn, &self.password, self.receive_bps),
        )
        .await;
        let (server_udp, send_request, driver) = match auth {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                endpoint.close(quinn::VarInt::from_u32(0), b"");
                return Err(e);
            }
            Err(_) => {
                endpoint.close(quinn::VarInt::from_u32(0), b"");
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "hysteria2: auth timeout",
                ));
            }
        };

        let udp_enabled = server_udp && self.want_udp;
        let hop_deadline = if !self.server_port_ranges.is_empty() {
            Some(std::time::Instant::now() + self.next_hop_interval())
        } else {
            None
        };

        Ok(Arc::new(Hy2Shared {
            endpoint,
            conn,
            _send_request: send_request,
            _h3_driver: driver,
            _relay: relay,
            hop_deadline,
            udp_enabled,
            next_session: AtomicU32::new(0),
            sessions: std::sync::Mutex::new(HashMap::new()),
            demux: std::sync::Mutex::new(None),
            handles: std::sync::Mutex::new(Vec::new()),
            leases: Arc::new(AtomicU32::new(0)),
        }))
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if !self.want_tcp {
            return Err(io::Error::other(
                "hysteria2: tcp not enabled in network field",
            ));
        }
        let shared = self.shared().await?;
        let lease = PoolLease::new(Arc::clone(&shared.leases));
        let (send, mut recv) = shared.conn.open_bi().await.map_err(io_from_quinn)?;

        let dest = dest_string(target);
        if dest.len() > MAX_ADDRESS {
            return Err(io::Error::other("hysteria2: destination too long"));
        }
        let padding = random_padding(64, 512);
        let mut head = Vec::with_capacity(16 + dest.len() + padding.len());
        put_varint(&mut head, FRAME_TCP_REQUEST);
        put_varint(&mut head, dest.len() as u64);
        head.extend_from_slice(dest.as_bytes());
        put_varint(&mut head, padding.len() as u64);
        head.extend_from_slice(padding.as_bytes());

        let mut send = send;
        send.write_all(&head).await?;
        read_tcp_response(&mut recv).await?;
        Ok(Box::new(QuicStream::with_lease(send, recv, lease)))
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        if !self.want_udp {
            return Err(io::Error::other(
                "hysteria2: udp not enabled in network field",
            ));
        }
        let shared = self.shared().await?;
        let lease = PoolLease::new(Arc::clone(&shared.leases));
        if !shared.udp_enabled {
            return Err(io::Error::other("hysteria2: UDP disabled by server"));
        }
        let dest = dest_string(target);
        if dest.len() > MAX_ADDRESS {
            return Err(io::Error::other("hysteria2: destination too long"));
        }

        let (local, peer) = udp_loopback_pair().await?;
        let sid = shared.next_session.fetch_add(1, Ordering::Relaxed);
        let peer = Arc::new(peer);
        let session = Arc::new(UdpSession {
            sock: Arc::clone(&peer),
            defragger: std::sync::Mutex::new(Defragger::new()),
            packet_id: AtomicU32::new(0),
        });
        shared
            .sessions
            .lock()
            .expect("sessions")
            .insert(sid, Arc::clone(&session));

        let shared_f = Arc::clone(&shared);
        let dest_f = dest.clone();
        let sess_f = Arc::clone(&session);
        let peer_f = Arc::clone(&peer);
        let handle = tokio::spawn(async move {
            let _lease = lease;
            let mut buf = vec![0u8; 65_535];
            loop {
                match tokio::time::timeout(DEFAULT_UDP_TIMEOUT, peer_f.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if let Err(e) =
                            send_hy2_datagram(&shared_f.conn, sid, &dest_f, &buf[..n], &sess_f)
                        {
                            logging::debug(format_args!("hysteria2 udp send {sid}: {e}"));
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        logging::debug(format_args!("hysteria2 udp recv {sid}: {e}"));
                        break;
                    }
                    Err(_) => break,
                }
            }
            shared_f.sessions.lock().expect("sessions").remove(&sid);
            let mut out = Vec::with_capacity(4);
            out.push(5);
            out.push(3);
            out.extend_from_slice(&sid.to_be_bytes());
            let _ = shared_f.conn.send_datagram(out.into());
        });
        shared.handles.lock().expect("handles").push(handle);
        Ok(local)
    }
}

struct Hy2Shared {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    _send_request: H3SendRequest,
    _h3_driver: tokio::task::JoinHandle<()>,
    _relay: Option<SalamanderRelay>,
    hop_deadline: Option<std::time::Instant>,
    udp_enabled: bool,
    next_session: AtomicU32,
    sessions: std::sync::Mutex<HashMap<u32, Arc<UdpSession>>>,
    demux: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    leases: Arc<AtomicU32>,
}

impl Hy2Shared {
    fn start_demux(self: &Arc<Self>) {
        if !self.udp_enabled {
            return;
        }
        let shared = Arc::clone(self);
        let handle = tokio::spawn(async move {
            loop {
                let Ok(data) = shared.conn.read_datagram().await else {
                    break;
                };
                let Some((sid, pid, fid, ftot, _dest, payload)) = parse_hy2_packet(&data) else {
                    continue;
                };
                let session = shared.sessions.lock().expect("sessions").get(&sid).cloned();
                let Some(session) = session else {
                    continue;
                };
                // share the datagram instead of copying the payload out of it
                let payload = data.slice(payload.as_ptr() as usize - data.as_ptr() as usize..);
                let complete = {
                    let mut defrag = session.defragger.lock().expect("defrag");
                    defrag.feed(pid, fid, ftot, payload)
                };
                if let Some(pkt) = complete {
                    let _ = session.sock.send(&pkt).await;
                }
            }
        });
        *self.demux.lock().expect("demux") = Some(handle);
    }
}

impl Drop for Hy2Shared {
    fn drop(&mut self) {
        if let Some(h) = self.demux.lock().expect("demux").take() {
            h.abort();
        }
        for h in self.handles.lock().expect("handles").drain(..) {
            h.abort();
        }
        self._h3_driver.abort();
        self.conn.close(quinn::VarInt::from_u32(0), b"");
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

struct UdpSession {
    sock: Arc<tokio::net::UdpSocket>,
    defragger: std::sync::Mutex<Defragger>,
    packet_id: AtomicU32,
}

fn go_parse_bool(s: &str) -> bool {
    matches!(s, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

async fn h3_auth(
    conn: &quinn::Connection,
    password: &str,
    receive_bps: u64,
) -> io::Result<(bool, H3SendRequest, tokio::task::JoinHandle<()>)> {
    let h3 = h3_quinn::Connection::new(conn.clone());
    let (mut connection, mut send_request) = h3::client::new(h3)
        .await
        .map_err(|e| io::Error::other(format!("hysteria2: http/3 handshake: {e}")))?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", receive_bps.to_string())
        .header("Hysteria-Padding", random_padding(256, 2048))
        .body(())
        .map_err(|e| io::Error::other(format!("hysteria2: auth request: {e}")))?;

    let response = async {
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: auth send: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: auth finish: {e}")))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: auth response: {e}")))?;
        while let Some(_chunk) = stream
            .recv_data()
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: auth body: {e}")))?
        {}
        let _ = stream.recv_trailers().await;
        Ok::<_, io::Error>(response)
    }
    .await;

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            driver.abort();
            conn.close(quinn::VarInt::from_u32(0), b"");
            return Err(e);
        }
    };
    let status = response.status().as_u16();
    if status != AUTH_STATUS_OK {
        driver.abort();
        conn.close(quinn::VarInt::from_u32(0), b"");
        return Err(io::Error::other(format!(
            "hysteria2: authentication failed, status code: {status}"
        )));
    }
    let udp_enabled = response
        .headers()
        .get("Hysteria-UDP")
        .and_then(|v| v.to_str().ok())
        .map(go_parse_bool)
        .unwrap_or(false);
    Ok((udp_enabled, send_request, driver))
}

pub(crate) async fn read_varint_stream(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut vr = VarintReader::default();
    let mut byte = [0u8; 1];
    loop {
        recv.read_exact(&mut byte)
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: read varint: {e}")))?;
        if let Some(v) = vr.push(byte[0]) {
            return Ok(v);
        }
    }
}

pub(crate) async fn read_exact_vec(recv: &mut quinn::RecvStream, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut off = 0;
    while off < n {
        let read = recv
            .read(&mut buf[off..])
            .await
            .map_err(|e| io::Error::other(format!("hysteria2: read: {e}")))?;
        let Some(read) = read else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "hysteria2: stream closed mid-response",
            ));
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "hysteria2: stream closed mid-response",
            ));
        }
        off += read;
    }
    Ok(buf)
}

async fn read_tcp_response(recv: &mut quinn::RecvStream) -> io::Result<()> {
    let mut status = [0u8; 1];
    recv.read_exact(&mut status)
        .await
        .map_err(|e| io::Error::other(format!("hysteria2: read status: {e}")))?;
    let msg_len = read_varint_stream(recv).await? as usize;
    if msg_len > MAX_MESSAGE {
        return Err(io::Error::other("hysteria2: invalid message length"));
    }
    let msg = read_exact_vec(recv, msg_len).await?;
    let pad_len = read_varint_stream(recv).await? as usize;
    if pad_len > MAX_PADDING {
        return Err(io::Error::other("hysteria2: invalid padding length"));
    }
    let _pad = read_exact_vec(recv, pad_len).await?;
    if status[0] != 0 {
        return Err(io::Error::other(format!(
            "hysteria2: remote error: {}",
            String::from_utf8_lossy(&msg)
        )));
    }
    Ok(())
}

fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

pub(crate) fn next_packet_id(counter: &AtomicU32) -> u16 {
    let n = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    (n % 65_535) as u16
}

pub(crate) fn pack_hy2(
    sid: u32,
    pid: u16,
    frag_id: u8,
    frag_total: u8,
    dest: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + varint_len(dest.len() as u64) + dest.len() + data.len());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&pid.to_be_bytes());
    out.push(frag_id);
    out.push(frag_total);
    put_varint(&mut out, dest.len() as u64);
    out.extend_from_slice(dest.as_bytes());
    out.extend_from_slice(data);
    out
}

pub(crate) fn parse_hy2_packet(data: &[u8]) -> Option<Hy2Packet<'_>> {
    if data.len() < 8 {
        return None;
    }
    let sid = u32::from_be_bytes(data[0..4].try_into().ok()?);
    let pid = u16::from_be_bytes(data[4..6].try_into().ok()?);
    let frag_id = data[6];
    let frag_total = data[7];
    let (dest_len, n) = read_varint(&data[8..])?;
    let dest_len = dest_len as usize;
    if dest_len == 0 || dest_len > MAX_ADDRESS {
        return None;
    }
    let start = 8 + n;
    if data.len() < start + dest_len {
        return None;
    }
    let dest = std::str::from_utf8(&data[start..start + dest_len]).ok()?;
    Some((
        sid,
        pid,
        frag_id,
        frag_total,
        dest,
        &data[start + dest_len..],
    ))
}

pub(crate) type Hy2Packet<'a> = (u32, u16, u8, u8, &'a str, &'a [u8]);

fn send_hy2_datagram(
    conn: &quinn::Connection,
    sid: u32,
    dest: &str,
    payload: &[u8],
    sess: &UdpSession,
) -> io::Result<()> {
    send_hy2_packet(conn, sid, dest, payload, &sess.packet_id)
}

/// The same MTU-aware framing is required for UDP replies from a server.
pub(crate) fn send_hy2_packet(
    conn: &quinn::Connection,
    sid: u32,
    dest: &str,
    payload: &[u8],
    packet_counter: &AtomicU32,
) -> io::Result<()> {
    if payload.len() > HY2_MAX_UDP {
        return Err(io::Error::other("hysteria2: udp payload exceeds 4096"));
    }
    let pid = next_packet_id(packet_counter);
    let header_len = 8 + varint_len(dest.len() as u64) + dest.len();
    let mut budget = conn.max_datagram_size().unwrap_or(1197);
    if payload.len() + header_len <= budget {
        let pkt = pack_hy2(sid, pid, 0, 1, dest, payload);
        match conn.send_datagram(pkt.into()) {
            Ok(()) => return Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                budget = budget.saturating_sub(64).max(header_len + 1);
            }
            Err(e) => return Err(io_from_datagram(e)),
        }
    }
    let max_data = budget.saturating_sub(header_len).max(1);
    let chunks: Vec<&[u8]> = payload.chunks(max_data).collect();
    if chunks.len() > 255 {
        return Err(io::Error::other(
            "hysteria2: udp packet needs too many fragments",
        ));
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let pkt = pack_hy2(sid, pid, i as u8, chunks.len() as u8, dest, chunk);
        conn.send_datagram(pkt.into()).map_err(io_from_datagram)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hy2_packet_roundtrip() {
        let packed = pack_hy2(7, 9, 0, 1, "example.com:443", b"payload");
        let parsed = parse_hy2_packet(&packed).expect("parse");
        assert_eq!(parsed.0, 7);
        assert_eq!(parsed.1, 9);
        assert_eq!(parsed.2, 0);
        assert_eq!(parsed.3, 1);
        assert_eq!(parsed.4, "example.com:443");
        assert_eq!(parsed.5, b"payload");
    }

    #[test]
    fn hy2_packet_parse_rejects_short() {
        assert!(parse_hy2_packet(&[0, 0, 0]).is_none());
        assert!(parse_hy2_packet(b"").is_none());
    }

    #[test]
    fn go_bool_parse() {
        assert!(go_parse_bool("true"));
        assert!(go_parse_bool("1"));
        assert!(!go_parse_bool("false"));
        assert!(!go_parse_bool(""));
    }

    #[test]
    fn packet_id_cycles_like_reference() {
        let c = AtomicU32::new(0);
        assert_eq!(next_packet_id(&c), 1);
        assert_eq!(next_packet_id(&c), 2);
        c.store(65_534, Ordering::Relaxed);
        assert_eq!(next_packet_id(&c), 0);
    }
}
