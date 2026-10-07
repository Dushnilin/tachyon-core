//! tuic v5 outbound: EKM auth over a uni stream, heartbeat datagrams, eager
//! TCP CONNECT header, native datagram or uni-stream UDP relay with
//! fragmentation (reference sing-quic tuic client).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::time::Duration;

use serde_json::Value;

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::inbound::{AnyStream, Target, network_includes_tcp, network_includes_udp};
use crate::logging;
use crate::outbound::proxy::server_endpoint;
use crate::outbound::quic::{
    CongestionKind, Defragger, POOL_MAX_CONNS, POOL_STREAMS_PER_CONN, PoolLease, QuicStream,
    QuicTunnelDefaults, QuicTunnelOptions, TUIC_MAX_UDP, bind_udp, io_from_datagram, io_from_quinn,
    put_sing_addr_empty, put_sing_addr_port, resolve_host, sing_addr_port_len, udp_loopback_pair,
};
use crate::outbound::uot::{UOT_DEFAULT_VERSION, magic_authority, request_header, spawn_bridge};
use crate::outbound::urltest::parse_duration;
use crate::tls_client::TlsOptions;
use tokio::io::AsyncWriteExt;

const TUIC_VERSION: u8 = 5;
const CMD_AUTHENTICATE: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_PACKET: u8 = 2;
const CMD_DISSOCIATE: u8 = 3;
const CMD_HEARTBEAT: u8 = 4;
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT: Duration = Duration::from_secs(5);
const MAX_ADDRESS: usize = 2048;

pub struct Tuic {
    server: String,
    port: u16,
    uuid: [u8; 16],
    password: String,
    congestion: CongestionKind,
    udp_stream: bool,
    /// `udp_over_stream`: relay datagrams over a CONNECT stream carrying the
    /// udp-over-tcp framing, instead of a QUIC stream
    udp_over_stream: bool,
    zero_rtt: bool,
    heartbeat: Duration,
    want_tcp: bool,
    want_udp: bool,
    quic: QuicTunnelOptions,
    tls: TlsOptions,
    connect_timeout: Duration,
    shared: tokio::sync::Mutex<Vec<Arc<TuicShared>>>,
}

impl Tuic {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let uuid_raw = obj
            .get("uuid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing uuid"))?;
        let uuid = crate::outbound::vmess::kdf::parse_uuid(uuid_raw)
            .map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?
            .to_string();

        let congestion = match obj
            .get("congestion_control")
            .and_then(Value::as_str)
            .unwrap_or("")
        {
            "" | "cubic" => CongestionKind::Cubic,
            "new_reno" => CongestionKind::NewReno,
            "bbr" => CongestionKind::Bbr,
            other => anyhow::bail!("{at}: unknown congestion control algorithm: {other}"),
        };

        let udp_relay_mode = obj
            .get("udp_relay_mode")
            .and_then(Value::as_str)
            .unwrap_or("");
        let udp_stream = match udp_relay_mode {
            "" | "native" => false,
            "quic" => true,
            other => anyhow::bail!("{at}: unknown udp_relay_mode: {other}"),
        };
        let udp_over_stream = obj
            .get("udp_over_stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // the reference rejects the pair even for the default `native`
        if udp_over_stream && !udp_relay_mode.is_empty() {
            anyhow::bail!("{at}: udp_over_stream is conflict with udp_relay_mode");
        }

        let zero_rtt = obj
            .get("zero_rtt_handshake")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let heartbeat = parse_duration(
            obj.get("heartbeat"),
            DEFAULT_HEARTBEAT,
            &format!("{at}.heartbeat"),
        )?;

        let tls = TlsOptions::from_outbound(obj, &server, at)?
            .ok_or_else(|| anyhow::anyhow!("{at}: TLS is required for tuic"))?;
        let quic = QuicTunnelOptions::parse(obj, at, QuicTunnelDefaults::tuic())?;
        let connect_timeout = parse_duration(
            obj.get("connect_timeout"),
            DEFAULT_CONNECT,
            &format!("{at}.connect_timeout"),
        )?;

        Ok(Self {
            server,
            port,
            uuid,
            password,
            congestion,
            udp_stream,
            udp_over_stream,
            zero_rtt,
            heartbeat,
            want_tcp: network_includes_tcp(obj),
            want_udp: network_includes_udp(obj),
            quic,
            tls,
            connect_timeout,
            shared: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    async fn shared(&self) -> io::Result<Arc<TuicShared>> {
        let mut pool = self.shared.lock().await;
        pool.retain(|s| s.conn.close_reason().is_none());
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

    async fn dial(&self) -> io::Result<Arc<TuicShared>> {
        tokio::time::timeout(
            self.connect_timeout + Duration::from_secs(1),
            self.dial_inner(),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic: dial timeout"))?
    }

    async fn dial_inner(&self) -> io::Result<Arc<TuicShared>> {
        let addr = resolve_host(&self.server, self.port).await?;
        let sock = bind_udp(addr)?;
        let (ep_config, transport) = self.quic.build_configs(self.congestion, None, true);
        let mut endpoint = quinn::Endpoint::new(
            ep_config,
            None,
            sock,
            quinn::default_runtime().ok_or_else(|| io::Error::other("tuic: no quinn runtime"))?,
        )?;
        let quic_tls = self.tls.quic_config(&[])?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(addr, self.tls.server_name())
            .map_err(|e| io::Error::other(format!("tuic: {e}")))?;

        let conn = if self.zero_rtt {
            match connecting.into_0rtt() {
                Ok((conn, accepted)) => {
                    let _ = tokio::time::timeout(self.connect_timeout, accepted)
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "tuic: 0-RTT handshake timeout")
                        })?;
                    conn
                }
                Err(connecting) => tokio::time::timeout(self.connect_timeout, connecting)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "tuic: handshake timeout")
                    })?
                    .map_err(|e| io::Error::other(format!("tuic: {e}")))?,
            }
        } else {
            tokio::time::timeout(self.connect_timeout, connecting)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic: handshake timeout"))?
                .map_err(|e| io::Error::other(format!("tuic: {e}")))?
        };

        tokio::time::timeout(
            self.connect_timeout,
            tuic_auth(&conn, &self.uuid, &self.password),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic: auth timeout"))
        .and_then(|r| r)
        .inspect_err(|_| {
            endpoint.close(quinn::VarInt::from_u32(0), b"");
        })?;

        let heartbeat_handle = spawn_heartbeat(conn.clone(), self.heartbeat);
        Ok(Arc::new(TuicShared {
            endpoint,
            conn,
            udp_stream: self.udp_stream,
            heartbeat_handle,
            next_session: AtomicU16::new(0),
            sessions: std::sync::Mutex::new(HashMap::new()),
            demux: std::sync::Mutex::new(None),
            uni: std::sync::Mutex::new(None),
            handles: std::sync::Mutex::new(Vec::new()),
            leases: Arc::new(AtomicU32::new(0)),
        }))
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if !self.want_tcp {
            return Err(io::Error::other("tuic: tcp not enabled in network field"));
        }
        let shared = self.shared().await?;
        let lease = PoolLease::new(Arc::clone(&shared.leases));
        let (send, recv) = tokio::time::timeout(self.connect_timeout, shared.conn.open_bi())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic: open_bi timeout"))?
            .map_err(io_from_quinn)?;
        let mut head = Vec::with_capacity(2 + sing_addr_port_len(target));
        head.push(TUIC_VERSION);
        head.push(CMD_CONNECT);
        put_sing_addr_port(&mut head, target);
        let mut send = send;
        tokio::time::timeout(self.connect_timeout, send.write_all(&head))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "tuic: write connect timeout")
            })??;
        Ok(Box::new(QuicStream::with_lease(send, recv, lease)))
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        if !self.want_udp {
            return Err(io::Error::other("tuic: udp not enabled in network field"));
        }
        if self.udp_over_stream {
            return self.connect_udp_over_stream(target).await;
        }
        let shared = self.shared().await?;
        let lease = PoolLease::new(Arc::clone(&shared.leases));
        let (local, peer) = udp_loopback_pair().await?;
        let sid = shared.next_session.fetch_add(1, Ordering::Relaxed);
        let peer = Arc::new(peer);
        let session = Arc::new(TuicUdpSession {
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
        let target_f = target.clone();
        let sess_f = Arc::clone(&session);
        let peer_f = Arc::clone(&peer);
        let handle = tokio::spawn(async move {
            let _lease = lease;
            let mut buf = vec![0u8; 65_535];
            loop {
                match tokio::time::timeout(DEFAULT_UDP_TIMEOUT, peer_f.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if let Err(e) =
                            send_tuic_datagram(&shared_f, sid, &target_f, &buf[..n], &sess_f).await
                        {
                            logging::debug(format_args!("tuic udp send {sid}: {e}"));
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        logging::debug(format_args!("tuic udp recv {sid}: {e}"));
                        break;
                    }
                    Err(_) => break,
                }
            }
            shared_f.sessions.lock().expect("sessions").remove(&sid);
            let mut out = Vec::with_capacity(4);
            out.push(TUIC_VERSION);
            out.push(CMD_DISSOCIATE);
            out.extend_from_slice(&sid.to_be_bytes());
            let _ = shared_f.conn.send_datagram(out.into());
        });
        shared.handles.lock().expect("handles").push(handle);
        Ok(local)
    }

    /// `udp_over_stream`: a CONNECT stream to the udp-over-tcp magic address,
    /// then the request header and bare datagrams on that stream.
    async fn connect_udp_over_stream(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let (local, peer) = udp_loopback_pair().await?;
        let mut stream = self
            .connect(&Target::Domain(
                magic_authority(UOT_DEFAULT_VERSION).to_string(),
                0,
            ))
            .await?;
        stream.write_all(&request_header(false, target)?).await?;
        spawn_bridge(stream, peer);
        Ok(local)
    }
}

struct TuicShared {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    udp_stream: bool,
    heartbeat_handle: tokio::task::JoinHandle<()>,
    next_session: AtomicU16,
    sessions: std::sync::Mutex<HashMap<u16, Arc<TuicUdpSession>>>,
    demux: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    uni: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    leases: Arc<AtomicU32>,
}

impl TuicShared {
    fn start_demux(self: &Arc<Self>) {
        let shared = Arc::clone(self);
        let handle = tokio::spawn(async move {
            loop {
                let Ok(data) = shared.conn.read_datagram().await else {
                    break;
                };
                handle_tuic_message(&shared, data);
            }
        });
        *self.demux.lock().expect("demux") = Some(handle);

        if self.udp_stream {
            let shared_u = Arc::clone(self);
            let handle = tokio::spawn(async move {
                while let Ok(mut stream) = shared_u.conn.accept_uni().await {
                    let shared2 = Arc::clone(&shared_u);
                    tokio::spawn(async move {
                        let mut head = [0u8; 2];
                        if stream.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        if head[0] != TUIC_VERSION || head[1] != CMD_PACKET {
                            return;
                        }
                        let body = match stream.read_to_end(MAX_ADDRESS).await {
                            Ok(b) => b,
                            Err(_) => return,
                        };
                        handle_tuic_packet_body(&shared2, bytes::Bytes::from(body)).await;
                    });
                }
            });
            *self.uni.lock().expect("uni") = Some(handle);
        }
    }
}

impl Drop for TuicShared {
    fn drop(&mut self) {
        if let Some(h) = self.demux.lock().expect("demux").take() {
            h.abort();
        }
        if let Some(h) = self.uni.lock().expect("uni").take() {
            h.abort();
        }
        for h in self.handles.lock().expect("handles").drain(..) {
            h.abort();
        }
        self.heartbeat_handle.abort();
        self.conn.close(quinn::VarInt::from_u32(0), b"");
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

struct TuicUdpSession {
    sock: Arc<tokio::net::UdpSocket>,
    defragger: std::sync::Mutex<Defragger>,
    packet_id: AtomicU32,
}

async fn tuic_auth(conn: &quinn::Connection, uuid: &[u8; 16], password: &str) -> io::Result<()> {
    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, uuid, password.as_bytes())
        .map_err(|e| io::Error::other(format!("tuic: export keying material: {e:?}")))?;
    let mut send = conn.open_uni().await.map_err(io_from_quinn)?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(TUIC_VERSION);
    auth.push(CMD_AUTHENTICATE);
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&ekm);
    send.write_all(&auth).await?;
    send.finish()?;
    Ok(())
}

fn spawn_heartbeat(conn: quinn::Connection, period: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + period,
            if period.is_zero() {
                DEFAULT_HEARTBEAT
            } else {
                period
            },
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if conn
                        .send_datagram(vec![TUIC_VERSION, CMD_HEARTBEAT].into())
                        .is_err()
                    {
                        break;
                    }
                }
                _ = conn.closed() => break,
            }
        }
    })
}

fn handle_tuic_message(shared: &Arc<TuicShared>, data: bytes::Bytes) {
    if data.len() < 2 || data[0] != TUIC_VERSION {
        return;
    }
    match data[1] {
        CMD_PACKET => {
            let shared = Arc::clone(shared);
            let body = data.slice(2..);
            tokio::spawn(async move {
                handle_tuic_packet_body(&shared, body).await;
            });
        }
        CMD_HEARTBEAT => {}
        _ => {}
    }
}

async fn handle_tuic_packet_body(shared: &Arc<TuicShared>, body: bytes::Bytes) {
    let Some((sid, pid, frag_id, frag_total, payload)) = parse_tuic_packet(&body) else {
        return;
    };
    let session = shared.sessions.lock().expect("sessions").get(&sid).cloned();
    let Some(session) = session else {
        return;
    };
    // share the message instead of copying the payload out of it — bounded
    // by the parsed length: a datagram may carry trailing bytes the parser
    // does not consider part of the fragment
    let len = payload.len();
    let offset = payload.as_ptr() as usize - body.as_ptr() as usize;
    let payload = body.slice(offset..offset + len);
    let complete = {
        let mut defrag = session.defragger.lock().expect("defrag");
        defrag.feed(pid, frag_id, frag_total, payload)
    };
    if let Some(pkt) = complete {
        let _ = session.sock.send(&pkt).await;
    }
}

fn parse_tuic_packet(body: &[u8]) -> Option<(u16, u16, u8, u8, &[u8])> {
    if body.len() < 8 {
        return None;
    }
    let sid = u16::from_be_bytes(body[0..2].try_into().ok()?);
    let pid = u16::from_be_bytes(body[2..4].try_into().ok()?);
    let frag_total = body[4];
    let frag_id = body[5];
    let data_len = u16::from_be_bytes(body[6..8].try_into().ok()?) as usize;
    let rest = &body[8..];
    let addr_len = skip_sing_addr(rest)?;
    if rest.len() < addr_len + data_len {
        return None;
    }
    Some((
        sid,
        pid,
        frag_id,
        frag_total,
        &rest[addr_len..addr_len + data_len],
    ))
}

fn skip_sing_addr(buf: &[u8]) -> Option<usize> {
    let family = *buf.first()?;
    match family {
        0x00 => {
            let len = usize::from(*buf.get(1)?);
            if len == 0 || len > MAX_ADDRESS || buf.len() < 2 + len + 2 {
                return None;
            }
            Some(2 + len + 2)
        }
        0x01 => (buf.len() >= 7).then_some(7),
        0x02 => (buf.len() >= 19).then_some(19),
        0xff => Some(1),
        _ => None,
    }
}

fn next_packet_id(counter: &AtomicU32) -> u16 {
    let n = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    (n % 65_535) as u16
}

fn pack_tuic(
    sid: u16,
    pid: u16,
    frag_total: u8,
    frag_id: u8,
    target: &Target,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + sing_addr_port_len(target) + data.len());
    out.push(TUIC_VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&pid.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    put_sing_addr_port(&mut out, target);
    out.extend_from_slice(data);
    out
}

fn pack_tuic_cont(sid: u16, pid: u16, frag_total: u8, frag_id: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(11 + data.len());
    out.push(TUIC_VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&pid.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    put_sing_addr_empty(&mut out);
    out.extend_from_slice(data);
    out
}

async fn send_tuic_datagram(
    shared: &TuicShared,
    sid: u16,
    target: &Target,
    payload: &[u8],
    sess: &TuicUdpSession,
) -> io::Result<()> {
    if payload.len() > TUIC_MAX_UDP {
        return Err(io::Error::other("tuic: udp payload exceeds 0xffff"));
    }
    let pid = next_packet_id(&sess.packet_id);
    let addr_len = sing_addr_port_len(target);
    let header_len = 10 + addr_len;
    let budget = shared.conn.max_datagram_size().unwrap_or(1197);

    if !shared.udp_stream {
        if payload.len() + header_len <= budget {
            let pkt = pack_tuic(sid, pid, 1, 0, target, payload);
            match shared.conn.send_datagram(pkt.into()) {
                Ok(()) => return Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => {}
                Err(e) => return Err(io_from_datagram(e)),
            }
        }
        let max_data = budget.saturating_sub(header_len).max(1);
        let chunks: Vec<&[u8]> = payload.chunks(max_data).collect();
        if chunks.len() > 255 {
            return Err(io::Error::other(
                "tuic: udp packet needs too many fragments",
            ));
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let pkt = if i == 0 {
                pack_tuic(sid, pid, chunks.len() as u8, i as u8, target, chunk)
            } else {
                pack_tuic_cont(sid, pid, chunks.len() as u8, i as u8, chunk)
            };
            shared
                .conn
                .send_datagram(pkt.into())
                .map_err(io_from_datagram)?;
        }
        return Ok(());
    }

    let max_data = TUIC_MAX_UDP.min(budget.saturating_sub(11)).max(1);
    let chunks: Vec<&[u8]> = payload.chunks(max_data).collect();
    if chunks.len() > 255 {
        return Err(io::Error::other(
            "tuic: udp packet needs too many fragments",
        ));
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let pkt = if i == 0 {
            pack_tuic(sid, pid, chunks.len() as u8, i as u8, target, chunk)
        } else {
            pack_tuic_cont(sid, pid, chunks.len() as u8, i as u8, chunk)
        };
        let mut send = shared.conn.open_uni().await.map_err(io_from_quinn)?;
        send.write_all(&pkt).await?;
        send.finish()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tuic_packet_roundtrip() {
        let target = Target::Domain("example.com".into(), 443);
        let packed = pack_tuic(3, 4, 1, 0, &target, b"abc");
        assert_eq!(packed[0], 5);
        assert_eq!(packed[1], 2);
        let body = &packed[2..];
        let parsed = parse_tuic_packet(body).expect("parse");
        assert_eq!(parsed.0, 3);
        assert_eq!(parsed.1, 4);
        assert_eq!(parsed.2, 0);
        assert_eq!(parsed.3, 1);
        assert_eq!(parsed.4, b"abc");
    }

    #[test]
    fn tuic_cont_packet_has_empty_addr() {
        let packed = pack_tuic_cont(1, 1, 2, 1, b"xy");
        let body = &packed[2..];
        let parsed = parse_tuic_packet(body).expect("parse");
        assert_eq!(parsed.4, b"xy");
        assert_eq!(body[8], 0xff);
    }

    #[test]
    fn skip_addr_families() {
        let mut v4 = vec![0x01, 1, 2, 3, 4, 0, 80];
        assert_eq!(skip_sing_addr(&v4), Some(7));
        v4.push(0);
        assert_eq!(skip_sing_addr(&[0xff]), Some(1));
        let mut fqdn = vec![0x00, 3];
        fqdn.extend_from_slice(b"abc");
        fqdn.extend_from_slice(&[1, 0]);
        assert_eq!(skip_sing_addr(&fqdn), Some(7));
    }

    #[test]
    fn packet_id_matches_reference() {
        let c = AtomicU32::new(0);
        assert_eq!(next_packet_id(&c), 1);
        c.store(65_534, Ordering::Relaxed);
        assert_eq!(next_packet_id(&c), 0);
    }

    fn options(extra: &[(&str, Value)]) -> serde_json::Map<String, Value> {
        let mut obj = json!({
            "type": "tuic",
            "tag": "t",
            "server": "example.com",
            "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "secret",
            "tls": {"enabled": true, "server_name": "example.com"},
        })
        .as_object()
        .expect("object")
        .clone();
        for (key, value) in extra {
            obj.insert((*key).to_string(), value.clone());
        }
        obj
    }

    #[test]
    fn udp_over_stream_is_accepted() {
        let tuic = Tuic::build(
            &options(&[("udp_over_stream", json!(true))]),
            "outbounds[0]",
        )
        .expect("build");
        assert!(tuic.udp_over_stream);
        assert!(!tuic.udp_stream, "the two relay modes stay exclusive");
    }

    #[test]
    fn udp_over_stream_conflicts_with_udp_relay_mode() {
        // the reference rejects the pair even when the mode is the default
        for mode in ["native", "quic"] {
            let err = match Tuic::build(
                &options(&[
                    ("udp_over_stream", json!(true)),
                    ("udp_relay_mode", json!(mode)),
                ]),
                "outbounds[0]",
            ) {
                Ok(_) => panic!("udp_over_stream + udp_relay_mode must be rejected"),
                Err(error) => error.to_string(),
            };
            assert!(err.contains("udp_over_stream is conflict"), "got {err}");
        }
    }

    #[test]
    fn the_udp_over_stream_request_names_the_target() {
        let target = Target::Domain("dns.example.com".into(), 53);
        let header = request_header(false, &target).expect("header");
        assert_eq!(header[0], 0, "a relay request, not a connect request");
        assert_eq!(&header[1..3], &[0x02, 15], "domain with its length");
        assert_eq!(&header[3..18], b"dns.example.com");
        assert_eq!(&header[18..], &53u16.to_be_bytes());
    }
}
