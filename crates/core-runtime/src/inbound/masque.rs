//! MASQUE (RFC 9484 CONNECT-IP over HTTP/3 QUIC) server inbound.
//!
//! Accepts HTTP/3 QUIC connections, negotiates Extended CONNECT + HTTP/3
//! datagrams via SETTINGS, responds `200 OK` (`capsule-protocol: ?1`) with
//! a default `ROUTE_ADVERTISEMENT` capsule (`0.0.0.0/0` and `::/0`), and
//! bridges client CONNECT-IP datagrams into the Tachyon `Router` via the
//! shared `smoltcp` virtual TCP responder stack and `UdpHub`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use smoltcp::iface::SocketSet;
use smoltcp::time::Instant as SmolInstant;
use tokio::sync::{Notify, mpsc};

use crate::inbound::parse_listen;
use crate::inbound::tls::ServerTls;
use crate::inbound::tun::{
    TunDevice, TunTcpSession, accept_virtual_tcp_packet, build_ipv4_udp, build_ipv6_udp,
    ipv4_checksum, ipv6_icmp_checksum, new_virtual_ip_iface, pump_virtual_tcp_sessions,
};
use crate::inbound::udp::{DEFAULT_UDP_TIMEOUT, DatagramFrame, Reply, TunReply, UdpHub};
use crate::logging;
use crate::outbound::quic::{put_varint, read_varint};
use crate::route::Router;

const STREAM_CONTROL: u8 = 0x00;
const STREAM_QPACK_ENCODER: u8 = 0x02;
const STREAM_QPACK_DECODER: u8 = 0x03;

const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
const SETTINGS_H3_DATAGRAM_00: u64 = 0x276;

const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

pub struct Masque {
    tag: String,
    router: Arc<Router>,
    endpoint: quinn::Endpoint,
    socket: Weak<dyn quinn::AsyncUdpSocket>,
    local_addr: SocketAddr,
    mtu: usize,
}

impl Masque {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbounds[masque]: must be an object"))?;
        let tag = map
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("masque")
            .to_string();
        let at = format!("inbound[{tag}]");

        let (ip, port) = parse_listen(map, &at)?;
        let addr = SocketAddr::new(ip, port);

        let mtu = map
            .get("mtu")
            .and_then(Value::as_u64)
            .filter(|&m| m >= 1200)
            .map(|m| m as usize)
            .unwrap_or(1280);

        let tls_obj = obj
            .get("tls")
            .ok_or_else(|| anyhow::anyhow!("{at}: tls is required for masque inbound"))?;
        let mut server_config = ServerTls::build_quic_server_config(tls_obj, &[b"h3"], &at)?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
        ));
        transport.min_mtu(1350);
        transport.initial_mtu(1400);
        transport.mtu_discovery_config(None);
        transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
        transport.datagram_send_buffer_size(2 * 1024 * 1024);
        server_config.transport_config(Arc::new(transport));

        let runtime =
            quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("{at}: no quinn runtime"))?;
        let sock = std::net::UdpSocket::bind(addr)?;
        let sock: Arc<dyn quinn::AsyncUdpSocket> = runtime.wrap_udp_socket(sock)?;
        let socket = Arc::downgrade(&sock);
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[11u8; 32]))),
            Some(server_config),
            sock,
            runtime,
        )?;
        let local_addr = endpoint.local_addr()?;

        Ok(Self {
            tag,
            router,
            endpoint,
            socket,
            local_addr,
            mtu,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub(crate) fn shutdown_endpoint(&self) -> (quinn::Endpoint, Weak<dyn quinn::AsyncUdpSocket>) {
        (self.endpoint.clone(), self.socket.clone())
    }

    pub async fn serve(self) {
        let tag = self.tag;
        logging::info(format_args!(
            "inbound masque[{tag}] listening on {}",
            self.local_addr
        ));

        let mut connections = tokio::task::JoinSet::new();
        while let Some(incoming) = self.endpoint.accept().await {
            while connections.try_join_next().is_some() {}
            let router = Arc::clone(&self.router);
            let tag = tag.clone();
            let mtu = self.mtu;
            connections.spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        logging::debug(format_args!("masque[{tag}] quic handshake: {e}"));
                        return;
                    }
                };
                if let Err(e) = handle_masque_conn(conn, &tag, router, mtu).await {
                    logging::debug(format_args!("masque[{tag}] session ended: {e}"));
                }
            });
        }
    }
}

async fn handle_masque_conn(
    conn: quinn::Connection,
    tag: &str,
    router: Arc<Router>,
    mtu: usize,
) -> io::Result<()> {
    // 1. Open server HTTP/3 control stream and send SETTINGS enabling Extended CONNECT & Datagrams
    let mut control = conn
        .open_uni()
        .await
        .map_err(|e| io::Error::other(format!("open control stream: {e}")))?;
    let mut settings_payload = Vec::with_capacity(32);
    put_varint(&mut settings_payload, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    put_varint(&mut settings_payload, 0);
    put_varint(&mut settings_payload, SETTINGS_ENABLE_CONNECT_PROTOCOL);
    put_varint(&mut settings_payload, 1);
    put_varint(&mut settings_payload, SETTINGS_H3_DATAGRAM);
    put_varint(&mut settings_payload, 1);
    put_varint(&mut settings_payload, SETTINGS_H3_DATAGRAM_00);
    put_varint(&mut settings_payload, 1);

    let mut control_frame = Vec::with_capacity(settings_payload.len() + 8);
    control_frame.push(STREAM_CONTROL);
    put_varint(&mut control_frame, FRAME_SETTINGS);
    put_varint(&mut control_frame, settings_payload.len() as u64);
    control_frame.extend_from_slice(&settings_payload);
    control
        .write_all(&control_frame)
        .await
        .map_err(|e| io::Error::other(format!("write settings: {e}")))?;

    // Open QPACK encoder & decoder unidirectional streams (capacity 0).
    // RFC 9204 §4.2: critical streams MUST NOT be closed (no .finish()) for the life of the connection.
    let mut _qenc_holder = None;
    if let Ok(mut qenc) = conn.open_uni().await {
        let _ = qenc.write_all(&[STREAM_QPACK_ENCODER]).await;
        _qenc_holder = Some(qenc);
    }
    let mut _qdec_holder = None;
    if let Ok(mut qdec) = conn.open_uni().await {
        let _ = qdec.write_all(&[STREAM_QPACK_DECODER]).await;
        _qdec_holder = Some(qdec);
    }

    // 2. Drain client unidirectional streams in the background
    let uni_conn = conn.clone();
    let uni_task = tokio::spawn(async move {
        while let Ok(mut stream) = uni_conn.accept_uni().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(Some(n)) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });

    // 3. Accept client Extended CONNECT bidirectional stream
    let (mut req_send, mut req_recv) = conn
        .accept_bi()
        .await
        .map_err(|e| io::Error::other(format!("accept request stream: {e}")))?;

    // Read initial request frame (HEADERS)
    let mut req_buf = [0u8; 4096];
    let _ = req_recv
        .read(&mut req_buf)
        .await
        .map_err(|e| io::Error::other(format!("read request headers: {e}")))?;

    // Send 200 OK QPACK response headers:
    // Required Insert Count = 0x00, Base = 0x00, Indexed Static 25 (:status = 200 -> 0xc0 | 25 = 0xd9),
    // plus literal `capsule-protocol: ?1`
    let mut qpack_resp = vec![0x00, 0x00, 0xd9];
    let hdr_name = b"capsule-protocol";
    let hdr_val = b"?1";
    qpack_resp.push(0x20 | (hdr_name.len() as u8 & 0x07));
    if hdr_name.len() >= 7 {
        qpack_resp[3] = 0x27;
        qpack_resp.push((hdr_name.len() - 7) as u8);
    }
    qpack_resp.extend_from_slice(hdr_name);
    qpack_resp.push(hdr_val.len() as u8);
    qpack_resp.extend_from_slice(hdr_val);

    let mut resp_frame = Vec::with_capacity(qpack_resp.len() + 64);
    put_varint(&mut resp_frame, FRAME_HEADERS);
    put_varint(&mut resp_frame, qpack_resp.len() as u64);
    resp_frame.extend_from_slice(&qpack_resp);

    // Append a DATA frame containing a default ROUTE_ADVERTISEMENT capsule (0.0.0.0/0 and ::/0)
    let route_capsule = encode_default_route_capsule();
    put_varint(&mut resp_frame, FRAME_DATA);
    put_varint(&mut resp_frame, route_capsule.len() as u64);
    resp_frame.extend_from_slice(&route_capsule);

    req_send
        .write_all(&resp_frame)
        .await
        .map_err(|e| io::Error::other(format!("write response headers: {e}")))?;

    // Keep the request stream alive and drain client capsules
    let capsule_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok(Some(n)) = req_recv.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        let _ = req_send;
    });

    // 4. Data plane: bridge QUIC H3 datagrams with UdpHub and smoltcp virtual TCP stack
    let hub = UdpHub::new(Arc::clone(&router), DEFAULT_UDP_TIMEOUT, DatagramFrame::Raw);
    let _stop_hub = crate::inbound::udp::StopHub(Arc::clone(&hub));
    let (reply_tx, mut reply_rx) = mpsc::channel::<TunReply>(256);
    let dgram_conn = conn.clone();
    let udp_reply_task = tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            let pkt = match (reply.src, reply.dest) {
                (SocketAddr::V4(src_v4), SocketAddr::V4(dst_v4)) => build_ipv4_udp(
                    *src_v4.ip(),
                    *dst_v4.ip(),
                    src_v4.port(),
                    dst_v4.port(),
                    &reply.payload,
                ),
                (SocketAddr::V6(src_v6), SocketAddr::V6(dst_v6)) => build_ipv6_udp(
                    *src_v6.ip(),
                    *dst_v6.ip(),
                    src_v6.port(),
                    dst_v6.port(),
                    &reply.payload,
                ),
                _ => continue,
            };
            send_h3_ip_datagram(&dgram_conn, &pkt);
        }
    });

    let effective_mtu = conn
        .max_datagram_size()
        .map(|m| m.saturating_sub(8))
        .unwrap_or(1200)
        .min(mtu)
        .max(576);
    let mut device = TunDevice::new(effective_mtu);
    let mut iface = new_virtual_ip_iface(&mut device);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_sessions: HashMap<(SocketAddr, SocketAddr), TunTcpSession> = HashMap::new();
    let mut scratch_buf = vec![0u8; 65_536];
    let notify = Arc::new(Notify::new());

    loop {
        let now = SmolInstant::now();
        let delay = match iface.poll_at(now, &sockets) {
            Some(at) if at <= now => Duration::from_millis(1),
            Some(at) => {
                Duration::from_micros((at - now).total_micros()).min(Duration::from_millis(50))
            }
            None => Duration::from_millis(50),
        };

        tokio::select! {
            dgram_res = conn.read_datagram() => {
                let bytes = match dgram_res {
                    Ok(b) => b,
                    Err(_) => break,
                };
                // Strip Quarter-Stream-ID varint and Context-ID varint
                let Some((_qsi, n1)) = read_varint(&bytes) else {
                    continue;
                };
                let Some((ctx_id, n2)) = read_varint(&bytes[n1..]) else {
                    continue;
                };
                if ctx_id != 0 {
                    continue;
                }
                let packet = &bytes[n1 + n2..];
                handle_masque_ip_packet(
                    packet,
                    tag,
                    &router,
                    &hub,
                    &reply_tx,
                    &conn,
                    &mut device,
                    &mut sockets,
                    &mut tcp_sessions,
                    &notify,
                );
                flush_masque_tcp_stack(
                    &mut iface,
                    &mut device,
                    &mut sockets,
                    &mut tcp_sessions,
                    &mut scratch_buf,
                    &conn,
                );
            }
            _ = notify.notified() => {
                flush_masque_tcp_stack(
                    &mut iface,
                    &mut device,
                    &mut sockets,
                    &mut tcp_sessions,
                    &mut scratch_buf,
                    &conn,
                );
            }
            _ = tokio::time::sleep(delay) => {
                flush_masque_tcp_stack(
                    &mut iface,
                    &mut device,
                    &mut sockets,
                    &mut tcp_sessions,
                    &mut scratch_buf,
                    &conn,
                );
            }
        }
    }

    uni_task.abort();
    capsule_task.abort();
    udp_reply_task.abort();
    Ok(())
}

fn flush_masque_tcp_stack(
    iface: &mut smoltcp::iface::Interface,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    tcp_sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    scratch_buf: &mut [u8],
    conn: &quinn::Connection,
) {
    pump_virtual_tcp_sessions(iface, device, sockets, tcp_sessions, scratch_buf);
    while let Some(pkt) = device.tx_queue.pop_front() {
        send_h3_ip_datagram(conn, &pkt);
    }
}

fn send_h3_ip_datagram(conn: &quinn::Connection, ip_pkt: &[u8]) {
    let mut wire = Vec::with_capacity(ip_pkt.len() + 2);
    wire.push(0x00); // QSI = 0
    wire.push(0x00); // Context ID = 0
    wire.extend_from_slice(ip_pkt);
    let _ = conn.send_datagram(Bytes::from(wire));
}

#[allow(clippy::too_many_arguments)]
fn handle_masque_ip_packet(
    packet: &[u8],
    tag: &str,
    router: &Arc<Router>,
    hub: &Arc<UdpHub>,
    reply_tx: &mpsc::Sender<TunReply>,
    conn: &quinn::Connection,
    device: &mut TunDevice,
    sockets: &mut SocketSet<'static>,
    tcp_sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    notify: &Arc<Notify>,
) {
    if packet.is_empty() {
        return;
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let ihl = ((packet[0] & 0x0f) * 4) as usize;
            if ihl < 20 || packet.len() < ihl {
                return;
            }
            let proto = packet[9];
            let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            match proto {
                1 if packet.len() >= ihl + 8 => {
                    if packet[ihl] == 8 && packet[ihl + 1] == 0 {
                        let mut reply_pkt = packet.to_vec();
                        reply_pkt[12..16].copy_from_slice(&dst_ip.octets());
                        reply_pkt[16..20].copy_from_slice(&src_ip.octets());
                        reply_pkt[10] = 0;
                        reply_pkt[11] = 0;
                        let ip_csum = ipv4_checksum(&reply_pkt[..ihl]);
                        reply_pkt[10] = (ip_csum >> 8) as u8;
                        reply_pkt[11] = ip_csum as u8;
                        reply_pkt[ihl] = 0;
                        reply_pkt[ihl + 2] = 0;
                        reply_pkt[ihl + 3] = 0;
                        let icmp_csum = ipv4_checksum(&reply_pkt[ihl..]);
                        reply_pkt[ihl + 2] = (icmp_csum >> 8) as u8;
                        reply_pkt[ihl + 3] = icmp_csum as u8;
                        send_h3_ip_datagram(conn, &reply_pkt);
                    }
                }
                17 if packet.len() >= ihl + 8 => {
                    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
                    if udp_len >= 8 && packet.len() >= ihl + udp_len {
                        let payload = &packet[ihl + 8..ihl + udp_len];
                        let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
                        let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
                        if !hub.try_existing(source, dest, payload) {
                            let payload = payload.to_vec();
                            let hub = Arc::clone(hub);
                            let reply = Reply::Tun {
                                sender: reply_tx.clone(),
                            };
                            let tag = tag.to_string();
                            tokio::spawn(async move {
                                let _ = hub.handle(reply, source, dest, &payload, &tag).await;
                            });
                        }
                    }
                }
                6 if packet.len() >= ihl + 20 => {
                    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                    let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
                    let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
                    let tcp_flags = packet[ihl + 13];
                    let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;
                    accept_virtual_tcp_packet(
                        packet,
                        source,
                        dest,
                        is_syn,
                        tag,
                        router,
                        device,
                        sockets,
                        tcp_sessions,
                        notify,
                    );
                }
                _ => {}
            }
        }
        6 if packet.len() >= 40 => {
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&packet[24..40]);
            let src_ip = Ipv6Addr::from(src_bytes);
            let dst_ip = Ipv6Addr::from(dst_bytes);
            let proto = packet[6];
            let payload = &packet[40..];
            match proto {
                58 if payload.len() >= 8 => {
                    if payload[0] == 128 && payload[1] == 0 {
                        let mut reply_pkt = packet.to_vec();
                        reply_pkt[8..24].copy_from_slice(&dst_ip.octets());
                        reply_pkt[24..40].copy_from_slice(&src_ip.octets());
                        reply_pkt[40] = 129;
                        reply_pkt[42] = 0;
                        reply_pkt[43] = 0;
                        let csum = ipv6_icmp_checksum(dst_ip, src_ip, &reply_pkt[40..]);
                        reply_pkt[42] = (csum >> 8) as u8;
                        reply_pkt[43] = csum as u8;
                        send_h3_ip_datagram(conn, &reply_pkt);
                    }
                }
                17 if payload.len() >= 8 => {
                    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
                    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
                    let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                    if udp_len >= 8 && payload.len() >= udp_len {
                        let data = &payload[8..udp_len];
                        let source = SocketAddr::new(IpAddr::V6(src_ip), src_port);
                        let dest = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
                        if !hub.try_existing(source, dest, data) {
                            let data = data.to_vec();
                            let hub = Arc::clone(hub);
                            let reply = Reply::Tun {
                                sender: reply_tx.clone(),
                            };
                            let tag = tag.to_string();
                            tokio::spawn(async move {
                                let _ = hub.handle(reply, source, dest, &data, &tag).await;
                            });
                        }
                    }
                }
                6 if payload.len() >= 20 => {
                    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
                    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
                    let source = SocketAddr::new(IpAddr::V6(src_ip), src_port);
                    let dest = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
                    let tcp_flags = payload[13];
                    let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;
                    accept_virtual_tcp_packet(
                        packet,
                        source,
                        dest,
                        is_syn,
                        tag,
                        router,
                        device,
                        sockets,
                        tcp_sessions,
                        notify,
                    );
                }
                _ => {}
            }
        }
        _ => {}
    }
}

fn encode_default_route_capsule() -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    // IPv4 0.0.0.0 .. 255.255.255.255, proto 0
    payload.push(4);
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&[255, 255, 255, 255]);
    payload.push(0);
    // IPv6 :: .. ffff:ffff:..., proto 0
    payload.push(6);
    payload.extend_from_slice(&[0u8; 16]);
    payload.extend_from_slice(&[0xffu8; 16]);
    payload.push(0);

    let mut capsule = Vec::with_capacity(payload.len() + 4);
    put_varint(&mut capsule, CAPSULE_ROUTE_ADVERTISEMENT);
    put_varint(&mut capsule, payload.len() as u64);
    capsule.extend_from_slice(&payload);
    capsule
}
