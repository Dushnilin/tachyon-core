//! Minimal HTTP/3 client for the MASQUE CONNECT-IP tunnel.
//!
//! The `h3` crate cannot express an arbitrary `:protocol` (its `Protocol`
//! enum is a hardcoded webtransport/connect-udp pair), so the HTTP/3 layer a
//! CONNECT-IP client actually needs is implemented here directly on top of
//! quinn: control stream + SETTINGS, static-only QPACK (the client declares
//! table capacity 0, so static references are RFC-correct for both
//! directions), extended CONNECT request/response, DATA-frame capsules and
//! QUIC datagrams. Mirrors `transport/masque/masque.go` +
//! `transport/masque/connectip`.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use super::connectip::{
    CAPSULE_ADDRESS_ASSIGN, CAPSULE_ADDRESS_REQUEST, CAPSULE_ROUTE_ADVERTISEMENT, MIN_MTU, Prefix,
    Route, compose_datagram, compose_icmp_too_large, encode_route_advertisement,
    parse_address_assign, parse_context_id, parse_route_advertisement, snapshot_head,
    validate_incoming,
};
use super::hpack::Field;
use super::profile::Profile;
use super::qpack::{qpack_decode, qpack_encode};
use super::tls::MasqueTls;
use crate::outbound::quic::{bind_udp, put_varint, read_varint};

// HTTP/3 frame types (RFC 9114 §7.2).
const FRAME_DATA: u64 = 0x0;
const FRAME_HEADERS: u64 = 0x1;
const FRAME_SETTINGS: u64 = 0x4;
const FRAME_GOAWAY: u64 = 0x7;

// HTTP/3 unidirectional stream types (RFC 9114 §6.2).
const STREAM_CONTROL: u8 = 0x00;
const STREAM_PUSH: u8 = 0x01;
const STREAM_QPACK_ENCODER: u8 = 0x02;
const STREAM_QPACK_DECODER: u8 = 0x03;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
// The official WARP client still advertises the deprecated
// SETTINGS_H3_DATAGRAM_00; WARP expects it (reference masque.go).
const SETTINGS_H3_DATAGRAM_00: u64 = 0x276;

const INITIAL_MTU: u16 = 1400;
/// Memory quinn keeps for its datagram queue.
const DATAGRAM_BUFFER: usize = 2 * 1024 * 1024;
const STREAM_WINDOW: u64 = 8 << 20;
const CONNECTION_WINDOW: u64 = 16 << 20;
/// Bound for a single buffered frame payload (stream windows cap this).
const MAX_FRAME_PAYLOAD: usize = 8 << 20;
/// Capsule payloads carry at most an IP packet (reference `maxCapsulePayload`).
const MAX_CAPSULE_PAYLOAD: usize = 65_535;

/// Established CONNECT-IP tunnel over HTTP/3.
pub(crate) struct H3Conn {
    conn: quinn::Connection,
    endpoint: quinn::Endpoint,
    send: AsyncMutex<quinn::SendStream>,
    _control: quinn::SendStream,
    _qpack_enc: quinn::SendStream,
    _qpack_dec: quinn::SendStream,
    rx: mpsc::Receiver<Vec<u8>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Tunnel policy state shared between the capsule and datagram tasks:
/// locally assigned addresses (address-assign capsule) and the routes we
/// advertised (also used to validate incoming destinations).
#[derive(Default)]
struct TunnelState {
    assigned: RwLock<Vec<Prefix>>,
    local_routes: RwLock<Vec<Route>>,
    available_routes: RwLock<Vec<Route>>,
}

/// Parsed pieces of the CONNECT-IP request URI.
struct ConnectUri {
    authority: String,
    scheme: String,
    path: String,
}

impl H3Conn {
    /// Dial `server`, run the HTTP/3 handshake (control settings + extended
    /// CONNECT) and advertise the default route. `handshake_budget` caps the
    /// QUIC handshake only — the socket dial may be slow on its own and the
    /// CONNECT-IP exchange runs unbounded under the caller's context
    /// (reference `connectH3WithBudget`).
    pub(crate) async fn connect(
        tls: &MasqueTls,
        profile: &Profile,
        uri: &str,
        server: SocketAddr,
        keep_alive: Option<Duration>,
        handshake_budget: Option<Duration>,
    ) -> io::Result<H3Conn> {
        let request = parse_connect_uri(uri)?;

        let sock = bind_udp(server)?;
        let mut reset = [0u8; 32];
        crate::outbound::shadowsocks::crypto::random_bytes(&mut reset)?;
        let endpoint_config = quinn::EndpointConfig::new(Arc::new(
            crate::outbound::quic::HmacSha256Wrapper::new(&reset),
        ));
        let mut endpoint = quinn::Endpoint::new(
            endpoint_config,
            None,
            sock,
            quinn::default_runtime()
                .ok_or_else(|| io::Error::other("masque h3: no quinn runtime"))?,
        )?;

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(keep_alive);
        transport.min_mtu(1350);
        transport.initial_mtu(INITIAL_MTU);
        transport.mtu_discovery_config(None);
        transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
        transport.datagram_send_buffer_size(DATAGRAM_BUFFER);
        transport.stream_receive_window(quinn::VarInt::from_u64(STREAM_WINDOW).unwrap());
        transport.receive_window(quinn::VarInt::from_u64(CONNECTION_WINDOW).unwrap());
        let quic_tls = tls
            .quic_config()
            .map_err(|e| io::Error::other(format!("masque h3: tls config: {e}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);

        // A disabled SNI still needs a syntactic server name; the custom
        // verifier never consults it (and IP names carry no SNI extension).
        let sni = if tls.server_name().is_empty() {
            "0.0.0.0"
        } else {
            tls.server_name()
        };
        let connecting = endpoint
            .connect(server, sni)
            .map_err(|e| io::Error::other(format!("masque h3: {e}")))?;
        let conn = match handshake_budget {
            Some(budget) => tokio::time::timeout(budget, connecting)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "masque h3: QUIC handshake timed out",
                    )
                })?
                .map_err(|e| io::Error::other(format!("masque h3: dial quic: {e}")))?,
            None => connecting
                .await
                .map_err(|e| io::Error::other(format!("masque h3: dial quic: {e}")))?,
        };

        // Client control stream first (RFC 9114 §6.1), then the two QPACK
        // streams. We declare an empty dynamic table, so no encoder/decoder
        // instructions ever follow the type byte.
        let mut control = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::other(format!("masque h3: open control stream: {e}")))?;
        let mut settings_payload = Vec::new();
        put_varint(&mut settings_payload, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        put_varint(&mut settings_payload, 0);
        put_varint(&mut settings_payload, SETTINGS_H3_DATAGRAM);
        put_varint(&mut settings_payload, 1);
        put_varint(&mut settings_payload, SETTINGS_H3_DATAGRAM_00);
        put_varint(&mut settings_payload, 1);
        let mut control_write = Vec::with_capacity(settings_payload.len() + 16);
        control_write.push(STREAM_CONTROL);
        put_varint(&mut control_write, FRAME_SETTINGS);
        put_varint(&mut control_write, settings_payload.len() as u64);
        control_write.extend_from_slice(&settings_payload);
        control
            .write_all(&control_write)
            .await
            .map_err(|e| io::Error::other(format!("masque h3: write settings: {e}")))?;

        let mut qpack_enc = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::other(format!("masque h3: open qpack stream: {e}")))?;
        qpack_enc
            .write_all(&[STREAM_QPACK_ENCODER])
            .await
            .map_err(|e| io::Error::other(format!("masque h3: write qpack stream: {e}")))?;
        let mut qpack_dec = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::other(format!("masque h3: open qpack stream: {e}")))?;
        qpack_dec
            .write_all(&[STREAM_QPACK_DECODER])
            .await
            .map_err(|e| io::Error::other(format!("masque h3: write qpack stream: {e}")))?;

        // Accept the server's unidirectional streams; the control stream
        // yields the SETTINGS that gate the request. Everything up to the
        // response runs in one fallable block so a failed handshake still
        // tears the connection down (the accept task alone would linger).
        let (settings_tx, settings_rx) = oneshot::channel();
        let accept_conn = conn.clone();
        let accept_task = tokio::spawn(accept_uni_streams(accept_conn, settings_tx));

        let setup = async {
            let settings = tokio::select! {
                settings = settings_rx => settings.map_err(|_| {
                    io::Error::other("masque h3: control stream closed before SETTINGS")
                })?,
                closed = conn.closed() => {
                    return Err(io::Error::other(format!(
                        "masque h3: connection closed: {closed}"
                    )));
                }
            };
            if !profile.ignore_extended_connect
                && settings.get(&SETTINGS_ENABLE_CONNECT_PROTOCOL) != Some(&1)
            {
                return Err(io::Error::other(
                    "connect-ip: server didn't enable Extended CONNECT",
                ));
            }
            let datagrams_enabled = settings.get(&SETTINGS_H3_DATAGRAM) == Some(&1)
                || settings.get(&SETTINGS_H3_DATAGRAM_00) == Some(&1);
            if !datagrams_enabled {
                return Err(io::Error::other(
                    "connect-ip: server didn't enable datagrams",
                ));
            }

            // Extended CONNECT request on a fresh bidirectional stream.
            let (send, recv) = conn
                .open_bi()
                .await
                .map_err(|e| io::Error::other(format!("masque h3: open request stream: {e}")))?;
            let fields = [
                Field::new(":method", "CONNECT"),
                Field::new(":protocol", profile.request_protocol),
                Field::new(":scheme", &request.scheme),
                Field::new(":path", &request.path),
                Field::new(":authority", &request.authority),
                Field::new("capsule-protocol", "?1"),
                // The official WARP client sends an empty User-Agent.
                Field::new("user-agent", ""),
            ];
            let block = qpack_encode(&fields);
            let mut head = Vec::with_capacity(block.len() + 8);
            put_varint(&mut head, FRAME_HEADERS);
            put_varint(&mut head, block.len() as u64);
            head.extend_from_slice(&block);
            let mut send = send;
            send.write_all(&head)
                .await
                .map_err(|e| io::Error::other(format!("masque h3: send request headers: {e}")))?;

            // Response: HEADERS with a final status (skip informational 1xx).
            let mut reader = FrameReader::new(recv);
            let status = loop {
                let (frame_type, payload) = reader.next().await?.ok_or_else(|| {
                    io::Error::other("masque h3: read response: connection closed")
                })?;
                if frame_type != FRAME_HEADERS {
                    continue;
                }
                let fields = qpack_decode(&payload).map_err(|e| {
                    io::Error::other(format!("masque h3: decode response headers: {e:?}"))
                })?;
                let Some(status_line) = fields.iter().find(|f| f.name == ":status") else {
                    return Err(io::Error::other(
                        "masque h3: response has no :status header",
                    ));
                };
                let status: u16 = status_line.value.parse().map_err(|_| {
                    io::Error::other(format!(
                        "masque h3: malformed :status {:?}",
                        status_line.value
                    ))
                })?;
                if (100..200).contains(&status) {
                    continue;
                }
                break status;
            };
            if !(200..=299).contains(&status) {
                return Err(io::Error::other(format!(
                    "connect-ip: server responded with {status}"
                )));
            }
            Ok::<_, io::Error>((send, reader))
        };
        let (mut send, mut reader) = match setup.await {
            Ok(pair) => pair,
            Err(e) => {
                accept_task.abort();
                conn.close(quinn::VarInt::from_u32(0), b"");
                endpoint.close(quinn::VarInt::from_u32(0), b"");
                return Err(e);
            }
        };

        // Tunnel policy: validate incoming destinations against our assigned
        // addresses plus the default routes we are about to advertise.
        let state = Arc::new(TunnelState::default());
        let default_routes = default_routes();
        *state.local_routes.write().unwrap() = default_routes.to_vec();

        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        let datagram_task = tokio::spawn(datagram_loop(conn.clone(), Arc::clone(&state), tx));

        // Capsule reader: address assignments / server routes / teardown on
        // the unsupported or unknown capsule (reference `readFromStream`).
        let capsule_conn = conn.clone();
        let capsule_state = Arc::clone(&state);
        let capsule_task = tokio::spawn(async move {
            let result = capsule_loop(&mut reader, &capsule_state).await;
            if let Err(e) = result {
                crate::logging::debug(format_args!("masque h3: capsule stream: {e}"));
            }
            // Any capsule-stream end (clean or not) means the tunnel is gone:
            // closing the connection cascades to the datagram task and the
            // packet pump.
            capsule_conn.close(quinn::VarInt::from_u32(0), b"");
        });

        let tasks = vec![accept_task, datagram_task, capsule_task];

        // Advertise the default route (reference `advertiseDefaultRoute`):
        // the h2 shim does no route advertisement, the h3 path requires it
        // before the endpoint routes anything our way.
        let capsule = encode_route_advertisement(&default_routes);
        let mut data_frame = Vec::with_capacity(capsule.len() + 4);
        put_varint(&mut data_frame, FRAME_DATA);
        put_varint(&mut data_frame, capsule.len() as u64);
        data_frame.extend_from_slice(&capsule);
        if let Err(e) = send.write_all(&data_frame).await {
            for task in &tasks {
                task.abort();
            }
            conn.close(quinn::VarInt::from_u32(0), b"");
            endpoint.close(quinn::VarInt::from_u32(0), b"");
            return Err(io::Error::other(format!(
                "masque h3: advertise routes: {e}"
            )));
        }

        Ok(H3Conn {
            conn,
            endpoint,
            send: AsyncMutex::new(send),
            _control: control,
            _qpack_enc: qpack_enc,
            _qpack_dec: qpack_dec,
            rx,
            tasks,
        })
    }

    /// Next validated inbound IP packet.
    pub(crate) async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| io::Error::other("masque h3: tunnel closed"))
    }

    pub(crate) fn try_read_packet(&mut self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }

    /// Send one outbound IP packet as an HTTP datagram. Returns an ICMP
    /// packet-too-big reply to inject locally when the datagram does not
    /// fit the path. Compose failures (short packet, TTL<=1, unknown
    /// version) drop the packet silently (reference `WritePacket`).
    pub(crate) async fn write_packet(&mut self, pkt: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
        if pkt.is_empty() {
            return Ok(None);
        }
        let orig = snapshot_head(pkt);
        let mut data = match compose_datagram(pkt) {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };
        let mut wire = Vec::with_capacity(data.len() + 1);
        put_varint(&mut wire, 0); // quarter stream id of our request stream
        wire.append(&mut data);
        match self.conn.send_datagram(Bytes::from(wire)) {
            Ok(()) => Ok(None),
            Err(quinn::SendDatagramError::TooLarge) => {
                Ok(compose_icmp_too_large(&orig, MIN_MTU).ok())
            }
            Err(e) => Err(io::Error::other(format!("masque h3: send datagram: {e}"))),
        }
    }

    /// Tear down the tunnel: abort tasks, close the connection and the
    /// endpoint (drops the UDP socket).
    pub(crate) fn close(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        self.conn.close(quinn::VarInt::from_u32(0), b"");
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

impl Drop for H3Conn {
    fn drop(&mut self) {
        self.close();
    }
}

/// The default route advertisement: all IPv4 and IPv6 traffic (reference
/// `advertiseDefaultRoute`).
fn default_routes() -> [Route; 2] {
    [
        Route {
            start: Ipv4Addr::UNSPECIFIED.into(),
            end: Ipv4Addr::BROADCAST.into(),
            proto: 0,
        },
        Route {
            start: Ipv6Addr::UNSPECIFIED.into(),
            end: Ipv6Addr::new(
                u16::MAX,
                u16::MAX,
                u16::MAX,
                u16::MAX,
                u16::MAX,
                u16::MAX,
                u16::MAX,
                u16::MAX,
            )
            .into(),
            proto: 0,
        },
    ]
}

/// Receive the server's unidirectional streams: parse SETTINGS off the
/// control stream, drain QPACK/push/unknown streams (RFC 9114 §6.2: unknown
/// stream types are discarded).
async fn accept_uni_streams(
    conn: quinn::Connection,
    settings_tx: oneshot::Sender<HashMap<u64, u64>>,
) {
    let mut settings_tx = Some(settings_tx);
    loop {
        let mut stream = match conn.accept_uni().await {
            Ok(stream) => stream,
            Err(_) => break,
        };
        let mut kind = [0u8; 1];
        let read = stream.read(&mut kind).await;
        let kind = match read {
            Ok(Some(_)) => kind[0],
            Ok(None) | Err(_) => break,
        };
        match kind {
            STREAM_CONTROL => {
                let settings = control_settings(stream, settings_tx.take()).await;
                match settings {
                    Ok(true) => continue, // SETTINGS delivered; keep reading (GOAWAY)
                    Ok(false) | Err(_) => break,
                }
            }
            STREAM_PUSH | STREAM_QPACK_ENCODER | STREAM_QPACK_DECODER => {
                tokio::spawn(drain_stream(stream));
            }
            _ => {
                // Unknown stream type: discard its data.
                tokio::spawn(drain_stream(stream));
            }
        }
    }
    // The accept loop ended (connection gone or control stream closed);
    // cascade into the rest of the tunnel.
    conn.close(quinn::VarInt::from_u32(0), b"");
}

/// Read frames off the control stream until EOF/GOAWAY. Returns whether the
/// SETTINGS frame was delivered.
async fn control_settings(
    stream: quinn::RecvStream,
    mut settings_tx: Option<oneshot::Sender<HashMap<u64, u64>>>,
) -> io::Result<bool> {
    let mut reader = FrameReader::new(stream);
    let mut delivered = false;
    while let Some((frame_type, payload)) = reader.next().await? {
        match frame_type {
            FRAME_SETTINGS if !delivered => {
                let settings = parse_settings(&payload)?;
                if let Some(tx) = settings_tx.take() {
                    let _ = tx.send(settings);
                }
                delivered = true;
            }
            FRAME_GOAWAY => break,
            _ => {} // MAX_PUSH_ID and reserved frames are ignored
        }
    }
    Ok(delivered)
}

async fn drain_stream(mut stream: quinn::RecvStream) {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(Some(0)) => continue,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

/// Receive proxied packets: strip the quarter-stream-id, then the context-ID
/// varint, validate against the tunnel policy and hand them to the pump.
/// Malformed or disallowed datagrams are dropped, never fatal
/// (reference `ReadPacket`).
async fn datagram_loop(
    conn: quinn::Connection,
    state: Arc<TunnelState>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    loop {
        let bytes = match conn.read_datagram().await {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        let Some((qsi, n)) = read_varint(&bytes) else {
            continue;
        };
        if qsi != 0 {
            // Only our request stream (id 0 -> QSI 0) carries packets.
            continue;
        }
        let Ok(packet) = parse_context_id(&bytes[n..]) else {
            continue;
        };
        {
            let assigned = state.assigned.read().unwrap();
            let routes = state.local_routes.read().unwrap();
            if validate_incoming(packet, &assigned, &routes, None).is_err() {
                continue;
            }
        }
        if tx.send(packet.to_vec()).await.is_err() {
            break;
        }
    }
}

/// Consume capsules from the request stream: address assignments and server
/// route advertisements update the policy; an address request or an unknown
/// capsule type tears the tunnel down (reference `readFromStream`).
async fn capsule_loop(reader: &mut FrameReader, state: &TunnelState) -> io::Result<()> {
    let mut buf = Vec::new();
    while let Some((frame_type, payload)) = reader.next().await? {
        if frame_type != FRAME_DATA {
            continue;
        }
        buf.extend_from_slice(&payload);
        while let Some((capsule_type, payload)) = take_capsule(&mut buf)? {
            match capsule_type {
                CAPSULE_ADDRESS_ASSIGN => {
                    let addresses = parse_address_assign(&payload).map_err(|e| {
                        io::Error::other(format!("connect-ip: bad address assignment: {e}"))
                    })?;
                    let prefixes = addresses
                        .into_iter()
                        .map(|a| Prefix::new(a.addr, a.prefix_len))
                        .collect();
                    *state.assigned.write().unwrap() = prefixes;
                }
                CAPSULE_ADDRESS_REQUEST => {
                    return Err(io::Error::other(
                        "connect-ip: address request not yet supported",
                    ));
                }
                CAPSULE_ROUTE_ADVERTISEMENT => {
                    let routes = parse_route_advertisement(&payload).map_err(|e| {
                        io::Error::other(format!("connect-ip: bad route advertisement: {e}"))
                    })?;
                    *state.available_routes.write().unwrap() = routes;
                }
                other => {
                    return Err(io::Error::other(format!("unknown capsule type: {other}")));
                }
            }
        }
    }
    Err(io::Error::other("connect-ip: request stream closed"))
}

/// Pop one complete capsule from the buffer head. `Ok(None)` means the
/// buffer holds a partial capsule; a declared payload over
/// [`MAX_CAPSULE_PAYLOAD`] is a protocol violation.
pub(super) fn take_capsule(buf: &mut Vec<u8>) -> io::Result<Option<(u64, Vec<u8>)>> {
    let rest: &[u8] = buf;
    let Some((capsule_type, n1)) = read_varint(rest) else {
        return Ok(None);
    };
    let Some((len, n2)) = read_varint(&rest[n1..]) else {
        return Ok(None);
    };
    let len = usize::try_from(len)
        .map_err(|_| io::Error::other("connect-ip: capsule length overflow"))?;
    if len > MAX_CAPSULE_PAYLOAD {
        return Err(io::Error::other(format!(
            "connect-ip: capsule payload too large: {len}"
        )));
    }
    if rest.len() < n1 + n2 + len {
        return Ok(None);
    }
    let payload = rest[n1 + n2..n1 + n2 + len].to_vec();
    buf.drain(..n1 + n2 + len);
    Ok(Some((capsule_type, payload)))
}

fn parse_settings(payload: &[u8]) -> io::Result<HashMap<u64, u64>> {
    let mut settings = HashMap::new();
    let mut rest: &[u8] = payload;
    while !rest.is_empty() {
        let (id, n1) = read_varint(rest)
            .ok_or_else(|| io::Error::other("masque h3: truncated SETTINGS identifier"))?;
        let (value, n2) = read_varint(&rest[n1..])
            .ok_or_else(|| io::Error::other("masque h3: truncated SETTINGS value"))?;
        settings.insert(id, value);
        rest = &rest[n1 + n2..];
    }
    Ok(settings)
}

fn parse_connect_uri(uri: &str) -> io::Result<ConnectUri> {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return Err(io::Error::other(format!(
            "connect-ip: parse connect uri: {uri}"
        )));
    };
    if scheme.is_empty() {
        return Err(io::Error::other(format!(
            "connect-ip: parse connect uri: {uri}"
        )));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(io::Error::other(format!(
            "connect-ip: parse connect uri: {uri}"
        )));
    }
    Ok(ConnectUri {
        authority: authority.to_string(),
        scheme: scheme.to_string(),
        path: if path.is_empty() { "/" } else { path }.to_string(),
    })
}

/// Buffered HTTP/3 frame reader over a quinn stream: type varint, length
/// varint, payload. HTTP/3 has no continuation frames, so a frame payload is
/// read whole; the length is capped by the negotiated stream window.
struct FrameReader {
    stream: quinn::RecvStream,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl FrameReader {
    fn new(stream: quinn::RecvStream) -> Self {
        FrameReader {
            stream,
            buf: Vec::with_capacity(8192),
            pos: 0,
            eof: false,
        }
    }

    async fn fill(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }
        let mut chunk = [0u8; 16 * 1024];
        match self.stream.read(&mut chunk).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
            }
            Ok(None) => self.eof = true,
            Err(e) => {
                return Err(io::Error::other(format!("masque h3: stream read: {e}")));
            }
        }
        Ok(())
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    async fn next(&mut self) -> io::Result<Option<(u64, Vec<u8>)>> {
        loop {
            let rest = self.available();
            if rest.is_empty() && self.eof {
                return Ok(None);
            }
            let Some((frame_type, n1)) = read_varint(rest) else {
                if self.eof {
                    return Err(io::Error::other("masque h3: truncated frame header"));
                }
                self.fill().await?;
                continue;
            };
            let Some((len, n2)) = read_varint(&rest[n1..]) else {
                if self.eof {
                    return Err(io::Error::other("masque h3: truncated frame length"));
                }
                self.fill().await?;
                continue;
            };
            let len = usize::try_from(len)
                .map_err(|_| io::Error::other("masque h3: frame length overflow"))?;
            if len > MAX_FRAME_PAYLOAD {
                return Err(io::Error::other(format!(
                    "masque h3: frame payload too large: {len}"
                )));
            }
            if rest.len() < n1 + n2 + len {
                if self.eof {
                    return Err(io::Error::other("masque h3: truncated frame payload"));
                }
                self.fill().await?;
                continue;
            }
            let payload = rest[n1 + n2..n1 + n2 + len].to_vec();
            self.pos += n1 + n2 + len;
            if self.pos > 16 * 1024 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            return Ok(Some((frame_type, payload)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri_variants() {
        let u = parse_connect_uri("https://cloudflareaccess.com").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.authority, "cloudflareaccess.com");
        assert_eq!(u.path, "/");

        let u = parse_connect_uri("https://example.com:8443/.well-known/masque/ip/4/1/").unwrap();
        assert_eq!(u.authority, "example.com:8443");
        assert_eq!(u.path, "/.well-known/masque/ip/4/1/");

        assert!(parse_connect_uri("cloudflareaccess.com").is_err());
        assert!(parse_connect_uri("https://").is_err());
    }

    #[test]
    fn settings_roundtrip() {
        let mut payload = Vec::new();
        put_varint(&mut payload, SETTINGS_H3_DATAGRAM);
        put_varint(&mut payload, 1);
        put_varint(&mut payload, SETTINGS_H3_DATAGRAM_00);
        put_varint(&mut payload, 1);
        let settings = parse_settings(&payload).unwrap();
        assert_eq!(settings.get(&SETTINGS_H3_DATAGRAM), Some(&1));
        assert_eq!(settings.get(&SETTINGS_H3_DATAGRAM_00), Some(&1));
        assert!(!settings.contains_key(&SETTINGS_ENABLE_CONNECT_PROTOCOL));
        assert!(parse_settings(&[0x80]).is_err()); // truncated varint
    }

    #[test]
    fn capsule_reassembly() {
        let mut buf = Vec::new();
        // One complete capsule then a partial header.
        put_varint(&mut buf, CAPSULE_ROUTE_ADVERTISEMENT);
        put_varint(&mut buf, 3);
        buf.extend_from_slice(&[1, 2, 3]);
        put_varint(&mut buf, CAPSULE_ADDRESS_ASSIGN);
        buf.push(0x80); // continuation bit without a terminal byte
        let (typ, payload) = take_capsule(&mut buf).unwrap().unwrap();
        assert_eq!(typ, CAPSULE_ROUTE_ADVERTISEMENT);
        assert_eq!(payload, vec![1, 2, 3]);
        assert!(take_capsule(&mut buf).unwrap().is_none());
        // Oversized declared payload is a protocol violation.
        let mut bad = Vec::new();
        put_varint(&mut bad, 0);
        put_varint(&mut bad, u64::from(u32::MAX) + 1);
        assert!(take_capsule(&mut bad).is_err());
    }

    #[test]
    fn default_route_advertisement_encodes_both_families() {
        let capsule = encode_route_advertisement(&default_routes());
        let mut rest: &[u8] = &capsule;
        let (typ, payload) = read_capsule_from(&mut rest).unwrap();
        assert_eq!(typ, 3);
        let routes = parse_route_advertisement(payload).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains(Ipv4Addr::new(1, 2, 3, 4).into(), 6, false));
        assert!(routes[1].contains(
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1).into(),
            17,
            false
        ));
    }

    fn read_capsule_from<'a>(rest: &'a mut &'a [u8]) -> Result<(u64, &'a [u8]), ()> {
        super::super::connectip::read_capsule(rest).map_err(|_| ())
    }
}
