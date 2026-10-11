//! Native WireGuard peer sessions over direct UDP and authenticated DERP.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

use super::config::TailscaleConfig;
use super::disco::{self, Message as Discovery};
use super::netmap::{Netmap, Peer};
use super::relay::{self, Relay};
use crate::outbound::wireguard::noise::{self as wg, Handshake, Session};

const MAX_PENDING: usize = 64;
const MAX_PACKET: usize = 2048;
const REKEY: Duration = Duration::from_secs(120);
const REJECT: Duration = Duration::from_secs(180);

pub struct Mesh {
    pub send: mpsc::Sender<Vec<u8>>,
    pub receive: mpsc::Receiver<Vec<u8>>,
    pub local_addr: SocketAddr,
    pub disco_public: [u8; 32],
    task: JoinHandle<()>,
}

impl Drop for Mesh {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PeerState {
    peer: Peer,
    session: Option<(Session, Instant)>,
    previous: Option<(Session, Instant)>,
    /// A responder key is not usable for sending until the initiator confirms it.
    next: Option<(Session, Instant)>,
    handshake: Option<(Handshake, Instant)>,
    latest_timestamp: [u8; 12],
    direct: Option<(SocketAddr, Instant)>,
    reply_relay: Option<u16>,
    probes: VecDeque<([u8; 12], SocketAddr, Instant)>,
    last_probe: Option<Instant>,
    pending: VecDeque<Vec<u8>>,
}

enum Event {
    Datagram(SocketAddr, Vec<u8>),
    Relay(u16, [u8; 32], Vec<u8>),
    RelayReady(u16, u64, io::Result<Relay>),
}

struct Tasks(Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Aggregate failure stages without logging peer keys or packet contents.
#[derive(Default, Debug)]
struct TransportCounters {
    received: u64,
    unknown_session: u64,
    wrong_peer: u64,
    expired: u64,
    open_failed: u64,
    keepalive: u64,
    bad_ip: u64,
    bad_source: u64,
    forwarded: u64,
    tcp: u64,
    udp: u64,
    outgoing: u64,
    unknown_destination: u64,
    sealed: u64,
    queued: u64,
}

pub async fn start(
    cfg: TailscaleConfig,
    secret: StaticSecret,
    map: Arc<RwLock<Netmap>>,
    mut updates: watch::Receiver<u64>,
) -> io::Result<Mesh> {
    let discovery = disco::fresh_key()?;
    let disco_public = *PublicKey::from(&discovery).as_bytes();
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", cfg.listen_port)).await?);
    let local_addr = socket.local_addr()?;
    let (send, mut outgoing) = mpsc::channel::<Vec<u8>>(128);
    let (received, receive) = mpsc::channel(128);
    let (events, mut event_rx) = mpsc::channel(256);
    let public = *PublicKey::from(&secret).as_bytes();
    let task = tokio::spawn(async move {
        let reader_socket = Arc::clone(&socket);
        let reader_events = events.clone();
        let mut tasks = Tasks(vec![tokio::spawn(async move {
            let mut bytes = vec![0; 65536];
            while let Ok((size, addr)) = reader_socket.recv_from(&mut bytes).await {
                if size <= MAX_PACKET
                    && reader_events
                        .send(Event::Datagram(addr, bytes[..size].to_vec()))
                        .await
                        .is_err()
                {
                    break;
                }
            }
        })]);
        let mut peers: HashMap<[u8; 32], PeerState> = HashMap::new();
        let mut relays: HashMap<u16, Relay> = HashMap::new();
        let mut connecting: HashMap<u16, Instant> = HashMap::new();
        let mut home = 0;
        let mut generation = 0u64;
        let mut transport = TransportCounters::default();
        let mut last_report = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            // Network maps are small and the lock is never held across await.
            let netmap = map.read().map(|map| map.active_clone()).unwrap_or_default();
            if home != netmap.home_derp {
                home = netmap.home_derp;
                generation = generation.wrapping_add(1);
                // Preference is part of DERP authentication. Reconnect so a
                // map-driven home change cannot retain the old preferred role.
                relays.clear();
                connecting.clear();
            }
            let mut wanted = vec![home];
            for peer in netmap.peers.values().filter(|peer| !peer.is_expired()) {
                wanted.push(peer.home_derp);
                peers
                    .entry(peer.key)
                    .and_modify(|state| {
                        if state.peer.endpoints != peer.endpoints
                            || state.peer.home_derp != peer.home_derp
                            || state.peer.disco_key != peer.disco_key
                        {
                            state.direct = None;
                            state.probes.clear();
                            state.last_probe = None;
                        }
                        state.peer = peer.clone();
                    })
                    .or_insert_with(|| PeerState {
                        peer: peer.clone(),
                        session: None,
                        previous: None,
                        next: None,
                        handshake: None,
                        latest_timestamp: [0; 12],
                        direct: None,
                        reply_relay: None,
                        probes: VecDeque::new(),
                        last_probe: None,
                        pending: VecDeque::new(),
                    });
            }
            peers.retain(|_, state| {
                netmap
                    .peers
                    .get(&state.peer.id)
                    .is_some_and(|peer| peer.key == state.peer.key && !peer.is_expired())
            });
            wanted.sort_unstable();
            wanted.dedup();
            relays.retain(|id, relay| wanted.contains(id) && !relay.send.is_closed());
            for id in wanted.into_iter().filter(|id| *id != 0) {
                if relays.contains_key(&id)
                    || connecting
                        .get(&id)
                        .is_some_and(|time| time.elapsed() < Duration::from_secs(20))
                {
                    continue;
                }
                let Some(node) = netmap
                    .derp
                    .regions
                    .get(&id.to_string())
                    .and_then(|region| region.nodes.iter().find(|node| !node.stun_only))
                    .cloned()
                else {
                    continue;
                };
                connecting.insert(id, Instant::now());
                let secret = secret.clone();
                let events = events.clone();
                tasks.0.push(tokio::spawn(async move {
                    let (relay_tx, mut relay_rx) = mpsc::channel(128);
                    let forward_events = events.clone();
                    let forward = tokio::spawn(async move {
                        while let Some((key, packet)) = relay_rx.recv().await {
                            if forward_events
                                .send(Event::Relay(id, key, packet))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    let result = relay::connect(&node, &secret, id == home, relay_tx).await;
                    if result.is_err() {
                        forward.abort();
                    }
                    let _ = events.send(Event::RelayReady(id, generation, result)).await;
                    // Relay owns sender; after it is dropped the forwarder ends.
                    // A connection attempt is bounded by relay::connect.
                }));
            }
            tasks.0.retain(|task| !task.is_finished());
            tokio::select! {
                changed = updates.changed() => { if changed.is_err() { break; } }
                _ = tick.tick() => {
                    if last_report.elapsed() >= Duration::from_secs(5) {
                        if transport.received != 0 || transport.outgoing != 0 {
                            crate::logging::debug(format_args!("tailscale[{}]: transport {transport:?}", cfg.tag));
                        }
                        transport = TransportCounters::default();
                        last_report = Instant::now();
                    }
                    for state in peers.values_mut() {
                        if (state.session.is_some() || !state.pending.is_empty()) && state.last_probe.is_none_or(|last| last.elapsed() >= Duration::from_secs(10)) {
                            let mut endpoints = state.peer.endpoints.clone();
                            if let Some((address,_)) = state.direct { endpoints.push(address); }
                            probe_endpoints(state, &discovery, &public, &socket, endpoints).await;
                        }
                        if state.session.as_ref().is_some_and(|(_, started)| started.elapsed() >= REJECT) { state.session = None; }
                        if state.next.as_ref().is_some_and(|(_, started)| started.elapsed() >= REJECT) { state.next = None; }
                        if !state.pending.is_empty() && !awaiting_confirmation(state) && state.handshake.as_ref().is_none_or(|(_, started)| started.elapsed() >= Duration::from_secs(5)) {
                            begin_handshake(state, &secret, &discovery, &public, &socket, &relays).await;
                        }
                    }
                }
                packet = outgoing.recv() => {
                    let Some(packet) = packet else { break; };
                    transport.outgoing += 1;
                    let Some((_, destination, _)) = ip_header(&packet) else { continue; };
                    let state = peers.values_mut().filter(|state| !state.peer.is_expired())
                        .filter_map(|state| {
                            let prefix = state.peer.allowed.iter().filter(|prefix| prefix.prefix_len()!=0 && prefix.contains_addr(&IpAddress::from(destination)))
                                .filter(|prefix| cfg.accept_routes || state.peer.addresses.iter().any(|address| address == *prefix))
                                .map(|prefix| prefix.prefix_len()).max()?;
                            Some((prefix, state))
                        }).max_by_key(|(prefix, _)| *prefix).map(|(_, state)| state);
                    let Some(state) = state else { transport.unknown_destination += 1; continue; };
                    if packet.len() > MAX_PACKET || packet.len() > cfg.system_interface_mtu.unwrap_or(1280) as usize { continue; }
                    if state.session.as_ref().is_some_and(|(_, time)| time.elapsed() < REKEY) {
                        if let Some(packet) = state.session.as_mut().and_then(|(session, _)| session.seal(&packet)) {
                            transport.sealed += 1;
                            transmit(state, &socket, &relays, packet).await;
                        }
                    } else {
                        if state.pending.len() < MAX_PENDING { state.pending.push_back(packet); transport.queued += 1; }
                        if !awaiting_confirmation(state) && state.handshake.as_ref().is_none_or(|(_, time)| time.elapsed() >= Duration::from_secs(5)) {
                            begin_handshake(state, &secret, &discovery, &public, &socket, &relays).await;
                        }
                    }
                }
                event = event_rx.recv() => {
                    let Some(event) = event else { break; };
                    let (relay_source, relay_region, direct, packet) = match event {
                        Event::RelayReady(id, epoch, result) => {
                            if epoch != generation { continue; }
                            connecting.insert(id, Instant::now());
                            match result {
                                Ok(relay) => { crate::logging::info(format_args!("tailscale[{}]: DERP region {id} connected", cfg.tag)); relays.insert(id, relay); }
                                Err(error) => crate::logging::warn(format_args!("tailscale[{}]: DERP region {id} unavailable: {error}",cfg.tag)),
                            }
                            continue;
                        }
                        Event::Datagram(addr, packet) => (None, None, Some(addr), packet),
                        Event::Relay(region, key, packet) => (Some(key), Some(region), None, packet),
                    };
                    if let Some(sender) = disco::sender(&packet) {
                        // Reject unknown discovery identities before doing DH.
                        // A DERP sender must also match its authorized node key.
                        if !peers.values().any(|state| state.peer.disco_key == Some(sender)
                            && relay_source.is_none_or(|key| key == state.peer.key)) { continue; }
                        let Some(message) = disco::open(&discovery, &packet) else { continue; };
                        let Some(state) = peers.values_mut().find(|state| {
                            state.peer.disco_key == Some(sender)
                                && relay_source.is_none_or(|key| key == state.peer.key)
                                && match &message {
                                    Discovery::Ping { node:Some(key), .. } => *key == state.peer.key,
                                    Discovery::Pong {id,..} => state.probes.iter().any(|(expected,address,started)| expected == id && direct == Some(*address) && started.elapsed() < Duration::from_secs(10)),
                                    _ => true,
                                }
                        }) else { continue; };
                        match message {
                            Discovery::Ping { id, .. } => {
                                let source = direct.unwrap_or_else(|| SocketAddr::from(([127,3,3,40],relay_region.unwrap_or(0))));
                                if let Some(reply) = disco::seal(&discovery,&sender,&Discovery::Pong {id,source}) {
                                    if let Some(address) = direct { let _ = socket.send_to(&reply,address).await; }
                                    else if let Some(relay) = relay_region.and_then(|id| relays.get(&id)) { let _ = relay.send.try_send((state.peer.key,reply)); }
                                }
                                if let Some(address) = direct && state.last_probe.is_none_or(|last| last.elapsed() >= Duration::from_secs(5)) {
                                    probe_endpoints(state,&discovery,&public,&socket,vec![address]).await;
                                }
                            }
                            Discovery::Pong { id, .. } => {
                                if let Some(address) = direct {
                                    state.probes.retain(|(expected,_,_)| *expected != id);
                                    state.direct = Some((address,Instant::now()));
                                    if let Some((handshake,_)) = &state.handshake {
                                        let _ = socket.send_to(handshake.initiation(),address).await;
                                    }
                                }
                            }
                            Discovery::CallMeMaybe(endpoints) if relay_source.is_some() => {
                                probe_endpoints(state,&discovery,&public,&socket,endpoints).await;
                            }
                            _ => {},
                        }
                        continue;
                    }
                    if packet.len() < 4 || packet.len() > MAX_PACKET { continue; }
                    let kind = u32::from_le_bytes(packet[..4].try_into().unwrap());
                    let peer_key = match kind {
                        1 if packet.len() == wg::INITIATION_LEN => {
                            let init = match wg::process_initiation(&secret.to_bytes(), &public, &packet) {
                                Ok(init) => init,
                                Err(error) => { crate::logging::debug(format_args!("tailscale[{}]: WireGuard initiation rejected: {error}",cfg.tag)); continue; }
                            };
                            if relay_source.is_some_and(|key| key != init.sender_static_pub) { continue; }
                            let Some(state) = peers.get_mut(&init.sender_static_pub) else { continue; };
                            if init.timestamp <= state.latest_timestamp { continue; }
                            state.latest_timestamp = init.timestamp;
                            if let Some(region) = relay_region { state.reply_relay = Some(region); }
                            let (reply, session) = wg::build_response(&init, &secret.to_bytes(), None, 2);
                            if let Some(addr) = direct { let _ = socket.send_to(&reply, addr).await; }
                            else { transmit(state, &socket, &relays, reply).await; }
                            state.next = Some((session, Instant::now()));
                            crate::logging::debug(format_args!("tailscale[{}]: WireGuard responder awaiting key confirmation (home {}, relay {:?})",cfg.tag,state.peer.home_derp,relay_region));
                            continue;
                        }
                        2 if packet.len() == wg::RESPONSE_LEN => {
                            let receiver = u32::from_le_bytes(packet[8..12].try_into().unwrap());
                            let Some(state) = peers.values_mut().find(|state| state.handshake.as_ref().is_some_and(|(handshake, _)| handshake.sender_index == receiver)) else { continue; };
                            if relay_source.is_some_and(|key| key != state.peer.key) { continue; }
                            let Some((handshake, _)) = state.handshake.as_ref() else { continue; };
                            let Ok(session) = wg::process_response(handshake, &packet, &public, None) else { continue; };
                            if let Some(region) = relay_region { state.reply_relay = Some(region); }
                            install_session(state,session); state.handshake = None; state.next = None;
                            state.peer.key
                        }
                        4 if packet.len() >= 32 => {
                            transport.received += 1;
                            let receiver = u32::from_le_bytes(packet[4..8].try_into().unwrap());
                            let Some(state) = peers.values_mut().find(|state| state.session.as_ref().is_some_and(|(session, _)| session.local_index == receiver) || state.previous.as_ref().is_some_and(|(session,_)|session.local_index==receiver) || state.next.as_ref().is_some_and(|(session,_)|session.local_index==receiver)) else { transport.unknown_session += 1; continue; };
                            if relay_source.is_some_and(|key| key != state.peer.key) { transport.wrong_peer += 1; continue; }
                            let confirms_next = state.next.as_ref().is_some_and(|(session,_)|session.local_index==receiver);
                            let Some((session, started)) = (if confirms_next {state.next.as_mut()} else if state.session.as_ref().is_some_and(|(session,_)|session.local_index==receiver) {state.session.as_mut()} else {state.previous.as_mut()}) else { continue; };
                            if started.elapsed() >= REJECT { transport.expired += 1; continue; }
                            let Some(mut plaintext) = session.open(&packet) else { transport.open_failed += 1; continue; };
                            if let Some(region) = relay_region { state.reply_relay = Some(region); }
                            if let Some(addr) = direct && state.peer.disco_key.is_none() { state.direct = Some((addr, Instant::now())); }
                            if confirms_next {
                                let (session, _) = state.next.take().expect("authenticated next session");
                                install_session(state, session);
                                crate::logging::debug(format_args!("tailscale[{}]: WireGuard responder key confirmed",cfg.tag));
                                flush_pending(state, &socket, &relays).await;
                            }
                            if plaintext.is_empty() { transport.keepalive += 1; continue; }
                            let Some((source, _, length)) = ip_header(&plaintext) else { transport.bad_ip += 1; continue; };
                            if !state.peer.owns_source(source) || (!cfg.accept_routes && !state.peer.addresses.iter().any(|address|address.contains_addr(&IpAddress::from(source)))) { transport.bad_source += 1; continue; }
                            plaintext.truncate(length);
                            match if plaintext[0] >> 4 == 4 { plaintext[9] } else { plaintext[6] } {
                                6 => transport.tcp += 1,
                                17 => transport.udp += 1,
                                _ => {},
                            }
                            if received.send(plaintext).await.is_err() { break; }
                            transport.forwarded += 1;
                            continue;
                        }
                        _ => continue,
                    };
                    let Some(state) = peers.get_mut(&peer_key) else { continue; };
                    if let Some(addr) = direct && state.peer.disco_key.is_none() { state.direct = Some((addr, Instant::now())); }
                    if let Some(packet) = state.session.as_mut().and_then(|(session, _)| session.seal(&[])) { transmit(state, &socket, &relays, packet).await; }
                    flush_pending(state, &socket, &relays).await;
                }
            }
        }
    });
    Ok(Mesh {
        send,
        receive,
        local_addr,
        disco_public,
        task,
    })
}

fn install_session(state: &mut PeerState, session: Session) {
    state.previous = state
        .session
        .take()
        .filter(|(_, started)| started.elapsed() < REJECT);
    state.session = Some((session, Instant::now()));
}

fn awaiting_confirmation(state: &PeerState) -> bool {
    state
        .next
        .as_ref()
        .is_some_and(|(_, started)| started.elapsed() < Duration::from_secs(5))
}

async fn flush_pending(state: &mut PeerState, socket: &UdpSocket, relays: &HashMap<u16, Relay>) {
    while let Some(packet) = state.pending.pop_front() {
        if let Some(packet) = state
            .session
            .as_mut()
            .and_then(|(session, _)| session.seal(&packet))
        {
            transmit(state, socket, relays, packet).await;
        }
    }
}

async fn begin_handshake(
    state: &mut PeerState,
    secret: &StaticSecret,
    discovery: &StaticSecret,
    public: &[u8; 32],
    socket: &UdpSocket,
    relays: &HashMap<u16, Relay>,
) {
    if state
        .last_probe
        .is_none_or(|last| last.elapsed() >= Duration::from_secs(5))
    {
        probe_endpoints(
            state,
            discovery,
            public,
            socket,
            state.peer.endpoints.clone(),
        )
        .await;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut timestamp = [0; 12];
    timestamp[..8].copy_from_slice(&(now.as_secs() + 0x4000_0000_0000_000a).to_be_bytes());
    timestamp[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    let handshake = wg::build_initiation(
        &secret.to_bytes(),
        public,
        &state.peer.key,
        None,
        &timestamp,
        1,
    );
    transmit(state, socket, relays, handshake.initiation().to_vec()).await;
    state.handshake = Some((handshake, Instant::now()));
}

async fn probe_endpoints(
    state: &mut PeerState,
    discovery: &StaticSecret,
    public: &[u8; 32],
    socket: &UdpSocket,
    endpoints: Vec<SocketAddr>,
) {
    let Some(key) = state.peer.disco_key else {
        return;
    };
    state
        .probes
        .retain(|(_, _, started)| started.elapsed() < Duration::from_secs(10));
    state.last_probe = Some(Instant::now());
    for endpoint in endpoints
        .into_iter()
        .filter(|address| {
            address.is_ipv4()
                && address.port() != 0
                && !address.ip().is_unspecified()
                && !address.ip().is_multicast()
        })
        .take(8)
    {
        let mut id = [0; 12];
        if getrandom::fill(&mut id).is_err() {
            break;
        }
        let Some(packet) = disco::seal(
            discovery,
            &key,
            &Discovery::Ping {
                id,
                node: Some(*public),
            },
        ) else {
            continue;
        };
        if socket.send_to(&packet, endpoint).await.is_ok() {
            if state.probes.len() >= 16 {
                state.probes.pop_front();
            }
            state.probes.push_back((id, endpoint, Instant::now()));
        }
    }
}

async fn transmit(
    state: &PeerState,
    socket: &UdpSocket,
    relays: &HashMap<u16, Relay>,
    packet: Vec<u8>,
) {
    if let Some((addr, last)) = state
        .direct
        .filter(|(_, last)| last.elapsed() < Duration::from_secs(15))
    {
        let _ = last;
        if socket.send_to(&packet, addr).await.is_ok() {
            return;
        }
    }
    // Unvalidated direct endpoints are probes; also send through DERP so a
    // stale endpoint cannot black-hole a connection.
    for endpoint in state
        .peer
        .endpoints
        .iter()
        .filter(|addr| state.peer.disco_key.is_none() && addr.is_ipv4())
        .take(8)
    {
        let _ = socket.send_to(&packet, endpoint).await;
    }
    // A sender also reads the DERP connection it used to reach us. Reply on
    // that authenticated reverse path when its home region is unreachable.
    if let Some(relay) = state
        .reply_relay
        .and_then(|id| relays.get(&id))
        .or_else(|| relays.get(&state.peer.home_derp))
    {
        let _ = relay.send.try_send((state.peer.key, packet));
    }
}

pub fn ip_header(bytes: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    match bytes.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new_checked(bytes).ok()?;
            if !packet.verify_checksum() || packet.more_frags() || packet.frag_offset() != 0 {
                return None;
            }
            Some((
                packet.src_addr().into(),
                packet.dst_addr().into(),
                usize::from(packet.total_len()),
            ))
        }
        6 => {
            let packet = Ipv6Packet::new_checked(bytes).ok()?;
            Some((
                packet.src_addr().into(),
                packet.dst_addr().into(),
                usize::from(packet.payload_len()) + 40,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::time::timeout;

    #[tokio::test]
    async fn responder_queues_data_until_authenticated_key_confirmation() {
        let our = StaticSecret::from([41; 32]);
        let peer = StaticSecret::from([42; 32]);
        let our_public = *PublicKey::from(&our).as_bytes();
        let peer_public = *PublicKey::from(&peer).as_bytes();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut netmap = Netmap::default();
        netmap
            .update(&json!({"Peers":[{
                "ID":1,"Key":super::super::control::node_key_str(&PublicKey::from(&peer)),
                "Addresses":["100.64.0.2/32"],
                "Endpoints":[client.local_addr().unwrap().to_string()]
            }]}))
            .unwrap();
        let cfg = TailscaleConfig::parse(
            json!({"tag":"confirmation","listen_port":0})
                .as_object()
                .unwrap(),
            "confirmation",
        )
        .unwrap();
        let (_updates, receiver) = watch::channel(0);
        let mut mesh = start(cfg, our, Arc::new(RwLock::new(netmap)), receiver)
            .await
            .unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], mesh.local_addr.port()));
        let mut timestamp = [0; 12];
        timestamp[0] = 1;
        let handshake = wg::build_initiation(
            &peer.to_bytes(),
            &peer_public,
            &our_public,
            None,
            &timestamp,
            1,
        );
        client
            .send_to(handshake.initiation(), address)
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        let (length, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(length, wg::RESPONSE_LEN);
        let mut session =
            wg::process_response(&handshake, &buffer[..length], &peer_public, None).unwrap();
        let packet = crate::outbound::wireguard::build_ipv4_udp(
            "100.64.0.1".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            1234,
            5678,
            b"queued before confirmation",
        );
        mesh.send.send(packet.clone()).await.unwrap();
        assert!(
            timeout(Duration::from_millis(80), client.recv_from(&mut buffer))
                .await
                .is_err(),
            "responder must not send keepalives or data before key confirmation"
        );
        client
            .send_to(&session.seal(&[]).unwrap(), address)
            .await
            .unwrap();
        let (length, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let plaintext = session.open(&buffer[..length]).unwrap();
        assert_eq!(&plaintext[..packet.len()], packet);
        let incoming = crate::outbound::wireguard::build_ipv4_udp(
            "100.64.0.2".parse().unwrap(),
            "100.64.0.1".parse().unwrap(),
            5678,
            1234,
            b"confirmed response",
        );
        client
            .send_to(&session.seal(&incoming).unwrap(), address)
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), mesh.receive.recv())
                .await
                .unwrap()
                .unwrap(),
            incoming
        );
    }
}
