//! Server inbounds for the proxy protocols (F5): accept, authenticate, and hand
//! the connection to the router the way the reference's `newConnectionEx` does.
//!
//! The request heads are the mirror image of what our own outbounds write, so
//! the test for each of them is our client against our server over a real
//! socket -- no fixture, no mock.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::tls::ServerTls;
use super::transport::Transport;
use super::udp::{relay_stream_datagrams, udp_destination};
use crate::inbound::{AnyStream, AnyWrite, ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::route::Router;

/// Request command bytes (`vmess.CommandTCP` and friends).
pub(crate) const COMMAND_TCP: u8 = 0x01;
pub(crate) const COMMAND_UDP: u8 = 0x02;
/// trojan numbers its mux command 0x7f (`transport/trojan/protocol.go`).
pub(crate) const COMMAND_MUX: u8 = 0x7f;

/// trojan's UDP command is 2 in sing's `protocol.go` and 3 in Xray's
/// `protocol.RequestCommand`, and both spellings are in the field -- sing-box
/// reads 2, Xray writes 3, and our own client writes what Xray writes. A server
/// that picked one number would refuse half of them, so both are read as the
/// same command and the mux value stays 0x7f, which neither of them uses.
pub(crate) const COMMAND_UDP_ALT: u8 = 0x03;
/// VLESS command 3 carries Xray Mux.Cool/XUDP, not sing-mux H2MUX.
const VLESS_COMMAND_MUX: u8 = 0x03;

/// The answer head the server puts in front of the first payload: version and
/// addons length, both zero (`serverConn.Write`).
const RESPONSE_HEAD: [u8; 2] = [0x00, 0x00];

/// One configured user: the name the reference logs, and the secret it checks.
#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub uuid: [u8; 16],
    /// `flow`, empty when the user does not ask for Vision
    pub flow: String,
}

/// `users: [{"name": ..., "uuid": ...}]`, the reference's `option.VLESSUser`.
pub(crate) fn vless_users(obj: &Value, at: &str) -> anyhow::Result<Vec<User>> {
    let list = obj
        .get("users")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("{at}: missing users"))?;
    if list.is_empty() {
        anyhow::bail!("{at}: users is required and must not be empty");
    }
    let mut out = Vec::with_capacity(list.len());
    for (index, entry) in list.iter().enumerate() {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let raw = entry
            .get("uuid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}.users[{index}]: missing uuid"))?;
        // the reference turns anything `uuid.FromString` refuses into a UUIDv5
        // of the raw string, so the same fallback belongs here
        let uuid = crate::outbound::vmess::kdf::parse_uuid(raw)
            .map_err(|e| anyhow::anyhow!("{at}.users[{index}]: {e}"))?;
        out.push(User {
            name: if name.is_empty() {
                index.to_string()
            } else {
                name
            },
            uuid,
            flow: entry
                .get("flow")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    Ok(out)
}

/// A vless server inbound: the request head is
/// `[version][uuid][addonsLen][addons][command][addr][port]`.
pub struct Vless {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    users: HashMap<[u8; 16], User>,
    tls: Option<Arc<ServerTls>>,
    transport: Option<Arc<Transport>>,
}

impl Vless {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("vless")
            .to_string();
        let at = format!("inbound[{tag}]");
        let users = vless_users(obj, &at)?
            .into_iter()
            .map(|user| (user.uuid, user))
            .collect::<HashMap<_, _>>();
        let tls = ServerTls::from_inbound(obj, &at)?;
        let transport = Transport::from_inbound(obj, &at)?.map(Arc::new);
        let listen = parse_listen(object, &at)?;
        let listener = super::bind_tcp(std::net::SocketAddr::from(listen))
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            users,
            tls,
            transport,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let users = self.users.clone();
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let tls = self.tls.clone();
                    let transport = self.transport.clone();
                    tokio::spawn(async move {
                        // The socket's own address is read here because a TLS
                        // stream is handed over where the socket was, and
                        // nothing downstream can ask it again.
                        let local = stream.local_addr().unwrap_or(peer);
                        let result = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(stream) => {
                                    serve_vless(stream, transport, peer, local, users, tag, router)
                                        .await
                                }
                                Err(err) => Err(err),
                            },
                            None => {
                                serve_vless(stream, transport, peer, local, users, tag, router)
                                    .await
                            }
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("vless {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    super::serve_stalled("vless accept", &err).await;
                }
            }
        }
    }
}

/// One connection: read the request, check the user, route it.
/// Take the transport off the front of the connection, if the listener has one,
/// then hand what is left to the protocol. TLS first: the handshake is inside it.
async fn serve_vless<S>(
    stream: S,
    transport: Option<Arc<Transport>>,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<[u8; 16], User>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // With no transport the concrete type is kept: boxing it here would cost the
    // relay the `Any` downcast it does to find a bare TcpStream and splice the two
    // directions instead of copying them. Measured on vless, eight streams:
    // 0.39 -> 0.78 CPU-s/GiB, with the latency unchanged, so only the CPU split
    // ever saw it.
    match transport {
        None => handle_vless(stream, peer, local, users, tag, router).await,
        Some(transport) => {
            let stream = Box::new(stream) as AnyStream;
            let accepted = transport.accept(stream).await.map_err(io::Error::other)?;
            // A gRPC connection carries a session per stream and drives itself
            // while waiting for the next, so its sessions run as tasks; every
            // other transport carries exactly one, awaited here. The session's
            // own error is logged where it happens, so the outer log only ever
            // sees the connection's.
            crate::inbound::transport::serve_sessions(accepted, move |stream| {
                let users = users.clone();
                let tag = tag.clone();
                let router = router.clone();
                async move {
                    if let Err(err) = handle_vless(stream, peer, local, users, tag, router).await {
                        logging::debug(format_args!("vless {peer}: {err}"));
                    }
                }
            })
            .await
        }
    }
}

async fn handle_vless<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: HashMap<[u8; 16], User>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (user, command, destination, flow) = read_request(&mut stream, &users).await?;
    if flow != user.flow {
        return Err(io::Error::other(format!(
            "flow mismatch: expected {}, but got {}",
            if user.flow.is_empty() {
                "none"
            } else {
                &user.flow
            },
            if flow.is_empty() { "none" } else { &flow }
        )));
    }
    if flow == "xtls-rprx-vision" && command == COMMAND_UDP {
        return Err(io::Error::other(
            "xtls-rprx-vision flow does not support UDP",
        ));
    }
    if command == VLESS_COMMAND_MUX {
        stream.write_all(&RESPONSE_HEAD).await?;
        let framed: AnyStream = if flow == "xtls-rprx-vision" {
            Box::new(crate::outbound::vision::VisionStream::new(
                Box::new(stream),
                user.uuid,
            ))
        } else {
            Box::new(stream)
        };
        return serve_xudp(framed, peer, &tag, &router).await;
    }
    if command == COMMAND_UDP {
        let dest = udp_destination(&destination)?;
        // The answer head goes out in front of the first datagram, not in
        // front of a payload that may never come: `serverPacketConn` writes it
        // on the first `WriteTo`, and a client waiting for it before its first
        // read would otherwise wait forever.
        stream.write_all(&RESPONSE_HEAD).await?;
        let (reader, writer) = tokio::io::split(stream);
        return relay_stream_datagrams(
            reader,
            Arc::new(tokio::sync::Mutex::new(Box::new(writer) as AnyWrite)),
            peer,
            dest,
            &tag,
            &router,
        )
        .await;
    }
    if command == COMMAND_MUX || crate::inbound::mux::is_mux_target(&destination) {
        logging::info(format_args!("vless [{}] inbound mux session", user.name));
        stream.write_all(&RESPONSE_HEAD).await?;
        return crate::inbound::mux::serve_mux(Box::new(stream), peer, local, &tag, &router).await;
    }
    if command != COMMAND_TCP {
        return Err(io::Error::other(format!(
            "command {command} is not implemented by this server"
        )));
    }
    logging::info(format_args!(
        "vless [{}] inbound connection to {destination}",
        user.name
    ));
    // The reference writes `[version][addonsLen]` lazily, in front of the first
    // payload the client reads. Writing it here instead puts the same two bytes
    // in the socket buffer, which a client cannot tell apart -- except when the
    // route below fails, and then a close is what it sees either way.
    stream.write_all(&RESPONSE_HEAD).await?;
    // Vision frames the payload both ways; the framing is symmetric, so the
    // client's own stream type does for the server too. It is not a bare
    // socket, so the relay takes the buffered path.
    let framed: AnyStream = if flow == "xtls-rprx-vision" {
        Box::new(crate::outbound::vision::VisionStream::new(
            Box::new(stream),
            user.uuid,
        ))
    } else {
        Box::new(stream)
    };
    drive_framed(
        ClientConn::framed(framed, local),
        peer,
        destination,
        &tag,
        &router,
    )
    .await
}

struct XudpSession {
    hub: Arc<super::udp::UdpHub>,
    target: Target,
    address: SocketAddr,
}

impl Drop for XudpSession {
    fn drop(&mut self) {
        // End, replacement, EOF and cancelled transport all stop reverse readers.
        self.hub.stop();
    }
}

/// The UDP subset of Xray Mux.Cool. Keep H2MUX on the separate sing-mux path.
/// Global IDs are accepted but cross-connection XUDP migration is not provided.
async fn serve_xudp(
    stream: AnyStream,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    use super::udp::{DatagramFrame, Reply, UdpHub};
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(tokio::sync::Mutex::new(Box::new(writer) as AnyWrite));
    let reply = Reply::Stream(Arc::clone(&writer));
    let mut sessions = HashMap::<u16, XudpSession>::new();
    loop {
        let meta_len = match reader.read_u16().await {
            Ok(len) => usize::from(len),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if !(4..=512).contains(&meta_len) {
            return Err(io::Error::other("xudp: invalid metadata length"));
        }
        let mut metadata = vec![0; meta_len];
        reader.read_exact(&mut metadata).await?;
        let id = u16::from_be_bytes([metadata[0], metadata[1]]);
        let status = metadata[2];
        let option = metadata[3];
        let mut target = None;
        let mut unsupported_tcp = false;
        if status == 1 || (status == 2 && meta_len > 4) {
            let network = *metadata
                .get(4)
                .ok_or_else(|| io::Error::other("xudp: missing network"))?;
            if !matches!(network, 1 | 2) {
                return Err(io::Error::other("xudp: invalid network"));
            }
            unsupported_tcp = network == 1;
            target = Some(read_vless_target(&mut &metadata[5..]).await?);
        }
        // Control frames without Data have no payload-length field.
        let payload = if option & 1 != 0 {
            let len = reader.read_u16().await?;
            let mut payload = vec![0; usize::from(len)];
            reader.read_exact(&mut payload).await?;
            Some(payload)
        } else {
            None
        };
        match status {
            3 => {
                sessions.remove(&id);
                continue;
            }
            4 => continue,
            1 | 2 => {}
            _ => return Err(io::Error::other("xudp: invalid session status")),
        }
        if unsupported_tcp || (status == 2 && !sessions.contains_key(&id)) {
            // Reject only this session, keeping other UDP sessions usable.
            let mut writer = writer.lock().await;
            writer
                .write_all(&[0, 4, metadata[0], metadata[1], 3, 2])
                .await?;
            continue;
        }
        if status == 1 {
            sessions.remove(&id);
            if sessions.len() >= 1024 {
                return Err(io::Error::other("xudp: too many sessions"));
            }
        }
        if let Some(target) = target {
            if sessions
                .get(&id)
                .is_some_and(|session| session.target != target)
            {
                sessions.remove(&id);
            }
            let address = match &target {
                Target::Ip(address) => *address,
                Target::Domain(host, port) => crate::outbound::dial::resolve(host, *port)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| io::Error::other("xudp: destination has no addresses"))?,
            };
            let session = sessions.entry(id).or_insert_with(|| XudpSession {
                hub: UdpHub::new(
                    Arc::clone(router),
                    std::time::Duration::ZERO,
                    DatagramFrame::Xudp(id),
                ),
                target: target.clone(),
                address,
            });
            session.target = target;
            session.address = address;
        }
        if let Some(payload) = payload {
            let session = sessions
                .get(&id)
                .ok_or_else(|| io::Error::other("xudp: missing session"))?;
            session
                .hub
                .handle_routed(
                    reply.clone(),
                    peer,
                    session.address,
                    &payload,
                    tag,
                    &session.target,
                )
                .await?;
        }
    }
}

/// trojan server inbound: the request is
/// `[56-byte SHA224 hex][CRLF][command][atyp][addr][port][CRLF]`, which is
/// `trojan.Service.NewConnection` byte for byte -- 56 bytes of key, the CRLF
/// skipped, the command, `M.SocksaddrSerializer` for the destination, then the
/// trailing CRLF. There is no answer head at all.
pub struct Trojan {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    /// SHA224 hex of each password, keyed by those bytes
    keys: HashMap<[u8; KEY_LENGTH], String>,
    tls: Option<Arc<ServerTls>>,
    transport: Option<Arc<Transport>>,
}

/// `KeyLength`: SHA224 in hex is 56 bytes.
const KEY_LENGTH: usize = 56;

impl Trojan {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("trojan")
            .to_string();
        let at = format!("inbound[{tag}]");
        let list = object
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing users"))?;
        if list.is_empty() {
            anyhow::bail!("{at}: users is required and must not be empty");
        }
        let mut keys: HashMap<[u8; KEY_LENGTH], String> = HashMap::new();
        for (index, entry) in list.iter().enumerate() {
            let password = entry
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{at}.users[{index}]: missing password"))?;
            // `UpdateUsers` refuses a password another user already has
            let hash = password_hash(password);
            let mut key = [0u8; KEY_LENGTH];
            key.copy_from_slice(hash.as_bytes());
            if let Some(name) = keys.insert(
                key,
                entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ) {
                anyhow::bail!("{at}: password used by {name} (users[{index}])");
            }
        }
        let listen = parse_listen(object, &at)?;
        let listener = super::bind_tcp(std::net::SocketAddr::from(listen))
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            keys,
            tls: ServerTls::from_inbound(obj, &at)?,
            transport: Transport::from_inbound(obj, &at)?.map(Arc::new),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let keys = self.keys.clone();
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let tls = self.tls.clone();
                    let transport = self.transport.clone();
                    tokio::spawn(async move {
                        let local = stream.local_addr().unwrap_or(peer);
                        let result = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(stream) => {
                                    serve_trojan(stream, transport, peer, local, keys, tag, router)
                                        .await
                                }
                                Err(err) => Err(err),
                            },
                            None => {
                                serve_trojan(stream, transport, peer, local, keys, tag, router)
                                    .await
                            }
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("trojan {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    super::serve_stalled("trojan accept", &err).await;
                }
            }
        }
    }
}

/// SHA224 of the password, hex, lowercase -- what the trojan protocol sends.
/// The client side builds the same string in `outbound::secure::Trojan::build`.
pub(crate) fn password_hash(password: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha224::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The same two steps for trojan, in the same order.
async fn serve_trojan<S>(
    stream: S,
    transport: Option<Arc<Transport>>,
    peer: SocketAddr,
    local: SocketAddr,
    keys: HashMap<[u8; KEY_LENGTH], String>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match transport {
        None => handle_trojan(stream, peer, local, keys, tag, router).await,
        Some(transport) => {
            let stream = Box::new(stream) as AnyStream;
            let accepted = transport.accept(stream).await.map_err(io::Error::other)?;
            // Same shape as vless above: a gRPC connection hands out a session
            // per stream over a connection that outlives them, everything else
            // exactly one session. Session errors log in their own closure.
            crate::inbound::transport::serve_sessions(accepted, move |stream| {
                let keys = keys.clone();
                let tag = tag.clone();
                let router = router.clone();
                async move {
                    if let Err(err) = handle_trojan(stream, peer, local, keys, tag, router).await {
                        logging::debug(format_args!("trojan {peer}: {err}"));
                    }
                }
            })
            .await
        }
    }
}

async fn handle_trojan<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    keys: HashMap<[u8; KEY_LENGTH], String>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (name, command, destination) = read_trojan_request(&mut stream, &keys).await?;
    if matches!(command, COMMAND_UDP | COMMAND_UDP_ALT) {
        let dest = udp_destination(&destination)?;
        let (reader, writer) = tokio::io::split(stream);
        return relay_stream_datagrams(
            reader,
            Arc::new(tokio::sync::Mutex::new(Box::new(writer) as AnyWrite)),
            peer,
            dest,
            &tag,
            &router,
        )
        .await;
    }
    if command == COMMAND_MUX || crate::inbound::mux::is_mux_target(&destination) {
        logging::info(format_args!("trojan [{name}] inbound mux session"));
        return crate::inbound::mux::serve_mux(Box::new(stream), peer, local, &tag, &router).await;
    }
    if command != COMMAND_TCP {
        return Err(io::Error::other(format!(
            "command {command} is not implemented by this server"
        )));
    }
    logging::info(format_args!(
        "trojan [{name}] inbound connection to {destination}"
    ));
    let framed: AnyStream = Box::new(stream);
    drive_framed(
        ClientConn::framed(framed, local),
        peer,
        destination,
        &tag,
        &router,
    )
    .await
}

async fn read_trojan_request<S>(
    stream: &mut S,
    keys: &HashMap<[u8; KEY_LENGTH], String>,
) -> io::Result<(String, u8, Target)>
where
    S: AsyncRead + Unpin,
{
    let mut key = [0u8; KEY_LENGTH];
    // the reference reads exactly KeyLength bytes and calls a short one a bad
    // request, so a truncated head must not reach the lookup
    match stream.read_exact(&mut key).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(io::Error::other("bad request size"));
        }
        Err(err) => return Err(err),
    }
    let name = keys
        .get(&key)
        .ok_or_else(|| io::Error::other("bad request"))?
        .clone();
    skip_crlf(stream).await?;
    let mut command = [0u8; 1];
    stream.read_exact(&mut command).await?;
    if !matches!(
        command[0],
        COMMAND_TCP | COMMAND_UDP | COMMAND_UDP_ALT | COMMAND_MUX
    ) {
        return Err(io::Error::other(format!("unknown command {}", command[0])));
    }
    let destination = read_target(stream).await?;
    skip_crlf(stream).await?;
    Ok((name, command[0], destination))
}

async fn skip_crlf<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(io::Error::other("skip crlf"));
    }
    Ok(())
}

/// `[version][uuid][addonsLen][addons][command][addr][port]`, and the addons
/// block that carries the flow (`readAddons`: `(1<<3)|2` then a uvarint length).
async fn read_request<S>(
    stream: &mut S,
    users: &HashMap<[u8; 16], User>,
) -> io::Result<(User, u8, Target, String)>
where
    S: AsyncRead + Unpin,
{
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != 0 {
        return Err(io::Error::other(format!("unknown version: {}", version[0])));
    }
    let mut uuid = [0u8; 16];
    stream.read_exact(&mut uuid).await?;
    let mut addons_len = [0u8; 1];
    stream.read_exact(&mut addons_len).await?;
    let mut flow = String::new();
    if addons_len[0] > 0 {
        let mut addons = vec![0u8; addons_len[0] as usize];
        stream.read_exact(&mut addons).await?;
        flow = read_addons(&addons)?;
    }
    let mut command = [0u8; 1];
    stream.read_exact(&mut command).await?;
    let user = users
        .get(&uuid)
        .ok_or_else(|| io::Error::other(format!("unknown UUID: {}", hex(&uuid))))?
        .clone();
    // Command 3 ends the VLESS header; its destinations are inside mux frames.
    let destination = if command[0] == VLESS_COMMAND_MUX {
        Target::Domain("v1.mux.cool".to_string(), 0)
    } else {
        read_vless_target(stream).await?
    };
    Ok((user, command[0], destination, flow))
}

fn read_addons(addons: &[u8]) -> io::Result<String> {
    let mut at = 0usize;
    let mut flow = String::new();
    while at < addons.len() {
        let header = addons[at];
        at += 1;
        match header & 0x07 {
            2 => {
                let (len, used) = read_uvarint(&addons[at..])?;
                at += used;
                let end = at + len as usize;
                let bytes = addons
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("addon field is truncated"))?;
                // field 1 is the flow; field 2 is the seed for the AEAD modes we
                // do not speak
                if header >> 3 == 1 {
                    flow = String::from_utf8_lossy(bytes).to_string();
                }
                at = end;
            }
            _ => return Err(io::Error::other(format!("unknown addon proto: {header}"))),
        }
    }
    Ok(flow)
}

fn read_uvarint(bytes: &[u8]) -> io::Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(io::Error::other("varint is too long"));
        }
    }
    Err(io::Error::other("varint is truncated"))
}

/// The address block in the socks shape, `[atyp][addr][port]`, which is what
/// trojan's `M.SocksaddrSerializer` writes.
async fn read_target<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    // Trojan uses SOCKS address types (1/3/4); the shared reader uses
    // VLESS/VMess types (1/2/3). Translate only at the Trojan boundary.
    let addr_type = match atyp[0] {
        0x01 => 0x01,
        0x03 => 0x02,
        0x04 => 0x03,
        other => return Err(io::Error::other(format!("unknown address type: {other}"))),
    };
    let addr = read_addr(stream, addr_type).await?;
    Ok(addr.with_port(read_port(stream).await?))
}

/// The vless destination block is `[port][atyp][addr]`: `vmess.AddressSerializer`
/// is the port-first serializer, and both the reference's vless client and ours
/// write it that way. It is not the socks shape, and a server that reads one as
/// the other is invisible until a third party's client arrives -- which is how
/// this one shipped: our own client failed against our own server, and the test
/// was green because its hand-written client repeated the mistake.
async fn read_vless_target<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + Unpin,
{
    let port = read_port(stream).await?;
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    let addr = read_addr(stream, atyp[0]).await?;
    Ok(addr.with_port(port))
}

enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String),
}

impl Addr {
    fn with_port(self, port: u16) -> Target {
        match self {
            Addr::V4(octets) => Target::Ip(SocketAddr::from((octets, port))),
            Addr::V6(octets) => Target::Ip(SocketAddr::from((octets, port))),
            Addr::Domain(host) => Target::Domain(host, port),
        }
    }
}

async fn read_addr<S>(stream: &mut S, atyp: u8) -> io::Result<Addr>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ok(Addr::V4(octets))
        }
        0x02 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            Ok(Addr::Domain(String::from_utf8_lossy(&host).into_owned()))
        }
        0x03 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ok(Addr::V6(octets))
        }
        other => Err(io::Error::other(format!("unknown address type: {other}"))),
    }
}

async fn read_port<S>(stream: &mut S) -> io::Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

fn hex(uuid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (index, byte) in uuid.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod trojan_address_tests {
    use super::*;

    async fn assert_request(address: &[u8], expected: Target) {
        let key = [b'a'; KEY_LENGTH];
        let keys = HashMap::from([(key, "test-user".to_string())]);
        let mut request = key.to_vec();
        request.extend_from_slice(b"\r\n\x01");
        request.extend_from_slice(address);
        request.extend_from_slice(b"\r\npayload");
        let mut stream = request.as_slice();
        let (name, command, target) = read_trojan_request(&mut stream, &keys).await.unwrap();
        assert_eq!(name, "test-user");
        assert_eq!(command, COMMAND_TCP);
        assert_eq!(target, expected);
        assert_eq!(
            stream, b"payload",
            "address parsing must preserve the payload"
        );
    }

    #[tokio::test]
    async fn trojan_ipv4_request() {
        assert_request(
            &[1, 127, 0, 0, 1, 0x01, 0xbb],
            Target::Ip("127.0.0.1:443".parse().unwrap()),
        )
        .await;
    }

    #[tokio::test]
    async fn trojan_domain_request() {
        // SOCKS/Trojan domain ATYP is 3, not VLESS/VMess's 2.
        assert_request(
            b"\x03\x0bexample.com\x01\xbb",
            Target::Domain("example.com".into(), 443),
        )
        .await;
        let mut address = vec![3, 255];
        address.extend_from_slice(&[b'a'; 255]);
        address.extend_from_slice(&8443u16.to_be_bytes());
        assert_request(&address, Target::Domain("a".repeat(255), 8443)).await;
    }

    #[tokio::test]
    async fn trojan_ipv6_request() {
        let mut address = vec![4];
        address.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        address.extend_from_slice(&8443u16.to_be_bytes());
        assert_request(&address, Target::Ip("[::1]:8443".parse().unwrap())).await;
    }

    #[tokio::test]
    async fn trojan_rejects_unknown_address_types() {
        for atyp in [0, 2, 5, 255] {
            let bytes = [atyp, 1, b'a', 0x01, 0xbb];
            let mut stream = bytes.as_slice();
            assert!(read_target(&mut stream).await.is_err(), "ATYP {atyp}");
            assert_eq!(
                stream,
                &bytes[1..],
                "unknown ATYP must not consume an address"
            );
        }
    }

    #[tokio::test]
    async fn trojan_rejects_truncated_addresses_and_ports() {
        let addresses: &[&[u8]] = &[
            &[1, 127, 0, 0, 1, 0x01, 0xbb],
            b"\x03\x0bexample.com\x01\xbb",
            &[
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
            ],
        ];
        for address in addresses {
            for len in 0..address.len() {
                let mut stream = &address[..len];
                assert!(
                    read_target(&mut stream).await.is_err(),
                    "{address:?} at {len}"
                );
            }
        }
    }

    #[tokio::test]
    async fn vless_keeps_its_port_first_address_types() {
        let cases = [
            (
                b"\x01\xbb\x01\x7f\x00\x00\x01".as_slice(),
                Target::Ip("127.0.0.1:443".parse().unwrap()),
            ),
            (
                b"\x01\xbb\x02\x0bexample.com".as_slice(),
                Target::Domain("example.com".into(), 443),
            ),
            (
                b"\x01\xbb\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                    .as_slice(),
                Target::Ip("[::1]:443".parse().unwrap()),
            ),
        ];
        for (mut stream, expected) in cases {
            assert_eq!(read_vless_target(&mut stream).await.unwrap(), expected);
            assert!(stream.is_empty());
        }
    }
}

#[cfg(test)]
mod xudp_tests {
    use super::*;
    use serde_json::json;
    use tokio::net::UdpSocket;

    async fn write_frame(
        stream: &mut tokio::io::DuplexStream,
        meta: &[u8],
        payload: Option<&[u8]>,
    ) {
        stream.write_u16(meta.len() as u16).await.unwrap();
        stream.write_all(meta).await.unwrap();
        if let Some(payload) = payload {
            stream.write_u16(payload.len() as u16).await.unwrap();
            stream.write_all(payload).await.unwrap();
        }
    }

    async fn read_frame(stream: &mut tokio::io::DuplexStream) -> (Vec<u8>, Option<Vec<u8>>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let len = stream.read_u16().await.unwrap();
            let mut meta = vec![0; usize::from(len)];
            stream.read_exact(&mut meta).await.unwrap();
            let payload = if meta[3] & 1 != 0 {
                let len = stream.read_u16().await.unwrap();
                let mut payload = vec![0; usize::from(len)];
                stream.read_exact(&mut payload).await.unwrap();
                Some(payload)
            } else {
                None
            };
            (meta, payload)
        })
        .await
        .expect("XUDP reply deadline")
    }

    #[tokio::test]
    async fn xudp_wire_control_frames_session_ids_and_end_cleanup() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = echo.local_addr().unwrap();
        let (observed, mut remotes) = tokio::sync::mpsc::unbounded_channel();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0; 2048];
            loop {
                let (n, from) = echo.recv_from(&mut buf).await.unwrap();
                observed.send(from).unwrap();
                echo.send_to(&buf[..n], from).await.unwrap();
            }
        });
        // A named target must retain its domain when the route is selected.
        let router = Router::new(&json!({
            "outbounds": [{"type":"direct","tag":"out"},{"type":"block","tag":"deny"}],
            "route":{"final":"deny","rules":[{"domain":"127.0.0.1","outbound":"out"}]}
        }))
        .unwrap();
        let (mut client, server) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            serve_xudp(
                Box::new(server),
                "127.0.0.1:12345".parse().unwrap(),
                "test",
                &router,
            )
            .await
        });
        let mut new = vec![1, 2, 1, 1, 2]; // session 0x0102, New/Data/UDP
        new.extend_from_slice(&address.port().to_be_bytes());
        new.extend_from_slice(&[2, 9]); // domain address, length
        new.extend_from_slice(b"127.0.0.1");
        new.extend_from_slice(&[0x42; 8]); // optional Xray GlobalID
        let mut expected = vec![1, 2, 2, 1, 2];
        expected.extend_from_slice(&address.port().to_be_bytes());
        expected.extend_from_slice(&[1, 127, 0, 0, 1]);
        write_frame(&mut client, &new, Some(b"first")).await;
        assert_eq!(
            read_frame(&mut client).await,
            (expected.clone(), Some(b"first".to_vec()))
        );
        let first_remote = remotes.recv().await.unwrap();

        // KeepAlive has no payload length; the following frame must stay aligned.
        write_frame(&mut client, &[0, 0, 4, 0], None).await;
        write_frame(&mut client, &[1, 2, 2, 1], Some(b"second")).await;
        assert_eq!(
            read_frame(&mut client).await,
            (expected.clone(), Some(b"second".to_vec()))
        );
        assert_eq!(remotes.recv().await.unwrap(), first_remote);

        new[0] = 3;
        new[1] = 4;
        write_frame(&mut client, &new, Some(b"independent")).await;
        let mut second_expected = expected.clone();
        second_expected[0] = 3;
        second_expected[1] = 4;
        assert_eq!(
            read_frame(&mut client).await,
            (second_expected.clone(), Some(b"independent".to_vec()))
        );
        let second_remote = remotes.recv().await.unwrap();
        assert_ne!(first_remote, second_remote);

        write_frame(&mut client, &[1, 2, 3, 0], None).await;
        write_frame(&mut client, &[1, 2, 2, 1], Some(b"closed")).await;
        assert_eq!(read_frame(&mut client).await, (vec![1, 2, 3, 2], None));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(socket) = UdpSocket::bind(first_remote).await {
                    drop(socket);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("End releases the UDP socket");
        write_frame(&mut client, &[3, 4, 2, 1], Some(b"still open")).await;
        assert_eq!(
            read_frame(&mut client).await,
            (second_expected, Some(b"still open".to_vec()))
        );
        remotes.recv().await.unwrap();

        // TCP mux is explicitly rejected, without disturbing the UDP session.
        new[0] = 5;
        new[1] = 6;
        new[4] = 1;
        write_frame(&mut client, &new, Some(b"unsupported TCP")).await;
        assert_eq!(read_frame(&mut client).await, (vec![5, 6, 3, 2], None));
        drop(client);
        task.await.unwrap().unwrap();
        echo_task.abort();
    }

    #[tokio::test]
    async fn xudp_rejects_unbounded_or_short_metadata() {
        for len in [3, 513] {
            let router = Router::new(&json!({"outbounds":[{"type":"direct"}]})).unwrap();
            let (mut client, server) = tokio::io::duplex(64);
            client.write_u16(len).await.unwrap();
            assert!(
                serve_xudp(
                    Box::new(server),
                    "127.0.0.1:1".parse().unwrap(),
                    "test",
                    &router
                )
                .await
                .is_err()
            );
        }
    }
}
