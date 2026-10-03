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
        let listen = parse_listen(object, &at)?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            users,
            tls,
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
                    tokio::spawn(async move {
                        // The socket's own address is read here because a TLS
                        // stream is handed over where the socket was, and
                        // nothing downstream can ask it again.
                        let local = stream.local_addr().unwrap_or(peer);
                        let result = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(stream) => {
                                    handle_vless(stream, peer, local, users, tag, router).await
                                }
                                Err(err) => Err(err),
                            },
                            None => handle_vless(stream, peer, local, users, tag, router).await,
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("vless {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::debug(format_args!("vless accept: {err}"));
                    return;
                }
            }
        }
    }
}

/// One connection: read the request, check the user, route it.
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
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            keys,
            tls: ServerTls::from_inbound(obj, &at)?,
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
                    tokio::spawn(async move {
                        let local = stream.local_addr().unwrap_or(peer);
                        let result = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(stream) => {
                                    handle_trojan(stream, peer, local, keys, tag, router).await
                                }
                                Err(err) => Err(err),
                            },
                            None => handle_trojan(stream, peer, local, keys, tag, router).await,
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("trojan {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::debug(format_args!("trojan accept: {err}"));
                    return;
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
    let destination = read_vless_target(stream).await?;
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
    let addr = read_addr(stream, atyp[0]).await?;
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
