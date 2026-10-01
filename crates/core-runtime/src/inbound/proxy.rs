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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use crate::inbound::{Target, drive_transparent, parse_listen};
use crate::logging;
use crate::route::Router;

/// Request command bytes (`vmess.CommandTCP` and friends).
pub(crate) const COMMAND_TCP: u8 = 0x01;
pub(crate) const COMMAND_UDP: u8 = 0x02;

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
        let listen = parse_listen(object, &at)?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;
        Ok(Self {
            listener,
            tag,
            router,
            users,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let users = self.users.clone();
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    tokio::spawn(async move {
                        if let Err(err) = handle_vless(stream, peer, users, tag, router).await {
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
async fn handle_vless(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    users: HashMap<[u8; 16], User>,
    tag: String,
    router: Arc<Router>,
) -> io::Result<()> {
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
    drive_transparent(stream, peer, destination, &tag, &router).await
}

/// `[version][uuid][addonsLen][addons][command][addr][port]`, and the addons
/// block that carries the flow (`readAddons`: `(1<<3)|2` then a uvarint length).
async fn read_request(
    stream: &mut tokio::net::TcpStream,
    users: &HashMap<[u8; 16], User>,
) -> io::Result<(User, u8, Target, String)> {
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
    let destination = read_target(stream).await?;
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

/// The address block, the same one our client writes: `[atyp][addr][port]`.
async fn read_target(stream: &mut tokio::net::TcpStream) -> io::Result<Target> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let port = read_port(stream).await?;
            Ok(Target::Ip(SocketAddr::from((addr, port))))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            let port = read_port(stream).await?;
            Ok(Target::Domain(
                String::from_utf8_lossy(&host).to_string(),
                port,
            ))
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let port = read_port(stream).await?;
            Ok(Target::Ip(SocketAddr::from((addr, port))))
        }
        other => Err(io::Error::other(format!("unknown address type: {other}"))),
    }
}

async fn read_port(stream: &mut tokio::net::TcpStream) -> io::Result<u16> {
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
