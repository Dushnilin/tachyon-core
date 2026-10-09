//! AnyTLS server inbound: TLS transport + anytls session/stream framing.
//!
//! Accepts TLS connections, validates SHA256(password) greeting, exchanges
//! settings frames, and multiplexes client streams (`CMD_SYN`, `CMD_PSH`, `CMD_FIN`)
//! into the router data plane.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

use super::tls::ServerTls;
use crate::inbound::{ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::route::Router;

const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_RST: u8 = 6;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const FRAME_HEADER: usize = 7;

fn encode_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER + data.len());
    frame.push(cmd);
    frame.extend_from_slice(&sid.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn parse_header(header: &[u8; FRAME_HEADER]) -> (u8, u32, usize) {
    let cmd = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    (cmd, sid, len)
}

pub struct AnyTls {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    password_hash: [u8; 32],
    tls: Option<Arc<ServerTls>>,
}

impl AnyTls {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("anytls")
            .to_string();
        let at = format!("inbound[{tag}]");

        let password = object
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?;
        let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();

        let listen = parse_listen(object, &at)?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;

        let tls = ServerTls::from_inbound(obj, &at)?;

        Ok(Self {
            listener,
            tag,
            router,
            password_hash,
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
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let tls = self.tls.clone();
                    let expected_hash = self.password_hash;

                    tokio::spawn(async move {
                        let local = stream.local_addr().unwrap_or(peer);
                        let result: io::Result<()> = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(tls_stream) => {
                                    handle_session(
                                        tls_stream,
                                        peer,
                                        local,
                                        expected_hash,
                                        tag,
                                        router,
                                    )
                                    .await
                                }
                                Err(e) => Err(e),
                            },
                            None => {
                                handle_session(stream, peer, local, expected_hash, tag, router).await
                            }
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("anytls {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    logging::debug(format_args!("anytls accept: {err}"));
                    return;
                }
            }
        }
    }
}

async fn handle_session<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    expected_hash: [u8; 32],
    tag: String,
    router: Arc<Router>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. Read greeting: 32 bytes password hash + 2 bytes padding length
    let mut greeting = [0u8; 34];
    stream.read_exact(&mut greeting).await?;
    if greeting[..32] != expected_hash {
        return Err(io::Error::other("anytls: authentication failed"));
    }
    let pad_len = u16::from_be_bytes([greeting[32], greeting[33]]) as usize;
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        stream.read_exact(&mut pad).await?;
    }

    // 2. Read CMD_SETTINGS frame
    let mut header = [0u8; FRAME_HEADER];
    stream.read_exact(&mut header).await?;
    let (cmd, _sid, len) = parse_header(&header);
    if cmd != CMD_SETTINGS {
        return Err(io::Error::other(format!(
            "anytls: expected CMD_SETTINGS, got {cmd}"
        )));
    }
    let mut settings_buf = vec![0u8; len];
    stream.read_exact(&mut settings_buf).await?;

    // Respond with CMD_SERVER_SETTINGS
    stream
        .write_all(&encode_frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
        .await?;

    // Split stream into read and write halves
    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_half = Arc::new(Mutex::new(write_half));

    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // 3. Process session frames
    loop {
        if let Err(e) = read_half.read_exact(&mut header).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e);
        }
        let (cmd, sid, len) = parse_header(&header);
        let mut payload = vec![0u8; len];
        if len > 0 {
            read_half.read_exact(&mut payload).await?;
        }

        match cmd {
            CMD_SYN => {
                // Register new stream
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
                {
                    let mut map = streams.lock().await;
                    map.insert(sid, tx);
                }

                let write_out = Arc::clone(&write_half);
                let streams_ref = Arc::clone(&streams);
                let router = Arc::clone(&router);
                let tag = tag.clone();

                tokio::spawn(async move {
                    // First PSH carries the target address
                    let addr_payload = match rx.recv().await {
                        Some(data) => data,
                        None => return,
                    };
                    let target = match parse_target(&addr_payload) {
                        Ok(t) => t,
                        Err(e) => {
                            logging::debug(format_args!("anytls stream {sid}: parse target: {e}"));
                            let _ = write_out
                                .lock()
                                .await
                                .write_all(&encode_frame(CMD_RST, sid, &[]))
                                .await;
                            return;
                        }
                    };

                    let (client_read, mut client_write) = tokio::io::duplex(65536);
                    let (mut server_read, server_write) = tokio::io::duplex(65536);

                    // Forward incoming data from rx to client_write
                    let to_client = tokio::spawn(async move {
                        while let Some(data) = rx.recv().await {
                            if client_write.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    });

                    // Forward outgoing data from server_read to session write_half
                    let write_back = Arc::clone(&write_out);
                    let from_client = tokio::spawn(async move {
                        let mut buf = vec![0u8; 16384];
                        loop {
                            match server_read.read(&mut buf).await {
                                Ok(0) => {
                                    let _ = write_back
                                        .lock()
                                        .await
                                        .write_all(&encode_frame(CMD_FIN, sid, &[]))
                                        .await;
                                    break;
                                }
                                Ok(n) => {
                                    if write_back
                                        .lock()
                                        .await
                                        .write_all(&encode_frame(CMD_PSH, sid, &buf[..n]))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });

                    let stream_bridge = DualStream {
                        read: Box::new(client_read),
                        write: Box::new(server_write),
                    };

                    let client = ClientConn::framed(Box::new(stream_bridge), local);
                    let _ = drive_framed(client, peer, target, &tag, &router).await;

                    let _ = to_client.await;
                    let _ = from_client.await;
                    streams_ref.lock().await.remove(&sid);
                });
            }
            CMD_PSH => {
                let sender = {
                    let map = streams.lock().await;
                    map.get(&sid).cloned()
                };
                if let Some(tx) = sender {
                    let _ = tx.send(payload).await;
                }
            }
            CMD_FIN | CMD_RST => {
                let mut map = streams.lock().await;
                map.remove(&sid);
            }
            CMD_HEART_REQUEST => {
                let mut out = write_half.lock().await;
                let _ = out
                    .write_all(&encode_frame(CMD_HEART_RESPONSE, sid, &[]))
                    .await;
            }
            _ => {}
        }
    }

    Ok(())
}

fn parse_target(data: &[u8]) -> io::Result<Target> {
    if data.is_empty() {
        return Err(io::Error::other("empty target"));
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err(io::Error::other("short ipv4 target"));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Target::Ip(SocketAddr::new(std::net::IpAddr::V4(ip), port)))
        }
        0x04 => {
            if data.len() < 19 {
                return Err(io::Error::other("short ipv6 target"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Target::Ip(SocketAddr::new(std::net::IpAddr::V6(ip), port)))
        }
        0x03 => {
            if data.len() < 2 {
                return Err(io::Error::other("short domain target"));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(io::Error::other("incomplete domain target"));
            }
            let host = String::from_utf8(data[2..2 + len].to_vec())
                .map_err(|e| io::Error::other(format!("invalid domain: {e}")))?;
            let port = u16::from_be_bytes([data[2 + len], data[2 + len + 1]]);
            Ok(Target::Domain(host, port))
        }
        other => Err(io::Error::other(format!("unknown target atyp: {other}"))),
    }
}

struct DualStream {
    read: Box<tokio::io::DuplexStream>,
    write: Box<tokio::io::DuplexStream>,
}

impl AsyncRead for DualStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for DualStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_valid_domain() {
        let mut data = vec![0x03, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let target = parse_target(&data).unwrap();
        assert_eq!(target, Target::Domain("example.com".to_string(), 443));
    }

    #[test]
    fn parse_target_valid_ipv4() {
        let mut data = vec![0x01, 8, 8, 8, 8];
        data.extend_from_slice(&53u16.to_be_bytes());
        let target = parse_target(&data).unwrap();
        assert_eq!(target, Target::Ip("8.8.8.8:53".parse().unwrap()));
    }
}
