//! Authenticated DERP transport. It carries only encrypted WireGuard packets.

use std::io;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

use super::control_wire::{ControlUrl, read_http_header};
use super::derp::{self, DerpFrame, DerpNode};

pub struct Relay {
    pub send: mpsc::Sender<([u8; 32], Vec<u8>)>,
    task: JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub type Incoming = ([u8; 32], Vec<u8>);

pub async fn connect(
    node: &DerpNode,
    secret: &StaticSecret,
    preferred: bool,
    incoming: mpsc::Sender<Incoming>,
) -> io::Result<Relay> {
    let stream = tokio::time::timeout(Duration::from_secs(15), handshake(node, secret, preferred))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "tailscale: DERP connect timeout")
        })??;
    let (send, mut outgoing) = mpsc::channel::<Incoming>(128);
    let task = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(stream);
        // Reader runs separately: cancelling read_exact in a select branch
        // would discard a partially read frame and desynchronize the stream.
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let reader = tokio::spawn(async move {
            loop {
                let frame = match tokio::time::timeout(
                    Duration::from_secs(130),
                    derp::read_derp_frame(&mut read),
                )
                .await
                {
                    Ok(Ok(frame)) => frame,
                    _ => break,
                };
                match frame {
                    DerpFrame::RecvPacket { src_key, data } => {
                        if incoming.send((src_key, data)).await.is_err() {
                            break;
                        }
                    }
                    DerpFrame::Other {
                        frame_type: derp::FRAME_PING,
                        data,
                    } if data.len() == 8 => {
                        if control_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        });
        // Aborting a supervisor also aborts its reader.
        struct Guard(JoinHandle<()>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let mut reader = Guard(reader);
        loop {
            let frame = tokio::select! {
                result = &mut reader.0 => { let _ = result; break; }
                packet = outgoing.recv() => match packet {
                    Some((key, packet)) if packet.len() <= 65536 => derp::encode_send_packet(&key, &packet),
                    Some(_) => continue,
                    None => break,
                },
                ping = control_rx.recv() => match ping {
                    Some(bytes) => { let mut frame = vec![derp::FRAME_PONG, 0, 0, 0, 8]; frame.extend_from_slice(&bytes); frame },
                    None => break,
                }
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(10), write.write_all(&frame)).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    });
    Ok(Relay { send, task })
}

async fn handshake(
    node: &DerpNode,
    secret: &StaticSecret,
    preferred: bool,
) -> io::Result<crate::inbound::AnyStream> {
    // TLS authenticates the host before trusting its ephemeral DERP key.
    let url = ControlUrl::parse(&format!(
        "https://{}:{}",
        node.host_name,
        if node.port == 0 { 443 } else { node.port }
    ))?;
    let mut stream = url.connect().await?;
    let request = format!(
        "GET /derp HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n",
        url.authority
    );
    stream.write_all(request.as_bytes()).await?;
    let header = read_http_header(&mut stream).await?;
    if header.status != 101
        || !header
            .get("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("derp"))
    {
        return Err(io::Error::other("tailscale: DERP HTTP upgrade rejected"));
    }
    let DerpFrame::Other {
        frame_type: derp::FRAME_SERVER_KEY,
        data,
    } = derp::read_derp_frame(&mut stream).await?
    else {
        return Err(io::Error::other("tailscale: missing DERP server key"));
    };
    if data.len() < 40 || &data[..8] != derp::DERP_MAGIC {
        return Err(io::Error::other("tailscale: invalid DERP server key"));
    }
    let server = PublicKey::from(<[u8; 32]>::try_from(&data[8..40]).unwrap());
    let shared = secret.diffie_hellman(&server);
    if !shared.was_contributory() {
        return Err(io::Error::other("tailscale: invalid DERP DH key"));
    }
    let box_key = core_crypto::nacl::box_key(shared.as_bytes());
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce)
        .map_err(|_| io::Error::other("tailscale: DERP entropy unavailable"))?;
    let mut info = nonce.to_vec();
    info.extend_from_slice(&core_crypto::nacl::seal(
        &box_key,
        &nonce,
        br#"{"version":2}"#,
    ));
    stream
        .write_all(&derp::encode_client_info(
            PublicKey::from(secret).as_bytes(),
            &info,
        ))
        .await?;
    let DerpFrame::ServerInfo(info) = derp::read_derp_frame(&mut stream).await? else {
        return Err(io::Error::other(
            "tailscale: missing authenticated DERP server info",
        ));
    };
    if info.len() < 40 {
        return Err(io::Error::other("tailscale: truncated DERP server info"));
    }
    let nonce: &[u8; 24] = info[..24].try_into().unwrap();
    let info = core_crypto::nacl::open(&box_key, nonce, &info[24..])
        .ok_or_else(|| io::Error::other("tailscale: DERP authentication failed"))?;
    let info: serde_json::Value = serde_json::from_slice(&info)
        .map_err(|_| io::Error::other("tailscale: invalid DERP server info"))?;
    if info.get("version").and_then(serde_json::Value::as_u64) != Some(2) {
        return Err(io::Error::other(
            "tailscale: unsupported DERP protocol version",
        ));
    }
    stream
        .write_all(&derp::encode_note_preferred(preferred))
        .await?;
    Ok(stream)
}
