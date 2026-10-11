//! HTTPS upgrade, controlbase records and HTTP/2 for the native control client.
//! Wire formats follow tailscale/control/{controlbase,controlhttp,ts2021}.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::inbound::AnyStream;
use crate::tls_client::TlsOptions;

use super::control::parse_key_hex;
use super::noise::{CipherState, NoiseIkInitiator};

// Advertise only semantics this implementation understands. In particular,
// maps use full PacketFilter, not capability grants or compressed zstd bodies.
pub const CAPABILITY_VERSION: u16 = 46;
const MAX_HEADER: usize = 16 * 1024;
pub const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_RECORD: usize = 4096 - 3;
const UPGRADE: &str = "tailscale-control-protocol";

pub struct ControlUrl {
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub prefix: String,
}

impl ControlUrl {
    pub fn parse(url: &str) -> io::Result<Self> {
        let uri: http::Uri = url
            .parse()
            .map_err(|_| invalid("tailscale: invalid control URL"))?;
        if uri.scheme_str() != Some("https") || uri.authority().is_none() || uri.query().is_some() {
            return Err(invalid(
                "tailscale: control_url must be an HTTPS origin or base path",
            ));
        }
        let authority = uri.authority().unwrap();
        if authority.as_str().contains('@') {
            return Err(invalid("tailscale: control URL credentials are forbidden"));
        }
        Ok(Self {
            authority: authority.to_string(),
            host: uri.host().unwrap().trim_matches(['[', ']']).to_owned(),
            port: uri.port_u16().unwrap_or(443),
            prefix: uri.path().trim_end_matches('/').to_owned(),
        })
    }

    pub(super) async fn connect(&self) -> io::Result<AnyStream> {
        let socket = TcpStream::connect((self.host.as_str(), self.port)).await?;
        socket.set_nodelay(true)?;
        let options =
            json!({"tls": {"enabled": true, "server_name": self.host, "alpn": ["http/1.1"]}});
        let tls = TlsOptions::from_outbound(
            options.as_object().unwrap(),
            &self.host,
            "tailscale.control",
        )
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("tailscale: missing control TLS"))?;
        tls.establish(socket, &[b"http/1.1"]).await
    }

    fn path(&self, path: &str) -> String {
        format!("{}{path}", self.prefix)
    }

    async fn server_key(&self) -> io::Result<PublicKey> {
        let mut stream = self.connect().await?;
        let path = self.path(&format!("/key?v={CAPABILITY_VERSION}"));
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.authority
        );
        stream.write_all(request.as_bytes()).await?;
        let response = read_http_header(&mut stream).await?;
        if response.status != 200 {
            return Err(invalid("tailscale: control key request rejected"));
        }
        let body = read_http_body(&mut stream, &response).await?;
        let response: Value = serde_json::from_slice(&body)
            .map_err(|_| invalid("tailscale: invalid control key response"))?;
        let key = response
            .get("publicKey")
            .or_else(|| response.get("PublicKey"))
            .and_then(Value::as_str)
            .and_then(parse_key_hex)
            .ok_or_else(|| invalid("tailscale: missing control Noise key"))?;
        if key == [0; 32] {
            return Err(invalid("tailscale: zero control key"));
        }
        Ok(PublicKey::from(key))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) struct HttpHeader {
    pub status: u16,
    headers: Vec<(String, String)>,
}

impl HttpHeader {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

// Read no bytes past the HTTP upgrade boundary: Noise immediately follows it.
pub(super) async fn read_http_header<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<HttpHeader> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= MAX_HEADER {
            return Err(invalid("tailscale: oversized HTTP header"));
        }
        bytes.push(stream.read_u8().await?);
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| invalid("tailscale: invalid HTTP header"))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("tailscale: invalid HTTP status"))?;
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("tailscale: malformed HTTP header"))?;
        headers.push((key.to_owned(), value.trim().to_owned()));
    }
    Ok(HttpHeader { status, headers })
}

async fn read_http_body<R: AsyncRead + Unpin>(
    stream: &mut R,
    response: &HttpHeader,
) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    if response
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                if line.len() >= 128 {
                    return Err(invalid("tailscale: oversized HTTP chunk header"));
                }
                line.push(stream.read_u8().await?);
            }
            let text = std::str::from_utf8(&line)
                .map_err(|_| invalid("tailscale: invalid HTTP chunk size"))?;
            let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| invalid("tailscale: invalid HTTP chunk size"))?;
            if size == 0 {
                return Ok(body);
            }
            if size > MAX_BODY - body.len() {
                return Err(invalid("tailscale: oversized control key response"));
            }
            let start = body.len();
            body.resize(start + size, 0);
            stream.read_exact(&mut body[start..]).await?;
            let mut end = [0; 2];
            stream.read_exact(&mut end).await?;
            if end != *b"\r\n" {
                return Err(invalid("tailscale: invalid HTTP chunk ending"));
            }
        }
    }
    if let Some(length) = response.get("content-length") {
        let length: usize = length
            .parse()
            .map_err(|_| invalid("tailscale: invalid HTTP content length"))?;
        if length > MAX_BODY {
            return Err(invalid("tailscale: oversized control key response"));
        }
        body.resize(length, 0);
        stream.read_exact(&mut body).await?;
    } else {
        stream
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut body)
            .await?;
        if body.len() > MAX_BODY {
            return Err(invalid("tailscale: oversized control key response"));
        }
    }
    Ok(body)
}

// A bounded duplex supplies AsyncRead/AsyncWrite without unsafe pin projections.
// Owner cancellation stops both pumps, including a blocked relay/control read.
pub struct ControlConnection {
    sender: Mutex<h2::client::SendRequest<Bytes>>,
    tasks: Vec<JoinHandle<()>>,
    authority: String,
    prefix: String,
}

impl Drop for ControlConnection {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl ControlConnection {
    pub async fn connect(url: &str, machine: &StaticSecret) -> io::Result<Arc<Self>> {
        tokio::time::timeout(Duration::from_secs(20), Self::connect_inner(url, machine))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tailscale: control connection timeout",
                )
            })?
    }

    async fn connect_inner(url: &str, machine: &StaticSecret) -> io::Result<Arc<Self>> {
        let url = ControlUrl::parse(url)?;
        let server = url.server_key().await?;
        if !machine.diffie_hellman(&server).was_contributory() {
            return Err(invalid("tailscale: non-contributory control key"));
        }
        let prologue = format!("Tailscale Control Protocol v{CAPABILITY_VERSION}");
        let mut noise = NoiseIkInitiator::new(machine.clone(), server, prologue.as_bytes());
        let payload = noise.write_msg1(&[]);
        let mut init = CAPABILITY_VERSION.to_be_bytes().to_vec();
        init.push(1);
        init.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        init.extend_from_slice(&payload);
        let init = base64::engine::general_purpose::STANDARD.encode(init);
        let mut stream = url.connect().await?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: {UPGRADE}\r\nX-Tailscale-Handshake: {init}\r\nContent-Length: 0\r\n\r\n",
            url.path("/ts2021"),
            url.authority
        );
        stream.write_all(request.as_bytes()).await?;
        let response = read_http_header(&mut stream).await?;
        if response.status != 101 || response.get("upgrade") != Some(UPGRADE) {
            return Err(invalid("tailscale: control protocol upgrade rejected"));
        }
        let mut header = [0; 3];
        stream.read_exact(&mut header).await?;
        if header != [2, 0, 48] {
            return Err(invalid("tailscale: invalid Noise handshake response"));
        }
        let mut payload = [0; 48];
        stream.read_exact(&mut payload).await?;
        let (_, (tx, rx)) = noise.read_msg2(&payload).map_err(io::Error::other)?;
        let (io, remote) = tokio::io::duplex(65536);
        let (remote_read, remote_write) = tokio::io::split(remote);
        let (read, write) = tokio::io::split(stream);
        let rx_task = tokio::spawn(async move {
            let _ = receive_records(read, remote_write, rx.into_transport()).await;
        });
        let tx_task = tokio::spawn(async move {
            let _ = send_records(remote_read, write, tx.into_transport()).await;
        });
        let handshake = h2::client::handshake(io).await;
        let (sender, connection) = match handshake {
            Ok(pair) => pair,
            Err(error) => {
                rx_task.abort();
                tx_task.abort();
                return Err(io::Error::other(error));
            }
        };
        let h2_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(Self {
            sender: Mutex::new(sender),
            tasks: vec![rx_task, tx_task, h2_task],
            authority: url.authority,
            prefix: url.prefix,
        }))
    }

    pub async fn request(&self, path: &str, value: &Value) -> io::Result<h2::RecvStream> {
        let body = serde_json::to_vec(value).map_err(io::Error::other)?;
        if body.len() > MAX_BODY {
            return Err(invalid("tailscale: oversized control request"));
        }
        let mut request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{}{}{path}", self.authority, self.prefix))
            .header("content-type", "application/json");
        if let Some(node) = value.get("NodeKey").and_then(Value::as_str) {
            request = request.header("Ts-Lb", node);
        }
        let request = request.body(()).map_err(io::Error::other)?;
        let (response, mut stream) = self
            .sender
            .lock()
            .await
            .send_request(request, false)
            .map_err(io::Error::other)?;
        stream
            .send_data(Bytes::from(body), true)
            .map_err(io::Error::other)?;
        let response = response.await.map_err(io::Error::other)?;
        if response.status() != http::StatusCode::OK {
            // Status and the fixed protocol path are safe diagnostic context;
            // response bodies can contain login URLs and must stay private.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tailscale: control {path} rejected ({})", response.status()),
            ));
        }
        Ok(response.into_body())
    }

    pub async fn json(&self, path: &str, value: &Value) -> io::Result<Value> {
        let mut stream = self.request(path, value).await?;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk.map_err(io::Error::other)?;
            if chunk.len() > MAX_BODY - bytes.len() {
                return Err(invalid("tailscale: oversized control response"));
            }
            bytes.extend_from_slice(&chunk);
            stream
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(io::Error::other)?;
        }
        serde_json::from_slice(&bytes).map_err(|_| invalid("tailscale: malformed control response"))
    }
}

async fn send_records<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
    mut cipher: CipherState,
) -> io::Result<()> {
    let mut bytes = vec![0; MAX_RECORD - 16];
    loop {
        let size = read.read(&mut bytes).await?;
        if size == 0 {
            return write.shutdown().await;
        }
        let ciphertext = cipher.encrypt_with_ad(&[], &bytes[..size]);
        write.write_all(&[4]).await?;
        write
            .write_all(&(ciphertext.len() as u16).to_be_bytes())
            .await?;
        write.write_all(&ciphertext).await?;
        write.flush().await?;
    }
}

async fn receive_records<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
    mut cipher: CipherState,
) -> io::Result<()> {
    let mut initial = Vec::new();
    let mut first = true;
    loop {
        let mut header = [0; 3];
        read.read_exact(&mut header).await?;
        let size = usize::from(u16::from_be_bytes([header[1], header[2]]));
        if header[0] != 4 || !(16..=MAX_RECORD).contains(&size) {
            return Err(invalid("tailscale: invalid control record"));
        }
        let mut bytes = vec![0; size];
        read.read_exact(&mut bytes).await?;
        let bytes = cipher
            .decrypt_with_ad(&[], &bytes)
            .map_err(io::Error::other)?;
        if first {
            initial.extend_from_slice(&bytes);
            if initial.len() < 9 {
                continue;
            }
            if initial.starts_with(b"\xff\xff\xffTS") {
                let length = u32::from_be_bytes(initial[5..9].try_into().unwrap()) as usize;
                if length > MAX_BODY {
                    return Err(invalid("tailscale: oversized early Noise payload"));
                }
                if initial.len() < 9 + length {
                    continue;
                }
                let _: Value = serde_json::from_slice(&initial[9..9 + length])
                    .map_err(|_| invalid("tailscale: invalid early Noise payload"))?;
                write.write_all(&initial[9 + length..]).await?;
            } else {
                write.write_all(&initial).await?;
            }
            first = false;
            initial.clear();
        } else {
            write.write_all(&bytes).await?;
        }
    }
}

/// HTTP/2 body adapter for the map's little-endian length-prefixed JSON stream.
pub async fn read_maps(
    mut stream: h2::RecvStream,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> io::Result<()> {
    let mut buffered = Vec::new();
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(120), stream.data())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tailscale: map keepalive expired"))?
    {
        let chunk = chunk.map_err(io::Error::other)?;
        buffered.extend_from_slice(&chunk);
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(io::Error::other)?;
        while buffered.len() >= 4 {
            let length = u32::from_le_bytes(buffered[..4].try_into().unwrap()) as usize;
            if length == 0 || length > MAX_BODY {
                return Err(invalid("tailscale: oversized map frame"));
            }
            if buffered.len() < 4 + length {
                break;
            }
            let value = serde_json::from_slice(&buffered[4..4 + length])
                .map_err(|_| invalid("tailscale: invalid map frame"))?;
            tx.send(value).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "tailscale: map receiver stopped")
            })?;
            buffered.drain(..4 + length);
        }
        if buffered.len() > MAX_BODY + 4 {
            return Err(invalid("tailscale: oversized map buffer"));
        }
    }
    if !buffered.is_empty() {
        return Err(invalid("tailscale: truncated map frame"));
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "tailscale: map stream closed",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upgrade_header_never_consumes_the_first_noise_byte() {
        let mut input = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n\x02\x00\x30".as_slice();
        assert_eq!(read_http_header(&mut input).await.unwrap().status, 101);
        assert_eq!(input, &[2, 0, 48]);
    }

    #[tokio::test]
    async fn chunked_key_response_is_bounded_and_decoded() {
        let header = HttpHeader {
            status: 200,
            headers: vec![("Transfer-Encoding".into(), "chunked".into())],
        };
        let mut body = b"3\r\nabc\r\n2;ext=yes\r\nde\r\n0\r\n\r\n".as_slice();
        assert_eq!(read_http_body(&mut body, &header).await.unwrap(), b"abcde");
        let mut body = b"ffffff\r\n".as_slice();
        assert!(read_http_body(&mut body, &header).await.is_err());
    }

    #[test]
    fn control_origin_requires_verified_https_and_no_embedded_credentials() {
        assert!(ControlUrl::parse("http://localhost").is_err());
        assert!(ControlUrl::parse("https://user:password@host").is_err());
        let url = ControlUrl::parse("https://[::1]:8443/base/").unwrap();
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 8443);
        assert_eq!(url.path("/key"), "/base/key");
    }
}
