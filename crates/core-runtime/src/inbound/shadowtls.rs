//! ShadowTLS server inbound (v2 and v3).
//!
//! Accepts TLS connections, extracts ClientHello (SNI, random, Session ID),
//! validates HMAC-SHA1 authentication against configured password/users.
//! If authenticated, queries the decoy server for a real ServerHello, forwards it
//! to the client, and routes the authenticated application stream.
//! If authentication fails and strict_mode is false, transparently proxies the connection
//! to the decoy handshake server.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::inbound::{Target, drive_transparent, parse_listen};
use crate::logging;
use crate::route::Router;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug)]
pub struct DecoyServer {
    pub server: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ParsedClientHello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub sni: Option<String>,
}

pub struct ShadowTls {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    version: u8,
    passwords: Vec<String>,
    handshake: Option<DecoyServer>,
    handshake_for_server_name: HashMap<String, DecoyServer>,
    strict_mode: bool,
    wildcard_sni: bool,
    detour: Option<String>,
}

impl ShadowTls {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("shadowtls")
            .to_string();
        let at = format!("inbound[{tag}]");

        let version = match object.get("version").and_then(Value::as_u64) {
            Some(2) => 2,
            Some(3) | None => 3,
            Some(v) => anyhow::bail!("{at}: unsupported shadowtls version {v} (expected 2 or 3)"),
        };

        let mut passwords = Vec::new();
        if let Some(pw) = object.get("password").and_then(Value::as_str)
            && !pw.is_empty()
        {
            passwords.push(pw.to_string());
        }
        if let Some(users) = object.get("users").and_then(Value::as_array) {
            for user in users {
                if let Some(pw) = user.get("password").and_then(Value::as_str)
                    && !pw.is_empty()
                    && !passwords.iter().any(|p| p == pw)
                {
                    passwords.push(pw.to_string());
                }
            }
        }
        if passwords.is_empty() {
            anyhow::bail!("{at}: missing password or users");
        }

        let handshake = parse_decoy(object.get("handshake"));
        let mut handshake_for_server_name = HashMap::new();
        if let Some(map) = object
            .get("handshake_for_server_name")
            .and_then(Value::as_object)
        {
            for (sni, val) in map {
                if let Some(decoy) = parse_decoy(Some(val)) {
                    handshake_for_server_name.insert(sni.clone(), decoy);
                }
            }
        }

        let strict_mode = object
            .get("strict_mode")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let wildcard_sni = object
            .get("wildcard_sni")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let detour = object
            .get("detour")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let listen = parse_listen(object, &at)?;
        let listener = super::bind_tcp(std::net::SocketAddr::from(listen))
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;

        logging::info(format_args!(
            "inbound shadowtls[{tag}] listening at {}:{} (version: {version}, strict: {strict_mode})",
            listen.0, listen.1
        ));

        Ok(Self {
            listener,
            tag,
            router,
            version,
            passwords,
            handshake,
            handshake_for_server_name,
            strict_mode,
            wildcard_sni,
            detour,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        let tag = Arc::new(self.tag);
        let router = self.router;
        let passwords = Arc::new(self.passwords);
        let handshake = Arc::new(self.handshake);
        let handshake_map = Arc::new(self.handshake_for_server_name);
        let strict_mode = self.strict_mode;
        let version = self.version;
        let wildcard_sni = self.wildcard_sni;
        let detour = Arc::new(self.detour);

        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let tag = Arc::clone(&tag);
                    let router = Arc::clone(&router);
                    let passwords = Arc::clone(&passwords);
                    let handshake = Arc::clone(&handshake);
                    let handshake_map = Arc::clone(&handshake_map);
                    let detour = Arc::clone(&detour);

                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(
                            stream,
                            peer,
                            &tag,
                            &router,
                            version,
                            &passwords,
                            handshake.as_ref().as_ref(),
                            &handshake_map,
                            strict_mode,
                            wildcard_sni,
                            detour.as_deref(),
                        )
                        .await
                        {
                            logging::debug(format_args!("shadowtls[{tag}] {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    super::serve_stalled(&format!("shadowtls[{tag}] accept"), &err).await;
                }
            }
        }
    }
}

fn parse_decoy(val: Option<&Value>) -> Option<DecoyServer> {
    let obj = val?.as_object()?;
    let server = obj.get("server")?.as_str()?.to_string();
    let port = obj
        .get("server_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(443);
    Some(DecoyServer { server, port })
}

/// Parse TLS ClientHello record: extract random, session_id and SNI.
pub fn parse_client_hello(raw: &[u8]) -> Option<ParsedClientHello> {
    if raw.len() < 5 || raw[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    if raw.len() < 5 + record_len {
        return None;
    }
    let body = &raw[5..5 + record_len];
    if body.len() < 39 || body[0] != 0x01 {
        return None;
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&body[6..38]);

    let sess_id_len = body[38] as usize;
    if body.len() < 39 + sess_id_len {
        return None;
    }
    let session_id = body[39..39 + sess_id_len].to_vec();

    let mut offset = 39 + sess_id_len;
    if offset + 2 > body.len() {
        return Some(ParsedClientHello {
            random,
            session_id,
            sni: None,
        });
    }
    let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2 + suites_len;

    if offset + 1 > body.len() {
        return Some(ParsedClientHello {
            random,
            session_id,
            sni: None,
        });
    }
    let comp_len = body[offset] as usize;
    offset += 1 + comp_len;

    if offset + 2 > body.len() {
        return Some(ParsedClientHello {
            random,
            session_id,
            sni: None,
        });
    }
    let ext_total = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;

    let ext_end = (offset + ext_total).min(body.len());
    let mut sni = None;
    while offset + 4 <= ext_end {
        let kind = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        if offset + len > ext_end {
            break;
        }
        if kind == 0x0000 && len >= 5 {
            let name_type = body[offset + 2];
            let name_len = u16::from_be_bytes([body[offset + 3], body[offset + 4]]) as usize;
            if name_type == 0
                && offset + 5 + name_len <= offset + len
                && let Ok(s) = std::str::from_utf8(&body[offset + 5..offset + 5 + name_len])
            {
                sni = Some(s.to_string());
            }
        }
        offset += len;
    }

    Some(ParsedClientHello {
        random,
        session_id,
        sni,
    })
}

fn verify_auth_v3(passwords: &[String], session_id: &[u8], sni: &str) -> bool {
    if session_id.len() != 32 {
        return false;
    }
    for pw in passwords {
        let Ok(mut mac) = HmacSha1::new_from_slice(pw.as_bytes()) else {
            continue;
        };
        mac.update(&session_id[..28]);
        mac.update(sni.as_bytes());
        let expected = mac.finalize().into_bytes();
        if session_id[28..32] == expected[..4] {
            return true;
        }
    }
    false
}

fn verify_auth_v2(passwords: &[String], random: &[u8; 32], session_id: &[u8]) -> bool {
    if session_id.len() != 32 {
        return false;
    }
    for pw in passwords {
        let Ok(mut mac) = HmacSha1::new_from_slice(pw.as_bytes()) else {
            continue;
        };
        mac.update(&random[..16]);
        let expected = mac.finalize().into_bytes();
        if session_id[..20] == expected[..20] {
            let ts = u32::from_be_bytes([
                session_id[20],
                session_id[21],
                session_id[22],
                session_id[23],
            ]);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            if (now as i64 - ts as i64).abs() <= 300 {
                return true;
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
    version: u8,
    passwords: &[String],
    default_decoy: Option<&DecoyServer>,
    decoy_map: &HashMap<String, DecoyServer>,
    strict_mode: bool,
    _wildcard_sni: bool,
    _detour: Option<&str>,
) -> io::Result<()> {
    // 1. Read TLS Record header (5 bytes)
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let is_tls = header[0] == 0x16;
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if !is_tls || record_len == 0 || record_len > 16384 {
        if strict_mode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shadowtls: not TLS handshake in strict mode",
            ));
        }
        return proxy_to_decoy(stream, &header, default_decoy).await;
    }

    // 2. Read full ClientHello record body
    let mut body = vec![0u8; record_len];
    stream.read_exact(&mut body).await?;

    let mut raw_client_hello = Vec::with_capacity(5 + record_len);
    raw_client_hello.extend_from_slice(&header);
    raw_client_hello.extend_from_slice(&body);

    let parsed = parse_client_hello(&raw_client_hello);
    let sni = parsed
        .as_ref()
        .and_then(|p| p.sni.as_deref())
        .unwrap_or_default();

    let decoy = parsed
        .as_ref()
        .and_then(|p| p.sni.as_ref())
        .and_then(|s| decoy_map.get(s))
        .or(default_decoy);

    // 3. Verify HMAC authentication
    let authenticated = if let Some(p) = &parsed {
        match version {
            2 => verify_auth_v2(passwords, &p.random, &p.session_id),
            _ => verify_auth_v3(passwords, &p.session_id, sni),
        }
    } else {
        false
    };

    if !authenticated {
        if strict_mode {
            logging::debug(format_args!(
                "shadowtls[{tag}] {peer}: client auth failed (strict mode, closing)"
            ));
            return Ok(());
        }
        logging::debug(format_args!(
            "shadowtls[{tag}] {peer}: client auth failed, relaying to decoy"
        ));
        return proxy_to_decoy_with_body(stream, &raw_client_hello, decoy).await;
    }

    logging::info(format_args!(
        "shadowtls[{tag}] {peer}: authenticated client (version {version}, sni: {sni})"
    ));

    // 4. Client is authenticated: fetch real ServerHello from decoy and forward to client
    if let Some(decoy) = decoy {
        let mut decoy_stream = TcpStream::connect((decoy.server.as_str(), decoy.port)).await?;
        decoy_stream.write_all(&raw_client_hello).await?;
        decoy_stream.flush().await?;

        // Read ServerHello from decoy
        let mut s_header = [0u8; 5];
        decoy_stream.read_exact(&mut s_header).await?;
        if s_header[0] == 0x16 {
            let s_len = u16::from_be_bytes([s_header[3], s_header[4]]) as usize;
            let mut s_body = vec![0u8; s_len];
            decoy_stream.read_exact(&mut s_body).await?;

            // Send ServerHello to client
            stream.write_all(&s_header).await?;
            stream.write_all(&s_body).await?;
            stream.flush().await?;
        }
        // Decoy handshake complete, drop decoy connection
        let _ = decoy_stream.shutdown().await;
    }

    // 5. Route client application stream
    let target = if !sni.is_empty() {
        Target::Domain(sni.to_string(), 443)
    } else {
        Target::Ip(SocketAddr::from(([127, 0, 0, 1], 443)))
    };

    drive_transparent(stream, peer, target, tag, router).await
}

async fn proxy_to_decoy(
    mut client: TcpStream,
    initial: &[u8],
    decoy: Option<&DecoyServer>,
) -> io::Result<()> {
    let Some(decoy) = decoy else {
        return Ok(());
    };
    let mut decoy_stream = TcpStream::connect((decoy.server.as_str(), decoy.port)).await?;
    decoy_stream.write_all(initial).await?;
    decoy_stream.flush().await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut decoy_stream).await;
    Ok(())
}

async fn proxy_to_decoy_with_body(
    mut client: TcpStream,
    full_payload: &[u8],
    decoy: Option<&DecoyServer>,
) -> io::Result<()> {
    let Some(decoy) = decoy else {
        return Ok(());
    };
    let mut decoy_stream = TcpStream::connect((decoy.server.as_str(), decoy.port)).await?;
    decoy_stream.write_all(full_payload).await?;
    decoy_stream.flush().await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut decoy_stream).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::shadowtls::{build_session_id_v2, build_session_id_v3};

    #[test]
    fn test_auth_v3_roundtrip() {
        let password = "my_secret_password";
        let passwords = vec![password.to_string()];
        let sni = "gateway.icloud.com";
        let random = [7u8; 32];

        let session_id = build_session_id_v3(password, &random, sni.as_bytes()).unwrap();
        assert!(verify_auth_v3(&passwords, &session_id, sni));
        assert!(!verify_auth_v3(&passwords, &session_id, "wrong.com"));
        assert!(!verify_auth_v3(&["other_pw".into()], &session_id, sni));
    }

    #[test]
    fn test_auth_v2_roundtrip() {
        let password = "my_secret_password";
        let passwords = vec![password.to_string()];
        let random = [42u8; 32];

        let session_id = build_session_id_v2(password, &random).unwrap();
        assert!(verify_auth_v2(&passwords, &random, &session_id));
        assert!(!verify_auth_v2(&["other".into()], &random, &session_id));
    }

    #[tokio::test]
    async fn test_shadowtls_handshake_flow() {
        // 1. Start mock decoy TLS server
        let decoy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = decoy_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n > 0 {
                        // Send mock ServerHello record
                        let mock_server_hello =
                            [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
                        let _ = sock.write_all(&mock_server_hello).await;
                    }
                });
            }
        });

        // 2. Start ShadowTLS server
        let cfg = serde_json::json!({
            "type": "shadowtls",
            "tag": "stls-in",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "version": 3,
            "password": "test_password_123",
            "handshake": {
                "server": "127.0.0.1",
                "server_port": decoy_addr.port()
            }
        });
        let router = Router::new(&serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }))
        .unwrap();
        let server = ShadowTls::bind(&cfg, router).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        // 3. Connect client and perform handshake
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let sni = "gateway.icloud.com";
        let random = [9u8; 32];
        let session_id = build_session_id_v3("test_password_123", &random, sni.as_bytes()).unwrap();

        // Construct TLS record
        let hello = build_test_client_hello(sni, &random, &session_id);
        client.write_all(&hello).await.unwrap();
        client.flush().await.unwrap();

        let mut resp_header = [0u8; 5];
        client.read_exact(&mut resp_header).await.unwrap();
        assert_eq!(resp_header[0], 0x16); // Handshake ServerHello
    }

    fn build_test_client_hello(sni: &str, random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x01); // ClientHello
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x03, 0x03]); // version
        msg.extend_from_slice(random);
        msg.push(32);
        msg.extend_from_slice(session_id);
        msg.extend_from_slice(&2u16.to_be_bytes());
        msg.extend_from_slice(&[0x13, 0x01]); // cipher suite
        msg.extend_from_slice(&[1, 0]); // compression

        // SNI extension
        let sni_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);

        let mut ext_buf = Vec::new();
        ext_buf.extend_from_slice(&0x0000u16.to_be_bytes());
        ext_buf.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext_buf.extend_from_slice(&sni_ext);

        msg.extend_from_slice(&(ext_buf.len() as u16).to_be_bytes());
        msg.extend_from_slice(&ext_buf);

        let len_bytes = (msg.len() as u32).to_be_bytes();
        body.extend_from_slice(&len_bytes[1..4]);
        body.extend_from_slice(&msg);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }
}
