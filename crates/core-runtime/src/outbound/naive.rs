//! NaiveProxy outbound: HTTP/2 `CONNECT` over TLS (ALPN `h2`), with optional
//! UDP over the sing `uot` framing.
//!
//! The tunnel authority is the requested destination (NaiveProxy servers act
//! as a TCP forward proxy), the proxy identity travels in
//! `proxy-authorization: Basic`, and the TLS SNI comes from `tls.server_name`
//! or the server address. UDP needs `udp_over_tcp`: the client opens a tunnel
//! to the reserved magic address, writes the uot request header, and then
//! exchanges bare datagrams.

use std::io;
use std::net::IpAddr;

use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::proxy::{base64_std, server_endpoint};
use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::transport::h2io::{H2Io, H2Stream};
use crate::tls_client::TlsOptions;

/// sing `uot` v2 magic destination (version 0/2).
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
/// sing `uot` v1 (legacy): no request header, bare datagrams.
const UOT_LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";
const UOT_DEFAULT_VERSION: u8 = 2;

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const UDP_BUF: usize = 65_535;

/// Config knobs that only tune the reference (cronet) client internals.
const TUNING_FIELDS: &[&str] = &[
    "insecure_concurrency",
    "stream_receive_window",
    "quic_session_receive_window",
];

#[derive(Debug)]
pub struct Naive {
    server: String,
    port: u16,
    tls: TlsOptions,
    /// ready-made `proxy-authorization` value
    authorization: Option<String>,
    extra_headers: Vec<(String, String)>,
    /// `None` → UDP unsupported; `Some(1|2)` → uot framing version
    uot_version: Option<u8>,
}

impl Naive {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let Some(tls) = TlsOptions::from_outbound(obj, &server, at)? else {
            anyhow::bail!("{at}: naive outbound requires tls");
        };
        if obj.get("quic").and_then(Value::as_bool) == Some(true) {
            anyhow::bail!("{at}: naive quic transport is not implemented yet");
        }
        for field in TUNING_FIELDS {
            if obj.get(*field).is_some_and(|value| !value.is_null()) {
                logging::warn(format_args!(
                    "naive outbound {at}: {field} only tunes the reference client (ignored)"
                ));
            }
        }
        if obj
            .get("quic_congestion_control")
            .is_some_and(|value| !value.is_null())
        {
            logging::warn(format_args!(
                "naive outbound {at}: quic_congestion_control requires quic (ignored)"
            ));
        }
        let authorization = match (
            obj.get("username").and_then(Value::as_str),
            obj.get("password").and_then(Value::as_str),
        ) {
            (Some(username), Some(password)) => {
                let mut raw = Vec::new();
                raw.extend_from_slice(username.as_bytes());
                raw.push(b':');
                raw.extend_from_slice(password.as_bytes());
                Some(format!("Basic {}", base64_std(&raw)))
            }
            _ => None,
        };
        let mut extra_headers = Vec::new();
        if let Some(Value::Object(headers)) = obj.get("extra_headers") {
            for (name, value) in headers {
                // reference keeps the first value of each list
                let first = match value {
                    Value::String(text) => Some(text.clone()),
                    Value::Array(items) => {
                        items.first().and_then(Value::as_str).map(str::to_string)
                    }
                    _ => None,
                };
                let Some(first) = first else { continue };
                extra_headers.push((name.to_ascii_lowercase(), first));
            }
        }
        let uot_version = match obj.get("udp_over_tcp") {
            Some(Value::Bool(enabled)) => enabled.then_some(UOT_DEFAULT_VERSION),
            Some(Value::Object(map)) => {
                let enabled = map.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                if !enabled {
                    None
                } else {
                    let version = map
                        .get("version")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(u8::MAX as u64) as u8;
                    Some(if version == 0 {
                        UOT_DEFAULT_VERSION
                    } else {
                        version
                    })
                }
            }
            _ => None,
        };
        if let Some(version) = uot_version
            && version != 1
            && version != UOT_DEFAULT_VERSION
        {
            anyhow::bail!("{at}: unknown udp over tcp protocol version: {version}");
        }
        Ok(Self {
            server,
            port,
            tls,
            authorization,
            extra_headers,
            uot_version,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        self.tunnel(&authority_of(target)?).await
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let Some(version) = self.uot_version else {
            return Err(io::Error::other(
                "naive: UDP is not supported unless UDP over TCP is enabled",
            ));
        };
        let magic = if version == 1 {
            UOT_LEGACY_MAGIC
        } else {
            UOT_MAGIC
        };
        let (local, peer) = udp_loopback_pair().await?;
        let mut stream = self.tunnel(&format!("{magic}:0")).await?;
        if version != 1 {
            let header = uot_request(true, target)?;
            stream.write_all(&header).await?;
        }
        // datagrams: loopback peer -> tunnel
        spawn_bridge(stream, peer);
        Ok(local)
    }

    /// One h2 CONNECT stream: handshake, request, wrapped as raw pipes.
    async fn tunnel(&self, authority: &str) -> io::Result<AnyStream> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            crate::dns::connect_tcp(&self.server, self.port),
        )
        .await
        .map_err(|_| io::Error::other("naive: connect timeout"))??;
        let stream = self.tls.wrap_with_defaults(tcp, &[b"h2"]).await?;
        let (send_request, connection) = h2::client::handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("naive: h2 handshake: {e}")))?;
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut send_request = send_request
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("naive: h2 ready: {e}")))?;
        let mut builder = http::Request::builder()
            .method("CONNECT")
            .uri(authority.to_string());
        if let Some(authorization) = &self.authorization {
            builder = builder.header("proxy-authorization", authorization.clone());
        }
        for (name, value) in &self.extra_headers {
            builder = builder.header(name.clone(), value.clone());
        }
        let request = builder
            .body(())
            .map_err(|e| io::Error::other(format!("naive: build request: {e}")))?;
        let (response, send) = send_request
            .send_request(request, true)
            .map_err(|e| io::Error::other(format!("naive: send request: {e}")))?;
        Ok(Box::new(H2Io {
            h2: H2Stream::new(response, send, conn_task),
        }))
    }
}

/// Copy datagrams between the loopback socket and the tunnel in both
/// directions; the tunnel is the shared owner of the CONNECT stream.
fn spawn_bridge(stream: AnyStream, peer: tokio::net::UdpSocket) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let peer_send = std::sync::Arc::new(peer);
    let peer_recv = std::sync::Arc::clone(&peer_send);
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if peer_send.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF];
        while let Ok(n) = peer_recv.recv(&mut buf).await {
            if writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
}

/// CONNECT authority for a target (`host:port`, IPv6 bracketed).
fn authority_of(target: &Target) -> io::Result<String> {
    Ok(match target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) => format!("{v4}:{}", addr.port()),
            IpAddr::V6(v6) => format!("[{v6}]:{}", addr.port()),
        },
    })
}

/// `uot.WriteRequest`: `[is_connect][addr type][addr][port]`.
fn uot_request(is_connect: bool, target: &Target) -> io::Result<Vec<u8>> {
    let mut out = vec![u8::from(is_connect)];
    match target {
        Target::Domain(host, port) => {
            if host.len() > 255 {
                return Err(io::Error::other("naive: udp target domain too long"));
            }
            out.push(0x02);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) => {
                out.push(0x00);
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                out.push(0x01);
                out.extend_from_slice(&v6.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(extra: Value) -> Map<String, Value> {
        let mut base = json!({
            "type": "naive",
            "tag": "nv",
            "server": "example.com",
            "server_port": 443,
            "tls": {"enabled": true, "server_name": "cdn.example.com"},
        });
        let map = base.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("object") {
            map.insert(key.clone(), value.clone());
        }
        map.clone()
    }

    #[test]
    fn build_requires_tls() {
        let mut map = obj(json!({}));
        map.remove("tls");
        let err = Naive::build(&map, "outbounds[0]").unwrap_err().to_string();
        assert_eq!(err, "outbounds[0]: naive outbound requires tls");
        let mut map = obj(json!({}));
        map.insert("tls".to_string(), json!({"enabled": false}));
        assert!(Naive::build(&map, "outbounds[0]").is_err());
    }

    #[test]
    fn build_rejects_quic_transport() {
        let err = Naive::build(&obj(json!({"quic": true})), "outbounds[0]")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "outbounds[0]: naive quic transport is not implemented yet"
        );
    }

    #[test]
    fn build_authorization_and_headers() {
        let naive = Naive::build(
            &obj(json!({
                "username": "user",
                "password": "pass",
                "extra_headers": {"X-Padding": ["one", "two"], "X-Skip": 7},
            })),
            "outbounds[0]",
        )
        .expect("build");
        // base64("user:pass")
        assert_eq!(naive.authorization.as_deref(), Some("Basic dXNlcjpwYXNz"));
        assert_eq!(
            naive.extra_headers,
            vec![("x-padding".to_string(), "one".to_string())]
        );
        // tls.server_name is the SNI, the tunnel authority is the destination
        assert_eq!(naive.tls.server_name(), "cdn.example.com");
    }

    #[test]
    fn build_udp_over_tcp_versions() {
        assert_eq!(
            Naive::build(&obj(json!({})), "at")
                .expect("build")
                .uot_version,
            None
        );
        assert_eq!(
            Naive::build(&obj(json!({"udp_over_tcp": true})), "at")
                .expect("build")
                .uot_version,
            Some(2)
        );
        assert_eq!(
            Naive::build(&obj(json!({"udp_over_tcp": {"enabled": true}})), "at")
                .expect("build")
                .uot_version,
            Some(2)
        );
        assert_eq!(
            Naive::build(
                &obj(json!({"udp_over_tcp": {"enabled": true, "version": 1}})),
                "at"
            )
            .expect("build")
            .uot_version,
            Some(1)
        );
        assert_eq!(
            Naive::build(
                &obj(json!({"udp_over_tcp": {"enabled": false, "version": 2}})),
                "at"
            )
            .expect("build")
            .uot_version,
            None
        );
        let err = Naive::build(
            &obj(json!({"udp_over_tcp": {"enabled": true, "version": 3}})),
            "at",
        )
        .unwrap_err()
        .to_string();
        assert_eq!(err, "at: unknown udp over tcp protocol version: 3");
    }

    #[test]
    fn authority_and_uot_headers() {
        assert_eq!(
            authority_of(&Target::Domain("example.com".into(), 80)).expect("authority"),
            "example.com:80"
        );
        assert_eq!(
            authority_of(&Target::Ip("1.2.3.4:443".parse().expect("addr"))).expect("authority"),
            "1.2.3.4:443"
        );
        assert_eq!(
            authority_of(&Target::Ip("[::1]:443".parse().expect("addr"))).expect("authority"),
            "[::1]:443"
        );

        let v4 = uot_request(true, &Target::Ip("10.0.0.1:53".parse().expect("addr"))).expect("v4");
        assert_eq!(v4, vec![0x01, 0x00, 10, 0, 0, 1, 0, 53]);
        let v6 = uot_request(false, &Target::Ip("[::1]:5353".parse().expect("addr"))).expect("v6");
        let mut expected = vec![0x00, 0x01];
        expected.extend_from_slice(&[0u8; 15]);
        expected.push(1);
        expected.extend_from_slice(&5353u16.to_be_bytes());
        assert_eq!(v6, expected);
        let domain =
            uot_request(true, &Target::Domain("dns.example.com".into(), 53)).expect("fqdn");
        assert_eq!(&domain[..2], &[0x01, 0x02]);
        assert_eq!(domain[2] as usize, "dns.example.com".len());
        assert_eq!(&domain[3..3 + 15], b"dns.example.com");
        assert_eq!(&domain[domain.len() - 2..], &53u16.to_be_bytes());
    }
}
