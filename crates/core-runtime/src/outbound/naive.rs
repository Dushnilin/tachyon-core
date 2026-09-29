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
use std::sync::Arc;

use serde_json::{Map, Value};
use tokio::io::AsyncWriteExt;

use crate::inbound::{AnyStream, Target};
use crate::logging;
use crate::outbound::proxy::{base64_std, server_endpoint};
use crate::outbound::quic::{CongestionKind, udp_loopback_pair};
use crate::outbound::transport::h2io::{H2Io, H2Stream};
use crate::outbound::uot::{UOT_DEFAULT_VERSION, magic_authority, request_header, spawn_bridge};
use crate::tls_client::TlsOptions;

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    /// `quic: true` runs the tunnel over HTTP/3 instead of HTTP/2
    quic: bool,
    quic_tunnel: crate::outbound::quic::QuicTunnelOptions,
    congestion: crate::outbound::quic::CongestionKind,
}

impl Naive {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let Some(tls) = TlsOptions::from_outbound(obj, &server, at)? else {
            anyhow::bail!("{at}: naive outbound requires tls");
        };
        // the reference refuses a naive tunnel that skips certificate checking
        if obj
            .get("tls")
            .and_then(|tls| tls.get("insecure"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            anyhow::bail!("{at}: insecure is not supported on naive outbound");
        }
        if obj
            .get("tls")
            .and_then(|tls| tls.get("disable_sni"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            anyhow::bail!("{at}: disable_sni is not supported on naive outbound");
        }
        let quic = obj.get("quic").and_then(Value::as_bool).unwrap_or(false);
        // the switch runs whether or not quic is on, like the reference
        let congestion = match obj
            .get("quic_congestion_control")
            .and_then(Value::as_str)
            .unwrap_or("")
        {
            "" | "bbr" | "bbr2" => CongestionKind::Bbr,
            "cubic" => CongestionKind::Cubic,
            "reno" => CongestionKind::NewReno,
            other => anyhow::bail!("{at}: unknown quic congestion control: {other}"),
        };
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
            quic,
            quic_tunnel: crate::outbound::quic::QuicTunnelOptions::parse(
                obj,
                at,
                crate::outbound::quic::QuicTunnelDefaults::tuic(),
            )?,
            congestion,
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
        let (local, peer) = udp_loopback_pair().await?;
        let mut stream = self.tunnel(&magic_authority(version)).await?;
        if version != 1 {
            let header = request_header(true, target)?;
            stream.write_all(&header).await?;
        }
        spawn_bridge(stream, peer);
        Ok(local)
    }

    /// One h2 CONNECT stream: handshake, request, wrapped as raw pipes.
    async fn tunnel(&self, authority: &str) -> io::Result<AnyStream> {
        if self.quic {
            return self.tunnel_quic(authority).await;
        }
        self.tunnel_h2(authority).await
    }

    /// The same CONNECT over HTTP/3, which is what `quic: true` asks for.
    async fn tunnel_quic(&self, authority: &str) -> io::Result<AnyStream> {
        let addr = crate::outbound::quic::resolve_host(&self.server, self.port).await?;
        let sock = crate::outbound::quic::bind_udp(addr)?;
        let (ep_config, transport) = self.quic_tunnel.build_configs(self.congestion, None, true);
        let mut endpoint = quinn::Endpoint::new(
            ep_config,
            None,
            sock,
            quinn::default_runtime().ok_or_else(|| io::Error::other("naive: no quinn runtime"))?,
        )?;
        let quic_tls = self.tls.quic_config(&[b"h3"])?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(addr, self.tls.server_name())
            .map_err(|e| io::Error::other(format!("naive: quic connect: {e}")))?;
        let connection = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| io::Error::other("naive: quic connect timeout"))?
            .map_err(|e| io::Error::other(format!("naive: quic connect: {e}")))?;
        let (mut h3_connection, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .map_err(|e| io::Error::other(format!("naive: h3 handshake: {e}")))?;
        let conn_task = tokio::spawn(async move {
            // the h3 connection is polled by hand; `wait_idle` never returns
            let _ = h3_connection.wait_idle().await;
        });
        let mut builder = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://{authority}"));
        if let Some(authorization) = &self.authorization {
            builder = builder.header("proxy-authorization", authorization.clone());
        }
        for (name, value) in &self.extra_headers {
            builder = builder.header(name.clone(), value.clone());
        }
        let request = builder
            .body(())
            .map_err(|e| io::Error::other(format!("naive: build request: {e}")))?;
        let request_stream =
            tokio::time::timeout(CONNECT_TIMEOUT, send_request.send_request(request))
                .await
                .map_err(|_| io::Error::other("naive: h3 request timeout"))?
                .map_err(|e| io::Error::other(format!("naive: h3 request: {e}")))?;
        Ok(Box::new(
            crate::outbound::transport::h3io::H3Stream::new(request_stream, conn_task).await?,
        ))
    }

    /// One h2 CONNECT stream: handshake, request, wrapped as raw pipes.
    async fn tunnel_h2(&self, authority: &str) -> io::Result<AnyStream> {
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
    fn build_accepts_the_quic_transport() {
        let naive = Naive::build(&obj(json!({"quic": true})), "outbounds[0]").expect("quic");
        assert!(naive.quic);
        assert!(
            !Naive::build(&obj(json!({})), "outbounds[0]")
                .expect("plain")
                .quic
        );
        assert!(
            Naive::build(
                &obj(json!({"quic": true, "quic_congestion_control": "reno"})),
                "outbounds[0]"
            )
            .is_ok()
        );
        let err = Naive::build(
            &obj(json!({"quic": true, "quic_congestion_control": "wombat"})),
            "outbounds[0]",
        )
        .map(|_| ())
        .expect_err("unknown congestion control")
        .to_string();
        assert!(err.contains("unknown quic congestion control"), "got {err}");
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
    fn authority_of_targets() {
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
    }
}
