//! NaiveProxy server inbound: HTTP/2 CONNECT over TLS with padding and Basic auth.
//!
//! Accepts TLS connections, negotiates H2, validates Proxy-Authorization header,
//! unpacks naive padding framing (`Padded<S>`), and bridges into the router.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value;
use tokio::net::TcpListener;

use super::tls::ServerTls;
use crate::inbound::{ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::outbound::naive::Padded;
use crate::outbound::transport::h2io::{H2Io, H2Stream, server_builder};
use crate::route::Router;

pub struct Naive {
    listener: TcpListener,
    tag: String,
    router: Arc<Router>,
    allowed_auths: HashSet<String>,
    tls: Option<Arc<ServerTls>>,
}

impl Naive {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let object = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("inbound: must be an object"))?;
        let tag = object
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("naive")
            .to_string();
        let at = format!("inbound[{tag}]");

        let mut allowed_auths = HashSet::new();
        if let Some(users) = object.get("users").and_then(Value::as_array) {
            for user in users {
                let username = user.get("username").and_then(Value::as_str).unwrap_or("");
                let password = user.get("password").and_then(Value::as_str).unwrap_or("");
                let token = B64.encode(format!("{username}:{password}"));
                allowed_auths.insert(format!("Basic {token}"));
            }
        }

        let listen = parse_listen(object, &at)?;
        let listener = super::bind_tcp(std::net::SocketAddr::from(listen))
            .map_err(|e| anyhow::anyhow!("{at}: bind {}:{}: {e}", listen.0, listen.1))?;

        let tls = ServerTls::from_inbound(obj, &at)?;

        Ok(Self {
            listener,
            tag,
            router,
            allowed_auths,
            tls,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self) {
        let allowed_auths = Arc::new(self.allowed_auths);
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let tag = self.tag.clone();
                    let router = Arc::clone(&self.router);
                    let tls = self.tls.clone();
                    let allowed_auths = Arc::clone(&allowed_auths);

                    tokio::spawn(async move {
                        let local = stream.local_addr().unwrap_or(peer);
                        let result: io::Result<()> = match tls {
                            Some(tls) => match tls.accept(stream).await {
                                Ok(tls_stream) => {
                                    handle_h2(
                                        tls_stream,
                                        peer,
                                        local,
                                        &tag,
                                        &router,
                                        &allowed_auths,
                                    )
                                    .await
                                }
                                Err(e) => Err(e),
                            },
                            None => {
                                handle_h2(stream, peer, local, &tag, &router, &allowed_auths).await
                            }
                        };
                        if let Err(err) = result {
                            logging::debug(format_args!("naive {peer}: {err}"));
                        }
                    });
                }
                Err(err) => {
                    super::serve_stalled("naive accept", &err).await;
                }
            }
        }
    }
}

async fn handle_h2<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
    allowed_auths: &HashSet<String>,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = server_builder()
        .handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("naive: h2 handshake: {e}")))?;

    while let Some(result) = connection.accept().await {
        let (request, mut respond) = match result {
            Ok(v) => v,
            Err(e) => {
                logging::debug(format_args!("naive[{tag}]: accept error: {e}"));
                break;
            }
        };

        if request.method() != http::Method::CONNECT {
            let response = http::Response::builder()
                .status(http::StatusCode::METHOD_NOT_ALLOWED)
                .body(())
                .map_err(|e| io::Error::other(e.to_string()))?;
            let _ = respond.send_response(response, true);
            continue;
        }

        // Check authentication if configured
        if !allowed_auths.is_empty() {
            let auth = request
                .headers()
                .get(http::header::PROXY_AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let authed = match auth {
                Some(a) => allowed_auths.contains(a),
                None => false,
            };
            if !authed {
                let response = http::Response::builder()
                    .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(http::header::PROXY_AUTHENTICATE, "Basic realm=\"naive\"")
                    .body(())
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let _ = respond.send_response(response, true);
                continue;
            }
        }

        let target = match parse_connect_target(&request) {
            Ok(t) => t,
            Err(e) => {
                logging::debug(format_args!("naive[{tag}]: parse target: {e}"));
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(())
                    .map_err(|err| io::Error::other(err.to_string()))?;
                let _ = respond.send_response(response, true);
                continue;
            }
        };

        let padding_header_val = request
            .headers()
            .get("padding")
            .and_then(|v| v.to_str().ok());
        let has_padding_version = request
            .headers()
            .get("padding-version")
            .and_then(|v| v.to_str().ok())
            == Some("1");
        let has_padding = padding_header_val.is_some() || has_padding_version;

        let mut res_builder = http::Response::builder().status(http::StatusCode::OK);
        if padding_header_val.is_some() {
            res_builder = res_builder.header("padding", crate::outbound::naive::padding_header());
        } else if has_padding_version {
            res_builder = res_builder.header("padding-version", "1");
        }
        let response = res_builder
            .body(())
            .map_err(|e| io::Error::other(e.to_string()))?;

        let send_stream = match respond.send_response(response, false) {
            Ok(s) => s,
            Err(e) => {
                logging::debug(format_args!("naive[{tag}]: send response error: {e}"));
                continue;
            }
        };

        let recv_stream = request.into_body();
        let h2_io = H2Io {
            h2: H2Stream::server(recv_stream, send_stream),
        };

        let router = Arc::clone(router);
        let tag = tag.to_string();

        tokio::spawn(async move {
            let framed: crate::inbound::AnyStream = if has_padding {
                Box::new(Padded::new(h2_io))
            } else {
                Box::new(h2_io)
            };
            let client = ClientConn::framed(framed, local);
            let _ = drive_framed(client, peer, target, &tag, &router).await;
        });
    }

    Ok(())
}

fn parse_connect_target<B>(req: &http::Request<B>) -> io::Result<Target> {
    let auth = if let Some(authority) = req.uri().authority() {
        authority.as_str()
    } else if let Some(ca) = req
        .headers()
        .get("-connect-authority")
        .and_then(|v| v.to_str().ok())
    {
        ca
    } else if let Some(host) = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        host
    } else {
        return Err(io::Error::other("naive: missing authority in CONNECT"));
    };
    if let Ok(addr) = auth.parse::<SocketAddr>() {
        Ok(Target::Ip(addr))
    } else {
        let (host, port_str) = auth
            .rsplit_once(':')
            .ok_or_else(|| io::Error::other("naive: missing port in authority"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| io::Error::other("naive: invalid port"))?;
        let clean_host = host.trim_matches(['[', ']']);
        if let Ok(ip) = clean_host.parse::<std::net::IpAddr>() {
            Ok(Target::Ip(SocketAddr::new(ip, port)))
        } else {
            Ok(Target::Domain(clean_host.to_string(), port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("https://example.com:443")
            .body(())
            .unwrap();
        let target = parse_connect_target(&req).unwrap();
        assert_eq!(target, Target::Domain("example.com".to_string(), 443));
    }

    #[test]
    fn test_parse_connect_target_connect_authority() {
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("/")
            .header("-connect-authority", "target.site:8443")
            .body(())
            .unwrap();
        let target = parse_connect_target(&req).unwrap();
        assert_eq!(target, Target::Domain("target.site".to_string(), 8443));
    }
}
