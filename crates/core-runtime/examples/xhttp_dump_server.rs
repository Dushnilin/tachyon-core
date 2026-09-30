//! An h2 server that only reports what it was asked for.
//!
//! The XHTTP tests run our client against an h2 server of our own making, which
//! is exactly the arrangement where a client and a server agree with each other
//! and neither agrees with Xray. So this one is deliberately not an XHTTP server:
//! it prints every request it receives and answers 200, so the same configuration
//! can be pointed at our client and at the reference's and the two transcripts
//! compared line by line.
//!
//! It speaks TLS with the certificate the repository already carries, and nothing
//! trusts it -- point the client at it with `insecure: true`. That matters: a
//! client with no TLS speaks HTTP/1.1 (the reference's rule, from Xray's), so a
//! cleartext listener would compare our h2c against their 1.1 and every difference
//! would look like a finding.
//!
//!     cargo run -p core-runtime --example xhttp_dump_server -- <port>
//!
//! `--plain` skips the TLS, for when a cleartext comparison is what you want.

use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    core_tls::install_default_provider();
    let args: Vec<String> = env::args().collect();
    let port: u16 = args
        .get(1)
        .map(|p| p.parse().expect("a port number"))
        .unwrap_or(19700);
    let plain = args.iter().any(|a| a == "--plain");

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!(
        "xhttp-dump listening on 127.0.0.1:{port} ({})",
        if plain { "cleartext h2c" } else { "TLS h2" }
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if plain {
                serve(socket, peer).await;
                return;
            }
            let config = match server_config() {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("[{peer}] server config: {e}");
                    return;
                }
            };
            match tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
                .accept(socket)
                .await
            {
                Ok(tls) => serve(tls, peer).await,
                Err(e) => eprintln!("[{peer}] tls: {e}"),
            }
        });
    }
}

/// The repository's own fixture: self signed for `localhost`, valid until 2036.
fn server_config() -> Result<core_tls::rustls::ServerConfig, Box<dyn std::error::Error>> {
    use core_tls::rustls::pki_types::CertificateDer;
    let dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(dir.join("localhost.crt"))?,
    ))
    .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(
        dir.join("localhost.key"),
    )?))?
    .expect("the key fixture holds one key");
    let mut config = core_tls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

async fn serve<S>(socket: S, peer: std::net::SocketAddr)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut server = match h2::server::handshake(socket).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("[{peer}] not h2: {e}");
            return;
        }
    };
    eprintln!("[{peer}] ---- connection");
    while let Some(request) = server.accept().await {
        let (request, mut respond) = match request {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("[{peer}] stream error: {e}");
                break;
            }
        };
        let method = request.method().clone();
        let uri = request.uri().clone();
        println!("REQ {method} {uri}");
        for name in request.headers().keys() {
            let value = request
                .headers()
                .get(name)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
                .unwrap_or_default();
            // a long padding value is noise; its length is the interesting part
            let shown = if value.len() > 60 {
                format!("{}…({} bytes)", &value[..40], value.len())
            } else {
                value
            };
            println!("    {name}: {shown}");
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let mut body = request.into_body();
        let mut uploaded = Vec::new();
        while let Some(chunk) = body.data().await {
            let Ok(chunk) = chunk else { break };
            let _ = body.flow_control().release_capacity(chunk.len());
            uploaded.extend_from_slice(&chunk);
        }
        if !uploaded.is_empty() {
            println!("    body: {} bytes: {}", uploaded.len(), hex(&uploaded));
        }

        let response = http::Response::builder().status(200).body(()).unwrap();
        match respond.send_response(response, false) {
            Ok(mut send) => {
                let _ = send.send_data(bytes::Bytes::from_static(b"server-says-hello"), true);
            }
            Err(e) => eprintln!("[{peer}] send_response: {e}"),
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter()
        .take(48)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
