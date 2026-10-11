//! HTTPS URLTest authenticates the site in every probe entry point.
use core_tls::rustls::{self, ServerConfig, pki_types::CertificateDer};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug)]
struct BadSigningKey(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for BadSigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|s| Box::new(BadSigner(s)) as Box<dyn rustls::sign::Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct BadSigner(Box<dyn rustls::sign::Signer>);
impl rustls::sign::Signer for BadSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;
        *signature.last_mut().unwrap() ^= 1;
        Ok(signature)
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        self.0.scheme()
    }
}

async fn tls_server(
    mut pem: &[u8],
    bad_signature: bool,
    version: &'static rustls::SupportedProtocolVersion,
) -> (String, tokio::task::JoinHandle<()>) {
    core_tls::install_default_provider();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem)
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
    )
    .unwrap()
    .unwrap();
    let provider = core_crypto::provider();
    let signing_key = provider.key_provider.load_private_key(key).unwrap();
    let signing_key: Arc<dyn rustls::sign::SigningKey> = if bad_signature {
        Arc::new(BadSigningKey(signing_key))
    } else {
        signing_key
    };
    let certified = rustls::sign::CertifiedKey::new(certs, signing_key);
    let cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://127.0.0.1:{}/generate_204",
        listener.local_addr().unwrap().port()
    );
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buffer = [0; 1024];
                while !head.ends_with(b"\r\n\r\n") {
                    let Ok(n) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..n]);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                // Single-request URLs remain supported.
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
            });
        }
    });
    (url, task)
}

async fn api(addr: std::net::SocketAddr, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut byte = [0];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
    }
    let head = String::from_utf8(response).unwrap();
    let size: usize = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    let mut body = vec![0; size];
    stream.read_exact(&mut body).await.unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_slice(&body).unwrap(),
    )
}

/// All entry points must refuse a forged HTTPS site, even when the node's
/// transport could connect to it. No permissive verifier is used by the fixture.
#[tokio::test]
async fn manual_group_and_background_tests_authenticate_the_site() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for (label, cert, trust_ca) in [
            (
                "trusted",
                include_bytes!("../../../tests/golden/certs/urltest-valid.crt").as_slice(),
                true,
            ),
            (
                "unknown issuer",
                include_bytes!("../../../tests/golden/certs/urltest-valid.crt").as_slice(),
                false,
            ),
            (
                "untrusted signature",
                include_bytes!("../../../tests/golden/certs/urltest-untrusted.crt").as_slice(),
                true,
            ),
            (
                "expired",
                include_bytes!("../../../tests/golden/certs/urltest-expired.crt").as_slice(),
                true,
            ),
            (
                "wrong name",
                include_bytes!("../../../tests/golden/certs/urltest-wrong-name.crt").as_slice(),
                true,
            ),
            (
                "bad handshake signature",
                include_bytes!("../../../tests/golden/certs/urltest-valid.crt").as_slice(),
                true,
            ),
        ] {
            let (url, server) = tls_server(cert, label == "bad handshake signature", version).await;
            let mut cfg = json!({
                "log": {"level": "error"},
                "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
                "outbounds": [
                    {"type": "direct", "tag": "node"},
                    {"type": "urltest", "tag": "provider", "outbounds": ["node"], "url": url, "interval": "1h"}
                ],
                "route": {"final": "provider"}
            });
            if trust_ca {
                cfg["certificate"] = json!({"certificate_path": [concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/certs/urltest-ca.crt")]});
            }
            let instance = core_runtime::start(&cfg).await.unwrap();
            let addr = instance.clash_api_addr().unwrap();
            tokio::time::sleep(Duration::from_millis(400)).await;
            let (_, node) = api(addr, "/proxies/node").await;
            let history = node["history"].as_array().unwrap();
            assert_eq!(
                !history.is_empty(),
                label == "trusted",
                "background: {label}"
            );
            for path in ["/proxies/node/delay", "/group/provider/delay"] {
                let (status, _) = api(addr, &format!("{path}?timeout=2000&url={url}")).await;
                assert_eq!(
                    status,
                    if label == "trusted" { 200 } else { 503 },
                    "{path}: {label}"
                );
            }
            instance.shutdown();
            server.abort();
        }
    }
}
