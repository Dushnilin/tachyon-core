//! Delay excludes TLS setup, while setup failures still obey the full budget.
use core_tls::rustls::{ServerConfig, pki_types::CertificateDer};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn tls_server(mut pem: &[u8], setup: Duration) -> (String, tokio::task::JoinHandle<()>) {
    core_tls::install_default_provider();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem)
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
    )
    .unwrap()
    .unwrap();
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
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
                tokio::time::sleep(setup).await;
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

#[tokio::test]
async fn manual_group_and_background_tests_exclude_tls_but_keep_timeout() {
    let (url, server) = tls_server(
        include_bytes!("../../../tests/golden/certs/urltest-valid.crt"),
        Duration::from_millis(350),
    )
    .await;
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "certificate": {"certificate": include_str!("../../../tests/golden/certs/urltest-ca.crt")},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
        "outbounds": [
            {"type": "direct", "tag": "node"},
            {"type": "urltest", "tag": "provider", "outbounds": ["node"], "url": url, "interval": "1h"}
        ],
        "route": {"final": "provider"}
    })).await.unwrap();
    let addr = instance.clash_api_addr().unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    let (_, node) = api(addr, "/proxies/node").await;
    let background = node["history"].as_array().unwrap().last().unwrap()["delay"]
        .as_u64()
        .unwrap();
    assert!(
        (40..250).contains(&background),
        "background included TLS: {background}"
    );
    for path in ["/proxies/node/delay", "/group/provider/delay"] {
        let start = std::time::Instant::now();
        let (status, result) = api(addr, &format!("{path}?timeout=2000&url={url}")).await;
        assert_eq!(status, 200);
        assert!(start.elapsed() >= Duration::from_millis(350));
        let ms = result["delay"].as_u64().unwrap();
        assert!(
            (40..250).contains(&ms),
            "manual included TLS or lost response delay: {ms}"
        );
    }
    let (status, _) = api(addr, &format!("/proxies/node/delay?timeout=100&url={url}")).await;
    assert_eq!(status, 504, "TLS setup must obey the original deadline");
    instance.shutdown();
    server.abort();
}
