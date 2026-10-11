//! Real QUIC streams through a loopback UDP relay with controlled delay/loss.
//! Run explicitly: cargo test -p core-runtime brutal_wire -- --ignored --nocapture
use super::brutal::BrutalConfig;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

async fn transfer(rtt_ms: u64, drop_every: u64) -> f64 {
    core_tls::install_default_provider();
    let certs: Vec<_> = rustls_pemfile::certs(
        &mut include_bytes!("../../../../../tests/golden/certs/localhost.crt").as_slice(),
    )
    .collect::<Result<_, _>>()
    .unwrap();
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../../../../tests/golden/certs/localhost.key").as_slice(),
    )
    .unwrap()
    .unwrap();
    let mut tls = core_tls::rustls::ServerConfig::builder_with_provider(
        core_tls::quic::configured_provider(),
    )
    .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs.clone(), key)
    .unwrap();
    tls.alpn_protocols = vec![b"brutal-test".to_vec()];
    let server_config = quinn::ServerConfig::new(
        Arc::new(core_tls::quic::QuicServerConfig::try_from(tls).unwrap()),
        Arc::new(core_tls::quic::HandshakeTokenKeyRustCrypto::new([7; 64])),
    );
    let config =
        || quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[9; 32])));
    let server = quinn::Endpoint::new(
        config(),
        Some(server_config),
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay.local_addr().unwrap();
    let relay_task = tokio::spawn(async move {
        let mut client = None;
        let mut count = 0u64;
        let mut buffer = vec![0; 65535];
        let mut deliveries = tokio::task::JoinSet::new();
        loop {
            let (len, source) = relay.recv_from(&mut buffer).await.unwrap();
            let to = if source == server_addr {
                match client {
                    Some(c) => c,
                    None => continue,
                }
            } else {
                client = Some(source);
                if buffer[0] & 0x80 == 0 {
                    count += 1;
                    if drop_every > 0 && count.is_multiple_of(drop_every) {
                        continue;
                    }
                }
                server_addr
            };
            let socket = relay.clone();
            let data = buffer[..len].to_vec();
            deliveries.spawn(async move {
                tokio::time::sleep(Duration::from_millis(rtt_ms / 2)).await;
                socket.send_to(&data, to).await.unwrap();
            });
            while deliveries.try_join_next().is_some() {}
        }
    });
    let receiver = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut stream = connection.accept_uni().await.unwrap();
        let mut bytes = 0;
        let mut buffer = [0; 16384];
        while let Some(n) = stream.read(&mut buffer).await.unwrap() {
            bytes += n;
        }
        // Keep the endpoint alive long enough to deliver final acknowledgements.
        tokio::time::sleep(Duration::from_millis(rtt_ms + 50)).await;
        (bytes, server)
    });
    let mut roots = core_tls::rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).unwrap();
    }
    let mut tls = core_tls::rustls::ClientConfig::builder_with_provider(
        core_tls::quic::configured_provider(),
    )
    .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"brutal-test".to_vec()];
    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(BrutalConfig::new(500_000)));
    transport.max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()));
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        core_tls::quic::QuicClientConfig::try_from_rustls(Arc::new(tls)).unwrap(),
    ));
    client_config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::new(
        config(),
        None,
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(relay_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let start = Instant::now();
    let mut stream = connection.open_uni().await.unwrap();
    stream.write_all(&vec![42; 1_000_000]).await.unwrap();
    stream.finish().unwrap();
    stream.stopped().await.unwrap();
    let elapsed = start.elapsed().as_secs_f64();
    let (bytes, server) = receiver.await.unwrap();
    assert_eq!(bytes, 1_000_000);
    let rate = bytes as f64 / elapsed;
    eprintln!(
        "Brutal RTT={rtt_ms}ms drop_every={drop_every}: {rate:.0} bytes/s, elapsed={elapsed:.3}s, lost={}",
        connection.stats().path.lost_packets
    );
    endpoint.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");
    relay_task.abort();
    let _ = relay_task.await;
    rate
}

#[tokio::test]
#[ignore = "controlled throughput experiment; run explicitly outside parallel CI tests"]
async fn brutal_wire_rtt_and_loss() {
    for (rtt, loss) in [(20, 0), (200, 0), (200, 10)] {
        let rate = tokio::time::timeout(Duration::from_secs(30), transfer(rtt, loss))
            .await
            .expect("transfer timed out");
        assert!(
            (300_000.0..650_000.0).contains(&rate),
            "RTT={rtt} drop_every={loss}: {rate}"
        );
    }
}
