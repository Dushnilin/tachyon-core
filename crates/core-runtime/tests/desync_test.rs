use core_runtime::inbound::Target;
use core_runtime::outbound::desync::config::{DesyncConfig, DesyncMode, SplitPos};
use core_runtime::outbound::desync::engine::{apply_desync_tcp, apply_desync_udp};
use core_runtime::outbound::desync::packet::{find_sni, is_tls_client_hello, split_tls_record};
use core_runtime::outbound::desync::payload::{FAKE_QUIC_INITIAL, build_fake_tls_client_hello};
use core_runtime::route::Router;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[test]
fn test_desync_config_parsing_and_presets() {
    // 1. Default config
    let empty_map = serde_json::Map::new();
    let cfg = DesyncConfig::from_json(&empty_map).expect("default config");
    assert_eq!(cfg.mode, DesyncMode::FakeSplit);
    assert_eq!(cfg.split_pos, SplitPos::MidSld);
    assert_eq!(cfg.fake_ttl, 6);
    assert_eq!(cfg.fake_sni, "www.google.com");
    assert!(cfg.udp_fake);

    // 2. Preset: split
    let json_split = json!({
        "preset": "split"
    });
    let cfg_split = DesyncConfig::from_json(json_split.as_object().unwrap()).unwrap();
    assert_eq!(cfg_split.mode, DesyncMode::Split);
    assert_eq!(cfg_split.split_pos, SplitPos::MidSld);

    // 3. Preset: tlsrec
    let json_rec = json!({
        "preset": "tlsrec"
    });
    let cfg_rec = DesyncConfig::from_json(json_rec.as_object().unwrap()).unwrap();
    assert_eq!(cfg_rec.mode, DesyncMode::TlsRec);
    assert_eq!(cfg_rec.split_pos, SplitPos::Sni);

    // 4. Preset: disorder with custom split pos and fake_ttl
    let json_disorder = json!({
        "preset": "disorder",
        "split_pos": 2,
        "fake_ttl": 4
    });
    let cfg_dis = DesyncConfig::from_json(json_disorder.as_object().unwrap()).unwrap();
    assert_eq!(cfg_dis.mode, DesyncMode::Disorder);
    assert_eq!(cfg_dis.split_pos, SplitPos::Byte(2));
    assert_eq!(cfg_dis.fake_ttl, 4);

    // 5. Preset: fake_split with custom fake_sni
    let json_custom = json!({
        "preset": "fake_split",
        "fake_sni": "gosuslugi.ru",
        "fake_ttl": 8,
        "repeats": 2,
        "udp_fake": true,
        "udp_repeats": 5
    });
    let cfg_custom = DesyncConfig::from_json(json_custom.as_object().unwrap()).unwrap();
    assert_eq!(cfg_custom.fake_sni, "gosuslugi.ru");
    assert_eq!(cfg_custom.fake_ttl, 8);
    assert_eq!(cfg_custom.repeats, 2);
    assert_eq!(cfg_custom.udp_repeats, 5);
}

#[test]
fn test_tls_record_splitting_and_reassembly() {
    let client_hello = build_fake_tls_client_hello("r4---sn-ab5sznzl.googlevideo.com");
    assert!(is_tls_client_hello(&client_hello));

    let m = find_sni(&client_hello).expect("find sni");
    assert_eq!(m.host, "r4---sn-ab5sznzl.googlevideo.com");

    let split_pos = m.midsld_offset - 5; // offset relative to handshake body
    let multi = split_tls_record(&client_hello, split_pos).expect("split tls record");

    // Must have at least 2 records (10 bytes of record headers total)
    assert_eq!(multi.len(), client_hello.len() + 5);

    // Verify record 1 header
    assert_eq!(multi[0], 0x16);
    let len1 = u16::from_be_bytes([multi[3], multi[4]]) as usize;
    assert_eq!(len1, split_pos);

    // Verify record 2 header
    let rec2_start = 5 + len1;
    assert_eq!(multi[rec2_start], 0x16);
    let len2 = u16::from_be_bytes([multi[rec2_start + 3], multi[rec2_start + 4]]) as usize;
    assert_eq!(rec2_start + 5 + len2, multi.len());

    // Verify reassembled handshake payload matches original exactly
    let mut reassembled = Vec::new();
    reassembled.extend_from_slice(&multi[5..5 + len1]);
    reassembled.extend_from_slice(&multi[rec2_start + 5..]);
    assert_eq!(reassembled, &client_hello[5..]);
}

#[tokio::test]
async fn test_tcp_desync_split_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match socket.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        buf
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let client_hello = build_fake_tls_client_hello("discord.com");

    let cfg = DesyncConfig {
        mode: DesyncMode::Split,
        split_pos: SplitPos::MidSld,
        split_delay_ms: 2,
        ..Default::default()
    };

    apply_desync_tcp(&client, &client_hello, &cfg)
        .await
        .unwrap();
    drop(client); // close write to trigger EOF

    let received = server_task.await.unwrap();
    assert_eq!(received, client_hello);
}

#[tokio::test]
async fn test_tcp_desync_tlsrec_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match socket.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        buf
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let client_hello = build_fake_tls_client_hello("youtube.com");

    let cfg = DesyncConfig {
        mode: DesyncMode::TlsRec,
        split_pos: SplitPos::Sni,
        ..Default::default()
    };

    apply_desync_tcp(&client, &client_hello, &cfg)
        .await
        .unwrap();
    drop(client);

    let received = server_task.await.unwrap();
    // In TlsRec mode, the server receives 2 valid TLS records with exact same handshake content
    assert_eq!(received.len(), client_hello.len() + 5);
}

#[tokio::test]
async fn test_udp_desync_burst() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = server.local_addr().unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(srv_addr).await.unwrap();

    let cfg = DesyncConfig {
        udp_fake: true,
        udp_repeats: 2,
        udp_fake_ttl: 6,
        ..Default::default()
    };

    // Send UDP desync burst (target port 443 simulates QUIC)
    apply_desync_udp(&client, 443, &cfg).await.unwrap();

    // Client also sends real packet
    client.send(b"real-quic-payload").await.unwrap();

    // Server should receive the fake bursts and real packet
    let mut buf = [0u8; 1500];
    let n1 = server.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n1], &FAKE_QUIC_INITIAL[..]);

    let n2 = server.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], &FAKE_QUIC_INITIAL[..]);

    let n3 = server.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n3], b"real-quic-payload");
}

#[tokio::test]
async fn test_router_integration_with_desync_outbound() {
    let cfg = json!({
        "outbounds": [
            {
                "type": "desync",
                "tag": "dpi-bypass",
                "preset": "fake_split",
                "split_pos": "midsld",
                "fake_ttl": 6,
                "fake_sni": "www.google.com"
            }
        ]
    });

    let router = Router::new(&cfg).expect("build router with desync outbound");
    assert_eq!(router.default_tag(), "dpi-bypass");

    // Start a listener to test router connect
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let target = Target::Ip(addr);
    let conn = router
        .connect(&target)
        .await
        .expect("connect via desync outbound");
    assert!(matches!(conn, core_runtime::inbound::Conn::Desync(..)));
}
