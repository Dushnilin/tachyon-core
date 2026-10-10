use core_config::check_str;

#[test]
fn xhttp_accepts_extended_options_and_numbers() {
    for table in [Some("hex"), None] {
        let mut transport = serde_json::json!({
            "type": "xhttp",
            "mode": "packet-up",
            "session_id_length": "16-32",
            "sc_max_each_post_bytes": 32768,
            "sc_min_posts_interval_ms": 10,
            "uplink_chunk_size": 0,
            "xmux": {
                "max_concurrency": "8-32",
                "max_connections": 0
            }
        });
        if let Some(table) = table {
            transport["session_id_table"] = table.into();
        }
        let config = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "transport": transport
            }]
        });
        check_str(&config.to_string()).unwrap();
    }
    assert_eq!(core_config::xhttp_session_table("hex"), "0123456789abcdef");
    assert_eq!(core_config::xhttp_session_table("ALPHABET"), "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    assert_eq!(core_config::xhttp_session_table("number"), "0123456789");
}
