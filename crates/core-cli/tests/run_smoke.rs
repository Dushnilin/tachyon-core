//! The built binary, started as a process.
//!
//! Everything else in this workspace calls `core_runtime::start` in-process, so
//! nothing here would notice the executable itself failing to come up: a missing
//! symbol, a panic on the first line, a config file the CLI reads differently than
//! the library does. A release is a file someone runs, and this is the only test
//! that runs the file.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

/// How long the daemon gets to bind. Generous, because a cold build of the test
/// on a loaded machine is slow -- but bounded, because a test that hangs costs
/// the whole run more than a test that fails.
const STARTUP: Duration = Duration::from_secs(30);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free port")
        .local_addr()
        .expect("its address")
        .port()
}

/// A config that does exactly one thing: listen.
fn config(port: u16) -> serde_json::Value {
    json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": port
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    })
}

fn write_config(name: &str, value: &serde_json::Value) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("tachyon-core-smoke-{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(value).expect("json")).expect("write config");
    path
}

/// The daemon, with its output discarded: this test is about the socket it opens,
/// not about what it says.
fn spawn(config: &std::path::Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("run")
        .arg("-c")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tachyon-core run")
}

/// The whole point: `run` takes the same configuration the library does, comes
/// up, and serves.
#[test]
fn run_starts_and_serves() {
    let port = free_port();
    let path = write_config("run", &config(port));
    let mut child = spawn(&path);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("address");

    let deadline = Instant::now() + STARTUP;
    let mut greeting = [0u8; 2];
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("tachyon-core run exited before it served: {status}");
        }
        if let Ok(mut stream) =
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
        {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if stream.write_all(&[0x05, 0x01, 0x00]).is_ok()
                && stream.read_exact(&mut greeting).is_ok()
            {
                break;
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("tachyon-core run did not serve socks on {addr} within {STARTUP:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        greeting,
        [0x05, 0x00],
        "socks greeting over the real binary"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&path);
}

/// `check` on the same document has to pass: the file `run` is given is read by
/// the CLI before the runtime ever sees it, and a disagreement between the two
/// is a config that validates and then refuses to start.
#[test]
fn check_accepts_what_run_takes() {
    let port = free_port();
    let path = write_config("check", &config(port));
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("check")
        .arg("-c")
        .arg(&path)
        .output()
        .expect("run check");
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "check refused a config run accepts: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A config that does not exist is an error with a message, not a silent success
/// and not a panic.
#[test]
fn run_refuses_a_config_it_cannot_read() {
    let missing = std::env::temp_dir().join("tachyon-core-smoke-absent.json");
    let _ = std::fs::remove_file(&missing);
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("run")
        .arg("-c")
        .arg(&missing)
        .stdin(Stdio::null())
        .output()
        .expect("run tachyon-core");
    assert!(
        !output.status.success(),
        "run accepted a config that is not there"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(!said.trim().is_empty(), "the refusal said nothing");
}

/// The version string is what the Tachyon package reads to decide what it has
/// installed, so its shape is part of the interface.
#[test]
fn version_is_the_shape_tachyon_parses() {
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("version")
        .output()
        .expect("run version");
    assert!(output.status.success());
    let said = String::from_utf8_lossy(&output.stdout);
    let expected = env!("CARGO_PKG_VERSION");
    assert!(
        said.contains(expected),
        "`version` said {said:?}, which does not carry {expected}"
    );
}

#[test]
fn openwrt_cli_invocations() {
    let port = free_port();
    let path = write_config("openwrt-check", &config(port));
    let temp_dir = std::env::temp_dir();

    // 1. Tachyon watchdog style: sing-box -c <path> check
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("-c")
        .arg(&path)
        .arg("check")
        .output()
        .expect("run leading -c check");
    assert!(output.status.success(), "leading -c check failed");

    // 2. OpenWrt procd style: sing-box -D <dir> -c <path> check
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("-D")
        .arg(&temp_dir)
        .arg("-c")
        .arg(&path)
        .arg("check")
        .output()
        .expect("run -D check");
    assert!(output.status.success(), "-D check failed");

    // 3. Trailing options with --disable-color
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("check")
        .arg("-c")
        .arg(&path)
        .arg("-D")
        .arg(&temp_dir)
        .arg("--disable-color")
        .output()
        .expect("check with trailing flags");
    assert!(output.status.success(), "trailing flags check failed");

    // 4. Short -v version
    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("-v")
        .output()
        .expect("run -v");
    assert!(output.status.success(), "-v failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));

    // 5. Config directory (-C / --config-directory) and multi-config merging
    let conf_dir = std::env::temp_dir().join(format!("tachyon-conf-d-{}", free_port()));
    let _ = std::fs::create_dir_all(&conf_dir);
    let part1 = conf_dir.join("00-log.json");
    let part2 = conf_dir.join("10-inbound.json");
    std::fs::write(&part1, r#"{"log": {"level": "error"}}"#).unwrap();
    std::fs::write(
        &part2,
        serde_json::to_string(&json!({
            "inbounds": [{
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": port
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("check")
        .arg("-C")
        .arg(&conf_dir)
        .output()
        .expect("check -C dir");
    assert!(
        output.status.success(),
        "check -C failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
        .arg("check")
        .arg("-c")
        .arg(&part1)
        .arg("-c")
        .arg(&part2)
        .output()
        .expect("check multiple -c");
    assert!(
        output.status.success(),
        "check multi -c failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(&conf_dir);
    let _ = std::fs::remove_file(path);
}
