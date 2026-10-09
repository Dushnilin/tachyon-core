// The router build runs on musl/aarch64 where the system allocator is the
// one thing every packet allocation goes through.
#[cfg(all(
    target_os = "linux",
    not(target_env = "msvc"),
    not(feature = "allocstat")
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(target_os = "linux", not(target_env = "msvc"), feature = "allocstat"))]
#[global_allocator]
static GLOBAL: allocstat::Counting = allocstat::Counting;

#[cfg(all(target_os = "linux", not(target_env = "msvc"), feature = "allocstat"))]
mod allocstat;

#[cfg(all(target_os = "linux", not(target_env = "msvc")))]
unsafe extern "C" {
    fn mi_option_set(option: std::ffi::c_int, value: std::ffi::c_long);
}

// On soft-float targets (armv6/mips, no FPU) LLVM lowers `f64::max` to a
// libcall named `fmaximum_num`, the C23 spelling of the IEEE maxNum helper.
// musl never grew C23 float functions, so the final link dies with
// `undefined symbol: fmaximum_num` -- everywhere else the comparison is
// expanded inline and the symbol is never mentioned. LLVM expects libm to
// provide it; here libm is this function.
#[cfg(all(
    target_os = "linux",
    not(target_env = "msvc"),
    any(target_arch = "arm", target_arch = "mips", target_arch = "mips64")
))]
#[unsafe(no_mangle)]
pub extern "C" fn fmaximum_num(a: f64, b: f64) -> f64 {
    if a.is_nan() {
        b
    } else if b.is_nan() {
        a
    } else if a > b {
        a
    } else if a < b {
        b
    } else {
        a
    }
}

mod rule_set;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Compatibility contract: Tachyon parses `sing-box version X` (generator.uc).
/// When invoked through the `sing-box` name we print upstream-shaped output;
/// under our own name we print tachyon-core output.
fn bin_invoked_as_sing_box() -> bool {
    std::env::args()
        .next()
        .map(|arg0| {
            Path::new(&arg0)
                .file_stem()
                .is_some_and(|name| name == "sing-box")
        })
        .unwrap_or(false)
}

fn version_line() -> String {
    if bin_invoked_as_sing_box() {
        format!(
            "sing-box version v{}-tachyon.0\n",
            env!("CARGO_PKG_VERSION")
        )
    } else {
        format!("tachyon-core {}\n", env!("CARGO_PKG_VERSION"))
    }
}

fn config_path_from(args: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => return args.get(i + 1).map(PathBuf::from),
            s if s.starts_with("--config=") => {
                return Some(PathBuf::from(&s["--config=".len()..]));
            }
            _ => i += 1,
        }
    }
    None
}

fn cmd_check(args: &[String]) -> Result<(), String> {
    let path = config_path_from(args).ok_or("check: missing -c/--config <path>")?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("check: read {}: {e}", path.display()))?;
    // like the reference, `check` reports errors only — the ResolveLX
    // deprecation warnings surface at run time
    core_config::check_str(&raw).map_err(|e| format!("check: {}: {e}", path.display()))?;
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let path = config_path_from(args).ok_or("run: missing -c/--config <path>")?;
    #[cfg(all(target_os = "linux", not(target_env = "msvc"), feature = "allocstat"))]
    allocstat::start();
    if let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(warnings) = core_config::check_str_warnings(&raw)
    {
        // the reference logs ResolveLX deprecations when the box starts
        for warning in warnings {
            eprintln!("WARN[0000] {warning}");
        }
    }
    // Sized to the cores we are actually allowed to run on. Left to itself tokio
    // reads `sched_getaffinity` at startup, which happens to be right on a router
    // and is a lie the moment something pins the process afterwards: the worker
    // count is fixed by then, and a worker per host core on two pinned cores is
    // sixteen runtimes fighting over two CPUs.
    //
    // One worker means one core: there the multi-thread runtime keeps paying
    // for machinery nothing can use — the steal queues, the cross-worker
    // handoffs — while every task switch could have been a plain loop over the
    // ready queue, so that case takes the current-thread runtime instead.
    // TACHYON_WORKERS overrides the guess (benchmarks, cpu-restricted cgroups).
    let workers = std::env::var("TACHYON_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let runtime = if workers == 1 {
        tokio::runtime::Builder::new_current_thread()
            .event_interval(31)
            .max_blocking_threads(16)
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .event_interval(31)
            .max_blocking_threads(16 * workers.max(1))
            .enable_all()
            .build()
    }
    .map_err(|e| format!("run: {e}"))?;
    runtime
        .block_on(async { core_runtime::run(&path).await })
        .map_err(|e| format!("run: {e:#}"))
}

/// `api <method> <path> [body]` against our own Clash REST controller
/// (`--url`, `--secret`; defaults `BOX_API_URL` / `BOX_API_SECRET`). The
/// reference ships a gRPC client for its daemon service, which belongs to the
/// F7 daemon track; this is the router-friendly HTTP equivalent.
fn cmd_api(args: &[String]) -> Result<(), String> {
    let mut url = std::env::var("BOX_API_URL").unwrap_or_default();
    let mut secret = std::env::var("BOX_API_SECRET").unwrap_or_default();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                url = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--secret" => {
                secret = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            other if other.starts_with("--url=") => {
                url = other["--url=".len()..].to_string();
                i += 1;
            }
            other if other.starts_with("--secret=") => {
                secret = other["--secret=".len()..].to_string();
                i += 1;
            }
            other => {
                rest.push(other.to_string());
                i += 1;
            }
        }
    }
    let (method, path) = match rest.len() {
        0 => return Err("api: usage: api [--url URL] [--secret S] <method> <path> [body]".into()),
        1 => ("GET".to_string(), rest[0].clone()),
        _ => (rest[0].clone(), rest[1].clone()),
    };
    let body = rest.get(2).cloned().unwrap_or_default();
    if url.is_empty() {
        return Err("api: missing --url (or BOX_API_URL)".into());
    }
    let response = http_request(&url, &method, &path, &body, &secret)
        .map_err(|e| format!("api: {method} {path}: {e}"))?;
    print!("{response}");
    Ok(())
}

/// Minimal blocking HTTP/1.1 request; returns the response body.
fn http_request(
    url: &str,
    method: &str,
    path: &str,
    body: &str,
    secret: &str,
) -> std::io::Result<String> {
    use std::io::{Read, Write};
    if url.starts_with("https://") {
        return Err(std::io::Error::other(
            "https is not supported by the api client",
        ));
    }
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let mut stream = std::net::TcpStream::connect(authority)?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    if !secret.is_empty() {
        request.push_str(&format!("Authorization: Bearer {secret}\r\n"));
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map(|(h, b)| (h.to_string(), b.to_string()))
        .unwrap_or((text, String::new()));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("?");
    if status.starts_with('2') {
        return Ok(body);
    }
    Err(std::io::Error::other(format!("status {status}: {body}")))
}

fn cmd_generate(args: &[String]) -> Result<(), String> {
    use base64::Engine;
    use rand_core::RngCore;

    if args.is_empty() {
        return Err("usage: generate <reality-keypair|wg-keypair|uuid|rand>".into());
    }
    match args[0].as_str() {
        "reality-keypair" => {
            let mut priv_bytes = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut priv_bytes);
            let sk = x25519_dalek::StaticSecret::from(priv_bytes);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let priv_str = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(priv_bytes);
            let pub_str = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes());
            println!("PrivateKey: {priv_str}\nPublicKey: {pub_str}");
            Ok(())
        }
        "wg-keypair" => {
            let mut priv_bytes = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut priv_bytes);
            priv_bytes[0] &= 248;
            priv_bytes[31] &= 127;
            priv_bytes[31] |= 64;
            let sk = x25519_dalek::StaticSecret::from(priv_bytes);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let priv_str = base64::engine::general_purpose::STANDARD.encode(priv_bytes);
            let pub_str = base64::engine::general_purpose::STANDARD.encode(pk.as_bytes());
            println!("PrivateKey: {priv_str}\nPublicKey: {pub_str}");
            Ok(())
        }
        "uuid" => {
            let mut b = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut b);
            b[6] = (b[6] & 0x0f) | 0x40; // version 4
            b[8] = (b[8] & 0x3f) | 0x80; // variant 1
            println!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                b[0],
                b[1],
                b[2],
                b[3],
                b[4],
                b[5],
                b[6],
                b[7],
                b[8],
                b[9],
                b[10],
                b[11],
                b[12],
                b[13],
                b[14],
                b[15]
            );
            Ok(())
        }
        "rand" => {
            let len = args
                .get(1)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(16);
            let mut b = vec![0u8; len];
            rand_core::OsRng.fill_bytes(&mut b);
            println!("{}", base64::engine::general_purpose::STANDARD.encode(&b));
            Ok(())
        }
        other => Err(format!("generate: unknown command '{other}'")),
    }
}

fn cmd_format(args: &[String]) -> Result<(), String> {
    let path = config_path_from(args).ok_or("format: missing -c/--config <path>")?;
    let in_place = args.iter().any(|a| a == "-w" || a == "--write");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("format: read {}: {e}", path.display()))?;
    let val: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("format: parse {}: {e}", path.display()))?;
    let formatted = serde_json::to_string_pretty(&val)
        .map_err(|e| format!("format: encode {}: {e}", path.display()))?;
    if in_place {
        std::fs::write(&path, format!("{formatted}\n"))
            .map_err(|e| format!("format: write {}: {e}", path.display()))?;
    } else {
        println!("{formatted}");
    }
    Ok(())
}

fn merge_json_values(base: &mut serde_json::Value, patch: serde_json::Value) {
    use serde_json::Value;
    match (base, patch) {
        (Value::Object(b_map), Value::Object(p_map)) => {
            for (k, p_val) in p_map {
                if let Some(b_val) = b_map.get_mut(&k) {
                    merge_json_values(b_val, p_val);
                } else {
                    b_map.insert(k, p_val);
                }
            }
        }
        (Value::Array(b_arr), Value::Array(p_arr)) => {
            b_arr.extend(p_arr);
        }
        (b_val, p_val) => {
            let _ = (b_val, p_val);
        }
    }
}

fn cmd_merge(args: &[String]) -> Result<(), String> {
    let mut out_path = None;
    let mut config_paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if let Some(p) = args.get(i + 1) {
                    config_paths.push(PathBuf::from(p));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            s if s.starts_with("--config=") => {
                config_paths.push(PathBuf::from(&s["--config=".len()..]));
                i += 1;
            }
            s if s.starts_with("-c=") => {
                config_paths.push(PathBuf::from(&s["-c=".len()..]));
                i += 1;
            }
            s if s.starts_with('-') => {
                i += 1;
            }
            pos => {
                if out_path.is_none() {
                    out_path = Some(PathBuf::from(pos));
                }
                i += 1;
            }
        }
    }
    let out = out_path.ok_or("usage: merge <output-path> [flags]")?;
    if config_paths.is_empty() {
        return Err("merge: no config files specified (-c <path>)".into());
    }
    let mut merged = serde_json::Value::Object(serde_json::Map::new());
    for p in &config_paths {
        let raw =
            std::fs::read_to_string(p).map_err(|e| format!("merge: read {}: {e}", p.display()))?;
        let val: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| format!("merge: parse {}: {e}", p.display()))?;
        merge_json_values(&mut merged, val);
    }
    let formatted =
        serde_json::to_string_pretty(&merged).map_err(|e| format!("merge: encode: {e}"))?;
    std::fs::write(&out, format!("{formatted}\n"))
        .map_err(|e| format!("merge: write {}: {e}", out.display()))?;
    println!("{}\n{formatted}", out.display());
    Ok(())
}

fn usage() -> String {
    "usage: tachyon-core <command> [options]\n\
     \n\
     commands:\n\
       check     -c <path>                 validate configuration\n\
       run       -c <path>                 start the proxy\n\
       api       <method> <path> [body]    call the Clash REST controller\n\
       generate  <command>                 generate things (reality-keypair, wg-keypair, uuid, rand)\n\
       format    -c <path> [-w]            format configuration\n\
       merge     <output-path> -c <path>   merge configurations\n\
       rule-set  <command>                 manage rule-sets\n\
       version                             print version\n\
       help                                show this help\n"
        .to_string()
}

fn main() -> ExitCode {
    // mimalloc options RSS lives or dies by, set here because the defaults
    // are desktop defaults, not proxy defaults:
    //   15 purge_delay -- freed pages stay dirty for a whole second by
    //       default; after a burst that is tens of MiB of RSS nobody asked
    //       for.
    //   43 allow_thp -- mimalloc marks its arena MADV_HUGEPAGE, khugepaged
    //       merges it into 2MiB pages, and RSS then grows in 2MiB
    //       granules: AnonHugePages alone reached 33 MiB and VmHWM swung
    //       ±20 MiB from run to run. Small pages cost nothing measurable.
    // Indices are `mi_option_t` of mimalloc v3 (== v2 up to use_numa_nodes).
    // The same-named env vars are read once at the option's first access,
    // which the runtime does before main -- these two calls are what stands.
    #[cfg(all(target_os = "linux", not(target_env = "msvc")))]
    unsafe {
        mi_option_set(15, 0);
        mi_option_set(43, 0);
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // The reference accepts its global options before the command, and tachyon
    // validates configs as `sing-box -c <path> check` — without this every
    // tachyon-side restart died on `unknown command '-c'`.
    let mut leading_config: Option<String> = None;
    while args.len() >= 2 && (args[0] == "-c" || args[0] == "--config") {
        leading_config = Some(args[1].clone());
        args.drain(0..2);
    }
    let command = if args.is_empty() {
        "help".to_string()
    } else {
        args.remove(0)
    };
    if let Some(path) = leading_config
        && !args.iter().any(|arg| arg == "-c" || arg == "--config")
    {
        args.splice(0..0, ["-c".to_string(), path]);
    }

    let result = match command.as_str() {
        "version" | "-v" | "--version" => {
            print!("{}", version_line());
            Ok(())
        }
        "check" => cmd_check(&args),
        "run" => cmd_run(&args),
        "api" => cmd_api(&args),
        "generate" => cmd_generate(&args),
        "format" => cmd_format(&args),
        "merge" => cmd_merge(&args),
        "rule-set" => rule_set::cmd_rule_set(&args),
        // the process that holds an `unshare` network namespace open; it does
        // nothing until its stdin closes
        #[cfg(target_os = "linux")]
        "netns-holder" => {
            core_runtime::netns::hold();
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        "netns-holder" => Err("netns-holder is only supported on Linux".to_string()),
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{}", usage())),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_commands() {
        assert!(cmd_generate(&["reality-keypair".to_string()]).is_ok());
        assert!(cmd_generate(&["wg-keypair".to_string()]).is_ok());
        assert!(cmd_generate(&["uuid".to_string()]).is_ok());
        assert!(cmd_generate(&["rand".to_string(), "16".to_string()]).is_ok());
        assert!(cmd_generate(&["unknown".to_string()]).is_err());
    }

    #[test]
    fn test_merge_json_values() {
        use serde_json::json;

        let mut a = json!({
            "log": { "level": "warn" },
            "inbounds": [ { "type": "mixed", "tag": "in" } ]
        });
        let b = json!({
            "log": { "timestamp": true },
            "inbounds": [ { "type": "direct", "tag": "out" } ],
            "route": { "rules": [] }
        });

        merge_json_values(&mut a, b);

        assert_eq!(a["log"]["level"], "warn");
        assert_eq!(a["log"]["timestamp"], true);
        assert_eq!(a["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(a["inbounds"][0]["tag"], "in");
        assert_eq!(a["inbounds"][1]["tag"], "out");
        assert!(a.get("route").is_some());
    }

    #[test]
    fn test_format_and_merge_cli() {
        let temp_dir = std::env::temp_dir();
        let path1 = temp_dir.join(format!("tachyon_test_cfg1_{}.json", std::process::id()));
        let path2 = temp_dir.join(format!("tachyon_test_cfg2_{}.json", std::process::id()));
        let path_out = temp_dir.join(format!("tachyon_test_cfg_out_{}.json", std::process::id()));

        std::fs::write(&path1, r#"{"log":{"level":"debug"}}"#).unwrap();
        std::fs::write(&path2, r#"{"inbounds":[{"tag":"in","type":"mixed"}]}"#).unwrap();

        // format in-place
        assert!(cmd_format(&["-c".into(), path1.to_str().unwrap().into(), "-w".into()]).is_ok());
        let formatted = std::fs::read_to_string(&path1).unwrap();
        assert!(formatted.contains("\n  \"log\": {\n    \"level\": \"debug\"\n  }"));

        // merge
        assert!(
            cmd_merge(&[
                path_out.to_str().unwrap().into(),
                "-c".into(),
                path1.to_str().unwrap().into(),
                "-c".into(),
                path2.to_str().unwrap().into()
            ])
            .is_ok()
        );

        let merged: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path_out).unwrap()).unwrap();
        assert_eq!(merged["log"]["level"], "debug");
        assert_eq!(merged["inbounds"][0]["tag"], "in");

        let _ = std::fs::remove_file(path1);
        let _ = std::fs::remove_file(path2);
        let _ = std::fs::remove_file(path_out);
    }
}
