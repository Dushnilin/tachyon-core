// The router build runs on musl/aarch64 where the system allocator is the
// one thing every packet allocation goes through.
#[cfg(all(
    target_os = "linux",
    not(target_env = "msvc"),
    not(feature = "allocstat"),
    target_arch = "x86_64"
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(target_os = "linux", not(target_env = "msvc"), feature = "allocstat"))]
#[global_allocator]
static GLOBAL: allocstat::Counting = allocstat::Counting;

#[cfg(all(target_os = "linux", not(target_env = "msvc"), feature = "allocstat"))]
mod allocstat;

#[cfg(all(target_os = "linux", not(target_env = "msvc"), target_arch = "x86_64"))]
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

fn version_line() -> String {
    format!("tachyon-core {}\n", env!("CARGO_PKG_VERSION"))
}

fn collect_dir_configs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("read directory {}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry in {}: {e}", dir.display()))?;
        let p = entry.path();
        if p.is_file() && p.extension().is_some_and(|ext| ext == "json") {
            files.push(p);
        }
    }
    files.sort();
    out.extend(files);
    Ok(())
}

fn config_path_from(args: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => return args.get(i + 1).map(PathBuf::from),
            s if s.starts_with("--config=") => {
                return Some(PathBuf::from(&s["--config=".len()..]));
            }
            s if s.starts_with("-c=") => {
                return Some(PathBuf::from(&s["-c=".len()..]));
            }
            _ => i += 1,
        }
    }
    None
}

fn load_config(args: &[String]) -> Result<String, String> {
    let mut config_files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if let Some(p) = args.get(i + 1) {
                    config_files.push(PathBuf::from(p));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            s if s.starts_with("--config=") => {
                config_files.push(PathBuf::from(&s["--config=".len()..]));
                i += 1;
            }
            s if s.starts_with("-c=") => {
                config_files.push(PathBuf::from(&s["-c=".len()..]));
                i += 1;
            }
            "-C" | "--config-directory" => {
                if let Some(p) = args.get(i + 1) {
                    collect_dir_configs(Path::new(p), &mut config_files)?;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            s if s.starts_with("--config-directory=") => {
                let p = &s["--config-directory=".len()..];
                collect_dir_configs(Path::new(p), &mut config_files)?;
                i += 1;
            }
            s if s.starts_with("-C=") => {
                let p = &s["-C=".len()..];
                collect_dir_configs(Path::new(p), &mut config_files)?;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if config_files.is_empty() {
        return Err("missing -c/--config or -C/--config-directory <path>".into());
    }

    let mut expanded = Vec::new();
    for p in config_files {
        if p.is_dir() {
            collect_dir_configs(&p, &mut expanded)?;
        } else {
            expanded.push(p);
        }
    }

    if expanded.is_empty() {
        return Err("no .json configuration files found".into());
    }

    if expanded.len() == 1 {
        let path = &expanded[0];
        return std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()));
    }

    let mut merged = serde_json::Value::Object(serde_json::Map::new());
    for p in &expanded {
        let raw = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
        let val: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", p.display()))?;
        merge_json_values(&mut merged, val);
    }
    serde_json::to_string_pretty(&merged).map_err(|e| format!("encode: {e}"))
}

fn cmd_check(args: &[String]) -> Result<(), String> {
    let raw = load_config(args).map_err(|e| format!("check: {e}"))?;
    // like the reference, `check` reports errors only — the ResolveLX
    // deprecation warnings surface at run time
    core_config::check_str(&raw).map_err(|e| format!("check: {e}"))?;
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let args_owned = args.to_vec();
    let raw = load_config(&args_owned).map_err(|e| format!("run: {e}"))?;
    #[cfg(all(target_os = "linux", not(target_env = "msvc"), feature = "allocstat"))]
    allocstat::start();
    // The reference validates the same document `check` does before it opens
    // anything, so a config `check` rejects must not reach `start()` either;
    // ResolveLX deprecations are warnings and are logged when the box starts.
    let warnings = core_config::check_str_warnings(&raw).map_err(|e| format!("run: {e}"))?;
    for warning in warnings {
        eprintln!("WARN[0000] {warning}");
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
    let result = runtime
        .block_on(
            async move { core_runtime::run_reloadable(move || load_config(&args_owned)).await },
        )
        .map_err(|e| format!("run: {e:#}"));
    // Blocking workers must not postpone process exit after
    // a failed reload; procd needs to restart the data plane promptly.
    runtime.shutdown_timeout(std::time::Duration::from_millis(250));
    result
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

#[cfg(all(target_os = "linux", not(target_env = "msvc")))]
unsafe fn raise_rlimit_nofile() {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
            eprintln!(
                "warning: getrlimit(RLIMIT_NOFILE): {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // Only the soft limit moves, and never past the inherited hard one:
        // procd hands out 1024/4096 on OpenWrt, and asking for 65535 there is
        // EINVAL, which used to leave the core at 1024.
        let target = rlim.rlim_max.min(65535);
        if rlim.rlim_cur < target {
            rlim.rlim_cur = target;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
                eprintln!(
                    "warning: setrlimit(RLIMIT_NOFILE): {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

#[cfg(all(test, target_os = "linux", not(target_env = "msvc")))]
mod nofile_tests {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    fn limit() -> libc::rlimit {
        let mut l = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) }, 0);
        l
    }

    /// The limit is per process, so every case runs in a child of the test
    /// binary that starts with the limits procd would have handed it.
    #[test]
    fn the_soft_limit_rises_to_the_inherited_hard_one() {
        const CASE: &str = "TACHYON_NOFILE_CASE";
        let ceiling = limit().rlim_max;
        // (soft, hard, expected soft); an unprivileged runner cannot raise its
        // own hard limit, so every number is capped to what it inherited
        let cases: [(libc::rlim_t, libc::rlim_t, libc::rlim_t); 4] = [
            (1024, 4096, 4096),
            (1024, 65535, 65535),
            (1024, 70000, 65535),
            (70000, 70000, 70000),
        ]
        .map(|(s, h, e)| (s.min(ceiling), h.min(ceiling), e.min(ceiling)));
        if let Ok(i) = std::env::var(CASE) {
            let (_, hard, expected) = cases[i.parse::<usize>().unwrap()];
            unsafe { super::raise_rlimit_nofile() };
            let got = limit();
            assert_eq!((got.rlim_cur, got.rlim_max), (expected, hard));
            return;
        }
        for (i, (soft, hard, _)) in cases.into_iter().enumerate() {
            let mut child = Command::new(std::env::current_exe().unwrap());
            child.args([
                "--exact",
                "nofile_tests::the_soft_limit_rises_to_the_inherited_hard_one",
                "--nocapture",
            ]);
            child.env(CASE, i.to_string());
            unsafe {
                child.pre_exec(move || {
                    let l = libc::rlimit {
                        rlim_cur: soft,
                        rlim_max: hard,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &l) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            assert!(child.status().unwrap().success(), "case {i}");
        }
    }
}

fn usage() -> String {
    "usage: tachyon-core [options] <command> [command-options]\n\
     \n\
     global options:\n\
       -c, --config <path>               configuration file path\n\
       -C, --config-directory <path>     configuration directory path\n\
       -D, --directory <dir>             working directory\n\
       --disable-color                   disable color in log output\n\
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
        #[cfg(target_arch = "x86_64")]
        {
            mi_option_set(15, 0);
            mi_option_set(43, 0);
        }
        raise_rlimit_nofile();
    }
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    // The reference accepts global options (-c, -C, -D, --disable-color) before or after the command.
    // On OpenWrt, Tachyon/Podkop calls `sing-box -c <path> check`, or `sing-box -D <dir> -c <path> run`.
    let mut working_dir: Option<PathBuf> = None;
    let mut config_from_flags: Option<PathBuf> = None;
    let mut command: Option<String> = None;
    let mut cmd_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        match arg.as_str() {
            "-D" | "--directory" if i + 1 < raw_args.len() => {
                working_dir = Some(PathBuf::from(&raw_args[i + 1]));
                i += 2;
            }
            s if s.starts_with("--directory=") => {
                working_dir = Some(PathBuf::from(&s["--directory=".len()..]));
                i += 1;
            }
            "-c" | "--config" if i + 1 < raw_args.len() => {
                let p = PathBuf::from(&raw_args[i + 1]);
                if config_from_flags.is_none() {
                    config_from_flags = Some(p);
                }
                cmd_args.push(raw_args[i].clone());
                cmd_args.push(raw_args[i + 1].clone());
                i += 2;
            }
            s if s.starts_with("--config=") => {
                let p = PathBuf::from(&s["--config=".len()..]);
                if config_from_flags.is_none() {
                    config_from_flags = Some(p);
                }
                cmd_args.push(raw_args[i].clone());
                i += 1;
            }
            s if s.starts_with("-c=") => {
                let p = PathBuf::from(&s["-c=".len()..]);
                if config_from_flags.is_none() {
                    config_from_flags = Some(p);
                }
                cmd_args.push(raw_args[i].clone());
                i += 1;
            }
            "-C" | "--config-directory" if i + 1 < raw_args.len() => {
                cmd_args.push(raw_args[i].clone());
                cmd_args.push(raw_args[i + 1].clone());
                i += 2;
            }
            s if s.starts_with("--config-directory=") || s.starts_with("-C=") => {
                cmd_args.push(raw_args[i].clone());
                i += 1;
            }
            "--disable-color" => {
                // Accepted for upstream CLI parity on OpenWrt loggers
                i += 1;
            }
            "-v" | "--version" if command.is_none() => {
                command = Some("version".to_string());
                i += 1;
            }
            "-h" | "--help" if command.is_none() => {
                command = Some("help".to_string());
                i += 1;
            }
            _ => {
                if command.is_none() && !arg.starts_with('-') {
                    command = Some(arg.clone());
                } else {
                    cmd_args.push(arg.clone());
                }
                i += 1;
            }
        }
    }

    if let Some(dir) = working_dir
        && let Err(e) = std::env::set_current_dir(&dir)
    {
        eprintln!("failed to change directory to {}: {e}", dir.display());
        return ExitCode::from(1);
    }

    let command_str = command.unwrap_or_else(|| "help".to_string());

    let result = match command_str.as_str() {
        "version" | "-v" | "--version" => {
            print!("{}", version_line());
            Ok(())
        }
        "check" => cmd_check(&cmd_args),
        "run" => cmd_run(&cmd_args),
        "api" => cmd_api(&cmd_args),
        "generate" => cmd_generate(&cmd_args),
        "format" => cmd_format(&cmd_args),
        "merge" => cmd_merge(&cmd_args),
        "rule-set" => rule_set::cmd_rule_set(&cmd_args),
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
