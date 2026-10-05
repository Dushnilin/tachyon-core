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
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
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

fn usage() -> String {
    "usage: tachyon-core <command> [options]\n\
     \n\
     commands:\n\
       check  -c <path>   validate configuration\n\
       run    -c <path>   start the proxy\n\
       api    <method> <path> [body]  call the Clash REST controller\n\
       version            print version\n\
       help               show this help\n"
        .to_string()
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().cloned().unwrap_or_else(|| "help".into());
    args.remove(0);

    let result = match command.as_str() {
        "version" | "-v" | "--version" => {
            print!("{}", version_line());
            Ok(())
        }
        "check" => cmd_check(&args),
        "run" => cmd_run(&args),
        "api" => cmd_api(&args),
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
