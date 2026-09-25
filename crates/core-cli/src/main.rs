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
    core_config::check_str(&raw).map_err(|e| format!("check: {}: {e}", path.display()))?;
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let path = config_path_from(args).ok_or("run: missing -c/--config <path>")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("run: {e}"))?;
    runtime
        .block_on(async { core_runtime::run(&path).await })
        .map_err(|e| format!("run: {e:#}"))
}

fn usage() -> String {
    "usage: tachyon-core <command> [options]\n\
     \n\
     commands:\n\
       check  -c <path>   validate configuration\n\
       run    -c <path>   start the proxy\n\
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
