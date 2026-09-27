//! Golden corpus contract:
//! every config under `../tests/golden/{lx,tachyon,ext}` must pass
//! `core_config::check_str` (schema + semantic validation), and every config
//! under `../tests/golden/invalid` must fail it. `ext/` holds tachyon-core
//! extensions (e.g. `fptn` token outbounds) that the reference sing-box
//! rejects as unknown types, so the differential harness skips that dir.

use std::fs;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
}

/// `check` resolves relative paths (certificate/key files) against the working
/// directory, exactly like the reference CLI, so the corpus is checked from the
/// workspace root.
fn use_workspace_cwd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::set_current_dir(&root).expect("set workspace cwd");
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    files
}

fn corpus_files(dir_name: &str) -> Vec<PathBuf> {
    let dir = corpus_root().join(dir_name);
    let files = json_files(&dir);
    assert!(
        !files.is_empty(),
        "corpus dir {dir_name} is empty or missing: {}",
        dir.display()
    );
    files
}

/// Corpus entries the current platform rejects by design: `routing_mark` and
/// the other dialer gates exist on Linux only (common/dialer.New).
const PLATFORM_SKIPPED: &[&str] = &["tachyon/f1-exit-gate.json"];

fn assert_accepts(dir_name: &str) {
    use_workspace_cwd();
    for file in corpus_files(dir_name) {
        let name = file
            .strip_prefix(&corpus_root())
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if !cfg!(target_os = "linux") && PLATFORM_SKIPPED.contains(&name.as_str()) {
            continue;
        }
        let raw =
            fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let result = core_config::check_str(&raw);
        if let Err(e) = result {
            panic!("check rejected valid config {}: {e}", file.display());
        }
    }
}

fn assert_rejects(dir_name: &str) {
    use_workspace_cwd();
    for file in corpus_files(dir_name) {
        let raw =
            fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        if core_config::check_str(&raw).is_ok() {
            panic!("check accepted invalid config {}", file.display());
        }
    }
}

#[test]
fn golden_lx_configs_pass_check() {
    assert_accepts("lx");
}

#[test]
fn golden_tachyon_configs_pass_check() {
    assert_accepts("tachyon");
}

#[test]
fn golden_ext_configs_pass_check() {
    assert_accepts("ext");
}

#[test]
fn golden_invalid_configs_fail_check() {
    assert_rejects("invalid");
}
