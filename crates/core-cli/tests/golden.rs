//! Golden corpus contract:
//! every config under `../tests/golden/{lx,tachyon}` is importable
//! (syntactically valid JSON, permissive schema), and every config under
//! `../tests/golden/invalid` is at least syntactically valid JSON so the
//! differential harness can exercise semantic rejection later (F1).

use std::fs;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
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

fn assert_parses(dir_name: &str) {
    let dir = corpus_root().join(dir_name);
    let files = json_files(&dir);
    assert!(
        !files.is_empty(),
        "corpus dir {dir_name} is empty or missing: {}",
        dir.display()
    );
    for file in files {
        let raw =
            fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        core_config::parse_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
    }
}

#[test]
fn golden_lx_configs_parse() {
    assert_parses("lx");
}

#[test]
fn golden_tachyon_configs_parse() {
    assert_parses("tachyon");
}

#[test]
fn golden_invalid_configs_are_json() {
    assert_parses("invalid");
}
