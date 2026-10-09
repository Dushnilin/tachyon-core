//! Memory-Mapped Rule-Sets (TSRS) and Incremental Delta Updates (TDLT).
//!
//! Provides zero-RAM rule matching by memory-mapping binary rule databases via `mmap(2)`
//! and applying small incremental diffs (50–300 KB) without re-downloading or re-parsing 40–80 MB files.

pub mod compiler;
pub mod delta;
pub mod format;
pub mod matcher;
pub mod mmap_io;

pub use compiler::RuleSetCompiler;
pub use delta::{DeltaBuilder, apply_delta};

use self::matcher::MmapView;
use self::mmap_io::MmapBuffer;
use crate::route::ConnContext;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmapMode {
    #[default]
    Auto,
    Mmap,
    Memory,
}

impl MmapMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "mmap" => Some(Self::Mmap),
            "memory" | "ram" => Some(Self::Memory),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    pub fn should_use_mmap(self) -> bool {
        matches!(self, Self::Mmap)
    }
}

pub struct MmapRuleSet {
    buffer: MmapBuffer,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for MmapRuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapRuleSet")
            .field("path", &self.path)
            .field("len", &self.buffer.len())
            .finish()
    }
}

impl MmapRuleSet {
    /// Open an existing .tsrs file from disk/tmpfs.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Self::open_with_mode(path, MmapMode::Auto)
    }

    /// Open an existing .tsrs file with the specified MmapMode.
    pub fn open_with_mode<P: AsRef<Path>>(path: P, mode: MmapMode) -> std::io::Result<Self> {
        let p = path.as_ref().to_path_buf();
        let buffer = if mode == MmapMode::Memory {
            let data = std::fs::read(&p)?;
            MmapBuffer::from_bytes(&data)
        } else {
            MmapBuffer::open(&p)?
        };
        if MmapView::parse(&buffer).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid TSRS binary rule-set header",
            ));
        }
        Ok(Self {
            buffer,
            path: Some(p),
        })
    }

    /// Construct directly from in-memory compiled bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let _ = MmapView::parse(bytes)?;
        let buffer = MmapBuffer::from_bytes(bytes);
        Some(Self { buffer, path: None })
    }

    /// View into the parsed tables.
    #[inline]
    pub fn view(&self) -> MmapView<'_> {
        MmapView::parse(&self.buffer).expect("already validated during creation")
    }

    #[inline]
    pub fn matches(&self, ctx: &ConnContext) -> bool {
        self.view().matches(ctx)
    }

    #[inline]
    pub fn rule_count(&self) -> usize {
        self.view().rule_count()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::compiler::RuleSetCompiler;
    use super::delta::{DeltaBuilder, apply_delta, sha256_digest};
    use super::*;
    use serde_json::json;

    #[test]
    fn test_tsrs_compile_and_mmap_match() {
        let mut compiler = RuleSetCompiler::new();
        let rules = vec![json!({
            "domain": ["example.com", "openai.com"],
            "domain_suffix": [".google.com", "cloudflare.com"],
            "domain_keyword": ["torrent"],
            "ip_cidr": ["192.168.1.0/24", "10.0.0.1/32"],
            "port": [80, 443],
            "port_range": ["8000-8080"]
        })];
        compiler.feed_rules(&rules);
        let bytes = compiler.finish();

        let set = MmapRuleSet::from_bytes(&bytes).expect("parse TSRS");
        assert_eq!(set.rule_count(), 1);

        let view = set.view();

        // 1. Exact domain
        assert!(view.matches_domain("example.com"));
        assert!(view.matches_domain("openai.com"));
        assert!(!view.matches_domain("other.com"));

        // 2. Suffix
        assert!(view.matches_domain("www.google.com"));
        assert!(view.matches_domain("mail.google.com"));
        assert!(view.matches_domain("google.com"));
        assert!(view.matches_domain("sub.cloudflare.com"));
        assert!(!view.matches_domain("notgoogle.com"));

        // 3. Keyword
        assert!(view.matches_domain("mytorrentsite.org"));
        assert!(!view.matches_domain("cleansite.org"));

        // 4. IPv4
        assert!(view.matches_ip("192.168.1.50".parse().unwrap()));
        assert!(view.matches_ip("10.0.0.1".parse().unwrap()));
        assert!(!view.matches_ip("10.0.0.2".parse().unwrap()));
        assert!(!view.matches_ip("192.168.2.1".parse().unwrap()));

        // 5. Ports
        assert!(view.matches_port(80));
        assert!(view.matches_port(443));
        assert!(view.matches_port(8000));
        assert!(view.matches_port(8050));
        assert!(view.matches_port(8080));
        assert!(!view.matches_port(8081));
    }

    #[test]
    fn test_tsrs_incremental_delta_patch() {
        let mut compiler1 = RuleSetCompiler::new();
        compiler1.add_domain("alpha.com");
        compiler1.add_suffix("beta.com");
        compiler1.add_cidr("1.1.1.0/24");
        let base_bytes = compiler1.finish();
        let base_hash = sha256_digest(&base_bytes);

        // Build target in one shot
        let mut compiler2 = RuleSetCompiler::new();
        compiler2.add_domain("gamma.com"); // added
        compiler2.add_suffix("beta.com"); // kept
        compiler2.add_cidr("1.1.1.0/24"); // kept
        compiler2.add_cidr("8.8.8.8/32"); // added
        let target_bytes = compiler2.finish();
        let target_hash = sha256_digest(&target_bytes);

        // Build delta: del alpha.com, add gamma.com, add 8.8.8.8/32
        let mut delta_builder = DeltaBuilder::new(base_hash, target_hash);
        delta_builder.del_domain("alpha.com");
        delta_builder.add_domain("gamma.com");
        delta_builder.add_cidr("8.8.8.8/32");
        let delta_bytes = delta_builder.finish();

        // Apply delta
        let patched_bytes = apply_delta(&base_bytes, &delta_bytes).expect("apply delta");
        assert_eq!(sha256_digest(&patched_bytes), target_hash);

        let patched_set = MmapRuleSet::from_bytes(&patched_bytes).expect("parse patched TSRS");
        let view = patched_set.view();

        assert!(
            !view.matches_domain("alpha.com"),
            "alpha.com should be deleted"
        );
        assert!(
            view.matches_domain("gamma.com"),
            "gamma.com should be added"
        );
        assert!(
            view.matches_domain("sub.beta.com"),
            "beta.com should be kept"
        );
        assert!(
            view.matches_ip("8.8.8.8".parse().unwrap()),
            "8.8.8.8 should be added"
        );
    }
}
