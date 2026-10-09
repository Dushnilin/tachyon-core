//! Incremental delta patch engine (TDLT) for binary rule-sets.
//!
//! Allows downloading tiny delta patches (50–300 KB) instead of full 40–80 MB databases,
//! verifying base hash, updating in-memory or in /tmp, and atomically swapping rule pointers.

use super::compiler::RuleSetCompiler;
use super::format::*;
use super::matcher::MmapView;
use sha2::{Digest, Sha256};

pub const OP_ADD_DOMAIN: u8 = 0x01;
pub const OP_DEL_DOMAIN: u8 = 0x02;
pub const OP_ADD_SUFFIX: u8 = 0x03;
pub const OP_DEL_SUFFIX: u8 = 0x04;
pub const OP_ADD_KEYWORD: u8 = 0x05;
pub const OP_DEL_KEYWORD: u8 = 0x06;
pub const OP_ADD_CIDR: u8 = 0x07;
pub const OP_DEL_CIDR: u8 = 0x08;
pub const OP_ADD_PORT: u8 = 0x09;
pub const OP_DEL_PORT: u8 = 0x0A;

#[derive(Debug)]
pub enum DeltaError {
    InvalidMagic,
    InvalidVersion,
    PayloadTooShort,
    BaseHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    TargetHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    BaseParseFailed,
    MalformedOperation,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid delta patch magic"),
            Self::InvalidVersion => write!(f, "unsupported delta patch version"),
            Self::PayloadTooShort => write!(f, "delta patch payload truncated"),
            Self::BaseHashMismatch { .. } => write!(f, "base rule-set hash mismatch"),
            Self::TargetHashMismatch { .. } => {
                write!(f, "target rule-set hash verification failed")
            }
            Self::BaseParseFailed => write!(f, "failed to parse base rule-set"),
            Self::MalformedOperation => write!(f, "malformed delta operation"),
        }
    }
}

impl std::error::Error for DeltaError {}

pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Applies a TDLT delta patch to base TSRS binary bytes.
pub fn apply_delta(base_bytes: &[u8], patch_bytes: &[u8]) -> Result<Vec<u8>, DeltaError> {
    if patch_bytes.len() < 72 {
        return Err(DeltaError::PayloadTooShort);
    }

    if &patch_bytes[0..4] != TDLT_MAGIC {
        return Err(DeltaError::InvalidMagic);
    }

    let version = u32::from_le_bytes(patch_bytes[4..8].try_into().unwrap());
    if version != TDLT_VERSION {
        return Err(DeltaError::InvalidVersion);
    }

    let mut base_sha256 = [0u8; 32];
    base_sha256.copy_from_slice(&patch_bytes[8..40]);

    let mut target_sha256 = [0u8; 32];
    target_sha256.copy_from_slice(&patch_bytes[40..72]);

    // 1. Verify base hash
    let actual_base_hash = sha256_digest(base_bytes);
    if base_sha256 != [0u8; 32] && base_sha256 != actual_base_hash {
        return Err(DeltaError::BaseHashMismatch {
            expected: base_sha256,
            actual: actual_base_hash,
        });
    }

    // 2. Load base into compiler
    let base_view = MmapView::parse(base_bytes).ok_or(DeltaError::BaseParseFailed)?;
    let mut compiler = RuleSetCompiler::new();
    compiler.set_total_rules(base_view.header.total_rules as usize);

    // Populate existing entries from base_view
    for entry in base_view.domains {
        if let Some(s) = entry.as_str(base_view.string_table) {
            compiler.add_domain(s);
        }
    }
    for entry in base_view.suffixes {
        if let Some(s) = entry.as_str(base_view.string_table) {
            compiler.add_suffix(s);
        }
    }
    for entry in base_view.keywords {
        if let Some(s) = entry.as_str(base_view.string_table) {
            compiler.add_keyword(s);
        }
    }
    for entry in base_view.dest_v4 {
        compiler.add_cidr(&format!(
            "{}/{}",
            std::net::Ipv4Addr::from(entry.addr),
            entry.prefix_len
        ));
    }
    for entry in base_view.dest_v6 {
        compiler.add_cidr(&format!(
            "{}/{}",
            std::net::Ipv6Addr::from(entry.addr),
            entry.prefix_len
        ));
    }
    for entry in base_view.dest_ports {
        compiler.add_port_range(entry.start, entry.end);
    }

    // 3. Replay delta operations
    let mut pos = 72;
    while pos < patch_bytes.len() {
        let op = patch_bytes[pos];
        pos += 1;

        match op {
            OP_ADD_DOMAIN | OP_DEL_DOMAIN | OP_ADD_SUFFIX | OP_DEL_SUFFIX | OP_ADD_KEYWORD
            | OP_DEL_KEYWORD => {
                if pos + 2 > patch_bytes.len() {
                    return Err(DeltaError::MalformedOperation);
                }
                let len =
                    u16::from_le_bytes(patch_bytes[pos..pos + 2].try_into().unwrap()) as usize;
                pos += 2;
                if pos + len > patch_bytes.len() {
                    return Err(DeltaError::MalformedOperation);
                }
                let s = std::str::from_utf8(&patch_bytes[pos..pos + len])
                    .map_err(|_| DeltaError::MalformedOperation)?;
                pos += len;

                match op {
                    OP_ADD_DOMAIN => compiler.add_domain(s),
                    OP_DEL_DOMAIN => compiler.remove_domain(s),
                    OP_ADD_SUFFIX => compiler.add_suffix(s),
                    OP_DEL_SUFFIX => compiler.remove_suffix(s),
                    OP_ADD_KEYWORD => compiler.add_keyword(s),
                    OP_DEL_KEYWORD => compiler.remove_keyword(s),
                    _ => unreachable!(),
                }
            }
            OP_ADD_CIDR | OP_DEL_CIDR => {
                if pos + 2 > patch_bytes.len() {
                    return Err(DeltaError::MalformedOperation);
                }
                let len =
                    u16::from_le_bytes(patch_bytes[pos..pos + 2].try_into().unwrap()) as usize;
                pos += 2;
                if pos + len > patch_bytes.len() {
                    return Err(DeltaError::MalformedOperation);
                }
                let s = std::str::from_utf8(&patch_bytes[pos..pos + len])
                    .map_err(|_| DeltaError::MalformedOperation)?;
                pos += len;

                match op {
                    OP_ADD_CIDR => compiler.add_cidr(s),
                    OP_DEL_CIDR => compiler.remove_cidr(s),
                    _ => unreachable!(),
                }
            }
            OP_ADD_PORT | OP_DEL_PORT => {
                if pos + 4 > patch_bytes.len() {
                    return Err(DeltaError::MalformedOperation);
                }
                let start = u16::from_le_bytes(patch_bytes[pos..pos + 2].try_into().unwrap());
                let end = u16::from_le_bytes(patch_bytes[pos + 2..pos + 4].try_into().unwrap());
                pos += 4;

                match op {
                    OP_ADD_PORT => compiler.add_port_range(start, end),
                    OP_DEL_PORT => compiler.remove_port_range(start, end),
                    _ => unreachable!(),
                }
            }
            _ => return Err(DeltaError::MalformedOperation),
        }
    }

    // 4. Compile new TSRS image
    let new_tsrs = compiler.finish();

    // 5. Verify target hash if specified
    if target_sha256 != [0u8; 32] {
        let actual_target_hash = sha256_digest(&new_tsrs);
        if target_sha256 != actual_target_hash {
            return Err(DeltaError::TargetHashMismatch {
                expected: target_sha256,
                actual: actual_target_hash,
            });
        }
    }

    Ok(new_tsrs)
}

/// Helper to build a delta patch file between two sets of rules/strings.
pub struct DeltaBuilder {
    base_sha256: [u8; 32],
    target_sha256: [u8; 32],
    ops: Vec<u8>,
}

impl DeltaBuilder {
    pub fn new(base_sha256: [u8; 32], target_sha256: [u8; 32]) -> Self {
        Self {
            base_sha256,
            target_sha256,
            ops: Vec::new(),
        }
    }

    pub fn add_domain(&mut self, domain: &str) -> &mut Self {
        self.ops.push(OP_ADD_DOMAIN);
        let bytes = domain.as_bytes();
        self.ops
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.ops.extend_from_slice(bytes);
        self
    }

    pub fn del_domain(&mut self, domain: &str) -> &mut Self {
        self.ops.push(OP_DEL_DOMAIN);
        let bytes = domain.as_bytes();
        self.ops
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.ops.extend_from_slice(bytes);
        self
    }

    pub fn add_suffix(&mut self, suffix: &str) -> &mut Self {
        self.ops.push(OP_ADD_SUFFIX);
        let bytes = suffix.as_bytes();
        self.ops
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.ops.extend_from_slice(bytes);
        self
    }

    pub fn del_suffix(&mut self, suffix: &str) -> &mut Self {
        self.ops.push(OP_DEL_SUFFIX);
        let bytes = suffix.as_bytes();
        self.ops
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.ops.extend_from_slice(bytes);
        self
    }

    pub fn add_cidr(&mut self, cidr: &str) -> &mut Self {
        self.ops.push(OP_ADD_CIDR);
        let bytes = cidr.as_bytes();
        self.ops
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.ops.extend_from_slice(bytes);
        self
    }

    pub fn del_cidr(&mut self, cidr: &str) -> &mut Self {
        self.ops.push(OP_DEL_CIDR);
        let bytes = cidr.as_bytes();
        self.ops
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.ops.extend_from_slice(bytes);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72 + self.ops.len());
        out.extend_from_slice(TDLT_MAGIC);
        out.extend_from_slice(&TDLT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.base_sha256);
        out.extend_from_slice(&self.target_sha256);
        out.extend_from_slice(&self.ops);
        out
    }

    pub fn finish(self) -> Vec<u8> {
        self.build()
    }
}
