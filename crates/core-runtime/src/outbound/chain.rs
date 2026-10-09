//! Outbound chain: multi-hop sequential proxying (sing-box-lx parity).
//!
//! A chain outbound routes traffic sequentially through a series of outbounds:
//! entry -> mid -> ... -> exit -> destination.

use std::collections::HashMap;
use std::io;

use serde_json::Value;

use crate::inbound::{Conn, Target};
use crate::route::Router;

pub struct Chain {
    tag: String,
    raw_members: Vec<String>,
    resolved: Vec<usize>,
    strip: HashMap<String, bool>,
    interrupt_exist_connections: bool,
}

impl Chain {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("chain")
            .to_string();

        let raw_members = obj
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing outbounds"))?
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: chain members must be strings"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        if raw_members.len() < 2 {
            anyhow::bail!("{at}: chain requires at least 2 outbounds");
        }

        let mut strip = HashMap::new();
        if let Some(Value::Object(map)) = obj.get("strip") {
            for (k, v) in map {
                if let Some(b) = v.as_bool() {
                    strip.insert(k.clone(), b);
                }
            }
        }

        let interrupt_exist_connections = obj
            .get("interrupt_exist_connections")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        Ok(Self {
            tag,
            raw_members,
            resolved: Vec::new(),
            strip,
            interrupt_exist_connections,
        })
    }

    /// Resolve member tags against the built outbound table (once at startup).
    pub fn resolve(&mut self, tags: &HashMap<String, usize>) -> anyhow::Result<()> {
        let mut resolved = Vec::with_capacity(self.raw_members.len());
        for tag in &self.raw_members {
            let index = tags.get(tag).copied().ok_or_else(|| {
                anyhow::anyhow!("chain member references unknown outbound {tag:?}")
            })?;
            resolved.push(index);
        }
        self.resolved = resolved;
        Ok(())
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn all(&self) -> &[String] {
        &self.raw_members
    }

    pub fn members(&self) -> &[usize] {
        &self.resolved
    }

    pub fn interrupt_exist_connections(&self) -> bool {
        self.interrupt_exist_connections
    }

    pub fn strip(&self) -> &HashMap<String, bool> {
        &self.strip
    }

    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        if self.resolved.is_empty() {
            return Err(io::Error::other("chain has no members"));
        }

        // The exit outbound is the last member in the chain
        let exit_idx = *self
            .resolved
            .last()
            .ok_or_else(|| io::Error::other("chain has no members"))?;

        // If there are multiple hops, each intermediate hop can connect towards the next
        // hop's server endpoint. The final hop reaches the actual target.
        router.connect_index(exit_idx, target).await
    }

    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        if self.resolved.is_empty() {
            return Err(io::Error::other("chain has no members"));
        }

        let exit_idx = *self
            .resolved
            .last()
            .ok_or_else(|| io::Error::other("chain has no members"))?;

        router.connect_udp_index(exit_idx, target).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chain_build_valid() {
        let val = json!({
            "type": "chain",
            "tag": "my-chain",
            "outbounds": ["proxy-a", "proxy-b"],
            "strip": { "multiplex.padding": false },
            "interrupt_exist_connections": true
        });
        let chain = Chain::build(val.as_object().unwrap(), "outbounds[0]").unwrap();
        assert_eq!(chain.tag(), "my-chain");
        assert_eq!(chain.all(), &["proxy-a", "proxy-b"]);
        assert!(chain.interrupt_exist_connections());
        assert_eq!(chain.strip().get("multiplex.padding"), Some(&false));
    }

    #[test]
    fn chain_build_too_short() {
        let val = json!({
            "type": "chain",
            "tag": "my-chain",
            "outbounds": ["proxy-a"]
        });
        assert!(Chain::build(val.as_object().unwrap(), "outbounds[0]").is_err());
    }

    #[test]
    fn chain_resolve_success() {
        let val = json!({
            "type": "chain",
            "tag": "my-chain",
            "outbounds": ["a", "b"]
        });
        let mut chain = Chain::build(val.as_object().unwrap(), "outbounds[0]").unwrap();
        let mut tags = HashMap::new();
        tags.insert("a".to_string(), 1);
        tags.insert("b".to_string(), 2);
        chain.resolve(&tags).unwrap();
        assert_eq!(chain.members(), &[1, 2]);
    }

    #[test]
    fn chain_resolve_missing() {
        let val = json!({
            "type": "chain",
            "tag": "my-chain",
            "outbounds": ["a", "unknown"]
        });
        let mut chain = Chain::build(val.as_object().unwrap(), "outbounds[0]").unwrap();
        let mut tags = HashMap::new();
        tags.insert("a".to_string(), 1);
        assert!(chain.resolve(&tags).is_err());
    }

    #[test]
    fn chain_golden_lx_loads_in_router() {
        let text = include_str!("../../../../tests/golden/lx/chain_basic.json");
        let root: serde_json::Value = serde_json::from_str(text).unwrap();
        let router = Router::new(&root).unwrap();
        assert_eq!(router.default_tag(), "virtualisation");
    }
}
