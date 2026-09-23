use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::net::TcpStream;

use crate::inbound::Target;
use crate::logging;
use crate::outbound::block::Block;
use crate::outbound::direct::Direct;

pub enum Outbound {
    Direct(Direct),
    Block(Block),
}

impl Outbound {
    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        match self {
            Outbound::Direct(direct) => direct.connect(target).await,
            Outbound::Block(block) => block.connect(target).await,
        }
    }

    fn build(obj: &Value, at: &str) -> anyhow::Result<Outbound> {
        let ty = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing type"))?;
        match ty {
            "direct" => Ok(Outbound::Direct(Direct)),
            "block" => Ok(Outbound::Block(Block)),
            other => Err(anyhow::anyhow!(
                "{at}: outbound type {other:?} not implemented yet"
            )),
        }
    }
}

pub struct Router {
    outbounds: Vec<Outbound>,
    tags: HashMap<String, usize>,
    default: usize,
}

impl Router {
    pub fn new(root: &Value) -> anyhow::Result<Arc<Router>> {
        let empty = Vec::new();
        let outbounds_list = root
            .get("outbounds")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let mut outbounds = Vec::with_capacity(outbounds_list.len());
        let mut tags = HashMap::new();
        for (i, obj) in outbounds_list.iter().enumerate() {
            let tag = obj
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !tag.is_empty() {
                if tags.contains_key(&tag) {
                    anyhow::bail!("duplicate outbound tag: {tag}");
                }
                tags.insert(tag, i);
            }
            outbounds.push(Outbound::build(obj, &format!("outbounds[{i}]"))?);
        }
        let default = match root
            .get("route")
            .and_then(|r| r.get("final"))
            .and_then(Value::as_str)
        {
            Some(final_tag) => {
                let idx = *tags.get(final_tag).ok_or_else(|| {
                    anyhow::anyhow!("route.final: unknown outbound {final_tag:?}")
                })?;
                logging::info(format_args!("routing final: {final_tag}"));
                idx
            }
            None => 0,
        };
        Ok(Arc::new(Router {
            outbounds,
            tags,
            default,
        }))
    }

    pub fn index_of(&self, tag: &str) -> Option<usize> {
        self.tags.get(tag).copied()
    }

    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        let Some(outbound) = self.outbounds.get(self.default) else {
            return Err(io::Error::other("no outbounds configured"));
        };
        outbound.connect(target).await
    }
}
