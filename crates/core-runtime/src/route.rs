use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use crate::inbound::{Conn, Target};
use crate::logging;
use crate::outbound::block::Block;
use crate::outbound::direct::Direct;
use crate::outbound::proxy::{HttpOut, Selector, Socks};
use crate::outbound::shadowsocks::stream::Shadowsocks;

pub enum Outbound {
    Direct(Direct),
    Block(Block),
    Socks(Socks),
    Http(HttpOut),
    Shadowsocks(Shadowsocks),
    Selector(Selector),
}

impl Outbound {
    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        match self {
            Outbound::Direct(direct) => direct.connect(target).await.map(Conn::Plain),
            Outbound::Block(block) => block.connect(target).await.map(Conn::Plain),
            Outbound::Socks(socks) => socks.connect(target).await.map(Conn::Plain),
            Outbound::Http(http) => http.connect(target).await.map(Conn::Plain),
            Outbound::Shadowsocks(ss) => ss
                .connect(target)
                .await
                .map(|(reader, writer)| Conn::Shadowsocks(Box::new(reader), Box::new(writer))),
            Outbound::Selector(selector) => selector.connect(router, target).await,
        }
    }

    fn build(obj: &Value, at: &str) -> anyhow::Result<Outbound> {
        let ty = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing type"))?;
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        match ty {
            "direct" => Ok(Outbound::Direct(Direct)),
            "block" => Ok(Outbound::Block(Block)),
            "socks" => Ok(Outbound::Socks(Socks::build(obj, at)?)),
            "http" => Ok(Outbound::Http(HttpOut::build(obj, at)?)),
            "shadowsocks" => Ok(Outbound::Shadowsocks(Shadowsocks::build(obj, at)?)),
            "selector" => Ok(Outbound::Selector(Selector::build(obj, at)?)),
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
        for outbound in &mut outbounds {
            if let Outbound::Selector(selector) = outbound {
                selector.resolve(&tags)?;
            }
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

    pub fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        self.connect_index(self.default, target)
    }

    /// dyn-erased so selector chains do not form an infinitely sized future.
    pub fn connect_index<'a>(
        &'a self,
        index: usize,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        Box::pin(async move {
            let Some(outbound) = self.outbounds.get(index) else {
                return Err(io::Error::other("outbound index out of range"));
            };
            outbound.connect(self, target).await
        })
    }
}
