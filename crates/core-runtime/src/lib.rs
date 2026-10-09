pub mod cache_file;
pub mod clash_api;
pub mod clash_mode;
pub mod clash_state;
pub mod dns;
pub(crate) use core_tls::fastchacha;
pub(crate) use core_tls::fastgcm;
pub mod http_client;
pub mod inbound;
pub mod logging;
#[cfg(target_os = "linux")]
pub mod netns;
pub mod ntp;
pub mod outbound;
#[cfg(unix)]
pub mod protect;
pub mod route;
pub mod tls_client;
pub mod tls_utls;
pub mod ws;
mod zip;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::route::Router;

/// A started box instance: running inbound listeners plus their tasks.
pub struct BoxInstance {
    tasks: Vec<JoinHandle<()>>,
    inbounds: Vec<(String, SocketAddr)>,
    dns: Option<Arc<dns::DnsService>>,
    clash_api: Option<SocketAddr>,
    cache_file: Option<Arc<std::sync::Mutex<cache_file::CacheFile>>>,
}

/// Dialer options `check` accepts and the runtime does not read. The reference
/// applies each of them to the outbound's own sockets; saying so once per
/// entry beats leaving a mistyped `netns` looking like it worked.
///
/// Everything else in `DIALER_OUT_FIELDS` is honoured by
/// `outbound::dial::DialOptions`, which is the single place a socket is built.
const UNHONORED_DIALER_FIELDS: &[&str] = &[
    "fallback_network_type",
    "network_strategy",
    "network_type",
    // a Linux socket option and a Linux-only dial, applied by `outbound/dial.rs`
    // there and nowhere else
    #[cfg(not(target_os = "linux"))]
    "netns",
    #[cfg(not(target_os = "linux"))]
    "tcp_multi_path",
    // `protect_path` is a unix socket protocol, and a no-op off unix
    #[cfg(not(unix))]
    "protect_path",
];

/// One warning per entry per field, so a shared option is not repeated.
fn warn_unhonored_options(root: &Value) {
    for (section, index, field) in unhonored_options(root) {
        logging::warn(format_args!(
            "{section}[{index}].{field}: accepted by check, not applied at runtime (ignored)"
        ));
    }
}

/// Which entries carry an option we accept but do not apply.
fn unhonored_options(root: &Value) -> Vec<(&'static str, usize, &'static str)> {
    let mut out = Vec::new();
    for section in ["outbounds", "endpoints", "inbounds"] {
        let empty = Vec::new();
        for (i, entry) in root
            .get(section)
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let Some(object) = entry.as_object() else {
                continue;
            };
            for field in UNHONORED_DIALER_FIELDS {
                if object.contains_key(*field) && !object[*field].is_null() {
                    out.push((section, i, *field));
                }
            }
        }
    }
    out
}

impl BoxInstance {
    /// Local addresses of all started inbounds.
    pub fn inbound_addrs(&self) -> &[(String, SocketAddr)] {
        &self.inbounds
    }

    /// The configured dns service (`None` without a `dns` section).
    pub fn dns(&self) -> Option<Arc<dns::DnsService>> {
        self.dns.clone()
    }

    /// The `experimental.cache_file` store (`None` when not configured).
    pub fn cache_file(&self) -> Option<cache_file::SharedCacheFile> {
        self.cache_file.clone()
    }

    /// Bound clash-api external controller (`None` when not configured).
    pub fn clash_api_addr(&self) -> Option<SocketAddr> {
        self.clash_api
    }

    /// Abort all listeners and connection tasks.
    pub fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

/// Build and start the data plane from a parsed configuration document.
pub async fn start(root: &Value) -> anyhow::Result<BoxInstance> {
    core_tls::install_default_provider();
    warn_unhonored_options(root);
    let log = root.get("log");
    let level = log.and_then(|l| l.get("level")).and_then(Value::as_str);
    let output = log.and_then(|l| l.get("output")).and_then(Value::as_str);
    let timestamp = log
        .and_then(|l| l.get("timestamp"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let disabled = log
        .and_then(|l| l.get("disabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !logging::init(output, level, timestamp)
        && let Some(raw) = level
    {
        anyhow::bail!("unknown log level: {raw}");
    }
    if disabled {
        logging::set_disabled();
    }

    // network_namespaces: every namespace has to be enterable before the first
    // dial asks for one, which is where the reference starts them too
    #[cfg(target_os = "linux")]
    if let Some(namespaces) = root.get("network_namespaces") {
        for line in netns::setup(&netns_from_config(namespaces)?)? {
            logging::info(format_args!("{line}"));
        }
    }

    // experimental.cache_file: the bbolt store for rule-sets, fakeip and DNS
    let cache_file: Option<cache_file::SharedCacheFile> = cache_file::CacheFile::open(
        cache_file::CacheFileOptions::from_config(root.get("experimental"))?,
    )?
    .map(|store| Arc::new(std::sync::Mutex::new(store)));
    // the clash mode is persisted like the reference persists bucketMode
    clash_mode::attach_store(cache_file.clone());
    let router = Router::new(root)?;
    // remote rule sets fetch before the instance is up: a failed first fetch
    // aborts the start, exactly like `RemoteRuleSet.StartContext`
    router
        .rule_sets()
        .start_remote(&router, cache_file.clone())
        .await?;
    router.start_endpoints().await?;
    let dns_service = dns::DnsService::build(root).context("dns section")?;
    if let Some(service) = &dns_service {
        // `dns.server.detour` dials through the outbounds
        service.set_router(Arc::clone(&router));
    }
    dns::set_service(dns_service.clone());

    let mut tasks = Vec::new();
    tasks.extend(router.take_probe_tasks());
    let mut clash_api = None;
    if let Some(clash) = clash_api::ClashApi::build(root).context("experimental.clash_api")? {
        let (addr, handle) = clash.bind_and_spawn(Arc::clone(&router)).await?;
        logging::info(format_args!("clash-api: restful api listening at {addr}"));
        tasks.push(handle);
        clash_api = Some(addr);
    }
    if let Some(ntp) = ntp::NtpService::build(root)? {
        tasks.push(ntp.spawn());
    }
    let mut inbounds = Vec::new();
    let empty = Vec::new();
    let list = root
        .get("inbounds")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for (i, obj) in list.iter().enumerate() {
        let ty = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("inbounds[{i}]: missing type"))?;
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match ty {
            "mixed" | "socks" | "http" => {
                let flavor = match ty {
                    "socks" => inbound::mixed::Flavor::Socks,
                    "http" => inbound::mixed::Flavor::Http,
                    _ => inbound::mixed::Flavor::Mixed,
                };
                let inbound = inbound::mixed::Mixed::bind_as(obj, Arc::clone(&router), flavor)
                    .await
                    .with_context(|| format!("inbounds[{i}]: {ty}"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "direct" => {
                let inbound = inbound::direct::Direct::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: direct"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "redirect" => {
                let inbound = inbound::redirect::Redirect::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: redirect"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "tproxy" => {
                let inbound = inbound::tproxy::Tproxy::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tproxy"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "vless" => {
                let inbound = inbound::proxy::Vless::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: vless"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "trojan" => {
                let inbound = inbound::proxy::Trojan::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: trojan"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "vmess" => {
                let inbound = inbound::vmess::Vmess::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: vmess"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "shadowsocks" => {
                let inbound = inbound::shadowsocks::Shadowsocks::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: shadowsocks"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "tun" => {
                let inbound = inbound::tun::Tun::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tun"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "anytls" => {
                let inbound = inbound::anytls::AnyTls::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: anytls"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "naive" => {
                let inbound = inbound::naive::Naive::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: naive"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "shadowtls" => {
                let inbound = inbound::shadowtls::ShadowTls::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: shadowtls"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "fptn" => {
                let inbound = inbound::fptn::Fptn::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: fptn"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "hysteria2" => {
                let inbound = inbound::hysteria2::Hysteria2::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: hysteria2"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "tuic" => {
                let inbound = inbound::tuic::Tuic::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tuic"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            other => anyhow::bail!("inbounds[{i}]: inbound type {other:?} not implemented yet"),
        }
    }

    Ok(BoxInstance {
        tasks,
        inbounds,
        dns: dns_service,
        clash_api,
        cache_file,
    })
}

/// Load a configuration file, run the box, and block until SIGINT/SIGTERM.
pub async fn run(config_path: &std::path::Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config {}", config_path.display()))?;
    let root: Value = serde_json::from_str(&raw).with_context(|| "decode config".to_string())?;
    let instance = start(&root).await?;
    wait_for_signal().await;
    logging::info(format_args!("shutting down"));
    instance.shutdown();
    Ok(())
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The `network_namespaces` section as the manager wants it.
#[cfg(target_os = "linux")]
fn netns_from_config(value: &Value) -> anyhow::Result<Vec<netns::Namespace>> {
    let list = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("network_namespaces: must be a list"))?;
    list.iter()
        .map(|entry| {
            let kind = match entry.get("type").and_then(Value::as_str).unwrap_or("") {
                "" | "default" => netns::Kind::Default,
                "unshare" => netns::Kind::Unshare,
                other => anyhow::bail!("network namespace: unknown type: {other}"),
            };
            Ok(netns::Namespace {
                kind,
                tag: entry
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                path: entry
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                pid_file: entry
                    .get("pid_file")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn options_we_accept_but_do_not_apply_are_named() {
        let config = json!({
            "outbounds": [
                {"type": "direct", "tag": "d", "netns": "n", "network_strategy": "prefer_ipv4",
                 "routing_mark": 99, "bind_interface": "eth0"},
                {"type": "block", "tag": "b", "reuse_addr": true, "network_strategy": null}
            ],
            "inbounds": [
                {"type": "mixed", "tag": "in", "tcp_multi_path": true}
            ]
        });
        // `domain_strategy` and `fallback_delay` are applied everywhere;
        // `netns` and `tcp_multi_path` only on Linux, and the interface group
        // is not applied at all, which is what the reference does off Android
        let expected: Vec<(&str, usize, &str)> = if cfg!(target_os = "linux") {
            vec![("outbounds", 0, "network_strategy")]
        } else {
            vec![
                ("outbounds", 0, "network_strategy"),
                ("outbounds", 0, "netns"),
                ("inbounds", 0, "tcp_multi_path"),
            ]
        };
        assert_eq!(
            unhonored_options(&config),
            expected,
            "the honored options stay quiet and a null is not an option"
        );
    }
}
