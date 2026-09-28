pub mod clash_api;
pub mod clash_state;
pub mod dns;
pub mod http_client;
pub mod inbound;
pub mod logging;
pub mod ntp;
pub mod outbound;
pub mod route;
pub mod tls_client;

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

    let router = Router::new(root)?;
    // remote rule sets fetch before the instance is up: a failed first fetch
    // aborts the start, exactly like `RemoteRuleSet.StartContext`
    router.rule_sets().start_remote(&router).await?;
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
            "mixed" => {
                let inbound = inbound::mixed::Mixed::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: mixed"))?;
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
            other => anyhow::bail!("inbounds[{i}]: inbound type {other:?} not implemented yet"),
        }
    }

    Ok(BoxInstance {
        tasks,
        inbounds,
        dns: dns_service,
        clash_api,
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
