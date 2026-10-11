pub mod cache_file;
#[cfg(feature = "clash-api")]
pub mod clash_api;
pub mod clash_mode;
pub mod clash_state;
pub mod dns;
pub(crate) use core_tls::fastchacha;
pub(crate) use core_tls::fastgcm;
pub mod http_client;
pub mod inbound;
pub mod logging;
pub mod mieru;
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
#[cfg(feature = "clash-api")]
mod zip;

use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use anyhow::Context;
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::route::Router;

/// A started box instance: running inbound listeners plus their tasks.
pub struct BoxInstance {
    router: Arc<Router>,
    tasks: Vec<JoinHandle<()>>,
    quic_endpoints: Vec<(quinn::Endpoint, Weak<dyn quinn::AsyncUdpSocket>)>,
    udp_sockets: Vec<Weak<tokio::net::UdpSocket>>,
    inbounds: Vec<(String, SocketAddr)>,
    dns: Option<Arc<dns::DnsService>>,
    clash_api: Option<SocketAddr>,
    cache_file: Option<Arc<std::sync::Mutex<cache_file::CacheFile>>>,
}

/// Everything `start()` has spawned so far, aborted together if it does not
/// come up.
///
/// A `?` anywhere in `start()` used to strand whatever had already been
/// spawned: listeners still bound, sockets still held, and no `BoxInstance`
/// anywhere to shut them down. Holding them here makes a failed start leave
/// nothing behind but the error, which is what lets a reload fall back to
/// the configuration that was running.
#[derive(Default)]
struct TaskGuard(Vec<JoinHandle<()>>);

impl TaskGuard {
    fn push(&mut self, task: JoinHandle<()>) {
        self.0.push(task);
    }

    fn extend(&mut self, tasks: impl IntoIterator<Item = JoinHandle<()>>) {
        self.0.extend(tasks);
    }

    /// The box is up: its tasks belong to it now, and this guard must not
    /// touch them when it drops.
    fn keep(mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Spawn a listener and say so if it ever comes back on its own.
///
/// `serve` runs until the box shuts down. If it returns sooner, a port has
/// gone quiet while the process still reports `running` — issue #5's exact
/// symptom — and nothing else in the box would ever print a line about it.
fn serve_forever(
    kind: &str,
    tag: &str,
    serve: impl std::future::Future<Output = ()> + Send + 'static,
) -> JoinHandle<()> {
    let label = if tag.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}[{tag}]")
    };
    tokio::spawn(async move {
        serve.await;
        logging::error(format_args!("inbound {label}: listener stopped"));
    })
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

    /// Running router instance.
    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    /// Perform in-place hot reload without stopping inbounds or dropping connections.
    /// Perform in-place hot reload without stopping inbounds or dropping connections.
    pub async fn reload_in_place(&mut self, new_root: &Value) -> anyhow::Result<()> {
        warn_unhonored_options(new_root);

        // 1. Build and validate new router inner BEFORE mutating anything running
        let new_inner = Router::build_inner(new_root)?;

        // 2. Build and validate new DNS service BEFORE mutating anything running
        let new_dns = dns::DnsService::build_with_registry(new_root, new_inner.rule_sets())
            .context("dns section")?;

        // 3. Migrate active DNS cache, server addrs, reverse mappings, and fakeip pools
        if let (Some(new_svc), Some(old_svc)) = (&new_dns, &self.dns) {
            new_svc.migrate_from(old_svc);
        }

        // 4. Atomically apply the new router inner (delay history, selectors, and urltest preserved)
        self.router.apply_inner(new_inner).await?;

        // 5. Connect DNS service to the shared router and publish globally
        if let Some(service) = &new_dns {
            service.set_router(Arc::clone(&self.router));
        }
        dns::set_service(new_dns.clone());
        self.dns = new_dns;

        // 6. Start remote rule sets and endpoints for the new router
        self.router
            .rule_sets()
            .start_remote(&self.router, self.cache_file.clone())
            .await?;
        self.router.start_endpoints().await?;

        // 7. Hot-apply log settings
        let log = new_root.get("log");
        let level = log.and_then(|l| l.get("level")).and_then(Value::as_str);
        let disabled = log
            .and_then(|l| l.get("disabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if let Some(lvl) = level {
            logging::set_level(lvl);
        }
        logging::set_enabled(!disabled);

        Ok(())
    }

    /// Abort all listeners and connection tasks.
    pub fn shutdown(&self) {
        self.abort_listeners();
        let inner = self.router.inner();
        for (_, _, outbound) in inner.outbound_table() {
            if let crate::route::Outbound::Tailscale(endpoint) = outbound {
                endpoint.abort();
            }
        }
    }

    fn abort_listeners(&self) {
        for (endpoint, _) in &self.quic_endpoints {
            endpoint.close(quinn::VarInt::from_u32(0), b"configuration reload");
        }
        for task in &self.tasks {
            task.abort();
        }
    }

    /// Abort them all, then wait for each to actually stop.
    ///
    /// The waiting is the point: an aborted task that has not run its `drop`
    /// yet still holds its sockets, and the next `bind` gets `EADDRINUSE` —
    /// the reload failure reported in issue #5. The fixed 50 ms sleep this
    /// replaces was a guess at the same thing, and it was too short for a
    /// tproxy UDP socket with a session still holding it.
    pub async fn shutdown_wait(&mut self) {
        self.shutdown();
        let inner = self.router.inner();
        for (_, _, outbound) in inner.outbound_table() {
            if let crate::route::Outbound::Tailscale(endpoint) = outbound {
                endpoint.shutdown().await;
            }
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        // Aborting a reverse reader releases its reply socket when Tokio next
        // polls it. Observe the actual direct UDP socket before rebinding.
        for socket in self.udp_sockets.drain(..) {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while socket.strong_count() != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .ok();
        }
        for (endpoint, socket) in self.quic_endpoints.drain(..) {
            // QUIC connections retain the listening socket after the accept
            // task is aborted. Drain them before trying to bind that port again.
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.wait_idle()).await;
            drop(endpoint);
            // wait_idle tracks protocol state, not the driver's socket lifetime.
            // A weak reference observes the actual socket without retaining it.
            let released = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while socket.strong_count() != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await;
            if released.is_err() {
                logging::warn(format_args!("QUIC socket did not release during shutdown"));
            }
        }
    }
}

impl Drop for BoxInstance {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Build and start the data plane from a parsed configuration document.
///
/// All or nothing: anything `start_inner` leaves spawned while a later step
/// fails is aborted here, so a failed start holds no sockets and the caller
/// is free to try another configuration.
pub async fn start(root: &Value) -> anyhow::Result<BoxInstance> {
    let mut guard = TaskGuard::default();
    let instance = start_inner(root, &mut guard).await;
    match instance {
        Ok(mut instance) => {
            instance.tasks = guard.keep();
            Ok(instance)
        }
        Err(err) => Err(err),
    }
}

async fn start_inner(root: &Value, guard: &mut TaskGuard) -> anyhow::Result<BoxInstance> {
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
    let dns_service =
        dns::DnsService::build_with_registry(root, &router.rule_sets()).context("dns section")?;
    if let Some(service) = &dns_service {
        // `dns.server.detour` dials through the outbounds
        service.set_router(Arc::clone(&router));
    }
    dns::set_service(dns_service.clone());

    let mut quic_endpoints = Vec::new();
    let mut udp_sockets = Vec::new();
    guard.extend(router.take_probe_tasks());
    #[allow(unused_mut)]
    let mut clash_api = None;
    #[cfg(feature = "clash-api")]
    if let Some(clash) = clash_api::ClashApi::build(root).context("experimental.clash_api")? {
        let (addr, handle) = clash.bind_and_spawn(Arc::clone(&router)).await?;
        logging::info(format_args!("clash-api: restful api listening at {addr}"));
        guard.push(handle);
        clash_api = Some(addr);
    }
    if let Some(ntp) = ntp::NtpService::build(root)? {
        guard.push(ntp.spawn());
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
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "direct" => {
                let inbound = inbound::direct::Direct::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: direct"))?;
                let addr = inbound.local_addr()?;
                if let Some(socket) = inbound.shutdown_socket() {
                    udp_sockets.push(socket);
                }
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "redirect" => {
                let inbound = inbound::redirect::Redirect::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: redirect"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "tproxy" => {
                let inbound = inbound::tproxy::Tproxy::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tproxy"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "vless" => {
                let inbound = inbound::proxy::Vless::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: vless"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "trojan" => {
                let inbound = inbound::proxy::Trojan::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: trojan"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "vmess" => {
                let inbound = inbound::vmess::Vmess::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: vmess"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "shadowsocks" => {
                let inbound = inbound::shadowsocks::Shadowsocks::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: shadowsocks"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "tun" => {
                let inbound = inbound::tun::Tun::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tun"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "mieru" => {
                let inbound = inbound::mieru::Mieru::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: mieru"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "anytls" => {
                let inbound = inbound::anytls::AnyTls::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: anytls"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "naive" => {
                let inbound = inbound::naive::Naive::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: naive"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "shadowtls" => {
                let inbound = inbound::shadowtls::ShadowTls::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: shadowtls"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "fptn" => {
                let inbound = inbound::fptn::Fptn::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: fptn"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "hysteria2" => {
                let inbound = inbound::hysteria2::Hysteria2::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: hysteria2"))?;
                let addr = inbound.local_addr()?;
                quic_endpoints.push(inbound.shutdown_endpoint());
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            "tuic" => {
                let inbound = inbound::tuic::Tuic::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tuic"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                guard.push(serve_forever(ty, &tag, inbound.serve()));
            }
            other => anyhow::bail!("inbounds[{i}]: inbound type {other:?} not implemented yet"),
        }
    }

    Ok(BoxInstance {
        router,
        quic_endpoints,
        udp_sockets,
        tasks: Vec::new(),
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
    run_str(&raw).await
}

/// Run the box from raw JSON configuration string, and block until SIGINT/SIGTERM.
pub async fn run_str(raw: &str) -> anyhow::Result<()> {
    let root: Value = serde_json::from_str(raw).with_context(|| "decode config".to_string())?;
    let mut instance = start(&root).await?;
    wait_for_signal().await;
    logging::info(format_args!("shutting down"));
    instance.shutdown_wait().await;
    Ok(())
}

/// Run the box with reload support: on SIGHUP, invoke `load()` and restart the box in-place.
///
/// The running box is only stopped once the new configuration has passed
/// `check`, and it comes back if the new one will not start. Exiting with an
/// error when both fail is deliberate: a box with no listeners must not sit
/// there looking `running`.
pub async fn run_reloadable<F>(mut load: F) -> anyhow::Result<()>
where
    F: FnMut() -> Result<String, String> + Send + 'static,
{
    let raw = load().map_err(|e| anyhow::anyhow!("{e}"))?;
    #[allow(unused_mut)] // only the SIGHUP path writes it back
    let mut root: Value =
        serde_json::from_str(&raw).with_context(|| "decode config".to_string())?;
    let mut instance = start(&root).await?;
    #[allow(unused_mut)] // only the SIGHUP path can set it
    let mut fatal: Option<anyhow::Error> = None;

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sighup = signal(SignalKind::hangup()).expect("install SIGHUP handler");

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    logging::info(format_args!("received SIGINT, shutting down"));
                    break;
                }
                _ = sigterm.recv() => {
                    logging::info(format_args!("received SIGTERM, shutting down"));
                    break;
                }
                _ = sighup.recv() => {
                    logging::info(format_args!("received SIGHUP, reloading configuration"));
                    if let Some(err) = reload(&mut load, &mut root, &mut instance).await {
                        fatal = Some(err);
                        break;
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    logging::info(format_args!("shutting down"));
    instance.shutdown_wait().await;
    match fatal {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

pub fn can_reload_in_place(old_root: &Value, new_root: &Value) -> bool {
    if old_root.get("inbounds") != new_root.get("inbounds") {
        return false;
    }
    let old_clash = old_root
        .get("experimental")
        .and_then(|e| e.get("clash_api"));
    let new_clash = new_root
        .get("experimental")
        .and_then(|e| e.get("clash_api"));
    if old_clash != new_clash {
        return false;
    }
    #[cfg(target_os = "linux")]
    if old_root.get("network_namespaces") != new_root.get("network_namespaces") {
        return false;
    }
    if old_root.get("ntp") != new_root.get("ntp") {
        return false;
    }
    true
}

/// One SIGHUP: load, `check`, hot reload in-place if inbounds are unchanged,
/// or stop running box and start new one if listeners changed.
///
/// `Err` means the box is down and nothing is listening.
#[cfg(unix)]
async fn reload<F>(
    load: &mut F,
    root: &mut Value,
    instance: &mut BoxInstance,
) -> Option<anyhow::Error>
where
    F: FnMut() -> Result<String, String> + Send + 'static,
{
    let new_raw = match load() {
        Ok(raw) => raw,
        Err(err) => {
            logging::error(format_args!(
                "failed to load configuration on SIGHUP: {err}"
            ));
            return None;
        }
    };
    // `check` before anything is stopped: a configuration the CLI itself
    // rejects must not cost the box that is already serving.
    if let Err(err) = core_config::check_str(&new_raw) {
        logging::error(format_args!("reload rejected by check: {err}"));
        return None;
    }
    let new_root: Value = match serde_json::from_str(&new_raw) {
        Ok(value) => value,
        Err(err) => {
            logging::error(format_args!(
                "failed to parse configuration after SIGHUP: {err}"
            ));
            return None;
        }
    };

    if can_reload_in_place(root, &new_root) {
        logging::info(format_args!(
            "inbounds unchanged: applying hot reload in-place"
        ));
        if let Err(err) = instance.reload_in_place(&new_root).await {
            logging::error(format_args!(
                "in-place hot reload failed: {err:#}, keeping running configuration"
            ));
            return None;
        }
        *root = new_root;
        logging::info(format_args!(
            "configuration hot-reloaded successfully without downtime"
        ));
        return None;
    }

    logging::info(format_args!("inbounds changed, restarting box listeners"));
    // No fixed sleep here: this waits for every task to finish, so by the
    // time it returns the ports are actually free to bind again.
    instance.shutdown_wait().await;
    match start(&new_root).await {
        Ok(new_instance) => {
            *instance = new_instance;
            *root = new_root;
            logging::info(format_args!("configuration reloaded successfully"));
            None
        }
        Err(err) => {
            logging::error(format_args!(
                "failed to start box after SIGHUP reload: {err:#}"
            ));
            match start(root).await {
                Ok(previous) => {
                    *instance = previous;
                    logging::error(format_args!(
                        "rolled back to the configuration that was running; the new one was not applied"
                    ));
                    None
                }
                Err(err) => {
                    logging::error(format_args!("rollback failed: {err:#}"));
                    Some(err.context("reload left the box without listeners"))
                }
            }
        }
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut hup = signal(SignalKind::hangup()).expect("install SIGHUP handler");
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
                _ = hup.recv() => {
                    logging::info(format_args!("received SIGHUP (ignored in non-reloadable mode)"));
                }
            }
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
