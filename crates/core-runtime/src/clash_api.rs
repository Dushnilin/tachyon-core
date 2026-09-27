//! Minimal Clash REST API (F4 slice, Yacd control plane).
//!
//! Implements the surface the FX track needs to show outbounds like
//! subscription nodes: `GET /version`, `GET /proxies`, `GET /proxies/{name}`,
//! `PUT /proxies/{name}` (selector switching) and `GET /proxies/{name}/delay`,
//! with reference-compatible auth, CORS and error bodies
//! (`experimental/clashapi` in the sing-box reference, probed against
//! `sing-box 1.14.2-lx.3`).
//!
//! Also serves the reference data views: `GET /logs` and `GET /traffic`
//! (chunked streams), `GET|DELETE /connections` (with
//! `DELETE /connections/{id}`), `GET /rules` and `GET|PATCH /configs`, plus
//! `external_ui` static files when configured.
//!
//! Known gaps (roadmap): proxy/rule providers (404 — no provider runtime),
//! `external_ui` auto-download, and cache.db persistence of the delay
//! history, fakeip and DNS cache.
//!
//! Known deviations (deliberate): HTTP keep-alive loop without `Date`
//! headers; version string reports `tachyon-core`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::clash_state;
use crate::inbound::Target;
use crate::route::{Outbound, Router, SelectError};
use crate::{logging, tls_client};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
const DEFAULT_DELAY_URL: &str = "https://www.gstatic.com/generate_204";
const DEPRECATED_MSG: &str = "create clash-server: cache_file and related fields in Clash API \
     is deprecated in sing-box 1.8.0, use experimental.cache_file instead.";

const GET_ONLY: &[&str] = &["GET"];
const GET_PUT: &[&str] = &["GET", "PUT"];
const GET_DELETE: &[&str] = &["GET", "DELETE"];
const GET_PUT_PATCH: &[&str] = &["GET", "PUT", "PATCH"];
const PREFLIGHT_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

pub struct ClashApi {
    bind: String,
    secret: Option<String>,
    allow_origins: Vec<String>,
    allow_private_network: bool,
    /// `experimental.clash_api.external_ui` directory served for unknown GETs.
    external_ui: Option<String>,
    /// `external_ui-download-url`: the reference fetches a dashboard bundle;
    /// we only report it as unimplemented.
    external_ui_download: Option<String>,
}

impl ClashApi {
    /// Parse `experimental.clash_api`; `None` without a listener address.
    pub fn build(root: &Value) -> anyhow::Result<Option<Self>> {
        let Some(clash) = root
            .get("experimental")
            .and_then(|e| e.get("clash_api"))
            .filter(|v| !v.is_null())
        else {
            return Ok(None);
        };
        let obj = clash
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("experimental.clash_api: must be a JSON object"))?;
        let truthy = |k: &str| obj.get(k) == Some(&Value::Bool(true));
        let nonempty = |k: &str| {
            obj.get(k)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        };
        if ["store_mode", "store_selected", "store_fakeip"]
            .iter()
            .any(|k| truthy(k))
            || ["cache_file", "cache_id"].iter().any(|k| nonempty(k))
        {
            anyhow::bail!("{DEPRECATED_MSG}");
        }
        let bind = obj
            .get("external_controller")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if bind.is_empty() {
            return Ok(None);
        }
        let secret = obj
            .get("secret")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let allow_origins = match obj.get("access_control_allow_origin") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        let allow_origins = if allow_origins.is_empty() {
            vec!["*".to_string()]
        } else {
            allow_origins
        };
        let allow_private_network = obj
            .get("access_control_allow_private_network")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let external_ui = obj
            .get("external_ui")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        if let Some(dir) = external_ui.as_deref()
            && !std::path::Path::new(dir).is_dir()
        {
            anyhow::bail!("external_ui: {dir} is not a directory");
        }
        let external_ui_download = obj
            .get("external_ui_download_url")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        if external_ui_download.is_some() {
            logging::warn(format_args!(
                "external_ui_download_url: fetching a dashboard bundle is not implemented yet (ignored)"
            ));
        }
        Ok(Some(Self {
            bind,
            secret,
            allow_origins,
            allow_private_network,
            external_ui,
            external_ui_download,
        }))
    }

    /// Bind the controller address and spawn the accept loop.
    pub async fn bind_and_spawn(
        self,
        router: Arc<Router>,
    ) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(normalize_bind(&self.bind))
            .await
            .with_context(|| "external controller listen error")?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(serve(listener, Arc::new(self), router));
        Ok((addr, handle))
    }

    /// `Access-Control-Allow-Origin` for this request, if any.
    fn allowed_origin(&self, origin: Option<&str>) -> Option<String> {
        let origin = origin?;
        self.allow_origins
            .iter()
            .find(|o| o.as_str() == "*" || o.as_str() == origin)
            .map(|o| {
                if o.as_str() == "*" {
                    "*".to_string()
                } else {
                    origin.to_string()
                }
            })
    }
}

/// Headers every response carries (reference cors middleware): `Vary: Origin`
/// always, `Access-Control-Allow-Origin` when the request origin is allowed.
fn cors_base(api: &ClashApi, origin: Option<&str>) -> Vec<String> {
    let mut headers = vec!["Vary: Origin".to_string()];
    if let Some(value) = api.allowed_origin(origin) {
        headers.push(format!("Access-Control-Allow-Origin: {value}"));
    }
    headers
}

/// Go `net.Listen` accepts bare `:9090`; Rust needs the wildcard host.
fn normalize_bind(addr: &str) -> String {
    if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.to_string()
    }
}

async fn serve(listener: TcpListener, api: Arc<ClashApi>, router: Arc<Router>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let api = Arc::clone(&api);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, &api, &router).await {
                        logging::debug(format_args!("clash-api: connection error: {e}"));
                    }
                });
            }
            Err(e) => {
                logging::debug(format_args!("clash-api: accept error: {e}"));
                return;
            }
        }
    }
}

/// One client connection: the reference `http.Server` keeps it alive, so
/// requests are served until EOF (responses carry `Content-Length`).
async fn handle_conn(
    mut stream: TcpStream,
    api: &ClashApi,
    router: &Router,
) -> std::io::Result<()> {
    loop {
        let Some(head) = read_head(&mut stream).await? else {
            return Ok(());
        };
        if !handle_request(&mut stream, api, router, &head).await? {
            return Ok(());
        }
    }
}

/// Result: `false` closes the connection (oversized/short body reads).
async fn handle_request(
    stream: &mut TcpStream,
    api: &ClashApi,
    router: &Router,
    head: &[u8],
) -> std::io::Result<bool> {
    let Some((request_line, headers)) = split_head(head) else {
        respond_text(
            stream,
            400,
            "Bad Request",
            "Bad Request\n",
            &[],
            "text/plain; charset=utf-8",
        )
        .await?;
        return Ok(false);
    };
    let mut parts = request_line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (percent_decode(p), parse_query(q)),
        None => (percent_decode(target), Vec::new()),
    };
    let origin = header_get(&headers, "origin").map(str::to_string);
    let cors = cors_base(api, origin.as_deref());

    // Reference: the chi `cors.Handler` middleware intercepts preflight
    // requests before authentication and routing.
    if method == "OPTIONS"
        && let Some(acrm) = header_get(&headers, "access-control-request-method")
    {
        let acrh = header_get(&headers, "access-control-request-headers");
        let acpn = header_get(&headers, "access-control-request-private-network");
        preflight(stream, api, origin.as_deref(), acrm, acrh, acpn).await?;
        return Ok(true);
    }

    let (route, methods) = classify_with_ui(&path, api.external_ui.is_some());

    // Unknown paths answer 404 outside the authenticated group (chi layout).
    if matches!(route, Route::Unknown) {
        let mut headers = cors;
        headers.push("X-Content-Type-Options: nosniff".to_string());
        respond_text(
            stream,
            404,
            "Not Found",
            "404 page not found\n",
            &headers,
            "text/plain; charset=utf-8",
        )
        .await?;
        return Ok(true);
    }

    // Direct routes (`/`, `/version`): method mismatch never reaches the
    // group middleware, so 405 comes before auth. Mounted `/proxies`
    // authenticates first (probed against the reference).
    let mounted = matches!(
        route,
        Route::Proxies
            | Route::Proxy(_)
            | Route::Delay(_)
            | Route::Logs
            | Route::Traffic
            | Route::Connections
            | Route::Connection(_)
            | Route::Rules
            | Route::Configs
            | Route::Providers
    );
    if !mounted && !methods.contains(&method) {
        method_not_allowed(stream, methods, method == "OPTIONS", &cors).await?;
        return Ok(true);
    }
    if !authorized(
        api,
        &headers,
        &query,
        header_get(&headers, "upgrade").unwrap_or(""),
    ) {
        respond_json(stream, 401, "Unauthorized", &unauthorized(), &cors).await?;
        return Ok(true);
    }
    if !methods.contains(&method) {
        method_not_allowed(stream, methods, method == "OPTIONS", &cors).await?;
        return Ok(true);
    }

    match route {
        Route::Root => {
            respond_json(stream, 200, "OK", &json!({"hello": "clash"}), &cors).await?;
        }
        Route::Version => {
            let version = format!("tachyon-core {}", env!("CARGO_PKG_VERSION"));
            respond_json(
                stream,
                200,
                "OK",
                &json!({"version": version, "premium": true, "meta": true}),
                &cors,
            )
            .await?;
        }
        Route::Proxies => {
            let body = proxies_view(router);
            respond_text(
                stream,
                200,
                "OK",
                &body.to_string(),
                &cors,
                "text/plain; charset=utf-8",
            )
            .await?;
        }
        Route::Proxy(name) => {
            return handle_proxy_route(
                stream, router, method, &name, false, &headers, &query, &cors,
            )
            .await;
        }
        Route::Delay(name) => {
            return handle_proxy_route(
                stream, router, method, &name, true, &headers, &query, &cors,
            )
            .await;
        }
        Route::Logs => {
            return stream_logs(stream, &query, &cors).await;
        }
        Route::Traffic => {
            return stream_traffic(stream, &cors).await;
        }
        Route::Connections => {
            return handle_connections(stream, method, &cors).await;
        }
        Route::Connection(id) => {
            return handle_connection(stream, method, id, &cors).await;
        }
        Route::Rules => {
            let body = rules_view(router);
            respond_json(stream, 200, "OK", &body, &cors).await?;
        }
        Route::Configs => {
            return handle_configs(stream, method, &headers, api, &cors).await;
        }
        Route::Providers => {
            // No provider runtime yet: the reference lists proxy/rule
            // providers, we report the feature instead of an empty list.
            respond_json(
                stream,
                404,
                "Not Found",
                &json!({"message": "providers are not implemented yet"}),
                &cors,
            )
            .await?;
        }
        Route::Static(asset) => {
            return serve_static(stream, api, &asset, &cors).await;
        }
        Route::Unknown => unreachable!("unknown route handled above"),
    }
    Ok(true)
}

enum Route {
    Root,
    Version,
    Proxies,
    Proxy(String),
    Delay(String),
    Logs,
    Traffic,
    Connections,
    Connection(u64),
    Rules,
    Configs,
    Providers,
    /// unknown path with `external_ui` configured: try a static file
    Static(String),
    Unknown,
}

/// URL → route class + allowed methods (reference chi router layout).
/// Unknown paths become static-asset lookups only when `external_ui` is set.
fn classify_with_ui(path: &str, external_ui: bool) -> (Route, &'static [&'static str]) {
    match path {
        "/" => (Route::Root, GET_ONLY),
        "/version" => (Route::Version, GET_ONLY),
        "/proxies" | "/proxies/" => (Route::Proxies, GET_ONLY),
        "/logs" => (Route::Logs, GET_ONLY),
        "/traffic" => (Route::Traffic, GET_ONLY),
        "/connections" => (Route::Connections, GET_DELETE),
        "/rules" => (Route::Rules, GET_ONLY),
        "/configs" => (Route::Configs, GET_PUT_PATCH),
        "/providers/proxies" | "/providers/rules" => (Route::Providers, GET_ONLY),
        p => match p.strip_prefix("/connections/") {
            Some(rest) => {
                let rest = rest.strip_suffix('/').unwrap_or(rest);
                match rest.parse::<u64>() {
                    Ok(id) => (Route::Connection(id), GET_DELETE),
                    Err(_) => (Route::Unknown, GET_DELETE),
                }
            }
            None => match p.strip_prefix("/providers/") {
                Some(_) => (Route::Providers, GET_ONLY),
                None => classify_proxies(path, external_ui),
            },
        },
    }
}

fn classify_proxies(path: &str, external_ui: bool) -> (Route, &'static [&'static str]) {
    match path.strip_prefix("/proxies/") {
        Some(rest) => {
            let rest = rest.strip_suffix('/').unwrap_or(rest);
            match rest.rsplit_once('/') {
                Some((base, "delay")) if !base.is_empty() && !base.contains('/') => {
                    (Route::Delay(base.to_string()), GET_ONLY)
                }
                Some(_) => (Route::Unknown, GET_ONLY),
                None if !rest.is_empty() => (Route::Proxy(rest.to_string()), GET_PUT),
                None => (Route::Unknown, GET_ONLY),
            }
        }
        None if external_ui && !path.contains("..") => (Route::Static(path.to_string()), GET_ONLY),
        None => (Route::Unknown, GET_ONLY),
    }
}

/// `GET /logs`: replay the ring buffer, then stream live lines. The response
/// is chunked, like the reference's flusher-based handler.
async fn stream_logs(
    stream: &mut TcpStream,
    query: &[(String, String)],
    cors: &[String],
) -> std::io::Result<bool> {
    let level_raw = query
        .iter()
        .find(|(k, _)| k == "level")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let level = if level_raw.is_empty() {
        logging::Level::Trace
    } else {
        match logging::Level::parse(level_raw) {
            Some(level) => level,
            None => {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(true);
            }
        }
    };
    let (id, mut live) = logging::subscribe();
    let mut headers = cors.to_vec();
    headers.push("Content-Type: application/json".to_string());
    send_chunked_head(stream, &headers).await?;
    for line in logging::recent(level) {
        write_chunk(stream, &log_entry(level_raw, level, &line)).await?;
    }
    while let Some((entry_level, line)) = live.recv().await {
        if entry_level >= level {
            write_chunk(stream, &log_entry(level_raw, level, &line)).await?;
        }
    }
    logging::unsubscribe(id);
    Ok(false)
}

fn log_entry(requested: &str, level: logging::Level, message: &str) -> String {
    let name = if requested.is_empty() {
        level.level_name()
    } else {
        requested
    };
    json!({"type": name, "payload": message}).to_string()
}

/// `GET /traffic`: one JSON object per second with the running totals.
async fn stream_traffic(stream: &mut TcpStream, cors: &[String]) -> std::io::Result<bool> {
    let mut headers = cors.to_vec();
    headers.push("Content-Type: application/json".to_string());
    send_chunked_head(stream, &headers).await?;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let (_, up, down) = clash_state::snapshot();
        write_chunk(stream, &json!({"up": up, "down": down}).to_string()).await?;
    }
}

/// `GET /connections` / `DELETE /connections`.
async fn handle_connections(
    stream: &mut TcpStream,
    method: &str,
    cors: &[String],
) -> std::io::Result<bool> {
    match method {
        "GET" => {
            let (views, up, down) = clash_state::snapshot();
            let connections: Vec<Value> = views.iter().map(connection_json).collect();
            let body = json!({
                "downloadTotal": down,
                "uploadTotal": up,
                "connections": connections,
                "memory": 0,
            });
            respond_json(stream, 200, "OK", &body, cors).await?;
        }
        _ => {
            let closed = clash_state::close_all();
            logging::info(format_args!("clash-api: closed {closed} connections"));
            respond_no_content(stream, cors).await?;
        }
    }
    Ok(true)
}

/// `GET|DELETE /connections/{id}`.
async fn handle_connection(
    stream: &mut TcpStream,
    method: &str,
    id: u64,
    cors: &[String],
) -> std::io::Result<bool> {
    match method {
        "GET" => {
            let (views, _, _) = clash_state::snapshot();
            match views.iter().find(|view| view.id == id.to_string()) {
                Some(view) => {
                    let body = connection_json(view);
                    respond_json(stream, 200, "OK", &body, cors).await?;
                }
                None => {
                    respond_json(stream, 404, "Not Found", &not_found(), cors).await?;
                }
            }
        }
        _ => {
            if clash_state::close(id) {
                respond_no_content(stream, cors).await?;
            } else {
                respond_json(stream, 404, "Not Found", &not_found(), cors).await?;
            }
        }
    }
    Ok(true)
}

fn connection_json(view: &clash_state::ConnView) -> Value {
    let (source_ip, source_port) = split_host_port(&view.meta.source);
    let (dest_ip, dest_port) = split_host_port(&view.meta.destination);
    json!({
        "id": view.id,
        "metadata": {
            "network": view.meta.network,
            "type": "Clash",
            "sourceIP": source_ip,
            "sourcePort": source_port,
            "host": view.meta.host,
            "destinationIP": dest_ip,
            "destinationPort": dest_port,
            "chains": view.meta.chains,
        },
        "upload": view.upload,
        "download": view.download,
        "start": rfc3339_utc(view.start.elapsed()),
        "rule": view.meta.rule,
        "rulePayload": view.meta.rule_payload,
    })
}

fn split_host_port(value: &str) -> (String, String) {
    match value.rsplit_once(':') {
        Some((host, port)) => (host.trim_matches(['[', ']']).to_string(), port.to_string()),
        None => (value.to_string(), String::new()),
    }
}

/// Clash `start` field: RFC3339 UTC, derived from the elapsed age.
fn rfc3339_utc(elapsed: Duration) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day, hour, minute, second) = civil_from_epoch(now - elapsed.as_secs());
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's civil_from_days plus the time of day.
fn civil_from_epoch(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m as u32,
        d as u32,
        (rem / 3_600) as u32,
        ((rem % 3_600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// `GET /rules`: reference shape — `{type, payload, proxy}` per rule, where
/// payload is the sing-box item description (`rule.String()`).
fn rules_view(router: &Router) -> Value {
    let rules: Vec<Value> = router
        .clash_rules()
        .into_iter()
        .map(|(kind, payload, proxy)| json!({"type": kind, "payload": payload, "proxy": proxy}))
        .collect();
    json!({ "rules": rules })
}

/// `GET /configs` and `PATCH /configs {"log-level": "debug"}`.
async fn handle_configs(
    stream: &mut TcpStream,
    method: &str,
    headers: &[(String, String)],
    api: &ClashApi,
    cors: &[String],
) -> std::io::Result<bool> {
    match method {
        "GET" => {
            let body = json!({
                "port": 0,
                "socks-port": 0,
                "redir-port": 0,
                "tproxy-port": 0,
                "mixed-port": 0,
                "mode": "rule",
                "log-level": logging::level().map(logging::Level::level_name),
                "ipv6": false,
                "allow-lan": false,
                "external-controller": api.bind,
                "external-ui": api.external_ui,
                "external-ui-download-url": api.external_ui_download,
            });
            respond_json(stream, 200, "OK", &body, cors).await?;
        }
        "PATCH" => {
            let len: usize = header_get(headers, "content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if len > MAX_BODY {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(false);
            }
            let mut body = vec![0u8; len];
            if len > 0 && stream.read_exact(&mut body).await.is_err() {
                return Ok(false);
            }
            let Ok(value) = serde_json::from_slice::<Value>(&body) else {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(true);
            };
            let requested = value
                .get("log-level")
                .and_then(Value::as_str)
                .map(str::to_string);
            match requested {
                Some(level) if !logging::set_level(&level) => {
                    respond_json(
                        stream,
                        400,
                        "Bad Request",
                        &json!({"message": "invalid log level"}),
                        cors,
                    )
                    .await?;
                }
                Some(level) => {
                    logging::info(format_args!("clash-api: log level set to {level}"));
                    respond_no_content(stream, cors).await?;
                }
                None => {
                    respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                }
            }
        }
        _ => {
            // PUT would reload the whole configuration; unsupported.
            respond_json(
                stream,
                501,
                "Not Implemented",
                &json!({"message": "config reload is not implemented yet"}),
                cors,
            )
            .await?;
        }
    }
    Ok(true)
}

/// `external_ui` static files; unknown paths fall back to `index.html`.
async fn serve_static(
    stream: &mut TcpStream,
    api: &ClashApi,
    asset: &str,
    cors: &[String],
) -> std::io::Result<bool> {
    let Some(dir) = api.external_ui.as_deref() else {
        respond_text(
            stream,
            404,
            "Not Found",
            "404 page not found\n",
            cors,
            "text/plain; charset=utf-8",
        )
        .await?;
        return Ok(true);
    };
    let relative = asset.trim_start_matches('/');
    let relative = if relative.is_empty() {
        "index.html"
    } else {
        relative
    };
    let mut path = std::path::PathBuf::from(dir);
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        path.push(part);
    }
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(_) => match std::fs::read(std::path::PathBuf::from(dir).join("index.html")) {
            Ok(body) => body,
            Err(_) => {
                respond_text(
                    stream,
                    404,
                    "Not Found",
                    "404 page not found\n",
                    cors,
                    "text/plain; charset=utf-8",
                )
                .await?;
                return Ok(true);
            }
        },
    };
    let mime = mime_for(&path);
    let mut headers = cors.to_vec();
    headers.push(format!("Content-Type: {mime}"));
    send(stream, 200, "OK", None, &headers, &body, false).await?;
    Ok(true)
}

fn mime_for(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

/// Chunked response head (Go's flusher-based handlers).
async fn send_chunked_head(stream: &mut TcpStream, headers: &[String]) -> std::io::Result<()> {
    let mut head = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n");
    for header in headers {
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await
}

async fn write_chunk(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    stream
        .write_all(format!("{:x}\r\n{body}\r\n", body.len()).as_bytes())
        .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_proxy_route(
    stream: &mut TcpStream,
    router: &Router,
    method: &str,
    name: &str,
    delay: bool,
    headers: &[(String, String)],
    query: &[(String, String)],
    cors: &[String],
) -> std::io::Result<bool> {
    let Some(index) = router.index_of(name) else {
        respond_json(stream, 404, "Not Found", &not_found(), cors).await?;
        return Ok(true);
    };
    let query_get = |field: &str| -> String {
        query
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    match (method, delay) {
        ("GET", false) => {
            // Reference writes the proxy info via `w.Write` — Go sniffs the
            // JSON body as `text/plain`.
            let info = proxy_info(router, index, name);
            respond_text(
                stream,
                200,
                "OK",
                &info.to_string(),
                cors,
                "text/plain; charset=utf-8",
            )
            .await?;
            Ok(true)
        }
        ("PUT", false) => {
            let len: usize = header_get(headers, "content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if len > MAX_BODY {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(false);
            }
            let mut body = vec![0u8; len];
            if len > 0 && stream.read_exact(&mut body).await.is_err() {
                return Ok(false);
            }
            let Ok(value) = serde_json::from_slice::<Value>(&body) else {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(true);
            };
            let Some(obj) = value.as_object() else {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(true);
            };
            let member = match obj.get("name") {
                Some(Value::String(s)) => s.clone(),
                Some(_) => {
                    respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                    return Ok(true);
                }
                None => String::new(),
            };
            match router.select_member(name, &member) {
                Ok(_) => {
                    // 204: no Content-Type and no Content-Length (Go behaviour).
                    respond_no_content(stream, cors).await?;
                }
                Err(SelectError::NotSelector) => {
                    respond_json(
                        stream,
                        400,
                        "Bad Request",
                        &json!({"message": "Must be a Selector"}),
                        cors,
                    )
                    .await?;
                }
                Err(_) => {
                    respond_json(
                        stream,
                        400,
                        "Bad Request",
                        &json!({"message": "Selector update error: not found"}),
                        cors,
                    )
                    .await?;
                }
            }
            Ok(true)
        }
        ("GET", true) => {
            let timeout_text = query_get("timeout");
            let Ok(timeout) = timeout_text.parse::<i16>() else {
                respond_json(stream, 400, "Bad Request", &bad_request(), cors).await?;
                return Ok(true);
            };
            let mut url = query_get("url");
            // Reference quirk: plain-http links fall back to the default probe.
            if url.starts_with("http://") {
                url.clear();
            }
            if url.is_empty() {
                url = DEFAULT_DELAY_URL.to_string();
            }
            delay_test(stream, router, index, &url, timeout, cors).await?;
            Ok(true)
        }
        _ => {
            method_not_allowed(stream, GET_ONLY, method == "OPTIONS", cors).await?;
            Ok(true)
        }
    }
}

/// `GET /proxies` — GLOBAL plus one entry per outbound (reference layout).
fn proxies_view(router: &Router) -> Value {
    let entries: Vec<(usize, String, &Outbound)> = router
        .outbound_table()
        .map(|(i, tag, outbound)| (i, tag.to_string(), outbound))
        .collect();
    let mut all: Vec<String> = entries
        .iter()
        .filter(|(_, _, outbound)| !matches!(outbound, Outbound::Direct(_) | Outbound::Block(_)))
        .map(|(_, tag, _)| tag.clone())
        .collect();
    let default_tag = router.default_tag();
    // Stable sort puts the default outbound first (reference behaviour).
    all.sort_by_key(|tag| tag != default_tag);

    let mut proxies = serde_json::Map::new();
    proxies.insert(
        "GLOBAL".to_string(),
        json!({
            "type": "Fallback",
            "name": "GLOBAL",
            "udp": true,
            "history": [],
            "all": all,
            "now": default_tag,
        }),
    );
    for (i, tag, outbound) in entries {
        let key = if tag.is_empty() {
            i.to_string()
        } else {
            tag.clone()
        };
        proxies.insert(key, proxy_info_outbound(outbound, &tag));
    }
    json!({"proxies": Value::Object(proxies)})
}

fn proxy_info(router: &Router, index: usize, tag: &str) -> Value {
    match router.outbound_table().find(|(i, ..)| *i == index) {
        Some((_, _, outbound)) => proxy_info_outbound(outbound, tag),
        None => json!({}),
    }
}

fn proxy_info_outbound(outbound: &Outbound, tag: &str) -> Value {
    let mut info = serde_json::Map::new();
    info.insert("type".into(), json!(clash_type_name(outbound)));
    info.insert("name".into(), json!(tag));
    info.insert("udp".into(), json!(udp_capable(outbound)));
    info.insert("history".into(), json!([]));
    match outbound {
        Outbound::Selector(selector) => {
            info.insert("now".into(), json!(selector.now()));
            info.insert("all".into(), json!(selector.all()));
        }
        Outbound::Urltest(urltest) => {
            info.insert("now".into(), json!(urltest.now()));
            info.insert("all".into(), json!(urltest.all()));
        }
        _ => {}
    }
    Value::Object(info)
}

/// Clash display names (`constant.ProxyDisplayName`), plus our own types.
fn clash_type_name(outbound: &Outbound) -> &'static str {
    match outbound {
        Outbound::Direct(_) => "Direct",
        // Reference maps TypeBlock to its clash display name "Reject".
        Outbound::Block(_) => "Reject",
        Outbound::Socks(_) => "SOCKS",
        Outbound::Http(_) => "HTTP",
        Outbound::Shadowsocks(_) => "Shadowsocks",
        Outbound::Vless(_) => "VLESS",
        Outbound::Trojan(_) => "Trojan",
        Outbound::Vmess(_) => "VMess",
        Outbound::Hysteria2(_) => "Hysteria2",
        Outbound::Fptn(_) => "FPTN",
        Outbound::Masque(_) => "MASQUE",
        Outbound::Snell(_) => "Snell",
        Outbound::Tuic(_) => "TUIC",
        Outbound::WireGuard(_) => "WireGuard",
        Outbound::OpenVpn(_) => "OpenVPN",
        Outbound::Naive(_) => "NaiveProxy",
        Outbound::AnyTls(_) => "AnyTLS",
        Outbound::Urltest(_) => "URLTest",
        Outbound::Selector(_) => "Selector",
    }
}

fn udp_capable(outbound: &Outbound) -> bool {
    !matches!(outbound, Outbound::Socks(_) | Outbound::Http(_))
}

/// Reference `urltest.URLTest`: HEAD through the outbound, any HTTP response
/// counts, delay measured from the dial (reset before the TLS handshake).
async fn delay_test(
    stream: &mut TcpStream,
    router: &Router,
    index: usize,
    url: &str,
    timeout: i16,
    cors: &[String],
) -> std::io::Result<()> {
    let deadline = Duration::from_millis(timeout.max(0) as u64);
    let test = async {
        let (tls, host, port, authority, path) = parse_link(url)?;
        let target = Target::Domain(host.clone(), port);
        let mut start = Instant::now();
        let Ok(crate::inbound::Conn::Plain(conn)) = router.connect_index(index, &target).await
        else {
            return None;
        };
        let mut stream: crate::inbound::AnyStream = if tls {
            // Reference resets the clock after the dial, before the handshake.
            start = Instant::now();
            tls_client::wrap_probe(conn, &host).await.ok()?
        } else {
            conn
        };
        let request =
            format!("HEAD {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut byte = [0u8; 1];
        let mut status = Vec::new();
        loop {
            stream.read_exact(&mut byte).await.ok()?;
            status.push(byte[0]);
            if status.ends_with(b"\r\n") || status.len() >= 64 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&status);
        let _ = text.split_whitespace().nth(1)?;
        u16::try_from(start.elapsed().as_millis()).ok()
    };
    match tokio::time::timeout(deadline, test).await {
        Err(_) => respond_json(stream, 504, "Gateway Timeout", &timeout_err(), cors).await,
        Ok(None) | Ok(Some(0)) => {
            respond_json(stream, 503, "Service Unavailable", &delay_err(), cors).await
        }
        Ok(Some(delay)) => respond_json(stream, 200, "OK", &json!({"delay": delay}), cors).await,
    }
}

/// Minimal URL split: `(tls, host, port, authority, path-with-query)`.
fn parse_link(url: &str) -> Option<(bool, String, u16, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let (authority, tail) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let path = if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    let (host, port) = split_authority(authority)?;
    Some((tls, host, port, authority.to_string(), path))
}

fn split_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => return Some((host.to_string(), 443)),
        };
        Some((host.to_string(), port))
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Some((host.to_string(), port.parse().ok()?))
    } else {
        Some((authority.to_string(), 443))
    }
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Reference `authentication` middleware: `Bearer <secret>` header, or a
/// non-empty `?token=` on websocket upgrades only.
fn authorized(
    api: &ClashApi,
    headers: &[(String, String)],
    query: &[(String, String)],
    upgrade: &str,
) -> bool {
    let Some(secret) = &api.secret else {
        return true;
    };
    if upgrade.eq_ignore_ascii_case("websocket")
        && let Some(token) = query
            .iter()
            .find(|(k, v)| k == "token" && !v.is_empty())
            .map(|(_, v)| v)
    {
        return token == secret;
    }
    match header_get(headers, "authorization").and_then(|v| v.split_once(' ')) {
        Some(("Bearer", token)) => token == secret,
        _ => false,
    }
}

/// Preflight interception (reference `cors.Handler`): 200 with CORS headers
/// only when origin, method and every requested header are allowed —
/// otherwise a bare 200 with `Vary` only.
async fn preflight(
    stream: &mut TcpStream,
    api: &ClashApi,
    origin: Option<&str>,
    acrm: &str,
    acrh: Option<&str>,
    acpn: Option<&str>,
) -> std::io::Result<()> {
    let mut headers = vec![
        "Vary: Origin".to_string(),
        "Vary: Access-Control-Request-Method".to_string(),
        "Vary: Access-Control-Request-Headers".to_string(),
    ];
    let requested = acrh.filter(|v| !v.is_empty());
    let headers_ok = requested.is_none_or(|list| {
        list.split(',')
            .map(str::trim)
            .all(is_allowed_preflight_header)
    });
    if api.allowed_origin(origin).is_some() && PREFLIGHT_METHODS.contains(&acrm) && headers_ok {
        if let Some(value) = api.allowed_origin(origin) {
            headers.push(format!("Access-Control-Allow-Origin: {value}"));
        }
        if let Some(list) = requested {
            let names: Vec<String> = list
                .split(',')
                .map(|h| canonical_header_name(h.trim()))
                .collect();
            headers.push(format!(
                "Access-Control-Allow-Headers: {}",
                names.join(", ")
            ));
        }
        headers.push(format!("Access-Control-Allow-Methods: {acrm}"));
        headers.push("Access-Control-Max-Age: 300".to_string());
        if api.allow_private_network && acpn == Some("true") {
            headers.push("Access-Control-Allow-Private-Network: true".to_string());
        }
    }
    send(stream, 200, "OK", None, &headers, b"", true).await
}

fn is_allowed_preflight_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-type") || name.eq_ignore_ascii_case("authorization")
}

/// MIME header canonical form (`Authorization`, `X-Custom`).
fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name.chars() {
        if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else if c == '-' {
            out.push('-');
            upper = true;
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// 405 with one `Allow` header per method (reference emits them in reverse
/// registration order for plain OPTIONS — probed against lx.3).
async fn method_not_allowed(
    stream: &mut TcpStream,
    methods: &[&str],
    options: bool,
    cors: &[String],
) -> std::io::Result<()> {
    let mut headers = cors.to_vec();
    if options {
        for m in methods.iter().rev() {
            headers.push(format!("Allow: {m}"));
        }
    } else {
        for m in methods {
            headers.push(format!("Allow: {m}"));
        }
    }
    send(stream, 405, "Method Not Allowed", None, &headers, b"", true).await
}

async fn read_head(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return if head.is_empty() {
                Ok(None)
            } else {
                Ok(Some(head))
            };
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(Some(head));
        }
        if head.len() > MAX_HEAD {
            return Ok(None);
        }
    }
}

/// Split raw head bytes into the request line and headers.
fn split_head(head: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let text = String::from_utf8_lossy(head);
    let (request_line, rest) = text.split_once("\r\n")?;
    let mut headers = Vec::new();
    for line in rest.split_terminator("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Some((request_line.to_string(), headers))
}

fn parse_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode_plus(v)),
            None => (percent_decode(part), String::new()),
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    decode_impl(input, false)
}

fn percent_decode_plus(input: &str) -> String {
    decode_impl(input, true)
}

fn decode_impl(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &input[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn bad_request() -> Value {
    json!({"message": "Body invalid"})
}

fn unauthorized() -> Value {
    json!({"message": "Unauthorized"})
}

fn not_found() -> Value {
    json!({"message": "Resource not found"})
}

fn timeout_err() -> Value {
    json!({"message": "Timeout"})
}

fn delay_err() -> Value {
    json!({"message": "An error occurred in the delay test"})
}

async fn respond_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &Value,
    cors: &[String],
) -> std::io::Result<()> {
    let body = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    send(
        stream,
        status,
        reason,
        Some("application/json"),
        cors,
        &body,
        true,
    )
    .await
}

async fn respond_text(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    cors: &[String],
    content_type: &str,
) -> std::io::Result<()> {
    send(
        stream,
        status,
        reason,
        Some(content_type),
        cors,
        body.as_bytes(),
        true,
    )
    .await
}

async fn respond_no_content(stream: &mut TcpStream, cors: &[String]) -> std::io::Result<()> {
    send(stream, 204, "No Content", None, cors, b"", false).await
}

async fn send(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: Option<&str>,
    headers: &[String],
    body: &[u8],
    with_length: bool,
) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    if let Some(content_type) = content_type {
        out.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    for header in headers {
        out.push_str(header);
        out.push_str("\r\n");
    }
    if with_length {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(secret: Option<&str>) -> ClashApi {
        ClashApi {
            bind: "127.0.0.1:0".into(),
            secret: secret.map(str::to_string),
            allow_origins: vec!["*".into()],
            allow_private_network: false,
            external_ui: None,
            external_ui_download: None,
        }
    }

    #[test]
    fn parse_link_shapes() {
        let (tls, host, port, authority, path) =
            parse_link("https://example.com:8443/a?b=1").expect("parse");
        assert!(tls);
        assert_eq!(
            (host.as_str(), port, authority.as_str(), path.as_str()),
            ("example.com", 8443, "example.com:8443", "/a?b=1")
        );
        let (tls, host, port, authority, path) = parse_link("http://example.com/x").expect("parse");
        assert!(!tls);
        assert_eq!(
            (host.as_str(), port, authority.as_str(), path.as_str()),
            ("example.com", 443, "example.com", "/x")
        );
        let (tls, host, port, authority, path) = parse_link("https://h?x=1").expect("parse");
        assert!(tls);
        assert_eq!(
            (host.as_str(), port, authority.as_str(), path.as_str()),
            ("h", 443, "h", "/?x=1")
        );
        assert!(parse_link("ftp://x/").is_none());
        assert!(parse_link("https:///x").is_none());
    }

    #[test]
    fn authorization_rules() {
        let auth = |value: &str| vec![("Authorization".to_string(), value.to_string())];
        let with_secret = api(Some("s3cr3t"));
        assert!(authorized(&with_secret, &auth("Bearer s3cr3t"), &[], ""));
        assert!(!authorized(&with_secret, &[], &[], ""));
        assert!(!authorized(&with_secret, &auth("Bearer wrong"), &[], ""));
        assert!(!authorized(&with_secret, &auth("Basic s3cr3t"), &[], ""));
        // websocket: non-empty token matches without a header…
        assert!(authorized(
            &with_secret,
            &[],
            &[("token".into(), "s3cr3t".into())],
            "websocket"
        ));
        assert!(!authorized(
            &with_secret,
            &[],
            &[("token".into(), "wrong".into())],
            "websocket"
        ));
        // …an empty token falls through to the header check (reference).
        assert!(!authorized(
            &with_secret,
            &[],
            &[("token".into(), String::new())],
            "websocket"
        ));
        assert!(authorized(
            &with_secret,
            &auth("Bearer s3cr3t"),
            &[("token".into(), String::new())],
            "websocket"
        ));
        // token without the websocket upgrade is ignored
        assert!(!authorized(
            &with_secret,
            &[],
            &[("token".into(), "s3cr3t".into())],
            ""
        ));
        assert!(authorized(&api(None), &[], &[], ""));
    }

    #[test]
    fn origin_matching() {
        let wildcard = api(None);
        assert_eq!(
            wildcard.allowed_origin(Some("http://x")).as_deref(),
            Some("*")
        );
        assert_eq!(wildcard.allowed_origin(None), None);
        let strict = ClashApi {
            allow_origins: vec!["http://allowed".into()],
            ..api(None)
        };
        assert_eq!(
            strict.allowed_origin(Some("http://allowed")).as_deref(),
            Some("http://allowed")
        );
        assert_eq!(strict.allowed_origin(Some("http://evil")), None);
    }

    #[test]
    fn preflight_header_rules() {
        assert!(is_allowed_preflight_header("content-type"));
        assert!(is_allowed_preflight_header("Authorization"));
        assert!(!is_allowed_preflight_header("x-custom"));
        assert_eq!(canonical_header_name("authorization"), "Authorization");
        assert_eq!(canonical_header_name("content-type"), "Content-Type");
        assert_eq!(canonical_header_name("x-foo-bar"), "X-Foo-Bar");
    }

    #[test]
    fn route_classification() {
        assert!(matches!(classify_with_ui("/", false).0, Route::Root));
        assert!(matches!(
            classify_with_ui("/version", false).0,
            Route::Version
        ));
        assert!(matches!(
            classify_with_ui("/proxies", false).0,
            Route::Proxies
        ));
        assert!(matches!(
            classify_with_ui("/proxies/", false).0,
            Route::Proxies
        ));
        assert!(matches!(
            classify_with_ui("/proxies/sel", false).0,
            Route::Proxy(_)
        ));
        assert!(matches!(
            classify_with_ui("/proxies/sel/", false).0,
            Route::Proxy(_)
        ));
        assert!(matches!(
            classify_with_ui("/proxies/sel/delay", false).0,
            Route::Delay(_)
        ));
        assert!(matches!(
            classify_with_ui("/proxies/sel/delay/", false).0,
            Route::Delay(_)
        ));
        assert!(matches!(
            classify_with_ui("/proxies/a/b", false).0,
            Route::Unknown
        ));
        assert!(matches!(
            classify_with_ui("/proxies//sel", false).0,
            Route::Unknown
        ));
        assert!(matches!(
            classify_with_ui("/proxies/", false).0,
            Route::Proxies
        ));
        assert!(matches!(classify_with_ui("/nope", false).0, Route::Unknown));
        assert!(matches!(
            classify_with_ui("/version/", false).0,
            Route::Unknown
        ));
        assert_eq!(classify_with_ui("/proxies/sel", false).1, GET_PUT);
        assert_eq!(classify_with_ui("/version", false).1, GET_ONLY);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode_plus("a+b"), "a b");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn normalize_bind_wildcard() {
        assert_eq!(normalize_bind(":9090"), "0.0.0.0:9090");
        assert_eq!(normalize_bind("127.0.0.1:9090"), "127.0.0.1:9090");
    }

    #[test]
    fn data_view_routes_classify() {
        assert!(matches!(classify_with_ui("/logs", false).0, Route::Logs));
        assert!(matches!(
            classify_with_ui("/traffic", false).0,
            Route::Traffic
        ));
        assert!(matches!(
            classify_with_ui("/connections", false).0,
            Route::Connections
        ));
        assert!(matches!(
            classify_with_ui("/connections/42", false).0,
            Route::Connection(42)
        ));
        assert!(matches!(
            classify_with_ui("/connections/abc", false).0,
            Route::Unknown
        ));
        assert!(matches!(classify_with_ui("/rules", false).0, Route::Rules));
        assert!(matches!(
            classify_with_ui("/configs", false).0,
            Route::Configs
        ));
        assert!(matches!(
            classify_with_ui("/providers/proxies", false).0,
            Route::Providers
        ));
        assert!(matches!(
            classify_with_ui("/providers/rule/abc", false).0,
            Route::Providers
        ));
        assert_eq!(classify_with_ui("/connections", false).1, GET_DELETE);
        assert_eq!(classify_with_ui("/configs", false).1, GET_PUT_PATCH);
        // external_ui turns unknown paths into static lookups
        assert!(matches!(
            classify_with_ui("/ui/app.js", true).0,
            Route::Static(_)
        ));
        assert!(matches!(
            classify_with_ui("/ui/app.js", false).0,
            Route::Unknown
        ));
        // traversal attempts never become file lookups
        assert!(matches!(
            classify_with_ui("/../etc/passwd", true).0,
            Route::Unknown
        ));
    }

    #[test]
    fn rfc3339_and_ports() {
        assert_eq!(rfc3339_utc(Duration::from_secs(0)).len(), 20);
        assert!(rfc3339_utc(Duration::from_secs(0)).ends_with('Z'));
        // 2024-01-02T03:04:05Z
        let (y, m, d, hh, mm, ss) = civil_from_epoch(1_704_164_645);
        assert_eq!(
            (y, m, d, hh, mm, ss),
            (2024, 1, 2, 3, 4, 5),
            "civil_from_epoch"
        );
        assert_eq!(
            split_host_port("192.168.1.10:5000"),
            ("192.168.1.10".to_string(), "5000".to_string())
        );
        assert_eq!(
            split_host_port("[::1]:443"),
            ("::1".to_string(), "443".to_string())
        );
        assert_eq!(
            split_host_port("example.com"),
            ("example.com".to_string(), String::new())
        );
    }

    #[test]
    fn log_entry_shape() {
        // serde_json keeps the insertion order (preserve_order feature)
        assert_eq!(
            log_entry("", logging::Level::Info, "hello"),
            r#"{"type":"info","payload":"hello"}"#
        );
        assert_eq!(
            log_entry("warning", logging::Level::Warn, "careful"),
            r#"{"type":"warning","payload":"careful"}"#
        );
    }

    #[test]
    fn mime_guesses() {
        assert_eq!(
            mime_for(std::path::Path::new("a/index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            mime_for(std::path::Path::new("a/app.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            mime_for(std::path::Path::new("a/x.bin")),
            "application/octet-stream"
        );
    }
}
