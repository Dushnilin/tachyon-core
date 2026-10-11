//! Remote rule sets: `RemoteRuleSet` in the reference. The set is created
//! empty and filled during start, so the first fetch failures surface the same
//! way the reference reports them (`initial rule-set: <tag>`).

use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use serde_json::Value;

use super::super::cache_file::{BUCKET_RULE_SET, SharedCacheFile, saved_binary};
use super::super::http_client::HttpClient;
use super::super::logging;
use super::rule_set::RuleSet;
use crate::route::Router;

/// `sha256` over the (tag-expanded) URL, as the reference keys the cache.
fn url_hash(url: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    hasher.finalize().into()
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Default path for caching mmap-able .tsrs binary images.
/// On Linux/OpenWrt this points to `/tmp/tachyon-rulesets/` (tmpfs in RAM),
/// which prevents wearing down SPI flash storage.
pub fn default_tsrs_cache_path(tag: &str) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from(format!("/tmp/tachyon-rulesets/{tag}.tsrs"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join(format!("tachyon-rulesets/{tag}.tsrs"))
    }
}

/// Reference default: 24h when `update_interval` is absent.
const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Retry ladder for a set that was still empty at start: 5, 10, 20 and then
/// every 30 seconds, the schedule podkop-engine's OpenWrt build settled on.
/// Once one fetch lands, the periodic updater takes over.
const RECOVERY_LADDER: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
    Duration::from_secs(30),
];

/// Keep the engine running with an empty rule-set instead of aborting
/// the start when a remote set cannot be fetched immediately, and fetch it
/// in the background via the recovery ladder.
///
/// On by default on OpenWrt routers so booting before WAN is established or
/// transient DNS outages do not take down the entire proxy core and router DNS.
/// Can be explicitly disabled via `TACHYON_RULESET_SOFT_START=0` or `"false"`.
pub fn soft_start_enabled() -> bool {
    !matches!(
        std::env::var("TACHYON_RULESET_SOFT_START").as_deref(),
        Ok("0") | Ok("false") | Ok("no")
    )
}

#[derive(Debug, Clone)]
pub struct RemoteSpec {
    pub url: String,
    /// `initial_path`: a local copy to start from before the first fetch.
    pub initial_path: Option<String>,
    /// `update_interval` (0 = the 24h default).
    pub update_interval: Duration,
    pub client: HttpClient,
    /// `format`, when the config pinned one.
    pub format: Option<String>,
    /// Zero-copy mmap binary rule-set toggle.
    pub mmap: bool,
    /// Incremental binary delta updates toggle.
    pub delta_update: bool,
    /// Cache update interval (e.g. "1h"). Overrides update_interval when set.
    pub cache_interval: Duration,
    /// Custom path to cache .tsrs binary file (default: /tmp/tachyon-rulesets/<tag>.tsrs).
    pub cache_file: Option<String>,
    /// Mmap mode: "auto" | "mmap" | "memory".
    pub mode: crate::route::mmap_set::MmapMode,
}

/// The live state of one remote set: the shared set plus the fetch bookkeeping.
/// The lock is async because a fetch holds it across I/O.
#[derive(Debug)]
pub struct RemoteRuleSet {
    pub tags: Vec<String>,
    pub spec: RemoteSpec,
    pub set: Arc<RuleSet>,
    pub etag: Option<String>,
    pub last_updated: Option<std::time::SystemTime>,
}

impl RemoteRuleSet {
    pub fn tag(&self) -> &str {
        &self.tags[0]
    }

    pub fn tsrs_cache_path(&self) -> std::path::PathBuf {
        if let Some(path) = &self.spec.cache_file {
            std::path::PathBuf::from(path)
        } else {
            default_tsrs_cache_path(self.tag())
        }
    }

    fn compile_and_cache_mmap(
        &self,
        rules: &[Value],
        cache_path: &std::path::Path,
    ) -> io::Result<crate::route::mmap_set::MmapRuleSet> {
        let mut compiler = crate::route::mmap_set::RuleSetCompiler::new();
        let bytes = compiler
            .compile(rules)
            .map_err(|e| io::Error::other(format!("compile tsrs: {e}")))?;
        if let Some(parent) = cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_path = cache_path.with_extension("tmp");
        std::fs::write(&tmp_path, &bytes)?;
        std::fs::rename(&tmp_path, cache_path)?;
        crate::route::mmap_set::MmapRuleSet::open_with_mode(cache_path, self.spec.mode)
            .map_err(|e| io::Error::other(format!("open tsrs: {e}")))
    }

    /// `RemoteRuleSet.StartContext`: cache file, then initial path, then the
    /// first fetch. A cache entry saved from a different URL is refetched.
    pub async fn start(
        &mut self,
        router: &Router,
        cache: Option<&SharedCacheFile>,
    ) -> io::Result<()> {
        let mut loaded = false;
        let tsrs_path = self.tsrs_cache_path();
        let use_mmap = self.spec.mmap || self.spec.mode.should_use_mmap();

        if use_mmap && tsrs_path.exists() {
            match crate::route::mmap_set::MmapRuleSet::open_with_mode(&tsrs_path, self.spec.mode) {
                Ok(mmap_set) => {
                    self.set.replace_mmap(Arc::new(mmap_set));
                    loaded = true;
                    logging::info(format_args!(
                        "restored rule-set {} via mmap from {}",
                        self.tag(),
                        tsrs_path.display()
                    ));
                }
                Err(error) => {
                    logging::warn(format_args!(
                        "open cached mmap rule-set {}: {error}, will refetch",
                        tsrs_path.display()
                    ));
                }
            }
        }

        #[allow(clippy::collapsible_if)]
        if !loaded {
            if let Some(cache) = cache {
                match self.restore_from_cache(cache) {
                    Ok(true) => loaded = true,
                    Ok(false) => {}
                    Err(error) => {
                        logging::warn(format_args!(
                            "restore cached rule-set, will refetch: {error}"
                        ));
                    }
                }
            }
        }
        #[allow(clippy::collapsible_if)]
        if !loaded {
            if let Some(path) = &self.spec.initial_path {
                match std::fs::read(path) {
                    Ok(data) => {
                        if data.starts_with(b"TSRS") {
                            match crate::route::mmap_set::MmapRuleSet::open_with_mode(
                                path,
                                self.spec.mode,
                            ) {
                                Ok(mmap_set) => {
                                    self.set.replace_mmap(Arc::new(mmap_set));
                                    loaded = true;
                                    logging::info(format_args!(
                                        "loaded rule-set {} via mmap from {}",
                                        self.tag(),
                                        path
                                    ));
                                }
                                Err(error) => logging::warn(format_args!(
                                    "load initial mmap rule-set from {path}: {error}"
                                )),
                            }
                        } else {
                            match parse_payload(&data, self.spec.format.as_deref()) {
                                Ok(rules) => {
                                    #[allow(clippy::collapsible_if)]
                                    if use_mmap {
                                        if let Ok(mmap_set) =
                                            self.compile_and_cache_mmap(&rules, &tsrs_path)
                                        {
                                            self.set.replace_mmap(Arc::new(mmap_set));
                                            loaded = true;
                                            logging::info(format_args!(
                                                "loaded rule-set {} (compiled to mmap) from {}",
                                                self.tag(),
                                                path
                                            ));
                                        }
                                    }
                                    if !loaded {
                                        self.set.replace_rules(rules);
                                        loaded = true;
                                        logging::info(format_args!(
                                            "loaded rule-set {} from {}",
                                            self.tag(),
                                            path
                                        ));
                                    }
                                }
                                Err(error) => logging::warn(format_args!(
                                    "load initial rule-set from {path}: {error}"
                                )),
                            }
                        }
                    }
                    Err(error) => {
                        logging::warn(format_args!("load initial rule-set from {path}: {error}"))
                    }
                }
            }
        }
        if !loaded {
            self.fetch(router, true, cache).await.map_err(|error| {
                io::Error::other(format!("initial rule-set: {}: {error}", self.tag()))
            })?;
        }
        Ok(())
    }

    /// Load a cached copy; `Ok(false)` when there is nothing usable.
    fn restore_from_cache(&mut self, cache: &SharedCacheFile) -> io::Result<bool> {
        let raw = {
            let guard = cache.lock().expect("cache file");
            guard.get(BUCKET_RULE_SET, self.tag().as_bytes())
        };
        let Some(raw) = raw else {
            return Ok(false);
        };
        let saved = saved_binary::unmarshal(&raw)
            .ok_or_else(|| io::Error::other("malformed cached rule-set"))?;
        if !saved.url_hash.is_empty() && saved.url_hash != url_hash(&self.spec.url) {
            logging::info(format_args!(
                "cached rule-set was downloaded from another URL, will refetch"
            ));
            return Ok(false);
        }
        let rules = parse_payload(&saved.content, self.spec.format.as_deref())?;
        self.set.replace_rules(rules);
        self.etag = if saved.last_etag.is_empty() {
            None
        } else {
            Some(saved.last_etag)
        };
        self.last_updated =
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(saved.last_updated));
        logging::info(format_args!("restored rule-set {} from cache", self.tag()));
        Ok(true)
    }

    fn save_to_cache(&self, cache: &SharedCacheFile, content: &[u8]) {
        let saved = saved_binary::SavedBinary {
            last_updated: self
                .last_updated
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or_else(saved_binary::now_unix),
            content: content.to_vec(),
            last_etag: self.etag.clone().unwrap_or_default(),
            url_hash: url_hash(&self.spec.url),
        };
        let mut guard = cache.lock().expect("cache file");
        guard.put(
            BUCKET_RULE_SET,
            self.tag().as_bytes(),
            saved_binary::marshal(&saved),
        );
        if let Err(error) = guard.flush() {
            logging::error(format_args!("save rule-set cache: {error}"));
        }
    }

    /// `RemoteRuleSet.fetch`: conditional GET, 304 keeps the current rules.
    /// Supports incremental binary delta updates (`.delta`) and zero-copy mmap.
    pub async fn fetch(
        &mut self,
        router: &Router,
        is_start: bool,
        cache: Option<&SharedCacheFile>,
    ) -> io::Result<()> {
        let tsrs_path = self.tsrs_cache_path();
        let use_mmap = self.spec.mmap || self.spec.mode.should_use_mmap();

        // 1. Try delta update if mmap and delta_update enabled, and base .tsrs exists
        #[allow(clippy::collapsible_if)]
        if use_mmap && self.spec.delta_update && tsrs_path.exists() {
            if let Ok(base_bytes) = std::fs::read(&tsrs_path) {
                if base_bytes.starts_with(b"TSRS") {
                    let base_sha = sha256_digest(&base_bytes);
                    let delta_url = format!("{}.delta", self.spec.url);
                    let mut delta_headers = Vec::new();
                    delta_headers.push(("X-Base-SHA256".to_string(), hex_encode(&base_sha)));
                    if let Some(etag) = &self.etag {
                        delta_headers.push(("If-None-Match".to_string(), etag.clone()));
                    }

                    #[allow(clippy::collapsible_if)]
                    if let Ok(delta_resp) = self
                        .spec
                        .client
                        .get(router, &delta_url, &delta_headers)
                        .await
                    {
                        if delta_resp.status == 200 && delta_resp.body.starts_with(b"TDLT") {
                            match crate::route::mmap_set::apply_delta(&base_bytes, &delta_resp.body)
                            {
                                Ok(new_bytes) => {
                                    let tmp_path = tsrs_path.with_extension("tmp");
                                    if let Some(parent) = tsrs_path.parent() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                    let _ = std::fs::write(&tmp_path, &new_bytes);
                                    if std::fs::rename(&tmp_path, &tsrs_path).is_ok() {
                                        match crate::route::mmap_set::MmapRuleSet::open_with_mode(
                                            &tsrs_path,
                                            self.spec.mode,
                                        ) {
                                            Ok(mmap_set) => {
                                                self.set.replace_mmap(Arc::new(mmap_set));
                                                if let Some(etag) = delta_resp.header("etag") {
                                                    self.etag = Some(etag.to_string());
                                                }
                                                self.last_updated =
                                                    Some(std::time::SystemTime::now());
                                                logging::info(format_args!(
                                                    "atomically updated rule-set {} via delta patch ({} bytes)",
                                                    self.tag(),
                                                    delta_resp.body.len()
                                                ));
                                                return Ok(());
                                            }
                                            Err(e) => {
                                                logging::warn(format_args!(
                                                    "failed to open mmap after delta patch: {e}"
                                                ));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    logging::warn(format_args!(
                                        "delta patch application failed: {e}, falling back to full fetch"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Full fetch
        let mut headers = Vec::new();
        if let Some(etag) = &self.etag {
            headers.push(("If-None-Match".to_string(), etag.clone()));
        }
        let response = self
            .spec
            .client
            .get(router, &self.spec.url, &headers)
            .await?;
        match response.status {
            200 => {}
            304 => {
                self.last_updated = Some(std::time::SystemTime::now());
                if let Some(cache) = cache {
                    self.touch_cache(cache);
                }
                logging::info(format_args!("update rule-set {}: not modified", self.tag()));
                return Ok(());
            }
            status => {
                return Err(io::Error::other(format!("unexpected status: {status}")));
            }
        }
        let _ = is_start;

        if response.body.starts_with(b"TSRS") {
            if let Some(parent) = tsrs_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let tmp_path = tsrs_path.with_extension("tmp");
            std::fs::write(&tmp_path, &response.body)?;
            std::fs::rename(&tmp_path, &tsrs_path)?;
            let mmap_set =
                crate::route::mmap_set::MmapRuleSet::open_with_mode(&tsrs_path, self.spec.mode)
                    .map_err(|e| io::Error::other(format!("open downloaded tsrs: {e}")))?;
            self.set.replace_mmap(Arc::new(mmap_set));
            logging::info(format_args!(
                "updated rule-set {} via TSRS binary",
                self.tag()
            ));
        } else {
            let rules = parse_payload(&response.body, self.spec.format.as_deref())?;
            if use_mmap {
                match self.compile_and_cache_mmap(&rules, &tsrs_path) {
                    Ok(mmap_set) => {
                        self.set.replace_mmap(Arc::new(mmap_set));
                        logging::info(format_args!(
                            "compiled and mmapped rule-set {} ({} rules)",
                            self.tag(),
                            rules.len()
                        ));
                    }
                    Err(e) => {
                        logging::warn(format_args!(
                            "failed to compile mmap: {e}, falling back to memory rules"
                        ));
                        self.set.replace_rules(rules);
                    }
                }
            } else {
                self.set.replace_rules(rules);
            }
        }

        if let Some(etag) = response.header("etag") {
            self.etag = Some(etag.to_string());
        }
        self.last_updated = Some(std::time::SystemTime::now());
        if let Some(cache) = cache {
            self.save_to_cache(cache, &response.body);
        }
        logging::info(format_args!("updated rule-set {}", self.tag()));
        Ok(())
    }

    /// 304 keeps the content; only the timestamp moves (reference behaviour).
    fn touch_cache(&self, cache: &SharedCacheFile) {
        let raw = {
            let guard = cache.lock().expect("cache file");
            guard.get(BUCKET_RULE_SET, self.tag().as_bytes())
        };
        let Some(mut saved) = raw.as_deref().and_then(saved_binary::unmarshal) else {
            return;
        };
        saved.last_updated = self
            .last_updated
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or_else(saved_binary::now_unix);
        saved.url_hash = url_hash(&self.spec.url);
        let mut guard = cache.lock().expect("cache file");
        guard.put(
            BUCKET_RULE_SET,
            self.tag().as_bytes(),
            saved_binary::marshal(&saved),
        );
        if let Err(error) = guard.flush() {
            logging::error(format_args!("save rule-set updated time: {error}"));
        }
    }
}

/// Split out so the updater task can own the state without cloning the set.
#[derive(Debug, Default)]
pub struct RemoteRegistry {
    sets: Vec<Arc<Mutex<RemoteRuleSet>>>,
}

impl RemoteRegistry {
    pub fn new() -> Self {
        Self { sets: Vec::new() }
    }

    pub fn push(&mut self, set: RemoteRuleSet) {
        self.sets.push(Arc::new(Mutex::new(set)));
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Fetch every remote set once; a failure aborts the start unless
    /// `TACHYON_RULESET_SOFT_START` asks for the set to be filled later.
    pub async fn start_all(
        &self,
        router: &Arc<Router>,
        cache: Option<&SharedCacheFile>,
    ) -> anyhow::Result<()> {
        self.start_all_with(router, cache, soft_start_enabled())
            .await
    }

    async fn start_all_with(
        &self,
        router: &Arc<Router>,
        cache: Option<&SharedCacheFile>,
        soft: bool,
    ) -> anyhow::Result<()> {
        for set in &self.sets {
            if let Err(error) = set.lock().await.start(router, cache).await {
                if !soft {
                    return Err(error.into());
                }
                logging::warn(format_args!(
                    "{error}: starting with an empty rule-set, retrying in the background"
                ));
                spawn_recovery(Arc::clone(set), Arc::clone(router), cache.cloned());
            }
        }
        Ok(())
    }

    /// Periodic refresh; the task ends with the process.
    pub fn spawn_updaters(&self, router: Arc<Router>, cache: Option<SharedCacheFile>) {
        for set in &self.sets {
            let state = Arc::clone(set);
            let router = Arc::clone(&router);
            let cache = cache.clone();
            let interval = {
                let guard = set.try_lock().expect("rule-set mutex");
                if !guard.spec.cache_interval.is_zero() {
                    guard.spec.cache_interval
                } else if !guard.spec.update_interval.is_zero() {
                    guard.spec.update_interval
                } else {
                    DEFAULT_UPDATE_INTERVAL
                }
            };
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let mut guard = state.lock().await;
                    if let Err(error) = guard.fetch(&router, false, cache.as_ref()).await {
                        logging::error(format_args!("fetch rule-set {}: {error}", guard.tag()));
                    }
                }
            });
        }
    }
}

/// Keep fetching a set that was empty at start: the recovery ladder until one
/// attempt lands, after which the periodic updater owns it again.
fn spawn_recovery(
    set: Arc<Mutex<RemoteRuleSet>>,
    router: Arc<Router>,
    cache: Option<SharedCacheFile>,
) {
    tokio::spawn(async move {
        for delay in RECOVERY_LADDER {
            tokio::time::sleep(delay).await;
            let mut guard = set.lock().await;
            match guard.fetch(&router, false, cache.as_ref()).await {
                Ok(()) => {
                    logging::info(format_args!(
                        "recovered rule-set {} after an empty start",
                        guard.tag()
                    ));
                    return;
                }
                Err(error) => {
                    logging::warn(format_args!("fetch rule-set {}: {error}", guard.tag()));
                }
            }
        }
        logging::warn(format_args!(
            "rule-set {} is still empty, the periodic updater will keep trying",
            set.lock().await.tag()
        ));
    });
}

/// `ruleSet.Read` for a downloaded payload: the pinned `format` wins, then the
/// SRS magic, then the URL/path extension (`ruleSetDefaultFormat`).
pub fn parse_payload(data: &[u8], format: Option<&str>) -> io::Result<Vec<Value>> {
    match format {
        Some("source") => parse_source(data),
        Some("binary") => parse_binary(data),
        Some("tsrs") => Ok(Vec::new()),
        Some(other) => Err(io::Error::other(format!(
            "unknown rule-set format: {other}"
        ))),
        None => {
            if data.starts_with(b"TSRS") {
                Ok(Vec::new())
            } else if data.starts_with(b"SRS") {
                parse_binary(data)
            } else {
                parse_source(data)
            }
        }
    }
}

fn parse_source(data: &[u8]) -> io::Result<Vec<Value>> {
    let value: Value = serde_json::from_slice(data)
        .map_err(|error| io::Error::other(format!("decode rule-set source: {error}")))?;
    let rules = value
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(rules)
}

fn parse_binary(data: &[u8]) -> io::Result<Vec<Value>> {
    core_config::srs::read(data)
        .map_err(|error| io::Error::other(format!("read rule-set: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CRLF: &str = "\r\n";

    async fn router() -> Arc<Router> {
        Router::new(&json!({
            "log": {"level": "error"},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .expect("router")
    }

    fn srs_with(domain: &str) -> Vec<u8> {
        core_config::srs::compile(&json!({"rules": [{"domain_suffix": [domain]}]}), 2)
            .expect("compile")
    }

    fn remote(tag: &str, url: &str) -> RemoteRuleSet {
        let tags = vec![tag.to_string()];
        let set = Arc::new(RuleSet::new(tags.clone(), Vec::new()));
        RemoteRuleSet {
            tags,
            spec: RemoteSpec {
                url: url.to_string(),
                initial_path: None,
                update_interval: Duration::ZERO,
                client: HttpClient::default(),
                format: None,
                mmap: false,
                delta_update: true,
                cache_interval: Duration::ZERO,
                cache_file: None,
                mode: crate::route::mmap_set::MmapMode::Auto,
            },
            set,
            etag: None,
            last_updated: None,
        }
    }

    async fn serve(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });
        (format!("http://{addr}/ruleset.srs"), handle)
    }

    fn body_response(payload: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK{CRLF}Content-Length: {}{CRLF}{CRLF}",
            payload.len()
        )
        .into_bytes();
        response.extend_from_slice(payload);
        response
    }

    #[test]
    fn payload_format_detection() {
        let srs = srs_with("example.com");
        let rules = parse_payload(&srs, None).expect("srs");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["domain_suffix"][0], "example.com");
        let source = json!({"rules": [{"domain": ["a.test"]}]}).to_string();
        let rules = parse_payload(source.as_bytes(), None).expect("source");
        assert_eq!(rules[0]["domain"][0], "a.test");
        // a pinned format wins over the payload sniffing
        let error = parse_payload(&srs, Some("source")).unwrap_err();
        assert!(error.to_string().contains("rule-set source"));
        let error = parse_payload(source.as_bytes(), Some("other")).unwrap_err();
        assert_eq!(error.to_string(), "unknown rule-set format: other");
    }

    #[tokio::test]
    async fn start_fetches_and_fills_the_set() {
        let router = router().await;
        let payload = srs_with("fetched.example");
        let (url, server) = serve(body_response(&payload)).await;
        let mut set = remote("rs", &url);
        set.start(&router, None).await.expect("start");
        server.abort();
        assert_eq!(set.set.rule_count(), 1);
        assert!(set.last_updated.is_some());
    }

    #[tokio::test]
    async fn not_modified_keeps_the_rules() {
        let router = router().await;
        let payload = srs_with("cached.example");
        let (url, server) = serve(body_response(&payload)).await;
        let mut set = remote("rs", &url);
        set.start(&router, None).await.expect("start");
        server.abort();
        // the second response is 304: the set keeps what it had
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let etag_url = format!("http://{addr}/ruleset.srs");
        set.spec.url = etag_url.clone();
        set.etag = Some("W/\"".to_string());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut head = [0u8; 1024];
            let read = stream.read(&mut head).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&head[..read]).to_string();
            assert!(request.contains("If-None-Match"), "{request}");
            let _ = stream
                .write_all(format!("HTTP/1.1 304 Not Modified{CRLF}{CRLF}").as_bytes())
                .await;
        });
        set.fetch(&router, false, None).await.expect("fetch");
        server.await.ok();
        assert_eq!(set.set.rule_count(), 1);
    }

    #[tokio::test]
    async fn unexpected_status_is_an_error() {
        let router = router().await;
        let (url, server) =
            serve(format!("HTTP/1.1 500 Internal Server Error{CRLF}{CRLF}").into_bytes()).await;
        let mut set = remote("rs", &url);
        let error = set.start(&router, None).await.unwrap_err();
        assert!(
            error.to_string().contains("unexpected status: 500"),
            "{error}"
        );
        assert!(error.to_string().contains("initial rule-set: rs"));
        server.abort();
    }

    #[tokio::test]
    async fn soft_start_survives_and_recovers_the_set() {
        let router = router().await;
        let payload = srs_with("recovered.example");
        // 500 for the start attempts, the real set for the recovery fetch
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let response = if served.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                    format!("HTTP/1.1 500 Internal Server Error{CRLF}{CRLF}").into_bytes()
                } else {
                    body_response(&payload)
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });
        let mut registry = RemoteRegistry::new();
        registry.push(remote("rs", &format!("http://{addr}/ruleset.srs")));

        // with soft start disabled explicitly, start aborts like the reference
        let error = registry
            .start_all_with(&router, None, false)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("initial rule-set: rs"),
            "{error}"
        );

        // soft start (enabled by default): engine stays up, set starts empty
        registry.start_all(&router, None).await.expect("soft start");
        assert_eq!(registry.sets[0].lock().await.set.rule_count(), 0);

        // and the background ladder fills it without help
        for _ in 0..100 {
            if registry.sets[0].lock().await.set.rule_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let set = registry.sets[0].lock().await;
        assert_eq!(set.set.rule_count(), 1, "recovered in the background");
        assert!(
            set.set.index().has_suffix("recovered.example"),
            "the recovered set compiled its suffix"
        );
        drop(set);
        server.abort();
    }

    #[tokio::test]
    async fn initial_path_is_used_before_the_first_fetch() {
        let router = router().await;
        let payload = srs_with("local.example");
        let path = std::env::temp_dir().join("tachyon-remote-rule-set-test.srs");
        std::fs::write(&path, &payload).expect("write");
        let path = path.to_string_lossy().to_string();
        // a URL that would fail: the initial path must be enough
        let mut set = remote("rs", "http://127.0.0.1:1/ruleset.srs");
        set.spec.initial_path = Some(path);
        set.start(&router, None).await.expect("start");
        assert_eq!(set.set.rule_count(), 1);
        assert!(
            set.set.index().has_suffix("local.example"),
            "the initial path compiled its suffix"
        );
        let _ = std::fs::remove_file(std::env::temp_dir().join("tachyon-remote-rule-set-test.srs"));
    }

    #[tokio::test]
    async fn remote_mmap_compile_and_match() {
        let router = router().await;
        let payload = srs_with("mmap-fast.org");
        let (url, server) = serve(body_response(&payload)).await;
        let cache_file = std::env::temp_dir().join(format!("test-rs-{}.tsrs", std::process::id()));
        let mut set = remote("mmap_rs", &url);
        set.spec.mmap = true;
        set.spec.cache_file = Some(cache_file.to_string_lossy().to_string());
        set.start(&router, None).await.expect("start");
        server.abort();

        // Check file exists on disk/tmpfs
        assert!(cache_file.exists(), "cache_file must be written");
        let data = std::fs::read(&cache_file).expect("read cached tsrs");
        assert!(data.starts_with(b"TSRS"));

        // Match context
        let ctx = crate::route::ConnContext::new(
            "in",
            "10.0.0.2:1234".parse().unwrap(),
            crate::route::Target::Domain("sub.mmap-fast.org".to_string(), 443),
            "tcp",
        );
        assert!(
            set.set.matches(&ctx),
            "mmap rule set must match sub.mmap-fast.org"
        );

        let _ = std::fs::remove_file(&cache_file);
    }

    #[tokio::test]
    async fn remote_delta_update_flow() {
        let router = router().await;
        let base_rules = json!([{"domain_suffix": ["base-site.com"]}]);
        let mut compiler = crate::route::mmap_set::RuleSetCompiler::new();
        let base_tsrs = compiler.compile(base_rules.as_array().unwrap()).unwrap();
        let base_sha = sha256_digest(&base_tsrs);

        let cache_file =
            std::env::temp_dir().join(format!("test-delta-{}.tsrs", std::process::id()));
        std::fs::write(&cache_file, &base_tsrs).unwrap();

        // Build target tsrs with additional domain
        let mut target_compiler = crate::route::mmap_set::RuleSetCompiler::new();
        let target_rules = json!([{"domain_suffix": ["base-site.com", "delta-added.com"]}]);
        let target_tsrs = target_compiler
            .compile(target_rules.as_array().unwrap())
            .unwrap();
        let target_sha = sha256_digest(&target_tsrs);

        let delta_bytes = crate::route::mmap_set::DeltaBuilder::new(base_sha, target_sha)
            .add_suffix("delta-added.com")
            .build();

        // Serve delta when requested
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let delta_clone = delta_bytes.clone();
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let response = body_response(&delta_clone);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });

        let mut set = remote("delta_rs", &format!("http://{addr}/ruleset.srs"));
        set.spec.mmap = true;
        set.spec.delta_update = true;
        set.spec.cache_file = Some(cache_file.to_string_lossy().to_string());
        set.start(&router, None).await.expect("start");

        // Verify base matches before delta
        let ctx = crate::route::ConnContext::new(
            "in",
            "10.0.0.2:1234".parse().unwrap(),
            crate::route::Target::Domain("delta-added.com".to_string(), 443),
            "tcp",
        );
        assert!(
            !set.set.matches(&ctx),
            "delta-added should not match before delta"
        );

        // Now trigger fetch, which requests .delta and applies it
        set.fetch(&router, false, None).await.expect("fetch delta");
        assert!(
            set.set.matches(&ctx),
            "delta-added must match after delta applied"
        );

        server.abort();
        let _ = std::fs::remove_file(&cache_file);
    }
}
