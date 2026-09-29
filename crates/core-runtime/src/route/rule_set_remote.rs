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

/// Opt-in: keep the engine running with an empty rule-set instead of aborting
/// the start, and fetch it in the background. `TACHYON_RULESET_SOFT_START=1`.
///
/// Off by default, because the reference aborts with `initial rule-set:
/// <tag>` and an empty set means the rules pointing at it match nothing. A
/// router booting before its WAN is up is the case this is for: failing to
/// start there costs DNS as well as the proxy.
pub fn soft_start_enabled() -> bool {
    matches!(
        std::env::var("TACHYON_RULESET_SOFT_START").as_deref(),
        Ok("1") | Ok("true")
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

    /// `RemoteRuleSet.StartContext`: cache file, then initial path, then the
    /// first fetch. A cache entry saved from a different URL is refetched.
    pub async fn start(
        &mut self,
        router: &Router,
        cache: Option<&SharedCacheFile>,
    ) -> io::Result<()> {
        let mut loaded = false;
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
        if let Some(path) = &self.spec.initial_path {
            match std::fs::read(path) {
                Ok(data) => match parse_payload(&data, self.spec.format.as_deref()) {
                    Ok(rules) => {
                        self.set.replace_rules(rules);
                        loaded = true;
                        logging::info(format_args!("loaded rule-set {} from {}", self.tag(), path));
                    }
                    Err(error) => {
                        logging::warn(format_args!("load initial rule-set from {path}: {error}"))
                    }
                },
                Err(error) => {
                    logging::warn(format_args!("load initial rule-set from {path}: {error}"))
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
    pub async fn fetch(
        &mut self,
        router: &Router,
        is_start: bool,
        cache: Option<&SharedCacheFile>,
    ) -> io::Result<()> {
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
        let rules = parse_payload(&response.body, self.spec.format.as_deref())?;
        self.set.replace_rules(rules);
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
                if guard.spec.update_interval.is_zero() {
                    DEFAULT_UPDATE_INTERVAL
                } else {
                    guard.spec.update_interval
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
        Some(other) => Err(io::Error::other(format!(
            "unknown rule-set format: {other}"
        ))),
        None => {
            if data.starts_with(b"SRS") {
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

        // the reference aborts the start
        let error = registry.start_all(&router, None).await.unwrap_err();
        assert!(
            error.to_string().contains("initial rule-set: rs"),
            "{error}"
        );

        // soft start: the engine stays up, the set is empty for now
        registry
            .start_all_with(&router, None, true)
            .await
            .expect("soft start");
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
        assert_eq!(
            set.set.snapshot()[0]["domain_suffix"][0],
            "recovered.example"
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
        let rules = set.set.snapshot();
        assert_eq!(rules[0]["domain_suffix"][0], "local.example");
        let _ = std::fs::remove_file(std::env::temp_dir().join("tachyon-remote-rule-set-test.srs"));
    }
}
