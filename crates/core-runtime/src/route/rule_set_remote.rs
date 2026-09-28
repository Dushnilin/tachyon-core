//! Remote rule sets: `RemoteRuleSet` in the reference. The set is created
//! empty and filled during start, so the first fetch failures surface the same
//! way the reference reports them (`initial rule-set: <tag>`).

use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use serde_json::Value;

use super::super::http_client::HttpClient;
use super::super::logging;
use super::rule_set::RuleSet;
use crate::route::Router;

/// Reference default: 24h when `update_interval` is absent.
const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

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

    /// `RemoteRuleSet.StartContext` without the cache-file restore (F3.4).
    pub async fn start(&mut self, router: &Router) -> io::Result<()> {
        let mut loaded = false;
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
            self.fetch(router, true).await.map_err(|error| {
                io::Error::other(format!("initial rule-set: {}: {error}", self.tag()))
            })?;
        }
        Ok(())
    }

    /// `RemoteRuleSet.fetch`: conditional GET, 304 keeps the current rules.
    pub async fn fetch(&mut self, router: &Router, is_start: bool) -> io::Result<()> {
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
        logging::info(format_args!("updated rule-set {}", self.tag()));
        Ok(())
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

    /// Fetch every remote set once; a failure aborts the start.
    pub async fn start_all(&self, router: &Router) -> anyhow::Result<()> {
        for set in &self.sets {
            set.lock().await.start(router).await?;
        }
        Ok(())
    }

    /// Periodic refresh; the task ends with the process.
    pub fn spawn_updaters(&self, router: Arc<Router>) {
        for set in &self.sets {
            let state = Arc::clone(set);
            let router = Arc::clone(&router);
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
                    if let Err(error) = guard.fetch(&router, false).await {
                        logging::error(format_args!("fetch rule-set {}: {error}", guard.tag()));
                    }
                }
            });
        }
    }
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
        set.start(&router).await.expect("start");
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
        set.start(&router).await.expect("start");
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
        set.fetch(&router, false).await.expect("fetch");
        server.await.ok();
        assert_eq!(set.set.rule_count(), 1);
    }

    #[tokio::test]
    async fn unexpected_status_is_an_error() {
        let router = router().await;
        let (url, server) =
            serve(format!("HTTP/1.1 500 Internal Server Error{CRLF}{CRLF}").into_bytes()).await;
        let mut set = remote("rs", &url);
        let error = set.start(&router).await.unwrap_err();
        assert!(
            error.to_string().contains("unexpected status: 500"),
            "{error}"
        );
        assert!(error.to_string().contains("initial rule-set: rs"));
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
        set.start(&router).await.expect("start");
        assert_eq!(set.set.rule_count(), 1);
        let rules = set.set.snapshot();
        assert_eq!(rules[0]["domain_suffix"][0], "local.example");
        let _ = std::fs::remove_file(std::env::temp_dir().join("tachyon-remote-rule-set-test.srs"));
    }
}
