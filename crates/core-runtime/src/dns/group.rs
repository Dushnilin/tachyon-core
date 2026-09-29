//! The lx `group` DNS server type (SPEC 033 v2): several member servers
//! behind one tag, with the selection built on two tables of expiring records
//! instead of per-server states.
//!
//! * a failed exchange writes an ERROR record (`error_ttl`) and erases that
//!   server's live wins — a win must not outlive a failure, that is the
//!   flap-back trap of `win_ttl > error_ttl`;
//! * the first success of a fan writes a WIN record (`win_ttl`, `fastest` only)
//!   and becomes the sticky target, while any success merely erases the
//!   server's live errors — never a win, so nothing self-reinforces.
//!
//! CLEAN = no live error. The mode picks a target among the clean members;
//! with no clean member the query makes exactly ONE attempt through the least
//! dirty server and never fans (survival mode). The group sits *under* the DNS
//! cache, so only the answer it returns is ever cached.
//!
//! Not ported: the SPEC 035 query trace and the `GetDNSGroups` state RPC, both
//! lxd-daemon surfaces (F7), and the network-change amnesty `Reset`, which has
//! no caller before a network monitor exists.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::codec;
use hickory_proto::op::ResponseCode;

/// Reference `DefaultErrorTTL`.
const DEFAULT_ERROR_TTL: Duration = Duration::from_secs(2 * 60);
/// Reference `DefaultWinTTL`.
const DEFAULT_WIN_TTL: Duration = Duration::from_secs(5 * 60);
/// Reference `maxRecords`: counts above it are indistinguishable for selection,
/// and the cap bounds memory on a dead network where every query adds one.
const MAX_RECORDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Stable,
    Fastest,
    Parallel,
}

impl Mode {
    /// `""` is the default, `stable` the fallback; anything else is refused
    /// with the reference's message by the caller.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "" | "stable" => Some(Self::Stable),
            "fastest" => Some(Self::Fastest),
            "parallel" => Some(Self::Parallel),
            _ => None,
        }
    }
}

/// One member exchange, taking its arguments by value so a fan can spawn it.
/// The runtime's `DnsService` is the only implementor: reaching a member means
/// going through its transport.
pub trait Members: Send + Sync {
    fn exchange(
        self: Arc<Self>,
        tag: String,
        query: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;
}

#[derive(Debug, Default)]
struct State {
    errors: HashMap<String, Vec<Instant>>,
    wins: HashMap<String, Vec<Instant>>,
    /// Last successful probe per member, kept for the state snapshot.
    last_rtt: HashMap<String, Duration>,
    /// The sticky target: kept while it is still a candidate.
    current: Option<String>,
    /// `fastest`: one query at a time runs the deciding fan.
    election: bool,
}

pub struct Group {
    pub tag: String,
    pub members: Vec<String>,
    mode: Mode,
    error_ttl: Duration,
    win_ttl: Duration,
    /// The whole query's budget; the target gets half of it and the rest is
    /// reserved for the rescue fan.
    budget: Duration,
    state: Mutex<State>,
}

impl Group {
    /// `NewTransport`: an unset `win_ttl` means five minutes, and outside
    /// `fastest` mode it is ignored entirely.
    pub fn new(
        tag: String,
        members: Vec<String>,
        mode: Mode,
        error_ttl: Duration,
        win_ttl: Duration,
        budget: Duration,
    ) -> Arc<Self> {
        let win_ttl = match win_ttl.is_zero() {
            true => DEFAULT_WIN_TTL,
            false if mode != Mode::Fastest => {
                crate::logging::warn(format_args!(
                    "group[{tag}]: win_ttl is only used in fastest mode, ignoring"
                ));
                Duration::ZERO
            }
            false => win_ttl,
        };
        Arc::new(Self {
            tag,
            members,
            mode,
            error_ttl: match error_ttl.is_zero() {
                true => DEFAULT_ERROR_TTL,
                false => error_ttl,
            },
            win_ttl,
            budget,
            state: Mutex::new(State::default()),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// One query, capped by the group's own budget like the reference caps the
    /// exchange by the request context.
    pub async fn exchange(
        self: &Arc<Self>,
        members: Arc<dyn Members>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        // the reference records a failure only while the request budget is
        // alive: a result that arrives after the answer says nothing about the
        // server, it only says the caller is gone
        let live = Arc::new(AtomicBool::new(true));
        let result = tokio::time::timeout(
            self.budget,
            self.exchange_inner(members, query, Arc::clone(&live)),
        )
        .await;
        live.store(false, Ordering::SeqCst);
        match result {
            Ok(result) => result,
            Err(_) => Err(io::Error::other(format!(
                "group[{}]: no answer within {:?}",
                self.tag, self.budget
            ))),
        }
    }

    async fn exchange_inner(
        self: &Arc<Self>,
        members: Arc<dyn Members>,
        query: &[u8],
        live: Arc<AtomicBool>,
    ) -> io::Result<Vec<u8>> {
        match self.select()? {
            Selection::Fan { tags, election } => {
                self.fan(members, query, &tags, election, live).await
            }
            Selection::Survival { tag } => self.survival(members, query, &tag).await,
            Selection::Single { tag, provisional } => {
                self.single(members, query, &tag, provisional, live).await
            }
        }
    }

    /// The routing decision for one query, under the record tables.
    fn select(&self) -> io::Result<Selection> {
        let now = Instant::now();
        let mut state = self.state();
        let clean: Vec<String> = self
            .members
            .iter()
            .filter(|tag| live_errors(&mut state, tag, now, self.error_ttl).is_empty())
            .cloned()
            .collect();
        if clean.is_empty() {
            // no clean member: one attempt through the least dirty one
            return Ok(Selection::Survival {
                tag: least_dirty(&mut state, &self.members, now, self.error_ttl),
            });
        }
        Ok(match self.mode {
            Mode::Parallel => Selection::Fan {
                tags: clean,
                election: false,
            },
            Mode::Fastest => {
                let (best, max_wins) = fastest_candidates(&mut state, &clean, now, self.win_ttl);
                if max_wins > 0 {
                    Selection::Single {
                        tag: sticky_pick(&mut state, &best),
                        provisional: false,
                    }
                } else if !state.election {
                    // nobody has a live win: one query decides, the concurrent
                    // queries of that window go to a random clean member
                    state.election = true;
                    Selection::Fan {
                        tags: clean,
                        election: true,
                    }
                } else {
                    Selection::Single {
                        tag: pick(&clean),
                        provisional: true,
                    }
                }
            }
            Mode::Stable => Selection::Single {
                tag: sticky_pick(&mut state, &clean),
                provisional: false,
            },
        })
    }

    /// The normal path: one exchange with the sticky target under half the
    /// budget — the other half belongs to the rescue fan, so a blackholed
    /// target cannot eat the whole query.
    async fn single(
        self: &Arc<Self>,
        members: Arc<dyn Members>,
        query: &[u8],
        tag: &str,
        provisional: bool,
        live: Arc<AtomicBool>,
    ) -> io::Result<Vec<u8>> {
        // a provisional pick (an election-window concurrent) serves the query
        // but must not move the sticky target
        if !provisional {
            self.set_current(tag);
        }
        let (response, error, _rtt) = self
            .probe(Arc::clone(&members), tag, query, self.budget / 2)
            .await;
        if !is_failure(response.as_deref(), error.as_ref()) {
            self.note_success(tag, _rtt);
            return unwrap_response(response, error, &self.tag);
        }
        self.note_error(tag);
        let rescuers = self.clean_except(tag);
        if rescuers.is_empty() {
            return failure(tag, response, error, &self.tag);
        }
        self.fan(members, query, &rescuers, false, live).await
    }

    /// Survival: no clean member, so exactly one attempt with the full budget —
    /// never a fan, one attempt is the whole price of a query on a dead network.
    async fn survival(
        self: &Arc<Self>,
        members: Arc<dyn Members>,
        query: &[u8],
        tag: &str,
    ) -> io::Result<Vec<u8>> {
        crate::logging::warn(format_args!(
            "group[{}]: no clean servers, survival attempt via {tag}",
            self.tag
        ));
        let (response, error, rtt) = self.probe(members, tag, query, self.budget).await;
        if !is_failure(response.as_deref(), error.as_ref()) {
            // back to clean, so stickiness keeps the healed server
            self.note_success(tag, rtt);
            return unwrap_response(response, error, &self.tag);
        }
        self.note_error(tag);
        failure(tag, response, error, &self.tag)
    }

    /// The fan-out primitive behind the rescue fan, the `fastest` election and
    /// every parallel query. The collector keeps consuming after the winner is
    /// delivered, so a late answer still heals its server.
    async fn fan(
        self: &Arc<Self>,
        members: Arc<dyn Members>,
        query: &[u8],
        tags: &[String],
        election: bool,
        live: Arc<AtomicBool>,
    ) -> io::Result<Vec<u8>> {
        let (results, mut rx) = tokio::sync::mpsc::channel(tags.len().max(1));
        let (winners, mut winner_rx) = tokio::sync::mpsc::channel(1);
        for tag in tags {
            let members = Arc::clone(&members);
            let results = results.clone();
            let query = query.to_vec();
            let tag = tag.clone();
            tokio::spawn(async move {
                let started = Instant::now();
                let result = members.exchange(tag.clone(), query).await;
                let _ = results.send((tag, result, started.elapsed())).await;
            });
        }
        drop(results);
        let group = Arc::clone(self);
        tokio::spawn(async move {
            let mut delivered = false;
            let mut errors: Vec<String> = Vec::new();
            while let Some((tag, result, rtt)) = rx.recv().await {
                let (response, error) = match result {
                    Ok(raw) => (Some(raw), None),
                    Err(error) => (None, Some(error)),
                };
                if is_failure(response.as_deref(), error.as_ref()) {
                    if !live.load(Ordering::SeqCst) {
                        continue;
                    }
                    group.note_error(&tag);
                    errors.push(match error {
                        Some(error) => format!("{tag}: {error}"),
                        None => format!("{tag}: SERVFAIL"),
                    });
                    continue;
                }
                // a late answer is discarded but still heals its server
                group.note_success(&tag, rtt);
                if delivered || !live.load(Ordering::SeqCst) {
                    continue;
                }
                delivered = true;
                if group.mode == Mode::Fastest {
                    group.note_win(&tag);
                }
                if group.mode != Mode::Parallel {
                    group.set_current(&tag);
                }
                let outcome = unwrap_response(response, error, &group.tag);
                let _ = winners.send(outcome).await;
            }
            if election {
                // released here so a fan the caller walked away from cannot
                // leak the single-flight lock
                group.state().election = false;
            }
            if !delivered {
                let _ = winners
                    .send(Err(io::Error::other(if errors.is_empty() {
                        format!("group[{}]: fan yielded no result", group.tag)
                    } else {
                        format!("group[{}]: {}", group.tag, errors.join(", "))
                    })))
                    .await;
            }
        });
        match winner_rx.recv().await {
            Some(result) => result,
            None => Err(io::Error::other(format!(
                "group[{}]: fan yielded no result",
                self.tag
            ))),
        }
    }

    /// One member exchange, timed, with the round trip kept for the snapshot.
    async fn probe(
        &self,
        members: Arc<dyn Members>,
        tag: &str,
        query: &[u8],
        budget: Duration,
    ) -> (Option<Vec<u8>>, Option<io::Error>, Duration) {
        let started = Instant::now();
        let result =
            tokio::time::timeout(budget, members.exchange(tag.to_string(), query.to_vec())).await;
        let rtt = started.elapsed();
        let (response, error) = split(result);
        (response, error, rtt)
    }

    fn clean_except(&self, except: &str) -> Vec<String> {
        let now = Instant::now();
        let mut state = self.state();
        self.members
            .iter()
            .filter(|tag| tag.as_str() != except)
            .filter(|tag| live_errors(&mut state, tag, now, self.error_ttl).is_empty())
            .cloned()
            .collect()
    }

    fn note_error(&self, tag: &str) {
        let mut state = self.state();
        let now = Instant::now();
        let record = state.errors.entry(tag.to_string()).or_default();
        record.push(now);
        if record.len() > MAX_RECORDS {
            let drop_to = record.len() - MAX_RECORDS;
            record.drain(..drop_to);
        }
        // a win must not outlive a failure
        state.wins.remove(tag);
    }

    fn note_success(&self, tag: &str, rtt: Duration) {
        let mut state = self.state();
        state.errors.remove(tag);
        if !rtt.is_zero() {
            state.last_rtt.insert(tag.to_string(), rtt);
        }
    }

    fn note_win(&self, tag: &str) {
        let mut state = self.state();
        let record = state.wins.entry(tag.to_string()).or_default();
        record.push(Instant::now());
        if record.len() > MAX_RECORDS {
            let drop_to = record.len() - MAX_RECORDS;
            record.drain(..drop_to);
        }
    }

    fn set_current(&self, tag: &str) {
        let mut state = self.state();
        let changed = state.current.as_deref() != Some(tag);
        state.current = Some(tag.to_string());
        if changed {
            crate::logging::info(format_args!("group[{}]: current server: {tag}", self.tag));
        }
    }

    /// Per-member health, for tests and for the state RPC that comes with lxd.
    pub fn snapshot(&self) -> Vec<MemberState> {
        let now = Instant::now();
        let mut state = self.state();
        self.members
            .iter()
            .map(|tag| {
                let errors = live_errors(&mut state, tag, now, self.error_ttl).len();
                let wins = live_wins(&mut state, tag, now, self.win_ttl).len();
                MemberState {
                    tag: tag.clone(),
                    clean: errors == 0,
                    live_errors: errors,
                    live_wins: wins,
                    current: state.current.as_deref() == Some(tag.as_str()),
                    last_rtt: state.last_rtt.get(tag).copied(),
                }
            })
            .collect()
    }
}

/// One member's health, as the reference's `MemberState` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    pub tag: String,
    pub clean: bool,
    pub live_errors: usize,
    pub live_wins: usize,
    pub current: bool,
    pub last_rtt: Option<Duration>,
}

enum Selection {
    Single {
        tag: String,
        /// an election-window concurrent: serves the query, keeps the target
        provisional: bool,
    },
    Fan {
        tags: Vec<String>,
        election: bool,
    },
    Survival {
        tag: String,
    },
}

fn split(
    result: Result<io::Result<Vec<u8>>, tokio::time::error::Elapsed>,
) -> (Option<Vec<u8>>, Option<io::Error>) {
    match result {
        Ok(Ok(raw)) => (Some(raw), None),
        Ok(Err(error)) => (None, Some(error)),
        Err(_) => (
            None,
            Some(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
        ),
    }
}

/// A transport error, a timeout and SERVFAIL are failures; NXDOMAIN and an
/// empty answer are valid answers.
fn is_failure(response: Option<&[u8]>, error: Option<&io::Error>) -> bool {
    if error.is_some() {
        return true;
    }
    match response {
        Some(raw) => codec::parse_message(raw)
            .map(|msg| msg.metadata.response_code == ResponseCode::ServFail)
            // an undecodable answer is not an answer
            .unwrap_or(true),
        None => true,
    }
}

fn unwrap_response(
    response: Option<Vec<u8>>,
    error: Option<io::Error>,
    tag: &str,
) -> io::Result<Vec<u8>> {
    match (response, error) {
        (Some(raw), _) => Ok(raw),
        (None, Some(error)) => Err(error),
        (None, None) => Err(io::Error::other(format!("group[{tag}]: no answer"))),
    }
}

fn failure(
    tag: &str,
    response: Option<Vec<u8>>,
    error: Option<io::Error>,
    group: &str,
) -> io::Result<Vec<u8>> {
    // a SERVFAIL is still a response the client can look at
    if let Some(raw) = response {
        return Ok(raw);
    }
    Err(error.unwrap_or_else(|| io::Error::other(format!("group[{group}]: {tag}: no answer"))))
}

/// Prune the expired prefix, reference `pruneTimes`.
fn live(times: &mut Vec<Instant>, ttl: Duration, now: Instant) -> &[Instant] {
    let first_live = times
        .iter()
        .position(|at| now.duration_since(*at) < ttl)
        .unwrap_or(times.len());
    if first_live > 0 {
        times.drain(..first_live);
    }
    times
}

fn live_errors<'a>(state: &'a mut State, tag: &str, now: Instant, ttl: Duration) -> &'a [Instant] {
    match state.errors.get_mut(tag) {
        Some(times) => live(times, ttl, now),
        None => &[],
    }
}

fn live_wins<'a>(state: &'a mut State, tag: &str, now: Instant, ttl: Duration) -> &'a [Instant] {
    match state.wins.get_mut(tag) {
        Some(times) => live(times, ttl, now),
        None => &[],
    }
}

/// «stickiness before randomness»: keep the current target while it is still a
/// candidate, re-elect at random otherwise.
fn sticky_pick(state: &mut State, candidates: &[String]) -> String {
    if let Some(current) = &state.current
        && let Some(hit) = candidates.iter().find(|tag| *tag == current)
    {
        return hit.clone();
    }
    pick(candidates)
}

/// The clean members with the most live wins, and that maximum.
fn fastest_candidates(
    state: &mut State,
    clean: &[String],
    now: Instant,
    ttl: Duration,
) -> (Vec<String>, usize) {
    let mut best: Vec<String> = Vec::new();
    let mut max_wins = 0usize;
    for tag in clean {
        let wins = live_wins(state, tag, now, ttl).len();
        if wins > max_wins {
            max_wins = wins;
            best.clear();
            best.push(tag.clone());
        } else if wins == max_wins {
            best.push(tag.clone());
        }
    }
    (best, max_wins)
}

/// Survival target: fewest live errors, ties broken by the oldest last error,
/// a full tie at random.
fn least_dirty(state: &mut State, members: &[String], now: Instant, ttl: Duration) -> String {
    let mut best: Vec<String> = Vec::new();
    let mut best_count = usize::MAX;
    let mut best_last: Option<Instant> = None;
    for tag in members {
        let errors = live_errors(state, tag, now, ttl);
        let count = errors.len();
        let last = errors.last().copied();
        let better = best_count == usize::MAX
            || count < best_count
            || (count == best_count && last < best_last);
        if better {
            best.clear();
            best.push(tag.clone());
            best_count = count;
            best_last = last;
        } else if count == best_count && last == best_last {
            best.push(tag.clone());
        }
    }
    pick(&best)
}

/// A uniform-enough pick over a handful of members; the reference uses
/// `math/rand/v2`'s `IntN` for the same job.
fn pick(items: &[String]) -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).unwrap_or_default();
    items[(u32::from_le_bytes(bytes) as usize) % items.len()].clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real answer for the mocks to hand out: the group classifies a result
    /// by rcode, so a canned byte string would read as an undecodable answer.
    fn answer_body() -> Vec<u8> {
        let query = codec::parse_message(
            &codec::build_query(1, "a.test", hickory_proto::rr::RecordType::A).expect("query"),
        )
        .expect("query message");
        codec::synth_address(&query, "203.0.113.7".parse().expect("ip"), 60).expect("answer")
    }

    /// A member set that answers with a canned body or a canned failure, and
    /// counts what it was asked for.
    struct Mock {
        answer: Option<Vec<u8>>,
        delay: Duration,
        calls: Mutex<HashMap<String, usize>>,
    }

    impl Mock {
        fn answering() -> Arc<Self> {
            Arc::new(Self {
                answer: Some(answer_body()),
                delay: Duration::ZERO,
                calls: Mutex::new(HashMap::new()),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                answer: None,
                delay: Duration::ZERO,
                calls: Mutex::new(HashMap::new()),
            })
        }

        fn slow() -> Arc<Self> {
            Arc::new(Self {
                answer: Some(answer_body()),
                delay: Duration::from_millis(200),
                calls: Mutex::new(HashMap::new()),
            })
        }

        fn calls(&self, tag: &str) -> usize {
            self.calls
                .lock()
                .expect("calls")
                .get(tag)
                .copied()
                .unwrap_or(0)
        }
    }

    impl Members for Mock {
        fn exchange(
            self: Arc<Self>,
            tag: String,
            _query: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>> {
            Box::pin(async move {
                *self
                    .calls
                    .lock()
                    .expect("calls")
                    .entry(tag.clone())
                    .or_default() += 1;
                tokio::time::sleep(self.delay).await;
                match &self.answer {
                    Some(body) => Ok(body.clone()),
                    None => Err(io::Error::other("connection refused")),
                }
            })
        }
    }

    /// A SERVFAIL response, which is the one rcode a member must not answer with.
    fn servfail() -> Vec<u8> {
        let mut msg = codec::parse_message(
            &codec::build_query(1, "a.test", hickory_proto::rr::RecordType::A).expect("query"),
        )
        .expect("query message");
        msg.metadata.message_type = hickory_proto::op::MessageType::Response;
        msg.metadata.response_code = ResponseCode::ServFail;
        msg.to_vec().expect("servfail")
    }

    fn nxdomain() -> Vec<u8> {
        let query = codec::parse_message(
            &codec::build_query(1, "a.test", hickory_proto::rr::RecordType::A).expect("query"),
        )
        .expect("query message");
        codec::name_error(&query).expect("nxdomain")
    }

    fn group(mode: Mode, members: &[&str], error_ttl: Duration) -> Arc<Group> {
        group_with(mode, members, error_ttl, Duration::from_secs(2))
    }

    fn group_with(
        mode: Mode,
        members: &[&str],
        error_ttl: Duration,
        budget: Duration,
    ) -> Arc<Group> {
        Group::new(
            "g".to_string(),
            members.iter().map(|tag| tag.to_string()).collect(),
            mode,
            error_ttl,
            Duration::ZERO,
            budget,
        )
    }

    #[tokio::test]
    async fn stable_sticks_to_one_member() {
        let mock = Mock::answering();
        let members: Arc<dyn Members> = mock.clone();
        let group = group(Mode::Stable, &["a", "b"], Duration::from_secs(60));
        for _ in 0..3 {
            let answer = group
                .exchange(Arc::clone(&members), b"q")
                .await
                .expect("answer");
            assert_eq!(answer, answer_body());
        }
        // whichever member won the first pick, it served every query alone
        let (a_calls, b_calls) = (mock.calls("a"), mock.calls("b"));
        let (target, other) = match (a_calls, b_calls) {
            (3, 0) => ("a", "b"),
            (0, 3) => ("b", "a"),
            other => panic!("one member must serve every query, got {other:?}"),
        };
        let state = group.snapshot();
        assert!(state.iter().any(|m| m.current && m.tag == target));
        assert!(
            state
                .iter()
                .any(|m| !m.current && m.tag == other && m.clean),
            "the untouched member stays clean"
        );
    }

    #[tokio::test]
    async fn a_failed_target_is_rescued_by_a_fan() {
        let mock = Mock::answering();
        // "a" fails, "b" answers: the group must still return b's answer
        let members: Arc<dyn Members> = Arc::new(Flaky {
            failing: "a".to_string(),
            inner: Arc::clone(&mock),
        });
        let group = group(Mode::Stable, &["a", "b"], Duration::from_secs(60));
        // pin the target so the rescue path is the one under test
        group.set_current("a");
        let answer = group.exchange(members, b"q").await.expect("answer");
        assert_eq!(answer, answer_body());
        let state = group.snapshot();
        let a = state.iter().find(|m| m.tag == "a").expect("a");
        assert_eq!(a.live_errors, 1, "the failed target is dirty");
        let b = state.iter().find(|m| m.tag == "b").expect("b");
        assert!(b.clean, "the rescuer stays clean");
        // the rescuer takes over as the sticky target
        assert!(b.current, "the answer's member becomes the target");
    }

    /// Wraps a mock so one named member always fails.
    struct Flaky {
        failing: String,
        inner: Arc<Mock>,
    }

    impl Members for Flaky {
        fn exchange(
            self: Arc<Self>,
            tag: String,
            query: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>> {
            let failing = tag == self.failing;
            let inner = Arc::clone(&self.inner);
            Box::pin(async move {
                if failing {
                    return Err(io::Error::other("connection refused"));
                }
                Arc::clone(&inner).exchange(tag, query).await
            })
        }
    }

    #[tokio::test]
    async fn a_dead_group_survives_on_one_attempt() {
        let members: Arc<dyn Members> = Mock::failing();
        let group = group(Mode::Parallel, &["a", "b", "c"], Duration::from_secs(60));
        // nothing ever succeeds, so every member is dirty after the first query
        assert!(group.exchange(Arc::clone(&members), b"q").await.is_err());
        let state = group.snapshot();
        assert!(
            state.iter().all(|m| !m.clean),
            "every member carries an error record"
        );
        // survival: one attempt, and the query still fails rather than hanging
        assert!(group.exchange(Arc::clone(&members), b"q").await.is_err());
    }

    #[tokio::test]
    async fn parallel_answers_from_a_live_member() {
        let mock = Mock::answering();
        let members: Arc<dyn Members> = Arc::new(Flaky {
            failing: "a".to_string(),
            inner: Arc::clone(&mock),
        });
        let group = group(Mode::Parallel, &["a", "b"], Duration::from_secs(60));
        let answer = group.exchange(members, b"q").await.expect("answer");
        assert_eq!(answer, answer_body());
        let state = group.snapshot();
        assert!(
            state.iter().all(|m| !m.current),
            "parallel mode has no sticky target"
        );
    }

    #[tokio::test]
    async fn fastest_elects_once_and_then_keeps_the_winner() {
        let mock = Mock::answering();
        let members: Arc<dyn Members> = mock.clone();
        let group = group(Mode::Fastest, &["a", "b"], Duration::from_secs(60));
        group
            .exchange(Arc::clone(&members), b"q")
            .await
            .expect("election");
        let winner = group
            .snapshot()
            .into_iter()
            .find(|m| m.live_wins > 0)
            .expect("a win record");
        // the win sticks: the next query is a single exchange with that member
        let before = mock.calls(&winner.tag);
        group
            .exchange(Arc::clone(&members), b"q")
            .await
            .expect("answer");
        assert_eq!(
            mock.calls(&winner.tag),
            before + 1,
            "the winner serves the next query alone"
        );
    }

    #[tokio::test]
    async fn errors_expire_and_the_member_is_clean_again() {
        let members: Arc<dyn Members> = Mock::failing();
        let group = group(Mode::Stable, &["a"], Duration::from_millis(30));
        assert!(group.exchange(Arc::clone(&members), b"q").await.is_err());
        assert!(!group.snapshot()[0].clean);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            group.snapshot()[0].clean,
            "the error record expired by error_ttl"
        );
    }

    #[test]
    fn servfail_is_a_failure_and_nxdomain_is_not() {
        // a SERVFAIL response must not look like an answer
        let (response, error) = (Some(servfail()), None);
        assert!(is_failure(response.as_deref(), error.as_ref()));
        // NXDOMAIN is a valid answer
        let (response, error) = (Some(nxdomain()), None);
        assert!(!is_failure(response.as_deref(), error.as_ref()));
    }

    #[tokio::test]
    async fn a_slow_member_cannot_eat_the_whole_budget() {
        let members: Arc<dyn Members> = Mock::slow();
        let group = group_with(
            Mode::Stable,
            &["a"],
            Duration::from_secs(60),
            Duration::from_millis(40),
        );
        let started = Instant::now();
        assert!(group.exchange(Arc::clone(&members), b"q").await.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the group's own budget cuts the exchange short"
        );
    }

    #[test]
    fn the_wire_modes_parse_and_the_rest_do_not() {
        assert_eq!(Mode::parse(""), Some(Mode::Stable));
        assert_eq!(Mode::parse("stable"), Some(Mode::Stable));
        assert_eq!(Mode::parse("fastest"), Some(Mode::Fastest));
        assert_eq!(Mode::parse("parallel"), Some(Mode::Parallel));
        assert_eq!(Mode::parse("failover"), None, "the v1 mode is refused");
    }

    #[test]
    fn error_records_are_capped() {
        let group = group(Mode::Stable, &["a"], Duration::from_secs(60));
        for _ in 0..(MAX_RECORDS + 10) {
            group.note_error("a");
        }
        assert_eq!(group.snapshot()[0].live_errors, MAX_RECORDS);
        // a success erases them, and a win does not survive a later failure
        group.note_success("a", Duration::from_millis(1));
        assert!(group.snapshot()[0].clean);
        group.note_win("a");
        group.note_error("a");
        let state = group.snapshot();
        assert_eq!(state[0].live_wins, 0, "a failure erases the live wins");
    }
}
