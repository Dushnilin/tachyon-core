use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use portable_atomic::AtomicU64;

use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// `Level::Disabled` marker: `set_disabled` stores 255.
const LEVEL_DISABLED: u8 = u8::MAX;

impl Level {
    pub fn parse(raw: &str) -> Option<Level> {
        match raw {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" | "fatal" => Some(Level::Error),
            _ => None,
        }
    }

    /// clash `/logs` level names are lower case.
    pub fn level_name(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warning",
            Level::Error => "error",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// Where log lines go after the level filter (reference `option.LogOptions.Output`).
enum Sink {
    Stderr,
    Stdout,
    /// File path from `log.output`; console gets nothing (reference
    /// `log.New` sets `logWriter = io.Discard` for non-stream outputs).
    File(Mutex<File>),
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static START: OnceLock<Instant> = OnceLock::new();
static SINK: OnceLock<Sink> = OnceLock::new();
static TIMESTAMP: AtomicU8 = AtomicU8::new(0);

/// Recent lines kept in memory for `GET /logs` (reference `log_buffer`).
const RING_CAPACITY: usize = 1024;
static RING: OnceLock<Mutex<VecDeque<(Level, String)>>> = OnceLock::new();
/// `(level, message)` feed for one `/logs` subscriber. Bounded: a reader that
/// stopped draining its socket cannot make the process grow without limit —
/// lines are dropped for it instead (`TrySendError::Full` keeps the id).
const SUBSCRIBER_CAPACITY: usize = 512;
type Subscriber = mpsc::Sender<(Level, String)>;
static SUBSCRIBERS: OnceLock<Mutex<HashMap<u64, Subscriber>>> = OnceLock::new();
static NEXT_SUBSCRIBER: AtomicU64 = AtomicU64::new(1);

fn ring() -> &'static Mutex<VecDeque<(Level, String)>> {
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(RING_CAPACITY)))
}

fn subscribers() -> &'static Mutex<HashMap<u64, Subscriber>> {
    SUBSCRIBERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Buffered lines at or above `level` (oldest first).
pub fn recent(level: Level) -> Vec<String> {
    let Ok(guard) = ring().lock() else {
        return Vec::new();
    };
    guard
        .iter()
        .filter(|(lvl, _)| *lvl >= level)
        .map(|(_, msg)| msg.clone())
        .collect()
}

/// Register a live `/logs` subscriber; drop the id to unsubscribe.
pub fn subscribe() -> (u64, mpsc::Receiver<(Level, String)>) {
    let (tx, rx) = mpsc::channel(SUBSCRIBER_CAPACITY);
    let id = NEXT_SUBSCRIBER.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = subscribers().lock() {
        guard.insert(id, tx);
    }
    (id, rx)
}

pub fn unsubscribe(id: u64) {
    if let Ok(mut guard) = subscribers().lock() {
        guard.remove(&id);
    }
}

/// Current level, `None` while `log.disabled` is in effect.
pub fn level() -> Option<Level> {
    match LEVEL.load(Ordering::Relaxed) {
        LEVEL_DISABLED => None,
        raw => Level::parse(raw_to_name(raw)),
    }
}

fn raw_to_name(raw: u8) -> &'static str {
    match raw {
        0 => "trace",
        1 => "debug",
        3 => "warn",
        4 => "error",
        _ => "info",
    }
}

/// `PATCH /configs {"log-level": "debug"}`; re-enables a disabled logger.
pub fn set_level(raw: &str) -> bool {
    let Some(level) = Level::parse(raw) else {
        return false;
    };
    LEVEL.store(level as u8, Ordering::Relaxed);
    true
}

pub fn set_enabled(enabled: bool) {
    if enabled {
        let raw = LEVEL.load(Ordering::Relaxed);
        if raw == LEVEL_DISABLED {
            LEVEL.store(Level::Info as u8, Ordering::Relaxed);
        }
    } else {
        LEVEL.store(LEVEL_DISABLED, Ordering::Relaxed);
    }
}

/// True when `level` passes the current filter (used by `/logs?level=`).
pub fn passes(level: Level) -> bool {
    enabled(level)
}

/// Configure level / sink / timestamp from the `log` section.
///
/// * `output` — `""`/`"stderr"`/`"stdout"` or a file path.
/// * unknown level returns false (caller must bail like `start()` does).
pub fn init(output: Option<&str>, level: Option<&str>, timestamp: bool) -> bool {
    let parsed = match level {
        None => Some(Level::Info),
        Some(raw) => Level::parse(raw),
    };
    let Some(level) = parsed else {
        return false;
    };
    LEVEL.store(level as u8, Ordering::Relaxed);
    TIMESTAMP.store(u8::from(timestamp), Ordering::Relaxed);
    let _ = SINK.get_or_init(|| match output.unwrap_or("") {
        "" | "stderr" => Sink::Stderr,
        "stdout" => Sink::Stdout,
        path => match OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(path))
        {
            Ok(file) => Sink::File(Mutex::new(file)),
            Err(err) => {
                eprintln!("log.output: open {path}: {err}");
                Sink::Stderr
            }
        },
    });
    true
}

/// Silence every level (`log.disabled: true`); LEVEL=255 fails all compares.
pub fn set_disabled() {
    set_enabled(false);
}

fn enabled(level: Level) -> bool {
    (level as u8) >= LEVEL.load(Ordering::Relaxed)
}

fn emit(level: Level, msg: fmt::Arguments) {
    if !enabled(level) {
        return;
    }
    let text = msg.to_string();
    if let Ok(mut guard) = subscribers().lock()
        && !guard.is_empty()
    {
        guard.retain(|_, tx| match tx.try_send((level, text.clone())) {
            Ok(()) => true,
            // a slow reader misses lines; it never stalls the emitter
            Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        });
    }
    let start = START.get_or_init(Instant::now);
    let stamp = if TIMESTAMP.load(Ordering::Relaxed) == 1 {
        humantime_prefix()
    } else {
        String::new()
    };
    let line = format!(
        "{stamp}{}[{:04}] {}",
        level.as_str(),
        start.elapsed().as_secs(),
        text
    );
    if let Ok(mut guard) = ring().lock() {
        if guard.len() >= RING_CAPACITY {
            guard.pop_front();
        }
        guard.push_back((level, text));
    }
    match SINK.get() {
        Some(Sink::Stderr) => eprintln!("{line}"),
        Some(Sink::Stdout) => println!("{line}"),
        Some(Sink::File(file)) => {
            if let Ok(mut guard) = file.lock()
                && let Err(err) = writeln!(guard, "{line}")
            {
                drop(guard);
                eprintln!("log.output: write: {err}");
            }
        }
        None => eprintln!("{line}"),
    }
}

/// Minimal local-time stamp for `log.timestamp` (wall clock, second precision).
fn humantime_prefix() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 1970-01-01 epoch → civil date (Howard Hinnant's algorithm, UTC only;
    // sing-box uses local zone — documented divergence for F1).
    let days = (now / 86_400) as i64;
    let secs = now % 86_400;
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
    // the trailing space is the separator `emit` puts after the stamp: one
    // allocation instead of a String plus a format! around it
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} +0000 ",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

pub fn trace(msg: fmt::Arguments) {
    emit(Level::Trace, msg);
}

pub fn debug(msg: fmt::Arguments) {
    emit(Level::Debug, msg);
}

pub fn info(msg: fmt::Arguments) {
    emit(Level::Info, msg);
}

pub fn warn(msg: fmt::Arguments) {
    emit(Level::Warn, msg);
}

pub fn error(msg: fmt::Arguments) {
    emit(Level::Error, msg);
}
