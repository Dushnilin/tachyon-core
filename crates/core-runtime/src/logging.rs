use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl Level {
    fn parse(raw: &str) -> Option<Level> {
        match raw {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" => Some(Level::Warn),
            "error" | "fatal" => Some(Level::Error),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static START: OnceLock<Instant> = OnceLock::new();

/// Configure the minimum level; unknown names return false.
pub fn init(level: Option<&str>) -> bool {
    let parsed = match level {
        None => Some(Level::Info),
        Some(raw) => Level::parse(raw),
    };
    match parsed {
        Some(level) => {
            LEVEL.store(level as u8, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

fn enabled(level: Level) -> bool {
    (level as u8) >= LEVEL.load(Ordering::Relaxed)
}

fn emit(level: Level, msg: fmt::Arguments) {
    if !enabled(level) {
        return;
    }
    let start = START.get_or_init(Instant::now);
    eprintln!(
        "{}[{:04}] {}",
        level.as_str(),
        start.elapsed().as_secs(),
        msg
    );
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
