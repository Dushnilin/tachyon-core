//! Feature `allocstat`: a counting allocator wrapped around the system
//! allocator, dumping one line per second to `/tmp/tachyon-allocstat.txt`
//! while `TACHYON_ALLOCSTAT` is set. The bench needs to know where the heap
//! actually sits -- live bytes and objects by size class, plus allocation
//! churn -- which no amount of reading `/proc` says.
//! Counters are plain relaxed atomics on the alloc/free path and are compiled
//! in only under the feature, so the shipped binary pays nothing.

use std::alloc::{GlobalAlloc, Layout};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

const BUCKETS: usize = 40;
/// Everything at or above this is counted by its exact size: the buckets say
/// "the 128k class holds 4 MiB", which is useless when the question is which
/// of the three big buffers that is.
const BIG_MIN: usize = 64 * 1024;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static FREES: AtomicU64 = AtomicU64::new(0);
static LIVE_B: AtomicU64 = AtomicU64::new(0);
static PEAK_B: AtomicU64 = AtomicU64::new(0);
static LIVE_N: [AtomicU64; BUCKETS] = [const { AtomicU64::new(0) }; BUCKETS];
static LIVE_S: [AtomicU64; BUCKETS] = [const { AtomicU64::new(0) }; BUCKETS];
/// size -> (live objects, live bytes) for allocations of `BIG_MIN` and up
static BIG: Mutex<Option<HashMap<usize, (u64, u64)>>> = Mutex::new(None);

fn big(size: usize, grow: bool) {
    if size < BIG_MIN {
        return;
    }
    let Ok(mut guard) = BIG.lock() else {
        return;
    };
    let entry = guard
        .get_or_insert_with(HashMap::new)
        .entry(size)
        .or_insert((0, 0));
    if grow {
        entry.0 += 1;
        entry.1 += size as u64;
    } else {
        entry.0 = entry.0.saturating_sub(1);
        entry.1 = entry.1.saturating_sub(size as u64);
    }
}

fn bucket(size: usize) -> usize {
    ((usize::BITS - 1).saturating_sub(size.leading_zeros()) as usize).min(BUCKETS - 1)
}

fn add(size: usize) {
    ALLOCS.fetch_add(1, Relaxed);
    LIVE_B.fetch_add(size as u64, Relaxed);
    PEAK_B.fetch_max(LIVE_B.load(Relaxed), Relaxed);
    let b = bucket(size);
    LIVE_N[b].fetch_add(1, Relaxed);
    LIVE_S[b].fetch_add(size as u64, Relaxed);
    big(size, true);
}

fn sub(size: usize) {
    FREES.fetch_add(1, Relaxed);
    dec(&LIVE_B, size as u64);
    let b = bucket(size);
    dec(&LIVE_N[b], 1);
    dec(&LIVE_S[b], size as u64);
    big(size, false);
}

fn dec(c: &AtomicU64, by: u64) {
    loop {
        let v = c.load(Relaxed);
        if c.compare_exchange_weak(v, v.saturating_sub(by), Relaxed, Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

pub struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { std::alloc::System.alloc(layout) };
        if !p.is_null() {
            add(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) };
        sub(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { std::alloc::System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            sub(layout.size());
            add(new_size);
        }
        p
    }
}

fn label(b: usize) -> String {
    if b >= 10 {
        format!("{}k", 1u64 << (b - 10))
    } else {
        format!("{}b", 1u64 << b)
    }
}

pub(crate) fn start() {
    if std::env::var_os("TACHYON_ALLOCSTAT").is_none() {
        return;
    }
    std::thread::spawn(|| {
        let started = std::time::Instant::now();
        let mut last = (0u64, 0u64);
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let a = ALLOCS.load(Relaxed);
            let f = FREES.load(Relaxed);
            let mut classes = String::new();
            let mut order: Vec<usize> = (0..BUCKETS)
                .filter(|&b| LIVE_N[b].load(Relaxed) > 0)
                .collect();
            order.sort_by_key(|&b| std::cmp::Reverse(LIVE_S[b].load(Relaxed)));
            for b in order.into_iter().take(14) {
                let n = LIVE_N[b].load(Relaxed);
                let s = LIVE_S[b].load(Relaxed) / 1024;
                classes.push_str(&format!(" {}:{}x{}k", label(b), n, s));
            }
            let mut bigs = String::new();
            if let Ok(guard) = BIG.lock()
                && let Some(map) = guard.as_ref()
            {
                let mut v: Vec<_> = map.iter().filter(|(_, e)| e.0 > 0).collect();
                v.sort_by_key(|(_, e)| std::cmp::Reverse(e.1));
                for (size, (n, b)) in v {
                    bigs.push_str(&format!(" {size}:{n}x{}k", b / 1024));
                }
            }
            let _ = writeln_dump(format!(
                "{} pid={} allocs={} frees={} live={}KiB peak={}KiB cls={} big={}",
                started.elapsed().as_secs(),
                std::process::id(),
                a.saturating_sub(last.0),
                f.saturating_sub(last.1),
                LIVE_B.load(Relaxed) / 1024,
                PEAK_B.load(Relaxed) / 1024,
                classes.trim_start(),
                bigs.trim_start(),
            ));
            last = (a, f);
        }
    });
}

fn writeln_dump(line: String) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/tachyon-allocstat.txt")?;
    writeln!(f, "{line}")
}
