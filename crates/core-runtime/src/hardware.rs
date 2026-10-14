use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Host memory classification determined at startup from `/proc/meminfo` and cgroup limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryTier {
    /// <= 128 MiB RAM (legacy routers, tight cgroup containers)
    Constrained,
    /// 129 MiB ..= 512 MiB (typical OpenWrt routers: MT7621, NanoPi R2S/R3S)
    Router,
    /// 513 MiB ..= 2048 MiB (Filogic MT798x, RPi 4, mid-range gateways)
    Midrange,
    /// > 2048 MiB (x86 gateways, mini-PCs, servers, desktops)
    DesktopServer,
}

impl MemoryTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Constrained => "Constrained",
            Self::Router => "Router",
            Self::Midrange => "Midrange",
            Self::DesktopServer => "DesktopServer",
        }
    }
}

/// Static hardware profile computed once at process startup.
/// Manual `TACHYON_*` environment variables always take precedence.
#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub mem_tier: MemoryTier,
    pub total_ram_mb: usize,
    pub workers: usize,
    pub max_blocking_threads: usize,
    pub relay_buf_size: usize,
    pub buf_pool_capacity: usize,
    pub stream_max_buf: usize,
    pub h2_stream_window: u32,
    pub h2_conn_window: u32,
    pub h2_max_send_buf: usize,
    pub splice_pipe_size: usize,
    pub smol_tcp_buf: usize,
}

static MEMORY_PRESSURE: AtomicBool = AtomicBool::new(false);

/// Fast lock-free check used on the hot path to decide whether to return
/// buffers to pools or drop/shrink them immediately.
#[inline]
pub fn is_memory_pressured() -> bool {
    MEMORY_PRESSURE.load(Ordering::Relaxed)
}

/// Sample current process RSS and system `MemAvailable` (on Linux) and update
/// the global `MEMORY_PRESSURE` flag. Returns `true` if under pressure.
pub fn refresh_memory_pressure() -> bool {
    let pressured = detect_memory_pressure(HardwareProfile::detect());
    let prev = MEMORY_PRESSURE.swap(pressured, Ordering::Relaxed);
    if pressured && !prev {
        crate::inbound::clear_global_buf_pool();
    }
    pressured
}

impl HardwareProfile {
    pub fn detect() -> &'static Self {
        static PROFILE: OnceLock<HardwareProfile> = OnceLock::new();
        PROFILE.get_or_init(Self::detect_uncached)
    }

    pub fn from_ram_and_cpus(total_ram_mb: usize, raw_cpus: usize) -> Self {
        let mem_tier = match total_ram_mb {
            0..=128 => MemoryTier::Constrained,
            129..=512 => MemoryTier::Router,
            513..=2048 => MemoryTier::Midrange,
            _ => MemoryTier::DesktopServer,
        };

        let workers = std::env::var("TACHYON_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                let cpus = raw_cpus.max(1);
                match mem_tier {
                    MemoryTier::Constrained if total_ram_mb <= 64 => 1,
                    MemoryTier::Constrained => cpus.min(2),
                    _ => cpus,
                }
            });

        let max_blocking_threads = match mem_tier {
            MemoryTier::Constrained => 4,
            MemoryTier::Router => 8,
            MemoryTier::Midrange => 16,
            MemoryTier::DesktopServer => 16 * workers.max(1),
        };

        let relay_buf_size = std::env::var("TACHYON_RELAY_BUF")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| (4096..=1048576).contains(n))
            .unwrap_or(match mem_tier {
                MemoryTier::Constrained => 16 * 1024,
                MemoryTier::Router => 32 * 1024,
                MemoryTier::Midrange => 64 * 1024,
                MemoryTier::DesktopServer => 128 * 1024,
            });

        let buf_pool_capacity = match mem_tier {
            MemoryTier::Constrained => 16,
            MemoryTier::Router => 32,
            MemoryTier::Midrange => 64,
            MemoryTier::DesktopServer => 128,
        };

        let stream_max_buf = match mem_tier {
            MemoryTier::Constrained => 16 * 1024,
            MemoryTier::Router => 32 * 1024,
            MemoryTier::Midrange => 64 * 1024,
            MemoryTier::DesktopServer => 128 * 1024,
        };

        let (h2_stream_window, h2_conn_window, h2_max_send_buf) = match mem_tier {
            MemoryTier::Constrained => (256 * 1024, 1024 * 1024, 256 * 1024),
            MemoryTier::Router => (512 * 1024, 2 * 1024 * 1024, 512 * 1024),
            MemoryTier::Midrange => (2 * 1024 * 1024, 8 * 1024 * 1024, 1024 * 1024),
            MemoryTier::DesktopServer => (16 * 1024 * 1024, 64 * 1024 * 1024, 4 * 1024 * 1024),
        };

        let splice_pipe_size = match mem_tier {
            MemoryTier::Constrained => 64 * 1024,
            MemoryTier::Router => 128 * 1024,
            MemoryTier::Midrange => 256 * 1024,
            MemoryTier::DesktopServer => 1024 * 1024,
        };

        let smol_tcp_buf = std::env::var("TACHYON_SMOL_TCP_BUF")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|kb| (64..=4096).contains(kb))
            .map(|kb| (kb * 1024).next_power_of_two())
            .unwrap_or(match mem_tier {
                MemoryTier::Constrained => 64 * 1024,
                MemoryTier::Router => 128 * 1024,
                MemoryTier::Midrange | MemoryTier::DesktopServer => 256 * 1024,
            });

        Self {
            mem_tier,
            total_ram_mb,
            workers,
            max_blocking_threads,
            relay_buf_size,
            buf_pool_capacity,
            stream_max_buf,
            h2_stream_window,
            h2_conn_window,
            h2_max_send_buf,
            splice_pipe_size,
            smol_tcp_buf,
        }
    }

    fn detect_uncached() -> Self {
        let total_ram_mb = detect_total_ram_mb();
        let raw_cpus = detect_cpus();
        Self::from_ram_and_cpus(total_ram_mb, raw_cpus)
    }
}

fn detect_total_ram_mb() -> usize {
    #[cfg(target_os = "linux")]
    {
        let mut ram_mb = 256usize;
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    if let Some(kb_str) = rest.split_whitespace().next()
                        && let Ok(kb) = kb_str.parse::<usize>()
                    {
                        ram_mb = (kb / 1024).max(16);
                    }
                    break;
                }
            }
        }
        if let Some(cg_mb) = detect_cgroup_memory_mb() {
            ram_mb = ram_mb.min(cg_mb.max(16));
        }
        ram_mb
    }
    #[cfg(not(target_os = "linux"))]
    {
        4096
    }
}

#[cfg(target_os = "linux")]
fn detect_cgroup_memory_mb() -> Option<usize> {
    for path in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let trimmed = raw.trim();
            if trimmed == "max" {
                continue;
            }
            if let Ok(bytes) = trimmed.parse::<u64>() {
                // Ignore unlimited sentinel values (> 1 TiB)
                if bytes > 0 && bytes < (1u64 << 40) {
                    return Some((bytes / (1024 * 1024)) as usize);
                }
            }
        }
    }
    None
}

fn detect_cpus() -> usize {
    let host_cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    #[cfg(target_os = "linux")]
    {
        if let Some(cg_cpus) = detect_cgroup_cpus() {
            return host_cpus.min(cg_cpus.max(1));
        }
    }
    host_cpus
}

#[cfg(target_os = "linux")]
fn detect_cgroup_cpus() -> Option<usize> {
    if let Ok(raw) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        let mut parts = raw.split_whitespace();
        if let (Some(quota_str), Some(period_str)) = (parts.next(), parts.next())
            && quota_str != "max"
            && let (Ok(quota), Ok(period)) = (quota_str.parse::<u64>(), period_str.parse::<u64>())
            && quota > 0
            && period > 0
        {
            return Some(quota.div_ceil(period) as usize);
        }
    }
    if let (Ok(q_raw), Ok(p_raw)) = (
        std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"),
        std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us"),
    ) && let (Ok(quota), Ok(period)) = (q_raw.trim().parse::<i64>(), p_raw.trim().parse::<i64>())
        && quota > 0
        && period > 0
    {
        return Some(((quota + period - 1) / period) as usize);
    }
    None
}

fn detect_memory_pressure(profile: &HardwareProfile) -> bool {
    #[cfg(target_os = "linux")]
    {
        // 1. Check process RSS via /proc/self/statm (second token is resident pages)
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm")
            && let Some(rss_pages_str) = statm.split_whitespace().nth(1)
            && let Ok(rss_pages) = rss_pages_str.parse::<usize>()
        {
            let rss_mb = (rss_pages * 4) / 1024;
            let rss_limit_mb = match profile.mem_tier {
                MemoryTier::Constrained => 48,
                MemoryTier::Router => 128,
                MemoryTier::Midrange => 512,
                MemoryTier::DesktopServer => (profile.total_ram_mb * 3 / 4).max(1024),
            };
            if rss_mb >= rss_limit_mb {
                return true;
            }
        }
        // 2. On Constrained/Router tiers, also check system-wide MemAvailable
        if matches!(
            profile.mem_tier,
            MemoryTier::Constrained | MemoryTier::Router
        ) && let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo")
        {
            for line in meminfo.lines() {
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    if let Some(kb_str) = rest.split_whitespace().next()
                        && let Ok(kb) = kb_str.parse::<usize>()
                    {
                        let min_avail_kb = match profile.mem_tier {
                            MemoryTier::Constrained => 12 * 1024,
                            _ => 24 * 1024,
                        };
                        if kb < min_avail_kb {
                            return true;
                        }
                    }
                    break;
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_classification_and_scaling() {
        let p64 = HardwareProfile::from_ram_and_cpus(64, 4);
        assert_eq!(p64.mem_tier, MemoryTier::Constrained);
        assert_eq!(p64.buf_pool_capacity, 16);
        assert_eq!(p64.h2_stream_window, 256 * 1024);
        assert_eq!(p64.splice_pipe_size, 64 * 1024);

        let p256 = HardwareProfile::from_ram_and_cpus(256, 2);
        assert_eq!(p256.mem_tier, MemoryTier::Router);
        assert_eq!(p256.buf_pool_capacity, 32);
        assert_eq!(p256.h2_stream_window, 512 * 1024);
        assert_eq!(p256.splice_pipe_size, 128 * 1024);

        let p1024 = HardwareProfile::from_ram_and_cpus(1024, 4);
        assert_eq!(p1024.mem_tier, MemoryTier::Midrange);
        assert_eq!(p1024.buf_pool_capacity, 64);
        assert_eq!(p1024.h2_stream_window, 2 * 1024 * 1024);

        let p8192 = HardwareProfile::from_ram_and_cpus(8192, 8);
        assert_eq!(p8192.mem_tier, MemoryTier::DesktopServer);
        assert_eq!(p8192.buf_pool_capacity, 128);
        assert_eq!(p8192.h2_stream_window, 16 * 1024 * 1024);
        assert_eq!(p8192.splice_pipe_size, 1024 * 1024);
    }
}
