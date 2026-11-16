//! Universal proactive memory pressure monitor, host heap trimmer,
//! internal cache evictor, and safe engine low-memory signal coordinator.

use std::ffi::c_int;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ACTION_HOST_HEAP_TRIM: u32 = 1 << 0;
pub const ACTION_CACHE_TRIM: u32 = 1 << 1;
pub const ACTION_ENGINE_LOW_MEMORY: u32 = 1 << 2;

const MIB: u64 = 1024 * 1024;
const KIB: u64 = 1024;
const MAX_TRIM_CALLBACKS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum PressureLevel {
    None = 0,
    Moderate = 1,
    Low = 2,
    Critical = 3,
}

impl PressureLevel {
    pub fn trim_level_android(self) -> c_int {
        match self {
            PressureLevel::None => 0,
            PressureLevel::Moderate => 5, // TRIM_MEMORY_RUNNING_MODERATE
            PressureLevel::Low => 10,     // TRIM_MEMORY_RUNNING_LOW
            PressureLevel::Critical => 15,// TRIM_MEMORY_RUNNING_CRITICAL
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostMemInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureDecision {
    pub level: PressureLevel,
    pub actions: u32,
}

impl Default for PressureDecision {
    fn default() -> Self {
        Self {
            level: PressureLevel::None,
            actions: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PressureEvaluator {
    pub initialized: bool,
    pub init_ms: u64,
    pub peak_committed_bytes: u64,
    pub last_trimmed_committed_bytes: u64,
    pub last_host_trim_ms: u64,
    pub last_cache_trim_ms: u64,
    pub last_engine_low_mem_ms: u64,
    pub has_host_trimmed: bool,
    pub has_cache_trimmed: bool,
    pub has_engine_trimmed: bool,
    pub last_level: PressureLevel,
    pub forced_once: bool,
}

impl Default for PressureLevel {
    fn default() -> Self {
        PressureLevel::None
    }
}

impl PressureEvaluator {
    pub fn evaluate(
        &mut self,
        now_ms: u64,
        committed_bytes: u64,
        meminfo: Option<HostMemInfo>,
        limit_bytes: u64,
        force_trim: bool,
    ) -> PressureDecision {
        if !self.initialized {
            self.initialized = true;
            self.init_ms = now_ms;
            self.peak_committed_bytes = committed_bytes;
            self.last_trimmed_committed_bytes = committed_bytes;
            self.last_host_trim_ms = now_ms;
            self.last_cache_trim_ms = now_ms;
            self.last_engine_low_mem_ms = now_ms;
            self.last_level = PressureLevel::None;
            return PressureDecision::default();
        }

        if committed_bytes > self.peak_committed_bytes {
            self.peak_committed_bytes = committed_bytes;
        }

        let mut level = PressureLevel::None;

        // 1) Configured hard/soft budget guard (percentage of user limit_bytes).
        if limit_bytes > 0 {
            if committed_bytes >= limit_bytes.saturating_mul(90) / 100 {
                level = level.max(PressureLevel::Critical);
            } else if committed_bytes >= limit_bytes.saturating_mul(78) / 100 {
                level = level.max(PressureLevel::Low);
            } else if committed_bytes >= limit_bytes.saturating_mul(65) / 100 {
                level = level.max(PressureLevel::Moderate);
            }
        }

        // 2) Universal host physical RAM headroom & footprint checks.
        if let Some(info) = meminfo {
            if info.total_bytes > 0 {
                let avail_pct = info.available_bytes.saturating_mul(100) / info.total_bytes;
                let rss_pct = committed_bytes.saturating_mul(100) / info.total_bytes;

                if info.available_bytes < 384 * MIB || avail_pct < 10 || rss_pct >= 72 {
                    level = level.max(PressureLevel::Critical);
                } else if info.available_bytes < 768 * MIB || avail_pct < 18 || rss_pct >= 52 {
                    level = level.max(PressureLevel::Low);
                } else if info.available_bytes < 1280 * MIB || avail_pct < 28 || rss_pct >= 35 {
                    level = level.max(PressureLevel::Moderate);
                }
            }
        }

        // 3) Universal spike & post-exit release heuristics (works even on high-RAM hosts).
        if committed_bytes >= 512 * MIB
            && committed_bytes >= self.last_trimmed_committed_bytes.saturating_add(256 * MIB)
        {
            level = level.max(PressureLevel::Low);
        } else if committed_bytes.saturating_add(64 * MIB) <= self.peak_committed_bytes
            && now_ms.saturating_sub(self.last_host_trim_ms) >= 10_000
        {
            // When RSS recedes (e.g. leaving an experience), nudge glibc arenas back to OS.
            level = level.max(PressureLevel::Moderate);
        }

        // 4) Optional diagnostic/verification one-shot force-trim after short warmup.
        let mut trigger_force = false;
        if force_trim && !self.forced_once && now_ms.saturating_sub(self.init_ms) >= 1_500 {
            self.forced_once = true;
            trigger_force = true;
            level = level.max(PressureLevel::Low);
        }

        let escalated = level > self.last_level && now_ms.saturating_sub(self.last_host_trim_ms) >= 1_000;
        let mut actions = 0u32;

        // Periodic light host heap return even when pressure is Moderate/None above 384 MiB.
        let host_cooldown_ms = match level {
            PressureLevel::Critical => 2_000,
            PressureLevel::Low => 5_000,
            PressureLevel::Moderate => 10_000,
            PressureLevel::None => {
                if committed_bytes >= 384 * MIB {
                    20_000
                } else {
                    u64::MAX
                }
            }
        };

        let host_due = if level >= PressureLevel::Moderate && (!self.has_host_trimmed || escalated) {
            true
        } else {
            now_ms.saturating_sub(self.last_host_trim_ms) >= host_cooldown_ms
        };
        if trigger_force || host_due {
            actions |= ACTION_HOST_HEAP_TRIM;
            self.has_host_trimmed = true;
            self.last_host_trim_ms = now_ms;
            self.last_trimmed_committed_bytes = committed_bytes;
        }

        if level >= PressureLevel::Low {
            let cache_cooldown_ms = if level == PressureLevel::Critical {
                3_000
            } else {
                8_000
            };
            let cache_due = !self.has_cache_trimmed
                || escalated
                || now_ms.saturating_sub(self.last_cache_trim_ms) >= cache_cooldown_ms;
            if trigger_force || cache_due {
                actions |= ACTION_CACHE_TRIM;
                self.has_cache_trimmed = true;
                self.last_cache_trim_ms = now_ms;
            }

            let engine_cooldown_ms = if level == PressureLevel::Critical {
                8_000
            } else {
                20_000
            };
            let engine_due = !self.has_engine_trimmed
                || escalated
                || now_ms.saturating_sub(self.last_engine_low_mem_ms) >= engine_cooldown_ms;
            if trigger_force || engine_due {
                actions |= ACTION_ENGINE_LOW_MEMORY;
                self.has_engine_trimmed = true;
                self.last_engine_low_mem_ms = now_ms;
            }
        }

        self.last_level = level;
        if actions != 0 {
            self.peak_committed_bytes = self.peak_committed_bytes.min(committed_bytes.saturating_add(32 * MIB)).max(committed_bytes);
        }

        PressureDecision { level, actions }
    }
}

pub fn parse_meminfo(content: &str) -> Option<HostMemInfo> {
    let mut mem_total: Option<u64> = None;
    let mut mem_avail: Option<u64> = None;
    let mut mem_free: u64 = 0;
    let mut buffers: u64 = 0;
    let mut cached: u64 = 0;
    let mut swap_total: u64 = 0;
    let mut swap_free: u64 = 0;

    for line in content.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        let Some(val_str) = tokens.next() else {
            continue;
        };
        let Ok(kib) = val_str.parse::<u64>() else {
            continue;
        };
        let bytes = kib.saturating_mul(KIB);
        match key {
            "MemTotal" => mem_total = Some(bytes),
            "MemAvailable" => mem_avail = Some(bytes),
            "MemFree" => mem_free = bytes,
            "Buffers" => buffers = bytes,
            "Cached" => cached = bytes,
            "SwapTotal" => swap_total = bytes,
            "SwapFree" => swap_free = bytes,
            _ => {}
        }
    }

    let total_bytes = mem_total?;
    let available_bytes = mem_avail.unwrap_or_else(|| {
        mem_free.saturating_add(buffers).saturating_add(cached).min(total_bytes)
    });

    Some(HostMemInfo {
        total_bytes,
        available_bytes,
        swap_total_bytes: swap_total,
        swap_free_bytes: swap_free,
    })
}

fn read_host_meminfo() -> Option<HostMemInfo> {
    #[cfg(target_os = "linux")]
    {
        let content = fs::read_to_string("/proc/meminfo").ok()?;
        parse_meminfo(&content)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn monotonic_or_epoch_ms() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
            return (ts.tv_sec as u64)
                .saturating_mul(1_000)
                .saturating_add((ts.tv_nsec as u64) / 1_000_000);
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn env_flag_enabled(name: &str, default_value: bool) -> bool {
    match std::env::var(name) {
        Ok(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                default_value
            } else {
                trimmed != "0"
                    && !trimmed.eq_ignore_ascii_case("false")
                    && !trimmed.eq_ignore_ascii_case("off")
            }
        }
        Err(_) => default_value,
    }
}

fn trim_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| env_flag_enabled("MOCKTAIL_MEMORY_TRIM", true))
}

fn low_mem_callback_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| env_flag_enabled("MOCKTAIL_LOW_MEMORY_CALLBACK", true))
}

fn stats_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| env_flag_enabled("MOCKTAIL_MEMORY_STATS", false))
}

fn force_trim_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| env_flag_enabled("MOCKTAIL_MEMORY_FORCE_TRIM", false))
}

pub type MocktailRustMemoryTrimFn = extern "C" fn(c_int);

struct MemoryStats {
    polls: AtomicU64,
    pressure_moderate: AtomicU64,
    pressure_low: AtomicU64,
    pressure_critical: AtomicU64,
    malloc_trims: AtomicU64,
    cache_trims: AtomicU64,
    engine_low_mem_queued: AtomicU64,
    engine_low_mem_invoked: AtomicU64,
    reclaimed_bytes: AtomicU64,
    peak_rss_bytes: AtomicU64,
    last_rss_bytes: AtomicU64,
    last_avail_bytes: AtomicU64,
}

impl MemoryStats {
    const fn new() -> Self {
        Self {
            polls: AtomicU64::new(0),
            pressure_moderate: AtomicU64::new(0),
            pressure_low: AtomicU64::new(0),
            pressure_critical: AtomicU64::new(0),
            malloc_trims: AtomicU64::new(0),
            cache_trims: AtomicU64::new(0),
            engine_low_mem_queued: AtomicU64::new(0),
            engine_low_mem_invoked: AtomicU64::new(0),
            reclaimed_bytes: AtomicU64::new(0),
            peak_rss_bytes: AtomicU64::new(0),
            last_rss_bytes: AtomicU64::new(0),
            last_avail_bytes: AtomicU64::new(0),
        }
    }
}

static STATS: MemoryStats = MemoryStats::new();
static EVALUATOR: OnceLock<Mutex<PressureEvaluator>> = OnceLock::new();
static TRIM_CALLBACKS: OnceLock<Mutex<[Option<MocktailRustMemoryTrimFn>; MAX_TRIM_CALLBACKS]>> =
    OnceLock::new();
static PENDING_ENGINE_LOW_MEMORY: AtomicBool = AtomicBool::new(false);
static ENGINE_LOW_MEMORY_DISABLED: AtomicBool = AtomicBool::new(false);

fn evaluator() -> &'static Mutex<PressureEvaluator> {
    EVALUATOR.get_or_init(|| Mutex::new(PressureEvaluator::default()))
}

fn trim_callbacks() -> &'static Mutex<[Option<MocktailRustMemoryTrimFn>; MAX_TRIM_CALLBACKS]> {
    TRIM_CALLBACKS.get_or_init(|| Mutex::new([None; MAX_TRIM_CALLBACKS]))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn perform_host_malloc_trim() -> bool {
    extern "C" {
        fn malloc_trim(pad: usize) -> c_int;
    }
    unsafe { malloc_trim(0) != 0 }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn perform_host_malloc_trim() -> bool {
    false
}

fn invoke_registered_cache_trims(level: PressureLevel) {
    let callbacks: [Option<MocktailRustMemoryTrimFn>; MAX_TRIM_CALLBACKS] = {
        let guard = trim_callbacks().lock().unwrap_or_else(|e| e.into_inner());
        *guard
    };
    let android_level = level.trim_level_android();
    let mut ran = 0u64;
    for cb in callbacks.into_iter().flatten() {
        cb(android_level);
        ran += 1;
    }
    if ran > 0 {
        STATS.cache_trims.fetch_add(ran, Ordering::Relaxed);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_register_trim_callback(
    cb: Option<MocktailRustMemoryTrimFn>,
) -> c_int {
    let Some(func) = cb else {
        return -1;
    };
    let addr = func as usize;
    let mut guard = trim_callbacks().lock().unwrap_or_else(|e| e.into_inner());
    for slot in guard.iter() {
        if let Some(existing) = slot {
            if (*existing as usize) == addr {
                return 0;
            }
        }
    }
    for slot in guard.iter_mut() {
        if slot.is_none() {
            *slot = Some(func);
            return 0;
        }
    }
    -2
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_poll_and_trim(limit_bytes: u64) -> c_int {
    if !trim_enabled() {
        return 0;
    }

    let mut rss = 0u64;
    let mut swap = 0u64;
    if crate::mocktail_rust_read_self_memory(&mut rss, &mut swap) != 1 {
        return 0;
    }
    let committed = rss.saturating_add(swap);
    let meminfo = read_host_meminfo();
    let now_ms = monotonic_or_epoch_ms();

    if stats_enabled() {
        STATS.polls.fetch_add(1, Ordering::Relaxed);
        STATS.last_rss_bytes.store(rss, Ordering::Relaxed);
        let mut peak = STATS.peak_rss_bytes.load(Ordering::Relaxed);
        while rss > peak {
            match STATS.peak_rss_bytes.compare_exchange_weak(
                peak,
                rss,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(cur) => peak = cur,
            }
        }
        if let Some(info) = meminfo {
            STATS.last_avail_bytes.store(info.available_bytes, Ordering::Relaxed);
        }
    }

    let decision = {
        let mut guard = evaluator().lock().unwrap_or_else(|e| e.into_inner());
        guard.evaluate(now_ms, committed, meminfo, limit_bytes, force_trim_enabled())
    };

    if stats_enabled() {
        match decision.level {
            PressureLevel::None => {}
            PressureLevel::Moderate => {
                STATS.pressure_moderate.fetch_add(1, Ordering::Relaxed);
            }
            PressureLevel::Low => {
                STATS.pressure_low.fetch_add(1, Ordering::Relaxed);
            }
            PressureLevel::Critical => {
                STATS.pressure_critical.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if decision.actions == 0 {
        return 0;
    }

    let track_reclaim = (decision.actions & (ACTION_HOST_HEAP_TRIM | ACTION_CACHE_TRIM)) != 0;

    if (decision.actions & ACTION_CACHE_TRIM) != 0 {
        invoke_registered_cache_trims(decision.level);
    }

    if (decision.actions & ACTION_HOST_HEAP_TRIM) != 0 {
        let _ = perform_host_malloc_trim();
        STATS.malloc_trims.fetch_add(1, Ordering::Relaxed);
    }

    if track_reclaim && stats_enabled() {
        let mut after_rss = 0u64;
        let mut after_swap = 0u64;
        if crate::mocktail_rust_read_self_memory(&mut after_rss, &mut after_swap) == 1 {
            STATS.last_rss_bytes.store(after_rss, Ordering::Relaxed);
            if after_rss < rss {
                STATS
                    .reclaimed_bytes
                    .fetch_add(rss - after_rss, Ordering::Relaxed);
            }
        }
    }

    if (decision.actions & ACTION_ENGINE_LOW_MEMORY) != 0
        && low_mem_callback_enabled()
        && !ENGINE_LOW_MEMORY_DISABLED.load(Ordering::Acquire)
    {
        if !PENDING_ENGINE_LOW_MEMORY.swap(true, Ordering::AcqRel) {
            STATS.engine_low_mem_queued.fetch_add(1, Ordering::Relaxed);
        }
    }

    decision.level as c_int
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_consume_engine_low_memory() -> c_int {
    if ENGINE_LOW_MEMORY_DISABLED.load(Ordering::Relaxed)
        || !PENDING_ENGINE_LOW_MEMORY.load(Ordering::Relaxed)
    {
        return 0;
    }
    if PENDING_ENGINE_LOW_MEMORY.swap(false, Ordering::AcqRel) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_note_engine_low_memory_invoked() {
    STATS.engine_low_mem_invoked.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_disable_engine_low_memory() {
    ENGINE_LOW_MEMORY_DISABLED.store(true, Ordering::Release);
    PENDING_ENGINE_LOW_MEMORY.store(false, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_dump_stats() {
    if !stats_enabled() {
        return;
    }
    let mut rss = 0u64;
    let mut swap = 0u64;
    let _ = crate::mocktail_rust_read_self_memory(&mut rss, &mut swap);
    let last_rss = rss.max(STATS.last_rss_bytes.load(Ordering::Relaxed));
    let avail = read_host_meminfo()
        .map(|i| i.available_bytes)
        .unwrap_or_else(|| STATS.last_avail_bytes.load(Ordering::Relaxed));

    eprintln!(
        "  [memory] trim={} low_mem_cb={} peak_rss={}MiB last_rss={}MiB host_avail={}MiB polls={} pressure(mod={} low={} crit={}) malloc_trims={} cache_trims={} engine_low_mem(queued={} invoked={}) reclaimed={}KiB",
        if trim_enabled() { "on" } else { "off" },
        if low_mem_callback_enabled() && !ENGINE_LOW_MEMORY_DISABLED.load(Ordering::Relaxed) {
            "on"
        } else {
            "off"
        },
        STATS.peak_rss_bytes.load(Ordering::Relaxed) / MIB,
        last_rss / MIB,
        avail / MIB,
        STATS.polls.load(Ordering::Relaxed),
        STATS.pressure_moderate.load(Ordering::Relaxed),
        STATS.pressure_low.load(Ordering::Relaxed),
        STATS.pressure_critical.load(Ordering::Relaxed),
        STATS.malloc_trims.load(Ordering::Relaxed),
        STATS.cache_trims.load(Ordering::Relaxed),
        STATS.engine_low_mem_queued.load(Ordering::Relaxed),
        STATS.engine_low_mem_invoked.load(Ordering::Relaxed),
        STATS.reclaimed_bytes.load(Ordering::Relaxed) / KIB,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo_with_available_and_fallback() {
        let modern = "\
MemTotal:        8000000 kB
MemFree:          500000 kB
MemAvailable:    3200000 kB
Buffers:          100000 kB
Cached:          2000000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
";
        let info = parse_meminfo(modern).unwrap();
        assert_eq!(info.total_bytes, 8_000_000 * KIB);
        assert_eq!(info.available_bytes, 3_200_000 * KIB);
        assert_eq!(info.swap_total_bytes, 2_000_000 * KIB);
        assert_eq!(info.swap_free_bytes, 1_500_000 * KIB);

        let legacy = "\
MemTotal:        4000000 kB
MemFree:          300000 kB
Buffers:          200000 kB
Cached:           500000 kB
";
        let info_legacy = parse_meminfo(legacy).unwrap();
        assert_eq!(info_legacy.available_bytes, 1_000_000 * KIB);
    }

    #[test]
    fn evaluator_detects_pressure_levels_spikes_and_cooldowns_universally() {
        let mut eval = PressureEvaluator::default();
        let host_8g = HostMemInfo {
            total_bytes: 8 * 1024 * MIB,
            available_bytes: 5 * 1024 * MIB,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };

        // First sample initializes baselines cleanly without trimming.
        let d0 = eval.evaluate(1_000, 300 * MIB, Some(host_8g), 0, false);
        assert_eq!(d0.level, PressureLevel::None);
        assert_eq!(d0.actions, 0);

        // Large memory spike (+300 MiB over baseline above 512 MiB) triggers Low trim + engine signal.
        let d1 = eval.evaluate(2_000, 620 * MIB, Some(host_8g), 0, false);
        assert_eq!(d1.level, PressureLevel::Low);
        assert_ne!(d1.actions & ACTION_HOST_HEAP_TRIM, 0);
        assert_ne!(d1.actions & ACTION_CACHE_TRIM, 0);
        assert_ne!(d1.actions & ACTION_ENGINE_LOW_MEMORY, 0);

        // Immediate follow-up inside cooldown stays suppressed cleanly.
        let d2 = eval.evaluate(2_500, 630 * MIB, Some(host_8g), 0, false);
        assert_eq!(d2.actions, 0);

        // Host low available RAM (< 10%) escalates to Critical on any hardware size.
        let tight_host = HostMemInfo {
            total_bytes: 16 * 1024 * MIB,
            available_bytes: 1_200 * MIB, // ~7.3%
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };
        let d3 = eval.evaluate(12_000, 2_048 * MIB, Some(tight_host), 0, false);
        assert_eq!(d3.level, PressureLevel::Critical);
        assert_ne!(d3.actions & ACTION_HOST_HEAP_TRIM, 0);
        assert_ne!(d3.actions & ACTION_CACHE_TRIM, 0);
        assert_ne!(d3.actions & ACTION_ENGINE_LOW_MEMORY, 0);
    }

    #[test]
    fn evaluator_honors_explicit_memory_limit_percentages_before_oom() {
        let mut eval = PressureEvaluator::default();
        let roomy_host = HostMemInfo {
            total_bytes: 32 * 1024 * MIB,
            available_bytes: 24 * 1024 * MIB,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };
        let limit = 1_000 * MIB;

        assert_eq!(eval.evaluate(1_000, 400 * MIB, Some(roomy_host), limit, false).level, PressureLevel::None);
        // 80% of 1000 MiB -> Low, schedules host+cache+engine trim before 100% hard kill!
        let d = eval.evaluate(2_000, 800 * MIB, Some(roomy_host), limit, false);
        assert_eq!(d.level, PressureLevel::Low);
        assert_ne!(d.actions & ACTION_ENGINE_LOW_MEMORY, 0);
    }
}
