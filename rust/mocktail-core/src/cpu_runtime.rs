//! Universal CPU topology discovery, role-based thread scheduling policy,
//! timer slack tuning, and Rust Bionic synchronization/sysconf/prctl runtime.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void, CStr};
use std::fs;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

// ============================================================================
// Telemetry & Feature Toggles
// ============================================================================

#[derive(Default)]
pub struct CpuRuntimeStats {
    pub threads_named: AtomicU64,
    pub role_critical: AtomicU64,
    pub role_worker: AtomicU64,
    pub role_io: AtomicU64,
    pub role_audio: AtomicU64,
    pub affinity_applied: AtomicU64,
    pub nice_applied: AtomicU64,
    pub sched_yields: AtomicU64,
    pub nanosleeps: AtomicU64,
    pub futex_waits: AtomicU64,
    pub rwlock_ops: AtomicU64,
    pub rwlock_wakes: AtomicU64,
    pub rwlock_wakes_skipped: AtomicU64,
    pub sem_ops: AtomicU64,
}

static STATS: CpuRuntimeStats = CpuRuntimeStats::new();

impl CpuRuntimeStats {
    const fn new() -> Self {
        Self {
            threads_named: AtomicU64::new(0),
            role_critical: AtomicU64::new(0),
            role_worker: AtomicU64::new(0),
            role_io: AtomicU64::new(0),
            role_audio: AtomicU64::new(0),
            affinity_applied: AtomicU64::new(0),
            nice_applied: AtomicU64::new(0),
            sched_yields: AtomicU64::new(0),
            nanosleeps: AtomicU64::new(0),
            futex_waits: AtomicU64::new(0),
            rwlock_ops: AtomicU64::new(0),
            rwlock_wakes: AtomicU64::new(0),
            rwlock_wakes_skipped: AtomicU64::new(0),
            sem_ops: AtomicU64::new(0),
        }
    }
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

fn stats_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| env_flag_enabled("MOCKTAIL_CPU_STATS", false))
}

fn cpu_policy_enabled() -> bool {
    env_flag_enabled("MOCKTAIL_CPU_POLICY", true)
}

fn l3_locality_enabled() -> bool {
    env_flag_enabled("MOCKTAIL_CPU_L3_LOCALITY", true)
}

fn bg_ecore_enabled() -> bool {
    env_flag_enabled("MOCKTAIL_CPU_BG_ON_ECORE", true)
}

// ============================================================================
// Universal CPU Topology Discovery
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyKind {
    Homogeneous,
    HybridPerfAndEff,
    MultiLlcClusters,
}

impl TopologyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TopologyKind::Homogeneous => "homogeneous",
            TopologyKind::HybridPerfAndEff => "hybrid-p-e",
            TopologyKind::MultiLlcClusters => "multi-llc",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CpuTopology {
    pub kind: TopologyKind,
    pub allowed_logical: Vec<usize>,
    pub physical_cores: usize,
    pub p_cores_logical: Vec<usize>,
    pub e_cores_logical: Vec<usize>,
    pub llc_clusters: Vec<Vec<usize>>,
}

impl CpuTopology {
    pub fn from_inputs(
        allowed_logical: Vec<usize>,
        physical_core_pairs: &[(i32, i32)],
        explicit_perf_cpus: Option<&[usize]>,
        perf_scores: &HashMap<usize, u64>,
        llc_lists: &[Vec<usize>],
    ) -> Self {
        let mut allowed = allowed_logical;
        allowed.sort_unstable();
        allowed.dedup();
        if allowed.is_empty() {
            let fallback = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            allowed = (0..fallback).collect();
        }
        let allowed_set: HashSet<usize> = allowed.iter().copied().collect();

        let unique_phys: HashSet<(i32, i32)> = physical_core_pairs.iter().copied().collect();
        let physical_cores = if unique_phys.is_empty() {
            allowed.len().max(1)
        } else {
            unique_phys.len()
        };

        // 1. Detect hybrid P-core / E-core layouts universally (sysfs cpu_core or perf ratio).
        let (p_cores_logical, e_cores_logical) =
            classify_hybrid_cores(&allowed, explicit_perf_cpus, perf_scores);

        // 2. Deduplicate shared LLC (L3 / last-level cache) clusters intersecting allowed CPUs.
        let mut seen_cluster_keys = HashSet::new();
        let mut llc_clusters: Vec<Vec<usize>> = Vec::new();
        for raw_cluster in llc_lists {
            let mut filtered: Vec<usize> = raw_cluster
                .iter()
                .copied()
                .filter(|id| allowed_set.contains(id))
                .collect();
            filtered.sort_unstable();
            filtered.dedup();
            if !filtered.is_empty() && seen_cluster_keys.insert(filtered.clone()) {
                llc_clusters.push(filtered);
            }
        }
        llc_clusters.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a[0].cmp(&b[0])));

        let kind = if !p_cores_logical.is_empty() && !e_cores_logical.is_empty() {
            TopologyKind::HybridPerfAndEff
        } else if llc_clusters.len() > 1 {
            TopologyKind::MultiLlcClusters
        } else {
            TopologyKind::Homogeneous
        };

        Self {
            kind,
            allowed_logical: allowed,
            physical_cores,
            p_cores_logical,
            e_cores_logical,
            llc_clusters,
        }
    }

    pub fn detect_host() -> Self {
        let allowed = read_host_allowed_cpus();
        let mut phys_pairs = Vec::new();
        let mut perf_scores = HashMap::new();
        let mut llc_lists = Vec::new();

        for &cpu in &allowed {
            let base = format!("/sys/devices/system/cpu/cpu{cpu}");
            if let (Some(pkg), Some(core)) = (
                read_trimmed_i32(&format!("{base}/topology/physical_package_id")),
                read_trimmed_i32(&format!("{base}/topology/core_id")),
            ) {
                phys_pairs.push((pkg, core));
            }
            if let Some(perf) = read_trimmed_u64(&format!("{base}/acpi_cppc/highest_perf"))
                .or_else(|| read_trimmed_u64(&format!("{base}/cpufreq/cpuinfo_max_freq")))
            {
                if perf > 0 {
                    perf_scores.insert(cpu, perf);
                }
            }
            if let Some(shared) = read_llc_shared_list(&base) {
                llc_lists.push(shared);
            }
        }

        let explicit_perf = fs::read_to_string("/sys/devices/cpu_core/cpus")
            .ok()
            .map(|s| parse_cpu_list_str(&s))
            .filter(|v| !v.is_empty());

        Self::from_inputs(
            allowed,
            &phys_pairs,
            explicit_perf.as_deref(),
            &perf_scores,
            &llc_lists,
        )
    }
}

fn classify_hybrid_cores(
    allowed: &[usize],
    explicit_perf_cpus: Option<&[usize]>,
    perf_scores: &HashMap<usize, u64>,
) -> (Vec<usize>, Vec<usize>) {
    if let Some(perf_list) = explicit_perf_cpus {
        let perf_set: HashSet<usize> = perf_list.iter().copied().collect();
        let mut p = Vec::new();
        let mut e = Vec::new();
        for &cpu in allowed {
            if perf_set.contains(&cpu) {
                p.push(cpu);
            } else {
                e.push(cpu);
            }
        }
        if !p.is_empty() && !e.is_empty() {
            return (p, e);
        }
    }

    if perf_scores.len() == allowed.len() && allowed.len() >= 2 {
        let min_perf = *perf_scores.values().min().unwrap_or(&0);
        let max_perf = *perf_scores.values().max().unwrap_or(&0);
        // Treat >=10% frequency/CPPC disparity across cores as hybrid performance tiers.
        if min_perf > 0 && max_perf * 10 >= min_perf * 11 {
            let threshold = (max_perf * 92) / 100;
            let mut p = Vec::new();
            let mut e = Vec::new();
            for &cpu in allowed {
                if perf_scores.get(&cpu).copied().unwrap_or(0) >= threshold {
                    p.push(cpu);
                } else {
                    e.push(cpu);
                }
            }
            if !p.is_empty() && !e.is_empty() {
                return (p, e);
            }
        }
    }

    (Vec::new(), Vec::new())
}

pub fn parse_cpu_list_str(raw: &str) -> Vec<usize> {
    let mut out = BTreeSet::new();
    for part in raw.trim().split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = item.split_once('-') {
            if let (Ok(start), Ok(end)) =
                (start_s.trim().parse::<usize>(), end_s.trim().parse::<usize>())
            {
                let clamped_end = end.min(4095);
                if start <= clamped_end {
                    for cpu in start..=clamped_end {
                        out.insert(cpu);
                    }
                }
            }
        } else if let Ok(single) = item.parse::<usize>() {
            if single < 4096 {
                out.insert(single);
            }
        }
    }
    out.into_iter().collect()
}

fn read_trimmed_i32(path: &str) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse::<i32>().ok()
}

fn read_trimmed_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

fn read_llc_shared_list(cpu_base: &str) -> Option<Vec<usize>> {
    // Prefer level 3 cache; fallback to highest available cache index.
    let l3 = format!("{cpu_base}/cache/index3/shared_cpu_list");
    if let Ok(content) = fs::read_to_string(&l3) {
        let parsed = parse_cpu_list_str(&content);
        if !parsed.is_empty() {
            return Some(parsed);
        }
    }
    for idx in (1..=2).rev() {
        let path = format!("{cpu_base}/cache/index{idx}/shared_cpu_list");
        if let Ok(content) = fs::read_to_string(&path) {
            let parsed = parse_cpu_list_str(&content);
            if !parsed.is_empty() {
                return Some(parsed);
            }
        }
    }
    None
}

fn read_host_allowed_cpus() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut set) };
        if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) }
            == 0
        {
            let mut cpus = Vec::new();
            let max_cpus = std::mem::size_of::<libc::cpu_set_t>() * 8;
            for cpu in 0..max_cpus.min(4096) {
                if unsafe { libc::CPU_ISSET(cpu, &set) } {
                    cpus.push(cpu);
                }
            }
            if !cpus.is_empty() {
                return cpus;
            }
        }
    }
    let count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (0..count).collect()
}

static TOPOLOGY: OnceLock<CpuTopology> = OnceLock::new();

pub fn host_topology() -> &'static CpuTopology {
    TOPOLOGY.get_or_init(CpuTopology::detect_host)
}

// ============================================================================
// Thread Role Classification & Universal Affinity/Nice Selection
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadRole {
    CriticalEngine,
    EngineWorker,
    BackgroundIo,
    Audio,
    Other,
}

pub fn classify_thread_role(name: &str) -> ThreadRole {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return ThreadRole::Other;
    }
    if trimmed.eq_ignore_ascii_case("HttpClient")
        || trimmed.contains("IoEvLoop")
        || trimmed.starts_with("RBX IO")
        || trimmed.contains("SpanExport")
        || trimmed.contains("Crash")
        || trimmed.contains("Uploader")
        || trimmed.contains("WriteWorker")
    {
        return ThreadRole::BackgroundIo;
    }
    if trimmed.contains("FMOD") || trimmed.contains("Audio") || trimmed.contains("WebRTC") {
        return ThreadRole::Audio;
    }
    if trimmed == "RBX Main"
        || trimmed.contains("Render")
        || trimmed.contains("GLThread")
        || trimmed.contains("Vulkan")
    {
        return ThreadRole::CriticalEngine;
    }
    if trimmed.starts_with("RBX Worker")
        || trimmed.contains("TaskScheduler")
        || trimmed.contains("WorkerThread")
        || trimmed.contains("SimNarrow")
    {
        return ThreadRole::EngineWorker;
    }
    ThreadRole::Other
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPlacementPlan {
    pub target_cpus: Option<Vec<usize>>,
    pub nice_delta: Option<i32>,
}

pub fn plan_thread_placement(
    topo: &CpuTopology,
    role: ThreadRole,
    allow_l3_locality: bool,
    allow_bg_ecore: bool,
) -> ThreadPlacementPlan {
    let mut target_cpus: Option<Vec<usize>> = None;
    let mut nice_delta: Option<i32> = None;

    match role {
        ThreadRole::CriticalEngine | ThreadRole::Audio => {
            if topo.kind == TopologyKind::HybridPerfAndEff && topo.p_cores_logical.len() >= 2 {
                target_cpus = Some(topo.p_cores_logical.clone());
            } else if allow_l3_locality
                && topo.kind == TopologyKind::MultiLlcClusters
                && topo.llc_clusters.first().is_some_and(|c| c.len() >= 4)
            {
                target_cpus = Some(topo.llc_clusters[0].clone());
            }
        }
        ThreadRole::EngineWorker => {
            if topo.kind == TopologyKind::HybridPerfAndEff && topo.p_cores_logical.len() >= 4 {
                target_cpus = Some(topo.p_cores_logical.clone());
            } else if allow_l3_locality
                && topo.kind == TopologyKind::MultiLlcClusters
                && topo.llc_clusters.first().is_some_and(|c| c.len() >= 6)
            {
                target_cpus = Some(topo.llc_clusters[0].clone());
            }
        }
        ThreadRole::BackgroundIo => {
            nice_delta = Some(4);
            if allow_bg_ecore
                && topo.kind == TopologyKind::HybridPerfAndEff
                && topo.e_cores_logical.len() >= 2
            {
                target_cpus = Some(topo.e_cores_logical.clone());
            }
        }
        ThreadRole::Other => {}
    }

    ThreadPlacementPlan {
        target_cpus,
        nice_delta,
    }
}

fn apply_affinity_mask(target: &[usize]) -> bool {
    #[cfg(target_os = "linux")]
    {
        if target.is_empty() {
            return false;
        }
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut set) };
        let max_bits = std::mem::size_of::<libc::cpu_set_t>() * 8;
        let mut count = 0usize;
        for &cpu in target {
            if cpu < max_bits {
                unsafe { libc::CPU_SET(cpu, &mut set) };
                count += 1;
            }
        }
        if count == 0 {
            return false;
        }
        let rc = unsafe {
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
        };
        return rc == 0;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        false
    }
}

fn apply_affinity_for_pthread(thread: libc::pthread_t, target: &[usize]) -> bool {
    if unsafe { libc::pthread_equal(thread, libc::pthread_self()) } != 0 {
        return apply_affinity_mask(target);
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        if target.is_empty() {
            return false;
        }
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut set) };
        let max_bits = std::mem::size_of::<libc::cpu_set_t>() * 8;
        let mut count = 0usize;
        for &cpu in target {
            if cpu < max_bits {
                unsafe { libc::CPU_SET(cpu, &mut set) };
                count += 1;
            }
        }
        if count == 0 {
            return false;
        }
        return unsafe {
            libc::pthread_setaffinity_np(
                thread,
                std::mem::size_of::<libc::cpu_set_t>(),
                &set,
            ) == 0
        };
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}

fn apply_self_nice(nice_val: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { set_errno(0) };
        let cur = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        if cur == -1 && unsafe { last_errno() } != 0 {
            return false;
        }
        if cur >= nice_val {
            return false;
        }
        return unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice_val) } == 0;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = nice_val;
        false
    }
}

fn record_role_stat(role: ThreadRole) {
    if !stats_enabled() {
        return;
    }
    STATS.threads_named.fetch_add(1, Ordering::Relaxed);
    match role {
        ThreadRole::CriticalEngine => STATS.role_critical.fetch_add(1, Ordering::Relaxed),
        ThreadRole::EngineWorker => STATS.role_worker.fetch_add(1, Ordering::Relaxed),
        ThreadRole::BackgroundIo => STATS.role_io.fetch_add(1, Ordering::Relaxed),
        ThreadRole::Audio => STATS.role_audio.fetch_add(1, Ordering::Relaxed),
        ThreadRole::Other => 0,
    };
}

// ============================================================================
// Process & Exported ABI Entry Points (Topologies, pthread_setname_np, Timer)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_cpu_available_physical_cores() -> i32 {
    host_topology().physical_cores as i32
}

#[no_mangle]
pub extern "C" fn mocktail_rust_cpu_apply_process_tuning() {
    if !cpu_policy_enabled() {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        const PR_SET_TIMERSLACK: c_int = 29;
        let slack_ns = std::env::var("MOCKTAIL_TIMERSLACK_NS")
            .ok()
            .and_then(|s| s.trim().parse::<c_ulong>().ok())
            .filter(|&v| v > 0 && v <= 50_000)
            .unwrap_or(5_000);
        unsafe { libc::prctl(PR_SET_TIMERSLACK, slack_ns, 0, 0, 0) };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_cpu_on_thread_named(
    thread: libc::pthread_t,
    name_ptr: *const c_char,
) {
    if name_ptr.is_null() {
        return;
    }
    let Ok(name) = unsafe { CStr::from_ptr(name_ptr) }.to_str() else {
        return;
    };
    let role = classify_thread_role(name);
    record_role_stat(role);
    if !cpu_policy_enabled() {
        return;
    }
    let plan = plan_thread_placement(
        host_topology(),
        role,
        l3_locality_enabled(),
        bg_ecore_enabled(),
    );
    if let Some(ref cpus) = plan.target_cpus {
        if apply_affinity_for_pthread(thread, cpus) && stats_enabled() {
            STATS.affinity_applied.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(nice) = plan.nice_delta {
        if unsafe { libc::pthread_equal(thread, libc::pthread_self()) } != 0
            && apply_self_nice(nice)
            && stats_enabled()
        {
            STATS.nice_applied.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_pthread_setname_np(
    thread: libc::pthread_t,
    name: *const c_char,
) -> c_int {
    let rc = unsafe { libc::pthread_setname_np(thread, name) };
    mocktail_rust_cpu_on_thread_named(thread, name);
    rc
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_sched_yield() -> c_int {
    if stats_enabled() {
        STATS.sched_yields.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { libc::sched_yield() }
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_nanosleep(
    req: *const libc::timespec,
    rem: *mut libc::timespec,
) -> c_int {
    if stats_enabled() {
        STATS.nanosleeps.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { libc::nanosleep(req, rem) }
}

#[no_mangle]
pub extern "C" fn mocktail_cpu_dump_stats() {
    if !stats_enabled() {
        return;
    }
    let topo = host_topology();
    eprintln!(
        "  [cpu] policy={} topology={} allowed={} physical={} p_cores={} e_cores={} llc_clusters={} named={} roles(crit={} worker={} io={} audio={}) affinity_applied={} nice_applied={} sched_yields={} nanosleeps={} futex_waits={} rwlock_ops={} rwlock_wakes={} rwlock_wakes_skipped={} sem_ops={}",
        if cpu_policy_enabled() { "on" } else { "off" },
        topo.kind.as_str(),
        topo.allowed_logical.len(),
        topo.physical_cores,
        topo.p_cores_logical.len(),
        topo.e_cores_logical.len(),
        topo.llc_clusters.len(),
        STATS.threads_named.load(Ordering::Relaxed),
        STATS.role_critical.load(Ordering::Relaxed),
        STATS.role_worker.load(Ordering::Relaxed),
        STATS.role_io.load(Ordering::Relaxed),
        STATS.role_audio.load(Ordering::Relaxed),
        STATS.affinity_applied.load(Ordering::Relaxed),
        STATS.nice_applied.load(Ordering::Relaxed),
        STATS.sched_yields.load(Ordering::Relaxed),
        STATS.nanosleeps.load(Ordering::Relaxed),
        STATS.futex_waits.load(Ordering::Relaxed),
        STATS.rwlock_ops.load(Ordering::Relaxed),
        STATS.rwlock_wakes.load(Ordering::Relaxed),
        STATS.rwlock_wakes_skipped.load(Ordering::Relaxed),
        STATS.sem_ops.load(Ordering::Relaxed),
    );
}

// ============================================================================
// Helpers for errno & futex (Linux)
// ============================================================================

#[cfg(target_os = "linux")]
unsafe fn set_errno(val: c_int) {
    *libc::__errno_location() = val;
}

#[cfg(not(target_os = "linux"))]
unsafe fn set_errno(_val: c_int) {}

#[cfg(target_os = "linux")]
unsafe fn last_errno() -> c_int {
    *libc::__errno_location()
}

#[cfg(not(target_os = "linux"))]
unsafe fn last_errno() -> c_int {
    libc::EINVAL
}

#[cfg(target_os = "linux")]
fn futex_wait_private(addr: *const c_void, expected: i32) -> c_int {
    if stats_enabled() {
        STATS.futex_waits.fetch_add(1, Ordering::Relaxed);
    }
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<c_void>(),
            0,
        ) as c_int
    }
}

#[cfg(not(target_os = "linux"))]
fn futex_wait_private(_addr: *const c_void, _expected: i32) -> c_int {
    -1
}

#[cfg(target_os = "linux")]
fn futex_wake_private(addr: *const c_void, count: c_int) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<c_void>(),
            0,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn futex_wake_private(_addr: *const c_void, _count: c_int) {}

fn current_tid() -> i32 {
    thread_local! {
        static TLS_TID: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    }
    TLS_TID.with(|c| {
        let cur = c.get();
        if cur != 0 {
            return cur;
        }
        #[cfg(target_os = "linux")]
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        #[cfg(not(target_os = "linux"))]
        let tid = 1;
        c.set(tid);
        tid
    })
}

// ============================================================================
// Bionic RWLock Runtime (exact Bionic LP64 state layout)
// ============================================================================

const RWLOCK_WRITER_FLAG: i32 = 1 << 31;
const RWLOCK_PENDING_WRITERS_FLAG: i32 = 1 << 1;
const RWLOCK_PENDING_READERS_FLAG: i32 = 1 << 0;
const RWLOCK_READER_STEP: i32 = 1 << 2;
const RWLOCK_PENDING_MASK: i32 = RWLOCK_PENDING_WRITERS_FLAG | RWLOCK_PENDING_READERS_FLAG;

#[inline]
fn invalid_guest_ptr<T>(ptr: *const T) -> bool {
    (ptr as usize) < 4096
}

#[inline]
unsafe fn rwlock_state(rwlock: *mut libc::pthread_rwlock_t) -> &'static AtomicI32 {
    &*(rwlock as *const AtomicI32)
}

#[inline]
unsafe fn rwlock_writer_tid(rwlock: *mut libc::pthread_rwlock_t) -> &'static AtomicI32 {
    &*((rwlock as *const u8).add(4) as *const AtomicI32)
}

#[inline]
fn rwlock_owned_by_writer(state: i32) -> bool {
    state < 0
}

#[inline]
fn rwlock_owned_by_readers(state: i32) -> bool {
    state >= RWLOCK_READER_STEP
}

fn try_rdlock(state: &AtomicI32) -> c_int {
    let mut old_state = state.load(Ordering::Relaxed);
    while !rwlock_owned_by_writer(old_state) {
        let new_state = old_state.wrapping_add(RWLOCK_READER_STEP);
        if !rwlock_owned_by_readers(new_state) {
            return libc::EAGAIN;
        }
        match state.compare_exchange_weak(
            old_state,
            new_state,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return 0,
            Err(actual) => old_state = actual,
        }
    }
    libc::EBUSY
}

fn try_wrlock(state: &AtomicI32, writer_tid: &AtomicI32) -> c_int {
    let mut old_state = state.load(Ordering::Relaxed);
    while !rwlock_owned_by_writer(old_state) && !rwlock_owned_by_readers(old_state) {
        let new_state = old_state | RWLOCK_WRITER_FLAG;
        match state.compare_exchange_weak(
            old_state,
            new_state,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                writer_tid.store(current_tid(), Ordering::Relaxed);
                return 0;
            }
            Err(actual) => old_state = actual,
        }
    }
    libc::EBUSY
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_pthread_rwlock_init(
    rwlock: *mut libc::pthread_rwlock_t,
    _attr: *const libc::pthread_rwlockattr_t,
) -> c_int {
    if invalid_guest_ptr(rwlock) {
        return libc::EINVAL;
    }
    unsafe { std::ptr::write_bytes(rwlock as *mut u8, 0, std::mem::size_of::<libc::pthread_rwlock_t>()) };
    0
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_pthread_rwlock_destroy(
    rwlock: *mut libc::pthread_rwlock_t,
) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    let state = unsafe { rwlock_state(rwlock) }.load(Ordering::Relaxed);
    if (state & !RWLOCK_PENDING_MASK) != 0 {
        return libc::EBUSY;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_pthread_rwlock_rdlock(
    rwlock: *mut libc::pthread_rwlock_t,
) -> c_int {
    if invalid_guest_ptr(rwlock) {
        return libc::EINVAL;
    }
    if stats_enabled() {
        STATS.rwlock_ops.fetch_add(1, Ordering::Relaxed);
    }
    let state = unsafe { rwlock_state(rwlock) };
    if try_rdlock(state) == 0 {
        return 0;
    }
    loop {
        let rc = try_rdlock(state);
        if rc == 0 || rc == libc::EAGAIN {
            return rc;
        }
        let old_state = state.load(Ordering::Relaxed);
        if !rwlock_owned_by_writer(old_state) {
            continue;
        }
        let pending = old_state | RWLOCK_PENDING_READERS_FLAG;
        if state
            .compare_exchange_weak(old_state, pending, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        futex_wait_private(state as *const AtomicI32 as *const c_void, pending);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_pthread_rwlock_wrlock(
    rwlock: *mut libc::pthread_rwlock_t,
) -> c_int {
    if invalid_guest_ptr(rwlock) {
        return libc::EINVAL;
    }
    if stats_enabled() {
        STATS.rwlock_ops.fetch_add(1, Ordering::Relaxed);
    }
    let state = unsafe { rwlock_state(rwlock) };
    let writer_tid = unsafe { rwlock_writer_tid(rwlock) };
    if writer_tid.load(Ordering::Relaxed) == current_tid() {
        return libc::EDEADLK;
    }
    if try_wrlock(state, writer_tid) == 0 {
        return 0;
    }
    loop {
        if try_wrlock(state, writer_tid) == 0 {
            return 0;
        }
        let old_state = state.load(Ordering::Relaxed);
        if !rwlock_owned_by_writer(old_state) && !rwlock_owned_by_readers(old_state) {
            continue;
        }
        let pending = old_state | RWLOCK_PENDING_WRITERS_FLAG;
        if state
            .compare_exchange_weak(old_state, pending, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        futex_wait_private(state as *const AtomicI32 as *const c_void, pending);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_pthread_rwlock_unlock(
    rwlock: *mut libc::pthread_rwlock_t,
) -> c_int {
    if invalid_guest_ptr(rwlock) {
        return libc::EINVAL;
    }
    let state = unsafe { rwlock_state(rwlock) };
    let writer_tid = unsafe { rwlock_writer_tid(rwlock) };
    let old_state = state.load(Ordering::Relaxed);
    let had_pending = if rwlock_owned_by_writer(old_state) {
        if writer_tid.load(Ordering::Relaxed) != current_tid() {
            return libc::EPERM;
        }
        writer_tid.store(0, Ordering::Relaxed);
        let prev = state.fetch_and(
            !(RWLOCK_WRITER_FLAG | RWLOCK_PENDING_MASK),
            Ordering::Release,
        );
        (prev & RWLOCK_PENDING_MASK) != 0
    } else if rwlock_owned_by_readers(old_state) {
        let mut cur = old_state;
        loop {
            if !rwlock_owned_by_readers(cur) {
                return libc::EPERM;
            }
            if (cur >> 2) > 1 {
                let next = cur - RWLOCK_READER_STEP;
                match state.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return 0,
                    Err(actual) => cur = actual,
                }
            } else {
                match state.compare_exchange_weak(
                    cur,
                    0,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break (cur & RWLOCK_PENDING_MASK) != 0,
                    Err(actual) => cur = actual,
                }
            }
        }
    } else {
        return libc::EPERM;
    };

    if had_pending {
        if stats_enabled() {
            STATS.rwlock_wakes.fetch_add(1, Ordering::Relaxed);
        }
        futex_wake_private(state as *const AtomicI32 as *const c_void, i32::MAX);
    } else if stats_enabled() {
        STATS.rwlock_wakes_skipped.fetch_add(1, Ordering::Relaxed);
    }
    0
}

// ============================================================================
// Bionic Semaphore Runtime (exact Bionic 31:1 count word layout)
// ============================================================================

const SEM_VALUE_MASK: u32 = 0xffff_fffe;
const SEM_VALUE_SHIFT: u32 = 1;
const SEM_ONE: u32 = 1 << SEM_VALUE_SHIFT;
const SEM_MINUS_ONE: u32 = SEM_VALUE_MASK;
const HOST_SEM_VALUE_MAX: u32 = i32::MAX as u32;

#[inline]
unsafe fn sem_count(sem: *mut libc::sem_t) -> &'static AtomicU32 {
    &*(sem as *const AtomicU32)
}

#[inline]
fn sem_value(encoded: u32) -> i32 {
    (encoded as i32) >> SEM_VALUE_SHIFT
}

#[inline]
fn sem_encode(value: u32) -> u32 {
    (value.wrapping_shl(SEM_VALUE_SHIFT)) & SEM_VALUE_MASK
}

fn sem_dec(count: &AtomicU32) -> i32 {
    let mut old_value = count.load(Ordering::Relaxed);
    loop {
        if sem_value(old_value) < 0 {
            break;
        }
        let next = (old_value.wrapping_sub(SEM_ONE)) & SEM_VALUE_MASK;
        match count.compare_exchange_weak(
            old_value,
            next,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => old_value = actual,
        }
    }
    sem_value(old_value)
}

fn sem_inc(count: &AtomicU32) -> i32 {
    let mut old_value = count.load(Ordering::Relaxed);
    loop {
        let val = sem_value(old_value);
        if val == HOST_SEM_VALUE_MAX as i32 {
            break;
        }
        let next = if val < 0 {
            SEM_ONE
        } else {
            (old_value.wrapping_add(SEM_ONE)) & SEM_VALUE_MASK
        };
        match count.compare_exchange_weak(
            old_value,
            next,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => old_value = actual,
        }
    }
    sem_value(old_value)
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_sem_init(
    semaphore: *mut libc::sem_t,
    process_shared: c_int,
    value: c_uint,
) -> c_int {
    if semaphore.is_null() || process_shared != 0 || value > HOST_SEM_VALUE_MAX {
        unsafe { set_errno(libc::EINVAL) };
        return -1;
    }
    unsafe { sem_count(semaphore) }.store(sem_encode(value), Ordering::Relaxed);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_sem_destroy(semaphore: *mut libc::sem_t) -> c_int {
    if semaphore.is_null() {
        unsafe { set_errno(libc::EINVAL) };
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_sem_wait(semaphore: *mut libc::sem_t) -> c_int {
    if semaphore.is_null() {
        unsafe { set_errno(libc::EINVAL) };
        return -1;
    }
    if stats_enabled() {
        STATS.sem_ops.fetch_add(1, Ordering::Relaxed);
    }
    let count = unsafe { sem_count(semaphore) };
    loop {
        if sem_dec(count) > 0 {
            return 0;
        }
        let rc = futex_wait_private(count as *const AtomicU32 as *const c_void, SEM_MINUS_ONE as i32);
        if rc != 0 {
            let err = unsafe { last_errno() };
            if err == libc::EINTR || err == libc::EAGAIN {
                continue;
            }
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_sem_post(semaphore: *mut libc::sem_t) -> c_int {
    if semaphore.is_null() {
        unsafe { set_errno(libc::EINVAL) };
        return -1;
    }
    if stats_enabled() {
        STATS.sem_ops.fetch_add(1, Ordering::Relaxed);
    }
    let count = unsafe { sem_count(semaphore) };
    let old_value = sem_inc(count);
    if old_value < 0 {
        futex_wake_private(count as *const AtomicU32 as *const c_void, i32::MAX);
    } else if old_value == HOST_SEM_VALUE_MAX as i32 {
        unsafe { set_errno(libc::EOVERFLOW) };
        return -1;
    }
    0
}

// ============================================================================
// Bionic Sysconf & Prctl Runtime
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_bionic_sysconf(name: c_int) -> c_long {
    let mut standard_sc: i32 = 0;
    let mut fixed_val: i64 = 0;
    let kind = crate::mocktail_rust_bionic_sysconf_translate_name(
        name,
        &mut standard_sc,
        &mut fixed_val,
    );
    if kind == 1 {
        return fixed_val as c_long;
    }
    if kind == 0 {
        let host_name = match name {
            0x0000 => libc::_SC_ARG_MAX,
            0x0005 => libc::_SC_CHILD_MAX,
            0x000b => libc::_SC_OPEN_MAX,
            0x0026 => libc::_SC_IOV_MAX,
            0x0027 | 0x0028 => libc::_SC_PAGESIZE,
            0x0060 => libc::_SC_NPROCESSORS_CONF,
            0x0061 => libc::_SC_NPROCESSORS_ONLN,
            0x0062 => libc::_SC_PHYS_PAGES,
            0x0063 => libc::_SC_AVPHYS_PAGES,
            _ => {
                unsafe { set_errno(libc::EINVAL) };
                return -1;
            }
        };
        return unsafe { libc::sysconf(host_name) };
    }
    unsafe { set_errno(libc::EINVAL) };
    -1
}

fn is_freebsd_linuxulator() -> bool {
    static DETECTED: OnceLock<bool> = OnceLock::new();
    *DETECTED.get_or_init(|| {
        fs::read_to_string("/proc/version")
            .map(|v| v.contains("FreeBSD") || v.contains("freebsd.org"))
            .unwrap_or(false)
    })
}

fn is_page_aligned_range(addr: c_ulong, length: c_ulong) -> bool {
    if addr == 0 || length == 0 || addr.checked_add(length).is_none() {
        return false;
    }
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return false;
    }
    let mask = (page_size as c_ulong) - 1;
    (addr & mask) == 0 && (length & mask) == 0
}

#[no_mangle]
pub extern "C" fn mocktail_bionic_prctl(
    option: c_int,
    arg2: c_ulong,
    arg3: c_ulong,
    arg4: c_ulong,
    arg5: c_ulong,
) -> c_int {
    const PR_SET_VMA: c_int = 0x53564d41;
    const PR_SET_VMA_ANON_NAME: c_ulong = 0;
    const PR_SET_THP_DISABLE: c_int = 41;
    const PR_GET_THP_DISABLE: c_int = 42;

    let prev_errno = unsafe { last_errno() };
    #[cfg(target_os = "linux")]
    let res = unsafe { libc::prctl(option, arg2, arg3, arg4, arg5) };
    #[cfg(not(target_os = "linux"))]
    let res: c_int = -1;

    if res != -1 || !is_freebsd_linuxulator() {
        return res;
    }
    let err = unsafe { last_errno() };
    if err != libc::EINVAL && err != libc::ENOSYS && err != libc::EOPNOTSUPP {
        return res;
    }
    if option == PR_GET_THP_DISABLE {
        unsafe { set_errno(prev_errno) };
        return 1;
    }
    if option == PR_SET_THP_DISABLE && arg2 != 0 {
        unsafe { set_errno(prev_errno) };
        return 0;
    }
    if option == PR_SET_VMA && arg2 == PR_SET_VMA_ANON_NAME && is_page_aligned_range(arg3, arg4) {
        unsafe { set_errno(prev_errno) };
        return 0;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complex_cpu_list_strings() {
        assert_eq!(parse_cpu_list_str("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list_str("0-1,4,6-7\n"), vec![0, 1, 4, 6, 7]);
        assert_eq!(parse_cpu_list_str(""), Vec::<usize>::new());
    }

    #[test]
    fn classifies_homogeneous_hybrid_and_multi_llc_topologies_universally() {
        // Homogeneous 4c/8t (no E-core, single LLC)
        let homo = CpuTopology::from_inputs(
            (0..8).collect(),
            &[(0, 0), (0, 0), (0, 1), (0, 1), (0, 2), (0, 2), (0, 3), (0, 3)],
            None,
            &HashMap::new(),
            &[(0..8).collect()],
        );
        assert_eq!(homo.kind, TopologyKind::Homogeneous);
        assert_eq!(homo.physical_cores, 4);
        assert_eq!(
            plan_thread_placement(&homo, ThreadRole::CriticalEngine, true, true).target_cpus,
            None
        );
        assert_eq!(
            plan_thread_placement(&homo, ThreadRole::BackgroundIo, true, true).nice_delta,
            Some(4)
        );

        // Hybrid Intel-style 6 P-core threads (0..5) + 4 E-cores (6..9)
        let hybrid = CpuTopology::from_inputs(
            (0..10).collect(),
            &[(0, 0), (0, 0), (0, 1), (0, 1), (0, 2), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6)],
            Some(&[0, 1, 2, 3, 4, 5]),
            &HashMap::new(),
            &[],
        );
        assert_eq!(hybrid.kind, TopologyKind::HybridPerfAndEff);
        assert_eq!(hybrid.physical_cores, 7);
        assert_eq!(
            plan_thread_placement(&hybrid, ThreadRole::CriticalEngine, true, true).target_cpus,
            Some(vec![0, 1, 2, 3, 4, 5])
        );
        assert_eq!(
            plan_thread_placement(&hybrid, ThreadRole::BackgroundIo, true, true).target_cpus,
            Some(vec![6, 7, 8, 9])
        );

        // Multi-CCD Ryzen-style 2x 6t L3 clusters (0..5 and 6..11)
        let multi_ccd = CpuTopology::from_inputs(
            (0..12).collect(),
            &(0..12).map(|i| (0, (i / 2) as i32)).collect::<Vec<_>>(),
            None,
            &HashMap::new(),
            &[(0..6).collect(), (6..12).collect()],
        );
        assert_eq!(multi_ccd.kind, TopologyKind::MultiLlcClusters);
        assert_eq!(
            plan_thread_placement(&multi_ccd, ThreadRole::CriticalEngine, true, true).target_cpus,
            Some(vec![0, 1, 2, 3, 4, 5])
        );
        assert_eq!(
            plan_thread_placement(&multi_ccd, ThreadRole::EngineWorker, true, true).target_cpus,
            Some(vec![0, 1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn classifies_guest_thread_roles() {
        assert_eq!(classify_thread_role("RBX Main"), ThreadRole::CriticalEngine);
        assert_eq!(classify_thread_role(" RBX Main"), ThreadRole::CriticalEngine);
        assert_eq!(classify_thread_role("RBX Worker 0"), ThreadRole::EngineWorker);
        assert_eq!(classify_thread_role("HttpClient"), ThreadRole::BackgroundIo);
        assert_eq!(classify_thread_role("RBX IoEvLoop 1"), ThreadRole::BackgroundIo);
        assert_eq!(classify_thread_role("FMOD mixer thread"), ThreadRole::Audio);
    }

    #[test]
    fn rust_bionic_rwlock_and_semaphore_behave_correctly() {
        unsafe {
            let mut rw: libc::pthread_rwlock_t = std::mem::zeroed();
            assert_eq!(mocktail_bionic_pthread_rwlock_init(&mut rw, std::ptr::null()), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_rdlock(&mut rw), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_rdlock(&mut rw), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_unlock(&mut rw), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_unlock(&mut rw), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_wrlock(&mut rw), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_wrlock(&mut rw), libc::EDEADLK);
            assert_eq!(mocktail_bionic_pthread_rwlock_unlock(&mut rw), 0);
            assert_eq!(mocktail_bionic_pthread_rwlock_destroy(&mut rw), 0);

            let mut sem: libc::sem_t = std::mem::zeroed();
            assert_eq!(mocktail_bionic_sem_init(&mut sem, 0, 1), 0);
            assert_eq!(mocktail_bionic_sem_wait(&mut sem), 0);
            assert_eq!(mocktail_bionic_sem_post(&mut sem), 0);
            assert_eq!(mocktail_bionic_sem_destroy(&mut sem), 0);
        }
    }
}
