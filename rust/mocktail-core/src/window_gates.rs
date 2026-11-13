use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::atomic::{fence, AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread::ThreadId;

pub const VULKAN_SURFACE_RECOVERY_RETRY_INTERVAL_NS: u64 = 1_000_000_000;
pub const VULKAN_PRESENT_STALL_THRESHOLD_NS: u64 = 5_000_000_000;

const CALL_SLOT_COUNT: usize = 32;
const RESERVED_CALL_SEQUENCE: u64 = u64::MAX;
const LIFECYCLE_INACTIVE: u8 = 0;
const LIFECYCLE_INITIALIZING: u8 = 1;
const LIFECYCLE_ACTIVE: u8 = 2;

static HOST_PRESENT_CALL_NAME: &[u8] = b"vkQueuePresentKHR(host)\0";

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_while_unpoisoned<'a, T, F>(
    cv: &Condvar,
    guard: MutexGuard<'a, T>,
    condition: F,
) -> MutexGuard<'a, T>
where
    F: FnMut(&mut T) -> bool,
{
    cv.wait_while(guard, condition)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ============================================================================
// 124. Input Pump Pacer
// ============================================================================

struct RustInputPumpPacer {
    interval_ns: u64,
    next_deadline_ns: u64,
}

impl RustInputPumpPacer {
    fn new(interval_ns: u64) -> Self {
        Self {
            interval_ns,
            next_deadline_ns: 0,
        }
    }

    fn delay_before_next_pump(&mut self, now_ns: u64) -> u64 {
        if self.interval_ns == 0 {
            return 0;
        }
        if self.next_deadline_ns == 0 || now_ns >= self.next_deadline_ns {
            self.next_deadline_ns = now_ns.saturating_add(self.interval_ns);
            return 0;
        }
        let delay_ns = self.next_deadline_ns - now_ns;
        self.next_deadline_ns = self.next_deadline_ns.saturating_add(self.interval_ns);
        delay_ns
    }

    fn reset(&mut self) {
        self.next_deadline_ns = 0;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_pump_pacer_new(interval_ns: u64) -> *mut c_void {
    Box::into_raw(Box::new(RustInputPumpPacer::new(interval_ns))) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_pump_pacer_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut RustInputPumpPacer));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_pump_pacer_delay_before_next_pump(
    ptr: *mut c_void,
    now_ns: u64,
) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    let pacer = unsafe { &mut *(ptr as *mut RustInputPumpPacer) };
    pacer.delay_before_next_pump(now_ns)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_pump_pacer_reset(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let pacer = unsafe { &mut *(ptr as *mut RustInputPumpPacer) };
    pacer.reset();
}

// ============================================================================
// 125. Vulkan Surface Recovery Gate
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MocktailRustVulkanSurfaceRecoveryRequest {
    pub observed_error_count: u64,
    pub coalesced_error_count: u64,
    pub retry: bool,
}

#[derive(Default)]
struct RecoveryGateInner {
    handled_out_of_date_count: u64,
    present_count_at_last_rebind: u64,
    last_rebind_ticks_ns: u64,
}

struct RustVulkanSurfaceRecoveryGate {
    active: AtomicBool,
    out_of_date_count: AtomicU64,
    present_count: AtomicU64,
    inner: Mutex<RecoveryGateInner>,
}

impl Default for RustVulkanSurfaceRecoveryGate {
    fn default() -> Self {
        Self {
            active: AtomicBool::new(false),
            out_of_date_count: AtomicU64::new(0),
            present_count: AtomicU64::new(0),
            inner: Mutex::new(RecoveryGateInner::default()),
        }
    }
}

impl RustVulkanSurfaceRecoveryGate {
    fn reset_counters_locked(&self, inner: &mut RecoveryGateInner) {
        self.out_of_date_count.store(0, Ordering::Relaxed);
        self.present_count.store(0, Ordering::Relaxed);
        inner.handled_out_of_date_count = 0;
        inner.present_count_at_last_rebind = 0;
        inner.last_rebind_ticks_ns = 0;
    }

    fn activate(&self) -> bool {
        let mut inner = lock_unpoisoned(&self.inner);
        if self.active.load(Ordering::Relaxed) {
            return false;
        }
        self.reset_counters_locked(&mut inner);
        self.active.store(true, Ordering::Release);
        true
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
        let mut inner = lock_unpoisoned(&self.inner);
        self.reset_counters_locked(&mut inner);
    }

    fn notify_out_of_date(&self) {
        if self.active.load(Ordering::Acquire) {
            self.out_of_date_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn notify_present(&self) {
        if self.active.load(Ordering::Acquire) {
            self.present_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn take_rebind_request(&self, now_ticks_ns: u64) -> Option<MocktailRustVulkanSurfaceRecoveryRequest> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let mut inner = lock_unpoisoned(&self.inner);
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }

        let out_of_date_count = self.out_of_date_count.load(Ordering::Acquire);
        if out_of_date_count == inner.handled_out_of_date_count {
            return None;
        }
        let present_count = self.present_count.load(Ordering::Acquire);
        let presented_since_last_rebind = present_count != inner.present_count_at_last_rebind;
        let retry_due = inner.last_rebind_ticks_ns == 0
            || now_ticks_ns < inner.last_rebind_ticks_ns
            || now_ticks_ns - inner.last_rebind_ticks_ns
                >= VULKAN_SURFACE_RECOVERY_RETRY_INTERVAL_NS;
        if !presented_since_last_rebind && !retry_due {
            return None;
        }

        let request = MocktailRustVulkanSurfaceRecoveryRequest {
            observed_error_count: out_of_date_count,
            coalesced_error_count: out_of_date_count - inner.handled_out_of_date_count,
            retry: inner.last_rebind_ticks_ns != 0 && !presented_since_last_rebind,
        };
        inner.handled_out_of_date_count = out_of_date_count;
        inner.present_count_at_last_rebind = present_count;
        inner.last_rebind_ticks_ns = now_ticks_ns;
        Some(request)
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_new() -> *mut c_void {
    Box::into_raw(Box::new(RustVulkanSurfaceRecoveryGate::default())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut RustVulkanSurfaceRecoveryGate));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_activate(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanSurfaceRecoveryGate) };
    gate.activate()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_deactivate(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanSurfaceRecoveryGate) };
    gate.deactivate();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_notify_out_of_date(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanSurfaceRecoveryGate) };
    gate.notify_out_of_date();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_notify_present(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanSurfaceRecoveryGate) };
    gate.notify_present();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
    ptr: *mut c_void,
    now_ticks_ns: u64,
    out_request: *mut MocktailRustVulkanSurfaceRecoveryRequest,
) -> bool {
    if ptr.is_null() || out_request.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanSurfaceRecoveryGate) };
    match gate.take_rebind_request(now_ticks_ns) {
        Some(request) => {
            unsafe {
                *out_request = request;
            }
            true
        }
        None => false,
    }
}

// ============================================================================
// 126. Vulkan Present Progress Gate
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MocktailRustVulkanPresentStallReport {
    pub stage: i32,
    pub call_name: *const c_char,
    pub call_sequence: u64,
    pub thread_id: u64,
    pub elapsed_ns: u64,
    pub frame_count: u64,
    pub host_present_count: u64,
    pub last_present_thread_id: u64,
    pub last_completed_call_snapshot_coherent: bool,
    pub last_completed_call_name: *const c_char,
    pub last_completed_call_sequence: u64,
    pub last_completed_call_thread_id: u64,
    pub last_completed_call_started_ns: u64,
    pub last_completed_call_completed_ns: u64,
    pub last_completed_call_result: i32,
    pub oldest_active_call_name: *const c_char,
    pub oldest_active_call_sequence: u64,
    pub oldest_active_call_thread_id: u64,
    pub oldest_active_call_elapsed_ns: u64,
}

impl Default for MocktailRustVulkanPresentStallReport {
    fn default() -> Self {
        Self {
            stage: 0,
            call_name: std::ptr::null(),
            call_sequence: 0,
            thread_id: 0,
            elapsed_ns: 0,
            frame_count: 0,
            host_present_count: 0,
            last_present_thread_id: 0,
            last_completed_call_snapshot_coherent: false,
            last_completed_call_name: std::ptr::null(),
            last_completed_call_sequence: 0,
            last_completed_call_thread_id: 0,
            last_completed_call_started_ns: 0,
            last_completed_call_completed_ns: 0,
            last_completed_call_result: 0,
            oldest_active_call_name: std::ptr::null(),
            oldest_active_call_sequence: 0,
            oldest_active_call_thread_id: 0,
            oldest_active_call_elapsed_ns: 0,
        }
    }
}

#[derive(Default)]
struct CallSlot {
    sequence: AtomicU64,
    // Caller-owned static Vulkan call name C string pointer stored lock-free.
    call_name: AtomicUsize,
    started_ns: AtomicU64,
    thread_id: AtomicU64,
    lifecycle_epoch: AtomicU64,
}

struct RustVulkanPresentProgressGate {
    lifecycle_state: AtomicU8,
    lifecycle_epoch: AtomicU64,
    has_presented_frame: AtomicBool,
    host_present_in_flight: AtomicBool,
    present_generation: AtomicU64,
    reported_stall_generation: AtomicU64,
    reported_call_sequence: AtomicU64,
    reported_host_present_count: AtomicU64,
    host_present_started_ns: AtomicU64,
    host_present_thread_id: AtomicU64,
    host_present_lifecycle_epoch: AtomicU64,
    last_progress_ns: AtomicU64,
    frame_count: AtomicU64,
    host_present_count: AtomicU64,
    last_present_thread_id: AtomicU64,
    last_present_lifecycle_epoch: AtomicU64,
    next_call_sequence: AtomicU64,
    last_call_record_version: AtomicU64,
    last_call_lifecycle_epoch: AtomicU64,
    last_call_name: AtomicUsize,
    last_call_sequence: AtomicU64,
    last_call_thread_id: AtomicU64,
    last_call_started_ns: AtomicU64,
    last_call_completed_ns: AtomicU64,
    last_call_result: std::sync::atomic::AtomicI32,
    call_slots: [CallSlot; CALL_SLOT_COUNT],
}

impl Default for RustVulkanPresentProgressGate {
    fn default() -> Self {
        Self {
            lifecycle_state: AtomicU8::new(LIFECYCLE_INACTIVE),
            lifecycle_epoch: AtomicU64::new(0),
            has_presented_frame: AtomicBool::new(false),
            host_present_in_flight: AtomicBool::new(false),
            present_generation: AtomicU64::new(0),
            reported_stall_generation: AtomicU64::new(0),
            reported_call_sequence: AtomicU64::new(0),
            reported_host_present_count: AtomicU64::new(0),
            host_present_started_ns: AtomicU64::new(0),
            host_present_thread_id: AtomicU64::new(0),
            host_present_lifecycle_epoch: AtomicU64::new(0),
            last_progress_ns: AtomicU64::new(0),
            frame_count: AtomicU64::new(0),
            host_present_count: AtomicU64::new(0),
            last_present_thread_id: AtomicU64::new(0),
            last_present_lifecycle_epoch: AtomicU64::new(0),
            next_call_sequence: AtomicU64::new(0),
            last_call_record_version: AtomicU64::new(0),
            last_call_lifecycle_epoch: AtomicU64::new(0),
            last_call_name: AtomicUsize::new(0),
            last_call_sequence: AtomicU64::new(0),
            last_call_thread_id: AtomicU64::new(0),
            last_call_started_ns: AtomicU64::new(0),
            last_call_completed_ns: AtomicU64::new(0),
            last_call_result: std::sync::atomic::AtomicI32::new(0),
            call_slots: std::array::from_fn(|_| CallSlot::default()),
        }
    }
}

impl RustVulkanPresentProgressGate {
    fn is_active(&self) -> bool {
        self.lifecycle_state.load(Ordering::Acquire) == LIFECYCLE_ACTIVE
    }

    fn reset_progress(&self) {
        self.has_presented_frame.store(false, Ordering::Relaxed);
        self.host_present_in_flight.store(false, Ordering::Relaxed);
        self.host_present_started_ns.store(0, Ordering::Relaxed);
        self.last_progress_ns.store(0, Ordering::Relaxed);
        self.frame_count.store(0, Ordering::Relaxed);
        self.last_present_thread_id.store(0, Ordering::Relaxed);
    }

    fn activate(&self) -> bool {
        if self
            .lifecycle_state
            .compare_exchange(
                LIFECYCLE_INACTIVE,
                LIFECYCLE_INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        self.reset_progress();
        self.lifecycle_state
            .store(LIFECYCLE_ACTIVE, Ordering::Release);
        true
    }

    fn deactivate(&self) {
        self.lifecycle_state
            .store(LIFECYCLE_INACTIVE, Ordering::Release);
        self.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        self.reset_progress();
    }

    fn notify_host_present_begin(&self, now_ticks_ns: u64, thread_id: u64) -> u64 {
        if !self.is_active() {
            return 0;
        }
        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        self.host_present_started_ns
            .store(now_ticks_ns, Ordering::Relaxed);
        let sequence = self
            .host_present_count
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        self.host_present_thread_id
            .store(thread_id, Ordering::Relaxed);
        self.host_present_lifecycle_epoch
            .store(lifecycle_epoch, Ordering::Relaxed);
        if !self.is_active() || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch {
            return 0;
        }
        self.host_present_in_flight.store(true, Ordering::Release);
        sequence
    }

    fn notify_host_present_end(&self, sequence: u64) {
        if sequence == 0
            || !self.is_active()
            || self.host_present_count.load(Ordering::Acquire) != sequence
        {
            return;
        }
        self.host_present_in_flight.store(false, Ordering::Release);
    }

    fn notify_call_begin(&self, call_name: *const c_char, now_ticks_ns: u64, thread_id: u64) -> u64 {
        if call_name.is_null() || !self.is_active() {
            return 0;
        }
        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        if !self.is_active() {
            return 0;
        }
        let mut sequence = self
            .next_call_sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if sequence == 0 || sequence == RESERVED_CALL_SEQUENCE {
            sequence = self
                .next_call_sequence
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
        }
        for slot in &self.call_slots {
            if slot
                .sequence
                .compare_exchange(
                    0,
                    RESERVED_CALL_SEQUENCE,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }
            slot.call_name.store(call_name as usize, Ordering::Relaxed);
            slot.started_ns.store(now_ticks_ns, Ordering::Relaxed);
            slot.thread_id.store(thread_id, Ordering::Relaxed);
            slot.lifecycle_epoch
                .store(lifecycle_epoch, Ordering::Relaxed);
            if !self.is_active() || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
            {
                slot.sequence.store(0, Ordering::Release);
                return 0;
            }
            slot.sequence.store(sequence, Ordering::Release);
            return sequence;
        }
        0
    }

    fn notify_call_end(&self, sequence: u64, result: i32, now_ticks_ns: u64, thread_id: u64) {
        if sequence == 0 || sequence == RESERVED_CALL_SEQUENCE {
            return;
        }
        for slot in &self.call_slots {
            if slot
                .sequence
                .compare_exchange(
                    sequence,
                    RESERVED_CALL_SEQUENCE,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }
            let completed_thread_id = if thread_id != 0 {
                thread_id
            } else {
                slot.thread_id.load(Ordering::Relaxed)
            };
            let call_lifecycle_epoch = slot.lifecycle_epoch.load(Ordering::Relaxed);
            let render_thread_id = self.last_present_thread_id.load(Ordering::Acquire);
            let current_lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
            let record_version = self.last_call_record_version.load(Ordering::Relaxed);
            if self.is_active()
                && call_lifecycle_epoch == current_lifecycle_epoch
                && (render_thread_id == 0 || completed_thread_id == render_thread_id)
                && (record_version & 1) == 0
                && self
                    .last_call_record_version
                    .compare_exchange(
                        record_version,
                        record_version.wrapping_add(1),
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                self.last_call_name
                    .store(slot.call_name.load(Ordering::Relaxed), Ordering::Relaxed);
                self.last_call_sequence.store(sequence, Ordering::Relaxed);
                self.last_call_thread_id
                    .store(completed_thread_id, Ordering::Relaxed);
                self.last_call_started_ns
                    .store(slot.started_ns.load(Ordering::Relaxed), Ordering::Relaxed);
                self.last_call_completed_ns
                    .store(now_ticks_ns, Ordering::Relaxed);
                self.last_call_result.store(result, Ordering::Relaxed);
                self.last_call_lifecycle_epoch
                    .store(call_lifecycle_epoch, Ordering::Relaxed);
                self.last_call_record_version
                    .store(record_version.wrapping_add(2), Ordering::Release);
            }
            slot.sequence.store(0, Ordering::Release);
            return;
        }
    }

    fn notify_frame_presented(&self, now_ticks_ns: u64, frame_count: u64, thread_id: u64) {
        if !self.is_active() {
            return;
        }
        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        self.last_progress_ns.store(now_ticks_ns, Ordering::Relaxed);
        self.frame_count.store(frame_count, Ordering::Relaxed);
        self.last_present_thread_id
            .store(thread_id, Ordering::Relaxed);
        self.last_present_lifecycle_epoch
            .store(lifecycle_epoch, Ordering::Relaxed);
        if !self.is_active() || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch {
            return;
        }
        self.present_generation.fetch_add(1, Ordering::Release);
        self.has_presented_frame.store(true, Ordering::Release);
    }

    fn poll(
        &self,
        now_ticks_ns: u64,
        window_can_present: bool,
    ) -> Option<MocktailRustVulkanPresentStallReport> {
        if !window_can_present
            || !self.is_active()
            || !self.has_presented_frame.load(Ordering::Acquire)
        {
            return None;
        }

        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        let present_generation = self.present_generation.load(Ordering::Acquire);
        if self.last_present_lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch {
            return None;
        }
        let last_progress_ns = self.last_progress_ns.load(Ordering::Acquire);
        if present_generation == 0
            || last_progress_ns == 0
            || now_ticks_ns < last_progress_ns
            || now_ticks_ns - last_progress_ns < VULKAN_PRESENT_STALL_THRESHOLD_NS
        {
            return None;
        }

        let render_thread_id = self.last_present_thread_id.load(Ordering::Acquire);
        let frame_count = self.frame_count.load(Ordering::Acquire);
        let host_present_in_flight = self.host_present_in_flight.load(Ordering::Acquire);

        let mut host_present_started_ns = 0u64;
        let mut host_present_count = 0u64;
        let mut host_present_thread_id = 0u64;
        let mut stalled_host_present = false;
        let mut blocked_host_present = false;
        if host_present_in_flight {
            host_present_started_ns = self.host_present_started_ns.load(Ordering::Acquire);
            host_present_count = self.host_present_count.load(Ordering::Acquire);
            host_present_thread_id = self.host_present_thread_id.load(Ordering::Acquire);
            stalled_host_present = self.host_present_lifecycle_epoch.load(Ordering::Acquire)
                == lifecycle_epoch
                && host_present_started_ns >= last_progress_ns
                && now_ticks_ns >= host_present_started_ns
                && now_ticks_ns - host_present_started_ns >= VULKAN_PRESENT_STALL_THRESHOLD_NS;
            blocked_host_present = stalled_host_present
                && (render_thread_id == 0 || host_present_thread_id == render_thread_id);
        }

        let mut call_name: *const c_char = std::ptr::null();
        let mut call_sequence = 0u64;
        let mut call_thread_id = 0u64;
        let mut baseline_ns = last_progress_ns;

        let mut oldest_active_call_name: *const c_char = std::ptr::null();
        let mut oldest_active_call_sequence = 0u64;
        let mut oldest_active_call_thread_id = 0u64;
        let mut oldest_active_call_started_ns = now_ticks_ns;
        let host_present_name_ptr = HOST_PRESENT_CALL_NAME.as_ptr() as *const c_char;
        if stalled_host_present && !blocked_host_present {
            oldest_active_call_name = host_present_name_ptr;
            oldest_active_call_sequence = host_present_count;
            oldest_active_call_thread_id = host_present_thread_id;
            oldest_active_call_started_ns = host_present_started_ns;
        }

        for slot in &self.call_slots {
            let sequence = slot.sequence.load(Ordering::Acquire);
            if sequence == 0 || sequence == RESERVED_CALL_SEQUENCE {
                continue;
            }
            let started_ns = slot.started_ns.load(Ordering::Relaxed);
            let candidate_name = slot.call_name.load(Ordering::Relaxed) as *const c_char;
            let candidate_thread_id = slot.thread_id.load(Ordering::Relaxed);
            let candidate_lifecycle_epoch = slot.lifecycle_epoch.load(Ordering::Relaxed);
            if slot.sequence.load(Ordering::Acquire) == sequence
                && candidate_lifecycle_epoch == lifecycle_epoch
                && !candidate_name.is_null()
                && now_ticks_ns >= started_ns
                && now_ticks_ns - started_ns >= VULKAN_PRESENT_STALL_THRESHOLD_NS
                && (oldest_active_call_sequence == 0
                    || started_ns < oldest_active_call_started_ns)
            {
                oldest_active_call_name = candidate_name;
                oldest_active_call_sequence = sequence;
                oldest_active_call_thread_id = candidate_thread_id;
                oldest_active_call_started_ns = started_ns;
            }
            if blocked_host_present
                || slot.sequence.load(Ordering::Acquire) != sequence
                || candidate_lifecycle_epoch != lifecycle_epoch
                || started_ns < last_progress_ns
                || now_ticks_ns < started_ns
                || now_ticks_ns - started_ns < VULKAN_PRESENT_STALL_THRESHOLD_NS
                || candidate_name.is_null()
                || (render_thread_id != 0 && candidate_thread_id != render_thread_id)
                || (call_sequence != 0 && started_ns >= baseline_ns)
            {
                continue;
            }
            baseline_ns = started_ns;
            call_name = candidate_name;
            call_sequence = sequence;
            call_thread_id = candidate_thread_id;
        }

        let mut report = MocktailRustVulkanPresentStallReport {
            stage: if blocked_host_present {
                2
            } else if call_sequence != 0 {
                1
            } else {
                0
            },
            call_name: if blocked_host_present {
                host_present_name_ptr
            } else {
                call_name
            },
            call_sequence: if blocked_host_present {
                host_present_count
            } else {
                call_sequence
            },
            thread_id: if blocked_host_present {
                host_present_thread_id
            } else {
                call_thread_id
            },
            elapsed_ns: now_ticks_ns
                - if blocked_host_present {
                    host_present_started_ns
                } else {
                    baseline_ns
                },
            frame_count,
            host_present_count: self.host_present_count.load(Ordering::Acquire),
            last_present_thread_id: render_thread_id,
            oldest_active_call_name,
            oldest_active_call_sequence,
            oldest_active_call_thread_id,
            oldest_active_call_elapsed_ns: if oldest_active_call_sequence != 0 {
                now_ticks_ns - oldest_active_call_started_ns
            } else {
                0
            },
            ..Default::default()
        };

        for _ in 0..2 {
            let record_version_before = self.last_call_record_version.load(Ordering::Acquire);
            if (record_version_before & 1) != 0 {
                continue;
            }
            let completed_name = self.last_call_name.load(Ordering::Relaxed) as *const c_char;
            let completed_sequence = self.last_call_sequence.load(Ordering::Relaxed);
            let completed_thread_id = self.last_call_thread_id.load(Ordering::Relaxed);
            let completed_started_ns = self.last_call_started_ns.load(Ordering::Relaxed);
            let completed_ns = self.last_call_completed_ns.load(Ordering::Relaxed);
            let completed_result = self.last_call_result.load(Ordering::Relaxed);
            let completed_lifecycle_epoch =
                self.last_call_lifecycle_epoch.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            let record_version_after = self.last_call_record_version.load(Ordering::Relaxed);
            if record_version_before != record_version_after || (record_version_after & 1) != 0 {
                continue;
            }
            report.last_completed_call_snapshot_coherent = true;
            if completed_lifecycle_epoch == lifecycle_epoch
                && (render_thread_id == 0 || completed_thread_id == render_thread_id)
            {
                report.last_completed_call_name = completed_name;
                report.last_completed_call_sequence = completed_sequence;
                report.last_completed_call_thread_id = completed_thread_id;
                report.last_completed_call_started_ns = completed_started_ns;
                report.last_completed_call_completed_ns = completed_ns;
                report.last_completed_call_result = completed_result;
            }
            break;
        }

        if !self.is_active()
            || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
            || self.last_present_lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
            || self.present_generation.load(Ordering::Acquire) != present_generation
            || self.last_progress_ns.load(Ordering::Acquire) != last_progress_ns
        {
            return None;
        }
        if blocked_host_present
            && (!self.host_present_in_flight.load(Ordering::Acquire)
                || self.host_present_lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
                || self.host_present_count.load(Ordering::Acquire) != host_present_count)
        {
            return None;
        }
        if call_sequence != 0 {
            let mut call_still_active = false;
            for slot in &self.call_slots {
                if slot.sequence.load(Ordering::Acquire) == call_sequence
                    && slot.lifecycle_epoch.load(Ordering::Relaxed) == lifecycle_epoch
                {
                    call_still_active = true;
                    break;
                }
            }
            if !call_still_active {
                return None;
            }
        }
        if blocked_host_present {
            if self
                .reported_host_present_count
                .swap(host_present_count, Ordering::AcqRel)
                == host_present_count
            {
                return None;
            }
            self.reported_stall_generation
                .store(present_generation, Ordering::Release);
        } else if call_sequence != 0 {
            if self
                .reported_call_sequence
                .swap(call_sequence, Ordering::AcqRel)
                == call_sequence
            {
                return None;
            }
            self.reported_stall_generation
                .store(present_generation, Ordering::Release);
        } else if self
            .reported_stall_generation
            .swap(present_generation, Ordering::AcqRel)
            == present_generation
        {
            return None;
        }
        Some(report)
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_new() -> *mut c_void {
    Box::into_raw(Box::new(RustVulkanPresentProgressGate::default())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut RustVulkanPresentProgressGate));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_activate(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.activate()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_deactivate(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.deactivate();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_notify_host_present_begin(
    ptr: *mut c_void,
    now_ticks_ns: u64,
    thread_id: u64,
) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.notify_host_present_begin(now_ticks_ns, thread_id)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_notify_host_present_end(
    ptr: *mut c_void,
    sequence: u64,
) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.notify_host_present_end(sequence);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_notify_call_begin(
    ptr: *mut c_void,
    call_name: *const c_char,
    now_ticks_ns: u64,
    thread_id: u64,
) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.notify_call_begin(call_name, now_ticks_ns, thread_id)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_notify_call_end(
    ptr: *mut c_void,
    sequence: u64,
    result: i32,
    now_ticks_ns: u64,
    thread_id: u64,
) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.notify_call_end(sequence, result, now_ticks_ns, thread_id);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_notify_frame_presented(
    ptr: *mut c_void,
    now_ticks_ns: u64,
    frame_count: u64,
    thread_id: u64,
) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    gate.notify_frame_presented(now_ticks_ns, frame_count, thread_id);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_present_progress_gate_poll(
    ptr: *mut c_void,
    now_ticks_ns: u64,
    window_can_present: bool,
    out_report: *mut MocktailRustVulkanPresentStallReport,
) -> bool {
    if ptr.is_null() || out_report.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustVulkanPresentProgressGate) };
    match gate.poll(now_ticks_ns, window_can_present) {
        Some(report) => {
            unsafe {
                *out_report = report;
            }
            true
        }
        None => false,
    }
}

// ============================================================================
// 127 & 129. Shared Callback Drain Gate (WindowFullscreenStateSync & PlatformEventObserverGate)
// ============================================================================

pub type MocktailRustFullscreenStateSyncCb = unsafe extern "C" fn(*mut c_void, bool) -> bool;
pub type MocktailRustPlatformEventDispatchFn = unsafe extern "C" fn(*mut c_void, *const c_void);
pub type MocktailRustDestroyTargetFn = unsafe extern "C" fn(*mut c_void);

#[derive(Clone, Copy)]
struct CallbackTarget {
    callback: usize,
    context: usize,
    destroy: Option<MocktailRustDestroyTargetFn>,
}

impl CallbackTarget {
    fn destroy_now(self) {
        if let Some(destroy_fn) = self.destroy {
            unsafe {
                destroy_fn(self.context as *mut c_void);
            }
        }
    }
}

struct DrainGateInner {
    target: Option<CallbackTarget>,
    in_flight: usize,
    clearing: bool,
    active: bool,
}

struct SharedCallbackDrainGate {
    inner: Mutex<DrainGateInner>,
    cv: Condvar,
}

impl Drop for SharedCallbackDrainGate {
    fn drop(&mut self) {
        let stale = lock_unpoisoned(&self.inner).target.take();
        if let Some(target) = stale {
            target.destroy_now();
        }
    }
}

struct DrainFinishGuard<'a>(&'a SharedCallbackDrainGate);

impl Drop for DrainFinishGuard<'_> {
    fn drop(&mut self) {
        let mut inner = lock_unpoisoned(&self.0.inner);
        inner.in_flight -= 1;
        drop(inner);
        self.0.cv.notify_all();
    }
}

impl SharedCallbackDrainGate {
    fn new(initially_active: bool) -> Self {
        Self {
            inner: Mutex::new(DrainGateInner {
                target: None,
                in_flight: 0,
                clearing: false,
                active: initially_active,
            }),
            cv: Condvar::new(),
        }
    }

    fn activate(&self) -> bool {
        let mut inner = lock_unpoisoned(&self.inner);
        if inner.active {
            return false;
        }
        let stale = inner.target.take();
        inner.clearing = false;
        inner.active = true;
        drop(inner);
        if let Some(target) = stale {
            target.destroy_now();
        }
        true
    }

    fn deactivate(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        inner.active = false;
        let stale = inner.target.take();
        let _inner = wait_while_unpoisoned(&self.cv, inner, |s| s.in_flight != 0);
        drop(_inner);
        if let Some(target) = stale {
            target.destroy_now();
        }
    }

    fn register(
        &self,
        callback: usize,
        context: usize,
        destroy: Option<MocktailRustDestroyTargetFn>,
    ) -> bool {
        if callback == 0 || context == 0 {
            return false;
        }
        let mut inner = lock_unpoisoned(&self.inner);
        if !inner.active || inner.clearing || inner.target.is_some() {
            return false;
        }
        inner.target = Some(CallbackTarget {
            callback,
            context,
            destroy,
        });
        true
    }

    fn clear(&self) {
        let mut inner = wait_while_unpoisoned(&self.cv, lock_unpoisoned(&self.inner), |s| {
            s.clearing
        });
        inner.clearing = true;
        let stale = inner.target.take();
        let mut inner = wait_while_unpoisoned(&self.cv, inner, |s| s.in_flight != 0);
        inner.clearing = false;
        drop(inner);
        self.cv.notify_all();
        if let Some(target) = stale {
            target.destroy_now();
        }
    }

    fn has_target(&self) -> bool {
        let inner = lock_unpoisoned(&self.inner);
        inner.active && inner.target.is_some()
    }

    fn enter(&self) -> Option<(CallbackTarget, DrainFinishGuard<'_>)> {
        let mut inner = lock_unpoisoned(&self.inner);
        if !inner.active {
            return None;
        }
        let target = inner.target?;
        inner.in_flight += 1;
        drop(inner);
        Some((target, DrainFinishGuard(self)))
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_state_sync_new() -> *mut c_void {
    Box::into_raw(Box::new(SharedCallbackDrainGate::new(true))) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_state_sync_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut SharedCallbackDrainGate));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_state_sync_register(
    ptr: *mut c_void,
    callback: Option<MocktailRustFullscreenStateSyncCb>,
    context: *mut c_void,
) -> bool {
    let Some(cb) = callback else {
        return false;
    };
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    gate.register(cb as usize, context as usize, None)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_state_sync_notify(
    ptr: *mut c_void,
    fullscreen: bool,
) -> bool {
    if ptr.is_null() {
        return true;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    let Some((target, _guard)) = gate.enter() else {
        return true;
    };
    let cb: MocktailRustFullscreenStateSyncCb = unsafe { std::mem::transmute(target.callback) };
    unsafe { cb(target.context as *mut c_void, fullscreen) }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_state_sync_clear(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    gate.clear();
}

// ============================================================================
// 128. Main Thread Command Gate
// ============================================================================

pub type MocktailRustMainThreadCommandCb = unsafe extern "C" fn(*mut c_void) -> bool;

#[derive(Default)]
struct MainThreadCommandInner {
    callback: Option<MocktailRustMainThreadCommandCb>,
    context: usize,
    in_flight: usize,
    invoking_thread: Option<ThreadId>,
    active: bool,
}

struct RustMainThreadCommandGate {
    registered: AtomicBool,
    inner: Mutex<MainThreadCommandInner>,
    cv: Condvar,
}

impl Default for RustMainThreadCommandGate {
    fn default() -> Self {
        Self {
            registered: AtomicBool::new(false),
            inner: Mutex::new(MainThreadCommandInner::default()),
            cv: Condvar::new(),
        }
    }
}

struct MainThreadInvokeGuard<'a>(&'a RustMainThreadCommandGate);

impl Drop for MainThreadInvokeGuard<'_> {
    fn drop(&mut self) {
        let mut inner = lock_unpoisoned(&self.0.inner);
        inner.in_flight -= 1;
        if inner.in_flight == 0 {
            inner.invoking_thread = None;
        }
        drop(inner);
        self.0.cv.notify_all();
    }
}

impl RustMainThreadCommandGate {
    fn activate(&self) {
        lock_unpoisoned(&self.inner).active = true;
    }

    fn register(
        &self,
        callback: Option<MocktailRustMainThreadCommandCb>,
        context: *mut c_void,
    ) -> bool {
        let Some(cb) = callback else {
            return false;
        };
        if context.is_null() {
            return false;
        }
        let mut inner = lock_unpoisoned(&self.inner);
        if !inner.active || inner.callback.is_some() {
            return false;
        }
        inner.callback = Some(cb);
        inner.context = context as usize;
        self.registered.store(true, Ordering::Release);
        true
    }

    fn invoke(&self) -> bool {
        if !self.registered.load(Ordering::Acquire) {
            return true;
        }
        let (cb, ctx) = {
            let mut inner = lock_unpoisoned(&self.inner);
            if !inner.active {
                return true;
            }
            let Some(cb) = inner.callback else {
                return true;
            };
            let ctx = inner.context as *mut c_void;
            inner.invoking_thread = Some(std::thread::current().id());
            inner.in_flight += 1;
            (cb, ctx)
        };
        let _guard = MainThreadInvokeGuard(self);
        unsafe { cb(ctx) }
    }

    fn clear(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        self.registered.store(false, Ordering::Release);
        inner.callback = None;
        inner.context = 0;
        let is_same_thread = inner.invoking_thread == Some(std::thread::current().id());
        if !is_same_thread {
            let _inner = wait_while_unpoisoned(&self.cv, inner, |s| s.in_flight != 0);
        }
    }

    fn deactivate(&self) {
        self.clear();
        lock_unpoisoned(&self.inner).active = false;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_new() -> *mut c_void {
    Box::into_raw(Box::new(RustMainThreadCommandGate::default())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut RustMainThreadCommandGate));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_activate(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustMainThreadCommandGate) };
    gate.activate();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_register(
    ptr: *mut c_void,
    callback: Option<MocktailRustMainThreadCommandCb>,
    context: *mut c_void,
) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustMainThreadCommandGate) };
    gate.register(callback, context)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_invoke(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return true;
    }
    let gate = unsafe { &*(ptr as *const RustMainThreadCommandGate) };
    gate.invoke()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_clear(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustMainThreadCommandGate) };
    gate.clear();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_main_thread_command_gate_deactivate(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustMainThreadCommandGate) };
    gate.deactivate();
}

// ============================================================================
// 129. Platform Event Observer Gate
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_new() -> *mut c_void {
    Box::into_raw(Box::new(SharedCallbackDrainGate::new(false))) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_free(ptr: *mut c_void) {
    mocktail_rust_window_fullscreen_state_sync_free(ptr);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_activate(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    gate.activate()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_deactivate(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    gate.deactivate();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_register(
    ptr: *mut c_void,
    dispatch: Option<MocktailRustPlatformEventDispatchFn>,
    target_box: *mut c_void,
    destroy_target: Option<MocktailRustDestroyTargetFn>,
) -> bool {
    let Some(dispatch_fn) = dispatch else {
        return false;
    };
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    gate.register(dispatch_fn as usize, target_box as usize, destroy_target)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_clear(ptr: *mut c_void) {
    mocktail_rust_window_fullscreen_state_sync_clear(ptr);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_has_observer(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    gate.has_target()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_event_observer_gate_notify(
    ptr: *mut c_void,
    event_ptr: *const c_void,
) {
    if ptr.is_null() || event_ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const SharedCallbackDrainGate) };
    let Some((target, _guard)) = gate.enter() else {
        return;
    };
    let dispatch_fn: MocktailRustPlatformEventDispatchFn =
        unsafe { std::mem::transmute(target.callback) };
    unsafe { dispatch_fn(target.context as *mut c_void, event_ptr) };
}

// ============================================================================
// 130. Present Observer Registry & Present Lifecycle Gate
// ============================================================================

pub type MocktailRustPresentObserverCb = unsafe extern "C" fn(*mut c_void, u64);

#[derive(Default)]
struct ObserverSlot {
    observer: Option<MocktailRustPresentObserverCb>,
    context: usize,
}

#[derive(Default)]
struct RustPresentObserverRegistry {
    inner: Mutex<ObserverSlot>,
}

impl RustPresentObserverRegistry {
    fn register(&self, observer: Option<MocktailRustPresentObserverCb>, context: *mut c_void) -> bool {
        let Some(obs) = observer else {
            return false;
        };
        if context.is_null() {
            return false;
        }
        let mut inner = lock_unpoisoned(&self.inner);
        if inner.observer.is_some() {
            return false;
        }
        inner.observer = Some(obs);
        inner.context = context as usize;
        true
    }

    fn clear(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        inner.observer = None;
        inner.context = 0;
    }

    fn notify(&self, frame_serial: u64) {
        let inner = lock_unpoisoned(&self.inner);
        if let Some(obs) = inner.observer {
            unsafe { obs(inner.context as *mut c_void, frame_serial) };
        }
    }
}

#[derive(Default)]
struct LifecycleGateState {
    active: bool,
    busy: bool,
}

#[derive(Default)]
struct RustPresentLifecycleGate {
    state: Mutex<LifecycleGateState>,
    cv: Condvar,
    observers: RustPresentObserverRegistry,
}

struct LifecycleOpGuard<'a>(&'a RustPresentLifecycleGate);

impl Drop for LifecycleOpGuard<'_> {
    fn drop(&mut self) {
        self.0.release_lifecycle_lock();
    }
}

impl RustPresentLifecycleGate {
    fn acquire_lifecycle_lock(&self) -> LifecycleOpGuard<'_> {
        let mut state = wait_while_unpoisoned(&self.cv, lock_unpoisoned(&self.state), |s| s.busy);
        state.busy = true;
        LifecycleOpGuard(self)
    }

    fn release_lifecycle_lock(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.busy = false;
        drop(state);
        self.cv.notify_all();
    }

    fn activate(&self) -> bool {
        let _guard = self.acquire_lifecycle_lock();
        if lock_unpoisoned(&self.state).active {
            return false;
        }
        self.observers.clear();
        lock_unpoisoned(&self.state).active = true;
        true
    }

    fn deactivate(&self) {
        let _guard = self.acquire_lifecycle_lock();
        lock_unpoisoned(&self.state).active = false;
        self.observers.clear();
    }

    fn register(&self, observer: Option<MocktailRustPresentObserverCb>, context: *mut c_void) -> bool {
        let _guard = self.acquire_lifecycle_lock();
        if !lock_unpoisoned(&self.state).active {
            return false;
        }
        self.observers.register(observer, context)
    }

    fn clear(&self) {
        let _guard = self.acquire_lifecycle_lock();
        self.observers.clear();
    }

    fn enter_present(&self) -> bool {
        let mut state = wait_while_unpoisoned(&self.cv, lock_unpoisoned(&self.state), |s| s.busy);
        if !state.active {
            return false;
        }
        state.busy = true;
        true
    }

    fn notify_observer_in_scope(&self, frame_serial: u64) {
        self.observers.notify(frame_serial);
    }

    fn exit_present(&self) {
        self.release_lifecycle_lock();
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_observer_registry_new() -> *mut c_void {
    Box::into_raw(Box::new(RustPresentObserverRegistry::default())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_observer_registry_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut RustPresentObserverRegistry));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_observer_registry_register(
    ptr: *mut c_void,
    observer: Option<MocktailRustPresentObserverCb>,
    context: *mut c_void,
) -> bool {
    if ptr.is_null() {
        return false;
    }
    let registry = unsafe { &*(ptr as *const RustPresentObserverRegistry) };
    registry.register(observer, context)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_observer_registry_clear(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let registry = unsafe { &*(ptr as *const RustPresentObserverRegistry) };
    registry.clear();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_observer_registry_notify(
    ptr: *mut c_void,
    frame_serial: u64,
) {
    if ptr.is_null() {
        return;
    }
    let registry = unsafe { &*(ptr as *const RustPresentObserverRegistry) };
    registry.notify(frame_serial);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_new() -> *mut c_void {
    Box::into_raw(Box::new(RustPresentLifecycleGate::default())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut RustPresentLifecycleGate));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_activate(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.activate()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_deactivate(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.deactivate();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_register(
    ptr: *mut c_void,
    observer: Option<MocktailRustPresentObserverCb>,
    context: *mut c_void,
) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.register(observer, context)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_clear(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.clear();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_enter_present(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.enter_present()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_notify_observer(
    ptr: *mut c_void,
    frame_serial: u64,
) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.notify_observer_in_scope(frame_serial);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_lifecycle_gate_exit_present(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let gate = unsafe { &*(ptr as *const RustPresentLifecycleGate) };
    gate.exit_present();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_input_pump_pacer_rebase_and_saturate() {
        let pacer = mocktail_rust_input_pump_pacer_new(4_000_000);
        assert!(!pacer.is_null());
        assert_eq!(mocktail_rust_input_pump_pacer_delay_before_next_pump(pacer, 1_000_000), 0);
        assert_eq!(
            mocktail_rust_input_pump_pacer_delay_before_next_pump(pacer, 2_000_000),
            3_000_000
        );
        assert_eq!(
            mocktail_rust_input_pump_pacer_delay_before_next_pump(pacer, 20_000_000),
            0
        );
        mocktail_rust_input_pump_pacer_reset(pacer);
        assert_eq!(
            mocktail_rust_input_pump_pacer_delay_before_next_pump(pacer, u64::MAX - 10),
            0
        );
        mocktail_rust_input_pump_pacer_free(pacer);
    }

    #[test]
    fn test_vulkan_surface_recovery_gate_coalesce_and_retry() {
        let gate = mocktail_rust_vulkan_surface_recovery_gate_new();
        let mut req = MocktailRustVulkanSurfaceRecoveryRequest::default();
        assert!(!mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
            gate, 1, &mut req
        ));
        assert!(mocktail_rust_vulkan_surface_recovery_gate_activate(gate));
        assert!(!mocktail_rust_vulkan_surface_recovery_gate_activate(gate));

        mocktail_rust_vulkan_surface_recovery_gate_notify_out_of_date(gate);
        mocktail_rust_vulkan_surface_recovery_gate_notify_out_of_date(gate);
        assert!(mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
            gate, 1000, &mut req
        ));
        assert_eq!(req.observed_error_count, 2);
        assert_eq!(req.coalesced_error_count, 2);
        assert!(!req.retry);

        mocktail_rust_vulkan_surface_recovery_gate_notify_out_of_date(gate);
        assert!(!mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
            gate,
            1000 + VULKAN_SURFACE_RECOVERY_RETRY_INTERVAL_NS - 1,
            &mut req
        ));
        assert!(mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
            gate,
            1000 + VULKAN_SURFACE_RECOVERY_RETRY_INTERVAL_NS,
            &mut req
        ));
        assert!(req.retry);
        mocktail_rust_vulkan_surface_recovery_gate_free(gate);
    }

    #[test]
    fn test_vulkan_present_progress_gate_stages_and_seqlock() {
        let gate = mocktail_rust_vulkan_present_progress_gate_new();
        assert!(mocktail_rust_vulkan_present_progress_gate_activate(gate));
        mocktail_rust_vulkan_present_progress_gate_notify_frame_presented(gate, 1000, 5, 77);
        let name = b"vkResetFences\0";
        let seq = mocktail_rust_vulkan_present_progress_gate_notify_call_begin(
            gate,
            name.as_ptr() as *const c_char,
            1100,
            77,
        );
        assert_ne!(seq, 0);
        mocktail_rust_vulkan_present_progress_gate_notify_call_end(gate, seq, -7, 1150, 77);

        let mut report = MocktailRustVulkanPresentStallReport::default();
        assert!(mocktail_rust_vulkan_present_progress_gate_poll(
            gate,
            1000 + VULKAN_PRESENT_STALL_THRESHOLD_NS,
            true,
            &mut report
        ));
        assert_eq!(report.stage, 0);
        assert!(report.last_completed_call_snapshot_coherent);
        assert_eq!(report.last_completed_call_sequence, seq);
        assert_eq!(report.last_completed_call_result, -7);
        mocktail_rust_vulkan_present_progress_gate_free(gate);
    }

    #[test]
    fn test_main_thread_command_gate_reentrant_clear() {
        let gate = mocktail_rust_main_thread_command_gate_new();
        unsafe extern "C" fn reentrant_cb(ctx: *mut c_void) -> bool {
            mocktail_rust_main_thread_command_gate_clear(ctx);
            true
        }
        mocktail_rust_main_thread_command_gate_activate(gate);
        assert!(mocktail_rust_main_thread_command_gate_register(
            gate,
            Some(reentrant_cb),
            gate
        ));
        assert!(mocktail_rust_main_thread_command_gate_invoke(gate));
        mocktail_rust_main_thread_command_gate_deactivate(gate);
        mocktail_rust_main_thread_command_gate_free(gate);
    }

    #[test]
    fn test_fullscreen_and_present_lifecycle_gates() {
        let fs_gate = mocktail_rust_window_fullscreen_state_sync_new();
        let called = Arc::new(AtomicBool::new(false));
        unsafe extern "C" fn fs_cb(ctx: *mut c_void, fs: bool) -> bool {
            let flag = &*(ctx as *const AtomicBool);
            flag.store(fs, Ordering::Release);
            true
        }
        assert!(mocktail_rust_window_fullscreen_state_sync_register(
            fs_gate,
            Some(fs_cb),
            Arc::as_ptr(&called) as *mut c_void
        ));
        assert!(mocktail_rust_window_fullscreen_state_sync_notify(fs_gate, true));
        assert!(called.load(Ordering::Acquire));
        mocktail_rust_window_fullscreen_state_sync_clear(fs_gate);
        mocktail_rust_window_fullscreen_state_sync_free(fs_gate);

        let present_gate = mocktail_rust_present_lifecycle_gate_new();
        assert!(!mocktail_rust_present_lifecycle_gate_enter_present(present_gate));
        assert!(mocktail_rust_present_lifecycle_gate_activate(present_gate));
        assert!(mocktail_rust_present_lifecycle_gate_enter_present(present_gate));
        mocktail_rust_present_lifecycle_gate_exit_present(present_gate);
        mocktail_rust_present_lifecycle_gate_deactivate(present_gate);
        mocktail_rust_present_lifecycle_gate_free(present_gate);
    }
}
