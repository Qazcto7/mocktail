//! Pure-Rust Linux epoll + eventfd ALooper implementation backing `libandroid.so`.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const K_POLL_WAKE: c_int = -1;
const K_POLL_CALLBACK: c_int = -2;
const K_POLL_TIMEOUT: c_int = -3;
const K_POLL_ERROR: c_int = -4;
const K_PREPARE_ALLOW_NON_CALLBACKS: c_int = 1 << 0;
const K_WAKE_TOKEN: u64 = 0;

pub type ALooperCallbackFn = extern "C" fn(c_int, c_int, *mut c_void) -> c_int;

#[derive(Clone, Copy)]
struct LooperRegistration {
    fd: c_int,
    ident: c_int,
    callback: Option<ALooperCallbackFn>,
    data: *mut c_void,
    token: u64,
}

unsafe impl Send for LooperRegistration {}
unsafe impl Sync for LooperRegistration {}

#[derive(Clone, Copy)]
struct LooperResponse {
    registration: LooperRegistration,
    events: c_int,
}

unsafe impl Send for LooperResponse {}

struct LooperInner {
    token_by_fd: HashMap<c_int, u64>,
    registrations_by_token: HashMap<u64, LooperRegistration>,
    next_token: u64,
}

struct PollState {
    epoll_scratch: Vec<libc::epoll_event>,
    responses_scratch: Vec<LooperResponse>,
    pending_responses: VecDeque<LooperResponse>,
}

pub struct RustALooper {
    allow_non_callbacks: bool,
    epoll_fd: c_int,
    wake_fd: c_int,
    refs: AtomicU32,
    polling: AtomicBool,
    inner: Mutex<LooperInner>,
    poll_state: Mutex<PollState>,
}

impl RustALooper {
    fn new(requested_opts: c_int) -> Option<Box<Self>> {
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return None;
        }
        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if wake_fd < 0 {
            unsafe { libc::close(epoll_fd) };
            return None;
        }

        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: K_WAKE_TOKEN,
        };
        if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, wake_fd, &mut event) } != 0 {
            unsafe {
                libc::close(epoll_fd);
                libc::close(wake_fd);
            }
            return None;
        }

        Some(Box::new(Self {
            allow_non_callbacks: (requested_opts & K_PREPARE_ALLOW_NON_CALLBACKS) != 0,
            epoll_fd,
            wake_fd,
            refs: AtomicU32::new(1),
            polling: AtomicBool::new(false),
            inner: Mutex::new(LooperInner {
                token_by_fd: HashMap::new(),
                registrations_by_token: HashMap::new(),
                next_token: 1,
            }),
            poll_state: Mutex::new(PollState {
                epoll_scratch: vec![libc::epoll_event { events: 0, u64: 0 }; 16],
                responses_scratch: Vec::with_capacity(16),
                pending_responses: VecDeque::new(),
            }),
        }))
    }

    fn valid(&self) -> bool {
        self.epoll_fd >= 0 && self.wake_fd >= 0
    }
}

impl Drop for RustALooper {
    fn drop(&mut self) {
        if self.epoll_fd >= 0 {
            unsafe { libc::close(self.epoll_fd) };
            self.epoll_fd = -1;
        }
        if self.wake_fd >= 0 {
            unsafe { libc::close(self.wake_fd) };
            self.wake_fd = -1;
        }
    }
}

struct ThreadLooperHolder {
    ptr: *mut RustALooper,
}

impl Drop for ThreadLooperHolder {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { mocktail_rust_alooper_release(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

thread_local! {
    static TLS_LOOPER: RefCell<ThreadLooperHolder> = const {
        RefCell::new(ThreadLooperHolder { ptr: std::ptr::null_mut() })
    };
}

#[inline]
unsafe fn set_errno(val: c_int) {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location() = val;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = val;
}

#[inline]
unsafe fn last_errno() -> c_int {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location()
    }
    #[cfg(not(target_os = "linux"))]
    {
        libc::EINVAL
    }
}

#[inline]
fn epoll_events_from_android(events: c_int) -> u32 {
    let mut result = 0u32;
    if (events & (1 << 0)) != 0 {
        result |= libc::EPOLLIN as u32;
    }
    if (events & (1 << 1)) != 0 {
        result |= libc::EPOLLOUT as u32;
    }
    result
}

#[inline]
fn android_events_from_epoll(events: u32) -> c_int {
    let mut result = 0;
    if (events & (libc::EPOLLIN as u32)) != 0 {
        result |= 1 << 0;
    }
    if (events & (libc::EPOLLOUT as u32)) != 0 {
        result |= 1 << 1;
    }
    if (events & (libc::EPOLLERR as u32)) != 0 {
        result |= 1 << 2;
    }
    if (events & (libc::EPOLLHUP as u32)) != 0 {
        result |= 1 << 3;
    }
    result
}

fn next_registration_token_locked(inner: &mut LooperInner) -> u64 {
    loop {
        let token = inner.next_token;
        inner.next_token = inner.next_token.wrapping_add(1);
        if inner.next_token == K_WAKE_TOKEN {
            inner.next_token = 1;
        }
        if token != K_WAKE_TOKEN && !inner.registrations_by_token.contains_key(&token) {
            return token;
        }
    }
}

fn remove_fd_locked(inner: &mut LooperInner, epoll_fd: c_int, fd: c_int, expected_token: u64) -> c_int {
    let Some(&token) = inner.token_by_fd.get(&fd) else {
        return 0;
    };
    if expected_token != 0 && token != expected_token {
        return 0;
    }
    let ctl_result = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
    let ctl_errno = unsafe { last_errno() };
    if ctl_result != 0 && ctl_errno != libc::ENOENT && ctl_errno != libc::EBADF {
        unsafe { set_errno(ctl_errno) };
        return -1;
    }
    inner.token_by_fd.remove(&fd);
    inner.registrations_by_token.remove(&token);
    1
}

fn registration_is_current(looper: &RustALooper, reg: &LooperRegistration) -> bool {
    let guard = looper.inner.lock().unwrap_or_else(|e| e.into_inner());
    guard.token_by_fd.get(&reg.fd) == Some(&reg.token)
        && guard.registrations_by_token.contains_key(&reg.token)
}

unsafe fn clear_poll_outputs(
    out_fd: *mut c_int,
    out_events: *mut c_int,
    out_data: *mut *mut c_void,
) {
    if !out_fd.is_null() {
        *out_fd = 0;
    }
    if !out_events.is_null() {
        *out_events = 0;
    }
    if !out_data.is_null() {
        *out_data = std::ptr::null_mut();
    }
}

unsafe fn take_pending_ident(
    looper: &RustALooper,
    pending: &mut VecDeque<LooperResponse>,
    out_fd: *mut c_int,
    out_events: *mut c_int,
    out_data: *mut *mut c_void,
) -> Option<c_int> {
    while let Some(response) = pending.pop_front() {
        if !registration_is_current(looper, &response.registration)
            || response.registration.callback.is_some()
        {
            continue;
        }
        if !out_fd.is_null() {
            *out_fd = response.registration.fd;
        }
        if !out_events.is_null() {
            *out_events = response.events;
        }
        if !out_data.is_null() {
            *out_data = response.registration.data;
        }
        return Some(response.registration.ident);
    }
    None
}

fn remaining_poll_timeout(original_timeout: c_int, deadline: Option<Instant>) -> c_int {
    if original_timeout < 0 {
        return -1;
    }
    if original_timeout == 0 {
        return 0;
    }
    let Some(dl) = deadline else {
        return 0;
    };
    let now = Instant::now();
    if now >= dl {
        return 0;
    }
    let rem = dl.duration_since(now);
    let mut millis = rem.as_millis();
    if u128::from(rem.subsec_nanos() % 1_000_000) != 0 {
        millis = millis.saturating_add(1);
    }
    millis.min(c_int::MAX as u128) as c_int
}

#[no_mangle]
pub extern "C" fn mocktail_rust_alooper_for_thread() -> *mut RustALooper {
    TLS_LOOPER.with(|cell| cell.borrow().ptr)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_alooper_prepare(opts: c_int) -> *mut RustALooper {
    TLS_LOOPER.with(|cell| {
        let mut holder = cell.borrow_mut();
        if !holder.ptr.is_null() {
            return holder.ptr;
        }
        let Some(boxed) = RustALooper::new(opts) else {
            return std::ptr::null_mut();
        };
        let ptr = Box::into_raw(boxed);
        holder.ptr = ptr;
        ptr
    })
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_acquire(looper: *mut RustALooper) {
    if let Some(l) = looper.as_ref() {
        l.refs.fetch_add(1, Ordering::Relaxed);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_release(looper: *mut RustALooper) {
    if looper.is_null() {
        return;
    }
    if (*looper).refs.fetch_sub(1, Ordering::AcqRel) == 1 {
        drop(Box::from_raw(looper));
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_add_fd(
    looper_ptr: *mut RustALooper,
    fd: c_int,
    ident: c_int,
    events: c_int,
    callback: Option<ALooperCallbackFn>,
    data: *mut c_void,
) -> c_int {
    let Some(looper) = looper_ptr.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let callback_ident_valid = ident >= 0 || ident == K_POLL_CALLBACK;
    if !looper.valid()
        || fd < 0
        || (callback.is_none() && (!looper.allow_non_callbacks || ident < 0))
        || (callback.is_some() && !callback_ident_valid)
    {
        set_errno(libc::EINVAL);
        return -1;
    }

    let mut guard = looper.inner.lock().unwrap_or_else(|e| e.into_inner());
    let old_token = guard.token_by_fd.get(&fd).copied();
    let update = old_token.is_some();
    let token = next_registration_token_locked(&mut guard);
    let registration = LooperRegistration {
        fd,
        ident: if callback.is_some() { K_POLL_CALLBACK } else { ident },
        callback,
        data,
        token,
    };

    let mut ev = libc::epoll_event {
        events: epoll_events_from_android(events),
        u64: token,
    };
    let mut op = if update { libc::EPOLL_CTL_MOD } else { libc::EPOLL_CTL_ADD };
    let mut ctl_result = libc::epoll_ctl(looper.epoll_fd, op, fd, &mut ev);
    if ctl_result != 0 && update && last_errno() == libc::ENOENT {
        op = libc::EPOLL_CTL_ADD;
        ctl_result = libc::epoll_ctl(looper.epoll_fd, op, fd, &mut ev);
    } else if ctl_result != 0 && !update && last_errno() == libc::EEXIST {
        op = libc::EPOLL_CTL_MOD;
        ctl_result = libc::epoll_ctl(looper.epoll_fd, op, fd, &mut ev);
    }
    if ctl_result != 0 {
        return -1;
    }

    if let Some(prev) = old_token {
        guard.registrations_by_token.remove(&prev);
    }
    guard.token_by_fd.insert(fd, token);
    guard.registrations_by_token.insert(token, registration);
    1
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_remove_fd(
    looper_ptr: *mut RustALooper,
    fd: c_int,
) -> c_int {
    let Some(looper) = looper_ptr.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if !looper.valid() || fd < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut guard = looper.inner.lock().unwrap_or_else(|e| e.into_inner());
    remove_fd_locked(&mut guard, looper.epoll_fd, fd, 0)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_wake(looper_ptr: *mut RustALooper) {
    let Some(looper) = looper_ptr.as_ref() else {
        return;
    };
    if looper.wake_fd < 0 {
        return;
    }
    let value: u64 = 1;
    loop {
        let written = libc::write(
            looper.wake_fd,
            (&value as *const u64).cast::<c_void>(),
            std::mem::size_of::<u64>(),
        );
        if written >= 0 || last_errno() != libc::EINTR {
            break;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_is_polling(looper_ptr: *mut RustALooper) -> bool {
    looper_ptr
        .as_ref()
        .is_some_and(|l| l.polling.load(Ordering::Acquire))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_poll_once(
    timeout_ms: c_int,
    out_fd: *mut c_int,
    out_events: *mut c_int,
    out_data: *mut *mut c_void,
) -> c_int {
    clear_poll_outputs(out_fd, out_events, out_data);
    let looper_ptr = mocktail_rust_alooper_for_thread();
    let Some(looper) = looper_ptr.as_ref() else {
        return K_POLL_ERROR;
    };
    if !looper.valid() {
        return K_POLL_ERROR;
    }

    let mut poll = looper.poll_state.lock().unwrap_or_else(|e| e.into_inner());
    let PollState {
        ref mut epoll_scratch,
        ref mut responses_scratch,
        ref mut pending_responses,
    } = *poll;
    if let Some(ident) = take_pending_ident(looper, pending_responses, out_fd, out_events, out_data)
    {
        return ident;
    }

    let deadline = if timeout_ms > 0 {
        Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
    } else {
        None
    };
    let mut wait_timeout = timeout_ms;

    loop {
        let cap_needed = {
            let guard = looper.inner.lock().unwrap_or_else(|e| e.into_inner());
            1 + guard.registrations_by_token.len()
        };
        if cap_needed > c_int::MAX as usize {
            set_errno(libc::EOVERFLOW);
            return K_POLL_ERROR;
        }
        if epoll_scratch.len() < cap_needed {
            epoll_scratch.resize(cap_needed, libc::epoll_event { events: 0, u64: 0 });
        }
        let max_events = epoll_scratch.len() as c_int;

        looper.polling.store(true, Ordering::Release);
        let ready = libc::epoll_wait(
            looper.epoll_fd,
            epoll_scratch.as_mut_ptr(),
            max_events,
            wait_timeout,
        );
        let wait_errno = last_errno();
        looper.polling.store(false, Ordering::Release);

        if ready == 0 {
            return K_POLL_TIMEOUT;
        }
        if ready < 0 {
            if wait_errno != libc::EINTR {
                set_errno(wait_errno);
                return K_POLL_ERROR;
            }
            wait_timeout = remaining_poll_timeout(timeout_ms, deadline);
            continue;
        }

        let mut had_wake = false;
        responses_scratch.clear();
        for ev in epoll_scratch.iter().take(ready as usize) {
            if ev.u64 == K_WAKE_TOKEN {
                let mut value: u64 = 0;
                loop {
                    let rd = libc::read(
                        looper.wake_fd,
                        (&mut value as *mut u64).cast::<c_void>(),
                        std::mem::size_of::<u64>(),
                    );
                    if rd >= 0 || last_errno() != libc::EINTR {
                        break;
                    }
                }
                had_wake = true;
            }
        }

        {
            let guard = looper.inner.lock().unwrap_or_else(|e| e.into_inner());
            for ev in epoll_scratch.iter().take(ready as usize) {
                let token = ev.u64;
                if token == K_WAKE_TOKEN {
                    continue;
                }
                if let Some(&reg) = guard.registrations_by_token.get(&token) {
                    responses_scratch.push(LooperResponse {
                        registration: reg,
                        events: android_events_from_epoll(ev.events),
                    });
                }
            }
        }

        let mut invoked_callback = false;
        for response in responses_scratch.iter() {
            let Some(cb) = response.registration.callback else {
                continue;
            };
            let keep = cb(
                response.registration.fd,
                response.events,
                response.registration.data,
            );
            invoked_callback = true;
            if keep == 0 {
                let mut guard = looper.inner.lock().unwrap_or_else(|e| e.into_inner());
                let _ = remove_fd_locked(
                    &mut guard,
                    looper.epoll_fd,
                    response.registration.fd,
                    response.registration.token,
                );
            }
        }

        for response in responses_scratch.iter() {
            if response.registration.callback.is_none() {
                pending_responses.push_back(*response);
            }
        }

        if let Some(ident) =
            take_pending_ident(looper, pending_responses, out_fd, out_events, out_data)
        {
            return ident;
        }

        if invoked_callback {
            return K_POLL_CALLBACK;
        }
        if had_wake {
            return K_POLL_WAKE;
        }
        wait_timeout = remaining_poll_timeout(timeout_ms, deadline);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_alooper_poll_all(
    timeout_ms: c_int,
    out_fd: *mut c_int,
    out_events: *mut c_int,
    out_data: *mut *mut c_void,
) -> c_int {
    let mut current_timeout = timeout_ms;
    loop {
        let result = mocktail_rust_alooper_poll_once(current_timeout, out_fd, out_events, out_data);
        if result != K_POLL_CALLBACK {
            return result;
        }
        current_timeout = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_alooper_poll_wake_and_non_callback_fd_work() {
        let looper = mocktail_rust_alooper_prepare(K_PREPARE_ALLOW_NON_CALLBACKS);
        assert!(!looper.is_null());
        unsafe {
            mocktail_rust_alooper_wake(looper);
            let mut out_fd = -1;
            assert_eq!(
                mocktail_rust_alooper_poll_once(100, &mut out_fd, std::ptr::null_mut(), std::ptr::null_mut()),
                K_POLL_WAKE
            );
            let efd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
            assert!(efd >= 0);
            let mut marker: usize = 77;
            assert_eq!(
                mocktail_rust_alooper_add_fd(
                    looper,
                    efd,
                    42,
                    1,
                    None,
                    (&mut marker as *mut usize).cast()
                ),
                1
            );
            let val: u64 = 1;
            assert_eq!(
                libc::write(efd, (&val as *const u64).cast(), std::mem::size_of::<u64>()),
                8
            );
            let mut got_fd = -1;
            let mut got_events = 0;
            let mut got_data: *mut c_void = std::ptr::null_mut();
            assert_eq!(
                mocktail_rust_alooper_poll_once(100, &mut got_fd, &mut got_events, &mut got_data),
                42
            );
            assert_eq!(got_fd, efd);
            assert_ne!(got_events & 1, 0);
            assert_eq!(got_data, (&mut marker as *mut usize).cast());
            assert_eq!(mocktail_rust_alooper_remove_fd(looper, efd), 1);
            libc::close(efd);
        }
    }
}
