//! Native updater preflight launcher, progress monitor channel, stderr
//! failure relay, and periodic background download worker.

use std::ffi::{c_char, c_void, CStr, CString, OsString};
use std::marker::PhantomData;
use std::os::fd::RawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::unix_ipc::{
    build_filtered_helper_env_ptrs, copy_filtered_process_env_entries,
    create_pipe_cloexec_above_stdio, create_seqpacket_pair_cloexec_above_stdio, cstrings_as_mut_ptrs,
    errno_message, last_errno, path_from_ffi, path_to_cstr, posix_spawn_raw, push_env_kv,
    read_proc_self_exe, slice_from_ffi, validate_executable_absolute_regular_file,
    validate_executable_regular_file, waitpid_blocking, write_all_fd, OwnedFd, SpawnFileActions,
};

const K_PROGRESS_FINISHED_PACKET: u8 = b'S';
const K_MAX_STDERR_FAILURE_BYTES: usize = 400;
const K_UPDATER_PREFIX: &[u8] = b"[native-updater] ";
const K_WARNING_PREFIX: &[u8] = b"warning: ";

pub type MocktailRustPreflightEnvValueCallback =
    Option<unsafe extern "C" fn(cb_ctx: *mut c_void, val: *const c_char, val_len: usize)>;

pub type MocktailRustPreflightEnvLookupFn = Option<
    unsafe extern "C" fn(
        env_ctx: *const c_void,
        name: *const c_char,
        name_len: usize,
        on_value: MocktailRustPreflightEnvValueCallback,
        cb_ctx: *mut c_void,
    ) -> bool,
>;

pub type MocktailRustPreflightResultCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        attempted: bool,
        error: *const c_char,
        error_len: usize,
        details: *const c_char,
        details_len: usize,
    ),
>;

#[repr(C)]
pub struct MocktailRustPreflightRuntimePaths {
    pub config_file: *const c_char,
    pub config_file_len: usize,
    pub config_root: *const c_char,
    pub config_root_len: usize,
    pub data_root: *const c_char,
    pub data_root_len: usize,
    pub cache_root: *const c_char,
    pub cache_root_len: usize,
    pub state_root: *const c_char,
    pub state_root_len: usize,
}

#[derive(Clone)]
pub(crate) struct PreflightRuntimePaths {
    pub config_file: PathBuf,
    pub config_root: PathBuf,
    pub data_root: PathBuf,
    pub cache_root: PathBuf,
    pub state_root: PathBuf,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PreflightResult {
    pub attempted: bool,
    pub error: String,
    pub details: String,
}

pub(crate) trait EnvSource {
    fn get_bytes(&self, name: &str) -> Option<Vec<u8>>;

    fn enabled(&self, name: &str) -> bool {
        self.get_bytes(name)
            .is_some_and(|v| !v.is_empty() && v != b"0")
    }

    fn has_non_empty(&self, name: &str) -> bool {
        self.get_bytes(name).is_some_and(|v| !v.is_empty())
    }

    fn get_path(&self, name: &str) -> Option<PathBuf> {
        self.get_bytes(name)
            .map(|b| PathBuf::from(OsString::from_vec(b)))
    }
}

struct FfiEnv<'a> {
    ctx: *const c_void,
    lookup: MocktailRustPreflightEnvLookupFn,
    _marker: PhantomData<&'a c_void>,
}

impl<'a> EnvSource for FfiEnv<'a> {
    fn get_bytes(&self, name: &str) -> Option<Vec<u8>> {
        let lookup_fn = self.lookup?;
        let mut captured: Option<Vec<u8>> = None;
        unsafe extern "C" fn receive(cb_ctx: *mut c_void, val: *const c_char, val_len: usize) {
            let slot = &mut *(cb_ctx.cast::<Option<Vec<u8>>>());
            *slot = Some(slice_from_ffi(val, val_len).to_vec());
        }
        let found = unsafe {
            lookup_fn(
                self.ctx,
                name.as_ptr().cast::<c_char>(),
                name.len(),
                Some(receive),
                (&mut captured as *mut Option<Vec<u8>>).cast::<c_void>(),
            )
        };
        if found {
            Some(captured.unwrap_or_default())
        } else {
            None
        }
    }
}

pub(crate) fn trim_to_utf8_boundary_bytes(slice: &[u8], max_bytes: usize) -> usize {
    if slice.is_empty() || max_bytes == 0 {
        return 0;
    }
    if slice.len() <= max_bytes {
        return slice.len();
    }
    let mut size = max_bytes;
    while size > 0 && (slice[size] & 0xC0) == 0x80 {
        size -= 1;
    }
    size
}

pub(crate) fn parse_updater_stderr_line_bytes(line: &[u8]) -> Option<&[u8]> {
    if line.len() > K_UPDATER_PREFIX.len() && line.starts_with(K_UPDATER_PREFIX) {
        let detail = &line[K_UPDATER_PREFIX.len()..];
        if !detail.starts_with(K_WARNING_PREFIX) {
            let trim_len = trim_to_utf8_boundary_bytes(detail, K_MAX_STDERR_FAILURE_BYTES);
            return Some(&detail[..trim_len]);
        }
    }
    None
}

fn has_display(env: &dyn EnvSource) -> bool {
    env.has_non_empty("DISPLAY") || env.has_non_empty("WAYLAND_DISPLAY")
}

pub(crate) fn locate_update_helper(
    env: &dyn EnvSource,
    install_libdir: &Path,
) -> Option<PathBuf> {
    if let Some(helper) = env.get_path("MOCKTAIL_UPDATE_HELPER") {
        return if validate_executable_absolute_regular_file(&helper) {
            Some(helper)
        } else {
            None
        };
    }

    if let Some(root) = env.get_path("MOCKTAIL_PROJECT_ROOT") {
        if !root.is_absolute() {
            return None;
        }
        for candidate in [
            root.join("build/mocktail_updater"),
            root.join("bin/mocktail_updater"),
        ] {
            if validate_executable_regular_file(&candidate) {
                return Some(candidate);
            }
        }
        return None;
    }

    let executable = read_proc_self_exe()?;
    let executable_dir = executable.parent()?;
    let mut candidates = vec![executable_dir.join("mocktail_updater")];
    if let Some(prefix_dir) = executable_dir.parent() {
        candidates.push(prefix_dir.join("libexec/mocktail/mocktail_updater"));
        let libdir = if install_libdir.as_os_str().is_empty() {
            Path::new("lib")
        } else {
            install_libdir
        };
        candidates.push(prefix_dir.join(libdir).join("mocktail/mocktail_updater"));
    }
    candidates
        .into_iter()
        .find(|candidate| validate_executable_regular_file(candidate))
}

fn locate_progress_helper(env: &dyn EnvSource) -> Option<PathBuf> {
    if let Some(helper) = env.get_path("MOCKTAIL_UPDATE_PROGRESS_HELPER") {
        return if validate_executable_absolute_regular_file(&helper) {
            Some(helper)
        } else {
            None
        };
    }

    let executable = read_proc_self_exe()?;
    let candidate = executable.parent()?.join("mocktail_failure_dialog");
    if validate_executable_regular_file(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

struct UpdateProgressMonitor {
    socket: OwnedFd,
    pid: libc::pid_t,
}

impl UpdateProgressMonitor {
    fn start(env: &dyn EnvSource) -> Option<Self> {
        if env.enabled("MOCKTAIL_DISABLE_UPDATE_PROGRESS")
            || env.enabled("MOCKTAIL_DISABLE_FAILURE_DIALOG")
            || env.enabled("MOCKTAIL_ISOLATED_CANARY")
            || env.enabled("MOCKTAIL_HEADLESS")
            || !has_display(env)
        {
            return None;
        }
        let helper = locate_progress_helper(env)?;
        let helper_cstr = path_to_cstr(&helper)?;
        let (sock_parent, sock_child) = create_seqpacket_pair_cloexec_above_stdio()?;

        let mut actions = SpawnFileActions::new().ok()?;
        actions
            .add_dup2(sock_child.as_raw(), libc::STDIN_FILENO)
            .ok()?;
        actions.add_close(sock_parent.as_raw()).ok()?;
        actions.add_close(sock_child.as_raw()).ok()?;

        let arg1 = CString::new("--progress-monitor").ok()?;
        let argv = [
            helper_cstr.as_ptr().cast_mut(),
            arg1.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ];
        let env_ptrs = unsafe { build_filtered_helper_env_ptrs() };
        let pid = unsafe { posix_spawn_raw(&helper_cstr, Some(&actions), &argv, &env_ptrs) }.ok()?;
        drop(sock_child);
        Some(Self {
            socket: sock_parent,
            pid,
        })
    }

    fn socket_fd(&self) -> RawFd {
        self.socket.as_raw()
    }
}

impl Drop for UpdateProgressMonitor {
    fn drop(&mut self) {
        unsafe {
            libc::send(
                self.socket.as_raw(),
                (&K_PROGRESS_FINISHED_PACKET as *const u8).cast::<c_void>(),
                1,
                libc::MSG_NOSIGNAL,
            );
            libc::shutdown(self.socket.as_raw(), libc::SHUT_RDWR);
        }
        self.socket.close_now();
        let _ = waitpid_blocking(self.pid);
    }
}

struct UpdaterStderrRelay {
    read_end: Option<OwnedFd>,
    write_end: Option<OwnedFd>,
    failure: String,
    last_line: String,
}

impl UpdaterStderrRelay {
    fn new() -> Self {
        match create_pipe_cloexec_above_stdio() {
            Some((r, w)) => Self {
                read_end: Some(r),
                write_end: Some(w),
                failure: String::new(),
                last_line: String::new(),
            },
            None => Self {
                read_end: None,
                write_end: None,
                failure: String::new(),
                last_line: String::new(),
            },
        }
    }

    fn read_fd(&self) -> Option<RawFd> {
        self.read_end.as_ref().map(OwnedFd::as_raw)
    }

    fn write_fd(&self) -> Option<RawFd> {
        self.write_end.as_ref().map(OwnedFd::as_raw)
    }

    fn close_write(&mut self) {
        self.write_end = None;
    }

    fn record_line(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        let mut trimmed_len = line.len();
        while trimmed_len > 0
            && matches!(line[trimmed_len - 1], b'\r' | b'\n' | b' ')
        {
            trimmed_len -= 1;
        }
        if trimmed_len > 0 {
            self.last_line = String::from_utf8_lossy(&line[..trimmed_len]).into_owned();
        }
        if let Some(detail) = parse_updater_stderr_line_bytes(line) {
            if !detail.is_empty() {
                self.failure = String::from_utf8_lossy(detail).into_owned();
            }
        }
    }

    fn drain(&mut self) {
        let Some(fd) = self.read_fd() else {
            return;
        };
        let mut pending: Vec<u8> = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let received = unsafe {
                libc::read(
                    fd,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len(),
                )
            };
            if received < 0 && last_errno() == libc::EINTR {
                continue;
            }
            if received <= 0 {
                break;
            }
            let chunk = &buffer[..received as usize];
            let _ = write_all_fd(libc::STDERR_FILENO, chunk);
            pending.extend_from_slice(chunk);
            while let Some(newline_pos) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=newline_pos).collect();
                self.record_line(&line[..line.len() - 1]);
            }
        }
        let trailing = std::mem::take(&mut pending);
        self.record_line(&trailing);
        self.read_end = None;
    }
}

fn build_child_environment(
    paths: &PreflightRuntimePaths,
    progress_fd: Option<RawFd>,
) -> Vec<CString> {
    const OVERRIDDEN_NAMES: &[&[u8]] = &[
        b"MOCKTAIL_CONFIG_FILE",
        b"MOCKTAIL_CONFIG_ROOT",
        b"MOCKTAIL_DATA_ROOT",
        b"MOCKTAIL_CACHE_ROOT",
        b"MOCKTAIL_STATE_ROOT",
        b"MOCKTAIL_UPDATE_PROGRESS_FD",
    ];
    let mut entries = copy_filtered_process_env_entries(OVERRIDDEN_NAMES);
    for (name, path) in [
        (&b"MOCKTAIL_CONFIG_FILE"[..], paths.config_file.as_path()),
        (&b"MOCKTAIL_CONFIG_ROOT"[..], paths.config_root.as_path()),
        (&b"MOCKTAIL_DATA_ROOT"[..], paths.data_root.as_path()),
        (&b"MOCKTAIL_CACHE_ROOT"[..], paths.cache_root.as_path()),
        (&b"MOCKTAIL_STATE_ROOT"[..], paths.state_root.as_path()),
    ] {
        let _ = push_env_kv(&mut entries, name, path.as_os_str().as_bytes());
    }
    if let Some(fd) = progress_fd {
        let _ = push_env_kv(
            &mut entries,
            b"MOCKTAIL_UPDATE_PROGRESS_FD",
            fd.to_string().as_bytes(),
        );
    }
    entries
}

pub(crate) fn run_payload_update_preflight_with_env(
    env: &dyn EnvSource,
    paths: &PreflightRuntimePaths,
    install_libdir: &Path,
    force_run_latest: bool,
) -> PreflightResult {
    let mut result = PreflightResult::default();
    if !force_run_latest
        && (env.enabled("MOCKTAIL_SKIP_UPDATE_CHECK") || env.has_non_empty("ROBLOX_LIB_PATH"))
    {
        return result;
    }

    let Some(helper) = locate_update_helper(env, install_libdir) else {
        if force_run_latest || env.has_non_empty("MOCKTAIL_RUNTIME_LIBRARY_DIR") {
            result.error = "cannot locate the Mocktail update helper".to_string();
        }
        return result;
    };

    let Some(helper_cstr) = path_to_cstr(&helper) else {
        result.error = "cannot locate the Mocktail update helper".to_string();
        return result;
    };

    result.attempted = true;
    // Keep `progress` declared before `stderr_relay` so `stderr_relay` drains/drops
    // before `progress` signals `'S'` and waits on exit.
    let progress = UpdateProgressMonitor::start(env);
    let env_entries = build_child_environment(paths, progress.as_ref().map(|p| p.socket_fd()));
    let env_ptrs = cstrings_as_mut_ptrs(&env_entries);
    let mut stderr_relay = UpdaterStderrRelay::new();

    let actions = if progress.is_some() || stderr_relay.read_fd().is_some() {
        let setup = (|| -> Result<SpawnFileActions, i32> {
            let mut act = SpawnFileActions::new()?;
            if let Some(ref mon) = progress {
                // Same-descriptor spawn dup2 clears FD_CLOEXEC in the child.
                act.add_dup2(mon.socket_fd(), mon.socket_fd())?;
            }
            if let Some(write_fd) = stderr_relay.write_fd() {
                act.add_dup2(write_fd, libc::STDERR_FILENO)?;
                act.add_close(write_fd)?;
            }
            if let Some(read_fd) = stderr_relay.read_fd() {
                act.add_close(read_fd)?;
            }
            Ok(act)
        })();
        match setup {
            Ok(act) => Some(act),
            Err(err) => {
                result.error = errno_message("cannot prepare Roblox update progress channel", err);
                return result;
            }
        }
    } else {
        None
    };

    let arg1 = CString::new("update").unwrap();
    let arg2 = CString::new(if force_run_latest {
        "--force-run-latest"
    } else {
        "--startup-preflight"
    })
    .unwrap();
    let argv = [
        helper_cstr.as_ptr().cast_mut(),
        arg1.as_ptr().cast_mut(),
        arg2.as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];

    let child = match unsafe { posix_spawn_raw(&helper_cstr, actions.as_ref(), &argv, &env_ptrs) } {
        Ok(pid) => pid,
        Err(err) => {
            result.error = errno_message("cannot start Roblox update preflight", err);
            return result;
        }
    };

    // The child owns the write end now; the relay must observe end-of-file.
    stderr_relay.close_write();
    stderr_relay.drain();

    let child_status = match waitpid_blocking(child) {
        Ok(status) => status,
        Err(err) => {
            result.error = errno_message("cannot wait for Roblox update preflight", err);
            return result;
        }
    };

    if !libc::WIFEXITED(child_status) || libc::WEXITSTATUS(child_status) != 0 {
        result.error = if force_run_latest {
            "forced latest Roblox run failed".to_string()
        } else {
            "Roblox update preflight failed".to_string()
        };
        result.details = stderr_relay.failure;
        if libc::WIFSIGNALED(child_status) {
            let sig = libc::WTERMSIG(child_status);
            let mut termination = format!("Roblox updater terminated by signal {sig}");
            let desc_ptr = unsafe { libc::strsignal(sig) };
            if !desc_ptr.is_null() {
                let desc = unsafe { CStr::from_ptr(desc_ptr) }.to_string_lossy();
                termination.push_str(&format!(" ({desc})"));
            }
            termination.push('.');
            if !result.details.is_empty() {
                termination.push('\n');
                termination.push_str(&result.details);
            }
            result.details = termination;
        } else if libc::WIFEXITED(child_status) && result.details.is_empty() {
            result.details = format!(
                "Roblox updater exited with code {} without an error message.",
                libc::WEXITSTATUS(child_status)
            );
        } else if result.details.is_empty() {
            result.details =
                format!("Roblox updater returned unexpected process status {child_status}.");
        }
    }

    result
}

struct BackgroundState {
    stopped: bool,
    child: Option<libc::pid_t>,
}

struct BackgroundSync {
    mutex: Mutex<BackgroundState>,
    wake: Condvar,
}

pub struct MocktailRustBackgroundPayloadUpdate {
    sync: Arc<BackgroundSync>,
    worker: Option<JoinHandle<()>>,
}

impl MocktailRustBackgroundPayloadUpdate {
    pub(crate) fn new() -> Self {
        Self {
            sync: Arc::new(BackgroundSync {
                mutex: Mutex::new(BackgroundState {
                    stopped: false,
                    child: None,
                }),
                wake: Condvar::new(),
            }),
            worker: None,
        }
    }

    pub(crate) fn start(
        &mut self,
        env: &dyn EnvSource,
        paths: &PreflightRuntimePaths,
        install_libdir: &Path,
        interval_ms: i64,
    ) {
        if self.worker.is_some()
            || interval_ms <= 0
            || env.enabled("MOCKTAIL_SKIP_UPDATE_CHECK")
            || env.enabled("MOCKTAIL_ISOLATED_CANARY")
            || env.has_non_empty("ROBLOX_LIB_PATH")
        {
            return;
        }
        let Some(helper) = locate_update_helper(env, install_libdir) else {
            return;
        };
        let Some(helper_cstr) = path_to_cstr(&helper) else {
            return;
        };

        let child_environment = build_child_environment(paths, None);
        {
            let mut guard = self.sync.mutex.lock().unwrap_or_else(|e| e.into_inner());
            guard.stopped = false;
            guard.child = None;
        }

        let sync = Arc::clone(&self.sync);
        let interval = Duration::from_millis(interval_ms as u64);
        self.worker = Some(thread::spawn(move || {
            let env_ptrs = cstrings_as_mut_ptrs(&child_environment);
            let arg1 = CString::new("update").unwrap();
            let arg2 = CString::new("--download-only").unwrap();
            let argv = [
                helper_cstr.as_ptr().cast_mut(),
                arg1.as_ptr().cast_mut(),
                arg2.as_ptr().cast_mut(),
                std::ptr::null_mut(),
            ];

            let mut guard = sync.mutex.lock().unwrap_or_else(|e| e.into_inner());
            let mut delay = interval.min(Duration::from_millis(5000));
            loop {
                let (next_guard, _) = sync
                    .wake
                    .wait_timeout_while(guard, delay, |s| !s.stopped)
                    .unwrap_or_else(|e| e.into_inner());
                guard = next_guard;
                if guard.stopped {
                    break;
                }
                delay = interval;

                let Ok(pid) = (unsafe { posix_spawn_raw(&helper_cstr, None, &argv, &env_ptrs) })
                else {
                    continue;
                };
                guard.child = Some(pid);
                while let Some(child_pid) = guard.child {
                    let exited = unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), libc::WNOHANG) };
                    if exited == child_pid || (exited < 0 && last_errno() == libc::ECHILD) {
                        guard.child = None;
                    } else {
                        let (next_guard, _) = sync
                            .wake
                            .wait_timeout(guard, Duration::from_millis(50))
                            .unwrap_or_else(|e| e.into_inner());
                        guard = next_guard;
                    }
                }
            }
        }));
    }

    pub(crate) fn stop(&mut self) {
        {
            let mut guard = self.sync.mutex.lock().unwrap_or_else(|e| e.into_inner());
            guard.stopped = true;
            if let Some(child_pid) = guard.child {
                unsafe {
                    libc::kill(child_pid, libc::SIGTERM);
                }
            }
        }
        self.sync.wake.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for MocktailRustBackgroundPayloadUpdate {
    fn drop(&mut self) {
        self.stop();
    }
}

fn parse_runtime_paths(paths: *const MocktailRustPreflightRuntimePaths) -> Option<PreflightRuntimePaths> {
    let p = unsafe { paths.as_ref()? };
    Some(PreflightRuntimePaths {
        config_file: path_from_ffi(p.config_file, p.config_file_len)?,
        config_root: path_from_ffi(p.config_root, p.config_root_len)?,
        data_root: path_from_ffi(p.data_root, p.data_root_len)?,
        cache_root: path_from_ffi(p.cache_root, p.cache_root_len)?,
        state_root: path_from_ffi(p.state_root, p.state_root_len)?,
    })
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_run_payload_update_preflight(
    env_ctx: *const c_void,
    get_env: MocktailRustPreflightEnvLookupFn,
    paths: *const MocktailRustPreflightRuntimePaths,
    install_libdir: *const c_char,
    install_libdir_len: usize,
    force_run_latest: bool,
    on_result: MocktailRustPreflightResultCallback,
    ctx: *mut c_void,
) {
    let env = FfiEnv {
        ctx: env_ctx,
        lookup: get_env,
        _marker: PhantomData,
    };
    let libdir = path_from_ffi(install_libdir, install_libdir_len).unwrap_or_else(|| PathBuf::from("lib"));
    let result = match parse_runtime_paths(paths) {
        Some(parsed_paths) => {
            run_payload_update_preflight_with_env(&env, &parsed_paths, &libdir, force_run_latest)
        }
        None => PreflightResult {
            attempted: false,
            error: "invalid payload update preflight runtime paths".to_string(),
            details: String::new(),
        },
    };
    if let Some(cb) = on_result {
        cb(
            ctx,
            result.attempted,
            result.error.as_ptr().cast::<c_char>(),
            result.error.len(),
            result.details.as_ptr().cast::<c_char>(),
            result.details.len(),
        );
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_background_payload_update_create(
) -> *mut MocktailRustBackgroundPayloadUpdate {
    Box::into_raw(Box::new(MocktailRustBackgroundPayloadUpdate::new()))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_background_payload_update_start(
    handle: *mut MocktailRustBackgroundPayloadUpdate,
    env_ctx: *const c_void,
    get_env: MocktailRustPreflightEnvLookupFn,
    paths: *const MocktailRustPreflightRuntimePaths,
    install_libdir: *const c_char,
    install_libdir_len: usize,
    interval_ms: i64,
) {
    let Some(updater) = handle.as_mut() else {
        return;
    };
    let Some(parsed_paths) = parse_runtime_paths(paths) else {
        return;
    };
    let libdir =
        path_from_ffi(install_libdir, install_libdir_len).unwrap_or_else(|| PathBuf::from("lib"));
    let env = FfiEnv {
        ctx: env_ctx,
        lookup: get_env,
        _marker: PhantomData,
    };
    updater.start(&env, &parsed_paths, &libdir, interval_ms);
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_background_payload_update_stop(
    handle: *mut MocktailRustBackgroundPayloadUpdate,
) {
    if let Some(updater) = handle.as_mut() {
        updater.stop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_background_payload_update_destroy(
    handle: *mut MocktailRustBackgroundPayloadUpdate,
) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_ipc::{create_unique_temp_dir, TEST_ENV_LOCK};
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    struct MapEnv(HashMap<&'static str, String>);

    impl EnvSource for MapEnv {
        fn get_bytes(&self, name: &str) -> Option<Vec<u8>> {
            self.0.get(name).map(|v| v.as_bytes().to_vec())
        }
    }

    struct DirCleanup(PathBuf);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn dummy_paths(root: &Path) -> PreflightRuntimePaths {
        PreflightRuntimePaths {
            config_file: root.join("config/config.yaml"),
            config_root: root.join("config"),
            data_root: root.join("data"),
            cache_root: root.join("cache"),
            state_root: root.join("state"),
        }
    }

    #[test]
    fn locates_updater_respecting_relative_override_rejection() {
        let env = MapEnv(HashMap::from([(
            "MOCKTAIL_UPDATE_HELPER",
            "relative/mocktail_updater".to_string(),
        )]));
        assert!(locate_update_helper(&env, Path::new("lib")).is_none());
    }

    #[test]
    fn preflight_captures_last_failure_and_ignores_warnings() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let temp = create_unique_temp_dir(Path::new("/tmp"), "mocktail_preflight_rs").unwrap();
        let _cleanup = DirCleanup(temp.clone());
        let helper = temp.join("updater");
        fs::write(
            &helper,
            "#!/bin/sh\n\
             printf '%s\\n' \"$2\" > \"$MOCKTAIL_TEST_PREFLIGHT_ARG\"\n\
             echo '[native-updater] warning: benign config warning' >&2\n\
             echo 'plain diagnostic' >&2\n\
             echo '[native-updater] actual fatal updater error' >&2\n\
             exit 7\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&helper).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&helper, perms).unwrap();

        let arg_capture = temp.join("arg");
        let k = CString::new("MOCKTAIL_TEST_PREFLIGHT_ARG").unwrap();
        let v = CString::new(arg_capture.to_str().unwrap()).unwrap();
        unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };

        let env = MapEnv(HashMap::from([(
            "MOCKTAIL_UPDATE_HELPER",
            helper.to_string_lossy().into_owned(),
        )]));
        let res = run_payload_update_preflight_with_env(
            &env,
            &dummy_paths(&temp),
            Path::new("lib"),
            true,
        );
        unsafe { libc::unsetenv(k.as_ptr()) };

        assert!(res.attempted);
        assert_eq!(res.error, "forced latest Roblox run failed");
        assert_eq!(res.details, "actual fatal updater error");
        assert_eq!(
            fs::read_to_string(&arg_capture).unwrap().trim(),
            "--force-run-latest"
        );
    }

    #[test]
    fn background_updater_stops_running_child_promptly() {
        let temp = create_unique_temp_dir(Path::new("/tmp"), "mocktail_bg_preflight_rs").unwrap();
        let _cleanup = DirCleanup(temp.clone());
        let helper = temp.join("updater");
        let marker = temp.join("started");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$2\" > '{}'\nsleep 5\n",
                marker.display()
            ),
        )
        .unwrap();
        let mut perms = fs::metadata(&helper).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&helper, perms).unwrap();

        let env = MapEnv(HashMap::from([(
            "MOCKTAIL_UPDATE_HELPER",
            helper.to_string_lossy().into_owned(),
        )]));
        let mut bg = MocktailRustBackgroundPayloadUpdate::new();
        bg.start(&env, &dummy_paths(&temp), Path::new("lib"), 10);

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !marker.exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read_to_string(&marker).unwrap().trim(), "--download-only");

        let before = std::time::Instant::now();
        bg.stop();
        assert!(before.elapsed() < Duration::from_secs(1));
    }
}
