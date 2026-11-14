//! Shared POSIX Unix-domain IPC, process-spawning, descriptor, and
//! atomic/locked filesystem helpers used across `discord_rpc`,
//! `external_launch_broker`, `webview_helper_launcher`, `roblox_cookie_store`,
//! `browser_tracker_service`, `payload_store`, `readiness_canary`, and
//! `payload_update_preflight`.

use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

extern "C" {
    static environ: *const *mut libc::c_char;
}

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII wrapper around a POSIX file descriptor (`>= 0`).
pub(crate) struct OwnedFd {
    fd: RawFd,
}

impl OwnedFd {
    pub(crate) fn from_raw(fd: RawFd) -> Option<Self> {
        if fd >= 0 {
            Some(Self { fd })
        } else {
            None
        }
    }

    pub(crate) fn as_raw(&self) -> RawFd {
        self.fd
    }

    pub(crate) fn release(mut self) -> RawFd {
        let fd = self.fd;
        self.fd = -1;
        fd
    }

    pub(crate) fn close_now(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        self.close_now();
    }
}

/// Non-blocking close-on-exec `eventfd` used to wake `poll()` loops cleanly.
pub(crate) struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    pub(crate) fn new() -> Result<Self, i32> {
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        match OwnedFd::from_raw(raw) {
            Some(fd) => Ok(Self { fd }),
            None => Err(last_errno()),
        }
    }

    pub(crate) fn as_raw(&self) -> RawFd {
        self.fd.as_raw()
    }

    pub(crate) fn signal(&self) {
        let value: u64 = 1;
        loop {
            let rc = unsafe {
                libc::write(
                    self.fd.as_raw(),
                    (&value as *const u64).cast::<libc::c_void>(),
                    mem::size_of::<u64>(),
                )
            };
            if rc >= 0 {
                break;
            }
            let err = last_errno();
            if err == libc::EINTR {
                continue;
            }
            // EAGAIN means the 64-bit eventfd counter already has a pending wake.
            break;
        }
    }

    pub(crate) fn drain(&self) {
        let mut buf: u64 = 0;
        loop {
            let rc = unsafe {
                libc::read(
                    self.fd.as_raw(),
                    (&mut buf as *mut u64).cast::<libc::c_void>(),
                    mem::size_of::<u64>(),
                )
            };
            if rc > 0 {
                continue;
            }
            if rc < 0 && last_errno() == libc::EINTR {
                continue;
            }
            break;
        }
    }
}

pub(crate) fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

pub(crate) fn errno_message(operation: &str, err: i32) -> String {
    let os_msg = io::Error::from_raw_os_error(err).to_string();
    format!("{operation}: {os_msg}")
}

pub(crate) fn current_uid() -> libc::uid_t {
    unsafe { libc::getuid() }
}

pub(crate) fn current_euid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

pub(crate) fn current_pid() -> libc::pid_t {
    unsafe { libc::getpid() }
}

/// Constructs a NUL-terminated pathname `sockaddr_un` if `path` fits inside `sun_path`.
pub(crate) fn build_sockaddr_un(path: &[u8]) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    if path.is_empty() || path.contains(&0) {
        return None;
    }
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    let sun_path_cap = addr.sun_path.len();
    if path.len() >= sun_path_cap {
        return None;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            path.as_ptr().cast::<libc::c_char>(),
            addr.sun_path.as_mut_ptr(),
            path.len(),
        );
    }
    let base = (&addr as *const libc::sockaddr_un) as usize;
    let field = (&addr.sun_path as *const _) as usize;
    let socklen = (field - base + path.len() + 1) as libc::socklen_t;
    Some((addr, socklen))
}

pub(crate) fn set_socket_timeouts(fd: RawFd, seconds: i64) -> bool {
    let timeout = libc::timeval {
        tv_sec: seconds as libc::time_t,
        tv_usec: 0,
    };
    let size = mem::size_of::<libc::timeval>() as libc::socklen_t;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast::<libc::c_void>(),
            size,
        ) == 0
            && libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                (&timeout as *const libc::timeval).cast::<libc::c_void>(),
                size,
            ) == 0
    }
}

pub(crate) fn poll_retry_eintr(fds: &mut [libc::pollfd], timeout_ms: i32) -> i32 {
    loop {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if rc < 0 && last_errno() == libc::EINTR {
            continue;
        }
        return rc;
    }
}

pub(crate) fn peer_uid(fd: RawFd) -> Option<libc::uid_t> {
    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut size = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast::<libc::c_void>(),
            &mut size,
        )
    };
    if rc == 0 && size == mem::size_of::<libc::ucred>() as libc::socklen_t {
        Some(unsafe { cred.assume_init() }.uid)
    } else {
        None
    }
}

pub(crate) unsafe fn slice_from_ffi<'a>(ptr: *const libc::c_char, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr.cast::<u8>(), len)
    }
}

pub(crate) fn path_from_ffi(ptr: *const libc::c_char, len: usize) -> Option<PathBuf> {
    if ptr.is_null() && len > 0 {
        return None;
    }
    let bytes = unsafe { slice_from_ffi(ptr, len) };
    if bytes.contains(&0) {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(bytes)))
}

pub(crate) fn path_to_slice(path: &Path) -> crate::update_json::MocktailRustStrSlice {
    let bytes = path.as_os_str().as_encoded_bytes();
    crate::update_json::MocktailRustStrSlice {
        ptr: bytes.as_ptr() as *const libc::c_char,
        len: bytes.len(),
    }
}

pub(crate) unsafe fn slice_to_str_lossy(
    slice: crate::update_json::MocktailRustStrSlice,
) -> String {
    if slice.ptr.is_null() || slice.len == 0 {
        return String::new();
    }
    if let Some(s) = crate::slice_to_str(slice.ptr, slice.len) {
        return s.to_string();
    }
    let raw = std::slice::from_raw_parts(slice.ptr as *const u8, slice.len);
    String::from_utf8_lossy(raw).into_owned()
}

pub(crate) unsafe fn slice_to_opt_str(
    slice: crate::update_json::MocktailRustStrSlice,
) -> Option<String> {
    if slice.ptr.is_null() && slice.len == 0 {
        return None;
    }
    Some(slice_to_str_lossy(slice))
}

pub(crate) unsafe fn slice_to_pathbuf(slice: crate::update_json::MocktailRustStrSlice) -> PathBuf {
    path_from_ffi(slice.ptr, slice.len).unwrap_or_default()
}

pub(crate) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

pub(crate) fn lexical_absolute(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    Some(lexical_normalize(&abs))
}

pub(crate) fn path_to_cstr(path: &Path) -> Option<CString> {
    CString::new(path.as_os_str().as_bytes()).ok()
}

pub(crate) fn lstat_cstr(cpath: &CStr) -> Result<libc::stat, i32> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    let rc = unsafe { libc::lstat(cpath.as_ptr(), st.as_mut_ptr()) };
    if rc == 0 {
        Ok(unsafe { st.assume_init() })
    } else {
        Err(last_errno())
    }
}

pub(crate) fn is_private_owned_dir(path: &Path, uid: libc::uid_t) -> bool {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return false;
    }
    let Some(cpath) = path_to_cstr(path) else {
        return false;
    };
    let Ok(st) = lstat_cstr(&cpath) else {
        return false;
    };
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_uid == uid && (st.st_mode & 0o077) == 0
}

pub(crate) fn is_non_group_other_writable_dir(st: &libc::stat, euid: libc::uid_t) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
        && st.st_uid == euid
        && (st.st_mode & (libc::S_IWGRP | libc::S_IWOTH)) == 0
}

pub(crate) fn parent_or_dot(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() && path != Path::new(".") {
        Some(PathBuf::from("."))
    } else if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent.to_path_buf())
    }
}

pub(crate) fn find_existing_directory_ancestor(directory: &Path) -> Option<PathBuf> {
    if directory.as_os_str().is_empty() {
        return None;
    }
    let mut candidate = directory.to_path_buf();
    loop {
        let cpath = path_to_cstr(&candidate)?;
        match lstat_cstr(&cpath) {
            Ok(st) => {
                if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                    return Some(candidate);
                }
                return None;
            }
            Err(err) => {
                if err != libc::ENOENT {
                    return None;
                }
                let next = parent_or_dot(&candidate)?;
                if next == candidate {
                    return None;
                }
                candidate = next;
            }
        }
    }
}

pub(crate) fn fsync_dir_path(path: &Path, nofollow: bool) -> bool {
    let Some(cpath) = path_to_cstr(path) else {
        return false;
    };
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let raw = unsafe { libc::open(cpath.as_ptr(), flags) };
    let Some(fd) = OwnedFd::from_raw(raw) else {
        return false;
    };
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    unsafe {
        libc::fstat(fd.as_raw(), st.as_mut_ptr()) == 0
            && (st.assume_init().st_mode & libc::S_IFMT) == libc::S_IFDIR
            && libc::fsync(fd.as_raw()) == 0
    }
}

pub(crate) fn fsync_directory_chain(first: &Path, last: &Path) -> bool {
    let mut current = first.to_path_buf();
    loop {
        if !fsync_dir_path(&current, true) {
            return false;
        }
        if current == last {
            return true;
        }
        let Some(next) = parent_or_dot(&current) else {
            return false;
        };
        if next == current {
            return false;
        }
        current = next;
    }
}

pub(crate) fn flock_fd(fd: RawFd, operation: libc::c_int) -> bool {
    loop {
        if unsafe { libc::flock(fd, operation) } == 0 {
            return true;
        }
        if last_errno() != libc::EINTR {
            return false;
        }
    }
}

pub(crate) fn is_safe_destination_at(dir_fd: RawFd, name: &CStr, euid: libc::uid_t) -> bool {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstatat(dir_fd, name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) }
        == 0
    {
        let st = unsafe { st.assume_init() };
        return (st.st_mode & libc::S_IFMT) == libc::S_IFREG
            && st.st_uid == euid
            && st.st_nlink == 1;
    }
    last_errno() == libc::ENOENT
}

pub(crate) fn is_opened_file_at(
    dir_fd: RawFd,
    name: &CStr,
    fd: RawFd,
    euid: libc::uid_t,
) -> bool {
    let mut opened = MaybeUninit::<libc::stat>::zeroed();
    let mut linked = MaybeUninit::<libc::stat>::zeroed();
    unsafe {
        if libc::fstat(fd, opened.as_mut_ptr()) != 0
            || libc::fstatat(
                dir_fd,
                name.as_ptr(),
                linked.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            ) != 0
        {
            return false;
        }
        let opened = opened.assume_init();
        let linked = linked.assume_init();
        (opened.st_mode & libc::S_IFMT) == libc::S_IFREG
            && (linked.st_mode & libc::S_IFMT) == libc::S_IFREG
            && opened.st_uid == euid
            && linked.st_uid == euid
            && opened.st_nlink == 1
            && linked.st_nlink == 1
            && opened.st_dev == linked.st_dev
            && opened.st_ino == linked.st_ino
    }
}

pub(crate) fn unlink_opened_file_at(dir_fd: RawFd, name: &CStr, fd: RawFd, euid: libc::uid_t) {
    if is_opened_file_at(dir_fd, name, fd, euid) {
        unsafe {
            libc::unlinkat(dir_fd, name.as_ptr(), 0);
        }
    }
}

pub(crate) fn read_all_fd(fd: RawFd, reserve: usize) -> Result<Vec<u8>, i32> {
    let mut out = Vec::with_capacity(reserve);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if rc == 0 {
            return Ok(out);
        }
        if rc < 0 {
            let err = last_errno();
            if err == libc::EINTR {
                continue;
            }
            return Err(err);
        }
        out.extend_from_slice(&buf[..rc as usize]);
    }
}

pub(crate) fn write_all_fd(fd: RawFd, bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let rc = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(offset).cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if rc < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        if rc == 0 {
            return false;
        }
        offset += rc as usize;
    }
    true
}

pub(crate) fn set_cloexec(fd: RawFd, enabled: bool) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return false;
    }
    let updated = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    unsafe { libc::fcntl(fd, libc::F_SETFD, updated) == 0 }
}

pub(crate) fn set_nonblocking(fd: RawFd) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return false;
    }
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0 }
}

/// Ensures a spawned child/parent descriptor is `>= 3` (not aliasing stdio).
pub(crate) fn move_fd_above_stdio(fd: OwnedFd) -> Option<OwnedFd> {
    if fd.as_raw() >= 3 {
        return Some(fd);
    }
    let duped = unsafe { libc::fcntl(fd.as_raw(), libc::F_DUPFD_CLOEXEC, 3) };
    OwnedFd::from_raw(duped)
}

/// Checks that `path` is a non-symlink regular file (`lstat`) and executable (`X_OK`).
/// Checks that `path` is a non-symlink regular file (`lstat`).
pub(crate) fn is_non_symlink_regular_file(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    let Some(cpath) = path_to_cstr(path) else {
        return false;
    };
    let Ok(st) = lstat_cstr(&cpath) else {
        return false;
    };
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
}

pub(crate) fn validate_executable_regular_file(path: &Path) -> bool {
    if !is_non_symlink_regular_file(path) {
        return false;
    }
    let Some(cpath) = path_to_cstr(path) else {
        return false;
    };
    unsafe { libc::access(cpath.as_ptr(), libc::X_OK) == 0 }
}

/// Checks that `path` is absolute, a non-symlink regular file (`lstat`), and executable (`X_OK`).
pub(crate) fn validate_executable_absolute_regular_file(path: &Path) -> bool {
    path.is_absolute() && validate_executable_regular_file(path)
}

pub(crate) fn read_proc_self_exe() -> Option<PathBuf> {
    fs::read_link("/proc/self/exe")
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TempDirError {
    CreateParent,
    CreateTemp,
}

pub(crate) fn create_unique_temp_dir(parent: &Path, prefix: &str) -> Result<PathBuf, TempDirError> {
    if fs::create_dir_all(parent).is_err() {
        return Err(TempDirError::CreateParent);
    }
    let pattern_path = parent.join(format!("{prefix}-XXXXXX"));
    let Some(pattern) = path_to_cstr(&pattern_path) else {
        return Err(TempDirError::CreateTemp);
    };
    let mut buf = pattern.into_bytes_with_nul();
    let created = unsafe { libc::mkdtemp(buf.as_mut_ptr().cast::<libc::c_char>()) };
    if created.is_null() {
        return Err(TempDirError::CreateTemp);
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(PathBuf::from(OsStr::from_bytes(&buf[..len])))
}

pub(crate) fn create_pipe_cloexec_above_stdio() -> Option<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    let read_end = OwnedFd::from_raw(fds[0])?;
    let write_end = OwnedFd::from_raw(fds[1])?;
    let read_end = move_fd_above_stdio(read_end)?;
    let write_end = move_fd_above_stdio(write_end)?;
    Some((read_end, write_end))
}

pub(crate) fn create_seqpacket_pair_cloexec_above_stdio() -> Option<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as RawFd; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return None;
    }
    let first = OwnedFd::from_raw(fds[0])?;
    let second = OwnedFd::from_raw(fds[1])?;
    let first = move_fd_above_stdio(first)?;
    let second = move_fd_above_stdio(second)?;
    Some((first, second))
}

pub(crate) struct SpawnFileActions {
    inner: libc::posix_spawn_file_actions_t,
}

impl SpawnFileActions {
    pub(crate) fn new() -> Result<Self, i32> {
        let mut inner = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        let rc = unsafe { libc::posix_spawn_file_actions_init(inner.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self {
            inner: unsafe { inner.assume_init() },
        })
    }

    pub(crate) fn add_dup2(&mut self, fd: RawFd, newfd: RawFd) -> Result<(), i32> {
        let rc = unsafe { libc::posix_spawn_file_actions_adddup2(&mut self.inner, fd, newfd) };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }

    pub(crate) fn add_close(&mut self, fd: RawFd) -> Result<(), i32> {
        let rc = unsafe { libc::posix_spawn_file_actions_addclose(&mut self.inner, fd) };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }

    pub(crate) fn as_ptr(&self) -> *const libc::posix_spawn_file_actions_t {
        &self.inner
    }
}

impl Drop for SpawnFileActions {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.inner);
        }
    }
}

pub(crate) unsafe fn posix_spawn_raw(
    path: &CStr,
    actions: Option<&SpawnFileActions>,
    argv: &[*mut libc::c_char],
    envp: &[*mut libc::c_char],
) -> Result<libc::pid_t, i32> {
    let mut pid: libc::pid_t = -1;
    let actions_ptr = actions.map_or(std::ptr::null(), SpawnFileActions::as_ptr);
    let rc = libc::posix_spawn(
        &mut pid,
        path.as_ptr(),
        actions_ptr,
        std::ptr::null(),
        argv.as_ptr().cast(),
        envp.as_ptr().cast(),
    );
    if rc == 0 {
        Ok(pid)
    } else {
        Err(rc)
    }
}

pub(crate) fn waitpid_blocking(pid: libc::pid_t) -> Result<libc::c_int, i32> {
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = last_errno();
            if err == libc::EINTR {
                continue;
            }
            return Err(err);
        }
        return Ok(status);
    }
}

pub(crate) fn terminate_and_reap(pid: libc::pid_t, grace: Duration) -> Option<libc::c_int> {
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    let mut status: libc::c_int = 0;
    while Instant::now() < deadline {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Some(status);
        }
        if waited < 0 && last_errno() != libc::EINTR {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if waited == pid {
        return Some(status);
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    waitpid_blocking(pid).ok()
}

pub(crate) fn is_env_entry(entry: &[u8], name: &[u8]) -> bool {
    entry.len() > name.len() && entry[name.len()] == b'=' && &entry[..name.len()] == name
}

pub(crate) fn lookup_process_env_bytes(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name.contains(&b'=') || name.contains(&0) {
        return None;
    }
    unsafe {
        let mut cur = environ;
        if cur.is_null() {
            return None;
        }
        while !(*cur).is_null() {
            let bytes = CStr::from_ptr(*cur).to_bytes();
            if is_env_entry(bytes, name) {
                return Some(bytes[name.len() + 1..].to_vec());
            }
            cur = cur.add(1);
        }
    }
    None
}

pub(crate) fn copy_filtered_process_env_entries(excluded_names: &[&[u8]]) -> Vec<CString> {
    let mut out = Vec::new();
    unsafe {
        let mut cur = environ;
        if cur.is_null() {
            return out;
        }
        while !(*cur).is_null() {
            let cstr = CStr::from_ptr(*cur);
            let bytes = cstr.to_bytes();
            if !excluded_names.iter().any(|name| is_env_entry(bytes, name)) {
                out.push(cstr.to_owned());
            }
            cur = cur.add(1);
        }
    }
    out
}

pub(crate) fn push_env_kv(entries: &mut Vec<CString>, name: &[u8], value: &[u8]) -> Result<(), ()> {
    if name.contains(&0) || name.contains(&b'=') || value.contains(&0) {
        return Err(());
    }
    let mut raw = Vec::with_capacity(name.len() + 1 + value.len() + 1);
    raw.extend_from_slice(name);
    raw.push(b'=');
    raw.extend_from_slice(value);
    CString::new(raw).map(|s| entries.push(s)).map_err(|_| ())
}

pub(crate) fn cstrings_as_mut_ptrs(entries: &[CString]) -> Vec<*mut libc::c_char> {
    let mut ptrs = Vec::with_capacity(entries.len() + 1);
    for entry in entries {
        ptrs.push(entry.as_ptr().cast_mut());
    }
    ptrs.push(std::ptr::null_mut());
    ptrs
}

const HELPER_EXCLUDED_ENV_NAME: &[u8] = b"MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON";

/// Filters `envp` (`NULL`-terminated C string pointers), omitting entries matching
/// `MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON=...`. Pointers remain valid while the
/// parent environment is unmodified.
pub(crate) unsafe fn filter_helper_env_ptrs(envp: *const *mut libc::c_char) -> Vec<*mut libc::c_char> {
    let mut out = Vec::new();
    if !envp.is_null() {
        let mut cur = envp;
        while !(*cur).is_null() {
            let entry = *cur;
            let bytes = CStr::from_ptr(entry).to_bytes();
            if !is_env_entry(bytes, HELPER_EXCLUDED_ENV_NAME) {
                out.push(entry);
            }
            cur = cur.add(1);
        }
    }
    out.push(std::ptr::null_mut());
    out
}

pub(crate) unsafe fn build_filtered_helper_env_ptrs() -> Vec<*mut libc::c_char> {
    filter_helper_env_ptrs(environ)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFileError {
    NotFound,
    OpenFailed(i32),
    InvalidFile,
    ReadFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadOwnedFileError {
    OpenFailed,
    InvalidOwnershipOrPermissions,
    ReadFailed,
}

fn open_and_stat_regular_fd(
    path: &Path,
    follow_symlinks: bool,
) -> Result<(OwnedFd, libc::stat), ReadFileError> {
    let Some(cpath) = path_to_cstr(path) else {
        return Err(ReadFileError::OpenFailed(libc::EINVAL));
    };
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC;
    if !follow_symlinks {
        flags |= libc::O_NOFOLLOW;
    }
    let raw_fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if raw_fd < 0 {
        let err = last_errno();
        return Err(if err == libc::ENOENT {
            ReadFileError::NotFound
        } else {
            ReadFileError::OpenFailed(err)
        });
    }
    let Some(fd) = OwnedFd::from_raw(raw_fd) else {
        return Err(ReadFileError::OpenFailed(libc::EBADF));
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw(), &mut st) } != 0 {
        return Err(ReadFileError::InvalidFile);
    }
    Ok((fd, st))
}

fn read_bounded_regular_fd(fd: &OwnedFd, st: &libc::stat, max_bytes: usize) -> Result<Vec<u8>, ()> {
    if st.st_size < 0 || (st.st_size as u64) > (max_bytes as u64) {
        return Err(());
    }
    let bytes = read_all_fd(fd.as_raw(), st.st_size as usize).map_err(|_| ())?;
    if bytes.len() > max_bytes {
        return Err(());
    }
    Ok(bytes)
}

/// Opens and reads a regular file bounded by `max_bytes`.
pub(crate) fn read_regular_file_limited(
    path: &Path,
    max_bytes: usize,
    follow_symlinks: bool,
    allow_empty: bool,
) -> Result<Vec<u8>, ReadFileError> {
    let (fd, st) = open_and_stat_regular_fd(path, follow_symlinks)?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
        || (!allow_empty && st.st_size == 0)
        || (st.st_size as u64) > (max_bytes as u64)
    {
        return Err(ReadFileError::InvalidFile);
    }
    read_bounded_regular_fd(&fd, &st, max_bytes).map_err(|_| ReadFileError::ReadFailed)
}

/// Opens and reads a regular non-symlink file owned by the effective user and not group/world-writable.
pub(crate) fn read_owned_regular_file_limited(
    path: &Path,
    max_bytes: usize,
    require_read_only: bool,
) -> Result<Vec<u8>, ReadOwnedFileError> {
    let (fd, st) = open_and_stat_regular_fd(path, false).map_err(|_| ReadOwnedFileError::OpenFailed)?;
    let write_mask = (libc::S_IWGRP | libc::S_IWOTH) as libc::mode_t;
    let usr_write = libc::S_IWUSR as libc::mode_t;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_uid != current_euid()
        || (st.st_mode & write_mask) != 0
        || (require_read_only && (st.st_mode & usr_write) != 0)
    {
        return Err(ReadOwnedFileError::InvalidOwnershipOrPermissions);
    }
    read_bounded_regular_fd(&fd, &st, max_bytes).map_err(|_| ReadOwnedFileError::ReadFailed)
}

/// Validates ownership, immutability, non-symlink regularity, and size bounds with exact error text.
pub(crate) fn read_owned_regular_file_strict_error(
    path: &Path,
    max_bytes: usize,
    require_immutable: bool,
) -> Result<Vec<u8>, String> {
    let Some(cpath) = path_to_cstr(path) else {
        return Err(format!("lstat({}): invalid path", path.display()));
    };
    let mut lstat_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(cpath.as_ptr(), &mut lstat_st) } != 0 {
        let msg = std::io::Error::last_os_error()
            .to_string()
            .split(" (os error")
            .next()
            .unwrap_or("lstat failed")
            .to_string();
        return Err(format!("lstat({}): {}", path.display(), msg));
    }
    if (lstat_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!("not a regular non-symlink file: {}", path.display()));
    }
    if lstat_st.st_uid != current_euid() {
        return Err(format!(
            "file is not owned by the current user: {}",
            path.display()
        ));
    }
    if (lstat_st.st_mode & ((libc::S_IWGRP | libc::S_IWOTH) as libc::mode_t)) != 0 {
        return Err(format!(
            "file is group- or world-writable: {}",
            path.display()
        ));
    }
    if require_immutable && (lstat_st.st_mode & (libc::S_IWUSR as libc::mode_t)) != 0 {
        return Err(format!(
            "approval evidence is owner-writable: {}",
            path.display()
        ));
    }
    if lstat_st.st_size < 0 || (lstat_st.st_size as u64) > (max_bytes as u64) {
        return Err(format!(
            "file exceeds the accepted size limit: {}",
            path.display()
        ));
    }
    let (fd, st) = open_and_stat_regular_fd(path, false)
        .map_err(|_| format!("cannot open file: {}", path.display()))?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_dev != lstat_st.st_dev
        || st.st_ino != lstat_st.st_ino
        || st.st_uid != current_euid()
        || (st.st_mode & ((libc::S_IWGRP | libc::S_IWOTH) as libc::mode_t)) != 0
        || (require_immutable && (st.st_mode & (libc::S_IWUSR as libc::mode_t)) != 0)
    {
        return Err(format!("not a regular non-symlink file: {}", path.display()));
    }
    read_bounded_regular_fd(&fd, &st, max_bytes)
        .map_err(|_| format!("cannot read file: {}", path.display()))
}

/// Canonicalizes an absolute non-symlink regular file path with exact diagnostics.
pub(crate) fn canonical_regular_path_strict(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    let cpath =
        path_to_cstr(path).ok_or_else(|| format!("lstat({}): invalid path", path.display()))?;
    let mut lstat_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(cpath.as_ptr(), &mut lstat_st) } != 0 {
        let msg = std::io::Error::last_os_error()
            .to_string()
            .split(" (os error")
            .next()
            .unwrap_or("lstat failed")
            .to_string();
        return Err(format!("lstat({}): {}", path.display(), msg));
    }
    if (lstat_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        return Err(format!("symlink paths are not accepted: {}", path.display()));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("cannot canonicalize {}: {}", path.display(), e))?;
    match std::fs::metadata(&canonical) {
        Ok(meta) if meta.is_file() => Ok(canonical),
        _ => Err(format!(
            "canonical path is not a regular file: {}",
            canonical.display()
        )),
    }
}

/// Returns current UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` ISO-8601 format.
pub(crate) fn format_utc_iso8601_now() -> String {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut utc: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&now, &mut utc) }.is_null() {
        return "1970-01-01T00:00:00Z".to_string();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec
    )
}

pub(crate) fn epoch_seconds_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn monotonic_nanos_now() -> i64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as i64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as i64)
}

/// Acquires an exclusive blocking `flock` on a non-symlink `O_WRONLY | O_CREAT` lock file.
pub(crate) fn flock_exclusive_file(path: &Path) -> Result<OwnedFd, i32> {
    let cpath = path_to_cstr(path).ok_or(libc::EINVAL)?;
    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if raw_fd < 0 {
        return Err(last_errno());
    }
    let fd = OwnedFd::from_raw(raw_fd).ok_or(libc::EBADF)?;
    if !flock_fd(fd.as_raw(), libc::LOCK_EX) {
        return Err(last_errno());
    }
    Ok(fd)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WritePrivateError {
    OpenFailed,
    WriteFailed,
    SyncFailed,
}

fn write_private_file_inner(
    path: &Path,
    bytes: &[u8],
    extra_open_flags: i32,
    require_fsync: bool,
) -> Result<(), WritePrivateError> {
    let cpath = path_to_cstr(path).ok_or(WritePrivateError::OpenFailed)?;
    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | extra_open_flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    let fd = OwnedFd::from_raw(raw_fd).ok_or(WritePrivateError::OpenFailed)?;
    if !write_all_fd(fd.as_raw(), bytes) {
        return Err(WritePrivateError::WriteFailed);
    }
    if unsafe { libc::fsync(fd.as_raw()) } != 0 && require_fsync {
        return Err(WritePrivateError::SyncFailed);
    }
    Ok(())
}

/// Writes `bytes` to a non-symlink regular file created/truncated with mode `0600` and checks `fsync`.
pub(crate) fn write_private_trunc_file_checked(
    path: &Path,
    bytes: &[u8],
) -> Result<(), WritePrivateError> {
    write_private_file_inner(path, bytes, libc::O_TRUNC, true)
}

/// Atomically creates a new non-symlink file (`O_EXCL | O_NOFOLLOW`, `0600`) and checks `fsync`.
pub(crate) fn write_private_excl_file_checked(
    path: &Path,
    bytes: &[u8],
) -> Result<(), WritePrivateError> {
    write_private_file_inner(path, bytes, libc::O_EXCL, true)
}

/// Writes `bytes` to a non-symlink regular file created/truncated with mode `0600` and `fsync`s it.
pub(crate) fn write_private_trunc_file(path: &Path, bytes: &[u8]) -> bool {
    write_private_file_inner(path, bytes, libc::O_TRUNC, false).is_ok()
}

/// Writes an immutable artifact atomically via a temporary `O_EXCL | O_NOFOLLOW` file + `fchmod` + `fsync` + `rename`.
/// Idempotent if an identical existing regular artifact already exists with matching mode/ownership.
pub(crate) fn write_mode_exclusive_atomic(
    path: &Path,
    contents: &[u8],
    mode: libc::mode_t,
    max_existing_bytes: usize,
) -> Result<(), String> {
    if !path.as_os_str().is_empty() {
        if let Ok(existing) = read_owned_regular_file_limited(path, max_existing_bytes, mode == 0o444)
        {
            if existing == contents {
                return Ok(());
            }
            return Err("immutable approval generation collision".to_string());
        }
        if std::fs::symlink_metadata(path).is_ok() {
            return Err("immutable approval generation collision".to_string());
        }
    }
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Err("cannot create approval artifact directory".to_string());
    };
    if std::fs::create_dir_all(parent).is_err() {
        return Err("cannot create approval artifact directory".to_string());
    }
    let temp = parent.join(format!(
        ".approval-{}-{}",
        current_pid(),
        monotonic_nanos_now()
    ));
    let Some(ctemp) = path_to_cstr(&temp) else {
        return Err("cannot create approval artifact".to_string());
    };
    let raw_fd = unsafe {
        libc::open(
            ctemp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    let Some(fd) = OwnedFd::from_raw(raw_fd) else {
        return Err("cannot create approval artifact".to_string());
    };
    if !write_all_fd(fd.as_raw(), contents) {
        drop(fd);
        let _ = std::fs::remove_file(&temp);
        return Err("cannot write approval artifact".to_string());
    }
    if unsafe { libc::fchmod(fd.as_raw(), mode) } != 0 {
        drop(fd);
        let _ = std::fs::remove_file(&temp);
        return Err("cannot make approval artifact immutable".to_string());
    }
    if unsafe { libc::fsync(fd.as_raw()) } != 0 {
        drop(fd);
        let _ = std::fs::remove_file(&temp);
        return Err("cannot write approval artifact".to_string());
    }
    drop(fd);
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err("cannot publish approval artifact".to_string());
    }
    Ok(())
}

/// Snapshots a bounded non-symlink regular file to `destination`, preferring a hard link.
pub(crate) fn hard_link_or_copy_regular_bounded(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
) -> Result<(), &'static str> {
    let Ok(meta) = std::fs::symlink_metadata(source) else {
        return Err("APK candidate is not a regular file");
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("APK candidate is not a regular file");
    }
    let size = meta.len();
    if size == 0 || size > max_bytes {
        return Err("APK candidate exceeds its size limit");
    }
    if std::fs::hard_link(source, destination).is_ok() {
        return Ok(());
    }
    if std::fs::copy(source, destination).is_err() {
        return Err("cannot snapshot APK candidate");
    }
    Ok(())
}

/// Read-only memory-mapped regular file guard (`O_NOFOLLOW` + `MAP_PRIVATE`).
pub(crate) struct MappedReadOnlyFile {
    _fd: OwnedFd,
    ptr: *const u8,
    len: usize,
}

impl MappedReadOnlyFile {
    pub(crate) fn open(path: &Path) -> Result<Self, ()> {
        Self::open_bounded(path, false, 0, None).map_err(|_| ())
    }

    pub(crate) fn open_bounded(
        path: &Path,
        follow_symlinks: bool,
        min_bytes: u64,
        max_bytes: Option<u64>,
    ) -> Result<Self, ReadFileError> {
        let (fd, st) = open_and_stat_regular_fd(path, follow_symlinks)?;
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || st.st_size < 0
            || (st.st_size as u64) < min_bytes
            || max_bytes.is_some_and(|max| (st.st_size as u64) > max)
        {
            return Err(ReadFileError::InvalidFile);
        }
        let Ok(len) = usize::try_from(st.st_size) else {
            return Err(ReadFileError::InvalidFile);
        };
        if len == 0 {
            return Ok(Self {
                _fd: fd,
                ptr: std::ptr::null(),
                len: 0,
            });
        }
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd.as_raw(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(ReadFileError::ReadFailed);
        }
        Ok(Self {
            _fd: fd,
            ptr: mapped.cast::<u8>(),
            len,
        })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        if self.len == 0 || self.ptr.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

impl Drop for MappedReadOnlyFile {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                let _ = libc::munmap(self.ptr.cast_mut().cast(), self.len);
            }
        }
    }
}

pub(crate) fn filter_env_slices(entries: &[&[u8]], excluded_names: &[&[u8]]) -> Vec<CString> {
    let mut out = Vec::with_capacity(entries.len() + 12);
    for &bytes in entries {
        if bytes.contains(&0) {
            continue;
        }
        if excluded_names
            .iter()
            .any(|&name| is_env_entry(bytes, name))
        {
            continue;
        }
        if let Ok(entry) = CString::new(bytes) {
            out.push(entry);
        }
    }
    out
}

pub(crate) fn strerror_string(err: i32) -> String {
    let mut buf = [0i8; 256];
    let rc = unsafe { libc::strerror_r(err, buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
        if !s.is_empty() {
            return s.into_owned();
        }
    }
    format!("errno {err}")
}

/// Returns `true` if `path` exists as a non-symlink directory.
pub(crate) fn is_real_dir_no_symlink(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => !meta.file_type().is_symlink() && meta.is_dir(),
        Err(_) => false,
    }
}

/// Returns `true` if `path` exists as a non-symlink regular file.
pub(crate) fn is_real_file_no_symlink(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => !meta.file_type().is_symlink() && meta.is_file(),
        Err(_) => false,
    }
}

/// Canonicalizes `path` if it exists, or canonicalizes its longest existing ancestor
/// and appends remaining lexically normalized components (matching `std::filesystem::weakly_canonical`).
pub(crate) fn weakly_canonical(path: &Path) -> std::io::Result<PathBuf> {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return Ok(canon);
    }
    let abs = lexical_absolute(path)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.as_path();
    while !cur.as_os_str().is_empty() {
        match std::fs::canonicalize(cur) {
            Ok(mut resolved) => {
                for comp in tail.into_iter().rev() {
                    resolved.push(comp);
                }
                return Ok(resolved);
            }
            Err(_) => {
                let Some(name) = cur.file_name() else {
                    break;
                };
                tail.push(name.to_os_string());
                cur = match cur.parent() {
                    Some(p) => p,
                    None => break,
                };
            }
        }
    }
    Ok(abs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn filter_helper_env_omits_overrides_and_keeps_null_terminator() {
        let a = CString::new("PATH=/usr/bin").unwrap();
        let b = CString::new("MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON={\"x\":1}").unwrap();
        let c = CString::new("MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON_EXTRA=preserved").unwrap();
        let raw = [
            a.as_ptr().cast_mut(),
            b.as_ptr().cast_mut(),
            c.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ];
        let filtered = unsafe { filter_helper_env_ptrs(raw.as_ptr()) };
        assert_eq!(filtered.len(), 3);
        assert_eq!(filtered[0], raw[0]);
        assert_eq!(filtered[1], raw[2]);
        assert!(filtered[2].is_null());
    }
}
