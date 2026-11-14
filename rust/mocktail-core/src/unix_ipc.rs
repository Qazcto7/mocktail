//! Shared POSIX Unix-domain IPC, process-spawning, and descriptor helpers
//! used across `discord_rpc`, `external_launch_broker`,
//! `webview_helper_launcher`, and `roblox_cookie_store`.

use std::ffi::{CStr, CString};
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::RawFd;
use std::path::Path;

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

pub(crate) fn path_to_cstr(path: &Path) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).ok()
}

pub(crate) fn lstat_cstr(cpath: &CString) -> Result<libc::stat, i32> {
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

/// Checks that `path` is absolute, a non-symlink regular file (`lstat`), and executable (`X_OK`).
pub(crate) fn validate_executable_absolute_regular_file(path: &Path) -> bool {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return false;
    }
    let Some(cpath) = path_to_cstr(path) else {
        return false;
    };
    let Ok(st) = lstat_cstr(&cpath) else {
        return false;
    };
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && unsafe { libc::access(cpath.as_ptr(), libc::X_OK) == 0 }
}

const HELPER_EXCLUDED_ENV_PREFIX: &[u8] = b"MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON=";

/// Filters `envp` (`NULL`-terminated C string pointers), omitting entries starting
/// with `MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON=`. Pointers remain valid while the
/// parent environment is unmodified.
pub(crate) unsafe fn filter_helper_env_ptrs(envp: *const *mut libc::c_char) -> Vec<*mut libc::c_char> {
    let mut out = Vec::new();
    if !envp.is_null() {
        let mut cur = envp;
        while !(*cur).is_null() {
            let entry = *cur;
            let bytes = CStr::from_ptr(entry).to_bytes();
            if !bytes.starts_with(HELPER_EXCLUDED_ENV_PREFIX) {
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
