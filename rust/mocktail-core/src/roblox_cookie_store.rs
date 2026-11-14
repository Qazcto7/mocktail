//! Secure Roblox cookie file reader, legacy SQLite cookie cleaner, and
//! `mocktail_cookie_helper` libsecret subprocess IPC client.

use std::ffi::{c_char, c_void};
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::unix_ipc::{
    build_filtered_helper_env_ptrs, current_euid, last_errno, lexical_absolute,
    move_fd_above_stdio, path_from_ffi, path_to_cstr, poll_retry_eintr, slice_from_ffi,
    validate_executable_absolute_regular_file, OwnedFd,
};

pub const K_COOKIE_STATUS_FOUND: i32 = 0;
pub const K_COOKIE_STATUS_MISSING: i32 = 1;
pub const K_COOKIE_STATUS_UNAVAILABLE: i32 = 2;

const K_MAXIMUM_COOKIE_BYTES: usize = 1024 * 1024;
const K_MAXIMUM_PROFILE_KEY_BYTES: usize = 4096;
const K_HELPER_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

pub type MocktailRustCookieStringCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const c_char, len: usize)>;

fn read_roblox_cookie_file_impl(
    path: &Path,
    required: bool,
) -> (i32, Zeroizing<Vec<u8>>, String) {
    let Some(cpath) = path_to_cstr(path) else {
        return (
            K_COOKIE_STATUS_UNAVAILABLE,
            Zeroizing::new(Vec::new()),
            "configured Roblox cookie file is unavailable".to_string(),
        );
    };

    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw_fd < 0 {
        let err = last_errno();
        if err == libc::ENOENT && !required {
            return (
                K_COOKIE_STATUS_MISSING,
                Zeroizing::new(Vec::new()),
                String::new(),
            );
        }
        return (
            K_COOKIE_STATUS_UNAVAILABLE,
            Zeroizing::new(Vec::new()),
            "configured Roblox cookie file is unavailable".to_string(),
        );
    }
    let fd = OwnedFd::from_raw(raw_fd).expect("raw_fd >= 0");

    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    let euid = current_euid();
    if unsafe { libc::fstat(fd.as_raw(), metadata.as_mut_ptr()) } != 0 {
        return (
            K_COOKIE_STATUS_UNAVAILABLE,
            Zeroizing::new(Vec::new()),
            "Roblox cookie source is not a regular file".to_string(),
        );
    }
    let metadata = unsafe { metadata.assume_init() };
    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG || metadata.st_uid != euid {
        return (
            K_COOKIE_STATUS_UNAVAILABLE,
            Zeroizing::new(Vec::new()),
            "Roblox cookie source is not a regular file".to_string(),
        );
    }
    if (metadata.st_mode & (libc::S_IRWXG | libc::S_IRWXO)) != 0 {
        return (
            K_COOKIE_STATUS_UNAVAILABLE,
            Zeroizing::new(Vec::new()),
            "Roblox cookie file permissions are not private".to_string(),
        );
    }
    if metadata.st_size < 0 || (metadata.st_size as u64) > K_MAXIMUM_COOKIE_BYTES as u64 {
        return (
            K_COOKIE_STATUS_UNAVAILABLE,
            Zeroizing::new(Vec::new()),
            "Roblox cookie file exceeds the safe read limit".to_string(),
        );
    }

    let mut value = Zeroizing::new(Vec::with_capacity(metadata.st_size as usize));
    let mut buffer = Zeroizing::new([0u8; 4096]);
    let mut read_error = String::new();
    loop {
        let count = unsafe {
            libc::read(
                fd.as_raw(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if count == 0 {
            break;
        }
        if count < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            read_error = "Roblox cookie file could not be read safely".to_string();
            break;
        }
        let n = count as usize;
        if value.len() + n > K_MAXIMUM_COOKIE_BYTES {
            read_error = "Roblox cookie file could not be read safely".to_string();
            break;
        }
        value.extend_from_slice(&buffer[..n]);
    }
    buffer.zeroize();

    if read_error.is_empty() {
        let mut after = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd.as_raw(), after.as_mut_ptr()) } != 0 {
            read_error = "Roblox cookie file changed while it was read".to_string();
        } else {
            let after = unsafe { after.assume_init() };
            if metadata.st_size != after.st_size
                || metadata.st_mtime != after.st_mtime
                || metadata.st_mtime_nsec != after.st_mtime_nsec
                || metadata.st_ctime != after.st_ctime
                || metadata.st_ctime_nsec != after.st_ctime_nsec
                || (after.st_size as usize) != value.len()
            {
                read_error = "Roblox cookie file changed while it was read".to_string();
            }
        }
    }

    if read_error.is_empty() && required && value.is_empty() {
        read_error = "configured Roblox cookie file is empty".to_string();
    }

    if !read_error.is_empty() {
        value.zeroize();
        return (K_COOKIE_STATUS_UNAVAILABLE, value, read_error);
    }

    (K_COOKIE_STATUS_FOUND, value, String::new())
}

fn remove_legacy_webview_cookies_impl(directory: &Path) -> bool {
    if directory.as_os_str().is_empty() {
        return true;
    }
    let Some(cdir) = path_to_cstr(directory) else {
        return false;
    };
    let raw_fd = unsafe {
        libc::open(
            cdir.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw_fd < 0 {
        return last_errno() == libc::ENOENT;
    }
    let dir_fd = OwnedFd::from_raw(raw_fd).expect("raw_fd >= 0");
    let euid = current_euid();

    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(dir_fd.as_raw(), metadata.as_mut_ptr()) } != 0 {
        return false;
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_uid != euid {
        return false;
    }

    const LEGACY_NAMES: [&[u8]; 4] = [
        b"cookies.sqlite\0",
        b"cookies.sqlite-wal\0",
        b"cookies.sqlite-shm\0",
        b"cookies.sqlite-journal\0",
    ];
    for name in LEGACY_NAMES {
        let mut entry_stat = MaybeUninit::<libc::stat>::zeroed();
        let rc = unsafe {
            libc::fstatat(
                dir_fd.as_raw(),
                name.as_ptr().cast::<c_char>(),
                entry_stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            if last_errno() == libc::ENOENT {
                continue;
            }
            return false;
        }
        let st = unsafe { entry_stat.assume_init() };
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_uid != euid || st.st_nlink != 1 {
            return false;
        }
        if unsafe { libc::unlinkat(dir_fd.as_raw(), name.as_ptr().cast::<c_char>(), 0) } != 0 {
            return false;
        }
    }

    unsafe { libc::fsync(dir_fd.as_raw()) == 0 }
}

fn resolve_cookie_helper_path(install_libdir: &str) -> Option<PathBuf> {
    if let Some(override_path) = std::env::var_os("MOCKTAIL_COOKIE_HELPER") {
        let p = PathBuf::from(override_path);
        return if validate_executable_absolute_regular_file(&p) {
            Some(p)
        } else {
            None
        };
    }

    let exe = std::fs::read_link("/proc/self/exe").ok()?;
    let directory = exe.parent()?;
    let libdir = if install_libdir.is_empty() {
        "lib"
    } else {
        install_libdir
    };

    let mut candidates = Vec::with_capacity(4);
    candidates.push(directory.join("mocktail_cookie_helper"));
    if let Some(parent) = directory.parent() {
        candidates.push(parent.join(libdir).join("mocktail/mocktail_cookie_helper"));
        candidates.push(parent.join("libexec/mocktail/mocktail_cookie_helper"));
        if directory.file_name().and_then(|n| n.to_str()) == Some("tests") {
            candidates.push(parent.join("mocktail_cookie_helper"));
        }
    }

    candidates
        .into_iter()
        .find(|p| validate_executable_absolute_regular_file(p))
}

fn spawn_cookie_helper_exchange(
    helper: &Path,
    child_fd: RawFd,
    parent_fd: RawFd,
) -> Option<libc::pid_t> {
    let program = path_to_cstr(helper)?;
    let mut program_buf = program.into_bytes_with_nul();
    let mut actions: libc::posix_spawn_file_actions_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut status = unsafe { libc::posix_spawn_file_actions_init(&mut actions) };
    if status != 0 {
        return None;
    }

    if status == 0 {
        status = unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions, child_fd, libc::STDIN_FILENO) };
    }
    if status == 0 {
        status = unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions, child_fd, libc::STDOUT_FILENO) };
    }
    if status == 0 {
        status = unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, parent_fd) };
    }
    if status == 0 {
        status = unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, child_fd) };
    }

    let mut child: libc::pid_t = -1;
    if status == 0 {
        let mut argv = [
            program_buf.as_mut_ptr().cast::<c_char>(),
            std::ptr::null_mut(),
        ];
        let env = unsafe { build_filtered_helper_env_ptrs() };
        status = unsafe {
            libc::posix_spawn(
                &mut child,
                program_buf.as_ptr().cast::<c_char>(),
                &actions,
                std::ptr::null(),
                argv.as_mut_ptr(),
                env.as_ptr(),
            )
        };
    }
    unsafe {
        libc::posix_spawn_file_actions_destroy(&mut actions);
    }
    if status == 0 && child > 0 {
        Some(child)
    } else {
        None
    }
}

fn exchange_cookie_impl(
    operation: u8,
    profile: &Path,
    cookie: &[u8],
    install_libdir: &str,
) -> Zeroizing<Vec<u8>> {
    let helper = match resolve_cookie_helper_path(install_libdir) {
        Some(h) => h,
        None => return Zeroizing::new(Vec::new()),
    };
    let abs_profile = match lexical_absolute(profile) {
        Some(p) => p,
        None => return Zeroizing::new(Vec::new()),
    };
    use std::os::unix::ffi::OsStrExt;
    let key = abs_profile.as_os_str().as_bytes();
    if key.is_empty()
        || key.len() > K_MAXIMUM_PROFILE_KEY_BYTES
        || key.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0)
        || cookie.len() > K_MAXIMUM_COOKIE_BYTES
    {
        return Zeroizing::new(Vec::new());
    }

    let mut sockets = [-1 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sockets.as_mut_ptr()) }
        != 0
    {
        return Zeroizing::new(Vec::new());
    }
    let Some(parent_sock) = OwnedFd::from_raw(sockets[0]).and_then(move_fd_above_stdio) else {
        let _ = OwnedFd::from_raw(sockets[1]);
        return Zeroizing::new(Vec::new());
    };
    let Some(child_sock) = OwnedFd::from_raw(sockets[1]).and_then(move_fd_above_stdio) else {
        return Zeroizing::new(Vec::new());
    };

    let child_pid = match spawn_cookie_helper_exchange(&helper, child_sock.as_raw(), parent_sock.as_raw()) {
        Some(pid) => pid,
        None => return Zeroizing::new(Vec::new()),
    };
    drop(child_sock);

    let mut request = Zeroizing::new(Vec::with_capacity(2 + key.len() + 1 + cookie.len()));
    request.push(operation);
    request.push(b'\n');
    request.extend_from_slice(key);
    request.push(b'\n');
    request.extend_from_slice(cookie);

    let mut response = Zeroizing::new(Vec::new());
    let mut sent = 0usize;
    let mut eof = false;
    let mut exited = false;
    let mut child_status: libc::c_int = 0;
    let deadline = Instant::now() + K_HELPER_EXCHANGE_TIMEOUT;

    while Instant::now() < deadline && !(eof && exited) {
        if !exited {
            let reaped = unsafe { libc::waitpid(child_pid, &mut child_status, libc::WNOHANG) };
            if reaped == child_pid {
                exited = true;
            } else if reaped < 0 && last_errno() != libc::EINTR {
                exited = true;
                child_status = 1 << 8;
                break;
            }
        }
        if eof {
            unsafe {
                libc::poll(std::ptr::null_mut(), 0, 20);
            }
            continue;
        }
        let events = libc::POLLIN | if sent < request.len() { libc::POLLOUT } else { 0 };
        let mut pfd = [libc::pollfd {
            fd: parent_sock.as_raw(),
            events,
            revents: 0,
        }];
        let poll_rc = poll_retry_eintr(&mut pfd, 20);
        if poll_rc < 0 {
            break;
        }
        let revents = pfd[0].revents;
        if (revents & libc::POLLOUT) != 0 && sent < request.len() {
            let count = unsafe {
                libc::send(
                    parent_sock.as_raw(),
                    request.as_ptr().add(sent).cast::<libc::c_void>(),
                    request.len() - sent,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if count > 0 {
                sent += count as usize;
                if sent == request.len() {
                    unsafe {
                        libc::shutdown(parent_sock.as_raw(), libc::SHUT_WR);
                    }
                }
            } else if count < 0 {
                let err = last_errno();
                if err != libc::EINTR && err != libc::EAGAIN && err != libc::EWOULDBLOCK {
                    break;
                }
            }
        }
        if (revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            let mut buffer = Zeroizing::new([0u8; 4096]);
            let count = unsafe {
                libc::recv(
                    parent_sock.as_raw(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if count == 0 {
                eof = true;
            } else if count > 0 {
                response.extend_from_slice(&buffer[..count as usize]);
            } else {
                let err = last_errno();
                if err != libc::EINTR && err != libc::EAGAIN && err != libc::EWOULDBLOCK {
                    buffer.zeroize();
                    break;
                }
            }
            buffer.zeroize();
            if response.len() > K_MAXIMUM_COOKIE_BYTES + 1 {
                break;
            }
        }
    }

    drop(parent_sock);
    request.zeroize();

    if !exited {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            while libc::waitpid(child_pid, &mut child_status, 0) < 0 && last_errno() == libc::EINTR {}
        }
    }

    if !exited
        || !eof
        || !libc::WIFEXITED(child_status)
        || libc::WEXITSTATUS(child_status) != 0
        || response.len() > K_MAXIMUM_COOKIE_BYTES + 1
    {
        response.zeroize();
        response.clear();
    }

    response
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_read_roblox_cookie_file(
    path_ptr: *const c_char,
    path_len: usize,
    required: i32,
    on_value: MocktailRustCookieStringCallback,
    on_error: MocktailRustCookieStringCallback,
    ctx: *mut c_void,
) -> i32 {
    let Some(path) = path_from_ffi(path_ptr, path_len) else {
        if let Some(cb) = on_error {
            let msg = b"configured Roblox cookie file is unavailable";
            cb(ctx, msg.as_ptr().cast::<c_char>(), msg.len());
        }
        return K_COOKIE_STATUS_UNAVAILABLE;
    };

    let (status, mut value, err_msg) = read_roblox_cookie_file_impl(&path, required != 0);
    if status == K_COOKIE_STATUS_FOUND {
        if let Some(cb) = on_value {
            cb(ctx, value.as_ptr().cast::<c_char>(), value.len());
        }
    } else if !err_msg.is_empty() {
        if let Some(cb) = on_error {
            cb(ctx, err_msg.as_ptr().cast::<c_char>(), err_msg.len());
        }
    }
    value.zeroize();
    status
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_remove_legacy_webview_cookies(
    dir_ptr: *const c_char,
    dir_len: usize,
) -> i32 {
    let Some(path) = path_from_ffi(dir_ptr, dir_len) else {
        return 0;
    };
    if remove_legacy_webview_cookies_impl(&path) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_cookie_helper_exchange(
    operation: u8,
    profile_ptr: *const c_char,
    profile_len: usize,
    cookie_ptr: *const c_char,
    cookie_len: usize,
    install_libdir_ptr: *const c_char,
    install_libdir_len: usize,
    on_response: MocktailRustCookieStringCallback,
    ctx: *mut c_void,
) -> i32 {
    if cookie_ptr.is_null() && cookie_len > 0 {
        return -1;
    }
    let Some(profile) = path_from_ffi(profile_ptr, profile_len) else {
        return -1;
    };
    let cookie = slice_from_ffi(cookie_ptr, cookie_len);
    let libdir_bytes = slice_from_ffi(install_libdir_ptr, install_libdir_len);
    let libdir = std::str::from_utf8(libdir_bytes).unwrap_or("lib");

    let mut response = exchange_cookie_impl(operation, &profile, cookie, libdir);
    if response.is_empty() {
        return -1;
    }
    if let Some(cb) = on_response {
        cb(ctx, response.as_ptr().cast::<c_char>(), response.len());
    }
    response.zeroize();
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_ipc::{current_pid, TEST_ENV_LOCK};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let unique = format!(
                "{}_{}_{}",
                prefix,
                current_pid(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, val: &Path) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref p) = self.prev {
                std::env::set_var(self.key, p);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn reads_private_cookie_file_and_rejects_unsafe_permissions_and_symlinks() {
        let dir = TempDir::new("mocktail_cookie_test");
        let missing = dir.path.join("missing.cookie");
        assert_eq!(read_roblox_cookie_file_impl(&missing, false).0, K_COOKIE_STATUS_MISSING);
        assert_eq!(read_roblox_cookie_file_impl(&missing, true).0, K_COOKIE_STATUS_UNAVAILABLE);

        let valid = dir.path.join("valid.cookie");
        std::fs::write(&valid, b"_|secret-token").unwrap();
        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (status, val, err) = read_roblox_cookie_file_impl(&valid, true);
        assert_eq!(status, K_COOKIE_STATUS_FOUND, "unexpected err: {err}");
        assert_eq!(&*val, b"_|secret-token");

        let empty = dir.path.join("empty.cookie");
        std::fs::write(&empty, b"").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_roblox_cookie_file_impl(&empty, false).0, K_COOKIE_STATUS_FOUND);
        assert_eq!(read_roblox_cookie_file_impl(&empty, true).0, K_COOKIE_STATUS_UNAVAILABLE);

        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(read_roblox_cookie_file_impl(&valid, false).0, K_COOKIE_STATUS_UNAVAILABLE);

        let symlink_path = dir.path.join("link.cookie");
        std::os::unix::fs::symlink(&empty, &symlink_path).unwrap();
        assert_eq!(read_roblox_cookie_file_impl(&symlink_path, false).0, K_COOKIE_STATUS_UNAVAILABLE);
    }

    #[test]
    fn removes_only_regular_legacy_cookie_sqlite_files() {
        let dir = TempDir::new("mocktail_legacy_cookies");
        assert!(remove_legacy_webview_cookies_impl(Path::new("")));
        assert!(remove_legacy_webview_cookies_impl(&dir.path.join("nonexistent")));

        for name in ["cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm", "cookies.sqlite-journal"] {
            std::fs::write(dir.path.join(name), b"sqlite").unwrap();
        }
        std::fs::write(dir.path.join("keep.txt"), b"ok").unwrap();
        assert!(remove_legacy_webview_cookies_impl(&dir.path));
        assert!(!dir.path.join("cookies.sqlite").exists());
        assert!(dir.path.join("keep.txt").exists());

        // Symlink named cookies.sqlite must fail closed without removing target.
        let target = dir.path.join("target.db");
        std::fs::write(&target, b"real").unwrap();
        std::os::unix::fs::symlink(&target, dir.path.join("cookies.sqlite")).unwrap();
        assert!(!remove_legacy_webview_cookies_impl(&dir.path));
        assert!(target.exists());
    }

    #[test]
    fn exchanges_cookies_with_helper_executable() {
        let _env_guard = TEST_ENV_LOCK.lock().unwrap();
        let dir = TempDir::new("mocktail_cookie_helper_ipc");
        let helper = dir.path.join("fake_cookie_helper.sh");
        let captured = dir.path.join("captured_req");
        let script = format!(
            "#!/bin/sh\ncat > '{}'\nprintf 'F_|helper-cookie'\n",
            captured.display()
        );
        std::fs::write(&helper, script).unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();

        let _env = EnvVarGuard::set("MOCKTAIL_COOKIE_HELPER", &helper);
        let resp = exchange_cookie_impl(b'L', Path::new("rel/../profile"), b"", "lib");

        assert_eq!(&*resp, b"F_|helper-cookie");
        let req_bytes = std::fs::read(&captured).unwrap();
        assert!(req_bytes.starts_with(b"L\n"));
        assert!(!req_bytes.windows(4).any(|w| w == b"/../"));
    }
}
