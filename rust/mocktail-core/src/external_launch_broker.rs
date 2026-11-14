//! External launch single-owner Unix `SOCK_SEQPACKET` broker and wire protocol.
//!
//! Preserves C++'s `ExternalLaunchBroker` public contract while moving path
//! resolution and ownership checks, non-blocking forwarding client with
//! `SO_PEERCRED` verification, `poll` + `eventfd` listener worker, wire frame
//! parsing, and FIFO pending queue management into Rust.

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::runtime_bridges::{
    validate_and_canonicalize_launch_json, K_MAX_EXPERIENCE_LAUNCH_JSON_BYTES,
};
use crate::storage_paths::slice_to_str;
use crate::unix_ipc::{
    build_sockaddr_un, current_uid, errno_message, is_private_owned_dir, last_errno, lstat_cstr,
    path_to_cstr, peer_uid, poll_retry_eintr, set_socket_timeouts, EventFd, OwnedFd,
};
use crate::{copy_error, copy_to_c_buffer};

pub(crate) const EXTERNAL_LAUNCH_WIRE_PREFIX: &[u8] = b"MOCKTAIL-EXTERNAL-LAUNCH/1\n";
pub(crate) const EXTERNAL_LAUNCH_REPLY_PREFIX: &[u8] = b"MTL1";
const K_REPLY_SIZE: usize = 5;
// Keep worker pthread stack large enough for processes loading the Android guest binary.
const K_WORKER_STACK_SIZE: usize = 64 * 1024 * 1024;
const K_PEER_IO_TIMEOUT_SECONDS: i64 = 2;
const K_MAXIMUM_CONFIGURED_PENDING_LAUNCHES: usize = 64;
const K_MAX_FORWARDING_TIMEOUT_MS: i32 = 30_000;

const STATUS_OK: i32 = 0;
const STATUS_INVALID_ARGUMENT: i32 = 1;
const STATUS_FAILED_PRECONDITION: i32 = 2;
const STATUS_UNAVAILABLE: i32 = 3;
const STATUS_PLATFORM_ERROR: i32 = 5;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireReply {
    Accepted = 0,
    Invalid = 1,
    QueueFull = 2,
    Denied = 3,
    Stopping = 4,
}

#[derive(Debug, Clone)]
struct BrokerError {
    code: i32,
    message: String,
}

impl BrokerError {
    fn invalid(msg: impl Into<String>) -> Self {
        Self {
            code: STATUS_INVALID_ARGUMENT,
            message: msg.into(),
        }
    }

    fn failed(msg: impl Into<String>) -> Self {
        Self {
            code: STATUS_FAILED_PRECONDITION,
            message: msg.into(),
        }
    }

    fn unavailable(msg: impl Into<String>) -> Self {
        Self {
            code: STATUS_UNAVAILABLE,
            message: msg.into(),
        }
    }

    fn platform(msg: impl Into<String>) -> Self {
        Self {
            code: STATUS_PLATFORM_ERROR,
            message: msg.into(),
        }
    }

    fn write_to_ffi(&self, out_status: *mut i32, out_err: *mut c_char, err_cap: usize) {
        if !out_status.is_null() {
            unsafe {
                *out_status = self.code;
            }
        }
        copy_error(out_err, err_cap, &self.message);
    }
}

pub type MocktailExternalLaunchDispatchFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        canonical_json_ptr: *const c_char,
        canonical_json_len: usize,
        out_status_code: *mut i32,
        out_err: *mut c_char,
        err_cap: usize,
    ) -> i32,
>;

struct BrokerInner {
    socket_path: PathBuf,
    socket_cstr: CString,
    socket_device: libc::dev_t,
    socket_inode: libc::ino_t,
    max_pending: usize,
    pending: Mutex<VecDeque<String>>,
    stopping: AtomicBool,
    stop_event: EventFd,
    owner_uid: libc::uid_t,
}

pub struct MocktailRustExternalLaunchBroker {
    inner: Arc<BrokerInner>,
    drain_mutex: Mutex<()>,
    lifecycle_mutex: Mutex<()>,
    worker: Mutex<Option<JoinHandle<()>>>,
    started: AtomicBool,
}

fn ensure_fallback_directory(
    path: &Path,
    owner: bool,
    uid: libc::uid_t,
) -> Result<(), BrokerError> {
    let Some(cpath) = path_to_cstr(path) else {
        return Err(BrokerError::invalid(
            "external-launch socket path contains interior NUL",
        ));
    };
    if let Err(err) = lstat_cstr(&cpath) {
        if err != libc::ENOENT {
            return Err(BrokerError::platform(errno_message(
                "cannot inspect external-launch directory",
                err,
            )));
        }
        if !owner {
            return Err(BrokerError::unavailable(
                "external-launch owner endpoint is unavailable",
            ));
        }
        let rc = unsafe { libc::mkdir(cpath.as_ptr(), 0o700) };
        if rc != 0 && last_errno() != libc::EEXIST {
            return Err(BrokerError::platform(errno_message(
                "cannot create external-launch directory",
                last_errno(),
            )));
        }
    }
    if !is_private_owned_dir(path, uid) {
        return Err(BrokerError::failed(
            "external-launch directory must be private and owned by this user",
        ));
    }
    Ok(())
}

fn validate_socket_path(path: &Path, uid: libc::uid_t) -> Result<(), BrokerError> {
    if path.as_os_str().is_empty() || !path.is_absolute() || path.file_name().is_none() {
        return Err(BrokerError::invalid(
            "external-launch socket path must be absolute",
        ));
    }
    use std::os::unix::ffi::OsStrExt;
    if build_sockaddr_un(path.as_os_str().as_bytes()).is_none() {
        return Err(BrokerError::invalid(
            "external-launch socket path is too long",
        ));
    }
    let parent_ok = path
        .parent()
        .map(|p| is_private_owned_dir(p, uid))
        .unwrap_or(false);
    if !parent_ok {
        return Err(BrokerError::failed(
            "external-launch socket parent must be private and user-owned",
        ));
    }
    Ok(())
}

fn format_socket_name(instance_key: &str, is_run_user: bool) -> String {
    if is_run_user {
        format!("mocktail.{instance_key}.external-launch-v1.sock")
    } else {
        format!("{instance_key}.external-launch-v1.sock")
    }
}

fn resolve_socket_path(owner: bool, instance_key: &str) -> Result<PathBuf, BrokerError> {
    let uid = current_uid();
    // Intentionally bypass XDG_RUNTIME_DIR to keep the endpoint aligned with
    // SingleInstanceLock across sandboxed browser launchers and the owner runtime.
    let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    if is_private_owned_dir(&runtime_dir, uid) {
        let candidate = runtime_dir.join(format_socket_name(instance_key, true));
        validate_socket_path(&candidate, uid)?;
        return Ok(candidate);
    }

    let fallback = PathBuf::from(format!("/tmp/mocktail-{uid}"));
    ensure_fallback_directory(&fallback, owner, uid)?;
    let candidate = fallback.join(format_socket_name(instance_key, false));
    validate_socket_path(&candidate, uid)?;
    Ok(candidate)
}

fn send_reply(fd: RawFd, reply: WireReply) -> bool {
    let mut bytes = [0u8; K_REPLY_SIZE];
    bytes[..4].copy_from_slice(EXTERNAL_LAUNCH_REPLY_PREFIX);
    bytes[4] = reply as u8;
    let rc = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    rc == bytes.len() as isize
}

fn remaining_ms(deadline: Instant) -> i32 {
    let now = Instant::now();
    if now >= deadline {
        return 0;
    }
    let rem = deadline.saturating_duration_since(now).as_millis();
    rem.min(i32::MAX as u128) as i32
}

fn normalize_launch_json(json: &str) -> Result<String, BrokerError> {
    if json.is_empty() {
        return Err(BrokerError::invalid(
            "external-launch canonical JSON is empty",
        ));
    }
    validate_and_canonicalize_launch_json(json)
        .map_err(|_| BrokerError::invalid("external-launch canonical JSON is invalid"))
}

fn remove_owned_socket_if_matching(
    cpath: &CString,
    uid: libc::uid_t,
    expected_dev: Option<libc::dev_t>,
    expected_ino: Option<libc::ino_t>,
) {
    if let Ok(st) = lstat_cstr(cpath) {
        let matches_type_and_uid = (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK && st.st_uid == uid;
        let matches_inode = match (expected_dev, expected_ino) {
            (Some(dev), Some(ino)) => st.st_dev == dev && st.st_ino == ino,
            _ => true,
        };
        if matches_type_and_uid && matches_inode {
            unsafe {
                libc::unlink(cpath.as_ptr());
            }
        }
    }
}

fn queue_normalized(inner: &BrokerInner, canonical_json: String) -> Result<(), BrokerError> {
    if inner.stopping.load(Ordering::Acquire) {
        return Err(BrokerError::failed("external-launch broker is stopping"));
    }
    let mut guard = match inner.pending.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if inner.stopping.load(Ordering::Relaxed) {
        return Err(BrokerError::failed("external-launch broker is stopping"));
    }
    if guard.len() >= inner.max_pending {
        return Err(BrokerError::unavailable("external-launch queue is full"));
    }
    guard.push_back(canonical_json);
    Ok(())
}

fn handle_peer(inner: &BrokerInner, peer_fd: RawFd) {
    if !set_socket_timeouts(peer_fd, K_PEER_IO_TIMEOUT_SECONDS) {
        return;
    }
    match peer_uid(peer_fd) {
        Some(uid) if uid == inner.owner_uid => {}
        _ => {
            let _ = send_reply(peer_fd, WireReply::Denied);
            return;
        }
    }

    let mut poll_fds = [
        libc::pollfd {
            fd: peer_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: inner.stop_event.as_raw(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let ready = poll_retry_eintr(&mut poll_fds, (K_PEER_IO_TIMEOUT_SECONDS * 1000) as i32);
    if ready <= 0
        || (poll_fds[1].revents & libc::POLLIN) != 0
        || inner.stopping.load(Ordering::Acquire)
    {
        if (poll_fds[1].revents & libc::POLLIN) != 0 || inner.stopping.load(Ordering::Acquire) {
            let _ = send_reply(peer_fd, WireReply::Stopping);
        }
        return;
    }
    if (poll_fds[0].revents & libc::POLLIN) == 0 {
        return;
    }

    let mut packet = vec![0u8; EXTERNAL_LAUNCH_WIRE_PREFIX.len() + K_MAX_EXPERIENCE_LAUNCH_JSON_BYTES];
    let received = unsafe {
        libc::recv(
            peer_fd,
            packet.as_mut_ptr().cast::<libc::c_void>(),
            packet.len(),
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
        )
    };
    if received <= 0 {
        let _ = send_reply(peer_fd, WireReply::Invalid);
        return;
    }
    let received_len = received as usize;
    // Reject truncated oversized packets before indexing into the receive buffer.
    if received_len > packet.len() || received_len <= EXTERNAL_LAUNCH_WIRE_PREFIX.len() {
        let _ = send_reply(peer_fd, WireReply::Invalid);
        return;
    }
    let frame = &packet[..received_len];
    if !frame.starts_with(EXTERNAL_LAUNCH_WIRE_PREFIX) {
        let _ = send_reply(peer_fd, WireReply::Invalid);
        return;
    }
    let json_bytes = &frame[EXTERNAL_LAUNCH_WIRE_PREFIX.len()..];
    let Ok(json_str) = std::str::from_utf8(json_bytes) else {
        let _ = send_reply(peer_fd, WireReply::Invalid);
        return;
    };
    let Ok(normalized) = validate_and_canonicalize_launch_json(json_str) else {
        let _ = send_reply(peer_fd, WireReply::Invalid);
        return;
    };
    let reply = match queue_normalized(inner, normalized) {
        Ok(()) => WireReply::Accepted,
        Err(e) if e.code == STATUS_UNAVAILABLE => WireReply::QueueFull,
        Err(_) => WireReply::Stopping,
    };
    let _ = send_reply(peer_fd, reply);
}

fn worker_loop(inner: Arc<BrokerInner>, listener: OwnedFd) {
    while !inner.stopping.load(Ordering::Acquire) {
        let mut descriptors = [
            libc::pollfd {
                fd: listener.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: inner.stop_event.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let poll_result = poll_retry_eintr(&mut descriptors, -1);
        if poll_result <= 0
            || (descriptors[1].revents & libc::POLLIN) != 0
            || inner.stopping.load(Ordering::Acquire)
        {
            break;
        }
        if (descriptors[0].revents & libc::POLLIN) == 0 {
            continue;
        }
        while !inner.stopping.load(Ordering::Acquire) {
            let raw_peer = unsafe {
                libc::accept4(
                    listener.as_raw(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw_peer < 0 {
                let err = last_errno();
                if err == libc::EINTR {
                    continue;
                }
                break;
            }
            if let Some(peer) = OwnedFd::from_raw(raw_peer) {
                handle_peer(&inner, peer.as_raw());
            }
        }
    }
}

fn connect_once(path: &Path, timeout_ms: i32) -> Result<OwnedFd, i32> {
    use std::os::unix::ffi::OsStrExt;
    let Some((address, address_len)) = build_sockaddr_un(path.as_os_str().as_bytes()) else {
        return Err(libc::EINVAL);
    };
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    let Some(fd) = OwnedFd::from_raw(raw) else {
        return Err(last_errno());
    };
    let rc = unsafe {
        libc::connect(
            fd.as_raw(),
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            address_len,
        )
    };
    if rc == 0 {
        return Ok(fd);
    }
    let err = last_errno();
    if err != libc::EINPROGRESS && err != libc::EAGAIN {
        return Err(err);
    }

    let mut wait = [libc::pollfd {
        fd: fd.as_raw(),
        events: libc::POLLOUT,
        revents: 0,
    }];
    let poll_rc = poll_retry_eintr(&mut wait, timeout_ms);
    if poll_rc <= 0 {
        return Err(if poll_rc == 0 {
            libc::ETIMEDOUT
        } else {
            last_errno()
        });
    }
    let mut so_error: c_int = 0;
    let mut error_size = mem::size_of::<c_int>() as libc::socklen_t;
    let opt_rc = unsafe {
        libc::getsockopt(
            fd.as_raw(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut so_error as *mut c_int).cast::<libc::c_void>(),
            &mut error_size,
        )
    };
    if opt_rc != 0 {
        return Err(last_errno());
    }
    if so_error != 0 {
        return Err(so_error);
    }
    Ok(fd)
}

fn send_forward_packet(
    fd: &OwnedFd,
    packet: &[u8],
    uid: libc::uid_t,
    deadline: Instant,
) -> Result<(), BrokerError> {
    match peer_uid(fd.as_raw()) {
        Some(p_uid) if p_uid == uid => {}
        _ => {
            return Err(BrokerError::failed(
                "external-launch owner credential check failed",
            ));
        }
    }

    loop {
        let sent = unsafe {
            libc::send(
                fd.as_raw(),
                packet.as_ptr().cast::<libc::c_void>(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent == packet.len() as isize {
            break;
        }
        if sent >= 0 {
            return Err(BrokerError::platform(
                "external-launch request was only partially sent",
            ));
        }
        let err = last_errno();
        if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
            return Err(BrokerError::platform(errno_message(
                "cannot send external-launch request",
                err,
            )));
        }
        let rem = remaining_ms(deadline);
        if rem == 0 {
            return Err(BrokerError::unavailable(
                "external-launch forwarding timed out",
            ));
        }
        let mut wait = [libc::pollfd {
            fd: fd.as_raw(),
            events: libc::POLLOUT,
            revents: 0,
        }];
        let poll_rc = poll_retry_eintr(&mut wait, rem);
        if poll_rc <= 0 {
            return Err(if poll_rc == 0 {
                BrokerError::unavailable("external-launch forwarding timed out")
            } else {
                BrokerError::platform(errno_message("cannot wait to forward launch", last_errno()))
            });
        }
    }

    let mut reply = [0u8; K_REPLY_SIZE];
    let received = loop {
        let rem = remaining_ms(deadline);
        if rem == 0 {
            return Err(BrokerError::unavailable(
                "external-launch owner ACK timed out",
            ));
        }
        let mut wait = [libc::pollfd {
            fd: fd.as_raw(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let poll_rc = poll_retry_eintr(&mut wait, rem);
        if poll_rc <= 0 {
            return Err(if poll_rc == 0 {
                BrokerError::unavailable("external-launch owner ACK timed out")
            } else {
                BrokerError::platform(errno_message("cannot wait for launch ACK", last_errno()))
            });
        }
        let rc = unsafe {
            libc::recv(
                fd.as_raw(),
                reply.as_mut_ptr().cast::<libc::c_void>(),
                reply.len(),
                0,
            )
        };
        if rc < 0 {
            let err = last_errno();
            if err == libc::EINTR || err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                continue;
            }
        }
        break rc;
    };
    if received != K_REPLY_SIZE as isize || &reply[..4] != EXTERNAL_LAUNCH_REPLY_PREFIX {
        return Err(BrokerError::platform(
            "external-launch owner returned an invalid ACK",
        ));
    }

    match reply[4] {
        0 => Ok(()),
        1 => Err(BrokerError::invalid(
            "external-launch owner rejected the normalized request",
        )),
        2 => Err(BrokerError::unavailable(
            "external-launch owner queue is full",
        )),
        3 => Err(BrokerError::failed(
            "external-launch owner denied the forwarding peer",
        )),
        4 => Err(BrokerError::unavailable(
            "external-launch owner is stopping",
        )),
        _ => Err(BrokerError::platform(
            "external-launch owner returned an unknown ACK",
        )),
    }
}

fn shutdown_broker(broker: &MocktailRustExternalLaunchBroker) -> Result<(), BrokerError> {
    let _lifecycle_guard = match broker.lifecycle_mutex.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if !broker.started.load(Ordering::Acquire) {
        return Ok(());
    }
    let _drain_guard = match broker.drain_mutex.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    broker.inner.stopping.store(true, Ordering::Release);
    broker.inner.stop_event.signal();

    let handle = match broker.worker.lock() {
        Ok(mut w) => w.take(),
        Err(p) => p.into_inner().take(),
    };
    if let Some(h) = handle {
        if h.join().is_err() {
            return Err(BrokerError::platform(
                "external-launch worker panicked during shutdown",
            ));
        }
    }

    remove_owned_socket_if_matching(
        &broker.inner.socket_cstr,
        broker.inner.owner_uid,
        Some(broker.inner.socket_device),
        Some(broker.inner.socket_inode),
    );
    if let Ok(mut guard) = broker.inner.pending.lock() {
        guard.clear();
    }
    broker.started.store(false, Ordering::Release);
    Ok(())
}

// ============================================================================
// Wire Protocol C-ABI Exports (Preserved + Re-exported)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_build_packet(
    json_ptr: *const c_char,
    json_len: usize,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    if json_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let total_len = EXTERNAL_LAUNCH_WIRE_PREFIX.len() + json_len;
    if total_len + 1 > out_cap {
        return -1;
    }
    unsafe {
        let dst = slice::from_raw_parts_mut(out_buf as *mut u8, out_cap);
        dst[..EXTERNAL_LAUNCH_WIRE_PREFIX.len()].copy_from_slice(EXTERNAL_LAUNCH_WIRE_PREFIX);
        let json_slice = slice::from_raw_parts(json_ptr as *const u8, json_len);
        dst[EXTERNAL_LAUNCH_WIRE_PREFIX.len()..total_len].copy_from_slice(json_slice);
        dst[total_len] = 0;
    }
    total_len as c_int
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_verify_and_strip_prefix(
    packet_ptr: *const c_char,
    packet_len: usize,
    out_json_offset: *mut usize,
    out_json_len: *mut usize,
) -> c_int {
    if packet_ptr.is_null() || out_json_offset.is_null() || out_json_len.is_null() {
        return -1;
    }
    if packet_len <= EXTERNAL_LAUNCH_WIRE_PREFIX.len() {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(packet_ptr as *const u8, packet_len) };
    if !slice.starts_with(EXTERNAL_LAUNCH_WIRE_PREFIX) {
        return -1;
    }
    unsafe {
        *out_json_offset = EXTERNAL_LAUNCH_WIRE_PREFIX.len();
        *out_json_len = packet_len - EXTERNAL_LAUNCH_WIRE_PREFIX.len();
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_build_reply(
    reply_code: u8,
    out_bytes: *mut u8,
    out_cap: usize,
) -> c_int {
    if out_bytes.is_null() || out_cap < K_REPLY_SIZE {
        return -1;
    }
    unsafe {
        let dst = slice::from_raw_parts_mut(out_bytes, out_cap);
        dst[..4].copy_from_slice(EXTERNAL_LAUNCH_REPLY_PREFIX);
        dst[4] = reply_code;
    }
    K_REPLY_SIZE as c_int
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_parse_reply(
    in_bytes: *const u8,
    in_len: usize,
    out_reply_code: *mut u8,
) -> c_int {
    if in_bytes.is_null() || out_reply_code.is_null() || in_len != K_REPLY_SIZE {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(in_bytes, in_len) };
    if &slice[..4] != EXTERNAL_LAUNCH_REPLY_PREFIX {
        return -1;
    }
    unsafe { *out_reply_code = slice[4] };
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_reply_status_code(reply_code: u8) -> c_int {
    match reply_code {
        0 => STATUS_OK,
        1 => STATUS_INVALID_ARGUMENT,
        2 => STATUS_UNAVAILABLE,
        3 => STATUS_FAILED_PRECONDITION,
        4 => STATUS_UNAVAILABLE,
        _ => STATUS_PLATFORM_ERROR,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_format_socket_name(
    instance_key_ptr: *const c_char,
    is_run_user: c_int,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    if instance_key_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let key = unsafe { CStr::from_ptr(instance_key_ptr).to_str().unwrap_or("") };
    let name = format_socket_name(key, is_run_user != 0);
    copy_to_c_buffer(&name, out_buf, out_cap)
}

// ============================================================================
// Broker Lifecycle & Forwarding C-ABI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_resolve_socket_path(
    owner: bool,
    instance_key_ptr: *const c_char,
    instance_key_len: usize,
    out_path: *mut c_char,
    path_cap: usize,
    out_status: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(instance_key) = slice_to_str(instance_key_ptr, instance_key_len) else {
        BrokerError::invalid("external-launch instance key is invalid").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    };
    match resolve_socket_path(owner, instance_key) {
        Ok(path) => {
            let s = path.to_string_lossy();
            if copy_to_c_buffer(&s, out_path, path_cap) != 0 {
                BrokerError::invalid("external-launch socket path buffer is too small")
                    .write_to_ffi(out_status, out_err, err_cap);
                return -1;
            }
            if !out_status.is_null() {
                unsafe {
                    *out_status = STATUS_OK;
                }
            }
            0
        }
        Err(err) => {
            err.write_to_ffi(out_status, out_err, err_cap);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_start(
    socket_path_ptr: *const c_char,
    socket_path_len: usize,
    instance_key_ptr: *const c_char,
    instance_key_len: usize,
    maximum_pending_launches: usize,
    forwarding_timeout_ms: i32,
    has_initial: bool,
    initial_json_ptr: *const c_char,
    initial_json_len: usize,
    out_broker: *mut *mut MocktailRustExternalLaunchBroker,
    out_status: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if out_broker.is_null() {
        BrokerError::invalid("external-launch broker output is null").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    }
    unsafe {
        *out_broker = std::ptr::null_mut();
    }

    if maximum_pending_launches == 0
        || maximum_pending_launches > K_MAXIMUM_CONFIGURED_PENDING_LAUNCHES
        || forwarding_timeout_ms <= 0
        || forwarding_timeout_ms > K_MAX_FORWARDING_TIMEOUT_MS
    {
        BrokerError::invalid("external-launch broker options are invalid").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    }

    let mut pending = VecDeque::new();
    if has_initial {
        let Some(raw_json) = slice_to_str(initial_json_ptr, initial_json_len) else {
            BrokerError::invalid("external-launch canonical JSON is invalid").write_to_ffi(
                out_status,
                out_err,
                err_cap,
            );
            return -1;
        };
        match normalize_launch_json(raw_json) {
            Ok(normalized) => pending.push_back(normalized),
            Err(err) => {
                err.write_to_ffi(out_status, out_err, err_cap);
                return -1;
            }
        }
    }

    let uid = current_uid();
    let requested_path = slice_to_str(socket_path_ptr, socket_path_len).unwrap_or("");
    let socket_path = if requested_path.is_empty() {
        let Some(instance_key) = slice_to_str(instance_key_ptr, instance_key_len) else {
            BrokerError::invalid("external-launch instance key is invalid").write_to_ffi(
                out_status,
                out_err,
                err_cap,
            );
            return -1;
        };
        match resolve_socket_path(true, instance_key) {
            Ok(p) => p,
            Err(err) => {
                err.write_to_ffi(out_status, out_err, err_cap);
                return -1;
            }
        }
    } else {
        let p = PathBuf::from(requested_path);
        if let Err(err) = validate_socket_path(&p, uid) {
            err.write_to_ffi(out_status, out_err, err_cap);
            return -1;
        }
        p
    };

    let Some(socket_cstr) = path_to_cstr(&socket_path) else {
        BrokerError::invalid("external-launch socket path is invalid").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    };

    match lstat_cstr(&socket_cstr) {
        Ok(stale) => {
            if (stale.st_mode & libc::S_IFMT) != libc::S_IFSOCK || stale.st_uid != uid {
                BrokerError::failed("external-launch endpoint is not an owned stale socket")
                    .write_to_ffi(out_status, out_err, err_cap);
                return -1;
            }
            if unsafe { libc::unlink(socket_cstr.as_ptr()) } != 0 {
                BrokerError::platform(errno_message(
                    "cannot remove stale external-launch socket",
                    last_errno(),
                ))
                .write_to_ffi(out_status, out_err, err_cap);
                return -1;
            }
        }
        Err(libc::ENOENT) => {}
        Err(err) => {
            BrokerError::platform(errno_message("cannot inspect external-launch socket", err))
                .write_to_ffi(out_status, out_err, err_cap);
            return -1;
        }
    }

    let raw_listener = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    let Some(listener) = OwnedFd::from_raw(raw_listener) else {
        BrokerError::platform(errno_message(
            "cannot create external-launch socket",
            last_errno(),
        ))
        .write_to_ffi(out_status, out_err, err_cap);
        return -1;
    };

    use std::os::unix::ffi::OsStrExt;
    let Some((address, address_len)) = build_sockaddr_un(socket_path.as_os_str().as_bytes()) else {
        BrokerError::invalid("external-launch socket path is too long").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    };

    let bind_ok = unsafe {
        libc::bind(
            listener.as_raw(),
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            address_len,
        ) == 0
            && libc::chmod(socket_cstr.as_ptr(), 0o600) == 0
            && libc::listen(listener.as_raw(), maximum_pending_launches as c_int) == 0
    };
    if !bind_ok {
        let err = last_errno();
        drop(listener);
        remove_owned_socket_if_matching(&socket_cstr, uid, None, None);
        BrokerError::platform(errno_message("cannot activate external-launch socket", err))
            .write_to_ffi(out_status, out_err, err_cap);
        return -1;
    }

    let bound = match lstat_cstr(&socket_cstr) {
        Ok(st)
            if (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
                && st.st_uid == uid
                && (st.st_mode & 0o077) == 0 =>
        {
            st
        }
        _ => {
            drop(listener);
            remove_owned_socket_if_matching(&socket_cstr, uid, None, None);
            BrokerError::failed("external-launch socket ownership is invalid").write_to_ffi(
                out_status,
                out_err,
                err_cap,
            );
            return -1;
        }
    };

    let stop_event = match EventFd::new() {
        Ok(ev) => ev,
        Err(err) => {
            drop(listener);
            remove_owned_socket_if_matching(
                &socket_cstr,
                uid,
                Some(bound.st_dev),
                Some(bound.st_ino),
            );
            BrokerError::platform(errno_message(
                "cannot create external-launch stop event",
                err,
            ))
            .write_to_ffi(out_status, out_err, err_cap);
            return -1;
        }
    };

    let inner = Arc::new(BrokerInner {
        socket_path,
        socket_cstr: socket_cstr.clone(),
        socket_device: bound.st_dev,
        socket_inode: bound.st_ino,
        max_pending: maximum_pending_launches,
        pending: Mutex::new(pending),
        stopping: AtomicBool::new(false),
        stop_event,
        owner_uid: uid,
    });

    let worker_inner = Arc::clone(&inner);
    let worker_handle = match thread::Builder::new()
        .name("mocktail-ext-broker".to_string())
        .stack_size(K_WORKER_STACK_SIZE)
        .spawn(move || worker_loop(worker_inner, listener))
    {
        Ok(h) => h,
        Err(err) => {
            let code = err.raw_os_error().unwrap_or(libc::ENOMEM);
            remove_owned_socket_if_matching(
                &socket_cstr,
                uid,
                Some(bound.st_dev),
                Some(bound.st_ino),
            );
            BrokerError::platform(format!(
                "cannot start external-launch broker worker: {}",
                code
            ))
            .write_to_ffi(out_status, out_err, err_cap);
            return -1;
        }
    };

    let broker = Box::new(MocktailRustExternalLaunchBroker {
        inner,
        drain_mutex: Mutex::new(()),
        lifecycle_mutex: Mutex::new(()),
        worker: Mutex::new(Some(worker_handle)),
        started: AtomicBool::new(true),
    });
    unsafe {
        *out_broker = Box::into_raw(broker);
    }
    if !out_status.is_null() {
        unsafe {
            *out_status = STATUS_OK;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_forward_to_owner(
    socket_path_ptr: *const c_char,
    socket_path_len: usize,
    instance_key_ptr: *const c_char,
    instance_key_len: usize,
    forwarding_timeout_ms: i32,
    json_ptr: *const c_char,
    json_len: usize,
    out_status: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if forwarding_timeout_ms <= 0 || forwarding_timeout_ms > K_MAX_FORWARDING_TIMEOUT_MS {
        BrokerError::invalid("external-launch forwarding timeout is invalid").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    }

    let Some(raw_json) = slice_to_str(json_ptr, json_len) else {
        BrokerError::invalid("external-launch canonical JSON is invalid").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    };
    let normalized = match normalize_launch_json(raw_json) {
        Ok(s) => s,
        Err(err) => {
            err.write_to_ffi(out_status, out_err, err_cap);
            return -1;
        }
    };

    let requested_path = slice_to_str(socket_path_ptr, socket_path_len).unwrap_or("");
    let instance_key = slice_to_str(instance_key_ptr, instance_key_len).unwrap_or("");
    let uid = current_uid();

    let mut packet = Vec::with_capacity(EXTERNAL_LAUNCH_WIRE_PREFIX.len() + normalized.len());
    packet.extend_from_slice(EXTERNAL_LAUNCH_WIRE_PREFIX);
    packet.extend_from_slice(normalized.as_bytes());

    let deadline = Instant::now() + Duration::from_millis(forwarding_timeout_ms as u64);
    let mut last_error: i32 = libc::ENOENT;

    while remaining_ms(deadline) > 0 {
        let path_result = if requested_path.is_empty() {
            resolve_socket_path(false, instance_key)
        } else {
            let p = PathBuf::from(requested_path);
            validate_socket_path(&p, uid).map(|()| p)
        };
        match path_result {
            Err(err) => {
                if err.code != STATUS_UNAVAILABLE {
                    err.write_to_ffi(out_status, out_err, err_cap);
                    return -1;
                }
            }
            Ok(path) => match connect_once(&path, remaining_ms(deadline)) {
                Ok(fd) => match send_forward_packet(&fd, &packet, uid, deadline) {
                    Ok(()) => {
                        if !out_status.is_null() {
                            unsafe {
                                *out_status = STATUS_OK;
                            }
                        }
                        return 0;
                    }
                    Err(err) => {
                        err.write_to_ffi(out_status, out_err, err_cap);
                        return -1;
                    }
                },
                Err(connect_err) => {
                    last_error = connect_err;
                    if !matches!(
                        last_error,
                        libc::ENOENT | libc::ECONNREFUSED | libc::EAGAIN | libc::ETIMEDOUT
                    ) {
                        BrokerError::platform(errno_message(
                            "cannot connect to external-launch owner",
                            last_error,
                        ))
                        .write_to_ffi(out_status, out_err, err_cap);
                        return -1;
                    }
                }
            },
        }
        let rem = remaining_ms(deadline);
        if rem > 0 {
            thread::sleep(Duration::from_millis((rem.min(20)) as u64));
        }
    }

    BrokerError::unavailable(errno_message(
        "external-launch owner is unavailable",
        last_error,
    ))
    .write_to_ffi(out_status, out_err, err_cap);
    -1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_queue_initial(
    broker: *mut MocktailRustExternalLaunchBroker,
    json_ptr: *const c_char,
    json_len: usize,
    out_status: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if broker.is_null() {
        BrokerError::invalid("external-launch broker is null").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    }
    let Some(raw_json) = slice_to_str(json_ptr, json_len) else {
        BrokerError::invalid("external-launch canonical JSON is invalid").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    };
    let normalized = match normalize_launch_json(raw_json) {
        Ok(s) => s,
        Err(err) => {
            err.write_to_ffi(out_status, out_err, err_cap);
            return -1;
        }
    };
    let b = unsafe { &*broker };
    match queue_normalized(&b.inner, normalized) {
        Ok(()) => {
            if !out_status.is_null() {
                unsafe {
                    *out_status = STATUS_OK;
                }
            }
            0
        }
        Err(err) => {
            err.write_to_ffi(out_status, out_err, err_cap);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_drain(
    broker: *mut MocktailRustExternalLaunchBroker,
    maximum_requests: usize,
    on_dispatch: MocktailExternalLaunchDispatchFn,
    dispatch_ctx: *mut c_void,
    out_status: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if broker.is_null() || on_dispatch.is_none() {
        BrokerError::invalid("external-launch sink is incomplete").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    }
    let b = unsafe { &*broker };
    let dispatch = on_dispatch.unwrap();
    let _drain_guard = match b.drain_mutex.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if b.inner.stopping.load(Ordering::Acquire) {
        BrokerError::failed("external-launch broker is stopping").write_to_ffi(
            out_status,
            out_err,
            err_cap,
        );
        return -1;
    }

    for _ in 0..maximum_requests {
        let next = {
            let mut guard = match b.inner.pending.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.pop_front()
        };
        let Some(canonical_json) = next else {
            break;
        };

        let mut dispatch_status: i32 = STATUS_PLATFORM_ERROR;
        let rc = unsafe {
            dispatch(
                dispatch_ctx,
                canonical_json.as_ptr().cast::<c_char>(),
                canonical_json.len(),
                &mut dispatch_status,
                out_err,
                err_cap,
            )
        };
        if rc != 0 {
            let mut guard = match b.inner.pending.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.push_front(canonical_json);
            if !out_status.is_null() {
                unsafe {
                    *out_status = dispatch_status;
                }
            }
            return -1;
        }
    }

    if !out_status.is_null() {
        unsafe {
            *out_status = STATUS_OK;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_shutdown(
    broker: *mut MocktailRustExternalLaunchBroker,
    out_status: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if broker.is_null() {
        if !out_status.is_null() {
            unsafe {
                *out_status = STATUS_OK;
            }
        }
        return 0;
    }
    let b = unsafe { &*broker };
    match shutdown_broker(b) {
        Ok(()) => {
            if !out_status.is_null() {
                unsafe {
                    *out_status = STATUS_OK;
                }
            }
            0
        }
        Err(err) => {
            err.write_to_ffi(out_status, out_err, err_cap);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_destroy(
    broker: *mut MocktailRustExternalLaunchBroker,
) {
    if broker.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(broker) };
    let _ = shutdown_broker(&boxed);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_pending_count(
    broker: *const MocktailRustExternalLaunchBroker,
) -> usize {
    if broker.is_null() {
        return 0;
    }
    let b = unsafe { &*broker };
    match b.inner.pending.lock() {
        Ok(g) => g.len(),
        Err(p) => p.into_inner().len(),
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_broker_socket_path(
    broker: *const MocktailRustExternalLaunchBroker,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    if broker.is_null() {
        return -1;
    }
    let b = unsafe { &*broker };
    let s = b.inner.socket_path.to_string_lossy();
    copy_to_c_buffer(&s, out_buf, out_cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let unique = format!(
                "{}_{}_{}",
                prefix,
                unsafe { libc::getpid() },
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct CaptureState {
        items: Vec<String>,
        reject_next: bool,
    }

    unsafe extern "C" fn capture_dispatch(
        ctx: *mut c_void,
        ptr: *const c_char,
        len: usize,
        out_status: *mut i32,
        out_err: *mut c_char,
        err_cap: usize,
    ) -> i32 {
        let state = &mut *(ctx as *mut CaptureState);
        if state.reject_next {
            state.reject_next = false;
            *out_status = STATUS_UNAVAILABLE;
            copy_error(out_err, err_cap, "sink temporarily busy");
            return -1;
        }
        let s = slice_to_str(ptr, len).unwrap().to_string();
        state.items.push(s);
        *out_status = STATUS_OK;
        0
    }

    fn start_test_broker(
        sock_path: &Path,
        max_pending: usize,
    ) -> *mut MocktailRustExternalLaunchBroker {
        let s = sock_path.to_string_lossy();
        let mut broker: *mut MocktailRustExternalLaunchBroker = std::ptr::null_mut();
        let mut status = 0;
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_external_launch_broker_start(
            s.as_ptr().cast::<c_char>(),
            s.len(),
            b"testkey".as_ptr().cast::<c_char>(),
            7,
            max_pending,
            1000,
            false,
            std::ptr::null(),
            0,
            &mut broker,
            &mut status,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(status, STATUS_OK);
        broker
    }

    #[test]
    fn resolves_socket_ignoring_xdg_runtime_dir() {
        let _env_guard = crate::unix_ipc::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TestDir::new("mocktail_ext_xdg");
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", &dir.path);

        let mut out = [0 as c_char; 512];
        let mut status = 0;
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_external_launch_resolve_socket_path(
            true,
            b"abc123".as_ptr().cast::<c_char>(),
            6,
            out.as_mut_ptr(),
            out.len(),
            &mut status,
            err.as_mut_ptr(),
            err.len(),
        );

        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }

        assert_eq!(rc, 0);
        let resolved = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert!(!resolved.starts_with(&*dir.path.to_string_lossy()));
        assert!(resolved.contains("abc123"));
    }

    #[test]
    fn forwards_queues_drains_requeues_and_shuts_down() {
        let dir = TestDir::new("mocktail_ext_broker");
        let sock_path = dir.path.join("broker.sock");
        let broker = start_test_broker(&sock_path, 2);

        let req1 = r#"{"placeId":1001}"#;
        let req2 = r#"{"placeId":1002,"gameInstanceId":"srv2"}"#;
        let req3 = r#"{"placeId":1003}"#;

        let mut status = 0;
        let mut err = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_external_launch_broker_queue_initial(
                broker,
                req1.as_ptr().cast::<c_char>(),
                req1.len(),
                &mut status,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );

        let sock_str = sock_path.to_string_lossy();
        assert_eq!(
            mocktail_rust_external_launch_forward_to_owner(
                sock_str.as_ptr().cast::<c_char>(),
                sock_str.len(),
                b"k".as_ptr().cast::<c_char>(),
                1,
                1000,
                req2.as_ptr().cast::<c_char>(),
                req2.len(),
                &mut status,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );

        // Queue capacity is 2 -> forwarding req3 fails closed with Unavailable.
        assert_ne!(
            mocktail_rust_external_launch_forward_to_owner(
                sock_str.as_ptr().cast::<c_char>(),
                sock_str.len(),
                b"k".as_ptr().cast::<c_char>(),
                1,
                1000,
                req3.as_ptr().cast::<c_char>(),
                req3.len(),
                &mut status,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(status, STATUS_UNAVAILABLE);
        assert_eq!(mocktail_rust_external_launch_broker_pending_count(broker), 2);

        let mut capture = CaptureState {
            items: Vec::new(),
            reject_next: true,
        };
        assert_ne!(
            mocktail_rust_external_launch_broker_drain(
                broker,
                2,
                Some(capture_dispatch),
                (&mut capture as *mut CaptureState).cast::<c_void>(),
                &mut status,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(status, STATUS_UNAVAILABLE);
        assert_eq!(mocktail_rust_external_launch_broker_pending_count(broker), 2);

        assert_eq!(
            mocktail_rust_external_launch_broker_drain(
                broker,
                2,
                Some(capture_dispatch),
                (&mut capture as *mut CaptureState).cast::<c_void>(),
                &mut status,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(capture.items.len(), 2);
        assert!(capture.items[0].contains("1001"));
        assert!(capture.items[1].contains("srv2"));
        assert_eq!(mocktail_rust_external_launch_broker_pending_count(broker), 0);

        mocktail_rust_external_launch_broker_destroy(broker);
        assert!(!sock_path.exists());
    }

    #[test]
    fn refuses_regular_file_and_replaces_stale_socket() {
        let dir = TestDir::new("mocktail_ext_files");
        let regular_path = dir.path.join("not_a_socket");
        let mut f = File::create(&regular_path).unwrap();
        f.write_all(b"keep-me").unwrap();
        drop(f);

        let mut broker: *mut MocktailRustExternalLaunchBroker = std::ptr::null_mut();
        let mut status = 0;
        let mut err = [0 as c_char; 256];
        let s = regular_path.to_string_lossy();
        let rc = mocktail_rust_external_launch_broker_start(
            s.as_ptr().cast::<c_char>(),
            s.len(),
            b"k".as_ptr().cast::<c_char>(),
            1,
            4,
            1000,
            false,
            std::ptr::null(),
            0,
            &mut broker,
            &mut status,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_ne!(rc, 0);
        assert_eq!(status, STATUS_FAILED_PRECONDITION);
        assert!(regular_path.exists());

        // Bind a stale owned SEQPACKET socket and close it cleanly.
        let stale_path = dir.path.join("stale.sock");
        {
            use std::os::unix::ffi::OsStrExt;
            let (addr, alen) = build_sockaddr_un(stale_path.as_os_str().as_bytes()).unwrap();
            let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
            let owned = OwnedFd::from_raw(raw).unwrap();
            assert_eq!(
                unsafe {
                    libc::bind(
                        owned.as_raw(),
                        (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                        alen,
                    )
                },
                0
            );
        }
        let broker2 = start_test_broker(&stale_path, 4);
        assert!(std::fs::symlink_metadata(&stale_path).unwrap().file_type().is_socket());
        mocktail_rust_external_launch_broker_destroy(broker2);
        assert!(!stale_path.exists());
    }
}
