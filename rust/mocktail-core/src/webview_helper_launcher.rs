//! Bounded WebView helper process launcher, private `SOCK_SEQPACKET` / TCP
//! control channel, URL origin/path sanitizer, and control/event packet codec.

use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CStr};
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::unix_ipc::{
    build_filtered_helper_env_ptrs, errno_message, last_errno, path_to_cstr, poll_retry_eintr,
    set_cloexec, set_nonblocking, validate_executable_absolute_regular_file, write_all_fd,
    OwnedFd,
};
use crate::{copy_error, is_valid_cookie_octet, webview_is_roblox_host_str};

pub const K_MAXIMUM_WEBVIEW_URL_BYTES: usize = 16 * 1024;
pub const K_MAXIMUM_WEBVIEW_TITLE_BYTES: usize = 512;
pub const K_MAXIMUM_WEBVIEW_JAVASCRIPT_BYTES: usize = 64 * 1024;
pub const K_MAXIMUM_WEBVIEW_COOKIE_BYTES: usize = 16 * 1024;
pub const K_MAXIMUM_WEBVIEW_CONTROL_PACKET_BYTES: usize = K_MAXIMUM_WEBVIEW_JAVASCRIPT_BYTES + 12;
pub const K_MAXIMUM_WEBVIEW_HYBRID_EVENT_BYTES: usize = 64 * 1024;
pub const K_MAXIMUM_WEBVIEW_EVENT_PACKET_BYTES: usize = K_MAXIMUM_WEBVIEW_HYBRID_EVENT_BYTES + 12;
pub const K_WEBVIEW_HELPER_CONTROL_DESCRIPTOR: RawFd = 198;

const K_PROTOCOL_HEADER: &[u8] = b"MOCKTAIL-WEBVIEW 1\n";
const K_CONTROL_MAGIC: &[u8; 4] = b"MWVC";
const K_EVENT_MAGIC: &[u8; 4] = b"MWVE";
const K_CONTROL_PROTOCOL_VERSION: u8 = 1;
const K_CONTROL_HEADER_BYTES: usize = 12;
const K_MAXIMUM_REQUEST_BYTES: usize =
    K_PROTOCOL_HEADER.len() + 20 + 1 + K_MAXIMUM_WEBVIEW_URL_BYTES;
const K_INTERNAL_ROUTE_PREFIX: &str = "www:";
const K_ROBLOX_WEB_ORIGIN: &str = "https://www.roblox.com/";
const K_FREEBSD_WEBVIEW_PORT: u16 = 2137;

pub const K_WEBVIEW_OP_LOAD_URL: u8 = 1;
pub const K_WEBVIEW_OP_SET_TITLE: u8 = 2;
pub const K_WEBVIEW_OP_SET_VISIBLE: u8 = 3;
pub const K_WEBVIEW_OP_EVALUATE_JAVASCRIPT: u8 = 4;
pub const K_WEBVIEW_OP_CLOSE: u8 = 5;
pub const K_WEBVIEW_OP_SET_BACK_NAVIGATION_DISABLED: u8 = 6;
pub const K_WEBVIEW_OP_SET_SHOW_DOMAIN_AS_TITLE: u8 = 7;
pub const K_WEBVIEW_OP_SET_ROBLOX_COOKIE: u8 = 8;
pub const K_WEBVIEW_OP_CLEAR_ROBLOX_COOKIE: u8 = 9;
pub const K_WEBVIEW_OP_RETAIN_PERSISTENT_ROBLOX_COOKIE: u8 = 10;

pub const K_WEBVIEW_EVENT_EXECUTE_ROBLOX: u8 = 1;
pub const K_WEBVIEW_EVENT_ROBLOX_WK_HYBRID: u8 = 2;
pub const K_WEBVIEW_EVENT_READY: u8 = 3;
pub const K_WEBVIEW_EVENT_ROBLOX_COOKIE: u8 = 4;

pub type MocktailRustWebViewBytesCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const c_char, len: usize)>;
pub type MocktailRustWebViewControlCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, operation: u8, payload: *const c_char, payload_len: usize, visible: i32)>;
pub type MocktailRustWebViewEventCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, event_type: u8, payload: *const c_char, payload_len: usize)>;
pub type MocktailRustWebViewExitFn = Option<unsafe extern "C" fn(ctx: *mut c_void)>;

fn contains_control_bytes(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b < 0x20 || b == 0x7f)
}

fn hex_digit_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn has_unsafe_path(path: &[u8]) -> bool {
    let mut segment = Vec::with_capacity(path.len());
    let mut i = 0usize;
    while i <= path.len() {
        if i == path.len() || path[i] == b'/' {
            if segment == b"." || segment == b".." {
                return true;
            }
            segment.clear();
            i += 1;
            continue;
        }
        let mut decoded = path[i];
        if decoded == b'%' {
            if i + 2 >= path.len() {
                return true;
            }
            let Some(hi) = hex_digit_value(path[i + 1]) else {
                return true;
            };
            let Some(lo) = hex_digit_value(path[i + 2]) else {
                return true;
            };
            decoded = (hi << 4) | lo;
            i += 2;
            if decoded == b'/' || decoded == b'\\' {
                return true;
            }
        }
        if decoded < 0x20 || decoded == 0x7f || decoded == b'\\' {
            return true;
        }
        segment.push(decoded);
        i += 1;
    }
    false
}

/// Extracts the un-normalized raw path component from `url` (before WHATWG dot-segment collapse).
fn extract_raw_url_path(url: &str) -> &str {
    let Some(scheme_end) = url.find("://") else {
        return "";
    };
    let after_scheme = &url[scheme_end + 3..];
    let Some(first_delim) = after_scheme.find(['/', '?', '#']) else {
        return "";
    };
    if after_scheme.as_bytes()[first_delim] != b'/' {
        return "";
    }
    let from_slash = &after_scheme[first_delim..];
    let end = from_slash.find(['?', '#']).unwrap_or(from_slash.len());
    &from_slash[..end]
}

fn extract_raw_authority(url: &str) -> &str {
    let Some(scheme_end) = url.find("://") else {
        return "";
    };
    let after_scheme = &url[scheme_end + 3..];
    let end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
    &after_scheme[..end]
}

pub(crate) fn validate_webview_url(url: &str) -> Result<(), &'static str> {
    if url.is_empty() || url.len() > K_MAXIMUM_WEBVIEW_URL_BYTES || contains_control_bytes(url.as_bytes()) {
        return Err("webview URL is empty, oversized, or contains control bytes");
    }
    let parsed = Url::parse(url).map_err(|_| "webview URL is malformed")?;
    let raw_host = parsed.host_str().unwrap_or("");
    if !parsed.scheme().eq_ignore_ascii_case("https")
        || raw_host.is_empty()
        || !webview_is_roblox_host_str(raw_host)
    {
        return Err("webview URL must use HTTPS on roblox.com");
    }
    let raw_authority = extract_raw_authority(url);
    if !parsed.username().is_empty() || parsed.password().is_some() || raw_authority.contains('@') {
        return Err("webview URL must not contain user information");
    }
    if let Some(port) = parsed.port() {
        if port != 443 {
            return Err("webview URL must use the default HTTPS port");
        }
    }
    if has_unsafe_path(extract_raw_url_path(url).as_bytes()) || has_unsafe_path(parsed.path().as_bytes()) {
        return Err("webview URL contains an unsafe path");
    }
    Ok(())
}

pub(crate) fn normalize_webview_url(url: &str) -> Result<Zeroizing<String>, &'static str> {
    if url.is_empty() || url.len() > K_MAXIMUM_WEBVIEW_URL_BYTES || contains_control_bytes(url.as_bytes()) {
        return Err("webview URL is empty, oversized, or contains control bytes");
    }
    let normalized = if let Some(route) = url.strip_prefix(K_INTERNAL_ROUTE_PREFIX) {
        if route.is_empty() || route.starts_with('/') {
            return Err("webview internal Roblox route is invalid");
        }
        let mut s = String::with_capacity(K_ROBLOX_WEB_ORIGIN.len() + route.len());
        s.push_str(K_ROBLOX_WEB_ORIGIN);
        s.push_str(route);
        Zeroizing::new(s)
    } else {
        Zeroizing::new(url.to_string())
    };
    validate_webview_url(&normalized)?;
    Ok(normalized)
}

fn encode_request(url: &str) -> Zeroizing<Vec<u8>> {
    let len_str = url.len().to_string();
    let mut out =
        Zeroizing::new(Vec::with_capacity(K_PROTOCOL_HEADER.len() + len_str.len() + 1 + url.len()));
    out.extend_from_slice(K_PROTOCOL_HEADER);
    out.extend_from_slice(len_str.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(url.as_bytes());
    out
}

pub(crate) fn decode_webview_request(request: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    if request.len() > K_MAXIMUM_REQUEST_BYTES || !request.starts_with(K_PROTOCOL_HEADER) {
        return Err("webview request has an invalid protocol header");
    }
    let rest = &request[K_PROTOCOL_HEADER.len()..];
    let Some(nl_pos) = rest.iter().position(|&b| b == b'\n') else {
        return Err("webview request has no bounded URL length");
    };
    let len_bytes = &rest[..nl_pos];
    if len_bytes.is_empty() || !len_bytes.iter().all(|b| b.is_ascii_digit()) {
        return Err("webview request URL length is invalid");
    }
    let Ok(len_str) = std::str::from_utf8(len_bytes) else {
        return Err("webview request URL length is invalid");
    };
    let Ok(expected_len) = len_str.parse::<usize>() else {
        return Err("webview request URL length is invalid");
    };
    let decoded = &rest[nl_pos + 1..];
    if expected_len != decoded.len() || expected_len > K_MAXIMUM_WEBVIEW_URL_BYTES {
        return Err("webview request URL length is invalid");
    }
    let Ok(url_str) = std::str::from_utf8(decoded) else {
        return Err("webview URL is empty, oversized, or contains control bytes");
    };
    validate_webview_url(url_str)?;
    Ok(Zeroizing::new(url_str.to_string()))
}

fn encode_packet_header(magic: &[u8; 4], op_or_type: u8, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut packet = Zeroizing::new(Vec::with_capacity(K_CONTROL_HEADER_BYTES + payload.len()));
    packet.extend_from_slice(magic);
    packet.push(K_CONTROL_PROTOCOL_VERSION);
    packet.push(op_or_type);
    packet.push(0);
    packet.push(0);
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub(crate) fn decode_control_packet(
    packet: &[u8],
) -> Result<(u8, Zeroizing<Vec<u8>>, bool), &'static str> {
    if packet.len() < K_CONTROL_HEADER_BYTES
        || packet.len() > K_MAXIMUM_WEBVIEW_CONTROL_PACKET_BYTES
        || &packet[0..4] != K_CONTROL_MAGIC
        || packet[4] != K_CONTROL_PROTOCOL_VERSION
        || packet[6] != 0
        || packet[7] != 0
    {
        return Err("webview control packet has an invalid header");
    }
    let payload_size = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]) as usize;
    let payload = &packet[K_CONTROL_HEADER_BYTES..];
    if payload_size != payload.len() {
        return Err("webview control packet has an invalid payload length");
    }
    let op = packet[5];
    let contains_nul = payload.contains(&0);
    match op {
        K_WEBVIEW_OP_LOAD_URL => {
            let url_str = std::str::from_utf8(payload)
                .map_err(|_| "webview URL is empty, oversized, or contains control bytes")?;
            validate_webview_url(url_str)?;
        }
        K_WEBVIEW_OP_SET_TITLE => {
            if payload.len() > K_MAXIMUM_WEBVIEW_TITLE_BYTES || contains_control_bytes(payload) {
                return Err("webview control title is oversized or unsafe");
            }
        }
        K_WEBVIEW_OP_SET_VISIBLE
        | K_WEBVIEW_OP_SET_BACK_NAVIGATION_DISABLED
        | K_WEBVIEW_OP_SET_SHOW_DOMAIN_AS_TITLE => {
            if payload.len() != 1 || (payload[0] != 0 && payload[0] != 1) {
                return Err("webview control boolean payload is invalid");
            }
        }
        K_WEBVIEW_OP_EVALUATE_JAVASCRIPT => {
            if payload.len() > K_MAXIMUM_WEBVIEW_JAVASCRIPT_BYTES || contains_nul {
                return Err("webview control JavaScript is oversized or contains NUL");
            }
        }
        K_WEBVIEW_OP_SET_ROBLOX_COOKIE => {
            if payload.is_empty()
                || payload.len() > K_MAXIMUM_WEBVIEW_COOKIE_BYTES
                || !payload.iter().copied().all(is_valid_cookie_octet)
            {
                return Err("webview Roblox cookie is oversized or unsafe");
            }
        }
        K_WEBVIEW_OP_CLEAR_ROBLOX_COOKIE => {
            if !payload.is_empty() {
                return Err("webview Roblox cookie clear payload must be empty");
            }
        }
        K_WEBVIEW_OP_RETAIN_PERSISTENT_ROBLOX_COOKIE => {
            if !payload.is_empty() {
                return Err("webview Roblox cookie retention payload must be empty");
            }
        }
        K_WEBVIEW_OP_CLOSE => {
            if !payload.is_empty() {
                return Err("webview control close payload must be empty");
            }
        }
        _ => return Err("webview control operation is unsupported"),
    }

    let visible = !payload.is_empty() && payload[0] != 0;
    Ok((op, Zeroizing::new(payload.to_vec()), visible))
}

pub(crate) fn encode_event_packet(
    event_type: u8,
    payload: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let is_ready = event_type == K_WEBVIEW_EVENT_READY;
    let is_cookie = event_type == K_WEBVIEW_EVENT_ROBLOX_COOKIE;
    let max_bytes = if is_cookie {
        K_MAXIMUM_WEBVIEW_COOKIE_BYTES
    } else {
        K_MAXIMUM_WEBVIEW_HYBRID_EVENT_BYTES
    };
    if (!is_ready && payload.is_empty())
        || payload.len() > max_bytes
        || payload.contains(&0)
        || !matches!(
            event_type,
            K_WEBVIEW_EVENT_EXECUTE_ROBLOX
                | K_WEBVIEW_EVENT_ROBLOX_WK_HYBRID
                | K_WEBVIEW_EVENT_READY
                | K_WEBVIEW_EVENT_ROBLOX_COOKIE
        )
    {
        return None;
    }
    Some(encode_packet_header(K_EVENT_MAGIC, event_type, payload))
}

pub(crate) fn decode_event_packet(
    packet: &[u8],
) -> Result<(u8, Zeroizing<Vec<u8>>), &'static str> {
    if packet.len() < K_CONTROL_HEADER_BYTES
        || packet.len() > K_MAXIMUM_WEBVIEW_EVENT_PACKET_BYTES
        || &packet[0..4] != K_EVENT_MAGIC
        || packet[4] != K_CONTROL_PROTOCOL_VERSION
        || packet[6] != 0
        || packet[7] != 0
    {
        return Err("webview event packet has an invalid header");
    }
    let payload_size = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]) as usize;
    let payload = &packet[K_CONTROL_HEADER_BYTES..];
    if payload_size != payload.len() || payload.contains(&0) {
        return Err("webview event packet has an invalid payload");
    }
    let event_type = packet[5];
    if !matches!(
        event_type,
        K_WEBVIEW_EVENT_EXECUTE_ROBLOX
            | K_WEBVIEW_EVENT_ROBLOX_WK_HYBRID
            | K_WEBVIEW_EVENT_READY
            | K_WEBVIEW_EVENT_ROBLOX_COOKIE
    ) {
        return Err("webview event type is unsupported");
    }
    if payload.is_empty() != (event_type == K_WEBVIEW_EVENT_READY)
        || (event_type == K_WEBVIEW_EVENT_ROBLOX_COOKIE
            && payload.len() > K_MAXIMUM_WEBVIEW_COOKIE_BYTES)
    {
        return Err("webview event payload does not match its type");
    }
    Ok((event_type, Zeroizing::new(payload.to_vec())))
}

fn frame_tcp_packet(packet: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut framed = Zeroizing::new(Vec::with_capacity(4 + packet.len()));
    framed.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    framed.extend_from_slice(packet);
    framed
}

fn extract_tcp_frame(buffer: &mut Vec<u8>) -> Option<Zeroizing<Vec<u8>>> {
    if buffer.len() < 4 {
        return None;
    }
    let size = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if size > K_MAXIMUM_WEBVIEW_EVENT_PACKET_BYTES {
        buffer.zeroize();
        buffer.clear();
        return None;
    }
    if buffer.len() < 4 + size {
        return None;
    }
    let frame = Zeroizing::new(buffer[4..4 + size].to_vec());
    let remaining = buffer.len() - (4 + size);
    buffer.copy_within(4 + size.., 0);
    // Clear trailing stale bytes before truncating.
    buffer[remaining..].zeroize();
    buffer.truncate(remaining);
    Some(frame)
}

fn host_is_freebsd() -> bool {
    let Ok(mut f) = std::fs::File::open("/proc/version") else {
        return false;
    };
    let mut buf = [0u8; 511];
    let n = f.read(&mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]);
    text.contains("FreeBSD") || text.contains("freebsd.org")
}

fn connect_to_freebsd_host() -> Option<OwnedFd> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let fd = OwnedFd::from_raw(raw)?;
    let _ = set_cloexec(fd.as_raw(), true);
    let mut addr: libc::sockaddr_in = unsafe { MaybeUninit::zeroed().assume_init() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = K_FREEBSD_WEBVIEW_PORT.to_be();
    addr.sin_addr = libc::in_addr {
        s_addr: libc::INADDR_LOOPBACK.to_be(),
    };
    let enabled: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd.as_raw(),
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&enabled as *const libc::c_int).cast::<c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    let rc = unsafe {
        libc::connect(
            fd.as_raw(),
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 || !set_nonblocking(fd.as_raw()) {
        return None;
    }
    Some(fd)
}

struct ControlInner {
    control_fd: RawFd,
    pending_events: VecDeque<(u8, Zeroizing<Vec<u8>>)>,
    receive_buffer: Vec<u8>,
    tcp: bool,
    ready: bool,
}

impl ControlInner {
    fn close_descriptor(&mut self) {
        if self.control_fd >= 0 {
            unsafe {
                libc::close(self.control_fd);
            }
            self.control_fd = -1;
        }
    }
}

impl Drop for ControlInner {
    fn drop(&mut self) {
        self.close_descriptor();
        self.receive_buffer.zeroize();
    }
}

pub struct MocktailRustWebViewProcess {
    child: AtomicI32,
    inner: Mutex<ControlInner>,
}

enum PacketRead {
    Packet(Zeroizing<Vec<u8>>),
    Again,
    Eof,
    Error,
}

impl MocktailRustWebViewProcess {
    fn receive_packet(inner: &mut ControlInner) -> PacketRead {
        if inner.control_fd < 0 {
            return PacketRead::Error;
        }
        if !inner.tcp {
            let mut packet = Zeroizing::new(vec![0u8; K_MAXIMUM_WEBVIEW_EVENT_PACKET_BYTES]);
            let count = unsafe {
                libc::recv(
                    inner.control_fd,
                    packet.as_mut_ptr().cast::<c_void>(),
                    packet.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if count < 0 {
                let err = last_errno();
                if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                    return PacketRead::Again;
                }
                return PacketRead::Error;
            }
            if count == 0 {
                return PacketRead::Eof;
            }
            let n = count as usize;
            if n > packet.len() {
                // Truncated oversized datagram; drop safely.
                return PacketRead::Error;
            }
            packet.truncate(n);
            return PacketRead::Packet(packet);
        }

        loop {
            if let Some(frame) = extract_tcp_frame(&mut inner.receive_buffer) {
                return PacketRead::Packet(frame);
            }
            let mut chunk = Zeroizing::new([0u8; 4096]);
            let count = unsafe {
                libc::read(
                    inner.control_fd,
                    chunk.as_mut_ptr().cast::<c_void>(),
                    chunk.len(),
                )
            };
            if count < 0 {
                let err = last_errno();
                if err == libc::EINTR {
                    continue;
                }
                if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                    return PacketRead::Again;
                }
                return PacketRead::Error;
            }
            if count == 0 {
                return PacketRead::Eof;
            }
            inner.receive_buffer.extend_from_slice(&chunk[..count as usize]);
            if inner.receive_buffer.len() > K_MAXIMUM_WEBVIEW_EVENT_PACKET_BYTES * 2 {
                inner.receive_buffer.zeroize();
                inner.receive_buffer.clear();
                return PacketRead::Error;
            }
        }
    }

    pub(crate) fn running(&self) -> bool {
        let Ok(inner) = self.inner.lock() else {
            return false;
        };
        if !inner.tcp {
            return self.child.load(Ordering::Acquire) > 0;
        }
        if inner.control_fd < 0 || self.child.load(Ordering::Acquire) <= 0 {
            return false;
        }
        let mut probe = [libc::pollfd {
            fd: inner.control_fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        let rc = unsafe { libc::poll(probe.as_mut_ptr(), 1, 0) };
        if rc > 0 {
            if (probe[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
                self.child.store(-1, Ordering::Release);
                return false;
            }
            if (probe[0].revents & libc::POLLIN) != 0 {
                let mut peek: u8 = 0;
                let count = unsafe {
                    libc::recv(
                        inner.control_fd,
                        (&mut peek as *mut u8).cast::<c_void>(),
                        1,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                if count == 0 {
                    self.child.store(-1, Ordering::Release);
                    return false;
                }
            }
        }
        true
    }

    pub(crate) fn process_id(&self) -> libc::pid_t {
        self.child.load(Ordering::Acquire)
    }

    fn send_control(&self, op: u8, payload: &[u8]) -> bool {
        let mut packet = encode_packet_header(K_CONTROL_MAGIC, op, payload);
        let mut sent = false;
        if let Ok(inner) = self.inner.lock() {
            if self.child.load(Ordering::Acquire) > 0 && inner.control_fd >= 0 {
                if inner.tcp {
                    let mut framed = frame_tcp_packet(&packet);
                    let mut offset = 0usize;
                    sent = true;
                    while offset < framed.len() {
                        let count = unsafe {
                            libc::send(
                                inner.control_fd,
                                framed.as_ptr().add(offset).cast::<c_void>(),
                                framed.len() - offset,
                                libc::MSG_NOSIGNAL,
                            )
                        };
                        if count < 0 {
                            let err = last_errno();
                            if err == libc::EINTR {
                                continue;
                            }
                            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                                let mut pfd = [libc::pollfd {
                                    fd: inner.control_fd,
                                    events: libc::POLLOUT,
                                    revents: 0,
                                }];
                                if poll_retry_eintr(&mut pfd, 1000) <= 0 {
                                    sent = false;
                                    break;
                                }
                                continue;
                            }
                            sent = false;
                            break;
                        }
                        if count == 0 {
                            sent = false;
                            break;
                        }
                        offset += count as usize;
                    }
                    framed.zeroize();
                } else {
                    loop {
                        let count = unsafe {
                            libc::send(
                                inner.control_fd,
                                packet.as_ptr().cast::<c_void>(),
                                packet.len(),
                                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL | libc::MSG_EOR,
                            )
                        };
                        if count < 0 && last_errno() == libc::EINTR {
                            continue;
                        }
                        sent = count == packet.len() as isize;
                        break;
                    }
                }
            }
        }
        packet.zeroize();
        sent
    }

    pub(crate) fn load_url(&self, url: &str) -> bool {
        let Ok(normalized) = normalize_webview_url(url) else {
            return false;
        };
        self.send_control(K_WEBVIEW_OP_LOAD_URL, normalized.as_bytes())
    }

    pub(crate) fn set_title(&self, title: &str) -> bool {
        if title.len() > K_MAXIMUM_WEBVIEW_TITLE_BYTES || contains_control_bytes(title.as_bytes()) {
            return false;
        }
        self.send_control(K_WEBVIEW_OP_SET_TITLE, title.as_bytes())
    }

    pub(crate) fn set_visible(&self, visible: bool) -> bool {
        let b = [u8::from(visible)];
        self.send_control(K_WEBVIEW_OP_SET_VISIBLE, &b)
    }

    pub(crate) fn evaluate_javascript(&self, script: &str) -> bool {
        if script.len() > K_MAXIMUM_WEBVIEW_JAVASCRIPT_BYTES || script.as_bytes().contains(&0) {
            return false;
        }
        self.send_control(K_WEBVIEW_OP_EVALUATE_JAVASCRIPT, script.as_bytes())
    }

    pub(crate) fn set_back_navigation_disabled(&self, disabled: bool) -> bool {
        let b = [u8::from(disabled)];
        self.send_control(K_WEBVIEW_OP_SET_BACK_NAVIGATION_DISABLED, &b)
    }

    pub(crate) fn set_show_domain_as_title(&self, enabled: bool) -> bool {
        let b = [u8::from(enabled)];
        self.send_control(K_WEBVIEW_OP_SET_SHOW_DOMAIN_AS_TITLE, &b)
    }

    pub(crate) fn set_roblox_cookie(&self, value: &[u8]) -> bool {
        if value.len() > K_MAXIMUM_WEBVIEW_COOKIE_BYTES {
            return false;
        }
        if value.is_empty() {
            self.send_control(K_WEBVIEW_OP_RETAIN_PERSISTENT_ROBLOX_COOKIE, &[])
        } else {
            self.send_control(K_WEBVIEW_OP_SET_ROBLOX_COOKIE, value)
        }
    }

    pub(crate) fn clear_roblox_cookie(&self) -> bool {
        self.send_control(K_WEBVIEW_OP_CLEAR_ROBLOX_COOKIE, &[])
    }

    pub(crate) fn wait_until_ready(&self, timeout_ms: i64) -> bool {
        if timeout_ms < 0 {
            return false;
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        while !inner.ready && inner.control_fd >= 0 && self.child.load(Ordering::Acquire) > 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
            if remaining_ms <= 0 {
                break;
            }
            let mut closed = false;
            while !inner.ready {
                match Self::receive_packet(&mut inner) {
                    PacketRead::Eof | PacketRead::Error => {
                        closed = true;
                        break;
                    }
                    PacketRead::Again => break,
                    PacketRead::Packet(packet) => {
                        if let Ok((ev_type, payload)) = decode_event_packet(&packet) {
                            if ev_type == K_WEBVIEW_EVENT_READY {
                                inner.ready = true;
                            } else {
                                inner.pending_events.push_back((ev_type, payload));
                            }
                        }
                    }
                }
            }
            if closed || inner.ready {
                break;
            }
            let mut pfd = [libc::pollfd {
                fd: inner.control_fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            let poll_rc = poll_retry_eintr(&mut pfd, remaining_ms);
            if poll_rc < 0 {
                break;
            }
            if poll_rc > 0 && (pfd[0].revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                break;
            }
        }
        inner.ready
    }

    pub(crate) unsafe fn drain_events(
        &self,
        cb: MocktailRustWebViewEventCallback,
        ctx: *mut c_void,
    ) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner.control_fd < 0 {
            return false;
        }
        while let Some((ev_type, mut payload)) = inner.pending_events.pop_front() {
            if let Some(f) = cb {
                f(ctx, ev_type, payload.as_ptr().cast::<c_char>(), payload.len());
            }
            payload.zeroize();
        }
        loop {
            match Self::receive_packet(&mut inner) {
                PacketRead::Again | PacketRead::Eof => return true,
                PacketRead::Error => return false,
                PacketRead::Packet(packet) => {
                    if let Ok((ev_type, mut payload)) = decode_event_packet(&packet) {
                        if ev_type == K_WEBVIEW_EVENT_READY {
                            inner.ready = true;
                        } else if let Some(f) = cb {
                            f(ctx, ev_type, payload.as_ptr().cast::<c_char>(), payload.len());
                        }
                        payload.zeroize();
                    }
                }
            }
        }
    }

    pub(crate) fn request_close(&self) -> bool {
        let child = self.process_id();
        if child <= 0 {
            return true;
        }
        if self.send_control(K_WEBVIEW_OP_CLOSE, &[]) {
            return true;
        }
        let is_tcp = self.inner.lock().map(|g| g.tcp).unwrap_or(false);
        if is_tcp {
            return false;
        }
        let current_child = self.process_id();
        if current_child <= 0 {
            return true;
        }
        unsafe { libc::kill(current_child, libc::SIGTERM) == 0 || last_errno() == libc::ESRCH }
    }
}

struct ExitObserverHolder {
    context: *mut c_void,
    on_exit: MocktailRustWebViewExitFn,
    on_drop: MocktailRustWebViewExitFn,
}

unsafe impl Send for ExitObserverHolder {}

impl ExitObserverHolder {
    fn fire_and_drop(mut self) {
        if !self.context.is_null() {
            if let Some(f) = self.on_exit {
                unsafe { f(self.context) };
            }
        }
        if !self.context.is_null() {
            if let Some(drop_fn) = self.on_drop {
                let ctx = self.context;
                self.context = std::ptr::null_mut();
                unsafe { drop_fn(ctx) };
            }
        }
    }
}

impl Drop for ExitObserverHolder {
    fn drop(&mut self) {
        if !self.context.is_null() {
            if let Some(drop_fn) = self.on_drop {
                let ctx = self.context;
                self.context = std::ptr::null_mut();
                unsafe { drop_fn(ctx) };
            }
        }
    }
}

fn terminate_and_reap_child(child: libc::pid_t) {
    unsafe {
        if libc::kill(child, libc::SIGKILL) < 0 && last_errno() != libc::ESRCH {
            return;
        }
        let mut status: libc::c_int = 0;
        while libc::waitpid(child, &mut status, 0) < 0 && last_errno() == libc::EINTR {}
    }
}

fn spawn_helper_process(
    helper: &Path,
    request_fd: RawFd,
    parent_control_fd: RawFd,
    child_control_fd: RawFd,
) -> Result<libc::pid_t, i32> {
    let Some(c_helper) = path_to_cstr(helper) else {
        return Err(libc::EINVAL);
    };
    let mut program_buf = c_helper.into_bytes_with_nul();

    let mut actions: libc::posix_spawn_file_actions_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut spawn_status = unsafe { libc::posix_spawn_file_actions_init(&mut actions) };
    if spawn_status != 0 {
        return Err(spawn_status);
    }

    if spawn_status == 0 {
        spawn_status =
            unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions, request_fd, libc::STDIN_FILENO) };
    }
    if spawn_status == 0 && request_fd != libc::STDIN_FILENO {
        spawn_status = unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, request_fd) };
    }
    if spawn_status == 0 {
        spawn_status =
            unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, parent_control_fd) };
    }
    if spawn_status == 0 {
        spawn_status = unsafe {
            libc::posix_spawn_file_actions_adddup2(
                &mut actions,
                child_control_fd,
                K_WEBVIEW_HELPER_CONTROL_DESCRIPTOR,
            )
        };
    }
    if spawn_status == 0 && child_control_fd != K_WEBVIEW_HELPER_CONTROL_DESCRIPTOR {
        spawn_status =
            unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, child_control_fd) };
    }

    let mut child: libc::pid_t = -1;
    if spawn_status == 0 {
        let mut argv = [
            program_buf.as_mut_ptr().cast::<c_char>(),
            std::ptr::null_mut(),
        ];
        let env = unsafe { build_filtered_helper_env_ptrs() };
        spawn_status = unsafe {
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
    if spawn_status == 0 && child > 0 {
        Ok(child)
    } else {
        Err(if spawn_status != 0 {
            spawn_status
        } else {
            libc::EIO
        })
    }
}

fn launch_webview_helper_impl(
    helper: &Path,
    url: &str,
    exit_observer: ExitObserverHolder,
) -> Result<(Arc<MocktailRustWebViewProcess>, libc::pid_t), String> {
    let normalized_url = normalize_webview_url(url).map_err(|e| e.to_string())?;

    if host_is_freebsd() {
        let tcp_fd = connect_to_freebsd_host()
            .ok_or_else(|| "cannot connect to the FreeBSD webview host".to_string())?;
        let proc_arc = Arc::new(MocktailRustWebViewProcess {
            child: AtomicI32::new(1),
            inner: Mutex::new(ControlInner {
                control_fd: tcp_fd.release(),
                pending_events: VecDeque::new(),
                receive_buffer: Vec::new(),
                tcp: true,
                ready: false,
            }),
        });
        if !proc_arc.load_url(&normalized_url) {
            return Err("cannot send the initial URL to the FreeBSD webview host".to_string());
        }
        drop(exit_observer);
        return Ok((proc_arc, 1));
    }

    if !validate_executable_absolute_regular_file(helper) {
        return Err("webview helper is not an executable absolute regular file".to_string());
    }

    let mut control_fds = [-1 as RawFd; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            control_fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err("cannot create private webview control channel".to_string());
    }
    let parent_control = OwnedFd::from_raw(control_fds[0])
        .ok_or_else(|| "cannot create private webview control channel".to_string())?;
    let child_control = OwnedFd::from_raw(control_fds[1])
        .ok_or_else(|| "cannot create private webview control channel".to_string())?;

    if child_control.as_raw() == K_WEBVIEW_HELPER_CONTROL_DESCRIPTOR
        && !set_cloexec(child_control.as_raw(), false)
    {
        return Err("cannot prepare private webview control channel".to_string());
    }

    let request = encode_request(&normalized_url);
    let request_name = CStr::from_bytes_with_nul(b"mocktail-webview-request\0").unwrap();
    let raw_memfd = unsafe { libc::memfd_create(request_name.as_ptr(), libc::MFD_CLOEXEC) };
    let request_fd = OwnedFd::from_raw(raw_memfd)
        .ok_or_else(|| "cannot create bounded webview request".to_string())?;
    if !write_all_fd(request_fd.as_raw(), &request)
        || unsafe { libc::lseek(request_fd.as_raw(), 0, libc::SEEK_SET) } < 0
    {
        return Err("cannot prepare bounded webview request".to_string());
    }

    let child_pid = spawn_helper_process(
        helper,
        request_fd.as_raw(),
        parent_control.as_raw(),
        child_control.as_raw(),
    )
    .map_err(|err| errno_message("cannot start webview helper", err))?;

    drop(child_control);
    drop(request_fd);

    let proc_arc = Arc::new(MocktailRustWebViewProcess {
        child: AtomicI32::new(child_pid),
        inner: Mutex::new(ControlInner {
            control_fd: parent_control.release(),
            pending_events: VecDeque::new(),
            receive_buffer: Vec::new(),
            tcp: false,
            ready: false,
        }),
    });

    let reaper_state = Arc::clone(&proc_arc);
    let spawn_reaper = std::thread::Builder::new()
        .name("mocktail-wv-reap".to_string())
        .spawn(move || {
            let mut status: libc::c_int = 0;
            unsafe {
                while libc::waitpid(child_pid, &mut status, 0) < 0 && last_errno() == libc::EINTR {
                }
            }
            reaper_state.child.store(-1, Ordering::Release);
            if let Ok(mut inner) = reaper_state.inner.lock() {
                inner.close_descriptor();
            }
            exit_observer.fire_and_drop();
        });

    if let Err(err) = spawn_reaper {
        let raw_err = err.raw_os_error().unwrap_or(libc::ENOMEM);
        terminate_and_reap_child(child_pid);
        return Err(errno_message("cannot own webview helper process", raw_err));
    }

    Ok((proc_arc, child_pid))
}

unsafe fn bytes_from_ffi<'a>(ptr: *const c_char, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        if len == 0 {
            Some(&[])
        } else {
            None
        }
    } else {
        Some(std::slice::from_raw_parts(ptr.cast::<u8>(), len))
    }
}

unsafe fn str_from_ffi<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    let bytes = bytes_from_ffi(ptr, len)?;
    std::str::from_utf8(bytes).ok()
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_validate_url(
    url_ptr: *const c_char,
    url_len: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(url_str) = str_from_ffi(url_ptr, url_len) else {
        copy_error(
            out_err,
            err_cap,
            "webview URL is empty, oversized, or contains control bytes",
        );
        return 0;
    };
    match validate_webview_url(url_str) {
        Ok(()) => 1,
        Err(msg) => {
            copy_error(out_err, err_cap, msg);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_normalize_url(
    url_ptr: *const c_char,
    url_len: usize,
    on_normalized: MocktailRustWebViewBytesCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(url_str) = str_from_ffi(url_ptr, url_len) else {
        copy_error(
            out_err,
            err_cap,
            "webview URL is empty, oversized, or contains control bytes",
        );
        return 0;
    };
    match normalize_webview_url(url_str) {
        Ok(normalized) => {
            if let Some(cb) = on_normalized {
                cb(ctx, normalized.as_ptr().cast::<c_char>(), normalized.len());
            }
            1
        }
        Err(msg) => {
            copy_error(out_err, err_cap, msg);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_decode_request(
    req_ptr: *const c_char,
    req_len: usize,
    on_url: MocktailRustWebViewBytesCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(req_bytes) = bytes_from_ffi(req_ptr, req_len) else {
        copy_error(out_err, err_cap, "webview request has an invalid protocol header");
        return 0;
    };
    match decode_webview_request(req_bytes) {
        Ok(url_str) => {
            if let Some(cb) = on_url {
                cb(ctx, url_str.as_ptr().cast::<c_char>(), url_str.len());
            }
            1
        }
        Err(msg) => {
            copy_error(out_err, err_cap, msg);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_decode_control_packet(
    packet_ptr: *const c_char,
    packet_len: usize,
    on_command: MocktailRustWebViewControlCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(packet) = bytes_from_ffi(packet_ptr, packet_len) else {
        copy_error(out_err, err_cap, "webview control packet has an invalid header");
        return 0;
    };
    match decode_control_packet(packet) {
        Ok((op, mut payload, visible)) => {
            if let Some(cb) = on_command {
                cb(
                    ctx,
                    op,
                    payload.as_ptr().cast::<c_char>(),
                    payload.len(),
                    i32::from(visible),
                );
            }
            payload.zeroize();
            1
        }
        Err(msg) => {
            copy_error(out_err, err_cap, msg);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_encode_event_packet(
    event_type: u8,
    payload_ptr: *const c_char,
    payload_len: usize,
    on_packet: MocktailRustWebViewBytesCallback,
    ctx: *mut c_void,
) -> i32 {
    let Some(payload) = bytes_from_ffi(payload_ptr, payload_len) else {
        return 0;
    };
    let Some(mut packet) = encode_event_packet(event_type, payload) else {
        return 0;
    };
    if let Some(cb) = on_packet {
        cb(ctx, packet.as_ptr().cast::<c_char>(), packet.len());
    }
    packet.zeroize();
    1
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_decode_event_packet(
    packet_ptr: *const c_char,
    packet_len: usize,
    on_event: MocktailRustWebViewEventCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(packet) = bytes_from_ffi(packet_ptr, packet_len) else {
        copy_error(out_err, err_cap, "webview event packet has an invalid header");
        return 0;
    };
    match decode_event_packet(packet) {
        Ok((ev_type, mut payload)) => {
            if let Some(cb) = on_event {
                cb(ctx, ev_type, payload.as_ptr().cast::<c_char>(), payload.len());
            }
            payload.zeroize();
            1
        }
        Err(msg) => {
            copy_error(out_err, err_cap, msg);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_launch(
    helper_ptr: *const c_char,
    helper_len: usize,
    url_ptr: *const c_char,
    url_len: usize,
    observer_ctx: *mut c_void,
    on_exit: MocktailRustWebViewExitFn,
    on_drop: MocktailRustWebViewExitFn,
    out_process: *mut *mut MocktailRustWebViewProcess,
    out_pid: *mut i32,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let holder = ExitObserverHolder {
        context: observer_ctx,
        on_exit,
        on_drop,
    };
    if out_process.is_null() || out_pid.is_null() {
        copy_error(out_err, err_cap, "invalid webview output handle");
        return -1;
    }
    *out_process = std::ptr::null_mut();
    *out_pid = -1;

    let Some(url_str) = str_from_ffi(url_ptr, url_len) else {
        copy_error(
            out_err,
            err_cap,
            "webview URL is empty, oversized, or contains control bytes",
        );
        return -1;
    };
    let Some(helper_bytes) = bytes_from_ffi(helper_ptr, helper_len) else {
        copy_error(
            out_err,
            err_cap,
            "webview helper is not an executable absolute regular file",
        );
        return -1;
    };
    use std::os::unix::ffi::OsStrExt;
    let helper_path = Path::new(std::ffi::OsStr::from_bytes(helper_bytes));

    match launch_webview_helper_impl(helper_path, url_str, holder) {
        Ok((proc_arc, child_pid)) => {
            *out_process = Arc::into_raw(proc_arc).cast_mut();
            *out_pid = child_pid;
            0
        }
        Err(err) => {
            copy_error(out_err, err_cap, &err);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_release(
    process: *mut MocktailRustWebViewProcess,
) {
    if !process.is_null() {
        drop(Arc::from_raw(process));
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_running(
    process: *const MocktailRustWebViewProcess,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).running())
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_pid(
    process: *const MocktailRustWebViewProcess,
) -> i32 {
    if process.is_null() {
        return -1;
    }
    (*process).process_id()
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_load_url(
    process: *const MocktailRustWebViewProcess,
    url_ptr: *const c_char,
    url_len: usize,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let Some(url_str) = str_from_ffi(url_ptr, url_len) else {
        return 0;
    };
    i32::from((*process).load_url(url_str))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_set_title(
    process: *const MocktailRustWebViewProcess,
    title_ptr: *const c_char,
    title_len: usize,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let Some(title) = str_from_ffi(title_ptr, title_len) else {
        return 0;
    };
    i32::from((*process).set_title(title))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_set_visible(
    process: *const MocktailRustWebViewProcess,
    visible: i32,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).set_visible(visible != 0))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_evaluate_javascript(
    process: *const MocktailRustWebViewProcess,
    script_ptr: *const c_char,
    script_len: usize,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let Some(script) = str_from_ffi(script_ptr, script_len) else {
        return 0;
    };
    i32::from((*process).evaluate_javascript(script))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_set_back_navigation_disabled(
    process: *const MocktailRustWebViewProcess,
    disabled: i32,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).set_back_navigation_disabled(disabled != 0))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_set_show_domain_as_title(
    process: *const MocktailRustWebViewProcess,
    enabled: i32,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).set_show_domain_as_title(enabled != 0))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_set_roblox_cookie(
    process: *const MocktailRustWebViewProcess,
    cookie_ptr: *const c_char,
    cookie_len: usize,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let Some(bytes) = bytes_from_ffi(cookie_ptr, cookie_len) else {
        return 0;
    };
    i32::from((*process).set_roblox_cookie(bytes))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_clear_roblox_cookie(
    process: *const MocktailRustWebViewProcess,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).clear_roblox_cookie())
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_wait_until_ready(
    process: *const MocktailRustWebViewProcess,
    timeout_ms: i64,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).wait_until_ready(timeout_ms))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_drain_events(
    process: *const MocktailRustWebViewProcess,
    on_event: MocktailRustWebViewEventCallback,
    ctx: *mut c_void,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).drain_events(on_event, ctx))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_process_request_close(
    process: *const MocktailRustWebViewProcess,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    i32::from((*process).request_close())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_ipc::current_pid;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
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

    #[test]
    fn url_validation_and_normalization_enforce_roblox_https_and_raw_paths() {
        assert!(validate_webview_url("https://www.roblox.com/login?returnUrl=%2F").is_ok());
        assert!(validate_webview_url("https://authorize.roblox.com/").is_ok());
        assert!(validate_webview_url("https://www.roblox.com:443/login").is_ok());
        for rejected in [
            "http://www.roblox.com/login",
            "https://evilroblox.com/login",
            "https://roblox.com.example.org/login",
            "https://user@roblox.com/login",
            "https://roblox.com:444/login",
            "https://roblox.com/login\nhttps://example.org",
            "https://www.roblox.com/games/../login",
            "https://www.roblox.com/games/%2e%2e/login",
            "https://www.roblox.com/games/%2Fetc",
            "https://www.roblox.com/games/%5cetc",
        ] {
            assert!(validate_webview_url(rejected).is_err(), "should reject {rejected}");
        }

        assert_eq!(
            &*normalize_webview_url("www:games/servers-section/987654321").unwrap(),
            "https://www.roblox.com/games/servers-section/987654321"
        );
        for rejected in [
            "www:",
            "www:/login",
            "www:games/servers-section/../login",
            "www:games/servers-section/%2e%2e",
        ] {
            assert!(normalize_webview_url(rejected).is_err(), "should reject {rejected}");
        }
    }

    #[test]
    fn request_control_and_event_codecs_round_trip_and_reject_invalid_frames() {
        let req = encode_request("https://www.roblox.com/login");
        assert_eq!(&*decode_webview_request(&req).unwrap(), "https://www.roblox.com/login");
        assert!(decode_webview_request(b"MOCKTAIL-WEBVIEW 1\n999\nhttps://www.roblox.com/login").is_err());

        let ctrl = encode_packet_header(K_CONTROL_MAGIC, K_WEBVIEW_OP_SET_ROBLOX_COOKIE, b"_|signed");
        let (op, payload, _) = decode_control_packet(&ctrl).unwrap();
        assert_eq!(op, K_WEBVIEW_OP_SET_ROBLOX_COOKIE);
        assert_eq!(&*payload, b"_|signed");

        let bad_cookie = encode_packet_header(K_CONTROL_MAGIC, K_WEBVIEW_OP_SET_ROBLOX_COOKIE, b"bad cookie");
        assert!(decode_control_packet(&bad_cookie).is_err());

        let ev = encode_event_packet(K_WEBVIEW_EVENT_READY, &[]).unwrap();
        let (ev_type, ev_payload) = decode_event_packet(&ev).unwrap();
        assert_eq!(ev_type, K_WEBVIEW_EVENT_READY);
        assert!(ev_payload.is_empty());
        assert!(encode_event_packet(K_WEBVIEW_EVENT_EXECUTE_ROBLOX, &[]).is_none());
    }

    #[test]
    fn tcp_frame_extraction_clears_consumed_prefix_safely() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame_tcp_packet(b"hello"));
        buf.extend_from_slice(&frame_tcp_packet(b"world"));
        assert_eq!(&*extract_tcp_frame(&mut buf).unwrap(), b"hello");
        assert_eq!(&*extract_tcp_frame(&mut buf).unwrap(), b"world");
        assert!(buf.is_empty());
    }

    #[test]
    fn launches_reaps_and_fires_exit_observer() {
        let dir = TempDir::new("mocktail_wv_launch_rs");
        let helper = dir.path.join("fake-helper");
        let out_req = dir.path.join("req");
        let body = format!("#!/bin/sh\ncat > '{}'\n", out_req.display());
        std::fs::write(&helper, body).unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();

        let exits = Box::new(AtomicUsize::new(0));
        let exits_ptr = Box::into_raw(exits);

        unsafe extern "C" fn on_exit(ctx: *mut c_void) {
            let cnt = &*(ctx as *const AtomicUsize);
            cnt.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn on_drop(_ctx: *mut c_void) {}

        let holder = ExitObserverHolder {
            context: exits_ptr.cast::<c_void>(),
            on_exit: Some(on_exit),
            on_drop: Some(on_drop),
        };
        let (proc_arc, pid) = launch_webview_helper_impl(&helper, "www:login", holder).unwrap();
        assert!(pid > 0);

        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { (*exits_ptr).load(Ordering::SeqCst) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let observed = unsafe { Box::from_raw(exits_ptr) }.load(Ordering::SeqCst);
        assert_eq!(observed, 1);
        assert!(!proc_arc.running());
        assert_eq!(
            std::fs::read(&out_req).unwrap(),
            b"MOCKTAIL-WEBVIEW 1\n28\nhttps://www.roblox.com/login"
        );
    }
}
