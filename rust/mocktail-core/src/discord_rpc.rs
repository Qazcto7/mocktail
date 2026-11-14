//! Discord Desktop local IPC (`discord-ipc-0..9`) Rich Presence client.
//!
//! Moves socket discovery, non-blocking/poll IPC framing, handshake/ping
//! handling, sliding-window rate limiting, Rich Presence payload construction,
//! and worker lifecycle out of C++ while preserving C++'s shared Roblox place
//! metadata cache and public `DiscordRpcSession` API.

use std::collections::{HashSet, VecDeque};
use std::ffi::{c_char, c_void};
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::runtime_policies::parse_json_object_str;
use crate::unix_ipc::{
    build_sockaddr_un, current_pid, current_uid, last_errno, poll_retry_eintr, set_socket_timeouts,
    EventFd, OwnedFd,
};
use crate::{copy_error, is_safe_url_bytes, truncate_utf8_str};

const K_MAXIMUM_DISCORD_FRAME_BYTES: usize = 1024 * 1024;
const K_DISCORD_WORKER_STACK_BYTES: usize = 16 * 1024 * 1024;
const K_RECONNECT_DELAY: Duration = Duration::from_millis(5000);
const K_DISCORD_ACTIVITY_RATE_WINDOW: Duration = Duration::from_secs(20);
const K_DISCORD_ACTIVITY_RATE_LIMIT: usize = 5;
const K_JOIN_PAGE_BASE: &str = "https://komaruworld.github.io/mocktail/join.html#placeId=";
const K_CONNECT_IO_TIMEOUT_SECS: i64 = 2;
const K_WRITE_POLL_TIMEOUT_MS: i32 = 1500;
const K_READ_POLL_TIMEOUT_MS: i32 = 3000;
const K_IDLE_POLL_TIMEOUT_MS: i32 = 500;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscordOpcode {
    Handshake = 0,
    Frame = 1,
    Close = 2,
    Ping = 3,
    Pong = 4,
}

impl DiscordOpcode {
    fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Handshake),
            1 => Some(Self::Frame),
            2 => Some(Self::Close),
            3 => Some(Self::Ping),
            4 => Some(Self::Pong),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresencePhase {
    Browsing = 0,
    Joining = 1,
    Playing = 2,
}

impl PresencePhase {
    pub(crate) fn from_i32(raw: i32) -> Self {
        match raw {
            1 => Self::Joining,
            2 => Self::Playing,
            _ => Self::Browsing,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Browsing => "browsing",
            Self::Joining => "joining",
            Self::Playing => "playing",
        }
    }
}

#[repr(C)]
pub struct MocktailRustDiscordConfig {
    pub enabled: i32,
    pub show_place_name: i32,
    pub show_elapsed_time: i32,
    pub join_enabled: i32,
    pub public_servers_only: i32,
    pub join_button_label_ptr: *const c_char,
    pub join_button_label_len: usize,
    pub application_id_ptr: *const c_char,
    pub application_id_len: usize,
    pub text_browsing_ptr: *const c_char,
    pub text_browsing_len: usize,
    pub text_joining_ptr: *const c_char,
    pub text_joining_len: usize,
    pub text_playing_ptr: *const c_char,
    pub text_playing_len: usize,
    pub text_state_ptr: *const c_char,
    pub text_state_len: usize,
    pub text_unknown_place_ptr: *const c_char,
    pub text_unknown_place_len: usize,
}

#[repr(C)]
pub struct MocktailRustDiscordLaunchSlice {
    pub place_id: i64,
    pub game_instance_id_ptr: *const c_char,
    pub game_instance_id_len: usize,
    pub has_private_access: bool,
}

pub type MocktailDiscordMetadataInspectResultFn = unsafe extern "C" fn(
    rust_out: *mut c_void,
    name_ptr: *const c_char,
    name_len: usize,
    icon_url_ptr: *const c_char,
    icon_url_len: usize,
    should_fetch_after_publish: bool,
    waiting_for_name: bool,
);

pub type MocktailDiscordMetadataInspectFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        phase: i32,
        place_id: i64,
        on_result: MocktailDiscordMetadataInspectResultFn,
        rust_out: *mut c_void,
    ),
>;

pub type MocktailDiscordMetadataRefreshFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, place_id: i64, out_retry_delay_secs: *mut i64) -> bool>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustDiscordMetadataCallbacks {
    pub ctx: *mut c_void,
    pub inspect: MocktailDiscordMetadataInspectFn,
    pub refresh: MocktailDiscordMetadataRefreshFn,
}

unsafe impl Send for MocktailRustDiscordMetadataCallbacks {}

pub type MocktailDiscordActivityFieldsCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        details_ptr: *const c_char,
        details_len: usize,
        state_ptr: *const c_char,
        state_len: usize,
        has_start_timestamp: bool,
        start_timestamp: i64,
        large_image_ptr: *const c_char,
        large_image_len: usize,
        large_text_ptr: *const c_char,
        large_text_len: usize,
        button_label_ptr: *const c_char,
        button_label_len: usize,
        button_url_ptr: *const c_char,
        button_url_len: usize,
    ),
>;

#[derive(Debug, Clone)]
struct DiscordConfig {
    show_place_name: bool,
    show_elapsed_time: bool,
    join_enabled: bool,
    public_servers_only: bool,
    join_button_label: String,
    application_id: String,
    text_browsing: String,
    text_joining: String,
    text_playing: String,
    text_state: String,
    text_unknown_place: String,
}

unsafe fn slice_to_lossy_opt(ptr: *const c_char, len: usize) -> Option<String> {
    if len == 0 {
        return Some(String::new());
    }
    if ptr.is_null() {
        return None;
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

impl DiscordConfig {
    unsafe fn from_ffi(raw: &MocktailRustDiscordConfig) -> Option<Self> {
        Some(Self {
            show_place_name: raw.show_place_name != 0,
            show_elapsed_time: raw.show_elapsed_time != 0,
            join_enabled: raw.join_enabled != 0,
            public_servers_only: raw.public_servers_only != 0,
            join_button_label: slice_to_lossy_opt(
                raw.join_button_label_ptr,
                raw.join_button_label_len,
            )?,
            application_id: slice_to_lossy_opt(raw.application_id_ptr, raw.application_id_len)?,
            text_browsing: slice_to_lossy_opt(raw.text_browsing_ptr, raw.text_browsing_len)?,
            text_joining: slice_to_lossy_opt(raw.text_joining_ptr, raw.text_joining_len)?,
            text_playing: slice_to_lossy_opt(raw.text_playing_ptr, raw.text_playing_len)?,
            text_state: slice_to_lossy_opt(raw.text_state_ptr, raw.text_state_len)?,
            text_unknown_place: slice_to_lossy_opt(
                raw.text_unknown_place_ptr,
                raw.text_unknown_place_len,
            )?,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct SanitizedLaunchTarget {
    present: bool,
    place_id: i64,
    game_instance_id: String,
    has_private_access: bool,
}

impl SanitizedLaunchTarget {
    unsafe fn from_ffi(has_request: bool, raw: *const MocktailRustDiscordLaunchSlice) -> Option<Self> {
        if !has_request || raw.is_null() {
            return Some(Self::default());
        }
        let s = &*raw;
        let game_instance_id =
            slice_to_lossy_opt(s.game_instance_id_ptr, s.game_instance_id_len).unwrap_or_default();
        Some(Self {
            present: true,
            place_id: s.place_id,
            game_instance_id,
            has_private_access: s.has_private_access,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BuiltActivity {
    pub(crate) details: String,
    pub(crate) state: String,
    pub(crate) start_timestamp: Option<i64>,
    pub(crate) large_image: String,
    pub(crate) large_text: String,
    pub(crate) button_label: String,
    pub(crate) button_url: String,
}

pub(crate) fn has_join_target_bytes(place_id: i64, instance_id: &[u8]) -> bool {
    if place_id <= 0 {
        return false;
    }
    if instance_id.is_empty() {
        return true;
    }
    if instance_id.len() > 128 {
        return false;
    }
    !instance_id.iter().any(|&b| b < 0x20 || b == 0x7f)
}

fn has_join_target(place_id: i64, instance_id: &str) -> bool {
    has_join_target_bytes(place_id, instance_id.as_bytes())
}

fn is_public_join(target: &SanitizedLaunchTarget) -> bool {
    target.present
        && has_join_target(target.place_id, &target.game_instance_id)
        && !target.has_private_access
}

pub(crate) fn percent_encode_bytes(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

pub(crate) fn build_join_url_bytes(place_id: i64, instance_id: &[u8]) -> String {
    if !has_join_target_bytes(place_id, instance_id) {
        return String::new();
    }
    let mut url = format!("{}{}", K_JOIN_PAGE_BASE, place_id);
    if !instance_id.is_empty() {
        url.push_str("&gameInstanceId=");
        url.push_str(&percent_encode_bytes(instance_id));
    }
    if url.len() > 512 {
        return String::new();
    }
    url
}

fn build_join_url(place_id: i64, instance_id: &str) -> String {
    build_join_url_bytes(place_id, instance_id.as_bytes())
}

pub(crate) fn render_place_template(template: &str, place_name: &str) -> String {
    let rendered = template.replace("{place_name}", place_name);
    truncate_utf8_str(&rendered, 128).to_string()
}

fn build_discord_activity(
    cfg: &DiscordConfig,
    phase: PresencePhase,
    target: Option<&SanitizedLaunchTarget>,
    place_name: &str,
    session_started_at: i64,
    place_icon_url: &str,
) -> BuiltActivity {
    let mut activity = BuiltActivity {
        state: truncate_utf8_str(&cfg.text_state, 128).to_string(),
        ..Default::default()
    };

    match phase {
        PresencePhase::Browsing => {
            activity.details = truncate_utf8_str(&cfg.text_browsing, 128).to_string();
        }
        PresencePhase::Joining | PresencePhase::Playing => {
            let effective_name = if place_name.is_empty() {
                if phase == PresencePhase::Joining {
                    activity.details = truncate_utf8_str(&cfg.text_joining, 128).to_string();
                    return activity;
                }
                cfg.text_unknown_place.as_str()
            } else {
                place_name
            };

            if cfg.show_place_name {
                activity.details = render_place_template(&cfg.text_playing, effective_name);
            } else {
                activity.details = activity.state.clone();
                activity.state.clear();
            }

            if phase == PresencePhase::Playing && cfg.show_elapsed_time && session_started_at > 0 {
                activity.start_timestamp = Some(session_started_at);
            }

            if is_safe_url_bytes(place_icon_url.as_bytes(), 512) {
                activity.large_image = place_icon_url.to_string();
                activity.large_text = truncate_utf8_str(effective_name, 128).to_string();
            }

            if phase == PresencePhase::Playing && cfg.join_enabled {
                if let Some(req) = target.filter(|r| r.present) {
                    if !cfg.public_servers_only || is_public_join(req) {
                        let url = build_join_url(req.place_id, &req.game_instance_id);
                        if !url.is_empty() {
                            activity.button_url = url;
                            activity.button_label = cfg.join_button_label.clone();
                        }
                    }
                }
            }
        }
    }

    activity
}

#[derive(Default)]
struct MetadataInspectResult {
    name: String,
    icon_url: String,
    should_fetch_after_publish: bool,
    waiting_for_name: bool,
}

unsafe extern "C" fn capture_metadata_inspect_result(
    rust_out: *mut c_void,
    name_ptr: *const c_char,
    name_len: usize,
    icon_url_ptr: *const c_char,
    icon_url_len: usize,
    should_fetch_after_publish: bool,
    waiting_for_name: bool,
) {
    if rust_out.is_null() {
        return;
    }
    let out = &mut *(rust_out as *mut MetadataInspectResult);
    if !name_ptr.is_null() && name_len > 0 {
        let bytes = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
        out.name = String::from_utf8_lossy(bytes).into_owned();
    }
    if !icon_url_ptr.is_null() && icon_url_len > 0 {
        let bytes = std::slice::from_raw_parts(icon_url_ptr as *const u8, icon_url_len);
        out.icon_url = String::from_utf8_lossy(bytes).into_owned();
    }
    out.should_fetch_after_publish = should_fetch_after_publish;
    out.waiting_for_name = waiting_for_name;
}

#[derive(Clone)]
struct DesiredState {
    phase: PresencePhase,
    target: SanitizedLaunchTarget,
    started_at: i64,
    revision: u64,
    stopping: bool,
}

impl Default for DesiredState {
    fn default() -> Self {
        Self {
            phase: PresencePhase::Browsing,
            target: SanitizedLaunchTarget::default(),
            started_at: 0,
            revision: 1,
            stopping: false,
        }
    }
}

struct SharedDiscordState {
    mutex: Mutex<DesiredState>,
    condvar: Condvar,
    wake_fd: EventFd,
    stop_fd: EventFd,
}

impl SharedDiscordState {
    fn new() -> Result<Self, i32> {
        Ok(Self {
            mutex: Mutex::new(DesiredState::default()),
            condvar: Condvar::new(),
            wake_fd: EventFd::new()?,
            stop_fd: EventFd::new()?,
        })
    }

    fn is_stopping(&self) -> bool {
        self.mutex
            .lock()
            .map(|guard| guard.stopping)
            .unwrap_or(true)
    }

    fn snapshot(&self) -> DesiredState {
        match self.mutex.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn update(&self, phase: PresencePhase, target: SanitizedLaunchTarget) {
        let started_at = if phase == PresencePhase::Playing {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        } else {
            0
        };

        let mut guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.stopping {
            return;
        }
        guard.phase = phase;
        guard.target = target;
        guard.started_at = started_at;
        guard.revision = guard.revision.saturating_add(1);
        let revision = guard.revision;
        let place_id = guard.target.place_id;
        drop(guard);

        eprintln!(
            "  [discord-rpc] queued phase={} revision={} place_id={}",
            phase.as_str(),
            revision,
            place_id
        );
        self.condvar.notify_all();
        self.wake_fd.signal();
    }

    fn request_stop(&self) {
        if let Ok(mut guard) = self.mutex.lock() {
            guard.stopping = true;
        }
        self.condvar.notify_all();
        self.wake_fd.signal();
        self.stop_fd.signal();
    }

    fn wait_for_change(&self, snapshot_revision: u64, duration: Duration) -> bool {
        let guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (guard, _) = match self.condvar.wait_timeout_while(guard, duration, |state| {
            !state.stopping && state.revision == snapshot_revision
        }) {
            Ok(res) => res,
            Err(poisoned) => poisoned.into_inner(),
        };
        !guard.stopping
    }
}

pub struct MocktailRustDiscordSession {
    shared: Arc<SharedDiscordState>,
    worker: Option<JoinHandle<()>>,
}

fn discord_socket_directories() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            candidates.push(runtime.clone());
            candidates.push(format!("{runtime}/app/com.discordapp.Discord"));
            candidates.push(format!("{runtime}/.flatpak/com.discordapp.Discord/xdg-run"));
            candidates.push(format!("{runtime}/app/dev.vencord.Vesktop"));
            candidates.push(format!("{runtime}/.flatpak/dev.vencord.Vesktop/xdg-run"));
            candidates.push(format!("{runtime}/app/com.discordapp.DiscordCanary"));
            candidates.push(format!("{runtime}/app/com.discordapp.DiscordPTB"));
            candidates.push(format!("{runtime}/snap.discord"));
        }
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if !tmpdir.is_empty() {
            candidates.push(tmpdir);
        }
    }
    candidates.push("/tmp".to_string());
    candidates.push(format!("/run/user/{}", current_uid()));

    let mut seen = HashSet::with_capacity(candidates.len());
    let mut unique = Vec::with_capacity(candidates.len());
    for dir in candidates {
        if seen.insert(dir.clone()) {
            unique.push(dir);
        }
    }
    unique
}

fn connect_discord(shared: &SharedDiscordState) -> Option<OwnedFd> {
    for directory in discord_socket_directories() {
        if shared.is_stopping() {
            return None;
        }
        for index in 0..10 {
            let path = format!("{directory}/discord-ipc-{index}");
            let Some((address, address_len)) = build_sockaddr_un(path.as_bytes()) else {
                continue;
            };
            let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            let Some(fd) = OwnedFd::from_raw(raw_fd) else {
                continue;
            };
            let _ = set_socket_timeouts(fd.as_raw(), K_CONNECT_IO_TIMEOUT_SECS);
            let rc = unsafe {
                libc::connect(
                    fd.as_raw(),
                    (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                    address_len,
                )
            };
            if rc == 0 {
                return Some(fd);
            }
        }
    }
    None
}

fn write_all_ipc(fd: RawFd, bytes: &[u8], stop_fd: Option<&EventFd>) -> bool {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let rc = unsafe {
            libc::send(
                fd,
                bytes[offset..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if rc > 0 {
            offset += rc as usize;
            continue;
        }
        let err = last_errno();
        if rc < 0 && err == libc::EINTR {
            continue;
        }
        if rc < 0 && (err == libc::EAGAIN || err == libc::EWOULDBLOCK) {
            if let Some(stop) = stop_fd {
                let mut fds = [
                    libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: stop.as_raw(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                let ready = poll_retry_eintr(&mut fds, K_WRITE_POLL_TIMEOUT_MS);
                if ready > 0 && (fds[1].revents & libc::POLLIN) == 0 && (fds[0].revents & libc::POLLOUT) != 0 {
                    continue;
                }
            } else {
                let mut fds = [libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                }];
                let ready = poll_retry_eintr(&mut fds, K_WRITE_POLL_TIMEOUT_MS);
                if ready > 0 && (fds[0].revents & libc::POLLOUT) != 0 {
                    continue;
                }
            }
        }
        return false;
    }
    true
}

fn read_all_ipc(fd: RawFd, out: &mut [u8], stop_fd: &EventFd) -> bool {
    let mut offset = 0usize;
    while offset < out.len() {
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop_fd.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = poll_retry_eintr(&mut fds, K_READ_POLL_TIMEOUT_MS);
        if ready <= 0 || (fds[1].revents & libc::POLLIN) != 0 {
            return false;
        }
        let rc = unsafe {
            libc::recv(
                fd,
                out[offset..].as_mut_ptr().cast::<libc::c_void>(),
                out.len() - offset,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if rc > 0 {
            offset += rc as usize;
            continue;
        }
        let err = last_errno();
        if rc < 0 && (err == libc::EINTR || err == libc::EAGAIN || err == libc::EWOULDBLOCK) {
            continue;
        }
        return false;
    }
    true
}

fn write_frame(fd: RawFd, opcode: DiscordOpcode, payload: &str, stop_fd: Option<&EventFd>) -> bool {
    let bytes = payload.as_bytes();
    if bytes.len() > K_MAXIMUM_DISCORD_FRAME_BYTES || bytes.len() > u32::MAX as usize {
        return false;
    }
    let mut frame = Vec::with_capacity(8 + bytes.len());
    frame.extend_from_slice(&(opcode as u32).to_le_bytes());
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
    write_all_ipc(fd, &frame, stop_fd)
}

fn read_frame(fd: RawFd, stop_fd: &EventFd) -> Option<(DiscordOpcode, String)> {
    let mut header = [0u8; 8];
    if !read_all_ipc(fd, &mut header, stop_fd) {
        return None;
    }
    let op_raw = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > K_MAXIMUM_DISCORD_FRAME_BYTES {
        return None;
    }
    let opcode = DiscordOpcode::from_u32(op_raw)?;
    let mut payload = vec![0u8; length];
    if length > 0 && !read_all_ipc(fd, &mut payload, stop_fd) {
        return None;
    }
    Some((opcode, String::from_utf8_lossy(&payload).into_owned()))
}

pub(crate) fn build_handshake_json(application_id: &str) -> Option<String> {
    let handshake = json!({
        "v": 1,
        "client_id": application_id,
    });
    serde_json::to_string(&handshake).ok()
}

pub(crate) fn is_ready_event_json(payload: &str) -> bool {
    parse_json_object_str(payload, false)
        .and_then(|obj| obj.get("evt").and_then(|v| v.as_str()).map(|s| s == "READY"))
        .unwrap_or(false)
}

fn handshake_discord(fd: RawFd, application_id: &str, stop_fd: &EventFd) -> bool {
    let Some(handshake_json) = build_handshake_json(application_id) else {
        return false;
    };
    if !write_frame(fd, DiscordOpcode::Handshake, &handshake_json, Some(stop_fd)) {
        return false;
    }
    for _ in 0..3 {
        let Some((opcode, payload)) = read_frame(fd, stop_fd) else {
            return false;
        };
        if opcode == DiscordOpcode::Ping {
            if !write_frame(fd, DiscordOpcode::Pong, &payload, Some(stop_fd)) {
                return false;
            }
            continue;
        }
        if opcode != DiscordOpcode::Frame {
            return false;
        }
        return is_ready_event_json(&payload);
    }
    false
}

pub(crate) fn build_set_activity_json(
    pid: i32,
    activity: Option<&BuiltActivity>,
    nonce: u64,
) -> Option<String> {
    let activity_val = match activity {
        None => Value::Null,
        Some(act) => {
            let mut map = Map::new();
            map.insert("type".to_owned(), Value::Number(0.into()));
            map.insert("details".to_owned(), Value::String(act.details.clone()));
            map.insert("instance".to_owned(), Value::Bool(true));
            if !act.state.is_empty() {
                map.insert("state".to_owned(), Value::String(act.state.clone()));
            }
            if let Some(ts) = act.start_timestamp {
                map.insert("timestamps".to_owned(), json!({ "start": ts }));
            }
            if !act.large_image.is_empty() {
                let mut assets = Map::new();
                assets.insert("large_image".to_owned(), Value::String(act.large_image.clone()));
                if !act.large_text.is_empty() {
                    assets.insert("large_text".to_owned(), Value::String(act.large_text.clone()));
                }
                map.insert("assets".to_owned(), Value::Object(assets));
            }
            if !act.button_label.is_empty() && !act.button_url.is_empty() {
                map.insert(
                    "buttons".to_owned(),
                    json!([{ "label": act.button_label, "url": act.button_url }]),
                );
            }
            Value::Object(map)
        }
    };

    let request = json!({
        "cmd": "SET_ACTIVITY",
        "args": {
            "pid": pid,
            "activity": activity_val,
        },
        "nonce": nonce.to_string(),
    });
    serde_json::to_string(&request).ok()
}

fn set_discord_activity(
    fd: RawFd,
    activity: Option<&BuiltActivity>,
    nonce: u64,
    stop_fd: Option<&EventFd>,
) -> bool {
    let Some(json) = build_set_activity_json(current_pid(), activity, nonce) else {
        return false;
    };
    write_frame(fd, DiscordOpcode::Frame, &json, stop_fd)
}

pub(crate) fn parse_rpc_error_fields(payload: &str) -> Option<(i64, String)> {
    let obj = parse_json_object_str(payload, false)?;
    if obj.get("evt").and_then(|v| v.as_str()) != Some("ERROR") {
        return None;
    }
    let mut code = 0i64;
    let mut message = String::from("Discord rejected an RPC request");
    if let Some(data) = obj.get("data").and_then(|v| v.as_object()) {
        if let Some(parsed_code) = data.get("code").and_then(|v| v.as_i64()) {
            code = parsed_code;
        }
        if let Some(raw_msg) = data.get("message").and_then(|v| v.as_str()) {
            let truncated = truncate_utf8_str(raw_msg, 256);
            message = truncated
                .chars()
                .map(|c| {
                    let u = c as u32;
                    if u < 0x20 || u == 0x7f {
                        ' '
                    } else {
                        c
                    }
                })
                .collect();
        }
    }
    Some((code, message))
}

fn log_discord_rpc_error(opcode: DiscordOpcode, payload: &str) {
    if opcode != DiscordOpcode::Frame {
        return;
    }
    if let Some((code, message)) = parse_rpc_error_fields(payload) {
        eprintln!("  [discord-rpc] request rejected code={}: {}", code, message);
    }
}

fn inspect_metadata(
    callbacks: &MocktailRustDiscordMetadataCallbacks,
    phase: PresencePhase,
    place_id: i64,
) -> MetadataInspectResult {
    let mut result = MetadataInspectResult::default();
    if let Some(inspect_fn) = callbacks.inspect {
        unsafe {
            inspect_fn(
                callbacks.ctx,
                phase as i32,
                place_id,
                capture_metadata_inspect_result,
                (&mut result as *mut MetadataInspectResult).cast::<c_void>(),
            );
        }
    }
    result
}

fn refresh_metadata(
    callbacks: &MocktailRustDiscordMetadataCallbacks,
    place_id: i64,
) -> (bool, i64) {
    let Some(refresh_fn) = callbacks.refresh else {
        return (false, 0);
    };
    let mut retry_delay_secs: i64 = 0;
    let changed = unsafe { refresh_fn(callbacks.ctx, place_id, &mut retry_delay_secs) };
    (changed, retry_delay_secs)
}

fn run_discord_worker(
    cfg: DiscordConfig,
    callbacks: MocktailRustDiscordMetadataCallbacks,
    shared: Arc<SharedDiscordState>,
) {
    let mut connection: Option<OwnedFd> = None;
    let mut published_revision: u64 = 0;
    let mut nonce: u64 = 1;
    let mut activity_updates: VecDeque<Instant> = VecDeque::new();

    while !shared.is_stopping() {
        let desired = shared.snapshot();
        let metadata = inspect_metadata(&callbacks, desired.phase, desired.target.place_id);

        if connection.is_none() {
            let connected = connect_discord(&shared).filter(|fd| {
                handshake_discord(fd.as_raw(), &cfg.application_id, &shared.stop_fd)
            });
            match connected {
                Some(fd) => {
                    eprintln!("  [discord-rpc] connected to Discord Desktop");
                    connection = Some(fd);
                    published_revision = 0;
                }
                None => {
                    if !shared.wait_for_change(desired.revision, K_RECONNECT_DELAY) {
                        break;
                    }
                    continue;
                }
            }
        }

        let Some(sock_fd) = connection.as_ref().map(OwnedFd::as_raw) else {
            continue;
        };

        if published_revision != desired.revision && !metadata.waiting_for_name {
            let now = Instant::now();
            while let Some(&front) = activity_updates.front() {
                if now.saturating_duration_since(front) >= K_DISCORD_ACTIVITY_RATE_WINDOW {
                    activity_updates.pop_front();
                } else {
                    break;
                }
            }
            if activity_updates.len() >= K_DISCORD_ACTIVITY_RATE_LIMIT {
                if let Some(&front) = activity_updates.front() {
                    let resume_at = front + K_DISCORD_ACTIVITY_RATE_WINDOW;
                    let delay = resume_at.saturating_duration_since(now);
                    if !shared.wait_for_change(desired.revision, delay) {
                        break;
                    }
                    continue;
                }
            }

            let target_ref = if desired.phase == PresencePhase::Browsing {
                None
            } else {
                Some(&desired.target)
            };
            let activity = build_discord_activity(
                &cfg,
                desired.phase,
                target_ref,
                &metadata.name,
                desired.started_at,
                &metadata.icon_url,
            );
            let current_nonce = nonce;
            nonce = nonce.wrapping_add(1);
            if !set_discord_activity(
                sock_fd,
                Some(&activity),
                current_nonce,
                Some(&shared.stop_fd),
            ) {
                connection = None;
                continue;
            }
            eprintln!(
                "  [discord-rpc] sent phase={} revision={}",
                desired.phase.as_str(),
                desired.revision
            );
            activity_updates.push_back(Instant::now());
            published_revision = desired.revision;
        }

        if metadata.should_fetch_after_publish && desired.target.place_id > 0 {
            let (changed, retry_delay_secs) =
                refresh_metadata(&callbacks, desired.target.place_id);
            if retry_delay_secs > 0 {
                eprintln!(
                    "  [discord-rpc] place metadata incomplete; retry in {}s place_id={}",
                    retry_delay_secs, desired.target.place_id
                );
            }
            if shared.snapshot().revision != desired.revision {
                continue;
            }
            if changed
                && matches!(
                    desired.phase,
                    PresencePhase::Joining | PresencePhase::Playing
                )
            {
                // Publish updated cached metadata through the normal rate limiter.
                published_revision = 0;
                continue;
            }
        }

        let mut fds = [
            libc::pollfd {
                fd: sock_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: shared.wake_fd.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = poll_retry_eintr(&mut fds, K_IDLE_POLL_TIMEOUT_MS);
        if ready < 0
            || (ready > 0 && (fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0)
        {
            connection = None;
            continue;
        }
        if ready > 0 && (fds[1].revents & libc::POLLIN) != 0 {
            shared.wake_fd.drain();
        }
        if ready > 0 && (fds[0].revents & libc::POLLIN) != 0 {
            match read_frame(sock_fd, &shared.stop_fd) {
                None => {
                    connection = None;
                }
                Some((DiscordOpcode::Ping, payload)) => {
                    if !write_frame(
                        sock_fd,
                        DiscordOpcode::Pong,
                        &payload,
                        Some(&shared.stop_fd),
                    ) {
                        connection = None;
                    }
                }
                Some((DiscordOpcode::Close, _)) => {
                    connection = None;
                }
                Some((opcode, payload)) => {
                    log_discord_rpc_error(opcode, &payload);
                }
            }
        }
    }

    if let Some(fd) = connection.as_ref() {
        let _ = set_discord_activity(fd.as_raw(), None, nonce, None);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_build_activity(
    config: *const MocktailRustDiscordConfig,
    phase: i32,
    has_request: bool,
    launch_slice: *const MocktailRustDiscordLaunchSlice,
    place_name_ptr: *const c_char,
    place_name_len: usize,
    session_started_at: i64,
    place_icon_url_ptr: *const c_char,
    place_icon_url_len: usize,
    on_built: MocktailDiscordActivityFieldsCallback,
    ctx: *mut c_void,
) -> i32 {
    if config.is_null() {
        return -1;
    }
    let Some(cfg) = (unsafe { DiscordConfig::from_ffi(&*config) }) else {
        return -1;
    };
    let Some(target) = (unsafe { SanitizedLaunchTarget::from_ffi(has_request, launch_slice) })
    else {
        return -1;
    };
    let place_name =
        unsafe { slice_to_lossy_opt(place_name_ptr, place_name_len) }.unwrap_or_default();
    let icon_url =
        unsafe { slice_to_lossy_opt(place_icon_url_ptr, place_icon_url_len) }.unwrap_or_default();
    let built = build_discord_activity(
        &cfg,
        PresencePhase::from_i32(phase),
        if target.present { Some(&target) } else { None },
        &place_name,
        session_started_at,
        &icon_url,
    );
    if let Some(cb) = on_built {
        unsafe {
            cb(
                ctx,
                built.details.as_ptr().cast::<c_char>(),
                built.details.len(),
                built.state.as_ptr().cast::<c_char>(),
                built.state.len(),
                built.start_timestamp.is_some(),
                built.start_timestamp.unwrap_or(0),
                built.large_image.as_ptr().cast::<c_char>(),
                built.large_image.len(),
                built.large_text.as_ptr().cast::<c_char>(),
                built.large_text.len(),
                built.button_label.as_ptr().cast::<c_char>(),
                built.button_label.len(),
                built.button_url.as_ptr().cast::<c_char>(),
                built.button_url.len(),
            );
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_session_start(
    config: *const MocktailRustDiscordConfig,
    metadata_callbacks: *const MocktailRustDiscordMetadataCallbacks,
    out_session: *mut *mut MocktailRustDiscordSession,
    out_detail: *mut c_char,
    detail_cap: usize,
) -> i32 {
    if out_session.is_null() {
        copy_error(out_detail, detail_cap, "null out_session pointer");
        return -1;
    }
    unsafe {
        *out_session = std::ptr::null_mut();
    }
    if config.is_null() {
        copy_error(out_detail, detail_cap, "null Discord configuration");
        return -1;
    }
    let raw = unsafe { &*config };
    if raw.enabled == 0 {
        copy_error(out_detail, detail_cap, "disabled by runtime policy");
        return 0;
    }
    let Some(cfg) = (unsafe { DiscordConfig::from_ffi(raw) }) else {
        copy_error(out_detail, detail_cap, "invalid Discord configuration");
        return -1;
    };
    if cfg.application_id.is_empty() {
        copy_error(out_detail, detail_cap, "no Discord application ID is bundled");
        return -1;
    }

    let cbs = if metadata_callbacks.is_null() {
        MocktailRustDiscordMetadataCallbacks {
            ctx: std::ptr::null_mut(),
            inspect: None,
            refresh: None,
        }
    } else {
        unsafe { *metadata_callbacks }
    };

    let shared = match SharedDiscordState::new() {
        Ok(s) => Arc::new(s),
        Err(err) => {
            copy_error(
                out_detail,
                detail_cap,
                &format!("could not start Discord RPC worker: {}", err),
            );
            return -1;
        }
    };
    let worker_shared = Arc::clone(&shared);
    let worker = match thread::Builder::new()
        .name("mocktail-discord".to_string())
        .stack_size(K_DISCORD_WORKER_STACK_BYTES)
        .spawn(move || run_discord_worker(cfg, cbs, worker_shared))
    {
        Ok(handle) => handle,
        Err(err) => {
            let raw_err = err.raw_os_error().unwrap_or(libc::ENOMEM);
            copy_error(
                out_detail,
                detail_cap,
                &format!("could not start Discord RPC worker: {}", raw_err),
            );
            return -1;
        }
    };

    let boxed = Box::new(MocktailRustDiscordSession {
        shared,
        worker: Some(worker),
    });
    unsafe {
        *out_session = Box::into_raw(boxed);
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_session_update(
    session: *mut MocktailRustDiscordSession,
    phase: i32,
    has_request: bool,
    launch_slice: *const MocktailRustDiscordLaunchSlice,
) -> i32 {
    if session.is_null() {
        return -1;
    }
    let Some(target) = (unsafe { SanitizedLaunchTarget::from_ffi(has_request, launch_slice) })
    else {
        return -1;
    };
    let s = unsafe { &*session };
    s.shared.update(PresencePhase::from_i32(phase), target);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_session_stop(session: *mut MocktailRustDiscordSession) {
    if session.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(session) };
    boxed.shared.request_stop();
    if let Some(handle) = boxed.worker.take() {
        let _ = handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(ref val) = self.prev {
                std::env::set_var(self.key, val);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
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

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn default_test_config() -> DiscordConfig {
        DiscordConfig {
            show_place_name: true,
            show_elapsed_time: true,
            join_enabled: true,
            public_servers_only: true,
            join_button_label: "Join Server".to_string(),
            application_id: "123456789012345678".to_string(),
            text_browsing: "Browsing experiences".to_string(),
            text_joining: "Joining an experience".to_string(),
            text_playing: "{place_name}".to_string(),
            text_state: "Playing Roblox".to_string(),
            text_unknown_place: "Unknown experience".to_string(),
        }
    }

    #[test]
    fn activity_builder_handles_phases_privacy_and_images() {
        let cfg = default_test_config();
        let browsing = build_discord_activity(&cfg, PresencePhase::Browsing, None, "", 0, "");
        assert_eq!(browsing.details, "Browsing experiences");
        assert_eq!(browsing.state, "Playing Roblox");
        assert!(browsing.button_url.is_empty());

        let pub_target = SanitizedLaunchTarget {
            present: true,
            place_id: 189707,
            game_instance_id: "job/a+b".to_string(),
            has_private_access: false,
        };
        let playing = build_discord_activity(
            &cfg,
            PresencePhase::Playing,
            Some(&pub_target),
            "Natural Disaster Survival",
            1770000000,
            "https://tr.rbxcdn.com/example/icon.png",
        );
        assert_eq!(playing.details, "Natural Disaster Survival");
        assert_eq!(playing.start_timestamp, Some(1770000000));
        assert_eq!(
            playing.large_image,
            "https://tr.rbxcdn.com/example/icon.png"
        );
        assert_eq!(
            playing.button_url,
            "https://komaruworld.github.io/mocktail/join.html#placeId=189707&gameInstanceId=job%2Fa%2Bb"
        );

        let priv_target = SanitizedLaunchTarget {
            present: true,
            place_id: 189707,
            game_instance_id: "job1".to_string(),
            has_private_access: true,
        };
        let private_act = build_discord_activity(
            &cfg,
            PresencePhase::Playing,
            Some(&priv_target),
            "Secret",
            1,
            "file:///etc/passwd",
        );
        assert!(private_act.button_url.is_empty());
        assert!(private_act.large_image.is_empty());
    }

    #[test]
    fn discord_ipc_session_handshakes_pings_updates_and_clears() {
        use std::io::{Read, Write};
        use std::sync::mpsc;

        let _env_lock = crate::unix_ipc::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDirGuard::new("mocktail_discord_rust_test");
        let sock_path = temp.path.join("discord-ipc-0");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let _env = EnvGuard::set("XDG_RUNTIME_DIR", &temp.path);
        let (tx, rx) = mpsc::channel::<usize>();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(4)))
                .unwrap();

            fn read_frame_std(s: &mut std::os::unix::net::UnixStream) -> (u32, String) {
                let mut hdr = [0u8; 8];
                s.read_exact(&mut hdr).unwrap();
                let op = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
                let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).unwrap();
                (op, String::from_utf8(body).unwrap())
            }

            fn write_frame_std(
                s: &mut std::os::unix::net::UnixStream,
                op: u32,
                payload: &str,
            ) {
                let mut pkt = Vec::with_capacity(8 + payload.len());
                pkt.extend_from_slice(&op.to_le_bytes());
                pkt.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                pkt.extend_from_slice(payload.as_bytes());
                s.write_all(&pkt).unwrap();
            }

            let (op, handshake) = read_frame_std(&mut stream);
            assert_eq!(op, 0);
            assert!(handshake.contains("123456789012345678"));

            // Send PING before READY to verify ping/pong during handshake.
            write_frame_std(&mut stream, 3, r#"{"nonce":"ping1"}"#);
            let (pong_op, pong_body) = read_frame_std(&mut stream);
            assert_eq!(pong_op, 4);
            assert_eq!(pong_body, r#"{"nonce":"ping1"}"#);

            write_frame_std(&mut stream, 1, r#"{"cmd":"DISPATCH","data":{},"evt":"READY"}"#);

            let (op1, p1) = read_frame_std(&mut stream);
            assert_eq!(op1, 1);
            assert!(p1.contains("Browsing experiences"));
            let _ = tx.send(1);

            let (op2, p2) = read_frame_std(&mut stream);
            assert_eq!(op2, 1);
            assert!(p2.contains("Playing Roblox"));
            assert!(p2.contains("Unknown experience"));
            let _ = tx.send(2);

            let (op3, p3) = read_frame_std(&mut stream);
            assert_eq!(op3, 1);
            assert!(p3.contains(r#""activity":null"#));
        });

        let app_id = CString::new("123456789012345678").unwrap();
        let cfg = MocktailRustDiscordConfig {
            enabled: 1,
            show_place_name: 1,
            show_elapsed_time: 1,
            join_enabled: 0,
            public_servers_only: 1,
            join_button_label_ptr: b"Join".as_ptr().cast::<c_char>(),
            join_button_label_len: 4,
            application_id_ptr: app_id.as_ptr(),
            application_id_len: app_id.as_bytes().len(),
            text_browsing_ptr: b"Browsing experiences".as_ptr().cast::<c_char>(),
            text_browsing_len: 20,
            text_joining_ptr: b"Joining".as_ptr().cast::<c_char>(),
            text_joining_len: 7,
            text_playing_ptr: b"{place_name}".as_ptr().cast::<c_char>(),
            text_playing_len: 12,
            text_state_ptr: b"Playing Roblox".as_ptr().cast::<c_char>(),
            text_state_len: 14,
            text_unknown_place_ptr: b"Unknown experience".as_ptr().cast::<c_char>(),
            text_unknown_place_len: 18,
        };
        let mut session: *mut MocktailRustDiscordSession = std::ptr::null_mut();
        let mut detail = [0 as c_char; 128];
        let rc = mocktail_rust_discord_session_start(
            &cfg,
            std::ptr::null(),
            &mut session,
            detail.as_mut_ptr(),
            detail.len(),
        );
        assert_eq!(rc, 0);
        assert!(!session.is_null());

        assert_eq!(rx.recv_timeout(Duration::from_secs(4)).unwrap(), 1);
        let slice = MocktailRustDiscordLaunchSlice {
            place_id: 0,
            game_instance_id_ptr: std::ptr::null(),
            game_instance_id_len: 0,
            has_private_access: false,
        };
        assert_eq!(
            mocktail_rust_discord_session_update(session, 2, true, &slice),
            0
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(4)).unwrap(), 2);
        mocktail_rust_discord_session_stop(session);
        server.join().unwrap();
    }

    #[test]
    fn discord_ipc_metadata_callbacks_resolve_and_republish_activity() {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;

        struct MockMetadata {
            ready: AtomicBool,
        }

        unsafe extern "C" fn mock_inspect(
            ctx: *mut c_void,
            phase: i32,
            place_id: i64,
            on_result: MocktailDiscordMetadataInspectResultFn,
            rust_out: *mut c_void,
        ) {
            let meta = &*(ctx as *const MockMetadata);
            if phase != 2 || place_id <= 0 {
                on_result(rust_out, std::ptr::null(), 0, std::ptr::null(), 0, false, false);
                return;
            }
            if meta.ready.load(Ordering::Acquire) {
                let name = b"Work at a Pizza Place";
                let icon = b"https://tr.rbxcdn.com/pizza/512/512/Png";
                on_result(
                    rust_out,
                    name.as_ptr().cast::<c_char>(),
                    name.len(),
                    icon.as_ptr().cast::<c_char>(),
                    icon.len(),
                    false,
                    false,
                );
            } else {
                on_result(rust_out, std::ptr::null(), 0, std::ptr::null(), 0, true, true);
            }
        }

        unsafe extern "C" fn mock_refresh(
            ctx: *mut c_void,
            place_id: i64,
            out_retry_delay_secs: *mut i64,
        ) -> bool {
            *out_retry_delay_secs = 0;
            if place_id == 192800 {
                let meta = &*(ctx as *const MockMetadata);
                meta.ready.store(true, Ordering::Release);
                return true;
            }
            false
        }

        let _env_lock = crate::unix_ipc::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDirGuard::new("mocktail_discord_meta_test");
        let sock_path = temp.path.join("discord-ipc-0");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let _env = EnvGuard::set("XDG_RUNTIME_DIR", &temp.path);
        let (tx, rx) = mpsc::channel::<usize>();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(4)))
                .unwrap();

            fn read_frame_std(s: &mut std::os::unix::net::UnixStream) -> (u32, String) {
                let mut hdr = [0u8; 8];
                s.read_exact(&mut hdr).unwrap();
                let op = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
                let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).unwrap();
                (op, String::from_utf8(body).unwrap())
            }

            let (op, _) = read_frame_std(&mut stream);
            assert_eq!(op, 0);
            let ready = r#"{"cmd":"DISPATCH","data":{},"evt":"READY"}"#;
            let mut hdr = Vec::with_capacity(8 + ready.len());
            hdr.extend_from_slice(&1u32.to_le_bytes());
            hdr.extend_from_slice(&(ready.len() as u32).to_le_bytes());
            hdr.extend_from_slice(ready.as_bytes());
            stream.write_all(&hdr).unwrap();

            let (_, p1) = read_frame_std(&mut stream);
            assert!(p1.contains("Browsing experiences"));
            let _ = tx.send(1);

            let (_, p2) = read_frame_std(&mut stream);
            assert!(p2.contains("Work at a Pizza Place"));
            assert!(p2.contains("https://tr.rbxcdn.com/pizza/512/512/Png"));
            let _ = tx.send(2);

            let (_, p3) = read_frame_std(&mut stream);
            assert!(p3.contains(r#""activity":null"#));
        });

        let app_id = CString::new("123456789012345678").unwrap();
        let cfg = MocktailRustDiscordConfig {
            enabled: 1,
            show_place_name: 1,
            show_elapsed_time: 1,
            join_enabled: 0,
            public_servers_only: 1,
            join_button_label_ptr: b"Join".as_ptr().cast::<c_char>(),
            join_button_label_len: 4,
            application_id_ptr: app_id.as_ptr(),
            application_id_len: app_id.as_bytes().len(),
            text_browsing_ptr: b"Browsing experiences".as_ptr().cast::<c_char>(),
            text_browsing_len: 20,
            text_joining_ptr: b"Joining".as_ptr().cast::<c_char>(),
            text_joining_len: 7,
            text_playing_ptr: b"{place_name}".as_ptr().cast::<c_char>(),
            text_playing_len: 12,
            text_state_ptr: b"Playing Roblox".as_ptr().cast::<c_char>(),
            text_state_len: 14,
            text_unknown_place_ptr: b"Unknown experience".as_ptr().cast::<c_char>(),
            text_unknown_place_len: 18,
        };
        let meta = Box::new(MockMetadata {
            ready: AtomicBool::new(false),
        });
        let cbs = MocktailRustDiscordMetadataCallbacks {
            ctx: (&*meta as *const MockMetadata).cast_mut().cast::<c_void>(),
            inspect: Some(mock_inspect),
            refresh: Some(mock_refresh),
        };
        let mut session: *mut MocktailRustDiscordSession = std::ptr::null_mut();
        let mut detail = [0 as c_char; 128];
        assert_eq!(
            mocktail_rust_discord_session_start(
                &cfg,
                &cbs,
                &mut session,
                detail.as_mut_ptr(),
                detail.len(),
            ),
            0
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(4)).unwrap(), 1);
        let slice = MocktailRustDiscordLaunchSlice {
            place_id: 192800,
            game_instance_id_ptr: std::ptr::null(),
            game_instance_id_len: 0,
            has_private_access: false,
        };
        assert_eq!(
            mocktail_rust_discord_session_update(session, 2, true, &slice),
            0
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(4)).unwrap(), 2);
        mocktail_rust_discord_session_stop(session);
        server.join().unwrap();
    }
}
