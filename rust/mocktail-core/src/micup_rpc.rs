//! Micup (`micup.gg`) Rich Presence / Game Activity Gateway RPC client.
//!
//! Unlike Discord Desktop RPC (which uses a local unauthenticated IPC socket),
//! Micup's official Game Activity protocol runs directly over the Micup Gateway
//! WebSocket (`wss://micup.gg/gateway?v=1&encoding=json`) using Op 10 (`HELLO`),
//! Op 2 (`IDENTIFY`), Op 1/11 (`HEARTBEAT`/`HEARTBEAT_ACK`), Op 3
//! (`PRESENCE_UPDATE` with `game_activity`), and Op 6 (`RESUME`).

use std::collections::VecDeque;
use std::ffi::c_char;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rustls::crypto::ring;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, ServerName};
use serde_json::{json, Value};
use tungstenite::error::Error as WsError;
use tungstenite::http::Uri;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::frame::CloseFrame;
use tungstenite::{client as ws_client, ClientRequestBuilder, Message, WebSocket};
use url::Url;
use zeroize::Zeroizing;

pub const DEFAULT_MICUP_GATEWAY_URL: &str = "wss://micup.gg/gateway?v=1&encoding=json";
pub const MICUP_ROBLOX_CATALOG_ID: &str = "roblox";

const MAX_GATEWAY_URL_BYTES: usize = 512;
const MAX_MICUP_TOKEN_BYTES: usize = 256;
const MAX_TOKEN_FILE_BYTES: usize = 4096;
const MAX_CA_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROXY_CONNECT_HEADER_BYTES: usize = 8192;
const MAX_MANUAL_NAME_CODEPOINTS: usize = 64;
const MAX_MANUAL_NAME_BYTES: usize = 256;
const MAX_GAME_ACTIVITY_JSON_BYTES: usize = 512;
const MAX_SAFE_TIMESTAMP_MS: i64 = 9_007_199_254_740_991;

const PRESENCE_RATE_LIMIT: usize = 5;
const PRESENCE_RATE_WINDOW: Duration = Duration::from_secs(20);
const ACTIVITY_BUCKET_CAPACITY: f64 = 2.0;
const ACTIVITY_BUCKET_REFILL_PER_SEC: f64 = 0.1; // 1 token per 10s
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(60); // server lease is 120s
const NO_ELAPSED_REFRESH_INTERVAL: Duration = Duration::from_secs(50);
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(2);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const IO_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IO_POLL_READ_TIMEOUT: Duration = Duration::from_millis(100);
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

// Events unrelated to session/presence state that the gateway can suppress to
// keep background traffic minimal while Roblox is running.
const IGNORED_GATEWAY_EVENTS: &[&str] = &[
    "MESSAGE_CREATE",
    "MESSAGE_UPDATE",
    "MESSAGE_DELETE",
    "MESSAGE_DELETE_BULK",
    "MESSAGE_REACTION_ADD",
    "MESSAGE_REACTION_REMOVE",
    "MESSAGE_REACTION_REMOVE_ALL",
    "TYPING_START",
    "GUILD_CREATE",
    "GUILD_UPDATE",
    "GUILD_DELETE",
    "GUILD_MEMBER_ADD",
    "GUILD_MEMBER_UPDATE",
    "GUILD_MEMBER_REMOVE",
    "CHANNEL_CREATE",
    "CHANNEL_UPDATE",
    "CHANNEL_DELETE",
    "VOICE_STATE_UPDATE",
    "VOICE_SERVER_UPDATE",
];

#[repr(C)]
pub struct MocktailRustMicupConfig {
    pub gateway_url_ptr: *const c_char,
    pub gateway_url_len: usize,
    pub token_ptr: *const c_char,
    pub token_len: usize,
    pub token_file_ptr: *const c_char,
    pub token_file_len: usize,
    pub status_ptr: *const c_char,
    pub status_len: usize,
    pub activity_mode_ptr: *const c_char,
    pub activity_mode_len: usize,
    pub text_browsing_ptr: *const c_char,
    pub text_browsing_len: usize,
    pub text_joining_ptr: *const c_char,
    pub text_joining_len: usize,
    pub text_playing_ptr: *const c_char,
    pub text_playing_len: usize,
    pub text_unknown_place_ptr: *const c_char,
    pub text_unknown_place_len: usize,
    pub ca_bundle_ptr: *const c_char,
    pub ca_bundle_len: usize,
    pub proxy_url_ptr: *const c_char,
    pub proxy_url_len: usize,
    pub proxy_username_ptr: *const c_char,
    pub proxy_username_len: usize,
    pub proxy_password_ptr: *const c_char,
    pub proxy_password_len: usize,
    pub enabled: i32,
    pub show_place_name: i32,
    pub show_elapsed_time: i32,
}

/// Opaque handle representing an active Micup Gateway RPC session.
pub struct MocktailRustMicupSession {
    shared: Arc<SharedSessionState>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresencePhase {
    Browsing,
    Joining,
    Playing,
}

impl PresencePhase {
    fn from_i32(raw: i32) -> Self {
        match raw {
            1 => Self::Joining,
            2 => Self::Playing,
            _ => Self::Browsing,
        }
    }
}

#[derive(Debug, Clone)]
struct MicupTextSettings {
    browsing: String,
    joining: String,
    playing: String,
    unknown_place: String,
}

impl Default for MicupTextSettings {
    fn default() -> Self {
        Self {
            browsing: "Browsing Roblox".to_string(),
            joining: "Joining an experience".to_string(),
            playing: "{place_name}".to_string(),
            unknown_place: "Unknown experience".to_string(),
        }
    }
}

#[derive(Clone)]
struct ProxyConfig {
    url: String,
    username: String,
    password: Zeroizing<String>,
}

#[derive(Clone)]
struct SessionConfig {
    gateway_url: String,
    token: Zeroizing<String>,
    status: String,
    activity_mode: String,
    show_place_name: bool,
    show_elapsed_time: bool,
    text: MicupTextSettings,
    proxy: Option<ProxyConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredPresence {
    phase: PresencePhase,
    place_id: i64,
    place_name: String,
    started_at_ms: i64,
    revision: u64,
}

impl Default for DesiredPresence {
    fn default() -> Self {
        Self {
            phase: PresencePhase::Browsing,
            place_id: 0,
            place_name: String::new(),
            started_at_ms: 0,
            revision: 1,
        }
    }
}

struct SharedInner {
    desired: DesiredPresence,
    stopping: bool,
}

struct SharedSessionState {
    inner: Mutex<SharedInner>,
    condvar: Condvar,
}

impl SharedSessionState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SharedInner {
                desired: DesiredPresence::default(),
                stopping: false,
            }),
            condvar: Condvar::new(),
        }
    }

    fn snapshot(&self) -> (DesiredPresence, bool) {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (guard.desired.clone(), guard.stopping)
    }

    fn update(&self, desired: DesiredPresence) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.stopping {
            return;
        }
        guard.desired = desired;
        self.condvar.notify_all();
    }

    fn request_stop(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.stopping = true;
        self.condvar.notify_all();
    }

    /// Waits until `stopping` becomes true or `desired.revision != revision` or
    /// `duration` elapses. Returns `false` if stopping was requested.
    fn wait_until(&self, revision: u64, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if guard.stopping {
                return false;
            }
            if guard.desired.revision != revision {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            let (next_guard, _) = self
                .condvar
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            guard = next_guard;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MicupGameActivity {
    Catalog {
        game_id: String,
        started_at: i64,
    },
    Manual {
        manual_name: String,
        started_at: i64,
    },
}

impl MicupGameActivity {
    /// Returns the activity variant + name without timestamp so we can detect
    /// genuine activity changes vs timer-only lease renewals cleanly.
    fn identity_key(&self) -> (&'static str, &str) {
        match self {
            Self::Catalog { game_id, .. } => ("catalog", game_id.as_str()),
            Self::Manual { manual_name, .. } => ("manual", manual_name.as_str()),
        }
    }

    fn to_json_value(&self) -> Value {
        let mut obj = match self {
            Self::Catalog { game_id, started_at } => json!({
                "game_id": game_id,
                "started_at": started_at,
            }),
            Self::Manual {
                manual_name,
                started_at,
            } => json!({
                "manual_name": manual_name,
                "started_at": started_at,
            }),
        };
        // Guard against any pathological UTF-8 encoding pushing past server's
        // 512-byte serialized JSON ceiling.
        if let Self::Manual { manual_name, .. } = self {
            let encoded_len = serde_json::to_vec(&obj).map(|v| v.len()).unwrap_or(0);
            if encoded_len > MAX_GAME_ACTIVITY_JSON_BYTES {
                let mut trimmed = manual_name.clone();
                while !trimmed.is_empty() {
                    trimmed.pop();
                    let candidate = json!({
                        "manual_name": trimmed.trim_end(),
                        "started_at": match self {
                            Self::Manual { started_at, .. } => *started_at,
                            _ => 0,
                        },
                    });
                    if serde_json::to_vec(&candidate)
                        .map(|v| v.len() <= MAX_GAME_ACTIVITY_JSON_BYTES)
                        .unwrap_or(false)
                    {
                        obj = candidate;
                        break;
                    }
                }
            }
        }
        obj
    }
}

fn copy_c_str(out: *mut c_char, cap: usize, msg: &str) {
    if out.is_null() || cap == 0 {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(cap - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, n);
        *out.add(n) = 0;
    }
}

unsafe fn slice_to_str<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    std::str::from_utf8(bytes).ok()
}

pub fn is_valid_micup_status(status: &str) -> bool {
    matches!(status, "auto" | "online" | "idle" | "dnd" | "invisible")
}

pub fn is_valid_micup_activity_mode(mode: &str) -> bool {
    matches!(mode, "auto" | "manual" | "catalog")
}

pub fn is_valid_micup_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && !text.bytes().any(|b| b < 0x20 || b == 0x7F)
}

pub fn is_valid_micup_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_MICUP_TOKEN_BYTES
        && !token.bytes().any(|b| b < 0x20 || b == 0x7F)
        && token.bytes().any(|b| b > 0x20)
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost") || trimmed == "127.0.0.1" || trimmed == "::1"
}

/// Validates and normalizes a Micup Gateway WebSocket URL.
/// Requires `wss://` for remote hosts; permits `ws://` only for loopback.
pub fn normalize_gateway_url(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_GATEWAY_URL_BYTES {
        return None;
    }
    if raw.bytes().any(|b| b <= 0x20 || b == 0x7F) {
        return None;
    }
    let mut url = Url::parse(raw).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return None;
    }
    let host = url.host_str()?;
    if host.is_empty() {
        return None;
    }
    match url.scheme() {
        "wss" => {}
        "ws" if is_loopback_host(host) => {}
        _ => return None,
    }
    let has_v = url.query_pairs().any(|(k, _)| k == "v");
    let has_enc = url.query_pairs().any(|(k, _)| k == "encoding");
    if !has_v || !has_enc {
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if !has_v {
            pairs.push(("v".to_string(), "1".to_string()));
        }
        if !has_enc {
            pairs.push(("encoding".to_string(), "json".to_string()));
        }
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    let normalized = url.to_string();
    if normalized.len() > MAX_GATEWAY_URL_BYTES {
        return None;
    }
    Some(normalized)
}

fn is_forbidden_manual_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c as u32,
            0x00AD
                | 0x034F
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x115F..=0x1160
                | 0x17B4..=0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
                | 0xE0100..=0xE01EF
        )
}

/// Sanitizes an experience title or status template into a valid Micup
/// `manual_name` matching Micup's `GameActivitySchemas` constraints:
/// strips control/format/variation-selector characters, enforces 64 Unicode
/// scalar values and 256 UTF-8 bytes, and falls back to `"Roblox"` if empty.
pub fn sanitize_manual_name(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len().min(MAX_MANUAL_NAME_BYTES));
    let mut last_was_space = false;
    for ch in raw.chars() {
        if matches!(ch, '\n' | '\r' | '\t') {
            if !cleaned.is_empty() && !last_was_space {
                cleaned.push(' ');
                last_was_space = true;
            }
            continue;
        }
        if is_forbidden_manual_char(ch) {
            continue;
        }
        if ch.is_whitespace() {
            if !cleaned.is_empty() && !last_was_space {
                cleaned.push(' ');
                last_was_space = true;
            }
            continue;
        }
        cleaned.push(ch);
        last_was_space = false;
    }

    let trimmed = cleaned.trim();
    let mut out = String::new();
    let mut codepoints = 0usize;
    for ch in trimmed.chars() {
        if codepoints >= MAX_MANUAL_NAME_CODEPOINTS {
            break;
        }
        if out.len() + ch.len_utf8() > MAX_MANUAL_NAME_BYTES {
            break;
        }
        out.push(ch);
        codepoints += 1;
    }
    let final_str = out.trim().to_string();
    if final_str.is_empty() {
        "Roblox".to_string()
    } else {
        final_str
    }
}

fn render_place_template(template: &str, place_name: &str) -> String {
    if template.contains("{place_name}") {
        template.replace("{place_name}", place_name)
    } else {
        template.to_string()
    }
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(MAX_SAFE_TIMESTAMP_MS as u128) as i64)
        .unwrap_or(1)
        .max(1)
}

fn build_micup_activity(
    activity_mode: &str,
    show_place_name: bool,
    show_elapsed_time: bool,
    text: &MicupTextSettings,
    phase: PresencePhase,
    place_name: &str,
    session_started_at_ms: i64,
    current_ms: i64,
) -> MicupGameActivity {
    let effective_now = current_ms.clamp(1, MAX_SAFE_TIMESTAMP_MS);
    let started_at =
        if phase == PresencePhase::Playing && show_elapsed_time && session_started_at_ms > 0 {
            session_started_at_ms.clamp(1, MAX_SAFE_TIMESTAMP_MS)
        } else {
            effective_now
        };

    if activity_mode == "catalog" {
        return MicupGameActivity::Catalog {
            game_id: MICUP_ROBLOX_CATALOG_ID.to_string(),
            started_at,
        };
    }

    match phase {
        PresencePhase::Browsing => MicupGameActivity::Manual {
            manual_name: sanitize_manual_name(&text.browsing),
            started_at,
        },
        PresencePhase::Joining => {
            if !show_place_name {
                if activity_mode == "auto" {
                    MicupGameActivity::Catalog {
                        game_id: MICUP_ROBLOX_CATALOG_ID.to_string(),
                        started_at,
                    }
                } else {
                    MicupGameActivity::Manual {
                        manual_name: sanitize_manual_name(&text.joining),
                        started_at,
                    }
                }
            } else if place_name.is_empty() {
                MicupGameActivity::Manual {
                    manual_name: sanitize_manual_name(&text.joining),
                    started_at,
                }
            } else {
                let rendered = render_place_template(&text.playing, place_name);
                MicupGameActivity::Manual {
                    manual_name: sanitize_manual_name(&rendered),
                    started_at,
                }
            }
        }
        PresencePhase::Playing => {
            if !show_place_name {
                if activity_mode == "auto" {
                    MicupGameActivity::Catalog {
                        game_id: MICUP_ROBLOX_CATALOG_ID.to_string(),
                        started_at,
                    }
                } else {
                    MicupGameActivity::Manual {
                        manual_name: "Roblox".to_string(),
                        started_at,
                    }
                }
            } else if !place_name.is_empty() {
                let rendered = render_place_template(&text.playing, place_name);
                MicupGameActivity::Manual {
                    manual_name: sanitize_manual_name(&rendered),
                    started_at,
                }
            } else if activity_mode == "auto" {
                MicupGameActivity::Catalog {
                    game_id: MICUP_ROBLOX_CATALOG_ID.to_string(),
                    started_at,
                }
            } else {
                MicupGameActivity::Manual {
                    manual_name: sanitize_manual_name(&text.unknown_place),
                    started_at,
                }
            }
        }
    }
}

fn expand_user_path(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

fn load_token_from_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("cannot open Micup token file {}: {}", path.display(), e))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat Micup token file {}: {}", path.display(), e))?;
    if !meta.is_file() {
        return Err(format!(
            "Micup token file {} is not a regular file",
            path.display()
        ));
    }
    let mut raw = Zeroizing::new(Vec::new());
    (&mut file)
        .take((MAX_TOKEN_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|e| format!("cannot read Micup token file {}: {}", path.display(), e))?;
    if raw.len() > MAX_TOKEN_FILE_BYTES {
        return Err("Micup token file exceeds maximum supported size".to_string());
    }
    let text = String::from_utf8(std::mem::take(&mut *raw))
        .map_err(|_| "Micup token file must be UTF-8 text".to_string())?;
    let text = Zeroizing::new(text);
    let trimmed = Zeroizing::new(text.trim_matches(|c| matches!(c, '\r' | '\n' | ' ' | '\t')).to_string());
    if !is_valid_micup_token(&trimmed) {
        return Err(
            "Micup token file does not contain a valid token (1..=256 visible bytes)"
                .to_string(),
        );
    }
    Ok(trimmed)
}

fn parse_pem_certificates(pem_bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(pem_bytes)
        .map_err(|_| "CA bundle must be valid UTF-8/ASCII PEM".to_string())?;
    let mut certs = Vec::new();
    let mut rest = text;
    while let Some(start_idx) = rest.find(BEGIN) {
        let after_begin = &rest[start_idx + BEGIN.len()..];
        let end_idx = after_begin
            .find(END)
            .ok_or_else(|| "unterminated PEM certificate block in CA bundle".to_string())?;
        let b64: String = after_begin[..end_idx]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = BASE64_STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| "invalid base64 certificate data in CA bundle".to_string())?;
        certs.push(CertificateDer::from(der));
        rest = &after_begin[end_idx + END.len()..];
    }
    Ok(certs)
}

fn build_tls_config(ca_bundle: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = ca_bundle {
        let mut file = File::open(path)
            .map_err(|e| format!("cannot open CA bundle {}: {}", path.display(), e))?;
        let mut buf = Vec::new();
        (&mut file)
            .take((MAX_CA_BUNDLE_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read CA bundle {}: {}", path.display(), e))?;
        if buf.len() > MAX_CA_BUNDLE_BYTES {
            return Err("CA bundle exceeds 4 MiB limit".to_string());
        }
        let certs = parse_pem_certificates(&buf)?;
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(format!(
                "no valid PEM certificates found in CA bundle {}",
                path.display()
            ));
        }
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cannot configure TLS versions: {}", e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn resolve_effective_status(
    configured: &str,
    other_session_visible: bool,
    server_user_status: Option<&str>,
) -> &'static str {
    match configured {
        "online" => "online",
        "idle" => "idle",
        "dnd" => "dnd",
        "invisible" => "invisible",
        _ => {
            if server_user_status == Some("invisible") || other_session_visible {
                "invisible"
            } else {
                "online"
            }
        }
    }
}

fn sessions_have_other_visible_session(sessions: &[Value], own_session_id: Option<&str>) -> bool {
    sessions.iter().any(|entry| {
        let Some(id) = entry.get("session_id").and_then(Value::as_str) else {
            return false;
        };
        if id == "all" || Some(id) == own_session_id {
            return false;
        }
        let status = entry
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("offline");
        matches!(status, "online" | "idle" | "dnd")
    })
}

enum GatewayStream {
    Plain(TcpStream),
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl GatewayStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.set_read_timeout(dur),
            Self::Tls(s) => s.sock.set_read_timeout(dur),
        }
    }
}

impl Read for GatewayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for GatewayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

fn connect_tcp_with_timeout(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {}:{}: {}", host, port, e))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("no addresses resolved for {}:{}", host, port));
    }
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, IO_CONNECT_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(IO_HANDSHAKE_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_HANDSHAKE_TIMEOUT));
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(format!(
        "TCP connect failed for {}:{}: {}",
        host,
        port,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn connect_via_http_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    let proxy_url = Url::parse(&proxy.url)
        .map_err(|e| format!("invalid proxy URL for Micup RPC: {}", e))?;
    if proxy_url.scheme() != "http" {
        return Err(format!(
            "Micup RPC currently supports direct connections or HTTP CONNECT proxies (got {}://)",
            proxy_url.scheme()
        ));
    }
    let proxy_host = proxy_url
        .host_str()
        .ok_or_else(|| "proxy URL missing host".to_string())?;
    let proxy_port = proxy_url.port_or_known_default().unwrap_or(8080);
    let mut stream = connect_tcp_with_timeout(proxy_host, proxy_port)?;

    let authority = if target_host.contains(':') {
        format!("[{}]:{}", target_host, target_port)
    } else {
        format!("{}:{}", target_host, target_port)
    };
    let mut req = Zeroizing::new(format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    ));
    if !proxy.username.is_empty() || !proxy.password.is_empty() {
        let raw_creds = Zeroizing::new(format!("{}:{}", proxy.username, &*proxy.password));
        let encoded = Zeroizing::new(BASE64_STANDARD.encode(raw_creds.as_bytes()));
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&encoded);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("failed to send proxy CONNECT: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush proxy CONNECT: {}", e))?;

    // Read single bytes until \r\n\r\n so we never over-read post-tunnel TLS bytes.
    let mut header_bytes = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    while header_bytes.len() < MAX_PROXY_CONNECT_HEADER_BYTES {
        let n = stream
            .read(&mut one)
            .map_err(|e| format!("failed reading proxy CONNECT response: {}", e))?;
        if n == 0 {
            return Err("proxy closed connection during CONNECT".to_string());
        }
        header_bytes.push(one[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header_bytes.ends_with(b"\r\n\r\n") {
        return Err("proxy CONNECT response headers exceeded limit".to_string());
    }
    let status_line = std::str::from_utf8(&header_bytes)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    let status_code = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code != 200 {
        return Err(format!("proxy CONNECT failed with status {}", status_code));
    }
    Ok(stream)
}

fn connect_gateway_websocket(
    gateway_url: &str,
    tls_config: &Arc<ClientConfig>,
    proxy: Option<&ProxyConfig>,
) -> Result<WebSocket<GatewayStream>, String> {
    let url = Url::parse(gateway_url).map_err(|e| format!("invalid gateway URL: {}", e))?;
    let host = url
        .host_str()
        .ok_or_else(|| "gateway URL missing host".to_string())?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let is_tls = url.scheme() == "wss";
    let port = url.port().unwrap_or(if is_tls { 443 } else { 80 });

    let tcp = match proxy {
        Some(p) if !is_loopback_host(host) => connect_via_http_proxy(p, host, port)?,
        _ => connect_tcp_with_timeout(host, port)?,
    };

    let stream = if is_tls {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| format!("invalid TLS server name: {}", host))?;
        let conn = ClientConnection::new(Arc::clone(tls_config), server_name)
            .map_err(|e| format!("cannot initialize TLS connection: {}", e))?;
        GatewayStream::Tls(StreamOwned::new(conn, tcp))
    } else {
        GatewayStream::Plain(tcp)
    };

    let uri: Uri = gateway_url
        .parse()
        .map_err(|e| format!("invalid WebSocket URI: {}", e))?;
    let request = ClientRequestBuilder::new(uri).with_header("User-Agent", "Mocktail/0.1 (Linux)");
    let (ws, _resp) = ws_client(request, stream)
        .map_err(|e| format!("WebSocket handshake failed: {}", e))?;
    let _ = ws.get_ref().set_read_timeout(Some(IO_POLL_READ_TIMEOUT));
    Ok(ws)
}

struct ActivityBucket {
    tokens: f64,
    last_refill: Instant,
}

impl ActivityBucket {
    fn new(now: Instant) -> Self {
        Self {
            tokens: ACTIVITY_BUCKET_CAPACITY,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens =
                (self.tokens + elapsed * ACTIVITY_BUCKET_REFILL_PER_SEC).min(ACTIVITY_BUCKET_CAPACITY);
            self.last_refill = now;
        }
    }

    fn delay_until_token(&mut self, now: Instant) -> Option<Duration> {
        self.refill(now);
        if self.tokens >= 1.0 {
            None
        } else {
            let needed = (1.0 - self.tokens) / ACTIVITY_BUCKET_REFILL_PER_SEC;
            Some(Duration::from_secs_f64(needed).max(Duration::from_millis(50)))
        }
    }

    fn consume(&mut self, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - 1.0).max(0.0);
    }
}

struct GatewayPersistentState {
    session_id: Option<String>,
    resume_gateway_url: Option<String>,
    seq: Option<u64>,
    should_resume: bool,
    server_user_status: Option<String>,
    other_session_visible: bool,
    fatal_auth_error: bool,
    reconnect_delay: Duration,
}

impl GatewayPersistentState {
    fn new() -> Self {
        Self {
            session_id: None,
            resume_gateway_url: None,
            seq: None,
            should_resume: false,
            server_user_status: None,
            other_session_visible: false,
            fatal_auth_error: false,
            reconnect_delay: INITIAL_RECONNECT_DELAY,
        }
    }

    fn clear_session(&mut self) {
        self.session_id = None;
        self.resume_gateway_url = None;
        self.seq = None;
        self.should_resume = false;
    }
}

fn send_json_frame(ws: &mut WebSocket<GatewayStream>, payload: &Value) -> Result<(), String> {
    let encoded =
        serde_json::to_string(payload).map_err(|e| format!("JSON encode error: {}", e))?;
    ws.send(Message::Text(encoded))
        .map_err(|e| format!("WebSocket send error: {}", e))?;
    ws.flush()
        .map_err(|e| format!("WebSocket flush error: {}", e))
}

fn build_identify_payload(config: &SessionConfig) -> Value {
    let initial_status = if config.status == "auto" {
        "invisible"
    } else {
        config.status.as_str()
    };
    json!({
        "op": 2,
        "d": {
            "token": &*config.token,
            "properties": {
                "os": "linux",
                "browser": "mocktail",
                "device": "mocktail",
            },
            "ignored_events": IGNORED_GATEWAY_EVENTS,
            "presence": {
                "status": initial_status,
                "afk": false,
                "mobile": false,
            }
        }
    })
}

fn build_resume_payload(config: &SessionConfig, session_id: &str, seq: Option<u64>) -> Value {
    json!({
        "op": 6,
        "d": {
            "token": &*config.token,
            "session_id": session_id,
            "seq": seq.unwrap_or(0),
        }
    })
}

fn build_presence_payload(status: &str, game_activity: Option<&MicupGameActivity>) -> Value {
    let activity_json = match game_activity {
        Some(a) => a.to_json_value(),
        None => Value::Null,
    };
    json!({
        "op": 3,
        "d": {
            "status": status,
            "afk": false,
            "mobile": false,
            "game_activity": activity_json,
        }
    })
}

fn is_non_resumable_close(code: u16) -> bool {
    matches!(code, 4004 | 4007 | 4009 | 4010 | 4011 | 4012 | 4013 | 4014)
}

#[derive(PartialEq, Eq)]
enum ConnectionOutcome {
    Stopped,
    ReconnectImmediate,
    ReconnectBackoff,
    FatalAuth,
}

fn wait_for_hello(
    ws: &mut WebSocket<GatewayStream>,
    shared: &SharedSessionState,
) -> Result<Duration, ConnectionOutcome> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, stopping) = shared.snapshot();
        if stopping {
            return Err(ConnectionOutcome::Stopped);
        }
        if Instant::now() >= deadline {
            eprintln!("  [micup-rpc] timed out waiting for Gateway HELLO");
            return Err(ConnectionOutcome::ReconnectBackoff);
        }
        match ws.read() {
            Ok(Message::Text(text)) => {
                if let Ok(val) = serde_json::from_str::<Value>(&text) {
                    if val.get("op").and_then(Value::as_u64) == Some(10) {
                        let interval_ms = val
                            .pointer("/d/heartbeat_interval")
                            .and_then(Value::as_u64)
                            .unwrap_or(45_000)
                            .clamp(1_000, 120_000);
                        return Ok(Duration::from_millis(interval_ms));
                    }
                }
            }
            Ok(Message::Close(frame)) => {
                let code = frame.as_ref().map(|f| u16::from(f.code)).unwrap_or(0);
                eprintln!("  [micup-rpc] Gateway closed before HELLO (code={})", code);
                if code == 4004 {
                    return Err(ConnectionOutcome::FatalAuth);
                }
                return Err(ConnectionOutcome::ReconnectBackoff);
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
            Ok(Message::Binary(_)) => {}
            Err(WsError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(err) => {
                eprintln!("  [micup-rpc] Gateway read error before HELLO: {}", err);
                return Err(ConnectionOutcome::ReconnectBackoff);
            }
        }
    }
}

fn run_single_connection(
    config: &SessionConfig,
    tls_config: &Arc<ClientConfig>,
    shared: &SharedSessionState,
    state: &mut GatewayPersistentState,
) -> ConnectionOutcome {
    let target_url = if state.should_resume {
        state
            .resume_gateway_url
            .as_deref()
            .filter(|u| normalize_gateway_url(u).is_some())
            .unwrap_or(config.gateway_url.as_str())
    } else {
        config.gateway_url.as_str()
    };

    let mut ws = match connect_gateway_websocket(target_url, tls_config, config.proxy.as_ref()) {
        Ok(ws) => ws,
        Err(err) => {
            eprintln!("  [micup-rpc] Gateway connect error: {}", err);
            return ConnectionOutcome::ReconnectBackoff;
        }
    };

    let heartbeat_interval = match wait_for_hello(&mut ws, shared) {
        Ok(d) => d,
        Err(outcome) => return outcome,
    };

    if state.should_resume {
        if let Some(ref sid) = state.session_id {
            let resume = build_resume_payload(config, sid, state.seq);
            if let Err(err) = send_json_frame(&mut ws, &resume) {
                eprintln!("  [micup-rpc] failed to send RESUME: {}", err);
                return ConnectionOutcome::ReconnectBackoff;
            }
        } else {
            state.clear_session();
            let identify = build_identify_payload(config);
            if let Err(err) = send_json_frame(&mut ws, &identify) {
                eprintln!("  [micup-rpc] failed to send IDENTIFY: {}", err);
                return ConnectionOutcome::ReconnectBackoff;
            }
        }
    } else {
        let identify = build_identify_payload(config);
        if let Err(err) = send_json_frame(&mut ws, &identify) {
            eprintln!("  [micup-rpc] failed to send IDENTIFY: {}", err);
            return ConnectionOutcome::ReconnectBackoff;
        }
    }

    let mut ready = false;
    let mut published_revision: u64 = 0;
    let mut last_sent_status: Option<&'static str> = None;
    let mut last_sent_activity: Option<MicupGameActivity> = None;
    let mut next_heartbeat = Instant::now() + heartbeat_interval;
    let mut awaiting_heartbeat_ack = false;
    let mut last_heartbeat_sent = Instant::now();
    let mut last_lease_renew = Instant::now();
    let mut presence_timestamps: VecDeque<Instant> = VecDeque::new();
    let mut activity_bucket = ActivityBucket::new(Instant::now());
    let mut rate_limit_retry_after: Option<Instant> = None;

    loop {
        let (desired, stopping) = shared.snapshot();
        if stopping {
            if ready {
                let effective_status = last_sent_status.unwrap_or_else(|| {
                    resolve_effective_status(
                        &config.status,
                        state.other_session_visible,
                        state.server_user_status.as_deref(),
                    )
                });
                let clear_payload = build_presence_payload(effective_status, None);
                let _ = send_json_frame(&mut ws, &clear_payload);
            }
            let _ = ws.close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: std::borrow::Cow::Borrowed("client shutdown"),
            }));
            let _ = ws.flush();
            return ConnectionOutcome::Stopped;
        }

        let now = Instant::now();

        if awaiting_heartbeat_ack
            && now.saturating_duration_since(last_heartbeat_sent) >= heartbeat_interval
        {
            eprintln!("  [micup-rpc] heartbeat ACK timeout; reconnecting");
            return ConnectionOutcome::ReconnectImmediate;
        }

        if now >= next_heartbeat {
            let hb = json!({ "op": 1, "d": state.seq });
            if let Err(err) = send_json_frame(&mut ws, &hb) {
                eprintln!("  [micup-rpc] failed sending heartbeat: {}", err);
                return ConnectionOutcome::ReconnectImmediate;
            }
            awaiting_heartbeat_ack = true;
            last_heartbeat_sent = now;
            next_heartbeat = now + heartbeat_interval;
        }

        if ready {
            let effective_status = resolve_effective_status(
                &config.status,
                state.other_session_visible,
                state.server_user_status.as_deref(),
            );
            let lease_due = now.saturating_duration_since(last_lease_renew) >= LEASE_RENEW_INTERVAL;
            let no_elapsed_refresh_due = !config.show_elapsed_time
                && desired.phase == PresencePhase::Playing
                && now.saturating_duration_since(last_lease_renew) >= NO_ELAPSED_REFRESH_INTERVAL;
            let status_changed = last_sent_status != Some(effective_status);
            let revision_changed = published_revision != desired.revision;

            if (revision_changed || status_changed || lease_due || no_elapsed_refresh_due)
                && rate_limit_retry_after.map(|t| now >= t).unwrap_or(true)
            {
                let activity = build_micup_activity(
                    &config.activity_mode,
                    config.show_place_name,
                    config.show_elapsed_time,
                    &config.text,
                    desired.phase,
                    &desired.place_name,
                    desired.started_at_ms,
                    now_epoch_ms(),
                );

                while let Some(&front) = presence_timestamps.front() {
                    if now.saturating_duration_since(front) >= PRESENCE_RATE_WINDOW {
                        presence_timestamps.pop_front();
                    } else {
                        break;
                    }
                }
                let activity_identity_changed = last_sent_activity
                    .as_ref()
                    .map(|prev| prev.identity_key() != activity.identity_key())
                    .unwrap_or(true);
                let bucket_wait = if activity_identity_changed {
                    activity_bucket.delay_until_token(now)
                } else {
                    None
                };

                if presence_timestamps.len() >= PRESENCE_RATE_LIMIT {
                    let wait_until =
                        *presence_timestamps.front().unwrap() + PRESENCE_RATE_WINDOW;
                    rate_limit_retry_after = Some(wait_until);
                } else if let Some(wait_dur) = bucket_wait {
                    rate_limit_retry_after = Some(now + wait_dur);
                } else {
                    let payload = build_presence_payload(effective_status, Some(&activity));
                    if let Err(err) = send_json_frame(&mut ws, &payload) {
                        eprintln!("  [micup-rpc] failed sending PRESENCE_UPDATE: {}", err);
                        return ConnectionOutcome::ReconnectImmediate;
                    }
                    presence_timestamps.push_back(now);
                    if activity_identity_changed {
                        activity_bucket.consume(now);
                    }
                    last_sent_status = Some(effective_status);
                    last_sent_activity = Some(activity);
                    published_revision = desired.revision;
                    last_lease_renew = now;
                    rate_limit_retry_after = None;
                }
            }
        }

        match ws.read() {
            Ok(Message::Text(text)) => {
                if let Ok(val) = serde_json::from_str::<Value>(&text) {
                    if let Some(s) = val.get("s").and_then(Value::as_u64) {
                        state.seq = Some(s);
                    }
                    let op = val.get("op").and_then(Value::as_u64).unwrap_or(u64::MAX);
                    match op {
                        0 => {
                            let event = val.get("t").and_then(Value::as_str).unwrap_or("");
                            match event {
                                "READY" => {
                                    if let Some(sid) =
                                        val.pointer("/d/session_id").and_then(Value::as_str)
                                    {
                                        state.session_id = Some(sid.to_string());
                                    }
                                    if let Some(url) = val
                                        .pointer("/d/resume_gateway_url")
                                        .and_then(Value::as_str)
                                    {
                                        if let Some(norm) = normalize_gateway_url(url) {
                                            state.resume_gateway_url = Some(norm);
                                        }
                                    }
                                    if let Some(st) = val
                                        .pointer("/d/user_settings/status")
                                        .and_then(Value::as_str)
                                    {
                                        state.server_user_status = Some(st.to_string());
                                    }
                                    if let Some(sessions) =
                                        val.pointer("/d/sessions").and_then(Value::as_array)
                                    {
                                        state.other_session_visible =
                                            sessions_have_other_visible_session(
                                                sessions,
                                                state.session_id.as_deref(),
                                            );
                                    }
                                    state.should_resume = state.session_id.is_some();
                                    state.reconnect_delay = INITIAL_RECONNECT_DELAY;
                                    ready = true;
                                    published_revision = 0;
                                    eprintln!("  [micup-rpc] connected and READY on Micup Gateway");
                                }
                                "RESUMED" => {
                                    state.reconnect_delay = INITIAL_RECONNECT_DELAY;
                                    ready = true;
                                    published_revision = 0;
                                    eprintln!("  [micup-rpc] resumed Micup Gateway session");
                                }
                                "SESSIONS_REPLACE" => {
                                    if let Some(sessions) = val.get("d").and_then(Value::as_array) {
                                        state.other_session_visible =
                                            sessions_have_other_visible_session(
                                                sessions,
                                                state.session_id.as_deref(),
                                            );
                                    }
                                }
                                "USER_SETTINGS_UPDATE" => {
                                    if let Some(st) =
                                        val.pointer("/d/status").and_then(Value::as_str)
                                    {
                                        state.server_user_status = Some(st.to_string());
                                    }
                                }
                                _ => {}
                            }
                        }
                        1 => {
                            let hb = json!({ "op": 1, "d": state.seq });
                            if let Err(err) = send_json_frame(&mut ws, &hb) {
                                eprintln!(
                                    "  [micup-rpc] failed replying to server heartbeat: {}",
                                    err
                                );
                                return ConnectionOutcome::ReconnectImmediate;
                            }
                        }
                        7 => {
                            eprintln!("  [micup-rpc] Gateway requested RECONNECT");
                            return ConnectionOutcome::ReconnectImmediate;
                        }
                        9 => {
                            let resumable =
                                val.get("d").and_then(Value::as_bool).unwrap_or(false);
                            if !resumable {
                                state.clear_session();
                            }
                            eprintln!(
                                "  [micup-rpc] Gateway INVALID_SESSION (resumable={})",
                                resumable
                            );
                            return if resumable {
                                ConnectionOutcome::ReconnectImmediate
                            } else {
                                ConnectionOutcome::ReconnectBackoff
                            };
                        }
                        11 => {
                            awaiting_heartbeat_ack = false;
                        }
                        12 => {
                            let code = val
                                .pointer("/d/code")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown");
                            let msg = val
                                .pointer("/d/message")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            eprintln!("  [micup-rpc] Gateway error code={} msg={}", code, msg);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Close(frame)) => {
                let code = frame.as_ref().map(|f| u16::from(f.code)).unwrap_or(0);
                eprintln!("  [micup-rpc] Gateway closed connection (code={})", code);
                if code == 4004 {
                    state.clear_session();
                    return ConnectionOutcome::FatalAuth;
                }
                if is_non_resumable_close(code) {
                    state.clear_session();
                    return ConnectionOutcome::ReconnectBackoff;
                }
                return ConnectionOutcome::ReconnectImmediate;
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
            Ok(Message::Binary(_)) => {}
            Err(WsError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(err) => {
                eprintln!("  [micup-rpc] Gateway socket error: {}", err);
                return ConnectionOutcome::ReconnectBackoff;
            }
        }
    }
}

fn run_gateway_worker(
    config: SessionConfig,
    tls_config: Arc<ClientConfig>,
    shared: Arc<SharedSessionState>,
) {
    let mut state = GatewayPersistentState::new();
    loop {
        let (_, stopping) = shared.snapshot();
        if stopping {
            break;
        }
        if state.fatal_auth_error {
            if !shared.wait_until(u64::MAX, Duration::from_secs(60)) {
                break;
            }
            continue;
        }

        let outcome = run_single_connection(&config, &tls_config, &shared, &mut state);
        match outcome {
            ConnectionOutcome::Stopped => break,
            ConnectionOutcome::FatalAuth => {
                eprintln!(
                    "  [micup-rpc] authentication failed (close 4004); check configured Micup token"
                );
                state.fatal_auth_error = true;
            }
            ConnectionOutcome::ReconnectImmediate => {
                let (desired, _) = shared.snapshot();
                if !shared.wait_until(desired.revision, Duration::from_millis(250)) {
                    break;
                }
            }
            ConnectionOutcome::ReconnectBackoff => {
                let delay = state.reconnect_delay;
                state.reconnect_delay = (delay * 2).min(MAX_RECONNECT_DELAY);
                let (desired, _) = shared.snapshot();
                if !shared.wait_until(desired.revision, delay) {
                    break;
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_is_valid_status(ptr: *const c_char, len: usize) -> i32 {
    match unsafe { slice_to_str(ptr, len) } {
        Some(s) if is_valid_micup_status(s) => 1,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_is_valid_activity_mode(
    ptr: *const c_char,
    len: usize,
) -> i32 {
    match unsafe { slice_to_str(ptr, len) } {
        Some(s) if is_valid_micup_activity_mode(s) => 1,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_is_valid_gateway_url(
    ptr: *const c_char,
    len: usize,
) -> i32 {
    match unsafe { slice_to_str(ptr, len) } {
        Some(s) if normalize_gateway_url(s).is_some() => 1,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_is_valid_token(ptr: *const c_char, len: usize) -> i32 {
    match unsafe { slice_to_str(ptr, len) } {
        Some(s) if is_valid_micup_token(s) => 1,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_is_valid_text(
    ptr: *const c_char,
    len: usize,
    max_bytes: usize,
) -> i32 {
    match unsafe { slice_to_str(ptr, len) } {
        Some(s) if is_valid_micup_text(s, max_bytes) => 1,
        _ => 0,
    }
}

/// Builds a Micup `game_activity` JSON object for tests or inspection.
#[no_mangle]
pub extern "C" fn mocktail_rust_micup_build_activity_json(
    activity_mode_ptr: *const c_char,
    activity_mode_len: usize,
    show_place_name: i32,
    show_elapsed_time: i32,
    text_browsing_ptr: *const c_char,
    text_browsing_len: usize,
    text_joining_ptr: *const c_char,
    text_joining_len: usize,
    text_playing_ptr: *const c_char,
    text_playing_len: usize,
    text_unknown_place_ptr: *const c_char,
    text_unknown_place_len: usize,
    phase: i32,
    place_name_ptr: *const c_char,
    place_name_len: usize,
    started_at_ms: i64,
    current_ms: i64,
    out_json: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let mode = unsafe { slice_to_str(activity_mode_ptr, activity_mode_len) }.unwrap_or("auto");
    let text = MicupTextSettings {
        browsing: unsafe { slice_to_str(text_browsing_ptr, text_browsing_len) }
            .filter(|s| !s.is_empty())
            .unwrap_or("Browsing Roblox")
            .to_string(),
        joining: unsafe { slice_to_str(text_joining_ptr, text_joining_len) }
            .filter(|s| !s.is_empty())
            .unwrap_or("Joining an experience")
            .to_string(),
        playing: unsafe { slice_to_str(text_playing_ptr, text_playing_len) }
            .filter(|s| !s.is_empty())
            .unwrap_or("{place_name}")
            .to_string(),
        unknown_place: unsafe { slice_to_str(text_unknown_place_ptr, text_unknown_place_len) }
            .filter(|s| !s.is_empty())
            .unwrap_or("Unknown experience")
            .to_string(),
    };
    let place_name = unsafe { slice_to_str(place_name_ptr, place_name_len) }.unwrap_or("");
    let activity = build_micup_activity(
        mode,
        show_place_name != 0,
        show_elapsed_time != 0,
        &text,
        PresencePhase::from_i32(phase),
        place_name,
        started_at_ms,
        current_ms,
    );
    let encoded = match serde_json::to_string(&activity.to_json_value()) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    if out_json.is_null() || encoded.len() >= out_cap {
        return -2;
    }
    copy_c_str(out_json, out_cap, &encoded);
    if !out_len.is_null() {
        unsafe {
            *out_len = encoded.len();
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_session_start(
    config: *const MocktailRustMicupConfig,
    out_session: *mut *mut MocktailRustMicupSession,
    out_detail: *mut c_char,
    detail_cap: usize,
) -> i32 {
    if out_session.is_null() {
        copy_c_str(out_detail, detail_cap, "null out_session pointer");
        return -1;
    }
    unsafe {
        *out_session = std::ptr::null_mut();
    }
    if config.is_null() {
        copy_c_str(out_detail, detail_cap, "null Micup configuration");
        return -1;
    }
    let cfg = unsafe { &*config };
    if cfg.enabled == 0 {
        copy_c_str(out_detail, detail_cap, "disabled by runtime policy");
        return 0;
    }

    let raw_gateway = unsafe { slice_to_str(cfg.gateway_url_ptr, cfg.gateway_url_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_MICUP_GATEWAY_URL);
    let Some(gateway_url) = normalize_gateway_url(raw_gateway) else {
        copy_c_str(out_detail, detail_cap, "invalid Micup gateway URL");
        return -1;
    };

    let status = unsafe { slice_to_str(cfg.status_ptr, cfg.status_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or("auto");
    if !is_valid_micup_status(status) {
        copy_c_str(out_detail, detail_cap, "invalid Micup status policy");
        return -1;
    }

    let activity_mode = unsafe { slice_to_str(cfg.activity_mode_ptr, cfg.activity_mode_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or("auto");
    if !is_valid_micup_activity_mode(activity_mode) {
        copy_c_str(
            out_detail,
            detail_cap,
            "invalid Micup activity_mode policy",
        );
        return -1;
    }

    let inline_token = unsafe { slice_to_str(cfg.token_ptr, cfg.token_len) }.unwrap_or("");
    let token_file_raw =
        unsafe { slice_to_str(cfg.token_file_ptr, cfg.token_file_len) }.unwrap_or("");

    let token: Zeroizing<String> = if !inline_token.is_empty() {
        if !is_valid_micup_token(inline_token) {
            copy_c_str(
                out_detail,
                detail_cap,
                "invalid Micup token (must be 1..=256 visible bytes)",
            );
            return -1;
        }
        Zeroizing::new(inline_token.to_string())
    } else if !token_file_raw.is_empty() {
        let expanded = expand_user_path(token_file_raw);
        match load_token_from_file(&expanded) {
            Ok(t) => t,
            Err(err) => {
                copy_c_str(out_detail, detail_cap, &err);
                return -1;
            }
        }
    } else {
        copy_c_str(
            out_detail,
            detail_cap,
            "no Micup account token configured (set token or token_file)",
        );
        return -1;
    };

    let ca_bundle = unsafe { slice_to_str(cfg.ca_bundle_ptr, cfg.ca_bundle_len) }
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let tls_config = match build_tls_config(ca_bundle.as_deref()) {
        Ok(c) => c,
        Err(err) => {
            copy_c_str(out_detail, detail_cap, &err);
            return -1;
        }
    };

    let proxy_url = unsafe { slice_to_str(cfg.proxy_url_ptr, cfg.proxy_url_len) }.unwrap_or("");
    let proxy = if proxy_url.is_empty() {
        None
    } else {
        Some(ProxyConfig {
            url: proxy_url.to_string(),
            username: unsafe { slice_to_str(cfg.proxy_username_ptr, cfg.proxy_username_len) }
                .unwrap_or("")
                .to_string(),
            password: Zeroizing::new(
                unsafe { slice_to_str(cfg.proxy_password_ptr, cfg.proxy_password_len) }
                    .unwrap_or("")
                    .to_string(),
            ),
        })
    };

    let defaults = MicupTextSettings::default();
    let text = MicupTextSettings {
        browsing: unsafe { slice_to_str(cfg.text_browsing_ptr, cfg.text_browsing_len) }
            .filter(|s| is_valid_micup_text(s, 128))
            .unwrap_or(&defaults.browsing)
            .to_string(),
        joining: unsafe { slice_to_str(cfg.text_joining_ptr, cfg.text_joining_len) }
            .filter(|s| is_valid_micup_text(s, 128))
            .unwrap_or(&defaults.joining)
            .to_string(),
        playing: unsafe { slice_to_str(cfg.text_playing_ptr, cfg.text_playing_len) }
            .filter(|s| is_valid_micup_text(s, 128))
            .unwrap_or(&defaults.playing)
            .to_string(),
        unknown_place: unsafe {
            slice_to_str(cfg.text_unknown_place_ptr, cfg.text_unknown_place_len)
        }
        .filter(|s| is_valid_micup_text(s, 128))
        .unwrap_or(&defaults.unknown_place)
        .to_string(),
    };

    let session_cfg = SessionConfig {
        gateway_url,
        token,
        status: status.to_string(),
        activity_mode: activity_mode.to_string(),
        show_place_name: cfg.show_place_name != 0,
        show_elapsed_time: cfg.show_elapsed_time != 0,
        text,
        proxy,
    };

    let shared = Arc::new(SharedSessionState::new());
    let worker_shared = Arc::clone(&shared);
    let worker = match thread::Builder::new()
        .name("mocktail-micup".to_string())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || run_gateway_worker(session_cfg, tls_config, worker_shared))
    {
        Ok(handle) => handle,
        Err(err) => {
            copy_c_str(
                out_detail,
                detail_cap,
                &format!("could not start Micup RPC worker: {}", err),
            );
            return -1;
        }
    };

    let boxed = Box::new(MocktailRustMicupSession {
        shared,
        worker: Some(worker),
    });
    unsafe {
        *out_session = Box::into_raw(boxed);
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_session_update(
    session: *mut MocktailRustMicupSession,
    phase: i32,
    place_id: i64,
    place_name_ptr: *const c_char,
    place_name_len: usize,
    started_at_ms: i64,
    revision: u64,
) -> i32 {
    if session.is_null() {
        return -1;
    }
    let place_name = match unsafe { slice_to_str(place_name_ptr, place_name_len) } {
        Some(s) => s.to_string(),
        None => return -1,
    };
    let s = unsafe { &*session };
    s.shared.update(DesiredPresence {
        phase: PresencePhase::from_i32(phase),
        place_id,
        place_name,
        started_at_ms,
        revision,
    });
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_micup_session_stop(session: *mut MocktailRustMicupSession) {
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
    use std::ffi::CStr;
    use std::net::TcpListener;
    use tungstenite::accept;

    #[test]
    fn sanitize_manual_name_strips_forbidden_chars_and_bounds_length() {
        assert_eq!(sanitize_manual_name("  Arsenal \u{FE0F}  "), "Arsenal");
        assert_eq!(sanitize_manual_name("Line1\nLine2\tGo\u{200B}!"), "Line1 Line2 Go!");
        assert_eq!(sanitize_manual_name("\u{0007}\u{200B}\u{FEFF}"), "Roblox");
        let long_title = "a".repeat(80);
        assert_eq!(sanitize_manual_name(&long_title).chars().count(), 64);
        let multi_byte = "ö".repeat(70);
        let sanitized = sanitize_manual_name(&multi_byte);
        assert_eq!(sanitized.chars().count(), 64);
        assert!(sanitized.len() <= 256);
    }

    #[test]
    fn normalize_gateway_url_validates_scheme_and_appends_query() {
        assert_eq!(
            normalize_gateway_url(DEFAULT_MICUP_GATEWAY_URL).as_deref(),
            Some("wss://micup.gg/gateway?v=1&encoding=json")
        );
        assert_eq!(
            normalize_gateway_url("ws://127.0.0.1:42000/").as_deref(),
            Some("ws://127.0.0.1:42000/?v=1&encoding=json")
        );
        assert_eq!(
            normalize_gateway_url("ws://localhost:9000/gw").as_deref(),
            Some("ws://localhost:9000/gw?v=1&encoding=json")
        );
        assert!(normalize_gateway_url("ws://micup.gg/gateway").is_none());
        assert!(normalize_gateway_url("https://micup.gg/gateway").is_none());
        assert!(normalize_gateway_url("wss://user:pass@micup.gg/gateway").is_none());
        assert!(normalize_gateway_url("wss://micup.gg/gateway#frag").is_none());
    }

    #[test]
    fn resolve_effective_status_respects_other_sessions_and_user_settings() {
        assert_eq!(resolve_effective_status("online", true, Some("invisible")), "online");
        assert_eq!(resolve_effective_status("auto", false, Some("online")), "online");
        assert_eq!(resolve_effective_status("auto", true, Some("online")), "invisible");
        assert_eq!(resolve_effective_status("auto", false, Some("invisible")), "invisible");
        assert_eq!(resolve_effective_status("auto", false, None), "online");
    }

    #[test]
    fn build_micup_activity_handles_modes_and_elapsed_time() {
        let text = MicupTextSettings::default();
        let browsing = build_micup_activity(
            "auto",
            true,
            true,
            &text,
            PresencePhase::Browsing,
            "",
            0,
            1_700_000_000_000,
        );
        assert_eq!(
            browsing,
            MicupGameActivity::Manual {
                manual_name: "Browsing Roblox".to_string(),
                started_at: 1_700_000_000_000,
            }
        );

        let playing_auto = build_micup_activity(
            "auto",
            true,
            true,
            &text,
            PresencePhase::Playing,
            "Brookhaven RP \u{FE0F}",
            1_699_999_000_000,
            1_700_000_000_000,
        );
        assert_eq!(
            playing_auto,
            MicupGameActivity::Manual {
                manual_name: "Brookhaven RP".to_string(),
                started_at: 1_699_999_000_000,
            }
        );

        let playing_hidden_place = build_micup_activity(
            "auto",
            false,
            false,
            &text,
            PresencePhase::Playing,
            "Brookhaven RP",
            1_699_999_000_000,
            1_700_000_000_000,
        );
        assert_eq!(
            playing_hidden_place,
            MicupGameActivity::Catalog {
                game_id: "roblox".to_string(),
                started_at: 1_700_000_000_000,
            }
        );
    }

    #[test]
    fn gateway_session_end_to_end_identify_presence_sessions_replace_and_clear() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let ws_url = format!("ws://127.0.0.1:{}/gateway", port);

        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let mut ws = accept(tcp).expect("ws accept");

            // 1. Send HELLO (Op 10)
            ws.send(Message::Text(
                json!({ "op": 10, "d": { "heartbeat_interval": 30000 } }).to_string(),
            ))
            .expect("send HELLO");

            // 2. Expect IDENTIFY (Op 2) with initial invisible status (mode=auto)
            let identify_msg = ws.read().expect("read identify");
            let identify: Value = serde_json::from_str(identify_msg.to_text().unwrap()).unwrap();
            assert_eq!(identify["op"], 2);
            assert_eq!(identify["d"]["token"], "test-micup-token-secret");
            assert_eq!(identify["d"]["presence"]["status"], "invisible");

            // 3. Send READY with NO other visible session -> "auto" switches to "online"
            ws.send(Message::Text(
                json!({
                    "op": 0,
                    "s": 1,
                    "t": "READY",
                    "d": {
                        "session_id": "sess-mocktail",
                        "user_settings": { "status": "online" },
                        "sessions": [
                            { "session_id": "sess-mocktail", "status": "invisible" }
                        ]
                    }
                })
                .to_string(),
            ))
            .expect("send READY");

            // 4. Expect PRESENCE_UPDATE browsing
            let browsing_msg = ws.read().expect("read browsing");
            let browsing: Value = serde_json::from_str(browsing_msg.to_text().unwrap()).unwrap();
            assert_eq!(browsing["op"], 3);
            assert_eq!(browsing["d"]["status"], "online");
            assert_eq!(browsing["d"]["game_activity"]["manual_name"], "Browsing Roblox");

            // 5. Expect PRESENCE_UPDATE playing Arsenal
            let playing_msg = ws.read().expect("read playing");
            let playing: Value = serde_json::from_str(playing_msg.to_text().unwrap()).unwrap();
            assert_eq!(playing["op"], 3);
            assert_eq!(playing["d"]["status"], "online");
            assert_eq!(playing["d"]["game_activity"]["manual_name"], "Arsenal");
            assert_eq!(playing["d"]["game_activity"]["started_at"], 1_700_000_000_000_i64);

            // 6. Simulate Desktop login -> SESSIONS_REPLACE with another visible session
            ws.send(Message::Text(
                json!({
                    "op": 0,
                    "s": 2,
                    "t": "SESSIONS_REPLACE",
                    "d": [
                        { "session_id": "all", "status": "dnd" },
                        { "session_id": "sess-desktop", "status": "dnd" },
                        { "session_id": "sess-mocktail", "status": "online" }
                    ]
                })
                .to_string(),
            ))
            .expect("send SESSIONS_REPLACE");

            // Expect Mocktail auto-yielding to invisible while preserving activity
            let yielded_msg = ws.read().expect("read yielded");
            let yielded: Value = serde_json::from_str(yielded_msg.to_text().unwrap()).unwrap();
            assert_eq!(yielded["op"], 3);
            assert_eq!(yielded["d"]["status"], "invisible");
            assert_eq!(yielded["d"]["game_activity"]["manual_name"], "Arsenal");

            // 7. Expect activity clear before shutdown Close
            let clear_msg = ws.read().expect("read clear");
            let clear_val: Value = serde_json::from_str(clear_msg.to_text().unwrap()).unwrap();
            assert_eq!(clear_val["op"], 3);
            assert!(clear_val["d"]["game_activity"].is_null());

            let close_msg = ws.read().expect("read close");
            assert!(matches!(close_msg, Message::Close(_)));
        });

        let token = "test-micup-token-secret";
        let status = "auto";
        let mode = "auto";
        let cfg = MocktailRustMicupConfig {
            gateway_url_ptr: ws_url.as_ptr() as *const c_char,
            gateway_url_len: ws_url.len(),
            token_ptr: token.as_ptr() as *const c_char,
            token_len: token.len(),
            token_file_ptr: std::ptr::null(),
            token_file_len: 0,
            status_ptr: status.as_ptr() as *const c_char,
            status_len: status.len(),
            activity_mode_ptr: mode.as_ptr() as *const c_char,
            activity_mode_len: mode.len(),
            text_browsing_ptr: std::ptr::null(),
            text_browsing_len: 0,
            text_joining_ptr: std::ptr::null(),
            text_joining_len: 0,
            text_playing_ptr: std::ptr::null(),
            text_playing_len: 0,
            text_unknown_place_ptr: std::ptr::null(),
            text_unknown_place_len: 0,
            ca_bundle_ptr: std::ptr::null(),
            ca_bundle_len: 0,
            proxy_url_ptr: std::ptr::null(),
            proxy_url_len: 0,
            proxy_username_ptr: std::ptr::null(),
            proxy_username_len: 0,
            proxy_password_ptr: std::ptr::null(),
            proxy_password_len: 0,
            enabled: 1,
            show_place_name: 1,
            show_elapsed_time: 1,
        };
        let mut session_ptr: *mut MocktailRustMicupSession = std::ptr::null_mut();
        let mut detail_buf = [0 as c_char; 256];
        let rc = mocktail_rust_micup_session_start(
            &cfg,
            &mut session_ptr,
            detail_buf.as_mut_ptr(),
            detail_buf.len(),
        );
        assert_eq!(rc, 0);
        assert!(!session_ptr.is_null());

        // Allow browsing publish, then transition to playing, allow SESSIONS_REPLACE yield, then stop.
        thread::sleep(Duration::from_millis(200));
        let place = "Arsenal";
        assert_eq!(
            mocktail_rust_micup_session_update(
                session_ptr,
                2,
                286090429,
                place.as_ptr() as *const c_char,
                place.len(),
                1_700_000_000_000,
                2,
            ),
            0
        );
        thread::sleep(Duration::from_millis(250));
        mocktail_rust_micup_session_stop(session_ptr);
        server_thread.join().expect("mock gateway server finished");
    }

    #[test]
    fn start_fails_cleanly_without_token_and_loads_trimmed_token_file() {
        let dir = std::env::temp_dir().join(format!(
            "mocktail_micup_token_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let token_path = dir.join("token.txt");
        std::fs::write(&token_path, "  file-secret-token  \n").unwrap();
        let loaded = load_token_from_file(&token_path).expect("load token file");
        assert_eq!(&*loaded, "file-secret-token");
        let _ = std::fs::remove_dir_all(&dir);

        let url = DEFAULT_MICUP_GATEWAY_URL;
        let cfg = MocktailRustMicupConfig {
            gateway_url_ptr: url.as_ptr() as *const c_char,
            gateway_url_len: url.len(),
            token_ptr: std::ptr::null(),
            token_len: 0,
            token_file_ptr: std::ptr::null(),
            token_file_len: 0,
            status_ptr: std::ptr::null(),
            status_len: 0,
            activity_mode_ptr: std::ptr::null(),
            activity_mode_len: 0,
            text_browsing_ptr: std::ptr::null(),
            text_browsing_len: 0,
            text_joining_ptr: std::ptr::null(),
            text_joining_len: 0,
            text_playing_ptr: std::ptr::null(),
            text_playing_len: 0,
            text_unknown_place_ptr: std::ptr::null(),
            text_unknown_place_len: 0,
            ca_bundle_ptr: std::ptr::null(),
            ca_bundle_len: 0,
            proxy_url_ptr: std::ptr::null(),
            proxy_url_len: 0,
            proxy_username_ptr: std::ptr::null(),
            proxy_username_len: 0,
            proxy_password_ptr: std::ptr::null(),
            proxy_password_len: 0,
            enabled: 1,
            show_place_name: 1,
            show_elapsed_time: 1,
        };
        let mut session_ptr: *mut MocktailRustMicupSession = std::ptr::null_mut();
        let mut detail_buf = [0 as c_char; 256];
        let rc = mocktail_rust_micup_session_start(
            &cfg,
            &mut session_ptr,
            detail_buf.as_mut_ptr(),
            detail_buf.len(),
        );
        assert_eq!(rc, -1);
        assert!(session_ptr.is_null());
        let detail = unsafe { CStr::from_ptr(detail_buf.as_ptr()) }.to_string_lossy();
        assert!(detail.contains("token"));
    }

    #[test]
    fn gateway_handles_reconnect_resume_heartbeat_and_4004_auth_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let ws_url = format!("ws://127.0.0.1:{}/gateway", port);

        let server_thread = thread::spawn(move || {
            // Connection 1: IDENTIFY -> READY -> server sends Op 1 heartbeat & Op 7 RECONNECT
            let (tcp1, _) = listener.accept().expect("accept1");
            let mut ws1 = accept(tcp1).expect("ws1");
            ws1.send(Message::Text(
                json!({ "op": 10, "d": { "heartbeat_interval": 30000 } }).to_string(),
            ))
            .unwrap();
            let id_msg: Value =
                serde_json::from_str(ws1.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(id_msg["op"], 2);

            ws1.send(Message::Text(
                json!({
                    "op": 0,
                    "s": 7,
                    "t": "READY",
                    "d": {
                        "session_id": "resume-sid-1",
                        "sessions": [{ "session_id": "resume-sid-1", "status": "invisible" }]
                    }
                })
                .to_string(),
            ))
            .unwrap();
            let _ = ws1.read().unwrap(); // browsing presence

            // Trigger immediate heartbeat request & RECONNECT (Op 7)
            ws1.send(Message::Text(json!({ "op": 1, "d": Value::Null }).to_string()))
                .unwrap();
            let hb: Value = serde_json::from_str(ws1.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(hb["op"], 1);
            assert_eq!(hb["d"], 7);
            ws1.send(Message::Text(json!({ "op": 11 }).to_string())).unwrap();
            ws1.send(Message::Text(json!({ "op": 7 }).to_string())).unwrap();
            drop(ws1);

            // Connection 2: expects Op 6 RESUME, then close 4004 stops reconnection loop
            let (tcp2, _) = listener.accept().expect("accept2");
            let mut ws2 = accept(tcp2).expect("ws2");
            ws2.send(Message::Text(
                json!({ "op": 10, "d": { "heartbeat_interval": 30000 } }).to_string(),
            ))
            .unwrap();
            let resume_msg: Value =
                serde_json::from_str(ws2.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(resume_msg["op"], 6);
            assert_eq!(resume_msg["d"]["session_id"], "resume-sid-1");
            assert_eq!(resume_msg["d"]["seq"], 7);

            ws2.close(Some(CloseFrame {
                code: CloseCode::from(4004),
                reason: std::borrow::Cow::Borrowed("Authentication failed"),
            }))
            .unwrap();
            let _ = ws2.flush();
        });

        let token = "tok-resume";
        let status = "online";
        let mode = "catalog";
        let cfg = MocktailRustMicupConfig {
            gateway_url_ptr: ws_url.as_ptr() as *const c_char,
            gateway_url_len: ws_url.len(),
            token_ptr: token.as_ptr() as *const c_char,
            token_len: token.len(),
            token_file_ptr: std::ptr::null(),
            token_file_len: 0,
            status_ptr: status.as_ptr() as *const c_char,
            status_len: status.len(),
            activity_mode_ptr: mode.as_ptr() as *const c_char,
            activity_mode_len: mode.len(),
            text_browsing_ptr: std::ptr::null(),
            text_browsing_len: 0,
            text_joining_ptr: std::ptr::null(),
            text_joining_len: 0,
            text_playing_ptr: std::ptr::null(),
            text_playing_len: 0,
            text_unknown_place_ptr: std::ptr::null(),
            text_unknown_place_len: 0,
            ca_bundle_ptr: std::ptr::null(),
            ca_bundle_len: 0,
            proxy_url_ptr: std::ptr::null(),
            proxy_url_len: 0,
            proxy_username_ptr: std::ptr::null(),
            proxy_username_len: 0,
            proxy_password_ptr: std::ptr::null(),
            proxy_password_len: 0,
            enabled: 1,
            show_place_name: 1,
            show_elapsed_time: 1,
        };
        let mut session_ptr: *mut MocktailRustMicupSession = std::ptr::null_mut();
        let mut detail_buf = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_micup_session_start(
                &cfg,
                &mut session_ptr,
                detail_buf.as_mut_ptr(),
                detail_buf.len()
            ),
            0
        );
        server_thread.join().expect("resume & 4004 server finished");
        // Verify no third connection is attempted after 4004 auth failure
        thread::sleep(Duration::from_millis(200));
        mocktail_rust_micup_session_stop(session_ptr);
    }

    #[test]
    fn http_connect_proxy_sends_basic_auth_and_preserves_post_tunnel_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req_buf = Vec::new();
            let mut byte = [0u8; 1];
            while conn.read(&mut byte).unwrap() == 1 {
                req_buf.push(byte[0]);
                if req_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8(req_buf).unwrap();
            assert!(req.starts_with("CONNECT micup.gg:443 HTTP/1.1\r\n"));
            assert!(req.contains("Proxy-Authorization: Basic "));
            conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nPAYLOAD")
                .unwrap();
            conn.flush().unwrap();
        });

        let proxy = ProxyConfig {
            url: format!("http://127.0.0.1:{}", port),
            username: "u".to_string(),
            password: Zeroizing::new("p".to_string()),
        };
        let mut stream = connect_via_http_proxy(&proxy, "micup.gg", 443).expect("proxy connect");
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).expect("post-tunnel bytes preserved");
        assert_eq!(&payload, b"PAYLOAD");
        server.join().unwrap();
    }
}
