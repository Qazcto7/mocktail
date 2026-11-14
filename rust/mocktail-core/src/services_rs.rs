use std::ffi::{c_char, c_void};
use std::path::{Path, PathBuf};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::http_transport::{perform_service_request, HttpMethod, HttpServiceRequest};
use crate::storage_paths::slice_to_str;
use crate::unix_ipc::read_regular_file_limited;
use crate::update_json::MocktailRustStrSlice;
use crate::{
    extract_auth_cookie_bytes, is_safe_auth_cookie_bytes, parse_auth_identity_slice,
    write_atomic_bytes, MOCKTAIL_SAFE_DEFAULTS_JSON,
};

const AUTH_STATUS_AUTHENTICATED: i32 = 0;
const AUTH_STATUS_GUEST: i32 = 1;
const AUTH_STATUS_INVALID: i32 = 2;
const AUTH_STATUS_UNAVAILABLE: i32 = 3;

const CLIENT_SETTINGS_SOURCE_EXPLICIT_JSON: i32 = 0;
const CLIENT_SETTINGS_SOURCE_EXPLICIT_FILE: i32 = 1;
const CLIENT_SETTINGS_SOURCE_BUNDLED_FILE: i32 = 2;
const CLIENT_SETTINGS_SOURCE_SAFE_DEFAULTS: i32 = 3;
const CLIENT_SETTINGS_SOURCE_DOWNLOADED: i32 = 4;
const CLIENT_SETTINGS_SOURCE_CACHE: i32 = 5;
const CLIENT_SETTINGS_SOURCE_EMPTY_DEFAULTS: i32 = 6;

const EMPTY_CLIENT_SETTINGS_JSON: &str = "{\"applicationSettings\":{}}";

pub type MocktailRustInjectedHttpRespFn = unsafe extern "C" fn(
    resp_ctx: *mut c_void,
    transport_ok: bool,
    status_code: i64,
    body: MocktailRustStrSlice,
    error: MocktailRustStrSlice,
);

pub type MocktailRustInjectedHttpGetFn = Option<
    unsafe extern "C" fn(
        http_ctx: *mut c_void,
        url: MocktailRustStrSlice,
        headers_ptr: *const MocktailRustStrSlice,
        headers_len: usize,
        timeout_ms: i64,
        maximum_body_bytes: usize,
        follow_redirects: bool,
        on_response: MocktailRustInjectedHttpRespFn,
        resp_ctx: *mut c_void,
    ),
>;

struct HttpGetResult {
    transport_ok: bool,
    status_code: i64,
    body: String,
    error: String,
}

fn execute_http_get(
    http_get: MocktailRustInjectedHttpGetFn,
    http_ctx: *mut c_void,
    url: &str,
    headers: &[String],
    timeout_ms: i64,
    maximum_body_bytes: usize,
    follow_redirects: bool,
) -> HttpGetResult {
    if let Some(cb) = http_get {
        unsafe extern "C" fn on_resp(
            ctx: *mut c_void,
            transport_ok: bool,
            status_code: i64,
            body: MocktailRustStrSlice,
            error: MocktailRustStrSlice,
        ) {
            if ctx.is_null() {
                return;
            }
            let out = &mut *ctx.cast::<HttpGetResult>();
            out.transport_ok = transport_ok;
            out.status_code = status_code;
            out.body = slice_to_str(body.ptr as *const c_char, body.len)
                .unwrap_or("")
                .to_string();
            out.error = slice_to_str(error.ptr as *const c_char, error.len)
                .unwrap_or("")
                .to_string();
        }

        let mut res = HttpGetResult {
            transport_ok: false,
            status_code: 0,
            body: String::new(),
            error: String::new(),
        };
        let header_slices: Vec<MocktailRustStrSlice> =
            headers.iter().map(|h| MocktailRustStrSlice::from_str(h)).collect();
        unsafe {
            cb(
                http_ctx,
                MocktailRustStrSlice::from_str(url),
                if header_slices.is_empty() {
                    std::ptr::null()
                } else {
                    header_slices.as_ptr()
                },
                header_slices.len(),
                timeout_ms,
                maximum_body_bytes,
                follow_redirects,
                on_resp,
                (&raw mut res).cast::<c_void>(),
            );
        }
        return res;
    }

    let resp = perform_service_request(&HttpServiceRequest {
        method: HttpMethod::Get,
        url: url.to_string(),
        body: String::new(),
        headers: headers.to_vec(),
        ca_bundle: String::new(),
        timeout_ms,
        max_redirects: if follow_redirects { 5 } else { 0 },
        max_response_bytes: maximum_body_bytes,
        max_attempts: 3,
        allow_local_socks5_fallback: true,
        fallback_env_ca_bundle: true,
        use_runtime_env_proxy: true,
        explicit_proxy: None,
    });
    HttpGetResult {
        transport_ok: resp.error.is_empty(),
        status_code: resp.status_code as i64,
        body: resp.body,
        error: resp.error,
    }
}

#[repr(C)]
pub struct MocktailRustAuthSessionResultView {
    pub status: i32,
    pub user_id: i64,
    pub username: MocktailRustStrSlice,
    pub display_name: MocktailRustStrSlice,
    pub http_status: i64,
    pub error: MocktailRustStrSlice,
}

pub type MocktailRustAuthSessionCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustAuthSessionResultView),
>;

struct AuthSessionData {
    status: i32,
    user_id: i64,
    username: String,
    display_name: String,
    http_status: i64,
    error: String,
}

fn resolve_auth_session_internal(
    cookie_header: &[u8],
    allow_guest: bool,
    http_get: MocktailRustInjectedHttpGetFn,
    http_ctx: *mut c_void,
) -> AuthSessionData {
    let (present, value_bytes) = extract_auth_cookie_bytes(cookie_header);
    if !present {
        if allow_guest {
            return AuthSessionData {
                status: AUTH_STATUS_GUEST,
                user_id: -1,
                username: String::new(),
                display_name: String::new(),
                http_status: 0,
                error: String::new(),
            };
        }
        return AuthSessionData {
            status: AUTH_STATUS_INVALID,
            user_id: -1,
            username: String::new(),
            display_name: String::new(),
            http_status: 0,
            error: "missing .ROBLOSECURITY cookie".to_string(),
        };
    }

    if !is_safe_auth_cookie_bytes(value_bytes) {
        return AuthSessionData {
            status: AUTH_STATUS_INVALID,
            user_id: -1,
            username: String::new(),
            display_name: String::new(),
            http_status: 0,
            error: "invalid .ROBLOSECURITY cookie".to_string(),
        };
    }

    let cookie_val = Zeroizing::new(String::from_utf8_lossy(value_bytes).into_owned());
    let cookie_req_header = Zeroizing::new(format!("Cookie: .ROBLOSECURITY={}", &*cookie_val));
    let headers = [
        "Accept: application/json".to_string(),
        cookie_req_header.as_str().to_string(),
    ];
    let http = execute_http_get(
        http_get,
        http_ctx,
        "https://users.roblox.com/v1/users/authenticated",
        &headers,
        15_000,
        1024 * 1024,
        false,
    );

    if !http.transport_ok {
        return AuthSessionData {
            status: AUTH_STATUS_UNAVAILABLE,
            user_id: -1,
            username: String::new(),
            display_name: String::new(),
            http_status: http.status_code,
            error: "authentication service unavailable".to_string(),
        };
    }
    if http.status_code == 401 || http.status_code == 403 {
        return AuthSessionData {
            status: AUTH_STATUS_INVALID,
            user_id: -1,
            username: String::new(),
            display_name: String::new(),
            http_status: http.status_code,
            error: "authentication rejected".to_string(),
        };
    }
    if http.status_code != 200 {
        return AuthSessionData {
            status: AUTH_STATUS_UNAVAILABLE,
            user_id: -1,
            username: String::new(),
            display_name: String::new(),
            http_status: http.status_code,
            error: "unexpected authentication HTTP status".to_string(),
        };
    }

    match parse_auth_identity_slice(http.body.as_bytes()) {
        Ok((user_id, username, display_name)) => AuthSessionData {
            status: AUTH_STATUS_AUTHENTICATED,
            user_id,
            username,
            display_name,
            http_status: http.status_code,
            error: String::new(),
        },
        Err(_) => AuthSessionData {
            status: AUTH_STATUS_UNAVAILABLE,
            user_id: -1,
            username: String::new(),
            display_name: String::new(),
            http_status: http.status_code,
            error: "invalid authenticated-user response".to_string(),
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_auth_resolve_session(
    cookie_header_ptr: *const c_char,
    cookie_header_len: usize,
    allow_guest: bool,
    http_get: MocktailRustInjectedHttpGetFn,
    http_ctx: *mut c_void,
    on_result: MocktailRustAuthSessionCallback,
    result_ctx: *mut c_void,
) {
    let slice = if cookie_header_ptr.is_null() || cookie_header_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(cookie_header_ptr as *const u8, cookie_header_len)
    };
    let resolved = resolve_auth_session_internal(slice, allow_guest, http_get, http_ctx);
    if let Some(cb) = on_result {
        let view = MocktailRustAuthSessionResultView {
            status: resolved.status,
            user_id: resolved.user_id,
            username: MocktailRustStrSlice::from_str(&resolved.username),
            display_name: MocktailRustStrSlice::from_str(&resolved.display_name),
            http_status: resolved.http_status,
            error: MocktailRustStrSlice::from_str(&resolved.error),
        };
        cb(result_ctx, &view);
    }
}

#[repr(C)]
pub struct MocktailRustClientSettingsOptionsView {
    pub explicit_json: MocktailRustStrSlice,
    pub explicit_file: MocktailRustStrSlice,
    pub bundled_file: MocktailRustStrSlice,
    pub cache_file: MocktailRustStrSlice,
    pub application: MocktailRustStrSlice,
    pub url: MocktailRustStrSlice,
    pub use_bundled: bool,
    pub sober_mode: bool,
    pub fetch: bool,
    pub auto_update: bool,
}

#[repr(C)]
pub struct MocktailRustClientSettingsResultView {
    pub json: MocktailRustStrSlice,
    pub source: i32,
    pub valid_json: bool,
    pub cache_updated: bool,
    pub error: MocktailRustStrSlice,
}

pub type MocktailRustClientSettingsCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustClientSettingsResultView),
>;

struct ClientSettingsData {
    json: String,
    source: i32,
    valid_json: bool,
    cache_updated: bool,
    error: String,
}

fn is_valid_settings_json_object(content: &str) -> bool {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return false;
    }
    serde_json::from_str::<Value>(trimmed).is_ok_and(|v| v.is_object())
}

fn read_settings_file_result(path: &Path, source: i32) -> Option<ClientSettingsData> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let bytes = read_regular_file_limited(path, 16 * 1024 * 1024, true, false).ok()?;
    let content = String::from_utf8(bytes).ok()?;
    let valid = is_valid_settings_json_object(&content);
    Some(ClientSettingsData {
        json: content,
        source,
        valid_json: valid,
        cache_updated: false,
        error: String::new(),
    })
}

fn resolve_client_settings_internal(
    explicit_json: &str,
    explicit_file: &Path,
    bundled_file: &Path,
    cache_file: &Path,
    application: &str,
    url: &str,
    use_bundled: bool,
    sober_mode: bool,
    fetch: bool,
    auto_update: bool,
    http_get: MocktailRustInjectedHttpGetFn,
    http_ctx: *mut c_void,
) -> ClientSettingsData {
    if !explicit_json.is_empty() {
        let valid = is_valid_settings_json_object(explicit_json);
        return ClientSettingsData {
            json: explicit_json.to_string(),
            source: CLIENT_SETTINGS_SOURCE_EXPLICIT_JSON,
            valid_json: valid,
            cache_updated: false,
            error: String::new(),
        };
    }

    if !explicit_file.as_os_str().is_empty() {
        if let Some(res) = read_settings_file_result(explicit_file, CLIENT_SETTINGS_SOURCE_EXPLICIT_FILE) {
            if res.valid_json {
                return res;
            }
        }
    }

    if !fetch && use_bundled && !bundled_file.as_os_str().is_empty() {
        if let Some(res) = read_settings_file_result(bundled_file, CLIENT_SETTINGS_SOURCE_BUNDLED_FILE) {
            if res.valid_json {
                return res;
            }
        }
    }

    if !fetch && sober_mode {
        return ClientSettingsData {
            json: MOCKTAIL_SAFE_DEFAULTS_JSON.to_string(),
            source: CLIENT_SETTINGS_SOURCE_SAFE_DEFAULTS,
            valid_json: true,
            cache_updated: false,
            error: String::new(),
        };
    }

    let mut update_error = String::new();
    if fetch {
        let app = if application.is_empty() {
            "GoogleAndroidApp"
        } else {
            application
        };
        let target_url = if url.is_empty() {
            format!("https://clientsettingscdn.roblox.com/v2/settings/application/{}", app)
        } else {
            url.to_string()
        };
        let resp = execute_http_get(
            http_get,
            http_ctx,
            &target_url,
            &[],
            15_000,
            16 * 1024 * 1024,
            true,
        );
        if resp.transport_ok && resp.status_code == 200 && is_valid_settings_json_object(&resp.body) {
            let mut updated = false;
            if auto_update && !cache_file.as_os_str().is_empty() {
                let same_as_existing = read_regular_file_limited(cache_file, 16 * 1024 * 1024, true, false)
                    .ok()
                    .is_some_and(|existing| existing == resp.body.as_bytes());
                if !same_as_existing {
                    match write_atomic_bytes(cache_file, resp.body.as_bytes()) {
                        Ok(()) => updated = true,
                        Err((_, msg)) => update_error = msg,
                    }
                }
            }
            return ClientSettingsData {
                json: resp.body,
                source: CLIENT_SETTINGS_SOURCE_DOWNLOADED,
                valid_json: true,
                cache_updated: updated,
                error: update_error,
            };
        }
        if !resp.transport_ok {
            update_error = if resp.error.is_empty() {
                "HTTP transport failed".to_string()
            } else {
                resp.error
            };
        } else if resp.status_code != 200 {
            update_error = format!("client settings server returned HTTP {}", resp.status_code);
        } else {
            update_error = "client settings response was empty or invalid JSON".to_string();
        }
    }

    if let Some(mut cached) = read_settings_file_result(cache_file, CLIENT_SETTINGS_SOURCE_CACHE) {
        if cached.valid_json {
            cached.error = update_error;
            return cached;
        }
    }

    ClientSettingsData {
        json: EMPTY_CLIENT_SETTINGS_JSON.to_string(),
        source: CLIENT_SETTINGS_SOURCE_EMPTY_DEFAULTS,
        valid_json: true,
        cache_updated: false,
        error: update_error,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_client_settings_resolve(
    options: *const MocktailRustClientSettingsOptionsView,
    http_get: MocktailRustInjectedHttpGetFn,
    http_ctx: *mut c_void,
    on_result: MocktailRustClientSettingsCallback,
    result_ctx: *mut c_void,
) {
    if options.is_null() {
        return;
    }
    let opts = &*options;
    let slice_str = |s: MocktailRustStrSlice| -> &str {
        slice_to_str(s.ptr as *const c_char, s.len).unwrap_or("")
    };
    let res = resolve_client_settings_internal(
        slice_str(opts.explicit_json),
        &PathBuf::from(slice_str(opts.explicit_file)),
        &PathBuf::from(slice_str(opts.bundled_file)),
        &PathBuf::from(slice_str(opts.cache_file)),
        slice_str(opts.application),
        slice_str(opts.url),
        opts.use_bundled,
        opts.sober_mode,
        opts.fetch,
        opts.auto_update,
        http_get,
        http_ctx,
    );
    if let Some(cb) = on_result {
        let view = MocktailRustClientSettingsResultView {
            json: MocktailRustStrSlice::from_str(&res.json),
            source: res.source,
            valid_json: res.valid_json,
            cache_updated: res.cache_updated,
            error: MocktailRustStrSlice::from_str(&res.error),
        };
        cb(result_ctx, &view);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_resolve_handles_guest_invalid_and_authenticated() {
        unsafe extern "C" fn fake_get(
            _ctx: *mut c_void,
            _url: MocktailRustStrSlice,
            _headers_ptr: *const MocktailRustStrSlice,
            _headers_len: usize,
            _timeout_ms: i64,
            _max_bytes: usize,
            _follow: bool,
            on_response: MocktailRustInjectedHttpRespFn,
            resp_ctx: *mut c_void,
        ) {
            let body = r#"{"id":42,"name":"Alice","displayName":"Alice D"}"#;
            on_response(
                resp_ctx,
                true,
                200,
                MocktailRustStrSlice::from_str(body),
                MocktailRustStrSlice::from_str(""),
            );
        }

        let guest = resolve_auth_session_internal(b"other=1", true, Some(fake_get), std::ptr::null_mut());
        assert_eq!(guest.status, AUTH_STATUS_GUEST);

        let invalid = resolve_auth_session_internal(b".ROBLOSECURITY=", true, Some(fake_get), std::ptr::null_mut());
        assert_eq!(invalid.status, AUTH_STATUS_INVALID);

        let authed = resolve_auth_session_internal(
            b".ROBLOSECURITY=_|tok123",
            false,
            Some(fake_get),
            std::ptr::null_mut(),
        );
        assert_eq!(authed.status, AUTH_STATUS_AUTHENTICATED);
        assert_eq!(authed.user_id, 42);
        assert_eq!(authed.username, "Alice");
    }

    #[test]
    fn client_settings_resolve_caches_and_falls_back() {
        unsafe extern "C" fn ok_get(
            _ctx: *mut c_void,
            _url: MocktailRustStrSlice,
            _hdr_ptr: *const MocktailRustStrSlice,
            _hdr_len: usize,
            _timeout_ms: i64,
            _max_bytes: usize,
            _follow: bool,
            on_response: MocktailRustInjectedHttpRespFn,
            resp_ctx: *mut c_void,
        ) {
            let body = r#"{"applicationSettings":{"A":1}}"#;
            on_response(
                resp_ctx,
                true,
                200,
                MocktailRustStrSlice::from_str(body),
                MocktailRustStrSlice::from_str(""),
            );
        }

        let dir = PathBuf::from(format!("/tmp/mocktail_cs_test_{}", std::process::id()));
        let cache = dir.join("cache.json");
        let _ = std::fs::remove_dir_all(&dir);

        let res = resolve_client_settings_internal(
            "",
            Path::new(""),
            Path::new(""),
            &cache,
            "GoogleAndroidApp",
            "",
            false,
            false,
            true,
            true,
            Some(ok_get),
            std::ptr::null_mut(),
        );
        assert_eq!(res.source, CLIENT_SETTINGS_SOURCE_DOWNLOADED);
        assert!(res.cache_updated);
        assert!(cache.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
