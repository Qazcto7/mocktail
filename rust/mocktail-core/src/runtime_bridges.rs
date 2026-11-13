use std::os::raw::{c_char, c_int, c_void};
use std::slice;

use crate::{copy_error, MocktailRustExperienceLaunchData};

pub const K_MAX_EXPERIENCE_LAUNCH_JSON_BYTES: usize = 64 * 1024;
pub const K_MAX_EXPERIENCE_LAUNCH_STRING_BYTES: usize = 16 * 1024;

pub const K_MAX_BROWSER_PAYLOAD_BYTES: usize = 64 * 1024;
pub const K_MAX_BROWSER_URL_BYTES: usize = 16 * 1024;
pub const K_MAX_BROWSER_WINDOW_TITLE_BYTES: usize = 512;
pub const K_MAX_BROWSER_QUEUED_EVENTS: usize = 64;
pub const K_MAX_BROWSER_QUEUED_BYTES: usize = 1024 * 1024;

pub const EXPERIENCE_LAUNCH_STRING_FIELDS: [&str; 12] = [
    "gameInstanceId",
    "reservedServerAccessCode",
    "callId",
    "referralPage",
    "accessCode",
    "linkCode",
    "launchData",
    "eventId",
    "gameJoinContext",
    "joinAttemptId",
    "joinAttemptOrigin",
    "isoContext",
];

pub type MocktailExperienceLaunchStringCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, field_index: u32, ptr: *const c_char, len: usize)>;
pub type MocktailExperienceLaunchCanonicalCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, ptr: *const c_char, len: usize)>;

fn read_optional_launch_int(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<i64, String> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(serde_json::Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| format!("{} must be an integer", key)),
        _ => Err(format!("{} must be an integer", key)),
    }
}

fn has_control_byte(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b < 0x20 || b == 0x7f)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_experience_launch_json_full(
    json_ptr: *const c_char,
    json_len: usize,
    out_data: *mut MocktailRustExperienceLaunchData,
    ctx: *mut c_void,
    on_string: MocktailExperienceLaunchStringCallback,
    on_canonical: MocktailExperienceLaunchCanonicalCallback,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if out_data.is_null() {
        copy_error(err_buf, err_cap, "experience launch output is null");
        return -1;
    }
    if json_ptr.is_null() || json_len == 0 || json_len > K_MAX_EXPERIENCE_LAUNCH_JSON_BYTES {
        copy_error(err_buf, err_cap, "experience launch JSON size is invalid");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(json_ptr as *const u8, json_len) };
    let text = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "experience launch payload is not a JSON object");
            return -2;
        }
    };
    let doc = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => {
            copy_error(err_buf, err_cap, "experience launch payload is not a JSON object");
            return -2;
        }
    };
    let obj = &doc;

    let place_id = match read_optional_launch_int(obj, "placeId") {
        Ok(v) => v,
        Err(msg) => {
            copy_error(err_buf, err_cap, &msg);
            return -3;
        }
    };
    let user_id = match read_optional_launch_int(obj, "userId") {
        Ok(v) => v,
        Err(msg) => {
            copy_error(err_buf, err_cap, &msg);
            return -3;
        }
    };
    let conversation_id = match read_optional_launch_int(obj, "conversationId") {
        Ok(v) => v,
        Err(msg) => {
            copy_error(err_buf, err_cap, &msg);
            return -3;
        }
    };
    let referred_by_player_id = match read_optional_launch_int(obj, "referredByPlayerId") {
        Ok(v) => v,
        Err(msg) => {
            copy_error(err_buf, err_cap, &msg);
            return -3;
        }
    };

    if place_id <= 0 {
        copy_error(err_buf, err_cap, "experience launch requires a positive placeId");
        return -4;
    }
    if user_id < 0 || conversation_id < 0 || referred_by_player_id < 0 {
        copy_error(err_buf, err_cap, "experience launch identifiers cannot be negative");
        return -5;
    }

    let mut extracted_strings: [(u32, &str); 12] = [(0, ""); 12];
    let mut extracted_count = 0usize;
    for (idx, field_name) in EXPERIENCE_LAUNCH_STRING_FIELDS.iter().enumerate() {
        match obj.get(*field_name) {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(s)) => {
                if s.len() > K_MAX_EXPERIENCE_LAUNCH_STRING_BYTES {
                    copy_error(
                        err_buf,
                        err_cap,
                        &format!("experience launch field is too large: {}", field_name),
                    );
                    return -6;
                }
                extracted_strings[extracted_count] = (idx as u32, s.as_str());
                extracted_count += 1;
            }
            Some(_) => {
                copy_error(
                    err_buf,
                    err_cap,
                    &format!("experience launch field is not a string: {}", field_name),
                );
                return -6;
            }
        }
    }

    let canonical = match serde_json::to_string(obj) {
        Ok(s) => s,
        Err(_) => {
            copy_error(err_buf, err_cap, "experience launch payload is not a JSON object");
            return -2;
        }
    };
    if canonical.len() > K_MAX_EXPERIENCE_LAUNCH_JSON_BYTES {
        copy_error(err_buf, err_cap, "canonical experience launch JSON is too large");
        return -7;
    }

    unsafe {
        *out_data = MocktailRustExperienceLaunchData {
            place_id,
            user_id,
            conversation_id,
            referred_by_player_id,
        };
    }

    if let Some(cb) = on_string {
        for &(idx, value) in &extracted_strings[..extracted_count] {
            unsafe {
                cb(ctx, idx, value.as_ptr() as *const c_char, value.len());
            }
        }
    }
    if let Some(cb) = on_canonical {
        unsafe {
            cb(
                ctx,
                canonical.as_ptr() as *const c_char,
                canonical.len(),
            );
        }
    }
    0
}

pub type MocktailRuntimeConfigKvCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        key: *const c_char,
        key_len: usize,
        val: *const c_char,
        val_len: usize,
    ),
>;

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_runtime_config_yaml_kv(
    yaml_bytes: *const u8,
    yaml_len: usize,
    ctx: *mut c_void,
    emit_kv: MocktailRuntimeConfigKvCallback,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    if yaml_len > 0 && yaml_bytes.is_null() {
        copy_error(out_error, error_cap, "invalid argument");
        return -1;
    }
    let slice = if yaml_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(yaml_bytes, yaml_len) }
    };
    let env = match crate::build_runtime_config_yaml_env_map(slice) {
        Ok(m) => m,
        Err((code, msg)) => {
            copy_error(out_error, error_cap, &msg);
            return code;
        }
    };
    if let Some(cb) = emit_kv {
        for (k, v) in env {
            if let Some(s) = v.as_str() {
                unsafe {
                    cb(
                        ctx,
                        k.as_ptr() as *const c_char,
                        k.len(),
                        s.as_ptr() as *const c_char,
                        s.len(),
                    );
                }
            }
        }
    }
    0
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustRuntimeConfigPolicyFlags {
    pub frame_rate_valid: i32,
    pub device_profile_valid: i32,
    pub has_usable_input: i32,
    pub graphics_backend_valid: i32,
    pub theme_mode_valid: i32,
    pub high_dpi_valid: i32,
    pub vsync_mode_valid: i32,
    pub present_mode_valid: i32,
    pub audio_output_device_valid: i32,
    pub audio_input_device_valid: i32,
    pub memory_limit_valid: i32,
    pub game_mode_valid: i32,
    pub physics_worker_mode_valid: i32,
    pub fleasion_valid: i32,
    pub ca_bundle_valid: i32,
    pub discord_rpc_valid: i32,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_runtime_config_policy(
    flags: *const MocktailRustRuntimeConfigPolicyFlags,
    for_export: i32,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    if flags.is_null() {
        copy_error(out_error, error_cap, "invalid runtime config policy flags");
        return -1;
    }
    let f = unsafe { &*flags };
    if for_export != 0 {
        let export_checks: &[(i32, &str)] = &[
            (f.present_mode_valid, "cannot export an invalid present mode"),
            (f.fleasion_valid, "cannot export invalid Fleasion configuration"),
            (f.device_profile_valid, "cannot export an invalid device profile"),
            (f.audio_output_device_valid, "cannot export an invalid audio output device"),
            (f.audio_input_device_valid, "cannot export an invalid audio input device"),
            (f.memory_limit_valid, "cannot export an invalid memory-limit policy"),
            (f.game_mode_valid, "cannot export an invalid GameMode policy"),
            (f.physics_worker_mode_valid, "cannot export an invalid physics worker policy"),
            (f.ca_bundle_valid, "cannot export an invalid CA bundle path"),
            (f.discord_rpc_valid, "cannot export an invalid Discord Rich Presence policy"),
        ];
        for &(ok, msg) in export_checks {
            if ok == 0 {
                copy_error(out_error, error_cap, msg);
                return -2;
            }
        }
        return 0;
    }

    let load_checks: &[(i32, &str)] = &[
        (f.frame_rate_valid, "frame-rate policy is invalid"),
        (f.device_profile_valid, "device profile is invalid"),
        (f.has_usable_input, "device must expose at least one usable input capability"),
        (f.graphics_backend_valid, "graphics backend is invalid"),
        (f.theme_mode_valid, "theme mode is invalid"),
        (f.high_dpi_valid, "window high-DPI policy is invalid"),
        (f.vsync_mode_valid, "VSync policy is invalid"),
        (f.present_mode_valid, "graphics.present_mode must be auto, fifo, mailbox, or immediate"),
        (f.audio_output_device_valid, "audio output device is invalid"),
        (f.audio_input_device_valid, "audio input device is invalid"),
        (f.memory_limit_valid, "memory-limit policy is invalid"),
        (f.game_mode_valid, "GameMode policy is invalid"),
        (f.physics_worker_mode_valid, "physics worker policy is invalid"),
        (
            f.fleasion_valid,
            "Fleasion configuration is invalid: use proxy_mode env or hosts, a port from 1 to 65535, an absolute CA certificate path, and no conflicting system/fixed proxy",
        ),
        (f.ca_bundle_valid, "CA bundle path is invalid"),
        (f.discord_rpc_valid, "Discord Rich Presence configuration is invalid"),
    ];
    for &(ok, msg) in load_checks {
        if ok == 0 {
            copy_error(out_error, error_cap, msg);
            return -2;
        }
    }
    0
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustBrowserServiceCommandHeader {
    pub command_type: i32,
    pub has_title: i32,
    pub has_visible: i32,
    pub visible: i32,
    pub modal: i32,
    pub has_back_navigation_disabled: i32,
    pub back_navigation_disabled: i32,
    pub show_domain_as_title: i32,
}

pub type MocktailBrowserServiceStringCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, field_kind: u32, ptr: *const c_char, len: usize)>;

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_browser_service_open_url(
    payload_ptr: *const c_char,
    payload_len: usize,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if payload_len == 0 || payload_ptr.is_null() || payload_len > K_MAX_BROWSER_URL_BYTES {
        copy_error(err_buf, err_cap, "BrowserService open URL is invalid");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(payload_ptr as *const u8, payload_len) };
    if has_control_byte(slice) {
        copy_error(err_buf, err_cap, "BrowserService open URL is invalid");
        return -1;
    }
    0
}

fn parse_optional_title(
    obj: &serde_json::Map<String, serde_json::Value>,
    err_buf: *mut c_char,
    err_cap: usize,
) -> Result<Option<&str>, i32> {
    match obj.get("title") {
        None => Ok(None),
        Some(v) => match v.as_str() {
            Some(t) => {
                if t.len() > K_MAX_BROWSER_WINDOW_TITLE_BYTES || has_control_byte(t.as_bytes()) {
                    copy_error(err_buf, err_cap, "BrowserService command field title is invalid");
                    Err(-5)
                } else {
                    Ok(Some(t))
                }
            }
            None => {
                copy_error(
                    err_buf,
                    err_cap,
                    "BrowserService command field title must be a string",
                );
                Err(-5)
            }
        },
    }
}

fn parse_optional_bool(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    err_buf: *mut c_char,
    err_cap: usize,
) -> Result<Option<bool>, i32> {
    match obj.get(key) {
        None => Ok(None),
        Some(v) => match v.as_bool() {
            Some(b) => Ok(Some(b)),
            None => {
                copy_error(
                    err_buf,
                    err_cap,
                    &format!("BrowserService command field {} must be a boolean", key),
                );
                Err(-5)
            }
        },
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_browser_service_command_full(
    json_str: *const c_char,
    json_len: usize,
    out_header: *mut MocktailRustBrowserServiceCommandHeader,
    ctx: *mut c_void,
    on_string: MocktailBrowserServiceStringCallback,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if out_header.is_null() {
        copy_error(err_buf, err_cap, "BrowserService command output is null");
        return -1;
    }
    if json_str.is_null() || json_len == 0 || json_len > K_MAX_BROWSER_PAYLOAD_BYTES {
        copy_error(err_buf, err_cap, "BrowserService command JSON size is invalid");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(json_str as *const u8, json_len) };
    let text = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "BrowserService command payload is not a JSON object");
            return -2;
        }
    };
    let val = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => {
            copy_error(err_buf, err_cap, "BrowserService command payload is not a JSON object");
            return -2;
        }
    };
    let obj = &val;
    let cmd = match obj.get("command").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => {
            copy_error(err_buf, err_cap, "BrowserService command requires a string command");
            return -3;
        }
    };

    if cmd == "open" {
        let url = match obj.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                copy_error(err_buf, err_cap, "BrowserService open command requires a string url");
                return -4;
            }
        };
        if url.is_empty()
            || url.len() > K_MAX_BROWSER_URL_BYTES
            || has_control_byte(url.as_bytes())
        {
            copy_error(err_buf, err_cap, "BrowserService open URL is invalid");
            return -5;
        }
        let title = match parse_optional_title(obj, err_buf, err_cap) {
            Ok(t) => t,
            Err(code) => return code,
        };
        let visible = match parse_optional_bool(obj, "visible", err_buf, err_cap) {
            Ok(b) => b.unwrap_or(true),
            Err(code) => return code,
        };
        let modal = match parse_optional_bool(obj, "modal", err_buf, err_cap) {
            Ok(b) => b.unwrap_or(false),
            Err(code) => return code,
        };
        let back = match parse_optional_bool(obj, "backNavigationDisabled", err_buf, err_cap) {
            Ok(b) => b.unwrap_or(false),
            Err(code) => return code,
        };
        let show_domain = match parse_optional_bool(obj, "showDomainAsTitle", err_buf, err_cap) {
            Ok(b) => b.unwrap_or(false),
            Err(code) => return code,
        };

        unsafe {
            *out_header = MocktailRustBrowserServiceCommandHeader {
                command_type: 1,
                has_title: i32::from(title.is_some()),
                has_visible: 1,
                visible: i32::from(visible),
                modal: i32::from(modal),
                has_back_navigation_disabled: 1,
                back_navigation_disabled: i32::from(back),
                show_domain_as_title: i32::from(show_domain),
            };
        }
        if let Some(cb) = on_string {
            unsafe {
                cb(ctx, 0, url.as_ptr() as *const c_char, url.len());
                if let Some(t) = title {
                    cb(ctx, 1, t.as_ptr() as *const c_char, t.len());
                }
            }
        }
        return 0;
    }

    if cmd == "config" {
        let title = match parse_optional_title(obj, err_buf, err_cap) {
            Ok(t) => t,
            Err(code) => return code,
        };
        let visible = match parse_optional_bool(obj, "visible", err_buf, err_cap) {
            Ok(b) => b,
            Err(code) => return code,
        };
        let back = match parse_optional_bool(obj, "backNavigationDisabled", err_buf, err_cap) {
            Ok(b) => b,
            Err(code) => return code,
        };

        unsafe {
            *out_header = MocktailRustBrowserServiceCommandHeader {
                command_type: 2,
                has_title: i32::from(title.is_some()),
                has_visible: i32::from(visible.is_some()),
                visible: i32::from(visible.unwrap_or(false)),
                modal: 0,
                has_back_navigation_disabled: i32::from(back.is_some()),
                back_navigation_disabled: i32::from(back.unwrap_or(false)),
                show_domain_as_title: 0,
            };
        }
        if let Some(cb) = on_string {
            if let Some(t) = title {
                unsafe {
                    cb(ctx, 1, t.as_ptr() as *const c_char, t.len());
                }
            }
        }
        return 0;
    }

    copy_error(err_buf, err_cap, "BrowserService command is unsupported");
    -6
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_service_can_queue_outgoing(
    queued_events: usize,
    queued_bytes: usize,
    drain_events: usize,
    drain_bytes: usize,
    incoming_bytes: usize,
) -> i32 {
    let total_events = match queued_events.checked_add(drain_events) {
        Some(v) => v,
        None => return 0,
    };
    let total_bytes = match queued_bytes.checked_add(drain_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let ok = total_events < K_MAX_BROWSER_QUEUED_EVENTS
        && total_bytes <= K_MAX_BROWSER_QUEUED_BYTES
        && incoming_bytes <= K_MAX_BROWSER_QUEUED_BYTES - total_bytes;
    i32::from(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn collect_launch_str(
        ctx: *mut c_void,
        field_index: u32,
        ptr: *const c_char,
        len: usize,
    ) {
        let out = &mut *(ctx as *mut (Vec<(u32, String)>, String));
        let s = std::str::from_utf8(slice::from_raw_parts(ptr as *const u8, len)).unwrap();
        out.0.push((field_index, s.to_string()));
    }

    unsafe extern "C" fn collect_launch_canonical(
        ctx: *mut c_void,
        ptr: *const c_char,
        len: usize,
    ) {
        let out = &mut *(ctx as *mut (Vec<(u32, String)>, String));
        let s = std::str::from_utf8(slice::from_raw_parts(ptr as *const u8, len)).unwrap();
        out.1 = s.to_string();
    }

    #[test]
    fn experience_launch_full_extracts_all_fields_and_enforces_64k_cap() {
        let json = r#"{"placeId":17580461965,"userId":42,"conversationId":7,"referredByPlayerId":9,"gameInstanceId":"inst","launchData":"payload","gameJoinContext":null}"#;
        let mut data = MocktailRustExperienceLaunchData {
            place_id: 0,
            user_id: 0,
            conversation_id: 0,
            referred_by_player_id: 0,
        };
        let mut collected: (Vec<(u32, String)>, String) = (Vec::new(), String::new());
        let mut err = [0i8; 256];
        let rc = mocktail_rust_parse_experience_launch_json_full(
            json.as_ptr() as *const c_char,
            json.len(),
            &mut data,
            &mut collected as *mut _ as *mut c_void,
            Some(collect_launch_str),
            Some(collect_launch_canonical),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(data.place_id, 17580461965);
        assert_eq!(data.user_id, 42);
        assert_eq!(data.conversation_id, 7);
        assert_eq!(data.referred_by_player_id, 9);
        assert!(collected.0.contains(&(0, "inst".to_string())));
        assert!(collected.0.contains(&(6, "payload".to_string())));
        assert!(!collected.0.iter().any(|(idx, _)| *idx == 8));
        assert!(!collected.1.is_empty());

        let too_big = vec![b' '; K_MAX_EXPERIENCE_LAUNCH_JSON_BYTES + 1];
        let rc_big = mocktail_rust_parse_experience_launch_json_full(
            too_big.as_ptr() as *const c_char,
            too_big.len(),
            &mut data,
            std::ptr::null_mut(),
            None,
            None,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_big, -1);

        let too_long_field = format!(
            r#"{{"placeId":1,"launchData":"{}"}}"#,
            "a".repeat(K_MAX_EXPERIENCE_LAUNCH_STRING_BYTES + 1)
        );
        let rc_str_big = mocktail_rust_parse_experience_launch_json_full(
            too_long_field.as_ptr() as *const c_char,
            too_long_field.len(),
            &mut data,
            std::ptr::null_mut(),
            None,
            None,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_str_big, -6);
    }

    unsafe extern "C" fn collect_browser_str(
        ctx: *mut c_void,
        kind: u32,
        ptr: *const c_char,
        len: usize,
    ) {
        let out = &mut *(ctx as *mut (String, String));
        let s = std::str::from_utf8(slice::from_raw_parts(ptr as *const u8, len)).unwrap();
        if kind == 0 {
            out.0 = s.to_string();
        } else if kind == 1 {
            out.1 = s.to_string();
        }
    }

    #[test]
    fn browser_service_supports_16k_open_url_and_config_optionals() {
        let long_url = format!("https://example.com/{}", "x".repeat(4000));
        let open_json = format!(r#"{{"command":"open","url":"{}","modal":true}}"#, long_url);
        let mut hdr = MocktailRustBrowserServiceCommandHeader::default();
        let mut out_strs = (String::new(), String::new());
        let mut err = [0i8; 256];
        let rc = mocktail_rust_parse_browser_service_command_full(
            open_json.as_ptr() as *const c_char,
            open_json.len(),
            &mut hdr,
            &mut out_strs as *mut _ as *mut c_void,
            Some(collect_browser_str),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(hdr.command_type, 1);
        assert_eq!(hdr.visible, 1);
        assert_eq!(hdr.modal, 1);
        assert_eq!(out_strs.0, long_url);

        let cfg_json = r#"{"command":"config","backNavigationDisabled":true}"#;
        out_strs = (String::new(), String::new());
        let rc_cfg = mocktail_rust_parse_browser_service_command_full(
            cfg_json.as_ptr() as *const c_char,
            cfg_json.len(),
            &mut hdr,
            &mut out_strs as *mut _ as *mut c_void,
            Some(collect_browser_str),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_cfg, 0);
        assert_eq!(hdr.command_type, 2);
        assert_eq!(hdr.has_title, 0);
        assert_eq!(hdr.has_visible, 0);
        assert_eq!(hdr.has_back_navigation_disabled, 1);
        assert_eq!(hdr.back_navigation_disabled, 1);
    }

    #[test]
    fn browser_service_queue_budget_enforces_limits_and_overflow() {
        assert_eq!(mocktail_rust_browser_service_can_queue_outgoing(63, 100, 0, 0, 50), 1);
        assert_eq!(mocktail_rust_browser_service_can_queue_outgoing(63, 100, 1, 0, 50), 0);
        assert_eq!(
            mocktail_rust_browser_service_can_queue_outgoing(0, K_MAX_BROWSER_QUEUED_BYTES - 10, 0, 0, 11),
            0
        );
        assert_eq!(
            mocktail_rust_browser_service_can_queue_outgoing(usize::MAX, 0, 1, 0, 1),
            0
        );
    }

    unsafe extern "C" fn collect_kv(
        ctx: *mut c_void,
        k: *const c_char,
        k_len: usize,
        v: *const c_char,
        v_len: usize,
    ) {
        let out = &mut *(ctx as *mut Vec<(String, String)>);
        let ks = std::str::from_utf8(slice::from_raw_parts(k as *const u8, k_len)).unwrap();
        let vs = std::str::from_utf8(slice::from_raw_parts(v as *const u8, v_len)).unwrap();
        out.push((ks.to_string(), vs.to_string()));
    }

    #[test]
    fn runtime_config_yaml_kv_streams_entries_and_policy_validator_reports_errors() {
        let yaml = b"version: 1\nappearance:\n  theme: dark\n";
        let mut kvs: Vec<(String, String)> = Vec::new();
        let mut err = [0i8; 256];
        let rc = mocktail_rust_parse_runtime_config_yaml_kv(
            yaml.as_ptr(),
            yaml.len(),
            &mut kvs as *mut _ as *mut c_void,
            Some(collect_kv),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert!(kvs.contains(&("MOCKTAIL_THEME".to_string(), "dark".to_string())));

        let mut flags = MocktailRustRuntimeConfigPolicyFlags {
            frame_rate_valid: 1,
            device_profile_valid: 1,
            has_usable_input: 1,
            graphics_backend_valid: 1,
            theme_mode_valid: 1,
            high_dpi_valid: 1,
            vsync_mode_valid: 1,
            present_mode_valid: 1,
            audio_output_device_valid: 1,
            audio_input_device_valid: 1,
            memory_limit_valid: 1,
            game_mode_valid: 1,
            physics_worker_mode_valid: 1,
            fleasion_valid: 1,
            ca_bundle_valid: 1,
            discord_rpc_valid: 1,
        };
        assert_eq!(
            mocktail_rust_validate_runtime_config_policy(&flags, 0, err.as_mut_ptr(), err.len()),
            0
        );
        flags.present_mode_valid = 0;
        assert_eq!(
            mocktail_rust_validate_runtime_config_policy(&flags, 1, err.as_mut_ptr(), err.len()),
            -2
        );
    }
}
