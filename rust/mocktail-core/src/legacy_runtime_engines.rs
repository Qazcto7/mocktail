use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use crate::*;

// ============================================================================
// 70. Environment Abstraction Engine
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_env_has_non_empty(name_ptr: *const c_char) -> c_int {
    if name_ptr.is_null() {
        return 0;
    }
    let name = unsafe { CStr::from_ptr(name_ptr).to_str().unwrap_or("") };
    match std::env::var(name) {
        Ok(val) => if !val.is_empty() { 1 } else { 0 },
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_env_get(
    name_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if name_ptr.is_null() {
        return -1;
    }
    let name = unsafe { CStr::from_ptr(name_ptr).to_str().unwrap_or("") };
    match std::env::var(name) {
        Ok(val) => {
            let bytes = val.as_bytes();
            if !out_len.is_null() {
                unsafe { *out_len = bytes.len(); }
            }
            if bytes.len() + 1 > out_cap {
                return -2;
            }
            if !out_buf.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
                    *out_buf.add(bytes.len()) = 0;
                }
            }
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_env_get_or(
    name_ptr: *const c_char,
    default_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    let name = if name_ptr.is_null() { "" } else { unsafe { CStr::from_ptr(name_ptr).to_str().unwrap_or("") } };
    let def = if default_ptr.is_null() { "" } else { unsafe { CStr::from_ptr(default_ptr).to_str().unwrap_or("") } };
    let val = match std::env::var(name) {
        Ok(v) => if !v.is_empty() { v } else { def.to_string() },
        Err(_) => def.to_string(),
    };
    let bytes = val.as_bytes();
    if !out_len.is_null() {
        unsafe { *out_len = bytes.len(); }
    }
    if bytes.len() + 1 > out_cap {
        return -2;
    }
    if !out_buf.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
            *out_buf.add(bytes.len()) = 0;
        }
    }
    0
}

// ============================================================================
// 71. Command Line Engine
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_command_line_usage(
    program_name_ptr: *const c_char,
    guest_abi_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    let prog = if program_name_ptr.is_null() {
        "mocktail"
    } else {
        let s = unsafe { CStr::from_ptr(program_name_ptr).to_str().unwrap_or("") };
        if s.is_empty() { "mocktail" } else { s }
    };
    let abi = if guest_abi_ptr.is_null() {
        "x86_64"
    } else {
        unsafe { CStr::from_ptr(guest_abi_ptr).to_str().unwrap_or("x86_64") }
    };

    let text = format!(
"Usage: {} [options] [roblox-uri]

Normal startup downloads and activates a verified managed {} Roblox payload automatically.

Options:
  --roblox-lib <path>      Development override for a specific {} libroblox.so
  --headless               Run without creating an SDL window
  --windowed               Force windowed startup (default)
  --graphics <backend>     auto | direct-vulkan | opengl | system | angle-vulkan (default: auto)
  --allow-unverified-build Run a known but unverified Build-ID profile
  --force-run-latest       Download and run the provider latest once without approval; it is not activated
  --launch-uri <uri>       Join from a roblox: or roblox-player: website link
  --help, -h               Show this help

Auth:
  When no saved Roblox session is found, Roblox's welcome screen opens with the native sign-in flow.
  Set MOCKTAIL_NATIVE_LOGIN=0 to use the optional WebView sign-in window.
  Roblox may still open a WebView for required verification challenges.
  New credentials are stored privately.

Additional runtime options are available as MOCKTAIL_* environment variables.
",
        prog, abi, abi
    );

    let bytes = text.as_bytes();
    if !out_len.is_null() {
        unsafe { *out_len = bytes.len(); }
    }
    if bytes.len() + 1 > out_cap {
        return -2;
    }
    if !out_buf.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
            *out_buf.add(bytes.len()) = 0;
        }
    }
    0
}

// ============================================================================
// 72. Frame Rate Policy Helpers
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_frame_rate_policy_name(
    mode: c_int,
    fps: c_int,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    let name = match mode {
        0 => "unmanaged".to_string(),
        1 => "display".to_string(),
        2 => format!("{}", fps),
        3 => "unlimited".to_string(),
        _ => "invalid".to_string(),
    };
    let bytes = name.as_bytes();
    if bytes.len() + 1 > out_cap {
        return -1;
    }
    if !out_buf.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
            *out_buf.add(bytes.len()) = 0;
        }
    }
    0
}

// ============================================================================
// 73. Present Mode Policy & Vulkan WSI Extension Translation
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_normalize_android_swapchain_result(result: i32) -> i32 {
    const VK_SUBOPTIMAL_KHR: i32 = 1000001003;
    const VK_SUCCESS: i32 = 0;
    if result == VK_SUBOPTIMAL_KHR {
        VK_SUCCESS
    } else {
        result
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_translate_android_vulkan_instance_extensions(
    android_exts_ptr: *const *const c_char,
    android_count: usize,
    host_wsi_exts_ptr: *const *const c_char,
    host_count: usize,
    out_exts_buf: *mut *mut c_char,
    out_cap: usize,
    out_count: *mut usize,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    const ANDROID_SURFACE: &str = "VK_KHR_android_surface";
    let mut requested_android_surface = false;
    let mut translated: Vec<String> = Vec::new();

    if android_count > 0 && android_exts_ptr.is_null() {
        copy_error(err_buf, err_cap, "Vulkan extension names must not be empty");
        return -1;
    }

    for i in 0..android_count {
        let p = unsafe { *android_exts_ptr.add(i) };
        if p.is_null() {
            copy_error(err_buf, err_cap, "Vulkan extension names must not be empty");
            return -1;
        }
        let name = unsafe { CStr::from_ptr(p).to_str().unwrap_or("") };
        if name.is_empty() {
            copy_error(err_buf, err_cap, "Vulkan extension names must not be empty");
            return -1;
        }
        if name == ANDROID_SURFACE {
            requested_android_surface = true;
            continue;
        }
        if !translated.iter().any(|e| e == name) {
            translated.push(name.to_string());
        }
    }

    if requested_android_surface {
        if host_count == 0 {
            copy_error(err_buf, err_cap, "Android Vulkan surface requested without host WSI extensions");
            return -2;
        }
        if host_wsi_exts_ptr.is_null() {
            copy_error(err_buf, err_cap, "Vulkan extension names must not be empty");
            return -1;
        }
        for i in 0..host_count {
            let p = unsafe { *host_wsi_exts_ptr.add(i) };
            if p.is_null() {
                copy_error(err_buf, err_cap, "Vulkan extension names must not be empty");
                return -1;
            }
            let name = unsafe { CStr::from_ptr(p).to_str().unwrap_or("") };
            if name.is_empty() {
                copy_error(err_buf, err_cap, "Vulkan extension names must not be empty");
                return -1;
            }
            if !translated.iter().any(|e| e == name) {
                translated.push(name.to_string());
            }
        }
    }

    if !out_count.is_null() {
        unsafe { *out_count = translated.len(); }
    }
    if translated.len() > out_cap {
        return -5;
    }

    for (idx, item) in translated.into_iter().enumerate() {
        if !out_exts_buf.is_null() {
            let c_str = match std::ffi::CString::new(item) {
                Ok(c) => c,
                Err(_) => return -3,
            };
            unsafe {
                *out_exts_buf.add(idx) = c_str.into_raw();
            }
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(ptr);
        }
    }
}

// ============================================================================
// 74. Display Refresh Capabilities Engine
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_normalize_display_refresh_capabilities(
    current_hz: f32,
    supported_hz: *const f32,
    count: usize,
    out_hz: *mut f32,
    out_cap: usize,
    out_count: *mut usize,
) -> i32 {
    if !current_hz.is_finite() || current_hz <= 0.0 {
        if !out_count.is_null() {
            unsafe { *out_count = 0 };
        }
        return 0;
    }

    let mut list = Vec::new();
    if !supported_hz.is_null() && count > 0 {
        let slice = unsafe { std::slice::from_raw_parts(supported_hz, count) };
        for &rate in slice {
            if rate.is_finite() && rate > 0.0 {
                list.push(rate);
            }
        }
    }
    list.push(current_hz);
    list.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    const DUPLICATE_TOLERANCE_HZ: f32 = 0.01;
    let mut deduplicated: Vec<f32> = Vec::new();
    for rate in list {
        if deduplicated.is_empty()
            || (deduplicated.last().unwrap() - rate).abs() > DUPLICATE_TOLERANCE_HZ
        {
            deduplicated.push(rate);
        }
    }

    if !out_count.is_null() {
        unsafe { *out_count = deduplicated.len() };
    }
    if !out_hz.is_null() && out_cap > 0 {
        let copy_len = std::cmp::min(deduplicated.len(), out_cap);
        unsafe {
            std::ptr::copy_nonoverlapping(deduplicated.as_ptr(), out_hz, copy_len);
        }
    }
    0
}

// ============================================================================
// 75. Platform Application Metadata & Identity
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_metadata_identity(
    name_buf: *mut c_char,
    name_cap: usize,
    id_buf: *mut c_char,
    id_cap: usize,
    type_buf: *mut c_char,
    type_cap: usize,
) -> i32 {
    copy_to_c_buffer("Mocktail", name_buf, name_cap);
    copy_to_c_buffer("space.bigrat.mocktail", id_buf, id_cap);
    copy_to_c_buffer("game", type_buf, type_cap);
    0
}

// ============================================================================
// 76. SDL Window Icon PNG Header Verifier
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_window_icon_png_header(
    data: *const u8,
    size: usize,
    out_width: *mut u32,
    out_height: *mut u32,
) -> i32 {
    const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.is_null() || size < 24 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    if &slice[0..8] != PNG_MAGIC {
        return -2;
    }
    if &slice[12..16] != b"IHDR" {
        return -3;
    }
    let width = u32::from_be_bytes([slice[16], slice[17], slice[18], slice[19]]);
    let height = u32::from_be_bytes([slice[20], slice[21], slice[22], slice[23]]);
    if width == 0 || height == 0 {
        return -4;
    }
    if !out_width.is_null() {
        unsafe { *out_width = width };
    }
    if !out_height.is_null() {
        unsafe { *out_height = height };
    }
    0
}

// ============================================================================
// 77. Supported Launch Policy Defaults Table
// ============================================================================

const INTERACTIVE_DEFAULTS: &[(&str, &str)] = &[
    ("MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP", "1"),
    ("MOCKTAIL_VALIDATE_ROBLOX_COOKIE", "0"),
    ("MOCKTAIL_ENGINE_DETACH", "0"),
    ("MOCKTAIL_CALL_REAL_APP_BRIDGE_INIT", "1"),
    ("MOCKTAIL_CALL_REAL_APP_BRIDGE_INIT_THREAD", "0"),
    ("MOCKTAIL_SKIP_LIBROBLOX_CTORS", "0"),
    ("MOCKTAIL_HOST_JNI_SINGLETON_SEED", "0"),
    ("MOCKTAIL_INIT_CLIENT_SETTINGS", "1"),
    ("MOCKTAIL_HEADLESS", "0"),
    ("MOCKTAIL_STARTUP_THREAD_TIMEOUT_MS", "120000"),
    ("MOCKTAIL_CALL_REAL_APP_BRIDGE_START", "1"),
    ("MOCKTAIL_STEP_START_APP_WITH_PARAMS", "1"),
    ("MOCKTAIL_UPDATE_SURFACE_APP_AFTER_START_APP", "1"),
    ("MOCKTAIL_CALL_REAL_APP_BRIDGE_UPDATE_SURFACE", "1"),
    ("MOCKTAIL_START_LUA_APP_DM", "1"),
    ("MOCKTAIL_STEP_START_LUA_APP_DM", "1"),
    ("MOCKTAIL_POST_CLIENT_SETTINGS", "1"),
    ("MOCKTAIL_STEP_POST_CLIENT_SETTINGS", "1"),
    ("MOCKTAIL_FETCH_CLIENT_SETTINGS", "1"),
    ("MOCKTAIL_START_LUA_APP_DM_AFTER_START_APP", "0"),
    ("MOCKTAIL_START_LUA_APP_DM_INLINE", "1"),
    ("MOCKTAIL_START_LUA_APP_DM_DELAY_MS", "0"),
    ("MOCKTAIL_START_GAME_WITH_PARAM", "0"),
    ("MOCKTAIL_RESUME_GAME_WITH_PLATFORM_PARAMS_AFTER_START_GAME", "0"),
    ("MOCKTAIL_SEND_APP_READY", "0"),
    ("MOCKTAIL_SEND_GAME_LOADED", "0"),
    ("MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS", "0"),
];

#[no_mangle]
pub extern "C" fn mocktail_rust_supported_launch_defaults_count(interactive: i32) -> usize {
    if interactive != 0 {
        INTERACTIVE_DEFAULTS.len()
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_supported_launch_default_entry(
    interactive: i32,
    index: usize,
    key_buf: *mut c_char,
    key_cap: usize,
    val_buf: *mut c_char,
    val_cap: usize,
) -> i32 {
    let list = if interactive != 0 {
        INTERACTIVE_DEFAULTS
    } else {
        return -1;
    };
    if index >= list.len() {
        return -2;
    }
    let (k, v) = list[index];
    copy_to_c_buffer(k, key_buf, key_cap);
    copy_to_c_buffer(v, val_buf, val_cap);
    0
}

// ============================================================================
// 78. Platform Profile Revision Generator & Android Path Normalizer
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_build_platform_profile_revision(
    device_profile: *const c_char,
    touch: i32,
    mouse: i32,
    keyboard: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let prof = if !device_profile.is_null() {
        unsafe { CStr::from_ptr(device_profile) }.to_str().unwrap_or("")
    } else {
        ""
    };
    let rev = format!(
        "device-v1-{}-t{}-m{}-k{}",
        prof,
        if touch != 0 { "1" } else { "0" },
        if mouse != 0 { "1" } else { "0" },
        if keyboard != 0 { "1" } else { "0" }
    );
    copy_to_c_buffer(&rev, out_buf, out_cap);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_translate_android_files_path(
    configured: *const c_char,
    data_root: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    if configured.is_null() || data_root.is_null() {
        return -1;
    }
    let conf = unsafe { CStr::from_ptr(configured) }.to_str().unwrap_or("");
    let root = unsafe { CStr::from_ptr(data_root) }.to_str().unwrap_or("");

    for prefix in &["/data/user/0/com.roblox.client", "/data/data/com.roblox.client"] {
        if conf == *prefix {
            copy_to_c_buffer(root, out_buf, out_cap);
            return 0;
        }
        if conf.starts_with(prefix) && conf.as_bytes().get(prefix.len()) == Some(&b'/') {
            let rel = &conf[prefix.len() + 1..];
            let joined = std::path::Path::new(root).join(rel);
            copy_to_c_buffer(&joined.to_string_lossy(), out_buf, out_cap);
            return 0;
        }
    }
    let p = std::path::Path::new(conf);
    if p.is_absolute() {
        copy_to_c_buffer(conf, out_buf, out_cap);
        return 0;
    }
    -2
}

#[no_mangle]
pub extern "C" fn mocktail_rust_has_path_prefix(
    path: *const c_char,
    prefix: *const c_char,
) -> i32 {
    if path.is_null() || prefix.is_null() {
        return 0;
    }
    let p_str = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or("");
    let pref_str = unsafe { CStr::from_ptr(prefix) }.to_str().unwrap_or("");
    let p = std::path::Path::new(p_str);
    let pref = std::path::Path::new(pref_str);
    if p.starts_with(pref) {
        1
    } else {
        0
    }
}

// ============================================================================
// 79. Platform Cache Migration Fingerprint Validator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_platform_cache_fingerprint(
    json_str: *const c_char,
    json_len: usize,
    revision_buf: *mut c_char,
    revision_cap: usize,
) -> i32 {
    if json_str.is_null() || json_len == 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(json_str as *const u8, json_len) };
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => return -2,
    };
    let val: serde_json::Value = match runtime_policies::parse_json_value_str(s, true) {
        Some(v) => v,
        None => return -3,
    };
    if let serde_json::Value::Object(map) = val {
        if map.get("schema_version").and_then(|v| v.as_i64()) != Some(1) {
            return -4;
        }
        if let Some(rev) = map.get("profile_revision").and_then(|v| v.as_str()) {
            copy_to_c_buffer(rev, revision_buf, revision_cap);
            return 0;
        }
    }
    -5
}

// ============================================================================
// 80. Roblox Browser Service Command Parser
// ============================================================================

#[repr(C)]
pub struct MocktailRustBrowserServiceOpenCommand {
    pub url: [c_char; 1024],
    pub title: [c_char; 512],
    pub has_title: i32,
    pub visible: i32,
    pub modal: i32,
    pub back_navigation_disabled: i32,
    pub show_domain_as_title: i32,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_browser_service_command(
    json_str: *const c_char,
    json_len: usize,
    out_command_type: *mut i32,
    out_cmd: *mut MocktailRustBrowserServiceOpenCommand,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    const MAX_PAYLOAD: usize = 64 * 1024;
    if json_str.is_null() || json_len == 0 || json_len > MAX_PAYLOAD {
        copy_error(err_buf, err_cap, "BrowserService command JSON size is invalid");
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(json_str as *const u8, json_len) };
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "BrowserService command payload is not a JSON object");
            return -2;
        }
    };
    let val: serde_json::Value = match serde_json::from_str(s) {
        Ok(serde_json::Value::Object(m)) => serde_json::Value::Object(m),
        _ => {
            copy_error(err_buf, err_cap, "BrowserService command payload is not a JSON object");
            return -2;
        }
    };
    let obj = val.as_object().unwrap();
    let cmd = match obj.get("command").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => {
            copy_error(err_buf, err_cap, "BrowserService command requires a string command");
            return -3;
        }
    };

    if cmd == "open" {
        if !out_command_type.is_null() {
            unsafe { *out_command_type = 1 };
        }
        let url = match obj.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                copy_error(err_buf, err_cap, "BrowserService open command requires a string url");
                return -4;
            }
        };
        if url.is_empty() || url.len() > 1024 || url.bytes().any(|b| b < 0x20 || b == 0x7f) {
            copy_error(err_buf, err_cap, "BrowserService open URL is invalid");
            return -5;
        }
        let title_str = if let Some(t_val) = obj.get("title") {
            match t_val.as_str() {
                Some(t) => {
                    if t.len() > 512 || t.bytes().any(|b| b < 0x20 || b == 0x7f) {
                        copy_error(err_buf, err_cap, "BrowserService command field title is invalid");
                        return -5;
                    }
                    t
                }
                None => {
                    copy_error(err_buf, err_cap, "BrowserService command field title must be a string");
                    return -5;
                }
            }
        } else {
            ""
        };

        let visible_val = if let Some(v) = obj.get("visible") {
            match v.as_bool() {
                Some(b) => b,
                None => {
                    copy_error(err_buf, err_cap, "BrowserService command field visible must be a boolean");
                    return -5;
                }
            }
        } else {
            true
        };

        let modal_val = if let Some(v) = obj.get("modal") {
            match v.as_bool() {
                Some(b) => b,
                None => {
                    copy_error(err_buf, err_cap, "BrowserService command field modal must be a boolean");
                    return -5;
                }
            }
        } else {
            false
        };

        let back_val = if let Some(v) = obj.get("backNavigationDisabled") {
            match v.as_bool() {
                Some(b) => b,
                None => {
                    copy_error(err_buf, err_cap, "BrowserService command field backNavigationDisabled must be a boolean");
                    return -5;
                }
            }
        } else {
            false
        };

        let domain_val = if let Some(v) = obj.get("showDomainAsTitle") {
            match v.as_bool() {
                Some(b) => b,
                None => {
                    copy_error(err_buf, err_cap, "BrowserService command field showDomainAsTitle must be a boolean");
                    return -5;
                }
            }
        } else {
            false
        };

        if !out_cmd.is_null() {
            unsafe {
                let cmd_ref = &mut *out_cmd;
                copy_to_c_buffer(url, cmd_ref.url.as_mut_ptr(), cmd_ref.url.len());
                copy_to_c_buffer(title_str, cmd_ref.title.as_mut_ptr(), cmd_ref.title.len());
                cmd_ref.has_title = if obj.contains_key("title") { 1 } else { 0 };
                cmd_ref.visible = if visible_val { 1 } else { 0 };
                cmd_ref.modal = if modal_val { 1 } else { 0 };
                cmd_ref.back_navigation_disabled = if back_val { 1 } else { 0 };
                cmd_ref.show_domain_as_title = if domain_val { 1 } else { 0 };
            }
        }
        return 0;
    } else if cmd == "config" {
        if !out_command_type.is_null() {
            unsafe { *out_command_type = 2 };
        }
        return 0;
    }

    copy_error(err_buf, err_cap, "BrowserService command is unsupported");
    -6
}

// ============================================================================
// 81. Roblox Text Display State & UTF-16 Cursor Engine
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_utf8_byte_for_utf16_cursor(
    text: *const c_char,
    size: usize,
    requested_utf16: i32,
    out_codepoints: *mut usize,
) -> usize {
    if text.is_null() || size == 0 {
        if !out_codepoints.is_null() {
            unsafe { *out_codepoints = 0 };
        }
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(text as *const u8, size) };
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => {
            if !out_codepoints.is_null() {
                unsafe { *out_codepoints = 0 };
            }
            return 0;
        }
    };
    let target = if requested_utf16 > 0 { requested_utf16 as usize } else { 0 };
    let mut utf16_count = 0;
    let mut byte_count = 0;
    let mut codepoint_count = 0;

    for ch in s.chars() {
        let u16_len = ch.len_utf16();
        if utf16_count + u16_len > target {
            break;
        }
        utf16_count += u16_len;
        byte_count += ch.len_utf8();
        codepoint_count += 1;
    }

    if !out_codepoints.is_null() {
        unsafe { *out_codepoints = codepoint_count };
    }
    byte_count
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_geometry_intersects_viewport(
    area_x: i32,
    area_y: i32,
    area_w: i32,
    area_h: i32,
    vp_w: i32,
    vp_h: i32,
) -> i32 {
    if vp_w <= 0 || vp_h <= 0 || area_w <= 0 || area_h <= 0 {
        return 0;
    }
    let right = (area_x as i64) + (area_w as i64);
    let bottom = (area_y as i64) + (area_h as i64);
    if right > 0 && bottom > 0 && area_x < vp_w && area_y < vp_h {
        1
    } else {
        0
    }
}

// ============================================================================
// 82. Roblox Fullscreen Machine Code Setter Contract Verifier
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_fullscreen_setter_contract(
    code: *const u8,
    size: usize,
) -> i32 {
    const K_SETTER_CONTRACT_BYTES: usize = 96;
    if code.is_null() || size < K_SETTER_CONTRACT_BYTES {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(code, size) };
    const PROLOGUE: [u8; 4] = [0x55, 0x48, 0x89, 0xe5];
    const CAPTURE_BOOL: [u8; 2] = [0x89, 0xf3];
    const CMP_LEGACY: [u8; 6] = [0x38, 0x98, 0x59, 0x01, 0x00, 0x00];
    const MOV_LEGACY: [u8; 6] = [0x88, 0x98, 0x59, 0x01, 0x00, 0x00];
    const CMP_CURRENT: [u8; 6] = [0x38, 0x98, 0x61, 0x01, 0x00, 0x00];
    const MOV_CURRENT: [u8; 6] = [0x88, 0x98, 0x61, 0x01, 0x00, 0x00];

    fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    if !slice.starts_with(&PROLOGUE) {
        return 0;
    }
    let cap_slice = &slice[..std::cmp::min(size, 24)];
    if !contains_sub(cap_slice, &CAPTURE_BOOL) {
        return 0;
    }
    let has_legacy = contains_sub(slice, &CMP_LEGACY) && contains_sub(slice, &MOV_LEGACY);
    let has_curr = contains_sub(slice, &CMP_CURRENT) && contains_sub(slice, &MOV_CURRENT);
    if has_legacy || has_curr {
        1
    } else {
        0
    }
}

// ============================================================================
// 83. Window Pointer Capture Evaluation Engine
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_pointer_capture_evaluate(
    focused: i32,
    query_ok: i32,
    locked_center: i32,
    right_button_held: i32,
    text_input_active: i32,
    out_capture_requested: *mut i32,
    out_cursor_visible: *mut i32,
) -> i32 {
    if focused == 0 {
        if !out_capture_requested.is_null() {
            unsafe { *out_capture_requested = 0 };
        }
        if !out_cursor_visible.is_null() {
            unsafe { *out_cursor_visible = 1 };
        }
        return 0;
    }
    let client_active = query_ok != 0;
    let native_capture_active = client_active && (locked_center != 0);
    let right_drag_active = right_button_held != 0;
    let capture_requested = native_capture_active || (right_drag_active && text_input_active == 0);
    let cursor_visible = !client_active && !capture_requested;

    if !out_capture_requested.is_null() {
        unsafe { *out_capture_requested = if capture_requested { 1 } else { 0 } };
    }
    if !out_cursor_visible.is_null() {
        unsafe { *out_cursor_visible = if cursor_visible { 1 } else { 0 } };
    }
    0
}

// ============================================================================
// 84. Window Text Input Type Mapper & Area Clamper
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_map_roblox_text_input_type(input_type: i32) -> i32 {
    match input_type {
        2 | 4 | 8 => 2, // Number
        3 => 3,         // Email
        5 | 9 | 10 => 4,// Password
        6 => 5,         // Username
        _ => 1,         // Text
    }
}

// ============================================================================
// 85. Bionic Sysconf Parameter Lookup
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_bionic_sysconf_translate_name(
    bionic_name: i32,
    out_standard_sc: *mut i32,
    out_fixed_value: *mut i64,
) -> i32 {
    match bionic_name {
        0x0006 => {
            if !out_fixed_value.is_null() {
                unsafe { *out_fixed_value = 100 };
            }
            1 // Fixed value
        }
        0x0000 | 0x0005 | 0x000b | 0x0026 | 0x0027 | 0x0028 | 0x0060 | 0x0061 | 0x0062 | 0x0063 => {
            if !out_standard_sc.is_null() {
                unsafe { *out_standard_sc = bionic_name };
            }
            0 // Standard sysconf
        }
        _ => -1, // Invalid
    }
}

// ============================================================================
// 86. Build Profile Parser & Hex RVA Reader
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_normalize_build_id(
    build_id: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    if build_id.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(build_id) }.to_str().unwrap_or("");
    let lower = s.to_ascii_lowercase();
    copy_to_c_buffer(&lower, out_buf, out_cap);
    0
}

pub(crate) fn parse_status_str(s: &str) -> i32 {
    match s {
        "supported" => 0,
        "experimental" => 1,
        "legacy-researched" => 2,
        "unverified" => 3,
        _ => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_status_string(status: *const c_char) -> i32 {
    if status.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(status) }.to_str().unwrap_or("");
    parse_status_str(s)
}

pub(crate) fn parse_hex_rva_str(s: &str) -> Result<usize, i32> {
    let trimmed = s.trim();
    if !trimmed.starts_with("0x") && !trimmed.starts_with("0X") {
        return Err(-2);
    }
    let hex_part = &trimmed[2..];
    if hex_part.is_empty() {
        return Err(-3);
    }
    match usize::from_str_radix(hex_part, 16) {
        Ok(0) => Err(-4),
        Ok(val) => Ok(val),
        Err(_) => Err(-5),
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_hex_rva(
    hex_str: *const c_char,
    out_rva: *mut usize,
) -> i32 {
    if hex_str.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(hex_str) }.to_str().unwrap_or("");
    match parse_hex_rva_str(s) {
        Ok(val) => {
            if !out_rva.is_null() {
                unsafe { *out_rva = val };
            }
            0
        }
        Err(rc) => rc,
    }
}

// ============================================================================
// 87. ELF Build ID Hex Validator
// ============================================================================

pub(crate) fn is_valid_build_id_bytes(slice: &[u8]) -> bool {
    slice.len() >= 8
        && slice.len() <= 128
        && slice.len() % 2 == 0
        && slice.iter().all(|&b| b.is_ascii_hexdigit())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_build_id(
    build_id: *const c_char,
    len: usize,
) -> i32 {
    if build_id.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(build_id as *const u8, len) };
    i32::from(is_valid_build_id_bytes(slice))
}

// ============================================================================
// 88. HTTP Client Spin Guard Rate Limiter
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_http_spin_limiter_observe(
    inout_op_count: *mut u64,
    inout_checkpoint_ns: *mut u64,
    now_ns: u64,
    batch_size: u64,
    batch_interval_ns: u64,
) -> u64 {
    if inout_op_count.is_null() || inout_checkpoint_ns.is_null() {
        return 0;
    }
    let op_count = unsafe { &mut *inout_op_count };
    let checkpoint = unsafe { &mut *inout_checkpoint_ns };

    *op_count += 1;
    if *op_count < batch_size {
        return 0;
    }
    *op_count = 0;

    if now_ns == 0 || *checkpoint == 0 || now_ns < *checkpoint {
        *checkpoint = now_ns;
        return 0;
    }
    let elapsed = now_ns - *checkpoint;
    if elapsed >= batch_interval_ns {
        *checkpoint = now_ns;
        return 0;
    }
    let pause_ns = batch_interval_ns - elapsed;
    *checkpoint = now_ns + pause_ns;
    pause_ns
}

// ============================================================================
// 89. Owned Pthread Wait Status Name
// ============================================================================

fn owned_pthread_status_name_static(status: i32) -> &'static [u8] {
    match status {
        0 => b"Joined\0",
        1 => b"TimedOut\0",
        2 => b"PlatformError\0",
        _ => b"Unknown\0",
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_owned_pthread_status_name_ptr(status: i32) -> *const c_char {
    owned_pthread_status_name_static(status).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_owned_pthread_status_name(
    status: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let bytes = owned_pthread_status_name_static(status);
    let name = unsafe { std::str::from_utf8_unchecked(&bytes[..bytes.len() - 1]) };
    copy_to_c_buffer(name, out_buf, out_cap)
}

// ============================================================================
// 90. Failure Dialog Protocol & Environment Evaluator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_failure_dialogs_enabled(
    disabled_by_env: i32,
    is_canary: i32,
    is_headless: i32,
    has_display: i32,
    has_wayland: i32,
) -> i32 {
    if disabled_by_env != 0 || is_canary != 0 || is_headless != 0 {
        return 0;
    }
    if has_display != 0 || has_wayland != 0 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_failure_dialog_format_packet(
    packet_type: c_char,
    message: *const c_char,
    max_bytes: usize,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let msg = if !message.is_null() {
        unsafe { CStr::from_ptr(message) }.to_str().unwrap_or("")
    } else {
        ""
    };
    let clamped_msg = if msg.len() > max_bytes {
        &msg[..max_bytes]
    } else {
        msg
    };
    let total_len = 1 + clamped_msg.len();
    if !out_len.is_null() {
        unsafe { *out_len = total_len };
    }
    if !out_buf.is_null() && out_cap >= total_len {
        unsafe {
            *out_buf = packet_type;
            std::ptr::copy_nonoverlapping(
                clamped_msg.as_ptr() as *const c_char,
                out_buf.add(1),
                clamped_msg.len(),
            );
        }
        return 0;
    }
    -1
}

// ============================================================================
// 91. APK Provider Failure Aggregator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_apk_provider_append_failure(
    existing: *const c_char,
    provider_name: *const c_char,
    failure_msg: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let ex = if !existing.is_null() {
        unsafe { CStr::from_ptr(existing) }.to_str().unwrap_or("")
    } else {
        ""
    };
    let prov = if !provider_name.is_null() {
        unsafe { CStr::from_ptr(provider_name) }.to_str().unwrap_or("")
    } else {
        "unknown"
    };
    let fail = if !failure_msg.is_null() {
        unsafe { CStr::from_ptr(failure_msg) }.to_str().unwrap_or("")
    } else {
        ""
    };

    let result = if ex.is_empty() {
        format!("{}: {}", prov, fail)
    } else {
        format!("{}; {}: {}", ex, prov, fail)
    };

    if !out_len.is_null() {
        unsafe { *out_len = result.len() };
    }
    copy_to_c_buffer(&result, out_buf, out_cap);
    0
}

// ============================================================================
// 92. Update Configuration YAML Parser
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateConfigData {
    pub automatic: bool,
    pub launch_after_update: bool,
    pub source: String,
    pub file_loaded: bool,
    pub warnings: Vec<String>,
}

pub(crate) fn parse_update_config_yaml_str(s: &str) -> Result<(bool, bool, String), (i32, String)> {
    let val: serde_yaml::Value = serde_yaml::from_str(s)
        .map_err(|_| (-3, "cannot parse update configuration".to_string()))?;
    let map = val
        .as_mapping()
        .ok_or_else(|| (-4, "configuration root must be a mapping".to_string()))?;

    if let Some(ver) = map.get(&serde_yaml::Value::String("version".to_string())) {
        let ver_str = match ver {
            serde_yaml::Value::String(s) => s.as_str(),
            serde_yaml::Value::Number(n) => {
                if n.as_i64() == Some(1) { "1" } else { "invalid" }
            }
            _ => "invalid",
        };
        if ver_str != "1" {
            return Err((-5, "only configuration version 1 is supported".to_string()));
        }
    }

    let updates = map
        .get(&serde_yaml::Value::String("updates".to_string()))
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| (-6, "updates must be a mapping".to_string()))?;

    let mut auto_val = true;
    let mut launch_val = true;
    let mut source_val = "auto".to_string();

    for (k, v) in updates {
        let key_str = k
            .as_str()
            .ok_or_else(|| (-7, "updates contains an empty or duplicate key".to_string()))?;
        match key_str {
            "automatic" => {
                auto_val = v
                    .as_bool()
                    .ok_or_else(|| (-8, "updates.automatic must be true or false".to_string()))?;
            }
            "launch_after_update" => {
                launch_val = v.as_bool().ok_or_else(|| {
                    (-9, "updates.launch_after_update must be true or false".to_string())
                })?;
            }
            "source" => match v.as_str() {
                Some(src) if src == "auto" || src == "apk-pure" => {
                    source_val = src.to_string();
                }
                _ => {
                    return Err((
                        -10,
                        "updates.source must be auto or apk-pure in the native updater".to_string(),
                    ));
                }
            },
            "testing_latest_only" => {}
            _ => {
                return Err((-11, format!("unknown updates key: {key_str}")));
            }
        }
    }

    Ok((auto_val, launch_val, source_val))
}

pub(crate) fn load_update_config_file(path: &Path) -> Result<UpdateConfigData, String> {
    let bytes = match crate::unix_ipc::read_regular_file_limited(
        path,
        1024 * 1024,
        false,
        true,
    ) {
        Ok(b) => b,
        Err(crate::unix_ipc::ReadFileError::NotFound) => {
            return Ok(UpdateConfigData {
                automatic: true,
                launch_after_update: false,
                source: "apk-pure".to_string(),
                file_loaded: false,
                warnings: Vec::new(),
            });
        }
        Err(crate::unix_ipc::ReadFileError::OpenFailed(_)) => {
            return Err(format!("cannot open update configuration: {}", path.display()));
        }
        Err(crate::unix_ipc::ReadFileError::InvalidFile) => {
            return Err("update configuration must be a regular file no larger than 1 MiB".to_string());
        }
        Err(crate::unix_ipc::ReadFileError::ReadFailed) => {
            return Err(format!("cannot read update configuration: {}", path.display()));
        }
    };
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| "cannot parse update configuration".to_string())?;
    let (automatic, launch_after_update, source) =
        parse_update_config_yaml_str(s).map_err(|(_, msg)| msg)?;
    let mut warnings = Vec::new();
    if s.contains("testing_latest_only") {
        warnings.push("updates.testing_latest_only is no longer supported and is ignored".to_string());
    }
    Ok(UpdateConfigData {
        automatic,
        launch_after_update,
        source,
        file_loaded: true,
        warnings,
    })
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_update_config_yaml(
    yaml_str: *const c_char,
    yaml_len: usize,
    out_auto: *mut i32,
    out_launch_after: *mut i32,
    source_buf: *mut c_char,
    source_cap: usize,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if yaml_str.is_null() || yaml_len == 0 {
        copy_error(err_buf, err_cap, "cannot parse update configuration");
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(yaml_str as *const u8, yaml_len) };
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "cannot parse update configuration");
            return -2;
        }
    };
    let (auto_val, launch_val, source_val) = match parse_update_config_yaml_str(s) {
        Ok(parsed) => parsed,
        Err((code, msg)) => {
            copy_error(err_buf, err_cap, &msg);
            return code;
        }
    };
    if !out_auto.is_null() {
        unsafe { *out_auto = if auto_val { 1 } else { 0 } };
    }
    if !out_launch_after.is_null() {
        unsafe { *out_launch_after = if launch_val { 1 } else { 0 } };
    }
    copy_to_c_buffer(&source_val, source_buf, source_cap);
    0
}

// ============================================================================
// 93. Unsafe Latest Environment Filter & Builder
// ============================================================================

pub(crate) const OVERRIDDEN_ENV_VAR_BYTES: &[&[u8]] = &[
    b"ROBLOX_LIB_PATH",
    b"MOCKTAIL_ASSET_ROOT",
    b"MOCKTAIL_ASSET_PATH",
    b"MOCKTAIL_COMPATIBILITY_MANIFEST",
    b"MOCKTAIL_HOST_ABI_PROFILE_FILE",
    b"MOCKTAIL_HOST_ABI_CANARY",
    b"MOCKTAIL_ALLOW_CANDIDATE_HOST_ABI",
    b"MOCKTAIL_HOST_ABI_APPROVAL_RECEIPT",
    b"MOCKTAIL_SKIP_UPDATE_CHECK",
    b"MOCKTAIL_UNSAFE_LATEST",
];

#[no_mangle]
pub extern "C" fn mocktail_rust_is_overridden_environment_var(entry: *const c_char) -> i32 {
    if entry.is_null() {
        return 0;
    }
    let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
    if OVERRIDDEN_ENV_VAR_BYTES
        .iter()
        .any(|&var| crate::unix_ipc::is_env_entry(bytes, var))
    {
        1
    } else {
        0
    }
}

// ============================================================================
// 94. Canary Readiness Backend & Audio Log Validator
// ============================================================================

// Readiness canary FFI (`mocktail_rust_canary_backend_parse`,
// `mocktail_rust_canary_backend_name`, `mocktail_rust_validate_canary_audio_log`,
// `mocktail_rust_validate_readiness_log`, `mocktail_rust_validate_teardown_crash_log`,
// and `mocktail_rust_run_readiness_canary`) lives in `crate::readiness_canary`.

// ============================================================================
// 95. Game Session State Machine & Transition Evaluator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_game_session_can_transition(
    current_state: i32,
    target_state: i32,
) -> i32 {
    if current_state == target_state {
        return 1;
    }
    if current_state == 7 {
        return 0; // Terminal stopped
    }
    if target_state == 6 || target_state == 7 {
        return 1;
    }
    match (current_state, target_state) {
        (0, 1) => 1,
        (1, 2) => 1,
        (2, 3) => 1,
        (3, 4) => 1,
        (4, 5) => 1,
        _ => 0,
    }
}

// ============================================================================
// 96. Capability Resolver Flags Evaluator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_evaluate_startup_flags(
    has_surface_app: i32,
    has_message_pump: i32,
    has_start_game: i32,
    has_surface_game: i32,
    out_flags: *mut i32,
) {
    if !out_flags.is_null() {
        let mut flags = 0;
        if has_surface_app != 0 { flags |= 1 << 0; }
        if has_message_pump != 0 { flags |= 1 << 1; }
        if has_start_game != 0 { flags |= 1 << 2; }
        if has_surface_game != 0 { flags |= 1 << 3; }
        unsafe { *out_flags = flags };
    }
}

// ============================================================================
// 97. Roblox App Lifecycle Status Name Engine
// ============================================================================

fn app_lifecycle_status_name_static(status: i32) -> &'static [u8] {
    match status {
        0 => b"Uninitialized\0",
        1 => b"Ready\0",
        2 => b"MissingRequiredSymbols\0",
        _ => b"Unknown\0",
    }
}

fn app_shutdown_status_name_static(status: i32) -> &'static [u8] {
    match status {
        0 => b"Completed\0",
        1 => b"AlreadyStopped\0",
        2 => b"ShutdownInProgress\0",
        3 => b"MissingRequiredSymbols\0",
        4 => b"InvalidJniState\0",
        5 => b"ReasonAllocationFailed\0",
        6 => b"OperationTimedOut\0",
        _ => b"Unknown\0",
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_app_lifecycle_status_name_ptr(status: i32) -> *const c_char {
    app_lifecycle_status_name_static(status).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_app_shutdown_status_name_ptr(status: i32) -> *const c_char {
    app_shutdown_status_name_static(status).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_app_lifecycle_status_name(
    status: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let bytes = app_lifecycle_status_name_static(status);
    let name = unsafe { std::str::from_utf8_unchecked(&bytes[..bytes.len() - 1]) };
    copy_to_c_buffer(name, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_app_shutdown_status_name(
    status: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let bytes = app_shutdown_status_name_static(status);
    let name = unsafe { std::str::from_utf8_unchecked(&bytes[..bytes.len() - 1]) };
    copy_to_c_buffer(name, out_buf, out_cap)
}

// ============================================================================
// 98. Fresh Start Game Params String Encoder
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_utf8_to_utf16_surrogates(
    utf8_str: *const c_char,
    utf8_len: usize,
    out_utf16: *mut u16,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    const MAX_FIELD_BYTES: usize = 16 * 1024;
    if utf8_str.is_null() || utf8_len > MAX_FIELD_BYTES {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(utf8_str as *const u8, utf8_len) };
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => return -2,
    };
    let utf16_vec: Vec<u16> = s.encode_utf16().collect();
    if !out_len.is_null() {
        unsafe { *out_len = utf16_vec.len() };
    }
    if !out_utf16.is_null() && out_cap >= utf16_vec.len() {
        unsafe {
            std::ptr::copy_nonoverlapping(utf16_vec.as_ptr(), out_utf16, utf16_vec.len());
        }
        return 0;
    }
    if out_cap < utf16_vec.len() {
        return -3;
    }
    0
}

// ============================================================================
// 99. Roblox Permissions Answer Formatter
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_format_permissions_reply(
    method: usize,
    mic_enabled: i32,
    request_json: *const c_char,
    out_body: *mut c_char,
    body_cap: usize,
    body_len: *mut usize,
    out_code: *mut i32,
    out_outcome: *mut c_char,
    outcome_cap: usize,
) -> i32 {
    const K_MICROPHONE: &str = "MICROPHONE_ACCESS";
    const K_LOCAL_NETWORK: &str = "LOCAL_NETWORK";
    let support = method == 0;
    let upsell = method >= 3;

    let (body, code, outcome) = if support {
        if request_json.is_null() || mocktail_rust_validate_json_depth(request_json, 8) == 0 {
            return -1;
        }
        let req_bytes = unsafe { CStr::from_ptr(request_json) }.to_bytes();
        if req_bytes.len() > 64 * 1024
            || !matches!(serde_json::from_slice::<serde_json::Value>(req_bytes), Ok(v) if v.is_object())
        {
            return -1;
        }
        (
            format!(r#"{{"permissions":["{}","{}"]}}"#, K_MICROPHONE, K_LOCAL_NETWORK),
            0,
            "supported".to_string(),
        )
    } else if upsell {
        let mut missing_buf = [0 as c_char; 4096];
        let mut has_missing = 0;
        let rc = mocktail_rust_check_permission_request(request_json, mic_enabled, &mut has_missing, missing_buf.as_mut_ptr(), missing_buf.len());
        if rc != 0 {
            return -1;
        }
        let hidden = if !request_json.is_null() {
            let req_str = unsafe { CStr::from_ptr(request_json) }.to_str().unwrap_or("{}");
            let v: serde_json::Value = serde_json::from_str(req_str).unwrap_or(serde_json::Value::Null);
            v.get("permissions").cloned().unwrap_or(serde_json::json!([]))
        } else {
            serde_json::json!([])
        };
        (
            format!(r#"{{"hiddenUpsellPermissions":{},"upsellStatus":"HIDE"}}"#, hidden),
            0,
            "HIDE".to_string(),
        )
    } else {
        let mut missing_buf = vec![0 as c_char; 64 * 1024];
        let mut has_missing = 0;
        let rc = mocktail_rust_check_permission_request(request_json, mic_enabled, &mut has_missing, missing_buf.as_mut_ptr(), missing_buf.len());
        if rc != 0 {
            return -1;
        }
        let missing_str = unsafe { CStr::from_ptr(missing_buf.as_ptr()) }.to_str().unwrap_or("[]");
        let outcome_str = if has_missing == 0 { "AUTHORIZED" } else { "DENIED" };
        (
            format!(r#"{{"missingPermissions":{},"status":"{}"}}"#, missing_str, outcome_str),
            0,
            outcome_str.to_string(),
        )
    };

    if !out_code.is_null() {
        unsafe { *out_code = code };
    }
    copy_to_c_buffer(&outcome, out_outcome, outcome_cap);
    if !body_len.is_null() {
        unsafe { *body_len = body.len() };
    }
    copy_to_c_buffer(&body, out_body, body_cap);
    0
}

// ============================================================================
// 100. Client Settings Source Naming & Default URL Builder
// ============================================================================

fn client_settings_source_name_static(source: i32) -> &'static [u8] {
    match source {
        0 => b"explicit JSON\0",
        1 => b"explicit file\0",
        2 => b"bundled file\0",
        3 => b"safe defaults\0",
        4 => b"download\0",
        5 => b"cache\0",
        6 => b"empty defaults\0",
        _ => b"unknown\0",
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_client_settings_source_name_ptr(source: i32) -> *const c_char {
    client_settings_source_name_static(source).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_client_settings_source_name(
    source: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let bytes = client_settings_source_name_static(source);
    let name = unsafe { std::str::from_utf8_unchecked(&bytes[..bytes.len() - 1]) };
    copy_to_c_buffer(name, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_client_settings_build_url(
    app_name: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let app = if !app_name.is_null() {
        unsafe { CStr::from_ptr(app_name) }.to_str().unwrap_or("")
    } else {
        ""
    };
    let url = format!(
        "https://clientsettingscdn.roblox.com/v2/settings/application/{}",
        app
    );
    copy_to_c_buffer(&url, out_buf, out_cap)
}

// ============================================================================
// 105. Interactive Process Launch Resource & Scheduler Policy Engine
// ============================================================================

pub const RLIM_INFINITY_U64: u64 = 0xffff_ffff_ffff_ffff;
pub const SCHED_OTHER_CONST: i32 = 0;
pub const SCHED_FIFO_CONST: i32 = 1;
pub const SCHED_RR_CONST: i32 = 2;
pub const SCHED_RESET_ON_FORK_CONST: i32 = 0x4000_0000;
pub const RLIMIT_CPU_CONST: i32 = 0;
pub const RLIMIT_RTTIME_CONST: i32 = 15;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RustRLimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RustSchedParam {
    pub sched_priority: std::ffi::c_int,
}

extern "C" {
    fn sched_getscheduler(pid: std::ffi::c_int) -> std::ffi::c_int;
    fn sched_setscheduler(
        pid: std::ffi::c_int,
        policy: std::ffi::c_int,
        param: *const RustSchedParam,
    ) -> std::ffi::c_int;
    fn getrlimit(resource: std::ffi::c_int, rlim: *mut RustRLimit) -> std::ffi::c_int;
    fn setrlimit(resource: std::ffi::c_int, rlim: *const RustRLimit) -> std::ffi::c_int;
    fn strerror(errnum: std::ffi::c_int) -> *const std::ffi::c_char;
}

#[cfg(target_os = "linux")]
unsafe fn get_c_errno() -> std::ffi::c_int {
    extern "C" {
        fn __errno_location() -> *mut std::ffi::c_int;
    }
    *__errno_location()
}

#[cfg(not(target_os = "linux"))]
unsafe fn get_c_errno() -> std::ffi::c_int {
    0
}

fn get_c_strerror(err: std::ffi::c_int) -> String {
    unsafe {
        let p = strerror(err);
        if p.is_null() {
            format!("error {}", err)
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

pub fn format_rlimit_value(value: u64, is_infinity: bool) -> String {
    if is_infinity || value == RLIM_INFINITY_U64 {
        "unlimited".to_string()
    } else {
        value.to_string()
    }
}

pub fn format_rlimit_entry(
    name: &str,
    cur: u64,
    cur_is_inf: bool,
    max: u64,
    max_is_inf: bool,
    units: &str,
) -> String {
    format!(
        "  [process] {} soft={} hard={} units={}\n",
        name,
        format_rlimit_value(cur, cur_is_inf),
        format_rlimit_value(max, max_is_inf),
        units
    )
}

pub fn evaluate_scheduler_policy(policy: i32) -> (bool, i32) {
    let base_policy = policy & !SCHED_RESET_ON_FORK_CONST;
    let is_realtime = base_policy == SCHED_FIFO_CONST || base_policy == SCHED_RR_CONST;
    let target_policy = SCHED_OTHER_CONST | (policy & SCHED_RESET_ON_FORK_CONST);
    (is_realtime, target_policy)
}

pub fn evaluate_cpu_limit(cur: u64, cur_is_inf: bool, max: u64, max_is_inf: bool) -> i32 {
    let cur_inf = cur_is_inf || cur == RLIM_INFINITY_U64;
    let max_inf = max_is_inf || max == RLIM_INFINITY_U64;
    if !cur_inf && max_inf {
        1 // Clear soft limit
    } else if !max_inf {
        2 // Finite limit warning
    } else {
        0 // No action
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_process_launch_format_limit(
    value: u64,
    is_infinity: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let s = format_rlimit_value(value, is_infinity != 0);
    copy_to_c_buffer(&s, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_process_launch_eval_scheduler(
    inherited_policy: i32,
    out_target_policy: *mut i32,
    out_is_realtime: *mut i32,
) -> i32 {
    let (is_rt, target) = evaluate_scheduler_policy(inherited_policy);
    if !out_target_policy.is_null() {
        unsafe { *out_target_policy = target };
    }
    if !out_is_realtime.is_null() {
        unsafe { *out_is_realtime = if is_rt { 1 } else { 0 } };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_process_launch_eval_cpu_limit(
    cur: u64,
    cur_is_inf: i32,
    max: u64,
    max_is_inf: i32,
    out_action: *mut i32,
) -> i32 {
    let action = evaluate_cpu_limit(cur, cur_is_inf != 0, max, max_is_inf != 0);
    if !out_action.is_null() {
        unsafe { *out_action = action };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apply_interactive_process_launch_policy(
    out_buf: *mut c_char,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    let mut log = String::new();

    // Browser protocol handlers inherit the browser's scheduling policy. A
    // compute-heavy engine thread running FIFO/RR can exhaust RLIMIT_RTTIME and
    // receive SIGXCPU even when the ordinary CPU-time limit is unlimited.
    let policy = unsafe { sched_getscheduler(0) };
    if policy < 0 {
        let err = unsafe { get_c_errno() };
        log.push_str(&format!(
            "  [process] cannot read scheduling policy: {}\n",
            get_c_strerror(err)
        ));
    } else {
        log.push_str(&format!("  [process] inherited scheduler={}\n", policy));
        let (is_rt, target_policy) = evaluate_scheduler_policy(policy);
        if is_rt {
            let parameters = RustSchedParam::default();
            // Clearing RESET_ON_FORK requires CAP_SYS_NICE, even when demoting.
            let res = unsafe { sched_setscheduler(0, target_policy, &parameters) };
            if res == 0 {
                log.push_str("  [process] reset inherited real-time scheduler to SCHED_OTHER\n");
            } else {
                let err = unsafe { get_c_errno() };
                log.push_str(&format!(
                    "  [process] cannot reset real-time scheduler: {}; RLIMIT_RTTIME may terminate startup\n",
                    get_c_strerror(err)
                ));
            }
        }
    }

    let mut cpu = RustRLimit::default();
    if unsafe { getrlimit(RLIMIT_CPU_CONST, &mut cpu) } == 0 {
        log.push_str(&format_rlimit_entry(
            "RLIMIT_CPU",
            cpu.rlim_cur,
            cpu.rlim_cur == RLIM_INFINITY_U64,
            cpu.rlim_max,
            cpu.rlim_max == RLIM_INFINITY_U64,
            "seconds",
        ));
        let action = evaluate_cpu_limit(
            cpu.rlim_cur,
            cpu.rlim_cur == RLIM_INFINITY_U64,
            cpu.rlim_max,
            cpu.rlim_max == RLIM_INFINITY_U64,
        );
        if action == 1 {
            cpu.rlim_cur = RLIM_INFINITY_U64;
            if unsafe { setrlimit(RLIMIT_CPU_CONST, &cpu) } == 0 {
                log.push_str("  [process] cleared inherited soft CPU-time limit\n");
            } else {
                let err = unsafe { get_c_errno() };
                log.push_str(&format!(
                    "  [process] cannot clear soft CPU-time limit: {}\n",
                    get_c_strerror(err)
                ));
            }
        } else if action == 2 {
            log.push_str("  [process] finite CPU-time limit retained; if startup ends with SIGXCPU, adjust the launching service's LimitCPU or launch from a terminal with an unlimited CPU-time limit\n");
        }
    } else {
        let err = unsafe { get_c_errno() };
        log.push_str(&format!(
            "  [process] cannot read RLIMIT_CPU: {}\n",
            get_c_strerror(err)
        ));
    }

    // Keep the real-time watchdog intact for any threads that deliberately opt
    // into real-time scheduling later (for example, an audio backend).
    let mut realtime = RustRLimit::default();
    if unsafe { getrlimit(RLIMIT_RTTIME_CONST, &mut realtime) } == 0 {
        log.push_str(&format_rlimit_entry(
            "RLIMIT_RTTIME",
            realtime.rlim_cur,
            realtime.rlim_cur == RLIM_INFINITY_U64,
            realtime.rlim_max,
            realtime.rlim_max == RLIM_INFINITY_U64,
            "microseconds",
        ));
    } else {
        let err = unsafe { get_c_errno() };
        log.push_str(&format!(
            "  [process] cannot read RLIMIT_RTTIME: {}\n",
            get_c_strerror(err)
        ));
    }

    let bytes = log.as_bytes();
    if !out_written.is_null() {
        unsafe { *out_written = bytes.len() };
    }
    if out_buf.is_null() || out_cap <= bytes.len() {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
        *out_buf.add(bytes.len()) = 0;
    }
    0
}

// ============================================================================
// 106. Pinned APK Provider Archive & Digest Verification Policy
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_pinned_apk_hex_digest(
    value: *const c_char,
    len: usize,
    expected_size: usize,
) -> i32 {
    if value.is_null() || len != expected_size {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(value as *const u8, len) };
    if slice.iter().all(|&c| (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f')) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_pinned_apk_archive_filename_valid(
    filename: *const c_char,
    len: usize,
) -> i32 {
    if filename.is_null() || len == 0 || len > 128 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(filename as *const u8, len) };
    let valid_chars = slice.iter().all(|&c| {
        c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-'
    });
    if !valid_chars {
        return 0;
    }
    if slice.ends_with(b".apk") {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_pinned_apk_archive_limits_valid(
    size_bytes: u64,
    maximum_bytes: u64,
) -> i32 {
    if size_bytes > 0 && size_bytes <= maximum_bytes {
        1
    } else {
        0
    }
}

// ============================================================================
// 107. Vulkan Swapchain Present & Surface Maintenance Policy
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_select_surface_maintenance_exts(
    supported_ptrs: *const *const c_char,
    supported_count: usize,
    enabled_ptrs: *const *const c_char,
    enabled_count: usize,
    out_append_nl: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    const VK_KHR_SURFACE: &str = "VK_KHR_surface";
    const VK_KHR_CAPS2: &str = "VK_KHR_get_surface_capabilities2";
    const VK_KHR_MAINT1: &str = "VK_KHR_surface_maintenance1";
    const VK_EXT_MAINT1: &str = "VK_EXT_surface_maintenance1";

    if !out_len.is_null() {
        unsafe { *out_len = 0 };
    }
    if !out_append_nl.is_null() && out_cap > 0 {
        unsafe { *out_append_nl = 0 };
    }
    if (supported_ptrs.is_null() && supported_count > 0)
        || (enabled_ptrs.is_null() && enabled_count > 0)
    {
        return -1;
    }

    let mut supported: Vec<&str> = Vec::with_capacity(supported_count);
    for i in 0..supported_count {
        let p = unsafe { *supported_ptrs.add(i) };
        if !p.is_null() {
            if let Ok(s) = unsafe { CStr::from_ptr(p) }.to_str() {
                supported.push(s);
            }
        }
    }

    let has_supported = |needle: &str| supported.iter().any(|&s| s == needle);
    let maintenance = if has_supported(VK_KHR_MAINT1) {
        VK_KHR_MAINT1
    } else {
        VK_EXT_MAINT1
    };

    if !has_supported(maintenance) || !has_supported(VK_KHR_CAPS2) || !has_supported(VK_KHR_SURFACE) {
        return 0;
    }

    let mut enabled: Vec<&str> = Vec::with_capacity(enabled_count);
    for i in 0..enabled_count {
        let p = unsafe { *enabled_ptrs.add(i) };
        if !p.is_null() {
            if let Ok(s) = unsafe { CStr::from_ptr(p) }.to_str() {
                enabled.push(s);
            }
        }
    }

    let mut to_append = String::new();
    for &req in &[VK_KHR_SURFACE, VK_KHR_CAPS2, maintenance] {
        if !enabled.iter().any(|&e| e == req) {
            if !to_append.is_empty() {
                to_append.push('\n');
            }
            to_append.push_str(req);
        }
    }

    if !out_len.is_null() {
        unsafe { *out_len = to_append.len() };
    }
    if !out_append_nl.is_null() {
        let rc = copy_to_c_buffer(&to_append, out_append_nl, out_cap);
        if rc != 0 {
            return rc;
        }
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_swapchain_image_policy(
    policy: c_int,
    selected_present_mode: u32,
) -> c_int {
    if selected_present_mode == VK_PRESENT_MODE_MAILBOX_KHR {
        return MocktailRustPresentModePolicy::Mailbox as c_int;
    }
    let mut explicit_mode = 0u32;
    if mocktail_rust_present_mode_explicit(policy, &mut explicit_mode) != 0
        && selected_present_mode != explicit_mode
    {
        return MocktailRustPresentModePolicy::Fifo as c_int;
    }
    policy
}

// ============================================================================
// 108. Texture Override Policy, FNV-1a Hash & RGBA Resampler
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_texture_override_has_png(dir_ptr: *const c_char) -> i32 {
    if dir_ptr.is_null() {
        return 0;
    }
    let dir_str = match unsafe { CStr::from_ptr(dir_ptr) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        _ => return 0,
    };
    let entries = match std::fs::read_dir(dir_str) {
        Ok(it) => it,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("png") {
            return 1;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_texture_override_hash_bytes(
    data: *const u8,
    size: usize,
) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    if data.is_null() || size == 0 {
        return hash;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    for &b in slice {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[no_mangle]
pub extern "C" fn mocktail_rust_texture_override_hash_name(
    hash: u64,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let text = format!("{hash:016x}");
    copy_to_c_buffer(&text, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_texture_override_resample_rgba(
    source: *const u8,
    source_width: u32,
    source_height: u32,
    width: u32,
    height: u32,
    destination: *mut u8,
) -> i32 {
    if source.is_null()
        || destination.is_null()
        || width == 0
        || height == 0
        || source_width == 0
        || source_height == 0
    {
        return -1;
    }
    let src_bytes = match (source_width as usize)
        .checked_mul(source_height as usize)
        .and_then(|v| v.checked_mul(4))
    {
        Some(v) if v <= isize::MAX as usize => v,
        _ => return -1,
    };
    let dst_bytes = match (width as usize)
        .checked_mul(height as usize)
        .and_then(|v| v.checked_mul(4))
    {
        Some(v) if v <= isize::MAX as usize => v,
        _ => return -1,
    };
    if width == source_width && height == source_height {
        if source as *const u8 != destination as *const u8 {
            unsafe {
                std::ptr::copy_nonoverlapping(source, destination, dst_bytes);
            }
        }
        return 0;
    }
    let src = unsafe { std::slice::from_raw_parts(source, src_bytes) };
    let dst = unsafe { std::slice::from_raw_parts_mut(destination, dst_bytes) };
    if width % source_width == 0 && height % source_height == 0 {
        let scale_x = (width / source_width) as usize;
        let scale_y = (height / source_height) as usize;
        let row_bytes = (width as usize) * 4;
        let mut row = vec![0u8; row_bytes];
        for y in 0..source_height as usize {
            let src_row_off = y * (source_width as usize) * 4;
            for x in 0..source_width as usize {
                let px = &src[src_row_off + x * 4..src_row_off + x * 4 + 4];
                for rep in 0..scale_x {
                    let dst_off = (x * scale_x + rep) * 4;
                    row[dst_off..dst_off + 4].copy_from_slice(px);
                }
            }
            let target_base = y * scale_y * row_bytes;
            for rep in 0..scale_y {
                let row_start = target_base + rep * row_bytes;
                dst[row_start..row_start + row_bytes].copy_from_slice(&row);
            }
        }
        return 0;
    }
    let sw = source_width as u64;
    let sh = source_height as u64;
    let dw = width as u64;
    let dh = height as u64;
    for y in 0..dh {
        let y0 = y * sh / dh;
        let mut y1 = (y + 1) * sh / dh;
        if y1 <= y0 {
            y1 = y0 + 1;
        }
        for x in 0..dw {
            let x0 = x * sw / dw;
            let mut x1 = (x + 1) * sw / dw;
            if x1 <= x0 {
                x1 = x0 + 1;
            }
            let mut sum = [0u64; 4];
            for sy in y0..y1 {
                for sx in x0..x1 {
                    let off = ((sy * sw + sx) * 4) as usize;
                    for ch in 0..4 {
                        sum[ch] += src[off + ch] as u64;
                    }
                }
            }
            let count = (y1 - y0) * (x1 - x0);
            let out_off = ((y * dw + x) * 4) as usize;
            for ch in 0..4 {
                dst[out_off + ch] = ((sum[ch] + count / 2) / count) as u8;
            }
        }
    }
    0
}

// ============================================================================
// 109. Bundled Sky ETC1-to-BC1 KTX1 Transcoder
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_etc1_is_bundled_sky_texture(path: *const c_char) -> i32 {
    if path.is_null() {
        return 0;
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    const SKY_DIR: &[u8] = b"/assets/android/textures/sky/";
    let has_dir = bytes.windows(SKY_DIR.len()).any(|w| w == SKY_DIR);
    if has_dir && bytes.ends_with(b".tex") {
        1
    } else {
        0
    }
}

fn etc1_decode_rgb_block(data: &[u8; 8]) -> [[u8; 3]; 16] {
    const WRITE_ORDER: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    const MODIFIER: [[i32; 2]; 8] = [
        [2, 8],
        [5, 17],
        [9, 29],
        [13, 42],
        [18, 60],
        [24, 80],
        [33, 106],
        [47, 183],
    ];
    const SUBBLOCK: [[usize; 16]; 2] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
        [0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1],
    ];
    let expand4 = |v: u8| -> u8 { (v << 4) | v };
    let expand5 = |v: i32| -> u8 { (((v << 3) | (v >> 2)) & 0xff) as u8 };
    let sign_ext3 = |v: u8| -> i32 {
        if (v & 4) != 0 {
            v as i32 - 8
        } else {
            v as i32
        }
    };

    let mut color = [[0u8; 3]; 2];
    if (data[3] & 2) != 0 {
        for ch in 0..3 {
            let base = (data[ch] >> 3) as i32;
            color[0][ch] = expand5(base);
            color[1][ch] = expand5(base + sign_ext3(data[ch] & 7));
        }
    } else {
        for ch in 0..3 {
            color[0][ch] = expand4(data[ch] >> 4);
            color[1][ch] = expand4(data[ch] & 15);
        }
    }

    let mut low_indices = ((data[6] as u16) << 8) | (data[7] as u16);
    let mut high_indices = ((data[4] as u16) << 8) | (data[5] as u16);
    let code = [(data[3] >> 5) as usize, ((data[3] >> 2) & 7) as usize];
    let subblock = &SUBBLOCK[(data[3] & 1) as usize];
    let mut out = [[0u8; 3]; 16];
    for pixel in 0..16 {
        let side = subblock[pixel];
        let modifier = MODIFIER[code[side]][(low_indices & 1) as usize];
        let delta = if (high_indices & 1) != 0 { -modifier } else { modifier };
        let base = color[side];
        out[WRITE_ORDER[pixel]] = [
            (base[0] as i32 + delta).clamp(0, 255) as u8,
            (base[1] as i32 + delta).clamp(0, 255) as u8,
            (base[2] as i32 + delta).clamp(0, 255) as u8,
        ];
        low_indices >>= 1;
        high_indices >>= 1;
    }
    out
}

fn etc1_convert_block_to_bc1_slice(etc1: &[u8; 8], bc1: &mut [u8; 8]) {
    let pack565 = |c: [u8; 3]| -> u16 {
        (((c[0] >> 3) as u16) << 11) | (((c[1] >> 2) as u16) << 5) | ((c[2] >> 3) as u16)
    };
    let unpack565 = |c: u16| -> [u8; 3] {
        let r = ((c >> 11) & 31) as u8;
        let g = ((c >> 5) & 63) as u8;
        let b = (c & 31) as u8;
        [(r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)]
    };
    let dist = |a: [u8; 3], b: [u8; 3]| -> u32 {
        let dr = a[0] as i32 - b[0] as i32;
        let dg = a[1] as i32 - b[1] as i32;
        let db = a[2] as i32 - b[2] as i32;
        (dr * dr + dg * dg + db * db) as u32
    };

    let pixels = etc1_decode_rgb_block(etc1);
    let mut min_c = pixels[0];
    let mut max_c = pixels[0];
    for p in &pixels {
        for ch in 0..3 {
            min_c[ch] = min_c[ch].min(p[ch]);
            max_c[ch] = max_c[ch].max(p[ch]);
        }
    }
    for ch in 0..3 {
        let inset = (max_c[ch] - min_c[ch]) / 16;
        min_c[ch] += inset;
        max_c[ch] -= inset;
    }
    let mut ep0 = pack565(max_c);
    let mut ep1 = pack565(min_c);
    if ep0 < ep1 {
        std::mem::swap(&mut ep0, &mut ep1);
    }
    if ep0 == ep1 {
        if ep0 < u16::MAX {
            ep0 += 1;
        } else {
            ep1 -= 1;
        }
    }
    let c0 = unpack565(ep0);
    let c1 = unpack565(ep1);
    let c2 = [
        ((2 * c0[0] as u16 + c1[0] as u16) / 3) as u8,
        ((2 * c0[1] as u16 + c1[1] as u16) / 3) as u8,
        ((2 * c0[2] as u16 + c1[2] as u16) / 3) as u8,
    ];
    let c3 = [
        ((c0[0] as u16 + 2 * c1[0] as u16) / 3) as u8,
        ((c0[1] as u16 + 2 * c1[1] as u16) / 3) as u8,
        ((c0[2] as u16 + 2 * c1[2] as u16) / 3) as u8,
    ];
    let palette = [c0, c1, c2, c3];
    let mut indices = 0u32;
    for (pix_idx, &pix) in pixels.iter().enumerate() {
        let mut best_dist = u32::MAX;
        let mut best_idx = 0u32;
        for (pal_idx, &pal) in palette.iter().enumerate() {
            let d = dist(pix, pal);
            if d < best_dist {
                best_dist = d;
                best_idx = pal_idx as u32;
            }
        }
        indices |= best_idx << (pix_idx * 2);
    }
    bc1[0..2].copy_from_slice(&ep0.to_le_bytes());
    bc1[2..4].copy_from_slice(&ep1.to_le_bytes());
    bc1[4..8].copy_from_slice(&indices.to_le_bytes());
}

#[no_mangle]
pub extern "C" fn mocktail_rust_etc1_convert_rgb_block_to_bc1(
    etc1: *const u8,
    bc1: *mut u8,
) -> i32 {
    if etc1.is_null() || bc1.is_null() {
        return -1;
    }
    let src: &[u8; 8] = unsafe { &*(etc1 as *const [u8; 8]) };
    let dst: &mut [u8; 8] = unsafe { &mut *(bc1 as *mut [u8; 8]) };
    etc1_convert_block_to_bc1_slice(src, dst);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_etc1_transcode_ktx1_for_vulkan(
    data: *mut u8,
    len: usize,
) -> i32 {
    const KTX1_HEADER_SIZE: usize = 64;
    const KTX1_IDENT: [u8; 12] = [0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a];
    const KTX1_LE: u32 = 0x04030201;
    const GL_ETC1_RGB8_OES: u32 = 0x00008d64;
    const GL_COMPRESSED_RGB_S3TC_DXT1: u32 = 0x000083f0;
    const GL_RGB: u32 = 0x00001907;
    const MAX_SKY_SIZE: usize = 16 * 1024 * 1024;

    if data.is_null() || len < KTX1_HEADER_SIZE || len > MAX_SKY_SIZE {
        return 0;
    }
    let file = unsafe { std::slice::from_raw_parts_mut(data, len) };
    let le32 = |off: usize| -> u32 {
        u32::from_le_bytes([file[off], file[off + 1], file[off + 2], file[off + 3]])
    };

    if file[0..12] != KTX1_IDENT
        || le32(12) != KTX1_LE
        || le32(16) != 0
        || le32(20) != 1
        || le32(24) != 0
        || le32(28) != GL_ETC1_RGB8_OES
        || le32(32) != GL_RGB
    {
        return 0;
    }
    let width = le32(36);
    let height = le32(40);
    let depth = le32(44);
    let array_elements = le32(48);
    let faces = le32(52);
    let mip_levels = le32(56);
    let key_value_bytes = le32(60) as usize;
    if width == 0
        || height == 0
        || depth != 0
        || array_elements != 0
        || faces != 1
        || mip_levels == 0
        || mip_levels > 32
        || key_value_bytes > len - KTX1_HEADER_SIZE
    {
        return 0;
    }

    let mut offset = KTX1_HEADER_SIZE + key_value_bytes;
    let mut mip_w = width;
    let mut mip_h = height;
    let mut mip_ranges: Vec<(usize, usize)> = Vec::with_capacity(mip_levels as usize);
    for _ in 0..mip_levels {
        if offset > len || len - offset < 4 {
            return 0;
        }
        let image_size = u32::from_le_bytes([file[offset], file[offset + 1], file[offset + 2], file[offset + 3]]) as usize;
        offset += 4;
        let blocks = (((mip_w as u64 + 3) / 4) * ((mip_h as u64 + 3) / 4)) * 8;
        if (image_size as u64) != blocks || image_size > len - offset {
            return 0;
        }
        mip_ranges.push((offset, image_size));
        offset += image_size;
        let padding = (4 - (image_size % 4)) % 4;
        if padding > len - offset {
            return 0;
        }
        offset += padding;
        mip_w = (mip_w / 2).max(1);
        mip_h = (mip_h / 2).max(1);
    }

    for (mip_offset, image_size) in mip_ranges {
        for block_off in (0..image_size).step_by(8) {
            let block_slice: [u8; 8] = file[mip_offset + block_off..mip_offset + block_off + 8].try_into().unwrap();
            let mut converted = [0u8; 8];
            etc1_convert_block_to_bc1_slice(&block_slice, &mut converted);
            file[mip_offset + block_off..mip_offset + block_off + 8].copy_from_slice(&converted);
        }
    }

    file[28..32].copy_from_slice(&GL_COMPRESSED_RGB_S3TC_DXT1.to_le_bytes());
    1
}

// 110. Vulkan ETC2 Emulation Helpers moved to vulkan_etc2 module.

// ============================================================================
// 111. Graphics Launch Policy, PCI GPU & Vulkan ICD Selector
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_select_egl_vendor_manifest(
    dirs_nl: *const c_char,
    needle: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    if dirs_nl.is_null() || needle.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let dirs_str = unsafe { CStr::from_ptr(dirs_nl) }.to_string_lossy();
    let needle_str = unsafe { CStr::from_ptr(needle) }.to_string_lossy();
    if needle_str.is_empty() {
        return -1;
    }
    for dir in dirs_str.lines() {
        let dir_trimmed = dir.trim();
        if dir_trimmed.is_empty() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir_trimmed) else {
            continue;
        };
        let mut names: Vec<(String, std::path::PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if !file_name.ends_with(".json") || !file_name.contains(needle_str.as_ref()) {
                continue;
            }
            let path = entry.path();
            if std::fs::File::open(&path).is_ok() {
                names.push((file_name, path));
            }
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some((_, best)) = names.first() {
            let best_str = best.to_string_lossy();
            let bytes = best_str.as_bytes();
            if bytes.len() < out_cap {
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, bytes.len());
                    *out_buf.add(bytes.len()) = 0;
                }
                return 0;
            }
            return -1;
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_haswell_intel(device_id: u32) -> i32 {
    let matched = (0x0150..=0x016a).contains(&device_id)
        || (0x0400..=0x042f).contains(&device_id)
        || (0x0a00..=0x0a2f).contains(&device_id)
        || (0x0c00..=0x0c2f).contains(&device_id)
        || (0x0d00..=0x0d2f).contains(&device_id);
    if matched { 1 } else { 0 }
}

pub(crate) fn is_legacy_intel_gpu_id(device_id: u32) -> bool {
    mocktail_rust_graphics_is_haswell_intel(device_id) != 0
        || (0x0040..=0x012f).contains(&device_id)
        || (0x0f30..=0x0f3f).contains(&device_id)
        || (0x1600..=0x163f).contains(&device_id)
        || (0x22b0..=0x22b3).contains(&device_id)
        || (0x29a0..=0x2e9f).contains(&device_id)
}

pub(crate) fn is_legacy_nvidia_gpu_id(device_id: u32) -> bool {
    device_id > 0 && device_id < 0x1300
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_should_auto_prefer_opengl(
    legacy_cpu: i32,
    has_legacy_gpu: i32,
    has_modern_vulkan_gpu: i32,
) -> i32 {
    if legacy_cpu != 0 || (has_legacy_gpu != 0 && has_modern_vulkan_gpu == 0) {
        1
    } else {
        0
    }
}

#[cfg(any(test, feature = "updater"))]
pub(crate) fn resolve_auto_graphics_backend_from_hardware(
    cpuinfo: &str,
    gpus: &[(u32, u32)],
) -> &'static str {
    let legacy_cpu = if is_legacy_cpu_info_str(cpuinfo) { 1 } else { 0 };
    let mut has_legacy_gpu = 0;
    let mut has_modern_vulkan_gpu = 0;
    for &(vendor_id, device_id) in gpus {
        match vendor_id {
            0x8086 => {
                if is_legacy_intel_gpu_id(device_id) {
                    has_legacy_gpu = 1;
                } else {
                    has_modern_vulkan_gpu = 1;
                }
            }
            0x10de => {
                if is_legacy_nvidia_gpu_id(device_id) {
                    has_legacy_gpu = 1;
                } else {
                    has_modern_vulkan_gpu = 1;
                }
            }
            0x1002 | 0x1022 => {
                has_modern_vulkan_gpu = 1;
            }
            _ => {}
        }
    }
    if mocktail_rust_graphics_should_auto_prefer_opengl(
        legacy_cpu,
        has_legacy_gpu,
        has_modern_vulkan_gpu,
    ) != 0
    {
        "opengl"
    } else {
        "direct-vulkan"
    }
}

#[cfg(any(test, feature = "updater"))]
pub(crate) fn resolve_host_auto_graphics_backend_str() -> &'static str {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut gpus = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("card") || name_str.contains('-') {
                continue;
            }
            let dev_dir = entry.path().join("device");
            let Ok(v_raw) = std::fs::read_to_string(dev_dir.join("vendor")) else {
                continue;
            };
            let Ok(d_raw) = std::fs::read_to_string(dev_dir.join("device")) else {
                continue;
            };
            let parse_hex = |raw: &str| -> Option<u32> {
                let t = raw.trim();
                let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
                u32::from_str_radix(h, 16).ok().filter(|&v| v <= 0xffff)
            };
            if let (Some(v), Some(d)) = (parse_hex(&v_raw), parse_hex(&d_raw)) {
                gpus.push((v, d));
            }
        }
    }
    resolve_auto_graphics_backend_from_hardware(&cpuinfo, &gpus)
}

pub(crate) fn is_legacy_cpu_info_str(cpuinfo: &str) -> bool {
    let mut vendor: Option<&str> = None;
    let mut family: Option<u32> = None;
    let mut model: Option<u32> = None;

    for raw_line in cpuinfo.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            if vendor.is_some() || family.is_some() || model.is_some() {
                break;
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "vendor_id" => vendor = Some(val),
            "cpu family" => family = val.parse::<u32>().ok(),
            "model" => model = val.parse::<u32>().ok(),
            _ => {}
        }
    }

    match (vendor, family, model) {
        (Some("GenuineIntel"), Some(fam), m_opt) => {
            if fam < 6 || fam == 15 {
                return true;
            }
            if fam == 6 {
                if let Some(m) = m_opt {
                    // Family 6 models before Skylake (0x4e/0x5e), plus Broadwell-EP/DE (0x4f, 0x56) and legacy Atoms.
                    return m < 0x4e || matches!(m, 0x4f | 0x56 | 0x5a | 0x5d);
                }
            }
            false
        }
        (Some("AuthenticAMD"), Some(fam), _) => fam < 0x17,
        _ => false,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_legacy_intel(device_id: u32) -> i32 {
    if is_legacy_intel_gpu_id(device_id) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_legacy_nvidia(device_id: u32) -> i32 {
    if is_legacy_nvidia_gpu_id(device_id) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_legacy_cpu(cpuinfo_content: *const c_char) -> i32 {
    if cpuinfo_content.is_null() {
        return 0;
    }
    let Ok(s) = (unsafe { CStr::from_ptr(cpuinfo_content) }).to_str() else {
        return 0;
    };
    if is_legacy_cpu_info_str(s) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_parse_pci_hex(
    raw: *const c_char,
    out_val: *mut u32,
) -> i32 {
    if raw.is_null() || out_val.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(raw) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return 0,
    };
    let hex_part = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if hex_part.is_empty() {
        return 0;
    }
    match u32::from_str_radix(hex_part, 16) {
        Ok(v) if v <= 0xffff => {
            unsafe { *out_val = v };
            1
        }
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_anv_sys_mem_limit_percent(
    meminfo_content: *const c_char,
) -> u32 {
    if meminfo_content.is_null() {
        return 50;
    }
    let content = match unsafe { CStr::from_ptr(meminfo_content) }.to_str() {
        Ok(s) => s,
        Err(_) => return 50,
    };
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("MemTotal:") {
            if let Some(kb_str) = parts.next() {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    return if kb > 4 * 1024 * 1024 { 75 } else { 50 };
                }
            }
        }
    }
    50
}

fn is_foreign_icd_arch(name: &str, target_is_aarch64: bool) -> bool {
    const FOREIGN_X86_64: &[&str] = &[
        "i686", "i586", "i486", "i386", "x86.", "aarch64", "arm64", "armhf", "armv7", "ppc64",
        "riscv64", "s390x",
    ];
    const FOREIGN_AARCH64: &[&str] = &[
        "i686", "i586", "i486", "i386", "x86_64", "x86.", "amd64", "armhf", "armv7", "ppc64",
        "riscv64", "s390x",
    ];
    let list = if target_is_aarch64 { FOREIGN_AARCH64 } else { FOREIGN_X86_64 };
    list.iter().any(|&arch| name.contains(arch))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_foreign_icd_name(
    name: *const c_char,
    target_is_aarch64: i32,
) -> i32 {
    if name.is_null() {
        return 0;
    }
    match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) if is_foreign_icd_arch(s, target_is_aarch64 != 0) => 1,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_select_icd_manifest(
    dirs_nl: *const c_char,
    needle: *const c_char,
    target_is_aarch64: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    if !out_buf.is_null() && out_cap > 0 {
        unsafe { *out_buf = 0 };
    }
    if dirs_nl.is_null() || needle.is_null() {
        return -1;
    }
    let dirs_str = match unsafe { CStr::from_ptr(dirs_nl) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let needle_str = match unsafe { CStr::from_ptr(needle) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        _ => return 0,
    };
    let native_arch = if target_is_aarch64 != 0 { "aarch64" } else { "x86_64" };

    for dir in dirs_str.lines().filter(|d| !d.is_empty()) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut names: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if !meta.is_file() {
                    continue;
                }
            } else {
                continue;
            }
            if let Some(fname) = entry.file_name().to_str() {
                if fname.contains(".json")
                    && fname.contains(needle_str)
                    && !is_foreign_icd_arch(fname, target_is_aarch64 != 0)
                {
                    names.push(fname.to_string());
                }
            }
        }
        names.sort();
        let mut generic: Option<String> = None;
        for name in names {
            let full = Path::new(dir).join(&name);
            if File::open(&full).is_err() {
                continue;
            }
            let full_str = full.to_string_lossy();
            if name.contains(native_arch) {
                return copy_to_c_buffer(&full_str, out_buf, out_cap);
            }
            if generic.is_none() {
                generic = Some(full_str.into_owned());
            }
        }
        if let Some(g) = generic {
            return copy_to_c_buffer(&g, out_buf, out_cap);
        }
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_radv_icd_list(manifests: *const c_char) -> i32 {
    if manifests.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(manifests) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        _ => return 0,
    };
    let mut saw_any = false;
    for part in s.split(':') {
        if part.is_empty() {
            return 0;
        }
        let path = Path::new(part);
        let fname = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !fname.starts_with("radeon_icd.") || ext != "json" {
            return 0;
        }
        saw_any = true;
    }
    if saw_any { 1 } else { 0 }
}

// ============================================================================
// 112. Graphics Backend Selection Policy
// ============================================================================

fn graphics_backend_name_str(backend: i32) -> &'static str {
    match backend {
        0 => "angle-vulkan",
        1 => "direct-vulkan",
        2 => "system-egl",
        _ => "unknown",
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_backend_name_ptr(backend: i32) -> *const c_char {
    let bytes: &'static [u8] = match backend {
        0 => b"angle-vulkan\0",
        1 => b"direct-vulkan\0",
        2 => b"system-egl\0",
        _ => b"unknown\0",
    };
    bytes.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_backend_select(
    requested: i32,
    allow_fallback: i32,
    require_hw: i32,
    require_runtime: i32,
    caps_backends: *const i32,
    caps_states: *const i32,
    caps_accels: *const i32,
    caps_details: *const *const c_char,
    caps_count: usize,
    out_selected_backend: *mut i32,
    out_detail_buf: *mut c_char,
    out_detail_cap: usize,
) -> i32 {
    if out_selected_backend.is_null() {
        return -1;
    }
    if caps_count > 0
        && (caps_backends.is_null()
            || caps_states.is_null()
            || caps_accels.is_null()
            || caps_details.is_null())
    {
        copy_error(out_detail_buf, out_detail_cap, "invalid graphics capability array");
        unsafe { *out_selected_backend = requested };
        return -1;
    }

    let find_idx = |target_backend: i32| -> Option<usize> {
        for i in 0..caps_count {
            let b = unsafe { *caps_backends.add(i) };
            if b == target_backend {
                return Some(i);
            }
        }
        None
    };

    let is_usable = |idx: usize| -> bool {
        let state = unsafe { *caps_states.add(idx) };
        let accel = unsafe { *caps_accels.add(idx) };
        if state == 0 {
            return false; // kUnavailable
        }
        if require_runtime != 0 && state != 2 {
            return false; // kReady == 2
        }
        if require_hw != 0 && accel != 2 {
            return false; // kHardware == 2
        }
        true
    };

    let read_detail = |idx: usize| -> String {
        let p = unsafe { *caps_details.add(idx) };
        if p.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };

    if let Some(req_idx) = find_idx(requested) {
        if is_usable(req_idx) {
            unsafe { *out_selected_backend = requested };
            let d = read_detail(req_idx);
            copy_error(out_detail_buf, out_detail_cap, &d);
            return 0;
        }
    }

    let mut reason = format!(
        "requested graphics backend {}",
        graphics_backend_name_str(requested)
    );
    match find_idx(requested) {
        None => reason.push_str(" was not probed"),
        Some(idx) => {
            let d = read_detail(idx);
            if !d.is_empty() {
                reason.push_str(" is unavailable: ");
                reason.push_str(&d);
            } else {
                reason.push_str(" did not satisfy the production capability policy");
            }
        }
    }

    if allow_fallback != 0 {
        for &candidate in &[0i32, 1i32, 2i32] {
            if candidate == requested {
                continue;
            }
            if let Some(idx) = find_idx(candidate) {
                if is_usable(idx) {
                    unsafe { *out_selected_backend = candidate };
                    let d = read_detail(idx);
                    copy_error(out_detail_buf, out_detail_cap, &d);
                    return 0;
                }
            }
        }
        reason.push_str("; no explicitly allowed fallback satisfies the policy");
    }

    unsafe { *out_selected_backend = requested };
    copy_error(out_detail_buf, out_detail_cap, &reason);
    -1
}

// ============================================================================
// 113. Window Surface Lifecycle State Machine & Creation Policy
// ============================================================================

const SURFACE_MIN_WIDTH: u32 = 160;
const SURFACE_MIN_HEIGHT: u32 = 120;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustSurfaceSnapshot {
    pub generation: u64,
    pub native_window: usize,
    pub width: u32,
    pub height: u32,
    pub available: i32,
    pub dpi_scale: f32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustSurfaceEvent {
    pub event_type: i32, // 0=Created, 1=Changed, 2=Destroyed
    pub surface: MocktailRustSurfaceSnapshot,
}

struct SurfaceLifecycleEngine {
    events: std::collections::VecDeque<MocktailRustSurfaceEvent>,
    current: MocktailRustSurfaceSnapshot,
    active: bool,
}

impl Default for SurfaceLifecycleEngine {
    fn default() -> Self {
        Self {
            events: std::collections::VecDeque::new(),
            current: MocktailRustSurfaceSnapshot {
                dpi_scale: 1.0,
                ..Default::default()
            },
            active: false,
        }
    }
}

impl SurfaceLifecycleEngine {
    fn valid_available(native_window: usize, width: u32, height: u32, dpi_scale: f32) -> bool {
        native_window != 0
            && width >= SURFACE_MIN_WIDTH
            && height >= SURFACE_MIN_HEIGHT
            && dpi_scale.is_finite()
            && dpi_scale > 0.0
    }

    fn queue(&mut self, event_type: i32, surface: MocktailRustSurfaceSnapshot) {
        if event_type == 1 {
            if let Some(last) = self.events.back_mut() {
                if last.event_type == 1 && last.surface.generation == surface.generation {
                    last.surface = surface;
                    return;
                }
            }
        }
        self.events.push_back(MocktailRustSurfaceEvent {
            event_type,
            surface,
        });
    }

    fn restore(&mut self, native_window: usize, width: u32, height: u32, dpi_scale: f32) -> Result<(), &'static str> {
        if self.current.generation == u64::MAX {
            return Err("window surface generation overflowed");
        }
        self.current.generation += 1;
        self.current.native_window = native_window;
        self.current.width = width;
        self.current.height = height;
        self.current.dpi_scale = dpi_scale;
        self.current.available = 1;
        let snap = self.current;
        self.queue(0, snap);
        self.queue(1, snap);
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_new() -> *mut std::ffi::c_void {
    Box::into_raw(Box::new(SurfaceLifecycleEngine::default())) as *mut std::ffi::c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_free(ptr: *mut std::ffi::c_void) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut SurfaceLifecycleEngine));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_activate(
    ptr: *mut std::ffi::c_void,
    native_window: usize,
    width: u32,
    height: u32,
    dpi_scale: f32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let st = unsafe { &mut *(ptr as *mut SurfaceLifecycleEngine) };
    if st.active {
        copy_error(err_buf, err_cap, "window surface lifecycle is already active");
        return 1;
    }
    if !SurfaceLifecycleEngine::valid_available(native_window, width, height, dpi_scale) {
        copy_error(
            err_buf,
            err_cap,
            "initial window surface requires a native handle, dimensions and DPI scale",
        );
        return 2;
    }
    st.events.clear();
    st.current = MocktailRustSurfaceSnapshot {
        generation: 1,
        native_window,
        width,
        height,
        available: 1,
        dpi_scale,
    };
    st.active = true;
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_deactivate(ptr: *mut std::ffi::c_void) {
    if ptr.is_null() {
        return;
    }
    let st = unsafe { &mut *(ptr as *mut SurfaceLifecycleEngine) };
    st.active = false;
    st.events.clear();
    st.current = MocktailRustSurfaceSnapshot {
        dpi_scale: 1.0,
        ..Default::default()
    };
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_observe(
    ptr: *mut std::ffi::c_void,
    native_window: usize,
    width: u32,
    height: u32,
    dpi_scale: f32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let st = unsafe { &mut *(ptr as *mut SurfaceLifecycleEngine) };
    if !st.active {
        copy_error(err_buf, err_cap, "window surface lifecycle is not active");
        return 1;
    }
    if native_window == 0 {
        if st.current.available != 0 {
            let mut destroyed = st.current;
            destroyed.available = 0;
            st.queue(2, destroyed);
            st.current.native_window = 0;
            st.current.available = 0;
        }
        return 0;
    }
    if !dpi_scale.is_finite() || dpi_scale <= 0.0 {
        copy_error(err_buf, err_cap, "observed window surface requires a DPI scale");
        return 2;
    }
    if width < SURFACE_MIN_WIDTH || height < SURFACE_MIN_HEIGHT {
        if st.current.available != 0 && native_window != st.current.native_window {
            let mut destroyed = st.current;
            destroyed.available = 0;
            st.queue(2, destroyed);
            st.current.native_window = 0;
            st.current.available = 0;
        }
        return 0;
    }
    if st.current.available == 0 {
        return match st.restore(native_window, width, height, dpi_scale) {
            Ok(()) => 0,
            Err(msg) => {
                copy_error(err_buf, err_cap, msg);
                1
            }
        };
    }
    if native_window != st.current.native_window {
        let mut destroyed = st.current;
        destroyed.available = 0;
        st.queue(2, destroyed);
        st.current.native_window = 0;
        st.current.available = 0;
        return match st.restore(native_window, width, height, dpi_scale) {
            Ok(()) => 0,
            Err(msg) => {
                copy_error(err_buf, err_cap, msg);
                1
            }
        };
    }
    if width == st.current.width && height == st.current.height && dpi_scale == st.current.dpi_scale {
        return 0;
    }
    st.current.width = width;
    st.current.height = height;
    st.current.dpi_scale = dpi_scale;
    let snap = st.current;
    st.queue(1, snap);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_refresh(
    ptr: *mut std::ffi::c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let st = unsafe { &mut *(ptr as *mut SurfaceLifecycleEngine) };
    if !st.active {
        copy_error(err_buf, err_cap, "window surface lifecycle is not active");
        return 1;
    }
    if st.current.available == 0
        || !SurfaceLifecycleEngine::valid_available(
            st.current.native_window,
            st.current.width,
            st.current.height,
            st.current.dpi_scale,
        )
    {
        copy_error(err_buf, err_cap, "window surface is unavailable for refresh");
        return 1;
    }
    let snap = st.current;
    st.queue(1, snap);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_recreate(
    ptr: *mut std::ffi::c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let st = unsafe { &mut *(ptr as *mut SurfaceLifecycleEngine) };
    if !st.active {
        copy_error(err_buf, err_cap, "window surface lifecycle is not active");
        return 1;
    }
    if st.current.available == 0
        || !SurfaceLifecycleEngine::valid_available(
            st.current.native_window,
            st.current.width,
            st.current.height,
            st.current.dpi_scale,
        )
    {
        copy_error(err_buf, err_cap, "window surface is unavailable for recreation");
        return 1;
    }
    if st.current.generation == u64::MAX {
        copy_error(err_buf, err_cap, "window surface generation overflowed");
        return 1;
    }
    let mut destroyed = st.current;
    destroyed.available = 0;
    st.queue(2, destroyed);
    st.current.generation += 1;
    let snap = st.current;
    st.queue(0, snap);
    st.queue(1, snap);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_poll(
    ptr: *mut std::ffi::c_void,
    out_event: *mut MocktailRustSurfaceEvent,
) -> i32 {
    if ptr.is_null() || out_event.is_null() {
        return 0;
    }
    let st = unsafe { &mut *(ptr as *mut SurfaceLifecycleEngine) };
    match st.events.pop_front() {
        Some(ev) => {
            unsafe { *out_event = ev };
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_snapshot(
    ptr: *const std::ffi::c_void,
    out_snapshot: *mut MocktailRustSurfaceSnapshot,
) -> i32 {
    if ptr.is_null() || out_snapshot.is_null() {
        return 0;
    }
    let st = unsafe { &*(ptr as *const SurfaceLifecycleEngine) };
    unsafe { *out_snapshot = st.current };
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_lifecycle_is_active(ptr: *const std::ffi::c_void) -> i32 {
    if ptr.is_null() {
        return 0;
    }
    let st = unsafe { &*(ptr as *const SurfaceLifecycleEngine) };
    if st.active { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_surface_event_type_name_ptr(event_type: i32) -> *const c_char {
    let bytes: &'static [u8] = match event_type {
        0 => b"Created\0",
        1 => b"Changed\0",
        2 => b"Destroyed\0",
        _ => b"Unknown\0",
    };
    bytes.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_apply_high_dpi_flag(
    flags: u64,
    high_dpi: i32,
    high_dpi_bit: u64,
) -> u64 {
    if high_dpi != 0 {
        flags | high_dpi_bit
    } else {
        flags & !high_dpi_bit
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_direct_vulkan_requires_sync(
    video_driver: *const c_char,
) -> i32 {
    if video_driver.is_null() {
        return 0;
    }
    if unsafe { CStr::from_ptr(video_driver) }.to_bytes() == b"wayland" {
        1
    } else {
        0
    }
}

// ============================================================================
// 114. Roblox Presence Cookie Extractor & JSON Parser
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_presence_extract_cookie(
    raw_cookie: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    if raw_cookie.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let owned = zeroize::Zeroizing::new(
        unsafe { CStr::from_ptr(raw_cookie) }.to_string_lossy().into_owned(),
    );
    let mut found: Option<&str> = None;
    for raw_seg in owned.split(|c| c == ';' || c == '\r' || c == '\n' || c == '\t') {
        let seg = raw_seg.trim_start_matches(' ');
        if let Some(rest) = seg.strip_prefix(".ROBLOSECURITY=") {
            found = Some(rest);
            break;
        }
        if seg.starts_with("_|") {
            found = Some(seg);
            break;
        }
    }
    let value = match found {
        Some(v) => v,
        None => {
            unsafe { *out_buf = 0 };
            return 0;
        }
    };
    if value.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b';') {
        unsafe { *out_buf = 0 };
        return 0;
    }
    let wrapped = zeroize::Zeroizing::new(value.to_string());
    copy_to_c_buffer(&wrapped, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_presence_parse_follow_response(
    json_str: *const c_char,
    out_place_id: *mut i64,
    out_game_id: *mut c_char,
    out_game_id_cap: usize,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if !out_game_id.is_null() && out_game_id_cap > 0 {
        unsafe { *out_game_id = 0 };
    }
    if json_str.is_null() || out_place_id.is_null() {
        copy_error(err_buf, err_cap, "Roblox presence lookup returned malformed JSON");
        return -1;
    }
    let s = match unsafe { CStr::from_ptr(json_str) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            copy_error(err_buf, err_cap, "Roblox presence lookup returned malformed JSON");
            return -1;
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "Roblox presence lookup returned malformed JSON");
            return -1;
        }
    };
    let presences = match parsed.get("userPresences").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a,
        _ => {
            copy_error(err_buf, err_cap, "Roblox presence lookup returned no data for user");
            return -1;
        }
    };
    let presence = &presences[0];
    let ptype = presence
        .get("userPresenceType")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if ptype != 2 {
        copy_error(
            err_buf,
            err_cap,
            "User is not currently in a joinable Roblox experience",
        );
        return -1;
    }
    let place_val = match presence.get("placeId") {
        Some(v) if !v.is_null() => v,
        _ => {
            copy_error(
                err_buf,
                err_cap,
                "Roblox presence lookup did not include a placeId",
            );
            return -1;
        }
    };
    let place_id = place_val.as_i64().unwrap_or(0);
    if place_id <= 0 {
        copy_error(
            err_buf,
            err_cap,
            "Roblox presence lookup returned an invalid placeId",
        );
        return -1;
    }
    if let Some(game_id) = presence.get("gameId").and_then(|v| v.as_str()) {
        if !out_game_id.is_null() {
            let rc = copy_to_c_buffer(game_id, out_game_id, out_game_id_cap);
            if rc != 0 {
                copy_error(err_buf, err_cap, "Roblox presence gameId buffer too small");
                return -2;
            }
        }
    }
    unsafe { *out_place_id = place_id };
    0
}

// ============================================================================
// 115. Bounded JSON State File Reader/Validator
// ============================================================================

pub(crate) fn read_update_state_json_string(path_str: &str) -> Option<(String, serde_json::Value)> {
    const MAX_STATE_BYTES: u64 = 65536;
    if path_str.is_empty() {
        return None;
    }
    let meta = std::fs::symlink_metadata(path_str).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > MAX_STATE_BYTES {
        return None;
    }
    let file = File::open(path_str).ok()?;
    let mut buf = String::new();
    if file
        .take(MAX_STATE_BYTES + 1)
        .read_to_string(&mut buf)
        .is_err()
        || buf.len() as u64 > MAX_STATE_BYTES
    {
        return None;
    }
    let doc: serde_json::Value = serde_json::from_str(&buf).ok()?;
    if !doc.is_object() {
        return None;
    }
    Some((buf, doc))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_read_json_file(
    path_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if !out_len.is_null() {
        unsafe { *out_len = 0 };
    }
    if !out_buf.is_null() && out_cap > 0 {
        unsafe { *out_buf = 0 };
    }
    if path_ptr.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let path_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        _ => return -1,
    };
    let Some((buf, _)) = read_update_state_json_string(path_str) else {
        return -1;
    };
    let rc = copy_to_c_buffer(&buf, out_buf, out_cap);
    if rc == 0 && !out_len.is_null() {
        unsafe { *out_len = buf.len() };
    }
    rc
}

// ============================================================================
// 116. WebView Helper Security Policy & Navigation URI Evaluator
// ============================================================================

fn webview_is_safe_version_str(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 32
        && version
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
}

pub(crate) fn webview_is_roblox_host_str(host: &str) -> bool {
    const ROOT: &str = "roblox.com";
    if host.len() < ROOT.len() {
        return false;
    }
    let tail = &host[host.len() - ROOT.len()..];
    if !tail.eq_ignore_ascii_case(ROOT) {
        return false;
    }
    host.len() == ROOT.len() || host.as_bytes()[host.len() - ROOT.len() - 1] == b'.'
}

fn webview_bounded_token(value: Option<&str>, fallback: &str) -> String {
    match value {
        Some(v) if !v.is_empty() => v
            .bytes()
            .take(128)
            .map(|b| if (0x21..=0x7e).contains(&b) { b as char } else { '?' })
            .collect(),
        _ => fallback.to_string(),
    }
}

fn webview_eval_uri(uri: &str) -> (bool, bool, String, String, Option<String>) {
    if uri == "about:blank" {
        return (true, false, "about".into(), "none".into(), None);
    }
    if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case("https://") {
        let rest = &uri[8..];
        if rest.is_empty() || rest.starts_with('/') {
            return (false, false, "https".into(), "none".into(), None);
        }
    }
    let parsed = match url::Url::parse(uri) {
        Ok(u) => u,
        Err(_) => return (false, false, String::new(), String::new(), None),
    };
    let scheme = webview_bounded_token(Some(parsed.scheme()), "invalid");
    let raw_host = parsed.host_str().unwrap_or("");
    let host = webview_bounded_token(Some(raw_host), "none");
    let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    let port_ok = match parsed.port() {
        None | Some(443) => true,
        Some(_) => false,
    };
    let allowed = parsed.scheme().eq_ignore_ascii_case("https")
        && !raw_host.is_empty()
        && !has_userinfo
        && port_ok;
    let priv_allowed = allowed && webview_is_roblox_host_str(raw_host);
    (allowed, priv_allowed, scheme, host, Some(parsed.path().to_string()))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_should_disable_sandbox(
    kernel_version: *const c_char,
    sandbox_override: *const c_char,
) -> i32 {
    if !sandbox_override.is_null() || kernel_version.is_null() {
        return 0;
    }
    let kv = unsafe { CStr::from_ptr(kernel_version) }.to_string_lossy();
    if kv.contains("FreeBSD") || kv.contains("freebsd.org") {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_should_disable_hw_accel(
    wayland_display: i32,
    compositing_override: *const c_char,
) -> i32 {
    if !compositing_override.is_null() {
        let ov = unsafe { CStr::from_ptr(compositing_override) }.to_bytes();
        return if ov != b"0" { 1 } else { 0 };
    }
    if wayland_display != 0 { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_build_user_agent(
    configured_version: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    const FALLBACK: &str = "2.725.1142";
    let ver = if configured_version.is_null() {
        FALLBACK
    } else {
        match unsafe { CStr::from_ptr(configured_version) }.to_str() {
            Ok(v) if webview_is_safe_version_str(v) => v,
            _ => FALLBACK,
        }
    };
    let ua = format!(
        "Mozilla/5.0 AppleWebKit/605.1.15 (KHTML, like Gecko)  ROBLOX Android App {ver} Tablet Hybrid()  GooglePlayStore RobloxApp/{ver} (GlobalDist; GooglePlayStore)"
    );
    copy_to_c_buffer(&ua, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_evaluate_navigation_uri(
    uri: *const c_char,
    out_allowed: *mut i32,
    out_privileged: *mut i32,
    scheme_buf: *mut c_char,
    scheme_cap: usize,
    host_buf: *mut c_char,
    host_cap: usize,
) -> i32 {
    if !out_allowed.is_null() {
        unsafe { *out_allowed = 0 };
    }
    if !out_privileged.is_null() {
        unsafe { *out_privileged = 0 };
    }
    if uri.is_null() {
        copy_error(scheme_buf, scheme_cap, "");
        copy_error(host_buf, host_cap, "");
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(uri) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            copy_error(scheme_buf, scheme_cap, "");
            copy_error(host_buf, host_cap, "");
            return 0;
        }
    };
    let (allowed, priv_allowed, scheme, host, _) = webview_eval_uri(s);
    if !out_allowed.is_null() {
        unsafe { *out_allowed = if allowed { 1 } else { 0 } };
    }
    if !out_privileged.is_null() {
        unsafe { *out_privileged = if priv_allowed { 1 } else { 0 } };
    }
    copy_error(scheme_buf, scheme_cap, &scheme);
    copy_error(host_buf, host_cap, &host);
    if allowed { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_is_browser_login_url(url_ptr: *const c_char) -> i32 {
    if url_ptr.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(url_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let (allowed, _, _, host, path) = webview_eval_uri(s);
    if !allowed {
        return 0;
    }
    let host_ok = host.eq_ignore_ascii_case("www.roblox.com") || host.eq_ignore_ascii_case("roblox.com");
    let path_str = path.as_deref().unwrap_or("");
    let path_ok = path_str.eq_ignore_ascii_case("/login") || path_str.eq_ignore_ascii_case("/login/");
    if host_ok && path_ok { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_is_essential_resource(uri_ptr: *const c_char) -> i32 {
    if uri_ptr.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(uri_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let (allowed, _, _, host, path) = webview_eval_uri(s);
    if !allowed {
        return 0;
    }
    if host == "css.rbxcdn.com" || host == "js.rbxcdn.com" {
        return 1;
    }
    if host != "arkoselabs.roblox.com" && host != "apis.rbxcdn.com" {
        return 0;
    }
    let path_str = path.as_deref().unwrap_or("");
    let essential = if host == "apis.rbxcdn.com" {
        path_str == "/captcha/v1/metadata"
    } else {
        path_str.starts_with("/v2/") || path_str.starts_with("/fc/")
    };
    if essential { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_captcha_event_name_ptr(event_type: i32) -> *const c_char {
    if event_type == 1 {
        b"CaptchaSuccess\0".as_ptr() as *const c_char
    } else {
        b"CaptchaShown\0".as_ptr() as *const c_char
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_parse_captcha_event(
    cmd: *const c_char,
    cmd_len: usize,
    out_type: *mut i32,
    out_cb: *mut c_char,
    cb_cap: usize,
) -> i32 {
    const MAX_CMD: usize = 65536;
    if cmd.is_null() || out_type.is_null() || cmd_len == 0 || cmd_len > MAX_CMD {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(cmd as *const u8, cmd_len) };
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let msg = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) if v.is_object() => v,
        _ => return 0,
    };
    let valid_ident = |s: &str, max_len: usize| -> bool {
        s.len() <= max_len && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
    };
    fn read_req<'a>(obj: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        let s = obj.get(key)?.as_str()?;
        if s.len() <= 128 && !s.bytes().any(|b| b < 0x20 || b == 0x7f) {
            Some(s)
        } else {
            None
        }
    }
    if read_req(&msg, "moduleID") != Some("Navigation")
        || read_req(&msg, "functionName") != Some("navigateToFeature")
    {
        return 0;
    }
    let feature = msg
        .get("params")
        .and_then(|p| p.get("params"))
        .and_then(|n| read_req(n, "feature"));
    let ev_type = match feature {
        Some("CaptchaShown") => 0i32,
        Some("CaptchaSuccess") => 1i32,
        _ => return 0,
    };
    let cb = match msg.get("callbackID") {
        None => "",
        Some(v) => match v.as_str() {
            Some(s) if valid_ident(s, 1024) => s,
            _ => return 0,
        },
    };
    if !out_cb.is_null() && copy_to_c_buffer(cb, out_cb, cb_cap) != 0 {
        return 0;
    }
    unsafe { *out_type = ev_type };
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_build_callback_script(
    cb_id: *const c_char,
    cb_len: usize,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let slice = if cb_id.is_null() || cb_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(cb_id as *const u8, cb_len) }
    };
    let cb = String::from_utf8_lossy(slice);
    let quoted = match serde_json::to_string(&*cb) {
        Ok(q) => q,
        Err(_) => return -1,
    };
    let script = format!(
        "(() => {{ try {{ if (window.Roblox.Hybrid && window.Roblox.Hybrid.Bridge.nativeCallback && typeof window.Roblox.Hybrid.Bridge.nativeCallback === \"function\") {{ window.Roblox.Hybrid.Bridge.nativeCallback({quoted}, true, {{}}); return true; }} }} catch (_) {{}} return false; }})();"
    );
    copy_to_c_buffer(&script, out_buf, out_cap)
}

// ============================================================================
// 118. Roblox Text Font Resolver
// ============================================================================

fn lexical_normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    let mut is_abs = false;
    for comp in path.components() {
        match comp {
            Component::RootDir => {
                is_abs = true;
            }
            Component::Prefix(p) => {
                stack.push(p.as_os_str().to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(stack.last(), Some(s) if s != "..") {
                    stack.pop();
                } else if !is_abs {
                    stack.push(std::ffi::OsString::from(".."));
                }
            }
            Component::Normal(s) => {
                stack.push(s.to_os_string());
            }
        }
    }
    let mut out = PathBuf::new();
    if is_abs {
        out.push(std::path::MAIN_SEPARATOR_STR);
    }
    for s in stack {
        out.push(s);
    }
    if out.as_os_str().is_empty() && !is_abs {
        return PathBuf::from(".");
    }
    out
}

fn is_safe_font_file_name(value: &str) -> bool {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return false;
    }
    let p = Path::new(value);
    !p.is_absolute() && p.file_name() == Some(std::ffi::OsStr::new(value))
}

fn load_font_mappings(
    asset_content_root: &Path,
) -> std::collections::HashMap<i32, (String, f32)> {
    let mut mappings = std::collections::HashMap::new();
    let mapping_file = asset_content_root
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("android/fonts/font-mappings.json");
    let raw = match std::fs::read(&mapping_file) {
        Ok(b) => b,
        Err(_) => return mappings,
    };
    let doc: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => return mappings,
    };
    let items = match doc.as_array() {
        Some(a) => a,
        None => return mappings,
    };
    for item in items {
        let obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let encoded_enum = match obj.get("enum").and_then(|v| v.as_i64()) {
            Some(e) if (0..=(i32::MAX as i64)).contains(&e) => e as i32,
            _ => continue,
        };
        let encoded_font = match obj.get("font").and_then(|v| v.as_str()) {
            Some(s) if is_safe_font_file_name(s) => s.to_string(),
            _ => continue,
        };
        let encoded_ratio = match obj.get("fromRbxFontRatio").and_then(|v| v.as_f64()) {
            Some(r) if r.is_finite() && r > 0.0 && r <= 4.0 => r as f32,
            _ => continue,
        };
        mappings.insert(encoded_enum, (encoded_font, encoded_ratio));
    }
    mappings
}

fn font_mapping_for(font: i32, asset_content_root: &Path) -> Option<(String, f32)> {
    static FONT_CATALOGS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<i32, (String, f32)>>>,
    > = std::sync::OnceLock::new();
    let key = lexical_normalize_path(asset_content_root)
        .to_string_lossy()
        .into_owned();
    let map = FONT_CATALOGS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
    let catalog = guard
        .entry(key)
        .or_insert_with(|| load_font_mappings(asset_content_root));
    catalog.get(&font).cloned()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_resolve_roblox_text_font(
    font: i32,
    asset_content_root_ptr: *const c_char,
    asset_content_root_len: usize,
    out_primary_file: *mut c_char,
    primary_file_cap: usize,
    out_size_scale: *mut f32,
    out_exact_mapping: *mut bool,
) -> c_int {
    unsafe {
        if !out_size_scale.is_null() {
            *out_size_scale = 0.795;
        }
        if !out_exact_mapping.is_null() {
            *out_exact_mapping = false;
        }
        if !out_primary_file.is_null() && primary_file_cap > 0 {
            *out_primary_file = 0;
        }
    }
    let root_owned = if asset_content_root_ptr.is_null() {
        std::env::var("MOCKTAIL_ASSET_PATH").unwrap_or_default()
    } else if asset_content_root_len == 0 {
        String::new()
    } else {
        let slice = unsafe {
            std::slice::from_raw_parts(asset_content_root_ptr as *const u8, asset_content_root_len)
        };
        String::from_utf8_lossy(slice).into_owned()
    };
    if root_owned.is_empty() {
        return 0;
    }

    let content = Path::new(&root_owned);
    if let Some((mapped_file, size_scale)) = font_mapping_for(font, content) {
        let candidate = content.join("fonts").join(mapped_file);
        if std::fs::metadata(&candidate).map(|m| m.is_file()).unwrap_or(false) {
            let norm = lexical_normalize_path(&candidate);
            let norm_str = norm.to_string_lossy();
            if !out_primary_file.is_null() && copy_to_c_buffer(&norm_str, out_primary_file, primary_file_cap) != 0 {
                return -1;
            }
            unsafe {
                if !out_size_scale.is_null() {
                    *out_size_scale = size_scale;
                }
                if !out_exact_mapping.is_null() {
                    *out_exact_mapping = true;
                }
            }
            return 0;
        }
    }

    let legacy_name = match font {
        4 => "SourceSansPro-Bold.ttf",
        5 => "SourceSansPro-Light.ttf",
        _ => "SourceSansPro-Regular.ttf",
    };
    let legacy = content
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("fonts")
        .join(legacy_name);
    if std::fs::metadata(&legacy).map(|m| m.is_file()).unwrap_or(false) {
        let norm = lexical_normalize_path(&legacy);
        let norm_str = norm.to_string_lossy();
        if !out_primary_file.is_null() && copy_to_c_buffer(&norm_str, out_primary_file, primary_file_cap) != 0 {
            return -1;
        }
    }
    0
}

// ============================================================================
// 119. Runtime Config & Network Proxy Engine
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_network_proxy_parse(
    host_ptr: *const c_char,
    host_len: usize,
    port_ptr: *const c_char,
    port_len: usize,
    scheme_ptr: *const c_char,
    scheme_len: usize,
    user_ptr: *const c_char,
    user_len: usize,
    pass_ptr: *const c_char,
    pass_len: usize,
    out_scheme: *mut c_char,
    scheme_cap: usize,
    out_port: *mut c_int,
) -> bool {
    let slice_from = |ptr: *const c_char, len: usize| -> &'static [u8] {
        if ptr.is_null() || len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }
        }
    };
    let scheme_bytes = slice_from(scheme_ptr, scheme_len);
    let normalized_scheme = match scheme_bytes {
        b"http" | b"https" => "http",
        b"socks" | b"socks5" | b"socks5h" => "socks5h",
        _ => return false,
    };
    let user_bytes = slice_from(user_ptr, user_len);
    let pass_bytes = slice_from(pass_ptr, pass_len);
    if (user_bytes.is_empty() && !pass_bytes.is_empty())
        || user_bytes.contains(&0)
        || pass_bytes.contains(&0)
        || (normalized_scheme == "socks5h" && (user_bytes.len() > 255 || pass_bytes.len() > 255))
    {
        return false;
    }
    let host_bytes = slice_from(host_ptr, host_len);
    let port_bytes = slice_from(port_ptr, port_len);
    if host_bytes.is_empty()
        || port_bytes.is_empty()
        || host_bytes.windows(3).any(|w| w == b"://")
        || host_bytes.iter().any(|&c| {
            c <= 0x20
                || c == 0x7f
                || matches!(c, b'/' | b'\\' | b'@' | b'[' | b']' | b'?' | b'#')
        })
    {
        return false;
    }
    if !port_bytes.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let parsed_port = match std::str::from_utf8(port_bytes).ok().and_then(|s| s.parse::<i32>().ok()) {
        Some(p) if (1..=65535).contains(&p) => p,
        _ => return false,
    };
    if !out_scheme.is_null() && copy_to_c_buffer(normalized_scheme, out_scheme, scheme_cap) != 0 {
        return false;
    }
    if !out_port.is_null() {
        unsafe { *out_port = parsed_port };
    }
    true
}

fn encode_proxy_credential(bytes: &[u8]) -> String {
    crate::discord_rpc::percent_encode_bytes(bytes)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_network_proxy_build_url(
    scheme_ptr: *const c_char,
    scheme_len: usize,
    host_ptr: *const c_char,
    host_len: usize,
    port: c_int,
    user_ptr: *const c_char,
    user_len: usize,
    pass_ptr: *const c_char,
    pass_len: usize,
    include_credentials: bool,
    out_url: *mut c_char,
    url_cap: usize,
) -> usize {
    let slice_from = |ptr: *const c_char, len: usize| -> &'static [u8] {
        if ptr.is_null() || len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }
        }
    };
    let scheme = String::from_utf8_lossy(slice_from(scheme_ptr, scheme_len));
    let host = String::from_utf8_lossy(slice_from(host_ptr, host_len));
    let user_bytes = slice_from(user_ptr, user_len);
    let pass_bytes = slice_from(pass_ptr, pass_len);
    let ipv6 = host.contains(':');
    let credentials = if include_credentials && !user_bytes.is_empty() {
        format!("{}:{}@", encode_proxy_credential(user_bytes), encode_proxy_credential(pass_bytes))
    } else {
        String::new()
    };
    let built = format!(
        "{}://{}{}{}{}:{}",
        scheme,
        credentials,
        if ipv6 { "[" } else { "" },
        host,
        if ipv6 { "]" } else { "" },
        port
    );
    if !out_url.is_null() && url_cap > 0 {
        let _ = copy_to_c_buffer(&built, out_url, url_cap);
    }
    built.len()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_parse_graphics_backend(
    name_ptr: *const c_char,
    name_len: usize,
) -> c_int {
    let name = if name_ptr.is_null() || name_len == 0 {
        ""
    } else {
        let slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len) };
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 5,
        }
    };
    match name {
        "" | "auto" => 0,
        "system" | "gles" | "opengl" => 1,
        "vulkan" | "native-vulkan" | "direct-vulkan" => 2,
        "angle-vulkan" => 3,
        "angle-swiftshader" => 4,
        _ => 5,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_parse_bool(
    val_ptr: *const c_char,
    val_len: usize,
    default_val: bool,
    out_valid: *mut bool,
) -> bool {
    let bytes = if val_ptr.is_null() || val_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(val_ptr as *const u8, val_len) }
    };
    match bytes {
        b"1" | b"true" | b"on" => {
            if !out_valid.is_null() {
                unsafe { *out_valid = true };
            }
            true
        }
        b"0" | b"false" | b"off" => {
            if !out_valid.is_null() {
                unsafe { *out_valid = true };
            }
            false
        }
        _ => {
            if !out_valid.is_null() {
                unsafe { *out_valid = false };
            }
            default_val
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_parse_positive_int(
    val_ptr: *const c_char,
    val_len: usize,
    default_val: c_int,
) -> c_int {
    if val_ptr.is_null() || val_len == 0 {
        return default_val;
    }
    let slice = unsafe { std::slice::from_raw_parts(val_ptr as *const u8, val_len) };
    if !slice.iter().all(|b| b.is_ascii_digit()) {
        return default_val;
    }
    match std::str::from_utf8(slice).ok().and_then(|s| s.parse::<i32>().ok()) {
        Some(v) if v > 0 => v,
        _ => default_val,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_is_discord_app_id(
    val_ptr: *const c_char,
    val_len: usize,
) -> bool {
    if val_len == 0 {
        return true;
    }
    if val_ptr.is_null() || !(17..=20).contains(&val_len) {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts(val_ptr as *const u8, val_len) };
    slice.iter().all(|b| b.is_ascii_digit())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_is_discord_text(
    val_ptr: *const c_char,
    val_len: usize,
    max_len: usize,
) -> bool {
    if val_ptr.is_null() || val_len == 0 || val_len > max_len {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts(val_ptr as *const u8, val_len) };
    slice.iter().all(|&b| b >= 0x20 && b != 0x7f)
}

// ============================================================================
// 120. Runtime Config Bootstrap
// ============================================================================

const DEFAULT_RUNTIME_CONFIG_YAML_WITH_NUL: &str =
    concat!(include_str!("../../../config/mocktail.example.yaml"), "\0");

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_default_yaml_ptr(
    out_len: *mut usize,
) -> *const c_char {
    let bytes = DEFAULT_RUNTIME_CONFIG_YAML_WITH_NUL.as_bytes();
    if !out_len.is_null() {
        unsafe { *out_len = bytes.len() - 1 };
    }
    bytes.as_ptr() as *const c_char
}

fn inspect_existing_config_file(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("refusing symlink runtime configuration".to_string());
            }
            if !metadata.file_type().is_file() {
                return Err("runtime configuration must be a regular file".to_string());
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot inspect first-run configuration: {}", e)),
    }
}

fn create_unique_temp_config(parent: &Path, fname: &str) -> Result<(std::fs::File, std::path::PathBuf), String> {
    use std::os::unix::fs::OpenOptionsExt;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let pid = std::process::id();
    for _ in 0..64 {
        let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent.join(format!(".{}.tmp.{}.{}", fname, pid, seq));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create temporary configuration: {}", e)),
        }
    }
    Err("cannot allocate unique temporary configuration path".to_string())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_config_ensure_file(
    path_ptr: *const c_char,
    out_created: *mut bool,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if !out_created.is_null() {
        unsafe { *out_created = false };
    }
    if !out_err.is_null() && err_cap > 0 {
        unsafe { *out_err = 0 };
    }
    if path_ptr.is_null() {
        copy_error(out_err, err_cap, "first-run configuration path must name a file");
        return -1;
    }
    let path_c = unsafe { CStr::from_ptr(path_ptr) };
    let path_str = match path_c.to_str() {
        Ok(s) => s,
        Err(_) => {
            copy_error(out_err, err_cap, "invalid configuration path encoding");
            return -1;
        }
    };
    let path = Path::new(path_str);
    let fname = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) if !path_str.is_empty() && !path_str.ends_with('/') && !n.is_empty() => n,
        _ => {
            copy_error(out_err, err_cap, "first-run configuration path must name a file");
            return -1;
        }
    };

    match inspect_existing_config_file(path) {
        Ok(true) => return 0,
        Ok(false) => {}
        Err(msg) => {
            copy_error(out_err, err_cap, &msg);
            return -1;
        }
    }

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let parent_existed = std::fs::symlink_metadata(parent).is_ok();
    if let Err(e) = std::fs::create_dir_all(parent) {
        copy_error(
            out_err,
            err_cap,
            &format!("cannot create configuration directory {}: {}", parent.display(), e),
        );
        return -1;
    }
    if !parent_existed {
        match std::fs::symlink_metadata(parent) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_dir() => {
                if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)) {
                    copy_error(out_err, err_cap, &format!("cannot secure configuration directory: {}", e));
                    return -1;
                }
            }
            Ok(_) => {
                copy_error(out_err, err_cap, "cannot secure configuration directory: unexpected non-directory");
                return -1;
            }
            Err(e) => {
                copy_error(out_err, err_cap, &format!("cannot secure configuration directory: {}", e));
                return -1;
            }
        }
    }

    let (mut file, tmp_path) = match create_unique_temp_config(parent, fname) {
        Ok(res) => res,
        Err(msg) => {
            copy_error(out_err, err_cap, &msg);
            return -1;
        }
    };

    let contents = &DEFAULT_RUNTIME_CONFIG_YAML_WITH_NUL.as_bytes()[..DEFAULT_RUNTIME_CONFIG_YAML_WITH_NUL.len() - 1];
    if let Err(e) = file.write_all(contents) {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        copy_error(out_err, err_cap, &format!("cannot write first-run configuration: {}", e));
        return -1;
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        copy_error(out_err, err_cap, &format!("cannot synchronize first-run configuration: {}", e));
        return -1;
    }
    drop(file);

    if let Err(e) = std::fs::hard_link(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            match inspect_existing_config_file(path) {
                Ok(true) => return 0,
                Ok(false) => {
                    copy_error(out_err, err_cap, "runtime configuration disappeared during creation");
                    return -1;
                }
                Err(msg) => {
                    copy_error(out_err, err_cap, &msg);
                    return -1;
                }
            }
        }
        copy_error(out_err, err_cap, &format!("cannot publish first-run configuration: {}", e));
        return -1;
    }

    if !out_created.is_null() {
        unsafe { *out_created = true };
    }
    if let Err(e) = std::fs::remove_file(&tmp_path) {
        copy_error(
            out_err,
            err_cap,
            &format!("configuration was created but its temporary link cannot be removed: {}", e),
        );
        return -1;
    }
    0
}

mod c_ffi {
    use std::ffi::c_void;
    use std::os::raw::{c_int, c_long};

    pub const PROT_READ: c_int = 1;
    pub const PROT_WRITE: c_int = 2;
    pub const PROT_EXEC: c_int = 4;
    pub const SC_PAGESIZE: c_int = 30;

    extern "C" {
        pub fn calloc(nmemb: usize, size: usize) -> *mut c_void;
        pub fn free(ptr: *mut c_void);
        pub fn sysconf(name: c_int) -> c_long;
        pub fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
    }
}

// ============================================================================
// 121. Host Allocator Bridge
// ============================================================================

const HOST_ALLOC_MAGIC: u64 = 0x4d4f434b5441494c;
const HOST_ALLOC_FRONT_PADDING: usize = 0x80;
const HOST_ALLOC_BACK_PADDING: usize = 0x200;
const HOST_ALLOC_MAX: usize = 1usize << 30;

#[repr(C)]
struct HostAllocHeader {
    magic: u64,
    raw: *mut std::ffi::c_void,
    requested_size: usize,
    usable_size: usize,
}

const HOST_ALLOC_SHARDS: usize = 64;

fn host_allocations_shard(
    pointer_addr: usize,
) -> &'static std::sync::Mutex<std::collections::HashMap<usize, usize>> {
    static SHARDS: std::sync::OnceLock<
        [std::sync::Mutex<std::collections::HashMap<usize, usize>>; HOST_ALLOC_SHARDS],
    > = std::sync::OnceLock::new();
    let shards = SHARDS.get_or_init(|| {
        std::array::from_fn(|_| std::sync::Mutex::new(std::collections::HashMap::new()))
    });
    let idx = ((pointer_addr >> 6) ^ (pointer_addr >> 13)) & (HOST_ALLOC_SHARDS - 1);
    &shards[idx]
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_aligned_allocate(
    size: usize,
    mut alignment: usize,
) -> *mut std::ffi::c_void {
    if size > HOST_ALLOC_MAX {
        return std::ptr::null_mut();
    }
    if alignment == 0 || (alignment & (alignment - 1)) != 0 {
        alignment = 16;
    }
    alignment = alignment.max(std::mem::align_of::<HostAllocHeader>());
    let actual_size = if size == 0 { 1 } else { size };
    let overhead = std::mem::size_of::<HostAllocHeader>()
        + HOST_ALLOC_FRONT_PADDING
        + HOST_ALLOC_BACK_PADDING
        + alignment
        - 1;
    if actual_size > usize::MAX - overhead {
        return std::ptr::null_mut();
    }
    let raw = unsafe { c_ffi::calloc(1, actual_size + overhead) };
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    let first = (raw as usize) + std::mem::size_of::<HostAllocHeader>() + HOST_ALLOC_FRONT_PADDING;
    let aligned = (first + alignment - 1) & !(alignment - 1);
    let header_addr = aligned - HOST_ALLOC_FRONT_PADDING - std::mem::size_of::<HostAllocHeader>();
    unsafe {
        std::ptr::write(
            header_addr as *mut HostAllocHeader,
            HostAllocHeader {
                magic: HOST_ALLOC_MAGIC,
                raw,
                requested_size: actual_size,
                usable_size: actual_size,
            },
        );
    }
    let mut guard = host_allocations_shard(aligned)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard.insert(aligned, header_addr);
    aligned as *mut std::ffi::c_void
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_allocate(size: usize) -> *mut std::ffi::c_void {
    mocktail_rust_host_aligned_allocate(size, 16)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_reallocate(
    pointer: *mut std::ffi::c_void,
    size: usize,
) -> *mut std::ffi::c_void {
    if pointer.is_null() {
        return mocktail_rust_host_allocate(size);
    }
    if size == 0 {
        mocktail_rust_host_free(pointer);
        return std::ptr::null_mut();
    }
    let copy_size = {
        let guard = host_allocations_shard(pointer as usize)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(&header_addr) = guard.get(&(pointer as usize)) {
            let header = unsafe { &*(header_addr as *const HostAllocHeader) };
            if header.magic == HOST_ALLOC_MAGIC {
                size.min(header.usable_size)
            } else {
                0
            }
        } else {
            0
        }
    };
    let replacement = mocktail_rust_host_allocate(size);
    if replacement.is_null() {
        return std::ptr::null_mut();
    }
    if copy_size != 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pointer as *const u8, replacement as *mut u8, copy_size);
        }
        mocktail_rust_host_free(pointer);
    }
    replacement
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_free(pointer: *mut std::ffi::c_void) {
    if pointer.is_null() {
        return;
    }
    let raw = {
        let mut guard = host_allocations_shard(pointer as usize)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let header_addr = match guard.remove(&(pointer as usize)) {
            Some(addr) => addr,
            None => return,
        };
        let header = unsafe { &mut *(header_addr as *mut HostAllocHeader) };
        if header.magic == HOST_ALLOC_MAGIC {
            header.magic = 0;
            header.raw
        } else {
            std::ptr::null_mut()
        }
    };
    if !raw.is_null() {
        unsafe { c_ffi::free(raw) };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_usable_size(pointer: *mut std::ffi::c_void) -> usize {
    if pointer.is_null() {
        return 0;
    }
    let guard = host_allocations_shard(pointer as usize)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match guard.get(&(pointer as usize)) {
        Some(&header_addr) => {
            let header = unsafe { &*(header_addr as *const HostAllocHeader) };
            if header.magic == HOST_ALLOC_MAGIC {
                header.usable_size
            } else {
                0
            }
        }
        None => 0,
    }
}

// ============================================================================
// 122. Host ABI Profile & Experiment Engine
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MocktailRustConstructorRange {
    pub begin: usize,
    pub end_exclusive: usize,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_has_valid_ranges(
    ranges_ptr: *const MocktailRustConstructorRange,
    range_count: usize,
    max_ranges: usize,
    init_array_count: usize,
) -> bool {
    if ranges_ptr.is_null() || range_count == 0 || range_count > max_ranges {
        return false;
    }
    let ranges = unsafe { std::slice::from_raw_parts(ranges_ptr, range_count) };
    let mut previous_end = 0usize;
    for (index, range) in ranges.iter().enumerate() {
        let valid_for = range.begin < range.end_exclusive && range.end_exclusive <= init_array_count;
        if !valid_for || (index != 0 && range.begin < previous_end) {
            return false;
        }
        previous_end = range.end_exclusive;
    }
    true
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_allows_constructor(
    ranges_ptr: *const MocktailRustConstructorRange,
    range_count: usize,
    max_ranges: usize,
    init_array_count: usize,
    index: usize,
) -> bool {
    if !mocktail_rust_host_abi_has_valid_ranges(ranges_ptr, range_count, max_ranges, init_array_count) {
        return false;
    }
    let ranges = unsafe { std::slice::from_raw_parts(ranges_ptr, range_count) };
    ranges
        .iter()
        .any(|r| r.begin <= index && index < r.end_exclusive)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_range_begin(
    ranges_ptr: *const MocktailRustConstructorRange,
    range_count: usize,
    max_ranges: usize,
    init_array_count: usize,
) -> usize {
    if !mocktail_rust_host_abi_has_valid_ranges(ranges_ptr, range_count, max_ranges, init_array_count) {
        return 0;
    }
    unsafe { (*ranges_ptr).begin }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_range_end_exclusive(
    ranges_ptr: *const MocktailRustConstructorRange,
    range_count: usize,
    max_ranges: usize,
    init_array_count: usize,
) -> usize {
    if !mocktail_rust_host_abi_has_valid_ranges(ranges_ptr, range_count, max_ranges, init_array_count) {
        return 0;
    }
    unsafe { (*ranges_ptr.add(range_count - 1)).end_exclusive }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_should_init_mimalloc_thread(
    ranges_ptr: *const MocktailRustConstructorRange,
    range_count: usize,
    max_ranges: usize,
    init_array_count: usize,
    init_after: usize,
    index: usize,
) -> bool {
    mocktail_rust_host_abi_has_valid_ranges(ranges_ptr, range_count, max_ranges, init_array_count)
        && init_after < init_array_count
        && mocktail_rust_host_abi_allows_constructor(
            ranges_ptr,
            range_count,
            max_ranges,
            init_array_count,
            init_after,
        )
        && index == init_after
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_resolve_allocator_strategy(
    default_strategy: c_int,
    override_present: bool,
    override_enabled: bool,
) -> c_int {
    if !override_present {
        return default_strategy;
    }
    if override_enabled { 0 } else { 1 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_patch_absolute_jump(
    address: usize,
    target: *mut std::ffi::c_void,
) -> bool {
    let page_size = unsafe { c_ffi::sysconf(c_ffi::SC_PAGESIZE) };
    if page_size <= 0 || address == 0 || target.is_null() {
        return false;
    }
    let target_addr = target as usize;
    #[cfg(target_arch = "aarch64")]
    let patch: [u8; 16] = {
        let mut buf = [
            0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        buf[8..16].copy_from_slice(&(target_addr as u64).to_ne_bytes());
        buf
    };
    #[cfg(not(target_arch = "aarch64"))]
    let patch: [u8; 12] = {
        let mut buf = [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0];
        buf[2..10].copy_from_slice(&(target_addr as u64).to_ne_bytes());
        buf
    };

    let page_mask = (page_size as usize) - 1;
    let page = address & !page_mask;
    let end = address + patch.len();
    let page_end = (end + page_mask) & !page_mask;
    let protect_size = page_end - page;
    if unsafe {
        c_ffi::mprotect(
            page as *mut std::ffi::c_void,
            protect_size,
            c_ffi::PROT_READ | c_ffi::PROT_WRITE | c_ffi::PROT_EXEC,
        )
    } != 0
    {
        return false;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), address as *mut u8, patch.len());
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        extern "C" {
            fn __clear_cache(beg: *mut c_char, end: *mut c_char);
        }
        __clear_cache(address as *mut c_char, (address + patch.len()) as *mut c_char);
    }
    unsafe {
        c_ffi::mprotect(
            page as *mut std::ffi::c_void,
            protect_size,
            c_ffi::PROT_READ | c_ffi::PROT_EXEC,
        ) == 0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_seed_jni_singleton(
    library_base: usize,
    jni_singleton_slot: usize,
    jni_singleton_bytes: usize,
    out_seeded_ptr: *mut *mut std::ffi::c_void,
) -> bool {
    if !out_seeded_ptr.is_null() {
        unsafe { *out_seeded_ptr = std::ptr::null_mut() };
    }
    if jni_singleton_slot == 0 || jni_singleton_bytes == 0 {
        return true;
    }
    let slot = (library_base + jni_singleton_slot) as *mut *mut std::ffi::c_void;
    if !unsafe { *slot }.is_null() {
        return true;
    }
    let object = unsafe { c_ffi::calloc(1, jni_singleton_bytes) };
    if object.is_null() {
        return false;
    }
    const K_LOAD_FACTOR_OFFSET: usize = 0x30 + 0x20;
    if jni_singleton_bytes >= K_LOAD_FACTOR_OFFSET + std::mem::size_of::<f32>() {
        let load_factor: f32 = 1.0;
        unsafe {
            std::ptr::copy_nonoverlapping(
                &load_factor.to_ne_bytes() as *const u8,
                (object as *mut u8).add(K_LOAD_FACTOR_OFFSET),
                std::mem::size_of::<f32>(),
            );
        }
    }
    unsafe {
        *slot = object;
        if !out_seeded_ptr.is_null() {
            *out_seeded_ptr = object;
        }
    }
    true
}

// ============================================================================
// 123. Window Game Surface Bridge Validation & State Machine
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustGameSurfaceBridgeSnapshot {
    pub accepted_events: u64,
    pub duplicate_events: u64,
    pub last_generation: u64,
    pub last_event_type: i32,
    pub failed: bool,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_surface_bridge_validate_event(
    event: *const MocktailRustSurfaceEvent,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    if event.is_null() {
        copy_error(out_err, err_cap, "window surface event is null");
        return -1;
    }
    let ev = unsafe { &*event };
    if ev.surface.generation == 0 {
        copy_error(out_err, err_cap, "window surface event has no generation");
        return -1;
    }
    match ev.event_type {
        0 | 2 => 0,
        1 => {
            if ev.surface.available == 0
                || ev.surface.native_window == 0
                || ev.surface.width == 0
                || ev.surface.height == 0
            {
                copy_error(
                    out_err,
                    err_cap,
                    "changed window surface requires an available handle and extent",
                );
                return -1;
            }
            0
        }
        _ => {
            copy_error(out_err, err_cap, "window surface event type is invalid");
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_surface_bridge_record_event(
    event: *const MocktailRustSurfaceEvent,
    changed: bool,
    io_snapshot: *mut MocktailRustGameSurfaceBridgeSnapshot,
) {
    if event.is_null() || io_snapshot.is_null() {
        return;
    }
    let ev = unsafe { &*event };
    let snap = unsafe { &mut *io_snapshot };
    snap.last_event_type = ev.event_type;
    snap.last_generation = ev.surface.generation;
    if changed {
        snap.accepted_events = snap.accepted_events.saturating_add(1);
    } else {
        snap.duplicate_events = snap.duplicate_events.saturating_add(1);
    }
}

