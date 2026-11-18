use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::slice;
use sha2::{Digest, Sha256};
use crate::*;

// ============================================================================
// 38. Present Mode Policy & Swapchain (Group 1)
// ============================================================================

pub(crate) fn copy_to_c_buffer(src: &str, dst: *mut c_char, cap: usize) -> c_int {
    if dst.is_null() || cap == 0 {
        return -1;
    }
    let src_bytes = src.as_bytes();
    if src_bytes.len() + 1 > cap {
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src_bytes.as_ptr() as *const c_char, dst, src_bytes.len());
        *dst.add(src_bytes.len()) = 0;
    }
    0
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustPresentModePolicy {
    HostDefault = 0,
    Vsync = 1,
    Unthrottled = 2,
    Fifo = 3,
    Mailbox = 4,
    Immediate = 5,
}

pub const VK_PRESENT_MODE_IMMEDIATE_KHR: u32 = 0;
pub const VK_PRESENT_MODE_MAILBOX_KHR: u32 = 1;
pub const VK_PRESENT_MODE_FIFO_KHR: u32 = 2;
pub const VK_PRESENT_MODE_FIFO_RELAXED_KHR: u32 = 3;
pub const VK_PRESENT_MODE_FIFO_LATEST_READY_KHR: u32 = 1000361000;

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_resolve(
    vsync_ptr: *const c_char,
    fps_ptr: *const c_char,
    pm_ptr: *const c_char,
) -> c_int {
    let vsync = if vsync_ptr.is_null() { "" } else { unsafe { CStr::from_ptr(vsync_ptr).to_str().unwrap_or("") } };
    let fps = if fps_ptr.is_null() { "" } else { unsafe { CStr::from_ptr(fps_ptr).to_str().unwrap_or("") } };
    let pm = if pm_ptr.is_null() { "" } else { unsafe { CStr::from_ptr(pm_ptr).to_str().unwrap_or("") } };

    if pm == "fifo" {
        return MocktailRustPresentModePolicy::Fifo as c_int;
    }
    if pm == "mailbox" {
        return MocktailRustPresentModePolicy::Mailbox as c_int;
    }
    if pm == "immediate" {
        return MocktailRustPresentModePolicy::Immediate as c_int;
    }
    if vsync == "on" || vsync == "1" {
        return MocktailRustPresentModePolicy::Vsync as c_int;
    }
    if vsync == "off" || vsync == "0" {
        return MocktailRustPresentModePolicy::Unthrottled as c_int;
    }
    if fps == "unlimited" {
        return MocktailRustPresentModePolicy::Unthrottled as c_int;
    }
    if fps.is_empty() || fps == "-1" {
        return MocktailRustPresentModePolicy::HostDefault as c_int;
    }
    MocktailRustPresentModePolicy::Vsync as c_int
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_explicit(
    policy: c_int,
    out_mode: *mut u32,
) -> c_int {
    if out_mode.is_null() {
        return 0;
    }
    match policy {
        3 /* Fifo */ => {
            unsafe { *out_mode = VK_PRESENT_MODE_FIFO_KHR; }
            1
        }
        4 /* Mailbox */ => {
            unsafe { *out_mode = VK_PRESENT_MODE_MAILBOX_KHR; }
            1
        }
        5 /* Immediate */ => {
            unsafe { *out_mode = VK_PRESENT_MODE_IMMEDIATE_KHR; }
            1
        }
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_swap_interval(
    policy: c_int,
    requested: c_int,
) -> c_int {
    match policy {
        0 /* HostDefault */ => requested,
        2 /* Unthrottled */ | 5 /* Immediate */ => 0,
        _ => 1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_resolve_vulkan_surface(
    configured: c_int,
    wayland_surface: i32,
) -> c_int {
    if wayland_surface != 0 && configured == MocktailRustPresentModePolicy::HostDefault as c_int {
        MocktailRustPresentModePolicy::Mailbox as c_int
    } else {
        configured
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_prefer_min_image_count(
    policy: c_int,
    requested: u32,
    min_images: u32,
    max_images: u32,
) -> u32 {
    if let Ok(env_val) = std::env::var("MOCKTAIL_SWAPCHAIN_IMAGES") {
        if let Ok(val) = env_val.trim().parse::<u32>() {
            if val > 0 {
                let mut c = val.max(min_images);
                if max_images != 0 {
                    c = c.min(max_images);
                }
                return c;
            }
        }
    }
    let mut count = requested.max(min_images);
    if policy == MocktailRustPresentModePolicy::Unthrottled as c_int {
        const UNTHROTTLED_IMAGES: u32 = 5;
        count = count.max(UNTHROTTLED_IMAGES);
        if min_images != 0 {
            count = count.max(min_images.saturating_add(2));
        }
    } else if policy == MocktailRustPresentModePolicy::Vsync as c_int {
        const VSYNC_IMAGES: u32 = 4;
        count = count.max(VSYNC_IMAGES);
        if min_images != 0 {
            count = count.max(min_images.saturating_add(2));
        }
    } else if policy == MocktailRustPresentModePolicy::Mailbox as c_int {
        count = count.max(3);
        // The presentation engine can retain more than two images. Mailbox
        // needs the surface minimum plus one to leave an image for acquisition.
        if min_images < u32::MAX {
            count = count.max(min_images + 1);
        }
    }
    if max_images != 0 {
        count = count.min(max_images);
    }
    count
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_filter(
    policy: c_int,
    host_modes_ptr: *const u32,
    host_count: usize,
    out_modes_ptr: *mut u32,
    out_cap: usize,
    out_count: *mut usize,
) -> c_int {
    if out_count.is_null()
        || (host_count > 0 && host_modes_ptr.is_null())
        || (out_cap > 0 && out_modes_ptr.is_null())
    {
        return -1;
    }

    if policy == MocktailRustPresentModePolicy::HostDefault as c_int || host_count == 0 {
        let copy_len = host_count.min(out_cap);
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(host_modes_ptr, out_modes_ptr, copy_len);
            }
        }
        unsafe {
            *out_count = copy_len;
        }
        return 0;
    }

    let host_modes = unsafe { std::slice::from_raw_parts(host_modes_ptr, host_count) };

    let mut explicit_mode = 0u32;
    if mocktail_rust_present_mode_explicit(policy, &mut explicit_mode) != 0 {
        if host_modes.contains(&explicit_mode) {
            if out_cap >= 1 {
                unsafe {
                    *out_modes_ptr = explicit_mode;
                    *out_count = 1;
                }
                return 0;
            }
        } else if host_modes.contains(&VK_PRESENT_MODE_FIFO_KHR) {
            if out_cap >= 1 {
                unsafe {
                    *out_modes_ptr = VK_PRESENT_MODE_FIFO_KHR;
                    *out_count = 1;
                }
                return 0;
            }
        }
        unsafe { *out_count = 0; }
        return 0;
    }

    let vsync_modes = [
        VK_PRESENT_MODE_FIFO_LATEST_READY_KHR,
        VK_PRESENT_MODE_MAILBOX_KHR,
        VK_PRESENT_MODE_FIFO_RELAXED_KHR,
        VK_PRESENT_MODE_FIFO_KHR,
    ];
    let unthrottled_modes = [
        VK_PRESENT_MODE_IMMEDIATE_KHR,
        VK_PRESENT_MODE_MAILBOX_KHR,
        VK_PRESENT_MODE_FIFO_RELAXED_KHR,
        VK_PRESENT_MODE_FIFO_KHR,
    ];

    let preferred = if policy == MocktailRustPresentModePolicy::Vsync as c_int {
        &vsync_modes[..]
    } else {
        &unthrottled_modes[..]
    };

    for &mode in preferred {
        if host_modes.contains(&mode) {
            if out_cap >= 1 {
                unsafe {
                    *out_modes_ptr = mode;
                    *out_count = 1;
                }
                return 0;
            }
        }
    }

    let copy_len = host_count.min(out_cap);
    if copy_len > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(host_modes_ptr, out_modes_ptr, copy_len);
        }
    }
    unsafe {
        *out_count = copy_len;
    }
    0
}

fn present_mode_khr_name_static(mode: u32) -> &'static [u8] {
    match mode {
        VK_PRESENT_MODE_IMMEDIATE_KHR => b"immediate\0",
        VK_PRESENT_MODE_MAILBOX_KHR => b"mailbox\0",
        VK_PRESENT_MODE_FIFO_KHR => b"fifo\0",
        VK_PRESENT_MODE_FIFO_RELAXED_KHR => b"fifo-relaxed\0",
        VK_PRESENT_MODE_FIFO_LATEST_READY_KHR => b"fifo-latest-ready\0",
        _ => b"other\0",
    }
}

fn present_mode_policy_name_static(policy: c_int) -> &'static [u8] {
    match policy {
        0 => b"host-default\0",
        1 => b"vsync\0",
        2 => b"unthrottled\0",
        3 => b"fifo\0",
        4 => b"mailbox\0",
        5 => b"immediate\0",
        _ => b"unknown\0",
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_khr_name_ptr(mode: u32) -> *const c_char {
    present_mode_khr_name_static(mode).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_policy_name_ptr(policy: c_int) -> *const c_char {
    present_mode_policy_name_static(policy).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_khr_name(
    mode: u32,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    let bytes = present_mode_khr_name_static(mode);
    let name = unsafe { std::str::from_utf8_unchecked(&bytes[..bytes.len() - 1]) };
    copy_to_c_buffer(name, out_buf, cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_present_mode_policy_name(
    policy: c_int,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    let bytes = present_mode_policy_name_static(policy);
    let name = unsafe { std::str::from_utf8_unchecked(&bytes[..bytes.len() - 1]) };
    copy_to_c_buffer(name, out_buf, cap)
}

// ============================================================================
// 39. Frame Rate Policy (Group 1)
// ============================================================================

pub const MOCKTAIL_MAXIMUM_SUPPORTED_ROBLOX_SCHEDULER_FPS: i32 = 240;

#[no_mangle]
pub extern "C" fn mocktail_rust_frame_rate_parse(
    val_ptr: *const c_char,
    out_mode: *mut c_int,
    out_fps: *mut c_int,
) -> c_int {
    if out_mode.is_null() || out_fps.is_null() {
        return -1;
    }
    let val = if val_ptr.is_null() { "" } else { unsafe { CStr::from_ptr(val_ptr).to_str().unwrap_or("") } };
    if val.is_empty() || val == "-1" {
        unsafe {
            *out_mode = 0; // kUnmanaged
            *out_fps = 0;
        }
        return 0;
    }
    if val == "display" {
        unsafe {
            *out_mode = 1; // kDisplay
            *out_fps = 0;
        }
        return 0;
    }
    if val == "unlimited" {
        unsafe {
            *out_mode = 3; // kUnlimited
            *out_fps = 0;
        }
        return 0;
    }
    if let Ok(fps) = val.parse::<i32>() {
        if fps > 0 && !val.starts_with('+') {
            unsafe {
                *out_mode = 2; // kFixed
                *out_fps = fps;
            }
            return 0;
        }
    }
    unsafe {
        *out_mode = 4; // kInvalid
        *out_fps = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_frame_rate_merge_client_settings(
    mode: c_int,
    fps: c_int,
    base_json_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_to_c_buffer(msg, out_err, err_cap);
    };

    if mode == 4 /* kInvalid */ {
        set_err("invalid frame-rate policy");
        return -1;
    }

    let base_json_str = if base_json_ptr.is_null() {
        "{}"
    } else {
        unsafe {
            CStr::from_ptr(base_json_ptr).to_str().unwrap_or("{}")
        }
    };
    let input_str = if base_json_str.is_empty() { "{}" } else { base_json_str };

    let mut parsed: serde_json::Value = match serde_json::from_str(input_str) {
        Ok(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
        _ => {
            set_err("client-settings overrides must be a JSON object");
            return -2;
        }
    };

    let obj = parsed.as_object_mut().unwrap();

    const CAP5_KEY: &str = "FFlagGameBasicSettingsFramerateCap5";
    if let Some(existing) = obj.get(CAP5_KEY) {
        if existing.as_str() != Some("True") {
            set_err(&format!("frame-rate policy conflicts with {}", CAP5_KEY));
            return -3;
        }
    } else {
        obj.insert(CAP5_KEY.to_string(), serde_json::Value::String("True".to_string()));
    }

    if mode == 0 /* kUnmanaged */ || mode == 1 /* kDisplay */ {
        let serialized = serde_json::to_string(&parsed).unwrap_or_else(|_| "{}".to_string());
        if copy_to_c_buffer(&serialized, out_buf, out_cap) != 0 {
            set_err("output buffer too small");
            return -5;
        }
        return 0;
    }

    let target_fps = if mode == 3 /* kUnlimited */ {
        MOCKTAIL_MAXIMUM_SUPPORTED_ROBLOX_SCHEDULER_FPS
    } else {
        fps
    };
    let target_str = target_fps.to_string();

    const TARGET_KEY: &str = "DFIntTaskSchedulerTargetFps";
    if let Some(existing) = obj.get(TARGET_KEY) {
        if existing.as_str() != Some(&target_str) {
            set_err(&format!("frame-rate policy conflicts with {}", TARGET_KEY));
            return -4;
        }
    } else {
        obj.insert(TARGET_KEY.to_string(), serde_json::Value::String(target_str));
    }

    let serialized = serde_json::to_string(&parsed).unwrap_or_else(|_| "{}".to_string());
    if copy_to_c_buffer(&serialized, out_buf, out_cap) != 0 {
        set_err("output buffer too small");
        return -5;
    }
    0
}

// ============================================================================
// 40. Gamepad & Input Mapping (Group 2)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_gamepad_valid_id(id: i64) -> c_int {
    if id > 0 && id <= (u32::MAX as i64) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gamepad_family(sdl_type: c_int) -> c_int {
    match sdl_type {
        1 | 2 => 1, // kXbox
        3 | 4 => 2, // kPlayStation4
        5 => 3,     // kPlayStation5
        _ => 0,     // kUnknown
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gamepad_button_to_android(button: u8) -> i32 {
    match button {
        0 /* SOUTH */ => 96,
        1 /* EAST */ => 97,
        2 /* WEST */ => 99,
        3 /* NORTH */ => 100,
        11 /* DPAD_UP */ => 19,
        12 /* DPAD_DOWN */ => 20,
        13 /* DPAD_LEFT */ => 21,
        14 /* DPAD_RIGHT */ => 22,
        9 /* LEFT_SHOULDER */ => 102,
        10 /* RIGHT_SHOULDER */ => 103,
        7 /* LEFT_STICK */ => 106,
        8 /* RIGHT_STICK */ => 107,
        6 /* START */ => 108,
        4 /* BACK */ => 109,
        _ => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_roblox_gamepad_type(family: c_int) -> i32 {
    match family {
        2 /* kPlayStation4 */ => 1,
        3 /* kPlayStation5 */ => 2,
        1 /* kXbox */ => 3,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gamepad_signed_axis(val: i16) -> f32 {
    (val as f32) / (if val < 0 { 32768.0 } else { 32767.0 })
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gamepad_stick(
    raw_x: i16,
    raw_y: i16,
    out_x: *mut f32,
    out_y: *mut f32,
) {
    if out_x.is_null() || out_y.is_null() {
        return;
    }
    const DEADZONE: f32 = 0.20;
    let x = mocktail_rust_gamepad_signed_axis(raw_x);
    let y = -mocktail_rust_gamepad_signed_axis(raw_y);
    let length = (x * x + y * y).sqrt();
    if length <= DEADZONE {
        unsafe {
            *out_x = 0.0;
            *out_y = 0.0;
        }
        return;
    }
    let scale = (length.min(1.0) - DEADZONE) / ((1.0 - DEADZONE) * length);
    unsafe {
        *out_x = x * scale;
        *out_y = y * scale;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gamepad_trigger(raw: i16) -> f32 {
    const DEADZONE: f32 = 0.02;
    let val = 0.0f32.max((raw as f32) / 32767.0);
    if val <= DEADZONE {
        0.0
    } else {
        (val - DEADZONE) / (1.0 - DEADZONE)
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_sdl_finger_action(sdl_type: u32) -> c_int {
    match sdl_type {
        0x700 => 0, // Down
        0x701 => 1, // Up
        0x702 => 2, // Move
        0x703 => 3, // Cancelled
        _ => -1,
    }
}

// ============================================================================
// 41. Device Memory Profile & Class Name (Group 3)
// ============================================================================

#[repr(C)]
pub struct MocktailRustDeviceMemoryProfile {
    pub total_memory_mb: i32,
    pub memory_class_mb: i32,
    pub large_memory_class_mb: i32,
    pub low_memory_killer_background_threshold: i32,
    pub low_memory_killer_foreground_threshold: i32,
    pub low_ram_device: c_int,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_build_device_memory_profile(
    host_memory_bytes: u64,
    out_profile: *mut MocktailRustDeviceMemoryProfile,
) {
    if out_profile.is_null() {
        return;
    }
    const MEBIBYTE: u64 = 1024 * 1024;
    const MINIMUM_NORMAL_RAM_BYTES: u64 = 4096 * MEBIBYTE;

    if host_memory_bytes < MINIMUM_NORMAL_RAM_BYTES {
        unsafe {
            (*out_profile).total_memory_mb = 2048;
            (*out_profile).memory_class_mb = 256;
            (*out_profile).large_memory_class_mb = 512;
            (*out_profile).low_memory_killer_background_threshold = 256;
            (*out_profile).low_memory_killer_foreground_threshold = 512;
            (*out_profile).low_ram_device = 1;
        }
        return;
    }

    let mb = (host_memory_bytes / MEBIBYTE).min(i32::MAX as u64) as i32;
    unsafe {
        (*out_profile).total_memory_mb = mb;
        (*out_profile).memory_class_mb = 512;
        (*out_profile).large_memory_class_mb = 1024;
        (*out_profile).low_memory_killer_background_threshold = 0;
        (*out_profile).low_memory_killer_foreground_threshold = 0;
        (*out_profile).low_ram_device = 0;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_device_class_name(
    device_class: c_int,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    let name = match device_class {
        0 => "pc",
        1 => "mobile",
        2 => "console",
        _ => "unknown",
    };
    copy_to_c_buffer(name, out_buf, cap)
}

// ============================================================================
// 42. Payload Integrity & Candidate Approval (Group 4)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_hash_text(
    text_ptr: *const c_char,
    text_len: usize,
    max_hex_chars: usize,
    out_hex: *mut c_char,
    hex_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    if text_ptr.is_null() || out_hex.is_null() {
        if !out_err.is_null() && err_cap > 0 {
            copy_to_c_buffer("invalid null argument", out_err, err_cap);
        }
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(text_ptr as *const u8, text_len) };
    let hash = Sha256::digest(bytes);
    let mut full_hex = String::with_capacity(64);
    for byte in hash.iter() {
        use std::fmt::Write;
        let _ = write!(&mut full_hex, "{:02x}", byte);
    }
    let result_str = if max_hex_chars > 0 && max_hex_chars < full_hex.len() {
        &full_hex[..max_hex_chars]
    } else {
        &full_hex[..]
    };
    copy_to_c_buffer(result_str, out_hex, hex_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_is_lower_hex(
    val_ptr: *const c_char,
    expected_len: usize,
) -> c_int {
    if val_ptr.is_null() {
        return 0;
    }
    let s = unsafe { CStr::from_ptr(val_ptr).to_str().unwrap_or("") };
    if s.len() != expected_len {
        return 0;
    }
    for b in s.bytes() {
        if !b.is_ascii_digit() && !(b >= b'a' && b <= b'f') {
            return 0;
        }
    }
    1
}

// ============================================================================
// 43. Session Log & Hardware Detection Helpers (Group 5)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_pci_vendor_fallback(
    vendor_id_ptr: *const c_char,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    if vendor_id_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let vid = unsafe { CStr::from_ptr(vendor_id_ptr).to_str().unwrap_or("") };
    let name = match vid {
        "1002" => "AMD".to_string(),
        "10de" => "NVIDIA".to_string(),
        "8086" => "Intel".to_string(),
        "13b5" => "Arm".to_string(),
        "5143" => "Qualcomm".to_string(),
        "14e4" => "Broadcom".to_string(),
        "1af4" => "Virtio".to_string(),
        "15ad" => "VMware".to_string(),
        _ => format!("PCI {}", vid),
    };
    copy_to_c_buffer(&name, out_buf, cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_hex_id(
    input_ptr: *const c_char,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    if input_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let mut s = unsafe { CStr::from_ptr(input_ptr).to_str().unwrap_or("").trim() };
    if s.starts_with("0x") || s.starts_with("0X") {
        s = &s[2..];
    }
    let lower = s.to_ascii_lowercase();
    if lower.len() == 4 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        copy_to_c_buffer(&lower, out_buf, cap)
    } else {
        unsafe {
            if cap > 0 { *out_buf = 0; }
        }
        -1
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_meminfo_total(
    contents_ptr: *const c_char,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    if contents_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let text = unsafe { CStr::from_ptr(contents_ptr).to_str().unwrap_or("") };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("MemTotal:") {
            let rest = trimmed["MemTotal:".len()..].trim();
            let mut parts = rest.split_whitespace();
            if let Some(num_str) = parts.next() {
                if let Ok(kib) = num_str.parse::<u64>() {
                    let mib = (kib + 512) / 1024;
                    let formatted = format!("{}MiB", mib);
                    return copy_to_c_buffer(&formatted, out_buf, cap);
                }
            }
        }
    }
    copy_to_c_buffer("unknown", out_buf, cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_cpuinfo_model(
    contents_ptr: *const c_char,
    out_buf: *mut c_char,
    cap: usize,
) -> c_int {
    if contents_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let text = unsafe { CStr::from_ptr(contents_ptr).to_str().unwrap_or("") };
    let mut fallback = String::new();
    for line in text.lines() {
        if let Some(sep) = line.find(':') {
            let key = line[..sep].trim();
            let val = line[sep + 1..].trim();
            if val.is_empty() {
                continue;
            }
            if key == "model name" {
                return copy_to_c_buffer(val, out_buf, cap);
            }
            if fallback.is_empty() && (key == "Hardware" || key == "Processor") {
                fallback = val.to_string();
            }
        }
    }
    if !fallback.is_empty() {
        return copy_to_c_buffer(&fallback, out_buf, cap);
    }
    copy_to_c_buffer("unknown", out_buf, cap)
}

// ============================================================================
// 44. Window Readiness Gates (Group A)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_request_from_android_flags(
    flags: i32,
    mask: i32,
    current_android_flags: *mut u32,
    pending_state: *mut i32,
) -> c_int {
    if current_android_flags.is_null() || pending_state.is_null() {
        return 0;
    }
    let requested_mask = mask as u32;
    const K_RELEVANT_FLAGS: u32 = 0x00000400 | 0x00000800;
    if (requested_mask & K_RELEVANT_FLAGS) == 0 {
        return 0;
    }
    let requested_flags = flags as u32;
    unsafe {
        *current_android_flags =
            (*current_android_flags & !requested_mask) | (requested_flags & requested_mask);
        let fullscreen = (*current_android_flags & 0x00000400) != 0
            && (*current_android_flags & 0x00000800) == 0;
        *pending_state = if fullscreen { 2 } else { 1 };
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_fullscreen_take(
    pending_state: *mut i32,
    out_fullscreen: *mut c_int,
) -> c_int {
    if pending_state.is_null() || out_fullscreen.is_null() {
        return 0;
    }
    unsafe {
        if *pending_state == 0 {
            return 0;
        }
        *out_fullscreen = if *pending_state == 2 { 1 } else { 0 };
        *pending_state = 0;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_roblox_fullscreen_menu_is_cycle(
    message_ptr: *const c_char,
) -> c_int {
    if message_ptr.is_null() {
        return 0;
    }
    let msg = unsafe { CStr::from_ptr(message_ptr).to_str().unwrap_or("") };
    if msg.contains("Maximum event re-entrancy depth exceeded for BindableEvent.Event")
        && msg.contains("CoreGui.RobloxGui.Modules.Settings.Pages.GameSettings")
    {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_roblox_fullscreen_menu_request(
    tag_ptr: *const c_char,
    message_ptr: *const c_char,
    monotonic_ns: u64,
    suppress_until_ns: u64,
    last_request_ns: *mut u64,
    pending: *mut c_int,
) -> c_int {
    if tag_ptr.is_null() || last_request_ns.is_null() || pending.is_null() {
        return 0;
    }
    let tag = unsafe { CStr::from_ptr(tag_ptr).to_str().unwrap_or("") };
    if tag != "Roblox" || mocktail_rust_roblox_fullscreen_menu_is_cycle(message_ptr) == 0 {
        return 0;
    }
    if monotonic_ns < suppress_until_ns {
        return 1;
    }
    unsafe {
        *pending = 1;
        *last_request_ns = monotonic_ns;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_roblox_fullscreen_menu_take(
    monotonic_ns: u64,
    last_request_ns: u64,
    quiet_ns: u64,
    suppress_ns: u64,
    suppress_until_ns: *mut u64,
    pending: *mut c_int,
) -> c_int {
    if suppress_until_ns.is_null() || pending.is_null() {
        return 0;
    }
    unsafe {
        if *pending == 0
            || monotonic_ns < last_request_ns
            || monotonic_ns - last_request_ns < quiet_ns
        {
            return 0;
        }
        *pending = 0;
        *suppress_until_ns = monotonic_ns + suppress_ns;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_state_name(state: u32) -> *const c_char {
    let s = match state {
        0 => "Disabled\0",
        1 => "WaitingForFirstPresent\0",
        2 => "ReadyToRequestResize\0",
        3 => "ResizeRequested\0",
        4 => "SurfaceCommitted\0",
        5 => "PostRebindPresented\0",
        6 => "Stopped\0",
        7 => "Failed\0",
        _ => "Unknown\0",
    };
    s.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_activate(
    enabled: c_int,
    target_width: u32,
    target_height: u32,
    initial_available: c_int,
    initial_generation: u64,
    initial_native_window: u64,
    initial_width: u32,
    initial_height: u32,
    state: *mut u32,
    surface_generation: *mut u64,
    target_width_out: *mut u32,
    target_height_out: *mut u32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if state.is_null() || surface_generation.is_null() || target_width_out.is_null() || target_height_out.is_null() {
        return -1;
    }
    unsafe {
        if *state != 0 || *surface_generation != 0 {
            copy_to_c_buffer("window resize readiness gate is already active", err_buf, err_cap);
            return -2; /* FailedPrecondition */
        }
        if enabled == 0 {
            return 0;
        }
        if initial_available == 0
            || initial_generation == 0
            || initial_native_window == 0
            || initial_width == 0
            || initial_height == 0
        {
            copy_to_c_buffer("window resize readiness gate requires an available initial surface", err_buf, err_cap);
            return -1; /* InvalidArgument */
        }
        if target_width == 0 || target_height == 0 {
            copy_to_c_buffer("window resize target must have a positive extent", err_buf, err_cap);
            return -1; /* InvalidArgument */
        }
        if target_width == initial_width && target_height == initial_height {
            copy_to_c_buffer("window resize target must differ from initial extent", err_buf, err_cap);
            return -1; /* InvalidArgument */
        }
        *state = 1; /* kWaitingForFirstPresent */
        *surface_generation = initial_generation;
        *target_width_out = target_width;
        *target_height_out = target_height;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_record_present(
    frame_serial: u64,
    state: *mut u32,
    first_present_serial: *mut u64,
    post_rebind_present_serial: *mut u64,
    failure_reason: *const c_char,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if state.is_null() || first_present_serial.is_null() || post_rebind_present_serial.is_null() {
        return -1;
    }
    unsafe {
        if *state == 0 /* kDisabled */ {
            return 0;
        }
        if *state == 7 /* kFailed */ || *state == 6 /* kStopped */ {
            let msg = if !failure_reason.is_null() && *failure_reason != 0 {
                CStr::from_ptr(failure_reason).to_str().unwrap_or("window resize readiness gate cannot accept a present")
            } else {
                "window resize readiness gate cannot accept a present"
            };
            copy_to_c_buffer(msg, err_buf, err_cap);
            return -2; /* FailedPrecondition */
        }
        if frame_serial == 0 {
            *state = 7; /* kFailed */
            copy_to_c_buffer("resize readiness received a zero present serial", err_buf, err_cap);
            return -2;
        }
        if *state == 1 /* kWaitingForFirstPresent */ {
            *first_present_serial = frame_serial;
            *state = 2; /* kReadyToRequestResize */
            return 0;
        }
        if *state == 4 /* kSurfaceCommitted */ {
            if frame_serial <= *first_present_serial {
                *state = 7; /* kFailed */
                copy_to_c_buffer("post-rebind present serial does not follow the first present", err_buf, err_cap);
                return -2;
            }
            *post_rebind_present_serial = frame_serial;
            *state = 5; /* kPostRebindPresented */
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_take_request(
    state: *mut u32,
    target_width: u32,
    target_height: u32,
    out_width: *mut u32,
    out_height: *mut u32,
) -> c_int {
    if state.is_null() || out_width.is_null() || out_height.is_null() {
        return 0;
    }
    unsafe {
        if *state != 2 /* kReadyToRequestResize */ {
            return 0;
        }
        *out_width = target_width;
        *out_height = target_height;
        *state = 3; /* kResizeRequested */
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_record_surface_event(
    event_type: c_int,
    available: c_int,
    generation: u64,
    native_window: u64,
    width: u32,
    height: u32,
    state: *mut u32,
    surface_generation: u64,
    target_width: u32,
    target_height: u32,
    failure_reason: *const c_char,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if state.is_null() {
        return -1;
    }
    unsafe {
        if *state == 0 /* kDisabled */ {
            return 0;
        }
        if *state == 7 /* kFailed */ || *state == 6 /* kStopped */ {
            let msg = if !failure_reason.is_null() && *failure_reason != 0 {
                CStr::from_ptr(failure_reason).to_str().unwrap_or("window resize readiness gate cannot accept a surface event")
            } else {
                "window resize readiness gate cannot accept a surface event"
            };
            copy_to_c_buffer(msg, err_buf, err_cap);
            return -2;
        }
        if *state != 3 /* kResizeRequested */ {
            return 0;
        }
        if event_type == 0 /* kCreated */ || event_type == 2 /* kDestroyed */ {
            *state = 7;
            copy_to_c_buffer("resize recreated the surface instead of preserving its generation", err_buf, err_cap);
            return -2;
        }
        if generation != surface_generation {
            *state = 7;
            copy_to_c_buffer("resize committed a different surface generation", err_buf, err_cap);
            return -2;
        }
        if available == 0 || native_window == 0 {
            *state = 7;
            copy_to_c_buffer("resize committed an unavailable surface", err_buf, err_cap);
            return -2;
        }
        if width != target_width || height != target_height {
            return 0; /* intermediate configure */
        }
        *state = 4; /* kSurfaceCommitted */
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_record_stopped(
    state: *mut u32,
    failure_reason: *const c_char,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if state.is_null() {
        return -1;
    }
    unsafe {
        if *state == 0 /* kDisabled */ {
            return 0;
        }
        if *state == 7 /* kFailed */ {
            let msg = if !failure_reason.is_null() && *failure_reason != 0 {
                CStr::from_ptr(failure_reason).to_str().unwrap_or("window resize failed")
            } else {
                "window resize failed"
            };
            copy_to_c_buffer(msg, err_buf, err_cap);
            return -2;
        }
        if *state != 5 /* kPostRebindPresented */ {
            *state = 7;
            copy_to_c_buffer("runtime stopped before resize rebind produced a later present", err_buf, err_cap);
            return -2;
        }
        *state = 6; /* kStopped */
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_resize_completion_status(
    state: u32,
    failure_reason: *const c_char,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if state == 0 /* kDisabled */ || state == 6 /* kStopped */ {
        return 0;
    }
    if state == 7 /* kFailed */ {
        let msg = if !failure_reason.is_null() && unsafe { *failure_reason != 0 } {
            unsafe { CStr::from_ptr(failure_reason).to_str().unwrap_or("window resize failed") }
        } else {
            "window resize failed"
        };
        copy_to_c_buffer(msg, err_buf, err_cap);
        return -2;
    }
    copy_to_c_buffer("window resize readiness evidence is incomplete", err_buf, err_cap);
    -2
}

// ============================================================================
// 45. Roblox Text Editor & UTF-8 / Grapheme Engine (Group B)
// ============================================================================

use unicode_segmentation::UnicodeSegmentation;

#[no_mangle]
pub extern "C" fn mocktail_rust_text_layout(
    utf8_ptr: *const c_char,
    utf8_len: usize,
    out_utf16_units: *mut i32,
    out_boundaries: *mut usize,
    boundaries_cap: usize,
    out_boundary_count: *mut usize,
) -> c_int {
    if utf8_ptr.is_null() && utf8_len > 0 {
        return 0;
    }
    let slice = if utf8_len == 0 {
        ""
    } else {
        let raw_slice = unsafe { slice::from_raw_parts(utf8_ptr as *const u8, utf8_len) };
        match std::str::from_utf8(raw_slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let mut utf16_units: i64 = 0;
    for c in slice.chars() {
        utf16_units += c.len_utf16() as i64;
    }
    if utf16_units > i32::MAX as i64 {
        return 0;
    }
    if !out_utf16_units.is_null() {
        unsafe { *out_utf16_units = utf16_units as i32 };
    }

    let mut count: usize = 1;
    let mut last_offset: usize = 0;
    if !out_boundaries.is_null() && boundaries_cap > 0 {
        unsafe { *out_boundaries = 0 };
    }
    for (offset, _) in slice.grapheme_indices(true) {
        if offset > 0 {
            if !out_boundaries.is_null() && count < boundaries_cap {
                unsafe { *out_boundaries.add(count) = offset };
            }
            count += 1;
            last_offset = offset;
        }
    }
    if slice.len() > last_offset {
        if !out_boundaries.is_null() && count < boundaries_cap {
            unsafe { *out_boundaries.add(count) = slice.len() };
        }
        count += 1;
    }

    if !out_boundary_count.is_null() {
        unsafe { *out_boundary_count = count };
    }

    1 /* valid */
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_utf16_cursor(
    utf8_ptr: *const c_char,
    utf8_len: usize,
    byte_offset: usize,
) -> i32 {
    if utf8_ptr.is_null() || utf8_len == 0 || byte_offset == 0 {
        return 0;
    }
    let limit = std::cmp::min(utf8_len, byte_offset);
    let raw_slice = unsafe { slice::from_raw_parts(utf8_ptr as *const u8, limit) };
    let s = match std::str::from_utf8(raw_slice) {
        Ok(valid) => valid,
        Err(e) => match std::str::from_utf8(&raw_slice[..e.valid_up_to()]) {
            Ok(part) => part,
            Err(_) => return 0,
        },
    };
    let mut units: i32 = 0;
    for c in s.chars() {
        units += c.len_utf16() as i32;
    }
    units
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_char_to_byte_offset(
    utf8_ptr: *const c_char,
    utf8_len: usize,
    char_index: i32,
) -> usize {
    if utf8_ptr.is_null() || utf8_len == 0 || char_index < 0 {
        return utf8_len;
    }
    let raw_slice = unsafe { slice::from_raw_parts(utf8_ptr as *const u8, utf8_len) };
    let s = match std::str::from_utf8(raw_slice) {
        Ok(val) => val,
        Err(_) => return utf8_len,
    };
    for (i, (byte_offset, _)) in s.char_indices().enumerate() {
        if i == char_index as usize {
            return byte_offset;
        }
    }
    utf8_len
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_shortcut_bit(scancode: u32) -> u32 {
    match scancode {
        4 => 1 << 0,  /* SDL_SCANCODE_A -> kShortcutSelectAll */
        6 => 1 << 1,  /* SDL_SCANCODE_C -> kShortcutCopy */
        25 => 1 << 2, /* SDL_SCANCODE_V -> kShortcutPaste */
        27 => 1 << 3, /* SDL_SCANCODE_X -> kShortcutCut */
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_is_password_input(text_input_type: i32) -> c_int {
    if text_input_type == 5 || text_input_type == 9 || text_input_type == 10 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_prev_grapheme(
    utf8_ptr: *const c_char,
    utf8_len: usize,
    cursor_byte: usize,
) -> usize {
    if utf8_ptr.is_null() || utf8_len == 0 || cursor_byte == 0 {
        return 0;
    }
    let raw_slice = unsafe { slice::from_raw_parts(utf8_ptr as *const u8, utf8_len) };
    let s = match std::str::from_utf8(raw_slice) {
        Ok(v) => v,
        Err(_) => return cursor_byte,
    };
    let mut prev = 0;
    for (offset, _) in s.grapheme_indices(true) {
        if offset >= cursor_byte {
            return prev;
        }
        prev = offset;
    }
    prev
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_next_grapheme(
    utf8_ptr: *const c_char,
    utf8_len: usize,
    cursor_byte: usize,
) -> usize {
    if utf8_ptr.is_null() || utf8_len == 0 {
        return 0;
    }
    let raw_slice = unsafe { slice::from_raw_parts(utf8_ptr as *const u8, utf8_len) };
    let s = match std::str::from_utf8(raw_slice) {
        Ok(v) => v,
        Err(_) => return cursor_byte,
    };
    for (offset, _) in s.grapheme_indices(true) {
        if offset > cursor_byte {
            return offset;
        }
    }
    utf8_len
}

// ============================================================================
// 46. External Launch Broker & Wire Protocol (moved to external_launch_broker.rs)
// ============================================================================

// ============================================================================
// 47. Split APK & Bundle Layout Resolver (Group D)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_apk_guest_lib_entry_name(
    abi_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    if abi_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let abi = unsafe { CStr::from_ptr(abi_ptr).to_str().unwrap_or("arm64-v8a") };
    let entry = format!("lib/{}/libroblox.so", abi);
    copy_to_c_buffer(&entry, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_valid_id(
    id_ptr: *const c_char,
    len: usize,
) -> c_int {
    if id_ptr.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { slice::from_raw_parts(id_ptr as *const u8, len) };
    match std::str::from_utf8(slice) {
        Ok(val) if storage_paths::is_valid_payload_id_only(val) => 1,
        _ => 0,
    }
}

// ============================================================================
// 48. Audio Buffer Queue & Output Device Bridge (Group E)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_opensl_result_from_status_code(status_code: i32) -> u32 {
    match status_code {
        0 => 0,  /* SL_RESULT_SUCCESS */
        1 => 2,  /* SL_RESULT_PARAMETER_INVALID */
        2 => 3,  /* SL_RESULT_PRECONDITIONS_VIOLATED */
        3 => 4,  /* SL_RESULT_RESOURCE_ERROR */
        4 => 12, /* SL_RESULT_FEATURE_UNSUPPORTED */
        5 => 6,  /* SL_RESULT_IO_ERROR */
        _ => 1,  /* SL_RESULT_INTERNAL_ERROR */
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_device_stable_guid(
    name_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    if name_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let name = unsafe { CStr::from_ptr(name_ptr).to_str().unwrap_or("") };
    let hash = Sha256::digest(name.as_bytes());
    let b = &hash[..16];
    let guid = format!(
        "{{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    );
    copy_to_c_buffer(&guid, out_buf, out_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_is_valid_elf_header(
    bytes_ptr: *const u8,
    len: usize,
) -> c_int {
    if bytes_ptr.is_null() || len < 64 {
        return 0;
    }
    let slice = unsafe { slice::from_raw_parts(bytes_ptr, len) };
    if &slice[0..4] != b"\x7fELF" || slice[4] != 2 /* ELFCLASS64 */ {
        return 0;
    }
    let phoff = u64::from_le_bytes(slice[32..40].try_into().unwrap());
    let phnum = u16::from_le_bytes(slice[56..58].try_into().unwrap());
    if phoff != 0 && phnum != 0 {
        1
    } else {
        0
    }
}

// ============================================================================
// 49. Discord RPC & Rich Presence Helpers
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_discord_has_join_target(
    place_id: i64,
    instance_id: *const c_char,
    instance_id_len: usize,
) -> bool {
    let slice = if instance_id.is_null() || instance_id_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(instance_id as *const u8, instance_id_len)
    };
    crate::discord_rpc::has_join_target_bytes(place_id, slice)
}

pub(crate) fn truncate_utf8_bytes(slice: &[u8], maximum: usize) -> usize {
    if slice.len() <= maximum {
        return slice.len();
    }
    let mut boundary = maximum;
    while boundary > 0 && (slice[boundary] & 0xc0) == 0x80 {
        boundary -= 1;
    }
    boundary
}

pub(crate) fn truncate_utf8_str(s: &str, maximum: usize) -> &str {
    let end = truncate_utf8_bytes(s.as_bytes(), maximum);
    &s[..end]
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_discord_truncate_utf8(
    src: *const c_char,
    src_len: usize,
    maximum: usize,
) -> usize {
    if src.is_null() || src_len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(src as *const u8, src_len);
    truncate_utf8_bytes(slice, maximum)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_discord_percent_encode(
    src: *const c_char,
    src_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    if src.is_null() || src_len == 0 {
        *out_len = 0;
        return 0;
    }
    let slice = std::slice::from_raw_parts(src as *const u8, src_len);
    let encoded = crate::discord_rpc::percent_encode_bytes(slice);
    let bytes = encoded.as_bytes();
    *out_len = bytes.len();
    if out_buf.is_null() {
        return 0;
    }
    let copy_len = bytes.len().min(out_cap);
    if copy_len > 0 {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
    }
    if bytes.len() > out_cap {
        return -2;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_discord_render_place_template(
    template: *const c_char,
    template_len: usize,
    place_name: *const c_char,
    place_name_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    let t_slice = if template.is_null() || template_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(template as *const u8, template_len)
    };
    let p_slice = if place_name.is_null() || place_name_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(place_name as *const u8, place_name_len)
    };

    let placeholder = b"{place_name}";
    let mut rendered: Vec<u8> = Vec::with_capacity(t_slice.len() + p_slice.len());
    let mut i = 0;
    while i < t_slice.len() {
        if i + placeholder.len() <= t_slice.len() && &t_slice[i..i + placeholder.len()] == placeholder {
            rendered.extend_from_slice(p_slice);
            i += placeholder.len();
        } else {
            rendered.push(t_slice[i]);
            i += 1;
        }
    }

    let truncated_len = mocktail_rust_discord_truncate_utf8(
        rendered.as_ptr() as *const c_char,
        rendered.len(),
        128,
    );
    *out_len = truncated_len;
    if out_buf.is_null() || out_cap < truncated_len {
        return if out_buf.is_null() { 0 } else { -2 };
    }
    std::ptr::copy_nonoverlapping(rendered.as_ptr(), out_buf, truncated_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_discord_build_join_url(
    place_id: i64,
    instance_id: *const c_char,
    instance_id_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    let slice = if instance_id.is_null() || instance_id_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(instance_id as *const u8, instance_id_len)
    };
    let url = crate::discord_rpc::build_join_url_bytes(place_id, slice);
    let bytes = url.as_bytes();
    *out_len = bytes.len();
    if bytes.is_empty() {
        return 0;
    }
    if out_buf.is_null() || out_cap < bytes.len() {
        return if out_buf.is_null() { 0 } else { -2 };
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    0
}

// ============================================================================
// 50. Roblox Browser Service & WebView Bridge Helpers
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_has_control_byte(
    data: *const u8,
    len: usize,
) -> bool {
    if data.is_null() || len == 0 {
        return false;
    }
    let slice = std::slice::from_raw_parts(data, len);
    for &b in slice {
        if b <= 0x1f || b == 0x7f {
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_has_embedded_nul(
    data: *const u8,
    len: usize,
) -> bool {
    if data.is_null() || len == 0 {
        return false;
    }
    let slice = std::slice::from_raw_parts(data, len);
    slice.contains(&0)
}

fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
    if text.len() < prefix.len() {
        return false;
    }
    for (a, b) in text[..prefix.len()].iter().zip(prefix.iter()) {
        if a.to_ascii_lowercase() != b.to_ascii_lowercase() {
            return false;
        }
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_webview_is_login_challenge_url(
    url: *const c_char,
    len: usize,
) -> bool {
    if url.is_null() || len == 0 {
        return false;
    }
    let slice = std::slice::from_raw_parts(url as *const u8, len);
    let mut normalized = slice;

    if starts_with_ignore_case(normalized, b"https://www.roblox.com/") {
        normalized = &normalized[23..];
    } else if starts_with_ignore_case(normalized, b"https://roblox.com/") {
        normalized = &normalized[19..];
    } else if starts_with_ignore_case(normalized, b"https://apis.roblox.com/") {
        normalized = &normalized[24..];
    } else if starts_with_ignore_case(normalized, b"https://arkose.roblox.com/") {
        normalized = &normalized[26..];
    } else if starts_with_ignore_case(normalized, b"www:") {
        normalized = &normalized[4..];
    } else if !normalized.is_empty() && normalized[0] == b'/' {
        normalized = &normalized[1..];
    }

    const PREFIXES: &[&[u8]] = &[
        b"captcha",
        b"view-generic-challenge",
        b"generic-challenge",
        b"login/challenge",
        b"challenge",
        b"arkose",
        b"login/twostepverification",
        b"twostepverification",
        b"login/two-step-verification",
        b"two-step-verification",
        b"reauthenticate",
    ];

    for &prefix in PREFIXES {
        if starts_with_ignore_case(normalized, prefix) {
            if normalized.len() == prefix.len()
                || normalized[prefix.len()] == b'/'
                || normalized[prefix.len()] == b'?'
                || normalized[prefix.len()] == b'#'
            {
                return true;
            }
        }
    }
    false
}

// ============================================================================
// 51. Game Session Coordinator Helpers
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_game_session_state_name(state: i32) -> *const c_char {
    match state {
        0 => b"Created\0".as_ptr() as *const c_char,
        1 => b"PrincipalReady\0".as_ptr() as *const c_char,
        2 => b"JoinRequestQueued\0".as_ptr() as *const c_char,
        3 => b"PreparingSurface\0".as_ptr() as *const c_char,
        4 => b"SurfaceCreated\0".as_ptr() as *const c_char,
        5 => b"SurfaceAvailable\0".as_ptr() as *const c_char,
        6 => b"Starting\0".as_ptr() as *const c_char,
        7 => b"Running\0".as_ptr() as *const c_char,
        8 => b"UpdatingSurface\0".as_ptr() as *const c_char,
        9 => b"Pausing\0".as_ptr() as *const c_char,
        10 => b"Paused\0".as_ptr() as *const c_char,
        11 => b"Resuming\0".as_ptr() as *const c_char,
        12 => b"Leaving\0".as_ptr() as *const c_char,
        13 => b"ReturnedToLuaApp\0".as_ptr() as *const c_char,
        14 => b"Failure\0".as_ptr() as *const c_char,
        15 => b"Stopping\0".as_ptr() as *const c_char,
        16 => b"Stopped\0".as_ptr() as *const c_char,
        _ => b"Unknown\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_present_backend_name(backend: i32) -> *const c_char {
    match backend {
        1 => b"Vulkan\0".as_ptr() as *const c_char,
        2 => b"OpenGlEs\0".as_ptr() as *const c_char,
        _ => b"Unknown\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_session_principal_kind_name(kind: i32) -> *const c_char {
    match kind {
        0 => b"LocalGuest\0".as_ptr() as *const c_char,
        1 => b"Authenticated\0".as_ptr() as *const c_char,
        _ => b"Unknown\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_session_valid_principal(
    generation: u64,
    base_url_len: usize,
    kind: i32,
    principal_id_len: usize,
) -> bool {
    if generation == 0 || base_url_len == 0 {
        return false;
    }
    if kind == 1 {
        principal_id_len > 0
    } else if kind == 0 {
        principal_id_len == 0
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_session_valid_request(
    request_id: u64,
    place_id: i64,
    launch_params_len: usize,
) -> bool {
    request_id != 0 && place_id >= 0 && launch_params_len > 0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_session_valid_surface(
    generation: u64,
    native_window: usize,
    width: u32,
    height: u32,
) -> bool {
    generation != 0 && native_window != 0 && width != 0 && height != 0
}

// ============================================================================
// 52. WebRTC & FMOD Audio Bridge Helpers
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_fmod_is_valid_channel_count(channels: i32) -> bool {
    channels == 1 || channels == 2 || channels == 6 || channels == 8
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webrtc_calc_frame_bytes(
    sample_rate_hz: u32,
    duration_ms: u32,
    channels: u32,
) -> usize {
    ((sample_rate_hz as u64 * duration_ms as u64 / 1000) as usize)
        .saturating_mul(channels as usize)
        .saturating_mul(2)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_audio_calc_pcm_s16le_peak(
    data: *const u8,
    size_bytes: usize,
) -> i32 {
    if data.is_null() || size_bytes < 2 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(data, size_bytes);
    let mut peak = 0i32;
    let mut i = 0;
    while i + 1 < size_bytes {
        let b0 = slice[i] as i32;
        let b1 = slice[i + 1] as i32;
        let mut word = b0 | (b1 << 8);
        if word >= 32768 {
            word -= 65536;
        }
        let abs_val = word.abs();
        if abs_val > peak {
            peak = abs_val;
        }
        i += 2;
    }
    peak
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_spec_equals(
    sr1: u32,
    ch1: u32,
    fmt1: i32,
    sr2: u32,
    ch2: u32,
    fmt2: i32,
) -> bool {
    sr1 == sr2 && ch1 == ch2 && fmt1 == fmt2
}

// ============================================================================
// 53. Update Coordinator & Download Preflight Helpers
// ============================================================================

pub(crate) fn host_matches_bytes(host_s: &[u8], allowed_s: &[u8]) -> bool {
    if host_s.is_empty() || allowed_s.is_empty() {
        return false;
    }
    if host_s.len() == allowed_s.len() {
        return host_s
            .iter()
            .zip(allowed_s.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase());
    }
    if host_s.len() > allowed_s.len() {
        let prefix_len = host_s.len() - allowed_s.len();
        if host_s[prefix_len - 1] != b'.' {
            return false;
        }
        return host_s[prefix_len..]
            .iter()
            .zip(allowed_s.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase());
    }
    false
}

pub(crate) fn is_redirect_status_code(status_code: i64) -> bool {
    matches!(status_code, 301 | 302 | 303 | 307 | 308)
}

pub(crate) fn is_retryable_status_code(status_code: i64) -> bool {
    status_code == 408 || status_code == 425 || status_code == 429 || status_code >= 500
}

pub(crate) fn is_retryable_curl_code_val(code: i32) -> bool {
    matches!(code, 7 | 6 | 5 | 28 | 18 | 56 | 55 | 52 | 35)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_update_host_matches(
    host: *const c_char,
    host_len: usize,
    allowed: *const c_char,
    allowed_len: usize,
) -> bool {
    if host.is_null() || allowed.is_null() || host_len == 0 || allowed_len == 0 {
        return false;
    }
    let host_s = std::slice::from_raw_parts(host as *const u8, host_len);
    let allowed_s = std::slice::from_raw_parts(allowed as *const u8, allowed_len);
    host_matches_bytes(host_s, allowed_s)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_is_redirect_status(status_code: i64) -> bool {
    is_redirect_status_code(status_code)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_is_retryable_status(status_code: i64) -> bool {
    is_retryable_status_code(status_code)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_is_retryable_curl_code(code: i32) -> bool {
    is_retryable_curl_code_val(code)
}

pub(crate) fn evaluate_update_plan(
    has_latest: bool,
    latest_code: u64,
    runnable: bool,
    runnable_code: u64,
    preferred_code: u64,
) -> (bool, bool) {
    let take_latest = has_latest && (!runnable || latest_code > runnable_code);
    let need_preferred = !runnable || preferred_code > runnable_code;
    let take_preferred = need_preferred && (!take_latest || latest_code != preferred_code);
    (take_latest, take_preferred)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_update_plan_evaluate(
    has_latest: bool,
    latest_code: u64,
    runnable: bool,
    runnable_code: u64,
    preferred_code: u64,
    out_take_latest: *mut bool,
    out_take_preferred: *mut bool,
) -> i32 {
    if out_take_latest.is_null() || out_take_preferred.is_null() {
        return -1;
    }
    let (take_latest, take_preferred) =
        evaluate_update_plan(has_latest, latest_code, runnable, runnable_code, preferred_code);
    *out_take_latest = take_latest;
    *out_take_preferred = take_preferred;
    0
}

// ============================================================================
// 54. Memory Watchdog & Statm Helpers
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_statm_pages_to_bytes(pages: u64, page_size: u64) -> u64 {
    pages.saturating_mul(page_size)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_parse_proc_statm(
    statm_content: *const c_char,
    len: usize,
    out_resident_pages: *mut u64,
) -> i32 {
    if statm_content.is_null() || out_resident_pages.is_null() || len == 0 {
        return -1;
    }
    let slice = std::slice::from_raw_parts(statm_content as *const u8, len);
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut parts = s.split_whitespace();
    let _size = match parts.next() {
        Some(v) => v,
        None => return -1,
    };
    let resident_str = match parts.next() {
        Some(v) => v,
        None => return -1,
    };
    match resident_str.parse::<u64>() {
        Ok(v) => {
            *out_resident_pages = v;
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_memory_limit_exceeded(
    resident_bytes: u64,
    swap_bytes: u64,
    limit_bytes: u64,
) -> bool {
    limit_bytes > 0 && resident_bytes.saturating_add(swap_bytes) >= limit_bytes
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_format_memory_limit_message(
    used_bytes: u64,
    limit_bytes: u64,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    const MB: u64 = 1024 * 1024;
    let used_mb = used_bytes / MB;
    let limit_mb = limit_bytes / MB;
    let msg = format!(
        "[memory] limit exceeded: RSS+swap={} MiB, limit={} MiB; terminating Mocktail with exit 137\n",
        used_mb, limit_mb
    );
    let bytes = msg.as_bytes();
    *out_len = bytes.len();
    if out_buf.is_null() || cap < bytes.len() {
        return if out_buf.is_null() { 0 } else { -2 };
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    0
}

// ============================================================================
// 55. Payload Update Preflight & Diagnostic Relay
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_trim_to_utf8_boundary(
    data: *const u8,
    len: usize,
    max_bytes: usize,
) -> usize {
    if data.is_null() || len == 0 || max_bytes == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(data, len);
    payload_update_preflight::trim_to_utf8_boundary_bytes(slice, max_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_parse_updater_stderr_line(
    line: *const c_char,
    len: usize,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
    out_is_failure: *mut bool,
) -> i32 {
    if line.is_null() || out_len.is_null() || out_is_failure.is_null() {
        return -1;
    }
    *out_len = 0;
    *out_is_failure = false;
    if len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(line as *const u8, len);
    if let Some(detail) = payload_update_preflight::parse_updater_stderr_line_bytes(slice) {
        *out_is_failure = true;
        *out_len = detail.len();
        if !out_buf.is_null() && cap >= detail.len() {
            std::ptr::copy_nonoverlapping(detail.as_ptr(), out_buf, detail.len());
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_is_env_entry(
    entry: *const c_char,
    entry_len: usize,
    name: *const c_char,
    name_len: usize,
) -> bool {
    if entry.is_null() || name.is_null() || entry_len <= name_len {
        return false;
    }
    let entry_s = std::slice::from_raw_parts(entry as *const u8, entry_len);
    let name_s = std::slice::from_raw_parts(name as *const u8, name_len);
    unix_ipc::is_env_entry(entry_s, name_s)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_format_preflight_failure(
    status_or_signal: i32,
    is_signal: bool,
    last_line: *const c_char,
    last_len: usize,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    let msg = if !last_line.is_null() && last_len > 0 {
        let s = std::slice::from_raw_parts(last_line as *const u8, last_len);
        let trimmed = std::str::from_utf8(s).unwrap_or("").trim();
        trimmed.to_string()
    } else if is_signal {
        format!("Updater process killed by signal {}", status_or_signal)
    } else {
        format!("Updater process exited with status {}", status_or_signal)
    };
    let bytes = msg.as_bytes();
    let write_len = mocktail_rust_trim_to_utf8_boundary(bytes.as_ptr(), bytes.len(), 400);
    *out_len = write_len;
    if out_buf.is_null() || cap < write_len {
        return if out_buf.is_null() { 0 } else { -2 };
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, write_len);
    0
}

// ============================================================================
// 56. Desktop App Policy & Layout Normalization
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_normalize_desktop_layout(
    policy_json: *const c_char,
    p_len: usize,
    forced_theme: *const c_char,
    t_len: usize,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if policy_json.is_null() || out_len.is_null() || p_len == 0 {
        return -1;
    }
    let slice = std::slice::from_raw_parts(policy_json as *const u8, p_len);
    let mut map: serde_json::Map<String, serde_json::Value> = match serde_json::from_slice(slice) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => return -1,
    };

    map.insert("PlatformGroup".to_string(), serde_json::Value::String("Desktop".to_string()));
    map.insert("UseGridHomePage".to_string(), serde_json::Value::Bool(true));
    map.insert("UseGridPageLayout".to_string(), serde_json::Value::Bool(true));
    map.insert("SystemBarPlacement".to_string(), serde_json::Value::String("Left".to_string()));
    map.insert("ShouldSystemBarUsuallyBePresent".to_string(), serde_json::Value::Bool(true));
    map.insert(
        "DevicePreferencesPersistentPresenceVariant".to_string(),
        serde_json::Value::String("windows".to_string()),
    );
    map.insert("ShowUncheckedBadge".to_string(), serde_json::Value::Bool(false));

    let theme = if !forced_theme.is_null() && t_len > 0 {
        let t_slice = std::slice::from_raw_parts(forced_theme as *const u8, t_len);
        std::str::from_utf8(t_slice).unwrap_or("").to_string()
    } else {
        String::new()
    };
    map.insert("ForceTheme".to_string(), serde_json::Value::String(theme));

    let serialized = match serde_json::to_string(&serde_json::Value::Object(map)) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let bytes = serialized.as_bytes();
    *out_len = bytes.len();
    if out_buf.is_null() || cap < bytes.len() {
        return if out_buf.is_null() { 0 } else { -2 };
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_merge_desktop_app_policy_settings(
    policy_json: *const c_char,
    p_len: usize,
    base_json: *const c_char,
    b_len: usize,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if policy_json.is_null() || out_len.is_null() || p_len == 0 {
        return -1;
    }
    let p_slice = std::slice::from_raw_parts(policy_json as *const u8, p_len);
    let p_str = match std::str::from_utf8(p_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match serde_json::from_str::<serde_json::Value>(p_str) {
        Ok(serde_json::Value::Object(_)) => {}
        _ => return -1,
    };

    let mut overrides: serde_json::Map<String, serde_json::Value> = if !base_json.is_null() && b_len > 0 {
        let b_slice = std::slice::from_raw_parts(base_json as *const u8, b_len);
        match serde_json::from_slice(b_slice) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => return -2,
        }
    } else {
        serde_json::Map::new()
    };

    let override_key = "FStringAppConfigurationOverrideAppPolicy";
    if let Some(existing) = overrides.get(override_key) {
        if let Some(existing_str) = existing.as_str() {
            if existing_str != p_str {
                return -3; // Conflict
            }
        } else {
            return -3; // Not a string
        }
    }

    overrides.insert(override_key.to_string(), serde_json::Value::String(p_str.to_string()));
    overrides.entry("FFlagLuaAppChartsAppPage".to_string()).or_insert_with(|| serde_json::Value::String("False".to_string()));

    let serialized = match serde_json::to_string(&serde_json::Value::Object(overrides)) {
        Ok(s) => s,
        Err(_) => return -4,
    };
    let bytes = serialized.as_bytes();
    *out_len = bytes.len();
    if out_buf.is_null() || cap < bytes.len() {
        return if out_buf.is_null() { 0 } else { -5 };
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    0
}

// ============================================================================
// 57. Browser Tracker Service & Cookie Helpers
// ============================================================================

pub(crate) fn is_valid_browser_tracker_id_bytes(slice: &[u8]) -> bool {
    if slice.is_empty() || slice.len() > 20 || slice[0] == b'0' {
        return false;
    }
    std::str::from_utf8(slice)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n != 0)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_tracker_is_valid_id(
    value: *const c_char,
    len: usize,
) -> bool {
    if value.is_null() || len == 0 || len > 20 {
        return false;
    }
    let slice = std::slice::from_raw_parts(value as *const u8, len);
    is_valid_browser_tracker_id_bytes(slice)
}

pub(crate) fn extract_cookie_value_str<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    let name_trimmed = name.trim();
    if name_trimmed.is_empty() || cookies.is_empty() {
        return None;
    }
    for part in cookies.split(&[';', '\r', '\n'][..]) {
        let part_trimmed = part.trim();
        if let Some((k, v)) = part_trimmed.split_once('=') {
            if k.trim() == name_trimmed {
                return Some(v.trim());
            }
        }
    }
    None
}

pub(crate) fn extract_tracker_from_headers_str<'a>(headers: &'a str) -> Option<&'a str> {
    for line in headers.lines() {
        let trimmed = line.trim();
        if trimmed.len() >= 11 && trimmed[..11].eq_ignore_ascii_case("set-cookie:") {
            if let Some(value) = extract_cookie_value_str(&trimmed[11..], "RBXEventTrackerV2") {
                return Some(value);
            }
        }
    }
    None
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_tracker_extract_cookie(
    cookies: *const c_char,
    c_len: usize,
    name: *const c_char,
    n_len: usize,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if cookies.is_null() || name.is_null() || out_len.is_null() || n_len == 0 {
        return -1;
    }
    *out_len = 0;
    if c_len == 0 {
        return 1; // not found
    }
    let c_slice = std::slice::from_raw_parts(cookies as *const u8, c_len);
    let n_slice = std::slice::from_raw_parts(name as *const u8, n_len);
    let cookies_str = match std::str::from_utf8(c_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let name_str = match std::str::from_utf8(n_slice) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    if let Some(val_trimmed) = extract_cookie_value_str(cookies_str, name_str) {
        let v_bytes = val_trimmed.as_bytes();
        *out_len = v_bytes.len();
        if out_buf.is_null() || cap < v_bytes.len() {
            return if out_buf.is_null() { 0 } else { -2 };
        }
        std::ptr::copy_nonoverlapping(v_bytes.as_ptr(), out_buf, v_bytes.len());
        return 0;
    }
    1 // not found
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_tracker_has_cookie(
    cookies: *const c_char,
    c_len: usize,
    name: *const c_char,
    n_len: usize,
) -> bool {
    let mut dummy_len = 0usize;
    mocktail_rust_browser_tracker_extract_cookie(
        cookies,
        c_len,
        name,
        n_len,
        std::ptr::null_mut(),
        0,
        &mut dummy_len,
    ) == 0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_tracker_from_headers(
    headers: *const c_char,
    h_len: usize,
    out_buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if headers.is_null() || out_len.is_null() || h_len == 0 {
        return -1;
    }
    *out_len = 0;
    let h_slice = std::slice::from_raw_parts(headers as *const u8, h_len);
    let headers_str = match std::str::from_utf8(h_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    if let Some(val_trimmed) = extract_tracker_from_headers_str(headers_str) {
        let v_bytes = val_trimmed.as_bytes();
        *out_len = v_bytes.len();
        if out_buf.is_null() || cap < v_bytes.len() {
            return if out_buf.is_null() { 0 } else { -2 };
        }
        std::ptr::copy_nonoverlapping(v_bytes.as_ptr(), out_buf, v_bytes.len());
        return 0;
    }
    1 // not found
}

// ============================================================================
// 58. Auth Service & Credential Processing
// ============================================================================

#[inline]
fn is_auth_cookie_delimiter(b: u8) -> bool {
    b == b';' || b == b'\r' || b == b'\n' || b == b'\t'
}

#[inline]
fn trim_ascii_whitespace(slice: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < slice.len() && slice[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = slice.len();
    while end > start && slice[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &slice[start..end]
}

pub(crate) fn extract_auth_cookie_bytes(slice: &[u8]) -> (bool, &[u8]) {
    if slice.is_empty() {
        return (false, &[]);
    }
    if slice.starts_with(b"_|") {
        let mut end = 0;
        while end < slice.len() && !is_auth_cookie_delimiter(slice[end]) {
            end += 1;
        }
        return (true, trim_ascii_whitespace(&slice[..end]));
    }

    let mut segment_begin = 0;
    while segment_begin < slice.len() {
        while segment_begin < slice.len()
            && (is_auth_cookie_delimiter(slice[segment_begin])
                || slice[segment_begin].is_ascii_whitespace())
        {
            segment_begin += 1;
        }
        let mut segment_end = segment_begin;
        while segment_end < slice.len() && !is_auth_cookie_delimiter(slice[segment_end]) {
            segment_end += 1;
        }
        let segment = trim_ascii_whitespace(&slice[segment_begin..segment_end]);
        let equals_pos = segment.iter().position(|&b| b == b'=');
        let name = match equals_pos {
            Some(pos) => trim_ascii_whitespace(&segment[..pos]),
            None => trim_ascii_whitespace(segment),
        };
        if name == b".ROBLOSECURITY" {
            let val = match equals_pos {
                Some(pos) => trim_ascii_whitespace(&segment[pos + 1..]),
                None => &[][..],
            };
            return (true, val);
        }
        segment_begin = segment_end + if segment_end < slice.len() { 1 } else { 0 };
    }
    (false, &[])
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_auth_extract_cookie(
    header: *const c_char,
    header_len: usize,
    out_present: *mut bool,
    out_buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    if out_present.is_null() {
        return -1;
    }
    *out_present = false;
    if !out_len.is_null() {
        *out_len = 0;
    }
    if header.is_null() || header_len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(header as *const u8, header_len);
    let (present, val) = extract_auth_cookie_bytes(slice);
    *out_present = present;
    if present && !out_buf.is_null() && !out_len.is_null() {
        if cap <= val.len() {
            return -2;
        }
        if !val.is_empty() {
            std::ptr::copy_nonoverlapping(val.as_ptr() as *const c_char, out_buf, val.len());
        }
        *out_buf.add(val.len()) = 0;
        *out_len = val.len();
    }
    0
}

#[inline]
pub(crate) fn is_safe_auth_cookie_bytes(slice: &[u8]) -> bool {
    !slice.is_empty() && slice.iter().all(|&b| b > 0x20 && b < 0x7f && b != b';')
}

#[no_mangle]
pub extern "C" fn mocktail_rust_auth_is_safe_cookie_value(
    value: *const c_char,
    len: usize,
) -> bool {
    if value.is_null() || len == 0 {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts(value as *const u8, len) };
    is_safe_auth_cookie_bytes(slice)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_auth_redact_rejected(
    header: *const c_char,
    header_len: usize,
    rejected_val: *const c_char,
    rejected_len: usize,
    out_buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    if header.is_null() || rejected_val.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    *out_len = 0;
    if rejected_len == 0 || cap <= header_len {
        return -1;
    }
    let mut effective_present = false;
    let mut effective_buf = vec![0 as c_char; header_len + 1];
    let mut effective_len = 0usize;
    let rc = mocktail_rust_auth_extract_cookie(
        header, header_len, &mut effective_present,
        effective_buf.as_mut_ptr(), effective_buf.len(), &mut effective_len,
    );
    if rc != 0 || !effective_present {
        return -1;
    }
    let rejected_slice = std::slice::from_raw_parts(rejected_val as *const u8, rejected_len);
    let effective_slice = std::slice::from_raw_parts(effective_buf.as_ptr() as *const u8, effective_len);
    if effective_slice != rejected_slice {
        return -1;
    }

    std::ptr::copy_nonoverlapping(header, out_buf, header_len);
    *out_buf.add(header_len) = 0;
    let out_slice = std::slice::from_raw_parts_mut(out_buf as *mut u8, header_len);

    let mut segment_begin = 0;
    let mut redacted = false;

    if out_slice.starts_with(b"_|") {
        let mut segment_end = 0;
        while segment_end < out_slice.len() && !is_auth_cookie_delimiter(out_slice[segment_end]) {
            segment_end += 1;
        }
        for b in &mut out_slice[0..segment_end] {
            *b = b' ';
        }
        segment_begin = segment_end + if segment_end < out_slice.len() { 1 } else { 0 };
        redacted = true;
    }

    while segment_begin < out_slice.len() {
        let mut segment_end = segment_begin;
        while segment_end < out_slice.len() && !is_auth_cookie_delimiter(out_slice[segment_end]) {
            segment_end += 1;
        }
        let seg = trim_ascii_whitespace(&out_slice[segment_begin..segment_end]);
        let equals_pos = seg.iter().position(|&b| b == b'=');
        let name = match equals_pos {
            Some(pos) => trim_ascii_whitespace(&seg[..pos]),
            None => trim_ascii_whitespace(seg),
        };
        if name == b".ROBLOSECURITY" {
            for b in &mut out_slice[segment_begin..segment_end] {
                *b = b' ';
            }
            redacted = true;
        }
        segment_begin = segment_end + if segment_end < out_slice.len() { 1 } else { 0 };
    }

    if !redacted {
        return -1;
    }
    *out_len = header_len;
    0
}

pub(crate) fn parse_auth_identity_slice(slice: &[u8]) -> Result<(i64, String, String), c_int> {
    if slice.is_empty() {
        return Err(-1);
    }
    let val: serde_json::Value = serde_json::from_slice(slice).map_err(|_| -2)?;
    let obj = val.as_object().ok_or(-3)?;
    let id_val = obj.get("id").ok_or(-4)?;
    let user_id = if let Some(n) = id_val.as_number() {
        if let Some(u) = n.as_u64() {
            if u == 0 || u > i64::MAX as u64 {
                return Err(-5);
            }
            u as i64
        } else if let Some(s) = n.as_i64() {
            if s <= 0 {
                return Err(-6);
            }
            s
        } else {
            return Err(-7);
        }
    } else {
        return Err(-8);
    };
    let name = match obj.get("name").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Err(-9),
    };
    let display_name = match obj.get("displayName").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        _ => return Err(-10),
    };
    Ok((user_id, name, display_name))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_auth_parse_identity(
    body: *const c_char,
    body_len: usize,
    out_user_id: *mut i64,
    out_name_buf: *mut c_char,
    name_cap: usize,
    out_display_name_buf: *mut c_char,
    display_cap: usize,
) -> c_int {
    if body.is_null() || body_len == 0 || out_user_id.is_null() || out_name_buf.is_null() || out_display_name_buf.is_null() {
        return -1;
    }
    *out_user_id = -1;
    let slice = std::slice::from_raw_parts(body as *const u8, body_len);
    let (user_id, name, display_name) = match parse_auth_identity_slice(slice) {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    if name.len() >= name_cap || display_name.len() >= display_cap {
        return -11;
    }
    std::ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, out_name_buf, name.len());
    *out_name_buf.add(name.len()) = 0;

    std::ptr::copy_nonoverlapping(display_name.as_ptr() as *const c_char, out_display_name_buf, display_name.len());
    *out_display_name_buf.add(display_name.len()) = 0;

    *out_user_id = user_id;
    0
}

// ============================================================================
// 59. Cookie Redaction Ranges
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MocktailRustCookieRedactionRange {
    pub begin: usize,
    pub end: usize,
    pub marker: usize,
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_auth_find_redaction_ranges(
    orig: *const c_char,
    orig_len: usize,
    red: *const c_char,
    red_len: usize,
    out_ranges: *mut MocktailRustCookieRedactionRange,
    max_ranges: usize,
    out_count: *mut usize,
) -> c_int {
    if orig.is_null() || red.is_null() || out_ranges.is_null() || out_count.is_null() {
        return -1;
    }
    *out_count = 0;
    if orig_len != red_len {
        return -1;
    }
    let orig_slice = std::slice::from_raw_parts(orig as *const u8, orig_len);
    let red_slice = std::slice::from_raw_parts(red as *const u8, red_len);

    let mut segment_begin = 0;
    let mut count = 0;
    while segment_begin < orig_len {
        let mut segment_end = segment_begin;
        while segment_end < orig_len && !is_auth_cookie_delimiter(orig_slice[segment_end]) {
            segment_end += 1;
        }
        if orig_slice[segment_begin..segment_end] != red_slice[segment_begin..segment_end] {
            let mut marker = segment_begin;
            while marker < segment_end && orig_slice[marker] == red_slice[marker] {
                marker += 1;
            }
            if marker == segment_end {
                *out_count = 0;
                return -2;
            }
            if count < max_ranges {
                *out_ranges.add(count) = MocktailRustCookieRedactionRange {
                    begin: segment_begin,
                    end: segment_end,
                    marker,
                };
                count += 1;
            }
        }
        segment_begin = segment_end + if segment_end < orig_len { 1 } else { 0 };
    }
    *out_count = count;
    0
}

// ============================================================================
// 60. Capability Requirements & Input Flags Evaluator
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustCapabilityInputSymbolsPresence {
    pub has_gamepad_axis_event: bool,
    pub has_gamepad_button_event: bool,
    pub has_gamepad_connect_event_with_gamepad_type: bool,
    pub has_gamepad_disconnect_event: bool,
    pub has_get_main_window_is_mouse_locked_center: bool,
    pub has_pass_accelerometer_change: bool,
    pub has_pass_gravity_change: bool,
    pub has_pass_gyroscope_change: bool,
    pub has_pass_input: bool,
    pub has_pass_long_press_gesture: bool,
    pub has_pass_mouse_button: bool,
    pub has_pass_mouse_move: bool,
    pub has_pass_mouse_pan: bool,
    pub has_pass_mouse_pinch: bool,
    pub has_pass_mouse_wheel: bool,
    pub has_pass_key_event: bool,
    pub has_sync_textbox_text_and_cursor_position2: bool,
    pub has_get_text_box_info: bool,
    pub has_pass_text: bool,
    pub has_return_pressed_from_on_screen_keyboard: bool,
    pub has_release_focus: bool,
    pub has_pass_pan_gesture_multitouch: bool,
    pub has_pass_pan_gesture_with_velocity: bool,
    pub has_pass_pinch_gesture: bool,
    pub has_pass_rotate_gesture: bool,
    pub has_pass_swipe_gesture: bool,
    pub has_pass_tap_gesture: bool,
    pub has_set_accelerometer_enabled: bool,
    pub has_set_gamepad_supported_key_with_gamepad_type: bool,
    pub has_set_gamepad_supported_motion_with_gamepad_type: bool,
    pub has_set_gyroscope_enabled: bool,
    pub has_set_tv_remote_supported_key: bool,
    pub has_tv_remote_button_event: bool,
    pub has_tv_remote_connect_event: bool,
    pub has_tv_remote_disconnect_event: bool,
    pub has_update_screen_orientation: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustCapabilityInputFlags {
    pub gamepad_api: i32,
    pub has_gamepad_events: bool,
    pub has_mouse: bool,
    pub has_touch: bool,
    pub has_hardware_keyboard: bool,
    pub has_text_input: bool,
    pub has_gestures: bool,
    pub has_sensors: bool,
    pub has_tv_remote: bool,
    pub has_screen_orientation: bool,
    pub clear_partial_gamepad: bool,
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_capability_eval_input_flags(
    in_presence: *const MocktailRustCapabilityInputSymbolsPresence,
    out_flags: *mut MocktailRustCapabilityInputFlags,
) {
    if in_presence.is_null() || out_flags.is_null() {
        return;
    }
    let p = &*in_presence;
    let has_modern_gamepad_api = p.has_gamepad_connect_event_with_gamepad_type
        && p.has_set_gamepad_supported_key_with_gamepad_type
        && p.has_set_gamepad_supported_motion_with_gamepad_type;

    let mut flags = MocktailRustCapabilityInputFlags::default();

    if has_modern_gamepad_api {
        flags.gamepad_api = 1; // kWithGamepadType
        flags.clear_partial_gamepad = false;
    } else {
        flags.gamepad_api = 0; // kUnsupported
        flags.clear_partial_gamepad = true;
    }

    flags.has_gamepad_events = has_modern_gamepad_api
        && p.has_gamepad_axis_event
        && p.has_gamepad_button_event
        && p.has_gamepad_disconnect_event;

    flags.has_mouse = p.has_get_main_window_is_mouse_locked_center
        && p.has_pass_mouse_button
        && p.has_pass_mouse_move
        && p.has_pass_mouse_pan
        && p.has_pass_mouse_pinch
        && p.has_pass_mouse_wheel;

    flags.has_touch = p.has_pass_input;
    flags.has_hardware_keyboard = p.has_pass_key_event;
    flags.has_text_input = p.has_sync_textbox_text_and_cursor_position2
        && p.has_get_text_box_info
        && p.has_pass_text
        && p.has_return_pressed_from_on_screen_keyboard
        && p.has_release_focus;

    flags.has_gestures = p.has_pass_long_press_gesture
        && p.has_pass_pan_gesture_multitouch
        && p.has_pass_pan_gesture_with_velocity
        && p.has_pass_pinch_gesture
        && p.has_pass_rotate_gesture
        && p.has_pass_swipe_gesture
        && p.has_pass_tap_gesture;

    flags.has_sensors = p.has_pass_accelerometer_change
        && p.has_pass_gravity_change
        && p.has_pass_gyroscope_change
        && p.has_set_accelerometer_enabled
        && p.has_set_gyroscope_enabled;

    flags.has_tv_remote = p.has_set_tv_remote_supported_key
        && p.has_tv_remote_button_event
        && p.has_tv_remote_connect_event
        && p.has_tv_remote_disconnect_event;

    flags.has_screen_orientation = p.has_update_screen_orientation;

    *out_flags = flags;
}

// ============================================================================
// 61. Session Log Environment, Hardware & Path Normalization
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_session_log_display_path(
    path: *const c_char,
    path_len: usize,
    home: *const c_char,
    home_len: usize,
    out_buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_buf.is_null() || cap == 0 {
        return -1;
    }
    if !out_len.is_null() {
        *out_len = 0;
    }
    if path.is_null() || path_len == 0 {
        let default_val = b"unknown";
        if default_val.len() >= cap {
            return -1;
        }
        std::ptr::copy_nonoverlapping(default_val.as_ptr(), out_buf as *mut u8, default_val.len());
        *out_buf.add(default_val.len()) = 0;
        if !out_len.is_null() {
            *out_len = default_val.len();
        }
        return 0;
    }

    let path_slice = std::slice::from_raw_parts(path as *const u8, path_len);
    let path_str = match std::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let p = std::path::Path::new(path_str);
    let result = if !home.is_null() && home_len > 0 {
        let home_slice = std::slice::from_raw_parts(home as *const u8, home_len);
        if let Ok(home_str) = std::str::from_utf8(home_slice) {
            let h = std::path::Path::new(home_str);
            if let Ok(rel) = p.strip_prefix(h) {
                if rel.as_os_str().is_empty() {
                    "~/.".to_string()
                } else {
                    format!("~/{}", rel.display())
                }
            } else {
                path_str.to_string()
            }
        } else {
            path_str.to_string()
        }
    } else {
        path_str.to_string()
    };

    let res_bytes = result.as_bytes();
    if res_bytes.len() >= cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(res_bytes.as_ptr(), out_buf as *mut u8, res_bytes.len());
    *out_buf.add(res_bytes.len()) = 0;
    if !out_len.is_null() {
        *out_len = res_bytes.len();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_session_log_package_kind(
    has_flatpak_id: bool,
    has_appimage: bool,
    has_appdir: bool,
    exec_path: *const c_char,
    exec_len: usize,
    out_buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_buf.is_null() || cap == 0 {
        return -1;
    }
    if !out_len.is_null() {
        *out_len = 0;
    }

    let kind: &str = if has_flatpak_id {
        "flatpak"
    } else if has_appimage {
        "appimage"
    } else if has_appdir {
        "portable"
    } else {
        let p = if !exec_path.is_null() && exec_len > 0 {
            std::str::from_utf8(std::slice::from_raw_parts(exec_path as *const u8, exec_len)).unwrap_or("")
        } else {
            ""
        };
        if p.starts_with("/usr/") || p.starts_with("/opt/") || p.starts_with("/app/") {
            "system-install"
        } else {
            "local-build"
        }
    };

    let k_bytes = kind.as_bytes();
    if k_bytes.len() >= cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(k_bytes.as_ptr(), out_buf as *mut u8, k_bytes.len());
    *out_buf.add(k_bytes.len()) = 0;
    if !out_len.is_null() {
        *out_len = k_bytes.len();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_session_log_display_server(
    has_wayland_display: bool,
    has_display: bool,
    out_buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_buf.is_null() || cap == 0 {
        return -1;
    }
    if !out_len.is_null() {
        *out_len = 0;
    }

    let server: &str = if has_wayland_display {
        "wayland"
    } else if has_display {
        "x11"
    } else {
        "none"
    };

    let s_bytes = server.as_bytes();
    if s_bytes.len() >= cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(s_bytes.as_ptr(), out_buf as *mut u8, s_bytes.len());
    *out_buf.add(s_bytes.len()) = 0;
    if !out_len.is_null() {
        *out_len = s_bytes.len();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_session_log_device_node_name(
    name: *const c_char,
    name_len: usize,
    prefix: *const c_char,
    prefix_len: usize,
) -> bool {
    if name.is_null() || prefix.is_null() || name_len <= prefix_len {
        return false;
    }
    let name_slice = std::slice::from_raw_parts(name as *const u8, name_len);
    let prefix_slice = std::slice::from_raw_parts(prefix as *const u8, prefix_len);
    if &name_slice[..prefix_len] != prefix_slice {
        return false;
    }
    name_slice[prefix_len..].iter().all(|&b| b.is_ascii_digit())
}

// ============================================================================
// 62. Candidate Approval Serialization & Evidence Fingerprinting
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustPayloadFingerprintInput {
    pub payload_id: *const c_char,
    pub payload_id_len: usize,
    pub metadata_sha256: *const c_char,
    pub metadata_sha256_len: usize,
    pub library_sha256: *const c_char,
    pub library_sha256_len: usize,
    pub base_apk_sha256: *const c_char,
    pub base_apk_sha256_len: usize,
    pub guest_abi: *const c_char,
    pub guest_abi_len: usize,
    pub split_apk_sha256: *const c_char,
    pub split_apk_sha256_len: usize,
    pub asset_tree_sha256: *const c_char,
    pub asset_tree_sha256_len: usize,
}

unsafe fn c_to_str<'a>(ptr: *const c_char, len: usize) -> Result<&'a str, ()> {
    if ptr.is_null() {
        if len == 0 {
            Ok("")
        } else {
            Err(())
        }
    } else {
        std::str::from_utf8(std::slice::from_raw_parts(ptr as *const u8, len)).map_err(|_| ())
    }
}

pub(crate) fn compute_approval_fingerprint_hex(
    payload_id: &str,
    metadata_sha256: &str,
    library_sha256: &str,
    base_apk_sha256: &str,
    guest_abi: &str,
    split_apk_sha256: &str,
    asset_tree_sha256: &str,
) -> Result<String, i32> {
    if payload_id.is_empty() {
        return Err(-2);
    }
    let mut evidence = String::with_capacity(512);
    evidence.push_str("payload_id=");
    evidence.push_str(payload_id);
    evidence.push('\n');
    evidence.push_str("metadata=");
    evidence.push_str(metadata_sha256);
    evidence.push('\n');
    evidence.push_str("libroblox=");
    evidence.push_str(library_sha256);
    evidence.push('\n');
    evidence.push_str("base_apk=");
    evidence.push_str(base_apk_sha256);
    evidence.push('\n');
    evidence.push_str(guest_abi);
    evidence.push_str("_split=");
    evidence.push_str(split_apk_sha256);
    evidence.push('\n');
    evidence.push_str("assets=");
    evidence.push_str(asset_tree_sha256);
    evidence.push('\n');
    Ok(sha256_bytes_hex(evidence.as_bytes()))
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_fingerprint(
    input: *const MocktailRustPayloadFingerprintInput,
    out_sha256: *mut c_char,
    cap: usize,
) -> i32 {
    if input.is_null() || out_sha256.is_null() || cap < 65 {
        return -1;
    }
    let inp = &*input;
    let payload_id = match c_to_str(inp.payload_id, inp.payload_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let metadata_sha256 = match c_to_str(inp.metadata_sha256, inp.metadata_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let library_sha256 = match c_to_str(inp.library_sha256, inp.library_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let base_apk_sha256 = match c_to_str(inp.base_apk_sha256, inp.base_apk_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let guest_abi = match c_to_str(inp.guest_abi, inp.guest_abi_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let split_apk_sha256 = match c_to_str(inp.split_apk_sha256, inp.split_apk_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let asset_tree_sha256 = match c_to_str(inp.asset_tree_sha256, inp.asset_tree_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let hex_str = match compute_approval_fingerprint_hex(
        payload_id,
        metadata_sha256,
        library_sha256,
        base_apk_sha256,
        guest_abi,
        split_apk_sha256,
        asset_tree_sha256,
    ) {
        Ok(h) => h,
        Err(rc) => return rc,
    };
    std::ptr::copy_nonoverlapping(hex_str.as_ptr(), out_sha256 as *mut u8, 64);
    *out_sha256.add(64) = 0;
    0
}

pub(crate) fn compute_approval_generation_hex(
    runtime_build_id: &str,
    fingerprint: &str,
    profile_sha256: &str,
    compatibility_sha256: &str,
    canary_1_sha256: &str,
    canary_2_sha256: &str,
) -> String {
    let mut evidence = String::with_capacity(512);
    evidence.push_str("runtime_build_id=");
    evidence.push_str(runtime_build_id);
    evidence.push('\n');
    evidence.push_str("payload=");
    evidence.push_str(fingerprint);
    evidence.push('\n');
    evidence.push_str("profile=");
    evidence.push_str(profile_sha256);
    evidence.push('\n');
    evidence.push_str("compatibility=");
    evidence.push_str(compatibility_sha256);
    evidence.push('\n');
    evidence.push_str("canary_1=");
    evidence.push_str(canary_1_sha256);
    evidence.push('\n');
    evidence.push_str("canary_2=");
    evidence.push_str(canary_2_sha256);
    evidence.push('\n');

    let digest = Sha256::digest(evidence.as_bytes());
    let mut hex_str = hex::encode(digest);
    hex_str.truncate(40);
    hex_str
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_generation(
    runtime_build_id: *const c_char,
    r_len: usize,
    fingerprint: *const c_char,
    f_len: usize,
    profile_sha256: *const c_char,
    p_len: usize,
    compatibility_sha256: *const c_char,
    c_len: usize,
    canary_1_sha256: *const c_char,
    c1_len: usize,
    canary_2_sha256: *const c_char,
    c2_len: usize,
    out_generation_40: *mut c_char,
    cap: usize,
) -> i32 {
    if out_generation_40.is_null() || cap < 41 {
        return -1;
    }
    let rbid = match c_to_str(runtime_build_id, r_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let fp = match c_to_str(fingerprint, f_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let prof = match c_to_str(profile_sha256, p_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let compat = match c_to_str(compatibility_sha256, c_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let c1 = match c_to_str(canary_1_sha256, c1_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let c2 = match c_to_str(canary_2_sha256, c2_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let hex_str = compute_approval_generation_hex(rbid, fp, prof, compat, c1, c2);
    std::ptr::copy_nonoverlapping(hex_str.as_ptr(), out_generation_40 as *mut u8, 40);
    *out_generation_40.add(40) = 0;
    0
}

unsafe fn write_err_msg(out_err: *mut c_char, err_cap: usize, msg: &str) {
    copy_error(out_err, err_cap, msg);
}

pub(crate) fn validate_approval_binding_bytes(
    profile_bytes: &[u8],
    compat_bytes: &[u8],
    payload_id: &str,
    elf_build_id: &str,
    library_sha256: &str,
    version_name: &str,
    version_code: u64,
) -> Result<(), &'static str> {
    if profile_bytes.is_empty() || compat_bytes.is_empty() {
        return Err("derived approval profile is not bound to exact payload bytes");
    }
    let profile: serde_json::Value = serde_json::from_slice(profile_bytes)
        .map_err(|_| "derived approval profile is not bound to exact payload bytes")?;
    let compatibility: serde_json::Value = serde_json::from_slice(compat_bytes)
        .map_err(|_| "derived approval profile is not bound to exact payload bytes")?;

    let expected_payload_path = format!("payloads/{}", payload_id);

    let profile_valid = profile.is_object()
        && profile.get("schema_version").and_then(|v| v.as_i64()) == Some(1)
        && profile.get("payload_id").and_then(|v| v.as_str()) == Some(payload_id)
        && profile.get("payload_path").and_then(|v| v.as_str()) == Some(&expected_payload_path)
        && profile.get("elf_build_id").and_then(|v| v.as_str()) == Some(elf_build_id)
        && profile.get("payload_sha256").and_then(|v| v.as_str()) == Some(library_sha256)
        && profile.get("profile").is_some_and(|v| v.is_object())
        && profile.get("profile").and_then(|p| p.get("elf_build_id")).and_then(|v| v.as_str()) == Some(elf_build_id)
        && profile.get("reference").is_some_and(|v| v.is_object())
        && compatibility.is_object()
        && compatibility.get("schema_version").and_then(|v| v.as_i64()) == Some(1)
        && compatibility.get("profiles").and_then(|v| v.as_array()).is_some_and(|arr| arr.len() == 1);

    if !profile_valid {
        return Err("derived approval profile is not bound to exact payload bytes");
    }

    let entry = &compatibility.get("profiles").unwrap().as_array().unwrap()[0];
    let entry_valid = entry.is_object()
        && entry.get("version_name").and_then(|v| v.as_str()) == Some(version_name)
        && entry.get("version_code").and_then(|v| v.as_u64()) == Some(version_code)
        && entry.get("elf_build_id").and_then(|v| v.as_str()) == Some(elf_build_id)
        && entry.get("status").and_then(|v| v.as_str()) == Some("experimental")
        && entry.get("default_allowed").and_then(|v| v.as_bool()) == Some(true)
        && entry.get("allow_legacy_binary_patches").map_or(true, |v| v.as_bool().unwrap_or(true)) == false
        && entry.get("allow_host_abi_bridges").and_then(|v| v.as_bool()) == Some(true)
        && entry.get("allow_host_constructor_replay").and_then(|v| v.as_bool()) == Some(true);

    if !entry_valid {
        return Err("candidate compatibility manifest is not exact probation metadata");
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_validate_binding(
    profile_json: *const c_char,
    p_len: usize,
    compatibility_json: *const c_char,
    c_len: usize,
    payload_id: *const c_char,
    payload_id_len: usize,
    elf_build_id: *const c_char,
    elf_len: usize,
    library_sha256: *const c_char,
    lib_len: usize,
    version_name: *const c_char,
    ver_name_len: usize,
    version_code: u64,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let payload_id_str = match c_to_str(payload_id, payload_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let elf_build_id_str = match c_to_str(elf_build_id, elf_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let lib_sha_str = match c_to_str(library_sha256, lib_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let ver_name_str = match c_to_str(version_name, ver_name_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let p_slice = if !profile_json.is_null() && p_len > 0 {
        std::slice::from_raw_parts(profile_json as *const u8, p_len)
    } else {
        &[]
    };
    let c_slice = if !compatibility_json.is_null() && c_len > 0 {
        std::slice::from_raw_parts(compatibility_json as *const u8, c_len)
    } else {
        &[]
    };

    if let Err(msg) = validate_approval_binding_bytes(
        p_slice,
        c_slice,
        payload_id_str,
        elf_build_id_str,
        lib_sha_str,
        ver_name_str,
        version_code,
    ) {
        write_err_msg(out_err, err_cap, msg);
        return 1;
    }
    0
}

// ============================================================================
// 63. Candidate Approval Attestation & Receipt Generator
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustCanaryAttestationInput {
    pub run: usize,
    pub run_id: *const c_char,
    pub run_id_len: usize,
    pub payload_id: *const c_char,
    pub payload_id_len: usize,
    pub payload_fingerprint: *const c_char,
    pub payload_fingerprint_len: usize,
    pub profile_sha256: *const c_char,
    pub profile_sha256_len: usize,
    pub compatibility_manifest_sha256: *const c_char,
    pub compatibility_manifest_sha256_len: usize,
    pub runtime_sha256: *const c_char,
    pub runtime_sha256_len: usize,
    pub runtime_build_id: *const c_char,
    pub runtime_build_id_len: usize,
    pub log_sha256: *const c_char,
    pub log_sha256_len: usize,
}

pub(crate) fn build_canary_attestation_json(
    run: usize,
    run_id: &str,
    payload_id: &str,
    payload_fingerprint: &str,
    profile_sha256: &str,
    compatibility_manifest_sha256: &str,
    runtime_sha256: &str,
    runtime_build_id: &str,
    log_sha256: &str,
) -> Option<String> {
    let mut map = std::collections::BTreeMap::new();
    map.insert("canary_tier", serde_json::Value::String("C".into()));
    map.insert(
        "compatibility_manifest_sha256",
        serde_json::Value::String(compatibility_manifest_sha256.into()),
    );
    map.insert(
        "payload_fingerprint",
        serde_json::Value::String(payload_fingerprint.into()),
    );
    map.insert("payload_id", serde_json::Value::String(payload_id.into()));
    map.insert("profile_sha256", serde_json::Value::String(profile_sha256.into()));
    map.insert("readiness_log_sha256", serde_json::Value::String(log_sha256.into()));
    map.insert("run", serde_json::Value::Number(serde_json::Number::from(run)));
    map.insert("run_id", serde_json::Value::String(run_id.into()));
    map.insert("runtime_build_id", serde_json::Value::String(runtime_build_id.into()));
    map.insert("runtime_sha256", serde_json::Value::String(runtime_sha256.into()));
    map.insert("schema_version", serde_json::Value::Number(serde_json::Number::from(1)));
    map.insert("status", serde_json::Value::String("passed".into()));

    let mut json_str = serde_json::to_string_pretty(&map).ok()?;
    json_str.push('\n');
    Some(json_str)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_build_attestation(
    input: *const MocktailRustCanaryAttestationInput,
    out_json: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if input.is_null() || out_json.is_null() || cap == 0 {
        return -1;
    }
    if !out_len.is_null() {
        *out_len = 0;
    }
    let inp = &*input;
    let run_id = match c_to_str(inp.run_id, inp.run_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let payload_id = match c_to_str(inp.payload_id, inp.payload_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let payload_fingerprint = match c_to_str(inp.payload_fingerprint, inp.payload_fingerprint_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let profile_sha256 = match c_to_str(inp.profile_sha256, inp.profile_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let compatibility_manifest_sha256 = match c_to_str(inp.compatibility_manifest_sha256, inp.compatibility_manifest_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let runtime_sha256 = match c_to_str(inp.runtime_sha256, inp.runtime_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let runtime_build_id = match c_to_str(inp.runtime_build_id, inp.runtime_build_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let log_sha256 = match c_to_str(inp.log_sha256, inp.log_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let Some(json_str) = build_canary_attestation_json(
        inp.run,
        run_id,
        payload_id,
        payload_fingerprint,
        profile_sha256,
        compatibility_manifest_sha256,
        runtime_sha256,
        runtime_build_id,
        log_sha256,
    ) else {
        return -1;
    };

    let bytes = json_str.as_bytes();
    if bytes.len() >= cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_json as *mut u8, bytes.len());
    *out_json.add(bytes.len()) = 0;
    if !out_len.is_null() {
        *out_len = bytes.len();
    }
    0
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustApprovalReceiptInput {
    pub payload_id: *const c_char,
    pub payload_id_len: usize,
    pub generation: *const c_char,
    pub generation_len: usize,
    pub payload_path: *const c_char,
    pub payload_path_len: usize,
    pub elf_build_id: *const c_char,
    pub elf_build_id_len: usize,
    pub library_sha256: *const c_char,
    pub library_sha256_len: usize,
    pub payload_fingerprint: *const c_char,
    pub payload_fingerprint_len: usize,
    pub profile_sha256: *const c_char,
    pub profile_sha256_len: usize,
    pub compatibility_manifest_sha256: *const c_char,
    pub compatibility_manifest_sha256_len: usize,
    pub runtime_sha256: *const c_char,
    pub runtime_sha256_len: usize,
    pub runtime_build_id: *const c_char,
    pub runtime_build_id_len: usize,
    pub canary_1_sha256: *const c_char,
    pub canary_1_sha256_len: usize,
    pub canary_2_sha256: *const c_char,
    pub canary_2_sha256_len: usize,
    pub approved_at_utc: *const c_char,
    pub approved_at_utc_len: usize,
}

pub(crate) fn build_approval_receipt_json(
    payload_id: &str,
    generation: &str,
    payload_path: &str,
    elf_build_id: &str,
    library_sha256: &str,
    payload_fingerprint: &str,
    profile_sha256: &str,
    compatibility_manifest_sha256: &str,
    runtime_sha256: &str,
    runtime_build_id: &str,
    canary_1: &str,
    canary_2: &str,
    approved_at: &str,
) -> Option<String> {
    let mut map = std::collections::BTreeMap::new();
    map.insert("approved_at", serde_json::Value::String(approved_at.into()));
    map.insert(
        "canary_attestation_sha256",
        serde_json::Value::Array(vec![
            serde_json::Value::String(canary_1.into()),
            serde_json::Value::String(canary_2.into()),
        ]),
    );
    map.insert("canary_runtime_sha256", serde_json::Value::String(runtime_sha256.into()));
    map.insert("canary_tier", serde_json::Value::String("C".into()));
    map.insert(
        "compatibility_manifest_sha256",
        serde_json::Value::String(compatibility_manifest_sha256.into()),
    );
    map.insert("elf_build_id", serde_json::Value::String(elf_build_id.into()));
    map.insert("generation", serde_json::Value::String(generation.into()));
    map.insert(
        "payload_fingerprint",
        serde_json::Value::String(payload_fingerprint.into()),
    );
    map.insert("payload_id", serde_json::Value::String(payload_id.into()));
    map.insert("payload_path", serde_json::Value::String(payload_path.into()));
    map.insert("payload_sha256", serde_json::Value::String(library_sha256.into()));
    map.insert("profile_sha256", serde_json::Value::String(profile_sha256.into()));
    map.insert("runtime_build_id", serde_json::Value::String(runtime_build_id.into()));
    map.insert("runtime_sha256", serde_json::Value::String(runtime_sha256.into()));
    map.insert("schema_version", serde_json::Value::Number(serde_json::Number::from(1)));
    map.insert("status", serde_json::Value::String("approved".into()));
    map.insert("successful_runs", serde_json::Value::Number(serde_json::Number::from(2)));

    let mut json_str = serde_json::to_string_pretty(&map).ok()?;
    json_str.push('\n');
    Some(json_str)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_build_receipt(
    input: *const MocktailRustApprovalReceiptInput,
    out_json: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if input.is_null() || out_json.is_null() || cap == 0 {
        return -1;
    }
    if !out_len.is_null() {
        *out_len = 0;
    }
    let inp = &*input;
    let payload_id = match c_to_str(inp.payload_id, inp.payload_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let generation = match c_to_str(inp.generation, inp.generation_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let payload_path = match c_to_str(inp.payload_path, inp.payload_path_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let elf_build_id = match c_to_str(inp.elf_build_id, inp.elf_build_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let library_sha256 = match c_to_str(inp.library_sha256, inp.library_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let payload_fingerprint = match c_to_str(inp.payload_fingerprint, inp.payload_fingerprint_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let profile_sha256 = match c_to_str(inp.profile_sha256, inp.profile_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let compatibility_manifest_sha256 = match c_to_str(inp.compatibility_manifest_sha256, inp.compatibility_manifest_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let runtime_sha256 = match c_to_str(inp.runtime_sha256, inp.runtime_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let runtime_build_id = match c_to_str(inp.runtime_build_id, inp.runtime_build_id_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let canary_1 = match c_to_str(inp.canary_1_sha256, inp.canary_1_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let canary_2 = match c_to_str(inp.canary_2_sha256, inp.canary_2_sha256_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let approved_at = match c_to_str(inp.approved_at_utc, inp.approved_at_utc_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let Some(json_str) = build_approval_receipt_json(
        payload_id,
        generation,
        payload_path,
        elf_build_id,
        library_sha256,
        payload_fingerprint,
        profile_sha256,
        compatibility_manifest_sha256,
        runtime_sha256,
        runtime_build_id,
        canary_1,
        canary_2,
        approved_at,
    ) else {
        return -1;
    };

    let bytes = json_str.as_bytes();
    if bytes.len() >= cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_json as *mut u8, bytes.len());
    *out_json.add(bytes.len()) = 0;
    if !out_len.is_null() {
        *out_len = bytes.len();
    }
    0
}

// ============================================================================
// 64. GameMode & Physics Worker Policies (Parsing, States & Worker Counts)
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_game_mode_parse_policy(
    value: *const c_char,
    val_len: usize,
    out_policy: *mut i32,
) -> bool {
    if out_policy.is_null() {
        return false;
    }
    let s = match c_to_str(value, val_len) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if s == "auto" {
        *out_policy = 0; // kAuto
        true
    } else if s == "on" || s == "1" || s == "true" {
        *out_policy = 1; // kOn
        true
    } else if s == "off" || s == "0" || s == "false" {
        *out_policy = 2; // kOff
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_mode_policy_name(policy: i32) -> *const c_char {
    match policy {
        0 => b"auto\0".as_ptr() as *const c_char,
        1 => b"on\0".as_ptr() as *const c_char,
        2 => b"off\0".as_ptr() as *const c_char,
        _ => b"invalid\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_game_mode_session_state_name(state: i32) -> *const c_char {
    match state {
        0 => b"disabled\0".as_ptr() as *const c_char,
        1 => b"unavailable\0".as_ptr() as *const c_char,
        2 => b"request-failed\0".as_ptr() as *const c_char,
        3 => b"already-active\0".as_ptr() as *const c_char,
        4 => b"active\0".as_ptr() as *const c_char,
        5 => b"stopped\0".as_ptr() as *const c_char,
        6 => b"stop-failed\0".as_ptr() as *const c_char,
        _ => b"invalid\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_performance_parse_physics_worker_mode(
    value: *const c_char,
    val_len: usize,
    out_mode: *mut i32,
) -> bool {
    if out_mode.is_null() {
        return false;
    }
    let s = match c_to_str(value, val_len) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if s.is_empty() || s == "auto" {
        *out_mode = 0; // kAuto
        true
    } else if s == "latency" {
        *out_mode = 1; // kLatency
        true
    } else if s == "throughput" {
        *out_mode = 2; // kThroughput
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_performance_physics_worker_mode_name(mode: i32) -> *const c_char {
    match mode {
        0 => b"auto\0".as_ptr() as *const c_char,
        1 => b"latency\0".as_ptr() as *const c_char,
        2 => b"throughput\0".as_ptr() as *const c_char,
        _ => b"auto\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_performance_calculate_throughput_worker_count(
    available_physical_cores: i32,
) -> i32 {
    std::cmp::max(1, available_physical_cores)
}

// ============================================================================
// 65. Single Instance Lock Isolated Canary & Sibling Path Gate
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustCanaryPathsInput {
    pub canary_value: *const c_char,
    pub canary_len: usize,
    pub has_data_root: bool,
    pub has_cache_root: bool,
    pub has_state_root: bool,
    pub has_roblox_lib: bool,
    pub has_asset_path: bool,
    pub skip_update_value: *const c_char,
    pub skip_update_len: usize,
    pub auto_exit_ms_value: *const c_char,
    pub auto_exit_ms_len: usize,
    pub data_root: *const c_char,
    pub data_root_len: usize,
    pub cache_root: *const c_char,
    pub cache_root_len: usize,
    pub state_root: *const c_char,
    pub state_root_len: usize,
}

fn is_positive_decimal_str(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut has_non_zero = false;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return false;
        }
        if b != b'0' {
            has_non_zero = true;
        }
    }
    has_non_zero
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_single_instance_validate_isolated_canary(
    input: *const MocktailRustCanaryPathsInput,
    out_error: *mut c_char,
    error_cap: usize,
) -> i32 {
    if input.is_null() {
        return -1;
    }
    let inp = &*input;
    let canary = match c_to_str(inp.canary_value, inp.canary_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let skip_update = match c_to_str(inp.skip_update_value, inp.skip_update_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let auto_exit_ms = match c_to_str(inp.auto_exit_ms_value, inp.auto_exit_ms_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let data_root = match c_to_str(inp.data_root, inp.data_root_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let cache_root = match c_to_str(inp.cache_root, inp.cache_root_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let state_root = match c_to_str(inp.state_root, inp.state_root_len) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    if canary != "1"
        || !inp.has_data_root
        || !inp.has_cache_root
        || !inp.has_state_root
        || !inp.has_roblox_lib
        || !inp.has_asset_path
        || skip_update != "1"
        || !is_positive_decimal_str(auto_exit_ms)
    {
        write_err_msg(
            out_error,
            error_cap,
            "isolated canary requires explicit payload, XDG roots, update bypass, and a bounded present timer",
        );
        return 1;
    }

    let p_data = std::path::Path::new(data_root);
    let p_cache = std::path::Path::new(cache_root);
    let p_state = std::path::Path::new(state_root);

    let is_valid_siblings = p_data.is_absolute()
        && p_cache.is_absolute()
        && p_state.is_absolute()
        && p_data != p_cache
        && p_data != p_state
        && p_cache != p_state
        && p_data.parent().is_some()
        && p_data.parent() == p_cache.parent()
        && p_data.parent() == p_state.parent();

    if !is_valid_siblings {
        write_err_msg(
            out_error,
            error_cap,
            "isolated canary data, cache, and state roots must be distinct absolute siblings",
        );
        return 2;
    }

    0
}

// ============================================================================
// 66. Audio & HttpClient Overrides Policy Engine
// ============================================================================

unsafe fn merge_settings_map(
    base_json: *const c_char,
    base_len: usize,
    mut overrides: Vec<(&str, &str)>,
    out_json: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_json.is_null() || cap == 0 {
        return -1;
    }
    if !out_len.is_null() {
        *out_len = 0;
    }

    let base_slice = if !base_json.is_null() && base_len > 0 {
        std::slice::from_raw_parts(base_json as *const u8, base_len)
    } else {
        b"{}"
    };

    let mut doc: serde_json::Value = match serde_json::from_slice(base_slice) {
        Ok(v) => v,
        Err(_) => return -2,
    };

    let map = match doc.as_object_mut() {
        Some(m) => m,
        None => return -2,
    };

    for (k, v) in overrides.drain(..) {
        map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }

    let json_str = match serde_json::to_string(&doc) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let bytes = json_str.as_bytes();
    if bytes.len() >= cap {
        return -3;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_json as *mut u8, bytes.len());
    *out_json.add(bytes.len()) = 0;
    if !out_len.is_null() {
        *out_len = bytes.len();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_http_client_merge_settings_overrides(
    base_json: *const c_char,
    base_len: usize,
    out_json: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let overrides = vec![
        ("FFlagUseRuntimeMutexRvHttpClient", "False"),
        ("DFFlagHttpClientSkipRetryForStreamingRequests", "True"),
        ("FFlagLuaAppDefaultHttpRetry", "False"),
    ];
    merge_settings_map(base_json, base_len, overrides, out_json, cap, out_len)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_audio_device_menu_merge_overrides(
    base_json: *const c_char,
    base_len: usize,
    out_json: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let overrides = vec![
        ("FFlagDebugUseWebRtcAudioDevices", "False"),
        ("FFlagRemoteAudioDeviceSync", "False"),
    ];
    merge_settings_map(base_json, base_len, overrides, out_json, cap, out_len)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_audio_capture_merge_overrides(
    base_json: *const c_char,
    base_len: usize,
    out_json: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let overrides = vec![
        ("DFFlagVoiceChatSkipPermissionCheckForTests", "False"),
    ];
    merge_settings_map(base_json, base_len, overrides, out_json, cap, out_len)
}

// ============================================================================
// 67. Texture Memory Policy Engine
// ============================================================================

pub(crate) fn copy_error(dst: *mut c_char, cap: usize, msg: &str) {
    if dst.is_null() || cap == 0 {
        return;
    }
    let max_bytes = cap - 1;
    let mut len = msg.len().min(max_bytes);
    while len > 0 && !msg.is_char_boundary(len) {
        len -= 1;
    }
    unsafe {
        if len > 0 {
            std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, dst, len);
        }
        *dst.add(len) = 0;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_texture_memory_calculate_budget(
    host_memory_bytes: u64,
) -> u64 {
    const K_MEBIBYTE: u64 = 1024 * 1024;
    const K_MINIMUM_HOST_MEMORY_BYTES: u64 = 4096 * K_MEBIBYTE;
    const K_MINIMUM_BUDGET_BYTES: u64 = 256 * K_MEBIBYTE;
    const K_MAXIMUM_BUDGET_BYTES: u64 = 1536 * K_MEBIBYTE;

    if host_memory_bytes < K_MINIMUM_HOST_MEMORY_BYTES {
        return 0;
    }
    (host_memory_bytes / 8).clamp(K_MINIMUM_BUDGET_BYTES, K_MAXIMUM_BUDGET_BYTES)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_texture_memory_merge_overrides(
    budget_bytes: u64,
    base_json_ptr: *const c_char,
    base_json_len: usize,
    out_ptr: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
    err_ptr: *mut c_char,
    err_cap: usize,
) -> c_int {
    let base_slice = if base_json_ptr.is_null() || base_json_len == 0 {
        "{}"
    } else {
        let s = unsafe { std::slice::from_raw_parts(base_json_ptr as *const u8, base_json_len) };
        match std::str::from_utf8(s) {
            Ok(st) => {
                let trimmed = st.trim();
                if trimmed.is_empty() { "{}" } else { trimmed }
            }
            Err(_) => {
                copy_error(err_ptr, err_cap, "texture memory client-settings input must be a JSON object");
                return -1;
            }
        }
    };

    let mut json_val: serde_json::Value = match serde_json::from_str(base_slice) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_ptr, err_cap, "texture memory client-settings input must be a JSON object");
            return -1;
        }
    };

    let map = match json_val.as_object_mut() {
        Some(m) => m,
        None => {
            copy_error(err_ptr, err_cap, "texture memory client-settings input must be a JSON object");
            return -1;
        }
    };

    const VIDEO_MEMORY_OVERRIDE: &str = "FIntRenderForceVideoMemorySize";
    if budget_bytes != 0 && !map.contains_key(VIDEO_MEMORY_OVERRIDE) {
        let clamped = budget_bytes.min(i32::MAX as u64);
        map.insert(VIDEO_MEMORY_OVERRIDE.to_string(), serde_json::Value::String(clamped.to_string()));
    }

    let serialized = match serde_json::to_string(&json_val) {
        Ok(s) => s,
        Err(_) => {
            copy_error(err_ptr, err_cap, "failed to serialize merged client settings");
            return -2;
        }
    };

    let bytes = serialized.as_bytes();
    if !out_len.is_null() {
        unsafe { *out_len = bytes.len(); }
    }
    if bytes.len() + 1 > out_cap {
        return -5;
    }
    if !out_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_ptr, bytes.len());
            *out_ptr.add(bytes.len()) = 0;
        }
    }
    0
}

// ============================================================================
// 68. Roblox Desktop App Policy Engine
// ============================================================================

fn normalize_desktop_layout_internal(policy: &mut serde_json::Value, forced_theme: &str) {
    if let Some(map) = policy.as_object_mut() {
        map.insert("PlatformGroup".to_string(), serde_json::Value::String("Desktop".to_string()));
        map.insert("UseGridHomePage".to_string(), serde_json::Value::Bool(true));
        map.insert("UseGridPageLayout".to_string(), serde_json::Value::Bool(true));
        map.insert("SystemBarPlacement".to_string(), serde_json::Value::String("Left".to_string()));
        map.insert("ShouldSystemBarUsuallyBePresent".to_string(), serde_json::Value::Bool(true));
        map.insert("DevicePreferencesPersistentPresenceVariant".to_string(), serde_json::Value::String("windows".to_string()));
        map.insert("ShowUncheckedBadge".to_string(), serde_json::Value::Bool(false));
        map.insert("ForceTheme".to_string(), serde_json::Value::String(forced_theme.to_string()));
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_process_desktop_app_policy(
    storage_json_ptr: *const c_char,
    storage_json_len: usize,
    has_storage: bool,
    default_policy_ptr: *const c_char,
    default_policy_len: usize,
    authenticated_user_id: i64,
    theme_mode_ptr: *const c_char,
    out_storage_ptr: *mut c_char,
    out_storage_cap: usize,
    out_storage_len: *mut usize,
    out_policy_ptr: *mut c_char,
    out_policy_cap: usize,
    out_policy_len: *mut usize,
    out_updated: *mut bool,
    out_normalized_count: *mut usize,
    err_ptr: *mut c_char,
    err_cap: usize,
) -> c_int {
    let theme_mode = if theme_mode_ptr.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(theme_mode_ptr).to_str().unwrap_or("") }
    };

    if authenticated_user_id < -1 || (theme_mode != "roblox" && theme_mode != "system" && theme_mode != "light" && theme_mode != "dark") {
        copy_error(err_ptr, err_cap, "desktop app-policy paths, user ID, or theme are invalid");
        return -1;
    }

    let forced_theme = match theme_mode {
        "light" => "light",
        "dark" => "dark",
        _ => "",
    };

    let mut storage_obj: serde_json::Map<String, serde_json::Value> = if has_storage {
        let slice = unsafe { std::slice::from_raw_parts(storage_json_ptr as *const u8, storage_json_len) };
        let s = match std::str::from_utf8(slice) {
            Ok(v) => v,
            Err(_) => {
                copy_error(err_ptr, err_cap, "Roblox appStorage is not a JSON object");
                return -2;
            }
        };
        match serde_json::from_str::<serde_json::Value>(s) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => {
                copy_error(err_ptr, err_cap, "Roblox appStorage is not a JSON object");
                return -2;
            }
        }
    } else {
        serde_json::Map::new()
    };

    let mut configurations: serde_json::Map<String, serde_json::Value> = match storage_obj.get("AppConfiguration") {
        Some(serde_json::Value::String(enc)) => {
            match serde_json::from_str::<serde_json::Value>(enc) {
                Ok(serde_json::Value::Object(m)) => m,
                _ => {
                    copy_error(err_ptr, err_cap, "Roblox AppConfiguration encoding is invalid");
                    return -4;
                }
            }
        }
        Some(_) => {
            copy_error(err_ptr, err_cap, "Roblox AppConfiguration is not an encoded object");
            return -3;
        }
        None => serde_json::Map::new(),
    };

    let mut template_policy: Option<serde_json::Value> = None;
    let mut guest_policy: Option<serde_json::Value> = None;
    let mut authenticated_policy: Option<serde_json::Value> = None;
    let authenticated_key = if authenticated_user_id >= 0 {
        format!("GUAC:{}:app-policy", authenticated_user_id)
    } else {
        String::new()
    };

    let mut norm_count: usize = 0;
    const SUFFIX: &str = ":app-policy";

    for (k, v) in configurations.iter_mut() {
        if !k.ends_with(SUFFIX) {
            continue;
        }
        let enc_str = match v.as_str() {
            Some(s) => s,
            None => {
                copy_error(err_ptr, err_cap, "cached Roblox app-policy encoding is invalid");
                return -5;
            }
        };
        let mut policy_val: serde_json::Value = match serde_json::from_str::<serde_json::Value>(enc_str) {
            Ok(p) if p.is_object() => p,
            _ => {
                copy_error(err_ptr, err_cap, "cached Roblox app-policy encoding is invalid");
                return -5;
            }
        };

        normalize_desktop_layout_internal(&mut policy_val, forced_theme);
        let new_enc = policy_val.to_string();
        *v = serde_json::Value::String(new_enc);

        if template_policy.is_none() {
            template_policy = Some(policy_val.clone());
        }
        if k == "GUAC:-1:app-policy" {
            guest_policy = Some(policy_val.clone());
        }
        if !authenticated_key.is_empty() && k == &authenticated_key {
            authenticated_policy = Some(policy_val);
        }
        norm_count += 1;
    }

    if let Some(auth) = authenticated_policy {
        template_policy = Some(auth);
    } else if let Some(guest) = guest_policy {
        template_policy = Some(guest);
    }

    if template_policy.is_none() {
        if default_policy_ptr.is_null() || default_policy_len == 0 {
            copy_error(err_ptr, err_cap, "Roblox default app-policy is missing");
            return -6;
        }
        let slice = unsafe { std::slice::from_raw_parts(default_policy_ptr as *const u8, default_policy_len) };
        let s = match std::str::from_utf8(slice) {
            Ok(v) => v,
            Err(_) => {
                copy_error(err_ptr, err_cap, "Roblox default app-policy is not a JSON object");
                return -6;
            }
        };
        let mut def_val: serde_json::Value = match serde_json::from_str::<serde_json::Value>(s) {
            Ok(p) if p.is_object() => p,
            _ => {
                copy_error(err_ptr, err_cap, "Roblox default app-policy is not a JSON object");
                return -6;
            }
        };
        normalize_desktop_layout_internal(&mut def_val, forced_theme);
        template_policy = Some(def_val);
    }

    let tpl = template_policy.unwrap();
    let encoded_policy = tpl.to_string();
    configurations.insert("GUAC:-1:app-policy".to_string(), serde_json::Value::String(encoded_policy.clone()));
    if !authenticated_key.is_empty() {
        configurations.insert(authenticated_key, serde_json::Value::String(encoded_policy.clone()));
    }

    let encoded_configurations = serde_json::to_string(&configurations).unwrap_or_default();
    let changed = match storage_obj.get("AppConfiguration") {
        Some(serde_json::Value::String(existing)) => existing != &encoded_configurations,
        _ => true,
    };

    if changed {
        storage_obj.insert("AppConfiguration".to_string(), serde_json::Value::String(encoded_configurations));
    }

    let new_storage_dump = serde_json::to_string(&storage_obj).unwrap_or_default();

    if !out_updated.is_null() {
        unsafe { *out_updated = changed; }
    }
    if !out_normalized_count.is_null() {
        unsafe { *out_normalized_count = norm_count; }
    }

    // Write policy_json
    let pol_bytes = encoded_policy.as_bytes();
    if !out_policy_len.is_null() {
        unsafe { *out_policy_len = pol_bytes.len(); }
    }
    if pol_bytes.len() + 1 > out_policy_cap {
        return -7;
    }
    if !out_policy_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(pol_bytes.as_ptr() as *const c_char, out_policy_ptr, pol_bytes.len());
            *out_policy_ptr.add(pol_bytes.len()) = 0;
        }
    }

    // Write storage_json
    let sto_bytes = new_storage_dump.as_bytes();
    if !out_storage_len.is_null() {
        unsafe { *out_storage_len = sto_bytes.len(); }
    }
    if sto_bytes.len() + 1 > out_storage_cap {
        return -8;
    }
    if !out_storage_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(sto_bytes.as_ptr() as *const c_char, out_storage_ptr, sto_bytes.len());
            *out_storage_ptr.add(sto_bytes.len()) = 0;
        }
    }

    0
}

// ============================================================================
// 69. Launch Experience JSON Engine
// ============================================================================

#[repr(C)]
pub struct MocktailRustExperienceLaunchData {
    pub place_id: i64,
    pub user_id: i64,
    pub conversation_id: i64,
    pub referred_by_player_id: i64,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_experience_launch_json(
    json_ptr: *const c_char,
    json_len: usize,
    out_data: *mut MocktailRustExperienceLaunchData,
    canonical_buf: *mut c_char,
    canonical_cap: usize,
    canonical_len: *mut usize,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    const K_MAXIMUM_EXPERIENCE_LAUNCH_JSON_BYTES: usize = 16 * 1024 * 1024;
    if json_ptr.is_null() || json_len == 0 || json_len > K_MAXIMUM_EXPERIENCE_LAUNCH_JSON_BYTES {
        copy_error(err_buf, err_cap, "experience launch JSON size is invalid");
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(json_ptr as *const u8, json_len) };
    let s = match std::str::from_utf8(slice) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "experience launch payload is not a JSON object");
            return -2;
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(s) {
        Ok(serde_json::Value::Object(m)) => serde_json::Value::Object(m),
        _ => {
            copy_error(err_buf, err_cap, "experience launch payload is not a JSON object");
            return -2;
        }
    };

    let obj = doc.as_object().unwrap();

    fn read_opt_int(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<i64, ()> {
        match obj.get(key) {
            None | Some(serde_json::Value::Null) => Ok(0),
            Some(serde_json::Value::Number(n)) => n.as_i64().ok_or(()),
            _ => Err(()),
        }
    }

    let place_id = match read_opt_int(obj, "placeId") {
        Ok(val) => val,
        Err(_) => {
            copy_error(err_buf, err_cap, "placeId must be an integer");
            return -3;
        }
    };
    let user_id = match read_opt_int(obj, "userId") {
        Ok(val) => val,
        Err(_) => {
            copy_error(err_buf, err_cap, "userId must be an integer");
            return -3;
        }
    };
    let conv_id = match read_opt_int(obj, "conversationId") {
        Ok(val) => val,
        Err(_) => {
            copy_error(err_buf, err_cap, "conversationId must be an integer");
            return -3;
        }
    };
    let ref_by = match read_opt_int(obj, "referredByPlayerId") {
        Ok(val) => val,
        Err(_) => {
            copy_error(err_buf, err_cap, "referredByPlayerId must be an integer");
            return -3;
        }
    };

    if place_id <= 0 {
        copy_error(err_buf, err_cap, "experience launch requires a positive placeId");
        return -4;
    }
    if user_id < 0 || conv_id < 0 || ref_by < 0 {
        copy_error(err_buf, err_cap, "experience launch identifiers cannot be negative");
        return -5;
    }

    if !out_data.is_null() {
        unsafe {
            (*out_data).place_id = place_id;
            (*out_data).user_id = user_id;
            (*out_data).conversation_id = conv_id;
            (*out_data).referred_by_player_id = ref_by;
        }
    }

    let canonical = doc.to_string();
    if canonical.len() > K_MAXIMUM_EXPERIENCE_LAUNCH_JSON_BYTES {
        copy_error(err_buf, err_cap, "canonical experience launch JSON is too large");
        return -6;
    }

    let can_bytes = canonical.as_bytes();
    if !canonical_len.is_null() {
        unsafe { *canonical_len = can_bytes.len(); }
    }
    if can_bytes.len() + 1 > canonical_cap {
        return -7;
    }
    if !canonical_buf.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(can_bytes.as_ptr() as *const c_char, canonical_buf, can_bytes.len());
            *canonical_buf.add(can_bytes.len()) = 0;
        }
    }
    0
}

