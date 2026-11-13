use std::os::raw::{c_char, c_int};
use std::slice;

const PASSWORD_BULLET: &str = "\u{2022}";
const PASSWORD_BULLET_BYTES: &[u8] = PASSWORD_BULLET.as_bytes();

pub const TEXT_DISPLAY_EVENT_SHOW: i32 = 0;
pub const TEXT_DISPLAY_EVENT_UPDATE: i32 = 1;
pub const TEXT_DISPLAY_EVENT_HIDE: i32 = 2;

pub const TEXT_DISPLAY_APPLY_INVALID_EVENT: i32 = -1;
pub const TEXT_DISPLAY_APPLY_NOOP: i32 = 0;
pub const TEXT_DISPLAY_APPLY_HIDE_CLEAR: i32 = 1;
pub const TEXT_DISPLAY_APPLY_BUILD_PRESENTATION: i32 = 2;

pub const TEXT_DISPLAY_BUILD_NULL_OUT: i32 = -1;
pub const TEXT_DISPLAY_BUILD_OK: i32 = 0;
pub const TEXT_DISPLAY_BUILD_INVALID_GENERATION: i32 = 1;
pub const TEXT_DISPLAY_BUILD_INVALID_VIEWPORT: i32 = 2;
pub const TEXT_DISPLAY_BUILD_INVALID_UTF8_PTR: i32 = 3;
pub const TEXT_DISPLAY_BUILD_INVALID_UTF8: i32 = 4;
pub const TEXT_DISPLAY_BUILD_PASSWORD_OVERFLOW: i32 = 5;
pub const TEXT_DISPLAY_BUILD_BUFFER_TOO_SMALL: i32 = 6;

// ============================================================================
// 131. Roblox Text Display State & Password Masking
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MocktailRustTextOverlayGeometryResult {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub used_fallback: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MocktailRustTextPresentationMetrics {
    pub codepoint_count: usize,
    pub display_bytes: usize,
    pub caret_utf8_byte: usize,
    pub selection_begin_utf8_byte: usize,
    pub selection_end_utf8_byte: usize,
    pub is_password: bool,
}

fn viewport_is_valid(width: i32, height: i32, density_scale: f32) -> bool {
    width > 0 && height > 0 && density_scale.is_finite() && density_scale > 0.0
}

fn viewport_coordinate_extent(extent: i32, density_scale: f32) -> i32 {
    if extent <= 0 || !density_scale.is_finite() || density_scale <= 0.0 {
        return 0;
    }
    let scaled = (extent as f32) / density_scale;
    if !scaled.is_finite() {
        return 0;
    }
    scaled.round() as i32
}

fn utf8_byte_and_codepoints_for_utf16(text: &str, requested_utf16: i32) -> (usize, usize) {
    let target = if requested_utf16 > 0 {
        requested_utf16 as usize
    } else {
        0
    };
    let mut utf16_count = 0usize;
    let mut byte_count = 0usize;
    let mut codepoint_count = 0usize;

    for ch in text.chars() {
        let u16_len = ch.len_utf16();
        if utf16_count + u16_len > target {
            break;
        }
        utf16_count += u16_len;
        byte_count += ch.len_utf8();
        codepoint_count += 1;
    }

    (byte_count, codepoint_count)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_overlay_viewport_coordinate_size(
    extent: i32,
    density_scale: f32,
) -> i32 {
    viewport_coordinate_extent(extent, density_scale)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_overlay_resolve_geometry(
    area_x: i32,
    area_y: i32,
    area_w: i32,
    area_h: i32,
    vp_w: i32,
    vp_h: i32,
    density_scale: f32,
    out_geom: *mut MocktailRustTextOverlayGeometryResult,
) -> bool {
    if out_geom.is_null() {
        return false;
    }
    if !viewport_is_valid(vp_w, vp_h, density_scale) {
        unsafe {
            *out_geom = MocktailRustTextOverlayGeometryResult::default();
        }
        return false;
    }
    let coord_w = viewport_coordinate_extent(vp_w, density_scale);
    let coord_h = viewport_coordinate_extent(vp_h, density_scale);
    if crate::mocktail_rust_text_geometry_intersects_viewport(
        area_x, area_y, area_w, area_h, coord_w, coord_h,
    ) != 1
    {
        unsafe {
            *out_geom = MocktailRustTextOverlayGeometryResult::default();
        }
        return false;
    }
    unsafe {
        *out_geom = MocktailRustTextOverlayGeometryResult {
            x: area_x,
            y: area_y,
            width: area_w,
            height: area_h,
            used_fallback: false,
        };
    }
    true
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_display_decide_apply(
    event: i32,
    update_generation: u64,
    current_visible: bool,
    current_generation: u64,
) -> i32 {
    match event {
        TEXT_DISPLAY_EVENT_HIDE => {
            if !current_visible || update_generation != current_generation {
                TEXT_DISPLAY_APPLY_NOOP
            } else {
                TEXT_DISPLAY_APPLY_HIDE_CLEAR
            }
        }
        TEXT_DISPLAY_EVENT_UPDATE => {
            if !current_visible || update_generation != current_generation {
                TEXT_DISPLAY_APPLY_NOOP
            } else {
                TEXT_DISPLAY_APPLY_BUILD_PRESENTATION
            }
        }
        TEXT_DISPLAY_EVENT_SHOW => {
            if current_visible && update_generation < current_generation {
                TEXT_DISPLAY_APPLY_NOOP
            } else {
                TEXT_DISPLAY_APPLY_BUILD_PRESENTATION
            }
        }
        _ => TEXT_DISPLAY_APPLY_INVALID_EVENT,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_display_prepare_presentation(
    generation: u64,
    vp_w: i32,
    vp_h: i32,
    density_scale: f32,
    text_input_type: i32,
    utf8: *const c_char,
    utf8_size: usize,
    cursor_utf16: i32,
    selection_begin_utf16: i32,
    selection_end_utf16: i32,
    out_metrics: *mut MocktailRustTextPresentationMetrics,
) -> i32 {
    if out_metrics.is_null() {
        return TEXT_DISPLAY_BUILD_NULL_OUT;
    }
    if generation == 0 {
        return TEXT_DISPLAY_BUILD_INVALID_GENERATION;
    }
    if !viewport_is_valid(vp_w, vp_h, density_scale) {
        return TEXT_DISPLAY_BUILD_INVALID_VIEWPORT;
    }
    if utf8_size != 0 && utf8.is_null() {
        return TEXT_DISPLAY_BUILD_INVALID_UTF8_PTR;
    }

    let raw_bytes: &[u8] = if utf8_size == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(utf8 as *const u8, utf8_size) }
    };
    let text = match std::str::from_utf8(raw_bytes) {
        Ok(valid) => valid,
        Err(_) => return TEXT_DISPLAY_BUILD_INVALID_UTF8,
    };

    let codepoint_count = text.chars().count();
    let (caret_source_byte, codepoints_before_cursor) =
        utf8_byte_and_codepoints_for_utf16(text, cursor_utf16);
    let (selection_begin_source_byte, codepoints_before_selection_begin) =
        utf8_byte_and_codepoints_for_utf16(text, selection_begin_utf16);
    let (selection_end_source_byte, codepoints_before_selection_end) =
        utf8_byte_and_codepoints_for_utf16(text, selection_end_utf16);

    let is_password = crate::mocktail_rust_text_is_password_input(text_input_type) != 0;
    let metrics = if is_password {
        let Some(display_bytes) = codepoint_count.checked_mul(PASSWORD_BULLET_BYTES.len()) else {
            return TEXT_DISPLAY_BUILD_PASSWORD_OVERFLOW;
        };
        let sel_lo_cp = codepoints_before_selection_begin.min(codepoints_before_selection_end);
        let sel_hi_cp = codepoints_before_selection_begin.max(codepoints_before_selection_end);
        MocktailRustTextPresentationMetrics {
            codepoint_count,
            display_bytes,
            caret_utf8_byte: codepoints_before_cursor * PASSWORD_BULLET_BYTES.len(),
            selection_begin_utf8_byte: sel_lo_cp * PASSWORD_BULLET_BYTES.len(),
            selection_end_utf8_byte: sel_hi_cp * PASSWORD_BULLET_BYTES.len(),
            is_password: true,
        }
    } else {
        MocktailRustTextPresentationMetrics {
            codepoint_count,
            display_bytes: utf8_size,
            caret_utf8_byte: caret_source_byte,
            selection_begin_utf8_byte: selection_begin_source_byte.min(selection_end_source_byte),
            selection_end_utf8_byte: selection_begin_source_byte.max(selection_end_source_byte),
            is_password: false,
        }
    };

    unsafe {
        *out_metrics = metrics;
    }
    TEXT_DISPLAY_BUILD_OK
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_display_write_password_bullets(
    codepoint_count: usize,
    out_buf: *mut u8,
    out_cap: usize,
) -> i32 {
    let Some(required_bytes) = codepoint_count.checked_mul(PASSWORD_BULLET_BYTES.len()) else {
        return TEXT_DISPLAY_BUILD_PASSWORD_OVERFLOW;
    };
    if required_bytes == 0 {
        return TEXT_DISPLAY_BUILD_OK;
    }
    if out_buf.is_null() {
        return TEXT_DISPLAY_BUILD_NULL_OUT;
    }
    if out_cap < required_bytes {
        return TEXT_DISPLAY_BUILD_BUFFER_TOO_SMALL;
    }
    let dst = unsafe { slice::from_raw_parts_mut(out_buf, required_bytes) };
    for chunk in dst.chunks_exact_mut(PASSWORD_BULLET_BYTES.len()) {
        chunk.copy_from_slice(PASSWORD_BULLET_BYTES);
    }
    TEXT_DISPLAY_BUILD_OK
}

// ============================================================================
// 132. Visible Text Window Slicing
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MocktailRustVisibleTextWindow {
    pub begin: usize,
    pub end: usize,
    pub caret_byte: usize,
    pub selection_begin_byte: usize,
    pub selection_end_byte: usize,
}

fn is_utf8_continuation(byte: u8) -> bool {
    (byte & 0xC0) == 0x80
}

fn map_byte_to_window(byte: usize, begin: usize, end: usize) -> usize {
    if byte <= begin {
        0
    } else if byte >= end {
        end - begin
    } else {
        byte - begin
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_text_visible_window(
    text: *const u8,
    text_len: usize,
    caret_byte: usize,
    selection_begin_byte: usize,
    selection_end_byte: usize,
    max_window_bytes: usize,
    out_window: *mut MocktailRustVisibleTextWindow,
) -> c_int {
    if out_window.is_null() || (text_len != 0 && text.is_null()) {
        return -1;
    }

    let bytes: &[u8] = if text_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(text, text_len) }
    };

    let caret = caret_byte.min(text_len);
    let sel_begin = selection_begin_byte.min(text_len);
    let sel_end = selection_end_byte.min(text_len);
    let sel_lo = sel_begin.min(sel_end);
    let sel_hi = sel_begin.max(sel_end);

    if text_len <= max_window_bytes {
        unsafe {
            *out_window = MocktailRustVisibleTextWindow {
                begin: 0,
                end: text_len,
                caret_byte: caret,
                selection_begin_byte: sel_lo,
                selection_end_byte: sel_hi,
            };
        }
        return 0;
    }

    if max_window_bytes == 0 {
        unsafe {
            *out_window = MocktailRustVisibleTextWindow::default();
        }
        return 0;
    }

    let half = max_window_bytes / 2;
    let mut begin = caret.saturating_sub(half);
    let mut end = begin.saturating_add(max_window_bytes).min(text_len);
    if end - begin < max_window_bytes && begin != 0 {
        begin = end - max_window_bytes;
    }
    while begin < text_len && is_utf8_continuation(bytes[begin]) {
        begin += 1;
    }
    while end > begin && end < text_len && is_utf8_continuation(bytes[end]) {
        end -= 1;
    }

    let window_len = end - begin;
    let mapped_caret = caret.saturating_sub(begin).min(window_len);
    unsafe {
        *out_window = MocktailRustVisibleTextWindow {
            begin,
            end,
            caret_byte: mapped_caret,
            selection_begin_byte: map_byte_to_window(sel_lo, begin, end),
            selection_end_byte: map_byte_to_window(sel_hi, begin, end),
        };
    }
    0
}

// ============================================================================
// 133. General Bounded UTF-8 -> UTF-16 Surrogate Encoder
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_utf8_to_utf16_bounded(
    utf8_str: *const c_char,
    utf8_len: usize,
    max_bytes: usize,
    out_utf16: *mut u16,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if utf8_len == 0 {
        if !out_len.is_null() {
            unsafe {
                *out_len = 0;
            }
        }
        return 0;
    }
    if utf8_str.is_null() || (max_bytes != 0 && utf8_len > max_bytes) {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(utf8_str as *const u8, utf8_len) };
    let text = match std::str::from_utf8(slice) {
        Ok(valid) => valid,
        Err(_) => return -2,
    };

    let utf16_len: usize = text.chars().map(char::len_utf16).sum();
    if !out_len.is_null() {
        unsafe {
            *out_len = utf16_len;
        }
    }
    if out_utf16.is_null() || out_cap < utf16_len {
        return -3;
    }
    let dst = unsafe { slice::from_raw_parts_mut(out_utf16, utf16_len) };
    for (slot, unit) in dst.iter_mut().zip(text.encode_utf16()) {
        *slot = unit;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewport_coordinate_and_geometry_resolution() {
        assert_eq!(mocktail_rust_text_overlay_viewport_coordinate_size(1630, 1.145833), 1423);
        assert_eq!(mocktail_rust_text_overlay_viewport_coordinate_size(0, 1.0), 0);
        assert_eq!(mocktail_rust_text_overlay_viewport_coordinate_size(800, f32::NAN), 0);

        let mut geom = MocktailRustTextOverlayGeometryResult::default();
        assert!(mocktail_rust_text_overlay_resolve_geometry(
            120, 80, 360, 44, 1280, 720, 1.0, &mut geom
        ));
        assert_eq!(
            geom,
            MocktailRustTextOverlayGeometryResult {
                x: 120,
                y: 80,
                width: 360,
                height: 44,
                used_fallback: false,
            }
        );

        assert!(!mocktail_rust_text_overlay_resolve_geometry(
            0, 0, 0, 0, 1000, 700, 1.0, &mut geom
        ));
        assert_eq!(geom, MocktailRustTextOverlayGeometryResult::default());
    }

    #[test]
    fn test_display_state_decide_apply_and_password_masking() {
        assert_eq!(
            mocktail_rust_text_display_decide_apply(TEXT_DISPLAY_EVENT_HIDE, 4, false, 4),
            TEXT_DISPLAY_APPLY_NOOP
        );
        assert_eq!(
            mocktail_rust_text_display_decide_apply(TEXT_DISPLAY_EVENT_HIDE, 3, true, 4),
            TEXT_DISPLAY_APPLY_NOOP
        );
        assert_eq!(
            mocktail_rust_text_display_decide_apply(TEXT_DISPLAY_EVENT_HIDE, 4, true, 4),
            TEXT_DISPLAY_APPLY_HIDE_CLEAR
        );
        assert_eq!(
            mocktail_rust_text_display_decide_apply(TEXT_DISPLAY_EVENT_UPDATE, 3, true, 4),
            TEXT_DISPLAY_APPLY_NOOP
        );
        assert_eq!(
            mocktail_rust_text_display_decide_apply(TEXT_DISPLAY_EVENT_SHOW, 3, true, 4),
            TEXT_DISPLAY_APPLY_NOOP
        );
        assert_eq!(
            mocktail_rust_text_display_decide_apply(TEXT_DISPLAY_EVENT_SHOW, 5, true, 4),
            TEXT_DISPLAY_APPLY_BUILD_PRESENTATION
        );

        let text = "a😀z";
        let mut metrics = MocktailRustTextPresentationMetrics::default();
        let rc = mocktail_rust_text_display_prepare_presentation(
            1,
            1280,
            720,
            1.0,
            5,
            text.as_ptr() as *const c_char,
            text.len(),
            3,
            1,
            3,
            &mut metrics,
        );
        assert_eq!(rc, TEXT_DISPLAY_BUILD_OK);
        assert!(metrics.is_password);
        assert_eq!(metrics.codepoint_count, 3);
        assert_eq!(metrics.display_bytes, 9);
        assert_eq!(metrics.caret_utf8_byte, 6);
        assert_eq!(metrics.selection_begin_utf8_byte, 3);
        assert_eq!(metrics.selection_end_utf8_byte, 6);

        let mut bullets = vec![0u8; metrics.display_bytes];
        assert_eq!(
            mocktail_rust_text_display_write_password_bullets(
                metrics.codepoint_count,
                bullets.as_mut_ptr(),
                bullets.len(),
            ),
            TEXT_DISPLAY_BUILD_OK
        );
        assert_eq!(std::str::from_utf8(&bullets).unwrap(), "•••");

        assert_eq!(
            mocktail_rust_text_display_prepare_presentation(
                1,
                1280,
                720,
                1.0,
                1,
                std::ptr::null(),
                0,
                0,
                0,
                0,
                &mut metrics,
            ),
            TEXT_DISPLAY_BUILD_OK
        );
        assert_eq!(metrics.display_bytes, 0);

        let invalid = [0xffu8, 0xfeu8];
        assert_eq!(
            mocktail_rust_text_display_prepare_presentation(
                1,
                1280,
                720,
                1.0,
                1,
                invalid.as_ptr() as *const c_char,
                invalid.len(),
                0,
                0,
                0,
                &mut metrics,
            ),
            TEXT_DISPLAY_BUILD_INVALID_UTF8
        );
    }

    #[test]
    fn test_visible_text_window_respects_utf8_boundaries() {
        let repeated: String = "😀".repeat(20); // 80 bytes
        let mut win = MocktailRustVisibleTextWindow::default();
        let rc = mocktail_rust_text_visible_window(
            repeated.as_ptr(),
            repeated.len(),
            40,
            36,
            48,
            10,
            &mut win,
        );
        assert_eq!(rc, 0);
        assert!(win.begin <= win.end && win.end <= repeated.len());
        let sliced = std::str::from_utf8(&repeated.as_bytes()[win.begin..win.end]);
        assert!(sliced.is_ok());
        assert_eq!(win.caret_byte, 40 - win.begin);
        assert!(win.selection_begin_byte <= win.selection_end_byte);
        assert!(win.selection_end_byte <= win.end - win.begin);
    }

    #[test]
    fn test_utf8_to_utf16_bounded_handles_empty_large_and_invalid() {
        let mut out_len = 99usize;
        assert_eq!(
            mocktail_rust_utf8_to_utf16_bounded(
                std::ptr::null(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                &mut out_len
            ),
            0
        );
        assert_eq!(out_len, 0);

        let large: String = "A😀Б".repeat(3000); // 21,000 bytes (> 16 KiB)
        let mut out = vec![0u16; large.len()];
        assert_eq!(
            mocktail_rust_utf8_to_utf16_bounded(
                large.as_ptr() as *const c_char,
                large.len(),
                0,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            0
        );
        let decoded = String::from_utf16(&out[..out_len]).unwrap();
        assert_eq!(decoded, large);

        let bad = [0x80u8, 0x81u8];
        assert_eq!(
            mocktail_rust_utf8_to_utf16_bounded(
                bad.as_ptr() as *const c_char,
                bad.len(),
                0,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            -2
        );
    }
}
