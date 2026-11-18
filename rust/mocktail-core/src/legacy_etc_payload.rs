use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::slice;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::*;

// ============================================================================
// 26. ETC1 / ETC2 / EAC Software Texture Decoder
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustEtcFormat {
    Etc2Rgb8 = 0,
    Etc2Rgb8A1 = 1,
    Etc2Rgba8 = 2,
    EacR11 = 3,
    EacR11Signed = 4,
    EacRg11 = 5,
    EacRg11Signed = 6,
}

static ETC_DISTANCE: [i32; 8] = [3, 6, 11, 16, 23, 32, 41, 64];

static ETC1_MODIFIERS: [[i32; 4]; 8] = [
    [2, 8, -2, -8],     [5, 17, -5, -17],   [9, 29, -9, -29],
    [13, 42, -13, -42], [18, 60, -18, -60], [24, 80, -24, -80],
    [33, 106, -33, -106], [47, 183, -47, -183],
];

static EAC_MODIFIERS: [[i32; 8]; 16] = [
    [-3, -6, -9, -15, 2, 5, 8, 14],  [-3, -7, -10, -13, 2, 6, 9, 12],
    [-2, -5, -8, -13, 1, 4, 7, 12],  [-2, -4, -6, -13, 1, 3, 5, 12],
    [-3, -6, -8, -12, 2, 5, 7, 11],  [-3, -7, -9, -11, 2, 6, 8, 10],
    [-4, -7, -8, -11, 3, 6, 7, 10],  [-3, -5, -8, -11, 2, 4, 7, 10],
    [-2, -6, -8, -10, 1, 5, 7, 9],   [-2, -5, -8, -10, 1, 4, 7, 9],
    [-2, -4, -8, -10, 1, 3, 7, 9],   [-2, -5, -7, -10, 1, 4, 6, 9],
    [-3, -4, -7, -10, 2, 3, 6, 9],   [-1, -2, -3, -10, 0, 1, 2, 9],
    [-4, -6, -8, -9, 3, 5, 7, 8],    [-3, -5, -7, -9, 2, 4, 6, 8],
];

#[inline]
fn clamp255(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

#[inline]
fn expand4(v: i32) -> i32 { (v << 4) | v }
#[inline]
fn expand5(v: i32) -> i32 { (v << 3) | (v >> 2) }
#[inline]
fn expand6(v: i32) -> i32 { (v << 2) | (v >> 4) }
#[inline]
fn expand7(v: i32) -> i32 { (v << 1) | (v >> 6) }

fn decode_rgb_block(b: &[u8], punchthrough: bool, out: &mut [u8; 64]) {
    const K_DELTA: [i32; 8] = [0, 1, 2, 3, -4, -3, -2, -1];
    let diff_or_opaque = (b[3] & 2) != 0;
    let opaque = !punchthrough || diff_or_opaque;
    let msb = ((b[4] as i32) << 8) | (b[5] as i32);
    let lsb = ((b[6] as i32) << 8) | (b[7] as i32);

    let index_of = |texel: usize| -> usize {
        (((msb >> texel) & 1) << 1 | ((lsb >> texel) & 1)) as usize
    };

    let r_sum = ((b[0] >> 3) as i32) + K_DELTA[(b[0] & 7) as usize];
    let g_sum = ((b[1] >> 3) as i32) + K_DELTA[(b[1] & 7) as usize];
    let b_sum = ((b[2] >> 3) as i32) + K_DELTA[(b[2] & 7) as usize];
    let individual = !punchthrough && !diff_or_opaque;

    if !individual && (r_sum < 0 || r_sum > 31 || g_sum < 0 || g_sum > 31) {
        let mut paint = [[0i32; 3]; 4];
        if r_sum < 0 || r_sum > 31 {
            let c1 = [
                expand4(((((b[0] >> 3) & 3) << 2) | (b[0] & 3)) as i32),
                expand4((b[1] >> 4) as i32),
                expand4((b[1] & 15) as i32),
            ];
            let c2 = [
                expand4((b[2] >> 4) as i32),
                expand4((b[2] & 15) as i32),
                expand4((b[3] >> 4) as i32),
            ];
            let d = ETC_DISTANCE[((((b[3] >> 2) & 3) << 1) | (b[3] & 1)) as usize];
            for c in 0..3 {
                paint[0][c] = c1[c];
                paint[1][c] = c2[c] + d;
                paint[2][c] = c2[c];
                paint[3][c] = c2[c] - d;
            }
        } else {
            let c1 = [
                expand4(((b[0] >> 3) & 15) as i32),
                expand4((((b[0] & 7) << 1) | ((b[1] >> 4) & 1)) as i32),
                expand4(((b[1] & 8) | ((b[1] & 3) << 1) | (b[2] >> 7)) as i32),
            ];
            let c2 = [
                expand4(((b[2] >> 3) & 15) as i32),
                expand4((((b[2] & 7) << 1) | (b[3] >> 7)) as i32),
                expand4(((b[3] >> 3) & 15) as i32),
            ];
            let v1 = (c1[0] << 16) | (c1[1] << 8) | c1[2];
            let v2 = (c2[0] << 16) | (c2[1] << 8) | c2[2];
            let d = ETC_DISTANCE[((b[3] & 4) | ((b[3] & 1) << 1) | (if v1 >= v2 { 1 } else { 0 })) as usize];
            for c in 0..3 {
                paint[0][c] = c1[c] + d;
                paint[1][c] = c1[c] - d;
                paint[2][c] = c2[c] + d;
                paint[3][c] = c2[c] - d;
            }
        }
        for texel in 0..16 {
            let idx = index_of(texel);
            let o = texel * 4;
            if !opaque && idx == 2 {
                out[o] = 0; out[o + 1] = 0; out[o + 2] = 0; out[o + 3] = 0;
            } else {
                out[o] = clamp255(paint[idx][0]);
                out[o + 1] = clamp255(paint[idx][1]);
                out[o + 2] = clamp255(paint[idx][2]);
                out[o + 3] = 255;
            }
        }
        return;
    }

    if !individual && (b_sum < 0 || b_sum > 31) {
        let ro = expand6(((b[0] >> 1) & 63) as i32);
        let go = expand7((((b[0] & 1) << 6) | ((b[1] >> 1) & 63)) as i32);
        let bo = expand6((((b[1] & 1) << 5) | (b[2] & 0x18) | ((b[2] & 3) << 1) | (b[3] >> 7)) as i32);
        let rh = expand6((((b[3] & 0x7c) >> 1) | (b[3] & 1)) as i32);
        let gh = expand7((b[4] >> 1) as i32);
        let bh = expand6((((b[4] & 1) << 5) | (b[5] >> 3)) as i32);
        let rv = expand6((((b[5] & 7) << 3) | (b[6] >> 5)) as i32);
        let gv = expand7((((b[6] & 31) << 2) | (b[7] >> 6)) as i32);
        let bv = expand6((b[7] & 63) as i32);
        for x in 0..4i32 {
            for y in 0..4i32 {
                let o = ((x * 4 + y) * 4) as usize;
                out[o] = clamp255((x * (rh - ro) + y * (rv - ro) + 4 * ro + 2) >> 2);
                out[o + 1] = clamp255((x * (gh - go) + y * (gv - go) + 4 * go + 2) >> 2);
                out[o + 2] = clamp255((x * (bh - bo) + y * (bv - bo) + 4 * bo + 2) >> 2);
                out[o + 3] = 255;
            }
        }
        return;
    }

    let mut base = [[0i32; 3]; 2];
    for c in 0..3 {
        if individual {
            base[0][c] = expand4((b[c] >> 4) as i32);
            base[1][c] = expand4((b[c] & 15) as i32);
        } else {
            base[0][c] = expand5((b[c] >> 3) as i32);
            base[1][c] = expand5(((b[c] >> 3) as i32) + K_DELTA[(b[c] & 7) as usize]);
        }
    }
    let tables = [(b[3] >> 5) as usize, ((b[3] >> 2) & 7) as usize];
    let flipped = (b[3] & 1) != 0;
    for x in 0..4 {
        for y in 0..4 {
            let texel = x * 4 + y;
            let idx = index_of(texel);
            let o = texel * 4;
            if !opaque && idx == 2 {
                out[o] = 0; out[o + 1] = 0; out[o + 2] = 0; out[o + 3] = 0;
                continue;
            }
            let sub = if flipped { if y >= 2 { 1 } else { 0 } } else { if x >= 2 { 1 } else { 0 } };
            let modifier = if !opaque && idx == 0 { 0 } else { ETC1_MODIFIERS[tables[sub]][idx] };
            out[o] = clamp255(base[sub][0] + modifier);
            out[o + 1] = clamp255(base[sub][1] + modifier);
            out[o + 2] = clamp255(base[sub][2] + modifier);
            out[o + 3] = 255;
        }
    }
}

#[inline]
fn eac_index(b: &[u8], texel: usize) -> usize {
    let mut bits = 0u64;
    for i in 2..8 {
        bits = (bits << 8) | (b[i] as u64);
    }
    ((bits >> (45 - texel * 3)) & 7) as usize
}

#[inline]
fn eac_modifier(b: &[u8], texel: usize) -> i32 {
    EAC_MODIFIERS[(b[1] & 15) as usize][eac_index(b, texel)]
}

fn decode_r11(b: &[u8], texel: usize, is_signed: bool) -> u16 {
    let multiplier = (b[1] >> 4) as i32;
    let modifier = eac_modifier(b, texel);
    let scaled = if multiplier != 0 { modifier * multiplier * 8 } else { modifier };
    if !is_signed {
        let value = ((b[0] as i32) * 8 + 4 + scaled).clamp(0, 2047);
        ((value << 5) | (value >> 6)) as u16
    } else {
        let base = std::cmp::max(-127, (b[0] as i8) as i32);
        let value = (base * 8 + scaled).clamp(-1023, 1023);
        let magnitude = value.abs();
        let expanded = (magnitude << 5) | (magnitude >> 5);
        (if value < 0 { -expanded } else { expanded }) as i16 as u16
    }
}

fn etc_block_bytes(format: MocktailRustEtcFormat) -> usize {
    match format {
        MocktailRustEtcFormat::Etc2Rgba8
        | MocktailRustEtcFormat::EacRg11
        | MocktailRustEtcFormat::EacRg11Signed => 16,
        _ => 8,
    }
}

fn etc_decoded_texel_bytes(format: MocktailRustEtcFormat) -> usize {
    match format {
        MocktailRustEtcFormat::EacR11 | MocktailRustEtcFormat::EacR11Signed => 2,
        _ => 4,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_decode_etc_image_block_rows(
    format: MocktailRustEtcFormat,
    source: *const u8,
    source_bytes: usize,
    width: u32,
    height: u32,
    first_block_row: u32,
    block_row_count: u32,
    destination: *mut u8,
    destination_bytes: usize,
) -> c_int {
    if source.is_null() || destination.is_null() || width == 0 || height == 0 {
        return 0;
    }
    let blocks_wide = ((width as u64) + 3) / 4;
    let blocks_high = ((height as u64) + 3) / 4;
    let block_bytes = etc_block_bytes(format);
    let texel_bytes = etc_decoded_texel_bytes(format);

    let required_source_bytes = blocks_wide
        .checked_mul(blocks_high)
        .and_then(|blocks| blocks.checked_mul(block_bytes as u64));
    match required_source_bytes {
        Some(bytes) if bytes <= (source_bytes as u64) => {}
        _ => return 0,
    }
    let required_dest_bytes = (width as u64)
        .checked_mul(height as u64)
        .and_then(|pixels| pixels.checked_mul(texel_bytes as u64));
    match required_dest_bytes {
        Some(bytes) if bytes <= (destination_bytes as u64) => {}
        _ => return 0,
    }
    let end_block_row = match (first_block_row as u64).checked_add(block_row_count as u64) {
        Some(end) if end <= blocks_high => end as u32,
        _ => return 0,
    };

    let src_slice = unsafe { slice::from_raw_parts(source, source_bytes) };
    let dst_slice = unsafe { slice::from_raw_parts_mut(destination, destination_bytes) };

    let mut rgba = [0u8; 64];

    for by in first_block_row..end_block_row {
        for bx in 0..blocks_wide as u32 {
            let block_offset = ((by as usize) * (blocks_wide as usize) + (bx as usize)) * block_bytes;
            let block = &src_slice[block_offset..block_offset + block_bytes];

            match format {
                MocktailRustEtcFormat::Etc2Rgb8 => decode_rgb_block(block, false, &mut rgba),
                MocktailRustEtcFormat::Etc2Rgb8A1 => decode_rgb_block(block, true, &mut rgba),
                MocktailRustEtcFormat::Etc2Rgba8 => decode_rgb_block(&block[8..16], false, &mut rgba),
                _ => {}
            }

            for y in 0..4u32 {
                let py = (by as u64) * 4 + (y as u64);
                if py >= (height as u64) {
                    continue;
                }
                for x in 0..4u32 {
                    let px = (bx as u64) * 4 + (x as u64);
                    if px >= (width as u64) {
                        continue;
                    }
                    let texel = (x * 4 + y) as usize;
                    let out_offset = ((py as usize) * (width as usize) + (px as usize)) * texel_bytes;
                    match format {
                        MocktailRustEtcFormat::Etc2Rgb8 | MocktailRustEtcFormat::Etc2Rgb8A1 | MocktailRustEtcFormat::Etc2Rgba8 => {
                            dst_slice[out_offset..out_offset + 4].copy_from_slice(&rgba[texel * 4..texel * 4 + 4]);
                            if format == MocktailRustEtcFormat::Etc2Rgba8 {
                                let alpha = (block[0] as i32) + eac_modifier(block, texel) * ((block[1] >> 4) as i32);
                                dst_slice[out_offset + 3] = clamp255(alpha);
                            }
                        }
                        MocktailRustEtcFormat::EacR11 | MocktailRustEtcFormat::EacR11Signed
                        | MocktailRustEtcFormat::EacRg11 | MocktailRustEtcFormat::EacRg11Signed => {
                            let is_signed = format == MocktailRustEtcFormat::EacR11Signed || format == MocktailRustEtcFormat::EacRg11Signed;
                            let channels = texel_bytes / 2;
                            for channel in 0..channels {
                                let val = decode_r11(&block[channel * 8..(channel + 1) * 8], texel, is_signed);
                                dst_slice[out_offset + channel * 2] = val as u8;
                                dst_slice[out_offset + channel * 2 + 1] = (val >> 8) as u8;
                            }
                        }
                    }
                }
            }
        }
    }
    1
}


// ============================================================================
// 27. ZIP Archive Manager
// ============================================================================

pub(crate) fn is_safe_archive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes[0] == b'/' {
        return false;
    }
    for &b in bytes {
        if b < 0x20 || b == 0x7f || b == b'\\' {
            return false;
        }
    }
    let mut parts = bytes.split(|&b| b == b'/');
    let mut is_first = true;
    while let Some(part) = parts.next() {
        if part.is_empty() {
            if parts.clone().next().is_none() && !is_first {
                return true;
            }
            return false;
        }
        if part == b"." || part == b".." {
            return false;
        }
        is_first = false;
    }
    true
}

#[derive(Serialize, Deserialize)]
pub struct MocktailRustZipEntryInfo {
    pub name: String,
    pub uncompressed_size: u64,
    pub directory: bool,
    pub symbolic_link: bool,
}

fn open_regular_zip(path: &Path, err_code: c_int) -> Result<File, (c_int, String)> {
    use std::os::unix::fs::OpenOptionsExt;
    let not_regular = || {
        (
            err_code,
            format!("ZIP archive is not a regular file: {}", path.display()),
        )
    };
    if !std::fs::symlink_metadata(path).map(|m| m.file_type().is_file()).unwrap_or(false) {
        return Err(not_regular());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| not_regular())?;
    if !file.metadata().map(|m| m.file_type().is_file()).unwrap_or(false) {
        return Err(not_regular());
    }
    Ok(file)
}

pub(crate) fn zip_list_entries_path(
    path: &Path,
    max_entries: usize,
) -> Result<Vec<MocktailRustZipEntryInfo>, (c_int, String)> {
    let file = open_regular_zip(path, -3)?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| (-4, format!("cannot parse ZIP archive: {}", e)))?;
    if zip.len() > max_entries {
        return Err((-5, "ZIP archive has an invalid or excessive entry count".to_string()));
    }
    let mut entries = Vec::with_capacity(zip.len());
    for i in 0..zip.len() {
        let entry = zip
            .by_index(i)
            .map_err(|e| (-6, format!("cannot read ZIP entry metadata: {}", e)))?;
        let name = entry.name().to_string();
        if !is_safe_archive_path(&name) {
            return Err((-7, "ZIP entry path is unsafe".to_string()));
        }
        let uncompressed_size = entry.size();
        let directory = entry.is_dir() || name.ends_with('/');
        let mode = entry.unix_mode().unwrap_or(0);
        let symbolic_link = (mode & 0o170000) == 0o120000;
        entries.push(MocktailRustZipEntryInfo {
            name,
            uncompressed_size,
            directory,
            symbolic_link,
        });
    }
    Ok(entries)
}

pub(crate) fn zip_list_entries_internal(
    path: &str,
    max_entries: usize,
) -> Result<Vec<MocktailRustZipEntryInfo>, (c_int, String)> {
    zip_list_entries_path(Path::new(path), max_entries)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_zip_list_entries(
    archive_path: *const c_char,
    max_entries: usize,
    out_json: *mut c_char,
    json_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if archive_path.is_null() || out_json.is_null() || json_cap == 0 {
        set_err("invalid arguments");
        return -1;
    }
    let path = match unsafe { CStr::from_ptr(archive_path) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid archive path encoding");
            return -2;
        }
    };
    let entries = match zip_list_entries_internal(path, max_entries) {
        Ok(e) => e,
        Err((code, msg)) => {
            set_err(&msg);
            return code;
        }
    };
    let serialized = match serde_json::to_string(&entries) {
        Ok(s) => s,
        Err(e) => {
            set_err(&format!("JSON serialization error: {}", e));
            return -8;
        }
    };
    if serialized.len() >= json_cap {
        set_err("JSON output buffer too small");
        return -9;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(serialized.as_ptr() as *const c_char, out_json, serialized.len());
        *out_json.add(serialized.len()) = 0;
    }
    0
}

pub(crate) fn zip_read_entry_bytes(
    archive_path: &Path,
    target_name: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, (c_int, String)> {
    let file = open_regular_zip(archive_path, -4)?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| (-5, format!("cannot parse ZIP archive: {}", e)))?;
    let mut entry = zip
        .by_name(target_name)
        .map_err(|_| (-6, format!("ZIP entry is missing: {}", target_name)))?;
    if entry.size() > max_bytes as u64 {
        return Err((-7, "decompressed ZIP data exceeds its size limit".to_string()));
    }
    let mut out = Vec::with_capacity((entry.size() as usize).min(max_bytes));
    let mut chunk = [0u8; 16384];
    loop {
        match entry.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if out.len().saturating_add(n) > max_bytes {
                    return Err((-8, "decompressed ZIP data exceeds its size limit".to_string()));
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err((-9, format!("cannot decompress ZIP entry: {}", e))),
        }
    }
    Ok(out)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_zip_read_entry(
    archive_path: *const c_char,
    entry_name: *const c_char,
    max_bytes: usize,
    out_buf: *mut u8,
    buf_cap: usize,
    out_read_len: *mut usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if archive_path.is_null() || entry_name.is_null() || out_buf.is_null() || out_read_len.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    let path = match unsafe { CStr::from_ptr(archive_path) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid archive path encoding");
            return -2;
        }
    };
    let target_name = match unsafe { CStr::from_ptr(entry_name) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid entry name encoding");
            return -3;
        }
    };
    let bytes = match zip_read_entry_bytes(Path::new(path), target_name, max_bytes.min(buf_cap)) {
        Ok(b) => b,
        Err((code, msg)) => {
            set_err(&msg);
            return code;
        }
    };
    unsafe {
        if !bytes.is_empty() {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        }
        *out_read_len = bytes.len();
    }
    0
}

pub(crate) fn zip_extract_entry_file(
    archive_path: &Path,
    target_name: &str,
    dest: &Path,
    max_bytes: usize,
) -> Result<(), (c_int, String)> {
    let file = open_regular_zip(archive_path, -5)?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| (-6, format!("cannot parse ZIP archive: {}", e)))?;
    let mut entry = zip
        .by_name(target_name)
        .map_err(|_| (-7, format!("ZIP entry is missing: {}", target_name)))?;
    if entry.size() > max_bytes as u64 {
        return Err((-8, "decompressed ZIP data exceeds its size limit".to_string()));
    }
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| (-9, format!("cannot create directory: {}", e)))?;
    let tmp_path = parent.join(format!(
        ".tmp_extract_{}_{}",
        std::process::id(),
        target_name.replace('/', "_")
    ));
    let mut out_file = std::fs::File::create(&tmp_path)
        .map_err(|e| (-10, format!("cannot create temporary file: {}", e)))?;
    let mut total_written = 0usize;
    let mut buffer = [0u8; 16384];
    loop {
        match entry.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total_written += n;
                if total_written > max_bytes {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err((-11, "decompressed ZIP data exceeds its size limit".to_string()));
                }
                if let Err(e) = out_file.write_all(&buffer[..n]) {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err((-12, format!("cannot write temporary file: {}", e)));
                }
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err((-13, format!("cannot decompress ZIP entry: {}", e)));
            }
        }
    }
    if let Err(e) = out_file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err((-14, format!("cannot sync file: {}", e)));
    }
    drop(out_file);
    if let Err(e) = std::fs::rename(&tmp_path, dest) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err((-15, format!("cannot rename to destination: {}", e)));
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_zip_extract_entry(
    archive_path: *const c_char,
    entry_name: *const c_char,
    dest_path: *const c_char,
    max_bytes: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if archive_path.is_null() || entry_name.is_null() || dest_path.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    let path = match unsafe { CStr::from_ptr(archive_path) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid archive path encoding");
            return -2;
        }
    };
    let target_name = match unsafe { CStr::from_ptr(entry_name) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid entry name encoding");
            return -3;
        }
    };
    let dest = match unsafe { CStr::from_ptr(dest_path) }.to_str() {
        Ok(p) => Path::new(p),
        Err(_) => {
            set_err("invalid dest path encoding");
            return -4;
        }
    };
    if let Err((code, msg)) = zip_extract_entry_file(Path::new(path), target_name, dest, max_bytes) {
        set_err(&msg);
        return code;
    }
    0
}

pub(crate) fn zip_extract_prefix_dir(
    archive_path: &Path,
    pref: &str,
    dest_base: &Path,
    max_total_bytes: usize,
) -> Result<usize, (c_int, String)> {
    let file = open_regular_zip(archive_path, -5)?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| (-6, format!("cannot parse ZIP archive: {}", e)))?;
    let mut total_bytes = 0usize;
    let mut count = 0usize;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| (-7, format!("cannot read ZIP entry: {}", e)))?;
        let name = entry.name().to_string();
        if !name.starts_with(pref) {
            continue;
        }
        let rel_name = &name[pref.len()..];
        if rel_name.is_empty() {
            continue;
        }
        if !is_safe_archive_path(rel_name) {
            return Err((-8, format!("unsafe entry path in prefix extract: {}", rel_name)));
        }
        let target_path = dest_base.join(rel_name);
        if entry.is_dir() || rel_name.ends_with('/') {
            std::fs::create_dir_all(&target_path)
                .map_err(|e| (-9, format!("cannot create directory {}: {}", target_path.display(), e)))?;
            continue;
        }
        if let Some(p) = target_path.parent() {
            std::fs::create_dir_all(p)
                .map_err(|e| (-10, format!("cannot create parent directory {}: {}", p.display(), e)))?;
        }
        let mut out = std::fs::File::create(&target_path)
            .map_err(|e| (-11, format!("cannot create file {}: {}", target_path.display(), e)))?;
        let mut buf = [0u8; 16384];
        loop {
            match entry.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n;
                    if total_bytes > max_total_bytes {
                        return Err((-12, "total extracted size exceeded limit".to_string()));
                    }
                    out.write_all(&buf[..n])
                        .map_err(|e| (-13, format!("cannot write file {}: {}", target_path.display(), e)))?;
                }
                Err(e) => return Err((-14, format!("cannot read entry {}: {}", name, e))),
            }
        }
        count += 1;
    }
    Ok(count)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_zip_extract_prefix(
    archive_path: *const c_char,
    prefix: *const c_char,
    dest_dir: *const c_char,
    max_total_bytes: usize,
    out_extracted_count: *mut usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if archive_path.is_null() || prefix.is_null() || dest_dir.is_null() || out_extracted_count.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    let arc_p = match unsafe { CStr::from_ptr(archive_path) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid archive path encoding");
            return -2;
        }
    };
    let pref = match unsafe { CStr::from_ptr(prefix) }.to_str() {
        Ok(p) => p,
        Err(_) => {
            set_err("invalid prefix encoding");
            return -3;
        }
    };
    let dest_base = match unsafe { CStr::from_ptr(dest_dir) }.to_str() {
        Ok(p) => Path::new(p),
        Err(_) => {
            set_err("invalid dest directory encoding");
            return -4;
        }
    };
    match zip_extract_prefix_dir(Path::new(arc_p), pref, dest_base, max_total_bytes) {
        Ok(count) => {
            unsafe {
                *out_extracted_count = count;
            }
            0
        }
        Err((code, msg)) => {
            set_err(&msg);
            code
        }
    }
}

// ============================================================================
// 28. Payload Integrity & Asset Tree
// ============================================================================

fn walk_asset_tree(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(err) => return Err(format!("cannot read directory {}: {}", current.display(), err)),
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => return Err(format!("error reading directory entry: {}", err)),
        };
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(err) => return Err(format!("error inspecting file type: {}", err)),
        };
        if file_type.is_symlink() {
            return Err("asset tree contains a symbolic link".to_string());
        }
        if file_type.is_dir() {
            walk_asset_tree(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            if let Ok(rel) = entry.path().strip_prefix(root) {
                files.push(rel.to_path_buf());
            }
        } else {
            return Err("asset tree contains a non-regular entry".to_string());
        }
    }
    Ok(())
}

pub(crate) fn sha256_regular_file_strict(
    path: &Path,
    display_label: Option<&str>,
) -> Result<String, String> {
    let label = display_label
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string());
    let Some(cpath) = unix_ipc::path_to_cstr(path) else {
        return Err(format!("cannot open regular file: {}", label));
    };
    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let Some(fd) = unix_ipc::OwnedFd::from_raw(raw_fd) else {
        return Err(format!("cannot open regular file: {}", label));
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw(), &mut st) } != 0
        || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
    {
        return Err(format!("cannot open regular file: {}", label));
    }
    use std::os::unix::io::FromRawFd;
    let mut file = unsafe { File::from_raw_fd(fd.release()) };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return Err(format!("cannot read regular file: {}", label)),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn hash_asset_tree_dir(root_path: &Path) -> Result<(String, usize), (c_int, String)> {
    let sym_meta = std::fs::symlink_metadata(root_path)
        .map_err(|_| (-3, "asset root is not a real directory".to_string()))?;
    if sym_meta.file_type().is_symlink() || !sym_meta.is_dir() {
        return Err((-4, "asset root is not a real directory".to_string()));
    }

    let mut files = Vec::new();
    walk_asset_tree(root_path, root_path, &mut files).map_err(|e| (-5, e))?;

    files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    let mut tree_hasher = Sha256::new();

    for rel_path in &files {
        let full_path = root_path.join(rel_path);
        let mut file = File::open(&full_path)
            .map_err(|_| (-6, format!("cannot open file {}", full_path.display())))?;
        let mut file_hasher = Sha256::new();
        let mut buf = [0u8; 16384];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => file_hasher.update(&buf[..n]),
                Err(_) => return Err((-7, format!("cannot read file {}", full_path.display()))),
            }
        }
        let file_sha = hex::encode(file_hasher.finalize());
        let rel_unix_str = rel_path.to_string_lossy().replace('\\', "/");
        tree_hasher.update(file_sha.as_bytes());
        tree_hasher.update(b"  ");
        tree_hasher.update(rel_unix_str.as_bytes());
        tree_hasher.update(&[0u8]);
    }

    Ok((hex::encode(tree_hasher.finalize()), files.len()))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_hash_asset_tree(
    root_dir: *const c_char,
    out_hex: *mut c_char,
    hex_cap: usize,
    out_file_count: *mut usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if root_dir.is_null() || out_hex.is_null() || hex_cap < 65 {
        set_err("invalid arguments");
        return -1;
    }
    let root_str = match unsafe { CStr::from_ptr(root_dir) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid root directory encoding");
            return -2;
        }
    };
    match hash_asset_tree_dir(Path::new(root_str)) {
        Ok((final_hex, count)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    final_hex.as_ptr() as *const c_char,
                    out_hex,
                    final_hex.len(),
                );
                *out_hex.add(final_hex.len()) = 0;
                if !out_file_count.is_null() {
                    *out_file_count = count;
                }
            }
            0
        }
        Err((code, msg)) => {
            set_err(&msg);
            code
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MocktailRustPayloadInfo {
    pub package_name: String,
    pub version_name: String,
    pub version_code: u64,
    pub build_id: String,
    pub library_sha256: String,
    pub base_apk_sha256: String,
    pub split_apk_sha256: String,
    pub asset_file_count: usize,
    pub asset_tree_sha256: String,
    pub payload_id: String,
}

pub(crate) fn internal_inspect_payload(dir: &Path) -> Result<MocktailRustPayloadInfo, String> {
    let sym = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(_) => return Err("payload root is not a real directory".to_string()),
    };
    if sym.file_type().is_symlink() || !sym.is_dir() {
        return Err("payload root is not a real directory".to_string());
    }

    let split_apk_rel = if dir.join("sober_apk/split_config.arm64_v8a.apk").exists() {
        "sober_apk/split_config.arm64_v8a.apk"
    } else if cfg!(target_arch = "aarch64") {
        "sober_apk/split_config.arm64_v8a.apk"
    } else {
        "sober_apk/split_config.x86_64.apk"
    };
    let required_files = [
        "libroblox.so",
        "sober_apk/base.apk",
        split_apk_rel,
        "roblox_payload.json",
    ];
    for f in required_files {
        let p = dir.join(f);
        let m = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => return Err(format!("payload is missing regular file: {}", f)),
        };
        if m.file_type().is_symlink() || !m.is_file() {
            return Err(format!("payload is missing regular file: {}", f));
        }
    }

    let required_dirs = ["assets", "assets/content"];
    for d in required_dirs {
        let p = dir.join(d);
        let m = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => return Err(format!("payload is missing real directory: {}", d)),
        };
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(format!("payload is missing real directory: {}", d));
        }
    }

    let manifest_path = dir.join("roblox_payload.json");
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(_) => return Err("cannot read payload metadata".to_string()),
    };
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Err("payload metadata schema is invalid".to_string()),
    };
    if !doc.is_object() || doc.get("schema_version").and_then(|v| v.as_i64()) != Some(1) {
        return Err("payload metadata schema is invalid".to_string());
    }

    let package = doc.get("package").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let version_name = doc.get("version_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let version_code = match doc.get("version_code").and_then(|v| v.as_u64()) {
        Some(c) => c,
        None => return Err("payload metadata schema is invalid".to_string()),
    };
    let build_id = doc.get("elf_build_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let sha_obj = match doc.get("sha256").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Err("payload metadata schema is invalid".to_string()),
    };
    let library_sha256 = sha_obj.get("libroblox").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let base_apk_sha256 = sha_obj.get("base_apk").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let split_hash_key = if cfg!(target_arch = "aarch64") {
        "arm64_v8a_split_apk"
    } else {
        "x86_64_split_apk"
    };
    let split_apk_sha256 = sha_obj
        .get(split_hash_key)
        .or_else(|| sha_obj.get("x86_64_split_apk"))
        .or_else(|| sha_obj.get("arm64_v8a_split_apk"))
        .or_else(|| sha_obj.get("split_config_x86_64"))
        .or_else(|| sha_obj.get("split_apk"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let assets_obj = match doc.get("assets").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Err("payload metadata schema is invalid".to_string()),
    };
    let asset_file_count = match assets_obj.get("file_count").and_then(|v| v.as_u64()) {
        Some(c) => c as usize,
        None => return Err("payload metadata asset count is invalid".to_string()),
    };
    let asset_tree_sha256 = assets_obj.get("sha256_tree").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let is_lower_hex = |s: &str, expected_len: usize| {
        s.len() == expected_len && s.chars().all(|c| c.is_ascii_digit() || (c >= 'a' && c <= 'f'))
    };

    if package != "com.roblox.client"
        || version_name.is_empty()
        || version_code == 0
        || !is_lower_hex(&build_id, 40)
        || !is_lower_hex(&library_sha256, 64)
        || !is_lower_hex(&base_apk_sha256, 64)
        || !is_lower_hex(&split_apk_sha256, 64)
        || !is_lower_hex(&asset_tree_sha256, 64)
    {
        return Err("payload metadata identity or hashes are invalid".to_string());
    }

    let payload_id = format!("{}-{}", version_code, build_id);

    Ok(MocktailRustPayloadInfo {
        package_name: package,
        version_name,
        version_code,
        build_id,
        library_sha256,
        base_apk_sha256,
        split_apk_sha256,
        asset_file_count,
        asset_tree_sha256,
        payload_id,
    })
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_inspect(
    dir_path: *const c_char,
    out_json: *mut c_char,
    json_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if dir_path.is_null() || out_json.is_null() || json_cap == 0 {
        set_err("invalid arguments");
        return -1;
    }
    let p_str = match unsafe { CStr::from_ptr(dir_path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid directory path encoding");
            return -2;
        }
    };
    match internal_inspect_payload(Path::new(p_str)) {
        Ok(info) => {
            let json = serde_json::to_string(&info).unwrap_or_default();
            if json.len() >= json_cap {
                set_err("JSON output buffer too small");
                return -3;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(json.as_ptr() as *const c_char, out_json, json.len());
                *out_json.add(json.len()) = 0;
            }
            0
        }
        Err(e) => {
            set_err(&e);
            -4
        }
    }
}

pub(crate) fn verify_payload_internal(dir: &Path) -> Result<MocktailRustPayloadInfo, (c_int, String)> {
    let info = internal_inspect_payload(dir).map_err(|e| (-3, e))?;

    let check_file_sha = |rel: &str, expected: &str| -> Result<(), String> {
        let actual = sha256_regular_file_strict(&dir.join(rel), Some(rel))?;
        if actual != expected {
            return Err(format!("payload hash mismatch: {}", rel));
        }
        Ok(())
    };

    check_file_sha("libroblox.so", &info.library_sha256).map_err(|e| (-4, e))?;
    check_file_sha("sober_apk/base.apk", &info.base_apk_sha256).map_err(|e| (-5, e))?;
    let split_file = if dir.join("sober_apk/split_config.arm64_v8a.apk").exists() {
        "sober_apk/split_config.arm64_v8a.apk"
    } else if cfg!(target_arch = "aarch64") {
        "sober_apk/split_config.arm64_v8a.apk"
    } else {
        "sober_apk/split_config.x86_64.apk"
    };
    check_file_sha(split_file, &info.split_apk_sha256).map_err(|e| (-6, e))?;

    let (actual_tree_hex, actual_count) =
        hash_asset_tree_dir(&dir.join("assets")).map_err(|(_, msg)| (-8, msg))?;
    if actual_count != info.asset_file_count || actual_tree_hex != info.asset_tree_sha256 {
        return Err((-9, "payload asset tree does not match metadata".to_string()));
    }
    Ok(info)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_verify(
    dir_path: *const c_char,
    out_json: *mut c_char,
    json_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if dir_path.is_null() || out_json.is_null() || json_cap == 0 {
        set_err("invalid arguments");
        return -1;
    }
    let p_str = match unsafe { CStr::from_ptr(dir_path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid directory path encoding");
            return -2;
        }
    };
    let info = match verify_payload_internal(Path::new(p_str)) {
        Ok(i) => i,
        Err((code, msg)) => {
            set_err(&msg);
            return code;
        }
    };

    let json = serde_json::to_string(&info).unwrap_or_default();
    if json.len() >= json_cap {
        set_err("JSON output buffer too small");
        return -10;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr() as *const c_char, out_json, json.len());
        *out_json.add(json.len()) = 0;
    }
    0
}

// ============================================================================
// 29. FFlag & ClientAppSettings Merger
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_fflags_load_and_merge(
    file_path: *const c_char,
    base_json: *const c_char,
    out_json: *mut c_char,
    json_cap: usize,
    out_count: *mut usize,
    out_loaded: *mut c_int,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if out_json.is_null() || json_cap == 0 {
        set_err("invalid arguments");
        return -1;
    }

    let mut merged: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    if !base_json.is_null() {
        let b_str = match unsafe { CStr::from_ptr(base_json) }.to_str() {
            Ok(s) => s.trim(),
            Err(_) => {
                set_err("invalid base json encoding");
                return -2;
            }
        };
        if !b_str.is_empty() {
            match serde_json::from_str::<serde_json::Value>(b_str) {
                Ok(serde_json::Value::Object(m)) => {
                    merged = m;
                }
                _ => {
                    set_err("base client-settings overrides must be a JSON object");
                    return -3;
                }
            }
        }
    }

    let mut loaded = 0;
    let mut added_count = 0;

    if !file_path.is_null() {
        let p_str = match unsafe { CStr::from_ptr(file_path) }.to_str() {
            Ok(s) => s.trim(),
            Err(_) => {
                set_err("invalid file path encoding");
                return -4;
            }
        };
        if !p_str.is_empty() {
            let path = Path::new(p_str);
            match std::fs::symlink_metadata(path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.is_file() {
                        set_err("fflags file is not a regular file");
                        return -5;
                    }
                    if meta.len() > 1024 * 1024 {
                        set_err("fflags file exceeds 1 MiB limit");
                        return -6;
                    }
                    let content = match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            set_err(&format!("cannot read fflags file: {}", e));
                            return -7;
                        }
                    };
                    let file_obj = match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(serde_json::Value::Object(o)) => o,
                        _ => {
                            set_err("fflags file must contain a JSON object");
                            return -8;
                        }
                    };

                    for (k, v) in &file_obj {
                        if k.is_empty() {
                            set_err("fflags file contains an invalid key");
                            return -9;
                        }
                        if !v.is_string() && !v.is_boolean() && !v.is_number() {
                            set_err("fflags file values must be strings, booleans, or integers");
                            return -10;
                        }
                    }

                    for (k, v) in file_obj {
                        if !merged.contains_key(&k) {
                            let norm_val = match v {
                                serde_json::Value::Bool(b) => serde_json::Value::String(if b { "True".to_string() } else { "False".to_string() }),
                                serde_json::Value::Number(n) => serde_json::Value::String(n.to_string()),
                                serde_json::Value::String(s) => serde_json::Value::String(s),
                                _ => serde_json::Value::String(String::new()),
                            };
                            merged.insert(k, norm_val);
                            added_count += 1;
                        }
                    }
                    loaded = 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // File does not exist: valid, loaded = 0
                }
                Err(_) => {
                    set_err("cannot safely open fflags file");
                    return -11;
                }
            }
        }
    }

    let out_serialized = serde_json::to_string(&serde_json::Value::Object(merged)).unwrap_or_else(|_| "{}".to_string());
    if out_serialized.len() >= json_cap {
        set_err("JSON output buffer too small");
        return -12;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(out_serialized.as_ptr() as *const c_char, out_json, out_serialized.len());
        *out_json.add(out_serialized.len()) = 0;
        if !out_count.is_null() {
            *out_count = added_count;
        }
        if !out_loaded.is_null() {
            *out_loaded = loaded;
        }
    }
    0
}

// ============================================================================
// 30. APKPure Provider Parser
// ============================================================================

struct ApkPureVersionMarker {
    begin: usize,
    colon: usize,
    value: String,
}

fn apkpure_version_character(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'+' || c == b'_' || c == b'-'
}

fn apkpure_version_markers(metadata: &[u8]) -> Vec<ApkPureVersionMarker> {
    let mut markers = Vec::new();
    let mut index = 0;
    while index < metadata.len() {
        if !metadata[index].is_ascii_digit() || (index > 0 && apkpure_version_character(metadata[index - 1])) {
            index += 1;
            continue;
        }
        let mut end = index;
        let mut dot = false;
        while end < metadata.len() && apkpure_version_character(metadata[end]) {
            if metadata[end] == b'.' {
                dot = true;
            }
            end += 1;
        }
        if dot && end < metadata.len() && metadata[end] == b':' {
            if let Ok(val) = std::str::from_utf8(&metadata[index..end]) {
                markers.push(ApkPureVersionMarker {
                    begin: index,
                    colon: end,
                    value: val.to_string(),
                });
            }
            index = end;
        }
        index += 1;
    }
    markers
}

fn is_apkpure_url_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-@:%._+~#=?&/()".contains(&c)
}

fn apkpure_version_code(data: &[u8], marker: &ApkPureVersionMarker) -> u64 {
    let begin = marker.begin.saturating_sub(128);
    let mut position = marker.begin;
    while position > begin {
        position -= 1;
        if data[position] != 0x2a || position + 3 >= marker.begin {
            continue;
        }
        let code_len = data[position + 1] as usize;
        let code_begin = position + 2;
        let name_tag = code_begin + code_len;
        if code_len == 0 || code_len > 20 || name_tag + 2 != marker.begin {
            continue;
        }
        if data[name_tag] != 0x32 || data[name_tag + 1] as usize != marker.value.len() {
            continue;
        }
        let code_slice = &data[code_begin..name_tag];
        if code_slice.iter().all(|b| b.is_ascii_digit()) {
            if let Ok(text) = std::str::from_utf8(code_slice) {
                if let Ok(code) = text.parse::<u64>() {
                    return code;
                }
            }
        }
    }
    0
}

fn apkpure_downloads_in_record(record: &[u8]) -> Vec<String> {
    let allowed_hosts = ["pureapk.com", "apkpure.com", "winudf.com"];
    let mut downloads = Vec::new();
    let mut index = 0;
    while index < record.len() {
        let mut url_begin = None;
        if record[index..].starts_with(b"XAPKJ") && index + 7 < record.len() {
            url_begin = Some(index + 7);
        } else if record[index..].starts_with(b"APKJ") && index + 6 < record.len() {
            url_begin = Some(index + 6);
        }
        if let Some(begin) = url_begin {
            if record[begin..].starts_with(b"https://") {
                let mut url_end = begin;
                while url_end < record.len() && is_apkpure_url_char(record[url_end]) {
                    url_end += 1;
                }
                if let Ok(url_str) = std::str::from_utf8(&record[begin..url_end]) {
                    if let Ok(parsed) = url::Url::parse(url_str) {
                        if parsed.scheme() == "https"
                            && parsed.username().is_empty()
                            && parsed.password().is_none()
                            && parsed.port().map_or(true, |p| p == 443)
                        {
                            if let Some(host) = parsed.host_str() {
                                let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
                                let trusted = allowed_hosts.iter().any(|&h| {
                                    normalized_host == h
                                        || normalized_host.ends_with(&format!(".{}", h))
                                });
                                if trusted {
                                    downloads.push(url_str.to_string());
                                }
                            }
                        }
                    }
                }
                index = url_end;
                continue;
            }
        }
        index += 1;
    }
    downloads
}

pub(crate) fn apkpure_is_valid_version_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.bytes().all(apkpure_version_character)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_is_valid_version_name(
    name_ptr: *const c_char,
    name_len: usize,
) -> bool {
    if name_ptr.is_null() || name_len == 0 || name_len > 128 {
        return false;
    }
    let slice = unsafe { slice::from_raw_parts(name_ptr as *const u8, name_len) };
    std::str::from_utf8(slice).is_ok_and(apkpure_is_valid_version_name)
}

pub(crate) fn apkpure_has_zip_magic(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic).unwrap_or(0);
    n == 4
        && magic[0] == b'P'
        && magic[1] == b'K'
        && matches!(magic[2], 3 | 5 | 7)
        && matches!(magic[3], 4 | 6 | 8)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_has_zip_magic(path_ptr: *const c_char) -> bool {
    if path_ptr.is_null() {
        return false;
    }
    let path_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        _ => return false,
    };
    apkpure_has_zip_magic(Path::new(path_str))
}

pub(crate) fn apkpure_parse_latest_bytes(data: &[u8]) -> Result<(String, u64), &'static str> {
    if data.is_empty() {
        return Err("APKPure metadata contains no downloadable version identity");
    }
    let markers = apkpure_version_markers(data);
    let mut best_code: u64 = 0;
    let mut best_name = String::new();
    for (index, marker) in markers.iter().enumerate() {
        let code = apkpure_version_code(data, marker);
        let end = if index + 1 < markers.len() {
            markers[index + 1].begin
        } else {
            data.len()
        };
        let record_slice = &data[marker.colon + 1..end];
        if code > best_code && !apkpure_downloads_in_record(record_slice).is_empty() {
            best_code = code;
            best_name = marker.value.clone();
        }
    }
    if best_code == 0 || best_name.is_empty() {
        return Err("APKPure metadata contains no downloadable version identity");
    }
    Ok((best_name, best_code))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_parse_latest(
    metadata: *const u8,
    meta_len: usize,
    out_version_name: *mut c_char,
    ver_cap: usize,
    out_version_code: *mut u64,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if (metadata.is_null() && meta_len > 0) || out_version_name.is_null() || ver_cap == 0 || out_version_code.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    let data = if meta_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(metadata, meta_len) }
    };
    let (best_name, best_code) = match apkpure_parse_latest_bytes(data) {
        Ok(v) => v,
        Err(msg) => {
            set_err(msg);
            return -2;
        }
    };
    if best_name.len() >= ver_cap {
        set_err("version name buffer too small");
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(best_name.as_ptr() as *const c_char, out_version_name, best_name.len());
        *out_version_name.add(best_name.len()) = 0;
        *out_version_code = best_code;
    }
    0
}

pub(crate) fn apkpure_collect_exact_urls(
    data: &[u8],
    ver_target: &str,
    version_code: u64,
) -> Result<Vec<String>, (c_int, &'static str)> {
    if data.is_empty() {
        return Err((-3, "APKPure does not offer the requested exact version"));
    }
    let markers = apkpure_version_markers(data);
    let mut results = Vec::new();
    for i in 0..markers.len() {
        if markers[i].value != ver_target
            || (version_code != 0 && apkpure_version_code(data, &markers[i]) != version_code)
        {
            continue;
        }
        let record_end = if i + 1 < markers.len() { markers[i + 1].begin } else { data.len() };
        let record_slice = &data[markers[i].colon + 1..record_end];
        let downloads = apkpure_downloads_in_record(record_slice);
        if let Some(first) = downloads.first() {
            if !results.contains(first) {
                results.push(first.clone());
            }
        }
    }
    if results.is_empty() {
        return Err((-3, "APKPure does not offer the requested exact version"));
    }
    if results.len() > 4 {
        return Err((-4, "APKPure returned too many candidates"));
    }
    Ok(results)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_parse_exact_urls(
    metadata: *const u8,
    meta_len: usize,
    version: *const c_char,
    version_code: u64,
    out_urls_json: *mut c_char,
    json_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if (metadata.is_null() && meta_len > 0) || version.is_null() || out_urls_json.is_null() || json_cap == 0 {
        set_err("invalid arguments");
        return -1;
    }
    let ver_target = match unsafe { CStr::from_ptr(version) }.to_str() {
        Ok(v) => v,
        Err(_) => {
            set_err("invalid version encoding");
            return -2;
        }
    };
    let data = if meta_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(metadata, meta_len) }
    };
    let results = match apkpure_collect_exact_urls(data, ver_target, version_code) {
        Ok(r) => r,
        Err((code, msg)) => {
            set_err(msg);
            return code;
        }
    };
    let json = match serde_json::to_string(&results) {
        Ok(j) => j,
        Err(_) => {
            set_err("JSON serialization failed");
            return -5;
        }
    };
    if json.len() >= json_cap {
        set_err("JSON output buffer too small");
        return -6;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr() as *const c_char, out_urls_json, json.len());
        *out_urls_json.add(json.len()) = 0;
    }
    0
}

// ============================================================================
// 31. BrowserTracker & RBXEventTracker
// ============================================================================

pub(crate) fn is_valid_browser_id(val: &str) -> bool {
    !val.is_empty() && val.len() <= 20 && !val.starts_with('0') && val.chars().all(|c| c.is_ascii_digit())
}

pub(crate) fn generate_browser_tracker_id_string() -> String {
    // Read from /dev/urandom for crypto-secure random 64-bit uint > 0
    let mut rand_val: u64 = 0;
    let mut got_random = false;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut buf = [0u8; 8];
        if f.read_exact(&mut buf).is_ok() {
            rand_val = u64::from_ne_bytes(buf);
            got_random = true;
        }
    }
    if !got_random || rand_val == 0 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        rand_val = (now as u64) ^ 0x5bf03635467c4187;
        if rand_val == 0 {
            rand_val = 13374210987654321;
        }
    }
    rand_val.to_string()
}

pub(crate) fn extract_browser_id_from_tracker(tracker_cookie: &str) -> Option<String> {
    for field in tracker_cookie.split('&') {
        let field = field.trim();
        if let Some((k, v)) = field.split_once('=') {
            if k.trim() == "browserid" {
                let id = v.trim();
                if is_valid_browser_id(id) {
                    return Some(id.to_owned());
                }
            }
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_tracker_generate_id(
    out_id: *mut c_char,
    id_cap: usize,
) -> c_int {
    if out_id.is_null() || id_cap < 21 {
        return -1;
    }
    let id_str = generate_browser_tracker_id_string();
    unsafe {
        std::ptr::copy_nonoverlapping(id_str.as_ptr() as *const c_char, out_id, id_str.len());
        *out_id.add(id_str.len()) = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_tracker_extract_id(
    tracker_cookie: *const c_char,
    out_id: *mut c_char,
    id_cap: usize,
) -> c_int {
    if tracker_cookie.is_null() || out_id.is_null() || id_cap == 0 {
        return -1;
    }
    let cookie_str = match unsafe { CStr::from_ptr(tracker_cookie) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    if let Some(id) = extract_browser_id_from_tracker(cookie_str) {
        if id.len() >= id_cap {
            return -3;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(id.as_ptr() as *const c_char, out_id, id.len());
            *out_id.add(id.len()) = 0;
        }
        return 0;
    }
    -4
}

// ============================================================================
// 32. Support Bundle & Log Redactor
// ============================================================================

pub(crate) fn is_diagnostic_token_str(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '+' | '-'))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_is_diagnostic_token(token: *const c_char) -> c_int {
    if token.is_null() {
        return 0;
    }
    match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(v) if is_diagnostic_token_str(v) => 1,
        _ => 0,
    }
}

fn safe_log_line(line: &str) -> bool {
    let allowlisted_markers = [
        "[FATAL]",
        "[compat]",
        "[window] first Roblox Vulkan frame presented",
        "[vulkan]",
        "[mocktail][audio]",
        "[input]",
        "[lifecycle]",
        "[main] Roblox lifecycle shutdown: Stopped",
        "setStage:",
        "JNI_OnLoad",
        "RenderView created",
        "RenderView destroyed",
        "[native-updater]",
        "Segmentation fault",
        "core dumped",
    ];
    if line.contains(".ROBLOSECURITY")
        || line.contains("Authorization:")
        || line.contains("authenticationTicket")
        || line.contains("http://")
        || line.contains("https://")
    {
        return false;
    }
    allowlisted_markers.iter().any(|&m| line.contains(m))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_sanitize_log(
    raw_log: *const u8,
    raw_len: usize,
    out_sanitized: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if raw_log.is_null() || out_sanitized.is_null() || out_cap == 0 {
        return -1;
    }
    let data = unsafe { std::slice::from_raw_parts(raw_log, raw_len) };
    let text = String::from_utf8_lossy(data);
    let mut sanitized = String::new();

    for line in text.lines() {
        if safe_log_line(line) {
            let bounded = if line.len() > 1024 { &line[..1024] } else { line };
            sanitized.push_str(bounded);
            sanitized.push('\n');
        }
    }

    let bytes = sanitized.as_bytes();
    let copy_len = std::cmp::min(bytes.len(), out_cap - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_sanitized, copy_len);
        *out_sanitized.add(copy_len) = 0;
        if !out_len.is_null() {
            *out_len = copy_len;
        }
    }
    0
}

// ============================================================================
// 33. Client Settings & Atomic File Store (Group A)
// ============================================================================

pub const MOCKTAIL_SAFE_DEFAULTS_JSON: &str = r#"{
    "applicationSettings": {
      "BeginScheduledFlagFetch3": "False",
      "BeginScheduledFlagFetch5": "false",
      "RetryFlagPrefetchOnBackgroundFailure": "false",
      "FFlagEnableVersionCheckFromClientSettingsCDN": "False",
      "FIntScheduledFlagFetchPeriodMinutes": "1000000",
      "FIntScheduledFlagFetchPeriodFlexMinutes": "0",
      "DFFlagFetchAndWriteFlagsAfterSuccessfulCachedFlagsLoad": "False",
      "DFFlagWriteFlagCacheAfterDynamicFetch": "False",
      "DFFlagWriteFlagCacheAfterFlagFetch": "False",
      "DFFlagWriteFlagCacheAfterFlagFetch2": "False",
      "DFFlagEnableAppPlatformQoSEmergencyOnStartup3": "False",
      "DFFlagEnableAppPlatformQoSEmergencyOnFlagReload3": "False",
      "DFFlagEnableAppPlatformQoSEmergencyOnFlagReload4": "False",
      "FFlagAndroidEnableQoS": "False",
      "FFlagEnableNetworkStatusObserving": "False",
      "DFFlagDontReportAccumulatedStatsInHttpClientDestroy2": "True",
      "FFlagEnableJNIAppbridgeStartMilestone": "False"
    }
  }"#;

#[no_mangle]
pub extern "C" fn mocktail_rust_client_settings_safe_defaults(
    out_buf: *mut c_char,
    buf_cap: usize,
) -> c_int {
    if out_buf.is_null() || buf_cap <= MOCKTAIL_SAFE_DEFAULTS_JSON.len() {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            MOCKTAIL_SAFE_DEFAULTS_JSON.as_ptr() as *const c_char,
            out_buf,
            MOCKTAIL_SAFE_DEFAULTS_JSON.len(),
        );
        *out_buf.add(MOCKTAIL_SAFE_DEFAULTS_JSON.len()) = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_client_settings_default_url(
    app_name: *const c_char,
    out_buf: *mut c_char,
    buf_cap: usize,
) -> c_int {
    if app_name.is_null() || out_buf.is_null() || buf_cap == 0 {
        return -1;
    }
    let app = match unsafe { CStr::from_ptr(app_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let url = format!(
        "https://clientsettingscdn.roblox.com/v2/settings/application/{}",
        app
    );
    if url.len() >= buf_cap {
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(url.as_ptr() as *const c_char, out_buf, url.len());
        *out_buf.add(url.len()) = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_client_settings_is_valid_json(
    json_str: *const c_char,
) -> c_int {
    if json_str.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(json_str) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return 0,
    };
    if s.is_empty() {
        return 0;
    }
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(v) => if v.is_object() { 1 } else { 0 },
        Err(_) => 0,
    }
}

pub(crate) fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), (c_int, String)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::create_dir_all(parent) {
        return Err((-3, format!("could not create directory: {}", e)));
    }

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp_path = parent.join(format!(
        ".tmp_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));

    let mut file = match std::fs::File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => return Err((-4, format!("cannot create temporary file: {}", e))),
    };
    use std::io::Write;
    if let Err(e) = file.write_all(bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err((-5, format!("cannot write temporary file: {}", e)));
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err((-6, format!("cannot sync temporary file: {}", e)));
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err((-7, format!("cannot rename temporary file: {}", e)));
    }
    if let Ok(dir_file) = std::fs::File::open(parent) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_atomic_write_file(
    file_path: *const c_char,
    content: *const c_char,
    content_len: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if file_path.is_null() {
        set_err("path is null");
        return -1;
    }
    let path_str = match unsafe { CStr::from_ptr(file_path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid path encoding");
            return -2;
        }
    };
    let bytes = if content_len > 0 && !content.is_null() {
        unsafe { std::slice::from_raw_parts(content as *const u8, content_len) }
    } else {
        &[]
    };
    if let Err((code, msg)) = write_atomic_bytes(Path::new(path_str), bytes) {
        set_err(&msg);
        return code;
    }
    0
}

// ============================================================================
// 34. Window State & Video Driver Policy (Group B)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustWindowState {
    pub x: c_int,
    pub y: c_int,
    pub width: c_int,
    pub height: c_int,
    pub has_position: c_int,
    pub fullscreen: c_int,
    pub maximized: c_int,
    pub configured_width: c_int,
    pub configured_height: c_int,
    pub has_configured_size: c_int,
}

const MIN_WINDOW_WIDTH: i32 = 160;
const MIN_WINDOW_HEIGHT: i32 = 120;
const MAX_EXTENT: i32 = 16384;
const MAX_COORDINATE_MAGNITUDE: i32 = 131072;
const MAX_STATE_BYTES: u64 = 32 * 1024;

fn is_valid_window_state(state: &MocktailRustWindowState) -> bool {
    state.width >= MIN_WINDOW_WIDTH
        && state.width <= MAX_EXTENT
        && state.height >= MIN_WINDOW_HEIGHT
        && state.height <= MAX_EXTENT
        && (state.has_configured_size == 0
            || (state.configured_width > 0 && state.configured_height > 0))
        && (state.has_position == 0
            || (state.x >= -MAX_COORDINATE_MAGNITUDE
                && state.x <= MAX_COORDINATE_MAGNITUDE
                && state.y >= -MAX_COORDINATE_MAGNITUDE
                && state.y <= MAX_COORDINATE_MAGNITUDE))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_state_load(
    path_ptr: *const c_char,
    out_state: *mut MocktailRustWindowState,
    out_found: *mut c_int,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if path_ptr.is_null() || out_state.is_null() || out_found.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    unsafe {
        *out_found = 0;
    }
    let p_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid path encoding");
            return -2;
        }
    };
    let path = Path::new(p_str);
    if !path.is_absolute() {
        set_err("window state path must be absolute");
        return -3;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return 0;
            }
            set_err("cannot safely open window state");
            return -4;
        }
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_STATE_BYTES {
        set_err("window state is not a bounded regular file");
        return -5;
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            set_err("cannot read window state");
            return -6;
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => {
            set_err("window state is not a JSON object");
            return -7;
        }
    };
    if !doc.is_object() {
        set_err("window state is not a JSON object");
        return -7;
    }
    let schema_version = doc.get("schema_version").and_then(|v| v.as_i64()).unwrap_or(0);
    if schema_version != 1 {
        set_err("window state has an unsupported schema");
        return -8;
    }
    let windowed = match doc.get("windowed").and_then(|v| v.as_object()) {
        Some(w) => w,
        None => {
            set_err("window state has an unsupported schema");
            return -8;
        }
    };
    let width = match windowed.get("width").and_then(|v| v.as_i64()) {
        Some(w) => w as i32,
        None => {
            set_err("window state has an unsupported schema");
            return -8;
        }
    };
    let height = match windowed.get("height").and_then(|v| v.as_i64()) {
        Some(h) => h as i32,
        None => {
            set_err("window state has an unsupported schema");
            return -8;
        }
    };
    let has_position = match windowed.get("has_position").and_then(|v| v.as_bool()) {
        Some(hp) => hp,
        None => {
            set_err("window state has an unsupported schema");
            return -8;
        }
    };
    let fullscreen = match doc.get("fullscreen").and_then(|v| v.as_bool()) {
        Some(f) => f,
        None => {
            set_err("window state has an unsupported schema");
            return -8;
        }
    };
    let maximized = match doc.get("maximized").and_then(|v| v.as_bool()) {
        Some(m) => m,
        None => {
            set_err("window state has an unsupported schema");
            return -8;
        }
    };

    let mut x = 0;
    let mut y = 0;
    if has_position {
        x = match windowed.get("x").and_then(|v| v.as_i64()) {
            Some(xv) => xv as i32,
            None => {
                set_err("window state position is incomplete");
                return -9;
            }
        };
        y = match windowed.get("y").and_then(|v| v.as_i64()) {
            Some(yv) => yv as i32,
            None => {
                set_err("window state position is incomplete");
                return -9;
            }
        };
    }

    let mut configured_width = 0;
    let mut configured_height = 0;
    let mut has_configured_size = false;
    if let Some(configured) = doc.get("configured").and_then(|v| v.as_object()) {
        let cw = match configured.get("width").and_then(|v| v.as_i64()) {
            Some(w) => w as i32,
            None => {
                set_err("window state configured size is malformed");
                return -10;
            }
        };
        let ch = match configured.get("height").and_then(|v| v.as_i64()) {
            Some(h) => h as i32,
            None => {
                set_err("window state configured size is malformed");
                return -10;
            }
        };
        configured_width = cw;
        configured_height = ch;
        has_configured_size = true;
    }

    let state = MocktailRustWindowState {
        x,
        y,
        width,
        height,
        has_position: if has_position { 1 } else { 0 },
        fullscreen: if fullscreen { 1 } else { 0 },
        maximized: if maximized { 1 } else { 0 },
        configured_width,
        configured_height,
        has_configured_size: if has_configured_size { 1 } else { 0 },
    };

    if !is_valid_window_state(&state) {
        set_err("window state geometry is out of range");
        return -11;
    }

    unsafe {
        *out_state = state;
        *out_found = 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_state_store(
    path_ptr: *const c_char,
    state_ptr: *const MocktailRustWindowState,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if path_ptr.is_null() || state_ptr.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    let state = unsafe { *state_ptr };
    let p_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid path encoding");
            return -2;
        }
    };
    let path = Path::new(p_str);
    if !path.is_absolute() {
        set_err("window state path must be absolute");
        return -3;
    }
    if !is_valid_window_state(&state) {
        set_err("window state geometry is out of range");
        return -4;
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::create_dir_all(parent) {
        set_err(&format!("cannot create window state directory: {}", e));
        return -5;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            set_err("window state target is a symlink");
            return -6;
        }
    }

    let mut windowed = serde_json::json!({
        "has_position": state.has_position != 0,
        "width": state.width,
        "height": state.height,
    });
    if state.has_position != 0 {
        windowed["x"] = serde_json::json!(state.x);
        windowed["y"] = serde_json::json!(state.y);
    }
    let mut doc = serde_json::json!({
        "schema_version": 1,
        "fullscreen": state.fullscreen != 0,
        "maximized": state.maximized != 0,
        "windowed": windowed,
    });
    if state.has_configured_size != 0 {
        doc["configured"] = serde_json::json!({
            "width": state.configured_width,
            "height": state.configured_height,
        });
    }

    let serialized = doc.to_string();

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp_path = parent.join(format!(
        ".mocktail-window-state.tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));

    use std::io::Write;
    let mut file = match std::fs::File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot create temporary window state: {}", e));
            return -7;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    if let Err(e) = file.write_all(serialized.as_bytes()) {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot write window state: {}", e));
        return -8;
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot sync window state: {}", e));
        return -9;
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot atomically store window state: {}", e));
        return -10;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_window_plan_presentation(
    fullscreen: c_int,
    maximized: c_int,
    out_fullscreen_at_creation: *mut c_int,
    out_maximize_after_constraints: *mut c_int,
) {
    if !out_fullscreen_at_creation.is_null() {
        unsafe {
            *out_fullscreen_at_creation = if fullscreen != 0 { 1 } else { 0 };
        }
    }
    if !out_maximize_after_constraints.is_null() {
        unsafe {
            *out_maximize_after_constraints = if fullscreen != 0 { 0 } else if maximized != 0 { 1 } else { 0 };
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_video_driver_resolve(
    has_explicit_sdl_driver: c_int,
    force_wayland: c_int,
    force_x11: c_int,
    has_x11_display: c_int,
    uses_direct_vulkan: c_int,
    has_nvidia_kernel_driver: c_int,
    has_wayland_session: c_int,
    prefer_wayland: c_int,
) -> c_int {
    // 0 = SdlDefault, 1 = Wayland, 2 = X11, 3 = NvidiaDirectVulkanX11
    if has_explicit_sdl_driver != 0 {
        return 0;
    }
    if force_wayland != 0 {
        return 1;
    }
    if force_x11 != 0 && has_x11_display != 0 {
        return 2;
    }
    if uses_direct_vulkan != 0
        && has_nvidia_kernel_driver != 0
        && has_wayland_session != 0
        && has_x11_display != 0
    {
        return 3;
    }
    if prefer_wayland != 0 && has_wayland_session != 0 {
        return 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_video_driver_has_candidate(
    requested: *const c_char,
    candidates_csv: *const c_char,
) -> c_int {
    if requested.is_null() || candidates_csv.is_null() {
        return 0;
    }
    let req = match unsafe { CStr::from_ptr(requested) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let cand_str = match unsafe { CStr::from_ptr(candidates_csv) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let candidates: Vec<&str> = cand_str.split(',').map(|s| s.trim()).collect();
    for part in req.split(',') {
        let p = part.trim();
        if !p.is_empty() && candidates.contains(&p) {
            return 1;
        }
    }
    0
}

// ============================================================================
// 35. Runtime Paths & XDG Layout (Group C)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_paths_is_lower_hex_build_id(
    build_id: *const c_char,
) -> c_int {
    if build_id.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(build_id) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_digit() || (c >= 'a' && c <= 'f')) {
        1
    } else {
        0
    }
}

// ============================================================================
// 36. Host ABI Profile Loader & Payload Compatibility (Group D)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_compute_file_sha256(
    file_path: *const c_char,
    out_hex: *mut c_char,
    hex_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if file_path.is_null() || out_hex.is_null() || hex_cap < 65 {
        set_err("invalid arguments");
        return -1;
    }
    let p_str = match unsafe { CStr::from_ptr(file_path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("invalid file path encoding");
            return -2;
        }
    };
    let mut hex_buf = [0 as c_char; 65];
    let rc = mocktail_rust_sha256_file(file_path, hex_buf.as_mut_ptr(), 65);
    if rc != 0 {
        set_err(&format!("cannot hash file: {}", p_str));
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(hex_buf.as_ptr(), out_hex, 65);
    }
    0
}

// ============================================================================
// 37. Audio Sink & PCM Validation (Group E)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustPcmFormat {
    Unsigned8 = 0,
    Signed16LittleEndian = 1,
    Signed32LittleEndian = 2,
    Float32LittleEndian = 3,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_bytes_per_sample(
    format: MocktailRustPcmFormat,
) -> usize {
    match format {
        MocktailRustPcmFormat::Unsigned8 => 1,
        MocktailRustPcmFormat::Signed16LittleEndian => 2,
        MocktailRustPcmFormat::Signed32LittleEndian
        | MocktailRustPcmFormat::Float32LittleEndian => 4,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_validate_pcm(
    sample_rate_hz: c_int,
    channels: u8,
    format: MocktailRustPcmFormat,
    out_bytes_per_frame: *mut usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        copy_error(out_err, err_cap, msg);
    };
    if sample_rate_hz < 8000 || sample_rate_hz > 384000 {
        set_err("PCM sample rate must be between 8000 and 384000 Hz");
        return -1;
    }
    if channels == 0 || channels > 8 {
        set_err("PCM channel count must be between 1 and 8");
        return -2;
    }
    let bps = mocktail_rust_audio_bytes_per_sample(format);
    if bps == 0 {
        set_err("PCM sample format is unsupported");
        return -3;
    }
    let bpf = bps * (channels as usize);
    if !out_bytes_per_frame.is_null() {
        unsafe {
            *out_bytes_per_frame = bpf;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_apply_gain_f32(
    samples: *mut f32,
    count: usize,
    gain: f32,
) {
    if samples.is_null() || count == 0 {
        return;
    }
    let safe_gain = if gain.is_nan() || gain.is_infinite() || gain < 0.0 {
        0.0
    } else {
        gain
    };
    let slice = unsafe { std::slice::from_raw_parts_mut(samples, count) };
    for sample in slice.iter_mut() {
        let val = *sample * safe_gain;
        *sample = val.clamp(-1.0, 1.0);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_convert_f32_to_i16(
    src: *const f32,
    dst: *mut i16,
    count: usize,
) {
    if src.is_null() || dst.is_null() || count == 0 {
        return;
    }
    let in_slice = unsafe { std::slice::from_raw_parts(src, count) };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(dst, count) };
    for (s_in, s_out) in in_slice.iter().zip(out_slice.iter_mut()) {
        let clamped = s_in.clamp(-1.0, 1.0);
        let scaled = (clamped * 32767.0).round();
        *s_out = scaled as i16;
    }
}

