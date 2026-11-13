use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use std::slice;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub mod text_runtime;
pub use text_runtime::*;
pub mod window_gates;
pub use window_gates::*;

/// Returns the mocktail-core Rust library version string.
#[no_mangle]
pub extern "C" fn mocktail_rust_version() -> *const c_char {
    static VERSION: &[u8] = b"0.3.0-rust-core\0";
    VERSION.as_ptr() as *const c_char
}

/// Initializes and verifies the mocktail-core Rust subsystem.
#[no_mangle]
pub extern "C" fn mocktail_rust_init() -> c_int {
    // 0 = Success
    0
}

// ============================================================================
// 1. Secure Memory & Cryptography
// ============================================================================

/// Securely zeroes out sensitive memory (such as Roblox session cookies, tokens).
#[no_mangle]
pub extern "C" fn mocktail_rust_secure_zero(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
}

/// Computes the SHA-256 hash of a memory buffer.
#[no_mangle]
pub extern "C" fn mocktail_rust_sha256(
    data: *const u8,
    len: usize,
    out_hex: *mut c_char,
    out_cap: usize,
) -> c_int {
    if data.is_null() || out_hex.is_null() || out_cap < 65 {
        return -1;
    }
    let input = unsafe { slice::from_raw_parts(data, len) };
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let hex_str = hex::encode(hash);

    let c_str = match CString::new(hex_str) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let bytes = c_str.as_bytes_with_nul();
    if bytes.len() > out_cap {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_hex, bytes.len());
    }
    0
}

/// Computes the SHA-256 hash of a file on disk using buffered streaming I/O.
#[no_mangle]
pub extern "C" fn mocktail_rust_sha256_file(
    path: *const c_char,
    out_hex: *mut c_char,
    out_cap: usize,
) -> c_int {
    if path.is_null() || out_hex.is_null() || out_cap < 65 {
        return -1;
    }
    let c_path = unsafe { CStr::from_ptr(path) };
    let path_str = match c_path.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let file = match File::open(path_str) {
        Ok(f) => f,
        Err(_) => return -1,
    };

    if let Ok(meta) = file.metadata() {
        if !meta.is_file() {
            return -1;
        }
    } else {
        return -1;
    }

    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16384];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return -1,
        }
    }

    let hash = hasher.finalize();
    let hex_str = hex::encode(hash);
    let c_str = match CString::new(hex_str) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let bytes = c_str.as_bytes_with_nul();
    if bytes.len() > out_cap {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_hex, bytes.len());
    }
    0
}

/// Compares a file's SHA-256 hash against an expected hexadecimal string.
#[no_mangle]
pub extern "C" fn mocktail_rust_verify_file_sha256(
    path: *const c_char,
    expected_hex: *const c_char,
) -> c_int {
    if path.is_null() || expected_hex.is_null() {
        return -1;
    }
    let expected = unsafe { CStr::from_ptr(expected_hex) };
    let expected_str = match expected.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    let mut computed = [0 as c_char; 65];
    if mocktail_rust_sha256_file(path, computed.as_mut_ptr(), computed.len()) != 0 {
        return -1;
    }

    let computed_str = match unsafe { CStr::from_ptr(computed.as_ptr()) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    if computed_str.eq_ignore_ascii_case(expected_str) {
        1
    } else {
        0
    }
}

// ============================================================================
// 2. APK & Archive Safety (Zip-Slip & Safe Extraction)
// ============================================================================

/// Validates whether an archive relative path is safe against Zip-Slip, directory traversal,
/// and control character injection.
#[no_mangle]
pub extern "C" fn mocktail_rust_is_safe_archive_path(path: *const c_char) -> c_int {
    if path.is_null() {
        return 0;
    }
    let c_path = unsafe { CStr::from_ptr(path) };
    let bytes = c_path.to_bytes();
    if bytes.is_empty() || bytes[0] == b'/' {
        return 0;
    }
    for &b in bytes {
        if b < 0x20 || b == 0x7f || b == b'\\' {
            return 0;
        }
    }
    let mut parts = bytes.split(|&b| b == b'/');
    let mut is_first = true;
    while let Some(part) = parts.next() {
        if part.is_empty() {
            if parts.clone().next().is_none() && !is_first {
                return 1;
            }
            return 0;
        }
        if part == b"." || part == b".." {
            return 0;
        }
        is_first = false;
    }
    1
}

/// Safely extracts an individual entry from a ZIP / APK archive with Zip-Slip protection
/// and atomic replacement.
#[no_mangle]
pub extern "C" fn mocktail_rust_extract_zip_entry(
    archive_path: *const c_char,
    entry_name: *const c_char,
    dest_path: *const c_char,
    max_bytes: usize,
) -> c_int {
    if archive_path.is_null() || entry_name.is_null() || dest_path.is_null() {
        return -1;
    }
    let c_archive = unsafe { CStr::from_ptr(archive_path) };
    let c_entry = unsafe { CStr::from_ptr(entry_name) };
    let c_dest = unsafe { CStr::from_ptr(dest_path) };

    let archive_str = match c_archive.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let entry_str = match c_entry.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let dest_str = match c_dest.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let file = match File::open(archive_str) {
        Ok(f) => f,
        Err(_) => return -2,
    };

    let mut zip = match zip::ZipArchive::new(BufReader::new(file)) {
        Ok(z) => z,
        Err(_) => return -3,
    };

    let mut zip_file = match zip.by_name(entry_str) {
        Ok(zf) => zf,
        Err(_) => return -4,
    };

    if zip_file.enclosed_name().is_none() {
        return -5;
    }

    if zip_file.is_dir() {
        return -6;
    }

    let uncompressed_size = zip_file.size();
    if uncompressed_size > max_bytes as u64 {
        return -7;
    }

    let dest = Path::new(dest_str);
    if dest.exists() {
        return -15;
    }
    if let Some(parent) = dest.parent() {
        if let Err(_) = std::fs::create_dir_all(parent) {
            return -8;
        }
    }

    let tmp_path = dest.with_extension("tmp_extract");
    let mut out_file = match File::create(&tmp_path) {
        Ok(f) => f,
        Err(_) => return -9,
    };

    let mut written = 0usize;
    let mut buffer = [0u8; 32768];
    loop {
        match zip_file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                written += n;
                if written > max_bytes {
                    let _ = std::fs::remove_file(&tmp_path);
                    return -10;
                }
                if let Err(_) = out_file.write_all(&buffer[..n]) {
                    let _ = std::fs::remove_file(&tmp_path);
                    return -11;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = std::fs::remove_file(&tmp_path);
                return -12;
            }
        }
    }

    if let Err(_) = out_file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return -13;
    }
    drop(out_file);

    if let Err(_) = std::fs::rename(&tmp_path, dest) {
        let _ = std::fs::remove_file(&tmp_path);
        return -14;
    }

    0
}

/// Verifies whether the provided slice matches the APK Signing Block magic "APK Sig Block 42".
#[no_mangle]
pub extern "C" fn mocktail_rust_verify_apk_signing_magic(magic: *const u8, len: usize) -> c_int {
    if magic.is_null() || len != 16 {
        return 0;
    }
    static APK_SIG_MAGIC: &[u8; 16] = b"APK Sig Block 42";
    let slice = unsafe { slice::from_raw_parts(magic, len) };
    if slice == APK_SIG_MAGIC {
        1
    } else {
        0
    }
}

// ============================================================================
// 3. Android Binary XML (AndroidManifest.xml) Safe Parser
// ============================================================================

#[repr(C)]
pub struct MocktailRustManifestResult {
    pub package_name: [c_char; 256],
    pub version_name: [c_char; 256],
    pub split_name: [c_char; 256],
    pub version_code: u64,
    pub error: [c_char; 256],
}

fn write_c_buf(dst: &mut [c_char], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(dst.len() - 1);
    for i in 0..len {
        dst[i] = bytes[i] as c_char;
    }
    dst[len] = 0;
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_android_manifest(
    data: *const u8,
    len: usize,
    out: *mut MocktailRustManifestResult,
) -> c_int {
    if data.is_null() || out.is_null() || len < 8 {
        return -1;
    }
    let res = unsafe { &mut *out };
    res.package_name[0] = 0;
    res.version_name[0] = 0;
    res.split_name[0] = 0;
    res.version_code = 0;
    res.error[0] = 0;

    let bytes = unsafe { slice::from_raw_parts(data, len) };
    if let Err(e) = parse_manifest_internal(bytes, res) {
        write_c_buf(&mut res.error, &e);
        return 0; // Parsed with error recorded
    }
    1 // Success
}

fn parse_manifest_internal(bytes: &[u8], res: &mut MocktailRustManifestResult) -> Result<(), String> {
    const RES_XML_TYPE: u16 = 0x0003;
    const RES_STRING_POOL_TYPE: u16 = 0x0001;
    const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
    const UTF8_FLAG: u32 = 0x00000100;

    if bytes.len() < 8 {
        return Err("AndroidManifest.xml is too small".to_string());
    }
    let xml_type = u16::from_le_bytes([bytes[0], bytes[1]]);
    let xml_header_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    let xml_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

    if xml_type != RES_XML_TYPE || xml_size != bytes.len() || xml_header_size < 8 {
        return Err("AndroidManifest.xml is not valid binary XML".to_string());
    }

    let mut pool: Vec<String> = Vec::new();
    let mut has_pool = false;
    let mut offset = xml_header_size;

    while offset + 8 <= bytes.len() {
        let chunk_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let chunk_header_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let chunk_size = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;

        if chunk_size < chunk_header_size || offset + chunk_size > bytes.len() {
            return Err("AndroidManifest.xml contains an invalid chunk".to_string());
        }

        if chunk_type == RES_STRING_POOL_TYPE {
            if has_pool {
                return Err("duplicate Android string pool".to_string());
            }
            if chunk_header_size < 28 {
                return Err("Android string pool header is invalid".to_string());
            }
            let count = u32::from_le_bytes([
                bytes[offset + 8],
                bytes[offset + 9],
                bytes[offset + 10],
                bytes[offset + 11],
            ]) as usize;
            let flags = u32::from_le_bytes([
                bytes[offset + 16],
                bytes[offset + 17],
                bytes[offset + 18],
                bytes[offset + 19],
            ]);
            let strings_start = u32::from_le_bytes([
                bytes[offset + 20],
                bytes[offset + 21],
                bytes[offset + 22],
                bytes[offset + 23],
            ]) as usize;

            let is_utf8 = (flags & UTF8_FLAG) != 0;
            pool.reserve(count.min(100000));

            for i in 0..count {
                let off_idx = offset + chunk_header_size + i * 4;
                if off_idx + 4 > offset + chunk_size {
                    break;
                }
                let str_rel = u32::from_le_bytes([
                    bytes[off_idx],
                    bytes[off_idx + 1],
                    bytes[off_idx + 2],
                    bytes[off_idx + 3],
                ]) as usize;
                let str_pos = offset + strings_start + str_rel;
                if str_pos >= offset + chunk_size {
                    pool.push(String::new());
                    continue;
                }
                let mut cursor = str_pos;
                if is_utf8 {
                    // skip char len
                    if cursor < bytes.len() && (bytes[cursor] & 0x80) != 0 {
                        cursor += 2;
                    } else {
                        cursor += 1;
                    }
                    // read byte len
                    let byte_len = if cursor < bytes.len() && (bytes[cursor] & 0x80) != 0 {
                        let len = ((bytes[cursor] as usize & 0x7f) << 8) | bytes[cursor + 1] as usize;
                        cursor += 2;
                        len
                    } else if cursor < bytes.len() {
                        let len = bytes[cursor] as usize;
                        cursor += 1;
                        len
                    } else {
                        0
                    };
                    if cursor + byte_len <= bytes.len() {
                        let s = String::from_utf8_lossy(&bytes[cursor..cursor + byte_len]).to_string();
                        pool.push(s);
                    } else {
                        pool.push(String::new());
                    }
                } else {
                    // UTF-16
                    let mut u16_len = if cursor + 2 <= bytes.len() {
                        let l = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                        cursor += 2;
                        l
                    } else {
                        0
                    };
                    if (u16_len & 0x8000) != 0 && cursor + 2 <= bytes.len() {
                        let l2 = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                        cursor += 2;
                        u16_len = ((u16_len & 0x7fff) << 16) | l2;
                    }
                    if cursor + u16_len * 2 <= bytes.len() {
                        let u16_slice: Vec<u16> = bytes[cursor..cursor + u16_len * 2]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        let s = String::from_utf16_lossy(&u16_slice);
                        pool.push(s);
                    } else {
                        pool.push(String::new());
                    }
                }
            }
            has_pool = true;
        } else if chunk_type == RES_XML_START_ELEMENT_TYPE && has_pool {
            if chunk_header_size < 16 || offset + 36 > bytes.len() {
                offset += chunk_size;
                continue;
            }
            let name_idx = u32::from_le_bytes([
                bytes[offset + 20],
                bytes[offset + 21],
                bytes[offset + 22],
                bytes[offset + 23],
            ]) as usize;
            let attr_start = u16::from_le_bytes([bytes[offset + 24], bytes[offset + 25]]) as usize;
            let attr_size = u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]) as usize;
            let attr_count = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;

            if name_idx < pool.len() && pool[name_idx] == "manifest" {
                let attrs_pos = offset + 16 + attr_start;
                for a in 0..attr_count {
                    let a_off = attrs_pos + a * attr_size;
                    if a_off + 20 > offset + chunk_size {
                        break;
                    }
                    let a_name_idx = u32::from_le_bytes([
                        bytes[a_off + 4],
                        bytes[a_off + 5],
                        bytes[a_off + 6],
                        bytes[a_off + 7],
                    ]) as usize;
                    let a_raw_idx = u32::from_le_bytes([
                        bytes[a_off + 8],
                        bytes[a_off + 9],
                        bytes[a_off + 10],
                        bytes[a_off + 11],
                    ]) as usize;
                    let data_type = bytes[a_off + 15];
                    let typed_data = u32::from_le_bytes([
                        bytes[a_off + 16],
                        bytes[a_off + 17],
                        bytes[a_off + 18],
                        bytes[a_off + 19],
                    ]);

                    let attr_name = if a_name_idx < pool.len() { &pool[a_name_idx] } else { "" };
                    let str_val = if a_raw_idx < pool.len() {
                        Some(&pool[a_raw_idx])
                    } else if data_type == 0x03 && (typed_data as usize) < pool.len() {
                        Some(&pool[typed_data as usize])
                    } else {
                        None
                    };

                    match attr_name {
                        "package" => {
                            if let Some(v) = str_val {
                                write_c_buf(&mut res.package_name, v);
                            }
                        }
                        "versionName" => {
                            if let Some(v) = str_val {
                                write_c_buf(&mut res.version_name, v);
                            }
                        }
                        "split" => {
                            if let Some(v) = str_val {
                                write_c_buf(&mut res.split_name, v);
                            }
                        }
                        "versionCode" => {
                            if (0x10..=0x1f).contains(&data_type) {
                                res.version_code = typed_data as u64;
                            }
                        }
                        _ => {}
                    }
                }
                if res.package_name[0] == 0 || res.version_code == 0 {
                    return Err("Android manifest has no package or versionCode".to_string());
                }
                return Ok(());
            }
        }
        offset += chunk_size;
    }
    Err("Android manifest element is missing".to_string())
}

// ============================================================================
// 4. Text & URI Parsing (UTF-8, Controls, Percent-Decode)
// ============================================================================

/// Validates whether a byte buffer is completely valid UTF-8.
#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_utf8(data: *const u8, len: usize) -> c_int {
    if data.is_null() && len > 0 {
        return 0;
    }
    if len == 0 {
        return 1;
    }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    if std::str::from_utf8(slice).is_ok() {
        1
    } else {
        0
    }
}

/// Checks whether a byte buffer contains ASCII control characters (< 0x20 or 0x7f).
#[no_mangle]
pub extern "C" fn mocktail_rust_contains_control_bytes(data: *const u8, len: usize) -> c_int {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    for &b in slice {
        if b < 0x20 || b == 0x7f {
            return 1;
        }
    }
    0
}

/// Safely decodes a percent-encoded string with optional '+' to space conversion.
#[no_mangle]
pub extern "C" fn mocktail_rust_percent_decode(
    in_str: *const c_char,
    plus_as_space: c_int,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    if in_str.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let c_in = unsafe { CStr::from_ptr(in_str) };
    let bytes = c_in.to_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());

    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = match (bytes[i + 1] as char).to_digit(16) {
                Some(v) => v as u8,
                None => return -2,
            };
            let l = match (bytes[i + 2] as char).to_digit(16) {
                Some(v) => v as u8,
                None => return -2,
            };
            decoded.push((h << 4) | l);
            i += 3;
        } else if bytes[i] == b'+' && plus_as_space != 0 {
            decoded.push(b' ');
            i += 1;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }

    if decoded.len() + 1 > out_cap {
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(decoded.as_ptr() as *const c_char, out_buf, decoded.len());
        *out_buf.add(decoded.len()) = 0;
    }
    0
}

// ============================================================================
// 5. System Memory & Process Memory Monitoring (/proc/self/status)
// ============================================================================

/// Parses VmRSS and VmSwap in kibibytes from a /proc/self/status buffer.
#[no_mangle]
pub extern "C" fn mocktail_rust_parse_status_memory(
    status_str: *const c_char,
    out_rss: *mut u64,
    out_swap: *mut u64,
) -> c_int {
    if status_str.is_null() || out_rss.is_null() || out_swap.is_null() {
        return 0;
    }
    let c_status = unsafe { CStr::from_ptr(status_str) };
    let text = match c_status.to_str() {
        Ok(t) => t,
        Err(_) => return 0,
    };

    let parse_field = |field: &str| -> Option<u64> {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(field) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 2 && parts[1] == "kB" {
                    if let Ok(kib) = parts[0].parse::<u64>() {
                        return kib.checked_mul(1024);
                    }
                }
            }
        }
        None
    };

    let rss = match parse_field("VmRSS:") {
        Some(r) => r,
        None => return 0,
    };
    let swap = parse_field("VmSwap:").unwrap_or(0);

    unsafe {
        *out_rss = rss;
        *out_swap = swap;
    }
    1
}

/// Reads /proc/self/status directly and parses RSS and Swap memory safely.
#[no_mangle]
pub extern "C" fn mocktail_rust_read_self_memory(out_rss: *mut u64, out_swap: *mut u64) -> c_int {
    if out_rss.is_null() || out_swap.is_null() {
        return 0;
    }
    let file = match File::open("/proc/self/status") {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut reader = BufReader::new(file);
    let mut content = String::with_capacity(4096);
    if reader.read_to_string(&mut content).is_err() {
        return 0;
    }
    let c_content = match CString::new(content) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    mocktail_rust_parse_status_memory(c_content.as_ptr(), out_rss, out_swap)
}

// ============================================================================
// 6. Discord RPC IPC Frame Builder
// ============================================================================

/// Encodes a Discord IPC frame: 4 bytes opcode (LE) + 4 bytes payload length (LE) + payload JSON.
#[no_mangle]
pub extern "C" fn mocktail_rust_build_discord_frame(
    opcode: u32,
    payload_json: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if payload_json.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let c_payload = unsafe { CStr::from_ptr(payload_json) };
    let bytes = c_payload.to_bytes();
    let frame_len = 8 + bytes.len();

    if frame_len > out_cap {
        return -2;
    }

    let op_bytes = opcode.to_le_bytes();
    let len_bytes = (bytes.len() as u32).to_le_bytes();

    unsafe {
        std::ptr::copy_nonoverlapping(op_bytes.as_ptr(), out_buf, 4);
        std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), out_buf.add(4), 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.add(8), bytes.len());
        *out_len = frame_len;
    }
    0
}

// ============================================================================
// 7. JNI Method Signature Validator
// ============================================================================

/// Validates whether a JNI method descriptor strictly conforms to JVMS §4.3.3.
#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_jni_signature(sig: *const c_char) -> c_int {
    if sig.is_null() {
        return 0;
    }
    let c_sig = unsafe { CStr::from_ptr(sig) };
    let bytes = c_sig.to_bytes();
    if bytes.is_empty() || bytes[0] != b'(' {
        return 0;
    }

    let mut i = 1;
    while i < bytes.len() && bytes[i] != b')' {
        if !parse_jni_type(bytes, &mut i, false) {
            return 0;
        }
    }
    if i >= bytes.len() || bytes[i] != b')' {
        return 0;
    }
    i += 1;

    if !parse_jni_type(bytes, &mut i, true) {
        return 0;
    }

    if i == bytes.len() {
        1
    } else {
        0
    }
}

fn parse_jni_type(bytes: &[u8], idx: &mut usize, allow_void: bool) -> bool {
    let mut array_depth = 0;
    while *idx < bytes.len() && bytes[*idx] == b'[' {
        array_depth += 1;
        *idx += 1;
        if array_depth > 255 {
            return false;
        }
    }
    if *idx >= bytes.len() {
        return false;
    }
    match bytes[*idx] {
        b'V' if allow_void && array_depth == 0 => {
            *idx += 1;
            true
        }
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
            *idx += 1;
            true
        }
        b'L' => {
            *idx += 1;
            let start = *idx;
            while *idx < bytes.len() && bytes[*idx] != b';' {
                let b = bytes[*idx];
                if b <= 0x20 || b >= 0x7f || b == b'[' || b == b'(' || b == b')' {
                    return false;
                }
                *idx += 1;
            }
            if *idx >= bytes.len() || bytes[*idx] != b';' || *idx == start {
                return false;
            }
            *idx += 1;
            true
        }
        _ => false,
    }
}

// ============================================================================
// 8. General JSON & URL Validation
// ============================================================================

/// Validates whether a given C string is syntactically valid JSON.
#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_json(json_str: *const c_char) -> c_int {
    if json_str.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let bytes = c_str.to_bytes();
    if bytes.is_empty() {
        return 0;
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Validates if a URL is safe (https scheme, max 2048 chars, valid ASCII without controls).
#[no_mangle]
pub extern "C" fn mocktail_rust_is_safe_url(url: *const c_char) -> c_int {
    if url.is_null() {
        return 0;
    }
    let c_url = unsafe { CStr::from_ptr(url) };
    let bytes = c_url.to_bytes();
    if bytes.is_empty() || bytes.len() > 2048 {
        return 0;
    }
    if !bytes.starts_with(b"https://") {
        return 0;
    }
    if bytes.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return 0;
    }
    1
}

// ============================================================================
// 10. JNI Modified UTF-8 (MUTF-8) Engine
// ============================================================================

/// Converts MUTF-8 to UTF-16 code units.
/// In MUTF-8, 0x00 is encoded as 0xC0 0x80. Standard surrogate pairs are preserved.
#[no_mangle]
pub extern "C" fn mocktail_rust_mutf8_to_utf16(
    mutf8_ptr: *const u8,
    mutf8_len: usize,
    out_utf16: *mut u16,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if (mutf8_ptr.is_null() && mutf8_len > 0) || out_utf16.is_null() || out_len.is_null() {
        return -1;
    }
    let bytes = if mutf8_len == 0 { &[] } else { unsafe { slice::from_raw_parts(mutf8_ptr, mutf8_len) } };
    let mut code_units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let b1 = bytes[index];
        if b1 != 0 && b1 <= 0x7F {
            code_units.push(b1 as u16);
            index += 1;
        } else if (b1 & 0xE0) == 0xC0 && index + 1 < bytes.len() && (bytes[index + 1] & 0xC0) == 0x80 {
            let b2 = bytes[index + 1];
            let cp = (((b1 & 0x1F) as u32) << 6) | ((b2 & 0x3F) as u32);
            code_units.push(cp as u16);
            index += 2;
        } else if (b1 & 0xF0) == 0xE0 && index + 2 < bytes.len()
            && (bytes[index + 1] & 0xC0) == 0x80 && (bytes[index + 2] & 0xC0) == 0x80 {
            let b2 = bytes[index + 1];
            let b3 = bytes[index + 2];
            let cp = (((b1 & 0x0F) as u32) << 12) | (((b2 & 0x3F) as u32) << 6) | ((b3 & 0x3F) as u32);
            code_units.push(cp as u16);
            index += 3;
        } else if (b1 & 0xF8) == 0xF0 && index + 3 < bytes.len()
            && (bytes[index + 1] & 0xC0) == 0x80 && (bytes[index + 2] & 0xC0) == 0x80 && (bytes[index + 3] & 0xC0) == 0x80 {
            // Standard UTF-8 4-byte sequence -> convert to surrogate pair for Java UTF-16
            let b2 = bytes[index + 1];
            let b3 = bytes[index + 2];
            let b4 = bytes[index + 3];
            let cp = (((b1 & 0x07) as u32) << 18) | (((b2 & 0x3F) as u32) << 12)
                | (((b3 & 0x3F) as u32) << 6) | ((b4 & 0x3F) as u32);
            if cp >= 0x10000 && cp <= 0x10FFFF {
                let sub = cp - 0x10000;
                let high = (0xD800 + (sub >> 10)) as u16;
                let low = (0xDC00 + (sub & 0x3FF)) as u16;
                code_units.push(high);
                code_units.push(low);
            } else {
                code_units.push(0xFFFD);
            }
            index += 4;
        } else {
            code_units.push(0xFFFD);
            index += 1;
        }
    }
    if code_units.len() > out_cap {
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(code_units.as_ptr(), out_utf16, code_units.len());
        *out_len = code_units.len();
    }
    0
}

/// Converts UTF-16 code units to MUTF-8.
#[no_mangle]
pub extern "C" fn mocktail_rust_utf16_to_mutf8(
    utf16_ptr: *const u16,
    utf16_len: usize,
    out_mutf8: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if (utf16_ptr.is_null() && utf16_len > 0) || out_mutf8.is_null() || out_len.is_null() {
        return -1;
    }
    let units = if utf16_len == 0 { &[] } else { unsafe { slice::from_raw_parts(utf16_ptr, utf16_len) } };
    let mut mutf8: Vec<u8> = Vec::with_capacity(units.len() * 3);
    for &u in units {
        if u == 0 {
            mutf8.push(0xC0);
            mutf8.push(0x80);
        } else if u <= 0x7F {
            mutf8.push(u as u8);
        } else if u <= 0x7FF {
            mutf8.push(0xC0 | ((u >> 6) as u8));
            mutf8.push(0x80 | ((u & 0x3F) as u8));
        } else {
            mutf8.push(0xE0 | ((u >> 12) as u8));
            mutf8.push(0x80 | (((u >> 6) & 0x3F) as u8));
            mutf8.push(0x80 | ((u & 0x3F) as u8));
        }
    }
    if mutf8.len() > out_cap {
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(mutf8.as_ptr(), out_mutf8, mutf8.len());
        *out_len = mutf8.len();
    }
    0
}

/// Converts MUTF-8 bytes to standard UTF-8 string bytes.
#[no_mangle]
pub extern "C" fn mocktail_rust_mutf8_to_utf8(
    mutf8_ptr: *const u8,
    mutf8_len: usize,
    out_utf8: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if (mutf8_ptr.is_null() && mutf8_len > 0) || out_utf8.is_null() || out_len.is_null() {
        return -1;
    }
    let bytes = if mutf8_len == 0 { &[] } else { unsafe { slice::from_raw_parts(mutf8_ptr, mutf8_len) } };
    let mut utf16 = Vec::new();
    let mut idx = 0;
    while idx < bytes.len() {
        let b1 = bytes[idx];
        if b1 != 0 && b1 <= 0x7F {
            utf16.push(b1 as u16);
            idx += 1;
        } else if (b1 & 0xE0) == 0xC0 && idx + 1 < bytes.len() && (bytes[idx + 1] & 0xC0) == 0x80 {
            let b2 = bytes[idx + 1];
            let cp = (((b1 & 0x1F) as u16) << 6) | ((b2 & 0x3F) as u16);
            utf16.push(cp);
            idx += 2;
        } else if (b1 & 0xF0) == 0xE0 && idx + 2 < bytes.len()
            && (bytes[idx + 1] & 0xC0) == 0x80 && (bytes[idx + 2] & 0xC0) == 0x80 {
            let b2 = bytes[idx + 1];
            let b3 = bytes[idx + 2];
            let cp = (((b1 & 0x0F) as u16) << 12) | (((b2 & 0x3F) as u16) << 6) | ((b3 & 0x3F) as u16);
            utf16.push(cp);
            idx += 3;
        } else {
            utf16.push(0xFFFD);
            idx += 1;
        }
    }
    let string = String::from_utf16_lossy(&utf16);
    let str_bytes = string.as_bytes();
    if str_bytes.len() > out_cap {
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(str_bytes.as_ptr(), out_utf8, str_bytes.len());
        *out_len = str_bytes.len();
    }
    0
}

// ============================================================================
// 11. Roblox Cookie & Token Parser
// ============================================================================

#[inline]
fn is_valid_cookie_octet(b: u8) -> bool {
    b == 0x21 || (b >= 0x23 && b <= 0x2B) || (b >= 0x2D && b <= 0x3A)
        || (b >= 0x3C && b <= 0x5B) || (b >= 0x5D && b <= 0x7E)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_cookie_octet(byte: u8) -> c_int {
    if is_valid_cookie_octet(byte) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_roblox_cookie(
    raw_input: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if raw_input.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(raw_input) };
    let mut bytes = c_str.to_bytes();
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return -2;
    }
    // If it contains ".ROBLOSECURITY=", slice after it
    static PREFIX: &[u8] = b".ROBLOSECURITY=";
    if let Some(pos) = bytes.windows(PREFIX.len()).position(|w| w == PREFIX) {
        bytes = &bytes[pos + PREFIX.len()..];
    }
    // Slice until semicolon if present
    if let Some(semi) = bytes.iter().position(|&b| b == b';') {
        bytes = &bytes[..semi];
    }
    // Trim whitespace
    let mut start = 0;
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t' || bytes[start] == b'\r' || bytes[start] == b'\n') {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t' || bytes[end - 1] == b'\r' || bytes[end - 1] == b'\n') {
        end -= 1;
    }
    bytes = &bytes[start..end];

    // Trim quotes if wrapped
    if bytes.len() >= 2 && bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"') {
        bytes = &bytes[1..bytes.len() - 1];
    }

    if bytes.is_empty() || bytes.len() > 4096 {
        return -3;
    }
    if !bytes.iter().all(|&b| is_valid_cookie_octet(b)) {
        return -4;
    }
    if bytes.len() + 1 > out_cap {
        return -5;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
        *out_buf.add(bytes.len()) = 0;
        *out_len = bytes.len();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_parse_webview_roblox_cookie(
    raw_input: *const c_char,
    in_len: usize,
    out_buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    if raw_input.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    *out_len = 0;
    let prefix = b".ROBLOSECURITY=";
    if in_len < prefix.len() {
        return -1;
    }
    let slice = std::slice::from_raw_parts(raw_input as *const u8, in_len);
    if !slice.starts_with(prefix) {
        return -1;
    }
    let val = &slice[prefix.len()..];
    if val.is_empty() || val.len() > 4096 {
        return -1;
    }
    if !val.iter().all(|&b| is_valid_cookie_octet(b)) {
        return -1;
    }
    if cap <= val.len() {
        return -2;
    }
    std::ptr::copy_nonoverlapping(val.as_ptr() as *const c_char, out_buf, val.len());
    *out_buf.add(val.len()) = 0;
    *out_len = val.len();
    0
}

// ============================================================================
// 12. Roblox MessageBus JSON & Permissions Bridge
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_json_depth(json_str: *const c_char, max_depth: usize) -> c_int {
    if json_str.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let bytes = c_str.to_bytes();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
        } else if b == b'{' || b == b'[' {
            depth += 1;
            if depth > max_depth {
                return 0;
            }
        } else if b == b'}' || b == b']' {
            if depth > 0 {
                depth -= 1;
            }
        }
    }
    if quoted || depth != 0 {
        return 0;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_check_permission_request(
    json_str: *const c_char,
    microphone_enabled: c_int,
    out_has_missing: *mut c_int,
    out_missing_json: *mut c_char,
    out_cap: usize,
) -> c_int {
    if json_str.is_null() || out_has_missing.is_null() || out_missing_json.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let bytes = c_str.to_bytes();
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return -2;
    }
    if mocktail_rust_validate_json_depth(json_str, 8) == 0 {
        return -3;
    }
    let val: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return -4,
    };
    let obj = match val.as_object() {
        Some(o) => o,
        None => return -5,
    };
    let perms_arr = match obj.get("permissions").and_then(|p| p.as_array()) {
        Some(a) => a,
        None => return -6,
    };
    if perms_arr.len() > 64 {
        return -7;
    }
    let mut missing = Vec::new();
    for item in perms_arr {
        let s = match item.as_str() {
            Some(s) => s,
            None => return -8,
        };
        if s.is_empty() || s.len() > 128 || s.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\t' || b == 0) {
            return -9;
        }
        if s != "LOCAL_NETWORK" && (s != "MICROPHONE_ACCESS" || microphone_enabled == 0) {
            missing.push(serde_json::Value::String(s.to_string()));
        }
    }
    let missing_json = match serde_json::to_string(&missing) {
        Ok(j) => j,
        Err(_) => return -10,
    };
    if missing_json.len() + 1 > out_cap {
        return -11;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(missing_json.as_ptr() as *const c_char, out_missing_json, missing_json.len());
        *out_missing_json.add(missing_json.len()) = 0;
        *out_has_missing = if missing.is_empty() { 0 } else { 1 };
    }
    0
}

// ============================================================================
// 13. ELF Header & GNU Build-ID Safe Parser
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_verify_elf_architecture(
    elf_bytes: *const u8,
    elf_len: usize,
    expected_machine: u16,
) -> c_int {
    if elf_bytes.is_null() || elf_len < 64 {
        return 0;
    }
    let bytes = unsafe { slice::from_raw_parts(elf_bytes, elf_len) };
    if &bytes[0..4] != b"\x7fELF" {
        return 0;
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        // Must be 64-bit (2) and Little-Endian (1)
        return 0;
    }
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if expected_machine != 0 && e_machine != expected_machine {
        return 0;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_elf_build_id(
    elf_bytes: *const u8,
    elf_len: usize,
    out_hex: *mut c_char,
    out_cap: usize,
) -> c_int {
    if elf_bytes.is_null() || elf_len < 64 || out_hex.is_null() {
        return -1;
    }
    let bytes = unsafe { slice::from_raw_parts(elf_bytes, elf_len) };
    if &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return -2;
    }

    let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;

    let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;

    let parse_notes = |note_data: &[u8]| -> Option<String> {
        let mut offset = 0;
        while offset + 12 <= note_data.len() {
            let namesz = u32::from_le_bytes(note_data[offset..offset + 4].try_into().unwrap()) as usize;
            let descsz = u32::from_le_bytes(note_data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            let n_type = u32::from_le_bytes(note_data[offset + 8..offset + 12].try_into().unwrap());
            offset += 12;

            let namesz_padded = (namesz + 3) & !3;
            let descsz_padded = (descsz + 3) & !3;

            if offset + namesz_padded + descsz > note_data.len() {
                break;
            }

            let name = &note_data[offset..offset + namesz];
            let desc = &note_data[offset + namesz_padded..offset + namesz_padded + descsz];
            offset += namesz_padded + descsz_padded;

            if n_type == 3 && namesz >= 3 && name.starts_with(b"GNU") && descsz > 0 && descsz <= 64 {
                return Some(hex::encode(desc));
            }
        }
        None
    };

    if e_phentsize >= 56 && e_phnum > 0 && e_phoff + e_phnum * e_phentsize <= elf_len {
        for i in 0..e_phnum {
            let ph_offset = e_phoff + i * e_phentsize;
            let p_type = u32::from_le_bytes(bytes[ph_offset..ph_offset + 4].try_into().unwrap());
            if p_type == 4 { // PT_NOTE
                let p_offset = u64::from_le_bytes(bytes[ph_offset + 8..ph_offset + 16].try_into().unwrap()) as usize;
                let p_filesz = u64::from_le_bytes(bytes[ph_offset + 32..ph_offset + 40].try_into().unwrap()) as usize;
                if p_offset + p_filesz <= elf_len {
                    if let Some(id) = parse_notes(&bytes[p_offset..p_offset + p_filesz]) {
                        if id.len() + 1 > out_cap {
                            return -3;
                        }
                        unsafe {
                            std::ptr::copy_nonoverlapping(id.as_ptr() as *const c_char, out_hex, id.len());
                            *out_hex.add(id.len()) = 0;
                        }
                        return 0;
                    }
                }
            }
        }
    }

    if e_shentsize >= 64 && e_shnum > 0 && e_shoff + e_shnum * e_shentsize <= elf_len {
        for i in 0..e_shnum {
            let sh_offset = e_shoff + i * e_shentsize;
            let sh_type = u32::from_le_bytes(bytes[sh_offset + 4..sh_offset + 8].try_into().unwrap());
            if sh_type == 7 { // SHT_NOTE
                let s_offset = u64::from_le_bytes(bytes[sh_offset + 24..sh_offset + 32].try_into().unwrap()) as usize;
                let s_size = u64::from_le_bytes(bytes[sh_offset + 32..sh_offset + 40].try_into().unwrap()) as usize;
                if s_offset + s_size <= elf_len {
                    if let Some(id) = parse_notes(&bytes[s_offset..s_offset + s_size]) {
                        if id.len() + 1 > out_cap {
                            return -3;
                        }
                        unsafe {
                            std::ptr::copy_nonoverlapping(id.as_ptr() as *const c_char, out_hex, id.len());
                            *out_hex.add(id.len()) = 0;
                        }
                        return 0;
                    }
                }
            }
        }
    }

    -4
}

// ============================================================================
// 14. Linux ⇄ Android Keycode & Input Translation Engine
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MocktailRustKeyMapping {
    pub scan_code: i32,
    pub key_code: i32,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_map_sdl_key_to_android(
    sdl_scancode: u32,
    sdl_key: u32,
    out_mapping: *mut MocktailRustKeyMapping,
) -> c_int {
    if out_mapping.is_null() {
        return 0;
    }
    let mapping = match sdl_scancode {
        4 => (30, 29),    // A
        5 => (48, 30),    // B
        6 => (46, 31),    // C
        7 => (32, 32),    // D
        8 => (18, 33),    // E
        9 => (33, 34),    // F
        10 => (34, 35),   // G
        11 => (35, 36),   // H
        12 => (23, 37),   // I
        13 => (36, 38),   // J
        14 => (37, 39),   // K
        15 => (38, 40),   // L
        16 => (50, 41),   // M
        17 => (49, 42),   // N
        18 => (24, 43),   // O
        19 => (25, 44),   // P
        20 => (16, 45),   // Q
        21 => (19, 46),   // R
        22 => (31, 47),   // S
        23 => (20, 48),   // T
        24 => (22, 49),   // U
        25 => (47, 50),   // V
        26 => (17, 51),   // W
        27 => (45, 52),   // X
        28 => (21, 53),   // Y
        29 => (44, 54),   // Z
        30 => (2, 8),     // 1
        31 => (3, 9),     // 2
        32 => (4, 10),    // 3
        33 => (5, 11),    // 4
        34 => (6, 12),    // 5
        35 => (7, 13),    // 6
        36 => (8, 14),    // 7
        37 => (9, 15),    // 8
        38 => (10, 16),   // 9
        39 => (11, 7),    // 0
        40 => (28, 66),   // RETURN
        41 => (1, 111),   // ESCAPE
        42 => (14, 67),   // BACKSPACE
        43 => (15, 61),   // TAB
        44 => (57, 62),   // SPACE
        45 => (12, 69),   // MINUS
        46 => (13, 70),   // EQUALS
        47 => (26, 71),   // LEFTBRACKET
        48 => (27, 72),   // RIGHTBRACKET
        49 => (43, 73),   // BACKSLASH
        51 => (39, 74),   // SEMICOLON
        52 => (40, 75),   // APOSTROPHE
        53 => (41, 68),   // GRAVE
        54 => (51, 55),   // COMMA
        55 => (52, 56),   // PERIOD
        56 => (53, 76),   // SLASH
        57 => (58, 115),  // CAPSLOCK
        58 => (59, 131),  // F1
        59 => (60, 132),  // F2
        60 => (61, 133),  // F3
        61 => (62, 134),  // F4
        62 => (63, 135),  // F5
        63 => (64, 136),  // F6
        64 => (65, 137),  // F7
        65 => (66, 138),  // F8
        66 => (67, 139),  // F9
        67 => (68, 140),  // F10
        68 => (87, 141),  // F11
        69 => (88, 142),  // F12
        70 => (99, 120),  // PRINTSCREEN
        71 => (70, 116),  // SCROLLLOCK
        72 => (119, 121), // PAUSE
        73 => (110, 124), // INSERT
        74 => (102, 122), // HOME
        75 => (104, 92),  // PAGEUP
        76 => (111, 112), // DELETE
        77 => (107, 123), // END
        78 => (109, 93),  // PAGEDOWN
        79 => (106, 22),  // RIGHT
        80 => (105, 21),  // LEFT
        81 => (108, 20),  // DOWN
        82 => (103, 19),  // UP
        83 => (69, 143),  // NUMLOCKCLEAR
        84 => (98, 154),  // KP_DIVIDE
        85 => (55, 155),  // KP_MULTIPLY
        86 => (74, 156),  // KP_MINUS
        87 => (78, 157),  // KP_PLUS
        88 => (96, 160),  // KP_ENTER
        89 => (79, 145),  // KP_1
        90 => (80, 146),  // KP_2
        91 => (81, 147),  // KP_3
        92 => (75, 148),  // KP_4
        93 => (76, 149),  // KP_5
        94 => (77, 150),  // KP_6
        95 => (71, 151),  // KP_7
        96 => (72, 152),  // KP_8
        97 => (73, 153),  // KP_9
        98 => (82, 144),  // KP_0
        99 => (83, 158),  // KP_PERIOD
        224 => (29, 113), // LCTRL
        225 => (42, 59),  // LSHIFT
        226 => (56, 57),  // LALT
        227 => (125, 117),// LGUI
        228 => (97, 114), // RCTRL
        229 => (54, 60),  // RSHIFT
        230 => (100, 58), // RALT
        231 => (126, 118),// RGUI
        232 => (127, 82), // APPLICATION
        _ => {
            let mut fallback_keycode = 0i32;
            if (b'0'..=b'9').contains(&(sdl_key as u8)) {
                fallback_keycode = 7 + (sdl_key as i32 - b'0' as i32);
            } else if (b'a'..=b'z').contains(&(sdl_key as u8)) {
                fallback_keycode = 29 + (sdl_key as i32 - b'a' as i32);
            } else if (b'A'..=b'Z').contains(&(sdl_key as u8)) {
                fallback_keycode = 29 + (sdl_key as i32 - b'A' as i32);
            }
            if fallback_keycode > 0 {
                let scan = if sdl_scancode > 0 { sdl_scancode as i32 } else { fallback_keycode };
                (scan, fallback_keycode)
            } else if sdl_scancode > 0 {
                (sdl_scancode as i32, sdl_scancode as i32)
            } else {
                (0, 0)
            }
        }
    };
    unsafe {
        (*out_mapping).scan_code = mapping.0;
        (*out_mapping).key_code = mapping.1;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_map_sdl_mouse_button(sdl_button: u8) -> i32 {
    match sdl_button {
        1 => 0,  // SDL_BUTTON_LEFT -> Roblox Left (0)
        3 => 1,  // SDL_BUTTON_RIGHT -> Roblox Right (1)
        2 => 2,  // SDL_BUTTON_MIDDLE -> Roblox Middle (2)
        4 => 7,  // SDL_BUTTON_X1 -> Roblox Button 4 / X1 (7)
        5 => 15, // SDL_BUTTON_X2 -> Roblox Button 5 / X2 (15)
        _ => -1,
    }
}

// ============================================================================
// 15. System Proxy & URI Resolver
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_proxy_uri(
    candidate: *const c_char,
    out_scheme: *mut c_char,
    scheme_cap: usize,
    out_host: *mut c_char,
    host_cap: usize,
    out_port: *mut u16,
    out_is_direct: *mut c_int,
    out_has_auth: *mut c_int,
) -> c_int {
    if candidate.is_null()
        || out_scheme.is_null()
        || out_host.is_null()
        || out_port.is_null()
        || out_is_direct.is_null()
        || out_has_auth.is_null()
    {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(candidate) };
    let s = match c_str.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -2,
    };
    if s.is_empty() {
        return -3;
    }
    if s.eq_ignore_ascii_case("direct://") {
        unsafe {
            *out_is_direct = 1;
            *out_has_auth = 0;
            *out_port = 0;
            if scheme_cap > 0 { *out_scheme = 0; }
            if host_cap > 0 { *out_host = 0; }
        }
        return 0;
    }
    unsafe {
        *out_is_direct = 0;
    }
    let parsed_url = match url::Url::parse(s) {
        Ok(u) => u,
        Err(_) => return -4,
    };
    let scheme = parsed_url.scheme();
    let has_auth = !parsed_url.username().is_empty() || parsed_url.password().is_some();
    unsafe {
        *out_has_auth = if has_auth { 1 } else { 0 };
    }
    let host = match parsed_url.host_str() {
        Some(h) => h,
        None => return -5,
    };
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let port = parsed_url.port().unwrap_or(match scheme {
        "http" => 80,
        "https" => 443,
        "socks5" | "socks5h" => 1080,
        _ => 0,
    });
    if port == 0 {
        return -6;
    }
    if scheme.len() + 1 > scheme_cap || clean_host.len() + 1 > host_cap {
        return -7;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(scheme.as_ptr() as *const c_char, out_scheme, scheme.len());
        *out_scheme.add(scheme.len()) = 0;

        std::ptr::copy_nonoverlapping(clean_host.as_ptr() as *const c_char, out_host, clean_host.len());
        *out_host.add(clean_host.len()) = 0;

        *out_port = port;
    }
    0
}

// ============================================================================
// 16. Single Instance Lock & Instance Key
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_compute_instance_key(
    exe_path: *const c_char,
    out_key: *mut c_char,
    out_cap: usize,
) -> c_int {
    if exe_path.is_null() || out_key.is_null() || out_cap < 17 {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(exe_path) };
    let bytes = c_str.to_bytes();
    let mut hash: u64 = 14695981039346656037;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    let hex_str = format!("{:016x}", hash);
    unsafe {
        std::ptr::copy_nonoverlapping(hex_str.as_ptr() as *const c_char, out_key, 16);
        *out_key.add(16) = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_is_positive_decimal(val: *const c_char) -> c_int {
    if val.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(val) };
    let bytes = c_str.to_bytes();
    if bytes.is_empty() || bytes == b"0" {
        return 0;
    }
    if bytes.iter().all(|&b| b >= b'0' && b <= b'9') {
        1
    } else {
        0
    }
}

// ============================================================================
// 17. Compatibility Catalog & Approval Manifest
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustPayloadProfile {
    pub version_name: [c_char; 64],
    pub version_code: u64,
    pub elf_build_id: [c_char; 41],
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_compatibility_catalog(
    json_bytes: *const u8,
    json_len: usize,
    guest_abi: *const c_char,
    out_profiles: *mut MocktailRustPayloadProfile,
    out_cap: usize,
    out_count: *mut usize,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };

    if json_bytes.is_null() || out_count.is_null() || (out_profiles.is_null() && out_cap > 0) {
        set_error("invalid argument");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(json_bytes, json_len) };
    let val: serde_json::Value = match serde_json::from_slice(slice) {
        Ok(v) => v,
        Err(_) => {
            set_error("compatibility manifest is not valid JSON");
            return -2;
        }
    };
    let obj = match val.as_object() {
        Some(o) => o,
        None => {
            set_error("compatibility manifest has an unsupported schema");
            return -3;
        }
    };
    if obj.get("schema_version").and_then(|v| v.as_i64()) != Some(1) {
        set_error("compatibility manifest has an unsupported schema");
        return -4;
    }
    let profiles_arr = match obj.get("profiles").and_then(|p| p.as_array()) {
        Some(a) => a,
        None => {
            set_error("compatibility manifest has an unsupported schema");
            return -5;
        }
    };
    let target_abi = if guest_abi.is_null() {
        "x86_64"
    } else {
        unsafe { CStr::from_ptr(guest_abi).to_str().unwrap_or("x86_64") }
    };

    let mut parsed_list: Vec<MocktailRustPayloadProfile> = Vec::new();
    for p in profiles_arr {
        let p_obj = match p.as_object() {
            Some(o) => o,
            None => continue,
        };
        if let Some(status) = p_obj.get("status") {
            if !status.is_string() {
                set_error("compatibility profile has invalid policy field types");
                return -6;
            }
            if status.as_str() != Some("supported") {
                continue;
            }
        } else {
            continue;
        }
        if let Some(allowed) = p_obj.get("default_allowed") {
            if !allowed.is_boolean() {
                set_error("compatibility profile has invalid policy field types");
                return -6;
            }
            if allowed.as_bool() != Some(true) {
                continue;
            }
        } else {
            continue;
        }
        if let Some(patches) = p_obj.get("allow_legacy_binary_patches") {
            if !patches.is_boolean() {
                set_error("compatibility profile has invalid policy field types");
                return -6;
            }
            if patches.as_bool() != Some(false) {
                continue;
            }
        } else {
            continue;
        }
        let profile_abi = match p_obj.get("abi") {
            Some(v) => match v.as_str() {
                Some(s) => s,
                None => {
                    set_error("supported compatibility profile is incomplete");
                    return -7;
                }
            },
            None => "x86_64",
        };
        if profile_abi != target_abi {
            continue;
        }
        let version_name = match p_obj.get("version_name").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => {
                set_error("supported compatibility profile is incomplete");
                return -8;
            }
        };
        let version_code = match p_obj.get("version_code").and_then(|v| v.as_u64()) {
            Some(c) if c > 0 => c,
            _ => {
                set_error("supported compatibility profile is incomplete");
                return -9;
            }
        };
        let elf_build_id = match p_obj.get("elf_build_id").and_then(|v| v.as_str()) {
            Some(s) if s.len() == 40 && s.bytes().all(|b| (b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F')) => s,
            _ => {
                set_error("supported compatibility profile has invalid identity");
                return -10;
            }
        };

        let mut prof = MocktailRustPayloadProfile {
            version_name: [0; 64],
            version_code,
            elf_build_id: [0; 41],
        };
        let vn_bytes = version_name.as_bytes();
        let vn_len = std::cmp::min(vn_bytes.len(), 63);
        unsafe {
            std::ptr::copy_nonoverlapping(vn_bytes.as_ptr() as *const c_char, prof.version_name.as_mut_ptr(), vn_len);
        }
        let id_lower = elf_build_id.to_ascii_lowercase();
        unsafe {
            std::ptr::copy_nonoverlapping(id_lower.as_ptr() as *const c_char, prof.elf_build_id.as_mut_ptr(), 40);
        }
        parsed_list.push(prof);
    }
    if parsed_list.is_empty() {
        set_error("compatibility manifest has no default-supported payload");
        return -11;
    }
    let count = std::cmp::min(parsed_list.len(), out_cap);
    if count > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(parsed_list.as_ptr(), out_profiles, count);
        }
    }
    unsafe {
        *out_count = parsed_list.len();
    }
    0
}

// ============================================================================
// 18. Crash Report Policy & FFlags Injection
// ============================================================================

static CRASH_SETTINGS: &[(&str, &str)] = &[
    ("DFFlagUseCrashpad", "False"),
    ("FFlagUseCrashpad", "False"),
    ("UseCrashpad", "False"),
    ("UseAppCrashpadReporterAndroid", "False"),
    ("FFlagUseAppCrashpadReporterForAndroidHangMonitor", "False"),
    ("FFlagUseCrashpadDirectlyForAndroidHangMonitor", "False"),
    ("EnableAppHangMonitor", "False"),
    ("CrashpadUploadToBacktraceUrl", ""),
    ("CrashpadUploadToBacktraceAndroidPlayerToken", ""),
    ("CrashpadUploadToBacktraceAndroidPlayerToken_PlaceFilter", ""),
    ("DFStringCrashpadUploadToBacktraceAndroidPlayerToken", ""),
    ("DFStringCrashpadUploadToBacktraceAndroidPlayerToken_PlaceFilter", ""),
    ("CrashpadUploadAttachmentKiloByteLimit", "0"),
    ("DFIntCrashUploadAttachmentKiloByteLimit", "0"),
    ("DFIntCrashReportingHundredthsPercentage", "0"),
    ("CrashUploadToBacktraceBaseUrl", ""),
    ("DFStringCrashUploadToBacktraceBaseUrl", ""),
    ("CrashUploadToBacktracePercentage", "0"),
    ("DFIntCrashUploadToBacktracePercentage", "0"),
    ("DFIntCrashUploadToBacktracePercentage_DataCenterFilter", ""),
    ("DFIntCrashUploadToBacktracePercentage_PlaceFilter", ""),
    ("CrashUploadToBacktraceRolloutMinimumEnabled", "False"),
    ("DFFlagCrashUploadToBacktraceRolloutMinimumEnabled", "False"),
    ("CrashUploadToBacktraceRolloutMinimumPercentage", "0"),
    ("DFIntCrashUploadToBacktraceRolloutMinimumPercentage", "0"),
    ("ErrorUploadToBacktraceBaseUrl", ""),
    ("DFStringErrorUploadToBacktraceBaseUrl", ""),
    ("ErrorUploadToBacktraceLuaAppToken", ""),
    ("DFStringErrorUploadToBacktraceLuaAppToken", ""),
    ("JavaCrashUploadToBacktracePercentage", "0"),
    ("JavaCrashUploadToBacktraceUrl", ""),
    ("JavaCrashUploadToBacktraceToken", ""),
    ("JavaANRUploadToBacktracePercentage", "0"),
    ("DFFlagReportCrashReasonWithTelemetry", "False"),
    ("DFFlagUseCrashReportLogGroup", "False"),
    ("DFFlagEnableCrashHandlerSessionDurationAndroid", "False"),
    ("DFFlagCrashMetricStorageEnableBufferConstantReporting", "False"),
    ("DFIntCrashMetricStorageHundredthPercentageSent", "0"),
    ("DFIntSessionReportCrashErrorEventIngestThrottleHundredthsPercent", "0"),
    ("DFIntSessionReportCrashErrorPointsThrottleHundredthsPercent", "0"),
    ("FIntCoreScriptBacktraceErrorReportPercentage", "0"),
    ("FIntLuaAppBacktraceErrorReportPercentage", "0"),
    ("FStringCoreScriptBacktraceErrorUploadToken", ""),
    ("FFlagBacktraceReporterSourceCodeFieldAndEndpoint2", "False"),
    ("FFlagUserAgentInBacktraceReports", "False"),
    ("FFlagEnableBacktraceRobloxChannel2", "False"),
    ("FStringBacktraceLogTags", ""),
    ("BacktraceLogSize", "0"),
    ("DFIntBacktraceMetricKitUploadHundrethsPercent", "0"),
    ("FFlagEnableBacktraceMetricKitReporter2", "False"),
    ("FFlagEnableBacktraceMetricKitReporter3", "False"),
    ("FFlagenableBacktraceMetricKitReporterMinidump", "False"),
    ("FFlagEnablePLCrashReporterApi", "False"),
    ("DFFlagInferredCrashReportToBacktrace", "False"),
    ("DFFlagInferredCrashReportToBacktrace2", "False"),
    ("InferredCrashReportToBacktrace", "False"),
    ("InferredCrashReportToBacktraceRegister", "False"),
    ("DFFlagInferredCrashReportToBacktraceRegister", "False"),
    ("InferredCrashReportSynchronous", "False"),
    ("DFFlagInferredCrashReportSynchronous", "False"),
    ("FFlagInferredCrashReportSynchronous", "False"),
    ("InferredCrashReportToBacktraceHundredthPercent", "0"),
    ("DFIntInferredCrashReportToBacktraceHundredthPercent", "0"),
    ("InferredCrashReportToBacktraceThrottleHundredthsPercentage", "0"),
    ("DFIntInferredCrashReportToBacktraceThrottleHundredthsPercentage", "0"),
    ("InferredCrashReportBacktraceToken", ""),
    ("DFStringInferredCrashReportBacktraceToken", ""),
    ("InferredCrashReportBacktraceTokenSync", ""),
    ("DFStringInferredCrashReportBacktraceTokenSync", ""),
    ("DFFlagObtainAndroidInferredCrashExitLog", "False"),
    ("DFFlagStoreUniqueIdInferredCrashSystem", "False"),
    ("FFlagLuaAppInferredCrashReportOnStateChange", "False"),
    ("FFlagVideoSessionTrackingOnInferredCrash", "False"),
    ("SkipReportingIsolatedProcessAsInferredCrash", "True"),
    ("FFlagEnableIsolatedAdsBacktrace", "False"),
    ("FFlagEnableIsolatedAdsBacktraceAnrDetection", "False"),
    ("FIntIsolatedAdsBacktraceCrashUploadPercent", "0"),
    ("FIntIsolatedAdsBacktraceAnrUploadPercent", "0"),
];

#[inline]
fn is_fast_variable(name: &str) -> bool {
    const PREFIXES: &[&str] = &["DFFlag", "DFInt", "DFString", "FFlag", "FInt", "FString"];
    PREFIXES.iter().any(|&p| name.starts_with(p))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_merge_crash_report_settings(
    base_json: *const c_char,
    fast_flags_only: c_int,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let base_slice = if base_json.is_null() {
        b"{}"
    } else {
        let c_str = unsafe { CStr::from_ptr(base_json) };
        let b = c_str.to_bytes();
        if b.is_empty() { b"{}" } else { b }
    };
    let mut root: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(base_slice) {
        Ok(v) if v.is_object() => v,
        _ => return -2,
    };
    let obj = match root.as_object_mut() {
        Some(o) => o,
        None => return -3,
    };
    for &(name, val) in CRASH_SETTINGS {
        if fast_flags_only == 0 || is_fast_variable(name) {
            obj.insert(name.to_string(), serde_json::Value::String(val.to_string()));
        }
    }
    let dumped = match serde_json::to_string(&root) {
        Ok(s) => s,
        Err(_) => return -4,
    };
    if dumped.len() + 1 > out_cap {
        return -5;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dumped.as_ptr() as *const c_char, out_buf, dumped.len());
        *out_buf.add(dumped.len()) = 0;
        *out_len = dumped.len();
    }
    0
}

// ============================================================================
// 19. Device Profile & Hardware Presets
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_canonical_device_profile_name(
    name: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
) -> c_int {
    if name.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(name) };
    let s = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let canonical = match s {
        "pc" => "pc-windows-11",
        "mobile" => "mobile-pixel-7",
        "console" | "console-xbox-series-x" => "console-ps5",
        other => other,
    };
    if canonical.len() + 1 > out_cap {
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(canonical.as_ptr() as *const c_char, out_buf, canonical.len());
        *out_buf.add(canonical.len()) = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_device_profile_value(
    value: *const c_char,
    maximum: usize,
) -> c_int {
    if value.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(value) };
    let bytes = c_str.to_bytes();
    if bytes.is_empty() || bytes.len() > maximum {
        return 0;
    }
    if bytes.iter().all(|&b| b >= 0x20 && b != 0x7F) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_build_device_profile_cache_key(
    name: *const c_char,
    platform: *const c_char,
    display: *const c_char,
    manufacturer: *const c_char,
    model: *const c_char,
    brand: *const c_char,
    code: *const c_char,
    sku: *const c_char,
    soc: *const c_char,
    out_key: *mut c_char,
    out_cap: usize,
) -> c_int {
    if name.is_null() || out_key.is_null() {
        return -1;
    }
    let fields = [name, platform, display, manufacturer, model, brand, code, sku, soc];
    let mut hash: u64 = 14695981039346656037;
    for &f in &fields {
        if !f.is_null() {
            let bytes = unsafe { CStr::from_ptr(f) }.to_bytes();
            for &b in bytes {
                hash ^= b as u64;
                hash = hash.wrapping_mul(1099511628211);
            }
        }
        hash ^= 0xFF;
        hash = hash.wrapping_mul(1099511628211);
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = format!("{}-custom-{:016x}", name_str, hash);
    if key.len() + 1 > out_cap {
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr() as *const c_char, out_key, key.len());
        *out_key.add(key.len()) = 0;
    }
    0
}

// ============================================================================
// 20. Bionic DNS & Crash Host Blocker
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_is_blocked_crash_host(host: *const c_char) -> c_int {
    if host.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(host) };
    let s = match c_str.to_str() {
        Ok(s) => s.trim_end_matches('.'),
        Err(_) => return 0,
    };
    const BLOCKED: &[&str] = &["crashes.rbxinfra.com", "backtrace.rbx.com", "backtrace.io"];
    for &suffix in BLOCKED {
        if s.eq_ignore_ascii_case(suffix) {
            return 1;
        }
        if s.len() > suffix.len() {
            let prefix_len = s.len() - suffix.len();
            if s.as_bytes()[prefix_len - 1] == b'.' && s[prefix_len..].eq_ignore_ascii_case(suffix) {
                return 1;
            }
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_bionic_eai_error(posix_error: c_int) -> c_int {
    if posix_error == 0 {
        return 0;
    }
    match posix_error {
        -1 => 3,   // EAI_BADFLAGS
        -2 => 8,   // EAI_NONAME -> kBionicAddressInfoNameNotFound
        -3 => 2,   // EAI_AGAIN
        -4 => 4,   // EAI_FAIL -> kBionicAddressInfoFailure
        -6 => 5,   // EAI_FAMILY
        -7 => 10,  // EAI_SOCKTYPE
        -8 => 9,   // EAI_SERVICE
        -10 => 6,  // EAI_MEMORY -> kBionicAddressInfoMemory
        -11 => 11, // EAI_SYSTEM
        -12 => 14, // EAI_OVERFLOW
        _ => 4,    // kBionicAddressInfoFailure
    }
}

// ============================================================================
// 21. Roblox Launch URI & Deep Links
// ============================================================================

fn percent_decode_helper(encoded: &str, plus_as_space: bool) -> Result<String, &'static str> {
    if encoded.len() > 16384 {
        return Err("Roblox launch parameter size is invalid");
    }
    let bytes = encoded.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("Roblox launch URI contains invalid percent encoding");
            }
            let h = match (bytes[i + 1] as char).to_digit(16) {
                Some(v) => v as u8,
                None => return Err("Roblox launch URI contains invalid percent encoding"),
            };
            let l = match (bytes[i + 2] as char).to_digit(16) {
                Some(v) => v as u8,
                None => return Err("Roblox launch URI contains invalid percent encoding"),
            };
            decoded.push((h << 4) | l);
            i += 3;
        } else if bytes[i] == b'+' && plus_as_space {
            decoded.push(b' ');
            i += 1;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    if decoded.iter().any(|&b| b < 0x20 || b == 0x7F) {
        return Err("Roblox launch URI contains a control byte");
    }
    let s = String::from_utf8(decoded).map_err(|_| "Roblox launch parameter is not bounded UTF-8")?;
    if s.len() > 16384 {
        return Err("Roblox launch parameter is not bounded UTF-8");
    }
    Ok(s)
}

#[derive(Default, Debug)]
struct ParsedLaunchFields {
    place_id: i64,
    user_id: i64,
    conversation_id: i64,
    referred_by_player_id: i64,
    request_type: String,
    game_instance_id: String,
    reserved_server_access_code: String,
    call_id: String,
    referral_page: String,
    access_code: String,
    link_code: String,
    launch_data: String,
    event_id: String,
    game_join_context: String,
    join_attempt_id: String,
    join_attempt_origin: String,
    iso_context: String,
    seen_fields: std::collections::HashSet<String>,
}

fn assign_launch_field(
    raw_key: &str,
    mut value: String,
    decode_modern_launch_data: bool,
    fields: &mut ParsedLaunchFields,
) -> Result<(), &'static str> {
    if raw_key.is_empty() || raw_key.len() > 128 {
        return Err("Roblox launch parameter key is invalid");
    }
    let key = raw_key.to_ascii_lowercase();
    let canonical = match key.as_str() {
        "request" | "requesttype" => "request",
        "placeid" => "placeId",
        "userid" => "userId",
        "conversationid" => "conversationId",
        "referredbyplayerid" => "referredByPlayerId",
        "gameid" | "gameinstanceid" | "instanceid" => "gameInstanceId",
        "reservedserveraccesscode" => "reservedServerAccessCode",
        "callid" => "callId",
        "referralpage" => "referralPage",
        "accesscode" => "accessCode",
        "linkcode" | "privateserverlinkcode" => "linkCode",
        "launchdata" => "launchData",
        "eventid" => "eventId",
        "gamejoincontext" => "gameJoinContext",
        "joinattemptid" => "joinAttemptId",
        "joinattemptorigin" => "joinAttemptOrigin",
        "isocontext" => "isoContext",
        _ => return Ok(()),
    };
    if !fields.seen_fields.insert(canonical.to_string()) {
        return Err("Roblox launch URI repeats a singleton field");
    }
    if canonical == "launchData" && decode_modern_launch_data && value.contains('%') {
        value = percent_decode_helper(&value, false)?;
    }
    match canonical {
        "request" => fields.request_type = value,
        "placeId" => fields.place_id = parse_decimal_int(&value, false)?,
        "userId" => fields.user_id = parse_decimal_int(&value, true)?,
        "conversationId" => fields.conversation_id = parse_decimal_int(&value, true)?,
        "referredByPlayerId" => fields.referred_by_player_id = parse_decimal_int(&value, true)?,
        "gameInstanceId" => fields.game_instance_id = value,
        "reservedServerAccessCode" => fields.reserved_server_access_code = value,
        "callId" => fields.call_id = value,
        "referralPage" => fields.referral_page = value,
        "accessCode" => fields.access_code = value,
        "linkCode" => fields.link_code = value,
        "launchData" => fields.launch_data = value,
        "eventId" => fields.event_id = value,
        "gameJoinContext" => fields.game_join_context = value,
        "joinAttemptId" => fields.join_attempt_id = value,
        "joinAttemptOrigin" => fields.join_attempt_origin = value,
        "isoContext" => fields.iso_context = value,
        _ => {}
    }
    Ok(())
}

fn parse_decimal_int(val: &str, allow_zero: bool) -> Result<i64, &'static str> {
    if val.is_empty() || val.starts_with('+') || val.starts_with('-') {
        return Err("Roblox launch integer is invalid");
    }
    match val.parse::<i64>() {
        Ok(n) if n >= 0 && (allow_zero || n > 0) => Ok(n),
        _ => Err("Roblox launch integer is invalid"),
    }
}

fn parse_launch_query(
    query: &str,
    decode_modern_launch_data: bool,
    fields: &mut ParsedLaunchFields,
) -> Result<(), &'static str> {
    if query.is_empty() {
        return Err("Roblox launch URI query is missing");
    }
    let mut count = 0;
    for pair in query.split('&') {
        count += 1;
        if count > 64 {
            return Err("Roblox launch URI has too many parameters");
        }
        if pair.is_empty() {
            return Err("Roblox launch URI contains an empty parameter");
        }
        let equals = pair.find('=').ok_or("Roblox launch URI parameter has no value")?;
        if equals == 0 {
            return Err("Roblox launch URI parameter has no value");
        }
        let key = percent_decode_helper(&pair[..equals], true)?;
        let val = percent_decode_helper(&pair[equals + 1..], true)?;
        assign_launch_field(&key, val, decode_modern_launch_data, fields)?;
    }
    Ok(())
}

fn parse_place_launcher_url(launcher_url: &str, fields: &mut ParsedLaunchFields) -> Result<(), &'static str> {
    if launcher_url.is_empty() || launcher_url.len() > 2048 {
        return Err("Roblox PlaceLauncher URL is invalid");
    }
    let parsed = url::Url::parse(launcher_url).map_err(|_| "Roblox PlaceLauncher URL cannot be parsed")?;
    if parsed.scheme().to_ascii_lowercase() != "https" {
        return Err("Roblox PlaceLauncher URL origin or path is not allowed");
    }
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    if host != "www.roblox.com" && host != "roblox.com" && host != "assetgame.roblox.com" {
        return Err("Roblox PlaceLauncher URL origin or path is not allowed");
    }
    if parsed.path().to_ascii_lowercase() != "/game/placelauncher.ashx" {
        return Err("Roblox PlaceLauncher URL origin or path is not allowed");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("Roblox PlaceLauncher URL origin or path is not allowed");
    }
    if let Some(port) = parsed.port() {
        if port != 443 {
            return Err("Roblox PlaceLauncher URL port is not allowed");
        }
    }
    let query = parsed.query().ok_or("Roblox PlaceLauncher URL has no query")?;
    parse_launch_query(query, false, fields)
}

fn parse_classic_payload(payload: &str, fields: &mut ParsedLaunchFields) -> Result<(), &'static str> {
    if payload.is_empty() {
        return Err("Roblox player launch payload is missing");
    }
    let mut version_seen = false;
    let mut launch_mode_seen = false;
    let mut launcher_url_seen = false;
    let mut launcher_url = String::new();
    let mut count = 0;
    for field in payload.split('+') {
        count += 1;
        if count > 64 {
            return Err("Roblox player launch payload has too many fields");
        }
        if field.len() > 128 + 1 + 16384 {
            return Err("Roblox player launch field is too large");
        }
        if !version_seen {
            if field != "1" {
                return Err("Roblox player launch version is unsupported");
            }
            version_seen = true;
        } else {
            let colon = field.find(':').ok_or("Roblox player launch field is malformed")?;
            if colon == 0 {
                return Err("Roblox player launch field is malformed");
            }
            let key = field[..colon].to_ascii_lowercase();
            let encoded_value = &field[colon + 1..];
            if key == "launchmode" {
                if launch_mode_seen {
                    return Err("Roblox player launch repeats launchmode");
                }
                launch_mode_seen = true;
                let mode = percent_decode_helper(encoded_value, false)?;
                if mode.to_ascii_lowercase() != "play" {
                    return Err("Roblox player launch mode is unsupported");
                }
            } else if key == "placelauncherurl" {
                if launcher_url_seen {
                    return Err("Roblox player launch repeats PlaceLauncher URL");
                }
                launcher_url_seen = true;
                launcher_url = percent_decode_helper(encoded_value, false)?;
            }
        }
    }
    if !version_seen || !launch_mode_seen || !launcher_url_seen {
        return Err("Roblox player launch contract is incomplete");
    }
    parse_place_launcher_url(&launcher_url, fields)?;
    if fields.request_type.is_empty() {
        return Err("Roblox PlaceLauncher request type is missing");
    }
    Ok(())
}

fn parse_modern_payload(payload: &str, fields: &mut ParsedLaunchFields) -> Result<(), &'static str> {
    let lower = payload.to_ascii_lowercase();
    let query;
    let decode_launch_data_twice;
    if lower.starts_with("//experiences/start?") {
        query = &payload["//experiences/start?".len()..];
        decode_launch_data_twice = true;
    } else if lower.starts_with("//placeid=") {
        query = &payload[2..];
        decode_launch_data_twice = false;
    } else {
        return Err("Roblox launch path is unsupported");
    }
    if query.contains('#') || query.contains('/') {
        return Err("Roblox launch URI contains an unsupported fragment");
    }
    parse_launch_query(query, decode_launch_data_twice, fields)
}

fn validate_launch_selectors(fields: &ParsedLaunchFields) -> Result<(), &'static str> {
    let private_join = !fields.access_code.is_empty() || !fields.link_code.is_empty();
    let selectors = [
        fields.user_id > 0,
        fields.conversation_id > 0,
        private_join,
        !fields.game_instance_id.is_empty(),
        !fields.reserved_server_access_code.is_empty(),
    ];
    let selector_count = selectors.iter().filter(|&&b| b).count();
    if selector_count > 1 {
        return Err("Roblox launch URI contains conflicting join selectors");
    }
    if fields.request_type.is_empty() {
        return Ok(());
    }
    let req = fields.request_type.to_ascii_lowercase();
    match req.as_str() {
        "requestgame" => {
            if selector_count != 0 {
                return Err("RequestGame contains a non-public join selector");
            }
        }
        "requestgamejob" => {
            if fields.game_instance_id.is_empty() {
                return Err("RequestGameJob requires a game instance");
            }
        }
        "requestprivategame" => {
            if !private_join && fields.reserved_server_access_code.is_empty() {
                return Err("RequestPrivateGame requires an access code");
            }
        }
        "requestplaytogethergame" => {
            if fields.conversation_id <= 0 {
                return Err("RequestPlayTogetherGame requires a conversation");
            }
        }
        "requestfollowuser" => {
            if fields.place_id <= 0 {
                return Err("RequestFollowUser could not resolve a place");
            }
        }
        _ => return Err("Roblox PlaceLauncher request type is unsupported"),
    }
    Ok(())
}

fn build_launch_json(fields: &ParsedLaunchFields) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("placeId".to_string(), serde_json::json!(fields.place_id));
    if fields.user_id > 0 {
        map.insert("userId".to_string(), serde_json::json!(fields.user_id));
    }
    if fields.conversation_id > 0 {
        map.insert("conversationId".to_string(), serde_json::json!(fields.conversation_id));
    }
    if fields.referred_by_player_id > 0 {
        map.insert("referredByPlayerId".to_string(), serde_json::json!(fields.referred_by_player_id));
    }
    if !fields.game_instance_id.is_empty() {
        map.insert("gameInstanceId".to_string(), serde_json::json!(fields.game_instance_id));
    }
    if !fields.reserved_server_access_code.is_empty() {
        map.insert("reservedServerAccessCode".to_string(), serde_json::json!(fields.reserved_server_access_code));
    }
    if !fields.call_id.is_empty() {
        map.insert("callId".to_string(), serde_json::json!(fields.call_id));
    }
    if !fields.referral_page.is_empty() {
        map.insert("referralPage".to_string(), serde_json::json!(fields.referral_page));
    }
    if !fields.access_code.is_empty() {
        map.insert("accessCode".to_string(), serde_json::json!(fields.access_code));
    }
    if !fields.link_code.is_empty() {
        map.insert("linkCode".to_string(), serde_json::json!(fields.link_code));
    }
    if !fields.launch_data.is_empty() {
        map.insert("launchData".to_string(), serde_json::json!(fields.launch_data));
    }
    if !fields.event_id.is_empty() {
        map.insert("eventId".to_string(), serde_json::json!(fields.event_id));
    }
    if !fields.game_join_context.is_empty() {
        map.insert("gameJoinContext".to_string(), serde_json::json!(fields.game_join_context));
    }
    if !fields.join_attempt_id.is_empty() {
        map.insert("joinAttemptId".to_string(), serde_json::json!(fields.join_attempt_id));
    }
    if !fields.join_attempt_origin.is_empty() {
        map.insert("joinAttemptOrigin".to_string(), serde_json::json!(fields.join_attempt_origin));
    }
    if !fields.iso_context.is_empty() {
        map.insert("isoContext".to_string(), serde_json::json!(fields.iso_context));
    }
    serde_json::Value::Object(map)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_roblox_launch_uri(
    uri: *const c_char,
    override_place_id: i64,
    override_game_instance: *const c_char,
    out_json: *mut c_char,
    out_cap: usize,
    out_error: *mut c_char,
    error_cap: usize,
    out_follow_user_id: *mut i64,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };

    if uri.is_null() || out_json.is_null() || out_cap == 0 {
        set_error("invalid argument");
        return -1;
    }
    let uri_str = match unsafe { CStr::from_ptr(uri) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("Roblox launch URI size or encoding is invalid");
            return -2;
        }
    };
    if uri_str.is_empty() || uri_str.len() > 2048 || uri_str.bytes().any(|b| b < 0x20 || b == 0x7F) {
        set_error("Roblox launch URI size or encoding is invalid");
        return -3;
    }
    let colon = match uri_str.find(':') {
        Some(pos) if pos > 0 => pos,
        _ => {
            set_error("Roblox launch URI has no supported scheme");
            return -4;
        }
    };
    let scheme = uri_str[..colon].to_ascii_lowercase();
    let payload = &uri_str[colon + 1..];

    let mut fields = ParsedLaunchFields::default();
    let parse_res = match scheme.as_str() {
        "roblox-player" => parse_classic_payload(payload, &mut fields),
        "roblox" => parse_modern_payload(payload, &mut fields),
        _ => {
            set_error("Roblox launch URI scheme is unsupported");
            return -5;
        }
    };
    if let Err(e) = parse_res {
        set_error(e);
        return -6;
    }

    let is_follow_user = fields.request_type.to_ascii_lowercase() == "requestfollowuser";
    if override_place_id > 0 {
        fields.place_id = override_place_id;
        if !override_game_instance.is_null() {
            if let Ok(inst) = unsafe { CStr::from_ptr(override_game_instance) }.to_str() {
                if !inst.is_empty() {
                    fields.game_instance_id = inst.to_string();
                }
            }
        }
        fields.user_id = 0;
    } else if fields.place_id <= 0 && is_follow_user {
        if !out_follow_user_id.is_null() {
            unsafe { *out_follow_user_id = fields.user_id; }
        }
        return 1; // Needs user_id -> place_id resolution in C++
    }

    if fields.place_id <= 0 && !is_follow_user {
        set_error("Roblox launch URI requires a positive placeId");
        return -7;
    }

    if let Err(e) = validate_launch_selectors(&fields) {
        set_error(e);
        return -8;
    }

    let doc = build_launch_json(&fields);
    let dumped = doc.to_string();
    if dumped.len() + 1 > out_cap {
        set_error("output buffer too small");
        return -9;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dumped.as_ptr() as *const c_char, out_json, dumped.len());
        *out_json.add(dumped.len()) = 0;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_webview_launch_game(
    command_json: *const c_char,
    override_place_id: i64,
    override_game_instance: *const c_char,
    out_json: *mut c_char,
    out_cap: usize,
    out_error: *mut c_char,
    error_cap: usize,
    out_follow_user_id: *mut i64,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if command_json.is_null() || out_json.is_null() || out_cap == 0 {
        set_error("invalid argument");
        return -1;
    }
    let cmd_str = match unsafe { CStr::from_ptr(command_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("WebView command is invalid UTF-8");
            return -2;
        }
    };
    if cmd_str.len() > 2048 {
        set_error("WebView command exceeds maximum size");
        return -3;
    }
    let val: serde_json::Value = match serde_json::from_str(cmd_str) {
        Ok(v) => v,
        Err(_) => {
            set_error("WebView command is not launchGame");
            return -4;
        }
    };
    if val.get("functionName").and_then(|v| v.as_str()) != Some("launchGame") {
        set_error("WebView command is not launchGame");
        return -5;
    }
    let req_obj = match val.get("params").and_then(|p| p.get("request")).and_then(|r| r.as_object()) {
        Some(o) => o,
        None => {
            set_error("Roblox launchGame has no request");
            return -6;
        }
    };
    if req_obj.len() > 64 {
        set_error("Roblox launchGame request has too many fields");
        return -7;
    }
    let mut fields = ParsedLaunchFields::default();
    for (k, v) in req_obj {
        let text = if let Some(s) = v.as_str() {
            s.to_string()
        } else if let Some(n) = v.as_u64() {
            n.to_string()
        } else if let Some(n) = v.as_i64() {
            n.to_string()
        } else {
            continue;
        };
        if text.len() > 16384 || text.bytes().any(|b| b < 0x20 || b == 0x7F) {
            set_error("Roblox launchGame field is invalid");
            return -8;
        }
        let key_name = if k == "requestType" { "request" } else { k.as_str() };
        if let Err(e) = assign_launch_field(key_name, text, false, &mut fields) {
            set_error(e);
            return -9;
        }
    }
    if fields.request_type.is_empty() {
        set_error("Roblox launchGame request type is missing");
        return -10;
    }

    let is_follow_user = fields.request_type.to_ascii_lowercase() == "requestfollowuser";
    if override_place_id > 0 {
        fields.place_id = override_place_id;
        if !override_game_instance.is_null() {
            if let Ok(inst) = unsafe { CStr::from_ptr(override_game_instance) }.to_str() {
                if !inst.is_empty() {
                    fields.game_instance_id = inst.to_string();
                }
            }
        }
        fields.user_id = 0;
    } else if fields.place_id <= 0 && is_follow_user {
        if !out_follow_user_id.is_null() {
            unsafe { *out_follow_user_id = fields.user_id; }
        }
        return 1;
    }

    if fields.place_id <= 0 && !is_follow_user {
        set_error("Roblox launch URI requires a positive placeId");
        return -11;
    }
    if let Err(e) = validate_launch_selectors(&fields) {
        set_error(e);
        return -12;
    }
    let doc = build_launch_json(&fields);
    let dumped = doc.to_string();
    if dumped.len() + 1 > out_cap {
        set_error("output buffer too small");
        return -13;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dumped.as_ptr() as *const c_char, out_json, dumped.len());
        *out_json.add(dumped.len()) = 0;
    }
    0
}

// ============================================================================
// 22. YAML Runtime Configuration Parser
// ============================================================================

fn flatten_yaml_node(
    prefix: &str,
    node: &serde_yaml::Value,
    depth: usize,
    max_depth: usize,
    map: &mut std::collections::HashMap<String, String>,
) -> Result<(), String> {
    match node {
        serde_yaml::Value::Mapping(m) => {
            if depth > max_depth {
                return Err(format!("{} must be a scalar", prefix));
            }
            let mut keys_seen = std::collections::HashSet::new();
            for (k, v) in m {
                let key_str = match k.as_str() {
                    Some(s) if !s.is_empty() => s,
                    _ => return Err(format!("{} contains a non-scalar or empty key", prefix)),
                };
                if !keys_seen.insert(key_str.to_string()) {
                    return Err(format!("{} contains duplicate key: {}", prefix, key_str));
                }
                let new_path = if prefix.is_empty() {
                    key_str.to_string()
                } else {
                    format!("{}.{}", prefix, key_str)
                };
                match v {
                    serde_yaml::Value::Mapping(_) => {
                        if depth >= max_depth {
                            return Err(format!("{} must be a scalar", new_path));
                        }
                        flatten_yaml_node(&new_path, v, depth + 1, max_depth, map)?;
                    }
                    serde_yaml::Value::String(s) => {
                        map.insert(new_path, s.clone());
                    }
                    serde_yaml::Value::Number(n) => {
                        map.insert(new_path, n.to_string());
                    }
                    serde_yaml::Value::Bool(b) => {
                        map.insert(new_path, if *b { "true".to_string() } else { "false".to_string() });
                    }
                    serde_yaml::Value::Null => {
                        map.insert(new_path, String::new());
                    }
                    _ => return Err(format!("{} must be a scalar", new_path)),
                }
            }
            Ok(())
        }
        _ => Err(format!("{} must be a mapping", prefix)),
    }
}

fn parse_yaml_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_runtime_config_yaml(
    yaml_bytes: *const u8,
    yaml_len: usize,
    out_env_json: *mut c_char,
    out_cap: usize,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if yaml_bytes.is_null() || out_env_json.is_null() || out_cap == 0 {
        set_error("invalid argument");
        return -1;
    }
    if yaml_len > 1024 * 1024 {
        set_error("runtime configuration file exceeds maximum allowed size");
        return -2;
    }
    let slice = unsafe { slice::from_raw_parts(yaml_bytes, yaml_len) };
    let parsed_val: serde_yaml::Value = match serde_yaml::from_slice(slice) {
        Ok(v) => v,
        Err(e) => {
            set_error(&format!("runtime configuration contains invalid YAML: {}", e));
            return -3;
        }
    };
    let root_map = match parsed_val.as_mapping() {
        Some(m) => m,
        None => {
            set_error("root must be a mapping");
            return -4;
        }
    };

    let mut values = std::collections::HashMap::new();
    for (k, v) in root_map {
        let key_str = match k.as_str() {
            Some(s) => s,
            None => {
                set_error("root contains non-scalar key");
                return -5;
            }
        };
        if key_str == "device" {
            if let Some(s) = v.as_str() {
                values.insert("device".to_string(), s.to_string());
            } else if v.is_mapping() {
                values.insert("device.__mapping".to_string(), "1".to_string());
                if let Err(e) = flatten_yaml_node("device", v, 1, 1, &mut values) {
                    set_error(&e);
                    return -6;
                }
            } else {
                set_error("device must be a preset scalar or detailed mapping");
                return -7;
            }
        } else if [
            "runtime", "appearance", "auth", "graphics", "performance",
            "audio", "window", "input", "compatibility", "network",
        ].contains(&key_str) {
            if let Err(e) = flatten_yaml_node(key_str, v, 1, 1, &mut values) {
                set_error(&e);
                return -8;
            }
        } else if key_str == "integrations" {
            if let Err(e) = flatten_yaml_node("integrations", v, 1, 3, &mut values) {
                set_error(&e);
                return -9;
            }
        } else if key_str == "version" {
            if let Some(s) = v.as_str() {
                values.insert("version".to_string(), s.to_string());
            } else if let Some(n) = v.as_i64() {
                values.insert("version".to_string(), n.to_string());
            }
        }
    }

    const SUPPORTED: &[&str] = &[
        "version", "device", "device.__mapping", "device.type", "device.platform",
        "device.name", "device.manufacturer", "device.model", "device.brand",
        "device.code", "device.sku", "device.soc_model", "device.touch",
        "device.mouse", "device.keyboard", "runtime.headless", "auth.use_libsecret",
        "runtime.roblox_library", "appearance.theme", "graphics.backend",
        "graphics.frame_rate_limit", "graphics.vsync", "graphics.present_mode",
        "performance.multithreaded_rendering", "performance.physics_worker_mode",
        "performance.memory_limit_mb", "performance.gamemode", "audio.output_device",
        "audio.input_device", "window.width", "window.height", "window.title",
        "window.high_dpi", "input.touch_enabled", "compatibility.desktop_playability",
        "network.use_system_proxy", "network.proxy_host", "network.proxy_port",
        "network.proxy_scheme", "network.proxy_username", "network.proxy_password",
        "network.ca_bundle", "integrations.fleasion.enabled", "integrations.fleasion.proxy_mode",
        "integrations.fleasion.proxy_port", "integrations.fleasion.ca_certificate",
        "integrations.discord_rpc.enabled", "integrations.discord_rpc.show_place_name",
        "integrations.discord_rpc.show_elapsed_time", "integrations.discord_rpc.application_id",
        "integrations.discord_rpc.join.enabled", "integrations.discord_rpc.join.public_servers_only",
        "integrations.discord_rpc.join.button_label", "integrations.discord_rpc.text.browsing",
        "integrations.discord_rpc.text.joining", "integrations.discord_rpc.text.playing",
        "integrations.discord_rpc.text.state", "integrations.discord_rpc.text.unknown_place",
    ];

    for (k, _) in &values {
        if !SUPPORTED.contains(&k.as_str()) {
            set_error(&format!("unknown runtime configuration key: {}", k));
            return -10;
        }
    }

    if let Some(v) = values.get("version") {
        if v != "1" {
            set_error(&format!("unsupported runtime configuration version: {}", v));
            return -11;
        }
    }

    let mut env = serde_json::Map::new();

    let scalar_device = values.get("device").cloned();
    let detailed_device = values.contains_key("device.__mapping");
    let detailed_type = values.get("device.type").cloned();
    if detailed_device && detailed_type.is_none() {
        set_error("device.type is required for detailed device configuration");
        return -12;
    }
    let selected_device = scalar_device.or(detailed_type);
    if let Some(ref dev) = selected_device {
        const VALID_DEVS: &[&str] = &[
            "pc", "mobile", "console", "pc-windows-11", "mobile-pixel-7", "console-ps5",
        ];
        if !VALID_DEVS.contains(&dev.as_str()) {
            set_error("device must be pc, mobile, console, pc-windows-11, mobile-pixel-7, or console-ps5");
            return -13;
        }
        if values.contains_key("input.touch_enabled") || values.contains_key("compatibility.desktop_playability") {
            set_error("device cannot be combined with input.touch_enabled or compatibility.desktop_playability");
            return -14;
        }
        env.insert("MOCKTAIL_DEVICE_PROFILE".to_string(), serde_json::json!(dev));
    }

    if detailed_device {
        let string_fields = [
            ("device.platform", "MOCKTAIL_DEVICE_PLATFORM_NAME", 128),
            ("device.name", "MOCKTAIL_DEVICE_NAME", 128),
            ("device.manufacturer", "MOCKTAIL_DEVICE_MANUFACTURER", 128),
            ("device.model", "MOCKTAIL_DEVICE_MODEL", 128),
            ("device.brand", "MOCKTAIL_DEVICE_BRAND", 64),
            ("device.code", "MOCKTAIL_DEVICE_CODE", 64),
            ("device.sku", "MOCKTAIL_DEVICE_SKU", 64),
            ("device.soc_model", "MOCKTAIL_DEVICE_SOC_MODEL", 128),
        ];
        for (yaml_key, env_key, max_len) in string_fields {
            if let Some(val) = values.get(yaml_key) {
                if val.is_empty() || val.len() > max_len || val.bytes().any(|b| b < 0x20 || b == 0x7F) {
                    set_error(&format!("{} must be non-empty, bounded, and contain no control bytes", yaml_key));
                    return -15;
                }
                env.insert(env_key.to_string(), serde_json::json!(val));
            }
        }
        for (yaml_key, env_key) in [
            ("device.touch", "MOCKTAIL_TOUCH_MODE"),
            ("device.mouse", "MOCKTAIL_MOUSE_MODE"),
            ("device.keyboard", "MOCKTAIL_KEYBOARD_MODE"),
        ] {
            if let Some(val) = values.get(yaml_key) {
                let parsed = match parse_yaml_bool(val) {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => {
                        set_error(&format!("{} must be true or false", yaml_key));
                        return -16;
                    }
                };
                env.insert(env_key.to_string(), serde_json::json!(parsed));
            }
        }
    }

    // Runtime section
    if let Some(h) = values.get("runtime.headless") {
        match parse_yaml_bool(h) {
            Some(true) => { env.insert("MOCKTAIL_HEADLESS".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_HEADLESS".to_string(), serde_json::json!("0")); }
            None => {
                set_error("runtime.headless must be true or false");
                return -17;
            }
        }
    }
    if let Some(lib) = values.get("runtime.roblox_library") {
        if lib.is_empty() {
            set_error("runtime.roblox_library must not be empty");
            return -18;
        }
        env.insert("ROBLOX_LIB_PATH".to_string(), serde_json::json!(lib));
    }

    // Appearance section
    if let Some(theme) = values.get("appearance.theme") {
        if !["roblox", "system", "light", "dark"].contains(&theme.as_str()) {
            set_error("appearance.theme must be roblox, system, light, or dark");
            return -19;
        }
        env.insert("MOCKTAIL_THEME".to_string(), serde_json::json!(theme));
    }

    // Graphics section
    if let Some(backend) = values.get("graphics.backend") {
        if !["direct-vulkan", "vulkan", "native-vulkan", "opengl", "gles", "system", "angle-vulkan", "angle-swiftshader", "auto"].contains(&backend.as_str()) {
            set_error(&format!("graphics.backend is not supported: {}", backend));
            return -20;
        }
        let mapped_backend = if backend == "vulkan" || backend == "native-vulkan" {
            "direct-vulkan"
        } else if backend == "gles" {
            "opengl"
        } else {
            backend.as_str()
        };
        env.insert("MOCKTAIL_GRAPHICS_BACKEND".to_string(), serde_json::json!(mapped_backend));
    }
    if let Some(fps) = values.get("graphics.frame_rate_limit") {
        let mut mode = 0i32;
        let mut fps_val = 0i32;
        let c_fps = std::ffi::CString::new(fps.as_str()).unwrap_or_default();
        mocktail_rust_frame_rate_parse(c_fps.as_ptr(), &mut mode, &mut fps_val);
        if mode == 4 { // kInvalid
            set_error(&format!("graphics.frame_rate_limit is not supported: {}", fps));
            return -21;
        }
        env.insert("MOCKTAIL_FRAME_RATE_LIMIT".to_string(), serde_json::json!(fps));
    }
    if let Some(vsync) = values.get("graphics.vsync") {
        if !["auto", "on", "off"].contains(&vsync.as_str()) {
            set_error("graphics.vsync must be auto, on, or off");
            return -21;
        }
        env.insert("MOCKTAIL_VSYNC".to_string(), serde_json::json!(vsync));
    }
    if let Some(pm) = values.get("graphics.present_mode") {
        if !["auto", "fifo", "mailbox", "immediate"].contains(&pm.as_str()) {
            set_error("graphics.present_mode must be auto, fifo, mailbox, or immediate");
            return -22;
        }
        env.insert("MOCKTAIL_PRESENT_MODE".to_string(), serde_json::json!(pm));
    }

    // Performance section
    if let Some(mr) = values.get("performance.multithreaded_rendering") {
        match parse_yaml_bool(mr) {
            Some(true) => { env.insert("MOCKTAIL_MULTITHREADED_RENDERING".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_MULTITHREADED_RENDERING".to_string(), serde_json::json!("0")); }
            None => {
                set_error("performance.multithreaded_rendering must be true or false");
                return -23;
            }
        }
    }
    if let Some(pwm) = values.get("performance.physics_worker_mode") {
        if !["auto", "latency", "throughput"].contains(&pwm.as_str()) {
            set_error("performance.physics_worker_mode must be auto, latency, or throughput");
            return -24;
        }
        env.insert("MOCKTAIL_PHYSICS_WORKER_MODE".to_string(), serde_json::json!(pwm));
    }
    if let Some(mem) = values.get("performance.memory_limit_mb") {
        let n: u64 = match mem.parse() {
            Ok(v) => v,
            Err(_) => {
                set_error("performance.memory_limit_mb must be a non-negative integer");
                return -25;
            }
        };
        env.insert("MOCKTAIL_MEMORY_LIMIT_MB".to_string(), serde_json::json!(n.to_string()));
    }
    if let Some(gm) = values.get("performance.gamemode") {
        if !["auto", "on", "off"].contains(&gm.as_str()) {
            set_error("performance.gamemode must be auto, on, or off");
            return -26;
        }
        env.insert("MOCKTAIL_GAMEMODE".to_string(), serde_json::json!(gm));
    }

    // Audio section
    if let Some(out_dev) = values.get("audio.output_device") {
        if out_dev.is_empty() || out_dev.len() > 512 || out_dev.bytes().any(|b| b < 0x20 || b == 0x7F) {
            set_error("audio.output_device must be non-empty, bounded, and contain no control bytes");
            return -27;
        }
        env.insert("MOCKTAIL_AUDIO_OUTPUT_DEVICE".to_string(), serde_json::json!(out_dev));
    }
    if let Some(in_dev) = values.get("audio.input_device") {
        if in_dev.is_empty() || in_dev.len() > 512 || in_dev.bytes().any(|b| b < 0x20 || b == 0x7F) {
            set_error("audio.input_device must be non-empty, bounded, and contain no control bytes");
            return -28;
        }
        env.insert("MOCKTAIL_AUDIO_INPUT_DEVICE".to_string(), serde_json::json!(in_dev));
    }

    // Window section
    if let Some(w) = values.get("window.width") {
        let n: u32 = match w.parse() {
            Ok(v) if v > 0 => v,
            _ => {
                set_error("window.width must be a positive integer");
                return -29;
            }
        };
        env.insert("MOCKTAIL_WIN_WIDTH".to_string(), serde_json::json!(n.to_string()));
    }
    if let Some(h) = values.get("window.height") {
        let n: u32 = match h.parse() {
            Ok(v) if v > 0 => v,
            _ => {
                set_error("window.height must be a positive integer");
                return -30;
            }
        };
        env.insert("MOCKTAIL_WIN_HEIGHT".to_string(), serde_json::json!(n.to_string()));
    }
    if let Some(title) = values.get("window.title") {
        if title.is_empty() {
            set_error("window.title must not be empty");
            return -31;
        }
        env.insert("MOCKTAIL_WIN_TITLE".to_string(), serde_json::json!(title));
    }
    if let Some(hdpi) = values.get("window.high_dpi") {
        match parse_yaml_bool(hdpi) {
            Some(true) => { env.insert("MOCKTAIL_WIN_HIGH_DPI".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_WIN_HIGH_DPI".to_string(), serde_json::json!("0")); }
            None => {
                set_error("window.high_dpi must be true or false");
                return -32;
            }
        }
    }

    // Input section
    if let Some(touch) = values.get("input.touch_enabled") {
        match parse_yaml_bool(touch) {
            Some(true) => { env.insert("MOCKTAIL_TOUCH_MODE".to_string(), serde_json::json!("on")); }
            Some(false) => { env.insert("MOCKTAIL_TOUCH_MODE".to_string(), serde_json::json!("off")); }
            None => {
                set_error("input.touch_enabled must be true or false");
                return -33;
            }
        }
    }

    // Compatibility section
    if let Some(dp) = values.get("compatibility.desktop_playability") {
        match parse_yaml_bool(dp) {
            Some(true) => { env.insert("MOCKTAIL_DESKTOP_PLAYABILITY".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_DESKTOP_PLAYABILITY".to_string(), serde_json::json!("0")); }
            None => {
                set_error("compatibility.desktop_playability must be true or false");
                return -34;
            }
        }
    }

    // Network section
    if let Some(sys_prox) = values.get("network.use_system_proxy") {
        match parse_yaml_bool(sys_prox) {
            Some(true) => { env.insert("MOCKTAIL_USE_SYSTEM_PROXY".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_USE_SYSTEM_PROXY".to_string(), serde_json::json!("0")); }
            None => {
                set_error("network.use_system_proxy must be true or false");
                return -35;
            }
        }
    }
    let proxy_host = values.get("network.proxy_host");
    let proxy_port = values.get("network.proxy_port");
    let proxy_scheme = values.get("network.proxy_scheme");
    let proxy_username = values.get("network.proxy_username");
    let proxy_password = values.get("network.proxy_password");
    if proxy_host.is_some() != proxy_port.is_some()
        || (proxy_scheme.is_some() && proxy_host.is_none())
        || (proxy_username.is_some() && proxy_host.is_none())
        || (proxy_password.is_some() && proxy_host.is_none()) {
        set_error("network.proxy_host and network.proxy_port must be configured together");
        return -36;
    }
    if let Some(host) = proxy_host {
        let port_str = proxy_port.unwrap();
        let port_num = port_str.parse::<u32>().unwrap_or(0);
        if host.contains("://") || host.contains('/') || port_num == 0 || port_num > 65535 {
            set_error("network proxy must use a valid host without a scheme, a port from 1 to 65535, an HTTP or SOCKS5 scheme, and valid credentials");
            return -38;
        }
        if let Some(scheme) = proxy_scheme {
            if !["http", "https", "socks5"].contains(&scheme.as_str()) {
                set_error("network proxy must use a valid host without a scheme, a port from 1 to 65535, an HTTP or SOCKS5 scheme, and valid credentials");
                return -39;
            }
        }
        env.insert("MOCKTAIL_HTTP_PROXY_HOST".to_string(), serde_json::json!(host));
        env.insert("MOCKTAIL_HTTP_PROXY_PORT".to_string(), serde_json::json!(port_str));
        env.insert("MOCKTAIL_HTTP_PROXY_SCHEME".to_string(), serde_json::json!(proxy_scheme.map(|s| s.as_str()).unwrap_or("http")));
        if let Some(u) = proxy_username {
            env.insert("MOCKTAIL_HTTP_PROXY_USERNAME".to_string(), serde_json::json!(u));
        }
        if let Some(p) = proxy_password {
            env.insert("MOCKTAIL_HTTP_PROXY_PASSWORD".to_string(), serde_json::json!(p));
        }
    }
    if let Some(ca) = values.get("network.ca_bundle") {
        if ca.is_empty() || !ca.starts_with('/') {
            set_error("network.ca_bundle must be an absolute file path");
            return -37;
        }
        env.insert("MOCKTAIL_CA_BUNDLE".to_string(), serde_json::json!(ca));
    }

    // Auth section
    if let Some(sec) = values.get("auth.use_libsecret") {
        match parse_yaml_bool(sec) {
            Some(true) => { env.insert("MOCKTAIL_USE_LIBSECRET".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_USE_LIBSECRET".to_string(), serde_json::json!("0")); }
            None => {
                set_error("auth.use_libsecret must be true or false");
                return -38;
            }
        }
    }

    // Integrations - Fleasion
    if let Some(fl) = values.get("integrations.fleasion.enabled") {
        match parse_yaml_bool(fl) {
            Some(true) => { env.insert("MOCKTAIL_FLEASION_ENABLED".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_FLEASION_ENABLED".to_string(), serde_json::json!("0")); }
            None => {
                set_error("integrations.fleasion.enabled must be true or false");
                return -39;
            }
        }
    }
    if let Some(pm) = values.get("integrations.fleasion.proxy_mode") {
        env.insert("MOCKTAIL_FLEASION_PROXY_MODE".to_string(), serde_json::json!(pm));
    }
    if let Some(port) = values.get("integrations.fleasion.proxy_port") {
        env.insert("MOCKTAIL_FLEASION_PROXY_PORT".to_string(), serde_json::json!(port));
    }
    if let Some(ca) = values.get("integrations.fleasion.ca_certificate") {
        env.insert("MOCKTAIL_FLEASION_CA_CERTIFICATE".to_string(), serde_json::json!(ca));
    }

    // Integrations - Discord RPC
    let bool_discord_fields = [
        ("integrations.discord_rpc.enabled", "MOCKTAIL_DISCORD_RPC_ENABLED"),
        ("integrations.discord_rpc.show_place_name", "MOCKTAIL_DISCORD_RPC_SHOW_PLACE_NAME"),
        ("integrations.discord_rpc.show_elapsed_time", "MOCKTAIL_DISCORD_RPC_SHOW_ELAPSED_TIME"),
        ("integrations.discord_rpc.join.enabled", "MOCKTAIL_DISCORD_RPC_JOIN_ENABLED"),
        ("integrations.discord_rpc.join.public_servers_only", "MOCKTAIL_DISCORD_RPC_PUBLIC_SERVERS_ONLY"),
    ];
    for (k, env_k) in bool_discord_fields {
        if let Some(val) = values.get(k) {
            match parse_yaml_bool(val) {
                Some(true) => { env.insert(env_k.to_string(), serde_json::json!("1")); }
                Some(false) => { env.insert(env_k.to_string(), serde_json::json!("0")); }
                None => {
                    set_error(&format!("{} must be true or false", k));
                    return -40;
                }
            }
        }
    }

    if let Some(app_id) = values.get("integrations.discord_rpc.application_id") {
        if app_id.len() < 17 || app_id.len() > 20 || !app_id.chars().all(|c| c.is_ascii_digit()) {
            set_error("integrations.discord_rpc.application_id must be a Discord snowflake");
            return -41;
        }
        env.insert("MOCKTAIL_DISCORD_APPLICATION_ID".to_string(), serde_json::json!(app_id));
    }

    let string_discord_fields = [
        ("integrations.discord_rpc.join.button_label", "MOCKTAIL_DISCORD_RPC_JOIN_BUTTON_LABEL", 32),
        ("integrations.discord_rpc.text.browsing", "MOCKTAIL_DISCORD_RPC_TEXT_BROWSING", 128),
        ("integrations.discord_rpc.text.joining", "MOCKTAIL_DISCORD_RPC_TEXT_JOINING", 128),
        ("integrations.discord_rpc.text.playing", "MOCKTAIL_DISCORD_RPC_TEXT_PLAYING", 128),
        ("integrations.discord_rpc.text.state", "MOCKTAIL_DISCORD_RPC_TEXT_STATE", 128),
        ("integrations.discord_rpc.text.unknown_place", "MOCKTAIL_DISCORD_RPC_TEXT_UNKNOWN_PLACE", 128),
    ];
    for (yaml_key, env_key, max_len) in string_discord_fields {
        if let Some(val) = values.get(yaml_key) {
            if val.is_empty() || val.len() > max_len || val.bytes().any(|b| b < 0x20 || b == 0x7F) {
                set_error(&format!("{} must be non-empty, bounded, and contain no control bytes", yaml_key));
                return -42;
            }
            env.insert(env_key.to_string(), serde_json::json!(val));
        }
    }

    let dumped = serde_json::Value::Object(env).to_string();
    if dumped.len() + 1 > out_cap {
        set_error("output buffer too small");
        return -43;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dumped.as_ptr() as *const c_char, out_env_json, dumped.len());
        *out_env_json.add(dumped.len()) = 0;
    }
    0
}

// ============================================================================
// 23. Startup Lifecycle State Machine
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustStartupState {
    Created = 0,
    Configured = 1,
    JniRuntimeReady = 2,
    LibrariesLoaded = 3,
    JniOnLoadComplete = 4,
    EngineStarted = 5,
    DataModelLoading = 6,
    LuaAppReady = 7,
    Ready = 8,
    Failure = 9,
    Stopping = 10,
    Stopped = 11,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustStartupEvidence {
    Configured = 0,
    JniRuntimeReady = 1,
    LibrariesLoaded = 2,
    JniOnLoadComplete = 3,
    EngineStarted = 4,
    DataModelLoading = 5,
    LuaAppReady = 6,
    RealFramePresented = 7,
    InputReady = 8,
    AudioReady = 9,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustStartupRequirements {
    pub windowed: c_int,
    pub require_input_ready: c_int,
    pub require_audio_ready: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustStartupSnapshot {
    pub state: MocktailRustStartupState,
    pub requirements: MocktailRustStartupRequirements,
    pub configured: c_int,
    pub jni_runtime_ready: c_int,
    pub libraries_loaded: c_int,
    pub jni_on_load_complete: c_int,
    pub engine_started: c_int,
    pub data_model_loading: c_int,
    pub lua_app_ready: c_int,
    pub real_frame_presented: c_int,
    pub input_ready: c_int,
    pub audio_ready: c_int,
    pub revision: u64,
}

pub struct MocktailRustStartupSm {
    requirements: MocktailRustStartupRequirements,
    state: MocktailRustStartupState,
    evidence_bits: u32,
    revision: u64,
    failure_reason: String,
}

#[inline]
fn evidence_bit(ev: MocktailRustStartupEvidence) -> u32 {
    1u32 << (ev as u32)
}

fn expected_evidence_for_state(state: MocktailRustStartupState) -> Option<MocktailRustStartupEvidence> {
    match state {
        MocktailRustStartupState::Created => Some(MocktailRustStartupEvidence::Configured),
        MocktailRustStartupState::Configured => Some(MocktailRustStartupEvidence::JniRuntimeReady),
        MocktailRustStartupState::JniRuntimeReady => Some(MocktailRustStartupEvidence::LibrariesLoaded),
        MocktailRustStartupState::LibrariesLoaded => Some(MocktailRustStartupEvidence::JniOnLoadComplete),
        MocktailRustStartupState::JniOnLoadComplete => Some(MocktailRustStartupEvidence::EngineStarted),
        MocktailRustStartupState::EngineStarted => Some(MocktailRustStartupEvidence::DataModelLoading),
        MocktailRustStartupState::DataModelLoading => Some(MocktailRustStartupEvidence::LuaAppReady),
        _ => None,
    }
}

fn startup_state_name(state: MocktailRustStartupState) -> &'static str {
    match state {
        MocktailRustStartupState::Created => "Created",
        MocktailRustStartupState::Configured => "Configured",
        MocktailRustStartupState::JniRuntimeReady => "JniRuntimeReady",
        MocktailRustStartupState::LibrariesLoaded => "LibrariesLoaded",
        MocktailRustStartupState::JniOnLoadComplete => "JniOnLoadComplete",
        MocktailRustStartupState::EngineStarted => "EngineStarted",
        MocktailRustStartupState::DataModelLoading => "DataModelLoading",
        MocktailRustStartupState::LuaAppReady => "LuaAppReady",
        MocktailRustStartupState::Ready => "Ready",
        MocktailRustStartupState::Failure => "Failure",
        MocktailRustStartupState::Stopping => "Stopping",
        MocktailRustStartupState::Stopped => "Stopped",
    }
}

fn startup_evidence_name(ev_val: c_int) -> &'static str {
    match ev_val {
        0 => "Configured",
        1 => "JniRuntimeReady",
        2 => "LibrariesLoaded",
        3 => "JniOnLoadComplete",
        4 => "EngineStarted",
        5 => "DataModelLoading",
        6 => "LuaAppReady",
        7 => "RealFramePresented",
        8 => "InputReady",
        9 => "AudioReady",
        _ => "Unknown",
    }
}

fn expected_evidence_name_for_state(state: MocktailRustStartupState) -> &'static str {
    match state {
        MocktailRustStartupState::Created => "Configured",
        MocktailRustStartupState::Configured => "JniRuntimeReady",
        MocktailRustStartupState::JniRuntimeReady => "LibrariesLoaded",
        MocktailRustStartupState::LibrariesLoaded => "JniOnLoadComplete",
        MocktailRustStartupState::JniOnLoadComplete => "EngineStarted",
        MocktailRustStartupState::EngineStarted => "DataModelLoading",
        MocktailRustStartupState::DataModelLoading => "LuaAppReady",
        _ => "no further evidence",
    }
}

fn state_for_core_evidence(evidence: MocktailRustStartupEvidence) -> MocktailRustStartupState {
    match evidence {
        MocktailRustStartupEvidence::Configured => MocktailRustStartupState::Configured,
        MocktailRustStartupEvidence::JniRuntimeReady => MocktailRustStartupState::JniRuntimeReady,
        MocktailRustStartupEvidence::LibrariesLoaded => MocktailRustStartupState::LibrariesLoaded,
        MocktailRustStartupEvidence::JniOnLoadComplete => MocktailRustStartupState::JniOnLoadComplete,
        MocktailRustStartupEvidence::EngineStarted => MocktailRustStartupState::EngineStarted,
        MocktailRustStartupEvidence::DataModelLoading => MocktailRustStartupState::DataModelLoading,
        MocktailRustStartupEvidence::LuaAppReady => MocktailRustStartupState::LuaAppReady,
        _ => MocktailRustStartupState::Failure,
    }
}

impl MocktailRustStartupSm {
    fn has_evidence(&self, ev: MocktailRustStartupEvidence) -> bool {
        (self.evidence_bits & evidence_bit(ev)) != 0
    }

    fn evaluate_ready(&mut self) {
        if !self.has_evidence(MocktailRustStartupEvidence::LuaAppReady) {
            return;
        }
        if self.requirements.windowed != 0 && !self.has_evidence(MocktailRustStartupEvidence::RealFramePresented) {
            self.state = MocktailRustStartupState::LuaAppReady;
            return;
        }
        if self.requirements.require_input_ready != 0 && !self.has_evidence(MocktailRustStartupEvidence::InputReady) {
            self.state = MocktailRustStartupState::LuaAppReady;
            return;
        }
        if self.requirements.require_audio_ready != 0 && !self.has_evidence(MocktailRustStartupEvidence::AudioReady) {
            self.state = MocktailRustStartupState::LuaAppReady;
            return;
        }
        self.state = MocktailRustStartupState::Ready;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_create(
    req: MocktailRustStartupRequirements,
) -> *mut MocktailRustStartupSm {
    let sm = Box::new(MocktailRustStartupSm {
        requirements: req,
        state: MocktailRustStartupState::Created,
        evidence_bits: 0,
        revision: 0,
        failure_reason: String::new(),
    });
    Box::into_raw(sm)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_destroy(sm: *mut MocktailRustStartupSm) {
    if !sm.is_null() {
        unsafe { drop(Box::from_raw(sm)); }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_record_evidence(
    sm_ptr: *mut MocktailRustStartupSm,
    evidence_val: c_int,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    let ev = match evidence_val {
        0 => MocktailRustStartupEvidence::Configured,
        1 => MocktailRustStartupEvidence::JniRuntimeReady,
        2 => MocktailRustStartupEvidence::LibrariesLoaded,
        3 => MocktailRustStartupEvidence::JniOnLoadComplete,
        4 => MocktailRustStartupEvidence::EngineStarted,
        5 => MocktailRustStartupEvidence::DataModelLoading,
        6 => MocktailRustStartupEvidence::LuaAppReady,
        7 => MocktailRustStartupEvidence::RealFramePresented,
        8 => MocktailRustStartupEvidence::InputReady,
        9 => MocktailRustStartupEvidence::AudioReady,
        _ => {
            let expected = expected_evidence_name_for_state(sm.state);
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected {}, received Unknown",
                startup_state_name(sm.state),
                expected
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
    };

    if sm.has_evidence(ev) {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        let msg = format!("duplicate startup evidence: {}", startup_evidence_name(evidence_val));
        set_msg(&msg);
        return 0;
    }

    if sm.state == MocktailRustStartupState::Failure
        || sm.state == MocktailRustStartupState::Stopping
        || sm.state == MocktailRustStartupState::Stopped
    {
        let msg = format!("startup evidence rejected in state {}", startup_state_name(sm.state));
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 2; /* Rejected */ }
        }
        set_msg(&msg);
        return 0;
    }

    let is_core = (evidence_val >= 0) && (evidence_val <= 6);
    if is_core {
        let expected_ev = expected_evidence_for_state(sm.state);
        if expected_ev != Some(ev) {
            let expected_str = expected_evidence_name_for_state(sm.state);
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected {}, received {}",
                startup_state_name(sm.state),
                expected_str,
                startup_evidence_name(evidence_val)
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
        sm.evidence_bits |= evidence_bit(ev);
        sm.state = state_for_core_evidence(ev);
        sm.revision += 1;
        sm.evaluate_ready();
        let msg = format!("accepted startup evidence: {}", startup_evidence_name(evidence_val));
        set_msg(&msg);
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 0; /* Applied */ }
        }
        return 0;
    } else {
        if !sm.has_evidence(MocktailRustStartupEvidence::Configured) {
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected Configured, received {}",
                startup_state_name(sm.state),
                startup_evidence_name(evidence_val)
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
        if ev == MocktailRustStartupEvidence::RealFramePresented && !sm.has_evidence(MocktailRustStartupEvidence::EngineStarted) {
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected EngineStarted, received {}",
                startup_state_name(sm.state),
                startup_evidence_name(evidence_val)
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
        sm.evidence_bits |= evidence_bit(ev);
        sm.revision += 1;
        sm.evaluate_ready();
        let msg = format!("accepted startup evidence: {}", startup_evidence_name(evidence_val));
        set_msg(&msg);
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 0; /* Applied */ }
        }
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_fail(
    sm_ptr: *mut MocktailRustStartupSm,
    reason: *const c_char,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    if sm.state == MocktailRustStartupState::Failure {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        set_msg(&sm.failure_reason);
        return 0;
    }
    if sm.state == MocktailRustStartupState::Stopped {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 2; /* Rejected */ }
        }
        set_msg("cannot fail an already stopped runtime");
        return 0;
    }
    let r_str = if reason.is_null() {
        "startup failed"
    } else {
        unsafe { CStr::from_ptr(reason) }.to_str().unwrap_or("startup failed")
    };
    sm.failure_reason = if r_str.is_empty() { "startup failed".to_string() } else { r_str.to_string() };
    sm.state = MocktailRustStartupState::Failure;
    sm.revision += 1;
    unsafe {
        if !out_state.is_null() { *out_state = sm.state; }
        if !out_status.is_null() { *out_status = 0; /* Applied */ }
    }
    set_msg(&sm.failure_reason);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_begin_stopping(
    sm_ptr: *mut MocktailRustStartupSm,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    if sm.state == MocktailRustStartupState::Stopping || sm.state == MocktailRustStartupState::Stopped {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        let msg = format!("runtime is already {}", startup_state_name(sm.state));
        set_msg(&msg);
        return 0;
    }
    sm.state = MocktailRustStartupState::Stopping;
    sm.revision += 1;
    unsafe {
        if !out_state.is_null() { *out_state = sm.state; }
        if !out_status.is_null() { *out_status = 0; /* Applied */ }
    }
    set_msg("runtime stopping");
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_mark_stopped(
    sm_ptr: *mut MocktailRustStartupSm,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    if sm.state == MocktailRustStartupState::Stopped {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        set_msg("runtime is already Stopped");
        return 0;
    }
    if sm.state != MocktailRustStartupState::Stopping {
        sm.failure_reason = format!(
            "invalid lifecycle order: Stopped requires Stopping, was {}",
            startup_state_name(sm.state)
        );
        sm.state = MocktailRustStartupState::Failure;
        sm.revision += 1;
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 2; /* Rejected */ }
        }
        set_msg(&sm.failure_reason);
        return 0;
    }
    sm.state = MocktailRustStartupState::Stopped;
    sm.revision += 1;
    unsafe {
        if !out_state.is_null() { *out_state = sm.state; }
        if !out_status.is_null() { *out_status = 0; /* Applied */ }
    }
    set_msg("runtime stopped");
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_snapshot(
    sm_ptr: *const MocktailRustStartupSm,
    out_snapshot: *mut MocktailRustStartupSnapshot,
    out_reason: *mut c_char,
    reason_cap: usize,
) -> c_int {
    if sm_ptr.is_null() || out_snapshot.is_null() {
        return -1;
    }
    let sm = unsafe { &*sm_ptr };
    unsafe {
        (*out_snapshot).state = sm.state;
        (*out_snapshot).requirements = sm.requirements;
        (*out_snapshot).configured = if sm.has_evidence(MocktailRustStartupEvidence::Configured) { 1 } else { 0 };
        (*out_snapshot).jni_runtime_ready = if sm.has_evidence(MocktailRustStartupEvidence::JniRuntimeReady) { 1 } else { 0 };
        (*out_snapshot).libraries_loaded = if sm.has_evidence(MocktailRustStartupEvidence::LibrariesLoaded) { 1 } else { 0 };
        (*out_snapshot).jni_on_load_complete = if sm.has_evidence(MocktailRustStartupEvidence::JniOnLoadComplete) { 1 } else { 0 };
        (*out_snapshot).engine_started = if sm.has_evidence(MocktailRustStartupEvidence::EngineStarted) { 1 } else { 0 };
        (*out_snapshot).data_model_loading = if sm.has_evidence(MocktailRustStartupEvidence::DataModelLoading) { 1 } else { 0 };
        (*out_snapshot).lua_app_ready = if sm.has_evidence(MocktailRustStartupEvidence::LuaAppReady) { 1 } else { 0 };
        (*out_snapshot).real_frame_presented = if sm.has_evidence(MocktailRustStartupEvidence::RealFramePresented) { 1 } else { 0 };
        (*out_snapshot).input_ready = if sm.has_evidence(MocktailRustStartupEvidence::InputReady) { 1 } else { 0 };
        (*out_snapshot).audio_ready = if sm.has_evidence(MocktailRustStartupEvidence::AudioReady) { 1 } else { 0 };
        (*out_snapshot).revision = sm.revision;
        if !out_reason.is_null() && reason_cap > 0 {
            let len = std::cmp::min(sm.failure_reason.len(), reason_cap - 1);
            std::ptr::copy_nonoverlapping(sm.failure_reason.as_ptr() as *const c_char, out_reason, len);
            *out_reason.add(len) = 0;
        }
    }
    0
}

// ============================================================================
// 24. Fleasion CA Certificate & Bundle Manager
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_fleasion_prepare_bundle(
    ca_pem_path: *const c_char,
    base_bundle_path: *const c_char,
    dest_bundle_path: *const c_char,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if ca_pem_path.is_null() || base_bundle_path.is_null() || dest_bundle_path.is_null() {
        set_error("invalid argument");
        return -1;
    }
    let ca_path = match unsafe { CStr::from_ptr(ca_pem_path) }.to_str() {
        Ok(s) => Path::new(s),
        Err(_) => {
            set_error("invalid ca path encoding");
            return -2;
        }
    };
    let base_path = match unsafe { CStr::from_ptr(base_bundle_path) }.to_str() {
        Ok(s) => Path::new(s),
        Err(_) => {
            set_error("invalid base bundle path encoding");
            return -3;
        }
    };
    let dest_path = match unsafe { CStr::from_ptr(dest_bundle_path) }.to_str() {
        Ok(s) => Path::new(s),
        Err(_) => {
            set_error("invalid dest bundle path encoding");
            return -4;
        }
    };

    let ca_pem = match std::fs::read_to_string(ca_path) {
        Ok(s) => s,
        Err(_) => {
            set_error(&format!("cannot read Fleasion CA certificate at {}", ca_path.display()));
            return -5;
        }
    };
    if !ca_pem.contains("-----BEGIN CERTIFICATE-----") || !ca_pem.contains("-----END CERTIFICATE-----") {
        set_error("Fleasion CA must be a currently valid PEM CA certificate");
        return -6;
    }

    let base_pem = match std::fs::read_to_string(base_path) {
        Ok(s) => s,
        Err(_) => {
            set_error(&format!("cannot read base CA bundle for Fleasion: {}", base_path.display()));
            return -7;
        }
    };

    let mut out_bundle = String::new();
    let mut cursor = 0;
    let mut count = 0;
    while let Some(start) = base_pem[cursor..].find("-----BEGIN CERTIFICATE-----") {
        let abs_start = cursor + start;
        if let Some(end) = base_pem[abs_start..].find("-----END CERTIFICATE-----") {
            let abs_end = abs_start + end + "-----END CERTIFICATE-----".len();
            let cert_block = &base_pem[abs_start..abs_end];
            let cert_norm: String = cert_block.chars().filter(|c| !c.is_whitespace()).collect();
            let ca_norm: String = ca_pem.chars().filter(|c| !c.is_whitespace()).collect();
            if cert_norm != ca_norm {
                out_bundle.push_str(cert_block.trim());
                out_bundle.push('\n');
                count += 1;
            }
            cursor = abs_end;
        } else {
            break;
        }
    }
    if count == 0 {
        set_error("base bundle must contain PEM certificates");
        return -8;
    }

    out_bundle.push_str(ca_pem.trim());
    out_bundle.push('\n');

    if let Some(parent) = dest_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp_path = format!("{}.tmp.{}", dest_path.display(), std::process::id());
    if std::fs::write(&tmp_path, out_bundle.as_bytes()).is_err() {
        set_error(&format!("cannot write generated Fleasion CA bundle: {}", dest_path.display()));
        return -9;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    if std::fs::rename(&tmp_path, dest_path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        set_error(&format!("cannot write generated Fleasion CA bundle: {}", dest_path.display()));
        return -10;
    }
    0
}

// ============================================================================
// 25. APK Signing Block & Chunk Hash Verifier
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustApkSigningBlockInfo {
    pub block_begin: u64,
    pub central_directory: u64,
    pub eocd: u64,
    pub v2_offset: u64,
    pub v2_len: u64,
    pub v3_offset: u64,
    pub v3_len: u64,
    pub v31_offset: u64,
    pub v31_len: u64,
}

#[inline]
fn read_u32_le(slice: &[u8]) -> u32 {
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}

#[inline]
fn read_u64_le(slice: &[u8]) -> u64 {
    u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3],
        slice[4], slice[5], slice[6], slice[7],
    ])
}

#[no_mangle]
pub extern "C" fn mocktail_rust_find_apk_signing_block(
    file_bytes: *const u8,
    file_size: usize,
    out_info: *mut MocktailRustApkSigningBlockInfo,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if file_bytes.is_null() || out_info.is_null() || file_size < 32 {
        set_error("invalid argument");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(file_bytes, file_size) };

    let min_search = if file_size > 65557 { file_size - 65557 } else { 0 };
    let mut eocd_pos = None;
    for pos in (min_search..=file_size - 22).rev() {
        if read_u32_le(&slice[pos..pos + 4]) == 0x06054b50 {
            let comment_len = u16::from_le_bytes([slice[pos + 20], slice[pos + 21]]) as usize;
            if pos + 22 + comment_len == file_size {
                eocd_pos = Some(pos);
                break;
            }
        }
    }
    let eocd = match eocd_pos {
        Some(p) => p,
        None => {
            set_error("APK has no valid ZIP end record");
            return -2;
        }
    };

    let cd_offset = read_u32_le(&slice[eocd + 16..eocd + 20]) as usize;
    if cd_offset < 32 || cd_offset > eocd {
        set_error("APK has no Signature Scheme v2/v3 block");
        return -3;
    }
    if &slice[cd_offset - 16..cd_offset] != b"APK Sig Block 42" {
        set_error("APK has no Signature Scheme v2/v3 block");
        return -4;
    }
    let footer_size = read_u64_le(&slice[cd_offset - 24..cd_offset - 16]) as usize;
    if footer_size < 24 || footer_size > cd_offset - 8 {
        set_error("APK signing block size is invalid");
        return -5;
    }
    let total_size = footer_size + 8;
    let block_begin = cd_offset - total_size;
    if read_u64_le(&slice[block_begin..block_begin + 8]) as usize != footer_size {
        set_error("APK signing block size headers disagree");
        return -6;
    }

    let mut info = MocktailRustApkSigningBlockInfo {
        block_begin: block_begin as u64,
        central_directory: cd_offset as u64,
        eocd: eocd as u64,
        v2_offset: 0,
        v2_len: 0,
        v3_offset: 0,
        v3_len: 0,
        v31_offset: 0,
        v31_len: 0,
    };

    let mut cursor = block_begin + 8;
    let pairs_end = cd_offset - 24;
    while cursor < pairs_end {
        if pairs_end - cursor < 12 {
            set_error("APK signing block pair is truncated");
            return -7;
        }
        let pair_size = read_u64_le(&slice[cursor..cursor + 8]) as usize;
        cursor += 8;
        if pair_size < 4 || pair_size > pairs_end - cursor {
            set_error("APK signing block pair is malformed");
            return -8;
        }
        let id = read_u32_le(&slice[cursor..cursor + 4]);
        let val_offset = (cursor + 4) as u64;
        let val_len = (pair_size - 4) as u64;
        match id {
            0x7109871a => {
                info.v2_offset = val_offset;
                info.v2_len = val_len;
            }
            0xf05368c0 => {
                info.v3_offset = val_offset;
                info.v3_len = val_len;
            }
            0x1b93ad61 => {
                info.v31_offset = val_offset;
                info.v31_len = val_len;
            }
            _ => {}
        }
        cursor += pair_size;
    }

    unsafe {
        *out_info = info;
    }
    0
}

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

fn is_safe_archive_path(path: &str) -> bool {
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
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot open ZIP archive: {}: {}", path, e));
            return -3;
        }
    };
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => {
            set_err(&format!("cannot parse ZIP archive: {}", e));
            return -4;
        }
    };
    if zip.len() > max_entries {
        set_err("ZIP archive has an invalid or excessive entry count");
        return -5;
    }
    let mut entries = Vec::new();
    for i in 0..zip.len() {
        let entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                set_err(&format!("cannot read ZIP entry metadata: {}", e));
                return -6;
            }
        };
        let name = entry.name().to_string();
        if !is_safe_archive_path(&name) {
            set_err("ZIP entry path is unsafe");
            return -7;
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
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot open ZIP archive: {}: {}", path, e));
            return -4;
        }
    };
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => {
            set_err(&format!("cannot parse ZIP archive: {}", e));
            return -5;
        }
    };
    let mut entry = match zip.by_name(target_name) {
        Ok(e) => e,
        Err(_) => {
            set_err(&format!("ZIP entry is missing: {}", target_name));
            return -6;
        }
    };
    if entry.size() > max_bytes as u64 || entry.size() > buf_cap as u64 {
        set_err("decompressed ZIP data exceeds its size limit");
        return -7;
    }
    use std::io::Read;
    let mut total_read = 0;
    let slice = unsafe { std::slice::from_raw_parts_mut(out_buf, buf_cap) };
    while total_read < slice.len() {
        match entry.read(&mut slice[total_read..]) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                if total_read > max_bytes {
                    set_err("decompressed ZIP data exceeds its size limit");
                    return -8;
                }
            }
            Err(e) => {
                set_err(&format!("cannot decompress ZIP entry: {}", e));
                return -9;
            }
        }
    }
    unsafe {
        *out_read_len = total_read;
    }
    0
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
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot open ZIP archive: {}: {}", path, e));
            return -5;
        }
    };
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => {
            set_err(&format!("cannot parse ZIP archive: {}", e));
            return -6;
        }
    };
    let mut entry = match zip.by_name(target_name) {
        Ok(e) => e,
        Err(_) => {
            set_err(&format!("ZIP entry is missing: {}", target_name));
            return -7;
        }
    };
    if entry.size() > max_bytes as u64 {
        set_err("decompressed ZIP data exceeds its size limit");
        return -8;
    }
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::create_dir_all(parent) {
        set_err(&format!("cannot create directory: {}", e));
        return -9;
    }
    let tmp_path = parent.join(format!(".tmp_extract_{}_{}", std::process::id(), target_name.replace('/', "_")));
    let mut out_file = match std::fs::File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot create temporary file: {}", e));
            return -10;
        }
    };
    use std::io::{Read, Write};
    let mut total_written = 0;
    let mut buffer = [0u8; 16384];
    loop {
        match entry.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total_written += n;
                if total_written > max_bytes {
                    let _ = std::fs::remove_file(&tmp_path);
                    set_err("decompressed ZIP data exceeds its size limit");
                    return -11;
                }
                if let Err(e) = out_file.write_all(&buffer[..n]) {
                    let _ = std::fs::remove_file(&tmp_path);
                    set_err(&format!("cannot write temporary file: {}", e));
                    return -12;
                }
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                set_err(&format!("cannot decompress ZIP entry: {}", e));
                return -13;
            }
        }
    }
    if let Err(e) = out_file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot sync file: {}", e));
        return -14;
    }
    drop(out_file);
    if let Err(e) = std::fs::rename(&tmp_path, dest) {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot rename to destination: {}", e));
        return -15;
    }
    0
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
    let file = match std::fs::File::open(arc_p) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot open ZIP archive: {}: {}", arc_p, e));
            return -5;
        }
    };
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => {
            set_err(&format!("cannot parse ZIP archive: {}", e));
            return -6;
        }
    };
    use std::io::{Read, Write};
    let mut total_bytes = 0;
    let mut count = 0;
    for i in 0..zip.len() {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                set_err(&format!("cannot read ZIP entry: {}", e));
                return -7;
            }
        };
        let name = entry.name().to_string();
        if !name.starts_with(pref) {
            continue;
        }
        let rel_name = &name[pref.len()..];
        if rel_name.is_empty() {
            continue;
        }
        if !is_safe_archive_path(rel_name) {
            set_err(&format!("unsafe entry path in prefix extract: {}", rel_name));
            return -8;
        }
        let target_path = dest_base.join(rel_name);
        if entry.is_dir() || rel_name.ends_with('/') {
            if let Err(e) = std::fs::create_dir_all(&target_path) {
                set_err(&format!("cannot create directory {}: {}", target_path.display(), e));
                return -9;
            }
            continue;
        }
        if let Some(p) = target_path.parent() {
            if let Err(e) = std::fs::create_dir_all(p) {
                set_err(&format!("cannot create parent directory {}: {}", p.display(), e));
                return -10;
            }
        }
        let mut out = match std::fs::File::create(&target_path) {
            Ok(f) => f,
            Err(e) => {
                set_err(&format!("cannot create file {}: {}", target_path.display(), e));
                return -11;
            }
        };
        let mut buf = [0u8; 16384];
        loop {
            match entry.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n;
                    if total_bytes > max_total_bytes {
                        set_err("total extracted size exceeded limit");
                        return -12;
                    }
                    if let Err(e) = out.write_all(&buf[..n]) {
                        set_err(&format!("cannot write file {}: {}", target_path.display(), e));
                        return -13;
                    }
                }
                Err(e) => {
                    set_err(&format!("cannot read entry {}: {}", name, e));
                    return -14;
                }
            }
        }
        count += 1;
    }
    unsafe {
        *out_extracted_count = count;
    }
    0
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
    let root_path = Path::new(root_str);
    let sym_meta = match std::fs::symlink_metadata(root_path) {
        Ok(m) => m,
        Err(_) => {
            set_err("asset root is not a real directory");
            return -3;
        }
    };
    if sym_meta.file_type().is_symlink() || !sym_meta.is_dir() {
        set_err("asset root is not a real directory");
        return -4;
    }

    let mut files = Vec::new();
    if let Err(e) = walk_asset_tree(root_path, root_path, &mut files) {
        set_err(&e);
        return -5;
    }

    files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    use sha2::{Digest, Sha256};
    let mut tree_hasher = Sha256::new();

    for rel_path in &files {
        let full_path = root_path.join(rel_path);
        let mut file = match std::fs::File::open(&full_path) {
            Ok(f) => f,
            Err(_) => {
                set_err(&format!("cannot open file {}", full_path.display()));
                return -6;
            }
        };
        let mut file_hasher = Sha256::new();
        let mut buf = [0u8; 16384];
        use std::io::Read;
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => file_hasher.update(&buf[..n]),
                Err(_) => {
                    set_err(&format!("cannot read file {}", full_path.display()));
                    return -7;
                }
            }
        }
        let file_sha = hex::encode(file_hasher.finalize());
        let rel_unix_str = rel_path.to_string_lossy().replace('\\', "/");
        tree_hasher.update(file_sha.as_bytes());
        tree_hasher.update(b"  ");
        tree_hasher.update(rel_unix_str.as_bytes());
        tree_hasher.update(&[0u8]);
    }

    let final_hex = hex::encode(tree_hasher.finalize());
    unsafe {
        std::ptr::copy_nonoverlapping(final_hex.as_ptr() as *const c_char, out_hex, final_hex.len());
        *out_hex.add(final_hex.len()) = 0;
        if !out_file_count.is_null() {
            *out_file_count = files.len();
        }
    }
    0
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

fn internal_inspect_payload(dir: &Path) -> Result<MocktailRustPayloadInfo, String> {
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
    let dir = Path::new(p_str);
    let info = match internal_inspect_payload(dir) {
        Ok(i) => i,
        Err(e) => {
            set_err(&e);
            return -3;
        }
    };

    use sha2::{Digest, Sha256};
    let check_file_sha = |rel: &str, expected: &str| -> Result<(), String> {
        let f_path = dir.join(rel);
        let mut file = match std::fs::File::open(&f_path) {
            Ok(f) => f,
            Err(_) => return Err(format!("cannot open regular file: {}", rel)),
        };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 16384];
        use std::io::Read;
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => return Err(format!("cannot read regular file: {}", rel)),
            }
        }
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            return Err(format!("payload hash mismatch: {}", rel));
        }
        Ok(())
    };

    if let Err(e) = check_file_sha("libroblox.so", &info.library_sha256) {
        set_err(&e);
        return -4;
    }
    if let Err(e) = check_file_sha("sober_apk/base.apk", &info.base_apk_sha256) {
        set_err(&e);
        return -5;
    }
    let split_file = if dir.join("sober_apk/split_config.arm64_v8a.apk").exists() {
        "sober_apk/split_config.arm64_v8a.apk"
    } else if cfg!(target_arch = "aarch64") {
        "sober_apk/split_config.arm64_v8a.apk"
    } else {
        "sober_apk/split_config.x86_64.apk"
    };
    if let Err(e) = check_file_sha(split_file, &info.split_apk_sha256) {
        set_err(&e);
        return -6;
    }

    let mut actual_count = 0;
    let mut tree_hex = [0 as c_char; 65];
    let mut tree_err = [0 as c_char; 256];
    let assets_cstr = match CString::new(dir.join("assets").to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            set_err("invalid assets path");
            return -7;
        }
    };
    let rc = mocktail_rust_payload_hash_asset_tree(
        assets_cstr.as_ptr(),
        tree_hex.as_mut_ptr(),
        65,
        &mut actual_count,
        tree_err.as_mut_ptr(),
        256,
    );
    if rc != 0 {
        let err_msg = unsafe { CStr::from_ptr(tree_err.as_ptr()) }.to_str().unwrap_or("asset tree error");
        set_err(err_msg);
        return -8;
    }
    let actual_tree_hex = unsafe { CStr::from_ptr(tree_hex.as_ptr()) }.to_str().unwrap_or("");
    if actual_count != info.asset_file_count || actual_tree_hex != info.asset_tree_sha256 {
        set_err("payload asset tree does not match metadata");
        return -9;
    }

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

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_is_valid_version_name(
    name_ptr: *const c_char,
    name_len: usize,
) -> bool {
    if name_ptr.is_null() || name_len == 0 || name_len > 128 {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len) };
    slice.iter().copied().all(apkpure_version_character)
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
    let mut file = match File::open(path_str) {
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
    if meta_len == 0 {
        set_err("APKPure metadata contains no downloadable version identity");
        return -2;
    }
    let data = unsafe { std::slice::from_raw_parts(metadata, meta_len) };
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
        set_err("APKPure metadata contains no downloadable version identity");
        return -2;
    }
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
    if meta_len == 0 {
        set_err("APKPure does not offer the requested exact version");
        return -3;
    }
    let data = unsafe { std::slice::from_raw_parts(metadata, meta_len) };
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
        set_err("APKPure does not offer the requested exact version");
        return -3;
    }
    if results.len() > 4 {
        set_err("APKPure returned too many candidates");
        return -4;
    }
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

fn is_valid_browser_id(val: &str) -> bool {
    !val.is_empty() && val.len() <= 20 && !val.starts_with('0') && val.chars().all(|c| c.is_ascii_digit())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_tracker_generate_id(
    out_id: *mut c_char,
    id_cap: usize,
) -> c_int {
    if out_id.is_null() || id_cap < 21 {
        return -1;
    }
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
    let id_str = rand_val.to_string();
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
    for field in cookie_str.split('&') {
        let field = field.trim();
        if let Some((k, v)) = field.split_once('=') {
            if k.trim() == "browserid" {
                let id = v.trim();
                if is_valid_browser_id(id) {
                    if id.len() >= id_cap {
                        return -3;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(id.as_ptr() as *const c_char, out_id, id.len());
                        *out_id.add(id.len()) = 0;
                    }
                    return 0;
                }
            }
        }
    }
    -4
}

// ============================================================================
// 32. Support Bundle & Log Redactor
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_is_diagnostic_token(token: *const c_char) -> c_int {
    if token.is_null() {
        return 0;
    }
    let s = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if s.is_empty() || s.len() > 64 {
        return 0;
    }
    if !s.chars().next().map_or(false, |c| c.is_ascii_alphanumeric()) {
        return 0;
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == ':' || c == '+' || c == '-') {
        1
    } else {
        0
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
    let path = Path::new(path_str);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::create_dir_all(parent) {
        set_err(&format!("could not create directory: {}", e));
        return -3;
    }

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp_path = parent.join(format!(
        ".tmp_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));

    let bytes = if content_len > 0 && !content.is_null() {
        unsafe { std::slice::from_raw_parts(content as *const u8, content_len) }
    } else {
        &[]
    };

    let mut file = match std::fs::File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            set_err(&format!("cannot create temporary file: {}", e));
            return -4;
        }
    };
    use std::io::Write;
    if let Err(e) = file.write_all(bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot write temporary file: {}", e));
        return -5;
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot sync temporary file: {}", e));
        return -6;
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        set_err(&format!("cannot rename temporary file: {}", e));
        return -7;
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

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_paths_resolve_adjacent_assets(
    roblox_lib_path: *const c_char,
    working_dir: *const c_char,
    out_path: *mut c_char,
    out_cap: usize,
) -> c_int {
    if roblox_lib_path.is_null() || out_path.is_null() || out_cap == 0 {
        return -1;
    }
    let lib_str = match unsafe { CStr::from_ptr(roblox_lib_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let mut p = PathBuf::from(lib_str);
    if !p.is_absolute() && !working_dir.is_null() {
        if let Ok(wd) = unsafe { CStr::from_ptr(working_dir) }.to_str() {
            p = Path::new(wd).join(p);
        }
    }
    let candidate = if let Some(parent) = p.parent() {
        parent.join("assets")
    } else {
        PathBuf::from("assets")
    };
    let res = if candidate.is_dir() {
        candidate.to_string_lossy().to_string()
    } else {
        String::new()
    };
    if res.len() >= out_cap {
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(res.as_ptr() as *const c_char, out_path, res.len());
        *out_path.add(res.len()) = 0;
    }
    0
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

// ============================================================================
// 38. Present Mode Policy & Swapchain (Group 1)
// ============================================================================

fn copy_to_c_buffer(src: &str, dst: *mut c_char, cap: usize) -> c_int {
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
// 46. External Launch Broker & Wire Protocol (Group C)
// ============================================================================

const EXTERNAL_LAUNCH_WIRE_PREFIX: &[u8] = b"MOCKTAIL-EXTERNAL-LAUNCH/1\n";
const EXTERNAL_LAUNCH_REPLY_PREFIX: &[u8] = b"MTL1";

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
    if out_bytes.is_null() || out_cap < 5 {
        return -1;
    }
    unsafe {
        let dst = slice::from_raw_parts_mut(out_bytes, out_cap);
        dst[..4].copy_from_slice(EXTERNAL_LAUNCH_REPLY_PREFIX);
        dst[4] = reply_code;
    }
    5
}

#[no_mangle]
pub extern "C" fn mocktail_rust_external_launch_parse_reply(
    in_bytes: *const u8,
    in_len: usize,
    out_reply_code: *mut u8,
) -> c_int {
    if in_bytes.is_null() || out_reply_code.is_null() || in_len != 5 {
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
        0 => 0, /* kOk */
        1 => 1, /* kInvalidArgument */
        2 => 3, /* kUnavailable */
        3 => 2, /* kFailedPrecondition */
        4 => 3, /* kUnavailable */
        _ => 5, /* kPlatformError */
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
    let name = if is_run_user != 0 {
        format!("mocktail.{}.external-launch-v1.sock", key)
    } else {
        format!("{}.external-launch-v1.sock", key)
    };
    copy_to_c_buffer(&name, out_buf, out_cap)
}

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
    let s = match std::str::from_utf8(slice) {
        Ok(val) => val,
        Err(_) => return 0,
    };
    let dash = match s.find('-') {
        Some(pos) => pos,
        None => return 0,
    };
    if dash == 0 || s.len() - dash - 1 != 40 {
        return 0;
    }
    for (i, c) in s.char_indices() {
        if i == dash {
            continue;
        }
        if i < dash {
            if !c.is_ascii_digit() {
                return 0;
            }
        } else {
            if !c.is_ascii_digit() && !(c >= 'a' && c <= 'f') {
                return 0;
            }
        }
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_validate_manifest_json(
    json_ptr: *const c_char,
    len: usize,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if json_ptr.is_null() || len == 0 {
        copy_to_c_buffer("manifest json is empty", err_buf, err_cap);
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(json_ptr as *const u8, len) };
    let s = match std::str::from_utf8(slice) {
        Ok(val) => val,
        Err(_) => {
            copy_to_c_buffer("manifest json is not valid UTF-8", err_buf, err_cap);
            return -1;
        }
    };
    let v: serde_json::Value = match serde_json::from_str(s) {
        Ok(val) => val,
        Err(_) => {
            copy_to_c_buffer("manifest json is not a valid JSON document", err_buf, err_cap);
            return -1;
        }
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            copy_to_c_buffer("manifest root must be an object", err_buf, err_cap);
            return -1;
        }
    };
    if obj.get("format").and_then(|x| x.as_i64()) != Some(1) {
        copy_to_c_buffer("unsupported manifest format", err_buf, err_cap);
        return -1;
    }
    let pid = obj.get("payload_id").and_then(|x| x.as_str()).unwrap_or("");
    let pid_c = match CString::new(pid) {
        Ok(c) => c,
        Err(_) => {
            copy_to_c_buffer("invalid payload_id", err_buf, err_cap);
            return -1;
        }
    };
    if mocktail_rust_payload_store_valid_id(pid_c.as_ptr(), pid.len()) == 0 {
        copy_to_c_buffer("invalid payload_id format", err_buf, err_cap);
        return -1;
    }
    if obj.get("version_name").and_then(|x| x.as_str()).unwrap_or("").is_empty() {
        copy_to_c_buffer("version_name must not be empty", err_buf, err_cap);
        return -1;
    }
    if obj.get("version_code").and_then(|x| x.as_u64()).unwrap_or(0) == 0 {
        copy_to_c_buffer("version_code must be positive", err_buf, err_cap);
        return -1;
    }
    let bid = obj.get("build_id").and_then(|x| x.as_str()).unwrap_or("");
    let bid_c = match CString::new(bid) {
        Ok(c) => c,
        Err(_) => {
            copy_to_c_buffer("invalid build_id", err_buf, err_cap);
            return -1;
        }
    };
    if mocktail_rust_is_lower_hex(bid_c.as_ptr(), 40) == 0 {
        copy_to_c_buffer("build_id must be a 40-character hex string", err_buf, err_cap);
        return -1;
    }
    if obj.get("staging_timestamp").and_then(|x| x.as_str()).unwrap_or("").is_empty() {
        copy_to_c_buffer("staging_timestamp must not be empty", err_buf, err_cap);
        return -1;
    }
    if obj.get("source").and_then(|x| x.as_str()).unwrap_or("").is_empty() {
        copy_to_c_buffer("source must not be empty", err_buf, err_cap);
        return -1;
    }
    0
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
    if place_id <= 0 {
        return false;
    }
    if instance_id.is_null() || instance_id_len == 0 {
        return true;
    }
    if instance_id_len > 128 {
        return false;
    }
    let slice = std::slice::from_raw_parts(instance_id as *const u8, instance_id_len);
    for &b in slice {
        if b < 0x20 || b == 0x7f {
            return false;
        }
    }
    true
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
    if src_len <= maximum {
        return src_len;
    }
    let slice = std::slice::from_raw_parts(src as *const u8, src_len);
    let mut boundary = maximum;
    while boundary > 0 && (slice[boundary] & 0xc0) == 0x80 {
        boundary -= 1;
    }
    boundary
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let slice = std::slice::from_raw_parts(src as *const u8, src_len);
    let mut written = 0;
    for &b in slice {
        let is_unreserved = (b >= b'a' && b <= b'z')
            || (b >= b'A' && b <= b'Z')
            || (b >= b'0' && b <= b'9')
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'~';
        if is_unreserved {
            if !out_buf.is_null() && written < out_cap {
                *out_buf.add(written) = b;
            }
            written += 1;
        } else {
            if !out_buf.is_null() && written + 2 < out_cap {
                *out_buf.add(written) = b'%';
                *out_buf.add(written + 1) = HEX[(b >> 4) as usize];
                *out_buf.add(written + 2) = HEX[(b & 0x0f) as usize];
            }
            written += 3;
        }
    }
    *out_len = written;
    if !out_buf.is_null() && written > out_cap {
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
    if !mocktail_rust_discord_has_join_target(place_id, instance_id, instance_id_len) {
        *out_len = 0;
        return 0;
    }
    let base = "https://komaruworld.github.io/mocktail/join.html#placeId=";
    let place_str = place_id.to_string();
    let mut url = Vec::with_capacity(256);
    url.extend_from_slice(base.as_bytes());
    url.extend_from_slice(place_str.as_bytes());

    if !instance_id.is_null() && instance_id_len > 0 {
        url.extend_from_slice(b"&gameInstanceId=");
        let mut enc_len = 0usize;
        mocktail_rust_discord_percent_encode(instance_id, instance_id_len, std::ptr::null_mut(), 0, &mut enc_len);
        let cur_len = url.len();
        url.resize(cur_len + enc_len, 0);
        let mut actual_enc = 0usize;
        mocktail_rust_discord_percent_encode(
            instance_id,
            instance_id_len,
            url[cur_len..].as_mut_ptr(),
            enc_len,
            &mut actual_enc,
        );
    }

    if url.len() > 512 {
        *out_len = 0;
        return 0;
    }

    *out_len = url.len();
    if out_buf.is_null() || out_cap < url.len() {
        return if out_buf.is_null() { 0 } else { -2 };
    }
    std::ptr::copy_nonoverlapping(url.as_ptr(), out_buf, url.len());
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

    if host_s.len() == allowed_s.len() {
        return host_s.iter().zip(allowed_s.iter()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase());
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

#[no_mangle]
pub extern "C" fn mocktail_rust_update_is_redirect_status(status_code: i64) -> bool {
    status_code == 301
        || status_code == 302
        || status_code == 303
        || status_code == 307
        || status_code == 308
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_is_retryable_status(status_code: i64) -> bool {
    status_code == 408 || status_code == 425 || status_code == 429 || status_code >= 500
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_is_retryable_curl_code(code: i32) -> bool {
    matches!(code, 7 | 6 | 5 | 28 | 18 | 56 | 55 | 52 | 35)
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
    let take_latest = has_latest && (!runnable || latest_code > runnable_code);
    let need_preferred = !runnable || preferred_code > runnable_code;
    let take_preferred = need_preferred && (!take_latest || latest_code != preferred_code);
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
    if len <= max_bytes {
        return len;
    }
    let slice = std::slice::from_raw_parts(data, len);
    let mut size = max_bytes;
    while size > 0 && (slice[size] & 0xC0) == 0x80 {
        size -= 1;
    }
    size
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
    let prefix = b"[native-updater] ";
    let warning_prefix = b"warning: ";

    if slice.len() > prefix.len() && slice.starts_with(prefix) {
        let detail = &slice[prefix.len()..];
        if !detail.starts_with(warning_prefix) {
            *out_is_failure = true;
            let trim_len = mocktail_rust_trim_to_utf8_boundary(detail.as_ptr(), detail.len(), 400);
            *out_len = trim_len;
            if !out_buf.is_null() && cap >= trim_len {
                std::ptr::copy_nonoverlapping(detail.as_ptr(), out_buf, trim_len);
            }
            return 0;
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
    entry_s[name_len] == b'=' && &entry_s[..name_len] == name_s
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

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_tracker_is_valid_id(
    value: *const c_char,
    len: usize,
) -> bool {
    if value.is_null() || len == 0 || len > 20 {
        return false;
    }
    let slice = std::slice::from_raw_parts(value as *const u8, len);
    if slice[0] == b'0' {
        return false;
    }
    match std::str::from_utf8(slice) {
        Ok(s) => match s.parse::<u64>() {
            Ok(n) => n != 0,
            Err(_) => false,
        },
        Err(_) => false,
    }
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

    for part in cookies_str.split(&[';', '\r', '\n'][..]) {
        let part_trimmed = part.trim();
        if let Some((k, v)) = part_trimmed.split_once('=') {
            if k.trim() == name_str {
                let val_trimmed = v.trim();
                let v_bytes = val_trimmed.as_bytes();
                *out_len = v_bytes.len();
                if out_buf.is_null() || cap < v_bytes.len() {
                    return if out_buf.is_null() { 0 } else { -2 };
                }
                std::ptr::copy_nonoverlapping(v_bytes.as_ptr(), out_buf, v_bytes.len());
                return 0;
            }
        }
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
    let cookie_name = b"RBXEventTrackerV2";

    for line in headers_str.lines() {
        let trimmed = line.trim();
        if trimmed.len() >= 11 && trimmed[..11].eq_ignore_ascii_case("set-cookie:") {
            let rest = &trimmed[11..];
            let rc = mocktail_rust_browser_tracker_extract_cookie(
                rest.as_ptr() as *const c_char,
                rest.len(),
                cookie_name.as_ptr() as *const c_char,
                cookie_name.len(),
                out_buf,
                cap,
                out_len,
            );
            if rc == 0 {
                return 0;
            }
        }
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
    if slice.starts_with(b"_|") {
        let mut end = 0;
        while end < slice.len() && !is_auth_cookie_delimiter(slice[end]) {
            end += 1;
        }
        let val = trim_ascii_whitespace(&slice[..end]);
        *out_present = true;
        if !out_buf.is_null() && !out_len.is_null() {
            if cap <= val.len() {
                return -2;
            }
            if !val.is_empty() {
                std::ptr::copy_nonoverlapping(val.as_ptr() as *const c_char, out_buf, val.len());
            }
            *out_buf.add(val.len()) = 0;
            *out_len = val.len();
        }
        return 0;
    }

    let mut segment_begin = 0;
    while segment_begin < slice.len() {
        while segment_begin < slice.len() && (is_auth_cookie_delimiter(slice[segment_begin]) || slice[segment_begin].is_ascii_whitespace()) {
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
            *out_present = true;
            let val = match equals_pos {
                Some(pos) => trim_ascii_whitespace(&segment[pos + 1..]),
                None => &[][..],
            };
            if !out_buf.is_null() && !out_len.is_null() {
                if cap <= val.len() {
                    return -2;
                }
                if !val.is_empty() {
                    std::ptr::copy_nonoverlapping(val.as_ptr() as *const c_char, out_buf, val.len());
                }
                *out_buf.add(val.len()) = 0;
                *out_len = val.len();
            }
            return 0;
        }
        segment_begin = segment_end + if segment_end < slice.len() { 1 } else { 0 };
    }
    0
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
    slice.iter().all(|&b| b > 0x20 && b < 0x7f && b != b';')
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
    let val: serde_json::Value = match serde_json::from_slice(slice) {
        Ok(v) => v,
        Err(_) => return -2,
    };
    let obj = match val.as_object() {
        Some(o) => o,
        None => return -3,
    };
    let id_val = match obj.get("id") {
        Some(v) => v,
        None => return -4,
    };
    let user_id = if let Some(n) = id_val.as_number() {
        if let Some(u) = n.as_u64() {
            if u == 0 || u > i64::MAX as u64 {
                return -5;
            }
            u as i64
        } else if let Some(s) = n.as_i64() {
            if s <= 0 {
                return -6;
            }
            s
        } else {
            return -7;
        }
    } else {
        return -8;
    };

    let name = match obj.get("name").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return -9,
    };
    let display_name = match obj.get("displayName").and_then(|v| v.as_str()) {
        Some(s) => s,
        _ => return -10,
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
    if payload_id.is_empty() {
        return -2;
    }
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

    let digest = Sha256::digest(evidence.as_bytes());
    let hex_str = hex::encode(digest);
    std::ptr::copy_nonoverlapping(hex_str.as_ptr(), out_sha256 as *mut u8, 64);
    *out_sha256.add(64) = 0;
    0
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

    let mut evidence = String::with_capacity(512);
    evidence.push_str("runtime_build_id=");
    evidence.push_str(rbid);
    evidence.push('\n');
    evidence.push_str("payload=");
    evidence.push_str(fp);
    evidence.push('\n');
    evidence.push_str("profile=");
    evidence.push_str(prof);
    evidence.push('\n');
    evidence.push_str("compatibility=");
    evidence.push_str(compat);
    evidence.push('\n');
    evidence.push_str("canary_1=");
    evidence.push_str(c1);
    evidence.push('\n');
    evidence.push_str("canary_2=");
    evidence.push_str(c2);
    evidence.push('\n');

    let digest = Sha256::digest(evidence.as_bytes());
    let hex_str = hex::encode(digest);
    std::ptr::copy_nonoverlapping(hex_str.as_ptr(), out_generation_40 as *mut u8, 40);
    *out_generation_40.add(40) = 0;
    0
}

unsafe fn write_err_msg(out_err: *mut c_char, err_cap: usize, msg: &str) {
    copy_error(out_err, err_cap, msg);
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
        write_err_msg(out_err, err_cap, "derived approval profile is not bound to exact payload bytes");
        return 1;
    };

    let c_slice = if !compatibility_json.is_null() && c_len > 0 {
        std::slice::from_raw_parts(compatibility_json as *const u8, c_len)
    } else {
        write_err_msg(out_err, err_cap, "derived approval profile is not bound to exact payload bytes");
        return 1;
    };

    let profile: serde_json::Value = match serde_json::from_slice(p_slice) {
        Ok(v) => v,
        Err(_) => {
            write_err_msg(out_err, err_cap, "derived approval profile is not bound to exact payload bytes");
            return 1;
        }
    };

    let compatibility: serde_json::Value = match serde_json::from_slice(c_slice) {
        Ok(v) => v,
        Err(_) => {
            write_err_msg(out_err, err_cap, "derived approval profile is not bound to exact payload bytes");
            return 1;
        }
    };

    let expected_payload_path = format!("payloads/{}", payload_id_str);

    let profile_valid = profile.is_object()
        && profile.get("schema_version").and_then(|v| v.as_i64()) == Some(1)
        && profile.get("payload_id").and_then(|v| v.as_str()) == Some(payload_id_str)
        && profile.get("payload_path").and_then(|v| v.as_str()) == Some(&expected_payload_path)
        && profile.get("elf_build_id").and_then(|v| v.as_str()) == Some(elf_build_id_str)
        && profile.get("payload_sha256").and_then(|v| v.as_str()) == Some(lib_sha_str)
        && profile.get("profile").map_or(false, |v| v.is_object())
        && profile.get("profile").and_then(|p| p.get("elf_build_id")).and_then(|v| v.as_str()) == Some(elf_build_id_str)
        && profile.get("reference").map_or(false, |v| v.is_object())
        && compatibility.is_object()
        && compatibility.get("schema_version").and_then(|v| v.as_i64()) == Some(1)
        && compatibility.get("profiles").and_then(|v| v.as_array()).map_or(false, |arr| arr.len() == 1);

    if !profile_valid {
        write_err_msg(out_err, err_cap, "derived approval profile is not bound to exact payload bytes");
        return 1;
    }

    let profiles = compatibility.get("profiles").unwrap().as_array().unwrap();
    let entry = &profiles[0];

    let entry_valid = entry.is_object()
        && entry.get("version_name").and_then(|v| v.as_str()) == Some(ver_name_str)
        && entry.get("version_code").and_then(|v| v.as_u64()) == Some(version_code)
        && entry.get("elf_build_id").and_then(|v| v.as_str()) == Some(elf_build_id_str)
        && entry.get("status").and_then(|v| v.as_str()) == Some("experimental")
        && entry.get("default_allowed").and_then(|v| v.as_bool()) == Some(true)
        && entry.get("allow_legacy_binary_patches").map_or(true, |v| v.as_bool().unwrap_or(true)) == false
        && entry.get("allow_host_abi_bridges").and_then(|v| v.as_bool()) == Some(true)
        && entry.get("allow_host_constructor_replay").and_then(|v| v.as_bool()) == Some(true);

    if !entry_valid {
        write_err_msg(out_err, err_cap, "candidate compatibility manifest is not exact probation metadata");
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

    let mut map = std::collections::BTreeMap::new();
    map.insert("canary_tier", serde_json::Value::String("C".into()));
    map.insert("compatibility_manifest_sha256", serde_json::Value::String(compatibility_manifest_sha256.into()));
    map.insert("payload_fingerprint", serde_json::Value::String(payload_fingerprint.into()));
    map.insert("payload_id", serde_json::Value::String(payload_id.into()));
    map.insert("profile_sha256", serde_json::Value::String(profile_sha256.into()));
    map.insert("readiness_log_sha256", serde_json::Value::String(log_sha256.into()));
    map.insert("run", serde_json::Value::Number(serde_json::Number::from(inp.run)));
    map.insert("run_id", serde_json::Value::String(run_id.into()));
    map.insert("runtime_build_id", serde_json::Value::String(runtime_build_id.into()));
    map.insert("runtime_sha256", serde_json::Value::String(runtime_sha256.into()));
    map.insert("schema_version", serde_json::Value::Number(serde_json::Number::from(1)));
    map.insert("status", serde_json::Value::String("passed".into()));

    let mut json_str = match serde_json::to_string_pretty(&map) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    json_str.push('\n');

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

    let mut map = std::collections::BTreeMap::new();
    map.insert("approved_at", serde_json::Value::String(approved_at.into()));
    map.insert("canary_attestation_sha256", serde_json::Value::Array(vec![
        serde_json::Value::String(canary_1.into()),
        serde_json::Value::String(canary_2.into()),
    ]));
    map.insert("canary_runtime_sha256", serde_json::Value::String(runtime_sha256.into()));
    map.insert("canary_tier", serde_json::Value::String("C".into()));
    map.insert("compatibility_manifest_sha256", serde_json::Value::String(compatibility_manifest_sha256.into()));
    map.insert("elf_build_id", serde_json::Value::String(elf_build_id.into()));
    map.insert("generation", serde_json::Value::String(generation.into()));
    map.insert("payload_fingerprint", serde_json::Value::String(payload_fingerprint.into()));
    map.insert("payload_id", serde_json::Value::String(payload_id.into()));
    map.insert("payload_path", serde_json::Value::String(payload_path.into()));
    map.insert("payload_sha256", serde_json::Value::String(library_sha256.into()));
    map.insert("profile_sha256", serde_json::Value::String(profile_sha256.into()));
    map.insert("runtime_build_id", serde_json::Value::String(runtime_build_id.into()));
    map.insert("runtime_sha256", serde_json::Value::String(runtime_sha256.into()));
    map.insert("schema_version", serde_json::Value::Number(serde_json::Number::from(1)));
    map.insert("status", serde_json::Value::String("approved".into()));
    map.insert("successful_runs", serde_json::Value::Number(serde_json::Number::from(2)));

    let mut json_str = match serde_json::to_string_pretty(&map) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    json_str.push('\n');

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

fn copy_error(dst: *mut c_char, cap: usize, msg: &str) {
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
  --graphics <backend>     direct-vulkan | opengl | system | angle-vulkan (default: direct-vulkan)
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
    let val: serde_json::Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => return -3,
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

#[no_mangle]
pub extern "C" fn mocktail_rust_clamp_text_input_area(
    x: *mut i32,
    y: *mut i32,
    w: *mut i32,
    h: *mut i32,
    cursor: *mut i32,
) {
    unsafe {
        if !w.is_null() && *w <= 0 {
            *w = 1;
        }
        if !h.is_null() && *h <= 0 {
            *h = 1;
        }
        if !x.is_null() && *x < 0 {
            *x = 0;
        }
        if !y.is_null() && *y < 0 {
            *y = 0;
        }
        if !cursor.is_null() && *cursor < 0 {
            *cursor = 0;
        }
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

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_status_string(status: *const c_char) -> i32 {
    if status.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(status) }.to_str().unwrap_or("");
    match s {
        "supported" => 0,
        "experimental" => 1,
        "legacy-researched" => 2,
        "unverified" => 3,
        _ => -1,
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
    let s = unsafe { CStr::from_ptr(hex_str) }.to_str().unwrap_or("").trim();
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return -2;
    }
    let hex_part = &s[2..];
    if hex_part.is_empty() {
        return -3;
    }
    match usize::from_str_radix(hex_part, 16) {
        Ok(val) => {
            if val == 0 {
                return -4;
            }
            if !out_rva.is_null() {
                unsafe { *out_rva = val };
            }
            0
        }
        Err(_) => -5,
    }
}

// ============================================================================
// 87. ELF Build ID Hex Validator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_is_valid_build_id(
    build_id: *const c_char,
    len: usize,
) -> i32 {
    if build_id.is_null() || len < 8 || len > 128 || len % 2 != 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(build_id as *const u8, len) };
    if slice.iter().all(|&b| b.is_ascii_hexdigit()) {
        1
    } else {
        0
    }
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
    let val: serde_yaml::Value = match serde_yaml::from_str(s) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "cannot parse update configuration");
            return -3;
        }
    };
    let map = match val.as_mapping() {
        Some(m) => m,
        None => {
            copy_error(err_buf, err_cap, "configuration root must be a mapping");
            return -4;
        }
    };

    if let Some(ver) = map.get(&serde_yaml::Value::String("version".to_string())) {
        let ver_str = match ver {
            serde_yaml::Value::String(s) => s.as_str(),
            serde_yaml::Value::Number(n) => {
                if n.as_i64() == Some(1) { "1" } else { "invalid" }
            }
            _ => "invalid",
        };
        if ver_str != "1" {
            copy_error(err_buf, err_cap, "only configuration version 1 is supported");
            return -5;
        }
    }

    let updates = match map.get(&serde_yaml::Value::String("updates".to_string())).and_then(|v| v.as_mapping()) {
        Some(u) => u,
        None => {
            copy_error(err_buf, err_cap, "updates must be a mapping");
            return -6;
        }
    };

    let mut auto_val = true;
    let mut launch_val = true;
    let mut source_val = "auto".to_string();

    for (k, v) in updates {
        let key_str = match k.as_str() {
            Some(s) => s,
            None => {
                copy_error(err_buf, err_cap, "updates contains an empty or duplicate key");
                return -7;
            }
        };
        match key_str {
            "automatic" => {
                match v.as_bool() {
                    Some(b) => auto_val = b,
                    None => {
                        copy_error(err_buf, err_cap, "updates.automatic must be true or false");
                        return -8;
                    }
                }
            }
            "launch_after_update" => {
                match v.as_bool() {
                    Some(b) => launch_val = b,
                    None => {
                        copy_error(err_buf, err_cap, "updates.launch_after_update must be true or false");
                        return -9;
                    }
                }
            }
            "source" => {
                match v.as_str() {
                    Some(s) if s == "auto" || s == "apk-pure" => {
                        source_val = s.to_string();
                    }
                    _ => {
                        copy_error(err_buf, err_cap, "updates.source must be auto or apk-pure in the native updater");
                        return -10;
                    }
                }
            }
            "testing_latest_only" => {
                // Deprecated, ignored
            }
            _ => {
                let err_msg = format!("unknown updates key: {}", key_str);
                copy_error(err_buf, err_cap, &err_msg);
                return -11;
            }
        }
    }

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

const OVERRIDDEN_ENV_VARS: &[&str] = &[
    "ROBLOX_LIB_PATH",
    "MOCKTAIL_ASSET_ROOT",
    "MOCKTAIL_ASSET_PATH",
    "MOCKTAIL_COMPATIBILITY_MANIFEST",
    "MOCKTAIL_HOST_ABI_PROFILE_FILE",
    "MOCKTAIL_HOST_ABI_CANARY",
    "MOCKTAIL_ALLOW_CANDIDATE_HOST_ABI",
    "MOCKTAIL_HOST_ABI_APPROVAL_RECEIPT",
    "MOCKTAIL_SKIP_UPDATE_CHECK",
    "MOCKTAIL_UNSAFE_LATEST",
];

#[no_mangle]
pub extern "C" fn mocktail_rust_is_overridden_environment_var(entry: *const c_char) -> i32 {
    if entry.is_null() {
        return 0;
    }
    let s = unsafe { CStr::from_ptr(entry) }.to_str().unwrap_or("");
    for &var in OVERRIDDEN_ENV_VARS {
        if s.starts_with(var) && s.as_bytes().get(var.len()) == Some(&b'=') {
            return 1;
        }
    }
    0
}

// ============================================================================
// 94. Canary Readiness Backend & Audio Log Validator
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_canary_backend_parse(
    name: *const c_char,
    out_backend: *mut i32,
) -> i32 {
    let s = if !name.is_null() {
        unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
    } else {
        ""
    };
    let val = match s {
        "" | "vulkan" | "native-vulkan" | "direct-vulkan" => 0,
        "gles" | "opengl" => 1,
        "auto" | "system" => 2,
        "angle-vulkan" => 3,
        "angle-swiftshader" => 4,
        _ => return -1,
    };
    if !out_backend.is_null() {
        unsafe { *out_backend = val };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_canary_backend_name(
    backend: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let name = match backend {
        0 => "direct-vulkan",
        1 => "opengl",
        2 => "system",
        3 => "angle-vulkan",
        4 => "angle-swiftshader",
        _ => "direct-vulkan",
    };
    copy_to_c_buffer(name, out_buf, out_cap);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_canary_audio_log(
    log_text: *const c_char,
    log_len: usize,
    require_clean_shutdown: i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if log_text.is_null() || log_len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(log_text as *const u8, log_len) };
    let log = String::from_utf8_lossy(slice);

    fn has_positive_number_after(text: &str, marker: &str) -> bool {
        let mut pos = 0;
        while let Some(found) = text[pos..].find(marker) {
            let start = pos + found + marker.len();
            let digits: String = text[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(num) = digits.parse::<u64>() {
                if num > 0 {
                    return true;
                }
            }
            pos = start;
        }
        false
    }

    let opensl = has_positive_number_after(&log, "[mocktail][audio] OpenSL playback activity: submitted_buffers=");
    let fmod = has_positive_number_after(&log, "[mocktail][audio] fmod_java first_submission submitted_buffers=");

    if log.contains("[mocktail][audio] fmod_java init_failed")
        || log.contains("[mocktail][audio] fmod_java write_failed")
        || log.contains("[mocktail][audio] fmod_java close_failed")
    {
        copy_error(err_buf, err_cap, "graphics canary observed an FMOD audio failure");
        return -1;
    }
    if opensl
        && (!has_positive_number_after(&log, "[mocktail][audio] OpenSL playback evidence: consumed_buffers=")
            || (require_clean_shutdown != 0
                && (!log.contains("[mocktail][audio] OpenSL player shutdown: submitted=")
                    || !log.contains("clean=true"))))
    {
        copy_error(err_buf, err_cap, "graphics canary submitted OpenSL audio without clean consumption");
        return -2;
    }
    if fmod
        && (!has_positive_number_after(&log, "consumed_buffers=")
            || (require_clean_shutdown != 0
                && (!log.contains("[mocktail][audio] fmod_java shutdown submitted_buffers=")
                    || !log.contains("pending_buffers=0"))))
    {
        copy_error(err_buf, err_cap, "graphics canary submitted FMOD audio without clean consumption");
        return -3;
    }

    0
}

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
        if mocktail_rust_validate_json_depth(request_json, 8) == 0 {
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

// ============================================================================
// 110. Vulkan ETC2 Emulation Helpers & Streaming Staging Copy
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_lookup_format(
    vk_format: i32,
    out_host_format: *mut i32,
    out_etc_format: *mut i32,
) -> i32 {
    const VK_FORMAT_R8G8B8A8_UNORM: i32 = 37;
    const VK_FORMAT_R8G8B8A8_SRGB: i32 = 43;
    const VK_FORMAT_R16_UNORM: i32 = 70;
    const VK_FORMAT_R16_SNORM: i32 = 71;
    const VK_FORMAT_R16G16_UNORM: i32 = 77;
    const VK_FORMAT_R16G16_SNORM: i32 = 78;

    let (host, etc) = match vk_format {
        147 => (VK_FORMAT_R8G8B8A8_UNORM, 0),
        148 => (VK_FORMAT_R8G8B8A8_SRGB, 0),
        149 => (VK_FORMAT_R8G8B8A8_UNORM, 1),
        150 => (VK_FORMAT_R8G8B8A8_SRGB, 1),
        151 => (VK_FORMAT_R8G8B8A8_UNORM, 2),
        152 => (VK_FORMAT_R8G8B8A8_SRGB, 2),
        153 => (VK_FORMAT_R16_UNORM, 3),
        154 => (VK_FORMAT_R16_SNORM, 4),
        155 => (VK_FORMAT_R16G16_UNORM, 5),
        156 => (VK_FORMAT_R16G16_SNORM, 6),
        _ => return 0,
    };
    if !out_host_format.is_null() {
        unsafe { *out_host_format = host };
    }
    if !out_etc_format.is_null() {
        unsafe { *out_etc_format = etc };
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_emulated_features(host_features: u32) -> u32 {
    const COMPRESSED_FEATURES: u32 = 0x0000_0001 | 0x0000_1000 | 0x0000_0400 | 0x0000_4000 | 0x0000_8000;
    host_features & COMPRESSED_FEATURES
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_upload_byte_counts(
    block_bytes: u64,
    texel_bytes: u64,
    width: u32,
    height: u32,
    depth: u32,
    layer_count: u32,
    out_compressed: *mut u64,
    out_decoded: *mut u64,
) -> i32 {
    if width == 0
        || height == 0
        || depth != 1
        || layer_count == 0
        || out_compressed.is_null()
        || out_decoded.is_null()
    {
        return 0;
    }
    let blocks_w = (width as u64).saturating_add(3) / 4;
    let blocks_h = (height as u64).saturating_add(3) / 4;
    let compressed = blocks_w
        .checked_mul(blocks_h)
        .and_then(|b| b.checked_mul(block_bytes))
        .and_then(|b| b.checked_mul(layer_count as u64));
    let decoded = (width as u64)
        .checked_mul(height as u64)
        .and_then(|p| p.checked_mul(texel_bytes))
        .and_then(|p| p.checked_mul(layer_count as u64));
    match (compressed, decoded) {
        (Some(c), Some(d)) => {
            unsafe {
                *out_compressed = c;
                *out_decoded = d;
            }
            1
        }
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_support_advertised(value: *const c_char) -> i32 {
    if value.is_null() {
        return 1;
    }
    if unsafe { CStr::from_ptr(value) }.to_bytes() != b"0" {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_small_texture_upscale(value: *const c_char) -> u32 {
    if value.is_null() {
        return 1;
    }
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return 1;
    }
    let mut parsed: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            break;
        }
        parsed = parsed.saturating_mul(10).saturating_add((b - b'0') as u64);
    }
    parsed.clamp(1, 8) as u32
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn copy_from_mapped_sse41(mut dst: *mut u8, mut src: *const u8, mut size: usize) {
    use std::arch::x86_64::{__m128i, _mm_storeu_si128, _mm_stream_load_si128};
    while size != 0 && ((src as usize) & 15) != 0 {
        *dst = *src;
        dst = dst.add(1);
        src = src.add(1);
        size -= 1;
    }
    let mut in_ptr = src as *mut __m128i;
    while size >= 64 {
        let a = _mm_stream_load_si128(in_ptr);
        let b = _mm_stream_load_si128(in_ptr.add(1));
        let c = _mm_stream_load_si128(in_ptr.add(2));
        let d = _mm_stream_load_si128(in_ptr.add(3));
        _mm_storeu_si128(dst as *mut __m128i, a);
        _mm_storeu_si128(dst.add(16) as *mut __m128i, b);
        _mm_storeu_si128(dst.add(32) as *mut __m128i, c);
        _mm_storeu_si128(dst.add(48) as *mut __m128i, d);
        in_ptr = in_ptr.add(4);
        dst = dst.add(64);
        size -= 64;
    }
    if size > 0 {
        std::ptr::copy_nonoverlapping(in_ptr as *const u8, dst, size);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_copy_from_mapped(
    destination: *mut u8,
    source: *const u8,
    size: usize,
) {
    if destination.is_null() || source.is_null() || size == 0 || destination as *const u8 == source {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.1") {
        unsafe {
            copy_from_mapped_sse41(destination, source, size);
        }
        return;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(source, destination, size);
    }
}

// ============================================================================
// 111. Graphics Launch Policy, PCI GPU & Vulkan ICD Selector
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_is_haswell_intel(device_id: u32) -> i32 {
    let matched = (0x0150..=0x016a).contains(&device_id)
        || (0x0400..=0x042f).contains(&device_id)
        || (0x0a00..=0x0a2f).contains(&device_id)
        || (0x0c00..=0x0c2f).contains(&device_id)
        || (0x0d00..=0x0d2f).contains(&device_id);
    if matched { 1 } else { 0 }
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

#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_read_json_file(
    path_ptr: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    const MAX_STATE_BYTES: u64 = 65536;
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
        Ok(s) if !s.is_empty() => s,
        _ => return -1,
    };
    let meta = match std::fs::symlink_metadata(path_str) {
        Ok(m) => m,
        Err(_) => return -1,
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > MAX_STATE_BYTES {
        return -1;
    }
    let file = match File::open(path_str) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let mut buf = String::new();
    if file
        .take(MAX_STATE_BYTES + 1)
        .read_to_string(&mut buf)
        .is_err()
        || buf.len() as u64 > MAX_STATE_BYTES
    {
        return -1;
    }
    let doc: serde_json::Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    if !doc.is_object() {
        return -1;
    }
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

fn webview_is_roblox_host_str(host: &str) -> bool {
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            encoded.push(b as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(b >> 4) as usize] as char);
            encoded.push(HEX[(b & 15) as usize] as char);
        }
    }
    encoded
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

fn host_allocations_map() -> &'static std::sync::Mutex<std::collections::HashMap<usize, usize>> {
    static MAP: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<usize, usize>>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
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
    let mut guard = host_allocations_map().lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = host_allocations_map().lock().unwrap_or_else(|e| e.into_inner());
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
        let mut guard = host_allocations_map().lock().unwrap_or_else(|e| e.into_inner());
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
    let guard = host_allocations_map().lock().unwrap_or_else(|e| e.into_inner());
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
#[derive(Debug, Clone, Copy, Default)]
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_secure_zero() {
        let mut buf = [1u8, 2, 3, 4, 5];
        mocktail_rust_secure_zero(buf.as_mut_ptr(), buf.len());
        assert_eq!(buf, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_sha256() {
        let data = b"hello mocktail";
        let mut out = [0 as c_char; 65];
        let rc = mocktail_rust_sha256(data.as_ptr(), data.len(), out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_utf8_and_control_bytes() {
        let valid = b"hello world\0";
        assert_eq!(mocktail_rust_is_valid_utf8(valid.as_ptr(), 11), 1);
        assert_eq!(mocktail_rust_contains_control_bytes(valid.as_ptr(), 11), 0);

        let with_ctrl = b"hello\x07world\0";
        assert_eq!(mocktail_rust_contains_control_bytes(with_ctrl.as_ptr(), 11), 1);
    }

    #[test]
    fn test_percent_decode() {
        let enc = CString::new("Hello%20World%21").unwrap();
        let mut out = [0 as c_char; 32];
        let rc = mocktail_rust_percent_decode(enc.as_ptr(), 0, out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "Hello World!");

        let enc_plus = CString::new("a+b").unwrap();
        let rc2 = mocktail_rust_percent_decode(enc_plus.as_ptr(), 1, out.as_mut_ptr(), out.len());
        assert_eq!(rc2, 0);
        let s2 = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s2, "a b");
    }

    #[test]
    fn test_status_memory_parsing() {
        let sample = "Name:\tmocktail\nVmRSS:\t   12345 kB\nVmSwap:\t    100 kB\n";
        let c_sample = CString::new(sample).unwrap();
        let mut rss = 0u64;
        let mut swap = 0u64;
        let ok = mocktail_rust_parse_status_memory(c_sample.as_ptr(), &mut rss, &mut swap);
        assert_eq!(ok, 1);
        assert_eq!(rss, 12345 * 1024);
        assert_eq!(swap, 100 * 1024);
    }

    #[test]
    fn test_discord_frame_builder() {
        let payload = CString::new("{\"v\": 1}").unwrap();
        let mut buf = [0u8; 64];
        let mut len = 0usize;
        let rc = mocktail_rust_build_discord_frame(
            1,
            payload.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut len,
        );
        assert_eq!(rc, 0);
        assert_eq!(len, 8 + 8);
        assert_eq!(buf[0..4], 1u32.to_le_bytes());
        assert_eq!(buf[4..8], 8u32.to_le_bytes());
        assert_eq!(&buf[8..16], b"{\"v\": 1}");
    }

    #[test]
    fn test_safe_archive_path() {
        let safe1 = CString::new("assets/data.bin").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(safe1.as_ptr()), 1);

        let safe2 = CString::new("dir/subdir/").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(safe2.as_ptr()), 1);

        let unsafe1 = CString::new("../etc/passwd").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe1.as_ptr()), 0);

        let unsafe2 = CString::new("/absolute/path").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe2.as_ptr()), 0);

        let unsafe3 = CString::new("dir/../escape").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe3.as_ptr()), 0);

        let unsafe4 = CString::new("dir//escape").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe4.as_ptr()), 0);

        let unsafe5 = CString::new("win\\path").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe5.as_ptr()), 0);
    }

    #[test]
    fn test_jni_signature() {
        let valid1 = CString::new("(Ljava/lang/String;I)V").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(valid1.as_ptr()), 1);

        let valid2 = CString::new("()I").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(valid2.as_ptr()), 1);

        let valid3 = CString::new("([B)[Ljava/lang/String;").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(valid3.as_ptr()), 1);

        let invalid1 = CString::new("invalid").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid1.as_ptr()), 0);

        let invalid2 = CString::new("(Ljava/lang/String)V").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid2.as_ptr()), 0);

        let invalid3 = CString::new("([V)V").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid3.as_ptr()), 0);
    }

    #[test]
    fn test_file_sha256() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let file_path = dir.join("mocktail_test_file2.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"mocktail-file-test2").unwrap();
        }
        let c_path = CString::new(file_path.to_str().unwrap()).unwrap();
        let mut out = [0 as c_char; 65];
        let rc = mocktail_rust_sha256_file(c_path.as_ptr(), out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0);

        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s.len(), 64);

        let verify_rc = mocktail_rust_verify_file_sha256(c_path.as_ptr(), out.as_ptr());
        assert_eq!(verify_rc, 1);

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_apk_signing_magic() {
        assert_eq!(mocktail_rust_verify_apk_signing_magic(b"APK Sig Block 42".as_ptr(), 16), 1);
        assert_eq!(mocktail_rust_verify_apk_signing_magic(b"WrongMagicBlock!".as_ptr(), 16), 0);
    }

    #[test]
    fn test_mutf8() {
        // Test null byte encoding: \0 -> 0xC0 0x80
        let null_u16 = [0u16];
        let mut mutf8_buf = [0u8; 8];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_utf16_to_mutf8(null_u16.as_ptr(), 1, mutf8_buf.as_mut_ptr(), 8, &mut len), 0);
        assert_eq!(len, 2);
        assert_eq!(&mutf8_buf[0..2], &[0xC0, 0x80]);

        // Test decode 0xC0 0x80 back to 0u16
        let mut u16_buf = [0u16; 8];
        let mut u16_len = 0usize;
        assert_eq!(mocktail_rust_mutf8_to_utf16(mutf8_buf.as_ptr(), 2, u16_buf.as_mut_ptr(), 8, &mut u16_len), 0);
        assert_eq!(u16_len, 1);
        assert_eq!(u16_buf[0], 0);

        // Test normal string "Hello"
        let hello = b"Hello\0";
        assert_eq!(mocktail_rust_mutf8_to_utf16(hello.as_ptr(), 5, u16_buf.as_mut_ptr(), 8, &mut u16_len), 0);
        assert_eq!(u16_len, 5);
        assert_eq!(&u16_buf[0..5], &[b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16]);

        let mut utf8_buf = [0u8; 16];
        let mut utf8_len = 0usize;
        assert_eq!(mocktail_rust_mutf8_to_utf8(hello.as_ptr(), 5, utf8_buf.as_mut_ptr(), 16, &mut utf8_len), 0);
        assert_eq!(utf8_len, 5);
        assert_eq!(&utf8_buf[0..5], b"Hello");
    }

    #[test]
    fn test_cookie_parser() {
        let cookie = CString::new(".ROBLOSECURITY=\"_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_ABC1234567890XYZ\"; path=/; domain=.roblox.com").unwrap();
        let mut out = [0 as c_char; 256];
        let mut out_len = 0usize;
        let rc = mocktail_rust_parse_roblox_cookie(cookie.as_ptr(), out.as_mut_ptr(), out.len(), &mut out_len);
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert!(s.starts_with("_|WARNING:"));
        assert!(s.ends_with("ABC1234567890XYZ"));

        assert_eq!(mocktail_rust_is_valid_cookie_octet(b'A'), 1);
        assert_eq!(mocktail_rust_is_valid_cookie_octet(b' '), 0);
    }

    #[test]
    fn test_permissions_bridge() {
        assert_eq!(mocktail_rust_validate_json_depth(b"{\"a\":{\"b\":1}}\0".as_ptr() as *const c_char, 8), 1);
        assert_eq!(mocktail_rust_validate_json_depth(b"{\"a\":{\"b\":{\"c\":{\"d\":1}}}}\0".as_ptr() as *const c_char, 2), 0);

        let json = CString::new("{\"permissions\":[\"LOCAL_NETWORK\",\"MICROPHONE_ACCESS\"]}").unwrap();
        let mut has_missing = 0;
        let mut missing_buf = [0 as c_char; 256];

        // Mic enabled -> none missing
        let rc = mocktail_rust_check_permission_request(json.as_ptr(), 1, &mut has_missing, missing_buf.as_mut_ptr(), 256);
        assert_eq!(rc, 0);
        assert_eq!(has_missing, 0);

        // Mic disabled -> MICROPHONE_ACCESS missing
        let rc2 = mocktail_rust_check_permission_request(json.as_ptr(), 0, &mut has_missing, missing_buf.as_mut_ptr(), 256);
        assert_eq!(rc2, 0);
        assert_eq!(has_missing, 1);
        let missing_str = unsafe { CStr::from_ptr(missing_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(missing_str, "[\"MICROPHONE_ACCESS\"]");
    }

    #[test]
    fn test_elf_parser() {
        let mut elf_buf = vec![0u8; 256];
        elf_buf[0..4].copy_from_slice(b"\x7fELF");
        elf_buf[4] = 2; // 64-bit
        elf_buf[5] = 1; // Little-Endian
        elf_buf[18] = 0x3E; // x86_64
        elf_buf[19] = 0x00;

        assert_eq!(mocktail_rust_verify_elf_architecture(elf_buf.as_ptr(), elf_buf.len(), 0x3E), 1);
        assert_eq!(mocktail_rust_verify_elf_architecture(elf_buf.as_ptr(), elf_buf.len(), 0xB7), 0);

        // Program headers setup: e_phoff = 64, e_phentsize = 56, e_phnum = 1
        elf_buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf_buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf_buf[56..58].copy_from_slice(&1u16.to_le_bytes());

        // Phdr at 64: p_type = 4 (PT_NOTE), p_offset = 120, p_filesz = 32
        elf_buf[64..68].copy_from_slice(&4u32.to_le_bytes());
        elf_buf[72..80].copy_from_slice(&120u64.to_le_bytes());
        elf_buf[96..104].copy_from_slice(&32u64.to_le_bytes());

        // Note at 120: namesz = 4, descsz = 4, type = 3
        elf_buf[120..124].copy_from_slice(&4u32.to_le_bytes());
        elf_buf[124..128].copy_from_slice(&4u32.to_le_bytes());
        elf_buf[128..132].copy_from_slice(&3u32.to_le_bytes());
        // Name: "GNU\0"
        elf_buf[132..136].copy_from_slice(b"GNU\0");
        // Desc: 0x12, 0x34, 0x56, 0x78
        elf_buf[136..140].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        let mut out_hex = [0 as c_char; 64];
        let rc = mocktail_rust_parse_elf_build_id(elf_buf.as_ptr(), elf_buf.len(), out_hex.as_mut_ptr(), 64);
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out_hex.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "12345678");
    }

    #[test]
    fn test_key_mapping() {
        let mut mapping = MocktailRustKeyMapping { scan_code: 0, key_code: 0 };
        assert_eq!(mocktail_rust_map_sdl_key_to_android(4, 0, &mut mapping), 1); // SDL_SCANCODE_A
        assert_eq!(mapping.scan_code, 30);
        assert_eq!(mapping.key_code, 29);

        assert_eq!(mocktail_rust_map_sdl_key_to_android(40, 0, &mut mapping), 1); // RETURN
        assert_eq!(mapping.scan_code, 28);
        assert_eq!(mapping.key_code, 66);

        assert_eq!(mocktail_rust_map_sdl_mouse_button(1), 0);
        assert_eq!(mocktail_rust_map_sdl_mouse_button(3), 1);
        assert_eq!(mocktail_rust_map_sdl_mouse_button(2), 2);
    }

    #[test]
    fn test_system_proxy_resolver() {
        let uri = CString::new("http://127.0.0.1:8080").unwrap();
        let mut scheme = [0 as c_char; 32];
        let mut host = [0 as c_char; 64];
        let mut port: u16 = 0;
        let mut is_direct: c_int = 0;
        let mut has_auth: c_int = 0;

        let rc = mocktail_rust_parse_proxy_uri(
            uri.as_ptr(),
            scheme.as_mut_ptr(),
            32,
            host.as_mut_ptr(),
            64,
            &mut port,
            &mut is_direct,
            &mut has_auth,
        );
        assert_eq!(rc, 0);
        assert_eq!(unsafe { CStr::from_ptr(scheme.as_ptr()) }.to_str().unwrap(), "http");
        assert_eq!(unsafe { CStr::from_ptr(host.as_ptr()) }.to_str().unwrap(), "127.0.0.1");
        assert_eq!(port, 8080);
        assert_eq!(is_direct, 0);
        assert_eq!(has_auth, 0);

        // Test direct://
        let direct_uri = CString::new("direct://").unwrap();
        let rc_dir = mocktail_rust_parse_proxy_uri(
            direct_uri.as_ptr(),
            scheme.as_mut_ptr(),
            32,
            host.as_mut_ptr(),
            64,
            &mut port,
            &mut is_direct,
            &mut has_auth,
        );
        assert_eq!(rc_dir, 0);
        assert_eq!(is_direct, 1);
        assert_eq!(port, 0);

        // Test auth
        let auth_uri = CString::new("socks5://user:pass@192.168.1.1").unwrap();
        let rc_auth = mocktail_rust_parse_proxy_uri(
            auth_uri.as_ptr(),
            scheme.as_mut_ptr(),
            32,
            host.as_mut_ptr(),
            64,
            &mut port,
            &mut is_direct,
            &mut has_auth,
        );
        assert_eq!(rc_auth, 0);
        assert_eq!(has_auth, 1);
        assert_eq!(port, 1080);
    }

    #[test]
    fn test_single_instance_lock() {
        let exe = CString::new("/usr/bin/mocktail").unwrap();
        let mut key = [0 as c_char; 32];
        let rc = mocktail_rust_compute_instance_key(exe.as_ptr(), key.as_mut_ptr(), 32);
        assert_eq!(rc, 0);
        let key_str = unsafe { CStr::from_ptr(key.as_ptr()) }.to_str().unwrap();
        assert_eq!(key_str.len(), 16);

        let valid_dec = CString::new("12345").unwrap();
        let zero_dec = CString::new("0").unwrap();
        let neg_dec = CString::new("-5").unwrap();
        let text_dec = CString::new("123a").unwrap();
        assert_eq!(mocktail_rust_is_positive_decimal(valid_dec.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_positive_decimal(zero_dec.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_positive_decimal(neg_dec.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_positive_decimal(text_dec.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_positive_decimal(std::ptr::null()), 0);
    }

    #[test]
    fn test_compatibility_catalog() {
        let json = r#"{
            "schema_version": 1,
            "profiles": [
                {
                    "abi": "x86_64",
                    "version_name": "2.600.123",
                    "version_code": 600123,
                    "elf_build_id": "0123456789abcdef0123456789abcdef01234567",
                    "status": "supported",
                    "default_allowed": true,
                    "allow_legacy_binary_patches": false
                },
                {
                    "abi": "arm64-v8a",
                    "version_name": "2.600.123",
                    "version_code": 600123,
                    "elf_build_id": "abcdef0123456789abcdef0123456789abcdef01",
                    "status": "supported",
                    "default_allowed": true,
                    "allow_legacy_binary_patches": false
                }
            ]
        }"#;

        let abi = CString::new("x86_64").unwrap();
        let mut profiles = [MocktailRustPayloadProfile {
            version_name: [0; 64],
            version_code: 0,
            elf_build_id: [0; 41],
        }; 4];
        let mut count: usize = 0;
        let mut err_buf = [0 as c_char; 128];

        let rc = mocktail_rust_parse_compatibility_catalog(
            json.as_ptr(),
            json.len(),
            abi.as_ptr(),
            profiles.as_mut_ptr(),
            4,
            &mut count,
            err_buf.as_mut_ptr(),
            128,
        );
        assert_eq!(rc, 0);
        assert_eq!(count, 1);
        let vn = unsafe { CStr::from_ptr(profiles[0].version_name.as_ptr()) }.to_str().unwrap();
        assert_eq!(vn, "2.600.123");
        assert_eq!(profiles[0].version_code, 600123);
        let bid = unsafe { CStr::from_ptr(profiles[0].elf_build_id.as_ptr()) }.to_str().unwrap();
        assert_eq!(bid, "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn test_crash_report_policy() {
        let base = CString::new("{\"CustomFlag\":\"123\"}").unwrap();
        let mut out_buf = [0 as c_char; 8192];
        let mut out_len: usize = 0;

        let rc = mocktail_rust_merge_crash_report_settings(
            base.as_ptr(),
            0,
            out_buf.as_mut_ptr(),
            8192,
            &mut out_len,
        );
        assert_eq!(rc, 0);
        let merged_str = unsafe { CStr::from_ptr(out_buf.as_ptr()) }.to_str().unwrap();
        assert!(merged_str.contains("\"CustomFlag\":\"123\""));
        assert!(merged_str.contains("\"DFFlagUseCrashpad\":\"False\""));
        assert!(merged_str.contains("\"EnableAppHangMonitor\":\"False\""));
    }

    #[test]
    fn test_device_profile() {
        let mut name_buf = [0 as c_char; 64];
        let pc = CString::new("pc").unwrap();
        assert_eq!(mocktail_rust_canonical_device_profile_name(pc.as_ptr(), name_buf.as_mut_ptr(), 64), 0);
        assert_eq!(unsafe { CStr::from_ptr(name_buf.as_ptr()) }.to_str().unwrap(), "pc-windows-11");

        let val_valid = CString::new("Valid_Value-1").unwrap();
        let val_invalid = CString::new("Invalid\nValue").unwrap();
        assert_eq!(mocktail_rust_is_valid_device_profile_value(val_valid.as_ptr(), 32), 1);
        assert_eq!(mocktail_rust_is_valid_device_profile_value(val_invalid.as_ptr(), 32), 0);

        let mut key_buf = [0 as c_char; 128];
        let platform = CString::new("Android").unwrap();
        let rc_key = mocktail_rust_build_device_profile_cache_key(
            pc.as_ptr(),
            platform.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            key_buf.as_mut_ptr(),
            128,
        );
        assert_eq!(rc_key, 0);
        let key_str = unsafe { CStr::from_ptr(key_buf.as_ptr()) }.to_str().unwrap();
        assert!(key_str.starts_with("pc-custom-"));
    }

    #[test]
    fn test_bionic_dns_blocker() {
        let blocked1 = CString::new("crashes.rbxinfra.com").unwrap();
        let blocked2 = CString::new("sub.crashes.rbxinfra.com.").unwrap();
        let blocked3 = CString::new("backtrace.io").unwrap();
        let safe1 = CString::new("roblox.com").unwrap();
        let safe2 = CString::new("notcrashes.rbxinfra.com").unwrap();

        assert_eq!(mocktail_rust_is_blocked_crash_host(blocked1.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_blocked_crash_host(blocked2.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_blocked_crash_host(blocked3.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_blocked_crash_host(safe1.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_blocked_crash_host(safe2.as_ptr()), 0);

        // POSIX EAI codes to Bionic error codes
        assert_eq!(mocktail_rust_bionic_eai_error(0), 0);
        assert_eq!(mocktail_rust_bionic_eai_error(-2), 8); // EAI_NONAME -> kBionicAddressInfoNameNotFound (8)
        assert_eq!(mocktail_rust_bionic_eai_error(-4), 4); // EAI_FAIL -> kBionicAddressInfoFailure (4)
        assert_eq!(mocktail_rust_bionic_eai_error(-10), 6); // EAI_MEMORY -> kBionicAddressInfoMemory (6)
    }

    #[test]
    fn test_roblox_launch_uri() {
        let uri = CString::new("roblox://experiences/start?placeId=1818&launchData=hello%20world").unwrap();
        let mut out_json = [0 as c_char; 1024];
        let mut out_err = [0 as c_char; 256];
        let mut follow_id = 0i64;

        let rc = mocktail_rust_parse_roblox_launch_uri(
            uri.as_ptr(),
            0,
            std::ptr::null(),
            out_json.as_mut_ptr(),
            1024,
            out_err.as_mut_ptr(),
            256,
            &mut follow_id,
        );
        assert_eq!(rc, 0);
        let json_str = unsafe { CStr::from_ptr(out_json.as_ptr()) }.to_str().unwrap();
        assert!(json_str.contains("\"placeId\":1818"));
        assert!(json_str.contains("\"launchData\":\"hello world\""));

        // Test classic roblox-player:
        let classic = CString::new("roblox-player:1+launchmode:play+placelauncherurl:https%3A%2F%2Fwww.roblox.com%2Fgame%2Fplacelauncher.ashx%3Frequest%3DRequestGame%26placeId%3D12345").unwrap();
        let rc_classic = mocktail_rust_parse_roblox_launch_uri(
            classic.as_ptr(),
            0,
            std::ptr::null(),
            out_json.as_mut_ptr(),
            1024,
            out_err.as_mut_ptr(),
            256,
            &mut follow_id,
        );
        assert_eq!(rc_classic, 0);
        let classic_json = unsafe { CStr::from_ptr(out_json.as_ptr()) }.to_str().unwrap();
        assert!(classic_json.contains("\"placeId\":12345"));
    }

    #[test]
    fn test_runtime_config_yaml() {
        let yaml = r#"
version: 1
graphics:
  backend: direct-vulkan
  vsync: "on"
performance:
  memory_limit_mb: 2048
runtime:
  headless: false
integrations:
  discord_rpc:
    enabled: true
    show_place_name: true
    show_elapsed_time: true
    join:
      enabled: true
      public_servers_only: true
      button_label: "Join Game"
"#;
        let mut out_env = [0 as c_char; 4096];
        let mut out_err = [0 as c_char; 256];
        let rc = mocktail_rust_parse_runtime_config_yaml(
            yaml.as_ptr(),
            yaml.len(),
            out_env.as_mut_ptr(),
            4096,
            out_err.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        let env_str = unsafe { CStr::from_ptr(out_env.as_ptr()) }.to_str().unwrap();
        assert!(env_str.contains("\"MOCKTAIL_GRAPHICS_BACKEND\":\"direct-vulkan\""));
        assert!(env_str.contains("\"MOCKTAIL_VSYNC\":\"on\""));
        assert!(env_str.contains("\"MOCKTAIL_MEMORY_LIMIT_MB\":\"2048\""));
        assert!(env_str.contains("\"MOCKTAIL_HEADLESS\":\"0\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_ENABLED\":\"1\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_JOIN_ENABLED\":\"1\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_PUBLIC_SERVERS_ONLY\":\"1\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_JOIN_BUTTON_LABEL\":\"Join Game\""));
    }

    #[test]
    fn test_startup_state_machine() {
        let req = MocktailRustStartupRequirements {
            windowed: 1,
            require_input_ready: 1,
            require_audio_ready: 0,
        };
        let sm = mocktail_rust_startup_sm_create(req);
        assert!(!sm.is_null());

        let mut state = MocktailRustStartupState::Created;
        let mut status = 0;
        let mut msg = [0 as c_char; 128];

        // Step 1: Configured
        mocktail_rust_startup_sm_record_evidence(sm, 0, &mut state, &mut status, msg.as_mut_ptr(), 128);
        assert_eq!(state, MocktailRustStartupState::Configured);
        assert_eq!(status, 0);

        // Step 2: JniRuntimeReady
        mocktail_rust_startup_sm_record_evidence(sm, 1, &mut state, &mut status, msg.as_mut_ptr(), 128);
        assert_eq!(state, MocktailRustStartupState::JniRuntimeReady);

        // Step 3: Duplicate evidence
        mocktail_rust_startup_sm_record_evidence(sm, 1, &mut state, &mut status, msg.as_mut_ptr(), 128);
        assert_eq!(status, 1); // Duplicate

        // Step 4: Snapshot
        let mut snap = MocktailRustStartupSnapshot {
            state: MocktailRustStartupState::Created,
            requirements: req,
            configured: 0,
            jni_runtime_ready: 0,
            libraries_loaded: 0,
            jni_on_load_complete: 0,
            engine_started: 0,
            data_model_loading: 0,
            lua_app_ready: 0,
            real_frame_presented: 0,
            input_ready: 0,
            audio_ready: 0,
            revision: 0,
        };
        mocktail_rust_startup_sm_snapshot(sm, &mut snap, msg.as_mut_ptr(), 128);
        assert_eq!(snap.state, MocktailRustStartupState::JniRuntimeReady);
        assert_eq!(snap.configured, 1);
        assert_eq!(snap.jni_runtime_ready, 1);

        mocktail_rust_startup_sm_destroy(sm);
    }

    #[test]
    fn test_fleasion_prepare_bundle() {
        let ca_cert = "-----BEGIN CERTIFICATE-----\nMIIBcaCAQ...\n-----END CERTIFICATE-----\n";
        let base_bundle = "-----BEGIN CERTIFICATE-----\nMIIBase...\n-----END CERTIFICATE-----\n";

        let temp_dir = std::env::temp_dir();
        let ca_file = temp_dir.join("test_ca.pem");
        let base_file = temp_dir.join("test_base.pem");
        let dest_file = temp_dir.join("test_dest.pem");

        std::fs::write(&ca_file, ca_cert).unwrap();
        std::fs::write(&base_file, base_bundle).unwrap();

        let ca_cstr = CString::new(ca_file.to_str().unwrap()).unwrap();
        let base_cstr = CString::new(base_file.to_str().unwrap()).unwrap();
        let dest_cstr = CString::new(dest_file.to_str().unwrap()).unwrap();
        let mut err_buf = [0 as c_char; 256];

        let rc = mocktail_rust_fleasion_prepare_bundle(
            ca_cstr.as_ptr(),
            base_cstr.as_ptr(),
            dest_cstr.as_ptr(),
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);

        let merged = std::fs::read_to_string(&dest_file).unwrap();
        assert!(merged.contains("MIIBase..."));
        assert!(merged.contains("MIIBcaCAQ..."));

        let _ = std::fs::remove_file(ca_file);
        let _ = std::fs::remove_file(base_file);
        let _ = std::fs::remove_file(dest_file);
    }

    #[test]
    fn test_apk_signing_block_finder() {
        let mut file = vec![0u8; 1024];
        let file_len = file.len();
        // Place EOCD at file_len - 22
        let eocd_pos = file_len - 22;
        file[eocd_pos..eocd_pos + 4].copy_from_slice(&0x06054b50u32.to_le_bytes());
        // cd_offset = 512
        file[eocd_pos + 16..eocd_pos + 20].copy_from_slice(&512u32.to_le_bytes());

        // Sig block right before CD (512)
        // Magic at 512 - 16 = 496
        file[496..512].copy_from_slice(b"APK Sig Block 42");
        // footer_size = 56: (32 bytes pair + 8 bytes footer size + 16 bytes magic)
        file[488..496].copy_from_slice(&56u64.to_le_bytes());
        // total_size = 64, block_begin = 512 - 64 = 448
        // Header size at 448..456
        file[448..456].copy_from_slice(&56u64.to_le_bytes());

        // Place a v2 pair at 456: pair_size = 24, id = 0x7109871a
        file[456..464].copy_from_slice(&24u64.to_le_bytes());
        file[464..468].copy_from_slice(&0x7109871au32.to_le_bytes());

        let mut info = MocktailRustApkSigningBlockInfo::default();
        let mut err_buf = [0 as c_char; 256];
        let rc = mocktail_rust_find_apk_signing_block(
            file.as_ptr(),
            file.len(),
            &mut info,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        assert_eq!(info.central_directory, 512);
        assert_eq!(info.v2_offset, 468);
        assert_eq!(info.v2_len, 20);
    }

    #[test]
    fn test_etc2_decoder() {
        let block = [
            0x24u8, 0x35, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut dst = [0u8; 64]; // 4x4 RGBA8
        let rc = mocktail_rust_decode_etc_image_block_rows(
            MocktailRustEtcFormat::Etc2Rgb8,
            block.as_ptr(),
            block.len(),
            4,
            4,
            0,
            1,
            dst.as_mut_ptr(),
            dst.len(),
        );
        assert_eq!(rc, 1);
        // Alpha channel should be 255 for opaque RGB8
        assert_eq!(dst[3], 255);
        assert_eq!(dst[7], 255);
    }

    #[test]
    fn test_zip_archive() {
        let temp_dir = std::env::temp_dir().join(format!("mocktail_zip_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let zip_path = temp_dir.join("test.zip");

        // Create zip archive with zip writer
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            zip.start_file("assets/test.txt", options).unwrap();
            use std::io::Write;
            zip.write_all(b"Hello Zip World!").unwrap();

            zip.add_directory("assets/sub/", options).unwrap();
            zip.start_file("assets/sub/nested.txt", options).unwrap();
            zip.write_all(b"Nested content").unwrap();

            zip.finish().unwrap();
        }

        // 1. List entries
        let zip_cstr = CString::new(zip_path.to_str().unwrap()).unwrap();
        let mut list_json = [0 as c_char; 2048];
        let mut err_buf = [0 as c_char; 256];
        let rc_list = mocktail_rust_zip_list_entries(
            zip_cstr.as_ptr(),
            100,
            list_json.as_mut_ptr(),
            2048,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_list, 0);
        let list_str = unsafe { CStr::from_ptr(list_json.as_ptr()) }.to_str().unwrap();
        assert!(list_str.contains("assets/test.txt"));
        assert!(list_str.contains("assets/sub/nested.txt"));

        // 2. Read entry
        let entry_cstr = CString::new("assets/test.txt").unwrap();
        let mut read_buf = [0u8; 128];
        let mut read_len = 0;
        let rc_read = mocktail_rust_zip_read_entry(
            zip_cstr.as_ptr(),
            entry_cstr.as_ptr(),
            128,
            read_buf.as_mut_ptr(),
            128,
            &mut read_len,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_read, 0);
        assert_eq!(&read_buf[..read_len], b"Hello Zip World!");

        // 3. Extract entry
        let dest_single = temp_dir.join("extracted_single.txt");
        let dest_single_cstr = CString::new(dest_single.to_str().unwrap()).unwrap();
        let rc_extract = mocktail_rust_zip_extract_entry(
            zip_cstr.as_ptr(),
            entry_cstr.as_ptr(),
            dest_single_cstr.as_ptr(),
            1024,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_extract, 0);
        assert_eq!(std::fs::read(&dest_single).unwrap(), b"Hello Zip World!");

        // 4. Extract prefix
        let dest_prefix_dir = temp_dir.join("prefix_out");
        let dest_prefix_cstr = CString::new(dest_prefix_dir.to_str().unwrap()).unwrap();
        let prefix_cstr = CString::new("assets/").unwrap();
        let mut extracted_count = 0;
        let rc_prefix = mocktail_rust_zip_extract_prefix(
            zip_cstr.as_ptr(),
            prefix_cstr.as_ptr(),
            dest_prefix_cstr.as_ptr(),
            10240,
            &mut extracted_count,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_prefix, 0);
        assert!(extracted_count >= 2);
        assert_eq!(std::fs::read(dest_prefix_dir.join("test.txt")).unwrap(), b"Hello Zip World!");
        assert_eq!(std::fs::read(dest_prefix_dir.join("sub/nested.txt")).unwrap(), b"Nested content");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_fflags_merger() {
        let temp_dir = std::env::temp_dir().join(format!("mocktail_fflags_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let fflags_file = temp_dir.join("ClientAppSettings.json");

        let file_json = r#"{"FFlagTarget": true, "DFFlagCount": 120, "SFlagName": "Custom"}"#;
        std::fs::write(&fflags_file, file_json).unwrap();

        let base_json = r#"{"FFlagTarget": "False", "BasePreserved": "1"}"#;
        let file_cstr = CString::new(fflags_file.to_str().unwrap()).unwrap();
        let base_cstr = CString::new(base_json).unwrap();

        let mut out_json = [0 as c_char; 2048];
        let mut out_count = 0;
        let mut out_loaded = 0;
        let mut err_buf = [0 as c_char; 256];

        let rc = mocktail_rust_fflags_load_and_merge(
            file_cstr.as_ptr(),
            base_cstr.as_ptr(),
            out_json.as_mut_ptr(),
            2048,
            &mut out_count,
            &mut out_loaded,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        assert_eq!(out_loaded, 1);
        assert_eq!(out_count, 2); // DFFlagCount and SFlagName added; FFlagTarget kept base value "False"

        let merged_str = unsafe { CStr::from_ptr(out_json.as_ptr()) }.to_str().unwrap();
        assert!(merged_str.contains("\"FFlagTarget\":\"False\""));
        assert!(merged_str.contains("\"BasePreserved\":\"1\""));
        assert!(merged_str.contains("\"DFFlagCount\":\"120\""));
        assert!(merged_str.contains("\"SFlagName\":\"Custom\""));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_browser_tracker() {
        let mut id_buf = [0 as c_char; 32];
        let rc_gen = mocktail_rust_browser_tracker_generate_id(id_buf.as_mut_ptr(), 32);
        assert_eq!(rc_gen, 0);
        let id_str = unsafe { CStr::from_ptr(id_buf.as_ptr()) }.to_str().unwrap();
        assert!(!id_str.is_empty());
        assert!(!id_str.starts_with('0'));
        assert!(id_str.parse::<u64>().is_ok());

        let cookie = CString::new("path=/&browserid=1234567890123&domain=roblox.com").unwrap();
        let mut extract_buf = [0 as c_char; 32];
        let rc_ext = mocktail_rust_browser_tracker_extract_id(cookie.as_ptr(), extract_buf.as_mut_ptr(), 32);
        assert_eq!(rc_ext, 0);
        let ext_str = unsafe { CStr::from_ptr(extract_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(ext_str, "1234567890123");
    }

    #[test]
    fn test_support_bundle() {
        let valid_tok = CString::new("roblox_crash_dump.1").unwrap();
        assert_eq!(mocktail_rust_is_diagnostic_token(valid_tok.as_ptr()), 1);

        let invalid_tok = CString::new("/bin/sh").unwrap();
        assert_eq!(mocktail_rust_is_diagnostic_token(invalid_tok.as_ptr()), 0);

        let raw_log = b"Starting engine...\n[FATAL] Segmentation fault in libroblox\nSecret: .ROBLOSECURITY=_|WARNING\n[compat] Loading libc.so\nhttps://evil.com/leak\n";
        let mut out_sanitized = [0 as c_char; 1024];
        let mut out_len = 0;
        let rc = mocktail_rust_sanitize_log(
            raw_log.as_ptr(),
            raw_log.len(),
            out_sanitized.as_mut_ptr(),
            1024,
            &mut out_len,
        );
        assert_eq!(rc, 0);
        let sanitized = unsafe { CStr::from_ptr(out_sanitized.as_ptr()) }.to_str().unwrap();
        assert!(sanitized.contains("[FATAL] Segmentation fault"));
        assert!(sanitized.contains("[compat] Loading libc.so"));
        assert!(!sanitized.contains(".ROBLOSECURITY"));
        assert!(!sanitized.contains("https://evil.com"));
    }

    #[test]
    fn test_client_settings_and_atomic_write() {
        let mut def_buf = [0 as c_char; 2048];
        let rc = mocktail_rust_client_settings_safe_defaults(def_buf.as_mut_ptr(), def_buf.len());
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(def_buf.as_ptr()) }.to_str().unwrap();
        assert!(s.contains("applicationSettings"));

        let app = CString::new("TestApp").unwrap();
        let mut url_buf = [0 as c_char; 256];
        let rc_url = mocktail_rust_client_settings_default_url(app.as_ptr(), url_buf.as_mut_ptr(), url_buf.len());
        assert_eq!(rc_url, 0);
        let url_s = unsafe { CStr::from_ptr(url_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(url_s, "https://clientsettingscdn.roblox.com/v2/settings/application/TestApp");

        let valid_json = CString::new("{\"key\":\"value\"}").unwrap();
        assert_eq!(mocktail_rust_client_settings_is_valid_json(valid_json.as_ptr()), 1);

        let invalid_json = CString::new("not_json").unwrap();
        assert_eq!(mocktail_rust_client_settings_is_valid_json(invalid_json.as_ptr()), 0);

        let tmp_dir = std::env::temp_dir().join(format!("mocktail_test_{}", std::process::id()));
        let tmp_file = tmp_dir.join("test_write.txt");
        let p_c = CString::new(tmp_file.to_str().unwrap()).unwrap();
        let content = b"hello mocktail rust atomic write";
        let mut err_buf = [0 as c_char; 256];
        let rc_write = mocktail_rust_atomic_write_file(
            p_c.as_ptr(),
            content.as_ptr() as *const c_char,
            content.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        );
        assert_eq!(rc_write, 0);
        assert_eq!(std::fs::read(&tmp_file).unwrap(), content);
        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_window_state_and_video_driver() {
        let mut fs_creation = 0;
        let mut max_constr = 0;
        mocktail_rust_window_plan_presentation(1, 0, &mut fs_creation, &mut max_constr);
        assert_eq!(fs_creation, 1);
        assert_eq!(max_constr, 0);

        mocktail_rust_window_plan_presentation(0, 1, &mut fs_creation, &mut max_constr);
        assert_eq!(fs_creation, 0);
        assert_eq!(max_constr, 1);

        // Video driver resolve
        let choice = mocktail_rust_video_driver_resolve(0, 1, 0, 0, 0, 0, 0, 0);
        assert_eq!(choice, 1); // Wayland

        let choice_nv = mocktail_rust_video_driver_resolve(0, 0, 0, 1, 1, 1, 1, 0);
        assert_eq!(choice_nv, 3); // NvidiaDirectVulkanX11

        let req = CString::new("wayland,x11").unwrap();
        let cand = CString::new("x11,kmsdrm").unwrap();
        assert_eq!(mocktail_rust_video_driver_has_candidate(req.as_ptr(), cand.as_ptr()), 1);

        // Window state storage & load
        let tmp_dir = std::env::temp_dir().join(format!("mocktail_ws_test_{}", std::process::id()));
        let ws_file = tmp_dir.join("window_state.json");
        let p_c = CString::new(ws_file.to_str().unwrap()).unwrap();
        let state = MocktailRustWindowState {
            x: 100,
            y: 200,
            width: 1280,
            height: 720,
            has_position: 1,
            fullscreen: 0,
            maximized: 1,
            configured_width: 1920,
            configured_height: 1080,
            has_configured_size: 1,
        };
        let mut err_buf = [0 as c_char; 256];
        let rc_store = mocktail_rust_window_state_store(p_c.as_ptr(), &state, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc_store, 0);

        let mut loaded = MocktailRustWindowState::default();
        let mut found = 0;
        let rc_load = mocktail_rust_window_state_load(p_c.as_ptr(), &mut loaded, &mut found, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc_load, 0);
        assert_eq!(found, 1);
        assert_eq!(loaded.width, 1280);
        assert_eq!(loaded.height, 720);
        assert_eq!(loaded.x, 100);
        assert_eq!(loaded.y, 200);
        assert_eq!(loaded.maximized, 1);
        assert_eq!(loaded.configured_width, 1920);

        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_runtime_paths_rust() {
        let valid_bid = CString::new("1686400865ae0e408cd7bd67de7a439625c6fd13").unwrap();
        assert_eq!(mocktail_rust_runtime_paths_is_lower_hex_build_id(valid_bid.as_ptr()), 1);

        let invalid_bid = CString::new("1686400865ae0e408cd7bd67de7a439625c6fd1G").unwrap();
        assert_eq!(mocktail_rust_runtime_paths_is_lower_hex_build_id(invalid_bid.as_ptr()), 0);

        let short_bid = CString::new("16864008").unwrap();
        assert_eq!(mocktail_rust_runtime_paths_is_lower_hex_build_id(short_bid.as_ptr()), 0);
    }

    #[test]
    fn test_audio_pcm_and_gain() {
        assert_eq!(mocktail_rust_audio_bytes_per_sample(MocktailRustPcmFormat::Unsigned8), 1);
        assert_eq!(mocktail_rust_audio_bytes_per_sample(MocktailRustPcmFormat::Signed16LittleEndian), 2);
        assert_eq!(mocktail_rust_audio_bytes_per_sample(MocktailRustPcmFormat::Float32LittleEndian), 4);

        let mut bpf = 0;
        let mut err_buf = [0 as c_char; 128];
        let rc = mocktail_rust_audio_validate_pcm(48000, 2, MocktailRustPcmFormat::Signed16LittleEndian, &mut bpf, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc, 0);
        assert_eq!(bpf, 4);

        let rc_bad = mocktail_rust_audio_validate_pcm(1000, 2, MocktailRustPcmFormat::Signed16LittleEndian, &mut bpf, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc_bad, -1);

        let mut samples = [0.5f32, -0.5f32, 1.0f32];
        mocktail_rust_audio_apply_gain_f32(samples.as_mut_ptr(), samples.len(), 2.0);
        assert_eq!(samples[0], 1.0);
        assert_eq!(samples[1], -1.0);
        assert_eq!(samples[2], 1.0);

        let f32_samples = [0.0f32, 1.0f32, -1.0f32];
        let mut i16_samples = [0i16; 3];
        mocktail_rust_audio_convert_f32_to_i16(f32_samples.as_ptr(), i16_samples.as_mut_ptr(), 3);
        assert_eq!(i16_samples[0], 0);
        assert_eq!(i16_samples[1], 32767);
        assert_eq!(i16_samples[2], -32767);
    }

    #[test]
    fn test_present_mode_and_swapchain() {
        let _guard = test_env_lock();
        std::env::remove_var("MOCKTAIL_SWAPCHAIN_IMAGES");
        let vsync_auto = CString::new("auto").unwrap();
        let fps_neg1 = CString::new("-1").unwrap();
        let fps_display = CString::new("display").unwrap();
        let fps_unlimited = CString::new("unlimited").unwrap();
        let pm_fifo = CString::new("fifo").unwrap();
        let pm_mailbox = CString::new("mailbox").unwrap();
        let pm_immediate = CString::new("immediate").unwrap();
        let pm_auto = CString::new("auto").unwrap();

        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_neg1.as_ptr(), pm_auto.as_ptr()), 0); // HostDefault
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_auto.as_ptr()), 1); // Vsync
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_unlimited.as_ptr(), pm_auto.as_ptr()), 2); // Unthrottled
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_fifo.as_ptr()), 3); // Fifo
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_mailbox.as_ptr()), 4); // Mailbox
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_immediate.as_ptr()), 5); // Immediate

        // Wayland HostDefault promotes to Mailbox (ede9080)
        assert_eq!(mocktail_rust_present_mode_resolve_vulkan_surface(0, 1), 4);
        assert_eq!(mocktail_rust_present_mode_resolve_vulkan_surface(0, 0), 0);
        assert_eq!(mocktail_rust_present_mode_resolve_vulkan_surface(3, 1), 3);

        let mut explicit = 0u32;
        assert_eq!(mocktail_rust_present_mode_explicit(3, &mut explicit), 1);
        assert_eq!(explicit, VK_PRESENT_MODE_FIFO_KHR);
        assert_eq!(mocktail_rust_present_mode_explicit(0, &mut explicit), 0);

        assert_eq!(mocktail_rust_present_mode_swap_interval(0, 2), 2);
        assert_eq!(mocktail_rust_present_mode_swap_interval(2, 1), 0);
        assert_eq!(mocktail_rust_present_mode_swap_interval(1, 0), 1);
        assert_eq!(mocktail_rust_present_mode_swap_interval(5, 1), 0);

        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(4 /* Mailbox */, 2, 2, 8), 3);
        // Mailbox preserves min_images + 1 headroom when min_images >= 3 (94715e3)
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(4 /* Mailbox */, 3, 3, 8), 4);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(3 /* Fifo */, 2, 2, 8), 2);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(1 /* Vsync */, 2, 2, 8), 4);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(2 /* Unthrottled */, 2, 2, 8), 5);

        let host_modes = [VK_PRESENT_MODE_IMMEDIATE_KHR, VK_PRESENT_MODE_FIFO_KHR];
        let mut out_modes = [0u32; 8];
        let mut out_count = 0usize;
        let rc = mocktail_rust_present_mode_filter(1 /* Vsync */, host_modes.as_ptr(), host_modes.len(), out_modes.as_mut_ptr(), out_modes.len(), &mut out_count);
        assert_eq!(rc, 0);
        assert_eq!(out_count, 1);
        assert_eq!(out_modes[0], VK_PRESENT_MODE_FIFO_KHR);

        let khr = unsafe { CStr::from_ptr(mocktail_rust_present_mode_khr_name_ptr(VK_PRESENT_MODE_MAILBOX_KHR)) }.to_str().unwrap();
        let pol = unsafe { CStr::from_ptr(mocktail_rust_present_mode_policy_name_ptr(4)) }.to_str().unwrap();
        assert_eq!(khr, "mailbox");
        assert_eq!(pol, "mailbox");
    }

    #[test]
    fn test_frame_rate_policy() {
        let mut mode = 0;
        let mut fps = 0;

        let empty = CString::new("").unwrap();
        mocktail_rust_frame_rate_parse(empty.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 0); // Unmanaged

        let display = CString::new("display").unwrap();
        mocktail_rust_frame_rate_parse(display.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 1); // Display

        let fps144 = CString::new("144").unwrap();
        mocktail_rust_frame_rate_parse(fps144.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 2); // Fixed
        assert_eq!(fps, 144);

        let unlimited = CString::new("unlimited").unwrap();
        mocktail_rust_frame_rate_parse(unlimited.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 3); // Unlimited

        let invalid = CString::new("bad_fps").unwrap();
        mocktail_rust_frame_rate_parse(invalid.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 4); // Invalid

        // Merge settings
        let base_json = CString::new("{}").unwrap();
        let mut out_buf = [0 as c_char; 1024];
        let mut out_err = [0 as c_char; 256];
        let rc = mocktail_rust_frame_rate_merge_client_settings(
            2, 144, base_json.as_ptr(), out_buf.as_mut_ptr(), out_buf.len(), out_err.as_mut_ptr(), out_err.len()
        );
        assert_eq!(rc, 0);
        let out_str = unsafe { CStr::from_ptr(out_buf.as_ptr()).to_str().unwrap() };
        assert!(out_str.contains("\"DFIntTaskSchedulerTargetFps\":\"144\""));
        assert!(out_str.contains("\"FFlagGameBasicSettingsFramerateCap5\":\"True\""));
    }

    #[test]
    fn test_gamepad_and_input() {
        assert_eq!(mocktail_rust_gamepad_valid_id(1), 1);
        assert_eq!(mocktail_rust_gamepad_valid_id(0), 0);
        assert_eq!(mocktail_rust_gamepad_valid_id(-1), 0);

        assert_eq!(mocktail_rust_gamepad_family(1), 1); // Xbox
        assert_eq!(mocktail_rust_gamepad_family(4), 2); // PS4
        assert_eq!(mocktail_rust_gamepad_family(5), 3); // PS5

        assert_eq!(mocktail_rust_gamepad_button_to_android(0), 96);
        assert_eq!(mocktail_rust_gamepad_button_to_android(1), 97);
        assert_eq!(mocktail_rust_gamepad_button_to_android(255), -1);

        assert_eq!(mocktail_rust_roblox_gamepad_type(1), 3); // Xbox
        assert_eq!(mocktail_rust_roblox_gamepad_type(2), 1); // PS4
        assert_eq!(mocktail_rust_roblox_gamepad_type(3), 2); // PS5

        assert_eq!(mocktail_rust_gamepad_signed_axis(0), 0.0);
        assert_eq!(mocktail_rust_gamepad_signed_axis(32767), 1.0);
        assert_eq!(mocktail_rust_gamepad_signed_axis(-32768), -1.0);

        let mut ox = 0.0f32;
        let mut oy = 0.0f32;
        mocktail_rust_gamepad_stick(0, 0, &mut ox, &mut oy);
        assert_eq!(ox, 0.0);
        assert_eq!(oy, 0.0);

        assert_eq!(mocktail_rust_gamepad_trigger(0), 0.0);
        assert_eq!(mocktail_rust_gamepad_trigger(32767), 1.0);

        assert_eq!(mocktail_rust_sdl_finger_action(0x700), 0);
        assert_eq!(mocktail_rust_sdl_finger_action(0x701), 1);
        assert_eq!(mocktail_rust_sdl_finger_action(0x702), 2);
        assert_eq!(mocktail_rust_sdl_finger_action(0x703), 3);
        assert_eq!(mocktail_rust_sdl_finger_action(0x999), -1);
    }

    #[test]
    fn test_device_memory_and_class() {
        let mut profile = MocktailRustDeviceMemoryProfile {
            total_memory_mb: 0,
            memory_class_mb: 0,
            large_memory_class_mb: 0,
            low_memory_killer_background_threshold: 0,
            low_memory_killer_foreground_threshold: 0,
            low_ram_device: 0,
        };
        mocktail_rust_build_device_memory_profile(2 * 1024 * 1024 * 1024, &mut profile);
        assert_eq!(profile.low_ram_device, 1);
        assert_eq!(profile.total_memory_mb, 2048);

        mocktail_rust_build_device_memory_profile(8 * 1024 * 1024 * 1024, &mut profile);
        assert_eq!(profile.low_ram_device, 0);
        assert_eq!(profile.total_memory_mb, 8192);

        let mut class_buf = [0 as c_char; 32];
        mocktail_rust_device_class_name(0, class_buf.as_mut_ptr(), class_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(class_buf.as_ptr()).to_str().unwrap() }, "pc");
    }

    #[test]
    fn test_payload_integrity_and_session_log_helpers() {
        let text = CString::new("hello world").unwrap();
        let mut hex_buf = [0 as c_char; 65];
        let mut err_buf = [0 as c_char; 128];
        let rc = mocktail_rust_hash_text(text.as_ptr(), 11, 0, hex_buf.as_mut_ptr(), hex_buf.len(), err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc, 0);
        let hex_str = unsafe { CStr::from_ptr(hex_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(hex_str, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

        let hex_valid = CString::new("0123456789abcdef").unwrap();
        assert_eq!(mocktail_rust_is_lower_hex(hex_valid.as_ptr(), 16), 1);
        let hex_invalid = CString::new("0123456789ABCDEF").unwrap();
        assert_eq!(mocktail_rust_is_lower_hex(hex_invalid.as_ptr(), 16), 0);

        let mut vendor_buf = [0 as c_char; 64];
        let vid_nvidia = CString::new("10de").unwrap();
        mocktail_rust_pci_vendor_fallback(vid_nvidia.as_ptr(), vendor_buf.as_mut_ptr(), vendor_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(vendor_buf.as_ptr()).to_str().unwrap() }, "NVIDIA");

        let mut hex_id_buf = [0 as c_char; 16];
        let hid = CString::new("0x10DE").unwrap();
        mocktail_rust_hex_id(hid.as_ptr(), hex_id_buf.as_mut_ptr(), hex_id_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(hex_id_buf.as_ptr()).to_str().unwrap() }, "10de");

        let meminfo = CString::new("MemTotal:        8163532 kB\nMemFree:         123456 kB\n").unwrap();
        let mut total_buf = [0 as c_char; 32];
        mocktail_rust_parse_meminfo_total(meminfo.as_ptr(), total_buf.as_mut_ptr(), total_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(total_buf.as_ptr()).to_str().unwrap() }, "7972MiB");

        let cpuinfo = CString::new("processor: 0\nmodel name: Intel Core i7-4500U CPU @ 1.80GHz\n").unwrap();
        let mut model_buf = [0 as c_char; 128];
        mocktail_rust_parse_cpuinfo_model(cpuinfo.as_ptr(), model_buf.as_mut_ptr(), model_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(model_buf.as_ptr()).to_str().unwrap() }, "Intel Core i7-4500U CPU @ 1.80GHz");
    }

    #[test]
    fn test_window_readiness_gates() {
        let mut flags: u32 = 0;
        let mut pending: i32 = 0;
        let r = mocktail_rust_window_fullscreen_request_from_android_flags(0x400, 0x400, &mut flags, &mut pending);
        assert_eq!(r, 1);
        assert_eq!(pending, 2);
        let mut fs: c_int = 0;
        assert_eq!(mocktail_rust_window_fullscreen_take(&mut pending, &mut fs), 1);
        assert_eq!(fs, 1);
        assert_eq!(pending, 0);

        let msg = CString::new("Maximum event re-entrancy depth exceeded for BindableEvent.Event in CoreGui.RobloxGui.Modules.Settings.Pages.GameSettings").unwrap();
        assert_eq!(mocktail_rust_roblox_fullscreen_menu_is_cycle(msg.as_ptr()), 1);

        let mut state: u32 = 0;
        let mut surf_gen: u64 = 0;
        let mut tw: u32 = 0;
        let mut th: u32 = 0;
        let mut err = [0 as c_char; 128];
        let rc = mocktail_rust_window_resize_activate(1, 1920, 1080, 1, 10, 100, 800, 600, &mut state, &mut surf_gen, &mut tw, &mut th, err.as_mut_ptr(), err.len());
        assert_eq!(rc, 0);
        assert_eq!(state, 1);
        assert_eq!(surf_gen, 10);
        assert_eq!(tw, 1920);
        assert_eq!(th, 1080);
    }

    #[test]
    fn test_text_editor_layout_and_graphemes() {
        let family = "👨‍👩‍👧‍👦é";
        let family_c = CString::new(family).unwrap();
        let mut units: i32 = 0;
        let mut bounds = [0usize; 8];
        let mut count: usize = 0;
        let valid = mocktail_rust_text_layout(family_c.as_ptr(), family.len(), &mut units, bounds.as_mut_ptr(), bounds.len(), &mut count);
        assert_eq!(valid, 1);
        assert_eq!(count, 3);
        assert_eq!(&bounds[..count], &[0, 25, 28]);
        assert_eq!(units, 13); // 7 units for family (surrogates: 👨=2, ‍=1, 👩=2, ‍=1, 👧=2, ‍=1, 👦=2 -> 11) wait chars utf16 length

        assert_eq!(mocktail_rust_text_shortcut_bit(4), 1);
        assert_eq!(mocktail_rust_text_shortcut_bit(6), 2);
        assert_eq!(mocktail_rust_text_shortcut_bit(25), 4);
        assert_eq!(mocktail_rust_text_shortcut_bit(27), 8);
        assert_eq!(mocktail_rust_text_is_password_input(5), 1);
        assert_eq!(mocktail_rust_text_is_password_input(1), 0);

        assert_eq!(mocktail_rust_text_prev_grapheme(family_c.as_ptr(), family.len(), 28), 25);
        assert_eq!(mocktail_rust_text_prev_grapheme(family_c.as_ptr(), family.len(), 25), 0);
        assert_eq!(mocktail_rust_text_next_grapheme(family_c.as_ptr(), family.len(), 0), 25);
        assert_eq!(mocktail_rust_text_next_grapheme(family_c.as_ptr(), family.len(), 25), 28);
    }

    #[test]
    fn test_external_launch_wire_protocol() {
        let json = "{\"placeId\":123}";
        let json_c = CString::new(json).unwrap();
        let mut pkt = [0 as c_char; 256];
        let len = mocktail_rust_external_launch_build_packet(json_c.as_ptr(), json.len(), pkt.as_mut_ptr(), pkt.len());
        assert!(len > 0);

        let mut off: usize = 0;
        let mut jlen: usize = 0;
        let ok = mocktail_rust_external_launch_verify_and_strip_prefix(pkt.as_ptr(), len as usize, &mut off, &mut jlen);
        assert_eq!(ok, 0);
        assert_eq!(off, 27);
        assert_eq!(jlen, json.len());

        let mut reply = [0u8; 8];
        assert_eq!(mocktail_rust_external_launch_build_reply(0, reply.as_mut_ptr(), reply.len()), 5);
        let mut code: u8 = 99;
        assert_eq!(mocktail_rust_external_launch_parse_reply(reply.as_ptr(), 5, &mut code), 0);
        assert_eq!(code, 0);
        assert_eq!(mocktail_rust_external_launch_reply_status_code(code), 0);
    }

    #[test]
    fn test_apk_bundle_and_payload_store() {
        let abi = CString::new("arm64-v8a").unwrap();
        let mut entry = [0 as c_char; 64];
        mocktail_rust_apk_guest_lib_entry_name(abi.as_ptr(), entry.as_mut_ptr(), entry.len());
        assert_eq!(unsafe { CStr::from_ptr(entry.as_ptr()).to_str().unwrap() }, "lib/arm64-v8a/libroblox.so");

        let pid_valid = CString::new("650-0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(mocktail_rust_payload_store_valid_id(pid_valid.as_ptr(), 44), 1);
        let pid_invalid = CString::new("650_invalid").unwrap();
        assert_eq!(mocktail_rust_payload_store_valid_id(pid_invalid.as_ptr(), 11), 0);
    }

    #[test]
    fn test_audio_queue_and_output_device_bridge() {
        assert_eq!(mocktail_rust_opensl_result_from_status_code(0), 0);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(1), 2);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(2), 3);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(3), 4);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(4), 12);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(5), 6);

        let dev_name = CString::new("Built-in Audio").unwrap();
        let mut guid_buf = [0 as c_char; 64];
        assert_eq!(mocktail_rust_audio_device_stable_guid(dev_name.as_ptr(), guid_buf.as_mut_ptr(), guid_buf.len()), 0);
        let guid = unsafe { CStr::from_ptr(guid_buf.as_ptr()).to_str().unwrap() };
        assert!(guid.starts_with("{") && guid.ends_with("}") && guid.len() == 38);
    }

    #[test]
    fn test_discord_rpc_helpers() {
        unsafe {
            assert!(mocktail_rust_discord_has_join_target(12345, std::ptr::null(), 0));
            assert!(!mocktail_rust_discord_has_join_target(0, std::ptr::null(), 0));
            assert!(!mocktail_rust_discord_has_join_target(-5, std::ptr::null(), 0));

            let valid_instance = CString::new("job-123-abc").unwrap();
            assert!(mocktail_rust_discord_has_join_target(12345, valid_instance.as_ptr(), 11));
            let invalid_ctrl = b"job\x01test";
            assert!(!mocktail_rust_discord_has_join_target(12345, invalid_ctrl.as_ptr() as *const c_char, 8));

            let sample = "Hello World UTF8 öçşğü";
            let c_sample = CString::new(sample).unwrap();
            let trunc = mocktail_rust_discord_truncate_utf8(c_sample.as_ptr(), sample.len(), 10);
            assert!(trunc <= 10);

            let tmpl = "Playing: {place_name}!";
            let c_tmpl = CString::new(tmpl).unwrap();
            let place = "Bloxburg";
            let c_place = CString::new(place).unwrap();
            let mut out = [0u8; 128];
            let mut out_len = 0usize;
            assert_eq!(mocktail_rust_discord_render_place_template(
                c_tmpl.as_ptr(), tmpl.len(),
                c_place.as_ptr(), place.len(),
                out.as_mut_ptr(), out.len(), &mut out_len
            ), 0);
            let rendered = std::str::from_utf8(&out[..out_len]).unwrap();
            assert_eq!(rendered, "Playing: Bloxburg!");

            let mut url_buf = [0u8; 512];
            let mut url_len = 0usize;
            assert_eq!(mocktail_rust_discord_build_join_url(
                9876, valid_instance.as_ptr(), 11,
                url_buf.as_mut_ptr(), url_buf.len(), &mut url_len
            ), 0);
            let join_url = std::str::from_utf8(&url_buf[..url_len]).unwrap();
            assert_eq!(join_url, "https://komaruworld.github.io/mocktail/join.html#placeId=9876&gameInstanceId=job-123-abc");
        }
    }

    #[test]
    fn test_browser_and_webview_helpers() {
        unsafe {
            let ctrl = b"abc\x07def";
            assert!(mocktail_rust_browser_has_control_byte(ctrl.as_ptr(), ctrl.len()));
            let normal = b"abc def 123";
            assert!(!mocktail_rust_browser_has_control_byte(normal.as_ptr(), normal.len()));

            let embedded_nul = b"abc\0def";
            assert!(mocktail_rust_browser_has_embedded_nul(embedded_nul.as_ptr(), embedded_nul.len()));
            assert!(!mocktail_rust_browser_has_embedded_nul(normal.as_ptr(), normal.len()));

            let challenge1 = CString::new("https://www.roblox.com/login/challenge").unwrap();
            assert!(mocktail_rust_webview_is_login_challenge_url(challenge1.as_ptr(), challenge1.as_bytes().len()));
            let challenge2 = CString::new("https://apis.roblox.com/view-generic-challenge?test=1").unwrap();
            assert!(mocktail_rust_webview_is_login_challenge_url(challenge2.as_ptr(), challenge2.as_bytes().len()));
            let non_challenge = CString::new("https://www.roblox.com/games/12345").unwrap();
            assert!(!mocktail_rust_webview_is_login_challenge_url(non_challenge.as_ptr(), non_challenge.as_bytes().len()));
        }
    }

    #[test]
    fn test_game_session_coordinator_helpers() {
        unsafe {
            let name_run = CStr::from_ptr(mocktail_rust_game_session_state_name(7)).to_str().unwrap();
            assert_eq!(name_run, "Running");
            let name_pause = CStr::from_ptr(mocktail_rust_game_session_state_name(10)).to_str().unwrap();
            assert_eq!(name_pause, "Paused");

            let backend_vk = CStr::from_ptr(mocktail_rust_game_present_backend_name(1)).to_str().unwrap();
            assert_eq!(backend_vk, "Vulkan");

            let kind_guest = CStr::from_ptr(mocktail_rust_game_session_principal_kind_name(0)).to_str().unwrap();
            assert_eq!(kind_guest, "LocalGuest");
            let kind_auth = CStr::from_ptr(mocktail_rust_game_session_principal_kind_name(1)).to_str().unwrap();
            assert_eq!(kind_auth, "Authenticated");

            assert!(mocktail_rust_game_session_valid_principal(1, 10, 0, 0));
            assert!(!mocktail_rust_game_session_valid_principal(1, 10, 0, 5));
            assert!(mocktail_rust_game_session_valid_principal(1, 10, 1, 5));
            assert!(!mocktail_rust_game_session_valid_principal(0, 10, 1, 5));

            assert!(mocktail_rust_game_session_valid_request(100, 12345, 10));
            assert!(!mocktail_rust_game_session_valid_request(0, 12345, 10));

            assert!(mocktail_rust_game_session_valid_surface(1, 0x1234, 1920, 1080));
            assert!(!mocktail_rust_game_session_valid_surface(0, 0x1234, 1920, 1080));
        }
    }

    #[test]
    fn test_audio_and_webrtc_helpers() {
        unsafe {
            assert!(mocktail_rust_fmod_is_valid_channel_count(1));
            assert!(mocktail_rust_fmod_is_valid_channel_count(2));
            assert!(mocktail_rust_fmod_is_valid_channel_count(6));
            assert!(mocktail_rust_fmod_is_valid_channel_count(8));
            assert!(!mocktail_rust_fmod_is_valid_channel_count(3));
            assert!(!mocktail_rust_fmod_is_valid_channel_count(0));

            // 48000 Hz, 10 ms, 1 channel -> 480 samples * 2 bytes = 960 bytes
            assert_eq!(mocktail_rust_webrtc_calc_frame_bytes(48000, 10, 1), 960);

            let pcm = [0x00u8, 0x00, 0x00, 0x40]; // 0, 16384
            assert_eq!(mocktail_rust_audio_calc_pcm_s16le_peak(pcm.as_ptr(), pcm.len()), 16384);

            assert!(mocktail_rust_audio_spec_equals(48000, 2, 1, 48000, 2, 1));
            assert!(!mocktail_rust_audio_spec_equals(48000, 2, 1, 44100, 2, 1));
        }
    }

    #[test]
    fn test_update_and_download_helpers() {
        unsafe {
            let host1 = CString::new("download.pureapk.com").unwrap();
            let host2 = CString::new("pureapk.com.attacker.test").unwrap();
            let allowed = CString::new("pureapk.com").unwrap();

            assert!(mocktail_rust_update_host_matches(host1.as_ptr(), 20, allowed.as_ptr(), 11));
            assert!(!mocktail_rust_update_host_matches(host2.as_ptr(), 25, allowed.as_ptr(), 11));

            assert!(mocktail_rust_update_is_redirect_status(301));
            assert!(mocktail_rust_update_is_redirect_status(302));
            assert!(!mocktail_rust_update_is_redirect_status(200));

            assert!(mocktail_rust_update_is_retryable_status(429));
            assert!(mocktail_rust_update_is_retryable_status(503));
            assert!(!mocktail_rust_update_is_retryable_status(404));

            assert!(mocktail_rust_update_is_retryable_curl_code(7)); // CURLE_COULDNT_CONNECT
            assert!(!mocktail_rust_update_is_retryable_curl_code(0));

            let mut take_latest = false;
            let mut take_preferred = false;
            assert_eq!(mocktail_rust_update_plan_evaluate(
                true, 200, true, 100, 150, &mut take_latest, &mut take_preferred
            ), 0);
            assert!(take_latest);
            assert!(take_preferred);
        }
    }

    #[test]
    fn test_memory_and_statm_helpers() {
        unsafe {
            assert_eq!(mocktail_rust_statm_pages_to_bytes(100, 4096), 409600);
            let statm = CString::new("1000 250 50 10 0 200 0\n").unwrap();
            let mut resident = 0u64;
            assert_eq!(mocktail_rust_parse_proc_statm(statm.as_ptr(), statm.as_bytes().len(), &mut resident), 0);
            assert_eq!(resident, 250);

            assert!(mocktail_rust_memory_limit_exceeded(500, 100, 550));
            assert!(!mocktail_rust_memory_limit_exceeded(500, 100, 700));

            let mut buf = [0u8; 256];
            let mut len = 0usize;
            assert_eq!(mocktail_rust_format_memory_limit_message(1024 * 1024 * 512, 1024 * 1024 * 1024, buf.as_mut_ptr(), buf.len(), &mut len), 0);
            let msg = std::str::from_utf8(&buf[..len]).unwrap();
            assert!(msg.contains("RSS+swap=512 MiB"));
            assert!(msg.contains("limit=1024 MiB"));
        }
    }

    #[test]
    fn test_preflight_and_diagnostic_helpers() {
        unsafe {
            let data = "hello world \u{1F600}".as_bytes();
            let trim = mocktail_rust_trim_to_utf8_boundary(data.as_ptr(), data.len(), data.len() - 2);
            assert_eq!(trim, 12); // Cuts at the emoji boundary

            let line = CString::new("[native-updater] signature verification failed\n").unwrap();
            let mut out = [0u8; 128];
            let mut out_len = 0usize;
            let mut is_failure = false;
            assert_eq!(mocktail_rust_parse_updater_stderr_line(line.as_ptr(), line.as_bytes().len(), out.as_mut_ptr(), out.len(), &mut out_len, &mut is_failure), 0);
            assert!(is_failure);
            let parsed_detail = std::str::from_utf8(&out[..out_len]).unwrap();
            assert_eq!(parsed_detail, "signature verification failed\n");

            let env_str = CString::new("MOCKTAIL_DEBUG=1").unwrap();
            let name_str = CString::new("MOCKTAIL_DEBUG").unwrap();
            assert!(mocktail_rust_is_env_entry(env_str.as_ptr(), env_str.as_bytes().len(), name_str.as_ptr(), name_str.as_bytes().len()));

            let mut fail_buf = [0u8; 256];
            let mut fail_len = 0usize;
            assert_eq!(mocktail_rust_format_preflight_failure(137, false, std::ptr::null(), 0, fail_buf.as_mut_ptr(), fail_buf.len(), &mut fail_len), 0);
            let formatted = std::str::from_utf8(&fail_buf[..fail_len]).unwrap();
            assert_eq!(formatted, "Updater process exited with status 137");
        }
    }

    #[test]
    fn test_desktop_app_policy_helpers() {
        unsafe {
            let base_policy = CString::new(r#"{"PlatformGroup":"Mobile"}"#).unwrap();
            let theme = CString::new("dark").unwrap();
            let mut out = [0u8; 512];
            let mut out_len = 0usize;
            assert_eq!(mocktail_rust_normalize_desktop_layout(
                base_policy.as_ptr(), base_policy.as_bytes().len(),
                theme.as_ptr(), theme.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut out_len
            ), 0);
            let norm = std::str::from_utf8(&out[..out_len]).unwrap();
            assert!(norm.contains(r#""PlatformGroup":"Desktop""#));
            assert!(norm.contains(r#""ForceTheme":"dark""#));

            let base_settings = CString::new(r#"{"FFlagExisting":"True"}"#).unwrap();
            let mut merged = [0u8; 512];
            let mut merged_len = 0usize;
            assert_eq!(mocktail_rust_merge_desktop_app_policy_settings(
                norm.as_ptr() as *const c_char, norm.len(),
                base_settings.as_ptr(), base_settings.as_bytes().len(),
                merged.as_mut_ptr(), merged.len(), &mut merged_len
            ), 0);
            let merged_str = std::str::from_utf8(&merged[..merged_len]).unwrap();
            assert!(merged_str.contains("FStringAppConfigurationOverrideAppPolicy"));
            assert!(merged_str.contains(r#""FFlagLuaAppChartsAppPage":"False""#));
        }
    }

    #[test]
    fn test_browser_tracker_and_cookie_helpers() {
        unsafe {
            let valid_id = CString::new("123456789012345678").unwrap();
            let zero_id = CString::new("012345").unwrap();
            assert!(mocktail_rust_browser_tracker_is_valid_id(valid_id.as_ptr(), valid_id.as_bytes().len()));
            assert!(!mocktail_rust_browser_tracker_is_valid_id(zero_id.as_ptr(), zero_id.as_bytes().len()));

            let cookie_header = CString::new("a=1; RBXEventTrackerV2=browser_id:987654321; c=3").unwrap();
            let name = CString::new("RBXEventTrackerV2").unwrap();
            let mut cookie_val = [0u8; 64];
            let mut cookie_len = 0usize;
            assert_eq!(mocktail_rust_browser_tracker_extract_cookie(
                cookie_header.as_ptr(), cookie_header.as_bytes().len(),
                name.as_ptr(), name.as_bytes().len(),
                cookie_val.as_mut_ptr(), cookie_val.len(), &mut cookie_len
            ), 0);
            let extracted = std::str::from_utf8(&cookie_val[..cookie_len]).unwrap();
            assert_eq!(extracted, "browser_id:987654321");
            assert!(mocktail_rust_browser_tracker_has_cookie(
                cookie_header.as_ptr(), cookie_header.as_bytes().len(),
                name.as_ptr(), name.as_bytes().len()
            ));

            let headers = CString::new("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: RBXEventTrackerV2=from_header_token; Path=/\r\n\r\n").unwrap();
            let mut hdr_cookie = [0u8; 64];
            let mut hdr_len = 0usize;
            assert_eq!(mocktail_rust_browser_tracker_from_headers(
                headers.as_ptr(), headers.as_bytes().len(),
                hdr_cookie.as_mut_ptr(), hdr_cookie.len(), &mut hdr_len
            ), 0);
            let hdr_extracted = std::str::from_utf8(&hdr_cookie[..hdr_len]).unwrap();
            assert_eq!(hdr_extracted, "from_header_token");
        }
    }

    #[test]
    fn test_auth_service_helpers() {
        unsafe {
            let cookie_header = CString::new("Other=1; .ROBLOSECURITY = _|valid-token ; Tail=2").unwrap();
            let mut present = false;
            let mut buf = [0 as c_char; 64];
            let mut len = 0usize;
            assert_eq!(mocktail_rust_auth_extract_cookie(
                cookie_header.as_ptr(), cookie_header.as_bytes().len(),
                &mut present, buf.as_mut_ptr(), buf.len(), &mut len
            ), 0);
            assert!(present);
            let extracted = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(extracted, "_|valid-token");

            let raw_cookie = CString::new("_|raw-token; other=3").unwrap();
            assert_eq!(mocktail_rust_auth_extract_cookie(
                raw_cookie.as_ptr(), raw_cookie.as_bytes().len(),
                &mut present, buf.as_mut_ptr(), buf.len(), &mut len
            ), 0);
            assert!(present);
            let raw_extracted = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(raw_extracted, "_|raw-token");

            assert!(mocktail_rust_auth_is_safe_cookie_value(b"_|valid-token\0".as_ptr() as *const c_char, 13));
            assert!(!mocktail_rust_auth_is_safe_cookie_value(b"_|with space\0".as_ptr() as *const c_char, 12));
            assert!(!mocktail_rust_auth_is_safe_cookie_value(b"_|with;semi\0".as_ptr() as *const c_char, 11));

            let to_redact = CString::new("Other=1\n.ROBLOSECURITY=_|bad-token\nTail=2").unwrap();
            let bad_val = CString::new("_|bad-token").unwrap();
            let mut red_buf = [0 as c_char; 128];
            let mut red_len = 0usize;
            assert_eq!(mocktail_rust_auth_redact_rejected(
                to_redact.as_ptr(), to_redact.as_bytes().len(),
                bad_val.as_ptr(), bad_val.as_bytes().len(),
                red_buf.as_mut_ptr(), red_buf.len(), &mut red_len
            ), 0);
            let redacted_str = CStr::from_ptr(red_buf.as_ptr()).to_str().unwrap();
            assert!(redacted_str.starts_with("Other=1\n   "));
            assert!(redacted_str.ends_with("\nTail=2"));

            let identity_json = CString::new(r#"{"id":123456789,"name":"TestUser","displayName":"Display Name"}"#).unwrap();
            let mut user_id = 0i64;
            let mut name_buf = [0 as c_char; 32];
            let mut disp_buf = [0 as c_char; 32];
            assert_eq!(mocktail_rust_auth_parse_identity(
                identity_json.as_ptr(), identity_json.as_bytes().len(),
                &mut user_id, name_buf.as_mut_ptr(), name_buf.len(),
                disp_buf.as_mut_ptr(), disp_buf.len()
            ), 0);
            assert_eq!(user_id, 123456789);
            assert_eq!(CStr::from_ptr(name_buf.as_ptr()).to_str().unwrap(), "TestUser");
            assert_eq!(CStr::from_ptr(disp_buf.as_ptr()).to_str().unwrap(), "Display Name");
        }
    }

    #[test]
    fn test_auth_redaction_ranges() {
        unsafe {
            let orig = CString::new("a=1\nb=2\nc=3").unwrap();
            let red = CString::new("a=1\n   \nc=3").unwrap();
            let mut ranges = [MocktailRustCookieRedactionRange { begin: 0, end: 0, marker: 0 }; 8];
            let mut count = 0usize;
            assert_eq!(mocktail_rust_auth_find_redaction_ranges(
                orig.as_ptr(), orig.as_bytes().len(),
                red.as_ptr(), red.as_bytes().len(),
                ranges.as_mut_ptr(), ranges.len(), &mut count
            ), 0);
            assert_eq!(count, 1);
            assert_eq!(ranges[0].begin, 4);
            assert_eq!(ranges[0].end, 7);
            assert_eq!(ranges[0].marker, 4);
        }
    }

    #[test]
    fn test_capability_input_flags() {
        let mut presence = MocktailRustCapabilityInputSymbolsPresence::default();
        presence.has_gamepad_connect_event_with_gamepad_type = true;
        presence.has_set_gamepad_supported_key_with_gamepad_type = true;
        presence.has_set_gamepad_supported_motion_with_gamepad_type = true;
        presence.has_gamepad_axis_event = true;
        presence.has_gamepad_button_event = true;
        presence.has_gamepad_disconnect_event = true;

        let mut flags = MocktailRustCapabilityInputFlags::default();
        unsafe {
            mocktail_rust_capability_eval_input_flags(&presence, &mut flags);
        }
        assert_eq!(flags.gamepad_api, 1);
        assert!(!flags.clear_partial_gamepad);
        assert!(flags.has_gamepad_events);

        // Incomplete gamepad modern api
        presence.has_set_gamepad_supported_motion_with_gamepad_type = false;
        unsafe {
            mocktail_rust_capability_eval_input_flags(&presence, &mut flags);
        }
        assert_eq!(flags.gamepad_api, 0);
        assert!(flags.clear_partial_gamepad);
        assert!(!flags.has_gamepad_events);
    }

    #[test]
    fn test_session_log_helpers() {
        unsafe {
            // Display path
            let mut out = [0 as c_char; 128];
            let mut len = 0usize;

            let path_empty = CString::new("").unwrap();
            let home = CString::new("/home/user").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_empty.as_ptr(), 0,
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "unknown");

            let path_inside = CString::new("/home/user/logs/session.log").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_inside.as_ptr(), path_inside.as_bytes().len(),
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "~/logs/session.log");

            let path_home = CString::new("/home/user").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_home.as_ptr(), path_home.as_bytes().len(),
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "~/.");

            let path_outside = CString::new("/usr/bin/mocktail").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_outside.as_ptr(), path_outside.as_bytes().len(),
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "/usr/bin/mocktail");

            // Package kind
            assert_eq!(mocktail_rust_session_log_package_kind(
                true, false, false, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "flatpak");

            assert_eq!(mocktail_rust_session_log_package_kind(
                false, true, false, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "appimage");

            assert_eq!(mocktail_rust_session_log_package_kind(
                false, false, true, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "portable");

            let sys_path = CString::new("/usr/bin/mocktail").unwrap();
            assert_eq!(mocktail_rust_session_log_package_kind(
                false, false, false, sys_path.as_ptr(), sys_path.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "system-install");

            let build_path = CString::new("/home/user/mocktail/build/mocktail").unwrap();
            assert_eq!(mocktail_rust_session_log_package_kind(
                false, false, false, build_path.as_ptr(), build_path.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "local-build");

            // Display server
            assert_eq!(mocktail_rust_session_log_display_server(
                true, false, out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "wayland");

            assert_eq!(mocktail_rust_session_log_display_server(
                false, true, out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "x11");

            assert_eq!(mocktail_rust_session_log_display_server(
                false, false, out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "none");

            // Device node name
            assert!(mocktail_rust_session_log_device_node_name(
                b"renderD128\0".as_ptr() as *const c_char, 10,
                b"renderD\0".as_ptr() as *const c_char, 7
            ));
            assert!(!mocktail_rust_session_log_device_node_name(
                b"renderD\0".as_ptr() as *const c_char, 7,
                b"renderD\0".as_ptr() as *const c_char, 7
            ));
            assert!(!mocktail_rust_session_log_device_node_name(
                b"renderDabc\0".as_ptr() as *const c_char, 10,
                b"renderD\0".as_ptr() as *const c_char, 7
            ));
            assert!(mocktail_rust_session_log_device_node_name(
                b"card0\0".as_ptr() as *const c_char, 5,
                b"card\0".as_ptr() as *const c_char, 4
            ));
        }
    }

    #[test]
    fn test_candidate_approval_fingerprint_and_generation() {
        unsafe {
            let pid = CString::new("pay123").unwrap();
            let meta = CString::new("meta_sha").unwrap();
            let lib = CString::new("lib_sha").unwrap();
            let base = CString::new("base_sha").unwrap();
            let abi = CString::new("x86_64").unwrap();
            let split = CString::new("split_sha").unwrap();
            let assets = CString::new("assets_sha").unwrap();

            let input = MocktailRustPayloadFingerprintInput {
                payload_id: pid.as_ptr(), payload_id_len: pid.as_bytes().len(),
                metadata_sha256: meta.as_ptr(), metadata_sha256_len: meta.as_bytes().len(),
                library_sha256: lib.as_ptr(), library_sha256_len: lib.as_bytes().len(),
                base_apk_sha256: base.as_ptr(), base_apk_sha256_len: base.as_bytes().len(),
                guest_abi: abi.as_ptr(), guest_abi_len: abi.as_bytes().len(),
                split_apk_sha256: split.as_ptr(), split_apk_sha256_len: split.as_bytes().len(),
                asset_tree_sha256: assets.as_ptr(), asset_tree_sha256_len: assets.as_bytes().len(),
            };

            let mut fp_buf = [0 as c_char; 65];
            assert_eq!(mocktail_rust_candidate_approval_fingerprint(&input, fp_buf.as_mut_ptr(), fp_buf.len()), 0);
            let fp_str = CStr::from_ptr(fp_buf.as_ptr()).to_str().unwrap();
            assert_eq!(fp_str.len(), 64);

            let rbid = CString::new("1686400865ae0e408cd7bd67de7a439625c6fd13").unwrap();
            let prof = CString::new("profile_sha").unwrap();
            let compat = CString::new("compat_sha").unwrap();
            let c1 = CString::new("c1_sha").unwrap();
            let c2 = CString::new("c2_sha").unwrap();

            let mut gen_buf = [0 as c_char; 41];
            assert_eq!(mocktail_rust_candidate_approval_generation(
                rbid.as_ptr(), rbid.as_bytes().len(),
                fp_buf.as_ptr(), fp_str.len(),
                prof.as_ptr(), prof.as_bytes().len(),
                compat.as_ptr(), compat.as_bytes().len(),
                c1.as_ptr(), c1.as_bytes().len(),
                c2.as_ptr(), c2.as_bytes().len(),
                gen_buf.as_mut_ptr(), gen_buf.len()
            ), 0);
            let gen_str = CStr::from_ptr(gen_buf.as_ptr()).to_str().unwrap();
            assert_eq!(gen_str.len(), 40);
        }
    }

    #[test]
    fn test_candidate_approval_validate_binding() {
        unsafe {
            let pid = "2814-test";
            let bid = "1686400865ae0e408cd7bd67de7a439625c6fd13";
            let lib_sha = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
            let ver_name = "2.732.1043";
            let ver_code = 2814u64;

            let prof_json = format!(
                r#"{{"schema_version":1,"payload_id":"{pid}","payload_path":"payloads/{pid}","elf_build_id":"{bid}","payload_sha256":"{lib_sha}","profile":{{"elf_build_id":"{bid}"}},"reference":{{}}}}"#
            );
            let compat_json = format!(
                r#"{{"schema_version":1,"profiles":[{{"version_name":"{ver_name}","version_code":{ver_code},"elf_build_id":"{bid}","status":"experimental","default_allowed":true,"allow_legacy_binary_patches":false,"allow_host_abi_bridges":true,"allow_host_constructor_replay":true}}]}}"#
            );

            let p_c = CString::new(prof_json).unwrap();
            let c_c = CString::new(compat_json).unwrap();
            let pid_c = CString::new(pid).unwrap();
            let bid_c = CString::new(bid).unwrap();
            let lib_c = CString::new(lib_sha).unwrap();
            let ver_c = CString::new(ver_name).unwrap();

            let mut err_buf = [0 as c_char; 256];
            assert_eq!(mocktail_rust_candidate_approval_validate_binding(
                p_c.as_ptr(), p_c.as_bytes().len(),
                c_c.as_ptr(), c_c.as_bytes().len(),
                pid_c.as_ptr(), pid_c.as_bytes().len(),
                bid_c.as_ptr(), bid_c.as_bytes().len(),
                lib_c.as_ptr(), lib_c.as_bytes().len(),
                ver_c.as_ptr(), ver_c.as_bytes().len(),
                ver_code,
                err_buf.as_mut_ptr(), err_buf.len()
            ), 0);

            // Mismatched build id
            let bad_bid = CString::new("0000000000000000000000000000000000000000").unwrap();
            assert_eq!(mocktail_rust_candidate_approval_validate_binding(
                p_c.as_ptr(), p_c.as_bytes().len(),
                c_c.as_ptr(), c_c.as_bytes().len(),
                pid_c.as_ptr(), pid_c.as_bytes().len(),
                bad_bid.as_ptr(), bad_bid.as_bytes().len(),
                lib_c.as_ptr(), lib_c.as_bytes().len(),
                ver_c.as_ptr(), ver_c.as_bytes().len(),
                ver_code,
                err_buf.as_mut_ptr(), err_buf.len()
            ), 1);
            let err_str = CStr::from_ptr(err_buf.as_ptr()).to_str().unwrap();
            assert_eq!(err_str, "derived approval profile is not bound to exact payload bytes");
        }
    }

    #[test]
    fn test_candidate_approval_attestation_and_receipt() {
        unsafe {
            let run_id = CString::new("run-123").unwrap();
            let pid = CString::new("pay-456").unwrap();
            let fp = CString::new("fp-789").unwrap();
            let prof = CString::new("prof-sha").unwrap();
            let compat = CString::new("compat-sha").unwrap();
            let rsha = CString::new("run-sha").unwrap();
            let rbid = CString::new("run-bid").unwrap();
            let lsha = CString::new("log-sha").unwrap();

            let att_in = MocktailRustCanaryAttestationInput {
                run: 1,
                run_id: run_id.as_ptr(), run_id_len: run_id.as_bytes().len(),
                payload_id: pid.as_ptr(), payload_id_len: pid.as_bytes().len(),
                payload_fingerprint: fp.as_ptr(), payload_fingerprint_len: fp.as_bytes().len(),
                profile_sha256: prof.as_ptr(), profile_sha256_len: prof.as_bytes().len(),
                compatibility_manifest_sha256: compat.as_ptr(), compatibility_manifest_sha256_len: compat.as_bytes().len(),
                runtime_sha256: rsha.as_ptr(), runtime_sha256_len: rsha.as_bytes().len(),
                runtime_build_id: rbid.as_ptr(), runtime_build_id_len: rbid.as_bytes().len(),
                log_sha256: lsha.as_ptr(), log_sha256_len: lsha.as_bytes().len(),
            };

            let mut json_buf = [0 as c_char; 1024];
            let mut out_len = 0usize;
            assert_eq!(mocktail_rust_candidate_approval_build_attestation(
                &att_in, json_buf.as_mut_ptr(), json_buf.len(), &mut out_len
            ), 0);
            let att_json = CStr::from_ptr(json_buf.as_ptr()).to_str().unwrap();
            assert!(att_json.contains(r#""canary_tier": "C""#));
            assert!(att_json.contains(r#""readiness_log_sha256": "log-sha""#));
            assert!(att_json.ends_with('\n'));

            let gen = CString::new("gen-abc").unwrap();
            let ppath = CString::new("/path/to/lib").unwrap();
            let c1 = CString::new("canary1-hash").unwrap();
            let c2 = CString::new("canary2-hash").unwrap();
            let app_at = CString::new("2026-10-31T12:00:00Z").unwrap();

            let rcpt_in = MocktailRustApprovalReceiptInput {
                payload_id: pid.as_ptr(), payload_id_len: pid.as_bytes().len(),
                generation: gen.as_ptr(), generation_len: gen.as_bytes().len(),
                payload_path: ppath.as_ptr(), payload_path_len: ppath.as_bytes().len(),
                elf_build_id: rbid.as_ptr(), elf_build_id_len: rbid.as_bytes().len(),
                library_sha256: prof.as_ptr(), library_sha256_len: prof.as_bytes().len(),
                payload_fingerprint: fp.as_ptr(), payload_fingerprint_len: fp.as_bytes().len(),
                profile_sha256: prof.as_ptr(), profile_sha256_len: prof.as_bytes().len(),
                compatibility_manifest_sha256: compat.as_ptr(), compatibility_manifest_sha256_len: compat.as_bytes().len(),
                runtime_sha256: rsha.as_ptr(), runtime_sha256_len: rsha.as_bytes().len(),
                runtime_build_id: rbid.as_ptr(), runtime_build_id_len: rbid.as_bytes().len(),
                canary_1_sha256: c1.as_ptr(), canary_1_sha256_len: c1.as_bytes().len(),
                canary_2_sha256: c2.as_ptr(), canary_2_sha256_len: c2.as_bytes().len(),
                approved_at_utc: app_at.as_ptr(), approved_at_utc_len: app_at.as_bytes().len(),
            };

            assert_eq!(mocktail_rust_candidate_approval_build_receipt(
                &rcpt_in, json_buf.as_mut_ptr(), json_buf.len(), &mut out_len
            ), 0);
            let rcpt_json = CStr::from_ptr(json_buf.as_ptr()).to_str().unwrap();
            assert!(rcpt_json.contains(r#""status": "approved""#));
            assert!(rcpt_json.contains(r#""canary_attestation_sha256": ["#));
            assert!(rcpt_json.ends_with('\n'));
        }
    }

    #[test]
    fn test_game_mode_and_physics_policies() {
        unsafe {
            let mut policy = -1;
            let a = CString::new("auto").unwrap();
            assert!(mocktail_rust_game_mode_parse_policy(a.as_ptr(), a.as_bytes().len(), &mut policy));
            assert_eq!(policy, 0);

            let on = CString::new("on").unwrap();
            assert!(mocktail_rust_game_mode_parse_policy(on.as_ptr(), on.as_bytes().len(), &mut policy));
            assert_eq!(policy, 1);

            let off = CString::new("false").unwrap();
            assert!(mocktail_rust_game_mode_parse_policy(off.as_ptr(), off.as_bytes().len(), &mut policy));
            assert_eq!(policy, 2);

            let inv = CString::new("invalid_val").unwrap();
            assert!(!mocktail_rust_game_mode_parse_policy(inv.as_ptr(), inv.as_bytes().len(), &mut policy));

            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(0)).to_str().unwrap(), "auto");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(1)).to_str().unwrap(), "on");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(2)).to_str().unwrap(), "off");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(99)).to_str().unwrap(), "invalid");

            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_session_state_name(0)).to_str().unwrap(), "disabled");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_session_state_name(4)).to_str().unwrap(), "active");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_session_state_name(99)).to_str().unwrap(), "invalid");

            let mut mode = -1;
            let lat = CString::new("latency").unwrap();
            assert!(mocktail_rust_performance_parse_physics_worker_mode(lat.as_ptr(), lat.as_bytes().len(), &mut mode));
            assert_eq!(mode, 1);

            let tp = CString::new("throughput").unwrap();
            assert!(mocktail_rust_performance_parse_physics_worker_mode(tp.as_ptr(), tp.as_bytes().len(), &mut mode));
            assert_eq!(mode, 2);

            assert_eq!(CStr::from_ptr(mocktail_rust_performance_physics_worker_mode_name(1)).to_str().unwrap(), "latency");
            assert_eq!(mocktail_rust_performance_calculate_throughput_worker_count(8), 8);
            assert_eq!(mocktail_rust_performance_calculate_throughput_worker_count(0), 1);
        }
    }

    #[test]
    fn test_single_instance_canary_validation() {
        unsafe {
            let can = CString::new("1").unwrap();
            let skip = CString::new("1").unwrap();
            let timer = CString::new("5000").unwrap();
            let data = CString::new("/tmp/test/data").unwrap();
            let cache = CString::new("/tmp/test/cache").unwrap();
            let state = CString::new("/tmp/test/state").unwrap();

            let inp = MocktailRustCanaryPathsInput {
                canary_value: can.as_ptr(), canary_len: can.as_bytes().len(),
                has_data_root: true, has_cache_root: true, has_state_root: true,
                has_roblox_lib: true, has_asset_path: true,
                skip_update_value: skip.as_ptr(), skip_update_len: skip.as_bytes().len(),
                auto_exit_ms_value: timer.as_ptr(), auto_exit_ms_len: timer.as_bytes().len(),
                data_root: data.as_ptr(), data_root_len: data.as_bytes().len(),
                cache_root: cache.as_ptr(), cache_root_len: cache.as_bytes().len(),
                state_root: state.as_ptr(), state_root_len: state.as_bytes().len(),
            };

            let mut err = [0 as c_char; 256];
            assert_eq!(mocktail_rust_single_instance_validate_isolated_canary(&inp, err.as_mut_ptr(), err.len()), 0);

            // Missing variable
            let mut bad_inp = inp;
            bad_inp.has_roblox_lib = false;
            assert_eq!(mocktail_rust_single_instance_validate_isolated_canary(&bad_inp, err.as_mut_ptr(), err.len()), 1);

            // Non-sibling paths (different parent)
            let bad_state = CString::new("/other/test/state").unwrap();
            bad_inp.has_roblox_lib = true;
            bad_inp.state_root = bad_state.as_ptr();
            bad_inp.state_root_len = bad_state.as_bytes().len();
            assert_eq!(mocktail_rust_single_instance_validate_isolated_canary(&bad_inp, err.as_mut_ptr(), err.len()), 2);
        }
    }

    #[test]
    fn test_settings_overrides_engine() {
        unsafe {
            let base = CString::new(r#"{"ExistingKey":"123"}"#).unwrap();
            let mut out = [0 as c_char; 1024];
            let mut len = 0usize;

            assert_eq!(mocktail_rust_http_client_merge_settings_overrides(
                base.as_ptr(), base.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            let s1 = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
            assert!(s1.contains(r#""ExistingKey":"123""#));
            assert!(s1.contains(r#""FFlagUseRuntimeMutexRvHttpClient":"False""#));

            assert_eq!(mocktail_rust_audio_device_menu_merge_overrides(
                base.as_ptr(), base.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            let s2 = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
            assert!(s2.contains(r#""FFlagDebugUseWebRtcAudioDevices":"False""#));

            assert_eq!(mocktail_rust_audio_capture_merge_overrides(
                base.as_ptr(), base.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            let s3 = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
            assert!(s3.contains(r#""DFFlagVoiceChatSkipPermissionCheckForTests":"False""#));
        }
    }

    #[test]
    fn test_section67_texture_memory_policy() {
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(0), 0);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(2048 * 1024 * 1024), 0);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(4096 * 1024 * 1024), 512 * 1024 * 1024);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(8192 * 1024 * 1024), 1024 * 1024 * 1024);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(65536 * 1024 * 1024), 1536 * 1024 * 1024);

        let base = CString::new(r#"{"Existing":"true"}"#).unwrap();
        let mut out = [0 as c_char; 512];
        let mut out_len = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_texture_memory_merge_overrides(
            512 * 1024 * 1024,
            base.as_ptr(),
            base.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert!(s.contains("FIntRenderForceVideoMemorySize"));
        assert!(s.contains("536870912"));

        // Malformed json
        let bad = CString::new(r#"["not", "object"]"#).unwrap();
        let rc_bad = mocktail_rust_texture_memory_merge_overrides(
            512 * 1024 * 1024,
            bad.as_ptr(),
            bad.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_bad, -1);
    }

    #[test]
    fn test_section68_desktop_app_policy() {
        let default_policy = CString::new(r#"{"PlatformGroup":"Unknown","Existing":1}"#).unwrap();
        let theme = CString::new("dark").unwrap();
        let mut out_storage = [0 as c_char; 2048];
        let mut out_storage_len = 0usize;
        let mut out_policy = [0 as c_char; 2048];
        let mut out_policy_len = 0usize;
        let mut updated = false;
        let mut norm_count = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_process_desktop_app_policy(
            std::ptr::null(),
            0,
            false,
            default_policy.as_ptr(),
            default_policy.as_bytes().len(),
            42,
            theme.as_ptr(),
            out_storage.as_mut_ptr(),
            out_storage.len(),
            &mut out_storage_len,
            out_policy.as_mut_ptr(),
            out_policy.len(),
            &mut out_policy_len,
            &mut updated,
            &mut norm_count,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert!(updated);
        let pol = unsafe { CStr::from_ptr(out_policy.as_ptr()).to_str().unwrap() };
        assert!(pol.contains(r#""PlatformGroup":"Desktop""#));
        assert!(pol.contains(r#""ForceTheme":"dark""#));
        assert!(pol.contains(r#""Existing":1"#));
    }

    #[test]
    fn test_section69_experience_launch_json() {
        let valid_json = CString::new(r#"{"placeId":17580461965,"userId":123,"gameInstanceId":"server-1"}"#).unwrap();
        let mut data = MocktailRustExperienceLaunchData {
            place_id: 0,
            user_id: 0,
            conversation_id: 0,
            referred_by_player_id: 0,
        };
        let mut can_buf = [0 as c_char; 1024];
        let mut can_len = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_parse_experience_launch_json(
            valid_json.as_ptr(),
            valid_json.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(data.place_id, 17580461965);
        assert_eq!(data.user_id, 123);

        // Missing/invalid placeId
        let invalid_json = CString::new(r#"{"placeId":0,"userId":123}"#).unwrap();
        let rc_inv = mocktail_rust_parse_experience_launch_json(
            invalid_json.as_ptr(),
            invalid_json.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_inv, -4);

        // String placeId
        let str_place = CString::new(r#"{"placeId":"17580461965"}"#).unwrap();
        let rc_str = mocktail_rust_parse_experience_launch_json(
            str_place.as_ptr(),
            str_place.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_str, -3);

        // Overflow placeId
        let oflow_place = CString::new(r#"{"placeId":18446744073709551615}"#).unwrap();
        let rc_oflow = mocktail_rust_parse_experience_launch_json(
            oflow_place.as_ptr(),
            oflow_place.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_oflow, -3);
    }

    #[test]
    fn test_section70_environment_abstraction() {
        std::env::set_var("MOCKTAIL_TEST_ENV_VAR", "test_val");
        let name = CString::new("MOCKTAIL_TEST_ENV_VAR").unwrap();
        assert_eq!(mocktail_rust_env_has_non_empty(name.as_ptr()), 1);

        let mut out = [0 as c_char; 64];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_env_get(name.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert_eq!(s, "test_val");

        let missing = CString::new("MOCKTAIL_TEST_NON_EXISTENT_VAR").unwrap();
        assert_eq!(mocktail_rust_env_has_non_empty(missing.as_ptr()), 0);
        let def = CString::new("fallback").unwrap();
        assert_eq!(mocktail_rust_env_get_or(missing.as_ptr(), def.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        let s_def = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert_eq!(s_def, "fallback");
    }

    #[test]
    fn test_section71_command_line_usage() {
        let prog = CString::new("mocktail-app").unwrap();
        let abi = CString::new("x86_64").unwrap();
        let mut out = [0 as c_char; 4096];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_command_line_usage(prog.as_ptr(), abi.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert!(s.contains("Usage: mocktail-app [options] [roblox-uri]"));
        assert!(s.contains("--graphics"));
        assert!(s.contains("--allow-unverified-build"));
    }

    #[test]
    fn test_section72_frame_rate_policy_helpers() {
        let mut buf = [0 as c_char; 32];
        assert_eq!(mocktail_rust_frame_rate_policy_name(0, 0, buf.as_mut_ptr(), buf.len()), 0);
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "unmanaged");

        assert_eq!(mocktail_rust_frame_rate_policy_name(2, 144, buf.as_mut_ptr(), buf.len()), 0);
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "144");
    }

    #[test]
    fn test_section73_present_mode_and_wsi_extensions() {
        let mut khr_buf = [0 as c_char; 32];
        assert_eq!(mocktail_rust_present_mode_khr_name(VK_PRESENT_MODE_FIFO_KHR, khr_buf.as_mut_ptr(), khr_buf.len()), 0);
        let fifo_name = unsafe { CStr::from_ptr(khr_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(fifo_name, "fifo");

        let mut pol_buf = [0 as c_char; 32];
        assert_eq!(mocktail_rust_present_mode_policy_name(1, pol_buf.as_mut_ptr(), pol_buf.len()), 0);
        let vsync_name = unsafe { CStr::from_ptr(pol_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(vsync_name, "vsync");

        assert_eq!(mocktail_rust_normalize_android_swapchain_result(1000001003), 0);
        assert_eq!(mocktail_rust_normalize_android_swapchain_result(0), 0);
        assert_eq!(mocktail_rust_normalize_android_swapchain_result(-4), -4);

        let ext1 = CString::new("VK_KHR_surface").unwrap();
        let ext2 = CString::new("VK_KHR_android_surface").unwrap();
        let ext3 = CString::new("VK_EXT_debug_utils").unwrap();
        let android_ptrs = [ext1.as_ptr(), ext2.as_ptr(), ext3.as_ptr()];

        let host1 = CString::new("VK_KHR_surface").unwrap();
        let host2 = CString::new("VK_KHR_xcb_surface").unwrap();
        let host_ptrs = [host1.as_ptr(), host2.as_ptr()];

        let mut out_ptrs = [std::ptr::null_mut() as *mut c_char; 16];
        let mut out_count = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_translate_android_vulkan_instance_extensions(
            android_ptrs.as_ptr(),
            android_ptrs.len(),
            host_ptrs.as_ptr(),
            host_ptrs.len(),
            out_ptrs.as_mut_ptr(),
            out_ptrs.len(),
            &mut out_count,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(out_count, 3);
        let s0 = unsafe { CStr::from_ptr(out_ptrs[0]).to_str().unwrap() };
        let s1 = unsafe { CStr::from_ptr(out_ptrs[1]).to_str().unwrap() };
        let s2 = unsafe { CStr::from_ptr(out_ptrs[2]).to_str().unwrap() };
        assert_eq!(s0, "VK_KHR_surface");
        assert_eq!(s1, "VK_EXT_debug_utils");
        assert_eq!(s2, "VK_KHR_xcb_surface");

        for i in 0..out_count {
            mocktail_rust_free_c_string(out_ptrs[i]);
        }
    }

    #[test]
    fn test_swapchain_images_env_override() {
        let _guard = test_env_lock();
        std::env::set_var("MOCKTAIL_SWAPCHAIN_IMAGES", "3");
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(3 /* Fifo */, 2, 2, 8), 3);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(1 /* Vsync */, 2, 2, 8), 3);
        std::env::remove_var("MOCKTAIL_SWAPCHAIN_IMAGES");
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(3 /* Fifo */, 2, 2, 8), 2);
    }

    #[test]
    fn test_section74_display_refresh_capabilities() {
        let supp = [60.0f32, 144.0, 60.001, -1.0, f32::NAN, 120.0];
        let mut out = [0.0f32; 8];
        let mut count = 0usize;
        let rc = mocktail_rust_normalize_display_refresh_capabilities(
            60.0,
            supp.as_ptr(),
            supp.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut count,
        );
        assert_eq!(rc, 0);
        assert_eq!(count, 3); // 60.0 (merged with 60.001), 120.0, 144.0
        assert_eq!(out[0], 60.0);
        assert_eq!(out[1], 120.0);
        assert_eq!(out[2], 144.0);
    }

    #[test]
    fn test_section75_platform_metadata_identity() {
        let mut name = [0 as c_char; 32];
        let mut id = [0 as c_char; 64];
        let mut ty = [0 as c_char; 32];
        assert_eq!(
            mocktail_rust_platform_metadata_identity(
                name.as_mut_ptr(),
                name.len(),
                id.as_mut_ptr(),
                id.len(),
                ty.as_mut_ptr(),
                ty.len()
            ),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(name.as_ptr()).to_str().unwrap() }, "Mocktail");
        assert_eq!(unsafe { CStr::from_ptr(id.as_ptr()).to_str().unwrap() }, "space.bigrat.mocktail");
        assert_eq!(unsafe { CStr::from_ptr(ty.as_ptr()).to_str().unwrap() }, "game");
    }

    #[test]
    fn test_section76_window_icon_png_header() {
        let mut png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // magic
            0x00, 0x00, 0x00, 0x0D,                         // IHDR len
            b'I', b'H', b'D', b'R',
            0x00, 0x00, 0x01, 0x00, // width 256
            0x00, 0x00, 0x01, 0x00, // height 256
            0x08, 0x06, 0x00, 0x00, 0x00,
        ];
        let mut w = 0u32;
        let mut h = 0u32;
        assert_eq!(mocktail_rust_validate_window_icon_png_header(png.as_ptr(), png.len(), &mut w, &mut h), 0);
        assert_eq!(w, 256);
        assert_eq!(h, 256);

        png[0] = 0;
        assert_eq!(mocktail_rust_validate_window_icon_png_header(png.as_ptr(), png.len(), &mut w, &mut h), -2);
    }

    #[test]
    fn test_section77_supported_launch_defaults() {
        let cnt = mocktail_rust_supported_launch_defaults_count(1);
        assert_eq!(cnt, 27);
        assert_eq!(mocktail_rust_supported_launch_defaults_count(0), 0);

        let mut key = [0 as c_char; 96];
        let mut val = [0 as c_char; 96];
        assert_eq!(
            mocktail_rust_supported_launch_default_entry(1, 0, key.as_mut_ptr(), key.len(), val.as_mut_ptr(), val.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(key.as_ptr()).to_str().unwrap() }, "MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP");
        assert_eq!(unsafe { CStr::from_ptr(val.as_ptr()).to_str().unwrap() }, "1");
        for i in 0..cnt {
            assert_eq!(
                mocktail_rust_supported_launch_default_entry(1, i, key.as_mut_ptr(), key.len(), val.as_mut_ptr(), val.len()),
                0
            );
            let k = unsafe { CStr::from_ptr(key.as_ptr()).to_str().unwrap() };
            assert_ne!(k, "MOCKTAIL_MAIN_THREAD_MESSAGE_PUMP");
        }
    }

    #[test]
    fn test_section78_platform_profile_and_paths() {
        let prof = CString::new("desktop").unwrap();
        let mut rev = [0 as c_char; 64];
        assert_eq!(
            mocktail_rust_build_platform_profile_revision(prof.as_ptr(), 1, 0, 1, rev.as_mut_ptr(), rev.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(rev.as_ptr()).to_str().unwrap() }, "device-v1-desktop-t1-m0-k1");

        let conf = CString::new("/data/user/0/com.roblox.client/files").unwrap();
        let root = CString::new("/home/user/.mocktail/data").unwrap();
        let mut out = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_translate_android_files_path(conf.as_ptr(), root.as_ptr(), out.as_mut_ptr(), out.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() }, "/home/user/.mocktail/data/files");
    }

    #[test]
    fn test_section79_platform_cache_fingerprint() {
        let json = CString::new(r#"{"schema_version":1,"profile_revision":"rev-123"}"#).unwrap();
        let mut rev = [0 as c_char; 64];
        assert_eq!(
            mocktail_rust_validate_platform_cache_fingerprint(json.as_ptr(), json.as_bytes().len(), rev.as_mut_ptr(), rev.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(rev.as_ptr()).to_str().unwrap() }, "rev-123");
    }

    #[test]
    fn test_section80_browser_service_command() {
        let json = CString::new(r#"{"command":"open","url":"https://roblox.com/home","title":"Home","visible":true}"#).unwrap();
        let mut cmd_type = 0i32;
        let mut cmd = MocktailRustBrowserServiceOpenCommand {
            url: [0; 1024],
            title: [0; 512],
            has_title: 0,
            visible: 0,
            modal: 0,
            back_navigation_disabled: 0,
            show_domain_as_title: 0,
        };
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_parse_browser_service_command(
            json.as_ptr(),
            json.as_bytes().len(),
            &mut cmd_type,
            &mut cmd,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(cmd_type, 1);
        assert_eq!(unsafe { CStr::from_ptr(cmd.url.as_ptr()).to_str().unwrap() }, "https://roblox.com/home");
        assert_eq!(unsafe { CStr::from_ptr(cmd.title.as_ptr()).to_str().unwrap() }, "Home");
        assert_eq!(cmd.visible, 1);
    }

    #[test]
    fn test_section81_text_display_state() {
        let text = CString::new("Hello 🌍!").unwrap();
        let mut cp = 0usize;
        let bytes = mocktail_rust_utf8_byte_for_utf16_cursor(text.as_ptr(), text.as_bytes().len(), 6, &mut cp);
        assert_eq!(bytes, 6); // "Hello "
        assert_eq!(cp, 6);

        assert_eq!(mocktail_rust_text_geometry_intersects_viewport(10, 10, 100, 50, 800, 600), 1);
        assert_eq!(mocktail_rust_text_geometry_intersects_viewport(900, 10, 100, 50, 800, 600), 0);
    }

    #[test]
    fn test_section82_fullscreen_setter_contract() {
        let mut code = vec![0u8; 120];
        code[0..4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        code[4..6].copy_from_slice(&[0x89, 0xf3]);
        code[20..26].copy_from_slice(&[0x38, 0x98, 0x61, 0x01, 0x00, 0x00]);
        code[30..36].copy_from_slice(&[0x88, 0x98, 0x61, 0x01, 0x00, 0x00]);
        assert_eq!(mocktail_rust_validate_fullscreen_setter_contract(code.as_ptr(), code.len()), 1);

        code[0] = 0;
        assert_eq!(mocktail_rust_validate_fullscreen_setter_contract(code.as_ptr(), code.len()), 0);
    }

    #[test]
    fn test_section83_pointer_capture_evaluate() {
        let mut cap = 0i32;
        let mut vis = 0i32;
        mocktail_rust_pointer_capture_evaluate(1, 1, 1, 0, 0, &mut cap, &mut vis);
        assert_eq!(cap, 1);
        assert_eq!(vis, 0);

        mocktail_rust_pointer_capture_evaluate(0, 1, 1, 0, 0, &mut cap, &mut vis);
        assert_eq!(cap, 0);
        assert_eq!(vis, 1);
    }

    #[test]
    fn test_section84_text_input_type_mapper() {
        assert_eq!(mocktail_rust_map_roblox_text_input_type(2), 2); // Number
        assert_eq!(mocktail_rust_map_roblox_text_input_type(3), 3); // Email
        assert_eq!(mocktail_rust_map_roblox_text_input_type(5), 4); // Password
        assert_eq!(mocktail_rust_map_roblox_text_input_type(6), 5); // Username
        assert_eq!(mocktail_rust_map_roblox_text_input_type(0), 1); // Text
    }

    #[test]
    fn test_section85_bionic_sysconf() {
        let mut std_sc = 0i32;
        let mut fix = 0i64;
        assert_eq!(mocktail_rust_bionic_sysconf_translate_name(0x0006, &mut std_sc, &mut fix), 1);
        assert_eq!(fix, 100);

        assert_eq!(mocktail_rust_bionic_sysconf_translate_name(0x0027, &mut std_sc, &mut fix), 0);
        assert_eq!(std_sc, 0x0027);
    }

    #[test]
    fn test_section86_build_profile() {
        let id = CString::new("ABCD12EF").unwrap();
        let mut out = [0 as c_char; 32];
        assert_eq!(mocktail_rust_normalize_build_id(id.as_ptr(), out.as_mut_ptr(), out.len()), 0);
        assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() }, "abcd12ef");

        let st = CString::new("supported").unwrap();
        assert_eq!(mocktail_rust_parse_status_string(st.as_ptr()), 0);

        let rva_str = CString::new("0x1234abcd").unwrap();
        let mut rva = 0usize;
        assert_eq!(mocktail_rust_parse_hex_rva(rva_str.as_ptr(), &mut rva), 0);
        assert_eq!(rva, 0x1234abcd);
    }

    #[test]
    fn test_section87_elf_build_id() {
        let valid = CString::new("0123456789abcdef").unwrap();
        assert_eq!(mocktail_rust_is_valid_build_id(valid.as_ptr(), valid.as_bytes().len()), 1);

        let odd = CString::new("123").unwrap();
        assert_eq!(mocktail_rust_is_valid_build_id(odd.as_ptr(), odd.as_bytes().len()), 0);
    }

    #[test]
    fn test_section88_http_client_spin_limiter() {
        let mut count = 63u64;
        let mut cp = 1000u64;
        let pause = mocktail_rust_http_spin_limiter_observe(&mut count, &mut cp, 1000 + 500, 64, 1000);
        assert_eq!(pause, 500);
    }

    #[test]
    fn test_section89_owned_pthread_status_name() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_owned_pthread_status_name(0, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "Joined");
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_owned_pthread_status_name_ptr(1)).to_str().unwrap() },
            "TimedOut"
        );
    }

    #[test]
    fn test_section90_failure_dialog() {
        assert_eq!(mocktail_rust_failure_dialogs_enabled(0, 0, 0, 1, 0), 1);
        assert_eq!(mocktail_rust_failure_dialogs_enabled(1, 0, 0, 1, 0), 0);

        let msg = CString::new("error occurred").unwrap();
        let mut pkt = [0 as c_char; 64];
        let mut len = 0usize;
        assert_eq!(
            mocktail_rust_failure_dialog_format_packet(b'M' as c_char, msg.as_ptr(), 2048, pkt.as_mut_ptr(), pkt.len(), &mut len),
            0
        );
        assert_eq!(len, 15);
        assert_eq!(pkt[0], b'M' as c_char);
    }

    #[test]
    fn test_section91_apk_provider_append_failure() {
        let ex = CString::new("prov1: err1").unwrap();
        let p2 = CString::new("prov2").unwrap();
        let e2 = CString::new("err2").unwrap();
        let mut out = [0 as c_char; 128];
        let mut len = 0usize;
        assert_eq!(
            mocktail_rust_apk_provider_append_failure(ex.as_ptr(), p2.as_ptr(), e2.as_ptr(), out.as_mut_ptr(), out.len(), &mut len),
            0
        );
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert_eq!(s, "prov1: err1; prov2: err2");
    }

    #[test]
    fn test_section92_update_config_yaml() {
        let yaml = CString::new("version: 1\nupdates:\n  automatic: true\n  launch_after_update: false\n  source: auto\n").unwrap();
        let mut auto = 0i32;
        let mut launch = 0i32;
        let mut src = [0 as c_char; 32];
        let mut err = [0 as c_char; 128];
        assert_eq!(
            mocktail_rust_parse_update_config_yaml(
                yaml.as_ptr(),
                yaml.as_bytes().len(),
                &mut auto,
                &mut launch,
                src.as_mut_ptr(),
                src.len(),
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(auto, 1);
        assert_eq!(launch, 0);
        assert_eq!(unsafe { CStr::from_ptr(src.as_ptr()).to_str().unwrap() }, "auto");
    }

    #[test]
    fn test_section93_unsafe_latest_overrides() {
        let e1 = CString::new("ROBLOX_LIB_PATH=/path").unwrap();
        assert_eq!(mocktail_rust_is_overridden_environment_var(e1.as_ptr()), 1);

        let e2 = CString::new("PATH=/usr/bin").unwrap();
        assert_eq!(mocktail_rust_is_overridden_environment_var(e2.as_ptr()), 0);
    }

    #[test]
    fn test_section94_canary_backend_and_audio() {
        let mut b = 0i32;
        let s = CString::new("angle-vulkan").unwrap();
        assert_eq!(mocktail_rust_canary_backend_parse(s.as_ptr(), &mut b), 0);
        assert_eq!(b, 3);

        let mut buf = [0 as c_char; 32];
        mocktail_rust_canary_backend_name(3, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "angle-vulkan");

        let log = CString::new("[mocktail][audio] OpenSL playback activity: submitted_buffers=10\n[mocktail][audio] OpenSL playback evidence: consumed_buffers=10\n[mocktail][audio] OpenSL player shutdown: submitted=10 clean=true\n").unwrap();
        let mut err = [0 as c_char; 128];
        assert_eq!(mocktail_rust_validate_canary_audio_log(log.as_ptr(), log.as_bytes().len(), 1, err.as_mut_ptr(), err.len()), 0);

        let partial_log = CString::new("[mocktail][audio] OpenSL playback activity: submitted_buffers=10\n[mocktail][audio] OpenSL playback evidence: consumed_buffers=10\n").unwrap();
        assert_eq!(mocktail_rust_validate_canary_audio_log(partial_log.as_ptr(), partial_log.as_bytes().len(), 0, err.as_mut_ptr(), err.len()), 0);
        assert_ne!(mocktail_rust_validate_canary_audio_log(partial_log.as_ptr(), partial_log.as_bytes().len(), 1, err.as_mut_ptr(), err.len()), 0);
    }

    #[test]
    fn test_section95_game_session() {
        let ptr = mocktail_rust_game_session_state_name(1);
        assert_eq!(unsafe { CStr::from_ptr(ptr).to_str().unwrap() }, "PrincipalReady");

        assert_eq!(mocktail_rust_game_session_can_transition(0, 1), 1);
        assert_eq!(mocktail_rust_game_session_can_transition(0, 5), 0);
        assert_eq!(mocktail_rust_game_session_can_transition(3, 7), 1);
    }

    #[test]
    fn test_section96_capability_flags() {
        let mut flags = 0i32;
        mocktail_rust_evaluate_startup_flags(1, 0, 1, 0, &mut flags);
        assert_eq!(flags, (1 << 0) | (1 << 2));
    }

    #[test]
    fn test_section97_app_lifecycle_names() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_app_lifecycle_status_name(1, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "Ready");

        mocktail_rust_app_shutdown_status_name(1, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "AlreadyStopped");
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_app_lifecycle_status_name_ptr(2)).to_str().unwrap() },
            "MissingRequiredSymbols"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_app_shutdown_status_name_ptr(2)).to_str().unwrap() },
            "ShutdownInProgress"
        );
    }

    #[test]
    fn test_section98_fresh_game_params_utf16() {
        let s = CString::new("Hello 🌟").unwrap();
        let mut out = [0u16; 32];
        let mut len = 0usize;
        assert_eq!(
            mocktail_rust_utf8_to_utf16_surrogates(s.as_ptr(), s.as_bytes().len(), out.as_mut_ptr(), out.len(), &mut len),
            0
        );
        assert_eq!(len, 8); // "Hello " (6) + star surrogate pair (2)
    }

    #[test]
    fn test_section99_permissions_reply() {
        let req = CString::new("{}").unwrap();
        let mut body = [0 as c_char; 256];
        let mut len = 0usize;
        let mut code = 0i32;
        let mut outcome = [0 as c_char; 32];
        assert_eq!(
            mocktail_rust_format_permissions_reply(0, 1, req.as_ptr(), body.as_mut_ptr(), body.len(), &mut len, &mut code, outcome.as_mut_ptr(), outcome.len()),
            0
        );
        let b = unsafe { CStr::from_ptr(body.as_ptr()).to_str().unwrap() };
        assert!(b.contains("MICROPHONE_ACCESS"));
        assert_eq!(unsafe { CStr::from_ptr(outcome.as_ptr()).to_str().unwrap() }, "supported");
    }

    #[test]
    fn test_section100_client_settings() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_client_settings_source_name(0, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "explicit JSON");
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_client_settings_source_name_ptr(2)).to_str().unwrap() },
            "bundled file"
        );

        let app = CString::new("RobloxStudio").unwrap();
        let mut url_buf = [0 as c_char; 128];
        mocktail_rust_client_settings_build_url(app.as_ptr(), url_buf.as_mut_ptr(), url_buf.len());
        assert_eq!(
            unsafe { CStr::from_ptr(url_buf.as_ptr()).to_str().unwrap() },
            "https://clientsettingscdn.roblox.com/v2/settings/application/RobloxStudio"
        );
    }

    #[test]
    fn test_section105_process_launch_policy() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_process_launch_format_limit(100, 0, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "100");

        mocktail_rust_process_launch_format_limit(0, 1, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "unlimited");

        let mut target = -1i32;
        let mut is_rt = -1i32;
        mocktail_rust_process_launch_eval_scheduler(0, &mut target, &mut is_rt);
        assert_eq!(is_rt, 0);
        assert_eq!(target, 0);

        mocktail_rust_process_launch_eval_scheduler(1, &mut target, &mut is_rt); // SCHED_FIFO
        assert_eq!(is_rt, 1);
        assert_eq!(target, 0);

        mocktail_rust_process_launch_eval_scheduler(2 | 0x4000_0000, &mut target, &mut is_rt); // SCHED_RR | RESET_ON_FORK
        assert_eq!(is_rt, 1);
        assert_eq!(target, 0x4000_0000);

        let mut action = -1i32;
        mocktail_rust_process_launch_eval_cpu_limit(30, 0, 0, 1, &mut action);
        assert_eq!(action, 1); // clear soft limit

        mocktail_rust_process_launch_eval_cpu_limit(30, 0, 60, 0, &mut action);
        assert_eq!(action, 2); // finite limit retained

        mocktail_rust_process_launch_eval_cpu_limit(0, 1, 0, 1, &mut action);
        assert_eq!(action, 0); // no action

        let mut diag = [0 as c_char; 2048];
        let mut written = 0usize;
        assert_eq!(
            mocktail_rust_apply_interactive_process_launch_policy(
                diag.as_mut_ptr(),
                diag.len(),
                &mut written
            ),
            0
        );
        let s = unsafe { CStr::from_ptr(diag.as_ptr()).to_str().unwrap() };
        assert!(s.contains("[process]"));
        assert!(s.contains("RLIMIT_CPU"));
    }

    #[test]
    fn test_section106_pinned_apk_provider() {
        let valid_hex = CString::new("d26d3afb9815d22f812538aca07d69fa686d10ea10aa0b466bb0203b70094d12").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_hex_digest(valid_hex.as_ptr(), 64, 64), 1);
        assert_eq!(mocktail_rust_pinned_apk_hex_digest(valid_hex.as_ptr(), 63, 64), 0);

        let invalid_hex = CString::new("z26d3afb9815d22f812538aca07d69fa686d10ea10aa0b466bb0203b70094d12").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_hex_digest(invalid_hex.as_ptr(), 64, 64), 0);

        let valid_fn = CString::new("base.apk").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_archive_filename_valid(valid_fn.as_ptr(), 8), 1);

        let invalid_fn1 = CString::new("../base.apk").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_archive_filename_valid(invalid_fn1.as_ptr(), 11), 0);

        let invalid_fn2 = CString::new("base.zip").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_archive_filename_valid(invalid_fn2.as_ptr(), 8), 0);

        assert_eq!(mocktail_rust_pinned_apk_archive_limits_valid(102828147, 1024 * 1024 * 1024), 1);
        assert_eq!(mocktail_rust_pinned_apk_archive_limits_valid(0, 1024 * 1024 * 1024), 0);
        assert_eq!(mocktail_rust_pinned_apk_archive_limits_valid(2000 * 1024 * 1024, 1024 * 1024 * 1024), 0);
    }

    #[test]
    fn test_section107_vulkan_swapchain_policy() {
        let sup = [
            CString::new("VK_KHR_surface").unwrap(),
            CString::new("VK_KHR_get_surface_capabilities2").unwrap(),
            CString::new("VK_EXT_surface_maintenance1").unwrap(),
        ];
        let sup_ptrs: Vec<*const c_char> = sup.iter().map(|s| s.as_ptr()).collect();
        let en = [CString::new("VK_KHR_surface").unwrap()];
        let en_ptrs: Vec<*const c_char> = en.iter().map(|s| s.as_ptr()).collect();
        let mut out = [0 as c_char; 256];
        let mut out_len = 0usize;
        let rc = mocktail_rust_vulkan_select_surface_maintenance_exts(
            sup_ptrs.as_ptr(),
            sup_ptrs.len(),
            en_ptrs.as_ptr(),
            en_ptrs.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        assert_eq!(rc, 1);
        let text = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(text, "VK_KHR_get_surface_capabilities2\nVK_EXT_surface_maintenance1");

        // Missing maintenance extension -> returns 0 (cannot enable)
        let rc_none = mocktail_rust_vulkan_select_surface_maintenance_exts(
            en_ptrs.as_ptr(),
            en_ptrs.len(),
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        assert_eq!(rc_none, 0);
        assert_eq!(out_len, 0);

        // Image policy fallback & mailbox override
        assert_eq!(mocktail_rust_vulkan_swapchain_image_policy(3 /* Fifo */, VK_PRESENT_MODE_MAILBOX_KHR), 4 /* Mailbox */);
        assert_eq!(mocktail_rust_vulkan_swapchain_image_policy(5 /* Immediate */, VK_PRESENT_MODE_FIFO_KHR), 3 /* Fifo */);
        assert_eq!(mocktail_rust_vulkan_swapchain_image_policy(1 /* Vsync */, VK_PRESENT_MODE_FIFO_KHR), 1 /* Vsync */);
    }

    #[test]
    fn test_section108_texture_override() {
        let dir = std::env::temp_dir().join(format!("mocktail_rust_tex_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_c = CString::new(dir.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(mocktail_rust_texture_override_has_png(dir_c.as_ptr()), 0);
        std::fs::write(dir.join("note.txt"), b"hi").unwrap();
        assert_eq!(mocktail_rust_texture_override_has_png(dir_c.as_ptr()), 0);
        std::fs::write(dir.join("0001.png"), b"\x89PNG").unwrap();
        assert_eq!(mocktail_rust_texture_override_has_png(dir_c.as_ptr()), 1);
        let _ = std::fs::remove_dir_all(&dir);

        let h = mocktail_rust_texture_override_hash_bytes(b"abc".as_ptr(), 3);
        assert_eq!(h, 0xe71fa2190541574bu64);
        let mut name = [0 as c_char; 32];
        assert_eq!(mocktail_rust_texture_override_hash_name(h, name.as_mut_ptr(), name.len()), 0);
        let name_str = unsafe { CStr::from_ptr(name.as_ptr()) }.to_str().unwrap();
        assert_eq!(name_str, "e71fa2190541574b");

        // Nearest-neighbor 1x1 -> 2x2 integer upscale + box downsample
        let src = [10u8, 20, 30, 40];
        let mut up = [0u8; 2 * 2 * 4];
        assert_eq!(mocktail_rust_texture_override_resample_rgba(src.as_ptr(), 1, 1, 2, 2, up.as_mut_ptr()), 0);
        assert_eq!(&up[0..4], &src);
        assert_eq!(&up[12..16], &src);

        let mut down = [0u8; 4];
        assert_eq!(mocktail_rust_texture_override_resample_rgba(up.as_ptr(), 2, 2, 1, 1, down.as_mut_ptr()), 0);
        assert_eq!(down, src);
    }

    #[test]
    fn test_section109_etc1_sky_transcoder() {
        let sky = CString::new("/data/pkg/assets/android/textures/sky/day.tex").unwrap();
        let nonsky = CString::new("/data/pkg/assets/android/textures/ui/btn.tex").unwrap();
        assert_eq!(mocktail_rust_etc1_is_bundled_sky_texture(sky.as_ptr()), 1);
        assert_eq!(mocktail_rust_etc1_is_bundled_sky_texture(nonsky.as_ptr()), 0);

        // Build valid 4x4 ETC1 KTX1 file (64-byte header + 4-byte imageSize + 8-byte ETC1 block = 76 bytes)
        let mut ktx = vec![0u8; 76];
        ktx[0..12].copy_from_slice(&[0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a]);
        ktx[12..16].copy_from_slice(&0x04030201u32.to_le_bytes()); // LE
        ktx[20..24].copy_from_slice(&1u32.to_le_bytes()); // typeSize = 1
        ktx[28..32].copy_from_slice(&0x00008d64u32.to_le_bytes()); // GL_ETC1_RGB8_OES
        ktx[32..36].copy_from_slice(&0x00001907u32.to_le_bytes()); // GL_RGB
        ktx[36..40].copy_from_slice(&4u32.to_le_bytes()); // w=4
        ktx[40..44].copy_from_slice(&4u32.to_le_bytes()); // h=4
        ktx[52..56].copy_from_slice(&1u32.to_le_bytes()); // faces=1
        ktx[56..60].copy_from_slice(&1u32.to_le_bytes()); // mips=1
        ktx[64..68].copy_from_slice(&8u32.to_le_bytes()); // imageSize=8
        assert_eq!(mocktail_rust_etc1_transcode_ktx1_for_vulkan(ktx.as_mut_ptr(), ktx.len()), 1);
        let new_fmt = u32::from_le_bytes([ktx[28], ktx[29], ktx[30], ktx[31]]);
        assert_eq!(new_fmt, 0x000083f0u32); // GL_COMPRESSED_RGB_S3TC_DXT1

        let mut bc1 = [0u8; 8];
        let etc1 = [0xffu8, 0x80, 0x00, 0x02, 0, 0, 0, 0];
        assert_eq!(mocktail_rust_etc1_convert_rgb_block_to_bc1(etc1.as_ptr(), bc1.as_mut_ptr()), 0);
        let ep0 = u16::from_le_bytes([bc1[0], bc1[1]]);
        let ep1 = u16::from_le_bytes([bc1[2], bc1[3]]);
        assert!(ep0 > ep1);
    }

    #[test]
    fn test_section110_vulkan_etc2_and_copy() {
        let mut host = 0;
        let mut etc = -1;
        assert_eq!(mocktail_rust_vulkan_etc2_lookup_format(147, &mut host, &mut etc), 1);
        assert_eq!((host, etc), (37, 0));
        assert_eq!(mocktail_rust_vulkan_etc2_lookup_format(156, &mut host, &mut etc), 1);
        assert_eq!((host, etc), (78, 6));
        assert_eq!(mocktail_rust_vulkan_etc2_lookup_format(37, &mut host, &mut etc), 0);

        let masked = mocktail_rust_vulkan_etc2_emulated_features(0xffff_ffff);
        assert_eq!(masked, 0x0000_d401);

        let mut comp = 0u64;
        let mut dec = 0u64;
        assert_eq!(mocktail_rust_vulkan_etc2_upload_byte_counts(8, 4, 8, 4, 1, 2, &mut comp, &mut dec), 1);
        assert_eq!((comp, dec), (32, 256));
        assert_eq!(mocktail_rust_vulkan_etc2_upload_byte_counts(8, 4, u32::MAX, u32::MAX, 1, 1, &mut comp, &mut dec), 0);

        let zero = CString::new("0").unwrap();
        let one = CString::new("1").unwrap();
        let ten = CString::new("10").unwrap();
        assert_eq!(mocktail_rust_vulkan_etc2_support_advertised(std::ptr::null()), 1);
        assert_eq!(mocktail_rust_vulkan_etc2_support_advertised(zero.as_ptr()), 0);
        assert_eq!(mocktail_rust_vulkan_etc2_small_texture_upscale(one.as_ptr()), 1);
        assert_eq!(mocktail_rust_vulkan_etc2_small_texture_upscale(ten.as_ptr()), 8);

        let src: Vec<u8> = (0..137u8).collect();
        let mut dst = vec![0u8; 137];
        mocktail_rust_vulkan_etc2_copy_from_mapped(dst.as_mut_ptr(), src.as_ptr(), src.len());
        assert_eq!(dst, src);
    }

    #[test]
    fn test_section111_graphics_launch_policy() {
        assert_eq!(mocktail_rust_graphics_is_haswell_intel(0x0412), 1);
        assert_eq!(mocktail_rust_graphics_is_haswell_intel(0x5916), 0);

        let mut parsed = 0u32;
        let ok = CString::new("0x8086\n").unwrap();
        let bad = CString::new("0x10000").unwrap();
        assert_eq!(mocktail_rust_graphics_parse_pci_hex(ok.as_ptr(), &mut parsed), 1);
        assert_eq!(parsed, 0x8086);
        assert_eq!(mocktail_rust_graphics_parse_pci_hex(bad.as_ptr(), &mut parsed), 0);

        let mem_big = CString::new("MemTotal:       8388608 kB\n").unwrap();
        let mem_small = CString::new("MemTotal:       2097152 kB\n").unwrap();
        assert_eq!(mocktail_rust_graphics_anv_sys_mem_limit_percent(mem_big.as_ptr()), 75);
        assert_eq!(mocktail_rust_graphics_anv_sys_mem_limit_percent(mem_small.as_ptr()), 50);

        let f_i686 = CString::new("radeon_icd.i686.json").unwrap();
        let f_x64 = CString::new("radeon_icd.x86_64.json").unwrap();
        assert_eq!(mocktail_rust_graphics_is_foreign_icd_name(f_i686.as_ptr(), 0), 1);
        assert_eq!(mocktail_rust_graphics_is_foreign_icd_name(f_x64.as_ptr(), 0), 0);
        assert_eq!(mocktail_rust_graphics_is_foreign_icd_name(f_x64.as_ptr(), 1), 1);

        let icd_dir = std::env::temp_dir().join(format!("mocktail_rust_icd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&icd_dir);
        std::fs::create_dir_all(&icd_dir).unwrap();
        std::fs::write(icd_dir.join("radeon_icd.i686.json"), b"{}").unwrap();
        std::fs::write(icd_dir.join("radeon_icd.x86_64.json"), b"{}").unwrap();
        let dirs_c = CString::new(icd_dir.to_string_lossy().as_bytes()).unwrap();
        let needle_c = CString::new("radeon_icd").unwrap();
        let mut selected = [0 as c_char; 512];
        assert_eq!(mocktail_rust_graphics_select_icd_manifest(dirs_c.as_ptr(), needle_c.as_ptr(), 0, selected.as_mut_ptr(), selected.len()), 0);
        let sel_str = unsafe { CStr::from_ptr(selected.as_ptr()) }.to_str().unwrap();
        assert!(sel_str.ends_with("radeon_icd.x86_64.json"));
        let sel_c = CString::new(sel_str).unwrap();
        assert_eq!(mocktail_rust_graphics_is_radv_icd_list(sel_c.as_ptr()), 1);
        let _ = std::fs::remove_dir_all(&icd_dir);
    }

    #[test]
    fn test_section112_graphics_backend() {
        let n0 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(0)) }.to_str().unwrap();
        let n1 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(1)) }.to_str().unwrap();
        let n2 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(2)) }.to_str().unwrap();
        let n9 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(9)) }.to_str().unwrap();
        assert_eq!((n0, n1, n2, n9), ("angle-vulkan", "direct-vulkan", "system-egl", "unknown"));

        let backends = [0i32, 1, 2];
        let states = [0i32, 2, 1]; // angle=unavail, direct=ready, egl=probed
        let accels = [0i32, 2, 1]; // angle=unknown, direct=hw, egl=sw
        let d0 = CString::new("no vulkan").unwrap();
        let d1 = CString::new("vk ready").unwrap();
        let d2 = CString::new("llvmpipe").unwrap();
        let details = [d0.as_ptr(), d1.as_ptr(), d2.as_ptr()];
        let mut selected = -1;
        let mut detail = [0 as c_char; 256];
        // Request angle with fallback enabled, require_hw=1, require_runtime=1 -> falls back to direct-vulkan
        let rc = mocktail_rust_graphics_backend_select(
            0, 1, 1, 1,
            backends.as_ptr(), states.as_ptr(), accels.as_ptr(), details.as_ptr(), 3,
            &mut selected, detail.as_mut_ptr(), detail.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(selected, 1);

        // Request angle without fallback -> fails with reason
        let rc_fail = mocktail_rust_graphics_backend_select(
            0, 0, 1, 1,
            backends.as_ptr(), states.as_ptr(), accels.as_ptr(), details.as_ptr(), 3,
            &mut selected, detail.as_mut_ptr(), detail.len(),
        );
        assert_eq!(rc_fail, -1);
    }

    #[test]
    fn test_section113_surface_lifecycle_and_window() {
        let eng = mocktail_rust_surface_lifecycle_new();
        assert!(!eng.is_null());
        assert_eq!(mocktail_rust_surface_lifecycle_is_active(eng), 0);
        let mut err = [0 as c_char; 128];
        // Zero or sub-minimum (<160x120) size rejected on activate, 160x120 accepted
        assert_eq!(mocktail_rust_surface_lifecycle_activate(eng, 0x100, 159, 120, 1.0, err.as_mut_ptr(), err.len()), 2);
        // Valid activate
        assert_eq!(mocktail_rust_surface_lifecycle_activate(eng, 0x100, 160, 120, 1.0, err.as_mut_ptr(), err.len()), 0);
        assert_eq!(mocktail_rust_surface_lifecycle_is_active(eng), 1);

        // Coalesce resize events on same generation
        assert_eq!(mocktail_rust_surface_lifecycle_observe(eng, 0x100, 1300, 720, 1.0, err.as_mut_ptr(), err.len()), 0);
        assert_eq!(mocktail_rust_surface_lifecycle_observe(eng, 0x100, 1400, 800, 2.0, err.as_mut_ptr(), err.len()), 0);
        let mut ev = MocktailRustSurfaceEvent::default();
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 1);
        assert_eq!((ev.event_type, ev.surface.width, ev.surface.height), (1, 1400, 800));
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 0);

        // Recreate emits Destroyed -> Created -> Changed with generation 2
        assert_eq!(mocktail_rust_surface_lifecycle_recreate(eng, err.as_mut_ptr(), err.len()), 0);
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 1);
        assert_eq!(ev.event_type, 2);
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 1);
        assert_eq!((ev.event_type, ev.surface.generation), (0, 2));
        mocktail_rust_surface_lifecycle_free(eng);

        assert_eq!(mocktail_rust_window_apply_high_dpi_flag(0x10, 1, 0x2000), 0x2010);
        assert_eq!(mocktail_rust_window_apply_high_dpi_flag(0x2010, 0, 0x2000), 0x10);
        let wl = CString::new("wayland").unwrap();
        let x11 = CString::new("x11").unwrap();
        assert_eq!(mocktail_rust_window_direct_vulkan_requires_sync(wl.as_ptr()), 1);
        assert_eq!(mocktail_rust_window_direct_vulkan_requires_sync(x11.as_ptr()), 0);
    }

    #[test]
    fn test_section114_presence_resolver() {
        let raw = CString::new("foo=1; .ROBLOSECURITY=_|WARNING:secret_val; Path=/").unwrap();
        let mut cookie = [0 as c_char; 256];
        assert_eq!(mocktail_rust_presence_extract_cookie(raw.as_ptr(), cookie.as_mut_ptr(), cookie.len()), 0);
        let cstr = unsafe { CStr::from_ptr(cookie.as_ptr()) }.to_str().unwrap();
        assert_eq!(cstr, "_|WARNING:secret_val");

        let json_ok = CString::new(r#"{"userPresences":[{"userPresenceType":2,"placeId":1818,"gameId":"job-xyz"}]}"#).unwrap();
        let mut place = 0i64;
        let mut gid = [0 as c_char; 128];
        let mut err = [0 as c_char; 256];
        assert_eq!(mocktail_rust_presence_parse_follow_response(json_ok.as_ptr(), &mut place, gid.as_mut_ptr(), gid.len(), err.as_mut_ptr(), err.len()), 0);
        assert_eq!(place, 1818);
        assert_eq!(unsafe { CStr::from_ptr(gid.as_ptr()) }.to_str().unwrap(), "job-xyz");

        let json_offline = CString::new(r#"{"userPresences":[{"userPresenceType":0}]}"#).unwrap();
        assert_eq!(mocktail_rust_presence_parse_follow_response(json_offline.as_ptr(), &mut place, gid.as_mut_ptr(), gid.len(), err.as_mut_ptr(), err.len()), -1);
    }

    #[test]
    fn test_section115_update_state_file() {
        let dir = std::env::temp_dir().join(format!("mocktail_rust_state_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("state.json");
        let bad = dir.join("bad.json");
        std::fs::write(&good, br#"{"version":1}"#).unwrap();
        std::fs::write(&bad, b"[1,2,3]").unwrap();

        let good_c = CString::new(good.to_string_lossy().as_bytes()).unwrap();
        let bad_c = CString::new(bad.to_string_lossy().as_bytes()).unwrap();
        let mut out = [0 as c_char; 256];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_update_state_read_json_file(good_c.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        assert_eq!(len, 13);
        assert_eq!(mocktail_rust_update_state_read_json_file(bad_c.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), -1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_section116_webview_helper_policy() {
        let fbsd = CString::new("FreeBSD 14.1-RELEASE").unwrap();
        let lin = CString::new("6.8.0-generic").unwrap();
        assert_eq!(mocktail_rust_webview_should_disable_sandbox(fbsd.as_ptr(), std::ptr::null()), 1);
        assert_eq!(mocktail_rust_webview_should_disable_sandbox(lin.as_ptr(), std::ptr::null()), 0);
        assert_eq!(mocktail_rust_webview_should_disable_hw_accel(1, std::ptr::null()), 1);
        let zero = CString::new("0").unwrap();
        assert_eq!(mocktail_rust_webview_should_disable_hw_accel(1, zero.as_ptr()), 0);

        let mut ua = [0 as c_char; 256];
        let bad_ver = CString::new("2.0\nEvil").unwrap();
        assert_eq!(mocktail_rust_webview_build_user_agent(bad_ver.as_ptr(), ua.as_mut_ptr(), ua.len()), 0);
        let ua_s = unsafe { CStr::from_ptr(ua.as_ptr()) }.to_str().unwrap();
        assert!(ua_s.contains("2.725.1142"));

        let mut allowed = 0;
        let mut priv_allowed = 0;
        let mut scheme = [0 as c_char; 64];
        let mut host = [0 as c_char; 128];
        let rbx = CString::new("https://www.roblox.com/login").unwrap();
        assert_eq!(mocktail_rust_webview_evaluate_navigation_uri(rbx.as_ptr(), &mut allowed, &mut priv_allowed, scheme.as_mut_ptr(), scheme.len(), host.as_mut_ptr(), host.len()), 1);
        assert_eq!((allowed, priv_allowed), (1, 1));
        assert_eq!(mocktail_rust_webview_is_browser_login_url(rbx.as_ptr()), 1);

        let triple_slash = CString::new("https:///missing-host").unwrap();
        assert_eq!(mocktail_rust_webview_evaluate_navigation_uri(triple_slash.as_ptr(), &mut allowed, &mut priv_allowed, scheme.as_mut_ptr(), scheme.len(), host.as_mut_ptr(), host.len()), 0);
        assert_eq!((allowed, priv_allowed), (0, 0));

        let essential = CString::new("https://apis.rbxcdn.com/captcha/v1/metadata").unwrap();
        assert_eq!(mocktail_rust_webview_is_essential_resource(essential.as_ptr()), 1);

        let cmd = br#"{"moduleID":"Navigation","functionName":"navigateToFeature","callbackID":"cb\"1","params":{"params":{"feature":"CaptchaSuccess"}}}"#;
        let mut ev_type = -1;
        let mut cb = [0 as c_char; 64];
        assert_eq!(mocktail_rust_webview_parse_captcha_event(cmd.as_ptr() as *const c_char, cmd.len(), &mut ev_type, cb.as_mut_ptr(), cb.len()), 1);
        assert_eq!(ev_type, 1);
        let mut script = [0 as c_char; 512];
        let cb_len = unsafe { CStr::from_ptr(cb.as_ptr()) }.to_bytes().len();
        assert_eq!(mocktail_rust_webview_build_callback_script(cb.as_ptr(), cb_len, script.as_mut_ptr(), script.len()), 0);
        let script_s = unsafe { CStr::from_ptr(script.as_ptr()) }.to_str().unwrap();
        assert!(script_s.contains("nativeCallback(\"cb\\\"1\""));
    }

    #[test]
    fn test_section117_apkpure_provider() {
        let valid = b"2.681.812";
        assert!(mocktail_rust_apkpure_is_valid_version_name(valid.as_ptr() as *const c_char, valid.len()));
        let bad = b"../bad";
        assert!(!mocktail_rust_apkpure_is_valid_version_name(bad.as_ptr() as *const c_char, bad.len()));

        let mut meta = Vec::new();
        meta.extend_from_slice(&[0x2a, 3]);
        meta.extend_from_slice(b"812");
        meta.extend_from_slice(&[0x32, 9]);
        meta.extend_from_slice(b"2.681.812:");
        meta.extend_from_slice(b"XAPKJ\x00\x00https://user:pass@d.apkpure.com/b/APK/bad");
        meta.push(0);
        meta.extend_from_slice(b"APKJ\x00\x00https://d.apkpure.com./b/APK/com.roblox.client?versionCode=812");
        meta.push(0);

        let mut ver_buf = [0 as c_char; 64];
        let mut code = 0u64;
        let mut err_buf = [0 as c_char; 256];
        let rc = mocktail_rust_apkpure_parse_latest(
            meta.as_ptr(),
            meta.len(),
            ver_buf.as_mut_ptr(),
            ver_buf.len(),
            &mut code,
            err_buf.as_mut_ptr(),
            err_buf.len(),
        );
        assert_eq!(rc, 0);
        let ver_s = unsafe { CStr::from_ptr(ver_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(ver_s, "2.681.812");
        assert_eq!(code, 812);

        let target_ver = CString::new("2.681.812").unwrap();
        let mut urls_buf = [0 as c_char; 1024];
        let rc2 = mocktail_rust_apkpure_parse_exact_urls(
            meta.as_ptr(),
            meta.len(),
            target_ver.as_ptr(),
            812,
            urls_buf.as_mut_ptr(),
            urls_buf.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        );
        assert_eq!(rc2, 0);
        let urls_s = unsafe { CStr::from_ptr(urls_buf.as_ptr()) }.to_str().unwrap();
        assert!(!urls_s.contains("user:pass"));
        assert!(urls_s.contains("https://d.apkpure.com./b/APK/com.roblox.client?versionCode=812"));

        let tmp = std::env::temp_dir().join("mocktail_apkpure_zip_test.bin");
        std::fs::write(&tmp, b"PK\x03\x04rest").unwrap();
        let tmp_c = CString::new(tmp.to_string_lossy().as_bytes()).unwrap();
        assert!(mocktail_rust_apkpure_has_zip_magic(tmp_c.as_ptr()));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_section118_roblox_text_font_resolver() {
        let mut buf = [0 as c_char; 256];
        let mut scale = 0.0f32;
        let mut exact = false;
        let rc = mocktail_rust_resolve_roblox_text_font(
            0,
            std::ptr::null(),
            0,
            buf.as_mut_ptr(),
            buf.len(),
            &mut scale,
            &mut exact,
        );
        assert!(rc >= 0);
    }

    #[test]
    fn test_section119_runtime_config() {
        let host = b"127.0.0.1";
        let port = b"8080";
        let scheme = b"http";
        let mut out_scheme = [0 as c_char; 32];
        let mut out_port = 0i32;
        assert!(mocktail_rust_network_proxy_parse(
            host.as_ptr() as *const c_char, host.len(),
            port.as_ptr() as *const c_char, port.len(),
            scheme.as_ptr() as *const c_char, scheme.len(),
            std::ptr::null(), 0,
            std::ptr::null(), 0,
            out_scheme.as_mut_ptr(), out_scheme.len(),
            &mut out_port,
        ));
        assert_eq!(out_port, 8080);

        let mut url_buf = [0 as c_char; 256];
        let url_len = mocktail_rust_network_proxy_build_url(
            scheme.as_ptr() as *const c_char, scheme.len(),
            host.as_ptr() as *const c_char, host.len(),
            out_port,
            std::ptr::null(), 0,
            std::ptr::null(), 0,
            false,
            url_buf.as_mut_ptr(), url_buf.len(),
        );
        assert!(url_len > 0);

        let vulkan = b"vulkan";
        assert_ne!(mocktail_rust_runtime_config_parse_graphics_backend(vulkan.as_ptr() as *const c_char, vulkan.len()), -1);

        let mut valid = false;
        let yes = b"true";
        assert!(mocktail_rust_runtime_config_parse_bool(yes.as_ptr() as *const c_char, yes.len(), false, &mut valid));
        assert!(valid);

        let num = b"42";
        assert_eq!(mocktail_rust_runtime_config_parse_positive_int(num.as_ptr() as *const c_char, num.len(), 10), 42);

        let app_id = b"123456789012345678";
        assert!(mocktail_rust_runtime_config_is_discord_app_id(app_id.as_ptr() as *const c_char, app_id.len()));
        let short_id = b"1234567890";
        assert!(!mocktail_rust_runtime_config_is_discord_app_id(short_id.as_ptr() as *const c_char, short_id.len()));
        let text = b"Playing Roblox";
        assert!(mocktail_rust_runtime_config_is_discord_text(text.as_ptr() as *const c_char, text.len(), 128));
    }

    #[test]
    fn test_section120_runtime_config_bootstrap() {
        let mut yaml_len = 0usize;
        let ptr = mocktail_rust_runtime_config_default_yaml_ptr(&mut yaml_len);
        assert!(!ptr.is_null() && yaml_len > 0);

        let tmp = std::env::temp_dir().join(format!("mocktail_cfg_boot_{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let tmp_c = CString::new(tmp.to_string_lossy().as_bytes()).unwrap();
        let mut created = false;
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_runtime_config_ensure_file(tmp_c.as_ptr(), &mut created, err.as_mut_ptr(), err.len());
        assert_eq!(rc, 0);
        assert!(created);
        assert!(tmp.exists());
        let rc2 = mocktail_rust_runtime_config_ensure_file(tmp_c.as_ptr(), &mut created, err.as_mut_ptr(), err.len());
        assert_eq!(rc2, 0);
        assert!(!created);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_section121_host_allocator_bridge() {
        let p = mocktail_rust_host_allocate(64);
        assert!(!p.is_null());
        assert!(mocktail_rust_host_usable_size(p) >= 64);
        let p2 = mocktail_rust_host_reallocate(p, 128);
        assert!(!p2.is_null());
        assert!(mocktail_rust_host_usable_size(p2) >= 128);
        mocktail_rust_host_free(p2);

        let pa = mocktail_rust_host_aligned_allocate(256, 64);
        assert!(!pa.is_null());
        assert_eq!((pa as usize) % 64, 0);
        mocktail_rust_host_free(pa);
    }

    #[test]
    fn test_section122_host_abi_profile_and_experiment() {
        let ranges = [
            MocktailRustConstructorRange { begin: 1, end_exclusive: 4 },
            MocktailRustConstructorRange { begin: 6, end_exclusive: 8 },
        ];
        assert!(mocktail_rust_host_abi_has_valid_ranges(ranges.as_ptr(), ranges.len(), 8, 10));
        assert!(mocktail_rust_host_abi_allows_constructor(ranges.as_ptr(), ranges.len(), 8, 10, 2));
        assert!(!mocktail_rust_host_abi_allows_constructor(ranges.as_ptr(), ranges.len(), 8, 10, 5));
        assert_eq!(mocktail_rust_host_abi_range_begin(ranges.as_ptr(), ranges.len(), 8, 10), 1);
        assert_eq!(mocktail_rust_host_abi_range_end_exclusive(ranges.as_ptr(), ranges.len(), 8, 10), 8);
        assert!(mocktail_rust_host_abi_should_init_mimalloc_thread(ranges.as_ptr(), ranges.len(), 8, 10, 3, 3));
        assert!(!mocktail_rust_host_abi_should_init_mimalloc_thread(ranges.as_ptr(), ranges.len(), 8, 10, 3, 4));
        assert_eq!(mocktail_rust_host_abi_resolve_allocator_strategy(1, true, true), 0);
        assert_eq!(mocktail_rust_host_abi_resolve_allocator_strategy(0, true, false), 1);
        assert_eq!(mocktail_rust_host_abi_resolve_allocator_strategy(1, false, true), 1);
    }

    #[test]
    fn test_section123_window_game_surface_bridge() {
        let ev = MocktailRustSurfaceEvent {
            event_type: 0,
            surface: MocktailRustSurfaceSnapshot {
                generation: 1,
                native_window: 0x1234,
                width: 1280,
                height: 720,
                available: 1,
                dpi_scale: 1.0,
            },
        };
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_game_surface_bridge_validate_event(&ev, err.as_mut_ptr(), err.len());
        assert_eq!(rc, 0);
        let mut snap = MocktailRustGameSurfaceBridgeSnapshot {
            accepted_events: 0,
            duplicate_events: 0,
            last_generation: 0,
            last_event_type: -1,
            failed: false,
        };
        mocktail_rust_game_surface_bridge_record_event(&ev, true, &mut snap);
        assert_eq!(snap.accepted_events, 1);
        assert_eq!(snap.last_generation, 1);
        assert!(!snap.failed);
    }

    #[test]
    fn test_graphics_vulkan_bug_fixes() {
        // 1. Overflow guard in mocktail_rust_decode_etc_image_block_rows:
        // ((u32::MAX as u64 + 3) / 4)^2 * 16 would not wrap on u64 alone only for some sizes,
        // whereas (width=0xFFFF_FFFF, height=0xFFFF_FFFF) width*height*16 wraps or exceeds tiny buffers cleanly.
        let mut src_block = [0u8; 16];
        let mut dst_pixel = [0u8; 16];
        assert_eq!(
            mocktail_rust_decode_etc_image_block_rows(
                MocktailRustEtcFormat::Etc2Rgb8,
                src_block.as_ptr(),
                src_block.len(),
                u32::MAX,
                u32::MAX,
                0,
                1,
                dst_pixel.as_mut_ptr(),
                dst_pixel.len(),
            ),
            0
        );
        // Also test 2^31 x 2^31: width * height * 4 = 2^64 (wraps u64 to 0 without checked_mul!).
        assert_eq!(
            mocktail_rust_decode_etc_image_block_rows(
                MocktailRustEtcFormat::Etc2Rgb8,
                src_block.as_ptr(),
                src_block.len(),
                1u32 << 31,
                1u32 << 31,
                0,
                1,
                dst_pixel.as_mut_ptr(),
                dst_pixel.len(),
            ),
            0
        );
        let _ = &mut src_block;

        // 2. Empty host_modes_ptr with host_count == 0 in mocktail_rust_present_mode_filter
        let mut out_mode = 99u32;
        let mut out_count = 99usize;
        let pm_rc = mocktail_rust_present_mode_filter(
            MocktailRustPresentModePolicy::Vsync as c_int,
            std::ptr::null(),
            0,
            &mut out_mode,
            1,
            &mut out_count,
        );
        assert_eq!(pm_rc, 0);
        assert_eq!(out_count, 0);
        assert_eq!(
            mocktail_rust_present_mode_filter(
                MocktailRustPresentModePolicy::Vsync as c_int,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut out_count,
            ),
            0
        );
        assert_eq!(out_count, 0);

        // 3. Null pointer guards in mocktail_rust_translate_android_vulkan_instance_extensions
        let mut ext_count = 0usize;
        let mut err = [0 as c_char; 128];
        assert_eq!(
            mocktail_rust_translate_android_vulkan_instance_extensions(
                std::ptr::null(),
                1,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut ext_count,
                err.as_mut_ptr(),
                err.len(),
            ),
            -1
        );
        let android_surface = CString::new("VK_KHR_android_surface").unwrap();
        let android_exts = [android_surface.as_ptr()];
        assert_eq!(
            mocktail_rust_translate_android_vulkan_instance_extensions(
                android_exts.as_ptr(),
                android_exts.len(),
                std::ptr::null(),
                1,
                std::ptr::null_mut(),
                0,
                &mut ext_count,
                err.as_mut_ptr(),
                err.len(),
            ),
            -1
        );

        // 4. Atomic validation before in-place transcode in mocktail_rust_etc1_transcode_ktx1_for_vulkan
        let mut ktx = vec![0u8; 64 + 4 + 32 + 4];
        ktx[0..12].copy_from_slice(&[0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a]);
        ktx[12..16].copy_from_slice(&0x0403_0201u32.to_le_bytes());
        ktx[20..24].copy_from_slice(&1u32.to_le_bytes());
        ktx[28..32].copy_from_slice(&0x0000_8d64u32.to_le_bytes());
        ktx[32..36].copy_from_slice(&0x0000_1907u32.to_le_bytes());
        ktx[36..40].copy_from_slice(&8u32.to_le_bytes()); // width = 8
        ktx[40..44].copy_from_slice(&8u32.to_le_bytes()); // height = 8
        ktx[52..56].copy_from_slice(&1u32.to_le_bytes()); // faces = 1
        ktx[56..60].copy_from_slice(&2u32.to_le_bytes()); // mip_levels = 2
        ktx[64..68].copy_from_slice(&32u32.to_le_bytes()); // mip 0 size = 32
        for (i, b) in ktx[68..100].iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5a;
        }
        // mip 1 size claims 8 bytes, but no payload follows -> must fail and leave mip 0 untouched
        ktx[100..104].copy_from_slice(&8u32.to_le_bytes());
        let before = ktx.clone();
        assert_eq!(mocktail_rust_etc1_transcode_ktx1_for_vulkan(ktx.as_mut_ptr(), ktx.len()), 0);
        assert_eq!(ktx, before);
    }

}
