use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use std::slice;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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
                if let Some(num_str) = parts.first() {
                    if let Ok(kib) = num_str.parse::<u64>() {
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
        if !out_error.is_null() && error_cap > 0 {
            let len = std::cmp::min(msg.len(), error_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_error, len);
                *out_error.add(len) = 0;
            }
        }
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
        if s.len() > suffix.len() && s.ends_with(suffix) {
            let prefix_len = s.len() - suffix.len();
            if s.as_bytes()[prefix_len - 1] == b'.' {
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
        if !out_error.is_null() && error_cap > 0 {
            let len = std::cmp::min(msg.len(), error_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_error, len);
                *out_error.add(len) = 0;
            }
        }
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
        if !out_error.is_null() && error_cap > 0 {
            let len = std::cmp::min(msg.len(), error_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_error, len);
                *out_error.add(len) = 0;
            }
        }
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
    map: &mut std::collections::HashMap<String, String>,
) -> Result<(), String> {
    match node {
        serde_yaml::Value::Mapping(m) => {
            if depth > 2 {
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
                        flatten_yaml_node(&new_path, v, depth + 1, map)?;
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
        _ => Err("root must be a mapping".to_string()),
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
        if !out_error.is_null() && error_cap > 0 {
            let len = std::cmp::min(msg.len(), error_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_error, len);
                *out_error.add(len) = 0;
            }
        }
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
            set_error(&format!("YAML syntax error: {}", e));
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
                if let Err(e) = flatten_yaml_node("device", v, 1, &mut values) {
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
            if let Err(e) = flatten_yaml_node(key_str, v, 1, &mut values) {
                set_error(&e);
                return -8;
            }
        } else if key_str == "integrations" {
            if let Err(e) = flatten_yaml_node("integrations", v, 1, &mut values) {
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
                let parsed = match val.as_str() {
                    "true" => "on",
                    "false" => "off",
                    _ => {
                        set_error(&format!("{} must be true or false", yaml_key));
                        return -16;
                    }
                };
                env.insert(env_key.to_string(), serde_json::json!(parsed));
            }
        }
    }

    if let Some(h) = values.get("runtime.headless") {
        match h.as_str() {
            "true" => { env.insert("MOCKTAIL_HEADLESS".to_string(), serde_json::json!("1")); }
            "false" => { env.insert("MOCKTAIL_HEADLESS".to_string(), serde_json::json!("0")); }
            _ => {
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

    if let Some(theme) = values.get("appearance.theme") {
        if !["roblox", "system", "light", "dark"].contains(&theme.as_str()) {
            set_error("appearance.theme must be roblox, system, light, or dark");
            return -19;
        }
        env.insert("MOCKTAIL_THEME".to_string(), serde_json::json!(theme));
    }

    if let Some(backend) = values.get("graphics.backend") {
        if !["direct-vulkan", "opengl", "system", "angle-vulkan"].contains(&backend.as_str()) {
            set_error(&format!("graphics.backend is not supported: {}", backend));
            return -20;
        }
        env.insert("MOCKTAIL_GRAPHICS_BACKEND".to_string(), serde_json::json!(backend));
    }

    if let Some(fps) = values.get("graphics.frame_rate_limit") {
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

    if let Some(mem) = values.get("performance.memory_limit_mb") {
        let n: u64 = match mem.parse() {
            Ok(v) if v > 0 => v,
            _ => {
                set_error("performance.memory_limit_mb must be a positive integer");
                return -23;
            }
        };
        env.insert("MOCKTAIL_MEMORY_LIMIT_MB".to_string(), serde_json::json!(n.to_string()));
    }

    if let Some(rpc) = values.get("integrations.discord_rpc.enabled") {
        match rpc.as_str() {
            "true" => { env.insert("MOCKTAIL_DISCORD_RPC_ENABLED".to_string(), serde_json::json!("1")); }
            "false" => { env.insert("MOCKTAIL_DISCORD_RPC_ENABLED".to_string(), serde_json::json!("0")); }
            _ => {
                set_error("integrations.discord_rpc.enabled must be true or false");
                return -24;
            }
        }
    }

    if let Some(fl) = values.get("integrations.fleasion.enabled") {
        match fl.as_str() {
            "true" => { env.insert("MOCKTAIL_FLEASION_ENABLED".to_string(), serde_json::json!("1")); }
            "false" => { env.insert("MOCKTAIL_FLEASION_ENABLED".to_string(), serde_json::json!("0")); }
            _ => {
                set_error("integrations.fleasion.enabled must be true or false");
                return -25;
            }
        }
    }

    let dumped = serde_json::Value::Object(env).to_string();
    if dumped.len() + 1 > out_cap {
        set_error("output buffer too small");
        return -26;
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
        if !out_error.is_null() && error_cap > 0 {
            let len = std::cmp::min(msg.len(), error_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_error, len);
                *out_error.add(len) = 0;
            }
        }
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
        if !out_error.is_null() && error_cap > 0 {
            let len = std::cmp::min(msg.len(), error_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_error, len);
                *out_error.add(len) = 0;
            }
        }
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

    if (blocks_wide * blocks_high * (block_bytes as u64)) > (source_bytes as u64) {
        return 0;
    }
    if ((width as u64) * (height as u64) * (texel_bytes as u64)) > (destination_bytes as u64) {
        return 0;
    }
    if (first_block_row as u64) + (block_row_count as u64) > blocks_high {
        return 0;
    }

    let src_slice = unsafe { slice::from_raw_parts(source, source_bytes) };
    let dst_slice = unsafe { slice::from_raw_parts_mut(destination, destination_bytes) };

    let mut rgba = [0u8; 64];
    let end_block_row = first_block_row + block_row_count;

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
                if by * 4 + y >= height {
                    continue;
                }
                for x in 0..4u32 {
                    if bx * 4 + x >= width {
                        continue;
                    }
                    let texel = (x * 4 + y) as usize;
                    let out_offset = (((by * 4 + y) * width + bx * 4 + x) as usize) * texel_bytes;
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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

    let required_files = [
        "libroblox.so",
        "sober_apk/base.apk",
        "sober_apk/split_config.x86_64.apk",
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
    let split_apk_sha256 = sha_obj
        .get("split_config_x86_64")
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
    if let Err(e) = check_file_sha("sober_apk/split_config.x86_64.apk", &info.split_apk_sha256) {
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
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
                        if let Some(host) = parsed.host_str() {
                            let trusted = allowed_hosts.iter().any(|&h| host == h || host.ends_with(&format!(".{}", h)));
                            if trusted {
                                downloads.push(url_str.to_string());
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
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
    };
    if metadata.is_null() || meta_len == 0 || out_version_name.is_null() || out_version_code.is_null() {
        set_err("invalid arguments");
        return -1;
    }
    let data = unsafe { std::slice::from_raw_parts(metadata, meta_len) };
    let markers = apkpure_version_markers(data);
    if markers.is_empty() {
        set_err("APKPure metadata contains no version identity");
        return -2;
    }
    let marker = &markers[0];
    let prefix_begin = if marker.begin > 128 { marker.begin - 128 } else { 0 };

    let mut position = marker.begin;
    while position > prefix_begin {
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
        let mut code: u64 = 0;
        let mut valid = true;
        for i in code_begin..name_tag {
            let c = data[i];
            if !c.is_ascii_digit() || code > 999999999999999999 {
                valid = false;
                break;
            }
            code = code * 10 + (c - b'0') as u64;
        }
        if valid && code > 0 {
            if marker.value.len() >= ver_cap {
                set_err("version name buffer too small");
                return -3;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(marker.value.as_ptr() as *const c_char, out_version_name, marker.value.len());
                *out_version_name.add(marker.value.len()) = 0;
                *out_version_code = code;
            }
            return 0;
        }
    }
    set_err("APKPure metadata contains no version code");
    -4
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_parse_exact_urls(
    metadata: *const u8,
    meta_len: usize,
    version: *const c_char,
    out_urls_json: *mut c_char,
    json_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let set_err = |msg: &str| {
        if !out_err.is_null() && err_cap > 0 {
            let len = std::cmp::min(msg.len(), err_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_err, len);
                *out_err.add(len) = 0;
            }
        }
    };
    if metadata.is_null() || meta_len == 0 || version.is_null() || out_urls_json.is_null() {
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
    let data = unsafe { std::slice::from_raw_parts(metadata, meta_len) };
    let markers = apkpure_version_markers(data);
    let mut results = Vec::new();
    for i in 0..markers.len() {
        if markers[i].value != ver_target {
            continue;
        }
        let record_end = if i + 1 < markers.len() { markers[i + 1].begin } else { data.len() };
        let record_slice = &data[markers[i].colon + 1..record_end];
        let downloads = apkpure_downloads_in_record(record_slice);
        for d in downloads {
            if !results.contains(&d) {
                results.push(d);
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
"#;
        let mut out_env = [0 as c_char; 1024];
        let mut out_err = [0 as c_char; 256];
        let rc = mocktail_rust_parse_runtime_config_yaml(
            yaml.as_ptr(),
            yaml.len(),
            out_env.as_mut_ptr(),
            1024,
            out_err.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        let env_str = unsafe { CStr::from_ptr(out_env.as_ptr()) }.to_str().unwrap();
        assert!(env_str.contains("\"MOCKTAIL_GRAPHICS_BACKEND\":\"direct-vulkan\""));
        assert!(env_str.contains("\"MOCKTAIL_VSYNC\":\"on\""));
        assert!(env_str.contains("\"MOCKTAIL_MEMORY_LIMIT_MB\":\"2048\""));
        assert!(env_str.contains("\"MOCKTAIL_HEADLESS\":\"0\""));
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
}
