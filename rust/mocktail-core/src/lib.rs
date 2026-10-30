use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::os::raw::{c_char, c_int};
use std::path::Path;
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
}
