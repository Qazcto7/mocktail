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
}
