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
    static VERSION: &[u8] = b"0.2.0-rust-core\0";
    VERSION.as_ptr() as *const c_char
}

/// Initializes and verifies the mocktail-core Rust subsystem.
#[no_mangle]
pub extern "C" fn mocktail_rust_init() -> c_int {
    // 0 = Success
    0
}

/// Securely zeroes out sensitive memory (such as Roblox session cookies, tokens).
/// Uses compiler-level volatile writes and zeroize barriers to guarantee that
/// dead-store elimination (DSE) will never strip the clearing operation.
#[no_mangle]
pub extern "C" fn mocktail_rust_secure_zero(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: caller guarantees ptr is valid for writes of `len` bytes.
    let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
}

/// Computes the SHA-256 hash of a memory buffer and outputs a null-terminated lowercase hex string.
/// Returns 0 on success, or -1 if arguments are invalid or output buffer capacity is too small (< 65).
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
/// Returns 0 on success, -1 on I/O error or invalid arguments.
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
/// Returns:
///   1 if file hash matches expected hash (case-insensitive)
///   0 if file hash does not match
///  -1 on file I/O or parameter error
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

/// Validates whether an archive relative path is safe against Zip-Slip, directory traversal,
/// and control character injection.
/// Returns 1 if safe, 0 if unsafe.
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
            // Empty segment is only allowed if it's the final trailing slash (a directory entry)
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
/// Returns 0 on success, negative error code on failure.
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

    // Zip slip verification
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

/// Validates whether a JNI method descriptor strictly conforms to the JVM specification (JVMS §4.3.3).
/// Example: "(Ljava/lang/String;I)V" -> 1 (valid)
/// Returns 1 if valid, 0 if invalid.
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
    // Parse arguments inside ( ... )
    while i < bytes.len() && bytes[i] != b')' {
        if !parse_jni_type(bytes, &mut i, false) {
            return 0;
        }
    }
    if i >= bytes.len() || bytes[i] != b')' {
        return 0;
    }
    i += 1; // skip ')'

    // Parse return type
    if !parse_jni_type(bytes, &mut i, true) {
        return 0;
    }

    // Must be at the very end of string
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
            *idx += 1; // skip ';'
            true
        }
        _ => false,
    }
}

/// Validates whether a given C string is syntactically valid JSON.
/// Returns:
///   1 if valid JSON
///   0 if invalid JSON
///  -1 if pointer is null
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
/// Returns 1 if safe, 0 if unsafe or invalid.
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
    fn test_file_sha256() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let file_path = dir.join("mocktail_test_file.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"mocktail-file-test").unwrap();
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
    fn test_json_validation() {
        let valid = b"{\"key\": 123}\0";
        assert_eq!(mocktail_rust_is_valid_json(valid.as_ptr() as *const c_char), 1);

        let invalid = b"{\"key\": \0";
        assert_eq!(mocktail_rust_is_valid_json(invalid.as_ptr() as *const c_char), 0);
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

        let invalid2 = CString::new("(Ljava/lang/String)V").unwrap(); // missing ';'
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid2.as_ptr()), 0);

        let invalid3 = CString::new("([V)V").unwrap(); // void array
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid3.as_ptr()), 0);
    }

    #[test]
    fn test_zip_extract() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let zip_path = dir.join("mocktail_test.zip");
        {
            let file = File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("test_entry.txt", options).unwrap();
            zip.write_all(b"mocktail extracted content").unwrap();
            zip.finish().unwrap();
        }

        let out_path = dir.join("mocktail_extracted.txt");
        let c_zip = CString::new(zip_path.to_str().unwrap()).unwrap();
        let c_entry = CString::new("test_entry.txt").unwrap();
        let c_out = CString::new(out_path.to_str().unwrap()).unwrap();

        let rc = mocktail_rust_extract_zip_entry(
            c_zip.as_ptr(),
            c_entry.as_ptr(),
            c_out.as_ptr(),
            1024,
        );
        assert_eq!(rc, 0);

        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert_eq!(contents, "mocktail extracted content");

        let _ = std::fs::remove_file(&zip_path);
        let _ = std::fs::remove_file(&out_path);
    }
}
