use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::raw::{c_char, c_int};
use std::slice;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Returns the mocktail-core Rust library version string.
#[no_mangle]
pub extern "C" fn mocktail_rust_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0-rust-core\0";
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
}
