#ifndef MOCKTAIL_RUST_H_
#define MOCKTAIL_RUST_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the mocktail-core Rust library version string.
 */
const char* mocktail_rust_version(void);

/**
 * Initializes and verifies the mocktail-core Rust subsystem.
 * Returns 0 on success.
 */
int mocktail_rust_init(void);

/**
 * Securely zeroes out memory using Rust's zeroize and volatile barriers.
 * Guarantees that compiler dead-store elimination will not remove the zeroing.
 */
void mocktail_rust_secure_zero(void* ptr, size_t len);

/**
 * Computes SHA-256 hash of a memory buffer.
 * out_hex must have capacity of at least 65 bytes.
 * Returns 0 on success, -1 on error.
 */
int mocktail_rust_sha256(const void* data, size_t len, char* out_hex, size_t out_cap);

/**
 * Computes SHA-256 hash of a file using buffered streaming I/O in Rust.
 * out_hex must have capacity of at least 65 bytes.
 * Returns 0 on success, -1 on I/O error or failure.
 */
int mocktail_rust_sha256_file(const char* path, char* out_hex, size_t out_cap);

/**
 * Verifies if a file matches an expected SHA-256 hexadecimal hash.
 * Returns:
 *   1 if matches (case-insensitive)
 *   0 if does not match
 *  -1 on error
 */
int mocktail_rust_verify_file_sha256(const char* path, const char* expected_hex);

/**
 * Validates whether a given C string is syntactically valid JSON.
 * Returns 1 if valid, 0 if invalid, -1 if null.
 */
int mocktail_rust_is_valid_json(const char* json_str);

/**
 * Validates whether a URL has a safe HTTPS scheme and valid characters.
 * Returns 1 if safe, 0 otherwise.
 */
int mocktail_rust_is_safe_url(const char* url);

/**
 * Validates whether an archive relative path is safe against Zip-Slip and path traversal.
 * Returns 1 if safe, 0 if unsafe.
 */
int mocktail_rust_is_safe_archive_path(const char* path);

/**
 * Safely extracts an individual entry from a ZIP / APK archive with Zip-Slip protection
 * and atomic replacement.
 * Returns 0 on success, negative error code on failure.
 */
int mocktail_rust_extract_zip_entry(
    const char* archive_path,
    const char* entry_name,
    const char* dest_path,
    size_t max_bytes);

/**
 * Validates whether a JNI method descriptor strictly conforms to JVMS §4.3.3.
 * Returns 1 if valid, 0 if invalid.
 */
int mocktail_rust_is_valid_jni_signature(const char* sig);

#ifdef __cplusplus
}
#endif

#endif  // MOCKTAIL_RUST_H_
