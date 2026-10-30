#ifndef MOCKTAIL_RUST_H_
#define MOCKTAIL_RUST_H_

#include <stddef.h>
#include <stdint.h>

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

// ============================================================================
// 1. Memory Security & Hashing
// ============================================================================

/**
 * Securely zeroes out memory using Rust's zeroize and volatile barriers.
 * Guarantees that compiler dead-store elimination will not remove the zeroing.
 */
void mocktail_rust_secure_zero(void* ptr, size_t len);

/**
 * Computes SHA-256 hash of a memory buffer.
 * out_hex must have capacity of at least 65 bytes.
 */
int mocktail_rust_sha256(const void* data, size_t len, char* out_hex, size_t out_cap);

/**
 * Computes SHA-256 hash of a file using buffered streaming I/O in Rust.
 * out_hex must have capacity of at least 65 bytes.
 */
int mocktail_rust_sha256_file(const char* path, char* out_hex, size_t out_cap);

/**
 * Verifies if a file matches an expected SHA-256 hexadecimal hash.
 */
int mocktail_rust_verify_file_sha256(const char* path, const char* expected_hex);

// ============================================================================
// 2. APK & Archive Safety
// ============================================================================

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
 * Verifies whether the provided 16-byte slice matches "APK Sig Block 42".
 * Returns 1 if match, 0 if not.
 */
int mocktail_rust_verify_apk_signing_magic(const uint8_t* magic, size_t len);

// ============================================================================
// 3. Android Binary XML (AndroidManifest.xml)
// ============================================================================

typedef struct {
    char package_name[256];
    char version_name[256];
    char split_name[256];
    uint64_t version_code;
    char error[256];
} MocktailRustManifestResult;

/**
 * Safely parses Android Binary XML (AndroidManifest.xml) and extracts identity attributes.
 * Returns 1 on success, 0 on parsed with error in result, -1 on invalid arguments.
 */
int mocktail_rust_parse_android_manifest(
    const uint8_t* data,
    size_t len,
    MocktailRustManifestResult* out);

// ============================================================================
// 4. Text & URI Parsing
// ============================================================================

/**
 * Validates whether a byte buffer is completely valid UTF-8.
 * Returns 1 if valid, 0 if invalid.
 */
int mocktail_rust_is_valid_utf8(const uint8_t* data, size_t len);

/**
 * Checks whether a byte buffer contains ASCII control characters (< 0x20 or 0x7f).
 * Returns 1 if control bytes present, 0 if clean.
 */
int mocktail_rust_contains_control_bytes(const uint8_t* data, size_t len);

/**
 * Safely decodes a percent-encoded string with optional '+' to space conversion.
 * Returns 0 on success, negative error code on failure.
 */
int mocktail_rust_percent_decode(
    const char* in_str,
    int plus_as_space,
    char* out_buf,
    size_t out_cap);

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

// ============================================================================
// 5. System Memory & Process Memory Monitoring
// ============================================================================

/**
 * Parses VmRSS and VmSwap in bytes from a /proc/self/status buffer.
 * Returns 1 if VmRSS was parsed, 0 on failure.
 */
int mocktail_rust_parse_status_memory(
    const char* status_str,
    uint64_t* out_rss,
    uint64_t* out_swap);

/**
 * Reads /proc/self/status directly and parses RSS and Swap memory safely.
 * Returns 1 on success, 0 on failure.
 */
int mocktail_rust_read_self_memory(uint64_t* out_rss, uint64_t* out_swap);

// ============================================================================
// 6. Discord RPC Framing
// ============================================================================

/**
 * Encodes a Discord IPC frame: 4 bytes opcode (LE) + 4 bytes payload length (LE) + payload JSON.
 * Returns 0 on success, negative error code on failure.
 */
int mocktail_rust_build_discord_frame(
    uint32_t opcode,
    const char* payload_json,
    uint8_t* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 7. JNI Method Signature Validator
// ============================================================================

/**
 * Validates whether a JNI method descriptor strictly conforms to JVMS §4.3.3.
 * Returns 1 if valid, 0 if invalid.
 */
int mocktail_rust_is_valid_jni_signature(const char* sig);

#ifdef __cplusplus
}
#endif

#endif  // MOCKTAIL_RUST_H_
