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

// ============================================================================
// 8. JNI Modified UTF-8 (MUTF-8) Engine
// ============================================================================

int mocktail_rust_mutf8_to_utf16(
    const uint8_t* mutf8_ptr,
    size_t mutf8_len,
    uint16_t* out_utf16,
    size_t out_cap,
    size_t* out_len);

int mocktail_rust_utf16_to_mutf8(
    const uint16_t* utf16_ptr,
    size_t utf16_len,
    uint8_t* out_mutf8,
    size_t out_cap,
    size_t* out_len);

int mocktail_rust_mutf8_to_utf8(
    const uint8_t* mutf8_ptr,
    size_t mutf8_len,
    uint8_t* out_utf8,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 9. Roblox Cookie & Token Parser
// ============================================================================

int mocktail_rust_is_valid_cookie_octet(uint8_t byte);

int mocktail_rust_parse_roblox_cookie(
    const char* raw_input,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 10. Roblox MessageBus JSON & Permissions Bridge
// ============================================================================

int mocktail_rust_validate_json_depth(const char* json_str, size_t max_depth);

int mocktail_rust_check_permission_request(
    const char* json_str,
    int microphone_enabled,
    int* out_has_missing,
    char* out_missing_json,
    size_t out_cap);

// ============================================================================
// 11. ELF Header & GNU Build-ID Safe Parser
// ============================================================================

int mocktail_rust_verify_elf_architecture(
    const uint8_t* elf_bytes,
    size_t elf_len,
    uint16_t expected_machine);

int mocktail_rust_parse_elf_build_id(
    const uint8_t* elf_bytes,
    size_t elf_len,
    char* out_hex,
    size_t out_cap);

// ============================================================================
// 12. Linux ⇄ Android Keycode & Input Translation Engine
// ============================================================================

typedef struct MocktailRustKeyMapping {
    int32_t scan_code;
    int32_t key_code;
} MocktailRustKeyMapping;

int mocktail_rust_map_sdl_key_to_android(
    uint32_t sdl_scancode,
    uint32_t sdl_key,
    MocktailRustKeyMapping* out_mapping);

int32_t mocktail_rust_map_sdl_mouse_button(uint8_t sdl_button);

// ============================================================================
// 15. System Proxy & URI Resolver
// ============================================================================

int mocktail_rust_parse_proxy_uri(
    const char* candidate,
    char* out_scheme,
    size_t scheme_cap,
    char* out_host,
    size_t host_cap,
    uint16_t* out_port,
    int* out_is_direct,
    int* out_has_auth);

// ============================================================================
// 16. Single Instance Lock & Instance Key
// ============================================================================

int mocktail_rust_compute_instance_key(
    const char* exe_path,
    char* out_key,
    size_t out_cap);

int mocktail_rust_is_positive_decimal(const char* val);

// ============================================================================
// 17. Compatibility Catalog & Approval Manifest
// ============================================================================

typedef struct MocktailRustPayloadProfile {
    char version_name[64];
    uint64_t version_code;
    char elf_build_id[41];
} MocktailRustPayloadProfile;

int mocktail_rust_parse_compatibility_catalog(
    const uint8_t* json_bytes,
    size_t json_len,
    const char* guest_abi,
    MocktailRustPayloadProfile* out_profiles,
    size_t out_cap,
    size_t* out_count,
    char* out_error,
    size_t error_cap);

// ============================================================================
// 18. Crash Report Policy & FFlags Injection
// ============================================================================

int mocktail_rust_merge_crash_report_settings(
    const char* base_json,
    int fast_flags_only,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 19. Device Profile & Hardware Presets
// ============================================================================

int mocktail_rust_canonical_device_profile_name(
    const char* name,
    char* out_buf,
    size_t out_cap);

int mocktail_rust_is_valid_device_profile_value(
    const char* value,
    size_t maximum);

int mocktail_rust_build_device_profile_cache_key(
    const char* name,
    const char* platform,
    const char* display,
    const char* manufacturer,
    const char* model,
    const char* brand,
    const char* code,
    const char* sku,
    const char* soc,
    char* out_key,
    size_t out_cap);

// ============================================================================
// 20. Bionic DNS & Crash Host Blocker
// ============================================================================

int mocktail_rust_is_blocked_crash_host(const char* host);

int mocktail_rust_bionic_eai_error(int posix_error);

// ============================================================================
// 21. Roblox Launch URI & Deep Links
// ============================================================================

int mocktail_rust_parse_roblox_launch_uri(
    const char* uri,
    int64_t override_place_id,
    const char* override_game_instance,
    char* out_json,
    size_t out_cap,
    char* out_error,
    size_t error_cap,
    int64_t* out_follow_user_id);

int mocktail_rust_parse_webview_launch_game(
    const char* command_json,
    int64_t override_place_id,
    const char* override_game_instance,
    char* out_json,
    size_t out_cap,
    char* out_error,
    size_t error_cap,
    int64_t* out_follow_user_id);

// ============================================================================
// 22. YAML Runtime Configuration Parser
// ============================================================================

int mocktail_rust_parse_runtime_config_yaml(
    const uint8_t* yaml_bytes,
    size_t yaml_len,
    char* out_env_json,
    size_t out_cap,
    char* out_error,
    size_t error_cap);

// ============================================================================
// 23. Startup Lifecycle State Machine
// ============================================================================

typedef enum MocktailRustStartupState {
    kRustStartupCreated = 0,
    kRustStartupConfigured = 1,
    kRustStartupJniRuntimeReady = 2,
    kRustStartupLibrariesLoaded = 3,
    kRustStartupJniOnLoadComplete = 4,
    kRustStartupEngineStarted = 5,
    kRustStartupDataModelLoading = 6,
    kRustStartupLuaAppReady = 7,
    kRustStartupReady = 8,
    kRustStartupFailure = 9,
    kRustStartupStopping = 10,
    kRustStartupStopped = 11,
} MocktailRustStartupState;

typedef enum MocktailRustStartupEvidence {
    kRustEvidenceConfigured = 0,
    kRustEvidenceJniRuntimeReady = 1,
    kRustEvidenceLibrariesLoaded = 2,
    kRustEvidenceJniOnLoadComplete = 3,
    kRustEvidenceEngineStarted = 4,
    kRustEvidenceDataModelLoading = 5,
    kRustEvidenceLuaAppReady = 6,
    kRustEvidenceRealFramePresented = 7,
    kRustEvidenceInputReady = 8,
    kRustEvidenceAudioReady = 9,
} MocktailRustStartupEvidence;

typedef struct MocktailRustStartupRequirements {
    int windowed;
    int require_input_ready;
    int require_audio_ready;
} MocktailRustStartupRequirements;

typedef struct MocktailRustStartupSnapshot {
    MocktailRustStartupState state;
    MocktailRustStartupRequirements requirements;
    int configured;
    int jni_runtime_ready;
    int libraries_loaded;
    int jni_on_load_complete;
    int engine_started;
    int data_model_loading;
    int lua_app_ready;
    int real_frame_presented;
    int input_ready;
    int audio_ready;
    uint64_t revision;
} MocktailRustStartupSnapshot;

typedef struct MocktailRustStartupSm MocktailRustStartupSm;

MocktailRustStartupSm* mocktail_rust_startup_sm_create(
    MocktailRustStartupRequirements req);

void mocktail_rust_startup_sm_destroy(MocktailRustStartupSm* sm);

int mocktail_rust_startup_sm_record_evidence(
    MocktailRustStartupSm* sm,
    int evidence_val,
    MocktailRustStartupState* out_state,
    int* out_status,
    char* out_msg,
    size_t msg_cap);

int mocktail_rust_startup_sm_fail(
    MocktailRustStartupSm* sm,
    const char* reason,
    MocktailRustStartupState* out_state,
    int* out_status,
    char* out_msg,
    size_t msg_cap);

int mocktail_rust_startup_sm_begin_stopping(
    MocktailRustStartupSm* sm,
    MocktailRustStartupState* out_state,
    int* out_status,
    char* out_msg,
    size_t msg_cap);

int mocktail_rust_startup_sm_mark_stopped(
    MocktailRustStartupSm* sm,
    MocktailRustStartupState* out_state,
    int* out_status,
    char* out_msg,
    size_t msg_cap);

int mocktail_rust_startup_sm_snapshot(
    const MocktailRustStartupSm* sm,
    MocktailRustStartupSnapshot* out_snapshot,
    char* out_reason,
    size_t reason_cap);

// ============================================================================
// 24. Fleasion CA Certificate & Bundle Manager
// ============================================================================

int mocktail_rust_fleasion_prepare_bundle(
    const char* ca_pem_path,
    const char* base_bundle_path,
    const char* dest_bundle_path,
    char* out_error,
    size_t error_cap);

// ============================================================================
// 25. APK Signing Block & Chunk Hash Verifier
// ============================================================================

typedef struct MocktailRustApkSigningBlockInfo {
    uint64_t block_begin;
    uint64_t central_directory;
    uint64_t eocd;
    uint64_t v2_offset;
    uint64_t v2_len;
    uint64_t v3_offset;
    uint64_t v3_len;
    uint64_t v31_offset;
    uint64_t v31_len;
} MocktailRustApkSigningBlockInfo;

int mocktail_rust_find_apk_signing_block(
    const uint8_t* file_bytes,
    size_t file_size,
    MocktailRustApkSigningBlockInfo* out_info,
    char* out_error,
    size_t error_cap);

// ============================================================================
// 26. ETC1 / ETC2 / EAC Software Texture Decoder
// ============================================================================

typedef enum MocktailRustEtcFormat {
    kRustEtc2Rgb8 = 0,
    kRustEtc2Rgb8A1 = 1,
    kRustEtc2Rgba8 = 2,
    kRustEacR11 = 3,
    kRustEacR11Signed = 4,
    kRustEacRg11 = 5,
    kRustEacRg11Signed = 6,
} MocktailRustEtcFormat;

int mocktail_rust_decode_etc_image_block_rows(
    MocktailRustEtcFormat format,
    const uint8_t* source,
    size_t source_bytes,
    uint32_t width,
    uint32_t height,
    uint32_t first_block_row,
    uint32_t block_row_count,
    uint8_t* destination,
    size_t destination_bytes);

#ifdef __cplusplus
}
#endif

#endif  // MOCKTAIL_RUST_H_
