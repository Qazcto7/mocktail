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

int mocktail_rust_parse_webview_roblox_cookie(
    const char* raw_input,
    size_t in_len,
    char* out_buf,
    size_t cap,
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

// ============================================================================
// 27. ZIP Archive Manager
// ============================================================================

int mocktail_rust_zip_list_entries(
    const char* archive_path,
    size_t max_entries,
    char* out_json,
    size_t json_cap,
    char* out_err,
    size_t err_cap);

int mocktail_rust_zip_read_entry(
    const char* archive_path,
    const char* entry_name,
    size_t max_bytes,
    uint8_t* out_buffer,
    size_t buf_cap,
    size_t* out_read_len,
    char* out_err,
    size_t err_cap);

int mocktail_rust_zip_extract_entry(
    const char* archive_path,
    const char* entry_name,
    const char* destination_path,
    size_t max_bytes,
    char* out_err,
    size_t err_cap);

int mocktail_rust_zip_extract_prefix(
    const char* archive_path,
    const char* prefix,
    const char* destination_dir,
    size_t max_total_bytes,
    size_t* out_extracted_count,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 28. Payload Integrity & Asset Tree Verifier
// ============================================================================

int mocktail_rust_payload_hash_asset_tree(
    const char* root_dir,
    char* out_sha256_hex,
    size_t hex_cap,
    size_t* out_file_count,
    char* out_err,
    size_t err_cap);

int mocktail_rust_payload_inspect(
    const char* payload_dir,
    char* out_json,
    size_t json_cap,
    char* out_err,
    size_t err_cap);

int mocktail_rust_payload_verify(
    const char* payload_dir,
    char* out_json,
    size_t json_cap,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 29. ClientAppSettings / FFlags Merger
// ============================================================================

int mocktail_rust_fflags_load_and_merge(
    const char* file_path,
    const char* base_json,
    char* out_json,
    size_t json_cap,
    size_t* out_applied_count,
    int* out_file_loaded,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 30. APKPure Update Provider
// ============================================================================

bool mocktail_rust_apkpure_is_valid_version_name(
    const char* name_ptr,
    size_t name_len);

bool mocktail_rust_apkpure_has_zip_magic(const char* path_ptr);

int mocktail_rust_apkpure_parse_latest(
    const uint8_t* metadata,
    size_t meta_len,
    char* out_version_name,
    size_t ver_cap,
    uint64_t* out_version_code,
    char* out_err,
    size_t err_cap);

int mocktail_rust_apkpure_parse_exact_urls(
    const uint8_t* metadata,
    size_t meta_len,
    const char* version,
    uint64_t version_code,
    char* out_urls_json,
    size_t json_cap,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 31. BrowserTracker Service
// ============================================================================

int mocktail_rust_browser_tracker_generate_id(
    char* out_buf,
    size_t buf_cap);

int mocktail_rust_browser_tracker_extract_id(
    const char* cookie_str,
    char* out_buf,
    size_t buf_cap);

// ============================================================================
// 32. Support Bundle & Log Redactor
// ============================================================================

int mocktail_rust_is_diagnostic_token(const char* token);

int mocktail_rust_sanitize_log(
    const uint8_t* log_bytes,
    size_t log_len,
    char* out_buf,
    size_t buf_cap,
    size_t* out_len);

// ============================================================================
// 33. Client Settings & Atomic File Store (Group A)
// ============================================================================

int mocktail_rust_client_settings_safe_defaults(
    char* out_buf,
    size_t buf_cap);

int mocktail_rust_client_settings_default_url(
    const char* app_name,
    char* out_buf,
    size_t buf_cap);

int mocktail_rust_client_settings_is_valid_json(
    const char* json_str);

int mocktail_rust_atomic_write_file(
    const char* file_path,
    const char* content,
    size_t content_len,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 34. Window State & Video Driver Policy (Group B)
// ============================================================================

typedef struct MocktailRustWindowState {
    int x;
    int y;
    int width;
    int height;
    int has_position;
    int fullscreen;
    int maximized;
    int configured_width;
    int configured_height;
    int has_configured_size;
} MocktailRustWindowState;

int mocktail_rust_window_state_load(
    const char* path_ptr,
    MocktailRustWindowState* out_state,
    int* out_found,
    char* out_err,
    size_t err_cap);

int mocktail_rust_window_state_store(
    const char* path_ptr,
    const MocktailRustWindowState* state_ptr,
    char* out_err,
    size_t err_cap);

void mocktail_rust_window_plan_presentation(
    int fullscreen,
    int maximized,
    int* out_fullscreen_at_creation,
    int* out_maximize_after_constraints);

int mocktail_rust_video_driver_resolve(
    int has_explicit_sdl_driver,
    int force_wayland,
    int force_x11,
    int has_x11_display,
    int uses_direct_vulkan,
    int has_nvidia_kernel_driver,
    int has_wayland_session,
    int prefer_wayland);

int mocktail_rust_video_driver_has_candidate(
    const char* requested,
    const char* candidates_csv);

// ============================================================================
// 35. Runtime Paths & XDG Layout (Group C)
// ============================================================================

int mocktail_rust_runtime_paths_is_lower_hex_build_id(
    const char* build_id);

int mocktail_rust_runtime_paths_resolve_adjacent_assets(
    const char* roblox_lib_path,
    const char* working_dir,
    char* out_path,
    size_t out_cap);

// ============================================================================
// 36. Host ABI Profile Loader & Payload Compatibility (Group D)
// ============================================================================

int mocktail_rust_compute_file_sha256(
    const char* file_path,
    char* out_hex,
    size_t hex_cap,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 37. Audio Sink & PCM Validation (Group E)
// ============================================================================

typedef enum MocktailRustPcmFormat {
    kMocktailRustPcmUnsigned8 = 0,
    kMocktailRustPcmSigned16LittleEndian = 1,
    kMocktailRustPcmSigned32LittleEndian = 2,
    kMocktailRustPcmFloat32LittleEndian = 3,
} MocktailRustPcmFormat;

size_t mocktail_rust_audio_bytes_per_sample(
    MocktailRustPcmFormat format);

int mocktail_rust_audio_validate_pcm(
    int sample_rate_hz,
    uint8_t channels,
    MocktailRustPcmFormat format,
    size_t* out_bytes_per_frame,
    char* out_err,
    size_t err_cap);

void mocktail_rust_audio_apply_gain_f32(
    float* samples,
    size_t count,
    float gain);

void mocktail_rust_audio_convert_f32_to_i16(
    const float* src,
    int16_t* dst,
    size_t count);

// ============================================================================
// 38. Present Mode Policy & Swapchain (Group 1)
// ============================================================================

int mocktail_rust_present_mode_resolve(
    const char* vsync_str,
    const char* fps_str,
    const char* present_mode_str);

int mocktail_rust_present_mode_resolve_vulkan_surface(
    int configured,
    int32_t wayland_surface);

int mocktail_rust_present_mode_explicit(
    int policy,
    uint32_t* out_mode);

int mocktail_rust_present_mode_swap_interval(
    int policy,
    int requested);

uint32_t mocktail_rust_present_mode_prefer_min_image_count(
    int policy,
    uint32_t requested,
    uint32_t min_images,
    uint32_t max_images);

int mocktail_rust_present_mode_filter(
    int policy,
    const uint32_t* host_modes,
    size_t host_count,
    uint32_t* out_modes,
    size_t out_cap,
    size_t* out_count);

const char* mocktail_rust_present_mode_khr_name_ptr(uint32_t mode);

const char* mocktail_rust_present_mode_policy_name_ptr(int policy);

int mocktail_rust_present_mode_khr_name(
    uint32_t mode,
    char* out_buf,
    size_t cap);

int mocktail_rust_present_mode_policy_name(
    int policy,
    char* out_buf,
    size_t cap);

// ============================================================================
// 39. Frame Rate Policy (Group 1)
// ============================================================================

int mocktail_rust_frame_rate_parse(
    const char* val_str,
    int* out_mode,
    int* out_fps);

int mocktail_rust_frame_rate_merge_client_settings(
    int mode,
    int fps,
    const char* base_json,
    char* out_buf,
    size_t out_cap,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 40. Gamepad & Input Mapping (Group 2)
// ============================================================================

int mocktail_rust_gamepad_valid_id(int64_t id);

int mocktail_rust_gamepad_family(int sdl_type);

int32_t mocktail_rust_gamepad_button_to_android(uint8_t button);

int32_t mocktail_rust_roblox_gamepad_type(int family);

float mocktail_rust_gamepad_signed_axis(int16_t val);

void mocktail_rust_gamepad_stick(
    int16_t raw_x,
    int16_t raw_y,
    float* out_x,
    float* out_y);

float mocktail_rust_gamepad_trigger(int16_t raw);

int mocktail_rust_sdl_finger_action(uint32_t sdl_type);

// ============================================================================
// 41. Device Memory Profile & Class Name (Group 3)
// ============================================================================

typedef struct MocktailRustDeviceMemoryProfile {
    int32_t total_memory_mb;
    int32_t memory_class_mb;
    int32_t large_memory_class_mb;
    int32_t low_memory_killer_background_threshold;
    int32_t low_memory_killer_foreground_threshold;
    int low_ram_device;
} MocktailRustDeviceMemoryProfile;

void mocktail_rust_build_device_memory_profile(
    uint64_t host_memory_bytes,
    MocktailRustDeviceMemoryProfile* out_profile);

int mocktail_rust_device_class_name(
    int device_class,
    char* out_buf,
    size_t cap);

// ============================================================================
// 42. Payload Integrity & Candidate Approval (Group 4)
// ============================================================================

int mocktail_rust_hash_text(
    const char* text,
    size_t text_len,
    size_t max_hex_chars,
    char* out_hex,
    size_t hex_cap,
    char* out_err,
    size_t err_cap);

int mocktail_rust_is_lower_hex(
    const char* val_str,
    size_t expected_len);

// ============================================================================
// 43. Session Log & Hardware Detection Helpers (Group 5)
// ============================================================================

int mocktail_rust_pci_vendor_fallback(
    const char* vendor_id,
    char* out_buf,
    size_t cap);

int mocktail_rust_hex_id(
    const char* input,
    char* out_buf,
    size_t cap);

int mocktail_rust_parse_meminfo_total(
    const char* contents,
    char* out_buf,
    size_t cap);

int mocktail_rust_parse_cpuinfo_model(
    const char* contents,
    char* out_buf,
    size_t cap);

// ============================================================================
// 44. Window Readiness Gates (Group A)
// ============================================================================

int mocktail_rust_window_fullscreen_request_from_android_flags(
    int flags,
    int mask,
    uint32_t* current_android_flags,
    int* pending_state);

int mocktail_rust_window_fullscreen_take(
    int* pending_state,
    int* out_fullscreen);

int mocktail_rust_roblox_fullscreen_menu_is_cycle(
    const char* message);

int mocktail_rust_roblox_fullscreen_menu_request(
    const char* tag,
    const char* message,
    uint64_t monotonic_ns,
    uint64_t suppress_until_ns,
    uint64_t* last_request_ns,
    int* pending);

int mocktail_rust_roblox_fullscreen_menu_take(
    uint64_t monotonic_ns,
    uint64_t last_request_ns,
    uint64_t quiet_ns,
    uint64_t suppress_ns,
    uint64_t* suppress_until_ns,
    int* pending);

const char* mocktail_rust_window_resize_state_name(
    uint32_t state);

int mocktail_rust_window_resize_activate(
    int enabled,
    uint32_t target_width,
    uint32_t target_height,
    int initial_available,
    uint64_t initial_generation,
    uint64_t initial_native_window,
    uint32_t initial_width,
    uint32_t initial_height,
    uint32_t* state,
    uint64_t* surface_generation,
    uint32_t* target_width_out,
    uint32_t* target_height_out,
    char* err_buf,
    size_t err_cap);

int mocktail_rust_window_resize_record_present(
    uint64_t frame_serial,
    uint32_t* state,
    uint64_t* first_present_serial,
    uint64_t* post_rebind_present_serial,
    const char* failure_reason,
    char* err_buf,
    size_t err_cap);

int mocktail_rust_window_resize_take_request(
    uint32_t* state,
    uint32_t target_width,
    uint32_t target_height,
    uint32_t* out_width,
    uint32_t* out_height);

int mocktail_rust_window_resize_record_surface_event(
    int event_type,
    int available,
    uint64_t generation,
    uint64_t native_window,
    uint32_t width,
    uint32_t height,
    uint32_t* state,
    uint64_t surface_generation,
    uint32_t target_width,
    uint32_t target_height,
    const char* failure_reason,
    char* err_buf,
    size_t err_cap);

int mocktail_rust_window_resize_record_stopped(
    uint32_t* state,
    const char* failure_reason,
    char* err_buf,
    size_t err_cap);

int mocktail_rust_window_resize_completion_status(
    uint32_t state,
    const char* failure_reason,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 45. Roblox Text Editor & UTF-8 / Grapheme Engine (Group B)
// ============================================================================

int mocktail_rust_text_layout(
    const char* utf8,
    size_t utf8_len,
    int32_t* out_utf16_units,
    size_t* out_boundaries,
    size_t boundaries_cap,
    size_t* out_boundary_count);

int32_t mocktail_rust_text_utf16_cursor(
    const char* utf8,
    size_t utf8_len,
    size_t byte_offset);

size_t mocktail_rust_text_char_to_byte_offset(
    const char* utf8,
    size_t utf8_len,
    int char_index);

uint32_t mocktail_rust_text_shortcut_bit(
    uint32_t scancode);

int mocktail_rust_text_is_password_input(
    int32_t text_input_type);

size_t mocktail_rust_text_prev_grapheme(
    const char* utf8,
    size_t utf8_len,
    size_t cursor_byte);

size_t mocktail_rust_text_next_grapheme(
    const char* utf8,
    size_t utf8_len,
    size_t cursor_byte);

// ============================================================================
// 46. External Launch Broker & Wire Protocol (Group C)
// ============================================================================

int mocktail_rust_external_launch_build_packet(
    const char* json,
    size_t json_len,
    char* out_buf,
    size_t out_cap);

int mocktail_rust_external_launch_verify_and_strip_prefix(
    const char* packet,
    size_t packet_len,
    size_t* out_json_offset,
    size_t* out_json_len);

int mocktail_rust_external_launch_build_reply(
    uint8_t reply_code,
    uint8_t* out_bytes,
    size_t out_cap);

int mocktail_rust_external_launch_parse_reply(
    const uint8_t* in_bytes,
    size_t in_len,
    uint8_t* out_reply_code);

int mocktail_rust_external_launch_reply_status_code(
    uint8_t reply_code);

int mocktail_rust_external_launch_format_socket_name(
    const char* instance_key,
    int is_run_user,
    char* out_buf,
    size_t out_cap);

// ============================================================================
// 47. Split APK & Bundle Layout Resolver (Group D)
// ============================================================================

int mocktail_rust_apk_guest_lib_entry_name(
    const char* abi,
    char* out_buf,
    size_t out_cap);

int mocktail_rust_payload_store_valid_id(
    const char* id,
    size_t len);

int mocktail_rust_payload_store_validate_manifest_json(
    const char* json,
    size_t len,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 48. Audio Buffer Queue & Output Device Bridge (Group E)
// ============================================================================

uint32_t mocktail_rust_opensl_result_from_status_code(
    int32_t status_code);

int mocktail_rust_audio_device_stable_guid(
    const char* name,
    char* out_buf,
    size_t out_cap);

int mocktail_rust_audio_is_valid_elf_header(
    const uint8_t* bytes,
    size_t len);

// ============================================================================
// 49. Discord RPC & Rich Presence Helpers
// ============================================================================

bool mocktail_rust_discord_has_join_target(
    int64_t place_id,
    const char* instance_id,
    size_t instance_id_len);

size_t mocktail_rust_discord_truncate_utf8(
    const char* src,
    size_t src_len,
    size_t maximum);

int mocktail_rust_discord_percent_encode(
    const char* src,
    size_t src_len,
    uint8_t* out_buf,
    size_t out_cap,
    size_t* out_len);

int mocktail_rust_discord_render_place_template(
    const char* template_str,
    size_t template_len,
    const char* place_name,
    size_t place_name_len,
    uint8_t* out_buf,
    size_t out_cap,
    size_t* out_len);

int mocktail_rust_discord_build_join_url(
    int64_t place_id,
    const char* instance_id,
    size_t instance_id_len,
    uint8_t* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 50. Roblox Browser Service & WebView Bridge Helpers
// ============================================================================

bool mocktail_rust_browser_has_control_byte(
    const uint8_t* data,
    size_t len);

bool mocktail_rust_browser_has_embedded_nul(
    const uint8_t* data,
    size_t len);

bool mocktail_rust_webview_is_login_challenge_url(
    const char* url,
    size_t len);

// ============================================================================
// 51. Game Session Coordinator Helpers
// ============================================================================

const char* mocktail_rust_game_session_state_name(
    int32_t state);

const char* mocktail_rust_game_present_backend_name(
    int32_t backend);

const char* mocktail_rust_game_session_principal_kind_name(
    int32_t kind);

bool mocktail_rust_game_session_valid_principal(
    uint64_t generation,
    size_t base_url_len,
    int32_t kind,
    size_t principal_id_len);

bool mocktail_rust_game_session_valid_request(
    uint64_t request_id,
    int64_t place_id,
    size_t launch_params_len);

bool mocktail_rust_game_session_valid_surface(
    uint64_t generation,
    uintptr_t native_window,
    uint32_t width,
    uint32_t height);

// ============================================================================
// 52. WebRTC & FMOD Audio Bridge Helpers
// ============================================================================

bool mocktail_rust_fmod_is_valid_channel_count(
    int32_t channels);

size_t mocktail_rust_webrtc_calc_frame_bytes(
    uint32_t sample_rate_hz,
    uint32_t duration_ms,
    uint32_t channels);

int32_t mocktail_rust_audio_calc_pcm_s16le_peak(
    const uint8_t* data,
    size_t size_bytes);

bool mocktail_rust_audio_spec_equals(
    uint32_t sr1,
    uint32_t ch1,
    int32_t fmt1,
    uint32_t sr2,
    uint32_t ch2,
    int32_t fmt2);

// ============================================================================
// 53. Update Coordinator & Download Preflight Helpers
// ============================================================================

bool mocktail_rust_update_host_matches(
    const char* host,
    size_t host_len,
    const char* allowed,
    size_t allowed_len);

bool mocktail_rust_update_is_redirect_status(
    int64_t status_code);

bool mocktail_rust_update_is_retryable_status(
    int64_t status_code);

bool mocktail_rust_update_is_retryable_curl_code(
    int32_t code);

int mocktail_rust_update_plan_evaluate(
    bool has_latest,
    uint64_t latest_code,
    bool runnable,
    uint64_t runnable_code,
    uint64_t preferred_code,
    bool* out_take_latest,
    bool* out_take_preferred);

// ============================================================================
// 54. Memory Watchdog & Statm Helpers
// ============================================================================

uint64_t mocktail_rust_statm_pages_to_bytes(
    uint64_t pages,
    uint64_t page_size);

int32_t mocktail_rust_parse_proc_statm(
    const char* statm_content,
    size_t len,
    uint64_t* out_resident_pages);

bool mocktail_rust_memory_limit_exceeded(
    uint64_t resident_bytes,
    uint64_t swap_bytes,
    uint64_t limit_bytes);

int32_t mocktail_rust_format_memory_limit_message(
    uint64_t used_bytes,
    uint64_t limit_bytes,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len);

// ============================================================================
// 55. Payload Update Preflight & Diagnostic Relay
// ============================================================================

size_t mocktail_rust_trim_to_utf8_boundary(
    const uint8_t* data,
    size_t len,
    size_t max_bytes);

int32_t mocktail_rust_parse_updater_stderr_line(
    const char* line,
    size_t len,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len,
    bool* out_is_failure);

bool mocktail_rust_is_env_entry(
    const char* entry,
    size_t entry_len,
    const char* name,
    size_t name_len);

int32_t mocktail_rust_format_preflight_failure(
    int32_t status_or_signal,
    bool is_signal,
    const char* last_line,
    size_t last_len,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len);

// ============================================================================
// 56. Desktop App Policy & Layout Normalization
// ============================================================================

int32_t mocktail_rust_normalize_desktop_layout(
    const char* policy_json,
    size_t p_len,
    const char* forced_theme,
    size_t t_len,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len);

int32_t mocktail_rust_merge_desktop_app_policy_settings(
    const char* policy_json,
    size_t p_len,
    const char* base_json,
    size_t b_len,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len);

// ============================================================================
// 57. Browser Tracker Service & Cookie Helpers
// ============================================================================

bool mocktail_rust_browser_tracker_is_valid_id(
    const char* value,
    size_t len);

int32_t mocktail_rust_browser_tracker_extract_cookie(
    const char* cookies,
    size_t c_len,
    const char* name,
    size_t n_len,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len);

bool mocktail_rust_browser_tracker_has_cookie(
    const char* cookies,
    size_t c_len,
    const char* name,
    size_t n_len);

int32_t mocktail_rust_browser_tracker_from_headers(
    const char* headers,
    size_t h_len,
    uint8_t* out_buf,
    size_t cap,
    size_t* out_len);

// ============================================================================
// 58. Auth Service & Credential Processing
// ============================================================================

int32_t mocktail_rust_auth_extract_cookie(
    const char* header,
    size_t header_len,
    bool* out_present,
    char* out_buf,
    size_t cap,
    size_t* out_len);

bool mocktail_rust_auth_is_safe_cookie_value(
    const char* value,
    size_t len);

int32_t mocktail_rust_auth_redact_rejected(
    const char* header,
    size_t header_len,
    const char* rejected_val,
    size_t rejected_len,
    char* out_buf,
    size_t cap,
    size_t* out_len);

int32_t mocktail_rust_auth_parse_identity(
    const char* body,
    size_t body_len,
    int64_t* out_user_id,
    char* out_name_buf,
    size_t name_cap,
    char* out_display_name_buf,
    size_t display_cap);

// ============================================================================
// 59. Cookie Redaction Ranges
// ============================================================================

typedef struct MocktailRustCookieRedactionRange {
  size_t begin;
  size_t end;
  size_t marker;
} MocktailRustCookieRedactionRange;

int32_t mocktail_rust_auth_find_redaction_ranges(
    const char* orig,
    size_t orig_len,
    const char* red,
    size_t red_len,
    MocktailRustCookieRedactionRange* out_ranges,
    size_t max_ranges,
    size_t* out_count);

// ============================================================================
// 60. Capability Requirements & Input Flags Evaluator
// ============================================================================

typedef struct MocktailRustCapabilityInputSymbolsPresence {
  bool has_gamepad_axis_event;
  bool has_gamepad_button_event;
  bool has_gamepad_connect_event_with_gamepad_type;
  bool has_gamepad_disconnect_event;
  bool has_get_main_window_is_mouse_locked_center;
  bool has_pass_accelerometer_change;
  bool has_pass_gravity_change;
  bool has_pass_gyroscope_change;
  bool has_pass_input;
  bool has_pass_long_press_gesture;
  bool has_pass_mouse_button;
  bool has_pass_mouse_move;
  bool has_pass_mouse_pan;
  bool has_pass_mouse_pinch;
  bool has_pass_mouse_wheel;
  bool has_pass_key_event;
  bool has_sync_textbox_text_and_cursor_position2;
  bool has_get_text_box_info;
  bool has_pass_text;
  bool has_return_pressed_from_on_screen_keyboard;
  bool has_release_focus;
  bool has_pass_pan_gesture_multitouch;
  bool has_pass_pan_gesture_with_velocity;
  bool has_pass_pinch_gesture;
  bool has_pass_rotate_gesture;
  bool has_pass_swipe_gesture;
  bool has_pass_tap_gesture;
  bool has_set_accelerometer_enabled;
  bool has_set_gamepad_supported_key_with_gamepad_type;
  bool has_set_gamepad_supported_motion_with_gamepad_type;
  bool has_set_gyroscope_enabled;
  bool has_set_tv_remote_supported_key;
  bool has_tv_remote_button_event;
  bool has_tv_remote_connect_event;
  bool has_tv_remote_disconnect_event;
  bool has_update_screen_orientation;
} MocktailRustCapabilityInputSymbolsPresence;

typedef struct MocktailRustCapabilityInputFlags {
  int32_t gamepad_api;
  bool has_gamepad_events;
  bool has_mouse;
  bool has_touch;
  bool has_hardware_keyboard;
  bool has_text_input;
  bool has_gestures;
  bool has_sensors;
  bool has_tv_remote;
  bool has_screen_orientation;
  bool clear_partial_gamepad;
} MocktailRustCapabilityInputFlags;

void mocktail_rust_capability_eval_input_flags(
    const MocktailRustCapabilityInputSymbolsPresence* in_presence,
    MocktailRustCapabilityInputFlags* out_flags);

// ============================================================================
// 61. Session Log Environment, Hardware & Path Normalization
// ============================================================================

int32_t mocktail_rust_session_log_display_path(
    const char* path,
    size_t path_len,
    const char* home,
    size_t home_len,
    char* out_buf,
    size_t cap,
    size_t* out_len);

int32_t mocktail_rust_session_log_package_kind(
    bool has_flatpak_id,
    bool has_appimage,
    bool has_appdir,
    const char* exec_path,
    size_t exec_len,
    char* out_buf,
    size_t cap,
    size_t* out_len);

int32_t mocktail_rust_session_log_display_server(
    bool has_wayland_display,
    bool has_display,
    char* out_buf,
    size_t cap,
    size_t* out_len);

bool mocktail_rust_session_log_device_node_name(
    const char* name,
    size_t name_len,
    const char* prefix,
    size_t prefix_len);

// ============================================================================
// 62. Candidate Approval Serialization & Evidence Fingerprinting
// ============================================================================

typedef struct MocktailRustPayloadFingerprintInput {
  const char* payload_id;
  size_t payload_id_len;
  const char* metadata_sha256;
  size_t metadata_sha256_len;
  const char* library_sha256;
  size_t library_sha256_len;
  const char* base_apk_sha256;
  size_t base_apk_sha256_len;
  const char* guest_abi;
  size_t guest_abi_len;
  const char* split_apk_sha256;
  size_t split_apk_sha256_len;
  const char* asset_tree_sha256;
  size_t asset_tree_sha256_len;
} MocktailRustPayloadFingerprintInput;

int32_t mocktail_rust_candidate_approval_fingerprint(
    const MocktailRustPayloadFingerprintInput* input,
    char* out_sha256,
    size_t cap);

int32_t mocktail_rust_candidate_approval_generation(
    const char* runtime_build_id,
    size_t r_len,
    const char* fingerprint,
    size_t f_len,
    const char* profile_sha256,
    size_t p_len,
    const char* compatibility_sha256,
    size_t c_len,
    const char* canary_1_sha256,
    size_t c1_len,
    const char* canary_2_sha256,
    size_t c2_len,
    char* out_generation_40,
    size_t cap);

int32_t mocktail_rust_candidate_approval_validate_binding(
    const char* profile_json,
    size_t p_len,
    const char* compatibility_json,
    size_t c_len,
    const char* payload_id,
    size_t payload_id_len,
    const char* elf_build_id,
    size_t elf_len,
    const char* library_sha256,
    size_t lib_len,
    const char* version_name,
    size_t ver_name_len,
    uint64_t version_code,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 63. Candidate Approval Attestation & Receipt Generator
// ============================================================================

typedef struct MocktailRustCanaryAttestationInput {
  size_t run;
  const char* run_id;
  size_t run_id_len;
  const char* payload_id;
  size_t payload_id_len;
  const char* payload_fingerprint;
  size_t payload_fingerprint_len;
  const char* profile_sha256;
  size_t profile_sha256_len;
  const char* compatibility_manifest_sha256;
  size_t compatibility_manifest_sha256_len;
  const char* runtime_sha256;
  size_t runtime_sha256_len;
  const char* runtime_build_id;
  size_t runtime_build_id_len;
  const char* log_sha256;
  size_t log_sha256_len;
} MocktailRustCanaryAttestationInput;

int32_t mocktail_rust_candidate_approval_build_attestation(
    const MocktailRustCanaryAttestationInput* input,
    char* out_json,
    size_t cap,
    size_t* out_len);

typedef struct MocktailRustApprovalReceiptInput {
  const char* payload_id;
  size_t payload_id_len;
  const char* generation;
  size_t generation_len;
  const char* payload_path;
  size_t payload_path_len;
  const char* elf_build_id;
  size_t elf_build_id_len;
  const char* library_sha256;
  size_t library_sha256_len;
  const char* payload_fingerprint;
  size_t payload_fingerprint_len;
  const char* profile_sha256;
  size_t profile_sha256_len;
  const char* compatibility_manifest_sha256;
  size_t compatibility_manifest_sha256_len;
  const char* runtime_sha256;
  size_t runtime_sha256_len;
  const char* runtime_build_id;
  size_t runtime_build_id_len;
  const char* canary_1_sha256;
  size_t canary_1_sha256_len;
  const char* canary_2_sha256;
  size_t canary_2_sha256_len;
  const char* approved_at_utc;
  size_t approved_at_utc_len;
} MocktailRustApprovalReceiptInput;

int32_t mocktail_rust_candidate_approval_build_receipt(
    const MocktailRustApprovalReceiptInput* input,
    char* out_json,
    size_t cap,
    size_t* out_len);

// ============================================================================
// 64. GameMode & Physics Worker Policies (Parsing, States & Worker Counts)
// ============================================================================

bool mocktail_rust_game_mode_parse_policy(
    const char* value,
    size_t val_len,
    int32_t* out_policy);

const char* mocktail_rust_game_mode_policy_name(int32_t policy);

const char* mocktail_rust_game_mode_session_state_name(int32_t state);

bool mocktail_rust_performance_parse_physics_worker_mode(
    const char* value,
    size_t val_len,
    int32_t* out_mode);

const char* mocktail_rust_performance_physics_worker_mode_name(int32_t mode);

int32_t mocktail_rust_performance_calculate_throughput_worker_count(
    int32_t available_physical_cores);

// ============================================================================
// 65. Single Instance Lock Isolated Canary & Sibling Path Gate
// ============================================================================

typedef struct MocktailRustCanaryPathsInput {
  const char* canary_value;
  size_t canary_len;
  bool has_data_root;
  bool has_cache_root;
  bool has_state_root;
  bool has_roblox_lib;
  bool has_asset_path;
  const char* skip_update_value;
  size_t skip_update_len;
  const char* auto_exit_ms_value;
  size_t auto_exit_ms_len;
  const char* data_root;
  size_t data_root_len;
  const char* cache_root;
  size_t cache_root_len;
  const char* state_root;
  size_t state_root_len;
} MocktailRustCanaryPathsInput;

int32_t mocktail_rust_single_instance_validate_isolated_canary(
    const MocktailRustCanaryPathsInput* input,
    char* out_error,
    size_t error_cap);

// ============================================================================
// 66. Audio & HttpClient Overrides Policy Engine
// ============================================================================

int32_t mocktail_rust_http_client_merge_settings_overrides(
    const char* base_json,
    size_t base_len,
    char* out_json,
    size_t cap,
    size_t* out_len);

int32_t mocktail_rust_audio_device_menu_merge_overrides(
    const char* base_json,
    size_t base_len,
    char* out_json,
    size_t cap,
    size_t* out_len);

int32_t mocktail_rust_audio_capture_merge_overrides(
    const char* base_json,
    size_t base_len,
    char* out_json,
    size_t cap,
    size_t* out_len);

// ============================================================================
// 67. Texture Memory Policy Engine
// ============================================================================

uint64_t mocktail_rust_texture_memory_calculate_budget(uint64_t host_memory_bytes);

int32_t mocktail_rust_texture_memory_merge_overrides(
    uint64_t budget_bytes,
    const char* base_json,
    size_t base_len,
    char* out_json,
    size_t cap,
    size_t* out_len,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 68. Roblox Desktop App Policy Engine
// ============================================================================

int32_t mocktail_rust_process_desktop_app_policy(
    const char* storage_json,
    size_t storage_json_len,
    bool has_storage,
    const char* default_policy_json,
    size_t default_policy_json_len,
    int64_t authenticated_user_id,
    const char* theme_mode,
    char* out_storage_json,
    size_t out_storage_cap,
    size_t* out_storage_len,
    char* out_policy_json,
    size_t out_policy_cap,
    size_t* out_policy_len,
    bool* out_updated,
    size_t* out_normalized_count,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 69. Launch Experience JSON Engine
// ============================================================================

typedef struct MocktailRustExperienceLaunchData {
  int64_t place_id;
  int64_t user_id;
  int64_t conversation_id;
  int64_t referred_by_player_id;
} MocktailRustExperienceLaunchData;

int32_t mocktail_rust_parse_experience_launch_json(
    const char* json_ptr,
    size_t json_len,
    MocktailRustExperienceLaunchData* out_data,
    char* canonical_buf,
    size_t canonical_cap,
    size_t* canonical_len,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 70. Environment Abstraction Engine
// ============================================================================

int32_t mocktail_rust_env_has_non_empty(const char* name);

int32_t mocktail_rust_env_get(
    const char* name,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

int32_t mocktail_rust_env_get_or(
    const char* name,
    const char* default_val,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 71. Command Line Engine
// ============================================================================

int32_t mocktail_rust_command_line_usage(
    const char* program_name,
    const char* guest_abi,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 72. Frame Rate Policy Helpers
// ============================================================================

int32_t mocktail_rust_frame_rate_policy_name(
    int32_t mode,
    int32_t fps,
    char* out_buf,
    size_t out_cap);

// ============================================================================
// 73. Present Mode Policy & Vulkan WSI Extension Translation
// ============================================================================

int32_t mocktail_rust_normalize_android_swapchain_result(int32_t result);

int32_t mocktail_rust_translate_android_vulkan_instance_extensions(
    const char* const* android_exts,
    size_t android_count,
    const char* const* host_wsi_exts,
    size_t host_count,
    char** out_exts,
    size_t out_cap,
    size_t* out_count,
    char* err_buf,
    size_t err_cap);

void mocktail_rust_free_c_string(char* ptr);

// ============================================================================
// 74. Display Refresh Capabilities Engine
// ============================================================================

int32_t mocktail_rust_normalize_display_refresh_capabilities(
    float current_hz,
    const float* supported_hz,
    size_t count,
    float* out_hz,
    size_t out_cap,
    size_t* out_count);

// ============================================================================
// 75. Platform Application Metadata & Identity
// ============================================================================

int32_t mocktail_rust_platform_metadata_identity(
    char* name_buf,
    size_t name_cap,
    char* id_buf,
    size_t id_cap,
    char* type_buf,
    size_t type_cap);

// ============================================================================
// 76. SDL Window Icon PNG Header Verifier
// ============================================================================

int32_t mocktail_rust_validate_window_icon_png_header(
    const uint8_t* data,
    size_t size,
    uint32_t* out_width,
    uint32_t* out_height);

// ============================================================================
// 77. Supported Launch Policy Defaults Table
// ============================================================================

size_t mocktail_rust_supported_launch_defaults_count(int32_t interactive);

int32_t mocktail_rust_supported_launch_default_entry(
    int32_t interactive,
    size_t index,
    char* key_buf,
    size_t key_cap,
    char* val_buf,
    size_t val_cap);

// ============================================================================
// 78. Platform Profile Revision Generator & Android Path Normalizer
// ============================================================================

int32_t mocktail_rust_build_platform_profile_revision(
    const char* device_profile,
    int32_t touch,
    int32_t mouse,
    int32_t keyboard,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_translate_android_files_path(
    const char* configured,
    const char* data_root,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_has_path_prefix(
    const char* path,
    const char* prefix);

// ============================================================================
// 79. Platform Cache Migration Fingerprint Validator
// ============================================================================

int32_t mocktail_rust_validate_platform_cache_fingerprint(
    const char* json_str,
    size_t json_len,
    char* revision_buf,
    size_t revision_cap);

// ============================================================================
// 80. Roblox Browser Service Command Parser
// ============================================================================

typedef struct MocktailRustBrowserServiceOpenCommand {
    char url[1024];
    char title[512];
    int32_t has_title;
    int32_t visible;
    int32_t modal;
    int32_t back_navigation_disabled;
    int32_t show_domain_as_title;
} MocktailRustBrowserServiceOpenCommand;

int32_t mocktail_rust_parse_browser_service_command(
    const char* json_str,
    size_t json_len,
    int32_t* out_command_type,
    MocktailRustBrowserServiceOpenCommand* out_cmd,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 81. Roblox Text Display State & UTF-16 Cursor Engine
// ============================================================================

size_t mocktail_rust_utf8_byte_for_utf16_cursor(
    const char* text,
    size_t size,
    int32_t requested_utf16,
    size_t* out_codepoints);

int32_t mocktail_rust_text_geometry_intersects_viewport(
    int32_t area_x,
    int32_t area_y,
    int32_t area_w,
    int32_t area_h,
    int32_t vp_w,
    int32_t vp_h);

// ============================================================================
// 82. Roblox Fullscreen Machine Code Setter Contract Verifier
// ============================================================================

int32_t mocktail_rust_validate_fullscreen_setter_contract(
    const uint8_t* code,
    size_t size);

// ============================================================================
// 83. Window Pointer Capture Evaluation Engine
// ============================================================================

int32_t mocktail_rust_pointer_capture_evaluate(
    int32_t focused,
    int32_t query_ok,
    int32_t locked_center,
    int32_t right_button_held,
    int32_t text_input_active,
    int32_t* out_capture_requested,
    int32_t* out_cursor_visible);

// ============================================================================
// 84. Window Text Input Type Mapper & Area Clamper
// ============================================================================

int32_t mocktail_rust_map_roblox_text_input_type(int32_t input_type);

void mocktail_rust_clamp_text_input_area(
    int32_t* x,
    int32_t* y,
    int32_t* w,
    int32_t* h,
    int32_t* cursor);

// ============================================================================
// 85. Bionic Sysconf Parameter Lookup
// ============================================================================

int32_t mocktail_rust_bionic_sysconf_translate_name(
    int32_t bionic_name,
    int32_t* out_standard_sc,
    int64_t* out_fixed_value);

// ============================================================================
// 86. Build Profile Parser & Hex RVA Reader
// ============================================================================

int32_t mocktail_rust_normalize_build_id(
    const char* build_id,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_parse_status_string(const char* status);

int32_t mocktail_rust_parse_hex_rva(
    const char* hex_str,
    uintptr_t* out_rva);

// ============================================================================
// 87. ELF Build ID Hex Validator
// ============================================================================

int32_t mocktail_rust_is_valid_build_id(
    const char* build_id,
    size_t len);

// ============================================================================
// 88. HTTP Client Spin Guard Rate Limiter
// ============================================================================

uint64_t mocktail_rust_http_spin_limiter_observe(
    uint64_t* inout_op_count,
    uint64_t* inout_checkpoint_ns,
    uint64_t now_ns,
    uint64_t batch_size,
    uint64_t batch_interval_ns);

// ============================================================================
// 89. Owned Pthread Wait Status Name
// ============================================================================

const char* mocktail_rust_owned_pthread_status_name_ptr(int32_t status);

int32_t mocktail_rust_owned_pthread_status_name(
    int32_t status,
    char* out_buf,
    size_t out_cap);

// ============================================================================
// 90. Failure Dialog Protocol & Environment Evaluator
// ============================================================================

int32_t mocktail_rust_failure_dialogs_enabled(
    int32_t disabled_by_env,
    int32_t is_canary,
    int32_t is_headless,
    int32_t has_display,
    int32_t has_wayland);

int32_t mocktail_rust_failure_dialog_format_packet(
    char packet_type,
    const char* message,
    size_t max_bytes,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 91. APK Provider Failure Aggregator
// ============================================================================

int32_t mocktail_rust_apk_provider_append_failure(
    const char* existing,
    const char* provider_name,
    const char* failure_msg,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 92. Update Configuration YAML Parser
// ============================================================================

int32_t mocktail_rust_parse_update_config_yaml(
    const char* yaml_str,
    size_t yaml_len,
    int32_t* out_auto,
    int32_t* out_launch_after,
    char* source_buf,
    size_t source_cap,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 93. Unsafe Latest Environment Filter & Builder
// ============================================================================

int32_t mocktail_rust_is_overridden_environment_var(const char* entry);

// ============================================================================
// 94. Canary Readiness Backend & Audio Log Validator
// ============================================================================

int32_t mocktail_rust_canary_backend_parse(
    const char* name,
    int32_t* out_backend);

int32_t mocktail_rust_canary_backend_name(
    int32_t backend,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_validate_canary_audio_log(
    const char* log_text,
    size_t log_len,
    int32_t require_clean_shutdown,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 95. Game Session State Machine & Transition Evaluator
// ============================================================================

int32_t mocktail_rust_game_session_can_transition(
    int32_t current_state,
    int32_t target_state);

// ============================================================================
// 96. Capability Resolver Flags Evaluator
// ============================================================================

void mocktail_rust_evaluate_startup_flags(
    int32_t has_surface_app,
    int32_t has_message_pump,
    int32_t has_start_game,
    int32_t has_surface_game,
    int32_t* out_flags);

// ============================================================================
// 97. Roblox App Lifecycle Status Name Engine
// ============================================================================

const char* mocktail_rust_app_lifecycle_status_name_ptr(int32_t status);

const char* mocktail_rust_app_shutdown_status_name_ptr(int32_t status);

int32_t mocktail_rust_app_lifecycle_status_name(
    int32_t status,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_app_shutdown_status_name(
    int32_t status,
    char* out_buf,
    size_t out_cap);

// ============================================================================
// 98. Fresh Start Game Params String Encoder
// ============================================================================

int32_t mocktail_rust_utf8_to_utf16_surrogates(
    const char* utf8_str,
    size_t utf8_len,
    uint16_t* out_utf16,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 99. Roblox Permissions Answer Formatter
// ============================================================================

int32_t mocktail_rust_format_permissions_reply(
    size_t method,
    int32_t mic_enabled,
    const char* request_json,
    char* out_body,
    size_t body_cap,
    size_t* body_len,
    int32_t* out_code,
    char* out_outcome,
    size_t outcome_cap);

// ============================================================================
// 100. Client Settings Source Naming & Default URL Builder
// ============================================================================

const char* mocktail_rust_client_settings_source_name_ptr(int32_t source);

int32_t mocktail_rust_client_settings_source_name(
    int32_t source,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_client_settings_build_url(
    const char* app_name,
    char* out_buf,
    size_t out_cap);

// ============================================================================
// 105. Interactive Process Launch Resource & Scheduler Policy Engine
// ============================================================================

int32_t mocktail_rust_process_launch_format_limit(
    uint64_t value,
    int32_t is_infinity,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_process_launch_eval_scheduler(
    int32_t inherited_policy,
    int32_t* out_target_policy,
    int32_t* out_is_realtime);

int32_t mocktail_rust_process_launch_eval_cpu_limit(
    uint64_t cur,
    int32_t cur_is_inf,
    uint64_t max,
    int32_t max_is_inf,
    int32_t* out_action);

int32_t mocktail_rust_apply_interactive_process_launch_policy(
    char* out_buf,
    size_t out_cap,
    size_t* out_written);

// ============================================================================
// 106. Pinned APK Provider Archive & Digest Verification Policy
// ============================================================================

int32_t mocktail_rust_pinned_apk_hex_digest(
    const char* value,
    size_t len,
    size_t expected_size);

int32_t mocktail_rust_pinned_apk_archive_filename_valid(
    const char* filename,
    size_t len);

int32_t mocktail_rust_pinned_apk_archive_limits_valid(
    uint64_t size_bytes,
    uint64_t maximum_bytes);

// ============================================================================
// 107. Vulkan Swapchain Present & Surface Maintenance Policy
// ============================================================================

int32_t mocktail_rust_vulkan_select_surface_maintenance_exts(
    const char* const* supported_ptrs,
    size_t supported_count,
    const char* const* enabled_ptrs,
    size_t enabled_count,
    char* out_append_nl,
    size_t out_cap,
    size_t* out_len);

int mocktail_rust_vulkan_swapchain_image_policy(
    int policy,
    uint32_t selected_present_mode);

// ============================================================================
// 108. Texture Override Policy, FNV-1a Hash & RGBA Resampler
// ============================================================================

int32_t mocktail_rust_texture_override_has_png(const char* dir_ptr);

uint64_t mocktail_rust_texture_override_hash_bytes(
    const uint8_t* data,
    size_t size);

int32_t mocktail_rust_texture_override_hash_name(
    uint64_t hash,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_texture_override_resample_rgba(
    const uint8_t* source,
    uint32_t source_width,
    uint32_t source_height,
    uint32_t width,
    uint32_t height,
    uint8_t* destination);

// ============================================================================
// 109. Bundled Sky ETC1-to-BC1 KTX1 Transcoder
// ============================================================================

int32_t mocktail_rust_etc1_is_bundled_sky_texture(const char* path);

int32_t mocktail_rust_etc1_convert_rgb_block_to_bc1(
    const uint8_t* etc1,
    uint8_t* bc1);

int32_t mocktail_rust_etc1_transcode_ktx1_for_vulkan(
    uint8_t* data,
    size_t len);

// ============================================================================
// 110. Vulkan ETC2 Emulation Helpers & Streaming Staging Copy
// ============================================================================

int32_t mocktail_rust_vulkan_etc2_lookup_format(
    int32_t vk_format,
    int32_t* out_host_format,
    int32_t* out_etc_format);

uint32_t mocktail_rust_vulkan_etc2_emulated_features(uint32_t host_features);

int32_t mocktail_rust_vulkan_etc2_upload_byte_counts(
    uint64_t block_bytes,
    uint64_t texel_bytes,
    uint32_t width,
    uint32_t height,
    uint32_t depth,
    uint32_t layer_count,
    uint64_t* out_compressed,
    uint64_t* out_decoded);

int32_t mocktail_rust_vulkan_etc2_support_advertised(const char* value);

uint32_t mocktail_rust_vulkan_etc2_small_texture_upscale(const char* value);

void mocktail_rust_vulkan_etc2_copy_from_mapped(
    uint8_t* destination,
    const uint8_t* source,
    size_t size);

// ============================================================================
// 111. Graphics Launch Policy, PCI GPU & Vulkan ICD Selector
// ============================================================================

int32_t mocktail_rust_graphics_is_haswell_intel(uint32_t device_id);

int32_t mocktail_rust_graphics_parse_pci_hex(
    const char* raw,
    uint32_t* out_val);

uint32_t mocktail_rust_graphics_anv_sys_mem_limit_percent(
    const char* meminfo_content);

int32_t mocktail_rust_graphics_is_foreign_icd_name(
    const char* name,
    int32_t target_is_aarch64);

int32_t mocktail_rust_graphics_select_icd_manifest(
    const char* dirs_nl,
    const char* needle,
    int32_t target_is_aarch64,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_graphics_is_radv_icd_list(const char* manifests);

// ============================================================================
// 112. Graphics Backend Selection Policy
// ============================================================================

const char* mocktail_rust_graphics_backend_name_ptr(int32_t backend);

int32_t mocktail_rust_graphics_backend_select(
    int32_t requested,
    int32_t allow_fallback,
    int32_t require_hw,
    int32_t require_runtime,
    const int32_t* caps_backends,
    const int32_t* caps_states,
    const int32_t* caps_accels,
    const char* const* caps_details,
    size_t caps_count,
    int32_t* out_selected_backend,
    char* out_detail_buf,
    size_t out_detail_cap);

// ============================================================================
// 113. Window Surface Lifecycle State Machine & Creation Policy
// ============================================================================

typedef struct MocktailRustSurfaceSnapshot {
    uint64_t generation;
    uintptr_t native_window;
    uint32_t width;
    uint32_t height;
    int32_t available;
    float dpi_scale;
} MocktailRustSurfaceSnapshot;

typedef struct MocktailRustSurfaceEvent {
    int32_t event_type;
    MocktailRustSurfaceSnapshot surface;
} MocktailRustSurfaceEvent;

void* mocktail_rust_surface_lifecycle_new(void);

void mocktail_rust_surface_lifecycle_free(void* ptr);

int32_t mocktail_rust_surface_lifecycle_activate(
    void* ptr,
    uintptr_t native_window,
    uint32_t width,
    uint32_t height,
    float dpi_scale,
    char* err_buf,
    size_t err_cap);

void mocktail_rust_surface_lifecycle_deactivate(void* ptr);

int32_t mocktail_rust_surface_lifecycle_observe(
    void* ptr,
    uintptr_t native_window,
    uint32_t width,
    uint32_t height,
    float dpi_scale,
    char* err_buf,
    size_t err_cap);

int32_t mocktail_rust_surface_lifecycle_refresh(
    void* ptr,
    char* err_buf,
    size_t err_cap);

int32_t mocktail_rust_surface_lifecycle_recreate(
    void* ptr,
    char* err_buf,
    size_t err_cap);

int32_t mocktail_rust_surface_lifecycle_poll(
    void* ptr,
    MocktailRustSurfaceEvent* out_event);

int32_t mocktail_rust_surface_lifecycle_snapshot(
    const void* ptr,
    MocktailRustSurfaceSnapshot* out_snapshot);

int32_t mocktail_rust_surface_lifecycle_is_active(const void* ptr);

const char* mocktail_rust_surface_event_type_name_ptr(int32_t event_type);

uint64_t mocktail_rust_window_apply_high_dpi_flag(
    uint64_t flags,
    int32_t high_dpi,
    uint64_t high_dpi_bit);

int32_t mocktail_rust_window_direct_vulkan_requires_sync(
    const char* video_driver);

// ============================================================================
// 114. Roblox Presence Cookie Extractor & JSON Parser
// ============================================================================

int32_t mocktail_rust_presence_extract_cookie(
    const char* raw_cookie,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_presence_parse_follow_response(
    const char* json_str,
    int64_t* out_place_id,
    char* out_game_id,
    size_t out_game_id_cap,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 115. Bounded JSON State File Reader/Validator
// ============================================================================

int32_t mocktail_rust_update_state_read_json_file(
    const char* path_ptr,
    char* out_buf,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 116. WebView Helper Security Policy & Navigation URI Evaluator
// ============================================================================

int32_t mocktail_rust_webview_should_disable_sandbox(
    const char* kernel_version,
    const char* sandbox_override);

int32_t mocktail_rust_webview_should_disable_hw_accel(
    int32_t wayland_display,
    const char* compositing_override);

int32_t mocktail_rust_webview_build_user_agent(
    const char* configured_version,
    char* out_buf,
    size_t out_cap);

int32_t mocktail_rust_webview_evaluate_navigation_uri(
    const char* uri,
    int32_t* out_allowed,
    int32_t* out_privileged,
    char* scheme_buf,
    size_t scheme_cap,
    char* host_buf,
    size_t host_cap);

int32_t mocktail_rust_webview_is_browser_login_url(const char* url_ptr);

int32_t mocktail_rust_webview_is_essential_resource(const char* uri_ptr);

const char* mocktail_rust_webview_captcha_event_name_ptr(int32_t event_type);

int32_t mocktail_rust_webview_parse_captcha_event(
    const char* cmd,
    size_t cmd_len,
    int32_t* out_type,
    char* out_cb,
    size_t cb_cap);

int32_t mocktail_rust_webview_build_callback_script(
    const char* cb_id,
    size_t cb_len,
    char* out_buf,
    size_t out_cap);

// ============================================================================
// 118. Roblox Text Font Resolver
// ============================================================================

int32_t mocktail_rust_resolve_roblox_text_font(
    int32_t font,
    const char* asset_content_root_ptr,
    size_t asset_content_root_len,
    char* out_primary_file,
    size_t primary_file_cap,
    float* out_size_scale,
    bool* out_exact_mapping);

// ============================================================================
// 119. Runtime Config & Network Proxy Helpers
// ============================================================================

bool mocktail_rust_network_proxy_parse(
    const char* host_ptr,
    size_t host_len,
    const char* port_ptr,
    size_t port_len,
    const char* scheme_ptr,
    size_t scheme_len,
    const char* user_ptr,
    size_t user_len,
    const char* pass_ptr,
    size_t pass_len,
    char* out_scheme,
    size_t scheme_cap,
    int32_t* out_port);

size_t mocktail_rust_network_proxy_build_url(
    const char* scheme_ptr,
    size_t scheme_len,
    const char* host_ptr,
    size_t host_len,
    int32_t port,
    const char* user_ptr,
    size_t user_len,
    const char* pass_ptr,
    size_t pass_len,
    bool include_credentials,
    char* out_url,
    size_t url_cap);

int32_t mocktail_rust_runtime_config_parse_graphics_backend(
    const char* name_ptr,
    size_t name_len);

bool mocktail_rust_runtime_config_parse_bool(
    const char* val_ptr,
    size_t val_len,
    bool default_val,
    bool* out_valid);

int32_t mocktail_rust_runtime_config_parse_positive_int(
    const char* val_ptr,
    size_t val_len,
    int32_t default_val);

bool mocktail_rust_runtime_config_is_discord_app_id(
    const char* val_ptr,
    size_t val_len);

bool mocktail_rust_runtime_config_is_discord_text(
    const char* val_ptr,
    size_t val_len,
    size_t max_len);

// ============================================================================
// 120. Runtime Config Bootstrap
// ============================================================================

const char* mocktail_rust_runtime_config_default_yaml_ptr(size_t* out_len);

int32_t mocktail_rust_runtime_config_ensure_file(
    const char* path_ptr,
    bool* out_created,
    char* out_err,
    size_t err_cap);

// ============================================================================
// 121. Host Allocator Bridge
// ============================================================================

void* mocktail_rust_host_aligned_allocate(size_t size, size_t alignment);
void* mocktail_rust_host_allocate(size_t size);
void* mocktail_rust_host_reallocate(void* pointer, size_t size);
void mocktail_rust_host_free(void* pointer);
size_t mocktail_rust_host_usable_size(void* pointer);

// ============================================================================
// 122. Host ABI Profile & Experiment Engine
// ============================================================================

typedef struct MocktailRustConstructorRange {
    size_t begin;
    size_t end_exclusive;
} MocktailRustConstructorRange;

bool mocktail_rust_host_abi_has_valid_ranges(
    const MocktailRustConstructorRange* ranges_ptr,
    size_t range_count,
    size_t max_ranges,
    size_t init_array_count);

bool mocktail_rust_host_abi_allows_constructor(
    const MocktailRustConstructorRange* ranges_ptr,
    size_t range_count,
    size_t max_ranges,
    size_t init_array_count,
    size_t index);

size_t mocktail_rust_host_abi_range_begin(
    const MocktailRustConstructorRange* ranges_ptr,
    size_t range_count,
    size_t max_ranges,
    size_t init_array_count);

size_t mocktail_rust_host_abi_range_end_exclusive(
    const MocktailRustConstructorRange* ranges_ptr,
    size_t range_count,
    size_t max_ranges,
    size_t init_array_count);

bool mocktail_rust_host_abi_should_init_mimalloc_thread(
    const MocktailRustConstructorRange* ranges_ptr,
    size_t range_count,
    size_t max_ranges,
    size_t init_array_count,
    size_t init_after,
    size_t index);

int32_t mocktail_rust_host_abi_resolve_allocator_strategy(
    int32_t default_strategy,
    bool override_present,
    bool override_enabled);

bool mocktail_rust_host_abi_patch_absolute_jump(
    size_t address,
    void* target);

bool mocktail_rust_host_abi_seed_jni_singleton(
    size_t library_base,
    size_t jni_singleton_slot,
    size_t jni_singleton_bytes,
    void** out_seeded_ptr);

// ============================================================================
// 123. Window Game Surface Bridge Validation & State Machine
// ============================================================================

typedef struct MocktailRustGameSurfaceBridgeSnapshot {
    uint64_t accepted_events;
    uint64_t duplicate_events;
    uint64_t last_generation;
    int32_t last_event_type;
    bool failed;
} MocktailRustGameSurfaceBridgeSnapshot;

int32_t mocktail_rust_game_surface_bridge_validate_event(
    const MocktailRustSurfaceEvent* event,
    char* out_err,
    size_t err_cap);

void mocktail_rust_game_surface_bridge_record_event(
    const MocktailRustSurfaceEvent* event,
    bool changed,
    MocktailRustGameSurfaceBridgeSnapshot* io_snapshot);

// ============================================================================
// 124. Input Pump Pacer
// ============================================================================

void* mocktail_rust_input_pump_pacer_new(uint64_t interval_ns);
void mocktail_rust_input_pump_pacer_free(void* ptr);
uint64_t mocktail_rust_input_pump_pacer_delay_before_next_pump(
    void* ptr,
    uint64_t now_ns);
void mocktail_rust_input_pump_pacer_reset(void* ptr);

// ============================================================================
// 125. Vulkan Surface Recovery Gate
// ============================================================================

typedef struct MocktailRustVulkanSurfaceRecoveryRequest {
    uint64_t observed_error_count;
    uint64_t coalesced_error_count;
    bool retry;
} MocktailRustVulkanSurfaceRecoveryRequest;

void* mocktail_rust_vulkan_surface_recovery_gate_new(void);
void mocktail_rust_vulkan_surface_recovery_gate_free(void* ptr);
bool mocktail_rust_vulkan_surface_recovery_gate_activate(void* ptr);
void mocktail_rust_vulkan_surface_recovery_gate_deactivate(void* ptr);
void mocktail_rust_vulkan_surface_recovery_gate_notify_out_of_date(void* ptr);
void mocktail_rust_vulkan_surface_recovery_gate_notify_present(void* ptr);
bool mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
    void* ptr,
    uint64_t now_ticks_ns,
    MocktailRustVulkanSurfaceRecoveryRequest* out_request);

// ============================================================================
// 126. Vulkan Present Progress Gate
// ============================================================================

typedef struct MocktailRustVulkanPresentStallReport {
    int32_t stage;
    const char* call_name;
    uint64_t call_sequence;
    uint64_t thread_id;
    uint64_t elapsed_ns;
    uint64_t frame_count;
    uint64_t host_present_count;
    uint64_t last_present_thread_id;
    bool last_completed_call_snapshot_coherent;
    const char* last_completed_call_name;
    uint64_t last_completed_call_sequence;
    uint64_t last_completed_call_thread_id;
    uint64_t last_completed_call_started_ns;
    uint64_t last_completed_call_completed_ns;
    int32_t last_completed_call_result;
    const char* oldest_active_call_name;
    uint64_t oldest_active_call_sequence;
    uint64_t oldest_active_call_thread_id;
    uint64_t oldest_active_call_elapsed_ns;
} MocktailRustVulkanPresentStallReport;

void* mocktail_rust_vulkan_present_progress_gate_new(void);
void mocktail_rust_vulkan_present_progress_gate_free(void* ptr);
bool mocktail_rust_vulkan_present_progress_gate_activate(void* ptr);
void mocktail_rust_vulkan_present_progress_gate_deactivate(void* ptr);
uint64_t mocktail_rust_vulkan_present_progress_gate_notify_host_present_begin(
    void* ptr,
    uint64_t now_ticks_ns,
    uint64_t thread_id);
void mocktail_rust_vulkan_present_progress_gate_notify_host_present_end(
    void* ptr,
    uint64_t sequence);
uint64_t mocktail_rust_vulkan_present_progress_gate_notify_call_begin(
    void* ptr,
    const char* call_name,
    uint64_t now_ticks_ns,
    uint64_t thread_id);
void mocktail_rust_vulkan_present_progress_gate_notify_call_end(
    void* ptr,
    uint64_t sequence,
    int32_t result,
    uint64_t now_ticks_ns,
    uint64_t thread_id);
void mocktail_rust_vulkan_present_progress_gate_notify_frame_presented(
    void* ptr,
    uint64_t now_ticks_ns,
    uint64_t frame_count,
    uint64_t thread_id);
bool mocktail_rust_vulkan_present_progress_gate_poll(
    void* ptr,
    uint64_t now_ticks_ns,
    bool window_can_present,
    MocktailRustVulkanPresentStallReport* out_report);

// ============================================================================
// 127. Window Fullscreen State Sync Gate
// ============================================================================

typedef bool (*MocktailRustFullscreenStateSyncCb)(void* context, bool fullscreen);

void* mocktail_rust_window_fullscreen_state_sync_new(void);
void mocktail_rust_window_fullscreen_state_sync_free(void* ptr);
bool mocktail_rust_window_fullscreen_state_sync_register(
    void* ptr,
    MocktailRustFullscreenStateSyncCb callback,
    void* context);
bool mocktail_rust_window_fullscreen_state_sync_notify(
    void* ptr,
    bool fullscreen);
void mocktail_rust_window_fullscreen_state_sync_clear(void* ptr);

// ============================================================================
// 128. Main Thread Command Gate
// ============================================================================

typedef bool (*MocktailRustMainThreadCommandCb)(void* context);

void* mocktail_rust_main_thread_command_gate_new(void);
void mocktail_rust_main_thread_command_gate_free(void* ptr);
void mocktail_rust_main_thread_command_gate_activate(void* ptr);
bool mocktail_rust_main_thread_command_gate_register(
    void* ptr,
    MocktailRustMainThreadCommandCb callback,
    void* context);
bool mocktail_rust_main_thread_command_gate_invoke(void* ptr);
void mocktail_rust_main_thread_command_gate_clear(void* ptr);
void mocktail_rust_main_thread_command_gate_deactivate(void* ptr);

// ============================================================================
// 129. Platform Event Observer Gate
// ============================================================================

typedef void (*MocktailRustPlatformEventDispatchFn)(
    void* target_box,
    const void* event_ptr);
typedef void (*MocktailRustDestroyTargetFn)(void* target_box);

void* mocktail_rust_platform_event_observer_gate_new(void);
void mocktail_rust_platform_event_observer_gate_free(void* ptr);
bool mocktail_rust_platform_event_observer_gate_activate(void* ptr);
void mocktail_rust_platform_event_observer_gate_deactivate(void* ptr);
// Takes ownership of target_box only when returning true.
bool mocktail_rust_platform_event_observer_gate_register(
    void* ptr,
    MocktailRustPlatformEventDispatchFn dispatch,
    void* target_box,
    MocktailRustDestroyTargetFn destroy_target);
void mocktail_rust_platform_event_observer_gate_clear(void* ptr);
bool mocktail_rust_platform_event_observer_gate_has_observer(void* ptr);
void mocktail_rust_platform_event_observer_gate_notify(
    void* ptr,
    const void* event_ptr);

// ============================================================================
// 130. Present Observer Registry & Present Lifecycle Gate
// ============================================================================

typedef void (*MocktailRustPresentObserverCb)(
    void* context,
    uint64_t frame_serial);

void* mocktail_rust_present_observer_registry_new(void);
void mocktail_rust_present_observer_registry_free(void* ptr);
bool mocktail_rust_present_observer_registry_register(
    void* ptr,
    MocktailRustPresentObserverCb observer,
    void* context);
void mocktail_rust_present_observer_registry_clear(void* ptr);
void mocktail_rust_present_observer_registry_notify(
    void* ptr,
    uint64_t frame_serial);

void* mocktail_rust_present_lifecycle_gate_new(void);
void mocktail_rust_present_lifecycle_gate_free(void* ptr);
bool mocktail_rust_present_lifecycle_gate_activate(void* ptr);
void mocktail_rust_present_lifecycle_gate_deactivate(void* ptr);
bool mocktail_rust_present_lifecycle_gate_register(
    void* ptr,
    MocktailRustPresentObserverCb observer,
    void* context);
void mocktail_rust_present_lifecycle_gate_clear(void* ptr);
bool mocktail_rust_present_lifecycle_gate_enter_present(void* ptr);
void mocktail_rust_present_lifecycle_gate_notify_observer(
    void* ptr,
    uint64_t frame_serial);
void mocktail_rust_present_lifecycle_gate_exit_present(void* ptr);

// ============================================================================
// 131. Roblox Text Display State & Password Masking
// ============================================================================

enum {
    MOCKTAIL_RUST_TEXT_DISPLAY_EVENT_SHOW = 0,
    MOCKTAIL_RUST_TEXT_DISPLAY_EVENT_UPDATE = 1,
    MOCKTAIL_RUST_TEXT_DISPLAY_EVENT_HIDE = 2,
};

enum {
    MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_INVALID_EVENT = -1,
    MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_NOOP = 0,
    MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_HIDE_CLEAR = 1,
    MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_BUILD_PRESENTATION = 2,
};

enum {
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_NULL_OUT = -1,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_OK = 0,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_GENERATION = 1,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_VIEWPORT = 2,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_UTF8_PTR = 3,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_UTF8 = 4,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_PASSWORD_OVERFLOW = 5,
    MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_BUFFER_TOO_SMALL = 6,
};

typedef struct MocktailRustTextOverlayGeometryResult {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
    bool used_fallback;
} MocktailRustTextOverlayGeometryResult;

typedef struct MocktailRustTextPresentationMetrics {
    size_t codepoint_count;
    size_t display_bytes;
    size_t caret_utf8_byte;
    size_t selection_begin_utf8_byte;
    size_t selection_end_utf8_byte;
    bool is_password;
} MocktailRustTextPresentationMetrics;

int32_t mocktail_rust_text_overlay_viewport_coordinate_size(
    int32_t extent,
    float density_scale);
bool mocktail_rust_text_overlay_resolve_geometry(
    int32_t area_x,
    int32_t area_y,
    int32_t area_w,
    int32_t area_h,
    int32_t vp_w,
    int32_t vp_h,
    float density_scale,
    MocktailRustTextOverlayGeometryResult* out_geom);
int32_t mocktail_rust_text_display_decide_apply(
    int32_t event,
    uint64_t update_generation,
    bool current_visible,
    uint64_t current_generation);
int32_t mocktail_rust_text_display_prepare_presentation(
    uint64_t generation,
    int32_t vp_w,
    int32_t vp_h,
    float density_scale,
    int32_t text_input_type,
    const char* utf8,
    size_t utf8_size,
    int32_t cursor_utf16,
    int32_t selection_begin_utf16,
    int32_t selection_end_utf16,
    MocktailRustTextPresentationMetrics* out_metrics);
int32_t mocktail_rust_text_display_write_password_bullets(
    size_t codepoint_count,
    uint8_t* out_buf,
    size_t out_cap);

// ============================================================================
// 132. Visible Text Window Slicing
// ============================================================================

typedef struct MocktailRustVisibleTextWindow {
    size_t begin;
    size_t end;
    size_t caret_byte;
    size_t selection_begin_byte;
    size_t selection_end_byte;
} MocktailRustVisibleTextWindow;

int mocktail_rust_text_visible_window(
    const uint8_t* text,
    size_t text_len,
    size_t caret_byte,
    size_t selection_begin_byte,
    size_t selection_end_byte,
    size_t max_window_bytes,
    MocktailRustVisibleTextWindow* out_window);

// ============================================================================
// 133. General Bounded UTF-8 -> UTF-16 Surrogate Encoder
// ============================================================================

int32_t mocktail_rust_utf8_to_utf16_bounded(
    const char* utf8_str,
    size_t utf8_len,
    size_t max_bytes,
    uint16_t* out_utf16,
    size_t out_cap,
    size_t* out_len);

// ============================================================================
// 134. Runtime Bridges (Experience Launch / Runtime Config / Browser Service)
// ============================================================================

typedef void (*MocktailExperienceLaunchStringCallback)(
    void* ctx, uint32_t field_index, const char* ptr, size_t len);
typedef void (*MocktailExperienceLaunchCanonicalCallback)(
    void* ctx, const char* ptr, size_t len);

int32_t mocktail_rust_parse_experience_launch_json_full(
    const char* json_ptr,
    size_t json_len,
    MocktailRustExperienceLaunchData* out_data,
    void* ctx,
    MocktailExperienceLaunchStringCallback on_string,
    MocktailExperienceLaunchCanonicalCallback on_canonical,
    char* err_buf,
    size_t err_cap);

typedef void (*MocktailRuntimeConfigKvCallback)(
    void* ctx,
    const char* key,
    size_t key_len,
    const char* val,
    size_t val_len);

int32_t mocktail_rust_parse_runtime_config_yaml_kv(
    const uint8_t* yaml_bytes,
    size_t yaml_len,
    void* ctx,
    MocktailRuntimeConfigKvCallback emit_kv,
    char* out_error,
    size_t error_cap);

typedef struct MocktailRustRuntimeConfigPolicyFlags {
    int32_t frame_rate_valid;
    int32_t device_profile_valid;
    int32_t has_usable_input;
    int32_t graphics_backend_valid;
    int32_t theme_mode_valid;
    int32_t high_dpi_valid;
    int32_t vsync_mode_valid;
    int32_t present_mode_valid;
    int32_t audio_output_device_valid;
    int32_t audio_input_device_valid;
    int32_t memory_limit_valid;
    int32_t game_mode_valid;
    int32_t physics_worker_mode_valid;
    int32_t fleasion_valid;
    int32_t ca_bundle_valid;
    int32_t discord_rpc_valid;
    int32_t micup_rpc_valid;
} MocktailRustRuntimeConfigPolicyFlags;

int32_t mocktail_rust_validate_runtime_config_policy(
    const MocktailRustRuntimeConfigPolicyFlags* flags,
    int32_t for_export,
    char* out_error,
    size_t error_cap);

typedef struct MocktailRustBrowserServiceCommandHeader {
    int32_t command_type;
    int32_t has_title;
    int32_t has_visible;
    int32_t visible;
    int32_t modal;
    int32_t has_back_navigation_disabled;
    int32_t back_navigation_disabled;
    int32_t show_domain_as_title;
} MocktailRustBrowserServiceCommandHeader;

typedef void (*MocktailBrowserServiceStringCallback)(
    void* ctx, uint32_t field_kind, const char* ptr, size_t len);

int32_t mocktail_rust_validate_browser_service_open_url(
    const char* payload_ptr,
    size_t payload_len,
    char* err_buf,
    size_t err_cap);

int32_t mocktail_rust_parse_browser_service_command_full(
    const char* json_str,
    size_t json_len,
    MocktailRustBrowserServiceCommandHeader* out_header,
    void* ctx,
    MocktailBrowserServiceStringCallback on_string,
    char* err_buf,
    size_t err_cap);

int32_t mocktail_rust_browser_service_can_queue_outgoing(
    size_t queued_events,
    size_t queued_bytes,
    size_t drain_events,
    size_t drain_bytes,
    size_t incoming_bytes);

// ============================================================================
// 135. Stateful Input & Gamepad Router
// ============================================================================

typedef struct MocktailRustInputRouterState MocktailRustInputRouterState;

typedef struct MocktailRustInputViewport {
    int32_t logical_width;
    int32_t logical_height;
    int32_t pixel_width;
    int32_t pixel_height;
    float density_scale;
} MocktailRustInputViewport;

typedef struct MocktailRustInputSnapshot {
    int32_t active;
    int32_t focused;
    MocktailRustInputViewport viewport;
    uint64_t mouse_events;
    uint64_t touch_events;
    uint64_t keyboard_events;
    uint64_t ignored_text_events;
    uint64_t text_events;
    uint64_t native_errors;
    uint32_t active_mouse_buttons;
    uint32_t active_touches;
    uint32_t active_keys;
    uint64_t gamepad_events;
    uint32_t detected_gamepads;
    uint32_t connected_gamepads;
} MocktailRustInputSnapshot;

typedef struct MocktailRustInputDispatchResult {
    int32_t state;
    int32_t kind;
    int32_t status_code;
} MocktailRustInputDispatchResult;

typedef struct MocktailRustInputCallbacks {
    int32_t has_mouse_move;
    int32_t has_mouse_button;
    int32_t has_mouse_wheel;
    int32_t has_touch;
    int32_t has_key;
    int32_t has_gamepad;
    int32_t (*mouse_move)(void* ctx, float x, float y, float dx, float dy);
    int32_t (*mouse_button)(void* ctx, float x, float y, int32_t pressed, int32_t button);
    int32_t (*mouse_wheel)(void* ctx, float x, float y, float delta_y);
    int32_t (*touch)(void* ctx, int32_t pointer_id, float x, float y, int32_t action, int32_t w, int32_t h);
    int32_t (*key)(void* ctx, int32_t pressed, int32_t scan_code, int32_t key_code, int32_t repeat);
    int32_t (*end_text_focus)(void* ctx);
    int32_t (*gamepad_supported_key)(void* ctx, int32_t device_id, int32_t key, int32_t supported, int32_t gp_type);
    int32_t (*gamepad_supported_motion)(void* ctx, int32_t device_id, int32_t axis, int32_t direction, int32_t supported, int32_t gp_type);
    int32_t (*gamepad_connect)(void* ctx, int32_t device_id, int32_t gp_type);
    int32_t (*gamepad_disconnect)(void* ctx, int32_t device_id);
    int32_t (*gamepad_button)(void* ctx, int32_t device_id, int32_t key, int32_t pressed);
    int32_t (*gamepad_axis)(void* ctx, int32_t device_id, int32_t axis, float x, float y, float z);
} MocktailRustInputCallbacks;

MocktailRustInputRouterState* mocktail_rust_input_router_new(void);
void mocktail_rust_input_router_free(MocktailRustInputRouterState* state);
void mocktail_rust_input_router_snapshot(
    const MocktailRustInputRouterState* state,
    MocktailRustInputSnapshot* out_snapshot);
int32_t mocktail_rust_input_router_is_active(
    const MocktailRustInputRouterState* state);
int32_t mocktail_rust_input_router_activate(
    MocktailRustInputRouterState* state,
    MocktailRustInputViewport viewport,
    int32_t initially_focused,
    char* err_buf,
    size_t err_cap);
int32_t mocktail_rust_input_router_deactivate(
    MocktailRustInputRouterState* state,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx);
int32_t mocktail_rust_input_router_prepare_routed_event(
    MocktailRustInputRouterState* state);
MocktailRustInputDispatchResult mocktail_rust_input_router_record_text_result(
    MocktailRustInputRouterState* state,
    int32_t handled,
    int32_t dispatched,
    int32_t failed);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_viewport(
    MocktailRustInputRouterState* state,
    MocktailRustInputViewport viewport,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_focus(
    MocktailRustInputRouterState* state,
    int32_t focused,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_mouse_motion(
    MocktailRustInputRouterState* state,
    float x,
    float y,
    float delta_x,
    float delta_y,
    int32_t relative_mode,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_mouse_button(
    MocktailRustInputRouterState* state,
    int32_t pressed,
    uint8_t sdl_button,
    float x,
    float y,
    int32_t relative_mode,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_mouse_wheel(
    MocktailRustInputRouterState* state,
    float delta_y,
    float mouse_x,
    float mouse_y,
    int32_t relative_mode,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_touch(
    MocktailRustInputRouterState* state,
    int32_t action_kind,
    int64_t touch_id,
    int64_t finger_id,
    float norm_x,
    float norm_y,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_key(
    MocktailRustInputRouterState* state,
    int32_t pressed,
    int32_t repeat,
    uint32_t scancode,
    uint32_t keycode,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_gamepad_connection(
    MocktailRustInputRouterState* state,
    int64_t instance_id,
    int32_t connected,
    int32_t remapped,
    int32_t family,
    const char* name,
    uint32_t buttons_mask,
    uint32_t axes_mask,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_gamepad_button(
    MocktailRustInputRouterState* state,
    int64_t instance_id,
    uint8_t button,
    int32_t pressed,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);
MocktailRustInputDispatchResult mocktail_rust_input_router_handle_gamepad_axis(
    MocktailRustInputRouterState* state,
    int64_t instance_id,
    uint8_t axis,
    int16_t value,
    const MocktailRustInputCallbacks* cb,
    void* cb_ctx,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 136. Full APK Signature Scheme Container & Merkle Digest Verifier
// ============================================================================

typedef int32_t (*MocktailApkVerifySigFn)(
    void* ctx,
    const uint8_t* pubkey,
    size_t pubkey_len,
    const uint8_t* signed_data,
    size_t signed_data_len,
    const uint8_t* signature,
    size_t signature_len,
    int32_t digest_kind,
    int32_t is_pss,
    char* err_buf,
    size_t err_cap);

typedef int32_t (*MocktailApkVerifyCertFn)(
    void* ctx,
    const uint8_t* encoded_cert,
    size_t encoded_cert_len,
    int32_t is_leaf,
    char* err_buf,
    size_t err_cap);

typedef void (*MocktailApkEmitFingerprintFn)(
    void* ctx, const char* hex_ptr, size_t hex_len);

int32_t mocktail_rust_verify_apk_signature_container(
    const uint8_t* file_bytes,
    size_t file_size,
    void* cb_ctx,
    MocktailApkVerifySigFn verify_sig,
    MocktailApkVerifyCertFn verify_cert,
    MocktailApkEmitFingerprintFn emit_fingerprint,
    char* err_buf,
    size_t err_cap);

// ============================================================================
// 137. Storage Paths, Payload Store & Host ABI Profile Loader (storage_paths)
// ============================================================================

typedef void (*MocktailRuntimePathsFieldCallback)(void* ctx, uint32_t field_id,
                                                  const char* ptr, size_t len);
typedef void (*MocktailPayloadStoreStringCallback)(void* ctx, const char* ptr,
                                                   size_t len);
typedef void (*MocktailPayloadStoreApprovalPathsCallback)(
    void* ctx, const char* profile_ptr, size_t profile_len,
    const char* compat_ptr, size_t compat_len, const char* receipt_ptr,
    size_t receipt_len);

enum {
  MOCKTAIL_RUNTIME_PATH_FIELD_PAYLOAD_ID = 0,
  MOCKTAIL_RUNTIME_PATH_FIELD_PAYLOAD_REL = 1,
  MOCKTAIL_RUNTIME_PATH_FIELD_COMPATIBILITY_REL = 2,
  MOCKTAIL_RUNTIME_PATH_FIELD_PROFILE_REL = 3,
  MOCKTAIL_RUNTIME_PATH_FIELD_RECEIPT_REL = 4,
  MOCKTAIL_RUNTIME_PATH_FIELD_GENERATION = 5,
};

struct MocktailRustHostBridgeEntry {
  uint64_t rva;
  int32_t kind;
  char label[65];
};

struct MocktailRustParsedHostAbiProfile {
  char build_id[65];
  char reference_build_id[65];
  char reference_payload_sha256[65];
  struct MocktailRustHostBridgeEntry bridge_entries[8];
  size_t bridge_entry_count;
  uint64_t allocator_object_slot;
  uint64_t empty_string_slot;
  uint64_t jni_singleton_slot;
  size_t jni_singleton_bytes;
  uint64_t arena_initializer;
  uint64_t allocator_thread_initializer;
  uint64_t arena_guard_slot;
  uint64_t arena_table_slot;
  size_t arena_table_slot_count;
  uint64_t native_allocator_allocate;
  uint64_t native_allocator_deallocate;
  uint64_t init_array_offset;
  size_t init_array_count;
  struct MocktailRustConstructorRange constructor_run_ranges[26];
  size_t constructor_run_range_count;
  struct MocktailRustConstructorRange native_mimalloc_constructor_run_ranges[26];
  size_t native_mimalloc_constructor_run_range_count;
  size_t native_mimalloc_thread_initializer_after_constructor;
  uint64_t native_pre_jni_registry_initializer;
  uint64_t native_pre_jni_registry_slot;
  int32_t default_allocator_strategy;
  uint8_t host_allocator_bridges_supported;
  uint64_t derivation_code_rvas[7];
  size_t derivation_code_rva_count;
};

struct MocktailRustParsedApprovalReceipt {
  char generation[41];
  char runtime_build_id[41];
  char canary_runtime_sha256[65];
  char compatibility_manifest_sha256[65];
  char payload_fingerprint[65];
  char attestation_sha256_0[65];
  char attestation_sha256_1[65];
  uint8_t attestation_hashes_valid_array;
  uint8_t attestation_hash_0_is_string;
  uint8_t attestation_hash_1_is_string;
};

int32_t mocktail_rust_runtime_paths_parse_active_manifest(
    const char* json_ptr, size_t json_len,
    MocktailRuntimePathsFieldCallback on_field, void* ctx, char* err_buf,
    size_t err_cap);
int32_t mocktail_rust_runtime_paths_parse_active_approval_refs(
    const char* json_ptr, size_t json_len, const char* payload_id,
    MocktailRuntimePathsFieldCallback on_field, void* ctx,
    uint8_t* out_has_approval, char* err_buf, size_t err_cap);
int32_t mocktail_rust_runtime_paths_resolve_adjacent_roblox_asset_path(
    const char* roblox_library, const char* working_dir,
    MocktailPayloadStoreStringCallback on_path, void* ctx);

int32_t mocktail_rust_payload_store_parse_manifest_identity(
    const char* json_ptr, size_t json_len,
    MocktailPayloadStoreStringCallback on_payload_id, void* ctx, char* err_buf,
    size_t err_cap);
int32_t mocktail_rust_payload_store_build_activation_manifest(
    const char* payload_id, const char* version_name, uint64_t version_code,
    const char* build_id, const char* library_sha256,
    const char* approval_generation, MocktailPayloadStoreStringCallback on_json,
    void* ctx);
int32_t mocktail_rust_payload_store_inspect_manifest_json(
    const char* json_ptr, size_t json_len, const char* expected_version_name,
    uint64_t expected_version_code, const char* expected_build_id,
    const char* expected_library_sha256,
    MocktailPayloadStoreApprovalPathsCallback on_approval_paths, void* ctx,
    uint8_t* out_has_approval, char* err_buf, size_t err_cap);
int32_t mocktail_rust_payload_store_persist_payload_sha256(
    const char* json_ptr, size_t json_len, const char* library_sha256,
    MocktailPayloadStoreStringCallback on_updated_json, void* ctx,
    uint8_t* out_needs_write, char* err_buf, size_t err_cap);
int32_t mocktail_rust_payload_store_build_status_json(
    const char* update_json_path, const char* current_json_ptr,
    size_t current_json_len, const char* previous_json_ptr,
    size_t previous_json_len, MocktailPayloadStoreStringCallback on_json,
    void* ctx);

void mocktail_rust_host_abi_set_hashing_fault_for_testing(bool enabled);
int32_t mocktail_rust_host_abi_sha256_hex(const uint8_t* bytes_ptr,
                                          size_t bytes_len, size_t max_chars,
                                          char* out_hex, size_t hex_cap);
bool mocktail_rust_host_abi_validate_payload_id(const char* payload_id,
                                                const char* build_id);
bool mocktail_rust_host_abi_validate_canary_run_id(const char* run_id,
                                                   const char* payload_id,
                                                   size_t run);
int32_t mocktail_rust_host_abi_parse_profile_json(
    const char* json_ptr, size_t json_len, bool is_x86_64, size_t pointer_align,
    uint64_t uintptr_max, struct MocktailRustParsedHostAbiProfile* out_profile,
    char* err_buf, size_t err_cap);
int32_t mocktail_rust_host_abi_validate_profile_identity(
    const char* json_ptr, size_t json_len, const char* profile_build_id,
    const char* reference_build_id, const char* reference_payload_sha256,
    const char* canonical_payload_path, const char* expected_launch_build_id,
    char* out_payload_sha256, size_t sha_cap, char* out_payload_id,
    size_t pid_cap);
int32_t mocktail_rust_host_abi_parse_receipt_json(
    const char* json_ptr, size_t json_len, const char* receipt_path,
    const char* canonical_payload_path, const char* payload_sha256,
    const char* profile_sha256, const char* payload_id, const char* build_id,
    struct MocktailRustParsedApprovalReceipt* out_receipt, char* err_buf,
    size_t err_cap);
int32_t mocktail_rust_host_abi_validate_canary_attestation_json(
    const char* json_ptr, size_t json_len, size_t expected_run,
    const char* payload_id, const char* payload_fingerprint,
    const char* profile_sha256, const char* compatibility_manifest_sha256,
    const char* runtime_sha256, const char* runtime_build_id, char* out_sha256,
    size_t sha_cap, MocktailPayloadStoreStringCallback on_run_id, void* ctx,
    char* err_buf, size_t err_cap);
int32_t mocktail_rust_host_abi_verify_receipt_evidence(
    const struct MocktailRustParsedApprovalReceipt* receipt,
    const char* profile_sha256, const char* manifest_sha256,
    const char* canary_sha_0, const char* run_id_0, const char* canary_sha_1,
    const char* run_id_1, char* err_buf, size_t err_cap);

// ============================================================================
// 138. Updater JSON Migration Helpers (Zip, Payload, APKPure, Pinned, State)
// ============================================================================

typedef void (*MocktailZipEntryCallback)(
    void* ctx, const char* name, size_t name_len, uint64_t uncompressed_size,
    bool directory, bool symbolic_link);

struct MocktailRustStrSlice {
  const char* ptr;
  size_t len;
};

struct MocktailRustPayloadInfoView {
  struct MocktailRustStrSlice package_name;
  struct MocktailRustStrSlice version_name;
  uint64_t version_code;
  struct MocktailRustStrSlice build_id;
  struct MocktailRustStrSlice library_sha256;
  struct MocktailRustStrSlice base_apk_sha256;
  struct MocktailRustStrSlice split_apk_sha256;
  size_t asset_file_count;
  struct MocktailRustStrSlice asset_tree_sha256;
  struct MocktailRustStrSlice payload_id;
};

typedef void (*MocktailPayloadInfoCallback)(
    void* ctx, const struct MocktailRustPayloadInfoView* info);

struct MocktailRustApkMetadataRequest {
  const char* version_name;
  uint64_t version_code;
  const char* abi;
  const char* elf_build_id;
  const char* library_sha256;
  const char* base_apk_sha256;
  const char* split_apk_hash_key;
  const char* split_apk_sha256;
  const char* const* signing_certs;
  size_t signing_certs_count;
  size_t asset_file_count;
  const char* asset_tree_sha256;
  const char* source;
  const char* imported_at;
  bool exact_supported;
  bool monolithic;
};

typedef void (*MocktailCandidateActivationCallback)(
    void* ctx, const char* generation, size_t gen_len,
    const char* approval_ref, size_t approval_len, const char* profile_ref,
    size_t profile_len, const char* compat_ref, size_t compat_len);

struct MocktailRustCandidateEvidenceRequest {
  const char* receipt_ptr;
  size_t receipt_len;
  const char* canary1_ptr;
  size_t canary1_len;
  const char* canary2_ptr;
  size_t canary2_len;
  const char* payload_id;
  const char* generation;
  const char* canonical_library_path;
  const char* elf_build_id;
  const char* library_sha256;
  const char* fingerprint;
  const char* profile_sha256;
  const char* compatibility_sha256;
};

typedef bool (*MocktailTrustedUrlCallback)(void* ctx, const char* url,
                                           size_t url_len);

typedef void (*MocktailPinnedArchiveCallback)(
    void* ctx, const char* filename, size_t filename_len, const char* url,
    size_t url_len, const char* sha256, size_t sha256_len, uint64_t size);

struct MocktailRustUpdateState;

int mocktail_rust_zip_list_entries_cb(const char* archive_path,
                                      size_t max_entries,
                                      MocktailZipEntryCallback on_entry,
                                      void* ctx, char* out_err, size_t err_cap);
int mocktail_rust_payload_inspect_cb(const char* payload_dir,
                                     MocktailPayloadInfoCallback on_info,
                                     void* ctx, char* out_err, size_t err_cap);
int mocktail_rust_payload_verify_cb(const char* payload_dir,
                                    MocktailPayloadInfoCallback on_info,
                                    void* ctx, char* out_err, size_t err_cap);
int mocktail_rust_apkpure_parse_exact_urls_cb(
    const uint8_t* metadata, size_t meta_len, const char* version,
    uint64_t version_code, MocktailPayloadStoreStringCallback on_url, void* ctx,
    char* out_err, size_t err_cap);
int32_t mocktail_rust_apk_parse_trusted_certificates(
    const char* json_ptr, size_t json_len,
    MocktailPayloadStoreStringCallback on_sha256, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_apk_build_payload_metadata(
    const struct MocktailRustApkMetadataRequest* req,
    MocktailPayloadStoreStringCallback on_json, void* ctx);
int32_t mocktail_rust_candidate_approval_parse_activation(
    const char* activation_ptr, size_t activation_len, const char* payload_id,
    MocktailCandidateActivationCallback on_parsed, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_candidate_approval_verify_evidence(
    const struct MocktailRustCandidateEvidenceRequest* req, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_pinned_apk_find_source(
    const char* manifest_path, const char* version_name, uint64_t version_code,
    const char* abi, uint64_t max_archive_bytes,
    MocktailTrustedUrlCallback is_trusted_url,
    MocktailPayloadStoreStringCallback on_build_id,
    MocktailPinnedArchiveCallback on_archive, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_http_read_resume_etag(const char* state_path,
                                            const char* expected_url,
                                            char* out_etag, size_t etag_cap);
int32_t mocktail_rust_http_write_resume_state(const char* state_path,
                                              const char* url,
                                              const char* etag);

struct MocktailRustUpdateState* mocktail_rust_update_state_new(
    const char* state_path);
void mocktail_rust_update_state_free(struct MocktailRustUpdateState* state);
void mocktail_rust_update_state_save_phase(
    struct MocktailRustUpdateState* state, const char* phase);
void mocktail_rust_update_state_set_metadata_status(
    struct MocktailRustUpdateState* state, const char* status);
void mocktail_rust_update_state_record_latest_check(
    struct MocktailRustUpdateState* state, bool available,
    const char* version_name, uint64_t version_code);
bool mocktail_rust_update_state_get_latest_downloaded(
    const struct MocktailRustUpdateState* state, char* out_version_name,
    size_t ver_cap, uint64_t* out_version_code, char* out_payload_id,
    size_t pid_cap);
void mocktail_rust_update_state_record_latest_downloaded(
    struct MocktailRustUpdateState* state, const char* payload_id,
    const char* version_name, uint64_t version_code);
void mocktail_rust_update_state_finish_and_save(
    struct MocktailRustUpdateState* state, bool active_valid,
    const char* active_payload_id, const char* active_version_name,
    uint64_t active_version_code, uint64_t supported_version_code,
    bool succeeded, bool changed, const char* message, const char* error,
    bool* out_stale);

// 139. Runtime Policies, Compat Build Profile & WebView/Discord JSON Helpers
typedef struct MocktailRustBuildProfileView {
  struct MocktailRustStrSlice version_name;
  int32_t version_code;
  struct MocktailRustStrSlice elf_build_id;
  int32_t status;
  bool default_allowed;
  bool allow_legacy_binary_patches;
  bool allow_host_abi_bridges;
  bool allow_host_constructor_replay;
  bool has_fullscreen_setter_rva;
  uintptr_t fullscreen_setter_rva;
  bool has_fmod_bridge;
  uintptr_t fmod_vtable_rva;
  uintptr_t fmod_string_constructor_rva;
  uintptr_t fmod_count_method_rva;
  uintptr_t fmod_info_method_rva;
  uintptr_t fmod_current_method_rva;
  uintptr_t fmod_select_method_rva;
  uint8_t fmod_vtable_layout_version;
  uintptr_t fmod_input_method_rvas[4];
  struct MocktailRustStrSlice reason;
} MocktailRustBuildProfileView;

typedef void (*MocktailBuildProfileCallback)(
    void* ctx, const MocktailRustBuildProfileView* profile);

typedef struct MocktailRustDiscordActivity {
  const char* details;
  size_t details_len;
  const char* state;
  size_t state_len;
  bool has_start_timestamp;
  int64_t start_timestamp;
  const char* large_image;
  size_t large_image_len;
  const char* large_text;
  size_t large_text_len;
  const char* button_label;
  size_t button_label_len;
  const char* button_url;
  size_t button_url_len;
} MocktailRustDiscordActivity;

typedef struct MocktailRustWebViewOpenView {
  struct MocktailRustStrSlice url;
  bool has_title;
  struct MocktailRustStrSlice title;
  bool has_is_visible;
  bool is_visible;
  bool has_window_type;
  struct MocktailRustStrSlice window_type;
  bool has_show_domain_as_title;
  bool show_domain_as_title;
  bool has_back_button_visible;
  bool back_button_visible;
  bool has_hide_header;
  bool hide_header;
  bool has_search_type;
  struct MocktailRustStrSlice search_type;
} MocktailRustWebViewOpenView;

typedef void (*MocktailWebViewOpenCallback)(
    void* ctx, const MocktailRustWebViewOpenView* view);

typedef struct MocktailRustWebViewMutationView {
  bool has_url;
  struct MocktailRustStrSlice url;
  bool has_title;
  struct MocktailRustStrSlice title;
  bool has_is_visible;
  bool is_visible;
  bool has_window_type;
  struct MocktailRustStrSlice window_type;
  bool has_show_domain_as_title;
  bool show_domain_as_title;
  bool has_search_type;
  struct MocktailRustStrSlice search_type;
} MocktailRustWebViewMutationView;

typedef void (*MocktailWebViewMutationCallback)(
    void* ctx, const MocktailRustWebViewMutationView* view);

typedef void (*MocktailCaptchaOpenCallback)(
    void* ctx, bool is_login, const char* normalized_type, size_t type_len,
    const char* credential_value, size_t value_len);

int32_t mocktail_rust_json_normalize_object(
    const char* json_ptr, size_t json_len, bool allow_comments,
    MocktailPayloadStoreStringCallback on_json, void* ctx);
void mocktail_rust_support_bundle_format_payload_summary(
    const char* manifest_ptr, size_t manifest_len,
    MocktailPayloadStoreStringCallback on_summary, void* ctx);
int32_t mocktail_rust_find_build_profile(
    const char* manifest_path, const char* build_id, size_t build_id_len,
    MocktailBuildProfileCallback on_profile, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_performance_merge_overrides(
    bool multithreaded_rendering, int32_t physics_worker_mode,
    bool physics_worker_mode_valid, int32_t available_physical_cores,
    const char* graphics_quality_ptr, size_t graphics_quality_len,
    const char* base_json_ptr, size_t base_json_len,
    MocktailPayloadStoreStringCallback on_json, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_platform_cache_strip_hydration_keys(
    const char* json_ptr, size_t json_len, bool* out_changed,
    MocktailPayloadStoreStringCallback on_json, void* ctx);
int32_t mocktail_rust_platform_cache_build_fingerprint(
    int32_t schema_version, const char* revision_ptr, size_t revision_len,
    MocktailPayloadStoreStringCallback on_json, void* ctx);
int32_t mocktail_rust_platform_cache_read_theme(
    const char* json_ptr, size_t json_len, int64_t authenticated_user_id,
    bool* out_has_theme, bool* out_dark_theme);
int32_t mocktail_rust_platform_cache_apply_theme(
    const char* json_ptr, size_t json_len, bool has_storage,
    int64_t authenticated_user_id, bool dark_theme, bool* out_changed,
    MocktailPayloadStoreStringCallback on_json, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_browser_tracker_read_stored_id(
    const char* json_ptr, size_t json_len, bool* out_has_id, char* out_id,
    size_t id_cap);
int32_t mocktail_rust_browser_tracker_set_stored_id(
    const char* json_ptr, size_t json_len, const char* id_ptr, size_t id_len,
    MocktailPayloadStoreStringCallback on_json, void* ctx);
int32_t mocktail_rust_browser_tracker_parse_init_response(
    const char* body_ptr, size_t body_len, char* out_id, size_t id_cap);
int32_t mocktail_rust_discord_parse_rpc_error(
    const char* payload_ptr, size_t payload_len, int64_t* out_code,
    char* out_msg, size_t msg_cap);
int32_t mocktail_rust_discord_build_handshake(
    const char* app_id_ptr, size_t app_id_len,
    MocktailPayloadStoreStringCallback on_json, void* ctx);
bool mocktail_rust_discord_is_ready_event(const char* payload_ptr,
                                          size_t payload_len);
int32_t mocktail_rust_discord_build_set_activity(
    int32_t pid, const struct MocktailRustDiscordActivity* activity,
    uint64_t nonce, MocktailPayloadStoreStringCallback on_json, void* ctx);
int32_t mocktail_rust_discord_parse_universe_id(const char* json_ptr,
                                                size_t json_len,
                                                int64_t* out_universe_id);
int32_t mocktail_rust_discord_parse_game_name(const char* json_ptr,
                                              size_t json_len, char* out_name,
                                              size_t name_cap);
int32_t mocktail_rust_discord_parse_icon_url(const char* json_ptr,
                                             size_t json_len, char* out_url,
                                             size_t url_cap);
int32_t mocktail_rust_webview_parse_open_json(
    const char* json_ptr, size_t json_len, MocktailWebViewOpenCallback on_parsed,
    void* ctx, char* out_err, size_t err_cap);
int32_t mocktail_rust_webview_parse_mutation_json(
    const char* json_ptr, size_t json_len,
    MocktailWebViewMutationCallback on_parsed, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_webview_parse_captcha_open_json(
    const char* json_ptr, size_t json_len,
    MocktailCaptchaOpenCallback on_parsed, void* ctx, char* out_err,
    size_t err_cap);

// 140. HostAbi Deriver JSON Helpers
typedef void (*MocktailDeriverSpecCallback)(void* ctx, const char* name,
                                            size_t name_len,
                                            uint64_t reference_rva,
                                            size_t instruction_count,
                                            bool registry_size_may_change,
                                            size_t minimum_anchor_bytes);

typedef struct MocktailRustDeriverRuntimeAnchors {
  bool has_fullscreen_setter;
  uint64_t fullscreen_setter_rva;
  bool has_fmod;
  uint64_t fmod_vtable_rva;
  uint64_t fmod_string_constructor_rva;
  uint64_t fmod_count_method_rva;
  uint64_t fmod_info_method_rva;
  uint64_t fmod_current_method_rva;
  uint64_t fmod_select_method_rva;
  int32_t fmod_layout_version;
  uint64_t fmod_input_methods[4];
} MocktailRustDeriverRuntimeAnchors;

typedef struct MocktailRustDeriverPlan {
  size_t candidate_constructor_indices[4];
  uint64_t candidate_constructor_rvas[4];
  uint64_t allocator_object_slot_rva;
  uint64_t empty_string_slot_rva;
  uint64_t jni_singleton_slot_rva;
  uint64_t arena_guard_slot_rva;
  uint64_t arena_table_slot_rva;
  uint64_t old_registry_initializer_rva;
  uint64_t old_registry_slot_rva;
} MocktailRustDeriverPlan;

typedef struct MocktailRustDeriverBuildInputs {
  struct MocktailRustStrSlice ref_build_id;
  struct MocktailRustStrSlice ref_sha256;
  struct MocktailRustStrSlice cand_build_id;
  struct MocktailRustStrSlice cand_sha256;
  size_t reference_init_count;
  size_t candidate_init_count;
  uint64_t init_array_offset;
  uint64_t bridge_rvas[6];
  uint64_t arena_initializer_rva;
  uint64_t allocator_thread_initializer_rva;
  uint64_t registry_initializer_rva;
  uint64_t registry_slot_rva;
  uint64_t allocator_object_initializer_rva;
  uint64_t empty_string_initializer_rva;
  uint64_t jni_singleton_initializer_rva;
  uint64_t allocator_object_slot_rva;
  uint64_t empty_string_slot_rva;
  uint64_t jni_singleton_slot_rva;
  uint64_t arena_guard_slot_rva;
  uint64_t arena_table_slot_rva;
  uint64_t candidate_constructor_rvas[4];
  size_t candidate_constructor_indices[4];
  bool has_derived_fullscreen_setter;
  uint64_t derived_fullscreen_setter_rva;
  bool has_derived_fmod;
  uint64_t derived_fmod_vtable_rva;
  uint64_t derived_fmod_string_constructor_rva;
  uint64_t derived_fmod_count_method_rva;
  uint64_t derived_fmod_info_method_rva;
  uint64_t derived_fmod_current_method_rva;
  uint64_t derived_fmod_select_method_rva;
  int32_t derived_fmod_layout_version;
  bool derived_fmod_has_input;
  uint64_t derived_fmod_input_methods[4];
} MocktailRustDeriverBuildInputs;

int32_t mocktail_rust_deriver_read_sidecar_identity(
    const char* json_ptr, size_t json_len, const char* sidecar_path_ptr,
    size_t sidecar_path_len, char* out_build_id, size_t build_id_cap,
    char* out_payload_id, size_t payload_id_cap, char* out_err, size_t err_cap);
int32_t mocktail_rust_deriver_load_candidate_metadata(
    const char* json_ptr, size_t json_len, const char* metadata_path_ptr,
    size_t metadata_path_len, const char* dir_filename_ptr,
    size_t dir_filename_len, const char* candidate_build_id_ptr,
    size_t candidate_build_id_len, const char* candidate_sha256_ptr,
    size_t candidate_sha256_len, const char* guest_abi_ptr,
    size_t guest_abi_len, char* out_version_name, size_t version_name_cap,
    uint64_t* out_version_code, char* out_err, size_t err_cap);
int32_t mocktail_rust_deriver_load_runtime_anchors(
    const struct MocktailRustStrSlice* manifest_jsons_ptr,
    const struct MocktailRustStrSlice* manifest_paths_ptr,
    size_t manifest_count, const char* reference_build_id_ptr,
    size_t reference_build_id_len,
    MocktailRustDeriverRuntimeAnchors* out_anchors, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_deriver_validate_reference_identity(
    const char* sidecar_ptr, size_t sidecar_len,
    const char* ref_build_id_ptr, size_t ref_build_id_len,
    const char* ref_sha256_ptr, size_t ref_sha256_len, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_deriver_extract_specs(
    const char* sidecar_ptr, size_t sidecar_len,
    MocktailDeriverSpecCallback on_spec, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_deriver_check_init_array(
    const char* sidecar_ptr, size_t sidecar_len, size_t reference_init_len,
    size_t candidate_init_len, size_t* out_reference_count, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_deriver_resolve_constructors_and_seeds(
    const char* sidecar_ptr, size_t sidecar_len,
    const uint64_t* reference_init_ptr, size_t reference_init_len,
    const uint64_t* candidate_init_ptr, size_t candidate_init_len,
    const uint64_t* ctor_candidate_rvas_ptr,
    const uint64_t* ctor_ref_first_insn_rvas_ptr,
    MocktailRustDeriverPlan* out_plan, char* out_err, size_t err_cap);
int32_t mocktail_rust_deriver_build_documents(
    const char* sidecar_ptr, size_t sidecar_len, const char* metadata_ptr,
    size_t metadata_len, const MocktailRustDeriverBuildInputs* inputs,
    MocktailPayloadStoreStringCallback on_profile_json,
    MocktailPayloadStoreStringCallback on_compatibility_json, void* ctx,
    char* out_err, size_t err_cap);

typedef struct MocktailRustMicupConfig {
  const char* gateway_url_ptr;
  size_t gateway_url_len;
  const char* token_ptr;
  size_t token_len;
  const char* token_file_ptr;
  size_t token_file_len;
  const char* status_ptr;
  size_t status_len;
  const char* activity_mode_ptr;
  size_t activity_mode_len;
  const char* text_browsing_ptr;
  size_t text_browsing_len;
  const char* text_joining_ptr;
  size_t text_joining_len;
  const char* text_playing_ptr;
  size_t text_playing_len;
  const char* text_unknown_place_ptr;
  size_t text_unknown_place_len;
  const char* ca_bundle_ptr;
  size_t ca_bundle_len;
  const char* proxy_url_ptr;
  size_t proxy_url_len;
  const char* proxy_username_ptr;
  size_t proxy_username_len;
  const char* proxy_password_ptr;
  size_t proxy_password_len;
  int32_t enabled;
  int32_t show_place_name;
  int32_t show_elapsed_time;
} MocktailRustMicupConfig;

typedef struct MocktailRustMicupSession MocktailRustMicupSession;

int32_t mocktail_rust_micup_is_valid_status(const char* ptr, size_t len);
int32_t mocktail_rust_micup_is_valid_activity_mode(const char* ptr,
                                                   size_t len);
int32_t mocktail_rust_micup_is_valid_gateway_url(const char* ptr, size_t len);
int32_t mocktail_rust_micup_is_valid_token(const char* ptr, size_t len);
int32_t mocktail_rust_micup_is_valid_text(const char* ptr, size_t len,
                                          size_t max_bytes);
int32_t mocktail_rust_micup_build_activity_json(
    const char* activity_mode_ptr, size_t activity_mode_len,
    int32_t show_place_name, int32_t show_elapsed_time,
    const char* text_browsing_ptr, size_t text_browsing_len,
    const char* text_joining_ptr, size_t text_joining_len,
    const char* text_playing_ptr, size_t text_playing_len,
    const char* text_unknown_place_ptr, size_t text_unknown_place_len,
    int32_t phase, const char* place_name_ptr, size_t place_name_len,
    int64_t started_at_ms, int64_t current_ms, char* out_json, size_t out_cap,
    size_t* out_len);
int32_t mocktail_rust_micup_session_start(
    const MocktailRustMicupConfig* config,
    MocktailRustMicupSession** out_session, char* out_detail,
    size_t detail_cap);
int32_t mocktail_rust_micup_session_update(
    MocktailRustMicupSession* session, int32_t phase, int64_t place_id,
    const char* place_name_ptr, size_t place_name_len, int64_t started_at_ms,
    uint64_t revision);
void mocktail_rust_micup_session_stop(MocktailRustMicupSession* session);

typedef struct MocktailRustDiscordConfig {
  int32_t enabled;
  int32_t show_place_name;
  int32_t show_elapsed_time;
  int32_t join_enabled;
  int32_t public_servers_only;
  const char* join_button_label_ptr;
  size_t join_button_label_len;
  const char* application_id_ptr;
  size_t application_id_len;
  const char* text_browsing_ptr;
  size_t text_browsing_len;
  const char* text_joining_ptr;
  size_t text_joining_len;
  const char* text_playing_ptr;
  size_t text_playing_len;
  const char* text_state_ptr;
  size_t text_state_len;
  const char* text_unknown_place_ptr;
  size_t text_unknown_place_len;
} MocktailRustDiscordConfig;

typedef struct MocktailRustDiscordLaunchSlice {
  int64_t place_id;
  const char* game_instance_id_ptr;
  size_t game_instance_id_len;
  bool has_private_access;
} MocktailRustDiscordLaunchSlice;

typedef void (*MocktailDiscordMetadataInspectResultFn)(
    void* rust_out, const char* name_ptr, size_t name_len,
    const char* icon_url_ptr, size_t icon_url_len,
    bool should_fetch_after_publish, bool waiting_for_name);

typedef void (*MocktailDiscordMetadataInspectFn)(
    void* ctx, int32_t phase, int64_t place_id,
    MocktailDiscordMetadataInspectResultFn on_result, void* rust_out);

typedef bool (*MocktailDiscordMetadataRefreshFn)(
    void* ctx, int64_t place_id, int64_t* out_retry_delay_secs);

typedef struct MocktailRustDiscordMetadataCallbacks {
  void* ctx;
  MocktailDiscordMetadataInspectFn inspect;
  MocktailDiscordMetadataRefreshFn refresh;
} MocktailRustDiscordMetadataCallbacks;

typedef void (*MocktailDiscordActivityFieldsCallback)(
    void* ctx, const char* details_ptr, size_t details_len,
    const char* state_ptr, size_t state_len, bool has_start_timestamp,
    int64_t start_timestamp, const char* large_image_ptr,
    size_t large_image_len, const char* large_text_ptr, size_t large_text_len,
    const char* button_label_ptr, size_t button_label_len,
    const char* button_url_ptr, size_t button_url_len);

typedef struct MocktailRustDiscordSession MocktailRustDiscordSession;

int32_t mocktail_rust_discord_build_activity(
    const MocktailRustDiscordConfig* config, int32_t phase, bool has_request,
    const MocktailRustDiscordLaunchSlice* launch_slice,
    const char* place_name_ptr, size_t place_name_len,
    int64_t session_started_at, const char* place_icon_url_ptr,
    size_t place_icon_url_len, MocktailDiscordActivityFieldsCallback on_built,
    void* ctx);
int32_t mocktail_rust_discord_session_start(
    const MocktailRustDiscordConfig* config,
    const MocktailRustDiscordMetadataCallbacks* metadata_callbacks,
    MocktailRustDiscordSession** out_session, char* out_detail,
    size_t detail_cap);
int32_t mocktail_rust_discord_session_update(
    MocktailRustDiscordSession* session, int32_t phase, bool has_request,
    const MocktailRustDiscordLaunchSlice* launch_slice);
void mocktail_rust_discord_session_stop(MocktailRustDiscordSession* session);

typedef int32_t (*MocktailExternalLaunchDispatchFn)(
    void* ctx, const char* canonical_json_ptr, size_t canonical_json_len,
    int32_t* out_status_code, char* out_err, size_t err_cap);

typedef struct MocktailRustExternalLaunchBroker
    MocktailRustExternalLaunchBroker;

int32_t mocktail_rust_external_launch_resolve_socket_path(
    bool owner, const char* instance_key_ptr, size_t instance_key_len,
    char* out_path, size_t path_cap, int32_t* out_status, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_external_launch_broker_start(
    const char* socket_path_ptr, size_t socket_path_len,
    const char* instance_key_ptr, size_t instance_key_len,
    size_t maximum_pending_launches, int32_t forwarding_timeout_ms,
    bool has_initial, const char* initial_json_ptr, size_t initial_json_len,
    MocktailRustExternalLaunchBroker** out_broker, int32_t* out_status,
    char* out_err, size_t err_cap);
int32_t mocktail_rust_external_launch_forward_to_owner(
    const char* socket_path_ptr, size_t socket_path_len,
    const char* instance_key_ptr, size_t instance_key_len,
    int32_t forwarding_timeout_ms, const char* json_ptr, size_t json_len,
    int32_t* out_status, char* out_err, size_t err_cap);
int32_t mocktail_rust_external_launch_broker_queue_initial(
    MocktailRustExternalLaunchBroker* broker, const char* json_ptr,
    size_t json_len, int32_t* out_status, char* out_err, size_t err_cap);
int32_t mocktail_rust_external_launch_broker_drain(
    MocktailRustExternalLaunchBroker* broker, size_t maximum_requests,
    MocktailExternalLaunchDispatchFn on_dispatch, void* dispatch_ctx,
    int32_t* out_status, char* out_err, size_t err_cap);
int32_t mocktail_rust_external_launch_broker_shutdown(
    MocktailRustExternalLaunchBroker* broker, int32_t* out_status,
    char* out_err, size_t err_cap);
void mocktail_rust_external_launch_broker_destroy(
    MocktailRustExternalLaunchBroker* broker);
size_t mocktail_rust_external_launch_broker_pending_count(
    const MocktailRustExternalLaunchBroker* broker);
int32_t mocktail_rust_external_launch_broker_socket_path(
    const MocktailRustExternalLaunchBroker* broker, char* out_buf,
    size_t out_cap);

typedef void (*MocktailRustCookieStringCallback)(void* ctx, const char* data,
                                                 size_t len);

int32_t mocktail_rust_read_roblox_cookie_file(
    const char* path_ptr, size_t path_len, int32_t required,
    MocktailRustCookieStringCallback on_value,
    MocktailRustCookieStringCallback on_error, void* ctx);
int32_t mocktail_rust_remove_legacy_webview_cookies(const char* dir_ptr,
                                                    size_t dir_len);
int32_t mocktail_rust_cookie_helper_exchange(
    uint8_t operation, const char* profile_ptr, size_t profile_len,
    const char* cookie_ptr, size_t cookie_len, const char* install_libdir_ptr,
    size_t install_libdir_len, MocktailRustCookieStringCallback on_response,
    void* ctx);

typedef struct MocktailRustWebViewProcess MocktailRustWebViewProcess;

typedef void (*MocktailRustWebViewBytesCallback)(void* ctx, const char* data,
                                                 size_t len);
typedef void (*MocktailRustWebViewControlCallback)(void* ctx, uint8_t operation,
                                                   const char* payload,
                                                   size_t payload_len,
                                                   int32_t visible);
typedef void (*MocktailRustWebViewEventCallback)(void* ctx, uint8_t event_type,
                                                 const char* payload,
                                                 size_t payload_len);
typedef void (*MocktailRustWebViewExitFn)(void* ctx);

int32_t mocktail_rust_webview_validate_url(const char* url_ptr, size_t url_len,
                                           char* out_err, size_t err_cap);
int32_t mocktail_rust_webview_normalize_url(
    const char* url_ptr, size_t url_len,
    MocktailRustWebViewBytesCallback on_normalized, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_webview_decode_request(
    const char* req_ptr, size_t req_len,
    MocktailRustWebViewBytesCallback on_url, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_webview_decode_control_packet(
    const char* packet_ptr, size_t packet_len,
    MocktailRustWebViewControlCallback on_command, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_webview_encode_event_packet(
    uint8_t event_type, const char* payload_ptr, size_t payload_len,
    MocktailRustWebViewBytesCallback on_packet, void* ctx);
int32_t mocktail_rust_webview_decode_event_packet(
    const char* packet_ptr, size_t packet_len,
    MocktailRustWebViewEventCallback on_event, void* ctx, char* out_err,
    size_t err_cap);
int32_t mocktail_rust_webview_launch(
    const char* helper_ptr, size_t helper_len, const char* url_ptr,
    size_t url_len, void* observer_ctx, MocktailRustWebViewExitFn on_exit,
    MocktailRustWebViewExitFn on_drop,
    MocktailRustWebViewProcess** out_process, int32_t* out_pid, char* out_err,
    size_t err_cap);
void mocktail_rust_webview_process_release(
    MocktailRustWebViewProcess* process);
int32_t mocktail_rust_webview_process_running(
    const MocktailRustWebViewProcess* process);
int32_t mocktail_rust_webview_process_pid(
    const MocktailRustWebViewProcess* process);
int32_t mocktail_rust_webview_process_load_url(
    const MocktailRustWebViewProcess* process, const char* url_ptr,
    size_t url_len);
int32_t mocktail_rust_webview_process_set_title(
    const MocktailRustWebViewProcess* process, const char* title_ptr,
    size_t title_len);
int32_t mocktail_rust_webview_process_set_visible(
    const MocktailRustWebViewProcess* process, int32_t visible);
int32_t mocktail_rust_webview_process_evaluate_javascript(
    const MocktailRustWebViewProcess* process, const char* script_ptr,
    size_t script_len);
int32_t mocktail_rust_webview_process_set_back_navigation_disabled(
    const MocktailRustWebViewProcess* process, int32_t disabled);
int32_t mocktail_rust_webview_process_set_show_domain_as_title(
    const MocktailRustWebViewProcess* process, int32_t enabled);
int32_t mocktail_rust_webview_process_set_roblox_cookie(
    const MocktailRustWebViewProcess* process, const char* cookie_ptr,
    size_t cookie_len);
int32_t mocktail_rust_webview_process_clear_roblox_cookie(
    const MocktailRustWebViewProcess* process);
int32_t mocktail_rust_webview_process_wait_until_ready(
    const MocktailRustWebViewProcess* process, int64_t timeout_ms);
int32_t mocktail_rust_webview_process_drain_events(
    const MocktailRustWebViewProcess* process,
    MocktailRustWebViewEventCallback on_event, void* ctx);
int32_t mocktail_rust_webview_process_request_close(
    const MocktailRustWebViewProcess* process);

#ifdef __cplusplus
}
#endif

#endif  // MOCKTAIL_RUST_H_
