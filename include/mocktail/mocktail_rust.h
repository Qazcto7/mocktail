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

#ifdef __cplusplus
}
#endif

#endif  // MOCKTAIL_RUST_H_
