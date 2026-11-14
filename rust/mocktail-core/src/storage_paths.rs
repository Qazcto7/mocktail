use std::ffi::{c_char, c_int, c_void, CStr};
use std::path::Path;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{
    copy_error, copy_to_c_buffer, read_update_state_json_string, MocktailRustConstructorRange,
};

pub const K_RUNTIME_PATH_FIELD_PAYLOAD_ID: u32 = 0;
pub const K_RUNTIME_PATH_FIELD_PAYLOAD_REL: u32 = 1;
pub const K_RUNTIME_PATH_FIELD_COMPATIBILITY_REL: u32 = 2;
pub const K_RUNTIME_PATH_FIELD_PROFILE_REL: u32 = 3;
pub const K_RUNTIME_PATH_FIELD_RECEIPT_REL: u32 = 4;
pub const K_RUNTIME_PATH_FIELD_GENERATION: u32 = 5;

pub const K_MAXIMUM_INIT_ARRAY_ENTRIES: usize = 1024 * 1024;
pub const K_MAXIMUM_SEED_ALLOCATION_BYTES: usize = 16 * 1024 * 1024;
pub const K_MAXIMUM_ARENA_TABLE_SLOTS: usize = 16 * 1024 * 1024;
pub const K_MAX_HOST_BRIDGE_ENTRIES: usize = 8;
pub const K_MAX_CONSTRUCTOR_RUN_RANGES: usize = 26;

static HOST_ABI_HASHING_FAULT_FOR_TESTING: AtomicBool = AtomicBool::new(false);

pub type MocktailRuntimePathsFieldCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, field_id: u32, ptr: *const c_char, len: usize)>;

pub type MocktailPayloadStoreStringCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, ptr: *const c_char, len: usize)>;

pub type MocktailPayloadStoreApprovalPathsCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        profile_ptr: *const c_char,
        profile_len: usize,
        compat_ptr: *const c_char,
        compat_len: usize,
        receipt_ptr: *const c_char,
        receipt_len: usize,
    ),
>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustHostBridgeEntry {
    pub rva: u64,
    pub kind: i32,
    pub label: [c_char; 65],
}

impl Default for MocktailRustHostBridgeEntry {
    fn default() -> Self {
        Self {
            rva: 0,
            kind: 0,
            label: [0; 65],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustParsedHostAbiProfile {
    pub build_id: [c_char; 65],
    pub reference_build_id: [c_char; 65],
    pub reference_payload_sha256: [c_char; 65],
    pub bridge_entries: [MocktailRustHostBridgeEntry; K_MAX_HOST_BRIDGE_ENTRIES],
    pub bridge_entry_count: usize,
    pub allocator_object_slot: u64,
    pub empty_string_slot: u64,
    pub jni_singleton_slot: u64,
    pub jni_singleton_bytes: usize,
    pub arena_initializer: u64,
    pub allocator_thread_initializer: u64,
    pub arena_guard_slot: u64,
    pub arena_table_slot: u64,
    pub arena_table_slot_count: usize,
    pub native_allocator_allocate: u64,
    pub native_allocator_deallocate: u64,
    pub init_array_offset: u64,
    pub init_array_count: usize,
    pub constructor_run_ranges: [MocktailRustConstructorRange; K_MAX_CONSTRUCTOR_RUN_RANGES],
    pub constructor_run_range_count: usize,
    pub native_mimalloc_constructor_run_ranges:
        [MocktailRustConstructorRange; K_MAX_CONSTRUCTOR_RUN_RANGES],
    pub native_mimalloc_constructor_run_range_count: usize,
    pub native_mimalloc_thread_initializer_after_constructor: usize,
    pub native_pre_jni_registry_initializer: u64,
    pub native_pre_jni_registry_slot: u64,
    pub default_allocator_strategy: i32,
    pub host_allocator_bridges_supported: u8,
    pub derivation_code_rvas: [u64; 7],
    pub derivation_code_rva_count: usize,
}

impl Default for MocktailRustParsedHostAbiProfile {
    fn default() -> Self {
        Self {
            build_id: [0; 65],
            reference_build_id: [0; 65],
            reference_payload_sha256: [0; 65],
            bridge_entries: [MocktailRustHostBridgeEntry::default(); K_MAX_HOST_BRIDGE_ENTRIES],
            bridge_entry_count: 0,
            allocator_object_slot: 0,
            empty_string_slot: 0,
            jni_singleton_slot: 0,
            jni_singleton_bytes: 0,
            arena_initializer: 0,
            allocator_thread_initializer: 0,
            arena_guard_slot: 0,
            arena_table_slot: 0,
            arena_table_slot_count: 0,
            native_allocator_allocate: 0,
            native_allocator_deallocate: 0,
            init_array_offset: 0,
            init_array_count: 0,
            constructor_run_ranges: [MocktailRustConstructorRange::default();
                K_MAX_CONSTRUCTOR_RUN_RANGES],
            constructor_run_range_count: 0,
            native_mimalloc_constructor_run_ranges: [MocktailRustConstructorRange::default();
                K_MAX_CONSTRUCTOR_RUN_RANGES],
            native_mimalloc_constructor_run_range_count: 0,
            native_mimalloc_thread_initializer_after_constructor: 0,
            native_pre_jni_registry_initializer: 0,
            native_pre_jni_registry_slot: 0,
            default_allocator_strategy: 0,
            host_allocator_bridges_supported: 1,
            derivation_code_rvas: [0; 7],
            derivation_code_rva_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustParsedApprovalReceipt {
    pub generation: [c_char; 41],
    pub runtime_build_id: [c_char; 41],
    pub canary_runtime_sha256: [c_char; 65],
    pub compatibility_manifest_sha256: [c_char; 65],
    pub payload_fingerprint: [c_char; 65],
    pub attestation_sha256_0: [c_char; 65],
    pub attestation_sha256_1: [c_char; 65],
    pub attestation_hashes_valid_array: u8,
    pub attestation_hash_0_is_string: u8,
    pub attestation_hash_1_is_string: u8,
}

impl Default for MocktailRustParsedApprovalReceipt {
    fn default() -> Self {
        Self {
            generation: [0; 41],
            runtime_build_id: [0; 41],
            canary_runtime_sha256: [0; 65],
            compatibility_manifest_sha256: [0; 65],
            payload_fingerprint: [0; 65],
            attestation_sha256_0: [0; 65],
            attestation_sha256_1: [0; 65],
            attestation_hashes_valid_array: 0,
            attestation_hash_0_is_string: 0,
            attestation_hash_1_is_string: 0,
        }
    }
}

pub(crate) fn c_str_opt<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

pub(crate) fn slice_to_str<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, len) };
    std::str::from_utf8(bytes).ok()
}

fn emit_field(
    cb: MocktailRuntimePathsFieldCallback,
    ctx: *mut c_void,
    field_id: u32,
    value: &str,
) {
    if let Some(f) = cb {
        unsafe { f(ctx, field_id, value.as_ptr() as *const c_char, value.len()) };
    }
}

pub(crate) fn emit_string(cb: MocktailPayloadStoreStringCallback, ctx: *mut c_void, value: &str) {
    if let Some(f) = cb {
        unsafe { f(ctx, value.as_ptr() as *const c_char, value.len()) };
    }
}

pub(crate) fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn is_valid_lower_build_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.len().is_multiple_of(2)
        && is_lower_hex(value, value.len())
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

pub(crate) fn is_valid_payload_id_only(payload_id: &str) -> bool {
    let Some((prefix, build_id)) = payload_id.split_once('-') else {
        return false;
    };
    is_decimal(prefix) && is_lower_hex(build_id, 40)
}

fn is_valid_payload_id_with_build_id(payload_id: &str, build_id: &str) -> bool {
    let Some((prefix, suffix)) = payload_id.split_once('-') else {
        return false;
    };
    is_lower_hex(build_id, 40) && is_decimal(prefix) && suffix == build_id
}

fn is_valid_canary_run_id(run_id: &str, payload_id: &str, run: usize) -> bool {
    let prefix = format!("{}-{}-", payload_id, run);
    if run_id.len() <= prefix.len() || !run_id.starts_with(&prefix) {
        return false;
    }
    let suffix = &run_id[prefix.len()..];
    let Some((a, b)) = suffix.split_once('-') else {
        return false;
    };
    !b.contains('-') && is_decimal(a) && is_decimal(b)
}

fn compute_sha256_hex_internal(bytes: &[u8], max_chars: usize) -> Option<String> {
    if HOST_ABI_HASHING_FAULT_FOR_TESTING.load(Ordering::Acquire) {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut hex_str = hex::encode(hasher.finalize());
    if max_chars > 0 && max_chars < hex_str.len() {
        hex_str.truncate(max_chars);
    }
    Some(hex_str)
}

// ============================================================================
// 1. Runtime Paths Manifest, Approval Validation & Adjacent Assets
// ============================================================================

fn parse_approval_generation(
    relative: &str,
    directory_name: &str,
    payload_id: &str,
) -> Result<String, String> {
    let expected_prefix = format!("{}/{}-", directory_name, payload_id);
    let expected_len = expected_prefix.len() + 40 + ".json".len();
    if relative.starts_with('/')
        || relative.len() != expected_len
        || !relative.starts_with(&expected_prefix)
        || !relative.ends_with(".json")
    {
        return Err(format!(
            "active payload approval path is not a generated direct {} child",
            directory_name
        ));
    }
    let generation = &relative[expected_prefix.len()..expected_prefix.len() + 40];
    if !is_lower_hex(generation, 40) {
        return Err("active payload approval generation is invalid".to_string());
    }
    Ok(generation.to_string())
}

pub fn resolve_adjacent_roblox_asset_path_internal(
    roblox_library: &str,
    working_directory: &str,
) -> String {
    if roblox_library.is_empty() || working_directory.is_empty() {
        return String::new();
    }
    let combined = if roblox_library.starts_with('/') {
        roblox_library.to_string()
    } else {
        format!("{}/{}", working_directory, roblox_library)
    };
    if !combined.starts_with('/') {
        return String::new();
    }

    let trailing_is_dir = combined.ends_with('/') || combined.ends_with("/.");
    let mut segments: Vec<&str> = Vec::new();
    for seg in combined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    // Match std::filesystem::path::parent_path() on a non-empty normalized path.
    if !trailing_is_dir && !segments.is_empty() {
        segments.pop();
    }
    segments.push("assets");
    segments.push("content");
    format!("/{}", segments.join("/"))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_paths_parse_active_manifest(
    json_ptr: *const c_char,
    json_len: usize,
    on_field: MocktailRuntimePathsFieldCallback,
    ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "active payload manifest is not valid JSON");
        return -1;
    };
    let doc: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "active payload manifest is not valid JSON");
            return -1;
        }
    };
    let Some(obj) = doc.as_object() else {
        copy_error(err_buf, err_cap, "active payload manifest is not valid JSON");
        return -1;
    };

    let schema_ok = obj.get("schema_version").and_then(|v| v.as_i64()) == Some(1);
    let payload_id = obj.get("payload_id").and_then(|v| v.as_str());
    let payload_path = obj.get("payload_path").and_then(|v| v.as_str());
    let version_name = obj.get("version_name").and_then(|v| v.as_str());
    let version_code = obj.get("version_code").and_then(|v| v.as_i64()).filter(|&n| n >= 0);
    let elf_build_id = obj.get("elf_build_id").and_then(|v| v.as_str());

    let (Some(id), Some(rel_path), Some(ver_name), Some(ver_code), Some(build_id)) = (
        if schema_ok { payload_id } else { None },
        payload_path,
        version_name.filter(|s| !s.is_empty()),
        version_code,
        elf_build_id,
    ) else {
        copy_error(err_buf, err_cap, "active payload manifest has an unsupported schema");
        return -1;
    };
    let _ = ver_name;

    let expected_id = format!("{}-{}", ver_code, build_id);
    let expected_rel = format!("payloads/{}", id);
    if id.is_empty()
        || id != expected_id
        || rel_path != expected_rel
        || !is_lower_hex(build_id, 40)
    {
        copy_error(err_buf, err_cap, "active payload path is not a direct payloads child");
        return -1;
    }

    emit_field(on_field, ctx, K_RUNTIME_PATH_FIELD_PAYLOAD_ID, id);
    emit_field(on_field, ctx, K_RUNTIME_PATH_FIELD_PAYLOAD_REL, rel_path);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_paths_parse_active_approval_refs(
    json_ptr: *const c_char,
    json_len: usize,
    payload_id_ptr: *const c_char,
    on_field: MocktailRuntimePathsFieldCallback,
    ctx: *mut c_void,
    out_has_approval: *mut u8,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if !out_has_approval.is_null() {
        unsafe { *out_has_approval = 0 };
    }
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "active payload manifest is not valid JSON");
        return -1;
    };
    let Some(payload_id) = c_str_opt(payload_id_ptr) else {
        copy_error(err_buf, err_cap, "invalid payload_id");
        return -1;
    };
    let doc: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "active payload manifest is not valid JSON");
            return -1;
        }
    };
    let Some(obj) = doc.as_object() else {
        copy_error(err_buf, err_cap, "active payload manifest is not valid JSON");
        return -1;
    };

    let compat = obj.get("compatibility_manifest_path");
    let profile = obj.get("host_abi_profile_path");
    let receipt = obj.get("approval_path");
    if compat.is_none() && profile.is_none() && receipt.is_none() {
        return 0;
    }

    let (Some(compat_str), Some(profile_str), Some(receipt_str)) = (
        compat.and_then(|v| v.as_str()),
        profile.and_then(|v| v.as_str()),
        receipt.and_then(|v| v.as_str()),
    ) else {
        copy_error(
            err_buf,
            err_cap,
            "active payload approval references must be a complete string set",
        );
        return -1;
    };

    let compat_gen =
        match parse_approval_generation(compat_str, "compatibility_profiles", payload_id) {
            Ok(g) => g,
            Err(e) => {
                copy_error(err_buf, err_cap, &e);
                return -1;
            }
        };
    let profile_gen = match parse_approval_generation(profile_str, "host_abi_profiles", payload_id)
    {
        Ok(g) => g,
        Err(e) => {
            copy_error(err_buf, err_cap, &e);
            return -1;
        }
    };
    let receipt_gen = match parse_approval_generation(receipt_str, "approvals", payload_id) {
        Ok(g) => g,
        Err(e) => {
            copy_error(err_buf, err_cap, &e);
            return -1;
        }
    };

    if compat_gen != profile_gen || compat_gen != receipt_gen {
        copy_error(
            err_buf,
            err_cap,
            "active payload approval references use different generations",
        );
        return -1;
    }

    if !out_has_approval.is_null() {
        unsafe { *out_has_approval = 1 };
    }
    emit_field(on_field, ctx, K_RUNTIME_PATH_FIELD_COMPATIBILITY_REL, compat_str);
    emit_field(on_field, ctx, K_RUNTIME_PATH_FIELD_PROFILE_REL, profile_str);
    emit_field(on_field, ctx, K_RUNTIME_PATH_FIELD_RECEIPT_REL, receipt_str);
    emit_field(on_field, ctx, K_RUNTIME_PATH_FIELD_GENERATION, &compat_gen);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_runtime_paths_resolve_adjacent_roblox_asset_path(
    roblox_library_ptr: *const c_char,
    working_dir_ptr: *const c_char,
    on_path: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> c_int {
    let lib = c_str_opt(roblox_library_ptr).unwrap_or("");
    let wd = c_str_opt(working_dir_ptr).unwrap_or("");
    let resolved = resolve_adjacent_roblox_asset_path_internal(lib, wd);
    emit_string(on_path, ctx, &resolved);
    0
}

// ============================================================================
// 2. Payload Store Manifest Parsing, Serialization & Status JSON
// ============================================================================

pub(crate) struct InspectedApprovalPaths {
    pub profile: String,
    pub compatibility: String,
    pub receipt: String,
}

pub(crate) fn parse_manifest_identity_str(
    json_str: &str,
) -> Result<String, (Option<String>, &'static str)> {
    let doc: serde_json::Value =
        serde_json::from_str(json_str).map_err(|_| (None, "active payload manifest is invalid"))?;
    let obj = doc
        .as_object()
        .ok_or((None, "active payload manifest is invalid"))?;
    let schema_ok = obj.get("schema_version").and_then(|v| v.as_i64()) == Some(1);
    let payload_id = if schema_ok {
        obj.get("payload_id").and_then(|v| v.as_str())
    } else {
        None
    }
    .ok_or((None, "active payload manifest is invalid"))?;

    let expected_path = format!("payloads/{}", payload_id);
    if !is_valid_payload_id_only(payload_id)
        || obj.get("payload_path").and_then(|v| v.as_str()) != Some(expected_path.as_str())
    {
        return Err((
            Some(payload_id.to_owned()),
            "active payload manifest identity is invalid",
        ));
    }
    Ok(payload_id.to_owned())
}

pub(crate) fn build_activation_manifest_str(
    payload_id: &str,
    version_name: &str,
    version_code: u64,
    build_id: &str,
    library_sha256: &str,
    approval_generation: Option<&str>,
) -> Option<String> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut map = serde_json::Map::new();
    map.insert("schema_version".to_string(), serde_json::json!(1));
    map.insert("payload_id".to_string(), serde_json::json!(payload_id));
    map.insert(
        "payload_path".to_string(),
        serde_json::json!(format!("payloads/{}", payload_id)),
    );
    map.insert("version_name".to_string(), serde_json::json!(version_name));
    map.insert("version_code".to_string(), serde_json::json!(version_code));
    map.insert("elf_build_id".to_string(), serde_json::json!(build_id));
    map.insert(
        "payload_sha256".to_string(),
        serde_json::json!(library_sha256),
    );
    map.insert("activated_at_epoch".to_string(), serde_json::json!(epoch));

    if let Some(gen) = approval_generation.filter(|g| !g.is_empty()) {
        let stem = format!("{}-{}", payload_id, gen);
        map.insert(
            "approval_path".to_string(),
            serde_json::json!(format!("approvals/{}.json", stem)),
        );
        map.insert(
            "host_abi_profile_path".to_string(),
            serde_json::json!(format!("host_abi_profiles/{}.json", stem)),
        );
        map.insert(
            "compatibility_manifest_path".to_string(),
            serde_json::json!(format!("compatibility_profiles/{}.json", stem)),
        );
    }

    let mut rendered = serde_json::to_string_pretty(&serde_json::Value::Object(map)).ok()?;
    rendered.push('\n');
    Some(rendered)
}

pub(crate) fn inspect_manifest_json_str(
    json_str: &str,
    exp_ver_name: &str,
    exp_ver_code: u64,
    exp_build_id: &str,
    exp_sha256: &str,
) -> Result<Option<InspectedApprovalPaths>, &'static str> {
    let doc: serde_json::Value =
        serde_json::from_str(json_str).map_err(|_| "active payload manifest is invalid")?;
    let obj = doc
        .as_object()
        .ok_or("active payload manifest is invalid")?;

    if obj.get("version_name").and_then(|v| v.as_str()) != Some(exp_ver_name)
        || obj.get("version_code").and_then(|v| v.as_u64()) != Some(exp_ver_code)
        || obj.get("elf_build_id").and_then(|v| v.as_str()) != Some(exp_build_id)
    {
        return Err("active payload manifest is invalid");
    }

    if let Some(cached_sha) = obj.get("payload_sha256") {
        if cached_sha.as_str() != Some(exp_sha256) {
            return Err("active payload manifest hash does not match payload");
        }
    }

    let prof_val = obj.get("host_abi_profile_path");
    let compat_val = obj.get("compatibility_manifest_path");
    let receipt_val = obj.get("approval_path");
    let profile = prof_val.and_then(|v| v.as_str()).unwrap_or("");
    let compatibility = compat_val.and_then(|v| v.as_str()).unwrap_or("");
    let receipt = receipt_val.and_then(|v| v.as_str()).unwrap_or("");
    let non_string_present = prof_val.is_some_and(|v| !v.is_string())
        || compat_val.is_some_and(|v| !v.is_string())
        || receipt_val.is_some_and(|v| !v.is_string());

    if non_string_present || !profile.is_empty() || !compatibility.is_empty() || !receipt.is_empty()
    {
        if profile.is_empty() || compatibility.is_empty() || receipt.is_empty() {
            return Err("active payload approval reference set is incomplete");
        }
        return Ok(Some(InspectedApprovalPaths {
            profile: profile.to_owned(),
            compatibility: compatibility.to_owned(),
            receipt: receipt.to_owned(),
        }));
    }

    Ok(None)
}

pub(crate) fn persist_payload_sha256_str(
    json_str: &str,
    library_sha256: &str,
) -> Result<Option<String>, &'static str> {
    let mut doc: serde_json::Value =
        serde_json::from_str(json_str).map_err(|_| "active payload manifest is invalid")?;
    let obj = doc
        .as_object_mut()
        .ok_or("active payload manifest is invalid")?;

    if let Some(cached) = obj.get("payload_sha256") {
        if cached.as_str() != Some(library_sha256) {
            return Err("active payload manifest hash does not match payload");
        }
        return Ok(None);
    }

    obj.insert(
        "payload_sha256".to_string(),
        serde_json::json!(library_sha256),
    );
    let mut rendered =
        serde_json::to_string_pretty(&doc).map_err(|_| "active payload manifest is invalid")?;
    rendered.push('\n');
    Ok(Some(rendered))
}

pub(crate) fn build_status_json_str(
    update_json_path: Option<&Path>,
    current_json: &str,
    previous_json: &str,
) -> Option<String> {
    let updates_val = update_json_path
        .and_then(|p| p.to_str())
        .and_then(read_update_state_json_string)
        .map(|(_, doc)| doc)
        .unwrap_or(serde_json::Value::Null);

    let parse_opt_manifest = |s: &str| -> serde_json::Value {
        if s.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
        }
    };

    let mut root = serde_json::Map::new();
    root.insert("updates".to_string(), updates_val);
    root.insert("current".to_string(), parse_opt_manifest(current_json));
    root.insert("previous_good".to_string(), parse_opt_manifest(previous_json));

    let mut rendered = serde_json::to_string_pretty(&serde_json::Value::Object(root)).ok()?;
    rendered.push('\n');
    Some(rendered)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_parse_manifest_identity(
    json_ptr: *const c_char,
    json_len: usize,
    on_payload_id: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "active payload manifest is invalid");
        return -1;
    };
    match parse_manifest_identity_str(json_str) {
        Ok(payload_id) => {
            emit_string(on_payload_id, ctx, &payload_id);
            0
        }
        Err((opt_id, msg)) => {
            if let Some(pid) = opt_id {
                emit_string(on_payload_id, ctx, &pid);
            }
            copy_error(err_buf, err_cap, msg);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_build_activation_manifest(
    payload_id_ptr: *const c_char,
    version_name_ptr: *const c_char,
    version_code: u64,
    build_id_ptr: *const c_char,
    library_sha256_ptr: *const c_char,
    approval_generation_ptr: *const c_char,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> c_int {
    let (Some(payload_id), Some(version_name), Some(build_id), Some(library_sha256)) = (
        c_str_opt(payload_id_ptr),
        c_str_opt(version_name_ptr),
        c_str_opt(build_id_ptr),
        c_str_opt(library_sha256_ptr),
    ) else {
        return -1;
    };
    let approval_generation = c_str_opt(approval_generation_ptr).filter(|g| !g.is_empty());
    let Some(rendered) = build_activation_manifest_str(
        payload_id,
        version_name,
        version_code,
        build_id,
        library_sha256,
        approval_generation,
    ) else {
        return -1;
    };
    emit_string(on_json, ctx, &rendered);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_inspect_manifest_json(
    json_ptr: *const c_char,
    json_len: usize,
    expected_version_name_ptr: *const c_char,
    expected_version_code: u64,
    expected_build_id_ptr: *const c_char,
    expected_library_sha256_ptr: *const c_char,
    on_approval_paths: MocktailPayloadStoreApprovalPathsCallback,
    ctx: *mut c_void,
    out_has_approval: *mut u8,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if !out_has_approval.is_null() {
        unsafe { *out_has_approval = 0 };
    }
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "active payload manifest is invalid");
        return -1;
    };
    let (Some(exp_ver_name), Some(exp_build_id), Some(exp_sha256)) = (
        c_str_opt(expected_version_name_ptr),
        c_str_opt(expected_build_id_ptr),
        c_str_opt(expected_library_sha256_ptr),
    ) else {
        copy_error(err_buf, err_cap, "active payload manifest is invalid");
        return -1;
    };
    match inspect_manifest_json_str(
        json_str,
        exp_ver_name,
        expected_version_code,
        exp_build_id,
        exp_sha256,
    ) {
        Ok(Some(paths)) => {
            if !out_has_approval.is_null() {
                unsafe { *out_has_approval = 1 };
            }
            if let Some(cb) = on_approval_paths {
                unsafe {
                    cb(
                        ctx,
                        paths.profile.as_ptr() as *const c_char,
                        paths.profile.len(),
                        paths.compatibility.as_ptr() as *const c_char,
                        paths.compatibility.len(),
                        paths.receipt.as_ptr() as *const c_char,
                        paths.receipt.len(),
                    );
                }
            }
            0
        }
        Ok(None) => 0,
        Err(msg) => {
            copy_error(err_buf, err_cap, msg);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_persist_payload_sha256(
    json_ptr: *const c_char,
    json_len: usize,
    library_sha256_ptr: *const c_char,
    on_updated_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    out_needs_write: *mut u8,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if !out_needs_write.is_null() {
        unsafe { *out_needs_write = 0 };
    }
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "active payload manifest is invalid");
        return -1;
    };
    let Some(library_sha256) = c_str_opt(library_sha256_ptr) else {
        copy_error(err_buf, err_cap, "active payload manifest is invalid");
        return -1;
    };
    match persist_payload_sha256_str(json_str, library_sha256) {
        Ok(None) => 0,
        Ok(Some(rendered)) => {
            if !out_needs_write.is_null() {
                unsafe { *out_needs_write = 1 };
            }
            emit_string(on_updated_json, ctx, &rendered);
            0
        }
        Err(msg) => {
            copy_error(err_buf, err_cap, msg);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_store_build_status_json(
    update_json_path_ptr: *const c_char,
    current_json_ptr: *const c_char,
    current_json_len: usize,
    previous_json_ptr: *const c_char,
    previous_json_len: usize,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> c_int {
    let update_path = c_str_opt(update_json_path_ptr).map(Path::new);
    let current_json = slice_to_str(current_json_ptr, current_json_len).unwrap_or("");
    let previous_json = slice_to_str(previous_json_ptr, previous_json_len).unwrap_or("");
    let Some(rendered) = build_status_json_str(update_path, current_json, previous_json) else {
        return -1;
    };
    emit_string(on_json, ctx, &rendered);
    0
}

// ============================================================================
// 3. Host ABI Profile Loader, Receipt & Canary Attestation Validation
// ============================================================================

fn read_required_str<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a str> {
    obj.get(name)?.as_str()
}

fn read_size(value: &serde_json::Value, maximum: usize) -> Option<usize> {
    let parsed = value.as_u64()?;
    if parsed > maximum as u64 {
        return None;
    }
    usize::try_from(parsed).ok()
}

fn read_required_size(
    obj: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    maximum: usize,
) -> Option<usize> {
    read_size(obj.get(name)?, maximum)
}

fn read_hex_rva(
    obj: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    uintptr_max: u64,
) -> Option<u64> {
    let encoded = obj.get(name)?.as_str()?;
    let hex_digits = encoded.strip_prefix("0x")?;
    if hex_digits.is_empty() || !hex_digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let parsed = u64::from_str_radix(hex_digits, 16).ok()?;
    if parsed == 0 || parsed > uintptr_max {
        return None;
    }
    Some(parsed)
}

fn parse_bridge_kind(kind: &str) -> Option<i32> {
    match kind {
        "allocate" => Some(0),
        "reallocate" => Some(1),
        "aligned_allocate" => Some(2),
        "free" => Some(3),
        "usable_size" => Some(4),
        _ => None,
    }
}

fn expected_kind_for_label(label: &str) -> Option<i32> {
    match label {
        "small-allocate" | "allocate" => Some(0),
        "reallocate" => Some(1),
        "aligned-allocate-direct" => Some(2),
        "free" => Some(3),
        "usable-size" => Some(4),
        _ => None,
    }
}

fn is_safe_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse_constructor_ranges(
    obj: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    init_count: usize,
) -> Option<([MocktailRustConstructorRange; K_MAX_CONSTRUCTOR_RUN_RANGES], usize)> {
    let arr = obj.get(name)?.as_array()?;
    if arr.is_empty() || arr.len() > K_MAX_CONSTRUCTOR_RUN_RANGES {
        return None;
    }
    let mut ranges = [MocktailRustConstructorRange::default(); K_MAX_CONSTRUCTOR_RUN_RANGES];
    for (idx, item) in arr.iter().enumerate() {
        let item_obj = item.as_object()?;
        let begin = read_required_size(item_obj, "begin", init_count)?;
        let end_exclusive = read_required_size(item_obj, "end_exclusive", init_count)?;
        ranges[idx] = MocktailRustConstructorRange {
            begin,
            end_exclusive,
        };
    }
    Some((ranges, arr.len()))
}

fn copy_fixed_str(dst: &mut [c_char], val: &str) -> bool {
    copy_to_c_buffer(val, dst.as_mut_ptr(), dst.len()) == 0
}

/// Parses and validates the six host-bridge entries, returning `(allocate_rva, free_rva)`.
fn parse_bridge_entries(
    profile_obj: &serde_json::Map<String, serde_json::Value>,
    uintptr_max: u64,
    out: &mut MocktailRustParsedHostAbiProfile,
) -> Result<(u64, u64), &'static str> {
    let bridge_entries = profile_obj
        .get("bridge_entries")
        .and_then(|v| v.as_array())
        .filter(|arr| arr.len() == 6)
        .ok_or("external host ABI profile has an invalid bridge table")?;

    let mut observed_kinds = [false; 5];
    let mut observed_rvas: Vec<u64> = Vec::with_capacity(6);
    let mut observed_labels: Vec<String> = Vec::with_capacity(6);
    let mut primary_allocate_rva = 0u64;
    let mut free_rva = 0u64;

    for entry in bridge_entries {
        let entry_obj = entry
            .as_object()
            .ok_or("external host ABI profile has an invalid bridge entry")?;
        let (Some(rva), Some(kind_name), Some(label)) = (
            read_hex_rva(entry_obj, "rva", uintptr_max),
            read_required_str(entry_obj, "kind"),
            read_required_str(entry_obj, "label"),
        ) else {
            return Err("external host ABI profile has an invalid bridge entry");
        };
        if !is_safe_label(label) {
            return Err("external host ABI profile has an invalid bridge entry");
        }
        let (Some(kind), Some(expected_kind)) =
            (parse_bridge_kind(kind_name), expected_kind_for_label(label))
        else {
            return Err("external host ABI profile has an unknown or duplicate bridge");
        };
        if kind != expected_kind
            || observed_rvas.contains(&rva)
            || observed_labels.iter().any(|l| l == label)
        {
            return Err("external host ABI profile has an unknown or duplicate bridge");
        }
        let idx = out.bridge_entry_count;
        out.bridge_entry_count += 1;
        out.bridge_entries[idx].rva = rva;
        out.bridge_entries[idx].kind = kind;
        let _ = copy_fixed_str(&mut out.bridge_entries[idx].label, label);
        observed_rvas.push(rva);
        observed_labels.push(label.to_string());
        observed_kinds[kind as usize] = true;
        if label == "allocate" {
            primary_allocate_rva = rva;
        } else if label == "free" {
            free_rva = rva;
        }
    }
    if !observed_kinds.iter().all(|&b| b) {
        return Err("external host ABI profile is missing a required bridge kind");
    }
    Ok((primary_allocate_rva, free_rva))
}

/// Parses `data_seeds` from the profile JSON and returns its five writable slot RVAs.
fn parse_data_seeds(
    profile_obj: &serde_json::Map<String, serde_json::Value>,
    uintptr_max: u64,
    out: &mut MocktailRustParsedHostAbiProfile,
) -> Result<[u64; 5], &'static str> {
    let seeds = profile_obj
        .get("data_seeds")
        .and_then(|v| v.as_object())
        .ok_or("external host ABI profile has invalid data seeds")?;
    let (
        Some(allocator_object_slot),
        Some(empty_string_slot),
        Some(jni_singleton_slot),
        Some(jni_singleton_bytes),
        Some(arena_initializer),
        Some(allocator_thread_initializer),
        Some(arena_guard_slot),
        Some(arena_table_slot),
        Some(arena_table_slot_count),
    ) = (
        read_hex_rva(seeds, "allocator_object_slot", uintptr_max),
        read_hex_rva(seeds, "empty_string_slot", uintptr_max),
        read_hex_rva(seeds, "jni_singleton_slot", uintptr_max),
        read_required_size(seeds, "jni_singleton_bytes", K_MAXIMUM_SEED_ALLOCATION_BYTES),
        read_hex_rva(seeds, "arena_initializer", uintptr_max),
        read_hex_rva(seeds, "allocator_thread_initializer", uintptr_max),
        read_hex_rva(seeds, "arena_guard_slot", uintptr_max),
        read_hex_rva(seeds, "arena_table_slot", uintptr_max),
        read_required_size(seeds, "arena_table_slot_count", K_MAXIMUM_ARENA_TABLE_SLOTS),
    )
    else {
        return Err("external host ABI profile has invalid data seeds");
    };
    if jni_singleton_bytes != 0x400 || arena_table_slot_count != 0x40_0000 {
        return Err("external host ABI profile changed fixed seed allocation sizes");
    }
    out.allocator_object_slot = allocator_object_slot;
    out.empty_string_slot = empty_string_slot;
    out.jni_singleton_slot = jni_singleton_slot;
    out.jni_singleton_bytes = jni_singleton_bytes;
    out.arena_initializer = arena_initializer;
    out.allocator_thread_initializer = allocator_thread_initializer;
    out.arena_guard_slot = arena_guard_slot;
    out.arena_table_slot = arena_table_slot;
    out.arena_table_slot_count = arena_table_slot_count;
    Ok([
        allocator_object_slot,
        empty_string_slot,
        jni_singleton_slot,
        arena_guard_slot,
        arena_table_slot,
    ])
}

/// Validates constructor range monotonicity and mimalloc policy alignment.
fn validate_constructor_policy(
    is_x86_64: bool,
    bridges_supported: bool,
    has_constructor_indices: bool,
    constructor_indices: [usize; 4],
    out: &MocktailRustParsedHostAbiProfile,
) -> Result<(), &'static str> {
    let init_count = out.init_array_count;
    let ctor_ranges = &out.constructor_run_ranges;
    let ctor_count = out.constructor_run_range_count;
    let mim_ranges = &out.native_mimalloc_constructor_run_ranges;
    let mim_count = out.native_mimalloc_constructor_run_range_count;
    let checkpoint = out.native_mimalloc_thread_initializer_after_constructor;

    let ctor_valid = crate::mocktail_rust_host_abi_has_valid_ranges(
        ctor_ranges.as_ptr(),
        ctor_count,
        K_MAX_CONSTRUCTOR_RUN_RANGES,
        init_count,
    );
    let mim_valid = crate::mocktail_rust_host_abi_has_valid_ranges(
        mim_ranges.as_ptr(),
        mim_count,
        K_MAX_CONSTRUCTOR_RUN_RANGES,
        init_count,
    );
    let mim_allows_thread_init = crate::mocktail_rust_host_abi_allows_constructor(
        mim_ranges.as_ptr(),
        mim_count,
        K_MAX_CONSTRUCTOR_RUN_RANGES,
        init_count,
        checkpoint,
    );
    if out.native_allocator_allocate == 0
        || out.native_allocator_deallocate == 0
        || !ctor_valid
        || !mim_valid
        || out.native_pre_jni_registry_initializer == 0
        || out.native_pre_jni_registry_slot == 0
        || !mim_allows_thread_init
    {
        return Err("external host ABI profile has inconsistent constructor policy");
    }

    if bridges_supported {
        let expected_indices = [checkpoint, checkpoint + 1, checkpoint + 2, checkpoint + 3];
        if init_count <= checkpoint + 3
            || ctor_count != 2
            || ctor_ranges[0]
                != (MocktailRustConstructorRange {
                    begin: checkpoint,
                    end_exclusive: checkpoint + 1,
                })
            || ctor_ranges[1]
                != (MocktailRustConstructorRange {
                    begin: checkpoint + 3,
                    end_exclusive: init_count,
                })
            || mim_count != 1
            || mim_ranges[0]
                != (MocktailRustConstructorRange {
                    begin: checkpoint,
                    end_exclusive: init_count,
                })
            || (is_x86_64 && checkpoint != 2)
            || (has_constructor_indices && constructor_indices != expected_indices)
        {
            return Err("external host ABI profile changed the verified constructor policy");
        }
    } else {
        let mut sorted = constructor_indices;
        sorted.sort_unstable();
        if sorted[0] < 2
            || sorted[3] >= init_count
            || sorted.windows(2).any(|w| w[0] == w[1])
            || checkpoint != constructor_indices[0]
            || mim_count != 1
            || mim_ranges[0]
                != (MocktailRustConstructorRange {
                    begin: 2,
                    end_exclusive: init_count,
                })
            || ctor_count != 1
            || ctor_ranges[0]
                != (MocktailRustConstructorRange {
                    begin: 2,
                    end_exclusive: init_count,
                })
        {
            return Err("external host ABI profile has inconsistent constructor roles");
        }
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_set_hashing_fault_for_testing(enabled: bool) {
    HOST_ABI_HASHING_FAULT_FOR_TESTING.store(enabled, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_sha256_hex(
    bytes_ptr: *const u8,
    bytes_len: usize,
    max_chars: usize,
    out_hex: *mut c_char,
    hex_cap: usize,
) -> c_int {
    if out_hex.is_null() || hex_cap == 0 {
        return -1;
    }
    unsafe { *out_hex = 0 };
    if bytes_ptr.is_null() && bytes_len > 0 {
        return -1;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) }
    };
    let Some(hex_str) = compute_sha256_hex_internal(input, max_chars) else {
        return -1;
    };
    copy_to_c_buffer(&hex_str, out_hex, hex_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_validate_payload_id(
    payload_id_ptr: *const c_char,
    build_id_ptr: *const c_char,
) -> bool {
    match (c_str_opt(payload_id_ptr), c_str_opt(build_id_ptr)) {
        (Some(pid), Some(bid)) => is_valid_payload_id_with_build_id(pid, bid),
        _ => false,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_validate_canary_run_id(
    run_id_ptr: *const c_char,
    payload_id_ptr: *const c_char,
    run: usize,
) -> bool {
    match (c_str_opt(run_id_ptr), c_str_opt(payload_id_ptr)) {
        (Some(rid), Some(pid)) => is_valid_canary_run_id(rid, pid, run),
        _ => false,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_parse_profile_json(
    json_ptr: *const c_char,
    json_len: usize,
    is_x86_64: bool,
    pointer_align: usize,
    uintptr_max: u64,
    out_profile: *mut MocktailRustParsedHostAbiProfile,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if out_profile.is_null() || pointer_align == 0 {
        copy_error(err_buf, err_cap, "invalid arguments");
        return -1;
    }
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "invalid JSON object");
        return -2;
    };
    let root: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "invalid JSON object");
            return -2;
        }
    };
    let Some(root_obj) = root.as_object() else {
        copy_error(err_buf, err_cap, "invalid JSON object");
        return -2;
    };

    let schema_ok = root_obj
        .get("schema_version")
        .and_then(|v| read_size(v, 1))
        == Some(1);
    let reference = root_obj.get("reference").and_then(|v| v.as_object());
    let derivation = root_obj.get("derivation_anchors").and_then(|v| v.as_object());
    let profile_json = root_obj.get("profile").and_then(|v| v.as_object());
    let (Some(reference_obj), Some(derivation_obj), Some(profile_obj)) = (
        if schema_ok { reference } else { None },
        derivation,
        profile_json,
    ) else {
        copy_error(
            err_buf,
            err_cap,
            "unsupported external host ABI profile schema",
        );
        return -1;
    };
    if reference_obj.is_empty() || derivation_obj.is_empty() {
        copy_error(
            err_buf,
            err_cap,
            "unsupported external host ABI profile schema",
        );
        return -1;
    }

    let Some(build_id) = read_required_str(root_obj, "elf_build_id") else {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has an invalid exact Build ID",
        );
        return -1;
    };
    let Some(nested_build_id) = read_required_str(profile_obj, "elf_build_id") else {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has an invalid exact Build ID",
        );
        return -1;
    };
    if !is_valid_lower_build_id(build_id) || nested_build_id != build_id {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has an invalid exact Build ID",
        );
        return -1;
    }

    let (Some(ref_build_id), Some(ref_payload_sha256)) = (
        read_required_str(reference_obj, "elf_build_id"),
        read_required_str(reference_obj, "payload_sha256"),
    ) else {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has invalid reference identity",
        );
        return -1;
    };
    if !is_valid_lower_build_id(ref_build_id) || !is_lower_hex(ref_payload_sha256, 64) {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has invalid reference identity",
        );
        return -1;
    }

    if read_required_size(derivation_obj, "signature_version", 1) != Some(1) {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has unsupported derivation anchors",
        );
        return -1;
    }

    let mut out = MocktailRustParsedHostAbiProfile::default();
    if !copy_fixed_str(&mut out.build_id, build_id)
        || !copy_fixed_str(&mut out.reference_build_id, ref_build_id)
        || !copy_fixed_str(&mut out.reference_payload_sha256, ref_payload_sha256)
    {
        copy_error(err_buf, err_cap, "external host ABI profile field too long");
        return -1;
    }

    for name in [
        "allocator_object_initializer_rva",
        "empty_string_initializer_rva",
        "jni_singleton_initializer_rva",
    ] {
        let Some(rva) = read_hex_rva(derivation_obj, name, uintptr_max) else {
            copy_error(
                err_buf,
                err_cap,
                "external host ABI profile is missing a derivation anchor",
            );
            return -1;
        };
        out.derivation_code_rvas[out.derivation_code_rva_count] = rva;
        out.derivation_code_rva_count += 1;
    }

    let mut bridges_supported = true;
    if let Some(supported) = profile_obj.get("host_allocator_bridges_supported") {
        let Some(b) = supported.as_bool() else {
            copy_error(
                err_buf,
                err_cap,
                "host allocator bridge support must be boolean",
            );
            return -1;
        };
        bridges_supported = b;
    }
    out.host_allocator_bridges_supported = if bridges_supported { 1 } else { 0 };

    let mut constructor_indices = [2usize, 3, 4, 5];
    let indices_val = derivation_obj.get("constructor_indices");
    if indices_val.is_some() || !bridges_supported {
        let Some(indices_obj) = indices_val.and_then(|v| v.as_object()) else {
            copy_error(
                err_buf,
                err_cap,
                "external host ABI profile has invalid constructor indices",
            );
            return -1;
        };
        if indices_obj.len() != 4 {
            copy_error(
                err_buf,
                err_cap,
                "external host ABI profile has invalid constructor indices",
            );
            return -1;
        }
        for (role, key) in ["2", "3", "4", "5"].iter().enumerate() {
            let Some(val) = read_required_size(indices_obj, key, K_MAXIMUM_INIT_ARRAY_ENTRIES - 1)
            else {
                copy_error(
                    err_buf,
                    err_cap,
                    "external host ABI profile has invalid constructor indices",
                );
                return -1;
            };
            constructor_indices[role] = val;
        }
    }

    let Some(constructor_anchors) = derivation_obj
        .get("constructor_rvas")
        .and_then(|v| v.as_object())
    else {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has invalid constructor anchors",
        );
        return -1;
    };
    for key in ["2", "3", "4", "5"] {
        let Some(rva) = read_hex_rva(constructor_anchors, key, uintptr_max) else {
            copy_error(
                err_buf,
                err_cap,
                "external host ABI profile is missing a constructor anchor",
            );
            return -1;
        };
        out.derivation_code_rvas[out.derivation_code_rva_count] = rva;
        out.derivation_code_rva_count += 1;
    }

    let (primary_allocate_rva, free_rva) = match parse_bridge_entries(profile_obj, uintptr_max, &mut out) {
        Ok(rvas) => rvas,
        Err(msg) => {
            copy_error(err_buf, err_cap, msg);
            return -1;
        }
    };

    let seed_slots = match parse_data_seeds(profile_obj, uintptr_max, &mut out) {
        Ok(slots) => slots,
        Err(msg) => {
            copy_error(err_buf, err_cap, msg);
            return -1;
        }
    };

    let allocator = profile_obj.get("native_allocator").and_then(|v| v.as_object());
    let bootstrap = profile_obj
        .get("native_pre_jni_bootstrap")
        .and_then(|v| v.as_object());
    let (
        Some(alloc_obj),
        Some(boot_obj),
        Some(nat_alloc),
        Some(nat_dealloc),
        Some(reg_init),
        Some(reg_slot),
        Some(init_offset),
        Some(init_count),
    ) = (
        allocator,
        bootstrap,
        allocator.and_then(|o| read_hex_rva(o, "allocate", uintptr_max)),
        allocator.and_then(|o| read_hex_rva(o, "deallocate", uintptr_max)),
        bootstrap.and_then(|o| read_hex_rva(o, "registry_initializer", uintptr_max)),
        bootstrap.and_then(|o| read_hex_rva(o, "registry_slot", uintptr_max)),
        read_hex_rva(profile_obj, "init_array_offset", uintptr_max),
        read_required_size(profile_obj, "init_array_count", K_MAXIMUM_INIT_ARRAY_ENTRIES)
            .filter(|&c| c > 0),
    )
    else {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has invalid native bootstrap fields",
        );
        return -1;
    };
    let _ = (alloc_obj, boot_obj);

    let (
        Some((ctor_ranges, ctor_count)),
        Some((mim_ranges, mim_count)),
        Some(thread_init_after),
    ) = (
        parse_constructor_ranges(profile_obj, "constructor_run_ranges", init_count),
        parse_constructor_ranges(
            profile_obj,
            "native_mimalloc_constructor_run_ranges",
            init_count,
        ),
        read_required_size(
            profile_obj,
            "native_mimalloc_thread_initializer_after_constructor",
            init_count - 1,
        ),
    )
    else {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile has invalid native bootstrap fields",
        );
        return -1;
    };

    out.native_allocator_allocate = nat_alloc;
    out.native_allocator_deallocate = nat_dealloc;
    out.native_pre_jni_registry_initializer = reg_init;
    out.native_pre_jni_registry_slot = reg_slot;
    out.init_array_offset = init_offset;
    out.init_array_count = init_count;
    out.constructor_run_ranges = ctor_ranges;
    out.constructor_run_range_count = ctor_count;
    out.native_mimalloc_constructor_run_ranges = mim_ranges;
    out.native_mimalloc_constructor_run_range_count = mim_count;
    out.native_mimalloc_thread_initializer_after_constructor = thread_init_after;

    if nat_alloc != primary_allocate_rva || nat_dealloc != free_rva {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile native allocator disagrees with bridges",
        );
        return -1;
    }

    let mut writable_slots = [
        seed_slots[0],
        seed_slots[1],
        seed_slots[2],
        seed_slots[3],
        seed_slots[4],
        reg_slot,
    ];
    if writable_slots.iter().any(|&rva| rva % (pointer_align as u64) != 0) {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile contains an unaligned writable slot",
        );
        return -1;
    }
    writable_slots.sort_unstable();
    if writable_slots.windows(2).any(|w| w[0] == w[1]) {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile aliases writable state slots",
        );
        return -1;
    }

    if read_required_str(profile_obj, "default_allocator_strategy") != Some("native_mimalloc") {
        copy_error(
            err_buf,
            err_cap,
            "external host ABI profile must retain native mimalloc",
        );
        return -1;
    }
    out.default_allocator_strategy = 1; // kNativeMimalloc

    if let Err(msg) = validate_constructor_policy(
        is_x86_64,
        bridges_supported,
        indices_val.is_some(),
        constructor_indices,
        &out,
    ) {
        copy_error(err_buf, err_cap, msg);
        return -1;
    }

    unsafe { *out_profile = out };
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_validate_profile_identity(
    json_ptr: *const c_char,
    json_len: usize,
    profile_build_id_ptr: *const c_char,
    reference_build_id_ptr: *const c_char,
    reference_payload_sha256_ptr: *const c_char,
    canonical_payload_path_ptr: *const c_char,
    expected_launch_build_id_ptr: *const c_char,
    out_payload_sha256: *mut c_char,
    sha_cap: usize,
    out_payload_id: *mut c_char,
    pid_cap: usize,
) -> c_int {
    let (
        Some(json_str),
        Some(profile_build_id),
        Some(reference_build_id),
        Some(reference_payload_sha256),
        Some(canonical_payload_path),
        Some(expected_launch_build_id),
    ) = (
        slice_to_str(json_ptr, json_len),
        c_str_opt(profile_build_id_ptr),
        c_str_opt(reference_build_id_ptr),
        c_str_opt(reference_payload_sha256_ptr),
        c_str_opt(canonical_payload_path_ptr),
        c_str_opt(expected_launch_build_id_ptr),
    )
    else {
        return -1;
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return -1;
    };
    let Some(obj) = doc.as_object() else {
        return -1;
    };
    let (Some(encoded_sha), Some(encoded_path), Some(payload_id)) = (
        read_required_str(obj, "payload_sha256"),
        read_required_str(obj, "payload_path"),
        read_required_str(obj, "payload_id"),
    ) else {
        return -1;
    };

    let lib_path = Path::new(canonical_payload_path);
    let stored_path_ok = encoded_path == format!("payloads/{}", payload_id)
        && lib_path.file_name().and_then(|s| s.to_str()) == Some("libroblox.so")
        && lib_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            == Some(payload_id)
        && lib_path
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            == Some("payloads");

    if !is_lower_hex(encoded_sha, 64)
        || !is_valid_payload_id_with_build_id(payload_id, profile_build_id)
        || !stored_path_ok
        || reference_build_id == profile_build_id
        || reference_payload_sha256 == encoded_sha
        || profile_build_id != expected_launch_build_id.to_ascii_lowercase()
    {
        return -1;
    }

    if copy_to_c_buffer(encoded_sha, out_payload_sha256, sha_cap) != 0
        || copy_to_c_buffer(payload_id, out_payload_id, pid_cap) != 0
    {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_parse_receipt_json(
    json_ptr: *const c_char,
    json_len: usize,
    receipt_path_ptr: *const c_char,
    canonical_payload_path_ptr: *const c_char,
    payload_sha256_ptr: *const c_char,
    profile_sha256_ptr: *const c_char,
    payload_id_ptr: *const c_char,
    build_id_ptr: *const c_char,
    out_receipt: *mut MocktailRustParsedApprovalReceipt,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if out_receipt.is_null() {
        copy_error(err_buf, err_cap, "invalid arguments");
        return -1;
    }
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "invalid JSON object");
        return -2;
    };
    let doc: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "invalid JSON object");
            return -2;
        }
    };
    let Some(obj) = doc.as_object() else {
        copy_error(err_buf, err_cap, "invalid JSON object");
        return -2;
    };

    let (
        Some(receipt_path),
        Some(canonical_payload_path),
        Some(payload_sha256),
        Some(profile_sha256),
        Some(payload_id),
        Some(build_id),
    ) = (
        c_str_opt(receipt_path_ptr),
        c_str_opt(canonical_payload_path_ptr),
        c_str_opt(payload_sha256_ptr),
        c_str_opt(profile_sha256_ptr),
        c_str_opt(payload_id_ptr),
        c_str_opt(build_id_ptr),
    )
    else {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt does not authorize the exact ABI profile and payload",
        );
        return -1;
    };

    let schema_ok = obj.get("schema_version").and_then(|v| read_size(v, 1)) == Some(1);
    let (
        Some(status),
        Some(r_pid),
        Some(generation),
        Some(r_build_id),
        Some(r_payload_path),
        Some(r_payload_sha),
        Some(r_profile_sha),
        Some(r_runtime_build_id),
        Some(canary_runtime_sha),
        Some(r_runtime_sha),
        Some(r_manifest_sha),
        Some(payload_fingerprint),
        Some(canary_tier),
        Some(successful_runs),
    ) = (
        if schema_ok {
            read_required_str(obj, "status")
        } else {
            None
        },
        read_required_str(obj, "payload_id"),
        read_required_str(obj, "generation"),
        read_required_str(obj, "elf_build_id"),
        read_required_str(obj, "payload_path"),
        read_required_str(obj, "payload_sha256"),
        read_required_str(obj, "profile_sha256"),
        read_required_str(obj, "runtime_build_id"),
        read_required_str(obj, "canary_runtime_sha256"),
        read_required_str(obj, "runtime_sha256"),
        read_required_str(obj, "compatibility_manifest_sha256"),
        read_required_str(obj, "payload_fingerprint"),
        read_required_str(obj, "canary_tier"),
        read_required_size(obj, "successful_runs", 2),
    )
    else {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt does not authorize the exact ABI profile and payload",
        );
        return -1;
    };

    if status != "approved"
        || r_pid != payload_id
        || !is_lower_hex(generation, 40)
        || successful_runs != 2
        || canary_tier != "C"
        || r_build_id != build_id
        || r_payload_path != canonical_payload_path
        || r_payload_sha != payload_sha256
        || r_profile_sha != profile_sha256
        || !is_lower_hex(r_runtime_build_id, 40)
        || !is_lower_hex(canary_runtime_sha, 64)
        || r_runtime_sha != canary_runtime_sha
        || !is_lower_hex(payload_fingerprint, 64)
    {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt does not authorize the exact ABI profile and payload",
        );
        return -1;
    }

    let expected_filename = format!("{}-{}.json", payload_id, generation);
    if Path::new(receipt_path).file_name().and_then(|s| s.to_str()) != Some(expected_filename.as_str())
    {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt filename does not match its evidence generation",
        );
        return -1;
    }

    let mut out = MocktailRustParsedApprovalReceipt::default();
    if !copy_fixed_str(&mut out.generation, generation)
        || !copy_fixed_str(&mut out.runtime_build_id, r_runtime_build_id)
        || !copy_fixed_str(&mut out.canary_runtime_sha256, canary_runtime_sha)
        || !copy_fixed_str(&mut out.compatibility_manifest_sha256, r_manifest_sha)
        || !copy_fixed_str(&mut out.payload_fingerprint, payload_fingerprint)
    {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt does not authorize the exact ABI profile and payload",
        );
        return -1;
    }

    if let Some(hashes) = obj
        .get("canary_attestation_sha256")
        .and_then(|v| v.as_array())
        .filter(|a| a.len() == 2)
    {
        out.attestation_hashes_valid_array = 1;
        if let Some(h0) = hashes[0].as_str() {
            out.attestation_hash_0_is_string =
                u8::from(copy_fixed_str(&mut out.attestation_sha256_0, h0));
        }
        if let Some(h1) = hashes[1].as_str() {
            out.attestation_hash_1_is_string =
                u8::from(copy_fixed_str(&mut out.attestation_sha256_1, h1));
        }
    }

    unsafe { *out_receipt = out };
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_validate_canary_attestation_json(
    json_ptr: *const c_char,
    json_len: usize,
    expected_run: usize,
    payload_id_ptr: *const c_char,
    payload_fingerprint_ptr: *const c_char,
    profile_sha256_ptr: *const c_char,
    compatibility_manifest_sha256_ptr: *const c_char,
    runtime_sha256_ptr: *const c_char,
    runtime_build_id_ptr: *const c_char,
    out_sha256: *mut c_char,
    sha_cap: usize,
    on_run_id: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(json_str) = slice_to_str(json_ptr, json_len) else {
        copy_error(err_buf, err_cap, "invalid JSON object");
        return -2;
    };
    let doc: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            copy_error(err_buf, err_cap, "invalid JSON object");
            return -2;
        }
    };
    let Some(obj) = doc.as_object() else {
        copy_error(err_buf, err_cap, "invalid JSON object");
        return -2;
    };

    let (
        Some(payload_id),
        Some(payload_fingerprint),
        Some(profile_sha256),
        Some(compat_sha256),
        Some(runtime_sha256),
        Some(runtime_build_id),
    ) = (
        c_str_opt(payload_id_ptr),
        c_str_opt(payload_fingerprint_ptr),
        c_str_opt(profile_sha256_ptr),
        c_str_opt(compatibility_manifest_sha256_ptr),
        c_str_opt(runtime_sha256_ptr),
        c_str_opt(runtime_build_id_ptr),
    )
    else {
        copy_error(
            err_buf,
            err_cap,
            "canary attestation does not match the exact approval evidence",
        );
        return -1;
    };

    let schema_ok = obj.get("schema_version").and_then(|v| read_size(v, 1)) == Some(1);
    let (
        Some(status),
        Some(canary_tier),
        Some(run),
        Some(run_id),
        Some(a_pid),
        Some(a_fp),
        Some(a_prof),
        Some(a_man),
        Some(a_rsha),
        Some(a_rbid),
        Some(readiness_log_sha),
    ) = (
        if schema_ok {
            read_required_str(obj, "status")
        } else {
            None
        },
        read_required_str(obj, "canary_tier"),
        read_required_size(obj, "run", 2),
        read_required_str(obj, "run_id"),
        read_required_str(obj, "payload_id"),
        read_required_str(obj, "payload_fingerprint"),
        read_required_str(obj, "profile_sha256"),
        read_required_str(obj, "compatibility_manifest_sha256"),
        read_required_str(obj, "runtime_sha256"),
        read_required_str(obj, "runtime_build_id"),
        read_required_str(obj, "readiness_log_sha256"),
    )
    else {
        copy_error(
            err_buf,
            err_cap,
            "canary attestation does not match the exact approval evidence",
        );
        return -1;
    };

    if status != "passed"
        || canary_tier != "C"
        || run != expected_run
        || !is_valid_canary_run_id(run_id, payload_id, expected_run)
        || a_pid != payload_id
        || a_fp != payload_fingerprint
        || a_prof != profile_sha256
        || a_man != compat_sha256
        || a_rsha != runtime_sha256
        || a_rbid != runtime_build_id
        || !is_lower_hex(readiness_log_sha, 64)
    {
        copy_error(
            err_buf,
            err_cap,
            "canary attestation does not match the exact approval evidence",
        );
        return -1;
    }

    let Some(evidence_sha256) = compute_sha256_hex_internal(json_str.as_bytes(), 0) else {
        copy_error(err_buf, err_cap, "cannot compute canary attestation SHA-256");
        return -1;
    };
    if copy_to_c_buffer(&evidence_sha256, out_sha256, sha_cap) != 0 {
        copy_error(err_buf, err_cap, "cannot compute canary attestation SHA-256");
        return -1;
    }
    emit_string(on_run_id, ctx, run_id);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_host_abi_verify_receipt_evidence(
    receipt: *const MocktailRustParsedApprovalReceipt,
    profile_sha256_ptr: *const c_char,
    manifest_sha256_ptr: *const c_char,
    canary_sha_0_ptr: *const c_char,
    run_id_0_ptr: *const c_char,
    canary_sha_1_ptr: *const c_char,
    run_id_1_ptr: *const c_char,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if receipt.is_null() {
        copy_error(err_buf, err_cap, "invalid arguments");
        return -1;
    }
    let rec = unsafe { &*receipt };
    let (
        Some(generation),
        Some(runtime_build_id),
        Some(payload_fingerprint),
        Some(expected_h0),
        Some(expected_h1),
        Some(profile_sha256),
        Some(manifest_sha256),
        Some(canary_sha_0),
        Some(run_id_0),
        Some(canary_sha_1),
        Some(run_id_1),
    ) = (
        c_str_opt(rec.generation.as_ptr()),
        c_str_opt(rec.runtime_build_id.as_ptr()),
        c_str_opt(rec.payload_fingerprint.as_ptr()),
        c_str_opt(rec.attestation_sha256_0.as_ptr()),
        c_str_opt(rec.attestation_sha256_1.as_ptr()),
        c_str_opt(profile_sha256_ptr),
        c_str_opt(manifest_sha256_ptr),
        c_str_opt(canary_sha_0_ptr),
        c_str_opt(run_id_0_ptr),
        c_str_opt(canary_sha_1_ptr),
        c_str_opt(run_id_1_ptr),
    )
    else {
        copy_error(err_buf, err_cap, "invalid arguments");
        return -1;
    };

    if run_id_0 == run_id_1 {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt canary attestations reuse one run ID",
        );
        return -1;
    }
    if rec.attestation_hashes_valid_array == 0 {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt must bind exactly two canary attestations",
        );
        return -1;
    }
    if rec.attestation_hash_0_is_string == 0
        || rec.attestation_hash_1_is_string == 0
        || expected_h0 != canary_sha_0
        || expected_h1 != canary_sha_1
    {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt canary attestation hash does not match",
        );
        return -1;
    }

    let evidence = format!(
        "runtime_build_id={}\npayload={}\nprofile={}\ncompatibility={}\ncanary_1={}\ncanary_2={}\n",
        runtime_build_id,
        payload_fingerprint,
        profile_sha256,
        manifest_sha256,
        canary_sha_0,
        canary_sha_1,
    );
    let expected_generation = compute_sha256_hex_internal(evidence.as_bytes(), 40).unwrap_or_default();
    if generation != expected_generation {
        copy_error(
            err_buf,
            err_cap,
            "approval receipt evidence generation does not match",
        );
        return -1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe extern "C" fn collect_field_cb(
        ctx: *mut c_void,
        field_id: u32,
        ptr: *const c_char,
        len: usize,
    ) {
        let out = &mut *(ctx as *mut Vec<(u32, String)>);
        let bytes = slice::from_raw_parts(ptr as *const u8, len);
        out.push((field_id, String::from_utf8_lossy(bytes).into_owned()));
    }

    unsafe extern "C" fn collect_string_cb(ctx: *mut c_void, ptr: *const c_char, len: usize) {
        let out = &mut *(ctx as *mut String);
        let bytes = slice::from_raw_parts(ptr as *const u8, len);
        *out = String::from_utf8_lossy(bytes).into_owned();
    }

    #[test]
    fn adjacent_asset_and_active_manifest_parsing() {
        assert_eq!(
            resolve_adjacent_roblox_asset_path_internal(
                "/opt/mocktail/payloads/1-aa/libroblox.so",
                "/tmp"
            ),
            "/opt/mocktail/payloads/1-aa/assets/content"
        );
        assert_eq!(
            resolve_adjacent_roblox_asset_path_internal("rbx_bin/libroblox.so", "/workspace/m"),
            "/workspace/m/rbx_bin/assets/content"
        );
        assert_eq!(resolve_adjacent_roblox_asset_path_internal("", "/workspace"), "");
        assert_eq!(
            resolve_adjacent_roblox_asset_path_internal("libroblox.so", "relative"),
            ""
        );

        let build_id = "0123456789abcdef0123456789abcdef01234567";
        let gen = "fedcba9876543210fedcba9876543210fedcba98";
        let payload_id = format!("42-{}", build_id);
        let manifest = format!(
            concat!(
                "{{",
                "\"schema_version\":1,",
                "\"payload_id\":\"{pid}\",",
                "\"payload_path\":\"payloads/{pid}\",",
                "\"version_name\":\"2.650.0\",",
                "\"version_code\":42,",
                "\"elf_build_id\":\"{bid}\",",
                "\"compatibility_manifest_path\":\"compatibility_profiles/{pid}-{gen}.json\",",
                "\"host_abi_profile_path\":\"host_abi_profiles/{pid}-{gen}.json\",",
                "\"approval_path\":\"approvals/{pid}-{gen}.json\"",
                "}}"
            ),
            pid = payload_id,
            bid = build_id,
            gen = gen
        );
        let mut fields: Vec<(u32, String)> = Vec::new();
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_runtime_paths_parse_active_manifest(
            manifest.as_ptr() as *const c_char,
            manifest.len(),
            Some(collect_field_cb),
            &mut fields as *mut _ as *mut c_void,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(
            fields,
            vec![
                (K_RUNTIME_PATH_FIELD_PAYLOAD_ID, payload_id.clone()),
                (
                    K_RUNTIME_PATH_FIELD_PAYLOAD_REL,
                    format!("payloads/{}", payload_id)
                ),
            ]
        );

        let pid_c = CString::new(payload_id.clone()).unwrap();
        let mut app_fields: Vec<(u32, String)> = Vec::new();
        let mut has_approval: u8 = 0;
        let rc2 = mocktail_rust_runtime_paths_parse_active_approval_refs(
            manifest.as_ptr() as *const c_char,
            manifest.len(),
            pid_c.as_ptr(),
            Some(collect_field_cb),
            &mut app_fields as *mut _ as *mut c_void,
            &mut has_approval,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc2, 0);
        assert_eq!(has_approval, 1);
        assert_eq!(
            app_fields.last().unwrap(),
            &(K_RUNTIME_PATH_FIELD_GENERATION, gen.to_string())
        );

        let bad_gen_manifest = manifest.replace(
            &format!("host_abi_profiles/{}-{}.json", payload_id, gen),
            &format!("host_abi_profiles/{}-0000000000000000000000000000000000000000.json", payload_id),
        );
        let rc3 = mocktail_rust_runtime_paths_parse_active_approval_refs(
            bad_gen_manifest.as_ptr() as *const c_char,
            bad_gen_manifest.len(),
            pid_c.as_ptr(),
            None,
            std::ptr::null_mut(),
            &mut has_approval,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc3, -1);
        let err_str = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(err_str.contains("different generations"));
    }

    #[test]
    fn payload_store_manifest_roundtrip_and_sha_update() {
        let build_id = "0123456789abcdef0123456789abcdef01234567";
        let payload_id = format!("7-{}", build_id);
        let pid_c = CString::new(payload_id.clone()).unwrap();
        let ver_c = CString::new("1.2.3").unwrap();
        let bid_c = CString::new(build_id).unwrap();
        let sha_c = CString::new("a".repeat(64)).unwrap();

        let mut json_out = String::new();
        assert_eq!(
            mocktail_rust_payload_store_build_activation_manifest(
                pid_c.as_ptr(),
                ver_c.as_ptr(),
                7,
                bid_c.as_ptr(),
                sha_c.as_ptr(),
                std::ptr::null(),
                Some(collect_string_cb),
                &mut json_out as *mut _ as *mut c_void,
            ),
            0
        );
        let mut parsed_id = String::new();
        let mut err = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_payload_store_parse_manifest_identity(
                json_out.as_ptr() as *const c_char,
                json_out.len(),
                Some(collect_string_cb),
                &mut parsed_id as *mut _ as *mut c_void,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(parsed_id, payload_id);

        // Missing payload_sha256 triggers rewrite via callback
        let manifest_without_sha = json_without_sha(&payload_id, build_id);
        let mut updated = String::new();
        let mut needs_write = 0u8;
        assert_eq!(
            mocktail_rust_payload_store_persist_payload_sha256(
                manifest_without_sha.as_ptr() as *const c_char,
                manifest_without_sha.len(),
                sha_c.as_ptr(),
                Some(collect_string_cb),
                &mut updated as *mut _ as *mut c_void,
                &mut needs_write,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(needs_write, 1);
        assert!(updated.contains(&"a".repeat(64)));
    }

    fn json_without_sha(payload_id: &str, build_id: &str) -> String {
        format!(
            "{{\"schema_version\":1,\"payload_id\":\"{}\",\"payload_path\":\"payloads/{}\",\"version_name\":\"1.2.3\",\"version_code\":7,\"elf_build_id\":\"{}\"}}",
            payload_id, payload_id, build_id
        )
    }

    #[test]
    fn host_abi_profile_and_receipt_validation() {
        let build_id = "0123456789abcdef0123456789abcdef01234567";
        let ref_bid = "fedcba9876543210fedcba9876543210fedcba98";
        let ref_sha = "b".repeat(64);
        let payload_sha = "c".repeat(64);
        let payload_id = format!("100-{}", build_id);

        let profile_json = format!(
            concat!(
                "{{",
                "\"schema_version\":1,",
                "\"elf_build_id\":\"{bid}\",",
                "\"payload_sha256\":\"{psha}\",",
                "\"payload_path\":\"payloads/{pid}\",",
                "\"payload_id\":\"{pid}\",",
                "\"reference\":{{\"elf_build_id\":\"{rbid}\",\"payload_sha256\":\"{rsha}\"}},",
                "\"derivation_anchors\":{{",
                "\"signature_version\":1,",
                "\"allocator_object_initializer_rva\":\"0x1000\",",
                "\"empty_string_initializer_rva\":\"0x1010\",",
                "\"jni_singleton_initializer_rva\":\"0x1020\",",
                "\"constructor_indices\":{{\"2\":2,\"3\":3,\"4\":4,\"5\":5}},",
                "\"constructor_rvas\":{{\"2\":\"0x1100\",\"3\":\"0x1110\",\"4\":\"0x1120\",\"5\":\"0x1130\"}}",
                "}},",
                "\"profile\":{{",
                "\"elf_build_id\":\"{bid}\",",
                "\"host_allocator_bridges_supported\":true,",
                "\"bridge_entries\":[",
                "{{\"rva\":\"0x2000\",\"kind\":\"allocate\",\"label\":\"small-allocate\"}},",
                "{{\"rva\":\"0x2010\",\"kind\":\"allocate\",\"label\":\"allocate\"}},",
                "{{\"rva\":\"0x2020\",\"kind\":\"usable_size\",\"label\":\"usable-size\"}},",
                "{{\"rva\":\"0x2030\",\"kind\":\"reallocate\",\"label\":\"reallocate\"}},",
                "{{\"rva\":\"0x2040\",\"kind\":\"aligned_allocate\",\"label\":\"aligned-allocate-direct\"}},",
                "{{\"rva\":\"0x2050\",\"kind\":\"free\",\"label\":\"free\"}}",
                "],",
                "\"data_seeds\":{{",
                "\"allocator_object_slot\":\"0x4000\",",
                "\"empty_string_slot\":\"0x4008\",",
                "\"jni_singleton_slot\":\"0x4010\",",
                "\"jni_singleton_bytes\":1024,",
                "\"arena_initializer\":\"0x3000\",",
                "\"allocator_thread_initializer\":\"0x3010\",",
                "\"arena_guard_slot\":\"0x4018\",",
                "\"arena_table_slot\":\"0x4020\",",
                "\"arena_table_slot_count\":4194304",
                "}},",
                "\"native_allocator\":{{\"allocate\":\"0x2010\",\"deallocate\":\"0x2050\"}},",
                "\"native_pre_jni_bootstrap\":{{\"registry_initializer\":\"0x3020\",\"registry_slot\":\"0x4028\"}},",
                "\"init_array_offset\":\"0x5000\",",
                "\"init_array_count\":8,",
                "\"constructor_run_ranges\":[{{\"begin\":2,\"end_exclusive\":3}},{{\"begin\":5,\"end_exclusive\":8}}],",
                "\"native_mimalloc_constructor_run_ranges\":[{{\"begin\":2,\"end_exclusive\":8}}],",
                "\"native_mimalloc_thread_initializer_after_constructor\":2,",
                "\"default_allocator_strategy\":\"native_mimalloc\"",
                "}}",
                "}}"
            ),
            bid = build_id,
            rbid = ref_bid,
            rsha = ref_sha,
            psha = payload_sha,
            pid = payload_id
        );

        let mut parsed = MocktailRustParsedHostAbiProfile::default();
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_host_abi_parse_profile_json(
            profile_json.as_ptr() as *const c_char,
            profile_json.len(),
            true,
            std::mem::align_of::<usize>(),
            usize::MAX as u64,
            &mut parsed,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(parsed.bridge_entry_count, 6);
        assert_eq!(parsed.derivation_code_rva_count, 7);
        assert_eq!(parsed.default_allocator_strategy, 1);

        // Corrupt writable slot alignment -> reject cleanly
        let unaligned = profile_json.replace("\"0x4028\"", "\"0x4024\"");
        let rc_bad = mocktail_rust_host_abi_parse_profile_json(
            unaligned.as_ptr() as *const c_char,
            unaligned.len(),
            true,
            std::mem::align_of::<usize>(),
            usize::MAX as u64,
            &mut parsed,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_bad, -1);
        let err_str = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(err_str.contains("unaligned writable slot"));

        assert!(is_valid_canary_run_id(
            &format!("{}-1-1700000-99", payload_id),
            &payload_id,
            1
        ));
        assert!(!is_valid_canary_run_id(
            &format!("{}-2-1700000-99", payload_id),
            &payload_id,
            1
        ));
    }
}
