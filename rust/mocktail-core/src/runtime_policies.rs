use crate::storage_paths::{c_str_opt, emit_string, slice_to_str, MocktailPayloadStoreStringCallback};
use crate::update_json::MocktailRustStrSlice;
use crate::{
    copy_error, copy_to_c_buffer, is_diagnostic_token_str, is_safe_url_bytes,
    is_valid_browser_tracker_id_bytes, is_valid_build_id_bytes, parse_hex_rva_str,
    parse_status_str, truncate_utf8_str,
};
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::ffi::{c_char, c_void};
use std::fs;

const MAXIMUM_WEBVIEW_JSON_BYTES: usize = 64 * 1024;
const MAXIMUM_WEBVIEW_URL_BYTES: usize = 16 * 1024;

// ============================================================================
// Shared JSON Helpers
// ============================================================================

/// Strips JSONC `//` line comments and `/* ... */` block comments outside of
/// string literals, matching `nlohmann::json::parse(..., ignore_comments=true)`.
pub(crate) fn strip_json_comments(input: &str) -> Cow<'_, str> {
    if !input.contains('/') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let mut copy_from = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'/' {
                out.push_str(&input[copy_from..i]);
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                copy_from = i;
                continue;
            }
            if next == b'*' {
                out.push_str(&input[copy_from..i]);
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i = bytes.len();
                }
                out.push(' ');
                copy_from = i;
                continue;
            }
        }
        i += 1;
    }

    if copy_from == 0 {
        return Cow::Borrowed(input);
    }
    out.push_str(&input[copy_from..]);
    Cow::Owned(out)
}

pub(crate) fn parse_json_value_str(input: &str, allow_comments: bool) -> Option<Value> {
    if allow_comments {
        let stripped = strip_json_comments(input);
        serde_json::from_str(&stripped).ok()
    } else {
        serde_json::from_str(input).ok()
    }
}

pub(crate) fn parse_json_object_str(
    input: &str,
    allow_comments: bool,
) -> Option<Map<String, Value>> {
    match parse_json_value_str(input, allow_comments)? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn has_control_bytes(value: &str) -> bool {
    value.bytes().any(|b| b <= 0x1f || b == 0x7f)
}

fn slice_to_lossy_cow<'a>(ptr: *const c_char, len: usize) -> Cow<'a, str> {
    if len == 0 || ptr.is_null() {
        return Cow::Borrowed("");
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    String::from_utf8_lossy(bytes)
}

/// Validates (and optionally emits compact serialized) JSON object text.
#[no_mangle]
pub extern "C" fn mocktail_rust_json_normalize_object(
    json_ptr: *const c_char,
    json_len: usize,
    allow_comments: bool,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> i32 {
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    let Some(map) = parse_json_object_str(s, allow_comments) else {
        return -1;
    };
    if on_json.is_some() {
        let Ok(compact) = serde_json::to_string(&Value::Object(map)) else {
            return -1;
        };
        emit_string(on_json, ctx, &compact);
    }
    0
}

// ============================================================================
// Support Bundle Active Payload Summary
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_support_bundle_format_payload_summary(
    manifest_ptr: *const c_char,
    manifest_len: usize,
    on_summary: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) {
    let Some(manifest) = slice_to_str(manifest_ptr, manifest_len) else {
        emit_string(on_summary, ctx, "status=unavailable\n");
        return;
    };
    let Some(doc) = parse_json_object_str(manifest, true) else {
        emit_string(on_summary, ctx, "status=unavailable\n");
        return;
    };
    let payload_id = doc.get("payload_id").and_then(|v| v.as_str()).unwrap_or("");
    let version_name = doc.get("version_name").and_then(|v| v.as_str()).unwrap_or("");
    let build_id = doc.get("elf_build_id").and_then(|v| v.as_str()).unwrap_or("");
    if !is_diagnostic_token_str(payload_id)
        || !is_diagnostic_token_str(version_name)
        || build_id.len() != 40
    {
        emit_string(on_summary, ctx, "status=unavailable\n");
        return;
    }
    let summary = format!(
        "status=active\npayload_id={payload_id}\nversion_name={version_name}\nelf_build_id={build_id}\n"
    );
    emit_string(on_summary, ctx, &summary);
}

// ============================================================================
// Compatibility Build Profile Manifest Lookup
// ============================================================================

#[repr(C)]
pub struct MocktailRustBuildProfileView {
    pub version_name: MocktailRustStrSlice,
    pub version_code: i32,
    pub elf_build_id: MocktailRustStrSlice,
    pub status: i32,
    pub default_allowed: bool,
    pub allow_legacy_binary_patches: bool,
    pub allow_host_abi_bridges: bool,
    pub allow_host_constructor_replay: bool,
    pub has_fullscreen_setter_rva: bool,
    pub fullscreen_setter_rva: usize,
    pub has_fmod_bridge: bool,
    pub fmod_vtable_rva: usize,
    pub fmod_string_constructor_rva: usize,
    pub fmod_count_method_rva: usize,
    pub fmod_info_method_rva: usize,
    pub fmod_current_method_rva: usize,
    pub fmod_select_method_rva: usize,
    pub fmod_vtable_layout_version: u8,
    pub fmod_input_method_rvas: [usize; 4],
    pub reason: MocktailRustStrSlice,
}

pub type MocktailBuildProfileCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, profile: *const MocktailRustBuildProfileView)>;

struct FmodBridgeParsed {
    vtable_rva: usize,
    string_constructor_rva: usize,
    count_method_rva: usize,
    info_method_rva: usize,
    current_method_rva: usize,
    select_method_rva: usize,
    vtable_layout_version: u8,
    input_method_rvas: [usize; 4],
}

struct MatchedBuildProfile {
    version_name: String,
    version_code: i32,
    elf_build_id: String,
    status: i32,
    default_allowed: bool,
    allow_legacy_binary_patches: bool,
    allow_host_abi_bridges: bool,
    allow_host_constructor_replay: bool,
    fullscreen_setter_rva: Option<usize>,
    fmod_bridge: Option<FmodBridgeParsed>,
    reason: String,
}

fn parse_optional_rva(object: &Map<String, Value>, name: &str) -> Result<Option<usize>, ()> {
    let Some(val) = object.get(name) else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    let Some(s) = val.as_str() else {
        return Err(());
    };
    parse_hex_rva_str(s).map(Some).map_err(|_| ())
}

fn parse_optional_fmod_bridge(object: &Map<String, Value>) -> Result<Option<FmodBridgeParsed>, ()> {
    let Some(val) = object.get("fmod_output_device_bridge") else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    let Some(bridge_obj) = val.as_object() else {
        return Err(());
    };

    let vtable_rva = parse_optional_rva(bridge_obj, "vtable_rva")?.ok_or(())?;
    let string_constructor_rva =
        parse_optional_rva(bridge_obj, "string_constructor_rva")?.ok_or(())?;
    let count_method_rva = parse_optional_rva(bridge_obj, "count_method_rva")?.ok_or(())?;
    let info_method_rva = parse_optional_rva(bridge_obj, "info_method_rva")?.ok_or(())?;
    let current_method_rva = parse_optional_rva(bridge_obj, "current_method_rva")?.ok_or(())?;
    let select_method_rva = parse_optional_rva(bridge_obj, "select_method_rva")?.ok_or(())?;

    let mut layout: u8 = 1;
    if let Some(layout_val) = bridge_obj.get("vtable_layout_version") {
        let Some(v) = layout_val.as_i64() else {
            return Err(());
        };
        if v != 1 && v != 2 {
            return Err(());
        }
        layout = v as u8;
    }

    const INPUT_FIELDS: [&str; 4] = [
        "input_count_method_rva",
        "input_info_method_rva",
        "input_current_method_rva",
        "input_select_method_rva",
    ];
    let mut input_method_rvas = [0usize; 4];
    let mut present = 0usize;
    for (idx, field_name) in INPUT_FIELDS.iter().enumerate() {
        if let Some(rva) = parse_optional_rva(bridge_obj, field_name)? {
            input_method_rvas[idx] = rva;
            present += 1;
        }
    }
    if present != 0 && present != 4 {
        return Err(());
    }

    Ok(Some(FmodBridgeParsed {
        vtable_rva,
        string_constructor_rva,
        count_method_rva,
        info_method_rva,
        current_method_rva,
        select_method_rva,
        vtable_layout_version: layout,
        input_method_rvas,
    }))
}

fn apply_cached_fmod_input_upgrades(build_id: &str, bridge: &mut FmodBridgeParsed) {
    if bridge.input_method_rvas.iter().any(|&v| v != 0) {
        return;
    }
    if build_id == "ade08266c67aee88ec9c1d00902150e1684dad3a"
        && bridge.vtable_rva == 0x6c58040
        && bridge.vtable_layout_version == 1
    {
        bridge.input_method_rvas = [0x32d12dc, 0x32d12ea, 0x32d13a6, 0x32d0a56];
    } else if build_id == "5f0704edd9064f566ee3d6df2bd2fabbcc709f03"
        && bridge.vtable_rva == 0x6cd3ce0
        && bridge.vtable_layout_version == 2
    {
        bridge.input_method_rvas = [0x320ccf6, 0x320cd04, 0x320d152, 0x320bd18];
    } else if build_id == "a67a91ef96c700c0730acd36a250c2f93cfafbc1"
        && bridge.vtable_rva == 0x6e3d1d0
        && bridge.vtable_layout_version == 2
    {
        bridge.input_method_rvas = [0x2ee4f10, 0x2ee4f1e, 0x2ee536c, 0x2ee3f32];
    }
}

/// Parses and validates a compatibility manifest JSON file, returning the
/// matching Build ID profile (`0` found, `1` not found, `-1` error).
#[no_mangle]
pub extern "C" fn mocktail_rust_find_build_profile(
    manifest_path: *const c_char,
    build_id: *const c_char,
    build_id_len: usize,
    on_profile: MocktailBuildProfileCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let Some(requested) = slice_to_str(build_id, build_id_len) else {
        copy_error(out_err, err_cap, "invalid ELF Build ID: ");
        return -1;
    };
    if !is_valid_build_id_bytes(requested.as_bytes()) {
        copy_error(out_err, err_cap, &format!("invalid ELF Build ID: {requested}"));
        return -1;
    }
    let Some(path) = c_str_opt(manifest_path) else {
        copy_error(out_err, err_cap, "cannot open compatibility manifest: ");
        return -1;
    };
    let Ok(raw) = fs::read_to_string(path) else {
        copy_error(
            out_err,
            err_cap,
            &format!("cannot open compatibility manifest: {path}"),
        );
        return -1;
    };
    let Some(root) = parse_json_object_str(&raw, false) else {
        copy_error(
            out_err,
            err_cap,
            &format!("invalid compatibility manifest JSON: {path}"),
        );
        return -1;
    };
    let schema_ok = root.get("schema_version").and_then(|v| v.as_i64()) == Some(1);
    let Some(profiles) = root.get("profiles").and_then(|v| v.as_array()) else {
        copy_error(
            out_err,
            err_cap,
            &format!("unsupported compatibility manifest schema: {path}"),
        );
        return -1;
    };
    if !schema_ok {
        copy_error(
            out_err,
            err_cap,
            &format!("unsupported compatibility manifest schema: {path}"),
        );
        return -1;
    }

    let normalized_requested = requested.to_ascii_lowercase();
    let mut matched: Option<MatchedBuildProfile> = None;

    for entry_val in profiles {
        let Some(entry) = entry_val.as_object() else {
            copy_error(out_err, err_cap, "compatibility profile is not an object");
            return -1;
        };

        let Some(version_name) = entry.get("version_name").and_then(|v| v.as_str()) else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(version_code) = entry
            .get("version_code")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
        else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(profile_build_id) = entry.get("elf_build_id").and_then(|v| v.as_str()) else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(status_str) = entry.get("status").and_then(|v| v.as_str()) else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(default_allowed) = entry.get("default_allowed").and_then(|v| v.as_bool()) else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(allow_legacy_binary_patches) = entry
            .get("allow_legacy_binary_patches")
            .and_then(|v| v.as_bool())
        else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(allow_host_abi_bridges) =
            entry.get("allow_host_abi_bridges").and_then(|v| v.as_bool())
        else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(allow_host_constructor_replay) = entry
            .get("allow_host_constructor_replay")
            .and_then(|v| v.as_bool())
        else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Some(reason) = entry.get("reason").and_then(|v| v.as_str()) else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Ok(fullscreen_setter_rva) =
            parse_optional_rva(entry, "user_game_settings_fullscreen_setter_rva")
        else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };
        let Ok(mut fmod_bridge) = parse_optional_fmod_bridge(entry) else {
            copy_error(out_err, err_cap, "compatibility profile has missing or invalid fields");
            return -1;
        };

        let normalized_profile = profile_build_id.to_ascii_lowercase();
        if !is_valid_build_id_bytes(normalized_profile.as_bytes()) {
            copy_error(out_err, err_cap, "compatibility profile contains an invalid Build ID");
            return -1;
        }
        let parsed_status = parse_status_str(status_str);
        if parsed_status < 0 {
            copy_error(out_err, err_cap, "compatibility profile contains an unknown status");
            return -1;
        }
        if normalized_profile != normalized_requested {
            continue;
        }
        if matched.is_some() {
            copy_error(
                out_err,
                err_cap,
                &format!("duplicate compatibility profile for Build ID {normalized_requested}"),
            );
            return -1;
        }
        if let Some(ref mut bridge) = fmod_bridge {
            apply_cached_fmod_input_upgrades(&normalized_profile, bridge);
        }
        matched = Some(MatchedBuildProfile {
            version_name: version_name.to_owned(),
            version_code,
            elf_build_id: normalized_profile,
            status: parsed_status,
            default_allowed,
            allow_legacy_binary_patches,
            allow_host_abi_bridges,
            allow_host_constructor_replay,
            fullscreen_setter_rva,
            fmod_bridge,
            reason: reason.to_owned(),
        });
    }

    let Some(ref prof) = matched else {
        return 1;
    };
    if let Some(cb) = on_profile {
        let mut view = MocktailRustBuildProfileView {
            version_name: MocktailRustStrSlice::from_str(&prof.version_name),
            version_code: prof.version_code,
            elf_build_id: MocktailRustStrSlice::from_str(&prof.elf_build_id),
            status: prof.status,
            default_allowed: prof.default_allowed,
            allow_legacy_binary_patches: prof.allow_legacy_binary_patches,
            allow_host_abi_bridges: prof.allow_host_abi_bridges,
            allow_host_constructor_replay: prof.allow_host_constructor_replay,
            has_fullscreen_setter_rva: prof.fullscreen_setter_rva.is_some(),
            fullscreen_setter_rva: prof.fullscreen_setter_rva.unwrap_or(0),
            has_fmod_bridge: false,
            fmod_vtable_rva: 0,
            fmod_string_constructor_rva: 0,
            fmod_count_method_rva: 0,
            fmod_info_method_rva: 0,
            fmod_current_method_rva: 0,
            fmod_select_method_rva: 0,
            fmod_vtable_layout_version: 1,
            fmod_input_method_rvas: [0; 4],
            reason: MocktailRustStrSlice::from_str(&prof.reason),
        };
        if let Some(ref bridge) = prof.fmod_bridge {
            view.has_fmod_bridge = true;
            view.fmod_vtable_rva = bridge.vtable_rva;
            view.fmod_string_constructor_rva = bridge.string_constructor_rva;
            view.fmod_count_method_rva = bridge.count_method_rva;
            view.fmod_info_method_rva = bridge.info_method_rva;
            view.fmod_current_method_rva = bridge.current_method_rva;
            view.fmod_select_method_rva = bridge.select_method_rva;
            view.fmod_vtable_layout_version = bridge.vtable_layout_version;
            view.fmod_input_method_rvas = bridge.input_method_rvas;
        }
        unsafe { cb(ctx, &view) };
    }
    0
}

// ============================================================================
// Performance Policy ClientSettings Merge
// ============================================================================

fn set_compatible_setting(
    overrides: &mut Map<String, Value>,
    name: &str,
    value: &str,
) -> Result<(), String> {
    if let Some(existing) = overrides.get(name) {
        if existing.as_str() != Some(value) {
            return Err(format!("performance policy conflicts with {name}"));
        }
        return Ok(());
    }
    overrides.insert(name.to_owned(), Value::String(value.to_owned()));
    Ok(())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_performance_merge_overrides(
    multithreaded_rendering: bool,
    physics_worker_mode: i32,
    physics_worker_mode_valid: bool,
    available_physical_cores: i32,
    graphics_quality_ptr: *const c_char,
    graphics_quality_len: usize,
    base_json_ptr: *const c_char,
    base_json_len: usize,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    let base = match slice_to_str(base_json_ptr, base_json_len) {
        Some("") => "{}",
        Some(s) => s,
        None => {
            copy_error(out_err, err_cap, "client-settings overrides must be a JSON object");
            return -1;
        }
    };
    let Some(mut overrides) = parse_json_object_str(base, true) else {
        copy_error(out_err, err_cap, "client-settings overrides must be a JSON object");
        return -1;
    };
    if !physics_worker_mode_valid {
        copy_error(out_err, err_cap, "physics worker mode is invalid");
        return -1;
    }
    if !multithreaded_rendering && physics_worker_mode == 0 {
        let Ok(compact) = serde_json::to_string(&Value::Object(overrides)) else {
            return -1;
        };
        emit_string(on_json, ctx, &compact);
        return 0;
    }

    let throughput_mode = physics_worker_mode == 2;
    let latency_mode = physics_worker_mode == 1;
    if latency_mode {
        if let Err(err) = set_compatible_setting(
            &mut overrides,
            "DFIntSimMidPhaseContactPipelineBatchSize",
            "128",
        ) {
            copy_error(out_err, err_cap, &err);
            return -1;
        }
    }

    let render_worker_count = available_physical_cores.max(1);
    if throughput_mode {
        let workers_str = render_worker_count.to_string();
        let async_min_str = render_worker_count.min(3).to_string();
        for (k, v) in [
            ("FIntTaskSchedulerThreadMin", "0"),
            ("FIntTaskSchedulerAsyncTasksMinimumThreadCount", async_min_str.as_str()),
            ("FIntTaskSchedulerAutoThreadLimit", workers_str.as_str()),
            ("DFIntSimMidPhaseContactPipelineBatchSize", "128"),
        ] {
            if let Err(err) = set_compatible_setting(&mut overrides, k, v) {
                copy_error(out_err, err_cap, &err);
                return -1;
            }
        }
    } else if multithreaded_rendering && !latency_mode {
        let workers_str = render_worker_count.to_string();
        for (k, v) in [
            ("FIntTaskSchedulerThreadMin", workers_str.as_str()),
            ("FIntTaskSchedulerAsyncTasksMinimumThreadCount", workers_str.as_str()),
        ] {
            if let Err(err) = set_compatible_setting(&mut overrides, k, v) {
                copy_error(out_err, err_cap, &err);
                return -1;
            }
        }
    }

    if (multithreaded_rendering || throughput_mode) && !latency_mode {
        let workers_str = render_worker_count.to_string();
        let occlusion_str = (render_worker_count / 2).max(1).to_string();
        let quality = slice_to_str(graphics_quality_ptr, graphics_quality_len).unwrap_or("");
        let mip_bias = if quality == "1" { "2" } else { "1" };

        let rendering_settings: [(&str, &str); 61] = [
            ("FIntSmoothClusterTaskQueueMaxParallelTasks", workers_str.as_str()),
            ("FIntOcclusionWorkerThreadCount", occlusion_str.as_str()),
            ("FFlagMovePrerenderV2", "True"),
            ("FFlagGcInParallelWithRenderPrepare3", "True"),
            ("FIntRenderTextureMipBias", mip_bias),
            ("FFlagSimRuntimeContentTranscodeBlockingCall", "False"),
            ("FFlagRenderEnableLowEndLOD", "True"),
            ("FIntTerrainArraySliceSize", "4"),
            ("FFlagRenderFixParticlesCulling", "True"),
            ("FFlagLuauIncrementalGC", "True"),
            ("FIntLuauGcStepMultiplier", "100"),
            ("FIntLuauGcGoalRatio", "200"),
            ("FIntAssetProviderThreads", "2"),
            ("FFlagUITextureCompressionDesktop", "True"),
            ("FFlagTCTextureCompressionDesktop", "True"),
            ("FFlagUITextureUncompressed", "False"),
            ("FFlagMeshCompression", "True"),
            ("FFlagPhysicsMeshCompression", "True"),
            ("FFlagSupportMeshLOD", "True"),
            ("FFlagMeshLOD", "True"),
            ("FFlagMeshLodApplyGeomMeshOptimizer", "False"),
            ("FFlagAdaptiveMeshCacheSizeForAndroid", "True"),
            ("FIntDefaultMeshCacheSizeMB", "64"),
            ("FIntRenderMeshOrphanBudgetMB", "8"),
            ("FIntTerrainGpuMeshMemoryTargetMib", "32"),
            ("FIntAvatarMeshMemoryMax", "33554432"),
            ("FIntSmoothTerrainPhysicsCacheSize", "32"),
            ("FIntRenderTextureTotalBudgetMB", "128"),
            ("FIntRenderTextureOrphanBudgetMB", "8"),
            ("FFlagDebugTerrainVTCompressedTextures", "True"),
            ("FFlagStreamingObserverMemoryOptimization", "True"),
            ("FIntNetworkStreamingGCMaxMicroSecondLimit", "5000"),
            ("FFlagfeatureFastClusterCacheEnabled", "True"),
            ("FFlagEnableMultiVETextureManagerSharing", "True"),
            ("FFlagVulkanCompressedTextureAliasing", "True"),
            ("FFlagCSGPublishDedupSolidMesh", "True"),
            ("FFlagDeduplicateLodRemovalRegions", "True"),
            ("FFlagCurlUsePools", "True"),
            ("FIntRenderTextureCompositorBudget", "32"),
            ("FIntTextureCompositorActiveJobs", "1"),
            ("FIntTextureCompositorLowResFactor", "2"),
            ("FIntTextureCompositorMeshCache", "16"),
            ("FFlagContentProviderMmapAssets", "True"),
            ("FIntAssetProviderAssetCacheReadThreadCount", "1"),
            ("FIntAssetProviderAssetCacheWriteThreadCount", "1"),
            ("FIntInitialAudioAssetCacheSize", "32"),
            ("FIntAvatarTextureMemoryMax", "33554432"),
            ("FFlagEnableSLIMAvatars", "True"),
            ("FFlagEnableSlimAvatarsDefaultEnabled", "True"),
            ("FFlagLayeredClothingCacheOptimizations", "True"),
            ("FFlagLuauStartupGcSuppression", "False"),
            ("FIntLuauGcStepMul", "300"),
            ("FIntLuauGcGoalCore", "120"),
            ("FIntLuauGcStartupWorkingSetMb", "64"),
            ("FIntLuaGcMaxKb", "262144"),
            ("FIntTaskSchedulerMaxTempArenaSizeBytes", "16777216"),
            ("FFlagLocalStorageArenaOptimization", "True"),
            ("FIntProjectedMaxBytesUsedForSoundsMB", "32"),
            ("FIntAudioMetadataCacheSizeKB", "2048"),
            ("FIntDefaultAudioDecodeBufferSizeMs", "50"),
            ("FIntMaxAudibleSoundChannels", "32"),
        ];
        for (k, v) in rendering_settings {
            if let Err(err) = set_compatible_setting(&mut overrides, k, v) {
                copy_error(out_err, err_cap, &err);
                return -1;
            }
        }
    }

    let Ok(compact) = serde_json::to_string(&Value::Object(overrides)) else {
        return -1;
    };
    emit_string(on_json, ctx, &compact);
    0
}

// ============================================================================
// Platform Cache Migration & Roblox Theme Override
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_cache_strip_hydration_keys(
    json_ptr: *const c_char,
    json_len: usize,
    out_changed: *mut bool,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> i32 {
    if !out_changed.is_null() {
        unsafe { *out_changed = false };
    }
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    let Some(mut map) = parse_json_object_str(s, true) else {
        return -1;
    };
    let mut removed = false;
    for key in [
        "PlayerHydrationBlob",
        "PlayerHydrationSignature",
        "AppConfiguration",
    ] {
        if map.remove(key).is_some() {
            removed = true;
        }
    }
    if !out_changed.is_null() {
        unsafe { *out_changed = removed };
    }
    if removed {
        let Ok(compact) = serde_json::to_string(&Value::Object(map)) else {
            return -1;
        };
        emit_string(on_json, ctx, &compact);
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_cache_build_fingerprint(
    schema_version: i32,
    revision_ptr: *const c_char,
    revision_len: usize,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> i32 {
    let Some(revision) = slice_to_str(revision_ptr, revision_len) else {
        return -1;
    };
    let doc = json!({
        "schema_version": schema_version,
        "profile_revision": revision,
    });
    let Ok(compact) = serde_json::to_string(&doc) else {
        return -1;
    };
    emit_string(on_json, ctx, &compact);
    0
}

fn parse_theme_str(val: Option<&Value>) -> Option<bool> {
    match val.and_then(|v| v.as_str()) {
        Some("dark") => Some(true),
        Some("light") => Some(false),
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_cache_read_theme(
    json_ptr: *const c_char,
    json_len: usize,
    authenticated_user_id: i64,
    out_has_theme: *mut bool,
    out_dark_theme: *mut bool,
) -> i32 {
    if !out_has_theme.is_null() {
        unsafe { *out_has_theme = false };
    }
    if !out_dark_theme.is_null() {
        unsafe { *out_dark_theme = false };
    }
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    let Some(storage) = parse_json_object_str(s, true) else {
        return -1;
    };
    if authenticated_user_id >= 0 {
        if let Some(encoded) = storage.get("DeviceLevelTheme").and_then(|v| v.as_str()) {
            if let Some(device_themes) = parse_json_object_str(encoded, true) {
                let key = authenticated_user_id.to_string();
                if let Some(dark) = parse_theme_str(device_themes.get(&key)) {
                    if !out_has_theme.is_null() {
                        unsafe { *out_has_theme = true };
                    }
                    if !out_dark_theme.is_null() {
                        unsafe { *out_dark_theme = dark };
                    }
                    return 0;
                }
            }
        }
    }
    if let Some(dark) = parse_theme_str(storage.get("AuthenticatedTheme")) {
        if !out_has_theme.is_null() {
            unsafe { *out_has_theme = true };
        }
        if !out_dark_theme.is_null() {
            unsafe { *out_dark_theme = dark };
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_platform_cache_apply_theme(
    json_ptr: *const c_char,
    json_len: usize,
    has_storage: bool,
    authenticated_user_id: i64,
    dark_theme: bool,
    out_changed: *mut bool,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if !out_changed.is_null() {
        unsafe { *out_changed = false };
    }
    let mut storage = if has_storage {
        let Some(s) = slice_to_str(json_ptr, json_len) else {
            copy_error(out_err, err_cap, "platform cache metadata is not a JSON object");
            return -1;
        };
        let Some(map) = parse_json_object_str(s, true) else {
            copy_error(out_err, err_cap, "platform cache metadata is not a JSON object");
            return -1;
        };
        map
    } else {
        Map::new()
    };

    let original = storage.clone();
    let desired_theme = if dark_theme { "dark" } else { "light" };
    storage.insert(
        "AuthenticatedTheme".to_owned(),
        Value::String(desired_theme.to_owned()),
    );

    if authenticated_user_id >= 0 {
        let mut device_themes = if let Some(existing) = storage.get("DeviceLevelTheme") {
            let Some(encoded) = existing.as_str() else {
                copy_error(out_err, err_cap, "Roblox DeviceLevelTheme is not an encoded object");
                return -1;
            };
            let Some(parsed) = parse_json_object_str(encoded, true) else {
                copy_error(out_err, err_cap, "Roblox DeviceLevelTheme encoding is invalid");
                return -1;
            };
            parsed
        } else {
            Map::new()
        };
        device_themes.insert(
            authenticated_user_id.to_string(),
            Value::String(desired_theme.to_owned()),
        );
        let Ok(encoded) = serde_json::to_string(&Value::Object(device_themes)) else {
            return -1;
        };
        storage.insert("DeviceLevelTheme".to_owned(), Value::String(encoded));
    }

    let changed = storage != original;
    if !out_changed.is_null() {
        unsafe { *out_changed = changed };
    }
    if changed {
        let Ok(compact) = serde_json::to_string(&Value::Object(storage)) else {
            return -1;
        };
        emit_string(on_json, ctx, &compact);
    }
    0
}

// ============================================================================
// Browser Tracker appStorage & Init Response Helpers
// ============================================================================

pub(crate) fn read_stored_browser_tracker_id_str(json_str: &str) -> Result<Option<String>, ()> {
    let Some(map) = parse_json_object_str(json_str, false) else {
        return Err(());
    };
    let Some(val) = map.get("BrowserTrackerId") else {
        return Ok(None);
    };
    let Some(id_str) = val.as_str() else {
        return Err(());
    };
    if !is_valid_browser_tracker_id_bytes(id_str.as_bytes()) {
        return Err(());
    }
    Ok(Some(id_str.to_owned()))
}

pub(crate) fn set_stored_browser_tracker_id_str(json_str: &str, new_id: &str) -> Option<String> {
    let mut map = if json_str.is_empty() {
        Map::new()
    } else {
        parse_json_object_str(json_str, false)?
    };
    map.insert(
        "BrowserTrackerId".to_owned(),
        Value::String(new_id.to_owned()),
    );
    serde_json::to_string(&Value::Object(map)).ok()
}

pub(crate) fn parse_browser_tracker_init_response_str(body_str: &str) -> Option<String> {
    let body = parse_json_value_str(body_str, false)?;
    let id = match &body {
        Value::Number(num) => num.as_u64().map(|n| n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => match map.get("browserTrackerId") {
            Some(Value::Number(num)) => num.as_u64().map(|n| n.to_string()),
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }?;
    if !is_valid_browser_tracker_id_bytes(id.as_bytes()) {
        return None;
    }
    Some(id)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_tracker_read_stored_id(
    json_ptr: *const c_char,
    json_len: usize,
    out_has_id: *mut bool,
    out_id: *mut c_char,
    id_cap: usize,
) -> i32 {
    if !out_has_id.is_null() {
        unsafe { *out_has_id = false };
    }
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    match read_stored_browser_tracker_id_str(s) {
        Ok(None) => 0,
        Ok(Some(id_str)) => {
            if !out_has_id.is_null() {
                unsafe { *out_has_id = true };
            }
            if !out_id.is_null() && id_cap > 0 && copy_to_c_buffer(&id_str, out_id, id_cap) != 0 {
                return -1;
            }
            0
        }
        Err(()) => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_tracker_set_stored_id(
    json_ptr: *const c_char,
    json_len: usize,
    id_ptr: *const c_char,
    id_len: usize,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(s), Some(id_str)) = (slice_to_str(json_ptr, json_len), slice_to_str(id_ptr, id_len))
    else {
        return -1;
    };
    let Some(compact) = set_stored_browser_tracker_id_str(s, id_str) else {
        return -1;
    };
    emit_string(on_json, ctx, &compact);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_browser_tracker_parse_init_response(
    body_ptr: *const c_char,
    body_len: usize,
    out_id: *mut c_char,
    id_cap: usize,
) -> i32 {
    let Some(body_str) = slice_to_str(body_ptr, body_len) else {
        return -1;
    };
    let Some(id_str) = parse_browser_tracker_init_response_str(body_str) else {
        return -1;
    };
    if copy_to_c_buffer(&id_str, out_id, id_cap) != 0 {
        return -1;
    }
    0
}

// ============================================================================
// Discord RPC Frame & Metadata Helpers
// ============================================================================

#[repr(C)]
pub struct MocktailRustDiscordActivity {
    pub details: *const c_char,
    pub details_len: usize,
    pub state: *const c_char,
    pub state_len: usize,
    pub has_start_timestamp: bool,
    pub start_timestamp: i64,
    pub large_image: *const c_char,
    pub large_image_len: usize,
    pub large_text: *const c_char,
    pub large_text_len: usize,
    pub button_label: *const c_char,
    pub button_label_len: usize,
    pub button_url: *const c_char,
    pub button_url_len: usize,
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_parse_rpc_error(
    payload_ptr: *const c_char,
    payload_len: usize,
    out_code: *mut i64,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> i32 {
    let Some(payload) = slice_to_str(payload_ptr, payload_len) else {
        return -1;
    };
    let Some((code, message)) = crate::discord_rpc::parse_rpc_error_fields(payload) else {
        return -1;
    };
    if !out_code.is_null() {
        unsafe { *out_code = code };
    }
    copy_error(out_msg, msg_cap, &message);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_build_handshake(
    app_id_ptr: *const c_char,
    app_id_len: usize,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> i32 {
    if app_id_ptr.is_null() && app_id_len > 0 {
        return -1;
    }
    let app_id = slice_to_lossy_cow(app_id_ptr, app_id_len);
    let Some(compact) = crate::discord_rpc::build_handshake_json(&app_id) else {
        return -1;
    };
    emit_string(on_json, ctx, &compact);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_is_ready_event(
    payload_ptr: *const c_char,
    payload_len: usize,
) -> bool {
    let Some(payload) = slice_to_str(payload_ptr, payload_len) else {
        return false;
    };
    crate::discord_rpc::is_ready_event_json(payload)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_build_set_activity(
    pid: i32,
    activity: *const MocktailRustDiscordActivity,
    nonce: u64,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> i32 {
    let built = if activity.is_null() {
        None
    } else {
        let act = unsafe { &*activity };
        Some(crate::discord_rpc::BuiltActivity {
            details: slice_to_lossy_cow(act.details, act.details_len).into_owned(),
            state: slice_to_lossy_cow(act.state, act.state_len).into_owned(),
            start_timestamp: if act.has_start_timestamp {
                Some(act.start_timestamp)
            } else {
                None
            },
            large_image: slice_to_lossy_cow(act.large_image, act.large_image_len).into_owned(),
            large_text: slice_to_lossy_cow(act.large_text, act.large_text_len).into_owned(),
            button_label: slice_to_lossy_cow(act.button_label, act.button_label_len).into_owned(),
            button_url: slice_to_lossy_cow(act.button_url, act.button_url_len).into_owned(),
        })
    };

    let Some(compact) = crate::discord_rpc::build_set_activity_json(pid, built.as_ref(), nonce)
    else {
        return -1;
    };
    emit_string(on_json, ctx, &compact);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_parse_universe_id(
    json_ptr: *const c_char,
    json_len: usize,
    out_universe_id: *mut i64,
) -> i32 {
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    let Some(obj) = parse_json_object_str(s, false) else {
        return -1;
    };
    let Some(val) = obj.get("universeId") else {
        return -1;
    };
    let Some(uid) = val.as_i64() else {
        return -1;
    };
    if uid <= 0 {
        return -1;
    }
    if !out_universe_id.is_null() {
        unsafe { *out_universe_id = uid };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_parse_game_name(
    json_ptr: *const c_char,
    json_len: usize,
    out_name: *mut c_char,
    name_cap: usize,
) -> i32 {
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    let Some(obj) = parse_json_object_str(s, false) else {
        return -1;
    };
    let Some(name) = obj
        .get("data")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_object())
        .and_then(|first| first.get("name"))
        .and_then(|v| v.as_str())
    else {
        return -1;
    };
    let truncated = truncate_utf8_str(name, 128);
    if copy_to_c_buffer(truncated, out_name, name_cap) != 0 {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_discord_parse_icon_url(
    json_ptr: *const c_char,
    json_len: usize,
    out_url: *mut c_char,
    url_cap: usize,
) -> i32 {
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        return -1;
    };
    let Some(obj) = parse_json_object_str(s, false) else {
        return -1;
    };
    let Some(icon_url) = obj
        .get("data")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_object())
        .and_then(|first| first.get("imageUrl"))
        .and_then(|v| v.as_str())
    else {
        return -1;
    };
    if !is_safe_url_bytes(icon_url.as_bytes(), 512) {
        return -1;
    }
    if copy_to_c_buffer(icon_url, out_url, url_cap) != 0 {
        return -1;
    }
    0
}

// ============================================================================
// Roblox WebView & Captcha Open JSON Parsers
// ============================================================================

#[repr(C)]
pub struct MocktailRustWebViewOpenView {
    pub url: MocktailRustStrSlice,
    pub has_title: bool,
    pub title: MocktailRustStrSlice,
    pub has_is_visible: bool,
    pub is_visible: bool,
    pub has_window_type: bool,
    pub window_type: MocktailRustStrSlice,
    pub has_show_domain_as_title: bool,
    pub show_domain_as_title: bool,
    pub has_back_button_visible: bool,
    pub back_button_visible: bool,
    pub has_hide_header: bool,
    pub hide_header: bool,
    pub has_search_type: bool,
    pub search_type: MocktailRustStrSlice,
}

pub type MocktailWebViewOpenCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, view: *const MocktailRustWebViewOpenView)>;

#[repr(C)]
pub struct MocktailRustWebViewMutationView {
    pub has_url: bool,
    pub url: MocktailRustStrSlice,
    pub has_title: bool,
    pub title: MocktailRustStrSlice,
    pub has_is_visible: bool,
    pub is_visible: bool,
    pub has_window_type: bool,
    pub window_type: MocktailRustStrSlice,
    pub has_show_domain_as_title: bool,
    pub show_domain_as_title: bool,
    pub has_search_type: bool,
    pub search_type: MocktailRustStrSlice,
}

pub type MocktailWebViewMutationCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, view: *const MocktailRustWebViewMutationView)>;

pub type MocktailCaptchaOpenCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        is_login: bool,
        normalized_type: *const c_char,
        type_len: usize,
        credential_value: *const c_char,
        value_len: usize,
    ),
>;

fn parse_optional_webview_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<&'a str>, String> {
    let Some(val) = obj.get(key) else {
        return Ok(None);
    };
    let Some(s) = val.as_str() else {
        return Err(format!("WebView mutation field {key} must be a string"));
    };
    if s.len() > max_bytes || has_control_bytes(s) {
        return Err(format!("WebView mutation field {key} is invalid"));
    }
    Ok(Some(s))
}

fn parse_optional_webview_bool(
    obj: &Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, String> {
    let Some(val) = obj.get(key) else {
        return Ok(None);
    };
    let Some(b) = val.as_bool() else {
        return Err(format!("WebView mutation field {key} must be a boolean"));
    };
    Ok(Some(b))
}

fn opt_str_slice(value: Option<&str>) -> (bool, MocktailRustStrSlice) {
    match value {
        Some(s) => (true, MocktailRustStrSlice::from_str(s)),
        None => (false, MocktailRustStrSlice::from_str("")),
    }
}

fn parse_webview_search_type<'a>(
    doc: &'a Map<String, Value>,
    kind: &str,
) -> Result<Option<&'a str>, String> {
    let Some(sp_val) = doc.get("searchParams") else {
        return Ok(None);
    };
    let Some(sp) = sp_val.as_object() else {
        return Err(format!("WebView {kind} field searchParams must be an object"));
    };
    parse_optional_webview_str(sp, "searchType", 512)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_parse_open_json(
    json_ptr: *const c_char,
    json_len: usize,
    on_parsed: MocktailWebViewOpenCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if json_len == 0 || json_len > MAXIMUM_WEBVIEW_JSON_BYTES {
        copy_error(out_err, err_cap, "WebView open JSON size is invalid");
        return -1;
    }
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        copy_error(out_err, err_cap, "WebView open payload is not a JSON object");
        return -1;
    };
    let Some(doc) = parse_json_object_str(s, false) else {
        copy_error(out_err, err_cap, "WebView open payload is not a JSON object");
        return -1;
    };
    let Some(url) = doc.get("url").and_then(|v| v.as_str()) else {
        copy_error(out_err, err_cap, "WebView open payload requires a string url");
        return -1;
    };
    if url.is_empty() || url.len() > MAXIMUM_WEBVIEW_URL_BYTES {
        copy_error(out_err, err_cap, "WebView open url size is invalid");
        return -1;
    }

    let title = if let Some(val) = doc.get("title") {
        let Some(t) = val.as_str() else {
            copy_error(out_err, err_cap, "WebView open title is invalid");
            return -1;
        };
        if t.len() > 512 || has_control_bytes(t) {
            copy_error(out_err, err_cap, "WebView open title is invalid");
            return -1;
        }
        Some(t)
    } else {
        None
    };

    let is_visible = match parse_optional_webview_bool(&doc, "isVisible") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let window_type = match parse_optional_webview_str(&doc, "windowType", 512) {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let show_domain_as_title = match parse_optional_webview_bool(&doc, "showDomainAsTitle") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let back_button_visible = match parse_optional_webview_bool(&doc, "backButtonVisible") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let hide_header = match parse_optional_webview_bool(&doc, "hideHeader") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let search_type = match parse_webview_search_type(&doc, "open") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };

    let (has_title, title_slice) = opt_str_slice(title);
    let (has_window_type, window_type_slice) = opt_str_slice(window_type);
    let (has_search_type, search_type_slice) = opt_str_slice(search_type);
    if let Some(cb) = on_parsed {
        let view = MocktailRustWebViewOpenView {
            url: MocktailRustStrSlice::from_str(url),
            has_title,
            title: title_slice,
            has_is_visible: is_visible.is_some(),
            is_visible: is_visible.unwrap_or(false),
            has_window_type,
            window_type: window_type_slice,
            has_show_domain_as_title: show_domain_as_title.is_some(),
            show_domain_as_title: show_domain_as_title.unwrap_or(false),
            has_back_button_visible: back_button_visible.is_some(),
            back_button_visible: back_button_visible.unwrap_or(false),
            has_hide_header: hide_header.is_some(),
            hide_header: hide_header.unwrap_or(false),
            has_search_type,
            search_type: search_type_slice,
        };
        unsafe { cb(ctx, &view) };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_parse_mutation_json(
    json_ptr: *const c_char,
    json_len: usize,
    on_parsed: MocktailWebViewMutationCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if json_len == 0 || json_len > MAXIMUM_WEBVIEW_JSON_BYTES {
        copy_error(out_err, err_cap, "WebView mutation JSON size is invalid");
        return -1;
    }
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        copy_error(
            out_err,
            err_cap,
            "WebView mutation payload is not a JSON object",
        );
        return -1;
    };
    let Some(doc) = parse_json_object_str(s, false) else {
        copy_error(
            out_err,
            err_cap,
            "WebView mutation payload is not a JSON object",
        );
        return -1;
    };
    let url = match parse_optional_webview_str(&doc, "url", MAXIMUM_WEBVIEW_URL_BYTES) {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let title = match parse_optional_webview_str(&doc, "title", 512) {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let is_visible = match parse_optional_webview_bool(&doc, "isVisible") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let window_type = match parse_optional_webview_str(&doc, "windowType", 512) {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let show_domain_as_title = match parse_optional_webview_bool(&doc, "showDomainAsTitle") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };
    let search_type = match parse_webview_search_type(&doc, "mutation") {
        Ok(v) => v,
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            return -1;
        }
    };

    let (has_url, url_slice) = opt_str_slice(url);
    let (has_title, title_slice) = opt_str_slice(title);
    let (has_window_type, window_type_slice) = opt_str_slice(window_type);
    let (has_search_type, search_type_slice) = opt_str_slice(search_type);
    if let Some(cb) = on_parsed {
        let view = MocktailRustWebViewMutationView {
            has_url,
            url: url_slice,
            has_title,
            title: title_slice,
            has_is_visible: is_visible.is_some(),
            is_visible: is_visible.unwrap_or(false),
            has_window_type,
            window_type: window_type_slice,
            has_show_domain_as_title: show_domain_as_title.is_some(),
            show_domain_as_title: show_domain_as_title.unwrap_or(false),
            has_search_type,
            search_type: search_type_slice,
        };
        unsafe { cb(ctx, &view) };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_webview_parse_captcha_open_json(
    json_ptr: *const c_char,
    json_len: usize,
    on_parsed: MocktailCaptchaOpenCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> i32 {
    if json_len == 0 || json_len > MAXIMUM_WEBVIEW_JSON_BYTES {
        copy_error(out_err, err_cap, "captcha open JSON size is invalid");
        return -1;
    }
    let Some(s) = slice_to_str(json_ptr, json_len) else {
        copy_error(out_err, err_cap, "captcha open payload is not a JSON object");
        return -1;
    };
    let Some(doc) = parse_json_object_str(s, false) else {
        copy_error(out_err, err_cap, "captcha open payload is not a JSON object");
        return -1;
    };
    let Some(captcha_type) = doc.get("captchaType").and_then(|v| v.as_str()) else {
        copy_error(out_err, err_cap, "captcha open payload requires captchaType");
        return -1;
    };
    if captcha_type != "login" {
        if let Some(cb) = on_parsed {
            unsafe { cb(ctx, false, std::ptr::null(), 0, std::ptr::null(), 0) };
        }
        return 0;
    }
    let Some(cred_type) = doc.get("cvalueType").and_then(|v| v.as_str()) else {
        copy_error(
            out_err,
            err_cap,
            "login captcha requires credential type and value",
        );
        return -1;
    };
    let Some(cred_value) = doc.get("cvalue").and_then(|v| v.as_str()) else {
        copy_error(
            out_err,
            err_cap,
            "login captcha requires credential type and value",
        );
        return -1;
    };
    let normalized_type = match cred_type {
        "phone_number" => "phonenumber",
        "username" => "username",
        "email" => "email",
        _ => {
            copy_error(out_err, err_cap, "login captcha credential type is unsupported");
            return -1;
        }
    };
    if cred_value.is_empty() || cred_value.len() > 4096 || has_control_bytes(cred_value) {
        copy_error(out_err, err_cap, "login captcha credential value is invalid");
        return -1;
    }
    if let Some(cb) = on_parsed {
        unsafe {
            cb(
                ctx,
                true,
                normalized_type.as_ptr() as *const c_char,
                normalized_type.len(),
                cred_value.as_ptr() as *const c_char,
                cred_value.len(),
            )
        };
    }
    0
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe extern "C" fn capture_str(ctx: *mut c_void, ptr: *const c_char, len: usize) {
        let out = &mut *(ctx as *mut String);
        let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
        *out = String::from_utf8_lossy(bytes).into_owned();
    }

    #[test]
    fn strip_json_comments_preserves_strings_and_strips_comments() {
        let src = "{\n  // line comment\n  \"url\": \"https://example.com//a/*b*/\", /* block */ \"n\": 1\n}";
        let stripped = strip_json_comments(src);
        let v: Value = serde_json::from_str(&stripped).expect("valid stripped JSON");
        assert_eq!(v["url"], "https://example.com//a/*b*/");
        assert_eq!(v["n"], 1);
    }

    #[test]
    fn support_bundle_formats_active_and_unavailable() {
        let valid = CString::new(format!(
            "{{\"payload_id\":\"3100-abc\",\"version_name\":\"2.738.0\",\"elf_build_id\":\"{}\"}}",
            "a".repeat(40)
        ))
        .unwrap();
        let mut out = String::new();
        mocktail_rust_support_bundle_format_payload_summary(
            valid.as_ptr(),
            valid.as_bytes().len(),
            Some(capture_str),
            &mut out as *mut String as *mut c_void,
        );
        assert!(out.starts_with("status=active\npayload_id=3100-abc\nversion_name=2.738.0\n"));

        let bad = CString::new("{}").unwrap();
        mocktail_rust_support_bundle_format_payload_summary(
            bad.as_ptr(),
            bad.as_bytes().len(),
            Some(capture_str),
            &mut out as *mut String as *mut c_void,
        );
        assert_eq!(out, "status=unavailable\n");
    }

    #[test]
    fn performance_merge_detects_conflicts_and_applies_rendering() {
        let mut out = String::new();
        let mut err = [0 as c_char; 256];
        let base = r#"{"FFlagMovePrerenderV2":"False"}"#;
        let rc = mocktail_rust_performance_merge_overrides(
            true,
            0,
            true,
            4,
            std::ptr::null(),
            0,
            base.as_ptr() as *const c_char,
            base.len(),
            Some(capture_str),
            &mut out as *mut String as *mut c_void,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, -1);
        let err_str = unsafe { std::ffi::CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert_eq!(err_str, "performance policy conflicts with FFlagMovePrerenderV2");

        let rc_ok = mocktail_rust_performance_merge_overrides(
            true,
            2,
            true,
            4,
            b"1".as_ptr() as *const c_char,
            1,
            b"".as_ptr() as *const c_char,
            0,
            Some(capture_str),
            &mut out as *mut String as *mut c_void,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_ok, 0);
        let merged: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(merged["FIntRenderTextureMipBias"], "2");
        assert_eq!(merged["FIntTaskSchedulerAutoThreadLimit"], "4");
        assert_eq!(merged["FIntTaskSchedulerAsyncTasksMinimumThreadCount"], "3");
    }

    #[test]
    fn platform_cache_theme_and_hydration_round_trip() {
        let storage = r#"{"PlayerHydrationBlob":"x","AuthenticatedTheme":"light","DeviceLevelTheme":"{\"42\":\"dark\"}"}"#;
        let mut has_theme = false;
        let mut dark = false;
        assert_eq!(
            mocktail_rust_platform_cache_read_theme(
                storage.as_ptr() as *const c_char,
                storage.len(),
                42,
                &mut has_theme,
                &mut dark,
            ),
            0
        );
        assert!(has_theme && dark);

        let mut stripped = String::new();
        let mut changed = false;
        assert_eq!(
            mocktail_rust_platform_cache_strip_hydration_keys(
                storage.as_ptr() as *const c_char,
                storage.len(),
                &mut changed,
                Some(capture_str),
                &mut stripped as *mut String as *mut c_void,
            ),
            0
        );
        assert!(changed);
        let stripped_val: Value = serde_json::from_str(&stripped).unwrap();
        assert!(stripped_val.get("PlayerHydrationBlob").is_none());

        let mut applied = String::new();
        let mut err = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_platform_cache_apply_theme(
                stripped.as_ptr() as *const c_char,
                stripped.len(),
                true,
                42,
                false,
                &mut changed,
                Some(capture_str),
                &mut applied as *mut String as *mut c_void,
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert!(changed);
        assert_eq!(
            mocktail_rust_platform_cache_read_theme(
                applied.as_ptr() as *const c_char,
                applied.len(),
                42,
                &mut has_theme,
                &mut dark,
            ),
            0
        );
        assert!(has_theme && !dark);
    }

    #[test]
    fn browser_tracker_and_discord_parsers_validate_inputs() {
        let resp = r#"{"browserTrackerId":987654321}"#;
        let mut id_buf = [0 as c_char; 32];
        assert_eq!(
            mocktail_rust_browser_tracker_parse_init_response(
                resp.as_ptr() as *const c_char,
                resp.len(),
                id_buf.as_mut_ptr(),
                id_buf.len(),
            ),
            0
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(id_buf.as_ptr()) }.to_str().unwrap(),
            "987654321"
        );

        let rpc_err = r#"{"evt":"ERROR","data":{"code":4002,"message":"bad\npayload"}}"#;
        let mut code = 0i64;
        let mut msg_buf = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_discord_parse_rpc_error(
                rpc_err.as_ptr() as *const c_char,
                rpc_err.len(),
                &mut code,
                msg_buf.as_mut_ptr(),
                msg_buf.len(),
            ),
            0
        );
        assert_eq!(code, 4002);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(msg_buf.as_ptr()) }.to_str().unwrap(),
            "bad payload"
        );
    }
}
