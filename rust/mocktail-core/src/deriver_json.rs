use crate::runtime_policies::parse_json_object_str;
use crate::storage_paths::{emit_string, slice_to_str, MocktailPayloadStoreStringCallback};
use crate::update_json::MocktailRustStrSlice;
use crate::{copy_error, copy_to_c_buffer};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void};
use std::path::Path;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MocktailRustDeriverRuntimeAnchors {
    pub has_fullscreen_setter: bool,
    pub fullscreen_setter_rva: u64,
    pub has_fmod: bool,
    pub fmod_vtable_rva: u64,
    pub fmod_string_constructor_rva: u64,
    pub fmod_count_method_rva: u64,
    pub fmod_info_method_rva: u64,
    pub fmod_current_method_rva: u64,
    pub fmod_select_method_rva: u64,
    pub fmod_layout_version: i32,
    pub fmod_input_methods: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MocktailRustDeriverPlan {
    pub candidate_constructor_indices: [usize; 4],
    pub candidate_constructor_rvas: [u64; 4],
    pub allocator_object_slot_rva: u64,
    pub empty_string_slot_rva: u64,
    pub jni_singleton_slot_rva: u64,
    pub arena_guard_slot_rva: u64,
    pub arena_table_slot_rva: u64,
    pub old_registry_initializer_rva: u64,
    pub old_registry_slot_rva: u64,
}

#[repr(C)]
pub struct MocktailRustDeriverBuildInputs {
    pub ref_build_id: MocktailRustStrSlice,
    pub ref_sha256: MocktailRustStrSlice,
    pub cand_build_id: MocktailRustStrSlice,
    pub cand_sha256: MocktailRustStrSlice,
    pub reference_init_count: usize,
    pub candidate_init_count: usize,
    pub init_array_offset: u64,
    pub bridge_rvas: [u64; 6],
    pub arena_initializer_rva: u64,
    pub allocator_thread_initializer_rva: u64,
    pub registry_initializer_rva: u64,
    pub registry_slot_rva: u64,
    pub allocator_object_initializer_rva: u64,
    pub empty_string_initializer_rva: u64,
    pub jni_singleton_initializer_rva: u64,
    pub allocator_object_slot_rva: u64,
    pub empty_string_slot_rva: u64,
    pub jni_singleton_slot_rva: u64,
    pub arena_guard_slot_rva: u64,
    pub arena_table_slot_rva: u64,
    pub candidate_constructor_rvas: [u64; 4],
    pub candidate_constructor_indices: [usize; 4],
    pub has_derived_fullscreen_setter: bool,
    pub derived_fullscreen_setter_rva: u64,
    pub has_derived_fmod: bool,
    pub derived_fmod_vtable_rva: u64,
    pub derived_fmod_string_constructor_rva: u64,
    pub derived_fmod_count_method_rva: u64,
    pub derived_fmod_info_method_rva: u64,
    pub derived_fmod_current_method_rva: u64,
    pub derived_fmod_select_method_rva: u64,
    pub derived_fmod_layout_version: i32,
    pub derived_fmod_has_input: bool,
    pub derived_fmod_input_methods: [u64; 4],
}

const BRIDGE_SIGNATURES: [(&str, usize); 6] = [
    ("small-allocate", 24),
    ("usable-size", 18),
    ("reallocate", 24),
    ("allocate", 24),
    ("aligned-allocate-direct", 24),
    ("free", 24),
];

fn slice_from_raw(s: MocktailRustStrSlice) -> Option<&'static str> {
    slice_to_str(s.ptr, s.len)
}

fn json_int_eq_one(map: &Map<String, Value>, key: &str) -> bool {
    match map.get(key) {
        Some(v) => v.as_i64() == Some(1) || v.as_u64() == Some(1),
        None => false,
    }
}

fn json_str_or_empty<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or("")
}

fn parse_rva(value: &Value, description: &str) -> Result<u64, String> {
    let encoded = value
        .as_str()
        .ok_or_else(|| format!("{description} must be a nonzero hex RVA"))?;
    let bytes = encoded.as_bytes();
    if bytes.len() < 3
        || !encoded.starts_with("0x")
        || bytes[2] == b'0'
        || !bytes[2..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(format!("{description} must be a canonical nonzero hex RVA"));
    }
    u64::from_str_radix(&encoded[2..], 16)
        .map_err(|_| format!("{description} RVA exceeds 64 bits"))
}

fn profile_rva(object: &Map<String, Value>, field: &str) -> Result<u64, String> {
    let val = object
        .get(field)
        .ok_or_else(|| format!("reference profile is missing {field}"))?;
    parse_rva(val, field)
}

fn format_rva(value: u64) -> String {
    if value == 0 {
        "0x".to_string()
    } else {
        format!("0x{value:x}")
    }
}

fn positive_size(value: Option<&Value>, description: &str) -> Result<usize, String> {
    let num = value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{description} must be a positive integer"))?;
    if num == 0 {
        return Err(format!("{description} is outside native size bounds"));
    }
    usize::try_from(num).map_err(|_| format!("{description} is outside native size bounds"))
}

fn adjust_ranges(
    ranges: Option<&Value>,
    reference_count: usize,
    candidate_count: usize,
) -> Result<Value, String> {
    let arr = ranges
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "constructor ranges are missing".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    let mut previous_end = 0usize;
    for range in arr {
        let obj = range
            .as_object()
            .ok_or_else(|| "constructor range is invalid".to_string())?;
        let begin_u64 = obj
            .get("begin")
            .and_then(Value::as_u64)
            .ok_or_else(|| "constructor range is invalid".to_string())?;
        let end_u64 = obj
            .get("end_exclusive")
            .and_then(Value::as_u64)
            .ok_or_else(|| "constructor range is invalid".to_string())?;
        let begin = usize::try_from(begin_u64)
            .map_err(|_| "constructor range cannot fit candidate init-array".to_string())?;
        let mut end = usize::try_from(end_u64)
            .map_err(|_| "constructor range cannot fit candidate init-array".to_string())?;
        if end == reference_count {
            end = candidate_count;
        }
        if begin >= end || begin < previous_end || end > candidate_count {
            return Err("constructor range cannot fit candidate init-array".to_string());
        }
        out.push(json!({"begin": begin, "end_exclusive": end}));
        previous_end = end;
    }
    Ok(Value::Array(out))
}

fn parse_sidecar_object(json_ptr: *const c_char, json_len: usize) -> Option<Map<String, Value>> {
    let raw = slice_to_str(json_ptr, json_len)?;
    parse_json_object_str(raw, true)
}

pub(crate) fn validate_reference_identity_inner(
    sidecar: &Map<String, Value>,
    ref_build_id: &str,
    ref_sha256: &str,
) -> Result<(), String> {
    let profile = sidecar.get("profile").and_then(Value::as_object);
    let anchors = sidecar.get("derivation_anchors").and_then(Value::as_object);
    let identity_ok = json_int_eq_one(sidecar, "schema_version")
        && json_str_or_empty(sidecar, "elf_build_id") == ref_build_id
        && json_str_or_empty(sidecar, "payload_sha256") == ref_sha256
        && profile.is_some_and(|p| json_str_or_empty(p, "elf_build_id") == ref_build_id)
        && anchors.is_some_and(|a| json_int_eq_one(a, "signature_version"));
    if !identity_ok {
        return Err("reference ELF bytes do not match exact HostAbi sidecar".to_string());
    }
    let payload_id = json_str_or_empty(sidecar, "payload_id");
    let suffix_ok = payload_id.len() > 41
        && payload_id
            .get(payload_id.len() - 40..)
            .is_some_and(|tail| tail == ref_build_id);
    if payload_id.is_empty()
        || json_str_or_empty(sidecar, "payload_path") != format!("payloads/{payload_id}")
        || !suffix_ok
    {
        return Err("reference HostAbi sidecar payload identity is inconsistent".to_string());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct ParsedSpec {
    pub(crate) name: &'static str,
    pub(crate) rva: u64,
    pub(crate) instruction_count: usize,
    pub(crate) registry_size_may_change: bool,
    pub(crate) minimum_anchor_bytes: usize,
}

pub(crate) fn extract_specs_inner(sidecar: &Map<String, Value>) -> Result<Vec<ParsedSpec>, String> {
    let profile = sidecar
        .get("profile")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let anchors = sidecar
        .get("derivation_anchors")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let bridge_entries = profile
        .get("bridge_entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let seeds = profile
        .get("data_seeds")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let bootstrap = profile
        .get("native_pre_jni_bootstrap")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let constructors = anchors
        .get("constructor_rvas")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;

    let mut bridges: BTreeMap<String, u64> = BTreeMap::new();
    for entry in bridge_entries {
        let obj = entry
            .as_object()
            .ok_or_else(|| "reference HostAbi bridge is incomplete".to_string())?;
        let label = obj
            .get("label")
            .and_then(Value::as_str)
            .ok_or_else(|| "reference HostAbi bridge is incomplete".to_string())?;
        let rva_val = obj
            .get("rva")
            .ok_or_else(|| "reference HostAbi bridge is incomplete".to_string())?;
        let rva = parse_rva(rva_val, "reference bridge")?;
        if bridges.insert(label.to_string(), rva).is_some() {
            return Err("reference HostAbi bridge is duplicated".to_string());
        }
    }

    let mut specs = Vec::with_capacity(15);
    for &(label, count) in &BRIDGE_SIGNATURES {
        let rva = bridges
            .get(label)
            .copied()
            .ok_or_else(|| format!("reference HostAbi bridge is missing: {label}"))?;
        specs.push(ParsedSpec {
            name: label,
            rva,
            instruction_count: count,
            registry_size_may_change: false,
            minimum_anchor_bytes: 6,
        });
    }

    let add_field = |specs: &mut Vec<ParsedSpec>,
                     name: &'static str,
                     map: &Map<String, Value>,
                     field: &str,
                     count: usize,
                     registry: bool,
                     min_bytes: usize|
     -> Result<(), String> {
        let val = map.get(field).unwrap_or(&Value::Null);
        let rva = parse_rva(val, name)?;
        specs.push(ParsedSpec {
            name,
            rva,
            instruction_count: count,
            registry_size_may_change: registry,
            minimum_anchor_bytes: min_bytes,
        });
        Ok(())
    };

    add_field(
        &mut specs,
        "arena-initializer",
        seeds,
        "arena_initializer",
        24,
        false,
        6,
    )?;
    add_field(
        &mut specs,
        "allocator-thread-initializer",
        seeds,
        "allocator_thread_initializer",
        19,
        false,
        6,
    )?;
    add_field(
        &mut specs,
        "registry-initializer",
        bootstrap,
        "registry_initializer",
        20,
        true,
        6,
    )?;
    add_field(
        &mut specs,
        "allocator-object-initializer",
        anchors,
        "allocator_object_initializer_rva",
        19,
        false,
        6,
    )?;
    add_field(
        &mut specs,
        "empty-string-initializer",
        anchors,
        "empty_string_initializer_rva",
        23,
        false,
        6,
    )?;
    add_field(
        &mut specs,
        "jni-singleton-initializer",
        anchors,
        "jni_singleton_initializer_rva",
        11,
        false,
        6,
    )?;
    add_field(&mut specs, "constructor-2", constructors, "2", 24, false, 6)?;
    add_field(&mut specs, "constructor-3", constructors, "3", 24, false, 6)?;
    add_field(&mut specs, "constructor-4", constructors, "4", 24, false, 3)?;

    Ok(specs)
}

pub(crate) fn parse_sidecar_identity(
    json_bytes: &[u8],
    sidecar_path: &Path,
) -> Result<(String, String), String> {
    let sidecar_display = sidecar_path.display();
    let Some(map) = parse_sidecar_object(json_bytes.as_ptr().cast::<c_char>(), json_bytes.len())
    else {
        return Err(format!("JSON input must contain one object: {sidecar_display}"));
    };
    if !json_int_eq_one(&map, "schema_version") {
        return Err(format!(
            "HostAbi sidecar has an unsupported schema: {sidecar_display}"
        ));
    }
    let build_id = json_str_or_empty(&map, "elf_build_id").to_ascii_lowercase();
    let payload_id = json_str_or_empty(&map, "payload_id");
    let payload_path = json_str_or_empty(&map, "payload_path");
    let suffix_matches = payload_id.len() > 41
        && payload_id
            .get(payload_id.len() - 40..)
            .is_some_and(|tail| tail == build_id);
    if build_id.len() != 40
        || !suffix_matches
        || payload_path != format!("payloads/{payload_id}")
    {
        return Err(format!(
            "HostAbi sidecar identity is inconsistent: {sidecar_display}"
        ));
    }
    Ok((build_id, payload_id.to_string()))
}

pub(crate) fn read_bounded_regular_json_bytes(path: &Path) -> Result<Vec<u8>, String> {
    match crate::unix_ipc::read_regular_file_limited(path, 1024 * 1024, false, false) {
        Ok(bytes) => Ok(bytes),
        Err(crate::unix_ipc::ReadFileError::NotFound | crate::unix_ipc::ReadFileError::OpenFailed(_)) => {
            Err(format!("cannot open JSON input: {}", path.display()))
        }
        Err(crate::unix_ipc::ReadFileError::InvalidFile) => {
            Err("JSON input is not a bounded regular file".to_string())
        }
        Err(crate::unix_ipc::ReadFileError::ReadFailed) => {
            Err("cannot read JSON input".to_string())
        }
    }
}

pub(crate) fn read_host_abi_sidecar_identity_file(
    sidecar_path: &Path,
) -> Result<(String, String), String> {
    let raw = read_bounded_regular_json_bytes(sidecar_path)?;
    parse_sidecar_identity(&raw, sidecar_path)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_deriver_read_sidecar_identity(
    json_ptr: *const c_char,
    json_len: usize,
    sidecar_path_ptr: *const c_char,
    sidecar_path_len: usize,
    out_build_id: *mut c_char,
    build_id_cap: usize,
    out_payload_id: *mut c_char,
    payload_id_cap: usize,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let sidecar_path = slice_to_str(sidecar_path_ptr, sidecar_path_len).unwrap_or("");
    let json_bytes = if json_ptr.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(json_ptr as *const u8, json_len) }
    };
    let (build_id, payload_id) = match parse_sidecar_identity(json_bytes, Path::new(sidecar_path)) {
        Ok(pair) => pair,
        Err(err) => {
            copy_error(out_err, err_cap, &err);
            return -1;
        }
    };
    if copy_to_c_buffer(&build_id, out_build_id, build_id_cap) < 0
        || copy_to_c_buffer(&payload_id, out_payload_id, payload_id_cap) < 0
    {
        copy_error(
            out_err,
            err_cap,
            &format!("HostAbi sidecar identity buffer too small: {sidecar_path}"),
        );
        return -1;
    }
    0
}

pub(crate) fn load_candidate_metadata_data(
    metadata_json: &str,
    metadata_path: &str,
    dir_filename: &str,
    cand_build_id: &str,
    cand_sha256: &str,
    guest_abi: &str,
) -> Result<(String, u64), String> {
    let Some(map) = parse_json_object_str(metadata_json, true) else {
        return Err(format!("JSON input must contain one object: {metadata_path}"));
    };
    let version_name = json_str_or_empty(&map, "version_name");
    let version_code = map.get("version_code").and_then(Value::as_u64).unwrap_or(0);
    let hashes = map.get("sha256").and_then(Value::as_object);
    let valid = json_int_eq_one(&map, "schema_version")
        && json_str_or_empty(&map, "package") == "com.roblox.client"
        && json_str_or_empty(&map, "abi") == guest_abi
        && !version_name.is_empty()
        && version_code != 0
        && json_str_or_empty(&map, "elf_build_id") == cand_build_id
        && hashes.is_some_and(|h| json_str_or_empty(h, "libroblox") == cand_sha256);
    if !valid {
        return Err("payload metadata does not match candidate ELF bytes".to_string());
    }
    let payload_id = format!("{version_code}-{cand_build_id}");
    if dir_filename != payload_id {
        return Err("candidate ELF parent is not the canonical payload ID".to_string());
    }
    Ok((version_name.to_string(), version_code))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_deriver_load_candidate_metadata(
    json_ptr: *const c_char,
    json_len: usize,
    metadata_path_ptr: *const c_char,
    metadata_path_len: usize,
    dir_filename_ptr: *const c_char,
    dir_filename_len: usize,
    candidate_build_id_ptr: *const c_char,
    candidate_build_id_len: usize,
    candidate_sha256_ptr: *const c_char,
    candidate_sha256_len: usize,
    guest_abi_ptr: *const c_char,
    guest_abi_len: usize,
    out_version_name: *mut c_char,
    version_name_cap: usize,
    out_version_code: *mut u64,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let metadata_path = slice_to_str(metadata_path_ptr, metadata_path_len).unwrap_or("");
    let Some(metadata_json) = slice_to_str(json_ptr, json_len) else {
        copy_error(
            out_err,
            err_cap,
            &format!("JSON input must contain one object: {metadata_path}"),
        );
        return -1;
    };
    let dir_filename = slice_to_str(dir_filename_ptr, dir_filename_len).unwrap_or("");
    let cand_build_id = slice_to_str(candidate_build_id_ptr, candidate_build_id_len).unwrap_or("");
    let cand_sha256 = slice_to_str(candidate_sha256_ptr, candidate_sha256_len).unwrap_or("");
    let guest_abi = slice_to_str(guest_abi_ptr, guest_abi_len).unwrap_or("");

    let (version_name, version_code) = match load_candidate_metadata_data(
        metadata_json,
        metadata_path,
        dir_filename,
        cand_build_id,
        cand_sha256,
        guest_abi,
    ) {
        Ok(v) => v,
        Err(msg) => {
            copy_error(out_err, err_cap, &msg);
            return -1;
        }
    };
    if !out_version_code.is_null() {
        unsafe { *out_version_code = version_code };
    }
    if copy_to_c_buffer(&version_name, out_version_name, version_name_cap) < 0 {
        copy_error(out_err, err_cap, "candidate version_name exceeds buffer");
        return -1;
    }
    0
}

pub(crate) fn load_runtime_anchors_data<'a>(
    manifests: &[(&'a str, &'a str)],
    ref_build_id: &str,
) -> Result<MocktailRustDeriverRuntimeAnchors, String> {
    const CORE_FIELDS: [&str; 6] = [
        "vtable_rva",
        "string_constructor_rva",
        "count_method_rva",
        "info_method_rva",
        "current_method_rva",
        "select_method_rva",
    ];
    const INPUT_FIELDS: [&str; 4] = [
        "input_count_method_rva",
        "input_info_method_rva",
        "input_current_method_rva",
        "input_select_method_rva",
    ];

    let mut result = MocktailRustDeriverRuntimeAnchors::default();
    let mut prev_fmod: Option<MocktailRustDeriverRuntimeAnchors> = None;

    for &(raw, path_str) in manifests {
        let doc = parse_json_object_str(raw, true)
            .ok_or_else(|| format!("JSON input must contain one object: {path_str}"))?;
        let profiles = doc
            .get("profiles")
            .and_then(Value::as_array)
            .filter(|_| json_int_eq_one(&doc, "schema_version"))
            .ok_or_else(|| "reference compatibility manifest schema is unsupported".to_string())?;

        for profile_val in profiles {
            let Some(profile) = profile_val.as_object() else {
                continue;
            };
            if json_str_or_empty(profile, "elf_build_id") != ref_build_id {
                continue;
            }
            if let Some(setter_val) = profile.get("user_game_settings_fullscreen_setter_rva") {
                let value = parse_rva(setter_val, "reference fullscreen setter")?;
                if result.has_fullscreen_setter && result.fullscreen_setter_rva != value {
                    return Err(
                        "reference compatibility manifests disagree on fullscreen setter"
                            .to_string(),
                    );
                }
                result.has_fullscreen_setter = true;
                result.fullscreen_setter_rva = value;
            }
            let Some(bridge_val) = profile.get("fmod_output_device_bridge") else {
                continue;
            };
            let bridge = bridge_val
                .as_object()
                .ok_or_else(|| "reference FMOD output-device profile is incomplete".to_string())?;
            let has_input = bridge.contains_key(INPUT_FIELDS[0]);
            let has_layout = bridge.contains_key("vtable_layout_version");
            let expected_len =
                CORE_FIELDS.len() + usize::from(has_layout) + if has_input { 4 } else { 0 };
            let allowed = profile
                .get("allow_host_abi_bridges")
                .and_then(Value::as_bool)
                == Some(true);
            if bridge.len() != expected_len || !allowed {
                return Err("reference FMOD output-device profile is incomplete".to_string());
            }
            let mut values = [0u64; 6];
            for (field_idx, &field) in CORE_FIELDS.iter().enumerate() {
                let val = bridge
                    .get(field)
                    .ok_or_else(|| "reference FMOD output-device profile is incomplete".to_string())?;
                values[field_idx] = parse_rva(val, field)?;
            }
            let mut layout = 1i32;
            if has_layout {
                let layout_val = bridge.get("vtable_layout_version").unwrap_or(&Value::Null);
                let parsed_layout = layout_val
                    .as_i64()
                    .filter(|&v| v == 1 || v == 2)
                    .or_else(|| {
                        layout_val
                            .as_u64()
                            .filter(|&v| v == 1 || v == 2)
                            .map(|v| v as i64)
                    })
                    .ok_or_else(|| "reference FMOD vtable layout is unsupported".to_string())?;
                layout = parsed_layout as i32;
            }
            let mut discovered = MocktailRustDeriverRuntimeAnchors {
                has_fullscreen_setter: false,
                fullscreen_setter_rva: 0,
                has_fmod: true,
                fmod_vtable_rva: values[0],
                fmod_string_constructor_rva: values[1],
                fmod_count_method_rva: values[2],
                fmod_info_method_rva: values[3],
                fmod_current_method_rva: values[4],
                fmod_select_method_rva: values[5],
                fmod_layout_version: layout,
                fmod_input_methods: [0; 4],
            };
            if has_input {
                for (i, &field) in INPUT_FIELDS.iter().enumerate() {
                    let val = bridge
                        .get(field)
                        .ok_or_else(|| "reference FMOD input profile is incomplete".to_string())?;
                    discovered.fmod_input_methods[i] = parse_rva(val, field)?;
                }
            }
            if let Some(mut previous) = prev_fmod {
                if previous.fmod_input_methods[0] == 0 {
                    previous.fmod_input_methods = discovered.fmod_input_methods;
                }
                if discovered.fmod_input_methods[0] == 0 {
                    discovered.fmod_input_methods = previous.fmod_input_methods;
                }
                if previous != discovered {
                    return Err(
                        "reference compatibility manifests disagree on FMOD anchors".to_string(),
                    );
                }
            }
            prev_fmod = Some(discovered);
        }
    }

    if let Some(fmod) = prev_fmod {
        result.has_fmod = true;
        result.fmod_vtable_rva = fmod.fmod_vtable_rva;
        result.fmod_string_constructor_rva = fmod.fmod_string_constructor_rva;
        result.fmod_count_method_rva = fmod.fmod_count_method_rva;
        result.fmod_info_method_rva = fmod.fmod_info_method_rva;
        result.fmod_current_method_rva = fmod.fmod_current_method_rva;
        result.fmod_select_method_rva = fmod.fmod_select_method_rva;
        result.fmod_layout_version = fmod.fmod_layout_version;
        result.fmod_input_methods = fmod.fmod_input_methods;
    }
    Ok(result)
}

fn load_runtime_anchors_inner(
    jsons: &[MocktailRustStrSlice],
    paths: &[MocktailRustStrSlice],
    ref_build_id: &str,
) -> Result<MocktailRustDeriverRuntimeAnchors, String> {
    let mut pairs = Vec::with_capacity(jsons.len());
    for (raw_slice, path_slice) in jsons.iter().zip(paths.iter()) {
        let path_str = slice_from_raw(*path_slice).unwrap_or("");
        let raw = slice_from_raw(*raw_slice)
            .ok_or_else(|| format!("JSON input must contain one object: {path_str}"))?;
        pairs.push((raw, path_str));
    }
    load_runtime_anchors_data(&pairs, ref_build_id)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_deriver_load_runtime_anchors(
    manifest_jsons_ptr: *const MocktailRustStrSlice,
    manifest_paths_ptr: *const MocktailRustStrSlice,
    manifest_count: usize,
    reference_build_id_ptr: *const c_char,
    reference_build_id_len: usize,
    out_anchors: *mut MocktailRustDeriverRuntimeAnchors,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    if out_anchors.is_null() {
        copy_error(out_err, err_cap, "null runtime anchors output");
        return -1;
    }
    let Some(ref_build_id) = slice_to_str(reference_build_id_ptr, reference_build_id_len) else {
        copy_error(out_err, err_cap, "invalid reference build ID");
        return -1;
    };
    let jsons = if manifest_count == 0 {
        &[][..]
    } else if manifest_jsons_ptr.is_null() {
        copy_error(out_err, err_cap, "null manifest JSON list");
        return -1;
    } else {
        unsafe { std::slice::from_raw_parts(manifest_jsons_ptr, manifest_count) }
    };
    let paths = if manifest_count == 0 {
        &[][..]
    } else if manifest_paths_ptr.is_null() {
        copy_error(out_err, err_cap, "null manifest path list");
        return -1;
    } else {
        unsafe { std::slice::from_raw_parts(manifest_paths_ptr, manifest_count) }
    };

    match load_runtime_anchors_inner(jsons, paths, ref_build_id) {
        Ok(result) => {
            unsafe { *out_anchors = result };
            0
        }
        Err(e) => {
            copy_error(out_err, err_cap, &e);
            -1
        }
    }
}

pub(crate) fn check_init_array_data(
    sidecar: &Map<String, Value>,
    reference_init_len: usize,
    candidate_init_len: usize,
) -> Result<usize, String> {
    let ref_count_val = sidecar
        .get("profile")
        .and_then(Value::as_object)
        .and_then(|p| p.get("init_array_count"));
    let ref_count = positive_size(ref_count_val, "reference init-array count")?;
    if reference_init_len != ref_count || candidate_init_len < 8 {
        return Err("init-array shape is not derivable".to_string());
    }
    Ok(ref_count)
}

pub(crate) fn resolve_constructors_and_seeds_inner(
    sidecar: &Map<String, Value>,
    reference_init: &[u64],
    candidate_init: &[u64],
    ctor_cand_rvas: &[u64],
    ctor_ref_first_rvas: &[u64],
) -> Result<MocktailRustDeriverPlan, String> {
    let reference_profile = sidecar
        .get("profile")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let reference_anchors = sidecar
        .get("derivation_anchors")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let role_rvas = reference_anchors
        .get("constructor_rvas")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let reference_indices = reference_anchors.get("constructor_indices");
    let mut plan = MocktailRustDeriverPlan::default();

    for (slot_idx, role) in [2usize, 3, 4, 5].into_iter().enumerate() {
        let key = role.to_string();
        let mut reference_index = role;
        if let Some(indices_val) = reference_indices {
            let indices_obj = indices_val
                .as_object()
                .ok_or_else(|| "reference constructor indices are incomplete".to_string())?;
            let val = indices_obj
                .get(&key)
                .ok_or_else(|| "reference constructor indices are incomplete".to_string())?;
            reference_index = positive_size(Some(val), "constructor index")?;
        }
        let reference_rva = profile_rva(role_rvas, &key)?;
        let expected_rva = if role == 5 {
            profile_rva(reference_anchors, "jni_singleton_initializer_rva")?
        } else {
            ctor_ref_first_rvas[slot_idx]
        };
        let cand_rva = ctor_cand_rvas[slot_idx];
        let ref_count = reference_init.iter().filter(|&&v| v == reference_rva).count();
        let cand_count = candidate_init.iter().filter(|&&v| v == cand_rva).count();
        if reference_rva != expected_rva
            || reference_index < 2
            || reference_index >= reference_init.len()
            || reference_init[reference_index] != reference_rva
            || ref_count != 1
            || cand_count != 1
        {
            return Err("constructor role has no unique verified init-array entry".to_string());
        }
        let cand_index = candidate_init
            .iter()
            .position(|&v| v == cand_rva)
            .unwrap_or(0);
        if cand_index < 2 {
            return Err("constructor role moved into reserved startup entries".to_string());
        }
        if role == 2 {
            let tls_checkpoint = reference_profile
                .get("native_mimalloc_thread_initializer_after_constructor")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .unwrap_or(usize::MAX);
            if tls_checkpoint != reference_index {
                return Err(
                    "reference allocator constructor disagrees with its TLS checkpoint".to_string(),
                );
            }
        }
        plan.candidate_constructor_indices[slot_idx] = cand_index;
        plan.candidate_constructor_rvas[slot_idx] = cand_rva;
    }

    let seeds = reference_profile
        .get("data_seeds")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let old_bootstrap = reference_profile
        .get("native_pre_jni_bootstrap")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;

    plan.allocator_object_slot_rva = profile_rva(seeds, "allocator_object_slot")?;
    plan.empty_string_slot_rva = profile_rva(seeds, "empty_string_slot")?;
    plan.jni_singleton_slot_rva = profile_rva(seeds, "jni_singleton_slot")?;
    plan.arena_guard_slot_rva = profile_rva(seeds, "arena_guard_slot")?;
    plan.arena_table_slot_rva = profile_rva(seeds, "arena_table_slot")?;
    plan.old_registry_initializer_rva = profile_rva(old_bootstrap, "registry_initializer")?;
    plan.old_registry_slot_rva = profile_rva(old_bootstrap, "registry_slot")?;
    Ok(plan)
}

pub(crate) fn build_documents_data(
    sidecar: &Map<String, Value>,
    metadata_raw: &str,
    inp: &MocktailRustDeriverBuildInputs,
) -> Result<(String, String), String> {
    let metadata = parse_json_object_str(metadata_raw, true)
        .ok_or_else(|| "invalid candidate metadata JSON".to_string())?;
    let reference_profile = sidecar
        .get("profile")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let seeds = reference_profile
        .get("data_seeds")
        .and_then(Value::as_object)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;
    let bridge_entries = reference_profile
        .get("bridge_entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "reference HostAbi sidecar shape is incomplete".to_string())?;

    let native_ranges = adjust_ranges(
        reference_profile.get("native_mimalloc_constructor_run_ranges"),
        inp.reference_init_count,
        inp.candidate_init_count,
    )?;
    let valid_range = native_ranges
        .as_array()
        .filter(|arr| arr.len() == 1)
        .and_then(|arr| arr[0].as_object())
        .is_some_and(|obj| {
            obj.get("begin").and_then(Value::as_u64) == Some(2)
                && obj.get("end_exclusive").and_then(Value::as_u64)
                    == u64::try_from(inp.candidate_init_count).ok()
        });
    if !valid_range {
        return Err("native constructor replay must cover all non-reserved entries".to_string());
    }

    let singleton_bytes = positive_size(seeds.get("jni_singleton_bytes"), "JNI singleton size")?;
    let arena_slots = positive_size(seeds.get("arena_table_slot_count"), "arena table slot count")?;

    let ref_build_id = slice_from_raw(inp.ref_build_id).unwrap_or("");
    let ref_sha256 = slice_from_raw(inp.ref_sha256).unwrap_or("");
    let cand_build_id = slice_from_raw(inp.cand_build_id).unwrap_or("");
    let cand_sha256 = slice_from_raw(inp.cand_sha256).unwrap_or("");

    let bridge_rva_for = |label: &str| -> u64 {
        BRIDGE_SIGNATURES
            .iter()
            .position(|&(name, _)| name == label)
            .map(|idx| inp.bridge_rvas[idx])
            .unwrap_or(0)
    };

    let mut candidate_bridges = Vec::with_capacity(bridge_entries.len());
    for entry in bridge_entries {
        let label = entry.get("label").and_then(Value::as_str).unwrap_or("");
        let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
        let rva = bridge_rva_for(label);
        candidate_bridges.push(json!({
            "rva": format_rva(rva),
            "kind": kind,
            "label": label,
        }));
    }

    let thread_boundary = inp.candidate_constructor_indices[0];
    let candidate_constructor_rvas = json!({
        "2": format_rva(inp.candidate_constructor_rvas[0]),
        "3": format_rva(inp.candidate_constructor_rvas[1]),
        "4": format_rva(inp.candidate_constructor_rvas[2]),
        "5": format_rva(inp.candidate_constructor_rvas[3]),
    });
    let candidate_indices = json!({
        "2": inp.candidate_constructor_indices[0],
        "3": inp.candidate_constructor_indices[1],
        "4": inp.candidate_constructor_indices[2],
        "5": inp.candidate_constructor_indices[3],
    });

    let profile = json!({
        "elf_build_id": cand_build_id,
        "bridge_entries": candidate_bridges,
        "data_seeds": {
            "allocator_object_slot": format_rva(inp.allocator_object_slot_rva),
            "empty_string_slot": format_rva(inp.empty_string_slot_rva),
            "jni_singleton_slot": format_rva(inp.jni_singleton_slot_rva),
            "jni_singleton_bytes": singleton_bytes,
            "arena_initializer": format_rva(inp.arena_initializer_rva),
            "allocator_thread_initializer": format_rva(inp.allocator_thread_initializer_rva),
            "arena_guard_slot": format_rva(inp.arena_guard_slot_rva),
            "arena_table_slot": format_rva(inp.arena_table_slot_rva),
            "arena_table_slot_count": arena_slots,
        },
        "native_allocator": {
            "allocate": format_rva(bridge_rva_for("allocate")),
            "deallocate": format_rva(bridge_rva_for("free")),
        },
        "init_array_offset": format_rva(inp.init_array_offset),
        "init_array_count": inp.candidate_init_count,
        "constructor_run_ranges": native_ranges,
        "native_mimalloc_constructor_run_ranges": native_ranges,
        "native_mimalloc_thread_initializer_after_constructor": thread_boundary,
        "native_pre_jni_bootstrap": {
            "registry_initializer": format_rva(inp.registry_initializer_rva),
            "registry_slot": format_rva(inp.registry_slot_rva),
        },
        "default_allocator_strategy": "native_mimalloc",
        "host_allocator_bridges_supported": false,
    });
    let anchors = json!({
        "signature_version": 1,
        "allocator_object_initializer_rva": format_rva(inp.allocator_object_initializer_rva),
        "empty_string_initializer_rva": format_rva(inp.empty_string_initializer_rva),
        "jni_singleton_initializer_rva": format_rva(inp.jni_singleton_initializer_rva),
        "constructor_rvas": candidate_constructor_rvas,
        "constructor_indices": candidate_indices,
    });

    let version_code = metadata.get("version_code").and_then(Value::as_u64).unwrap_or(0);
    let version_name = json_str_or_empty(&metadata, "version_name");
    let payload_id = format!("{version_code}-{cand_build_id}");

    let derived = json!({
        "schema_version": 1,
        "elf_build_id": cand_build_id,
        "payload_sha256": cand_sha256,
        "payload_id": payload_id,
        "payload_path": format!("payloads/{payload_id}"),
        "reference": {
            "elf_build_id": ref_build_id,
            "payload_sha256": ref_sha256,
        },
        "profile": profile,
        "derivation_anchors": anchors,
    });

    let mut compat_profile_map = Map::new();
    compat_profile_map.insert("version_name".into(), Value::String(version_name.to_string()));
    compat_profile_map.insert("version_code".into(), json!(version_code));
    compat_profile_map.insert("elf_build_id".into(), Value::String(cand_build_id.to_string()));
    compat_profile_map.insert("status".into(), Value::String("experimental".to_string()));
    compat_profile_map.insert("default_allowed".into(), Value::Bool(true));
    compat_profile_map.insert("allow_legacy_binary_patches".into(), Value::Bool(false));
    compat_profile_map.insert("allow_host_abi_bridges".into(), Value::Bool(true));
    compat_profile_map.insert("allow_host_constructor_replay".into(), Value::Bool(true));
    compat_profile_map.insert(
        "reason".into(),
        Value::String(
            "Machine-derived exact-Build-ID profile for isolated probation only; normal activation requires two successful no-recovery Tier C canaries."
                .to_string(),
        ),
    );
    if inp.has_derived_fullscreen_setter {
        compat_profile_map.insert(
            "user_game_settings_fullscreen_setter_rva".into(),
            Value::String(format_rva(inp.derived_fullscreen_setter_rva)),
        );
    }
    if inp.has_derived_fmod {
        let mut fmod_map = Map::new();
        fmod_map.insert("vtable_rva".into(), Value::String(format_rva(inp.derived_fmod_vtable_rva)));
        fmod_map.insert(
            "string_constructor_rva".into(),
            Value::String(format_rva(inp.derived_fmod_string_constructor_rva)),
        );
        fmod_map.insert(
            "count_method_rva".into(),
            Value::String(format_rva(inp.derived_fmod_count_method_rva)),
        );
        fmod_map.insert(
            "info_method_rva".into(),
            Value::String(format_rva(inp.derived_fmod_info_method_rva)),
        );
        fmod_map.insert(
            "current_method_rva".into(),
            Value::String(format_rva(inp.derived_fmod_current_method_rva)),
        );
        fmod_map.insert(
            "select_method_rva".into(),
            Value::String(format_rva(inp.derived_fmod_select_method_rva)),
        );
        if inp.derived_fmod_has_input {
            let input_keys = [
                "input_count_method_rva",
                "input_info_method_rva",
                "input_current_method_rva",
                "input_select_method_rva",
            ];
            for (idx, key) in input_keys.into_iter().enumerate() {
                fmod_map.insert(
                    key.into(),
                    Value::String(format_rva(inp.derived_fmod_input_methods[idx])),
                );
            }
        }
        if inp.derived_fmod_layout_version != 1 {
            fmod_map.insert(
                "vtable_layout_version".into(),
                json!(inp.derived_fmod_layout_version),
            );
        }
        compat_profile_map.insert("fmod_output_device_bridge".into(), Value::Object(fmod_map));
    }

    let compatibility = json!({
        "schema_version": 1,
        "profiles": [Value::Object(compat_profile_map)],
    });

    let mut derived_pretty = serde_json::to_string_pretty(&derived)
        .map_err(|_| "failed to serialize derived HostAbi profile".to_string())?;
    derived_pretty.push('\n');
    let mut compat_pretty = serde_json::to_string_pretty(&compatibility)
        .map_err(|_| "failed to serialize derived compatibility manifest".to_string())?;
    compat_pretty.push('\n');
    Ok((derived_pretty, compat_pretty))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_deriver_build_documents(
    sidecar_ptr: *const c_char,
    sidecar_len: usize,
    metadata_ptr: *const c_char,
    metadata_len: usize,
    inputs: *const MocktailRustDeriverBuildInputs,
    on_profile_json: MocktailPayloadStoreStringCallback,
    on_compatibility_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    if inputs.is_null() {
        copy_error(out_err, err_cap, "null build inputs");
        return -1;
    }
    let inp = unsafe { &*inputs };
    let Some(sidecar) = parse_sidecar_object(sidecar_ptr, sidecar_len) else {
        copy_error(out_err, err_cap, "JSON input must contain one object");
        return -1;
    };
    let Some(metadata_raw) = slice_to_str(metadata_ptr, metadata_len) else {
        copy_error(out_err, err_cap, "invalid candidate metadata UTF-8");
        return -1;
    };
    match build_documents_data(&sidecar, metadata_raw, inp) {
        Ok((derived_pretty, compat_pretty)) => {
            emit_string(on_profile_json, ctx, &derived_pretty);
            emit_string(on_compatibility_json, ctx, &compat_pretty);
            0
        }
        Err(msg) => {
            copy_error(out_err, err_cap, &msg);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_policies::parse_json_value_str;

    #[test]
    fn deriver_parse_and_format_rva_enforce_canonical_hex() {
        assert_eq!(parse_rva(&json!("0x12ab"), "field").unwrap(), 0x12ab);
        assert_eq!(format_rva(0x12ab), "0x12ab");
        assert!(parse_rva(&json!("0x012"), "field")
            .unwrap_err()
            .contains("canonical nonzero hex RVA"));
        assert!(parse_rva(&json!("0x12AB"), "field")
            .unwrap_err()
            .contains("canonical nonzero hex RVA"));
        assert!(parse_rva(&json!(123), "field")
            .unwrap_err()
            .contains("nonzero hex RVA"));
    }

    #[test]
    fn deriver_runtime_anchors_merge_partial_input_and_reject_disagreement() {
        let m1 = r#"{
            "schema_version": 1,
            "profiles": [{
                "elf_build_id": "abcd",
                "allow_host_abi_bridges": true,
                "user_game_settings_fullscreen_setter_rva": "0x111",
                "fmod_output_device_bridge": {
                    "vtable_rva": "0x1000",
                    "string_constructor_rva": "0x1008",
                    "count_method_rva": "0x1010",
                    "info_method_rva": "0x1018",
                    "current_method_rva": "0x1020",
                    "select_method_rva": "0x1028",
                    "vtable_layout_version": 2
                }
            }]
        }"#;
        let m2 = r#"{
            "schema_version": 1,
            "profiles": [{
                "elf_build_id": "abcd",
                "allow_host_abi_bridges": true,
                "fmod_output_device_bridge": {
                    "vtable_rva": "0x1000",
                    "string_constructor_rva": "0x1008",
                    "count_method_rva": "0x1010",
                    "info_method_rva": "0x1018",
                    "current_method_rva": "0x1020",
                    "select_method_rva": "0x1028",
                    "vtable_layout_version": 2,
                    "input_count_method_rva": "0x2000",
                    "input_info_method_rva": "0x2008",
                    "input_current_method_rva": "0x2010",
                    "input_select_method_rva": "0x2018"
                }
            }]
        }"#;
        let jsons = [
            MocktailRustStrSlice::from_str(m1),
            MocktailRustStrSlice::from_str(m2),
        ];
        let paths = [
            MocktailRustStrSlice::from_str("a.json"),
            MocktailRustStrSlice::from_str("b.json"),
        ];
        let mut out = MocktailRustDeriverRuntimeAnchors::default();
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_deriver_load_runtime_anchors(
            jsons.as_ptr(),
            paths.as_ptr(),
            2,
            "abcd".as_ptr() as *const c_char,
            4,
            &mut out,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert!(out.has_fullscreen_setter);
        assert_eq!(out.fullscreen_setter_rva, 0x111);
        assert!(out.has_fmod);
        assert_eq!(out.fmod_layout_version, 2);
        assert_eq!(out.fmod_input_methods, [0x2000, 0x2008, 0x2010, 0x2018]);

        let mismatch = m1.replace("0x111", "0x222");
        let jsons_bad = [
            MocktailRustStrSlice::from_str(m1),
            MocktailRustStrSlice::from_str(&mismatch),
        ];
        let rc_bad = mocktail_rust_deriver_load_runtime_anchors(
            jsons_bad.as_ptr(),
            paths.as_ptr(),
            2,
            "abcd".as_ptr() as *const c_char,
            4,
            &mut out,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_bad, -1);
    }

    #[test]
    fn deriver_sidecar_and_candidate_metadata_checks_work() {
        let build_id = "0123456789abcdef0123456789abcdef01234567";
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sidecar_json = serde_json::to_string(&json!({
            "schema_version": 1,
            "elf_build_id": build_id.to_ascii_uppercase(),
            "payload_id": format!("2908-{build_id}"),
            "payload_path": format!("payloads/2908-{build_id}")
        }))
        .unwrap();
        let mut out_bid = [0 as c_char; 64];
        let mut out_pid = [0 as c_char; 128];
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_deriver_read_sidecar_identity(
            sidecar_json.as_ptr() as *const c_char,
            sidecar_json.len(),
            "s.json".as_ptr() as *const c_char,
            6,
            out_bid.as_mut_ptr(),
            out_bid.len(),
            out_pid.as_mut_ptr(),
            out_pid.len(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);

        let meta_json = serde_json::to_string(&json!({
            "schema_version": 1,
            "package": "com.roblox.client",
            "abi": "x86_64",
            "version_name": "2.700.1",
            "version_code": 2908,
            "elf_build_id": build_id,
            "sha256": { "libroblox": sha }
        }))
        .unwrap();
        let dir_name = format!("2908-{build_id}");
        let mut out_vname = [0 as c_char; 64];
        let mut out_vcode = 0u64;
        let rc_meta = mocktail_rust_deriver_load_candidate_metadata(
            meta_json.as_ptr() as *const c_char,
            meta_json.len(),
            "roblox_payload.json".as_ptr() as *const c_char,
            19,
            dir_name.as_ptr() as *const c_char,
            dir_name.len(),
            build_id.as_ptr() as *const c_char,
            build_id.len(),
            sha.as_ptr() as *const c_char,
            sha.len(),
            "x86_64".as_ptr() as *const c_char,
            6,
            out_vname.as_mut_ptr(),
            out_vname.len(),
            &mut out_vcode,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_meta, 0);
        assert_eq!(out_vcode, 2908);
    }

    #[test]
    fn deriver_build_documents_emits_valid_pretty_json() {
        let ref_id = "0123456789abcdef0123456789abcdef01234567";
        let cand_id = "fedcba9876543210fedcba9876543210fedcba98";
        let ref_sha = "1111111111111111111111111111111111111111111111111111111111111111";
        let cand_sha = "2222222222222222222222222222222222222222222222222222222222222222";
        let sidecar = json!({
            "schema_version": 1,
            "elf_build_id": ref_id,
            "payload_sha256": ref_sha,
            "payload_id": format!("2908-{ref_id}"),
            "payload_path": format!("payloads/2908-{ref_id}"),
            "profile": {
                "elf_build_id": ref_id,
                "bridge_entries": [
                    {"label": "small-allocate", "kind": "a", "rva": "0x10"},
                    {"label": "usable-size", "kind": "a", "rva": "0x20"},
                    {"label": "reallocate", "kind": "a", "rva": "0x30"},
                    {"label": "allocate", "kind": "a", "rva": "0x40"},
                    {"label": "aligned-allocate-direct", "kind": "a", "rva": "0x50"},
                    {"label": "free", "kind": "a", "rva": "0x60"}
                ],
                "data_seeds": {
                    "allocator_object_slot": "0x100",
                    "empty_string_slot": "0x108",
                    "jni_singleton_slot": "0x110",
                    "jni_singleton_bytes": 64,
                    "arena_initializer": "0x118",
                    "allocator_thread_initializer": "0x120",
                    "arena_guard_slot": "0x128",
                    "arena_table_slot": "0x130",
                    "arena_table_slot_count": 32
                },
                "init_array_count": 10,
                "native_mimalloc_constructor_run_ranges": [{"begin": 2, "end_exclusive": 10}],
                "native_mimalloc_thread_initializer_after_constructor": 2,
                "native_pre_jni_bootstrap": {
                    "registry_initializer": "0x140",
                    "registry_slot": "0x148"
                }
            },
            "derivation_anchors": {
                "signature_version": 1,
                "allocator_object_initializer_rva": "0x200",
                "empty_string_initializer_rva": "0x210",
                "jni_singleton_initializer_rva": "0x220",
                "constructor_rvas": { "2": "0x300", "3": "0x310", "4": "0x320", "5": "0x220" }
            }
        })
        .to_string();
        let meta = json!({
            "schema_version": 1,
            "package": "com.roblox.client",
            "abi": "x86_64",
            "version_name": "2.700.2",
            "version_code": 2999,
            "elf_build_id": cand_id,
            "sha256": { "libroblox": cand_sha }
        })
        .to_string();
        let inp = MocktailRustDeriverBuildInputs {
            ref_build_id: MocktailRustStrSlice::from_str(ref_id),
            ref_sha256: MocktailRustStrSlice::from_str(ref_sha),
            cand_build_id: MocktailRustStrSlice::from_str(cand_id),
            cand_sha256: MocktailRustStrSlice::from_str(cand_sha),
            reference_init_count: 10,
            candidate_init_count: 12,
            init_array_offset: 0x5000,
            bridge_rvas: [0x11, 0x21, 0x31, 0x41, 0x51, 0x61],
            arena_initializer_rva: 0x119,
            allocator_thread_initializer_rva: 0x121,
            registry_initializer_rva: 0x141,
            registry_slot_rva: 0x149,
            allocator_object_initializer_rva: 0x201,
            empty_string_initializer_rva: 0x211,
            jni_singleton_initializer_rva: 0x221,
            allocator_object_slot_rva: 0x101,
            empty_string_slot_rva: 0x109,
            jni_singleton_slot_rva: 0x111,
            arena_guard_slot_rva: 0x129,
            arena_table_slot_rva: 0x131,
            candidate_constructor_rvas: [0x301, 0x311, 0x321, 0x221],
            candidate_constructor_indices: [2, 3, 4, 6],
            has_derived_fullscreen_setter: true,
            derived_fullscreen_setter_rva: 0x777,
            has_derived_fmod: false,
            derived_fmod_vtable_rva: 0,
            derived_fmod_string_constructor_rva: 0,
            derived_fmod_count_method_rva: 0,
            derived_fmod_info_method_rva: 0,
            derived_fmod_current_method_rva: 0,
            derived_fmod_select_method_rva: 0,
            derived_fmod_layout_version: 1,
            derived_fmod_has_input: false,
            derived_fmod_input_methods: [0; 4],
        };
        struct OutPair(String, String);
        unsafe extern "C" fn capture_profile(ctx: *mut c_void, ptr: *const c_char, len: usize) {
            let pair = &mut *(ctx as *mut OutPair);
            pair.0 = std::str::from_utf8(std::slice::from_raw_parts(ptr as *const u8, len))
                .unwrap()
                .to_string();
        }
        unsafe extern "C" fn capture_compat(ctx: *mut c_void, ptr: *const c_char, len: usize) {
            let pair = &mut *(ctx as *mut OutPair);
            pair.1 = std::str::from_utf8(std::slice::from_raw_parts(ptr as *const u8, len))
                .unwrap()
                .to_string();
        }
        let mut out = OutPair(String::new(), String::new());
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_deriver_build_documents(
            sidecar.as_ptr() as *const c_char,
            sidecar.len(),
            meta.as_ptr() as *const c_char,
            meta.len(),
            &inp,
            Some(capture_profile),
            Some(capture_compat),
            &mut out as *mut OutPair as *mut c_void,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert!(out.0.ends_with('\n'));
        assert!(out.1.ends_with('\n'));
        assert!(parse_json_value_str(&out.0, false).is_some());
        let compat_val = parse_json_value_str(&out.1, false).unwrap();
        assert_eq!(
            compat_val["profiles"][0]["user_game_settings_fullscreen_setter_rva"],
            "0x777"
        );
    }
}
