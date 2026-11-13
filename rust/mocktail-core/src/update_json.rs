use crate::storage_paths::{
    c_str_opt, emit_string, is_lower_hex, slice_to_str, MocktailPayloadStoreStringCallback,
};
use crate::{
    apkpure_collect_exact_urls, compute_approval_generation_hex, copy_error, copy_to_c_buffer,
    internal_inspect_payload, mocktail_rust_pinned_apk_archive_filename_valid,
    mocktail_rust_pinned_apk_archive_limits_valid, read_update_state_json_string,
    verify_payload_internal, write_atomic_bytes, zip_list_entries_internal,
    MocktailRustPayloadInfo,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{c_char, c_int, c_void};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Callback & FFI View Types for Updater Subsystems
// ============================================================================

pub type MocktailZipEntryCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        name: *const c_char,
        name_len: usize,
        uncompressed_size: u64,
        directory: bool,
        symbolic_link: bool,
    ),
>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustStrSlice {
    pub ptr: *const c_char,
    pub len: usize,
}

impl MocktailRustStrSlice {
    pub(crate) fn from_str(value: &str) -> Self {
        Self {
            ptr: value.as_ptr() as *const c_char,
            len: value.len(),
        }
    }
}

#[repr(C)]
pub struct MocktailRustPayloadInfoView {
    pub package_name: MocktailRustStrSlice,
    pub version_name: MocktailRustStrSlice,
    pub version_code: u64,
    pub build_id: MocktailRustStrSlice,
    pub library_sha256: MocktailRustStrSlice,
    pub base_apk_sha256: MocktailRustStrSlice,
    pub split_apk_sha256: MocktailRustStrSlice,
    pub asset_file_count: usize,
    pub asset_tree_sha256: MocktailRustStrSlice,
    pub payload_id: MocktailRustStrSlice,
}

pub type MocktailPayloadInfoCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, info: *const MocktailRustPayloadInfoView)>;

#[repr(C)]
pub struct MocktailRustApkMetadataRequest {
    pub version_name: *const c_char,
    pub version_code: u64,
    pub abi: *const c_char,
    pub elf_build_id: *const c_char,
    pub library_sha256: *const c_char,
    pub base_apk_sha256: *const c_char,
    pub split_apk_hash_key: *const c_char,
    pub split_apk_sha256: *const c_char,
    pub signing_certs: *const *const c_char,
    pub signing_certs_count: usize,
    pub asset_file_count: usize,
    pub asset_tree_sha256: *const c_char,
    pub source: *const c_char,
    pub imported_at: *const c_char,
    pub exact_supported: bool,
    pub monolithic: bool,
}

pub type MocktailCandidateActivationCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        generation: *const c_char,
        gen_len: usize,
        approval_ref: *const c_char,
        approval_len: usize,
        profile_ref: *const c_char,
        profile_len: usize,
        compat_ref: *const c_char,
        compat_len: usize,
    ),
>;

#[repr(C)]
pub struct MocktailRustCandidateEvidenceRequest {
    pub receipt_ptr: *const c_char,
    pub receipt_len: usize,
    pub canary1_ptr: *const c_char,
    pub canary1_len: usize,
    pub canary2_ptr: *const c_char,
    pub canary2_len: usize,
    pub payload_id: *const c_char,
    pub generation: *const c_char,
    pub canonical_library_path: *const c_char,
    pub elf_build_id: *const c_char,
    pub library_sha256: *const c_char,
    pub fingerprint: *const c_char,
    pub profile_sha256: *const c_char,
    pub compatibility_sha256: *const c_char,
}

pub type MocktailTrustedUrlCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, url: *const c_char, url_len: usize) -> bool>;

pub type MocktailPinnedArchiveCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        filename: *const c_char,
        filename_len: usize,
        url: *const c_char,
        url_len: usize,
        sha256: *const c_char,
        sha256_len: usize,
        size: u64,
    ),
>;

// ============================================================================
// 1. Zip Archive & Payload Integrity Struct Callbacks
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_zip_list_entries_cb(
    archive_path: *const c_char,
    max_entries: usize,
    on_entry: MocktailZipEntryCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(path) = c_str_opt(archive_path) else {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    };
    match zip_list_entries_internal(path, max_entries) {
        Ok(entries) => {
            if let Some(cb) = on_entry {
                for entry in entries {
                    unsafe {
                        cb(
                            ctx,
                            entry.name.as_ptr() as *const c_char,
                            entry.name.len(),
                            entry.uncompressed_size,
                            entry.directory,
                            entry.symbolic_link,
                        );
                    }
                }
            }
            0
        }
        Err((code, msg)) => {
            copy_error(out_err, err_cap, &msg);
            code
        }
    }
}

fn emit_payload_info(
    info: &MocktailRustPayloadInfo,
    on_info: MocktailPayloadInfoCallback,
    ctx: *mut c_void,
) {
    let Some(cb) = on_info else {
        return;
    };
    let view = MocktailRustPayloadInfoView {
        package_name: MocktailRustStrSlice::from_str(&info.package_name),
        version_name: MocktailRustStrSlice::from_str(&info.version_name),
        version_code: info.version_code,
        build_id: MocktailRustStrSlice::from_str(&info.build_id),
        library_sha256: MocktailRustStrSlice::from_str(&info.library_sha256),
        base_apk_sha256: MocktailRustStrSlice::from_str(&info.base_apk_sha256),
        split_apk_sha256: MocktailRustStrSlice::from_str(&info.split_apk_sha256),
        asset_file_count: info.asset_file_count,
        asset_tree_sha256: MocktailRustStrSlice::from_str(&info.asset_tree_sha256),
        payload_id: MocktailRustStrSlice::from_str(&info.payload_id),
    };
    unsafe { cb(ctx, &view) };
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_inspect_cb(
    payload_dir: *const c_char,
    on_info: MocktailPayloadInfoCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(dir) = c_str_opt(payload_dir) else {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    };
    match internal_inspect_payload(Path::new(dir)) {
        Ok(info) => {
            emit_payload_info(&info, on_info, ctx);
            0
        }
        Err(msg) => {
            copy_error(out_err, err_cap, &msg);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_payload_verify_cb(
    payload_dir: *const c_char,
    on_info: MocktailPayloadInfoCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(dir) = c_str_opt(payload_dir) else {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    };
    match verify_payload_internal(Path::new(dir)) {
        Ok(info) => {
            emit_payload_info(&info, on_info, ctx);
            0
        }
        Err((code, msg)) => {
            copy_error(out_err, err_cap, &msg);
            code
        }
    }
}

// ============================================================================
// 2. APKPure Exact URL Callback
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_apkpure_parse_exact_urls_cb(
    metadata: *const u8,
    meta_len: usize,
    version: *const c_char,
    version_code: u64,
    on_url: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(ver_target) = c_str_opt(version) else {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    };
    let data = if meta_len == 0 {
        &[]
    } else if metadata.is_null() {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    } else {
        unsafe { std::slice::from_raw_parts(metadata, meta_len) }
    };

    match apkpure_collect_exact_urls(data, ver_target, version_code) {
        Ok(urls) => {
            for url in urls {
                emit_string(on_url, ctx, &url);
            }
            0
        }
        Err((code, msg)) => {
            copy_error(out_err, err_cap, msg);
            code
        }
    }
}

// ============================================================================
// 3. APK Bundle Signing Trust & Payload Metadata JSON
// ============================================================================

fn parse_trusted_certificates_internal(contents: &str) -> Result<BTreeSet<String>, &'static str> {
    let doc: Value = serde_json::from_str(contents)
        .map_err(|_| "Roblox signing trust manifest is invalid")?;
    let obj = doc
        .as_object()
        .ok_or("Roblox signing trust manifest is invalid")?;
    let schema_ok = obj.get("schema_version").and_then(|v| v.as_i64()) == Some(1);
    let package_ok = obj.get("package").and_then(|v| v.as_str()) == Some("com.roblox.client");
    let array = obj
        .get("trusted_sha256")
        .and_then(|v| v.as_array())
        .filter(|_| schema_ok && package_ok)
        .ok_or("Roblox signing trust manifest is invalid")?;

    let mut trusted = BTreeSet::new();
    for value in array {
        let s = value
            .as_str()
            .ok_or("Roblox signing trust manifest contains a non-string digest")?;
        let lower = s.to_ascii_lowercase();
        if !is_lower_hex(&lower, 64) {
            return Err("Roblox signing trust manifest contains an invalid digest");
        }
        trusted.insert(lower);
    }
    if trusted.is_empty() {
        return Err("Roblox signing trust manifest is empty");
    }
    Ok(trusted)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apk_parse_trusted_certificates(
    json_ptr: *const c_char,
    json_len: usize,
    on_sha256: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(contents) = slice_to_str(json_ptr, json_len) else {
        copy_error(out_err, err_cap, "Roblox signing trust manifest is invalid");
        return -1;
    };
    match parse_trusted_certificates_internal(contents) {
        Ok(trusted) => {
            for digest in trusted {
                emit_string(on_sha256, ctx, &digest);
            }
            0
        }
        Err(msg) => {
            copy_error(out_err, err_cap, msg);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_apk_build_payload_metadata(
    req: *const MocktailRustApkMetadataRequest,
    on_json: MocktailPayloadStoreStringCallback,
    ctx: *mut c_void,
) -> c_int {
    if req.is_null() {
        return -1;
    }
    let inp = unsafe { &*req };
    let (
        Some(version_name),
        Some(abi),
        Some(elf_build_id),
        Some(library_sha256),
        Some(base_apk_sha256),
        Some(split_apk_hash_key),
        Some(split_apk_sha256),
        Some(asset_tree_sha256),
        Some(source),
        Some(imported_at),
    ) = (
        c_str_opt(inp.version_name),
        c_str_opt(inp.abi),
        c_str_opt(inp.elf_build_id),
        c_str_opt(inp.library_sha256),
        c_str_opt(inp.base_apk_sha256),
        c_str_opt(inp.split_apk_hash_key),
        c_str_opt(inp.split_apk_sha256),
        c_str_opt(inp.asset_tree_sha256),
        c_str_opt(inp.source),
        c_str_opt(inp.imported_at),
    )
    else {
        return -1;
    };

    let mut certs = Vec::with_capacity(inp.signing_certs_count);
    if inp.signing_certs_count > 0 {
        if inp.signing_certs.is_null() {
            return -1;
        }
        let ptrs = unsafe { std::slice::from_raw_parts(inp.signing_certs, inp.signing_certs_count) };
        for &cert_ptr in ptrs {
            let Some(cert) = c_str_opt(cert_ptr) else {
                return -1;
            };
            certs.push(Value::String(cert.to_string()));
        }
    }

    let mut sha_map = BTreeMap::new();
    sha_map.insert("base_apk", Value::String(base_apk_sha256.to_string()));
    sha_map.insert("libroblox", Value::String(library_sha256.to_string()));
    sha_map.insert(split_apk_hash_key, Value::String(split_apk_sha256.to_string()));

    let mut assets_map = BTreeMap::new();
    assets_map.insert("file_count", Value::from(inp.asset_file_count as u64));
    assets_map.insert(
        "sha256_tree",
        Value::String(asset_tree_sha256.to_string()),
    );

    let compat_status = if inp.exact_supported {
        "exact-supported"
    } else {
        "verified-candidate"
    };
    let apk_layout = if inp.monolithic {
        "monolithic"
    } else {
        "split"
    };

    let mut root = serde_json::Map::new();
    root.insert("schema_version".into(), Value::from(1));
    root.insert("package".into(), Value::String("com.roblox.client".into()));
    root.insert("version_name".into(), Value::String(version_name.to_string()));
    root.insert("version_code".into(), Value::from(inp.version_code));
    root.insert("abi".into(), Value::String(abi.to_string()));
    root.insert("elf_build_id".into(), Value::String(elf_build_id.to_string()));
    root.insert(
        "sha256".into(),
        Value::Object(
            sha_map
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        ),
    );
    root.insert("signing_certificates_sha256".into(), Value::Array(certs));
    root.insert(
        "assets".into(),
        Value::Object(
            assets_map
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        ),
    );
    root.insert("source".into(), Value::String(source.to_string()));
    root.insert("imported_at".into(), Value::String(imported_at.to_string()));
    root.insert(
        "compatibility_status".into(),
        Value::String(compat_status.to_string()),
    );
    root.insert("apk_layout".into(), Value::String(apk_layout.to_string()));

    let Ok(mut rendered) = serde_json::to_string_pretty(&Value::Object(root)) else {
        return -1;
    };
    rendered.push('\n');
    emit_string(on_json, ctx, &rendered);
    0
}

// ============================================================================
// 4. Candidate Approval Activation & Evidence Verification
// ============================================================================

fn extract_generation(relative: &str, directory: &str, payload_id: &str) -> Option<String> {
    let prefix = format!("{}/{}-", directory, payload_id);
    let rest = relative.strip_prefix(&prefix)?;
    let generation = rest.strip_suffix(".json")?;
    if !is_lower_hex(generation, 40) {
        return None;
    }
    Some(generation.to_string())
}

#[no_mangle]
pub extern "C" fn mocktail_rust_candidate_approval_parse_activation(
    activation_ptr: *const c_char,
    activation_len: usize,
    payload_id_ptr: *const c_char,
    on_parsed: MocktailCandidateActivationCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let Some(payload_id) = c_str_opt(payload_id_ptr) else {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    };
    let Some(json_str) = slice_to_str(activation_ptr, activation_len) else {
        copy_error(out_err, err_cap, "approval artifact is not a JSON object");
        return -1;
    };
    let Ok(doc) = serde_json::from_str::<Value>(json_str) else {
        copy_error(out_err, err_cap, "approval artifact is not a JSON object");
        return -1;
    };
    let Some(obj) = doc.as_object() else {
        copy_error(out_err, err_cap, "approval artifact is not a JSON object");
        return -1;
    };

    let approval_ref = obj
        .get("approval_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let profile_ref = obj
        .get("host_abi_profile_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let compat_ref = obj
        .get("compatibility_manifest_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let Some(generation) = extract_generation(approval_ref, "approvals", payload_id) else {
        copy_error(
            out_err,
            err_cap,
            "approved payload manifest has invalid approval references",
        );
        return -1;
    };
    let expected_profile = format!("host_abi_profiles/{}-{}.json", payload_id, generation);
    let expected_compat = format!("compatibility_profiles/{}-{}.json", payload_id, generation);
    if profile_ref != expected_profile || compat_ref != expected_compat {
        copy_error(
            out_err,
            err_cap,
            "approved payload manifest has invalid approval references",
        );
        return -1;
    }

    if let Some(cb) = on_parsed {
        unsafe {
            cb(
                ctx,
                generation.as_ptr() as *const c_char,
                generation.len(),
                approval_ref.as_ptr() as *const c_char,
                approval_ref.len(),
                profile_ref.as_ptr() as *const c_char,
                profile_ref.len(),
                compat_ref.as_ptr() as *const c_char,
                compat_ref.len(),
            );
        }
    }
    0
}

fn sha256_lower_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_candidate_approval_verify_evidence(
    req: *const MocktailRustCandidateEvidenceRequest,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    if req.is_null() {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    }
    let inp = unsafe { &*req };
    let (
        Some(payload_id),
        Some(generation),
        Some(canonical_library_path),
        Some(elf_build_id),
        Some(library_sha256),
        Some(fingerprint),
        Some(profile_sha256),
        Some(compatibility_sha256),
        Some(receipt_str),
        Some(canary1_str),
        Some(canary2_str),
    ) = (
        c_str_opt(inp.payload_id),
        c_str_opt(inp.generation),
        c_str_opt(inp.canonical_library_path),
        c_str_opt(inp.elf_build_id),
        c_str_opt(inp.library_sha256),
        c_str_opt(inp.fingerprint),
        c_str_opt(inp.profile_sha256),
        c_str_opt(inp.compatibility_sha256),
        slice_to_str(inp.receipt_ptr, inp.receipt_len),
        slice_to_str(inp.canary1_ptr, inp.canary1_len),
        slice_to_str(inp.canary2_ptr, inp.canary2_len),
    )
    else {
        copy_error(out_err, err_cap, "approval artifact is not a JSON object");
        return -1;
    };

    let Ok(receipt_doc) = serde_json::from_str::<Value>(receipt_str) else {
        copy_error(out_err, err_cap, "approval artifact is not a JSON object");
        return -1;
    };
    let Some(receipt) = receipt_doc.as_object() else {
        copy_error(out_err, err_cap, "approval artifact is not a JSON object");
        return -1;
    };

    let canary_runtime_sha256 = receipt
        .get("canary_runtime_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let runtime_sha256 = receipt
        .get("runtime_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let runtime_build_id = receipt
        .get("runtime_build_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let attestations = receipt
        .get("canary_attestation_sha256")
        .and_then(|v| v.as_array());

    let receipt_ok = receipt.get("schema_version").and_then(|v| v.as_i64()) == Some(1)
        && receipt.get("status").and_then(|v| v.as_str()) == Some("approved")
        && receipt.get("payload_id").and_then(|v| v.as_str()) == Some(payload_id)
        && receipt.get("generation").and_then(|v| v.as_str()) == Some(generation)
        && receipt.get("payload_path").and_then(|v| v.as_str()) == Some(canonical_library_path)
        && receipt.get("elf_build_id").and_then(|v| v.as_str()) == Some(elf_build_id)
        && receipt.get("payload_sha256").and_then(|v| v.as_str()) == Some(library_sha256)
        && receipt.get("payload_fingerprint").and_then(|v| v.as_str()) == Some(fingerprint)
        && receipt.get("profile_sha256").and_then(|v| v.as_str()) == Some(profile_sha256)
        && receipt
            .get("compatibility_manifest_sha256")
            .and_then(|v| v.as_str())
            == Some(compatibility_sha256)
        && is_lower_hex(canary_runtime_sha256, 64)
        && runtime_sha256 == canary_runtime_sha256
        && is_lower_hex(runtime_build_id, 40)
        && receipt.get("canary_tier").and_then(|v| v.as_str()) == Some("C")
        && receipt.get("successful_runs").and_then(|v| v.as_u64()) == Some(2)
        && attestations.is_some_and(|arr| arr.len() == 2);

    if !receipt_ok {
        copy_error(
            out_err,
            err_cap,
            "approval receipt does not authorize exact payload evidence",
        );
        return -1;
    }
    let attestations = attestations.unwrap();

    let canary_inputs = [canary1_str, canary2_str];
    let mut attestation_hashes = [String::new(), String::new()];
    let mut run_ids = [String::new(), String::new()];

    for index in 0..2 {
        let bytes_str = canary_inputs[index];
        let Ok(att_doc) = serde_json::from_str::<Value>(bytes_str) else {
            copy_error(out_err, err_cap, "approval artifact is not a JSON object");
            return -1;
        };
        let Some(att) = att_doc.as_object() else {
            copy_error(out_err, err_cap, "approval artifact is not a JSON object");
            return -1;
        };
        attestation_hashes[index] = sha256_lower_hex(bytes_str.as_bytes());
        run_ids[index] = att
            .get("run_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let att_ok = att.get("schema_version").and_then(|v| v.as_i64()) == Some(1)
            && att.get("status").and_then(|v| v.as_str()) == Some("passed")
            && att.get("canary_tier").and_then(|v| v.as_str()) == Some("C")
            && att.get("run").and_then(|v| v.as_u64()) == Some(index as u64 + 1)
            && att.get("payload_id").and_then(|v| v.as_str()) == Some(payload_id)
            && att.get("payload_fingerprint").and_then(|v| v.as_str()) == Some(fingerprint)
            && att.get("profile_sha256").and_then(|v| v.as_str()) == Some(profile_sha256)
            && att
                .get("compatibility_manifest_sha256")
                .and_then(|v| v.as_str())
                == Some(compatibility_sha256)
            && att.get("runtime_sha256").and_then(|v| v.as_str()) == Some(canary_runtime_sha256)
            && att.get("runtime_build_id").and_then(|v| v.as_str()) == Some(runtime_build_id)
            && is_lower_hex(
                att.get("readiness_log_sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                64,
            )
            && attestations[index].as_str() == Some(attestation_hashes[index].as_str());

        if !att_ok {
            copy_error(
                out_err,
                err_cap,
                "canary attestation does not match approval evidence",
            );
            return -1;
        }
    }

    if run_ids[0].is_empty() || run_ids[0] == run_ids[1] {
        copy_error(
            out_err,
            err_cap,
            "approval canaries do not have distinct run identities",
        );
        return -1;
    }

    let computed = compute_approval_generation_hex(
        runtime_build_id,
        fingerprint,
        profile_sha256,
        compatibility_sha256,
        &attestation_hashes[0],
        &attestation_hashes[1],
    );
    if computed != generation {
        copy_error(out_err, err_cap, "approval evidence generation does not match");
        return -1;
    }
    0
}

// ============================================================================
// 5. Pinned APK Source Manifest Query & Validation
// ============================================================================

struct PinnedArchiveEntry {
    filename: String,
    url: String,
    sha256: String,
    size: u64,
}

fn find_pinned_source_internal(
    manifest_path: &str,
    version_name: &str,
    version_code: u64,
    abi: &str,
    max_archive_bytes: u64,
    url_checker: &dyn Fn(&str) -> bool,
) -> Result<(String, Vec<PinnedArchiveEntry>), String> {
    let Some((_, doc)) = read_update_state_json_string(manifest_path) else {
        return Err("pinned APK source manifest is unavailable or invalid".to_string());
    };
    let Some(obj) = doc.as_object() else {
        return Err("pinned APK source manifest is unavailable or invalid".to_string());
    };
    let schema_ok = obj
        .get("schema_version")
        .is_some_and(|v| v.is_i64() && v.as_i64() == Some(1));
    let Some(sources) = obj
        .get("sources")
        .and_then(|v| v.as_array())
        .filter(|_| schema_ok)
    else {
        return Err("pinned APK source manifest is unavailable or invalid".to_string());
    };

    let mut matched_build_id = String::new();
    let mut matched_archives: Vec<PinnedArchiveEntry> = Vec::new();

    for source in sources {
        let Some(source_obj) = source.as_object() else {
            continue;
        };
        if source_obj.get("abi").and_then(|v| v.as_str()) != Some(abi)
            || source_obj.get("version_name").and_then(|v| v.as_str()) != Some(version_name)
            || source_obj.get("version_code").and_then(|v| v.as_u64()) != Some(version_code)
        {
            continue;
        }
        if !matched_archives.is_empty() {
            return Err("pinned APK source is duplicated".to_string());
        }
        let Some(pkg) = source_obj.get("package").and_then(|v| v.as_str()) else {
            return Err("pinned APK source has invalid identity or archives".to_string());
        };
        let Some(build_id) = source_obj.get("elf_build_id").and_then(|v| v.as_str()) else {
            return Err("pinned APK source has invalid identity or archives".to_string());
        };
        let Some(archives_arr) = source_obj.get("archives").and_then(|v| v.as_array()) else {
            return Err("pinned APK source has invalid identity or archives".to_string());
        };
        if pkg != "com.roblox.client"
            || !is_lower_hex(build_id, 40)
            || archives_arr.is_empty()
            || archives_arr.len() > 4
        {
            return Err("pinned APK source has invalid identity or archives".to_string());
        }

        matched_build_id = build_id.to_string();
        let mut seen_filenames = HashSet::new();
        for entry in archives_arr {
            let Some(entry_obj) = entry.as_object() else {
                return Err("pinned APK archive is incomplete".to_string());
            };
            let (Some(filename), Some(url), Some(sha256), Some(size)) = (
                entry_obj.get("filename").and_then(|v| v.as_str()),
                entry_obj.get("url").and_then(|v| v.as_str()),
                entry_obj.get("sha256").and_then(|v| v.as_str()),
                entry_obj.get("size").and_then(|v| v.as_u64()),
            ) else {
                return Err("pinned APK archive is incomplete".to_string());
            };

            let filename_valid = !filename.is_empty()
                && mocktail_rust_pinned_apk_archive_filename_valid(
                    filename.as_ptr() as *const c_char,
                    filename.len(),
                ) == 1;
            let limits_valid =
                mocktail_rust_pinned_apk_archive_limits_valid(size, max_archive_bytes) == 1;
            if !filename_valid
                || !seen_filenames.insert(filename.to_string())
                || !limits_valid
                || !is_lower_hex(sha256, 64)
                || !url_checker(url)
            {
                return Err("pinned APK archive has an invalid name, URL, or digest".to_string());
            }

            matched_archives.push(PinnedArchiveEntry {
                filename: filename.to_string(),
                url: url.to_string(),
                sha256: sha256.to_string(),
                size,
            });
        }
    }

    if matched_archives.is_empty() {
        return Err(format!(
            "no pinned APK source for Roblox {} ({})",
            version_name, abi
        ));
    }
    Ok((matched_build_id, matched_archives))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_pinned_apk_find_source(
    manifest_path: *const c_char,
    version_name: *const c_char,
    version_code: u64,
    abi: *const c_char,
    max_archive_bytes: u64,
    is_trusted_url: MocktailTrustedUrlCallback,
    on_build_id: MocktailPayloadStoreStringCallback,
    on_archive: MocktailPinnedArchiveCallback,
    ctx: *mut c_void,
    out_err: *mut c_char,
    err_cap: usize,
) -> c_int {
    let (Some(manifest), Some(ver), Some(abi_str)) = (
        c_str_opt(manifest_path),
        c_str_opt(version_name),
        c_str_opt(abi),
    ) else {
        copy_error(out_err, err_cap, "invalid arguments");
        return -1;
    };

    let checker = |url: &str| -> bool {
        if let Some(cb) = is_trusted_url {
            unsafe { cb(ctx, url.as_ptr() as *const c_char, url.len()) }
        } else {
            false
        }
    };

    match find_pinned_source_internal(manifest, ver, version_code, abi_str, max_archive_bytes, &checker) {
        Ok((build_id, archives)) => {
            emit_string(on_build_id, ctx, &build_id);
            if let Some(cb) = on_archive {
                for archive in archives {
                    unsafe {
                        cb(
                            ctx,
                            archive.filename.as_ptr() as *const c_char,
                            archive.filename.len(),
                            archive.url.as_ptr() as *const c_char,
                            archive.url.len(),
                            archive.sha256.as_ptr() as *const c_char,
                            archive.sha256.len(),
                            archive.size,
                        );
                    }
                }
            }
            0
        }
        Err(msg) => {
            copy_error(out_err, err_cap, &msg);
            -1
        }
    }
}

// ============================================================================
// 6. HTTP Resume ETag State Helpers
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_http_read_resume_etag(
    state_path: *const c_char,
    expected_url: *const c_char,
    out_etag: *mut c_char,
    etag_cap: usize,
) -> c_int {
    if !out_etag.is_null() && etag_cap > 0 {
        unsafe { *out_etag = 0 };
    }
    let (Some(path_str), Some(url_str)) = (c_str_opt(state_path), c_str_opt(expected_url)) else {
        return -1;
    };
    let Some((_, doc)) = read_update_state_json_string(path_str) else {
        return 1;
    };
    let Some(obj) = doc.as_object() else {
        return 1;
    };
    if obj.get("url").and_then(|v| v.as_str()) != Some(url_str) {
        return 1;
    }
    let Some(etag) = obj.get("etag").and_then(|v| v.as_str()) else {
        return 1;
    };
    copy_to_c_buffer(etag, out_etag, etag_cap)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_http_write_resume_state(
    state_path: *const c_char,
    url: *const c_char,
    etag: *const c_char,
) -> c_int {
    let (Some(path_str), Some(url_str), Some(etag_str)) =
        (c_str_opt(state_path), c_str_opt(url), c_str_opt(etag))
    else {
        return -1;
    };
    let mut root = serde_json::Map::new();
    root.insert("etag".into(), Value::String(etag_str.to_string()));
    root.insert("url".into(), Value::String(url_str.to_string()));
    let Ok(mut rendered) = serde_json::to_string_pretty(&Value::Object(root)) else {
        return -1;
    };
    rendered.push('\n');
    let path = Path::new(path_str);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if fs::create_dir_all(parent).is_err() {
            return -1;
        }
    }
    if write_atomic_bytes(path, rendered.as_bytes()).is_err() {
        return -1;
    }
    0
}

// ============================================================================
// 7. Update Coordinator Opaque `update.json` State
// ============================================================================

pub struct MocktailRustUpdateState {
    path: PathBuf,
    map: serde_json::Map<String, Value>,
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read_stored_version(val: Option<&Value>) -> Option<(String, u64, String)> {
    let obj = val?.as_object()?;
    let ver_name = obj.get("version_name")?.as_str()?;
    let ver_code = obj.get("version_code")?.as_u64()?;
    if ver_name.is_empty() || ver_code == 0 {
        return None;
    }
    let payload_id = obj
        .get("payload_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((ver_name.to_string(), ver_code, payload_id))
}

impl MocktailRustUpdateState {
    fn open(path: &Path) -> Self {
        let mut map = path
            .to_str()
            .and_then(read_update_state_json_string)
            .and_then(|(_, v)| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        map.insert("schema_version".into(), Value::from(1));
        map.insert("metadata_status".into(), Value::String("unchecked".into()));
        Self {
            path: path.to_path_buf(),
            map,
        }
    }

    fn save(&self) {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut rendered) = serde_json::to_string_pretty(&Value::Object(self.map.clone())) {
            rendered.push('\n');
            let _ = write_atomic_bytes(&self.path, rendered.as_bytes());
        }
    }

    fn save_phase(&mut self, phase: &str) {
        self.map
            .insert("phase".into(), Value::String(phase.to_string()));
        self.map
            .insert("updated_at".into(), Value::from(now_unix_secs()));
        self.save();
    }

    fn stored_version_code(&self, key: &str) -> u64 {
        read_stored_version(self.map.get(key))
            .map(|(_, code, _)| code)
            .unwrap_or(0)
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_new(
    state_path: *const c_char,
) -> *mut MocktailRustUpdateState {
    let Some(path_str) = c_str_opt(state_path) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(MocktailRustUpdateState::open(Path::new(path_str))))
}

/// Frees a `MocktailRustUpdateState` handle allocated by `mocktail_rust_update_state_new`.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_free(state: *mut MocktailRustUpdateState) {
    if !state.is_null() {
        unsafe { drop(Box::from_raw(state)) };
    }
}

/// Updates the updater phase and persists the state file.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_save_phase(
    state: *mut MocktailRustUpdateState,
    phase: *const c_char,
) {
    if state.is_null() {
        return;
    }
    if let Some(phase_str) = c_str_opt(phase) {
        unsafe { (*state).save_phase(phase_str) };
    }
}

/// Sets the updater metadata status field in memory.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_set_metadata_status(
    state: *mut MocktailRustUpdateState,
    status: *const c_char,
) {
    if state.is_null() {
        return;
    }
    if let Some(status_str) = c_str_opt(status) {
        unsafe {
            (*state)
                .map
                .insert("metadata_status".into(), Value::String(status_str.to_string()));
        }
    }
}

/// Records the result of checking the latest remote metadata.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_record_latest_check(
    state: *mut MocktailRustUpdateState,
    available: bool,
    version_name: *const c_char,
    version_code: u64,
) {
    if state.is_null() {
        return;
    }
    let st = unsafe { &mut *state };
    st.map
        .insert("checked_at".into(), Value::from(now_unix_secs()));
    if available {
        st.map
            .insert("metadata_status".into(), Value::String("available".into()));
        let ver_name = c_str_opt(version_name).unwrap_or("");
        if st.stored_version_code("latest_seen") <= version_code {
            st.map.insert(
                "latest_seen".into(),
                serde_json::json!({
                    "version_name": ver_name,
                    "version_code": version_code,
                }),
            );
        }
    } else {
        st.map.insert(
            "metadata_status".into(),
            Value::String("unavailable".into()),
        );
    }
}

/// Reads the highest recorded downloaded version into caller-provided buffers.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_get_latest_downloaded(
    state: *const MocktailRustUpdateState,
    out_version_name: *mut c_char,
    ver_cap: usize,
    out_version_code: *mut u64,
    out_payload_id: *mut c_char,
    pid_cap: usize,
) -> bool {
    if state.is_null() {
        return false;
    }
    let st = unsafe { &*state };
    let Some((ver_name, ver_code, payload_id)) =
        read_stored_version(st.map.get("latest_downloaded"))
    else {
        return false;
    };
    if copy_to_c_buffer(&ver_name, out_version_name, ver_cap) != 0 {
        return false;
    }
    if !out_version_code.is_null() {
        unsafe { *out_version_code = ver_code };
    }
    if !out_payload_id.is_null()
        && pid_cap > 0
        && copy_to_c_buffer(&payload_id, out_payload_id, pid_cap) != 0
    {
        return false;
    }
    true
}

/// Records the latest downloaded payload version metadata in state.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_record_latest_downloaded(
    state: *mut MocktailRustUpdateState,
    payload_id: *const c_char,
    version_name: *const c_char,
    version_code: u64,
) {
    if state.is_null() {
        return;
    }
    let st = unsafe { &mut *state };
    let pid = c_str_opt(payload_id).unwrap_or("");
    let vname = c_str_opt(version_name).unwrap_or("");
    if st.stored_version_code("latest_downloaded") <= version_code {
        st.map.insert(
            "latest_downloaded".into(),
            serde_json::json!({
                "payload_id": pid,
                "version_name": vname,
                "version_code": version_code,
            }),
        );
    }
}

/// Finalizes the update outcome, computes staleness, and persists the state file.
#[no_mangle]
pub extern "C" fn mocktail_rust_update_state_finish_and_save(
    state: *mut MocktailRustUpdateState,
    active_valid: bool,
    active_payload_id: *const c_char,
    active_version_name: *const c_char,
    active_version_code: u64,
    supported_version_code: u64,
    succeeded: bool,
    changed: bool,
    message: *const c_char,
    error: *const c_char,
    out_stale: *mut bool,
) {
    if state.is_null() {
        return;
    }
    let st = unsafe { &mut *state };
    if active_valid {
        let pid = c_str_opt(active_payload_id).unwrap_or("");
        let vname = c_str_opt(active_version_name).unwrap_or("");
        st.map.insert(
            "active".into(),
            serde_json::json!({
                "payload_id": pid,
                "version_name": vname,
                "version_code": active_version_code,
            }),
        );
    } else {
        st.map.insert("active".into(), Value::Null);
    }

    let highest_seen = supported_version_code.max(st.stored_version_code("latest_seen"));
    let stale = active_valid && active_version_code < highest_seen;
    if !out_stale.is_null() {
        unsafe { *out_stale = stale };
    }

    let msg_str = c_str_opt(message).unwrap_or("");
    let err_str = c_str_opt(error).unwrap_or("");
    st.map
        .insert("message".into(), Value::String(msg_str.to_string()));
    st.map
        .insert("error".into(), Value::String(err_str.to_string()));
    st.map.insert("stale".into(), Value::Bool(stale));

    let cur_phase = st
        .map
        .get("phase")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let meta_status = st
        .map
        .get("metadata_status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let next_phase = if !succeeded {
        "error".to_string()
    } else if changed {
        if stale { "blocked" } else { "current" }.to_string()
    } else if cur_phase == "checking" {
        if meta_status == "unavailable" {
            "metadata-unavailable".to_string()
        } else if stale {
            "blocked".to_string()
        } else {
            "current".to_string()
        }
    } else {
        cur_phase
    };
    st.save_phase(&next_phase);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn trusted_certificates_validation_accepts_and_lowercases() {
        let valid = r#"{
            "schema_version": 1,
            "package": "com.roblox.client",
            "trusted_sha256": [
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "2bebd189e8d3106401347056c93d045b61e20e22d0c3cbed85474aeb00a3d12a"
            ]
        }"#;
        let set = parse_trusted_certificates_internal(valid).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&"a".repeat(64)));

        let empty = r#"{"schema_version":1,"package":"com.roblox.client","trusted_sha256":[]}"#;
        assert_eq!(
            parse_trusted_certificates_internal(empty).unwrap_err(),
            "Roblox signing trust manifest is empty"
        );
    }

    #[test]
    fn pinned_source_validation_and_update_state_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("mocktail_update_json_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let manifest_path = temp_dir.join("sources.json");
        let manifest_json = format!(
            r#"{{
                "schema_version": 1,
                "sources": [{{
                    "package": "com.roblox.client",
                    "version_name": "2.742.1059",
                    "version_code": 3222,
                    "abi": "x86_64",
                    "elf_build_id": "{}",
                    "archives": [{{
                        "filename": "base.apk",
                        "url": "https://github.com/example/base.apk",
                        "sha256": "{}",
                        "size": 128
                    }}]
                }}]
            }}"#,
            "a".repeat(40),
            "b".repeat(64)
        );
        fs::write(&manifest_path, manifest_json).unwrap();
        let (bid, archives) = find_pinned_source_internal(
            manifest_path.to_str().unwrap(),
            "2.742.1059",
            3222,
            "x86_64",
            1024 * 1024,
            &|url| url.starts_with("https://github.com/"),
        )
        .unwrap();
        assert_eq!(bid, "a".repeat(40));
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[0].filename, "base.apk");

        let state_path = temp_dir.join("update.json");
        let state_c = CString::new(state_path.to_str().unwrap()).unwrap();
        let phase_c = CString::new("checking").unwrap();
        let vname_c = CString::new("2.800.0").unwrap();
        let pid_c = CString::new(format!("2800-{}", "c".repeat(40))).unwrap();
        let msg_c = CString::new("downloaded").unwrap();
        let err_c = CString::new("").unwrap();

        let st = mocktail_rust_update_state_new(state_c.as_ptr());
        assert!(!st.is_null());
        mocktail_rust_update_state_save_phase(st, phase_c.as_ptr());
        mocktail_rust_update_state_record_latest_check(st, true, vname_c.as_ptr(), 3500);
        mocktail_rust_update_state_record_latest_downloaded(
            st,
            pid_c.as_ptr(),
            vname_c.as_ptr(),
            3500,
        );

        let mut out_v = [0 as c_char; 64];
        let mut out_code = 0u64;
        let mut out_pid = [0 as c_char; 128];
        assert!(mocktail_rust_update_state_get_latest_downloaded(
            st,
            out_v.as_mut_ptr(),
            out_v.len(),
            &mut out_code,
            out_pid.as_mut_ptr(),
            out_pid.len(),
        ));
        assert_eq!(out_code, 3500);

        let mut stale = false;
        mocktail_rust_update_state_finish_and_save(
            st,
            true,
            pid_c.as_ptr(),
            vname_c.as_ptr(),
            3400,
            3400,
            true,
            false,
            msg_c.as_ptr(),
            err_c.as_ptr(),
            &mut stale,
        );
        assert!(stale);
        mocktail_rust_update_state_free(st);

        let persisted: Value =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        assert_eq!(persisted["phase"], "blocked");
        assert_eq!(persisted["stale"], true);
        assert_eq!(persisted["latest_seen"]["version_code"], 3500);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
