use std::ffi::{c_void, OsStr};
use std::fs;
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};

use crate::payload_store::{
    MocktailRustCandidateApprovalData, MocktailRustPayloadInfoData,
};
use crate::unix_ipc::{
    current_pid, epoch_seconds_now, format_utc_iso8601_now, path_to_slice,
    read_owned_regular_file_limited, slice_to_pathbuf, slice_to_str_lossy,
    write_mode_exclusive_atomic, ReadOwnedFileError,
};
use crate::update_json::{
    parse_candidate_activation_json, verify_candidate_evidence_json, CandidateEvidenceParams,
    MocktailRustStrSlice,
};
use crate::{
    build_approval_receipt_json, build_canary_attestation_json, compute_approval_fingerprint_hex,
    compute_approval_generation_hex, host_guest_abi, read_elf_build_id_file, sha256_bytes_hex,
    sha256_file_hex, sha256_regular_file_strict, validate_approval_binding_bytes,
    MocktailRustPayloadInfo,
};

const K_MAXIMUM_APPROVAL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default, Clone)]
pub(crate) struct CandidateApprovalOptionsData {
    pub store_root: PathBuf,
    pub payload_directory: PathBuf,
    pub profile: PathBuf,
    pub compatibility_manifest: PathBuf,
    pub runtime_binary: PathBuf,
    pub canary_logs: [PathBuf; 2],
}

#[derive(Debug, Default, Clone)]
pub(crate) struct CandidateApprovalResultData {
    pub generation: String,
    pub receipt: PathBuf,
    pub profile: PathBuf,
    pub compatibility_manifest: PathBuf,
    pub error: String,
}

impl CandidateApprovalResultData {
    fn from_error(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            ..Self::default()
        }
    }
}

fn read_approval_artifact(path: &Path, require_read_only: bool) -> Result<Vec<u8>, String> {
    read_owned_regular_file_limited(path, K_MAXIMUM_APPROVAL_BYTES, require_read_only).map_err(
        |err| match err {
            ReadOwnedFileError::OpenFailed => format!("cannot open approval artifact: {}", path.display()),
            ReadOwnedFileError::InvalidOwnershipOrPermissions => {
                "approval artifact ownership or permissions are invalid".to_string()
            }
            ReadOwnedFileError::ReadFailed => "cannot read approval artifact".to_string(),
        },
    )
}

fn copy_immutable_artifact(source: &Path, destination: &Path) -> Result<(), String> {
    let contents = read_approval_artifact(source, false)?;
    write_mode_exclusive_atomic(destination, &contents, 0o444, K_MAXIMUM_APPROVAL_BYTES)
}

fn validate_relative_approval_path(
    root: &Path,
    path: &Path,
    directory: &str,
    payload_id: &str,
    generation: &str,
) -> Result<PathBuf, String> {
    let expected_name = format!("{}-{}.json", payload_id, generation);
    let expected_rel = Path::new(directory).join(&expected_name);
    if path.is_absolute() || path != expected_rel {
        return Err("approval reference is outside its generated directory".to_string());
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|_| "approval store root cannot be resolved safely".to_string())?;
    let canonical = fs::canonicalize(root.join(path))
        .map_err(|_| "approval reference cannot be resolved safely".to_string())?;
    if canonical.parent() != Some(canonical_root.join(directory).as_path())
        || canonical.file_name() != Some(OsStr::new(&expected_name))
    {
        return Err("approval reference cannot be resolved safely".to_string());
    }
    Ok(canonical)
}

/// Computes the Tier-C runtime fingerprint binding a verified payload's metadata, binaries, and assets.
pub(crate) fn payload_runtime_fingerprint(
    payload_directory: &Path,
    payload: &MocktailRustPayloadInfo,
) -> Result<String, String> {
    if payload.payload_id.is_empty() {
        return Err("cannot fingerprint an invalid payload".to_string());
    }
    let metadata_sha256 =
        sha256_regular_file_strict(&payload_directory.join("roblox_payload.json"), None)?;
    compute_approval_fingerprint_hex(
        &payload.payload_id,
        &metadata_sha256,
        &payload.library_sha256,
        &payload.base_apk_sha256,
        host_guest_abi(),
        &payload.split_apk_sha256,
        &payload.asset_tree_sha256,
    )
    .map_err(|_| "cannot fingerprint an invalid payload".to_string())
}

/// Generates immutable `0444` Tier-C probation approval artifacts (attestations, profile, compat, receipt).
pub(crate) fn create_candidate_approval(
    options: &CandidateApprovalOptionsData,
    verified_payload: &MocktailRustPayloadInfo,
) -> CandidateApprovalResultData {
    if verified_payload.payload_id.is_empty()
        || options
            .payload_directory
            .file_name()
            .and_then(|n| n.to_str())
            != Some(verified_payload.payload_id.as_str())
    {
        return CandidateApprovalResultData::from_error(
            "candidate approval requires a preverified exact payload",
        );
    }
    if options.canary_logs[0].as_os_str().is_empty()
        || options.canary_logs[1].as_os_str().is_empty()
        || options.canary_logs[0] == options.canary_logs[1]
    {
        return CandidateApprovalResultData::from_error(
            "candidate approval requires two distinct canary logs",
        );
    }

    let profile_bytes = match read_approval_artifact(&options.profile, false) {
        Ok(b) => b,
        Err(e) => return CandidateApprovalResultData::from_error(e),
    };
    let compatibility_bytes = match read_approval_artifact(&options.compatibility_manifest, false) {
        Ok(b) => b,
        Err(e) => return CandidateApprovalResultData::from_error(e),
    };
    if let Err(msg) = validate_approval_binding_bytes(
        &profile_bytes,
        &compatibility_bytes,
        &verified_payload.payload_id,
        &verified_payload.build_id,
        &verified_payload.library_sha256,
        &verified_payload.version_name,
        verified_payload.version_code,
    ) {
        return CandidateApprovalResultData::from_error(msg);
    }

    let fingerprint = match payload_runtime_fingerprint(&options.payload_directory, verified_payload)
    {
        Ok(f) => f,
        Err(e) => return CandidateApprovalResultData::from_error(e),
    };
    let Some(runtime_sha256) = sha256_file_hex(&options.runtime_binary) else {
        return CandidateApprovalResultData::from_error(format!(
            "cannot hash regular file: {}",
            options.runtime_binary.display()
        ));
    };
    let Some(runtime_build_id) = read_elf_build_id_file(&options.runtime_binary) else {
        return CandidateApprovalResultData::from_error("cannot read ELF GNU Build ID");
    };
    let profile_sha256 = sha256_bytes_hex(&profile_bytes);
    let compatibility_sha256 = sha256_bytes_hex(&compatibility_bytes);

    let epoch = epoch_seconds_now();
    let pid = current_pid();
    let mut attestations = [String::new(), String::new()];
    let mut attestation_hashes = [String::new(), String::new()];
    for (index, log_path) in options.canary_logs.iter().enumerate() {
        let log_sha256 = match sha256_regular_file_strict(log_path, None) {
            Ok(h) => h,
            Err(e) => return CandidateApprovalResultData::from_error(e),
        };
        let run = index + 1;
        let run_id = format!("{}-{}-{}-{}", verified_payload.payload_id, run, epoch, pid);
        let Some(attestation_json) = build_canary_attestation_json(
            run,
            &run_id,
            &verified_payload.payload_id,
            &fingerprint,
            &profile_sha256,
            &compatibility_sha256,
            &runtime_sha256,
            &runtime_build_id,
            &log_sha256,
        ) else {
            return CandidateApprovalResultData::from_error("cannot serialize canary attestation");
        };
        attestation_hashes[index] = sha256_bytes_hex(attestation_json.as_bytes());
        attestations[index] = attestation_json;
    }

    let generation = compute_approval_generation_hex(
        &runtime_build_id,
        &fingerprint,
        &profile_sha256,
        &compatibility_sha256,
        &attestation_hashes[0],
        &attestation_hashes[1],
    );
    if generation.len() != 40 {
        return CandidateApprovalResultData::from_error(
            "cannot derive candidate approval generation",
        );
    }

    let stem = format!("{}-{}", verified_payload.payload_id, generation);
    let result_profile = options
        .store_root
        .join("host_abi_profiles")
        .join(format!("{}.json", stem));
    let result_compat = options
        .store_root
        .join("compatibility_profiles")
        .join(format!("{}.json", stem));
    let result_receipt = options
        .store_root
        .join("approvals")
        .join(format!("{}.json", stem));
    let attestation_paths = [
        options
            .store_root
            .join("approvals")
            .join(format!("{}.canary-1.json", stem)),
        options
            .store_root
            .join("approvals")
            .join(format!("{}.canary-2.json", stem)),
    ];

    if let Err(e) = copy_immutable_artifact(&options.profile, &result_profile)
        .and_then(|_| copy_immutable_artifact(&options.compatibility_manifest, &result_compat))
        .and_then(|_| {
            write_mode_exclusive_atomic(
                &attestation_paths[0],
                attestations[0].as_bytes(),
                0o444,
                K_MAXIMUM_APPROVAL_BYTES,
            )
        })
        .and_then(|_| {
            write_mode_exclusive_atomic(
                &attestation_paths[1],
                attestations[1].as_bytes(),
                0o444,
                K_MAXIMUM_APPROVAL_BYTES,
            )
        })
    {
        return CandidateApprovalResultData::from_error(e);
    }

    let canonical_library = match fs::canonicalize(options.payload_directory.join("libroblox.so")) {
        Ok(p) => p,
        Err(_) => {
            return CandidateApprovalResultData::from_error(
                "cannot canonicalize approved payload library",
            );
        }
    };
    let canonical_str = canonical_library.to_string_lossy();
    let approved_at = format_utc_iso8601_now();
    let Some(receipt_json) = build_approval_receipt_json(
        &verified_payload.payload_id,
        &generation,
        &canonical_str,
        &verified_payload.build_id,
        &verified_payload.library_sha256,
        &fingerprint,
        &profile_sha256,
        &compatibility_sha256,
        &runtime_sha256,
        &runtime_build_id,
        &attestation_hashes[0],
        &attestation_hashes[1],
        &approved_at,
    ) else {
        return CandidateApprovalResultData::from_error(
            "cannot serialize candidate approval receipt",
        );
    };

    if let Err(e) = write_mode_exclusive_atomic(
        &result_receipt,
        receipt_json.as_bytes(),
        0o444,
        K_MAXIMUM_APPROVAL_BYTES,
    ) {
        return CandidateApprovalResultData::from_error(e);
    }

    CandidateApprovalResultData {
        generation,
        receipt: result_receipt,
        profile: result_profile,
        compatibility_manifest: result_compat,
        error: String::new(),
    }
}

/// Validates immutable `0444` Tier-C approval artifacts referenced by an activation manifest.
pub(crate) fn validate_candidate_approval(
    store_root: &Path,
    activation_json: &str,
    payload: &MocktailRustPayloadInfo,
) -> Result<CandidateApprovalResultData, String> {
    let refs = parse_candidate_activation_json(activation_json, &payload.payload_id)
        .map_err(str::to_string)?;

    let receipt_path = validate_relative_approval_path(
        store_root,
        Path::new(&refs.approval_ref),
        "approvals",
        &payload.payload_id,
        &refs.generation,
    )?;
    let profile_path = validate_relative_approval_path(
        store_root,
        Path::new(&refs.profile_ref),
        "host_abi_profiles",
        &payload.payload_id,
        &refs.generation,
    )?;
    let compat_path = validate_relative_approval_path(
        store_root,
        Path::new(&refs.compatibility_ref),
        "compatibility_profiles",
        &payload.payload_id,
        &refs.generation,
    )?;

    let receipt_bytes = read_approval_artifact(&receipt_path, true)?;
    let profile_bytes = read_approval_artifact(&profile_path, true)?;
    let compatibility_bytes = read_approval_artifact(&compat_path, true)?;

    validate_approval_binding_bytes(
        &profile_bytes,
        &compatibility_bytes,
        &payload.payload_id,
        &payload.build_id,
        &payload.library_sha256,
        &payload.version_name,
        payload.version_code,
    )
    .map_err(str::to_string)?;

    let payload_dir = store_root.join("payloads").join(&payload.payload_id);
    let fingerprint = payload_runtime_fingerprint(&payload_dir, payload)?;
    let profile_sha256 = sha256_bytes_hex(&profile_bytes);
    let compatibility_sha256 = sha256_bytes_hex(&compatibility_bytes);

    let canonical_library = fs::canonicalize(payload_dir.join("libroblox.so"))
        .map_err(|_| "cannot canonicalize approved payload library".to_string())?;

    let canary1_path = store_root
        .join("approvals")
        .join(format!("{}-{}.canary-1.json", payload.payload_id, refs.generation));
    let canary2_path = store_root
        .join("approvals")
        .join(format!("{}-{}.canary-2.json", payload.payload_id, refs.generation));
    let canary1_bytes = read_approval_artifact(&canary1_path, true)?;
    let canary2_bytes = read_approval_artifact(&canary2_path, true)?;

    let receipt_str = std::str::from_utf8(&receipt_bytes)
        .map_err(|_| "approval artifact is not a JSON object".to_string())?;
    let canary1_str = std::str::from_utf8(&canary1_bytes)
        .map_err(|_| "approval artifact is not a JSON object".to_string())?;
    let canary2_str = std::str::from_utf8(&canary2_bytes)
        .map_err(|_| "approval artifact is not a JSON object".to_string())?;
    let canonical_str = canonical_library.to_string_lossy();

    verify_candidate_evidence_json(&CandidateEvidenceParams {
        payload_id: &payload.payload_id,
        generation: &refs.generation,
        canonical_library_path: &canonical_str,
        elf_build_id: &payload.build_id,
        library_sha256: &payload.library_sha256,
        fingerprint: &fingerprint,
        profile_sha256: &profile_sha256,
        compatibility_sha256: &compatibility_sha256,
        receipt_str,
        canary1_str,
        canary2_str,
    })
    .map_err(str::to_string)?;

    Ok(CandidateApprovalResultData {
        generation: refs.generation,
        receipt: receipt_path,
        profile: profile_path,
        compatibility_manifest: compat_path,
        error: String::new(),
    })
}

// ============================================================================
// C ABI Entry Points
// ============================================================================

#[repr(C)]
pub struct MocktailRustCandidateApprovalOptionsView {
    pub store_root: MocktailRustStrSlice,
    pub payload_directory: MocktailRustStrSlice,
    pub profile: MocktailRustStrSlice,
    pub compatibility_manifest: MocktailRustStrSlice,
    pub runtime_binary: MocktailRustStrSlice,
    pub canary_log_0: MocktailRustStrSlice,
    pub canary_log_1: MocktailRustStrSlice,
}

unsafe fn payload_info_from_ffi(data: *const MocktailRustPayloadInfoData) -> MocktailRustPayloadInfo {
    if data.is_null() {
        return MocktailRustPayloadInfo {
            package_name: String::new(),
            version_name: String::new(),
            version_code: 0,
            build_id: String::new(),
            library_sha256: String::new(),
            base_apk_sha256: String::new(),
            split_apk_sha256: String::new(),
            asset_file_count: 0,
            asset_tree_sha256: String::new(),
            payload_id: String::new(),
        };
    }
    let d = &*data;
    let slice = |ptr: *const c_char, len: usize| {
        slice_to_str_lossy(MocktailRustStrSlice { ptr, len })
    };
    MocktailRustPayloadInfo {
        package_name: slice(d.package_name, d.package_name_len),
        version_name: slice(d.version_name, d.version_name_len),
        version_code: d.version_code,
        build_id: slice(d.build_id, d.build_id_len),
        library_sha256: slice(d.library_sha256, d.library_sha256_len),
        base_apk_sha256: slice(d.base_apk_sha256, d.base_apk_sha256_len),
        split_apk_sha256: slice(d.split_apk_sha256, d.split_apk_sha256_len),
        asset_file_count: d.asset_file_count,
        asset_tree_sha256: slice(d.asset_tree_sha256, d.asset_tree_sha256_len),
        payload_id: slice(d.payload_id, d.payload_id_len),
    }
}

fn emit_approval_result(
    res: &CandidateApprovalResultData,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustCandidateApprovalData),
    >,
    ctx: *mut c_void,
) {
    let Some(cb) = on_result else {
        return;
    };
    let gen_slice = MocktailRustStrSlice::from_str(&res.generation);
    let profile_slice = path_to_slice(&res.profile);
    let compat_slice = path_to_slice(&res.compatibility_manifest);
    let receipt_slice = path_to_slice(&res.receipt);
    let err_slice = MocktailRustStrSlice::from_str(&res.error);
    let ffi = MocktailRustCandidateApprovalData {
        generation: gen_slice.ptr,
        generation_len: gen_slice.len,
        profile: profile_slice.ptr,
        profile_len: profile_slice.len,
        compatibility_manifest: compat_slice.ptr,
        compatibility_manifest_len: compat_slice.len,
        receipt: receipt_slice.ptr,
        receipt_len: receipt_slice.len,
        error: err_slice.ptr,
        error_len: err_slice.len,
    };
    unsafe { cb(ctx, &ffi) };
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_compute_fingerprint(
    payload_directory: MocktailRustStrSlice,
    payload: *const MocktailRustPayloadInfoData,
    on_result: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            fingerprint: MocktailRustStrSlice,
            error: MocktailRustStrSlice,
        ),
    >,
    ctx: *mut c_void,
) -> c_int {
    let dir = slice_to_pathbuf(payload_directory);
    let info = payload_info_from_ffi(payload);
    match payload_runtime_fingerprint(&dir, &info) {
        Ok(fp) => {
            if let Some(cb) = on_result {
                cb(
                    ctx,
                    MocktailRustStrSlice::from_str(&fp),
                    MocktailRustStrSlice::from_str(""),
                );
            }
            0
        }
        Err(err) => {
            if let Some(cb) = on_result {
                cb(
                    ctx,
                    MocktailRustStrSlice::from_str(""),
                    MocktailRustStrSlice::from_str(&err),
                );
            }
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_create(
    options: *const MocktailRustCandidateApprovalOptionsView,
    verified_payload: *const MocktailRustPayloadInfoData,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustCandidateApprovalData),
    >,
    ctx: *mut c_void,
) {
    if options.is_null() {
        emit_approval_result(
            &CandidateApprovalResultData::from_error("invalid candidate approval options"),
            on_result,
            ctx,
        );
        return;
    }
    let opt = &*options;
    let parsed_opts = CandidateApprovalOptionsData {
        store_root: slice_to_pathbuf(opt.store_root),
        payload_directory: slice_to_pathbuf(opt.payload_directory),
        profile: slice_to_pathbuf(opt.profile),
        compatibility_manifest: slice_to_pathbuf(opt.compatibility_manifest),
        runtime_binary: slice_to_pathbuf(opt.runtime_binary),
        canary_logs: [
            slice_to_pathbuf(opt.canary_log_0),
            slice_to_pathbuf(opt.canary_log_1),
        ],
    };
    let info = payload_info_from_ffi(verified_payload);
    let res = create_candidate_approval(&parsed_opts, &info);
    emit_approval_result(&res, on_result, ctx);
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_candidate_approval_validate(
    store_root: MocktailRustStrSlice,
    activation_json: MocktailRustStrSlice,
    payload: *const MocktailRustPayloadInfoData,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustCandidateApprovalData),
    >,
    ctx: *mut c_void,
) -> bool {
    let root = slice_to_pathbuf(store_root);
    let json = slice_to_str_lossy(activation_json);
    let info = payload_info_from_ffi(payload);
    match validate_candidate_approval(&root, &json, &info) {
        Ok(res) => {
            emit_approval_result(&res, on_result, ctx);
            true
        }
        Err(err) => {
            emit_approval_result(&CandidateApprovalResultData::from_error(err), on_result, ctx);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mocktail_cand_approval_{}_{}_{}",
                label,
                current_pid(),
                crate::unix_ipc::monotonic_nanos_now()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            fn make_writable(dir: &Path) {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir() {
                            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o755));
                            make_writable(&p);
                        } else {
                            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o644));
                        }
                    }
                }
            }
            make_writable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup_fixture(root: &Path) -> (CandidateApprovalOptionsData, MocktailRustPayloadInfo) {
        let build_id = "a6c1f5c57f9d7aa3fb99a5fa30565e07e5c88f6a".to_string();
        let payload_id = format!("2814-{}", build_id);
        let store_root = root.join("store");
        let payload_dir = store_root.join("payloads").join(&payload_id);
        fs::create_dir_all(payload_dir.join("sober_apk")).unwrap();
        fs::create_dir_all(payload_dir.join("assets")).unwrap();
        fs::write(payload_dir.join("libroblox.so"), b"libroblox-bytes").unwrap();
        fs::write(payload_dir.join("sober_apk/base.apk"), b"base-bytes").unwrap();
        fs::write(
            payload_dir.join("sober_apk/split_config.x86_64.apk"),
            b"split-bytes",
        )
        .unwrap();
        fs::write(payload_dir.join("roblox_payload.json"), b"{\"schema_version\":1}\n").unwrap();

        let lib_sha = sha256_bytes_hex(b"libroblox-bytes");
        let base_sha = sha256_bytes_hex(b"base-bytes");
        let split_sha = sha256_bytes_hex(b"split-bytes");
        let asset_sha = sha256_bytes_hex(b"assets");

        let info = MocktailRustPayloadInfo {
            package_name: "com.roblox.client".to_string(),
            version_name: "2.732.1043".to_string(),
            version_code: 2814,
            build_id: build_id.clone(),
            library_sha256: lib_sha.clone(),
            base_apk_sha256: base_sha,
            split_apk_sha256: split_sha,
            asset_file_count: 1,
            asset_tree_sha256: asset_sha,
            payload_id: payload_id.clone(),
        };

        let profile_path = root.join("candidate.json");
        let profile_json = serde_json::json!({
            "schema_version": 1,
            "elf_build_id": build_id,
            "payload_sha256": lib_sha,
            "payload_id": payload_id,
            "payload_path": format!("payloads/{}", payload_id),
            "reference": {
                "elf_build_id": "1686400865ae0e408cd7bd67de7a439625c6fd13",
                "payload_sha256": "3e9c26c81186f93458ff65d8a8bc240c220974db02b8388b91340b77b336997d"
            },
            "profile": {
                "elf_build_id": build_id
            }
        });
        fs::write(&profile_path, serde_json::to_string_pretty(&profile_json).unwrap()).unwrap();

        let compat_path = root.join("compat.json");
        let compat_json = serde_json::json!({
            "schema_version": 1,
            "profiles": [{
                "version_name": "2.732.1043",
                "version_code": 2814,
                "elf_build_id": build_id,
                "status": "experimental",
                "default_allowed": true,
                "allow_legacy_binary_patches": false,
                "allow_host_abi_bridges": true,
                "allow_host_constructor_replay": true
            }]
        });
        fs::write(&compat_path, serde_json::to_string_pretty(&compat_json).unwrap()).unwrap();

        let log0 = root.join("canary-1.log");
        let log1 = root.join("canary-2.log");
        fs::write(&log0, b"canary pass 1\n").unwrap();
        fs::write(&log1, b"canary pass 2\n").unwrap();

        let opts = CandidateApprovalOptionsData {
            store_root,
            payload_directory: payload_dir,
            profile: profile_path,
            compatibility_manifest: compat_path,
            runtime_binary: PathBuf::from("/proc/self/exe"),
            canary_logs: [log0, log1],
        };
        (opts, info)
    }

    #[test]
    fn create_and_validate_candidate_approval_roundtrip_and_guards() {
        let tmp = TempDirGuard::new("roundtrip");
        let (opts, info) = setup_fixture(&tmp.0);

        let created = create_candidate_approval(&opts, &info);
        assert!(created.error.is_empty(), "unexpected error: {}", created.error);
        assert_eq!(created.generation.len(), 40);
        assert_eq!(
            fs::metadata(&created.receipt).unwrap().permissions().mode() & 0o777,
            0o444
        );

        let activation = serde_json::json!({
            "approval_path": format!("approvals/{}-{}.json", info.payload_id, created.generation),
            "host_abi_profile_path": format!("host_abi_profiles/{}-{}.json", info.payload_id, created.generation),
            "compatibility_manifest_path": format!("compatibility_profiles/{}-{}.json", info.payload_id, created.generation),
        })
        .to_string();

        let validated = validate_candidate_approval(&opts.store_root, &activation, &info)
            .expect("validate_candidate_approval failed");
        assert_eq!(validated.generation, created.generation);

        // Idempotent re-creation when profile/compat match
        let log_a = opts.canary_logs[0].clone();
        let mut opts_dup = opts.clone();
        opts_dup.canary_logs[1] = log_a;
        let dup_err = create_candidate_approval(&opts_dup, &info);
        assert_eq!(
            dup_err.error,
            "candidate approval requires two distinct canary logs"
        );

        // Writable receipt must be rejected
        fs::set_permissions(&created.receipt, fs::Permissions::from_mode(0o644)).unwrap();
        let writable_err = validate_candidate_approval(&opts.store_root, &activation, &info)
            .unwrap_err();
        assert_eq!(
            writable_err,
            "approval artifact ownership or permissions are invalid"
        );

        // Collision on pre-existing profile with different content
        fs::set_permissions(&created.profile, fs::Permissions::from_mode(0o644)).unwrap();
        let mut altered_profile = fs::read(&opts.profile).unwrap();
        altered_profile.extend_from_slice(b" ");
        fs::write(&created.profile, altered_profile).unwrap();
        fs::set_permissions(&created.profile, fs::Permissions::from_mode(0o444)).unwrap();
        let mut err_buf = None;
        let _ = write_mode_exclusive_atomic(
            &created.profile,
            &fs::read(&opts.profile).unwrap(),
            0o444,
            K_MAXIMUM_APPROVAL_BYTES,
        )
        .map_err(|e| err_buf = Some(e));
        assert_eq!(
            err_buf.as_deref(),
            Some("immutable approval generation collision")
        );
    }
}
