use std::collections::BTreeSet;
use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};

use crate::elf_reader::{
    cstr_slice_at, parse_elf64_header, parse_elf64_shdrs, read_u16_le, read_u32_le, ELFCLASS64,
    ELFDATA2LSB, SHT_DYNSYM,
};
use crate::unix_ipc::{
    format_utc_iso8601_now, hard_link_or_copy_regular_bounded, path_to_slice,
    read_regular_file_limited, slice_to_opt_str, slice_to_pathbuf, slice_to_str_lossy,
    write_private_trunc_file_checked, MappedReadOnlyFile, ReadFileError, WritePrivateError,
};
use crate::update_json::{
    build_apk_payload_metadata_json, parse_trusted_certificates_internal, ApkPayloadMetadataParams,
    MocktailRustStrSlice,
};
use crate::{
    guest_abi, host_guest_abi, internal_inspect_payload, parse_android_manifest_bytes,
    parse_elf_build_id_bytes, sha256_regular_file_strict, zip_extract_entry_file,
    zip_extract_prefix_dir, zip_list_entries_path, zip_read_entry_bytes, ParsedAndroidManifest,
};

const K_MAXIMUM_APK_BYTES: usize = 1024 * 1024 * 1024;
const K_MAXIMUM_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const K_MAXIMUM_ASSET_BYTES: usize = 2 * 1024 * 1024 * 1024;
const K_MAXIMUM_CANDIDATES: usize = 64;
const K_MAXIMUM_ZIP_ENTRIES: usize = 100_000;

const K_REQUIRED_EXPORTS: [&str; 7] = [
    "JNI_OnLoad",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeGameGlobalInit",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeUpdateAdapterInit",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2InitWithParams",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeStartLuaAppDM",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2StartAppWithParams",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams",
];

#[derive(Debug, Default, Clone)]
pub(crate) struct ExpectedPayloadIdentityData {
    pub version_name: String,
    pub version_code: u64,
    pub exact_build_id: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PreparedPayloadData {
    pub directory: PathBuf,
    pub payload_id: String,
    pub version_name: String,
    pub version_code: u64,
    pub build_id: String,
    pub error: String,
}

impl PreparedPayloadData {
    fn from_error(err: impl Into<String>) -> Self {
        Self {
            error: err.into(),
            ..Self::default()
        }
    }
}

pub(crate) trait ApkSignatureVerifier {
    fn verify_apk_signature(&self, apk_path: &Path) -> Result<Vec<String>, String>;
}

struct ApkCandidate {
    path: PathBuf,
    identity: ParsedAndroidManifest,
    has_guest_library: bool,
    has_assets: bool,
}

fn guest_lib_entry_name() -> String {
    format!("lib/{}/libroblox.so", host_guest_abi())
}

fn read_regular_bounded_str(path: &Path) -> Result<String, String> {
    let bytes = read_regular_file_limited(path, K_MAXIMUM_MANIFEST_BYTES, false, true).map_err(
        |err| match err {
            ReadFileError::NotFound | ReadFileError::OpenFailed(_) => {
                format!("cannot open regular file: {}", path.display())
            }
            ReadFileError::InvalidFile => {
                format!("file exceeds its size limit: {}", path.display())
            }
            ReadFileError::ReadFailed => format!("cannot read regular file: {}", path.display()),
        },
    )?;
    String::from_utf8(bytes).map_err(|_| format!("cannot read regular file: {}", path.display()))
}

fn write_private_metadata(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    write_private_trunc_file_checked(path, bytes).map_err(|err| match err {
        WritePrivateError::OpenFailed => "cannot create payload metadata",
        WritePrivateError::WriteFailed => "cannot write payload metadata",
        WritePrivateError::SyncFailed => "cannot persist payload metadata",
    })
}

fn collect_candidates(archives: &[PathBuf], directory: &Path) -> Result<Vec<PathBuf>, String> {
    if fs::create_dir_all(directory).is_err() {
        return Err("cannot create APK candidate directory".to_string());
    }
    let mut candidate_number = 0usize;
    let mut candidates = Vec::new();
    for archive in archives {
        let entries = zip_list_entries_path(archive, K_MAXIMUM_ZIP_ENTRIES).map_err(|(_, e)| e)?;
        if entries.iter().any(|e| e.name == "AndroidManifest.xml") {
            candidate_number += 1;
            if candidate_number > K_MAXIMUM_CANDIDATES {
                return Err("provider produced too many APK candidates".to_string());
            }
            let destination = directory.join(format!("candidate-{}.apk", candidate_number));
            hard_link_or_copy_regular_bounded(archive, &destination, K_MAXIMUM_APK_BYTES as u64)?;
            candidates.push(destination);
            continue;
        }
        for entry in entries {
            if entry.directory || !entry.name.ends_with(".apk") {
                continue;
            }
            candidate_number += 1;
            if candidate_number > K_MAXIMUM_CANDIDATES
                || entry.uncompressed_size > K_MAXIMUM_APK_BYTES as u64
            {
                return Err("provider bundle has excessive APK candidates".to_string());
            }
            let destination = directory.join(format!("candidate-{}.apk", candidate_number));
            zip_extract_entry_file(archive, &entry.name, &destination, K_MAXIMUM_APK_BYTES)
                .map_err(|(_, e)| e)?;
            candidates.push(destination);
        }
    }
    if candidates.is_empty() {
        return Err("provider output contains no APK candidates".to_string());
    }
    Ok(candidates)
}

fn inspect_candidates(
    paths: &[PathBuf],
    expected: &ExpectedPayloadIdentityData,
) -> Result<Vec<ApkCandidate>, &'static str> {
    let guest_entry = guest_lib_entry_name();
    let mut candidates = Vec::new();
    for path in paths {
        let Ok(entries) = zip_list_entries_path(path, K_MAXIMUM_ZIP_ENTRIES) else {
            continue;
        };
        let Ok(manifest_bytes) =
            zip_read_entry_bytes(path, "AndroidManifest.xml", K_MAXIMUM_MANIFEST_BYTES)
        else {
            continue;
        };
        let Ok(identity) = parse_android_manifest_bytes(&manifest_bytes) else {
            continue;
        };
        if identity.package_name != "com.roblox.client"
            || identity.version_code != expected.version_code
            || (identity.version_name != expected.version_name
                && !(identity.version_name.is_empty() && !identity.split_name.is_empty()))
        {
            continue;
        }
        let has_guest_library = entries.iter().any(|e| e.name == guest_entry);
        let has_assets = entries
            .iter()
            .any(|e| e.name.len() > 7 && e.name.starts_with("assets/"));
        candidates.push(ApkCandidate {
            path: path.clone(),
            identity,
            has_guest_library,
            has_assets,
        });
    }
    if candidates.is_empty() {
        return Err("no APK matches the requested Roblox version");
    }
    Ok(candidates)
}

fn trusted_certificates(manifest: &Path) -> Result<BTreeSet<String>, String> {
    let contents = read_regular_bounded_str(manifest)?;
    parse_trusted_certificates_internal(&contents).map_err(str::to_string)
}

fn common_trusted_certificates(
    base: &Path,
    split: &Path,
    signing_trust_manifest: &Path,
    verifier: &dyn ApkSignatureVerifier,
) -> Result<Vec<String>, String> {
    let trusted = trusted_certificates(signing_trust_manifest)?;
    let base_certs = verifier
        .verify_apk_signature(base)
        .map_err(|e| format!("base APK signature: {}", e))?;
    let split_certs = if base == split {
        base_certs.clone()
    } else {
        verifier
            .verify_apk_signature(split)
            .map_err(|e| format!("{} APK signature: {}", host_guest_abi(), e))?
    };

    let accepted: Vec<String> = base_certs
        .into_iter()
        .filter(|cert| trusted.contains(cert) && split_certs.contains(cert))
        .collect();
    if accepted.is_empty() {
        return Err("APK pair has no common trusted Roblox signing certificate".to_string());
    }
    Ok(accepted)
}

/// Validates an ELF64 guest `libroblox.so` (header architecture, `.note.android.ident`,
/// 7 required `SHT_DYNSYM` JNI exports, and 20-byte GNU Build-ID) without `libelf`.
pub(crate) fn validate_elf64_guest_so_bytes(bytes: &[u8]) -> Result<String, String> {
    let Some(hdr) = parse_elf64_header(bytes) else {
        return Err("extracted libroblox.so is not ELF".to_string());
    };
    if hdr.ei_class != ELFCLASS64 || hdr.ei_data != ELFDATA2LSB {
        return Err("extracted libroblox.so is not ELF".to_string());
    }
    if hdr.e_machine != guest_abi::ELF_MACHINE {
        return Err(format!("libroblox.so is not a {} ELF", host_guest_abi()));
    }

    let shdrs = parse_elf64_shdrs(bytes, &hdr, false).map_err(|err| match err {
        crate::elf_reader::ShdrError::TableInvalid => "cannot inspect libroblox.so sections",
        crate::elf_reader::ShdrError::SectionOutOfBounds => "cannot inspect libroblox.so section",
    })?;
    let shstrndx = usize::try_from(if hdr.raw_shstrndx == crate::elf_reader::SHN_XINDEX {
        read_u32_le(bytes, hdr.e_shoff + 40).unwrap_or(u32::MAX) as usize
    } else {
        hdr.raw_shstrndx as usize
    })
    .unwrap_or(usize::MAX);
    let shstr_sec = shdrs
        .get(shstrndx)
        .ok_or_else(|| "cannot inspect libroblox.so sections".to_string())?;
    let shstrtab = &bytes[shstr_sec.sh_offset as usize..(shstr_sec.sh_offset + shstr_sec.sh_size) as usize];

    let mut has_android_ident = false;
    let mut found_exports = [false; 7];

    for sec in &shdrs {
        if let Some(sec_name) = cstr_slice_at(shstrtab, sec.sh_name as usize) {
            if sec_name == b".note.android.ident" {
                has_android_ident = true;
            }
        }
        if sec.sh_type == SHT_DYNSYM {
            let sym_entsize = if sec.sh_entsize == 0 {
                24
            } else {
                sec.sh_entsize as usize
            };
            let str_sec = shdrs
                .get(sec.sh_link as usize)
                .filter(|_| sym_entsize >= 24)
                .ok_or_else(|| "cannot inspect libroblox.so section".to_string())?;
            let strtab =
                &bytes[str_sec.sh_offset as usize..(str_sec.sh_offset + str_sec.sh_size) as usize];
            let sh_off = sec.sh_offset as usize;
            let count = sec.sh_size as usize / sym_entsize;
            for sym_idx in 0..count {
                let sym_base = sh_off + sym_idx * sym_entsize;
                let st_name = read_u32_le(bytes, sym_base).unwrap_or(0);
                let st_shndx = read_u16_le(bytes, sym_base + 6).unwrap_or(0);
                if st_name == 0 || st_shndx == 0 {
                    continue;
                }
                if let Some(sym_name) = cstr_slice_at(strtab, st_name as usize) {
                    for (exp_idx, required) in K_REQUIRED_EXPORTS.iter().enumerate() {
                        if !found_exports[exp_idx] && sym_name == required.as_bytes() {
                            found_exports[exp_idx] = true;
                        }
                    }
                }
            }
        }
    }

    if !has_android_ident {
        return Err("libroblox.so has no Android identity note".to_string());
    }
    for (exp_idx, required) in K_REQUIRED_EXPORTS.iter().enumerate() {
        if !found_exports[exp_idx] {
            return Err(format!("libroblox.so is missing required export: {}", required));
        }
    }

    let Some(build_id) = parse_elf_build_id_bytes(bytes) else {
        return Err("ELF GNU Build ID note is missing".to_string());
    };
    if build_id.len() != 40 {
        return Err("libroblox.so Build ID is not 20 bytes".to_string());
    }
    Ok(build_id)
}

fn validate_elf_file(path: &Path) -> Result<String, String> {
    let mapped =
        MappedReadOnlyFile::open(path).map_err(|_| "cannot open extracted libroblox.so".to_string())?;
    validate_elf64_guest_so_bytes(mapped.as_slice())
}

/// Validates, extracts, hashes, and prepares an immutable Roblox APK bundle inside an empty `workspace`.
pub(crate) fn prepare_payload_from_archives(
    archives: &[PathBuf],
    expected: &ExpectedPayloadIdentityData,
    signing_trust_manifest: &Path,
    workspace: &Path,
    source: &str,
    verifier: &dyn ApkSignatureVerifier,
) -> PreparedPayloadData {
    if archives.is_empty() {
        return PreparedPayloadData::from_error("provider returned no archives");
    }
    if fs::create_dir_all(workspace).is_err()
        || fs::read_dir(workspace)
            .map(|mut it| it.next().is_some())
            .unwrap_or(true)
    {
        return PreparedPayloadData::from_error("payload preparation workspace must be empty");
    }

    let candidate_paths = match collect_candidates(archives, &workspace.join("candidates")) {
        Ok(paths) => paths,
        Err(err) => return PreparedPayloadData::from_error(err),
    };
    let candidates = match inspect_candidates(&candidate_paths, expected) {
        Ok(c) => c,
        Err(err) => return PreparedPayloadData::from_error(err),
    };

    let base = candidates
        .iter()
        .find(|c| c.identity.split_name.is_empty() && c.has_assets);
    let split = candidates.iter().find(|c| {
        c.has_guest_library
            && (c.identity.split_name == guest_abi::SPLIT_NAME || c.identity.split_name.is_empty())
    });
    let (Some(base), Some(split)) = (base, split) else {
        return PreparedPayloadData::from_error(format!(
            "no matching Roblox base and {} APK pair was found",
            host_guest_abi()
        ));
    };

    let accepted = match common_trusted_certificates(
        &base.path,
        &split.path,
        signing_trust_manifest,
        verifier,
    ) {
        Ok(certs) => certs,
        Err(err) => return PreparedPayloadData::from_error(err),
    };

    let prepared = workspace.join("prepared");
    let sober_apk_dir = prepared.join("sober_apk");
    let base_dest = sober_apk_dir.join("base.apk");
    let split_dest = sober_apk_dir.join(guest_abi::SPLIT_APK_FILE);

    if let Err(err) = fs::create_dir_all(&sober_apk_dir)
        .map_err(|_| "cannot create prepared payload".to_string())
        .and_then(|_| {
            hard_link_or_copy_regular_bounded(&base.path, &base_dest, K_MAXIMUM_APK_BYTES as u64)
                .map_err(str::to_string)
        })
        .and_then(|_| {
            hard_link_or_copy_regular_bounded(&split.path, &split_dest, K_MAXIMUM_APK_BYTES as u64)
                .map_err(str::to_string)
        })
    {
        return PreparedPayloadData::from_error(err);
    }

    if let Err((_, err)) = zip_extract_entry_file(
        &split.path,
        &guest_lib_entry_name(),
        &prepared.join("libroblox.so"),
        K_MAXIMUM_APK_BYTES,
    ) {
        return PreparedPayloadData::from_error(err);
    }

    let asset_count = match zip_extract_prefix_dir(
        &base.path,
        "assets/",
        &prepared.join("assets"),
        K_MAXIMUM_ASSET_BYTES,
    ) {
        Ok(0) => return PreparedPayloadData::from_error("base APK contains no assets"),
        Ok(n) => n,
        Err((_, err)) => return PreparedPayloadData::from_error(err),
    };

    let build_id = match validate_elf_file(&prepared.join("libroblox.so")) {
        Ok(id) => id,
        Err(err) => return PreparedPayloadData::from_error(err),
    };

    if let Some(ref exact) = expected.exact_build_id {
        if &build_id != exact {
            return PreparedPayloadData::from_error(
                "downloaded Roblox Build ID is not exact-supported",
            );
        }
    }

    let (asset_tree_hash, asset_count_verified) =
        match crate::hash_asset_tree_dir(&prepared.join("assets")) {
            Ok((hash, count)) if count == asset_count => (hash, count),
            Ok(_) => {
                return PreparedPayloadData::from_error(
                    "extracted asset count does not match prepared tree",
                )
            }
            Err((_, err)) => return PreparedPayloadData::from_error(err),
        };

    let library_hash = match sha256_regular_file_strict(&prepared.join("libroblox.so"), None) {
        Ok(h) => h,
        Err(e) => return PreparedPayloadData::from_error(e),
    };
    let base_hash = match sha256_regular_file_strict(&base_dest, None) {
        Ok(h) => h,
        Err(e) => return PreparedPayloadData::from_error(e),
    };
    let split_hash = match sha256_regular_file_strict(&split_dest, None) {
        Ok(h) => h,
        Err(e) => return PreparedPayloadData::from_error(e),
    };

    let cert_refs: Vec<&str> = accepted.iter().map(String::as_str).collect();
    let imported_at = format_utc_iso8601_now();
    let Some(serialized_metadata) = build_apk_payload_metadata_json(&ApkPayloadMetadataParams {
        version_name: &expected.version_name,
        version_code: expected.version_code,
        abi: host_guest_abi(),
        elf_build_id: &build_id,
        library_sha256: &library_hash,
        base_apk_sha256: &base_hash,
        split_apk_hash_key: guest_abi::SPLIT_APK_HASH_KEY,
        split_apk_sha256: &split_hash,
        signing_certs: &cert_refs,
        asset_file_count: asset_count_verified,
        asset_tree_sha256: &asset_tree_hash,
        source,
        imported_at: &imported_at,
        exact_supported: expected.exact_build_id.is_some(),
        monolithic: base.path == split.path,
    }) else {
        return PreparedPayloadData::from_error("cannot serialize payload metadata");
    };

    if let Err(err) = write_private_metadata(
        &prepared.join("roblox_payload.json"),
        serialized_metadata.as_bytes(),
    ) {
        return PreparedPayloadData::from_error(err);
    }

    let expected_payload_id = format!("{}-{}", expected.version_code, build_id);
    let verified = match internal_inspect_payload(&prepared) {
        Ok(v) => v,
        Err(err) => return PreparedPayloadData::from_error(err),
    };
    if verified.payload_id != expected_payload_id {
        return PreparedPayloadData::from_error("prepared payload identity changed");
    }

    PreparedPayloadData {
        directory: prepared,
        payload_id: expected_payload_id,
        version_name: expected.version_name.clone(),
        version_code: expected.version_code,
        build_id,
        error: String::new(),
    }
}

// ============================================================================
// C ABI Entry Points
// ============================================================================

#[repr(C)]
pub struct MocktailRustExpectedPayloadIdentityView {
    pub version_name: MocktailRustStrSlice,
    pub version_code: u64,
    pub has_exact_build_id: bool,
    pub exact_build_id: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustPreparedPayloadView {
    pub directory: MocktailRustStrSlice,
    pub payload_id: MocktailRustStrSlice,
    pub version_name: MocktailRustStrSlice,
    pub version_code: u64,
    pub build_id: MocktailRustStrSlice,
    pub error: MocktailRustStrSlice,
}

pub type MocktailRustVerifyApkSignatureFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        apk_path: MocktailRustStrSlice,
        emit_cert: Option<
            unsafe extern "C" fn(receiver_ctx: *mut c_void, cert_sha256: MocktailRustStrSlice),
        >,
        receiver_ctx: *mut c_void,
        set_error: Option<
            unsafe extern "C" fn(receiver_ctx: *mut c_void, error: MocktailRustStrSlice),
        >,
    ) -> bool,
>;

struct CallbackApkSignatureVerifier {
    cb: MocktailRustVerifyApkSignatureFn,
    ctx: *mut c_void,
}

impl ApkSignatureVerifier for CallbackApkSignatureVerifier {
    fn verify_apk_signature(&self, apk_path: &Path) -> Result<Vec<String>, String> {
        let Some(cb) = self.cb else {
            return Err("APK signature verifier is unavailable".to_string());
        };
        struct State {
            certs: Vec<String>,
            error: String,
        }
        unsafe extern "C" fn emit_cert(raw: *mut c_void, cert: MocktailRustStrSlice) {
            if !raw.is_null() {
                (*raw.cast::<State>())
                    .certs
                    .push(slice_to_str_lossy(cert));
            }
        }
        unsafe extern "C" fn set_error(raw: *mut c_void, err: MocktailRustStrSlice) {
            if !raw.is_null() {
                (*raw.cast::<State>()).error = slice_to_str_lossy(err);
            }
        }
        let mut state = State {
            certs: Vec::new(),
            error: String::new(),
        };
        let ok = unsafe {
            cb(
                self.ctx,
                path_to_slice(apk_path),
                Some(emit_cert),
                (&raw mut state).cast::<c_void>(),
                Some(set_error),
            )
        };
        if !ok {
            return Err(if state.error.is_empty() {
                "APK signature verification failed".to_string()
            } else {
                state.error
            });
        }
        Ok(state.certs)
    }
}

fn emit_prepared_payload(
    res: &PreparedPayloadData,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustPreparedPayloadView),
    >,
    ctx: *mut c_void,
) {
    let Some(cb) = on_result else {
        return;
    };
    let ffi = MocktailRustPreparedPayloadView {
        directory: path_to_slice(&res.directory),
        payload_id: MocktailRustStrSlice::from_str(&res.payload_id),
        version_name: MocktailRustStrSlice::from_str(&res.version_name),
        version_code: res.version_code,
        build_id: MocktailRustStrSlice::from_str(&res.build_id),
        error: MocktailRustStrSlice::from_str(&res.error),
    };
    unsafe { cb(ctx, &ffi) };
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_apk_prepare_payload_from_archives(
    archives_ptr: *const MocktailRustStrSlice,
    archives_len: usize,
    expected: *const MocktailRustExpectedPayloadIdentityView,
    signing_trust_manifest: MocktailRustStrSlice,
    workspace: MocktailRustStrSlice,
    source: MocktailRustStrSlice,
    verify_signature: MocktailRustVerifyApkSignatureFn,
    verify_ctx: *mut c_void,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustPreparedPayloadView),
    >,
    ctx: *mut c_void,
) {
    if expected.is_null() {
        emit_prepared_payload(
            &PreparedPayloadData::from_error("invalid expected payload identity"),
            on_result,
            ctx,
        );
        return;
    }
    let exp = &*expected;
    let parsed_expected = ExpectedPayloadIdentityData {
        version_name: slice_to_str_lossy(exp.version_name),
        version_code: exp.version_code,
        exact_build_id: if exp.has_exact_build_id {
            Some(slice_to_opt_str(exp.exact_build_id).unwrap_or_default())
        } else {
            None
        },
    };
    let archives: Vec<PathBuf> = if archives_ptr.is_null() || archives_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(archives_ptr, archives_len)
            .iter()
            .copied()
            .map(|s| slice_to_pathbuf(s))
            .collect()
    };
    let verifier = CallbackApkSignatureVerifier {
        cb: verify_signature,
        ctx: verify_ctx,
    };
    let res = prepare_payload_from_archives(
        &archives,
        &parsed_expected,
        &slice_to_pathbuf(signing_trust_manifest),
        &slice_to_pathbuf(workspace),
        &slice_to_str_lossy(source),
        &verifier,
    );
    emit_prepared_payload(&res, on_result, ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    const TEST_CERT_SHA: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct TempDirGuard(PathBuf);
    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mocktail_apk_bundle_{}_{}_{}",
                label,
                crate::unix_ipc::current_pid(),
                crate::unix_ipc::monotonic_nanos_now()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct StubVerifier(Result<Vec<String>, String>);
    impl ApkSignatureVerifier for StubVerifier {
        fn verify_apk_signature(&self, _apk_path: &Path) -> Result<Vec<String>, String> {
            self.0.clone()
        }
    }

    fn build_axml_manifest(
        package: &str,
        version_name: Option<&str>,
        version_code: u32,
        split_name: Option<&str>,
    ) -> Vec<u8> {
        let mut strings: Vec<&str> = vec!["manifest", "package", package, "versionCode"];
        let vn_idx = version_name.map(|v| {
            let n = strings.len();
            strings.push("versionName");
            strings.push(v);
            n
        });
        let sp_idx = split_name.map(|s| {
            let n = strings.len();
            strings.push("split");
            strings.push(s);
            n
        });

        let mut string_data = Vec::new();
        let mut offsets = Vec::new();
        for s in &strings {
            offsets.push(string_data.len() as u32);
            let b = s.as_bytes();
            string_data.push(b.len() as u8);
            string_data.push(b.len() as u8);
            string_data.extend_from_slice(b);
            string_data.push(0);
        }
        while string_data.len() % 4 != 0 {
            string_data.push(0);
        }

        let sp_header_size = 28u16;
        let sp_strings_start = sp_header_size as u32 + (strings.len() as u32) * 4;
        let sp_chunk_size = sp_strings_start + string_data.len() as u32;

        let mut sp_chunk = Vec::new();
        sp_chunk.extend_from_slice(&0x0001u16.to_le_bytes()); // RES_STRING_POOL_TYPE
        sp_chunk.extend_from_slice(&sp_header_size.to_le_bytes());
        sp_chunk.extend_from_slice(&sp_chunk_size.to_le_bytes());
        sp_chunk.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        sp_chunk.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        sp_chunk.extend_from_slice(&0x00000100u32.to_le_bytes()); // UTF8_FLAG
        sp_chunk.extend_from_slice(&sp_strings_start.to_le_bytes());
        sp_chunk.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for off in offsets {
            sp_chunk.extend_from_slice(&off.to_le_bytes());
        }
        sp_chunk.extend_from_slice(&string_data);

        let mut attrs = Vec::new();
        let mut push_attr = |name_idx: u32, raw_idx: u32, data_type: u8, data: u32| {
            attrs.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // ns
            attrs.extend_from_slice(&name_idx.to_le_bytes());
            attrs.extend_from_slice(&raw_idx.to_le_bytes());
            attrs.extend_from_slice(&8u16.to_le_bytes()); // size
            attrs.push(0); // res0
            attrs.push(data_type);
            attrs.extend_from_slice(&data.to_le_bytes());
        };
        push_attr(1, 2, 0x03, 2);
        push_attr(3, u32::MAX, 0x10, version_code);
        let mut attr_count = 2u16;
        if let Some(i) = vn_idx {
            push_attr(i as u32, (i + 1) as u32, 0x03, (i + 1) as u32);
            attr_count += 1;
        }
        if let Some(i) = sp_idx {
            push_attr(i as u32, (i + 1) as u32, 0x03, (i + 1) as u32);
            attr_count += 1;
        }

        let elem_chunk_size = 36u32 + attrs.len() as u32;
        let mut elem_chunk = Vec::new();
        elem_chunk.extend_from_slice(&0x0102u16.to_le_bytes()); // RES_XML_START_ELEMENT_TYPE
        elem_chunk.extend_from_slice(&16u16.to_le_bytes());
        elem_chunk.extend_from_slice(&elem_chunk_size.to_le_bytes());
        elem_chunk.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
        elem_chunk.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // comment
        elem_chunk.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // ns
        elem_chunk.extend_from_slice(&0u32.to_le_bytes()); // name = "manifest"
        elem_chunk.extend_from_slice(&0x0014u16.to_le_bytes()); // attributeStart
        elem_chunk.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
        elem_chunk.extend_from_slice(&attr_count.to_le_bytes());
        elem_chunk.extend_from_slice(&0u16.to_le_bytes()); // idIndex
        elem_chunk.extend_from_slice(&0u16.to_le_bytes()); // classIndex
        elem_chunk.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
        elem_chunk.extend_from_slice(&attrs);

        let total_size = 8u32 + sp_chunk.len() as u32 + elem_chunk.len() as u32;
        let mut doc = Vec::with_capacity(total_size as usize);
        doc.extend_from_slice(&0x0003u16.to_le_bytes()); // RES_XML_TYPE
        doc.extend_from_slice(&8u16.to_le_bytes());
        doc.extend_from_slice(&total_size.to_le_bytes());
        doc.extend_from_slice(&sp_chunk);
        doc.extend_from_slice(&elem_chunk);
        doc
    }

    fn build_synthetic_elf64(
        machine: u16,
        include_android_ident: bool,
        exports: &[&str],
        build_id_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        out[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        out[18..20].copy_from_slice(&machine.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize

        let mut shstrtab = b"\0.shstrtab\0".to_vec();
        let ident_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(if include_android_ident {
            b".note.android.ident\0"
        } else {
            b".note.other\0"
        });
        let bid_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".note.gnu.build-id\0");
        let dynstr_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".dynstr\0");
        let dynsym_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".dynsym\0");

        let mut note_bid = Vec::new();
        note_bid.extend_from_slice(&4u32.to_le_bytes());
        note_bid.extend_from_slice(&(build_id_bytes.len() as u32).to_le_bytes());
        note_bid.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        note_bid.extend_from_slice(b"GNU\0");
        note_bid.extend_from_slice(build_id_bytes);
        while note_bid.len() % 4 != 0 {
            note_bid.push(0);
        }

        let mut dynstr = vec![0u8];
        let mut dynsym = vec![0u8; 24]; // STN_UNDEF
        for sym in exports {
            let name_off = dynstr.len() as u32;
            dynstr.extend_from_slice(sym.as_bytes());
            dynstr.push(0);
            let mut ent = [0u8; 24];
            ent[0..4].copy_from_slice(&name_off.to_le_bytes());
            ent[4] = 0x12; // STB_GLOBAL | STT_FUNC
            ent[6..8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx != SHN_UNDEF
            dynsym.extend_from_slice(&ent);
        }

        while out.len() % 8 != 0 {
            out.push(0);
        }
        let shstr_off = out.len();
        out.extend_from_slice(&shstrtab);
        let ident_off = out.len();
        out.extend_from_slice(&[0u8; 4]);
        let bid_off = out.len();
        out.extend_from_slice(&note_bid);
        let dynstr_off = out.len();
        out.extend_from_slice(&dynstr);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let dynsym_off = out.len();
        out.extend_from_slice(&dynsym);
        while out.len() % 8 != 0 {
            out.push(0);
        }

        let e_shoff = out.len() as u64;
        let mut push_shdr = |name: u32, sh_type: u32, offset: usize, size: usize, link: u32, entsize: u64| {
            let mut sh = [0u8; 64];
            sh[0..4].copy_from_slice(&name.to_le_bytes());
            sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
            sh[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
            sh[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            sh[40..44].copy_from_slice(&link.to_le_bytes());
            sh[56..64].copy_from_slice(&entsize.to_le_bytes());
            out.extend_from_slice(&sh);
        };
        push_shdr(0, 0, 0, 0, 0, 0); // [0] NULL
        push_shdr(1, 3, shstr_off, shstrtab.len(), 0, 0); // [1] .shstrtab
        push_shdr(ident_name_off, 7, ident_off, 4, 0, 0); // [2] .note.android.ident
        push_shdr(bid_name_off, 7, bid_off, note_bid.len(), 0, 0); // [3] .note.gnu.build-id
        push_shdr(dynstr_name_off, 3, dynstr_off, dynstr.len(), 0, 0); // [4] .dynstr
        push_shdr(dynsym_name_off, 11, dynsym_off, dynsym.len(), 4, 24); // [5] .dynsym

        out[40..48].copy_from_slice(&e_shoff.to_le_bytes());
        out[60..62].copy_from_slice(&6u16.to_le_bytes()); // e_shnum
        out[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx
        out
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let f = fs::File::create(path).unwrap();
        let mut zw = ZipWriter::new(f);
        for (name, bytes) in entries {
            zw.start_file(*name, SimpleFileOptions::default()).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap();
    }

    #[test]
    fn validate_elf64_checks_arch_note_exports_and_build_id() {
        let valid_bid = [0xabu8; 20];
        let elf = build_synthetic_elf64(guest_abi::ELF_MACHINE, true, &K_REQUIRED_EXPORTS, &valid_bid);
        let parsed = validate_elf64_guest_so_bytes(&elf).expect("expected valid ELF64");
        assert_eq!(parsed, hex::encode(valid_bid));

        let wrong_arch = build_synthetic_elf64(guest_abi::ELF_MACHINE ^ 1, true, &K_REQUIRED_EXPORTS, &valid_bid);
        assert_eq!(
            validate_elf64_guest_so_bytes(&wrong_arch).unwrap_err(),
            format!("libroblox.so is not a {} ELF", host_guest_abi())
        );

        let no_ident = build_synthetic_elf64(guest_abi::ELF_MACHINE, false, &K_REQUIRED_EXPORTS, &valid_bid);
        assert_eq!(
            validate_elf64_guest_so_bytes(&no_ident).unwrap_err(),
            "libroblox.so has no Android identity note"
        );

        let missing_exp = build_synthetic_elf64(
            guest_abi::ELF_MACHINE,
            true,
            &K_REQUIRED_EXPORTS[..6],
            &valid_bid,
        );
        assert_eq!(
            validate_elf64_guest_so_bytes(&missing_exp).unwrap_err(),
            format!("libroblox.so is missing required export: {}", K_REQUIRED_EXPORTS[6])
        );

        let short_bid = build_synthetic_elf64(guest_abi::ELF_MACHINE, true, &K_REQUIRED_EXPORTS, &[0x12u8; 8]);
        assert_eq!(
            validate_elf64_guest_so_bytes(&short_bid).unwrap_err(),
            "libroblox.so Build ID is not 20 bytes"
        );
    }

    #[test]
    fn prepare_payload_from_archives_handles_split_xapk_and_monolithic() {
        let tmp = TempDirGuard::new("xapk");
        let bid_bytes = [0x42u8; 20];
        let bid_hex = hex::encode(bid_bytes);
        let elf = build_synthetic_elf64(guest_abi::ELF_MACHINE, true, &K_REQUIRED_EXPORTS, &bid_bytes);
        let trust_path = tmp.0.join("trust.json");
        fs::write(
            &trust_path,
            serde_json::json!({
                "schema_version": 1,
                "package": "com.roblox.client",
                "trusted_sha256": [TEST_CERT_SHA],
            })
            .to_string(),
        )
        .unwrap();

        let base_apk = tmp.0.join("base.apk");
        let split_apk = tmp.0.join("split.apk");
        write_zip(
            &base_apk,
            &[
                (
                    "AndroidManifest.xml",
                    &build_axml_manifest("com.roblox.client", Some("2.732.1043"), 2814, None),
                ),
                ("assets/content/test.bin", b"asset-payload"),
            ],
        );
        let lib_entry = guest_lib_entry_name();
        write_zip(
            &split_apk,
            &[
                (
                    "AndroidManifest.xml",
                    &build_axml_manifest(
                        "com.roblox.client",
                        None,
                        2814,
                        Some(guest_abi::SPLIT_NAME),
                    ),
                ),
                (lib_entry.as_str(), &elf),
            ],
        );

        let xapk = tmp.0.join("bundle.xapk");
        write_zip(
            &xapk,
            &[
                ("base.apk", &fs::read(&base_apk).unwrap()),
                (guest_abi::SPLIT_APK_FILE, &fs::read(&split_apk).unwrap()),
            ],
        );

        let expected = ExpectedPayloadIdentityData {
            version_name: "2.732.1043".to_string(),
            version_code: 2814,
            exact_build_id: Some(bid_hex.clone()),
        };
        let ws_split = tmp.0.join("ws_split");
        let prepared = prepare_payload_from_archives(
            &[xapk],
            &expected,
            &trust_path,
            &ws_split,
            "apkpure",
            &StubVerifier(Ok(vec![TEST_CERT_SHA.to_string()])),
        );
        assert!(prepared.error.is_empty(), "split failed: {}", prepared.error);
        assert_eq!(prepared.payload_id, format!("2814-{}", bid_hex));
        let meta: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(prepared.directory.join("roblox_payload.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(meta["apk_layout"], "split");
        assert_eq!(meta["compatibility_status"], "exact-supported");

        // Monolithic APK with untrusted certificate failure then success
        let mono_apk = tmp.0.join("mono.apk");
        write_zip(
            &mono_apk,
            &[
                (
                    "AndroidManifest.xml",
                    &build_axml_manifest("com.roblox.client", Some("2.732.1043"), 2814, None),
                ),
                ("assets/content/test.bin", b"asset-payload"),
                (lib_entry.as_str(), &elf),
            ],
        );
        let ws_untrusted = tmp.0.join("ws_untrusted");
        let fail_res = prepare_payload_from_archives(
            &[mono_apk.clone()],
            &expected,
            &trust_path,
            &ws_untrusted,
            "local",
            &StubVerifier(Ok(vec!["f".repeat(64)])),
        );
        assert_eq!(
            fail_res.error,
            "APK pair has no common trusted Roblox signing certificate"
        );

        let ws_mono = tmp.0.join("ws_mono");
        let ok_mono = prepare_payload_from_archives(
            &[mono_apk],
            &expected,
            &trust_path,
            &ws_mono,
            "local",
            &StubVerifier(Ok(vec![TEST_CERT_SHA.to_string()])),
        );
        assert!(ok_mono.error.is_empty(), "mono failed: {}", ok_mono.error);
        let mono_meta: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(ok_mono.directory.join("roblox_payload.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(mono_meta["apk_layout"], "monolithic");
    }
}
