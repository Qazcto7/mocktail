use crate::deriver_json::read_host_abi_sidecar_identity_file;
use crate::readiness_canary::{
    canary_backend_name_str, run_readiness_canary, CanaryRunConfig,
};
use crate::storage_paths::slice_to_str;
use crate::unix_ipc::{
    copy_filtered_process_env_entries, create_unique_temp_dir, filter_env_slices,
    flock_exclusive_file, is_non_symlink_regular_file, lookup_process_env_bytes, path_from_ffi,
    path_to_cstr, posix_spawn_raw, push_env_kv, cstrings_as_mut_ptrs, strerror_string,
    validate_executable_regular_file, waitpid_blocking, write_private_trunc_file, OwnedFd,
    TempDirError,
};
use crate::update_json::{MocktailRustStrSlice, MocktailRustUpdateState};
use crate::{
    evaluate_update_plan, host_guest_abi, internal_inspect_payload, load_compatibility_catalog_file,
    load_update_config_file, read_elf_build_id_file, sha256_bytes_hex, sha256_file_hex,
    verify_payload_internal, SupportedProfile, OVERRIDDEN_ENV_VAR_BYTES,
};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ============================================================================
// C ABI Types
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustSupportedProfileView {
    pub version_name: MocktailRustStrSlice,
    pub version_code: u64,
    pub elf_build_id: MocktailRustStrSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustCoordinatorStoreResultView {
    pub valid: bool,
    pub payload_id: MocktailRustStrSlice,
    pub payload_directory: MocktailRustStrSlice,
    pub host_abi_profile: MocktailRustStrSlice,
    pub compatibility_manifest: MocktailRustStrSlice,
    pub version_name: MocktailRustStrSlice,
    pub version_code: u64,
    pub build_id: MocktailRustStrSlice,
    pub error: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustUpdateCandidatePlanView {
    pub version_name: MocktailRustStrSlice,
    pub version_code: u64,
    pub has_exact_build_id: bool,
    pub exact_build_id: MocktailRustStrSlice,
    pub exact_supported: bool,
    pub reuse_installed: bool,
    pub origin: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustUnsafeLatestOptions {
    pub runtime_binary: MocktailRustStrSlice,
    pub payload_directory: MocktailRustStrSlice,
    pub compatibility_manifest: MocktailRustStrSlice,
    pub host_abi_profile: MocktailRustStrSlice,
    pub inherited_environment: *const MocktailRustStrSlice,
    pub inherited_environment_count: usize,
}

#[repr(C)]
pub struct MocktailRustUpdatePathsView {
    pub config_file: MocktailRustStrSlice,
    pub data_root: MocktailRustStrSlice,
    pub cache_root: MocktailRustStrSlice,
    pub state_root: MocktailRustStrSlice,
    pub compatibility_manifest: MocktailRustStrSlice,
    pub signing_trust_manifest: MocktailRustStrSlice,
    pub download_sources_manifest: MocktailRustStrSlice,
    pub host_abi_reference_profile: MocktailRustStrSlice,
    pub runtime_binary: MocktailRustStrSlice,
    pub runtime_launcher: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustUpdateRequestView {
    pub startup_preflight: bool,
    pub check_latest: bool,
    pub run_canary: bool,
    pub download_only: bool,
    pub force_run_latest: bool,
    pub canary_graphics_backend: i32,
    pub progress_fd: i32,
}

#[repr(C)]
pub struct MocktailRustUpdateResultView {
    pub changed: bool,
    pub stale: bool,
    pub payload_id: MocktailRustStrSlice,
    pub message: MocktailRustStrSlice,
    pub warnings: *const MocktailRustStrSlice,
    pub warning_count: usize,
    pub error: MocktailRustStrSlice,
}

pub type MocktailCoordinatorProviderCheckLatestFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            version_name: MocktailRustStrSlice,
            version_code: u64,
            error: MocktailRustStrSlice,
        ),
    ),
>;

pub type MocktailCoordinatorDownloadAndPrepareFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        version_name: MocktailRustStrSlice,
        version_code: u64,
        has_exact_build_id: bool,
        exact_build_id: MocktailRustStrSlice,
        download_directory: MocktailRustStrSlice,
        prepare_prefix: MocktailRustStrSlice,
        signing_trust_manifest: MocktailRustStrSlice,
        progress_fd: i32,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            prepared_directory: MocktailRustStrSlice,
            error: MocktailRustStrSlice,
        ),
    ),
>;

pub type MocktailCoordinatorDeriveHostAbiFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        reference_library: MocktailRustStrSlice,
        reference_profile: MocktailRustStrSlice,
        reference_manifests: *const MocktailRustStrSlice,
        reference_manifests_count: usize,
        candidate_payload_directory: MocktailRustStrSlice,
        output_directory: MocktailRustStrSlice,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            profile: MocktailRustStrSlice,
            compatibility_manifest: MocktailRustStrSlice,
            error: MocktailRustStrSlice,
        ),
    ),
>;

pub type MocktailCoordinatorStoreInspectFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            result: *const MocktailRustCoordinatorStoreResultView,
        ),
    ),
>;

pub type MocktailCoordinatorStoreStageFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        prepared_directory: MocktailRustStrSlice,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            result: *const MocktailRustCoordinatorStoreResultView,
        ),
    ),
>;

pub type MocktailCoordinatorStorePromoteFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        payload_id: MocktailRustStrSlice,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            result: *const MocktailRustCoordinatorStoreResultView,
        ),
    ),
>;

pub type MocktailCoordinatorStorePromoteProbationFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        payload_id: MocktailRustStrSlice,
        candidate_profile: MocktailRustStrSlice,
        candidate_compatibility: MocktailRustStrSlice,
        canary_log_0: MocktailRustStrSlice,
        canary_log_1: MocktailRustStrSlice,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            result: *const MocktailRustCoordinatorStoreResultView,
        ),
    ),
>;

pub type MocktailCoordinatorStoreCollectGarbageFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        keep: *const MocktailRustStrSlice,
        keep_count: usize,
        receiver_ctx: *mut c_void,
        on_result: unsafe extern "C" fn(
            receiver_ctx: *mut c_void,
            removed_count: usize,
            freed_bytes: u64,
            error: MocktailRustStrSlice,
        ),
    ),
>;

#[repr(C)]
pub struct MocktailRustUpdateCoordinatorOps {
    pub ctx: *mut c_void,
    pub provider_check_latest: MocktailCoordinatorProviderCheckLatestFn,
    pub download_and_prepare: MocktailCoordinatorDownloadAndPrepareFn,
    pub derive_host_abi_profile: MocktailCoordinatorDeriveHostAbiFn,
    pub store_inspect_current: MocktailCoordinatorStoreInspectFn,
    pub store_verify_current: MocktailCoordinatorStoreInspectFn,
    pub store_stage: MocktailCoordinatorStoreStageFn,
    pub store_promote: MocktailCoordinatorStorePromoteFn,
    pub store_promote_probation: MocktailCoordinatorStorePromoteProbationFn,
    pub store_collect_garbage: MocktailCoordinatorStoreCollectGarbageFn,
}

// ============================================================================
// Domain Model & Backend Abstraction
// ============================================================================

#[derive(Debug, Clone, Default)]
struct UpdatePathsData {
    config_file: PathBuf,
    data_root: PathBuf,
    cache_root: PathBuf,
    state_root: PathBuf,
    compatibility_manifest: PathBuf,
    signing_trust_manifest: PathBuf,
    host_abi_reference_profile: PathBuf,
    runtime_binary: PathBuf,
    runtime_launcher: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct UpdateRequestData {
    startup_preflight: bool,
    check_latest: bool,
    run_canary: bool,
    download_only: bool,
    force_run_latest: bool,
    canary_graphics_backend: i32,
    progress_fd: i32,
}

#[derive(Debug, Clone, Default)]
struct UpdateResultData {
    changed: bool,
    stale: bool,
    payload_id: String,
    message: String,
    warnings: Vec<String>,
    error: String,
}

impl UpdateResultData {
    fn is_ok(&self) -> bool {
        self.error.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExpectedIdentityData {
    version_name: String,
    version_code: u64,
    exact_build_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct CoordinatorStoreResult {
    payload_id: String,
    payload_directory: PathBuf,
    host_abi_profile: PathBuf,
    compatibility_manifest: PathBuf,
    version_name: String,
    version_code: u64,
    build_id: String,
    error: String,
}

impl CoordinatorStoreResult {
    fn is_valid(&self) -> bool {
        self.error.is_empty() && !self.payload_id.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CandidatePlanData {
    identity: ExpectedIdentityData,
    exact_supported: bool,
    reuse_installed: bool,
    origin: &'static str,
}

#[derive(Debug, Clone, Default)]
struct ProviderVersionData {
    version_name: String,
    version_code: u64,
    error: String,
}

impl ProviderVersionData {
    fn is_valid(&self) -> bool {
        self.error.is_empty() && !self.version_name.is_empty() && self.version_code > 0
    }
}

#[derive(Debug, Default)]
struct CandidateData {
    staged: CoordinatorStoreResult,
    exact_supported: bool,
    profile: PathBuf,
    compatibility: PathBuf,
    error: String,
}

impl CandidateData {
    fn is_valid(&self) -> bool {
        self.error.is_empty() && self.staged.is_valid()
    }
}

#[derive(Debug, Default)]
struct ReferenceProfileData {
    library: PathBuf,
    profile: PathBuf,
    compatibility_manifests: Vec<PathBuf>,
    error: String,
}

impl ReferenceProfileData {
    fn is_valid(&self) -> bool {
        self.error.is_empty()
            && !self.library.as_os_str().is_empty()
            && !self.profile.as_os_str().is_empty()
    }
}

#[derive(Debug, Default)]
struct GarbageCollectData {
    removed_count: usize,
    freed_bytes: u64,
    error: String,
}

#[derive(Debug, Default)]
struct DerivedHostAbiData {
    profile: PathBuf,
    compatibility_manifest: PathBuf,
    error: String,
}

trait UpdateBackend {
    fn provider_check_latest(&self) -> ProviderVersionData;
    fn download_and_prepare(
        &self,
        identity: &ExpectedIdentityData,
        download_directory: &Path,
        prepare_prefix: &Path,
        signing_trust_manifest: &Path,
        progress_fd: i32,
    ) -> Result<PathBuf, String>;
    fn derive_host_abi_profile(
        &self,
        reference_library: &Path,
        reference_profile: &Path,
        reference_manifests: &[PathBuf],
        candidate_payload_directory: &Path,
        output_directory: &Path,
    ) -> DerivedHostAbiData;
    fn store_inspect_current(&self) -> CoordinatorStoreResult;
    fn store_verify_current(&self) -> CoordinatorStoreResult;
    fn store_stage(&self, prepared_directory: &Path) -> CoordinatorStoreResult;
    fn store_promote(&self, payload_id: &str) -> CoordinatorStoreResult;
    fn store_promote_probation(
        &self,
        payload_id: &str,
        candidate_profile: &Path,
        candidate_compatibility: &Path,
        canary_logs: [&Path; 2],
    ) -> CoordinatorStoreResult;
    fn store_collect_garbage(&self, keep: &[String]) -> GarbageCollectData;
}

// ============================================================================
// FFI Backend Implementation
// ============================================================================

struct FfiBackend<'a> {
    ops: &'a MocktailRustUpdateCoordinatorOps,
}

fn path_to_slice(path: &Path) -> MocktailRustStrSlice {
    let bytes = path.as_os_str().as_encoded_bytes();
    MocktailRustStrSlice {
        ptr: bytes.as_ptr() as *const c_char,
        len: bytes.len(),
    }
}

fn opt_str_to_slice(opt: Option<&str>) -> (bool, MocktailRustStrSlice) {
    match opt {
        Some(s) => (true, MocktailRustStrSlice::from_str(s)),
        None => (false, MocktailRustStrSlice::from_str("")),
    }
}

unsafe fn slice_to_string(slice: MocktailRustStrSlice) -> String {
    slice_to_str(slice.ptr, slice.len)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if slice.ptr.is_null() || slice.len == 0 {
                String::new()
            } else {
                let raw = std::slice::from_raw_parts(slice.ptr as *const u8, slice.len);
                String::from_utf8_lossy(raw).into_owned()
            }
        })
}

unsafe fn slice_to_pathbuf(slice: MocktailRustStrSlice) -> PathBuf {
    path_from_ffi(slice.ptr, slice.len).unwrap_or_default()
}

unsafe fn store_view_to_data(view: &MocktailRustCoordinatorStoreResultView) -> CoordinatorStoreResult {
    CoordinatorStoreResult {
        payload_id: slice_to_string(view.payload_id),
        payload_directory: slice_to_pathbuf(view.payload_directory),
        host_abi_profile: slice_to_pathbuf(view.host_abi_profile),
        compatibility_manifest: slice_to_pathbuf(view.compatibility_manifest),
        version_name: slice_to_string(view.version_name),
        version_code: view.version_code,
        build_id: slice_to_string(view.build_id),
        error: slice_to_string(view.error),
    }
}

unsafe extern "C" fn on_store_result_cb(
    receiver_ctx: *mut c_void,
    result: *const MocktailRustCoordinatorStoreResultView,
) {
    if receiver_ctx.is_null() || result.is_null() {
        return;
    }
    let slot = &mut *receiver_ctx.cast::<Option<CoordinatorStoreResult>>();
    *slot = Some(store_view_to_data(&*result));
}

unsafe extern "C" fn on_check_latest_cb(
    receiver_ctx: *mut c_void,
    version_name: MocktailRustStrSlice,
    version_code: u64,
    error: MocktailRustStrSlice,
) {
    if receiver_ctx.is_null() {
        return;
    }
    let slot = &mut *receiver_ctx.cast::<Option<ProviderVersionData>>();
    *slot = Some(ProviderVersionData {
        version_name: slice_to_string(version_name),
        version_code,
        error: slice_to_string(error),
    });
}

unsafe extern "C" fn on_download_prepared_cb(
    receiver_ctx: *mut c_void,
    prepared_directory: MocktailRustStrSlice,
    error: MocktailRustStrSlice,
) {
    if receiver_ctx.is_null() {
        return;
    }
    let slot = &mut *receiver_ctx.cast::<Option<(PathBuf, String)>>();
    *slot = Some((slice_to_pathbuf(prepared_directory), slice_to_string(error)));
}

unsafe extern "C" fn on_derived_cb(
    receiver_ctx: *mut c_void,
    profile: MocktailRustStrSlice,
    compatibility_manifest: MocktailRustStrSlice,
    error: MocktailRustStrSlice,
) {
    if receiver_ctx.is_null() {
        return;
    }
    let slot = &mut *receiver_ctx.cast::<Option<DerivedHostAbiData>>();
    *slot = Some(DerivedHostAbiData {
        profile: slice_to_pathbuf(profile),
        compatibility_manifest: slice_to_pathbuf(compatibility_manifest),
        error: slice_to_string(error),
    });
}

unsafe extern "C" fn on_collect_garbage_cb(
    receiver_ctx: *mut c_void,
    removed_count: usize,
    freed_bytes: u64,
    error: MocktailRustStrSlice,
) {
    if receiver_ctx.is_null() {
        return;
    }
    let slot = &mut *receiver_ctx.cast::<Option<GarbageCollectData>>();
    *slot = Some(GarbageCollectData {
        removed_count,
        freed_bytes,
        error: slice_to_string(error),
    });
}

impl UpdateBackend for FfiBackend<'_> {
    fn provider_check_latest(&self) -> ProviderVersionData {
        let Some(f) = self.ops.provider_check_latest else {
            return ProviderVersionData {
                error: "provider check_latest callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let mut slot: Option<ProviderVersionData> = None;
        unsafe {
            f(
                self.ops.ctx,
                std::ptr::addr_of_mut!(slot).cast(),
                on_check_latest_cb,
            );
        }
        slot.unwrap_or_else(|| ProviderVersionData {
            error: "provider check_latest produced no result".to_string(),
            ..Default::default()
        })
    }

    fn download_and_prepare(
        &self,
        identity: &ExpectedIdentityData,
        download_directory: &Path,
        prepare_prefix: &Path,
        signing_trust_manifest: &Path,
        progress_fd: i32,
    ) -> Result<PathBuf, String> {
        let Some(f) = self.ops.download_and_prepare else {
            return Err("download_and_prepare callback unavailable".to_string());
        };
        let (has_exact, exact_slice) = opt_str_to_slice(identity.exact_build_id.as_deref());
        let mut slot: Option<(PathBuf, String)> = None;
        unsafe {
            f(
                self.ops.ctx,
                MocktailRustStrSlice::from_str(&identity.version_name),
                identity.version_code,
                has_exact,
                exact_slice,
                path_to_slice(download_directory),
                path_to_slice(prepare_prefix),
                path_to_slice(signing_trust_manifest),
                progress_fd,
                std::ptr::addr_of_mut!(slot).cast(),
                on_download_prepared_cb,
            );
        }
        match slot {
            Some((dir, err)) if err.is_empty() && !dir.as_os_str().is_empty() => Ok(dir),
            Some((_, err)) => Err(if err.is_empty() {
                "download_and_prepare failed".to_string()
            } else {
                err
            }),
            None => Err("download_and_prepare produced no result".to_string()),
        }
    }

    fn derive_host_abi_profile(
        &self,
        reference_library: &Path,
        reference_profile: &Path,
        reference_manifests: &[PathBuf],
        candidate_payload_directory: &Path,
        output_directory: &Path,
    ) -> DerivedHostAbiData {
        let Some(f) = self.ops.derive_host_abi_profile else {
            return DerivedHostAbiData {
                error: "derive_host_abi_profile callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let manifest_slices: Vec<MocktailRustStrSlice> =
            reference_manifests.iter().map(|p| path_to_slice(p)).collect();
        let mut slot: Option<DerivedHostAbiData> = None;
        unsafe {
            f(
                self.ops.ctx,
                path_to_slice(reference_library),
                path_to_slice(reference_profile),
                manifest_slices.as_ptr(),
                manifest_slices.len(),
                path_to_slice(candidate_payload_directory),
                path_to_slice(output_directory),
                std::ptr::addr_of_mut!(slot).cast(),
                on_derived_cb,
            );
        }
        slot.unwrap_or_else(|| DerivedHostAbiData {
            error: "derive_host_abi_profile produced no result".to_string(),
            ..Default::default()
        })
    }

    fn store_inspect_current(&self) -> CoordinatorStoreResult {
        let Some(f) = self.ops.store_inspect_current else {
            return CoordinatorStoreResult {
                error: "store_inspect_current callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let mut slot: Option<CoordinatorStoreResult> = None;
        unsafe {
            f(self.ops.ctx, std::ptr::addr_of_mut!(slot).cast(), on_store_result_cb);
        }
        slot.unwrap_or_default()
    }

    fn store_verify_current(&self) -> CoordinatorStoreResult {
        let Some(f) = self.ops.store_verify_current else {
            return CoordinatorStoreResult {
                error: "store_verify_current callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let mut slot: Option<CoordinatorStoreResult> = None;
        unsafe {
            f(self.ops.ctx, std::ptr::addr_of_mut!(slot).cast(), on_store_result_cb);
        }
        slot.unwrap_or_default()
    }

    fn store_stage(&self, prepared_directory: &Path) -> CoordinatorStoreResult {
        let Some(f) = self.ops.store_stage else {
            return CoordinatorStoreResult {
                error: "store_stage callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let mut slot: Option<CoordinatorStoreResult> = None;
        unsafe {
            f(
                self.ops.ctx,
                path_to_slice(prepared_directory),
                std::ptr::addr_of_mut!(slot).cast(),
                on_store_result_cb,
            );
        }
        slot.unwrap_or_default()
    }

    fn store_promote(&self, payload_id: &str) -> CoordinatorStoreResult {
        let Some(f) = self.ops.store_promote else {
            return CoordinatorStoreResult {
                error: "store_promote callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let mut slot: Option<CoordinatorStoreResult> = None;
        unsafe {
            f(
                self.ops.ctx,
                MocktailRustStrSlice::from_str(payload_id),
                std::ptr::addr_of_mut!(slot).cast(),
                on_store_result_cb,
            );
        }
        slot.unwrap_or_default()
    }

    fn store_promote_probation(
        &self,
        payload_id: &str,
        candidate_profile: &Path,
        candidate_compatibility: &Path,
        canary_logs: [&Path; 2],
    ) -> CoordinatorStoreResult {
        let Some(f) = self.ops.store_promote_probation else {
            return CoordinatorStoreResult {
                error: "store_promote_probation callback unavailable".to_string(),
                ..Default::default()
            };
        };
        let mut slot: Option<CoordinatorStoreResult> = None;
        unsafe {
            f(
                self.ops.ctx,
                MocktailRustStrSlice::from_str(payload_id),
                path_to_slice(candidate_profile),
                path_to_slice(candidate_compatibility),
                path_to_slice(canary_logs[0]),
                path_to_slice(canary_logs[1]),
                std::ptr::addr_of_mut!(slot).cast(),
                on_store_result_cb,
            );
        }
        slot.unwrap_or_default()
    }

    fn store_collect_garbage(&self, keep: &[String]) -> GarbageCollectData {
        let Some(f) = self.ops.store_collect_garbage else {
            return GarbageCollectData::default();
        };
        let keep_slices: Vec<MocktailRustStrSlice> =
            keep.iter().map(|s| MocktailRustStrSlice::from_str(s)).collect();
        let mut slot: Option<GarbageCollectData> = None;
        unsafe {
            f(
                self.ops.ctx,
                keep_slices.as_ptr(),
                keep_slices.len(),
                std::ptr::addr_of_mut!(slot).cast(),
                on_collect_garbage_cb,
            );
        }
        slot.unwrap_or_default()
    }
}

// ============================================================================
// Pure-Rust Utilities: Progress, Lock, Trace Timer, Workspaces, Rejections
// ============================================================================

fn send_progress(progress_fd: i32, message: &str) {
    if progress_fd < 0 {
        return;
    }
    let mut packet = Vec::with_capacity(1 + message.len());
    packet.push(b'P');
    packet.extend_from_slice(message.as_bytes());
    unsafe {
        let _ = libc::send(progress_fd, packet.as_ptr().cast(), packet.len(), libc::MSG_NOSIGNAL);
    }
}

fn trace_flag_enabled(name: &[u8]) -> bool {
    lookup_process_env_bytes(name).is_some_and(|v| !v.is_empty() && v != b"0")
}

fn update_trace_enabled() -> bool {
    trace_flag_enabled(b"MOCKTAIL_UPDATE_TRACE")
        || trace_flag_enabled(b"MOCKTAIL_TRACE_ALL")
        || trace_flag_enabled(b"MOCKTAIL_FULL_TRACE")
}

struct StageTimer {
    name: Option<String>,
    start: Instant,
}

impl StageTimer {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            start: Instant::now(),
        }
    }

    fn report(&mut self) {
        let Some(name) = self.name.take() else {
            return;
        };
        if update_trace_enabled() {
            let ms = self.start.elapsed().as_millis();
            eprintln!("  [update] {name} {ms} ms");
        }
    }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        self.report();
    }
}

struct TempWorkspaceGuard(PathBuf);

impl Drop for TempWorkspaceGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn acquire_update_lock(data_root: &Path) -> Result<OwnedFd, String> {
    if fs::create_dir_all(data_root).is_err() {
        return Err("cannot create updater data root".to_string());
    }
    let lock_path = data_root.join(".native-update.lock");
    flock_exclusive_file(&lock_path).map_err(|_| "cannot lock native updater".to_string())
}

fn remove_stale_workspaces(parent: &Path) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".update-")
        {
            stale.push(entry.path());
        }
    }
    for path in stale {
        let is_dir = fs::symlink_metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if is_dir {
            let _ = fs::remove_dir_all(&path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
}

fn create_workspace(parent: &Path) -> Result<PathBuf, String> {
    create_unique_temp_dir(parent, ".update").map_err(|err| match err {
        TempDirError::CreateParent => "cannot create native updater cache".to_string(),
        TempDirError::CreateTemp => "cannot create native updater workspace".to_string(),
    })
}

fn find_staged_candidate(
    paths: &UpdatePathsData,
    identity: &ExpectedIdentityData,
    exact_supported: bool,
) -> CandidateData {
    let payloads_dir = paths.data_root.join("payloads");
    let Ok(entries) = fs::read_dir(&payloads_dir) else {
        return CandidateData::default();
    };
    let mut matched: Option<CandidateData> = None;
    for entry in entries {
        let Ok(entry) = entry else {
            return CandidateData::default();
        };
        let entry_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&entry_path) else {
            return CandidateData::default();
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        let Ok(payload) = internal_inspect_payload(&entry_path) else {
            continue;
        };
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        if payload.payload_id == dir_name
            && payload.version_name == identity.version_name
            && payload.version_code == identity.version_code
            && identity
                .exact_build_id
                .as_ref()
                .is_none_or(|bid| &payload.build_id == bid)
        {
            if matched.is_some() {
                // Provider download remains the unambiguous source of truth if the
                // local store somehow contains two Build IDs for one version.
                return CandidateData::default();
            }
            matched = Some(CandidateData {
                staged: CoordinatorStoreResult {
                    payload_id: payload.payload_id,
                    payload_directory: entry_path,
                    version_name: payload.version_name,
                    version_code: payload.version_code,
                    build_id: payload.build_id,
                    ..Default::default()
                },
                exact_supported,
                ..Default::default()
            });
        }
    }
    let Some(candidate) = matched else {
        return CandidateData::default();
    };
    if verify_payload_internal(&candidate.staged.payload_directory).is_err() {
        return CandidateData::default();
    }
    candidate
}

fn rejection_marker_path(
    paths: &UpdatePathsData,
    candidate: &CandidateData,
    graphics_backend: i32,
) -> Option<PathBuf> {
    if !candidate.staged.is_valid() || paths.runtime_binary.as_os_str().is_empty() {
        return None;
    }
    let runtime_build_id = read_elf_build_id_file(&paths.runtime_binary)?;
    let mut fingerprint = String::new();
    if let Some(h) = sha256_file_hex(&paths.compatibility_manifest) {
        fingerprint.push_str(&h);
    }
    if let Some(h) = sha256_file_hex(&paths.data_root.join("current.json")) {
        fingerprint.push_str(&h);
    }
    let mut references = Vec::new();
    if paths.host_abi_reference_profile.is_dir() {
        if let Ok(entries) = fs::read_dir(&paths.host_abi_reference_profile) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    references.push(p);
                }
            }
        }
    } else {
        references.push(paths.host_abi_reference_profile.clone());
    }
    references.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
    for reference in references {
        if let Some(h) = sha256_file_hex(&reference) {
            fingerprint.push_str(&h);
        }
    }
    let digest = sha256_bytes_hex(fingerprint.as_bytes());
    let digest16 = &digest[..digest.len().min(16)];
    let backend_name = canary_backend_name_str(graphics_backend);
    Some(paths.data_root.join("rejections").join(format!(
        "{}-{}-{}-{}.txt",
        candidate.staged.payload_id, runtime_build_id, digest16, backend_name
    )))
}

fn record_rejection(
    paths: &UpdatePathsData,
    candidate: &CandidateData,
    graphics_backend: i32,
    reason: &str,
) {
    let Some(marker) = rejection_marker_path(paths, candidate, graphics_backend) else {
        return;
    };
    if let Some(parent) = marker.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let truncated_len = reason.len().min(4096);
    let mut contents = Vec::with_capacity(truncated_len + 1);
    contents.extend_from_slice(&reason.as_bytes()[..truncated_len]);
    contents.push(b'\n');
    let _ = write_private_trunc_file(&marker, &contents);
}

// ============================================================================
// Pure-Rust Logic: Reference Sidecars & Update Candidate Planning
// ============================================================================

fn collect_reference_sidecars(location: &Path) -> BTreeMap<String, PathBuf> {
    let mut files = Vec::new();
    if location.is_dir() {
        if let Ok(entries) = fs::read_dir(location) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    files.push(p);
                }
            }
        }
    } else if location.is_file() {
        files.push(location.to_path_buf());
    }
    let mut sidecars = BTreeMap::new();
    for file in files {
        if let Ok((elf_build_id, _payload_id)) = read_host_abi_sidecar_identity_file(&file) {
            sidecars.entry(elf_build_id).or_insert(file);
        }
    }
    sidecars
}

fn resolve_reference_profile_internal(
    location: &Path,
    profiles: &[SupportedProfile],
) -> Option<(usize, PathBuf)> {
    let sidecars = collect_reference_sidecars(location);
    let mut selected: Option<(usize, PathBuf)> = None;
    for (index, profile) in profiles.iter().enumerate() {
        let Some(sidecar) = sidecars.get(&profile.elf_build_id) else {
            continue;
        };
        let replace = match &selected {
            None => true,
            Some((best_idx, _)) => profiles[*best_idx].version_code < profile.version_code,
        };
        if replace {
            selected = Some((index, sidecar.clone()));
        }
    }
    selected
}

fn preferred_supported_profile(profiles: &[SupportedProfile]) -> Option<&SupportedProfile> {
    profiles.iter().max_by_key(|p| p.version_code)
}

fn find_supported_profile<'a>(
    profiles: &'a [SupportedProfile],
    version_name: &str,
    version_code: u64,
) -> Option<&'a SupportedProfile> {
    profiles.iter().find(|p| {
        p.version_name == version_name && (version_code == 0 || p.version_code == version_code)
    })
}

fn exact_payload_identity(profile: &SupportedProfile) -> ExpectedIdentityData {
    ExpectedIdentityData {
        version_name: profile.version_name.clone(),
        version_code: profile.version_code,
        exact_build_id: Some(profile.elf_build_id.clone()),
    }
}

fn plan_update_candidates_internal(
    profiles: &[SupportedProfile],
    preferred: &SupportedProfile,
    latest: Option<&ProviderVersionData>,
    current: &CoordinatorStoreResult,
    installed: &CoordinatorStoreResult,
) -> Vec<CandidatePlanData> {
    let mut plans = Vec::new();
    let runnable = current.is_valid();
    let runnable_code = if runnable { current.version_code } else { 0 };
    let valid_latest = latest.filter(|v| v.is_valid());
    let has_latest = valid_latest.is_some();
    let latest_code = valid_latest.map_or(0, |v| v.version_code);

    let (take_latest, take_preferred) = evaluate_update_plan(
        has_latest,
        latest_code,
        runnable,
        runnable_code,
        preferred.version_code,
    );

    if let (true, Some(latest_ver)) = (take_latest, valid_latest) {
        let exact =
            find_supported_profile(profiles, &latest_ver.version_name, latest_ver.version_code);
        let identity = ExpectedIdentityData {
            version_name: latest_ver.version_name.clone(),
            version_code: latest_ver.version_code,
            exact_build_id: exact.map(|p| p.elf_build_id.clone()),
        };
        let reuse_installed = installed.is_valid()
            && installed.version_name == latest_ver.version_name
            && installed.version_code == latest_ver.version_code
            && !installed.host_abi_profile.as_os_str().is_empty()
            && !installed.compatibility_manifest.as_os_str().is_empty();
        plans.push(CandidatePlanData {
            identity,
            exact_supported: exact.is_some(),
            reuse_installed,
            origin: "provider latest",
        });
    }
    if take_preferred {
        plans.push(CandidatePlanData {
            identity: exact_payload_identity(preferred),
            exact_supported: true,
            reuse_installed: false,
            origin: "supported catalog",
        });
    }
    plans
}

// ============================================================================
// Pure-Rust Logic: Unsafe Latest Candidate Runner
// ============================================================================

struct UnsafeLatestConfig {
    runtime_binary: PathBuf,
    payload_directory: PathBuf,
    compatibility_manifest: PathBuf,
    host_abi_profile: PathBuf,
    inherited_environment: Vec<Vec<u8>>,
}

struct UnsafeLatestOutcome {
    exit_code: i32,
    error: String,
}

fn build_unsafe_latest_environment(config: &UnsafeLatestConfig) -> Result<Vec<CString>, String> {
    let mut entries = if config.inherited_environment.is_empty() {
        copy_filtered_process_env_entries(OVERRIDDEN_ENV_VAR_BYTES)
    } else {
        let refs: Vec<&[u8]> = config.inherited_environment.iter().map(Vec::as_slice).collect();
        filter_env_slices(&refs, OVERRIDDEN_ENV_VAR_BYTES)
    };

    let push_path = |out: &mut Vec<CString>, name: &[u8], path: &Path| -> Result<(), String> {
        push_env_kv(out, name, path.as_os_str().as_encoded_bytes())
            .map_err(|_| "unsafe latest environment contains NUL byte".to_string())
    };
    let push_str = |out: &mut Vec<CString>, name: &[u8], val: &[u8]| -> Result<(), String> {
        push_env_kv(out, name, val)
            .map_err(|_| "unsafe latest environment contains NUL byte".to_string())
    };

    push_path(&mut entries, b"ROBLOX_LIB_PATH", &config.payload_directory.join("libroblox.so"))?;
    push_path(&mut entries, b"MOCKTAIL_ASSET_ROOT", &config.payload_directory.join("assets"))?;
    push_path(
        &mut entries,
        b"MOCKTAIL_ASSET_PATH",
        &config.payload_directory.join("assets/content"),
    )?;
    push_path(
        &mut entries,
        b"MOCKTAIL_COMPATIBILITY_MANIFEST",
        &config.compatibility_manifest,
    )?;
    push_str(&mut entries, b"MOCKTAIL_SKIP_UPDATE_CHECK", b"1")?;
    push_str(&mut entries, b"MOCKTAIL_UNSAFE_LATEST", b"1")?;

    if !config.host_abi_profile.as_os_str().is_empty() {
        push_path(&mut entries, b"MOCKTAIL_HOST_ABI_PROFILE_FILE", &config.host_abi_profile)?;
        push_str(&mut entries, b"MOCKTAIL_HOST_ABI_CANARY", b"1")?;
        push_str(&mut entries, b"MOCKTAIL_ALLOW_CANDIDATE_HOST_ABI", b"1")?;
    }

    Ok(entries)
}

fn run_unsafe_latest_candidate_internal(config: &UnsafeLatestConfig) -> UnsafeLatestOutcome {
    if !validate_executable_regular_file(&config.runtime_binary) {
        return UnsafeLatestOutcome {
            exit_code: -1,
            error: "unsafe latest runtime is not an executable regular file".to_string(),
        };
    }
    if !is_non_symlink_regular_file(&config.payload_directory.join("libroblox.so")) {
        return UnsafeLatestOutcome {
            exit_code: -1,
            error: "unsafe latest payload library is not a regular file".to_string(),
        };
    }
    if !is_non_symlink_regular_file(&config.compatibility_manifest) {
        return UnsafeLatestOutcome {
            exit_code: -1,
            error: "unsafe latest compatibility manifest is not a regular file".to_string(),
        };
    }
    if !config.host_abi_profile.as_os_str().is_empty()
        && !is_non_symlink_regular_file(&config.host_abi_profile)
    {
        return UnsafeLatestOutcome {
            exit_code: -1,
            error: "unsafe latest HostAbi profile is not a regular file".to_string(),
        };
    }

    let env_entries = match build_unsafe_latest_environment(config) {
        Ok(e) => e,
        Err(err) => {
            return UnsafeLatestOutcome {
                exit_code: -1,
                error: err,
            };
        }
    };
    let Some(c_binary) = path_to_cstr(&config.runtime_binary) else {
        return UnsafeLatestOutcome {
            exit_code: -1,
            error: "unsafe latest runtime path contains NUL byte".to_string(),
        };
    };
    let arg_windowed = CString::new("--windowed").unwrap();
    let arg_unverified = CString::new("--allow-unverified-build").unwrap();
    let mut argv: [*mut libc::c_char; 4] = [
        c_binary.as_ptr().cast_mut(),
        arg_windowed.as_ptr().cast_mut(),
        if config.host_abi_profile.as_os_str().is_empty() {
            std::ptr::null_mut()
        } else {
            arg_unverified.as_ptr().cast_mut()
        },
        std::ptr::null_mut(),
    ];
    let envp = cstrings_as_mut_ptrs(&env_entries);

    let pid = match unsafe { posix_spawn_raw(&c_binary, None, &argv, &envp) } {
        Ok(pid) => pid,
        Err(spawn_err) => {
            return UnsafeLatestOutcome {
                exit_code: -1,
                error: format!("cannot start unsafe latest Roblox: {}", strerror_string(spawn_err)),
            };
        }
    };
    let _ = &mut argv;

    let status = match waitpid_blocking(pid) {
        Ok(st) => st,
        Err(wait_err) => {
            return UnsafeLatestOutcome {
                exit_code: -1,
                error: format!(
                    "cannot wait for unsafe latest Roblox: {}",
                    strerror_string(wait_err)
                ),
            };
        }
    };

    if !libc::WIFEXITED(status) {
        let sig = if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        };
        return UnsafeLatestOutcome {
            exit_code: 128 + sig,
            error: "unsafe latest Roblox terminated before a normal exit".to_string(),
        };
    }

    let exit_code = libc::WEXITSTATUS(status);
    let error = if exit_code != 0 {
        format!("unsafe latest Roblox exited with status {exit_code}")
    } else {
        String::new()
    };
    UnsafeLatestOutcome { exit_code, error }
}

// ============================================================================
// Pure-Rust Orchestration: Download, Reference, Canary, Promote, RunUpdate
// ============================================================================

fn download_candidate<B: UpdateBackend>(
    backend: &B,
    identity: &ExpectedIdentityData,
    exact_supported: bool,
    paths: &UpdatePathsData,
    workspace: &Path,
    progress_fd: i32,
) -> CandidateData {
    let mut candidate = CandidateData {
        exact_supported,
        ..Default::default()
    };
    send_progress(progress_fd, "Downloading Roblox...");
    let mut download_timer = StageTimer::new("download-and-verify");
    let download_directory = paths
        .cache_root
        .join("downloads/native-updater/archives")
        .join(format!("{}-{}", host_guest_abi(), identity.version_code));
    let prepared_directory = match backend.download_and_prepare(
        identity,
        &download_directory,
        workspace,
        &paths.signing_trust_manifest,
        progress_fd,
    ) {
        Ok(dir) => dir,
        Err(err) => {
            candidate.error = err;
            return candidate;
        }
    };
    download_timer.report();

    let _stage_timer = StageTimer::new("stage");
    candidate.staged = backend.store_stage(&prepared_directory);
    if !candidate.staged.is_valid() {
        candidate.error = candidate.staged.error.clone();
    } else {
        let _ = fs::remove_dir_all(&download_directory);
    }
    candidate
}

fn resolve_reference<B: UpdateBackend>(
    backend: &B,
    paths: &UpdatePathsData,
    installed: &CoordinatorStoreResult,
    profiles: &[SupportedProfile],
    workspace: &Path,
    progress_fd: i32,
) -> ReferenceProfileData {
    if installed.is_valid() && !installed.host_abi_profile.as_os_str().is_empty() {
        if let Ok((elf_build_id, _)) =
            read_host_abi_sidecar_identity_file(&installed.host_abi_profile)
        {
            let lib_path = installed.payload_directory.join("libroblox.so");
            if elf_build_id == installed.build_id && lib_path.is_file() {
                let mut manifests = Vec::new();
                if !installed.compatibility_manifest.as_os_str().is_empty()
                    && installed.compatibility_manifest.is_file()
                {
                    manifests.push(installed.compatibility_manifest.clone());
                }
                if paths.compatibility_manifest.is_file()
                    && manifests.first() != Some(&paths.compatibility_manifest)
                {
                    manifests.push(paths.compatibility_manifest.clone());
                }
                return ReferenceProfileData {
                    library: lib_path,
                    profile: installed.host_abi_profile.clone(),
                    compatibility_manifests: manifests,
                    error: String::new(),
                };
            }
        }
    }

    let Some((ref_idx, sidecar)) =
        resolve_reference_profile_internal(&paths.host_abi_reference_profile, profiles)
    else {
        return ReferenceProfileData {
            error: "no HostAbi reference sidecar matches a supported Roblox profile".to_string(),
            ..Default::default()
        };
    };
    let reference = &profiles[ref_idx];
    let reference_id = format!("{}-{}", reference.version_code, reference.elf_build_id);
    let reference_directory = paths.data_root.join("payloads").join(&reference_id);
    if let Ok(info) = internal_inspect_payload(&reference_directory) {
        if info.payload_id == reference_id {
            return ReferenceProfileData {
                library: reference_directory.join("libroblox.so"),
                profile: sidecar,
                compatibility_manifests: vec![paths.compatibility_manifest.clone()],
                error: String::new(),
            };
        }
    }

    let downloaded = download_candidate(
        backend,
        &exact_payload_identity(reference),
        true,
        paths,
        &workspace.join("reference"),
        progress_fd,
    );
    if !downloaded.is_valid() {
        return ReferenceProfileData {
            error: format!(
                "cannot obtain HostAbi derivation reference {}: {}",
                reference.version_name, downloaded.error
            ),
            ..Default::default()
        };
    }

    ReferenceProfileData {
        library: downloaded.staged.payload_directory.join("libroblox.so"),
        profile: sidecar,
        compatibility_manifests: vec![paths.compatibility_manifest.clone()],
        error: String::new(),
    }
}

fn runtime_binary_for_launch(paths: &UpdatePathsData) -> PathBuf {
    if paths.runtime_launcher.as_os_str().is_empty() {
        paths.runtime_binary.clone()
    } else {
        paths.runtime_launcher.clone()
    }
}

fn derive_candidate_host_abi<B: UpdateBackend>(
    backend: &B,
    paths: &UpdatePathsData,
    installed: &CoordinatorStoreResult,
    profiles: &[SupportedProfile],
    candidate: &mut CandidateData,
    workspace: &Path,
    derivation_dir: &Path,
    progress_fd: i32,
    progress_label: &str,
) -> Result<(), (bool, String)> {
    let reference = resolve_reference(backend, paths, installed, profiles, workspace, progress_fd);
    if !reference.is_valid() {
        return Err((false, reference.error));
    }
    send_progress(progress_fd, progress_label);
    let derived = {
        let _timer = StageTimer::new("derive-host-abi");
        backend.derive_host_abi_profile(
            &reference.library,
            &reference.profile,
            &reference.compatibility_manifests,
            &candidate.staged.payload_directory,
            derivation_dir,
        )
    };
    if !derived.error.is_empty() {
        return Err((true, derived.error));
    }
    candidate.profile = derived.profile;
    candidate.compatibility = derived.compatibility_manifest;
    Ok(())
}

fn run_unsafe_latest<B: UpdateBackend>(
    backend: &B,
    paths: &UpdatePathsData,
    request: &UpdateRequestData,
    profiles: &[SupportedProfile],
    installed: &CoordinatorStoreResult,
) -> UpdateResultData {
    let mut result = UpdateResultData::default();
    if request.startup_preflight || !request.check_latest {
        result.error = "unsafe latest launch requires an explicit latest-version check".to_string();
        return result;
    }

    send_progress(request.progress_fd, "Checking latest Roblox...");
    let latest = {
        let _timer = StageTimer::new("check-latest");
        backend.provider_check_latest()
    };
    if !latest.is_valid() {
        result.error = format!(
            "cannot check latest Roblox for unsafe launch: {}",
            latest.error
        );
        return result;
    }

    let workspace_path = match create_workspace(&paths.cache_root.join("downloads/native-updater")) {
        Ok(p) => p,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    let _workspace_guard = TempWorkspaceGuard(workspace_path.clone());

    let exact = find_supported_profile(profiles, &latest.version_name, latest.version_code);
    let identity = ExpectedIdentityData {
        version_name: latest.version_name,
        version_code: latest.version_code,
        exact_build_id: exact.map(|p| p.elf_build_id.clone()),
    };
    let mut candidate = find_staged_candidate(paths, &identity, exact.is_some());
    if !candidate.is_valid() {
        candidate = download_candidate(
            backend,
            &identity,
            exact.is_some(),
            paths,
            &workspace_path.join("candidate"),
            request.progress_fd,
        );
    }
    if !candidate.is_valid() {
        result.error = format!(
            "cannot prepare latest Roblox for unsafe launch: {}",
            candidate.error
        );
        return result;
    }

    if !candidate.exact_supported {
        if let Err((rejected_derive, err)) = derive_candidate_host_abi(
            backend,
            paths,
            installed,
            profiles,
            &mut candidate,
            &workspace_path,
            &workspace_path.join("derived"),
            request.progress_fd,
            "Deriving latest Roblox compatibility...",
        ) {
            result.error = if rejected_derive {
                format!("cannot derive latest Roblox HostAbi profile: {err}")
            } else {
                format!("cannot prepare latest Roblox for unsafe launch: {err}")
            };
            return result;
        }
    }

    let launch = UnsafeLatestConfig {
        runtime_binary: runtime_binary_for_launch(paths),
        payload_directory: candidate.staged.payload_directory.clone(),
        compatibility_manifest: if candidate.exact_supported {
            paths.compatibility_manifest.clone()
        } else {
            candidate.compatibility.clone()
        },
        host_abi_profile: candidate.profile.clone(),
        inherited_environment: Vec::new(),
    };
    send_progress(request.progress_fd, "Launching unapproved latest Roblox...");
    let launched = run_unsafe_latest_candidate_internal(&launch);
    result.payload_id = candidate.staged.payload_id.clone();
    if !launched.error.is_empty() || launched.exit_code != 0 {
        result.error = format!(
            "unsafe latest Roblox {} did not complete: {}",
            candidate.staged.version_name, launched.error
        );
        return result;
    }
    result.message = format!(
        "unsafe latest Roblox {} exited successfully; active payload was not changed",
        candidate.staged.version_name
    );
    result
}

fn run_candidate_canaries(
    paths: &UpdatePathsData,
    candidate: &CandidateData,
    run_canary: bool,
    graphics_backend: i32,
    progress_fd: i32,
) -> Result<[PathBuf; 2], String> {
    if !run_canary {
        if !candidate.exact_supported {
            return Err("latest candidate cannot be activated without Tier C probation".to_string());
        }
        return Ok([PathBuf::new(), PathBuf::new()]);
    }
    let runs: usize = if candidate.exact_supported { 1 } else { 2 };
    let mut logs = [PathBuf::new(), PathBuf::new()];
    let compat_manifest = if candidate.exact_supported {
        paths.compatibility_manifest.clone()
    } else {
        candidate.compatibility.clone()
    };
    let runtime_bin = runtime_binary_for_launch(paths);

    for (index, log_slot) in logs.iter_mut().take(runs).enumerate() {
        let msg = if candidate.exact_supported {
            "Testing Roblox...".to_string()
        } else {
            format!("Testing latest Roblox ({}/2)...", index + 1)
        };
        send_progress(progress_fd, &msg);
        let config = CanaryRunConfig {
            runtime_binary: runtime_bin.clone(),
            payload_directory: candidate.staged.payload_directory.clone(),
            compatibility_manifest: compat_manifest.clone(),
            host_abi_profile: candidate.profile.clone(),
            cache_root: paths.cache_root.clone(),
            state_root: paths.state_root.clone(),
            graphics_backend,
            timeout_seconds: 150,
        };
        let canary_result = {
            let _timer = StageTimer::new(format!("canary[{}/{}]", index + 1, runs));
            run_readiness_canary(&config)
        };
        if !canary_result.is_ok() {
            let mut err = canary_result.error;
            if !canary_result.log_path.is_empty() {
                err.push_str("; log: ");
                err.push_str(&canary_result.log_path);
            }
            return Err(err);
        }
        *log_slot = PathBuf::from(&canary_result.log_path);
    }
    Ok(logs)
}

fn promote_candidate<B: UpdateBackend>(
    backend: &B,
    paths: &UpdatePathsData,
    request: &UpdateRequestData,
    candidate: &CandidateData,
) -> Result<CoordinatorStoreResult, String> {
    let logs = run_candidate_canaries(
        paths,
        candidate,
        request.run_canary,
        request.canary_graphics_backend,
        request.progress_fd,
    )?;
    send_progress(request.progress_fd, "Installing Roblox...");
    let _promote_timer = StageTimer::new("promote");
    let promoted = if candidate.exact_supported {
        backend.store_promote(&candidate.staged.payload_id)
    } else {
        backend.store_promote_probation(
            &candidate.staged.payload_id,
            &candidate.profile,
            &candidate.compatibility,
            [logs[0].as_path(), logs[1].as_path()],
        )
    };
    if !promoted.is_valid() {
        return Err(promoted.error);
    }
    Ok(promoted)
}

fn plan_description(plan: &CandidatePlanData) -> String {
    format!(
        "Roblox {} ({})",
        plan.identity.version_name, plan.identity.version_code
    )
}

fn reference_payload_ids(paths: &UpdatePathsData, profiles: &[SupportedProfile]) -> Vec<String> {
    let Some((idx, _)) =
        resolve_reference_profile_internal(&paths.host_abi_reference_profile, profiles)
    else {
        return Vec::new();
    };
    let reference = &profiles[idx];
    vec![format!(
        "{}-{}",
        reference.version_code, reference.elf_build_id
    )]
}

fn collect_superseded_payloads<B: UpdateBackend>(backend: &B, keep: &[String]) -> String {
    if trace_flag_enabled(b"MOCKTAIL_KEEP_OLD_PAYLOADS") {
        return String::new();
    }
    let collected = backend.store_collect_garbage(keep);
    if !collected.error.is_empty() || collected.removed_count == 0 {
        return String::new();
    }
    let freed_mib = collected.freed_bytes / (1024 * 1024);
    let plural = if collected.removed_count == 1 {
        ""
    } else {
        "s"
    };
    format!(
        "; freed {freed_mib} MiB from {} superseded payload{plural}",
        collected.removed_count
    )
}

fn run_update_internal<B: UpdateBackend>(
    paths: &UpdatePathsData,
    request: &UpdateRequestData,
    backend: &B,
) -> UpdateResultData {
    let mut result = UpdateResultData::default();
    let _total_timer = StageTimer::new("total");
    let _update_lock = match acquire_update_lock(&paths.data_root) {
        Ok(lock) => lock,
        Err(err) => {
            result.error = err;
            return result;
        }
    };

    let mut state = MocktailRustUpdateState::open(&paths.data_root.join("update.json"));
    let mut supported_version_code: u64 = 0;

    let finish = |state: &mut MocktailRustUpdateState,
                  mut result: UpdateResultData,
                  supported_version_code: u64|
     -> UpdateResultData {
        let active = backend.store_inspect_current();
        result.stale = state.finish_and_save(
            active.is_valid(),
            &active.payload_id,
            &active.version_name,
            active.version_code,
            supported_version_code,
            result.is_ok(),
            result.changed,
            &result.message,
            &result.error,
        );
        result
    };

    state.save_phase("checking");
    let configured = match load_update_config_file(&paths.config_file) {
        Ok(cfg) => {
            result.warnings = cfg.warnings.clone();
            cfg
        }
        Err(err) => {
            result.error = err;
            return finish(&mut state, result, supported_version_code);
        }
    };
    if configured.source != "apk-pure" && configured.source != "auto" {
        result.error = "native updater supports only the direct APK providers".to_string();
        return finish(&mut state, result, supported_version_code);
    }

    let catalog = match load_compatibility_catalog_file(&paths.compatibility_manifest, host_guest_abi())
    {
        Ok(profiles) => profiles,
        Err(err) => {
            result.error = err;
            return finish(&mut state, result, supported_version_code);
        }
    };
    let Some(preferred) = preferred_supported_profile(&catalog).cloned() else {
        result.error = "no preferred supported Roblox profile is available".to_string();
        return finish(&mut state, result, supported_version_code);
    };
    supported_version_code = preferred.version_code;

    let current = if request.download_only {
        backend.store_inspect_current()
    } else {
        backend.store_verify_current()
    };
    let mut installed = current.clone();
    if !current.is_valid()
        && !current.payload_id.is_empty()
        && !current.host_abi_profile.as_os_str().is_empty()
        && !current.compatibility_manifest.as_os_str().is_empty()
    {
        // Integrity was already checked. A receipt from an older runtime is still
        // a valid derivation reference, but it must pass probation again before it
        // can become runnable with this runtime.
        installed.error.clear();
    } else if !current.is_valid() {
        installed = backend.store_inspect_current();
    }

    if request.force_run_latest {
        let mut unsafe_res = run_unsafe_latest(backend, paths, request, &catalog, &installed);
        unsafe_res.warnings = std::mem::take(&mut result.warnings);
        return finish(&mut state, unsafe_res, supported_version_code);
    }

    if !configured.automatic && (request.startup_preflight || request.download_only) {
        state.save_phase("disabled");
        if current.is_valid() || request.download_only {
            result.payload_id = current.payload_id;
            result.message = "automatic Roblox updates are disabled".to_string();
        } else {
            result.error =
                "no runnable payload is installed and automatic updates are disabled".to_string();
        }
        return finish(&mut state, result, supported_version_code);
    }

    let mut latest_version: Option<ProviderVersionData> = None;
    if request.startup_preflight {
        state.set_metadata_status("deferred");
    }
    if request.check_latest && !request.startup_preflight {
        send_progress(request.progress_fd, "Checking Roblox...");
        let latest = {
            let _timer = StageTimer::new("check-latest");
            backend.provider_check_latest()
        };
        let valid = latest.is_valid();
        state.record_latest_check(valid, &latest.version_name, latest.version_code);
        if valid {
            latest_version = Some(latest);
        } else {
            result.warnings.push(format!(
                "update metadata is temporarily unavailable: {}",
                latest.error
            ));
        }
    }

    let mut downloaded = ProviderVersionData::default();
    let mut downloaded_payload_id = String::new();
    if let Some((ver_name, ver_code, pid)) = state.get_latest_downloaded() {
        downloaded.version_name = ver_name;
        downloaded.version_code = ver_code;
        downloaded_payload_id = pid;
    }

    if downloaded.is_valid()
        && latest_version
            .as_ref()
            .is_none_or(|v| downloaded.version_code > v.version_code)
        && (!request.startup_preflight
            || current.is_valid()
            || find_supported_profile(&catalog, &downloaded.version_name, downloaded.version_code)
                .is_some())
    {
        let identity = ExpectedIdentityData {
            version_name: downloaded.version_name.clone(),
            version_code: downloaded.version_code,
            exact_build_id: None,
        };
        if find_staged_candidate(paths, &identity, false).is_valid() {
            latest_version = Some(downloaded.clone());
        }
    }

    if request.download_only && latest_version.is_none() {
        result.payload_id = current.payload_id;
        result.message = "cannot discover a newer Roblox release".to_string();
        return finish(&mut state, result, supported_version_code);
    }

    if current.is_valid() {
        if let Some(latest_ver) = &latest_version {
            if current.version_code >= latest_ver.version_code
                && current.version_code >= preferred.version_code
            {
                result.payload_id = current.payload_id.clone();
                result.message = format!("Roblox {} is installed", current.version_name);
                if !request.download_only {
                    let mut keep = reference_payload_ids(paths, &catalog);
                    if downloaded.is_valid() && !downloaded_payload_id.is_empty() {
                        keep.push(downloaded_payload_id);
                    }
                    result.message.push_str(&collect_superseded_payloads(backend, &keep));
                }
                return finish(&mut state, result, supported_version_code);
            }
        }
    }

    let plans = plan_update_candidates_internal(
        &catalog,
        &preferred,
        latest_version.as_ref(),
        &current,
        &installed,
    );
    if plans.is_empty() {
        if !current.is_valid() {
            result.error = "no Roblox payload is available to install".to_string();
        } else {
            result.payload_id = current.payload_id;
            result.message = format!(
                "installed Roblox {} ({}) remains installed",
                current.version_name, current.version_code
            );
        }
        return finish(&mut state, result, supported_version_code);
    }

    let native_updater_cache = paths.cache_root.join("downloads/native-updater");
    remove_stale_workspaces(&native_updater_cache);
    let workspace = match create_workspace(&native_updater_cache) {
        Ok(w) => w,
        Err(err) => {
            result.error = err;
            return finish(&mut state, result, supported_version_code);
        }
    };
    let _workspace_guard = TempWorkspaceGuard(workspace.clone());

    let mut blocked = String::new();
    let mut attempt: usize = 0;
    let mut examined = reference_payload_ids(paths, &catalog);

    for plan in plans {
        let description = plan_description(&plan);
        attempt += 1;
        let mut candidate = if plan.reuse_installed {
            CandidateData {
                staged: installed.clone(),
                exact_supported: plan.exact_supported,
                profile: installed.host_abi_profile.clone(),
                compatibility: installed.compatibility_manifest.clone(),
                error: String::new(),
            }
        } else {
            let found = find_staged_candidate(paths, &plan.identity, plan.exact_supported);
            if found.is_valid() {
                found
            } else {
                state.save_phase("downloading");
                download_candidate(
                    backend,
                    &plan.identity,
                    plan.exact_supported,
                    paths,
                    &workspace.join(format!("candidate-{attempt}")),
                    request.progress_fd,
                )
            }
        };

        if !candidate.is_valid() {
            state.save_phase("blocked");
            blocked = format!("{description} could not be prepared: {}", candidate.error);
            continue;
        }

        examined.push(candidate.staged.payload_id.clone());
        state.record_latest_downloaded(
            &candidate.staged.payload_id,
            &candidate.staged.version_name,
            candidate.staged.version_code,
        );

        if request.download_only {
            result.payload_id = current.payload_id;
            result.message = format!(
                "Roblox {} is downloaded for the next launch",
                candidate.staged.version_name
            );
            state.save_phase("ready");
            return finish(&mut state, result, supported_version_code);
        }

        state.save_phase("verifying");
        let mut candidate_error = String::new();
        let mut candidate_rejected = false;

        if !candidate.exact_supported && candidate.profile.as_os_str().is_empty() {
            if let Err((rejected, err)) = derive_candidate_host_abi(
                backend,
                paths,
                &installed,
                &catalog,
                &mut candidate,
                &workspace,
                &workspace.join(format!("derived-{attempt}")),
                request.progress_fd,
                "Checking latest Roblox compatibility...",
            ) {
                candidate_rejected = rejected;
                candidate_error = err;
            }
        }

        let mut promoted = CoordinatorStoreResult::default();
        if candidate_error.is_empty() {
            match promote_candidate(backend, paths, request, &candidate) {
                Ok(p) => promoted = p,
                Err(err) => {
                    candidate_error = err;
                    candidate_rejected = true;
                }
            }
        }

        if candidate_error.is_empty() && promoted.is_valid() {
            result.changed =
                !current.is_valid() || current.payload_id != promoted.payload_id;
            result.payload_id = promoted.payload_id.clone();
            let mut msg = if candidate.exact_supported {
                format!(
                    "installed exact-supported Roblox {} ({})",
                    promoted.version_name, promoted.version_code
                )
            } else {
                format!(
                    "Roblox {} ({}) passed two {} graphics canaries and is current",
                    promoted.version_name,
                    promoted.version_code,
                    canary_backend_name_str(request.canary_graphics_backend)
                )
            };
            if !blocked.is_empty() {
                msg.push_str("; ");
                msg.push_str(&blocked);
            }
            msg.push_str(&collect_superseded_payloads(backend, &examined));
            result.message = msg;
            return finish(&mut state, result, supported_version_code);
        }

        if candidate_rejected {
            record_rejection(paths, &candidate, request.canary_graphics_backend, &candidate_error);
        }
        blocked = format!("{description} was rejected: {candidate_error}");
    }

    if !current.is_valid() {
        result.error = format!("no Roblox payload could be installed; {blocked}");
        return finish(&mut state, result, supported_version_code);
    }

    state.save_phase("blocked");
    result.payload_id = current.payload_id;
    result.stale = latest_version
        .as_ref()
        .is_some_and(|v| current.version_code < v.version_code);
    result.message = format!(
        "kept Roblox {} ({}); {blocked}",
        current.version_name, current.version_code
    );
    if result.stale {
        if let Some(v) = &latest_version {
            result.message.push_str(&format!(
                "; Roblox {} is published, so this session can be rejected as outdated",
                v.version_name
            ));
        }
    }
    finish(&mut state, result, supported_version_code)
}

// ============================================================================
// C ABI Entry Points
// ============================================================================

unsafe fn convert_profiles(
    profiles: *const MocktailRustSupportedProfileView,
    profile_count: usize,
) -> Vec<SupportedProfile> {
    if profiles.is_null() || profile_count == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(profiles, profile_count)
        .iter()
        .map(|p| SupportedProfile {
            version_name: slice_to_string(p.version_name),
            version_code: p.version_code,
            elf_build_id: slice_to_string(p.elf_build_id),
        })
        .collect()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_resolve_reference_profile(
    location: MocktailRustStrSlice,
    profiles: *const MocktailRustSupportedProfileView,
    profile_count: usize,
    on_match: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            profile_index: usize,
            sidecar_path: MocktailRustStrSlice,
        ),
    >,
    ctx: *mut c_void,
) -> bool {
    let loc_path = unsafe { slice_to_pathbuf(location) };
    if loc_path.as_os_str().is_empty() {
        return false;
    }
    let profile_vec = unsafe { convert_profiles(profiles, profile_count) };
    let Some((index, sidecar)) = resolve_reference_profile_internal(&loc_path, &profile_vec) else {
        return false;
    };
    if let Some(cb) = on_match {
        unsafe { cb(ctx, index, path_to_slice(&sidecar)) };
    }
    true
}

#[no_mangle]
pub extern "C" fn mocktail_rust_plan_update_candidates(
    profiles: *const MocktailRustSupportedProfileView,
    profile_count: usize,
    preferred: *const MocktailRustSupportedProfileView,
    has_latest: bool,
    latest_version_name: MocktailRustStrSlice,
    latest_version_code: u64,
    current: *const MocktailRustCoordinatorStoreResultView,
    installed: *const MocktailRustCoordinatorStoreResultView,
    on_plan: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            plan: *const MocktailRustUpdateCandidatePlanView,
        ),
    >,
    ctx: *mut c_void,
) {
    if preferred.is_null() || current.is_null() || installed.is_null() {
        return;
    }
    let profile_vec = unsafe { convert_profiles(profiles, profile_count) };
    let pref_view = unsafe { &*preferred };
    let pref = SupportedProfile {
        version_name: unsafe { slice_to_string(pref_view.version_name) },
        version_code: pref_view.version_code,
        elf_build_id: unsafe { slice_to_string(pref_view.elf_build_id) },
    };
    let latest_data = if has_latest {
        Some(ProviderVersionData {
            version_name: unsafe { slice_to_string(latest_version_name) },
            version_code: latest_version_code,
            error: String::new(),
        })
    } else {
        None
    };
    let current_data = unsafe { store_view_to_data(&*current) };
    let installed_data = unsafe { store_view_to_data(&*installed) };
    let plans = plan_update_candidates_internal(
        &profile_vec,
        &pref,
        latest_data.as_ref(),
        &current_data,
        &installed_data,
    );
    let Some(cb) = on_plan else {
        return;
    };
    for plan in &plans {
        let (has_exact, exact_slice) = opt_str_to_slice(plan.identity.exact_build_id.as_deref());
        let view = MocktailRustUpdateCandidatePlanView {
            version_name: MocktailRustStrSlice::from_str(&plan.identity.version_name),
            version_code: plan.identity.version_code,
            has_exact_build_id: has_exact,
            exact_build_id: exact_slice,
            exact_supported: plan.exact_supported,
            reuse_installed: plan.reuse_installed,
            origin: MocktailRustStrSlice::from_str(plan.origin),
        };
        unsafe { cb(ctx, &view) };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_run_unsafe_latest_candidate(
    options: *const MocktailRustUnsafeLatestOptions,
    on_result: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            exit_code: i32,
            error: MocktailRustStrSlice,
        ),
    >,
    ctx: *mut c_void,
) -> i32 {
    let Some(opts) = (unsafe { options.as_ref() }) else {
        return -1;
    };
    let mut inherited = Vec::new();
    if !opts.inherited_environment.is_null() && opts.inherited_environment_count > 0 {
        let entries = unsafe {
            std::slice::from_raw_parts(opts.inherited_environment, opts.inherited_environment_count)
        };
        for entry in entries {
            if entry.ptr.is_null() {
                continue;
            }
            let bytes = unsafe { std::slice::from_raw_parts(entry.ptr as *const u8, entry.len) };
            inherited.push(bytes.to_vec());
        }
    }
    let config = UnsafeLatestConfig {
        runtime_binary: unsafe { slice_to_pathbuf(opts.runtime_binary) },
        payload_directory: unsafe { slice_to_pathbuf(opts.payload_directory) },
        compatibility_manifest: unsafe { slice_to_pathbuf(opts.compatibility_manifest) },
        host_abi_profile: unsafe { slice_to_pathbuf(opts.host_abi_profile) },
        inherited_environment: inherited,
    };
    let outcome = run_unsafe_latest_candidate_internal(&config);
    if let Some(cb) = on_result {
        unsafe { cb(ctx, outcome.exit_code, MocktailRustStrSlice::from_str(&outcome.error)) };
    }
    if outcome.error.is_empty() && outcome.exit_code == 0 {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_run_update(
    paths: *const MocktailRustUpdatePathsView,
    request: *const MocktailRustUpdateRequestView,
    ops: *const MocktailRustUpdateCoordinatorOps,
    on_result: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            result: *const MocktailRustUpdateResultView,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(paths_view), Some(req_view), Some(ops_ref)) = (
        unsafe { paths.as_ref() },
        unsafe { request.as_ref() },
        unsafe { ops.as_ref() },
    ) else {
        return;
    };
    let paths_data = unsafe {
        UpdatePathsData {
            config_file: slice_to_pathbuf(paths_view.config_file),
            data_root: slice_to_pathbuf(paths_view.data_root),
            cache_root: slice_to_pathbuf(paths_view.cache_root),
            state_root: slice_to_pathbuf(paths_view.state_root),
            compatibility_manifest: slice_to_pathbuf(paths_view.compatibility_manifest),
            signing_trust_manifest: slice_to_pathbuf(paths_view.signing_trust_manifest),
            host_abi_reference_profile: slice_to_pathbuf(paths_view.host_abi_reference_profile),
            runtime_binary: slice_to_pathbuf(paths_view.runtime_binary),
            runtime_launcher: slice_to_pathbuf(paths_view.runtime_launcher),
        }
    };
    let request_data = UpdateRequestData {
        startup_preflight: req_view.startup_preflight,
        check_latest: req_view.check_latest,
        run_canary: req_view.run_canary,
        download_only: req_view.download_only,
        force_run_latest: req_view.force_run_latest,
        canary_graphics_backend: req_view.canary_graphics_backend,
        progress_fd: req_view.progress_fd,
    };
    let backend = FfiBackend { ops: ops_ref };
    let result = run_update_internal(&paths_data, &request_data, &backend);
    let Some(cb) = on_result else {
        return;
    };
    let warning_slices: Vec<MocktailRustStrSlice> = result
        .warnings
        .iter()
        .map(|w| MocktailRustStrSlice::from_str(w))
        .collect();
    let view = MocktailRustUpdateResultView {
        changed: result.changed,
        stale: result.stale,
        payload_id: MocktailRustStrSlice::from_str(&result.payload_id),
        message: MocktailRustStrSlice::from_str(&result.message),
        warnings: warning_slices.as_ptr(),
        warning_count: warning_slices.len(),
        error: MocktailRustStrSlice::from_str(&result.error),
    };
    unsafe { cb(ctx, &view) };
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness_canary::K_CANARY_BACKEND_DIRECT_VULKAN;
    use std::cell::RefCell;

    struct TempDirCleanup(PathBuf);
    impl Drop for TempDirCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_temp_dir(tag: &str) -> TempDirCleanup {
        let base = std::env::temp_dir().join("mocktail-update-coordinator-tests");
        let created = create_unique_temp_dir(&base, tag).unwrap();
        TempDirCleanup(created)
    }

    fn sample_profile(ver: &str, code: u64, ch: char) -> SupportedProfile {
        SupportedProfile {
            version_name: ver.to_string(),
            version_code: code,
            elf_build_id: ch.to_string().repeat(40),
        }
    }

    #[test]
    fn resolve_reference_profile_selects_newest_matching_sidecar() {
        let tmp = make_temp_dir("ref");
        let dir = &tmp.0;
        let older_bid = "a".repeat(40);
        let newer_bid = "b".repeat(40);
        let unknown_bid = "c".repeat(40);

        for (name, code, bid) in [
            ("older.json", 100u64, &older_bid),
            ("newer.json", 200u64, &newer_bid),
            ("unknown.json", 300u64, &unknown_bid),
        ] {
            let pid = format!("{code}-{bid}");
            let doc = serde_json::json!({
                "schema_version": 1,
                "elf_build_id": bid,
                "payload_id": pid,
                "payload_path": format!("payloads/{pid}"),
            });
            fs::write(dir.join(name), doc.to_string()).unwrap();
        }
        fs::write(dir.join("broken.json"), b"not-json").unwrap();

        let profiles = vec![
            sample_profile("1.0.0", 100, 'a'),
            sample_profile("2.0.0", 200, 'b'),
            sample_profile("4.0.0", 400, 'd'),
        ];
        let matched = resolve_reference_profile_internal(dir, &profiles).unwrap();
        assert_eq!(matched.0, 1);
        assert_eq!(matched.1, dir.join("newer.json"));
    }

    #[test]
    fn plan_update_candidates_orders_latest_before_preferred_and_skips_when_current() {
        let p_old = sample_profile("1.0.0", 100, 'a');
        let p_pref = sample_profile("2.0.0", 200, 'b');
        let profiles = vec![p_old.clone(), p_pref.clone()];

        let latest_probation = ProviderVersionData {
            version_name: "3.0.0".to_string(),
            version_code: 300,
            error: String::new(),
        };
        let empty = CoordinatorStoreResult::default();
        let plans = plan_update_candidates_internal(
            &profiles,
            &p_pref,
            Some(&latest_probation),
            &empty,
            &empty,
        );
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].identity.version_code, 300);
        assert!(!plans[0].exact_supported);
        assert_eq!(plans[0].origin, "provider latest");
        assert_eq!(plans[1].identity.version_code, 200);
        assert!(plans[1].exact_supported);
        assert_eq!(plans[1].origin, "supported catalog");

        let current_300 = CoordinatorStoreResult {
            payload_id: "300-x".to_string(),
            version_name: "3.0.0".to_string(),
            version_code: 300,
            ..Default::default()
        };
        assert!(plan_update_candidates_internal(
            &profiles,
            &p_pref,
            Some(&latest_probation),
            &current_300,
            &current_300,
        )
        .is_empty());

        let installed_probation = CoordinatorStoreResult {
            payload_id: "300-x".to_string(),
            version_name: "3.0.0".to_string(),
            version_code: 300,
            host_abi_profile: PathBuf::from("/tmp/p.json"),
            compatibility_manifest: PathBuf::from("/tmp/c.json"),
            ..Default::default()
        };
        let reverify_plans = plan_update_candidates_internal(
            &profiles,
            &p_pref,
            Some(&latest_probation),
            &empty,
            &installed_probation,
        );
        assert!(reverify_plans[0].reuse_installed);
    }

    #[test]
    fn unsafe_latest_runner_validates_files_and_builds_overridden_env() {
        let tmp = make_temp_dir("unsafe-runner");
        let dir = &tmp.0;
        let payload_dir = dir.join("payload");
        fs::create_dir_all(&payload_dir).unwrap();
        let runtime = dir.join("mocktail-runtime");
        fs::write(&runtime, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let compat = dir.join("compatibility.json");
        fs::write(&compat, b"{}").unwrap();

        let cfg = UnsafeLatestConfig {
            runtime_binary: runtime.clone(),
            payload_directory: payload_dir.clone(),
            compatibility_manifest: compat.clone(),
            host_abi_profile: PathBuf::new(),
            inherited_environment: vec![
                b"PATH=/usr/bin".to_vec(),
                b"MOCKTAIL_UNSAFE_LATEST=0".to_vec(),
                b"ROBLOX_LIB_PATH=/bad".to_vec(),
            ],
        };
        let err_missing_lib = run_unsafe_latest_candidate_internal(&cfg);
        assert_eq!(
            err_missing_lib.error,
            "unsafe latest payload library is not a regular file"
        );

        let built = build_unsafe_latest_environment(&UnsafeLatestConfig {
            host_abi_profile: compat.clone(),
            ..cfg
        })
        .unwrap();
        let strings: Vec<String> = built
            .into_iter()
            .map(|c| c.into_string().unwrap())
            .collect();
        assert!(strings.contains(&"PATH=/usr/bin".to_string()));
        assert!(!strings.contains(&"MOCKTAIL_UNSAFE_LATEST=0".to_string()));
        assert!(!strings.contains(&"ROBLOX_LIB_PATH=/bad".to_string()));
        assert!(strings.contains(&"MOCKTAIL_UNSAFE_LATEST=1".to_string()));
        assert!(strings.contains(&"MOCKTAIL_HOST_ABI_CANARY=1".to_string()));
    }

    struct MockBackend {
        current: RefCell<CoordinatorStoreResult>,
        latest: ProviderVersionData,
        fail_derive: bool,
        gc_called: RefCell<Option<Vec<String>>>,
    }

    impl UpdateBackend for MockBackend {
        fn provider_check_latest(&self) -> ProviderVersionData {
            self.latest.clone()
        }
        fn download_and_prepare(
            &self,
            identity: &ExpectedIdentityData,
            _download_directory: &Path,
            prepare_prefix: &Path,
            _signing_trust_manifest: &Path,
            _progress_fd: i32,
        ) -> Result<PathBuf, String> {
            let prep = prepare_prefix.join("prepare-1");
            fs::create_dir_all(&prep).unwrap();
            let bid = identity
                .exact_build_id
                .clone()
                .unwrap_or_else(|| "c".repeat(40));
            fs::write(prep.join(".mock_id"), format!("{}-{bid}|{}", identity.version_code, identity.version_name)).unwrap();
            Ok(prep)
        }
        fn derive_host_abi_profile(
            &self,
            _reference_library: &Path,
            _reference_profile: &Path,
            _reference_manifests: &[PathBuf],
            _candidate_payload_directory: &Path,
            output_directory: &Path,
        ) -> DerivedHostAbiData {
            if self.fail_derive {
                return DerivedHostAbiData {
                    error: "derived failure".to_string(),
                    ..Default::default()
                };
            }
            fs::create_dir_all(output_directory).unwrap();
            let p = output_directory.join("host_abi_profile.json");
            let c = output_directory.join("compatibility.json");
            fs::write(&p, b"{}").unwrap();
            fs::write(&c, b"{}").unwrap();
            DerivedHostAbiData {
                profile: p,
                compatibility_manifest: c,
                error: String::new(),
            }
        }
        fn store_inspect_current(&self) -> CoordinatorStoreResult {
            self.current.borrow().clone()
        }
        fn store_verify_current(&self) -> CoordinatorStoreResult {
            self.current.borrow().clone()
        }
        fn store_stage(&self, prepared_directory: &Path) -> CoordinatorStoreResult {
            let raw = fs::read_to_string(prepared_directory.join(".mock_id")).unwrap();
            let (pid, vname) = raw.split_once('|').unwrap();
            let (code_s, bid) = pid.split_once('-').unwrap();
            CoordinatorStoreResult {
                payload_id: pid.to_string(),
                payload_directory: prepared_directory.to_path_buf(),
                version_name: vname.to_string(),
                version_code: code_s.parse().unwrap(),
                build_id: bid.to_string(),
                ..Default::default()
            }
        }
        fn store_promote(&self, payload_id: &str) -> CoordinatorStoreResult {
            let (code_s, bid) = payload_id.split_once('-').unwrap();
            let res = CoordinatorStoreResult {
                payload_id: payload_id.to_string(),
                version_name: "2.0.0".to_string(),
                version_code: code_s.parse().unwrap(),
                build_id: bid.to_string(),
                ..Default::default()
            };
            *self.current.borrow_mut() = res.clone();
            res
        }
        fn store_promote_probation(
            &self,
            payload_id: &str,
            _candidate_profile: &Path,
            _candidate_compatibility: &Path,
            _canary_logs: [&Path; 2],
        ) -> CoordinatorStoreResult {
            self.store_promote(payload_id)
        }
        fn store_collect_garbage(&self, keep: &[String]) -> GarbageCollectData {
            *self.gc_called.borrow_mut() = Some(keep.to_vec());
            GarbageCollectData {
                removed_count: 1,
                freed_bytes: 5 * 1024 * 1024,
                error: String::new(),
            }
        }
    }

    #[test]
    fn run_update_installs_exact_supported_and_writes_update_json() {
        let tmp = make_temp_dir("run-update");
        let root = &tmp.0;
        let data_root = root.join("data");
        let cache_root = root.join("cache");
        let state_root = root.join("state");
        let bid = "b".repeat(40);
        let compat_path = root.join("compatibility.json");
        let compat = serde_json::json!({
            "schema_version": 1,
            "profiles": [{
                "status": "supported",
                "default_allowed": true,
                "allow_legacy_binary_patches": false,
                "abi": host_guest_abi(),
                "version_name": "2.0.0",
                "version_code": 200,
                "elf_build_id": bid,
            }]
        });
        fs::write(&compat_path, compat.to_string()).unwrap();

        let paths = UpdatePathsData {
            config_file: root.join("config.yaml"),
            data_root: data_root.clone(),
            cache_root,
            state_root,
            compatibility_manifest: compat_path,
            signing_trust_manifest: root.join("trust.json"),
            host_abi_reference_profile: root.join("refs"),
            runtime_binary: PathBuf::new(),
            runtime_launcher: PathBuf::new(),
        };
        let req = UpdateRequestData {
            startup_preflight: false,
            check_latest: true,
            run_canary: false,
            download_only: false,
            force_run_latest: false,
            canary_graphics_backend: K_CANARY_BACKEND_DIRECT_VULKAN,
            progress_fd: -1,
        };
        let backend = MockBackend {
            current: RefCell::new(CoordinatorStoreResult::default()),
            latest: ProviderVersionData {
                version_name: "2.0.0".to_string(),
                version_code: 200,
                error: String::new(),
            },
            fail_derive: false,
            gc_called: RefCell::new(None),
        };
        let res = run_update_internal(&paths, &req, &backend);
        assert!(res.is_ok(), "unexpected error: {}", res.error);
        assert!(res.changed);
        assert_eq!(res.payload_id, format!("200-{bid}"));
        assert!(res.message.contains("installed exact-supported Roblox 2.0.0 (200)"));
        assert!(res.message.contains("freed 5 MiB from 1 superseded payload"));
        assert!(data_root.join("update.json").is_file());
        assert!(backend.gc_called.borrow().is_some());
    }
}
