//! Immutable payload store management: `flock` locking, atomic manifests,
//! CoW/reflink (`FICLONE`) & `copy_file_range` tree staging, quarantine,
//! rollback, garbage collection, and activation/probation orchestration.

use std::ffi::{c_char, c_void, OsStr};
use std::fs::{self, Permissions};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage_paths::{
    build_activation_manifest_str, build_status_json_str, inspect_manifest_json_str,
    is_valid_payload_id_only, parse_manifest_identity_str, persist_payload_sha256_str,
};
use crate::unix_ipc::{
    current_pid, flock_fd, fsync_dir_path, last_errno, path_from_ffi, path_to_cstr, read_all_fd,
    slice_from_ffi, write_all_fd, OwnedFd,
};

const K_MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const K_COPY_FALLBACK_BUFFER_BYTES: usize = 256 * 1024;

static MANIFEST_GENERATION: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
pub struct MocktailRustPayloadInfoData {
    pub payload_id: *const c_char,
    pub payload_id_len: usize,
    pub package_name: *const c_char,
    pub package_name_len: usize,
    pub version_name: *const c_char,
    pub version_name_len: usize,
    pub version_code: u64,
    pub build_id: *const c_char,
    pub build_id_len: usize,
    pub library_sha256: *const c_char,
    pub library_sha256_len: usize,
    pub base_apk_sha256: *const c_char,
    pub base_apk_sha256_len: usize,
    pub split_apk_sha256: *const c_char,
    pub split_apk_sha256_len: usize,
    pub asset_file_count: usize,
    pub asset_tree_sha256: *const c_char,
    pub asset_tree_sha256_len: usize,
    pub error: *const c_char,
    pub error_len: usize,
}

#[repr(C)]
pub struct MocktailRustCandidateApprovalData {
    pub generation: *const c_char,
    pub generation_len: usize,
    pub profile: *const c_char,
    pub profile_len: usize,
    pub compatibility_manifest: *const c_char,
    pub compatibility_manifest_len: usize,
    pub receipt: *const c_char,
    pub receipt_len: usize,
    pub error: *const c_char,
    pub error_len: usize,
}

#[repr(C)]
pub struct MocktailRustPayloadStorePaths {
    pub root_ptr: *const c_char,
    pub root_len: usize,
    pub compatibility_manifest_ptr: *const c_char,
    pub compatibility_manifest_len: usize,
    pub runtime_binary_ptr: *const c_char,
    pub runtime_binary_len: usize,
}

#[repr(C)]
pub struct MocktailRustPayloadStoreResultData {
    pub payload_id: *const c_char,
    pub payload_id_len: usize,
    pub payload_directory: *const c_char,
    pub payload_directory_len: usize,
    pub host_abi_profile: *const c_char,
    pub host_abi_profile_len: usize,
    pub compatibility_manifest: *const c_char,
    pub compatibility_manifest_len: usize,
    pub approval_receipt: *const c_char,
    pub approval_receipt_len: usize,
    pub version_name: *const c_char,
    pub version_name_len: usize,
    pub version_code: u64,
    pub build_id: *const c_char,
    pub build_id_len: usize,
    pub error: *const c_char,
    pub error_len: usize,
}

pub type MocktailRustPayloadInfoReceiver = Option<
    unsafe extern "C" fn(receiver_ctx: *mut c_void, info: *const MocktailRustPayloadInfoData),
>;

pub type MocktailRustCandidateApprovalReceiver = Option<
    unsafe extern "C" fn(
        receiver_ctx: *mut c_void,
        approval: *const MocktailRustCandidateApprovalData,
    ),
>;

pub type MocktailRustPayloadStoreStrReceiver =
    Option<unsafe extern "C" fn(receiver_ctx: *mut c_void, ptr: *const c_char, len: usize)>;

pub type MocktailRustPayloadStoreResultCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustPayloadStoreResultData),
>;

#[repr(C)]
pub struct MocktailRustPayloadStoreOps {
    pub ctx: *mut c_void,
    pub inspect_prepared_payload: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            dir_ptr: *const c_char,
            dir_len: usize,
            receiver_ctx: *mut c_void,
            receiver: MocktailRustPayloadInfoReceiver,
        ),
    >,
    pub verify_prepared_payload: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            dir_ptr: *const c_char,
            dir_len: usize,
            receiver_ctx: *mut c_void,
            receiver: MocktailRustPayloadInfoReceiver,
        ),
    >,
    pub hash_regular_file: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            path_ptr: *const c_char,
            path_len: usize,
            receiver_ctx: *mut c_void,
            on_hash: MocktailRustPayloadStoreStrReceiver,
            on_error: MocktailRustPayloadStoreStrReceiver,
        ),
    >,
    pub exact_supported: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            compat_ptr: *const c_char,
            compat_len: usize,
            payload: *const MocktailRustPayloadInfoData,
            receiver_ctx: *mut c_void,
            on_error: MocktailRustPayloadStoreStrReceiver,
        ) -> bool,
    >,
    pub create_candidate_approval: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            store_root_ptr: *const c_char,
            store_root_len: usize,
            payload_dir_ptr: *const c_char,
            payload_dir_len: usize,
            profile_ptr: *const c_char,
            profile_len: usize,
            compat_ptr: *const c_char,
            compat_len: usize,
            runtime_binary_ptr: *const c_char,
            runtime_binary_len: usize,
            canary0_ptr: *const c_char,
            canary0_len: usize,
            canary1_ptr: *const c_char,
            canary1_len: usize,
            verified_payload: *const MocktailRustPayloadInfoData,
            receiver_ctx: *mut c_void,
            receiver: MocktailRustCandidateApprovalReceiver,
        ),
    >,
    pub validate_candidate_approval: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            store_root_ptr: *const c_char,
            store_root_len: usize,
            activation_json_ptr: *const c_char,
            activation_json_len: usize,
            payload: *const MocktailRustPayloadInfoData,
            receiver_ctx: *mut c_void,
            receiver: MocktailRustCandidateApprovalReceiver,
        ) -> bool,
    >,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PayloadInfo {
    pub payload_id: String,
    pub package_name: String,
    pub version_name: String,
    pub version_code: u64,
    pub build_id: String,
    pub library_sha256: String,
    pub base_apk_sha256: String,
    pub split_apk_sha256: String,
    pub asset_file_count: usize,
    pub asset_tree_sha256: String,
    pub error: String,
}

impl PayloadInfo {
    fn is_ok(&self) -> bool {
        self.error.is_empty()
    }

    fn as_ffi(&self) -> MocktailRustPayloadInfoData {
        MocktailRustPayloadInfoData {
            payload_id: self.payload_id.as_ptr().cast::<c_char>(),
            payload_id_len: self.payload_id.len(),
            package_name: self.package_name.as_ptr().cast::<c_char>(),
            package_name_len: self.package_name.len(),
            version_name: self.version_name.as_ptr().cast::<c_char>(),
            version_name_len: self.version_name.len(),
            version_code: self.version_code,
            build_id: self.build_id.as_ptr().cast::<c_char>(),
            build_id_len: self.build_id.len(),
            library_sha256: self.library_sha256.as_ptr().cast::<c_char>(),
            library_sha256_len: self.library_sha256.len(),
            base_apk_sha256: self.base_apk_sha256.as_ptr().cast::<c_char>(),
            base_apk_sha256_len: self.base_apk_sha256.len(),
            split_apk_sha256: self.split_apk_sha256.as_ptr().cast::<c_char>(),
            split_apk_sha256_len: self.split_apk_sha256.len(),
            asset_file_count: self.asset_file_count,
            asset_tree_sha256: self.asset_tree_sha256.as_ptr().cast::<c_char>(),
            asset_tree_sha256_len: self.asset_tree_sha256.len(),
            error: self.error.as_ptr().cast::<c_char>(),
            error_len: self.error.len(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CandidateApprovalInfo {
    pub generation: String,
    pub profile: PathBuf,
    pub compatibility_manifest: PathBuf,
    pub receipt: PathBuf,
    pub error: String,
}

impl CandidateApprovalInfo {
    fn is_ok(&self) -> bool {
        self.error.is_empty() && !self.generation.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct StoreResult {
    pub payload_id: String,
    pub payload_directory: PathBuf,
    pub host_abi_profile: PathBuf,
    pub compatibility_manifest: PathBuf,
    pub approval_receipt: PathBuf,
    pub version_name: String,
    pub version_code: u64,
    pub build_id: String,
    pub error: String,
}

impl StoreResult {
    pub(crate) fn is_ok(&self) -> bool {
        self.error.is_empty() && !self.payload_id.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GarbageResult {
    pub removed: Vec<String>,
    pub freed_bytes: u64,
    pub error: String,
}

pub(crate) trait StoreCallbacks {
    fn inspect_prepared_payload(&self, dir: &Path) -> PayloadInfo;
    fn verify_prepared_payload(&self, dir: &Path) -> PayloadInfo;
    fn hash_regular_file(&self, path: &Path) -> Result<String, String>;
    fn exact_supported(&self, compatibility: &Path, payload: &PayloadInfo) -> Result<(), String>;
    fn create_candidate_approval(
        &self,
        store_root: &Path,
        payload_dir: &Path,
        profile: &Path,
        compatibility_manifest: &Path,
        runtime_binary: &Path,
        canary_logs: [&Path; 2],
        verified_payload: &PayloadInfo,
    ) -> CandidateApprovalInfo;
    fn validate_candidate_approval(
        &self,
        store_root: &Path,
        activation_json: &str,
        payload: &PayloadInfo,
    ) -> Result<CandidateApprovalInfo, String>;
}

unsafe fn lossy_str<'a>(ptr: *const c_char, len: usize) -> std::borrow::Cow<'a, str> {
    String::from_utf8_lossy(slice_from_ffi(ptr, len))
}

unsafe extern "C" fn receive_payload_info(
    receiver_ctx: *mut c_void,
    info: *const MocktailRustPayloadInfoData,
) {
    if receiver_ctx.is_null() || info.is_null() {
        return;
    }
    let out = &mut *(receiver_ctx as *mut PayloadInfo);
    let d = &*info;
    out.payload_id = lossy_str(d.payload_id, d.payload_id_len).into_owned();
    out.package_name = lossy_str(d.package_name, d.package_name_len).into_owned();
    out.version_name = lossy_str(d.version_name, d.version_name_len).into_owned();
    out.version_code = d.version_code;
    out.build_id = lossy_str(d.build_id, d.build_id_len).into_owned();
    out.library_sha256 = lossy_str(d.library_sha256, d.library_sha256_len).into_owned();
    out.base_apk_sha256 = lossy_str(d.base_apk_sha256, d.base_apk_sha256_len).into_owned();
    out.split_apk_sha256 = lossy_str(d.split_apk_sha256, d.split_apk_sha256_len).into_owned();
    out.asset_file_count = d.asset_file_count;
    out.asset_tree_sha256 = lossy_str(d.asset_tree_sha256, d.asset_tree_sha256_len).into_owned();
    out.error = lossy_str(d.error, d.error_len).into_owned();
}

unsafe extern "C" fn receive_candidate_approval(
    receiver_ctx: *mut c_void,
    approval: *const MocktailRustCandidateApprovalData,
) {
    if receiver_ctx.is_null() || approval.is_null() {
        return;
    }
    let out = &mut *(receiver_ctx as *mut CandidateApprovalInfo);
    let d = &*approval;
    out.generation = lossy_str(d.generation, d.generation_len).into_owned();
    out.profile = PathBuf::from(OsStr::from_bytes(slice_from_ffi(d.profile, d.profile_len)));
    out.compatibility_manifest = PathBuf::from(OsStr::from_bytes(slice_from_ffi(
        d.compatibility_manifest,
        d.compatibility_manifest_len,
    )));
    out.receipt = PathBuf::from(OsStr::from_bytes(slice_from_ffi(d.receipt, d.receipt_len)));
    out.error = lossy_str(d.error, d.error_len).into_owned();
}

unsafe extern "C" fn receive_string(receiver_ctx: *mut c_void, ptr: *const c_char, len: usize) {
    if receiver_ctx.is_null() {
        return;
    }
    let out = &mut *(receiver_ctx as *mut String);
    *out = lossy_str(ptr, len).into_owned();
}

struct FfiStoreCallbacks<'a> {
    ops: &'a MocktailRustPayloadStoreOps,
}

impl StoreCallbacks for FfiStoreCallbacks<'_> {
    fn inspect_prepared_payload(&self, dir: &Path) -> PayloadInfo {
        let mut info = PayloadInfo::default();
        let Some(cb) = self.ops.inspect_prepared_payload else {
            info.error = "missing inspect_prepared_payload callback".to_owned();
            return info;
        };
        let bytes = dir.as_os_str().as_bytes();
        unsafe {
            cb(
                self.ops.ctx,
                bytes.as_ptr().cast::<c_char>(),
                bytes.len(),
                (&mut info as *mut PayloadInfo).cast::<c_void>(),
                Some(receive_payload_info),
            );
        }
        info
    }

    fn verify_prepared_payload(&self, dir: &Path) -> PayloadInfo {
        let mut info = PayloadInfo::default();
        let Some(cb) = self.ops.verify_prepared_payload else {
            info.error = "missing verify_prepared_payload callback".to_owned();
            return info;
        };
        let bytes = dir.as_os_str().as_bytes();
        unsafe {
            cb(
                self.ops.ctx,
                bytes.as_ptr().cast::<c_char>(),
                bytes.len(),
                (&mut info as *mut PayloadInfo).cast::<c_void>(),
                Some(receive_payload_info),
            );
        }
        info
    }

    fn hash_regular_file(&self, path: &Path) -> Result<String, String> {
        let Some(cb) = self.ops.hash_regular_file else {
            return Err("missing hash_regular_file callback".to_owned());
        };
        let mut hash = String::new();
        let mut err = String::new();
        let mut pair = (&mut hash, &mut err);
        unsafe extern "C" fn on_hash(ctx: *mut c_void, ptr: *const c_char, len: usize) {
            let pair = &mut *(ctx as *mut (&mut String, &mut String));
            *pair.0 = lossy_str(ptr, len).into_owned();
        }
        unsafe extern "C" fn on_error(ctx: *mut c_void, ptr: *const c_char, len: usize) {
            let pair = &mut *(ctx as *mut (&mut String, &mut String));
            *pair.1 = lossy_str(ptr, len).into_owned();
        }
        let bytes = path.as_os_str().as_bytes();
        unsafe {
            cb(
                self.ops.ctx,
                bytes.as_ptr().cast::<c_char>(),
                bytes.len(),
                (&mut pair as *mut (&mut String, &mut String)).cast::<c_void>(),
                Some(on_hash),
                Some(on_error),
            );
        }
        if err.is_empty() {
            Ok(hash)
        } else {
            Err(err)
        }
    }

    fn exact_supported(&self, compatibility: &Path, payload: &PayloadInfo) -> Result<(), String> {
        let Some(cb) = self.ops.exact_supported else {
            return Err("missing exact_supported callback".to_owned());
        };
        let mut err = String::new();
        let bytes = compatibility.as_os_str().as_bytes();
        let ffi_payload = payload.as_ffi();
        let ok = unsafe {
            cb(
                self.ops.ctx,
                bytes.as_ptr().cast::<c_char>(),
                bytes.len(),
                &ffi_payload,
                (&mut err as *mut String).cast::<c_void>(),
                Some(receive_string),
            )
        };
        if ok {
            Ok(())
        } else {
            Err(err)
        }
    }

    fn create_candidate_approval(
        &self,
        store_root: &Path,
        payload_dir: &Path,
        profile: &Path,
        compatibility_manifest: &Path,
        runtime_binary: &Path,
        canary_logs: [&Path; 2],
        verified_payload: &PayloadInfo,
    ) -> CandidateApprovalInfo {
        let mut approval = CandidateApprovalInfo::default();
        let Some(cb) = self.ops.create_candidate_approval else {
            approval.error = "missing create_candidate_approval callback".to_owned();
            return approval;
        };
        let sr = store_root.as_os_str().as_bytes();
        let pd = payload_dir.as_os_str().as_bytes();
        let pr = profile.as_os_str().as_bytes();
        let cm = compatibility_manifest.as_os_str().as_bytes();
        let rb = runtime_binary.as_os_str().as_bytes();
        let c0 = canary_logs[0].as_os_str().as_bytes();
        let c1 = canary_logs[1].as_os_str().as_bytes();
        let ffi_payload = verified_payload.as_ffi();
        unsafe {
            cb(
                self.ops.ctx,
                sr.as_ptr().cast::<c_char>(),
                sr.len(),
                pd.as_ptr().cast::<c_char>(),
                pd.len(),
                pr.as_ptr().cast::<c_char>(),
                pr.len(),
                cm.as_ptr().cast::<c_char>(),
                cm.len(),
                rb.as_ptr().cast::<c_char>(),
                rb.len(),
                c0.as_ptr().cast::<c_char>(),
                c0.len(),
                c1.as_ptr().cast::<c_char>(),
                c1.len(),
                &ffi_payload,
                (&mut approval as *mut CandidateApprovalInfo).cast::<c_void>(),
                Some(receive_candidate_approval),
            );
        }
        approval
    }

    fn validate_candidate_approval(
        &self,
        store_root: &Path,
        activation_json: &str,
        payload: &PayloadInfo,
    ) -> Result<CandidateApprovalInfo, String> {
        let Some(cb) = self.ops.validate_candidate_approval else {
            return Err("missing validate_candidate_approval callback".to_owned());
        };
        let mut approval = CandidateApprovalInfo::default();
        let sr = store_root.as_os_str().as_bytes();
        let ffi_payload = payload.as_ffi();
        let ok = unsafe {
            cb(
                self.ops.ctx,
                sr.as_ptr().cast::<c_char>(),
                sr.len(),
                activation_json.as_ptr().cast::<c_char>(),
                activation_json.len(),
                &ffi_payload,
                (&mut approval as *mut CandidateApprovalInfo).cast::<c_void>(),
                Some(receive_candidate_approval),
            )
        };
        if ok {
            Ok(approval)
        } else {
            Err(approval.error)
        }
    }
}

struct StoreLock {
    _fd: OwnedFd,
}

impl StoreLock {
    fn acquire(root: &Path) -> Result<Self, String> {
        if fs::create_dir_all(root.join("payloads")).is_err() {
            return Err("cannot create payload store".to_owned());
        }
        let lock_path = root.join(".payload-store.lock");
        let Some(lock_c) = path_to_cstr(&lock_path) else {
            return Err("cannot lock payload store".to_owned());
        };
        let raw_fd = unsafe {
            libc::open(
                lock_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600 as libc::mode_t,
            )
        };
        let Some(fd) = OwnedFd::from_raw(raw_fd) else {
            return Err("cannot lock payload store".to_owned());
        };
        if !flock_fd(fd.as_raw(), libc::LOCK_EX) {
            return Err("cannot lock payload store".to_owned());
        }
        Ok(Self { _fd: fd })
    }
}

fn read_regular(path: &Path, maximum: usize, missing_ok: bool) -> Result<Vec<u8>, String> {
    let Some(cpath) = path_to_cstr(path) else {
        return Err(format!("cannot open payload-store file: {}", path.display()));
    };
    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw_fd < 0 {
        if missing_ok && last_errno() == libc::ENOENT {
            return Ok(Vec::new());
        }
        return Err(format!("cannot open payload-store file: {}", path.display()));
    }
    let fd = OwnedFd::from_raw(raw_fd).expect("raw_fd >= 0");
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd.as_raw(), st.as_mut_ptr()) } != 0 {
        return Err("payload-store file is not a bounded regular file".to_owned());
    }
    let st = unsafe { st.assume_init() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
        || (st.st_size as u64) > (maximum as u64)
    {
        return Err("payload-store file is not a bounded regular file".to_owned());
    }
    read_all_fd(fd.as_raw(), st.st_size as usize)
        .map_err(|_| "cannot read payload-store file".to_owned())
}

fn write_atomic(root: &Path, destination: &Path, contents: &str) -> Result<(), String> {
    let generation = MANIFEST_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let temporary = root.join(format!(".manifest-{}-{generation}", current_pid()));
    let Some(temp_c) = path_to_cstr(&temporary) else {
        return Err("cannot create atomic payload manifest".to_owned());
    };
    let raw_fd = unsafe {
        libc::open(
            temp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o644 as libc::mode_t,
        )
    };
    let Some(fd) = OwnedFd::from_raw(raw_fd) else {
        return Err("cannot create atomic payload manifest".to_owned());
    };
    if !write_all_fd(fd.as_raw(), contents.as_bytes()) {
        drop(fd);
        let _ = fs::remove_file(&temporary);
        return Err("cannot write atomic payload manifest".to_owned());
    }
    let synced = unsafe { libc::fsync(fd.as_raw()) } == 0;
    drop(fd);
    if !synced {
        let _ = fs::remove_file(&temporary);
        return Err("cannot persist atomic payload manifest".to_owned());
    }
    if fs::rename(&temporary, destination).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("cannot publish atomic payload manifest".to_owned());
    }
    let _ = fsync_dir_path(root, false);
    Ok(())
}

// CopyTree publishes payloads read-only, so the directories have to be made
// writable again before anything in them can be unlinked.
fn remove_payload_tree(payload: &Path, mut freed_bytes: Option<&mut u64>) -> bool {
    let root_meta = match fs::symlink_metadata(payload) {
        Ok(m) => m,
        Err(err) if err.kind() == ErrorKind::NotFound => return true,
        Err(_) => return false,
    };

    if root_meta.file_type().is_symlink() || !root_meta.file_type().is_dir() {
        let len = if root_meta.file_type().is_file() {
            root_meta.len()
        } else {
            0
        };
        if fs::remove_file(payload).is_ok() {
            if let Some(out) = freed_bytes {
                *out += len;
            }
            return true;
        }
        return false;
    }

    let mut bytes = 0u64;
    let mut stack = vec![payload.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(meta) = fs::symlink_metadata(&dir) {
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                let mode = meta.permissions().mode();
                let _ = fs::set_permissions(&dir, Permissions::from_mode(mode | 0o200));
            }
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(meta) = fs::symlink_metadata(&path) {
                    if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                        stack.push(path);
                    } else if meta.file_type().is_file() {
                        bytes += meta.len();
                    }
                }
            }
        }
    }

    if fs::remove_dir_all(payload).is_err() {
        return false;
    }
    if let Some(out) = freed_bytes.as_deref_mut() {
        *out += bytes;
    }
    true
}

fn same_payload_content(left: &PayloadInfo, right: &PayloadInfo) -> bool {
    left.library_sha256 == right.library_sha256
        && left.base_apk_sha256 == right.base_apk_sha256
        && left.split_apk_sha256 == right.split_apk_sha256
        && left.asset_tree_sha256 == right.asset_tree_sha256
        && left.asset_file_count == right.asset_file_count
}

fn timestamp_suffix() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}-{}", current_pid())
}

fn quarantine_payload_collision(root: &Path, payload: &Path, payload_id: &str) -> Result<(), String> {
    let quarantine = root
        .join("quarantine")
        .join(format!("{payload_id}-{}", timestamp_suffix()));
    let Some(quarantine_parent) = quarantine.parent() else {
        return Err("cannot create corrupt payload quarantine: missing parent".to_owned());
    };
    if let Err(err) = fs::create_dir_all(quarantine_parent) {
        return Err(format!("cannot create corrupt payload quarantine: {err}"));
    }

    let status = match fs::symlink_metadata(payload) {
        Ok(s) => s,
        Err(err) => return Err(format!("cannot inspect corrupt payload collision: {err}")),
    };
    let original_mode = status.permissions().mode();
    let read_only_directory = status.file_type().is_dir()
        && !status.file_type().is_symlink()
        && (original_mode & 0o200) == 0;
    if read_only_directory {
        // Moving a directory across parents updates its `..` entry. Linux denies
        // that operation for the read-only roots intentionally produced by
        // CopyTree, so briefly restore owner-write only on the collision root.
        if let Err(err) =
            fs::set_permissions(payload, Permissions::from_mode(original_mode | 0o200))
        {
            return Err(format!("cannot unlock corrupt payload collision: {err}"));
        }
    }

    if let Err(err) = fs::rename(payload, &quarantine) {
        if read_only_directory {
            let _ = fs::set_permissions(payload, Permissions::from_mode(original_mode));
        }
        return Err(format!("cannot quarantine corrupt payload collision: {err}"));
    }
    if read_only_directory {
        let _ = fs::set_permissions(&quarantine, Permissions::from_mode(original_mode));
    }
    Ok(())
}

// A payload tree is several hundred MiB. On a copy-on-write filesystem a
// reflink shares the extents instead of duplicating them, and copy_file_range
// keeps the bytes inside the kernel; both fall back to an ordinary copy.
// A hard link is deliberately not used: CopyTree makes the result read-only
// while the source stays writable, and a shared inode would break that.
fn clone_or_copy_file(source: &Path, destination: &Path) -> bool {
    let (Some(src_c), Some(dst_c)) = (path_to_cstr(source), path_to_cstr(destination)) else {
        return false;
    };
    let in_raw = unsafe {
        libc::open(
            src_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let Some(input) = OwnedFd::from_raw(in_raw) else {
        return false;
    };
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(input.as_raw(), metadata.as_mut_ptr()) } != 0 {
        return false;
    }
    let metadata = unsafe { metadata.assume_init() };
    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG || metadata.st_size < 0 {
        return false;
    }

    let output: RawFd = unsafe {
        libc::open(
            dst_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };
    if output < 0 {
        return false;
    }

    let cleanup_failure = |out_fd: RawFd| {
        unsafe { libc::close(out_fd) };
        let _ = fs::remove_file(destination);
    };

    #[cfg(target_os = "linux")]
    let mut copied = {
        let mut cloned_meta = MaybeUninit::<libc::stat>::zeroed();
        unsafe {
            libc::ioctl(output, libc::FICLONE, input.as_raw()) == 0
                && libc::fstat(output, cloned_meta.as_mut_ptr()) == 0
                && cloned_meta.assume_init().st_size == metadata.st_size
        }
    };
    #[cfg(not(target_os = "linux"))]
    let copied = false;

    #[cfg(target_os = "linux")]
    if !copied {
        let mut remaining = metadata.st_size;
        copied = true;
        while remaining > 0 {
            let moved = unsafe {
                libc::copy_file_range(
                    input.as_raw(),
                    std::ptr::null_mut(),
                    output,
                    std::ptr::null_mut(),
                    remaining as libc::size_t,
                    0,
                )
            };
            if moved < 0 && last_errno() == libc::EINTR {
                continue;
            }
            if moved <= 0 {
                copied = false;
                break;
            }
            remaining -= moved as libc::off_t;
        }
        // copy_file_range advances both file offsets, so a partial move must be
        // undone completely before the portable fallback can start from zero.
        if !copied
            && unsafe {
                libc::ftruncate(output, 0) != 0
                    || libc::lseek(input.as_raw(), 0, libc::SEEK_SET) != 0
                    || libc::lseek(output, 0, libc::SEEK_SET) != 0
            }
        {
            cleanup_failure(output);
            return false;
        }
    }

    if !copied {
        let mut buffer = vec![0u8; K_COPY_FALLBACK_BUFFER_BYTES];
        loop {
            let bytes = unsafe {
                libc::read(
                    input.as_raw(),
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len(),
                )
            };
            if bytes == 0 {
                break;
            }
            if bytes < 0 {
                if last_errno() == libc::EINTR {
                    continue;
                }
                cleanup_failure(output);
                return false;
            }
            if !write_all_fd(output, &buffer[..bytes as usize]) {
                cleanup_failure(output);
                return false;
            }
        }
    }

    drop(input);
    if unsafe { libc::close(output) } != 0 {
        let _ = fs::remove_file(destination);
        return false;
    }
    true
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), &'static str> {
    if fs::create_dir(destination).is_err() {
        return Err("cannot create immutable payload staging directory");
    }

    let mut stack = vec![(source.to_path_buf(), destination.to_path_buf())];
    let mut created_dirs = Vec::new();
    let mut created_files = Vec::new();

    while let Some((src_dir, dst_dir)) = stack.pop() {
        let entries = fs::read_dir(&src_dir).map_err(|_| "cannot copy payload into immutable store")?;
        for entry in entries {
            let entry = entry.map_err(|_| "cannot copy payload into immutable store")?;
            let src_path = entry.path();
            let dst_path = dst_dir.join(entry.file_name());
            let meta =
                fs::symlink_metadata(&src_path).map_err(|_| "cannot copy payload into immutable store")?;
            let ftype = meta.file_type();
            if ftype.is_symlink() || (!ftype.is_dir() && !ftype.is_file()) {
                return Err("payload tree contains an unsafe entry");
            }
            if ftype.is_dir() {
                fs::create_dir(&dst_path).map_err(|_| "cannot copy payload into immutable store")?;
                created_dirs.push(dst_path.clone());
                stack.push((src_path, dst_path));
            } else {
                if !clone_or_copy_file(&src_path, &dst_path)
                    && fs::copy(&src_path, &dst_path).is_err()
                {
                    return Err("cannot copy payload into immutable store");
                }
                created_files.push(dst_path);
            }
        }
    }

    for file in &created_files {
        if fs::set_permissions(file, Permissions::from_mode(0o444)).is_err() {
            return Err("cannot make staged payload immutable");
        }
    }
    for dir in created_dirs.iter().rev() {
        if fs::set_permissions(dir, Permissions::from_mode(0o555)).is_err() {
            return Err("cannot make staged payload immutable");
        }
    }
    if fs::set_permissions(destination, Permissions::from_mode(0o555)).is_err() {
        return Err("cannot make staged payload immutable");
    }
    Ok(())
}

#[derive(Default)]
struct ManifestIdentity {
    payload_id: String,
    contents: String,
    error: String,
}

impl ManifestIdentity {
    fn is_ok(&self) -> bool {
        self.error.is_empty() && !self.payload_id.is_empty()
    }
}

fn read_manifest(path: &Path, missing_ok: bool) -> ManifestIdentity {
    let mut result = ManifestIdentity::default();
    let bytes = match read_regular(path, K_MAX_MANIFEST_BYTES, missing_ok) {
        Ok(b) => b,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    if bytes.is_empty() {
        return result;
    }
    let Ok(text) = String::from_utf8(bytes) else {
        result.error = "active payload manifest is invalid".to_owned();
        return result;
    };
    result.contents = text;
    match parse_manifest_identity_str(&result.contents) {
        Ok(id) => result.payload_id = id,
        Err((opt_id, msg)) => {
            if let Some(id) = opt_id {
                result.payload_id = id;
            }
            result.error = msg.to_owned();
        }
    }
    result
}

fn populate_inspected_result(
    root: &Path,
    manifest: &ManifestIdentity,
    callbacks: &dyn StoreCallbacks,
    result: &mut StoreResult,
) -> Option<PayloadInfo> {
    result.payload_id = manifest.payload_id.clone();
    result.payload_directory = root.join("payloads").join(&result.payload_id);
    let payload = callbacks.inspect_prepared_payload(&result.payload_directory);
    if !payload.is_ok() || payload.payload_id != result.payload_id {
        result.error = if payload.is_ok() {
            "current payload identity mismatch".to_owned()
        } else {
            payload.error
        };
        return None;
    }
    result.version_name = payload.version_name.clone();
    result.version_code = payload.version_code;
    result.build_id = payload.build_id.clone();

    match inspect_manifest_json_str(
        &manifest.contents,
        &payload.version_name,
        payload.version_code,
        &payload.build_id,
        &payload.library_sha256,
    ) {
        Ok(Some(paths)) => {
            result.host_abi_profile = root.join(paths.profile);
            result.compatibility_manifest = root.join(paths.compatibility);
            result.approval_receipt = root.join(paths.receipt);
        }
        Ok(None) => {}
        Err(msg) => {
            result.error = msg.to_owned();
            return None;
        }
    }

    Some(payload)
}

fn persist_payload_sha256(
    root: &Path,
    manifest: &ManifestIdentity,
    payload: &PayloadInfo,
) -> Result<(), String> {
    let maybe_updated = persist_payload_sha256_str(&manifest.contents, &payload.library_sha256)
        .map_err(str::to_owned)?;
    if let Some(updated_json) = maybe_updated {
        write_atomic(root, &root.join("current.json"), &updated_json)?;
    }
    Ok(())
}

pub(crate) fn stage_impl(
    root: &Path,
    prepared_payload: &Path,
    callbacks: &dyn StoreCallbacks,
) -> StoreResult {
    let mut result = StoreResult::default();
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };

    // Preparation produced these bytes and recorded their hashes. Hashing the
    // workspace again proves nothing that the post-copy verify below does not
    // prove about the bytes that actually become the immutable store entry.
    let verified = callbacks.inspect_prepared_payload(prepared_payload);
    if !verified.is_ok() {
        result.error = verified.error;
        return result;
    }
    result.payload_id = verified.payload_id.clone();
    result.payload_directory = root.join("payloads").join(&result.payload_id);
    result.version_name = verified.version_name.clone();
    result.version_code = verified.version_code;
    result.build_id = verified.build_id.clone();

    if fs::symlink_metadata(&result.payload_directory).is_ok() {
        let existing = callbacks.verify_prepared_payload(&result.payload_directory);
        // What the bytes are, not where they came from. The metadata records the
        // moment of preparation, so comparing that file made every restage
        // quarantine the payload the store was running from.
        if existing.is_ok()
            && existing.payload_id == result.payload_id
            && same_payload_content(&existing, &verified)
        {
            return result;
        }
        if let Err(err) =
            quarantine_payload_collision(root, &result.payload_directory, &result.payload_id)
        {
            result.error = err;
            return result;
        }
    }

    let staging = root
        .join("payloads")
        .join(format!(".stage-{}-{}", result.payload_id, current_pid()));
    remove_payload_tree(&staging, None);
    if let Err(err) = copy_tree(prepared_payload, &staging) {
        remove_payload_tree(&staging, None);
        result.error = err.to_owned();
        return result;
    }
    let staged = callbacks.verify_prepared_payload(&staging);
    if !staged.is_ok() || staged.payload_id != result.payload_id {
        remove_payload_tree(&staging, None);
        result.error = if staged.is_ok() {
            "staged payload identity changed".to_owned()
        } else {
            staged.error
        };
        return result;
    }
    if fs::rename(&staging, &result.payload_directory).is_err() {
        result.error = "cannot publish immutable payload".to_owned();
    }
    result
}

pub(crate) fn promote_impl(
    root: &Path,
    compatibility_manifest: &Path,
    payload_id: &str,
    callbacks: &dyn StoreCallbacks,
) -> StoreResult {
    let mut result = StoreResult::default();
    if !is_valid_payload_id_only(payload_id) {
        result.error = "invalid payload ID".to_owned();
        return result;
    }
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    result.payload_id = payload_id.to_owned();
    result.payload_directory = root.join("payloads").join(&result.payload_id);
    let payload = callbacks.verify_prepared_payload(&result.payload_directory);
    if !payload.is_ok() || payload.payload_id != result.payload_id {
        result.error = if payload.is_ok() {
            "payload directory identity mismatch".to_owned()
        } else {
            payload.error
        };
        return result;
    }
    if let Err(err) = callbacks.exact_supported(compatibility_manifest, &payload) {
        result.error = err;
        return result;
    }
    result.version_name = payload.version_name.clone();
    result.version_code = payload.version_code;
    result.build_id = payload.build_id.clone();

    let current = read_manifest(&root.join("current.json"), true);
    if !current.is_ok() && !current.error.is_empty() {
        result.error = current.error;
        return result;
    }
    if !current.contents.is_empty() && current.payload_id != result.payload_id {
        if let Err(err) = write_atomic(root, &root.join("previous_good.json"), &current.contents) {
            result.error = err;
            return result;
        }
    }
    let Some(contents) = build_activation_manifest_str(
        &payload.payload_id,
        &payload.version_name,
        payload.version_code,
        &payload.build_id,
        &payload.library_sha256,
        None,
    ) else {
        result.error = "cannot serialize activation manifest".to_owned();
        return result;
    };
    if let Err(err) = write_atomic(root, &root.join("current.json"), &contents) {
        result.error = err;
    }
    result
}

pub(crate) fn promote_probation_impl(
    root: &Path,
    compatibility_manifest: &Path,
    runtime_binary: &Path,
    payload_id: &str,
    candidate_profile: &Path,
    candidate_compatibility: &Path,
    canary_logs: [&Path; 2],
    callbacks: &dyn StoreCallbacks,
) -> StoreResult {
    let mut result = StoreResult::default();
    if !is_valid_payload_id_only(payload_id) || runtime_binary.as_os_str().is_empty() {
        result.error = "probation promotion requires a valid payload and runtime".to_owned();
        return result;
    }
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    result.payload_id = payload_id.to_owned();
    result.payload_directory = root.join("payloads").join(&result.payload_id);
    let payload = callbacks.verify_prepared_payload(&result.payload_directory);
    if !payload.is_ok() || payload.payload_id != result.payload_id {
        result.error = if payload.is_ok() {
            "payload directory identity mismatch".to_owned()
        } else {
            payload.error
        };
        return result;
    }
    if callbacks
        .exact_supported(compatibility_manifest, &payload)
        .is_ok()
    {
        result.error = "exact-supported payload must use regular promotion".to_owned();
        return result;
    }
    let approval = callbacks.create_candidate_approval(
        root,
        &result.payload_directory,
        candidate_profile,
        candidate_compatibility,
        runtime_binary,
        canary_logs,
        &payload,
    );
    if !approval.is_ok() {
        result.error = approval.error;
        return result;
    }
    let Some(contents) = build_activation_manifest_str(
        &payload.payload_id,
        &payload.version_name,
        payload.version_code,
        &payload.build_id,
        &payload.library_sha256,
        Some(&approval.generation),
    ) else {
        result.error = "cannot serialize probation activation manifest".to_owned();
        return result;
    };
    let verified_approval = match callbacks.validate_candidate_approval(root, &contents, &payload) {
        Ok(a) => a,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    let current = read_manifest(&root.join("current.json"), true);
    if !current.is_ok() && !current.error.is_empty() {
        result.error = current.error;
        return result;
    }
    if !current.contents.is_empty() && current.payload_id != result.payload_id {
        if let Err(err) = write_atomic(root, &root.join("previous_good.json"), &current.contents) {
            result.error = err;
            return result;
        }
    }
    if let Err(err) = write_atomic(root, &root.join("current.json"), &contents) {
        result.error = err;
        return result;
    }
    result.version_name = payload.version_name;
    result.version_code = payload.version_code;
    result.build_id = payload.build_id;
    result.host_abi_profile = verified_approval.profile;
    result.compatibility_manifest = verified_approval.compatibility_manifest;
    result.approval_receipt = verified_approval.receipt;
    result
}

pub(crate) fn import_impl(
    root: &Path,
    compatibility_manifest: &Path,
    prepared_payload: &Path,
    callbacks: &dyn StoreCallbacks,
) -> StoreResult {
    let staged = stage_impl(root, prepared_payload, callbacks);
    if !staged.is_ok() {
        return staged;
    }
    promote_impl(root, compatibility_manifest, &staged.payload_id, callbacks)
}

pub(crate) fn verify_current_impl(
    root: &Path,
    compatibility_manifest: &Path,
    callbacks: &dyn StoreCallbacks,
) -> StoreResult {
    let mut result = StoreResult::default();
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    let manifest = read_manifest(&root.join("current.json"), false);
    if !manifest.is_ok() {
        result.error = if manifest.error.is_empty() {
            "no current payload".to_owned()
        } else {
            manifest.error
        };
        return result;
    }
    let Some(payload) = populate_inspected_result(root, &manifest, callbacks, &mut result) else {
        return result;
    };
    let lib_path = result.payload_directory.join("libroblox.so");
    match callbacks.hash_regular_file(&lib_path) {
        Ok(library_sha256) if library_sha256 == payload.library_sha256 => {}
        Ok(_) => {
            result.error = "current payload library hash mismatch".to_owned();
            return result;
        }
        Err(err) => {
            result.error = err;
            return result;
        }
    }
    if callbacks
        .exact_supported(compatibility_manifest, &payload)
        .is_ok()
    {
        if let Err(err) = persist_payload_sha256(root, &manifest, &payload) {
            result.error = err;
        }
        return result;
    }
    let approval = match callbacks.validate_candidate_approval(root, &manifest.contents, &payload) {
        Ok(a) => a,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    if let Err(err) = persist_payload_sha256(root, &manifest, &payload) {
        result.error = err;
        return result;
    }
    result.host_abi_profile = approval.profile;
    result.compatibility_manifest = approval.compatibility_manifest;
    result.approval_receipt = approval.receipt;
    result
}

pub(crate) fn inspect_current_impl(root: &Path, callbacks: &dyn StoreCallbacks) -> StoreResult {
    let mut result = StoreResult::default();
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    let manifest = read_manifest(&root.join("current.json"), false);
    if !manifest.is_ok() {
        result.error = if manifest.error.is_empty() {
            "no current payload".to_owned()
        } else {
            manifest.error
        };
        return result;
    }
    let _ = populate_inspected_result(root, &manifest, callbacks, &mut result);
    result
}

pub(crate) fn rollback_impl(
    root: &Path,
    compatibility_manifest: &Path,
    callbacks: &dyn StoreCallbacks,
) -> StoreResult {
    let mut result = StoreResult::default();
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };
    let previous = read_manifest(&root.join("previous_good.json"), false);
    if !previous.is_ok() {
        result.error = if previous.error.is_empty() {
            "no previous-good payload".to_owned()
        } else {
            previous.error
        };
        return result;
    }
    result.payload_id = previous.payload_id;
    result.payload_directory = root.join("payloads").join(&result.payload_id);
    let payload = callbacks.verify_prepared_payload(&result.payload_directory);
    if !payload.is_ok() {
        result.error = payload.error;
        return result;
    }
    if callbacks
        .exact_supported(compatibility_manifest, &payload)
        .is_err()
    {
        if let Err(err) =
            callbacks.validate_candidate_approval(root, &previous.contents, &payload)
        {
            result.error = err;
            return result;
        }
    }
    if payload.payload_id != result.payload_id {
        result.error = "previous-good payload identity mismatch".to_owned();
        return result;
    }
    result.version_name = payload.version_name;
    result.version_code = payload.version_code;
    result.build_id = payload.build_id;
    if let Err(err) = write_atomic(root, &root.join("current.json"), &previous.contents) {
        result.error = err;
    }
    result
}

pub(crate) fn collect_garbage_impl(root: &Path, keep: &[String]) -> GarbageResult {
    let mut result = GarbageResult::default();
    let _lock = match StoreLock::acquire(root) {
        Ok(l) => l,
        Err(err) => {
            result.error = err;
            return result;
        }
    };

    let mut retained: std::collections::HashSet<String> = keep.iter().cloned().collect();
    for manifest_name in ["current.json", "previous_good.json"] {
        let identity = read_manifest(&root.join(manifest_name), true);
        if !identity.error.is_empty() {
            // Nothing is deleted from a store whose own manifests cannot be read.
            result.error = identity.error;
            return result;
        }
        if !identity.payload_id.is_empty() {
            retained.insert(identity.payload_id);
        }
    }

    let mut superseded = Vec::new();
    let Ok(payload_entries) = fs::read_dir(root.join("payloads")) else {
        result.error = "cannot inspect the payload store".to_owned();
        return result;
    };
    for entry in payload_entries {
        let Ok(entry) = entry else {
            result.error = "cannot inspect the payload store".to_owned();
            return result;
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            result.error = "cannot inspect the payload store".to_owned();
            return result;
        };
        // Also the workspace a killed Stage left behind, just as large.
        let collectable = (is_valid_payload_id_only(&name) && !retained.contains(&name))
            || name.starts_with(".stage-");
        if meta.file_type().is_dir() && !meta.file_type().is_symlink() && collectable {
            superseded.push(path);
        }
    }

    // Nothing ever reads a quarantined tree back; it is a copy set aside by a
    // collision and it is the same 600 MiB as a payload.
    if let Ok(quarantine_entries) = fs::read_dir(root.join("quarantine")) {
        for entry in quarantine_entries {
            let Ok(entry) = entry else {
                break;
            };
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                break;
            };
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                superseded.push(path);
            }
        }
    }

    for payload in superseded {
        let filename = payload
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if remove_payload_tree(&payload, Some(&mut result.freed_bytes)) {
            result.removed.push(filename);
        }
    }
    result
}

pub(crate) fn status_json_impl(root: &Path) -> Result<String, String> {
    let _lock = StoreLock::acquire(root)?;
    let current = read_manifest(&root.join("current.json"), true);
    let previous = read_manifest(&root.join("previous_good.json"), true);
    if !current.error.is_empty() || !previous.error.is_empty() {
        return Err(if !current.error.is_empty() {
            current.error
        } else {
            previous.error
        });
    }
    let update_path = root.join("update.json");
    Ok(build_status_json_str(Some(&update_path), &current.contents, &previous.contents)
        .unwrap_or_default())
}

unsafe fn emit_store_result(
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
    res: &StoreResult,
) -> i32 {
    if let Some(cb) = on_result {
        let payload_dir_bytes = res.payload_directory.as_os_str().as_bytes();
        let profile_bytes = res.host_abi_profile.as_os_str().as_bytes();
        let compat_bytes = res.compatibility_manifest.as_os_str().as_bytes();
        let receipt_bytes = res.approval_receipt.as_os_str().as_bytes();
        let data = MocktailRustPayloadStoreResultData {
            payload_id: res.payload_id.as_ptr().cast::<c_char>(),
            payload_id_len: res.payload_id.len(),
            payload_directory: payload_dir_bytes.as_ptr().cast::<c_char>(),
            payload_directory_len: payload_dir_bytes.len(),
            host_abi_profile: profile_bytes.as_ptr().cast::<c_char>(),
            host_abi_profile_len: profile_bytes.len(),
            compatibility_manifest: compat_bytes.as_ptr().cast::<c_char>(),
            compatibility_manifest_len: compat_bytes.len(),
            approval_receipt: receipt_bytes.as_ptr().cast::<c_char>(),
            approval_receipt_len: receipt_bytes.len(),
            version_name: res.version_name.as_ptr().cast::<c_char>(),
            version_name_len: res.version_name.len(),
            version_code: res.version_code,
            build_id: res.build_id.as_ptr().cast::<c_char>(),
            build_id_len: res.build_id.len(),
            error: res.error.as_ptr().cast::<c_char>(),
            error_len: res.error.len(),
        };
        cb(ctx, &data);
    }
    if res.is_ok() {
        0
    } else {
        -1
    }
}

struct ParsedStorePaths {
    root: PathBuf,
    compatibility_manifest: PathBuf,
    runtime_binary: PathBuf,
}

unsafe fn parse_store_paths(paths: *const MocktailRustPayloadStorePaths) -> Option<ParsedStorePaths> {
    if paths.is_null() {
        return None;
    }
    let p = &*paths;
    Some(ParsedStorePaths {
        root: path_from_ffi(p.root_ptr, p.root_len)?,
        compatibility_manifest: path_from_ffi(
            p.compatibility_manifest_ptr,
            p.compatibility_manifest_len,
        )?,
        runtime_binary: path_from_ffi(p.runtime_binary_ptr, p.runtime_binary_len)?,
    })
}

unsafe fn emit_invalid_store_args(
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let res = StoreResult {
        error: "invalid payload store arguments".to_owned(),
        ..StoreResult::default()
    };
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_stage(
    paths: *const MocktailRustPayloadStorePaths,
    prepared_ptr: *const c_char,
    prepared_len: usize,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(p), Some(prepared), Some(ops_ref)) = (
        parse_store_paths(paths),
        path_from_ffi(prepared_ptr, prepared_len),
        ops.as_ref(),
    ) else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = stage_impl(&p.root, &prepared, &callbacks);
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_promote(
    paths: *const MocktailRustPayloadStorePaths,
    payload_id_ptr: *const c_char,
    payload_id_len: usize,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(p), Some(ops_ref)) = (parse_store_paths(paths), ops.as_ref()) else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let payload_id = String::from_utf8_lossy(slice_from_ffi(payload_id_ptr, payload_id_len));
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = promote_impl(&p.root, &p.compatibility_manifest, &payload_id, &callbacks);
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_promote_probation(
    paths: *const MocktailRustPayloadStorePaths,
    payload_id_ptr: *const c_char,
    payload_id_len: usize,
    candidate_profile_ptr: *const c_char,
    candidate_profile_len: usize,
    candidate_compat_ptr: *const c_char,
    candidate_compat_len: usize,
    canary0_ptr: *const c_char,
    canary0_len: usize,
    canary1_ptr: *const c_char,
    canary1_len: usize,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (
        Some(p),
        Some(candidate_profile),
        Some(candidate_compat),
        Some(canary0),
        Some(canary1),
        Some(ops_ref),
    ) = (
        parse_store_paths(paths),
        path_from_ffi(candidate_profile_ptr, candidate_profile_len),
        path_from_ffi(candidate_compat_ptr, candidate_compat_len),
        path_from_ffi(canary0_ptr, canary0_len),
        path_from_ffi(canary1_ptr, canary1_len),
        ops.as_ref(),
    )
    else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let payload_id = String::from_utf8_lossy(slice_from_ffi(payload_id_ptr, payload_id_len));
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = promote_probation_impl(
        &p.root,
        &p.compatibility_manifest,
        &p.runtime_binary,
        &payload_id,
        &candidate_profile,
        &candidate_compat,
        [&canary0, &canary1],
        &callbacks,
    );
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_import(
    paths: *const MocktailRustPayloadStorePaths,
    prepared_ptr: *const c_char,
    prepared_len: usize,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(p), Some(prepared), Some(ops_ref)) = (
        parse_store_paths(paths),
        path_from_ffi(prepared_ptr, prepared_len),
        ops.as_ref(),
    ) else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = import_impl(&p.root, &p.compatibility_manifest, &prepared, &callbacks);
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_verify_current(
    paths: *const MocktailRustPayloadStorePaths,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(p), Some(ops_ref)) = (parse_store_paths(paths), ops.as_ref()) else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = verify_current_impl(&p.root, &p.compatibility_manifest, &callbacks);
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_inspect_current(
    paths: *const MocktailRustPayloadStorePaths,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(p), Some(ops_ref)) = (parse_store_paths(paths), ops.as_ref()) else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = inspect_current_impl(&p.root, &callbacks);
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_rollback(
    paths: *const MocktailRustPayloadStorePaths,
    ops: *const MocktailRustPayloadStoreOps,
    on_result: MocktailRustPayloadStoreResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let (Some(p), Some(ops_ref)) = (parse_store_paths(paths), ops.as_ref()) else {
        return emit_invalid_store_args(on_result, ctx);
    };
    let callbacks = FfiStoreCallbacks { ops: ops_ref };
    let res = rollback_impl(&p.root, &p.compatibility_manifest, &callbacks);
    emit_store_result(on_result, ctx, &res)
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_collect_garbage(
    root_ptr: *const c_char,
    root_len: usize,
    keep_ptrs: *const *const c_char,
    keep_lens: *const usize,
    keep_count: usize,
    on_removed: MocktailRustPayloadStoreStrReceiver,
    out_freed_bytes: *mut u64,
    on_error: MocktailRustPayloadStoreStrReceiver,
    ctx: *mut c_void,
) -> i32 {
    if !out_freed_bytes.is_null() {
        *out_freed_bytes = 0;
    }
    let Some(root) = path_from_ffi(root_ptr, root_len) else {
        if let Some(cb) = on_error {
            let msg = b"invalid payload store arguments";
            cb(ctx, msg.as_ptr().cast::<c_char>(), msg.len());
        }
        return -1;
    };
    let mut keep = Vec::with_capacity(keep_count);
    if keep_count > 0 && !keep_ptrs.is_null() && !keep_lens.is_null() {
        for idx in 0..keep_count {
            let ptr = *keep_ptrs.add(idx);
            let len = *keep_lens.add(idx);
            keep.push(lossy_str(ptr, len).into_owned());
        }
    }

    let res = collect_garbage_impl(&root, &keep);
    if !out_freed_bytes.is_null() {
        *out_freed_bytes = res.freed_bytes;
    }
    if let Some(cb) = on_removed {
        for item in &res.removed {
            cb(ctx, item.as_ptr().cast::<c_char>(), item.len());
        }
    }
    if !res.error.is_empty() {
        if let Some(cb) = on_error {
            cb(ctx, res.error.as_ptr().cast::<c_char>(), res.error.len());
        }
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_payload_store_status_json(
    root_ptr: *const c_char,
    root_len: usize,
    on_json: MocktailRustPayloadStoreStrReceiver,
    on_error: MocktailRustPayloadStoreStrReceiver,
    ctx: *mut c_void,
) -> i32 {
    let Some(root) = path_from_ffi(root_ptr, root_len) else {
        if let Some(cb) = on_error {
            let msg = b"invalid payload store arguments";
            cb(ctx, msg.as_ptr().cast::<c_char>(), msg.len());
        }
        return -1;
    };
    match status_json_impl(&root) {
        Ok(json) => {
            if let Some(cb) = on_json {
                cb(ctx, json.as_ptr().cast::<c_char>(), json.len());
            }
            0
        }
        Err(err) => {
            if let Some(cb) = on_error {
                cb(ctx, err.as_ptr().cast::<c_char>(), err.len());
            }
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let seq = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mocktail-rust-payload-store-{label}-{}-{seq}",
                current_pid()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = remove_payload_tree(&self.path, None);
        }
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    struct MockCallbacks {
        exact_supported_code: u64,
        probation_generation: String,
    }

    impl MockCallbacks {
        fn new(exact_supported_code: u64) -> Self {
            Self {
                exact_supported_code,
                probation_generation: "99".to_owned(),
            }
        }

        fn inspect_or_verify(&self, dir: &Path, verify_hashes: bool) -> PayloadInfo {
            let mut info = PayloadInfo::default();
            let Ok(meta_str) = fs::read_to_string(dir.join("roblox_payload.json")) else {
                info.error = "missing roblox_payload.json".to_owned();
                return info;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&meta_str) else {
                info.error = "invalid roblox_payload.json".to_owned();
                return info;
            };
            info.package_name = v["package"].as_str().unwrap_or("").to_owned();
            info.version_name = v["version_name"].as_str().unwrap_or("").to_owned();
            info.version_code = v["version_code"].as_u64().unwrap_or(0);
            info.build_id = v["elf_build_id"].as_str().unwrap_or("").to_owned();
            info.library_sha256 = v["sha256"]["libroblox"].as_str().unwrap_or("").to_owned();
            info.base_apk_sha256 = v["sha256"]["base_apk"].as_str().unwrap_or("").to_owned();
            info.split_apk_sha256 = v["sha256"]["split_apk"].as_str().unwrap_or("").to_owned();
            info.asset_file_count = v["assets"]["file_count"].as_u64().unwrap_or(0) as usize;
            info.asset_tree_sha256 = v["assets"]["sha256_tree"].as_str().unwrap_or("").to_owned();
            if verify_hashes {
                let Ok(lib_bytes) = fs::read(dir.join("libroblox.so")) else {
                    info.error = "missing libroblox.so".to_owned();
                    return info;
                };
                if sha256_bytes(&lib_bytes) != info.library_sha256 {
                    info.error = "payload hash mismatch: libroblox.so".to_owned();
                    return info;
                }
            }
            info.payload_id = format!("{}-{}", info.version_code, info.build_id);
            info
        }
    }

    impl StoreCallbacks for MockCallbacks {
        fn inspect_prepared_payload(&self, dir: &Path) -> PayloadInfo {
            self.inspect_or_verify(dir, false)
        }

        fn verify_prepared_payload(&self, dir: &Path) -> PayloadInfo {
            self.inspect_or_verify(dir, true)
        }

        fn hash_regular_file(&self, path: &Path) -> Result<String, String> {
            let bytes = fs::read(path).map_err(|e| e.to_string())?;
            Ok(sha256_bytes(&bytes))
        }

        fn exact_supported(&self, _compat: &Path, payload: &PayloadInfo) -> Result<(), String> {
            if payload.version_code == self.exact_supported_code {
                Ok(())
            } else {
                Err("payload is not an exact default-supported profile".to_owned())
            }
        }

        fn create_candidate_approval(
            &self,
            store_root: &Path,
            _payload_dir: &Path,
            _profile: &Path,
            _compatibility_manifest: &Path,
            _runtime_binary: &Path,
            _canary_logs: [&Path; 2],
            verified_payload: &PayloadInfo,
        ) -> CandidateApprovalInfo {
            let stem = format!("{}-{}", verified_payload.payload_id, self.probation_generation);
            CandidateApprovalInfo {
                generation: self.probation_generation.clone(),
                profile: store_root.join(format!("host_abi_profiles/{stem}.json")),
                compatibility_manifest: store_root
                    .join(format!("compatibility_profiles/{stem}.json")),
                receipt: store_root.join(format!("approvals/{stem}.json")),
                error: String::new(),
            }
        }

        fn validate_candidate_approval(
            &self,
            store_root: &Path,
            _activation_json: &str,
            payload: &PayloadInfo,
        ) -> Result<CandidateApprovalInfo, String> {
            let stem = format!("{}-{}", payload.payload_id, self.probation_generation);
            Ok(CandidateApprovalInfo {
                generation: self.probation_generation.clone(),
                profile: store_root.join(format!("host_abi_profiles/{stem}.json")),
                compatibility_manifest: store_root
                    .join(format!("compatibility_profiles/{stem}.json")),
                receipt: store_root.join(format!("approvals/{stem}.json")),
                error: String::new(),
            })
        }
    }

    fn write_prepared_payload(dir: &Path, version_code: u64, build_id: &str, lib_bytes: &[u8]) {
        fs::create_dir_all(dir.join("assets/content")).unwrap();
        fs::write(dir.join("libroblox.so"), lib_bytes).unwrap();
        fs::write(dir.join("assets/content/fixture"), b"asset-bytes").unwrap();
        let meta = serde_json::json!({
            "schema_version": 1,
            "package": "com.roblox.client",
            "version_name": "2.727.1199",
            "version_code": version_code,
            "elf_build_id": build_id,
            "sha256": {
                "libroblox": sha256_bytes(lib_bytes),
                "base_apk": "base-hash",
                "split_apk": "split-hash"
            },
            "assets": {
                "file_count": 1,
                "sha256_tree": "asset-tree-hash"
            }
        });
        fs::write(
            dir.join("roblox_payload.json"),
            format!("{}\n", serde_json::to_string_pretty(&meta).unwrap()),
        )
        .unwrap();
    }

    #[test]
    fn stages_quarantines_read_only_collision_promotes_verifies_and_rolls_back() {
        let dir = TempDir::new("stage-promote");
        let root = dir.path.join("store");
        let compat = dir.path.join("compat.json");
        let build_a = "1686400865ae0e408cd7bd67de7a439625c6fd13";
        let build_b = "b".repeat(40);
        let prep_a = dir.path.join("prep-a");
        let prep_b = dir.path.join("prep-b");
        write_prepared_payload(&prep_a, 2628, build_a, b"lib-a");
        write_prepared_payload(&prep_b, 2700, &build_b, b"lib-b");

        let cb = MockCallbacks::new(2628);
        let staged_a = stage_impl(&root, &prep_a, &cb);
        assert!(staged_a.is_ok(), "{}", staged_a.error);
        let root_mode = fs::symlink_metadata(&staged_a.payload_directory)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(root_mode & 0o777, 0o555);

        // Identical restage reuses the installed directory without quarantine.
        let restaged_a = stage_impl(&root, &prep_a, &cb);
        assert!(restaged_a.is_ok(), "{}", restaged_a.error);
        assert!(!root.join("quarantine").exists());

        // Corrupt stored file and verify restage quarantines read-only root and recovers.
        let lib_stored = staged_a.payload_directory.join("libroblox.so");
        fs::set_permissions(&lib_stored, Permissions::from_mode(0o600)).unwrap();
        fs::write(&lib_stored, b"corrupted").unwrap();
        fs::set_permissions(&lib_stored, Permissions::from_mode(0o400)).unwrap();
        let recovered = stage_impl(&root, &prep_a, &cb);
        assert!(recovered.is_ok(), "{}", recovered.error);
        let q_entries: Vec<_> = fs::read_dir(root.join("quarantine"))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(q_entries.len(), 1);
        let q_mode = fs::symlink_metadata(q_entries[0].path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(q_mode & 0o200, 0);

        let promoted_a = promote_impl(&root, &compat, &staged_a.payload_id, &cb);
        assert!(promoted_a.is_ok(), "{}", promoted_a.error);
        let verified_a = verify_current_impl(&root, &compat, &cb);
        assert!(verified_a.is_ok(), "{}", verified_a.error);

        // Stage + probation-promote build_b, then roll back to build_a.
        let runtime = dir.path.join("mocktail");
        let prof = dir.path.join("cand.json");
        let cand_compat = dir.path.join("cand-compat.json");
        let c0 = dir.path.join("c0.log");
        let c1 = dir.path.join("c1.log");
        let staged_b = stage_impl(&root, &prep_b, &cb);
        assert!(staged_b.is_ok(), "{}", staged_b.error);
        let promoted_b = promote_probation_impl(
            &root,
            &compat,
            &runtime,
            &staged_b.payload_id,
            &prof,
            &cand_compat,
            [&c0, &c1],
            &cb,
        );
        assert!(promoted_b.is_ok(), "{}", promoted_b.error);
        assert!(promoted_b
            .approval_receipt
            .to_string_lossy()
            .contains("-99.json"));

        let rolled_back = rollback_impl(&root, &compat, &cb);
        assert!(rolled_back.is_ok(), "{}", rolled_back.error);
        assert_eq!(rolled_back.payload_id, staged_a.payload_id);

        let status = status_json_impl(&root).unwrap();
        let status_v: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(status_v["current"]["payload_id"], staged_a.payload_id);
        assert_eq!(status_v["previous_good"]["payload_id"], staged_a.payload_id);
    }

    #[test]
    fn collects_garbage_safely_including_read_only_superseded_and_quarantine() {
        let dir = TempDir::new("gc");
        let root = dir.path.join("store");
        let active = format!("2998-{}", "a".repeat(40));
        let rollback = format!("2908-{}", "b".repeat(40));
        let keep_ref = format!("2628-{}", "c".repeat(40));
        let superseded = format!("2546-{}", "d".repeat(40));
        let abandoned = format!(".stage-{superseded}-4242");

        for id in [&active, &rollback, &keep_ref, &superseded, &abandoned] {
            let p = root.join("payloads").join(id);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("libroblox.so"), b"payload bytes").unwrap();
        }
        fs::set_permissions(
            root.join("payloads").join(&superseded),
            Permissions::from_mode(0o555),
        )
        .unwrap();
        fs::create_dir_all(root.join("quarantine/old-quarantine")).unwrap();
        fs::write(root.join("quarantine/old-quarantine/file"), b"12345").unwrap();
        fs::set_permissions(
            root.join("quarantine/old-quarantine"),
            Permissions::from_mode(0o555),
        )
        .unwrap();

        let make_manifest = |id: &str| {
            serde_json::json!({
                "schema_version": 1,
                "payload_id": id,
                "payload_path": format!("payloads/{id}")
            })
            .to_string()
        };
        fs::write(root.join("current.json"), make_manifest(&active)).unwrap();
        fs::write(root.join("previous_good.json"), make_manifest(&rollback)).unwrap();

        let collected = collect_garbage_impl(&root, &[keep_ref.clone()]);
        assert_eq!(collected.error, "");
        assert_eq!(collected.removed.len(), 3);
        assert!(collected.freed_bytes >= 31);
        assert!(root.join("payloads").join(&active).exists());
        assert!(root.join("payloads").join(&rollback).exists());
        assert!(root.join("payloads").join(&keep_ref).exists());
        assert!(!root.join("payloads").join(&superseded).exists());
        assert!(!root.join("payloads").join(&abandoned).exists());
        assert!(!root.join("quarantine/old-quarantine").exists());
    }
}
