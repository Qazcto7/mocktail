//! Pure-Rust APK download providers, native payload store callbacks, and
//! native update backend (`UpdateBackend` implementation for `mocktail_updater`).

use std::cell::Cell;
use std::fs;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};

use crate::apk_bundle::{
    prepare_payload_from_archives, ApkSignatureVerifier, ExpectedPayloadIdentityData,
};
use crate::apk_signature_rs::verify_apk_signature_openssl;
use crate::candidate_approval::{
    create_candidate_approval, validate_candidate_approval, CandidateApprovalOptionsData,
    CandidateApprovalResultData,
};
use crate::capstone_ffi::CapstoneX86Disassembler;
use crate::host_abi_deriver::derive_host_abi_profile_rs;
use crate::http_download::{
    download_bytes_native, download_file_native, is_trusted_https_url, HttpBytesResultData,
    HttpDownloadResultData, HttpTransferRequestData,
};
use crate::payload_store::{
    collect_garbage_impl, inspect_current_impl, promote_impl, promote_probation_impl, stage_impl,
    verify_current_impl, CandidateApprovalInfo, PayloadInfo, StoreCallbacks, StoreResult,
};
use crate::update_coordinator::{
    CoordinatorStoreResult, DerivedHostAbiData, ExpectedIdentityData, GarbageCollectData,
    ProviderVersionData, UpdateBackend, UpdatePathsData,
};
use crate::update_json::{find_pinned_source_internal, PinnedArchiveEntry};
use crate::{
    apkpure_collect_exact_urls, apkpure_has_zip_magic, apkpure_is_valid_version_name,
    apkpure_parse_latest_bytes, host_guest_abi, internal_inspect_payload,
    load_compatibility_catalog_file, sha256_regular_file_strict, verify_payload_internal,
    MocktailRustPayloadInfo,
};

const K_MAXIMUM_METADATA_BYTES: usize = 4 * 1024 * 1024;
const K_MAXIMUM_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const APKPURE_API_URL: &str =
    "https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name=com.roblox.client";
const FALLBACK_ARCH_HEADER: &str = "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64";

fn apkpure_metadata_hosts() -> Vec<String> {
    vec!["api.pureapk.com".to_string()]
}

fn apkpure_download_hosts() -> Vec<String> {
    vec![
        "pureapk.com".to_string(),
        "apkpure.com".to_string(),
        "winudf.com".to_string(),
    ]
}

fn pinned_download_hosts() -> Vec<String> {
    vec![
        "github.com".to_string(),
        "release-assets.githubusercontent.com".to_string(),
        "objects.githubusercontent.com".to_string(),
    ]
}

pub(crate) struct OpenSslApkSignatureVerifier;

impl ApkSignatureVerifier for OpenSslApkSignatureVerifier {
    fn verify_apk_signature(&self, apk_path: &Path) -> Result<Vec<String>, String> {
        verify_apk_signature_openssl(apk_path)
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ProviderDownloadResult {
    pub source: String,
    pub archives: Vec<PathBuf>,
    pub error: String,
}

impl ProviderDownloadResult {
    pub(crate) fn is_ok(&self) -> bool {
        self.error.is_empty() && !self.archives.is_empty()
    }
}

pub(crate) type MetadataFetcher = Box<dyn Fn(&str) -> HttpBytesResultData>;
pub(crate) type FileDownloader =
    Box<dyn Fn(&HttpTransferRequestData, &Path, c_int) -> HttpDownloadResultData>;

pub(crate) struct ApkPureProvider {
    metadata_fetcher: MetadataFetcher,
    file_downloader: FileDownloader,
}

impl Default for ApkPureProvider {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl ApkPureProvider {
    pub(crate) fn new(
        metadata_fetcher: Option<MetadataFetcher>,
        file_downloader: Option<FileDownloader>,
    ) -> Self {
        Self {
            metadata_fetcher: metadata_fetcher.unwrap_or_else(|| {
                Box::new(|arch: &str| {
                    let req = HttpTransferRequestData {
                        url: APKPURE_API_URL.to_string(),
                        headers: vec![
                            "x-cv: 3172501".to_string(),
                            "x-sv: 29".to_string(),
                            "x-gp: 1".to_string(),
                            format!("x-abis: {arch}"),
                        ],
                        allowed_hosts: apkpure_metadata_hosts(),
                        maximum_bytes: K_MAXIMUM_METADATA_BYTES,
                        connect_timeout_ms: 5000,
                        transfer_timeout_ms: 15000,
                        maximum_attempts: 2,
                        ..HttpTransferRequestData::default()
                    };
                    download_bytes_native(&req)
                })
            }),
            file_downloader: file_downloader.unwrap_or_else(|| {
                Box::new(|req, dest, progress_fd| download_file_native(req, dest, progress_fd))
            }),
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "apkpure"
    }

    pub(crate) fn check_latest(&self) -> ProviderVersionData {
        let meta = (self.metadata_fetcher)(&host_guest_abi());
        if !meta.error.is_empty() {
            return ProviderVersionData {
                error: meta.error,
                ..ProviderVersionData::default()
            };
        }
        match apkpure_parse_latest_bytes(&meta.bytes) {
            Ok((version_name, version_code)) => ProviderVersionData {
                version_name,
                version_code,
                error: String::new(),
            },
            Err(err) => ProviderVersionData {
                error: err.to_string(),
                ..ProviderVersionData::default()
            },
        }
    }

    pub(crate) fn download_verified(
        &self,
        version: &ProviderVersionData,
        output_directory: &Path,
        progress_fd: c_int,
        validate: &mut dyn FnMut(&ProviderDownloadResult) -> String,
    ) -> ProviderDownloadResult {
        let mut result = ProviderDownloadResult {
            source: self.name().to_string(),
            ..ProviderDownloadResult::default()
        };
        if !version.is_valid() || !apkpure_is_valid_version_name(&version.version_name) {
            result.error = "invalid APKPure version".to_string();
            return result;
        }
        if fs::create_dir_all(output_directory).is_err()
            || fs::symlink_metadata(output_directory)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true)
        {
            result.error = "cannot create APKPure download directory".to_string();
            return result;
        }

        let meta = (self.metadata_fetcher)(&host_guest_abi());
        if !meta.error.is_empty() {
            result.error = meta.error;
            return result;
        }
        let mut parse_err = String::new();
        let mut urls = match apkpure_collect_exact_urls(
            &meta.bytes,
            &version.version_name,
            version.version_code,
        ) {
            Ok(list) => list,
            Err((_, msg)) => {
                parse_err = msg.to_string();
                Vec::new()
            }
        };
        if urls.is_empty() {
            parse_err.clear();
            let fallback_meta = (self.metadata_fetcher)(FALLBACK_ARCH_HEADER);
            if !fallback_meta.error.is_empty() {
                result.error = fallback_meta.error;
                return result;
            }
            urls = match apkpure_collect_exact_urls(
                &fallback_meta.bytes,
                &version.version_name,
                version.version_code,
            ) {
                Ok(list) => list,
                Err((_, msg)) => {
                    parse_err = msg.to_string();
                    Vec::new()
                }
            };
        }
        if !parse_err.is_empty() {
            result.error = parse_err;
            return result;
        }

        for (index, url) in urls.iter().enumerate() {
            let ext = if url.contains(".xapk") || url.contains("/XAPK/") {
                "xapk"
            } else {
                "apk"
            };
            let destination = output_directory.join(format!("candidate-{}.{}", index + 1, ext));
            let try_accept = |res: &mut ProviderDownloadResult, validate: &mut dyn FnMut(&ProviderDownloadResult) -> String| {
                res.archives = vec![destination.clone()];
                res.error.clear();
                res.error = validate(res);
                if res.is_ok() {
                    return true;
                }
                res.archives.clear();
                let _ = fs::remove_file(&destination);
                false
            };

            if apkpure_has_zip_magic(&destination) && try_accept(&mut result, validate) {
                return result;
            }

            let req = HttpTransferRequestData {
                url: url.clone(),
                allowed_hosts: apkpure_download_hosts(),
                maximum_bytes: K_MAXIMUM_ARCHIVE_BYTES as usize,
                transfer_timeout_ms: 0,
                maximum_attempts: 3,
                retry_delay_ms: 1000,
                maximum_redirects: 8,
                connect_timeout_ms: 10000,
                ..HttpTransferRequestData::default()
            };
            let downloaded = (self.file_downloader)(&req, &destination, progress_fd);
            if !downloaded.error.is_empty() || !apkpure_has_zip_magic(&destination) {
                let _ = fs::remove_file(&destination);
                result.error = if downloaded.error.is_empty() {
                    "APKPure response is not a ZIP archive".to_string()
                } else {
                    downloaded.error
                };
                continue;
            }
            if try_accept(&mut result, validate) {
                return result;
            }
            let _ = fs::remove_file(&destination);
        }

        if result.error.is_empty() {
            result.error = "APKPure returned no usable APK".to_string();
        }
        result
    }
}

pub(crate) struct PinnedApkProvider {
    manifest: PathBuf,
    file_downloader: FileDownloader,
}

impl PinnedApkProvider {
    pub(crate) fn new(manifest: PathBuf, file_downloader: Option<FileDownloader>) -> Self {
        Self {
            manifest,
            file_downloader: file_downloader.unwrap_or_else(|| {
                Box::new(|req, dest, progress_fd| download_file_native(req, dest, progress_fd))
            }),
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "pinned"
    }

    fn matches_archive(path: &Path, archive: &PinnedArchiveEntry) -> bool {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        meta.file_type().is_file()
            && meta.len() == archive.size
            && sha256_regular_file_strict(path, None).is_ok_and(|h| h == archive.sha256)
    }

    pub(crate) fn download_verified(
        &self,
        version: &ProviderVersionData,
        directory: &Path,
        progress_fd: c_int,
        validate: &mut dyn FnMut(&ProviderDownloadResult) -> String,
    ) -> ProviderDownloadResult {
        let mut result = ProviderDownloadResult {
            source: self.name().to_string(),
            ..ProviderDownloadResult::default()
        };
        if !version.is_valid() {
            result.error = "invalid pinned APK version".to_string();
            return result;
        }
        let manifest_str = self.manifest.to_string_lossy();
        let hosts = pinned_download_hosts();
        let (_, archives) = match find_pinned_source_internal(
            &manifest_str,
            &version.version_name,
            version.version_code,
            &host_guest_abi(),
            K_MAXIMUM_ARCHIVE_BYTES,
            &|u| is_trusted_https_url(u, &hosts).is_ok(),
        ) {
            Ok(v) => v,
            Err(err) => {
                result.error = err;
                return result;
            }
        };

        for archive in &archives {
            let destination = directory.join(&archive.filename);
            if !Self::matches_archive(&destination, archive) {
                if let Err(err) = fs::remove_file(&destination) {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        result.error = format!("cannot replace cached APK: {err}");
                        return result;
                    }
                }
                let req = HttpTransferRequestData {
                    url: archive.url.clone(),
                    allowed_hosts: hosts.clone(),
                    maximum_bytes: archive.size as usize,
                    transfer_timeout_ms: 0,
                    maximum_attempts: 3,
                    retry_delay_ms: 1000,
                    maximum_redirects: 8,
                    connect_timeout_ms: 10000,
                    ..HttpTransferRequestData::default()
                };
                let downloaded = (self.file_downloader)(&req, &destination, progress_fd);
                if !downloaded.error.is_empty() {
                    result.error = downloaded.error;
                    return result;
                }
                if !Self::matches_archive(&destination, archive) {
                    let _ = fs::remove_file(&destination);
                    result.error = format!(
                        "{} does not match the pinned SHA-256 or size",
                        archive.filename
                    );
                    return result;
                }
            }
            result.archives.push(destination);
        }

        result.error = validate(&result);
        if !result.is_ok() {
            result.archives.clear();
            if result.error.is_empty() {
                result.error = "provider returned no APK archives".to_string();
            }
        }
        result
    }
}

pub(crate) struct ProviderChain {
    pinned: Option<PinnedApkProvider>,
    apkpure: ApkPureProvider,
}

impl ProviderChain {
    pub(crate) fn new(download_sources_manifest: &Path) -> Self {
        let pinned = if download_sources_manifest.as_os_str().is_empty() {
            None
        } else {
            Some(PinnedApkProvider::new(
                download_sources_manifest.to_path_buf(),
                None,
            ))
        };
        Self {
            pinned,
            apkpure: ApkPureProvider::default(),
        }
    }

    fn append_failure(aggregate: &mut String, provider: &str, failure: &str) {
        if !aggregate.is_empty() {
            aggregate.push_str("; ");
        }
        aggregate.push_str(provider);
        aggregate.push_str(": ");
        aggregate.push_str(failure);
    }

    pub(crate) fn check_latest(&self) -> ProviderVersionData {
        self.apkpure.check_latest()
    }

    pub(crate) fn download_verified(
        &self,
        version: &ProviderVersionData,
        output_directory: &Path,
        progress_fd: c_int,
        validate: &mut dyn FnMut(&ProviderDownloadResult) -> String,
    ) -> ProviderDownloadResult {
        let mut failures = String::new();
        if let Some(pinned) = &self.pinned {
            let res = pinned.download_verified(
                version,
                &output_directory.join(pinned.name()),
                progress_fd,
                validate,
            );
            if res.is_ok() {
                return res;
            }
            Self::append_failure(&mut failures, pinned.name(), &res.error);
        }
        let res = self.apkpure.download_verified(
            version,
            &output_directory.join(self.apkpure.name()),
            progress_fd,
            validate,
        );
        if res.is_ok() {
            return res;
        }
        Self::append_failure(&mut failures, self.apkpure.name(), &res.error);
        ProviderDownloadResult {
            error: failures,
            ..ProviderDownloadResult::default()
        }
    }
}

fn to_store_payload_info(info: MocktailRustPayloadInfo) -> PayloadInfo {
    PayloadInfo {
        payload_id: info.payload_id,
        package_name: info.package_name,
        version_name: info.version_name,
        version_code: info.version_code,
        build_id: info.build_id,
        library_sha256: info.library_sha256,
        base_apk_sha256: info.base_apk_sha256,
        split_apk_sha256: info.split_apk_sha256,
        asset_file_count: info.asset_file_count,
        asset_tree_sha256: info.asset_tree_sha256,
        error: String::new(),
    }
}

fn from_store_payload_info(info: &PayloadInfo) -> MocktailRustPayloadInfo {
    MocktailRustPayloadInfo {
        payload_id: info.payload_id.clone(),
        package_name: info.package_name.clone(),
        version_name: info.version_name.clone(),
        version_code: info.version_code,
        build_id: info.build_id.clone(),
        library_sha256: info.library_sha256.clone(),
        base_apk_sha256: info.base_apk_sha256.clone(),
        split_apk_sha256: info.split_apk_sha256.clone(),
        asset_file_count: info.asset_file_count,
        asset_tree_sha256: info.asset_tree_sha256.clone(),
    }
}

fn to_approval_info(res: CandidateApprovalResultData) -> CandidateApprovalInfo {
    CandidateApprovalInfo {
        generation: res.generation,
        profile: res.profile,
        compatibility_manifest: res.compatibility_manifest,
        receipt: res.receipt,
        error: res.error,
    }
}

pub(crate) struct NativeStoreCallbacks;

impl StoreCallbacks for NativeStoreCallbacks {
    fn inspect_prepared_payload(&self, dir: &Path) -> PayloadInfo {
        match internal_inspect_payload(dir) {
            Ok(info) => to_store_payload_info(info),
            Err(error) => PayloadInfo {
                error,
                ..PayloadInfo::default()
            },
        }
    }

    fn verify_prepared_payload(&self, dir: &Path) -> PayloadInfo {
        match verify_payload_internal(dir) {
            Ok(info) => to_store_payload_info(info),
            Err((_, error)) => PayloadInfo {
                error,
                ..PayloadInfo::default()
            },
        }
    }

    fn hash_regular_file(&self, path: &Path) -> Result<String, String> {
        sha256_regular_file_strict(path, None)
    }

    fn exact_supported(&self, compatibility: &Path, payload: &PayloadInfo) -> Result<(), String> {
        let profiles = load_compatibility_catalog_file(compatibility, &host_guest_abi())?;
        let found = profiles.iter().any(|profile| {
            profile.version_code == payload.version_code
                && profile.version_name == payload.version_name
                && profile.elf_build_id == payload.build_id
        });
        if !found {
            return Err("payload is not an exact default-supported profile".to_string());
        }
        Ok(())
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
        let options = CandidateApprovalOptionsData {
            store_root: store_root.to_path_buf(),
            payload_directory: payload_dir.to_path_buf(),
            profile: profile.to_path_buf(),
            compatibility_manifest: compatibility_manifest.to_path_buf(),
            runtime_binary: runtime_binary.to_path_buf(),
            canary_logs: [canary_logs[0].to_path_buf(), canary_logs[1].to_path_buf()],
        };
        let rust_info = from_store_payload_info(verified_payload);
        to_approval_info(create_candidate_approval(&options, &rust_info))
    }

    fn validate_candidate_approval(
        &self,
        store_root: &Path,
        activation_json: &str,
        payload: &PayloadInfo,
    ) -> Result<CandidateApprovalInfo, String> {
        let rust_info = from_store_payload_info(payload);
        validate_candidate_approval(store_root, activation_json, &rust_info).map(to_approval_info)
    }
}

fn coordinator_store_from(res: StoreResult) -> CoordinatorStoreResult {
    CoordinatorStoreResult {
        payload_id: res.payload_id,
        payload_directory: res.payload_directory,
        host_abi_profile: res.host_abi_profile,
        compatibility_manifest: res.compatibility_manifest,
        version_name: res.version_name,
        version_code: res.version_code,
        build_id: res.build_id,
        error: res.error,
    }
}

fn send_progress_packet(descriptor: c_int, message: &str) {
    if descriptor < 0 {
        return;
    }
    let mut packet = Vec::with_capacity(1 + message.len());
    packet.push(b'P');
    packet.extend_from_slice(message.as_bytes());
    unsafe {
        let _ = libc::send(
            descriptor,
            packet.as_ptr().cast(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        );
    }
}

pub(crate) struct NativeUpdateBackend {
    paths: UpdatePathsData,
    providers: ProviderChain,
}

impl NativeUpdateBackend {
    pub(crate) fn new(paths: UpdatePathsData, download_sources_manifest: &Path) -> Self {
        let providers = ProviderChain::new(download_sources_manifest);
        Self { paths, providers }
    }
}

impl UpdateBackend for NativeUpdateBackend {
    fn provider_check_latest(&self) -> ProviderVersionData {
        self.providers.check_latest()
    }

    fn download_and_prepare(
        &self,
        identity: &ExpectedIdentityData,
        download_directory: &Path,
        prepare_prefix: &Path,
        signing_trust_manifest: &Path,
        progress_fd: i32,
    ) -> Result<PathBuf, String> {
        let version = ProviderVersionData {
            version_name: identity.version_name.clone(),
            version_code: identity.version_code,
            error: String::new(),
        };
        let bundle_identity = ExpectedPayloadIdentityData {
            version_name: identity.version_name.clone(),
            version_code: identity.version_code,
            exact_build_id: identity.exact_build_id.clone(),
        };
        let preparation = Cell::new(0usize);
        let mut prepared_dir = PathBuf::new();

        let downloaded = self.providers.download_verified(
            &version,
            download_directory,
            progress_fd,
            &mut |archives| {
                send_progress_packet(progress_fd, "Verifying Roblox...");
                let count = preparation.get() + 1;
                preparation.set(count);
                let workspace = prepare_prefix.join(format!("prepare-{count}"));
                let origin = format!("{}-native", archives.source);
                let prepared = prepare_payload_from_archives(
                    &archives.archives,
                    &bundle_identity,
                    signing_trust_manifest,
                    &workspace,
                    &origin,
                    &OpenSslApkSignatureVerifier,
                );
                if prepared.error.is_empty() {
                    prepared_dir = prepared.directory;
                }
                prepared.error
            },
        );
        if !downloaded.is_ok() {
            return Err(downloaded.error);
        }
        Ok(prepared_dir)
    }

    fn derive_host_abi_profile(
        &self,
        reference_library: &Path,
        reference_profile: &Path,
        reference_manifests: &[PathBuf],
        candidate_payload_directory: &Path,
        output_directory: &Path,
    ) -> DerivedHostAbiData {
        let mut disasm = CapstoneX86Disassembler::default();
        match derive_host_abi_profile_rs(
            reference_library,
            reference_profile,
            reference_manifests,
            candidate_payload_directory,
            output_directory,
            &mut disasm,
        ) {
            Ok((profile, compatibility_manifest)) => DerivedHostAbiData {
                profile,
                compatibility_manifest,
                error: String::new(),
            },
            Err(error) => DerivedHostAbiData {
                error,
                ..DerivedHostAbiData::default()
            },
        }
    }

    fn store_inspect_current(&self) -> CoordinatorStoreResult {
        coordinator_store_from(inspect_current_impl(
            &self.paths.data_root,
            &NativeStoreCallbacks,
        ))
    }

    fn store_verify_current(&self) -> CoordinatorStoreResult {
        coordinator_store_from(verify_current_impl(
            &self.paths.data_root,
            &self.paths.compatibility_manifest,
            &NativeStoreCallbacks,
        ))
    }

    fn store_stage(&self, prepared_directory: &Path) -> CoordinatorStoreResult {
        coordinator_store_from(stage_impl(
            &self.paths.data_root,
            prepared_directory,
            &NativeStoreCallbacks,
        ))
    }

    fn store_promote(&self, payload_id: &str) -> CoordinatorStoreResult {
        coordinator_store_from(promote_impl(
            &self.paths.data_root,
            &self.paths.compatibility_manifest,
            payload_id,
            &NativeStoreCallbacks,
        ))
    }

    fn store_promote_probation(
        &self,
        payload_id: &str,
        candidate_profile: &Path,
        candidate_compatibility: &Path,
        canary_logs: [&Path; 2],
    ) -> CoordinatorStoreResult {
        coordinator_store_from(promote_probation_impl(
            &self.paths.data_root,
            &self.paths.compatibility_manifest,
            &self.paths.runtime_binary,
            payload_id,
            candidate_profile,
            candidate_compatibility,
            canary_logs,
            &NativeStoreCallbacks,
        ))
    }

    fn store_collect_garbage(&self, keep: &[String]) -> GarbageCollectData {
        let res = collect_garbage_impl(&self.paths.data_root, keep);
        GarbageCollectData {
            removed_count: res.removed.len(),
            freed_bytes: res.freed_bytes,
            error: res.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "mocktail_provider_{}_{}_{:?}",
                tag,
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn apkpure_provider_parses_latest_and_falls_back_to_all_abis() {
        let tmp = TempDir::new("apkpure");
        let saw_fallback = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&saw_fallback);

        let fetcher: MetadataFetcher = Box::new(move |arch: &str| {
            let mut body = Vec::new();
            if arch == FALLBACK_ARCH_HEADER {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                body.extend_from_slice(&[0x2a, 4]);
                body.extend_from_slice(b"2814");
                body.extend_from_slice(&[0x32, 10]);
                body.extend_from_slice(b"2.732.1043:");
                body.extend_from_slice(
                    b"XAPKJ\x00\x00https://d.apkpure.com/b/XAPK/com.roblox.client?versionCode=2814",
                );
                body.push(0);
            } else {
                body.extend_from_slice(&[0x2a, 4]);
                body.extend_from_slice(b"2900");
                body.extend_from_slice(&[0x32, 7]);
                body.extend_from_slice(b"2.900.1:");
                body.extend_from_slice(
                    b"APKJ\x00\x00https://d.apkpure.com/b/APK/com.roblox.client?versionCode=2900",
                );
                body.push(0);
            }
            HttpBytesResultData {
                bytes: body,
                status_code: 200,
                ..HttpBytesResultData::default()
            }
        });

        let downloader: FileDownloader = Box::new(|_req, dest, _fd| {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::write(dest, b"PK\x03\x04dummy-zip").unwrap();
            HttpDownloadResultData {
                bytes_written: 13,
                ..HttpDownloadResultData::default()
            }
        });

        let provider = ApkPureProvider::new(Some(fetcher), Some(downloader));
        let latest = provider.check_latest();
        assert!(latest.is_valid(), "err: {}", latest.error);
        assert_eq!(latest.version_name, "2.900.1");
        assert_eq!(latest.version_code, 2900);

        let target = ProviderVersionData {
            version_name: "2.732.1043".to_string(),
            version_code: 2814,
            error: String::new(),
        };
        let dl_dir = tmp.0.join("out");
        let downloaded = provider.download_verified(&target, &dl_dir, -1, &mut |res| {
            assert_eq!(res.archives.len(), 1);
            String::new()
        });
        assert!(downloaded.is_ok(), "err: {}", downloaded.error);
        assert!(saw_fallback.load(std::sync::atomic::Ordering::SeqCst));
        assert!(downloaded.archives[0].ends_with("candidate-1.xapk"));
    }

    #[test]
    fn pinned_provider_verifies_cached_and_rejects_mismatched_download() {
        let tmp = TempDir::new("pinned");
        let manifest = tmp.0.join("sources.json");
        let payload = b"PK\x03\x04pinned-apk-content";
        let payload_sha = hex::encode(Sha256::digest(payload));
        let json = format!(
            r#"{{
  "schema_version": 1,
  "sources": [{{
    "package": "com.roblox.client",
    "abi": "{}",
    "version_name": "2.700.1",
    "version_code": 700,
    "elf_build_id": "0123456789abcdef0123456789abcdef01234567",
    "archives": [{{
      "filename": "base.apk",
      "url": "https://github.com/org/repo/releases/download/v1/base.apk",
      "sha256": "{}",
      "size": {}
    }}]
  }}]
}}"#,
            host_guest_abi(),
            payload_sha,
            payload.len()
        );
        fs::write(&manifest, json).unwrap();

        let bad_dl: FileDownloader = Box::new(|_req, dest, _fd| {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::write(dest, b"PK\x03\x04wrong-bytes!!").unwrap();
            HttpDownloadResultData {
                bytes_written: 17,
                ..HttpDownloadResultData::default()
            }
        });
        let provider_bad = PinnedApkProvider::new(manifest.clone(), Some(bad_dl));
        let ver = ProviderVersionData {
            version_name: "2.700.1".to_string(),
            version_code: 700,
            error: String::new(),
        };
        let dl_dir = tmp.0.join("dl");
        fs::create_dir_all(&dl_dir).unwrap();
        let res_bad = provider_bad.download_verified(&ver, &dl_dir, -1, &mut |_| String::new());
        assert!(!res_bad.is_ok());
        assert!(
            res_bad.error.contains("does not match the pinned SHA-256 or size"),
            "unexpected err: {}",
            res_bad.error
        );

        let good_dl: FileDownloader = Box::new(|_req, dest, _fd| {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::write(dest, b"PK\x03\x04pinned-apk-content").unwrap();
            HttpDownloadResultData {
                bytes_written: 22,
                ..HttpDownloadResultData::default()
            }
        });
        let provider_good = PinnedApkProvider::new(manifest, Some(good_dl));
        let res_good = provider_good.download_verified(&ver, &dl_dir, -1, &mut |_| String::new());
        assert!(res_good.is_ok(), "err: {}", res_good.error);
        assert_eq!(res_good.archives, vec![dl_dir.join("base.apk")]);
    }
}
