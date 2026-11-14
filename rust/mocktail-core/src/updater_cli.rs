//! 100% pure-Rust CLI entrypoint logic for `mocktail_updater`.
//!
//! Preserves exact path discovery, environment variable overrides, CLI commands,
//! stdout/stderr diagnostics, and exit codes.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::apk_bundle::{prepare_payload_from_archives, ExpectedPayloadIdentityData};
use crate::apk_signature_rs::verify_apk_signature_openssl;
use crate::capstone_ffi::CapstoneX86Disassembler;
use crate::host_abi_deriver::derive_host_abi_profile_rs;
use crate::payload_store::{rollback_impl, status_json_impl, verify_current_impl};
use crate::provider_rs::{
    ApkPureProvider, NativeStoreCallbacks, NativeUpdateBackend, OpenSslApkSignatureVerifier,
};
use crate::readiness_canary::canary_backend_parse_str;
use crate::update_coordinator::{
    exact_payload_identity, find_supported_profile, run_update_internal, UpdatePathsData,
    UpdateRequestData,
};
use crate::{
    host_guest_abi, load_compatibility_catalog_file, parse_android_manifest_bytes,
    zip_read_entry_bytes,
};

const K_MAXIMUM_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

const DEFAULT_COMPATIBILITY_MANIFEST: &str = match option_env!(
    "MOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST"
) {
    Some(v) => v,
    None => "config/roblox_compatibility.json",
};

const DEFAULT_SIGNING_TRUST_MANIFEST: &str = match option_env!(
    "MOCKTAIL_DEFAULT_SIGNING_TRUST_MANIFEST"
) {
    Some(v) => v,
    None => "config/roblox_signing_certificates.json",
};

const DEFAULT_DOWNLOAD_SOURCES_MANIFEST: &str = match option_env!(
    "MOCKTAIL_DEFAULT_DOWNLOAD_SOURCES_MANIFEST"
) {
    Some(v) => v,
    None => "config/roblox_download_sources.json",
};

#[derive(Debug, Clone)]
pub(crate) struct ResolvedUpdaterPaths {
    pub coordinator_paths: UpdatePathsData,
    pub download_sources_manifest: PathBuf,
}

fn non_empty_env_with<F>(var: &str, lookup: &F) -> Option<OsString>
where
    F: Fn(&str) -> Option<OsString>,
{
    lookup(var).filter(|v| !v.is_empty())
}

fn xdg_root_with<F>(variable: &str, fallback_suffix: &str, lookup: &F) -> PathBuf
where
    F: Fn(&str) -> Option<OsString>,
{
    if let Some(val) = non_empty_env_with(variable, lookup) {
        let path = PathBuf::from(&val);
        if path.is_absolute() {
            return path;
        }
    }
    let home = non_empty_env_with("HOME", lookup)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(fallback_suffix)
}

fn is_private_mocktail_bindir(directory: &Path) -> bool {
    if directory.file_name().and_then(|s| s.to_str()) != Some("mocktail") {
        return false;
    }
    matches!(
        directory
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str()),
        Some("lib" | "lib64" | "libexec")
    )
}

fn installed_metadata_entry_with<D, F>(
    executable: Option<&Path>,
    name: &str,
    directory_entry: bool,
    is_dir: &D,
    is_file: &F,
) -> Option<PathBuf>
where
    D: Fn(&Path) -> bool,
    F: Fn(&Path) -> bool,
{
    let exe = executable?;
    let directory = exe.parent()?;
    let parent = directory.parent()?;
    let prefix = if is_private_mocktail_bindir(directory) {
        parent.parent()?
    } else {
        parent
    };
    for metadata in [prefix.join("share/mocktail/metadata"), prefix.join("metadata")] {
        let candidate = metadata.join(name);
        let matches = if directory_entry {
            is_dir(&candidate)
        } else {
            is_file(&candidate)
        };
        if matches {
            return Some(candidate);
        }
    }
    None
}

pub(crate) fn resolve_paths_with<E, D, F>(
    executable: Option<&Path>,
    lookup_env: &E,
    is_dir: &D,
    is_file: &F,
) -> ResolvedUpdaterPaths
where
    E: Fn(&str) -> Option<OsString>,
    D: Fn(&Path) -> bool,
    F: Fn(&Path) -> bool,
{
    let config_file = non_empty_env_with("MOCKTAIL_CONFIG_FILE", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| xdg_root_with("XDG_CONFIG_HOME", ".config", lookup_env).join("mocktail/config.yaml"));
    let data_root = non_empty_env_with("MOCKTAIL_DATA_ROOT", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| xdg_root_with("XDG_DATA_HOME", ".local/share", lookup_env).join("mocktail"));
    let cache_root = non_empty_env_with("MOCKTAIL_CACHE_ROOT", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| xdg_root_with("XDG_CACHE_HOME", ".cache", lookup_env).join("mocktail"));
    let state_root = non_empty_env_with("MOCKTAIL_STATE_ROOT", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| xdg_root_with("XDG_STATE_HOME", ".local/state", lookup_env).join("mocktail"));

    let installed_compat =
        installed_metadata_entry_with(executable, "roblox_compatibility.json", false, is_dir, is_file);
    let installed_trust = installed_metadata_entry_with(
        executable,
        "roblox_signing_certificates.json",
        false,
        is_dir,
        is_file,
    );
    let installed_sources = installed_metadata_entry_with(
        executable,
        "roblox_download_sources.json",
        false,
        is_dir,
        is_file,
    );

    let default_host_abi = installed_metadata_entry_with(executable, "host_abi", true, is_dir, is_file)
        .or_else(|| {
            installed_metadata_entry_with(
                executable,
                "roblox_host_abi_reference.json",
                false,
                is_dir,
                is_file,
            )
        })
        .unwrap_or_else(|| {
            let local_dir = Path::new("config/host_abi");
            if is_dir(local_dir) {
                local_dir.to_path_buf()
            } else {
                PathBuf::from("config/roblox_host_abi_reference.json")
            }
        });

    let compatibility_manifest = non_empty_env_with("MOCKTAIL_UPDATE_COMPATIBILITY_PATH", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            installed_compat.unwrap_or_else(|| PathBuf::from(DEFAULT_COMPATIBILITY_MANIFEST))
        });
    let signing_trust_manifest = non_empty_env_with("MOCKTAIL_UPDATE_SIGNING_TRUST_PATH", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            installed_trust.unwrap_or_else(|| PathBuf::from(DEFAULT_SIGNING_TRUST_MANIFEST))
        });
    let download_sources_manifest =
        non_empty_env_with("MOCKTAIL_UPDATE_DOWNLOAD_SOURCES_PATH", lookup_env)
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                installed_sources
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_DOWNLOAD_SOURCES_MANIFEST))
            });
    let host_abi_reference_profile = non_empty_env_with("MOCKTAIL_UPDATE_HOST_ABI_REFERENCE", lookup_env)
        .map(PathBuf::from)
        .unwrap_or(default_host_abi);

    let runtime = executable
        .and_then(|exe| exe.parent())
        .map(|directory| {
            let mut candidate = directory.join("mocktail");
            if is_private_mocktail_bindir(directory) {
                if let Some(prefix) = directory.parent().and_then(|p| p.parent()) {
                    let public_runtime = prefix.join("bin/mocktail");
                    if is_file(&public_runtime) {
                        candidate = public_runtime;
                    }
                }
            }
            candidate
        })
        .unwrap_or_else(|| PathBuf::from("mocktail"));

    let runtime_launcher = non_empty_env_with("MOCKTAIL_UPDATE_CANARY_BIN", lookup_env)
        .map(PathBuf::from)
        .unwrap_or(runtime);
    let runtime_binary = non_empty_env_with("MOCKTAIL_UPDATE_RUNTIME_BINARY", lookup_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| runtime_launcher.clone());

    ResolvedUpdaterPaths {
        coordinator_paths: UpdatePathsData {
            config_file,
            data_root,
            cache_root,
            state_root,
            compatibility_manifest,
            signing_trust_manifest,
            host_abi_reference_profile,
            runtime_binary,
            runtime_launcher,
        },
        download_sources_manifest,
    }
}

fn resolve_paths() -> ResolvedUpdaterPaths {
    let exe = std::fs::read_link("/proc/self/exe").ok();
    resolve_paths_with(
        exe.as_deref(),
        &|k| env::var_os(k),
        &|p| p.is_dir(),
        &|p| p.is_file(),
    )
}

fn progress_descriptor() -> i32 {
    env::var("MOCKTAIL_UPDATE_PROGRESS_FD")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|&fd| fd >= 0)
        .unwrap_or(-1)
}

fn print_usage() {
    eprint!(
        "Usage: mocktail_updater COMMAND [OPTIONS]\n\n\
         Commands:\n\
         \x20 update [--startup-preflight] [--no-latest-check] [--skip-canary] [--download-only]\n\
         \x20 check-latest\n\
         \x20 verify-current\n\
         \x20 verify-apk APK\n\
         \x20 prepare-apks OUTPUT APK [APK...]\n\
         \x20 derive-host-abi OUTPUT REF_LIB REF_PROFILE CANDIDATE_DIR [REF_COMPAT...]\n\
         \x20 status\n\
         \x20 rollback\n"
    );
}

fn parse_update_request(
    options: &[String],
    graphics_backend_env: Option<&str>,
    progress_fd: i32,
) -> Result<UpdateRequestData, (i32, String)> {
    let backend_name = graphics_backend_env
        .filter(|s| !s.is_empty())
        .unwrap_or("direct-vulkan");
    let Some(canary_graphics_backend) = canary_backend_parse_str(backend_name) else {
        return Err((
            2,
            format!("[native-updater] unsupported graphics backend: {backend_name}"),
        ));
    };

    let mut request = UpdateRequestData {
        startup_preflight: false,
        check_latest: true,
        run_canary: true,
        download_only: false,
        force_run_latest: false,
        canary_graphics_backend,
        progress_fd,
    };

    for option in options {
        match option.as_str() {
            "--startup-preflight" => request.startup_preflight = true,
            "--no-latest-check" => request.check_latest = false,
            "--download-only" => request.download_only = true,
            "--skip-canary" => request.run_canary = false,
            "--force-run-latest" => request.force_run_latest = true,
            other => {
                return Err((2, format!("[native-updater] unknown option: {other}")));
            }
        }
    }

    if request.force_run_latest
        && (request.startup_preflight
            || request.download_only
            || !request.check_latest
            || !request.run_canary)
    {
        return Err((
            2,
            "[native-updater] --force-run-latest cannot be combined with \
             --startup-preflight, --download-only, --no-latest-check, or --skip-canary"
                .to_string(),
        ));
    }

    Ok(request)
}

fn run_with_args(args: &[String], resolved: ResolvedUpdaterPaths) -> i32 {
    if args.len() < 2 {
        print_usage();
        return 2;
    }

    let paths = resolved.coordinator_paths;
    let command = args[1].as_str();

    match command {
        "check-latest" => {
            if args.len() != 2 {
                return 2;
            }
            let latest = ApkPureProvider::default().check_latest();
            if !latest.is_valid() {
                eprintln!("[native-updater] {}", latest.error);
                return 1;
            }
            println!("{} {}", latest.version_name, latest.version_code);
            0
        }
        "status" => {
            if args.len() != 2 {
                return 2;
            }
            match status_json_impl(&paths.data_root) {
                Ok(status) => {
                    print!("{status}");
                    0
                }
                Err(err) => {
                    eprintln!("[native-updater] {err}");
                    1
                }
            }
        }
        "verify-current" => {
            if args.len() != 2 {
                return 2;
            }
            let current = verify_current_impl(
                &paths.data_root,
                &paths.compatibility_manifest,
                &NativeStoreCallbacks,
            );
            if !current.error.is_empty() || current.payload_id.is_empty() {
                eprintln!("[native-updater] {}", current.error);
                return 1;
            }
            println!("{}", current.payload_id);
            0
        }
        "verify-apk" => {
            if args.len() != 3 {
                return 2;
            }
            let apk = Path::new(&args[2]);
            let certs = match verify_apk_signature_openssl(apk) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("[native-updater] {err}");
                    return 1;
                }
            };
            let manifest_bytes =
                match zip_read_entry_bytes(apk, "AndroidManifest.xml", K_MAXIMUM_MANIFEST_BYTES) {
                    Ok(b) => b,
                    Err((_, err)) => {
                        eprintln!("[native-updater] {err}");
                        return 1;
                    }
                };
            let identity = match parse_android_manifest_bytes(&manifest_bytes) {
                Ok(id) => id,
                Err(err) => {
                    eprintln!("[native-updater] {err}");
                    return 1;
                }
            };
            let split_or_base = if identity.split_name.is_empty() {
                "base"
            } else {
                identity.split_name.as_str()
            };
            println!(
                "{} {} {} {}",
                identity.package_name, identity.version_name, identity.version_code, split_or_base
            );
            for cert in certs {
                println!("{cert}");
            }
            0
        }
        "prepare-apks" => {
            if args.len() < 4 {
                return 2;
            }
            let output_dir = Path::new(&args[2]);
            let archives: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();
            let manifest_bytes = match zip_read_entry_bytes(
                &archives[0],
                "AndroidManifest.xml",
                K_MAXIMUM_MANIFEST_BYTES,
            ) {
                Ok(b) => b,
                Err((_, err)) => {
                    eprintln!("[native-updater] {err}");
                    return 1;
                }
            };
            let identity = match parse_android_manifest_bytes(&manifest_bytes) {
                Ok(id) => id,
                Err(err) => {
                    eprintln!("[native-updater] {err}");
                    return 1;
                }
            };
            let catalog = match load_compatibility_catalog_file(
                &paths.compatibility_manifest,
                &host_guest_abi(),
            ) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("[native-updater] {err}");
                    return 1;
                }
            };
            let Some(profile) = find_supported_profile(
                &catalog,
                &identity.version_name,
                identity.version_code,
            ) else {
                eprintln!("[native-updater] APK is not exact-supported");
                return 1;
            };
            let exact = exact_payload_identity(profile);
            let bundle_expected = ExpectedPayloadIdentityData {
                version_name: exact.version_name,
                version_code: exact.version_code,
                exact_build_id: exact.exact_build_id,
            };
            let prepared = prepare_payload_from_archives(
                &archives,
                &bundle_expected,
                &paths.signing_trust_manifest,
                output_dir,
                "native-local-import",
                &OpenSslApkSignatureVerifier,
            );
            if !prepared.error.is_empty() || prepared.directory.as_os_str().is_empty() {
                eprintln!("[native-updater] {}", prepared.error);
                return 1;
            }
            println!("{}", prepared.directory.display());
            0
        }
        "rollback" => {
            if args.len() != 2 {
                return 2;
            }
            let rolled = rollback_impl(
                &paths.data_root,
                &paths.compatibility_manifest,
                &NativeStoreCallbacks,
            );
            if !rolled.error.is_empty() || rolled.payload_id.is_empty() {
                eprintln!("[native-updater] {}", rolled.error);
                return 1;
            }
            println!("{}", rolled.payload_id);
            0
        }
        "derive-host-abi" => {
            if args.len() < 6 {
                return 2;
            }
            let output_dir = Path::new(&args[2]);
            let ref_lib = Path::new(&args[3]);
            let ref_profile = Path::new(&args[4]);
            let candidate_dir = Path::new(&args[5]);
            let ref_compats: Vec<PathBuf> = args[6..].iter().map(PathBuf::from).collect();
            let mut disasm = CapstoneX86Disassembler::default();
            match derive_host_abi_profile_rs(
                ref_lib,
                ref_profile,
                &ref_compats,
                candidate_dir,
                output_dir,
                &mut disasm,
            ) {
                Ok((profile, compat)) => {
                    println!("{}", profile.display());
                    println!("{}", compat.display());
                    0
                }
                Err(err) => {
                    eprintln!("[native-updater] {err}");
                    1
                }
            }
        }
        "update" => {
            let graphics_backend = env::var("MOCKTAIL_GRAPHICS_BACKEND").ok();
            let request = match parse_update_request(
                &args[2..],
                graphics_backend.as_deref(),
                progress_descriptor(),
            ) {
                Ok(req) => req,
                Err((code, msg)) => {
                    eprintln!("{msg}");
                    return code;
                }
            };
            if request.force_run_latest {
                eprintln!(
                    "[native-updater] WARNING: latest Roblox will run once without \
                     approval and will not become the active payload"
                );
            }
            let backend =
                NativeUpdateBackend::new(paths.clone(), &resolved.download_sources_manifest);
            let updated = run_update_internal(&paths, &request, &backend);
            for warning in &updated.warnings {
                eprintln!("[native-updater] warning: {warning}");
            }
            if !updated.is_ok() {
                eprintln!("[native-updater] {}", updated.error);
                return 1;
            }
            if !updated.message.is_empty() {
                eprintln!("[native-updater] {}", updated.message);
            }
            if updated.stale {
                eprintln!(
                    "[native-updater] warning: the active Roblox payload is out \
                     of date and joining an experience can be refused"
                );
            }
            if !updated.payload_id.is_empty() {
                println!("{}", updated.payload_id);
            }
            0
        }
        _ => {
            print_usage();
            2
        }
    }
}

/// Process entrypoint invoked by `src/bin/mocktail_updater.rs`.
pub fn run_from_process_args() -> i32 {
    let args: Vec<String> = env::args().collect();
    let resolved = resolve_paths();
    run_with_args(&args, resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn resolve_paths_handles_private_lib_layout_and_env_overrides() {
        let mut envs: BTreeMap<&str, OsString> = BTreeMap::new();
        envs.insert("HOME", OsString::from("/home/alice"));
        envs.insert("XDG_CONFIG_HOME", OsString::from("/custom/cfg"));
        envs.insert("XDG_DATA_HOME", OsString::from("relative-ignored"));

        let exe = Path::new("/opt/app/lib/mocktail/mocktail_updater");
        let resolved = resolve_paths_with(
            Some(exe),
            &|k| envs.get(k).cloned(),
            &|p| p == Path::new("/opt/app/share/mocktail/metadata/host_abi"),
            &|p| {
                p == Path::new("/opt/app/share/mocktail/metadata/roblox_compatibility.json")
                    || p == Path::new("/opt/app/bin/mocktail")
            },
        );
        assert_eq!(
            resolved.coordinator_paths.config_file,
            PathBuf::from("/custom/cfg/mocktail/config.yaml")
        );
        assert_eq!(
            resolved.coordinator_paths.data_root,
            PathBuf::from("/home/alice/.local/share/mocktail")
        );
        assert_eq!(
            resolved.coordinator_paths.compatibility_manifest,
            PathBuf::from("/opt/app/share/mocktail/metadata/roblox_compatibility.json")
        );
        assert_eq!(
            resolved.coordinator_paths.host_abi_reference_profile,
            PathBuf::from("/opt/app/share/mocktail/metadata/host_abi")
        );
        assert_eq!(
            resolved.coordinator_paths.runtime_launcher,
            PathBuf::from("/opt/app/bin/mocktail")
        );
    }

    #[test]
    fn parse_update_request_validates_flags_and_graphics_backend() {
        let ok = parse_update_request(&["--skip-canary".to_string()], None, 7).unwrap();
        assert!(ok.check_latest);
        assert!(!ok.run_canary);
        assert_eq!(ok.progress_fd, 7);

        let conflict = parse_update_request(
            &["--force-run-latest".to_string(), "--skip-canary".to_string()],
            None,
            -1,
        )
        .unwrap_err();
        assert_eq!(conflict.0, 2);

        let bad_backend = parse_update_request(&[], Some("bogus"), -1).unwrap_err();
        assert_eq!(bad_backend.0, 2);
        assert!(bad_backend.1.contains("unsupported graphics backend: bogus"));
    }
}
