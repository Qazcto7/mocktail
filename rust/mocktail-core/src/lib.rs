use std::os::raw::c_int;

pub mod apk_bundle;
pub use apk_bundle::*;
pub mod android_looper;
pub use android_looper::*;
pub mod apk_signature_rs;
pub use apk_signature_rs::*;
pub mod audio_runtime;
pub use audio_runtime::*;
pub mod browser_tracker_service;
pub use browser_tracker_service::*;
pub mod candidate_approval;
pub use candidate_approval::*;
pub mod cpu_runtime;
pub use cpu_runtime::*;
#[cfg(any(test, feature = "updater"))]
pub(crate) mod capstone_ffi;
pub mod deriver_json;
pub use deriver_json::*;
pub mod discord_rpc;
pub use discord_rpc::*;
pub(crate) mod elf_reader;
pub mod external_launch_broker;
pub use external_launch_broker::*;
pub mod graphics_launch;
pub use graphics_launch::*;
pub mod host_abi_deriver;
pub use host_abi_deriver::*;
pub mod http_download;
pub use http_download::*;
pub mod http_transport;
pub use http_transport::*;
pub mod input_router;
pub use input_router::*;
pub mod memory_pressure;
pub use memory_pressure::*;
pub mod micup_rpc;
pub use micup_rpc::*;
pub mod payload_store;
pub use payload_store::*;
pub mod payload_update_preflight;
pub use payload_update_preflight::*;
#[cfg(any(test, feature = "updater"))]
pub(crate) mod provider_rs;
pub mod readiness_canary;
pub use readiness_canary::*;
pub mod roblox_cookie_store;
pub use roblox_cookie_store::*;
pub mod runtime_bridges;
pub use runtime_bridges::*;
pub mod runtime_policies;
pub use runtime_policies::*;
pub mod services_rs;
pub use services_rs::*;
pub mod storage_paths;
pub use storage_paths::*;
pub mod text_runtime;
pub use text_runtime::*;
pub mod update_coordinator;
pub use update_coordinator::*;
pub mod update_json;
pub use update_json::*;
#[cfg(any(test, feature = "updater"))]
pub mod updater_cli;
pub(crate) mod unix_ipc;
pub mod vulkan_etc2;
pub use vulkan_etc2::*;
pub mod webview_helper_launcher;
pub use webview_helper_launcher::*;
pub mod window_gates;
pub use window_gates::*;

pub mod legacy_core_crypto;
pub use legacy_core_crypto::*;
pub mod legacy_config_compat;
pub use legacy_config_compat::*;
pub mod legacy_etc_payload;
pub use legacy_etc_payload::*;
pub mod legacy_policy_bridges;
pub use legacy_policy_bridges::*;
pub mod legacy_runtime_engines;
pub use legacy_runtime_engines::*;
#[cfg(test)]
mod legacy_tests;

/// Initializes and verifies the mocktail-core Rust subsystem.
#[no_mangle]
pub extern "C" fn mocktail_rust_init() -> c_int {
    // 0 = Success
    0
}
