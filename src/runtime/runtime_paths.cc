// Includes changes by vii from CoderDayton/nightcap.
#include "runtime/runtime_paths.h"

#include <optional>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.data(), value.size()};
}

MocktailRustStrSlice ToSliceOpt(const std::optional<std::string>& value) {
  if (!value.has_value()) {
    return {nullptr, 0};
  }
  return ToSlice(*value);
}

std::string ToString(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return std::string(slice.ptr, slice.len);
}

std::filesystem::path ToPath(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return std::filesystem::path(std::string_view(slice.ptr, slice.len));
}

void AssignError(void* ctx, MocktailRustStrSlice error) {
  auto* target = static_cast<std::string*>(ctx);
  if (target != nullptr) {
    *target = ToString(error);
  }
}

void AssignRuntimeString(void* ctx, const char* value, size_t length) {
  auto* target = static_cast<std::string*>(ctx);
  if (target == nullptr) {
    return;
  }
  target->assign(value != nullptr ? value : "", length);
}

}  // namespace

RuntimePaths RuntimePaths::FromEnvironment(
    const Environment& environment, std::filesystem::path working_directory) {
  const std::optional<std::string> home = environment.Get("HOME");
  const std::string working_dir_str = working_directory.string();
  const std::optional<std::string> mocktail_config_root =
      environment.Get("MOCKTAIL_CONFIG_ROOT");
  const std::optional<std::string> xdg_config_home =
      environment.Get("XDG_CONFIG_HOME");
  const std::optional<std::string> xdg_data_home =
      environment.Get("XDG_DATA_HOME");
  const std::optional<std::string> xdg_cache_home =
      environment.Get("XDG_CACHE_HOME");
  const std::optional<std::string> xdg_state_home =
      environment.Get("XDG_STATE_HOME");
  const std::optional<std::string> mocktail_data_root =
      environment.Get("MOCKTAIL_DATA_ROOT");
  const std::optional<std::string> mocktail_cache_root =
      environment.Get("MOCKTAIL_CACHE_ROOT");
  const std::optional<std::string> mocktail_state_root =
      environment.Get("MOCKTAIL_STATE_ROOT");
  const std::optional<std::string> mocktail_auth_root =
      environment.Get("MOCKTAIL_AUTH_ROOT");
  const std::optional<std::string> use_real_sober_paths =
      environment.Get("MOCKTAIL_USE_REAL_SOBER_PATHS");

  MocktailRustRuntimeEnvOverridesView input{};
  input.home = ToSliceOpt(home);
  input.working_directory = ToSlice(working_dir_str);
  input.mocktail_config_root = ToSliceOpt(mocktail_config_root);
  input.xdg_config_home = ToSliceOpt(xdg_config_home);
  input.xdg_data_home = ToSliceOpt(xdg_data_home);
  input.xdg_cache_home = ToSliceOpt(xdg_cache_home);
  input.xdg_state_home = ToSliceOpt(xdg_state_home);
  input.mocktail_data_root = ToSliceOpt(mocktail_data_root);
  input.mocktail_cache_root = ToSliceOpt(mocktail_cache_root);
  input.mocktail_state_root = ToSliceOpt(mocktail_state_root);
  input.mocktail_auth_root = ToSliceOpt(mocktail_auth_root);
  input.use_real_sober_paths = ToSliceOpt(use_real_sober_paths);

  RuntimePaths paths;
  mocktail_rust_runtime_paths_from_environment(
      &input,
      [](void* ctx, const MocktailRustRuntimePathsView* view) {
        if (ctx == nullptr || view == nullptr) {
          return;
        }
        auto* out = static_cast<RuntimePaths*>(ctx);
        out->home_ = ToPath(view->home);
        out->working_directory_ = ToPath(view->working_directory);
        out->sober_data_root_ = ToPath(view->sober_data_root);
        out->sober_cache_root_ = ToPath(view->sober_cache_root);
        out->cache_root_ = ToPath(view->cache_root);
        out->config_root_ = ToPath(view->config_root);
        out->data_root_ = ToPath(view->data_root);
        out->state_root_ = ToPath(view->state_root);
        out->auth_root_ = ToPath(view->auth_root);
        out->payloads_root_ = ToPath(view->payloads_root);
        out->downloads_root_ = ToPath(view->downloads_root);
        out->logs_root_ = ToPath(view->logs_root);
        out->android_runtime_root_ = ToPath(view->android_runtime_root);
        out->android_data_root_ = ToPath(view->android_data_root);
        out->android_cache_root_ = ToPath(view->android_cache_root);
        out->vulkan_shader_cache_file_ =
            ToPath(view->vulkan_shader_cache_file);
        out->config_file_ = ToPath(view->config_file);
        out->active_payload_manifest_ = ToPath(view->active_payload_manifest);
        out->cookie_file_ = ToPath(view->cookie_file);
        out->use_real_sober_paths_ = view->use_real_sober_paths;
      },
      &paths);
  return paths;
}

std::filesystem::path RuntimePaths::DefaultAssetPath() const {
  const std::string data_root = data_root_.string();
  const std::string payloads_root = payloads_root_.string();
  const std::string active_manifest = active_payload_manifest_.string();
  const std::string working_directory = working_directory_.string();
  const std::string sober_data_root = sober_data_root_.string();
  std::filesystem::path resolved;
  mocktail_rust_runtime_paths_default_asset_path(
      ToSlice(data_root), ToSlice(payloads_root), ToSlice(active_manifest),
      ToSlice(working_directory), ToSlice(sober_data_root),
      use_real_sober_paths_,
      [](void* ctx, MocktailRustStrSlice path) {
        if (ctx != nullptr) {
          *static_cast<std::filesystem::path*>(ctx) = ToPath(path);
        }
      },
      &resolved);
  return resolved;
}

ActivePayloadPaths RuntimePaths::ResolveActivePayload() const {
  const std::string data_root = data_root_.string();
  const std::string payloads_root = payloads_root_.string();
  const std::string active_manifest = active_payload_manifest_.string();
  ActivePayloadPaths result;
  mocktail_rust_runtime_paths_resolve_active_payload(
      ToSlice(data_root), ToSlice(payloads_root), ToSlice(active_manifest),
      [](void* ctx, const MocktailRustActivePayloadPathsView* view) {
        if (ctx == nullptr || view == nullptr) {
          return;
        }
        auto* out = static_cast<ActivePayloadPaths*>(ctx);
        out->active = view->active;
        out->root = ToPath(view->root);
        out->roblox_library = ToPath(view->roblox_library);
        out->base_apk = ToPath(view->base_apk);
        out->arch_split_apk = ToPath(view->arch_split_apk);
        out->assets_content = ToPath(view->assets_content);
        out->compatibility_manifest = ToPath(view->compatibility_manifest);
        out->host_abi_profile = ToPath(view->host_abi_profile);
        out->host_abi_approval_receipt =
            ToPath(view->host_abi_approval_receipt);
        out->error = ToString(view->error);
      },
      &result);
  return result;
}

std::filesystem::path RuntimePaths::DefaultSoberAwarePath(
    const std::filesystem::path& sober_path,
    const std::filesystem::path& fallback_path) const {
  if (use_real_sober_paths_ && Exists(sober_path)) {
    return sober_path;
  }
  return fallback_path;
}

bool RuntimePaths::Exists(const std::filesystem::path& path) {
  if (path.empty()) {
    return false;
  }
  std::error_code error;
  return std::filesystem::exists(path, error) && !error;
}

bool RuntimePaths::EnsureDirectory(const std::filesystem::path& path,
                                   std::error_code* error) {
  std::error_code local_error;
  if (path.empty()) {
    local_error = std::make_error_code(std::errc::invalid_argument);
  } else if (!std::filesystem::create_directories(path, local_error) &&
             !local_error) {
    if (!std::filesystem::is_directory(path, local_error) && !local_error) {
      local_error = std::make_error_code(std::errc::not_a_directory);
    }
  }
  if (error != nullptr) {
    *error = local_error;
  }
  return !local_error;
}

bool ExportRuntimePathEnvironment(const RuntimePaths& paths,
                                  std::string* error) {
  const std::string config_root = paths.config_root().string();
  const std::string android_runtime_root =
      paths.android_runtime_root().string();
  const std::string android_cache_root = paths.android_cache_root().string();
  const std::string vulkan_shader_cache_file =
      paths.vulkan_shader_cache_file().string();
  std::string rust_error;
  const bool ok = mocktail_rust_runtime_paths_export_environment(
      ToSlice(config_root), ToSlice(android_runtime_root),
      ToSlice(android_cache_root), ToSlice(vulkan_shader_cache_file),
      AssignError, &rust_error);
  if (!ok && error != nullptr) {
    *error = std::move(rust_error);
  }
  return ok;
}

bool PrepareManagedPayloadWorkingDirectory(const RuntimePaths& paths,
                                           const ActivePayloadPaths& active,
                                           std::string* error) {
  const std::string data_root = paths.data_root().string();
  const std::string active_root = active.root.string();
  std::string rust_error;
  const bool ok = mocktail_rust_runtime_paths_prepare_managed_working_dir(
      ToSlice(data_root), ToSlice(active_root), active.active, AssignError,
      &rust_error);
  if (!ok && error != nullptr) {
    *error = std::move(rust_error);
  }
  return ok;
}

std::filesystem::path ResolveAdjacentRobloxAssetPath(
    const std::filesystem::path& roblox_library,
    const std::filesystem::path& working_directory) {
  std::string out;
  mocktail_rust_runtime_paths_resolve_adjacent_roblox_asset_path(
      roblox_library.c_str(), working_directory.c_str(), AssignRuntimeString,
      &out);
  return out.empty() ? std::filesystem::path() : std::filesystem::path(out);
}

}  // namespace runtime
}  // namespace mocktail
