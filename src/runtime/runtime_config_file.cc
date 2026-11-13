#include "runtime/runtime_config_file.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

using ValueMap = std::unordered_map<std::string, std::string>;

class LayeredEnvironment final : public Environment {
 public:
  LayeredEnvironment(const Environment& primary, ValueMap fallback)
      : primary_(primary), fallback_(std::move(fallback)) {}

  std::optional<std::string> Get(std::string_view name) const override {
    const std::optional<std::string> primary = primary_.Get(name);
    if (primary.has_value()) {
      return primary;
    }
    const auto found = fallback_.find(std::string(name));
    return found == fallback_.end() ? std::nullopt
                                    : std::optional<std::string>(found->second);
  }

 private:
  const Environment& primary_;
  ValueMap fallback_;
};

std::string FrameRateValue(const FrameRatePolicy& policy) {
  if (policy.mode == FrameRateLimitMode::kUnmanaged) {
    return "-1";
  }
  if (policy.mode == FrameRateLimitMode::kUnlimited) {
    return "unlimited";
  }
  if (policy.mode == FrameRateLimitMode::kFixed) {
    return std::to_string(policy.fixed_fps);
  }
  return "display";
}

bool SetEnvironmentValue(const char* name, const std::string& value,
                         std::string* error) {
  if (setenv(name, value.c_str(), 1) == 0) {
    return true;
  }
  if (error != nullptr) {
    *error = std::string("cannot export resolved runtime setting: ") + name;
  }
  return false;
}

bool UnsetEnvironmentValue(const char* name, std::string* error) {
  if (unsetenv(name) == 0) {
    return true;
  }
  if (error != nullptr) {
    *error = std::string("cannot clear resolved runtime setting: ") + name;
  }
  return false;
}

void CollectYamlEnvKv(void* ctx, const char* key, size_t key_len,
                      const char* val, size_t val_len) {
  auto* map = static_cast<ValueMap*>(ctx);
  if (map != nullptr && key != nullptr && val != nullptr) {
    (*map)[std::string(key, key_len)] = std::string(val, val_len);
  }
}

bool ValidateRuntimeConfigPolicy(const RuntimeConfig& config, bool for_export,
                                 std::string* error) {
  const MocktailRustRuntimeConfigPolicyFlags flags{
      config.frame_rate().valid() ? 1 : 0,
      config.device_profile_valid() ? 1 : 0,
      (config.input_capabilities().touch_enabled ||
       config.input_capabilities().mouse_enabled ||
       config.input_capabilities().keyboard_enabled)
          ? 1
          : 0,
      config.graphics_backend() != GraphicsBackend::kUnknown ? 1 : 0,
      config.theme_mode_valid() ? 1 : 0,
      config.window().high_dpi_valid ? 1 : 0,
      (config.vsync_mode() == "auto" || config.vsync_mode() == "on" ||
       config.vsync_mode() == "off")
          ? 1
          : 0,
      RuntimeConfig::IsValidPresentMode(config.present_mode()) ? 1 : 0,
      config.audio_output_device_valid() ? 1 : 0,
      config.audio_input_device_valid() ? 1 : 0,
      config.performance().memory_limit_valid ? 1 : 0,
      config.performance().game_mode_valid ? 1 : 0,
      config.performance().physics_worker_mode_valid ? 1 : 0,
      config.fleasion_valid() ? 1 : 0,
      config.ca_bundle_valid() ? 1 : 0,
      config.discord_rpc_valid() ? 1 : 0,
      config.micup_rpc_valid() ? 1 : 0,
  };
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_validate_runtime_config_policy(
      &flags, for_export ? 1 : 0, err_buf.data(), err_buf.size());
  if (rc == 0) {
    return true;
  }
  if (error != nullptr) {
    *error = err_buf[0] != '\0' ? err_buf.data()
                                : "runtime configuration policy is invalid";
  }
  return false;
}

}  // namespace

RuntimeConfigLoadResult LoadRuntimeConfig(
    const Environment& environment, const std::filesystem::path& config_file) {
  RuntimeConfigLoadResult result;
  constexpr std::size_t kMaximumRuntimeConfigBytes = 1024U * 1024U;
  struct stat metadata = {};
  if (lstat(config_file.c_str(), &metadata) != 0) {
    if (errno != ENOENT) {
      result.error =
          "cannot open runtime configuration file: " + config_file.string();
      return result;
    }
    result.file_loaded = false;
  } else {
    if (S_ISLNK(metadata.st_mode)) {
      result.error =
          "cannot open runtime configuration file: refusing symlink";
      return result;
    }
    if (!S_ISREG(metadata.st_mode)) {
      result.error =
          "cannot open runtime configuration file: not a regular file";
      return result;
    }
    if (metadata.st_size > static_cast<off_t>(kMaximumRuntimeConfigBytes)) {
      result.error = "runtime configuration file must be no larger than 1 MiB";
      return result;
    }

    std::ifstream file(config_file, std::ios::binary);
    if (!file) {
      result.error =
          "cannot open runtime configuration file: " + config_file.string();
      return result;
    }
    std::string contents((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    result.file_loaded = true;

    ValueMap fallback;
    std::array<char, 256> out_err{};
    const int rc = mocktail_rust_parse_runtime_config_yaml_kv(
        reinterpret_cast<const uint8_t*>(contents.data()), contents.size(),
        &fallback, &CollectYamlEnvKv, out_err.data(), out_err.size());
    if (rc != 0) {
      result.error = out_err[0] != '\0'
                         ? out_err.data()
                         : "runtime configuration contains invalid YAML";
      return result;
    }
    const LayeredEnvironment layered(environment, std::move(fallback));
    result.config = RuntimeConfig::FromEnvironment(layered);
  }

  if (!result.file_loaded) {
    result.config = RuntimeConfig::FromEnvironment(environment);
  }
  ValidateRuntimeConfigPolicy(result.config, false, &result.error);
  return result;
}

bool ExportRuntimeConfigEnvironment(const RuntimeConfig& config,
                                    std::string* error) {
  if (!ValidateRuntimeConfigPolicy(config, true, error)) {
    return false;
  }
  const DeviceProfile& device = config.device_profile();
  const bool base_exported =
      SetEnvironmentValue("MOCKTAIL_HEADLESS", config.headless() ? "1" : "0",
                          error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_PROFILE", std::string(device.name),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_CLASS",
                          std::string(DeviceClassName(device.device_class)),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_PLATFORM_NAME",
                          std::string(device.platform_name), error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_NAME",
                          std::string(device.display_name), error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_MANUFACTURER",
                          std::string(device.manufacturer), error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_MODEL", std::string(device.model),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_BRAND", std::string(device.brand),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_CODE",
                          std::string(device.device_code), error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_SKU", std::string(device.device_sku),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_DEVICE_SOC_MODEL",
                          std::string(device.soc_model), error) &&
      SetEnvironmentValue("ROBLOX_LIB_PATH",
                          config.roblox_library_path().string(), error) &&
      SetEnvironmentValue("MOCKTAIL_GRAPHICS_BACKEND",
                          config.graphics_backend_name(), error) &&
      SetEnvironmentValue("MOCKTAIL_THEME", config.theme_mode(), error) &&
      SetEnvironmentValue("MOCKTAIL_WIN_WIDTH",
                          std::to_string(config.window().width), error) &&
      SetEnvironmentValue("MOCKTAIL_WIN_HEIGHT",
                          std::to_string(config.window().height), error) &&
      SetEnvironmentValue("MOCKTAIL_WIN_TITLE", config.window().title, error) &&
      SetEnvironmentValue("MOCKTAIL_WIN_HIGH_DPI",
                          config.window().high_dpi ? "1" : "0", error) &&
      SetEnvironmentValue(
          "MOCKTAIL_TOUCH_MODE",
          config.input_capabilities().touch_enabled ? "on" : "off", error) &&
      SetEnvironmentValue(
          "MOCKTAIL_MOUSE_MODE",
          config.input_capabilities().mouse_enabled ? "on" : "off", error) &&
      SetEnvironmentValue(
          "MOCKTAIL_KEYBOARD_MODE",
          config.input_capabilities().keyboard_enabled ? "on" : "off", error) &&
      SetEnvironmentValue("MOCKTAIL_DESKTOP_PLAYABILITY",
                          config.desktop_playability() ? "1" : "0", error) &&
      SetEnvironmentValue("MOCKTAIL_FRAME_RATE_LIMIT",
                          FrameRateValue(config.frame_rate()), error) &&
      SetEnvironmentValue("MOCKTAIL_VSYNC", config.vsync_mode(), error) &&
      SetEnvironmentValue("MOCKTAIL_PRESENT_MODE", config.present_mode(), error) &&
      SetEnvironmentValue(
          "MOCKTAIL_MULTITHREADED_RENDERING",
          config.performance().multithreaded_rendering ? "1" : "0", error) &&
      SetEnvironmentValue("MOCKTAIL_PHYSICS_WORKER_MODE",
                          std::string(PhysicsWorkerModeName(
                              config.performance().physics_worker_mode)),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_MEMORY_LIMIT_MB",
                          std::to_string(config.performance().memory_limit_mb),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_GAMEMODE",
                          GameModePolicyName(config.performance().game_mode),
                          error) &&
      SetEnvironmentValue("MOCKTAIL_AUDIO_OUTPUT_DEVICE",
                          config.audio_output_device(), error) &&
      SetEnvironmentValue("MOCKTAIL_AUDIO_INPUT_DEVICE",
                          config.audio_input_device(), error) &&
      SetEnvironmentValue("MOCKTAIL_USE_SYSTEM_PROXY",
                          config.use_system_proxy() ? "1" : "0", error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_ENABLED",
                          config.discord_rpc().enabled ? "1" : "0", error) &&
      SetEnvironmentValue(
          "MOCKTAIL_DISCORD_RPC_SHOW_PLACE_NAME",
          config.discord_rpc().show_place_name ? "1" : "0", error) &&
      SetEnvironmentValue(
          "MOCKTAIL_DISCORD_RPC_SHOW_ELAPSED_TIME",
          config.discord_rpc().show_elapsed_time ? "1" : "0", error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_JOIN_ENABLED",
                          config.discord_rpc().join_enabled ? "1" : "0",
                          error) &&
      SetEnvironmentValue(
          "MOCKTAIL_DISCORD_RPC_PUBLIC_SERVERS_ONLY",
          config.discord_rpc().public_servers_only ? "1" : "0", error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_JOIN_BUTTON_LABEL",
                          config.discord_rpc().join_button_label, error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_APPLICATION_ID",
                          config.discord_rpc().application_id, error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_TEXT_BROWSING",
                          config.discord_rpc().text.browsing, error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_TEXT_JOINING",
                          config.discord_rpc().text.joining, error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_TEXT_PLAYING",
                          config.discord_rpc().text.playing, error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_TEXT_STATE",
                          config.discord_rpc().text.state, error) &&
      SetEnvironmentValue("MOCKTAIL_DISCORD_RPC_TEXT_UNKNOWN_PLACE",
                          config.discord_rpc().text.unknown_place, error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_ENABLED",
                          config.micup_rpc().enabled ? "1" : "0", error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_SHOW_PLACE_NAME",
                          config.micup_rpc().show_place_name ? "1" : "0",
                          error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_SHOW_ELAPSED_TIME",
                          config.micup_rpc().show_elapsed_time ? "1" : "0",
                          error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_GATEWAY_URL",
                          config.micup_rpc().gateway_url, error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_STATUS", config.micup_rpc().status,
                          error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_ACTIVITY_MODE",
                          config.micup_rpc().activity_mode, error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_TEXT_BROWSING",
                          config.micup_rpc().text.browsing, error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_TEXT_JOINING",
                          config.micup_rpc().text.joining, error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_TEXT_PLAYING",
                          config.micup_rpc().text.playing, error) &&
      SetEnvironmentValue("MOCKTAIL_MICUP_TEXT_UNKNOWN_PLACE",
                          config.micup_rpc().text.unknown_place, error);
  if (!base_exported) {
    return false;
  }
  if (!config.micup_rpc().token.empty()) {
    if (!SetEnvironmentValue("MOCKTAIL_MICUP_TOKEN", config.micup_rpc().token,
                             error)) {
      return false;
    }
  } else if (!UnsetEnvironmentValue("MOCKTAIL_MICUP_TOKEN", error)) {
    return false;
  }
  if (!config.micup_rpc().token_file.empty()) {
    if (!SetEnvironmentValue("MOCKTAIL_MICUP_TOKEN_FILE",
                             config.micup_rpc().token_file, error)) {
      return false;
    }
  } else if (!UnsetEnvironmentValue("MOCKTAIL_MICUP_TOKEN_FILE", error)) {
    return false;
  }
  if (!SetEnvironmentValue("MOCKTAIL_FLEASION_ENABLED",
                           config.fleasion_enabled() ? "1" : "0", error) ||
      !SetEnvironmentValue("MOCKTAIL_FLEASION_PROXY_MODE",
                           config.fleasion_proxy_mode(), error) ||
      !SetEnvironmentValue("MOCKTAIL_FLEASION_PROXY_PORT",
                           std::to_string(config.fleasion_proxy_port()), error))
    return false;
  if (config.fleasion_ca_certificate()) {
    if (!SetEnvironmentValue("MOCKTAIL_FLEASION_CA_CERTIFICATE",
                             config.fleasion_ca_certificate()->string(), error))
      return false;
  } else if (!UnsetEnvironmentValue("MOCKTAIL_FLEASION_CA_CERTIFICATE", error)) {
    return false;
  }
  if (config.ca_bundle().has_value()) {
    if (!SetEnvironmentValue("MOCKTAIL_CA_BUNDLE",
                             config.ca_bundle()->string(), error)) {
      return false;
    }
  } else if (!UnsetEnvironmentValue("MOCKTAIL_CA_BUNDLE", error)) {
    return false;
  }
  if (config.roblox_http_user_agent().has_value() &&
      !SetEnvironmentValue("MOCKTAIL_USER_AGENT",
                           *config.roblox_http_user_agent(), error)) {
    return false;
  }
  if (!config.roblox_http_user_agent().has_value() &&
      !UnsetEnvironmentValue("MOCKTAIL_USER_AGENT", error)) {
    return false;
  }
  return base_exported && ExportNetworkProxyEnvironment(config, error);
}

bool ExportNetworkProxyEnvironment(const RuntimeConfig& config,
                                   std::string* error) {
  if (!config.network_proxy().has_value()) return true;
  const std::string proxy_url =
      BuildNetworkProxyUrl(*config.network_proxy(), true);
  const bool native_proxy = config.network_proxy()->scheme == "http" &&
                            config.network_proxy()->username.empty();
  return SetEnvironmentValue("MOCKTAIL_HTTP_PROXY_HOST",
                             config.network_proxy()->host, error) &&
         SetEnvironmentValue("MOCKTAIL_HTTP_PROXY_PORT",
                             std::to_string(config.network_proxy()->port),
                             error) &&
         SetEnvironmentValue("MOCKTAIL_HTTP_PROXY_SCHEME",
                             config.network_proxy()->scheme, error) &&
         SetEnvironmentValue("MOCKTAIL_HTTP_PROXY_USERNAME",
                             config.network_proxy()->username, error) &&
         SetEnvironmentValue("MOCKTAIL_HTTP_PROXY_PASSWORD",
                             config.network_proxy()->password, error) &&
         SetEnvironmentValue("http_proxy", proxy_url, error) &&
         SetEnvironmentValue("https_proxy", proxy_url, error) &&
         SetEnvironmentValue("all_proxy", proxy_url, error) &&
         SetEnvironmentValue("no_proxy", "", error) &&
         SetEnvironmentValue("NO_PROXY", "", error) &&
         SetEnvironmentValue("MOCKTAIL_NATIVE_SET_HTTP_CLIENT_PROXY",
                             native_proxy ? "1" : "0", error);
}

}  // namespace runtime
}  // namespace mocktail
