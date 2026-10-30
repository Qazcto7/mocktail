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
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

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

}  // namespace

RuntimeConfigLoadResult LoadRuntimeConfig(
    const Environment& environment, const std::filesystem::path& config_file) {
  RuntimeConfigLoadResult result;
  std::error_code filesystem_error;
  if (!std::filesystem::exists(config_file, filesystem_error) ||
      filesystem_error) {
    result.file_loaded = false;
  } else {
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
    std::array<char, 16384> out_env{};
    std::array<char, 256> out_err{};
    const int rc = mocktail_rust_parse_runtime_config_yaml(
        reinterpret_cast<const uint8_t*>(contents.data()), contents.size(),
        out_env.data(), out_env.size(), out_err.data(), out_err.size());
    if (rc != 0) {
      result.error = out_err[0] != '\0'
                         ? out_err.data()
                         : "runtime configuration contains invalid YAML";
      return result;
    }
    const auto env_json =
        nlohmann::json::parse(out_env.data(), nullptr, false, true);
    if (env_json.is_object()) {
      for (const auto& [k, v] : env_json.items()) {
        fallback[k] = v.get<std::string>();
      }
    }
    const LayeredEnvironment layered(environment, std::move(fallback));
    result.config = RuntimeConfig::FromEnvironment(layered);
  }

  if (!result.file_loaded) {
    result.config = RuntimeConfig::FromEnvironment(environment);
  }
  if (!result.config.frame_rate().valid()) {
    result.error = "frame-rate policy is invalid";
  } else if (!result.config.device_profile_valid()) {
    result.error = "device profile is invalid";
  } else if (!result.config.input_capabilities().touch_enabled &&
             !result.config.input_capabilities().mouse_enabled &&
             !result.config.input_capabilities().keyboard_enabled) {
    result.error = "device must expose at least one usable input capability";
  } else if (result.config.graphics_backend() == GraphicsBackend::kUnknown) {
    result.error = "graphics backend is invalid";
  } else if (!result.config.theme_mode_valid()) {
    result.error = "theme mode is invalid";
  } else if (!result.config.window().high_dpi_valid) {
    result.error = "window high-DPI policy is invalid";
  } else if (result.config.vsync_mode() != "auto" &&
             result.config.vsync_mode() != "on" &&
             result.config.vsync_mode() != "off") {
    result.error = "VSync policy is invalid";
  } else if (!RuntimeConfig::IsValidPresentMode(result.config.present_mode())) {
    result.error = "graphics.present_mode must be auto, fifo, mailbox, or immediate";
  } else if (!result.config.audio_output_device_valid()) {
    result.error = "audio output device is invalid";
  } else if (!result.config.audio_input_device_valid()) {
    result.error = "audio input device is invalid";
  } else if (!result.config.performance().memory_limit_valid) {
    result.error = "memory-limit policy is invalid";
  } else if (!result.config.performance().game_mode_valid) {
    result.error = "GameMode policy is invalid";
  } else if (!result.config.performance().physics_worker_mode_valid) {
    result.error = "physics worker policy is invalid";
  } else if (!result.config.fleasion_valid()) {
    result.error = "Fleasion configuration is invalid: use proxy_mode env or hosts, "
                   "a port from 1 to 65535, an absolute CA certificate path, and "
                   "no conflicting system/fixed proxy";
  } else if (!result.config.ca_bundle_valid()) {
    result.error = "CA bundle path is invalid";
  } else if (!result.config.discord_rpc_valid()) {
    result.error = "Discord Rich Presence configuration is invalid";
  }
  return result;
}

bool ExportRuntimeConfigEnvironment(const RuntimeConfig& config,
                                    std::string* error) {
  if (!RuntimeConfig::IsValidPresentMode(config.present_mode())) {
    if (error != nullptr) *error = "cannot export an invalid present mode";
    return false;
  }
  if (!config.fleasion_valid()) {
    if (error != nullptr) *error = "cannot export invalid Fleasion configuration";
    return false;
  }
  if (!config.device_profile_valid()) {
    if (error != nullptr) {
      *error = "cannot export an invalid device profile";
    }
    return false;
  }
  if (!config.audio_output_device_valid()) {
    if (error != nullptr) {
      *error = "cannot export an invalid audio output device";
    }
    return false;
  }
  if (!config.audio_input_device_valid()) {
    if (error != nullptr) {
      *error = "cannot export an invalid audio input device";
    }
    return false;
  }
  if (!config.performance().memory_limit_valid) {
    if (error != nullptr) {
      *error = "cannot export an invalid memory-limit policy";
    }
    return false;
  }
  if (!config.performance().game_mode_valid) {
    if (error != nullptr) {
      *error = "cannot export an invalid GameMode policy";
    }
    return false;
  }
  if (!config.performance().physics_worker_mode_valid) {
    if (error != nullptr) {
      *error = "cannot export an invalid physics worker policy";
    }
    return false;
  }
  if (!config.ca_bundle_valid()) {
    if (error != nullptr) {
      *error = "cannot export an invalid CA bundle path";
    }
    return false;
  }
  if (!config.discord_rpc_valid()) {
    if (error != nullptr) {
      *error = "cannot export an invalid Discord Rich Presence policy";
    }
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
                          config.discord_rpc().text.unknown_place, error);
  if (!base_exported) {
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
