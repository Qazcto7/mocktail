#include "mocktail/mocktail_rust.h"
#include "runtime/supported_launch_policy.h"

#include <unistd.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#ifndef MOCKTAIL_INSTALL_LIBDIR
#define MOCKTAIL_INSTALL_LIBDIR "lib"
#endif

namespace mocktail {
namespace runtime {
namespace {

bool SetDefault(const char* name, const std::string& value,
                std::string* error) {
  const char* current = std::getenv(name);
  if (current != nullptr && current[0] != '\0') {
    return true;
  }
  if (setenv(name, value.c_str(), 1) == 0) {
    return true;
  }
  if (error != nullptr) {
    *error = std::string("cannot publish supported launch default: ") + name;
  }
  return false;
}

std::filesystem::path CurrentExecutable() {
  std::array<char, 4097> path{};
  const ssize_t length =
      readlink("/proc/self/exe", path.data(), path.size() - 1);
  if (length <= 0 || static_cast<std::size_t>(length) >= path.size()) {
    return {};
  }
  path[static_cast<std::size_t>(length)] = '\0';
  return path.data();
}

bool ApplyInstalledResourceDefaults(std::string* error) {
  const std::filesystem::path executable = CurrentExecutable();
  if (executable.empty()) {
    return true;
  }
  std::filesystem::path runtime_directory = executable.parent_path();
  const std::filesystem::path library_directory = MOCKTAIL_INSTALL_LIBDIR;
  std::filesystem::path prefix = runtime_directory.parent_path();
  if (runtime_directory.filename() == "mocktail") {
    for (auto component = library_directory.end();
         component != library_directory.begin();) {
      if (prefix.filename() != *--component) {
        return true;
      }
      prefix = prefix.parent_path();
    }
  } else if (runtime_directory.filename() == "bin") {
    runtime_directory = prefix / library_directory / "mocktail";
  } else {
    return true;
  }
  const std::filesystem::path helper =
      runtime_directory / "mocktail_webview_helper";
  const std::filesystem::path progress_helper =
      runtime_directory / "mocktail_failure_dialog";
  const std::filesystem::path update_helper =
      runtime_directory / "mocktail_updater";
  const std::filesystem::path data_directory = prefix / "share/mocktail";
  const std::filesystem::path metadata_directory = data_directory / "metadata";
  std::error_code filesystem_error;
  if (!std::filesystem::is_directory(metadata_directory, filesystem_error)) {
    return true;
  }

  const std::vector<std::pair<const char*, std::filesystem::path>> defaults = {
      {"MOCKTAIL_PROJECT_ROOT", data_directory},
      {"MOCKTAIL_COMPATIBILITY_MANIFEST",
       metadata_directory / "roblox_compatibility.json"},
      {"MOCKTAIL_UPDATE_COMPATIBILITY_PATH",
       metadata_directory / "roblox_compatibility.json"},
      {"MOCKTAIL_UPDATE_SIGNING_TRUST_PATH",
       metadata_directory / "roblox_signing_certificates.json"},
      {"MOCKTAIL_UPDATE_DOWNLOAD_SOURCES_PATH",
       metadata_directory / "roblox_download_sources.json"},
      {"MOCKTAIL_BOOTSTRAP_SOURCES_PATH",
       metadata_directory / "roblox_bootstrap_sources.json"},
      {"MOCKTAIL_UPDATE_CANARY_BIN", executable},
      {"MOCKTAIL_UPDATE_HELPER", update_helper},
      {"MOCKTAIL_RUNTIME_LIBRARY_DIR", runtime_directory},
      {"MOCKTAIL_WEBVIEW_HELPER", helper},
      {"MOCKTAIL_UPDATE_PROGRESS_HELPER", progress_helper},
  };
  for (const auto& [name, value] : defaults) {
    if (!SetDefault(name, value.string(), error)) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool ApplySupportedLaunchPolicy(bool interactive, std::string* error) {
  // A packaging launcher may reload its environment for each native child.
  // Keep the bundled default separate from the updater's per-candidate
  // manifest, which must survive both normal launches and isolated canaries.
  const char* packaged_manifest =
      std::getenv("MOCKTAIL_PACKAGED_COMPATIBILITY_MANIFEST");
  if (packaged_manifest != nullptr && packaged_manifest[0] != '\0' &&
      !SetDefault("MOCKTAIL_COMPATIBILITY_MANIFEST", packaged_manifest, error)) {
    return false;
  }
  if (!ApplyInstalledResourceDefaults(error)) {
    return false;
  }
  if (!interactive) {
    return true;
  }

  const size_t defaults_count =
      mocktail_rust_supported_launch_defaults_count(interactive ? 1 : 0);
  for (size_t i = 0; i < defaults_count; ++i) {
    char key[128];
    char val[128];
    if (mocktail_rust_supported_launch_default_entry(
            interactive ? 1 : 0, i, key, sizeof(key), val, sizeof(val)) == 0) {
      if (!SetDefault(key, val, error)) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace runtime
}  // namespace mocktail
