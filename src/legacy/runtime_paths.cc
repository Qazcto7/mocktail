#include "legacy/runtime_paths.h"

#include <unistd.h>

#include <cstdlib>
#include <iostream>

#include "legacy/runtime_environment.h"
#include "libc_shim/libc_shim.h"
#include "runtime/environment.h"
#include "runtime/runtime_paths.h"

namespace mocktail::legacy::internal {
namespace {

constexpr std::size_t kDefaultEngineStackSize = 1024ULL * 1024 * 1024;
constexpr std::size_t kMinEngineStackSize = 16ULL * 1024 * 1024;

runtime::RuntimePaths CurrentRuntimePaths() {
  const runtime::ProcessEnvironment environment;
  return runtime::RuntimePaths::FromEnvironment(environment);
}

bool EnsureDirectory(const std::string& path) {
  return runtime::RuntimePaths::EnsureDirectory(path);
}

}  // namespace

std::string SoberDataRoot() {
  return CurrentRuntimePaths().sober_data_root().string();
}

std::string SoberCacheRoot() {
  return CurrentRuntimePaths().sober_cache_root().string();
}

std::string MocktailCacheRoot() {
  return CurrentRuntimePaths().cache_root().string();
}

std::string MocktailConfigRoot() {
  return CurrentRuntimePaths().config_root().string();
}

std::string DefaultSoberAwarePath(const char* sober_path,
                                  const char* fallback_path) {
  return CurrentRuntimePaths()
      .DefaultSoberAwarePath(sober_path != nullptr ? sober_path : "",
                             fallback_path != nullptr ? fallback_path : "")
      .string();
}

std::string DefaultAssetPath() {
  return CurrentRuntimePaths().DefaultAssetPath().string();
}

std::string RuntimeVulkanAdapterPath() {
  const char* override_dir = std::getenv("MOCKTAIL_RUNTIME_LIBRARY_DIR");
  std::string directory;
  if (override_dir != nullptr && override_dir[0] != '\0') {
    directory = override_dir;
  } else {
    char executable_path[4097] = {};
    const ssize_t length = ::readlink("/proc/self/exe", executable_path,
                                      sizeof(executable_path) - 1U);
    if (length <= 0) {
      return {};
    }
    executable_path[length] = '\0';
    const std::string path(executable_path);
    const std::string::size_type separator = path.find_last_of('/');
    if (separator == std::string::npos) {
      return {};
    }
    directory = separator == 0 ? "/" : path.substr(0, separator);
  }
  if (directory.empty()) {
    return {};
  }
  return directory + "/libvulkan.so";
}

std::string GetEnvStringDefaultPath(const char* name,
                                    const std::string& default_value) {
  const char* value = std::getenv(name);
  if (value == nullptr || value[0] == '\0') {
    return default_value;
  }
  return value;
}

void EnsureAndroidDirectory(const std::string& android_path) {
  const std::string host_path = libc_shim::TranslatePath(android_path);
  if (EnsureDirectory(host_path) && host_path != android_path &&
      IsEnabled("MOCKTAIL_ENGINE_TRACE")) {
    std::cerr << "  [engine] directory " << android_path << " -> " << host_path
              << '\n';
  }
}

std::size_t GetEngineStackSize() {
  const char* value = std::getenv("MOCKTAIL_ENGINE_STACK_MB");
  if (value == nullptr || value[0] == '\0') {
    return kDefaultEngineStackSize;
  }

  char* end = nullptr;
  const unsigned long long stack_mb = std::strtoull(value, &end, 10);
  if (end == value || stack_mb == 0) {
    return kDefaultEngineStackSize;
  }

  const std::size_t stack_size =
      static_cast<std::size_t>(stack_mb) * 1024 * 1024;
  return stack_size < kMinEngineStackSize ? kMinEngineStackSize : stack_size;
}

}  // namespace mocktail::legacy::internal
