#include "update/readiness_canary.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

void ReceiveString(void* ctx, const char* data, std::size_t len) {
  auto* target = static_cast<std::string*>(ctx);
  if (target != nullptr && data != nullptr && len > 0) {
    target->assign(data, len);
  }
}

void ReceiveCanaryResult(void* ctx, int32_t exit_code, bool teardown_crash,
                         const char* log_path, std::size_t log_path_len,
                         const char* error, std::size_t error_len) {
  auto* result = static_cast<CanaryResult*>(ctx);
  if (result == nullptr) {
    return;
  }
  result->exit_code = exit_code;
  result->teardown_crash = teardown_crash;
  if (log_path != nullptr && log_path_len > 0) {
    result->log_path = std::string(log_path, log_path_len);
  } else {
    result->log_path.clear();
  }
  if (error != nullptr && error_len > 0) {
    result->error.assign(error, error_len);
  } else {
    result->error.clear();
  }
}

}  // namespace

std::string_view CanaryGraphicsBackendName(CanaryGraphicsBackend backend) {
  return mocktail_rust_canary_backend_name_cstr(static_cast<int32_t>(backend));
}

bool ParseCanaryGraphicsBackend(std::string_view name,
                                CanaryGraphicsBackend* backend) {
  if (backend == nullptr) return false;
  const std::string name_str(name);
  int32_t parsed_backend = 0;
  if (mocktail_rust_canary_backend_parse(name_str.c_str(), &parsed_backend) ==
      0) {
    *backend = static_cast<CanaryGraphicsBackend>(parsed_backend);
    return true;
  }
  return false;
}

bool ValidateReadinessLog(CanaryGraphicsBackend backend, std::string_view log,
                          std::string* error) {
  if (error != nullptr) error->clear();
  return mocktail_rust_validate_readiness_log(
             static_cast<int32_t>(backend), log.data(), log.size(),
             error != nullptr ? &ReceiveString : nullptr, error) == 0;
}

bool ValidateTeardownCrashLog(CanaryGraphicsBackend backend,
                              std::string_view log, std::string* error) {
  if (error != nullptr) error->clear();
  return mocktail_rust_validate_teardown_crash_log(
             static_cast<int32_t>(backend), log.data(), log.size(),
             error != nullptr ? &ReceiveString : nullptr, error) == 0;
}

CanaryResult RunReadinessCanary(const CanaryOptions& options) {
  CanaryResult result;
  const std::string runtime_binary = options.runtime_binary.string();
  const std::string payload_directory = options.payload_directory.string();
  const std::string compatibility_manifest =
      options.compatibility_manifest.string();
  const std::string host_abi_profile = options.host_abi_profile.string();
  const std::string cache_root = options.cache_root.string();
  const std::string state_root = options.state_root.string();

  const MocktailRustCanaryOptions raw_options{
      runtime_binary.data(),
      runtime_binary.size(),
      payload_directory.data(),
      payload_directory.size(),
      compatibility_manifest.data(),
      compatibility_manifest.size(),
      host_abi_profile.data(),
      host_abi_profile.size(),
      cache_root.data(),
      cache_root.size(),
      state_root.data(),
      state_root.size(),
      static_cast<int32_t>(options.graphics_backend),
      static_cast<int32_t>(options.timeout_seconds),
  };
  mocktail_rust_run_readiness_canary(&raw_options, &ReceiveCanaryResult, &result);
  return result;
}

}  // namespace mocktail::update
