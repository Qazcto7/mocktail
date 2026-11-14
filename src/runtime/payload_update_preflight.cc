#include "runtime/payload_update_preflight.h"

#include <cstddef>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"

#ifndef MOCKTAIL_INSTALL_LIBDIR
#define MOCKTAIL_INSTALL_LIBDIR "lib"
#endif

namespace mocktail {
namespace runtime {
namespace {

bool LookupEnvironment(const void* env_ctx, const char* name, std::size_t name_len,
                       MocktailRustPreflightEnvValueCallback on_value,
                       void* cb_ctx) {
  const auto* environment = static_cast<const Environment*>(env_ctx);
  if (environment == nullptr || name == nullptr) {
    return false;
  }
  const auto value = environment->Get(std::string_view(name, name_len));
  if (!value.has_value()) {
    return false;
  }
  if (on_value != nullptr) {
    on_value(cb_ctx, value->data(), value->size());
  }
  return true;
}

void ReceivePreflightResult(void* ctx, bool attempted, const char* error,
                            std::size_t error_len, const char* details,
                            std::size_t details_len) {
  auto* result = static_cast<PayloadUpdatePreflightResult*>(ctx);
  if (result == nullptr) {
    return;
  }
  result->attempted = attempted;
  if (error != nullptr && error_len > 0) {
    result->error.assign(error, error_len);
  } else {
    result->error.clear();
  }
  if (details != nullptr && details_len > 0) {
    result->details.assign(details, details_len);
  } else {
    result->details.clear();
  }
}

struct OwnedPreflightPaths {
  std::string config_file;
  std::string config_root;
  std::string data_root;
  std::string cache_root;
  std::string state_root;
  MocktailRustPreflightRuntimePaths ffi{};

  explicit OwnedPreflightPaths(const RuntimePaths& paths)
      : config_file(paths.config_file().string()),
        config_root(paths.config_root().string()),
        data_root(paths.data_root().string()),
        cache_root(paths.cache_root().string()),
        state_root(paths.state_root().string()),
        ffi{config_file.data(), config_file.size(), config_root.data(),
            config_root.size(), data_root.data(),   data_root.size(),
            cache_root.data(),  cache_root.size(),  state_root.data(),
            state_root.size()} {}
};

constexpr std::string_view kInstallLibdir = MOCKTAIL_INSTALL_LIBDIR;

}  // namespace

PayloadUpdatePreflightResult RunPayloadUpdatePreflight(
    const Environment& environment, const RuntimePaths& paths,
    bool force_run_latest) {
  PayloadUpdatePreflightResult result;
  const OwnedPreflightPaths owned_paths(paths);
  mocktail_rust_run_payload_update_preflight(
      &environment, &LookupEnvironment, &owned_paths.ffi,
      kInstallLibdir.data(), kInstallLibdir.size(), force_run_latest,
      &ReceivePreflightResult, &result);
  return result;
}

BackgroundPayloadUpdate::~BackgroundPayloadUpdate() {
  if (handle_ != nullptr) {
    mocktail_rust_background_payload_update_destroy(
        static_cast<MocktailRustBackgroundPayloadUpdate*>(handle_));
    handle_ = nullptr;
  }
}

void BackgroundPayloadUpdate::Start(const Environment& environment,
                                    const RuntimePaths& paths,
                                    std::chrono::milliseconds interval) {
  if (handle_ == nullptr) {
    handle_ = mocktail_rust_background_payload_update_create();
  }
  const OwnedPreflightPaths owned_paths(paths);
  mocktail_rust_background_payload_update_start(
      static_cast<MocktailRustBackgroundPayloadUpdate*>(handle_), &environment,
      &LookupEnvironment, &owned_paths.ffi, kInstallLibdir.data(),
      kInstallLibdir.size(), static_cast<int64_t>(interval.count()));
}

void BackgroundPayloadUpdate::Stop() {
  if (handle_ != nullptr) {
    mocktail_rust_background_payload_update_stop(
        static_cast<MocktailRustBackgroundPayloadUpdate*>(handle_));
  }
}

}  // namespace runtime
}  // namespace mocktail
