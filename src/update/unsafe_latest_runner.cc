#include "update/unsafe_latest_runner.h"

#include <string>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

MocktailRustStrSlice ToSlice(const std::string& value) {
  return {value.data(), value.size()};
}

}  // namespace

UnsafeLatestRunResult RunUnsafeLatestCandidate(
    const UnsafeLatestRunOptions& options) {
  const std::string runtime = options.runtime_binary.string();
  const std::string payload = options.payload_directory.string();
  const std::string compat = options.compatibility_manifest.string();
  const std::string profile = options.host_abi_profile.string();

  std::vector<MocktailRustStrSlice> env_slices;
  env_slices.reserve(options.inherited_environment.size());
  for (const std::string& entry : options.inherited_environment) {
    env_slices.push_back(ToSlice(entry));
  }

  MocktailRustUnsafeLatestOptions rust_opts{};
  rust_opts.runtime_binary = ToSlice(runtime);
  rust_opts.payload_directory = ToSlice(payload);
  rust_opts.compatibility_manifest = ToSlice(compat);
  rust_opts.host_abi_profile = ToSlice(profile);
  rust_opts.inherited_environment =
      env_slices.empty() ? nullptr : env_slices.data();
  rust_opts.inherited_environment_count = env_slices.size();

  UnsafeLatestRunResult result;
  mocktail_rust_run_unsafe_latest_candidate(
      &rust_opts,
      [](void* ctx, int32_t exit_code, MocktailRustStrSlice error) {
        auto* out = static_cast<UnsafeLatestRunResult*>(ctx);
        out->exit_code = exit_code;
        out->error.assign(error.ptr, error.len);
      },
      &result);
  return result;
}

}  // namespace mocktail::update
