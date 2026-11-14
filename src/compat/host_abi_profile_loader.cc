#include "compat/host_abi_profile_loader.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail::compat {

namespace {

struct OwnedHostAbiProfile {
  HostAbiProfile profile;
  std::string build_id;
  std::array<std::string, kMaxHostBridgeEntries> labels;
  std::string canonical_payload_path;
  std::string payload_sha256;
  std::string profile_sha256;
  std::string reference_build_id;
  std::string reference_payload_sha256;

  void BindViews() {
    profile.elf_build_id = build_id;
    for (std::size_t index = 0; index < profile.bridge_entry_count; ++index) {
      profile.bridge_entries[index].label = labels[index];
    }
  }
};

std::mutex g_external_profiles_mutex;
std::vector<std::unique_ptr<OwnedHostAbiProfile>> g_external_profiles;

MocktailRustStrSlice ToSlice(std::string_view value) noexcept {
  return MocktailRustStrSlice{value.data(), value.size()};
}

std::string FromSlice(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return std::string(slice.ptr, slice.len);
}

ExternalHostAbiProfileResult Failure(std::string error) {
  ExternalHostAbiProfileResult result;
  result.error = std::move(error);
  return result;
}

const OwnedHostAbiProfile* FindLoadedProfile(std::string_view build_id) {
  std::lock_guard<std::mutex> lock(g_external_profiles_mutex);
  for (const std::unique_ptr<OwnedHostAbiProfile>& profile :
       g_external_profiles) {
    if (profile->build_id == build_id) {
      return profile.get();
    }
  }
  return nullptr;
}

std::unique_ptr<OwnedHostAbiProfile> BuildOwnedProfile(
    const MocktailRustParsedHostAbiProfile& parsed,
    std::string canonical_payload_path, std::string payload_sha256,
    std::string profile_sha256) {
  auto owned = std::make_unique<OwnedHostAbiProfile>();
  owned->build_id = parsed.build_id;
  owned->reference_build_id = parsed.reference_build_id;
  owned->reference_payload_sha256 = parsed.reference_payload_sha256;
  owned->canonical_payload_path = std::move(canonical_payload_path);
  owned->payload_sha256 = std::move(payload_sha256);
  owned->profile_sha256 = std::move(profile_sha256);

  owned->profile.bridge_entry_count = parsed.bridge_entry_count;
  for (std::size_t i = 0; i < parsed.bridge_entry_count; ++i) {
    owned->labels[i] = parsed.bridge_entries[i].label;
    owned->profile.bridge_entries[i].rva =
        static_cast<uintptr_t>(parsed.bridge_entries[i].rva);
    owned->profile.bridge_entries[i].kind =
        static_cast<HostBridgeKind>(parsed.bridge_entries[i].kind);
    owned->profile.bridge_entries[i].label = {};
  }
  owned->profile.data_seeds.allocator_object_slot =
      static_cast<uintptr_t>(parsed.allocator_object_slot);
  owned->profile.data_seeds.empty_string_slot =
      static_cast<uintptr_t>(parsed.empty_string_slot);
  owned->profile.data_seeds.jni_singleton_slot =
      static_cast<uintptr_t>(parsed.jni_singleton_slot);
  owned->profile.data_seeds.jni_singleton_bytes = parsed.jni_singleton_bytes;
  owned->profile.data_seeds.arena_initializer =
      static_cast<uintptr_t>(parsed.arena_initializer);
  owned->profile.data_seeds.allocator_thread_initializer =
      static_cast<uintptr_t>(parsed.allocator_thread_initializer);
  owned->profile.data_seeds.arena_guard_slot =
      static_cast<uintptr_t>(parsed.arena_guard_slot);
  owned->profile.data_seeds.arena_table_slot =
      static_cast<uintptr_t>(parsed.arena_table_slot);
  owned->profile.data_seeds.arena_table_slot_count =
      parsed.arena_table_slot_count;
  owned->profile.native_allocator.allocate =
      static_cast<uintptr_t>(parsed.native_allocator_allocate);
  owned->profile.native_allocator.deallocate =
      static_cast<uintptr_t>(parsed.native_allocator_deallocate);
  owned->profile.init_array_offset =
      static_cast<uintptr_t>(parsed.init_array_offset);
  owned->profile.init_array_count = parsed.init_array_count;
  owned->profile.constructor_run_range_count =
      parsed.constructor_run_range_count;
  for (std::size_t i = 0; i < parsed.constructor_run_range_count; ++i) {
    owned->profile.constructor_run_ranges[i] = {
        parsed.constructor_run_ranges[i].begin,
        parsed.constructor_run_ranges[i].end_exclusive};
  }
  owned->profile.native_mimalloc_constructor_run_range_count =
      parsed.native_mimalloc_constructor_run_range_count;
  for (std::size_t i = 0;
       i < parsed.native_mimalloc_constructor_run_range_count; ++i) {
    owned->profile.native_mimalloc_constructor_run_ranges[i] = {
        parsed.native_mimalloc_constructor_run_ranges[i].begin,
        parsed.native_mimalloc_constructor_run_ranges[i].end_exclusive};
  }
  owned->profile.native_mimalloc_thread_initializer_after_constructor =
      parsed.native_mimalloc_thread_initializer_after_constructor;
  owned->profile.native_pre_jni_bootstrap.registry_initializer =
      static_cast<uintptr_t>(parsed.native_pre_jni_registry_initializer);
  owned->profile.native_pre_jni_bootstrap.registry_slot =
      static_cast<uintptr_t>(parsed.native_pre_jni_registry_slot);
  owned->profile.host_allocator_bridges_supported =
      parsed.host_allocator_bridges_supported != 0;
  owned->profile.default_allocator_strategy =
      static_cast<HostAllocatorStrategy>(parsed.default_allocator_strategy);
  owned->BindViews();
  return owned;
}

ExternalHostAbiProfileResult RegisterProfile(
    std::unique_ptr<OwnedHostAbiProfile> profile) {
  std::lock_guard<std::mutex> lock(g_external_profiles_mutex);
  for (const std::unique_ptr<OwnedHostAbiProfile>& existing :
       g_external_profiles) {
    if (existing->build_id != profile->build_id) {
      continue;
    }
    if (existing->canonical_payload_path == profile->canonical_payload_path &&
        existing->payload_sha256 == profile->payload_sha256 &&
        existing->profile_sha256 == profile->profile_sha256) {
      return {&existing->profile,
              existing->payload_sha256,
              existing->profile_sha256,
              {}};
    }
    return Failure(
        "a different external ABI profile is already loaded for this Build ID");
  }
  profile->BindViews();
  const HostAbiProfile* registered = &profile->profile;
  const std::string payload_sha256 = profile->payload_sha256;
  const std::string profile_sha256 = profile->profile_sha256;
  g_external_profiles.push_back(std::move(profile));
  return {registered, payload_sha256, profile_sha256, {}};
}

struct LoadCallbackState {
  std::unique_ptr<OwnedHostAbiProfile> owned;
  std::string error;
};

bool BuiltInConflictCallback(void* /*ctx*/,
                             MocktailRustStrSlice build_id_slice) {
  const std::string_view build_id(
      build_id_slice.ptr != nullptr ? build_id_slice.ptr : "",
      build_id_slice.len);
  return FindHostAbiProfile(build_id) != nullptr &&
         FindLoadedProfile(build_id) == nullptr;
}

void OnLoadedCallback(void* ctx,
                      const MocktailRustParsedHostAbiProfile* parsed,
                      MocktailRustStrSlice canonical_payload_path,
                      MocktailRustStrSlice payload_sha256,
                      MocktailRustStrSlice profile_sha256) {
  auto* state = static_cast<LoadCallbackState*>(ctx);
  if (state == nullptr || parsed == nullptr) {
    return;
  }
  state->owned = BuildOwnedProfile(*parsed, FromSlice(canonical_payload_path),
                                   FromSlice(payload_sha256),
                                   FromSlice(profile_sha256));
}

void OnErrorCallback(void* ctx, MocktailRustStrSlice error) {
  auto* state = static_cast<LoadCallbackState*>(ctx);
  if (state == nullptr) {
    return;
  }
  state->error = FromSlice(error);
}

}  // namespace

FileSha256Result ComputeFileSha256(const std::string& path) {
  char hex_buf[65] = {};
  char err_buf[512] = {};
  const int rc = mocktail_rust_compute_file_sha256(
      path.c_str(), hex_buf, sizeof(hex_buf), err_buf, sizeof(err_buf));
  if (rc != 0) {
    return {{}, err_buf[0] != '\0' ? err_buf : "cannot hash file: " + path};
  }
  return {std::string(hex_buf), {}};
}

const HostAbiProfile* FindLoadedExternalHostAbiProfile(
    std::string_view build_id) noexcept {
  const OwnedHostAbiProfile* loaded = FindLoadedProfile(build_id);
  return loaded != nullptr ? &loaded->profile : nullptr;
}

ExternalHostAbiProfileResult LoadExternalHostAbiProfile(
    const ExternalHostAbiProfileRequest& request) {
  const MocktailRustExternalHostAbiRequestView req_view{
      ToSlice(request.profile_file),
      ToSlice(request.payload_path),
      ToSlice(request.compatibility_manifest_path),
      ToSlice(request.expected_build_id),
      ToSlice(request.approval_receipt_path),
      request.candidate_canary,
      request.candidate_process_authorization,
      request.explicit_unverified_authorization,
  };
  LoadCallbackState state;
  const int32_t rc = mocktail_rust_host_abi_load_external_profile(
      &req_view, &BuiltInConflictCallback, &OnLoadedCallback, &OnErrorCallback,
      &state);
  if (rc != 0 || !state.owned) {
    return Failure(state.error.empty()
                       ? "cannot load external host ABI profile"
                       : std::move(state.error));
  }
  return RegisterProfile(std::move(state.owned));
}

ExternalHostAbiProfileResult InitializeHostAbiProfileFromEnvironment(
    const std::string& payload_path,
    const std::string& compatibility_manifest_path,
    const std::string& expected_build_id,
    bool explicit_unverified_authorization) {
  LoadCallbackState state;
  const int32_t rc = mocktail_rust_host_abi_initialize_from_env(
      ToSlice(payload_path), ToSlice(compatibility_manifest_path),
      ToSlice(expected_build_id), explicit_unverified_authorization,
      &BuiltInConflictCallback, &OnLoadedCallback, &OnErrorCallback, &state);
  if (rc == 1) {
    return {};
  }
  if (rc != 0 || !state.owned) {
    return Failure(state.error.empty()
                       ? "cannot load external host ABI profile"
                       : std::move(state.error));
  }
  return RegisterProfile(std::move(state.owned));
}

void SetHostAbiProfileHashingFaultForTesting(bool enabled) noexcept {
  mocktail_rust_host_abi_set_hashing_fault_for_testing(enabled);
}

}  // namespace mocktail::compat
