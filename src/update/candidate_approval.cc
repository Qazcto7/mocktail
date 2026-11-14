#include "update/candidate_approval.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.data(), value.size()};
}

std::string AssignSlice(const char* ptr, size_t len) {
  if (ptr == nullptr || len == 0) return {};
  return std::string(ptr, len);
}

std::string AssignSlice(MocktailRustStrSlice slice) {
  return AssignSlice(slice.ptr, slice.len);
}

MocktailRustPayloadInfoData ToFfiPayloadInfo(
    const PayloadIntegrityResult& info) {
  return MocktailRustPayloadInfoData{
      info.payload_id.data(),
      info.payload_id.size(),
      info.metadata.package_name.data(),
      info.metadata.package_name.size(),
      info.metadata.version_name.data(),
      info.metadata.version_name.size(),
      info.metadata.version_code,
      info.metadata.build_id.data(),
      info.metadata.build_id.size(),
      info.metadata.library_sha256.data(),
      info.metadata.library_sha256.size(),
      info.metadata.base_apk_sha256.data(),
      info.metadata.base_apk_sha256.size(),
      info.metadata.split_apk_sha256.data(),
      info.metadata.split_apk_sha256.size(),
      info.metadata.asset_file_count,
      info.metadata.asset_tree_sha256.data(),
      info.metadata.asset_tree_sha256.size(),
      info.error.data(),
      info.error.size(),
  };
}

void OnApprovalResult(void* ctx, const MocktailRustCandidateApprovalData* data) {
  auto* out = static_cast<CandidateApprovalResult*>(ctx);
  if (out == nullptr || data == nullptr) return;
  out->generation = AssignSlice(data->generation, data->generation_len);
  out->profile =
      std::filesystem::path(AssignSlice(data->profile, data->profile_len));
  out->compatibility_manifest = std::filesystem::path(AssignSlice(
      data->compatibility_manifest, data->compatibility_manifest_len));
  out->receipt =
      std::filesystem::path(AssignSlice(data->receipt, data->receipt_len));
  out->error = AssignSlice(data->error, data->error_len);
}

}  // namespace

std::string PayloadRuntimeFingerprint(
    const std::filesystem::path& payload_directory,
    const PayloadIntegrityResult& payload, std::string* error) {
  struct State {
    std::string fingerprint;
    std::string error;
  } state;
  const MocktailRustPayloadInfoData ffi_payload = ToFfiPayloadInfo(payload);
  mocktail_rust_candidate_approval_compute_fingerprint(
      ToSlice(payload_directory.native()), &ffi_payload,
      [](void* ctx, MocktailRustStrSlice fingerprint,
         MocktailRustStrSlice err) {
        auto* out = static_cast<State*>(ctx);
        out->fingerprint = AssignSlice(fingerprint);
        out->error = AssignSlice(err);
      },
      &state);
  if (error != nullptr && !state.error.empty()) {
    *error = std::move(state.error);
  }
  return state.fingerprint;
}

CandidateApprovalResult CreateCandidateApproval(
    const CandidateApprovalOptions& options,
    const PayloadIntegrityResult& verified_payload) {
  const MocktailRustCandidateApprovalOptionsView view{
      ToSlice(options.store_root.native()),
      ToSlice(options.payload_directory.native()),
      ToSlice(options.profile.native()),
      ToSlice(options.compatibility_manifest.native()),
      ToSlice(options.runtime_binary.native()),
      ToSlice(options.canary_logs[0].native()),
      ToSlice(options.canary_logs[1].native()),
  };
  const MocktailRustPayloadInfoData ffi_payload =
      ToFfiPayloadInfo(verified_payload);
  CandidateApprovalResult result;
  mocktail_rust_candidate_approval_create(&view, &ffi_payload, OnApprovalResult,
                                          &result);
  return result;
}

bool ValidateCandidateApproval(const std::filesystem::path& store_root,
                               std::string_view activation_json,
                               const PayloadIntegrityResult& payload,
                               CandidateApprovalResult* approval,
                               std::string* error) {
  const MocktailRustPayloadInfoData ffi_payload = ToFfiPayloadInfo(payload);
  CandidateApprovalResult parsed;
  const bool ok = mocktail_rust_candidate_approval_validate(
      ToSlice(store_root.native()), ToSlice(activation_json), &ffi_payload,
      OnApprovalResult, &parsed);
  if (error != nullptr) {
    *error = parsed.error;
  }
  if (approval != nullptr) {
    *approval = std::move(parsed);
  }
  return ok;
}

}  // namespace mocktail::update
