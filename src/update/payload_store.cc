#include "update/payload_store.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "update/candidate_approval.h"
#include "update/compatibility_catalog.h"
#include "update/payload_integrity.h"

namespace mocktail::update {
namespace {

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

PayloadIntegrityResult FromFfiPayloadInfo(
    const MocktailRustPayloadInfoData* data) {
  PayloadIntegrityResult out;
  if (data == nullptr) return out;
  if (data->payload_id != nullptr)
    out.payload_id.assign(data->payload_id, data->payload_id_len);
  if (data->package_name != nullptr)
    out.metadata.package_name.assign(data->package_name,
                                     data->package_name_len);
  if (data->version_name != nullptr)
    out.metadata.version_name.assign(data->version_name,
                                     data->version_name_len);
  out.metadata.version_code = data->version_code;
  if (data->build_id != nullptr)
    out.metadata.build_id.assign(data->build_id, data->build_id_len);
  if (data->library_sha256 != nullptr)
    out.metadata.library_sha256.assign(data->library_sha256,
                                       data->library_sha256_len);
  if (data->base_apk_sha256 != nullptr)
    out.metadata.base_apk_sha256.assign(data->base_apk_sha256,
                                        data->base_apk_sha256_len);
  if (data->split_apk_sha256 != nullptr)
    out.metadata.split_apk_sha256.assign(data->split_apk_sha256,
                                         data->split_apk_sha256_len);
  out.metadata.asset_file_count = data->asset_file_count;
  if (data->asset_tree_sha256 != nullptr)
    out.metadata.asset_tree_sha256.assign(data->asset_tree_sha256,
                                          data->asset_tree_sha256_len);
  if (data->error != nullptr) out.error.assign(data->error, data->error_len);
  return out;
}

std::filesystem::path PathFromSlice(const char* ptr, size_t len) {
  if (ptr == nullptr || len == 0) return {};
  return std::filesystem::path(std::string(ptr, len));
}

void OnInspectPreparedPayload(void* /*ctx*/, const char* dir_ptr,
                              size_t dir_len, void* receiver_ctx,
                              MocktailRustPayloadInfoReceiver receiver) {
  if (receiver == nullptr) return;
  const PayloadIntegrityResult info =
      InspectPreparedPayload(PathFromSlice(dir_ptr, dir_len));
  const MocktailRustPayloadInfoData ffi = ToFfiPayloadInfo(info);
  receiver(receiver_ctx, &ffi);
}

void OnVerifyPreparedPayload(void* /*ctx*/, const char* dir_ptr, size_t dir_len,
                             void* receiver_ctx,
                             MocktailRustPayloadInfoReceiver receiver) {
  if (receiver == nullptr) return;
  const PayloadIntegrityResult info =
      VerifyPreparedPayload(PathFromSlice(dir_ptr, dir_len));
  const MocktailRustPayloadInfoData ffi = ToFfiPayloadInfo(info);
  receiver(receiver_ctx, &ffi);
}

void OnHashRegularFile(void* /*ctx*/, const char* path_ptr, size_t path_len,
                       void* receiver_ctx,
                       MocktailRustPayloadStoreStrReceiver on_hash,
                       MocktailRustPayloadStoreStrReceiver on_error) {
  std::string error;
  const std::string sha256 =
      HashRegularFile(PathFromSlice(path_ptr, path_len), &error);
  if (!error.empty()) {
    if (on_error != nullptr) on_error(receiver_ctx, error.data(), error.size());
    return;
  }
  if (on_hash != nullptr) on_hash(receiver_ctx, sha256.data(), sha256.size());
}

bool OnExactSupported(void* /*ctx*/, const char* compat_ptr, size_t compat_len,
                      const MocktailRustPayloadInfoData* payload_data,
                      void* receiver_ctx,
                      MocktailRustPayloadStoreStrReceiver on_error) {
  const CompatibilityCatalogResult catalog =
      LoadCompatibilityCatalog(PathFromSlice(compat_ptr, compat_len));
  if (!catalog) {
    if (on_error != nullptr)
      on_error(receiver_ctx, catalog.error.data(), catalog.error.size());
    return false;
  }
  const PayloadIntegrityResult payload = FromFfiPayloadInfo(payload_data);
  const auto found = std::find_if(
      catalog.profiles.begin(), catalog.profiles.end(),
      [&](const auto& profile) {
        return profile.version_code == payload.metadata.version_code &&
               profile.version_name == payload.metadata.version_name &&
               profile.elf_build_id == payload.metadata.build_id;
      });
  if (found == catalog.profiles.end()) {
    static constexpr char kUnsupported[] =
        "payload is not an exact default-supported profile";
    if (on_error != nullptr)
      on_error(receiver_ctx, kUnsupported, sizeof(kUnsupported) - 1);
    return false;
  }
  return true;
}

void EmitApprovalResult(const CandidateApprovalResult& approval,
                        void* receiver_ctx,
                        MocktailRustCandidateApprovalReceiver receiver) {
  if (receiver == nullptr) return;
  const std::string& profile = approval.profile.native();
  const std::string& compat = approval.compatibility_manifest.native();
  const std::string& receipt = approval.receipt.native();
  const MocktailRustCandidateApprovalData ffi{
      approval.generation.data(),
      approval.generation.size(),
      profile.data(),
      profile.size(),
      compat.data(),
      compat.size(),
      receipt.data(),
      receipt.size(),
      approval.error.data(),
      approval.error.size(),
  };
  receiver(receiver_ctx, &ffi);
}

void OnCreateCandidateApproval(
    void* /*ctx*/, const char* store_root_ptr, size_t store_root_len,
    const char* payload_dir_ptr, size_t payload_dir_len,
    const char* profile_ptr, size_t profile_len, const char* compat_ptr,
    size_t compat_len, const char* runtime_binary_ptr,
    size_t runtime_binary_len, const char* canary0_ptr, size_t canary0_len,
    const char* canary1_ptr, size_t canary1_len,
    const MocktailRustPayloadInfoData* verified_payload, void* receiver_ctx,
    MocktailRustCandidateApprovalReceiver receiver) {
  CandidateApprovalOptions options;
  options.store_root = PathFromSlice(store_root_ptr, store_root_len);
  options.payload_directory = PathFromSlice(payload_dir_ptr, payload_dir_len);
  options.profile = PathFromSlice(profile_ptr, profile_len);
  options.compatibility_manifest = PathFromSlice(compat_ptr, compat_len);
  options.runtime_binary =
      PathFromSlice(runtime_binary_ptr, runtime_binary_len);
  options.canary_logs = {
      PathFromSlice(canary0_ptr, canary0_len),
      PathFromSlice(canary1_ptr, canary1_len),
  };
  const CandidateApprovalResult approval =
      CreateCandidateApproval(options, FromFfiPayloadInfo(verified_payload));
  EmitApprovalResult(approval, receiver_ctx, receiver);
}

bool OnValidateCandidateApproval(
    void* /*ctx*/, const char* store_root_ptr, size_t store_root_len,
    const char* activation_json_ptr, size_t activation_json_len,
    const MocktailRustPayloadInfoData* payload, void* receiver_ctx,
    MocktailRustCandidateApprovalReceiver receiver) {
  CandidateApprovalResult approval;
  const std::string_view json(
      activation_json_ptr != nullptr ? activation_json_ptr : "",
      activation_json_len);
  const bool ok = ValidateCandidateApproval(
      PathFromSlice(store_root_ptr, store_root_len), json,
      FromFfiPayloadInfo(payload), &approval, &approval.error);
  EmitApprovalResult(approval, receiver_ctx, receiver);
  return ok;
}

const MocktailRustPayloadStoreOps kPayloadStoreOps{
    nullptr,
    OnInspectPreparedPayload,
    OnVerifyPreparedPayload,
    OnHashRegularFile,
    OnExactSupported,
    OnCreateCandidateApproval,
    OnValidateCandidateApproval,
};

MocktailRustPayloadStorePaths MakeFfiPaths(
    const std::filesystem::path& root,
    const std::filesystem::path& compatibility_manifest,
    const std::filesystem::path& runtime_binary) {
  return MocktailRustPayloadStorePaths{
      root.native().data(),
      root.native().size(),
      compatibility_manifest.native().data(),
      compatibility_manifest.native().size(),
      runtime_binary.native().data(),
      runtime_binary.native().size(),
  };
}

void AssignStoreResult(void* raw_ctx,
                       const MocktailRustPayloadStoreResultData* data) {
  if (raw_ctx == nullptr || data == nullptr) return;
  auto* result = static_cast<PayloadStoreResult*>(raw_ctx);
  if (data->payload_id != nullptr)
    result->payload_id.assign(data->payload_id, data->payload_id_len);
  result->payload_directory =
      PathFromSlice(data->payload_directory, data->payload_directory_len);
  result->host_abi_profile =
      PathFromSlice(data->host_abi_profile, data->host_abi_profile_len);
  result->compatibility_manifest = PathFromSlice(
      data->compatibility_manifest, data->compatibility_manifest_len);
  result->approval_receipt =
      PathFromSlice(data->approval_receipt, data->approval_receipt_len);
  if (data->version_name != nullptr)
    result->version_name.assign(data->version_name, data->version_name_len);
  result->version_code = data->version_code;
  if (data->build_id != nullptr)
    result->build_id.assign(data->build_id, data->build_id_len);
  if (data->error != nullptr)
    result->error.assign(data->error, data->error_len);
}

void AppendString(void* raw_ctx, const char* ptr, size_t len) {
  if (raw_ctx == nullptr || ptr == nullptr) return;
  static_cast<std::vector<std::string>*>(raw_ctx)->emplace_back(ptr, len);
}

void AssignString(void* raw_ctx, const char* ptr, size_t len) {
  if (raw_ctx == nullptr) return;
  static_cast<std::string*>(raw_ctx)->assign(ptr != nullptr ? ptr : "", len);
}

struct GarbageCtx {
  PayloadGarbageResult* result;
};

void OnGarbageRemoved(void* raw_ctx, const char* ptr, size_t len) {
  AppendString(&static_cast<GarbageCtx*>(raw_ctx)->result->removed, ptr, len);
}

void OnGarbageError(void* raw_ctx, const char* ptr, size_t len) {
  AssignString(&static_cast<GarbageCtx*>(raw_ctx)->result->error, ptr, len);
}

struct StatusCtx {
  std::string* output;
  std::string* error;
};

void OnStatusJson(void* raw_ctx, const char* ptr, size_t len) {
  AssignString(static_cast<StatusCtx*>(raw_ctx)->output, ptr, len);
}

void OnStatusError(void* raw_ctx, const char* ptr, size_t len) {
  AssignString(static_cast<StatusCtx*>(raw_ctx)->error, ptr, len);
}

}  // namespace

PayloadStore::PayloadStore(std::filesystem::path root,
                           std::filesystem::path compatibility_manifest,
                           std::filesystem::path runtime_binary)
    : root_(std::move(root)),
      compatibility_manifest_(std::move(compatibility_manifest)),
      runtime_binary_(std::move(runtime_binary)) {}

PayloadStoreResult PayloadStore::Stage(
    const std::filesystem::path& prepared_payload) {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  const std::string& prepared = prepared_payload.native();
  mocktail_rust_payload_store_stage(&paths, prepared.data(), prepared.size(),
                                    &kPayloadStoreOps, AssignStoreResult,
                                    &result);
  return result;
}

PayloadStoreResult PayloadStore::Promote(std::string_view payload_id) {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  mocktail_rust_payload_store_promote(&paths, payload_id.data(),
                                      payload_id.size(), &kPayloadStoreOps,
                                      AssignStoreResult, &result);
  return result;
}

PayloadStoreResult PayloadStore::PromoteProbation(
    std::string_view payload_id, const std::filesystem::path& candidate_profile,
    const std::filesystem::path& candidate_compatibility,
    const std::array<std::filesystem::path, 2>& canary_logs) {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  mocktail_rust_payload_store_promote_probation(
      &paths, payload_id.data(), payload_id.size(),
      candidate_profile.native().data(), candidate_profile.native().size(),
      candidate_compatibility.native().data(),
      candidate_compatibility.native().size(), canary_logs[0].native().data(),
      canary_logs[0].native().size(), canary_logs[1].native().data(),
      canary_logs[1].native().size(), &kPayloadStoreOps, AssignStoreResult,
      &result);
  return result;
}

PayloadStoreResult PayloadStore::Import(
    const std::filesystem::path& prepared_payload) {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  const std::string& prepared = prepared_payload.native();
  mocktail_rust_payload_store_import(&paths, prepared.data(), prepared.size(),
                                     &kPayloadStoreOps, AssignStoreResult,
                                     &result);
  return result;
}

PayloadStoreResult PayloadStore::VerifyCurrent() {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  mocktail_rust_payload_store_verify_current(&paths, &kPayloadStoreOps,
                                             AssignStoreResult, &result);
  return result;
}

PayloadStoreResult PayloadStore::InspectCurrent() const {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  mocktail_rust_payload_store_inspect_current(&paths, &kPayloadStoreOps,
                                              AssignStoreResult, &result);
  return result;
}

PayloadStoreResult PayloadStore::Rollback() {
  PayloadStoreResult result;
  const MocktailRustPayloadStorePaths paths =
      MakeFfiPaths(root_, compatibility_manifest_, runtime_binary_);
  mocktail_rust_payload_store_rollback(&paths, &kPayloadStoreOps,
                                       AssignStoreResult, &result);
  return result;
}

PayloadGarbageResult PayloadStore::CollectGarbage(
    const std::vector<std::string>& keep) {
  PayloadGarbageResult result;
  std::vector<const char*> keep_ptrs;
  std::vector<size_t> keep_lens;
  keep_ptrs.reserve(keep.size());
  keep_lens.reserve(keep.size());
  for (const std::string& entry : keep) {
    keep_ptrs.push_back(entry.data());
    keep_lens.push_back(entry.size());
  }
  uint64_t freed_bytes = 0;
  GarbageCtx ctx{&result};
  mocktail_rust_payload_store_collect_garbage(
      root_.native().data(), root_.native().size(),
      keep_ptrs.empty() ? nullptr : keep_ptrs.data(),
      keep_lens.empty() ? nullptr : keep_lens.data(), keep.size(),
      OnGarbageRemoved, &freed_bytes, OnGarbageError, &ctx);
  result.freed_bytes = freed_bytes;
  return result;
}

std::string PayloadStore::StatusJson(std::string* output_error) const {
  std::string local_error;
  std::string* error = output_error != nullptr ? output_error : &local_error;
  std::string output;
  StatusCtx ctx{&output, error};
  if (mocktail_rust_payload_store_status_json(root_.native().data(),
                                              root_.native().size(),
                                              OnStatusJson, OnStatusError,
                                              &ctx) != 0) {
    return {};
  }
  return output;
}

}  // namespace mocktail::update
