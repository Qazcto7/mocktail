#include "update/candidate_approval.h"
#include "mocktail/mocktail_rust.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "compat/elf_build_id.h"
#include "compat/guest_abi.h"
#include "update/payload_integrity.h"

namespace mocktail::update {
namespace {

constexpr std::size_t kMaximumApprovalBytes = 1024U * 1024U;

bool IsLowerHex(std::string_view value, std::size_t size) {
  const std::string s(value);
  return mocktail_rust_is_lower_hex(s.c_str(), size) == 1;
}

std::string ReadRegular(const std::filesystem::path& path,
                        bool require_immutable, std::string* error) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    *error = "cannot open approval artifact: " + path.string();
    return {};
  }
  struct stat metadata = {};
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_uid != geteuid() || metadata.st_size < 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > kMaximumApprovalBytes ||
      (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      (require_immutable && (metadata.st_mode & S_IWUSR) != 0)) {
    close(descriptor);
    *error = "approval artifact ownership or permissions are invalid";
    return {};
  }
  std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const ssize_t bytes =
        read(descriptor, contents.data() + offset, contents.size() - offset);
    if (bytes < 0 && errno == EINTR) continue;
    if (bytes <= 0) {
      close(descriptor);
      *error = "cannot read approval artifact";
      return {};
    }
    offset += static_cast<std::size_t>(bytes);
  }
  close(descriptor);
  return contents;
}

bool WriteExclusive(const std::filesystem::path& path,
                    std::string_view contents, mode_t mode,
                    std::string* error) {
  std::error_code filesystem_error;
  std::filesystem::create_directories(path.parent_path(), filesystem_error);
  if (filesystem_error) {
    *error = "cannot create approval artifact directory";
    return false;
  }
  if (std::filesystem::exists(path, filesystem_error)) {
    std::string read_error;
    const std::string existing = ReadRegular(path, mode == 0444, &read_error);
    if (read_error.empty() && existing == contents) return true;
    *error = "immutable approval generation collision";
    return false;
  }
  const std::filesystem::path temporary =
      path.parent_path() /
      (".approval-" + std::to_string(getpid()) + "-" +
       std::to_string(
           std::chrono::steady_clock::now().time_since_epoch().count()));
  const int descriptor =
      open(temporary.c_str(),
           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    *error = "cannot create approval artifact";
    return false;
  }
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const ssize_t bytes =
        write(descriptor, contents.data() + offset, contents.size() - offset);
    if (bytes < 0 && errno == EINTR) continue;
    if (bytes <= 0) {
      close(descriptor);
      std::filesystem::remove(temporary, filesystem_error);
      *error = "cannot write approval artifact";
      return false;
    }
    offset += static_cast<std::size_t>(bytes);
  }
  if (fchmod(descriptor, mode) != 0 || fsync(descriptor) != 0) {
    close(descriptor);
    std::filesystem::remove(temporary, filesystem_error);
    *error = "cannot make approval artifact immutable";
    return false;
  }
  close(descriptor);
  std::filesystem::rename(temporary, path, filesystem_error);
  if (filesystem_error) {
    std::filesystem::remove(temporary, filesystem_error);
    *error = "cannot publish approval artifact";
    return false;
  }
  return true;
}

bool CopyImmutable(const std::filesystem::path& source,
                   const std::filesystem::path& destination,
                   std::string* error) {
  const std::string contents = ReadRegular(source, false, error);
  return error->empty() && WriteExclusive(destination, contents, 0444, error);
}

std::string UtcTimestamp() {
  const std::time_t now = std::time(nullptr);
  std::tm utc{};
  if (gmtime_r(&now, &utc) == nullptr) return "1970-01-01T00:00:00Z";
  std::array<char, 32> value{};
  std::strftime(value.data(), value.size(), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return value.data();
}

bool ValidateRelativeApprovalPath(const std::filesystem::path& root,
                                  const std::filesystem::path& path,
                                  std::string_view directory,
                                  std::string_view payload_id,
                                  std::string_view generation,
                                  std::filesystem::path* resolved,
                                  std::string* error) {
  if (path.is_absolute() || path.has_root_path() ||
      path != std::filesystem::path(directory) /
                  (std::string(payload_id) + "-" + std::string(generation) +
                   ".json")) {
    *error = "approval reference is outside its generated directory";
    return false;
  }
  std::error_code filesystem_error;
  const std::filesystem::path canonical_root =
      std::filesystem::canonical(root, filesystem_error);
  if (filesystem_error) {
    *error = "approval store root cannot be resolved safely";
    return false;
  }
  filesystem_error.clear();
  const std::filesystem::path canonical =
      std::filesystem::canonical(root / path, filesystem_error);
  if (filesystem_error ||
      canonical.parent_path() != canonical_root / directory ||
      canonical.filename() != path.filename()) {
    *error = "approval reference cannot be resolved safely";
    return false;
  }
  *resolved = canonical;
  return true;
}

bool ValidateProfileBinding(std::string_view profile_bytes,
                            std::string_view compatibility_bytes,
                            const PayloadIntegrityResult& payload,
                            std::string* error) {
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_candidate_approval_validate_binding(
      profile_bytes.data(), profile_bytes.size(),
      compatibility_bytes.data(), compatibility_bytes.size(),
      payload.payload_id.data(), payload.payload_id.size(),
      payload.metadata.build_id.data(), payload.metadata.build_id.size(),
      payload.metadata.library_sha256.data(),
      payload.metadata.library_sha256.size(),
      payload.metadata.version_name.data(),
      payload.metadata.version_name.size(), payload.metadata.version_code,
      err_buf.data(), err_buf.size());
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf.data()[0] != '\0'
                   ? err_buf.data()
                   : "derived approval profile is not bound to exact payload bytes";
    }
    return false;
  }
  return true;
}

}  // namespace

std::string PayloadRuntimeFingerprint(
    const std::filesystem::path& payload_directory,
    const PayloadIntegrityResult& payload, std::string* error) {
  if (!payload || payload.payload_id.empty()) {
    *error = "cannot fingerprint an invalid payload";
    return {};
  }
  const std::string metadata =
      HashRegularFile(payload_directory / "roblox_payload.json", error);
  if (!error->empty()) return {};

  const std::string guest_abi(compat::kGuestAbi);
  const MocktailRustPayloadFingerprintInput input{
      payload.payload_id.data(),
      payload.payload_id.size(),
      metadata.data(),
      metadata.size(),
      payload.metadata.library_sha256.data(),
      payload.metadata.library_sha256.size(),
      payload.metadata.base_apk_sha256.data(),
      payload.metadata.base_apk_sha256.size(),
      guest_abi.data(),
      guest_abi.size(),
      payload.metadata.split_apk_sha256.data(),
      payload.metadata.split_apk_sha256.size(),
      payload.metadata.asset_tree_sha256.data(),
      payload.metadata.asset_tree_sha256.size(),
  };

  std::array<char, 65> out_sha{};
  if (mocktail_rust_candidate_approval_fingerprint(&input, out_sha.data(),
                                                  out_sha.size()) != 0) {
    *error = "cannot fingerprint an invalid payload";
    return {};
  }
  return std::string(out_sha.data(), 64);
}

CandidateApprovalResult CreateCandidateApproval(
    const CandidateApprovalOptions& options,
    const PayloadIntegrityResult& verified_payload) {
  CandidateApprovalResult result;
  if (!verified_payload || verified_payload.payload_id.empty() ||
      options.payload_directory.filename() != verified_payload.payload_id) {
    result.error = "candidate approval requires a preverified exact payload";
    return result;
  }
  if (options.canary_logs[0].empty() || options.canary_logs[1].empty() ||
      options.canary_logs[0] == options.canary_logs[1]) {
    result.error = "candidate approval requires two distinct canary logs";
    return result;
  }
  const PayloadIntegrityResult& payload = verified_payload;
  std::string profile_bytes =
      ReadRegular(options.profile, false, &result.error);
  std::string compatibility_bytes =
      ReadRegular(options.compatibility_manifest, false, &result.error);
  if (!result.error.empty()) return result;
  if (!ValidateProfileBinding(profile_bytes, compatibility_bytes, payload,
                              &result.error)) {
    return result;
  }
  const std::string profile_sha256 = HashText(profile_bytes, &result.error);
  const std::string compatibility_sha256 =
      HashText(compatibility_bytes, &result.error);
  if (!result.error.empty()) return result;
  const std::string runtime_sha256 =
      HashRegularFile(options.runtime_binary, &result.error);
  const compat::BuildIdResult runtime_build_id =
      compat::ReadElfBuildId(options.runtime_binary.string());
  const std::string fingerprint = PayloadRuntimeFingerprint(
      options.payload_directory, payload, &result.error);
  if (!result.error.empty() || !runtime_build_id ||
      !IsLowerHex(runtime_build_id.build_id, 40)) {
    if (result.error.empty()) result.error = runtime_build_id.error;
    return result;
  }
  std::array<std::string, 2> attestations;
  std::array<std::string, 2> attestation_hashes;
  const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  for (std::size_t index = 0; index < options.canary_logs.size(); ++index) {
    const std::string log_sha256 =
        HashRegularFile(options.canary_logs[index], &result.error);
    if (!result.error.empty()) return result;
    const std::size_t run = index + 1;
    const std::string run_id = payload.payload_id + "-" + std::to_string(run) +
                               "-" + std::to_string(epoch) + "-" +
                               std::to_string(getpid());
    const MocktailRustCanaryAttestationInput attestation_input{
        run,
        run_id.data(),
        run_id.size(),
        payload.payload_id.data(),
        payload.payload_id.size(),
        fingerprint.data(),
        fingerprint.size(),
        profile_sha256.data(),
        profile_sha256.size(),
        compatibility_sha256.data(),
        compatibility_sha256.size(),
        runtime_sha256.data(),
        runtime_sha256.size(),
        runtime_build_id.build_id.data(),
        runtime_build_id.build_id.size(),
        log_sha256.data(),
        log_sha256.size(),
    };
    std::string attestation_json(4096, '\0');
    size_t attestation_len = 0;
    if (mocktail_rust_candidate_approval_build_attestation(
            &attestation_input, attestation_json.data(),
            attestation_json.size(), &attestation_len) != 0) {
      result.error = "cannot serialize canary attestation";
      return result;
    }
    attestation_json.resize(attestation_len);
    attestations[index] = std::move(attestation_json);
    attestation_hashes[index] = HashText(attestations[index], &result.error);
    if (!result.error.empty()) return result;
  }
  std::array<char, 41> generation_buf{};
  if (mocktail_rust_candidate_approval_generation(
          runtime_build_id.build_id.data(), runtime_build_id.build_id.size(),
          fingerprint.data(), fingerprint.size(),
          profile_sha256.data(), profile_sha256.size(),
          compatibility_sha256.data(), compatibility_sha256.size(),
          attestation_hashes[0].data(), attestation_hashes[0].size(),
          attestation_hashes[1].data(), attestation_hashes[1].size(),
          generation_buf.data(), generation_buf.size()) != 0) {
    result.error = "cannot derive candidate approval generation";
    return result;
  }
  result.generation = std::string(generation_buf.data(), 40);
  if (!result.error.empty()) return result;
  const std::string stem = payload.payload_id + "-" + result.generation;
  result.profile = options.store_root / "host_abi_profiles" / (stem + ".json");
  result.compatibility_manifest =
      options.store_root / "compatibility_profiles" / (stem + ".json");
  result.receipt = options.store_root / "approvals" / (stem + ".json");
  const std::array<std::filesystem::path, 2> attestation_paths = {
      options.store_root / "approvals" / (stem + ".canary-1.json"),
      options.store_root / "approvals" / (stem + ".canary-2.json"),
  };
  if (!CopyImmutable(options.profile, result.profile, &result.error) ||
      !CopyImmutable(options.compatibility_manifest,
                     result.compatibility_manifest, &result.error) ||
      !WriteExclusive(attestation_paths[0], attestations[0], 0444,
                      &result.error) ||
      !WriteExclusive(attestation_paths[1], attestations[1], 0444,
                      &result.error)) {
    return result;
  }
  std::error_code filesystem_error;
  const std::filesystem::path canonical_library = std::filesystem::canonical(
      options.payload_directory / "libroblox.so", filesystem_error);
  if (filesystem_error) {
    result.error = "cannot canonicalize approved payload library";
    return result;
  }
  const std::string approved_at = UtcTimestamp();
  const std::string canonical_str = canonical_library.string();
  const MocktailRustApprovalReceiptInput receipt_input{
      payload.payload_id.data(),
      payload.payload_id.size(),
      result.generation.data(),
      result.generation.size(),
      canonical_str.data(),
      canonical_str.size(),
      payload.metadata.build_id.data(),
      payload.metadata.build_id.size(),
      payload.metadata.library_sha256.data(),
      payload.metadata.library_sha256.size(),
      fingerprint.data(),
      fingerprint.size(),
      profile_sha256.data(),
      profile_sha256.size(),
      compatibility_sha256.data(),
      compatibility_sha256.size(),
      runtime_sha256.data(),
      runtime_sha256.size(),
      runtime_build_id.build_id.data(),
      runtime_build_id.build_id.size(),
      attestation_hashes[0].data(),
      attestation_hashes[0].size(),
      attestation_hashes[1].data(),
      attestation_hashes[1].size(),
      approved_at.data(),
      approved_at.size(),
  };
  std::string receipt_json(4096, '\0');
  size_t receipt_len = 0;
  if (mocktail_rust_candidate_approval_build_receipt(
          &receipt_input, receipt_json.data(), receipt_json.size(),
          &receipt_len) != 0) {
    result.error = "cannot serialize candidate approval receipt";
    return result;
  }
  receipt_json.resize(receipt_len);
  if (!WriteExclusive(result.receipt, receipt_json, 0444,
                      &result.error)) {
    return result;
  }
  return result;
}

bool ValidateCandidateApproval(const std::filesystem::path& store_root,
                               std::string_view activation_json,
                               const PayloadIntegrityResult& payload,
                               CandidateApprovalResult* approval,
                               std::string* error) {
  struct ParsedRefs {
    std::string generation;
    std::string approval_ref;
    std::string profile_ref;
    std::string compatibility_ref;
  } refs;
  char err_buf[256] = {};
  const auto on_parsed = [](void* ctx, const char* gen_ptr, size_t gen_len,
                            const char* app_ptr, size_t app_len,
                            const char* prof_ptr, size_t prof_len,
                            const char* comp_ptr, size_t comp_len) {
    auto* out = static_cast<ParsedRefs*>(ctx);
    if (gen_ptr != nullptr && gen_len > 0) out->generation.assign(gen_ptr, gen_len);
    if (app_ptr != nullptr && app_len > 0) out->approval_ref.assign(app_ptr, app_len);
    if (prof_ptr != nullptr && prof_len > 0) out->profile_ref.assign(prof_ptr, prof_len);
    if (comp_ptr != nullptr && comp_len > 0) out->compatibility_ref.assign(comp_ptr, comp_len);
  };
  if (mocktail_rust_candidate_approval_parse_activation(
          activation_json.data(), activation_json.size(),
          payload.payload_id.c_str(), on_parsed, &refs, err_buf,
          sizeof(err_buf)) != 0) {
    *error = err_buf[0] != '\0' ? err_buf
                                : "approval artifact is not a JSON object";
    return false;
  }
  approval->generation = refs.generation;
  if (!ValidateRelativeApprovalPath(store_root, refs.approval_ref, "approvals",
                                    payload.payload_id, refs.generation,
                                    &approval->receipt, error) ||
      !ValidateRelativeApprovalPath(store_root, refs.profile_ref,
                                    "host_abi_profiles", payload.payload_id,
                                    refs.generation, &approval->profile, error) ||
      !ValidateRelativeApprovalPath(
          store_root, refs.compatibility_ref, "compatibility_profiles",
          payload.payload_id, refs.generation,
          &approval->compatibility_manifest, error)) {
    return false;
  }
  const std::string receipt_bytes = ReadRegular(approval->receipt, true, error);
  const std::string profile_bytes = ReadRegular(approval->profile, true, error);
  const std::string compatibility_bytes =
      ReadRegular(approval->compatibility_manifest, true, error);
  if (!error->empty()) return false;
  if (!ValidateProfileBinding(profile_bytes, compatibility_bytes, payload,
                              error)) {
    return false;
  }
  const std::string fingerprint = PayloadRuntimeFingerprint(
      store_root / "payloads" / payload.payload_id, payload, error);
  const std::string profile_sha256 = HashText(profile_bytes, error);
  const std::string compatibility_sha256 =
      HashText(compatibility_bytes, error);
  if (!error->empty()) return false;
  std::error_code filesystem_error;
  const std::filesystem::path canonical_library = std::filesystem::canonical(
      store_root / "payloads" / payload.payload_id / "libroblox.so",
      filesystem_error);
  if (filesystem_error) {
    *error = "cannot canonicalize approved payload library";
    return false;
  }
  std::array<std::string, 2> canary_bytes;
  for (std::size_t index = 0; index < 2; ++index) {
    const std::filesystem::path attestation_path =
        store_root / "approvals" /
        (payload.payload_id + "-" + refs.generation + ".canary-" +
         std::to_string(index + 1) + ".json");
    canary_bytes[index] = ReadRegular(attestation_path, true, error);
    if (!error->empty()) return false;
  }
  MocktailRustCandidateEvidenceRequest evidence_req{};
  evidence_req.receipt_ptr = receipt_bytes.data();
  evidence_req.receipt_len = receipt_bytes.size();
  evidence_req.canary1_ptr = canary_bytes[0].data();
  evidence_req.canary1_len = canary_bytes[0].size();
  evidence_req.canary2_ptr = canary_bytes[1].data();
  evidence_req.canary2_len = canary_bytes[1].size();
  evidence_req.payload_id = payload.payload_id.c_str();
  evidence_req.generation = refs.generation.c_str();
  evidence_req.canonical_library_path = canonical_library.c_str();
  evidence_req.elf_build_id = payload.metadata.build_id.c_str();
  evidence_req.library_sha256 = payload.metadata.library_sha256.c_str();
  evidence_req.fingerprint = fingerprint.c_str();
  evidence_req.profile_sha256 = profile_sha256.c_str();
  evidence_req.compatibility_sha256 = compatibility_sha256.c_str();
  if (mocktail_rust_candidate_approval_verify_evidence(
          &evidence_req, err_buf, sizeof(err_buf)) != 0) {
    *error = err_buf[0] != '\0'
                 ? err_buf
                 : "approval receipt does not authorize exact payload evidence";
    return false;
  }
  return true;
}

}  // namespace mocktail::update
