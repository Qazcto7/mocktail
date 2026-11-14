#include "update/apk_bundle.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "update/apk_signature.h"

namespace mocktail::update {
namespace {

MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.data(), value.size()};
}

std::string AssignSlice(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) return {};
  return std::string(slice.ptr, slice.len);
}

bool OnVerifyApkSignature(
    void* /*ctx*/, MocktailRustStrSlice apk_path,
    void (*emit_cert)(void* receiver_ctx, MocktailRustStrSlice cert_sha256),
    void* receiver_ctx,
    void (*set_error)(void* receiver_ctx, MocktailRustStrSlice error)) {
  const ApkSignatureResult signature =
      VerifyApkSignature(std::filesystem::path(AssignSlice(apk_path)));
  if (!signature) {
    if (set_error != nullptr) {
      set_error(receiver_ctx, ToSlice(signature.error));
    }
    return false;
  }
  if (emit_cert != nullptr) {
    for (const std::string& cert : signature.certificate_sha256) {
      emit_cert(receiver_ctx, ToSlice(cert));
    }
  }
  return true;
}

void OnPreparedPayload(void* ctx, const MocktailRustPreparedPayloadView* data) {
  auto* out = static_cast<PreparedPayload*>(ctx);
  if (out == nullptr || data == nullptr) return;
  out->directory = std::filesystem::path(AssignSlice(data->directory));
  out->payload_id = AssignSlice(data->payload_id);
  out->version_name = AssignSlice(data->version_name);
  out->version_code = data->version_code;
  out->build_id = AssignSlice(data->build_id);
  out->error = AssignSlice(data->error);
}

}  // namespace

PreparedPayload PreparePayloadFromArchives(
    const std::vector<std::filesystem::path>& archives,
    const ExpectedPayloadIdentity& expected,
    const std::filesystem::path& signing_trust_manifest,
    const std::filesystem::path& workspace, std::string_view source) {
  std::vector<MocktailRustStrSlice> archive_slices;
  archive_slices.reserve(archives.size());
  for (const std::filesystem::path& archive : archives) {
    archive_slices.push_back(ToSlice(archive.native()));
  }
  const MocktailRustExpectedPayloadIdentityView expected_view{
      ToSlice(expected.version_name),
      expected.version_code,
      expected.exact_build_id.has_value(),
      expected.exact_build_id ? ToSlice(*expected.exact_build_id)
                              : MocktailRustStrSlice{},
  };
  PreparedPayload result;
  mocktail_rust_apk_prepare_payload_from_archives(
      archive_slices.empty() ? nullptr : archive_slices.data(),
      archive_slices.size(), &expected_view,
      ToSlice(signing_trust_manifest.native()), ToSlice(workspace.native()),
      ToSlice(source), OnVerifyApkSignature, nullptr, OnPreparedPayload,
      &result);
  return result;
}

ExpectedPayloadIdentity ExactPayloadIdentity(
    const SupportedPayloadProfile& profile) {
  return {profile.version_name, profile.version_code, profile.elf_build_id};
}

}  // namespace mocktail::update
