#include "update/payload_integrity.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "compat/guest_abi.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {



std::string FormatHex(const unsigned char* data, std::size_t size,
                      std::size_t max_chars = 0) {
  static constexpr char kHex[] = "0123456789abcdef";
  const std::size_t limit =
      (max_chars > 0 && max_chars < size * 2U) ? max_chars : size * 2U;
  std::string hex;
  hex.reserve(limit);
  for (std::size_t i = 0; i < size && hex.size() < limit; ++i) {
    hex.push_back(kHex[(data[i] >> 4) & 0x0f]);
    if (hex.size() < limit) {
      hex.push_back(kHex[data[i] & 0x0f]);
    }
  }
  return hex;
}

}  // namespace

FileDigest::FileDigest() : context_(EVP_MD_CTX_new()) {
  if (context_ != nullptr &&
      EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(context_);
    context_ = nullptr;
  }
}

FileDigest::~FileDigest() {
  if (context_ != nullptr) EVP_MD_CTX_free(context_);
}

bool FileDigest::Update(const void* data, std::size_t size) {
  if (size == 0) return context_ != nullptr;
  return context_ != nullptr && data != nullptr &&
         EVP_DigestUpdate(context_, data, size) == 1;
}

bool FileDigest::Update(std::string_view bytes) {
  return Update(bytes.data(), bytes.size());
}

std::string FileDigest::FinalHex(std::size_t max_chars) {
  unsigned char digest[EVP_MAX_MD_SIZE] = {};
  unsigned int size = 0;
  if (context_ == nullptr ||
      EVP_DigestFinal_ex(context_, digest, &size) != 1 || size != 32U) {
    return {};
  }
  return FormatHex(digest, size, max_chars);
}

std::string HashText(std::string_view text, std::size_t max_hex_chars,
                     std::string* error) {
  char hex_buf[65] = {};
  if (mocktail_rust_sha256(reinterpret_cast<const uint8_t*>(text.data()),
                           text.size(), hex_buf, sizeof(hex_buf)) != 0) {
    if (error != nullptr && error->empty()) {
      *error = "cannot compute SHA-256 text digest";
    }
    return {};
  }
  std::string hex(hex_buf);
  if (max_hex_chars > 0 && max_hex_chars < hex.size()) {
    hex.resize(max_hex_chars);
  }
  return hex;
}

std::string HashText(std::string_view text, std::string* error) {
  return HashText(text, 64, error);
}

std::string HashRegularFile(const std::filesystem::path& path,
                            std::string* output_error) {
  std::string local_error;
  std::string* error = output_error != nullptr ? output_error : &local_error;
  char hex_buf[65] = {};
  if (mocktail_rust_sha256_file(path.c_str(), hex_buf, sizeof(hex_buf)) == 0) {
    return std::string(hex_buf);
  }
  *error = "cannot hash regular file: " + path.string();
  return {};
}

std::string HashAssetTree(const std::filesystem::path& root,
                          std::size_t* file_count, std::string* output_error) {
  std::string local_error;
  std::string* error = output_error != nullptr ? output_error : &local_error;
  char hex_buf[65] = {};
  std::size_t count = 0;
  char err_buf[512] = {};
  int rc = mocktail_rust_payload_hash_asset_tree(
      root.c_str(), hex_buf, sizeof(hex_buf), &count, err_buf, sizeof(err_buf));
  if (rc != 0) {
    *error = err_buf[0] != '\0' ? err_buf : "failed to hash asset tree";
    return {};
  }
  if (file_count != nullptr) {
    *file_count = count;
  }
  return std::string(hex_buf);
}

namespace {

using PayloadInfoQueryFn = int (*)(const char*, MocktailPayloadInfoCallback,
                                   void*, char*, size_t);

PayloadIntegrityResult RunPayloadInfoQuery(
    const std::filesystem::path& directory, PayloadInfoQueryFn query_fn,
    const char* fallback_error) {
  PayloadIntegrityResult result;
  char err_buf[512] = {};
  const auto on_info = [](void* ctx,
                          const MocktailRustPayloadInfoView* view) {
    auto* out = static_cast<PayloadIntegrityResult*>(ctx);
    auto assign_slice = [](const MocktailRustStrSlice& s, std::string* dst) {
      if (s.ptr != nullptr && s.len > 0) {
        dst->assign(s.ptr, s.len);
      } else {
        dst->clear();
      }
    };
    assign_slice(view->package_name, &out->metadata.package_name);
    assign_slice(view->version_name, &out->metadata.version_name);
    out->metadata.version_code = view->version_code;
    assign_slice(view->build_id, &out->metadata.build_id);
    assign_slice(view->library_sha256, &out->metadata.library_sha256);
    assign_slice(view->base_apk_sha256, &out->metadata.base_apk_sha256);
    assign_slice(view->split_apk_sha256, &out->metadata.split_apk_sha256);
    out->metadata.asset_file_count = view->asset_file_count;
    assign_slice(view->asset_tree_sha256, &out->metadata.asset_tree_sha256);
    assign_slice(view->payload_id, &out->payload_id);
  };
  if (query_fn(directory.c_str(), on_info, &result, err_buf, sizeof(err_buf)) !=
      0) {
    result.error = err_buf[0] != '\0' ? err_buf : fallback_error;
  }
  return result;
}

}  // namespace

PayloadIntegrityResult InspectPreparedPayload(
    const std::filesystem::path& directory) {
  return RunPayloadInfoQuery(directory, mocktail_rust_payload_inspect_cb,
                             "failed to inspect payload");
}

PayloadIntegrityResult VerifyPreparedPayload(
    const std::filesystem::path& directory) {
  return RunPayloadInfoQuery(directory, mocktail_rust_payload_verify_cb,
                             "failed to verify payload");
}

}  // namespace mocktail::update
