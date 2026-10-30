#include "update/payload_integrity.h"

#define JSON_NOEXCEPTION 1
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
#include <nlohmann/json.hpp>
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

PayloadIntegrityResult InspectPreparedPayload(
    const std::filesystem::path& directory) {
  PayloadIntegrityResult result;
  std::vector<char> json_buf(8192);
  char err_buf[512] = {};
  int rc = mocktail_rust_payload_inspect(
      directory.c_str(), json_buf.data(), json_buf.size(), err_buf, sizeof(err_buf));
  if (rc != 0) {
    result.error = err_buf[0] != '\0' ? err_buf : "failed to inspect payload";
    return result;
  }
  const auto doc = nlohmann::json::parse(json_buf.data(), nullptr, false, true);
  if (doc.is_discarded() || !doc.is_object()) {
    result.error = "invalid payload inspection JSON";
    return result;
  }
  result.metadata.package_name = doc.value("package_name", "");
  result.metadata.version_name = doc.value("version_name", "");
  result.metadata.version_code = doc.value("version_code", 0ULL);
  result.metadata.build_id = doc.value("build_id", "");
  result.metadata.library_sha256 = doc.value("library_sha256", "");
  result.metadata.base_apk_sha256 = doc.value("base_apk_sha256", "");
  result.metadata.split_apk_sha256 = doc.value("split_apk_sha256", "");
  result.metadata.asset_file_count = doc.value("asset_file_count", 0ULL);
  result.metadata.asset_tree_sha256 = doc.value("asset_tree_sha256", "");
  result.payload_id = doc.value("payload_id", "");
  return result;
}

PayloadIntegrityResult VerifyPreparedPayload(
    const std::filesystem::path& directory) {
  PayloadIntegrityResult result;
  std::vector<char> json_buf(8192);
  char err_buf[512] = {};
  int rc = mocktail_rust_payload_verify(
      directory.c_str(), json_buf.data(), json_buf.size(), err_buf, sizeof(err_buf));
  if (rc != 0) {
    result.error = err_buf[0] != '\0' ? err_buf : "failed to verify payload";
    return result;
  }
  const auto doc = nlohmann::json::parse(json_buf.data(), nullptr, false, true);
  if (doc.is_discarded() || !doc.is_object()) {
    result.error = "invalid payload verification JSON";
    return result;
  }
  result.metadata.package_name = doc.value("package_name", "");
  result.metadata.version_name = doc.value("version_name", "");
  result.metadata.version_code = doc.value("version_code", 0ULL);
  result.metadata.build_id = doc.value("build_id", "");
  result.metadata.library_sha256 = doc.value("library_sha256", "");
  result.metadata.base_apk_sha256 = doc.value("base_apk_sha256", "");
  result.metadata.split_apk_sha256 = doc.value("split_apk_sha256", "");
  result.metadata.asset_file_count = doc.value("asset_file_count", 0ULL);
  result.metadata.asset_tree_sha256 = doc.value("asset_tree_sha256", "");
  result.payload_id = doc.value("payload_id", "");
  return result;
}

}  // namespace mocktail::update
