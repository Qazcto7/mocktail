#include "update/zip_archive.h"
#include "mocktail/mocktail_rust.h"

#define JSON_NOEXCEPTION 1
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <filesystem>

namespace mocktail::update {

bool IsSafeArchivePath(std::string_view path) {
  if (path.empty() || path.find('\0') != path.npos) {
    return false;
  }
  std::string null_terminated(path);
  return mocktail_rust_is_safe_archive_path(null_terminated.c_str()) == 1;
}

ZipListResult ListZipEntries(const std::filesystem::path& archive,
                             std::size_t maximum_entries) {
  ZipListResult result;
  std::size_t cap = 2 * 1024 * 1024;
  std::vector<char> json_buf(cap);
  char err_buf[512] = {};
  int rc = mocktail_rust_zip_list_entries(
      archive.c_str(), maximum_entries, json_buf.data(), json_buf.size(),
      err_buf, sizeof(err_buf));
  if (rc == -9) {
    cap = 16 * 1024 * 1024;
    json_buf.resize(cap);
    rc = mocktail_rust_zip_list_entries(
        archive.c_str(), maximum_entries, json_buf.data(), json_buf.size(),
        err_buf, sizeof(err_buf));
  }
  if (rc != 0) {
    result.error = err_buf[0] != '\0' ? err_buf : "failed to list zip entries";
    return result;
  }
  const auto parsed = nlohmann::json::parse(json_buf.data(), nullptr, false, true);
  if (parsed.is_discarded() || !parsed.is_array()) {
    result.error = "invalid zip entries metadata JSON";
    return result;
  }
  result.entries.reserve(parsed.size());
  for (const auto& item : parsed) {
    ZipEntry entry;
    entry.name = item.value("name", "");
    entry.uncompressed_size = item.value("uncompressed_size", 0ULL);
    entry.directory = item.value("directory", false);
    entry.symbolic_link = item.value("symbolic_link", false);
    result.entries.push_back(std::move(entry));
  }
  return result;
}

ZipReadResult ReadZipEntry(const std::filesystem::path& archive,
                           std::string_view entry, std::size_t maximum_bytes) {
  ZipReadResult result;
  std::string entry_str(entry);
  result.bytes.resize(maximum_bytes);
  std::size_t read_len = 0;
  char err_buf[512] = {};
  const int rc = mocktail_rust_zip_read_entry(
      archive.c_str(), entry_str.c_str(), maximum_bytes,
      reinterpret_cast<uint8_t*>(result.bytes.data()), result.bytes.size(),
      &read_len, err_buf, sizeof(err_buf));
  if (rc != 0) {
    result.bytes.clear();
    result.error = err_buf[0] != '\0' ? err_buf : "failed to read zip entry";
    return result;
  }
  result.bytes.resize(read_len);
  return result;
}

bool ExtractZipEntry(const std::filesystem::path& archive,
                     std::string_view entry,
                     const std::filesystem::path& destination,
                     std::size_t maximum_bytes, std::string* error) {
  std::string entry_str(entry);
  char err_buf[512] = {};
  const int rc = mocktail_rust_zip_extract_entry(
      archive.c_str(), entry_str.c_str(), destination.c_str(), maximum_bytes,
      err_buf, sizeof(err_buf));
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0' ? err_buf : "failed to extract zip entry";
    }
    return false;
  }
  return true;
}

bool ExtractZipPrefix(const std::filesystem::path& archive,
                      std::string_view prefix,
                      const std::filesystem::path& destination,
                      std::size_t maximum_total_bytes,
                      std::size_t* extracted_files, std::string* error) {
  std::string prefix_str(prefix);
  std::size_t count = 0;
  char err_buf[512] = {};
  const int rc = mocktail_rust_zip_extract_prefix(
      archive.c_str(), prefix_str.c_str(), destination.c_str(),
      maximum_total_bytes, &count, err_buf, sizeof(err_buf));
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0' ? err_buf : "failed to extract zip prefix";
    }
    return false;
  }
  if (extracted_files != nullptr) {
    *extracted_files = count;
  }
  return true;
}

}  // namespace mocktail::update
