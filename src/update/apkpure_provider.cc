#include "update/apkpure_provider.h"
#include "mocktail/mocktail_rust.h"

#define JSON_NOEXCEPTION 1
#include <nlohmann/json.hpp>
#include <sys/statvfs.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

#include "compat/guest_abi.h"
#include "update/http_download.h"

namespace mocktail::update {
namespace {

constexpr std::size_t kMaximumMetadataBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaximumArchiveBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumExactCandidates = 4;
constexpr std::string_view kApiUrl =
    "https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name="
    "com.roblox.client";

const std::vector<std::string> kMetadataHosts = {"api.pureapk.com"};
const std::vector<std::string> kDownloadHosts = {"pureapk.com", "apkpure.com",
                                                 "winudf.com"};

bool VersionCharacter(unsigned char character) {
  return std::isalnum(character) || character == '.' || character == '+' ||
         character == '_' || character == '-';
}

struct VersionMarker {
  std::size_t begin = 0;
  std::size_t colon = 0;
  std::string value;
};

std::vector<VersionMarker> VersionMarkers(std::string_view metadata) {
  std::vector<VersionMarker> markers;
  for (std::size_t index = 0; index < metadata.size(); ++index) {
    if (!std::isdigit(static_cast<unsigned char>(metadata[index])) ||
        (index > 0 &&
         VersionCharacter(static_cast<unsigned char>(metadata[index - 1])))) {
      continue;
    }
    std::size_t end = index;
    bool dot = false;
    while (end < metadata.size() &&
           VersionCharacter(static_cast<unsigned char>(metadata[end]))) {
      dot = dot || metadata[end] == '.';
      ++end;
    }
    if (dot && end < metadata.size() && metadata[end] == ':') {
      markers.push_back(VersionMarker{
          index, end, std::string(metadata.substr(index, end - index))});
      index = end;
    }
  }
  return markers;
}



HttpBytesResult FetchMetadata(std::string_view architecture) {
  HttpTransferRequest request;
  request.url = std::string(kApiUrl);
  request.headers = {
      "x-cv: 3172501",
      "x-sv: 29",
      "x-gp: 1",
      "x-abis: " + std::string(architecture),
  };
  request.allowed_hosts = kMetadataHosts;
  request.maximum_bytes = kMaximumMetadataBytes;
  request.transfer_timeout_ms = 60000;
  return DownloadBytes(request);
}

bool HasVersion(std::string_view metadata, std::string_view version) {
  const auto markers = VersionMarkers(metadata);
  return std::any_of(markers.begin(), markers.end(), [&](const auto& marker) {
    return marker.value == version;
  });
}

bool ZipMagic(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  char magic[4] = {};
  input.read(magic, sizeof(magic));
  return input.gcount() == 4 && magic[0] == 'P' && magic[1] == 'K' &&
         (magic[2] == 3 || magic[2] == 5 || magic[2] == 7) &&
         (magic[3] == 4 || magic[3] == 6 || magic[3] == 8);
}

}  // namespace

ProviderVersion ParseApkPureLatestMetadata(std::string_view metadata) {
  ProviderVersion result;
  char ver_name[128] = {};
  uint64_t ver_code = 0;
  char err_buf[256] = {};
  int rc = mocktail_rust_apkpure_parse_latest(
      reinterpret_cast<const uint8_t*>(metadata.data()), metadata.size(),
      ver_name, sizeof(ver_name), &ver_code, err_buf, sizeof(err_buf));
  if (rc != 0) {
    result.error = err_buf[0] != '\0' ? err_buf : "failed to parse APKPure latest metadata";
    return result;
  }
  result.version_name = ver_name;
  result.version_code = ver_code;
  return result;
}

std::vector<std::string> ParseApkPureExactDownloadUrls(
    std::string_view metadata, std::string_view version, std::string* error) {
  std::vector<std::string> result;
  std::string ver_str(version);
  std::vector<char> json_buf(8192);
  char err_buf[256] = {};
  int rc = mocktail_rust_apkpure_parse_exact_urls(
      reinterpret_cast<const uint8_t*>(metadata.data()), metadata.size(),
      ver_str.c_str(), json_buf.data(), json_buf.size(), err_buf, sizeof(err_buf));
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0' ? err_buf : "failed to parse APKPure exact download URLs";
    }
    return result;
  }
  const auto parsed = nlohmann::json::parse(json_buf.data(), nullptr, false, true);
  if (!parsed.is_discarded() && parsed.is_array()) {
    for (const auto& item : parsed) {
      if (item.is_string()) {
        result.push_back(item.get<std::string>());
      }
    }
  }
  return result;
}

ProviderVersion ApkPureProvider::CheckLatest() const {
  const HttpBytesResult metadata =
      FetchMetadata(std::string(compat::kGuestAbi));
  if (!metadata) return ProviderVersion{{}, 0, metadata.error};
  return ParseApkPureLatestMetadata(metadata.bytes);
}

ProviderDownloadResult ApkPureProvider::DownloadExact(
    std::string_view version, const std::filesystem::path& output_directory,
    int progress_fd) const {
  ProviderDownloadResult result;
  result.source = std::string(name());
  if (version.empty() || version.size() > 128 ||
      !std::all_of(version.begin(), version.end(), [](unsigned char character) {
        return VersionCharacter(character);
      })) {
    result.error = "invalid APKPure version";
    return result;
  }
  std::error_code filesystem_error;
  std::filesystem::create_directories(output_directory, filesystem_error);
  if (filesystem_error ||
      !std::filesystem::is_empty(output_directory, filesystem_error)) {
    result.error = "APKPure output directory must exist and be empty";
    return result;
  }
  HttpBytesResult metadata = FetchMetadata(std::string(compat::kGuestAbi));
  if (!metadata) {
    result.error = metadata.error;
    return result;
  }
  if (!HasVersion(metadata.bytes, version)) {
    metadata = FetchMetadata("arm64-v8a,armeabi-v7a,armeabi,x86,x86_64");
    if (!metadata) {
      result.error = metadata.error;
      return result;
    }
  }
  std::string parse_error;
  const std::vector<std::string> urls =
      ParseApkPureExactDownloadUrls(metadata.bytes, version, &parse_error);
  if (!parse_error.empty()) {
    result.error = parse_error;
    return result;
  }
  for (std::size_t index = 0; index < urls.size(); ++index) {
    const bool xapk = urls[index].find(".xapk") != std::string::npos;
    const std::filesystem::path destination =
        output_directory /
        ("candidate-" + std::to_string(index + 1) + (xapk ? ".xapk" : ".apk"));
    HttpTransferRequest request;
    request.url = urls[index];
    request.allowed_hosts = kDownloadHosts;
    request.maximum_bytes = kMaximumArchiveBytes;
    // Several hundred MiB over a slow link is not a failed transfer; the
    // quarter-hour cap failed those users outright. Stalls are caught by the
    // low-speed guard instead.
    request.transfer_timeout_ms = 0;
    const HttpDownloadResult downloaded =
        DownloadFile(request, destination, progress_fd);
    if (!downloaded || !ZipMagic(destination)) {
      std::filesystem::remove_all(output_directory, filesystem_error);
      result.error = downloaded ? "APKPure response is not a ZIP archive"
                                : downloaded.error;
      return result;
    }
    result.archives.push_back(destination);
  }
  return result;
}

}  // namespace mocktail::update
