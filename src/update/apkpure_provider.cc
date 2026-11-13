#include "update/apkpure_provider.h"

#include <sys/statvfs.h>

#include <array>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>

#include "compat/guest_abi.h"
#include "mocktail/mocktail_rust.h"
#include "update/http_download.h"

namespace mocktail::update {
namespace {

constexpr std::size_t kMaximumMetadataBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaximumArchiveBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::string_view kApiUrl =
    "https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name="
    "com.roblox.client";

const std::vector<std::string> kMetadataHosts = {"api.pureapk.com"};
const std::vector<std::string> kDownloadHosts = {"pureapk.com", "apkpure.com",
                                                 "winudf.com"};

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
  request.connect_timeout_ms = 5000;
  request.transfer_timeout_ms = 15000;
  request.maximum_attempts = 2;
  return DownloadBytes(request);
}

bool ZipMagic(const std::filesystem::path& path) {
  return mocktail_rust_apkpure_has_zip_magic(path.c_str());
}

}  // namespace

ProviderVersion ParseApkPureLatestMetadata(std::string_view metadata) {
  ProviderVersion result;
  std::array<char, 256> ver_buf{};
  std::array<char, 512> err_buf{};
  std::uint64_t code = 0;
  const int rc = mocktail_rust_apkpure_parse_latest(
      reinterpret_cast<const uint8_t*>(metadata.data()), metadata.size(),
      ver_buf.data(), ver_buf.size(), &code, err_buf.data(), err_buf.size());
  if (rc != 0) {
    result.error = err_buf[0] != '\0'
                       ? std::string(err_buf.data())
                       : "APKPure metadata contains no downloadable version identity";
    return result;
  }
  result.version_name = std::string(ver_buf.data());
  result.version_code = code;
  return result;
}

std::vector<std::string> ParseApkPureExactDownloadUrls(
    std::string_view metadata, std::string_view version, std::string* error,
    std::uint64_t version_code) {
  if (error != nullptr) error->clear();
  std::vector<std::string> result;
  const std::string version_str(version);
  std::string urls_json(8192, '\0');
  std::array<char, 512> err_buf{};
  const int rc = mocktail_rust_apkpure_parse_exact_urls(
      reinterpret_cast<const uint8_t*>(metadata.data()), metadata.size(),
      version_str.c_str(), version_code, urls_json.data(), urls_json.size(),
      err_buf.data(), err_buf.size());
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0'
                   ? std::string(err_buf.data())
                   : "APKPure does not offer the requested exact version";
    }
    return result;
  }
  const auto parsed = nlohmann::json::parse(urls_json.c_str(), nullptr, false);
  if (parsed.is_discarded() || !parsed.is_array()) {
    if (error != nullptr) {
      *error = "APKPure does not offer the requested exact version";
    }
    return result;
  }
  for (const auto& entry : parsed) {
    if (entry.is_string()) {
      result.push_back(entry.get<std::string>());
    }
  }
  if (result.empty() && error != nullptr) {
    *error = "APKPure does not offer the requested exact version";
  }
  return result;
}

ApkPureProvider::ApkPureProvider(MetadataFetcher metadata, Downloader download)
    : metadata_(std::move(metadata)), download_(std::move(download)) {
  if (!metadata_) metadata_ = FetchMetadata;
}

ProviderVersion ApkPureProvider::CheckLatest() const {
  const HttpBytesResult metadata =
      metadata_(compat::kGuestAbi);
  if (!metadata) return ProviderVersion{{}, 0, metadata.error};
  return ParseApkPureLatestMetadata(metadata.bytes);
}

ProviderDownloadResult ApkPureProvider::DownloadExact(
    const ProviderVersion& version,
    const std::filesystem::path& output_directory, int progress_fd) const {
  return DownloadVerified(version, output_directory, progress_fd, {});
}

ProviderDownloadResult ApkPureProvider::DownloadVerified(
    const ProviderVersion& version,
    const std::filesystem::path& output_directory, int progress_fd,
    const ArchiveValidator& validate) const {
  ProviderDownloadResult result;
  result.source = std::string(name());
  if (!version ||
      !mocktail_rust_apkpure_is_valid_version_name(
          version.version_name.data(), version.version_name.size())) {
    result.error = "invalid APKPure version";
    return result;
  }
  std::error_code filesystem_error;
  std::filesystem::create_directories(output_directory, filesystem_error);
  if (filesystem_error ||
      std::filesystem::is_symlink(output_directory, filesystem_error)) {
    result.error = "cannot create APKPure download directory";
    return result;
  }
  HttpBytesResult metadata = metadata_(compat::kGuestAbi);
  if (!metadata) {
    result.error = metadata.error;
    return result;
  }
  std::string parse_error;
  std::vector<std::string> urls = ParseApkPureExactDownloadUrls(
      metadata.bytes, version.version_name, &parse_error, version.version_code);
  if (urls.empty()) {
    metadata = metadata_("arm64-v8a,armeabi-v7a,armeabi,x86,x86_64");
    if (!metadata) {
      result.error = metadata.error;
      return result;
    }
    urls = ParseApkPureExactDownloadUrls(metadata.bytes, version.version_name,
                                         &parse_error, version.version_code);
  }
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
    request.transfer_timeout_ms = 0;
    const auto accept = [&]() {
      result.archives = {destination};
      result.error.clear();
      if (validate) result.error = validate(result);
      if (result) return true;
      result.archives.clear();
      std::filesystem::remove(destination, filesystem_error);
      return false;
    };
    if (ZipMagic(destination) && accept()) return result;
    const auto downloaded = download_(request, destination, progress_fd);
    if (!downloaded || !ZipMagic(destination)) {
      std::filesystem::remove(destination, filesystem_error);
      result.error = downloaded ? "APKPure response is not a ZIP archive"
                                : downloaded.error;
      continue;
    }
    if (accept()) return result;
    std::filesystem::remove(destination, filesystem_error);
  }
  if (result.error.empty()) result.error = "APKPure returned no usable APK";
  return result;
}

}  // namespace mocktail::update
