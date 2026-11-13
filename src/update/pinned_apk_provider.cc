#include "update/pinned_apk_provider.h"

#include <utility>

#include "compat/guest_abi.h"
#include "mocktail/mocktail_rust.h"
#include "update/payload_integrity.h"

namespace mocktail::update {
namespace {

constexpr std::size_t kMaximumArchiveBytes = 1024ULL * 1024ULL * 1024ULL;
const std::vector<std::string> kDownloadHosts = {
    "github.com", "release-assets.githubusercontent.com",
    "objects.githubusercontent.com"};

bool MatchesArchive(const std::filesystem::path& path,
                    const PinnedApkArchive& archive) {
  std::error_code error;
  return std::filesystem::is_regular_file(
             std::filesystem::symlink_status(path, error)) &&
         std::filesystem::file_size(path, error) == archive.size && !error &&
         HashRegularFile(path) == archive.sha256;
}

}  // namespace

PinnedApkSource LoadPinnedApkSource(const std::filesystem::path& manifest,
                                   const ProviderVersion& version,
                                   std::string_view abi) {
  PinnedApkSource result;
  if (!version) {
    result.error = "invalid pinned APK version";
    return result;
  }
  const std::string abi_str(abi);
  char err_buf[512] = {};
  const auto is_trusted = [](void*, const char* url_ptr, size_t url_len) -> bool {
    if (url_ptr == nullptr) return false;
    return IsTrustedHttpsUrl(std::string_view(url_ptr, url_len),
                             kDownloadHosts);
  };
  const auto on_build_id = [](void* ctx, const char* ptr, size_t len) {
    auto* out = static_cast<PinnedApkSource*>(ctx);
    if (ptr != nullptr && len > 0) out->build_id.assign(ptr, len);
  };
  const auto on_archive = [](void* ctx, const char* filename_ptr,
                             size_t filename_len, const char* url_ptr,
                             size_t url_len, const char* sha_ptr,
                             size_t sha_len, uint64_t size) {
    auto* out = static_cast<PinnedApkSource*>(ctx);
    PinnedApkArchive archive;
    if (filename_ptr != nullptr && filename_len > 0) {
      archive.filename.assign(filename_ptr, filename_len);
    }
    if (url_ptr != nullptr && url_len > 0) {
      archive.url.assign(url_ptr, url_len);
    }
    if (sha_ptr != nullptr && sha_len > 0) {
      archive.sha256.assign(sha_ptr, sha_len);
    }
    archive.size = size;
    out->archives.push_back(std::move(archive));
  };
  if (mocktail_rust_pinned_apk_find_source(
          manifest.c_str(), version.version_name.c_str(), version.version_code,
          abi_str.c_str(), kMaximumArchiveBytes, is_trusted, on_build_id,
          on_archive, &result, err_buf, sizeof(err_buf)) != 0) {
    result.build_id.clear();
    result.archives.clear();
    result.error = err_buf[0] != '\0'
                       ? err_buf
                       : "pinned APK source manifest is unavailable or invalid";
  }
  return result;
}

PinnedApkProvider::PinnedApkProvider(std::filesystem::path manifest,
                                     Downloader download)
    : manifest_(std::move(manifest)), download_(std::move(download)) {}

ProviderVersion PinnedApkProvider::CheckLatest() const {
  return {{}, 0, "pinned APK sources do not provide version discovery"};
}

ProviderDownloadResult PinnedApkProvider::DownloadExact(
    const ProviderVersion& version, const std::filesystem::path& directory,
    int progress_fd) const {
  ProviderDownloadResult result;
  result.source = name();
  const auto source = LoadPinnedApkSource(manifest_, version, compat::kGuestAbi);
  if (!source) {
    result.error = source.error;
    return result;
  }
  for (const auto& archive : source.archives) {
    const auto destination = directory / archive.filename;
    if (!MatchesArchive(destination, archive)) {
      std::error_code error;
      std::filesystem::remove(destination, error);
      if (error) {
        result.error = "cannot replace cached APK: " + error.message();
        return result;
      }
      HttpTransferRequest request;
      request.url = archive.url;
      request.allowed_hosts = kDownloadHosts;
      request.maximum_bytes = archive.size;
      request.transfer_timeout_ms = 0;
      const auto downloaded = download_(request, destination, progress_fd);
      if (!downloaded) {
        result.error = downloaded.error;
        return result;
      }
      if (!MatchesArchive(destination, archive)) {
        std::filesystem::remove(destination, error);
        result.error = archive.filename +
                       " does not match the pinned SHA-256 or size";
        return result;
      }
    }
    result.archives.push_back(destination);
  }
  return result;
}

}  // namespace mocktail::update
