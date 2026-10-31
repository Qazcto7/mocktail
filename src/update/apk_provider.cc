#include "update/apk_provider.h"

#include <string>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

void AppendFailure(std::string* aggregate, std::string_view provider,
                   std::string_view failure) {
  if (aggregate == nullptr) return;
  const std::string prov_str(provider);
  const std::string fail_str(failure);
  char out_buf[4096];
  size_t out_len = 0;
  if (mocktail_rust_apk_provider_append_failure(
          aggregate->c_str(), prov_str.c_str(), fail_str.c_str(),
          out_buf, sizeof(out_buf), &out_len) == 0) {
    *aggregate = std::string(out_buf, out_len);
  } else {
    if (!aggregate->empty()) aggregate->append("; ");
    aggregate->append(provider);
    aggregate->append(": ");
    aggregate->append(failure);
  }
}

}  // namespace

void ProviderChain::Add(std::unique_ptr<ApkProvider> provider) {
  if (provider != nullptr) providers_.push_back(std::move(provider));
}

ProviderVersion ProviderChain::CheckLatest() const {
  ProviderVersion result;
  if (providers_.empty()) {
    result.error = "no APK provider is configured";
    return result;
  }
  std::string failures;
  for (const std::unique_ptr<ApkProvider>& provider : providers_) {
    const ProviderVersion version = provider->CheckLatest();
    if (version) return version;
    AppendFailure(&failures, provider->name(), version.error);
  }
  result.error = std::move(failures);
  return result;
}

ProviderDownloadResult ProviderChain::DownloadExact(
    std::string_view version, const std::filesystem::path& output_directory,
    int progress_fd) const {
  ProviderDownloadResult result;
  if (providers_.empty()) {
    result.error = "no APK provider is configured";
    return result;
  }
  std::string failures;
  for (const std::unique_ptr<ApkProvider>& provider : providers_) {
    // Each provider gets its own directory: providers refuse to write into a
    // directory another one already populated, and a failed attempt must not
    // poison the next.
    ProviderDownloadResult downloaded = provider->DownloadExact(
        version, output_directory / provider->name(), progress_fd);
    if (downloaded) return downloaded;
    AppendFailure(&failures, provider->name(), downloaded.error);
  }
  result.error = std::move(failures);
  return result;
}

}  // namespace mocktail::update
