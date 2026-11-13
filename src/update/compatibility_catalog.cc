#include "update/compatibility_catalog.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <string>
#include <string_view>

#include "compat/guest_abi.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

constexpr std::size_t kMaximumManifestBytes = 4U * 1024U * 1024U;

bool ReadManifest(const std::filesystem::path& path, std::string* contents,
                  std::string* error) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    *error = "compatibility manifest is unavailable: " + path.string();
    return false;
  }
  struct stat metadata = {};
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_size < 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > kMaximumManifestBytes) {
    close(descriptor);
    *error = "compatibility manifest is not a bounded regular file";
    return false;
  }
  contents->clear();
  std::array<char, 16U * 1024U> buffer{};
  while (true) {
    const ssize_t bytes = read(descriptor, buffer.data(), buffer.size());
    if (bytes == 0) break;
    if (bytes < 0) {
      if (errno == EINTR) continue;
      close(descriptor);
      *error = "cannot read compatibility manifest";
      return false;
    }
    contents->append(buffer.data(), static_cast<std::size_t>(bytes));
  }
  close(descriptor);
  return true;
}

}  // namespace

CompatibilityCatalogResult LoadCompatibilityCatalog(
    const std::filesystem::path& path) {
  CompatibilityCatalogResult result;
  std::string contents;
  if (!ReadManifest(path, &contents, &result.error)) {
    return result;
  }
  std::vector<MocktailRustPayloadProfile> rust_profiles(64);
  std::size_t count = 0;
  std::array<char, 256> error_buf{};

  int rc = mocktail_rust_parse_compatibility_catalog(
      reinterpret_cast<const uint8_t*>(contents.data()),
      contents.size(),
      compat::kGuestAbi.data(),
      rust_profiles.data(),
      rust_profiles.size(),
      &count,
      error_buf.data(),
      error_buf.size());

  if (rc == 0 && count > rust_profiles.size()) {
    rust_profiles.resize(count);
    rc = mocktail_rust_parse_compatibility_catalog(
        reinterpret_cast<const uint8_t*>(contents.data()),
        contents.size(),
        compat::kGuestAbi.data(),
        rust_profiles.data(),
        rust_profiles.size(),
        &count,
        error_buf.data(),
        error_buf.size());
  }

  if (rc != 0) {
    result.error = error_buf[0] != '\0' ? error_buf.data()
                                        : "cannot parse compatibility catalog";
    return result;
  }

  for (std::size_t i = 0; i < count; ++i) {
    SupportedPayloadProfile supported;
    supported.version_name = rust_profiles[i].version_name;
    supported.version_code = rust_profiles[i].version_code;
    supported.elf_build_id = rust_profiles[i].elf_build_id;
    result.profiles.push_back(std::move(supported));
  }
  return result;
}

std::optional<SupportedPayloadProfile> PreferredSupportedProfile(
    const std::vector<SupportedPayloadProfile>& profiles) {
  if (profiles.empty()) return std::nullopt;
  return *std::max_element(profiles.begin(), profiles.end(),
                           [](const auto& left, const auto& right) {
                             return left.version_code < right.version_code;
                           });
}

std::optional<SupportedPayloadProfile> FindSupportedProfile(
    const std::vector<SupportedPayloadProfile>& profiles,
    std::string_view version_name, std::uint64_t version_code) {
  const auto found =
      std::find_if(profiles.begin(), profiles.end(), [&](const auto& profile) {
        return profile.version_name == version_name &&
               (version_code == 0 || profile.version_code == version_code);
      });
  return found == profiles.end()
             ? std::nullopt
             : std::optional<SupportedPayloadProfile>(*found);
}

}  // namespace mocktail::update
