#include "update/update_config.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <string>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

constexpr std::size_t kMaximumConfigBytes = 1024U * 1024U;

bool ReadFile(const std::filesystem::path& path, std::string* contents,
              bool* loaded, std::string* error) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    if (errno == ENOENT) {
      *loaded = false;
      return true;
    }
    *error = "cannot open update configuration: " + path.string();
    return false;
  }
  struct stat metadata = {};
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_size < 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > kMaximumConfigBytes) {
    close(descriptor);
    *error = "update configuration must be a regular file no larger than 1 MiB";
    return false;
  }
  contents->clear();
  contents->reserve(static_cast<std::size_t>(metadata.st_size));
  std::array<char, 16U * 1024U> buffer{};
  while (true) {
    const ssize_t read_bytes = read(descriptor, buffer.data(), buffer.size());
    if (read_bytes == 0) {
      break;
    }
    if (read_bytes < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(descriptor);
      *error = "cannot read update configuration: " + path.string();
      return false;
    }
    contents->append(buffer.data(), static_cast<std::size_t>(read_bytes));
  }
  close(descriptor);
  *loaded = true;
  return true;
}

}  // namespace

UpdateConfigResult LoadUpdateConfig(const std::filesystem::path& path) {
  UpdateConfigResult result;
  std::string contents;
  if (!ReadFile(path, &contents, &result.file_loaded, &result.error) ||
      !result.file_loaded) {
    return result;
  }

  int32_t auto_val = 1;
  int32_t launch_val = 1;
  char source_buf[64]{};
  char err_buf[256]{};
  if (mocktail_rust_parse_update_config_yaml(
          contents.data(), contents.size(), &auto_val, &launch_val,
          source_buf, sizeof(source_buf), err_buf, sizeof(err_buf)) != 0) {
    result.error =
        err_buf[0] != '\0' ? err_buf : "cannot parse update configuration";
    return result;
  }
  result.config.automatic = auto_val != 0;
  result.config.launch_after_update = launch_val != 0;
  result.config.source = source_buf;
  if (contents.find("testing_latest_only") != std::string::npos) {
    result.warnings.emplace_back(
        "updates.testing_latest_only is no longer supported and is ignored");
  }
  return result;
}

}  // namespace mocktail::update
