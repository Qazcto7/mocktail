#include "compat/elf_build_id.h"
#include "mocktail/mocktail_rust.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

namespace mocktail::compat {
namespace {

BuildIdResult Failure(std::string error) {
  return BuildIdResult{{}, std::move(error)};
}

}  // namespace

bool IsValidBuildId(std::string_view build_id) noexcept {
  if (build_id.size() < 8 || build_id.size() > 128 ||
      build_id.size() % 2 != 0) {
    return false;
  }
  for (const char character : build_id) {
    const bool digit = character >= '0' && character <= '9';
    const bool lowercase = character >= 'a' && character <= 'f';
    const bool uppercase = character >= 'A' && character <= 'F';
    if (!digit && !lowercase && !uppercase) {
      return false;
    }
  }
  return true;
}

BuildIdResult ReadElfBuildId(const std::string& path) {
  if (path.empty()) {
    return Failure("ELF path is empty");
  }

  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return Failure("open(" + path + "): " + std::strerror(errno));
  }

  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size < 64) {
    close(fd);
    return Failure("invalid ELF file size: " + path);
  }

  void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  if (map == MAP_FAILED) {
    return Failure("mmap failed: " + path);
  }

  char hex_buf[129] = {0};
  const int rc = mocktail_rust_parse_elf_build_id(
      static_cast<const uint8_t*>(map), st.st_size, hex_buf, sizeof(hex_buf));
  munmap(map, st.st_size);

  if (rc == 0 && hex_buf[0] != '\0') {
    return BuildIdResult{std::string(hex_buf), {}};
  }
  return Failure("no GNU build-id note found in " + path);
}

}  // namespace mocktail::compat
