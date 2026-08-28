#include "legacy/memory_inspection.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace mocktail::legacy::internal {

bool IsReadableMemoryRange(std::uintptr_t address, std::size_t size) {
  if (address == 0 || size == 0 || address + size < address) {
    return false;
  }

  const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }

  char buffer[262144];
  ssize_t bytes = 0;
  while (static_cast<std::size_t>(bytes) < sizeof(buffer) - 1) {
    const ssize_t chunk = read(fd, buffer + bytes, sizeof(buffer) - 1 - bytes);
    if (chunk < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return false;
    }
    if (chunk == 0) {
      break;
    }
    bytes += chunk;
  }
  close(fd);
  if (bytes <= 0) {
    return false;
  }
  buffer[bytes] = '\0';

  const char* line = buffer;
  while (*line != '\0') {
    const char* line_end = std::strchr(line, '\n');
    if (line_end == nullptr) {
      line_end = buffer + bytes;
    }

    const char* dash = static_cast<const char*>(
        std::memchr(line, '-', static_cast<std::size_t>(line_end - line)));
    const char* space = static_cast<const char*>(
        std::memchr(line, ' ', static_cast<std::size_t>(line_end - line)));
    if (dash == nullptr || space == nullptr || space + 1 >= line_end ||
        space[1] != 'r') {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    char* endptr = nullptr;
    const std::uintptr_t start =
        static_cast<std::uintptr_t>(std::strtoull(line, &endptr, 16));
    if (endptr == nullptr || endptr != dash) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    endptr = nullptr;
    const std::uintptr_t end =
        static_cast<std::uintptr_t>(std::strtoull(dash + 1, &endptr, 16));
    if (endptr == nullptr || endptr != space || end <= start) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    if (address >= start && address + size <= end) {
      return true;
    }

    line = (*line_end == '\n') ? line_end + 1 : line_end;
  }
  return false;
}

bool IsExecutableMemoryRange(std::uintptr_t address, std::size_t size) {
  if (address == 0 || size == 0 || address + size < address) {
    return false;
  }

  const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }

  char buffer[262144];
  ssize_t bytes = 0;
  while (static_cast<std::size_t>(bytes) < sizeof(buffer) - 1) {
    const ssize_t chunk = read(fd, buffer + bytes, sizeof(buffer) - 1 - bytes);
    if (chunk < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return false;
    }
    if (chunk == 0) {
      break;
    }
    bytes += chunk;
  }
  close(fd);
  if (bytes <= 0) {
    return false;
  }
  buffer[bytes] = '\0';

  const char* line = buffer;
  while (*line != '\0') {
    const char* line_end = std::strchr(line, '\n');
    if (line_end == nullptr) {
      line_end = buffer + bytes;
    }

    const char* dash = static_cast<const char*>(
        std::memchr(line, '-', static_cast<std::size_t>(line_end - line)));
    const char* space = static_cast<const char*>(
        std::memchr(line, ' ', static_cast<std::size_t>(line_end - line)));
    if (dash == nullptr || space == nullptr || space + 3 >= line_end ||
        space[3] != 'x') {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    char* endptr = nullptr;
    const std::uintptr_t start =
        static_cast<std::uintptr_t>(std::strtoull(line, &endptr, 16));
    if (endptr == nullptr || endptr != dash) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    endptr = nullptr;
    const std::uintptr_t end =
        static_cast<std::uintptr_t>(std::strtoull(dash + 1, &endptr, 16));
    if (endptr == nullptr || endptr != space || end <= start) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    if (address >= start && address + size <= end) {
      return true;
    }

    line = (*line_end == '\n') ? line_end + 1 : line_end;
  }
  return false;
}

bool EnsureWritablePage(void* address) {
  const long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0 || address == nullptr) {
    return false;
  }
  const std::uintptr_t raw_address = reinterpret_cast<std::uintptr_t>(address);
  const std::uintptr_t page =
      raw_address & ~(static_cast<std::uintptr_t>(page_size) - 1);
  return mprotect(reinterpret_cast<void*>(page),
                  static_cast<std::size_t>(page_size),
                  PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

std::uintptr_t ReadPointerIfReadable(std::uintptr_t address) {
  if (!IsReadableMemoryRange(address, sizeof(std::uintptr_t))) {
    return 0;
  }
  return *reinterpret_cast<const std::uintptr_t*>(address);
}

std::uint32_t ReadU32IfReadable(std::uintptr_t address) {
  if (!IsReadableMemoryRange(address, sizeof(std::uint32_t))) {
    return 0;
  }
  return *reinterpret_cast<const std::uint32_t*>(address);
}

unsigned long long ReadVectorElementCountIfReadable(
    std::uintptr_t vector_address, std::uintptr_t element_size) {
  if (element_size == 0 ||
      !IsReadableMemoryRange(vector_address, sizeof(std::uintptr_t) * 2)) {
    return 0;
  }
  const std::uintptr_t begin = ReadPointerIfReadable(vector_address);
  const std::uintptr_t end =
      ReadPointerIfReadable(vector_address + sizeof(std::uintptr_t));
  if (begin == 0 || end < begin) {
    return 0;
  }
  return static_cast<unsigned long long>((end - begin) / element_size);
}

void ReadLibcxxStringPreview(std::uintptr_t address, char* out,
                             std::size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (!IsReadableMemoryRange(address, 24)) {
    return;
  }

  unsigned char data[24];
  std::memcpy(data, reinterpret_cast<const void*>(address), sizeof(data));
  const bool is_long = (data[0] & 1u) != 0;
  std::size_t length = 0;
  std::uintptr_t chars = 0;
  if (is_long) {
    const auto* words = reinterpret_cast<const std::uintptr_t*>(data);
    length = static_cast<std::size_t>(words[1]);
    chars = words[2];
  } else {
    length = data[0] >> 1;
    chars = address + 1;
  }
  if (length == 0 || length >= 4096 || chars == 0 ||
      !IsReadableMemoryRange(chars, length)) {
    return;
  }

  const std::size_t copy_length = std::min(length, out_size - 1);
  std::memcpy(out, reinterpret_cast<const void*>(chars), copy_length);
  for (std::size_t i = 0; i < copy_length; ++i) {
    const unsigned char character = static_cast<unsigned char>(out[i]);
    if (character < 0x20 || character > 0x7e) {
      out[i] = '.';
    }
  }
  out[copy_length] = '\0';
}

bool ReadLibcxxStringView(std::uintptr_t address, const char** chars_out,
                          std::size_t* length_out) {
  if (chars_out == nullptr || length_out == nullptr) {
    return false;
  }
  *chars_out = nullptr;
  *length_out = 0;
  if (!IsReadableMemoryRange(address, 24)) {
    return false;
  }

  unsigned char data[24];
  std::memcpy(data, reinterpret_cast<const void*>(address), sizeof(data));
  const bool is_long = (data[0] & 1u) != 0;
  std::size_t length = 0;
  std::uintptr_t chars = 0;
  if (is_long) {
    const auto* words = reinterpret_cast<const std::uintptr_t*>(data);
    length = static_cast<std::size_t>(words[1]);
    chars = words[2];
  } else {
    length = data[0] >> 1;
    chars = address + 1;
  }
  if (length == 0 || length >= 4096 || chars == 0 ||
      !IsReadableMemoryRange(chars, length)) {
    return false;
  }

  *chars_out = reinterpret_cast<const char*>(chars);
  *length_out = length;
  return true;
}

void ReadMemoryHexPreview(std::uintptr_t address, char* out,
                          std::size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (address == 0) {
    std::snprintf(out, out_size, "null");
    return;
  }

  constexpr std::size_t kMaxPreviewBytes = 24;
  unsigned char bytes[kMaxPreviewBytes];
  std::size_t byte_count = 0;
  while (byte_count < kMaxPreviewBytes &&
         IsReadableMemoryRange(address + byte_count, 1)) {
    bytes[byte_count] =
        *reinterpret_cast<const unsigned char*>(address + byte_count);
    ++byte_count;
  }
  if (byte_count == 0) {
    std::snprintf(out, out_size, "unreadable");
    return;
  }

  char hex[kMaxPreviewBytes * 3 + 1];
  char ascii[kMaxPreviewBytes + 1];
  std::size_t hex_pos = 0;
  for (std::size_t i = 0; i < byte_count && hex_pos < sizeof(hex); ++i) {
    const int written =
        std::snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x%s", bytes[i],
                      i + 1 == byte_count ? "" : " ");
    if (written <= 0) {
      break;
    }
    hex_pos += static_cast<std::size_t>(written);
    ascii[i] = bytes[i] >= 0x20 && bytes[i] <= 0x7e
                   ? static_cast<char>(bytes[i])
                   : '.';
  }
  hex[std::min(hex_pos, sizeof(hex) - 1)] = '\0';
  ascii[byte_count] = '\0';
  std::snprintf(out, out_size, "%s |%s|", hex, ascii);
}

void ReadRawStringPreview(std::uintptr_t address, std::size_t length, char* out,
                          std::size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (address == 0 || length == 0) {
    return;
  }

  const std::size_t copy_length = std::min(length, out_size - 1);
  if (!IsReadableMemoryRange(address, copy_length)) {
    std::snprintf(out, out_size, "unreadable");
    return;
  }

  const auto* bytes = reinterpret_cast<const unsigned char*>(address);
  for (std::size_t i = 0; i < copy_length; ++i) {
    out[i] = std::isprint(bytes[i]) ? static_cast<char>(bytes[i]) : '.';
  }
  out[copy_length] = '\0';
}

void ReadCStringPreview(std::uintptr_t address, char* out,
                        std::size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (address == 0) {
    return;
  }

  std::size_t length = 0;
  while (length + 1 < out_size && IsReadableMemoryRange(address + length, 1)) {
    const unsigned char byte =
        *reinterpret_cast<const unsigned char*>(address + length);
    if (byte == '\0') {
      break;
    }
    out[length] = std::isprint(byte) ? static_cast<char>(byte) : '.';
    ++length;
  }
  out[length] = '\0';
  if (length == 0 && !IsReadableMemoryRange(address, 1)) {
    std::snprintf(out, out_size, "unreadable");
  }
}

}  // namespace mocktail::legacy::internal
