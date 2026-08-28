#include "legacy/rbxm_diagnostics.h"

#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <new>

#include "legacy/memory_inspection.h"

namespace mocktail::legacy::internal {

void ReadRbxmInstanceNameSlotPreview(uintptr_t object, char* out,
                                     size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (object == 0) {
    std::snprintf(out, out_size, "name_slot{object=null}");
    return;
  }

  const uintptr_t name_slot = ReadPointerIfReadable(object + 0xb0);
  char name_preview[160];
  char memory_preview[180];
  ReadLibcxxStringPreview(name_slot, name_preview, sizeof(name_preview));
  ReadMemoryHexPreview(name_slot, memory_preview, sizeof(memory_preview));
  std::snprintf(
      out, out_size, "name_slot{object=%p slot=%p value=\"%s\" preview=\"%s\"}",
      reinterpret_cast<void*>(object), reinterpret_cast<void*>(name_slot),
      name_preview, memory_preview);
}

void ReadRbxmInstanceStringFieldCandidatesPreview(uintptr_t object, char* out,
                                                  size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (object == 0) {
    std::snprintf(out, out_size, "string_fields{object=null}");
    return;
  }

  size_t pos = static_cast<size_t>(
      std::snprintf(out, out_size, "string_fields{object=%p",
                    reinterpret_cast<void*>(object)));
  if (pos >= out_size) {
    out[out_size - 1] = '\0';
    return;
  }

  size_t emitted = 0;
  for (uintptr_t offset = 0; offset <= 0x180 && emitted < 12;
       offset += sizeof(uintptr_t)) {
    char inline_preview[80];
    ReadLibcxxStringPreview(object + offset, inline_preview,
                            sizeof(inline_preview));
    if (inline_preview[0] != '\0') {
      const int written =
          std::snprintf(out + pos, out_size - pos, " inline+0x%lx=\"%s\"",
                        static_cast<unsigned long>(offset), inline_preview);
      if (written <= 0 || static_cast<size_t>(written) >= out_size - pos) {
        out[out_size - 1] = '\0';
        return;
      }
      pos += static_cast<size_t>(written);
      ++emitted;
    }

    const uintptr_t pointer = ReadPointerIfReadable(object + offset);
    char pointer_preview[80];
    ReadLibcxxStringPreview(pointer, pointer_preview, sizeof(pointer_preview));
    if (pointer_preview[0] != '\0' && emitted < 12) {
      const int written =
          std::snprintf(out + pos, out_size - pos, " ptr+0x%lx=%p:\"%s\"",
                        static_cast<unsigned long>(offset),
                        reinterpret_cast<void*>(pointer), pointer_preview);
      if (written <= 0 || static_cast<size_t>(written) >= out_size - pos) {
        out[out_size - 1] = '\0';
        return;
      }
      pos += static_cast<size_t>(written);
      ++emitted;
    }
  }

  if (pos + 2 < out_size) {
    out[pos++] = '}';
    out[pos] = '\0';
  } else {
    out[out_size - 1] = '\0';
  }
}

uintptr_t AllocateLibcxxStringCopy(const char* chars, size_t length) {
  if (chars == nullptr || length == 0 || length >= 4096) {
    return 0;
  }

  auto* storage = static_cast<unsigned char*>(::operator new(24, std::nothrow));
  if (storage == nullptr) {
    return 0;
  }
  std::memset(storage, 0, 24);

  if (length < 23) {
    storage[0] = static_cast<unsigned char>(length << 1);
    std::memcpy(storage + 1, chars, length);
    return reinterpret_cast<uintptr_t>(storage);
  }

  auto* data = static_cast<char*>(::operator new(length + 1, std::nothrow));
  if (data == nullptr) {
    ::operator delete(storage, std::nothrow);
    return 0;
  }
  std::memcpy(data, chars, length);
  data[length] = '\0';

  auto* words = reinterpret_cast<uintptr_t*>(storage);
  words[0] =
      ((static_cast<uintptr_t>(length) + 16u) & ~static_cast<uintptr_t>(15u)) |
      1u;
  words[1] = static_cast<uintptr_t>(length);
  words[2] = reinterpret_cast<uintptr_t>(data);
  return reinterpret_cast<uintptr_t>(storage);
}

bool RepairStage6RbxmInstanceNameSlotFromValue(uintptr_t object,
                                               uintptr_t value_variant,
                                               const char* reason) {
  if (object == 0) {
    return false;
  }

  const uintptr_t slot_address = object + 0xb0;
  if (!IsReadableMemoryRange(slot_address, sizeof(uintptr_t))) {
    return false;
  }
  const uintptr_t current_slot = ReadPointerIfReadable(slot_address);
  if (current_slot != 0) {
    return false;
  }

  const char* chars = nullptr;
  size_t length = 0;
  if (!ReadLibcxxStringView(value_variant, &chars, &length)) {
    return false;
  }

  const uintptr_t name_copy = AllocateLibcxxStringCopy(chars, length);
  if (name_copy == 0 ||
      !EnsureWritablePage(reinterpret_cast<void*>(slot_address))) {
    return false;
  }

  *reinterpret_cast<uintptr_t*>(slot_address) = name_copy;

  static volatile sig_atomic_t name_slot_repair_logs = 0;
  if (name_slot_repair_logs < 48) {
    char value_preview[180];
    ReadLibcxxStringPreview(name_copy, value_preview, sizeof(value_preview));
    char msg[600];
    int len = std::snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 RBXM Name slot apply repair "
        "name-slot-apply-repair reason=%s object=%p slot=%p name_ptr=%p "
        "name_len=%llu name=\"%s\"\n",
        reason != nullptr ? reason : "", reinterpret_cast<void*>(object),
        reinterpret_cast<void*>(slot_address),
        reinterpret_cast<void*>(name_copy),
        static_cast<unsigned long long>(length), value_preview);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++name_slot_repair_logs;
  }
  return true;
}

void ReadRbxmValueContextStringVectorPreview(uintptr_t value_context, char* out,
                                             size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (!IsReadableMemoryRange(value_context, sizeof(uintptr_t) * 3)) {
    std::snprintf(out, out_size, "value_context_strings{context=%p unreadable}",
                  reinterpret_cast<void*>(value_context));
    return;
  }

  const uintptr_t begin = ReadPointerIfReadable(value_context + 0x00);
  const uintptr_t end = ReadPointerIfReadable(value_context + 0x08);
  const uintptr_t cap = ReadPointerIfReadable(value_context + 0x10);
  const uintptr_t byte_count = end >= begin ? end - begin : 0;
  const bool aligned24 = begin != 0 && end >= begin && byte_count % 24 == 0;
  const bool aligned8 = begin != 0 && end >= begin && byte_count % 8 == 0;
  const unsigned long long count24 =
      aligned24 ? static_cast<unsigned long long>(byte_count / 24) : 0;
  const unsigned long long count8 =
      aligned8 ? static_cast<unsigned long long>(byte_count / 8) : 0;

  size_t pos = 0;
  int written = std::snprintf(
      out, out_size,
      "value_context_strings{context=%p begin=%p end=%p cap=%p "
      "bytes=0x%lx count24=%llu count8=%llu inline24[",
      reinterpret_cast<void*>(value_context), reinterpret_cast<void*>(begin),
      reinterpret_cast<void*>(end), reinterpret_cast<void*>(cap),
      static_cast<unsigned long>(byte_count), count24, count8);
  if (written <= 0) {
    return;
  }
  pos = std::min(static_cast<size_t>(written), out_size - 1);

  if (aligned24) {
    const unsigned long long sample_count = std::min(count24, 4ULL);
    for (unsigned long long i = 0; i < sample_count && pos < out_size - 1;
         ++i) {
      char string_preview[120];
      ReadLibcxxStringPreview(begin + static_cast<uintptr_t>(i) * 24,
                              string_preview, sizeof(string_preview));
      written = std::snprintf(out + pos, out_size - pos, "%s%llu=\"%s\"",
                              i == 0 ? "" : " ", i, string_preview);
      if (written <= 0) {
        break;
      }
      pos = std::min(pos + static_cast<size_t>(written), out_size - 1);
    }
  }

  if (pos < out_size - 1) {
    written = std::snprintf(out + pos, out_size - pos, "] ptr8[");
    if (written > 0) {
      pos = std::min(pos + static_cast<size_t>(written), out_size - 1);
    }
  }

  if (aligned8) {
    const unsigned long long sample_count = std::min(count8, 4ULL);
    for (unsigned long long i = 0; i < sample_count && pos < out_size - 1;
         ++i) {
      const uintptr_t pointer =
          ReadPointerIfReadable(begin + static_cast<uintptr_t>(i) * 8);
      char string_preview[120];
      ReadLibcxxStringPreview(pointer, string_preview, sizeof(string_preview));
      written = std::snprintf(out + pos, out_size - pos, "%s%llu=%p:\"%s\"",
                              i == 0 ? "" : " ", i,
                              reinterpret_cast<void*>(pointer), string_preview);
      if (written <= 0) {
        break;
      }
      pos = std::min(pos + static_cast<size_t>(written), out_size - 1);
    }
  }

  if (pos < out_size - 1) {
    std::snprintf(out + pos, out_size - pos, "]}");
  } else {
    out[out_size - 1] = '\0';
  }
}

}  // namespace mocktail::legacy::internal
