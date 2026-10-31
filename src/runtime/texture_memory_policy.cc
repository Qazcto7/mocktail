#include "runtime/texture_memory_policy.h"
#include "mocktail/mocktail_rust.h"

#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace mocktail {
namespace runtime {

std::uint64_t DetectHostMemoryBytes() {
  std::ifstream input("/proc/meminfo");
  std::string key;
  while (input >> key) {
    if (key != "MemTotal:") {
      input.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      continue;
    }
    std::uint64_t kibibytes = 0;
    if (!(input >> kibibytes)) {
      break;
    }
    if (kibibytes > std::numeric_limits<std::uint64_t>::max() / 1024U) {
      break;
    }
    return kibibytes * 1024U;
  }
  return 0;
}

std::uint64_t CalculateTextureMemoryBudgetBytes(
    std::uint64_t host_memory_bytes) {
  return mocktail_rust_texture_memory_calculate_budget(host_memory_bytes);
}

bool MergeTextureMemoryClientSettingsOverrides(std::uint64_t budget_bytes,
                                               std::string_view base_json,
                                               std::string* merged_json,
                                               std::string* error) {
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "texture memory client-settings output is required";
    }
    return false;
  }
  std::vector<char> out_buf(base_json.size() + 512);
  std::vector<char> err_buf(256, '\0');
  size_t out_len = 0;
  int32_t rc = mocktail_rust_texture_memory_merge_overrides(
      budget_bytes, base_json.data(), base_json.size(), out_buf.data(),
      out_buf.size(), &out_len, err_buf.data(), err_buf.size());
  if (rc == -5) {
    out_buf.resize(out_len + 128);
    rc = mocktail_rust_texture_memory_merge_overrides(
        budget_bytes, base_json.data(), base_json.size(), out_buf.data(),
        out_buf.size(), &out_len, err_buf.data(), err_buf.size());
  }
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0' ? err_buf.data()
                                  : "cannot merge texture memory client-settings";
    }
    return false;
  }
  merged_json->assign(out_buf.data(), out_len);
  return true;
}

}  // namespace runtime
}  // namespace mocktail
