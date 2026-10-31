#include "runtime/environment.h"
#include "mocktail/mocktail_rust.h"

#include <cstdlib>
#include <string>
#include <vector>

namespace mocktail {
namespace runtime {

bool Environment::HasNonEmpty(std::string_view name) const {
  const std::optional<std::string> value = Get(name);
  return value.has_value() && !value->empty();
}

std::string Environment::GetOr(std::string_view name,
                               std::string_view default_value) const {
  const std::optional<std::string> value = Get(name);
  if (!value.has_value() || value->empty()) {
    return std::string(default_value);
  }
  return *value;
}

std::optional<std::string> ProcessEnvironment::Get(
    std::string_view name) const {
  const std::string owned_name(name);
  std::vector<char> out_buf(1024);
  size_t out_len = 0;
  int32_t rc = mocktail_rust_env_get(owned_name.c_str(), out_buf.data(),
                                     out_buf.size(), &out_len);
  if (rc == -2) {
    out_buf.resize(out_len + 128);
    rc = mocktail_rust_env_get(owned_name.c_str(), out_buf.data(),
                               out_buf.size(), &out_len);
  }
  if (rc == 0) {
    return std::string(out_buf.data(), out_len);
  }
  return std::nullopt;
}

}  // namespace runtime
}  // namespace mocktail
