#include "runtime/runtime_config_bootstrap.h"

#include <array>
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {

std::string_view DefaultRuntimeConfigYaml() {
  std::size_t len = 0;
  const char* ptr = mocktail_rust_runtime_config_default_yaml_ptr(&len);
  return ptr != nullptr ? std::string_view(ptr, len) : std::string_view();
}

RuntimeConfigBootstrapResult EnsureRuntimeConfigFile(
    const std::filesystem::path& config_file) {
  RuntimeConfigBootstrapResult result;
  bool created = false;
  std::array<char, 512> err_buf{};
  const int32_t rc = mocktail_rust_runtime_config_ensure_file(
      config_file.c_str(), &created, err_buf.data(), err_buf.size());
  if (created) {
    result.status = RuntimeConfigBootstrapStatus::kCreated;
  }
  if (rc != 0) {
    result.error = err_buf[0] != '\0'
                       ? std::string(err_buf.data())
                       : "cannot ensure first-run configuration";
  }
  return result;
}

}  // namespace runtime
}  // namespace mocktail
