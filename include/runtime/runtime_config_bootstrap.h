// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MOCKTAIL_RUNTIME_RUNTIME_CONFIG_BOOTSTRAP_H_
#define MOCKTAIL_RUNTIME_RUNTIME_CONFIG_BOOTSTRAP_H_

#include <filesystem>
#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

enum class RuntimeConfigBootstrapStatus {
  kCreated,
  kPreservedExisting,
};

struct RuntimeConfigBootstrapResult {
  RuntimeConfigBootstrapStatus status =
      RuntimeConfigBootstrapStatus::kPreservedExisting;
  std::string error;

  explicit operator bool() const { return error.empty(); }
  bool created() const {
    return status == RuntimeConfigBootstrapStatus::kCreated;
  }
};

// Returns the complete versioned first-run configuration. Every active option
// carries its supported default and an adjacent type/behaviour comment.
std::string_view DefaultRuntimeConfigYaml();

// Atomically publishes the first-run configuration with mode 0600. An
// existing regular file is preserved byte-for-byte; symlinks and other entry
// types are rejected without modification.
RuntimeConfigBootstrapResult EnsureRuntimeConfigFile(
    const std::filesystem::path& config_file);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_RUNTIME_CONFIG_BOOTSTRAP_H_
