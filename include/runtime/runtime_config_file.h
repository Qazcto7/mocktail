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

#ifndef MOCKTAIL_RUNTIME_RUNTIME_CONFIG_FILE_H_
#define MOCKTAIL_RUNTIME_RUNTIME_CONFIG_FILE_H_

#include <filesystem>
#include <string>

#include "runtime/environment.h"
#include "runtime/runtime_config.h"

namespace mocktail {
namespace runtime {

struct RuntimeConfigLoadResult {
  RuntimeConfig config;
  bool file_loaded = false;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Loads the optional YAML file as a defaults layer. Values already present in
// the process environment win over YAML; RuntimeConfig defaults are used last.
RuntimeConfigLoadResult LoadRuntimeConfig(
    const Environment& environment, const std::filesystem::path& config_file);

// Transitional composition helper. The legacy runtime still consumes the
// supported settings through environment variables, so the composition
// root exports one already-resolved RuntimeConfig before entering that
// boundary.
bool ExportRuntimeConfigEnvironment(const RuntimeConfig& config,
                                    std::string* error = nullptr);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_RUNTIME_CONFIG_FILE_H_
