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

#ifndef MOCKTAIL_UPDATE_UPDATE_CONFIG_H_
#define MOCKTAIL_UPDATE_UPDATE_CONFIG_H_

#include <filesystem>
#include <string>

namespace mocktail::update {

struct UpdateConfig {
  bool automatic = true;
  bool launch_after_update = false;
  std::string source = "apk-pure";
};

struct UpdateConfigResult {
  UpdateConfig config;
  bool file_loaded = false;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Other top-level sections are handled by runtime_config_file.cc.
UpdateConfigResult LoadUpdateConfig(const std::filesystem::path& path);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_UPDATE_CONFIG_H_
