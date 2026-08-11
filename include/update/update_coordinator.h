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

#ifndef MOCKTAIL_UPDATE_UPDATE_COORDINATOR_H_
#define MOCKTAIL_UPDATE_UPDATE_COORDINATOR_H_

#include <filesystem>
#include <string>

#include "update/readiness_canary.h"

namespace mocktail::update {

struct UpdatePaths {
  std::filesystem::path config_file;
  std::filesystem::path data_root;
  std::filesystem::path cache_root;
  std::filesystem::path state_root;
  std::filesystem::path compatibility_manifest;
  std::filesystem::path signing_trust_manifest;
  std::filesystem::path host_abi_reference_profile;
  std::filesystem::path runtime_binary;
};

struct UpdateRequest {
  bool startup_preflight = false;
  bool check_latest = true;
  bool run_canary = true;
  CanaryGraphicsBackend canary_graphics_backend =
      CanaryGraphicsBackend::kDirectVulkan;
  int progress_fd = -1;
};

struct UpdateResult {
  bool changed = false;
  std::string payload_id;
  std::string message;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

UpdateResult RunUpdate(const UpdatePaths& paths, const UpdateRequest& request);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_UPDATE_COORDINATOR_H_
