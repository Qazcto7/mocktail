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

#ifndef MOCKTAIL_RUNTIME_PLATFORM_CACHE_MIGRATION_H_
#define MOCKTAIL_RUNTIME_PLATFORM_CACHE_MIGRATION_H_

#include <filesystem>
#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

class Environment;
class RuntimePaths;

// Every coordinate affects Roblox's server-refreshed platform policy. Keeping
// the canonical preset and input capabilities in one cache fingerprint
// prevents one emulated device from reusing another device's hydration data.
std::string BuildPlatformProfileRevision(std::string_view device_profile,
                                         bool touch_enabled, bool mouse_enabled,
                                         bool keyboard_enabled);

struct PlatformCacheMigrationResult {
  bool transitioned = false;
  bool app_storage_found = false;
  bool app_storage_updated = false;
  std::filesystem::path app_storage_file;
  std::filesystem::path fingerprint_file;
  std::string previous_revision;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Invalidates only platform-derived, server-refreshable appStorage entries
// when the platform profile revision changes. Installation identity,
// OTA state, credentials, and unrelated preferences remain untouched.
PlatformCacheMigrationResult MigratePlatformProfileCaches(
    const Environment& environment, const RuntimePaths& paths,
    std::string_view desired_revision);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_PLATFORM_CACHE_MIGRATION_H_
