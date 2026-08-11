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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_DESKTOP_APP_POLICY_H_
#define MOCKTAIL_RUNTIME_ROBLOX_DESKTOP_APP_POLICY_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

struct DesktopAppPolicyResult {
  bool app_storage_created = false;
  bool updated = false;
  std::size_t normalized_policy_count = 0;
  std::string policy_json;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Normalizes only Roblox UniversalApp layout coordinates for a PC profile.
// Account eligibility and feature-entitlement fields remain server-owned.
// The guest and authenticated cache keys are both populated so user-switch
// startup cannot fall back to the Android Unknown/mobile layout.
DesktopAppPolicyResult ApplyDesktopAppPolicy(
    const std::filesystem::path& app_storage_file,
    const std::filesystem::path& default_policy_file,
    std::int64_t authenticated_user_id);

// Routes the normalized policy through Roblox's supported runtime override so
// a later GUAC response cannot replace the in-memory desktop layout with the
// Android Unknown layout after startup.
bool MergeDesktopAppPolicyClientSettingsOverride(std::string_view policy_json,
                                                 std::string_view base_json,
                                                 std::string* merged_json,
                                                 std::string* error);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_DESKTOP_APP_POLICY_H_
