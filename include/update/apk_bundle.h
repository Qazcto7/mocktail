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

#ifndef MOCKTAIL_UPDATE_APK_BUNDLE_H_
#define MOCKTAIL_UPDATE_APK_BUNDLE_H_

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "update/compatibility_catalog.h"

namespace mocktail::update {

struct PreparedPayload {
  std::filesystem::path directory;
  std::string payload_id;
  std::string version_name;
  std::uint64_t version_code = 0;
  std::string build_id;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Provider identity known before the APK is opened. An exact Build ID is
// present for repository-reviewed versions and intentionally absent for a
// latest-version probation candidate. In both cases the APK signature,
// package, version, architecture, exports, and extracted payload hashes are
// verified before the result can leave the preparation workspace.
struct ExpectedPayloadIdentity {
  std::string version_name;
  std::uint64_t version_code = 0;
  std::optional<std::string> exact_build_id;
};

PreparedPayload PreparePayloadFromArchives(
    const std::vector<std::filesystem::path>& archives,
    const ExpectedPayloadIdentity& expected,
    const std::filesystem::path& signing_trust_manifest,
    const std::filesystem::path& workspace, std::string_view source);

ExpectedPayloadIdentity ExactPayloadIdentity(
    const SupportedPayloadProfile& profile);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_APK_BUNDLE_H_
