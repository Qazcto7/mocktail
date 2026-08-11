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

#ifndef MOCKTAIL_UPDATE_COMPATIBILITY_CATALOG_H_
#define MOCKTAIL_UPDATE_COMPATIBILITY_CATALOG_H_

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mocktail::update {

struct SupportedPayloadProfile {
  std::string version_name;
  std::uint64_t version_code = 0;
  std::string elf_build_id;
};

struct CompatibilityCatalogResult {
  std::vector<SupportedPayloadProfile> profiles;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

CompatibilityCatalogResult LoadCompatibilityCatalog(
    const std::filesystem::path& path);

std::optional<SupportedPayloadProfile> PreferredSupportedProfile(
    const std::vector<SupportedPayloadProfile>& profiles);

std::optional<SupportedPayloadProfile> FindSupportedProfile(
    const std::vector<SupportedPayloadProfile>& profiles,
    std::string_view version_name, std::uint64_t version_code = 0);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_COMPATIBILITY_CATALOG_H_
