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

#ifndef MOCKTAIL_UPDATE_HOST_ABI_DERIVER_H_
#define MOCKTAIL_UPDATE_HOST_ABI_DERIVER_H_

#include <filesystem>
#include <string>

namespace mocktail::update {

struct HostAbiDerivationOptions {
  std::filesystem::path reference_library;
  std::filesystem::path reference_profile;
  std::filesystem::path candidate_payload_directory;
  std::filesystem::path output_directory;
};

struct HostAbiDerivationResult {
  std::filesystem::path profile;
  std::filesystem::path compatibility_manifest;
  std::string error;

  explicit operator bool() const {
    return error.empty() && !profile.empty() && !compatibility_manifest.empty();
  }
};

// Derives an exact candidate HostAbi profile by matching normalized x86-64
// instruction signatures against one already approved reference payload. This
// is static analysis only; the result still requires two real Tier C canaries
// before normal runtime activation.
HostAbiDerivationResult DeriveHostAbiProfile(
    const HostAbiDerivationOptions& options);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_HOST_ABI_DERIVER_H_
