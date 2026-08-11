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

#ifndef MOCKTAIL_UPDATE_PAYLOAD_INTEGRITY_H_
#define MOCKTAIL_UPDATE_PAYLOAD_INTEGRITY_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace mocktail::update {

struct PayloadMetadata {
  std::string package_name;
  std::string version_name;
  std::uint64_t version_code = 0;
  std::string build_id;
  std::string library_sha256;
  std::string base_apk_sha256;
  std::string split_apk_sha256;
  std::size_t asset_file_count = 0;
  std::string asset_tree_sha256;
};

struct PayloadIntegrityResult {
  PayloadMetadata metadata;
  std::string payload_id;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

std::string HashRegularFile(const std::filesystem::path& path,
                            std::string* error = nullptr);

std::string HashAssetTree(const std::filesystem::path& root,
                          std::size_t* file_count,
                          std::string* error = nullptr);

PayloadIntegrityResult VerifyPreparedPayload(
    const std::filesystem::path& directory);

// Reads and validates the immutable payload layout and metadata without
// rehashing the archived APKs and complete asset tree. Callers that stage or
// promote new bytes must use VerifyPreparedPayload instead.
PayloadIntegrityResult InspectPreparedPayload(
    const std::filesystem::path& directory);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_PAYLOAD_INTEGRITY_H_
