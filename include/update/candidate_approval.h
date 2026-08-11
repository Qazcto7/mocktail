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

#ifndef MOCKTAIL_UPDATE_CANDIDATE_APPROVAL_H_
#define MOCKTAIL_UPDATE_CANDIDATE_APPROVAL_H_

#include <array>
#include <filesystem>
#include <string>
#include <string_view>

#include "update/payload_integrity.h"

namespace mocktail::update {

struct CandidateApprovalOptions {
  std::filesystem::path store_root;
  std::filesystem::path payload_directory;
  std::filesystem::path profile;
  std::filesystem::path compatibility_manifest;
  std::filesystem::path runtime_binary;
  std::array<std::filesystem::path, 2> canary_logs;
};

struct CandidateApprovalResult {
  std::string generation;
  std::filesystem::path profile;
  std::filesystem::path compatibility_manifest;
  std::filesystem::path receipt;
  std::string error;

  explicit operator bool() const {
    return error.empty() && !generation.empty();
  }
};

CandidateApprovalResult CreateCandidateApproval(
    const CandidateApprovalOptions& options,
    const PayloadIntegrityResult& verified_payload);

bool ValidateCandidateApproval(const std::filesystem::path& store_root,
                               std::string_view activation_json,
                               const PayloadIntegrityResult& payload,
                               const std::filesystem::path& runtime_binary,
                               CandidateApprovalResult* approval,
                               std::string* error);

std::string PayloadRuntimeFingerprint(
    const std::filesystem::path& payload_directory,
    const PayloadIntegrityResult& payload, std::string* error);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_CANDIDATE_APPROVAL_H_
