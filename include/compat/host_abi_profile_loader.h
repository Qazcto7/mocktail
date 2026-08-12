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

#ifndef MOCKTAIL_COMPAT_HOST_ABI_PROFILE_LOADER_H_
#define MOCKTAIL_COMPAT_HOST_ABI_PROFILE_LOADER_H_

#include <string>

#include "compat/host_abi_profile.h"

namespace mocktail::compat {

struct FileSha256Result {
  std::string sha256;
  std::string error;

  explicit operator bool() const noexcept { return error.empty(); }
};

// Approval receipts bind the profile, manifest, and payload to this digest.
// Runtime identity uses its Build ID because installation may rewrite RPATH.
FileSha256Result ComputeFileSha256(const std::string& path);

struct ExternalHostAbiProfileRequest {
  std::string profile_file;
  std::string payload_path;
  std::string compatibility_manifest_path;
  std::string expected_build_id;
  std::string approval_receipt_path;
  bool candidate_canary = false;
  bool candidate_process_authorization = false;
  bool explicit_unverified_authorization = false;
};

struct ExternalHostAbiProfileResult {
  const HostAbiProfile* profile = nullptr;
  std::string payload_sha256;
  std::string profile_sha256;
  std::string error;

  explicit operator bool() const noexcept { return error.empty(); }
};

// Candidates require canary authorization; normal launches require an
// approval receipt. Built-in profiles always win.
ExternalHostAbiProfileResult LoadExternalHostAbiProfile(
    const ExternalHostAbiProfileRequest& request);

// An unset profile is a no-op. Candidates require both canary flags and the
// research CLI marker; approved profiles require a receipt and no canary flag.
ExternalHostAbiProfileResult InitializeHostAbiProfileFromEnvironment(
    const std::string& payload_path,
    const std::string& compatibility_manifest_path,
    const std::string& expected_build_id,
    bool explicit_unverified_authorization);

const HostAbiProfile* FindLoadedExternalHostAbiProfile(
    std::string_view build_id) noexcept;

}  // namespace mocktail::compat

#endif  // MOCKTAIL_COMPAT_HOST_ABI_PROFILE_LOADER_H_
