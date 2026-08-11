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

// Computes a lowercase SHA-256 digest without invoking a shell or an external
// utility. The external ABI approval receipt binds exact profile,
// compatibility-manifest, and payload bytes through this implementation; the
// runtime itself is bound by its stable GNU Build ID because installation may
// rewrite RPATH bytes.
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

// Loads one exact, payload-bound ABI profile into the process registry. A
// candidate is accepted only by an explicitly authorized canary process. A
// normal launch instead requires a separate approval receipt produced after
// repeated Tier C readiness. Built-in profiles are immutable and always win.
ExternalHostAbiProfileResult LoadExternalHostAbiProfile(
    const ExternalHostAbiProfileRequest& request);

// Environment integration used by the pre-native compatibility gate. An
// unset MOCKTAIL_HOST_ABI_PROFILE_FILE is a successful no-op. If it is set,
// candidate authorization requires MOCKTAIL_HOST_ABI_CANARY=1,
// MOCKTAIL_ALLOW_CANDIDATE_HOST_ABI=1, and the explicit research command-line
// marker. Approved profiles require MOCKTAIL_HOST_ABI_APPROVAL_RECEIPT and
// neither canary environment marker.
ExternalHostAbiProfileResult InitializeHostAbiProfileFromEnvironment(
    const std::string& payload_path,
    const std::string& compatibility_manifest_path,
    const std::string& expected_build_id,
    bool explicit_unverified_authorization);

// Registry lookup used by FindHostAbiProfile after its immutable built-in
// table. Callers should use FindHostAbiProfile rather than this function.
const HostAbiProfile* FindLoadedExternalHostAbiProfile(
    std::string_view build_id) noexcept;

}  // namespace mocktail::compat

#endif  // MOCKTAIL_COMPAT_HOST_ABI_PROFILE_LOADER_H_
