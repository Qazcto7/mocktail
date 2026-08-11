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

#ifndef MOCKTAIL_UPDATE_APK_SIGNATURE_H_
#define MOCKTAIL_UPDATE_APK_SIGNATURE_H_

#include <filesystem>
#include <string>
#include <vector>

namespace mocktail::update {

struct ApkSignatureResult {
  std::vector<std::string> certificate_sha256;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Verifies an APK Signature Scheme v2/v3 signer, including the signed-data
// signature and APK chunked content digest, and returns signer certificate
// fingerprints. V1-only archives are rejected.
ApkSignatureResult VerifyApkSignature(const std::filesystem::path& apk_path);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_APK_SIGNATURE_H_
