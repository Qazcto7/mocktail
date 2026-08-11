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

#ifndef MOCKTAIL_UPDATE_ANDROID_MANIFEST_H_
#define MOCKTAIL_UPDATE_ANDROID_MANIFEST_H_

#include <cstdint>
#include <string>
#include <string_view>

namespace mocktail::update {

struct AndroidManifestIdentity {
  std::string package_name;
  std::string version_name;
  std::string split_name;
  std::uint64_t version_code = 0;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

AndroidManifestIdentity ParseAndroidManifest(std::string_view binary_xml);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_ANDROID_MANIFEST_H_
