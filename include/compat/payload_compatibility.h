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

#ifndef MOCKTAIL_COMPAT_PAYLOAD_COMPATIBILITY_H_
#define MOCKTAIL_COMPAT_PAYLOAD_COMPATIBILITY_H_

#include <string>

#include "compat/build_profile.h"

namespace mocktail {
namespace compat {

// Result of the side-effect-free compatibility gate used before any network,
// authentication, or native-loader work. The legacy runtime repeats the
// profile application while that ownership is migrated, but external startup
// services must not run until this gate succeeds.
struct PayloadCompatibilityResult {
  BuildProfile profile;
  std::string build_id;
  std::string error;

  explicit operator bool() const noexcept { return error.empty(); }
};

PayloadCompatibilityResult CheckPayloadCompatibility(
    const std::string& library_path, const std::string& manifest_path,
    bool allow_unverified_build);

}  // namespace compat
}  // namespace mocktail

#endif  // MOCKTAIL_COMPAT_PAYLOAD_COMPATIBILITY_H_
