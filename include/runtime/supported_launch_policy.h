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

#ifndef MOCKTAIL_RUNTIME_SUPPORTED_LAUNCH_POLICY_H_
#define MOCKTAIL_RUNTIME_SUPPORTED_LAUNCH_POLICY_H_

#include <string>

namespace mocktail {
namespace runtime {

// Publishes relocatable installed-resource paths and backend-independent
// interactive LuaApp defaults. Graphics policy is applied only after the
// runtime configuration has been resolved.
bool ApplySupportedLaunchPolicy(bool interactive, std::string* error = nullptr);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_SUPPORTED_LAUNCH_POLICY_H_
