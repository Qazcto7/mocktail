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

#ifndef MOCKTAIL_RUNTIME_HTTP_CLIENT_POLICY_H_
#define MOCKTAIL_RUNTIME_HTTP_CLIENT_POLICY_H_

#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

// Applies the supported Android HttpClient compatibility mode. The policy
// keeps endpoint-specific retries intact while disabling the generic LuaApp
// retry source and Roblox's RuntimeMutexRv backend, whose busy retry loop and
// lock traffic are disproportionately expensive across the Bionic bridge.
bool MergeHttpClientSettingsOverrides(std::string_view base_json,
                                      std::string* merged_json,
                                      std::string* error);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_HTTP_CLIENT_POLICY_H_
