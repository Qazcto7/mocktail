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

#ifndef MOCKTAIL_RUNTIME_CRASH_REPORT_POLICY_H_
#define MOCKTAIL_RUNTIME_CRASH_REPORT_POLICY_H_

#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

// Applies Mocktail's mandatory privacy boundary to the flat Roblox
// client-settings override object. The policy disables native Crashpad, Java
// crash/ANR uploads, Lua Backtrace errors, and inferred-crash submission while
// preserving unrelated caller overrides. Unsafe values are replaced rather
// than treated as conflicts because crash upload is not a user-configurable
// runtime capability.
bool MergeCrashReportClientSettingsOverrides(std::string_view base_json,
                                             std::string* merged_json,
                                             std::string* error);

// Applies the same mandatory values to Roblox's separate AppBridge
// fastFlagsJson channel. Only FastVariable names are inserted here;
// Java-only client settings remain on the client-settings boundary above.
bool MergeCrashReportFastFlagsOverrides(std::string_view base_json,
                                        std::string* merged_json,
                                        std::string* error);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_CRASH_REPORT_POLICY_H_
