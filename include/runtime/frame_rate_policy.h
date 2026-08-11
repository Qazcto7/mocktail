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

#ifndef MOCKTAIL_RUNTIME_FRAME_RATE_POLICY_H_
#define MOCKTAIL_RUNTIME_FRAME_RATE_POLICY_H_

#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

inline constexpr int kMaximumSupportedRobloxSchedulerFps = 240;

enum class FrameRateLimitMode {
  kDisplay,
  kFixed,
  kUnlimited,
  kInvalid,
};

struct FrameRatePolicy {
  FrameRateLimitMode mode = FrameRateLimitMode::kDisplay;
  int fixed_fps = 0;

  bool valid() const { return mode != FrameRateLimitMode::kInvalid; }
};

FrameRatePolicy ParseFrameRatePolicy(std::string_view value);

// Merges the scheduler policy into Roblox's supported client-settings ingress.
// Unlimited selects the unmodified payload's maximum scheduler target (240).
// With VSync auto/off, graphics policy separately requests an unthrottled
// Vulkan present mode when the host exposes one.
// Existing unrelated overrides are retained. A conflicting explicit override
// is rejected instead of silently choosing one source of truth.
bool MergeFrameRateClientSettingsOverrides(const FrameRatePolicy &policy,
                                           std::string_view base_json,
                                           std::string *merged_json,
                                           std::string *error);

} // namespace runtime
} // namespace mocktail

#endif // MOCKTAIL_RUNTIME_FRAME_RATE_POLICY_H_
