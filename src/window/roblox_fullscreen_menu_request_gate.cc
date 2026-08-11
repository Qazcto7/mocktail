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

#include "window/roblox_fullscreen_menu_request_gate.h"

#include <cstring>

namespace mocktail {
namespace window {
namespace {

constexpr std::uint64_t kQuietPeriodNs = 20'000'000ULL;
constexpr std::uint64_t kTrailingBurstSuppressionNs = 250'000'000ULL;

bool IsFullscreenSelectorCycle(const char* message) {
  return message != nullptr &&
         std::strstr(
             message,
             "Maximum event re-entrancy depth exceeded for "
             "BindableEvent.Event") != nullptr &&
         std::strstr(
             message,
             "CoreGui.RobloxGui.Modules.Settings.Pages.GameSettings") !=
             nullptr;
}

}  // namespace

bool RobloxFullscreenMenuRequestGate::RequestFromAndroidLog(
    const char* tag, const char* message, std::uint64_t monotonic_ns) {
  if (tag == nullptr || std::strcmp(tag, "Roblox") != 0 ||
      !IsFullscreenSelectorCycle(message)) {
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (monotonic_ns < suppress_until_ns_) {
    return true;
  }
  pending_ = true;
  last_request_ns_ = monotonic_ns;
  return true;
}

bool RobloxFullscreenMenuRequestGate::Take(std::uint64_t monotonic_ns) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!pending_ || monotonic_ns < last_request_ns_ ||
      monotonic_ns - last_request_ns_ < kQuietPeriodNs) {
    return false;
  }
  pending_ = false;
  suppress_until_ns_ = monotonic_ns + kTrailingBurstSuppressionNs;
  return true;
}

void RobloxFullscreenMenuRequestGate::Reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  last_request_ns_ = 0;
  suppress_until_ns_ = 0;
  pending_ = false;
}

}  // namespace window
}  // namespace mocktail
