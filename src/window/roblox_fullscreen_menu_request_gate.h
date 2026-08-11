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

#ifndef MOCKTAIL_WINDOW_ROBLOX_FULLSCREEN_MENU_REQUEST_GATE_H_
#define MOCKTAIL_WINDOW_ROBLOX_FULLSCREEN_MENU_REQUEST_GATE_H_

#include <cstdint>
#include <mutex>

namespace mocktail {
namespace window {

// The Android CoreScript calls GuiService.ToggleFullscreen, but the Android
// engine has no desktop window owner. Its cyclic selector error is the only
// observable boundary emitted by the current payload. Coalesce the recursive
// burst into one main-thread host toggle and suppress its trailing messages.
class RobloxFullscreenMenuRequestGate final {
 public:
  bool RequestFromAndroidLog(const char* tag, const char* message,
                             std::uint64_t monotonic_ns);
  bool Take(std::uint64_t monotonic_ns);
  void Reset();

 private:
  std::mutex mutex_;
  std::uint64_t last_request_ns_ = 0;
  std::uint64_t suppress_until_ns_ = 0;
  bool pending_ = false;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_ROBLOX_FULLSCREEN_MENU_REQUEST_GATE_H_
