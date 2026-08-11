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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_FULLSCREEN_RUNTIME_BRIDGE_H_
#define MOCKTAIL_RUNTIME_ROBLOX_FULLSCREEN_RUNTIME_BRIDGE_H_

#include <cstdint>

#include "compat/build_profile.h"
#include "mocktail/status.h"

namespace mocktail {
namespace runtime {

// Composes the Android CoreScript fullscreen intent with SDL and the exact
// UserGameSettings state setter allowed by the active Build-ID profile.
class RobloxFullscreenRuntimeBridge final {
 public:
  RobloxFullscreenRuntimeBridge() = default;
  ~RobloxFullscreenRuntimeBridge();

  RobloxFullscreenRuntimeBridge(const RobloxFullscreenRuntimeBridge&) =
      delete;
  RobloxFullscreenRuntimeBridge& operator=(
      const RobloxFullscreenRuntimeBridge&) = delete;

  Status Install(const compat::BuildProfile& profile);
  void Shutdown();
  bool installed() const { return installed_; }

 private:
  static void ObserveAndroidLog(int priority, const char* tag,
                                const char* message);
  static bool SynchronizeState(void* context, bool fullscreen);
  bool ApplyState(bool fullscreen);

  std::uintptr_t setter_rva_ = 0;
  std::uintptr_t library_base_ = 0;
  bool setter_validated_ = false;
  bool installed_ = false;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_FULLSCREEN_RUNTIME_BRIDGE_H_
