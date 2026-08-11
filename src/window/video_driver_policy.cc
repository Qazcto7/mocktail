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

#include "window/video_driver_policy.h"

namespace mocktail {
namespace window {

VideoDriverChoice ResolveVideoDriverChoice(
    const VideoDriverPolicyInput& input) {
  if (input.has_explicit_sdl_driver) {
    return VideoDriverChoice::kSdlDefault;
  }
  if (input.force_wayland) {
    return VideoDriverChoice::kWayland;
  }
  if (input.force_x11 && input.has_x11_display) {
    return VideoDriverChoice::kX11;
  }
  if (input.uses_direct_vulkan && input.has_nvidia_kernel_driver &&
      input.has_wayland_session && input.has_x11_display) {
    return VideoDriverChoice::kNvidiaDirectVulkanX11;
  }
  if (input.prefer_wayland && input.has_wayland_session) {
    return VideoDriverChoice::kWayland;
  }
  return VideoDriverChoice::kSdlDefault;
}

const char* VideoDriverChoiceName(VideoDriverChoice choice) {
  switch (choice) {
    case VideoDriverChoice::kWayland:
      return "wayland";
    case VideoDriverChoice::kX11:
    case VideoDriverChoice::kNvidiaDirectVulkanX11:
      return "x11";
    case VideoDriverChoice::kSdlDefault:
      return nullptr;
  }
  return nullptr;
}

}  // namespace window
}  // namespace mocktail
