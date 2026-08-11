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

#ifndef MOCKTAIL_WINDOW_VIDEO_DRIVER_POLICY_H_
#define MOCKTAIL_WINDOW_VIDEO_DRIVER_POLICY_H_

namespace mocktail {
namespace window {

enum class VideoDriverChoice {
  kSdlDefault,
  kWayland,
  kX11,
  kNvidiaDirectVulkanX11,
};

struct VideoDriverPolicyInput {
  bool has_explicit_sdl_driver = false;
  bool force_wayland = false;
  bool force_x11 = false;
  bool prefer_wayland = true;
  bool has_wayland_session = false;
  bool has_x11_display = false;
  bool uses_direct_vulkan = false;
  bool has_nvidia_kernel_driver = false;
};

// Resolves the SDL video backend before SDL_Init. An explicit SDL driver is
// always authoritative. NVIDIA's direct Vulkan WSI uses X11/XWayland by
// default when both display transports are available because a blocked native
// Wayland present cannot be cancelled without violating VkQueue ownership.
VideoDriverChoice ResolveVideoDriverChoice(const VideoDriverPolicyInput& input);

const char* VideoDriverChoiceName(VideoDriverChoice choice);

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_VIDEO_DRIVER_POLICY_H_
