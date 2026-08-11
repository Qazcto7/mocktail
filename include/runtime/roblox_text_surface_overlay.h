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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_TEXT_SURFACE_OVERLAY_H_
#define MOCKTAIL_RUNTIME_ROBLOX_TEXT_SURFACE_OVERLAY_H_

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "mocktail/graphics/text_overlay_frame.h"
#include "mocktail/status.h"
#include "runtime/roblox_text_display_state.h"

namespace mocktail {
namespace runtime {

// Thread-safe bridge from Roblox's synchronous TextBox callback to the
// direct-Vulkan present path. The input callback only updates bounded state.
// SDL3_ttf rasterization is deferred to the render thread and the resulting
// RGBA frame is copied into the existing swapchain by libvulkan.so.
class RobloxTextSurfaceOverlay final {
 public:
  RobloxTextSurfaceOverlay() = default;
  ~RobloxTextSurfaceOverlay();

  RobloxTextSurfaceOverlay(const RobloxTextSurfaceOverlay&) = delete;
  RobloxTextSurfaceOverlay& operator=(const RobloxTextSurfaceOverlay&) = delete;

  Status Initialize(RobloxTextOverlayViewport viewport);
  Status Shutdown();
  RobloxTextDisplaySink sink();

  bool QueryFrame(MocktailTextOverlayFrameInfo* frame);
  bool CopyFrame(std::uint64_t revision, void* rgba, std::size_t rgba_capacity);

 private:
  static void UpdateCallback(void* context,
                             const RobloxTextDisplayUpdate& update);
  void ApplyUpdate(const RobloxTextDisplayUpdate& update);
  Status RasterizeLocked();
  void ClearFrameLocked();
  void RecordFailureLocked(Status status);

  std::mutex mutex_;
  RobloxTextDisplayState state_;
  RobloxTextOverlayViewport viewport_;
  std::vector<std::uint8_t> rgba_;
  std::uint64_t state_revision_ = 0;
  std::uint64_t raster_revision_ = 0;
  Status failure_;
  bool initialized_ = false;
  bool failure_logged_ = false;
  bool ready_logged_ = false;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_TEXT_SURFACE_OVERLAY_H_
