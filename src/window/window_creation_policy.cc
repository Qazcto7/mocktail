#include "window/window_creation_policy.h"

#include "mocktail/mocktail_rust.h"

#include <string>

namespace mocktail {
namespace window {

SDL_WindowFlags ApplyHighPixelDensityWindowFlag(SDL_WindowFlags flags,
                                                bool high_dpi) {
  return static_cast<SDL_WindowFlags>(
      mocktail_rust_window_apply_high_dpi_flag(
          static_cast<uint64_t>(flags), high_dpi ? 1 : 0,
          static_cast<uint64_t>(SDL_WINDOW_HIGH_PIXEL_DENSITY)));
}

bool DirectVulkanWindowRequiresInitialSync(std::string_view video_driver) {
  const std::string driver_str(video_driver);
  return mocktail_rust_window_direct_vulkan_requires_sync(driver_str.c_str()) != 0;
}

}  // namespace window
}  // namespace mocktail
