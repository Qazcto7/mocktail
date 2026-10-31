#include "mocktail/platform/display_refresh_capabilities.h"

#include <SDL3/SDL.h>

#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace platform {

DisplayRefreshCapabilities
NormalizeDisplayRefreshCapabilities(float current_hz,
                                    std::vector<float> supported_hz) {
  DisplayRefreshCapabilities result;
  std::vector<float> out(supported_hz.size() + 1);
  size_t count = 0;
  if (mocktail_rust_normalize_display_refresh_capabilities(
          current_hz, supported_hz.data(), supported_hz.size(),
          out.data(), out.size(), &count) == 0 && count > 0) {
    result.current_hz = current_hz;
    out.resize(count);
    result.supported_hz = std::move(out);
  }
  return result;
}

DisplayRefreshCapabilities
QuerySdlDisplayRefreshCapabilities(SDL_Window *window) {
  if (window == nullptr) {
    return {};
  }
  const SDL_DisplayID display = SDL_GetDisplayForWindow(window);
  if (display == 0) {
    return {};
  }
  const SDL_DisplayMode *current_mode = SDL_GetCurrentDisplayMode(display);
  if (current_mode == nullptr) {
    return {};
  }

  std::vector<float> supported_hz;
  int mode_count = 0;
  SDL_DisplayMode **modes = SDL_GetFullscreenDisplayModes(display, &mode_count);
  if (modes != nullptr) {
    supported_hz.reserve(mode_count > 0 ? static_cast<size_t>(mode_count) : 0);
    for (int index = 0; index < mode_count; ++index) {
      if (modes[index] != nullptr) {
        supported_hz.push_back(modes[index]->refresh_rate);
      }
    }
    SDL_free(modes);
  }
  return NormalizeDisplayRefreshCapabilities(current_mode->refresh_rate,
                                             std::move(supported_hz));
}

} // namespace platform
} // namespace mocktail
