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

#include "mocktail/platform/display_refresh_capabilities.h"

#include <SDL3/SDL.h>

#include <algorithm>
#include <cmath>
#include <utility>

namespace mocktail {
namespace platform {
namespace {

constexpr float kDuplicateToleranceHz = 0.01f;

bool IsUsableRate(float rate_hz) {
  return std::isfinite(rate_hz) && rate_hz > 0.0f;
}

} // namespace

DisplayRefreshCapabilities
NormalizeDisplayRefreshCapabilities(float current_hz,
                                    std::vector<float> supported_hz) {
  DisplayRefreshCapabilities result;
  if (!IsUsableRate(current_hz)) {
    return result;
  }
  result.current_hz = current_hz;
  supported_hz.erase(
      std::remove_if(supported_hz.begin(), supported_hz.end(),
                     [](float rate_hz) { return !IsUsableRate(rate_hz); }),
      supported_hz.end());
  supported_hz.push_back(current_hz);
  std::sort(supported_hz.begin(), supported_hz.end());
  for (const float rate_hz : supported_hz) {
    if (result.supported_hz.empty() ||
        std::fabs(result.supported_hz.back() - rate_hz) >
            kDuplicateToleranceHz) {
      result.supported_hz.push_back(rate_hz);
    }
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
