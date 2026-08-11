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

#ifndef MOCKTAIL_PLATFORM_SDL_EVENT_CONVERTER_H_
#define MOCKTAIL_PLATFORM_SDL_EVENT_CONVERTER_H_

#include <SDL3/SDL_events.h>
#include <SDL3/SDL_video.h>

#include "mocktail/platform/platform_runtime.h"

namespace mocktail {
namespace platform {

// Converts one SDL event without retaining either argument. The caller remains
// the sole owner of SDL_PollEvent and decides how converted events are routed.
// Returns false for invalid arguments and SDL events outside the platform
// contract.
bool ConvertSdlEvent(SDL_Window* window, const SDL_Event& source,
                     PlatformEvent* destination);

}  // namespace platform
}  // namespace mocktail

#endif  // MOCKTAIL_PLATFORM_SDL_EVENT_CONVERTER_H_
