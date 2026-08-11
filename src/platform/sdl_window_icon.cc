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

#include "mocktail/platform/sdl_window_icon.h"

#include <SDL3/SDL.h>

#include <string>
#include <utility>

#include "mocktail/platform/sdl_window_icon_data.h"

namespace mocktail {
namespace platform {
namespace {

Status IconError(const char* operation) {
  std::string message = operation;
  message += " failed: ";
  const char* error = SDL_GetError();
  message += error != nullptr && error[0] != '\0' ? error : "unknown SDL error";
  return Status::Error(StatusCode::kPlatformError, std::move(message));
}

}  // namespace

Status ApplySdlWindowIcon(SDL_Window* window) {
  if (window == nullptr) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "SDL window must not be null");
  }

  SDL_IOStream* stream = SDL_IOFromConstMem(
      internal::kMocktailWindowIconPng,
      internal::kMocktailWindowIconPngSize);
  if (stream == nullptr) {
    return IconError("SDL_IOFromConstMem(window icon)");
  }

  SDL_Surface* icon = SDL_LoadPNG_IO(stream, true);
  if (icon == nullptr) {
    return IconError("SDL_LoadPNG_IO(window icon)");
  }

  if (!SDL_SetWindowIcon(window, icon)) {
    Status status = IconError("SDL_SetWindowIcon");
    SDL_DestroySurface(icon);
    return status;
  }
  SDL_DestroySurface(icon);
  return Status::Ok();
}

}  // namespace platform
}  // namespace mocktail
