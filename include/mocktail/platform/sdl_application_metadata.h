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

#ifndef MOCKTAIL_PLATFORM_SDL_APPLICATION_METADATA_H_
#define MOCKTAIL_PLATFORM_SDL_APPLICATION_METADATA_H_

#include "mocktail/status.h"

namespace mocktail {
namespace platform {

inline constexpr char kMocktailApplicationName[] = "Mocktail";
inline constexpr char kMocktailApplicationIdentifier[] =
    "space.bigrat.mocktail";

// Configures the stable compositor identity before SDL initializes. The
// identifier matches the installed desktop file and icon name so Wayland and
// X11 compositors can group the runtime window with its launcher.
Status ConfigureSdlApplicationMetadata();

}  // namespace platform
}  // namespace mocktail

#endif  // MOCKTAIL_PLATFORM_SDL_APPLICATION_METADATA_H_
