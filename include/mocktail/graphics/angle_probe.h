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

#ifndef MOCKTAIL_GRAPHICS_ANGLE_PROBE_H_
#define MOCKTAIL_GRAPHICS_ANGLE_PROBE_H_

#include <string>

#include "mocktail/graphics/graphics_backend.h"

namespace mocktail {
namespace graphics {

struct AngleProbeOptions {
  // Production callers provide paths from one pinned ANGLE distribution.
  // This probe intentionally does not scan browser installation directories.
  std::string egl_library_path;
  std::string gles_library_path;
  bool allow_software_device = false;
};

// Loads a pinned ANGLE pair, verifies the required EGL/GLES symbols, and
// initializes an EGL_PLATFORM_ANGLE Vulkan display. No context is fabricated.
BackendCapability ProbeAngleVulkan(const AngleProbeOptions& options);

}  // namespace graphics
}  // namespace mocktail

#endif  // MOCKTAIL_GRAPHICS_ANGLE_PROBE_H_
