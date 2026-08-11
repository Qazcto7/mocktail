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

#ifndef MOCKTAIL_GRAPHICS_GRAPHICS_BACKEND_H_
#define MOCKTAIL_GRAPHICS_GRAPHICS_BACKEND_H_

#include <string>
#include <vector>

#include "mocktail/status.h"

namespace mocktail {
namespace graphics {

enum class GraphicsBackendKind {
  kAngleVulkan = 0,
  kDirectVulkan,
  kSystemEgl,
};

enum class CapabilityState {
  kUnavailable = 0,
  // Loader and WSI entry points exist, but no device/surface was validated.
  kLoadable,
  // A real API display/device initialization completed successfully.
  kReady,
};

enum class HardwareAcceleration {
  kUnknown = 0,
  kSoftware,
  kHardware,
};

struct BackendCapability {
  GraphicsBackendKind backend = GraphicsBackendKind::kAngleVulkan;
  CapabilityState state = CapabilityState::kUnavailable;
  HardwareAcceleration acceleration = HardwareAcceleration::kUnknown;
  std::string detail;
};

struct BackendSelectionPolicy {
  GraphicsBackendKind requested = GraphicsBackendKind::kAngleVulkan;

  // Production remains fail-closed. Fallback must be an explicit policy.
  bool allow_fallback = false;
  bool require_hardware_acceleration = true;
  bool require_runtime_validation = true;
};

struct BackendSelection {
  Status status;
  GraphicsBackendKind backend = GraphicsBackendKind::kAngleVulkan;
  std::string detail;
};

BackendSelection SelectGraphicsBackend(
    const BackendSelectionPolicy& policy,
    const std::vector<BackendCapability>& capabilities);

const char* GraphicsBackendName(GraphicsBackendKind backend);

}  // namespace graphics
}  // namespace mocktail

#endif  // MOCKTAIL_GRAPHICS_GRAPHICS_BACKEND_H_
