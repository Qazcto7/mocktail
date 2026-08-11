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

#ifndef MOCKTAIL_RUNTIME_PERFORMANCE_POLICY_H_
#define MOCKTAIL_RUNTIME_PERFORMANCE_POLICY_H_

#include <cstdint>
#include <string>
#include <string_view>

#include "runtime/frame_rate_policy.h"
#include "runtime/game_mode.h"

namespace mocktail {
namespace runtime {

enum class PhysicsWorkerMode {
  kAuto,
  kLatency,
  kThroughput,
};

bool ParsePhysicsWorkerMode(std::string_view value, PhysicsWorkerMode* mode);
std::string_view PhysicsWorkerModeName(PhysicsWorkerMode mode);

// Makes every available physical core eligible for Roblox scheduler work.
// At least one scheduler worker remains on malformed topology input.
int CalculateThroughputWorkerCount(int available_physical_cores);

struct PerformancePolicy {
  bool multithreaded_rendering = false;
  int physical_core_count = 0;
  std::uint64_t memory_limit_mb = 0;
  bool memory_limit_valid = true;
  GameModePolicy game_mode = GameModePolicy::kAuto;
  bool game_mode_valid = true;
  PhysicsWorkerMode physics_worker_mode = PhysicsWorkerMode::kAuto;
  bool physics_worker_mode_valid = true;

  bool memory_limit_enabled() const {
    return memory_limit_valid && memory_limit_mb != 0;
  }
  std::uint64_t memory_limit_bytes() const {
    return memory_limit_mb * 1024U * 1024U;
  }
};

PerformancePolicy ParsePerformancePolicy(
    std::string_view multithreaded_rendering,
    std::string_view memory_limit_mb = "0", std::string_view game_mode = "auto",
    std::string_view physics_worker_mode = "auto");

// Counts unique physical cores available to the current process. Linux CPU
// affinity is respected; systems without readable topology fall back to the
// available logical CPU count.
int DetectAvailablePhysicalCoreCount();

// Merges the supported Roblox scheduler/rendering mode into the flat
// client-settings override object. Disabled policy leaves existing overrides
// intact. Conflicting explicit values fail closed instead of silently
// replacing the caller's settings.
bool MergePerformanceClientSettingsOverrides(const PerformancePolicy& policy,
                                             std::string_view base_json,
                                             std::string* merged_json,
                                             std::string* error);

// Applies every runtime policy in a stable order before the resulting
// override object crosses the legacy startup boundary. The mandatory
// HttpClient compatibility policy is applied before the mandatory crash-report
// upload block. Neither policy can be overridden by a caller-provided client
// setting.
bool MergeRuntimeClientSettingsOverrides(const FrameRatePolicy& frame_rate,
                                         const PerformancePolicy& performance,
                                         std::string_view base_json,
                                         std::string* merged_json,
                                         std::string* error);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_PERFORMANCE_POLICY_H_
