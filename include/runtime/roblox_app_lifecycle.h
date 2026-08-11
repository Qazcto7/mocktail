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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_APP_LIFECYCLE_H_
#define MOCKTAIL_RUNTIME_ROBLOX_APP_LIFECYCLE_H_

#include <jni.h>

#include <atomic>
#include <string>
#include <vector>

#include "runtime/roblox_capability_resolver.h"

namespace mocktail {
namespace runtime {

using NativeAppBridgeV2PauseAppFn = void (*)(JNIEnv *env, jclass clazz);
using SetTaskSchedulerBackgroundModeFn = void (*)(JNIEnv *env, jclass clazz,
                                                  jboolean enabled,
                                                  jstring context);
using NativeAppBridgeV2DestroyAppFn = void (*)(JNIEnv *env, jclass clazz);

struct RobloxAppLifecycleSymbols {
  NativeAppBridgeV2PauseAppFn app_bridge_v2_pause_app = nullptr;
  SetTaskSchedulerBackgroundModeFn set_task_scheduler_background_mode = nullptr;
  NativeAppBridgeV2DestroyAppFn app_bridge_v2_destroy_app = nullptr;

  bool complete() const;
};

enum class RobloxAppLifecycleResolutionStatus {
  kReady,
  kInvalidLookup,
  kMissingRequiredSymbols,
};

class RobloxAppLifecycleResolution final {
public:
  RobloxAppLifecycleResolutionStatus status() const { return status_; }
  bool ok() const {
    return status_ == RobloxAppLifecycleResolutionStatus::kReady;
  }
  const RobloxAppLifecycleSymbols *symbols() const {
    return ok() ? &symbols_ : nullptr;
  }
  const std::vector<std::string> &missing_required_symbols() const {
    return missing_required_symbols_;
  }

private:
  friend RobloxAppLifecycleResolution
  ResolveRobloxAppLifecycleSymbols(const RobloxSymbolLookup &lookup);

  RobloxAppLifecycleResolutionStatus status_ =
      RobloxAppLifecycleResolutionStatus::kInvalidLookup;
  RobloxAppLifecycleSymbols symbols_;
  std::vector<std::string> missing_required_symbols_;
};

RobloxAppLifecycleResolution
ResolveRobloxAppLifecycleSymbols(const RobloxSymbolLookup &lookup);

enum class RobloxAppShutdownStatus {
  kStopped,
  kAlreadyStopped,
  kShutdownInProgress,
  kMissingRequiredSymbols,
  kInvalidJniState,
  kReasonAllocationFailed,
};

struct RobloxAppShutdownResult {
  RobloxAppShutdownStatus status =
      RobloxAppShutdownStatus::kMissingRequiredSymbols;
  const char *message = "lifecycle symbols are incomplete";

  bool ok() const {
    return status == RobloxAppShutdownStatus::kStopped ||
           status == RobloxAppShutdownStatus::kAlreadyStopped;
  }
};

// Owns only lifecycle state and function pointers. The Android library
// handle and WSI resources remain owned by composition, ensuring
// they stay mapped/alive throughout native teardown.
class RobloxAppLifecycle final {
public:
  explicit RobloxAppLifecycle(RobloxAppLifecycleSymbols symbols);

  RobloxAppLifecycle(const RobloxAppLifecycle &) = delete;
  RobloxAppLifecycle &operator=(const RobloxAppLifecycle &) = delete;

  // Runs the supported ASMA shutdown sequence exactly once:
  //   pause app -> scheduler background(true, "ASMA.stop") -> destroy app.
  RobloxAppShutdownResult Shutdown(JNIEnv *env, jclass native_gl_class);

  bool stopped() const;

private:
  enum class State {
    kReady,
    kStopping,
    kStopped,
  };

  RobloxAppLifecycleSymbols symbols_;
  std::atomic<State> state_{State::kReady};
};

const char *RobloxAppLifecycleResolutionStatusName(
    RobloxAppLifecycleResolutionStatus status);
const char *RobloxAppShutdownStatusName(RobloxAppShutdownStatus status);

} // namespace runtime
} // namespace mocktail

#endif // MOCKTAIL_RUNTIME_ROBLOX_APP_LIFECYCLE_H_
