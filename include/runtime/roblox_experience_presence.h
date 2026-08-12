// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#ifndef MOCKTAIL_RUNTIME_ROBLOX_EXPERIENCE_PRESENCE_H_
#define MOCKTAIL_RUNTIME_ROBLOX_EXPERIENCE_PRESENCE_H_

#include "runtime/roblox_experience_launch_bridge.h"

namespace mocktail {
namespace runtime {

enum class RobloxExperiencePresencePhase {
  kBrowsing,
  kJoining,
  kPlaying,
};

using NotifyRobloxExperiencePresenceFn =
    void (*)(void* context, RobloxExperiencePresencePhase phase,
             const RobloxExperienceLaunchRequest* request);

// Non-owning observer retained by RobloxExperienceComposition. Its owner must
// outlive the composition. Browsing notifications carry a null request.
struct RobloxExperiencePresenceObserver {
  void* context = nullptr;
  NotifyRobloxExperiencePresenceFn notify = nullptr;

  bool valid() const { return notify != nullptr; }
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_EXPERIENCE_PRESENCE_H_
