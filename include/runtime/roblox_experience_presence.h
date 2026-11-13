#ifndef MOCKTAIL_RUNTIME_ROBLOX_EXPERIENCE_PRESENCE_H_
#define MOCKTAIL_RUNTIME_ROBLOX_EXPERIENCE_PRESENCE_H_

#include <array>
#include <cstddef>

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

// Fans out presence transitions to multiple observers through a single
// RobloxExperiencePresenceObserver handle without altering composition APIs.
class RobloxExperiencePresenceObserverFanout final {
 public:
  static constexpr std::size_t kMaxObservers = 4;

  void Add(RobloxExperiencePresenceObserver observer) {
    if (observer.valid() && count_ < observers_.size()) {
      observers_[count_++] = observer;
    }
  }

  RobloxExperiencePresenceObserver observer() {
    if (count_ == 0) {
      return {};
    }
    if (count_ == 1) {
      return observers_[0];
    }
    return {this, &RobloxExperiencePresenceObserverFanout::Notify};
  }

 private:
  static void Notify(void* context, RobloxExperiencePresencePhase phase,
                     const RobloxExperienceLaunchRequest* request) {
    if (context == nullptr) {
      return;
    }
    auto* self =
        static_cast<RobloxExperiencePresenceObserverFanout*>(context);
    for (std::size_t i = 0; i < self->count_; ++i) {
      if (self->observers_[i].valid()) {
        self->observers_[i].notify(self->observers_[i].context, phase,
                                   request);
      }
    }
  }

  std::array<RobloxExperiencePresenceObserver, kMaxObservers> observers_{};
  std::size_t count_ = 0;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_EXPERIENCE_PRESENCE_H_
