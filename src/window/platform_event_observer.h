#ifndef MOCKTAIL_WINDOW_PLATFORM_EVENT_OBSERVER_H_
#define MOCKTAIL_WINDOW_PLATFORM_EVENT_OBSERVER_H_

#include <memory>

#include "mocktail/platform/platform_runtime.h"

namespace mocktail {
namespace window {

using PlatformEventObserver = void (*)(void* context,
                                       const platform::PlatformEvent& event);

// One process-scoped consumer receives events synchronously from the sole SDL
// polling loop. Clear and Deactivate remove the observer first, then wait for
// any callback that already copied it. The callback runs without this gate's
// mutex and must not synchronously clear its own registration.
class PlatformEventObserverGate final {
 public:
  PlatformEventObserverGate();
  ~PlatformEventObserverGate();
  PlatformEventObserverGate(const PlatformEventObserverGate&) = delete;
  PlatformEventObserverGate& operator=(const PlatformEventObserverGate&) =
      delete;

  bool Activate();
  void Deactivate();
  bool Register(PlatformEventObserver observer, void* context);
  void Clear();
  bool HasObserver();
  void Notify(const platform::PlatformEvent& event);

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_PLATFORM_EVENT_OBSERVER_H_
