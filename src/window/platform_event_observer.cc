#include "window/platform_event_observer.h"

#include <new>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {
namespace {

struct ObserverTarget {
  PlatformEventObserver observer;
  void* context;
};

void DispatchObserverTarget(void* target_box, const void* event_ptr) {
  auto* target = static_cast<ObserverTarget*>(target_box);
  target->observer(target->context,
                   *static_cast<const platform::PlatformEvent*>(event_ptr));
}

void DestroyObserverTarget(void* target_box) {
  delete static_cast<ObserverTarget*>(target_box);
}

}  // namespace

PlatformEventObserverGate::PlatformEventObserverGate()
    : engine_(mocktail_rust_platform_event_observer_gate_new(),
              mocktail_rust_platform_event_observer_gate_free) {}

PlatformEventObserverGate::~PlatformEventObserverGate() = default;

bool PlatformEventObserverGate::Activate() {
  return mocktail_rust_platform_event_observer_gate_activate(engine_.get());
}

void PlatformEventObserverGate::Deactivate() {
  mocktail_rust_platform_event_observer_gate_deactivate(engine_.get());
}

bool PlatformEventObserverGate::Register(PlatformEventObserver observer,
                                         void* context) {
  if (observer == nullptr || context == nullptr) {
    return false;
  }
  auto* target = new (std::nothrow) ObserverTarget{observer, context};
  if (target == nullptr) {
    return false;
  }
  if (!mocktail_rust_platform_event_observer_gate_register(
          engine_.get(), &DispatchObserverTarget, target,
          &DestroyObserverTarget)) {
    delete target;
    return false;
  }
  return true;
}

void PlatformEventObserverGate::Clear() {
  mocktail_rust_platform_event_observer_gate_clear(engine_.get());
}

bool PlatformEventObserverGate::HasObserver() {
  return mocktail_rust_platform_event_observer_gate_has_observer(engine_.get());
}

void PlatformEventObserverGate::Notify(const platform::PlatformEvent& event) {
  mocktail_rust_platform_event_observer_gate_notify(engine_.get(), &event);
}

}  // namespace window
}  // namespace mocktail
