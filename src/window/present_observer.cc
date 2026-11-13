#include "window/present_observer.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

PresentObserverRegistry::PresentObserverRegistry()
    : engine_(mocktail_rust_present_observer_registry_new(),
              mocktail_rust_present_observer_registry_free) {}

PresentObserverRegistry::~PresentObserverRegistry() = default;

bool PresentObserverRegistry::Register(PresentObserver observer, void* context) {
  return mocktail_rust_present_observer_registry_register(engine_.get(),
                                                          observer, context);
}

void PresentObserverRegistry::Clear() {
  mocktail_rust_present_observer_registry_clear(engine_.get());
}

void PresentObserverRegistry::Notify(uint64_t frame_serial) {
  mocktail_rust_present_observer_registry_notify(engine_.get(), frame_serial);
}

PresentLifecycleGate::PresentScope::~PresentScope() {
  if (gate_engine_ != nullptr) {
    mocktail_rust_present_lifecycle_gate_exit_present(gate_engine_);
    gate_engine_ = nullptr;
  }
}

void PresentLifecycleGate::PresentScope::NotifyObserver(uint64_t frame_serial) {
  if (gate_engine_ != nullptr) {
    mocktail_rust_present_lifecycle_gate_notify_observer(gate_engine_,
                                                         frame_serial);
  }
}

PresentLifecycleGate::PresentLifecycleGate()
    : engine_(mocktail_rust_present_lifecycle_gate_new(),
              mocktail_rust_present_lifecycle_gate_free) {}

PresentLifecycleGate::~PresentLifecycleGate() = default;

bool PresentLifecycleGate::Activate() {
  return mocktail_rust_present_lifecycle_gate_activate(engine_.get());
}

void PresentLifecycleGate::Deactivate() {
  mocktail_rust_present_lifecycle_gate_deactivate(engine_.get());
}

bool PresentLifecycleGate::Register(PresentObserver observer, void* context) {
  return mocktail_rust_present_lifecycle_gate_register(engine_.get(), observer,
                                                       context);
}

void PresentLifecycleGate::Clear() {
  mocktail_rust_present_lifecycle_gate_clear(engine_.get());
}

PresentLifecycleGate::PresentScope PresentLifecycleGate::EnterPresent() {
  if (!mocktail_rust_present_lifecycle_gate_enter_present(engine_.get())) {
    return PresentScope();
  }
  return PresentScope(engine_.get());
}

}  // namespace window
}  // namespace mocktail
