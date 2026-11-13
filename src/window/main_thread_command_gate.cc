#include "window/main_thread_command_gate.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

MainThreadCommandGate::MainThreadCommandGate()
    : engine_(mocktail_rust_main_thread_command_gate_new(),
              mocktail_rust_main_thread_command_gate_free) {}

MainThreadCommandGate::~MainThreadCommandGate() = default;

void MainThreadCommandGate::Activate() {
  mocktail_rust_main_thread_command_gate_activate(engine_.get());
}

bool MainThreadCommandGate::Register(MainThreadCommandCallback callback,
                                     void* context) {
  return mocktail_rust_main_thread_command_gate_register(engine_.get(),
                                                         callback, context);
}

bool MainThreadCommandGate::Invoke() {
  return mocktail_rust_main_thread_command_gate_invoke(engine_.get());
}

void MainThreadCommandGate::Clear() {
  mocktail_rust_main_thread_command_gate_clear(engine_.get());
}

void MainThreadCommandGate::Deactivate() {
  mocktail_rust_main_thread_command_gate_deactivate(engine_.get());
}

}  // namespace window
}  // namespace mocktail
