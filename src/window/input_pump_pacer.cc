#include "window/input_pump_pacer.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

InputPumpPacer::InputPumpPacer(uint64_t interval_ns)
    : engine_(mocktail_rust_input_pump_pacer_new(interval_ns),
              mocktail_rust_input_pump_pacer_free) {}

InputPumpPacer::~InputPumpPacer() = default;

uint64_t InputPumpPacer::DelayBeforeNextPump(uint64_t now_ns) {
  return mocktail_rust_input_pump_pacer_delay_before_next_pump(engine_.get(),
                                                                now_ns);
}

void InputPumpPacer::Reset() {
  mocktail_rust_input_pump_pacer_reset(engine_.get());
}

}  // namespace window
}  // namespace mocktail
