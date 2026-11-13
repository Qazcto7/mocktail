#ifndef MOCKTAIL_WINDOW_INPUT_PUMP_PACER_H_
#define MOCKTAIL_WINDOW_INPUT_PUMP_PACER_H_

#include <cstdint>
#include <memory>

namespace mocktail {
namespace window {

inline constexpr uint64_t kProductionInputPumpHz = 240;
inline constexpr uint64_t kProductionInputPumpIntervalNs =
    1000000000ULL / kProductionInputPumpHz;

// Keeps SDL input polling aligned to Roblox's maximum supported render
// cadence. A missed deadline is rebased instead of issuing catch-up pumps,
// which prevents motion events from being delivered in artificial bursts.
class InputPumpPacer final {
 public:
  explicit InputPumpPacer(
      uint64_t interval_ns = kProductionInputPumpIntervalNs);
  ~InputPumpPacer();
  InputPumpPacer(const InputPumpPacer&) = delete;
  InputPumpPacer& operator=(const InputPumpPacer&) = delete;

  uint64_t DelayBeforeNextPump(uint64_t now_ns);
  void Reset();

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_INPUT_PUMP_PACER_H_
