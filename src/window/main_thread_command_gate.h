#ifndef MOCKTAIL_WINDOW_MAIN_THREAD_COMMAND_GATE_H_
#define MOCKTAIL_WINDOW_MAIN_THREAD_COMMAND_GATE_H_

#include <memory>

namespace mocktail {
namespace window {

using MainThreadCommandCallback = bool (*)(void* context);

// Synchronously invokes one registered command-drain callback from the SDL
// event owner. The atomic fast path avoids taking a mutex when no callback is
// installed. Clear waits for callbacks that already crossed that fast path.
class MainThreadCommandGate final {
 public:
  MainThreadCommandGate();
  ~MainThreadCommandGate();
  MainThreadCommandGate(const MainThreadCommandGate&) = delete;
  MainThreadCommandGate& operator=(const MainThreadCommandGate&) = delete;

  void Activate();
  bool Register(MainThreadCommandCallback callback, void* context);
  bool Invoke();
  void Clear();
  void Deactivate();

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_MAIN_THREAD_COMMAND_GATE_H_
