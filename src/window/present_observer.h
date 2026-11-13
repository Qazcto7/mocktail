#ifndef MOCKTAIL_WINDOW_PRESENT_OBSERVER_H_
#define MOCKTAIL_WINDOW_PRESENT_OBSERVER_H_

#include <cstdint>
#include <memory>

namespace mocktail {
namespace window {

using PresentObserver = void (*)(void* context, uint64_t frame_serial);

// Serializes successful-present notifications with observer replacement.
// Callbacks run synchronously and must not mutate their own registration.
class PresentObserverRegistry final {
 public:
  PresentObserverRegistry();
  ~PresentObserverRegistry();
  PresentObserverRegistry(const PresentObserverRegistry&) = delete;
  PresentObserverRegistry& operator=(const PresentObserverRegistry&) = delete;

  bool Register(PresentObserver observer, void* context);
  void Clear();
  void Notify(uint64_t frame_serial);

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

// Owns the synchronization boundary between a successful host presentation
// and window teardown for both Vulkan and EGL/OpenGL ES. A PresentScope keeps
// the window alive through the callback and post-present SDL access performed
// by its caller. Callbacks must not re-enter this gate or trigger teardown.
class PresentLifecycleGate final {
 public:
  class PresentScope final {
   public:
    PresentScope(PresentScope&& other) noexcept
        : gate_engine_(other.gate_engine_) {
      other.gate_engine_ = nullptr;
    }
    PresentScope& operator=(PresentScope&&) noexcept = delete;
    ~PresentScope();

    PresentScope(const PresentScope&) = delete;
    PresentScope& operator=(const PresentScope&) = delete;

    explicit operator bool() const { return gate_engine_ != nullptr; }

    void NotifyObserver(uint64_t frame_serial);

   private:
    friend class PresentLifecycleGate;

    PresentScope() = default;
    explicit PresentScope(void* gate_engine) : gate_engine_(gate_engine) {}

    void* gate_engine_ = nullptr;
  };

  PresentLifecycleGate();
  ~PresentLifecycleGate();
  PresentLifecycleGate(const PresentLifecycleGate&) = delete;
  PresentLifecycleGate& operator=(const PresentLifecycleGate&) = delete;

  bool Activate();
  void Deactivate();
  bool Register(PresentObserver observer, void* context);
  void Clear();
  PresentScope EnterPresent();

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_PRESENT_OBSERVER_H_
