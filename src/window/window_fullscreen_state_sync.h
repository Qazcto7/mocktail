#ifndef MOCKTAIL_WINDOW_WINDOW_FULLSCREEN_STATE_SYNC_H_
#define MOCKTAIL_WINDOW_WINDOW_FULLSCREEN_STATE_SYNC_H_

#include <memory>

namespace mocktail {
namespace window {

using FullscreenStateSyncCallback = bool (*)(void* context, bool fullscreen);

// Owns the optional guest-state synchronizer. SDL calls Notify only from its
// event thread; Clear still waits so the composition object cannot disappear
// while a callback copied its context.
class WindowFullscreenStateSync final {
 public:
  WindowFullscreenStateSync();
  ~WindowFullscreenStateSync();
  WindowFullscreenStateSync(const WindowFullscreenStateSync&) = delete;
  WindowFullscreenStateSync& operator=(const WindowFullscreenStateSync&) =
      delete;

  bool Register(FullscreenStateSyncCallback callback, void* context);
  bool Notify(bool fullscreen);
  void Clear();

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_WINDOW_FULLSCREEN_STATE_SYNC_H_
