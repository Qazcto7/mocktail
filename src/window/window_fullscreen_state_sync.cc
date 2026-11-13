#include "window/window_fullscreen_state_sync.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

WindowFullscreenStateSync::WindowFullscreenStateSync()
    : engine_(mocktail_rust_window_fullscreen_state_sync_new(),
              mocktail_rust_window_fullscreen_state_sync_free) {}

WindowFullscreenStateSync::~WindowFullscreenStateSync() = default;

bool WindowFullscreenStateSync::Register(FullscreenStateSyncCallback callback,
                                         void* context) {
  return mocktail_rust_window_fullscreen_state_sync_register(
      engine_.get(), callback, context);
}

bool WindowFullscreenStateSync::Notify(bool fullscreen) {
  return mocktail_rust_window_fullscreen_state_sync_notify(engine_.get(),
                                                           fullscreen);
}

void WindowFullscreenStateSync::Clear() {
  mocktail_rust_window_fullscreen_state_sync_clear(engine_.get());
}

}  // namespace window
}  // namespace mocktail
