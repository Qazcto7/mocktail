#include "window/window_fullscreen_request_gate.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

bool WindowFullscreenRequestGate::RequestFromAndroidFlags(int flags, int mask) {
  std::lock_guard<std::mutex> lock(mutex_);
  return mocktail_rust_window_fullscreen_request_from_android_flags(
             flags, mask, &android_flags_, &pending_state_) != 0;
}

bool WindowFullscreenRequestGate::Take(bool* fullscreen) {
  if (fullscreen == nullptr) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  int out_fs = 0;
  if (mocktail_rust_window_fullscreen_take(&pending_state_, &out_fs) == 0) {
    return false;
  }
  *fullscreen = (out_fs != 0);
  return true;
}

void WindowFullscreenRequestGate::Reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  pending_state_ = 0;
  android_flags_ = 0;
}

}  // namespace window
}  // namespace mocktail
