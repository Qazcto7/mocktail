// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MOCKTAIL_WINDOW_WINDOW_POINTER_CAPTURE_OWNER_H_
#define MOCKTAIL_WINDOW_WINDOW_POINTER_CAPTURE_OWNER_H_

#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace mocktail {
namespace window {

using MouseLockQueryCallback = bool (*)(void* context, bool* locked_center);

class PointerCaptureBackend {
 public:
  virtual ~PointerCaptureBackend() = default;
  virtual bool Apply(bool relative_mode, bool cursor_visible) = 0;
};

class WindowPointerCaptureOwner final {
 public:
  explicit WindowPointerCaptureOwner(PointerCaptureBackend* backend);
  ~WindowPointerCaptureOwner();

  WindowPointerCaptureOwner(const WindowPointerCaptureOwner&) = delete;
  WindowPointerCaptureOwner& operator=(const WindowPointerCaptureOwner&) =
      delete;

  bool RegisterQuery(MouseLockQueryCallback callback, void* context);
  void ClearQuery();
  bool Pump(bool text_input_active);
  // Android's lock-center query does not represent desktop RMB camera drag,
  // so the SDL owner tracks that transient capture source independently.
  bool OnRightButton(bool pressed, bool text_input_active);
  bool NeedsRightButtonReleaseRecovery(bool observed_pressed) const;
  // Mirrors Android's captured-pointer listener: the motion that releases a
  // transient capture is consumed instead of leaking one final camera delta.
  bool ShouldDispatchMouseMotion();
  bool OnFocusGained();
  bool OnFocusLost();
  bool Shutdown();

  bool captured() const { return captured_; }
  bool cursor_visible() const { return cursor_visible_; }

 private:
  bool Apply(bool capture, bool cursor_visible);

  PointerCaptureBackend* backend_ = nullptr;
  std::mutex mutex_;
  std::condition_variable condition_;
  MouseLockQueryCallback callback_ = nullptr;
  void* context_ = nullptr;
  std::size_t in_flight_ = 0;
  bool clearing_ = false;
  bool focused_ = true;
  bool right_button_held_ = false;
  bool native_lock_observed_ = false;
  bool native_lock_was_active_before_right_drag_ = false;
  bool wait_for_native_unlock_after_right_drag_ = false;
  bool discard_next_motion_after_right_drag_ = false;
  bool captured_ = false;
  bool cursor_visible_ = true;
};

class SdlPointerCaptureBackend final : public PointerCaptureBackend {
 public:
  explicit SdlPointerCaptureBackend(void* window) : window_(window) {}

  bool Apply(bool relative_mode, bool cursor_visible) override;

 private:
  void* window_ = nullptr;
  float capture_anchor_x_ = 0.0f;
  float capture_anchor_y_ = 0.0f;
  bool relative_mode_ = false;
  bool capture_anchor_valid_ = false;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_WINDOW_POINTER_CAPTURE_OWNER_H_
