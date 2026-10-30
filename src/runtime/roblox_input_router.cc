#include "runtime/roblox_input_router.h"
#include "mocktail/mocktail_rust.h"

#include <SDL3/SDL_mouse.h>
#include <SDL3/SDL_scancode.h>

#include <algorithm>
#include <utility>

namespace mocktail {
namespace runtime {
namespace {

constexpr int32_t kAndroidTouchDown = 0;
constexpr int32_t kAndroidTouchMove = 1;
constexpr int32_t kAndroidTouchUp = 2;
constexpr int32_t kMaximumAndroidPointers = 32;

Status InvalidArgument(const char* message) {
  return Status::Error(StatusCode::kInvalidArgument,
                       message != nullptr ? message : "invalid input event");
}

Status Unsupported(const char* message) {
  return Status::Error(
      StatusCode::kUnsupported,
      message != nullptr ? message : "unsupported input event");
}

RobloxInputDispatchResult Result(RobloxInputDispatchState state,
                                 RobloxInputEventKind kind,
                                 Status status = Status::Ok()) {
  return {state, kind, std::move(status)};
}

platform::SurfaceCoordinateTransform CoordinateTransform(
    const RobloxInputViewport& viewport) {
  return {viewport.logical_width, viewport.logical_height, viewport.pixel_width,
          viewport.pixel_height, viewport.density_scale};
}

}  // namespace

AndroidKeyMapping MapSdlKeyToAndroid(uint32_t sdl_scancode,
                                     uint32_t sdl_key) {
  MocktailRustKeyMapping rust_mapping{0, 0};
  if (mocktail_rust_map_sdl_key_to_android(sdl_scancode, sdl_key, &rust_mapping) == 1) {
    return {rust_mapping.scan_code, rust_mapping.key_code};
  }
  return {};
}

int32_t MapSdlMouseButtonToRoblox(uint8_t sdl_button) {
  return mocktail_rust_map_sdl_mouse_button(sdl_button);
}

RobloxInputRouter::RobloxInputRouter(RobloxInputSink sink,
                                     RobloxTextDisplaySink display_sink,
                                     platform::TextClipboard* clipboard)
    : sink_(sink), text_editor_(sink.text, display_sink, clipboard) {}

Status RobloxInputRouter::Activate(RobloxInputViewport viewport,
                                   bool initially_focused) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (snapshot_.active) {
    return Status::Error(StatusCode::kFailedPrecondition,
                         "Roblox input router is already active");
  }
  if (!viewport.valid()) {
    return InvalidArgument("input viewport dimensions must be positive");
  }
  snapshot_ = {};
  snapshot_.active = true;
  snapshot_.focused = initially_focused;
  snapshot_.viewport = viewport;
  active_mouse_buttons_.clear();
  active_touches_.clear();
  active_keys_.clear();
  gamepads_.clear();
  mouse_x_ = 0.0f;
  mouse_y_ = 0.0f;
  return Status::Ok();
}

Status RobloxInputRouter::Deactivate() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!snapshot_.active) {
    return Status::Ok();
  }
  Status status = ReleasePressedInputsLocked();
  Status gamepad_status = DisconnectGamepadsLocked();
  if (status.ok()) {
    status = std::move(gamepad_status);
  }
  const RobloxTextEditorSnapshot text = text_editor_.Snapshot();
  if (text.focused) {
    Status text_status = text_editor_.EndFocusSession(text.textbox_handle,
                                                      text.generation, true);
    if (status.ok()) {
      status = std::move(text_status);
    }
  }
  snapshot_.active = false;
  snapshot_.focused = false;
  snapshot_.active_mouse_buttons = 0;
  snapshot_.active_touches = 0;
  snapshot_.active_keys = 0;
  return status;
}

Status RobloxInputRouter::BeginTextFocusSession(
    RobloxTextFocusSession session) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!snapshot_.active) {
    return Status::Error(StatusCode::kFailedPrecondition,
                         "Roblox input router is inactive");
  }
  return text_editor_.BeginFocusSession(std::move(session));
}

Status RobloxInputRouter::EndTextFocusSession(int64_t textbox_handle,
                                              uint64_t generation,
                                              bool notify_native) {
  std::lock_guard<std::mutex> lock(mutex_);
  return text_editor_.EndFocusSession(textbox_handle, generation,
                                      notify_native);
}

Status RobloxInputRouter::ReplaceFocusedTextFromEngine(
    uint64_t generation, std::string authoritative_utf8) {
  std::lock_guard<std::mutex> lock(mutex_);
  return text_editor_.ReplaceFocusedTextFromEngine(
      generation, std::move(authoritative_utf8));
}

Status RobloxInputRouter::UpdateTextFocusProperties(
    uint64_t generation, const RobloxTextFocusProperties& properties) {
  std::lock_guard<std::mutex> lock(mutex_);
  return text_editor_.UpdateFocusProperties(generation, properties);
}

RobloxInputDispatchResult RobloxInputRouter::HandleEvent(
    const platform::PlatformEvent& event) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!snapshot_.active) {
    return Result(RobloxInputDispatchState::kIgnoredInactive,
                  RobloxInputEventKind::kNone);
  }

  if (const auto* resized =
          std::get_if<platform::WindowResizedEvent>(&event.payload)) {
    RobloxInputViewport viewport = {
        resized->logical_width, resized->logical_height, resized->pixel_width,
        resized->pixel_height, resized->density_scale};
    if (!viewport.valid()) {
      return Result(RobloxInputDispatchState::kRejectedInvalid,
                    RobloxInputEventKind::kViewport,
                    InvalidArgument("resized input viewport is invalid"));
    }
    snapshot_.viewport = viewport;
    return Result(RobloxInputDispatchState::kStateUpdated,
                  RobloxInputEventKind::kViewport);
  }

  if (const auto* focus =
          std::get_if<platform::WindowFocusEvent>(&event.payload)) {
    if (!focus->focused && snapshot_.focused) {
      Status status = ReleasePressedInputsLocked();
      const RobloxTextEditorSnapshot text = text_editor_.Snapshot();
      if (text.focused) {
        Status text_status = text_editor_.EndFocusSession(
            text.textbox_handle, text.generation, true);
        if (status.ok()) {
          status = std::move(text_status);
        }
      }
      snapshot_.focused = false;
      if (!status.ok()) {
        ++snapshot_.native_errors;
        return Result(RobloxInputDispatchState::kNativeError,
                      RobloxInputEventKind::kFocus, std::move(status));
      }
    } else {
      snapshot_.focused = focus->focused;
    }
    return Result(RobloxInputDispatchState::kStateUpdated,
                  RobloxInputEventKind::kFocus);
  }

  if (const auto* connection =
          std::get_if<platform::GamepadConnectionEvent>(&event.payload)) {
    return HandleGamepadConnectionLocked(*connection);
  }
  if (const auto* button =
          std::get_if<platform::GamepadButtonEvent>(&event.payload)) {
    return HandleGamepadButtonLocked(*button);
  }
  if (const auto* axis =
          std::get_if<platform::GamepadAxisEvent>(&event.payload)) {
    return HandleGamepadAxisLocked(*axis);
  }

  RobloxInputEventKind kind = RobloxInputEventKind::kNone;
  if (std::holds_alternative<platform::MouseMotionEvent>(event.payload)) {
    kind = RobloxInputEventKind::kMouseMotion;
  } else if (std::holds_alternative<platform::MouseButtonEvent>(
                 event.payload)) {
    kind = RobloxInputEventKind::kMouseButton;
  } else if (std::holds_alternative<platform::MouseWheelEvent>(event.payload)) {
    kind = RobloxInputEventKind::kMouseWheel;
  } else if (std::holds_alternative<platform::TouchEvent>(event.payload)) {
    kind = RobloxInputEventKind::kTouch;
  } else if (std::holds_alternative<platform::KeyEvent>(event.payload)) {
    kind = RobloxInputEventKind::kKeyboard;
  } else if (std::holds_alternative<platform::TextInputEvent>(event.payload) ||
             std::holds_alternative<platform::TextEditingEvent>(
                 event.payload)) {
    kind = RobloxInputEventKind::kText;
  }
  if (kind == RobloxInputEventKind::kNone) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported, kind,
                  Unsupported("platform event has no Roblox input route"));
  }
  if (!snapshot_.focused) {
    snapshot_.focused = true;
  }

  if (const auto* motion =
          std::get_if<platform::MouseMotionEvent>(&event.payload)) {
    return HandleMouseMotionLocked(*motion);
  }
  if (const auto* button =
          std::get_if<platform::MouseButtonEvent>(&event.payload)) {
    return HandleMouseButtonLocked(*button);
  }
  if (const auto* wheel =
          std::get_if<platform::MouseWheelEvent>(&event.payload)) {
    return HandleMouseWheelLocked(*wheel);
  }
  if (const auto* touch = std::get_if<platform::TouchEvent>(&event.payload)) {
    return HandleTouchLocked(*touch);
  }
  if (const auto* key = std::get_if<platform::KeyEvent>(&event.payload)) {
    RobloxTextEditResult text_result = text_editor_.HandleKey(*key);
    if (text_result.handled) {
      if (!text_result.status.ok()) {
        ++snapshot_.native_errors;
        return Result(RobloxInputDispatchState::kNativeError,
                      RobloxInputEventKind::kText,
                      std::move(text_result.status));
      }
      if (text_result.dispatched) {
        ++snapshot_.text_events;
      }
      return Result(text_result.dispatched
                        ? RobloxInputDispatchState::kDispatched
                        : RobloxInputDispatchState::kStateUpdated,
                    RobloxInputEventKind::kText);
    }
    return HandleKeyLocked(*key);
  }
  RobloxTextEditResult text_result;
  if (const auto* input =
          std::get_if<platform::TextInputEvent>(&event.payload)) {
    text_result = text_editor_.HandleTextInput(*input);
  } else if (const auto* editing =
                 std::get_if<platform::TextEditingEvent>(&event.payload)) {
    text_result = text_editor_.HandleTextEditing(*editing);
  }
  if (!text_result.handled) {
    ++snapshot_.ignored_text_events;
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kText,
                  Unsupported("text input has no focused Roblox TextBox"));
  }
  if (!text_result.status.ok()) {
    ++snapshot_.native_errors;
    return Result(RobloxInputDispatchState::kNativeError,
                  RobloxInputEventKind::kText, std::move(text_result.status));
  }
  if (text_result.dispatched) {
    ++snapshot_.text_events;
  }
  return Result(text_result.dispatched
                    ? RobloxInputDispatchState::kDispatched
                    : RobloxInputDispatchState::kStateUpdated,
                RobloxInputEventKind::kText);
}

RobloxInputSnapshot RobloxInputRouter::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  RobloxInputSnapshot snapshot = snapshot_;
  const RobloxTextEditorSnapshot text = text_editor_.Snapshot();
  snapshot.text_focus_generation = text.focused ? text.generation : 0;
  return snapshot;
}

RobloxInputDispatchResult RobloxInputRouter::HandleMouseMotionLocked(
    const platform::MouseMotionEvent& event) {
  if (sink_.mouse_move == nullptr) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kMouseMotion,
                  Unsupported("native mouse motion is unavailable"));
  }
  const platform::SurfaceCoordinateTransform transform =
      CoordinateTransform(snapshot_.viewport);
  const float delta_x = transform.HostLogicalToGuestX(event.delta_x);
  const float delta_y = transform.HostLogicalToGuestY(event.delta_y);

  if (event.relative_mode) {
    // Android's captured-pointer path maintains an unclipped virtual position.
    mouse_x_ += delta_x;
    mouse_y_ += delta_y;
  } else {
    mouse_x_ = transform.HostLogicalToGuestX(event.x);
    mouse_y_ = transform.HostLogicalToGuestY(event.y);
  }
  const float max_x = std::max(0.0F, transform.guest_width() - 1.0F);
  const float max_y = std::max(0.0F, transform.guest_height() - 1.0F);
  const float clamped_x = std::clamp(mouse_x_, 0.0f, max_x);
  const float clamped_y = std::clamp(mouse_y_, 0.0f, max_y);

  return NativeResultLocked(
      sink_.mouse_move(sink_.context,
                       event.relative_mode ? mouse_x_ : clamped_x,
                       event.relative_mode ? mouse_y_ : clamped_y,
                       delta_x, delta_y),
      RobloxInputEventKind::kMouseMotion);
}

RobloxInputDispatchResult RobloxInputRouter::HandleMouseButtonLocked(
    const platform::MouseButtonEvent& event) {
  if (sink_.mouse_button == nullptr) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kMouseButton,
                  Unsupported("native mouse buttons are unavailable"));
  }
  const int32_t roblox_button = MapSdlMouseButtonToRoblox(event.button);
  if (roblox_button < 0) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kMouseButton,
                  Unsupported("SDL mouse button has no Roblox mapping"));
  }
  const platform::SurfaceCoordinateTransform transform =
      CoordinateTransform(snapshot_.viewport);
  if (!event.relative_mode) {
    mouse_x_ = transform.HostLogicalToGuestX(event.x);
    mouse_y_ = transform.HostLogicalToGuestY(event.y);
  }
  const float max_x = std::max(0.0F, transform.guest_width() - 1.0F);
  const float max_y = std::max(0.0F, transform.guest_height() - 1.0F);
  const float clamped_x = std::clamp(mouse_x_, 0.0f, max_x);
  const float clamped_y = std::clamp(mouse_y_, 0.0f, max_y);
  // Let Roblox decide whether a click releases TextBox focus.
  Status status = sink_.mouse_button(sink_.context, clamped_x, clamped_y,
                                     event.pressed, roblox_button);
  if (status.ok()) {
    const auto active = std::find(active_mouse_buttons_.begin(),
                                  active_mouse_buttons_.end(), roblox_button);
    if (event.pressed && active == active_mouse_buttons_.end()) {
      active_mouse_buttons_.push_back(roblox_button);
    } else if (!event.pressed && active != active_mouse_buttons_.end()) {
      active_mouse_buttons_.erase(active);
    }
    snapshot_.active_mouse_buttons = active_mouse_buttons_.size();
  }
  return NativeResultLocked(std::move(status),
                            RobloxInputEventKind::kMouseButton);
}

RobloxInputDispatchResult RobloxInputRouter::HandleMouseWheelLocked(
    const platform::MouseWheelEvent& event) {
  if (sink_.mouse_wheel == nullptr || event.delta_y == 0.0f) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kMouseWheel,
                  Unsupported("vertical native mouse wheel is unavailable"));
  }
  const platform::SurfaceCoordinateTransform transform =
      CoordinateTransform(snapshot_.viewport);
  if (!event.relative_mode) {
    mouse_x_ = transform.HostLogicalToGuestX(std::max(0.0f, event.mouse_x));
    mouse_y_ = transform.HostLogicalToGuestY(std::max(0.0f, event.mouse_y));
  }
  return NativeResultLocked(
      sink_.mouse_wheel(sink_.context, std::max(0.0f, mouse_x_),
                        std::max(0.0f, mouse_y_), event.delta_y),
      RobloxInputEventKind::kMouseWheel);
}

RobloxInputDispatchResult RobloxInputRouter::HandleTouchLocked(
    const platform::TouchEvent& event) {
  if (sink_.touch == nullptr) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kTouch,
                  Unsupported("native touch input is unavailable"));
  }
  const platform::SurfaceCoordinateTransform transform =
      CoordinateTransform(snapshot_.viewport);
  const int32_t guest_width = transform.rounded_guest_width();
  const int32_t guest_height = transform.rounded_guest_height();
  const float x =
      std::clamp(event.x, 0.0f, 1.0f) * static_cast<float>(guest_width);
  const float y =
      std::clamp(event.y, 0.0f, 1.0f) * static_cast<float>(guest_height);
  auto active = FindTouchIteratorLocked(event.touch_id, event.finger_id);
  int32_t action = kAndroidTouchMove;
  int32_t pointer_id = -1;

  if (event.action == platform::TouchEvent::Action::kDown) {
    if (active != active_touches_.end()) {
      return Result(RobloxInputDispatchState::kRejectedInvalid,
                    RobloxInputEventKind::kTouch,
                    InvalidArgument("duplicate touch down was rejected"));
    }
    pointer_id = AllocatePointerIdLocked();
    if (pointer_id < 0) {
      return Result(RobloxInputDispatchState::kRejectedInvalid,
                    RobloxInputEventKind::kTouch,
                    InvalidArgument("Android pointer limit was reached"));
    }
    action = kAndroidTouchDown;
  } else {
    if (active == active_touches_.end()) {
      return Result(RobloxInputDispatchState::kRejectedInvalid,
                    RobloxInputEventKind::kTouch,
                    InvalidArgument("touch event has no active pointer"));
    }
    pointer_id = active->pointer_id;
    action = event.action == platform::TouchEvent::Action::kMove
                 ? kAndroidTouchMove
                 : kAndroidTouchUp;
  }

  Status status = sink_.touch(sink_.context, pointer_id, x, y, action,
                              guest_width, guest_height);
  if (event.action == platform::TouchEvent::Action::kDown && status.ok()) {
    active_touches_.push_back(
        {event.touch_id, event.finger_id, pointer_id, x, y});
  } else if (active != active_touches_.end()) {
    if (event.action == platform::TouchEvent::Action::kMove) {
      if (status.ok()) {
        active->x = x;
        active->y = y;
      }
    } else {
      active_touches_.erase(active);
    }
  }
  snapshot_.active_touches = active_touches_.size();
  return NativeResultLocked(std::move(status), RobloxInputEventKind::kTouch);
}

RobloxInputDispatchResult RobloxInputRouter::HandleKeyLocked(
    const platform::KeyEvent& event) {
  if (sink_.key == nullptr) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kKeyboard,
                  Unsupported("native hardware keyboard is unavailable"));
  }
  const AndroidKeyMapping android =
      MapSdlKeyToAndroid(event.scancode, event.keycode);
  if (!android.valid()) {
    return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                  RobloxInputEventKind::kKeyboard,
                  Unsupported("SDL key has no Android mapping"));
  }
  Status status = sink_.key(sink_.context, event.pressed, android.scan_code,
                            android.key_code, event.repeat);
  if (status.ok()) {
    auto active = FindKeyIteratorLocked(event.scancode);
    if (event.pressed && active == active_keys_.end()) {
      active_keys_.push_back({event.scancode, android});
    } else if (!event.pressed && active != active_keys_.end()) {
      active_keys_.erase(active);
    }
    snapshot_.active_keys = active_keys_.size();
  }
  return NativeResultLocked(std::move(status), RobloxInputEventKind::kKeyboard);
}

Status RobloxInputRouter::ReleasePressedInputsLocked() {
  Status first_error = Status::Ok();
  for (ActiveGamepad& gamepad : gamepads_) {
    Status status = ReleaseGamepadInputsLocked(gamepad);
    if (first_error.ok()) {
      first_error = std::move(status);
    }
  }
  for (int32_t button : active_mouse_buttons_) {
    if (sink_.mouse_button == nullptr) {
      continue;
    }
    Status status =
        sink_.mouse_button(sink_.context, mouse_x_, mouse_y_, false, button);
    if (status.ok()) {
      ++snapshot_.mouse_events;
    } else if (first_error.ok()) {
      first_error = std::move(status);
    }
  }
  active_mouse_buttons_.clear();

  for (const ActiveTouch& touch : active_touches_) {
    if (sink_.touch == nullptr) {
      continue;
    }
    const platform::SurfaceCoordinateTransform transform =
        CoordinateTransform(snapshot_.viewport);
    Status status = sink_.touch(
        sink_.context, touch.pointer_id, touch.x, touch.y, kAndroidTouchUp,
        transform.rounded_guest_width(), transform.rounded_guest_height());
    if (status.ok()) {
      ++snapshot_.touch_events;
    } else if (first_error.ok()) {
      first_error = std::move(status);
    }
  }
  active_touches_.clear();

  for (const ActiveKey& key : active_keys_) {
    if (sink_.key == nullptr) {
      continue;
    }
    Status status = sink_.key(sink_.context, false, key.android.scan_code,
                              key.android.key_code, false);
    if (status.ok()) {
      ++snapshot_.keyboard_events;
    } else if (first_error.ok()) {
      first_error = std::move(status);
    }
  }
  active_keys_.clear();
  snapshot_.active_mouse_buttons = 0;
  snapshot_.active_touches = 0;
  snapshot_.active_keys = 0;
  return first_error;
}

int32_t RobloxInputRouter::AllocatePointerIdLocked() const {
  for (int32_t candidate = 0; candidate < kMaximumAndroidPointers;
       ++candidate) {
    const auto used =
        std::find_if(active_touches_.begin(), active_touches_.end(),
                     [candidate](const ActiveTouch& touch) {
                       return touch.pointer_id == candidate;
                     });
    if (used == active_touches_.end()) {
      return candidate;
    }
  }
  return -1;
}

std::vector<RobloxInputRouter::ActiveTouch>::iterator
RobloxInputRouter::FindTouchIteratorLocked(int64_t touch_id,
                                           int64_t finger_id) {
  return std::find_if(active_touches_.begin(), active_touches_.end(),
                      [touch_id, finger_id](const ActiveTouch& touch) {
                        return touch.touch_id == touch_id &&
                               touch.finger_id == finger_id;
                      });
}

std::vector<RobloxInputRouter::ActiveKey>::iterator
RobloxInputRouter::FindKeyIteratorLocked(uint32_t sdl_scancode) {
  return std::find_if(active_keys_.begin(), active_keys_.end(),
                      [sdl_scancode](const ActiveKey& key) {
                        return key.sdl_scancode == sdl_scancode;
                      });
}

RobloxInputDispatchResult RobloxInputRouter::NativeResultLocked(
    Status status, RobloxInputEventKind kind) {
  if (!status.ok()) {
    ++snapshot_.native_errors;
    return Result(RobloxInputDispatchState::kNativeError, kind,
                  std::move(status));
  }
  switch (kind) {
    case RobloxInputEventKind::kMouseMotion:
    case RobloxInputEventKind::kMouseButton:
    case RobloxInputEventKind::kMouseWheel:
      ++snapshot_.mouse_events;
      break;
    case RobloxInputEventKind::kTouch:
      ++snapshot_.touch_events;
      break;
    case RobloxInputEventKind::kKeyboard:
      ++snapshot_.keyboard_events;
      break;
    case RobloxInputEventKind::kGamepadButton:
    case RobloxInputEventKind::kGamepadAxis:
      ++snapshot_.gamepad_events;
      break;
    default:
      break;
  }
  return Result(RobloxInputDispatchState::kDispatched, kind);
}

const char* RobloxInputDispatchStateName(RobloxInputDispatchState state) {
  switch (state) {
    case RobloxInputDispatchState::kDispatched:
      return "Dispatched";
    case RobloxInputDispatchState::kStateUpdated:
      return "StateUpdated";
    case RobloxInputDispatchState::kIgnoredInactive:
      return "IgnoredInactive";
    case RobloxInputDispatchState::kIgnoredUnfocused:
      return "IgnoredUnfocused";
    case RobloxInputDispatchState::kIgnoredUnsupported:
      return "IgnoredUnsupported";
    case RobloxInputDispatchState::kRejectedInvalid:
      return "RejectedInvalid";
    case RobloxInputDispatchState::kNativeError:
      return "NativeError";
  }
  return "Unknown";
}

const char* RobloxInputEventKindName(RobloxInputEventKind kind) {
  switch (kind) {
    case RobloxInputEventKind::kNone:
      return "None";
    case RobloxInputEventKind::kMouseMotion:
      return "MouseMotion";
    case RobloxInputEventKind::kMouseButton:
      return "MouseButton";
    case RobloxInputEventKind::kMouseWheel:
      return "MouseWheel";
    case RobloxInputEventKind::kTouch:
      return "Touch";
    case RobloxInputEventKind::kKeyboard:
      return "Keyboard";
    case RobloxInputEventKind::kText:
      return "Text";
    case RobloxInputEventKind::kFocus:
      return "Focus";
    case RobloxInputEventKind::kViewport:
      return "Viewport";
    case RobloxInputEventKind::kGamepadConnection:
      return "GamepadConnection";
    case RobloxInputEventKind::kGamepadButton:
      return "GamepadButton";
    case RobloxInputEventKind::kGamepadAxis:
      return "GamepadAxis";
  }
  return "Unknown";
}

}  // namespace runtime
}  // namespace mocktail
