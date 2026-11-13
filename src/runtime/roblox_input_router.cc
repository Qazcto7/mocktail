#include "runtime/roblox_input_router.h"
#include "mocktail/mocktail_rust.h"

#include <array>
#include <utility>

namespace mocktail {
namespace runtime {
namespace {

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

MocktailRustInputViewport ToRustViewport(const RobloxInputViewport& viewport) {
  return {viewport.logical_width, viewport.logical_height, viewport.pixel_width,
          viewport.pixel_height, viewport.density_scale};
}

RobloxInputViewport FromRustViewport(const MocktailRustInputViewport& viewport) {
  return {viewport.logical_width, viewport.logical_height, viewport.pixel_width,
          viewport.pixel_height, viewport.density_scale};
}

struct SinkCallContext {
  const RobloxInputSink& sink;
  RobloxTextEditor* text_editor = nullptr;
  Status first_error = Status::Ok();

  int32_t Record(Status status) {
    if (status.ok()) {
      return 0;
    }
    if (first_error.ok()) {
      first_error = std::move(status);
    }
    return -1;
  }
};

int32_t CallMouseMove(void* ctx, float x, float y, float dx, float dy) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.mouse_move == nullptr) {
    return 0;
  }
  return c->Record(c->sink.mouse_move(c->sink.context, x, y, dx, dy));
}

int32_t CallMouseButton(void* ctx, float x, float y, int32_t pressed,
                        int32_t button) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.mouse_button == nullptr) {
    return 0;
  }
  return c->Record(
      c->sink.mouse_button(c->sink.context, x, y, pressed != 0, button));
}

int32_t CallMouseWheel(void* ctx, float x, float y, float delta_y) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.mouse_wheel == nullptr) {
    return 0;
  }
  return c->Record(c->sink.mouse_wheel(c->sink.context, x, y, delta_y));
}

int32_t CallTouch(void* ctx, int32_t pointer_id, float x, float y,
                  int32_t action, int32_t w, int32_t h) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.touch == nullptr) {
    return 0;
  }
  return c->Record(c->sink.touch(c->sink.context, pointer_id, x, y, action, w, h));
}

int32_t CallKey(void* ctx, int32_t pressed, int32_t scan_code, int32_t key_code,
                int32_t repeat) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.key == nullptr) {
    return 0;
  }
  return c->Record(
      c->sink.key(c->sink.context, pressed != 0, scan_code, key_code, repeat != 0));
}

int32_t CallEndTextFocus(void* ctx) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->text_editor == nullptr) {
    return 0;
  }
  const RobloxTextEditorSnapshot text = c->text_editor->Snapshot();
  if (!text.focused) {
    return 0;
  }
  return c->Record(c->text_editor->EndFocusSession(text.textbox_handle,
                                                   text.generation, true));
}

int32_t CallGamepadSupportedKey(void* ctx, int32_t device_id, int32_t key,
                                int32_t supported, int32_t gp_type) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.gamepad.supported_key == nullptr) {
    return 0;
  }
  return c->Record(c->sink.gamepad.supported_key(
      c->sink.gamepad.context, device_id, key, supported != 0, gp_type));
}

int32_t CallGamepadSupportedMotion(void* ctx, int32_t device_id, int32_t axis,
                                   int32_t direction, int32_t supported,
                                   int32_t gp_type) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.gamepad.supported_motion == nullptr) {
    return 0;
  }
  return c->Record(c->sink.gamepad.supported_motion(
      c->sink.gamepad.context, device_id, axis, direction, supported != 0,
      gp_type));
}

int32_t CallGamepadConnect(void* ctx, int32_t device_id, int32_t gp_type) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.gamepad.connect == nullptr) {
    return 0;
  }
  return c->Record(
      c->sink.gamepad.connect(c->sink.gamepad.context, device_id, gp_type));
}

int32_t CallGamepadDisconnect(void* ctx, int32_t device_id) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.gamepad.disconnect == nullptr) {
    return 0;
  }
  return c->Record(
      c->sink.gamepad.disconnect(c->sink.gamepad.context, device_id));
}

int32_t CallGamepadButton(void* ctx, int32_t device_id, int32_t key,
                          int32_t pressed) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.gamepad.button == nullptr) {
    return 0;
  }
  return c->Record(
      c->sink.gamepad.button(c->sink.gamepad.context, device_id, key, pressed != 0));
}

int32_t CallGamepadAxis(void* ctx, int32_t device_id, int32_t axis, float x,
                        float y, float z) {
  auto* c = static_cast<SinkCallContext*>(ctx);
  if (c == nullptr || c->sink.gamepad.axis == nullptr) {
    return 0;
  }
  return c->Record(
      c->sink.gamepad.axis(c->sink.gamepad.context, device_id, axis, x, y, z));
}

MocktailRustInputCallbacks MakeCallbacks(const RobloxInputSink& sink) {
  MocktailRustInputCallbacks cb{};
  cb.has_mouse_move = sink.mouse_move != nullptr ? 1 : 0;
  cb.has_mouse_button = sink.mouse_button != nullptr ? 1 : 0;
  cb.has_mouse_wheel = sink.mouse_wheel != nullptr ? 1 : 0;
  cb.has_touch = sink.touch != nullptr ? 1 : 0;
  cb.has_key = sink.key != nullptr ? 1 : 0;
  cb.has_gamepad = sink.gamepad.valid() ? 1 : 0;
  cb.mouse_move = &CallMouseMove;
  cb.mouse_button = &CallMouseButton;
  cb.mouse_wheel = &CallMouseWheel;
  cb.touch = &CallTouch;
  cb.key = &CallKey;
  cb.end_text_focus = &CallEndTextFocus;
  cb.gamepad_supported_key = &CallGamepadSupportedKey;
  cb.gamepad_supported_motion = &CallGamepadSupportedMotion;
  cb.gamepad_connect = &CallGamepadConnect;
  cb.gamepad_disconnect = &CallGamepadDisconnect;
  cb.gamepad_button = &CallGamepadButton;
  cb.gamepad_axis = &CallGamepadAxis;
  return cb;
}

RobloxInputDispatchResult ToDispatchResult(
    const MocktailRustInputDispatchResult& res, SinkCallContext* ctx,
    const char* err_buf) {
  const auto state = static_cast<RobloxInputDispatchState>(res.state);
  const auto kind = static_cast<RobloxInputEventKind>(res.kind);
  Status status = Status::Ok();
  switch (res.status_code) {
    case 1:
      status = InvalidArgument(err_buf[0] != '\0' ? err_buf : nullptr);
      break;
    case 2:
      status = Unsupported(err_buf[0] != '\0' ? err_buf : nullptr);
      break;
    case 3:
      status = Status::Error(StatusCode::kFailedPrecondition,
                             err_buf[0] != '\0' ? err_buf : "invalid state");
      break;
    case 4:
      status = Status::Error(StatusCode::kUnavailable,
                             err_buf[0] != '\0' ? err_buf : "unavailable");
      break;
    case 5:
      status = ctx != nullptr ? std::move(ctx->first_error)
                              : Status::Error(StatusCode::kPlatformError,
                                              "native input callback failed");
      break;
    default:
      break;
  }
  return {state, kind, std::move(status)};
}

}  // namespace

void RobloxInputRouter::RustStateDeleter::operator()(
    MocktailRustInputRouterState* ptr) const {
  mocktail_rust_input_router_free(ptr);
}

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
    : sink_(sink),
      text_editor_(sink.text, display_sink, clipboard),
      rust_state_(mocktail_rust_input_router_new()) {}

Status RobloxInputRouter::Activate(RobloxInputViewport viewport,
                                   bool initially_focused) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_input_router_activate(
      rust_state_.get(), ToRustViewport(viewport), initially_focused ? 1 : 0,
      err_buf.data(), err_buf.size());
  if (rc == 0) {
    return Status::Ok();
  }
  if (rc == 3) {
    return Status::Error(
        StatusCode::kFailedPrecondition,
        err_buf[0] != '\0' ? err_buf.data()
                           : "Roblox input router is already active");
  }
  return InvalidArgument(err_buf[0] != '\0' ? err_buf.data()
                                            : "input viewport is invalid");
}

Status RobloxInputRouter::Deactivate() {
  std::lock_guard<std::mutex> lock(mutex_);
  SinkCallContext ctx{sink_, &text_editor_};
  const MocktailRustInputCallbacks cb = MakeCallbacks(sink_);
  mocktail_rust_input_router_deactivate(rust_state_.get(), &cb, &ctx);
  return std::move(ctx.first_error);
}

Status RobloxInputRouter::BeginTextFocusSession(
    RobloxTextFocusSession session) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (mocktail_rust_input_router_is_active(rust_state_.get()) == 0) {
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
  if (mocktail_rust_input_router_is_active(rust_state_.get()) == 0) {
    return Result(RobloxInputDispatchState::kIgnoredInactive,
                  RobloxInputEventKind::kNone);
  }

  std::array<char, 256> err_buf{};
  SinkCallContext ctx{sink_, &text_editor_};
  const MocktailRustInputCallbacks cb = MakeCallbacks(sink_);

  if (const auto* resized =
          std::get_if<platform::WindowResizedEvent>(&event.payload)) {
    const MocktailRustInputViewport vp{
        resized->logical_width, resized->logical_height, resized->pixel_width,
        resized->pixel_height, resized->density_scale};
    const auto res = mocktail_rust_input_router_handle_viewport(
        rust_state_.get(), vp, err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* focus =
          std::get_if<platform::WindowFocusEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_focus(
        rust_state_.get(), focus->focused ? 1 : 0, &cb, &ctx);
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* connection =
          std::get_if<platform::GamepadConnectionEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_gamepad_connection(
        rust_state_.get(), connection->instance_id,
        connection->connected ? 1 : 0, connection->remapped ? 1 : 0,
        static_cast<int32_t>(connection->descriptor.family),
        connection->descriptor.name.c_str(), connection->descriptor.buttons,
        connection->descriptor.axes, &cb, &ctx, err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* button =
          std::get_if<platform::GamepadButtonEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_gamepad_button(
        rust_state_.get(), button->instance_id, button->button,
        button->pressed ? 1 : 0, &cb, &ctx, err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* axis =
          std::get_if<platform::GamepadAxisEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_gamepad_axis(
        rust_state_.get(), axis->instance_id, axis->axis, axis->value, &cb,
        &ctx, err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* motion =
          std::get_if<platform::MouseMotionEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_mouse_motion(
        rust_state_.get(), motion->x, motion->y, motion->delta_x,
        motion->delta_y, motion->relative_mode ? 1 : 0, &cb, &ctx,
        err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* mb =
          std::get_if<platform::MouseButtonEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_mouse_button(
        rust_state_.get(), mb->pressed ? 1 : 0, mb->button, mb->x, mb->y,
        mb->relative_mode ? 1 : 0, &cb, &ctx, err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* wheel =
          std::get_if<platform::MouseWheelEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_mouse_wheel(
        rust_state_.get(), wheel->delta_y, wheel->mouse_x, wheel->mouse_y,
        wheel->relative_mode ? 1 : 0, &cb, &ctx, err_buf.data(),
        err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* touch = std::get_if<platform::TouchEvent>(&event.payload)) {
    const auto res = mocktail_rust_input_router_handle_touch(
        rust_state_.get(), static_cast<int32_t>(touch->action), touch->touch_id,
        touch->finger_id, touch->x, touch->y, &cb, &ctx, err_buf.data(),
        err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (const auto* key = std::get_if<platform::KeyEvent>(&event.payload)) {
    mocktail_rust_input_router_prepare_routed_event(rust_state_.get());
    RobloxTextEditResult text_result = text_editor_.HandleKey(*key);
    if (text_result.handled) {
      const auto res = mocktail_rust_input_router_record_text_result(
          rust_state_.get(), 1, text_result.dispatched ? 1 : 0,
          text_result.status.ok() ? 0 : 1);
      return Result(static_cast<RobloxInputDispatchState>(res.state),
                    RobloxInputEventKind::kText, std::move(text_result.status));
    }
    const auto res = mocktail_rust_input_router_handle_key(
        rust_state_.get(), key->pressed ? 1 : 0, key->repeat ? 1 : 0,
        key->scancode, key->keycode, &cb, &ctx, err_buf.data(), err_buf.size());
    return ToDispatchResult(res, &ctx, err_buf.data());
  }

  if (std::holds_alternative<platform::TextInputEvent>(event.payload) ||
      std::holds_alternative<platform::TextEditingEvent>(event.payload)) {
    mocktail_rust_input_router_prepare_routed_event(rust_state_.get());
    RobloxTextEditResult text_result;
    if (const auto* input =
            std::get_if<platform::TextInputEvent>(&event.payload)) {
      text_result = text_editor_.HandleTextInput(*input);
    } else if (const auto* editing =
                   std::get_if<platform::TextEditingEvent>(&event.payload)) {
      text_result = text_editor_.HandleTextEditing(*editing);
    }
    const auto res = mocktail_rust_input_router_record_text_result(
        rust_state_.get(), text_result.handled ? 1 : 0,
        text_result.dispatched ? 1 : 0, text_result.status.ok() ? 0 : 1);
    if (!text_result.handled) {
      return Result(static_cast<RobloxInputDispatchState>(res.state),
                    RobloxInputEventKind::kText,
                    Unsupported("text input has no focused Roblox TextBox"));
    }
    return Result(static_cast<RobloxInputDispatchState>(res.state),
                  RobloxInputEventKind::kText, std::move(text_result.status));
  }

  return Result(RobloxInputDispatchState::kIgnoredUnsupported,
                RobloxInputEventKind::kNone,
                Unsupported("platform event has no Roblox input route"));
}

RobloxInputSnapshot RobloxInputRouter::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  MocktailRustInputSnapshot raw{};
  mocktail_rust_input_router_snapshot(rust_state_.get(), &raw);
  RobloxInputSnapshot snapshot;
  snapshot.active = raw.active != 0;
  snapshot.focused = raw.focused != 0;
  snapshot.viewport = FromRustViewport(raw.viewport);
  snapshot.mouse_events = raw.mouse_events;
  snapshot.touch_events = raw.touch_events;
  snapshot.keyboard_events = raw.keyboard_events;
  snapshot.ignored_text_events = raw.ignored_text_events;
  snapshot.text_events = raw.text_events;
  const RobloxTextEditorSnapshot text = text_editor_.Snapshot();
  snapshot.text_focus_generation = text.focused ? text.generation : 0;
  snapshot.native_errors = raw.native_errors;
  snapshot.active_mouse_buttons = raw.active_mouse_buttons;
  snapshot.active_touches = raw.active_touches;
  snapshot.active_keys = raw.active_keys;
  snapshot.gamepad_events = raw.gamepad_events;
  snapshot.detected_gamepads = raw.detected_gamepads;
  snapshot.connected_gamepads = raw.connected_gamepads;
  return snapshot;
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
