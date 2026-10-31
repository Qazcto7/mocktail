#include "runtime/roblox_capability_resolver.h"
#include "mocktail/mocktail_rust.h"

#include <utility>

namespace mocktail {
namespace runtime {
namespace {

template <typename Function>
Function ResolveTyped(const RobloxSymbolLookup& lookup,
                      const char* symbol_name) {
  return reinterpret_cast<Function>(lookup.Find(symbol_name));
}

template <typename Function>
void ResolveRequired(const RobloxSymbolLookup& lookup, const char* symbol_name,
                     Function* destination,
                     std::vector<std::string>* missing_symbols) {
  *destination = ResolveTyped<Function>(lookup, symbol_name);
  if (*destination == nullptr) {
    missing_symbols->emplace_back(symbol_name);
  }
}

template <typename... Functions>
bool AllPresent(Functions... functions) {
  return (... && (functions != nullptr));
}

void ResolveStartupSymbols(const RobloxSymbolLookup& lookup,
                           RobloxCapabilityRequirements requirements,
                           RobloxStartupSymbols* symbols,
                           RobloxStartupCapabilityFlags* flags,
                           std::vector<std::string>* missing_symbols) {
  ResolveRequired(lookup, "JNI_OnLoad", &symbols->jni_on_load, missing_symbols);
  ResolveRequired(
      lookup,
      "Java_com_roblox_engine_jni_NativeGLInterface_nativeGameGlobalInit",
      &symbols->game_global_init, missing_symbols);
  ResolveRequired(
      lookup,
      "Java_com_roblox_engine_jni_NativeGLInterface_nativeUpdateAdapterInit",
      &symbols->update_adapter_init, missing_symbols);
  ResolveRequired(lookup,
                  "Java_com_roblox_engine_jni_NativeGLInterface_"
                  "nativeAppBridgeV2InitWithParams",
                  &symbols->app_bridge_v2_init_with_params, missing_symbols);
  ResolveRequired(lookup,
                  "Java_com_roblox_engine_jni_NativeGLInterface_"
                  "nativeAppBridgeStartLuaAppDM",
                  &symbols->app_bridge_start_lua_app_dm, missing_symbols);
  ResolveRequired(lookup,
                  "Java_com_roblox_engine_jni_NativeGLInterface_"
                  "nativeAppBridgeV2StartAppWithParams",
                  &symbols->app_bridge_v2_start_app_with_params,
                  missing_symbols);

  const char* surface_app_symbol =
      "Java_com_roblox_engine_jni_NativeGLInterface_"
      "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams";
  if (requirements.windowed) {
    ResolveRequired(
        lookup, surface_app_symbol,
        &symbols->app_bridge_v2_update_surface_app_with_platform_params,
        missing_symbols);
  } else {
    symbols->app_bridge_v2_update_surface_app_with_platform_params =
        ResolveTyped<NativeAppBridgeV2UpdateSurfaceAppFn>(lookup,
                                                          surface_app_symbol);
  }

  symbols->call_messages_from_main_thread =
      ResolveTyped<NativeCallMessagesFromMainThreadFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeGLInterface_"
          "nativeCallMessagesFromMainThread");
  symbols->app_bridge_v2_start_game_with_param =
      ResolveTyped<NativeAppBridgeV2StartGameWithParamFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeGLInterface_"
          "nativeAppBridgeV2StartGameWithParam");
  symbols->app_bridge_v2_update_surface_game_with_platform_params =
      ResolveTyped<NativeAppBridgeV2UpdateSurfaceGameFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeGLInterface_"
          "nativeAppBridgeV2UpdateSurfaceGameWithPlatformParams");

  int32_t startup_bitmask = 0;
  mocktail_rust_evaluate_startup_flags(
      symbols->app_bridge_v2_update_surface_app_with_platform_params != nullptr,
      symbols->call_messages_from_main_thread != nullptr,
      symbols->app_bridge_v2_start_game_with_param != nullptr,
      symbols->app_bridge_v2_update_surface_game_with_platform_params != nullptr,
      &startup_bitmask);
  flags->has_surface_app = (startup_bitmask & (1 << 0)) != 0;
  flags->has_message_pump = (startup_bitmask & (1 << 1)) != 0;
  flags->has_start_game = (startup_bitmask & (1 << 2)) != 0;
  flags->has_surface_game = (startup_bitmask & (1 << 3)) != 0;
}

void ResolveInputSymbols(const RobloxSymbolLookup& lookup,
                         RobloxInputSymbols* symbols,
                         RobloxInputCapabilityFlags* flags) {
  symbols->gamepad_axis_event = ResolveTyped<NativeGamepadAxisEventFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativeGamepadAxisEvent");
  symbols->gamepad_button_event = ResolveTyped<NativeGamepadButtonEventFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativeGamepadButtonEvent");
  symbols->gamepad_connect_event_with_gamepad_type =
      ResolveTyped<NativeGamepadConnectEventWithGamepadTypeFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeGamepadConnectEventWithGamepadType");
  symbols->gamepad_disconnect_event =
      ResolveTyped<NativeGamepadDisconnectEventFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeGamepadDisconnectEvent");
  symbols->get_main_window_is_mouse_locked_center =
      ResolveTyped<NativeGetMainWindowIsMouseLockedCenterFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeGetMainWindowIsMouseLockedCenter");
  symbols->pass_accelerometer_change = ResolveTyped<NativePassVector3Fn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassAccelerometerChange");
  symbols->pass_gravity_change = ResolveTyped<NativePassVector3Fn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassGravityChange");
  symbols->pass_gyroscope_change = ResolveTyped<NativePassGyroscopeChangeFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassGyroscopeChange");
  symbols->pass_input = ResolveTyped<NativePassInputFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_nativePassInput");
  symbols->pass_long_press_gesture = ResolveTyped<NativePassLongPressGestureFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassLongPressGesture");
  symbols->pass_mouse_button = ResolveTyped<NativePassMouseButtonFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassMouseButton");
  symbols->pass_mouse_move = ResolveTyped<NativePassMouseVector4Fn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_nativePassMouseMove");
  symbols->pass_mouse_pan = ResolveTyped<NativePassMouseVector4Fn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_nativePassMousePan");
  symbols->pass_mouse_pinch = ResolveTyped<NativePassMouseVector3Fn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_nativePassMousePinch");
  symbols->pass_mouse_wheel = ResolveTyped<NativePassMouseVector3Fn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_nativePassMouseWheel");
  symbols->pass_key_event = ResolveTyped<NativePassKeyEventFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeGLInterface_nativePassKeyEvent");
  symbols->sync_textbox_text_and_cursor_position2 =
      ResolveTyped<NativeSyncTextboxTextAndCursorPosition2Fn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeGLInterface_"
          "syncTextboxTextAndCursorPosition2");
  symbols->get_text_box_info = ResolveTyped<NativeGetTextBoxInfoFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeGLInterface_nativeGetTextBoxInfo");
  symbols->pass_text = ResolveTyped<NativePassTextFn>(
      lookup, "Java_com_roblox_engine_jni_NativeGLInterface_nativePassText");
  symbols->return_pressed_from_on_screen_keyboard =
      ResolveTyped<NativeTextboxHandleFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeGLInterface_"
          "nativeReturnPressedFromOnScreenKeyboard");
  symbols->release_focus = ResolveTyped<NativeTextboxHandleFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeGLInterface_nativeReleaseFocus");
  symbols->pass_pan_gesture_multitouch =
      ResolveTyped<NativePassPanGestureMultitouchFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativePassPanGestureMultitouch");
  symbols->pass_pan_gesture_with_velocity =
      ResolveTyped<NativePassGestureWithVelocityFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativePassPanGestureWithVelocity");
  symbols->pass_pinch_gesture = ResolveTyped<NativePassGestureWithVelocityFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassPinchGesture");
  symbols->pass_rotate_gesture = ResolveTyped<NativePassGestureWithVelocityFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassRotateGesture");
  symbols->pass_swipe_gesture = ResolveTyped<NativePassLongPressGestureFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativePassSwipeGesture");
  symbols->pass_tap_gesture = ResolveTyped<NativePassTapGestureFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_nativePassTapGesture");
  symbols->set_accelerometer_enabled = ResolveTyped<NativeSetSensorEnabledFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativeSetAccelerometerEnabled");
  symbols->set_gamepad_supported_key_with_gamepad_type =
      ResolveTyped<NativeSetGamepadSupportedKeyWithGamepadTypeFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeSetGamepadSupportedKeyWithGamepadType");
  symbols->set_gamepad_supported_motion_with_gamepad_type =
      ResolveTyped<NativeSetGamepadSupportedMotionWithGamepadTypeFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeSetGamepadSupportedMotionWithGamepadType");
  symbols->set_gyroscope_enabled = ResolveTyped<NativeSetSensorEnabledFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativeSetGyroscopeEnabled");
  symbols->set_tv_remote_supported_key =
      ResolveTyped<NativeSetTvRemoteSupportedKeyFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeSetTVRemoteSupportedKey");
  symbols->tv_remote_button_event = ResolveTyped<NativeTvRemoteButtonEventFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativeTVRemoteButtonEvent");
  symbols->tv_remote_connect_event = ResolveTyped<NativeTvRemoteConnectEventFn>(
      lookup,
      "Java_com_roblox_engine_jni_NativeInputInterface_"
      "nativeTVRemoteConnectEvent");
  symbols->tv_remote_disconnect_event =
      ResolveTyped<NativeTvRemoteConnectEventFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeTVRemoteDisconnectEvent");
  symbols->update_screen_orientation =
      ResolveTyped<NativeUpdateScreenOrientationFn>(
          lookup,
          "Java_com_roblox_engine_jni_NativeInputInterface_"
          "nativeUpdateScreenOrientation");

  MocktailRustCapabilityInputSymbolsPresence presence{};
  presence.has_gamepad_axis_event = symbols->gamepad_axis_event != nullptr;
  presence.has_gamepad_button_event = symbols->gamepad_button_event != nullptr;
  presence.has_gamepad_connect_event_with_gamepad_type = symbols->gamepad_connect_event_with_gamepad_type != nullptr;
  presence.has_gamepad_disconnect_event = symbols->gamepad_disconnect_event != nullptr;
  presence.has_get_main_window_is_mouse_locked_center = symbols->get_main_window_is_mouse_locked_center != nullptr;
  presence.has_pass_accelerometer_change = symbols->pass_accelerometer_change != nullptr;
  presence.has_pass_gravity_change = symbols->pass_gravity_change != nullptr;
  presence.has_pass_gyroscope_change = symbols->pass_gyroscope_change != nullptr;
  presence.has_pass_input = symbols->pass_input != nullptr;
  presence.has_pass_long_press_gesture = symbols->pass_long_press_gesture != nullptr;
  presence.has_pass_mouse_button = symbols->pass_mouse_button != nullptr;
  presence.has_pass_mouse_move = symbols->pass_mouse_move != nullptr;
  presence.has_pass_mouse_pan = symbols->pass_mouse_pan != nullptr;
  presence.has_pass_mouse_pinch = symbols->pass_mouse_pinch != nullptr;
  presence.has_pass_mouse_wheel = symbols->pass_mouse_wheel != nullptr;
  presence.has_pass_key_event = symbols->pass_key_event != nullptr;
  presence.has_sync_textbox_text_and_cursor_position2 = symbols->sync_textbox_text_and_cursor_position2 != nullptr;
  presence.has_get_text_box_info = symbols->get_text_box_info != nullptr;
  presence.has_pass_text = symbols->pass_text != nullptr;
  presence.has_return_pressed_from_on_screen_keyboard = symbols->return_pressed_from_on_screen_keyboard != nullptr;
  presence.has_release_focus = symbols->release_focus != nullptr;
  presence.has_pass_pan_gesture_multitouch = symbols->pass_pan_gesture_multitouch != nullptr;
  presence.has_pass_pan_gesture_with_velocity = symbols->pass_pan_gesture_with_velocity != nullptr;
  presence.has_pass_pinch_gesture = symbols->pass_pinch_gesture != nullptr;
  presence.has_pass_rotate_gesture = symbols->pass_rotate_gesture != nullptr;
  presence.has_pass_swipe_gesture = symbols->pass_swipe_gesture != nullptr;
  presence.has_pass_tap_gesture = symbols->pass_tap_gesture != nullptr;
  presence.has_set_accelerometer_enabled = symbols->set_accelerometer_enabled != nullptr;
  presence.has_set_gamepad_supported_key_with_gamepad_type = symbols->set_gamepad_supported_key_with_gamepad_type != nullptr;
  presence.has_set_gamepad_supported_motion_with_gamepad_type = symbols->set_gamepad_supported_motion_with_gamepad_type != nullptr;
  presence.has_set_gyroscope_enabled = symbols->set_gyroscope_enabled != nullptr;
  presence.has_set_tv_remote_supported_key = symbols->set_tv_remote_supported_key != nullptr;
  presence.has_tv_remote_button_event = symbols->tv_remote_button_event != nullptr;
  presence.has_tv_remote_connect_event = symbols->tv_remote_connect_event != nullptr;
  presence.has_tv_remote_disconnect_event = symbols->tv_remote_disconnect_event != nullptr;
  presence.has_update_screen_orientation = symbols->update_screen_orientation != nullptr;

  MocktailRustCapabilityInputFlags rust_flags{};
  mocktail_rust_capability_eval_input_flags(&presence, &rust_flags);

  flags->gamepad_api = rust_flags.gamepad_api == 1
                           ? RobloxGamepadApi::kWithGamepadType
                           : RobloxGamepadApi::kUnsupported;
  if (rust_flags.clear_partial_gamepad) {
    symbols->gamepad_connect_event_with_gamepad_type = nullptr;
    symbols->set_gamepad_supported_key_with_gamepad_type = nullptr;
    symbols->set_gamepad_supported_motion_with_gamepad_type = nullptr;
  }
  flags->has_gamepad_events = rust_flags.has_gamepad_events;
  flags->has_mouse = rust_flags.has_mouse;
  flags->has_touch = rust_flags.has_touch;
  flags->has_hardware_keyboard = rust_flags.has_hardware_keyboard;
  flags->has_text_input = rust_flags.has_text_input;
  flags->has_gestures = rust_flags.has_gestures;
  flags->has_sensors = rust_flags.has_sensors;
  flags->has_tv_remote = rust_flags.has_tv_remote;
  flags->has_screen_orientation = rust_flags.has_screen_orientation;
}

}  // namespace

void* RobloxSymbolLookup::Find(const char* symbol_name) const {
  if (callback_ == nullptr || symbol_name == nullptr ||
      symbol_name[0] == '\0') {
    return nullptr;
  }
  return callback_(context_, symbol_name);
}

RobloxCapabilityResolution ResolveRobloxCapabilities(
    const RobloxSymbolLookup& lookup,
    RobloxCapabilityRequirements requirements) {
  RobloxCapabilityResolution resolution;
  if (!lookup.valid()) {
    resolution.status_ = RobloxCapabilityResolutionStatus::kInvalidLookup;
    return resolution;
  }

  ResolveStartupSymbols(lookup, requirements, &resolution.capabilities_.startup,
                        &resolution.capabilities_.startup_flags,
                        &resolution.missing_required_symbols_);
  ResolveInputSymbols(lookup, &resolution.capabilities_.input,
                      &resolution.capabilities_.input_flags);

  resolution.status_ =
      resolution.missing_required_symbols_.empty()
          ? RobloxCapabilityResolutionStatus::kReady
          : RobloxCapabilityResolutionStatus::kMissingRequiredSymbols;
  return resolution;
}

const char* RobloxCapabilityResolutionStatusName(
    RobloxCapabilityResolutionStatus status) {
  switch (status) {
    case RobloxCapabilityResolutionStatus::kReady:
      return "Ready";
    case RobloxCapabilityResolutionStatus::kInvalidLookup:
      return "InvalidLookup";
    case RobloxCapabilityResolutionStatus::kMissingRequiredSymbols:
      return "MissingRequiredSymbols";
  }
  return "Unknown";
}

const char* RobloxGamepadApiName(RobloxGamepadApi api) {
  switch (api) {
    case RobloxGamepadApi::kUnsupported:
      return "Unsupported";
    case RobloxGamepadApi::kWithGamepadType:
      return "WithGamepadType";
  }
  return "Unknown";
}

}  // namespace runtime
}  // namespace mocktail
