#include <SDL3/SDL_gamepad.h>
#include "mocktail/mocktail_rust.h"

#include "runtime/roblox_input_router.h"

namespace mocktail {
namespace runtime {
namespace {

static_assert(SDL_GAMEPAD_AXIS_COUNT == 6);
static_assert(SDL_GAMEPAD_BUTTON_COUNT <= 32);
static_assert(SDL_GAMEPAD_BUTTON_SOUTH == 0);
static_assert(SDL_GAMEPAD_BUTTON_EAST == 1);
static_assert(SDL_GAMEPAD_BUTTON_WEST == 2);
static_assert(SDL_GAMEPAD_BUTTON_NORTH == 3);
static_assert(SDL_GAMEPAD_BUTTON_BACK == 4);
static_assert(SDL_GAMEPAD_BUTTON_START == 6);
static_assert(SDL_GAMEPAD_BUTTON_LEFT_STICK == 7);
static_assert(SDL_GAMEPAD_BUTTON_RIGHT_STICK == 8);
static_assert(SDL_GAMEPAD_BUTTON_LEFT_SHOULDER == 9);
static_assert(SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER == 10);
static_assert(SDL_GAMEPAD_BUTTON_DPAD_UP == 11);
static_assert(SDL_GAMEPAD_BUTTON_DPAD_DOWN == 12);
static_assert(SDL_GAMEPAD_BUTTON_DPAD_LEFT == 13);
static_assert(SDL_GAMEPAD_BUTTON_DPAD_RIGHT == 14);

}  // namespace

int32_t MapSdlGamepadButtonToAndroid(uint8_t button) {
  return mocktail_rust_gamepad_button_to_android(button);
}

int32_t RobloxGamepadType(platform::GamepadFamily family) {
  int fam = 0;
  switch (family) {
    case platform::GamepadFamily::kPlayStation4:
      fam = 2;
      break;
    case platform::GamepadFamily::kPlayStation5:
      fam = 3;
      break;
    case platform::GamepadFamily::kXbox:
      fam = 1;
      break;
    default:
      fam = 0;
      break;
  }
  return mocktail_rust_roblox_gamepad_type(fam);
}

}  // namespace runtime
}  // namespace mocktail
