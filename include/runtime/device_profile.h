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

#ifndef MOCKTAIL_RUNTIME_DEVICE_PROFILE_H_
#define MOCKTAIL_RUNTIME_DEVICE_PROFILE_H_

#include <cstddef>
#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

enum class DeviceClass {
  kPc,
  kMobile,
  kConsole,
};

// One immutable profile keeps Roblox admission, pseudo-Android hardware
// identity, and built-in input capabilities consistent. The guest ABI and
// client-settings group remain Android/GoogleAndroidApp.
struct DeviceProfile {
  std::string name;
  std::string cache_key;
  DeviceClass device_class = DeviceClass::kPc;
  std::string platform_name;
  std::string display_name;
  std::string manufacturer;
  std::string model;
  std::string brand;
  std::string device_code;
  std::string device_sku;
  std::string soc_model;
  std::string roblox_http_user_agent;
  bool touch_enabled = false;
  bool mouse_enabled = true;
  bool keyboard_enabled = true;
  bool pc_hardware = true;
};

inline constexpr std::string_view kDefaultDeviceProfileName = "pc-windows-11";
// These identifiers select Roblox server-side admission only. They never
// replace the Android APK ABI or its GoogleAndroidApp client-settings group.
inline constexpr std::string_view kRobloxDesktopHttpUserAgent =
    "Roblox/WinInet";
// The current Android-host playability endpoint recognizes this as console.
// PlayStation-labelled user agents currently fall back to desktop admission,
// so the PS5 marketing profile keeps this transport-only classifier.
inline constexpr std::string_view kRobloxConsoleAdmissionUserAgent =
    "Roblox/XboxOne";

// Accepts canonical names and the convenient pc/mobile/console aliases.
// Returned profiles have static lifetime.
const DeviceProfile* FindDeviceProfile(std::string_view name);
bool IsValidDeviceProfileValue(std::string_view value, std::size_t maximum);
std::string BuildCustomDeviceProfileCacheKey(const DeviceProfile& profile);
std::string_view DeviceClassName(DeviceClass device_class);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_DEVICE_PROFILE_H_
