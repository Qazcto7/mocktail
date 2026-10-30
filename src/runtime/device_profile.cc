#include "runtime/device_profile.h"

#include <array>
#include <cstdint>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

const std::array<DeviceProfile, 3> kProfiles = {{
    {
        "pc-windows-11",
        "pc-windows-11",
        DeviceClass::kPc,
        "Windows",
        "Windows 11 PC",
        "Microsoft",
        "Windows 11 PC",
        "Microsoft",
        "windows11",
        "windows-11-x86_64",
        "x86_64",
        std::string(kRobloxDesktopHttpUserAgent),
        false,
        true,
        true,
        true,
    },
    {
        "mobile-pixel-7",
        "mobile-pixel-7",
        DeviceClass::kMobile,
        "Android",
        "Google Pixel 7",
        "Google",
        "Pixel 7",
        "google",
        "panther",
        "panther",
        "Google Tensor G2",
        {},
        true,
        false,
        false,
        false,
    },
    {
        "console-ps5",
        "console-ps5",
        DeviceClass::kConsole,
        "PlayStation",
        "PlayStation 5",
        "Sony Interactive Entertainment",
        "PlayStation 5",
        "PlayStation",
        "prospero",
        "ps5",
        "AMD custom Zen 2 / RDNA 2",
        std::string(kRobloxConsoleAdmissionUserAgent),
        false,
        true,
        true,
        false,
    },
}};

std::string CanonicalName(std::string_view name) {
  const std::string name_str(name);
  std::array<char, 64> buf{};
  if (mocktail_rust_canonical_device_profile_name(
          name_str.c_str(), buf.data(), buf.size()) == 0) {
    return std::string(buf.data());
  }
  return name_str;
}

}  // namespace

const DeviceProfile* FindDeviceProfile(std::string_view name) {
  const std::string canonical = CanonicalName(name);
  for (const DeviceProfile& profile : kProfiles) {
    if (profile.name == canonical) {
      return &profile;
    }
  }
  return nullptr;
}

bool IsValidDeviceProfileValue(std::string_view value, std::size_t maximum) {
  const std::string s(value);
  return mocktail_rust_is_valid_device_profile_value(s.c_str(), maximum) == 1;
}

std::string BuildCustomDeviceProfileCacheKey(const DeviceProfile& profile) {
  std::array<char, 256> out_key{};
  if (mocktail_rust_build_device_profile_cache_key(
          profile.name.c_str(),
          profile.platform_name.c_str(),
          profile.display_name.c_str(),
          profile.manufacturer.c_str(),
          profile.model.c_str(),
          profile.brand.c_str(),
          profile.device_code.c_str(),
          profile.device_sku.c_str(),
          profile.soc_model.c_str(),
          out_key.data(),
          out_key.size()) == 0) {
    return std::string(out_key.data());
  }
  return profile.name + "-custom-error";
}

std::string_view DeviceClassName(DeviceClass device_class) {
  switch (device_class) {
    case DeviceClass::kPc:
      return "pc";
    case DeviceClass::kMobile:
      return "mobile";
    case DeviceClass::kConsole:
      return "console";
  }
  return "unknown";
}

}  // namespace runtime
}  // namespace mocktail
