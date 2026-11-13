#include "runtime/graphics_launch_policy.h"

#include "mocktail/mocktail_rust.h"
#include "runtime/frame_rate_policy.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace mocktail {
namespace runtime {
namespace {

constexpr char kVulkanClientSettingsOverrides[] =
    R"({"FStringGraphicsVulkanShaderMTDenyPattern":"4318:.*"})";

constexpr const char* kIcdDirectories[] = {
    "/usr/share/vulkan/icd.d",
    "/etc/vulkan/icd.d",
    "/usr/local/share/vulkan/icd.d",
};

#if defined(__aarch64__)
constexpr int32_t kTargetIsAarch64 = 1;
#else
constexpr int32_t kTargetIsAarch64 = 0;
#endif

struct HostGpus {
  bool intel = false;
  bool intel_haswell = false;
  bool nvidia = false;
  bool amd = false;
};

bool IsHaswellOrIvyBridgeIntel(unsigned int device_id) {
  return mocktail_rust_graphics_is_haswell_intel(device_id) != 0;
}

bool SetValue(const char* name, const std::string& value, std::string* error) {
  if (setenv(name, value.c_str(), 1) == 0) {
    return true;
  }
  if (error != nullptr) {
    *error = std::string("cannot publish resolved graphics setting: ") + name;
  }
  return false;
}

bool SetDefault(const char* name, const std::string& value,
                std::string* error) {
  const char* current = std::getenv(name);
  if (current != nullptr && current[0] != '\0') {
    return true;
  }
  return SetValue(name, value, error);
}

bool IsStrictOpenGlName(const std::string& name) {
  return name == "opengl" || name == "gles";
}

bool EnvIsOff(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr &&
         (std::strcmp(value, "0") == 0 || std::strcmp(value, "off") == 0 ||
          std::strcmp(value, "igpu") == 0);
}

bool ParsePciVendor(const std::string& raw, unsigned int* vendor) {
  if (vendor == nullptr || raw.empty()) {
    return false;
  }
  uint32_t parsed = 0;
  if (mocktail_rust_graphics_parse_pci_hex(raw.c_str(), &parsed) == 0) {
    return false;
  }
  *vendor = parsed;
  return true;
}

HostGpus DetectHostGpus() {
  HostGpus gpus;
  for (int index = 0; index < 16; ++index) {
    const std::string path = "/sys/class/drm/card" + std::to_string(index) +
                             "/device/vendor";
    std::ifstream input(path);
    std::string raw;
    unsigned int vendor = 0;
    if (!(input >> raw) || !ParsePciVendor(raw, &vendor)) {
      continue;
    }
    if (vendor == 0x8086) {
      gpus.intel = true;
      const std::string dev_path = "/sys/class/drm/card" + std::to_string(index) +
                                   "/device/device";
      std::ifstream dev_input(dev_path);
      std::string dev_raw;
      unsigned int device_id = 0;
      if ((dev_input >> dev_raw) && ParsePciVendor(dev_raw, &device_id)) {
        if (IsHaswellOrIvyBridgeIntel(device_id)) {
          gpus.intel_haswell = true;
        }
      }
    } else if (vendor == 0x10de) {
      gpus.nvidia = true;
    } else if (vendor == 0x1002) {
      gpus.amd = true;
    }
  }
  return gpus;
}

std::string FindIcdFile(const char* filename_needle) {
  if (filename_needle == nullptr || filename_needle[0] == '\0') {
    return {};
  }
  std::vector<std::filesystem::path> directories;
  for (const char* directory : kIcdDirectories) {
    directories.emplace_back(directory);
  }
  return SelectVulkanIcdManifest(directories, filename_needle);
}

std::string SelectHardwareIcd(const HostGpus& gpus) {
  const bool prefer_discrete = !EnvIsOff("DRI_PRIME") &&
                               !EnvIsOff("__NV_PRIME_RENDER_OFFLOAD");
  if (prefer_discrete && gpus.nvidia) {
    std::string nvidia = FindIcdFile("nvidia_icd");
    if (nvidia.empty()) {
      nvidia = FindIcdFile("nouveau_icd");
    }
    if (!nvidia.empty()) {
      return nvidia;
    }
  }
  if (prefer_discrete && gpus.amd) {
    const std::string amd = FindIcdFile("radeon_icd");
    if (!amd.empty()) {
      return amd;
    }
  }
  if (gpus.intel) {
    if (gpus.intel_haswell) {
      std::string hasvk = FindIcdFile("intel_hasvk_icd");
      if (!hasvk.empty()) {
        return hasvk;
      }
    }
    std::string intel = FindIcdFile("intel_icd");
    if (intel.empty()) {
      intel = FindIcdFile("intel_hasvk_icd");
    }
    return intel;
  }
  if (gpus.nvidia) {
    std::string nvidia = FindIcdFile("nvidia_icd");
    if (nvidia.empty()) {
      nvidia = FindIcdFile("nouveau_icd");
    }
    return nvidia;
  }
  if (gpus.amd) {
    return FindIcdFile("radeon_icd");
  }
  return {};
}

// Match Mesa ANV: 75% of RAM when the machine has more than 4GiB, else 50%.
// Forcing 50 on an 8GiB UHD 620 iGPU advertises a smaller Vk heap than ANV
// would, which increases BO eviction inside GEM_EXECBUFFER2.
const char* AnvSysMemLimitPercent() {
  std::ifstream input("/proc/meminfo");
  std::string line;
  std::string meminfo;
  while (std::getline(input, line)) {
    meminfo.append(line);
    meminfo.push_back('\n');
    if (line.rfind("MemTotal:", 0) == 0 || meminfo.size() >= 4096) {
      break;
    }
  }
  return mocktail_rust_graphics_anv_sys_mem_limit_percent(meminfo.c_str()) >= 75
             ? "75"
             : "50";
}

bool ApplyVulkanIcdPolicy(const HostGpus& gpus, std::string* error) {
  // Drop software/emulation ICDs even when the user already pinned a driver
  // list. Old loaders ignore this variable.
  if (!SetDefault("VK_LOADER_DRIVERS_DISABLE",
                  "lvp_icd:dzn_icd:virtio_icd", error)) {
    return false;
  }
  const char* existing_files = std::getenv("VK_DRIVER_FILES");
  const char* existing_icds = std::getenv("VK_ICD_FILENAMES");
  if ((existing_files != nullptr && existing_files[0] != '\0') ||
      (existing_icds != nullptr && existing_icds[0] != '\0')) {
    return true;
  }
  const std::string icd = SelectHardwareIcd(gpus);
  if (icd.empty()) {
    return true;
  }
  std::fprintf(stderr, "  [runtime] vulkan ICD=%s\n", icd.c_str());
  return SetDefault("VK_DRIVER_FILES", icd, error) &&
         SetDefault("VK_ICD_FILENAMES", icd, error);
}

bool RadvIcdSelected() {
  const char* manifests = std::getenv("VK_DRIVER_FILES");
  if (manifests == nullptr || manifests[0] == '\0') {
    manifests = std::getenv("VK_ICD_FILENAMES");
  }
  return mocktail_rust_graphics_is_radv_icd_list(manifests) != 0;
}

bool UsesCpuTextureOptions() {
  for (const char* name : {"MOCKTAIL_TEXTURE_OVERRIDE_DIR",
                            "MOCKTAIL_TEXTURE_DUMP_DIR",
                            "MOCKTAIL_SMALL_TEXTURE_UPSCALE"}) {
    const char* value = std::getenv(name);
    if (value != nullptr && value[0] != '\0') {
      return true;
    }
  }
  const char* advertise = std::getenv("MOCKTAIL_ADVERTISE_ETC2");
  return advertise != nullptr && std::strcmp(advertise, "0") == 0;
}

}  // namespace

std::string SelectVulkanIcdManifest(
    const std::vector<std::filesystem::path>& directories,
    std::string_view vendor) {
  if (vendor.empty()) {
    return {};
  }
  std::string dirs_nl;
  for (const std::filesystem::path& directory : directories) {
    if (!dirs_nl.empty()) {
      dirs_nl.push_back('\n');
    }
    dirs_nl.append(directory.string());
  }
  const std::string needle(vendor);
  std::array<char, 4096> selected{};
  if (mocktail_rust_graphics_select_icd_manifest(
          dirs_nl.c_str(), needle.c_str(), kTargetIsAarch64,
          selected.data(), selected.size()) == 0) {
    return selected.data();
  }
  return {};
}

bool ApplyGraphicsLaunchPolicy(const RuntimeConfig& config,
                               std::string* error) {
  if (!RuntimeConfig::IsValidPresentMode(config.present_mode())) {
    if (error != nullptr) *error = "cannot apply an invalid present mode";
    return false;
  }
  if (config.present_mode() != "auto" &&
      unsetenv("MESA_VK_WSI_PRESENT_MODE") != 0) {
    if (error != nullptr) *error = "cannot clear Mesa present mode override";
    return false;
  }
  if (config.graphics_backend() == GraphicsBackend::kUnknown) {
    if (error != nullptr) {
      *error = "cannot apply an unknown graphics backend";
    }
    return false;
  }

  const bool direct_vulkan =
      config.graphics_backend() == GraphicsBackend::kVulkan;
  if (!SetValue("MOCKTAIL_GRAPHICS_BACKEND",
                config.graphics_backend_name(), error) ||
      !SetValue("MOCKTAIL_PRELOAD_VULKAN_SHIM",
                direct_vulkan ? "1" : "0", error) ||
      !SetDefault("MOCKTAIL_REQUIRE_REAL_GRAPHICS", "1", error)) {
    return false;
  }

  if (IsStrictOpenGlName(config.graphics_backend_name()) &&
      (!SetValue("MOCKTAIL_DISABLE_AUTO_ANGLE_FALLBACK", "1", error) ||
       !SetValue("MOCKTAIL_SOFTWARE_WINDOW_FALLBACK", "0", error))) {
    return false;
  }

  if (direct_vulkan) {
    const HostGpus gpus = DetectHostGpus();
    if (!SetDefault("MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON",
                    kVulkanClientSettingsOverrides, error) ||
        !SetDefault("ANV_SYS_MEM_LIMIT", AnvSysMemLimitPercent(), error) ||
        // Move GEM_EXECBUFFER2 off the application thread onto Mesa's submit
        // worker so the render thread is not stuck in i915 ioctl.
        !SetDefault("MESA_VK_ENABLE_SUBMIT_THREAD", "1", error) ||
        !ApplyVulkanIcdPolicy(gpus, error)) {
      return false;
    }
    if (RadvIcdSelected() &&
        !SetDefault("vk_require_etc2",
                    UsesCpuTextureOptions() ? "false" : "true", error)) {
      return false;
    }
    // Low FRM only on Intel-only machines. Hybrid NVIDIA/AMD laptops should
    // keep the desktop quality default on the discrete GPU.
    if (gpus.intel && !gpus.nvidia && !gpus.amd &&
        !SetDefault("MOCKTAIL_GRAPHICS_QUALITY", "1", error)) {
      return false;
    }
  }
  return true;
}

}  // namespace runtime
}  // namespace mocktail
