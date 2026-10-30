#include "window/video_driver_policy.h"
#include "mocktail/mocktail_rust.h"

#include <algorithm>
#include <system_error>
#include <unistd.h>

namespace mocktail {
namespace window {

VideoDriverChoice ResolveVideoDriverChoice(
    const VideoDriverPolicyInput& input) {
  const int choice = mocktail_rust_video_driver_resolve(
      input.has_explicit_sdl_driver ? 1 : 0,
      input.force_wayland ? 1 : 0,
      input.force_x11 ? 1 : 0,
      input.has_x11_display ? 1 : 0,
      input.uses_direct_vulkan ? 1 : 0,
      input.has_nvidia_kernel_driver ? 1 : 0,
      input.has_wayland_session ? 1 : 0,
      input.prefer_wayland ? 1 : 0);
  switch (choice) {
    case 1:
      return VideoDriverChoice::kWayland;
    case 2:
      return VideoDriverChoice::kX11;
    case 3:
      return VideoDriverChoice::kNvidiaDirectVulkanX11;
    default:
      return VideoDriverChoice::kSdlDefault;
  }
}

const char* VideoDriverChoiceName(VideoDriverChoice choice) {
  switch (choice) {
    case VideoDriverChoice::kWayland:
      return "wayland";
    case VideoDriverChoice::kX11:
    case VideoDriverChoice::kNvidiaDirectVulkanX11:
      return "x11";
    case VideoDriverChoice::kSdlDefault:
      return nullptr;
  }
  return nullptr;
}

bool HasNvidiaKernelDriver(const std::filesystem::path& proc_version,
                          const std::filesystem::path& pci_driver) {
  if (access(proc_version.c_str(), R_OK) == 0) {
    return true;
  }

  std::error_code error;
  return std::filesystem::is_directory(pci_driver, error);
}

bool HasAvailableVideoDriverCandidate(
    std::string_view requested,
    const std::vector<std::string_view>& available_drivers) {
  std::string joined;
  for (std::size_t i = 0; i < available_drivers.size(); ++i) {
    if (i > 0) joined.push_back(',');
    joined.append(available_drivers[i]);
  }
  std::string req(requested);
  return mocktail_rust_video_driver_has_candidate(req.c_str(), joined.c_str()) == 1;
}

}  // namespace window
}  // namespace mocktail
