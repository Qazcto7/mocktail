#include "mocktail/graphics/present_mode_policy.h"
#include "mocktail/mocktail_rust.h"

#include <algorithm>
#include <cstdlib>
#include <string>

namespace mocktail {
namespace graphics {
namespace {

std::string_view EnvironmentOr(const char *name, const char *fallback) {
  const char *value = std::getenv(name);
  if (value == nullptr || value[0] == '\0') {
    return fallback;
  }
  return value;
}

PresentModePolicy FromRustPolicy(int policy) {
  switch (policy) {
    case 0: return PresentModePolicy::kHostDefault;
    case 1: return PresentModePolicy::kVsync;
    case 2: return PresentModePolicy::kUnthrottled;
    case 3: return PresentModePolicy::kFifo;
    case 4: return PresentModePolicy::kMailbox;
    case 5: return PresentModePolicy::kImmediate;
    default: return PresentModePolicy::kHostDefault;
  }
}

int ToRustPolicy(PresentModePolicy policy) {
  switch (policy) {
    case PresentModePolicy::kHostDefault: return 0;
    case PresentModePolicy::kVsync: return 1;
    case PresentModePolicy::kUnthrottled: return 2;
    case PresentModePolicy::kFifo: return 3;
    case PresentModePolicy::kMailbox: return 4;
    case PresentModePolicy::kImmediate: return 5;
  }
  return 0;
}

} // namespace

PresentModePolicy ResolvePresentModePolicy(std::string_view vsync_value,
                                           std::string_view frame_rate_value,
                                           std::string_view present_mode) {
  const std::string vsync_str(vsync_value);
  const std::string frame_rate_str(frame_rate_value);
  const std::string present_mode_str(present_mode);
  const int policy = mocktail_rust_present_mode_resolve(
      vsync_str.c_str(), frame_rate_str.c_str(), present_mode_str.c_str());
  return FromRustPolicy(policy);
}

PresentModePolicy CachedPresentModePolicy() {
  static const PresentModePolicy policy = [] {
    return ResolvePresentModePolicy(
        EnvironmentOr("MOCKTAIL_VSYNC", "auto"),
        EnvironmentOr("MOCKTAIL_FRAME_RATE_LIMIT", "-1"),
        EnvironmentOr("MOCKTAIL_PRESENT_MODE", "auto"));
  }();
  return policy;
}

std::vector<VkPresentModeKHR>
FilterPresentModes(PresentModePolicy policy,
                   const std::vector<VkPresentModeKHR> &host_modes) {
  if (host_modes.empty()) {
    return {};
  }
  std::vector<uint32_t> in_modes(host_modes.size());
  for (std::size_t i = 0; i < host_modes.size(); ++i) {
    in_modes[i] = static_cast<uint32_t>(host_modes[i]);
  }
  std::vector<uint32_t> out_modes(host_modes.size());
  size_t out_count = 0;
  const int rc = mocktail_rust_present_mode_filter(
      ToRustPolicy(policy), in_modes.data(), in_modes.size(),
      out_modes.data(), out_modes.size(), &out_count);
  if (rc != 0 || out_count == 0) {
    return {};
  }
  std::vector<VkPresentModeKHR> result(out_count);
  for (std::size_t i = 0; i < out_count; ++i) {
    result[i] = static_cast<VkPresentModeKHR>(out_modes[i]);
  }
  return result;
}

std::optional<VkPresentModeKHR> ExplicitPresentMode(PresentModePolicy policy) {
  uint32_t mode = 0;
  if (mocktail_rust_present_mode_explicit(ToRustPolicy(policy), &mode) != 0) {
    return static_cast<VkPresentModeKHR>(mode);
  }
  return std::nullopt;
}

int ResolveSwapInterval(PresentModePolicy policy, int requested) {
  return mocktail_rust_present_mode_swap_interval(ToRustPolicy(policy), requested);
}

const char *PresentModeKhrName(VkPresentModeKHR mode) {
  switch (mode) {
  case VK_PRESENT_MODE_IMMEDIATE_KHR:
    return "immediate";
  case VK_PRESENT_MODE_MAILBOX_KHR:
    return "mailbox";
  case VK_PRESENT_MODE_FIFO_KHR:
    return "fifo";
  case VK_PRESENT_MODE_FIFO_RELAXED_KHR:
    return "fifo-relaxed";
  case VK_PRESENT_MODE_FIFO_LATEST_READY_KHR:
    return "fifo-latest-ready";
  default:
    return "other";
  }
}

const char *PresentModePolicyName(PresentModePolicy policy) {
  switch (policy) {
  case PresentModePolicy::kHostDefault:
    return "host-default";
  case PresentModePolicy::kVsync:
    return "vsync";
  case PresentModePolicy::kUnthrottled:
    return "unthrottled";
  case PresentModePolicy::kFifo:
    return "fifo";
  case PresentModePolicy::kMailbox:
    return "mailbox";
  case PresentModePolicy::kImmediate:
    return "immediate";
  }
  return "unknown";
}

std::uint32_t PreferSwapchainMinImageCount(PresentModePolicy policy,
                                           std::uint32_t requested,
                                           std::uint32_t min_images,
                                           std::uint32_t max_images) {
  return mocktail_rust_present_mode_prefer_min_image_count(
      ToRustPolicy(policy), requested, min_images, max_images);
}

} // namespace graphics
} // namespace mocktail
