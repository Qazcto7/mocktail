#include "mocktail/graphics/vulkan_swapchain_policy.h"
#include "mocktail/mocktail_rust.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace mocktail::graphics {

bool EnableSurfaceMaintenanceExtensions(
    const std::vector<VkExtensionProperties>& supported,
    std::vector<std::string>* enabled) {
  if (enabled == nullptr) return false;
  std::vector<const char*> supported_ptrs;
  supported_ptrs.reserve(supported.size());
  for (const auto& extension : supported) {
    supported_ptrs.push_back(extension.extensionName);
  }
  std::vector<const char*> enabled_ptrs;
  enabled_ptrs.reserve(enabled->size());
  for (const auto& entry : *enabled) {
    enabled_ptrs.push_back(entry.c_str());
  }
  std::array<char, 256> to_append{};
  size_t out_len = 0;
  const int32_t rc = mocktail_rust_vulkan_select_surface_maintenance_exts(
      supported_ptrs.empty() ? nullptr : supported_ptrs.data(),
      supported_ptrs.size(),
      enabled_ptrs.empty() ? nullptr : enabled_ptrs.data(),
      enabled_ptrs.size(), to_append.data(), to_append.size(), &out_len);
  if (rc != 1) return false;
  if (out_len > 0) {
    const std::string append_str(to_append.data(), out_len);
    std::size_t start = 0;
    while (start < append_str.size()) {
      const std::size_t nl = append_str.find('\n', start);
      const std::size_t end =
          (nl == std::string::npos) ? append_str.size() : nl;
      if (end > start) {
        enabled->emplace_back(append_str.substr(start, end - start));
      }
      start = end + 1;
    }
  }
  return true;
}

VkResult ApplySwapchainPresentPolicy(PresentModePolicy policy,
                                     VkPhysicalDevice physical_device,
                                     const VulkanSurfaceQueries& queries,
                                     VkSwapchainCreateInfoKHR* create_info) {
  if (create_info == nullptr || physical_device == VK_NULL_HANDLE) {
    return VK_ERROR_INITIALIZATION_FAILED;
  }
  VkSwapchainCreateInfoKHR selected = *create_info;
  if (policy != PresentModePolicy::kHostDefault) {
    if (queries.present_modes == nullptr) return VK_ERROR_INITIALIZATION_FAILED;
    std::uint32_t count = 0;
    VkResult result = queries.present_modes(physical_device, selected.surface,
                                            &count, nullptr);
    if (result != VK_SUCCESS) return result;
    if (count == 0) return VK_ERROR_INITIALIZATION_FAILED;
    std::vector<VkPresentModeKHR> modes(count);
    result = queries.present_modes(physical_device, selected.surface, &count,
                                    modes.data());
    if (result != VK_SUCCESS && result != VK_INCOMPLETE) return result;
    modes.resize(std::min<std::size_t>(count, modes.size()));
    const auto filtered = FilterPresentModes(policy, modes);
    if (filtered.empty()) return VK_ERROR_INITIALIZATION_FAILED;
    selected.presentMode = filtered.front();
  }

  VkSurfaceCapabilitiesKHR capabilities{};
  VkResult result;
  if (queries.mode_capabilities != nullptr) {
    VkSurfacePresentModeKHR mode{};
    mode.sType = VK_STRUCTURE_TYPE_SURFACE_PRESENT_MODE_KHR;
    mode.presentMode = selected.presentMode;
    VkPhysicalDeviceSurfaceInfo2KHR info{};
    info.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SURFACE_INFO_2_KHR;
    info.pNext = &mode;
    info.surface = selected.surface;
    VkSurfaceCapabilities2KHR output{};
    output.sType = VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_2_KHR;
    result = queries.mode_capabilities(physical_device, &info, &output);
    capabilities = output.surfaceCapabilities;
  } else {
    if (queries.capabilities == nullptr) return VK_ERROR_INITIALIZATION_FAILED;
    result = queries.capabilities(physical_device, selected.surface,
                                   &capabilities);
  }
  if (result != VK_SUCCESS) return result;

  const auto image_policy = static_cast<PresentModePolicy>(
      mocktail_rust_vulkan_swapchain_image_policy(
          static_cast<int>(policy),
          static_cast<uint32_t>(selected.presentMode)));
  selected.minImageCount = PreferSwapchainMinImageCount(
      image_policy, selected.minImageCount, capabilities.minImageCount,
      capabilities.maxImageCount);
  *create_info = selected;
  return VK_SUCCESS;
}

}  // namespace mocktail::graphics
