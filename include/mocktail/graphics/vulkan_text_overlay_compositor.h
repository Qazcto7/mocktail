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

#ifndef MOCKTAIL_GRAPHICS_VULKAN_TEXT_OVERLAY_COMPOSITOR_H_
#define MOCKTAIL_GRAPHICS_VULKAN_TEXT_OVERLAY_COMPOSITOR_H_

#include <vulkan/vulkan.h>

#include <cstdint>

namespace mocktail {
namespace graphics {

// Composites the process-local RGBA text surface into application-owned
// swapchain images. The adapter retains ownership of every Vulkan object it
// registers. DestroySwapchain and DestroyDevice must be called before the
// corresponding host Vulkan destroy function.
//
// An unsupported device or swapchain remains a valid registration failure:
// QueuePresent then forwards the unmodified VkPresentInfoKHR to fallback.
class VulkanTextOverlayCompositor final {
 public:
  VulkanTextOverlayCompositor();
  ~VulkanTextOverlayCompositor();

  VulkanTextOverlayCompositor(const VulkanTextOverlayCompositor&) = delete;
  VulkanTextOverlayCompositor& operator=(const VulkanTextOverlayCompositor&) =
      delete;

  // enabled_features describes the features actually enabled by
  // vkCreateDevice, not merely the features supported by the physical device.
  // The supplied proc-address callbacks must bypass the Android-facing Vulkan
  // adapter and resolve host functions directly.
  bool RegisterDevice(VkInstance instance, VkPhysicalDevice physical_device,
                      VkDevice device, std::uint32_t api_version,
                      const char* const* enabled_extensions,
                      std::uint32_t enabled_extension_count,
                      std::uint32_t graphics_queue_family,
                      std::uint32_t graphics_queue_count,
                      const VkPhysicalDeviceFeatures2* enabled_features,
                      PFN_vkGetInstanceProcAddr get_instance_proc_addr,
                      PFN_vkGetDeviceProcAddr get_device_proc_addr);
  void DestroyDevice(VkDevice device);

  bool RegisterQueue(VkDevice device, VkQueue queue, std::uint32_t queue_family,
                     std::uint32_t queue_index);

  bool RegisterSwapchain(VkDevice device, VkSwapchainKHR swapchain,
                         const VkSwapchainCreateInfoKHR& create_info,
                         const VkImage* images, std::uint32_t image_count);
  void DestroySwapchain(VkDevice device, VkSwapchainKHR swapchain);

  // Serializes adapter-mediated submit, sparse-bind, present, and idle
  // operations on the exact queue range imported by libplacebo. Other
  // VkQueues remain independent, including the inactive-overlay fast path on
  // a non-imported queue.
  VkResult QueueSubmit(VkQueue queue, std::uint32_t submit_count,
                       const VkSubmitInfo* submits, VkFence fence,
                       PFN_vkQueueSubmit fallback);
  VkResult QueueSubmit2(VkQueue queue, std::uint32_t submit_count,
                        const VkSubmitInfo2* submits, VkFence fence,
                        PFN_vkQueueSubmit2 fallback);
  VkResult QueueBindSparse(VkQueue queue, std::uint32_t bind_info_count,
                           const VkBindSparseInfo* bind_info, VkFence fence,
                           PFN_vkQueueBindSparse fallback);
  VkResult QueueWaitIdle(VkQueue queue, PFN_vkQueueWaitIdle fallback);
  VkResult DeviceWaitIdle(VkDevice device, PFN_vkDeviceWaitIdle fallback);

  // Always invokes fallback when it is non-null. The original wait semaphores
  // are forwarded unchanged until the compositor successfully submits the
  // wait-collapse bridge; after that point only compositor-owned semaphores
  // are passed to fallback.
  VkResult QueuePresent(VkQueue queue, const VkPresentInfoKHR* present_info,
                        PFN_vkQueuePresentKHR fallback);

 private:
  struct Impl;
  Impl* impl_ = nullptr;
};

}  // namespace graphics
}  // namespace mocktail

#endif  // MOCKTAIL_GRAPHICS_VULKAN_TEXT_OVERLAY_COMPOSITOR_H_
