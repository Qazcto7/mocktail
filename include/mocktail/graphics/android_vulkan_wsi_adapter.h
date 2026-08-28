#ifndef MOCKTAIL_GRAPHICS_ANDROID_VULKAN_WSI_ADAPTER_H_
#define MOCKTAIL_GRAPHICS_ANDROID_VULKAN_WSI_ADAPTER_H_

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "mocktail/graphics/vulkan_abi.h"
#include "mocktail/graphics/sdl_vulkan_wsi.h"
#include "mocktail/status.h"

namespace mocktail {
namespace graphics {

// Stable signed 32-bit ABI, independent of the optional Vulkan SDK.
using AndroidVulkanResult = VkResult;

inline constexpr AndroidVulkanResult kAndroidVulkanSuccess =
    static_cast<AndroidVulkanResult>(0);
inline constexpr AndroidVulkanResult kAndroidVulkanErrorInitializationFailed =
    static_cast<AndroidVulkanResult>(-3);
inline constexpr std::uint64_t kHostInfiniteWaitDiagnosticSliceNs =
    1000000000ULL;
inline constexpr std::uint64_t kHostImageAcquireWatchdogTimeoutNs =
    kHostInfiniteWaitDiagnosticSliceNs;
// In unthrottled mode, infinite acquire preserves the guest's infinite wait
// rather than polling once with 0 (which returns VK_NOT_READY and drops frames)
// or forcing swapchain recreation as OUT_OF_DATE.
inline constexpr std::uint64_t kHostImageAcquireUnthrottledTimeoutNs =
    std::numeric_limits<std::uint64_t>::max();

inline constexpr char kAndroidSurfaceExtension[] =
    "VK_KHR_android_surface";

// Roblox treats VK_SUBOPTIMAL_KHR as a hard error, so expose it as success.
VkResult NormalizeAndroidSwapchainResult(VkResult result);

// Bounds only infinite acquire waits so a lost compositor wakeup cannot hang.
// Unthrottled infinite acquire preserves the guest infinite wait and never
// recovers as OUT_OF_DATE; the 1s watchdog path stays for vsync/default infinite waits.
std::uint64_t BoundHostImageAcquireTimeout(std::uint64_t requested_timeout);
std::uint64_t BoundHostImageAcquireTimeout(std::uint64_t requested_timeout,
                                           bool unthrottled);
bool IsHostImageAcquireWatchdogTimeout(std::uint64_t requested_timeout,
                                       VkResult host_result);
bool IsHostImageAcquireWatchdogTimeout(std::uint64_t requested_timeout,
                                       VkResult host_result, bool unthrottled);
VkResult NormalizeHostImageAcquireResult(std::uint64_t requested_timeout,
                                         VkResult host_result);
VkResult NormalizeHostImageAcquireResult(std::uint64_t requested_timeout,
                                         VkResult host_result,
                                         bool unthrottled);

// Infinite guest fence/semaphore waits use finite host slices without exposing
// slice timeouts. Unthrottled does not poll-once here: the engine asked to
// wait for GPU work, and a TIMEOUT return turns into cond_wait storms.
std::uint64_t BoundHostSynchronizationWaitTimeout(
    std::uint64_t requested_timeout);
std::uint64_t BoundHostSynchronizationWaitTimeout(
    std::uint64_t requested_timeout, bool unthrottled);
bool ShouldContinueHostSynchronizationWait(std::uint64_t requested_timeout,
                                           VkResult host_result);
bool ShouldContinueHostSynchronizationWait(std::uint64_t requested_timeout,
                                           VkResult host_result,
                                           bool unthrottled);

// Returned storage owns the translated extension names.
Status TranslateAndroidVulkanInstanceExtensions(
    const std::vector<std::string>& android_extensions,
    const std::vector<std::string>& host_wsi_extensions,
    std::vector<std::string>* host_extensions);

// Ignores the guest native-window field; SDL alone creates the host surface.
class AndroidVulkanWsiAdapter final {
 public:
  using PresentCallback = void (*)(void* user_data);

  Status Initialize(SdlVulkanWsi* host_wsi,
                    PresentCallback present_callback = nullptr,
                    void* present_callback_data = nullptr);
  void Shutdown();
  bool IsInitialized() const { return host_wsi_ != nullptr; }

  Status TranslateInstanceExtensions(
      const std::vector<std::string>& android_extensions,
      std::vector<std::string>* host_extensions) const;

  AndroidVulkanResult CreateAndroidSurface(
      VkInstance instance, const void* android_create_info,
      const VkAllocationCallbacks* allocator, VkSurfaceKHR* surface) const;
  void DestroySurface(VkInstance instance, VkSurfaceKHR surface,
                      const VkAllocationCallbacks* allocator) const;

  VkResult EnumerateInstanceExtensionProperties(
      const char* layer_name, std::uint32_t* property_count,
      VkExtensionProperties* properties) const;
  VkResult CreateInstance(const VkInstanceCreateInfo* create_info,
                          const VkAllocationCallbacks* allocator,
                          VkInstance* instance);
  PFN_vkVoidFunction GetInstanceProcAddress(VkInstance instance,
                                            const char* name);
  PFN_vkVoidFunction GetDeviceProcAddress(VkDevice device, const char* name);
  VkResult QueuePresent(VkQueue queue, const VkPresentInfoKHR* present_info);

 private:
  SdlVulkanWsi* host_wsi_ = nullptr;
  PFN_vkGetInstanceProcAddr host_get_instance_proc_address_ = nullptr;
  PFN_vkGetDeviceProcAddr host_get_device_proc_address_ = nullptr;
  PFN_vkQueuePresentKHR host_queue_present_ = nullptr;
  PresentCallback present_callback_ = nullptr;
  void* present_callback_data_ = nullptr;
};

}  // namespace graphics
}  // namespace mocktail

#endif  // MOCKTAIL_GRAPHICS_ANDROID_VULKAN_WSI_ADAPTER_H_
