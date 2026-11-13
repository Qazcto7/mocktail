#ifndef MOCKTAIL_WINDOW_VULKAN_SURFACE_RECOVERY_GATE_H_
#define MOCKTAIL_WINDOW_VULKAN_SURFACE_RECOVERY_GATE_H_

#include <cstdint>
#include <memory>

namespace mocktail {
namespace window {

struct VulkanSurfaceRecoveryRequest {
  uint64_t observed_error_count = 0;
  uint64_t coalesced_error_count = 0;
  bool retry = false;
};

// Transfers out-of-date WSI evidence from a Vulkan render thread to the SDL
// main thread. A burst is coalesced into one rebind, while a swapchain that
// remains invalid can request another rebind after a bounded retry interval.
class VulkanSurfaceRecoveryGate final {
 public:
  static constexpr uint64_t kRetryIntervalNs = 1000000000ULL;

  VulkanSurfaceRecoveryGate();
  ~VulkanSurfaceRecoveryGate();
  VulkanSurfaceRecoveryGate(const VulkanSurfaceRecoveryGate&) = delete;
  VulkanSurfaceRecoveryGate& operator=(const VulkanSurfaceRecoveryGate&) =
      delete;

  bool Activate();
  void Deactivate();
  void NotifyOutOfDate();
  void NotifyPresent();
  bool TakeRebindRequest(uint64_t now_ticks_ns,
                         VulkanSurfaceRecoveryRequest* request);

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_VULKAN_SURFACE_RECOVERY_GATE_H_
