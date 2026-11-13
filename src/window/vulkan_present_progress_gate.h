#ifndef MOCKTAIL_WINDOW_VULKAN_PRESENT_PROGRESS_GATE_H_
#define MOCKTAIL_WINDOW_VULKAN_PRESENT_PROGRESS_GATE_H_

#include <cstdint>
#include <memory>

namespace mocktail {
namespace window {

enum class VulkanPresentStallStage {
  kBeforeHostPresent,
  kInsideVulkanCall,
  kInsideHostPresent,
};

struct VulkanPresentStallReport {
  VulkanPresentStallStage stage = VulkanPresentStallStage::kBeforeHostPresent;
  const char* call_name = nullptr;
  uint64_t call_sequence = 0;
  uint64_t thread_id = 0;
  uint64_t elapsed_ns = 0;
  uint64_t frame_count = 0;
  uint64_t host_present_count = 0;
  uint64_t last_present_thread_id = 0;
  bool last_completed_call_snapshot_coherent = false;
  const char* last_completed_call_name = nullptr;
  uint64_t last_completed_call_sequence = 0;
  uint64_t last_completed_call_thread_id = 0;
  uint64_t last_completed_call_started_ns = 0;
  uint64_t last_completed_call_completed_ns = 0;
  int32_t last_completed_call_result = 0;
  const char* oldest_active_call_name = nullptr;
  uint64_t oldest_active_call_sequence = 0;
  uint64_t oldest_active_call_thread_id = 0;
  uint64_t oldest_active_call_elapsed_ns = 0;
};

// Transfers host-present progress from the Vulkan render thread to the SDL
// event thread. This gate is diagnostic only: a blocked vkQueuePresentKHR
// cannot be cancelled safely while the guest still owns the same VkQueue.
class VulkanPresentProgressGate final {
 public:
  static constexpr uint64_t kStallThresholdNs = 5000000000ULL;

  VulkanPresentProgressGate();
  ~VulkanPresentProgressGate();
  VulkanPresentProgressGate(const VulkanPresentProgressGate&) = delete;
  VulkanPresentProgressGate& operator=(const VulkanPresentProgressGate&) =
      delete;

  bool Activate();
  void Deactivate();
  uint64_t NotifyHostPresentBegin(uint64_t now_ticks_ns,
                                  uint64_t thread_id = 0);
  void NotifyHostPresentEnd(uint64_t sequence);

  // Records a potentially blocking host Vulkan call without serializing the
  // caller. The returned sequence must be passed to NotifyCallEnd. A fixed
  // slot table is sufficient because only threads currently inside a tracked
  // call occupy a slot; exhaustion drops diagnostics but never changes Vulkan
  // behavior.
  uint64_t NotifyCallBegin(const char* call_name, uint64_t now_ticks_ns,
                           uint64_t thread_id);
  void NotifyCallEnd(uint64_t sequence, int32_t result,
                     uint64_t now_ticks_ns = 0, uint64_t thread_id = 0);
  void NotifyFramePresented(uint64_t now_ticks_ns, uint64_t frame_count,
                            uint64_t thread_id = 0);
  bool Poll(uint64_t now_ticks_ns, bool window_can_present,
            VulkanPresentStallReport* report);

 private:
  std::unique_ptr<void, void (*)(void*)> engine_;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_VULKAN_PRESENT_PROGRESS_GATE_H_
