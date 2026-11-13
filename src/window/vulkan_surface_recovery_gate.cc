#include "window/vulkan_surface_recovery_gate.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

VulkanSurfaceRecoveryGate::VulkanSurfaceRecoveryGate()
    : engine_(mocktail_rust_vulkan_surface_recovery_gate_new(),
              mocktail_rust_vulkan_surface_recovery_gate_free) {}

VulkanSurfaceRecoveryGate::~VulkanSurfaceRecoveryGate() = default;

bool VulkanSurfaceRecoveryGate::Activate() {
  return mocktail_rust_vulkan_surface_recovery_gate_activate(engine_.get());
}

void VulkanSurfaceRecoveryGate::Deactivate() {
  mocktail_rust_vulkan_surface_recovery_gate_deactivate(engine_.get());
}

void VulkanSurfaceRecoveryGate::NotifyOutOfDate() {
  mocktail_rust_vulkan_surface_recovery_gate_notify_out_of_date(engine_.get());
}

void VulkanSurfaceRecoveryGate::NotifyPresent() {
  mocktail_rust_vulkan_surface_recovery_gate_notify_present(engine_.get());
}

bool VulkanSurfaceRecoveryGate::TakeRebindRequest(
    uint64_t now_ticks_ns, VulkanSurfaceRecoveryRequest* request) {
  if (request == nullptr) {
    return false;
  }
  MocktailRustVulkanSurfaceRecoveryRequest raw{};
  if (!mocktail_rust_vulkan_surface_recovery_gate_take_rebind_request(
          engine_.get(), now_ticks_ns, &raw)) {
    return false;
  }
  request->observed_error_count = raw.observed_error_count;
  request->coalesced_error_count = raw.coalesced_error_count;
  request->retry = raw.retry;
  return true;
}

}  // namespace window
}  // namespace mocktail
