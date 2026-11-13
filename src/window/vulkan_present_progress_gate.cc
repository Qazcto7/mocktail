#include "window/vulkan_present_progress_gate.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {
namespace {

VulkanPresentStallStage FromRustStage(int32_t stage) {
  if (stage == 1) {
    return VulkanPresentStallStage::kInsideVulkanCall;
  }
  if (stage == 2) {
    return VulkanPresentStallStage::kInsideHostPresent;
  }
  return VulkanPresentStallStage::kBeforeHostPresent;
}

}  // namespace

VulkanPresentProgressGate::VulkanPresentProgressGate()
    : engine_(mocktail_rust_vulkan_present_progress_gate_new(),
              mocktail_rust_vulkan_present_progress_gate_free) {}

VulkanPresentProgressGate::~VulkanPresentProgressGate() = default;

bool VulkanPresentProgressGate::Activate() {
  return mocktail_rust_vulkan_present_progress_gate_activate(engine_.get());
}

void VulkanPresentProgressGate::Deactivate() {
  mocktail_rust_vulkan_present_progress_gate_deactivate(engine_.get());
}

uint64_t VulkanPresentProgressGate::NotifyHostPresentBegin(
    uint64_t now_ticks_ns, uint64_t thread_id) {
  return mocktail_rust_vulkan_present_progress_gate_notify_host_present_begin(
      engine_.get(), now_ticks_ns, thread_id);
}

void VulkanPresentProgressGate::NotifyHostPresentEnd(uint64_t sequence) {
  mocktail_rust_vulkan_present_progress_gate_notify_host_present_end(
      engine_.get(), sequence);
}

uint64_t VulkanPresentProgressGate::NotifyCallBegin(const char* call_name,
                                                    uint64_t now_ticks_ns,
                                                    uint64_t thread_id) {
  return mocktail_rust_vulkan_present_progress_gate_notify_call_begin(
      engine_.get(), call_name, now_ticks_ns, thread_id);
}

void VulkanPresentProgressGate::NotifyCallEnd(uint64_t sequence, int32_t result,
                                              uint64_t now_ticks_ns,
                                              uint64_t thread_id) {
  mocktail_rust_vulkan_present_progress_gate_notify_call_end(
      engine_.get(), sequence, result, now_ticks_ns, thread_id);
}

void VulkanPresentProgressGate::NotifyFramePresented(uint64_t now_ticks_ns,
                                                     uint64_t frame_count,
                                                     uint64_t thread_id) {
  mocktail_rust_vulkan_present_progress_gate_notify_frame_presented(
      engine_.get(), now_ticks_ns, frame_count, thread_id);
}

bool VulkanPresentProgressGate::Poll(uint64_t now_ticks_ns,
                                     bool window_can_present,
                                     VulkanPresentStallReport* report) {
  if (report == nullptr) {
    return false;
  }
  MocktailRustVulkanPresentStallReport raw{};
  if (!mocktail_rust_vulkan_present_progress_gate_poll(
          engine_.get(), now_ticks_ns, window_can_present, &raw)) {
    return false;
  }
  report->stage = FromRustStage(raw.stage);
  report->call_name = raw.call_name;
  report->call_sequence = raw.call_sequence;
  report->thread_id = raw.thread_id;
  report->elapsed_ns = raw.elapsed_ns;
  report->frame_count = raw.frame_count;
  report->host_present_count = raw.host_present_count;
  report->last_present_thread_id = raw.last_present_thread_id;
  report->last_completed_call_snapshot_coherent =
      raw.last_completed_call_snapshot_coherent;
  report->last_completed_call_name = raw.last_completed_call_name;
  report->last_completed_call_sequence = raw.last_completed_call_sequence;
  report->last_completed_call_thread_id = raw.last_completed_call_thread_id;
  report->last_completed_call_started_ns = raw.last_completed_call_started_ns;
  report->last_completed_call_completed_ns =
      raw.last_completed_call_completed_ns;
  report->last_completed_call_result = raw.last_completed_call_result;
  report->oldest_active_call_name = raw.oldest_active_call_name;
  report->oldest_active_call_sequence = raw.oldest_active_call_sequence;
  report->oldest_active_call_thread_id = raw.oldest_active_call_thread_id;
  report->oldest_active_call_elapsed_ns = raw.oldest_active_call_elapsed_ns;
  return true;
}

}  // namespace window
}  // namespace mocktail
