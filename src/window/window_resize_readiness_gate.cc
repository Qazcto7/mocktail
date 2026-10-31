#include "window/window_resize_readiness_gate.h"
#include "mocktail/mocktail_rust.h"

#include <array>
#include <utility>

namespace mocktail {
namespace window {
namespace {

Status InvalidArgument(std::string message) {
  return Status::Error(StatusCode::kInvalidArgument, std::move(message));
}

Status FailedPrecondition(std::string message) {
  return Status::Error(StatusCode::kFailedPrecondition, std::move(message));
}

Status StatusFromRust(int rc, const char* err_buf) {
  if (rc == 0) {
    return Status::Ok();
  }
  if (rc == -1) {
    return InvalidArgument(err_buf != nullptr && err_buf[0] != '\0'
                               ? err_buf
                               : "invalid argument");
  }
  return FailedPrecondition(err_buf != nullptr && err_buf[0] != '\0'
                                ? err_buf
                                : "failed precondition");
}

}  // namespace

Status WindowResizeReadinessGate::Activate(
    WindowResizeReadinessConfig config,
    const WindowSurfaceSnapshot& initial_surface) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err{};
  uint32_t state = static_cast<uint32_t>(snapshot_.state);
  const int rc = mocktail_rust_window_resize_activate(
      config.enabled ? 1 : 0, config.target_width, config.target_height,
      initial_surface.available ? 1 : 0, initial_surface.generation,
      initial_surface.native_window, initial_surface.width,
      initial_surface.height, &state, &snapshot_.surface_generation,
      &snapshot_.target_width, &snapshot_.target_height, err.data(),
      err.size());
  snapshot_.state = static_cast<WindowResizeReadinessState>(state);
  if (rc != 0) {
    return StatusFromRust(rc, err.data());
  }
  return Status::Ok();
}

Status WindowResizeReadinessGate::RecordPresent(uint64_t frame_serial) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err{};
  uint32_t state = static_cast<uint32_t>(snapshot_.state);
  const int rc = mocktail_rust_window_resize_record_present(
      frame_serial, &state, &snapshot_.first_present_serial,
      &snapshot_.post_rebind_present_serial, snapshot_.failure_reason.c_str(),
      err.data(), err.size());
  snapshot_.state = static_cast<WindowResizeReadinessState>(state);
  if (rc != 0) {
    if (snapshot_.state == WindowResizeReadinessState::kFailed) {
      snapshot_.failure_reason = err.data();
    }
    return StatusFromRust(rc, err.data());
  }
  return Status::Ok();
}

bool WindowResizeReadinessGate::TakeResizeRequest(
    WindowResizeRequest* request) {
  if (request == nullptr) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  uint32_t state = static_cast<uint32_t>(snapshot_.state);
  uint32_t out_w = 0;
  uint32_t out_h = 0;
  if (mocktail_rust_window_resize_take_request(
          &state, snapshot_.target_width, snapshot_.target_height, &out_w,
          &out_h) != 0) {
    snapshot_.state = static_cast<WindowResizeReadinessState>(state);
    request->width = out_w;
    request->height = out_h;
    return true;
  }
  return false;
}

Status WindowResizeReadinessGate::RecordCommittedSurfaceEvent(
    const WindowSurfaceEvent& event) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err{};
  uint32_t state = static_cast<uint32_t>(snapshot_.state);
  const int rc = mocktail_rust_window_resize_record_surface_event(
      static_cast<int>(event.type), event.surface.available ? 1 : 0,
      event.surface.generation, event.surface.native_window,
      event.surface.width, event.surface.height, &state,
      snapshot_.surface_generation, snapshot_.target_width,
      snapshot_.target_height, snapshot_.failure_reason.c_str(), err.data(),
      err.size());
  snapshot_.state = static_cast<WindowResizeReadinessState>(state);
  if (rc != 0) {
    if (snapshot_.state == WindowResizeReadinessState::kFailed) {
      snapshot_.failure_reason = err.data();
    }
    return StatusFromRust(rc, err.data());
  }
  return Status::Ok();
}

Status WindowResizeReadinessGate::RecordStopped() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err{};
  uint32_t state = static_cast<uint32_t>(snapshot_.state);
  const int rc = mocktail_rust_window_resize_record_stopped(
      &state, snapshot_.failure_reason.c_str(), err.data(), err.size());
  snapshot_.state = static_cast<WindowResizeReadinessState>(state);
  if (rc != 0) {
    if (snapshot_.state == WindowResizeReadinessState::kFailed) {
      snapshot_.failure_reason = err.data();
    }
    return StatusFromRust(rc, err.data());
  }
  return Status::Ok();
}

Status WindowResizeReadinessGate::CompletionStatus() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err{};
  const int rc = mocktail_rust_window_resize_completion_status(
      static_cast<uint32_t>(snapshot_.state), snapshot_.failure_reason.c_str(),
      err.data(), err.size());
  if (rc != 0) {
    return StatusFromRust(rc, err.data());
  }
  return Status::Ok();
}

WindowResizeReadinessSnapshot WindowResizeReadinessGate::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_;
}

Status WindowResizeReadinessGate::FailLocked(std::string reason) {
  snapshot_.state = WindowResizeReadinessState::kFailed;
  snapshot_.failure_reason = std::move(reason);
  return FailedPrecondition(snapshot_.failure_reason);
}

const char* WindowResizeReadinessStateName(WindowResizeReadinessState state) {
  return mocktail_rust_window_resize_state_name(static_cast<uint32_t>(state));
}

}  // namespace window
}  // namespace mocktail
