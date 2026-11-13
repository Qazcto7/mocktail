#include "window/window_surface_lifecycle.h"

#include <array>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {
namespace {

Status MapRustError(int32_t rc, const std::array<char, 256>& err_buf) {
  if (rc == 0) {
    return Status::Ok();
  }
  const StatusCode code = (rc == 2) ? StatusCode::kInvalidArgument
                                    : StatusCode::kFailedPrecondition;
  return Status::Error(code, std::string(err_buf.data()));
}

WindowSurfaceSnapshot FromRustSnapshot(const MocktailRustSurfaceSnapshot& raw) {
  WindowSurfaceSnapshot out;
  out.generation = raw.generation;
  out.native_window = raw.native_window;
  out.width = raw.width;
  out.height = raw.height;
  out.available = raw.available != 0;
  out.dpi_scale = raw.dpi_scale;
  return out;
}

}  // namespace

WindowSurfaceLifecycle::WindowSurfaceLifecycle()
    : engine_(mocktail_rust_surface_lifecycle_new(),
              mocktail_rust_surface_lifecycle_free) {}

WindowSurfaceLifecycle::~WindowSurfaceLifecycle() = default;

Status WindowSurfaceLifecycle::Activate(uintptr_t native_window, uint32_t width,
                                        uint32_t height, float dpi_scale) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_surface_lifecycle_activate(
      engine_.get(), native_window, width, height, dpi_scale, err_buf.data(),
      err_buf.size());
  return MapRustError(rc, err_buf);
}

void WindowSurfaceLifecycle::Deactivate() {
  std::lock_guard<std::mutex> lock(mutex_);
  mocktail_rust_surface_lifecycle_deactivate(engine_.get());
}

Status WindowSurfaceLifecycle::Observe(uintptr_t native_window, uint32_t width,
                                       uint32_t height, float dpi_scale) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_surface_lifecycle_observe(
      engine_.get(), native_window, width, height, dpi_scale, err_buf.data(),
      err_buf.size());
  return MapRustError(rc, err_buf);
}

Status WindowSurfaceLifecycle::Refresh() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_surface_lifecycle_refresh(
      engine_.get(), err_buf.data(), err_buf.size());
  return MapRustError(rc, err_buf);
}

Status WindowSurfaceLifecycle::Recreate() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_surface_lifecycle_recreate(
      engine_.get(), err_buf.data(), err_buf.size());
  return MapRustError(rc, err_buf);
}

bool WindowSurfaceLifecycle::Poll(WindowSurfaceEvent* event) {
  if (event == nullptr) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  MocktailRustSurfaceEvent raw{};
  if (mocktail_rust_surface_lifecycle_poll(engine_.get(), &raw) == 0) {
    return false;
  }
  event->type = static_cast<WindowSurfaceEventType>(raw.event_type);
  event->surface = FromRustSnapshot(raw.surface);
  return true;
}

WindowSurfaceSnapshot WindowSurfaceLifecycle::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  MocktailRustSurfaceSnapshot raw{};
  (void)mocktail_rust_surface_lifecycle_snapshot(engine_.get(), &raw);
  return FromRustSnapshot(raw);
}

bool WindowSurfaceLifecycle::active() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return mocktail_rust_surface_lifecycle_is_active(engine_.get()) != 0;
}

const char* WindowSurfaceEventTypeName(WindowSurfaceEventType type) {
  return mocktail_rust_surface_event_type_name_ptr(static_cast<int32_t>(type));
}

}  // namespace window
}  // namespace mocktail
