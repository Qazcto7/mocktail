#include "window/window_state_store.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {

WindowStartupPresentationPlan PlanWindowStartupPresentation(
    const PersistedWindowState& state) {
  int fs_creation = 0;
  int max_constraints = 0;
  mocktail_rust_window_plan_presentation(
      state.fullscreen ? 1 : 0, state.maximized ? 1 : 0,
      &fs_creation, &max_constraints);
  return {fs_creation != 0, max_constraints != 0};
}

WindowStateLoadResult LoadWindowState(const std::filesystem::path& path) {
  WindowStateLoadResult result;
  MocktailRustWindowState rust_state = {};
  int found = 0;
  char err_buf[512] = {};
  const int rc = mocktail_rust_window_state_load(
      path.c_str(), &rust_state, &found, err_buf, sizeof(err_buf));
  if (rc != 0) {
    std::string msg = err_buf[0] != '\0' ? err_buf : "failed to load window state";
    if (rc == -4 || rc == -6) {
      result.status = Status::Error(StatusCode::kPlatformError, std::move(msg));
    } else {
      result.status = Status::Error(StatusCode::kInvalidArgument, std::move(msg));
    }
    return result;
  }
  if (found != 0) {
    result.found = true;
    result.state.x = rust_state.x;
    result.state.y = rust_state.y;
    result.state.width = rust_state.width;
    result.state.height = rust_state.height;
    result.state.has_position = rust_state.has_position != 0;
    result.state.fullscreen = rust_state.fullscreen != 0;
    result.state.maximized = rust_state.maximized != 0;
    result.state.configured_width = rust_state.configured_width;
    result.state.configured_height = rust_state.configured_height;
    result.state.has_configured_size = rust_state.has_configured_size != 0;
  }
  return result;
}

Status StoreWindowState(const std::filesystem::path& path,
                        const PersistedWindowState& state) {
  MocktailRustWindowState rust_state = {};
  rust_state.x = state.x;
  rust_state.y = state.y;
  rust_state.width = state.width;
  rust_state.height = state.height;
  rust_state.has_position = state.has_position ? 1 : 0;
  rust_state.fullscreen = state.fullscreen ? 1 : 0;
  rust_state.maximized = state.maximized ? 1 : 0;
  rust_state.configured_width = state.configured_width;
  rust_state.configured_height = state.configured_height;
  rust_state.has_configured_size = state.has_configured_size ? 1 : 0;

  char err_buf[512] = {};
  const int rc = mocktail_rust_window_state_store(
      path.c_str(), &rust_state, err_buf, sizeof(err_buf));
  if (rc != 0) {
    std::string msg = err_buf[0] != '\0' ? err_buf : "failed to store window state";
    if (rc == -5 || rc == -7 || rc == -8 || rc == -9 || rc == -10) {
      return Status::Error(StatusCode::kPlatformError, std::move(msg));
    }
    return Status::Error(StatusCode::kInvalidArgument, std::move(msg));
  }
  return Status::Ok();
}

}  // namespace window
}  // namespace mocktail
