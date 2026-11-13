#include "mocktail/graphics/graphics_backend.h"
#include "mocktail/mocktail_rust.h"

#include <array>
#include <string>

namespace mocktail {
namespace graphics {

BackendSelection SelectGraphicsBackend(
    const BackendSelectionPolicy& policy,
    const std::vector<BackendCapability>& capabilities) {
  std::vector<int32_t> backends;
  std::vector<int32_t> states;
  std::vector<int32_t> accels;
  std::vector<const char*> details;
  backends.reserve(capabilities.size());
  states.reserve(capabilities.size());
  accels.reserve(capabilities.size());
  details.reserve(capabilities.size());
  for (const BackendCapability& cap : capabilities) {
    backends.push_back(static_cast<int32_t>(cap.backend));
    states.push_back(static_cast<int32_t>(cap.state));
    accels.push_back(static_cast<int32_t>(cap.acceleration));
    details.push_back(cap.detail.c_str());
  }

  int32_t selected_backend = static_cast<int32_t>(policy.requested);
  std::array<char, 512> detail_buf{};
  const int32_t rc = mocktail_rust_graphics_backend_select(
      static_cast<int32_t>(policy.requested), policy.allow_fallback ? 1 : 0,
      policy.require_hardware_acceleration ? 1 : 0,
      policy.require_runtime_validation ? 1 : 0,
      backends.empty() ? nullptr : backends.data(),
      states.empty() ? nullptr : states.data(),
      accels.empty() ? nullptr : accels.data(),
      details.empty() ? nullptr : details.data(), capabilities.size(),
      &selected_backend, detail_buf.data(), detail_buf.size());

  const auto chosen = static_cast<GraphicsBackendKind>(selected_backend);
  const std::string detail(detail_buf.data());
  if (rc == 0) {
    return {Status::Ok(), chosen, detail};
  }
  return {Status::Error(StatusCode::kUnavailable, detail), chosen, detail};
}

const char* GraphicsBackendName(GraphicsBackendKind backend) {
  return mocktail_rust_graphics_backend_name_ptr(static_cast<int32_t>(backend));
}

}  // namespace graphics
}  // namespace mocktail
