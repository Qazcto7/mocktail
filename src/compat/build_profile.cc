#include "compat/build_profile.h"

#include "mocktail/mocktail_rust.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace mocktail::compat {
namespace {

ProfileLookupResult Failure(std::string error) {
  return ProfileLookupResult{std::nullopt, std::move(error)};
}

}  // namespace

std::string_view BuildStatusName(BuildStatus status) noexcept {
  switch (status) {
    case BuildStatus::kSupported:
      return "supported";
    case BuildStatus::kExperimental:
      return "experimental";
    case BuildStatus::kLegacyResearched:
      return "legacy-researched";
    case BuildStatus::kUnverified:
      return "unverified";
  }
  return "unverified";
}

ProfileLookupResult FindBuildProfile(const std::string& manifest_path,
                                     std::string_view build_id) {
  std::optional<BuildProfile> matched_profile;
  std::array<char, 512> err_buf{};
  const int32_t rc = mocktail_rust_find_build_profile(
      manifest_path.c_str(), build_id.data(), build_id.size(),
      [](void* ctx, const MocktailRustBuildProfileView* view) {
        auto* out = static_cast<std::optional<BuildProfile>*>(ctx);
        std::optional<std::uintptr_t> fullscreen_setter_rva;
        if (view->has_fullscreen_setter_rva) {
          fullscreen_setter_rva = view->fullscreen_setter_rva;
        }
        std::optional<FmodOutputDeviceBridgeProfile> fmod_bridge;
        if (view->has_fmod_bridge) {
          FmodOutputDeviceBridgeProfile bridge{
              view->fmod_vtable_rva,
              view->fmod_string_constructor_rva,
              view->fmod_count_method_rva,
              view->fmod_info_method_rva,
              view->fmod_current_method_rva,
              view->fmod_select_method_rva,
              static_cast<int>(view->fmod_vtable_layout_version),
          };
          for (std::size_t i = 0; i < 4; ++i) {
            bridge.input_method_rvas[i] = view->fmod_input_method_rvas[i];
          }
          fmod_bridge = bridge;
        }
        *out = BuildProfile{
            std::string(view->version_name.ptr, view->version_name.len),
            view->version_code,
            std::string(view->elf_build_id.ptr, view->elf_build_id.len),
            static_cast<BuildStatus>(view->status),
            view->default_allowed,
            view->allow_legacy_binary_patches,
            view->allow_host_abi_bridges,
            view->allow_host_constructor_replay,
            fullscreen_setter_rva,
            fmod_bridge,
            std::string(view->reason.ptr, view->reason.len),
        };
      },
      &matched_profile, err_buf.data(), err_buf.size());
  if (rc == 0 || rc == 1) {
    return ProfileLookupResult{std::move(matched_profile), {}};
  }
  return Failure(err_buf[0] != '\0' ? std::string(err_buf.data())
                                    : "compatibility manifest lookup failed");
}

}  // namespace mocktail::compat
