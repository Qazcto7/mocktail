#ifndef MOCKTAIL_RUNTIME_GRAPHICS_LAUNCH_POLICY_H_
#define MOCKTAIL_RUNTIME_GRAPHICS_LAUNCH_POLICY_H_

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "runtime/runtime_config.h"

namespace mocktail {
namespace runtime {

struct HostCpuCapabilities {
  std::string vendor_id;
  bool legacy_cpu = false;
};

struct HostGpuCapabilities {
  bool has_legacy_intel = false;
  bool has_modern_intel = false;
  bool has_legacy_nvidia = false;
  bool has_modern_nvidia = false;
  bool has_amd = false;
  bool has_amd_legacy_radeon = false;
  bool has_soc_vulkan = false;
  bool has_soc_gles_only = false;
  bool has_discrete_gpu = false;
  bool has_integrated_gpu = false;
  bool has_hw_vulkan_icd = false;
  bool has_virtual_gpu = false;
  bool host_verified_no_hw_icd = false;
  unsigned nvidia_driver_major = 0;
  unsigned long long total_ram_mb = 0;

  bool has_legacy_gpu() const {
    return has_legacy_intel || has_legacy_nvidia || has_amd_legacy_radeon;
  }
  bool has_modern_vulkan_gpu() const {
    return has_modern_intel || has_modern_nvidia || has_amd || has_soc_vulkan;
  }
  bool has_any_intel() const { return has_legacy_intel || has_modern_intel; }
  bool has_any_nvidia() const { return has_legacy_nvidia || has_modern_nvidia; }
  bool has_any_amd() const { return has_amd || has_amd_legacy_radeon; }
};

HostCpuCapabilities DetectHostCpuCapabilities();

// Resolves `kAuto` into a concrete runtime backend (`kSystem` / opengl on
// legacy CPUs or legacy-only GPUs; `kVulkan` otherwise).
GraphicsBackend ResolveEffectiveGraphicsBackend(
    GraphicsBackend requested,
    const HostCpuCapabilities& cpu,
    const HostGpuCapabilities& gpus);

GraphicsBackend ResolveEffectiveGraphicsBackend(GraphicsBackend requested);

// Readable ICD manifest for `vendor` that this build can actually load, or an
// empty path. Directories are searched in order; a manifest built for another
// architecture is never selected.
std::string SelectVulkanIcdManifest(
    const std::vector<std::filesystem::path>& directories,
    std::string_view vendor);

// Select an EGL GLVND vendor manifest (e.g. "mesa" or "nvidia") from the
// candidate directories so dual-GPU hosts do not accidentally initialize
// discrete/unused EGL ICDs before Mesa.
std::string SelectEglVendorManifest(
    const std::vector<std::filesystem::path>& directories,
    std::string_view vendor);

// Publishes the resolved graphics backend before the managed payload updater
// starts. OpenGL is a strict system EGL/GLES path; it never silently retries
// through ANGLE/Vulkan or accepts a window without a real graphics context.
bool ApplyGraphicsLaunchPolicy(const RuntimeConfig& config,
                               std::string* error = nullptr);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_GRAPHICS_LAUNCH_POLICY_H_
