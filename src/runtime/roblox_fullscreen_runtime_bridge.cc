#include "runtime/roblox_fullscreen_runtime_bridge.h"
#include "runtime/roblox_fullscreen_runtime_bridge_internal.h"
#include "mocktail/mocktail_rust.h"

#include <elf.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

#include "linker/linker.h"
#include "mocktail/platform/android_log_observer.h"
#include "window/window.h"

namespace mocktail {
namespace runtime {
namespace {

constexpr std::size_t kSetterContractBytes = 96;

bool IsExecutableImageRange(std::uintptr_t base, std::uintptr_t rva,
                            std::size_t size) {
  if (base == 0 || rva > std::numeric_limits<std::uintptr_t>::max() - size) {
    return false;
  }
  const auto* header = reinterpret_cast<const Elf64_Ehdr*>(base);
  if (std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
      header->e_ident[EI_CLASS] != ELFCLASS64 || header->e_phoff == 0 ||
      header->e_phnum == 0) {
    return false;
  }
  const auto* program_headers = reinterpret_cast<const Elf64_Phdr*>(
      base + static_cast<std::uintptr_t>(header->e_phoff));
  const std::uintptr_t range_end = rva + size;
  for (std::size_t index = 0; index < header->e_phnum; ++index) {
    const Elf64_Phdr& segment = program_headers[index];
    if (segment.p_type != PT_LOAD || (segment.p_flags & PF_X) == 0 ||
        segment.p_vaddr > std::numeric_limits<std::uintptr_t>::max() -
                                segment.p_memsz) {
      continue;
    }
    const std::uintptr_t segment_end =
        static_cast<std::uintptr_t>(segment.p_vaddr + segment.p_memsz);
    if (rva >= segment.p_vaddr && range_end <= segment_end) {
      return true;
    }
  }
  return false;
}

}  // namespace

namespace internal {

bool HasExpectedFullscreenSetterContract(const std::uint8_t* code,
                                         std::size_t size) {
  return mocktail_rust_validate_fullscreen_setter_contract(code, size) == 1;
}

}  // namespace internal

RobloxFullscreenRuntimeBridge::~RobloxFullscreenRuntimeBridge() { Shutdown(); }

Status RobloxFullscreenRuntimeBridge::Install(
    const compat::BuildProfile& profile) {
  if (installed_) {
    return Status::Error(StatusCode::kFailedPrecondition,
                         "fullscreen runtime bridge is already installed");
  }
  if (!profile.user_game_settings_fullscreen_setter_rva.has_value()) {
    return Status::Ok();
  }
  setter_rva_ = *profile.user_game_settings_fullscreen_setter_rva;
  if (!window::SetFullscreenStateSyncCallback(&SynchronizeState, this)) {
    setter_rva_ = 0;
    return Status::Error(
        StatusCode::kFailedPrecondition,
        "fullscreen state synchronizer already has an owner");
  }
  mocktail_android_log_set_observer(&ObserveAndroidLog);
  installed_ = true;
  std::fprintf(stderr,
               "  [fullscreen] Roblox menu bridge armed for Build ID %s\n",
               profile.elf_build_id.c_str());
  return Status::Ok();
}

void RobloxFullscreenRuntimeBridge::Shutdown() {
  if (!installed_) {
    return;
  }
  mocktail_android_log_set_observer(nullptr);
  window::ClearFullscreenStateSyncCallback();
  installed_ = false;
  setter_validated_ = false;
  library_base_ = 0;
  setter_rva_ = 0;
}

void RobloxFullscreenRuntimeBridge::ObserveAndroidLog(int priority,
                                                      const char* tag,
                                                      const char* message) {
  static_cast<void>(priority);
  (void)window::RequestFullscreenFromRobloxMenuLog(tag, message);
}

bool RobloxFullscreenRuntimeBridge::SynchronizeState(void* context,
                                                     bool fullscreen) {
  auto* bridge = static_cast<RobloxFullscreenRuntimeBridge*>(context);
  return bridge != nullptr && bridge->ApplyState(fullscreen);
}

bool RobloxFullscreenRuntimeBridge::ApplyState(bool fullscreen) {
  if (setter_rva_ == 0) {
    return false;
  }
  if (library_base_ == 0) {
    library_base_ = linker::FindLoadedAndroidLibraryBase("libroblox");
  }
  if (library_base_ == 0 ||
      !IsExecutableImageRange(library_base_, setter_rva_,
                              kSetterContractBytes)) {
    std::fprintf(stderr,
                 "  [fullscreen] libroblox setter is not in an executable "
                 "image range\n");
    return false;
  }
  const auto* setter_code = reinterpret_cast<const std::uint8_t*>(
      library_base_ + setter_rva_);
  if (!setter_validated_) {
    if (!internal::HasExpectedFullscreenSetterContract(
            setter_code, kSetterContractBytes)) {
      std::fprintf(stderr,
                   "  [fullscreen] Build-ID setter contract validation "
                   "failed\n");
      return false;
    }
    setter_validated_ = true;
  }

  using FullscreenSetter = void (*)(void* unused, int fullscreen);
  auto setter = reinterpret_cast<FullscreenSetter>(
      library_base_ + setter_rva_);
  setter(nullptr, fullscreen ? 1 : 0);
  std::fprintf(stderr, "  [fullscreen] Roblox state synchronized=%s\n",
               fullscreen ? "fullscreen" : "windowed");
  return true;
}

}  // namespace runtime
}  // namespace mocktail
