#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/runtime_environment.h"
#include "legacy/stage6_offsets.h"

namespace mocktail::legacy::internal {

bool PatchNullSurfaceAppCrash(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_PATCH_NULL_SURFACE_APP_CRASH")) {
    return false;
  }

  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kPatchOffset = 0x26906ad;
  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  auto* patch_address = reinterpret_cast<void*>(base + kPatchOffset);

  // Replaces a diagnostic-only block before dereferencing SurfaceApp with:
  //   test r14, r14
  //   je   cleanup
  //   cmpl $0, 0x138(r14)
  //   jne  cleanup
  //   nop ...
  //
  // This keeps normal non-null behavior and makes the headless path skip the
  // Android surface update when Java lifecycle setup did not create SurfaceApp.
  unsigned char patch[0x46];
  std::memset(patch, 0x90, sizeof(patch));
  const unsigned char prefix[] = {
      0x4d, 0x85, 0xf6, 0x0f, 0x84, 0x90, 0x01, 0x00, 0x00, 0x41, 0x83, 0xbe,
      0x38, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x85, 0x82, 0x01, 0x00, 0x00,
  };
  std::memcpy(patch, prefix, sizeof(prefix));
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  unsigned char callback_patch[0x17];
  std::memset(callback_patch, 0x90, sizeof(callback_patch));
  callback_patch[0] = 0xeb;
  callback_patch[1] = 0x15;
  patched = PatchCode(reinterpret_cast<void*>(base + 0x2690608), callback_patch,
                      sizeof(callback_patch)) &&
            patched;
  std::cout << "  [patch] null SurfaceApp guard "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchFontTableClassifierCrash(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_FONT_TABLE_CLASSIFIER_CRASH")) {
    return false;
  }

  bool patched = true;
  {
    constexpr uintptr_t kPatchOffset = 0x6063873;
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + kPatchOffset);
    const unsigned char expected[] = {0x45, 0x0f, 0xb7, 0x48, 0x0c};
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [patch] font table classifier signature mismatch at 0x"
                << std::hex << kPatchOffset << std::dec << '\n'
                << std::flush;
      patched = false;
    } else {
      const unsigned char patch[] = {0xe9, 0x52, 0x00, 0x00, 0x00};
      patched = PatchCode(patch_address, patch, sizeof(patch)) && patched;
    }
  }

  {
    constexpr uintptr_t kPatchOffset = 0x602fa71;
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + kPatchOffset);
    const unsigned char expected[] = {0x4c, 0x8b, 0x06, 0x41, 0x81};
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [patch] font table reverse classifier signature "
                << "mismatch at 0x" << std::hex << kPatchOffset << std::dec
                << '\n'
                << std::flush;
      patched = false;
    } else {
      const unsigned char patch[] = {0xe9, 0x2a, 0x00, 0x00, 0x00};
      patched = PatchCode(patch_address, patch, sizeof(patch)) && patched;
    }
  }

  {
    constexpr uintptr_t kPatchOffset = 0x602fab3;
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + kPatchOffset);
    const unsigned char expected[] = {0x4c, 0x8b, 0x02, 0x48, 0x83, 0xc2};
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [patch] font table fallback classifier signature "
                << "mismatch at 0x" << std::hex << kPatchOffset << std::dec
                << '\n'
                << std::flush;
      patched = false;
    } else {
      const unsigned char patch[] = {
          0x48, 0x83, 0xc2, 0xf8,  // add rdx, -8
          0xeb, 0xf5,              // jmp 0x602faae
      };
      patched = PatchCode(patch_address, patch, sizeof(patch)) && patched;
    }
  }

  std::cout << "  [patch] font table classifier crash guard "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchPostClientSettingsTelemetryCrash(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_POST_CLIENT_SETTINGS_TELEMETRY_CRASH")) {
    return false;
  }

  unsigned char patch[8];
  std::memset(patch, 0x90, sizeof(patch));
  patch[0] = 0x31;  // xor eax, eax
  patch[1] = 0xc0;
  patch[2] = 0xc3;  // ret

  bool patched = true;
  for (uintptr_t offset : {0x234abe3, 0x2346d5f, 0x67ac0be}) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + offset);
    const unsigned char expected[] = {0x55, 0x48, 0x89, 0xe5};
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [patch] post-client-settings telemetry signature "
                << "mismatch at 0x" << std::hex << offset << std::dec << '\n'
                << std::flush;
      patched = false;
      continue;
    }
    patched = PatchCode(patch_address, patch, sizeof(patch)) && patched;
  }

  {
    constexpr uintptr_t kSkipTelemetryObjectReadOffset = 0x2346ab8;
    auto* patch_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kSkipTelemetryObjectReadOffset);
    const unsigned char expected[] = {0x49, 0x8b, 0x06, 0x48, 0x85, 0xc0};
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [patch] telemetry object-read signature mismatch at 0x"
                << std::hex << kSkipTelemetryObjectReadOffset << std::dec
                << '\n'
                << std::flush;
      patched = false;
    } else {
      const unsigned char jump_patch[] = {0xe9, 0x81, 0x01, 0x00, 0x00, 0x90};
      patched =
          PatchCode(patch_address, jump_patch, sizeof(jump_patch)) && patched;
    }
  }

  {
    constexpr uintptr_t kSkipHeadlessCallbackCleanupLoopOffset = 0x233475c;
    auto* patch_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kSkipHeadlessCallbackCleanupLoopOffset);
    const unsigned char expected[] = {0x75, 0xe8};
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [patch] post-client-settings callback cleanup loop "
                << "signature mismatch at 0x" << std::hex
                << kSkipHeadlessCallbackCleanupLoopOffset << std::dec << '\n'
                << std::flush;
      patched = false;
    } else {
      const unsigned char nops[] = {0x90, 0x90};
      patched = PatchCode(patch_address, nops, sizeof(nops)) && patched;
    }
  }

  std::cout << "  [patch] post-client-settings telemetry crash guard "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool InitializeSystemDialogHandlerFallback(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_SYSTEM_DIALOG_HANDLER_FALLBACK")) {
    return false;
  }

  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kSystemDialogObjectOffset = 0x70b3b00;
  constexpr uintptr_t kSystemDialogObjectStorageAOffset = 0x70b3b08;
  constexpr uintptr_t kSystemDialogObjectStorageBOffset = 0x70b3b18;
  constexpr uintptr_t kSystemDialogGlobalOffset = 0x70b3c20;
  constexpr uintptr_t kSystemDialogVtableOffset = 0x6befa68;

  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  auto* global = reinterpret_cast<uintptr_t*>(base + kSystemDialogGlobalOffset);
  if (*global != 0) {
    return true;
  }

  auto* object = reinterpret_cast<uintptr_t*>(base + kSystemDialogObjectOffset);
  auto* storage_a = reinterpret_cast<unsigned char*>(
      base + kSystemDialogObjectStorageAOffset);
  auto* storage_b = reinterpret_cast<unsigned char*>(
      base + kSystemDialogObjectStorageBOffset);
  std::memset(storage_a, 0, 16);
  std::memset(storage_b, 0, 16);
  object[0] = base + kSystemDialogVtableOffset;
  *global = reinterpret_cast<uintptr_t>(object);

  std::cout << "  [patch] system dialog handler fallback installed\n"
            << std::flush;
  return true;
}

bool PatchSystemDialogPlatformCalls(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_PATCH_SYSTEM_DIALOG_CALLS")) {
    return false;
  }

  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kCallOffsets[] = {
      0x25067a7, 0x2f539c6, 0x2f54774, 0x2f5495b,
      0x2f57ae8, 0x2f57f9e, 0x2f585ff,
  };
  constexpr unsigned char kNopCall[] = {0x90, 0x90, 0x90, 0x90, 0x90};

  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  bool patched = true;
  for (uintptr_t offset : kCallOffsets) {
    patched = PatchCode(reinterpret_cast<void*>(base + offset), kNopCall,
                        sizeof(kNopCall)) &&
              patched;
  }
  std::cout << "  [patch] system dialog platform calls "
            << (patched ? "disabled" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchHeadlessUpdateAdapterInit(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_PATCH_UPDATE_ADAPTER_INIT")) {
    return false;
  }

  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kUpdateAdapterInitOffset = 0x2345314;
  constexpr unsigned char kReturnOk[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };

  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  bool patched =
      PatchCode(reinterpret_cast<void*>(base + kUpdateAdapterInitOffset),
                kReturnOk, sizeof(kReturnOk));
  std::cout << "  [patch] headless adapter init "
            << (patched ? "disabled" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchHeadlessNullIndexBufferWrite(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_PATCH_NULL_INDEX_BUFFER_WRITE")) {
    return false;
  }

  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kNullIndexWriteOffset = 0x35d3b35;
  constexpr unsigned char kNopWrite[] = {0x90, 0x90, 0x90, 0x90, 0x90};

  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  bool patched =
      PatchCode(reinterpret_cast<void*>(base + kNullIndexWriteOffset),
                kNopWrite, sizeof(kNopWrite));
  std::cout << "  [patch] headless null index buffer write "
            << (patched ? "disabled" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchHeadlessMessageBusJavaPublish(void* publish_response_raw) {
  if (IsDisabled("MOCKTAIL_PATCH_MESSAGE_BUS_JAVA_PUBLISH")) {
    return false;
  }

  constexpr unsigned char kReturnVoid[] = {0xc3};
  constexpr unsigned char kNopJne[] = {0x90, 0x90};

  bool patched =
      PatchCode(publish_response_raw, kReturnVoid, sizeof(kReturnVoid));

  auto* code = reinterpret_cast<unsigned char*>(publish_response_raw);
  bool patched_canary_branch = false;
  for (size_t i = 0; i < 0x800; ++i) {
    if (code[i] != 0x75) {
      continue;
    }

    bool has_epilogue_after_branch = false;
    for (size_t j = i + 2; j < i + 80 && j + 5 < 0x800; ++j) {
      if (code[j] == 0xc3 && code[j + 1] == 0xe8) {
        has_epilogue_after_branch = true;
        break;
      }
    }
    if (!has_epilogue_after_branch) {
      continue;
    }

    patched_canary_branch =
        PatchCode(code + i, kNopJne, sizeof(kNopJne)) || patched_canary_branch;
  }

  patched = patched && patched_canary_branch;
  std::cout << "  [patch] message bus Java publish "
            << (patched ? "disabled" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchHeadlessNullUtf16CopyWrite(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_PATCH_NULL_UTF16_COPY_WRITE")) {
    return false;
  }

  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kNullUtf16WriteOffset = 0x26f4012;
  constexpr unsigned char kNopStore[] = {0x90, 0x90, 0x90};

  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  bool patched =
      PatchCode(reinterpret_cast<void*>(base + kNullUtf16WriteOffset),
                kNopStore, sizeof(kNopStore));
  std::cout << "  [patch] headless null UTF-16 copy write "
            << (patched ? "disabled" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStartAppDebugTrap(void* native_start_app_with_params) {
  if (IsDisabled("MOCKTAIL_PATCH_START_APP_DEBUG_TRAP")) {
    return false;
  }

  // Patch only the diagnostic tail; replacing the entry point would disable
  // real startup.
  constexpr uintptr_t kNativeStartAppOffset = 0x250436d;
  constexpr uintptr_t kTailPatchOffset = 0x2504567;
  constexpr unsigned char kTailJumpPatch[] = {
      0xe9, 0xbc, 0xff, 0xff, 0xff,  // jmp 0x2504528
      0x90, 0x90, 0x90,              // pad overwritten call bytes
  };

  uintptr_t base = reinterpret_cast<uintptr_t>(native_start_app_with_params) -
                   kNativeStartAppOffset;
  bool patched = PatchCode(reinterpret_cast<void*>(base + kTailPatchOffset),
                           kTailJumpPatch, sizeof(kTailJumpPatch));
  std::cout << "  [patch] nativeAppBridgeV2StartAppWithParams tail block "
            << (patched ? "bypassed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchShouldDisplayOpenGLUnsupportedMessage(void* should_display_fn) {
  if (IsDisabled("MOCKTAIL_PATCH_OPENGL_UNSUPPORTED_MSG")) {
    return false;
  }

  constexpr unsigned char kReturnTrue[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };

  bool patched = PatchCode(should_display_fn, kReturnTrue, sizeof(kReturnTrue));
  std::cout << "  [patch] shouldDisplayOpenGLUnsupportedMessage=false "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6RslReleaseCountPanic(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_RSL_RELEASE_COUNT_PANIC")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6RslReleaseCountPanicOffset);
  const unsigned char expected[] = {
      0x48, 0x8b, 0x05, 0x59, 0xaa, 0x8e, 0x04, 0x48, 0x85, 0xc0,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 RSL release-count panic signature "
              << "mismatch at 0x" << std::hex
              << kStage6RslReleaseCountPanicOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  const unsigned char patch[] = {
      0xeb,
      0x20,  // jmp 0x277ef3a
  };
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 RSL release-count panic "
            << (patched ? "bypassed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6FmodErrorTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 || !IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_ERRORS")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6FmodLogHelperOffset);
  if (patch_address[0] == 0xcc) {
    return true;
  }
  if (patch_address[0] != 0x55) {
    std::cerr << "  [patch] Stage6 FMOD error trace signature mismatch at 0x"
              << std::hex << kStage6FmodLogHelperOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kTrap[] = {0xcc};
  const bool patched = PatchCode(patch_address, kTrap, sizeof(kTrap));
  std::cout << "  [trace] Stage6 FMOD error logger trace "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6FmodInitTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      (!IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_INIT") &&
       !IsEnabled("MOCKTAIL_PATCH_STAGE6_FMOD_INIT_FAILURE_AS_SUCCESS"))) {
    return false;
  }

  struct TrapSite {
    uintptr_t offset;
    const unsigned char* expected;
    size_t expected_size;
    const char* name;
  };
  constexpr unsigned char kSystemCreateReturn[] = {0x41, 0x89, 0xc6};
  constexpr unsigned char kSystemInitEntry[] = {0x55};
  constexpr unsigned char kSystemInitFunctionReturn[] = {0x44, 0x89, 0xe0};
  constexpr unsigned char kSystemInitReturn[] = {0x41, 0x89, 0xc5};
  const TrapSite sites[] = {
      {kStage6FmodSystemCreateReturnOffset, kSystemCreateReturn,
       sizeof(kSystemCreateReturn), "System_Create return"},
      {kStage6FmodSystemInitOffset, kSystemInitEntry, sizeof(kSystemInitEntry),
       "System::init entry"},
      {kStage6FmodSystemInitFunctionReturnOffset, kSystemInitFunctionReturn,
       sizeof(kSystemInitFunctionReturn), "System::init function return"},
      {kStage6FmodSystemInitReturnOffset, kSystemInitReturn,
       sizeof(kSystemInitReturn), "System::init return"},
  };

  constexpr unsigned char kTrap[] = {0xcc};
  bool patched_all = true;
  for (const auto& site : sites) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + site.offset);
    if (patch_address[0] == 0xcc) {
      continue;
    }
    if (std::memcmp(patch_address, site.expected, site.expected_size) != 0) {
      std::cerr << "  [patch] Stage6 FMOD init trace signature mismatch at 0x"
                << std::hex << site.offset << std::dec << " (" << site.name
                << ")\n"
                << std::flush;
      patched_all = false;
      continue;
    }
    patched_all &= PatchCode(patch_address, kTrap, sizeof(kTrap));
  }

  std::cout << "  [trace] Stage6 FMOD init trace "
            << (patched_all ? "installed" : "partially failed") << '\n'
            << std::flush;
  return patched_all;
}

bool PatchStage6FmodCreateGroupTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_CREATE_GROUP")) {
    return false;
  }

  struct TrapSite {
    uintptr_t offset;
    const char* name;
  };
  const TrapSite sites[] = {
      {kStage6FmodCreateChannelGroupWrapperReturnOffset, "wrapper return"},
      {kStage6FmodCreateChannelGroupReturnOffset, "create return"},
  };

  constexpr unsigned char kReturnMove[] = {0x44, 0x89, 0xf8};
  constexpr unsigned char kTrap[] = {0xcc};
  bool patched_all = true;
  for (const auto& site : sites) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + site.offset);
    if (patch_address[0] == 0xcc) {
      continue;
    }
    if (std::memcmp(patch_address, kReturnMove, sizeof(kReturnMove)) != 0) {
      std::cerr << "  [patch] Stage6 FMOD create-group trace signature "
                   "mismatch at 0x"
                << std::hex << site.offset << std::dec << " (" << site.name
                << ")\n"
                << std::flush;
      patched_all = false;
      continue;
    }
    patched_all &= PatchCode(patch_address, kTrap, sizeof(kTrap));
  }

  std::cout << "  [trace] Stage6 FMOD create-group trace "
            << (patched_all ? "installed" : "partially failed") << '\n'
            << std::flush;
  return patched_all;
}

bool PatchStage6FmodNativeAudioDeviceGroupFailureLog(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_FMOD_SKIP_GROUP_FAILURE_LOG")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6FmodNativeAudioDeviceGroupFailureLogOffset);
  constexpr unsigned char kExpected[] = {
      0x83, 0xf8, 0x26,  // cmp $0x26,%eax
      0x75, 0x09,        // jne 0x2fba4f8
  };
  if (std::memcmp(patch_address, kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [patch] Stage6 FMOD nativeAudioDeviceChanged "
                 "group-failure signature mismatch at 0x"
              << std::hex << kStage6FmodNativeAudioDeviceGroupFailureLogOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kPatch[] = {
      0xe9, 0x1f, 0x00, 0x00, 0x00,  // jmp 0x2fba50e
  };
  const bool patched = PatchCode(patch_address, kPatch, sizeof(kPatch));
  std::cout << "  [patch] Stage6 FMOD nativeAudioDeviceChanged "
               "group-failure log "
            << (patched ? "skipped" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6FmodNativeAudioDeviceChangedNoOp(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_FMOD_NATIVE_AUDIO_DEVICE_CHANGED_NOOP")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6FmodNativeAudioDeviceChangedOffset);
  constexpr unsigned char kExpected[] = {
      0x55,  // push %rbp
      0x48,
      0x89,
      0xe5,  // mov %rsp,%rbp
  };
  if (patch_address[0] == 0xc3) {
    return true;
  }
  if (std::memcmp(patch_address, kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [patch] Stage6 FMOD nativeAudioDeviceChanged no-op "
                 "signature mismatch at 0x"
              << std::hex << kStage6FmodNativeAudioDeviceChangedOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kPatch[] = {0xc3};  // ret
  const bool patched = PatchCode(patch_address, kPatch, sizeof(kPatch));
  std::cout << "  [patch] Stage6 FMOD nativeAudioDeviceChanged "
            << (patched ? "no-op installed" : "no-op failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6FmodRetryCount(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_FMOD_RETRY_COUNT")) {
    return false;
  }

  auto* retry_count = reinterpret_cast<int*>(libroblox_base +
                                             kStage6FmodRetryCountGlobalOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(retry_count),
                             sizeof(*retry_count))) {
    std::cerr << "  [patch] Stage6 FMOD retry-count global is unreadable\n"
              << std::flush;
    return false;
  }

  const int old_value = *retry_count;
  if (old_value > 0) {
    std::cout << "  [patch] Stage6 FMOD retry-count already " << old_value
              << '\n'
              << std::flush;
    return true;
  }

  if (!EnsureWritablePage(retry_count)) {
    std::cerr << "  [patch] Stage6 FMOD retry-count mprotect failed: "
              << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  *retry_count = 1;
  std::cout << "  [patch] Stage6 FMOD retry-count forced at 0x" << std::hex
            << kStage6FmodRetryCountGlobalOffset << std::dec
            << " old=" << old_value << " new=" << *retry_count << '\n'
            << std::flush;
  return true;
}

}  // namespace mocktail::legacy::internal
