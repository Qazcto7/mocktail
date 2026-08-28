#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/runtime_environment.h"
#include "legacy/stage6_offsets.h"
#include "legacy/stage6_runtime.h"

namespace mocktail::legacy::internal {

bool PatchRobloxStackCheckBranches(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STACK_CHECK_BRANCHES")) {
    return false;
  }

  constexpr unsigned char kNopJne[] = {0x90, 0x90};
  constexpr unsigned char kNopJneLong[] = {
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  };
  constexpr uintptr_t kOffsets[] = {
      0x233419b,  // NativeSettings cookie jar cleanup tail check.
      0x2346c7c,  // NativeGLInterface nativeUpdateAdapterInit tail check.
      0x231760c,  // Stage6 platform header parse error branch.
      0x231761e,  // Stage6 platform header parse error branch.
      0x231768a,  // Stage6 platform header parse error branch.
      0x2317698,  // Stage6 platform header parse error branch.
      0x2311bde,  // Stage6 logging timestamp tail check during StartApp.
      0x23a65fb,  // Stage6 post-client-settings singleton constructor tail
                  // check.
      0x23a67fb,  // Stage6 post-client-settings inner singleton helper tail
                  // check.
      0x23ae7f2,  // Stage6 post-client-settings callback tail check.
      0x233939d,  // Stage6 StartLuaDM dispatcher tail check.
      0x23c643f,  // Stage6 textbox sync outer tail check.
      0x23c66f8,  // Stage6 textbox sync string-copy tail check.
      0x242c58c,  // Stage6 AppBridge vector helper early tail check.
      0x242c71f,  // Stage6 AppBridge vector helper tail check.
      0x243bff9,  // nativeAppBridgeV2InitWithParams tail check after
                  // post-client-settings singleton init.
      0x2440719,  // Stage6 async AppBridge helper tail check.
      0x2440a69,  // Stage6 async AppBridge hash helper tail check.
      0x2440ae0,  // Stage6 async AppBridge hash resize tail check.
      0x2440b6a,  // Stage6 async AppBridge hash resize tail check.
      0x2606451,  // nativeAppBridgeV2StartAppWithParams tail check.
      0x2e012df,  // Stage6 async AppBridge XML serialization tail check.
      0x35e3888,  // Constructor helper stack-canary mismatch tail check.
      0x35e3a1b,  // Constructor helper stack-canary mismatch tail check.
      0x42d415f,  // Stage6 system dialog dismiss callback tail check.
      0x42d417a,  // Stage6 system dialog dismiss callback release tail check.
      0x42d45a7,  // Stage6 system dialog display callback tail check.
      0x42d45c2,  // Stage6 system dialog display callback release tail check.
      0x42d48ad,  // Stage6 system dialog callback outer tail check.
      0x4a42030,  // Stage6 async AppBridge system-dialog tail check.
      0x4a43384,  // Stage6 async AppBridge text-field tail check.
      0x4a434de,  // Stage6 async AppBridge text-field tail check.
      0x6a9035d,  // Stage6 platform text bridge error branch.
      0x6a90375,  // Stage6 platform text bridge tail check.
      0x6a90419,  // Stage6 platform text bridge error branch.
      0x6a9042a,  // Stage6 platform text bridge tail check.
  };

  bool all_patched = true;
  for (uintptr_t offset : kOffsets) {
    const unsigned char* patch_bytes = kNopJne;
    size_t patch_size = sizeof(kNopJne);
    if (offset == 0x231760c || offset == 0x231761e || offset == 0x242c58c ||
        offset == 0x2440ae0 || offset == 0x233939d || offset == 0x35e3888 ||
        offset == 0x4a42030) {
      patch_bytes = kNopJneLong;
      patch_size = sizeof(kNopJneLong);
    }
    bool patched = PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                             patch_bytes, patch_size);
    all_patched = all_patched && patched;
    std::cout << "  [patch] stack-check branch 0x" << std::hex << offset
              << std::dec << (patched ? " patched" : " failed") << '\n'
              << std::flush;
  }
  return all_patched;
}

bool PatchStage6StackCheckExceptionLandings(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_STACK_CHECK_EXCEPTION_LANDINGS")) {
    return false;
  }

  auto patch_landing = [&](uintptr_t landing_offset, uintptr_t cleanup_offset,
                           const char* label) -> bool {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + landing_offset);
    constexpr unsigned char kExpected[] = {0xbf, 0x08, 0x00, 0x00, 0x00};
    if (patch_address[0] == 0xe9) {
      std::cout << "  [patch] Stage6 stack-check exception landing " << label
                << " already patched\n"
                << std::flush;
      return true;
    }
    if (std::memcmp(patch_address, kExpected, sizeof(kExpected)) != 0) {
      std::cerr << "  [patch] Stage6 stack-check exception landing " << label
                << " signature mismatch at 0x" << std::hex << landing_offset
                << std::dec << '\n'
                << std::flush;
      return false;
    }

    const int64_t relative = static_cast<int64_t>(cleanup_offset) -
                             static_cast<int64_t>(landing_offset + 5);
    if (relative < INT32_MIN || relative > INT32_MAX) {
      std::cerr << "  [patch] Stage6 stack-check exception landing " << label
                << " rel32 out of range\n"
                << std::flush;
      return false;
    }

    unsigned char jump_to_cleanup[] = {0xe9, 0x00, 0x00, 0x00, 0x00};
    const int32_t relative32 = static_cast<int32_t>(relative);
    std::memcpy(jump_to_cleanup + 1, &relative32, sizeof(relative32));
    const bool patched =
        PatchCode(patch_address, jump_to_cleanup, sizeof(jump_to_cleanup));
    std::cout << "  [patch] Stage6 stack-check exception landing " << label
              << " 0x" << std::hex << landing_offset << " -> 0x"
              << cleanup_offset << std::dec
              << (patched ? " patched" : " failed") << '\n'
              << std::flush;
    return patched;
  };

  bool patched = true;
  patched &=
      patch_landing(kStage6InitHelperStackFailLandingOffset,
                    kStage6InitHelperStackFailCleanupOffset, "init-helper");
  patched &= patch_landing(kStage6StartAppLoggingStackFailLandingOffset,
                           kStage6StartAppLoggingStackFailCleanupOffset,
                           "StartApp logging");
  return patched;
}

bool PatchStage6ProtectedLockCmpxchgLoop(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_PROTECTED_LOCK_CMPXCHG_LOOP")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6ProtectedLockCmpxchgLoopOffset);
  const unsigned char expected[] = {
      0xf0, 0x48, 0x0f, 0xb1, 0x0c, 0xf2, 0x75, 0xed,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 protected lock-cmpxchg loop signature "
              << "mismatch at 0x" << std::hex
              << kStage6ProtectedLockCmpxchgLoopOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  const unsigned char patch[] = {
      0x48, 0x89, 0xc8,  // mov rax, rcx
      0x90, 0x90, 0x90, 0x90, 0x90,
  };
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 protected lock-cmpxchg loop "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6UnalignedStackMovaps(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_UNALIGNED_STACK_MOVAPS")) {
    return false;
  }

  struct MovapsPatch {
    uintptr_t offset;
    const unsigned char* expected;
    const unsigned char* replacement;
    std::size_t length;
    const char* name;
  };

  static constexpr unsigned char kAlignedLoadExpected[] = {0x41, 0x0f, 0x28,
                                                           0x06};
  static constexpr unsigned char kAlignedLoadReplacement[] = {0x41, 0x0f, 0x10,
                                                              0x06};
  static constexpr unsigned char kStackStoreExpected[] = {0x0f, 0x29, 0x45,
                                                          0xb0};
  static constexpr unsigned char kStackStoreReplacement[] = {0x0f, 0x11, 0x45,
                                                             0xb0};
  static constexpr unsigned char kAppBridgeHelperStackStoreExpected[] = {
      0x0f, 0x29, 0x45, 0xc0};
  static constexpr unsigned char kAppBridgeHelperStackStoreReplacement[] = {
      0x0f, 0x11, 0x45, 0xc0};
  static constexpr unsigned char kActivityLifecycleStackStoreExpected[] = {
      0x0f, 0x29, 0x45, 0xa0};
  static constexpr unsigned char kActivityLifecycleStackStoreReplacement[] = {
      0x0f, 0x11, 0x45, 0xa0};
  static constexpr unsigned char kActivityLifecycleStackLoadExpected[] = {
      0x0f, 0x28, 0x45, 0xa0};
  static constexpr unsigned char kActivityLifecycleStackLoadReplacement[] = {
      0x0f, 0x10, 0x45, 0xa0};
  static constexpr unsigned char kActivityLifecycleZeroStackStoreExpected[] = {
      0x0f, 0x29, 0x4d, 0xa0};
  static constexpr unsigned char kActivityLifecycleZeroStackStoreReplacement[] =
      {0x0f, 0x11, 0x4d, 0xa0};
  static constexpr unsigned char kAppBridgeStateStackLoadExpected[] = {
      0x0f, 0x28, 0x45, 0xc0};
  static constexpr unsigned char kAppBridgeStateStackLoadReplacement[] = {
      0x0f, 0x10, 0x45, 0xc0};
  static constexpr unsigned char kAppBridgeArgumentStackLoad20Expected[] = {
      0x0f, 0x28, 0x45, 0x20};
  static constexpr unsigned char kAppBridgeArgumentStackLoad20Replacement[] = {
      0x0f, 0x10, 0x45, 0x20};
  static constexpr unsigned char kAppBridgeArgumentStackLoad10Expected[] = {
      0x0f, 0x28, 0x45, 0x10};
  static constexpr unsigned char kAppBridgeArgumentStackLoad10Replacement[] = {
      0x0f, 0x10, 0x45, 0x10};
  static constexpr unsigned char kAppBridgeVectorLoadR13Expected[] = {
      0x41, 0x0f, 0x28, 0x45, 0x00};
  static constexpr unsigned char kAppBridgeVectorLoadR13Replacement[] = {
      0x41, 0x0f, 0x10, 0x45, 0x00};
  static constexpr unsigned char kAppBridgeVectorStoreR12Expected[] = {
      0x41, 0x0f, 0x29, 0x44, 0x24, 0x50};
  static constexpr unsigned char kAppBridgeVectorStoreR12Replacement[] = {
      0x41, 0x0f, 0x11, 0x44, 0x24, 0x50};
  static constexpr unsigned char kAppBridgeVectorStoreRdxExpected[] = {
      0x0f, 0x29, 0x02};
  static constexpr unsigned char kAppBridgeVectorStoreRdxReplacement[] = {
      0x0f, 0x11, 0x02};
  static constexpr unsigned char kAppBridgeStateStackStoreExpected[] = {
      0x0f, 0x29, 0x03};
  static constexpr unsigned char kAppBridgeStateStackStoreReplacement[] = {
      0x0f, 0x11, 0x03};
  static constexpr unsigned char kAppBridgeConfigStoreBaseExpected[] = {
      0x0f, 0x29, 0x07};
  static constexpr unsigned char kAppBridgeConfigStoreBaseReplacement[] = {
      0x0f, 0x11, 0x07};
  static constexpr unsigned char kAppBridgeConfigStore20Expected[] = {
      0x0f, 0x29, 0x47, 0x20};
  static constexpr unsigned char kAppBridgeConfigStore20Replacement[] = {
      0x0f, 0x11, 0x47, 0x20};
  static constexpr unsigned char kAppBridgeConfigStore30Expected[] = {
      0x0f, 0x29, 0x47, 0x30};
  static constexpr unsigned char kAppBridgeConfigStore30Replacement[] = {
      0x0f, 0x11, 0x47, 0x30};
  static constexpr unsigned char kAppBridgeConfigStore40Expected[] = {
      0x0f, 0x29, 0x47, 0x40};
  static constexpr unsigned char kAppBridgeConfigStore40Replacement[] = {
      0x0f, 0x11, 0x47, 0x40};
  static constexpr unsigned char kAppBridgeSettingsStoreExpected[] = {
      0x41, 0x0f, 0x29, 0x01};
  static constexpr unsigned char kAppBridgeSettingsStoreReplacement[] = {
      0x41, 0x0f, 0x11, 0x01};
  static constexpr unsigned char kAppBridgeStringStackStoreExpected[] = {
      0x0f, 0x29, 0x85, 0x30, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStoreReplacement[] = {
      0x0f, 0x11, 0x85, 0x30, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStore10Expected[] = {
      0x0f, 0x29, 0x85, 0x10, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStore10Replacement[] = {
      0x0f, 0x11, 0x85, 0x10, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStore50Expected[] = {
      0x0f, 0x29, 0x85, 0x50, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStore50Replacement[] = {
      0x0f, 0x11, 0x85, 0x50, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStore70Expected[] = {
      0x0f, 0x29, 0x85, 0x70, 0xff, 0xff, 0xff};
  static constexpr unsigned char kAppBridgeStringStackStore70Replacement[] = {
      0x0f, 0x11, 0x85, 0x70, 0xff, 0xff, 0xff};
  static constexpr unsigned char kTextboxStringStoreExpected[] = {0x0f, 0x29,
                                                                  0x45, 0xd0};
  static constexpr unsigned char kTextboxStringStoreReplacement[] = {
      0x0f, 0x11, 0x45, 0xd0};
  static constexpr unsigned char kAppBridgeXmlStoreE0Expected[] = {0x0f, 0x29,
                                                                   0x45, 0xe0};
  static constexpr unsigned char kAppBridgeXmlStoreE0Replacement[] = {
      0x0f, 0x11, 0x45, 0xe0};
  static constexpr unsigned char kAppBridgeXmlStoreD0Expected[] = {0x0f, 0x29,
                                                                   0x45, 0xd0};
  static constexpr unsigned char kAppBridgeXmlStoreD0Replacement[] = {
      0x0f, 0x11, 0x45, 0xd0};

  constexpr MovapsPatch kPatches[] = {
      {
          0x23982f6,
          kAlignedLoadExpected,
          kAlignedLoadReplacement,
          sizeof(kAlignedLoadExpected),
          "aligned load",
      },
      {
          0x1f25c8d,
          kStackStoreExpected,
          kStackStoreReplacement,
          sizeof(kStackStoreExpected),
          "stack store",
      },
      {
          0x2429fe3,
          kStackStoreExpected,
          kStackStoreReplacement,
          sizeof(kStackStoreExpected),
          "AppBridge settings stack store",
      },
      {
          0x1f36f0a,
          kAppBridgeSettingsStoreExpected,
          kAppBridgeSettingsStoreReplacement,
          sizeof(kAppBridgeSettingsStoreExpected),
          "AppBridge settings stack store",
      },
      {
          0x6a90541,
          kAppBridgeHelperStackStoreExpected,
          kAppBridgeHelperStackStoreReplacement,
          sizeof(kAppBridgeHelperStackStoreExpected),
          "AppBridge helper stack store",
      },
      {
          0x2426dea,
          kAppBridgeStateStackLoadExpected,
          kAppBridgeStateStackLoadReplacement,
          sizeof(kAppBridgeStateStackLoadExpected),
          "AppBridge state stack load",
      },
      {
          0x2427d40,
          kAppBridgeStateStackLoadExpected,
          kAppBridgeStateStackLoadReplacement,
          sizeof(kAppBridgeStateStackLoadExpected),
          "AppBridge state stack load",
      },
      {
          0x2427d48,
          kAppBridgeStateStackStoreExpected,
          kAppBridgeStateStackStoreReplacement,
          sizeof(kAppBridgeStateStackStoreExpected),
          "AppBridge state stack store",
      },
      {
          0x242b413,
          kAppBridgeArgumentStackLoad20Expected,
          kAppBridgeArgumentStackLoad20Replacement,
          sizeof(kAppBridgeArgumentStackLoad20Expected),
          "AppBridge argument stack load",
      },
      {
          0x242b41c,
          kAppBridgeArgumentStackLoad10Expected,
          kAppBridgeArgumentStackLoad10Replacement,
          sizeof(kAppBridgeArgumentStackLoad10Expected),
          "AppBridge argument stack load",
      },
      {
          0x242b98a,
          kAppBridgeVectorLoadR13Expected,
          kAppBridgeVectorLoadR13Replacement,
          sizeof(kAppBridgeVectorLoadR13Expected),
          "AppBridge vector load",
      },
      {
          0x242b98f,
          kAppBridgeVectorStoreR12Expected,
          kAppBridgeVectorStoreR12Replacement,
          sizeof(kAppBridgeVectorStoreR12Expected),
          "AppBridge vector store",
      },
      {
          0x242c4b0,
          kAppBridgeVectorStoreRdxExpected,
          kAppBridgeVectorStoreRdxReplacement,
          sizeof(kAppBridgeVectorStoreRdxExpected),
          "AppBridge vector stack store",
      },
      {
          0x242c5fd,
          kAppBridgeVectorStoreRdxExpected,
          kAppBridgeVectorStoreRdxReplacement,
          sizeof(kAppBridgeVectorStoreRdxExpected),
          "AppBridge vector stack store",
      },
      {
          0x611fe1b,
          kAppBridgeVectorStoreRdxExpected,
          kAppBridgeVectorStoreRdxReplacement,
          sizeof(kAppBridgeVectorStoreRdxExpected),
          "AppBridge vector stack store",
      },
      {
          0x2380102,
          kActivityLifecycleStackLoadExpected,
          kActivityLifecycleStackLoadReplacement,
          sizeof(kActivityLifecycleStackLoadExpected),
          "AppBridge platform header stack load",
      },
      {
          0x2380109,
          kActivityLifecycleZeroStackStoreExpected,
          kActivityLifecycleZeroStackStoreReplacement,
          sizeof(kActivityLifecycleZeroStackStoreExpected),
          "AppBridge platform header zero stack store",
      },
      {
          0x2314a8f,
          kActivityLifecycleStackStoreExpected,
          kActivityLifecycleStackStoreReplacement,
          sizeof(kActivityLifecycleStackStoreExpected),
          "activity lifecycle stack store",
      },
      {
          0x2429fe7,
          kActivityLifecycleStackStoreExpected,
          kActivityLifecycleStackStoreReplacement,
          sizeof(kActivityLifecycleStackStoreExpected),
          "AppBridge settings stack store",
      },
      {
          0x242a62d,
          kActivityLifecycleStackStoreExpected,
          kActivityLifecycleStackStoreReplacement,
          sizeof(kActivityLifecycleStackStoreExpected),
          "AppBridge settings stack store",
      },
      {
          0x2314ae9,
          kActivityLifecycleStackLoadExpected,
          kActivityLifecycleStackLoadReplacement,
          sizeof(kActivityLifecycleStackLoadExpected),
          "activity lifecycle stack load",
      },
      {
          0x6a42818,
          kActivityLifecycleStackLoadExpected,
          kActivityLifecycleStackLoadReplacement,
          sizeof(kActivityLifecycleStackLoadExpected),
          "activity lifecycle stack load",
      },
      {
          0x6a4281f,
          kActivityLifecycleZeroStackStoreExpected,
          kActivityLifecycleZeroStackStoreReplacement,
          sizeof(kActivityLifecycleZeroStackStoreExpected),
          "activity lifecycle zero stack store",
      },
      {
          0x2309f8e,
          kAppBridgeConfigStoreBaseExpected,
          kAppBridgeConfigStoreBaseReplacement,
          sizeof(kAppBridgeConfigStoreBaseExpected),
          "AppBridge config stack store",
      },
      {
          0x2309f9c,
          kAppBridgeConfigStore20Expected,
          kAppBridgeConfigStore20Replacement,
          sizeof(kAppBridgeConfigStore20Expected),
          "AppBridge config stack store",
      },
      {
          0x2309fa0,
          kAppBridgeConfigStore30Expected,
          kAppBridgeConfigStore30Replacement,
          sizeof(kAppBridgeConfigStore30Expected),
          "AppBridge config stack store",
      },
      {
          0x2309fa4,
          kAppBridgeConfigStore40Expected,
          kAppBridgeConfigStore40Replacement,
          sizeof(kAppBridgeConfigStore40Expected),
          "AppBridge config stack store",
      },
      {
          0x615e0cb,
          kAppBridgeStringStackStoreExpected,
          kAppBridgeStringStackStoreReplacement,
          sizeof(kAppBridgeStringStackStoreExpected),
          "AppBridge string stack store",
      },
      {
          0x615e14d,
          kAppBridgeStringStackStore10Expected,
          kAppBridgeStringStackStore10Replacement,
          sizeof(kAppBridgeStringStackStore10Expected),
          "AppBridge string stack store",
      },
      {
          0x615e1f9,
          kAppBridgeStringStackStore50Expected,
          kAppBridgeStringStackStore50Replacement,
          sizeof(kAppBridgeStringStackStore50Expected),
          "AppBridge string stack store",
      },
      {
          0x615e631,
          kAppBridgeStringStackStore50Expected,
          kAppBridgeStringStackStore50Replacement,
          sizeof(kAppBridgeStringStackStore50Expected),
          "AppBridge string stack store",
      },
      {
          0x242a587,
          kAppBridgeStringStackStore70Expected,
          kAppBridgeStringStackStore70Replacement,
          sizeof(kAppBridgeStringStackStore70Expected),
          "AppBridge string stack store",
      },
      {
          0x23c66bf,
          kTextboxStringStoreExpected,
          kTextboxStringStoreReplacement,
          sizeof(kTextboxStringStoreExpected),
          "textbox string store",
      },
      {
          0x243c7cb,
          kTextboxStringStoreExpected,
          kTextboxStringStoreReplacement,
          sizeof(kTextboxStringStoreExpected),
          "AppBridge map helper zero stack store",
      },
      {
          0x235aa2e,
          kAppBridgeXmlStoreE0Expected,
          kAppBridgeXmlStoreE0Replacement,
          sizeof(kAppBridgeXmlStoreE0Expected),
          "AppBridge XML helper stack store",
      },
      {
          0x235aa32,
          kAppBridgeXmlStoreD0Expected,
          kAppBridgeXmlStoreD0Replacement,
          sizeof(kAppBridgeXmlStoreD0Expected),
          "AppBridge XML helper stack store",
      },
      {
          0x235aac4,
          kAppBridgeXmlStoreE0Expected,
          kAppBridgeXmlStoreE0Replacement,
          sizeof(kAppBridgeXmlStoreE0Expected),
          "AppBridge XML helper stack store",
      },
      {
          0x235aac8,
          kAppBridgeXmlStoreD0Expected,
          kAppBridgeXmlStoreD0Replacement,
          sizeof(kAppBridgeXmlStoreD0Expected),
          "AppBridge XML helper stack store",
      },
  };

  bool all_patched = true;
  for (const MovapsPatch& patch : kPatches) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + patch.offset);
    if (std::memcmp(patch_address, patch.expected, patch.length) != 0) {
      std::cerr << "  [patch] Stage6 unaligned stack movaps signature "
                << "mismatch at 0x" << std::hex << patch.offset << std::dec
                << " (" << patch.name << ")\n"
                << std::flush;
      all_patched = false;
      continue;
    }

    bool patched = PatchCode(patch_address, patch.replacement, patch.length);
    all_patched = all_patched && patched;
    std::cout << "  [patch] Stage6 unaligned stack movaps 0x" << std::hex
              << patch.offset << std::dec << " (" << patch.name << ") "
              << (patched ? "patched" : "failed") << '\n'
              << std::flush;
  }
  return all_patched;
}

bool PatchStage6MessageBusSelfReferenceCallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_MESSAGEBUS_SELF_REFERENCE_CALLBACK")) {
    return false;
  }

  constexpr uintptr_t kSelfReferenceBranchOffset = 0x2c2658b;
  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kSelfReferenceBranchOffset);
  const unsigned char expected[] = {
      0x74,
      0x1b,  // je self-reference callback path.
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 MessageBus self-reference callback "
              << "signature mismatch at 0x" << std::hex
              << kSelfReferenceBranchOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  const unsigned char patch[] = {
      0xeb,
      0x0c,  // jmp empty-output path.
  };
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 MessageBus self-reference callback "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6MessagePumpReverseCopy(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_MESSAGE_PUMP_REVERSE_COPY")) {
    return false;
  }

  constexpr uintptr_t kReverseCopyBranchOffset = 0x1f241b7;
  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kReverseCopyBranchOffset);
  const unsigned char expected[] = {
      0x7e,
      0x21,  // jle skip reverse-copy loop.
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 message pump reverse-copy signature "
              << "mismatch at 0x" << std::hex << kReverseCopyBranchOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  const unsigned char patch[] = {
      0xeb,
      0x21,  // always skip reverse-copy loop with unstable buffer state.
  };
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 message pump reverse-copy "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlUnsupportedMessageHelpers(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_UNSUPPORTED_MESSAGE_HELPERS")) {
    return false;
  }

  struct HelperPatch {
    uintptr_t offset;
    unsigned char expected[4];
    unsigned char replacement[3];
    size_t replacement_size;
    const char* name;
  };
  constexpr HelperPatch kPatches[] = {
      {
          0x277c470,
          {0x55, 0x48, 0x89, 0xe5},
          {0x31, 0xc0, 0xc3},
          3,
          "system-dialog platform-message object",
      },
      {
          0x277d3a0,
          {0x55, 0x48, 0x89, 0xe5},
          {0xc3, 0x90, 0x90},
          1,
          "release invalid platform-message object",
      },
      {
          0x277d540,
          {0x55, 0x48, 0x89, 0xe5},
          {0xc3, 0x90, 0x90},
          1,
          "build platform-message object",
      },
      {
          0x277d6b0,
          {0x55, 0x48, 0x89, 0xe5},
          {0xc3, 0x90, 0x90},
          1,
          "read platform-message object",
      },
      {
          0x277e060,
          {0x55, 0x48, 0x89, 0xe5},
          {0x31, 0xc0, 0xc3},
          3,
          "query platform-message object",
      },
  };

  bool all_patched = true;
  for (const HelperPatch& patch : kPatches) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + patch.offset);
    if (std::memcmp(patch_address, patch.expected, sizeof(patch.expected)) !=
        0) {
      std::cerr << "  [patch] Stage6 GL unsupported-message helper "
                << "signature mismatch at 0x" << std::hex << patch.offset
                << std::dec << " (" << patch.name << ")\n"
                << std::flush;
      all_patched = false;
      continue;
    }

    bool patched =
        PatchCode(patch_address, patch.replacement, patch.replacement_size);
    all_patched = all_patched && patched;
    std::cout << "  [patch] Stage6 GL unsupported-message helper 0x" << std::hex
              << patch.offset << std::dec << " (" << patch.name << ") "
              << (patched ? "patched" : "failed") << '\n'
              << std::flush;
  }
  return all_patched;
}

bool PatchStage6PlatformHeadersLookupReturnEmptyEntry(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_PLATFORM_HEADERS_LOOKUP")) {
    return false;
  }

  constexpr uintptr_t kPlatformHeadersLookupOffset = 0x236d3d0;
  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kPlatformHeadersLookupOffset);
  const unsigned char expected[] = {
      0x55,
      0x48,
      0x89,
      0xe5,  // push rbp; mov rsp, rbp
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 platform headers lookup signature "
              << "mismatch at 0x" << std::hex << kPlatformHeadersLookupOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  std::memset(g_stage6_platform_headers_empty_entry, 0,
              sizeof(g_stage6_platform_headers_empty_entry));
  WriteLibcxxString(g_stage6_platform_headers_empty_entry + 0x28, "");
  std::memset(g_stage6_platform_headers_zero_string, 0,
              sizeof(g_stage6_platform_headers_zero_string));
  WriteLibcxxString(g_stage6_platform_headers_zero_string, "0");
  unsigned char patch[11] = {
      0x48, 0xb8,  // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0,
      0xc3,  // ret
  };
  const uintptr_t empty_entry =
      reinterpret_cast<uintptr_t>(g_stage6_platform_headers_empty_entry);
  std::memcpy(patch + 2, &empty_entry, sizeof(empty_entry));
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 platform headers lookup return-empty-entry "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartGameAssetAtIndexClamp(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_GAME_ASSET_AT_INDEX_CLAMP")) {
    return false;
  }

  struct TrapPatch {
    uintptr_t offset;
    const char* name;
  };
  constexpr TrapPatch kPatches[] = {
      {kStage6StartGameAssetLookupAtIndexAssertOffset, "lookup at_index"},
      {kStage6StartGameAssetLoopAtIndexAssertOffset, "loop at_index"},
  };

  bool patched_any = false;
  constexpr unsigned char kTrap = 0xcc;
  for (const TrapPatch& patch : kPatches) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + patch.offset);
    if (*patch_address != 0x48) {
      std::cerr << "  [patch] Stage6 StartGame asset " << patch.name
                << " signature mismatch at 0x" << std::hex << patch.offset
                << std::dec << '\n'
                << std::flush;
      continue;
    }
    const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
    patched_any = patched_any || patched;
    std::cout << "  [patch] Stage6 StartGame asset " << patch.name << " clamp "
              << (patched ? "armed" : "failed") << " at 0x" << std::hex
              << patch.offset << std::dec << '\n'
              << std::flush;
  }
  return patched_any;
}

bool PatchStage6StartLuaOptionalStringLookups(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_OPTIONAL_STRINGS")) {
    return false;
  }

  struct OptionalStringPatch {
    uintptr_t offset;
    unsigned char expected[9];
    unsigned char replacement[9];
    const char* name;
  };

  constexpr OptionalStringPatch kPatches[] = {
      {
          0x243ed84,
          {
              0x48,
              0x8d,
              0x7d,
              0xc0,  // lea -0x40(%rbp), %rdi
              0xe8,
              0x6b,
              0x93,
              0xf5,
              0xff,
          },
          {
              0x48,
              0xc7,
              0x45,
              0xc0,
              0x00,
              0x00,
              0x00,
              0x00,
              0x90,
          },
          "first optional string",
      },
      {
          0x243edfb,
          {
              0x48,
              0x8d,
              0x7d,
              0xa8,  // lea -0x58(%rbp), %rdi
              0xe8,
              0xf4,
              0x92,
              0xf5,
              0xff,
          },
          {
              0x48,
              0xc7,
              0x45,
              0xa8,
              0x00,
              0x00,
              0x00,
              0x00,
              0x90,
          },
          "second optional string",
      },
  };

  bool all_patched = true;
  for (const OptionalStringPatch& patch : kPatches) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + patch.offset);
    if (std::memcmp(patch_address, patch.expected, sizeof(patch.expected)) !=
        0) {
      std::cerr << "  [patch] Stage6 StartLuaAppDM optional string "
                << "signature mismatch at 0x" << std::hex << patch.offset
                << std::dec << " (" << patch.name << ")\n"
                << std::flush;
      all_patched = false;
      continue;
    }

    bool patched =
        PatchCode(patch_address, patch.replacement, sizeof(patch.replacement));
    all_patched = all_patched && patched;
    std::cout << "  [patch] Stage6 StartLuaAppDM " << patch.name << " "
              << (patched ? "patched" : "failed") << '\n'
              << std::flush;
  }
  return all_patched;
}

bool PatchStage6StartLuaNullAppStateGuard(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_NULL_APP_STATE_GUARD")) {
    return false;
  }

  constexpr uintptr_t kNullAppStateDerefOffset = 0x24ec821;
  constexpr uintptr_t kNullAppStateReturnOffset = 0x24ec840;
  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kNullAppStateDerefOffset);
  const unsigned char expected[] = {
      0x41, 0x83, 0xbe, 0x38, 0x01, 0x00, 0x00, 0x00,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 StartLuaAppDM null app-state guard "
              << "signature mismatch at 0x" << std::hex
              << kNullAppStateDerefOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  unsigned char jump_to_return[] = {
      0xe9,  // jmp rel32
      0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90,
  };
  const uintptr_t jump_next = kNullAppStateDerefOffset + 5;
  int32_t rel = static_cast<int32_t>(kNullAppStateReturnOffset - jump_next);
  std::memcpy(jump_to_return + 1, &rel, sizeof(rel));
  bool patched =
      PatchCode(patch_address, jump_to_return, sizeof(jump_to_return));
  std::cout << "  [patch] Stage6 StartLuaAppDM null app-state guard "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaForceLoggedInBranch(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_FORCE_LOGGED_IN_BRANCH")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaLoggedInBranchOffset);
  constexpr unsigned char expected[] = {
      0x0f, 0x84, 0x97, 0x00, 0x00, 0x00,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 StartLuaAppDM logged-in branch signature "
              << "mismatch at 0x" << std::hex
              << kStage6StartLuaLoggedInBranchOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char nops[] = {
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  };
  bool patched = PatchCode(patch_address, nops, sizeof(nops));
  std::cout << "  [patch] Stage6 StartLuaAppDM logged-in branch "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaForceAltSetupBranch(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_FORCE_ALT_SETUP_BRANCH")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaDirectClosureAltSetupBranchOffset);
  constexpr unsigned char expected[] = {
      0x75,
      0x25,  // jne +0x25
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 StartLuaAppDM alt setup branch signature "
              << "mismatch at 0x" << std::hex
              << kStage6StartLuaDirectClosureAltSetupBranchOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char force_jump[] = {
      0xeb,
      0x25,  // jmp +0x25
  };
  bool patched = PatchCode(patch_address, force_jump, sizeof(force_jump));
  std::cout << "  [patch] Stage6 StartLuaAppDM alt setup branch "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaDmForceSameThread(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaDMInvokerAsyncPathOffset);
  constexpr unsigned char kTrap = 0xcc;
  if (std::memcmp(patch_address, &kTrap, sizeof(kTrap)) == 0) {
    if (EngineTraceEnabled()) {
      std::cout << "  [patch] Stage6 StartLuaAppDM same-thread dispatch "
                << "already armed at 0x" << std::hex
                << kStage6StartLuaDMInvokerAsyncPathOffset << std::dec << '\n'
                << std::flush;
    }
    return true;
  }

  constexpr unsigned char kExpected = 0x4c;
  if (std::memcmp(patch_address, &kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [patch] Stage6 StartLuaAppDM same-thread dispatch "
              << "signature mismatch at 0x" << std::hex
              << kStage6StartLuaDMInvokerAsyncPathOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
  std::cout << "  [patch] Stage6 StartLuaAppDM same-thread dispatch "
            << (patched ? "armed" : "failed") << " at 0x" << std::hex
            << kStage6StartLuaDMInvokerAsyncPathOffset << std::dec << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaSingleSurfaceEntrySetup(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_SINGLE_SURFACE_ENTRY")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaSingleSurfaceStartLuaAppOffset);
  constexpr unsigned char kTrap = 0xcc;
  if (std::memcmp(patch_address, &kTrap, sizeof(kTrap)) == 0) {
    std::cout << "  [patch] Stage6 single-surface startLuaApp entry setup "
              << "already armed at 0x" << std::hex
              << kStage6StartLuaSingleSurfaceStartLuaAppOffset << std::dec
              << '\n'
              << std::flush;
    return true;
  }

  constexpr unsigned char kExpected = 0x55;
  if (std::memcmp(patch_address, &kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [patch] Stage6 single-surface startLuaApp entry setup "
              << "signature mismatch at 0x" << std::hex
              << kStage6StartLuaSingleSurfaceStartLuaAppOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
  std::cout << "  [patch] Stage6 single-surface startLuaApp entry setup "
            << (patched ? "armed" : "failed") << " at 0x" << std::hex
            << kStage6StartLuaSingleSurfaceStartLuaAppOffset << std::dec << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaAppDMGlobalLoadSetup(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_TABLE")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaAppDMGlobalLoadOffset);
  constexpr unsigned char kTrap = 0xcc;
  if (std::memcmp(patch_address, &kTrap, sizeof(kTrap)) == 0) {
    std::cout << "  [patch] Stage6 StartLuaAppDM global target-table setup "
              << "already armed at 0x" << std::hex
              << kStage6StartLuaAppDMGlobalLoadOffset << std::dec << '\n'
              << std::flush;
    return true;
  }

  constexpr unsigned char kExpected = 0x48;
  if (std::memcmp(patch_address, &kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [patch] Stage6 StartLuaAppDM global target-table setup "
              << "signature mismatch at 0x" << std::hex
              << kStage6StartLuaAppDMGlobalLoadOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
  std::cout << "  [patch] Stage6 StartLuaAppDM global target-table setup "
            << (patched ? "armed" : "failed") << " at 0x" << std::hex
            << kStage6StartLuaAppDMGlobalLoadOffset << std::dec << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaDeepEntryTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_DEEP")) {
    return false;
  }

  bool patched_any = false;
  auto patch_trace_byte = [&](uintptr_t offset, unsigned char expected,
                              const char* label) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + offset);
    constexpr unsigned char kTrap = 0xcc;
    if (std::memcmp(patch_address, &kTrap, sizeof(kTrap)) == 0) {
      std::cout << "  [trace] Stage6 " << label << " already armed at 0x"
                << std::hex << offset << std::dec << '\n'
                << std::flush;
      patched_any = true;
      return;
    }
    if (std::memcmp(patch_address, &expected, sizeof(expected)) != 0) {
      std::cerr << "  [trace] Stage6 " << label << " signature mismatch at 0x"
                << std::hex << offset << std::dec << '\n'
                << std::flush;
      return;
    }

    const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
    std::cout << "  [trace] Stage6 " << label << ' '
              << (patched ? "armed" : "failed") << '\n'
              << std::flush;
    patched_any |= patched;
  };

  patch_trace_byte(kStage6StartLuaAppDMGlobalLoadOffset, 0x48,
                   "StartLuaAppDM global load");
  patch_trace_byte(kStage6StartLuaAppDMBeforeDispatchOffset, 0x31,
                   "StartLuaAppDM before dispatch");
  patch_trace_byte(kStage6StartLuaAppDMAfterDispatchOffset, 0x48,
                   "StartLuaAppDM after dispatch");
  patch_trace_byte(kStage6StartLuaDMDispatchOffset, 0x55,
                   "StartLuaAppDM dispatch helper entry");
  patch_trace_byte(kStage6StartLuaDMDispatchSelectedManagerOffset, 0x49,
                   "StartLuaAppDM selected manager");
  patch_trace_byte(kStage6StartLuaDMInvokerOffset, 0x55,
                   "StartLuaAppDM invoker entry");
  patch_trace_byte(kStage6StartLuaDMInvokerSameThreadObjectLoadOffset, 0x48,
                   "StartLuaAppDM invoker same-thread path");
  patch_trace_byte(kStage6StartLuaDMInvokerAsyncPathOffset, 0x4c,
                   "StartLuaAppDM invoker async path");
  patch_trace_byte(kStage6StartLuaDMInvokerNullResultOffset, 0x48,
                   "StartLuaAppDM invoker null-result path");
  patch_trace_byte(kStage6StartLuaSingleSurfaceStartLuaAppOffset, 0x55,
                   "single-surface startLuaApp entry");
  patch_trace_byte(kStage6StartLuaUserDidLoginOffset, 0x55,
                   "userDidLogin entry");
  patch_trace_byte(kStage6StartLuaUserDidLoginDeepCallStateLoadOffset, 0x48,
                   "userDidLogin deep-call state load");
  patch_trace_byte(kStage6StartLuaDeepStartOffset, 0x55, "deep StartLua entry");
  patch_trace_byte(kStage6StartLuaDeepAppStateUpdateOffset, 0x55,
                   "deep app-state update entry");
  patch_trace_byte(kStage6StartLuaDeepStateCopyOffset, 0x55,
                   "deep state-copy entry");
  patch_trace_byte(kStage6StartLuaDeepHeaderLoadOffset, 0x49,
                   "deep header load");
  patch_trace_byte(kStage6StartLuaDeepHeaderChecksPassedOffset, 0x4d,
                   "deep header checks passed");
  patch_trace_byte(kStage6StartLuaDeepCleanupOffset, 0x48, "deep cleanup");
  return patched_any;
}

bool PatchStage6StartLuaUserDidLoginStateLoadRecovery(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_USER_DID_LOGIN_STATE_LOAD")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaUserDidLoginDeepCallStateLoadOffset);
  constexpr unsigned char kTrap = 0xcc;
  if (std::memcmp(patch_address, &kTrap, sizeof(kTrap)) == 0) {
    std::cout << "  [patch] Stage6 userDidLogin state-load recovery "
              << "already armed at 0x" << std::hex
              << kStage6StartLuaUserDidLoginDeepCallStateLoadOffset << std::dec
              << '\n'
              << std::flush;
    return true;
  }

  constexpr unsigned char kExpected = 0x48;
  if (std::memcmp(patch_address, &kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [patch] Stage6 userDidLogin state-load recovery "
              << "signature mismatch at 0x" << std::hex
              << kStage6StartLuaUserDidLoginDeepCallStateLoadOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
  std::cout << "  [patch] Stage6 userDidLogin state-load recovery "
            << (patched ? "armed" : "failed") << " at 0x" << std::hex
            << kStage6StartLuaUserDidLoginDeepCallStateLoadOffset << std::dec
            << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartLuaRefcountReleaseTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      (!IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_REFCOUNT_RELEASE") &&
       !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_REFCOUNT_RELEASE_ZERO"))) {
    return false;
  }

  auto* shared_patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaSharedRefcountReleaseHelperOffset);
  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaRefcountReleaseHelperOffset);
  constexpr unsigned char expected[] = {
      0x55,
      0x48,
      0x89,
      0xe5,  // push rbp; mov rbp, rsp
  };
  bool patched_any = false;
  if (std::memcmp(shared_patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [trace] Stage6 StartLua shared refcount release "
              << "signature mismatch at 0x" << std::hex
              << kStage6StartLuaSharedRefcountReleaseHelperOffset << std::dec
              << '\n'
              << std::flush;
  } else {
    constexpr unsigned char trap[] = {0xcc};
    const bool patched = PatchCode(shared_patch_address, trap, sizeof(trap));
    std::cout << "  [trace] Stage6 StartLua shared refcount release "
              << (patched ? "armed" : "failed") << '\n'
              << std::flush;
    patched_any |= patched;
  }

  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [trace] Stage6 StartLua refcount release signature "
              << "mismatch at 0x" << std::hex
              << kStage6StartLuaRefcountReleaseHelperOffset << std::dec << '\n'
              << std::flush;
    return patched_any;
  }

  constexpr unsigned char trap[] = {0xcc};
  const bool patched = PatchCode(patch_address, trap, sizeof(trap));
  std::cout << "  [trace] Stage6 StartLua refcount release "
            << (patched ? "armed" : "failed") << '\n'
            << std::flush;
  return patched_any || patched;
}

bool PatchStage6StartLuaGateTrace(uintptr_t libroblox_base) {
  const bool trace_gate = IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_GATE");
  const bool needs_target_table_hooks =
      IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_TARGET_TABLE") ||
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_OBJECT") ||
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALL_RESULT") ||
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_POST_APPLY_PAIR_ARGUMENT") ||
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_POST_APPLY_NULL_ARGUMENT") ||
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_DISPATCHER_SECOND_PAIR_ARGUMENT") ||
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_CALLBACK") ||
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PAIR_CALLBACK") ||
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_SPLIT_CALLBACK_"
          "ARGS");
  const bool trace_logged_in =
      IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_LOGGED_IN_HELPER") ||
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FROM_OWNER") ||
      needs_target_table_hooks;
  const bool trace_result20_lookup =
      IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_RESULT20_LOOKUP") ||
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_EMPTY") ||
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_TARGET_"
          "PAIR");
  const bool trace_source_builder =
      IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_SOURCE_BUILDER") ||
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_SYNTHETIC_INSTANCE_SOURCE");
  if (libroblox_base == 0 ||
      (!trace_gate && !trace_logged_in && !trace_result20_lookup &&
       !trace_source_builder)) {
    return false;
  }

  bool patched_any = false;
  if (trace_gate) {
    auto* state_load_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kStage6StartLuaGateStateLoadOffset);
    constexpr unsigned char state_load_expected[] = {0x48};
    if (std::memcmp(state_load_address, state_load_expected,
                    sizeof(state_load_expected)) == 0) {
      constexpr unsigned char trap[] = {0xcc};
      patched_any |= PatchCode(state_load_address, trap, sizeof(trap));
    } else {
      std::cerr
          << "  [trace] Stage6 StartLua gate state-load signature mismatch "
          << "at 0x" << std::hex << kStage6StartLuaGateStateLoadOffset
          << std::dec << '\n'
          << std::flush;
    }

    auto* helper_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kStage6StartLuaGateHelperOffset);
    constexpr unsigned char helper_expected[] = {0x55};
    if (std::memcmp(helper_address, helper_expected, sizeof(helper_expected)) ==
        0) {
      constexpr unsigned char trap[] = {0xcc};
      patched_any |= PatchCode(helper_address, trap, sizeof(trap));
    } else {
      std::cerr << "  [trace] Stage6 StartLua gate helper signature mismatch "
                << "at 0x" << std::hex << kStage6StartLuaGateHelperOffset
                << std::dec << '\n'
                << std::flush;
    }
  }

  if (trace_logged_in) {
    auto* logged_in_helper_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kStage6StartLuaLoggedInHelperOffset);
    constexpr unsigned char logged_in_helper_expected[] = {0x55};
    if (std::memcmp(logged_in_helper_address, logged_in_helper_expected,
                    sizeof(logged_in_helper_expected)) == 0) {
      constexpr unsigned char trap[] = {0xcc};
      patched_any |= PatchCode(logged_in_helper_address, trap, sizeof(trap));
    } else {
      std::cerr << "  [trace] Stage6 StartLua logged-in helper signature "
                << "mismatch at 0x" << std::hex
                << kStage6StartLuaLoggedInHelperOffset << std::dec << '\n'
                << std::flush;
    }

    auto* logged_in_target_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kStage6StartLuaLoggedInTargetEntryOffset);
    constexpr unsigned char logged_in_target_expected[] = {0x55};
    if (std::memcmp(logged_in_target_address, logged_in_target_expected,
                    sizeof(logged_in_target_expected)) == 0) {
      constexpr unsigned char trap[] = {0xcc};
      patched_any |= PatchCode(logged_in_target_address, trap, sizeof(trap));
    } else {
      std::cerr << "  [trace] Stage6 StartLua logged-in target signature "
                << "mismatch at 0x" << std::hex
                << kStage6StartLuaLoggedInTargetEntryOffset << std::dec << '\n'
                << std::flush;
    }

    if (needs_target_table_hooks) {
      auto* target_apply_address = reinterpret_cast<unsigned char*>(
          libroblox_base + kStage6StartLuaTargetApplyOffset);
      constexpr unsigned char target_apply_expected[] = {0x55};
      if (std::memcmp(target_apply_address, target_apply_expected,
                      sizeof(target_apply_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |= PatchCode(target_apply_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua target apply signature "
                  << "mismatch at 0x" << std::hex
                  << kStage6StartLuaTargetApplyOffset << std::dec << '\n'
                  << std::flush;
      }

      auto* target_post_apply_address = reinterpret_cast<unsigned char*>(
          libroblox_base + kStage6StartLuaTargetPostApplyOffset);
      constexpr unsigned char target_post_apply_expected[] = {0x55};
      if (std::memcmp(target_post_apply_address, target_post_apply_expected,
                      sizeof(target_post_apply_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |= PatchCode(target_post_apply_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua target post-apply signature "
                  << "mismatch at 0x" << std::hex
                  << kStage6StartLuaTargetPostApplyOffset << std::dec << '\n'
                  << std::flush;
      }

      auto* target_post_apply_trigger_address =
          reinterpret_cast<unsigned char*>(
              libroblox_base + kStage6StartLuaTargetPostApplyTriggerOffset);
      constexpr unsigned char target_post_apply_trigger_expected[] = {0x48};
      if (std::memcmp(target_post_apply_trigger_address,
                      target_post_apply_trigger_expected,
                      sizeof(target_post_apply_trigger_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |=
            PatchCode(target_post_apply_trigger_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua target post-apply trigger "
                  << "signature mismatch at 0x" << std::hex
                  << kStage6StartLuaTargetPostApplyTriggerOffset << std::dec
                  << '\n'
                  << std::flush;
      }

      auto* target_post_apply_callback_address =
          reinterpret_cast<unsigned char*>(
              libroblox_base + kStage6StartLuaTargetPostApplyCallbackOffset);
      constexpr unsigned char target_post_apply_callback_expected[] = {0x48};
      if (std::memcmp(target_post_apply_callback_address,
                      target_post_apply_callback_expected,
                      sizeof(target_post_apply_callback_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |=
            PatchCode(target_post_apply_callback_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua target post-apply callback "
                  << "signature mismatch at 0x" << std::hex
                  << kStage6StartLuaTargetPostApplyCallbackOffset << std::dec
                  << '\n'
                  << std::flush;
      }

      auto* target_post_apply_exit_address = reinterpret_cast<unsigned char*>(
          libroblox_base + kStage6StartLuaTargetPostApplyExitOffset);
      constexpr unsigned char target_post_apply_exit_expected[] = {0x49};
      if (std::memcmp(target_post_apply_exit_address,
                      target_post_apply_exit_expected,
                      sizeof(target_post_apply_exit_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |=
            PatchCode(target_post_apply_exit_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua target post-apply exit "
                  << "signature mismatch at 0x" << std::hex
                  << kStage6StartLuaTargetPostApplyExitOffset << std::dec
                  << '\n'
                  << std::flush;
      }

      auto* target_post_apply_task_thunk_address =
          reinterpret_cast<unsigned char*>(
              libroblox_base + kStage6StartLuaTargetPostApplyTaskThunkOffset);
      constexpr unsigned char target_post_apply_task_thunk_expected[] = {0x55};
      if (std::memcmp(target_post_apply_task_thunk_address,
                      target_post_apply_task_thunk_expected,
                      sizeof(target_post_apply_task_thunk_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |=
            PatchCode(target_post_apply_task_thunk_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua target post-apply task thunk "
                  << "signature mismatch at 0x" << std::hex
                  << kStage6StartLuaTargetPostApplyTaskThunkOffset << std::dec
                  << '\n'
                  << std::flush;
      }

      auto* target_post_apply_task_thunk_return_address =
          reinterpret_cast<unsigned char*>(
              libroblox_base +
              kStage6StartLuaTargetPostApplyTaskThunkReturnOffset);
      constexpr unsigned char target_post_apply_task_thunk_return_expected[] = {
          0x48};
      if (std::memcmp(target_post_apply_task_thunk_return_address,
                      target_post_apply_task_thunk_return_expected,
                      sizeof(target_post_apply_task_thunk_return_expected)) ==
          0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |= PatchCode(target_post_apply_task_thunk_return_address,
                                 trap, sizeof(trap));
      } else {
        std::cerr
            << "  [trace] Stage6 StartLua target post-apply task thunk return "
            << "signature mismatch at 0x" << std::hex
            << kStage6StartLuaTargetPostApplyTaskThunkReturnOffset << std::dec
            << '\n'
            << std::flush;
      }

      auto patch_task_thunk_trace_byte =
          [&](uintptr_t offset, unsigned char expected, const char* label) {
            auto* address =
                reinterpret_cast<unsigned char*>(libroblox_base + offset);
            if (std::memcmp(address, &expected, sizeof(expected)) == 0) {
              constexpr unsigned char trap[] = {0xcc};
              patched_any |= PatchCode(address, trap, sizeof(trap));
            } else {
              std::cerr << "  [trace] Stage6 StartLua task thunk " << label
                        << " signature mismatch at 0x" << std::hex << offset
                        << std::dec << '\n'
                        << std::flush;
            }
          };
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkInitReadyOffset, 0x4c,
          "init-ready");
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkBeforeTargetCallOffset, 0x48,
          "before-target-call");
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkAfterTargetCallOffset, 0x48,
          "after-target-call");
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkAfterResolveOffset, 0x48,
          "after-resolve");
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkCallbackInvokeOffset, 0x48,
          "callback-invoke");
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkAfterCallbackOffset, 0x48,
          "after-callback");
      patch_task_thunk_trace_byte(
          kStage6StartLuaTargetPostApplyTaskThunkFastNilOffset, 0x31,
          "fast-nil");

      if (IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_RESOLVER")) {
        patch_task_thunk_trace_byte(kStage6StartLuaResolverBuildOffset, 0x55,
                                    "resolver-build");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverAfterTaskBuildOffset,
                                    0x48, "resolver-after-task-build");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverQueueBindOffset,
                                    0x4c, "resolver-queue-bind");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverQueuePickOffset,
                                    0x55, "resolver-queue-pick");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverQueuePickNullOffset,
                                    0x48, "resolver-queue-pick-null");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverQueuePickStoreOffset,
                                    0x48, "resolver-queue-pick-store");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverSchedulerEntryOffset,
                                    0x55, "resolver-scheduler-entry");
        patch_task_thunk_trace_byte(
            kStage6StartLuaResolverSchedulerProcLoadOffset, 0x4c,
            "resolver-scheduler-proc-load");
        patch_task_thunk_trace_byte(
            kStage6StartLuaResolverClosureDispatchOffset, 0x49,
            "resolver-closure-dispatch");
        patch_task_thunk_trace_byte(
            kStage6StartLuaResolverProcMatchBranchOffset, 0x0f,
            "resolver-proc-match");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverScheduleReturnOffset,
                                    0x89, "resolver-schedule-return");
        patch_task_thunk_trace_byte(
            kStage6StartLuaResolverCleanupProcExchangeOffset, 0x87,
            "resolver-cleanup-proc-exchange");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverClosureRunOffset,
                                    0x55, "resolver-closure-run");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverClosureReturnOffset,
                                    0x89, "resolver-closure-return");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverClosureCoreOffset,
                                    0x55, "resolver-closure-core");
        patch_task_thunk_trace_byte(
            kStage6StartLuaResolverClosureCoreAllocResultOffset, 0x48,
            "resolver-closure-core-alloc-result");
        patch_task_thunk_trace_byte(
            kStage6StartLuaResolverClosureCoreFallbackAllocResultOffset, 0x48,
            "resolver-closure-core-fallback-alloc-result");
        patch_task_thunk_trace_byte(kStage6StartLuaResolverTaskCreateOffset,
                                    0x55, "resolver-task-create");
      }

      auto* dispatcher_empty_invoke_address = reinterpret_cast<unsigned char*>(
          libroblox_base + kStage6StartLuaDispatcherEmptyInvokeOffset);
      constexpr unsigned char dispatcher_empty_invoke_expected[] = {0x49};
      if (std::memcmp(dispatcher_empty_invoke_address,
                      dispatcher_empty_invoke_expected,
                      sizeof(dispatcher_empty_invoke_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |=
            PatchCode(dispatcher_empty_invoke_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua dispatcher empty invoke "
                  << "signature mismatch at 0x" << std::hex
                  << kStage6StartLuaDispatcherEmptyInvokeOffset << std::dec
                  << '\n'
                  << std::flush;
      }

      auto* dispatcher_second_invoke_address = reinterpret_cast<unsigned char*>(
          libroblox_base + kStage6StartLuaDispatcherSecondInvokeOffset);
      constexpr unsigned char dispatcher_second_invoke_expected[] = {0x49};
      if (std::memcmp(dispatcher_second_invoke_address,
                      dispatcher_second_invoke_expected,
                      sizeof(dispatcher_second_invoke_expected)) == 0) {
        constexpr unsigned char trap[] = {0xcc};
        patched_any |=
            PatchCode(dispatcher_second_invoke_address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua dispatcher second invoke "
                  << "signature mismatch at 0x" << std::hex
                  << kStage6StartLuaDispatcherSecondInvokeOffset << std::dec
                  << '\n'
                  << std::flush;
      }
    }
  }

  if (trace_result20_lookup) {
    auto* result20_lookup_tree_read_address = reinterpret_cast<unsigned char*>(
        libroblox_base + kStage6StartLuaResult20LookupTreeReadOffset);
    constexpr unsigned char result20_lookup_tree_read_expected[] = {0x48};
    constexpr unsigned char trap[] = {0xcc};
    if (std::memcmp(result20_lookup_tree_read_address, trap, sizeof(trap)) ==
        0) {
      patched_any = true;
    } else if (std::memcmp(result20_lookup_tree_read_address,
                           result20_lookup_tree_read_expected,
                           sizeof(result20_lookup_tree_read_expected)) == 0) {
      patched_any |=
          PatchCode(result20_lookup_tree_read_address, trap, sizeof(trap));
    } else {
      std::cerr << "  [trace] Stage6 StartLua result20 lookup tree-read "
                << "signature mismatch at 0x" << std::hex
                << kStage6StartLuaResult20LookupTreeReadOffset << std::dec
                << '\n'
                << std::flush;
    }
  }

  if (trace_source_builder) {
    auto patch_source_builder_trace_byte = [&](uintptr_t offset,
                                               unsigned char expected,
                                               const char* label) {
      auto* address = reinterpret_cast<unsigned char*>(libroblox_base + offset);
      constexpr unsigned char trap[] = {0xcc};
      if (std::memcmp(address, trap, sizeof(trap)) == 0) {
        patched_any = true;
      } else if (std::memcmp(address, &expected, sizeof(expected)) == 0) {
        patched_any |= PatchCode(address, trap, sizeof(trap));
      } else {
        std::cerr << "  [trace] Stage6 StartLua " << label
                  << " signature mismatch at 0x" << std::hex << offset
                  << std::dec << '\n'
                  << std::flush;
      }
    };
    patch_source_builder_trace_byte(
        kStage6StartLuaResult20SourceParseReturnOffset, 0x49,
        "result20 source parse return");
    patch_source_builder_trace_byte(
        kStage6StartLuaResult20SourceBuilderReturnOffset, 0x49,
        "result20 source builder return");
    patch_source_builder_trace_byte(
        kStage6StartLuaSyntheticInstanceUpdateCallOffset, 0xe8,
        "synthetic Instance update call");
  }

  if (!trace_gate && !trace_logged_in) {
    return patched_any;
  }

  auto* deep_args_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaGateDeepArgsOffset);
  constexpr unsigned char deep_args_expected[] = {0x4c};
  if (std::memcmp(deep_args_address, deep_args_expected,
                  sizeof(deep_args_expected)) == 0) {
    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(deep_args_address, trap, sizeof(trap));
  } else {
    std::cerr << "  [trace] Stage6 StartLua gate deep-args signature mismatch "
              << "at 0x" << std::hex << kStage6StartLuaGateDeepArgsOffset
              << std::dec << '\n'
              << std::flush;
  }

  auto* return_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaGateReturnOffset);
  constexpr unsigned char return_expected[] = {0x5b};
  if (std::memcmp(return_address, return_expected, sizeof(return_expected)) ==
      0) {
    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(return_address, trap, sizeof(trap));
  } else {
    std::cerr << "  [trace] Stage6 StartLua gate return signature mismatch "
              << "at 0x" << std::hex << kStage6StartLuaGateReturnOffset
              << std::dec << '\n'
              << std::flush;
  }

  std::cout << "  [trace] Stage6 StartLua gate "
            << (patched_any ? "armed" : "failed") << '\n'
            << std::flush;
  return patched_any;
}

bool PatchStage6AppBridgeV2OwnerInitTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_APP_BRIDGE_V2_OWNER_INIT")) {
    return false;
  }

  bool patched_any = false;
  auto* helper_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6AppBridgeV2OwnerInitHelperOffset);
  constexpr unsigned char helper_expected[] = {0x55};
  if (std::memcmp(helper_address, helper_expected, sizeof(helper_expected)) ==
      0) {
    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(helper_address, trap, sizeof(trap));
  } else {
    std::cerr << "  [trace] AppBridge V2 owner-init helper signature "
              << "mismatch at 0x" << std::hex
              << kStage6AppBridgeV2OwnerInitHelperOffset << std::dec << '\n'
              << std::flush;
  }

  auto* state_store_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6AppBridgeV2OwnerStateStoreOffset);
  constexpr unsigned char state_store_expected[] = {0x4c, 0x89, 0xb3};
  if (std::memcmp(state_store_address, state_store_expected,
                  sizeof(state_store_expected)) == 0) {
    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(state_store_address, trap, sizeof(trap));
  } else {
    std::cerr << "  [trace] AppBridge V2 owner state-store signature "
              << "mismatch at 0x" << std::hex
              << kStage6AppBridgeV2OwnerStateStoreOffset << std::dec << '\n'
              << std::flush;
  }

  std::cout << "  [trace] AppBridge V2 owner-init "
            << (patched_any ? "armed" : "failed") << '\n'
            << std::flush;
  return patched_any;
}

bool PatchStage6AsyncAppBridgeHashAllocationFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_APP_BRIDGE_HASH_ALLOC_FALLBACK")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6AsyncAppBridgeHashAllocationStoreOffset);
  constexpr unsigned char expected[] = {0x4d, 0x89, 0x6e, 0x08};
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 AppBridge hash allocation store "
              << "signature mismatch at 0x" << std::hex
              << kStage6AsyncAppBridgeHashAllocationStoreOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char trap[] = {0xcc};
  const bool patched = PatchCode(patch_address, trap, sizeof(trap));
  std::cout << "  [patch] Stage6 AppBridge hash allocation fallback "
            << (patched ? "armed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6AppBridgeVectorAllocationFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_APP_BRIDGE_VECTOR_ALLOC_FALLBACK")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6AppBridgeVectorAllocationNullCheckOffset);
  constexpr unsigned char expected[] = {
      0x48,
      0x85,
      0xdb,  // test rbx, rbx
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 AppBridge vector allocation null-check "
              << "signature mismatch at 0x" << std::hex
              << kStage6AppBridgeVectorAllocationNullCheckOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char trap[] = {0xcc};
  const bool patched = PatchCode(patch_address, trap, sizeof(trap));
  std::cout << "  [patch] Stage6 AppBridge vector allocation fallback "
            << (patched ? "armed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6StartAppParamsAllocationFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_START_APP_PARAMS_ALLOC_FALLBACK")) {
    return false;
  }

  bool patched_any = false;
  auto patch_return = [&](uintptr_t offset, const unsigned char* expected,
                          size_t expected_size, const char* label) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + offset);
    if (std::memcmp(patch_address, expected, expected_size) != 0) {
      std::cerr << "  [patch] Stage6 StartApp params allocation fallback "
                << label << " signature mismatch at 0x" << std::hex << offset
                << std::dec << '\n'
                << std::flush;
      return;
    }

    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(patch_address, trap, sizeof(trap));
  };

  constexpr unsigned char kMoveRaxToR13[] = {0x49, 0x89, 0xc5};
  constexpr unsigned char kMoveRaxToRbx[] = {0x48, 0x89, 0xc3};
  constexpr unsigned char kMoveRaxToR12[] = {0x49, 0x89, 0xc4};
  constexpr unsigned char kMoveRaxToR15[] = {0x49, 0x89, 0xc7};
  patch_return(kStage6StartAppParamsVectorBackingAllocReturnOffset,
               kMoveRaxToRbx, sizeof(kMoveRaxToRbx), "vector-backing");
  patch_return(kStage6StartAppParamsField40AllocReturnOffset, kMoveRaxToR13,
               sizeof(kMoveRaxToR13), "field40");
  patch_return(kStage6StartAppParamsField60AllocReturnOffset, kMoveRaxToR13,
               sizeof(kMoveRaxToR13), "field60");
  patch_return(kStage6StartAppParamsField0AllocReturnOffset, kMoveRaxToR12,
               sizeof(kMoveRaxToR12), "field0");
  patch_return(kStage6StartAppParamsField20AllocReturnOffset, kMoveRaxToR15,
               sizeof(kMoveRaxToR15), "field20");

  std::cout << "  [patch] Stage6 StartApp params allocation fallback "
            << (patched_any ? "armed" : "failed") << '\n'
            << std::flush;
  return patched_any;
}

bool PatchStage6StartAppInstanceArgTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_STAGE6_START_APP_INSTANCE_ARG")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartAppInstanceArgProbeOffset);
  constexpr unsigned char expected[] = {
      0x49,
      0x8b,
      0x07,  // mov (%r15), %rax
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [trace] Stage6 StartApp instance-arg cast signature "
              << "mismatch at 0x" << std::hex
              << kStage6StartAppInstanceArgProbeOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char trap[] = {0xcc};
  const bool patched = PatchCode(patch_address, trap, sizeof(trap));
  std::cout << "  [trace] Stage6 StartApp instance-arg cast "
            << (patched ? "armed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6DataModelPatchHelperReturnTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_HELPER")) {
    return false;
  }

  constexpr uintptr_t data_model_patch_helper_return_sites[] = {
      kStage6DataModelPatchHelperInitialReturnProbeOffset,
      kStage6DataModelPatchHelperConfigReturnProbeOffset,
      kStage6DataModelPatchHelperProviderReturnProbeOffset,
      kStage6DataModelPatchHelperReturnProbeOffset,
  };
  constexpr unsigned char expected[] = {
      0x48,
      0x89,
      0xc3,  // mov %rax, %rbx
  };
  constexpr unsigned char trap[] = {0xcc};

  size_t armed = 0;
  for (uintptr_t probe_offset : data_model_patch_helper_return_sites) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + probe_offset);
    if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
      std::cerr << "  [trace] Stage6 DataModel patch helper return signature "
                << "mismatch at 0x" << std::hex << probe_offset << std::dec
                << '\n'
                << std::flush;
      continue;
    }
    if (PatchCode(patch_address, trap, sizeof(trap))) {
      ++armed;
    }
  }

  std::cout << "  [trace] Stage6 DataModel patch helper return "
            << (armed > 0 ? "armed" : "failed") << " count=" << armed << '\n'
            << std::flush;
  return armed > 0;
}

bool PatchStage6DataModelPatchTerminalTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_TERMINAL")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6DataModelPatchTerminalFlagReadProbeOffset);
  constexpr unsigned char expected[] = {
      0x8a, 0x05, 0x85, 0xb4, 0xf6, 0x04,  // mov 0x4f6b485(%rip), %al
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [trace] Stage6 DataModel patch terminal signature "
              << "mismatch at 0x" << std::hex
              << kStage6DataModelPatchTerminalFlagReadProbeOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char trap[] = {0xcc};
  const bool patched = PatchCode(patch_address, trap, sizeof(trap));
  std::cout << "  [trace] Stage6 DataModel patch terminal "
            << (patched ? "armed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6DataModelPatchLoadStepTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_LOAD_STEPS")) {
    return false;
  }

  struct Probe {
    uintptr_t offset;
    const unsigned char* expected;
    size_t size;
    const char* name;
  };
  static constexpr unsigned char kOpenStreamReturnExpected[] = {
      0x48, 0x8d, 0xbd, 0x30, 0xfc, 0xff, 0xff,
  };
  static constexpr unsigned char kInlineLoadReturnExpected[] = {
      0x48, 0x8b, 0x9d, 0x68, 0xff, 0xff, 0xff,
  };
  static constexpr unsigned char kInlineBuildResultExpected[] = {
      0x48,
      0x85,
      0xdb,
  };
  static constexpr unsigned char kInnerLoaderStatusExpected[] = {
      0x83,
      0xfb,
      0x01,
  };
  static constexpr unsigned char kInnerLoaderReturnExpected[] = {
      0x48, 0x8b, 0x85, 0xf8, 0xfe, 0xff, 0xff,
  };
  static constexpr unsigned char kBuildListEmptyBranchExpected[] = {
      0x0f, 0x84, 0x20, 0x02, 0x00, 0x00,
  };
  static constexpr unsigned char kBuildContentNullBranchExpected[] = {
      0x0f, 0x84, 0x10, 0x02, 0x00, 0x00,
  };
  static constexpr unsigned char kBuildContentEmptyBranchExpected[] = {
      0x0f, 0x84, 0x03, 0x02, 0x00, 0x00,
  };
  static constexpr unsigned char kBuildFeatureGateBranchExpected[] = {
      0x0f, 0x84, 0x05, 0x02, 0x00, 0x00,
  };
  static constexpr unsigned char kBuildFallbackStatusExpected[] = {
      0x41,
      0x89,
      0xc6,
  };
  static constexpr unsigned char kBuildDeserializeReturnExpected[] = {
      0x48, 0x8b, 0x85, 0xf8, 0xfe, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmDeserializerSummaryExpected[] = {
      0x48, 0x8b, 0xbd, 0x08, 0xfc, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmInstIdsReturnExpected[] = {
      0x41, 0x80, 0x7f, 0x20, 0x00,
  };
  static constexpr unsigned char kRbxmInstModeBranchExpected[] = {
      0x3c,
      0x01,
  };
  static constexpr unsigned char kRbxmInstProviderReturnExpected[] = {
      0x48, 0x89, 0x85, 0x88, 0xfb, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmInstFactoryResultExpected[] = {
      0x48, 0x8b, 0x85, 0xd0, 0xfc, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmInstTableInsertReturnExpected[] = {
      0x48, 0x8b, 0x85, 0xd0, 0xfc, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmInstClassLookupExpected[] = {
      0x48,
      0x85,
      0xc0,
  };
  static constexpr unsigned char kRbxmPropApplyCallExpected[] = {
      0xe8, 0x2f, 0x32, 0x00, 0x00,
  };
  static constexpr unsigned char kRbxmPropApplyReturnExpected[] = {
      0x41, 0x80, 0x7e, 0x20, 0x00,
  };
  static constexpr unsigned char kRbxmPropertyApplyStreamByteExpected[] = {
      0xc6, 0x85, 0xd0, 0xfe, 0xff, 0xff, 0x00,
  };
  static constexpr unsigned char kRbxmPropertyApplyLoopDecisionExpected[] = {
      0x45,
      0x85,
      0xf6,
  };
  static constexpr unsigned char kRbxmPropertyApplyTypeBranchExpected[] = {
      0x41,
      0x83,
      0xfe,
      0x01,
  };
  static constexpr unsigned char kRbxmPropertySetterModeBranchExpected[] = {
      0x80, 0xbd, 0xfc, 0xfb, 0xff, 0xff, 0x01,
  };
  static constexpr unsigned char kRbxmPropertySetterCallExpected[] = {
      0xe8, 0x5b, 0xb0, 0x00, 0x00,
  };
  static constexpr unsigned char kRbxmGenericSetterCallExpected[] = {
      0xff, 0x90, 0xd0, 0x00, 0x00, 0x00,
  };
  static constexpr unsigned char kRbxmPrntChildIdsReturnExpected[] = {
      0x41, 0x80, 0x7e, 0x20, 0x00,
  };
  static constexpr unsigned char kRbxmPrntParentIdsReturnExpected[] = {
      0x41, 0x80, 0x7e, 0x20, 0x00,
  };
  static constexpr unsigned char kRbxmPrntObjectLookupExpected[] = {
      0x48, 0x8b, 0xbd, 0xe0, 0xfc, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmPrntParentBranchExpected[] = {
      0x48,
      0x39,
      0xc2,
  };
  static constexpr unsigned char kRbxmPrntRootAppendReturnExpected[] = {
      0xeb,
      0x0b,
  };
  static constexpr unsigned char kVerifyBuildStatusExpected[] = {
      0x41,
      0x89,
      0xc6,
  };
  static constexpr unsigned char kVerifyStatusReturnExpected[] = {
      0x41,
      0x89,
      0xc4,
  };
  static constexpr unsigned char kFinalResultExpected[] = {
      0x48, 0x8b, 0xb5, 0x90, 0xfa, 0xff, 0xff,
  };
  static constexpr unsigned char kRbxmFileManagerEntryExpected[] = {
      0x49,
      0x89,
      0xf6,
  };
  static constexpr unsigned char kRbxmFileManagerPostCheckStatusExpected[] = {
      0x41, 0x83, 0x7f, 0x60, 0x02,
  };
  static constexpr unsigned char
      kRbxmFileManagerLocalStorageUnavailableExpected[] = {
          0x48, 0x8b, 0x3d, 0x13, 0x71, 0x42, 0x01,
      };
  static constexpr unsigned char kRbxmFileManagerCachingDisabledExpected[] = {
      0x48, 0x8b, 0x3d, 0x35, 0x6f, 0x42, 0x01,
  };
  static constexpr unsigned char kRbxmFileManagerStatusZeroExpected[] = {
      0x41, 0xc7, 0x46, 0x60, 0x00, 0x00, 0x00, 0x00,
  };
  static constexpr unsigned char kRbxmFileManagerStatusOneExpected[] = {
      0xc7, 0x43, 0x60, 0x01, 0x00, 0x00, 0x00,
  };
  static constexpr unsigned char kRbxmFileManagerStatusTwoExpected[] = {
      0x41, 0xc7, 0x46, 0x60, 0x02, 0x00, 0x00, 0x00,
  };
  constexpr Probe probes[] = {
      {kStage6DataModelPatchOpenStreamReturnProbeOffset,
       kOpenStreamReturnExpected, sizeof(kOpenStreamReturnExpected),
       "open-stream"},
      {kStage6DataModelPatchInlineLoadReturnProbeOffset,
       kInlineLoadReturnExpected, sizeof(kInlineLoadReturnExpected),
       "inline-load"},
      {kStage6DataModelPatchInlineBuildResultProbeOffset,
       kInlineBuildResultExpected, sizeof(kInlineBuildResultExpected),
       "inline-build"},
      {kStage6DataModelPatchInnerLoaderStatusProbeOffset,
       kInnerLoaderStatusExpected, sizeof(kInnerLoaderStatusExpected),
       "inner-status"},
      {kStage6DataModelPatchInnerLoaderReturnProbeOffset,
       kInnerLoaderReturnExpected, sizeof(kInnerLoaderReturnExpected),
       "inner-return"},
      {kStage6DataModelPatchBuildListEmptyBranchProbeOffset,
       kBuildListEmptyBranchExpected, sizeof(kBuildListEmptyBranchExpected),
       "build-list-empty"},
      {kStage6DataModelPatchBuildContentNullBranchProbeOffset,
       kBuildContentNullBranchExpected, sizeof(kBuildContentNullBranchExpected),
       "build-content-null"},
      {kStage6DataModelPatchBuildContentEmptyBranchProbeOffset,
       kBuildContentEmptyBranchExpected,
       sizeof(kBuildContentEmptyBranchExpected), "build-content-empty"},
      {kStage6DataModelPatchBuildFeatureGateBranchProbeOffset,
       kBuildFeatureGateBranchExpected, sizeof(kBuildFeatureGateBranchExpected),
       "build-feature-gate"},
      {kStage6DataModelPatchBuildFallbackStatusProbeOffset,
       kBuildFallbackStatusExpected, sizeof(kBuildFallbackStatusExpected),
       "build-fallback-status"},
      {kStage6DataModelPatchBuildDeserializeReturnProbeOffset,
       kBuildDeserializeReturnExpected, sizeof(kBuildDeserializeReturnExpected),
       "build-deserialize-return"},
      {kStage6RbxmDeserializerSummaryProbeOffset,
       kRbxmDeserializerSummaryExpected,
       sizeof(kRbxmDeserializerSummaryExpected), "rbxm-deserialize-summary"},
      {kStage6RbxmInstIdsReturnProbeOffset, kRbxmInstIdsReturnExpected,
       sizeof(kRbxmInstIdsReturnExpected), "inst-ids-return"},
      {kStage6RbxmInstModeBranchProbeOffset, kRbxmInstModeBranchExpected,
       sizeof(kRbxmInstModeBranchExpected), "inst-mode-branch"},
      {kStage6RbxmInstProviderReturnProbeOffset,
       kRbxmInstProviderReturnExpected, sizeof(kRbxmInstProviderReturnExpected),
       "inst-provider-return"},
      {kStage6RbxmInstFactoryResultProbeOffset, kRbxmInstFactoryResultExpected,
       sizeof(kRbxmInstFactoryResultExpected), "inst-factory-result"},
      {kStage6RbxmInstTableInsertReturnProbeOffset,
       kRbxmInstTableInsertReturnExpected,
       sizeof(kRbxmInstTableInsertReturnExpected), "inst-table-insert-return"},
      {kStage6RbxmInstClassLookupProbeOffset, kRbxmInstClassLookupExpected,
       sizeof(kRbxmInstClassLookupExpected), "inst-class-lookup"},
      {kStage6RbxmPropApplyCallProbeOffset, kRbxmPropApplyCallExpected,
       sizeof(kRbxmPropApplyCallExpected), "prop-apply-call"},
      {kStage6RbxmPropApplyReturnProbeOffset, kRbxmPropApplyReturnExpected,
       sizeof(kRbxmPropApplyReturnExpected), "prop-apply-return"},
      {kStage6RbxmPropertyApplyStreamByteProbeOffset,
       kRbxmPropertyApplyStreamByteExpected,
       sizeof(kRbxmPropertyApplyStreamByteExpected),
       "property-apply-stream-byte"},
      {kStage6RbxmPropertyApplyLoopDecisionProbeOffset,
       kRbxmPropertyApplyLoopDecisionExpected,
       sizeof(kRbxmPropertyApplyLoopDecisionExpected),
       "property-apply-loop-decision"},
      {kStage6RbxmPropertyApplyTypeBranchProbeOffset,
       kRbxmPropertyApplyTypeBranchExpected,
       sizeof(kRbxmPropertyApplyTypeBranchExpected),
       "property-apply-type-branch"},
      {kStage6RbxmPropertySetterModeBranchProbeOffset,
       kRbxmPropertySetterModeBranchExpected,
       sizeof(kRbxmPropertySetterModeBranchExpected),
       "property-setter-mode-branch"},
      {kStage6RbxmPropertySetterCallProbeOffset,
       kRbxmPropertySetterCallExpected, sizeof(kRbxmPropertySetterCallExpected),
       "property-setter-call"},
      {kStage6RbxmGenericSetterCallProbeOffset, kRbxmGenericSetterCallExpected,
       sizeof(kRbxmGenericSetterCallExpected), "property-generic-setter-call"},
      {kStage6RbxmPrntChildIdsReturnProbeOffset,
       kRbxmPrntChildIdsReturnExpected, sizeof(kRbxmPrntChildIdsReturnExpected),
       "prnt-child-ids-return"},
      {kStage6RbxmPrntParentIdsReturnProbeOffset,
       kRbxmPrntParentIdsReturnExpected,
       sizeof(kRbxmPrntParentIdsReturnExpected), "prnt-parent-ids-return"},
      {kStage6RbxmPrntObjectLookupProbeOffset, kRbxmPrntObjectLookupExpected,
       sizeof(kRbxmPrntObjectLookupExpected), "prnt-object-lookup"},
      {kStage6RbxmPrntParentBranchProbeOffset, kRbxmPrntParentBranchExpected,
       sizeof(kRbxmPrntParentBranchExpected), "prnt-parent-branch"},
      {kStage6RbxmPrntRootAppendReturnProbeOffset,
       kRbxmPrntRootAppendReturnExpected,
       sizeof(kRbxmPrntRootAppendReturnExpected), "prnt-root-append-return"},
      {kStage6DataModelPatchVerifyBuildStatusProbeOffset,
       kVerifyBuildStatusExpected, sizeof(kVerifyBuildStatusExpected),
       "verify-build-status"},
      {kStage6DataModelPatchVerifyStatusReturnProbeOffset,
       kVerifyStatusReturnExpected, sizeof(kVerifyStatusReturnExpected),
       "verify-status"},
      {kStage6DataModelPatchFinalResultProbeOffset, kFinalResultExpected,
       sizeof(kFinalResultExpected), "final-result"},
      {kStage6RbxmFileManagerEntryProbeOffset, kRbxmFileManagerEntryExpected,
       sizeof(kRbxmFileManagerEntryExpected), "rbxm-file-manager-entry"},
      {kStage6RbxmFileManagerPostCheckStatusProbeOffset,
       kRbxmFileManagerPostCheckStatusExpected,
       sizeof(kRbxmFileManagerPostCheckStatusExpected),
       "rbxm-file-manager-post-check-status"},
      {kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset,
       kRbxmFileManagerLocalStorageUnavailableExpected,
       sizeof(kRbxmFileManagerLocalStorageUnavailableExpected),
       "rbxm-file-manager-local-storage-unavailable"},
      {kStage6RbxmFileManagerCachingDisabledProbeOffset,
       kRbxmFileManagerCachingDisabledExpected,
       sizeof(kRbxmFileManagerCachingDisabledExpected),
       "rbxm-file-manager-caching-disabled"},
      {kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset,
       kRbxmFileManagerStatusZeroExpected,
       sizeof(kRbxmFileManagerStatusZeroExpected),
       "rbxm-file-manager-no-local-storage-status"},
      {kStage6RbxmFileManagerPendingStatusProbeOffset,
       kRbxmFileManagerStatusOneExpected,
       sizeof(kRbxmFileManagerStatusOneExpected),
       "rbxm-file-manager-pending-status"},
      {kStage6RbxmFileManagerSuccessStatusProbeOffset,
       kRbxmFileManagerStatusTwoExpected,
       sizeof(kRbxmFileManagerStatusTwoExpected),
       "rbxm-file-manager-success-status"},
  };

  constexpr unsigned char trap[] = {0xcc};
  size_t armed = 0;
  for (const Probe& probe : probes) {
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + probe.offset);
    if (std::memcmp(patch_address, probe.expected, probe.size) != 0) {
      std::cerr << "  [trace] Stage6 DataModel patch load step signature "
                << "mismatch at 0x" << std::hex << probe.offset << std::dec
                << " (" << probe.name << ")\n"
                << std::flush;
      continue;
    }
    if (PatchCode(patch_address, trap, sizeof(trap))) {
      ++armed;
    }
  }

  std::cout << "  [trace] Stage6 DataModel patch load step "
            << (armed > 0 ? "armed" : "failed") << " count=" << armed << '\n'
            << std::flush;
  return armed > 0;
}

bool PatchStage6RbxmNameSlotApplyRepair(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_RBXM_NAME_SLOT_APPLY_REPAIR")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6RbxmGenericSetterReturnProbeOffset);
  constexpr unsigned char expected[] = {
      0x48,
      0xff,
      0xc3,  // inc %rbx
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    if (patch_address[0] == 0xcc) {
      return true;
    }
    std::cerr << "  [patch] Stage6 RBXM Name slot apply repair "
              << "signature mismatch at 0x" << std::hex
              << kStage6RbxmGenericSetterReturnProbeOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char trap[] = {0xcc};
  const bool patched = PatchCode(patch_address, trap, sizeof(trap));
  std::cout << "  [patch] Stage6 RBXM Name slot apply repair "
            << (patched ? "armed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6AsyncAppBridgeXmlDeserializeError(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_APP_BRIDGE_XML_DESERIALIZE_ERROR")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6AsyncAppBridgeXmlDeserializeErrorBranchOffset);
  constexpr unsigned char expected[] = {
      0x0f, 0x85, 0xd3, 0x01, 0x00, 0x00,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 AppBridge XML deserialize error branch "
              << "signature mismatch at 0x" << std::hex
              << kStage6AsyncAppBridgeXmlDeserializeErrorBranchOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char nops[] = {
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  };
  const bool patched = PatchCode(patch_address, nops, sizeof(nops));
  std::cout << "  [patch] Stage6 AppBridge XML deserialize error branch "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6SystemDialogFormatHelperReturnFalse(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_SYSTEM_DIALOG_FORMAT_HELPER")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6SystemDialogFormatHelperOffset);
  constexpr unsigned char expected[] = {
      0x41,
      0x56,  // push r14
      0x53,  // push rbx
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 system-dialog format helper "
              << "signature mismatch at 0x" << std::hex
              << kStage6SystemDialogFormatHelperOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  const bool patched =
      PatchCode(patch_address, kReturnFalse, sizeof(kReturnFalse));
  std::cout << "  [patch] Stage6 system-dialog format helper return-false "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6PlatformHeaderParseStackFailLanding(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_PLATFORM_HEADER_PARSE_STACK_FAIL")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6PlatformHeaderParseStackFailCallOffset);
  constexpr unsigned char expected[] = {
      0xe8, 0xa9, 0xbd, 0x80, 0x04,  // call __stack_chk_fail@plt
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 platform-header parse stack-fail "
              << "signature mismatch at 0x" << std::hex
              << kStage6PlatformHeaderParseStackFailCallOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr uintptr_t kPatchSize = 5;
  const int64_t relative_jump =
      static_cast<int64_t>(kStage6PlatformHeaderParseErrorLandingOffset) -
      static_cast<int64_t>(kStage6PlatformHeaderParseStackFailCallOffset +
                           kPatchSize);
  if (relative_jump < INT32_MIN || relative_jump > INT32_MAX) {
    std::cerr << "  [patch] Stage6 platform-header parse stack-fail "
              << "landing is out of range\n"
              << std::flush;
    return false;
  }

  const int32_t relative_jump32 = static_cast<int32_t>(relative_jump);
  unsigned char jump_to_landing[kPatchSize] = {
      0xe9, 0x00, 0x00, 0x00, 0x00,
  };
  std::memcpy(jump_to_landing + 1, &relative_jump32, sizeof(relative_jump32));
  const bool patched =
      PatchCode(patch_address, jump_to_landing, sizeof(jump_to_landing));
  std::cout << "  [patch] Stage6 platform-header parse stack-fail landing "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6AsyncAppBridgeOptionalContextFlag(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_APP_BRIDGE_OPTIONAL_CONTEXT_FLAG")) {
    return false;
  }

  auto* flag = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6AsyncAppBridgeOptionalContextFlagOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(flag),
                             sizeof(*flag))) {
    std::cerr << "  [patch] Stage6 AppBridge optional-context flag unreadable "
              << "at 0x" << std::hex
              << kStage6AsyncAppBridgeOptionalContextFlagOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  if (!EnsureWritablePage(flag)) {
    std::cerr << "  [patch] Stage6 AppBridge optional-context flag mprotect "
              << "failed at 0x" << std::hex
              << kStage6AsyncAppBridgeOptionalContextFlagOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  const unsigned char old_value = *flag;
  *flag = static_cast<unsigned char>(old_value & ~0x01u);
  __builtin___clear_cache(reinterpret_cast<char*>(flag),
                          reinterpret_cast<char*>(flag) + sizeof(*flag));
  std::cout << "  [patch] Stage6 AppBridge optional-context flag 0x" << std::hex
            << kStage6AsyncAppBridgeOptionalContextFlagOffset << " old=0x"
            << static_cast<unsigned int>(old_value) << " new=0x"
            << static_cast<unsigned int>(*flag) << std::dec << '\n'
            << std::flush;
  return true;
}

bool InstallStage6AsyncAppBridgeXmlNameStringFallbacks(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_APP_BRIDGE_XML_NAME_STRINGS")) {
    return false;
  }

  struct XmlNameSlot {
    uintptr_t offset;
    unsigned char* backing;
    const char* name;
  };
  constexpr XmlNameSlot kSlots[] = {
      {
          kStage6AsyncAppBridgeXmlNamePrimarySlotOffset,
          g_stage6_app_bridge_xml_name_primary_backing,
          "primary",
      },
      {
          kStage6AsyncAppBridgeXmlNameSecondarySlotOffset,
          g_stage6_app_bridge_xml_name_secondary_backing,
          "secondary",
      },
      {
          kStage6AsyncAppBridgeXmlNameTertiarySlotOffset,
          g_stage6_app_bridge_xml_name_tertiary_backing,
          "tertiary",
      },
      {
          kStage6AsyncAppBridgeXmlNameQuaternarySlotOffset,
          g_stage6_app_bridge_xml_name_quaternary_backing,
          "quaternary",
      },
      {
          kStage6AsyncAppBridgeXmlNameQuinarySlotOffset,
          g_stage6_app_bridge_xml_name_quinary_backing,
          "quinary",
      },
      {
          kStage6AsyncAppBridgeXmlNameSenarySlotOffset,
          g_stage6_app_bridge_xml_name_senary_backing,
          "senary",
      },
      {
          kStage6AsyncAppBridgeXmlNameSeptenarySlotOffset,
          g_stage6_app_bridge_xml_name_septenary_backing,
          "septenary",
      },
  };

  std::memset(g_stage6_app_bridge_xml_name_primary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_primary_backing));
  std::memset(g_stage6_app_bridge_xml_name_secondary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_secondary_backing));
  std::memset(g_stage6_app_bridge_xml_name_tertiary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_tertiary_backing));
  std::memset(g_stage6_app_bridge_xml_name_quaternary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_quaternary_backing));
  std::memset(g_stage6_app_bridge_xml_name_quinary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_quinary_backing));
  std::memset(g_stage6_app_bridge_xml_name_senary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_senary_backing));
  std::memset(g_stage6_app_bridge_xml_name_septenary_backing, 0,
              sizeof(g_stage6_app_bridge_xml_name_septenary_backing));

  bool all_installed = true;
  for (const XmlNameSlot& slot_info : kSlots) {
    auto** slot = reinterpret_cast<void**>(libroblox_base + slot_info.offset);
    if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(slot),
                               sizeof(*slot))) {
      std::cerr << "  [patch] Stage6 AppBridge XML name " << slot_info.name
                << " slot unreadable at 0x" << std::hex << slot_info.offset
                << std::dec << '\n'
                << std::flush;
      all_installed = false;
      continue;
    }
    if (*slot != nullptr) {
      continue;
    }
    if (!EnsureWritablePage(slot)) {
      std::cerr << "  [patch] Stage6 AppBridge XML name " << slot_info.name
                << " slot mprotect failed at 0x" << std::hex << slot_info.offset
                << std::dec << ": " << std::strerror(errno) << '\n'
                << std::flush;
      all_installed = false;
      continue;
    }
    *slot = slot_info.backing;
    std::cout << "  [patch] installed Stage6 AppBridge XML name "
              << slot_info.name << " fallback at 0x" << std::hex
              << slot_info.offset << std::dec
              << " ptr=" << static_cast<void*>(slot_info.backing) << '\n'
              << std::flush;
  }
  return all_installed;
}

bool PatchNativeUpdateScreenOrientationSetupTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_NATIVE_UPDATE_SCREEN_ORIENTATION_SETUP")) {
    return false;
  }

  bool patched_any = false;
  auto* setup_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kNativeUpdateScreenOrientationCallbackSetupOffset);
  constexpr unsigned char setup_expected[] = {0x4c, 0x8d};
  if (std::memcmp(setup_address, setup_expected, sizeof(setup_expected)) == 0) {
    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(setup_address, trap, sizeof(trap));
  } else {
    std::cerr << "  [trace] nativeUpdateScreenOrientation callback setup "
              << "signature mismatch at 0x" << std::hex
              << kNativeUpdateScreenOrientationCallbackSetupOffset << std::dec
              << '\n'
              << std::flush;
  }

  auto* state_load_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kNativeUpdateScreenOrientationStateSlotLoadOffset);
  constexpr unsigned char state_load_expected[] = {0x48, 0x8b};
  if (std::memcmp(state_load_address, state_load_expected,
                  sizeof(state_load_expected)) == 0) {
    constexpr unsigned char trap[] = {0xcc};
    patched_any |= PatchCode(state_load_address, trap, sizeof(trap));
  } else {
    std::cerr << "  [trace] nativeUpdateScreenOrientation state-slot load "
              << "signature mismatch at 0x" << std::hex
              << kNativeUpdateScreenOrientationStateSlotLoadOffset << std::dec
              << '\n'
              << std::flush;
  }

  std::cout << "  [trace] nativeUpdateScreenOrientation setup "
            << (patched_any ? "armed" : "failed") << '\n'
            << std::flush;
  return patched_any;
}

bool PatchStage6StartLuaGateForceDeep(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_GATE_FORCE_DEEP")) {
    return false;
  }

  bool patched_all = true;
  auto* check_block = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaGateCheckOffset);
  constexpr unsigned char check_expected[] = {0x41, 0x83};
  constexpr unsigned char jump_to_deep_args[] = {0xeb, 0x0e};
  if (std::memcmp(check_block, check_expected, sizeof(check_expected)) == 0) {
    patched_all &=
        PatchCode(check_block, jump_to_deep_args, sizeof(jump_to_deep_args));
  } else {
    std::cerr << "  [patch] Stage6 StartLua gate check-block signature "
              << "mismatch at 0x" << std::hex << kStage6StartLuaGateCheckOffset
              << " bytes=";
    for (int i = 0; i < 8; ++i) {
      std::cerr << (i == 0 ? "" : " ") << static_cast<int>(check_block[i]);
    }
    std::cerr << std::dec << '\n' << std::flush;
    patched_all = false;
  }

  auto* phase_branch = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaGatePhaseBranchOffset);
  constexpr unsigned char phase_expected[] = {0x75, 0x15};
  constexpr unsigned char nops[] = {0x90, 0x90};
  if (std::memcmp(phase_branch, phase_expected, sizeof(phase_expected)) == 0) {
    patched_all &= PatchCode(phase_branch, nops, sizeof(nops));
  } else {
    std::cerr << "  [patch] Stage6 StartLua gate phase branch signature "
              << "mismatch at 0x" << std::hex
              << kStage6StartLuaGatePhaseBranchOffset << std::dec << '\n'
              << std::flush;
    patched_all = false;
  }

  auto* payload_branch = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6StartLuaGatePayloadBranchOffset);
  constexpr unsigned char payload_expected[] = {0x7e, 0x0f};
  if (std::memcmp(payload_branch, payload_expected, sizeof(payload_expected)) ==
      0) {
    patched_all &= PatchCode(payload_branch, nops, sizeof(nops));
  } else {
    std::cerr << "  [patch] Stage6 StartLua gate payload branch signature "
              << "mismatch at 0x" << std::hex
              << kStage6StartLuaGatePayloadBranchOffset << std::dec << '\n'
              << std::flush;
    patched_all = false;
  }

  std::cout << "  [patch] Stage6 StartLua gate force-deep "
            << (patched_all ? "patched" : "failed") << '\n'
            << std::flush;
  return patched_all;
}

bool PatchStage6EnableDmNotificationMonitorFlag(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_ENABLE_DM_NOTIFICATION_MONITOR")) {
    return false;
  }

  auto* flag = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6EnableDmNotificationMonitorFlagOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(flag),
                             sizeof(*flag))) {
    std::cerr << "  [patch] EnableDMNotificationMonitor flag is unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(flag)) {
    std::cerr << "  [patch] EnableDMNotificationMonitor mprotect failed: "
              << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  *flag = 1;
  std::cout << "  [patch] EnableDMNotificationMonitor flag forced at 0x"
            << std::hex << kStage6EnableDmNotificationMonitorFlagOffset
            << std::dec << '\n'
            << std::flush;

  auto* branch = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6EnableDmNotificationMonitorBranchOffset);
  constexpr unsigned char kExpectedBranch[] = {0x74, 0x58};
  constexpr unsigned char kNopBranch[] = {0x90, 0x90};
  if (std::memcmp(branch, kExpectedBranch, sizeof(kExpectedBranch)) != 0) {
    std::cerr << "  [patch] EnableDMNotificationMonitor branch signature "
              << "mismatch at 0x" << std::hex
              << kStage6EnableDmNotificationMonitorBranchOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }
  const bool patched = PatchCode(branch, kNopBranch, sizeof(kNopBranch));
  std::cout << "  [patch] EnableDMNotificationMonitor branch "
            << (patched ? "forced" : "failed") << " at 0x" << std::hex
            << kStage6EnableDmNotificationMonitorBranchOffset << std::dec
            << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6EnableDmNotificationMonitorTrace(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_TRACE_ENABLE_DM_NOTIFICATION_MONITOR")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6EnableDmNotificationMonitorBlockOffset);
  constexpr unsigned char kExpected[] = {0x8a};
  if (std::memcmp(patch_address, kExpected, sizeof(kExpected)) != 0) {
    std::cerr << "  [trace] EnableDMNotificationMonitor block signature "
              << "mismatch at 0x" << std::hex
              << kStage6EnableDmNotificationMonitorBlockOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kTrap[] = {0xcc};
  const bool patched = PatchCode(patch_address, kTrap, sizeof(kTrap));
  std::cout << "  [trace] EnableDMNotificationMonitor block "
            << (patched ? "armed" : "failed") << " at 0x" << std::hex
            << kStage6EnableDmNotificationMonitorBlockOffset << std::dec << '\n'
            << std::flush;
  return patched;
}

}  // namespace mocktail::legacy::internal
