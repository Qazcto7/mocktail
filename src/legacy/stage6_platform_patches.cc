#include <sys/mman.h>

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
#include "legacy/stage6_runtime.h"
#include "legacy/symbol_resolver.h"

namespace jnivm {
extern void* my_segment[100000];
extern void* my_segment_table[];
}  // namespace jnivm

namespace mocktail::legacy::internal {

bool InstallRobloxUrlStringFallbacks(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_URL_STRING_FALLBACKS")) {
    return false;
  }

  auto install_slot = [libroblox_base](uintptr_t offset, void* backing,
                                       const char* name) -> bool {
    auto** slot = reinterpret_cast<void**>(libroblox_base + offset);
    if (*slot != nullptr) {
      return true;
    }
    if (!EnsureWritablePage(slot)) {
      std::cerr << "  [patch] " << name
                << " string slot mprotect failed: " << std::strerror(errno)
                << '\n'
                << std::flush;
      return false;
    }
    *slot = backing;
    std::cout << "  [patch] installed " << name << " string fallback at 0x"
              << std::hex << offset << std::dec << " ptr=" << backing << '\n'
              << std::flush;
    return true;
  };

  std::memset(g_base_url_owner_string_backing, 0,
              sizeof(g_base_url_owner_string_backing));
  std::memset(g_base_url_global_string_backing, 0,
              sizeof(g_base_url_global_string_backing));
  WriteLibcxxString(g_channel_string_backing, "production");
  bool channel_ok = install_slot(kRobloxChannelPointerOffset,
                                 g_channel_string_backing, "channel");
  bool owner_ok =
      install_slot(kRobloxBaseUrlOwnerPointerOffset,
                   g_base_url_owner_string_backing, "base-url owner");
  bool global_ok =
      install_slot(kRobloxBaseUrlGlobalPointerOffset,
                   g_base_url_global_string_backing, "base-url global");
  return channel_ok && owner_ok && global_ok;
}

bool PatchEmutlsZeroInitializerMemset(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_EMUTLS_ZERO_INITIALIZER_MEMSET")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kEmutlsZeroInitializerMemsetCallOffset);
  const unsigned char expected[] = {
      0xe8, 0x42, 0xa6, 0xf0, 0x03,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] emutls zero-initializer memset signature "
              << "mismatch at 0x" << std::hex
              << kEmutlsZeroInitializerMemsetCallOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kSkipMemset[] = {
      0x90, 0x90, 0x90, 0x90, 0x90,
  };
  bool patched = PatchCode(patch_address, kSkipMemset, sizeof(kSkipMemset));
  std::cout << "  [patch] emutls zero-initializer memset "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6OpenGLUnsupportedMessageCounter(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_OPENGL_UNSUPPORTED_MESSAGE_COUNTER")) {
    return false;
  }

  constexpr uintptr_t kUnsupportedMessageCounterOffset = 0x277d59f;
  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kUnsupportedMessageCounterOffset);
  const unsigned char expected[] = {
      0xf0, 0x0f, 0xc1, 0x43, 0x28,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 OpenGL unsupported-message counter "
                 "signature mismatch at 0x"
              << std::hex << kUnsupportedMessageCounterOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched = PatchCode(patch_address, kReturnFalse, sizeof(kReturnFalse));
  std::cout << "  [patch] Stage6 OpenGL unsupported-message counter "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlHelperStateSlot(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_HELPER_STATE_SLOT")) {
    return false;
  }

  InitialiseStage6GlScratchWithTls(g_stage6_gl_global_scratch,
                                   g_stage6_gl_global_tls_storage,
                                   g_stage6_gl_global_queue_lane_storage);

  auto* patch_address =
      reinterpret_cast<unsigned char*>(libroblox_base + 0x2779950);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x3d,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL helper state-slot signature mismatch\n"
              << std::flush;
    return false;
  }

  unsigned char patch[11] = {0x48, 0xb8};
  uintptr_t slot_address =
      reinterpret_cast<uintptr_t>(g_stage6_gl_global_tls_storage + 0x410);
  std::memcpy(patch + 2, &slot_address, sizeof(slot_address));
  patch[10] = 0xc3;
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 GL helper state-slot "
            << (patched ? "patched" : "failed")
            << " slot=" << reinterpret_cast<void*>(slot_address) << " queue="
            << *reinterpret_cast<void**>(g_stage6_gl_global_tls_storage + 0x410)
            << " state="
            << reinterpret_cast<void*>(g_stage6_gl_global_scratch + 0x1000)
            << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlPollReturn(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_POLL_RETURN")) {
    return false;
  }

  auto* patch_address =
      reinterpret_cast<unsigned char*>(libroblox_base + 0x277b3d0);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL poll signature mismatch\n" << std::flush;
    return false;
  }

  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched = PatchCode(patch_address, kReturnFalse, sizeof(kReturnFalse));
  std::cout << "  [patch] Stage6 GL poll return-false "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlInfiniteWait(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_INFINITE_WAIT")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlInfiniteWaitSyscallOffset);
  const unsigned char expected[] = {
      0xe8, 0xa1, 0x9b, 0x3a, 0x04,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL infinite-wait syscall signature "
              << "mismatch at 0x" << std::hex
              << kStage6GlInfiniteWaitSyscallOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnSuccess[] = {
      0x31, 0xc0,        // xor eax, eax
      0x90, 0x90, 0x90,  // nop; nop; nop
  };
  bool patched =
      PatchCode(patch_address, kReturnSuccess, sizeof(kReturnSuccess));
  std::cout << "  [patch] Stage6 GL infinite wait "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlWaitReturn(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_WAIT_RETURN")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlWaitHelperOffset);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL wait helper signature mismatch at 0x"
              << std::hex << kStage6GlWaitHelperOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnTrue[] = {
      0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
      0xc3,                          // ret
  };
  bool patched = PatchCode(patch_address, kReturnTrue, sizeof(kReturnTrue));
  std::cout << "  [patch] Stage6 GL wait return-true "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlTimedWaitReturnFalse(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_TIMED_WAIT_RETURN_FALSE")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlTimedWaitHelperOffset);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL timed-wait helper signature "
              << "mismatch at 0x" << std::hex << kStage6GlTimedWaitHelperOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched = PatchCode(patch_address, kReturnFalse, sizeof(kReturnFalse));
  std::cout << "  [patch] Stage6 GL timed wait return-false "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlConditionWaitWrapperReturnSuccess(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_CONDITION_WAIT_RETURN_SUCCESS")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlConditionWaitWrapperOffset);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL condition wait wrapper signature "
              << "mismatch at 0x" << std::hex
              << kStage6GlConditionWaitWrapperOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnSuccess[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched =
      PatchCode(patch_address, kReturnSuccess, sizeof(kReturnSuccess));
  std::cout << "  [patch] Stage6 GL condition wait return-success "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlQueuePopReturnEmpty(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_QUEUE_POP_RETURN_EMPTY")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlQueuePopHelperOffset);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL queue pop helper signature mismatch "
              << "at 0x" << std::hex << kStage6GlQueuePopHelperOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnEmpty[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched = PatchCode(patch_address, kReturnEmpty, sizeof(kReturnEmpty));
  std::cout << "  [patch] Stage6 GL queue pop return-empty "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlQueueTransferReturnFalse(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_QUEUE_TRANSFER_RETURN_FALSE")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlQueueTransferHelperOffset);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL queue transfer helper signature "
              << "mismatch at 0x" << std::hex
              << kStage6GlQueueTransferHelperOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched = PatchCode(patch_address, kReturnFalse, sizeof(kReturnFalse));
  std::cout << "  [patch] Stage6 GL queue transfer return-false "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlQueueCallbackTailReturnEmpty(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_QUEUE_CALLBACK_TAIL_RETURN_EMPTY")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlQueueCallbackTailOffset);
  const unsigned char expected[] = {
      0x48, 0x8b, 0x06, 0x48, 0x8b, 0x4e, 0x08, 0x48,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL queue callback tail signature "
              << "mismatch at 0x" << std::hex
              << kStage6GlQueueCallbackTailOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  unsigned char patch[20] = {
      0x48, 0x8d, 0xa5, 0x30, 0xff, 0xff, 0xff,  // lea -0xd0(%rbp), %rsp
      0xe9, 0x00, 0x00, 0x00, 0x00,              // jmp helper return
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  };
  uintptr_t jump_next = reinterpret_cast<uintptr_t>(patch_address) + 12;
  uintptr_t jump_target = libroblox_base + kStage6GlHelperReturnOffset;
  int32_t rel = static_cast<int32_t>(jump_target - jump_next);
  std::memcpy(patch + 8, &rel, sizeof(rel));
  bool patched = PatchCode(patch_address, patch, sizeof(patch));
  std::cout << "  [patch] Stage6 GL queue callback tail return-empty "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlQueueDrainReturnFalse(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_GL_QUEUE_DRAIN_RETURN_FALSE")) {
    return false;
  }

  auto* patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6GlQueueDrainHelperOffset);
  const unsigned char expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(patch_address, expected, sizeof(expected)) != 0) {
    std::cerr << "  [patch] Stage6 GL queue drain helper signature "
              << "mismatch at 0x" << std::hex << kStage6GlQueueDrainHelperOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  bool patched = PatchCode(patch_address, kReturnFalse, sizeof(kReturnFalse));
  std::cout << "  [patch] Stage6 GL queue drain return-false "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchStage6GlQueueTrace(uintptr_t libroblox_base) {
  const bool trace_enabled = IsEnabled("MOCKTAIL_TRACE_STAGE6_GL_QUEUE");
  const bool synthetic_drain_guard_enabled =
      IsEnabled("MOCKTAIL_PATCH_STAGE6_GL_QUEUE_DRAIN_SYNTHETIC_RETURN_FALSE");
  const bool synthetic_poll_guard_enabled =
      IsEnabled("MOCKTAIL_PATCH_STAGE6_GL_POLL_SYNTHETIC_RETURN_FALSE");
  if (libroblox_base == 0 ||
      (!trace_enabled && !synthetic_drain_guard_enabled &&
       !synthetic_poll_guard_enabled)) {
    return false;
  }

  constexpr unsigned char kTrap = 0xcc;
  struct TracePatch {
    uintptr_t offset;
    const char* name;
  };
  const TracePatch patches[] = {
      {kStage6StartLuaResolverSchedulerEntryOffset, "poll"},
      {kStage6GlWaitHelperOffset, "wait"},
      {kStage6GlQueuePopHelperOffset, "pop"},
      {kStage6GlQueueTransferHelperOffset, "transfer"},
      {kStage6GlQueueDrainHelperOffset, "drain"},
  };

  bool patched_any = false;
  for (const TracePatch& patch : patches) {
    if (!trace_enabled && std::strcmp(patch.name, "drain") != 0 &&
        !(synthetic_drain_guard_enabled &&
          std::strcmp(patch.name, "drain") == 0) &&
        !(synthetic_poll_guard_enabled &&
          std::strcmp(patch.name, "poll") == 0)) {
      continue;
    }
    auto* patch_address =
        reinterpret_cast<unsigned char*>(libroblox_base + patch.offset);
    if (patch_address[0] != 0x55) {
      std::cerr << "  [trace] Stage6 GL queue " << patch.name
                << " trace signature mismatch at 0x" << std::hex << patch.offset
                << std::dec << '\n'
                << std::flush;
      continue;
    }
    const bool patched = PatchCode(patch_address, &kTrap, sizeof(kTrap));
    std::cout << "  [trace] Stage6 GL queue " << patch.name
              << (trace_enabled ? " trace " : " synthetic guard ")
              << (patched ? "armed" : "failed") << '\n'
              << std::flush;
    patched_any = patched_any || patched;
  }
  return patched_any;
}

bool PatchStage6TextboxSyncNullString(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_STAGE6_TEXTBOX_SYNC_NULL_STRING")) {
    return false;
  }

  constexpr uintptr_t kTextboxSyncJniEntryOffset = 0x23c32c6;
  constexpr uintptr_t kTextboxSyncHeapCallbackCallOffset = 0x23c63bf;
  auto* entry_patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kTextboxSyncJniEntryOffset);
  const unsigned char entry_expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  };
  if (std::memcmp(entry_patch_address, entry_expected,
                  sizeof(entry_expected)) != 0) {
    std::cerr << "  [patch] Stage6 textbox sync JNI entry signature "
              << "mismatch at 0x" << std::hex << kTextboxSyncJniEntryOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  auto* heap_callback_patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kTextboxSyncHeapCallbackCallOffset);
  const unsigned char heap_callback_expected[] = {
      0xff,
      0x50,
      0x30,  // call *0x30(%rax)
  };
  if (std::memcmp(heap_callback_patch_address, heap_callback_expected,
                  sizeof(heap_callback_expected)) != 0) {
    std::cerr << "  [patch] Stage6 textbox sync heap-callback signature "
              << "mismatch at 0x" << std::hex
              << kTextboxSyncHeapCallbackCallOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr uintptr_t kTextboxSyncStringCopyOffset = 0x23c6692;
  constexpr uintptr_t kTextboxSyncNullStringDerefOffset = 0x23c66af;
  constexpr uintptr_t kTextboxSyncStringCopyEpilogueOffset = 0x23c66f1;
  auto* helper_patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kTextboxSyncStringCopyOffset);
  const unsigned char helper_expected[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x56, 0x53, 0x48,
  };
  if (std::memcmp(helper_patch_address, helper_expected,
                  sizeof(helper_expected)) != 0) {
    std::cerr << "  [patch] Stage6 textbox sync string-copy signature "
              << "mismatch at 0x" << std::hex << kTextboxSyncStringCopyOffset
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  auto* deref_patch_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kTextboxSyncNullStringDerefOffset);
  const unsigned char deref_expected[] = {
      0xf6, 0x06, 0x01, 0x75, 0x11,
  };
  if (std::memcmp(deref_patch_address, deref_expected,
                  sizeof(deref_expected)) != 0) {
    std::cerr << "  [patch] Stage6 textbox sync null-string deref "
              << "signature mismatch at 0x" << std::hex
              << kTextboxSyncNullStringDerefOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  constexpr unsigned char kReturn[] = {
      0xc3,  // ret; no Android text input backing service is present.
  };
  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0x90,  // nop
  };
  unsigned char jump_to_epilogue[] = {
      0xe9,  // jmp rel32
      0x00, 0x00, 0x00, 0x00,
  };
  const uintptr_t jump_next =
      kTextboxSyncNullStringDerefOffset + sizeof(jump_to_epilogue);
  const uintptr_t jump_target = kTextboxSyncStringCopyEpilogueOffset;
  int32_t rel = static_cast<int32_t>(jump_target - jump_next);
  std::memcpy(jump_to_epilogue + 1, &rel, sizeof(rel));
  bool patched = PatchCode(entry_patch_address, kReturn, sizeof(kReturn));
  patched = PatchCode(heap_callback_patch_address, kReturnFalse,
                      sizeof(kReturnFalse)) &&
            patched;
  patched =
      PatchCode(helper_patch_address, kReturn, sizeof(kReturn)) && patched;
  patched = PatchCode(deref_patch_address, jump_to_epilogue,
                      sizeof(jump_to_epilogue)) &&
            patched;
  std::cout << "  [patch] Stage6 textbox sync null-string "
            << (patched ? "patched" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchRobloxJniReferenceHighTagMask(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_JNI_REF_HIGH_TAG_MASK")) {
    return false;
  }

  auto install_jump = [libroblox_base](uintptr_t offset, uintptr_t bridge) {
    unsigned char patch[] = {
        0x48, 0xb8,                                // movabs rax, imm64
        0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
    };
    std::memcpy(patch + 2, &bridge, sizeof(bridge));
    return PatchCode(reinterpret_cast<void*>(libroblox_base + offset), patch,
                     sizeof(patch));
  };

  uintptr_t lookup_bridge =
      reinterpret_cast<uintptr_t>(+[](uintptr_t handle) -> void* {
        return ResolveRobloxTaggedPointer(
            handle, static_cast<uintptr_t>(g_libroblox_base));
      });
  uintptr_t release_bridge =
      reinterpret_cast<uintptr_t>(+[](uintptr_t handle) -> void* {
        auto* entry = static_cast<unsigned char*>(ResolveRobloxTaggedEntry(
            handle, static_cast<uintptr_t>(g_libroblox_base)));
        if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(entry) + 0x18,
                                   sizeof(void*))) {
          return nullptr;
        }
        void* previous = *reinterpret_cast<void**>(entry + 0x18);
        if (IsReadableMemoryRange(handle, sizeof(void*))) {
          *reinterpret_cast<void**>(handle) = previous;
        }
        *reinterpret_cast<uintptr_t*>(entry + 0x18) = handle;
        if (IsReadableMemoryRange(reinterpret_cast<uintptr_t>(entry) + 0x10,
                                  sizeof(uint16_t))) {
          --(*reinterpret_cast<uint16_t*>(entry + 0x10));
        }
        return previous;
      });

  bool patched = install_jump(0x22ad3d0, lookup_bridge);
  patched = install_jump(0x1f28fee, release_bridge) && patched;
  std::cout << "  [patch] JNI reference lookup bridges "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

void** ExpandedSegmentTable() {
  constexpr size_t kSegmentTableEntries = 1u << 20;
  constexpr size_t kSegmentSlotsPerEntry = 8192;
  static void* fallback_segment[kSegmentSlotsPerEntry] = {nullptr};
  static void** table = nullptr;
  if (!table) {
    size_t table_size = kSegmentTableEntries * sizeof(void*);
    table =
        static_cast<void**>(mmap(nullptr, table_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (table == MAP_FAILED) {
      table = nullptr;
      return jnivm::my_segment_table;
    }
    for (size_t i = 0; i < kSegmentTableEntries; ++i) {
      table[i] = fallback_segment;
    }
    for (size_t offset = 0; offset < 100000; offset += kSegmentSlotsPerEntry) {
      size_t table_index = offset / kSegmentSlotsPerEntry;
      table[table_index] = jnivm::my_segment + offset;
    }
  }
  return table;
}

greg_t* Stage5RegisterSlotById(ucontext_t* ucontext, int reg_id) {
  switch (reg_id) {
    case 0:
      return &ucontext->uc_mcontext.gregs[REG_RAX];
    case 1:
      return &ucontext->uc_mcontext.gregs[REG_RCX];
    case 2:
      return &ucontext->uc_mcontext.gregs[REG_RDX];
    case 3:
      return &ucontext->uc_mcontext.gregs[REG_RBX];
    case 4:
      return &ucontext->uc_mcontext.gregs[REG_RSP];
    case 5:
      return &ucontext->uc_mcontext.gregs[REG_RBP];
    case 6:
      return &ucontext->uc_mcontext.gregs[REG_RSI];
    case 7:
      return &ucontext->uc_mcontext.gregs[REG_RDI];
    case 8:
      return &ucontext->uc_mcontext.gregs[REG_R8];
    case 9:
      return &ucontext->uc_mcontext.gregs[REG_R9];
    case 10:
      return &ucontext->uc_mcontext.gregs[REG_R10];
    case 11:
      return &ucontext->uc_mcontext.gregs[REG_R11];
    case 12:
      return &ucontext->uc_mcontext.gregs[REG_R12];
    case 13:
      return &ucontext->uc_mcontext.gregs[REG_R13];
    case 14:
      return &ucontext->uc_mcontext.gregs[REG_R14];
    case 15:
      return &ucontext->uc_mcontext.gregs[REG_R15];
    default:
      return nullptr;
  }
}

}  // namespace mocktail::legacy::internal
